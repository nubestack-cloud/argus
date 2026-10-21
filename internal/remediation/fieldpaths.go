package remediation

import "fmt"

// Which live-object fields each action type actually writes (BACKLOG F11's
// allowlist generator).
//
// # Why this moved here, and why it is a table
//
// This mapping used to be a `switch` in internal/api, twenty lines from the code
// that consumed it, and it failed in the quietest possible way: an action type with
// no case returned `nil`, and a `nil` path list made the field-contention check
// return "" — so a new action type silently got NO warning that a GitOps controller
// owns the field it was about to write. Nothing errored. Nothing logged.
//
// plan.go's own comment about validActionTypes had already predicted it: "A switch
// elsewhere that forgets a case is a bug; this map is the single source of truth."
// That switch was the elsewhere.
//
// So: a table keyed by ActionType, in the same package as the closed set, with
// TestEveryActionTypeDeclaresItsFieldPaths asserting the two agree. Adding an
// action type without declaring its fields is now a test failure, which is what
// BACKLOG F11 asks for — "adding a path without updating the table is a lint
// failure rather than a silent gap".
//
// # Why "writes nothing" is declared rather than implied
//
// OpenPR genuinely writes no live object field: it changes a repository, and the
// cluster converges later via GitOps. Before this, "no paths" and "nobody mapped
// this action type" were the same value, so the safe case and the bug case were
// indistinguishable. They are now different states and only one of them is an
// error.
//
// # The paths are dot-notation, not JSONPointer
//
// lld/08-remediation-contracts.md §3 documents the same allowlist as JSONPointer
// (`/spec/replicas`, `/spec/template/metadata/annotations/*`) because that is what
// the admission policy's CEL consumes. objdiff.OwnersOf walks managedFields with
// dot paths and `[name]` for keyed list elements. TestFieldPathsMatchTheLLD
// converts between the two and fails if they diverge, so the LLD stays
// load-bearing instead of decorative.
type fieldPathSpec struct {
	// writesNoClusterFields marks an action that does not patch a live object at
	// all. Not the same as "has no declared paths yet".
	writesNoClusterFields bool
	// paths derives the concrete paths from this plan's params. Concrete because
	// several of them depend on the params — which container, and which of the four
	// resource fields were actually set.
	paths func(ActionParams) []string
}

var actionFieldPaths = map[ActionType]fieldPathSpec{
	ActionScaleDeployment: {
		paths: func(ActionParams) []string { return []string{"spec.replicas"} },
	},
	ActionRestartPod: {
		// The rollout-restart annotation on the pod template. Deliberately NOT
		// spec.template wholesale: a controller owning the template does not
		// necessarily own an annotation ARGUS adds to it, and the narrower path is
		// the honest claim about what is being written.
		paths: func(ActionParams) []string { return []string{"spec.template.metadata.annotations"} },
	},
	ActionPatchResourceLimits: {
		// Per FIELD, not per container: a plan that sets only the memory limit must
		// not claim to be writing CPU. The contention warning names the field an
		// approver is about to change, so a wider claim here would produce a wider
		// warning than the truth.
		paths: func(p ActionParams) []string {
			params, ok := p.(PatchResourceLimitsParams)
			if !ok {
				return nil
			}
			base := "spec.template.spec.containers[" + params.Container + "].resources"
			var out []string
			if params.MemoryLimit != "" {
				out = append(out, base+".limits.memory")
			}
			if params.MemoryRequest != "" {
				out = append(out, base+".requests.memory")
			}
			if params.CPULimit != "" {
				out = append(out, base+".limits.cpu")
			}
			if params.CPURequest != "" {
				out = append(out, base+".requests.cpu")
			}
			return out
		},
	},
	ActionRevertContainerImage: {
		paths: func(p ActionParams) []string {
			params, ok := p.(RevertContainerImageParams)
			if !ok {
				return nil
			}
			return []string{"spec.template.spec.containers[" + params.Container + "].image"}
		},
	},
	ActionPatchField: {
		// The one action whose written path IS its parameter, so this returns it
		// directly rather than composing one. Normalised through the same helper
		// the allowlist check uses, so the contention warning names the field in
		// the same notation an approver saw it authorised under — a warning about
		// `spec.ports[0].targetPort` and a permission for `spec.ports.*.targetPort`
		// describing the same write in two notations is how an approver stops
		// reading them.
		paths: func(p ActionParams) []string {
			params, ok := p.(PatchFieldParams)
			if !ok {
				return nil
			}
			if n := normaliseFieldPath(params.FieldPath); n != "" {
				return []string{n}
			}
			return nil
		},
	},
	ActionOpenPR: {
		// Writes a repository, not a cluster object. The whole point of this action
		// type is that the cluster converges through its own GitOps controller
		// afterwards, so there is no live field for ARGUS to contend over.
		writesNoClusterFields: true,
	},
	ActionStructuredPatch: {
		// One path per operation, normalised through the same helper
		// ActionPatchField's own entry uses, for the identical reason: the
		// contention warning must name each field in the same notation an
		// approver would see it authorised under.
		paths: func(p ActionParams) []string {
			params, ok := p.(StructuredPatchParams)
			if !ok {
				return nil
			}
			out := make([]string, 0, len(params.Ops))
			for _, op := range params.Ops {
				if n := normaliseFieldPath(op.FieldPath); n != "" {
					out = append(out, n)
				}
			}
			if len(out) == 0 {
				return nil
			}
			return out
		},
	},
	// AnnotateResource/LabelResource deliberately declare NO field-level
	// path, even though they demonstrably write one — the empty (non-nil)
	// slice below is a considered choice, not the "wrong concrete type"
	// error case PlannedFieldPaths' own doc comment describes for a nil
	// return.
	//
	// The reason is annotatelabel.go's own: a real annotation/label KEY
	// routinely contains literal dots and slashes ("argus.io/incident-id"),
	// and this package's dot-separated path notation (normaliseFieldPath,
	// fieldPathMatches) treats every "." as a path SEPARATOR. Feeding a key
	// like that through the same notation PatchField's own entry uses above
	// would silently mis-split it into fabricated nested segments
	// ("argus" -> "io/incident-id"), and objdiff.OwnersOf would then answer a
	// question about a structural path that does not correspond to how
	// managedFields actually encodes a map key (the whole key, dots and all,
	// as one fieldsV1 entry). A wrong answer here is worse than none: it
	// could read as "no controller owns this" when the true, differently-
	// keyed claim was never checked, or the reverse. So this action type
	// makes no field-level contention claim at all — checkGitOpsPrecedence
	// falls back to its own object-level message (fieldContentionDetail's own
	// doc comment: "no field-level claim can be made" is one of the three
	// situations empty plannedPaths covers) — exactly the same honest
	// fallback ActionDeleteResource uses below, for a related but distinct
	// reason.
	ActionAnnotateResource: {
		paths: func(p ActionParams) []string {
			if _, ok := p.(AnnotateResourceParams); !ok {
				return nil
			}
			return []string{}
		},
	},
	ActionLabelResource: {
		paths: func(p ActionParams) []string {
			if _, ok := p.(LabelResourceParams); !ok {
				return nil
			}
			return []string{}
		},
	},
	// ActionDeleteResource writes no FIELD at all — it removes the whole
	// object, which is a different kind of claim than "this plan sets
	// spec.foo" and has no narrower path to name. NOT writesNoClusterFields
	// (that flag's own doc comment reserves it for "does not patch a live
	// object at all", which is false here: a delete is very much a live
	// mutation) — the empty slice below reaches the identical fallback
	// (fieldContentionDetail's object-level message) through the "correct
	// type, nothing narrower to say" path rather than the "no live
	// mutation" one, which matters for anyone reading this table to
	// understand what each action type actually does.
	ActionDeleteResource: {
		paths: func(p ActionParams) []string {
			if _, ok := p.(DeleteResourceParams); !ok {
				return nil
			}
			return []string{}
		},
	},
	// CordonNode writes exactly spec.unschedulable. DrainNode writes the same
	// field on the Node and evicts pods, which are separate objects.
	ActionCordonNode: {
		paths: func(p ActionParams) []string {
			if _, ok := p.(CordonNodeParams); !ok {
				return nil
			}
			return []string{"spec.unschedulable"}
		},
	},
	ActionDrainNode: {
		paths: func(p ActionParams) []string {
			if _, ok := p.(DrainNodeParams); !ok {
				return nil
			}
			return []string{"spec.unschedulable"}
		},
	},
	// ActionCreateResource writes no FIELD of an existing object either —
	// there is no existing object for the field-contention question to be
	// about in the first place (the whole point of a create). Empty slice
	// for the identical "correct type, nothing narrower to say" reason
	// ActionDeleteResource's entry gives, not writesNoClusterFields (that
	// flag means "does not mutate the cluster at all," which is false here).
	// In practice internal/execution's preparePlan does not
	// even call the GitOps-precedence check this table feeds for a
	// CreateResource plan (there is no live object to ask a controller
	// about), so this entry exists for TestEveryActionTypeDeclaresItsFieldPaths'
	// exhaustiveness guard rather than for a code path that reads it today.
	ActionCreateResource: {
		paths: func(p ActionParams) []string {
			if _, ok := p.(CreateResourceParams); !ok {
				return nil
			}
			return []string{}
		},
	},
}

// PlannedFieldPaths returns the live-object field paths this plan will write.
//
// An empty slice with a nil error means "this action writes no cluster fields",
// which is a real answer (OpenPR). An ERROR means no one has declared what this
// action type writes — a programming error, returned rather than swallowed so the
// caller has to say something to the approver instead of quietly skipping the
// field-contention check.
func PlannedFieldPaths(plan RemediationPlan) ([]string, error) {
	spec, ok := actionFieldPaths[plan.ActionType]
	if !ok {
		return nil, fmt.Errorf("no field paths declared for action type %q — see internal/remediation/fieldpaths.go", plan.ActionType)
	}
	if spec.writesNoClusterFields {
		return nil, nil
	}
	if plan.Params == nil {
		return nil, fmt.Errorf("action type %q writes fields derived from its params, and params is nil", plan.ActionType)
	}
	paths := spec.paths(plan.Params)
	if paths == nil {
		// The params were the wrong concrete type for this action type.
		// RemediationPlan.Validate already rejects that mismatch, so reaching here
		// means something bypassed Validate — worth an error rather than an empty
		// allowlist that reads as "writes nothing".
		return nil, fmt.Errorf("action type %q could not derive field paths from params of type %T", plan.ActionType, plan.Params)
	}
	return paths, nil
}

// ActionTypesWithDeclaredFieldPaths is the key set of the table above, for the
// exhaustiveness test. Exported only for tests in other packages; production code
// should call PlannedFieldPaths.
func ActionTypesWithDeclaredFieldPaths() []ActionType {
	out := make([]ActionType, 0, len(actionFieldPaths))
	for t := range actionFieldPaths {
		out = append(out, t)
	}
	return out
}

// AllActionTypes returns the closed set validActionTypes declares.
//
// Added so tests can assert coverage OVER that set rather than restating it — a
// restated list is one more place to forget a new action type, which is the class
// of bug this whole file exists to close.
func AllActionTypes() []ActionType {
	out := make([]ActionType, 0, len(validActionTypes))
	for t := range validActionTypes {
		out = append(out, t)
	}
	return out
}
