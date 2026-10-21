// structuredpatch.go is BACKLOG.md F11's offline-testable slice: a
// RemediationPlan that proposes several {path, value} operations against ONE
// target object in a single atomic patch, instead of PatchField's one
// operation per plan.
//
// # Generic in mechanism, ENUMERATED in policy — same argument, extended
//
// patchfield.go's header comment states the whole safety argument for a
// generic path+value patcher: the MECHANISM is general, but the PERMISSION
// is an enumerated, reviewed table, because deploy/helm/argus-agent's
// ValidatingAdmissionPolicy holds by enumerating exactly the fields a write
// may touch. That argument does not change shape when a plan carries several
// operations instead of one — it just has to apply to every one of them,
// with no way for a single bad path to hide behind several good ones. See
// StructuredPatchParams.Validate and RemediationPlan.Validate's
// ActionStructuredPatch branch (plan.go) for where that is enforced.
//
// # Why this is not just "PatchField in a loop" at the call site
//
// It would be tempting to let a caller approve N independent PatchField
// plans instead of building this type at all. Two properties a loop of
// single-op plans cannot give:
//
//  1. Atomicity of the rehearsal. A dry run against N separate plans proves N
//     separate hypothetical patches, each against the object as it stood
//     when THAT plan was rehearsed — not what the object looks like after
//     the first N-1 have actually been applied. This type dry-runs and
//     diffs the WHOLE set as one patch, which is the only rehearsal that
//     actually matches one atomic multi-field Patch call.
//  2. Atomicity of the rollback. F14's own note (BACKLOG.md) is that F11
//     makes rollback "mechanically derivable per path" — see
//     internal/execution's rollbackForStructuredPatch, which
//     builds ONE compensating action reversing every path this plan touched,
//     from the SAME pre-change read this plan's own execution captured. N
//     independent PatchField approvals would each need their own rollback,
//     approved and executed separately, with no guarantee they are undone
//     together if only some execute.
package remediation

import "fmt"

// StructuredPatchOp is one {path, value} operation within a StructuredPatch
// plan — the same three fields PatchFieldParams carries, because the
// per-field rules (non-empty, single line, length-bounded, an allowlisted
// (kind, path) pair) are identical whether the plan carries one operation or
// several. See StructuredPatchParams.Validate, which builds one of these
// into a PatchFieldParams to reuse PatchFieldParams.Validate verbatim rather
// than re-stating those bounds a second time.
type StructuredPatchOp struct {
	// FieldPath is dot/bracket notation, exactly PatchFieldParams.FieldPath's
	// own convention.
	FieldPath string `json:"fieldPath"`
	// NewValue is the literal string form of the value this operation sets.
	NewValue string `json:"newValue"`
	// ExpectCurrent, when non-empty, must equal this field's current value at
	// execution time or the WHOLE plan refuses — see
	// internal/execution's execution-time re-check, which reads
	// every operation's live value from the same single object fetch before
	// applying any of them.
	ExpectCurrent string `json:"expectCurrent,omitempty"`
}

// StructuredPatchParams is what a StructuredPatch plan carries: a list of
// operations against the plan's single TargetGVK/TargetNamespace/TargetName,
// and nothing else — the target is the plan's, not each operation's, because
// a plan that could name a different object per operation would no longer be
// "one atomic patch against one object," which is the property the dry-run
// and rollback machinery both depend on.
type StructuredPatchParams struct {
	Ops []StructuredPatchOp `json:"ops"`
}

func (StructuredPatchParams) actionType() ActionType { return ActionStructuredPatch }

// Validate enforces every bound that can be decided from the params alone,
// before the target's kind is even known: at least one operation, no two
// operations naming the same field (which operation would win is not
// expressible, so it is refused rather than guessed), and each operation's
// own shape.
//
// The per-operation shape check is built by constructing a PatchFieldParams
// from each operation and calling ITS OWN Validate — not a second,
// hand-copied set of the same rules. PatchFieldParams.Validate already
// enforces "non-empty fieldPath", "non-empty, single-line, <=512-character
// newValue" for exactly this reason (patchfield.go), and a StructuredPatch
// operation has no field PatchFieldParams doesn't. Drifting the two apart
// would mean a value permitted as a single-op PatchField plan is refused (or
// worse, silently accepted with different bounds) inside a StructuredPatch
// plan for no principled reason.
//
// What this does NOT check, because it structurally cannot: whether each
// path is on the reviewed allowlist at all. That needs the plan's TargetGVK,
// which this struct does not carry — see RemediationPlan.Validate's
// ActionStructuredPatch branch (plan.go), which is where PatchFieldPermitted
// is actually consulted, once per operation, in the same order operations are
// declared.
func (p StructuredPatchParams) Validate() error {
	if len(p.Ops) == 0 {
		return fmt.Errorf("at least one operation is required")
	}

	seen := make(map[string]int, len(p.Ops))
	for i, op := range p.Ops {
		if err := (PatchFieldParams{FieldPath: op.FieldPath, NewValue: op.NewValue, ExpectCurrent: op.ExpectCurrent}).Validate(); err != nil {
			return fmt.Errorf("operation %d of %d: %w", i+1, len(p.Ops), err)
		}
		// Duplicate detection is on the NORMALISED path, matching every other
		// comparison in this package (PatchFieldPermitted, PlannedFieldPaths):
		// "spec.ports[0].targetPort" and "spec.ports.0.targetPort" are the
		// same field written two ways, and a plan naming both would silently
		// let whichever operation is applied last win — indistinguishable
		// from a plan-authoring bug, so refused rather than executed.
		normalised := normaliseFieldPath(op.FieldPath)
		if firstIdx, dup := seen[normalised]; dup {
			return fmt.Errorf("operation %d and operation %d both target %q — a plan may not set the same field twice", firstIdx+1, i+1, op.FieldPath)
		}
		seen[normalised] = i
	}
	return nil
}
