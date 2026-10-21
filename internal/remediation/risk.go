// risk.go implements DESIGN.md §9.3's first sentence, which
// is the one part of the risk model that is not a judgement call:
// "Risk is assigned by deterministic rules first, LLM second. The model may
// *raise* risk; it may never lower it below the rule-derived floor.
// Judgement is for nuance, not for the floor."
//
// Until this file existed, that sentence was unimplemented. A plan's
// RiskLevel was whatever the model wrote in its JSON (internal/llm/toolloop.go
// parses it straight through into RemediationPlan.RiskLevel), and the gate
// compared that self-report against the policy ceiling. So the single number
// deciding whether an action needs a human was chosen by the same
// uncalibrated component §9.1 opens by warning about — "confidence is the
// model's self-report ... treating it as a probability is a mistake that will
// eventually cost someone an outage" applies with at least as much force to a
// self-reported risk level, because unlike confidence, risk has an
// objectively knowable floor that does not depend on the analysis being right.
//
// The floor is derived from the action type plus the small amount of target
// context a plan actually carries. What it deliberately does NOT do is
// consult the cluster: §9.3's remaining modifiers (a `tier=data` label on the
// target, an `argus.io/protected` annotation on its namespace) are statements
// about live object metadata that a RemediationPlan does not carry, and
// inventing them from a model's claim about the cluster would be exactly the
// mistake this file exists to prevent. They belong at the execution layer,
// alongside the resourceVersion precondition, when there is real metadata to
// read; see the gap note at the bottom of this file.
package remediation

// baseRiskFloors is the per-action-type floor, transcribed from §9.3's own
// table rather than reasoned out afresh — the table is the spec, and a floor
// that quietly disagrees with it is a bug in this file, not a refinement.
//
//   - ScaleDeployment -> low. §9.3's low row names "scale up within quota"
//     explicitly. Note what stops this from being too permissive: the
//     modifiers below raise a StatefulSet or kube-system target, and the
//     execution layer separately refuses a scale-from-zero and a
//     wildly-disproportionate count (internal/execution), both
//     of which are live-state questions no floor can answer.
//   - RestartPod -> medium. §9.3's medium row names "restart a pod". This is
//     a real (and deliberate) change from the previous behaviour, where a
//     model was free to call a restart low-risk and have that accepted: a
//     rollout restart takes every pod of the workload down and back up, and
//     nothing in the plan can promise that the workload comes back.
//   - PatchResourceLimits -> medium. §9.3's medium row names "change resource
//     limits" verbatim. See NeverAutoApprove below for why medium is where
//     this floor stops rather than being pushed to high: the honest reading
//     of §9.3 is that this action is a config change with a controlled
//     restart, and pretending otherwise would devalue "high" for the actions
//     that genuinely delete or disrupt state.
//   - RevertContainerImage -> medium. §9.3's medium row names "update an image
//     tag" verbatim, and this action is exactly that, so medium is the
//     transcription and not a judgement call. It is worth being explicit about
//     why it is not floored LOWER, because the argument for low is superficially
//     strong: unlike every other action type, this one's target state provably
//     ran (the previous image is not a value ARGUS chose, it is one the cluster
//     recorded). What that property does NOT cover is that the change rolls
//     every pod of the workload, and that the image being rolled back may have
//     carried a security fix, a bug fix for a different incident, or a schema
//     migration whose new-shape data the older code cannot read — "it ran
//     before" is a statement about the past, not about the world the older image
//     would now start into. Nor is it floored HIGHER: reverting an image is a
//     config change with a controlled restart, and calling it high would devalue
//     "high" for the actions that genuinely delete or disrupt state. The
//     modifiers below still raise it, and the practical ceiling on this action
//     is NeverAutoApprove, not the floor.
//   - OpenPR -> low. A pull request mutates nothing in any cluster; it is
//     "additive and trivially reversible" (close the PR) in the most literal
//     sense §9.3's low row means. The risk of the CHANGE the PR proposes is
//     carried by the human review and CI that §10.2's third point is
//     specifically about inheriting.
//
// An action type missing from this map floors at high, not low — see
// RiskFloorFor. Adding an action type to validActionTypes without a floor
// here is caught by the package's own test, but the fallback exists so that
// the failure mode of forgetting is over-caution rather than a free pass.
var baseRiskFloors = map[ActionType]RiskLevel{
	ActionScaleDeployment:      RiskLow,
	ActionRestartPod:           RiskMedium,
	ActionPatchResourceLimits:  RiskMedium,
	ActionRevertContainerImage: RiskMedium,
	ActionOpenPR:               RiskLow,
	// PatchField's floor is per-FIELD, not per-action — see patchfield.go's
	// patchableField.Risk. This entry is the fallback for a plan whose field
	// somehow reached risk evaluation without an allowlist match, and it floors
	// at high on purpose: an unrecognised field is the one case where over-caution
	// is correct.
	ActionPatchField: RiskHigh,
	// StructuredPatch's floor is likewise not per-action but per-OPERATION —
	// RiskFloorFor below takes the highest Risk among every operation's own
	// matched patchableField entry, the same allowlist row PatchField's own
	// floor would use if it read patchableField.Risk (it does not, today; see
	// that field's own doc comment). This entry is the fallback for the same
	// reason ActionPatchField's is: a plan whose params are not
	// StructuredPatchParams, or whose Ops list is empty, reaches risk
	// evaluation with nothing to compute a floor from, and high is the correct
	// direction to fail.
	ActionStructuredPatch: RiskHigh,

	// AnnotateResource/LabelResource -> low. DESIGN.md §9.3's low row names
	// "add a label" verbatim as its own example, and an annotation/label
	// change touches only object metadata: no pod restart, no availability
	// impact, no data path. See risk.go's neverAutoApprove below for why
	// "low risk floor" and "never auto-approved" are not in tension for
	// these two — the same way PatchResourceLimits (medium risk) already
	// demonstrates risk level and auto-eligibility are independent axes in
	// this codebase.
	ActionAnnotateResource: RiskLow,
	ActionLabelResource:    RiskLow,

	// DeleteResource -> high. §9.3's high row names "delete anything"
	// verbatim; the allowlist in deleteresource.go never permits a target
	// (Namespace, CRD, StatefulSet) that would floor at forbidden instead.
	//
	// PersistentVolumeClaim (added 2026-09-01, BUGS.md 118 part (b)) is the
	// one allowlisted kind that COULD still float at forbidden under §9.3's
	// literal table — "delete namespace/CRD/PVC" — if this were any PVC.
	// It is not: deleteresource.go's allowlist entry, and the two live
	// re-checks behind it (internal/agent/deleteresource.go's liveness
	// precondition, internal/execution's non-overridable
	// ownership recheck), together narrow the reachable case to exactly the
	// one DESIGN.md §9.3's amended forbidden-tier row now excludes from that
	// prohibition: orphaned, unreferenced, ownership none. statefulTargetKinds
	// below still floors this at high the same as any other PVC-touching
	// action — that is the correct tier for the narrowed case, not a gap;
	// nothing here lets a model-declared risk level or a plan's own claims
	// reach that narrowing on their own (D11 still holds).
	ActionDeleteResource: RiskHigh,

	// CordonNode -> medium: it moves no pod, but it takes a node's capacity
	// out of scheduling for the whole cluster. DrainNode -> high: it evicts
	// every workload pod on the node, and a workload with no ready replica
	// elsewhere is down until its replacements are ready (nodeops.go).
	ActionCordonNode: RiskMedium,
	ActionDrainNode:  RiskHigh,

	// CreateResource -> medium. Not §9.3's low row ("additive or trivially
	// reversible... create a missing ConfigMap/PVC/ServiceAccount" is
	// literally low's own example!) — deliberately floored higher than that
	// example anyway, per this task's own brief: creating cluster state is
	// not "nothing changes if wrong" the way a label is, because unlike
	// annotateResource/labelResource's narrow, per-key-and-value-enumerated
	// mechanism, createResource's Data map is a generic, open-ended
	// key/value payload no allowlist can pre-approve the CONTENT of (see
	// createresource.go's own header for why that generic-content property
	// rules out matching annotate/label's low floor here). A wrong value in
	// a newly created ConfigMap an application then reads is a new failure
	// mode ARGUS itself introduced, not a metadata marker with no data path
	// — medium is the honest floor for a config change whose correctness
	// this layer cannot verify, the same reasoning PatchResourceLimits'
	// floor comment gives for a different action.
	ActionCreateResource: RiskMedium,
}

// statefulTargetKinds are the Kinds §9.3's high row means by "touch a
// StatefulSet or PVC": a workload whose identity and storage are part of its
// contract, where "the pods come back" is a much weaker guarantee than for a
// stateless Deployment (ordered rollout, one pod at a time, each waiting for
// its own PVC to reattach; a pod that cannot start blocks the ones behind
// it).
//
// Keyed by bare Kind, matching how the rest of this codebase reads a
// TargetGVK when it only needs the Kind (this package's own GVKKind in
// executionwindow.go; internal/execution's gvkKind).
var statefulTargetKinds = map[string]bool{
	"StatefulSet":           true,
	"PersistentVolumeClaim": true,
}

// protectedNamespaces are the namespaces §9.3 floors at high regardless of
// action: "anything in kube-system -> minimum high". kube-public and
// kube-node-lease are included on the same reasoning (cluster-owned
// namespaces whose contents are the control plane's, not a tenant's), and
// the agent's own namespace is included because ARGUS remediating ARGUS is
// the "modify the platform's own resources" case §9.3 lists under
// *forbidden* — this enum has no forbidden tier (see RiskLevel's own doc
// comment), so high is the strongest thing this floor can say, and the real
// refusal for that case has to come from a guardrail that can say no
// outright. Called out here rather than silently approximated.
var protectedNamespaces = map[string]bool{
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
	"argus-system":    true,
}

// BaseRiskFloors returns a copy of baseRiskFloors — exported so
// internal/api (PROJECT.md B167's approvalRiskRankExpr) can render this
// exact table as a SQL CASE expression and rank GET /api/v1/approvals rows
// by EffectiveRiskLevel in the database, instead of a second,
// independently-maintained copy of this table that could drift from it the
// way AllActionTypes/AllRiskLevels already exist to prevent for this
// package's other closed sets. A copy, not the map itself, so a caller
// mutating its result cannot corrupt every future RiskFloorFor call.
func BaseRiskFloors() map[ActionType]RiskLevel {
	out := make(map[ActionType]RiskLevel, len(baseRiskFloors))
	for k, v := range baseRiskFloors {
		out[k] = v
	}
	return out
}

// StatefulTargetKinds returns a copy of statefulTargetKinds, for the same
// reason BaseRiskFloors is exported: the SQL risk-rank expression's
// stateful-kind modifier has to read this table, not retype it.
func StatefulTargetKinds() map[string]bool {
	out := make(map[string]bool, len(statefulTargetKinds))
	for k, v := range statefulTargetKinds {
		out[k] = v
	}
	return out
}

// ProtectedNamespaces returns a copy of protectedNamespaces, for the same
// reason.
func ProtectedNamespaces() map[string]bool {
	out := make(map[string]bool, len(protectedNamespaces))
	for k, v := range protectedNamespaces {
		out[k] = v
	}
	return out
}

// RiskFloorFor returns the deterministic minimum risk level for a plan,
// computed from the action type and the target context the plan carries —
// never from anything the model asserted about how risky it thinks its own
// idea is.
//
// Risk is computed from action + context, not the action alone (§9.3):
// scaling a Deployment in an application namespace and scaling a StatefulSet
// in kube-system are the same ActionType and not remotely the same act.
func RiskFloorFor(plan RemediationPlan) RiskLevel {
	floor, ok := baseRiskFloors[plan.ActionType]
	if !ok {
		// Unrecognized action type. Evaluate blocks these outright before
		// risk is ever consulted, so this is unreachable via the gate — but
		// "unknown action" must never read as "harmless action" for any
		// caller that reaches this function directly.
		return RiskHigh
	}

	// StructuredPatch: the floor is the HIGHEST risk among the operations this
	// plan actually names, by consulting the SAME allowlist entries
	// RemediationPlan.Validate already checked each path against
	// (patchfield.go's patchableField.Risk) — not a second opinion about how
	// risky a field is, the same one. This REPLACES baseRiskFloors' fallback
	// (RiskHigh) rather than combining with it via maxRisk: that fallback
	// value is itself RiskHigh, so taking a max against it would make every
	// StructuredPatch plan floor at high regardless of its operations,
	// defeating the entire point of computing a per-operation floor.
	//
	// An operation whose path does not match any entry contributes nothing:
	// RemediationPlan.Validate refuses the whole plan before Evaluate ever
	// calls RiskFloorFor for real (see gate.go), so by the time this matters
	// every operation already matched an entry. A direct caller that skips
	// Validate — or params that are nil/wrong-typed/empty — gets the safe
	// baseline (RiskHigh, unchanged) rather than a floor computed from paths
	// that were never authorised in the first place.
	if plan.ActionType == ActionStructuredPatch {
		if params, ok := plan.Params.(StructuredPatchParams); ok {
			computed := RiskLow
			matched := false
			for _, op := range params.Ops {
				if entry, err := PatchFieldPermitted(plan.TargetGVK, op.FieldPath); err == nil {
					computed = maxRisk(computed, entry.Risk)
					matched = true
				}
			}
			if matched {
				floor = computed
			}
		}
	}

	// Modifiers only ever raise. Written as an explicit max rather than a
	// chain of assignments so that adding a modifier cannot accidentally
	// lower a floor another modifier already raised.
	if statefulTargetKinds[GVKKind(plan.TargetGVK)] {
		floor = maxRisk(floor, RiskHigh)
	}
	if protectedNamespaces[plan.TargetNamespace] {
		floor = maxRisk(floor, RiskHigh)
	}
	return floor
}

// EffectiveRiskLevel is the risk level every policy decision must be made
// against: the plan's declared level, raised to the deterministic floor when
// the declaration sits below it. §9.3's "the model may raise risk; it may
// never lower it below the rule-derived floor", as a single function.
//
// A declared level that is *higher* than the floor is honoured exactly as
// written — that is the "judgement is for nuance" half, and it is the one
// direction the model is trusted in. An unrecognized/empty declared level
// (which Validate rejects, so it should never reach here) yields the floor
// rather than being treated as comparable, so a malformed risk string can
// never come out looking safer than the rule.
func EffectiveRiskLevel(plan RemediationPlan) RiskLevel {
	floor := RiskFloorFor(plan)
	if !plan.RiskLevel.Valid() {
		return floor
	}
	return maxRisk(plan.RiskLevel, floor)
}

// maxRisk returns the riskier of two levels, treating an invalid level as
// the riskier one (a comparison it cannot rank must not silently win).
func maxRisk(a, b RiskLevel) RiskLevel {
	ra, okA := riskRank[a]
	rb, okB := riskRank[b]
	switch {
	case !okA:
		return b
	case !okB:
		return a
	case ra >= rb:
		return a
	default:
		return b
	}
}

// neverAutoApprove is the set of action types that are approval-only by
// construction, whatever a policy says and however confident the analysis is
// — the argus-add-remediation-action skill's step 4 demands an explicit
// verdict here rather than an ambiguous "probably fine", and this is where
// that verdict is recorded so it is enforced instead of merely documented.
//
// PatchResourceLimits is in this set. The reasoning, which is the whole
// reason the entry exists:
//
//  1. Both directions of the change are availability-affecting, and the
//     dangerous one is not the obvious one. Lowering a memory limit OOM-kills
//     a container that was working (the execution layer refuses to lower one
//     at all for exactly this reason); raising a memory or CPU *request* can
//     make the pod unschedulable, at which point the rollout stalls with
//     Pending pods and the workload is left with fewer replicas than it
//     started with. The second failure looks like success from the API
//     server's point of view: the patch is accepted, and nothing is wrong
//     until the scheduler declines.
//  2. The correct value is derivable but not *verifiable* before execution.
//     "Raise the ceiling above the one that was demonstrably too low" is a
//     defensible derivation, but nothing available at planning time knows the
//     container's real working set (there is no metrics integration wired
//     into the investigation loop yet — lld/07's query_metrics does not
//     exist) or whether a node has room for the new request. An action whose
//     correctness can only be observed after it has rolled every pod of a
//     workload is not one to fire unattended.
//  3. §12.2's validation-outcome table gives an automatic remediation one
//     chance to be wrong and then rolls it back — but the rollback here is
//     itself a rolling update, so a bad automatic patch costs the workload
//     two full rollouts, not one, and the incident that triggered it is
//     still unfixed.
//
// RevertContainerImage is in this set too, and its reasoning is different
// enough from PatchResourceLimits' to be worth its own list — the two are not
// "both medium risk, therefore both manual":
//
//  1. This action decides WHICH CHANGE WAS RIGHT, which is not a question
//     evidence from one incident can settle. Reverting an image asserts that
//     the newer image is worse than the older one, in every respect, for this
//     workload, right now. An investigation can establish that a fault appeared
//     with a deploy; it cannot establish that the deploy contained nothing worth
//     keeping. Unattended execution would therefore silently trade one team's
//     incident for another team's — the security patch, the fix for last week's
//     bug, the migration the newer code needs — with nobody in the loop who
//     knows what was in that release.
//  2. The "target state provably ran" property, which is this action's whole
//     safety argument, is strictly historical. The older image starts into a
//     world the newer one has already changed: a schema migration applied on
//     deploy is not undone by reverting the image, so the older code may now be
//     reading data it cannot parse. That failure looks nothing like the
//     symptom being fixed and would be attributed to the wrong cause.
//  3. Its own preconditions can be satisfied and still be wrong. A workload
//     whose newest revision is a legitimate rollout in progress, and whose
//     symptom is unrelated, presents exactly the same evidence to this action
//     as one broken by a bad deploy: a recent image change and an unhealthy
//     pod. The deterministic layer cannot tell those apart; a human who knows
//     what was released can.
//
// A human approving a revert is also the point at which the GitOps question
// gets asked properly. An in-place image revert on an Argo CD/Flux-managed
// Deployment is reverted by the controller within seconds (§10.2's first
// reason), and on a Helm-managed one it survives only until the next upgrade —
// so for a managed workload the durable fix is a change to the source, which
// is a decision, not a mechanism.
//
// Note this costs nothing today and is not a placeholder for a decision
// deferred: automatic mode does not exist at all (the gate's AutoApprove
// outcome deliberately routes to RecommendationReady, never Executing — see
// STATUS.md §2), so every execution of every action type is already
// human-approved. The entry is here so that when automatic mode is built,
// this action type is not swept into it by a policy change that never
// considered it.
var neverAutoApprove = map[ActionType]bool{
	ActionPatchResourceLimits:  true,
	ActionRevertContainerImage: true,
	// PatchField, for a reason the other two share and it holds more sharply:
	// every path in its allowlist sets a value that cannot be derived from the
	// API — that is why those faults were unreachable before it existed — so
	// there is always a human judgement in the value. A generic mechanism makes
	// that non-negotiable rather than merely prudent.
	ActionPatchField: true,
	// StructuredPatch shares PatchField's exact reasoning, N times over: every
	// operation sets a value that cannot be derived from the API, and a plan
	// naming several such fields at once is not a case where "just automate the
	// easy ones" has a coherent meaning — the whole plan is one atomic patch,
	// approved or not together.
	ActionStructuredPatch: true,

	// AnnotateResource/LabelResource share PatchField's generic-mechanism
	// reasoning even though their risk FLOOR is low (baseRiskFloors above),
	// not medium/high like PatchField's own fallback: the VALUE is still
	// chosen by whoever authored the plan, not derived from the API, and a
	// generic value-setting mechanism is what this codebase has already
	// decided means "a human judgement is always in the value" (patchfield.go's
	// header: "the mechanism being general makes that non-negotiable rather
	// than merely prudent"). The (kind, key) pair is enumerated and the value
	// is pattern/enum-bounded — narrower than PatchField's own reach — but
	// narrower is not the same as derivable: nothing computes "which incident
	// caused this" or "should this be marked remediated" from the live object
	// alone. So these two get DESIGN.md §9.3's low risk classification (the
	// characteristics genuinely are additive/reversible-by-a-human/no
	// availability impact) while staying approval-only by construction, the
	// same way PatchResourceLimits demonstrates a MEDIUM-risk action can be
	// manual for reasons independent of its risk level — here the same
	// independence runs the other way, at LOW risk.
	ActionAnnotateResource: true,
	ActionLabelResource:    true,

	// DeleteResource: DESIGN.md §10.5 is explicit and absolute — "deletion is
	// therefore effectively irreversible, which is why deleteResource is
	// classified high, is never automatic, and requires requireApprovers >= 1
	// with the irreversibility stated in the approval UI." Listed here
	// explicitly rather than relying only on gate.go's hard high-risk+
	// irreversible floor: RemediationPlan.Validate (plan.go) already refuses a
	// DeleteResource plan that declares Reversible=true, so the hard floor
	// alone would still block an honest one — but this entry is what keeps a
	// future relaxation of that floor, or a future policy change, from ever
	// sweeping DeleteResource into automatic mode by omission. Never at any
	// confidence, under any policy — see gate_test.go's
	// TestDeleteResourceNeverAutoApproves for the guard that this stays true.
	ActionDeleteResource: true,

	// Node actions are cluster-wide in effect and their RBAC cannot be
	// narrowed to one node, so a person always decides.
	ActionCordonNode: true,
	ActionDrainNode:  true,

	// CreateResource: the value being written (the ConfigMap's Data map) is
	// always chosen by whoever authored the plan, never derived from the
	// API — the identical "a generic value-setting mechanism means a human
	// judgement is always in the value" reasoning AnnotateResource/
	// LabelResource's own entries give above, applied to a mechanism that
	// creates new cluster state instead of touching existing metadata. It is
	// also, unlike those two, not low risk (see baseRiskFloors' own comment
	// for why): both axes point the same direction here, but they remain
	// independent — PatchResourceLimits (medium, manual) and
	// AnnotateResource (low, manual) already demonstrate that risk level and
	// auto-eligibility don't have to agree for the SAME reason in every
	// case.
	ActionCreateResource: true,
}

// NeverAutoApprove reports whether this action type is approval-only by
// construction. Exported so a caller building an approval UI or an autonomy
// policy editor can say so up front ("this action is never automatic")
// rather than only discovering it from a gate reason after the fact.
func NeverAutoApprove(actionType ActionType) bool {
	return neverAutoApprove[actionType]
}

// dataTierLabelKey/dataTierLabelValue and protectedNamespaceAnnotationKey
// back two of §9.3's three remaining live-metadata modifiers (BACKLOG.md R4,
// closed 2026-08-25; the third is VolumeMountedRaisesFloor below).
// Deliberately NOT map lookups keyed by GVK/namespace like
// statefulTargetKinds/protectedNamespaces above: those two are derivable
// from a RemediationPlan's own TargetGVK/TargetNamespace strings, but a
// resource's LABELS, its pod template's VOLUMES, and a namespace's
// ANNOTATIONS are live cluster metadata a RemediationPlan does not carry —
// asking the model to report them would make a deterministic rule depend on
// an LLM-supplied fact, the exact inversion this file exists to prevent.
// DataTierRaisesFloor, VolumeMountedRaisesFloor and NamespaceIsProtected
// below exist so the one place that DOES read live metadata —
// internal/execution's preparePlan, right after it fetches the
// live target object via describe_resource — has something pure to call
// rather than open-coding the checks there. RiskFloorFor itself is
// unchanged: it still only ever sees what a RemediationPlan carries.
const (
	dataTierLabelKey                = "tier"
	dataTierLabelValue              = "data"
	protectedNamespaceAnnotationKey = "argus.io/protected"
)

// DataTierRaisesFloor reports whether a target's own labels carry §9.3's
// "touching a resource labelled tier=data -> minimum high" modifier. Callers
// with live label data compare the result against their already-computed
// floor with HigherRisk, the same way RiskFloorFor's own statefulTargetKinds/
// protectedNamespaces modifiers do internally.
func DataTierRaisesFloor(labels map[string]string) bool {
	return labels[dataTierLabelKey] == dataTierLabelValue
}

// VolumeMountedRaisesFloor reports whether a pod template's volumes include
// a PersistentVolumeClaim — statefulTargetKinds' own reasoning ("the pods
// come back is a much weaker guarantee... a pod that cannot start blocks the
// ones behind it") applied to a workload whose STORAGE carries that
// property even though its own Kind does not. RiskFloorFor cannot see this:
// it keys statefulTargetKinds off the target's bare Kind, so a Deployment
// (never in that map) mounting a PVC gets the same floor as one that mounts
// nothing at all.
//
// Found concretely, not hypothetically, by BACKLOG.md R4's own review: issue
// catalogue PVC-014 ("Multi-attach error on RWO — two pods on different
// nodes claiming one RWO PVC, usually a Deployment with replicas > 1") is
// risk: high, autonomy: never_automatic — yet a ScaleDeployment plan against
// exactly that Deployment floors at RiskLow today, because "Deployment" is
// not in statefulTargetKinds. Not narrowed to ReadWriteOnce specifically:
// statefulTargetKinds' own PersistentVolumeClaim entry floors ANY PVC target
// at high regardless of access mode, and a Deployment mounting one has the
// identical "storage is part of its contract" property — narrowing this to
// one access mode would be a distinction RiskFloorFor's own sibling rule
// does not draw.
//
// volumes is a pod template's spec.template.spec.volumes, decoded generically
// (map[string]any per entry) rather than into a typed corev1.Volume: this
// package takes no Kubernetes API dependency anywhere else, and the only
// thing that matters here is whether the "persistentVolumeClaim" key is
// present at all.
func VolumeMountedRaisesFloor(volumes []map[string]any) bool {
	for _, v := range volumes {
		if _, ok := v["persistentVolumeClaim"]; ok {
			return true
		}
	}
	return false
}

// NamespaceIsProtected reports whether a namespace's own annotations carry
// §9.3's absolute modifier: "a namespace with a argus.io/protected
// annotation -> forbidden." Presence of the key is what matters, regardless
// of value — matching this codebase's established convention for a
// policy-enabling annotation (internal/agent/tools.go's spec.syncPolicy.
// automated presence check for Applier) — an operator marking a namespace
// protected should not also have to remember or spell a magic value
// correctly. A caller finding this true must treat the plan as
// RiskForbidden — see that constant's doc comment for why that outranks
// every other outcome Evaluate can reach, including NeedsApproval.
func NamespaceIsProtected(namespaceAnnotations map[string]string) bool {
	_, ok := namespaceAnnotations[protectedNamespaceAnnotationKey]
	return ok
}
