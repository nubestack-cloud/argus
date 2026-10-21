// Package remediation holds Phase 2's first slice: a typed RemediationPlan
// schema and the confidence×risk autonomy gate that decides what happens to
// one, per DESIGN.md §9 (risk/confidence/autonomy gate) and
// lld/08-remediation-contracts.md (the RemediationPlan/state-machine design
// this package implements one piece of).
//
// Deliberately its own package, not internal/orchestrator: STATUS.md's
// repository-layout note (and cmd/hub/main.go's own doc comment) reserve
// internal/orchestrator for the *incident state machine*
// (lld/08-remediation-contracts.md §2's Detected -> ... -> Resolved
// stateDiagram) — a stateful thing that will eventually own DB rows and
// drive transitions. The autonomy gate built here is the opposite shape: a
// pure, side-effect-free decision function over a plan/confidence/policy
// triple, with no state of its own and no DB access. Keeping it in its own
// package means it stays independently unit-testable with zero dependency
// on however the (still entirely unbuilt) state machine ends up
// structured, and internal/orchestrator can import internal/remediation
// later (evaluate a plan as part of a transition) without this package
// ever needing to import back.
//
// Scope, stated explicitly per this task's brief: this package builds the
// typed plan schema and the gate only. No API endpoint, no DB table, no
// connection to the investigation loop's real output (internal/llm's
// toolloop.go), no execution of anything, and no new RBAC/authz capability
// — internal/authz/permissions.go already carries CapRemediationApprove/
// CapRemediationReject/CapRemediationExecInplace/CapRemediationExecPR/
// CapRemediationRollback (granted to resolver/tenant-admin/super-admin),
// unused since nothing to approve/reject has existed until now; this
// package still gives them nothing to call. A later task wires Evaluate
// into the incident state machine and an approval-queue UI/API.
package remediation

// k8s.io/apimachinery/pkg/api/resource is this package's only non-stdlib
// import, added with ActionPatchResourceLimits. Worth justifying, since it
// means the hub binary (which otherwise links no Kubernetes client code at
// all — internal/agent is the only other user of apimachinery in this
// module) now links it: comparing "32Mi" against "64Gi", or "1000m" against
// "1", is quantity arithmetic with binary/decimal suffixes, negative
// exponents and scale normalization, and the one correct implementation of
// it is Kubernetes' own. A hand-rolled parser here would be a
// silently-wrong-by-a-factor-of-1024 bug generator in exactly the code path
// that decides whether a memory limit is sane. The package is a leaf (no
// client-go, no API types, no network) — the cost is a parser, not a
// dependency on a cluster.
import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"argus/internal/redact"
	"k8s.io/apimachinery/pkg/api/resource"
)

// ActionType is a closed enum of the remediation actions a RemediationPlan
// may describe. This is deliberately not a generic "run this command"
// string — DESIGN.md's core safety principle (§18.3): the
// model authors a plan, non-LLM code is what would ever act on it, and a
// plan can only ever name one of a fixed, reviewed set of actions.
//
// Adding a new action type here is a real, deliberate extension (add the
// constant, add its Params struct, add it to the validity/consistency
// checks below) — never something a caller can do by passing an arbitrary
// string. An ActionType value that isn't one of these constants is
// unrecognized and Evaluate blocks it (see gate.go) rather than treating it
// as some kind of permissive default.
type ActionType string

const (
	// ActionScaleDeployment changes a Deployment's replica count.
	// lld/08-remediation-contracts.md §3's scaleWorkload.
	ActionScaleDeployment ActionType = "ScaleDeployment"

	// ActionRestartPod restarts a Pod (in practice, via a rolling
	// annotation-triggered restart of its owning workload — see
	// lld/08-remediation-contracts.md §3's restartWorkload; modeled here
	// as its own action type per this task's brief).
	ActionRestartPod ActionType = "RestartPod"

	// ActionPatchResourceLimits changes ONE named container's CPU/memory
	// requests and/or limits on a Deployment or StatefulSet —
	// lld/08-remediation-contracts.md §3's patchResource, narrowed to the
	// single field group DESIGN.md §9.3 names explicitly
	// ("change resource limits", medium risk).
	//
	// Deliberately NOT a generic path+value patch action. §10.3's action
	// catalogue does list a general `patchResource`, but the
	// argus-add-remediation-action skill is explicit that "a fully generic
	// patch action is a manual-only elevated operation, never an automatic
	// recipe": a plan that can name an arbitrary field path is a plan whose
	// blast radius cannot be reviewed by reading its type, and it would make
	// deploy/helm/argus-agent's ValidatingAdmissionPolicy — the layer that
	// stops a compromised hub rewriting a container's image or security
	// context — impossible to write, because there would be no fixed set of
	// paths to allow. So the params below name a container and four specific
	// quantities, nothing else.
	//
	// This exists because ARGUS could already diagnose the fault class it
	// addresses and do nothing about it: a container OOM-killed against a
	// too-small memory limit is one of the reproduced faults in
	// CAPABILITIES.md, and unlike "fix the image tag" the corrected value
	// is derivable from the live object (raise the ceiling relative to the
	// one that is demonstrably too low) rather than invented.
	ActionPatchResourceLimits ActionType = "PatchResourceLimits"

	// ActionRevertContainerImage sets ONE named container's image back to the
	// image that same container ran under the workload's PREVIOUS revision —
	// lld/08-remediation-contracts.md §3's patchResource again, narrowed this
	// time to the single field DESIGN.md §9.3's medium row
	// calls "update an image tag".
	//
	// Why this action exists: "the last deploy broke it" is the most common
	// real cause of an outage, and it is the one fix where ARGUS invents
	// nothing at all. Every other action type has to choose a value — a
	// replica count, a memory ceiling — and defend that choice. This one has
	// the target state handed to it by the cluster's own rollout history: the
	// previous image demonstrably ran, on this workload, in this namespace,
	// until somebody replaced it.
	//
	// Two scope decisions are load-bearing enough to state here rather than
	// only in the params struct:
	//
	//  1. The IMAGE ONLY, never the whole pod template. `kubectl rollout undo`
	//     restores the entire previous PodTemplateSpec, and that is deliberately
	//     NOT what this is. deploy/helm/argus-agent's ValidatingAdmissionPolicy
	//     is the layer that holds when everything on the ARGUS side is
	//     compromised, and it holds by enumerating the fields that must compare
	//     equal. A full-template revert has no such enumeration: "equals some
	//     previous revision" is not expressible in CEL (the API server has no
	//     access to the revision history when it evaluates an admission
	//     request), so opening the whole template would mean opening it
	//     permanently to arbitrary values — env, volumes, securityContext,
	//     serviceAccountName. Reverting one field keeps the allowlist an
	//     allowlist.
	//  2. The MODEL NEVER NAMES THE IMAGE. RevertContainerImageParams below
	//     carries a container name and nothing else; the image is resolved by
	//     the hub from live cluster state at approval time
	//     (internal/execution's resolvePreviousImage) and signed
	//     into the plan envelope, then independently re-verified against the
	//     workload's own ReplicaSet history by the agent before the Patch. A
	//     model-supplied image would be the single worst field in this codebase
	//     to trust: an image reference is code, a hallucinated or injected tag
	//     is arbitrary code execution inside the customer's cluster, and no
	//     amount of string validation distinguishes "a real previous image"
	//     from "a plausible-looking one". So the schema makes it
	//     unrepresentable rather than validated.
	ActionRevertContainerImage ActionType = "RevertContainerImage"

	// ActionOpenPR proposes a change via a pull request against the
	// resource's owning Git repository, rather than a live cluster
	// mutation — the GitOps-owned-resource channel
	// (DESIGN.md §10.1-10.2, non-negotiable 5).
	ActionOpenPR ActionType = "OpenPR"

	// ActionPatchField sets one field on an explicitly enumerated (kind, field
	// path) pair — see patchfield.go for the allowlist and, more importantly, for
	// why the mechanism being generic makes the enumeration non-negotiable.
	//
	// This is the only action type whose reach is defined by a table rather than
	// by its own name, which is the point: FAILURE_MODES.md counts 30 faults that
	// are reachable in-cluster and blocked solely on there being no action type
	// for them, and thirty bespoke actions is a cost curve that guarantees
	// coverage stops early.
	ActionPatchField ActionType = "PatchField"

	// ActionStructuredPatch is BACKLOG.md F11's keystone mechanism: a plan
	// carries a LIST of {path, value} operations against ONE target object,
	// instead of PatchField's single {fieldPath, newValue}. See
	// structuredpatch.go for the params shape and validation.
	//
	// Deliberately built as a narrower slice than F11 describes in full. F11's
	// own entry in BACKLOG.md is explicit that the model-authored-vs-fixed-menu
	// question is still open (STATUS.md §3, "Is the enumerated action menu the
	// right shape at all?"), so this type exists to prove the SAFETY MACHINERY
	// (validation, dry-run, diff, rollback) works for a multi-op patch — not to
	// make one reachable. Concretely, and on purpose, this action type is:
	//
	//   - NOT described in either backend's system prompt
	//     (internal/llm/toolloop.go's SystemPrompt, internal/llm/
	//     cli_investigator.go) — mirroring exactly how PatchField itself was
	//     withheld pending its own open breadth question (STATUS.md §3) before
	//     BUGS.md 78 wired its execution path.
	//   - NOT parsed by internal/llm's parseProposedPlan (toolloop.go): that
	//     function's ActionType switch has no case for this value, so even a
	//     model that somehow emitted the literal string "StructuredPatch" as
	//     actionType would produce a plan with nil Params, which Validate below
	//     rejects outright (Blocked, InvalidPlan=true) before anything is
	//     persisted — see remediation.Evaluate and BUGS.md 86's fix
	//     (Decision.InvalidPlan) for why that path is safe rather than a raw
	//     CHECK-constraint violation.
	//   - NOT implemented as an agent-side tool. internal/api/
	//     internal/execution's executionToolForAction maps this to a tool name
	//     ("patch_structured") for the hub-side pipeline (dry-run, diff,
	//     rollback capture) to be genuinely exercisable in tests, but no such
	//     tool exists on the agent, so a real attestByDryRun call against a live
	//     cluster fails cleanly (an unrecognized tool) rather than mutating
	//     anything.
	//
	// Three independent gaps, not one, stand between this type and production
	// reachability. Closing them (system prompt, wire parser, agent tool) is
	// F11's OWN open question to resolve first, per BACKLOG.md's own framing —
	// not a decision this task is scoped to make.
	ActionStructuredPatch ActionType = "StructuredPatch"

	// ActionAnnotateResource sets one annotation key to one value on the
	// plan's target object — see annotatelabel.go for the (kind, key) ->
	// (risk, allowed values) allowlist and the full reasoning for why this
	// is a second, narrower mechanism rather than a PatchField path.
	ActionAnnotateResource ActionType = "AnnotateResource"

	// ActionLabelResource is ActionAnnotateResource's label-map twin — same
	// mechanism, same file, targeting metadata.labels instead of
	// metadata.annotations.
	ActionLabelResource ActionType = "LabelResource"

	// ActionDeleteResource removes the plan's target object from the
	// cluster entirely. See deleteresource.go for the enumerated (kind)
	// allowlist and DESIGN.md §10.5 for why this is high risk, never
	// automatic, and carries no representable rollback.
	ActionDeleteResource ActionType = "DeleteResource"

	// ActionCreateResource creates a brand-new object at the plan's target
	// GVK/namespace/name — see createresource.go for the enumerated (kind)
	// allowlist (ConfigMap only, today), why this needed a new RBAC verb and
	// a genuinely different admission-policy shape (no oldObject exists on a
	// CREATE), and why this action type's rollback is always nil.
	//
	// replaceResource — BACKLOG.md F9's other named-but-deferred verb, a
	// whole-object REPLACE of something that already exists — stays
	// deliberately unbuilt: this file's own ActionRevertContainerImage
	// comment already records why "equals some previous revision" is not
	// expressible in CEL, and a replace has the identical problem one layer
	// up (the whole object, not one field) with no narrower allowlist
	// possible. createResource does not share that problem: a CREATE names
	// no oldObject at all, so there is nothing to "equal", only a bare
	// object whose kind/namespace/absence-of-conflict can be checked — see
	// this constant's own referenced files for exactly what that check can
	// and cannot express.
	ActionCreateResource ActionType = "CreateResource"

	// ActionCordonNode and ActionDrainNode change a Node's schedulability
	// and move its pods off it — see nodeops.go.
	ActionCordonNode ActionType = "CordonNode"
	ActionDrainNode  ActionType = "DrainNode"
)

// validActionTypes is the authoritative closed set. A switch elsewhere that
// forgets a case is a bug; this map is the single source of truth Evaluate
// and ActionType.Valid both consult, so there is only one place to update
// when a new action type is added.
// ActionUpgradeAgent is a hub operation, not a remediation: a person asks the
// hub to move a cluster's agent onto the image the hub was released with
// (PROJECT.md AD10). It is signed like a plan so the agent can tell it came
// from its hub, and it is deliberately absent from validActionTypes and from
// resolution.PermittedActionTypes — no model output can ever produce one.
const ActionUpgradeAgent ActionType = "UpgradeAgent"

var validActionTypes = map[ActionType]bool{
	ActionScaleDeployment:      true,
	ActionRestartPod:           true,
	ActionPatchResourceLimits:  true,
	ActionRevertContainerImage: true,
	ActionOpenPR:               true,
	ActionPatchField:           true,
	ActionStructuredPatch:      true,
	ActionAnnotateResource:     true,
	ActionLabelResource:        true,
	ActionDeleteResource:       true,
	ActionCreateResource:       true,
	ActionCordonNode:           true,
	ActionDrainNode:            true,
}

// Valid reports whether a is one of the closed set of known action types.
func (a ActionType) Valid() bool {
	return validActionTypes[a]
}

// RiskLevel is a closed enum, never a free-text string (DESIGN.md §9.3).
//
// RiskForbidden (BACKLOG.md R4, added 2026-08-25) is §9.3's fourth tier:
// "never, at any confidence" — stronger than NeedsApproval, because a human
// approving it is exactly the outcome §9.3 rules out (its own examples are
// deleting a namespace/CRD/PVC, disabling admission control, modifying
// ARGUS's own resources). No ActionType in this codebase's closed set
// declares it as a base floor — none of ScaleDeployment/RestartPod/
// PatchResourceLimits/RevertContainerImage/OpenPR/PatchField IS one of
// those catastrophic acts — so the only way a plan's EFFECTIVE risk reaches
// RiskForbidden today is DESIGN.md §9.3's other absolute modifier: the
// target NAMESPACE carries an argus.io/protected annotation. See
// NamespaceIsProtected and internal/execution's preparePlan,
// the one place with live cluster metadata to check it against — this type
// only needs to know the value exists and outrank everything else.
type RiskLevel string

const (
	RiskLow       RiskLevel = "low"
	RiskMedium    RiskLevel = "medium"
	RiskHigh      RiskLevel = "high"
	RiskForbidden RiskLevel = "forbidden"
)

// riskRank gives RiskLevel a total order for comparison (Low < Medium <
// High < Forbidden) without exposing magic integers on the public type.
var riskRank = map[RiskLevel]int{
	RiskLow:       0,
	RiskMedium:    1,
	RiskHigh:      2,
	RiskForbidden: 3,
}

// Valid reports whether r is one of the closed set of known risk levels.
func (r RiskLevel) Valid() bool {
	_, ok := riskRank[r]
	return ok
}

// AllRiskLevels returns the closed set riskRank declares, matching
// AllActionTypes' own reasoning exactly: migrations 000040 and 000056 each
// independently forgot to widen remediation_recommendations' action_type
// CHECK constraint when a new ActionType was added, and
// TestActionTypeCheckConstraintAcceptsEveryActionType is what makes a third
// occurrence impossible by driving the real constraint from this function's
// sibling rather than a hand-copied list. risk_level carries the identical
// kind of CHECK constraint and had no equivalent guard when RiskForbidden
// was added (BACKLOG.md R4) — this function exists so
// TestRiskLevelCheckConstraintAcceptsEveryRiskLevel can close that gap
// before it repeats the same lesson a third time under a different column
// name.
func AllRiskLevels() []RiskLevel {
	out := make([]RiskLevel, 0, len(riskRank))
	for r := range riskRank {
		out = append(out, r)
	}
	return out
}

// atMost reports whether r is no riskier than max. Both must already be
// Valid; callers that haven't checked that get a conservative false, which
// is what causes Evaluate to route an invalid comparison to NeedsApproval
// rather than to ever compute AutoApprove from an unranked value.
// HigherRisk reports whether a ranks strictly above b on the Low < Medium <
// High order — exported so a caller outside this package (e.g.
// internal/execution's post-target-resolution recheck, WORKLOG
// §97 G3) can compare two RiskFloorFor results without reaching into this
// package's private ranking table. An unrecognized level ranks below every
// known one, matching riskRank's own comment: it can only ever look SAFER
// than reality, never more dangerous — so a caller comparing against it
// fails toward "re-check", not toward "trust it."
func HigherRisk(a, b RiskLevel) bool {
	ra, aOK := riskRank[a]
	rb, bOK := riskRank[b]
	if !aOK || !bOK {
		return false
	}
	return ra > rb
}

func (r RiskLevel) atMost(max RiskLevel) bool {
	rr, ok1 := riskRank[r]
	mr, ok2 := riskRank[max]
	return ok1 && ok2 && rr <= mr
}

// ActionParams is implemented by exactly the per-action-type parameter
// structs below (ScaleDeploymentParams, RestartPodParams,
// PatchResourceLimitsParams, RevertContainerImageParams, OpenPRParams).
// actionType is unexported, so no
// type outside this package can implement ActionParams —
// RemediationPlan.Params is closed to this package's own typed structs,
// never a generic map[string]any grab-bag a caller could populate with
// arbitrary fields.
type ActionParams interface {
	actionType() ActionType
}

// selfValidatingParams is the optional second interface a params struct may
// implement when its fields carry bounds of their own — RemediationPlan.
// Validate type-asserts for it and calls Validate when present (see below).
//
// Optional rather than folded into ActionParams on purpose: three of the five
// params types have nothing to bound beyond "the right shape", and forcing
// them all to carry an empty Validate method would make "this action type has
// real value bounds" invisible at a glance. The interface is unexported (so
// only this package decides what participates) while the method it names is
// exported, because internal/agent/tools.go re-runs exactly this check
// agent-side before issuing any Patch — DESIGN.md §10.3's
// "agent-side re-validation ... even a fully compromised hub cannot make an
// agent" exceed local guardrails. Sharing one method rather than
// hand-copying the bounds into the agent is deliberate: two copies of a
// numeric guardrail drift, and the drift is silent.
type selfValidatingParams interface {
	Validate() error
}

// ScaleDeploymentParams is ActionScaleDeployment's typed parameter struct —
// e.g. "scale Deployment X's replicas from 2 to 4".
type ScaleDeploymentParams struct {
	// Replicas is the target replica count. lld/08-remediation-contracts.md
	// §3 notes a sane-bound-relative-to-current check belongs at the
	// execution layer (rejecting a "0->500 jump" as a plan-authoring bug) —
	// out of scope for this package, which only carries the value.
	Replicas int
}

func (ScaleDeploymentParams) actionType() ActionType { return ActionScaleDeployment }

// RestartPodParams is ActionRestartPod's typed parameter struct. Carries no
// fields today (a restart has no tunable beyond "which pod," already named
// by RemediationPlan's Target* fields) — kept as its own named struct
// rather than reusing another action's params type, so ActionType and
// Params stay independently, mechanically checkable (see
// RemediationPlan.Validate) even though there's nothing to configure yet.
type RestartPodParams struct{}

func (RestartPodParams) actionType() ActionType { return ActionRestartPod }

// Absolute bounds for ActionPatchResourceLimits' four quantities, checked by
// PatchResourceLimitsParams.Validate below and re-checked agent-side
// (internal/agent/tools.go's patch_resource_limits) before any Patch.
//
// These are gross-error backstops, not tuning knobs — the same posture as
// internal/agent/tools.go's scaleReplicaCeiling. Their job is to make a
// plan-authoring mistake (a unit slip, a hallucinated number, a decimal in
// the wrong place) impossible to execute, not to encode a fleet's capacity
// policy. Each was chosen so that the nearest plausible typo lands outside
// it by a wide margin:
//
//   - maxMemoryQuantity 64Gi. The brief's own example of what must be
//     rejected is "a memory limit in the terabytes"; 1Ti is 16x this
//     ceiling, and so is every larger slip. 64Gi is still above any single
//     container this platform is expected to touch (it is most of a large
//     node), so a legitimate fix never brushes against it.
//   - minMemoryQuantity 16Mi. Below this, effectively nothing survives
//     startup — even a static, scratch-based binary with a small heap is
//     OOM-killed — so a memory limit under 16Mi cannot be a considered
//     remediation. Note this is an absolute floor only; the *relative*
//     floor that actually matters (never lower a running container's memory
//     ceiling) lives at the execution layer, where the live value is known
//     firsthand — see internal/execution's
//     checkResourceLimitsBound.
//   - maxCPUQuantity 32 (cores). Above this a request is unschedulable on
//     any node this fleet runs, and as a *limit* it stops meaning anything
//     (there is nothing left to throttle). A "32000" slip for "32000m" is
//     1000x out and caught here.
//   - minCPUQuantity 10m. Under ~10m a container is throttled hard enough
//     that its own liveness probe starts failing, i.e. the "fix" causes the
//     symptom. 10m is also the smallest value anyone writes deliberately.
//
// Stored as strings parsed through resource.ParseQuantity rather than as
// int64 byte/millicore constants so that the bound and the value it bounds
// are expressed in the same notation a human reads in a manifest, and so
// there is exactly one parser (Kubernetes' own) deciding what "64Gi" means.
const (
	minMemoryQuantity = "16Mi"
	maxMemoryQuantity = "64Gi"
	minCPUQuantity    = "10m"
	maxCPUQuantity    = "32"
)

// containerNameRE is Kubernetes' own DNS_LABEL shape, which every container
// name must already satisfy. Validated here even though the name is only
// ever used as a JSON *value* (a strategic-merge-patch merge key, never
// interpolated into a path, a selector or a command) — so this is not an
// injection defence, it is a fail-fast: a params struct carrying
// "my container" or "" can only be an authoring bug, and catching it in the
// gate is cheaper and clearer than watching the API server reject the patch
// later, or — worse — watching the patch succeed by adding a whole new
// container to the pod template (which is what a strategic-merge patch does
// with an unmatched merge key, and is precisely the outcome the execution
// layer's live-container check exists to prevent).
var containerNameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// PatchResourceLimitsParams is ActionPatchResourceLimits' typed parameter
// struct: the container to change, and the specific quantities to set on it.
//
// All four quantity fields are optional and independent; an empty string
// means "leave this one exactly as it is", which is why they are plain
// strings rather than *resource.Quantity — "" is a real, distinct third
// state next to "a valid quantity" and "garbage", and this struct is also
// what crosses the wire to the agent (see the json tags), where a nil
// pointer and an absent key are indistinguishable. At least one of the four
// must be set; a plan that changes nothing is rejected rather than executed
// as an expensive no-op that still rolls every pod.
//
// The json tags are load-bearing on this type specifically (the other three
// params structs have none — internal/orchestrator.marshalPlanParams owns
// their wire shape): the signed plan envelope carries these params to the
// agent, and the agent decodes them back into THIS type so it can re-run
// Validate against the same bounds the hub used. One struct, one wire shape,
// one set of bounds.
//
// What this action deliberately cannot express, each for a specific reason:
//   - Which container to add. Only an existing, named container can be
//     patched; the execution layer fails closed if the name is not present
//     on the live object.
//   - Adding a request/limit that is not already set. Introducing a limit
//     where there was none changes the pod's QoS class (BestEffort ->
//     Burstable) and therefore its eviction ordering — a different and
//     larger decision than raising a ceiling that is demonstrably too low —
//     and its compensating action would have to say "delete this field",
//     which this schema cannot say and which a strategic-merge patch
//     expresses only via an explicit null. Rejected at the execution layer
//     (internal/execution), where the live values are known.
//   - Ephemeral/init container resources, and any resource name other than
//     cpu and memory (GPUs, hugepages, extended resources). The admission
//     policy refuses those outright, so there is no point in the schema
//     being able to name them.
//
// Known, accepted consequence, stated rather than hidden: raising ONLY the
// limit on a container whose limit currently equals its request moves that
// pod from Guaranteed to Burstable QoS. That is not blocked, because
// refusing the most common legitimate use of this action (raise a too-small
// ceiling) to preserve a QoS class the operator can restore by also raising
// the request would be the wrong trade — and because every execution of
// this action is human-approved (see NeverAutoApprove in risk.go).
type PatchResourceLimitsParams struct {
	// Container is the name of the container within the target workload's
	// pod template whose resources are being changed. Required — this action
	// never means "every container".
	Container string `json:"container"`

	// MemoryLimit/MemoryRequest/CPULimit/CPURequest are the new values, in
	// Kubernetes quantity notation ("256Mi", "1Gi", "500m", "2"). Empty
	// means unchanged.
	MemoryLimit   string `json:"memoryLimit,omitempty"`
	MemoryRequest string `json:"memoryRequest,omitempty"`
	CPULimit      string `json:"cpuLimit,omitempty"`
	CPURequest    string `json:"cpuRequest,omitempty"`
}

func (PatchResourceLimitsParams) actionType() ActionType { return ActionPatchResourceLimits }

// Validate enforces every bound that can be decided from the params alone:
// a well-formed container name, at least one quantity to change, each
// quantity parseable and inside its absolute range, and requests no larger
// than the limits set in the same plan.
//
// What it deliberately does NOT check, because it structurally cannot: any
// comparison against the container's CURRENT values. "Is this limit lower
// than what the container is running with", "does this field even exist
// today", "is this request increase so large the pod becomes unschedulable"
// are all statements about live cluster state, and a claim about live state
// carried inside a plan would be the model's assertion, stale by however
// long the plan sat in the approval queue. Those checks belong where the
// live object is read firsthand — internal/execution's
// checkResourceLimitsBound, at the same moment it reads the resourceVersion
// precondition — exactly as ScaleDeploymentParams' own doc comment says of
// the equivalent replica check.
func (p PatchResourceLimitsParams) Validate() error {
	return p.validate(minMemoryQuantity, minCPUQuantity)
}

// ValidateRestore is Validate with the absolute MINIMUMS dropped, and is the
// only validation a compensating action derived from live state is ever put
// through. Everything else Validate checks still applies: the container-name
// shape, at-least-one-field, "parses as a quantity", "is greater than zero",
// both maxima, and request <= limit.
//
// Why the minimums cannot apply here (found live, T5, 2026-09-17). A container
// running under a 4Mi memory limit was OOMKilled on every start. The plan to
// raise it was correct and the cluster's dry run accepted it — and the hub
// refused to execute, because the undo it captured beforehand says "set the
// memory limit back to 4Mi", and 4Mi is below minMemoryQuantity. So the
// rollback-must-itself-be-valid rule made the fix unexecutable, and it did so
// most reliably on the workloads most badly misconfigured: the further below
// 16Mi a live limit sits, the more certain ARGUS was to refuse to raise it.
//
// The minimums are a statement about what ARGUS may PROPOSE ("a memory limit
// under 16Mi cannot be a considered remediation" — see their own doc comment),
// and a compensating action proposes nothing. It records a value that was read
// off the live object moments earlier and is, by direct observation, a value
// the API server already holds. Refusing it as unreasonable is refusing to
// describe reality.
//
// Safe to relax precisely because the envelope's rollback is never APPLIED
// from the envelope: internal/agent's patchResourceLimits validates it, checks
// it names the same container, and compares it against live state — the patch
// body it builds uses the forward params only. An operator-initiated undo goes
// back through the ordinary forward path (internal/api/rollback.go's undoPlan
// -> preparePlan), where the full Validate and every live-state bound apply
// again, so nothing reaches a cluster on the strength of this weaker check.
func (p PatchResourceLimitsParams) ValidateRestore() error {
	return p.validate("", "")
}

// validate is Validate's body, parameterised by the two absolute minimums so
// that ValidateRestore above can drop them without duplicating a single rule.
// An empty minimum means "no lower bound beyond greater-than-zero".
func (p PatchResourceLimitsParams) validate(minMemory, minCPU string) error {
	if !containerNameRE.MatchString(p.Container) {
		return fmt.Errorf("container %q is not a valid container name (lowercase alphanumeric and '-', per Kubernetes DNS_LABEL)", p.Container)
	}
	if p.MemoryLimit == "" && p.MemoryRequest == "" && p.CPULimit == "" && p.CPURequest == "" {
		return fmt.Errorf("no resource values to set: at least one of memoryLimit, memoryRequest, cpuLimit or cpuRequest is required")
	}

	memLimit, err := parseBoundedQuantity("memoryLimit", p.MemoryLimit, minMemory, maxMemoryQuantity)
	if err != nil {
		return err
	}
	memRequest, err := parseBoundedQuantity("memoryRequest", p.MemoryRequest, minMemory, maxMemoryQuantity)
	if err != nil {
		return err
	}
	cpuLimit, err := parseBoundedQuantity("cpuLimit", p.CPULimit, minCPU, maxCPUQuantity)
	if err != nil {
		return err
	}
	cpuRequest, err := parseBoundedQuantity("cpuRequest", p.CPURequest, minCPU, maxCPUQuantity)
	if err != nil {
		return err
	}

	// requests <= limits, per resource, when this one plan sets both. The
	// API server enforces this too, and rejects the patch if it is violated
	// — but a plan that reaches the cluster only to be refused has already
	// consumed an approval, moved the incident to Executing and recorded a
	// failure, so catching it in the gate is the difference between "this
	// plan was never approvable" and "this remediation failed". The case
	// where only ONE side is set in the plan is checked against the live
	// object at execution time, not here (see this method's doc comment).
	if memLimit != nil && memRequest != nil && memRequest.Cmp(*memLimit) > 0 {
		return fmt.Errorf("memoryRequest %s exceeds memoryLimit %s — a request may never be larger than its own limit", p.MemoryRequest, p.MemoryLimit)
	}
	if cpuLimit != nil && cpuRequest != nil && cpuRequest.Cmp(*cpuLimit) > 0 {
		return fmt.Errorf("cpuRequest %s exceeds cpuLimit %s — a request may never be larger than its own limit", p.CPURequest, p.CPULimit)
	}
	return nil
}

// parseBoundedQuantity parses one optional quantity field and range-checks
// it. Returns (nil, nil) for an unset field — the caller distinguishes
// "absent" from "present and valid" by the nil, so an omitted field never
// silently participates in a comparison as a zero quantity.
//
// resource.ParseQuantity is Kubernetes' own parser, used rather than
// strconv-plus-a-suffix-table because quantity notation has real subtleties
// this code must not get independently wrong: Mi/M are different (2^20 vs
// 10^6), "1000m" and "1" are the same value in different scales, and a
// bare number on memory means bytes. Comparisons then go through
// Quantity.Cmp, which normalizes scale, rather than comparing the strings a
// model happened to write.
func parseBoundedQuantity(field, value, min, max string) (*resource.Quantity, error) {
	if value == "" {
		return nil, nil
	}
	q, err := resource.ParseQuantity(value)
	if err != nil {
		return nil, fmt.Errorf("%s %q is not a valid Kubernetes quantity (e.g. \"256Mi\", \"500m\")", field, value)
	}
	if q.Sign() <= 0 {
		return nil, fmt.Errorf("%s %q must be greater than zero", field, value)
	}
	// MustParse on the package's own constants: these are fixed literals in
	// this file, so a parse failure would be a compile-time-class bug, not a
	// runtime condition worth an error path.
	//
	// An empty min means "no lower bound beyond the greater-than-zero check
	// just above" — see PatchResourceLimitsParams.ValidateRestore for the one
	// caller that passes it and why a restored value must not be held to a
	// floor written for a proposed one.
	maxQ := resource.MustParse(max)
	if min != "" {
		minQ := resource.MustParse(min)
		if q.Cmp(minQ) < 0 {
			return nil, fmt.Errorf("%s %q is below the minimum this action will set (%s) — a value that small cannot be a considered remediation", field, value, min)
		}
	}
	if q.Cmp(maxQ) > 0 {
		return nil, fmt.Errorf("%s %q exceeds the maximum this action will set (%s) — refusing to execute what looks like a plan-authoring error", field, value, max)
	}
	return &q, nil
}

// maxContainerImageLength bounds the resolved image reference the hub signs
// into a RevertContainerImage envelope. 512 is far above anything real (a
// registry host, a multi-segment repository path and a sha256 digest together
// come to roughly 150 characters) and far below anything that could be a
// payload rather than a reference — its job is to make "this is not an image
// name at all" fail immediately, at the layer that has no cluster to check
// against, rather than being written into somebody's pod template.
const maxContainerImageLength = 512

// containerImageRE is a shape check, not a reference parser, and the
// distinction matters enough to spell out: the authoritative test of whether
// an image is legitimate is NOT this regexp, it is that the image was read out
// of one of the target workload's own ReplicaSets — by the hub when it
// resolved the revision (internal/execution) and again,
// independently, by the agent before it patches (internal/agent/tools.go's
// revertContainerImage). A value that passes this pattern but does not appear
// in the workload's revision history is still refused.
//
// What the pattern is for is the failure this codebase can have without any
// cluster involvement: an image string carrying whitespace, quotes, newlines,
// shell metacharacters or non-printables is not a reference that was ever
// pulled, it is a sign that something upstream is malformed or hostile, and it
// must not be written into a pod template while we work out which. The
// character class is the union of what OCI reference grammar actually permits
// across a reference's parts — host[:port]/path/segments:tag or @algo:hex,
// where digest algorithms may carry '+', '.', '_' and '-' — and nothing else.
// Note this is not an injection defence in the shell sense: there is no shell
// anywhere on this path (DESIGN.md §10.3), and the value only
// ever becomes a JSON string in a strategic-merge patch body.
var containerImageRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$`)

// RevertContainerImageParams is ActionRevertContainerImage's typed parameter
// struct, and its shape is the whole safety argument for this action type: ONE
// field, the container name. There is no image field, and that is not an
// omission to be filled in later — see ActionRevertContainerImage's own doc
// comment for why a model-supplied image reference is the one value in this
// schema that must be unrepresentable rather than validated.
//
// Consequence worth stating plainly, because it is unusual for this package:
// this struct is NOT what crosses the wire to the agent. Every other action
// type's params are the same bytes at proposal time, at approval time and at
// execution time; this one's are not, because the executable form needs a
// field the proposable form must not have. The hub builds a
// RevertContainerImageExecParams (below) from live cluster state at approval
// time and signs THAT into the plan envelope. So:
//
//	proposed / persisted / displayed:  {"container": "api"}
//	signed / executed:                 {"container": "api", "image": "..."}
//
// The json tag is still load-bearing on this type: internal/llm's
// parseProposedPlan reads that exact lowercase key out of the model's
// proposedPlan, internal/orchestrator.marshalPlanParams writes it into
// remediation_recommendations.params, and UnmarshalPlanParams reads it back —
// and because the type has no image field, a params row that somehow acquired
// one (a hand-edited row, a future bug) cannot smuggle an image into an
// executed plan. It is dropped on decode, structurally.
type RevertContainerImageParams struct {
	// Container is the name of the container within the target Deployment's
	// pod template whose image is being reverted. Required — this action
	// never means "every container", for the same reason
	// PatchResourceLimitsParams doesn't: a strategic-merge patch naming one
	// container leaves its siblings alone, and a plan that touched all of
	// them would have a blast radius its own type could not describe.
	Container string `json:"container"`
}

func (RevertContainerImageParams) actionType() ActionType { return ActionRevertContainerImage }

// Validate enforces the only bound this params struct can carry on its own: a
// well-formed container name. Everything that actually decides whether this
// revert is safe is a statement about live cluster state — does this container
// exist, does the workload have a previous revision at all, what image did
// that revision run, is it different from the one running now — and every one
// of those is answered where the cluster is read firsthand
// (internal/execution), never from a claim carried inside a plan
// that may have sat in an approval queue for an hour. Same division of labour
// as PatchResourceLimitsParams.Validate; see its doc comment.
func (p RevertContainerImageParams) Validate() error {
	if !containerNameRE.MatchString(p.Container) {
		return fmt.Errorf("container %q is not a valid container name (lowercase alphanumeric and '-', per Kubernetes DNS_LABEL)", p.Container)
	}
	return nil
}

// RevertContainerImageExecParams is the execution-time form of the params
// above: the container, plus the image the HUB resolved from the target
// workload's own ReplicaSet history at approval time. It is what
// PlanContent.Params carries for a RevertContainerImage plan, what the agent
// decodes and re-validates, and — with Image holding the CURRENT image
// instead — what PlanContent.Rollback carries as the compensating action.
//
// Deliberately NOT an ActionParams: it has no actionType() method, so it
// cannot be assigned to RemediationPlan.Params at all. That is the type
// system enforcing the invariant this action rests on — an image can only
// enter the system through code that resolved it from the cluster, because
// there is no plan shape, no persisted row and no model output that can hold
// one. It is a separate struct rather than an extra field on
// RevertContainerImageParams with an `omitempty` tag for exactly this reason:
// one struct with an optional image would be assignable to Params, and the
// only thing keeping a model-supplied image out would then be that
// parseProposedPlan happens not to read that key.
type RevertContainerImageExecParams struct {
	Container string `json:"container"`
	Image     string `json:"image"`
}

// Validate checks both fields as far as they can be checked without a cluster.
// The agent runs this too, before its Patch, on both the plan's params and its
// rollback (§10.3's agent-side re-validation) — one definition of "well-formed
// enough to execute", not two.
func (p RevertContainerImageExecParams) Validate() error {
	if !containerNameRE.MatchString(p.Container) {
		return fmt.Errorf("container %q is not a valid container name (lowercase alphanumeric and '-', per Kubernetes DNS_LABEL)", p.Container)
	}
	if p.Image == "" {
		return fmt.Errorf("image is required: a RevertContainerImage plan is only executable once the hub has resolved a concrete image from the workload's revision history")
	}
	if len(p.Image) > maxContainerImageLength {
		return fmt.Errorf("image reference is %d characters, above the %d-character maximum this action will write — refusing to treat something this long as a container image", len(p.Image), maxContainerImageLength)
	}
	if !containerImageRE.MatchString(p.Image) {
		return fmt.Errorf("image %q is not a well-formed container image reference (expected something like \"registry.example.com/team/app:1.2.3\" or \"...@sha256:...\")", p.Image)
	}
	return nil
}

// ProposedFile is one file's whole proposed new content — the only unit a
// repository change is made of.
//
// Content is the file exactly as it should read after the change, not a diff
// and not a patch. ARGUS computes the diff itself, from this against the file
// at the pinned synced commit, so there is no diff format for a model to get
// subtly wrong and no patch application step that could apply somewhere
// unintended.
//
// # Delete, and why it is its own field rather than empty Content
//
// BACKLOG.md "still open" #2: `AB1`'s finding named the correct fix for two
// overlapping HPAs as "delete one whole HPA manifest from the repo" (and
// `CRD-001`'s addendum reached the identical shape for a manifest naming a
// never-installed CRD), and until now there was no way for a plan to say
// that — a whole-file edit could create and replace a file's content, never
// remove it.
//
// Empty Content was deliberately NOT reused to mean "delete this file".
// OpenPRParams.Validate refusing empty content outright is correct and
// load-bearing elsewhere: a plan that accidentally clears a file (a decode
// failure upstream, a model that emitted the wrong field) must still be
// refused as malformed, not silently reinterpreted as an intentional
// deletion — the exact failure mode reusing empty content would invite. An
// explicit, boolean field is harder to misuse: Delete=true unambiguously
// means "remove Path", and Validate refuses a file that sets both Delete and
// non-empty Content, rather than silently picking one.
type ProposedFile struct {
	// Path is relative to the repository root. It is checked against the
	// binding's forbidden-path denylist and confined to the directory the
	// GitOps controller reports syncing, in internal/gitops, before anything
	// is read or written — a path here is a request, never an authorisation.
	Path string `json:"path"`
	// Content is the whole file as proposed. Must be empty when Delete is
	// true, and non-empty otherwise (Validate enforces both directions).
	Content string `json:"content"`
	// Delete asks for Path to be removed from the repository entirely,
	// instead of written with Content. See this type's own doc comment for
	// why this is a distinct field rather than an empty-Content convention.
	Delete bool `json:"delete,omitempty"`
}

// OpenPRParams is ActionOpenPR's typed parameter struct — "open a pull request
// setting these files to this content", the GitOps channel (DESIGN.md
// §10.1-10.2).
//
// # Why this is whole files rather than a field and a value
//
// Until 2026-08-28 this struct carried FilePath/FieldPath/NewValue/
// ExpectedCurrentValue: one scalar, in one file. That could express a small
// fraction of the fault catalogue's repository-channel fixes, because most of
// them are not one scalar in one plain-YAML file — they are a Helm values key,
// a Kustomize overlay patch, a probe block that has to be ADDED, or two files
// that have to move together. Those four fields are gone, and
// internal/orchestrator.UnmarshalPlanParams refuses a stored plan that still
// carries any of them rather than silently reading a change it can no longer
// perform. See internal/gitops/files.go for the full argument.
type OpenPRParams struct {
	// Repository identifies the target repo (e.g. "org/repo"). Resolving this
	// to an actual git remote/credential is execution-layer work (DESIGN.md
	// §18.5's confused-deputy discussion) — this package only carries the
	// identifier the plan names, and the hub resolves the repository from the
	// incident's own stored ownership regardless of what a plan claims.
	Repository string
	// Files is the change: one or more files, each with its whole proposed
	// content. At least one is required.
	Files []ProposedFile
}

// maxProposedFiles / maxProposedFileBytes / maxProposedTotalBytes bound one
// plan. Cost and blast-radius bounds, not security boundaries — the denylist
// and the source-directory confinement in internal/gitops are those. A "fix"
// spanning more files than this is a refactor, and a machine should not be
// opening one against somebody's cluster source in a single pull request.
const (
	maxProposedFiles      = 20
	maxProposedFileBytes  = 2 << 20 // 2 MiB, matching internal/gitops' manifest bound
	maxProposedTotalBytes = 8 << 20
)

// ErrNewValueEchoesRedactionMarker is returned by OpenPRParams.Validate() and
// PatchFieldParams.Validate() when proposed content carries redact.Marker —
// BUGS.md 112. internal/redact strips every ConfigMap/Secret data/stringData
// value (and every literal env value) before the object it lives on ever
// crosses the tunnel, replacing it with the fixed, exported Marker string so
// the model can see the field EXISTS without ever seeing what it holds.
// Nothing stops the model from proposing to write that same marker string back
// out as if it were the field's real content — which is exactly what happened
// live (BUGS.md 112: a plan proposing `RETRY_LIMIT: "[REDACTED]"` as a real
// ConfigMap value, approved, and shipped as a real GitHub pull request,
// example-org/argocd-argus-test#56). Exported as a sentinel, rather than a bare
// fmt.Errorf, specifically so RemediationPlan.ParamsOnlyValidationFailure can
// recognise this one failure with errors.Is and exclude it from correction
// eligibility — see that function's doc comment for why a second attempt
// against the same model cannot help here, unlike the empty-value checks
// beside it.
//
// The name is historical: it predates whole-file proposals, when the only
// thing a plan could write was a single `newValue`. It now guards the content
// of every proposed file, which is a strictly wider reach for the identical
// reason.
var ErrNewValueEchoesRedactionMarker = errors.New("proposed content echoes the redaction marker")

// Validate checks an OpenPR plan's params: that it names at least one file,
// that no file is named twice, that every file has a path and non-empty
// content within bounds, and that no proposed content echoes the redaction
// marker.
//
// It does NOT check paths against the forbidden-path denylist or the synced
// directory. That is deliberate: those checks need the binding, and they are
// made in internal/gitops.prepareChanges immediately before any read or write,
// which is the one place they cannot be skipped by a caller. Duplicating them
// here would create a second, driftable copy of the actual security boundary.
//
// BUGS.md 112: the redact.Marker check below refuses content that echoes the
// sentinel internal/redact substitutes for a value the model was structurally
// never shown, before the plan ever reaches an approver — and
// internal/gitops.ApplyFileEdit refuses it again at the byte-writing
// chokepoint, so a caller that reached that function by any other route still
// cannot commit the marker as if it were content.
func (p OpenPRParams) Validate() error {
	if len(p.Files) == 0 {
		return fmt.Errorf("files is required — a repository change is one or more files with their proposed content")
	}
	if len(p.Files) > maxProposedFiles {
		return fmt.Errorf("this plan names %d files, over the %d-file bound for one pull request", len(p.Files), maxProposedFiles)
	}
	total := 0
	seen := make(map[string]bool, len(p.Files))
	for _, f := range p.Files {
		path := strings.TrimSpace(f.Path)
		if path == "" {
			return fmt.Errorf("every proposed file must name a path")
		}
		if seen[path] {
			// Two contents for one path is a plan disagreeing with itself.
			// Reconciling that silently — last one wins — is how a pull request
			// ends up holding content nobody chose.
			return fmt.Errorf("%s appears twice: a file may be given one proposed content, not two", path)
		}
		seen[path] = true
		if f.Delete {
			// A delete carries no content at all — Content set alongside
			// Delete is the plan disagreeing with itself about what this
			// entry means, refused rather than silently picking one
			// interpretation over the other.
			if strings.TrimSpace(f.Content) != "" {
				return fmt.Errorf("%s is marked for deletion but also carries content — a file may be deleted or given new content, not both", path)
			}
			continue
		}
		if strings.TrimSpace(f.Content) == "" {
			return fmt.Errorf("%s has no content — a pull request that empties a file's content without deleting it is not a change ARGUS can express; set \"delete\": true to remove the file instead", path)
		}
		if len(f.Content) > maxProposedFileBytes {
			return fmt.Errorf("%s is %d bytes, over the %d-byte bound", path, len(f.Content), maxProposedFileBytes)
		}
		total += len(f.Content)
		if strings.Contains(f.Content, redact.Marker) {
			return fmt.Errorf("%w: the content proposed for %s contains %q — internal/redact strips every ConfigMap/Secret data/stringData value (and every literal env value) before the object it lives on ever crosses the tunnel, so the model was structurally never shown this value and has no basis to reproduce it; a human must supply the real value, not the marker that stood in for it", ErrNewValueEchoesRedactionMarker, path, redact.Marker)
		}
	}
	if total > maxProposedTotalBytes {
		return fmt.Errorf("this plan proposes %d bytes of file content, over the %d-byte bound for one pull request", total, maxProposedTotalBytes)
	}
	return nil
}

func (OpenPRParams) actionType() ActionType { return ActionOpenPR }

// RemediationPlan is a structured, typed description of ONE proposed fix
// for an incident. It is not free-text from a model and not an executable
// command string — it is exactly what DESIGN.md §18.3
// requires: something non-LLM code can inspect and decide about, never
// something that gets shell-executed or otherwise interpreted as a
// command.
type RemediationPlan struct {
	// IncidentID references the incident this plan proposes to fix
	// (domain.PrefixIncident-prefixed ID, e.g. "inc_..." — plain string
	// per this codebase's existing convention, matching how incident IDs
	// are already threaded through internal/api/analyze.go).
	IncidentID string

	// AnalysisID references the specific Analysis (domain.PrefixAnalysis,
	// "an_...") whose root cause this plan proposes to address. A plan
	// with no AnalysisID is unusual but not, on its own, a validation
	// failure this package enforces — a later task connecting this to the
	// investigation loop's real output is what would make this
	// consistently populated.
	AnalysisID string

	// ActionType names which of the closed set of actions this plan is.
	ActionType ActionType

	// TargetGVK, TargetNamespace, and TargetName identify the single
	// Kubernetes object (or, for ActionOpenPR, the logical target the PR
	// would change) this plan acts on. TargetGVK uses this codebase's
	// existing wire convention from internal/agent/tools.go:
	// "<apiVersion>/<Kind>" (e.g. "apps/v1/Deployment").
	TargetGVK       string
	TargetNamespace string
	TargetName      string

	// Params carries the action-specific parameters — exactly one of the
	// per-action params structs above (nothing outside this package can
	// implement ActionParams), and it must agree with ActionType (see
	// Validate).
	Params ActionParams

	// Reversible states whether this plan's action has a known,
	// straightforward compensating action (e.g. scaling back down,
	// closing an unmerged PR) versus one that doesn't (e.g. a restart that
	// already happened cannot be "un-restarted"). This is authored
	// alongside the plan, not computed by this package.
	Reversible bool

	// RiskLevel is this plan's risk classification
	// (DESIGN.md §9.3: deterministic rules first, LLM
	// second — that classification happens upstream of this package;
	// RemediationPlan just carries the resulting floor).
	RiskLevel RiskLevel

	// restoreVerified is PROJECT.md B171's provenance line, drawn the same
	// way ValidateRestore already draws it for the absolute minimums: true
	// only for a plan built by NewVerifiedRestorePlan below, which exists
	// only to turn an already-captured remediation_executions.rollback_params
	// row back into a plan. Unexported deliberately — an ordinary literal
	// RemediationPlan{...} in this or any other package can never set it,
	// so nothing can assert "trust me, this is an undo" without having gone
	// through the one constructor that actually requires a
	// CompensatingAction to say so. See RestoreVerified's doc comment for
	// what a caller (internal/api's live-state resource-limits bound) may
	// and may not infer from it.
	restoreVerified bool
}

// RestoreVerified reports whether this plan was built by
// NewVerifiedRestorePlan from an already-captured CompensatingAction, rather
// than authored (by a model or by a human) as a fresh proposal.
//
// # Why this exists (PROJECT.md B171)
//
// A PatchResourceLimits memory-limit RAISE is captured with a compensating
// action that RESTORES the live value read moments before the raise —
// ValidateRestore already established that this value is a description of
// observed reality, not a proposal, and dropped the absolute-minimum floor on
// exactly that basis. But the live-state half of this action's bounds
// (internal/execution's checkResourceLimitsBound, rule 2: "a
// memory limit may only be RAISED") runs unconditionally in preparePlan for
// every PatchResourceLimits plan, forward or undo, because until now nothing
// distinguished the two — so the undo of a raise, which necessarily LOWERS
// the limit back, was refused by the exact rule that makes the forward raise
// safe. The rule itself must not weaken: a model proposing to lower a memory
// limit into OOMKill territory is exactly the mistake it exists to catch.
// What was missing was a way to tell "the model proposed lowering this" apart
// from "we are putting back a value that was itself live moments ago,"
// provable rather than merely asserted.
//
// # What this reports, and what it does not
//
// True here is that provenance question, answered honestly: this plan's
// Params came from a CompensatingAction, which by construction
// (rollbackForResourceLimits, captured at the ORIGINAL forward execution,
// before that mutation) held a value read directly off the live container —
// never a value carried in from a request body, a model's proposedPlan, or
// any other caller-supplied claim. It is NOT a statement that the value is
// still safe to apply now — the resourceVersion precondition and the
// drift check in internal/api/rollback.go (comparing the current live value
// against what the forward change applied) are what answer that, and both
// still run for a restore exactly as they do for anything else. This flag
// only ever lets a caller distinguish "may this specific rule be relaxed
// because the direction of change is a restore, not a proposal" — it must
// never be read as "skip validation" or "skip the live-state checks" in
// general; every OTHER bound in checkResourceLimitsBoundRules (rules 1, 3,
// 4) applies to a verified restore exactly as it does to a forward plan.
func (p RemediationPlan) RestoreVerified() bool { return p.restoreVerified }

// NewVerifiedRestorePlan builds the RemediationPlan for an operator-initiated
// undo of one recorded CompensatingAction — the only place restoreVerified is
// ever set true, and therefore the only way RestoreVerified() can ever report
// true for a plan this package hands back to a caller.
//
// action.Params must already be decoded into the concrete ActionParams this
// action type carries (internal/orchestrator.UnmarshalPlanParams does this
// for internal/api/rollback.go's undoPlan) — this constructor does not decode
// raw bytes itself, both because internal/remediation must not import the
// package that owns that decode table (it is imported the other way) and
// because accepting an already-typed ActionParams is what makes the
// provenance argument checkable at all: params.actionType() is asserted
// against actionType below, so a caller cannot mismatch the two and cannot
// smuggle a hand-built params value through as if it had come from a captured
// action. The safety property rests on the CALLER only ever obtaining that
// ActionParams by decoding action.Params — see RestoreVerified's doc comment
// for what this does and does not license once built.
//
// Reversible is unconditionally true and RiskLevel is unconditionally
// RiskLow, matching the reasoning undoPlan's own literal construction
// already used before this constructor existed: an undo's own plan is
// reversible by construction (its inverse is the value the forward change
// applied, on the same row) and its risk is the floor for "putting a
// workload back where it was" — preparePlan re-derives the real floor
// against the resolved target regardless, so this is a starting point, not a
// claim relied upon on its own.
func NewVerifiedRestorePlan(actionType ActionType, params ActionParams, targetGVK, targetNamespace, targetName string) (RemediationPlan, error) {
	if params == nil {
		return RemediationPlan{}, fmt.Errorf("cannot build a restore plan for %q with no decoded params", actionType)
	}
	if params.actionType() != actionType {
		return RemediationPlan{}, fmt.Errorf("restore params type %T is for action %q, not %q", params, params.actionType(), actionType)
	}
	return RemediationPlan{
		ActionType:      actionType,
		Params:          params,
		TargetGVK:       targetGVK,
		TargetNamespace: targetNamespace,
		TargetName:      targetName,
		Reversible:      true,
		RiskLevel:       RiskLow,
		restoreVerified: true,
	}, nil
}

// Validate reports whether p is a structurally well-formed plan: a
// recognized ActionType, Params of the matching concrete type, a
// recognized RiskLevel, and non-empty target identification. It does not
// evaluate policy or confidence — that is Evaluate's job (gate.go).
// Validate returning a non-nil error is exactly the condition under which
// Evaluate produces a Blocked decision: an unrecognized/malformed plan is
// blocked outright, never silently passed through to the confidence/risk
// gate as if it were well-formed.
// Validate checks the params alone — the parts that need no knowledge of the
// target kind. The allowlist check, which does, lives in RemediationPlan.Validate
// where TargetGVK is available.
func (p PatchFieldParams) Validate() error {
	if strings.TrimSpace(p.FieldPath) == "" {
		return fmt.Errorf("fieldPath is required")
	}
	if strings.TrimSpace(p.NewValue) == "" {
		// An empty string and an absent field are different states of an object,
		// and a plan should say which it means. Clearing a field is a deletion,
		// which this action deliberately cannot express.
		return fmt.Errorf("newValue is required — PatchField sets a value and cannot clear a field")
	}
	if strings.ContainsAny(p.NewValue, "\n\r") {
		return fmt.Errorf("newValue spans more than one line")
	}
	// BUGS.md 112: the identical redact.Marker guard OpenPRParams.Validate()
	// carries. Not reachable today through PatchFieldPermitted's allowlist
	// (internal/remediation/patchfield.go) — every entry in it is a Service/
	// Ingress/HPA/Deployment-scheduling/PDB/CronJob field, and none of those
	// are the data/stringData/env-value field classes internal/redact
	// actually replaces with Marker, so a live PatchField plan cannot carry
	// this failure the way BUGS.md 112's OpenPR one did. Kept anyway,
	// unconditionally, as the same defense-in-depth reasoning that governs
	// the allowlist itself (patchfield.go's own header: "the mechanism is
	// general ... every path is written out, reviewed, and justified"): a
	// future allowlist entry that DID reach a redacted field class would
	// otherwise reintroduce exactly BUGS.md 112's defect with no test ever
	// having exercised the guard meant to catch it.
	if strings.Contains(p.NewValue, redact.Marker) {
		return fmt.Errorf("%w: newValue contains %q — this field's real value was withheld from the model at capture time (internal/redact), so the model has no basis to know or reproduce it; a human must supply the real value, not the marker that stood in for it", ErrNewValueEchoesRedactionMarker, redact.Marker)
	}
	if len(p.NewValue) > 512 {
		// The same bound RevertContainerImage's envelope uses, and for the same
		// reason: far above anything real, low enough that a runaway value cannot
		// be smuggled through a field meant to hold a port number or a duration.
		return fmt.Errorf("newValue is %d characters, which is longer than any value this action sets", len(p.NewValue))
	}
	return nil
}

func (p RemediationPlan) Validate() error {
	if !p.ActionType.Valid() {
		return fmt.Errorf("unrecognized action type %q", p.ActionType)
	}
	if p.Params == nil {
		return fmt.Errorf("params is required for action type %q", p.ActionType)
	}
	if p.Params.actionType() != p.ActionType {
		return fmt.Errorf("params type %q does not match action type %q", p.Params.actionType(), p.ActionType)
	}
	// PROJECT.md B145: every per-action TARGET/KIND eligibility check below —
	// "is this action even reachable for this kind at all" — runs BEFORE the
	// generic selfValidatingParams.Validate() call further down ("are the
	// values THIS action was given well-formed"), not after. Found live
	// 2026-09-06 (SCHED-054 re-run): CreateResourceParams.Validate()'s "data
	// is required" fired first for a ServiceAccount target with an empty
	// Data map (a ServiceAccount has no data concept at all), so
	// CreateResourcePermitted's real "this kind is not in the reviewed
	// allowlist" refusal was never reached — a categorically out-of-scope
	// target produced a misleading "just needs data" message instead of the
	// one that actually explains why it is refused. Ordered generally, not
	// patched only for CreateResource, because eligibility-before-values is
	// the correct order for any action type that carries both an allowlist
	// and a self-validating params type, not a fact specific to one of them.
	//
	// PatchField's reach is a table, not its name, so the authorisation check
	// belongs here — this is the first point at which both the target kind and
	// the requested path are known.
	//
	// A refusal surfaces as Blocked rather than NeedsApproval, which is the
	// honest classification: "the model asked to set a field it may not set" is a
	// problem with the proposal, not a risk judgement to hand an approver. The
	// message names the pair, because which half was wrong is the actionable part
	// (the same path is permitted on a Deployment and refused on a StatefulSet).
	if p.ActionType == ActionPatchField {
		params, ok := p.Params.(PatchFieldParams)
		if !ok {
			return fmt.Errorf("params type %T is not PatchFieldParams", p.Params)
		}
		if _, err := PatchFieldPermitted(p.TargetGVK, params.FieldPath); err != nil {
			return err
		}
	}
	// StructuredPatch's reach is defined by the SAME table PatchField uses,
	// applied once per operation — this task's own requirement 2: "EVERY path
	// in the list must pass through the EXACT SAME PatchFieldPermitted
	// allowlist check ... do not build a second, parallel allowlist." A plan
	// naming even one path outside the allowlist is invalid IN FULL: this loop
	// returns on the first refusal rather than collecting the rest and
	// silently proceeding with whatever remains, so the plan as a whole never
	// half-validates. That is also what makes the three exclusions
	// PatchFieldPermitted's own header comment documents as load-bearing
	// (spec.replicas, containers[*].image, containers[*].resources.limits.*)
	// apply here automatically, with no separate check: this function is the
	// only place either action type asks "is this path permitted," so there is
	// nothing here that could diverge from PatchField's own answer.
	if p.ActionType == ActionStructuredPatch {
		params, ok := p.Params.(StructuredPatchParams)
		if !ok {
			return fmt.Errorf("params type %T is not StructuredPatchParams", p.Params)
		}
		for i, op := range params.Ops {
			if _, err := PatchFieldPermitted(p.TargetGVK, op.FieldPath); err != nil {
				return fmt.Errorf("operation %d of %d: %w", i+1, len(params.Ops), err)
			}
		}
	}
	// AnnotateResource/LabelResource: the (kind, key) -> allowed-value
	// allowlist check, same placement reasoning as PatchField/
	// StructuredPatch above — this is the first point at which both the
	// target kind and the requested key/value are known. See
	// annotatelabel.go for why this is a SEPARATE table from
	// PatchFieldPermitted's, keyed directly on the literal key rather than a
	// dot-notation path.
	if p.ActionType == ActionAnnotateResource {
		params, ok := p.Params.(AnnotateResourceParams)
		if !ok {
			return fmt.Errorf("params type %T is not AnnotateResourceParams", p.Params)
		}
		if _, err := AnnotationPermitted(p.TargetGVK, params.Key, params.Value); err != nil {
			return err
		}
	}
	if p.ActionType == ActionLabelResource {
		params, ok := p.Params.(LabelResourceParams)
		if !ok {
			return fmt.Errorf("params type %T is not LabelResourceParams", p.Params)
		}
		if _, err := LabelPermitted(p.TargetGVK, params.Key, params.Value); err != nil {
			return err
		}
	}
	// DeleteResource: the enumerated (kind) allowlist, plus the honesty
	// check DESIGN.md §10.5 demands — a plan that deletes an object may
	// never claim to be reversible. Deletion loses the object's identity
	// (uid) and any data a PVC held, which no spec-level snapshot restores,
	// so Reversible=true here would be a plan lying about its own blast
	// radius to whatever renders it for an approver. Checked here (Blocked,
	// not NeedsApproval) because — like an unrecognised ActionType — this is
	// a problem with the PLAN itself, not a risk judgement call to hand a
	// human: gate.go's hard high-risk+irreversible floor already refuses an
	// honest (Reversible=false) DeleteResource plan from ever
	// auto-approving, so this check exists to stop a DISHONEST one from
	// looking safer than it is, not to duplicate that floor.
	if p.ActionType == ActionCordonNode || p.ActionType == ActionDrainNode {
		if err := NodeActionPermitted(p.ActionType, p.TargetGVK); err != nil {
			return err
		}
		if p.TargetNamespace != "" {
			return fmt.Errorf("a Node is cluster-scoped; %s must not name a namespace", p.ActionType)
		}
		if p.ActionType == ActionDrainNode && p.Reversible {
			return fmt.Errorf("a DrainNode plan may not declare itself reversible — evicted pods are recreated by their controllers elsewhere, not put back; set reversible to false and propose an uncordon separately if the node should take work again")
		}
	}
	if p.ActionType == ActionDeleteResource {
		if _, ok := p.Params.(DeleteResourceParams); !ok {
			return fmt.Errorf("params type %T is not DeleteResourceParams", p.Params)
		}
		if _, err := DeleteResourcePermitted(p.TargetGVK); err != nil {
			return err
		}
		if p.Reversible {
			return fmt.Errorf("a DeleteResource plan may not declare itself reversible — deletion is effectively irreversible: a spec-level snapshot cannot recreate an object's identity (uid) or recover a PersistentVolumeClaim's data, so every ownerReference into the deleted object would dangle. Set reversible to false")
		}
	}
	// CreateResource: the enumerated (kind) allowlist, plus the honesty
	// check createresource.go's own header comment gives for why a rollback
	// can never be represented through this codebase's reviewed mechanisms —
	// deleteResource's own allowlist (Pod, Job) does not include any kind
	// createResource can target, so a claimed Reversible=true here would
	// promise an undo path that does not exist, the identical dishonesty
	// DeleteResource's own check above refuses in the opposite direction.
	if p.ActionType == ActionCreateResource {
		if _, ok := p.Params.(CreateResourceParams); !ok {
			return fmt.Errorf("params type %T is not CreateResourceParams", p.Params)
		}
		if _, err := CreateResourcePermitted(p.TargetGVK); err != nil {
			return err
		}
		if p.Reversible {
			return fmt.Errorf("a CreateResource plan may not declare itself reversible — deleteResource's own allowlist (internal/remediation/deleteresource.go) does not include any kind createResource can target, so there is no representable compensating action through this codebase's reviewed delete mechanism. Set reversible to false; an operator can remove the created object by hand")
		}
	}
	// Value bounds, for the params types that have any (selfValidatingParams).
	// Checked here rather than only at execution time so that a plan whose
	// numbers are impossible never reaches an approver at all: Evaluate turns
	// a Validate failure into Blocked ("a data problem upstream ... not a risk
	// judgment call a human approver should be asked to make" — see gate.go),
	// which is the honest classification for "the model asked for a 2Ti
	// memory limit". Deliberately AFTER every eligibility check above — see
	// this function's own B145 comment for why.
	if v, ok := p.Params.(selfValidatingParams); ok {
		if err := v.Validate(); err != nil {
			return fmt.Errorf("invalid %s params: %w", p.ActionType, err)
		}
	}
	if !p.RiskLevel.Valid() {
		return fmt.Errorf("unrecognized risk level %q", p.RiskLevel)
	}
	if p.TargetName == "" {
		return fmt.Errorf("target name is required")
	}
	return nil
}

// ParamsOnlyValidationFailure reports whether p fails Validate() for a
// reason that is fixable by supplying a DIFFERENT Params value alone — nil
// Params (BUGS.md 109's exact shape: the model omitted params entirely, or
// its wire.Params failed to unmarshal) or a Params value that parsed into
// the right concrete type but failed its own bounds check
// (selfValidatingParams.Validate) — as opposed to every other way Validate
// can fail: an unrecognized ActionType, an unrecognized RiskLevel, a missing
// TargetName, a Params/ActionType type mismatch, or a PatchField/
// StructuredPatch path the allowlist refuses regardless of what value is
// proposed for it. Those are problems with the plan's IDENTITY or its
// AUTHORIZATION to touch a given field, not with the values inside an
// otherwise-permitted Params object — no corrected Params could ever satisfy
// them, so a caller (internal/api's analyze-time correction attempt, BACKLOG
// AG1) must not spend a correction attempt, or a human's trust in "this
// plan proposes to change field.Path with value X", on trying.
//
// Returns ("", false) when p.Validate() already passes (nothing to correct)
// or when it fails for a reason outside this narrow set. When true, reason
// is the exact Validate() error — the same text a caller would otherwise
// have used to build a Blocked decision's Reason, reused here so there is
// only one place that renders "why was this plan rejected" prose.
//
// BUGS.md 110 / BACKLOG.md AL1's explicit decision, carried forward into the
// whole-file grammar: an OpenPRParams rejected for what the model PRODUCED —
// no files, a file with no path, a file with no content, a duplicate path — is
// deliberately left ELIGIBLE for a correction attempt, not excluded the way
// the PatchField/StructuredPatch allowlist refusal below is. The two look
// superficially similar (both are rejections routed through this function),
// but they are different KINDS of failure: the allowlist refusal is a policy
// refusal of a field PATH itself, independent of any value — a corrected
// params object naming the exact same disallowed path fails identically no
// matter what accompanies it, so a correction attempt against it is provably
// wasted. An unusable file set is a refusal of the model's OUTPUT, and
// OpenPRParams.Validate already satisfies selfValidatingParams (below), so it
// falls into this function's generic "the Params value itself failed its own
// bounds check" branch same as any other — the same branch
// TestParamsOnlyValidationFailure_InvalidParamsValue already exercises. A
// model given the rejection text can plausibly produce a usable file set on a
// second try; unlike the allowlist case, success here is not provably
// impossible.
//
// BUGS.md 110's original instance of this — a fix needing one word changed
// inside a YAML block scalar, unexpressible as a single-line NewValue — is not
// a rejection at all any more. Whole-file content spans as many lines as the
// file does.
//
// Consistent with this package's one-shot-never-loop convention (BUGS.md 109):
// at most one attempt is spent either way, so the cost of being wrong here is
// one bounded LLM round trip before falling through to
// NeedsHumanInvestigation exactly as it would have with no correction
// mechanism at all — not a second doomed AutoApprove, and not a loop.
//
// BUGS.md 112's explicit decision, by contrast: content rejected for echoing
// redact.Marker (ErrNewValueEchoesRedactionMarker, above) IS excluded from
// correction eligibility, unlike the unusable-file-set case just described
// even though both are, mechanically, refusals of what the model produced
// rather than of a PATH, and both would otherwise fall into the same generic
// selfValidatingParams branch below. The reason is not about the failure's
// SHAPE, it is about what a correction attempt could possibly achieve: an
// unusable file set asks the model to produce something it is fully capable
// of producing. This case asks the
// model to propose a value it was structurally never shown in the first
// place — internal/redact drops the real bytes at capture time, in the
// agent, before they ever reach a prompt (non-negotiable 9) — so
// CorrectPlanParams's one bounded round trip would hand the SAME model the
// SAME rejection text and the SAME absence of information it had the first
// time. It cannot magically learn the real value on a second try; at best
// it produces a different guess, and at worst it echoes the marker again or
// invents a plausible-looking replacement that is factually wrong in a way
// nothing downstream can catch — arguably a worse outcome than the current
// Blocked-and-explained state, since a corrected plan LOOKS like it survived
// scrutiny. Spending a bounded LLM round trip, and a human approver's trust
// in a "corrected" plan, on an attempt that is provably no better-informed
// than the one that already failed is not the bet BUGS 109's mechanism
// exists to make. So this is excluded the same way the PatchField/
// StructuredPatch allowlist refusal is excluded (for a different, PATH-
// shaped reason) — both fall straight through to NeedsHumanInvestigation,
// with the Blocked reason telling a human plainly that the real value is
// unknown to ARGUS and must come from them.
func (p RemediationPlan) ParamsOnlyValidationFailure() (reason string, ok bool) {
	err := p.Validate()
	if err == nil {
		return "", false
	}
	if !p.ActionType.Valid() {
		return "", false
	}
	if p.Params == nil {
		return err.Error(), true
	}
	if p.Params.actionType() != p.ActionType {
		return "", false
	}
	// BUGS.md 112: excluded ahead of every other check, and via errors.Is
	// rather than by re-deriving the string, so this exclusion holds
	// regardless of which Validate() branch produced err (OpenPRParams and
	// PatchFieldParams both wrap ErrNewValueEchoesRedactionMarker the same
	// way) and regardless of what else Validate() might also be unhappy
	// about. See this function's own doc comment for why a correction
	// attempt cannot help here: the model that produced this plan was never
	// shown the real value, and a second attempt asks the same model the
	// same question with no new information.
	if errors.Is(err, ErrNewValueEchoesRedactionMarker) {
		return "", false
	}
	// The PatchField/StructuredPatch allowlist check is a policy refusal of
	// the FIELD PATH itself, independent of the value being written to it —
	// a corrected params object using the exact same disallowed path would
	// fail identically, so this is deliberately excluded here even though
	// PatchField/StructuredPatch are not among paramsSchemaHint's correctable
	// action types today anyway (belt and suspenders against that changing
	// without this exclusion being revisited).
	if p.ActionType == ActionPatchField {
		if params, ok := p.Params.(PatchFieldParams); ok {
			if _, permErr := PatchFieldPermitted(p.TargetGVK, params.FieldPath); permErr != nil {
				return "", false
			}
		}
	}
	if p.ActionType == ActionStructuredPatch {
		if params, ok := p.Params.(StructuredPatchParams); ok {
			for _, op := range params.Ops {
				if _, permErr := PatchFieldPermitted(p.TargetGVK, op.FieldPath); permErr != nil {
					return "", false
				}
			}
		}
	}
	// AnnotateResource/LabelResource's (kind, key) -> allowed-value allowlist
	// refusal is the identical KIND of policy refusal PatchField/
	// StructuredPatch's is above — of the (key, value) pair itself,
	// independent of anything else the plan could have said — so it is
	// excluded from correction eligibility for the same reason: a corrected
	// params value naming the same disallowed key, or the same key with a
	// value outside its allowed set, fails identically.
	if p.ActionType == ActionAnnotateResource {
		if params, ok := p.Params.(AnnotateResourceParams); ok {
			if _, permErr := AnnotationPermitted(p.TargetGVK, params.Key, params.Value); permErr != nil {
				return "", false
			}
		}
	}
	if p.ActionType == ActionLabelResource {
		if params, ok := p.Params.(LabelResourceParams); ok {
			if _, permErr := LabelPermitted(p.TargetGVK, params.Key, params.Value); permErr != nil {
				return "", false
			}
		}
	}
	// DeleteResource's kind refusal is a policy refusal of the TARGET KIND
	// itself, independent of anything else in the plan — excluded for the
	// same reason. A plan refused for declaring Reversible=true also falls
	// through to "not correctable" here: RiskLevel/TargetName-shaped
	// problems already do (see this function's final comment), and a
	// dishonest reversibility claim is the same kind of structural problem,
	// not a Params-value problem a corrected Params could fix.
	if p.ActionType == ActionDeleteResource {
		if _, permErr := DeleteResourcePermitted(p.TargetGVK); permErr != nil {
			return "", false
		}
	}
	// CreateResource's kind refusal is a policy refusal of the TARGET KIND
	// itself, independent of anything else in the plan — excluded for the
	// same reason DeleteResource's is immediately above. A plan refused for
	// declaring Reversible=true also falls through to "not correctable"
	// here, for the identical reason DeleteResource's dishonest-reversibility
	// refusal does.
	if p.ActionType == ActionCreateResource {
		if _, permErr := CreateResourcePermitted(p.TargetGVK); permErr != nil {
			return "", false
		}
	}
	if v, ok := p.Params.(selfValidatingParams); ok {
		if v.Validate() != nil {
			return err.Error(), true
		}
	}
	// RiskLevel/TargetName problems (or anything else Validate() might reject
	// in the future) are structural, not a Params-value problem — fall
	// through to "not correctable" rather than guessing.
	return "", false
}
