package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/api/resource"

	"argus/internal/remediation"
)

// ErrScaleFromZeroRefused is the sentinel behind the scale-from-zero
// guardrail below. It exists so handleApproveIncident can answer this ONE
// deliberate policy refusal with its own problem type and status, instead of
// burying it in the same generic "could not execute this remediation" 502
// that a disconnected cluster, an unresolvable owner chain or a signing
// failure produce — those mean "we tried and something broke", this means
// "we understood perfectly and are declining". Recognize it with errors.Is,
// never by matching the message text, which is prose and will be reworded.
var ErrScaleFromZeroRefused = errors.New("refusing to scale a workload up from zero replicas without explicit confirmation")

// GuardrailScaleFromZero/GuardrailGitOpsManaged are the stable identifiers
// GuardrailConfirmationIssuer binds a token to. Not the same string as the
// request body's boolean field name (confirmScaleFromZero) or the problem
// type (scale-from-zero-refused) — kept as its own small vocabulary so
// renaming either of those elsewhere can never silently change what a token
// is considered to confirm.
const GuardrailScaleFromZero = "scaleFromZero"

// liveReplicaCount reads spec.replicas off the live object fetchPrecondition
// just retrieved. The bool is "we actually know the current count", which is
// deliberately a different answer from "the count is zero": both checks below
// make a safety decision from this number, so an absent or non-numeric field
// must never silently become a convenient one.
//
// float64 is the only type encoding/json produces for a JSON number when
// decoding into map[string]any, and so the only case that matters in
// production. json.Number is accepted so a future caller that switches to a
// UseNumber decoder doesn't quietly start reporting every count as unknown,
// and int so tests can hand-build a spec map the obvious way.
func liveReplicaCount(spec map[string]any) (int, bool) {
	switch v := spec["replicas"].(type) {
	case float64:
		return int(v), true
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return 0, false
		}
		return int(n), true
	case int:
		return v, true
	}
	return 0, false
}

// ErrScaleBoundRefused is the sentinel behind checkScaleBound's refusal
// below — BUGS.md 95: this is a pre-flight rejection inside PreparePlan,
// before anything is signed, sent to the agent, or changed on the cluster,
// so it gets its own problem type mapped to 409 rather than falling into the
// generic "could not execute this remediation" 502 that a disconnected
// cluster or a signing failure produce. Same reasoning as
// ErrScaleFromZeroRefused right below it, and deliberately a DIFFERENT
// sentinel: this refusal has no confirmation override (an implausible jump
// stays implausible no matter how many times it is confirmed), so the two
// must stay distinguishable via errors.Is rather than merged into one type
// that would wrongly imply this one, too, can be waived with a token.
var ErrScaleBoundRefused = errors.New("refusing a replica count outside the sane bound for this workload's current size")

// checkScaleBound rejects a ScaleDeployment plan whose requested replica
// count is wildly disproportionate to the object's live current count —
// lld/08 §3's own example of what this exists to catch ("reject a 0->500
// jump as a plan-authoring bug, not a valid scale action"). A generous,
// not tight, bound: at least 50, or 5x the current count if that's larger
// — this is a backstop against a gross error, not a policy knob.
func checkScaleBound(currentSpec map[string]any, requestedReplicas int) error {
	// An unknown live count keeps its original meaning HERE: treated as 0,
	// which just yields the 50 floor below. That stays unchanged on purpose —
	// this check is a gross-error backstop, and refusing an unreadable count
	// is checkScaleFromZero's job. Doing it in both places would only mean
	// one of the two refusal messages is lying about why we stopped.
	current, _ := liveReplicaCount(currentSpec)
	ceiling := current * 5
	if ceiling < 50 {
		ceiling = 50
	}
	if requestedReplicas < 0 || requestedReplicas > ceiling {
		return fmt.Errorf("%w: requested replica count %d is out of a sane range given the current count %d (max %d) — refusing to execute what looks like a plan-authoring error", ErrScaleBoundRefused, requestedReplicas, current, ceiling)
	}
	return nil
}

// checkScaleFromZero refuses to scale a workload UP from a live count of
// zero unless a human has explicitly said to.
//
// The reasoning, which is the whole point of this function: a Deployment
// sitting at 0 replicas is almost never broken — it is TURNED OFF, by a
// person, on purpose, for maintenance, for cost, or because it is being
// retired. "Scale it back up" is therefore not the low-risk, reversible,
// obviously-correct fix it looks like from the outside; it silently reverses
// somebody's deliberate decision. Worse, it looks its most convincing exactly
// when it is most wrong: a Service with no endpoints whose Deployment sits at
// 0 reads to the analysis loop as a textbook, trivially-fixable fault, which
// is how a real plan came out ScaleDeployment 0->1 with riskLevel low,
// reversible true, gateOutcome AutoApprove and confidence 1.00 — the
// highest-trust verdict the autonomy gate can issue, for an action no human
// asked for.
//
// Why the check lives at the execution layer and not in internal/remediation,
// where risk and approval policy otherwise live: the autonomy gate only ever
// sees ScaleDeploymentParams, which carries the TARGET count and nothing
// else. "Is this a scale up FROM ZERO" is a statement about the object's LIVE
// state, so the gate structurally cannot answer it — its own doc comment says
// a relative-to-current check "belongs at the execution layer". And even if a
// plan did carry a claimed current count, that would be the model's assertion
// about the cluster, stale by however long the plan sat in the queue, rather
// than the count fetchPrecondition read from the API server moments ago for
// this very request. Same authority argument as the resourceVersion
// precondition next to it: live state, never a remembered claim.
//
// `confirmed` is the one and only way through, and it comes from an operator
// stating the intent in the approve request itself (confirmScaleFromZero —
// see internal/api/approvals.go) where it is recorded in the audit trail. Rejected
// alternatives, both of which would have made this guardrail theatre: a
// per-tenant setting or policy knob (switched on once, then quietly applies
// to every future plan, including auto-approved ones — the exact failure this
// exists to prevent), and inferring intent from the approver's capabilities
// (holding remediation:execute:inplace says what someone MAY do, never what
// they MEANT to do on this workload).
func checkScaleFromZero(currentSpec map[string]any, requestedReplicas int, confirmed bool) error {
	if requestedReplicas <= 0 {
		// Not what this guards. Scaling something down to (or holding it at)
		// zero takes capacity away rather than overriding a human's decision
		// to switch it off, and the autonomy gate already judges that on its
		// own merits. A negative count is checkScaleBound's to reject.
		return nil
	}
	if confirmed {
		return nil
	}

	current, known := liveReplicaCount(currentSpec)
	if !known {
		// FAIL CLOSED: an unreadable spec.replicas means we cannot rule out
		// that this workload is deliberately switched off, and the asymmetry
		// isn't close — a wrong refusal costs the operator one extra
		// deliberate click, a wrong execution restarts a workload somebody
		// turned off on purpose. Note this is not a routine omission being
		// tolerated: a live Deployment/StatefulSet always comes back from the
		// API server with a defaulted spec.replicas, so reaching this branch
		// means something genuinely unexpected was returned.
		return fmt.Errorf("%w: the target's live replica count could not be read (spec.replicas is missing or not a number), so ARGUS cannot rule out that this workload is deliberately switched off. If you do intend to scale it up, approve again with \"confirmScaleFromZero\": true to state that intent explicitly", ErrScaleFromZeroRefused)
	}
	if current == 0 {
		return fmt.Errorf("%w: this workload is currently scaled to 0 replicas, which is normally a deliberate act — switched off for maintenance, for cost, or because it is being retired — so ARGUS will not turn it back on on its own. If you do intend to turn it back on, approve again with \"confirmScaleFromZero\": true to state that intent explicitly; the confirmation is recorded in the audit trail", ErrScaleFromZeroRefused)
	}
	return nil
}

// --- PatchResourceLimits: live-state bounds and the pre-computed rollback ---

// patchResourceLimitsKinds is the set of workload Kinds a resource-limits
// patch may target. Narrower than restartablePodTemplateKinds on purpose:
// DaemonSet has a pod template too, but neither the argus-remediate
// ClusterRole (get/patch/update on deployments and statefulsets only) nor
// deploy/helm/argus-agent/templates/validatingadmissionpolicy.yaml's field
// restriction covers daemonsets, so a DaemonSet patch would be refused by
// the API server after this hub had already committed the incident to
// Executing and burned the approval. Refusing it here means the operator
// gets a plain "not supported" answer with nothing recorded.
var patchResourceLimitsKinds = map[string]bool{
	"Deployment":  true,
	"StatefulSet": true,
}

// maxRequestIncreaseFactor bounds how much a single PatchResourceLimits plan
// may raise a request relative to the container's live request.
//
// This is the one bound that exists specifically for the "raising a request
// can make a pod unschedulable" hazard. It is a gross-error backstop, not a
// capacity check — the hub cannot cheaply know what any node has free (there
// is no metrics or node-capacity read on this path, and a scheduler
// simulation is a different feature). What it can know is that a real fix to
// an OOMKilling container moves a request by a factor, not an order of
// magnitude: 4x turns 128Mi into 512Mi, which is a generous headroom
// increase, while catching the unit slip (128Mi -> 128Gi, 1000x) and the
// hallucinated round number that would leave the workload Pending forever.
//
// Deliberately applied to requests only. A LIMIT increase costs nothing at
// schedule time (limits are not scheduled against), so bounding it
// proportionally would refuse the single most common legitimate use of this
// action — a container OOMKilled against a limit that is 10x too small —
// while preventing nothing. The absolute ceilings in
// internal/remediation.PatchResourceLimitsParams.Validate are what stop an
// absurd limit.
const maxRequestIncreaseFactor = 4

// requestFactorFloorMemory / requestFactorFloorCPU are the absolute
// magnitudes below which maxRequestIncreaseFactor above does NOT apply.
//
// Why this exists (found live, T5, 2026-09-17). A container running nginx
// under a 4Mi memory request/limit was OOMKilled on every start; the
// investigation was correct, the plan (request 4Mi -> 64Mi, limit 4Mi ->
// 128Mi) was correct, the cluster's own dry run accepted it — and the hub
// refused it at approval time, because 64Mi is 16x 4Mi. The factor bound had
// no absolute floor, which makes it strictest exactly where the starting
// value is most obviously wrong: the lower the broken request, the smaller
// the 4x ceiling, and "OOMKilled against a request an order of magnitude too
// small" is the canonical case this whole action exists to fix. A guardrail
// that blocks the fix in proportion to how broken the workload is has the
// sign of its own hazard backwards.
//
// The hazard the factor bounds is unschedulability, and that is a property of
// the ABSOLUTE size of a request against a node's allocatable, never of the
// ratio to what the container asked for before. So the factor is applied only
// once the post-patch request is large enough for the hazard to be real at
// all. 128Mi of memory and a quarter of a core are below the idle headroom of
// any node that can run a kubelet, so no increase landing under them can leave
// a pod Pending — while every slip the factor exists to catch is orders of
// magnitude above them (128Mi -> 128Gi is 1024x this floor, and Validate's own
// 64Gi/32-core ceilings sit far above it too).
//
// Deliberately the smallest floor that unblocks the observed case rather than
// the largest that could be argued for. Both values were chosen so that every
// refusal this function was already known to make still holds — in particular
// the 20Mi -> 150Mi memory request refused live under BUGS.md 95, and the
// 100m -> 500m CPU request that guards the MilliValue rounding trap below. A
// floor is a widening of a safety control, so it buys exactly one thing and
// leaves the rest alone.
//
// This is a floor on the CEILING, not a licence: an increase is refused unless
// it is within EITHER the 4x factor OR this absolute floor, so nothing that was
// permitted before is permitted less, and nothing above the floor is permitted
// more. The honest limit of that: a container whose request is 4Mi and whose
// real working set is 512Mi is still refused here, because 512Mi is neither
// within 4x nor under the floor. That refusal is correct — a jump of that size
// is a capacity decision rather than a symptom fix, and the recourse is the
// workload's source, with a human reading the diff.
const (
	requestFactorFloorMemory = "128Mi"
	requestFactorFloorCPU    = "250m"
)

// containerResources is one container's live cpu/memory requests and limits,
// as quantity strings exactly as the API server serialized them. Strings
// rather than resource.Quantity because these values are also what the
// compensating action carries back over the wire, and round-tripping the
// server's own canonical form ("128Mi", not "134217728") keeps a rollback
// record a human can read against the manifest they know.
//
// An empty field means "not set on the live container" — a real, distinct
// state from zero, and the one that makes this action refuse to proceed (see
// checkResourceLimitsBound).
type containerResources struct {
	MemoryLimit   string
	MemoryRequest string
	CPULimit      string
	CPURequest    string
}

// liveContainerResources digs one named container's current resources out of
// the spec fetchPrecondition already read. Locating the container (and failing
// closed when it cannot be located, or when the object's shape is not what a
// Deployment/StatefulSet's should be) is findPodTemplateContainer's job below;
// what this adds is the one further fail-closed rule specific to resources: a
// value that is present but not a string is an error, never a silent skip. A
// malformed quantity read as "unset" would be indistinguishable from a
// genuinely unset field, and unset is a state this action treats as "refuse to
// guess".
func liveContainerResources(spec map[string]any, container string) (containerResources, error) {
	c, err := findPodTemplateContainer(spec, container)
	if err != nil {
		return containerResources{}, err
	}

	// A container with no resources block at all is a valid object and a
	// valid answer: every field comes back empty, and
	// checkResourceLimitsBound is what refuses to introduce one.
	resources, _ := c["resources"].(map[string]any)
	limits, _ := resources["limits"].(map[string]any)
	requests, _ := resources["requests"].(map[string]any)

	live := containerResources{}
	if live.MemoryLimit, err = quantityString(limits, "memory"); err != nil {
		return containerResources{}, fmt.Errorf("container %q: limits.memory: %w", container, err)
	}
	if live.CPULimit, err = quantityString(limits, "cpu"); err != nil {
		return containerResources{}, fmt.Errorf("container %q: limits.cpu: %w", container, err)
	}
	if live.MemoryRequest, err = quantityString(requests, "memory"); err != nil {
		return containerResources{}, fmt.Errorf("container %q: requests.memory: %w", container, err)
	}
	if live.CPURequest, err = quantityString(requests, "cpu"); err != nil {
		return containerResources{}, fmt.Errorf("container %q: requests.cpu: %w", container, err)
	}
	return live, nil
}

// findPodTemplateContainer digs ONE named container out of a workload spec's
// pod template — the shared walk behind liveContainerResources above and
// liveContainerImage below, which need the same container out of the same spec
// for two different reasons and must never disagree about whether it exists.
// Extracted rather than copied precisely because the not-found branch is a
// safety decision (see below) and two copies of a safety decision is one copy
// too many.
//
// Fails closed on every path where it cannot be certain what it found, and the
// reasons are worth keeping next to the code:
//
//   - no spec.template[.spec][.containers] -> error. On a real
//     Deployment/StatefulSet these fields are required, so reaching one of
//     these branches means we are not looking at what we think we are looking
//     at, and patching a container inside an object whose shape we don't
//     recognize is exactly the case to refuse.
//   - the named container is absent -> error. This is the important one, for
//     both callers. A strategic-merge patch keyed on an unmatched container
//     name does not fail; it ADDS a container to the pod template. So "the
//     name is wrong" and "we are about to append a new container to somebody's
//     workload" are the same request, and the only place to tell them apart is
//     against the live object. The agent re-checks this independently before
//     its own Patch for the same reason.
//   - a container entry that isn't an object -> error, never a silent skip: a
//     list we cannot fully read is one where "the container is absent" and "we
//     failed to parse the entry that holds it" are indistinguishable.
//
// The returned map is the live container as decoded, so a caller reads its own
// fields off it (resources, image) rather than this function growing a
// per-caller result type.
func findPodTemplateContainer(spec map[string]any, container string) (map[string]any, error) {
	template, ok := spec["template"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("the live object has no spec.template — refusing to patch a container on an object whose shape could not be read")
	}
	podSpec, ok := template["spec"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("the live object has no spec.template.spec — refusing to patch a container on an object whose shape could not be read")
	}
	containers, ok := podSpec["containers"].([]any)
	if !ok || len(containers) == 0 {
		return nil, fmt.Errorf("the live object has no spec.template.spec.containers — refusing to patch a container on an object whose shape could not be read")
	}

	for _, raw := range containers {
		c, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("the live object has a malformed entry in spec.template.spec.containers — refusing to patch without being able to read every container")
		}
		if name, _ := c["name"].(string); name == container {
			return c, nil
		}
	}

	names := make([]string, 0, len(containers))
	for _, raw := range containers {
		if c, ok := raw.(map[string]any); ok {
			if name, _ := c["name"].(string); name != "" {
				names = append(names, name)
			}
		}
	}
	// Wraps ErrContainerNotInPodTemplate so a caller reading a HISTORICAL pod
	// template (fetchReplicaSetRevision) can tell "this container did not exist
	// in that revision" — a fact — apart from "we could not read that object" —
	// a failure. For the live target both are refusals, so the distinction
	// changes nothing there.
	return nil, fmt.Errorf("%w: no container named %q (it has: %s) — refusing to execute, because a patch keyed on an unmatched container name would ADD a container rather than change one", ErrContainerNotInPodTemplate, container, strings.Join(names, ", "))
}

// quantityString reads one resource key out of a limits/requests map. Absent
// is fine (""); present-but-not-a-string is an error, because the only thing
// the API server ever serializes there is a quantity string, so anything else
// means we are misreading the object.
func quantityString(m map[string]any, key string) (string, error) {
	raw, ok := m[key]
	if !ok || raw == nil {
		return "", nil
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("expected a quantity string, got %T", raw)
	}
	return s, nil
}

// checkResourceLimitsBound is the live-state half of this action's bounds —
// the checks internal/remediation.PatchResourceLimitsParams.Validate
// structurally cannot make, because they are all comparisons against values
// only the cluster knows. Same division of labour, and same reasoning, as
// checkScaleBound/checkScaleFromZero above: absolute sanity in the plan
// schema, relative-to-live judgement here, where the number was read from the
// API server moments ago rather than asserted by a model minutes ago.
//
// The rules, each with the failure it exists to prevent:
//
//  1. Every field the plan sets must already be set on the live container.
//     Introducing a request or limit where there was none changes the pod's
//     QoS class and therefore its eviction order under node pressure — a
//     bigger and differently-shaped decision than raising a ceiling — and it
//     makes the compensating action unrepresentable (the undo would have to
//     say "delete this field", which the typed params cannot say; see
//     PatchResourceLimitsParams' doc comment).
//  2. A memory limit may only be RAISED. This is the "reject a limit below
//     current usage-relevant floors" rule, and the live limit is the only
//     usage-relevant floor available cheaply: the container is running under
//     it right now, so it is a value we know the workload survives, whereas
//     nothing on this path knows the container's actual working set. Lowering
//     a memory limit is how a working container becomes an OOMKilled one, and
//     doing it in place — where the effect is a rolling restart into a
//     smaller box — is the worst way to find out the new value was too small.
//     Reducing memory is a considered capacity change that belongs in Git,
//     through the pullRequest channel, with a human reading the diff.
//  3. A request may not be raised by more than maxRequestIncreaseFactor, OR
//     to more than requestFactorFloorMemory/requestFactorFloorCPU, whichever
//     of the two is the larger allowance. Guards the unschedulable-pod
//     failure; see both constants for why that hazard needs an absolute floor
//     as well as a ratio, and what went wrong live without one.
//  4. Requests may never exceed limits, comparing each request against the
//     limit that will be in force AFTER this patch (the new value if the plan
//     sets one, the live value otherwise). Validate already catches the case
//     where one plan sets both; this catches the far more likely one, where a
//     plan raises a request against a limit it never mentions. The API server
//     would reject that too — but only after the approval was spent and the
//     incident moved to Executing.
//
// A CPU limit, unlike a memory limit, may be lowered (rule 2 is memory-only):
// exceeding a CPU limit throttles a container, it does not kill it, so the
// asymmetry is real rather than a convenience. It still may not go below the
// CPU request in force after the patch (rule 4).
//
// ErrResourceLimitsBoundRefused is this function's (and
// checkRequestUnderLimit's) sentinel — BUGS.md 95, live on rke2: a
// memoryRequest 7.5x the container's live value was correctly refused here,
// entirely before ExecuteApprovedPlan ever contacts the agent, yet came back
// as the same 502 remediation-execution-failed a real cluster failure would.
// Nothing was signed, recorded as Executing, or sent to the cluster — the
// incident stayed at AwaitingApproval — so this is exactly the "we understood
// perfectly and are declining" case ErrScaleFromZeroRefused's doc comment
// describes, not a failed execution attempt.
//
// checkResourceLimitsBound wraps every exit of checkResourceLimitsBoundRules
// (below) with this sentinel in one place, rather than at each of that
// function's several return statements (or checkRequestUnderLimit's): a
// single seam that every current and future rule is covered by automatically,
// and one a plain unit test can assert against directly (see
// TestCheckResourceLimitsBoundWrapsItsSentinel) without needing PreparePlan's
// DB/cluster context.
var ErrResourceLimitsBoundRefused = errors.New("refusing a resource limits patch that fails a live-state bound")

// ErrRollbackCaptureRefused marks every failure to CAPTURE a compensating
// action before execution — the "we could not write down how to undo this, so
// we will not do it" refusal that each rollbackFor* function makes.
//
// It exists for the reason BUGS.md 95 gave for ErrResourceLimitsBoundRefused,
// observed again live on 2026-09-17 (T5) for this different family of refusal:
// a rollback-capture failure came back from POST .../approve as
// `502 remediation-execution-failed`, "Could not execute this remediation",
// which reads as the cluster having refused a change ARGUS attempted. Nothing
// was attempted. Nothing was signed, sent, or recorded, the incident stayed at
// AwaitingApproval, and the reason was entirely ARGUS's own — exactly the
// class every sibling sentinel in this file already answers 409 for.
//
// Wrapped by captureRollback at each capture site rather than inside the
// rollbackFor* functions themselves, so the undo builders stay plain functions
// of their arguments (unit-testable without knowing about HTTP dispatch) and
// there is one seam a new action type is covered by automatically.
var ErrRollbackCaptureRefused = errors.New("refusing a change whose undo could not be captured")

// ErrCreateResourceContradictsEvidence is PROJECT.md B161's sentinel — the
// "we understood perfectly and are declining" class every sibling sentinel
// in this file already carries (see ErrScaleBoundRefused's own doc comment
// for that framing), for a CreateResource plan whose own Data contradicts
// the hub's recorded investigation evidence (llm.CheckPlanValueAgreement).
// Like ErrScaleBoundRefused and unlike ErrGitOpsManagedRefused, this has NO
// confirm-and-retry override: a value that disagrees with what was actually
// observed does not become correct by an operator confirming intent, so
// there is nothing honest a guardrail token could mean here. Recognize it
// with errors.Is, never by matching the message text (which carries the
// specific mismatched keys/values and will read differently every time).
var ErrCreateResourceContradictsEvidence = errors.New("refusing a CreateResource plan whose own parameter values contradict the hub's recorded investigation evidence")

// captureRollback wraps a rollbackFor* result in ErrRollbackCaptureRefused.
// Returns the compensating action unchanged on success, including a legitimate
// nil (the action types with no representable inverse).
func captureRollback(rollback *remediation.CompensatingAction, err error) (*remediation.CompensatingAction, error) {
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrRollbackCaptureRefused, err)
	}
	return rollback, nil
}

// restoreVerified comes from RemediationPlan.RestoreVerified() and relaxes
// exactly one rule: the memoryLimit-may-only-be-raised bound below. See
// checkResourceLimitsBoundRules' field table for why that single flag is the
// whole of PROJECT.md B171, and internal/remediation.NewVerifiedRestorePlan
// for why it cannot be forged by a caller (the field it reads is unexported
// and set in exactly one place, from a compensating action captured off live
// state before the forward mutation — never from a request body).
func checkResourceLimitsBound(live containerResources, p remediation.PatchResourceLimitsParams, restoreVerified bool) error {
	if err := checkResourceLimitsBoundRules(live, p, restoreVerified); err != nil {
		return fmt.Errorf("%w: %s", ErrResourceLimitsBoundRefused, err)
	}
	return nil
}

// checkResourceLimitsBoundRules is checkResourceLimitsBound's actual rule
// set, unwrapped — split out purely so the sentinel wrap above has one place
// to live rather than one per return statement.
func checkResourceLimitsBoundRules(live containerResources, p remediation.PatchResourceLimitsParams, restoreVerified bool) error {
	type field struct {
		name        string
		requested   string
		liveValue   string
		isRequest   bool
		mayDecline  bool   // false => this field may only ever be raised
		factorFloor string // requests only: absolute magnitude below which the factor bound does not apply
	}
	fields := []field{
		// mayDecline is restoreVerified, not a literal false — PROJECT.md
		// B171. A memory limit may only ever be RAISED by a forward plan,
		// because lowering the ceiling a running container already lives
		// under is how a working workload becomes an OOMKilled one. But the
		// undo of a raise is a decrease by definition, so a literal false
		// here made every captured undo of this field unexecutable while the
		// product recorded and displayed it as reversible. A verified restore
		// is not a fresh proposal: its value was read off the live container
		// moments before the forward change, so the workload demonstrably ran
		// under it. Only this one field, only this one direction — every other
		// rule below (no introducing an absent limit, the request-increase
		// factor ceiling, and rule 4's post-patch request<=limit check) still
		// applies to an undo exactly as it does to a forward plan.
		{"memoryLimit", p.MemoryLimit, live.MemoryLimit, false, restoreVerified, ""},
		{"memoryRequest", p.MemoryRequest, live.MemoryRequest, true, true, requestFactorFloorMemory},
		{"cpuLimit", p.CPULimit, live.CPULimit, false, true, ""},
		{"cpuRequest", p.CPURequest, live.CPURequest, true, true, requestFactorFloorCPU},
	}

	for _, f := range fields {
		if f.requested == "" {
			continue
		}
		if f.liveValue == "" {
			return fmt.Errorf("container %q has no %s set today, and this action will not introduce one: adding a request or limit where none exists changes the pod's QoS class and eviction order, which is a deliberate capacity decision for a human to make in the workload's source, not an in-place fix", p.Container, f.name)
		}
		requested, err := resource.ParseQuantity(f.requested)
		if err != nil {
			// Unreachable through the gate (Validate parsed the same string),
			// kept because "unreachable" plus "would otherwise skip a safety
			// comparison" is the wrong pair of properties to leave behind.
			return fmt.Errorf("%s %q is not a valid quantity", f.name, f.requested)
		}
		liveQ, err := resource.ParseQuantity(f.liveValue)
		if err != nil {
			return fmt.Errorf("container %q's live %s (%q) is not a valid quantity — refusing to execute a change whose starting point could not be read", p.Container, f.name, f.liveValue)
		}

		if !f.mayDecline && requested.Cmp(liveQ) < 0 {
			return fmt.Errorf("%s %s is below the container's current %s (%s) — this action only ever raises a memory limit, because lowering the ceiling a running container is already living under is how a working workload becomes an OOMKilled one; reduce it through the workload's source instead", f.name, f.requested, f.name, f.liveValue)
		}
		if f.isRequest {
			// Scaled through MilliValue, not Value: Quantity.Value() rounds a
			// sub-unit CPU quantity UP to whole cores ("100m" reads back as 1),
			// which would silently turn this into a 4-cores ceiling for every
			// small CPU request and let a 40x increase through. MilliValue is
			// exact for both the millicore and the byte scale.
			ceiling := resource.NewMilliQuantity(liveQ.MilliValue()*int64(maxRequestIncreaseFactor), liveQ.Format)
			// The absolute floor below which the factor does not apply at all
			// — see requestFactorFloorMemory/CPU for why the ratio is the
			// wrong measure of an unschedulability hazard at small sizes. The
			// ceiling becomes whichever of the two is HIGHER, so this only
			// ever relaxes the bound for a request that is small in absolute
			// terms, never tightens it.
			floorNote := ""
			if f.factorFloor != "" {
				floor, err := resource.ParseQuantity(f.factorFloor)
				if err != nil {
					// A malformed constant is a programming error, not an
					// operator's problem: fall back to the pure factor bound
					// rather than skipping the check.
					logger.Error("a resource-limits factor floor does not parse; applying the factor with no floor",
						slog.String("field", f.name), slog.String("factor_floor", f.factorFloor),
						slog.Int("factor", maxRequestIncreaseFactor))
				} else if ceiling.Cmp(floor) < 0 {
					ceiling = &floor
					floorNote = fmt.Sprintf(", and above the %s below which that factor is not applied", f.factorFloor)
				}
			}
			if requested.Cmp(*ceiling) > 0 {
				return fmt.Errorf("%s %s is more than %dx the container's current %s (%s)%s — refusing what looks like a plan-authoring error, since a request this much larger is likely to leave the pod unschedulable and the workload with fewer running replicas than it started with", f.name, f.requested, maxRequestIncreaseFactor, f.name, f.liveValue, floorNote)
			}
		}
	}

	// Rule 4, against the post-patch limits rather than the plan's own view.
	if err := checkRequestUnderLimit("memory", p.MemoryRequest, live.MemoryRequest, p.MemoryLimit, live.MemoryLimit); err != nil {
		return err
	}
	return checkRequestUnderLimit("cpu", p.CPURequest, live.CPURequest, p.CPULimit, live.CPULimit)
}

// checkRequestUnderLimit compares the request that will be in force after
// this patch against the limit that will be in force after it, for one
// resource. Either side may come from the plan or from the live object;
// "unset on both" is not a violation (nothing to compare).
func checkRequestUnderLimit(resourceName, requestedRequest, liveRequest, requestedLimit, liveLimit string) error {
	effRequest := firstNonEmpty(requestedRequest, liveRequest)
	effLimit := firstNonEmpty(requestedLimit, liveLimit)
	if effRequest == "" || effLimit == "" {
		return nil
	}
	req, err := resource.ParseQuantity(effRequest)
	if err != nil {
		return fmt.Errorf("%s request %q is not a valid quantity", resourceName, effRequest)
	}
	lim, err := resource.ParseQuantity(effLimit)
	if err != nil {
		return fmt.Errorf("%s limit %q is not a valid quantity", resourceName, effLimit)
	}
	if req.Cmp(lim) > 0 {
		return fmt.Errorf("after this patch the %s request (%s) would exceed the %s limit (%s), which Kubernetes rejects outright — the plan must set both, or set the request no higher than the limit already in force", resourceName, effRequest, resourceName, effLimit)
	}
	return nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// singleAppliedValue returns the one value a PatchResourceLimits sets, or "" if
// it sets more than one.
//
// Empty is a real answer, not a failure: with two fields changing there is no
// single scalar to compare an undo against, so the undo falls back to the
// resourceVersion precondition and says so rather than pretending to a check it
// cannot make.
func singleAppliedValue(p remediation.PatchResourceLimitsParams) string {
	var set []string
	for _, v := range []string{p.MemoryLimit, p.MemoryRequest, p.CPULimit, p.CPURequest} {
		if v != "" {
			set = append(set, v)
		}
	}
	if len(set) == 1 {
		return set[0]
	}
	return ""
}

// argusFieldManager is the field manager name ARGUS's own patches carry. Excluded
// from contention: a field ARGUS set on a previous execution is not contested, it
// is exactly what we expect to find.
const argusFieldManager = "argus-remediate"

// rollbackForScale builds the compensating action for a ScaleDeployment: scale
// back to the count the workload was on before.
//
// Trivially derivable, which is exactly why its absence was easy to miss — the
// two action types that needed real work to invert (resource limits, container
// image) both got one, and the one that needed a single integer did not.
// rollbackForCordon puts a node's schedulability back to what it was.
func rollbackForCordon(wasUnschedulable bool) (*remediation.CompensatingAction, error) {
	params, err := json.Marshal(remediation.CordonNodeParams{Unschedulable: wasUnschedulable})
	if err != nil {
		return nil, fmt.Errorf("marshal cordon rollback params: %w", err)
	}
	word := "schedulable"
	if wasUnschedulable {
		word = "cordoned"
	}
	return &remediation.CompensatingAction{
		ActionType:  remediation.ActionCordonNode,
		Params:      params,
		Description: "return the node to " + word,
	}, nil
}

func rollbackForScale(liveReplicas int) (*remediation.CompensatingAction, error) {
	params, err := json.Marshal(map[string]any{"replicas": liveReplicas})
	if err != nil {
		return nil, fmt.Errorf("marshal scale rollback params: %w", err)
	}
	return &remediation.CompensatingAction{
		ActionType:  remediation.ActionScaleDeployment,
		Params:      params,
		Description: fmt.Sprintf("scale back to %d replica(s)", liveReplicas),
	}, nil
}

// rollbackForResourceLimits builds the compensating action for a
// PatchResourceLimits plan from the values just read off the live container —
// DESIGN.md §10.3's "explicit rollback per action, captured
// before execution, so undo doesn't require re-analysis."
//
// The inverse is exact and minimal: it restores precisely the fields this
// plan overwrites, to precisely the values they held, and mentions no other
// field. That matters for two reasons. It means applying the rollback can
// never itself be a change nobody asked for (a rollback that re-asserted
// every resource value would silently revert an unrelated concurrent change
// to the ones this plan never touched), and it means the rollback satisfies
// the same schema and the same bounds as any other plan of this action type —
// including "the field must already be set", which holds by construction
// because these values were read from a live object where they were set.
//
// Returns nil only if there is nothing to undo, which Validate has already
// made impossible (at least one field must be set) — the nil branch exists so
// that a caller reading this function's signature is not invited to assume a
// non-nil result without checking, since the agent's refusal to execute
// without a rollback depends on that check being real.
func rollbackForResourceLimits(container string, live containerResources, p remediation.PatchResourceLimitsParams) (*remediation.CompensatingAction, error) {
	restore := remediation.PatchResourceLimitsParams{Container: container}
	var parts []string
	if p.MemoryLimit != "" {
		restore.MemoryLimit = live.MemoryLimit
		parts = append(parts, "memory limit "+live.MemoryLimit)
	}
	if p.MemoryRequest != "" {
		restore.MemoryRequest = live.MemoryRequest
		parts = append(parts, "memory request "+live.MemoryRequest)
	}
	if p.CPULimit != "" {
		restore.CPULimit = live.CPULimit
		parts = append(parts, "CPU limit "+live.CPULimit)
	}
	if p.CPURequest != "" {
		restore.CPURequest = live.CPURequest
		parts = append(parts, "CPU request "+live.CPURequest)
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("plan changes nothing, so no compensating action could be captured")
	}
	// Validated, not just assembled: a rollback that would itself be refused
	// as a plan is not a rollback, and finding that out now — before the
	// mutation — is the whole reason it is captured now.
	//
	// ValidateRestore, not Validate: the absolute minimums are a rule about
	// what ARGUS may propose, and these values were read off the live
	// container rather than proposed. Holding them to that floor made the fix
	// for a 4Mi-limited OOMKilling container unexecutable, because its undo
	// necessarily says "4Mi" — see ValidateRestore's own doc comment for the
	// live case and for why relaxing it reaches no cluster.
	if err := restore.ValidateRestore(); err != nil {
		return nil, fmt.Errorf("the compensating action built from the live container's values is not itself a valid plan (%w) — refusing to make a change that could not be undone by the same mechanism", err)
	}
	paramsJSON, err := json.Marshal(restore)
	if err != nil {
		return nil, fmt.Errorf("marshal rollback params: %w", err)
	}
	return &remediation.CompensatingAction{
		ActionType:  remediation.ActionPatchResourceLimits,
		Params:      paramsJSON,
		Description: fmt.Sprintf("restore container %q to %s", container, strings.Join(parts, ", ")),
	}, nil
}

// --- RevertContainerImage: resolving the previous revision from the cluster --

// revertContainerImageKinds is the set of workload Kinds an image revert may
// target, and it is narrower than both sets above: Deployment only.
//
// StatefulSet is excluded for a reason specific to this action rather than for
// the RBAC/admission-policy reason that excludes DaemonSet from
// patchResourceLimitsKinds. A Deployment's revision history is a set of
// ReplicaSets it owns, each carrying a full pod template and a
// deployment.kubernetes.io/revision annotation — real objects that the
// read-only argus-investigate grant can already list and that the agent can
// re-check for itself. A StatefulSet's (and DaemonSet's) history is a set of
// ControllerRevisions holding a compressed patch of the template, which is a
// different shape, is not in internal/agent's supportedGVKs, and is not granted
// to either ServiceAccount. Reverting a StatefulSet's image would therefore
// mean either trusting a target the agent cannot verify — the one property
// this whole action is built on — or adding a new read surface. Refused here
// with a plain answer instead, before anything is recorded.
var revertContainerImageKinds = map[string]bool{
	"Deployment": true,
}

// revisionAnnotation is the annotation the Deployment controller stamps on
// every ReplicaSet it creates, holding that ReplicaSet's revision number as a
// decimal string. It is Kubernetes' own record of rollout order and the only
// thing that makes "the previous revision" a well-defined phrase: ReplicaSet
// creationTimestamps have second granularity (two rollouts inside one second
// tie), names are hash suffixes with no order, and a scaled-to-zero old
// ReplicaSet looks exactly like a scaled-to-zero new one. So this annotation is
// load-bearing, and its absence is a refusal rather than something to work
// around — see fetchReplicaSetRevisions.
const revisionAnnotation = "deployment.kubernetes.io/revision"

// replicaSetRevision is one entry of a Deployment's revision history, reduced
// to the three things resolving a revert needs: which revision it was, what
// image the named container ran in it, and whether that container existed in
// it at all.
//
// HasContainer is a distinct field rather than "Image == \"\"" because the two
// are different facts with different consequences. A revision in which the
// container did not exist means the container was added or renamed since, so
// reverting "its image" is not a revert at all — that is a refusal. A revision
// in which the container exists but has an empty image is a malformed object we
// should not be reasoning from — also a refusal, but for a different reason
// and with a different message.
type replicaSetRevision struct {
	Name     string
	Revision int64
	// Image is the named container's image in this revision. Empty only when
	// HasContainer is false.
	Image        string
	HasContainer bool
}

// fetchReplicaSetRevisions reads the target Deployment's revision history — the
// ReplicaSets it owns — through the same two read-only tools the investigation
// loop uses, and reduces each to a replicaSetRevision.
//
// Why two tool calls per revision rather than one list call: get_owner_chain
// (direction "down") is the only tool that answers "which objects does THIS
// Deployment own", and it answers with identities, not objects — ownership must
// be established by ownerReference UID, never by the name-prefix heuristic
// (`<deployment>-<podtemplatehash>`) that a human reads a `kubectl get rs`
// listing with, because a name prefix is a coincidence and a UID is a fact. The
// per-ReplicaSet describe_resource is then what supplies the revision
// annotation and the pod template, neither of which list_resources' deliberately
// compact projection carries (internal/agent/tools.go's listResourceItem). A
// Deployment keeps revisionHistoryLimit (default 10) old ReplicaSets, so this is
// a bounded handful of reads on the approval path, all of them reads the
// investigate ServiceAccount could already make.
//
// An unparseable or missing revision annotation on ANY owned ReplicaSet fails
// the whole call, not just that entry. That is deliberate and it is the
// conservative direction: the annotation is what orders the history, so a
// ReplicaSet we cannot place in that order might BE the previous revision, and
// silently skipping it would mean happily reverting to an older image while
// believing it was the most recent one. Refusing costs an operator a clear
// error; guessing costs them a revert to the wrong release.
func (s *Executor) fetchReplicaSetRevisions(ctx context.Context, clusterID, namespace, deploymentName, container string) ([]replicaSetRevision, error) {
	argsJSON, err := json.Marshal(map[string]any{
		"gvk": "apps/v1/Deployment", "namespace": namespace, "name": deploymentName, "direction": "down",
	})
	if err != nil {
		return nil, fmt.Errorf("build get_owner_chain args: %w", err)
	}
	raw, err := s.gw.CallTool(ctx, clusterID, "get_owner_chain", argsJSON)
	if err != nil {
		return nil, fmt.Errorf("list the ReplicaSets owned by Deployment %s/%s: %w", namespace, deploymentName, err)
	}
	var nodes []struct {
		GVK       string `json:"gvk"`
		Namespace string `json:"namespace,omitempty"`
		Name      string `json:"name"`
		Resolved  bool   `json:"resolved"`
	}
	if err := json.Unmarshal(raw, &nodes); err != nil {
		return nil, fmt.Errorf("decode owner chain: %w", err)
	}

	revisions := make([]replicaSetRevision, 0, len(nodes))
	for _, n := range nodes {
		if !n.Resolved || gvkKind(n.GVK) != "ReplicaSet" {
			// A Deployment owns nothing but ReplicaSets, so anything else here
			// is either a dangling reference or a Kind this walk happened to
			// pick up; neither is part of the revision history.
			continue
		}
		rev, err := s.fetchReplicaSetRevision(ctx, clusterID, namespace, n.Name, container)
		if err != nil {
			return nil, err
		}
		revisions = append(revisions, rev)
	}
	return revisions, nil
}

// fetchReplicaSetRevision reads one ReplicaSet and reduces it to a
// replicaSetRevision. Split out of the loop above so the "what does one
// revision look like" decoding — annotation parsing, template digging — reads
// as one thing rather than as the middle of a fan-out.
func (s *Executor) fetchReplicaSetRevision(ctx context.Context, clusterID, namespace, name, container string) (replicaSetRevision, error) {
	argsJSON, err := json.Marshal(map[string]any{"gvk": "apps/v1/ReplicaSet", "namespace": namespace, "name": name})
	if err != nil {
		return replicaSetRevision{}, fmt.Errorf("build describe_resource args: %w", err)
	}
	raw, err := s.gw.CallTool(ctx, clusterID, "describe_resource", argsJSON)
	if err != nil {
		return replicaSetRevision{}, fmt.Errorf("describe ReplicaSet %s/%s: %w", namespace, name, err)
	}
	var result struct {
		Object json.RawMessage `json:"object"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return replicaSetRevision{}, fmt.Errorf("decode describe_resource result for ReplicaSet %s/%s: %w", namespace, name, err)
	}
	var obj struct {
		Metadata struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
		Spec map[string]any `json:"spec"`
	}
	if err := json.Unmarshal(result.Object, &obj); err != nil {
		return replicaSetRevision{}, fmt.Errorf("decode ReplicaSet %s/%s: %w", namespace, name, err)
	}

	annotation, ok := obj.Metadata.Annotations[revisionAnnotation]
	if !ok {
		return replicaSetRevision{}, fmt.Errorf("ReplicaSet %s/%s carries no %s annotation, so ARGUS cannot tell where it sits in this workload's rollout history — refusing to revert to a revision it cannot order", namespace, name, revisionAnnotation)
	}
	revision, err := strconv.ParseInt(strings.TrimSpace(annotation), 10, 64)
	if err != nil {
		return replicaSetRevision{}, fmt.Errorf("ReplicaSet %s/%s's %s annotation (%q) is not a number, so this workload's rollout history cannot be ordered — refusing to guess which revision came before which", namespace, name, revisionAnnotation, annotation)
	}

	rev := replicaSetRevision{Name: name, Revision: revision}
	// A ReplicaSet's spec.template is the same PodTemplateSpec a Deployment's
	// is — the controller copies it verbatim — so the reader used against the
	// live workload is correct here too, rather than merely convenient, and
	// using the same one is what guarantees the history and the live object are
	// read by identical rules. Its not-found branch is ordinary information
	// here (the container did not exist in this revision) while a shape problem
	// stays an error; the two are told apart by errors.Is, never by message.
	c, err := findPodTemplateContainer(obj.Spec, container)
	if err != nil {
		if errors.Is(err, ErrContainerNotInPodTemplate) {
			return rev, nil // HasContainer stays false
		}
		return replicaSetRevision{}, fmt.Errorf("ReplicaSet %s/%s (revision %d): %w", namespace, name, revision, err)
	}
	image, _ := c["image"].(string)
	rev.HasContainer = true
	rev.Image = image
	return rev, nil
}

// ErrContainerNotInPodTemplate distinguishes the one findPodTemplateContainer
// failure that is a FACT ABOUT THE OBJECT rather than a problem reading it: the
// pod template was perfectly readable and simply has no container by that
// name. For the live target that is still a refusal (a merge-key patch would
// append a container — see findPodTemplateContainer), but for a historical
// ReplicaSet it is ordinary information: the container did not exist in that
// revision. Callers that need to tell the two apart use errors.Is; nothing
// matches on message text.
var ErrContainerNotInPodTemplate = errors.New("no container by that name in this pod template")

// liveContainerImage reads the named container's CURRENT image off the spec
// fetchPrecondition already retrieved. This one value is both halves of the
// revert's framing: it is what the resolved previous image must differ from
// (otherwise there is nothing to do), and it is the compensating action —
// "put it back to this" — captured before the mutation because afterwards it is
// gone.
//
// An empty image on a live container is refused rather than tolerated. The API
// server requires the field, so an empty one means we are misreading the
// object; and an empty image is the one value that must never end up in a
// rollback, since applying it would be a patch that means nothing (or, with a
// strategic merge, silently nothing at all) at exactly the moment somebody is
// trying to undo a change.
func liveContainerImage(spec map[string]any, container string) (string, error) {
	c, err := findPodTemplateContainer(spec, container)
	if err != nil {
		return "", err
	}
	image, _ := c["image"].(string)
	if strings.TrimSpace(image) == "" {
		return "", fmt.Errorf("container %q on the live object has no image set — refusing to revert an image whose current value could not be read, since that value is also the only thing that could undo the change", container)
	}
	return image, nil
}

// resolvePreviousImage picks the image a RevertContainerImage plan will
// actually set, from the workload's own revision history and the image it is
// running right now. This is the function that makes "the model never chooses
// the image" true in practice: its inputs are a list of ReplicaSets read from
// the cluster moments ago and the live pod template, and nothing else.
//
// The rule, and every way it refuses:
//
//  1. The highest revision present is the CURRENT one. That is what the
//     Deployment controller guarantees — it stamps each new ReplicaSet with
//     max(existing)+1 — and it is why this needs no separate "which one is
//     live" lookup.
//  2. That current revision's image for this container must match the live pod
//     template. If it does not, the history and the live object disagree about
//     what is deployed, and "the previous revision" stops being well defined.
//     The honest case where this happens is a PAUSED rollout: `kubectl rollout
//     pause` followed by a template change leaves the Deployment carrying an
//     image no ReplicaSet has yet. Reverting there would mean undoing a pending,
//     unrolled-out change, which is a different act with a different intent, so
//     it is refused with a message that says so rather than quietly doing it.
//  3. Walking DOWN from there, the first revision whose image differs from the
//     live one is the target. Revisions whose image is identical are skipped
//     rather than being treated as "nothing to do": a revision can differ from
//     its successor in resources, env or replicas alone, and skipping those is
//     what makes this action find the last actual IMAGE change instead of
//     giving up whenever the most recent rollout happened to be something else.
//  4. A revision in which this container does not exist stops the walk with a
//     refusal, and does not silently skip to an older one. If the container was
//     added or renamed between then and now, "the image it ran before" is not a
//     question about this container, and reverting one field of a template that
//     has since been restructured is not a revert — it is an edit nobody
//     reviewed.
//  5. No previous revision at all (a first-ever deployment, or a history
//     pruned to revisionHistoryLimit: 0) is a CLEAN refusal, not an error about
//     something being broken. "There is nothing to revert to" is a perfectly
//     ordinary state of a healthy workload, and the message says that.
//  6. Every previous revision running the same image as the live one is also a
//     clean refusal: the last change to this workload was not an image change,
//     so this action has nothing to do.
//
// Returns the image and the name of the ReplicaSet it came from — the latter
// purely so the refusals and the audit trail can name the revision, which is
// what an operator needs to check the claim for themselves.
// isDigestPinned reports whether an image reference names an exact content
// digest (`...@sha256:...`) rather than a mutable tag.
//
// Why this matters here (WORKLOG §97 finding G4): "provably ran on this
// workload" is a claim about a REFERENCE, not about the bytes that reference
// resolves to. The agent's check in internal/agent/tools.go
// (verifyImageRanInThisWorkload) confirms the string being written matches a
// string recorded in one of this Deployment's own ReplicaSets — a real,
// valuable bound on a compromised HUB (it cannot invent an image, only pick
// one from genuine history). It says nothing about a registry that has since
// repointed a mutable tag: a workload that ran "app:stable" six revisions ago
// and reverts to "app:stable" today may pull entirely different bytes if the
// registry moved that tag in between. Digest references
// ("app@sha256:abc...") do not have this gap by construction — the reference
// IS the content.
//
// Deliberately not a refusal. This action already floors non-auto-approvable
// (risk.go) regardless of digest-ness, and most real workloads are not
// digest-pinned — refusing every mutable-tag revert would make the action
// nearly unusable for the common case it exists to help. Instead: prefer a
// digest when one is available (resolvePreviousImage's caller), and warn the
// approver plainly when the resolved target is not one, so the decision is
// informed rather than silent.
func isDigestPinned(image string) bool {
	return strings.Contains(image, "@sha256:")
}

// ErrImageRevertRefused is resolvePreviousImage's sentinel — same reasoning
// as ErrResourceLimitsBoundRefused: every one of that function's refusals is
// a pure judgement over data already read from the cluster (a paused
// rollout, no history to revert to, the container renamed since, the last
// change wasn't an image change), not a network call and not a mutation
// attempt, so a refusal here belongs in the same "we understood perfectly
// and are declining" 409 class as the two guardrails, not the generic 502 an
// actual failed agent/cluster call produces. Deliberately NOT applied to
// fetchReplicaSetRevisions'/fetchReplicaSetRevision's errors above this
// function — those mix a genuine tunnel/agent call with the annotation-shape
// checks nested inside it, and telling "the read failed" from "the object is
// unusable" apart there is a separate, deliberate change this pass left
// alone (BUGS.md 95).
//
// resolvePreviousImage wraps every exit of resolvePreviousImageRules (below)
// with this sentinel in one place — same "one seam, not one per return
// statement" shape as checkResourceLimitsBound/checkResourceLimitsBoundRules
// above, and for the same testability reason: a plain unit test can assert
// the sentinel directly (see TestResolvePreviousImageWrapsItsSentinel)
// without needing resolveRevertContainerImage's cluster/gateway context.
var ErrImageRevertRefused = errors.New("refusing to revert this container's image")

func resolvePreviousImage(revisions []replicaSetRevision, container, liveImage string) (image, fromReplicaSet string, err error) {
	image, fromReplicaSet, err = resolvePreviousImageRules(revisions, container, liveImage)
	if err != nil {
		return "", "", fmt.Errorf("%w: %s", ErrImageRevertRefused, err)
	}
	return image, fromReplicaSet, nil
}

// resolvePreviousImageRules is resolvePreviousImage's actual rule set,
// unwrapped — split out purely so the sentinel wrap above has one place to
// live rather than one per return statement.
func resolvePreviousImageRules(revisions []replicaSetRevision, container, liveImage string) (image, fromReplicaSet string, err error) {
	if len(revisions) == 0 {
		return "", "", fmt.Errorf("this workload owns no ReplicaSets, so it has no rollout history to revert to — nothing has been changed")
	}

	// Sorted descending, so index 0 is the current revision and the walk below
	// is simply "the rest, newest first". sort.Slice rather than a hand-rolled
	// max-then-scan: the ordering is the whole basis of "previous", and an
	// off-by-one in a bespoke scan would silently revert to the wrong release.
	ordered := make([]replicaSetRevision, len(revisions))
	copy(ordered, revisions)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Revision > ordered[j].Revision })

	current := ordered[0]
	if !current.HasContainer {
		return "", "", fmt.Errorf("container %q does not exist in this workload's current revision (%d, ReplicaSet %s) even though it is present on the live object — the rollout history and live state disagree, so ARGUS cannot tell what this container's previous image was", container, current.Revision, current.Name)
	}
	if current.Image != liveImage {
		return "", "", fmt.Errorf("this workload's current revision (%d, ReplicaSet %s) runs container %q with image %s, but the live pod template says %s — the two disagree, which normally means a template change has not been rolled out yet (a paused rollout). ARGUS will not revert an image while there is a pending change it did not make; resume or roll back the rollout first", current.Revision, current.Name, container, current.Image, liveImage)
	}

	previous := ordered[1:]
	if len(previous) == 0 {
		return "", "", fmt.Errorf("this workload has only one revision (%d) — a first deployment has no previous image to go back to, so there is nothing for this action to revert", current.Revision)
	}

	for _, rev := range previous {
		if !rev.HasContainer {
			return "", "", fmt.Errorf("container %q did not exist in revision %d (ReplicaSet %s), the newest revision before the current one that this action would have considered — the container was added or renamed since, so reverting just its image would not restore that revision; this needs a human", container, rev.Revision, rev.Name)
		}
		if rev.Image == "" {
			return "", "", fmt.Errorf("revision %d (ReplicaSet %s) records no image for container %q — refusing to revert to a revision ARGUS cannot read", rev.Revision, rev.Name, container)
		}
		if rev.Image != liveImage {
			return rev.Image, rev.Name, nil
		}
	}

	return "", "", fmt.Errorf("every previous revision of this workload (%d down to %d) runs container %q with the same image it is running now (%s) — the last change to this workload was not an image change, so there is nothing for this action to revert", previous[0].Revision, previous[len(previous)-1].Revision, container, liveImage)
}

// rollbackForContainerImage builds the compensating action for a
// RevertContainerImage plan: the same action type, aimed at the same container,
// carrying the image that container is running RIGHT NOW —
// DESIGN.md §10.3's "explicit rollback per action, captured
// before execution, so undo doesn't require re-analysis."
//
// This is the cheapest rollback of any action type in this codebase, and that
// is not a coincidence: the value it needs (the current image) is the same value
// the action already had to read in order to know whether the revert was a
// no-op. It costs one struct, and it means the undo of "go back a revision"
// never has to re-derive anything — no second look at the rollout history, no
// assumption that the history still looks the way it did.
//
// Validated rather than merely assembled, exactly as
// rollbackForResourceLimits does: a compensating action that would itself be
// refused as a plan is not a rollback, and finding that out now — before the
// mutation — is the entire reason it is captured now.
func rollbackForContainerImage(container, liveImage string) (*remediation.CompensatingAction, error) {
	restore := remediation.RevertContainerImageExecParams{Container: container, Image: liveImage}
	if err := restore.Validate(); err != nil {
		return nil, fmt.Errorf("the compensating action built from the live container's image is not itself valid (%w) — refusing to make a change that could not be undone by the same mechanism", err)
	}
	paramsJSON, err := json.Marshal(restore)
	if err != nil {
		return nil, fmt.Errorf("marshal rollback params: %w", err)
	}
	return &remediation.CompensatingAction{
		ActionType:  remediation.ActionRevertContainerImage,
		Params:      paramsJSON,
		Description: fmt.Sprintf("restore container %q to image %s", container, liveImage),
	}, nil
}

// resolveRevertContainerImage is the whole RevertContainerImage-specific half
// of ExecuteApprovedPlan, kept together here rather than inline in that
// function: it turns "revert container X" plus a live cluster into the exact
// params the envelope will carry and the compensating action that undoes them.
//
// Returns the EXECUTION params (container + resolved image) rather than
// re-marshaling the plan's own params, which is this action's one structural
// difference from the other three — see remediation.RevertContainerImageParams'
// doc comment for why the proposable form has no image field at all. The caller
// signs these bytes; nothing else in the flow diverges.
func (s *Executor) resolveRevertContainerImage(
	ctx context.Context, clusterID, targetGVK, targetNamespace, targetName string,
	spec map[string]any, params remediation.RevertContainerImageParams,
) (execParams json.RawMessage, rollback *remediation.CompensatingAction, digestWarning string, err error) {
	if !revertContainerImageKinds[gvkKind(targetGVK)] {
		return nil, nil, "", fmt.Errorf("a container image can only be reverted on a Deployment (its ReplicaSets are the rollout history this action reads); the resolved target is %s %s/%s", targetGVK, targetNamespace, targetName)
	}
	// FAIL CLOSED on an unreadable live container, for the same reason the
	// resources action does: both the "is this even a change" comparison and
	// the rollback are derived from this one value, so "we could not read it"
	// can only mean "we do not execute".
	liveImage, err := liveContainerImage(spec, params.Container)
	if err != nil {
		return nil, nil, "", err
	}
	revisions, err := s.fetchReplicaSetRevisions(ctx, clusterID, targetNamespace, targetName, params.Container)
	if err != nil {
		return nil, nil, "", err
	}
	previousImage, fromReplicaSet, err := resolvePreviousImage(revisions, params.Container, liveImage)
	if err != nil {
		return nil, nil, "", err
	}
	if !isDigestPinned(previousImage) {
		digestWarning = fmt.Sprintf(
			"the image being reverted to (%q, from %s) is a mutable tag, not a digest — if the registry has repointed this tag since the workload last ran it, the bytes pulled now may differ from what actually ran then",
			previousImage, fromReplicaSet)
	}

	exec := remediation.RevertContainerImageExecParams{Container: params.Container, Image: previousImage}
	// The resolved image goes through the same Validate the agent will re-run
	// on it. It came from the cluster, so this should never fire — which is
	// exactly why it is checked here: an image that fails validation agent-side
	// after the approval has been spent and the incident committed to Executing
	// is a failed remediation, while one caught here is a plan that was never
	// executable.
	if err := exec.Validate(); err != nil {
		return nil, nil, "", fmt.Errorf("the image read from revision ReplicaSet %s is not usable: %w", fromReplicaSet, err)
	}
	execParams, err = json.Marshal(exec)
	if err != nil {
		return nil, nil, "", fmt.Errorf("marshal revert container image params: %w", err)
	}
	if rollback, err = captureRollback(rollbackForContainerImage(params.Container, liveImage)); err != nil {
		return nil, nil, "", err
	}
	return execParams, rollback, digestWarning, nil
}

// readLiveFieldValue extracts one field from the live object at a concrete,
// already-selected field path — no wildcards, unlike the allowlist's own
// patterns — mirroring internal/agent/patchfield.go's nestedFieldAt exactly,
// segment for segment, since the two must walk the same object the same way
// or a value read here (for PatchField's rollback) could silently disagree
// with the value the agent re-reads immediately before patching.
//
// Kept as its own small walk rather than a dependency on internal/agent, for
// the same "hub-side package should not import agent-side k8s client code"
// reason restartablePodTemplateKinds is duplicated near the top of this file.
// Path NORMALISATION itself is NOT duplicated a second time, though —
// remediation.NormaliseFieldPath is the one piece both this function and the
// agent's copy need to agree on byte-for-byte, and internal/api already
// depends on internal/remediation for everything else PatchField needs
// (PatchFieldPermitted, PatchFieldParams), so importing the normaliser too
// costs nothing and removes a place the two could drift.
func readLiveFieldValue(liveObject json.RawMessage, fieldPath string) (value any, found bool, err error) {
	var obj map[string]any
	if err := json.Unmarshal(liveObject, &obj); err != nil {
		return nil, false, fmt.Errorf("decode live object: %w", err)
	}
	segments := strings.Split(remediation.NormaliseFieldPath(fieldPath), ".")
	var cur any = obj
	for i, seg := range segments {
		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[seg]
			if !ok {
				return nil, false, nil
			}
			cur = v
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil {
				return nil, false, fmt.Errorf("%q is a list, so %q must be an index", strings.Join(segments[:i], "."), seg)
			}
			if idx < 0 || idx >= len(node) {
				return nil, false, nil
			}
			cur = node[idx]
		default:
			return nil, false, fmt.Errorf("%q is a single value, so %q cannot be read from it", strings.Join(segments[:i], "."), seg)
		}
	}
	return cur, true, nil
}

// rollbackForPatchField builds the compensating action for a PatchField plan:
// the same field path, carrying the value it holds RIGHT NOW — DESIGN.md
// §10.3's "explicit rollback per action, captured before execution, so undo
// doesn't require re-analysis." Structurally the same move as
// rollbackForContainerImage (one field, captured as a string, re-validated as
// a plan in its own right before being trusted as an undo).
//
// currentValue is already the live value's %v-rendered string form — the same
// textual comparison internal/agent/patchfield.go's own no-op and
// ExpectCurrent checks use — so the rollback this builds and the value the
// agent will independently re-read moments before patching describe the same
// thing in the same notation.
func rollbackForPatchField(fieldPath, currentValue string) (*remediation.CompensatingAction, error) {
	restore := remediation.PatchFieldParams{FieldPath: fieldPath, NewValue: currentValue}
	if err := restore.Validate(); err != nil {
		return nil, fmt.Errorf("the compensating action built from the live object's value is not itself a valid plan (%w) — refusing to make a change that could not be undone by the same mechanism", err)
	}
	paramsJSON, err := json.Marshal(restore)
	if err != nil {
		return nil, fmt.Errorf("marshal rollback params: %w", err)
	}
	return &remediation.CompensatingAction{
		ActionType:  remediation.ActionPatchField,
		Params:      paramsJSON,
		Description: fmt.Sprintf("restore %s to %q", fieldPath, currentValue),
	}, nil
}

// rollbackForStructuredPatch is rollbackForPatchField generalized to N
// operations: BACKLOG.md F14's own note that F11 makes rollback "mechanically
// derivable per path" (BACKLOG.md's F11 entry cites this explicitly). One
// CompensatingAction reversing EVERY path this plan would write, not one per
// path — the atomicity argument structuredpatch.go's own header comment
// makes: a plan that patches N fields in one call is undone by patching the
// same N fields back in one call, not by N independent undos that could
// execute out of order or partially.
//
// currentValues is keyed by NormaliseFieldPath(op.FieldPath) — the same
// normalised form PatchFieldPermitted and PlannedFieldPaths key on — so the
// lookup cannot silently miss a value over a notational difference (bracket
// vs dot) between how an operation was authored and how its value was
// captured.
//
// Genuinely mechanical, per this task's own requirement to confirm that
// rather than merely assert it: this function does not know or care what
// fault the plan is fixing, does not special-case any field name, and does
// not consult patchfield.go's allowlist at all (that already happened before
// this is called — see the ActionStructuredPatch branch of PreparePlan
// below). It only pairs each op's path with the value PreparePlan already
// read from the SAME live object fetch every other branch uses, which is what
// makes this the same "capture before mutate" move as
// rollbackForScale/rollbackForResourceLimits/rollbackForContainerImage/
// rollbackForPatchField, applied uniformly across a list instead of hand-built
// per action type.
func rollbackForStructuredPatch(ops []remediation.StructuredPatchOp, currentValues map[string]string) (*remediation.CompensatingAction, error) {
	restoreOps := make([]remediation.StructuredPatchOp, 0, len(ops))
	descParts := make([]string, 0, len(ops))
	for _, op := range ops {
		current, found := currentValues[remediation.NormaliseFieldPath(op.FieldPath)]
		if !found {
			// A programming error, not a live-cluster condition: every op this
			// function is ever called with was already read into currentValues
			// by the same caller, in the same loop, before rollback is built.
			// Refused rather than silently building a partial rollback that
			// would leave one field with no way back.
			return nil, fmt.Errorf("no live value was captured for %s — refusing to build a rollback that could not restore every field this plan changes", op.FieldPath)
		}
		restoreOps = append(restoreOps, remediation.StructuredPatchOp{FieldPath: op.FieldPath, NewValue: current})
		descParts = append(descParts, fmt.Sprintf("%s to %q", op.FieldPath, current))
	}
	restore := remediation.StructuredPatchParams{Ops: restoreOps}
	if err := restore.Validate(); err != nil {
		return nil, fmt.Errorf("the compensating action built from the live object's values is not itself a valid plan (%w) — refusing to make a change that could not be undone by the same mechanism", err)
	}
	paramsJSON, err := json.Marshal(restore)
	if err != nil {
		return nil, fmt.Errorf("marshal rollback params: %w", err)
	}
	return &remediation.CompensatingAction{
		ActionType:  remediation.ActionStructuredPatch,
		Params:      paramsJSON,
		Description: "restore " + strings.Join(descParts, "; "),
	}, nil
}

// annotateOrLabelKeyValue reads the key/value an AnnotateResource/
// LabelResource plan carries, from its own typed params — a CHECKED
// assertion, matching every other branch in PreparePlan, because a
// zero-value params struct names no key at all and would otherwise silently
// address an empty-string key.
func annotateOrLabelKeyValue(plan remediation.RemediationPlan) (key, value string, err error) {
	switch plan.ActionType {
	case remediation.ActionAnnotateResource:
		params, ok := plan.Params.(remediation.AnnotateResourceParams)
		if !ok {
			return "", "", fmt.Errorf("plan is an AnnotateResource but its params are %T, not AnnotateResourceParams — refusing to execute a change whose key/value cannot be read", plan.Params)
		}
		return params.Key, params.Value, nil
	case remediation.ActionLabelResource:
		params, ok := plan.Params.(remediation.LabelResourceParams)
		if !ok {
			return "", "", fmt.Errorf("plan is a LabelResource but its params are %T, not LabelResourceParams — refusing to execute a change whose key/value cannot be read", plan.Params)
		}
		return params.Key, params.Value, nil
	default:
		return "", "", fmt.Errorf("annotateOrLabelKeyValue called for action type %q", plan.ActionType)
	}
}

// readLiveMetadataValue reads one literal key out of the live object's
// metadata.annotations or metadata.labels map — mapName is "annotations" or
// "labels". Deliberately NOT routed through readLiveFieldValue/
// NormaliseFieldPath: a real annotation/label key routinely contains "." and
// "/" (annotatelabel.go's own header comment explains why), and this
// package's dot-separated path notation would silently mis-split such a key
// into fabricated nested segments. A direct map lookup on the literal key
// has no such failure mode.
func readLiveMetadataValue(liveObject json.RawMessage, mapName, key string) (value string, found bool, err error) {
	var obj struct {
		Metadata struct {
			Annotations map[string]string `json:"annotations"`
			Labels      map[string]string `json:"labels"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(liveObject, &obj); err != nil {
		return "", false, fmt.Errorf("decode live object: %w", err)
	}
	m := obj.Metadata.Annotations
	if mapName == "labels" {
		m = obj.Metadata.Labels
	}
	v, ok := m[key]
	return v, ok, nil
}

// rollbackForAnnotateOrLabel builds the compensating action for an
// AnnotateResource/LabelResource plan whose key was already SET on the live
// object: the same key, carrying the value it holds RIGHT NOW — DESIGN.md
// §10.3's "explicit rollback per action, captured before execution".
// Structurally the same move as rollbackForPatchField; see that function's
// doc comment. Callers with no live value at all (a brand-new key) do not
// call this — see PreparePlan's own comment for why that case has no
// representable rollback.
func rollbackForAnnotateOrLabel(actionType remediation.ActionType, key, currentValue string) (*remediation.CompensatingAction, error) {
	var restore remediation.ActionParams
	var describeAs string
	switch actionType {
	case remediation.ActionAnnotateResource:
		p := remediation.AnnotateResourceParams{Key: key, Value: currentValue}
		if err := p.Validate(); err != nil {
			return nil, fmt.Errorf("the compensating action built from the live object's value is not itself a valid plan (%w) — refusing to make a change that could not be undone by the same mechanism", err)
		}
		restore, describeAs = p, "annotation"
	case remediation.ActionLabelResource:
		p := remediation.LabelResourceParams{Key: key, Value: currentValue}
		if err := p.Validate(); err != nil {
			return nil, fmt.Errorf("the compensating action built from the live object's value is not itself a valid plan (%w) — refusing to make a change that could not be undone by the same mechanism", err)
		}
		restore, describeAs = p, "label"
	default:
		return nil, fmt.Errorf("rollbackForAnnotateOrLabel called for action type %q", actionType)
	}
	paramsJSON, err := json.Marshal(restore)
	if err != nil {
		return nil, fmt.Errorf("marshal rollback params: %w", err)
	}
	return &remediation.CompensatingAction{
		ActionType:  actionType,
		Params:      paramsJSON,
		Description: fmt.Sprintf("restore %s %s to %q", describeAs, key, currentValue),
	}, nil
}
