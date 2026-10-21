// Package rolloutcheck answers two questions about a Deployment: how is its
// current rollout going — finished, moving, paused, or stuck past its
// progress deadline, and which new pods are holding it up — and, once it has
// settled, would the next rollout keep any replica serving. The first comes
// from the Deployment's status and its new ReplicaSet's pods; the second from
// the strategy's maxSurge and maxUnavailable resolved against the replica
// count, the way the Deployment controller resolves them.
package rolloutcheck

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// Verdicts the UI names (web/src/insight/tabs/AnalysisTabs.tsx).
const (
	VerdictStuck         = "stuck"
	VerdictInProgress    = "inProgress"
	VerdictPaused        = "paused"
	VerdictAtRisk        = "atRisk"
	VerdictSafe          = "safe"
	VerdictComplete      = "complete"
	VerdictNotApplicable = "notApplicable"
	VerdictUnknown       = "unknown"
)

// Report is what diagnose_rollout returns.
type Report struct {
	// Verdict is the live state when a rollout is under way; once settled,
	// the next-rollout verdict.
	Verdict  string  `json:"verdict"`
	Reason   string  `json:"reason"`
	Strategy string  `json:"strategy"`
	Replicas int32   `json:"replicas"`
	Risk     *Budget `json:"risk,omitempty"`
	Progress *Live   `json:"progress,omitempty"`
	// PolicyVerdict and PolicyReason are the next-rollout answer on its own
	// (atRisk, safe or notApplicable), shown beside a live verdict.
	PolicyVerdict string   `json:"policyVerdict"`
	PolicyReason  string   `json:"policyReason"`
	Notes         []string `json:"notes,omitempty"`
}

// Budget is the strategy's surge and unavailability allowance.
type Budget struct {
	MaxSurge       string `json:"maxSurge,omitempty"`
	MaxUnavailable string `json:"maxUnavailable,omitempty"`
	Message        string `json:"message,omitempty"`
	Remediation    string `json:"remediation,omitempty"`
}

// Live is the rollout in progress, from the Deployment's status.
type Live struct {
	State            string       `json:"state"`
	ConditionReason  string       `json:"conditionReason,omitempty"`
	ConditionMessage string       `json:"conditionMessage,omitempty"`
	Desired          int32        `json:"desired"`
	Updated          int32        `json:"updated"`
	Ready            int32        `json:"ready"`
	Available        int32        `json:"available"`
	Unavailable      int32        `json:"unavailable"`
	Total            int32        `json:"total"`
	NewReplicaSet    string       `json:"newReplicaSet,omitempty"`
	NotReadyPods     []WaitingPod `json:"notReadyPods,omitempty"`
}

// WaitingPod is a new-revision pod that is not Ready.
type WaitingPod struct {
	Name    string `json:"name"`
	Phase   string `json:"phase,omitempty"`
	Waiting string `json:"waiting,omitempty"`
	Node    string `json:"node,omitempty"`
}

const revisionAnnotation = "deployment.kubernetes.io/revision"
const maxWaitingPods = 10

// Check reports on d. ReplicaSets and pods may be nil: they only name the new
// revision and the pods it waits on.
func Check(d *appsv1.Deployment, replicaSets []*appsv1.ReplicaSet, pods []*corev1.Pod) Report {
	if d == nil {
		return Report{Verdict: VerdictUnknown, Reason: "No Deployment was given."}
	}
	desired := int32(1)
	if d.Spec.Replicas != nil {
		desired = *d.Spec.Replicas
	}
	rep := Report{Replicas: desired, Strategy: string(d.Spec.Strategy.Type)}
	if rep.Strategy == "" {
		rep.Strategy = string(appsv1.RollingUpdateDeploymentStrategyType)
	}
	rep.PolicyVerdict, rep.PolicyReason, rep.Risk = nextRollout(d, desired)
	if desired == 1 && rep.PolicyVerdict == VerdictNotApplicable {
		rep.Notes = append(rep.Notes, "With one replica, a node drain or an eviction still takes the workload down; a rollout is not the only way to lose it.")
	}

	live := progress(d, desired)
	if rs := newReplicaSet(d, replicaSets); rs != nil {
		live.NewReplicaSet = rs.Name
		if live.State != VerdictComplete {
			live.NotReadyPods = waitingPods(rs, pods)
		}
	}
	rep.Progress = live

	switch live.State {
	case VerdictStuck:
		rep.Verdict = VerdictStuck
		rep.Reason = fmt.Sprintf("The rollout passed its progress deadline (%s) with %d of %d replicas updated and %d available; it will not continue on its own.", live.ConditionReason, live.Updated, desired, live.Available)
		if w := waitingReasons(live.NotReadyPods); w != "" {
			rep.Reason += " The new pods are waiting on " + w + "."
		}
	case VerdictPaused:
		rep.Verdict = VerdictPaused
		rep.Reason = "The Deployment is paused: spec changes are recorded but not rolled out until it is resumed."
	case VerdictInProgress:
		rep.Verdict = VerdictInProgress
		rep.Reason = fmt.Sprintf("Rolling out: %d of %d replicas updated, %d available.", live.Updated, desired, live.Available)
	default:
		rep.Verdict, rep.Reason = rep.PolicyVerdict, rep.PolicyReason
		if rep.Verdict == VerdictNotApplicable && desired > 0 {
			rep.Verdict, rep.Reason = VerdictComplete, "The rollout is complete."
		}
	}
	return rep
}

// progress reads where the rollout stands. Stuck is the controller's own
// judgement (ProgressDeadlineExceeded); in progress is any sign the status
// does not yet describe the current spec fully rolled out.
func progress(d *appsv1.Deployment, desired int32) *Live {
	st := d.Status
	l := &Live{
		Desired: desired, Updated: st.UpdatedReplicas, Ready: st.ReadyReplicas,
		Available: st.AvailableReplicas, Unavailable: st.UnavailableReplicas, Total: st.Replicas,
	}
	var cond *appsv1.DeploymentCondition
	for i := range st.Conditions {
		if st.Conditions[i].Type == appsv1.DeploymentProgressing {
			cond = &st.Conditions[i]
		}
	}
	if cond != nil {
		l.ConditionReason, l.ConditionMessage = cond.Reason, cond.Message
	}
	switch {
	case d.Spec.Paused:
		l.State = VerdictPaused
	case cond != nil && cond.Status == corev1.ConditionFalse && cond.Reason == "ProgressDeadlineExceeded":
		l.State = VerdictStuck
	case st.ObservedGeneration < d.Generation, st.UpdatedReplicas < desired, st.Replicas > st.UpdatedReplicas, st.AvailableReplicas < desired:
		l.State = VerdictInProgress
	default:
		l.State = VerdictComplete
	}
	return l
}

// nextRollout resolves the strategy against the replica count: would a
// rollout leave at least one replica available throughout?
func nextRollout(d *appsv1.Deployment, desired int32) (string, string, *Budget) {
	if desired == 0 {
		return VerdictNotApplicable, "Scaled to zero, so there is nothing a rollout could take down.", nil
	}
	if d.Spec.Strategy.Type == appsv1.RecreateDeploymentStrategyType {
		return VerdictAtRisk, fmt.Sprintf("The Recreate strategy stops all %d replicas before starting the new ones, so every rollout is an outage.", desired),
			&Budget{Message: "Recreate always removes the old pods first.", Remediation: "Use RollingUpdate with maxUnavailable 0 and maxSurge 1, unless the workload cannot run two versions at once."}
	}
	surge := intstr.FromString("25%")
	unavail := intstr.FromString("25%")
	if ru := d.Spec.Strategy.RollingUpdate; ru != nil {
		if ru.MaxSurge != nil {
			surge = *ru.MaxSurge
		}
		if ru.MaxUnavailable != nil {
			unavail = *ru.MaxUnavailable
		}
	}
	s := resolve(surge, desired, true)
	u := resolve(unavail, desired, false)
	if s == 0 && u == 0 {
		u = 1 // the controller's own fallback, so the rollout can move at all
	}
	b := &Budget{MaxSurge: surge.String(), MaxUnavailable: unavail.String()}
	if desired == 1 && u == 0 {
		// The new pod starts before the old one stops, but one replica has
		// no spare to lose: "safe" would overstate it.
		return VerdictNotApplicable, "With one replica, availability during a rollout depends on the new pod starting before the old one stops, which this strategy does.", b
	}
	if u >= desired {
		b.Message = fmt.Sprintf("maxUnavailable %s allows %d of %d replicas down at once, so a rollout can take them all.", unavail.String(), u, desired)
		b.Remediation = fmt.Sprintf("Set maxUnavailable to %s and keep maxSurge at least 1, so new pods start before old ones stop.", strconv.Itoa(int(maxInt32(desired-1, 0))))
		return VerdictAtRisk, "A rollout of this Deployment can take every replica down at once.", b
	}
	return VerdictSafe, fmt.Sprintf("A rollout keeps at least %d of %d replicas available (up to %d down, %d extra at a time).", desired-u, desired, u, s), b
}

// resolve turns an int-or-percent into a count of replicas: surge rounds up
// and unavailability rounds down, as the Deployment controller does.
func resolve(v intstr.IntOrString, replicas int32, roundUp bool) int32 {
	n, err := intstr.GetScaledValueFromIntOrPercent(&v, int(replicas), roundUp)
	if err != nil || n < 0 {
		return 0
	}
	return int32(n)
}

// newReplicaSet is the ReplicaSet this Deployment owns at its current
// revision, or the highest revision it owns when the annotation is missing.
func newReplicaSet(d *appsv1.Deployment, all []*appsv1.ReplicaSet) *appsv1.ReplicaSet {
	var owned []*appsv1.ReplicaSet
	for _, rs := range all {
		if rs == nil || rs.Namespace != d.Namespace {
			continue
		}
		if ownedBy(rs.OwnerReferences, "Deployment", d.Name, d.UID) {
			owned = append(owned, rs)
		}
	}
	if len(owned) == 0 {
		return nil
	}
	want := d.Annotations[revisionAnnotation]
	for _, rs := range owned {
		if want != "" && rs.Annotations[revisionAnnotation] == want {
			return rs
		}
	}
	sort.Slice(owned, func(i, j int) bool { return revision(owned[i]) > revision(owned[j]) })
	return owned[0]
}

func revision(rs *appsv1.ReplicaSet) int {
	n, _ := strconv.Atoi(rs.Annotations[revisionAnnotation])
	return n
}

// waitingPods lists the new revision's pods that are not Ready, with what
// they wait on — the pods a stuck or slow rollout is waiting for.
func waitingPods(rs *appsv1.ReplicaSet, pods []*corev1.Pod) []WaitingPod {
	var out []WaitingPod
	for _, p := range pods {
		if p == nil || p.Namespace != rs.Namespace || p.DeletionTimestamp != nil {
			continue
		}
		if !ownedBy(p.OwnerReferences, "ReplicaSet", rs.Name, rs.UID) || ready(p) {
			continue
		}
		w := WaitingPod{Name: p.Name, Phase: string(p.Status.Phase), Node: p.Spec.NodeName}
		for _, cs := range append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
			if cs.State.Waiting != nil && cs.State.Waiting.Reason != "" {
				w.Waiting = cs.State.Waiting.Reason
				break
			}
		}
		if w.Waiting == "" {
			for _, c := range p.Status.Conditions {
				if c.Type == corev1.PodScheduled && c.Status == corev1.ConditionFalse && c.Reason != "" {
					w.Waiting = c.Reason
				}
			}
		}
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if len(out) > maxWaitingPods {
		out = out[:maxWaitingPods]
	}
	return out
}

// ownedBy matches an owner by kind and UID, or by name where either UID is
// missing. The controller flag is not required: objects created by other
// tools, and some restored from backup, carry the reference without it.
func ownedBy(refs []metav1.OwnerReference, kind, name string, uid types.UID) bool {
	for _, r := range refs {
		if r.Kind != kind {
			continue
		}
		if r.UID != "" && uid != "" {
			if r.UID == uid {
				return true
			}
			continue
		}
		if r.Name == name {
			return true
		}
	}
	return false
}

// waitingReasons: the distinct reasons the new pods wait on, in order seen.
func waitingReasons(pods []WaitingPod) string {
	var out []string
	seen := map[string]bool{}
	for _, p := range pods {
		if p.Waiting != "" && !seen[p.Waiting] {
			seen[p.Waiting] = true
			out = append(out, p.Waiting)
		}
	}
	return strings.Join(out, ", ")
}

func ready(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

func maxInt32(a, b int32) int32 {
	if a > b {
		return a
	}
	return b
}
