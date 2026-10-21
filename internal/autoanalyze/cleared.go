package autoanalyze

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"

	"github.com/jackc/pgx/v5"

	"argus/internal/agent/health"
	"argus/internal/data"
	"argus/internal/orchestrator"
)

// Cleared-incident closure: the stale sweep's second question.
//
// # The gap
//
// An incident nobody has investigated sits in Detected, and before this the
// only ways out of Detected were a person, or its object being deleted (the
// gone check above). orchestrator's sweepSelfHealing closes incidents whose
// fault went away, but only after an investigation concluded, so with
// automatic analysis off (the default) a fault that cleared by itself stayed
// open forever. Observed 2026-10-13: a node blip on both lab clusters opened
// 45 incidents, one per pod on the NotReady nodes, and every one of them was
// still Detected hours after every node was Ready again.
//
// # The rule
//
// A Detected incident closes as Resolved (resolution_kind self_healed, derived
// by SetState) when both of these hold:
//
//   - Quiet: no new finding for the cluster's quiet period
//     (orchestrator.QuietPeriods, the validation sweeper's own number),
//     measured from the later of the incident's last finding and the moment
//     the cluster's current tunnel session opened. Silence only counts while
//     an agent was connected to break it.
//   - Healthy now: the object the incident is really about (existenceTarget)
//     reads healthy, or intentionally idle, when graded live by the same
//     internal/agent/health functions the agent's own tools use.
//
// Quiet alone is not enough. Some faults are reported once and never again
// while they persist (Kubernetes emits NodeNotReady on a pod once, however long
// the node stays down), so silence can mean "still broken". Healthy-now alone
// is not enough either: a flapping workload is healthy for a moment between
// failures. An object this package cannot grade (an unknown kind, a missing
// status) stays open; unknown never counts as healthy.
//
// Detected and AwaitingApproval are considered. A pending approval for a fault
// that has cleared asks a question nobody needs to answer, and the plan's
// preconditions (its target pod, its resourceVersion) have usually gone with
// it: closing withdraws it, with the withdrawal on the timeline. An open pull
// request still blocks closure. Every other state has an investigation behind
// it (sweepSelfHealing's territory) or an action in flight.

// maxStaleCandidates bounds how many quiet incidents one pass loads. Cheap
// rows; the expensive part is the tunnel call per checked incident, which
// maxStaleChecksPerSweep bounds separately.
const maxStaleCandidates = 1000

// RuleChecker re-runs the declarative rule that opened an incident against
// the live object (api.Server.RuleStillFires; its contract is
// orchestrator.AppliedValueVerifier's). evaluated is false when no rule
// opened it; err means the question could not be asked, never "cleared".
type RuleChecker interface {
	RuleStillFires(ctx context.Context, incidentID string) (evaluated, fires bool, detail string, err error)
}

// SetRuleChecker gives the stale sweep the rule re-run. Call once, before
// RunStaleObjectSweeper starts.
func (p *Poller) SetRuleChecker(r RuleChecker) { p.rules = r }

// clearedEligible: the states the cleared check may close from. Every open
// state with a legal edge to Resolved and nothing in flight: not
// Investigating, Executing or Validating (another writer owns those), not
// AwaitingMerge (closing would orphan an open pull request). The others are
// all "a person or ARGUS looked, or tried, and the incident is waiting", and
// a fault a person fixed after that must close like any other; before this,
// an incident fixed by hand after its investigation stayed open forever,
// because sweepSelfHealing only closes one that went quiet straight after
// its analysis (observed live, loop campaign 2026-10-13, S07).
func clearedEligible(state string) bool {
	switch state {
	case orchestrator.StateDetected, orchestrator.StateRecommendationReady,
		orchestrator.StateNeedsHumanInvestigation, orchestrator.StateDiagnosed,
		orchestrator.StateAwaitingApproval, orchestrator.StatePlanRejected,
		orchestrator.StateFailed, orchestrator.StateExecutionUnknown,
		orchestrator.StateValidationUnknown, orchestrator.StateReopened:
		return true
	}
	return false
}

// clearedTail says what had happened before the fault cleared, so the
// closure never claims less (or more) than the incident's own history.
func clearedTail(state string) string {
	switch state {
	case orchestrator.StateDetected:
		return "nothing was investigated or applied"
	case orchestrator.StateAwaitingApproval:
		return "the pending approval was withdrawn and nothing was applied"
	case orchestrator.StatePlanRejected:
		return "the rejected plan was never applied"
	case orchestrator.StateFailed, orchestrator.StateExecutionUnknown, orchestrator.StateValidationUnknown, orchestrator.StateReopened:
		return "an earlier change attempt is on this incident's history; this closure verified the fault is gone, not that the change caused it"
	}
	return "it was investigated and nothing was applied"
}

// quietEnough: no finding for the quiet period, counted from the later of
// the last finding and the moment the agent's current session opened.
func quietEnough(lastSeen, connectedSince time.Time, quiet time.Duration, now time.Time) bool {
	if quiet <= 0 {
		return false
	}
	from := lastSeen
	if connectedSince.After(from) {
		from = connectedSince
	}
	return now.Sub(from) >= quiet
}

// ruleClearedOutcome is the closure when the rule that opened the incident
// no longer holds. detail is RuleStillFires' own sentence.
func ruleClearedOutcome(c staleCandidate, detail string, quiet time.Duration, connectedSince, now time.Time) *clearedClosure {
	from := c.LastSeen
	if connectedSince.After(from) {
		from = connectedSince
	}
	return &clearedClosure{
		Summary: fmt.Sprintf("cleared on its own: no recurrence for at least %s, and the check that opened it, re-run now, says %s; %s",
			quiet.Round(time.Minute), detail, clearedTail(c.State)),
		Detail: map[string]any{
			"fromState": c.State,
			"checkedBy": "rule",
			"rule":      detail,
			"quietFor":  now.Sub(from).Round(time.Second).String(),
		},
	}
}

// periodicDetectorID is the agent detector that re-evaluates every condition
// it reports on a fixed interval and re-sends while it still holds
// (internal/agent/sweep_detector.go: its Go checkers and the declarative
// rules). Its silence is a result. Event-driven detectors report once per
// Kubernetes event, so theirs is not.
const periodicDetectorID = "k8s-sweep"

// onlyPeriodicFindings reports whether every finding on the incident came from
// the periodic sweep. False on any error: no evidence, no closure.
func (p *Poller) onlyPeriodicFindings(ctx context.Context, clusterID, incidentID string) bool {
	var total, periodic int
	err := data.InFleetScope(ctx, p.db.Pool, func(ctx context.Context, tx pgx.Tx, tenantID string) error {
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			return err
		}
		return tx.QueryRow(ctx,
			`SELECT count(*), count(*) FILTER (WHERE detector_id = $2) FROM findings WHERE incident_id = $1`,
			incidentID, periodicDetectorID).Scan(&total, &periodic)
	})
	return err == nil && total > 0 && total == periodic
}

// periodicClearedOutcome is the closure when the object cannot be graded and
// only the periodic sweep ever reported it.
func periodicClearedOutcome(c staleCandidate, quiet time.Duration, connectedSince, now time.Time) *clearedClosure {
	from := c.LastSeen
	if connectedSince.After(from) {
		from = connectedSince
	}
	return &clearedClosure{
		Summary: fmt.Sprintf("cleared on its own: the periodic check that reported it has re-run every pass for at least %s and no longer finds it; %s",
			quiet.Round(time.Minute), clearedTail(c.State)),
		Detail: map[string]any{
			"fromState": c.State,
			"checkedBy": "periodic-sweep",
			"quietFor":  now.Sub(from).Round(time.Second).String(),
		},
	}
}

// clearedClosure is the evidence for closing one incident as cleared.
type clearedClosure struct {
	Summary string
	Detail  map[string]any
}

// clearedOutcome decides whether candidate c has cleared, given the object
// its existence target named, as describe_resource returned it. Pure: the
// sweep supplies the session start, quiet period and clock.
func clearedOutcome(c staleCandidate, target, targetKind string, object json.RawMessage, connectedSince time.Time, quiet time.Duration, now time.Time) *clearedClosure {
	if !clearedEligible(c.State) || !quietEnough(c.LastSeen, connectedSince, quiet, now) {
		return nil
	}
	from := c.LastSeen
	if connectedSince.After(from) {
		from = connectedSince
	}
	verdict := liveVerdict(target, object, now)
	if verdict.Level != health.LevelHealthy && verdict.Level != health.LevelNeutral {
		return nil
	}
	state := string(verdict.Level)
	if verdict.Reason != "" {
		state += " (" + verdict.Reason + ")"
	}
	return &clearedClosure{
		Summary: fmt.Sprintf("cleared on its own: no recurrence for at least %s, and %s reads %s now; %s",
			quiet.Round(time.Minute), describeKey(target), state, clearedTail(c.State)),
		Detail: map[string]any{
			"fromState":   c.State,
			"checked":     target,
			"checkedWhat": targetKind,
			"level":       string(verdict.Level),
			"reason":      verdict.Reason,
			"quietFor":    now.Sub(from).Round(time.Second).String(),
		},
	}
}

// liveVerdict grades an object read from the cluster. The kind is taken from
// the key the object was read by, so a decode into the wrong type cannot
// happen silently. Kinds the health package does not grade are Unknown.
func liveVerdict(key string, object json.RawMessage, now time.Time) health.Verdict {
	unknown := health.Verdict{Level: health.LevelUnknown}
	gvk := strings.SplitN(key, "|", 2)[0]
	kind := gvk[strings.LastIndex(gvk, "/")+1:]
	decode := func(into any) bool { return json.Unmarshal(object, into) == nil }
	switch kind {
	case "Pod":
		var o corev1.Pod
		if !decode(&o) {
			return unknown
		}
		return health.Pod(&o, now)
	case "Node":
		var o corev1.Node
		if !decode(&o) {
			return unknown
		}
		return health.NodeVerdict(&o)
	case "Deployment":
		var o appsv1.Deployment
		if !decode(&o) {
			return unknown
		}
		return health.Workload(&o, now)
	case "ReplicaSet":
		var o appsv1.ReplicaSet
		if !decode(&o) {
			return unknown
		}
		return health.Workload(&o, now)
	case "StatefulSet":
		var o appsv1.StatefulSet
		if !decode(&o) {
			return unknown
		}
		return health.Workload(&o, now)
	case "DaemonSet":
		var o appsv1.DaemonSet
		if !decode(&o) {
			return unknown
		}
		return health.Workload(&o, now)
	case "Job":
		var o batchv1.Job
		if !decode(&o) {
			return unknown
		}
		return health.Workload(&o, now)
	case "CronJob":
		var o batchv1.CronJob
		if !decode(&o) {
			return unknown
		}
		return health.Workload(&o, now)
	case "PersistentVolumeClaim":
		var o corev1.PersistentVolumeClaim
		if !decode(&o) {
			return unknown
		}
		return health.Workload(&o, now)
	case "Service":
		var o corev1.Service
		if !decode(&o) {
			return unknown
		}
		return serviceVerdict(&o)
	case "PodDisruptionBudget":
		var o policyv1.PodDisruptionBudget
		if !decode(&o) {
			return unknown
		}
		return pdbVerdict(&o)
	}
	return conditionVerdict(object)
}

// serviceVerdict: a Service has no conditions, so healthy means it has the
// address its type promises: a cluster IP (or "None", headless), and for a
// LoadBalancer an ingress address too. Anything else is unknown, not
// unhealthy: this only ever has to say "the thing that was missing is there".
func serviceVerdict(s *corev1.Service) health.Verdict {
	if s.Spec.Type == corev1.ServiceTypeExternalName {
		return health.Verdict{Level: health.LevelHealthy}
	}
	if s.Spec.ClusterIP == "" {
		return health.Verdict{Level: health.LevelUnknown}
	}
	if s.Spec.Type == corev1.ServiceTypeLoadBalancer && len(s.Status.LoadBalancer.Ingress) == 0 {
		return health.Verdict{Level: health.LevelUnknown}
	}
	return health.Verdict{Level: health.LevelHealthy}
}

// pdbVerdict: healthy when the controller has computed the budget for the
// current spec and enough selected pods are healthy. A budget that selects
// nothing (expectedPods 0) is unknown: that may be the very fault.
func pdbVerdict(b *policyv1.PodDisruptionBudget) health.Verdict {
	st := b.Status
	if st.ObservedGeneration < b.Generation || st.ExpectedPods == 0 {
		return health.Verdict{Level: health.LevelUnknown}
	}
	if st.CurrentHealthy >= st.DesiredHealthy {
		return health.Verdict{Level: health.LevelHealthy}
	}
	return health.Verdict{Level: health.LevelDegraded, Reason: "BelowDesiredHealthy"}
}

// conditionVerdict grades a kind nothing above knows by the convention most
// controllers follow: a Ready condition, or failing that an Available one,
// on the object's own status. True is healthy, False is unhealthy; no such
// condition, or Unknown, is unknown. This is what lets the check cover
// operator kinds (a cert-manager Certificate, a cnpg Cluster) without a
// case for each. A condition only counts when it describes the current
// spec: one with an observedGeneration older than the object's is unknown.
func conditionVerdict(object json.RawMessage) health.Verdict {
	var o struct {
		Metadata struct {
			Generation int64 `json:"generation"`
		} `json:"metadata"`
		Status struct {
			Conditions []struct {
				Type               string `json:"type"`
				Status             string `json:"status"`
				Reason             string `json:"reason"`
				ObservedGeneration int64  `json:"observedGeneration"`
			} `json:"conditions"`
		} `json:"status"`
	}
	if json.Unmarshal(object, &o) != nil {
		return health.Verdict{Level: health.LevelUnknown}
	}
	for _, want := range []string{"Ready", "Available"} {
		for _, c := range o.Status.Conditions {
			if c.Type != want {
				continue
			}
			if c.ObservedGeneration != 0 && c.ObservedGeneration < o.Metadata.Generation {
				return health.Verdict{Level: health.LevelUnknown}
			}
			switch c.Status {
			case "True":
				return health.Verdict{Level: health.LevelHealthy, Reason: want}
			case "False":
				return health.Verdict{Level: health.LevelUnhealthy, Reason: c.Reason}
			}
			return health.Verdict{Level: health.LevelUnknown}
		}
	}
	return health.Verdict{Level: health.LevelUnknown}
}

// clearedTarget is what the cleared check grades: the workload when there is
// one, else the object the finding named. Unlike existenceTarget it never
// uses a plan's target, which is usually a pod that a rollout replaces.
func clearedTarget(c staleCandidate) (key, kind string) {
	return existenceTargetFor("", c.WorkloadKey, c.ObjectKey)
}

// normalizeNodeKey repairs the two Node key shapes incidents carry, so a read
// of the Node succeeds. A static pod's owner is its Node, and the workload key
// built from that owner takes the pod's namespace (`v1/Node|kube-system|n`);
// a Node event's involvedObject has no apiVersion, so its object key is
// `Node||n`. A Node is cluster-scoped and core/v1. Normalised at read time
// rather than where the keys are built, because those keys are incident
// identity (grouping, correlation) and changing them would split open
// incidents at upgrade.
func normalizeNodeKey(gvk string) string {
	if gvk == "Node" || gvk == "v1/Node" {
		return "v1/Node"
	}
	return gvk
}

// describeKey renders a `gvk|namespace|name` key as "Kind namespace/name".
func describeKey(key string) string {
	parts := strings.SplitN(key, "|", 3)
	if len(parts) != 3 {
		return key
	}
	kind := parts[0][strings.LastIndex(parts[0], "/")+1:]
	if parts[1] == "" || normalizeNodeKey(parts[0]) == "v1/Node" {
		return kind + " " + parts[2]
	}
	return kind + " " + parts[1] + "/" + parts[2]
}

// staleCheckLog remembers when each incident was last checked, so a pass
// that may check only maxStaleChecksPerSweep incidents rotates through the
// backlog. Without it the oldest quiet incidents, if still broken, were
// re-checked every pass and newer ones were never reached.
type staleCheckLog map[string]time.Time

// pick chooses up to n candidates: never-checked first, then least recently
// checked, keeping the query's oldest-first order among equals. It records
// the picks as checked at now and forgets incidents no longer candidates.
func (l *staleCheckLog) pick(candidates []staleCandidate, n int, now time.Time) []staleCandidate {
	if *l == nil {
		*l = staleCheckLog{}
	}
	live := make(map[string]bool, len(candidates))
	for _, c := range candidates {
		live[c.ID] = true
	}
	for id := range *l {
		if !live[id] {
			delete(*l, id)
		}
	}
	ordered := append([]staleCandidate(nil), candidates...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return (*l)[ordered[i].ID].Before((*l)[ordered[j].ID])
	})
	if len(ordered) > n {
		ordered = ordered[:n]
	}
	for _, c := range ordered {
		(*l)[c.ID] = now
	}
	return ordered
}

func candidateClusterIDs(cs []staleCandidate) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.ClusterID)
	}
	return out
}
