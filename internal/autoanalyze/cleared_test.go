package autoanalyze

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"

	"argus/internal/orchestrator"
)

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readyNode(ready corev1.ConditionStatus) *corev1.Node {
	return &corev1.Node{Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: ready}}}}
}

func replicas(n int32) *int32 { return &n }

func TestClearedOutcome(t *testing.T) {
	now := time.Date(2026, 10, 13, 14, 0, 0, 0, time.UTC)
	quiet := 15 * time.Minute
	longAgo := now.Add(-2 * time.Hour)
	healthyDS := &appsv1.DaemonSet{Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 3, NumberReady: 3}}
	const dsKey = "apps/v1/DaemonSet|kube-system|canal"

	for _, tc := range []struct {
		name           string
		state          string
		lastSeen       time.Time
		connectedSince time.Time
		key            string
		object         any
		wantClose      bool
	}{
		{"healthy workload, quiet, connected throughout", orchestrator.StateDetected, longAgo, longAgo.Add(-time.Hour), dsKey, healthyDS, true},
		{"recurred inside the quiet period", orchestrator.StateDetected, now.Add(-5 * time.Minute), longAgo, dsKey, healthyDS, false},
		// The agent reconnected 5 minutes ago: its silence before that proves nothing.
		{"quiet measured from the session start", orchestrator.StateDetected, longAgo, now.Add(-5 * time.Minute), dsKey, healthyDS, false},
		// Observed live (loop campaign S07): fixed by hand after its
		// investigation, it stayed open because sweepSelfHealing needs quiet
		// straight after the analysis.
		{"investigated, then fixed by a person", orchestrator.StateNeedsHumanInvestigation, longAgo, longAgo, dsKey, healthyDS, true},
		{"a rejected plan, then fixed by a person", orchestrator.StatePlanRejected, longAgo, longAgo, dsKey, healthyDS, true},
		{"a fix being validated is the validation sweeper's", orchestrator.StateValidating, longAgo, longAgo, dsKey, healthyDS, false},
		{"an open pull request is never orphaned", orchestrator.StateAwaitingMerge, longAgo, longAgo, dsKey, healthyDS, false},
		{"an analysis in flight", orchestrator.StateInvestigating, longAgo, longAgo, dsKey, healthyDS, false},
		// Observed on lab-dev 2026-10-13: an approval for deleting a pod that
		// no longer existed, waiting six days after the Deployment recovered.
		{"a pending approval whose fault cleared", orchestrator.StateAwaitingApproval, longAgo, longAgo, dsKey, healthyDS, true},
		{"node back to Ready", orchestrator.StateDetected, longAgo, longAgo, "Node||worker-1", readyNode(corev1.ConditionTrue), true},
		// NodeNotReady is reported once: quiet here means still down, not fixed.
		{"node still NotReady", orchestrator.StateDetected, longAgo, longAgo, "Node||worker-1", readyNode(corev1.ConditionFalse), false},
		{"scaled to zero is idle, not broken", orchestrator.StateDetected, longAgo, longAgo, "apps/v1/Deployment|ns|web",
			&appsv1.Deployment{Spec: appsv1.DeploymentSpec{Replicas: replicas(0)}}, true},
		{"a failed Job stays open", orchestrator.StateDetected, longAgo, longAgo, "batch/v1/Job|ns|backup",
			&batchv1.Job{Status: batchv1.JobStatus{Conditions: []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "BackoffLimitExceeded"}}}}, false},
		{"a kind with no Ready or Available condition stays open", orchestrator.StateDetected, longAgo, longAgo, "argoproj.io/v1alpha1/Application|argocd|web",
			map[string]any{"status": map[string]any{"health": map[string]any{"status": "Healthy"}}}, false},
		// Observed on rke2 2026-10-13: each of these stayed open after it cleared.
		{"a renewed certificate (Ready=True)", orchestrator.StateDetected, longAgo, longAgo, "cert-manager.io/v1/Certificate|cattle-system|rancher-ingress",
			map[string]any{"metadata": map[string]any{"generation": 1}, "status": map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "True", "observedGeneration": 1}}}}, true},
		{"a cnpg Cluster back to Ready", orchestrator.StateDetected, longAgo, longAgo, "postgresql.cnpg.io/v1/Cluster|nebula|nebula-db",
			map[string]any{"status": map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "True"}}}}, true},
		{"Ready=False stays open", orchestrator.StateDetected, longAgo, longAgo, "postgresql.cnpg.io/v1/Cluster|nebula|nebula-db",
			map[string]any{"status": map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "False", "reason": "Failing"}}}}, false},
		{"a Ready condition for an older spec stays open", orchestrator.StateDetected, longAgo, longAgo, "cert-manager.io/v1/Certificate|ns|c",
			map[string]any{"metadata": map[string]any{"generation": 3}, "status": map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "True", "observedGeneration": 2}}}}, false},
		{"a Service that has its cluster IP", orchestrator.StateDetected, longAgo, longAgo, "v1/Service|nebula|nebula-db-pooler-rw",
			&corev1.Service{Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, ClusterIP: "10.43.69.135"}}, true},
		{"a LoadBalancer still waiting for an address", orchestrator.StateDetected, longAgo, longAgo, "v1/Service|ns|lb",
			&corev1.Service{Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, ClusterIP: "10.43.0.9"}}, false},
		{"a PDB with enough healthy pods", orchestrator.StateDetected, longAgo, longAgo, "policy/v1/PodDisruptionBudget|nebula-keycloak|keycloak",
			&policyv1.PodDisruptionBudget{Status: policyv1.PodDisruptionBudgetStatus{ExpectedPods: 3, CurrentHealthy: 3, DesiredHealthy: 2}}, true},
		{"a PDB that selects nothing stays open", orchestrator.StateDetected, longAgo, longAgo, "policy/v1/PodDisruptionBudget|ns|p",
			&policyv1.PodDisruptionBudget{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := staleCandidate{ID: "inc_1", ClusterID: "cl_1", State: tc.state, LastSeen: tc.lastSeen}
			got := clearedOutcome(c, tc.key, "the workload it belongs to", mustJSON(t, tc.object), tc.connectedSince, quiet, now)
			if (got != nil) != tc.wantClose {
				t.Fatalf("closes = %v, want %v (%+v)", got != nil, tc.wantClose, got)
			}
			if got != nil && !strings.Contains(got.Summary, "cleared on its own") {
				t.Errorf("summary does not say what happened: %q", got.Summary)
			}
		})
	}
}

func TestClearedOutcomeUndecodableObjectStaysOpen(t *testing.T) {
	now := time.Now()
	c := staleCandidate{State: orchestrator.StateDetected, LastSeen: now.Add(-time.Hour)}
	if got := clearedOutcome(c, "v1/Pod|ns|p", "", json.RawMessage(`{"status":"[redacted]"}`), now.Add(-2*time.Hour), time.Minute, now); got != nil {
		t.Fatalf("an object that does not decode was treated as healthy: %+v", got)
	}
}

// One pass checks only a few incidents. Without the rotation, the oldest quiet
// incidents (still broken, so never closed) were re-checked every pass and a
// newer, cleared one was never reached.
func TestStaleCheckLogRotates(t *testing.T) {
	var log staleCheckLog
	cands := []staleCandidate{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	t0 := time.Now()
	first := log.pick(cands, 2, t0)
	second := log.pick(cands, 2, t0.Add(time.Minute))
	if first[0].ID != "a" || first[1].ID != "b" {
		t.Fatalf("first pass should keep the query's order: %v", ids(first))
	}
	if second[0].ID != "c" {
		t.Fatalf("second pass should reach the unchecked incident first: %v", ids(second))
	}
	log.pick([]staleCandidate{{ID: "c"}}, 2, t0.Add(2*time.Minute))
	if len(log) != 1 {
		t.Fatalf("incidents that are no longer candidates should be forgotten, have %d entries", len(log))
	}
}

func ids(cs []staleCandidate) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.ID
	}
	return out
}

// Observed 2026-10-13 on lab-dev: kube-proxy's workload key was
// `v1/Node|kube-system|<node>` and a Node event's key `Node||<node>`; the agent
// refused both reads, so three incidents about a Ready node never closed.
func TestNormalizeNodeKey(t *testing.T) {
	for in, want := range map[string]string{"Node": "v1/Node", "v1/Node": "v1/Node", "v1/Pod": "v1/Pod", "apps/v1/DaemonSet": "apps/v1/DaemonSet"} {
		if got := normalizeNodeKey(in); got != want {
			t.Errorf("normalizeNodeKey(%q) = %q, want %q", in, got, want)
		}
	}
	if v := liveVerdict("Node||worker-1", mustJSON(t, readyNode(corev1.ConditionTrue)), time.Now()); v.Level != "healthy" {
		t.Errorf("a Ready node keyed `Node||name` graded %q", v.Level)
	}
}

func TestDescribeKeyDropsANodesNamespace(t *testing.T) {
	if got := describeKey("v1/Node|kube-system|worker-2"); got != "Node worker-2" {
		t.Errorf("describeKey = %q, want %q", got, "Node worker-2")
	}
	if got := describeKey("apps/v1/Deployment|ns|web"); got != "Deployment ns/web" {
		t.Errorf("describeKey = %q", got)
	}
}

func TestClearedApprovalSaysTheApprovalWasWithdrawn(t *testing.T) {
	now := time.Now()
	c := staleCandidate{State: orchestrator.StateAwaitingApproval, LastSeen: now.Add(-time.Hour), WorkloadKey: "apps/v1/Deployment|apps|gwas-frontend", TargetKey: "v1/Pod|apps|gwas-frontend-x"}
	key, _ := clearedTarget(c)
	if key != c.WorkloadKey {
		t.Fatalf("the cleared check must grade the workload, not the plan's pod: %q", key)
	}
	ready := &appsv1.Deployment{Spec: appsv1.DeploymentSpec{Replicas: replicas(1)}, Status: appsv1.DeploymentStatus{ReadyReplicas: 1, AvailableReplicas: 1, Replicas: 1, UpdatedReplicas: 1}}
	got := clearedOutcome(c, key, "the workload it belongs to", mustJSON(t, ready), now.Add(-2*time.Hour), 15*time.Minute, now)
	if got == nil || !strings.Contains(got.Summary, "pending approval was withdrawn") {
		t.Fatalf("summary = %+v", got)
	}
}

func TestQuietEnoughCountsFromTheLaterOfFindingAndSession(t *testing.T) {
	now := time.Now()
	q := 15 * time.Minute
	for _, tc := range []struct {
		name          string
		last, session time.Time
		want          bool
	}{
		{"quiet since the finding, connected throughout", now.Add(-time.Hour), now.Add(-2 * time.Hour), true},
		{"finding inside the window", now.Add(-5 * time.Minute), now.Add(-2 * time.Hour), false},
		{"agent reconnected inside the window", now.Add(-time.Hour), now.Add(-5 * time.Minute), false},
	} {
		if got := quietEnough(tc.last, tc.session, q, now); got != tc.want {
			t.Errorf("%s: got %v", tc.name, got)
		}
	}
	if quietEnough(now.Add(-time.Hour), now.Add(-time.Hour), 0, now) {
		t.Error("an unknown quiet period must never count as quiet")
	}
}

// A rule-opened incident (certificate expiry, a PDB, a quota) is judged by
// re-running that rule, whatever kind it watches.
func TestRuleClearedOutcomeQuotesTheReRun(t *testing.T) {
	now := time.Now()
	c := staleCandidate{State: orchestrator.StateDetected, LastSeen: now.Add(-time.Hour)}
	got := ruleClearedOutcome(c, "rule certificate-expiry-imminent no longer fires on cert-manager.io/v1/Certificate cattle-system/rancher-ingress", 15*time.Minute, now.Add(-2*time.Hour), now)
	if !strings.Contains(got.Summary, "re-run now, says rule certificate-expiry-imminent no longer fires") || got.Detail["checkedBy"] != "rule" {
		t.Fatalf("closure = %+v", got)
	}
	appr := ruleClearedOutcome(staleCandidate{State: orchestrator.StateAwaitingApproval, LastSeen: now.Add(-time.Hour)}, "x", time.Minute, now.Add(-time.Hour), now)
	if !strings.Contains(appr.Summary, "pending approval was withdrawn") {
		t.Errorf("approval closure = %q", appr.Summary)
	}
	if clearedEligible(orchestrator.StateAwaitingMerge) || clearedEligible(orchestrator.StateExecuting) || !clearedEligible(orchestrator.StateAwaitingApproval) || !clearedEligible(orchestrator.StateDiagnosed) {
		t.Error("eligibility: every open state with nothing in flight")
	}
}

func TestPeriodicClearedOutcomeSaysWhatWasReRun(t *testing.T) {
	now := time.Now()
	got := periodicClearedOutcome(staleCandidate{State: orchestrator.StateDetected, LastSeen: now.Add(-time.Hour)}, 15*time.Minute, now.Add(-time.Hour), now)
	if !strings.Contains(got.Summary, "periodic check that reported it has re-run") || got.Detail["checkedBy"] != "periodic-sweep" {
		t.Fatalf("closure = %+v", got)
	}
}

// A pending approval whose subject is gone closes: a deleted bare Pod, or a
// deleted Deployment, leaves the plan nothing to act on. Every other state
// was decided by the gone check before this point.
func TestSubjectGoneClosesOnlyPendingApprovals(t *testing.T) {
	if !subjectGoneCloses(orchestrator.StateAwaitingApproval) {
		t.Error("an AwaitingApproval incident whose workload or bare object is gone must close")
	}
	for _, s := range []string{orchestrator.StateDetected, orchestrator.StateDiagnosed, orchestrator.StateAwaitingMerge, orchestrator.StateExecuting, orchestrator.StateValidating} {
		if subjectGoneCloses(s) {
			t.Errorf("%s must not be closed here", s)
		}
	}
}
