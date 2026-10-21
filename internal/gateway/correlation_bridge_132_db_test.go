package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/tunnel"
)

// BUGS.md 132's regression tests: the object<->workload correlation bridge.
//
// Reproduces the live rke2 fixture (a single-replica Deployment whose
// container always exits 1 — BUGS.md 132's own row-8 citation) as a
// DB-backed test rather than against the real, shared cluster, per this
// round's own instructions ("via a DB-backed test reproducing the exact
// call sequence if live testing isn't practical/safe on this shared cluster
// right now"): rke2 is real, shared infrastructure the owner also uses
// personally (see HANDOFF.md's "Blocked on the owner" section on the exact
// same caution for E14 row 18), and reproducing a two-incident correlation
// bug needs no real kubelet/controller behaviour at all — only the two
// Finding shapes handleFinding actually receives over the tunnel, which
// this test constructs directly, exactly like workload_backfill_db_test.go's
// AZ1 regression test does for the adjacent bug.
//
// Uses workload_backfill_db_test.go's testPool/workloadBackfillTestCluster
// harness (argus_app, not the superuser) rather than duplicating it.
func bridge132Finding(clusterNS string, gvk, objectName, reason string, workloadGVK, workloadName string, occurredAt time.Time, fingerprint string) *tunnel.Finding {
	return &tunnel.Finding{
		DetectorID:      "test-bridge-132",
		DetectorVersion: "v1",
		Fingerprint:     fingerprint,
		GVK:             gvk,
		Namespace:       clusterNS,
		ObjectName:      objectName,
		ObjectUID:       "uid-" + objectName,
		ResourceVersion: "1",
		Reason:          reason,
		Message:         "test finding for BUGS.md 132",
		OccurrenceCount: 1,
		Severity:        "high",
		OccurredAt:      occurredAt,
		WorkloadGVK:     workloadGVK,
		WorkloadName:    workloadName,
	}
}

// bridge132Incidents returns every incident row for this cluster, newest
// first — enough for these tests to assert both "exactly one incident" and
// "exactly two, distinct" outcomes without guessing IDs in advance.
func bridge132Incidents(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID string) (ids []string, objectKeys, workloadKeys, openingReasons []*string, states []string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin lookup: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	rows, err := tx.Query(ctx,
		`SELECT id, object_key, workload_key, opening_reason, state FROM incidents WHERE cluster_id = $1 ORDER BY id`,
		clusterID)
	if err != nil {
		t.Fatalf("query incidents: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, state string
		var ok, wk, or *string
		if err := rows.Scan(&id, &ok, &wk, &or, &state); err != nil {
			t.Fatalf("scan incident: %v", err)
		}
		ids = append(ids, id)
		objectKeys = append(objectKeys, ok)
		workloadKeys = append(workloadKeys, wk)
		openingReasons = append(openingReasons, or)
		states = append(states, state)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate incidents: %v", err)
	}
	return
}

func bridge132SetState(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID, state string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin state update: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE incidents SET state = $1 WHERE id = $2`, state, incidentID); err != nil {
		t.Fatalf("set state: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit state update: %v", err)
	}
}

// TestBridge132_PodFindingThenDeploymentsOwnFindingMergeOneIncident is the
// exact row-8 fixture order: the Pod's CrashLoopBackOff-family Finding opens
// a workload-tier incident first (object_key = the pod, workload_key = the
// Deployment), and the Deployment's OWN Finding about itself
// (DeploymentReplicasUnavailable — workloadRolloutHealthReasons' family, not
// a byte-identical Reason) arrives ~16 minutes later. Before this fix these
// were the two incidents BUGS.md 132 found live on rke2, 16 minutes apart,
// neither ever finding the other. After it, this must be ONE incident.
func TestBridge132_PodFindingThenDeploymentsOwnFindingMergeOneIncident(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, fixture := workloadBackfillTestCluster(t, pool)
	// The pod's finding opens the incident; the Deployment's own finding
	// bridges into it (BUGS.md 132), so one incident, one IncidentOpened
	// event, and one findings row per handleFinding call below.
	fixture.Created("incidents", 1)
	fixture.Created("findings", 2)
	fixture.Created("timeline_events", 1)
	workloadBackfillCleanup(fixture, pool, tenantID, clusterID)
	g := &Gateway{db: &data.DB{Pool: pool}}
	ctx := context.Background()

	const ns = "e14-row08"
	now := time.Now()

	pod := bridge132Finding(ns, "v1/Pod", "row08-crashloop-abc123", "BackOff", "apps/v1/Deployment", "row08-crashloop", now, "test-fp-132-pod")
	if err := g.handleFinding(ctx, clusterID, pod); err != nil {
		t.Fatalf("handleFinding(pod): %v", err)
	}

	deployment := bridge132Finding(ns, "apps/v1/Deployment", "row08-crashloop", "DeploymentReplicasUnavailable", "", "", now.Add(16*time.Minute), "test-fp-132-deploy")
	if err := g.handleFinding(ctx, clusterID, deployment); err != nil {
		t.Fatalf("handleFinding(deployment): %v", err)
	}

	ids, _, _, _, _ := bridge132Incidents(t, pool, tenantID, clusterID)
	if len(ids) != 1 {
		t.Fatalf("BUGS.md 132: got %d incidents (%v), want exactly 1 — the pod's own finding and its owning Deployment's own finding about the same fault must bridge into one incident", len(ids), ids)
	}
}

// TestBridge132_DeploymentsOwnFindingThenPodFindingMergeOneIncident is the
// reverse arrival order — BUGS.md 132's own writeup confirms both orders
// were checked live and neither found the other; this proves the fix's
// object->workload bridge direction symmetrically.
func TestBridge132_DeploymentsOwnFindingThenPodFindingMergeOneIncident(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, fixture := workloadBackfillTestCluster(t, pool)
	// The deployment's own finding here is a legacy generic-anomaly reason
	// (GenericConditionAnomaly: prefix), so normalizeFindingEvidence classes
	// it Anomaly, not Fault — shouldPromoteFinding never opens an incident
	// for it (it still gets its own findings row). The pod's finding then
	// opens the only incident that exists.
	fixture.Created("incidents", 1)
	fixture.Created("findings", 2)
	fixture.Created("timeline_events", 1)
	workloadBackfillCleanup(fixture, pool, tenantID, clusterID)
	g := &Gateway{db: &data.DB{Pool: pool}}
	ctx := context.Background()

	const ns = "e14-row08-rev"
	now := time.Now()

	deployment := bridge132Finding(ns, "apps/v1/Deployment", "row08-crashloop", "GenericConditionAnomaly:Available", "", "", now, "test-fp-132r-deploy")
	if err := g.handleFinding(ctx, clusterID, deployment); err != nil {
		t.Fatalf("handleFinding(deployment): %v", err)
	}

	pod := bridge132Finding(ns, "v1/Pod", "row08-crashloop-abc123", "CrashLoopBackOff", "apps/v1/Deployment", "row08-crashloop", now.Add(16*time.Minute), "test-fp-132r-pod")
	if err := g.handleFinding(ctx, clusterID, pod); err != nil {
		t.Fatalf("handleFinding(pod): %v", err)
	}

	ids, _, workloadKeys, _, _ := bridge132Incidents(t, pool, tenantID, clusterID)
	if len(ids) != 1 {
		t.Fatalf("BUGS.md 132 (reverse order): got %d incidents (%v), want exactly 1", len(ids), ids)
	}
	// The bridge must not disturb AZ1's existing "fill an empty slot, never
	// overwrite" backfill: the incident opened at the object tier had
	// workload_key = NULL, and the later pod finding's own workload_key
	// backfill logic (unrelated to this fix, already covered by AZ1's own
	// tests) should still fill it in once the pod finding attaches.
	if workloadKeys[0] == nil || *workloadKeys[0] != "apps/v1/Deployment|"+ns+"|row08-crashloop" {
		t.Fatalf("incident %s workload_key = %v after the pod finding bridged in, want the backfilled workload key", ids[0], workloadKeys[0])
	}
}

// TestBridge132_UnrelatedObjectTierReasonDoesNotBridge is the DANGEROUS case
// the naive identity-only fix would get wrong, from the object-tier side:
// a Deployment-level Finding whose Reason is NOT a rollout-health signal
// (here, GenericObservedGenerationStale — a real, unrelated object-tier
// check with nothing to do with pod health) must NOT silently fold into an
// already-open incident for one of that Deployment's pods just because they
// name the same Deployment. Two real, distinct problems must stay two
// incidents.
func TestBridge132_UnrelatedObjectTierReasonDoesNotBridge(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, fixture := workloadBackfillTestCluster(t, pool)
	// Two genuinely distinct incidents (the bridge must not fire), each with
	// its own IncidentOpened event and findings row.
	fixture.Created("incidents", 2)
	fixture.Created("findings", 2)
	fixture.Created("timeline_events", 2)
	workloadBackfillCleanup(fixture, pool, tenantID, clusterID)
	g := &Gateway{db: &data.DB{Pool: pool}}
	ctx := context.Background()

	const ns = "e14-row08-unrelated"
	now := time.Now()

	pod := bridge132Finding(ns, "v1/Pod", "unrelated-abc123", "CrashLoopBackOff", "apps/v1/Deployment", "unrelated", now, "test-fp-132u-pod")
	if err := g.handleFinding(ctx, clusterID, pod); err != nil {
		t.Fatalf("handleFinding(pod): %v", err)
	}

	// A SECOND, genuinely different real fault on the same Deployment: not a
	// rollout-health signal at all.
	drift := bridge132Finding(ns, "apps/v1/Deployment", "unrelated", "GenericObservedGenerationStale", "", "", now.Add(5*time.Minute), "test-fp-132u-drift")
	if err := g.handleFinding(ctx, clusterID, drift); err != nil {
		t.Fatalf("handleFinding(drift): %v", err)
	}

	ids, _, _, _, _ := bridge132Incidents(t, pool, tenantID, clusterID)
	if len(ids) != 2 {
		t.Fatalf("BUGS.md 132 invisible-merge guard: got %d incidents (%v), want exactly 2 — an unrelated object-tier reason must not bridge into the pod's incident", len(ids), ids)
	}
}

// TestBridge132_UnrelatedCandidateOpeningReasonDoesNotBridge is the mirror
// image from the workload-tier side: an object-tier incident already open
// for a reason that ISN'T a rollout-health signal must not absorb a LATER,
// unrelated pod-tier finding on the same workload either. The restriction
// has to hold looking in both directions, not just on the arriving side.
func TestBridge132_UnrelatedCandidateOpeningReasonDoesNotBridge(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, fixture := workloadBackfillTestCluster(t, pool)
	// Two genuinely distinct incidents (the bridge must not fire), each with
	// its own IncidentOpened event and findings row.
	fixture.Created("incidents", 2)
	fixture.Created("findings", 2)
	fixture.Created("timeline_events", 2)
	workloadBackfillCleanup(fixture, pool, tenantID, clusterID)
	g := &Gateway{db: &data.DB{Pool: pool}}
	ctx := context.Background()

	const ns = "e14-row08-unrelated-rev"
	now := time.Now()

	// A stuck finalizer on the Deployment itself — real, but not a
	// rollout-health signal.
	stuck := bridge132Finding(ns, "apps/v1/Deployment", "unrelated2", "GenericStuckFinalizer", "", "", now, "test-fp-132ur-stuck")
	if err := g.handleFinding(ctx, clusterID, stuck); err != nil {
		t.Fatalf("handleFinding(stuck finalizer): %v", err)
	}

	pod := bridge132Finding(ns, "v1/Pod", "unrelated2-abc123", "CrashLoopBackOff", "apps/v1/Deployment", "unrelated2", now.Add(5*time.Minute), "test-fp-132ur-pod")
	if err := g.handleFinding(ctx, clusterID, pod); err != nil {
		t.Fatalf("handleFinding(pod): %v", err)
	}

	ids, _, _, _, _ := bridge132Incidents(t, pool, tenantID, clusterID)
	if len(ids) != 2 {
		t.Fatalf("BUGS.md 132 invisible-merge guard: got %d incidents (%v), want exactly 2 — a pod finding must not bridge into an object-tier incident whose own opening reason isn't a rollout-health signal", len(ids), ids)
	}
}

// TestBridge132_ResolvedIncidentIsNotReopenedByBridge is the "old, closed
// duplicate absorbs a fresh, different fault" danger named explicitly in
// this round's brief: a three-week-old (here, simulated by directly setting
// state) Pod incident that has since been marked Resolved must not have a
// FRESH Deployment-level rollout-health finding silently fold into it. The
// bridge's queries already carry `state NOT IN ('Resolved','Dismissed')` —
// identical to every other tier's correlation query — so this proves that
// carries through to the bridge path too, rather than assuming it by
// inspection alone.
func TestBridge132_ResolvedIncidentIsNotReopenedByBridge(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, fixture := workloadBackfillTestCluster(t, pool)
	// The old (later Resolved) incident, plus a fresh second incident the
	// bridge must open rather than reopen the resolved one — two incidents,
	// two IncidentOpened events, two findings rows.
	fixture.Created("incidents", 2)
	fixture.Created("findings", 2)
	fixture.Created("timeline_events", 2)
	workloadBackfillCleanup(fixture, pool, tenantID, clusterID)
	g := &Gateway{db: &data.DB{Pool: pool}}
	ctx := context.Background()

	const ns = "e14-row08-resolved"
	now := time.Now()

	pod := bridge132Finding(ns, "v1/Pod", "resolved-abc123", "CrashLoopBackOff", "apps/v1/Deployment", "resolved-dep", now.Add(-21*24*time.Hour), "test-fp-132res-pod")
	if err := g.handleFinding(ctx, clusterID, pod); err != nil {
		t.Fatalf("handleFinding(pod): %v", err)
	}
	ids, _, _, _, _ := bridge132Incidents(t, pool, tenantID, clusterID)
	if len(ids) != 1 {
		t.Fatalf("setup: want exactly 1 incident before resolving it, got %d", len(ids))
	}
	oldIncidentID := ids[0]
	bridge132SetState(t, pool, tenantID, clusterID, oldIncidentID, "Resolved")

	fresh := bridge132Finding(ns, "apps/v1/Deployment", "resolved-dep", "DeploymentReplicasUnavailable", "", "", now, "test-fp-132res-deploy")
	if err := g.handleFinding(ctx, clusterID, fresh); err != nil {
		t.Fatalf("handleFinding(fresh deployment finding): %v", err)
	}

	ids, _, _, _, states := bridge132Incidents(t, pool, tenantID, clusterID)
	if len(ids) != 2 {
		t.Fatalf("BUGS.md 132: a fresh fault must open its own new incident rather than reopen/absorb into an old, resolved one — got %d incidents (%v)", len(ids), ids)
	}
	var sawResolved, sawFresh bool
	for i, id := range ids {
		if id == oldIncidentID {
			sawResolved = true
			if states[i] != "Resolved" {
				t.Fatalf("old incident %s state = %q, want it to stay Resolved (untouched by the fresh finding)", id, states[i])
			}
		} else {
			sawFresh = true
			if states[i] == "Resolved" || states[i] == "Dismissed" {
				t.Fatalf("the fresh incident %s should be open (state=%q)", id, states[i])
			}
		}
	}
	if !sawResolved || !sawFresh {
		t.Fatalf("expected one Resolved incident and one fresh open incident, got ids=%v states=%v", ids, states)
	}
}

// TestReasonIndicatesWorkloadRolloutHealth is the pure unit-test half of the
// family check — no database needed, and kept alongside the DB tests above
// rather than in finding_test.go since it exists specifically to back the
// bridge those tests exercise end-to-end.
func TestReasonIndicatesWorkloadRolloutHealth(t *testing.T) {
	cases := []struct {
		reason string
		want   bool
	}{
		{"DeploymentReplicasUnavailable", true},
		{"StatefulSetReplicasUnavailable", true},
		{"DaemonSetReplicasUnavailable", true},
		{"GenericConditionAnomaly:Available", true},
		{"GenericConditionAnomaly:Progressing", true},
		{"GenericConditionAnomaly:ReplicaFailure", true},
		{"GenericConditionAnomaly:DiskPressure", false},
		{"GenericConditionAnomaly:Ready", false},
		{"GenericObservedGenerationStale", false},
		{"GenericStuckFinalizer", false},
		{"GenericPeerConditionShapeOutlier", false},
		{"BackOff", false},
		{"CrashLoopBackOff", false},
		{"", false},
	}
	for _, c := range cases {
		if got := reasonIndicatesWorkloadRolloutHealth(c.reason); got != c.want {
			t.Errorf("reasonIndicatesWorkloadRolloutHealth(%q) = %v, want %v", c.reason, got, c.want)
		}
	}
}
