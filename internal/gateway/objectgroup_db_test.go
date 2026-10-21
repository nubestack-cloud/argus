package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
	"argus/internal/orchestrator"
	"argus/internal/tunnel"
)

// objectGroupTestCluster mirrors timelineTestCluster/correlationCluster's own
// throwaway-cluster shape (same file's own doc comment explains why this
// isn't shared: each test file's helper cleans up exactly what that file's
// own tests write). Returns a dbtest.Fixture the caller must finish tracking
// (findings/incidents/timeline_events are produced by handleFinding, called
// from the test body, so their exact counts aren't known until after that
// runs) and clean up itself via objectGroupCleanup.
func objectGroupTestCluster(t *testing.T, pool *pgxpool.Pool) (tenantID, clusterID string, fixture *dbtest.Fixture) {
	t.Helper()
	ctx := context.Background()
	clusterID = domain.NewID(domain.PrefixCluster)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tenantID, err = data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	fixture = dbtest.New(t)
	fixture.OwnsCluster(tenantID, clusterID)
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "objectgroup-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	fixture.Created("clusters", 1)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}
	return tenantID, clusterID, fixture
}

// objectGroupCleanup registers this fixture's cleanup once the caller knows
// exactly how many findings/incidents/timeline_events rows its own
// handleFinding calls produced.
func objectGroupCleanup(fixture *dbtest.Fixture, pool *pgxpool.Pool, tenantID, clusterID string) {
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "timeline_events", SQL: `DELETE FROM timeline_events WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "findings", SQL: `DELETE FROM findings WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})
}

// incidentGroupRow is what this file's assertions read back per incident.
type incidentGroupRow struct {
	id                 string
	state              string
	workloadKey        *string
	relatedWorkloadKey *string
	objectGroupID      *string
}

func readIncidentGroupRow(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID string) incidentGroupRow {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin read: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	var row incidentGroupRow
	row.id = incidentID
	if err := tx.QueryRow(ctx,
		`SELECT state, workload_key, related_workload_key, object_group_id FROM incidents WHERE id = $1`, incidentID,
	).Scan(&row.state, &row.workloadKey, &row.relatedWorkloadKey, &row.objectGroupID); err != nil {
		t.Fatalf("read incident %s: %v", incidentID, err)
	}
	return row
}

func incidentIDForFingerprint(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, fingerprint string) string {
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
	var id string
	if err := tx.QueryRow(ctx, `SELECT id FROM incidents WHERE cluster_id = $1 AND fingerprint = $2`, clusterID, fingerprint).Scan(&id); err != nil {
		t.Fatalf("look up incident for fingerprint %s: %v", fingerprint, err)
	}
	return id
}

// TestA3b_PVCAndPodFindingsShareObjectGroup is BACKLOG.md A3b's real,
// measured scenario end to end (CAPABILITIES.md §5): a PersistentVolumeClaim
// stuck Pending, and the Pod that can't schedule because of it, each open
// their OWN incident (object-level correlation, migration 000036, is
// unaffected and must stay that way) — but internal/objectgroup must link
// the two for display via a shared object_group_id, because they are one
// underlying outage.
//
// This calls the REAL (g *Gateway).handleFinding twice, unmodified — the
// exact same production entry point the mTLS tunnel calls for every Finding
// — rather than calling internal/objectgroup.Recompute directly, so this is
// a genuine test of the wiring in internal/gateway/finding.go, not just of
// the grouping decision in isolation (that's objectgroup_test.go's job).
func TestA3b_PVCAndPodFindingsShareObjectGroup(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, fixture := objectGroupTestCluster(t, pool)
	// Two DIFFERENT objects (the PVC and the Pod), so two separate incidents,
	// each with its own IncidentOpened event and findings row — object-group
	// correlation groups them for display only, it never merges incidents.
	fixture.Created("incidents", 2)
	fixture.Created("findings", 2)
	fixture.Created("timeline_events", 2)
	objectGroupCleanup(fixture, pool, tenantID, clusterID)
	g := &Gateway{db: &data.DB{Pool: pool}}
	ctx := context.Background()

	const (
		workloadGVK  = "apps/v1/Deployment"
		workloadName = "softpack-frontend"
	)

	// Finding 1: the PVC, stuck Pending, resolved (agent-side, in the real
	// system — internal/agent/objectref.go's resolveRelatedWorkloadForPVC)
	// to the Deployment whose Pod mounts it. This Finding's own object is
	// the PVC, NOT the workload — RelatedWorkload*, not Workload*.
	pvcFinding := &tunnel.Finding{
		DetectorID:          "k8s-sweep",
		DetectorVersion:     "v1",
		Fingerprint:         "test-fp-pvc-" + clusterID,
		GVK:                 "v1/PersistentVolumeClaim",
		Namespace:           "apps",
		ObjectName:          "spack-cache",
		ObjectUID:           "uid-pvc-" + clusterID,
		ResourceVersion:     "1",
		Reason:              "PVCPendingTimeout",
		Message:             "PersistentVolumeClaim has been Pending for 156 days",
		OccurrenceCount:     1,
		Severity:            "high",
		OccurredAt:          time.Now(),
		RelatedWorkloadGVK:  workloadGVK,
		RelatedWorkloadName: workloadName,
	}
	if err := g.handleFinding(ctx, clusterID, pvcFinding); err != nil {
		t.Fatalf("handleFinding(pvc): %v", err)
	}

	// Finding 2: the Pod that can't schedule because the PVC never bound —
	// a genuinely DIFFERENT object (object_key differs: different GVK,
	// different name) resolved (agent-side, in the real system —
	// internal/agent/workload.go's resolveWorkloadFromOwnerRefs) to the SAME
	// owning Deployment. This is the existing A3a mechanism, WorkloadGVK/
	// WorkloadName, unchanged.
	podFinding := &tunnel.Finding{
		DetectorID:      "k8s-sweep",
		DetectorVersion: "v1",
		Fingerprint:     "test-fp-pod-" + clusterID,
		GVK:             "v1/Pod",
		Namespace:       "apps",
		ObjectName:      "softpack-frontend-abc123",
		ObjectUID:       "uid-pod-" + clusterID,
		ResourceVersion: "1",
		Reason:          "PendingTimeout",
		Message:         "pod has been Pending for 12m0s",
		OccurrenceCount: 1,
		Severity:        "high",
		OccurredAt:      time.Now(),
		WorkloadGVK:     workloadGVK,
		WorkloadName:    workloadName,
	}
	if err := g.handleFinding(ctx, clusterID, podFinding); err != nil {
		t.Fatalf("handleFinding(pod): %v", err)
	}

	pvcIncidentID := incidentIDForFingerprint(t, pool, tenantID, clusterID, pvcFinding.Fingerprint)
	podIncidentID := incidentIDForFingerprint(t, pool, tenantID, clusterID, podFinding.Fingerprint)

	if pvcIncidentID == podIncidentID {
		t.Fatalf("PVC and Pod findings opened the SAME incident (%s) — A3b must stay display-only, never merge incidents (see migration 000070's header)", pvcIncidentID)
	}

	pvcRow := readIncidentGroupRow(t, pool, tenantID, clusterID, pvcIncidentID)
	podRow := readIncidentGroupRow(t, pool, tenantID, clusterID, podIncidentID)

	// Object-level/A3a correlation must be exactly as before: the PVC
	// incident carries related_workload_key, never workload_key; the Pod
	// incident carries workload_key, never related_workload_key.
	if pvcRow.workloadKey != nil {
		t.Errorf("PVC incident carries workload_key = %q, want NULL (a PVC finding must never populate the merge-tier column)", *pvcRow.workloadKey)
	}
	if pvcRow.relatedWorkloadKey == nil || *pvcRow.relatedWorkloadKey != workloadGVK+"|apps|"+workloadName {
		t.Errorf("PVC incident related_workload_key = %v, want %q", pvcRow.relatedWorkloadKey, workloadGVK+"|apps|"+workloadName)
	}
	if podRow.relatedWorkloadKey != nil {
		t.Errorf("Pod incident carries related_workload_key = %q, want NULL", *podRow.relatedWorkloadKey)
	}
	if podRow.workloadKey == nil || *podRow.workloadKey != workloadGVK+"|apps|"+workloadName {
		t.Errorf("Pod incident workload_key = %v, want %q", podRow.workloadKey, workloadGVK+"|apps|"+workloadName)
	}

	// The actual A3b deliverable: both incidents share ONE non-null
	// object_group_id.
	if pvcRow.objectGroupID == nil || *pvcRow.objectGroupID == "" {
		t.Fatal("PVC incident has no object_group_id — A3b correlation did not fire")
	}
	if podRow.objectGroupID == nil || *podRow.objectGroupID == "" {
		t.Fatal("Pod incident has no object_group_id — A3b correlation did not fire")
	}
	if *pvcRow.objectGroupID != *podRow.objectGroupID {
		t.Fatalf("PVC incident object_group_id = %q, Pod incident object_group_id = %q, want equal", *pvcRow.objectGroupID, *podRow.objectGroupID)
	}
	if pvcRow.state == "Resolved" || pvcRow.state == "Dismissed" || podRow.state == "Resolved" || podRow.state == "Dismissed" {
		t.Fatalf("expected both incidents open (Detected), got PVC=%s Pod=%s", pvcRow.state, podRow.state)
	}

	// Close-time recompute: resolving the Pod's incident (internal/
	// orchestrator.SetState's own objectgroup.Recompute call, mirroring
	// replicagroup's) must shrink the group back to nothing — an anchor
	// with only ONE currently-open incident touching it is not a
	// cross-object correlation to show, per objectgroup.decideGroupID.
	txClose, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin close tx: %v", err)
	}
	defer txClose.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, txClose, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope close tx: %v", err)
	}
	if err := orchestrator.SetState(ctx, txClose, podIncidentID, orchestrator.StateResolved); err != nil {
		t.Fatalf("resolve pod incident: %v", err)
	}
	if err := txClose.Commit(ctx); err != nil {
		t.Fatalf("commit close: %v", err)
	}

	pvcRowAfterClose := readIncidentGroupRow(t, pool, tenantID, clusterID, pvcIncidentID)
	if pvcRowAfterClose.objectGroupID != nil {
		t.Errorf("after the Pod incident resolved, PVC incident still carries object_group_id = %q, want NULL (the group should have shrunk to a lone member)", *pvcRowAfterClose.objectGroupID)
	}
}

// TestA3b_ServiceAndPodFindingsShareObjectGroup is the OTHER named A3b
// scenario, end to end: a Service with no ready endpoints and the Pod(s)
// its selector matches (checkServiceNoEndpoints +
// resolveRelatedWorkloadForSelector, agent-side) must correlate for display
// the same way the PVC/Pod pair above does — proving the hub-side mechanism
// (relatedWorkloadCorrelationKey, the INSERT, objectgroup.Recompute) is
// genuinely shared by both A3b halves, not special-cased to PVCs.
func TestA3b_ServiceAndPodFindingsShareObjectGroup(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, fixture := objectGroupTestCluster(t, pool)
	// Two DIFFERENT objects (the Service and the Pod), so two separate
	// incidents, each with its own IncidentOpened event and findings row.
	fixture.Created("incidents", 2)
	fixture.Created("findings", 2)
	fixture.Created("timeline_events", 2)
	objectGroupCleanup(fixture, pool, tenantID, clusterID)
	g := &Gateway{db: &data.DB{Pool: pool}}
	ctx := context.Background()

	const (
		workloadGVK  = "apps/v1/StatefulSet"
		workloadName = "web"
	)

	svcFinding := &tunnel.Finding{
		DetectorID:          "k8s-sweep",
		DetectorVersion:     "v1",
		Fingerprint:         "test-fp-svc-" + clusterID,
		GVK:                 "v1/Service",
		Namespace:           "apps",
		ObjectName:          "web",
		ObjectUID:           "uid-svc-" + clusterID,
		ResourceVersion:     "1",
		Reason:              "ServiceNoEndpoints",
		Message:             "Service has a selector but no ready endpoints",
		OccurrenceCount:     1,
		Severity:            "high",
		OccurredAt:          time.Now(),
		RelatedWorkloadGVK:  workloadGVK,
		RelatedWorkloadName: workloadName,
	}
	if err := g.handleFinding(ctx, clusterID, svcFinding); err != nil {
		t.Fatalf("handleFinding(service): %v", err)
	}

	podFinding := &tunnel.Finding{
		DetectorID:      "k8s-pod-conditions",
		DetectorVersion: "v1",
		Fingerprint:     "test-fp-web-pod-" + clusterID,
		GVK:             "v1/Pod",
		Namespace:       "apps",
		ObjectName:      "web-0",
		ObjectUID:       "uid-web-pod-" + clusterID,
		ResourceVersion: "1",
		Reason:          "CrashLoopBackOff",
		Message:         "back-off restarting failed container",
		OccurrenceCount: 1,
		Severity:        "critical",
		OccurredAt:      time.Now(),
		WorkloadGVK:     workloadGVK,
		WorkloadName:    workloadName,
	}
	if err := g.handleFinding(ctx, clusterID, podFinding); err != nil {
		t.Fatalf("handleFinding(pod): %v", err)
	}

	svcIncidentID := incidentIDForFingerprint(t, pool, tenantID, clusterID, svcFinding.Fingerprint)
	podIncidentID := incidentIDForFingerprint(t, pool, tenantID, clusterID, podFinding.Fingerprint)
	if svcIncidentID == podIncidentID {
		t.Fatalf("Service and Pod findings opened the SAME incident (%s) — must stay two incidents", svcIncidentID)
	}

	svcRow := readIncidentGroupRow(t, pool, tenantID, clusterID, svcIncidentID)
	podRow := readIncidentGroupRow(t, pool, tenantID, clusterID, podIncidentID)

	if svcRow.objectGroupID == nil || podRow.objectGroupID == nil {
		t.Fatalf("expected both incidents grouped, got Service=%v Pod=%v", svcRow.objectGroupID, podRow.objectGroupID)
	}
	if *svcRow.objectGroupID != *podRow.objectGroupID {
		t.Fatalf("Service incident object_group_id = %q, Pod incident object_group_id = %q, want equal", *svcRow.objectGroupID, *podRow.objectGroupID)
	}
	// Severity escalation (an unrelated, pre-existing mechanism) must not be
	// confused with this one: the Service incident's own severity is
	// unaffected by the Pod incident's critical severity — A3b groups for
	// DISPLAY only, it does not touch either incident's state or fields.
	if svcRow.state != orchestrator.StateDetected {
		t.Errorf("Service incident state = %q, want unaffected (%q) by the correlated Pod incident", svcRow.state, orchestrator.StateDetected)
	}
}
