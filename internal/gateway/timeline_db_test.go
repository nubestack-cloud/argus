package gateway

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
	"argus/internal/tunnel"
)

// timelineTestCluster inserts a throwaway cluster and registers cleanup for
// it and anything handleFinding creates under it — mirrors
// correlation_db_test.go's correlationCluster, kept separate since that
// helper also builds a live-incident-seeding closure this test doesn't need.
func timelineTestCluster(t *testing.T, pool *pgxpool.Pool) (tenantID, clusterID string, fixture *dbtest.Fixture) {
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
		clusterID, tenantID, "timeline-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	fixture.Created("clusters", 1)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}
	return tenantID, clusterID, fixture
}

// timelineCleanup registers this fixture's cleanup once the caller knows
// exactly how many findings/incidents/timeline_events rows its own
// production-code calls produced.
func timelineCleanup(fixture *dbtest.Fixture, pool *pgxpool.Pool, tenantID, clusterID string) {
	// PROJECT.md B188. incident_notifications is in this delete list for
	// every test built on this fixture, not just the one that currently
	// triggers it: orchestrator.SetState writes a row here on any
	// AwaitingApproval/Failed/ExecutionUnknown/Reopened hop, and the table
	// carries no FK back to incidents (migration 000083 — incidents is
	// partitioned with a composite PK, and a composite FK would block
	// internal/partition's DROP TABLE retention), so deleting the incident
	// does not take the notification with it.
	//
	// Created(..., 0) rather than leaving the table untracked: Cleanup
	// rejects a delete for a table no Created call ever named, so this
	// declares the table in scope with a baseline of none, and a test whose
	// own product-code call reaches a notifiable transition adds its own
	// Created("incident_notifications", 1) on top. That keeps the exact-count
	// guarantee — a test that unexpectedly starts writing one fails here
	// rather than leaking it.
	fixture.Created("incident_notifications", 0)
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "incident_notifications", SQL: `DELETE FROM incident_notifications WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "timeline_events", SQL: `DELETE FROM timeline_events WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "findings", SQL: `DELETE FROM findings WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})
}

// TestHandleFindingWritesIncidentOpenedEvent is BACKLOG.md B1's acceptance
// test for the detection transition: a Finding that opens a brand new
// incident must write exactly one IncidentOpened timeline_events row, in the
// same transaction as the incident insert itself.
func TestHandleFindingWritesIncidentOpenedEvent(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, fixture := timelineTestCluster(t, pool)
	fixture.Created("incidents", 1)
	fixture.Created("findings", 1)
	fixture.Created("timeline_events", 1)
	timelineCleanup(fixture, pool, tenantID, clusterID)
	g := &Gateway{db: &data.DB{Pool: pool}}

	f := &tunnel.Finding{
		DetectorID:      "k8s-pod-conditions",
		DetectorVersion: "1",
		Fingerprint:     "test-fp-" + clusterID,
		GVK:             "v1/Pod",
		Namespace:       "default",
		ObjectName:      "timeline-test-pod",
		ObjectUID:       "uid-" + clusterID,
		ResourceVersion: "1",
		Reason:          "CrashLoopBackOff",
		Message:         "back-off restarting failed container",
		OccurrenceCount: 1,
		Severity:        "high",
		OccurredAt:      time.Now(),
	}

	if err := g.handleFinding(context.Background(), clusterID, f); err != nil {
		t.Fatalf("handleFinding: %v", err)
	}

	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin verify tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	var incidentID string
	if err := tx.QueryRow(ctx, `SELECT id FROM incidents WHERE cluster_id = $1 AND fingerprint = $2`, clusterID, f.Fingerprint).Scan(&incidentID); err != nil {
		t.Fatalf("look up the incident this Finding should have opened: %v", err)
	}

	rows, err := tx.Query(ctx, `SELECT event_type, payload FROM timeline_events WHERE incident_id = $1`, incidentID)
	if err != nil {
		t.Fatalf("query timeline_events: %v", err)
	}
	defer rows.Close()

	var count int
	for rows.Next() {
		var eventType string
		var payload []byte
		if err := rows.Scan(&eventType, &payload); err != nil {
			t.Fatalf("scan: %v", err)
		}
		count++
		if eventType != "IncidentOpened" {
			t.Errorf("event_type = %q, want %q", eventType, "IncidentOpened")
		}
		var decoded map[string]any
		if err := json.Unmarshal(payload, &decoded); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		if got, _ := decoded["reason"].(string); got != f.Reason {
			t.Errorf("payload[\"reason\"] = %q, want %q", got, f.Reason)
		}
		if got, _ := decoded["detectorId"].(string); got != f.DetectorID {
			t.Errorf("payload[\"detectorId\"] = %q, want %q", got, f.DetectorID)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}
	if count != 1 {
		t.Fatalf("timeline_events rows for incident %s = %d, want exactly 1", incidentID, count)
	}
}

// TestHandleFindingWritesValidationOutcomeEventOnEventDrivenReopen is
// BACKLOG.md E6's follow-up: the event-driven half of Validating -> Reopened
// (internal/gateway/finding.go's reopenAfterRecurrence, triggered by a live
// Finding recurring on the object) used to write no timeline_events row at
// all, unlike orchestrator.ValidationSweeper's own delayed half of the same
// transition. A Finding recurring against a Validating incident must now
// leave exactly one ValidationOutcome row behind, same event type
// ValidationSweeper itself uses (see timeline.EventValidationOutcome's own
// doc comment), so an operator reading only the timeline still sees why the
// incident reopened.
func TestHandleFindingWritesValidationOutcomeEventOnEventDrivenReopen(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, fixture := timelineTestCluster(t, pool)
	g := &Gateway{db: &data.DB{Pool: pool}}
	ctx := context.Background()

	// A Validating incident, already open, for the exact object the recurring
	// Finding below names — object-tier correlation is what
	// reopenAfterRecurrence's caller (handleFinding) needs to find it again.
	incidentID := domain.NewID(domain.PrefixIncident)
	objectKey := "v1/Pod|default|timeline-test-pod"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin insert: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		tx.Rollback(ctx) //nolint:errcheck
		t.Fatalf("scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, object_key, severity, state, first_seen, last_seen, occurrence_count)
		 VALUES ($1, $2, $3, $4, $5, 'high', 'Validating', now() - interval '1 hour', now() - interval '1 hour', 1)`,
		incidentID, tenantID, clusterID, "original-fp-"+incidentID, objectKey); err != nil {
		tx.Rollback(ctx) //nolint:errcheck
		t.Fatalf("insert Validating incident: %v", err)
	}
	fixture.Created("incidents", 1)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit insert: %v", err)
	}
	// The recurring finding below correlates into this ALREADY-open incident
	// (object tier) rather than opening a new one, and reopens it — writing
	// one findings row and one ValidationOutcome timeline row (not
	// IncidentOpened, since no new incident is created).
	fixture.Created("findings", 1)
	fixture.Created("timeline_events", 1)
	// The Validating -> Reopened hop is notifiable, so SetState also UPSERTs
	// one incident_notifications row for it (notify_key "Reopened@...").
	fixture.Created("incident_notifications", 1)
	timelineCleanup(fixture, pool, tenantID, clusterID)

	// No remediation_executions row exists for this incident, so
	// staleEvidenceForReopen fails open (no successful execution to be stale
	// relative to) and this recurrence reopens normally — deliberately the
	// simplest path through that guard, since this test is about the
	// timeline write on the reopen outcome, not the guard's own windows
	// (TestStaleEvidenceForReopen in correlation_db_test.go already covers
	// those).
	f := &tunnel.Finding{
		DetectorID:      "k8s-pod-conditions",
		DetectorVersion: "1",
		Fingerprint:     "test-fp-recurrence-" + clusterID,
		GVK:             "v1/Pod",
		Namespace:       "default",
		ObjectName:      "timeline-test-pod",
		ObjectUID:       "uid-recurrence-" + clusterID,
		ResourceVersion: "1",
		Reason:          "CrashLoopBackOff",
		Message:         "back-off restarting failed container",
		OccurrenceCount: 1,
		Severity:        "high",
		OccurredAt:      time.Now(),
	}

	if err := g.handleFinding(ctx, clusterID, f); err != nil {
		t.Fatalf("handleFinding: %v", err)
	}

	verifyTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin verify tx: %v", err)
	}
	defer verifyTx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, verifyTx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	var state string
	if err := verifyTx.QueryRow(ctx, `SELECT state FROM incidents WHERE id = $1`, incidentID).Scan(&state); err != nil {
		t.Fatalf("look up incident state: %v", err)
	}
	if state != "Reopened" {
		t.Fatalf("incident state = %q, want %q — the recurrence should have reopened it", state, "Reopened")
	}

	rows, err := verifyTx.Query(ctx, `SELECT event_type, payload FROM timeline_events WHERE incident_id = $1`, incidentID)
	if err != nil {
		t.Fatalf("query timeline_events: %v", err)
	}
	defer rows.Close()

	var count int
	for rows.Next() {
		var eventType string
		var payload []byte
		if err := rows.Scan(&eventType, &payload); err != nil {
			t.Fatalf("scan: %v", err)
		}
		count++
		if eventType != "ValidationOutcome" {
			t.Errorf("event_type = %q, want %q", eventType, "ValidationOutcome")
		}
		var decoded map[string]any
		if err := json.Unmarshal(payload, &decoded); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		if got, _ := decoded["outcome"].(string); got != "Reopened" {
			t.Errorf("payload[\"outcome\"] = %q, want %q", got, "Reopened")
		}
		if got, _ := decoded["route"].(string); got != "eventDriven" {
			t.Errorf("payload[\"route\"] = %q, want %q", got, "eventDriven")
		}
		summary, _ := decoded["summary"].(string)
		if summary == "" {
			t.Error("payload[\"summary\"] is empty — an operator reading only the timeline would not see why it reopened")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}
	if count != 1 {
		t.Fatalf("timeline_events rows for incident %s = %d, want exactly 1 (BACKLOG.md E6: the event-driven reopen path must leave a timeline trace, same as ValidationSweeper's own reopen path already does)", incidentID, count)
	}
}

// TestHandleFindingReopensAnExpiredIncidentToDetected is PROJECT.md T2's own
// regression test: "a recurrence can reopen an expired incident" is the
// requirement, and this is what makes it true end to end — an incident
// already in StateExpired, hit by a fresh Finding for the same object,
// moves to StateDetected (not StateReopened — nothing was ever fixed here)
// and leaves an IncidentRecurredAfterExpiry timeline trace, exactly the
// event-driven counterpart TestHandleFindingWritesValidationOutcomeEventOnEventDrivenReopen
// above already proves for the Validating case.
func TestHandleFindingReopensAnExpiredIncidentToDetected(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, fixture := timelineTestCluster(t, pool)
	g := &Gateway{db: &data.DB{Pool: pool}}
	ctx := context.Background()

	incidentID := domain.NewID(domain.PrefixIncident)
	objectKey := "v1/Pod|default|timeline-test-pod"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin insert: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		tx.Rollback(ctx) //nolint:errcheck
		t.Fatalf("scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, object_key, severity, state, first_seen, last_seen, occurrence_count)
		 VALUES ($1, $2, $3, $4, $5, 'high', 'Expired', now() - interval '30 days', now() - interval '30 days', 1)`,
		incidentID, tenantID, clusterID, "original-fp-"+incidentID, objectKey); err != nil {
		tx.Rollback(ctx) //nolint:errcheck
		t.Fatalf("insert Expired incident: %v", err)
	}
	fixture.Created("incidents", 1)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit insert: %v", err)
	}

	fixture.Created("findings", 1)
	fixture.Created("timeline_events", 1)
	timelineCleanup(fixture, pool, tenantID, clusterID)

	f := &tunnel.Finding{
		DetectorID:      "k8s-pod-conditions",
		DetectorVersion: "1",
		Fingerprint:     "test-fp-recurrence-after-expiry-" + clusterID,
		GVK:             "v1/Pod",
		Namespace:       "default",
		ObjectName:      "timeline-test-pod",
		ObjectUID:       "uid-recurrence-" + clusterID,
		ResourceVersion: "1",
		Reason:          "CrashLoopBackOff",
		Message:         "back-off restarting failed container",
		OccurrenceCount: 1,
		Severity:        "high",
		OccurredAt:      time.Now(),
	}

	if err := g.handleFinding(ctx, clusterID, f); err != nil {
		t.Fatalf("handleFinding: %v", err)
	}

	verifyTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin verify tx: %v", err)
	}
	defer verifyTx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, verifyTx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	var state string
	if err := verifyTx.QueryRow(ctx, `SELECT state FROM incidents WHERE id = $1`, incidentID).Scan(&state); err != nil {
		t.Fatalf("look up incident state: %v", err)
	}
	if state != "Detected" {
		t.Fatalf("incident state = %q, want %q — a recurrence must reopen an expired incident, honestly, into the same state a brand new one starts in", state, "Detected")
	}

	rows, err := verifyTx.Query(ctx, `SELECT event_type, payload FROM timeline_events WHERE incident_id = $1`, incidentID)
	if err != nil {
		t.Fatalf("query timeline_events: %v", err)
	}
	defer rows.Close()

	var count int
	for rows.Next() {
		var eventType string
		var payload []byte
		if err := rows.Scan(&eventType, &payload); err != nil {
			t.Fatalf("scan: %v", err)
		}
		count++
		if eventType != "IncidentRecurredAfterExpiry" {
			t.Errorf("event_type = %q, want %q", eventType, "IncidentRecurredAfterExpiry")
		}
		var decoded map[string]any
		if err := json.Unmarshal(payload, &decoded); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		if got, _ := decoded["outcome"].(string); got != "Detected" {
			t.Errorf("payload[\"outcome\"] = %q, want %q", got, "Detected")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}
	if count != 1 {
		t.Fatalf("timeline_events rows for incident %s = %d, want exactly 1", incidentID, count)
	}
}
