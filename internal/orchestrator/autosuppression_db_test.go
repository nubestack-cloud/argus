package orchestrator

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
)

// PROJECT.md T6: a dismissal or expiry must measurably change whether the
// same finding shape opens an incident again, and the mechanism must be
// inspectable and overridable — never an opaque learned score. These tests
// exercise suppressRecurrenceOnClose (recurrence.go) through the ONE real
// entry point it has, SetState (db.go's closed-state branch), against a
// real Postgres: the interesting behaviour (the EXISTS check that must see
// an INSERT made earlier in the SAME transaction, the CHECK constraint tying
// auto_created to a NULL created_by) is a property of the database, not of
// Go control flow.

// autoSuppressionFixture inserts a throwaway cluster and one incident naming
// a concrete object (object_key set — T6's mechanism needs one to scope a
// rule to), plus n findings rows with the given reasons, all attached to
// that incident. state starts 'Detected' so both -> Dismissed and ->
// Expired are legal direct transitions (state.go's allowedTransitions).
func autoSuppressionFixture(t *testing.T, pool *pgxpool.Pool, objectKey string, reasons []string) (fixture *dbtest.Fixture, tenantID, clusterID, incidentID string) {
	t.Helper()
	ctx := context.Background()

	clusterID = domain.NewID(domain.PrefixCluster)
	incidentID = domain.NewID(domain.PrefixIncident)

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
		clusterID, tenantID, "t6-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	fixture.Created("clusters", 1)

	now := time.Now()
	var objectKeyArg any
	if objectKey != "" {
		objectKeyArg = objectKey
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, object_key)
		 VALUES ($1, $2, $3, $4, 'high', 'Detected', $5, $5, 1, $6)`,
		incidentID, tenantID, clusterID, "test-t6-"+incidentID, now, objectKeyArg); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	fixture.Created("incidents", 1)

	for i, reason := range reasons {
		findingID := domain.NewID(domain.PrefixFinding)
		if _, err := tx.Exec(ctx,
			`INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint,
			    gvk, namespace, object_name, reason, severity, occurred_at, incident_id)
			 VALUES ($1, $2, $3, 'test-detector', 'v1', $4, 'apps/v1/Deployment', 'default', 'payments-api', $5, 'high', $6, $7)`,
			findingID, tenantID, clusterID, "test-t6-fp-"+incidentID, reason, now.Add(time.Duration(i)*time.Second), incidentID); err != nil {
			t.Fatalf("insert finding %d: %v", i, err)
		}
		fixture.Created("findings", 1)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}
	return fixture, tenantID, clusterID, incidentID
}

func cleanupAutoSuppressionFixture(fixture *dbtest.Fixture, pool *pgxpool.Pool, tenantID, clusterID string) {
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "incident_tolerations", SQL: `DELETE FROM incident_tolerations WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incident_notifications", SQL: `DELETE FROM incident_notifications WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "findings", SQL: `DELETE FROM findings WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})
}

// activeTolerationForObject is the same lookup FindingTolerated
// (internal/gateway/toleration.go) runs — reimplemented here, read-only,
// rather than imported, because internal/gateway imports internal/orchestrator
// and the reverse import would be a cycle. Proves the override case
// end-to-end: after removed_at is set, this must stop matching, exactly as
// FindingTolerated's own identical WHERE clause would.
func activeTolerationForObject(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, objectKey, reason string) bool {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	// Same scope every other query in this file uses — an empty/wrong scope
	// is exactly the "argus_app silently returns 0 rows under RLS, which
	// reads as no data rather than an error" trap this repo's own ground
	// rules warn about, and it is not hypothetical: this helper originally
	// scoped with ("", nil) and every positive assertion in this file
	// silently failed as a result.
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	var id string
	err = tx.QueryRow(ctx,
		`SELECT id FROM incident_tolerations
		   WHERE cluster_id = $1 AND object_key = $2 AND removed_at IS NULL
		     AND (expires_at IS NULL OR expires_at > now())
		     AND (reasons IS NULL OR $3 = ANY(reasons))
		   ORDER BY created_at DESC LIMIT 1`,
		clusterID, objectKey, reason).Scan(&id)
	if err == pgx.ErrNoRows {
		return false
	}
	if err != nil {
		t.Fatalf("query active toleration: %v", err)
	}
	return true
}

func TestSetStateDismissedAutoSuppressesTheSameFindingShape(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	objectKey := "apps/v1/Deployment|default|payments-api"

	fixture, tenantID, clusterID, incidentID := autoSuppressionFixture(t, pool, objectKey, []string{"OOMKilled"})

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	// Before: the same finding shape is not suppressed.
	if activeTolerationForObject(t, pool, tenantID, clusterID, objectKey, "OOMKilled") {
		t.Fatalf("a toleration already exists before the incident was even dismissed")
	}

	if err := SetState(ctx, tx, incidentID, StateDismissed); err != nil {
		t.Fatalf("SetState -> Dismissed: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// After: the SAME finding shape now matches an active, auto-created
	// toleration — this IS the "measurably changes whether the same finding
	// shape opens an incident again" acceptance criterion, checked against
	// the exact predicate the hot path (FindingTolerated) evaluates.
	if !activeTolerationForObject(t, pool, tenantID, clusterID, objectKey, "OOMKilled") {
		t.Fatalf("dismissing the incident did not create an active toleration for its own finding shape")
	}

	// Inspectable: the row's own fields say what happened and why, in plain
	// text, with a real bound (never a permanent/opaque rule).
	verifyTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin verify: %v", err)
	}
	defer verifyTx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, verifyTx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope verify: %v", err)
	}
	var (
		note          string
		autoCreated   bool
		createdBy     *string
		reasons       []string
		gotIncidentID *string
		expiresAt     *time.Time
	)
	if err := verifyTx.QueryRow(ctx,
		`SELECT note, auto_created, created_by, reasons, incident_id, expires_at
		   FROM incident_tolerations WHERE cluster_id = $1 AND object_key = $2`,
		clusterID, objectKey).Scan(&note, &autoCreated, &createdBy, &reasons, &gotIncidentID, &expiresAt); err != nil {
		t.Fatalf("read auto-toleration row: %v", err)
	}
	if !autoCreated {
		t.Fatalf("auto_created = false, want true")
	}
	if createdBy != nil {
		t.Fatalf("created_by = %v, want NULL (migration 000112's created_by-xor-auto_created invariant)", *createdBy)
	}
	if gotIncidentID == nil || *gotIncidentID != incidentID {
		t.Fatalf("incident_id = %v, want %s", gotIncidentID, incidentID)
	}
	if !slices.Contains(reasons, "OOMKilled") {
		t.Fatalf("reasons = %v, want it to contain %q", reasons, "OOMKilled")
	}
	if note == "" {
		t.Fatalf("note is empty — an auto-suppressed rule must be inspectable in plain text on TolerationsPage, not a bare row")
	}
	// The bound: Dismissed's window is 14 days, checked with slack rather
	// than pinning the exact constant, since the constant living in
	// recurrence.go is the source of truth this test is verifying reads
	// from, not re-deriving.
	if expiresAt == nil {
		t.Fatalf("expires_at is NULL — permanent suppression is exactly the failure mode T6 must avoid")
	}
	if until := time.Until(*expiresAt); until < 13*24*time.Hour || until > 15*24*time.Hour {
		t.Fatalf("expires_at is %s from now, want ~14 days (Dismissed's bound)", until)
	}

	// Override: removing the rule (the same soft-delete DELETE /tolerations/{id}
	// performs) genuinely un-suppresses the object — the other half of "an
	// operator can inspect and override."
	if _, err := verifyTx.Exec(ctx, `UPDATE incident_tolerations SET removed_at = now() WHERE cluster_id = $1 AND object_key = $2`, clusterID, objectKey); err != nil {
		t.Fatalf("remove toleration: %v", err)
	}
	if err := verifyTx.Commit(ctx); err != nil {
		t.Fatalf("commit removal: %v", err)
	}
	if activeTolerationForObject(t, pool, tenantID, clusterID, objectKey, "OOMKilled") {
		t.Fatalf("removing the toleration did not un-suppress the object — override did not work")
	}

	fixture.Created("incident_tolerations", 1)
	fixture.Created("incident_notifications", 0)
	cleanupAutoSuppressionFixture(fixture, pool, tenantID, clusterID)
}

func TestSetStateExpiredAutoSuppressesWithAShorterBound(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	objectKey := "apps/v1/Deployment|default|expired-object"

	fixture, tenantID, clusterID, incidentID := autoSuppressionFixture(t, pool, objectKey, []string{"GenericConditionAnomaly:Available"})

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	if err := SetState(ctx, tx, incidentID, StateExpired); err != nil {
		t.Fatalf("SetState -> Expired: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	if !activeTolerationForObject(t, pool, tenantID, clusterID, objectKey, "GenericConditionAnomaly:Available") {
		t.Fatalf("expiring the incident did not create an active toleration for its own finding shape")
	}

	verifyTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin verify: %v", err)
	}
	defer verifyTx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, verifyTx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope verify: %v", err)
	}
	var expiresAt time.Time
	if err := verifyTx.QueryRow(ctx,
		`SELECT expires_at FROM incident_tolerations WHERE cluster_id = $1 AND object_key = $2`,
		clusterID, objectKey).Scan(&expiresAt); err != nil {
		t.Fatalf("read expires_at: %v", err)
	}
	// Expired's bound (3 days) must be shorter than Dismissed's (14 days) —
	// StateExpired is explicitly "nobody reviewed this occurrence
	// individually" (state.go's own doc comment), so it earns less trust,
	// not the same amount.
	if until := time.Until(expiresAt); until < 2*24*time.Hour || until > 4*24*time.Hour {
		t.Fatalf("expires_at is %s from now, want ~3 days (Expired's shorter bound)", until)
	}

	fixture.Created("incident_tolerations", 1)
	fixture.Created("incident_notifications", 0)
	cleanupAutoSuppressionFixture(fixture, pool, tenantID, clusterID)
}

func TestSetStateResolvedDoesNotAutoSuppress(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	objectKey := "apps/v1/Deployment|default|resolved-object"

	fixture, tenantID, clusterID, incidentID := autoSuppressionFixture(t, pool, objectKey, []string{"CrashLoopBackOff"})

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	if err := SetState(ctx, tx, incidentID, StateResolved); err != nil {
		t.Fatalf("SetState -> Resolved: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Resolved means the fault is actually gone — it is not one of T6's two
	// triggers (Dismissed/Expired), and must never suppress future
	// detection of a genuinely recurring problem.
	if activeTolerationForObject(t, pool, tenantID, clusterID, objectKey, "CrashLoopBackOff") {
		t.Fatalf("resolving an incident must never auto-suppress — only Dismissed/Expired do")
	}

	fixture.Created("incident_tolerations", 0)
	fixture.Created("incident_notifications", 0)
	cleanupAutoSuppressionFixture(fixture, pool, tenantID, clusterID)
}

func TestSetStateDismissedWithNoObjectKeyDoesNotAutoSuppress(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	// No object_key: a fingerprint-only incident, same as
	// handleTolerateIncident's own refusal case — nothing stable to scope a
	// rule to, so the safe answer is no rule at all rather than guessing.
	fixture, tenantID, clusterID, incidentID := autoSuppressionFixture(t, pool, "", []string{"SomeReason"})

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	if err := SetState(ctx, tx, incidentID, StateDismissed); err != nil {
		t.Fatalf("SetState -> Dismissed: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	verifyTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin verify: %v", err)
	}
	defer verifyTx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, verifyTx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope verify: %v", err)
	}
	var count int
	if err := verifyTx.QueryRow(ctx, `SELECT count(*) FROM incident_tolerations WHERE cluster_id = $1`, clusterID).Scan(&count); err != nil {
		t.Fatalf("count tolerations: %v", err)
	}
	if count != 0 {
		t.Fatalf("count = %d, want 0 — an object-less incident must not auto-suppress", count)
	}

	fixture.Created("incident_tolerations", 0)
	fixture.Created("incident_notifications", 0)
	cleanupAutoSuppressionFixture(fixture, pool, tenantID, clusterID)
}

// TestSetStateDismissedDoesNotDuplicateAnActiveManualToleration reproduces
// handleTolerateIncident's own real shape: it INSERTs a human-authored
// toleration row, THEN calls SetState(..., StateDismissed) in the SAME
// transaction. suppressRecurrenceOnClose's EXISTS check must see that
// earlier, uncommitted INSERT and not add a second, auto-created row saying
// the same thing.
func TestSetStateDismissedDoesNotDuplicateAnActiveManualToleration(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	objectKey := "apps/v1/Deployment|default|manually-tolerated"

	fixture, tenantID, clusterID, incidentID := autoSuppressionFixture(t, pool, objectKey, []string{"OOMKilled"})

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	// The human path's own INSERT, ahead of SetState — mirrors
	// handleTolerateIncident (internal/api/tolerations.go) exactly.
	manualID := domain.NewID(domain.PrefixToleration)
	userID := domain.NewID(domain.PrefixUser)
	if _, err := tx.Exec(ctx,
		`INSERT INTO incident_tolerations (id, tenant_id, cluster_id, object_key, reasons, note, incident_id, created_by, auto_created)
		 VALUES ($1, $2, $3, $4, $5, 'a human decided to tolerate this', $6, $7, false)`,
		manualID, tenantID, clusterID, objectKey, []string{"OOMKilled"}, incidentID, userID); err != nil {
		t.Fatalf("insert manual toleration: %v", err)
	}

	if err := SetState(ctx, tx, incidentID, StateDismissed); err != nil {
		t.Fatalf("SetState -> Dismissed: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	verifyTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin verify: %v", err)
	}
	defer verifyTx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, verifyTx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope verify: %v", err)
	}
	var count int
	if err := verifyTx.QueryRow(ctx, `SELECT count(*) FROM incident_tolerations WHERE cluster_id = $1 AND object_key = $2`, clusterID, objectKey).Scan(&count); err != nil {
		t.Fatalf("count tolerations: %v", err)
	}
	if count != 1 {
		t.Fatalf("count = %d, want 1 — a human-created rule already covering this object must not get a second, auto-created one", count)
	}

	fixture.Created("incident_tolerations", 1)
	fixture.Created("incident_notifications", 0)
	cleanupAutoSuppressionFixture(fixture, pool, tenantID, clusterID)
}
