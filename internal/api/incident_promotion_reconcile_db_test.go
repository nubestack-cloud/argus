package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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

// The promotion-reconciliation regression, against a real Postgres.
//
// # What was wrong
//
// Migration 000092 drew the evidence boundary and said, correctly for a
// migration, that it would not touch historical incident state. Nothing then
// did. On the development database (2026-09-05) that left 42 of the 54 open
// incidents with any finding history at all sitting in the queue on evidence
// this hub would no longer promote — the oldest from 2026-06-17 — and they
// could never leave, because the findings that would have re-attached to them
// are now retained without an incident, so nothing bumps them and nothing
// closes them.
//
// # What each fixture incident is for
//
// The one that carries the finding is residueDefault. The obvious
// implementation of "non-promotable history" reads the stored evidence
// columns, and against real data that closes NOTHING: 000092's backfill is a
// one-shot UPDATE, and a hub build older than internal/gateway/promotion.go
// that writes a generic finding afterwards re-creates the column defaults it
// corrected. 490 such rows exist on the development database, attached to all
// 42 candidates. Delete the isPreEvidenceDefault branch from
// gateway.WouldPromoteStoredFinding and this test fails on that incident
// alone, which is the whole finding in one assertion.
//
// The rest pin the boundaries in the other direction — an incident with a real
// fault anywhere in its history is not a candidate, one with no findings at
// all is not a candidate (an empty history is not a non-promotable one), and
// an incident another writer owns is reported rather than closed.
//
// Gated on ARGUS_TEST_DATABASE_URL like this package's other *_db_test.go
// files; a machine without one gets a clean skip.

type promotionFixture struct {
	tenantID  string
	clusterID string
	// ids by role, see promotionReconcileFixture.
	ids     map[string]string
	fixture *dbtest.Fixture
}

// promotionReconcileFixture builds one throwaway cluster whose incidents cover
// every branch of the scan and the close, and returns a *dbtest.Fixture
// (embedded in promotionFixture.fixture) that already tracks the
// deterministic clusters/incidents/findings rows this setup itself inserts —
// 1 cluster, 7 incidents (backfilled, residueDefault, realFault, mixed,
// noFindings, inFlight, alreadyDismissed), and 7 findings (one each on
// backfilled/residueDefault/realFault/inFlight/alreadyDismissed, two on
// mixed, zero on noFindings: 1+1+1+2+0+1+1=7 — counted directly from the
// addFinding calls below, not assumed).
//
// It does NOT call Cleanup itself: the three tests below each drive
// handleReconcilePromotion (via callReconcilePromotion), which may write a
// different number of timeline_events/incident_notifications rows depending
// on whether it is a dry run or an apply, and how many incidents actually
// close — each test must finish tracking those with fixture.Created(...) and
// then call fixture.fixture.Cleanup(...) itself.
func promotionReconcileFixture(t *testing.T, pool *pgxpool.Pool) promotionFixture {
	t.Helper()
	ctx := context.Background()

	f := promotionFixture{clusterID: domain.NewID(domain.PrefixCluster), ids: map[string]string{}}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	f.tenantID, err = data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		f.clusterID, f.tenantID, "promotion-reconcile-test-"+f.clusterID, "fp-"+f.clusterID); err != nil {
		t.Fatalf("insert throwaway cluster: %v", err)
	}
	fixture := dbtest.New(t)
	fixture.Created("clusters", 1)

	now := time.Now()
	addIncident := func(role, state, openingReason string) string {
		id := domain.NewID(domain.PrefixIncident)
		f.ids[role] = id
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen,
			   occurrence_count, workload_key, opening_reason, object_key)
			 VALUES ($1, $2, $3, $4, 'medium', $5, $6, $6, 1, $7, $8, $9)`,
			id, f.tenantID, f.clusterID, "fp-promo-"+id, state, now,
			f.clusterID+"/apps/Deployment/default/"+role, openingReason,
			f.clusterID+"/v1/Pod/default/"+role); err != nil {
			t.Fatalf("insert %s incident: %v", role, err)
		}
		fixture.Created("incidents", 1)
		return id
	}
	addFinding := func(incidentID, reason, class, confidence, impact string) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint,
			   gvk, namespace, object_name, reason, message, severity, occurred_at, incident_id,
			   signal_class, confidence, impact)
			 VALUES ($1, $2, $3, 'test-detector', '1', $4, 'v1/Pod', 'default', 'obj', $5, 'msg',
			   'medium', $6, $7, $8, $9, $10)`,
			domain.NewID(domain.PrefixFinding), f.tenantID, f.clusterID, "fp-promo-fnd-"+incidentID+reason,
			reason, now, incidentID, class, confidence, impact); err != nil {
			t.Fatalf("insert finding %s on %s: %v", reason, incidentID, err)
		}
		fixture.Created("findings", 1)
	}

	// (1) The backfilled case: 000092 already wrote the honest tuple.
	addFinding(addIncident("backfilled", orchestrator.StateDetected, "GenericConditionAnomaly:Ready"),
		"GenericConditionAnomaly:Ready",
		tunnel.FindingClassAnomaly, tunnel.FindingConfidenceUnverified, tunnel.FindingImpactNone)

	// (2) The residue: a generic mechanism carrying migration 000092's column
	// DEFAULTS, written by a hub build that did not know the columns existed.
	// This is the assertion the finding is actually about.
	addFinding(addIncident("residueDefault", orchestrator.StateDetected, "GenericConditionAnomaly:CreatorMadeOwner"),
		"GenericConditionAnomaly:CreatorMadeOwner",
		tunnel.FindingClassFault, tunnel.FindingConfidenceVerified, tunnel.FindingImpactDegraded)

	// (3) A genuine fault. Not a candidate, and the same stored tuple as (2) —
	// so nothing here can be closing on the tuple alone.
	addFinding(addIncident("realFault", orchestrator.StateDetected, "CrashLoopBackOff"),
		"CrashLoopBackOff",
		tunnel.FindingClassFault, tunnel.FindingConfidenceVerified, tunnel.FindingImpactDegraded)

	// (4) A mixed history. Correlation keys on the OBJECT, not the symptom
	// (migration 000036), so one object legitimately accumulates findings from
	// several detectors — and a single promotable one anywhere in the history
	// means the incident was warranted.
	mixed := addIncident("mixed", orchestrator.StateDetected, "GenericConditionAnomaly:Ready")
	addFinding(mixed, "GenericConditionAnomaly:Ready",
		tunnel.FindingClassAnomaly, tunnel.FindingConfidenceUnverified, tunnel.FindingImpactNone)
	addFinding(mixed, "ImagePullBackOff",
		tunnel.FindingClassFault, tunnel.FindingConfidenceVerified, tunnel.FindingImpactDegraded)

	// (5) No findings at all. An empty history is not a non-promotable one.
	addIncident("noFindings", orchestrator.StateDetected, "GenericConditionAnomaly:Ready")

	// (6) A candidate another writer owns. Reported, never closed.
	addFinding(addIncident("inFlight", orchestrator.StateInvestigating, "GenericConditionAnomaly:Approved"),
		"GenericConditionAnomaly:Approved",
		tunnel.FindingClassAnomaly, tunnel.FindingConfidenceUnverified, tunnel.FindingImpactNone)

	// (7) Already closed. Must not be scanned at all.
	addFinding(addIncident("alreadyDismissed", orchestrator.StateDismissed, "GenericConditionAnomaly:Ready"),
		"GenericConditionAnomaly:Ready",
		tunnel.FindingClassAnomaly, tunnel.FindingConfidenceUnverified, tunnel.FindingImpactNone)

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup transaction: %v", err)
	}

	f.fixture = fixture
	return f
}

// promotionReconcileDeletes is the cleanup statement list every
// promotionReconcileFixture caller uses — every table the fixture setup OR
// handleReconcilePromotion could touch, so callers only need to get the
// Created(...) counts right, not the delete list itself.
func promotionReconcileDeletes(clusterID string) []dbtest.TableDelete {
	return []dbtest.TableDelete{
		{Table: "timeline_events", SQL: `DELETE FROM timeline_events WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incident_notifications", SQL: `DELETE FROM incident_notifications WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "findings", SQL: `DELETE FROM findings WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	}
}

// promotionScopedTx narrows to the fixture's own cluster, so the assertions
// below are about the fixture and not about whatever else the development
// database happens to hold.
func promotionScopedTx(t *testing.T, pool *pgxpool.Pool, f promotionFixture) pgx.Tx {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	t.Cleanup(func() { tx.Rollback(context.Background()) }) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	return tx
}

func promotionTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connString := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if connString == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping the promotion reconciliation regression test")
	}
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func promotionCandidateRoles(t *testing.T, f promotionFixture, candidates []promotionReconcileIncident) []string {
	t.Helper()
	byID := map[string]string{}
	for role, id := range f.ids {
		byID[id] = role
	}
	var roles []string
	for _, c := range candidates {
		roles = append(roles, byID[c.IncidentID])
	}
	return roles
}

// TestPromotionReconcileScanSelectsOnlyUnwarrantedIncidents pins which
// incidents the scan calls candidates, and — through residueDefault — that it
// judges by the current classification rather than by a stored tuple a
// pre-evidence writer left behind.
func TestPromotionReconcileScanSelectsOnlyUnwarrantedIncidents(t *testing.T) {
	pool := promotionTestPool(t)
	f := promotionReconcileFixture(t, pool)

	// promotionReconcileScan is read-only (no writes), and promotionScopedTx's
	// own tx is rolled back (never committed) regardless — so nothing beyond
	// the fixture's own committed setup rows exists for cleanup to find.
	// Registered BEFORE promotionScopedTx below: t.Cleanup is LIFO, and this
	// dbtest cleanup opens its OWN transaction — it must run AFTER
	// promotionScopedTx's rollback releases any row locks the exercised code
	// took, not before (a DELETE racing a still-open, lock-holding tx just
	// times out waiting on it).
	f.fixture.Created("timeline_events", 0)
	f.fixture.Created("incident_notifications", 0)
	f.fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterID})
	}, promotionReconcileDeletes(f.clusterID))

	ctx := context.Background()
	tx := promotionScopedTx(t, pool, f)

	scanned, candidates, err := promotionReconcileScan(ctx, tx)
	if err != nil {
		t.Fatalf("promotionReconcileScan: %v", err)
	}

	// backfilled, residueDefault, realFault, mixed, inFlight — every open
	// incident WITH findings. noFindings and alreadyDismissed are excluded for
	// different reasons and neither may appear.
	if scanned != 5 {
		t.Errorf("scanned %d open incident(s) with findings, want 5", scanned)
	}

	got := map[string]bool{}
	for _, role := range promotionCandidateRoles(t, f, candidates) {
		got[role] = true
	}
	want := map[string]bool{"backfilled": true, "residueDefault": true, "inFlight": true}
	for role := range want {
		if !got[role] {
			extra := ""
			if role == "residueDefault" {
				extra = " — a generic mechanism carrying migration 000092's column defaults was written by a build that predates those columns, not asserted as a verified fault; reading it as one is what leaves these incidents permanently in the queue"
			}
			t.Errorf("incident %q is not a candidate but should be%s", role, extra)
		}
	}
	for role := range got {
		if !want[role] {
			t.Errorf("incident %q is a candidate but must not be", role)
		}
	}
}

// TestPromotionReconcileDryRunChangesNothing is the safeguard: the default is
// a preview, and a preview that quietly closed anything would be the worst
// possible bug in a bulk close.
func TestPromotionReconcileDryRunChangesNothing(t *testing.T) {
	pool := promotionTestPool(t)
	f := promotionReconcileFixture(t, pool)

	// A dry run itself changes nothing, and promotionScopedTx's own tx is
	// rolled back (never committed) regardless of what runs inside it — so
	// nothing beyond the fixture's own committed setup rows exists for
	// cleanup to find. Registered BEFORE promotionScopedTx below for the same
	// lock-ordering reason as the scan test above.
	f.fixture.Created("timeline_events", 0)
	f.fixture.Created("incident_notifications", 0)
	f.fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterID})
	}, promotionReconcileDeletes(f.clusterID))

	ctx := context.Background()
	tx := promotionScopedTx(t, pool, f)

	resp := callReconcilePromotion(t, tx, f, `{}`)
	if resp.Applied {
		t.Errorf("applied = true for a body that never said so")
	}
	if resp.Closed != 0 {
		t.Errorf("closed %d incident(s) in a dry run", resp.Closed)
	}
	if resp.Candidates != 3 {
		t.Errorf("candidates = %d, want 3", resp.Candidates)
	}
	for role, id := range f.ids {
		if role == "alreadyDismissed" {
			continue
		}
		if state := promotionIncidentState(t, ctx, tx, id); state == orchestrator.StateDismissed {
			t.Errorf("incident %q is %s after a dry run", role, state)
		}
	}
}

// TestPromotionReconcileClosesTheUnwarrantedAndPreservesEveryFinding is the
// whole job in one test: the right incidents close, through the state machine,
// with the closing stamps and history a hand-dismissed incident gets — and
// every finding row is still there afterwards.
func TestPromotionReconcileClosesTheUnwarrantedAndPreservesEveryFinding(t *testing.T) {
	pool := promotionTestPool(t)
	f := promotionReconcileFixture(t, pool)

	// promotionScopedTx's own tx is rolled back (never committed) at the end
	// of this test regardless of what handleReconcilePromotion writes inside
	// it — so, from a fresh transaction's point of view (which is what
	// dbtest.Fixture's own cleanup uses), none of those writes ever happened;
	// only the fixture's own committed setup rows exist for cleanup to find.
	// Registered BEFORE promotionScopedTx below: this test's own UPDATE
	// incidents call (via handleReconcilePromotion, applying real closes)
	// takes row locks that live until promotionScopedTx's rollback runs —
	// t.Cleanup is LIFO, so this dbtest cleanup (its OWN, separate
	// transaction) must be registered first to run AFTER that rollback, or
	// its DELETE FROM incidents blocks on those locks until it times out.
	f.fixture.Created("timeline_events", 0)
	f.fixture.Created("incident_notifications", 0)
	f.fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterID})
	}, promotionReconcileDeletes(f.clusterID))

	ctx := context.Background()
	tx := promotionScopedTx(t, pool, f)

	before := promotionFindingCount(t, ctx, tx, f.clusterID)

	resp := callReconcilePromotion(t, tx, f,
		`{"apply": true, "note": "raised under a promotion rule the product has since retired"}`)

	if !resp.Applied {
		t.Fatalf("applied = false")
	}
	if resp.Closed != 2 {
		t.Errorf("closed %d incident(s), want 2 (backfilled and residueDefault)", resp.Closed)
	}
	if resp.SkippedInProgress != 1 {
		t.Errorf("skipped %d incident(s), want 1 (the Investigating one)", resp.SkippedInProgress)
	}

	// Findings are the record that the detector fired. Closing an incident
	// says the CLAIM was unwarranted; it must not touch the evidence.
	if after := promotionFindingCount(t, ctx, tx, f.clusterID); after != before {
		t.Errorf("findings went from %d to %d — this must never delete or detach a finding", before, after)
	}
	if resp.FindingsRetained == 0 {
		t.Errorf("findingsRetained = 0; the response has to be able to state what was kept")
	}

	// PROJECT.md T2 (2026-09-07): promotionReconcileClose now targets
	// StateExpired, not StateDismissed — a bulk/mechanical reconciliation
	// closure is exactly the "nobody individually judged this" case T2
	// exists to distinguish from a human's own Dismissed. alreadyDismissed
	// is untouched by the reconcile either way (it was already closed before
	// this call ran), so it stays the literal Dismissed it started as.
	wantState := map[string]string{
		"backfilled":       orchestrator.StateExpired,
		"residueDefault":   orchestrator.StateExpired,
		"realFault":        orchestrator.StateDetected,
		"mixed":            orchestrator.StateDetected,
		"noFindings":       orchestrator.StateDetected,
		"inFlight":         orchestrator.StateInvestigating,
		"alreadyDismissed": orchestrator.StateDismissed,
	}
	for role, want := range wantState {
		if got := promotionIncidentState(t, ctx, tx, f.ids[role]); got != want {
			t.Errorf("incident %q is %s, want %s", role, got, want)
		}
	}

	// SetState's own invariants, which a raw UPDATE would have skipped.
	for _, role := range []string{"backfilled", "residueDefault"} {
		var resolvedAt *time.Time
		var resolutionKind *string
		if err := tx.QueryRow(ctx,
			`SELECT resolved_at, resolution_kind FROM incidents WHERE id = $1`, f.ids[role],
		).Scan(&resolvedAt, &resolutionKind); err != nil {
			t.Fatalf("read closing stamps for %q: %v", role, err)
		}
		// resolved_at IS stamped for a transition into Expired
		// (PROJECT.md B156, fixed 2026-09-17): this assertion used to want
		// nil, reasoning that the column means "this incident's lifecycle
		// concluded," which is not true for a state whose whole point is
		// that a recurrence reopens it. That conflated two different
		// questions — orchestrator.IsClosed's own doc comment separates them
		// explicitly: "is this incident's OWN lifecycle over" (yes, the
		// moment it reaches Expired — ARGUS will not act on it again on its
		// own) versus "may a recurring Finding re-attach to it" (yes, via
		// the one real Expired -> Detected edge, which is a correlation
		// question, not a resolved_at question). The bug was that db.go's
		// SetState asked BOTH questions using fleetgroup.IsClosedState (the
		// 2-value correlation predicate), so Expired matched neither it nor
		// the StateResolved branch and got no stamp at all — not that the
		// stamp was wrong to want.
		if resolvedAt == nil {
			t.Errorf("incident %q closed with resolved_at = nil, want a real timestamp — Expired is still a closing transition for resolved_at purposes (PROJECT.md B156)", role)
		}
		if resolutionKind != nil {
			// Resolved would have derived 'self_healed' here, since there is
			// no succeeded execution and no merged pull request. Nothing
			// self-healed; nothing was ever wrong.
			t.Errorf("incident %q carries resolution_kind %q — a reconciliation close asserts no outcome", role, *resolutionKind)
		}

		var detail []byte
		if err := tx.QueryRow(ctx,
			`SELECT payload FROM timeline_events
			  WHERE incident_id = $1 AND event_type = 'IncidentExpired' ORDER BY occurred_at DESC LIMIT 1`,
			f.ids[role]).Scan(&detail); err != nil {
			t.Fatalf("read closing timeline event for %q: %v", role, err)
		}
		var parsed map[string]any
		if err := json.Unmarshal(detail, &parsed); err != nil {
			t.Fatalf("unmarshal timeline detail for %q: %v", role, err)
		}
		// The machine-readable key is the whole reason no new state and no new
		// column were added: it is how a later reader tells a bulk
		// reconciliation apart from a human's individual judgement.
		if parsed["reason"] != promotionReconcileReason {
			t.Errorf("incident %q closed with timeline reason %v, want %q", role, parsed["reason"], promotionReconcileReason)
		}
	}
}

func callReconcilePromotion(t *testing.T, tx pgx.Tx, f promotionFixture, body string) promotionReconcileResponse {
	t.Helper()
	s := &Server{}
	rc := &requestContext{Tx: tx, TenantID: f.tenantID, UserID: "usr_test"}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/reconcile-promotion", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleReconcilePromotion(rec, req, rc)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var resp promotionReconcileResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return resp
}

func promotionIncidentState(t *testing.T, ctx context.Context, tx pgx.Tx, incidentID string) string {
	t.Helper()
	var state string
	if err := tx.QueryRow(ctx, `SELECT state FROM incidents WHERE id = $1`, incidentID).Scan(&state); err != nil {
		t.Fatalf("read state of %s: %v", incidentID, err)
	}
	return state
}

func promotionFindingCount(t *testing.T, ctx context.Context, tx pgx.Tx, clusterID string) int {
	t.Helper()
	var n int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM findings WHERE cluster_id = $1 AND incident_id IS NOT NULL`, clusterID).Scan(&n); err != nil {
		t.Fatalf("count findings: %v", err)
	}
	return n
}
