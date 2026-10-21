package orchestrator

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
	"argus/internal/remediation"
)

// SetState's two real guarantees — that it refuses an illegal transition,
// and that it SERIALIZES concurrent transitions against the same incident —
// are both properties of a live Postgres, not of Go code. The transition
// table itself is exhaustively covered without a database in state_test.go;
// what those tests cannot show is that the row-level SELECT ... FOR UPDATE
// actually makes the check atomic, which is the entire reason the Executing
// race closes. So, like internal/authz/session_test.go (the existing
// precedent in this codebase for a DB-backed unit test), these talk to a
// real Postgres behind ARGUS_TEST_DATABASE_URL, and a machine without one
// gets a clean skip rather than a failure. Point it at the same dev-compose
// stack scripts/smoke-test.sh already exercises, e.g.:
//
//	export ARGUS_TEST_DATABASE_URL="postgres://argus_app:dev-local-password@localhost:5432/argus?sslmode=disable"
//
// (argus_app, not the postgres superuser — so these run under the same
// FORCE ROW LEVEL SECURITY the hub itself does, not a superuser's
// RLS-bypassing view.)
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connString := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if connString == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping DB-backed SetState tests (see this file's doc comment)")
	}
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// testIncident inserts a throwaway cluster and one incident in startState,
// and registers cleanup for both. Returns the ids and the tenant the
// caller's own transactions must scope to.
//
// A cluster of its own rather than reusing whatever the dev database
// happens to contain: incidents.cluster_id is a foreign key, and a test that
// leaves state on a real cluster's rows would show up in the UI and in
// fleetgroup recomputation for that cluster's actual fingerprints.
func testIncident(t *testing.T, pool *pgxpool.Pool, startState string) (tenantID, clusterID, incidentID, fingerprint string) {
	t.Helper()
	ctx := context.Background()

	clusterID = domain.NewID(domain.PrefixCluster)
	incidentID = domain.NewID(domain.PrefixIncident)
	// A fingerprint unique to this test run: fleetgroup.Recompute groups
	// incidents fleet-wide by fingerprint, so sharing one with a real
	// incident would make this test's transitions perturb that group.
	fingerprint = "test-setstate-" + incidentID

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err = data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "setstate-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert throwaway cluster: %v", err)
	}
	now := time.Now()
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
		 VALUES ($1, $2, $3, $4, 'high', $5, $6, $6, 1)`,
		incidentID, tenantID, clusterID, fingerprint, startState, now); err != nil {
		t.Fatalf("insert test incident in state %s: %v", startState, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup transaction: %v", err)
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		// PROJECT.md B188: the catalogue-driven half of the leak check, the
		// same one dbtest.Fixture.OwnsCluster wires up. This fixture is not
		// on dbtest.Fixture because its deletes are all keyed on a single
		// freshly-minted ULID, so the over-deletion half Fixture exists to
		// prevent is already structurally impossible here — what it is
		// missing is the other half: a table nobody thought to name.
		// AssertNoClusterResidue asks pg_class rather than this delete
		// list, so a migration that adds a cluster-scoped table joins the
		// check the day it lands.
		//
		// Deferred here, BEFORE tx.Rollback's own defer, so LIFO runs the
		// rollback first and this reads a settled database — and so it runs
		// even when a delete above returned early, which is precisely the
		// case where something has been left behind.
		defer dbtest.AssertNoClusterResidue(t, pool, tenantID, clusterID)

		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Errorf("cleanup: begin: %v", err)
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Errorf("cleanup: set request scope: %v", err)
			return
		}
		// timeline_events (BACKLOG.md B1): MarkInvestigating/ApplyAnalysisResult
		// now write it unconditionally, so any test built on this fixture that
		// exercises either one leaves rows here unless this cleanup deletes
		// them too — deleted before incidents rather than relying on a
		// cascade, since timeline_events carries no FK back to incidents.
		if _, err := tx.Exec(ctx, `DELETE FROM timeline_events WHERE incident_id = $1`, incidentID); err != nil {
			t.Errorf("cleanup: delete timeline_events for incident %s: %v", incidentID, err)
			return
		}
		// incident_notifications (BACKLOG.md N1): SetState now writes it for
		// every AwaitingApproval/Failed/ExecutionUnknown/Reopened transition
		// — any SetState-based test built on this fixture that reaches one
		// of those leaves a row here otherwise. No FK back to incidents
		// (migration 000083's own comment explains why), so this is purely
		// housekeeping, not a constraint this codebase would fail on either
		// way.
		if _, err := tx.Exec(ctx, `DELETE FROM incident_notifications WHERE incident_id = $1`, incidentID); err != nil {
			t.Errorf("cleanup: delete incident_notifications for incident %s: %v", incidentID, err)
			return
		}
		if _, err := tx.Exec(ctx, `DELETE FROM incidents WHERE id = $1`, incidentID); err != nil {
			t.Errorf("cleanup: delete incident %s: %v", incidentID, err)
			return
		}
		if _, err := tx.Exec(ctx, `DELETE FROM clusters WHERE id = $1`, clusterID); err != nil {
			t.Errorf("cleanup: delete cluster %s: %v", clusterID, err)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			t.Errorf("cleanup: commit: %v", err)
		}
	})

	return tenantID, clusterID, incidentID, fingerprint
}

// currentState reads one incident's state in its own scoped transaction.
func currentState(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID string) string {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin read transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	var state string
	if err := tx.QueryRow(ctx, `SELECT state FROM incidents WHERE id = $1`, incidentID).Scan(&state); err != nil {
		t.Fatalf("read incident state: %v", err)
	}
	return state
}

// TestSetStateRefusesToRevivADismissedIncident is the end-to-end form of the
// central bug: an approver rejects a plan (AwaitingApproval -> Dismissed, the
// real transition internal/api/approvals.go performs, fleetgroup recomputation
// included), and every attempt to walk that incident back out of Dismissed
// must now fail AND leave the stored state untouched. Before this fix,
// MarkInvestigating here succeeded silently, the incident collected a fresh
// plan, and a second approver could execute it.
func TestSetStateRefusesToReviveADismissedIncident(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, incidentID, _ := testIncident(t, pool, StateAwaitingApproval)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	// The legitimate reject transition must still work — this is the
	// "don't break what the code relies on today" half.
	if err := SetState(ctx, tx, incidentID, StateDismissed); err != nil {
		t.Fatalf("AwaitingApproval -> Dismissed must be legal (internal/api/approvals.go's reject handler does exactly this): %v", err)
	}

	for _, to := range []string{StateInvestigating, StateAwaitingApproval, StateExecuting, StateReopened, StateDetected} {
		err := SetState(ctx, tx, incidentID, to)
		if err == nil {
			t.Fatalf("SetState(Dismissed -> %s) succeeded; a rejected incident must stay rejected", to)
		}
		if !errors.Is(err, ErrIllegalTransition) {
			t.Errorf("SetState(Dismissed -> %s) error = %v, want one wrapping ErrIllegalTransition", to, err)
		}
		var illegal *IllegalTransitionError
		if !errors.As(err, &illegal) {
			t.Errorf("SetState(Dismissed -> %s) error is not an *IllegalTransitionError: %v", to, err)
		} else if illegal.From != StateDismissed || illegal.To != to || illegal.IncidentID != incidentID {
			t.Errorf("IllegalTransitionError = %+v, want {IncidentID:%s From:Dismissed To:%s}", illegal, incidentID, to)
		}
	}

	// MarkInvestigating is the specific entry point POST
	// /incidents/{id}/analyze and internal/autoanalyze both go through, so
	// assert it rather than only the SetState primitive underneath it.
	if err := MarkInvestigating(ctx, tx, tenantID, clusterID, incidentID); !errors.Is(err, ErrIllegalTransition) {
		t.Errorf("MarkInvestigating on a Dismissed incident: error = %v, want one wrapping ErrIllegalTransition", err)
	}

	var stored string
	if err := tx.QueryRow(ctx, `SELECT state FROM incidents WHERE id = $1`, incidentID).Scan(&stored); err != nil {
		t.Fatalf("re-read state: %v", err)
	}
	if stored != StateDismissed {
		t.Errorf("incident state = %q after every rejected transition, want %q — a refused transition must not partially apply", stored, StateDismissed)
	}
}

// TestSetStateStampsResolvedAtOnlyOnClose is BACKLOG.md H4's acceptance
// test: resolved_at (migration 000065) must be set exactly when an incident
// closes, through SetState — the one function that ever writes
// incidents.state — never on an ordinary open-state transition, and never
// twice (CanTransition already refuses any edge out of Resolved/Dismissed,
// so a second write is structurally unreachable, not just untested).
func TestSetStateStampsResolvedAtOnlyOnClose(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, incidentID, _ := testIncident(t, pool, StateAwaitingApproval)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	readResolvedAt := func() *time.Time {
		var v *time.Time
		if err := tx.QueryRow(ctx, `SELECT resolved_at FROM incidents WHERE id = $1`, incidentID).Scan(&v); err != nil {
			t.Fatalf("read resolved_at: %v", err)
		}
		return v
	}

	if v := readResolvedAt(); v != nil {
		t.Fatalf("resolved_at = %v before any transition, want nil", v)
	}

	// AwaitingApproval -> Investigating (re-analyze) is a legal, ordinary
	// open-state transition — must not stamp resolved_at.
	if err := SetState(ctx, tx, incidentID, StateInvestigating); err != nil {
		t.Fatalf("AwaitingApproval -> Investigating: %v", err)
	}
	if v := readResolvedAt(); v != nil {
		t.Errorf("resolved_at = %v after an ordinary open-state transition (Investigating), want nil — this incident has not closed", v)
	}
	// Back to AwaitingApproval so the close transition below is legal
	// (Investigating has no direct edge to Dismissed — a human waits for
	// the analysis to finish first, per allowedTransitions' own comment).
	if err := SetState(ctx, tx, incidentID, StateAwaitingApproval); err != nil {
		t.Fatalf("Investigating -> AwaitingApproval: %v", err)
	}

	before := time.Now().Add(-time.Second)
	if err := SetState(ctx, tx, incidentID, StateDismissed); err != nil {
		t.Fatalf("AwaitingApproval -> Dismissed: %v", err)
	}
	got := readResolvedAt()
	if got == nil {
		t.Fatal("resolved_at is nil after closing (Dismissed), want a real timestamp")
	}
	if got.Before(before) || got.After(time.Now().Add(time.Second)) {
		t.Errorf("resolved_at = %v, want a timestamp close to now (%v)", got, time.Now())
	}
}

// TestSetStateStampsResolvedAtAndRecomputesGroupsOnExpired is PROJECT.md
// B156's regression test. SetState's "is this closing?" check used to call
// fleetgroup.IsClosedState (the 2-value {Resolved, Dismissed} correlation
// predicate) instead of orchestrator.IsClosed (the 3-value
// {Resolved, Dismissed, Expired} lifecycle predicate) for BOTH the
// resolved_at stamp and the fleet/replica/object-group recompute gate, so a
// transition into Expired matched neither the StateResolved branch nor the
// fleetgroup.IsClosedState branch: it stamped no resolved_at and skipped the
// recompute every other closing transition performs.
//
// This mirrors TestSetStateStampsResolvedAtOnlyOnClose's resolved_at
// assertion (above) and adds the group-recompute assertion that test doesn't
// make. Two incidents on one cluster share (workload_key, opening_reason) and
// start with no workload_group_id/object_group_id — replicagroup/objectgroup
// have never run for them, the same as a real incident inserted by a Finding
// that arrived before any sibling shared its correlation key. Transitioning
// the first into Expired must stamp its own resolved_at AND run
// replicagroup.Recompute/objectgroup.Recompute, which groups the two siblings
// together.
//
// That grouping outcome is the concrete answer to this fix's one open policy
// question ("does an Expired incident leave its correlation group?"): no,
// and this fix doesn't have to decide that — replicagroup.Recompute and
// objectgroup.Recompute (like fleetgroup.Recompute) hardcode their OWN
// "currently open" query as the 2-value set (state NOT IN
// ('Resolved','Dismissed')), so an Expired incident is correctly still
// counted open FOR CORRELATION even though its lifecycle has closed
// (orchestrator.IsClosed's own doc comment). Firing the recompute on an
// Expired transition therefore never shrinks a group on account of THIS
// incident closing — it only ever picks up membership the incident hadn't
// been evaluated for yet, exactly as it would for any other still-open
// state. The resolved_at stamp and the recompute gate are fixed by the same
// one-line change in db.go; the recompute's own behaviour needed no change
// at all.
func TestSetStateStampsResolvedAtAndRecomputesGroupsOnExpired(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, addIncident := siblingFixture(t, pool)
	ctx := context.Background()

	const workload = "apps/v1/Deployment|argus-test|b156-target"
	const reason = "CrashLoopBackOff"
	now := time.Now()

	subject := addIncident(StateAwaitingApproval, workload, reason, now)
	sibling := addIncident(StateDetected, workload, reason, now)

	readIncident := func(incidentID string) (resolvedAt *time.Time, workloadGroupID, objectGroupID *string, state string) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin read: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Fatalf("scope: %v", err)
		}
		if err := tx.QueryRow(ctx,
			`SELECT resolved_at, workload_group_id, object_group_id, state FROM incidents WHERE id = $1`,
			incidentID).Scan(&resolvedAt, &workloadGroupID, &objectGroupID, &state); err != nil {
			t.Fatalf("read incident %s: %v", incidentID, err)
		}
		return resolvedAt, workloadGroupID, objectGroupID, state
	}

	// Precondition: neither incident has been through a group recompute yet
	// (both inserted directly, bypassing internal/gateway.handleFinding, the
	// only place that would otherwise have assigned these columns already).
	if _, wg, og, _ := readIncident(subject); wg != nil || og != nil {
		t.Fatalf("subject incident already has workload_group_id=%v object_group_id=%v before any transition, want both nil", wg, og)
	}
	if _, wg, og, _ := readIncident(sibling); wg != nil || og != nil {
		t.Fatalf("sibling incident already has workload_group_id=%v object_group_id=%v before any transition, want both nil", wg, og)
	}

	before := time.Now().Add(-time.Second)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if err := SetState(ctx, tx, subject, StateExpired); err != nil {
		t.Fatalf("AwaitingApproval -> Expired: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	subjectResolvedAt, subjectWG, subjectOG, subjectState := readIncident(subject)
	if subjectState != StateExpired {
		t.Fatalf("subject state = %q, want %q", subjectState, StateExpired)
	}
	if subjectResolvedAt == nil {
		t.Fatal("resolved_at is nil after closing (Expired), want a real timestamp — PROJECT.md B156")
	}
	if subjectResolvedAt.Before(before) || subjectResolvedAt.After(time.Now().Add(time.Second)) {
		t.Errorf("resolved_at = %v, want a timestamp close to now (%v)", subjectResolvedAt, time.Now())
	}
	if subjectWG == nil {
		t.Fatal("subject incident has no workload_group_id after transitioning to Expired — replicagroup.Recompute did not run (PROJECT.md B156)")
	}
	if subjectOG == nil {
		t.Fatal("subject incident has no object_group_id after transitioning to Expired — objectgroup.Recompute did not run (PROJECT.md B156)")
	}

	_, siblingWG, siblingOG, siblingState := readIncident(sibling)
	if siblingState != StateDetected {
		t.Fatalf("sibling state = %q, want %q — the sibling was never transitioned and must be untouched", siblingState, StateDetected)
	}
	if siblingWG == nil || *siblingWG != *subjectWG {
		t.Errorf("sibling workload_group_id = %v, subject workload_group_id = %v, want equal non-nil — both incidents share (workload_key, opening_reason), and replicagroup must still count the now-Expired subject as open for correlation", siblingWG, subjectWG)
	}
	if siblingOG == nil || *siblingOG != *subjectOG {
		t.Errorf("sibling object_group_id = %v, subject object_group_id = %v, want equal non-nil — both incidents share workload_key, and objectgroup must still count the now-Expired subject as open for correlation", siblingOG, subjectOG)
	}
}

// TestSetStateResetsAutoAnalysisAttemptedAtOnReopenUpToBound is PROJECT.md
// B144's regression test: a Reopened transition must reset
// auto_analysis_attempted_at to NULL — making the incident an ordinary
// automatic-analysis candidate again, per autoanalyze.candidateQuery's own
// state list, which never excluded Reopened in the first place — but only
// up to maxAutoAnalysisReopens times, after which the incident is left
// permanently attempted so a genuinely flip-flopping incident reaches a
// human instead of looping forever.
//
// State transitions between iterations are set directly rather than walked
// through SetState's own legal edges (Validating -> Reopened -> Investigating
// -> ... -> Validating is a real but much longer path, already covered by
// state_test.go/validation_test.go) — this test isolates SetState's OWN
// Reopened-handling logic, not the transition graph's shape.
func TestSetStateResetsAutoAnalysisAttemptedAtOnReopenUpToBound(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, incidentID, _ := testIncident(t, pool, StateValidating)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	readGate := func() (attemptedAt *time.Time, reopenCount int) {
		if err := tx.QueryRow(ctx, `SELECT auto_analysis_attempted_at, auto_analysis_reopen_count FROM incidents WHERE id = $1`, incidentID).
			Scan(&attemptedAt, &reopenCount); err != nil {
			t.Fatalf("read auto_analysis columns: %v", err)
		}
		return attemptedAt, reopenCount
	}
	stampAttemptedAndResetToValidating := func() {
		t.Helper()
		if _, err := tx.Exec(ctx,
			`UPDATE incidents SET state = 'Validating', auto_analysis_attempted_at = now() WHERE id = $1`, incidentID); err != nil {
			t.Fatalf("test setup: stamp attempted_at and reset to Validating: %v", err)
		}
	}

	// Simulate a completed automatic analysis before the FIRST reopen: the
	// real precondition for this to matter at all (a plan that was never
	// analyzed could not have reached Validating).
	stampAttemptedAndResetToValidating()

	for i := 1; i <= maxAutoAnalysisReopens; i++ {
		if err := SetState(ctx, tx, incidentID, StateReopened); err != nil {
			t.Fatalf("reopen #%d: SetState: %v", i, err)
		}
		attemptedAt, reopenCount := readGate()
		if attemptedAt != nil {
			t.Errorf("reopen #%d: auto_analysis_attempted_at = %v, want nil — reopen #%d is within the %d-reopen bound and must reset it", i, attemptedAt, i, maxAutoAnalysisReopens)
		}
		if reopenCount != i {
			t.Errorf("reopen #%d: auto_analysis_reopen_count = %d, want %d", i, reopenCount, i)
		}
		// Simulate autoanalyze picking this back up, completing a fresh
		// analysis, and the incident reaching Validating again.
		stampAttemptedAndResetToValidating()
	}

	// One more reopen, past the bound: auto_analysis_attempted_at must stay
	// stamped (the incident is left permanently attempted, exactly as
	// autoanalyze's own retry policy already does once ITS bound is spent),
	// and the counter must not keep climbing past the bound it exists to
	// enforce.
	if err := SetState(ctx, tx, incidentID, StateReopened); err != nil {
		t.Fatalf("reopen #%d (past the bound): SetState: %v", maxAutoAnalysisReopens+1, err)
	}
	attemptedAt, reopenCount := readGate()
	if attemptedAt == nil {
		t.Errorf("reopen #%d: auto_analysis_attempted_at is nil, want it left stamped — the %d-reopen bound was already spent, so this incident must not be reset again", maxAutoAnalysisReopens+1, maxAutoAnalysisReopens)
	}
	if reopenCount != maxAutoAnalysisReopens {
		t.Errorf("reopen #%d: auto_analysis_reopen_count = %d, want it to stay at %d, not keep climbing", maxAutoAnalysisReopens+1, reopenCount, maxAutoAnalysisReopens)
	}

	// Read within the same uncommitted tx (matching readGate above) rather
	// than through currentState's own fresh connection, which would see
	// nothing this test has written yet.
	var state string
	if err := tx.QueryRow(ctx, `SELECT state FROM incidents WHERE id = $1`, incidentID).Scan(&state); err != nil {
		t.Fatalf("read state: %v", err)
	}
	if state != StateReopened {
		t.Errorf("incident state = %q, want %q — the state transition itself must still succeed even once the reopen-reanalysis bound is spent", state, StateReopened)
	}
}

// TestSetStateClosesTheExecutingRace is the regression test for the worse
// half of the bug, and the reason SELECT ... FOR UPDATE is in SetState at
// all. It reproduces the exact interleaving: transaction A commits the
// AwaitingApproval -> Executing transition (what
// internal/execution's recordExecutingTransition does
// immediately before signing a plan and calling the agent), while
// transaction B concurrently tries to re-analyze the same incident.
//
// Before the fix, B's bare UPDATE overwrote the state to Investigating and
// then AwaitingApproval with a fresh plan, and the approve-and-execute path
// would sign and dispatch that second plan against the same workload the
// first plan was mid-flight on. Now B must block on A's row lock, observe
// Executing once A commits, and be refused.
func TestSetStateClosesTheExecutingRace(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, incidentID, _ := testIncident(t, pool, StateAwaitingApproval)
	ctx := context.Background()

	// Transaction A: take the incident to Executing, but do NOT commit yet —
	// this is the window in which the tunnel call would be in flight.
	txA, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin A: %v", err)
	}
	defer txA.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, txA, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("A: set request scope: %v", err)
	}
	if err := SetState(ctx, txA, incidentID, StateExecuting); err != nil {
		t.Fatalf("A: AwaitingApproval -> Executing must be legal: %v", err)
	}

	// Transaction B: a concurrent re-analyze of the same incident.
	type result struct{ err error }
	bDone := make(chan result, 1)
	go func() {
		txB, err := pool.Begin(ctx)
		if err != nil {
			bDone <- result{err: err}
			return
		}
		defer txB.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, txB, tenantID, []string{clusterID}); err != nil {
			bDone <- result{err: err}
			return
		}
		bDone <- result{err: MarkInvestigating(ctx, txB, tenantID, clusterID, incidentID)}
	}()

	// B must not be able to decide anything while A holds the row lock. If
	// it returns here, the lock isn't being taken and the check is racy by
	// construction — which is exactly the pre-fix behaviour.
	select {
	case r := <-bDone:
		t.Fatalf("the concurrent re-analyze returned (err=%v) while the Executing transition was still uncommitted — SetState is not taking a row lock, so its transition check is not atomic", r.err)
	case <-time.After(300 * time.Millisecond):
	}

	if err := txA.Commit(ctx); err != nil {
		t.Fatalf("A: commit: %v", err)
	}

	select {
	case r := <-bDone:
		if r.err == nil {
			t.Fatal("the concurrent re-analyze succeeded against an Executing incident — two plans can now be approved and dispatched against the same workload")
		}
		if !errors.Is(r.err, ErrIllegalTransition) {
			t.Errorf("concurrent re-analyze error = %v, want one wrapping ErrIllegalTransition", r.err)
		}
		var illegal *IllegalTransitionError
		if errors.As(r.err, &illegal) && illegal.From != StateExecuting {
			t.Errorf("concurrent re-analyze was refused from state %q, want %q — it should have seen the state A committed", illegal.From, StateExecuting)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the concurrent re-analyze never returned after the Executing transition committed — the row lock is not being released")
	}

	if got := currentState(t, pool, tenantID, clusterID, incidentID); got != StateExecuting {
		t.Errorf("incident state = %q, want %q — the refused re-analyze must have changed nothing", got, StateExecuting)
	}
}

// TestSetStateOnAMissingIncidentIsAnError covers what the old bare UPDATE
// silently swallowed: an UPDATE matching zero rows returned nil, so a
// transition against a nonexistent (or RLS-invisible) incident looked like
// success. Now that the current state has to be read anyway, saying so is
// free — and a caller that gets ErrIncidentNotFound has learned something
// real rather than nothing.
func TestSetStateOnAMissingIncidentIsAnError(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	err = SetState(ctx, tx, domain.NewID(domain.PrefixIncident), StateInvestigating)
	if !errors.Is(err, ErrIncidentNotFound) {
		t.Errorf("SetState on a nonexistent incident: error = %v, want one wrapping ErrIncidentNotFound", err)
	}
}

// --- plan params: marshal/unmarshal round-trip (no database needed) ----------

// TestPlanParamsRoundTrip covers marshalPlanParams/UnmarshalPlanParams for every
// action type in remediation's closed set. This is the pair that decides whether
// a proposed plan can be persisted at all and read back as the same typed value:
// a missing case marshals to `{}` (losing the params silently, since that branch
// is deliberately lenient — see marshalPlanParams' doc comment) or fails
// UnmarshalPlanParams outright at approval time, which is the last moment anyone
// would want to discover it.
//
// "Every action type" is now ENFORCED rather than claimed. This comment already
// said it before the table below actually did: six of the eleven types in the
// closed set (PatchField, StructuredPatch, AnnotateResource, LabelResource,
// DeleteResource, CreateResource) had no case at all, so the test's own headline
// property was untrue and adding a twelfth type would not have failed anything.
// The exhaustiveness loop at the end drives the requirement from
// remediation.AllActionTypes() — the closed set itself — matching the pattern
// this codebase already uses for exactly this failure shape everywhere else it
// has bitten: TestEveryActionTypeDeclaresItsFieldPaths (internal/remediation),
// TestActionTypeCheckConstraintAcceptsEveryActionType (this package), and
// TestEveryPermittedActionTypeIsReachable (internal/llm, added after three
// features shipped unreachable for want of one switch case).
//
// RevertContainerImage carries the extra property worth pinning here: its
// STORED params are a container name only. The image an execution uses is
// resolved from live cluster state at approval time and lives in the signed
// envelope, never in this row — so a round trip that grew an image field would
// mean a persisted, possibly stale image had become executable.
func TestPlanParamsRoundTrip(t *testing.T) {
	plans := []struct {
		name       string
		plan       remediation.RemediationPlan
		wantParams string // the exact stored JSON
	}{
		{
			"ScaleDeployment",
			remediation.RemediationPlan{ActionType: remediation.ActionScaleDeployment, Params: remediation.ScaleDeploymentParams{Replicas: 4}},
			`{"replicas":4}`,
		},
		{
			"RestartPod",
			remediation.RemediationPlan{ActionType: remediation.ActionRestartPod, Params: remediation.RestartPodParams{}},
			`{}`,
		},
		{
			"PatchResourceLimits",
			remediation.RemediationPlan{ActionType: remediation.ActionPatchResourceLimits, Params: remediation.PatchResourceLimitsParams{Container: "api", MemoryLimit: "256Mi"}},
			`{"container":"api","memoryLimit":"256Mi"}`,
		},
		{
			"RevertContainerImage",
			remediation.RemediationPlan{ActionType: remediation.ActionRevertContainerImage, Params: remediation.RevertContainerImageParams{Container: "api"}},
			`{"container":"api"}`,
		},
		{
			"OpenPR",
			remediation.RemediationPlan{ActionType: remediation.ActionOpenPR, Params: remediation.OpenPRParams{
				Repository: "org/repo",
				Files: []remediation.ProposedFile{
					{Path: "charts/web/values.yaml", Content: "replicaCount: 2\n"},
					{Path: "charts/web/templates/deployment.yaml", Content: "replicas: {{ .Values.replicaCount }}\n"},
				},
			}},
			`{"repository":"org/repo","files":[{"path":"charts/web/values.yaml","content":"replicaCount: 2\n"},{"path":"charts/web/templates/deployment.yaml","content":"replicas: {{ .Values.replicaCount }}\n"}]}`,
		},
		{
			// BACKLOG.md "still open" #2: a delete round-trips through the
			// exact same marshal/unmarshal path, with "delete":true instead
			// of a "content" key.
			"OpenPR with a delete",
			remediation.RemediationPlan{ActionType: remediation.ActionOpenPR, Params: remediation.OpenPRParams{
				Repository: "org/repo",
				Files: []remediation.ProposedFile{
					{Path: "envs/prod/hpa-a.yaml", Delete: true},
				},
			}},
			`{"repository":"org/repo","files":[{"path":"envs/prod/hpa-a.yaml","content":"","delete":true}]}`,
		},
		{
			"PatchField",
			remediation.RemediationPlan{ActionType: remediation.ActionPatchField, Params: remediation.PatchFieldParams{
				FieldPath: "spec.replicas", NewValue: "3", ExpectCurrent: "1",
			}},
			`{"fieldPath":"spec.replicas","newValue":"3","expectCurrent":"1"}`,
		},
		{
			// Built but deliberately not model-reachable (PROJECT.md F11).
			// Persistence still has to round-trip it: rows written before it
			// was parked are read back by the same code path.
			"StructuredPatch",
			remediation.RemediationPlan{ActionType: remediation.ActionStructuredPatch, Params: remediation.StructuredPatchParams{}},
			`{"ops":null}`,
		},
		{
			"AnnotateResource",
			remediation.RemediationPlan{ActionType: remediation.ActionAnnotateResource, Params: remediation.AnnotateResourceParams{
				Key: "argus.io/incident-id", Value: "inc_01hzz",
			}},
			`{"key":"argus.io/incident-id","value":"inc_01hzz"}`,
		},
		{
			// Shares marshalPlanParams' Annotate/Label case but has its own
			// UnmarshalPlanParams case, so the two halves are only proven to
			// agree by exercising both types, not one standing in for the other.
			"LabelResource",
			remediation.RemediationPlan{ActionType: remediation.ActionLabelResource, Params: remediation.LabelResourceParams{
				Key: "argus.io/remediated", Value: "true",
			}},
			`{"key":"argus.io/remediated","value":"true"}`,
		},
		{
			// Empty params, like RestartPod: the target columns identify the
			// object entirely. `{}` here is the correct stored shape, not the
			// silent-loss `{}` a missing marshal case would produce — which is
			// why the unmarshal half of the round trip is the real assertion.
			"DeleteResource",
			remediation.RemediationPlan{ActionType: remediation.ActionDeleteResource, Params: remediation.DeleteResourceParams{}},
			`{}`,
		},
		{
			"CordonNode",
			remediation.RemediationPlan{ActionType: remediation.ActionCordonNode, Params: remediation.CordonNodeParams{Unschedulable: true}},
			`{"unschedulable":true}`,
		},
		{
			"DrainNode",
			remediation.RemediationPlan{ActionType: remediation.ActionDrainNode, Params: remediation.DrainNodeParams{DeleteEmptyDirData: true}},
			`{"deleteEmptyDirData":true}`,
		},
		{
			"CreateResource",
			remediation.RemediationPlan{ActionType: remediation.ActionCreateResource, Params: remediation.CreateResourceParams{
				Data: map[string]string{"config.yaml": "level: debug\n"},
			}},
			`{"data":{"config.yaml":"level: debug\n"}}`,
		},
	}

	for _, c := range plans {
		t.Run(c.name, func(t *testing.T) {
			marshaled, err := marshalPlanParams(c.plan)
			if err != nil {
				t.Fatalf("marshalPlanParams: %v", err)
			}
			if string(marshaled) != c.wantParams {
				t.Errorf("marshalPlanParams = %s, want %s", marshaled, c.wantParams)
			}
			back, err := UnmarshalPlanParams(string(c.plan.ActionType), marshaled)
			if err != nil {
				t.Fatalf("UnmarshalPlanParams: %v", err)
			}
			// reflect.DeepEqual rather than !=: OpenPRParams holds a slice, so
			// == on the interface would panic at runtime.
			if !reflect.DeepEqual(back, c.plan.Params) {
				t.Errorf("round trip produced %#v, want %#v", back, c.plan.Params)
			}
		})
	}

	// The exhaustiveness half: the table above must name every action type in
	// the closed set. Derived from remediation.AllActionTypes() rather than a
	// second hand-written list, so a new action type fails HERE — at
	// `go test` — instead of at the first approval of a plan whose params
	// marshalled to a silent `{}`.
	covered := map[remediation.ActionType]bool{}
	for _, c := range plans {
		covered[c.plan.ActionType] = true
	}
	all := remediation.AllActionTypes()
	if len(all) == 0 {
		t.Fatal("remediation.AllActionTypes() is empty, so the exhaustiveness check would pass vacuously")
	}
	for _, at := range all {
		if !covered[at] {
			t.Errorf("action type %q is in remediation.AllActionTypes() but has no round-trip case here — "+
				"marshalPlanParams' default branch marshals an unhandled Params type to `{}` SILENTLY, so a missing case "+
				"is not discovered until someone approves a plan whose parameters have already been lost", at)
		}
	}

	if _, err := UnmarshalPlanParams("DeleteNamespace", []byte(`{}`)); err == nil {
		t.Error("UnmarshalPlanParams accepted an unrecognized action type, want an error")
	}
}

// TestReconstructPlanDropsAPersistedImage: a remediation_recommendations row
// whose params somehow carry an image — a hand-edited row, a restore from a
// differently-shaped backup, a future bug — must not be able to make that image
// executable. The typed params struct has no field for it, so the value is
// dropped on decode; this asserts that rather than assuming it.
func TestReconstructPlanDropsAPersistedImage(t *testing.T) {
	plan, err := ReconstructPlan("inc_1", "an_1", string(remediation.ActionRevertContainerImage),
		"apps/v1/Deployment", "payments", "checkout-api",
		[]byte(`{"container":"api","image":"evil.example.com/backdoor:latest"}`), true, "medium")
	if err != nil {
		t.Fatalf("ReconstructPlan: %v", err)
	}
	params, ok := plan.Params.(remediation.RevertContainerImageParams)
	if !ok {
		t.Fatalf("Params is %T, want RevertContainerImageParams", plan.Params)
	}
	if params.Container != "api" {
		t.Errorf("Container = %q, want %q", params.Container, "api")
	}
	if params != (remediation.RevertContainerImageParams{Container: "api"}) {
		t.Errorf("params = %#v, want only the container to have survived", params)
	}
}

// TestPlanTargetMatchesObjectKey covers lld/01-threat-model.md T3's stated
// observable — "a plan whose target doesn't correlate with the detector that
// opened the incident" — as a pure, DB-free comparison so the parsing logic is
// tested without needing a transaction.
func TestPlanTargetMatchesObjectKey(t *testing.T) {
	t.Run("same object matches", func(t *testing.T) {
		gvk, ns, name, matches, ok := planTargetMatchesObjectKey("v1/Pod|apps|web-1", "apps", "web-1")
		if !ok || !matches {
			t.Fatalf("got ok=%v matches=%v, want true/true", ok, matches)
		}
		if gvk != "v1/Pod" || ns != "apps" || name != "web-1" {
			t.Errorf("parsed (%q, %q, %q), want (v1/Pod, apps, web-1)", gvk, ns, name)
		}
	})

	t.Run("legitimate cross-object case does not match — this is expected, not blocked", func(t *testing.T) {
		// A Service incident whose real fix targets its backing Deployment: a
		// completely different name, and a completely legitimate plan. This
		// function must report matches=false (so the caller logs it for
		// visibility) but the CALLER must never treat that as a reason to
		// block — that decision lives one level up.
		_, _, _, matches, ok := planTargetMatchesObjectKey("v1/Service|apps|frontend", "apps", "frontend-backend-deploy")
		if !ok {
			t.Fatal("a well-formed object key must parse")
		}
		if matches {
			t.Error("a different object name must not report as matching")
		}
	})

	t.Run("unparseable object key is not a mismatch — it is undetermined", func(t *testing.T) {
		for _, bad := range []string{"", "not-a-key", "v1/Pod|apps"} {
			if _, _, _, _, ok := planTargetMatchesObjectKey(bad, "apps", "web-1"); ok {
				t.Errorf("planTargetMatchesObjectKey(%q, ...) reported ok=true for an unparseable key", bad)
			}
		}
	})

	t.Run("namespace differs, name same — must not match", func(t *testing.T) {
		_, _, _, matches, ok := planTargetMatchesObjectKey("v1/Pod|apps|web-1", "kube-system", "web-1")
		if !ok || matches {
			t.Error("a namespace mismatch must be reported, not silently ignored")
		}
	})
}

// TestUnmarshalPlanParams_RefusesTheRetiredOpenPRShape is the loud-failure
// discipline the whole-file rewrite had to preserve.
//
// Until 2026-08-28 an OpenPR plan's stored params were filePath/fieldPath/
// newValue/expectedCurrentValue: one scalar in one file. Those keys no longer
// decode into anything. Ignoring them would turn "approve this plan" into
// "open a pull request that changes nothing" — a stored plan silently rewritten
// into a different, empty meaning. So a row carrying any of them fails here, at
// the one place a stored plan is turned back into something actionable, and the
// approver is told to re-analyse.
//
// The old OpenPRParams.Validate applied exactly this discipline to a supplied
// filePath ("filePath must not be set: ... a supplied path would override
// [discovery] with a guess"). This is that rule, moved to where a persisted row
// is read.
func TestUnmarshalPlanParams_RefusesTheRetiredOpenPRShape(t *testing.T) {
	for _, stored := range []string{
		`{"repository":"org/repo","filePath":"a.yaml","fieldPath":"/spec/replicas","newValue":"3"}`,
		`{"repository":"org/repo","fieldPath":"/spec/replicas","newValue":"3"}`,
		`{"repository":"org/repo","newValue":"3"}`,
		// Present but empty still counts: the row was still written by a build
		// that believed a repository change was one field.
		`{"repository":"org/repo","fieldPath":"","newValue":""}`,
		`{"repository":"org/repo","expectedCurrentValue":"9999"}`,
	} {
		_, err := UnmarshalPlanParams(string(remediation.ActionOpenPR), []byte(stored))
		if err == nil {
			t.Errorf("UnmarshalPlanParams(%s) = nil error, want a loud refusal of the retired single-field shape", stored)
			continue
		}
		if !strings.Contains(err.Error(), "retired") {
			t.Errorf("UnmarshalPlanParams(%s) error = %v, want it to say the shape is retired", stored, err)
		}
	}

	// And the ordinary modern shape is not caught by it.
	if _, err := UnmarshalPlanParams(string(remediation.ActionOpenPR),
		[]byte(`{"repository":"org/repo","files":[{"path":"a.yaml","content":"a: b\n"}]}`)); err != nil {
		t.Errorf("UnmarshalPlanParams on a whole-file plan = %v, want nil", err)
	}
}
