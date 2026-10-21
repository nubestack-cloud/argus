package autoanalyze

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
	"argus/internal/llm"
	"argus/internal/orchestrator"
)

// The DB-backed halves of Findings 3 and 5. Both are properties of live SQL
// under FORCE ROW LEVEL SECURITY, not of Go: the candidate query's own
// exclusions, and what recordAnalysisFailure actually leaves behind in the
// row and on the timeline.
//
// Uses autoanalyze_db_test.go's testPool harness.

// sweeperFixture inserts a throwaway tenant + cluster and returns a
// *dbtest.Fixture tracking the deterministic part of what it created
// (organisations/clusters), WITHOUT calling Cleanup itself: every test built
// on this fixture calls addIncident its own, test-specific number of times
// (some of those calls also insert an analyses+remediation_recommendations
// pair), and some drive failAnalysis/setState, which may add
// timeline_events/incident_notifications rows — only the calling test knows
// its own final counts, so only it may call fixture.Cleanup (via
// cleanupSweeperFixture below).
//
// A dedicated ORGANISATION, for the same reason setupStarvationFixture uses
// one: both queries under test here are per-tenant sweeps over the whole
// incidents table with no incident-id filter, so running against the shared dev
// tenant would mean asserting against whatever that deployment has accumulated.
func sweeperFixture(t *testing.T, pool *pgxpool.Pool) (fixture *dbtest.Fixture, tenantID, clusterID string) {
	t.Helper()
	ctx := context.Background()
	tenantID = domain.NewID(domain.PrefixOrganisation)
	clusterID = domain.NewID(domain.PrefixCluster)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin fixture: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	fixture = dbtest.New(t)
	if _, err := tx.Exec(ctx,
		`INSERT INTO organisations (id, name) VALUES ($1, $2)`, tenantID, "sweeper-test-"+tenantID); err != nil {
		t.Fatalf("insert organisation: %v", err)
	}
	fixture.Created("organisations", 1)
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint, last_heartbeat_at)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4, now())`,
		clusterID, tenantID, "sweeper-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	fixture.Created("clusters", 1)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit fixture: %v", err)
	}

	return fixture, tenantID, clusterID
}

// cleanupSweeperFixture runs fixture.Cleanup with the full delete list every
// test built on sweeperFixture needs — the caller must have already tracked
// its own incidents/analyses/remediation_recommendations/timeline_events/
// incident_notifications counts via fixture.Created before calling this.
func cleanupSweeperFixture(fixture *dbtest.Fixture, pool *pgxpool.Pool, tenantID, clusterID string) {
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "timeline_events", SQL: `DELETE FROM timeline_events WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incident_notifications", SQL: `DELETE FROM incident_notifications WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "remediation_recommendations", SQL: `DELETE FROM remediation_recommendations WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "analyses", SQL: `DELETE FROM analyses WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
		// organisations has no RLS (see internal/data/org.go's
		// SingleOrganisationID, which reads it BEFORE any scope is set), so
		// this delete runs fine under the same cluster-scoped transaction —
		// same precedent as setupStarvationFixture/setupSeverityBacklogFixture
		// in autoanalyze_db_test.go, just folded into the same dbtest.Fixture
		// transaction instead of a second one, since nothing here needs it
		// deleted in a SEPARATE transaction (no other table depends on this
		// tenant existing after the fixture's own rows are gone).
		{Table: "organisations", SQL: `DELETE FROM organisations WHERE id = $1`, Args: []any{tenantID}},
	})
}

type incidentSpec struct {
	state            string
	objectKey        string
	workloadKey      string
	lastSeenAgo      time.Duration
	prNumber         *int
	prMerged         bool
	prClosedUnmerged bool
	// recommendationTarget, when set, adds a live (non-superseded)
	// recommendation whose target is this `gvk|namespace|name`.
	recommendationTarget string
}

func addIncident(t *testing.T, pool *pgxpool.Pool, fixture *dbtest.Fixture, tenantID, clusterID string, spec incidentSpec) string {
	t.Helper()
	ctx := context.Background()
	incidentID := domain.NewID(domain.PrefixIncident)
	seen := time.Now().Add(-spec.lastSeenAgo)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin add incident: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	var merged, closed *time.Time
	if spec.prMerged {
		m := seen
		merged = &m
	}
	if spec.prClosedUnmerged {
		c := seen
		closed = &c
	}
	var workloadKey *string
	if spec.workloadKey != "" {
		workloadKey = &spec.workloadKey
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen,
		                        occurrence_count, object_key, workload_key, pr_number, pr_merged_at, pr_closed_unmerged_at)
		 VALUES ($1, $2, $3, $4, 'high', $5, $6, $6, 1, $7, $8, $9, $10, $11)`,
		incidentID, tenantID, clusterID, "fp-"+incidentID, spec.state, seen,
		spec.objectKey, workloadKey, spec.prNumber, merged, closed); err != nil {
		t.Fatalf("insert incident (%s): %v", spec.state, err)
	}
	fixture.Created("incidents", 1)
	if spec.recommendationTarget != "" {
		analysisID := domain.NewID(domain.PrefixAnalysis)
		recID := domain.NewID(domain.PrefixPlan)
		if _, err := tx.Exec(ctx,
			`INSERT INTO analyses (id, incident_id, tenant_id, cluster_id, model, prompt_version, causal_chain,
			                       iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd)
			 VALUES ($1, $2, $3, $4, 'test-model', 'v1', '[]', 1, 1, 0, 0, 0, 0)`,
			analysisID, incidentID, tenantID, clusterID); err != nil {
			t.Fatalf("insert analysis: %v", err)
		}
		fixture.Created("analyses", 1)
		gvk, ns, name := splitKey(t, spec.recommendationTarget)
		if _, err := tx.Exec(ctx,
			`INSERT INTO remediation_recommendations
			   (id, incident_id, tenant_id, cluster_id, analysis_id, action_type, target_gvk, target_namespace,
			    target_name, params, reversible, risk_level, gate_outcome, gate_reason)
			 VALUES ($1, $2, $3, $4, $5, 'ScaleDeployment', $6, $7, $8, '{"replicas":3}', true, 'low', 'NeedsApproval', 'fixture')`,
			recID, incidentID, tenantID, clusterID, analysisID, gvk, ns, name); err != nil {
			t.Fatalf("insert recommendation: %v", err)
		}
		fixture.Created("remediation_recommendations", 1)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit add incident: %v", err)
	}
	return incidentID
}

func splitKey(t *testing.T, key string) (gvk, namespace, name string) {
	t.Helper()
	var parts []string
	start := 0
	for i := 0; i < len(key); i++ {
		if key[i] == '|' {
			parts = append(parts, key[start:i])
			start = i + 1
		}
	}
	parts = append(parts, key[start:])
	if len(parts) != 3 {
		t.Fatalf("malformed test key %q", key)
	}
	return parts[0], parts[1], parts[2]
}

// pollerFor builds a Poller wired to nothing but the database. Enough for
// collectStaleCandidates and recordAnalysisFailure, neither of which touches
// the gateway or the LLM.
func pollerFor(pool *pgxpool.Pool) *Poller { return &Poller{db: &data.DB{Pool: pool}} }

// ---------------------------------------------------------------------------
// Finding 5: the stale-object sweeper
// ---------------------------------------------------------------------------

// TestStaleSweepSkipsIncidentsWithAnActionInFlight is the regression test for
// the orphaned pull request.
//
// Before the fix, staleCandidateQuery excluded only Resolved, Dismissed,
// Executing and Validating — so an incident in AwaitingMerge, with a real pull
// request open against a real repository, was an ordinary candidate. Its
// original object is a Pod, and the rollout the pull request is waiting for is
// exactly what replaces that pod, so the check that decided the incident was
// stale was being satisfied by the very thing it was waiting on. The incident
// was resolved and the pull request left open, with nothing left to explain why
// it existed.
func TestStaleSweepSkipsIncidentsWithAnActionInFlight(t *testing.T) {
	pool := testPool(t)
	fixture, tenantID, clusterID := sweeperFixture(t, pool)
	quiet := staleObjectGracePeriod + time.Hour
	prNumber := 42

	awaitingMerge := addIncident(t, pool, fixture, tenantID, clusterID, incidentSpec{
		state: "AwaitingMerge", objectKey: "v1/Pod|prod|api-1", lastSeenAgo: quiet, prNumber: &prNumber,
	})
	awaitingApproval := addIncident(t, pool, fixture, tenantID, clusterID, incidentSpec{
		state: "AwaitingApproval", objectKey: "v1/Pod|prod|api-2", lastSeenAgo: quiet,
	})
	investigating := addIncident(t, pool, fixture, tenantID, clusterID, incidentSpec{
		state: "Investigating", objectKey: "v1/Pod|prod|api-3", lastSeenAgo: quiet,
	})
	// An incident in an ordinary state whose pull request happens to still be
	// open — the structural half of the rule, independent of the state name.
	failedWithOpenPR := addIncident(t, pool, fixture, tenantID, clusterID, incidentSpec{
		state: "Failed", objectKey: "v1/Pod|prod|api-4", lastSeenAgo: quiet, prNumber: &prNumber,
	})
	// Genuine candidates, which must still be selected: the fix must narrow
	// what this sweeper touches, not disable it.
	detected := addIncident(t, pool, fixture, tenantID, clusterID, incidentSpec{
		state: "Detected", objectKey: "v1/Pod|prod|api-5", lastSeenAgo: quiet,
	})
	failedMergedPR := addIncident(t, pool, fixture, tenantID, clusterID, incidentSpec{
		state: "Failed", objectKey: "v1/Pod|prod|api-6", lastSeenAgo: quiet, prNumber: &prNumber, prMerged: true,
	})

	selected := map[string]bool{}
	for _, c := range collectStale(t, pool, tenantID, clusterID) {
		selected[c.ID] = true
	}

	for _, tc := range []struct{ id, why string }{
		{awaitingMerge, "a pull request is open and nothing else closes it, so resolving here orphans a live change proposal"},
		{awaitingApproval, "a signed plan is queued for a decision the unattended executor keys on"},
		{investigating, "an analysis is in flight and another writer owns the state"},
		{failedWithOpenPR, "the pull request is open whatever state the incident is in"},
	} {
		if selected[tc.id] {
			t.Errorf("incident %s was selected as a stale-close candidate — %s", tc.id, tc.why)
		}
	}
	for _, tc := range []struct{ id, why string }{
		{detected, "an ordinary quiet incident is what this sweeper exists for"},
		{failedMergedPR, "a merged pull request is not in flight; there is nothing left to orphan"},
	} {
		if !selected[tc.id] {
			t.Errorf("incident %s was NOT selected — %s; the fix must narrow this sweeper, not disable it", tc.id, tc.why)
		}
	}

	// Six addIncident calls already tracked "incidents" incrementally, one
	// per call. None set recommendationTarget, so addIncident never tracked
	// analyses/remediation_recommendations at all — track them at 0
	// explicitly so Cleanup's table/Created pairing check is satisfied.
	// collectStale only reads; nothing here calls failAnalysis/setState, so
	// no timeline_events/incident_notifications either.
	fixture.Created("analyses", 0)
	fixture.Created("remediation_recommendations", 0)
	fixture.Created("timeline_events", 0)
	fixture.Created("incident_notifications", 0)
	cleanupSweeperFixture(fixture, pool, tenantID, clusterID)
}

// TestStaleSweepAsksAboutTheWorkloadNotThePod is the other half of Finding 5.
//
// incidents.object_key is the object the FINDING named, which for the great
// majority of incidents is a Pod — and pods are replaced by every rollout,
// drain, eviction and restart. So "the original object is gone" mostly measured
// Kubernetes rather than the fault. The sweeper now asks about the remediation
// target or the workload, either of which survives a pod being replaced.
func TestStaleSweepAsksAboutTheWorkloadNotThePod(t *testing.T) {
	pool := testPool(t)
	fixture, tenantID, clusterID := sweeperFixture(t, pool)
	quiet := staleObjectGracePeriod + time.Hour

	withWorkload := addIncident(t, pool, fixture, tenantID, clusterID, incidentSpec{
		state: "Detected", objectKey: "v1/Pod|prod|api-6679f7f545-w2xmp",
		workloadKey: "apps/v1/Deployment|prod|api", lastSeenAgo: quiet,
	})
	withPlan := addIncident(t, pool, fixture, tenantID, clusterID, incidentSpec{
		state: "Detected", objectKey: "v1/Pod|prod|web-1",
		workloadKey: "apps/v1/Deployment|prod|web", lastSeenAgo: quiet,
		recommendationTarget: "v1/ConfigMap|prod|web-config",
	})
	bare := addIncident(t, pool, fixture, tenantID, clusterID, incidentSpec{
		state: "Detected", objectKey: "v1/Pod|prod|standalone", lastSeenAgo: quiet,
	})

	byID := map[string]staleCandidate{}
	for _, c := range collectStale(t, pool, tenantID, clusterID) {
		byID[c.ID] = c
	}

	if got, _ := byID[withWorkload].existenceTarget(); got != "apps/v1/Deployment|prod|api" {
		t.Errorf("existenceTarget() = %q, want the workload — asking about the pod name means every rollout looks like the incident becoming moot", got)
	}
	if got, _ := byID[withPlan].existenceTarget(); got != "v1/ConfigMap|prod|web-config" {
		t.Errorf("existenceTarget() = %q, want the live recommendation's target — that is the object a fix would act on", got)
	}
	if got, _ := byID[bare].existenceTarget(); got != "v1/Pod|prod|standalone" {
		t.Errorf("existenceTarget() = %q, want the object itself — an unowned object with no plan has nothing else to ask about", got)
	}

	// Three addIncident calls already tracked "incidents", and withPlan's
	// recommendationTarget already tracked the one analyses+
	// remediation_recommendations pair — all via addIncident itself, nothing
	// left to add here. collectStale only reads; nothing here calls
	// failAnalysis/setState.
	fixture.Created("timeline_events", 0)
	fixture.Created("incident_notifications", 0)
	cleanupSweeperFixture(fixture, pool, tenantID, clusterID)
}

func collectStale(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID string) []staleCandidate {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	rows, err := tx.Query(ctx, staleCandidateQuery, staleObjectGracePeriod.Seconds(), maxStaleChecksPerSweep)
	if err != nil {
		t.Fatalf("stale candidate query: %v", err)
	}
	defer rows.Close()
	var out []staleCandidate
	for rows.Next() {
		var c staleCandidate
		if err := rows.Scan(&c.ID, &c.ClusterID, &c.ObjectKey, &c.State, &c.WorkloadKey, &c.TargetKey, &c.LastSeen); err != nil {
			t.Fatalf("scan stale candidate: %v", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate stale candidates: %v", err)
	}
	return out
}

// ---------------------------------------------------------------------------
// Finding 3: a failed automatic analysis
// ---------------------------------------------------------------------------

type incidentAnalysisRow struct {
	State       string
	Attempts    int
	LastError   *string
	RetryAfter  *time.Time
	AttemptedAt *time.Time
}

func readAnalysisRow(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID string) incidentAnalysisRow {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin read: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	var r incidentAnalysisRow
	if err := tx.QueryRow(ctx,
		`SELECT state, auto_analysis_attempts, auto_analysis_last_error, auto_analysis_retry_after, auto_analysis_attempted_at
		   FROM incidents WHERE id = $1`, incidentID).
		Scan(&r.State, &r.Attempts, &r.LastError, &r.RetryAfter, &r.AttemptedAt); err != nil {
		t.Fatalf("read incident: %v", err)
	}
	return r
}

func failAnalysis(t *testing.T, pool *pgxpool.Pool, p *Poller, tenantID, clusterID, incidentID string, attempts int, cause error) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	p.recordAnalysisFailure(ctx, tx, tenantID,
		incidentCandidate{ID: incidentID, ClusterID: clusterID, AutoAnalysisAttempts: attempts}, cause)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// TestTransientAnalysisFailureIsRetriedThenGivenUpOnHonestly walks the whole
// bounded-retry policy against real Postgres.
//
// The old behaviour, for comparison: the incident stayed in Investigating,
// auto_analysis_attempted_at was stamped, and both the candidate query's state
// filter AND its attempted_at filter then excluded it — two independent reasons
// it could never be looked at again, for a failure that had not concluded
// anything.
func TestTransientAnalysisFailureIsRetriedThenGivenUpOnHonestly(t *testing.T) {
	pool := testPool(t)
	fixture, tenantID, clusterID := sweeperFixture(t, pool)
	p := pollerFor(pool)
	incidentID := addIncident(t, pool, fixture, tenantID, clusterID, incidentSpec{
		state: "Investigating", objectKey: "v1/Pod|prod|api-1",
	})

	failAnalysis(t, pool, p, tenantID, clusterID, incidentID, 0, errors.New("provider returned 503"))

	got := readAnalysisRow(t, pool, tenantID, clusterID, incidentID)
	if got.State == "Investigating" {
		t.Fatal("the incident was left in Investigating after a failed investigation — it reads as 'an investigation is running now' forever, and candidateQuery excludes that state so nothing would ever retry it")
	}
	if got.State != orchestrator.StateDetected {
		t.Fatalf("state = %q, want %q", got.State, orchestrator.StateDetected)
	}
	if got.AttemptedAt != nil {
		t.Error("auto_analysis_attempted_at was stamped for a failure that is still going to be retried — that column means 'the automatic path is done with this incident'")
	}
	if got.Attempts != 1 {
		t.Errorf("auto_analysis_attempts = %d, want 1", got.Attempts)
	}
	if got.RetryAfter == nil {
		t.Fatal("no backoff was recorded, so the incident is retried on the very next tick")
	}
	if !got.RetryAfter.After(time.Now()) {
		t.Errorf("auto_analysis_retry_after = %s, already in the past", got.RetryAfter)
	}
	if got.LastError == nil || *got.LastError == "" {
		t.Error("the failure reason was not persisted — it survives only in a hub log, which is where it was already lost")
	}

	// The reason is on the incident's own history too, so an
	// InvestigationStarted with no AnalysisCompleted after it is interpretable.
	assertTimelineSays(t, pool, tenantID, clusterID, incidentID, "will be retried")

	// Walk it to the bound. The last attempt is the one that concludes.
	for attempts := 1; attempts < maxAutoAnalysisAttempts; attempts++ {
		setState(t, pool, tenantID, clusterID, incidentID, "Investigating")
		failAnalysis(t, pool, p, tenantID, clusterID, incidentID, attempts, errors.New("provider returned 503"))
	}
	got = readAnalysisRow(t, pool, tenantID, clusterID, incidentID)
	if got.Attempts != maxAutoAnalysisAttempts {
		t.Errorf("auto_analysis_attempts = %d, want %d", got.Attempts, maxAutoAnalysisAttempts)
	}
	if got.AttemptedAt == nil {
		t.Error("the bound was reached and the incident was not marked attempted — it would be retried forever")
	}
	if got.RetryAfter != nil {
		t.Error("a backoff is still set after the automatic path gave up")
	}
	if got.State != orchestrator.StateDetected {
		t.Errorf("state = %q, want %q — an incident nobody investigated is Detected, whatever the automatic path decided", got.State, orchestrator.StateDetected)
	}
	assertTimelineSays(t, pool, tenantID, clusterID, incidentID, "given up")

	// One addIncident call (no recommendationTarget) already tracked
	// "incidents"; analyses/remediation_recommendations were never touched,
	// so track them at 0 to satisfy Cleanup's pairing check. failAnalysis is
	// called once up front (attempts=0) plus once per loop iteration
	// (attempts=1,2 — maxAutoAnalysisAttempts=3, so 2 more calls), 3 calls
	// total; every one transitions Investigating -> Detected legally, so
	// recordAnalysisFailure writes exactly 1 timeline_events row per call.
	// setState is this package's own raw UPDATE helper, not
	// orchestrator.SetState, so it never writes incident_notifications.
	fixture.Created("analyses", 0)
	fixture.Created("remediation_recommendations", 0)
	fixture.Created("timeline_events", 3)
	fixture.Created("incident_notifications", 0)
	cleanupSweeperFixture(fixture, pool, tenantID, clusterID)
}

// TestConfigurationFailureDoesNotSpendTheIncidentsBudget: "no usable AI
// provider" is a fact about the hub. Charging it to whichever incident happened
// to be first in the queue would consume the whole backlog one incident at a
// time, and configuring a provider afterwards would fix nothing.
func TestConfigurationFailureDoesNotSpendTheIncidentsBudget(t *testing.T) {
	pool := testPool(t)
	fixture, tenantID, clusterID := sweeperFixture(t, pool)
	p := pollerFor(pool)
	incidentID := addIncident(t, pool, fixture, tenantID, clusterID, incidentSpec{
		state: "Investigating", objectKey: "v1/Pod|prod|api-1",
	})

	cause := fmt.Errorf("investigate: %w", llm.ErrNotConfigured)
	failAnalysis(t, pool, p, tenantID, clusterID, incidentID, 0, cause)

	got := readAnalysisRow(t, pool, tenantID, clusterID, incidentID)
	if got.State != orchestrator.StateDetected {
		t.Errorf("state = %q, want %q — it must not look like an investigation is still running", got.State, orchestrator.StateDetected)
	}
	if got.Attempts != 0 {
		t.Errorf("auto_analysis_attempts = %d, want 0 — a hub misconfiguration is not this incident's fault and must not spend its retry budget", got.Attempts)
	}
	if got.AttemptedAt != nil {
		t.Error("the incident was marked as finished with the automatic path because the HUB had no provider — configuring one later would then fix nothing for it")
	}
	if got.RetryAfter != nil {
		t.Error("a per-incident backoff was written for a hub-level problem; the poller backs off instead")
	}
	if got.LastError == nil || *got.LastError == "" {
		t.Error("the reason was not persisted")
	}
	assertTimelineSays(t, pool, tenantID, clusterID, incidentID, "hub configuration problem")

	// And the poller itself stood down, which is what stops the hot loop.
	if !p.providerBackoffActive() {
		t.Error("the poller did not back off, so the next tick attempts (and fails) the next incident, and so on through the backlog")
	}

	// One addIncident call already tracked "incidents"; analyses/
	// remediation_recommendations were never touched, tracked at 0 here. One
	// failAnalysis call — the configuration-cause branch still transitions
	// Investigating -> Detected legally, so recordAnalysisFailure still
	// writes 1 timeline_events row (confirmed above via assertTimelineSays).
	fixture.Created("analyses", 0)
	fixture.Created("remediation_recommendations", 0)
	fixture.Created("timeline_events", 1)
	fixture.Created("incident_notifications", 0)
	cleanupSweeperFixture(fixture, pool, tenantID, clusterID)
}

// TestFailureOnAnIncidentThatMovedIsLeftAlone: a human dismissing an incident
// mid-investigation must win. The failure path must not resurrect it, and must
// not write a backoff onto a closed incident.
func TestFailureOnAnIncidentThatMovedIsLeftAlone(t *testing.T) {
	pool := testPool(t)
	fixture, tenantID, clusterID := sweeperFixture(t, pool)
	p := pollerFor(pool)
	incidentID := addIncident(t, pool, fixture, tenantID, clusterID, incidentSpec{
		state: "Dismissed", objectKey: "v1/Pod|prod|api-1",
	})

	failAnalysis(t, pool, p, tenantID, clusterID, incidentID, 0, errors.New("provider returned 503"))

	got := readAnalysisRow(t, pool, tenantID, clusterID, incidentID)
	if got.State != "Dismissed" {
		t.Errorf("state = %q, want Dismissed — a terminal state must not be walked back by a failed background job", got.State)
	}
	if got.Attempts != 0 || got.RetryAfter != nil {
		t.Error("bookkeeping was written onto an incident that had already been closed")
	}

	// One addIncident call (Dismissed) already tracked "incidents"; analyses/
	// remediation_recommendations were never touched, tracked at 0 here.
	// recordAnalysisFailure's SetState call (Dismissed -> Detected) is an
	// illegal transition, so it returns BEFORE reaching its timeline.Record
	// call (see recordAnalysisFailure's own early-return comment) — 0
	// timeline_events rows, not 1.
	fixture.Created("analyses", 0)
	fixture.Created("remediation_recommendations", 0)
	fixture.Created("timeline_events", 0)
	fixture.Created("incident_notifications", 0)
	cleanupSweeperFixture(fixture, pool, tenantID, clusterID)
}

func setState(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID, state string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE incidents SET state = $2 WHERE id = $1`, incidentID, state); err != nil {
		t.Fatalf("set state: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func assertTimelineSays(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID, want string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	var summary string
	if err := tx.QueryRow(ctx,
		`SELECT payload->>'summary' FROM timeline_events
		  WHERE incident_id = $1 AND event_type = 'AutoAnalysisFailed'
		  ORDER BY occurred_at DESC LIMIT 1`, incidentID).Scan(&summary); err != nil {
		t.Fatalf("read AutoAnalysisFailed timeline event (it must exist — the reason surviving only in a hub log is the defect): %v", err)
	}
	if !strings.Contains(summary, want) {
		t.Errorf("timeline summary %q does not say %q", summary, want)
	}
}
