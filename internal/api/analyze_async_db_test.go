package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/gateway"
	"argus/internal/llm"
	"argus/internal/orchestrator"
	"argus/internal/repotools"
	"argus/internal/scm"
)

// PROJECT.md M1, against a real Postgres: the claim POST
// /incidents/{id}/analyze makes before answering 202, the duplicate
// suppression it carries, the background run surviving its request, and
// a failed run's outcome landing on the incident. Gated on
// ARGUS_TEST_DATABASE_URL and built on analyze_detach_db_test.go's fixture
// (which cleans up everything these write, residue-checked).

func asyncTestServer(pool *pgxpool.Pool, investigator llm.Investigator) *Server {
	return &Server{
		db:          &data.DB{Pool: pool},
		gw:          gateway.NewGateway(nil, nil, nil), // no agent connected: ownership resolves to "unknown", which is all these runs need
		scmStore:    scm.NewStore(nil),
		checkouts:   repotools.NewCheckouts(),
		llmProvider: investigator,
	}
}

type asyncTestRow struct {
	state     string
	startedAt *time.Time
	backend   *string
	model     *string
	errText   *string
}

func asyncTestReadIncident(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID string) asyncTestRow {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin read: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope read: %v", err)
	}
	var row asyncTestRow
	if err := tx.QueryRow(ctx, `SELECT state FROM incidents WHERE id = $1`, incidentID).Scan(&row.state); err != nil {
		t.Fatalf("read incident: %v", err)
	}
	run, err := latestInvestigationRun(ctx, tx, incidentID)
	if err != nil {
		t.Fatalf("read latest run: %v", err)
	}
	if run != nil {
		row.startedAt, row.backend, row.model, row.errText = &run.StartedAt, run.Backend, run.Model, run.Error
	}
	return row
}

func asyncTestExec(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, sql string, args ...any) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	if _, err := tx.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func asyncTestTimelineCount(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID, eventType string) int {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM timeline_events WHERE incident_id = $1 AND event_type = $2`, incidentID, eventType).Scan(&n); err != nil {
		t.Fatalf("count timeline events: %v", err)
	}
	return n
}

func TestClaimAnalysisRun_StampsTheRunAndRefusesADuplicate(t *testing.T) {
	pool := analyzeDetachTestPool(t)
	tenantID, clusterID, incidentID := analyzeDetachTestIncident(t, pool)
	s := asyncTestServer(pool, nil)
	ctx := context.Background()

	claim, err := s.claimAnalysisRun(ctx, tenantID, clusterID, incidentID, llm.RunSource{Backend: "api", Model: "test-model"}, 10*time.Minute)
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if claim.PriorState != orchestrator.StateDetected {
		t.Errorf("PriorState = %q, want Detected", claim.PriorState)
	}
	row := asyncTestReadIncident(t, pool, tenantID, clusterID, incidentID)
	if row.state != orchestrator.StateInvestigating {
		t.Errorf("state after claim = %q, want Investigating — the claim must be durable before the 202 goes out", row.state)
	}
	if row.startedAt == nil || !row.startedAt.Equal(claim.StartedAt) {
		t.Errorf("latest InvestigationStarted = %v, want the claim's %v", row.startedAt, claim.StartedAt)
	}
	if row.backend == nil || *row.backend != "api" || row.model == nil || *row.model != "test-model" {
		t.Errorf("source = %v/%v, want api/test-model", row.backend, row.model)
	}

	_, err = s.claimAnalysisRun(ctx, tenantID, clusterID, incidentID, llm.RunSource{Backend: "api"}, 10*time.Minute)
	var inProgress *analysisInProgressError
	if !errors.As(err, &inProgress) {
		t.Fatalf("second claim while the first is in flight: err = %v, want analysisInProgressError", err)
	}
	if inProgress.StartedAt == nil || !inProgress.StartedAt.Equal(claim.StartedAt) {
		t.Errorf("the refusal should name the running claim's start, got %v", inProgress.StartedAt)
	}
}

// An automatic investigation holds the incident row for its whole run
// without committing its claim; the manual claim must refuse promptly
// rather than queue behind it — queueing is what made the request outlive a
// proxy's idle timeout.
func TestClaimAnalysisRun_RefusesPromptlyWhileTheRowIsHeld(t *testing.T) {
	pool := analyzeDetachTestPool(t)
	tenantID, clusterID, incidentID := analyzeDetachTestIncident(t, pool)
	s := asyncTestServer(pool, nil)
	ctx := context.Background()

	holder, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin holder: %v", err)
	}
	defer holder.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, holder, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope holder: %v", err)
	}
	if _, err := holder.Exec(ctx, `SELECT id FROM incidents WHERE id = $1 FOR UPDATE`, incidentID); err != nil {
		t.Fatalf("lock row: %v", err)
	}

	started := time.Now()
	_, err = s.claimAnalysisRun(ctx, tenantID, clusterID, incidentID, llm.RunSource{}, 10*time.Minute)
	var inProgress *analysisInProgressError
	if !errors.As(err, &inProgress) {
		t.Fatalf("claim against a held row: err = %v, want analysisInProgressError", err)
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Errorf("claim took %s to refuse; it must give up after its short lock timeout", elapsed)
	}
	if err := holder.Rollback(ctx); err != nil {
		t.Fatalf("release holder: %v", err)
	}
	if got := asyncTestReadIncident(t, pool, tenantID, clusterID, incidentID).state; got != orchestrator.StateDetected {
		t.Errorf("a refused claim changed the incident to %q", got)
	}
}

// A hub that dies mid-run leaves the incident Investigating; once the run's
// budget has passed it must be claimable again.
func TestClaimAnalysisRun_ReclaimsAnAbandonedRun(t *testing.T) {
	pool := analyzeDetachTestPool(t)
	tenantID, clusterID, incidentID := analyzeDetachTestIncident(t, pool)
	s := asyncTestServer(pool, nil)
	ctx := context.Background()

	if _, err := s.claimAnalysisRun(ctx, tenantID, clusterID, incidentID, llm.RunSource{}, 10*time.Minute); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	asyncTestExec(t, pool, tenantID, clusterID,
		`UPDATE timeline_events SET occurred_at = now() - interval '1 hour' WHERE incident_id = $1 AND event_type = 'InvestigationStarted'`, incidentID)

	claim, err := s.claimAnalysisRun(ctx, tenantID, clusterID, incidentID, llm.RunSource{}, 10*time.Minute)
	if err != nil {
		t.Fatalf("claim over an abandoned run: %v", err)
	}
	if claim.PriorState != orchestrator.StateInvestigating {
		t.Errorf("PriorState = %q, want Investigating (the abandoned run's)", claim.PriorState)
	}
	if time.Since(claim.StartedAt) > time.Minute {
		t.Errorf("the new claim kept the abandoned run's start %v", claim.StartedAt)
	}
}

func TestClaimAnalysisRun_TerminalIncidentIsRefused(t *testing.T) {
	pool := analyzeDetachTestPool(t)
	tenantID, clusterID, incidentID := analyzeDetachTestIncident(t, pool)
	s := asyncTestServer(pool, nil)
	asyncTestExec(t, pool, tenantID, clusterID, `UPDATE incidents SET state = 'Dismissed' WHERE id = $1`, incidentID)

	_, err := s.claimAnalysisRun(context.Background(), tenantID, clusterID, incidentID, llm.RunSource{}, 10*time.Minute)
	if !errors.Is(err, orchestrator.ErrIllegalTransition) {
		t.Fatalf("err = %v, want ErrIllegalTransition (409 invalid-state)", err)
	}
}

func TestAnalysisRunFailure_RestoresTheIncidentAndRecordsWhy(t *testing.T) {
	pool := analyzeDetachTestPool(t)
	tenantID, clusterID, incidentID := analyzeDetachTestIncident(t, pool)
	s := asyncTestServer(pool, nil)
	ctx := context.Background()

	claim, err := s.claimAnalysisRun(ctx, tenantID, clusterID, incidentID, llm.RunSource{Backend: "api"}, 10*time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	job := analysisJob{inc: incidentSummary{ID: incidentID, ClusterID: clusterID}, tenantID: tenantID, claim: claim}
	s.recordAnalysisRunFailure(ctx, job, &analysisRunFailure{public: "could not complete the AI investigation: provider said no", err: errors.New("provider said no")})

	row := asyncTestReadIncident(t, pool, tenantID, clusterID, incidentID)
	if row.state != orchestrator.StateDetected {
		t.Errorf("state after a failed run = %q, want Detected (restored)", row.state)
	}
	if row.errText == nil || *row.errText != "could not complete the AI investigation: provider said no" {
		t.Errorf("analysisError = %v", row.errText)
	}
	if n := asyncTestTimelineCount(t, pool, tenantID, clusterID, incidentID, "AnalysisFailed"); n != 1 {
		t.Errorf("AnalysisFailed timeline events = %d, want 1", n)
	}

	// GET /incidents/{id}'s reader serves it.
	readTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer readTx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, readTx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	view, err := incidentAnalysisRun(ctx, readTx, incidentID)
	if err != nil {
		t.Fatalf("incidentAnalysisRun: %v", err)
	}
	if view.StartedAt == nil || view.Error == nil || view.Backend == nil || *view.Backend != "api" {
		t.Errorf("view = %+v, want startedAt, error and backend set", view)
	}
	_ = readTx.Rollback(ctx)

	// The next run's claim clears the previous run's error.
	if _, err := s.claimAnalysisRun(ctx, tenantID, clusterID, incidentID, llm.RunSource{}, 10*time.Minute); err != nil {
		t.Fatalf("re-claim: %v", err)
	}
	if row := asyncTestReadIncident(t, pool, tenantID, clusterID, incidentID); row.errText != nil {
		t.Errorf("the previous run's error survived a new run's claim: %q", *row.errText)
	}
}

// A failure must not clobber a state that another writer — here, a newer
// claim — now owns.
func TestAnalysisRunFailure_LeavesASupersededRunAlone(t *testing.T) {
	pool := analyzeDetachTestPool(t)
	tenantID, clusterID, incidentID := analyzeDetachTestIncident(t, pool)
	s := asyncTestServer(pool, nil)
	ctx := context.Background()

	claim, err := s.claimAnalysisRun(ctx, tenantID, clusterID, incidentID, llm.RunSource{}, 10*time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	// A newer run's claim (Investigating -> Investigating is legal).
	newer := func() {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Fatalf("scope: %v", err)
		}
		if err := orchestrator.MarkInvestigating(ctx, tx, tenantID, clusterID, incidentID); err != nil {
			t.Fatalf("newer MarkInvestigating: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}
	newer()

	job := analysisJob{inc: incidentSummary{ID: incidentID, ClusterID: clusterID}, tenantID: tenantID, claim: claim}
	s.recordAnalysisRunFailure(ctx, job, &analysisRunFailure{public: "stale", err: errors.New("stale")})

	row := asyncTestReadIncident(t, pool, tenantID, clusterID, incidentID)
	if row.state != orchestrator.StateInvestigating || row.errText != nil {
		t.Errorf("a superseded run's failure changed the incident: state %q, error %v", row.state, row.errText)
	}
	if n := asyncTestTimelineCount(t, pool, tenantID, clusterID, incidentID, "AnalysisFailed"); n != 0 {
		t.Errorf("AnalysisFailed timeline events = %d, want 0", n)
	}
}

// fakeAsyncInvestigator returns a fixed result once released, and reports
// whether its context was still live when it was.
type fakeAsyncInvestigator struct {
	release   chan struct{}
	ctxErr    chan error
	result    llm.Investigation
	returnErr error
}

func (f *fakeAsyncInvestigator) Investigate(ctx context.Context, _ llm.Target, _, _ string, _ llm.ToolCallback) (llm.Investigation, error) {
	<-f.release
	f.ctxErr <- ctx.Err()
	return f.result, f.returnErr
}

func waitForState(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID string, notState string) asyncTestRow {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		row := asyncTestReadIncident(t, pool, tenantID, clusterID, incidentID)
		if row.state != notState {
			return row
		}
		if time.Now().After(deadline) {
			t.Fatalf("incident still %s after 20s", notState)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// End to end through the background path: the request is cancelled before
// the investigation even returns, and the analysis still lands.
func TestAnalysisRun_RequestCancellationDoesNotCancelTheRun(t *testing.T) {
	pool := analyzeDetachTestPool(t)
	tenantID, clusterID, incidentID := analyzeDetachTestIncident(t, pool)
	inv := &fakeAsyncInvestigator{release: make(chan struct{}), ctxErr: make(chan error, 1), result: fakeInvestigationResult()}
	s := asyncTestServer(pool, inv)

	reqCtx, cancelReq := context.WithCancel(context.Background())
	claim, err := s.claimAnalysisRun(reqCtx, tenantID, clusterID, incidentID, llm.RunSource{Backend: "api"}, 10*time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	job := analysisJob{
		inc:        incidentSummary{ID: incidentID, ClusterID: clusterID},
		tenantID:   tenantID,
		userID:     "usr_m1test",
		userPrompt: "Findings:\n",
		claim:      claim,
	}
	s.launchAnalysisRun(reqCtx, 10*time.Minute, func(runCtx context.Context) {
		if failure := s.runAnalysis(runCtx, job); failure != nil {
			s.recordAnalysisRunFailure(runCtx, job, failure)
		}
	}, nil)

	cancelReq() // the proxy cut the request
	close(inv.release)
	if err := <-inv.ctxErr; err != nil {
		t.Fatalf("the investigation's context was cancelled with the request: %v", err)
	}
	if !s.DrainAnalyses(context.Background(), time.Second) {
		// Not expected: DrainAnalyses with an uncancellable context waits.
		t.Fatal("run did not finish")
	}

	row := waitForState(t, pool, tenantID, clusterID, incidentID, orchestrator.StateInvestigating)
	if row.errText != nil {
		t.Fatalf("run failed: %s", *row.errText)
	}
	if n := asyncTestTimelineCount(t, pool, tenantID, clusterID, incidentID, "AnalysisCompleted"); n != 1 {
		t.Errorf("AnalysisCompleted timeline events = %d, want 1 — the analysis must land", n)
	}
	if row.startedAt == nil || !row.startedAt.Equal(claim.StartedAt) {
		t.Errorf("analysisStartedAt after the run = %v, want it kept as %v", row.startedAt, claim.StartedAt)
	}
}

// A provider failure during the background run lands on the incident, which
// is the only place the operator can now read it.
func TestAnalysisRun_ProviderFailureLandsOnTheIncident(t *testing.T) {
	pool := analyzeDetachTestPool(t)
	tenantID, clusterID, incidentID := analyzeDetachTestIncident(t, pool)
	inv := &fakeAsyncInvestigator{release: make(chan struct{}), ctxErr: make(chan error, 1), returnErr: errors.New("argument list too long")}
	close(inv.release)
	s := asyncTestServer(pool, inv)
	ctx := context.Background()

	claim, err := s.claimAnalysisRun(ctx, tenantID, clusterID, incidentID, llm.RunSource{}, 10*time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	job := analysisJob{inc: incidentSummary{ID: incidentID, ClusterID: clusterID}, tenantID: tenantID, claim: claim}
	s.launchAnalysisRun(ctx, 10*time.Minute, func(runCtx context.Context) {
		if failure := s.runAnalysis(runCtx, job); failure != nil {
			s.recordAnalysisRunFailure(runCtx, job, failure)
		}
	}, nil)
	s.DrainAnalyses(ctx, time.Second)

	row := asyncTestReadIncident(t, pool, tenantID, clusterID, incidentID)
	if row.state != orchestrator.StateDetected {
		t.Errorf("state = %q, want Detected", row.state)
	}
	if row.errText == nil || *row.errText != "could not complete the AI investigation: argument list too long" {
		t.Errorf("analysisError = %v, want the provider's reason", row.errText)
	}
}
