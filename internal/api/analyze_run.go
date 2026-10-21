package api

// analyze_run.go is the background half of POST /incidents/{id}/analyze
// (PROJECT.md M1): claiming a run, launching it on a server-lifetime
// context, recording its failure on the incident, and draining runs at
// shutdown. analyze.go's handleAnalyzeIncident is the request half and
// runAnalysis the investigation itself.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"argus/internal/data"
	"argus/internal/events"
	"argus/internal/llm"
	"argus/internal/logging"
	"argus/internal/orchestrator"
	"argus/internal/settings"
	"argus/internal/timeline"
)

// analysisStartedResponse is POST /incidents/{id}/analyze's 202 body: the
// run was claimed and is under way. Everything about how it ends — the
// analysis, the next state, or the reason it failed — is read from GET
// /incidents/{id}, which the live-events feed signals on every change.
type analysisStartedResponse struct {
	IncidentID string `json:"incidentId"`
	State      string `json:"state"` // always "Investigating"
	StartedAt  string `json:"startedAt"`
	// Backend and Model are what the run was configured to use when it was
	// claimed (llm.RunSource) — omitted when not knowable before the run (a
	// cli agent picks its own model).
	Backend string `json:"backend,omitempty"`
	Model   string `json:"model,omitempty"`
}

// analysisPreflighter is implemented by *llm.Router. Optional, like
// cliBackendReporter, so a test fake Investigator need not grow a method it
// has no opinion about.
type analysisPreflighter interface {
	Preflight(ctx context.Context) (llm.RunSource, error)
}

// analysisSourceFromConfig is the RunSource used when the investigator
// cannot preflight: the configured kind, and the configured model for api.
func analysisSourceFromConfig(cfg settings.Config) llm.RunSource {
	kind := settings.NormalizeProviderKind(cfg.LLMProviderKind)
	src := llm.RunSource{Backend: kind}
	if kind == settings.ProviderKindAPI {
		src.Model = cfg.LLMModel
	}
	return src
}

// analysisClaim is what claimAnalysisRunTx committed: the run's
// InvestigationStarted timeline event (its id is the run's identity; its
// occurred_at is the run's start), the state the incident was in before it,
// and the source recorded on that event.
type analysisClaim struct {
	EventID    string
	StartedAt  time.Time
	PriorState string
	Backend    string
	Model      string
}

// analysisInProgressError is the duplicate-run refusal. StartedAt is nil when
// the run in flight was detected by its row lock rather than its stamp — an
// automatic investigation holds the incident row for its whole run without
// committing its claim, so it is visible only that way.
type analysisInProgressError struct {
	StartedAt *time.Time
}

func (e *analysisInProgressError) Error() string {
	return "an analysis is already running for this incident"
}

// Detail is the RFC 9457 detail for the 409.
func (e *analysisInProgressError) Detail() string {
	if e.StartedAt != nil {
		return fmt.Sprintf("An investigation of this incident started at %s and is still running. This page updates when it finishes.",
			formatRFC3339(*e.StartedAt))
	}
	return "Another investigation of this incident (possibly an automatic one) is still running. Try again when it finishes."
}

// analysisClaimLockTimeout bounds how long a claim waits for the incident
// row. Every ordinary writer holds it for milliseconds; the only long holders
// are an investigation in flight (an automatic one for its whole run, a
// manual one once it has resolved the incident's route), and those are
// exactly what the claim must refuse rather than queue behind — queueing is
// what would make this request outlive a proxy's idle timeout again.
const analysisClaimLockTimeout = "2s"

// analysisRunInFlight reports whether an incident in state, whose current run
// was stamped at startedAt, has an investigation running now. A run older
// than staleAfter (the run budget: its own context has expired by then) was
// abandoned — a hub that died mid-run leaves the incident Investigating with
// nothing behind it — and must not block a new one forever. A nil start
// while Investigating (no InvestigationStarted event: a state written some
// other way) has no run to protect either.
func analysisRunInFlight(state string, startedAt *time.Time, now time.Time, staleAfter time.Duration) bool {
	if state != orchestrator.StateInvestigating || startedAt == nil {
		return false
	}
	return now.Sub(*startedAt) < staleAfter
}

// analysisFailureRestoreState is where a failed manual run puts the incident
// back. The run moved it to Investigating from prior; the state machine
// only allows a few edges OUT of Investigating, so prior is restored exactly
// when one of those edges reaches it (Detected, NeedsHumanInvestigation,
// AwaitingApproval — whose pending plan is untouched by a failed re-analysis
// — and Diagnosed). Every other prior state (PlanRejected, Failed,
// Validating, Reopened, ...) has no edge back, deliberately — those edges
// would let any writer leave Investigating for them — so the run lands on
// NeedsHumanInvestigation: an investigation a person asked for did not reach
// a conclusion, and a person needs to look. The AnalysisFailed event says why.
func analysisFailureRestoreState(prior string) string {
	if prior != orchestrator.StateInvestigating && orchestrator.CanTransition(orchestrator.StateInvestigating, prior) {
		return prior
	}
	return orchestrator.StateNeedsHumanInvestigation
}

// claimAnalysisRun commits the claim in its own short transaction, on a
// context detached from the request: the claim must not be undone by the
// client disconnecting a moment after it was made (BUGS.md 89's mechanism —
// a cancelled context fails pgx's Commit and closes the connection).
func (s *Server) claimAnalysisRun(reqCtx context.Context, tenantID, clusterID, incidentID string, src llm.RunSource, staleAfter time.Duration) (analysisClaim, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(reqCtx), 15*time.Second)
	defer cancel()
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return analysisClaim{}, fmt.Errorf("begin the claim transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		return analysisClaim{}, fmt.Errorf("scope the claim transaction: %w", err)
	}
	claim, err := claimAnalysisRunTx(ctx, tx, tenantID, clusterID, incidentID, src, staleAfter)
	if err != nil {
		return analysisClaim{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return analysisClaim{}, fmt.Errorf("commit the claim: %w", err)
	}
	return claim, nil
}

// claimAnalysisRunTx is the duplicate-safe claim, on an already-scoped tx.
//
// The incident row lock (FOR UPDATE) is what makes it safe across hub
// replicas: two claims serialize on the row, and the second one reads the
// first one's committed Investigating + InvestigationStarted and refuses. A
// claim that cannot get the lock within analysisClaimLockTimeout refuses too
// — that is an investigation holding the row (see analysisClaimLockTimeout).
// Before this existed, two concurrent synchronous requests simply queued on
// the same lock and ran two investigations back to back; refusing the
// second is the guarantee the asynchronous path makes instead.
func claimAnalysisRunTx(ctx context.Context, tx pgx.Tx, tenantID, clusterID, incidentID string, src llm.RunSource, staleAfter time.Duration) (analysisClaim, error) {
	if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout = '"+analysisClaimLockTimeout+"'"); err != nil {
		return analysisClaim{}, fmt.Errorf("set the claim's lock timeout: %w", err)
	}
	var state string
	var now time.Time
	err := tx.QueryRow(ctx,
		`SELECT state, now() FROM incidents WHERE id = $1 FOR UPDATE`, incidentID,
	).Scan(&state, &now)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "55P03" { // lock_not_available
			return analysisClaim{}, &analysisInProgressError{}
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return analysisClaim{}, fmt.Errorf("%w: %s", orchestrator.ErrIncidentNotFound, incidentID)
		}
		return analysisClaim{}, fmt.Errorf("lock the incident for the claim: %w", err)
	}
	if state == orchestrator.StateInvestigating {
		current, err := latestInvestigationRun(ctx, tx, incidentID)
		if err != nil {
			return analysisClaim{}, err
		}
		var startedAt *time.Time
		if current != nil {
			startedAt = &current.StartedAt
		}
		// Database time on both sides of the comparison, so replicas with
		// skewed clocks agree about whether a run is stale.
		if analysisRunInFlight(state, startedAt, now, staleAfter) {
			return analysisClaim{}, &analysisInProgressError{StartedAt: startedAt}
		}
	}
	detail := map[string]any{"trigger": TriggeredByManual}
	if src.Backend != "" {
		detail["backend"] = src.Backend
	}
	if src.Model != "" {
		detail["model"] = src.Model
	}
	if err := orchestrator.MarkInvestigatingWithDetail(ctx, tx, tenantID, clusterID, incidentID, detail); err != nil {
		return analysisClaim{}, err
	}
	// Read back the event just written — under the row lock no other claim
	// can have written a later one — for the run's identity and start.
	run, err := latestInvestigationRun(ctx, tx, incidentID)
	if err != nil {
		return analysisClaim{}, err
	}
	if run == nil {
		return analysisClaim{}, errors.New("the claim's InvestigationStarted event is not readable back")
	}
	return analysisClaim{EventID: run.EventID, StartedAt: run.StartedAt, PriorState: state, Backend: src.Backend, Model: src.Model}, nil
}

// analysisRunFailure is a background run's failure: Public is the sentence
// an operator reads on the incident (what the synchronous path used to put
// in its RFC 9457 detail), Err the full error for the hub log.
type analysisRunFailure struct {
	public string
	err    error
}

// recordAnalysisRunFailure puts a failed run's outcome on the incident: the
// state is restored (analysisFailureRestoreState), and an AnalysisFailed
// timeline event naming the run's InvestigationStarted carries the reason —
// which is what GET /incidents/{id}'s analysisError reads. Previously the
// request's 502/503 told the one person who clicked; now the incident tells
// everyone.
//
// Only touches an incident that is still in THIS run's Investigating — same
// state, same latest InvestigationStarted event, checked under the row lock.
// Anything else means another writer has since moved it (a cluster
// decommission, a newer run claimed after this one was judged stale), and
// that writer owns the state now. On its own detached, bounded context, so a
// run cancelled by its deadline or by the hub draining can still record why
// it stopped.
func (s *Server) recordAnalysisRunFailure(runCtx context.Context, job analysisJob, failure *analysisRunFailure) {
	incidentID, clusterID := job.inc.ID, job.inc.ClusterID
	ctx, cancel := context.WithTimeout(context.WithoutCancel(runCtx), 15*time.Second)
	defer cancel()

	public := failure.public
	if s.IsShuttingDown() && errors.Is(runCtx.Err(), context.Canceled) {
		public = "the hub restarted before the investigation finished; run it again"
	}
	logger.ErrorContext(ctx, "background investigation failed",
		logging.IncidentID(incidentID), logging.ClusterID(clusterID),
		slog.String("reason", public), logging.Err(failure.err))

	if err := s.applyAnalysisRunFailure(ctx, job, public); err != nil {
		logger.ErrorContext(ctx, "recording the failed investigation on the incident failed; it stays Investigating until a new analysis is started",
			logging.IncidentID(incidentID), logging.Err(err))
		return
	}
	if s.events != nil {
		s.events.Publish(events.IncidentUpdated(incidentID, clusterID))
	}
}

func (s *Server) applyAnalysisRunFailure(ctx context.Context, job analysisJob, public string) error {
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := data.SetRequestScope(ctx, tx, job.tenantID, []string{job.inc.ClusterID}); err != nil {
		return err
	}
	applied, err := applyAnalysisRunFailureTx(ctx, tx, job.tenantID, job.inc.ClusterID, job.inc.ID, job.claim, public)
	if err != nil {
		return err
	}
	if !applied {
		logger.InfoContext(ctx, "the failed investigation's incident has already moved on; leaving its state alone",
			logging.IncidentID(job.inc.ID))
		return nil
	}
	return tx.Commit(ctx)
}

// applyAnalysisRunFailureTx is recordAnalysisRunFailure's database half, on
// an already-scoped tx. Reports false, writing nothing, when the incident is
// no longer in this run's Investigating.
func applyAnalysisRunFailureTx(ctx context.Context, tx pgx.Tx, tenantID, clusterID, incidentID string, claim analysisClaim, public string) (bool, error) {
	var state string
	if err := tx.QueryRow(ctx,
		`SELECT state FROM incidents WHERE id = $1 FOR UPDATE`, incidentID,
	).Scan(&state); err != nil {
		return false, fmt.Errorf("lock the incident: %w", err)
	}
	if state != orchestrator.StateInvestigating {
		return false, nil
	}
	current, err := latestInvestigationRun(ctx, tx, incidentID)
	if err != nil {
		return false, err
	}
	if current == nil || current.EventID != claim.EventID {
		return false, nil
	}
	restored := analysisFailureRestoreState(claim.PriorState)
	if err := orchestrator.SetState(ctx, tx, incidentID, restored); err != nil {
		return false, fmt.Errorf("restore the incident to %s: %w", restored, err)
	}
	stored := truncateRunes(public, maxAnalysisErrorRunes)
	if err := timeline.Record(ctx, tx, timeline.Event{
		TenantID: tenantID, ClusterID: clusterID, IncidentID: incidentID,
		Type:    timeline.EventAnalysisFailed,
		Summary: "Investigation did not complete: " + stored,
		Detail: map[string]any{
			"error":         stored,
			"restoredState": restored,
			"trigger":       TriggeredByManual,
			// The run this failure closes — how GET /incidents/{id} pairs the
			// two (latestInvestigationRun) without trusting timestamps.
			"runEventId": claim.EventID,
		},
	}); err != nil {
		return false, fmt.Errorf("record the AnalysisFailed timeline event: %w", err)
	}
	return true, nil
}

// maxAnalysisErrorRunes bounds the recorded failure reason. A provider's error can carry
// a whole response body; the incident needs the reason, not the payload.
const maxAnalysisErrorRunes = 2000

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// analysisRuns is the server-lifetime state background investigations run
// under. Zero-value-safe (a bare &Server{} in tests gets a lifetime context
// on first use), like the shutdown state in shutdown.go.
type analysisRuns struct {
	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// lifetime returns the context every background investigation's own context
// is cancelled with: it ends only when the hub drains (DrainAnalyses).
func (a *analysisRuns) lifetime() context.Context {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ctx == nil {
		a.ctx, a.cancel = context.WithCancel(context.Background())
	}
	return a.ctx
}

// launchAnalysisRun runs run in the background on a context that carries the
// request's values (its request id and log attributes) but NOT its
// cancellation, is bounded by budget, and is cancelled if the hub drains.
// A panic in run is recovered and handed to onPanic rather than taking the
// hub down — the request that would have surfaced it is long gone.
func (s *Server) launchAnalysisRun(reqCtx context.Context, budget time.Duration, run func(ctx context.Context), onPanic func(ctx context.Context, recovered any)) {
	lifetime := s.analysisRuns.lifetime()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(reqCtx), budget)
	stop := context.AfterFunc(lifetime, cancel)
	s.analysisRuns.wg.Add(1)
	go func() {
		defer s.analysisRuns.wg.Done()
		defer cancel()
		defer stop()
		defer func() {
			if recovered := recover(); recovered != nil {
				logger.ErrorContext(ctx, "background investigation panicked",
					slog.Any("panic", recovered), slog.String("stack", string(debug.Stack())))
				if onPanic != nil {
					onPanic(ctx, recovered)
				}
			}
		}()
		run(ctx)
	}()
}

// DrainAnalyses is the hub's shutdown step for background investigations
// (cmd/hub's drainHub, after the HTTP drain and before the tunnels close —
// an investigation needs its cluster's tunnel until it stops). It waits for
// running investigations until ctx expires, then cancels the rest and gives
// them recordWithin to record that they were cut short, so their incidents
// do not sit in Investigating until the stale window passes. Reports
// whether every run finished on its own.
func (s *Server) DrainAnalyses(ctx context.Context, recordWithin time.Duration) (finishedOnTheirOwn bool) {
	done := make(chan struct{})
	go func() { s.analysisRuns.wg.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-ctx.Done():
	}
	s.analysisRuns.lifetime() // ensure cancel exists
	s.analysisRuns.mu.Lock()
	cancel := s.analysisRuns.cancel
	s.analysisRuns.mu.Unlock()
	cancel()
	timer := time.NewTimer(recordWithin)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
	return false
}

// investigationRun is the latest investigation on an incident, read from
// its timeline: the InvestigationStarted event (orchestrator.MarkInvestigating
// writes it in the same transaction that moves the incident to Investigating,
// so it is THE record of when a run started — PROJECT.md M1 deliberately
// keeps no second copy on incidents) and, if that run failed in the
// background, the AnalysisFailed event naming it.
type investigationRun struct {
	EventID   string
	StartedAt time.Time
	Backend   *string
	Model     *string
	Error     *string
}

// latestInvestigationRun returns the incident's latest investigation run, or
// nil if none was ever started. Served by migration 000127's index.
func latestInvestigationRun(ctx context.Context, tx pgx.Tx, incidentID string) (*investigationRun, error) {
	var run investigationRun
	err := tx.QueryRow(ctx,
		`SELECT s.id, s.occurred_at, s.payload->>'backend', s.payload->>'model',
		        (SELECT f.payload->>'error' FROM timeline_events f
		          WHERE f.incident_id = s.incident_id AND f.event_type = $3
		            AND f.payload->>'runEventId' = s.id
		          ORDER BY f.occurred_at DESC LIMIT 1)
		   FROM timeline_events s
		  WHERE s.incident_id = $1 AND s.event_type = $2
		  ORDER BY s.occurred_at DESC, s.id DESC LIMIT 1`,
		incidentID, timeline.EventInvestigationStarted, timeline.EventAnalysisFailed,
	).Scan(&run.EventID, &run.StartedAt, &run.Backend, &run.Model, &run.Error)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the incident's latest investigation run: %w", err)
	}
	return &run, nil
}

// incidentAnalysisRunView is GET /incidents/{id}'s account of the current or
// most recent investigation run — four always-present, nullable top-level
// fields, matching how the detail payload carries route/routeReason/applier.
type incidentAnalysisRunView struct {
	StartedAt *string
	Backend   *string
	Model     *string
	Error     *string
}

func incidentAnalysisRun(ctx context.Context, tx pgx.Tx, incidentID string) (incidentAnalysisRunView, error) {
	run, err := latestInvestigationRun(ctx, tx, incidentID)
	if err != nil || run == nil {
		return incidentAnalysisRunView{}, err
	}
	startedAt := formatRFC3339(run.StartedAt)
	return incidentAnalysisRunView{StartedAt: &startedAt, Backend: run.Backend, Model: run.Model, Error: run.Error}, nil
}

// claimProblem is one RFC 9457 response for a refused claim.
type claimProblem struct {
	status             int
	typ, title, detail string
}

// analysisClaimProblem maps a claim refusal the caller can act on to its
// response. ok is false for anything else — a server error, logged by the
// handler and answered with a generic 500.
func analysisClaimProblem(err error) (claimProblem, bool) {
	var inProgress *analysisInProgressError
	switch {
	case errors.As(err, &inProgress):
		return claimProblem{http.StatusConflict, "https://argus.io/errors/analysis-in-progress",
			"An analysis is already running for this incident", inProgress.Detail()}, true
	case errors.Is(err, orchestrator.ErrIllegalTransition):
		// The state machine refuses to revive a terminal incident or to race
		// an in-flight execution (orchestrator.SetState). That is the caller
		// asking for something the incident's current state forbids — 409
		// with the actual reason, since "Could not start analysis" gives an
		// operator nothing to act on.
		return claimProblem{http.StatusConflict, "https://argus.io/errors/invalid-state",
			"This incident cannot be re-analyzed in its current state", err.Error()}, true
	case errors.Is(err, orchestrator.ErrIncidentNotFound):
		return claimProblem{http.StatusNotFound, "https://argus.io/errors/not-found", "Incident not found", ""}, true
	}
	return claimProblem{}, false
}
