package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/events"
	"argus/internal/knowledge"
	"argus/internal/llm"
	"argus/internal/logging"
	"argus/internal/metrics"
	"argus/internal/orchestrator"
	"argus/internal/remediation"
	"argus/internal/repotools"
	"argus/internal/settings"
	"argus/internal/timeline"
)

// analysisResponse is the pinned API contract GET /incidents/{id}'s embedded
// "analysis" field returns (POST /incidents/{id}/analyze returned it too
// until it became asynchronous, PROJECT.md M1) — the real
// evidence-based shape lld/07-analysis-contracts.md §3/§4 specs, replacing
// the old one-shot analysisSummary (model/statement/createdAt only). A
// parallel UI task (IncidentDetailPage.tsx) is built against these exact
// field names and this exact complete-vs-partial shape — see this file's
// package-level comment history in STATUS.md before changing any of them.
//
// On a complete result: RootCause/Confidence are populated, PartialReason is
// nil. SuggestedNextSteps is nil too UNLESS the incident's route
// (lld/08-remediation-contracts.md §12) is guidance — a real conclusion with
// no in-cluster action available still needs something actionable to show
// (§12.7). On a partial result (a bound was hit before the model concluded):
// RootCause and Confidence are BOTH nil — never a confidence number for an
// incomplete investigation, which would be exactly the "numerology" lld/07
// §4 warns against — PartialReason and SuggestedNextSteps are populated.
// CausalChain/RuledOut are populated in both cases with whatever was
// actually gathered; a partial analysis is a real, evidence-linked result,
// not a failure response.
type analysisResponse struct {
	// ID identifies THIS analysis, because an incident can be analysed several
	// times and anything judging one of them has to name which. That was
	// feedback's reason for existing (removed 2026-08-25, WISHLIST.md W1) and it
	// stays the reason a calibration curve will need this field. Omitted
	// when absent so the freshly-computed POST /analyze response, which has no row
	// id in hand at that point, does not report an empty string as an id.
	ID string `json:"id,omitempty"`
	// RawFinalAnswer and ParseError are present ONLY when this investigation's
	// concluding message could not be read (BACKLOG C2). They are the diagnostic
	// pair that answers "was this a prompt problem or a harness problem?", which
	// was previously unanswerable after the fact because nothing persisted the
	// answer. Omitted entirely on the ordinary path, so a client can treat their
	// presence as "this run's output was unreadable" with no extra flag.
	RawFinalAnswer string           `json:"rawFinalAnswer,omitempty"`
	ParseError     string           `json:"parseError,omitempty"`
	Model          string           `json:"model"`
	Status         string           `json:"status"` // "complete" | "partial"
	RootCause      *rootCauseOut    `json:"rootCause"`
	Confidence     *float64         `json:"confidence"`
	CausalChain    []llm.CausalStep `json:"causalChain"`
	// CausalChainProvenance is one of llm.CausalChainProvenanceHubObserved /
	// llm.CausalChainProvenanceSelfReported (BACKLOG.md C10) — which kind of
	// artifact CausalChain is: turn-by-turn calls the hub itself dispatched
	// and observed (the api backend), or the model's own account of its
	// reasoning, cross-checked against the hub's mcp_tool_calls ledger but
	// still fundamentally self-reported (the cli backend). Omitted (empty
	// string) on a row written before this field existed — every such row's
	// non-empty CausalChain, if it has one, was always hub-observed (the cli
	// backend reported nothing at all until this landed), so the UI treats a
	// missing value the same as hub-observed rather than as "unknown."
	// Per-tool-call ToolCallRecord.Corroborated only means anything when this
	// is self-reported — see that field's own doc comment.
	CausalChainProvenance string                   `json:"causalChainProvenance,omitempty"`
	RuledOut              []llm.RuledOutHypothesis `json:"ruledOut"`
	PartialReason         *string                  `json:"partialReason"`
	SuggestedNextSteps    []string                 `json:"suggestedNextSteps"`
	Iterations            int                      `json:"iterations"`
	CreatedAt             string                   `json:"createdAt"`
	// TokensBilledIn/TokensCacheRead/TokensOut/CostUSD are the same
	// low-key metadata tier as Model/Iterations/CreatedAt above — real
	// numbers summed across every model round-trip the investigation made
	// (internal/llm.Investigation's own doc comment), populated identically
	// on a "partial" result, since a bound-hit investigation still made
	// real, billed LLM calls. CostUSD is a real dollar figure computed from
	// an operator-configured per-token pricing table (see persistAnalysis's
	// comment, and internal/settings.Config.ComputeCostUSD) once one is
	// configured; it stays an honest 0 — never a fabricated number — until
	// then.
	TokensBilledIn  int64   `json:"tokensBilledIn"`
	TokensCacheRead int64   `json:"tokensCacheRead"`
	TokensOut       int64   `json:"tokensOut"`
	CostUSD         float64 `json:"costUsd"`
	// CostBasis says whether CostUSD is a measured figure ("metered") or
	// structurally unavailable ("subscription"/"unknown"). Without it on the
	// wire, a subscription-billed CLI run — which stores cost_usd = 0 meaning
	// *unavailable* — rendered in the UI as a definite "$0.0000", i.e. free.
	// lld/07-analysis-contracts.md §10.5 forbids exactly that, and the rule was
	// being enforced in the database and then dropped at the API boundary.
	CostBasis string `json:"costBasis"`
	// EvidenceCoverage: what the investigation could and could not read
	// (PROJECT.md IN6). Absent for analyses written before it was recorded.
	EvidenceCoverage *llm.EvidenceCoverage `json:"evidenceCoverage,omitempty"`

	// TriggeredBy is "manual" | "auto" | "" (BACKLOG.md C6, migration
	// 000074) — whether this analysis came from a human's POST
	// /incidents/{id}/analyze or internal/autoanalyze.Poller's unattended
	// sweep. Empty (json omits it) only for a row written before this
	// column existed; every analysis persisted from here on always carries
	// one of the two real values, since PersistAnalysis's triggeredBy
	// parameter is not optional. Not omitted for a genuinely empty value on
	// a fresh row — see analyses.triggered_by's own migration comment for
	// why that's deliberately a distinguishable "unknown," not backfilled.
	TriggeredBy string `json:"triggeredBy,omitempty"`

	// IncidentState/StateReason/Plan are new, additive fields this task adds
	// on top of the pinned §25/§26 contract above — internal/orchestrator's
	// real state-machine wiring. IncidentState is the incident's state AFTER
	// this analysis was applied (Investigating/RecommendationReady/
	// NeedsHumanInvestigation/AwaitingApproval — never Executing, see
	// internal/orchestrator's package doc comment for why). StateReason is
	// always populated (why that state, in plain language). Plan is nil
	// whenever the investigation didn't propose one (a normal, honest
	// outcome — see internal/orchestrator.Advance's own doc comment), and
	// only ever populated on getLatestAnalysis's read-back path if this
	// analysis is the incident's current one — see that function's own
	// comment.
	IncidentState string    `json:"incidentState"`
	StateReason   string    `json:"stateReason"`
	Plan          *planView `json:"plan"`
	// PairedPlan is the route's second recommendation (lld/08 §12.6, F17,
	// BACKLOG D8) — non-nil only when Plan's route was resolved to
	// `pullRequest+inPlace` and the model actually proposed both halves, in
	// which case remediation_recommendations carries two rows for this
	// analysis, linked by sibling_of_recommendation_id. This field existed as
	// a genuine gap until this task: the DB has carried the pairing since F17
	// landed (2026-08-25), orchestrator.Advance/ApplyAnalysisResult already
	// compute and persist it as adv.PairedPlan/PairedPlanID/PairedDecision,
	// but nothing between there and the wire ever copied it onto a response —
	// so an operator has never been able to see BOTH halves of a paired route
	// through the API, only whichever single row a `created_at`-ordered query
	// happened to pick (see recommendationIDsForAnalysis's own comment on why
	// that was also non-deterministic). Never populated standalone: a
	// PairedPlan with a nil Plan cannot happen, since EnforceRoute refuses a
	// paired proposal missing its primary half at parse time.
	PairedPlan *planView `json:"pairedPlan,omitempty"`
}

type rootCauseOut struct {
	Statement string `json:"statement"`
	// IsFault (PROJECT.md T4 gap 3) mirrors llm.RootCause.IsFault onto the
	// wire — omitted, not merely false, whenever the model was never asked
	// (any backend/prompt path that leaves llm.RootCause.IsFault nil) so a
	// client can tell "no verdict was ever recorded" apart from "the model
	// said this is not a fault". Read from rootCauseStored on the read-back
	// path (getLatestAnalysis below) and from the in-memory llm.Investigation
	// directly on the freshly-completed path (toAnalysisResponse) — the same
	// pointer, never re-derived, so the two paths cannot silently disagree
	// about a fact this thin.
	IsFault *bool `json:"isFault,omitempty"`
}

// handleAnalyzeIncident is POST /api/v1/incidents/{id}/analyze. Requires
// incident:reanalyse. Answers 202 Accepted once the run is claimed
// (analysisStartedResponse) and runs the investigation in the background
// (runAnalysis, PROJECT.md M1) — the outcome is read from GET
// /incidents/{id}. 409 when an investigation of this incident is already
// running or its state forbids one; 503 when its cluster has no live agent or
// no AI provider is usable, both checked before anything is claimed.
//
// The investigation is the real bounded, tool-calling investigation loop
// (internal/llm.Investigate, ADR-2 / lld/07-analysis-contracts.md) — get_events,
// get_logs, describe_resource, and get_owner_chain calls against the
// incident's own cluster, routed through s.gw.CallTool (the only path from
// model output to a live cluster call, staying inside argus-investigate's
// RBAC boundary by construction) — before concluding anything, replacing the
// old context-free one-shot call.
func (s *Server) handleAnalyzeIncident(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	incidentID := r.PathValue("id")
	ctx := r.Context()

	row := rc.Tx.QueryRow(ctx, incidentListQuery+" AND incidents.id = $1", incidentID)
	inc, err := scanIncidentSummary(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Incident not found", "")
			return
		}
		logger.ErrorContext(ctx, "looking up the incident to analyze failed",
			logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up incident", "")
		return
	}

	// Fail fast rather than run a pointless (and, for a real hosted
	// provider, billed) investigation loop against a cluster with no live
	// agent to call: every tool call would fail immediately for the same
	// reason, and the model would burn its bounded turn budget learning
	// that instead of ever gathering real evidence. This is a preflight
	// check, not a replacement for CallTool's own per-call handling of a
	// cluster that disconnects mid-investigation (internal/llm's loop
	// tolerates a tool-level error and keeps going — see toolloop_test.go's
	// TestInvestigateRecordsToolCallErrorsAndContinues — because THAT case
	// already has some evidence and a real chance of concluding usefully;
	// this case has none).
	if !s.gw.IsConnected(inc.ClusterID) {
		writeProblem(w, http.StatusServiceUnavailable, "https://argus.io/errors/cluster-unreachable",
			"Cluster not connected",
			"This cluster has no live agent connection right now, so no evidence can be gathered. "+
				"The cluster must be Active (its agent's mTLS tunnel connected) to run an analysis.")
		return
	}

	// Daily spend ceiling check (DESIGN.md §16.4,
	// internal/settings.Config.DailySpendCeilingUsd) — deliberately does NOT
	// block this manual path even when breached, unlike
	// internal/autoanalyze's automatic path (see that package's own doc
	// comment for the opposite choice there). Reasoning, stated rather than
	// left implicit: a human explicitly clicking "Analyze" on ONE specific
	// incident is a deliberate, bounded action — exactly the kind of thing a
	// blanket daily ceiling exists to NOT need to second-guess — whereas the
	// ceiling's whole purpose is to stop a noisy fleet from running up real
	// LLM spend completely unsupervised (internal/autoanalyze's poller, with
	// no human in the loop at all). Still checked and logged here, though,
	// so an operator who's over budget and clicking "Analyze" anyway leaves
	// a clear trail rather than a silent one. A no-op with no query at all
	// when SpendCeilingActive() is false (no ceiling configured, or pricing
	// not configured — see that method's own doc comment for why "no
	// pricing" must mean "this check never blocks anything").
	// cfg is also reused below, once we're past every early-return check, to
	// size the detached investigation's own workCtx deadline — resolved
	// here rather than a second time there, matching this codebase's
	// "resolve settings once per call" discipline elsewhere.
	cfg, err := settings.Resolve(ctx, rc.Tx)
	if err != nil {
		logger.ErrorContext(ctx, "resolving settings for the spend-ceiling check failed",
			logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not start analysis", "")
		return
	}
	if cfg.SpendCeilingActive() {
		todaySpend, err := TodaySpendUSD(ctx, rc.Tx)
		if err != nil {
			logger.ErrorContext(ctx, "checking the daily spend ceiling failed",
				logging.IncidentID(incidentID), logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not start analysis", "")
			return
		}
		if SpendCeilingBreached(cfg, todaySpend) {
			logger.WarnContext(ctx, "daily spend ceiling reached; proceeding anyway because this is a manual, human-initiated analyze request. Only internal/autoanalyze's unsupervised automatic path is stopped by the ceiling",
				logging.IncidentID(incidentID),
				slog.Float64("spent_today_usd", todaySpend),
				slog.Float64("daily_spend_ceiling_usd", *cfg.DailySpendCeilingUsd))
		}
	}

	// PROJECT.md D-Learn (the "Learn" step, previously unbuilt entirely):
	// retrieval is an enhancement to the prompt, never a new hard dependency
	// — a failure here is logged and the investigation proceeds with no
	// retrieved context, the same posture Store.TriggerAsync already
	// established for embedding failures. See RetrieveSimilar's own doc
	// comment for why this cannot silently masquerade as evidence.
	//
	// Gated on cfg.RetrievalEnabled (migration 000102), default false: live
	// measurement found 31% higher cost with no measurable confidence
	// benefit on one real repeated fault — an inconclusive result that must
	// not ship as an unconditional cost increase. Unconfiguring embedding
	// entirely was the only previous off switch, and that also disables the
	// storage retrieval depends on, which is not a real control.
	var retrievalSection string
	if cfg.RetrievalEnabled {
		if retrieved, rerr := s.knowledge.RetrieveSimilar(ctx, rc.Tx, incidentID); rerr != nil {
			logger.WarnContext(ctx, "retrieving similar prior analyses failed; proceeding without retrieved context",
				logging.IncidentID(incidentID), logging.Err(rerr))
		} else {
			retrievalSection = knowledge.FormatRetrievedForPrompt(retrieved)
		}
	}

	// llm.BuildFindingsPrompt, not a local loop. This handler and
	// internal/autoanalyze each had their own copy of an UNBOUNDED
	// `SELECT ... FROM findings WHERE incident_id = $1` concatenated one line
	// per row, which made every sufficiently long-lived incident permanently
	// impossible to analyse: the CLI runner passes the prompt as a single argv
	// element and Linux caps one argument at 128 KiB. See that function's own
	// comment for the measurements. One shared builder so the two paths cannot
	// drift, and so the bound cannot be fixed in one and forgotten in the other.
	userPrompt, err := llm.BuildFindingsPrompt(ctx, rc.Tx, incidentID,
		retrievalSection+fmt.Sprintf("Cluster: %s\nIncident fingerprint: %s, severity: %s, seen %d time(s)\n\nFindings:\n",
			inc.ClusterDisplayName, inc.Fingerprint, inc.Severity, inc.OccurrenceCount))
	if err != nil {
		logger.ErrorContext(ctx, "building the findings prompt failed",
			logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up incident findings", "")
		return
	}

	// PROJECT.md M1: from here on the request does not wait for the
	// investigation. A proxy idle timeout shorter than the investigation's
	// time limit cut the synchronous request while the investigation carried
	// on server-side, which read as a failure; so the handler claims the run,
	// answers 202, and the investigation proceeds in the background
	// (runAnalysis), reporting its progress and outcome through the incident
	// itself (state, and its timeline's InvestigationStarted/AnalysisFailed
	// events — analysisStartedAt/analysisError on GET) and the
	// IncidentUpdated live event.
	if s.IsShuttingDown() {
		writeProblem(w, http.StatusServiceUnavailable, "https://argus.io/errors/shutting-down",
			"Hub is shutting down", "This hub is draining for a restart and is not starting new investigations. Try again in a moment.")
		return
	}

	// The provider-configuration half of what used to surface as the
	// investigation's own ErrNotConfigured, checked BEFORE accepting the run
	// so a run that could never start is still refused synchronously, with
	// the router's own message (the specific message IS the diagnostic
	// value — see Router.Preflight). A provider that cannot preflight (a
	// test fake) skips this; Investigate still makes every check itself and
	// a failure there lands on the incident.
	source := analysisSourceFromConfig(cfg)
	if p, ok := s.llmProvider.(analysisPreflighter); ok {
		got, perr := p.Preflight(ctx)
		if perr != nil {
			if errors.Is(perr, llm.ErrNotConfigured) {
				writeProblem(w, http.StatusServiceUnavailable, "https://argus.io/errors/llm-not-configured",
					"AI provider not usable", perr.Error())
				return
			}
			logger.ErrorContext(ctx, "checking the AI provider before starting the investigation failed",
				logging.IncidentID(incidentID), logging.Err(perr))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not start analysis", "")
			return
		}
		source = got
	}

	// The investigation's deadline is a safety net, not the loop's real
	// bound: an operator-configured internal/llm.DefaultTimeLimit (or
	// cfg.AnalysisTimeLimitSeconds override) still governs how long an
	// investigation normally runs. It's widened by investigationCommitMargin
	// because investigate() only checks that limit BETWEEN model round-trips —
	// the round already in flight when the deadline lands still has to be
	// allowed to finish, and then PersistAnalysis/ApplyAnalysisResult still
	// have to run and commit. The same figure is how long a claimed run counts
	// as in flight for the duplicate check below: past it, the run's own
	// context has expired, so an incident still Investigating was abandoned
	// (a hub that died mid-run), not busy.
	timeLimit := llm.DefaultTimeLimit
	if cfg.AnalysisTimeLimitSeconds != nil {
		timeLimit = time.Duration(*cfg.AnalysisTimeLimitSeconds) * time.Second
	}
	runBudget := timeLimit + investigationCommitMargin

	// Claim the run: Detected (or any re-analysable state) -> Investigating,
	// committed NOW in its own short transaction on a detached context — not
	// on rc.Tx, whose commit happens after this handler returns on a context
	// that is cancelled the moment the client disconnects (BUGS.md 89). The
	// claim holds the incident row lock while it checks for a run already in
	// flight, so two concurrent POSTs — on this hub or another replica —
	// cannot both start one: the second gets 409. See claimAnalysisRunTx.
	claim, err := s.claimAnalysisRun(ctx, rc.TenantID, inc.ClusterID, incidentID, source, runBudget)
	if err != nil {
		if problem, ok := analysisClaimProblem(err); ok {
			writeProblem(w, problem.status, problem.typ, problem.title, problem.detail)
			return
		}
		logger.ErrorContext(ctx, "claiming the investigation run failed",
			logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not start analysis", "")
		return
	}
	// The claim is durable: every tab watching this incident should flip to
	// Investigating now, not when the run ends.
	if s.events != nil {
		s.events.Publish(events.IncidentUpdated(incidentID, inc.ClusterID))
	}

	job := analysisJob{
		inc:        inc,
		tenantID:   rc.TenantID,
		userID:     rc.UserID,
		grants:     rc.Grants,
		sourceIP:   clientIP(r),
		userPrompt: userPrompt,
		claim:      claim,
	}
	s.launchAnalysisRun(ctx, runBudget,
		func(runCtx context.Context) {
			if failure := s.runAnalysis(runCtx, job); failure != nil {
				s.recordAnalysisRunFailure(runCtx, job, failure)
			}
		},
		func(runCtx context.Context, recovered any) {
			s.recordAnalysisRunFailure(runCtx, job, &analysisRunFailure{
				public: "the investigation stopped on an internal error before it finished; run it again, and check the hub log if it repeats",
				err:    fmt.Errorf("panic: %v", recovered),
			})
		})

	resp := analysisStartedResponse{
		IncidentID: incidentID,
		State:      orchestrator.StateInvestigating,
		StartedAt:  formatRFC3339(claim.StartedAt),
		Backend:    claim.Backend,
		Model:      claim.Model,
	}
	writeJSON(w, http.StatusAccepted, resp)
}

// analysisJob is everything the background investigation needs from the
// request that started it, captured before the handler returns: the request
// context and its transaction are gone by the time most of it is used.
type analysisJob struct {
	inc        incidentSummary
	tenantID   string
	userID     string
	grants     []authz.EffectiveGrant
	sourceIP   string
	userPrompt string
	claim      analysisClaim
}

// runAnalysis is the investigation and everything that persists its result,
// run in the background by handleAnalyzeIncident after it has answered 202.
// ctx is the run's own context (launchAnalysisRun): detached from the
// request, bounded by the run budget, cancelled if the hub drains.
//
// It returns nil when the analysis was committed, or the failure — with the
// sentence an operator should read — for recordAnalysisRunFailure to put on
// the incident. Its own transaction is always rolled back or committed before
// it returns, so the failure recorder never waits on this run's row lock.
func (s *Server) runAnalysis(ctx context.Context, job analysisJob) *analysisRunFailure {
	inc := job.inc
	incidentID := inc.ID
	clusterID := inc.ClusterID

	workTx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return &analysisRunFailure{public: "could not start the investigation's database transaction", err: err}
	}
	// Rollback is the safety net for every early return below; it is a
	// documented no-op (pgx.ErrTxClosed, discarded) once Commit has already
	// succeeded further down. On a detached context, so a run whose own
	// deadline expired still releases its row lock promptly.
	defer func() {
		rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_ = workTx.Rollback(rbCtx)
	}()

	if err := data.SetRequestScope(ctx, workTx, job.tenantID, []string{clusterID}); err != nil {
		return &analysisRunFailure{public: "could not scope the investigation's database transaction", err: err}
	}

	// CallToolWithRetry, not plain CallTool: BACKLOG.md C5 / BUGS.md 96 — a
	// transient tunnel stall delayed an agent's correct, on-time answer past
	// the hub's 30s toolCallTimeout, and the caller (this exact loop)
	// discarded it and burned the whole investigation on nothing. Safe here
	// specifically because every tool this loop offers is read-only (see
	// gateway.CallToolWithRetry's own doc comment for the full reasoning).
	clusterCallTool := func(callCtx context.Context, tool string, args json.RawMessage) (json.RawMessage, error) {
		return s.gw.CallToolWithRetry(callCtx, clusterID, tool, args)
	}

	// lld/08-remediation-contracts.md §12: the route is computed by non-AI
	// code BEFORE the model proposes anything, and constrains which action
	// shapes the system prompt below even offers. job.grants are the real
	// grants of the human who triggered this analysis, so ExecutionAllowed's
	// capability half is a genuine check, not the autoanalyze default.
	routeDecision, err := ResolveIncidentRoute(ctx, workTx, s.gw, s.scmStore, incidentID, clusterID, job.grants)
	if err != nil {
		return &analysisRunFailure{public: "could not determine this incident's resolution route", err: err}
	}

	// BACKLOG.md F22 piece 1: the callback DISPATCHES rather than always
	// reaching for the tunnel — the two repository tools are served hub-side by
	// internal/repotools against a scope resolved here, before the model has
	// produced a single token; every other tool goes to the cluster agent
	// exactly as before. See internal/api/repo_tools.go for why the repository
	// is a hub-side read and why the scope cannot be influenced by model output.
	//
	// AFTER ResolveIncidentRoute, and that ordering is load-bearing:
	// IncidentRepoScope reads `incidents.ownership`, and ResolveIncidentRoute
	// is what resolves and caches that column (migration 000038). Resolving
	// the scope first meant an incident analysed for the FIRST time had no
	// ownership stored yet, so a genuinely Argo-managed object was silently
	// offered no repository tools.
	repoScope := IncidentRepoScope(ctx, workTx, s.scmStore, incidentID)
	var repoReader *repotools.Reader
	// readLog is BACKLOG.md F25's per-investigation truncation-provenance
	// record, consumed exactly once below by RefuseTruncatedRepositoryProposals.
	var readLog *repotools.ReadLog
	if repoScope.Valid() {
		// BACKLOG.md F28 finding 1: begin this investigation's ReadLog in the
		// SHARED registry so a call served by the cli backend (CallRepoTool, a
		// separate code path — see ReadLogRegistry's own doc comment) records
		// into the SAME log this function checks below. End is deferred right
		// next to Begin so every early return still cleans up.
		readLog = s.readLogs.Begin(incidentID)
		defer s.readLogs.End(incidentID)
		repoReader = repotools.NewReader(repoScope, s.checkouts).SetReadLog(readLog)
	}
	callTool := ChangesToolCallback(s.db, clusterID, RepoToolCallback(repoReader, clusterCallTool))

	// BACKLOG.md C4: resolved once, here, and used for both the tool surface
	// (Target.DryRunAvailable) and the system prompt's own description of
	// it — the two must agree, or the model would be told about a tool it
	// was not actually offered, or offered one it was never told about. The
	// same discipline covers query_metrics and F22's repository tools.
	dryRunAvailable := ClusterDryRunAvailable(ctx, workTx, clusterID)
	metricsAvailable := ClusterMetricsAvailable(ctx, workTx, clusterID)
	repoReadable := repoReader != nil
	// PROJECT.md T11: wrapped here, at the call site, where "did this
	// succeed" and "how long did it take" are both known.
	investigateStarted := time.Now()
	result, err := s.llmProvider.Investigate(ctx, llm.Target{ClusterID: clusterID, IncidentID: inc.ID, DryRunAvailable: dryRunAvailable, MetricsAvailable: metricsAvailable, RepoReadable: repoReadable}, llm.SystemPrompt(routeDecision.Route, dryRunAvailable, repoReadable, metricsAvailable), job.userPrompt, callTool)
	metrics.AnalysisDurationSeconds.Observe(time.Since(investigateStarted).Seconds(), "manual", AnalysisOutcomeLabel(err))
	if err != nil {
		// The reason, not just a headline: the provider's own error text is
		// the diagnostic value (an "argument list too long" or the router's
		// "no MCP listener" message is entirely actionable), and the incident
		// is now the only place the operator can read it — there is no
		// response body to carry it any more.
		if errors.Is(err, llm.ErrNotConfigured) {
			return &analysisRunFailure{public: "AI provider not usable: " + err.Error(), err: err}
		}
		return &analysisRunFailure{public: "could not complete the AI investigation: " + err.Error(), err: err}
	}

	// BACKLOG.md F25: refuse outright any OpenPR proposal built from a
	// partial read of the same investigation's own repository tools, before
	// route enforcement, correction, or persistence ever see it — see
	// RefuseTruncatedRepositoryProposals' own doc comment. A no-op whenever
	// readLog is nil (no repository scope for this incident at all).
	result = RefuseTruncatedRepositoryProposals(result, repoScope.SourceDir, readLog)

	// BACKLOG.md F28 finding 1: refuse outright any OpenPR proposal naming a
	// path this investigation never called read_repo_file for at all — see
	// RefuseUnreadRepositoryProposals' own doc comment.
	result = RefuseUnreadRepositoryProposals(result, repoScope.SourceDir, readLog)

	// BUGS.md 117: refuse an OpenPR plan that recreates a deleted resource as
	// a placeholder stub while removing, in the same plan, the only
	// reference to it — see RefuseOrphanedRecreatedResourceProposals' own
	// doc comment. A no-op whenever repoReader is nil.
	result = RefuseOrphanedRecreatedResourceProposals(ctx, result, repoReader, repoScope.SourceDir)

	// PROJECT.md B147: refuse outright any OpenPR proposal whose content
	// invents a top-level field its own declared kind's live OpenAPI schema
	// has never heard of — see RefuseSchemaInvalidRepositoryProposals' own
	// doc comment (it fails open when the cluster is unreachable, and says
	// why).
	result = RefuseSchemaInvalidRepositoryProposals(ctx, s.gw, clusterID, result)

	// §12.5's fail-closed check: a plan whose ActionType is outside
	// routeDecision.Route's permitted set is refused here, before Advance
	// ever sees it — the same shape isOfferedTool already enforces for
	// mid-loop tool calls. Ownership was already determined and cached by
	// ResolveIncidentRoute above, BEFORE this investigation ran.
	result = orchestrator.EnforceRoute(result, routeDecision.Route)

	// BACKLOG.md F27: after route enforcement has settled whether a plan
	// really does exist, record an honest note if this is a "complete"
	// analysis with no plan at all and no runnable suggestedNextSteps entry —
	// see FlagMissingRunnableNextStep's own doc comment.
	FlagMissingRunnableNextStep(ctx, workTx, job.tenantID, clusterID, incidentID, result)

	// BUGS.md 109 / BACKLOG.md AG1: a plan Blocked purely because the model
	// left Params nil/invalid gets exactly ONE bounded correction attempt
	// here, before this analysis is ever persisted or handed to
	// orchestrator.Advance. See analyze_correction.go for the full reasoning
	// and why this must live here rather than inside internal/orchestrator.
	// ActionType is unchanged by a Params-only correction, so EnforceRoute
	// above never needs to run a second time.
	var correctedPlan *remediation.RemediationPlan
	var correctionAttempt *analyzeTimeCorrectionAttempt
	correctedPlan, correctionAttempt = correctBlockedPlanParams(ctx, result.ProposedPlan, s.planCorrectorFunc())
	result.ProposedPlan = correctedPlan
	if correctionAttempt != nil {
		if err := timeline.Record(ctx, workTx, timeline.Event{
			TenantID: job.tenantID, ClusterID: clusterID, IncidentID: incidentID,
			Type: timeline.EventParamsCorrectionAttempted,
			Summary: fmt.Sprintf("Attempted to correct %s's proposed params: %s",
				result.ProposedPlan.ActionType, correctionAttempt.Outcome),
			Detail: map[string]any{
				"actionType":      string(result.ProposedPlan.ActionType),
				"reason":          correctionAttempt.Reason,
				"outcome":         correctionAttempt.Outcome,
				"succeeded":       correctionAttempt.Succeeded,
				"correctedParams": correctionAttempt.CorrectedParams,
			},
		}); err != nil {
			return &analysisRunFailure{public: "could not record the analysis", err: fmt.Errorf("record the params-correction timeline event: %w", err)}
		}
	}

	analysisID := domain.NewID(domain.PrefixAnalysis)
	createdAt := time.Now()
	costUSD, err := PersistAnalysis(ctx, workTx, job.tenantID, analysisID, incidentID, clusterID, result, createdAt, TriggeredByManual)
	if err != nil {
		return &analysisRunFailure{public: "could not record the analysis", err: fmt.Errorf("persist the analysis: %w", err)}
	}
	// PROJECT.md T11: costUSD here is exactly PersistAnalysis's own returned
	// figure, labeled with the SAME basis that function wrote to cost_basis,
	// so this metric can never disagree with the row it describes.
	metrics.AnalysisCostUSDTotal.Add(costUSD, "manual", costBasisOrDefault(result.CostBasis))

	// The one INFO line a SUCCESSFUL investigation writes (PROJECT.md T23).
	logger.InfoContext(ctx, "investigation complete",
		logging.IncidentID(incidentID), logging.ClusterID(clusterID),
		slog.String("analysis_id", analysisID),
		slog.String("model", result.Model),
		slog.String("status", result.Status),
		slog.Int("iterations", result.Iterations),
		slog.Int64("duration_ms", int64(result.DurationMs)),
		slog.Float64("cost_usd", costUSD),
		slog.String("cost_basis", costBasisOrDefault(result.CostBasis)))

	// The real state-machine wiring: run the investigation's result (and, if
	// it proposed one, its plan) through internal/remediation's gate, and
	// move the incident to whichever state internal/orchestrator's Advance
	// decided — never further than RecommendationReady/AwaitingApproval
	// (no Executing transition exists anywhere in this codebase).
	adv, err := orchestrator.ApplyAnalysisResult(ctx, workTx, job.tenantID, clusterID, incidentID, analysisID, result, routeDecision)
	if err != nil {
		return &analysisRunFailure{public: "could not apply the analysis result to the incident", err: fmt.Errorf("apply the analysis result: %w", err)}
	}

	// Record WHO decided to investigate this incident, and what it cost —
	// a deliberate human action behind its own capability
	// (CapIncidentReanalyse) that bypasses the daily spend ceiling by design.
	// An unattended analysis is NOT audited here: internal/autoanalyze has no
	// actor to name, and inventing one would be worse than the gap.
	//
	// Written inside workTx, so it commits with the analysis or not at all —
	// an audit row for an investigation that rolled back would be a lie, and
	// the hash chain makes it a durable one. A failure to audit does NOT fail
	// the run: the analysis has already run and been paid for, and discarding
	// it to preserve a log entry would be the more damaging outcome. It is
	// logged loudly instead, matching the sibling approval path.
	analyzeCapability := authz.CapIncidentReanalyse
	analyzeClusterRef := clusterID
	analyzeDetails := map[string]any{}
	// "gvk|namespace|name", the same shape incidents.object_key uses and the
	// shape the audit log's resource filter matches on. Built only when all
	// three parts are present.
	if inc.ObjectGVK != nil && inc.ObjectNamespace != nil && inc.ObjectName != nil {
		analyzeDetails["objectKey"] = *inc.ObjectGVK + "|" + *inc.ObjectNamespace + "|" + *inc.ObjectName
	}
	analyzeDetails["action"] = "analyze_incident"
	analyzeDetails["trigger"] = TriggeredByManual
	analyzeDetails["incidentId"] = incidentID
	analyzeDetails["analysisId"] = analysisID
	// Rounded to 6dp: the raw float64 renders as IEEE-754 representation
	// noise (`0.15612510000000002`), which is not precision the figure has.
	analyzeDetails["costUsd"] = math.Round(costUSD*1e6) / 1e6
	analyzeDetails["costBasis"] = costBasisOrDefault(result.CostBasis)
	analyzeDetails["analysisStatus"] = result.Status
	analyzeDetails["nextState"] = adv.NextState
	userID := job.userID
	if auditErr := audit.RecordEvent(ctx, workTx, audit.Event{
		TenantID: job.tenantID, ActorID: &userID, ActorAuthMethod: "jwt",
		SourceIP: job.sourceIP, Capability: &analyzeCapability, ClusterID: &analyzeClusterRef,
		Outcome: audit.OutcomeSuccess,
		Details: analyzeDetails,
	}); auditErr != nil {
		logger.ErrorContext(ctx, "writing the analyze_incident audit event failed; the analysis itself succeeded",
			logging.IncidentID(incidentID), logging.Err(auditErr))
	}

	if err := workTx.Commit(ctx); err != nil {
		return &analysisRunFailure{public: "could not record the analysis", err: fmt.Errorf("commit the investigation transaction: %w", err)}
	}

	// BACKLOG.md L2: embed this just-committed analysis in the background —
	// AFTER the real commit above, never blocking on an embedding call.
	// s.knowledge is nil-safe.
	s.knowledge.TriggerAsync(job.tenantID, clusterID, analysisID)

	// Published only after workTx's own real commit above.
	if s.events != nil {
		s.events.Publish(events.IncidentUpdated(incidentID, clusterID))
	}
	return nil
}

// investigationCommitMargin is added on top of the investigation's own
// configured time limit (internal/llm.DefaultTimeLimit, or
// cfg.AnalysisTimeLimitSeconds) when bounding the detached context
// handleAnalyzeIncident runs the investigation and its persistence under.
// Generous against what it has to cover: investigate() (internal/llm) only
// checks its own deadline BETWEEN model round-trips, so the round already
// under way when that deadline lands — one model completion plus however
// many tool calls it requested, each already capped at internal/gateway's
// own 30s toolCallTimeout — still has to be allowed to finish, followed by
// PersistAnalysis/ApplyAnalysisResult's own writes and this transaction's
// commit. This is a safety net, not itself the bound an operator
// configures; it is also how long a claimed run counts as in flight for the
// duplicate check (analysisRunInFlight).
const investigationCommitMargin = 3 * time.Minute

// remediationPlanToView builds a planView for a freshly-authored (already
// persisted, since PlanID is only ever non-empty after
// orchestrator.ApplyAnalysisResult wrote it) plan, marshaling Params through
// orchestrator.MarshalPlanParams — the same wire shape a
// remediation_recommendations row already carries in its own params
// column, so handleAnalyzeIncident's response and handleListApprovals'
// (approvals.go) never describe the same kind of object two different ways.
func remediationPlanToView(planID string, plan remediation.RemediationPlan, decision remediation.Decision, createdAt time.Time) *planView {
	paramsJSON, err := orchestrator.MarshalPlanParams(plan)
	if err != nil {
		// Params failing to marshal at all would be a real bug in this
		// package's own type switch, not a caller-triggerable condition —
		// logged, not surfaced as a request failure this deep into an
		// otherwise-successful analyze call whose analyses row is already
		// committed-pending.
		logger.Error("marshalling plan params for the response view failed; rendering an empty params object",
			slog.String("plan_id", planID), logging.Err(err))
		paramsJSON = json.RawMessage(`{}`)
	}
	view := buildPlanView(planID, string(plan.ActionType), plan.TargetGVK, plan.TargetNamespace, plan.TargetName,
		paramsJSON, plan.Reversible, string(plan.RiskLevel), string(decision.Outcome), decision.Reason, formatRFC3339(createdAt))
	return &view
}

// promptVersion is persisted on every analyses row this handler writes —
// 'v2-tool-loop', not the old one-shot 'v1-one-shot', per
// lld/07-analysis-contracts.md §3's versioning note: a future regression can
// be attributed to the right version rather than "the model got worse."
const promptVersion = "v2-tool-loop"

// TriggeredByManual/TriggeredByAuto are the two values PersistAnalysis's
// triggeredBy parameter accepts, persisted into analyses.triggered_by
// (migration 000074, BACKLOG.md C6). Exported, same reason CostBasisMetered/
// CostBasisSubscription/CostBasisUnknown (internal/llm) are: the two writers
// of an analyses row — this file's handleAnalyzeIncident and
// internal/autoanalyze.Poller — live in different packages, and a shared
// named constant is what keeps them from drifting onto different string
// literals for the same meaning. There is no "unknown" third value here the
// way cost_basis has one: both call sites always know which one they are.
const (
	TriggeredByManual = "manual"
	TriggeredByAuto   = "auto"
)

// rootCauseStored is what this handler marshals into the `analyses.root_cause`
// jsonb column — reusing that single existing nullable column for BOTH a
// complete result's statement AND a partial result's partialReason/
// suggestedNextSteps, tagged by its own `status` field, rather than adding
// new columns. Chosen over adding columns because every other piece of a
// complete-vs-partial analysis already has its own dedicated column
// (causal_chain, ruled_out, confidence, iterations) — root_cause was the
// ONE column already shaped to hold "this analysis's own concluding
// statement, or lack thereof," so folding partialReason/suggestedNextSteps
// in alongside it needs no migration and keeps every status-specific field
// in exactly one place a reader has to check. getLatestAnalysis (below) is
// the sole place that un-marshals this shape back out — no other code
// reads analyses.root_cause directly.
type rootCauseStored struct {
	Status             string   `json:"status"`
	Statement          string   `json:"statement,omitempty"`
	PartialReason      string   `json:"partialReason,omitempty"`
	SuggestedNextSteps []string `json:"suggestedNextSteps,omitempty"`
	// CausalChainProvenance folds analysisResponse.CausalChainProvenance
	// (BACKLOG.md C10) into this same reused-rather-than-migrated column, for
	// the identical reason SuggestedNextSteps lives here: every other
	// dedicated causal_chain/ruled_out/confidence/iterations column already
	// has its own home, and this is the one column already shaped to carry
	// "something new about this analysis, tagged by status" with no
	// migration. Set on both the "complete" and "partial" branches below —
	// provenance describes HOW the chain was produced, not whether the
	// investigation concluded.
	CausalChainProvenance string `json:"causalChainProvenance,omitempty"`
	// IsFault (PROJECT.md T4 gap 3) persists llm.RootCause.IsFault, which
	// used to be consumed once by orchestrator.Advance and then discarded —
	// absent from this column, from rootCauseOut and from
	// web/src/api/types.ts, so nothing downstream of the very first
	// Advance() call could ever tell "the model said this is not a fault"
	// apart from any other Diagnosed/NeedsHumanInvestigation incident.
	// Omitted (not `false`) both for a nil verdict (the model was never
	// asked) and for every row written before this field existed — both
	// read back as "unknown", never as a false "confirmed a real fault".
	IsFault *bool `json:"isFault,omitempty"`
}

// PersistAnalysis writes one internal/llm.Investigation result into the
// existing `analyses` table's columns — causal_chain/ruled_out now get the
// real, evidence-linked JSON arrays the tool loop actually gathered (not the
// old one-shot path's hardcoded '[]'), confidence is NULL on a partial
// result (never a fabricated number), and root_cause carries the
// rootCauseStored shape documented above.
//
// tokens_billed_in/tokens_cache_read/tokens_out are the real sums
// internal/llm.Investigation accumulated across every model round-trip the
// investigation made (not just the concluding one) — this used to be the
// gap this comment is now closing: tokens_cache_read was hardcoded to the
// literal 0 here regardless of what the model actually reported, and
// tokens_billed_in/tokens_out (already summed correctly inside toolloop.go's
// investigate()) had nowhere to report a cache-read figure alongside them.
//
// cost_usd used to be a literal 0 always, and that was an honest value, not
// a placeholder standing in for a real one: this codebase had no per-model
// USD pricing table anywhere. It now computes a REAL cost via
// internal/settings.Config.ComputeCostUSD (resolved fresh here, same as
// every other DB-backed, live-editable setting in this codebase) whenever
// an operator has configured one (GET/PUT /api/v1/admin/settings' "cost"
// section) — still a literal, honest 0 when they haven't, never a guessed
// or hardcoded per-model rate. See migration 000029_cost_settings and
// internal/settings.Config's own doc comment for the full rationale,
// including why the three price fields are validated as an all-or-nothing
// set rather than independently optional.
//
// Exported so a caller with an open pgx.Tx and tenantID — but no
// *requestContext — can call it directly: internal/autoanalyze's poller
// (its own transaction per incident, not a per-HTTP-request one) always
// has, and handleAnalyzeIncident above now does too (BUGS.md 89 — it used
// to go through a thin *requestContext-shaped wrapper around this same
// function, removed once the handler needed to persist through its own
// detached transaction instead of rc.Tx). Both call sites write the EXACT
// same row shape a manual POST /incidents/{id}/analyze and an unattended
// analysis produce, so the two paths can never silently drift apart on it.
//
// Returns the computed cost_usd (0 when pricing isn't configured) so
// callers that build a caller-facing response (handleAnalyzeIncident) can
// echo the exact number just persisted, rather than recomputing it a second
// time from a second settings.Resolve call.
//
// triggeredBy is one of TriggeredByManual/TriggeredByAuto (BACKLOG.md C6,
// migration 000074) — the caller states which it is rather than this
// function inferring it, since inference here would have to guess from
// context this function doesn't have (a *requestContext vs. a bare actor-less
// transaction is not, by itself, proof of who initiated the call).
func PersistAnalysis(ctx context.Context, tx pgx.Tx, tenantID, analysisID, incidentID, clusterID string, result llm.Investigation, createdAt time.Time, triggeredBy string) (float64, error) {
	causalChain := result.CausalChain
	if causalChain == nil {
		causalChain = []llm.CausalStep{}
	}
	ruledOut := result.RuledOut
	if ruledOut == nil {
		ruledOut = []llm.RuledOutHypothesis{}
	}
	causalChainJSON, err := json.Marshal(causalChain)
	if err != nil {
		return 0, fmt.Errorf("marshal causal chain: %w", err)
	}
	ruledOutJSON, err := json.Marshal(ruledOut)
	if err != nil {
		return 0, fmt.Errorf("marshal ruled out: %w", err)
	}

	var stored rootCauseStored
	var confidence *float64
	if result.Status == "complete" {
		stored = rootCauseStored{Status: "complete"}
		if result.RootCause != nil {
			stored.Statement = result.RootCause.Statement
			// PROJECT.md T4 gap 3: persist the verdict itself, not just the
			// statement it came with — see rootCauseStored.IsFault's own
			// doc comment.
			stored.IsFault = result.RootCause.IsFault
		}
		// lld/08 §12.7: a guidance route's "complete" result carries its own
		// SuggestedNextSteps too (BUGS.md 107) — persist it alongside the
		// statement so getLatestAnalysis's read-back has it, not just the
		// live POST /analyze response toAnalysisResponse builds in the same
		// request.
		stored.SuggestedNextSteps = result.SuggestedNextSteps
		confidence = result.Confidence
	} else {
		stored = rootCauseStored{
			Status:             "partial",
			PartialReason:      result.PartialReason,
			SuggestedNextSteps: result.SuggestedNextSteps,
		}
		confidence = nil
	}
	// BACKLOG.md C10: persisted on both branches — see rootCauseStored's own
	// comment on why provenance is orthogonal to complete/partial status.
	stored.CausalChainProvenance = result.CausalChainProvenance
	rootCauseJSON, err := json.Marshal(stored)
	if err != nil {
		return 0, fmt.Errorf("marshal root cause: %w", err)
	}

	cfg, err := settings.Resolve(ctx, tx)
	if err != nil {
		return 0, fmt.Errorf("resolve cost pricing settings: %w", err)
	}

	// Two cost paths, and which one applies is decided by the backend that
	// produced this result, not guessed at here
	// (lld/07-analysis-contracts.md §10.5):
	//
	//   - Empty CostBasis: the api backend. Unchanged behaviour — derive cost
	//     from this run's token counts against configured pricing, and record
	//     it as 'metered', which is what it has always truthfully been.
	//   - Non-empty: the cli backend already knows, because its runner
	//     reported it. Take both the figure and the basis as given rather
	//     than recomputing from tokens, since a CLI's own accounting is the
	//     authority for its own run and token-derived pricing would not apply
	//     to a subscription-billed one at all.
	//
	// Under 'subscription' the stored cost_usd of 0 means *unavailable*, and
	// cost_basis is the column that says so — nothing downstream may render
	// it as $0.00 (see internal/api/insights.go and the Overview cost tile).
	costBasis := result.CostBasis
	costUSD := result.CostUSD
	if costBasis == "" {
		costBasis = llm.CostBasisMetered
		costUSD = cfg.ComputeCostUSD(result.TokensIn, result.TokensCacheRead, result.TokensOut)
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO analyses (
		   id, incident_id, tenant_id, cluster_id, prompt_version, model, causal_chain, ruled_out,
		   root_cause, confidence, iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd, cost_basis, created_at,
		   raw_final_answer, parse_error, triggered_by, request_id, evidence_coverage
		 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)`,
		analysisID, incidentID, tenantID, clusterID, promptVersion, result.Model, causalChainJSON, ruledOutJSON,
		rootCauseJSON, confidence, result.Iterations, result.DurationMs,
		result.TokensIn, result.TokensCacheRead, result.TokensOut, costUSD, costBasis, createdAt,
		// BACKLOG C2. Both NULL on the ordinary path — migration 000054's CHECK
		// requires them to be null or non-null together, which is why they go
		// through one helper rather than two independent nullIfEmpty calls that
		// could drift apart.
		nullIfEmpty(result.RawFinalAnswer), nullIfEmpty(result.ParseError), triggeredBy,
		// PROJECT.md T23, migration 000117. Read off the CONTEXT rather than
		// taken as a parameter, deliberately: both callers (the manual
		// POST /incidents/{id}/analyze handler and internal/autoanalyze's
		// poller) already run under a context carrying the correlation id
		// for their unit of work, so there is no second place for the two
		// routes to disagree about what the id is, and no parameter a third
		// caller can forget to pass. NULL when there is none, which is what
		// a call from a test or a future path with no unit of work of its
		// own honestly is.
		nullIfEmpty(logging.RequestIDFrom(ctx)), coverageJSON(result.EvidenceCoverage))
	if err != nil {
		return 0, err
	}

	// BACKLOG.md B2: one `evidence` row per tool call this analysis's causal
	// chain actually carries an EvidenceID for (llm.ToolCallRecord's own doc
	// comment on why that's every dispatched call and no refused one). Same
	// transaction as the analyses insert just above — an evidence row and the
	// analysis it belongs to either both exist or neither does, rather than a
	// second, independently-committed write that could leave one without the
	// other after a crash between the two.
	if err := persistEvidence(ctx, tx, tenantID, clusterID, incidentID, analysisID, causalChain); err != nil {
		return 0, fmt.Errorf("persist evidence: %w", err)
	}

	return costUSD, nil
}

// toAnalysisResponse builds the pinned API response shape from a freshly
// completed Investigation, the timestamp it was persisted under, and the
// real cost_usd PersistAnalysis just computed and wrote for this exact row
// (0 when pricing isn't configured — see that function's own doc comment).
// costBasisOrDefault normalizes an empty/NULL basis to "metered". Empty means
// the row predates migration 000033's column, and every such row was written by
// the api backend, whose cost genuinely was measured — so "metered" is the
// truthful reading, not a guess. Anything else is passed through verbatim so the
// UI can distinguish subscription from unknown.
// AnalysisOutcomeLabel maps an Investigate() call's own error to
// metrics.AnalysisDurationSeconds' closed "outcome" label. Exported so
// internal/autoanalyze's identical call site (autoanalyze.go) uses the
// exact same two-value mapping rather than a second, independently
// maintained one.
func AnalysisOutcomeLabel(err error) string {
	if err != nil {
		return "error"
	}
	return "success"
}

func costBasisOrDefault(basis string) string {
	if basis == "" {
		return llm.CostBasisMetered
	}
	return basis
}

func toAnalysisResponse(result llm.Investigation, createdAt time.Time, costUSD float64) analysisResponse {
	resp := analysisResponse{
		Model:                 result.Model,
		Status:                result.Status,
		CausalChain:           nonNilSteps(result.CausalChain),
		CausalChainProvenance: result.CausalChainProvenance,
		RuledOut:              nonNilRuledOut(result.RuledOut),
		Iterations:            result.Iterations,
		CreatedAt:             formatRFC3339(createdAt),
		TokensBilledIn:        int64(result.TokensIn),
		TokensCacheRead:       int64(result.TokensCacheRead),
		TokensOut:             int64(result.TokensOut),
		CostUSD:               costUSD,
		CostBasis:             costBasisOrDefault(result.CostBasis),
	}
	if result.Status == "complete" {
		if result.RootCause != nil {
			resp.RootCause = &rootCauseOut{Statement: result.RootCause.Statement, IsFault: result.RootCause.IsFault}
		}
		resp.Confidence = result.Confidence
		// lld/08 §12.7: a guidance route's "complete" result carries
		// suggestedNextSteps too, now — see Investigation.SuggestedNextSteps's
		// own doc comment for why this is new for a non-partial result.
		resp.SuggestedNextSteps = result.SuggestedNextSteps
	} else {
		reason := result.PartialReason
		resp.PartialReason = &reason
		resp.SuggestedNextSteps = result.SuggestedNextSteps
	}
	return resp
}

func nonNilSteps(s []llm.CausalStep) []llm.CausalStep {
	if s == nil {
		return []llm.CausalStep{}
	}
	return s
}

func nonNilRuledOut(s []llm.RuledOutHypothesis) []llm.RuledOutHypothesis {
	if s == nil {
		return []llm.RuledOutHypothesis{}
	}
	return s
}

// getLatestAnalysis returns the most recent analysis for an incident, or nil
// if none exists yet — used by handleGetIncident to embed it, now returning
// the full analysisResponse shape (causal chain, ruled-out list, confidence,
// partial-analysis fields) rather than the old one-shot
// model/statement/createdAt triple.
func getLatestAnalysis(ctx context.Context, rc *requestContext, incidentID string) (*analysisResponse, error) {
	var analysisID, model string
	var causalChainJSON, ruledOutJSON, rootCauseJSON []byte
	var confidence *float64
	var iterations int
	var createdAt time.Time
	var tokensBilledIn, tokensCacheRead, tokensOut int64
	var costUSD float64
	var costBasis *string
	var rawFinalAnswer, parseError *string
	var triggeredBy *string
	var coverageRaw []byte
	err := rc.Tx.QueryRow(ctx,
		`SELECT id, model, causal_chain, ruled_out, root_cause, confidence, iterations, created_at,
		        tokens_billed_in, tokens_cache_read, tokens_out, cost_usd, cost_basis,
		        raw_final_answer, parse_error, triggered_by, evidence_coverage
		   FROM analyses
		  WHERE incident_id = $1 ORDER BY created_at DESC LIMIT 1`, incidentID,
	).Scan(&analysisID, &model, &causalChainJSON, &ruledOutJSON, &rootCauseJSON, &confidence, &iterations, &createdAt,
		&tokensBilledIn, &tokensCacheRead, &tokensOut, &costUSD, &costBasis, &rawFinalAnswer, &parseError, &triggeredBy, &coverageRaw)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	// The plan(s) this analysis proposed, if any — joined by analysis_id.
	// ApplyAnalysisResult persists at most TWO remediation_recommendations
	// rows per analysis (one-to-one, except a paired `pullRequest+inPlace`
	// route, which is one-to-two, linked by sibling_of_recommendation_id —
	// see recommendationIDsForAnalysis). Deliberately NOT accompanied by
	// IncidentState/StateReason here — those two fields describe "what
	// happened right when this analysis was applied," which this read-back
	// path has no honest way to keep re-deriving (the incident may have
	// since been approved/rejected/re-analyzed); the incident's own
	// top-level `state` field in handleGetIncident's response is the
	// current source of truth for that. Plan/PairedPlan don't have the same
	// staleness problem: they're immutable historical facts about what THIS
	// analysis proposed.
	plan, pairedPlan, err := latestPlanViewForAnalysis(ctx, rc.Tx, analysisID)
	if err != nil {
		return nil, fmt.Errorf("look up plan for analysis %s: %w", analysisID, err)
	}

	var causalChain []llm.CausalStep
	if err := json.Unmarshal(causalChainJSON, &causalChain); err != nil {
		return nil, fmt.Errorf("unmarshal causal_chain: %w", err)
	}
	var ruledOut []llm.RuledOutHypothesis
	if err := json.Unmarshal(ruledOutJSON, &ruledOut); err != nil {
		return nil, fmt.Errorf("unmarshal ruled_out: %w", err)
	}

	resp := &analysisResponse{
		ID:               analysisID,
		Model:            model,
		CausalChain:      nonNilSteps(causalChain),
		RuledOut:         nonNilRuledOut(ruledOut),
		Iterations:       iterations,
		CreatedAt:        formatRFC3339(createdAt),
		TokensBilledIn:   tokensBilledIn,
		TokensCacheRead:  tokensCacheRead,
		TokensOut:        tokensOut,
		CostUSD:          costUSD,
		CostBasis:        costBasisOrDefault(deref(costBasis)),
		TriggeredBy:      deref(triggeredBy),
		Plan:             plan,
		PairedPlan:       pairedPlan,
		RawFinalAnswer:   deref(rawFinalAnswer),
		ParseError:       deref(parseError),
		EvidenceCoverage: decodeCoverage(coverageRaw),
	}

	if len(rootCauseJSON) == 0 {
		// A row written before this task landed (root_cause was a plain
		// {"statement": "..."} with no status tag) — treat it as a
		// completed v1 analysis rather than erroring; its own
		// prompt_version column ('v1-one-shot') already distinguishes it
		// for anyone auditing why. This branch only matters for a hub
		// whose analyses table has pre-existing rows from before this
		// task; a fresh install never hits it.
		resp.Status = "complete"
		return resp, nil
	}
	var stored rootCauseStored
	if err := json.Unmarshal(rootCauseJSON, &stored); err != nil {
		return nil, fmt.Errorf("unmarshal root_cause: %w", err)
	}
	// BACKLOG.md C10: independent of complete/partial status — see
	// rootCauseStored's own comment.
	resp.CausalChainProvenance = stored.CausalChainProvenance

	if stored.Status == "partial" {
		resp.Status = "partial"
		reason := stored.PartialReason
		resp.PartialReason = &reason
		resp.SuggestedNextSteps = stored.SuggestedNextSteps
	} else {
		resp.Status = "complete"
		resp.RootCause = &rootCauseOut{Statement: stored.Statement, IsFault: stored.IsFault}
		resp.Confidence = confidence
		// BUGS.md 107: a guidance route's "complete" result carries its own
		// SuggestedNextSteps too (lld/08 §12.7) — read it back the same way
		// the "partial" branch above already does for its own field.
		resp.SuggestedNextSteps = stored.SuggestedNextSteps
	}
	return resp, nil
}

// deref is the nullable-text-column reader every scan in this package shares:
// a NULL column becomes "". Single helper by consolidation — derefString here
// and derefOrEmpty in routing.go were byte-identical copies of this and were
// folded into it.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// recommendationIDsForAnalysis resolves the primary and (if this analysis
// produced a paired `pullRequest+inPlace` route) secondary
// remediation_recommendations ids tied to one analysis — via
// sibling_of_recommendation_id, deliberately NOT `ORDER BY created_at ...
// LIMIT 1`. Both of a pair's rows are written in the SAME transaction
// (orchestrator.ApplyAnalysisResult) against a column whose default is
// `now()`, which Postgres fixes at the transaction's start rather than
// advancing per-statement — so they carry an IDENTICAL created_at, and a
// LIMIT-1-by-created_at query picks between them non-deterministically
// (exactly the bug BACKLOG D8's B1 found and fixed the same way for
// timeline_events, before anything read remediation_recommendations two-rows-
// deep enough to expose the identical problem here). The foreign key itself
// has no such ambiguity: exactly one row per analysis has a nil
// sibling_of_recommendation_id (the primary), and at most one other row
// points at it (the paired one).
func recommendationIDsForAnalysis(ctx context.Context, tx pgx.Tx, analysisID string) (primaryID, pairedID string, err error) {
	rows, err := tx.Query(ctx,
		`SELECT id, sibling_of_recommendation_id FROM remediation_recommendations WHERE analysis_id = $1`, analysisID)
	if err != nil {
		return "", "", err
	}
	defer rows.Close()

	type row struct {
		id        string
		siblingOf *string
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.siblingOf); err != nil {
			return "", "", err
		}
		all = append(all, r)
	}
	if err := rows.Err(); err != nil {
		return "", "", err
	}

	for _, r := range all {
		if r.siblingOf == nil {
			primaryID = r.id
			break
		}
	}
	if primaryID == "" {
		// No un-sibling'd row at all — either no recommendation exists for
		// this analysis (the common case: most investigations propose no
		// plan) or, if all() is non-empty, a row shape this function's own
		// invariant says should be unreachable (persistRecommendation never
		// writes a paired row without writing its primary first, in the
		// same transaction). Either way there is nothing to call primary.
		return "", "", nil
	}
	for _, r := range all {
		if r.siblingOf != nil && *r.siblingOf == primaryID {
			pairedID = r.id
			break
		}
	}
	return primaryID, pairedID, nil
}

// latestPlanViewForAnalysis looks up the remediation_recommendations row(s)
// tied to one specific analysis and builds their planViews — primary first,
// then the paired route's second recommendation if this analysis produced
// one (see recommendationIDsForAnalysis). Named "latest" from before F17's
// paired routes existed; kept rather than renamed everywhere, since it is
// still exactly what it says for the overwhelming majority of analyses that
// propose at most one plan.
func latestPlanViewForAnalysis(ctx context.Context, tx pgx.Tx, analysisID string) (plan *planView, pairedPlan *planView, err error) {
	primaryID, pairedID, err := recommendationIDsForAnalysis(ctx, tx, analysisID)
	if err != nil {
		return nil, nil, err
	}
	if primaryID == "" {
		return nil, nil, nil
	}
	plan, err = planViewByID(ctx, tx, primaryID)
	if err != nil {
		return nil, nil, err
	}
	if pairedID != "" {
		pairedPlan, err = planViewByID(ctx, tx, pairedID)
		if err != nil {
			return nil, nil, err
		}
	}
	return plan, pairedPlan, nil
}

// planViewByID reads one remediation_recommendations row by its own id and
// builds its planView, including the Approval/Execution facts recorded
// against THAT id — shared scan/view-building logic behind buildPlanView,
// same as remediationPlanToView above, just reading an already-persisted row
// instead of an in-memory plan.
func planViewByID(ctx context.Context, tx pgx.Tx, id string) (*planView, error) {
	var actionType, targetGVK, targetName, riskLevel, gateOutcome, gateReason string
	var targetNamespace *string
	var paramsJSON []byte
	var reversible bool
	var createdAt time.Time
	err := tx.QueryRow(ctx,
		`SELECT action_type, target_gvk, target_namespace, target_name, params, reversible, risk_level,
		        gate_outcome, gate_reason, created_at
		   FROM remediation_recommendations
		  WHERE id = $1`, id,
	).Scan(&actionType, &targetGVK, &targetNamespace, &targetName, &paramsJSON, &reversible, &riskLevel,
		&gateOutcome, &gateReason, &createdAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	view := buildPlanView(id, actionType, targetGVK, deref(targetNamespace), targetName, paramsJSON, reversible,
		riskLevel, gateOutcome, gateReason, formatRFC3339(createdAt))

	approval, err := latestApprovalDecisionView(ctx, tx, id)
	if err != nil {
		return nil, fmt.Errorf("look up approval decision for plan %s: %w", id, err)
	}
	view.Approval = approval

	execution, err := latestExecutionView(ctx, tx, id)
	if err != nil {
		return nil, fmt.Errorf("look up execution outcome for plan %s: %w", id, err)
	}
	view.Execution = execution

	return &view, nil
}

// ownershipLookupTimeout bounds the post-investigation ownership call. Generous
// against what the work costs — resolving an owner chain and reading one
// controller object is a handful of API reads, well under a second on a live
// cluster — and short enough that a wedged agent delays an analysis response by
// seconds rather than by the gateway's full per-call allowance.
const ownershipLookupTimeout = 15 * time.Second

// cacheIncidentOwnership asks the cluster who manages this incident's object
// and stores the answer on the incident row.
//
// The tuple to ask about comes from ownershipQueryTarget (repository_change.go)
// — incidents.workload_key when available, else incidents.object_key
// (migration 000036) — preferring workload_key because object_key is almost
// always a Pod, and a Pod can be gone by the time this runs.
//
// Every failure path is silent-and-continue, deliberately: an unparseable key,
// a disconnected agent, a tool error, a failed UPDATE. All of them leave
// ownership NULL, and NULL is the honest "not determined" that renders nothing.
// The alternative — surfacing an error from here — would fail a completed,
// already-paid-for investigation over a caveat.
func (s *Server) cacheIncidentOwnership(ctx context.Context, rc *requestContext, incidentID, clusterID string) {
	gvk, namespace, name, sourceKey, err := ownershipQueryTarget(ctx, rc.Tx, incidentID)
	if err != nil {
		logger.ErrorContext(ctx, "caching ownership: reading object_key failed",
			logging.IncidentID(incidentID), logging.Err(err))
		return
	}
	if sourceKey == "" {
		// A finding that named no object — nothing to ask about.
		return
	}

	args, err := json.Marshal(map[string]string{"gvk": gvk, "namespace": namespace, "name": name})
	if err != nil {
		logger.ErrorContext(ctx, "caching ownership: building the tool arguments failed",
			logging.IncidentID(incidentID), logging.Err(err))
		return
	}
	// A deadline of its own, detached from the request's. This call happens after
	// a whole investigation has run — 90 seconds and more is ordinary — and it
	// used to inherit whatever was left of the request context. On the first real
	// end-to-end GitOps run that inheritance is exactly what failed: the model's
	// own root cause named the Argo CD Application, the repository and the
	// revision, and this call still came back "context deadline exceeded", so
	// nothing was stored and the pull-request path had no repository to work
	// from.
	//
	// WithoutCancel keeps the context's values (the gateway reads none, but a
	// future middleware might) while dropping an expiry that has nothing to do
	// with how long asking a cluster who owns an object should take. Bounded
	// separately, because "detached" must not mean "unbounded".
	callCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ownershipLookupTimeout)
	defer cancel()
	raw, err := s.gw.CallTool(callCtx, clusterID, "get_gitops_ownership", args)
	if err != nil {
		logger.WarnContext(ctx, "caching ownership: the get_gitops_ownership tool call failed",
			logging.IncidentID(incidentID), slog.String("source_key", sourceKey), logging.Err(err))
		return
	}
	if _, err := rc.Tx.Exec(ctx, `UPDATE incidents SET ownership = $2 WHERE id = $1`, incidentID, raw); err != nil {
		logger.ErrorContext(ctx, "caching ownership: storing the result failed",
			logging.IncidentID(incidentID), logging.Err(err))
	}
}

// nullIfEmpty keeps empty strings out of nullable text columns, so "not answered"
// and "answered with nothing" do not become the same row.
//
// Moved here from internal/api/feedback.go when the incident-feedback feature was
// removed (WISHLIST.md W1) — analyze.go was its other caller.
//
// Also the "" -> SQL NULL conversion the execution-attempt inserts need: an
// empty string there would satisfy migration 000047's XOR check while meaning
// nothing. (internal/execution carried a byte-identical copy called
// nullString for exactly that; the two were folded into this one.)
func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// coverageJSON stores an investigation's evidence coverage, or NULL when it
// is unknown.
func coverageJSON(c *llm.EvidenceCoverage) any {
	if c == nil {
		return nil
	}
	b, err := json.Marshal(c)
	if err != nil {
		return nil
	}
	return b
}

func decodeCoverage(raw []byte) *llm.EvidenceCoverage {
	if len(raw) == 0 {
		return nil
	}
	var c llm.EvidenceCoverage
	if json.Unmarshal(raw, &c) != nil {
		return nil
	}
	return &c
}
