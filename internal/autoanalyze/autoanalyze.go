// Package autoanalyze is the "no one has to click Analyze" half of this
// task: an independent background poller, the same architectural shape as
// internal/notify.WebhookNotifier (own transaction(s), own ticker, resolves
// internal/settings.Config fresh every tick, no restart required for a
// setting change to take effect) that runs the exact same investigation
// POST /api/v1/incidents/{id}/analyze already runs on a manual click
// (internal/api.PersistAnalysis, internal/llm.Provider.Investigate)
// automatically against incidents an operator has opted into via
// PUT /api/v1/admin/settings' "automation" section
// (internal/settings.Config's AutoAnalysisEnabled/AutoAnalysisSeverities).
//
// Why a new package rather than folding into an existing one:
//
//   - internal/notify already has exactly this poller SHAPE, but none of
//     this poller's DEPENDENCIES (internal/llm.Provider, internal/gateway's
//     CallTool/IsConnected) — growing it to hold those would make a
//     package whose whole point is "post one webhook" also respond to LLM
//     settings and hold a gateway reference, for a second, unrelated
//     responsibility.
//   - internal/gateway is the tunnel/connection-registry layer itself, one
//     level below "decide whether an incident should be investigated and
//     drive that decision" — folding this poller's settings-resolution and
//     investigation-triggering logic into it would blur that boundary.
//   - internal/api already holds the manual trigger (handleAnalyzeIncident)
//     but is the HTTP-handler layer; a background poller has no request to
//     handle and isn't reached through routing.go, so it doesn't belong
//     there either — though this package DOES import internal/api for the
//     one function (PersistAnalysis) that must stay byte-for-byte identical
//     between the manual and automatic paths (see PersistAnalysis's own doc
//     comment for why duplicating that logic here would be worse).
//
// So: a new, standalone package, mirroring internal/notify's own "small,
// independent poller" shape exactly, just with the dependency set this
// specific job actually needs (internal/data, internal/settings,
// internal/llm, internal/gateway, internal/api).
//
// # Retry policy
//
// This used to read: "each incident is automatically attempted at MOST ONCE,
// ever — regardless of whether that one attempt succeeded, came back as a
// partial result, or failed outright (including 'no AI provider configured at
// all')", on the reasoning that a person can always run the manual endpoint
// afterward and that hot-looping on a structurally-broken incident is worse.
//
// The second half of that reasoning is right and is kept. The first half was
// wrong in a way that was observed live, and the shape of the failure is worth
// stating because it is not obvious from either end on its own:
// investigateOne moved the incident to Investigating, the investigation
// failed, the incident was LEFT in Investigating (deliberately — a failed
// attempt is a fact worth keeping), and auto_analysis_attempted_at was
// stamped anyway. But the candidate query EXCLUDES Investigating. So the
// incident was never retried, never re-selected, and never moved again by
// anything: permanently displaying the sentence "an investigation is running
// now, gathering live evidence from the cluster" for an investigation that had
// already failed, with the reason recorded nowhere but a log line. A failed
// provider call became indistinguishable from an analysis that is simply
// taking a long time.
//
// What happens now, by outcome:
//
//   - Succeeded (or concluded partially, or resolved-as-gone): marked
//     attempted, exactly as before. auto_analysis_attempted_at keeps its
//     original meaning — "the automatic path is DONE with this incident."
//   - Failed, transiently: the incident is returned to Detected (nothing is
//     running, and no analysis exists — that is what Detected means), the
//     attempt and its error are persisted (auto_analysis_attempts,
//     auto_analysis_last_error) AND recorded on the incident's own timeline,
//     and a backoff is set (auto_analysis_retry_after). It is retried up to
//     maxAutoAnalysisAttempts times, then marked attempted with the reason
//     kept.
//   - Failed because no AI provider is usable at all: the incident is returned
//     to Detected and the error is persisted, but this does NOT spend the
//     incident's retry budget — a hub-level misconfiguration is not this
//     incident's fault. The POLLER backs off instead (providerBackoff), so a
//     misconfigured hub does not hot-loop, does not silently consume the whole
//     backlog one incident at a time, and resumes on its own the moment a
//     provider is configured.
//
// A disconnected cluster is handled differently again (see selectEligible's
// doc comment): it's skipped before any work happens, NOT counted as an
// attempt, so it's retried on a later tick once the cluster reconnects.
package autoanalyze

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/agent/health"
	"argus/internal/api"
	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/events"
	"argus/internal/gateway"
	"argus/internal/knowledge"
	"argus/internal/llm"
	"argus/internal/logging"
	"argus/internal/metrics"
	"argus/internal/orchestrator"
	"argus/internal/repotools"
	"argus/internal/scm"
	"argus/internal/settings"
	"argus/internal/timeline"
)

// DefaultPollInterval mirrors notify.DefaultNotifyCheckInterval's naming and
// reasoning: how often Run sweeps for newly-eligible incidents. Shorter than
// notify's 30s (this feature's whole point is investigating "soon" without
// a human in the loop, and each tick is cheap — one read-only query — when
// nothing is eligible) but still "soon, not instant": a real investigation
// can itself take many seconds to minutes (internal/llm's bounded tool-
// calling loop), so polling faster than that wouldn't shorten anything real,
// just add empty ticks.
const DefaultPollInterval = 15 * time.Second

// candidateBatchSize caps how many not-yet-attempted, not-yet-analyzed
// incidents one sweep considers — same small-batch rationale as
// notify.notifyBatchSize: this is a poller, not a firehose, and severity/
// connectivity filtering happens in Go afterward (selectEligible), so this
// cap bounds one sweep's own work, not the count of incidents that actually
// get investigated (investigating one incident, via a real bounded LLM
// loop, is the actually expensive part — see investigateOne).
const candidateBatchSize = 50

// Poller drives the sweep. Held dependencies mirror exactly what
// internal/api/analyze.go's handleAnalyzeIncident already uses to run one
// manual analysis — this is intentional, not incidental: this package
// exists to run that same operation on a timer instead of a click.
type Poller struct {
	// staleChecks remembers when the stale sweep last checked each incident,
	// so one pass's bounded checks rotate through the backlog (cleared.go).
	// Touched only by RunStaleObjectSweeper's goroutine.
	staleChecks staleCheckLog
	// rules re-runs the declarative rule that opened an incident (the
	// api.Server's RuleStillFires). Nil means the cleared check uses live
	// health only. Set once at startup with SetRuleChecker.
	rules RuleChecker

	db          *data.DB
	gw          *gateway.Gateway
	llmProvider llm.Investigator
	events      *events.Bus // shared with internal/api.Server/internal/gateway.Gateway — see cmd/hub/main.go's construction order. May be nil in tests that don't exercise live-update publishing.
	// scmStore is api.ResolveIncidentRoute's own dependency, threaded through
	// here for BACKLOG.md F19 mechanism 1: gatherOwnershipFacts needs it to
	// check repository_bindings.spec.objectMappings, and this poller is the
	// SECOND of ResolveIncidentRoute's two callers (handleAnalyzeIncident is
	// the first) — see that function's own "one function, two callers"
	// rationale. A second *scm.Store, independent of internal/api.Server's
	// own, is fine: Store is stateless beyond the secretbox.Keeper reference
	// both hold, not a resource that needs to be shared for correctness.
	scmStore *scm.Store
	// checkouts backs BACKLOG.md F22 piece 1's read-only repository tools.
	// Its own cache rather than internal/api.Server's, for the same reason
	// scmStore above is its own Store: it holds no state that has to be shared
	// for correctness (a checkout is keyed by repository+commit+directory, so
	// two caches can only ever duplicate a fetch, never disagree about
	// content), and threading the Server's through here would couple this
	// poller's construction to the API server's.
	checkouts *repotools.Checkouts
	// knowledge is BACKLOG.md L2's storage half (2026-08-30 decision) —
	// investigateOne calls knowledge.TriggerAsync after ITS OWN commit
	// succeeds, the exact mirror of internal/api/analyze.go's
	// handleAnalyzeIncident doing the same for a manual analysis. Nil-safe
	// (Store.TriggerAsync's own doc comment), so the &Poller{} struct
	// literal this package's own tests already use leaves this nil and
	// simply never embeds anything.
	knowledge *knowledge.Store
	// readLogs is BACKLOG.md F28 finding 1's registry — UNLIKE checkouts just
	// above, this one genuinely must be the SAME instance internal/api.Server
	// holds, not an independent one: internal/api.CallRepoTool (the only
	// thing a cli-backend investigation's repo-tool calls ever reach) is a
	// method on *api.Server alone, regardless of whether THIS poller or a
	// manual click started the investigation. cmd/hub/main.go builds one
	// registry and passes it to both constructors — see
	// repotools.ReadLogRegistry's own doc comment. Nil-safe, so the &Poller{}
	// struct literal this package's own tests already use is unaffected.
	readLogs *repotools.ReadLogRegistry
	// loggedSeveritySkips backs logSeveritySkipOnce (BACKLOG.md C12): the set
	// of incident IDs already logged as skipped for severity, so the log
	// line fires once per incident for this process's lifetime rather than
	// once per tick forever — see logSeveritySkipOnce's own doc comment.
	// Lazily initialized there; the &Poller{} struct literal this package's
	// own tests already use leaves it nil, which is a valid empty map for
	// reads (only logSeveritySkipOnce ever writes to it, and it initializes
	// on first write).
	loggedSeveritySkips map[string]bool

	// mu guards providerUnusableUntil/providerBackoff only. Needed because
	// runWaves can run maxConcurrentInvestigations investigations at once and
	// any of them can be the one that discovers the provider is unusable.
	mu sync.Mutex
	// providerUnusableUntil is when this poller will next attempt an
	// investigation after discovering there is no usable AI provider, and
	// providerBackoff is the window that produced it. Both are process-local
	// on purpose: this is a throttle, not a correctness mechanism, so losing
	// it on restart simply means one more attempt is made — which is the right
	// behaviour anyway, since a restart is the most likely moment for a
	// provider to have been configured. See providerBackoffFloor.
	providerUnusableUntil time.Time
	providerBackoff       time.Duration
}

// providerBackoffActive reports whether this poller is currently standing down
// because no AI provider was usable. Silent by design — the arming log line
// (noteProviderUnusable) already says when the next attempt happens, and
// repeating it every DefaultPollInterval would bury it.
// logger is this package's structured logger (PROJECT.md T22). See
// investigateOne for where the correlation id that joins one investigation's
// lines together is minted.
var logger = logging.For("autoanalyze")

func (p *Poller) providerBackoffActive() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return time.Now().Before(p.providerUnusableUntil)
}

// noteProviderUnusable arms (or extends) the poller-level backoff after an
// investigation failed because no AI provider is usable. Logged loudly every
// time it arms: a fleet that has silently stopped being investigated is
// exactly the thing an operator has no other way to notice.
func (p *Poller) noteProviderUnusable(incidentID string, cause error) {
	p.mu.Lock()
	next := p.providerBackoff * 2
	if next < providerBackoffFloor {
		next = providerBackoffFloor
	}
	if next > providerBackoffCeiling {
		next = providerBackoffCeiling
	}
	p.providerBackoff = next
	p.providerUnusableUntil = time.Now().Add(next)
	p.mu.Unlock()
	logger.Warn("no usable AI provider: pausing ALL automatic investigation. This is a hub configuration problem, not a problem with this incident, so the incident keeps its full retry budget and stays eligible; investigation resumes by itself once a provider is configured in Settings, with no restart. A person can still run POST /incidents/{id}/analyze by hand",
		logging.IncidentID(incidentID), slog.Duration("paused_for", next), logging.Err(cause))
}

// noteProviderUsable clears the backoff after an investigation completes
// without a configuration error — so one recovered provider immediately
// restores the full poll cadence rather than leaving the doubled window in
// place until it happens to expire.
func (p *Poller) noteProviderUsable() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.providerUnusableUntil = time.Time{}
	p.providerBackoff = 0
}

// New builds a Poller. Always non-nil — whether auto-analysis is actually
// enabled is resolved fresh every sweep tick (settings.Resolve), not fixed
// at construction time, matching every other DB-backed, live-editable
// setting in this codebase (internal/notify.NewWebhookNotifier's own doc
// comment makes the identical point for its webhook URL).
func New(db *data.DB, gw *gateway.Gateway, llmProvider llm.Investigator, bus *events.Bus, scmStore *scm.Store, knowledgeStore *knowledge.Store, readLogs *repotools.ReadLogRegistry) *Poller {
	return &Poller{db: db, gw: gw, llmProvider: llmProvider, events: bus, scmStore: scmStore, checkouts: repotools.NewCheckouts(), knowledge: knowledgeStore, readLogs: readLogs}
}

// Run ticks every interval, running one sweep per tick, until ctx is
// cancelled. Blocks — callers run it in its own goroutine, the same pattern
// cmd/hub/main.go's runAPI already uses for notify.WebhookNotifier.Run,
// gateway.HealthMonitor.Run, and gateway.Gateway.ListenAndServeTLS.
func (p *Poller) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// The TICK gets a correlation id of its own for the selection
			// work (which incidents are eligible, what the gates said);
			// each investigation this tick spawns then mints its own,
			// narrower one — see investigateOne. A tick-level id alone
			// would interleave a whole wave's trails.
			sweepCtx, _ := logging.NewUnitOfWork(ctx)
			start := time.Now()
			err := p.sweep(sweepCtx)
			metrics.ObserveSweeperRun("auto_analysis", time.Since(start), err)
			if err != nil {
				logger.ErrorContext(sweepCtx, "auto-analysis sweep failed", logging.Err(err))
			}
		}
	}
}

// incidentCandidate is exactly what one sweep needs, per incident, to both
// decide eligibility (selectEligible) and run the investigation
// (investigateOne).
type incidentCandidate struct {
	ID              string
	ClusterID       string
	Fingerprint     string
	Severity        string
	OccurrenceCount int
	// ObjectKey is incidents.object_key (migration 000036) —
	// gvk|namespace|name for the object this incident is about. Empty when the
	// finding that opened it named no object. Used by objectIsGone to skip
	// paying for an investigation of something that no longer exists.
	ObjectKey string
	// FleetGroupID is incidents.fleet_group_id (migration 000005,
	// written only by internal/fleetgroup.Recompute) — the identity of the
	// cross-cluster group this incident belongs to, or "" for the large
	// majority of incidents, which are confined to one cluster. Read here
	// for one reason only: to schedule fleet-correlated siblings'
	// investigations TOGETHER rather than minutes apart (BUGS.md 99, see
	// fleetWaves). It never affects whether an incident is investigated,
	// only when relative to its siblings.
	FleetGroupID string
	// HasAnalysis is true if this incident already has at least one
	// analyses row FOR ITS CURRENT OPEN CYCLE — from a prior manual click,
	// or a prior automatic attempt that this sweep's own
	// auto_analysis_attempted_at IS NULL filter (see the candidate query)
	// wouldn't otherwise have excluded on its own account. Computed in SQL
	// (a single EXISTS subquery) rather than a second round-trip per
	// candidate.
	//
	// "Current open cycle" — not "ever, in this incident's whole history" —
	// since migration 000098 (PROJECT.md B144's own follow-on, found live
	// 2026-09-06): the EXISTS subquery only counts an analyses row that
	// postdates incidents.reopened_at, when set. Before this, ANY analysis
	// ever, however old, made HasAnalysis permanently true — which meant
	// resetting auto_analysis_attempted_at on a Reopened transition
	// (orchestrator.SetState) correctly re-admitted the incident past this
	// struct's OWN query's WHERE clause, only for selectEligible's HasAnalysis
	// check, below, to silently discard it anyway: a Reopened incident
	// almost always has a prior analysis (that is how its plan got approved
	// in the first place), so the fix that was supposed to let it be
	// re-analyzed never actually fired for a single real case.
	HasAnalysis bool
	// AutoAnalysisAttempts is incidents.auto_analysis_attempts (migration
	// 000093) — how many automatic investigations of this incident have
	// already been tried and failed. Read here rather than re-queried in the
	// failure path so the bounded-retry decision is made from the same
	// snapshot every other eligibility decision this tick was made from.
	AutoAnalysisAttempts int
	// WorkloadKey is incidents.workload_key (migration 000042) —
	// `apps/v1/Deployment|ns|name`, the workload ObjectKey belongs to, or empty
	// for an object with no resolvable owner. Read for exactly one purpose:
	// existenceTargetFor, so the "is this still worth investigating?" check
	// asks about something a pod being replaced does not destroy.
	WorkloadKey string
}

// candidateQuery selects incidents this sweep should even consider: the
// automatic path is not already finished with them (auto_analysis_attempted_at
// IS NULL) and any backoff from an earlier failed attempt has expired
// (auto_analysis_retry_after) — see the package doc comment's retry policy.
// Severity thresholding and "already analyzed" exclusion are
// deliberately NOT filtered here in SQL — see selectEligible's doc comment
// for why that logic lives in plain, DB-free Go instead.
//
// The auto_analysis_retry_after clause is what makes a bounded retry possible
// at all. Before it, "attempted" and "concluded" were the same bit: a failed
// investigation either burned the incident's only attempt or (as it actually
// did) left it in Investigating, which the state filter below excludes — two
// different ways of never trying again. NULL means "eligible now", which is
// every incident that has never failed, so this narrows nothing in the
// ordinary case.
//
// The state filter, by contrast, MUST be in SQL, and its absence was a real
// bug found within seconds of enabling automatic analysis for the first time.
// Six states are excluded, for three different reasons:
//
//   - Resolved / Dismissed are terminal (internal/orchestrator's
//     allowedTransitions gives them no outgoing edges), so investigateOne's
//     Detected -> Investigating transition can only ever fail on them. Every
//     poll re-selected every closed incident in the entire history, failed,
//     and logged — noise that grows without bound as a deployment ages.
//   - Investigating / Executing have work in flight. Starting a second
//     investigation on an incident already being investigated is wasted spend
//     at best, and racing another writer's state transition at worst.
//   - AwaitingMerge has a fix in flight OUTSIDE ARGUS: a pull request is open and
//     waiting on a human to merge it. Re-analysing would pay for a fresh
//     investigation of a problem whose fix already exists and is under review,
//     and would produce a second plan derived from a cluster that is about to
//     change. The symptom keeps recurring until the merge syncs, which is exactly
//     why this exclusion is needed — without it, every pending pull request
//     becomes a recurring reason to spend money.
//   - PlanRejected is a human's standing decision: someone read the plan ARGUS
//     proposed and refused it. Re-analysing on a timer would spend money to
//     put a very similar plan back in front of the same person, which is how a
//     product teaches operators that saying no does not stick. It is not
//     excluded because there is nothing left to do — there is, the fault is
//     live — but because the next move is a human's to choose
//     (incident:reanalyse is still there, and PlanRejected -> Investigating is
//     a legal edge for exactly that). In practice this bites only after a
//     MANUAL analysis, since an incident the automatic path already
//     investigated carries auto_analysis_attempted_at and never returns here.
//
// The consequence that made this urgent is not the log spam. This query is
// `ORDER BY first_seen ASC LIMIT $1`, so the OLDEST rows win the candidate
// slots — and closed incidents are, by definition, the oldest ones. A fleet
// with a few dozen resolved incidents therefore fills every slot with rows
// that can never be actioned, and a genuinely new high-severity incident is
// never picked up at all. Observed exactly that: automatic analysis appeared
// to be "working" (it logged busily every poll) while silently starving the
// one real incident it existed to catch.
//
// BUGS.md 120: the state filter above closed the CLOSED-INCIDENT version of
// this starvation shape; it does nothing for an incident that stays open and
// eligible FOREVER because its cluster is gone. Found live on this dev stack:
// 112+ rows (oldest from 2026-03-18) that had never been excluded and never
// would be, because selectEligible's isConnected check runs in Go, AFTER this
// query's own LIMIT has already truncated the candidate set to the oldest 50
// rows — so a cluster that disconnected once and never came back could sit at
// the front of that ordering indefinitely, permanently displacing every
// fresher, genuinely dispatchable incident.
//
// Fix chosen (of the three the bug entry named — exclude in SQL, mark
// attempted on skip, or re-rank by connectivity): exclude in SQL, joining
// clusters and applying two different rules for its two different kinds of
// "gone":
//
//   - Archived / Rejected are TERMINAL cluster states (internal/api/clusters.go's
//     handleDecommissionCluster is the only writer of Archived, and it is an
//     explicit human action — "there is no automatic transition into it"; a
//     Rejected cluster never had a working enrollment to begin with, and
//     internal/gateway's server.go refuses a new tunnel connection for either
//     state). Neither can ever reconnect, so both are excluded unconditionally,
//     no matter how young the row.
//   - Disconnected is NOT terminal — internal/gateway/health.go's HealthMonitor
//     demotes into it automatically after missed heartbeats, and ANY heartbeat
//     flips it straight back to Active (server.go's handleHeartbeat). Excluding
//     it outright would defeat that recovery path, so it is only excluded once
//     it has been quiet for staleUnreachableClusterAge — long past any real
//     reconnect, short enough that a genuinely dead cluster's incidents stop
//     starving the query quickly rather than accumulating for months.
//   - Provisioning shares that exact shape and was found live, 2026-09-04, NOT
//     excluded by name at all before this fix: an enrollment token issued and
//     never redeemed (internal/api/clusters.go's handleCreateEnrollmentToken)
//     leaves a cluster row in Provisioning with last_heartbeat_at NULL,
//     forever — this codebase's own smoke-test.sh alone left 17 such rows
//     accumulated over the trailing few days, none Disconnected (they never
//     connected even once to demote FROM), so the Disconnected-only clause
//     above never touched them. Measured live: 82 real incidents on genuinely
//     reachable clusters sat starved behind them in the ORDER BY (severity
//     boost, then first_seen ASC) — old, permanently-ineligible Provisioning
//     rows sorting ahead of new, genuinely eligible ones purely on age, the
//     same starvation shape BUGS.md 87/120 already fixed for a terminal state
//     and a dead-Disconnected state respectively, now found for a third
//     cluster state nobody had named yet. Fixed the same way: excluded once
//     old enough (COALESCE falls back to created_at here, since a
//     Provisioning cluster's last_heartbeat_at is always NULL by definition,
//     never having sent one), not excluded unconditionally, since a token
//     redeemed a minute after creation is the ordinary case, not the
//     exception.
//
// This was chosen over the other two options for reasons worth recording:
// marking auto_analysis_attempted_at on a connectivity skip (option 2) trades
// "eligible forever" for "never retried," and distinguishing a genuine
// analysis attempt from a connectivity skip well enough to reconsider the
// latter on reconnect would need a second column or a sentinel value — this
// SQL exclusion needs neither, and a cluster that reconnects (Disconnected ->
// Active via any heartbeat, or a fresh non-terminal cluster replacing an
// Archived one) makes its incidents eligible again automatically, with no
// separate reset step. Re-ranking by connectivity plausibility (option 3)
// would reduce how often a dead row wins a slot but, unlike an outright
// exclusion, could never fully stop a cluster that disconnected once from
// occupying candidate slots forever on an otherwise-quiet fleet.
//
// The same starvation shape, discovered live measuring BACKLOG.md C12
// (2026-09-02): severity-ineligible incidents are excluded in Go
// (selectEligible), same as before, but they are NEVER marked
// auto_analysis_attempted_at, so — unlike a terminal or long-dead-cluster
// row — they never leave this query's WHERE clause at all. On this dev
// stack, at the moment C12 was measured, 214 incidents were open and
// unattempted, 140 of them low/medium; the oldest 50 (this query's own
// LIMIT) were 74% severity-ineligible chaff that will occupy a candidate
// slot on every single tick, forever, while genuinely eligible high/
// critical incidents — including any newly detected AFTER this backlog
// formed — sit below the LIMIT cutoff and are never even queried until
// enough chaff ahead of them is resolved or dismissed by a human. That is
// this feature's whole point (investigate "soon," unattended) failing
// silently for exactly the incidents it exists to catch.
//
// Unlike the connectivity case above, this is fixed by ORDER BY priority
// ($3), not outright WHERE exclusion, and deliberately so: severity
// selection is operator-editable at any time (internal/settings.Resolve is
// re-read fresh every tick), and an outright SQL exclusion would mean a
// severity-ineligible incident, once excluded from a tick's results, is
// never seen by selectEligible again to LOG that it was skipped —
// defeating this same task's other fix (meetsSelectedSeverities' skip is
// now logged, not a bare continue) for the overwhelming majority of skips,
// which is worse than the noise a rare, priority-losing chaff row
// occasionally produces. Priority ordering keeps the actual safety
// property (an eligible candidate can never be starved by an arbitrarily
// large ineligible backlog, because eligible rows always sort first and
// there are far fewer than LIMIT of them in practice) while still letting
// a chaff row surface through selectEligible and get logged whenever fewer
// than LIMIT eligible rows exist this tick — which is every tick, on any
// fleet where severity-ineligible incidents aren't themselves in the tens
// of thousands.
const candidateQuery = `
	SELECT incidents.id, incidents.cluster_id, incidents.fingerprint, incidents.severity, incidents.occurrence_count,
	       COALESCE(incidents.object_key, '') AS object_key,
	       COALESCE(incidents.fleet_group_id, '') AS fleet_group_id,
	       COALESCE(incidents.workload_key, '') AS workload_key,
	       EXISTS (SELECT 1 FROM analyses WHERE analyses.incident_id = incidents.id
	                 AND (incidents.reopened_at IS NULL OR analyses.created_at > incidents.reopened_at)) AS has_analysis,
	       incidents.auto_analysis_attempts
	  FROM incidents
	  JOIN clusters ON clusters.id = incidents.cluster_id
	 WHERE incidents.auto_analysis_attempted_at IS NULL
	   AND (incidents.auto_analysis_retry_after IS NULL OR incidents.auto_analysis_retry_after <= now())
	   -- 'Expired' (PROJECT.md T2, migration 000101) belongs here for the same
	   -- reason 'Resolved'/'Dismissed' do: allowedTransitions gives StateExpired
	   -- exactly one edge, to StateDetected, so MarkInvestigating can never
	   -- succeed for one. Without this an Expired row with a NULL
	   -- auto_analysis_attempted_at is selected, fails the transition, and
	   -- returns WITHOUT stamping attempted_at — so it is re-selected every
	   -- tick, forever. Masked at the time this was added only because every
	   -- Expired row happened to be below the configured severity and so was
	   -- dropped by selectEligible before reaching the transition; one expired
	   -- high/critical incident is all it takes to make it live.
	   AND incidents.state NOT IN ('Resolved', 'Dismissed', 'Investigating', 'Executing', 'AwaitingMerge', 'PlanRejected', 'Expired')
	   AND clusters.state NOT IN ('Archived', 'Rejected')
	   AND (clusters.state NOT IN ('Disconnected', 'Provisioning')
	        OR COALESCE(clusters.last_heartbeat_at, clusters.created_at) > now() - ($2 * interval '1 second'))
	 ORDER BY (incidents.severity = ANY($3::text[])) DESC, incidents.first_seen ASC
	 LIMIT $1`

// staleUnreachableClusterAge is how long a cluster must have been silent
// (COALESCE(last_heartbeat_at, created_at), same fallback health.go's own
// demotion SQL uses for a cluster that reached Active without ever sending a
// real Heartbeat) before candidateQuery stops considering its incidents at
// all — applies identically to a cluster stuck Disconnected and one stuck
// Provisioning (BUGS.md 134: an unredeemed enrollment token leaves the
// latter with no heartbeat ever, the same permanently-unreachable shape as
// the former, just never having connected in the first place rather than
// having disconnected from one).
//
// Deliberately far above internal/gateway/health.go's own
// degradedThreshold/disconnectedThreshold (75s/150s): those exist to detect a
// missed heartbeat quickly for OPERATIONAL visibility (cluster health
// display, gating live tool calls), not to give up on reconnection. An hour
// is comfortably past any real network blip, restart, or upgrade window (or,
// for Provisioning, any real delay between issuing an enrollment token and
// redeeming it), while still bounding how long a truly dead cluster's
// incidents can occupy candidate slots before this predicate — rather than
// months (or, measured live 2026-09-04, indefinitely: the oldest stale
// Provisioning row found was already 4 days old with no natural expiry at
// all), as measured live before this fix.
const staleUnreachableClusterAge = 1 * time.Hour

// maxConcurrentInvestigations bounds how many investigations one sweep runs
// at the same time (see fleetWaves/runWaves and BUGS.md 99).
//
// Two, not more, and the number is a budget decision rather than a
// throughput one:
//
//   - Two is enough to FIX the bug. A batch (orchestrator.ResolveBatchGating)
//     forms the moment two members of one fleet group are simultaneously
//     eligible; the third and later members of a larger group attach to the
//     already-created batch as wave-2 stragglers on a later tick
//     (addStragglers), which is the designed path for them, not a
//     degradation.
//   - Each in-flight investigation holds one pooled connection open across a
//     real LLM round-trip — 30-90s, measured live — because investigateOne
//     deliberately keeps its transaction open across the Investigate call.
//     pgxpool's default MaxConns is max(4, NumCPU), so on a small hub host
//     four concurrent investigations would be the WHOLE pool, starving the
//     API of connections for a minute at a time. Two leaves headroom on
//     every host this runs on.
//
// The daily spend ceiling is unaffected: it is checked once per sweep in
// collectEligible, before any candidate is dispatched, exactly as before —
// this constant changes the ORDER and OVERLAP of a sweep's investigations,
// never how many of them a sweep runs.
const maxConcurrentInvestigations = 2

// maxAutoAnalysisAttempts is how many times the automatic path will try one
// incident before giving up on it and marking it attempted for good.
//
// Three, and the bound matters more than the number. Unbounded retries are the
// hot-loop this package's original "attempt at most once" rule was written to
// avoid, and that concern was real; one attempt was simply the wrong answer to
// it, because it made a transient provider hiccup permanent and invisible.
// Three attempts spread over autoAnalysisBackoff's schedule covers the
// failures that are actually transient in practice — a rate limit, a provider
// 5xx, a tunnel stall, a hub restarted mid-investigation — and stops well short
// of paying for a fourth investigation of something that has failed three
// times for a reason nobody has looked at yet.
//
// Reaching the bound is not silence: the incident is Detected (a human can
// analyze it), auto_analysis_last_error holds the reason, and the incident's
// own timeline carries an AutoAnalysisFailed event saying the automatic path
// has given up.
const maxAutoAnalysisAttempts = 3

// autoAnalysisBackoff is how long to wait before the nth retry.
//
// Deliberately coarse and capped rather than a true exponential: the thing
// being waited out is a provider or a cluster becoming healthy, which happens
// on human/operational timescales, not on millisecond ones. The first retry is
// far enough out that a rate limit or a rolling restart has cleared, and the
// last is far enough out that three attempts span most of an hour — long
// enough to survive a deploy, short enough that a genuinely transient failure
// does not delay an investigation until the next day.
func autoAnalysisBackoff(attempts int) time.Duration {
	switch {
	case attempts <= 1:
		return 5 * time.Minute
	case attempts == 2:
		return 20 * time.Minute
	default:
		return 45 * time.Minute
	}
}

// providerBackoffFloor/providerBackoffCeiling bound how often this poller
// re-tests a hub whose AI provider is not usable at all.
//
// This is a POLLER-level backoff, not a per-incident one, and that distinction
// is the whole point. "No usable AI provider" is a fact about the hub, not
// about the incident that happened to be first in the queue when it was
// discovered. Charging it to that incident's retry budget would mean a
// misconfigured hub quietly eats its own backlog one incident per tick — every
// incident permanently marked as tried-and-failed for a reason that had nothing
// to do with it, and no recovery when someone finally configures a provider.
//
// So instead the incident is left fully eligible and the SWEEP stands down.
// The backoff doubles from the floor to the ceiling on each consecutive
// failure, so a hub that is simply never going to be configured settles at one
// wasted attempt an hour rather than one every fifteen seconds, and a hub that
// IS configured resumes on the very next tick after the current window
// expires — with no restart, no manual reset, and no incident to un-mark.
const (
	providerBackoffFloor   = 15 * time.Minute
	providerBackoffCeiling = 1 * time.Hour
)

// maxRecordedErrorLength caps what goes into auto_analysis_last_error and the
// timeline event. Error text here is this codebase's own wrapped messages
// (llm.ErrNotConfigured's guidance sentence is itself several hundred bytes),
// never a raw provider response body — but a bound belongs on anything written
// from an error string regardless, and a truncated reason still tells an
// operator which failure they are looking at.
const maxRecordedErrorLength = 1000

// sweep runs one pass: resolve automation settings, gather candidates, keep
// the ones actually eligible, and investigate them. Candidate
// gathering runs in its own short, read-only transaction (committed before
// any investigation starts) rather than holding one transaction open across
// every incident's potentially-slow LLM round-trip — investigateOne opens
// its own transaction per incident instead (see its doc comment).
//
// BUGS.md 99: this loop used to be strictly sequential, and that was not a
// performance detail — it was the reason fleet-correlated incidents could
// never be batched by the real unattended pipeline. An investigation takes
// tens of seconds while internal/api's unattended executor sweeps every 30s
// and gates on what is eligible AT THAT MOMENT, so a sequential loop
// guarantees each sibling finishes alone, is the only eligible candidate on
// its own tick, and executes ungated — the exact "thirty clusters, thirty
// uncoordinated executions" case BACKLOG.md R3's staging exists to prevent,
// reproduced live twice. Scheduling siblings into the SAME wave is what
// makes them simultaneously eligible, which is the precondition
// ResolveBatchGating was already written to act on (that half was verified
// correct live; only its precondition was unreachable).
func (p *Poller) sweep(ctx context.Context) error {
	// Standing down because no AI provider was usable last time — see
	// noteProviderUnusable. This USED to be checked here, before
	// collectEligible ran at all, purely to skip a DB round trip. It is
	// checked INSIDE collectEligible now (PROJECT.md T14): this tick's
	// candidates still need to be fetched so the real reason — "no usable AI
	// provider" — can be persisted onto each of them, not just logged once
	// for the whole sweep with nothing recorded against any incident.
	candidates, err := p.collectEligible(ctx)
	if err != nil {
		return err
	}
	runWaves(ctx, fleetWaves(candidates, maxConcurrentInvestigations), p.investigateOne)
	return nil
}

// fleetWaves splits one sweep's candidates into the waves runWaves executes,
// pure and DB-free so the scheduling decision is unit-testable on its own
// (see autoanalyze_test.go) — the same split selectEligible already makes
// between "decide" and "do".
//
// The rule is deliberately narrow: a candidate that shares a non-empty
// fleet_group_id with later candidates pulls them into its own wave, up to
// maxConcurrent; everything else stays a wave of one, investigated exactly
// as serially as before. Siblings are pulled from ANYWHERE later in the
// list, not just adjacent positions, because the candidate query orders by
// first_seen and two clusters detecting one fleet-wide fault need not be
// adjacent in it.
//
// Consequences worth stating rather than discovering:
//
//   - An ungrouped fleet (the normal case) sees no behaviour change at all:
//     every wave holds one candidate and the sweep is the same serial loop
//     it always was.
//   - A group larger than maxConcurrent is split across consecutive waves.
//     The first wave forms the batch; the rest attach as wave-2 stragglers.
//   - Siblings detected far enough apart to land in DIFFERENT sweep ticks
//     still cannot share a wave — nothing here remembers a candidate
//     between ticks. That residue is bounded by the poll interval (15s)
//     rather than by investigation latency (30-90s and unbounded above),
//     which is the part BUGS.md 99 measured as deterministic failure.
func fleetWaves(candidates []incidentCandidate, maxConcurrent int) [][]incidentCandidate {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	scheduled := make([]bool, len(candidates))
	var waves [][]incidentCandidate
	for i, c := range candidates {
		if scheduled[i] {
			continue
		}
		scheduled[i] = true
		wave := []incidentCandidate{c}
		if c.FleetGroupID != "" {
			for j := i + 1; j < len(candidates) && len(wave) < maxConcurrent; j++ {
				if scheduled[j] || candidates[j].FleetGroupID != c.FleetGroupID {
					continue
				}
				scheduled[j] = true
				wave = append(wave, candidates[j])
			}
		}
		waves = append(waves, wave)
	}
	return waves
}

// runWaves runs each wave's candidates concurrently and waits for the whole
// wave before starting the next one — never more than one wave in flight, so
// the in-flight count is bounded by fleetWaves' maxConcurrent and nothing
// else.
//
// investigate (investigateOne in production) already logs and swallows every
// error per the package's "one incident's failure must never stop the rest
// of the batch" discipline, so there is nothing to collect here and no error
// to return. Each concurrent call opens its OWN transaction and sets its own
// request scope inside it (data.SetRequestScope is SET LOCAL, scoped to that
// transaction's connection), so running two at once cannot let one
// incident's RLS scope leak into another's — the property that makes this
// safe to parallelise at all.
//
// ctx is passed through unchanged: cancellation still propagates to every
// in-flight investigation, and a cancelled sweep stops starting new waves
// the moment the current one drains.
func runWaves(ctx context.Context, waves [][]incidentCandidate, investigate func(context.Context, incidentCandidate)) {
	for _, wave := range waves {
		if ctx.Err() != nil {
			return
		}
		if len(wave) == 1 {
			investigate(ctx, wave[0])
			continue
		}
		var wg sync.WaitGroup
		for _, c := range wave {
			wg.Add(1)
			go func(c incidentCandidate) {
				defer wg.Done()
				investigate(ctx, c)
			}(c)
		}
		wg.Wait()
	}
}

// collectEligible resolves automation settings and, if enabled, returns the
// candidates this tick should investigate (already filtered by
// selectEligible). Its own short transaction is read-only and always
// committed (never left to roll back on the happy path) — there is nothing
// in this transaction that needs to survive a later failure in
// investigateOne, since investigateOne runs entirely in its own,
// independent transaction per incident.
func (p *Poller) collectEligible(ctx context.Context) ([]incidentCandidate, error) {
	var eligible []incidentCandidate
	// nil accessible-cluster-ids, same rationale as notify.sweep: this poller
	// isn't scoped to one cluster's connection the way a tunnel handler is —
	// it needs to see eligible incidents across the whole tenant. InFleetScope
	// is that resolve-and-widen pair (PROJECT.md G11).
	if err := data.InFleetScope(ctx, p.db.Pool, func(ctx context.Context, tx pgx.Tx, tenantID string) error {
		cfg, err := settings.Resolve(ctx, tx)
		if err != nil {
			return fmt.Errorf("resolve automation settings: %w", err)
		}
		if !cfg.AutoAnalysisEnabled {
			return nil
		}

		// Exactly the severities the operator selected: the settings screen
		// promises that an unchecked severity is not investigated automatically.
		// Both the SQL priority ordering and selectEligible use this one value.
		effectiveSeverities := cfg.AutoAnalysisSeverities

		// Coalesced for the SQL parameter only ($3 = ANY($3::text[])):  nil would
		// evaluate to SQL NULL for every row's priority key rather than a real
		// false, an unhelpful three-valued ordering instead of "no priority
		// boost, fall back to first_seen ASC exactly as before" — the
		// deliberately inert case for a still-valid, if useless, "nothing
		// selected" configuration. selectEligible below gets effectiveSeverities
		// itself (never coalesced): its own meetsSelectedSeverities doc comment
		// is what actually defines nil/empty as "nothing qualifies."
		sqlSeverities := effectiveSeverities
		if sqlSeverities == nil {
			sqlSeverities = []string{}
		}
		rows, err := tx.Query(ctx, candidateQuery, candidateBatchSize, staleUnreachableClusterAge.Seconds(), sqlSeverities)
		if err != nil {
			return fmt.Errorf("query auto-analysis candidates: %w", err)
		}
		var candidates []incidentCandidate
		for rows.Next() {
			var c incidentCandidate
			if err := rows.Scan(&c.ID, &c.ClusterID, &c.Fingerprint, &c.Severity, &c.OccurrenceCount, &c.ObjectKey, &c.FleetGroupID, &c.WorkloadKey, &c.HasAnalysis, &c.AutoAnalysisAttempts); err != nil {
				rows.Close()
				return fmt.Errorf("scan auto-analysis candidate: %w", err)
			}
			candidates = append(candidates, c)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate auto-analysis candidates: %w", err)
		}

		// PROJECT.md T14: from here down, every reason this tick's candidates are
		// NOT about to be investigated is persisted onto each of them
		// (api.SetAutomationGate), in the same transaction and at the same
		// moment this function actually decides it — not logged only, and never
		// re-derived by a second function later. candidateQuery is fetched above
		// this point specifically so a fleet-wide refusal (provider backoff, the
		// spend ceiling) still knows which incidents it applies to.
		//
		// Ordered exactly as sweep() used to check them (provider backoff was
		// checked before this function was ever called; the ceiling was checked
		// immediately after resolving settings): no-usable-provider is the most
		// fleet-wide, most decisive refusal, so it is attributed first and
		// unconditionally over the ceiling or any per-incident reason below.
		if p.providerBackoffActive() {
			reason := "no usable AI provider is configured right now; automatic investigation is paused fleet-wide until one is configured (Settings) — a person can still run POST /incidents/{id}/analyze manually"
			if err := persistGateSkip(ctx, tx, candidates, api.GateNoAIProvider, reason); err != nil {
				return err
			}
			return nil
		}

		// Daily spend ceiling (DESIGN.md §16.4,
		// internal/settings.Config.DailySpendCeilingUsd) — re-checked fresh every
		// sweep tick (this function runs once per DefaultPollInterval), so a
		// ceiling reached mid-day stops every further automatic investigation for
		// the rest of that UTC calendar day, and automation resumes on its own the
		// next tick once spend resets or an operator raises the ceiling — no
		// restart, no manual re-enable needed either way. Unlike
		// internal/api/analyze.go's handleAnalyzeIncident (the MANUAL path, which
		// deliberately does NOT block on this same ceiling — see that handler's
		// own doc comment), this IS the unsupervised, no-human-in-the-loop path
		// DESIGN.md's "a noisy fleet could run up real LLM spend completely
		// unsupervised" risk is actually about, so this package makes the
		// opposite choice: skip starting ANY new investigation this sweep, logged
		// and persisted onto every candidate this tick, rather than a partial or
		// best-effort throttle. A no-op when SpendCeilingActive() is false (no
		// ceiling configured, or pricing not configured — see that method's own
		// doc comment).
		if cfg.SpendCeilingActive() {
			todaySpend, err := api.TodaySpendUSD(ctx, tx)
			if err != nil {
				return fmt.Errorf("check daily spend ceiling: %w", err)
			}
			if api.SpendCeilingBreached(cfg, todaySpend) {
				reason := fmt.Sprintf("today's measured spend ($%.4f) has reached the configured daily ceiling ($%.4f); automatic investigation is paused fleet-wide until it resets at UTC midnight or the ceiling is raised — a person can still run POST /incidents/{id}/analyze manually",
					todaySpend, *cfg.DailySpendCeilingUsd)
				logger.WarnContext(ctx, "daily spend ceiling reached: skipping automatic investigation for every eligible incident this sweep. A human can still run POST /incidents/{id}/analyze manually; this re-checks next tick",
					slog.Float64("spent_today_usd", todaySpend),
					slog.Float64("daily_spend_ceiling_usd", *cfg.DailySpendCeilingUsd),
					slog.Duration("recheck_interval", DefaultPollInterval))
				if err := persistGateSkip(ctx, tx, candidates, api.GateDailySpendCeiling, reason); err != nil {
					return err
				}
				return nil
			}
		}

		var skipped []gateSkip
		eligible, skipped = selectEligible(candidates, effectiveSeverities, p.gw.IsConnected, p.logSeveritySkipOnce)
		for _, sk := range skipped {
			if err := api.SetAutomationGate(ctx, tx, sk.IncidentID, sk.Gate, sk.Reason); err != nil {
				return fmt.Errorf("persist automation gate for incident %s: %w", sk.IncidentID, err)
			}
		}

		return nil
	}); err != nil {
		return nil, err
	}
	return eligible, nil
}

// gateSkip is one incident this tick decided NOT to investigate, and the
// exact reason — see selectEligible's own doc comment for why HasAnalysis
// exclusions produce no gateSkip (nothing to explain: the automatic path is
// simply done with that incident, not refusing it).
type gateSkip struct {
	IncidentID string
	Gate       api.AutomationGate
	Reason     string
}

// persistGateSkip writes the same gate/reason onto every one of candidates —
// used for the two fleet-wide refusals above (provider backoff, spend
// ceiling), where one decision applies to every candidate this tick rather
// than being computed per-incident.
func persistGateSkip(ctx context.Context, tx pgx.Tx, candidates []incidentCandidate, gate api.AutomationGate, reason string) error {
	for _, c := range candidates {
		if err := api.SetAutomationGate(ctx, tx, c.ID, gate, reason); err != nil {
			return fmt.Errorf("persist automation gate for incident %s: %w", c.ID, err)
		}
	}
	return nil
}

// logSeveritySkipOnce is the real, production logSeveritySkip callback
// passed to selectEligible — see that function's own doc comment for why a
// callback, not a direct log.Printf, is needed at all. Logs the first time
// a given incident is seen skipped for its severity, and never again for
// that same incident (loggedSeveritySkips only grows, never evicts — this
// poller's lifetime is one hub process, and one bit per skipped incident is
// not a meaningful memory concern next to everything else already held per
// incident elsewhere in this codebase).
func (p *Poller) logSeveritySkipOnce(incidentID, severity string) {
	if p.loggedSeveritySkips == nil {
		p.loggedSeveritySkips = make(map[string]bool)
	}
	if p.loggedSeveritySkips[incidentID] {
		return
	}
	p.loggedSeveritySkips[incidentID] = true
	logger.Info("incident severity does not match the configured auto-analysis severities: skipping automatic investigation. A person can still run POST /incidents/{id}/analyze manually; this incident is not retried automatically unless the configured severities change, and this line does not repeat for it",
		logging.IncidentID(incidentID), slog.String("severity", severity))
}

// meetsSelectedSeverities reports whether severity is a member of the
// configured set — replacing the old "severity >= threshold" ordinal
// comparison (migration 000020, superseded by 000024) with plain set
// membership, per the user's direct request: a checklist of individually
// selectable severities (e.g. `high` and `critical` selected, `medium`
// deliberately NOT) can express selections no single ordered threshold ever
// could.
//
// BACKLOG.md C12 (2026-09-02) proposed converting this back to an ordinal
// "this severity or higher, floor = lowest configured value" threshold,
// characterizing set membership as a bug. Investigated and deliberately
// NOT done: migration 000024's own up.sql says this exact conversion is why
// it exists ("the user asked for this directly: someone might want `high`
// and `critical` auto-analyzed but explicitly NOT `medium`, which no
// ordered threshold can express"), internal/settings.Config's
// AutoAnalysisSeverities doc comment repeats the same contract, and
// web/src/pages/SettingsPage.tsx renders it as four independent checkboxes
// ("any combination... is valid, including e.g. 'high' and 'critical'"). A
// floor-threshold reading of a non-contiguous selection like {low,critical}
// would silently investigate medium/high too, contradicting what the
// checklist UI shows the operator is doing. That is a worse defect than the
// one this entry named. For the specific configuration C12 actually enables
// (`{"high","critical"}`, contiguous, adjacent to the top of the enum),
// set-membership and a floor threshold agree exactly — so the owner's
// enable decision is unaffected either way. See autoanalyze_test.go's
// TestMeetsSelectedSeverities for the concrete non-contiguous case that
// proves this is still real set membership, not a threshold in disguise.
//
// A nil/empty severities set means NOTHING qualifies, not "every severity
// qualifies" the way the old nil minSeverity used to — see
// internal/settings.Config's AutoAnalysisSeverities doc comment for why that
// is the deliberate, safe reading of "nothing selected" rather than an
// oversight. An unrecognized severity value never passes (which shouldn't
// happen — incidents.severity has no DB CHECK of its own, but every write
// path this codebase has stays within the four-value enum), the same
// don't-trust-it-from-the-outside posture the old threshold check applied to
// an unrecognized minSeverity.
func meetsSelectedSeverities(severity string, severities []string) bool {
	for _, s := range severities {
		if s == severity {
			return true
		}
	}
	return false
}

// selectEligible is sweep's pure, DB-free selection logic — the part this
// task's brief specifically asked to be unit-testable without a live
// database (see autoanalyze_test.go). Three exclusions, each independently
// testable:
//
//   - already analyzed (c.HasAnalysis): an incident that already has an
//     analysis FOR ITS CURRENT OPEN CYCLE — from a prior manual click, most
//     likely — has nothing for auto-analysis to add; re-running it
//     automatically would just burn another LLM call for no new evidence.
//     "Current open cycle" matters (migration 000098, PROJECT.md B144): an
//     analysis from BEFORE the incident's most recent Reopened transition
//     does not count, or a reopen's whole point (getting re-analyzed
//     automatically) could never fire — see HasAnalysis's own doc comment.
//
//   - not a member of the configured severity set (meetsSelectedSeverities)
//     — a nil/empty set excludes every candidate, per its own doc comment.
//
//   - cluster not currently connected (isConnected): skipped, not treated
//     as an attempt — this candidate remains eligible on a LATER tick if
//     the cluster reconnects, unlike the "attempt at most once" rule that
//     applies once an investigation actually runs (see the package doc
//     comment). Mirrors internal/api/analyze.go's handleAnalyzeIncident
//     preflight check: calling a disconnected cluster's tools would only
//     ever produce evidence-free tool errors and burn the bounded
//     iteration budget learning that, exactly as that handler's own doc
//     comment explains.
//
//     This is a DIFFERENT signal from candidateQuery's own cluster.state/
//     last_heartbeat_at exclusion (BUGS.md 120) and deliberately not merged
//     with it: isConnected is the live, in-memory tunnel registry (instant,
//     but can go stale the moment a connection drops after this check runs —
//     see IsConnected's own doc comment), while the SQL predicate reads the
//     DB-persisted, health-monitor-maintained state that lags by up to
//     disconnectedThreshold+DefaultHealthCheckInterval. The SQL side exists
//     to stop a cluster that's been gone for a long time from ever occupying
//     a candidate slot; this Go side exists to catch a cluster that is
//     merely down RIGHT NOW, seconds after its last heartbeat, before the DB
//     state has even caught up to say so.
//
// logSeveritySkip is called for every severity-mismatch skip — BACKLOG.md
// C12's second named defect was that this used to be a bare continue with
// no log at all. It is a caller-supplied callback, not a direct log.Printf
// here, for one reason: severity-ineligible incidents are never marked
// auto_analysis_attempted_at (see meetsSelectedSeverities' own doc comment
// for why — the config can change later), so — unlike every other
// exclusion in this function — the SAME incident can be handed to this
// callback again on a later tick, indefinitely, for as long as it stays
// open and ineligible. Logging unconditionally here would eventually mean
// re-logging the identical line for the identical incident every
// DefaultPollInterval forever, once candidateQuery's priority ordering
// (see its own doc comment) lets it surface — which does happen, once the
// genuinely eligible backlog drains below one tick's LIMIT. selectEligible
// itself stays pure and DB-free either way (nil is a valid, no-op
// logSeveritySkip in tests that don't care); the caller
// (Poller.collectEligible) supplies the real, dedup ing implementation.
//
// Returns skipped alongside eligible (PROJECT.md T14) — one gateSkip per
// severity-mismatch or disconnected-cluster exclusion, so collectEligible can
// persist the exact reason onto each incident it is not about to investigate.
// HasAnalysis produces no gateSkip: that exclusion isn't a refusal to explain,
// it's the automatic path correctly recognising it already has nothing left
// to add.
func selectEligible(candidates []incidentCandidate, severities []string, isConnected func(clusterID string) bool, logSeveritySkip func(incidentID, severity string)) (eligible []incidentCandidate, skipped []gateSkip) {
	for _, c := range candidates {
		if c.HasAnalysis {
			continue
		}
		if !meetsSelectedSeverities(c.Severity, severities) {
			if logSeveritySkip != nil {
				logSeveritySkip(c.ID, c.Severity)
			}
			skipped = append(skipped, gateSkip{
				IncidentID: c.ID,
				Gate:       api.GateSeverityNotSelected,
				Reason: fmt.Sprintf(
					"this incident's severity (%s) is not one of the severities configured for automatic investigation — a person can still run POST /incidents/%s/analyze manually",
					c.Severity, c.ID),
			})
			continue
		}
		if !isConnected(c.ClusterID) {
			skipped = append(skipped, gateSkip{
				IncidentID: c.ID,
				Gate:       api.GateClusterUnreachable,
				Reason:     "this incident's cluster is not currently connected to the hub, so no automatic investigation can run against it right now — it will be retried automatically once the cluster reconnects",
			})
			continue
		}
		eligible = append(eligible, c)
	}
	return eligible, skipped
}

// investigateOne runs the exact investigation handleAnalyzeIncident runs on
// a manual click, then marks c attempted (auto_analysis_attempted_at =
// now()) regardless of whether the investigation succeeded, concluded only
// partially, or failed outright — see the package doc comment's retry
// policy. All of this — the findings read, the tool-calling investigation
// itself, persisting the result, and marking the incident attempted — runs
// inside ONE transaction per incident, held open across the Investigate
// call exactly the way internal/api/analyze.go's handleAnalyzeIncident holds
// rc.Tx open across the same call for a manual request. Since BUGS.md 99
// this poller may run up to maxConcurrentInvestigations of these at once
// (fleet-correlated siblings only — see fleetWaves), so that many pooled
// connections can be tied up this way at once; that constant is sized
// against pgxpool's default MaxConns for exactly this reason.
//
// Errors are logged and swallowed, never returned/propagated to sweep: one
// incident's failure (a transient DB error, an LLM call failing) must never
// stop the rest of the batch, the same "log and continue" discipline
// notify.sweep already applies per-row.
func (p *Poller) investigateOne(ctx context.Context, c incidentCandidate) {
	// PROJECT.md T23's background-worker half, at the granularity that
	// actually answers a support question: ONE INVESTIGATION, not one sweep
	// tick. A tick investigates a whole wave of fleet-correlated siblings
	// concurrently (fleetWaves, deliberately), so a tick-level id would
	// interleave several investigations' trails under one key and answer
	// nothing.
	//
	// Everything downstream of this line inherits it from the context: this
	// function's own log lines, internal/gateway's tunnel tool calls,
	// internal/llm's model call, and — because PersistAnalysis reads the id
	// off the context rather than taking it as a parameter — the
	// analyses.request_id column (migration 000117). That is what makes an
	// unattended investigation reconstructable end to end from its analysis
	// row alone.
	//
	// incident_id and cluster_id go on the context too, so the ~25 log
	// lines below do not each have to remember to name them, and cannot
	// name them inconsistently.
	ctx, _ = logging.NewUnitOfWork(ctx, logging.IncidentID(c.ID), logging.ClusterID(c.ClusterID))
	logger.InfoContext(ctx, "starting automatic investigation",
		slog.String("severity", c.Severity), slog.Int("occurrence_count", c.OccurrenceCount),
		slog.Int("prior_attempts", c.AutoAnalysisAttempts))

	// Re-check connectivity right before spending a transaction and a real
	// LLM round-trip on this incident — selectEligible's own check happened
	// moments earlier in the same sweep, but a cluster can disconnect in
	// between; re-checking here narrows that race to effectively nothing,
	// at zero DB cost.
	if !p.gw.IsConnected(c.ClusterID) {
		logger.InfoContext(ctx, "cluster disconnected since selection; skipping this incident this tick and retrying later")
		return
	}

	// A sibling in this same wave may have just discovered there is no usable
	// AI provider (noteProviderUnusable). Re-checked here, not only in sweep,
	// so one configuration failure stands the rest of THIS tick down too
	// instead of repeating itself once per candidate.
	if p.providerBackoffActive() {
		return
	}

	tx, err := p.db.Pool.Begin(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "begin transaction failed", logging.Err(err))
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		logger.ErrorContext(ctx, "resolve organisation failed", logging.Err(err))
		return
	}
	// Narrow scope to this one cluster, same rationale as
	// internal/gateway/finding.go's handleFinding: this transaction already
	// knows exactly which cluster it's about.
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{c.ClusterID}); err != nil {
		logger.ErrorContext(ctx, "set request scope failed", logging.Err(err))
		return
	}

	// Is the thing this incident is about still there?
	//
	// Checked HERE, immediately before spending a real LLM investigation, because
	// this is exactly where the money leaks. Observed twice within minutes of
	// enabling automatic analysis (WORKLOG §94): two investigations came back at
	// confidence 0.70/0.75 having correctly worked out that "the entire workload
	// has since been deleted from the namespace" — an honest answer, arrived at
	// by paying a frontier model to read a cluster and discover an absence.
	//
	// Deleting and redeploying is how operators routinely fix things, so a
	// resolved-by-deletion incident is the common case, not an edge one. Nobody
	// is watching an unattended sweep to skip the dead ones.
	//
	// One read-only tool call to avoid a multi-turn investigation is a trade
	// worth making by a wide margin. It is placed before MarkInvestigating so a
	// closed-because-gone incident never passes through Investigating on its way
	// out, which would leave a state history implying work that never happened.
	// Asked about the workload when there is one, not about the pod the finding
	// named — the same rule the stale sweep uses, for the same reason (see
	// existenceTargetFor). A pod is replaced by every rollout, drain and
	// restart, and this check RESOLVES the incident on a not-found, so asking
	// about the pod meant an ordinary rollout could close an unanalysed
	// incident about a workload that is still broken. Erring toward
	// investigating is also the asymmetry objectIsGone's own doc comment
	// already states: skipping wrongly hides a real problem, running wrongly
	// costs a few cents.
	existenceKey, existenceKind := existenceTargetFor("", c.WorkloadKey, c.ObjectKey)
	if gone, reason := p.objectIsGone(ctx, incidentCandidate{ID: c.ID, ClusterID: c.ClusterID, ObjectKey: existenceKey}); gone {
		reason = fmt.Sprintf("%s (%s)", reason, existenceKind)
		if err := orchestrator.SetState(ctx, tx, c.ID, orchestrator.StateResolved); err != nil {
			// Not fatal: leave the incident alone and let a later tick or a human
			// deal with it. Failing here would also skip marking the attempt,
			// putting this incident back in the candidate pool to be re-checked
			// forever.
			logger.ErrorContext(ctx, "the incident's object is gone but resolving the incident failed",
				slog.String("reason", reason), logging.Err(err))
			return
		}
		// Marked attempted for the same reason a real investigation is: this
		// incident must not return to the candidate pool every tick.
		if _, err := tx.Exec(ctx, `UPDATE incidents SET auto_analysis_attempted_at = now() WHERE id = $1`, c.ID); err != nil {
			logger.ErrorContext(ctx, "marking the incident as auto-analysis-attempted failed", logging.Err(err))
			return
		}
		if err := tx.Commit(ctx); err != nil {
			logger.ErrorContext(ctx, "committing the resolve-as-gone transaction failed", logging.Err(err))
			return
		}
		logger.InfoContext(ctx, "incident resolved without investigating: its object no longer exists",
			slog.String("reason", reason))
		if p.events != nil {
			p.events.Publish(events.IncidentUpdated(c.ID, c.ClusterID))
		}
		return
	}

	userPrompt, err := buildUserPrompt(ctx, tx, c, p.knowledge)
	if err != nil {
		logger.ErrorContext(ctx, "building the investigation prompt failed", logging.Err(err))
		return
	}

	// Detected -> Investigating, same real state-machine wiring
	// internal/api/analyze.go's handleAnalyzeIncident applies for a manual
	// click — see orchestrator.MarkInvestigating's doc comment for why this
	// is unconditional. This poller only ever attempts an incident once
	// (auto_analysis_attempted_at, per this package's own retry-policy
	// comment above) and only ever selects incidents with no analysis yet
	// (selectEligible), so in practice this always fires from Detected —
	// but calling the same unconditional helper handleAnalyzeIncident uses
	// keeps that an observation, not an assumption this code depends on.
	if err := orchestrator.MarkInvestigating(ctx, tx, tenantID, c.ClusterID, c.ID); err != nil {
		logger.ErrorContext(ctx, "marking the incident as Investigating failed", logging.Err(err))
		return
	}

	// PROJECT.md T10 / lld/01-threat-model.md T12, SR-13: reserve this
	// investigation's projected cost against today's spend ceiling in the
	// SAME transaction that just claimed the incident (MarkInvestigating,
	// immediately above) — see api.ReserveSpend's own doc comment for why
	// this, and not collectEligible's own earlier once-per-sweep check
	// above, is what actually closes the check-then-act race: this poller
	// runs up to maxConcurrentInvestigations investigations at once
	// (runWaves), each in its own transaction, and collectEligible's check
	// only ever reflects spend as of the START of the sweep — two
	// candidates in the SAME wave could otherwise both pass it and, only
	// together, spend past the ceiling. If ReserveSpend refuses (ok
	// false), this function returns without committing anything: the
	// deferred tx.Rollback above undoes MarkInvestigating too, so the
	// incident is left exactly as it was (still Detected, still eligible
	// on a later tick) rather than stranded mid-claim with nothing about
	// to happen.
	cfg, err := settings.Resolve(ctx, tx)
	if err != nil {
		logger.ErrorContext(ctx, "resolving settings for the spend reservation failed", logging.Err(err))
		return
	}
	spendReservation, reserveOK, err := api.ReserveSpend(ctx, tx, cfg, tenantID, c.ID, c.ClusterID)
	if err != nil {
		logger.ErrorContext(ctx, "reserving projected spend failed", logging.Err(err))
		return
	}
	if !reserveOK {
		logger.WarnContext(ctx, "skipped: reserving this investigation's projected cost would reach the daily spend ceiling. Checked atomically per incident, not once per sweep, so concurrent investigations cannot collectively exceed it. A human can still run POST /incidents/{id}/analyze; this retries next tick",
			slog.Float64("daily_spend_ceiling_usd", *cfg.DailySpendCeilingUsd))
		return
	}

	clusterID := c.ClusterID

	// BACKLOG.md C11: bound the ctx every CallToolWithRetry call below sees
	// to the SAME deadline the investigation itself is working against,
	// mirroring internal/api/analyze.go's handleAnalyzeIncident (workCtx)
	// exactly — see that call site's own comment for the full reasoning.
	// Before this, investigateOne handed callTool the poller's own
	// long-lived, no-deadline ctx (Run/sweep's), so a single hung tool call
	// could always spend its FULL toolCallTimeout+resultGraceWindow, and a
	// retry its full budget again, regardless of how much of this
	// investigation's own timeLimit was already gone — exactly the gap the
	// manual path had already closed and this automatic path had not.
	//
	// context.WithTimeout, not a new parameter threaded through callTool:
	// gateway.CallToolWithRetry/callToolAttemptWithGrace already derive
	// their own per-attempt timeout via context.WithTimeout(ctx,
	// toolCallTimeout), which takes the EARLIER of that and ctx's own
	// deadline — so once ctx itself carries an absolute deadline tied to
	// this investigation's remaining time, every tool call automatically
	// gets whichever is shorter, and a retry whose ctx has already expired
	// is skipped outright (callToolAttemptWithGrace's leading ctx.Err()
	// check) rather than sending a second, doomed ToolRequest. No change to
	// internal/gateway itself: it already composes correctly with a
	// tightening outer deadline, the exact property
	// tools_retry_outer_context_test.go's
	// TestCallToolWithRetry_TooShortOuterDeadlineDefeatsRetry protects for
	// the opposite (too-tight, single-attempt-sized) case — this fix relies
	// on the SAME mechanism from the other direction, deliberately: an
	// investigation-sized deadline (minutes) is always far larger than one
	// attempt's own bound (seconds), so it only ever binds once the
	// investigation is genuinely almost out of time.
	//
	// cfg is resolved again here, fresh, rather than threaded down from
	// collectEligible's own settings.Resolve call a moment ago in the same
	// sweep tick — same "resolved fresh per call, never cached" discipline
	// internal/llm.resolveBounds' own doc comment describes, and the same
	// double-resolve analyze.go already accepts (Investigate resolves cfg
	// AGAIN internally to get the same timeLimit for its own loop bound).
	// A resolve failure here is not fatal to the investigation — it only
	// costs this fix's own protection, so investigateOne falls back to the
	// poller's ordinary ctx exactly as before rather than aborting.
	toolCtx := ctx
	if cfg, cfgErr := settings.Resolve(ctx, tx); cfgErr != nil {
		logger.WarnContext(ctx, "resolving settings for the investigation deadline failed; continuing without a bounded tool-call context", logging.Err(cfgErr))
	} else {
		var cancelTool context.CancelFunc
		toolCtx, cancelTool = boundedInvestigationContext(ctx, cfg)
		defer cancelTool()
	}

	// CallToolWithRetry — same fix, same reasoning, as
	// internal/api/analyze.go's manual-analyze callback (BACKLOG.md C5 /
	// BUGS.md 96): this is the automatic-investigation mirror of that exact
	// loop, offering the identical six read-only tools, so a transient
	// tunnel stall deserves the identical bounded resilience rather than
	// silently burning this poller's own investigation for nothing.
	clusterCallTool := func(callCtx context.Context, tool string, args json.RawMessage) (json.RawMessage, error) {
		return p.gw.CallToolWithRetry(callCtx, clusterID, tool, args)
	}

	// lld/08-remediation-contracts.md §12: the route is computed before the
	// model proposes anything, same as the manual path — see
	// api.ResolveIncidentRoute's own doc comment for why the ownership fetch
	// moved here from after the investigation. grants is nil: this poller
	// runs unattended, with no human actor to hold a capability.
	routeDecision, err := api.ResolveIncidentRoute(ctx, tx, p.gw, p.scmStore, c.ID, clusterID, nil)
	if err != nil {
		logger.ErrorContext(ctx, "resolving the incident's resolution route failed", logging.Err(err))
		return
	}

	// BACKLOG.md C4: same resolve-once-use-twice discipline as the manual
	// path (internal/api/analyze.go) — see api.ClusterDryRunAvailable's own
	// doc comment.
	// BACKLOG.md F22 piece 1: dispatched by tool name, exactly as the manual
	// path does — repository tools served hub-side against a scope resolved
	// from this incident's own binding, everything else over the tunnel. An
	// unattended analysis must have the identical tool surface to a
	// human-triggered one, or the two paths silently produce
	// different-quality investigations of the same incident.
	//
	// After ResolveIncidentRoute for the same load-bearing reason the manual
	// path documents: that call is what resolves and caches
	// `incidents.ownership`, which IncidentRepoScope reads. This poller only
	// ever picks incidents with no analysis yet, so it hits the
	// first-analysis case EVERY time — getting this order wrong here would
	// have withheld the repository tools from every unattended investigation
	// there has ever been.
	repoScope := api.IncidentRepoScope(ctx, tx, p.scmStore, c.ID)
	var repoReader *repotools.Reader
	// readLog is BACKLOG.md F25's per-investigation truncation-provenance
	// record — same "one fresh log per investigation, attached to the Reader
	// it belongs with" discipline internal/api/analyze.go's manual path
	// follows, consumed below by the identical
	// api.RefuseTruncatedRepositoryProposals call that path makes, so an
	// unattended analysis is refused the identical unsafe proposals a
	// human-triggered one would be.
	var readLog *repotools.ReadLog
	if repoScope.Valid() {
		// BACKLOG.md F28 finding 1: same registry-backed Begin/End this
		// package's manual-analysis counterpart (internal/api/analyze.go)
		// uses, and for the identical reason — see that call site's own
		// comment and repotools.ReadLogRegistry's doc comment.
		readLog = p.readLogs.Begin(c.ID)
		defer p.readLogs.End(c.ID)
		repoReader = repotools.NewReader(repoScope, p.checkouts).SetReadLog(readLog)
	}
	callTool := api.ChangesToolCallback(p.db, clusterID, api.RepoToolCallback(repoReader, clusterCallTool))

	dryRunAvailable := api.ClusterDryRunAvailable(ctx, tx, clusterID)
	// BACKLOG.md C4: same resolve-once-use-twice discipline as dryRunAvailable
	// above, applied to query_metrics — see api.ClusterMetricsAvailable's own
	// doc comment.
	metricsAvailable := api.ClusterMetricsAvailable(ctx, tx, clusterID)
	repoReadable := repoReader != nil
	// Declared here, outside the persisted-analysis branch below, so the
	// post-commit knowledge.TriggerAsync call further down can tell "an
	// analysis was actually persisted this tick" (BACKLOG.md L2) from "the
	// investigation itself failed, nothing to embed" — its zero value is
	// exactly that "nothing to embed" signal.
	var analysisID string
	// toolCtx, not ctx: see its own construction above (BACKLOG.md C11) —
	// bounds this call, and every tool call it makes through callTool, to
	// this investigation's own remaining time rather than the poller's
	// long-lived, no-deadline ctx.
	// PROJECT.md T11: same wrap-at-the-call-site instrumentation as
	// internal/api's manual analyze handler — see AnalysisOutcomeLabel's own
	// doc comment for why both share one outcome mapping.
	investigateStarted := time.Now()
	result, investigateErr := p.llmProvider.Investigate(toolCtx, llm.Target{ClusterID: c.ClusterID, IncidentID: c.ID, DryRunAvailable: dryRunAvailable, MetricsAvailable: metricsAvailable, RepoReadable: repoReadable}, llm.SystemPrompt(routeDecision.Route, dryRunAvailable, repoReadable, metricsAvailable), userPrompt, callTool)
	metrics.AnalysisDurationSeconds.Observe(time.Since(investigateStarted).Seconds(), "auto", api.AnalysisOutcomeLabel(investigateErr))
	if investigateErr != nil {
		// The investigation did not happen. This branch used to log that fact
		// and fall through to marking the incident attempted, leaving it in
		// Investigating — which the candidate query excludes, so the incident
		// was never retried and never moved again by anything. See the package
		// doc comment's retry policy for the full shape of that failure.
		//
		// recordAnalysisFailure returns the incident to Detected, persists the
		// attempt and its reason (in the row AND on the incident's own
		// timeline), and decides whether a later tick tries again. It returns
		// here rather than falling through, because the unconditional
		// auto_analysis_attempted_at write below is precisely the "this
		// incident is finished with the automatic path" claim that must not be
		// made for a failure that is still going to be retried.
		//
		// The reservation is released, not settled: no chargeable outcome was
		// ever produced, so the projected headroom it held goes back to the
		// ceiling for the rest of today's sweeps (ReleaseSpendReservation is a
		// no-op if ReserveSpend didn't actually write a row — see
		// SpendReservation.Active).
		if err := api.ReleaseSpendReservation(ctx, tx, spendReservation); err != nil {
			logger.ErrorContext(ctx, "releasing the spend reservation failed", logging.Err(err))
		}
		p.recordAnalysisFailure(ctx, tx, tenantID, c, investigateErr)
		if err := tx.Commit(ctx); err != nil {
			logger.ErrorContext(ctx, "committing the failed-analysis record failed", logging.Err(err))
			return
		}
		if p.events != nil {
			p.events.Publish(events.IncidentUpdated(c.ID, c.ClusterID))
		}
		return
	}
	// The provider answered, so whatever earlier configuration failure armed
	// the poller-level backoff is over — clear it now rather than waiting for
	// the current window to expire on its own.
	p.noteProviderUsable()

	// BACKLOG.md F25: same refusal the manual path applies, before this
	// result is ever persisted — see
	// api.RefuseTruncatedRepositoryProposals' own doc comment.
	result = api.RefuseTruncatedRepositoryProposals(result, repoScope.SourceDir, readLog)

	// BACKLOG.md F28 finding 1: same refusal the manual path applies for a
	// plan naming a path never read at all this investigation — see
	// api.RefuseUnreadRepositoryProposals' own doc comment.
	result = api.RefuseUnreadRepositoryProposals(result, repoScope.SourceDir, readLog)

	// BUGS.md 117: same refusal the manual path applies for a plan that
	// recreates a deleted resource as a stub while removing, in the same
	// plan, the only reference to it — see
	// api.RefuseOrphanedRecreatedResourceProposals' own doc comment.
	result = api.RefuseOrphanedRecreatedResourceProposals(ctx, result, repoReader, repoScope.SourceDir)

	// PROJECT.md B147: same schema-validity refusal the manual path applies —
	// see api.RefuseSchemaInvalidRepositoryProposals' own doc comment. Fails
	// open if the cluster is unreachable.
	result = api.RefuseSchemaInvalidRepositoryProposals(ctx, p.gw, c.ClusterID, result)

	analysisID = domain.NewID(domain.PrefixAnalysis)
	costUSD, err := api.PersistAnalysis(ctx, tx, tenantID, analysisID, c.ID, c.ClusterID, result, time.Now(), api.TriggeredByAuto)
	if err != nil {
		// Deliberately does NOT fall through to marking c attempted:
		// the investigation itself succeeded but its result failed to
		// persist (a real bug or a transient DB error), so this
		// incident should be retried on a later tick rather than
		// silently losing the analysis forever.
		//
		// Released, not settled, for the same reason as the investigateErr
		// branch above: no real cost was ever durably recorded this attempt
		// (the analyses row this reservation was meant to reconcile against
		// never landed), so nothing chargeable exists to settle it to. A
		// retry on a later tick reserves fresh.
		if relErr := api.ReleaseSpendReservation(ctx, tx, spendReservation); relErr != nil {
			logger.ErrorContext(ctx, "releasing the spend reservation failed", logging.Err(relErr))
		}
		logger.ErrorContext(ctx, "persisting the analysis failed", logging.Err(err))
		return
	}
	// Reconcile the reservation to what PersistAnalysis actually wrote.
	// costBasis mirrors PersistAnalysis's own "empty CostBasis means the api
	// backend, which is always metered" rule (internal/api/analyze.go) —
	// duplicated here rather than having PersistAnalysis return it, since
	// this is the only caller anywhere that needs the basis, not just the
	// dollar figure, and analyze.go's own manual path never reserves in the
	// first place. Only a 'metered' basis is chargeable: TodaySpendUSD sums
	// exactly that basis and nothing else, so settling any other basis at
	// its face value would let this reservation hold ceiling headroom that
	// no future TodaySpendUSD call will ever see repaid — the same
	// non-chargeable-basis gap ActiveProviderSpendCountable already exists
	// to name, just re-applied here at the per-run level rather than the
	// per-provider one, in case a nominally countable provider ever returns
	// a non-metered basis for one run.
	costBasis := result.CostBasis
	if costBasis == "" {
		costBasis = llm.CostBasisMetered
	}
	// PROJECT.md T11: costUSD is exactly what PersistAnalysis just wrote,
	// and costBasis is the identical effective basis this function already
	// needed for the spend-reservation settlement immediately below — no
	// second cost computation, no second basis decision.
	metrics.AnalysisCostUSDTotal.Add(costUSD, "auto", costBasis)
	logger.InfoContext(ctx, "automatic investigation complete",
		slog.String("analysis_id", analysisID),
		slog.String("model", result.Model),
		slog.String("status", result.Status),
		slog.Int("iterations", result.Iterations),
		slog.Int64("duration_ms", int64(result.DurationMs)),
		slog.Float64("cost_usd", costUSD))
	if err := api.SettleSpendReservation(ctx, tx, spendReservation, costUSD, costBasis == llm.CostBasisMetered); err != nil {
		logger.ErrorContext(ctx, "settling the spend reservation failed", logging.Err(err))
	}
	// §12.5's fail-closed check, same as the manual path.
	result = orchestrator.EnforceRoute(result, routeDecision.Route)

	// BACKLOG.md F27: same honest-note guard the manual path applies,
	// at the same point (after EnforceRoute has settled whether a plan
	// really survives) — see api.FlagMissingRunnableNextStep's own doc
	// comment.
	api.FlagMissingRunnableNextStep(ctx, tx, tenantID, c.ClusterID, c.ID, result)

	// Same orchestrator.ApplyAnalysisResult call
	// handleAnalyzeIncident makes for a manual analysis — see that
	// function's own comment for why this is the one, shared place
	// this decision is made, for both call sites.
	if _, err := orchestrator.ApplyAnalysisResult(ctx, tx, tenantID, c.ClusterID, c.ID, analysisID, result, routeDecision); err != nil {
		logger.ErrorContext(ctx, "applying the analysis result to the incident failed", logging.Err(err))
		return
	}

	if _, err := tx.Exec(ctx, `UPDATE incidents SET auto_analysis_attempted_at = now() WHERE id = $1`, c.ID); err != nil {
		logger.ErrorContext(ctx, "marking the incident as auto-analysis-attempted failed", logging.Err(err))
		return
	}
	if err := tx.Commit(ctx); err != nil {
		logger.ErrorContext(ctx, "committing the investigation transaction failed", logging.Err(err))
		return
	}
	// BACKLOG.md L2 (storage half, decided 2026-08-30): the exact mirror of
	// internal/api/analyze.go's handleAnalyzeIncident calling
	// knowledge.TriggerAsync after ITS commit — analysisID is only non-empty
	// when the investigation succeeded AND PersistAnalysis actually wrote a
	// row this tick (see its declaration above), so a failed/skipped
	// investigation triggers nothing to embed.
	if analysisID != "" {
		p.knowledge.TriggerAsync(tenantID, c.ClusterID, analysisID)
	}
	// Unlike the HTTP handlers (analyze.go/approvals.go/clusters.go), this
	// poller owns and commits its own transaction end to end, so — unlike
	// those call sites — it CAN publish strictly after a real, observed
	// commit rather than "after every fallible step succeeded" as a proxy.
	if p.events != nil {
		p.events.Publish(events.IncidentUpdated(c.ID, c.ClusterID))
	}
}

// recordAnalysisFailure is the honest half of a failed automatic
// investigation: what the incident looks like afterwards, what is written down
// about why, and whether anything will ever try again.
//
// # What it fixes
//
// The failure path used to be a single log.Printf followed by an unconditional
// `auto_analysis_attempted_at = now()`. Three separate things went wrong at
// once, and each hid the next:
//
//   - The incident stayed in Investigating, which the UI renders as "an
//     investigation is running now, gathering live evidence from the cluster.
//     This page updates automatically when it finishes." It never finished.
//   - candidateQuery excludes Investigating, so it was never re-selected.
//   - attempted_at was stamped anyway, so even if it HAD been re-selected it
//     would have been filtered out.
//
// A provider failure therefore produced an incident that looked permanently
// mid-investigation and could not be moved by anything but a human noticing.
//
// # The two classes, and why they are treated differently
//
// A transient failure (a rate limit, a provider 5xx, a tunnel stall) is about
// this attempt. It gets a bounded retry: the attempt is counted, a backoff is
// set, and after maxAutoAnalysisAttempts the automatic path gives up and says
// so.
//
// A configuration failure (llm.ErrNotConfigured — "no usable AI provider") is
// about the HUB. Charging it to this incident would spend a retry budget on a
// fact that has nothing to do with this incident, and would do the same to
// every other eligible incident in turn until the backlog was silently used
// up. So the attempt is NOT counted and no backoff is written to the row; the
// poller stands itself down instead (noteProviderUnusable), which is bounded,
// loud, and self-healing.
//
// Both classes return the incident to Detected and write the reason to
// auto_analysis_last_error and to the incident's own timeline. Detected is the
// honest state in both: no analysis exists and nothing is running, which is
// exactly what it means. The attempt is not erased by that — the timeline
// keeps InvestigationStarted followed by AutoAnalysisFailed, which is a more
// complete record than the stuck Investigating state ever was.
//
// Errors are logged, never returned: this runs inside investigateOne's own
// transaction, which is committed by the caller, and the caller has already
// lost this incident's investigation. Failing to write the bookkeeping must
// not also lose the state rollback, so each step is independent.
func (p *Poller) recordAnalysisFailure(ctx context.Context, tx pgx.Tx, tenantID string, c incidentCandidate, cause error) {
	configuration := errors.Is(cause, llm.ErrNotConfigured)
	reason := truncateForRecord(cause.Error())

	// State first: it is the part an operator actually sees, and it must land
	// even if the bookkeeping below fails.
	//
	// An illegal transition here means the incident left Investigating while
	// this investigation was running — a human dismissed it, most likely. That
	// is not an error worth shouting about and there is nothing left to record
	// against it, so this returns rather than writing a backoff onto an
	// incident that has already moved on.
	if err := orchestrator.SetState(ctx, tx, c.ID, orchestrator.StateDetected); err != nil {
		if errors.Is(err, orchestrator.ErrIllegalTransition) {
			logger.WarnContext(ctx, "investigation failed and the incident had already left Investigating; leaving it alone",
				slog.String("cause", cause.Error()), logging.Err(err))
			return
		}
		logger.ErrorContext(ctx, "investigation failed and returning the incident to Detected also failed",
			slog.String("cause", cause.Error()), logging.Err(err))
		return
	}

	attempts := c.AutoAnalysisAttempts
	willRetry := true
	class := "transient"
	if configuration {
		class = "configuration"
		// Not counted, not backed off per-incident, and the whole sweep stands
		// down instead. See this function's doc comment and
		// noteProviderUnusable.
		p.noteProviderUnusable(c.ID, cause)
		if _, err := tx.Exec(ctx,
			`UPDATE incidents SET auto_analysis_last_error = $2 WHERE id = $1`, c.ID, reason); err != nil {
			logger.ErrorContext(ctx, "recording the analysis failure reason failed", logging.Err(err))
		}
	} else {
		attempts++
		willRetry = attempts < maxAutoAnalysisAttempts
		if willRetry {
			backoff := autoAnalysisBackoff(attempts)
			if _, err := tx.Exec(ctx,
				`UPDATE incidents
				    SET auto_analysis_attempts = $2,
				        auto_analysis_last_error = $3,
				        auto_analysis_retry_after = now() + ($4 * interval '1 second')
				  WHERE id = $1`, c.ID, attempts, reason, backoff.Seconds()); err != nil {
				logger.ErrorContext(ctx, "recording the analysis failure failed", logging.Err(err))
			}
			logger.WarnContext(ctx, "investigation failed: incident returned to Detected and will be retried",
				slog.String("cause", cause.Error()), slog.Int("attempt", attempts),
				slog.Int("max_attempts", maxAutoAnalysisAttempts), slog.Duration("retry_in", backoff))
		} else {
			// The bound is spent. attempted_at is written HERE, and only here,
			// for a transient failure: this is the one point at which "the
			// automatic path is done with this incident" becomes true.
			if _, err := tx.Exec(ctx,
				`UPDATE incidents
				    SET auto_analysis_attempts = $2,
				        auto_analysis_last_error = $3,
				        auto_analysis_retry_after = NULL,
				        auto_analysis_attempted_at = now()
				  WHERE id = $1`, c.ID, attempts, reason); err != nil {
				logger.ErrorContext(ctx, "recording the final analysis failure failed", logging.Err(err))
			}
			logger.WarnContext(ctx, "investigation failed too many times: incident returned to Detected and the automatic path is giving up on it. A person can still run POST /incidents/{id}/analyze by hand",
				slog.String("cause", cause.Error()), slog.Int("attempts", attempts))
		}
	}

	// The reason, on the incident's own history rather than only in a hub log
	// nobody is reading. This is what makes an InvestigationStarted with no
	// AnalysisCompleted after it interpretable.
	if err := timeline.Record(ctx, tx, timeline.Event{
		TenantID: tenantID, ClusterID: c.ClusterID, IncidentID: c.ID,
		Type:    timeline.EventAutoAnalysisFailed,
		Summary: autoAnalysisFailureSummary(class, reason, attempts, willRetry),
		Detail: map[string]any{
			"error":          reason,
			"attempts":       attempts,
			"willRetry":      willRetry,
			"classification": class,
		},
	}); err != nil {
		logger.ErrorContext(ctx, "recording the AutoAnalysisFailed timeline event failed", logging.Err(err))
	}
}

// autoAnalysisFailureSummary is the sentence an operator reads on the
// incident's timeline. Pure, so the wording for each of the three outcomes is
// unit-testable without a database.
//
// Worded as what it means for the reader, and never as a bare error dump: the
// first thing someone needs from this event is whether anything is still going
// to happen on its own.
func autoAnalysisFailureSummary(class, reason string, attempts int, willRetry bool) string {
	switch {
	case class == "configuration":
		return fmt.Sprintf("Automatic analysis could not run: no usable AI provider is configured on the hub (%s). This is a hub configuration problem, not a problem with this incident — automatic analysis resumes on its own once a provider is configured, and this incident keeps its full retry budget in the meantime.", reason)
	case willRetry:
		return fmt.Sprintf("Automatic analysis failed (attempt %d of %d) and will be retried: %s", attempts, maxAutoAnalysisAttempts, reason)
	default:
		return fmt.Sprintf("Automatic analysis failed %d times and has given up on this incident; nothing further will happen automatically. Run an analysis by hand to try again. Last error: %s", attempts, reason)
	}
}

// truncateForRecord bounds an error string written to the database. See
// maxRecordedErrorLength.
func truncateForRecord(s string) string {
	if len(s) <= maxRecordedErrorLength {
		return s
	}
	return s[:maxRecordedErrorLength] + "… (truncated)"
}

// boundedInvestigationContext is BACKLOG.md C11's fix, extracted as its own
// pure function (rather than left inline in investigateOne) specifically so
// autoanalyze_test.go can prove the deadline it derives actually shrinks
// with cfg.AnalysisTimeLimitSeconds, without needing a database, a
// transaction, or a real investigation to exercise it. See
// investigateOne's own call site comment for the full "why ctx, not a new
// parameter" reasoning; this function is only the arithmetic half of it.
//
// investigationCommitMargin mirrors internal/api/analyze.go's own constant
// of the same name and the same value, for the same reason: investigate()
// (internal/llm) only checks timeLimit BETWEEN model round-trips, so the
// round already under way when the deadline lands — one model completion
// plus however many tool calls it requested — still needs room to finish,
// followed by this function's caller's own persistence and commit. Not
// shared via import: this package already duplicates other analyze.go
// call-site comments verbatim rather than reaching across the package
// boundary for a three-line constant (see clusterCallTool's own comment in
// investigateOne for the established precedent).
const investigationCommitMargin = 3 * time.Minute

func boundedInvestigationContext(ctx context.Context, cfg settings.Config) (context.Context, context.CancelFunc) {
	timeLimit := llm.DefaultTimeLimit
	if cfg.AnalysisTimeLimitSeconds != nil {
		timeLimit = time.Duration(*cfg.AnalysisTimeLimitSeconds) * time.Second
	}
	return context.WithTimeout(ctx, timeLimit+investigationCommitMargin)
}

// buildUserPrompt builds the same kind of prompt
// internal/api/analyze.go's handleAnalyzeIncident builds for a manual
// request, from this incident's findings — deliberately not sharing that
// exact code (handleAnalyzeIncident's version uses the incident's cluster
// DISPLAY NAME, joined from an authenticated request's own incident-detail
// query; this poller only has the raw cluster_id, the same simplification
// internal/notify's own payload() already accepts for the identical
// reason — see its doc comment).
// buildUserPrompt delegates to llm.BuildFindingsPrompt — the same bounded
// builder internal/api/analyze.go's handler uses.
//
// This function used to hold its own copy of an unbounded findings query and
// concatenation loop, identical to the handler's. Both were replaced together:
// the prompt is passed to the CLI as one argv element, Linux caps a single
// argument at 128 KiB, and findings only ever accumulate — so any long-lived
// incident eventually became impossible to investigate, on the automatic path as
// well as the manual one. Fixing one copy and leaving the other would have left
// unattended analysis silently broken for exactly the incidents that most need
// it. See llm.BuildFindingsPrompt for the measurements.
// PROJECT.md D-Learn: retrieval (internal/knowledge.Store.RetrieveSimilar)
// runs first, in this same already-scoped transaction, and its formatted
// section is prepended to the header — same insertion point and same
// fail-open posture (log and proceed with no retrieved context) as
// internal/api/analyze.go's handleAnalyzeIncident, so the automatic and
// manual paths cannot silently diverge on this the way two independent
// findings-prompt loops already once did (see this function's own doc
// comment on that history).
func buildUserPrompt(ctx context.Context, tx pgx.Tx, c incidentCandidate, knowledgeStore *knowledge.Store) (string, error) {
	// Gated on settings.Config.RetrievalEnabled (migration 000102), default
	// false — same reasoning and the same gate internal/api/analyze.go's
	// handleAnalyzeIncident applies, so the manual and automatic paths
	// cannot silently diverge on this either. Resolved fresh here (not
	// cached), matching this package's own "no caching, no restart needed
	// for a settings change to take effect" convention elsewhere
	// (boundedInvestigationContext's identical resolve-per-call shape).
	var retrievalSection string
	if cfg, err := settings.Resolve(ctx, tx); err != nil {
		logger.WarnContext(ctx, "resolving settings for the knowledge-retrieval gate failed; proceeding without retrieved context", logging.Err(err))
	} else if cfg.RetrievalEnabled {
		if retrieved, err := knowledgeStore.RetrieveSimilar(ctx, tx, c.ID); err != nil {
			logger.WarnContext(ctx, "retrieving similar prior analyses failed; proceeding without retrieved context", logging.Err(err))
		} else {
			retrievalSection = knowledge.FormatRetrievedForPrompt(retrieved)
		}
	}
	return llm.BuildFindingsPrompt(ctx, tx, c.ID,
		retrievalSection+fmt.Sprintf("Cluster: %s\nIncident fingerprint: %s, severity: %s, seen %d time(s)\n\nFindings:\n",
			c.ClusterID, c.Fingerprint, c.Severity, c.OccurrenceCount))
}

// objectIsGone reports whether the object an incident is about no longer exists
// in its cluster, plus a human-readable reason for the log.
//
// Deliberately conservative: it returns true ONLY on a clear not-found answer.
// Every other outcome — no object key, an unparseable key, a tool error, an
// ambiguous response — returns false, so the investigation proceeds. The
// asymmetry is the point: wrongly skipping an investigation hides a real
// problem, while wrongly running one costs a few cents. A flaky check must
// never be able to silently close real incidents.
//
// The key it is asked about is `gvk|namespace|name`, the same tuple
// describe_resource takes. Both callers resolve WHICH key that is through
// existenceTargetFor rather than reaching for incidents.object_key directly:
// object_key is the object the FINDING named, which is a Pod for most
// incidents, and a pod is replaced by every rollout, drain, eviction and
// restart — so asking about it measured Kubernetes rather than the fault. See
// existenceTargetFor.
func (p *Poller) objectIsGone(ctx context.Context, c incidentCandidate) (bool, string) {
	_, gone, reason := p.readTarget(ctx, c.ClusterID, c.ObjectKey)
	return gone, reason
}

// readTarget asks the cluster for the object a `gvk|namespace|name` key names.
// It returns the object as describe_resource served it (already redacted at
// capture), or gone=true with a reason on a definitive not-found. Anything
// else, including a malformed key or an unreachable cluster, is neither: no
// object and not gone.
func (p *Poller) readTarget(ctx context.Context, clusterID, key string) (object json.RawMessage, gone bool, reason string) {
	if key == "" {
		return nil, false, ""
	}
	parts := strings.SplitN(key, "|", 3)
	if len(parts) != 3 || parts[2] == "" {
		return nil, false, ""
	}
	gvk, namespace, name := normalizeNodeKey(parts[0]), parts[1], parts[2]
	if gvk == "v1/Node" {
		namespace = ""
	}
	args, err := json.Marshal(map[string]string{"gvk": gvk, "namespace": namespace, "name": name})
	if err != nil {
		return nil, false, ""
	}
	out, err := p.gw.CallTool(ctx, clusterID, "describe_resource", args)
	if err != nil {
		// Matching on the error text is unavoidable here: the tool returns a
		// sanitized string, not a typed Kubernetes error (internal/agent's
		// Execute deliberately does not leak API error structure). Narrow
		// matching, and anything unrecognised falls through to "not gone".
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "not found") || strings.Contains(msg, "notfound") {
			return nil, true, fmt.Sprintf("%s %s/%s no longer exists", gvk, namespace, name)
		}
		return nil, false, ""
	}
	var described struct {
		Object json.RawMessage `json:"object"`
	}
	if err := json.Unmarshal(out, &described); err != nil || len(described.Object) == 0 {
		return nil, false, ""
	}
	return described.Object, false, ""
}

// Stale-object closure: the incident-lifecycle half of this package.
//
// # The problem, measured rather than supposed
//
// A live audit of this deployment found **26 of 36 open incidents were about
// objects that no longer existed** — 72%, and almost all of them Pods. Some were
// from test campaigns weeks earlier; two were from a fix that had just succeeded,
// where the pod was replaced by a new ReplicaSet and the incident kept naming the
// dead one. Nothing in the product could close any of them.
//
// That is not untidiness. An operator looking at that queue cannot tell which
// entries are real, so the queue stops being read, which defeats the whole point
// of having one.
//
// # Why the check already existed and still did not run
//
// objectIsGone, and the decision to resolve on a definitive not-found, have been
// in this file since WORKLOG §100 — but only inside investigateOne, which needs
// auto-analysis ENABLED and `auto_analysis_attempted_at IS NULL`. Auto-analysis is
// off by default and off on this deployment, so the check never ran, and an
// incident that had already been analysed was ineligible even when it was on.
//
// So this adds no new policy. It runs the existing, deliberately conservative
// check on its own schedule, because deciding an incident is stale is a
// lifecycle question and has nothing to do with whether the operator pays for
// automatic investigation.
//
// # What it asks, and what it refuses to touch
//
// Two things about that original design were wrong in the same direction — an
// absence of evidence read as a positive result — and both are corrected here:
//
//   - It asked whether the incident's ORIGINAL object still existed, and that
//     object is a Pod for the great majority of incidents. Pods are replaced by
//     every rollout, drain, eviction and restart, so the question mostly
//     measured Kubernetes rather than the fault. It now asks about the object
//     that would still matter — see existenceTarget.
//   - Its candidate set included states with an action in flight, so an incident
//     with a real pull request open could be closed because a pod name went
//     away, leaving that pull request orphaned. Nothing in ARGUS closes a pull
//     request when its incident closes. See staleCandidateQuery.
//
// This is the only thing in the product that closes an incident with no
// analysis, no approval and no human, so what it refuses to touch is as much
// the feature as what it closes.
//
// # Why it lives in this package
//
// It belongs conceptually with orchestrator.ValidationSweeper, and cannot go
// there: the check needs gateway.CallTool, and internal/gateway already imports
// internal/orchestrator, so that direction is an import cycle. This package has
// the gateway, owns the check, and already runs a poller. The alternative was
// exporting objectIsGone and a second package to call it, which spreads the
// decision over more places without making it clearer.

// DefaultStaleSweepInterval is how often the stale-object sweep runs. Slow on
// purpose: an incident about a deleted object is wrong but not urgent, and each
// pass costs one tunnel call per candidate.
const DefaultStaleSweepInterval = 10 * time.Minute

// staleObjectGracePeriod is how long an incident must have gone without a new
// finding before its object is even checked.
//
// Not about correctness — a gone object is gone — but about not racing a normal
// rollout. A Deployment rolling replaces pods, and for a few seconds the old pod
// is deleted while the incident about it is still current; the replacement's own
// finding will re-attach or open, and the detector's resend cooldown is five
// minutes. Waiting twice that means a check only ever runs on an incident nothing
// has confirmed recently.
const staleObjectGracePeriod = 10 * time.Minute

// maxStaleChecksPerSweep bounds one pass. A deployment that has accumulated
// hundreds of stale incidents works through them over successive sweeps rather
// than making hundreds of tunnel calls at once; staleCheckLog (cleared.go)
// rotates which ones each pass reaches.
const maxStaleChecksPerSweep = 25

// RunStaleObjectSweeper ticks until ctx is cancelled, closing incidents whose
// object has definitively gone. Blocks — cmd/hub runs it in its own goroutine.
//
// Runs unconditionally, unlike Run: this is not analysis and costs no model
// tokens, so gating it on the auto-analysis setting is what produced the 72%
// above.
func (p *Poller) RunStaleObjectSweeper(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweepCtx, _ := logging.NewUnitOfWork(ctx)
			start := time.Now()
			err := p.sweepStaleObjects(sweepCtx)
			metrics.ObserveSweeperRun("stale_object", time.Since(start), err)
			if err != nil {
				logger.ErrorContext(sweepCtx, "stale-object sweep failed", logging.Err(err))
			}
		}
	}
}

// staleCandidate is one open incident worth asking about.
type staleCandidate struct {
	ID        string
	ClusterID string
	ObjectKey string
	State     string
	// WorkloadKey is incidents.workload_key (migration 000042, written by
	// replicagroup.Recompute) — `apps/v1/Deployment|ns|name`, the workload the
	// incident's object belongs to. Empty for an object with no resolvable
	// owner (a bare Pod, a Service, a Node).
	WorkloadKey string
	// TargetKey is the object the incident's newest live remediation
	// recommendation would act on, in the same `gvk|namespace|name` shape,
	// or empty when there is no such recommendation. See existenceTarget.
	TargetKey string
	// LastSeen is incidents.last_seen when the candidate was selected: the
	// clock the cleared-incident check measures quiet from, and what it
	// re-checks under the row lock before closing (cleared.go).
	LastSeen time.Time
}

// existenceTarget is the object this incident is really about — the one whose
// disappearance would mean there is nothing left to act on.
//
// # Why this is not object_key
//
// It used to be, and that was the bug. incidents.object_key is the object the
// FINDING named, which for the great majority of incidents is a Pod. Pods are
// replaced constantly and by design: every Deployment rollout, every node
// drain, every eviction, every restart replaces the pod name the incident
// carries. So "the original object no longer exists" is, for a pod-keyed
// incident, mostly a statement about Kubernetes rather than about the fault —
// and this sweeper was reading it as "there is nothing here any more" and
// closing the incident.
//
// # The order, and why
//
//  1. The remediation target, when a live recommendation exists. That is
//     literally the object ARGUS proposes to act on; if it is still there, the
//     proposed fix still has something to act on, whatever became of the pod
//     that first reported the symptom.
//  2. The workload key. `apps/v1/Deployment|ns|name` is "the pods of one
//     workload" — exactly the identity that survives the replacement in the
//     paragraph above, and the same key validation.go's siblingStillFailing
//     already uses for the same reason.
//  3. The object key, only when neither of the above exists. A bare Pod, a
//     Service or a Node has no owner and no plan, and then the object's own
//     name IS its identity — which is the case the original check was right
//     about, and is preserved unchanged.
//
// Checking the workload rather than the pod is also strictly SAFER in the
// closing direction: if a Deployment is gone, its pods are necessarily gone
// too, so nothing that used to close correctly stops closing. What stops is
// closing an incident whose workload is alive and, quite possibly, still
// broken under a new pod name.
func (c staleCandidate) existenceTarget() (key, kind string) {
	return existenceTargetFor(c.TargetKey, c.WorkloadKey, c.ObjectKey)
}

// existenceTargetFor is the rule itself, shared by both places in this package
// that ask "does the thing this incident is about still exist?" — the stale
// sweep (staleCandidate.existenceTarget) and investigateOne's own pre-flight
// skip. Both used to ask about the object key alone, and both closed the
// incident on a definitive not-found, so both had the same defect; one rule
// means they cannot drift back apart.
func existenceTargetFor(targetKey, workloadKey, objectKey string) (key, kind string) {
	switch {
	case targetKey != "":
		return targetKey, "the object its proposed fix targets"
	case workloadKey != "":
		return workloadKey, "the workload it belongs to"
	default:
		return objectKey, "the object it names"
	}
}

// staleCandidateQuery selects open incidents that name an object, have been
// quiet for the grace period, and have NOTHING IN FLIGHT that closing them
// would strand.
//
// # The exclusions, in two groups
//
// Another writer owns the state:
//
//   - Executing has a mutation in flight.
//   - Investigating has an analysis in flight, and this package's own
//     candidateQuery excludes it for the same reason. (Resolved is not even a
//     legal transition out of Investigating, so this sweeper could only ever
//     have produced a refused transition and a confusing log line.)
//   - Validating is where "the object is gone" is genuinely ambiguous: a
//     workload ARGUS just patched rolls its pods, so the pod named by the
//     incident disappearing is the EXPECTED result of a successful fix.
//     Closing on that basis would bypass the validation sweeper's grace period
//     and its recurrence check; Validating has its own, better-informed
//     closure path.
//
// An ACTION is in flight, and closing the incident would abandon it:
//
//   - AwaitingMerge means a real pull request is open, against a real
//     repository, waiting on a human. Closing the incident does not close the
//     pull request — nothing does — so the PR is simply orphaned: it stays
//     open, still proposing a change, with the incident that explains why it
//     exists marked Resolved. That was reachable purely because a pod name went
//     away, which is the ordinary consequence of the very rollout the PR is
//     waiting for.
//   - AwaitingApproval means a signed plan is queued for a decision, and the
//     unattended executor's own candidate query keys on exactly that state.
//     Closing the incident silently withdraws a question a human was asked.
//
// Failed and Reopened are deliberately NOT excluded: neither has anything in
// flight (the execution is over; the symptom came back), and both are ordinary
// candidates for "the thing this was about is genuinely gone". What they needed
// was not an exclusion but a better question — see existenceTarget.
//
// # The open-pull-request predicate
//
// The AwaitingMerge exclusion above is a state check, and states can be moved
// by other paths. The pr_* predicate is the structural version of the same
// rule: an incident with a pull request that is neither merged nor closed has
// an open pull request, whatever state anyone put it in, and this sweeper does
// not close it. Belt and braces on purpose — orphaning a live change proposal
// is not a failure mode worth leaving to a state name.
//
// The LEFT JOIN LATERAL supplies existenceTarget's first choice: the newest
// non-superseded recommendation's target. remediation_recommendations carries a
// tenant-scope RLS policy only (no restrictive cluster-scope policy), so it is
// visible under this sweep's fleet-wide, empty-cluster-list scope — unlike
// cluster_facts, whose restrictive policy makes exactly this shape of join read
// as zero rows (see validation.go's reportedCooldowns for that trap).
const staleCandidateQuery = `
	SELECT i.id, i.cluster_id, i.object_key, i.state,
	       COALESCE(i.workload_key, ''),
	       COALESCE(rec.target_gvk || '|' || COALESCE(rec.target_namespace, '') || '|' || rec.target_name, ''),
	       i.last_seen
	  FROM incidents i
	  LEFT JOIN LATERAL (
	    SELECT target_gvk, target_namespace, target_name
	      FROM remediation_recommendations
	     WHERE incident_id = i.id AND superseded_at IS NULL
	     ORDER BY created_at DESC
	     LIMIT 1
	  ) rec ON true
	 WHERE i.state NOT IN ('Resolved', 'Dismissed', 'Executing', 'Validating',
	                       'Investigating', 'AwaitingApproval', 'AwaitingMerge',
	                       -- 'Expired' is already closed (PROJECT.md T2), and
	                       -- StateExpired's only allowed edge is to
	                       -- StateDetected, so a stale-object closure could
	                       -- never be applied to one. Kept in sync with
	                       -- staleClosureBlocked below, per this query's own
	                       -- note that the two answer the same question at two
	                       -- different moments.
	                       'Expired')
	   AND (i.pr_number IS NULL OR i.pr_merged_at IS NOT NULL OR i.pr_closed_unmerged_at IS NOT NULL)
	   AND i.archived_at IS NULL
	   AND i.object_key IS NOT NULL AND i.object_key <> ''
	   AND i.last_seen < now() - ($1 * interval '1 second')
	 ORDER BY i.last_seen ASC
	 LIMIT $2`

// subjectGoneCloses reports whether an incident is closed when the object it
// is about (its workload, or the object itself when it has none) is gone. Only
// AwaitingApproval reaches that question here: every other state was already
// closed by the gone check, which AwaitingApproval skips because its plan's
// target is a pod a rollout replaces.
func subjectGoneCloses(state string) bool {
	return state == orchestrator.StateAwaitingApproval
}

// awaitingApprovalCandidateQuery selects incidents waiting on an approval
// that have been quiet for the grace period, with no pull request open. They
// are never closed because a plan's target pod went away (a rollout replaces
// it); only by the health of the workload the incident is about (cleared.go),
// or because that workload, or the object itself when it has none, is gone.
// Same columns as staleCandidateQuery.
const awaitingApprovalCandidateQuery = `
	SELECT i.id, i.cluster_id, COALESCE(i.object_key, ''), i.state,
	       COALESCE(i.workload_key, ''), '', i.last_seen
	  FROM incidents i
	 WHERE i.state = 'AwaitingApproval'
	   AND (i.pr_number IS NULL OR i.pr_merged_at IS NOT NULL OR i.pr_closed_unmerged_at IS NOT NULL)
	   AND i.archived_at IS NULL
	   AND (COALESCE(i.workload_key, '') <> '' OR COALESCE(i.object_key, '') <> '')
	   AND i.last_seen < now() - ($1 * interval '1 second')
	 ORDER BY i.last_seen ASC
	 LIMIT $2`

// sweepStaleObjects runs one pass. Candidate gathering happens in its own short
// transaction, then each incident is checked and closed independently — the same
// shape as sweep/investigateOne, and for the same reason: one transaction held
// open across many tunnel calls would be worse than pointless.
func (p *Poller) sweepStaleObjects(ctx context.Context) error {
	all, tenantID, err := p.collectStaleCandidates(ctx)
	if err != nil {
		return err
	}
	// A disconnected cluster cannot answer, and readTarget treats an
	// unanswerable question as "not gone". Filtered before picking, so a
	// disconnected cluster's backlog does not use up this pass's checks.
	connected := all[:0:0]
	for _, c := range all {
		if p.gw.IsConnected(c.ClusterID) {
			connected = append(connected, c)
		}
	}
	now := time.Now()
	candidates := p.staleChecks.pick(connected, maxStaleChecksPerSweep, now)
	quiet := orchestrator.QuietPeriods(ctx, p.db, tenantID, candidateClusterIDs(candidates))
	for _, c := range candidates {
		// The question is asked about the object that would still MATTER, not
		// about the pod name the finding happened to carry — see
		// existenceTarget. This is the difference between "this workload is
		// gone, there is nothing to act on" and "Kubernetes replaced a pod",
		// which the old check could not tell apart.
		target, kind := c.existenceTarget()
		var object json.RawMessage
		if c.State != orchestrator.StateAwaitingApproval {
			var gone bool
			var reason string
			object, gone, reason = p.readTarget(ctx, c.ClusterID, target)
			if gone {
				p.closeStaleIncident(ctx, c, fmt.Sprintf("%s (%s)", reason, kind), nil)
				continue
			}
		}
		if !clearedEligible(c.State) {
			continue
		}
		connectedSince, ok := p.gw.ConnectedSince(c.ClusterID)
		if !ok || !quietEnough(c.LastSeen, connectedSince, quiet[c.ClusterID], time.Now()) {
			continue
		}
		// First: the rule that opened the incident, re-run on the live object.
		// It is the exact question that was asked, for any kind a rule covers,
		// so its answer outranks a health reading either way.
		if p.rules != nil {
			evaluated, fires, detail, err := p.rules.RuleStillFires(ctx, c.ID)
			if err != nil {
				continue // could not ask: no evidence either way
			}
			if evaluated {
				if !fires {
					cleared := ruleClearedOutcome(c, detail, quiet[c.ClusterID], connectedSince, time.Now())
					p.closeStaleIncident(ctx, c, cleared.Summary, cleared)
				}
				continue
			}
		}
		// Otherwise: live health of the workload (or the object itself when
		// it has none), never of a plan's target pod.
		healthKey, healthKind := clearedTarget(c)
		if healthKey != target || object == nil {
			var gone bool
			var reason string
			object, gone, reason = p.readTarget(ctx, c.ClusterID, healthKey)
			if gone {
				// Every other state already went through the gone check above.
				// An AwaitingApproval incident skipped it, because its plan's
				// target is usually a pod a rollout replaces; but this is the
				// workload it is about, or the object itself when it has none
				// (a bare Pod). With that gone there is nothing left for the
				// plan to act on, and the question it asks is moot.
				if subjectGoneCloses(c.State) {
					p.closeStaleIncident(ctx, c, fmt.Sprintf("%s (%s)", reason, healthKind), nil)
				}
				continue
			}
		}
		if object != nil && liveVerdict(healthKey, object, time.Now()).Level != health.LevelUnknown {
			if cleared := clearedOutcome(c, healthKey, healthKind, object, connectedSince, quiet[c.ClusterID], time.Now()); cleared != nil {
				p.closeStaleIncident(ctx, c, cleared.Summary, cleared)
			}
			continue
		}
		// Last: nothing grades this object (an Ingress, a webhook
		// configuration), but if everything that ever reported it was the
		// periodic sweep, that sweep has re-run its check every pass of the
		// quiet window and stopped finding it.
		if p.onlyPeriodicFindings(ctx, c.ClusterID, c.ID) {
			cleared := periodicClearedOutcome(c, quiet[c.ClusterID], connectedSince, time.Now())
			p.closeStaleIncident(ctx, c, cleared.Summary, cleared)
		}
	}
	return nil
}

// collectStaleCandidates returns every quiet open incident the stale sweep may
// consider, up to maxStaleCandidates, and the organisation they belong to.
// Which of them this pass actually checks is staleCheckLog.pick's decision.
func (p *Poller) collectStaleCandidates(ctx context.Context) ([]staleCandidate, string, error) {
	var out []staleCandidate
	var tenant string
	if err := data.InFleetScope(ctx, p.db.Pool, func(ctx context.Context, tx pgx.Tx, tenantID string) error {
		tenant = tenantID
		for _, q := range []string{staleCandidateQuery, awaitingApprovalCandidateQuery} {
			rows, err := tx.Query(ctx, q, staleObjectGracePeriod.Seconds(), maxStaleCandidates)
			if err != nil {
				return fmt.Errorf("select stale candidates: %w", err)
			}
			for rows.Next() {
				var c staleCandidate
				if err := rows.Scan(&c.ID, &c.ClusterID, &c.ObjectKey, &c.State, &c.WorkloadKey, &c.TargetKey, &c.LastSeen); err != nil {
					rows.Close()
					return fmt.Errorf("scan stale candidate: %w", err)
				}
				out = append(out, c)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return fmt.Errorf("iterate stale candidates: %w", err)
			}
		}
		return nil
	}); err != nil {
		return nil, "", err
	}
	return out, tenant, nil
}

// staleClosureBlocked is the Go mirror of staleCandidateQuery's own
// action-in-flight predicate, applied a second time under the row lock at the
// moment of closing. Pure, so the rule itself is unit-testable and so the two
// copies can be asserted to agree.
//
// Duplicated rather than shared, deliberately: the SQL copy exists to keep an
// ineligible incident out of a bounded candidate list, and this copy exists to
// refuse a closure for an incident that became ineligible after that list was
// built. They answer the same question at two different moments, and one
// cannot do the other's job.
func staleClosureBlocked(state string, hasPR, prMerged, prClosedUnmerged bool) bool {
	switch state {
	case orchestrator.StateExecuting, orchestrator.StateValidating,
		orchestrator.StateInvestigating, orchestrator.StateAwaitingApproval,
		orchestrator.StateAwaitingMerge,
		// StateExpired is already a closed outcome (PROJECT.md T2) and its
		// only allowed transition is back to StateDetected on recurrence, so
		// a stale-object closure can never legally apply to one. This is the
		// second of the two moments described above: the SQL copy keeps it
		// out of the candidate list, this copy refuses it if the row expired
		// after that list was built.
		orchestrator.StateExpired:
		return true
	}
	// An open pull request — proposed, and neither merged nor closed. Nothing
	// in ARGUS closes a pull request when its incident closes, so resolving
	// here leaves a live change proposal with no incident explaining it.
	return hasPR && !prMerged && !prClosedUnmerged
}

// closeStaleIncident resolves one incident, in its own transaction.
//
// Per-incident rather than one transaction for the batch: a single illegal
// transition or a lost row must not roll back the others, and each closure is an
// independent fact.
//
// cleared is nil for an object that has gone. For an incident whose fault
// cleared on its own it carries the evidence, and the closure is refused
// unless the incident is still Detected and nothing has recurred since it was
// selected.
func (p *Poller) closeStaleIncident(ctx context.Context, c staleCandidate, reason string, cleared *clearedClosure) {
	// Same reasoning as investigateOne: the unit of work an operator asks
	// about is one incident's closure, not the whole sweep. The sweep's own
	// id stays on the parent context; this narrows it and adds the
	// incident/cluster, which every line below then inherits.
	ctx, _ = logging.NewUnitOfWork(ctx, logging.IncidentID(c.ID), logging.ClusterID(c.ClusterID))

	tx, err := p.db.Pool.Begin(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "closing a stale incident: begin transaction failed", logging.Err(err))
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		logger.ErrorContext(ctx, "closing a stale incident: resolve organisation failed", logging.Err(err))
		return
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{c.ClusterID}); err != nil {
		logger.ErrorContext(ctx, "closing a stale incident: set request scope failed", logging.Err(err))
		return
	}

	// Re-read what the candidate query filtered on, under the same row lock
	// SetState is about to take, before closing anything.
	//
	// The window this closes is wide and real: DefaultStaleSweepInterval is ten
	// minutes and each candidate then costs a tunnel round trip, so an approval
	// can be granted or a pull request opened between a row being selected and
	// this function running. The state machine cannot catch it — AwaitingMerge
	// -> Resolved and AwaitingApproval -> Resolved are both LEGAL edges (they
	// are how a human closes an incident by hand), so SetState would accept
	// exactly the transition that orphans an open pull request. Only re-reading
	// the row can refuse it.
	//
	// `FOR UPDATE` before SetState's own identical lock is a no-op re-lock on a
	// row this transaction already holds, matching the precedent
	// internal/execution's recordExecutingTransition already set.
	var liveState string
	var prNumber *int
	var prMergedAt, prClosedUnmergedAt *time.Time
	var liveLastSeen time.Time
	if err := tx.QueryRow(ctx,
		`SELECT state, pr_number, pr_merged_at, pr_closed_unmerged_at, last_seen FROM incidents WHERE id = $1 FOR UPDATE`,
		c.ID).Scan(&liveState, &prNumber, &prMergedAt, &prClosedUnmergedAt, &liveLastSeen); err != nil {
		logger.ErrorContext(ctx, "closing a stale incident: re-read before closing failed", logging.Err(err))
		return
	}
	blocked := staleClosureBlocked(liveState, prNumber != nil, prMergedAt != nil, prClosedUnmergedAt != nil)
	if cleared != nil && liveState == orchestrator.StateAwaitingApproval && liveState == c.State {
		// The one closure allowed to withdraw a pending approval: the fault
		// cleared and the workload reads healthy, so the question is moot.
		// Recorded on the timeline (below), not silent. An open pull
		// request still blocks it.
		blocked = prNumber != nil && prMergedAt == nil && prClosedUnmergedAt == nil
	}
	if blocked {
		logger.InfoContext(ctx, "stale incident not closed: it now has an action in flight, and closing it would abandon that action",
			slog.String("live_state", liveState), slog.String("state_when_selected", c.State))
		return
	}
	if cleared != nil && (liveState != c.State || liveLastSeen.After(c.LastSeen)) {
		logger.InfoContext(ctx, "cleared incident not closed: it moved or recurred while this sweep was checking it",
			slog.String("live_state", liveState), slog.Time("last_seen", liveLastSeen))
		return
	}

	if err := orchestrator.SetState(ctx, tx, c.ID, orchestrator.StateResolved); err != nil {
		// An illegal transition here is not an error worth shouting about: the
		// incident moved while this sweep was deciding, which is exactly what the
		// state machine is for.
		logger.InfoContext(ctx, "stale incident not closed: it moved while this sweep was deciding",
			slog.String("state_when_selected", c.State), logging.Err(err))
		return
	}
	if cleared != nil {
		if err := timeline.Record(ctx, tx, timeline.Event{
			TenantID: tenantID, ClusterID: c.ClusterID, IncidentID: c.ID,
			Type:    timeline.EventIncidentSelfHealed,
			Summary: cleared.Summary,
			Detail:  cleared.Detail,
		}); err != nil {
			logger.ErrorContext(ctx, "closing a cleared incident: recording the timeline event failed", logging.Err(err))
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
		logger.ErrorContext(ctx, "closing a stale incident: commit failed", logging.Err(err))
		return
	}
	if cleared != nil {
		logger.InfoContext(ctx, "incident resolved: its fault cleared on its own",
			slog.String("from_state", c.State), slog.String("reason", reason))
	} else {
		logger.InfoContext(ctx, "stale incident resolved: nothing left to act on",
			slog.String("from_state", c.State), slog.String("reason", reason))
	}
	if p.events != nil {
		p.events.Publish(events.IncidentUpdated(c.ID, c.ClusterID))
	}
}
