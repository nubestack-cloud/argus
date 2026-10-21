package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/data"
	"argus/internal/events"
	"argus/internal/logging"
	"argus/internal/metrics"
	"argus/internal/timeline"
)

// validationGracePeriod is how long a Validating incident must go without a
// recurring Finding before ValidationSweeper promotes it to Resolved. This
// codebase has no real synthetic post-fix health check (re-running the
// original probe that flagged the problem) — this grace period, combined
// with the fact that a real recurrence flips the incident to Reopened well
// before this fires (see internal/gateway/finding.go's handleFinding), is
// the honest stand-in: "nothing went wrong again for a while" rather than
// "we actively confirmed it's fixed."
//
// This constant is the FLOOR, not the whole period. It is sized relative to
// internal/agent/detector.go's defaultFindingResendCooldown (5 minutes, the
// interval a still-present problem's own detector re-sends the same fingerprint
// at): 15 minutes is 3x that, generous enough that a merely slow-to-recur
// recurrence isn't missed, without leaving an incident sitting in Validating
// indefinitely.
//
// BACKLOG B2: that "3x" only held while the cooldown was 5 minutes, and it is an
// operator-settable per-agent environment variable. effectiveGracePeriod takes
// the max of this floor and 3x whatever the cluster's own agent reported, so a
// cluster configured to re-report every 20 minutes gets a window long enough for
// a recurrence to physically arrive in. Still not a setting — an operator tunes
// the cooldown and this follows, which is one knob instead of two that have to
// be kept consistent by hand.
const validationGracePeriod = 15 * time.Minute

// validationAssertionDeadline is how long PAST its own grace window a
// Validating incident may keep failing to produce an assertion before the
// sweeper stops waiting and moves it to StateValidationUnknown.
//
// # The bug this bounds
//
// The sweeper used to start every candidate at targetState = Resolved and,
// when it could not re-read the applied value or re-run the original rule,
// change only the explanatory sentence before committing Resolved anyway. A
// cluster that was merely unreachable therefore turned "we could not tell"
// into "we verified it worked" — and once written, that Resolved row is
// indistinguishable from a genuinely verified one. Absence of evidence was
// being reported as a positive result, which is the same mistake the
// condition-polarity gate was corrected for on 2026-09-02: there, a Finding
// that could not be classified is marked and let through rather than dropped,
// because silently asserting "this object is fine" on evidence too weak to
// support either claim is worse than a visible, downgraded signal.
//
// # Why a deadline rather than an attempt count
//
// The thing being waited out is a cluster being reachable again, which is a
// question about wall-clock time, not about how many times a 60-second ticker
// happened to fire. A count would also mean the bound moves whenever
// DefaultValidationSweepInterval is tuned, which nothing about the underlying
// judgement should depend on.
//
// One hour is chosen to sit comfortably past any ordinary network blip, node
// drain, hub restart or agent upgrade — the same reasoning
// internal/autoanalyze's staleUnreachableClusterAge uses for the same
// question — while still being short enough that an operator finds out the
// same day that a fix was never verified. An incident that reaches the
// deadline is not abandoned: ValidationUnknown notifies (db.go's
// notifiableStates) and keeps every exit a human needs.
const validationAssertionDeadline = 1 * time.Hour

// DefaultValidationSweepInterval is how often ValidationSweeper.Run sweeps.
// Deliberately much coarser than health.go's 20s (that monitors a 30s
// heartbeat cadence; this monitors a 15-minute grace period) — a minute's
// slop on top of validationGracePeriod is unnoticeable, and ticking any
// faster would just poll pointlessly often.
const DefaultValidationSweepInterval = 60 * time.Second

// ValidationSweeper implements the Resolved half of the Validating ->
// Resolved/Reopened automated re-check this package's own doc comment
// describes — the Reopened half is event-driven, from
// internal/gateway/finding.go's handleFinding, not from here.
type ValidationSweeper struct {
	db     *data.DB
	events *events.Bus // may be nil in tests that don't care about live-update publishing, matching gateway.HealthMonitor's own convention.
	// verifier turns "nothing came back" into an actual assertion. May be nil,
	// which keeps the previous behaviour exactly — see AppliedValueVerifier.
	verifier AppliedValueVerifier
}

// AppliedValueVerifier re-reads the field an execution changed and reports
// whether it still holds the value that was applied.
//
// # Why this is an interface rather than a method
//
// BACKLOG.md V1 asks for real post-fix validation: today `Validating -> Resolved`
// means "no recurrence for fifteen minutes", which `BACKLOG.md` calls "no news is
// good news, not an assertion". WORKLOG §145 then demonstrated the failure that
// wording predicts — an execution recorded `outcome = succeeded`, the incident was
// heading for `Resolved`, and Argo had already reverted the change. ARGUS was
// about to report a successful remediation for a change the cluster no longer had.
//
// Making the assertion needs a live read, which needs the tunnel, which lives in
// internal/gateway — and internal/gateway already imports this package, so calling
// it from here would be an import cycle. So this package declares what it needs
// and internal/api (which has the gateway, the field-path table and the precondition
// reader) supplies it, wired in cmd/hub. Dependency inversion rather than moving
// the sweeper, because the sweeper's job — the grace period and the state
// transitions — genuinely belongs with the state machine.
type AppliedValueVerifier interface {
	// VerifyAppliedValue re-reads what an execution changed. The in-place
	// route's half of the assertion.
	//
	// Returns held=true when the field still carries the applied value, false when
	// it demonstrably does not. An error means the assertion could not be made at
	// all — an unreachable cluster, an action type whose field is not modelled, an
	// execution that recorded no applied value — which is different from "the
	// change is gone" and is treated differently by the caller.
	VerifyAppliedValue(ctx context.Context, executionID string) (held bool, detail string, err error)

	// VerifyMergedPullRequest re-reads the field a merged, synced pull request
	// changed. The pull-request route's half of the assertion —
	// lld/08-remediation-contracts.md §12.8, closing BUGS.md 77: that route
	// writes no remediation_executions row, so VerifyAppliedValue has nothing to
	// key on, and this incident's clock is incidents.pr_merged_at rather than a
	// remediation_executions.executed_at.
	//
	// Same held/detail/err contract as VerifyAppliedValue — an error means the
	// assertion could not be made, never "the change is gone".
	VerifyMergedPullRequest(ctx context.Context, incidentID string) (held bool, detail string, err error)

	// RuleStillFires re-evaluates the ORIGINAL declarative rule
	// (BACKLOG.md E9, internal/agent/rules.go) that opened this incident,
	// against the live object, right now — BACKLOG.md V3's synthetic
	// post-fix health check, the thing VerifyAppliedValue/
	// VerifyMergedPullRequest above do NOT do: they confirm the field ARGUS
	// changed is still what it set it to, not that the symptom the field
	// change was meant to cure is actually gone. A rule can be re-run cheaply
	// (list its GVK, evaluate its condition) where a hand-written Go
	// checker's condition has no addressable identity to re-run at all — see
	// tunnel.Finding.RuleID's doc comment for why an explicit ID exists
	// instead of reverse-engineering one from Reason.
	//
	// evaluated is false when NO finding correlated into this incident ever
	// came from a known rule — an incident built entirely from the 13
	// hand-written Go checkers, the two watch-based detectors, or a rule ID
	// the agent no longer has loaded (removed/renamed since). "No finding
	// ever" rather than "the one that opened it": since BUGS.md 94 a rule
	// that fires on an object an earlier non-rule finding already opened an
	// incident about still supplies its identity, because which of two
	// producers reaches the hub first is a race that says nothing about
	// which one is true. This is an explicit
	// SCOPE BOUNDARY, not a failure: none of those have a cheap re-run path,
	// which is exactly why BACKLOG.md V3 says this "needs E9 first" — a rule
	// re-run is nearly free, a bespoke re-run of checkReplicaFailure's
	// owner-suppression logic (say) is a different, unbuilt feature. The
	// caller falls back to exactly the checks that existed before this
	// method, unchanged. fires/detail are meaningful only when evaluated is
	// true.
	//
	// err is set only when the re-check SHOULD have been possible
	// (evaluated would have been true) but could not be completed — an
	// unreachable cluster, a tunnel failure, the object having no resolvable
	// GVK/namespace/name to check. Same "an error is not evidence of
	// anything" contract as VerifyAppliedValue/VerifyMergedPullRequest: it
	// must never be read as "the rule cleared."
	RuleStillFires(ctx context.Context, incidentID string) (evaluated, fires bool, detail string, err error)
}

// NewValidationSweeper constructs a ValidationSweeper. Doesn't start
// sweeping — call Run for that.
//
// verifier may be nil, and nil means the sweeper behaves exactly as it did before
// V1: resolve on a quiet grace period. That is a deliberate escape hatch for tests
// and for a hub whose tunnel is unavailable, not a supported configuration — a nil
// verifier resolves incidents on the weaker evidence and says so in its log line.
func NewValidationSweeper(db *data.DB, bus *events.Bus, verifier AppliedValueVerifier) *ValidationSweeper {
	return &ValidationSweeper{db: db, events: bus, verifier: verifier}
}

// Run ticks every interval, running one sweep per tick, until ctx is
// cancelled. Blocks — callers run it in its own goroutine, the same pattern
// cmd/hub/main.go already uses for gateway.HealthMonitor/autoanalyze.Poller.
func (v *ValidationSweeper) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// PROJECT.md T23: one tick is one unit of work, and both
			// passes below share its correlation id. That granularity is
			// the right one here — a sweep resolves whichever incidents
			// have gone quiet, and the question an operator asks is "what
			// did the run that closed this incident actually check",
			// which is the whole tick, not one incident's slice of it.
			sweepCtx, _ := logging.NewUnitOfWork(ctx)
			start := time.Now()
			err := v.sweep(sweepCtx)
			metrics.ObserveSweeperRun("validation", time.Since(start), err)
			if err != nil {
				logger.ErrorContext(sweepCtx, "validation sweep failed", logging.Err(err))
			}
			// PROJECT.md T4: a second, independent pass over a disjoint
			// candidate set (Diagnosed/NeedsHumanInvestigation, never
			// Validating) — see sweepSelfHealing's own doc comment for why
			// this is not folded into sweep() above. A failure here must not
			// skip sweep() above on the next tick or vice versa, so each is
			// its own error, logged and moved past rather than returned.
			selfHealStart := time.Now()
			selfHealErr := v.sweepSelfHealing(sweepCtx)
			metrics.ObserveSweeperRun("self_healing", time.Since(selfHealStart), selfHealErr)
			if selfHealErr != nil {
				logger.ErrorContext(sweepCtx, "self-heal sweep failed", logging.Err(selfHealErr))
			}
		}
	}
}

// resolvableIncident is one row a sweep found ready to promote to Resolved.
type resolvableIncident struct {
	IncidentID string
	ClusterID  string
	// Route is which channel's fix landed this incident in Validating —
	// "inPlace" (remediation_executions) or "pullRequest" (incidents.validating_at)
	// — lld/08-remediation-contracts.md §12.8. Selects which half of
	// AppliedValueVerifier answers the assertion below, since the two routes
	// have no shared clock or evidence to key on (BUGS.md 77).
	Route string
	// ExecutionID is the successful execution whose change is being validated,
	// for Route == "inPlace". Empty for "pullRequest", which writes no
	// remediation_executions row at all — that absence is BUGS.md 77.
	ExecutionID string
	// FixLandedAt is when the fix actually landed: remediation_executions.executed_at
	// for "inPlace", incidents.validating_at for "pullRequest" (PROJECT.md
	// B139 — pr_merged_at is the GitHub merge instant, not when the fix was
	// observably in effect on the cluster; validating_at is stamped only
	// once MergeSweeper has already confirmed the GitOps sync, which is
	// what "fix landed" actually means here) — §12.8's "fix-landed
	// timestamp resolved per route". The grace period and every recurrence
	// check below are measured from this, whichever route produced it, so
	// the elapsed time has to be computed in Go rather than asserted once
	// in the query's WHERE clause (grace period is per-cluster, see
	// effectiveGracePeriod).
	FixLandedAt time.Time
	// ResendCooldownSeconds is what THIS cluster's agent reported as its
	// finding-resend cooldown, or 0 if it reported nothing. See
	// effectiveGracePeriod for why the grace period depends on it.
	ResendCooldownSeconds int
	// WorkloadKey identifies the workload this incident's object belongs to
	// (`apps/v1/Deployment|ns|name`), assigned by replicagroup.Recompute. Empty
	// when the object has no resolvable owner. Carried because a fix that rolls
	// the pods destroys the object this incident names — see siblingStillFailing.
	WorkloadKey string
}

// distinctClusterIDs de-duplicates a candidate list's cluster IDs, preserving
// first-seen order (irrelevant to correctness, just deterministic for tests).
// Split out so reportedCooldowns can serve both this file's candidate shapes
// (resolvableIncident and selfHealCandidate) without either caller
// re-implementing the same dedup loop, and without reportedCooldowns itself
// depending on either concrete type.
func distinctClusterIDs(clusterIDs []string) []string {
	seen := make(map[string]bool, len(clusterIDs))
	out := make([]string, 0, len(clusterIDs))
	for _, id := range clusterIDs {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// reportedCooldowns reads each candidate cluster's reported finding-resend
// cooldown, keyed by cluster id. A cluster missing from the result reported
// nothing, and effectiveGracePeriod reads that as unknown.
//
// Why this is a SEPARATE transaction with a SEPARATE scope, rather than a join in
// the candidate query above — two independent reasons, both learned the hard way:
//
//  1. cluster_facts' RLS policy has NO "empty means unrestricted" clause, unlike
//     the policy on incidents. This sweep is fleet-wide and so runs with an empty
//     accessible-cluster-id list, which makes cluster_facts read as ZERO ROWS.
//     A LEFT JOIN against it therefore yields NULL for every row and every
//     cooldown silently reads as "not reported" — the derivation compiles, runs,
//     logs nothing, and does nothing. internal/api/clusters.go's handleGetCluster
//     hit the same policy and names the reason it is so easy to miss: "no matching
//     row" and "row exists but RLS hides it" look identical to a SELECT. Narrowing
//     the scope to the clusters actually being read is that handler's fix and this
//     is the same fix.
//
//  2. The narrowing cannot happen in the sweep's own transaction, because that
//     transaction goes on to call SetState, which recomputes fleet groups and so
//     touches incidents in clusters outside the candidate set. Narrowing there
//     would hide rows a later statement legitimately needs.
//
// A failure returns an empty map rather than an error: not knowing a cooldown
// costs the derivation and falls back to the floor, which is the behaviour that
// shipped before B2. Failing the whole sweep instead would mean a cluster_facts
// hiccup could stop every incident in the fleet from ever resolving.
//
// Takes the distinct cluster IDs directly rather than a []resolvableIncident —
// PROJECT.md T4's sweepSelfHealing (below) needs this exact derivation for a
// different candidate shape (selfHealCandidate, no execution/PR route at all),
// and duplicating the dedup-and-scope logic for a second candidate type is
// exactly the "a second mechanism" this task was told not to invent. distinctClusterIDs
// below is the one place either candidate list is reduced to what this
// function actually needs.
func reportedCooldowns(ctx context.Context, db *data.DB, tenantID string, clusterIDs []string) map[string]int {
	out := map[string]int{}
	if len(clusterIDs) == 0 {
		return out
	}

	// Narrowed to exactly the clusters whose facts are about to be read, which is
	// what makes them visible at all. See the doc comment above. Partial results
	// are kept on error on purpose: `out` is written as rows arrive, and a cluster
	// whose timing was read before the failure keeps its real grace period rather
	// than being dragged back to the default with the rest.
	if err := data.ReadInScope(ctx, db.Pool, tenantID, clusterIDs, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT cluster_id, COALESCE((facts->'detection'->>'resendCooldownSeconds')::int, 0)
			   FROM cluster_facts WHERE cluster_id = ANY($1)`, clusterIDs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var clusterID string
			var cooldown int
			if err := rows.Scan(&clusterID, &cooldown); err != nil {
				return err
			}
			out[clusterID] = cooldown
		}
		return rows.Err()
	}); err != nil {
		logger.WarnContext(ctx, "could not read reported detector timings; every grace period not already read falls back to the default",
			slog.Duration("fallback_grace_period", validationGracePeriod), logging.Err(err))
	}
	return out
}

// siblingStillFailing reports whether the WORKLOAD this incident belongs to has
// been failing since the fix landed, on some object other than the one this
// incident names.
//
// # Why silence on one pod is not evidence of a fix
//
// A finding's fingerprint is per-object, and three of the four executable action
// types — PatchResourceLimits, RevertContainerImage and RestartPod — change a pod
// template, which rolls the workload and destroys the pod the incident names. So
// the incident is left watching an object that can no longer fail, and its own
// fingerprint can never recur *by construction*. Validation then sees quiet, V1's
// field assertion passes because the patched value is still on the workload, and
// the incident resolves — while the fault continues under a new pod name, as a new
// incident nobody has linked to it.
//
// Observed exactly this way on rke2 (WORKLOG §178): a 64Mi container OOMKilling,
// patched to 256Mi, which was still not enough. The patch rolled the Deployment;
// the remediated incident sat in Validating watching the dead pod while the new pod
// OOMKilled three more times as its own separate incident. Nothing about that is a
// per-cluster or per-fault quirk — it is what per-object fingerprinting plus a
// workload-level fix always produces.
//
// # Why the workload key rather than something new
//
// replicagroup.Recompute already stamps every incident with `workload_key`
// (`apps/v1/Deployment|ns|name`), which is exactly "the pods of one workload" —
// the five incidents in that live run all shared one. So the recurrence signal was
// already present and joined; validation was asking the narrower question.
//
// # The trade, stated rather than hidden
//
// A workload can carry two unrelated faults at once, and then this reopens an
// incident whose own fix genuinely worked. That is the safe direction — a human
// looks at something that is still broken — and the reason names the sibling
// incident so they can see immediately whether it is the same fault. Resolving on
// silence from a deleted object is the unsafe direction, and it is the one that
// happens by default.
//
// Empty WorkloadKey (an object with no resolvable owner — a bare pod, a Service)
// returns false: there is no workload to ask about, and the fingerprint-recurrence
// path already covers an object that survives its own fix.
func siblingStillFailing(ctx context.Context, tx pgx.Tx, c resolvableIncident) (string, bool, error) {
	if c.WorkloadKey == "" {
		return "", false, nil
	}
	var siblingID, siblingReason string
	var lastSeen time.Time
	err := tx.QueryRow(ctx,
		// cluster_id leads the predicate for both reasons it should: a
		// workload_key is only unique WITHIN a cluster (two clusters routinely run
		// the same Deployment name in the same namespace, and reopening incident A
		// because an unrelated cluster's copy is broken would be nonsense), and it
		// is the leading column of migration 000042's
		// incidents_workload_key_idx (cluster_id, workload_key, opening_reason).
		//
		// opening_reason is deliberately NOT required to match, even though
		// replicagroup.Recompute groups on it. A partial fix commonly changes the
		// symptom rather than removing it — patch a too-small memory limit to a
		// still-too-small one and OOMKilled can present as CrashLoopBackOff — and
		// that case is exactly as much "not fixed" as an identical recurrence.
		// Requiring reason equality would resolve it as a success.
		`SELECT id, COALESCE(opening_reason, ''), last_seen
		   FROM incidents
		  WHERE cluster_id = $1
		    AND workload_key = $2
		    AND id <> $3
		    AND state NOT IN ($4, $5)
		    -- Strictly after the fix landed. A sibling that stopped being seen
		    -- BEFORE the execution is evidence the fix worked, not against it.
		    AND last_seen > $6
		  ORDER BY last_seen DESC
		  LIMIT 1`,
		c.ClusterID, c.WorkloadKey, c.IncidentID, StateResolved, StateDismissed, c.FixLandedAt).
		Scan(&siblingID, &siblingReason, &lastSeen)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("check workload siblings for %s: %w", c.IncidentID, err)
	}
	detail := fmt.Sprintf("incident %s on the same workload was last seen %s, after this fix was applied",
		siblingID, lastSeen.Format(time.RFC3339))
	if siblingReason != "" {
		detail = fmt.Sprintf("incident %s (%s) on the same workload was last seen %s, after this fix was applied",
			siblingID, siblingReason, lastSeen.Format(time.RFC3339))
	}
	return detail, true, nil
}

// validationEvidence is everything one candidate's verdict turns on, gathered
// by sweep and handed to decideValidationOutcome, which is pure so the
// judgement itself is unit-testable without a database, a tunnel or a cluster.
//
// The split exists because the judgement is where the bug was. The gathering
// was always right — VerifyAppliedValue has documented since it was written
// that an error means "the assertion could not be made, never that the change
// is gone" — and the sweeper read that error, wrote a more careful sentence,
// and then resolved the incident anyway.
type validationEvidence struct {
	// route and grace only shape the wording, never the verdict.
	route string
	grace time.Duration
	// sinceFixLanded is how long ago the fix landed. Only consulted once the
	// verdict is already "nothing could be asserted": it decides between
	// retrying and giving up, never between resolved and not.
	sinceFixLanded time.Duration

	// siblingFailing is the local, decisive check — another incident on the
	// same workload seen failing after this fix landed.
	siblingFailing bool
	siblingDetail  string

	// verifierPresent is false only for NewValidationSweeper's documented nil
	// escape hatch (no verifier wired at all). It is deliberately NOT folded
	// into "every assertion errored": a hub with no verifier never attempted
	// an assertion, which is the pre-V1 behaviour that hatch exists to
	// preserve, and is a different thing from a verifier that tried and could
	// not answer.
	verifierPresent bool

	// The applied-value assertion (in-place) or merged-PR assertion. appliedErr
	// non-nil means it could not be made; appliedHeld is meaningless then.
	appliedHeld   bool
	appliedDetail string
	appliedErr    error

	// The original-rule re-check. ruleEvaluated false is a scope boundary (this
	// incident came from no known rule), not a failure. ruleErr non-nil means
	// the incident DID have a rule and it could not be re-run.
	ruleEvaluated bool
	ruleFires     bool
	ruleDetail    string
	ruleErr       error
}

// validationDecision is decideValidationOutcome's verdict.
type validationDecision struct {
	// TargetState is empty when the incident should stay in Validating and be
	// asked again on a later tick — the retry half of the fix. Nothing is
	// written for it beyond a log line; in particular no timeline event, since
	// "still trying" repeated every sweep interval would bury the incident's
	// actual history.
	TargetState string
	// Evidence is the sentence recorded on the timeline and logged. It is the
	// same string in both places on purpose, so what an operator reads in the
	// UI and what a hub log shows can never diverge.
	Evidence string
}

// decideValidationOutcome is the whole judgement, as one pure function.
//
// # The rule, stated once
//
// **Resolved requires a positive assertion.** Not "no news"; not "a careful
// sentence about why we could not check". At least one of the two checks that
// can actually assert something — the change ARGUS applied is still on the
// object, or the condition that opened the incident has been re-evaluated
// against live state and no longer holds — has to have come back, positively,
// this sweep. Anything else is inconclusive, and inconclusive is its own
// outcome rather than a footnote on a successful one.
//
// # Why either positive assertion is enough on its own
//
// The two are not redundant, and neither strictly dominates the other for this
// purpose:
//
//   - "The change still holds" can pass while the symptom persists (a memory
//     limit raised from 64Mi to 256Mi that is still too small).
//   - "The condition no longer holds" is the stronger claim about the fault,
//     and is what BACKLOG.md V3 built RuleStillFires for — but it is only
//     available for incidents opened by a known declarative rule, which is a
//     minority of them.
//
// So requiring BOTH would mean almost nothing could ever resolve, and would
// push the large, ordinary population of correctly-fixed incidents into
// ValidationUnknown — trading a false "verified" for a false "we could not
// tell", which is not an improvement, just a different untruth. Requiring
// EITHER keeps the honest claim available in both directions. When one
// asserted and the other could not, the failed attempt is appended to the
// evidence rather than hidden, so the record says exactly how much was
// actually checked.
//
// # Ordering
//
// Decisive negatives come first and are unchanged: a sibling still failing on
// the same workload, a change that demonstrably did not hold, or a rule that
// re-fires all mean the fix did not work, and Reopened is what this codebase
// already uses for that. An ERROR is never one of them — manufacturing a
// recurrence out of an unreachable cluster is the mirror image of the bug this
// function exists to fix, not a fix for it.
func decideValidationOutcome(e validationEvidence) validationDecision {
	quiet := fmt.Sprintf("no recurrence for at least %s since its fix landed (%s route)", e.grace, e.route)

	// Decisive negative, and asked first because it is decisive on its own and
	// costs only a local, indexed query.
	if e.siblingFailing {
		return validationDecision{TargetState: StateReopened, Evidence: fmt.Sprintf(
			"the workload this fix targeted is still failing: %s. The fix rolled the pods, so this incident's own object is gone and could not recur — its silence is not evidence of anything", e.siblingDetail)}
	}

	// The documented nil-verifier escape hatch: a hub with no verifier wired at
	// all behaves exactly as it did before BACKLOG.md V1, resolving on the
	// weaker evidence and saying so. Deliberately left alone by this fix — it
	// is a configuration this codebase already calls unsupported, and changing
	// it would silently strand every incident on a test hub that passes nil.
	if !e.verifierPresent {
		return validationDecision{TargetState: StateResolved, Evidence: quiet}
	}

	if e.appliedErr == nil && !e.appliedHeld {
		return validationDecision{TargetState: StateReopened, Evidence: fmt.Sprintf(
			"the change did not hold: %s. Something reverted it, so the symptom is not fixed even though nothing has recurred yet", e.appliedDetail)}
	}
	if e.ruleErr == nil && e.ruleEvaluated && e.ruleFires {
		return validationDecision{TargetState: StateReopened, Evidence: fmt.Sprintf(
			"re-checked the original condition against live state and it is STILL TRUE: %s", e.ruleDetail)}
	}

	confirmedGone := e.ruleErr == nil && e.ruleEvaluated && !e.ruleFires
	changeHeld := e.appliedErr == nil && e.appliedHeld

	// The strongest claim this codebase can make, so it leads when available.
	if confirmedGone {
		evidence := fmt.Sprintf("re-checked the original condition against live state and confirmed it no longer holds (%s) — not just quiet for %s, actually re-verified.", e.ruleDetail, e.grace)
		if e.appliedErr != nil {
			evidence = fmt.Sprintf("%s (the change ARGUS applied could not itself be re-read: %v — that does not weaken the re-check above, which asked about the symptom directly)", evidence, e.appliedErr)
		}
		return validationDecision{TargetState: StateResolved, Evidence: evidence}
	}
	if changeHeld {
		evidence := fmt.Sprintf("the change still holds (%s) and nothing recurred for %s", e.appliedDetail, e.grace)
		if e.ruleErr != nil {
			evidence = fmt.Sprintf("%s (the original check could not be re-run: %v, so this is 'our change is still applied and nothing recurred', not 'we confirmed the symptom is gone')", evidence, e.ruleErr)
		}
		return validationDecision{TargetState: StateResolved, Evidence: evidence}
	}

	// Nothing was asserted. This is the branch that used to fall through to
	// Resolved with nothing but a reworded sentence to show for it.
	failure := "the change itself could not be re-checked"
	if e.appliedErr != nil {
		failure = fmt.Sprintf("%s (%v)", failure, e.appliedErr)
	}
	if e.ruleErr != nil {
		failure = fmt.Sprintf("%s, and the original check could not be re-run (%v)", failure, e.ruleErr)
	}
	if e.sinceFixLanded < e.grace+validationAssertionDeadline {
		return validationDecision{TargetState: "", Evidence: fmt.Sprintf(
			"%s, and %s is not evidence of a fix — staying in Validating and retrying (giving up after %s of this)", failure, quiet, validationAssertionDeadline)}
	}
	return validationDecision{TargetState: StateValidationUnknown, Evidence: fmt.Sprintf(
		"%s — after %s of retrying, ARGUS still cannot tell whether this fix worked. %s, which is not evidence of one. Check the cluster directly.", failure, validationAssertionDeadline, quiet)}
}

// effectiveGracePeriod is how long this incident must stay quiet, given what its
// own agent reported about how often it re-reports a finding.
//
// BACKLOG B2: validationGracePeriod is 15 minutes with the stated rationale "3x
// the 5-minute resend cooldown" — but the cooldown is an operator-settable per-agent
// environment variable, so an operator who raises it to 20 minutes silently breaks
// the relationship the grace period rests on. The incident would resolve before a
// recurrence could physically be re-reported, which is the one thing the grace
// period exists to prevent.
//
// The floor and the derivation guard opposite mistakes, which is why both are here:
//
//   - A SHORT cooldown must not shorten the window. 3x30s is 90 seconds, and
//     resolving an incident 90 seconds after a fix on the strength of quiet alone
//     is not evidence of anything. validationGracePeriod stays the floor.
//   - A LONG cooldown must lengthen it, or the window closes before the signal it
//     is waiting for could arrive.
//
// A cluster that reported nothing — an agent older than tunnel.ClusterDetection —
// gets the floor, which is exactly today's behaviour. Zero is treated as unknown
// rather than as zero seconds, because computing 3x0 would collapse the window to
// nothing.
// QuietPeriods is effectiveGracePeriod for each of clusterIDs, from each
// cluster's reported resend cooldown. Exported for the hub's other
// closure-on-quiet path (autoanalyze's cleared-incident check), so "how long
// is quiet enough" is one rule, not two copies that drift.
func QuietPeriods(ctx context.Context, db *data.DB, tenantID string, clusterIDs []string) map[string]time.Duration {
	cooldowns := reportedCooldowns(ctx, db, tenantID, distinctClusterIDs(clusterIDs))
	out := make(map[string]time.Duration, len(clusterIDs))
	for _, id := range clusterIDs {
		out[id] = effectiveGracePeriod(cooldowns[id])
	}
	return out
}

func effectiveGracePeriod(reportedCooldownSeconds int) time.Duration {
	if reportedCooldownSeconds <= 0 {
		return validationGracePeriod
	}
	derived := 3 * time.Duration(reportedCooldownSeconds) * time.Second
	if derived > validationGracePeriod {
		return derived
	}
	return validationGracePeriod
}

// sweep runs one pass inside a single RLS-scoped transaction — the same
// data.InFleetScope call gateway.HealthMonitor.sweep already uses for a
// tenant-wide (not single-cluster) background job. Candidates are found
// first via a read-only query, then promoted one at a time through SetState
// — never a second, raw `UPDATE incidents SET state = ...` here, matching
// SetState's own doc comment that it's the one place anything writes
// incidents.state (which is also what gets this sweep fleetgroup.Recompute
// for free, Resolved being a closed state).
//
// PROJECT.md G11: the SingleOrganisationID + SetRequestScope(..., nil) pair
// this used to open with is now InFleetScope's, so the sweep body never
// holds a transaction that has not already been scoped.
func (v *ValidationSweeper) sweep(ctx context.Context) error {
	var transitioned []resolvableIncident
	if err := data.InFleetScope(ctx, v.db.Pool, func(ctx context.Context, tx pgx.Tx, tenantID string) error {
		// A Validating incident's fix-landed time is the clock this grace period
		// runs from — never incidents.last_seen alone, which can already be old the
		// moment Validating is entered (the last symptom observed and the moment a
		// human got around to approving the fix are two different clocks).
		// i.last_seen <= <fix-landed> is a defense-in-depth double-check, not the
		// primary mechanism: a real recurrence after the fix already flips state
		// away from Validating via handleFinding's Reopened transition before this
		// query would ever see it, so state = 'Validating' alone should already
		// guarantee no recurrence happened.
		//
		// Two routes, two clocks, unioned rather than a single query with an OR —
		// lld/08-remediation-contracts.md §12.8, closing BUGS.md 77. The in-place
		// route's clock is its newest successful remediation_executions row
		// (unchanged).
		//
		// The pull-request route's clock is incidents.validating_at (PROJECT.md
		// B139, migration 000096) — NOT pr_merged_at, which this query used
		// until the bug this comment now documents: pr_merged_at is the GitHub
		// merge instant, but the still-broken workload legitimately keeps
		// emitting findings until GitOps actually SYNCS, some real time later.
		// last_seen routinely ends up after pr_merged_at from nothing but
		// ordinary reconciliation lag, and since last_seen never moves
		// backward, the incident could then never satisfy the check and sat in
		// Validating forever — live-reproduced 2026-09-05 (docs/VERIFICATION.md):
		// merge 19:24:38Z, sync 19:28:12Z, last real finding 19:27:37Z.
		// validating_at is stamped by SetState only once the incident actually
		// transitions INTO Validating, which the pull-request route reaches
		// only after MergeSweeper has already confirmed the sync — so it is
		// the true "fix observably landed" instant this whole grace period is
		// supposed to run from, the same thing exec.executed_at already is for
		// the in-place route. pr_merged_at IS NOT NULL stays as the route
		// discriminator (distinguishing "this incident came via a merged PR" at
		// all); validating_at IS NOT NULL excludes any incident that entered
		// Validating before migration 000096 backfilled nothing for it — an
		// honest gap, not a silent wrong answer, matching resolved_at's own
		// no-backfill precedent. The two routes are mutually exclusive today
		// (there is no paired route yet, lld/08 §12.6), so UNION ALL cannot
		// double-count an incident.
		rows, err := tx.Query(ctx,
			`SELECT i.id, i.cluster_id, 'inPlace', exec.execution_id, exec.executed_at, COALESCE(i.workload_key, '')
		   FROM incidents i
		   JOIN (
		     -- DISTINCT ON rather than MAX(): the execution's own id is needed
		     -- now, so the newest successful row per incident has to be the row
		     -- itself rather than an aggregate over it.
		     SELECT DISTINCT ON (incident_id) incident_id, executed_at, id AS execution_id
		       FROM remediation_executions
		      WHERE outcome = 'succeeded'
		      ORDER BY incident_id, executed_at DESC
		   ) exec ON exec.incident_id = i.id
		  WHERE i.state = $1
		    -- The FLOOR, not the final answer. effectiveGracePeriod can require
		    -- longer for a cluster whose agent reports a long resend cooldown, so
		    -- this deliberately selects a superset and the loop below filters it.
		    -- Keeping the formula in one place (Go, where it is unit-tested) beats
		    -- a second copy of it in SQL that could silently drift.
		    AND exec.executed_at < now() - ($2 * interval '1 second')
		    AND i.last_seen <= exec.executed_at

		  UNION ALL

		  SELECT i.id, i.cluster_id, 'pullRequest', '', i.validating_at, COALESCE(i.workload_key, '')
		    FROM incidents i
		   WHERE i.state = $1
		     AND i.pr_merged_at IS NOT NULL
		     AND i.validating_at IS NOT NULL
		     AND i.validating_at < now() - ($2 * interval '1 second')
		     AND i.last_seen <= i.validating_at`,
			StateValidating, validationGracePeriod.Seconds())
		if err != nil {
			return fmt.Errorf("find incidents ready to resolve: %w", err)
		}
		var candidates []resolvableIncident
		for rows.Next() {
			var c resolvableIncident
			if err := rows.Scan(&c.IncidentID, &c.ClusterID, &c.Route, &c.ExecutionID, &c.FixLandedAt, &c.WorkloadKey); err != nil {
				rows.Close()
				return fmt.Errorf("scan resolvable incident: %w", err)
			}
			candidates = append(candidates, c)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate resolvable incidents: %w", err)
		}

		clusterIDs := make([]string, 0, len(candidates))
		for _, c := range candidates {
			clusterIDs = append(clusterIDs, c.ClusterID)
		}
		cooldowns := reportedCooldowns(ctx, v.db, tenantID, distinctClusterIDs(clusterIDs))

		// Every incident this sweep actually transitioned — not just the resolved
		// ones. Named for what it holds now that Resolved is no longer the only
		// destination.
		transitioned = make([]resolvableIncident, 0, len(candidates))
		now := time.Now()
		for _, c := range candidates {
			// BACKLOG B2: this cluster's own grace period, derived from what its agent
			// reported. The query above filtered on the floor, so a cluster with a long
			// resend cooldown can appear here before its own window has closed.
			c.ResendCooldownSeconds = cooldowns[c.ClusterID]
			grace := effectiveGracePeriod(c.ResendCooldownSeconds)
			if now.Sub(c.FixLandedAt) < grace {
				logger.DebugContext(ctx, "incident not yet due for validation",
					logging.IncidentID(c.IncidentID), logging.ClusterID(c.ClusterID),
					slog.String("route", c.Route),
					slog.Duration("elapsed", now.Sub(c.FixLandedAt).Round(time.Second)),
					slog.Duration("grace_period", grace),
					slog.Int("agent_resend_cooldown_seconds", c.ResendCooldownSeconds))
				continue
			}
			// The whole judgement now lives in decideValidationOutcome (pure, above);
			// this block only GATHERS. The split is the fix for a bug that was entirely
			// in the judgement: this loop used to open with `targetState :=
			// StateResolved` and let an unanswerable assertion change nothing but the
			// sentence attached to it.
			//
			// Gathering is still short-circuited exactly as before, so a decided
			// verdict never pays for a tunnel round trip it cannot change.
			ev := validationEvidence{
				route:           c.Route,
				grace:           grace,
				sinceFixLanded:  now.Sub(c.FixLandedAt),
				verifierPresent: v.verifier != nil,
			}

			// Asked BEFORE the V1 field assertion, for two reasons. It is decisive on
			// its own — a workload that is still failing is not fixed, whatever its
			// spec now says — and it is a local query against an already-indexed
			// column, where VerifyAppliedValue is a round trip through the tunnel to
			// the cluster. No reason to pay for the remote read to reach the same
			// conclusion.
			sibling, stillFailing, sibErr := siblingStillFailing(ctx, tx, c)
			if sibErr != nil {
				// Returned rather than logged-and-continued, unlike the verifier's
				// error branch below. A failed query inside a pgx transaction poisons
				// it, so every later statement in this sweep — including SetState —
				// would fail anyway; carrying on would only turn one clear error into
				// a pile of confusing ones. The tick is lost, the next one retries,
				// and no incident is resolved on evidence we failed to gather.
				return sibErr
			}
			ev.siblingFailing, ev.siblingDetail = stillFailing, sibling

			if !stillFailing && v.verifier != nil {
				// BACKLOG V1: assert the change is still there, rather than inferring
				// it from silence. §12.8's per-route dispatch: the two routes have no
				// shared clock or evidence to key on (BUGS.md 77), so each calls its
				// own half of the verifier.
				//
				// An error from either half means the assertion could not be MADE.
				// decideValidationOutcome treats that as inconclusive; it used to be
				// treated as a reason to reword the Resolved this loop had already
				// decided on before asking.
				if c.Route == "pullRequest" {
					ev.appliedHeld, ev.appliedDetail, ev.appliedErr = v.verifier.VerifyMergedPullRequest(ctx, c.IncidentID)
				} else {
					ev.appliedHeld, ev.appliedDetail, ev.appliedErr = v.verifier.VerifyAppliedValue(ctx, c.ExecutionID)
				}

				// BACKLOG.md V3: the synthetic post-fix health check — re-running the
				// ORIGINAL check that flagged the problem, not just the assertion
				// above. Skipped only when the assertion above already came back
				// DECISIVELY negative (the change is demonstrably gone): that verdict
				// is Reopened either way, so the round trip would buy nothing. An
				// assertion that merely errored does NOT skip it — an incident whose
				// field cannot be re-read may still have a rule that can be re-run,
				// and that is the one thing that can still turn this sweep into a real
				// answer instead of a shrug.
				//
				// Scope boundary, explicit and by design (see AppliedValueVerifier.
				// RuleStillFires' own doc comment): this only applies to an incident
				// whose OPENING finding came from a known BACKLOG.md E9 rule.
				// Anything opened by one of the hand-written Go checkers, or the
				// watch-based detectors, has no addressable check to re-run —
				// evaluated=false is a boundary, not a failure, and never counts as an
				// assertion that could not be made.
				if !(ev.appliedErr == nil && !ev.appliedHeld) {
					ev.ruleEvaluated, ev.ruleFires, ev.ruleDetail, ev.ruleErr = v.verifier.RuleStillFires(ctx, c.IncidentID)
				}
			}

			decision := decideValidationOutcome(ev)
			if decision.TargetState == "" {
				// Inconclusive, and still inside the retry window. The incident stays
				// in Validating and is asked again next tick — no SetState, no
				// timeline event (one per sweep interval would bury the incident's own
				// history), no live-update publish, because nothing about the incident
				// actually changed. The log line is the trace.
				logger.InfoContext(ctx, "incident still unverified; asking again next tick",
					logging.IncidentID(c.IncidentID), logging.ClusterID(c.ClusterID),
					slog.String("route", c.Route),
					slog.Duration("elapsed", now.Sub(c.FixLandedAt).Round(time.Second)),
					slog.String("evidence", decision.Evidence))
				continue
			}
			targetState, evidence := decision.TargetState, decision.Evidence

			err := SetState(ctx, tx, c.IncidentID, targetState)
			if errors.Is(err, ErrIllegalTransition) {
				// The candidate query above doesn't lock the rows it returns, so
				// a candidate can leave Validating between being selected and
				// being promoted — internal/gateway/finding.go's handleFinding
				// flipping it to Reopened because the symptom just recurred is
				// the case that actually happens. SetState re-reads under a row
				// lock and correctly refuses. Skipped and logged rather than
				// returned: one lost race must not abort the whole sweep and
				// roll back every other incident this tick legitimately
				// resolved. The skipped incident is simply no longer a candidate.
				logger.InfoContext(ctx, "incident left Validating while this sweep was running; leaving it alone",
					logging.IncidentID(c.IncidentID), logging.ClusterID(c.ClusterID), logging.Err(err))
				continue
			}
			if err != nil {
				return fmt.Errorf("resolve incident %s: %w", c.IncidentID, err)
			}

			// BACKLOG.md B1: the validation outcome — question 4 of the four the
			// incident screen answers, and the one transition this whole sweep
			// exists to make. evidence already carries exactly the honest
			// "no news is good news" vs. "actually re-checked and it held/didn't"
			// distinction V1 introduced; recorded verbatim rather than
			// re-derived.
			if err := timeline.Record(ctx, tx, timeline.Event{
				TenantID: tenantID, ClusterID: c.ClusterID, IncidentID: c.IncidentID,
				Type:    timeline.EventValidationOutcome,
				Summary: evidence,
				Detail:  map[string]any{"outcome": targetState, "route": c.Route},
			}); err != nil {
				return fmt.Errorf("record ValidationOutcome timeline event for incident %s: %w", c.IncidentID, err)
			}

			transitioned = append(transitioned, c)
			switch targetState {
			case StateReopened:
				logger.WarnContext(ctx, "incident REOPENED after validation",
					logging.IncidentID(c.IncidentID), logging.ClusterID(c.ClusterID),
					slog.String("evidence", evidence))
			case StateValidationUnknown:
				// Never worded as a resolution. This log line said "auto-resolved"
				// for every non-Reopened outcome, which for this state would be the
				// same untruth in a log that the state itself exists to stop
				// writing to the database.
				logger.WarnContext(ctx, "incident UNVERIFIED: the fix could not be confirmed either way",
					logging.IncidentID(c.IncidentID), logging.ClusterID(c.ClusterID),
					slog.String("evidence", evidence))
			default:
				logger.InfoContext(ctx, "incident auto-resolved after validation",
					logging.IncidentID(c.IncidentID), logging.ClusterID(c.ClusterID),
					slog.String("evidence", evidence))
			}
		}

		return nil
	}); err != nil {
		return err
	}
	// Published only after a successful commit, matching HealthMonitor's
	// own doc comment for exactly the same reason: never announce a
	// transition that might still roll back. Over `transitioned`, not
	// `candidates` — an incident this sweep skipped because it had already
	// left Validating, or left in Validating to be asked again, had nothing
	// announced about it here.
	if v.events != nil {
		for _, c := range transitioned {
			v.events.Publish(events.IncidentUpdated(c.IncidentID, c.ClusterID))
		}
	}
	return nil
}

// selfHealCandidate is one incident sweepSelfHealing found sitting in
// Diagnosed or NeedsHumanInvestigation with a genuinely CONCLUDED
// investigation behind it (root_cause->>'status' = 'complete' on its most
// recent analysis — never merely "an analysis exists"), long enough after
// that conclusion, with nothing having recurred since.
type selfHealCandidate struct {
	IncidentID string
	ClusterID  string
	// FromState is Diagnosed or NeedsHumanInvestigation — carried onto the
	// timeline event's Detail (see EventIncidentSelfHealed's own doc
	// comment) so a reader can tell PROJECT.md T4's two live cases apart
	// without re-deriving it from the rest of the incident's history.
	FromState string
	// ConcludedAt is this route's "fix landed" equivalent — sweep()'s clock
	// is remediation_executions.executed_at or incidents.validating_at
	// because something was actually APPLIED at one of those instants; here
	// nothing was ever applied, so the clock is instead the moment ARGUS's
	// own investigation last concluded (the incident's latest analyses row's
	// created_at, gated on that row's root_cause->>'status' being
	// 'complete' — see the query in sweepSelfHealing).
	ConcludedAt time.Time
}

// sweepSelfHealing is PROJECT.md T4's fix for "a fault that clears itself
// has no closure path": Diagnosed and NeedsHumanInvestigation are both
// requiresAction states (state.go) whose only exits, before this existed,
// were a human clicking resolve or dismiss — no matter how long the object
// that opened the incident went on behaving normally afterwards.
//
// # Why a second sweep rather than folding this into sweep() above
//
// sweep()'s candidate query, decideValidationOutcome and
// AppliedValueVerifier are ALL about one question this candidate set can
// never answer: "does the change ARGUS applied still hold?" Nothing was
// applied here — that is the entire premise of both live cases this fixes
// (isFault:false, and a complete investigation that proposed no plan at
// all) — so there is no execution to re-read and, for the large majority of
// incidents with no known declarative rule behind them
// (AppliedValueVerifier.RuleStillFires' own documented scope boundary), no
// re-runnable condition either. Routing these incidents through Validating
// to reuse sweep() verbatim would need decideValidationOutcome to treat
// "nothing could be asserted" as sufficient for THIS route while keeping it
// insufficient (a retry, then ValidationUnknown) for the other two — a
// route-shaped exception buried inside a function whose whole point is one
// honest rule for every route — and it would put the incident on screen as
// "Validating" (StateValidating's own doc comment: "a successful Patch
// lands... proves the mutation was accepted") for the entire grace period,
// which would be false: nothing was ever patched. A second, smaller sweep
// with its own honest verdict — quiet is sufficient here, because by
// construction there is nothing else TO check — keeps that false claim from
// ever being made, and keeps Diagnosed/NeedsHumanInvestigation's own,
// already-accurate copy (web/src/utils/incidents.ts's stateExplanation) on
// screen right up until the incident actually closes.
//
// # The predicate, reused rather than reinvented
//
// validationGracePeriod / effectiveGracePeriod / reportedCooldowns — the
// exact same 15-minute floor, 3x-resend-cooldown derivation sweep() uses
// above, called here UNCHANGED. What differs is only the CLOCK the grace
// period is measured from (see selfHealCandidate.ConcludedAt's own comment)
// and the verdict once the window has passed: no positive re-verification
// is required, because none is possible here by construction. This is
// PROJECT.md T4's explicit instruction — the model's own verdict may
// NOMINATE an incident into this candidate set (by concluding isFault:false,
// or reaching a route with nothing to execute) but the same live-cluster
// observation ValidationSweeper already trusts — a real quiet period with
// no new matching Finding — is what actually closes it, never the model's
// own confidence score (BACKLOG.md B151: a self-reported "this resolved"
// claim is not verified evidence).
//
// # Why NOT gated on isFault
//
// isFault only ever reaches Diagnosed, and even there it is one of TWO
// routes into that state (the other being route==Guidance with a real,
// unexecutable cause — see orchestrator.Advance). PROJECT.md T4's second
// live case reaches NeedsHumanInvestigation with isFault never in play at
// all: the model said the fault WAS real and had since cleared, which
// isFault's own two-value shape cannot express (its prompt defines false as
// "was never a fault", not "was a fault and has cleared" — see
// llm.RootCause's own doc comment). The one signal both live cases share,
// and the one this query actually gates on, is generically available
// regardless of fault type or of which of the two states an incident is in:
// analyses.root_cause->>'status' = 'complete' on the incident's OWN most
// recent analysis — "did ARGUS's investigation genuinely conclude, as
// opposed to hit a bound and give up" — exactly the distinction
// stateExplanation (web/src/utils/incidents.ts) already draws, for the
// identical reason. No per-fault-type or per-kind enumeration anywhere in
// this query, and none is needed: it never inspects what the root cause
// SAYS, only whether one was persisted at all.
//
// # Recurrence
//
// No new code needed in internal/gateway/finding.go: handleFinding already
// re-attaches a recurring Finding to any incident whose state is not
// Resolved/Dismissed (correlationIdentity.find's own predicate) and bumps
// incidents.last_seen unconditionally on that match — Diagnosed and
// NeedsHumanInvestigation were never excluded from this, because they are
// still open, on-somebody's-queue incidents throughout. That bump is this
// query's own disqualifying condition (`i.last_seen <= an.created_at`,
// re-checked under a row lock immediately below before ever calling
// SetState) — a Finding that recurs during the grace window simply keeps
// this incident out of (or removes it from) the candidate set on every tick
// until it goes quiet again, the same defense-in-depth double-check sweep()
// itself relies on. No StateReopened transition applies here, unlike
// Validating: Diagnosed/NeedsHumanInvestigation are ALREADY on a human's
// queue (state.go's RequiresAction, not InProgress) for as long as they sit
// here, so there is nothing to "re-open" — the incident was never closed in
// the first place, and this sweep's whole job is to make sure it stays that
// way until it is genuinely safe to close.
func (v *ValidationSweeper) sweepSelfHealing(ctx context.Context) error {
	var transitioned []selfHealCandidate
	if err := data.InFleetScope(ctx, v.db.Pool, func(ctx context.Context, tx pgx.Tx, tenantID string) error {
		// an: the incident's OWN latest analysis, whichever status it carries —
		// picked BEFORE filtering on status, so a later, genuinely inconclusive
		// re-analysis (a human re-ran it and this time it hit a bound) correctly
		// disqualifies an incident whose FIRST analysis happened to conclude.
		// Filtering root_cause->>'status' inside the DISTINCT ON subquery
		// instead would pick the latest COMPLETE analysis rather than the
		// latest analysis full stop — the wrong answer once an incident here has
		// ever been re-analyzed more than once.
		rows, err := tx.Query(ctx,
			`SELECT i.id, i.cluster_id, i.state, an.created_at
		   FROM incidents i
		   JOIN (
		     SELECT DISTINCT ON (incident_id) incident_id, created_at, root_cause->>'status' AS status
		       FROM analyses
		      ORDER BY incident_id, created_at DESC
		   ) an ON an.incident_id = i.id AND an.status = 'complete'
		  WHERE i.state IN ($1, $2)
		    AND an.created_at < now() - ($3 * interval '1 second')
		    AND i.last_seen <= an.created_at`,
			StateDiagnosed, StateNeedsHumanInvestigation, validationGracePeriod.Seconds())
		if err != nil {
			return fmt.Errorf("find incidents ready to self-heal: %w", err)
		}
		var candidates []selfHealCandidate
		for rows.Next() {
			var c selfHealCandidate
			if err := rows.Scan(&c.IncidentID, &c.ClusterID, &c.FromState, &c.ConcludedAt); err != nil {
				rows.Close()
				return fmt.Errorf("scan self-heal candidate: %w", err)
			}
			candidates = append(candidates, c)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate self-heal candidates: %w", err)
		}

		clusterIDs := make([]string, 0, len(candidates))
		for _, c := range candidates {
			clusterIDs = append(clusterIDs, c.ClusterID)
		}
		cooldowns := reportedCooldowns(ctx, v.db, tenantID, distinctClusterIDs(clusterIDs))

		now := time.Now()
		for _, c := range candidates {
			grace := effectiveGracePeriod(cooldowns[c.ClusterID])
			if now.Sub(c.ConcludedAt) < grace {
				logger.DebugContext(ctx, "incident not yet due for the self-heal check",
					logging.IncidentID(c.IncidentID), logging.ClusterID(c.ClusterID),
					slog.String("from_state", c.FromState),
					slog.Duration("elapsed", now.Sub(c.ConcludedAt).Round(time.Second)),
					slog.Duration("grace_period", grace))
				continue
			}

			// Re-checked under a row lock, immediately before promoting — the
			// candidate query above does not lock the rows it returns, so a
			// Finding can recur (bumping last_seen) between selection and this
			// point. Re-locking a row this same transaction's SetState call is
			// about to lock again momentarily is a no-op, matching the
			// established precedent for exactly this maneuver
			// (internal/execution's recordExecutingTransition).
			var lastSeen time.Time
			if err := tx.QueryRow(ctx, `SELECT last_seen FROM incidents WHERE id = $1 FOR UPDATE`, c.IncidentID).Scan(&lastSeen); err != nil {
				return fmt.Errorf("re-check incident %s before self-healing it: %w", c.IncidentID, err)
			}
			if lastSeen.After(c.ConcludedAt) {
				logger.InfoContext(ctx, "incident recurred since its investigation concluded; leaving it alone",
					logging.IncidentID(c.IncidentID), logging.ClusterID(c.ClusterID))
				continue
			}

			evidence := fmt.Sprintf(
				"no recurrence for at least %s since the investigation concluded there was nothing for ARGUS to execute (was %s) — closing as self-healed with no human action; no fix was ever applied",
				grace, c.FromState)

			err := SetState(ctx, tx, c.IncidentID, StateResolved)
			if errors.Is(err, ErrIllegalTransition) {
				// The candidate query doesn't lock the rows it returns, and the
				// re-check above only covers recurrence — a human resolving or
				// dismissing this incident by hand between selection and here is
				// the other way it can leave Diagnosed/NeedsHumanInvestigation
				// mid-sweep. Skipped and logged rather than returned, for the
				// identical reason sweep() above does the same: one lost race
				// must not roll back every other incident this tick legitimately
				// closed.
				logger.InfoContext(ctx, "incident left its state while the self-heal sweep was running; leaving it alone",
					logging.IncidentID(c.IncidentID), logging.ClusterID(c.ClusterID),
					slog.String("from_state", c.FromState), logging.Err(err))
				continue
			}
			if err != nil {
				return fmt.Errorf("self-heal incident %s: %w", c.IncidentID, err)
			}

			if err := timeline.Record(ctx, tx, timeline.Event{
				TenantID: tenantID, ClusterID: c.ClusterID, IncidentID: c.IncidentID,
				Type:    timeline.EventIncidentSelfHealed,
				Summary: evidence,
				Detail:  map[string]any{"fromState": c.FromState},
			}); err != nil {
				return fmt.Errorf("record IncidentSelfHealed timeline event for incident %s: %w", c.IncidentID, err)
			}

			transitioned = append(transitioned, c)
			logger.InfoContext(ctx, "incident closed as self-healed",
				logging.IncidentID(c.IncidentID), logging.ClusterID(c.ClusterID),
				slog.String("from_state", c.FromState), slog.String("evidence", evidence))
		}

		return nil
	}); err != nil {
		return err
	}
	if v.events != nil {
		for _, c := range transitioned {
			v.events.Publish(events.IncidentUpdated(c.IncidentID, c.ClusterID))
		}
	}
	return nil
}
