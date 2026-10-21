package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/data"
	"argus/internal/events"
	"argus/internal/execution"
	"argus/internal/logging"
	"argus/internal/metrics"
	"argus/internal/orchestrator"
	"argus/internal/settings"
)

// recordAutomationGate persists PROJECT.md T14's decisive gate/reason for one
// incident, in its own short transaction — mirroring checkBreaker/
// checkUnattendedBudget's own begin/scope/commit shape immediately below,
// since this is called from the same per-candidate loops those are, never
// inside the read-only collectUnattended transaction's own commit path where
// it's cheaper to just call SetAutomationGate on the existing tx directly.
//
// Best-effort and void: a failure to WRITE the explanation must never abort a
// sweep that has already correctly decided to refuse — the refusal itself
// (the incident staying at AwaitingApproval, untouched) is what matters and
// has already happened by the time this is called. Logged so a persistent
// failure here is still visible.
func (s *Server) recordAutomationGate(ctx context.Context, tenantID, incidentID string, gate AutomationGate, reason string) {
	if err := data.InScope(ctx, s.db.Pool, tenantID, nil, func(ctx context.Context, tx pgx.Tx) error {
		return SetAutomationGate(ctx, tx, incidentID, gate, reason)
	}); err != nil {
		logger.ErrorContext(ctx, "recording the automation gate failed",
			logging.IncidentID(incidentID), logging.Err(err))
	}
}

// Unattended execution: the sweeper that makes the auto-approval policy mean
// something against a real cluster.
//
// # What this is
//
// Every path in this codebase up to now required a human to click approve.
// internal/orchestrator.Advance routes an AutoApprove verdict to
// AwaitingApproval exactly like a NeedsApproval one, and says so in a comment
// that has been load-bearing for months. That is still what happens; this
// sweeper is what may then act on the result, and only while the operator has
// switched it on (org_settings.autonomy_unattended_execution_enabled, default
// false — migration 000046).
//
// # Why a sweeper rather than a call at the end of the analysis
//
// The obvious implementation is to execute inline, right after
// ApplyAnalysisResult commits, in both of its callers. Three things make that
// the wrong shape, and the first is decisive:
//
//   - **The blast-radius cap cannot be enforced concurrently.** The counter is
//     read, then the tunnel call happens, then the execution row is written.
//     Two analyses finishing at the same moment would both read 9-of-10 and both
//     execute, giving 11 — a limit that fails exactly when a burst makes it
//     matter, which is the only time it matters. There is no transaction that can
//     close that window, because the mutation happens outside the database. A
//     single sequential sweeper closes it by construction.
//   - **A hub restart mid-flight would silently orphan a plan.** Inline, an
//     auto-approved plan whose hub died before executing is simply never
//     executed and never explained. Here it is picked up on the next tick, or
//     ages out and waits for a human — either way something happens and it is
//     visible.
//   - **It is genuinely not part of the request.** The analyze request's response
//     describes an incident that would already be stale by the time it reached
//     the client. The UI polls; the transition arrives the same way any other
//     background transition does.
//
// # Why it lives in internal/api rather than its own package
//
// internal/autoanalyze is the precedent for a poller in its own package. This
// sweeper stayed here because what it is is an autonomy-policy gate — the
// breaker, the blast-radius budget, the maintenance windows, the namespace
// allowlist and the plan-age bound — reading the same settings and the same
// incident queue the handlers beside it read. What it is NOT is the execution
// path: since PROJECT.md P23 that lives in internal/execution, and this
// sweeper reaches it through exactly the surface a handler does
// (execution.ExecuteApprovedPlan, execution.Overrides, execution.PolicyActor),
// holding no more than handleApproveIncident does. So the sweeper is a method
// on Server, started from cmd/hub like any other background loop.
//
// # What authorizes it
//
// Not a capability — there is no principal here to hold one. The operator who
// enabled the setting is the authorization, and that is why the settings page
// states plainly what is being accepted. Everything else that gates a human
// approval still applies unchanged and unweakened: the risk floor, the
// re-derivation of that floor against the resolved target, every per-action
// bound, the GitOps-ownership refusal, the dry-run attestation, the signed plan,
// the resourceVersion precondition, the audit trail. The guardrails that require
// an explicit human confirmation (scale-from-zero, patching a GitOps-managed
// object) therefore REFUSE here, because no confirmation can exist — which is
// the correct outcome, not a gap.

// DefaultUnattendedSweepInterval is how often the sweeper looks.
//
// Deliberately not fast. There is no latency requirement — an incident that
// waits 30 seconds for an automatic fix is not meaningfully worse off than one
// that waits 3, and the slower cadence keeps the sequential-execution property
// above cheap to reason about. It also bounds how quickly a misconfiguration
// can spend the fleet-wide budget.
const DefaultUnattendedSweepInterval = 30 * time.Second

// maxUnattendedPlanAge bounds how old an auto-approved plan may be and still be
// executed without a human.
//
// This exists because of what happens the moment the switch is turned on: every
// auto-approved plan already sitting in the approval queue becomes eligible at
// once. An operator enabling the feature to see how it behaves would instead
// watch a backlog of accumulated diagnoses execute across the fleet, capped only
// by the blast-radius limits — the worst possible first impression, and a real
// incident rather than a surprise.
//
// The age bound also happens to be right on its own merits. A diagnosis is a
// statement about a cluster at a moment. Ten minutes later it is probably still
// true; three days later nobody should be acting on it unattended, however
// confident the model was. Older plans are not discarded — they stay in the
// queue for a person, which is where they already were.
//
// unattendedCandidateQuery exempts one case from this bound: a plan that is
// already a known wave-2+ member of a BatchExecution batch (BUGS.md 100). Its
// age there is time spent waiting on this feature's OWN wave gate — bounded by
// orchestrator.maxBatchHoldDuration, not by this constant — not evidence the
// diagnosis is stale, and validationGracePeriod's floor (15 minutes, itself
// only a floor) routinely exceeds this window, so without the exemption a
// held wave-2 plan would always age out before it could ever be released. See
// that query's own comment for the exact clause and why wave 1 is not
// exempted the same way.
const maxUnattendedPlanAge = 10 * time.Minute

// maxUnattendedPerSweep bounds one tick, independently of the blast-radius cap.
//
// The caps are per-window; this is per-pass. It keeps one sweep bounded in time
// (each execution makes several tunnel calls) so a large backlog is worked
// through over successive ticks rather than in one long-running pass that
// overlaps the next tick.
const maxUnattendedPerSweep = 5

// unattendedCandidate is one plan the sweeper may execute.
type unattendedCandidate struct {
	IncidentID string
	PlanID     string
	ClusterID  string
	ActionType string
	GateReason string
	// TargetNamespace is the recommendation's own target namespace (empty for
	// a cluster-scoped target) — PROJECT.md T14: read here so the namespace
	// allowlist check can move from unattendedCandidateQuery's own WHERE
	// clause into the Go loop right below (alongside the pre-existing
	// IsConnected check, the exact same "deny before anything downstream can
	// act on it, just one layer up" shape that check already established),
	// which is what lets a namespace-blocked candidate be attributed a real
	// gate/reason instead of silently never appearing at all.
	TargetNamespace string
	// FleetGroupID is internal/fleetgroup's currently-open-only correlation
	// id for this incident's fingerprint, nil when this incident is not
	// currently grouped with any other. Carried so orchestrator.
	// ResolveBatchGating (BACKLOG.md R3) can recognise the correlated case —
	// several incidents sharing a fleet group AND an action_type, eligible
	// around the same time — without a second query re-deriving what
	// fleetgroup.Recompute already decided.
	FleetGroupID *string
}

// RunUnattendedExecutor ticks until ctx is cancelled, sweeping once per tick.
// Blocks — cmd/hub runs it in its own goroutine, the same shape as
// autoanalyze.Poller.Run and notify.WebhookNotifier.Run.
//
// Runs unconditionally from hub startup, like those two, because whether
// unattended execution is enabled is DB-backed and live-editable: a
// startup-time conditional would mean enabling it in the UI did nothing until
// someone restarted the hub.
func (s *Server) RunUnattendedExecutor(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweepCtx, _ := logging.NewUnitOfWork(ctx)
			start := time.Now()
			err := s.sweepUnattended(sweepCtx)
			metrics.ObserveSweeperRun("unattended_execution", time.Since(start), err)
			if err != nil {
				logger.ErrorContext(sweepCtx, "unattended-execution sweep failed", logging.Err(err))
			}
		}
	}
}

// sweepUnattended runs one pass: resolve the policy, and if unattended
// execution is on, execute what is eligible — one at a time, re-checking the
// blast radius before each.
func (s *Server) sweepUnattended(ctx context.Context) error {
	in, err := s.collectUnattended(ctx)
	if err != nil {
		return err
	}
	if !in.Limits.Enabled || len(in.Candidates) == 0 {
		return nil
	}
	tenantID, limits, breakerLimits, windows, candidates := in.TenantID, in.Limits, in.Breaker, in.Windows, in.Candidates

	// The time gate (BACKLOG R2, DESIGN.md §9.4). Evaluated ONCE per sweep rather
	// than per candidate: it is a property of the moment, not of the incident, and
	// evaluating it per candidate would produce one log line per queued incident
	// every thirty seconds for the whole length of a freeze.
	//
	// Checked before the blast-radius budget, deliberately. Both refuse, but a
	// freeze is a statement about whether ARGUS may act at all, so it should not be
	// possible for a budget query to fail and mask the fact that a change freeze was
	// in force.
	if decision := orchestrator.CheckWindows(time.Now(), windows); !decision.Allowed {
		logger.InfoContext(ctx, "candidates not executed: a maintenance window or change freeze is in force",
			slog.Int("candidates", len(candidates)), slog.String("reason", decision.Reason))
		for _, c := range candidates {
			s.recordAutomationGate(ctx, tenantID, c.IncidentID, GateMaintenanceWindow, decision.Reason)
		}
		return nil
	}

	// Sequential, and that is the whole design (see this file's header). Each
	// iteration re-checks the budget against what the previous ones actually
	// wrote, so a sweep that starts inside the limit cannot finish outside it.
	for _, c := range candidates {
		// The outcome gate (BACKLOG R2's second half). Per candidate, not per
		// sweep, because it is per CLUSTER — a cluster whose changes keep failing
		// must stop without stopping the rest of the fleet.
		//
		// Checked before the volume budget: a tripped breaker is a decision that
		// has already been made and recorded, so it should not be possible for a
		// budget query to fail and mask it. Same ordering argument as the freeze
		// check above.
		breaker, err := s.checkBreaker(ctx, tenantID, c.ClusterID, breakerLimits)
		if err != nil {
			// A breaker whose state cannot be established is not a closed breaker.
			// Abandon the sweep, exactly as a failed budget count does: whatever
			// broke it will break for the next candidate too, and every incident
			// stays in the approval queue where a human can still act on it.
			return fmt.Errorf("check circuit breaker for cluster %s: %w", c.ClusterID, err)
		}
		if !breaker.Allowed {
			// TrippedNow separates the moment from the standing state. The trip
			// itself is worth a line every time it happens; re-announcing an open
			// breaker every thirty seconds for as long as it stays open is not.
			if breaker.TrippedNow {
				logger.WarnContext(ctx, "circuit breaker tripped", slog.String("reason", breaker.Reason))
			}
			logger.InfoContext(ctx, "incident not executed: the circuit breaker is open",
				logging.IncidentID(c.IncidentID), logging.ClusterID(c.ClusterID))
			s.recordAutomationGate(ctx, tenantID, c.IncidentID, GateCircuitBreaker, breaker.Reason)
			continue
		}

		decision, err := s.checkUnattendedBudget(ctx, tenantID, c.ClusterID, limits)
		if err != nil {
			// A budget that cannot be established is not a budget with room in
			// it. Abandon the sweep rather than the candidate: whatever broke
			// the count will break it for the next one too, and the incidents
			// all stay in the approval queue, which is exactly where they were.
			return fmt.Errorf("check blast radius for cluster %s: %w", c.ClusterID, err)
		}
		if !decision.Allowed {
			// Logged once per refused candidate rather than recorded on the
			// incident: the incident is already in the state a refusal implies
			// (AwaitingApproval, visible to a human), and writing a row per
			// tick per candidate would produce one every 30 seconds for as long
			// as the burst lasted.
			logger.InfoContext(ctx, "incident not executed: the blast-radius cap refused it",
				logging.IncidentID(c.IncidentID), logging.ClusterID(c.ClusterID),
				slog.String("reason", decision.Reason))
			s.recordAutomationGate(ctx, tenantID, c.IncidentID, GateBlastRadius, decision.Reason)
			continue
		}
		s.executeUnattended(ctx, tenantID, c, decision)
	}
	return nil
}

// candidateQuery selects auto-approved plans awaiting nobody.
//
// Every clause is load-bearing:
//
//   - state = AwaitingApproval, because that is where Advance parks an
//     AutoApprove verdict and it is also what recordExecutingTransition
//     re-checks under a row lock. An incident that moved on (a human approved
//     it, someone rejected it, the object vanished) is no longer a candidate.
//   - gate_outcome = 'AutoApprove'. NeedsApproval means the gate itself asked
//     for a human, and no setting on the autonomy page can overrule that; this
//     feature executes what the policy already approved, it does not widen the
//     policy.
//   - NOT EXISTS a decision, which is the durable "somebody already acted on
//     this" record — the same predicate handleApproveIncident checks.
//   - created_at within maxUnattendedPlanAge, for the backlog reason above —
//     UNLESS this candidate is already a known wave-2+ member of a batch
//     (BUGS.md 100). A held wave-2 plan's age reflects time spent waiting on
//     this feature's OWN gate (orchestrator.BatchMembership), not staleness of
//     the diagnosis, and validationGracePeriod's 15-minute floor (itself only
//     a floor — B2 can stretch it further per cluster) is routinely longer
//     than the 10-minute window below: without this exemption, wave 2 would
//     silently and permanently age out of candidacy before wave 1 ever
//     releases it, every time, not just under contention. The exemption is
//     bounded by maxBatchHoldDuration (orchestrator/batch.go, 2 hours), not by
//     this query: a batch that never resolves is marked BatchStatusAbandoned,
//     at which point BatchMembership.Eligible() stops returning true for it
//     regardless of this clause, so nothing here can keep an abandoned
//     candidate eligible forever. Wave-1 members (wave_number = 1) are not
//     exempted — they are Eligible() immediately and still need the ordinary
//     staleness guard.
//   - superseded_at IS NULL. This clause is the one that was MISSING, and its
//     absence is the strongest argument in this codebase for why "a state that
//     has quietly split in two" is dangerous. Migration 000049 made a plan
//     un-approvable once ARGUS proposed the fix at source — enforced in the
//     approve handler and shown in the UI — but this query keys on
//     `state = AwaitingApproval` alone, so the sweeper would have executed a
//     superseded plan anyway. On the live run that produced it, that plan would
//     have set a working image back to a broken tag, unattended, with no human
//     to read the 409. Two readers of the same state disagreed about what it
//     meant, which is what happens when the real state lives in a column on
//     another table.
//   - action_type <> 'OpenPR', because OpenPR has no execution path at all here
//     (approving one records a decision and stops), and opening a pull request
//     with no human in the loop is a different consent question from patching a
//     cluster — one this setting was not presented as answering.
//
// LATEST recommendation per incident only. An incident re-analysed after an
// earlier recommendation would otherwise offer two candidate plans, and the
// stale one must never be the one that executes.
// The namespace allowlist (migration 000055) used to be filtered HERE, in
// SQL. PROJECT.md T14 moved it to the Go loop in collectUnattended, right
// beside the IsConnected check — the exact same "deny before anything
// downstream can act on it, just one layer up" shape that check already
// used, chosen specifically so a namespace-blocked candidate can be
// attributed GateNamespaceScope instead of silently never appearing. The
// safety property this clause's own comment used to describe ("a candidate
// that is not permitted must never become a candidate at all") still holds:
// the Go check runs before anything else touches the row (before it's
// appended to `connected`, before batch gating, before ever reaching
// sweepUnattended) — see collectUnattended's own comment on that check.
const unattendedCandidateQuery = `
	SELECT DISTINCT ON (r.incident_id)
	       r.incident_id, r.id, r.cluster_id, r.action_type, r.gate_reason, i.fleet_group_id,
	       coalesce(r.target_namespace, '')
	  FROM remediation_recommendations r
	  JOIN incidents i ON i.id = r.incident_id
	 WHERE i.state = $1
	   AND r.gate_outcome = 'AutoApprove'
	   AND r.action_type <> 'OpenPR'
	   AND r.superseded_at IS NULL
	   AND (
	         r.created_at >= $2
	         -- BUGS.md 100: a wave-2+ batch member is exempt from the age
	         -- floor above. Matched on action_type the same way
	         -- orchestrator.existingMembership matches it, so a stale
	         -- membership row left over from a since-changed recommendation
	         -- (a re-analysis that proposed a different fix) does not exempt
	         -- today's candidate.
	         OR EXISTS (
	               SELECT 1 FROM unattended_batch_members m
	               JOIN unattended_batches b ON b.id = m.batch_id
	              WHERE m.incident_id = r.incident_id
	                AND m.wave_number > 1
	                AND b.action_type = r.action_type)
	       )
	   AND NOT EXISTS (
	         SELECT 1 FROM remediation_approval_decisions d
	          WHERE d.recommendation_id = r.id)
	 ORDER BY r.incident_id, r.created_at DESC`

// collectUnattended resolves the policy and gathers candidates in one short,
// read-only transaction, committed before any execution starts — the same
// shape as autoanalyze.collectEligible, and for the same reason: nothing here
// needs to survive a later failure, and holding a transaction open across
// several tunnel calls per candidate would be worse than pointless.
// unattendedSweepInput is everything one sweep decides against, loaded in a
// single transaction so the whole tick sees one consistent view: a freeze or a
// threshold changed mid-sweep takes effect on the next tick rather than on half of
// this one.
//
// A struct rather than more return values — this was already a five-tuple before
// the breaker limits joined it.
type unattendedSweepInput struct {
	TenantID   string
	Limits     orchestrator.UnattendedLimits
	Breaker    orchestrator.BreakerLimits
	Windows    []orchestrator.Window
	Candidates []unattendedCandidate
}

func (s *Server) collectUnattended(ctx context.Context) (unattendedSweepInput, error) {
	var result unattendedSweepInput
	if err := data.InFleetScope(ctx, s.db.Pool, func(ctx context.Context, tx pgx.Tx, tenantID string) error {
		cfg, err := settings.Resolve(ctx, tx)
		if err != nil {
			return fmt.Errorf("resolve autonomy settings: %w", err)
		}
		limits := orchestrator.ResolveUnattendedLimits(
			cfg.AutonomyUnattendedExecutionEnabled, cfg.AutonomyMaxUnattendedPerCluster,
			cfg.AutonomyMaxUnattendedFleetWide, cfg.AutonomyUnattendedWindowSeconds)
		breakerLimits := orchestrator.ResolveBreakerLimits(
			cfg.AutonomyBreakerEnabled, cfg.AutonomyBreakerPerCluster,
			cfg.AutonomyBreakerFleetWide, cfg.AutonomyBreakerWindowSeconds)

		if !limits.Enabled {
			// The ordinary case for most installations, and it must stay cheap: no
			// candidate query at all, so a hub with this switched off pays one
			// settings read every 30 seconds and nothing else.
			result = unattendedSweepInput{TenantID: tenantID, Limits: limits, Breaker: breakerLimits}
			return nil
		}

		// Loaded in the same transaction as the settings and the candidates, so one
		// sweep decides against one consistent view: a freeze added mid-sweep takes
		// effect on the next tick rather than half of this one.
		stored, err := loadAutomationWindows(ctx, tx)
		if err != nil {
			return fmt.Errorf("load automation windows: %w", err)
		}
		windows := windowsOf(stored)

		// Deny-by-default, checked BEFORE the candidate query runs so an installation
		// that switched unattended execution on without saying where pays nothing and,
		// more importantly, does nothing. The log line exists because the failure mode
		// otherwise is silence: an operator enables the feature, watches nothing
		// happen, and has no way to tell "no eligible incidents" from "I forgot the
		// second half of the configuration".
		if len(cfg.AutonomyUnattendedNamespaces) == 0 {
			logger.WarnContext(ctx, "unattended execution is enabled but no namespaces are permitted, so nothing is eligible: set autonomy.unattendedNamespaces to the namespaces automation may act in (an empty list denies rather than permits, deliberately)")
			result = unattendedSweepInput{TenantID: tenantID, Limits: limits, Breaker: breakerLimits}
			return nil
		}

		rows, err := tx.Query(ctx, unattendedCandidateQuery,
			orchestrator.StateAwaitingApproval, time.Now().Add(-maxUnattendedPlanAge))
		if err != nil {
			return fmt.Errorf("select candidates: %w", err)
		}

		// Every connected, in-namespace candidate this tick, UNCAPPED —
		// maxUnattendedPerSweep is applied below, only to what BatchExecution
		// gating leaves eligible. See that call for why: capping here first could
		// truncate away exactly the wave-1 candidates a batch decision needs to
		// see, letting an arbitrary SQL row order decide which of a correlated
		// batch's members counts as "wave 1" instead of
		// orchestrator.ResolveBatchGating's own deterministic assignment.
		var connected []unattendedCandidate
		for rows.Next() {
			var c unattendedCandidate
			if err := rows.Scan(&c.IncidentID, &c.PlanID, &c.ClusterID, &c.ActionType, &c.GateReason, &c.FleetGroupID, &c.TargetNamespace); err != nil {
				rows.Close()
				return fmt.Errorf("scan candidate: %w", err)
			}
			// Namespace allowlist (migration 000055) — see unattendedCandidateQuery's
			// own comment for why this moved here from SQL. An empty allowlist
			// denies every namespace, matching the SQL predicate's own
			// `= ANY($3::text[])` semantics against an empty array exactly (both
			// mean "matches nothing").
			if !slices.Contains(cfg.AutonomyUnattendedNamespaces, c.TargetNamespace) {
				reason := fmt.Sprintf(
					"this plan's target namespace (%q) is not in the unattended-execution namespace allowlist, so it needs a human to approve it — set autonomy.unattendedNamespaces to change which namespaces automation may act in",
					c.TargetNamespace)
				// Written on the transaction this function already holds open,
				// not via recordAutomationGate's own separate one — this loop is
				// inside collectUnattended's single read-and-decide transaction
				// (see this function's own doc comment), so there is no reason to
				// pay for a second connection per candidate the way sweepUnattended
				// must (its checks span several independently-committed
				// transactions, one per candidate, by design).
				if err := SetAutomationGate(ctx, tx, c.IncidentID, GateNamespaceScope, reason); err != nil {
					logger.ErrorContext(ctx, "recording the namespace-scope automation gate failed",
						logging.IncidentID(c.IncidentID), logging.ClusterID(c.ClusterID), logging.Err(err))
				}
				continue
			}
			// Checked here rather than in SQL because connectedness is in-memory
			// gateway state, not a column. A disconnected cluster is skipped
			// silently and picked up on a later tick once its agent redials — the
			// incident is not failed for it, since nothing was attempted.
			if !s.gw.IsConnected(c.ClusterID) {
				if err := SetAutomationGate(ctx, tx, c.IncidentID, GateClusterUnreachable,
					"this incident's cluster is not currently connected to the hub, so the auto-approved plan cannot execute unattended right now — it will be retried automatically once the cluster reconnects"); err != nil {
					logger.ErrorContext(ctx, "recording the cluster-unreachable automation gate failed",
						logging.IncidentID(c.IncidentID), logging.ClusterID(c.ClusterID), logging.Err(err))
				}
				continue
			}
			connected = append(connected, c)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("iterate candidates: %w", err)
		}
		rows.Close()

		// BACKLOG.md R3: BatchExecution. Resolves any batch whose wave-1 outcome
		// just became known, groups this tick's fleet-correlated candidates into
		// new or existing batches, and reports which candidates a batch is
		// currently holding back. A candidate absent from batchMembership
		// belongs to no batch and is ungated by this call — exactly the pre-R3
		// behaviour.
		batchCandidates := make([]orchestrator.BatchCandidate, len(connected))
		for i, c := range connected {
			batchCandidates[i] = orchestrator.BatchCandidate{
				IncidentID:   c.IncidentID,
				ClusterID:    c.ClusterID,
				ActionType:   c.ActionType,
				FleetGroupID: c.FleetGroupID,
			}
		}
		batchMembership, err := orchestrator.ResolveBatchGating(ctx, tx, tenantID, batchCandidates, time.Now())
		if err != nil {
			return fmt.Errorf("resolve batch gating: %w", err)
		}

		var out []unattendedCandidate
		for _, c := range connected {
			if m, batched := batchMembership[c.IncidentID]; batched && !m.Eligible() {
				// Held, not refused: this candidate has cleared every namespace/
				// age/decision check above and could execute right now as far as
				// the blast-radius cap and breaker are concerned. It is not
				// attempted this tick purely because it is a non-canary member of
				// a batch still waiting on (or blocked on) wave 1's outcome — see
				// orchestrator.BatchMembership.HoldReason.
				logger.InfoContext(ctx, "incident held, not refused: it is a non-canary member of a batch still waiting on wave 1",
					logging.IncidentID(c.IncidentID), logging.ClusterID(c.ClusterID),
					slog.String("reason", m.HoldReason()))
				if err := SetAutomationGate(ctx, tx, c.IncidentID, GateBatchHold, m.HoldReason()); err != nil {
					logger.ErrorContext(ctx, "recording the batch-hold automation gate failed",
						logging.IncidentID(c.IncidentID), logging.ClusterID(c.ClusterID), logging.Err(err))
				}
				continue
			}
			out = append(out, c)
			if len(out) >= maxUnattendedPerSweep {
				break
			}
		}

		result = unattendedSweepInput{
			TenantID:   tenantID,
			Limits:     limits,
			Breaker:    breakerLimits,
			Windows:    windows,
			Candidates: out,
		}
		return nil
	}); err != nil {
		return unattendedSweepInput{}, err
	}
	return result, nil
}

// checkBreaker evaluates the outcome breaker in its own short transaction, for
// the same reason checkUnattendedBudget does: the count and any trip it causes
// must commit together, and immediately before the execution they authorize.
func (s *Server) checkBreaker(ctx context.Context, tenantID, clusterID string, limits orchestrator.BreakerLimits) (orchestrator.BreakerDecision, error) {
	var decision orchestrator.BreakerDecision
	if err := data.InScope(ctx, s.db.Pool, tenantID, nil, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		decision, err = orchestrator.CheckBreaker(ctx, tx, tenantID, clusterID, limits)
		return err
	}); err != nil {
		return orchestrator.BreakerDecision{}, err
	}
	return decision, nil
}

// checkUnattendedBudget runs the blast-radius count in its own short
// transaction, immediately before the execution it authorizes — not once per
// sweep. The gap between the count and the write is the window this feature has
// to keep small, and re-counting per candidate is what makes the sequential
// property above actually hold.
func (s *Server) checkUnattendedBudget(ctx context.Context, tenantID, clusterID string, limits orchestrator.UnattendedLimits) (orchestrator.BlastRadiusDecision, error) {
	var decision orchestrator.BlastRadiusDecision
	if err := data.InScope(ctx, s.db.Pool, tenantID, nil, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		decision, err = orchestrator.CheckBlastRadius(ctx, tx, clusterID, limits, time.Now())
		return err
	}); err != nil {
		return orchestrator.BlastRadiusDecision{}, err
	}
	return decision, nil
}

// executeUnattended runs one plan through the exact same path a human approval
// takes — execution.PreparePlan, the Executing commit, the tunnel call, the outcome
// record — with the actor being the policy rather than a person.
//
// Sharing that path is not a convenience. A parallel implementation would be a
// second place for the risk floor, the guardrails, the dry-run gate and the
// signing to be got right, and the unattended one is the copy nobody is
// watching. Anything that refuses a human approval refuses here too.
func (s *Server) executeUnattended(ctx context.Context, tenantID string, c unattendedCandidate, budget orchestrator.BlastRadiusDecision) {
	// ReadInScope, not InScope: this transaction exists only to give
	// execution.PreparePlan a reader (resolveOwnership's cached ownership lookup needs
	// one). Nothing in it is written, and the two transactions that DO write
	// are opened separately by the recording functions — that split is what
	// makes a crash mid-execution leave an honest record, and it must not be
	// collapsed into this one. ReadInScope never commits, so it cannot be.
	if err := data.ReadInScope(ctx, s.db.Pool, tenantID, nil, func(ctx context.Context, tx pgx.Tx) error {
		plan, err := execution.LoadRecommendationPlan(ctx, tx, c.PlanID)
		if err != nil {
			logger.ErrorContext(ctx, "loading the recommendation plan failed",
				logging.IncidentID(c.IncidentID), logging.ClusterID(c.ClusterID),
				slog.String("plan_id", c.PlanID), logging.Err(err))
			return nil
		}

		// A synthetic requestContext, and the fields it deliberately leaves empty
		// are the point. UserID is "" because there is no user; Grants is nil
		// because there is no principal to hold capabilities, and nothing on this
		// path consults them (see the header: the setting is the authorization).
		// TenantID and Tx are the two things the shared path genuinely needs.
		rc := &requestContext{Tx: tx, TenantID: tenantID}

		actor := execution.PolicyActor
		// The reason is assembled here, at the moment of the decision, because
		// afterwards neither half is recoverable: the gate's verdict is about this
		// plan and the budget numbers are about this instant. Together they are the
		// complete answer to "why did this change happen and why was it allowed to
		// happen without me" — which is the question this feature has to be able to
		// answer, in the audit trail, without anyone reconstructing it.
		actor.Reason = fmt.Sprintf("executed without human approval because unattended execution is enabled and the autonomy gate auto-approved this plan (%s); blast radius at the time: %s",
			c.GateReason, budget.Reason)

		resp, err := s.exec().ExecuteApprovedPlan(ctx, scopeOf(rc), c.IncidentID, c.PlanID, c.ClusterID, plan,
			// No overrides and no confirmation token, which means the guardrails
			// that require an explicit human confirmation refuse. That is deliberate
			// and it is the one place where unattended execution is strictly more
			// restricted than an approval: scaling a workload up from zero, and
			// patching an object a Helm release or GitOps controller owns, both stay
			// impossible without someone stating the intent.
			execution.Overrides{}, actor)
		if err != nil {
			// Every refusal lands here, and they are not all the same kind of
			// event: a guardrail refusal is the system working, while a signing or
			// tunnel failure is not. Neither changes what happens next — the
			// incident stays at AwaitingApproval and a human sees it in the queue,
			// because nothing was committed. Logged with the plan so the reason is
			// findable; not written to the incident, for the same
			// once-every-30-seconds reason the budget refusal above is not.
			if errors.Is(err, execution.ErrScaleFromZeroRefused) || errors.Is(err, execution.ErrGitOpsManagedRefused) {
				logger.InfoContext(ctx, "plan needs an explicit human confirmation; left in the approval queue",
					logging.IncidentID(c.IncidentID), logging.ClusterID(c.ClusterID), logging.Err(err))
				return nil
			}
			logger.WarnContext(ctx, "incident not executed",
				logging.IncidentID(c.IncidentID), logging.ClusterID(c.ClusterID), logging.Err(err))
			return nil
		}

		logger.WarnContext(ctx, "EXECUTED WITHOUT HUMAN APPROVAL",
			logging.IncidentID(c.IncidentID), logging.ClusterID(c.ClusterID),
			slog.String("action_type", c.ActionType), slog.String("incident_state", resp.IncidentState))
		if s.events != nil {
			s.events.Publish(events.IncidentUpdated(c.IncidentID, c.ClusterID))
		}
		return nil
	}); err != nil {
		logger.ErrorContext(ctx, "unattended execution transaction failed",
			logging.IncidentID(c.IncidentID), logging.ClusterID(c.ClusterID), logging.Err(err))
	}
}
