package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/domain"
	"argus/internal/fleetgroup"
	"argus/internal/llm"
	"argus/internal/logging"
	"argus/internal/notify"
	"argus/internal/objectgroup"
	"argus/internal/remediation"
	"argus/internal/replicagroup"
	"argus/internal/resolution"
	"argus/internal/settings"
	"argus/internal/timeline"
)

// notifiableStates is BACKLOG.md N1's widened trigger set: the small, fixed
// list of incidents.state values that mean "a human should be told,"
// checked against every SINGLE transition SetState ever applies (see
// SetState's own doc comment: this is the one place incidents.state is
// ever written, so hooking here — rather than at each of the many call
// sites that reach it — cannot be bypassed by a call site nobody remembered
// to wire up, matching this codebase's "non-advertisement is not
// enforcement" lesson).
//
//   - AwaitingApproval: a plan needs a human decision.
//   - Failed / ExecutionUnknown: an execution attempt did not cleanly
//     resolve (BACKLOG.md C8's ExecutionUnknown outcome has "four exits and
//     nothing sweeps it" without this).
//   - ValidationUnknown: a fix was applied and ARGUS could not confirm
//     whether it held, repeatedly, past its bound. It belongs here for the
//     same reason ExecutionUnknown does, only more so: this state is reached
//     by a background sweeper with no human anywhere near it, and an incident
//     that quietly stops being validated is precisely the thing nobody goes
//     looking for. Without a notification, "we could not tell" is
//     operationally identical to the silence it replaced.
//   - Reopened: a symptom ARGUS believed fixed came back.
//
// Deliberately NOT self-transitionable per allowedTransitions (no state in
// that map has an edge to itself), so every call that reaches this check
// represents a genuinely NEW entry into the state, never a repeat sweep
// observing the same still-open question. See the notify.NotifyTransition
// call site below for why the key passed still can't be the bare state
// name, despite that.
// maxAutoAnalysisReopens is PROJECT.md B144's bound: how many times ONE
// incident's automatic-analysis eligibility may be reset by a Reopened
// transition before SetState stops resetting it and leaves the incident
// permanently attempted, same as autoanalyze's own maxAutoAnalysisAttempts
// gives up after exhausting ITS bound on a different failure mode. Three,
// matching that constant's own number for the same reason it was chosen
// there (BACKLOG.md/autoanalyze.go's own comment): enough that an ordinary,
// one-off spurious reopen (stale evidence arriving just after a genuine fix)
// is never mistaken for a problem, while a genuinely flip-flopping incident
// still gets handed to a human well before it could consume unlimited
// automatic analysis-and-possibly-execution cycles.
const maxAutoAnalysisReopens = 3

var notifiableStates = map[string]bool{
	StateAwaitingApproval:  true,
	StateFailed:            true,
	StateExecutionUnknown:  true,
	StateValidationUnknown: true,
	StateReopened:          true,
}

// ErrIllegalTransition is the sentinel every rejected state transition
// wraps (via IllegalTransitionError.Unwrap), so a caller can tell "this
// incident is not in a state where that makes sense" — an ordinary,
// expected outcome of a concurrent or out-of-order request, and an HTTP 409
// rather than a 500 — apart from a genuine database failure. Callers check
// with errors.Is(err, orchestrator.ErrIllegalTransition).
var ErrIllegalTransition = errors.New("illegal incident state transition")

// ErrIncidentNotFound is returned by SetState when the incident row is
// absent — or invisible under the calling transaction's RLS scope, which is
// indistinguishable from absent and equally a caller bug. The old bare
// UPDATE silently affected zero rows and returned nil in exactly this case;
// now that SetState has to read the current state anyway, saying so is
// free.
var ErrIncidentNotFound = errors.New("incident not found")

// IllegalTransitionError is the concrete error SetState returns when
// From -> To is not one of state.go's allowedTransitions edges. It carries
// both ends of the rejected transition so a log line or an API problem
// detail can name them without the caller re-reading the row.
type IllegalTransitionError struct {
	IncidentID string
	From       string
	To         string
}

func (e *IllegalTransitionError) Error() string {
	// The terminal wording is reserved for the two states that are terminal
	// BY DESIGN — an unrecognized `from` also has no outgoing edges, but
	// calling it "terminal" would misdescribe it (see allowedTransitions on
	// why an unknown state fails closed).
	if e.From == StateDismissed || e.From == StateResolved {
		return fmt.Sprintf("orchestrator: incident %s is %s, which is terminal — refusing to move it to %s",
			e.IncidentID, e.From, e.To)
	}
	return fmt.Sprintf("orchestrator: incident %s cannot move from %s to %s (not a legal transition; see internal/orchestrator/state.go's allowedTransitions)",
		e.IncidentID, e.From, e.To)
}

func (e *IllegalTransitionError) Unwrap() error { return ErrIllegalTransition }

// MarkInvestigating sets an incident's state to Investigating — called
// right before internal/llm.Provider.Investigate actually runs
// (internal/api/analyze.go's handleAnalyzeIncident,
// internal/autoanalyze's investigateOne).
//
// Reachable from every state EXCEPT Executing, Dismissed and Resolved, per
// state.go's allowedTransitions. This function used to be documented as
// deliberately unconditional, on the reasoning that re-analysis is a real,
// already-exposed capability (incident:reanalyse) invocable from any state
// and that "an investigation is running right now" is simply true whenever
// this is called. That reasoning still holds for every state the table
// allows — a stale RecommendationReady, a NeedsHumanInvestigation, a Failed
// execution, a Reopened symptom — and is why -> Investigating has by far
// the widest set of legal predecessors. What it did NOT justify, and what
// the three exclusions now close, is walking an incident out of a terminal
// state (silently erasing an approver's rejection) or out of Executing
// while a signed plan is in flight over the tunnel. See
// allowedTransitions' own doc comment for both concrete violations.
//
// A caller that gets back an error wrapping ErrIllegalTransition has been
// told something real about the incident, not about the database: the
// re-analysis was refused because the incident is closed or mid-execution.
//
// tenantID/clusterID are used only to write this transition's
// timeline_events row (BACKLOG.md B1) — SetState itself needs neither, it
// re-reads everything it requires from the locked incidents row.
func MarkInvestigating(ctx context.Context, tx pgx.Tx, tenantID, clusterID, incidentID string) error {
	return MarkInvestigatingWithDetail(ctx, tx, tenantID, clusterID, incidentID, nil)
}

// MarkInvestigatingWithDetail is MarkInvestigating with extra keys on the
// InvestigationStarted event's payload. That event is the record of when an
// investigation started (PROJECT.md M1: GET /incidents/{id}'s
// analysisStartedAt is read from it, not stored a second time), so a caller
// that knows more about the run it is starting — internal/api's manual
// analyze records the AI backend and model it was claimed with — attaches it
// here rather than to a parallel column.
func MarkInvestigatingWithDetail(ctx context.Context, tx pgx.Tx, tenantID, clusterID, incidentID string, detail map[string]any) error {
	if err := SetState(ctx, tx, incidentID, StateInvestigating); err != nil {
		return err
	}
	if err := timeline.Record(ctx, tx, timeline.Event{
		TenantID: tenantID, ClusterID: clusterID, IncidentID: incidentID,
		Type:    timeline.EventInvestigationStarted,
		Summary: "Investigation started",
		Detail:  detail,
	}); err != nil {
		return fmt.Errorf("orchestrator: record InvestigationStarted timeline event for incident %s: %w", incidentID, err)
	}
	return nil
}

// SetState moves an incident to newState, enforcing state.go's
// allowedTransitions — the primitive every other state-changing function in
// this package (MarkInvestigating, ApplyAnalysisResult, ValidationSweeper)
// and internal/api's approve/reject/execute paths and
// internal/gateway/finding.go's Reopened transition are built on, so there
// is exactly one line of SQL anywhere in this codebase that writes
// incidents.state — and therefore exactly one place that has to get the
// state machine right.
//
// The SELECT ... FOR UPDATE is load-bearing, not just a way to read the
// current state: it takes a row-level exclusive lock held until the
// caller's transaction commits or rolls back, which serializes every
// concurrent transition against the same incident. Without it, validating
// the transition would be pure theatre — two transactions could both read
// "AwaitingApproval", both find their transition legal, and both apply it.
// lld/08-remediation-contracts.md §6 specifies a per-(cluster, gvk,
// namespace, name) Redis lock held for a plan's whole execution, which does
// not exist in this codebase; a row lock on the incident is the minimum
// that closes the Executing race described in allowedTransitions' doc
// comment, and it needs no new infrastructure.
//
// The lock has always effectively been taken here — the old bare UPDATE
// locked the same row for the same duration — so this adds no new blocking
// behaviour beyond moving the lock acquisition a few microseconds earlier
// in the transaction. internal/execution's
// recordExecutingTransition already takes this exact lock itself before
// calling SetState; re-locking a row the same transaction already holds is
// a no-op, so that path is unaffected.
func SetState(ctx context.Context, tx pgx.Tx, incidentID, newState string) error {
	// fingerprint is read in the same round trip the lock is taken in — the
	// closed-state branch below needs it, and the old code paid for a
	// second query to get it. tenant_id is read for the same reason
	// notifiableStates' hook below needs it — incident_notifications
	// denormalizes tenant_id/cluster_id (migration 000083, lld/05-data-model.md
	// §6) and this is already the one query that locks and reads this row.
	var currentState, fingerprint, clusterID, tenantID string
	var workloadKey, openingReason, relatedWorkloadKey, objectKey *string
	var autoAnalysisReopenCount int
	if err := tx.QueryRow(ctx,
		`SELECT state, fingerprint, cluster_id, tenant_id, workload_key, opening_reason, related_workload_key, auto_analysis_reopen_count, object_key FROM incidents WHERE id = $1 FOR UPDATE`, incidentID,
	).Scan(&currentState, &fingerprint, &clusterID, &tenantID, &workloadKey, &openingReason, &relatedWorkloadKey, &autoAnalysisReopenCount, &objectKey); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("orchestrator: %w: %s", ErrIncidentNotFound, incidentID)
		}
		return fmt.Errorf("orchestrator: lock incident %s for a transition to %s: %w", incidentID, newState, err)
	}

	if !CanTransition(currentState, newState) {
		return &IllegalTransitionError{IncidentID: incidentID, From: currentState, To: newState}
	}

	// resolved_at (BACKLOG.md H4, migration 000065) records the moment an
	// incident actually closed — set here, in the one function that ever
	// writes incidents.state, so every closing path (manual resolve/dismiss,
	// the validation sweeper's auto-resolve, a merge-sweeper transition)
	// stamps it identically rather than each caller remembering to. Set only
	// on the transition INTO a closed state, never cleared or overwritten:
	// CanTransition already refuses any edge OUT of Resolved/Dismissed (both
	// have empty edge sets), so this UPDATE can never run a second time for
	// the same incident.
	if newState == StateResolved {
		// BACKLOG.md T2 (migration 000091): "self-healed" and "remediated"
		// read identically as Resolved today — measured 2026-09-04, roughly
		// 88% of this dev DB's 336 Resolved incidents carry neither a
		// succeeded execution nor a merged pull request, so "Resolved"
		// mostly means "stopped happening," not "we fixed it." Derived HERE,
		// the one place any incident ever becomes Resolved, rather than at
		// each of the (currently four) call sites that reach this state —
		// ValidationSweeper's field-verified close, autoanalyze's
		// object-is-gone and stale-object closes, and a human's manual
		// resolve via internal/api/incident_triage.go — so a fifth caller
		// added later gets this for free instead of silently reporting NULL.
		kind, err := deriveResolutionKind(ctx, tx, incidentID)
		if err != nil {
			return fmt.Errorf("orchestrator: derive resolution kind for incident %s: %w", incidentID, err)
		}
		if _, err := tx.Exec(ctx,
			`UPDATE incidents SET state = $2, resolved_at = now(), resolution_kind = $3, automation_gate = NULL, automation_gate_reason = NULL, automation_gate_at = NULL WHERE id = $1`,
			incidentID, newState, kind); err != nil {
			return fmt.Errorf("orchestrator: set incident %s state to %s: %w", incidentID, newState, err)
		}
	} else if IsClosed(newState) {
		// Dismissed or Expired — the two closed states that are not Resolved.
		// Deliberately NOT given a resolution_kind: neither "a human actively
		// rejected a plan" (Dismissed) nor "this candidate set aged out in
		// bulk, unconsidered individually" (Expired) is the same kind of fact
		// as "this closed, and here is what closed it" — see migration
		// 000091's own comment for why forcing either into the
		// remediated/self_healed enum would misdescribe it rather than leave
		// it honestly inapplicable.
		//
		// This branches on orchestrator.IsClosed, NOT fleetgroup.IsClosedState
		// (PROJECT.md B156) — the two are deliberately different sets (see
		// IsClosed's own doc comment): fleetgroup's is the 2-value
		// {Resolved, Dismissed} correlation-matching predicate, and using it
		// here used to mean a transition into Expired matched neither this
		// branch nor the StateResolved one above, so it stamped no
		// resolved_at at all. IsClosed is the 3-value {Resolved, Dismissed,
		// Expired} lifecycle predicate this stamp actually needs.
		if _, err := tx.Exec(ctx, `UPDATE incidents SET state = $2, resolved_at = now(), automation_gate = NULL, automation_gate_reason = NULL, automation_gate_at = NULL WHERE id = $1`, incidentID, newState); err != nil {
			return fmt.Errorf("orchestrator: set incident %s state to %s: %w", incidentID, newState, err)
		}
		// PROJECT.md T6: feed this closure back into promotion, by extending
		// the existing toleration mechanism rather than a second suppression
		// path — see suppressRecurrenceOnClose's own doc comment. Only
		// Dismissed/Expired reach this branch (Resolved took the `if` above),
		// which is exactly right: "the fault is gone" (Resolved) is not a
		// reason to stop detecting it if it comes back, but "this needs no
		// action" (Dismissed) or "nobody reviewed this occurrence" (Expired)
		// both are candidates for not re-raising the identical thing
		// immediately. Never fatal to the close itself.
		suppressRecurrenceOnClose(ctx, tx, incidentID, tenantID, clusterID, newState, objectKey)
	} else if newState == StateValidating {
		// validating_at (PROJECT.md B139, migration 000096) records when
		// THIS Validating stint began — overwritten every time, unlike
		// resolved_at, because CanTransition allows re-entering Validating
		// (a re-attempted fix after Investigating/ValidationUnknown), and
		// the pull-request route's sweep query needs "since the current
		// attempt landed," not "the first time this incident was ever
		// Validating." The in-place route's own clock
		// (remediation_executions.executed_at) is unaffected and unchanged.
		if _, err := tx.Exec(ctx, `UPDATE incidents SET state = $2, validating_at = now(), automation_gate = NULL, automation_gate_reason = NULL, automation_gate_at = NULL WHERE id = $1`, incidentID, newState); err != nil {
			return fmt.Errorf("orchestrator: set incident %s state to %s: %w", incidentID, newState, err)
		}
	} else if newState == StateReopened {
		// PROJECT.md B144 (migration 000097): a Reopened incident is a
		// perfectly ordinary automatic-analysis candidate by
		// autoanalyze.candidateQuery's OWN state list (Reopened is not one of
		// the states it excludes) — the sole reason it never actually got
		// re-analyzed is that auto_analysis_attempted_at is a ONE-SHOT gate
		// nothing ever reset, so an incident that reached Reopened stayed
		// permanently "already attempted" regardless of how long it had been
		// genuinely healthy again. This is the one place every Reopened
		// transition passes through, so it is the one place that can close
		// that gap for every caller (event-driven: gateway/finding.go's
		// reopenAfterRecurrence; sweep-driven: ValidationSweeper) without
		// either one having to remember to.
		//
		// Bounded deliberately, and by a NEW, separate counter
		// (auto_analysis_reopen_count) rather than by reusing
		// autoanalyze's own auto_analysis_attempts: that counter bounds
		// retries of a FAILED investigation call within one analysis cycle
		// (a different failure mode, already handled), and conflating the
		// two would let a reopen silently consume budget meant for
		// transient-failure retries or vice versa. maxAutoAnalysisReopens
		// bounds a DIFFERENT risk this bug being fixed newly creates: an
		// incident that keeps flip-flopping Validating <-> Reopened (a
		// genuinely bad fix, or noisy corroborating evidence) must not be
		// allowed to re-trigger automatic analysis — and, if auto-approved,
		// automatic execution — forever. Once the bound is spent,
		// auto_analysis_attempted_at is deliberately left exactly as it was
		// (permanently "attempted"): the existing, already-correct answer
		// for "give up and let a human decide" (autoanalyze's own retry
		// policy), applied to this new case rather than inventing a second
		// one.
		//
		// reopened_at (migration 000098, found live 2026-09-06 re-verifying
		// this very fix): resetting auto_analysis_attempted_at alone re-admits
		// the incident past candidateQuery's own SQL WHERE clause, but
		// autoanalyze.selectEligible's separate Go-side HasAnalysis exclusion
		// then silently discards it anyway — HasAnalysis meant "has ANY
		// analyses row, ever," true for essentially every Reopened incident,
		// since it needed an analysis to produce the plan that was executed
		// and later reopened. Stamped on EVERY Reopened transition
		// (regardless of the bound below), because it records a plain
		// historical fact ("this incident most recently reopened at T") that
		// candidateQuery's own HasAnalysis subquery now compares an
		// analyses.created_at against — not a second budget of its own.
		if autoAnalysisReopenCount < maxAutoAnalysisReopens {
			if _, err := tx.Exec(ctx,
				`UPDATE incidents SET state = $2, auto_analysis_reopen_count = auto_analysis_reopen_count + 1, auto_analysis_attempted_at = NULL, reopened_at = now(), automation_gate = NULL, automation_gate_reason = NULL, automation_gate_at = NULL WHERE id = $1`,
				incidentID, newState); err != nil {
				return fmt.Errorf("orchestrator: set incident %s state to %s: %w", incidentID, newState, err)
			}
		} else if _, err := tx.Exec(ctx, `UPDATE incidents SET state = $2, reopened_at = now(), automation_gate = NULL, automation_gate_reason = NULL, automation_gate_at = NULL WHERE id = $1`, incidentID, newState); err != nil {
			return fmt.Errorf("orchestrator: set incident %s state to %s: %w", incidentID, newState, err)
		}
	} else if _, err := tx.Exec(ctx, `UPDATE incidents SET state = $2, automation_gate = NULL, automation_gate_reason = NULL, automation_gate_at = NULL WHERE id = $1`, incidentID, newState); err != nil {
		return fmt.Errorf("orchestrator: set incident %s state to %s: %w", incidentID, newState, err)
	}

	// BACKLOG.md N1: tell a human. The key is deliberately NOT the bare
	// newState string: notify.NotifyTransition treats an unchanged key as
	// "still the same open question, don't re-notify" (see its own doc
	// comment), and a bare state name would wrongly conflate two SEPARATE
	// entries into the same state — e.g. AwaitingApproval -> Investigating
	// -> AwaitingApproval again after a re-analysis is a genuinely new
	// event (a fresh plan needs a fresh decision) that must still notify,
	// not be silently swallowed because the state name matches what was
	// stored from the first time. Suffixing with the current instant makes
	// this call's key differ from whatever is already stored for every
	// actual transition: two SetState calls for the SAME incident can't
	// observe the same nanosecond in practice (each already did a
	// round trip to Postgres to take this row's own lock), so this is safe
	// without needing a dedicated sequence column. Contrast
	// mergewatch.go's own call, which deliberately passes a fixed, un-
	// suffixed literal — repeated observation of an UNCHANGED condition
	// (the pull request is still stale next tick too) is exactly the case
	// that must collide and stay deduped.
	if notifiableStates[newState] {
		key := fmt.Sprintf("%s@%s", newState, time.Now().UTC().Format(time.RFC3339Nano))
		summary := fmt.Sprintf("Incident %s (cluster %s, fingerprint %s) is now %s.", incidentID, clusterID, fingerprint, newState)
		if err := notify.NotifyTransition(ctx, tx, tenantID, clusterID, incidentID, key, summary); err != nil {
			return fmt.Errorf("orchestrator: queue notification for incident %s -> %s: %w", incidentID, newState, err)
		}
	}

	// This incident's lifecycle just closed if (and only if) newState is one
	// of orchestrator's OWN closed states (IsClosed, not
	// fleetgroup.IsClosedState — PROJECT.md B156; same fix as the
	// resolved_at branch above, for the same reason) — MarkInvestigating's
	// calls (always -> Investigating, never closed) skip this entirely. See
	// fleetgroup.Recompute's own doc comment for why a closing transition is
	// one of exactly two events that can require a fleet-wide group to
	// shrink or disband.
	//
	// Firing this for a transition into Expired does not, by itself, make
	// this incident leave any of the three groups below: fleetgroup,
	// replicagroup and objectgroup each hardcode their OWN "currently open"
	// query as `state NOT IN ('Resolved', 'Dismissed')` (deliberately
	// 2-valued, matching fleetgroup.ClosedStates — see IsClosed's doc
	// comment on why that must stay 2-valued: a recurring Finding needs to
	// be able to re-attach to an Expired incident, which requires
	// correlation to keep treating it as open). So this incident is still
	// counted "open" by all three Recompute calls below even once Expired,
	// and the closing transition this block reacts to is this incident's
	// OWN lifecycle closing, not its removal from anyone's open set. What
	// firing Recompute here DOES still do correctly: pick up group
	// membership this incident had never been evaluated for (e.g. a sibling
	// incident opened after this one, on the same fingerprint/workload,
	// whose own Finding-driven Recompute call ran before this incident
	// existed) — the same correctness fix every other closing transition
	// already gets, applied uniformly rather than carved out for Expired.
	if IsClosed(newState) {
		if err := fleetgroup.Recompute(ctx, tx, fingerprint); err != nil {
			return fmt.Errorf("orchestrator: recompute fleet group for incident %s: %w", incidentID, err)
		}
		// Same trigger, replica-level correlation's re-scoped counterpart
		// (internal/replicagroup, migration 000042) — a closing incident
		// carrying a workload_key may need its (workload, reason) group to
		// shrink or disband, exactly like fleetgroup above.
		if workloadKey != nil && openingReason != nil {
			if err := replicagroup.Recompute(ctx, tx, clusterID, *workloadKey, *openingReason); err != nil {
				return fmt.Errorf("orchestrator: recompute replica group for incident %s: %w", incidentID, err)
			}
		}
		// Cross-object correlation's own close-time trigger (internal/
		// objectgroup, migration 000070, BACKLOG.md's A3b) — same event
		// fleetgroup/replicagroup above already recompute on: a closing
		// incident carrying either workload_key OR related_workload_key may
		// need its object group to shrink or disband. Whichever of the two
		// this incident carries is passed as the anchor (never both — see
		// internal/gateway's relatedWorkloadCorrelationKey doc comment);
		// Recompute is a no-op when handed "", so no extra guard is needed
		// for an incident carrying neither.
		anchorWorkloadKey := ""
		if workloadKey != nil {
			anchorWorkloadKey = *workloadKey
		} else if relatedWorkloadKey != nil {
			anchorWorkloadKey = *relatedWorkloadKey
		}
		if err := objectgroup.Recompute(ctx, tx, clusterID, anchorWorkloadKey); err != nil {
			return fmt.Errorf("orchestrator: recompute object group for incident %s: %w", incidentID, err)
		}
	}
	return nil
}

// resolutionKindRemediated/resolutionKindSelfHealed are migration 000091's
// incidents.resolution_kind values — mirrored here as constants (rather than
// left as bare strings at the one call site) so a future second caller, or a
// test, cannot introduce a third spelling.
const (
	resolutionKindRemediated = "remediated"
	resolutionKindSelfHealed = "self_healed"
)

// deriveResolutionKind answers, for an incident about to become Resolved,
// the one question BACKLOG.md T2 says is safe to answer after the fact: did
// ARGUS's own remediation machinery have anything to do with this closing —
// not "is the underlying fault actually gone," which nothing in this
// codebase can know retroactively (see migration 000091's own comment).
//
// "Remediated" means a succeeded remediation_executions row exists for this
// incident (the in-place channel) OR incidents.pr_merged_at is set (the
// pull-request channel, migration 000058) — the exact same two facts
// ValidationSweeper's own resolvableIncident.Route already distinguishes
// between, reused here rather than re-derived a second way. Everything else
// — the object was deleted (autoanalyze's objectIsGone/stale-object
// sweepers), a symptom simply stopped recurring, a human closed it by hand
// with nothing executed — is "self-healed": ARGUS observed it stop, or a
// human said so, but ARGUS did not make it stop.
//
// Queried fresh inside the caller's own transaction rather than threaded in
// as a parameter: SetState is the one place any incident ever becomes
// Resolved, and by the time it runs, whichever route produced this closure
// (an execution, a merge, or neither) was already committed by an earlier,
// separate transaction — there is nothing this read could observe mid-flight
// that the caller could have supplied more freshly itself.
func deriveResolutionKind(ctx context.Context, tx pgx.Tx, incidentID string) (string, error) {
	var remediated bool
	if err := tx.QueryRow(ctx,
		`SELECT incidents.pr_merged_at IS NOT NULL OR EXISTS (
		   SELECT 1 FROM remediation_executions re
		    WHERE re.incident_id = incidents.id AND re.outcome = 'succeeded'
		 )
		   FROM incidents WHERE incidents.id = $1`, incidentID,
	).Scan(&remediated); err != nil {
		return "", fmt.Errorf("check for a linked execution or merged pull request: %w", err)
	}
	if remediated {
		return resolutionKindRemediated, nil
	}
	return resolutionKindSelfHealed, nil
}

// ReadmitForAutoAnalysis re-arms a Diagnosed or NeedsHumanInvestigation
// incident's automatic-analysis eligibility when a Finding recurs on it —
// the event-driven counterpart to SetState's StateReopened branch above,
// for the one pair of states that branch explicitly does NOT cover (see
// sweepSelfHealing's own "Recurrence" doc comment: these two states never
// transition through Reopened at all, because they were never closed in
// the first place).
//
// # The gap this closes
//
// Found live 2026-10-13 investigating a real incident stuck exactly this
// way: a manually-triggered analysis concluded isFault:false, a Finding
// recurred 43 seconds later, and the incident then sat genuinely quiet for
// 15+ minutes with no automatic path back to a fresh conclusion.
// sweepSelfHealing correctly refuses to close it on elapsed time alone —
// TestSelfHealSweeper_RecurrenceDuringGracePeriodPreventsClose pins that a
// recurrence disqualifies the CONCLUSION it recurred against, permanently,
// not just temporarily, because new evidence the model never saw is a
// reason to look again, not a reason to trust an old "nothing to do"
// verdict once a timer runs out. That permanence is correct and this
// function does not touch it. The actual gap is one layer up: nothing ever
// produces the fresh analysis that permanence is waiting for, unless a
// human happens to click Re-analyze. auto_analysis_attempted_at is a
// one-shot gate (autoanalyze's own candidateQuery) — once ANY analysis
// (manual or automatic) has completed, autoanalyze's own poller, if
// enabled, will never reconsider this incident again, recurrence or not.
//
// # What this function actually does, and what it deliberately does not
//
// Resets auto_analysis_attempted_at to NULL so autoanalyze's candidateQuery
// can see this incident again, as an ordinary, otherwise-eligible candidate
// — same severity thresholds, same connectivity checks, same everything
// else that query already applies. It does NOT itself trigger an
// investigation, bypass auto_analysis_enabled, or spend anything: if
// automatic investigation is off (an operator's own deliberate choice —
// PROJECT.md's "opt-in per severity" promise), this is a no-op in every
// observable sense, exactly as it should be. The only path left in that
// case, same as before this function existed, is a human clicking
// Re-analyze.
//
// Bounded by maxAutoAnalysisReopens — the SAME budget SetState's Reopened
// branch spends from, not a second counter — because it is the identical
// risk: an incident with a chronically flaky, never-quite-gone symptom
// could otherwise re-arm this gate forever, spending one real investigation
// per recurrence without bound. Once the budget is spent,
// auto_analysis_attempted_at is left exactly as it is: the same "give up
// and let a human decide" answer the Reopened branch already gives for its
// own version of this risk, applied here rather than inventing a second
// policy.
//
// A no-op (0 rows affected, no error) whenever auto_analysis_attempted_at
// is already NULL — an incident that has never been automatically attempted
// is already an eligible candidate, so there is nothing to re-arm — or
// state is anything other than Diagnosed/NeedsHumanInvestigation, since
// every other state either excludes itself from candidateQuery already or
// is handled by SetState's own Reopened branch instead.
func ReadmitForAutoAnalysis(ctx context.Context, tx pgx.Tx, incidentID, state string) error {
	if state != StateDiagnosed && state != StateNeedsHumanInvestigation {
		return nil
	}
	if _, err := tx.Exec(ctx,
		`UPDATE incidents
		    SET auto_analysis_attempted_at = NULL,
		        auto_analysis_reopen_count = auto_analysis_reopen_count + 1
		  WHERE id = $1
		    AND auto_analysis_attempted_at IS NOT NULL
		    AND auto_analysis_reopen_count < $2`,
		incidentID, maxAutoAnalysisReopens); err != nil {
		return fmt.Errorf("re-admit incident %s for auto-analysis after recurrence: %w", incidentID, err)
	}
	return nil
}

// ApplyAnalysisResult is Advance's DB-touching half: it computes the same
// pure Advancement Advance would (unit-tested independently in
// orchestrator_test.go), then persists whatever that decision implies —
// the proposed plan (if any, into remediation_recommendations) and the
// incident's new state — inside the caller's already-open, RLS-scoped
// transaction. Called once per completed (or bound-hit) investigation, from
// both internal/api/analyze.go's handleAnalyzeIncident and
// internal/autoanalyze's investigateOne, so the two call sites can never
// silently diverge on how an investigation result turns into a state
// transition — mirroring internal/api.PersistAnalysis's own "one function,
// two callers" precedent for exactly the same reason.
//
// Resolves the autonomy policy fresh via settings.Resolve/
// ResolveAutonomyPolicy on every call — deliberately not accepted as a
// parameter the way it used to be — so neither call site can drift onto a
// stale or hand-picked policy, and so a policy change made through
// PUT /api/v1/admin/settings governs the very next investigation with no
// hub restart, matching this codebase's "live-editable" discipline for
// every other setting. tx is passed to settings.Resolve (not s.db.Pool, and
// this package has no pool of its own to fall back to anyway): org_settings
// carries no RLS, but reading through the caller's own open, not-yet-
// committed transaction avoids ever observing a stale pre-update row if a
// concurrent request in this same transaction already wrote one — the exact
// reasoning internal/settings.Resolve's own querier doc comment gives for
// internal/api/settings.go's PUT handler.
// RouteDecision is what the caller (internal/api) has already computed —
// via internal/orchestrator.ResolveRoute and, for a re-analysis where a plan
// is in flight, §12.9 decision B's "recorded but not applied" rule — before
// calling ApplyAnalysisResult. Threaded through as one value rather than
// three loose parameters so a future field (a real timeline event, once D8
// lands) has one place to join.
type RouteDecision struct {
	Route   resolution.Route
	Reason  string
	Applier resolution.Applier
	// Apply is false when the incident had a plan in flight at the moment
	// this analysis started (Executing, or AwaitingMerge with an open pull
	// request) — §12.9 decision B point 3: the recomputed route is recorded
	// in the log/return value but incidents.route/route_reason/applier are
	// left exactly as they were, so an in-flight plan is never stranded by
	// a route change underneath it.
	Apply bool
}

func ApplyAnalysisResult(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, clusterID, incidentID, analysisID string,
	result llm.Investigation,
	routeDecision RouteDecision,
) (Advancement, error) {
	cfg, err := settings.Resolve(ctx, tx)
	if err != nil {
		return Advancement{}, fmt.Errorf("orchestrator: resolve autonomy policy for incident %s: %w", incidentID, err)
	}
	policy := ResolveAutonomyPolicy(cfg)

	adv := Advance(result, policy, routeDecision.Route)

	if adv.Plan != nil {
		// PROJECT.md T7: "a rejection reason reaches something that acts on
		// it." What acts on it is unattended execution's own candidate
		// selection (internal/api/unattended.go), which keys off
		// remediation_recommendations.gate_outcome = 'AutoApprove' — the one
		// outcome that can execute a plan with no human looking at it again.
		// If a human already rejected the identical action type on this same
		// object, on a prior (necessarily closed — see T7's owner decision
		// that a recurrence LINKS rather than reopening) incident, this
		// downgrades the outcome to NeedsApproval so it reaches a human
		// again rather than silently repeating a refused fix. See
		// demoteIfPreviouslyRejected's own doc comment.
		if demoted, note := demoteIfPreviouslyRejected(ctx, tx, incidentID, adv.Plan, adv.Decision); demoted {
			adv.Reason = note
		}

		logPlanTargetCorrelation(ctx, tx, incidentID, *adv.Plan)

		planID := domain.NewID(domain.PrefixPlan)
		if err := persistRecommendation(ctx, tx, planID, incidentID, tenantID, clusterID, analysisID, *adv.Plan, *adv.Decision, ""); err != nil {
			return adv, fmt.Errorf("orchestrator: persist recommendation for incident %s: %w", incidentID, err)
		}
		adv.PlanID = planID

		// §12.6: the paired route's second recommendation, linked to the
		// first via sibling_of_recommendation_id — NOT superseded_at, which
		// stays reserved for "a better fix exists now" (see that column's
		// own migration comment).
		if adv.PairedPlan != nil {
			demoteIfPreviouslyRejected(ctx, tx, incidentID, adv.PairedPlan, adv.PairedDecision)

			pairedPlanID := domain.NewID(domain.PrefixPlan)
			if err := persistRecommendation(ctx, tx, pairedPlanID, incidentID, tenantID, clusterID, analysisID, *adv.PairedPlan, *adv.PairedDecision, planID); err != nil {
				return adv, fmt.Errorf("orchestrator: persist paired recommendation for incident %s: %w", incidentID, err)
			}
			adv.PairedPlanID = pairedPlanID
		}
	}

	if routeDecision.Apply {
		if _, err := tx.Exec(ctx,
			`UPDATE incidents SET route = $2, route_reason = $3, applier = $4 WHERE id = $1`,
			incidentID, nullIfEmptyRoute(routeDecision.Route), nullIfEmpty(routeDecision.Reason), nullIfEmptyApplier(routeDecision.Applier)); err != nil {
			return adv, fmt.Errorf("orchestrator: record route for incident %s: %w", incidentID, err)
		}
	} else {
		logger.InfoContext(ctx, "incident has a plan in flight: recomputed route not applied, keeping the stored one until it resolves",
			logging.IncidentID(incidentID), slog.String("recomputed_route", string(routeDecision.Route)),
			slog.String("route_reason", routeDecision.Reason))
	}

	if err := SetState(ctx, tx, incidentID, adv.NextState); err != nil {
		return adv, err
	}

	// BACKLOG.md B1: the investigation-finishing transition, question 2 of
	// the four the incident screen answers. Written once per call regardless
	// of outcome — a partial investigation or "could not determine" root
	// cause is still a real event, not something to skip recording.
	analysisSummary := adv.Reason
	analysisDetail := map[string]any{
		"status":    result.Status,
		"nextState": adv.NextState,
	}
	if result.Confidence != nil {
		analysisDetail["confidence"] = *result.Confidence
	}
	if result.RootCause != nil && result.RootCause.Statement != "" {
		analysisDetail["rootCause"] = result.RootCause.Statement
		if analysisSummary == "" {
			analysisSummary = result.RootCause.Statement
		}
	}
	if result.Status == "partial" {
		analysisDetail["partialReason"] = result.PartialReason
	}
	if analysisSummary == "" {
		analysisSummary = "Investigation completed"
	}
	if err := timeline.Record(ctx, tx, timeline.Event{
		TenantID: tenantID, ClusterID: clusterID, IncidentID: incidentID,
		Type: timeline.EventAnalysisCompleted, Summary: analysisSummary, Detail: analysisDetail,
	}); err != nil {
		return adv, fmt.Errorf("orchestrator: record AnalysisCompleted timeline event for incident %s: %w", incidentID, err)
	}

	// The recommendation being produced (question 3) is a separate,
	// conditional event from the analysis finishing above — an investigation
	// can complete with no plan at all (NeedsHumanInvestigation, a Diagnosed
	// no-fix-found conclusion), and this event exists precisely to mark the
	// cases where it did.
	if adv.Plan != nil {
		recDetail := map[string]any{
			"planId":     adv.PlanID,
			"actionType": string(adv.Plan.ActionType),
			"riskLevel":  string(adv.Plan.RiskLevel),
			"reversible": adv.Plan.Reversible,
		}
		if adv.Decision != nil {
			recDetail["gateOutcome"] = string(adv.Decision.Outcome)
			recDetail["gateReason"] = adv.Decision.Reason
		}
		if err := timeline.Record(ctx, tx, timeline.Event{
			TenantID: tenantID, ClusterID: clusterID, IncidentID: incidentID,
			Type:    timeline.EventRecommendationReady,
			Summary: fmt.Sprintf("Recommended: %s", adv.Plan.ActionType),
			Detail:  recDetail,
		}); err != nil {
			return adv, fmt.Errorf("orchestrator: record RecommendationReady timeline event for incident %s: %w", incidentID, err)
		}
	}
	if adv.PairedPlan != nil {
		pairedDetail := map[string]any{
			"planId":     adv.PairedPlanID,
			"actionType": string(adv.PairedPlan.ActionType),
			"riskLevel":  string(adv.PairedPlan.RiskLevel),
			"reversible": adv.PairedPlan.Reversible,
			"pairedWith": adv.PlanID,
		}
		if adv.PairedDecision != nil {
			pairedDetail["gateOutcome"] = string(adv.PairedDecision.Outcome)
			pairedDetail["gateReason"] = adv.PairedDecision.Reason
		}
		if err := timeline.Record(ctx, tx, timeline.Event{
			TenantID: tenantID, ClusterID: clusterID, IncidentID: incidentID,
			Type:    timeline.EventRecommendationReady,
			Summary: fmt.Sprintf("Recommended (paired): %s", adv.PairedPlan.ActionType),
			Detail:  pairedDetail,
		}); err != nil {
			return adv, fmt.Errorf("orchestrator: record paired RecommendationReady timeline event for incident %s: %w", incidentID, err)
		}
	}

	return adv, nil
}

// nullIfEmptyRoute/nullIfEmptyApplier keep the CHECK constraints on
// incidents.route/applier happy: an empty string is not one of the allowed
// values, and NULL ("not yet computed") is the honest answer for an
// incident this pass never actually routed (Advance's non-"complete"
// branches, an ownership check that itself failed before a route could be
// classified at all — resolution.RouteFor already turns THAT into
// guidance, but a caller that never got as far as calling ResolveRoute has
// no route value at all to write).
func nullIfEmptyRoute(r resolution.Route) *string {
	if r == "" {
		return nil
	}
	s := string(r)
	return &s
}

func nullIfEmptyApplier(a resolution.Applier) *string {
	if a == "" || a == resolution.ApplierDeployOnMerge {
		// ApplierDeployOnMerge never ships this cut (§12.9 decision A) and
		// is not in incidents.applier's CHECK constraint — guarded here so
		// a future caller that somehow produces it fails into NULL rather
		// than a constraint violation.
		return nil
	}
	s := string(a)
	return &s
}

// persistRecommendation writes one row to remediation_recommendations — see
// migration 000027_remediation_recommendations.up.sql's own comment for why
// this is a new, distinctly-named table rather than reusing migration
// 000006's fuller remediation_plans/plan_actions (the real, signed,
// execution-ready schema lld/05-data-model.md §3.6 defines, which this task
// deliberately does not populate).
func persistRecommendation(
	ctx context.Context,
	tx pgx.Tx,
	planID, incidentID, tenantID, clusterID, analysisID string,
	plan remediation.RemediationPlan,
	decision remediation.Decision,
	siblingOfRecommendationID string,
) error {
	paramsJSON, err := marshalPlanParams(plan)
	if err != nil {
		return fmt.Errorf("marshal plan params: %w", err)
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO remediation_recommendations (
		   id, incident_id, tenant_id, cluster_id, analysis_id, action_type,
		   target_gvk, target_namespace, target_name, params, reversible, risk_level,
		   gate_outcome, gate_reason, sibling_of_recommendation_id
		 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
		planID, incidentID, tenantID, clusterID, analysisID, string(plan.ActionType),
		plan.TargetGVK, nullIfEmpty(plan.TargetNamespace), plan.TargetName, paramsJSON, plan.Reversible, string(plan.RiskLevel),
		string(decision.Outcome), decision.Reason, nullIfEmpty(siblingOfRecommendationID))
	if err != nil {
		return err
	}
	return nil
}

// MarshalPlanParams is marshalPlanParams's exported form — used by
// internal/api's response-building code (analyze.go, approvals.go) so a
// freshly-authored, still-in-memory plan (before it's ever written to
// remediation_recommendations) can be rendered through the exact same
// lowercase-keyed JSON shape a row read back out of that table already has,
// without either package duplicating the other's type-switch.
func MarshalPlanParams(plan remediation.RemediationPlan) (json.RawMessage, error) {
	return marshalPlanParams(plan)
}

// marshalPlanParams serializes plan.Params into the same lowercase-keyed
// JSON shape internal/llm/toolloop.go's proposedPlanWire parses it FROM
// (replicas / {} / repository+filePath+fieldPath+newValue) — a type switch
// rather than json.Marshal(plan.Params) directly, since
// remediation.ScaleDeploymentParams/OpenPRParams's Go field names are
// capitalized (that package has no reason to carry its own JSON tags — it
// has never been marshaled before this task) and this keeps this package,
// not internal/remediation, responsible for the wire-shape choice. An
// unrecognized/nil Params (a structurally invalid plan that still made it
// this far — see llm.parseProposedPlan's doc comment for why that's
// possible) marshals to an empty object rather than failing the whole
// persist: the row's own gate_outcome/gate_reason columns already record
// that this plan was Blocked, and losing that record because of a second,
// redundant params error would be worse than an honestly-empty {}.
func marshalPlanParams(plan remediation.RemediationPlan) (json.RawMessage, error) {
	switch p := plan.Params.(type) {
	case remediation.ScaleDeploymentParams:
		return json.Marshal(map[string]any{"replicas": p.Replicas})
	case remediation.RestartPodParams:
		return json.Marshal(map[string]any{})
	case remediation.PatchResourceLimitsParams:
		// The one params type marshaled through its own struct tags rather
		// than a hand-built map. Deliberate, and the reason is not brevity:
		// this params struct also crosses the tunnel inside the signed plan
		// envelope, and internal/agent/tools.go decodes it back into the SAME
		// Go type to re-run remediation.PatchResourceLimitsParams.Validate
		// against the same absolute bounds the hub used (§10.3's agent-side
		// re-validation). A hand-built map here would make this file a second
		// definition of that wire shape, and the first symptom of the two
		// drifting apart would be an agent silently declining every plan — or,
		// worse, decoding a field it thought was named something else into a
		// zero value that passes a bounds check. One struct, one shape.
		return json.Marshal(p)
	case remediation.PatchFieldParams:
		// Through its own struct tags, for exactly the reason
		// PatchResourceLimitsParams is: this shape crosses the tunnel inside the
		// signed envelope and the agent decodes it back into the SAME Go type to
		// re-check the allowlist itself. A hand-built map here would make this
		// file a second definition of that wire shape.
		return json.Marshal(p)
	case remediation.RevertContainerImageParams:
		// Marshaled through its struct tag (one field, `container`), and the
		// interesting part is what is NOT here: the image. For every other
		// action type this function's output is also what the signed envelope
		// carries; for this one it deliberately is not. The envelope's params
		// are a remediation.RevertContainerImageExecParams the hub builds at
		// approval time from the cluster's own ReplicaSet history
		// (internal/execution), because the image must come from
		// live state rather than from a persisted row that was written when the
		// plan was proposed — possibly hours and several deploys ago. So this
		// row is the record of what was PROPOSED ("revert container api"), and
		// the audit trail's record of what was EXECUTED (which image, resolved
		// when) is the signed plan plus the approval event's rollback details.
		return json.Marshal(p)
	case remediation.OpenPRParams:
		// Through the wire shape's own tags rather than a hand-built map: this
		// params type is now a nested list, and a hand-built map would be a
		// second definition of it that UnmarshalPlanParams below could drift
		// from silently. The keys are `repository` and `files[{path,content}]`,
		// exactly what internal/llm's openPRParamsWire parses FROM.
		return json.Marshal(openPRParamsRow{Repository: p.Repository, Files: proposedFileRows(p.Files)})
	case remediation.StructuredPatchParams:
		// Through its own struct tags, for the same reason PatchFieldParams is:
		// this shape crosses the tunnel inside the signed envelope (were this
		// action type ever wired to execute against a live agent — see
		// ActionStructuredPatch's own doc comment for why it is not), and a
		// hand-built map here would be a second, driftable definition of that
		// wire shape.
		return json.Marshal(p)
	case remediation.AnnotateResourceParams, remediation.LabelResourceParams:
		// Both through their own struct tags (`key`/`value`) — same reasoning
		// as PatchFieldParams: this shape crosses the tunnel inside the
		// signed envelope, and the agent decodes it back into the SAME Go
		// type to re-run Validate and the (kind, key) allowlist check
		// against the same bounds the hub used.
		return json.Marshal(p)
	case remediation.DeleteResourceParams:
		// Carries no fields (RemediationPlan's own Target* identify the
		// object entirely), matching RestartPodParams' identical case above.
		return json.Marshal(map[string]any{})
	case remediation.CordonNodeParams, remediation.DrainNodeParams:
		// Through their own struct tags: the agent decodes the same types.
		return json.Marshal(p)
	case remediation.CreateResourceParams:
		// Through its own struct tags (`data`), for the same reason
		// PatchFieldParams/PatchResourceLimitsParams are: this shape crosses
		// the tunnel inside the signed envelope, and the agent decodes it
		// back into the SAME Go type to re-run Validate against the same
		// bounds the hub used.
		return json.Marshal(p)
	default:
		return json.Marshal(map[string]any{})
	}
}

// openPRParamsRow is the stored JSON shape of an OpenPR plan's params, used
// for both directions so the writer and the reader cannot disagree.
//
// The Legacy* fields exist only to be DETECTED. They are the retired
// single-field grammar's keys; nothing reads their values. Decoding them is
// what lets UnmarshalPlanParams tell "a plan from before 2026-08-28" apart
// from "a plan with an empty file list", and refuse the first loudly instead
// of treating it as the second.
type openPRParamsRow struct {
	Repository string            `json:"repository"`
	Files      []proposedFileRow `json:"files"`

	LegacyFilePath             *string `json:"filePath,omitempty"`
	LegacyFieldPath            *string `json:"fieldPath,omitempty"`
	LegacyNewValue             *string `json:"newValue,omitempty"`
	LegacyExpectedCurrentValue *string `json:"expectedCurrentValue,omitempty"`
}

type proposedFileRow struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	// Delete mirrors remediation.ProposedFile.Delete — BACKLOG.md "still
	// open" #2. omitempty so a row written before this field existed and a
	// row explicitly not deleting this path decode identically (both false).
	Delete bool `json:"delete,omitempty"`
}

func proposedFileRows(files []remediation.ProposedFile) []proposedFileRow {
	out := make([]proposedFileRow, 0, len(files))
	for _, f := range files {
		out = append(out, proposedFileRow{Path: f.Path, Content: f.Content, Delete: f.Delete})
	}
	return out
}

// legacyKeys names the retired keys this row actually carries, for the refusal
// message. A key present but empty still counts: it is still a row written by
// a build that believed a repository change was one field.
func (r openPRParamsRow) legacyKeys() []string {
	var out []string
	for _, k := range []struct {
		name string
		val  *string
	}{
		{"filePath", r.LegacyFilePath},
		{"fieldPath", r.LegacyFieldPath},
		{"newValue", r.LegacyNewValue},
		{"expectedCurrentValue", r.LegacyExpectedCurrentValue},
	} {
		if k.val != nil {
			out = append(out, k.name)
		}
	}
	return out
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// UnmarshalPlanParams is marshalPlanParams's inverse: given the action type
// and the lowercase-keyed params JSON a remediation_recommendations row
// already carries, it reconstructs the matching typed
// remediation.ActionParams. Exported for internal/api/approvals.go, which
// needs a fully typed remediation.RemediationPlan (via ReconstructPlan
// below) to sign at approval/execution time — the one place a stored
// recommendation must be acted on again, not just rendered as a planView.
func UnmarshalPlanParams(actionType string, paramsJSON []byte) (remediation.ActionParams, error) {
	switch remediation.ActionType(actionType) {
	case remediation.ActionScaleDeployment:
		var p struct {
			Replicas int `json:"replicas"`
		}
		if err := json.Unmarshal(paramsJSON, &p); err != nil {
			return nil, fmt.Errorf("unmarshal scale deployment params: %w", err)
		}
		return remediation.ScaleDeploymentParams{Replicas: p.Replicas}, nil
	case remediation.ActionRestartPod:
		return remediation.RestartPodParams{}, nil
	case remediation.ActionPatchResourceLimits:
		// Decoded straight into the typed struct via its own json tags — the
		// inverse of marshalPlanParams' one struct-tagged case above.
		// Deliberately NOT validated here: this function's job is "turn these
		// stored bytes back into the type they came from", and a row that was
		// persisted with out-of-bounds values (possible — orchestrator.Advance
		// persists a Blocked plan too, precisely so the record of a bad
		// proposal survives) must still be readable for display. Validation
		// happens where a decision is made: RemediationPlan.Validate at the
		// gate, checkResourceLimitsBound at approval, and the agent's own
		// re-check before the Patch.
		var p remediation.PatchResourceLimitsParams
		if err := json.Unmarshal(paramsJSON, &p); err != nil {
			return nil, fmt.Errorf("unmarshal patch resource limits params: %w", err)
		}
		return p, nil
	case remediation.ActionPatchField:
		// Same reasoning as PatchResourceLimits above: decode, do not validate.
		// The allowlist check that authorises this path lives at the gate and is
		// repeated agent-side, and a Blocked plan must still be readable so the
		// record of a refused proposal survives for display.
		var p remediation.PatchFieldParams
		if err := json.Unmarshal(paramsJSON, &p); err != nil {
			return nil, fmt.Errorf("unmarshal patch field params: %w", err)
		}
		return p, nil
	case remediation.ActionRevertContainerImage:
		// Decoded into the typed struct, which carries a container name and
		// nothing else. That is the point rather than an incidental detail: if
		// this row's params somehow contained an `image` key — a hand-edited
		// row, a future bug, a restore from a differently-shaped backup —
		// encoding/json drops it here, so no persisted value can influence
		// which image gets written into a pod template. The executed image is
		// resolved from the live cluster at approval time, every time (see
		// remediation.RevertContainerImageParams' own doc comment).
		var p remediation.RevertContainerImageParams
		if err := json.Unmarshal(paramsJSON, &p); err != nil {
			return nil, fmt.Errorf("unmarshal revert container image params: %w", err)
		}
		return p, nil
	case remediation.ActionOpenPR:
		// The one params type that REFUSES a legacy shape rather than ignoring
		// it, and the refusal is the point.
		//
		// Until 2026-08-28 an OpenPR plan was one field and one value
		// (filePath/fieldPath/newValue/expectedCurrentValue). Those fields no
		// longer exist, and a stored row still carrying them describes a change
		// this build cannot perform. Decoding it into an empty file list would
		// turn "approve this plan" into "open a pull request that changes
		// nothing", or worse, into whatever a later default filled in. So a row
		// whose params name any retired key fails loudly here, at the one place
		// a stored plan is turned back into something actionable, and the
		// approver is told to re-analyse rather than handed a plan whose
		// meaning was quietly rewritten. Same discipline the old
		// OpenPRParams.Validate applied to a supplied filePath.
		var p openPRParamsRow
		if err := json.Unmarshal(paramsJSON, &p); err != nil {
			return nil, fmt.Errorf("unmarshal open pr params: %w", err)
		}
		if legacy := p.legacyKeys(); len(legacy) > 0 {
			return nil, fmt.Errorf("this stored plan uses the retired single-field repository-change shape (%s) and cannot be turned into a pull request — a repository change is now one or more whole files. Re-analyse the incident to get a plan this build can act on", strings.Join(legacy, ", "))
		}
		files := make([]remediation.ProposedFile, 0, len(p.Files))
		for _, f := range p.Files {
			files = append(files, remediation.ProposedFile{Path: f.Path, Content: f.Content, Delete: f.Delete})
		}
		return remediation.OpenPRParams{Repository: p.Repository, Files: files}, nil
	case remediation.ActionStructuredPatch:
		// Decoded straight into the typed struct via its own json tags, same as
		// PatchResourceLimits/PatchField above: this function's job is "turn
		// these stored bytes back into the type they came from," not to
		// re-validate them. A row persisted with an out-of-allowlist path is
		// not reachable in practice (RemediationPlan.Validate refuses it before
		// persistRecommendation is ever called — see BUGS.md 86's fix), but if
		// one ever existed (a hand-edited row, a future bug upstream of this
		// function) it must still be readable for display, exactly like every
		// other action type here.
		var p remediation.StructuredPatchParams
		if err := json.Unmarshal(paramsJSON, &p); err != nil {
			return nil, fmt.Errorf("unmarshal structured patch params: %w", err)
		}
		return p, nil
	case remediation.ActionAnnotateResource:
		// Decode, do not validate — same reasoning as PatchField/
		// PatchResourceLimits above: a Blocked row (a key/value the
		// allowlist refused) must still be readable for display.
		var p remediation.AnnotateResourceParams
		if err := json.Unmarshal(paramsJSON, &p); err != nil {
			return nil, fmt.Errorf("unmarshal annotate resource params: %w", err)
		}
		return p, nil
	case remediation.ActionLabelResource:
		var p remediation.LabelResourceParams
		if err := json.Unmarshal(paramsJSON, &p); err != nil {
			return nil, fmt.Errorf("unmarshal label resource params: %w", err)
		}
		return p, nil
	case remediation.ActionDeleteResource:
		// Carries no fields — same as ActionRestartPod above.
		return remediation.DeleteResourceParams{}, nil
	case remediation.ActionCordonNode:
		var p remediation.CordonNodeParams
		if err := json.Unmarshal(paramsJSON, &p); err != nil {
			return nil, fmt.Errorf("unmarshal cordon node params: %w", err)
		}
		return p, nil
	case remediation.ActionDrainNode:
		var p remediation.DrainNodeParams
		if err := json.Unmarshal(paramsJSON, &p); err != nil {
			return nil, fmt.Errorf("unmarshal drain node params: %w", err)
		}
		return p, nil
	case remediation.ActionCreateResource:
		// Decode, do not validate — same reasoning as every other typed
		// params case above: a Blocked row (a kind the allowlist refused, or
		// data that failed its own bounds check) must still be readable for
		// display.
		var p remediation.CreateResourceParams
		if err := json.Unmarshal(paramsJSON, &p); err != nil {
			return nil, fmt.Errorf("unmarshal create resource params: %w", err)
		}
		return p, nil
	default:
		return nil, fmt.Errorf("unrecognized action type %q", actionType)
	}
}

// ReconstructPlan rebuilds a typed remediation.RemediationPlan from a
// remediation_recommendations row's own columns — persistRecommendation's
// inverse. targetNamespace is the row's possibly-nil column value; an empty
// string round-trips through nullIfEmpty exactly like it did on the way in.
func ReconstructPlan(incidentID, analysisID, actionType, targetGVK, targetNamespace, targetName string, paramsJSON []byte, reversible bool, riskLevel string) (remediation.RemediationPlan, error) {
	params, err := UnmarshalPlanParams(actionType, paramsJSON)
	if err != nil {
		return remediation.RemediationPlan{}, err
	}
	return remediation.RemediationPlan{
		IncidentID:      incidentID,
		AnalysisID:      analysisID,
		ActionType:      remediation.ActionType(actionType),
		TargetGVK:       targetGVK,
		TargetNamespace: targetNamespace,
		TargetName:      targetName,
		Params:          params,
		Reversible:      reversible,
		RiskLevel:       remediation.RiskLevel(riskLevel),
	}, nil
}

// logPlanTargetCorrelation is lld/01-threat-model.md T3's stated observable,
// made real: "a proposed plan whose action type or target doesn't correlate
// with the detector that opened the incident" is exactly the shape a
// successful prompt injection would take (the attacker's whole goal is
// getting the model to propose an action against a target it was never given
// evidence about).
//
// LOGGED, deliberately not blocking. A hard equality check between the
// plan's target and the incident's own object would produce real false
// positives on exactly the reasoning this product exists to do: an incident
// opened on a Service (ServiceNoEndpoints) whose correct fix targets the
// Deployment BEHIND it — a different namespace/name/kind entirely, and a
// completely legitimate plan. Distinguishing "the model correctly reasoned
// to the real owner" from "the model was steered somewhere unrelated" needs
// an owner-chain-aware check this function does not attempt — see
// BACKLOG.md's G6 for that as a follow-up. What this function adds now is
// visibility with zero risk of blocking a real remediation: every mismatch
// is written to the log, so a mismatch that OUGHT to have been a red flag is
// at minimum discoverable by anyone grepping hub logs or wiring an alert on
// this line, rather than invisible.
//
// object_key comes from incidents.object_key (migration 000036) — the exact
// gvk|namespace|name tuple established as this incident's own identity. A
// missing or unparseable key logs nothing: there is no ground truth to
// compare against, and "cannot determine a mismatch" must not be treated as
// "found no mismatch" by anyone reading these logs, so it stays silent rather
// than falsely reassuring.
func logPlanTargetCorrelation(ctx context.Context, tx pgx.Tx, incidentID string, plan remediation.RemediationPlan) {
	var objectKey *string
	if err := tx.QueryRow(ctx, `SELECT object_key FROM incidents WHERE id = $1`, incidentID).Scan(&objectKey); err != nil {
		logger.ErrorContext(ctx, "reading object_key for the plan-target correlation check failed",
			logging.IncidentID(incidentID), logging.Err(err))
		return
	}
	if objectKey == nil || *objectKey == "" {
		return
	}
	incidentGVK, incidentNamespace, incidentName, matches, ok := planTargetMatchesObjectKey(*objectKey, plan.TargetNamespace, plan.TargetName)
	if !ok || matches {
		return
	}
	// WARN rather than INFO, deliberately: this is EXPECTED when the model
	// correctly traced a symptom to its real owner (a Service incident whose
	// fix targets its backing Deployment), but it is also the exact shape
	// lld/01-threat-model.md T3 (prompt injection) would take. A reader has
	// to see it either way, and a level that makes it greppable is the
	// cheapest way to keep that true.
	logger.WarnContext(ctx, "proposed plan targets an object other than the incident's own",
		logging.IncidentID(incidentID),
		slog.String("incident_gvk", incidentGVK),
		slog.String("incident_namespace", incidentNamespace),
		slog.String("incident_name", incidentName),
		slog.String("action_type", string(plan.ActionType)),
		slog.String("plan_gvk", plan.TargetGVK),
		slog.String("plan_namespace", plan.TargetNamespace),
		slog.String("plan_name", plan.TargetName))
}

// planTargetMatchesObjectKey is the pure parse-and-compare half of
// logPlanTargetCorrelation, split out so the comparison logic is unit-testable
// without a database. ok is false when objectKey cannot be parsed at all —
// the caller's "cannot determine a mismatch must not read as no mismatch"
// rule lives with the caller, not here.
func planTargetMatchesObjectKey(objectKey, targetNamespace, targetName string) (gvk, namespace, name string, matches, ok bool) {
	parts := strings.SplitN(objectKey, "|", 3)
	if len(parts) != 3 {
		return "", "", "", false, false
	}
	gvk, namespace, name = parts[0], parts[1], parts[2]
	matches = targetNamespace == namespace && targetName == name
	return gvk, namespace, name, matches, true
}
