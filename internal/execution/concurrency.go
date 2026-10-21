package execution

// This file implements the two concurrency guards BACKLOG.md G6 left open as
// "lower urgency" — planId replay dedup and the per-target lock
// internal/orchestrator/state.go:207 calls out by name as "(unbuilt)". Both
// close races that are real for CONCURRENT requests specifically: the
// resourceVersion precondition on the actual Kubernetes patch call bounds the
// DAMAGE either race could cause (a stale write fails at the API server), but
// it does nothing to stop the hub itself processing the same plan twice, or
// two different plans against the same target executing at once — which is
// what produces a duplicate audit/decision row, a duplicate notification, or
// a wasted round trip to the agent that the API server's own rejection then
// has to clean up after.
//
// Both guards deliberately reuse mechanisms this codebase already has a
// precedent for, rather than inventing a new locking primitive:
//
//   - Replay dedup reuses SetState's own "SELECT ... FOR UPDATE on the
//     incidents row" idiom (internal/orchestrator/db.go's own doc comment:
//     "the SELECT ... FOR UPDATE is load-bearing ... it serialises concurrent
//     transitions against the same incident"). internal/execution's
//     recordExecutingTransition already took this lock and rechecked before
//     committing an in-place approval; the actual gap was that
//     approveByOpeningPullRequest (internal/api/approvals.go) opened a
//     real pull request with NO equivalent check first, and
//     handleRejectIncident inserted its decision row before ever taking the
//     lock that would have told it a concurrent request had already decided
//     this plan. LockIncidentForDecision is the one implementation all three
//     paths now share, so a concurrent pair of requests always agrees on the
//     same serialization point instead of three call sites maintaining their
//     own copy of "is this plan still decidable" and inevitably drifting.
//
//   - The per-target lock reuses pg_advisory_xact_lock(hashtext(...)), the
//     idiom internal/fleetgroup, internal/objectgroup, internal/replicagroup
//     and internal/gateway/finding.go already use to serialize a
//     check-then-act sequence against something that is not a single row a
//     plain FOR UPDATE can lock (here: "the live object a plan is about to
//     patch", which is identified by gvk+namespace+name — the exact same
//     identity FetchPreconditionWithObject already keys its own
//     resourceVersion read on — not by incident or plan, since two DIFFERENT
//     incidents/plans naming the SAME object is exactly the case an
//     incident-scoped lock cannot see).
//
//     Taken on scope.Tx rather than a dedicated transaction. That is deliberate,
//     and it is what makes a transaction-scoped lock adequate here even
//     though the "in flight" window this needs to cover spans PreparePlan's
//     read-only cluster calls, the dry run, the separate commit-to-Executing
//     transaction, the real tunnel call, AND recordExecutionOutcome's
//     transaction — none of which run inside one Postgres transaction, by
//     internal/execution's own explicit design (a database
//     transaction is never held open across the tunnel call to the agent).
//     scope.Tx itself, however, IS already held open for that entire span: this
//     codebase's middleware (completeRequest, called only after the whole
//     handler returns) commits or rolls it back once, at the very end of the
//     HTTP request — so a lock acquired on scope.Tx at the top of
//     ExecuteApprovedPlan/ExecuteUndo is released automatically exactly when
//     "this request is completely done, one way or another" becomes true,
//     with no separate acquire/release bookkeeping, no new table, and no
//     manual staleness handling: a hub process dying mid-request drops the
//     connection, and Postgres releases every lock that connection held along
//     with it.
//
//     A second, concurrent request naming the same target BLOCKS on this call
//     until the first's transaction ends — this codebase's established
//     "serialize" answer to contention (see the four precedents above), which
//     this task's own brief names as an acceptable alternative to an outright
//     refusal. It is also the more correct answer for this specific case: the
//     second plan is not stale merely for having waited, since PreparePlan
//     re-fetches the resourceVersion precondition (and every live-state bound)
//     fresh, every time, regardless of how it got to run.

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"argus/internal/orchestrator"
	"argus/internal/remediation"
)

// ErrPlanAlreadyDecided is returned by LockIncidentForDecision when, UNDER
// the incident row's lock, this plan turns out to already be decided —
// either a concurrent request beat this one to approving/rejecting it, or
// the incident has moved out of AwaitingApproval for some other reason
// entirely (e.g. it was re-analyzed, though MarkInvestigating's own
// exclusions make that unreachable while a plan is actually in flight).
// Callers map this to a clean 409 naming what already happened, rather than
// letting it fall through to a generic 500/502.
type ErrPlanAlreadyDecided struct {
	IncidentID, PlanID, Detail string
}

func (e *ErrPlanAlreadyDecided) Error() string { return e.Detail }

// existingPlanVerdict reports the verdict already recorded for planID, if
// any — "" means no decision exists yet. Only meaningful when called AFTER
// LockIncidentForDecision's own FOR UPDATE has been taken in the same
// transaction; called on its own, this is exactly the unlocked
// check-then-act read that this task exists to stop relying on.
func existingPlanVerdict(ctx context.Context, tx pgx.Tx, planID string) (string, error) {
	var verdict string
	err := tx.QueryRow(ctx,
		`SELECT verdict FROM remediation_approval_decisions WHERE recommendation_id = $1 ORDER BY created_at ASC LIMIT 1`,
		planID).Scan(&verdict)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("check existing decision for plan %s: %w", planID, err)
	}
	return verdict, nil
}

// LockIncidentForDecision is BACKLOG.md G6's planId replay dedup chokepoint —
// the one place that decides, atomically, whether a plan may still be
// approved, opened-as-a-pull-request, or rejected right now. It takes the
// SAME row lock orchestrator.SetState itself takes (SELECT ... FOR UPDATE on
// incidents), which is what makes this genuinely race-safe rather than a
// second unlocked check that merely narrows the window: two concurrent
// callers both land here, one gets the lock first and either succeeds or
// commits a decision, and the other blocks until the first transaction ends
// — at which point it re-reads the row under its own lock and sees the
// truth, not a snapshot from before the race resolved.
//
// Called by recordExecutingTransition (in its own separately-committed
// transaction, before committing AwaitingApproval -> Executing),
// approveByOpeningPullRequest (on scope.Tx, before ever opening a pull request —
// previously the one path with NO such check at all), and
// handleRejectIncident (on scope.Tx, before inserting the rejection decision).
func LockIncidentForDecision(ctx context.Context, tx pgx.Tx, incidentID, planID string) error {
	var state string
	if err := tx.QueryRow(ctx, `SELECT state FROM incidents WHERE id = $1 FOR UPDATE`, incidentID).Scan(&state); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("incident %s not found", incidentID)
		}
		return fmt.Errorf("lock incident %s for a plan decision: %w", incidentID, err)
	}
	if state != orchestrator.StateAwaitingApproval {
		return &ErrPlanAlreadyDecided{IncidentID: incidentID, PlanID: planID,
			Detail: fmt.Sprintf("incident %s is now %q, not %q — a concurrent request has already acted on it", incidentID, state, orchestrator.StateAwaitingApproval)}
	}
	verdict, err := existingPlanVerdict(ctx, tx, planID)
	if err != nil {
		return err
	}
	if verdict != "" {
		return &ErrPlanAlreadyDecided{IncidentID: incidentID, PlanID: planID,
			Detail: fmt.Sprintf("plan %s has already been %s by a concurrent request", planID, verdict)}
	}
	return nil
}

// executionTargetForLock resolves the object a plan will actually mutate —
// duplicating, deliberately, the same resolution PreparePlan performs for
// RestartPod/PatchResourceLimits/RevertContainerImage (walking up to the
// owning Deployment/StatefulSet/DaemonSet via resolvePodTemplateTarget,
// because all three act on a pod template and the real write always targets
// the workload that owns it, never the Pod a finding named). This has to be
// resolved BEFORE the per-target lock is taken, and the lock has to be taken
// before PreparePlan ever runs — so this is called first, and PreparePlan
// re-resolves the same target a moment later. That second resolution is
// redundant, cheap (one more read-only get_owner_chain call against a live
// cluster that has not changed in the interim), and deliberately not
// threaded through as a shared value: PreparePlan's own resolution is what
// actually gets patched, so it must remain the authority regardless of what
// this function decided a few milliseconds earlier.
//
// ScaleDeployment and PatchField need no resolution at all — a
// ScaleDeployment plan already names the workload directly, and PatchField's
// allowlist (internal/remediation/patchfield.go) is defined in terms of
// whatever object the plan names, not a pod template — so both fall through
// to the plan's own target unchanged.
func (s *Executor) executionTargetForLock(ctx context.Context, clusterID string, plan remediation.RemediationPlan) (gvk, namespace, name string, err error) {
	switch plan.ActionType {
	case remediation.ActionRestartPod, remediation.ActionPatchResourceLimits, remediation.ActionRevertContainerImage:
		return s.resolvePodTemplateTarget(ctx, clusterID, plan.TargetGVK, plan.TargetNamespace, plan.TargetName)
	default:
		return plan.TargetGVK, plan.TargetNamespace, plan.TargetName, nil
	}
}

// targetLockKey names the pg_advisory_xact_lock this package's
// acquireTargetLock takes — see this file's own header comment for why a
// transaction-scoped advisory lock on scope.Tx is the right primitive here.
func targetLockKey(clusterID, gvk, namespace, name string) string {
	return "remediation-target:" + clusterID + "|" + gvk + "|" + namespace + "|" + name
}

// acquireTargetLock resolves plan's real execution target and takes the
// per-target lock on it, on tx. Callers pass scope.Tx (never a short-lived
// dedicated transaction) precisely so the lock lasts as long as scope.Tx does —
// see this file's header comment. Only ever called from a PrepForExecution
// path (ExecuteApprovedPlan, ExecuteUndo): a preflight/preview never mutates
// the cluster, so it neither needs to hold this lock nor should be made to
// wait behind a real execution's hold on it — PrepForPreflight's own
// contract is that refusals become advice, not that the preview blocks.
func (s *Executor) acquireTargetLock(ctx context.Context, tx pgx.Tx, clusterID string, plan remediation.RemediationPlan) error {
	gvk, namespace, name, err := s.executionTargetForLock(ctx, clusterID, plan)
	if err != nil {
		return fmt.Errorf("resolve execution target for the per-target lock: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, targetLockKey(clusterID, gvk, namespace, name)); err != nil {
		return fmt.Errorf("acquire per-target execution lock for %s %s/%s: %w", gvk, namespace, name, err)
	}
	return nil
}
