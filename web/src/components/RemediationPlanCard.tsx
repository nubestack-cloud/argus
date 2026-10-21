import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'

import { ApiError, rollbackExecution } from '../api/client'
import type { Analysis, RemediationPlan, RollbackRequest } from '../api/types'
import {
  CAP_REMEDIATION_APPROVE,
  CAP_REMEDIATION_EXECUTE_INPLACE,
  CAP_REMEDIATION_ROLLBACK,
} from '../api/capabilities'
import { missingCapabilityMessage } from '../api/capabilityInfo'
import { useAuth } from '../auth/useAuth'
import { useHasCapability } from '../auth/useCapabilities'
import { formatDateTime, formatRelativeTime } from '../utils/time'

// The remediation ARGUS proposed for one analysis, shared.
//
// Lifted out of IncidentDetailPage (unchanged) once TolerationsPage needed it:
// a toleration's expanded detail has to show the fix ARGUS had recommended for
// the incident that prompted the rule — BUGS.md item 37's other half — and the
// only honest way to show a plan is the way the approval path already shows it,
// same summary, same risk badge, same gate reason.

// approvalStatusLine/executionStatusLine render the two additive facts a
// plan may now carry (internal/api/remediation_exec.go) — both absent for
// a plan nobody has decided on yet, or for OpenPR, which never executes.
function approvalStatusLine(plan: RemediationPlan) {
  if (!plan.approval) return null
  const who = plan.approval.actorEmail ?? 'someone'
  return plan.approval.verdict === 'approved' ? (
    <p className="remediation-status-line">
      <span className="badge badge-green">Approved</span> by {who} · <span title={formatDateTime(plan.approval.createdAt)}>{formatRelativeTime(plan.approval.createdAt)}</span>
    </p>
  ) : (
    <p className="remediation-status-line">
      <span className="badge badge-gray">Rejected</span> by {who}{plan.approval.reason ? `: ${plan.approval.reason}` : ''} ·{' '}
      <span title={formatDateTime(plan.approval.createdAt)}>{formatRelativeTime(plan.approval.createdAt)}</span>
    </p>
  )
}

// The undo control.
//
// Rendered only when there is genuinely something to undo: a succeeded execution
// that recorded a compensating action and has not already been reversed. Absent —
// not disabled — when the action type has no undo, because a disabled button
// invites the question "why can't I?" and the answer ("a restart cannot be
// un-restarted, the pods are already gone") is a property of the action, not of
// this operator's permissions.
//
// One deliberate click, then the request. No modal: the confirmation text is the
// button's own label ("Undo: scale back to 2 replica(s)"), which says exactly
// what will happen — and every genuinely dangerous case is refused by the hub
// with a reason, which is shown in full rather than summarised.
function UndoControl({ plan, incidentId }: { plan: RemediationPlan; incidentId: string }) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const canRollback = useHasCapability(CAP_REMEDIATION_ROLLBACK)
  const canExecute = useHasCapability(CAP_REMEDIATION_EXECUTE_INPLACE)
  const [armed, setArmed] = useState(false)

  const exec = plan.execution
  const mutation = useMutation({
    mutationFn: (body: RollbackRequest) => rollbackExecution(exec!.id, body, accessToken!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incident', incidentId] })
      queryClient.invalidateQueries({ queryKey: ['incidents'] })
    },
  })

  // exec.outcome !== 'succeeded' also excludes 'unknown' (BACKLOG.md C8):
  // an execution whose real outcome could not be confirmed must not offer
  // an undo either — ARGUS cannot honestly promise what "undo" would even
  // mean for a change it isn't sure happened.
  if (!exec || exec.outcome !== 'succeeded' || !exec.rollback) return null

  if (exec.rolledBackAt) {
    return (
      <p className="remediation-status-line">
        <span className="badge badge-gray">Rolled back</span> {exec.rollback} ·{' '}
        <span title={formatDateTime(exec.rolledBackAt)}>{formatRelativeTime(exec.rolledBackAt)}</span>
      </p>
    )
  }

  if (mutation.isSuccess) {
    return (
      <p className="remediation-status-line">
        <span className="badge badge-gray">Rolled back</span> {mutation.data.undid} — this incident is
        now {mutation.data.incidentState}. The original problem is still there; the undo reversed
        ARGUS's change, it did not re-diagnose anything.
      </p>
    )
  }

  const missing = [
    !canRollback && CAP_REMEDIATION_ROLLBACK,
    !canExecute && CAP_REMEDIATION_EXECUTE_INPLACE,
  ].filter((c): c is string => typeof c === 'string')
  // A sentence, not two wire constants comma-joined. "Missing capability:
  // remediation:rollback, remediation:execute:inplace" named the identifiers
  // the hub checks and answered nothing an operator asked; this says what they
  // cannot do AND keeps the constants, because the constant is what a support
  // request has to name to be actionable (api/capabilityInfo.ts).
  const missingReason = missing.length > 0 ? missingCapabilityMessage(missing) : undefined

  return (
    <div className="remediation-undo">
      {mutation.isError && (
        // Shown in full. Every refusal here names something the operator needs:
        // the value has moved since, the change is already gone, this execution
        // failed so there is nothing to put back, a guardrail wants an explicit
        // confirmation. Summarising would throw away the only useful part.
        <p className="form-error" role="alert">
          {mutation.error instanceof ApiError
            ? mutation.error.detail || mutation.error.message
            : 'Could not apply the undo.'}
        </p>
      )}
      {armed ? (
        <div className="form-actions">
          <button
            type="button"
            className="danger"
            disabled={mutation.isPending}
            onClick={() => mutation.mutate({})}
          >
            {mutation.isPending ? 'Applying…' : `Yes — ${exec.rollback}`}
          </button>
          <button type="button" className="secondary" disabled={mutation.isPending} onClick={() => setArmed(false)}>
            Cancel
          </button>
        </div>
      ) : (
        <button
          type="button"
          className="secondary"
          disabled={!!missingReason}
          title={missingReason ?? `Undo: ${exec.rollback}`}
          onClick={() => setArmed(true)}
        >
          Undo this change
        </button>
      )}
      {/* Visible, not hover-only: a `title` is unreachable by keyboard and by
          touch, and this is the one sentence that tells a blocked operator what
          to go and ask for. */}
      {missingReason && <p className="field-hint">{missingReason}</p>}
      <p className="field-hint">
        Undo: <strong>{exec.rollback}</strong> — the values ARGUS read off the live object before it
        made the change. This reverses what ARGUS did; it does not fix the original problem, which
        will still be there afterwards.
      </p>
    </div>
  )
}

function executionStatusLine(plan: RemediationPlan) {
  if (!plan.execution) return null
  if (plan.execution.outcome === 'succeeded') {
    return (
      <p className="remediation-status-line">
        <span className="badge badge-green">Executed</span> — the cluster accepted the change ·{' '}
        <span title={formatDateTime(plan.execution.executedAt)}>{formatRelativeTime(plan.execution.executedAt)}</span>
      </p>
    )
  }
  // BACKLOG.md C8 / BUGS.md 104: 'unknown' is its own branch, not folded
  // into the failed one — a tunnel drop mid-mutation whose follow-up
  // verify couldn't confirm either way is not the same claim as "this
  // definitely did not work," and asserting the stronger claim is the
  // exact false negative this fix exists to stop making. Amber, matching
  // this state's badge elsewhere (utils/incidents.ts's STATE_BADGE_CLASS),
  // never red — red is reserved for a confirmed failure.
  if (plan.execution.outcome === 'unknown') {
    return (
      <p className="remediation-status-line">
        <span className="badge badge-amber">Outcome unknown</span>{' '}
        {plan.execution.error ?? 'the change could not be confirmed to have applied or not'} — check the
        cluster directly ·{' '}
        <span title={formatDateTime(plan.execution.executedAt)}>{formatRelativeTime(plan.execution.executedAt)}</span>
      </p>
    )
  }
  return (
    <p className="remediation-status-line">
      <span className="badge badge-red">Execution failed</span> {plan.execution.error ?? 'unknown error'} ·{' '}
      <span title={formatDateTime(plan.execution.executedAt)}>{formatRelativeTime(plan.execution.executedAt)}</span>
    </p>
  )
}

// Renders nothing when the analysis proposed no plan, which is the most common
// outcome rather than an edge case — of ten fault types driven end to end
// against a real cluster, exactly one had a fix ARGUS could execute. Callers
// that need to SAY that (the resolution path panel, a toleration's detail) do
// so themselves; this component never renders a placeholder for an absent plan.
export function RemediationPlanCard({
  analysis,
  incidentId,
}: {
  analysis: Analysis
  // Optional because TolerationsPage renders this card for a CLOSED incident's
  // historical plan, where undoing is not on offer — passing an id there would
  // imply an action that screen deliberately does not have.
  incidentId?: string
}) {
  // The approvals page needs remediation:approve to open, so the link to it is
  // offered only to a viewer who holds it.
  const canApprove = useHasCapability(CAP_REMEDIATION_APPROVE)
  const plan = analysis.plan
  if (!plan) return null
  const target = [plan.targetNamespace, plan.targetName].filter(Boolean).join('/')
  return (
    <div className="card remediation-plan-card">
      <div className="section-heading-row">
        <div>
          <p className="eyebrow">Recommended remediation</p>
          <h3>{plan.summary}</h3>
        </div>
        <span className={`badge ${plan.riskLevel === 'high' ? 'badge-red' : plan.riskLevel === 'medium' ? 'badge-amber' : 'badge-blue'}`}>
          {plan.riskLevel} risk
        </span>
      </div>
      <dl className="detail-fact-grid compact">
        <div><dt>Action</dt><dd>{plan.actionType}</dd></div>
        <div><dt>Target</dt><dd>{plan.targetGvk} · {target || plan.targetName}</dd></div>
        <div><dt>Reversible</dt><dd>{plan.reversible ? 'Yes' : 'No'}</dd></div>
        <div><dt>Gate</dt><dd>{plan.gateOutcome}</dd></div>
      </dl>
      <p className="field-hint">{plan.gateReason}</p>
      {approvalStatusLine(plan)}
      {executionStatusLine(plan)}
      {/* Only where undoing is actually on offer: the incident's own page. A
          toleration's historical plan renders the same card without an id, and
          therefore without an action, because that incident is closed. */}
      {incidentId && <UndoControl plan={plan} incidentId={incidentId} />}
      {plan.gateOutcome === 'NeedsApproval' && !plan.approval && canApprove && <Link to="/approvals">Review in approvals →</Link>}
    </div>
  )
}
