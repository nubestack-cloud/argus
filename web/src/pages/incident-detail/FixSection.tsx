// The Fix phase of the incident page (incident lifecycle redesign, 2026-10-12):
// the route stated ONCE, then one option per way this incident can be fixed —
// ARGUS runs it, a pull request, or you do it — in the order ARGUS recommends.
//
// Before this, one fix was spread across three stage cards (Recommendation,
// Approve, Apply): the change was drawn three times, the route explained four
// times, and the Approve button sat ~3,900px below the root cause. Each option
// now carries its own change, its own checks and its own controls, and the
// in-place decision is the SAME ApprovalDecisionCard the queue renders, in its
// embedded form — one decision core, so the gates cannot drift between the two
// pages.
//
// Every honest sentence the old cards carried is still here, read from the same
// stage functions: the gate notices, the paired-route caveat, the revert
// warning on a managed object, the unavailable-route reasons.
import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import type { ApprovalQueueItem, IncidentDetail } from '../../api/types'
import { ApprovalDecisionCard, ApprovalActionsWithoutQueue } from '../../components/ApprovalDecisionCard'
import { RemediationPlanCard } from '../../components/RemediationPlanCard'
import { RepositoryChangePanel } from '../../components/RepositoryChangePanel'
import { SuggestedNextSteps } from '../../components/AnalysisConclusion'
import { AiClaim } from '../../components/AiClaim'
import { HelpTip } from '../../components/HelpTip'
import { SkeletonLines } from '../../components/Skeleton'
import { executesForReal } from '../../utils/incidents'
import { executeStage, OWNERSHIP_COPY, prAvailability, ROUTE_LABEL } from '../incidentLifecycle'
import { fixRoute } from '../incidentPhases'
import { AutomationGateNotice, BatchHoldNotice } from './OwnershipContext'
import { InPlaceChangePreview, LinkRepositoryForm, PairedPlanChangePreview, RouteProvenance } from './ResolutionPanel'
import { PullRequestRecord } from './TriagePanel'

type OptionKind = 'argus' | 'pr' | 'you'

function OptionCard({ kind, primary, children, status }: { kind: OptionKind; primary?: boolean; status?: ReactNode; children: ReactNode }) {
  const who = kind === 'argus' ? 'ARGUS runs it' : kind === 'pr' ? 'Pull request' : 'You do it'
  return (
    <section className={`fix-option fix-option-${kind}${primary ? ' fix-option-primary' : ''}`} aria-label={who}>
      <div className="fix-option-head">
        <span className="fix-option-who">{who}</span>
        {status}
      </div>
      {children}
    </section>
  )
}

export function FixSection({
  incident,
  approvalItem,
  approvalsLoading,
  canApprove,
  hideManualSteps,
}: {
  incident: IncidentDetail
  approvalItem?: ApprovalQueueItem
  approvalsLoading: boolean
  canApprove: boolean
  hideManualSteps?: boolean
}) {
  const analysis = incident.analysis
  const plan = analysis?.plan ?? null
  const pairedPlan = analysis?.pairedPlan ?? null
  const ownership = incident.ownership ?? null
  const copy = ownership ? OWNERSHIP_COPY[ownership.managedBy] : undefined
  const route = fixRoute(incident)
  const pr = prAvailability(ownership)
  const steps = analysis?.status === 'complete' ? analysis.suggestedNextSteps ?? [] : []

  const argusPlan = plan && executesForReal(plan) ? plan : null
  const prPlan = plan && plan.actionType === 'OpenPR' ? plan : null

  // The decision for a plan: the live, shared decision card while the queue
  // has it; otherwise the plan's own record (what was decided, what ran, the
  // undo) and the stage's one-line status.
  const decision = (forPlan: NonNullable<typeof plan>) =>
    approvalItem && approvalItem.plan.id === forPlan.id ? (
      <ApprovalDecisionCard items={[approvalItem]} embedded />
    ) : (
      <>
        <RemediationPlanCard analysis={analysis!} incidentId={incident.id} />
        {/* The change itself, drawn, for an in-place plan — the queue card
            draws it when it is mounted; without it (decided, already run, or
            no approve capability) the diff must still be on the page. */}
        {executesForReal(forPlan) && <InPlaceChangePreview plan={forPlan} incidentId={incident.id} />}
        <p className="fix-status">{executeStage(incident).text}</p>
        {forPlan.gateOutcome === 'NeedsApproval' && !forPlan.approval && (
          !canApprove ? (
            // Disabled with the missing capability named, never hidden
            // (BACKLOG.md D9 U3, lld/11 §6).
            <ApprovalActionsWithoutQueue incidentId={incident.id} />
          ) : approvalsLoading ? (
            <SkeletonLines count={2} />
          ) : (
            <p className="field-hint">
              <Link to="/approvals">Review it in the approval queue →</Link>
            </p>
          )
        )}
      </>
    )

  const gateNotices = (
    <>
      {/* PROJECT.md T14: why an auto-approved plan has not run yet. batch_hold
          is BatchHoldNotice's own, with the wave detail this one lacks. */}
      {incident.automationGate && incident.automationGate.gate !== 'batch_hold' && (
        <AutomationGateNotice gate={incident.automationGate} />
      )}
      {incident.unattendedBatch && <BatchHoldNotice batch={incident.unattendedBatch} />}
    </>
  )

  const argusOption = argusPlan && (
    <OptionCard kind="argus" key="argus" primary={route === 'argus'}>
      {gateNotices}
      {decision(argusPlan)}
      {copy && (
        <p className="fix-caveat">
          {copy.badge} reverts it on the next reconcile — an in-place change buys time, it does not last.
        </p>
      )}
    </OptionCard>
  )

  const prOption = (
    <OptionCard
      kind="pr"
      key="pr"
      primary={route === 'pr'}
      status={
        !prPlan && !incident.pullRequest && !pr.available ? <span className="verification-chip verification-chip-neutral">Not available</span> : undefined
      }
    >
      {prPlan && (
        <>
          {route === 'pr' && gateNotices}
          {decision(prPlan)}
        </>
      )}
      {incident.pullRequest && <PullRequestRecord pr={incident.pullRequest} />}
      {pairedPlan && (
        <>
          <p className="fix-option-title">{pairedPlan.summary}</p>
          <p className="field-hint">
            Proposed alongside the in-place change. Approve/reject on this incident always acts on the in-place plan;
            deciding this pull request independently isn't available from this screen yet.
          </p>
          <PairedPlanChangePreview plan={pairedPlan} />
        </>
      )}
      {!pr.available && !prPlan && !incident.pullRequest && <p className="field-hint">ARGUS cannot open one: {pr.reason}.</p>}
      {/* Helm releases and plain manifests have no controller record naming
          their repository; the one-time link is the fix (LinkRepositoryForm). */}
      {!pr.available && (!ownership || ownership.managedBy === 'helm') && <LinkRepositoryForm ownership={ownership} incidentId={incident.id} />}
      {ownership?.repo && <RepositoryChangePanel incidentId={incident.id} repo={ownership.repo} plan={plan} />}
    </OptionCard>
  )

  const youOption = steps.length > 0 && !hideManualSteps && (
    <OptionCard kind="you" key="you" primary={route === 'you'}>
      <AiClaim>
        <SuggestedNextSteps steps={steps} label={null} />
      </AiClaim>
      {/* PROJECT.md D13: keyed off ownership, not ownership.repo — a Helm
          release with no repository linked is still managed, and its next
          upgrade wipes a manual change. */}
      <p className="fix-caveat">
        {copy
          ? `Running these recovers the cluster now, but the change will not last. ${copy.revert}`
          : 'Nothing here has been run. ARGUS is describing the change, not making it — check it against your own knowledge of this cluster before applying it.'}
      </p>
      <p className="field-hint">When it is done, close the incident from Close out at the top of the page.</p>
    </OptionCard>
  )

  const order: Array<ReactNode> =
    route === 'pr' ? [prOption, argusOption, youOption] : route === 'argus' ? [argusOption, youOption, prOption] : [youOption, prOption, argusOption]

  return (
    <section className="card lc-card" id="incident-fix" tabIndex={-1} aria-labelledby="incident-fix-h">
      <div className="lc-card-head">
        <h2 id="incident-fix-h">Fix</h2>
        <span className="field-hint">What to do, and who does it</span>
      </div>
      {/* The route, once: ARGUS's code decides it from ownership before the
          model proposes anything (ADR-18), and routeReason says why. */}
      {incident.routeReason && (
        <p className="fix-route">
          <span className="eyebrow">Route</span>
          <span className={`route-badge${incident.route === 'pullRequest' ? ' route-badge-blue' : incident.route === 'inPlace' ? ' route-badge-amber' : ''}`}>{ROUTE_LABEL[incident.route ?? ''] ?? 'Route'}</span>
          <span className="field-hint">{incident.routeReason}</span>
        </p>
      )}
      {/* BACKLOG.md D9 U5: a path from the proposed fix back to the evidence
          it was built from — never a claim without the way to check it. */}
      {!!analysis?.causalChain.length && (
        <p className="field-hint">
          <a
            href="#causal-chain"
            onClick={() => {
              // A hash change does not re-render the page, so open the
              // collapsed chain this link points at; the browser then scrolls.
              const chain = document.getElementById('causal-chain')
              if (chain instanceof HTMLDetailsElement) chain.open = true
            }}
          >
            Built from the {analysis.causalChain.length}-step causal chain ↑
          </a>
        </p>
      )}
      {pairedPlan && (
        <p className="field-hint">
          ARGUS proposed this fix on both routes at once.{' '}
          <HelpTip
            label="the two routes"
            text="The in-place change takes effect in the cluster now, and the pull request keeps it from being reverted the next time this object syncs from Git."
          />
        </p>
      )}
      {!plan && steps.length === 0 && analysis?.status === 'complete' && !incident.pullRequest && (
        <p className="fix-status">
          {analysis.rootCause
            ? 'No fix proposed — ARGUS has no action for this cause and gave no steps.'
            : 'No fix proposed — the investigation recorded no cause.'}
        </p>
      )}
      <div className="fix-options">{order}</div>
      <RouteProvenance ownership={ownership} />
    </section>
  )
}
