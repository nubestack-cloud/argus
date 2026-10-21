// The incident lifecycle as the detail page draws it: four phases and an
// outcome (owner-approved redesign, 2026-10-12, "Incident lifecycle redesign"
// artifact).
//
//   Detected → Diagnosed → Fix → Holding → outcome
//
// The six-step model before this (Detection, Analysis, Recommendation, Approve,
// Apply, Validate) split one decision across three steps and drew every step
// for every incident, so the common case — nothing executed — read as four
// empty boxes. Here Recommendation/Approve/Apply are the Fix phase's sub-steps,
// drawn as pills for the one route this incident is on, and a phase that cannot
// happen is `skipped`, never an empty step.
//
// Nothing here decides a state on its own. Every status below is read from the
// stage functions in incidentLifecycle.ts (executeStage, validateStage, …),
// which carry the honesty rules this page has accumulated — "unknown" never
// worded as "failed", a self-healed close never credited to ARGUS, a merged
// pull request recognised from the incident's own record. This module only
// regroups their answers, so the spine cannot disagree with them.
import type { IncidentDetail } from '../api/types'
import { executesForReal, isClosedIncidentState, RESOLUTION_KIND_EXPLANATION, stateExplanation } from '../utils/incidents'
import { compactDuration } from '../utils/time'
import { approveStage, executeStage, nextActionSummary, validateStage, type ResolutionStageState } from './incidentLifecycle'

export type PhaseStatus = 'done' | 'current' | 'next' | 'skipped' | 'failed'
export type PhaseKey = 'detected' | 'diagnosed' | 'fix' | 'holding'
export type FixRoute = 'argus' | 'pr' | 'you' | null

export interface PhasePip {
  label: string
  status: 'done' | 'current' | 'next' | 'failed'
}

export interface Phase {
  key: PhaseKey
  name: string
  // The question the phase answers — the same words as the matching card's
  // eyebrow, so the spine and the cards read as one structure.
  question: string
  status: PhaseStatus
  // A few words, never a sentence: a count, a route, a state.
  detail: string
  // When the phase was reached. Absent when the payload carries no time for it
  // rather than estimated.
  at?: string
  // Time since the previous phase, for a phase that has been reached.
  took?: string
  // How long the incident has sat in this phase, for the current one.
  waiting?: string
  route?: FixRoute
  routeLabel?: string
  pips?: PhasePip[]
}

export interface Outcome {
  label: string
  tone: 'open' | 'green' | 'gray'
}

export type NowTone = 'you' | 'argus' | 'team' | 'watch' | 'closed'

export interface NowLine {
  who: string
  tone: NowTone
  what: string
  // Where the reader acts, as the id of a section on the page.
  target?: 'incident-why' | 'incident-fix' | 'incident-hold'
}

export interface PhaseModel {
  phases: Phase[]
  outcome: Outcome
  now: NowLine
}

const stageToPip = (s: ResolutionStageState): PhasePip['status'] =>
  s === 'done' ? 'done' : s === 'current' ? 'current' : s === 'blocked' ? 'failed' : 'next'

// The first clause of a server sentence, for the one-line "now" bar — the
// full reason is beside the Approve button in the Fix section.
function firstClause(sentence: string): string {
  const cut = sentence.search(/, so |; | — |\. /)
  return cut > 0 ? sentence.slice(0, cut) : sentence.replace(/\.$/, '')
}

function since(from: string | undefined, nowIso: string): string | undefined {
  if (!from) return undefined
  return compactDuration(from, nowIso) ?? undefined
}

// Which Fix branch this incident is on. A pull request route wins whenever one
// exists — an OpenPR plan, an open/merged pull request, or AwaitingMerge —
// because once a pull request is in flight the in-place plan cannot be
// approved (nextActionSummary's AwaitingMerge branch).
export function fixRoute(incident: IncidentDetail): FixRoute {
  const analysis = incident.analysis
  const plan = analysis?.plan ?? null
  if (plan?.actionType === 'OpenPR' || incident.state === 'AwaitingMerge' || (incident.pullRequest && !plan)) return 'pr'
  if (plan && executesForReal(plan)) return 'argus'
  if (plan) return 'pr'
  if (analysis?.status === 'complete') return 'you'
  return null
}

export function phaseModel(
  incident: IncidentDetail,
  opts: {
    investigating?: boolean
    canApprove?: boolean
    executionBlockedReason?: string
    now?: string
    // From the timeline: an IncidentResolved event is a person's own close
    // (internal/timeline's EventIncidentResolved), which resolutionKind cannot
    // say — it stamps every close with no ARGUS fix "self_healed".
    resolvedByPerson?: boolean
  } = {},
): PhaseModel {
  const nowIso = opts.now ?? new Date().toISOString()
  const analysis = incident.analysis
  const plan = analysis?.plan ?? null
  const state = incident.state
  const closed = isClosedIncidentState(state)
  const running = !!opts.investigating || state === 'Investigating'

  // ---- 1. Detected — always reached; the incident exists because of it.
  const detected: Phase = {
    key: 'detected',
    name: 'Detected',
    question: 'What broke',
    status: 'done',
    detail: state === 'Reopened' ? 'Reopened' : `${incident.occurrenceCount.toLocaleString()} occurrence${incident.occurrenceCount === 1 ? '' : 's'}`,
    at: incident.firstSeen,
  }

  // ---- 2. Diagnosed
  let diagnosed: Phase
  if (running) {
    diagnosed = { key: 'diagnosed', name: 'Diagnosed', question: 'Why', status: 'current', detail: 'Investigating' }
  } else if (!analysis) {
    diagnosed = { key: 'diagnosed', name: 'Diagnosed', question: 'Why', status: closed ? 'skipped' : 'current', detail: 'Not investigated' }
  } else if (analysis.status !== 'complete') {
    diagnosed = { key: 'diagnosed', name: 'Diagnosed', question: 'Why', status: 'current', detail: 'Stopped early', at: analysis.createdAt }
  } else {
    const pct = analysis.confidence == null ? '' : ` · ${Math.round(analysis.confidence * 100)}%`
    diagnosed = {
      key: 'diagnosed',
      name: 'Diagnosed',
      question: 'Why',
      status: 'done',
      detail: analysis.rootCause ? `Cause found${pct}` : 'No cause recorded',
      at: analysis.createdAt,
    }
  }

  // ---- 3. Fix — one branch, the one this incident is on.
  const route = fixRoute(incident)
  const execute = executeStage(incident)
  const approve = approveStage(incident)
  let fix: Phase
  if (!analysis || analysis.status !== 'complete' || running) {
    // A partial run with a plan still has a fix to look at; without one the
    // phase has not started.
    fix = { key: 'fix', name: 'Fix', question: 'What to do', status: closed ? 'skipped' : 'next', detail: closed ? 'Not reached' : 'After diagnosis', route: null }
    if (plan && !running) fix = { ...fix, status: 'current', detail: plan.summary }
  } else if (route === 'argus') {
    const pips: PhasePip[] = [
      { label: plan?.approval?.verdict === 'approved' ? 'Approved' : plan?.approval?.verdict === 'rejected' ? 'Rejected' : 'Decide', status: stageToPip(approve.state) },
      // A rejected plan never ran: its Run step is not reached, not failed —
      // a red Run would claim an execution that never happened.
      {
        label: plan?.execution?.outcome === 'succeeded' ? 'Ran' : 'Run',
        status: plan?.approval?.verdict === 'rejected' && !plan.execution ? 'next' : stageToPip(execute.state),
      },
    ]
    const status: PhaseStatus =
      execute.state === 'done' ? 'done' : execute.state === 'blocked' || approve.state === 'blocked' ? 'failed' : execute.state === 'current' || approve.state === 'current' ? 'current' : closed ? 'skipped' : 'current'
    fix = {
      key: 'fix',
      name: 'Fix',
      question: 'What to do',
      status,
      route,
      routeLabel: 'ARGUS runs it',
      detail:
        plan?.approval?.verdict === 'rejected'
          ? 'Rejected'
          : plan?.execution?.outcome === 'succeeded'
            ? 'Applied'
            : plan?.execution?.outcome === 'unknown'
              ? 'Outcome unknown'
              : plan?.execution?.outcome === 'failed'
                ? 'Failed'
                : state === 'Executing'
                  ? 'Running'
                  : plan?.gateOutcome === 'Blocked'
                    ? 'Blocked by the gate'
                    : 'Waiting on a decision',
      at: plan?.execution?.executedAt ?? plan?.approval?.createdAt,
      pips,
    }
  } else if (route === 'pr') {
    const pr = incident.pullRequest
    const opened = !!pr
    const merged = !!pr?.mergedAt
    const closedUnmerged = !!pr?.closedUnmergedAt
    const rejected = plan?.approval?.verdict === 'rejected'
    const pips: PhasePip[] = [
      { label: rejected ? 'Rejected' : 'Decide', status: rejected ? 'failed' : opened || plan?.approval?.verdict === 'approved' ? 'done' : 'current' },
      { label: 'Opened', status: closedUnmerged ? 'failed' : opened ? 'done' : 'next' },
      { label: 'Merged', status: merged ? 'done' : opened && !closedUnmerged ? 'current' : 'next' },
    ]
    fix = {
      key: 'fix',
      name: 'Fix',
      question: 'What to do',
      status: merged ? 'done' : closedUnmerged || rejected ? 'failed' : closed ? 'skipped' : 'current',
      route,
      routeLabel: 'Pull request',
      detail: merged
        ? 'Merged'
        : closedUnmerged
          ? 'Closed without merging'
          : rejected
            ? 'Rejected'
            : opened
              ? `#${pr!.number} in review`
              : 'Waiting on a decision',
      at: pr?.mergedAt ?? pr?.openedAt ?? plan?.approval?.createdAt,
      pips,
    }
  } else {
    // A complete investigation with no plan: the fix, if one is needed, is a
    // person's. On a closed incident ARGUS ran nothing, which is a skip.
    fix = closed
      ? { key: 'fix', name: 'Fix', question: 'What to do', status: 'skipped', detail: 'Nothing ARGUS ran', route: 'you' }
      : {
          key: 'fix',
          name: 'Fix',
          question: 'What to do',
          status: 'current',
          route: 'you',
          routeLabel: 'You do it',
          detail: analysis.rootCause ? 'Yours to make' : 'No fix proposed',
          pips: [
            { label: 'Steps', status: 'current' },
            { label: 'Close out', status: 'next' },
          ],
        }
  }

  // ---- 4. Holding — read from validateStage.
  const validate = validateStage(incident)
  let holding: Phase
  if (state === 'Resolved') {
    holding = {
      key: 'holding',
      name: 'Holding',
      question: 'Did it hold',
      status: 'done',
      detail:
        incident.resolutionKind === 'remediated'
          ? 'No new findings'
          : opts.resolvedByPerson
            ? 'Closed by a person'
            : 'Closed without an ARGUS fix',
      at: incident.resolvedAt,
    }
  } else if (state === 'Dismissed' || state === 'Expired') {
    holding = { key: 'holding', name: 'Holding', question: 'Did it hold', status: 'skipped', detail: 'Not watched' }
  } else {
    const status: PhaseStatus =
      validate.state === 'current' ? 'current' : validate.state === 'blocked' ? 'failed' : validate.state === 'unreachable' ? 'skipped' : validate.state === 'done' ? 'done' : 'next'
    holding = {
      key: 'holding',
      name: 'Holding',
      question: 'Did it hold',
      status: state === 'AwaitingMerge' ? 'next' : status,
      detail:
        state === 'Reopened'
          ? incident.reopenedBy && !incident.reopenedBy.sameObject
            ? 'Another object failing'
            : 'Recurred'
          : state === 'Validating'
            ? 'Watching'
            : state === 'ValidationUnknown'
              ? 'Not confirmed'
              : status === 'failed'
                ? 'Not reached'
                : status === 'skipped'
                  ? 'Nothing to watch'
                  : 'After the fix',
    }
  }

  const phases = [detected, diagnosed, fix, holding]

  // Time taken between consecutive reached phases, and the wait on the current one.
  let prevAt: string | undefined
  for (const p of phases) {
    if (p.at && prevAt && (p.status === 'done' || p.status === 'failed' || p.status === 'current')) p.took = since(prevAt, p.at)
    if (p.status === 'current' && !closed) p.waiting = since(p.at ?? prevAt, nowIso)
    if (p.at) prevAt = p.at
  }

  // ---- Outcome
  const outcome: Outcome =
    state === 'Resolved'
      ? incident.resolutionKind === 'remediated'
        ? { label: 'Fixed by ARGUS', tone: 'green' }
        : opts.resolvedByPerson
          ? { label: 'Resolved by a person', tone: 'green' }
          : incident.resolutionKind === 'self_healed'
          ? { label: 'Resolved · self-healed', tone: 'green' }
          : { label: 'Resolved', tone: 'green' }
      : state === 'Dismissed'
        ? { label: 'Dismissed', tone: 'gray' }
        : state === 'Expired'
          ? { label: 'Expired', tone: 'gray' }
          : { label: 'Open', tone: 'open' }

  return { phases, outcome, now: nowLine(incident, route, { running, closed, ...opts }) }
}

function nowLine(
  incident: IncidentDetail,
  route: FixRoute,
  o: { running: boolean; closed: boolean; canApprove?: boolean; executionBlockedReason?: string; resolvedByPerson?: boolean },
): NowLine {
  const state = incident.state
  const analysis = incident.analysis
  const plan = analysis?.plan ?? null

  if (o.closed) {
    if (state === 'Resolved') {
      return {
        who: 'Closed',
        tone: 'closed',
        what:
          incident.resolutionKind === 'remediated'
            ? "Fixed by ARGUS — no new findings during the re-check window. That is an absence of findings, not a positive re-check."
            : o.resolvedByPerson
              ? 'Resolved by a person — ARGUS ran no fix for this. What they recorded is in History.'
              : incident.resolutionKind === 'self_healed'
              ? RESOLUTION_KIND_EXPLANATION.self_healed
              : 'Resolved.',
      }
    }
    if (state === 'Expired') {
      return { who: 'Closed', tone: 'closed', what: 'Closed in bulk, not by an individual decision — if the problem recurs, this incident reopens automatically.' }
    }
    return { who: 'Closed', tone: 'closed', what: 'Dismissed — closed without acting on it. If the problem recurs, its detector opens a new incident.' }
  }

  if (o.running) {
    return { who: 'ARGUS is working', tone: 'argus', what: 'Investigating — gathering live evidence from the cluster. This page updates when it finishes.', target: 'incident-why' }
  }
  if (!analysis) {
    return {
      who: 'Your move',
      tone: 'you',
      what: incident.automationGate
        ? `Investigate to find the cause — not picked up automatically: ${incident.automationGate.reason}`
        : stateExplanation('Detected') ?? 'Investigate to find the cause.',
      target: 'incident-why',
    }
  }
  if (state === 'Executing') return { who: 'ARGUS is working', tone: 'argus', what: 'Running the approved fix now.', target: 'incident-fix' }
  if (state === 'AwaitingMerge') {
    const n = incident.pullRequest?.number
    return {
      who: "Your team's review",
      tone: 'team',
      what: `${n ? `Pull request #${n}` : 'The pull request'} waits for review and merge. ARGUS never merges; it re-reads the synced files after the merge.`,
      target: 'incident-fix',
    }
  }
  if (state === 'Validating') {
    return { who: 'ARGUS is watching', tone: 'watch', what: 'Watching for recurrence — closes as resolved if nothing comes back.', target: 'incident-hold' }
  }
  if (plan && route !== 'you' && !plan.approval && !plan.execution && plan.gateOutcome !== 'Blocked' && (state === 'AwaitingApproval' || state === 'RecommendationReady')) {
    const verb = route === 'pr' ? 'open a pull request for' : 'run'
    return {
      who: o.canApprove === false ? 'Waiting on an approver' : 'Your move',
      tone: 'you',
      what: `Approve or reject — ARGUS would ${verb}: ${plan.summary.replace(/\s*\([^)]*\)\s*$/, '')}${o.executionBlockedReason ? `. Cannot run yet: ${firstClause(o.executionBlockedReason)}` : ''}`,
      target: 'incident-fix',
    }
  }
  if (analysis.status !== 'complete') {
    return { who: 'Your move', tone: 'you', what: 'The investigation stopped early — review what it found, or re-investigate.', target: 'incident-why' }
  }
  // The states whose meaning needs a sentence get the shared one — the same
  // words wherever the state is explained, including "possibly nothing needs
  // doing" for a diagnosis with no fix (never "apply the fix yourself", which
  // is false when the investigation found nothing wrong — see validateStage).
  const explained = stateExplanation(state, analysis)
  if (explained) return { who: 'Your move', tone: 'you', what: explained, target: 'incident-fix' }
  return { who: 'Your move', tone: 'you', what: nextActionSummary(incident), target: 'incident-fix' }
}
