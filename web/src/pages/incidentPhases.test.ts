import { describe, expect, it } from 'vitest'
import type { IncidentDetail, RemediationPlan, TimelineEvent } from '../api/types'
import { phaseModel } from './incidentPhases'
import { milestonesFrom } from './incidentHistory'

const NOW = '2026-08-27T09:00:00Z'

const scalePlan: RemediationPlan = {
  id: 'plan_scale',
  actionType: 'ScaleDeployment',
  targetGvk: 'apps/v1/Deployment',
  targetNamespace: 'payments',
  targetName: 'payments-api',
  params: { replicas: 3 },
  reversible: true,
  riskLevel: 'low',
  effectiveRiskLevel: 'low',
  summary: 'Scale payments-api to 3 replicas',
  gateOutcome: 'NeedsApproval',
  gateReason: 'Confidence below the auto-approve threshold',
  createdAt: '2026-08-25T10:00:00Z',
}

function incident(over: Partial<IncidentDetail> = {}, analysisOver: Record<string, unknown> | null = {}): IncidentDetail {
  return {
    id: 'inc_1',
    clusterId: 'cl_1',
    clusterDisplayName: 'prod-eu',
    fingerprint: 'fp_1',
    severity: 'high',
    state: 'AwaitingApproval',
    firstSeen: '2026-08-25T09:00:00Z',
    lastSeen: '2026-08-25T09:30:00Z',
    occurrenceCount: 4,
    analysis:
      analysisOver === null
        ? null
        : {
            id: 'an_1',
            status: 'complete',
            causalChain: [],
            ruledOut: [],
            rootCause: { statement: 'OOMKilled repeatedly' },
            confidence: 0.8,
            partialReason: null,
            suggestedNextSteps: null,
            model: 'm',
            iterations: 1,
            createdAt: '2026-08-25T10:00:00Z',
            tokensBilledIn: 0,
            tokensCacheRead: 0,
            tokensOut: 0,
            costUsd: 0,
            costBasis: 'metered',
            incidentState: 'AwaitingApproval',
            stateReason: '',
            plan: scalePlan,
            ...analysisOver,
          },
    findings: [],
    findingGroups: [],
    ownership: null,
    evidence: null,
    unattendedBatch: null,
    priorIncidents: [],
    ...over,
  } as IncidentDetail
}

const statuses = (m: ReturnType<typeof phaseModel>) => m.phases.map((p) => `${p.key}:${p.status}`)

describe('phaseModel — the four phases and the outcome', () => {
  it('not investigated: Diagnosed is current, Fix and Holding are ahead, and the next move is to investigate', () => {
    const m = phaseModel(incident({ state: 'Detected' }, null), { now: NOW })
    expect(statuses(m)).toEqual(['detected:done', 'diagnosed:current', 'fix:next', 'holding:next'])
    expect(m.phases[1].detail).toBe('Not investigated')
    expect(m.outcome.label).toBe('Open')
    expect(m.now.tone).toBe('you')
    expect(m.now.target).toBe('incident-why')
    // How long it has waited, from the real first-seen time.
    expect(m.phases[1].waiting).toBe('2d')
  })

  it('an investigation running is ARGUS\'s move, not the reader\'s', () => {
    const m = phaseModel(incident({ state: 'Investigating' }, null), { now: NOW })
    expect(m.phases[1].detail).toBe('Investigating')
    expect(m.now.tone).toBe('argus')
  })

  it('waiting on approval for an in-place plan: the Fix phase is on the ARGUS route with Decide current', () => {
    const m = phaseModel(incident(), { now: NOW, canApprove: true, executionBlockedReason: 'lab-dev has no remediation agent connected' })
    expect(statuses(m)).toEqual(['detected:done', 'diagnosed:done', 'fix:current', 'holding:next'])
    const fix = m.phases[2]
    expect(fix.route).toBe('argus')
    expect(fix.pips?.map((p) => `${p.label}:${p.status}`)).toEqual(['Decide:current', 'Run:next'])
    expect(m.phases[1].took).toBe('1h')
    expect(m.now.what).toMatch(/Approve or reject/)
    // The execution block is named on the line, not left for the reader to find.
    expect(m.now.what).toMatch(/Cannot run yet: lab-dev has no remediation agent connected/)
  })

  it('a viewer who cannot approve is told the move is an approver\'s, not theirs', () => {
    const m = phaseModel(incident(), { now: NOW, canApprove: false })
    expect(m.now.who).toBe('Waiting on an approver')
  })

  it('a diagnosis with no plan routes the fix to a person, and never claims a fix is needed', () => {
    const m = phaseModel(incident({ state: 'Diagnosed' }, { plan: null }), { now: NOW })
    expect(m.phases[2].route).toBe('you')
    expect(m.phases[2].status).toBe('current')
    // validateStage's rule: a diagnosis with no fix may mean nothing needs doing.
    expect(m.now.what).not.toMatch(/apply the fix yourself/i)
    expect(m.now.what).toMatch(/possibility that nothing needs doing/)
  })

  it('NeedsHumanInvestigation with no recorded cause reads as inconclusive, not as a fix to make', () => {
    const m = phaseModel(incident({ state: 'NeedsHumanInvestigation' }, { plan: null, rootCause: null }), { now: NOW })
    expect(m.phases[2].detail).toBe('No fix proposed')
    expect(m.now.what).toMatch(/without a clear cause/)
  })

  it('a pull request in review is the team\'s move, on the pull request route', () => {
    const m = phaseModel(
      incident(
        { state: 'AwaitingMerge', pullRequest: { number: 42, openedAt: '2026-08-25T11:00:00Z' } },
        { plan: { ...scalePlan, actionType: 'OpenPR', approval: { verdict: 'approved', createdAt: '2026-08-25T10:30:00Z' } } },
      ),
      { now: NOW },
    )
    const fix = m.phases[2]
    expect(fix.route).toBe('pr')
    expect(fix.detail).toBe('#42 in review')
    expect(fix.pips?.map((p) => `${p.label}:${p.status}`)).toEqual(['Decide:done', 'Opened:done', 'Merged:current'])
    expect(m.phases[3].status).toBe('next')
    expect(m.now.tone).toBe('team')
    expect(m.now.what).toMatch(/Pull request #42/)
  })

  it('a pull request closed without merging is a Fix that did not complete', () => {
    const m = phaseModel(
      incident(
        { state: 'AwaitingApproval', pullRequest: { number: 7, openedAt: '2026-08-25T11:00:00Z', closedUnmergedAt: '2026-08-26T11:00:00Z' } },
        { plan: { ...scalePlan, actionType: 'OpenPR' } },
      ),
      { now: NOW },
    )
    expect(m.phases[2].status).toBe('failed')
    expect(m.phases[2].detail).toBe('Closed without merging')
  })

  it('validating after a successful run: Fix done, Holding current, and ARGUS is watching', () => {
    const m = phaseModel(
      incident(
        { state: 'Validating' },
        {
          plan: {
            ...scalePlan,
            approval: { verdict: 'approved', createdAt: '2026-08-25T10:30:00Z' },
            execution: { id: 'ex_1', outcome: 'succeeded', executedAt: '2026-08-25T10:31:00Z' },
          },
        },
      ),
      { now: NOW },
    )
    expect(statuses(m)).toEqual(['detected:done', 'diagnosed:done', 'fix:done', 'holding:current'])
    expect(m.now.tone).toBe('watch')
  })

  it('an unknown execution outcome is never worded as a failure', () => {
    const m = phaseModel(
      incident(
        { state: 'ExecutionUnknown' },
        { plan: { ...scalePlan, approval: { verdict: 'approved', createdAt: '2026-08-25T10:30:00Z' }, execution: { id: 'ex_1', outcome: 'unknown', executedAt: '2026-08-25T10:31:00Z' } } },
      ),
      { now: NOW },
    )
    expect(m.phases[2].detail).toBe('Outcome unknown')
    expect(m.now.what).not.toMatch(/\bfailed\b/i)
  })

  it('reopened by a sibling object names that, not a failed fix', () => {
    const m = phaseModel(
      incident(
        { state: 'Reopened', reopenedBy: { sameObject: false, objectName: 'payments-api-7f9', occurredAt: '2026-08-26T09:00:00Z' } },
        { plan: { ...scalePlan, approval: { verdict: 'approved', createdAt: '2026-08-25T10:30:00Z' }, execution: { id: 'ex_1', outcome: 'succeeded', executedAt: '2026-08-25T10:31:00Z' } } },
      ),
      { now: NOW },
    )
    expect(m.phases[0].detail).toBe('Reopened')
    expect(m.phases[3].status).toBe('failed')
    expect(m.phases[3].detail).toBe('Another object failing')
  })

  it('self-healed: Fix skipped (ARGUS ran nothing), Holding done, outcome self-healed — never credited to ARGUS', () => {
    const m = phaseModel(
      incident({ state: 'Resolved', resolutionKind: 'self_healed', resolvedAt: '2026-08-25T12:00:00Z' }, { plan: null }),
      { now: NOW },
    )
    expect(statuses(m)).toEqual(['detected:done', 'diagnosed:done', 'fix:skipped', 'holding:done'])
    expect(m.outcome).toEqual({ label: 'Resolved · self-healed', tone: 'green' })
    expect(m.phases[3].detail).toBe('Closed without an ARGUS fix')
    expect(m.now.tone).toBe('closed')
    expect(m.now.what).toMatch(/ARGUS did not act/)
    // A closed incident is not waiting on anything.
    expect(m.phases.some((p) => p.waiting)).toBe(false)
  })

  it('a person resolving it by hand is said as that, not as self-healed', () => {
    const m = phaseModel(
      incident({ state: 'Resolved', resolutionKind: 'self_healed', resolvedAt: '2026-08-25T12:00:00Z' }, { plan: null }),
      { now: NOW, resolvedByPerson: true },
    )
    expect(m.outcome.label).toBe('Resolved by a person')
    expect(m.phases[3].detail).toBe('Closed by a person')
    expect(m.now.what).toMatch(/Resolved by a person — ARGUS ran no fix/)
  })

  it('fixed by ARGUS is the only outcome that credits ARGUS', () => {
    const m = phaseModel(
      incident(
        { state: 'Resolved', resolutionKind: 'remediated', resolvedAt: '2026-08-25T12:00:00Z' },
        { plan: { ...scalePlan, approval: { verdict: 'approved', createdAt: '2026-08-25T10:30:00Z' }, execution: { id: 'ex_1', outcome: 'succeeded', executedAt: '2026-08-25T10:31:00Z' } } },
      ),
      { now: NOW },
    )
    expect(m.outcome.label).toBe('Fixed by ARGUS')
    expect(statuses(m)).toEqual(['detected:done', 'diagnosed:done', 'fix:done', 'holding:done'])
  })

  it('dismissed before any investigation skips the phases it never reached', () => {
    const m = phaseModel(incident({ state: 'Dismissed' }, null), { now: NOW })
    expect(statuses(m)).toEqual(['detected:done', 'diagnosed:skipped', 'fix:skipped', 'holding:skipped'])
    expect(m.outcome).toEqual({ label: 'Dismissed', tone: 'gray' })
  })

  it('a rejected plan is a Fix that did not complete, and the next move is the reader\'s', () => {
    const m = phaseModel(
      incident({ state: 'PlanRejected' }, { plan: { ...scalePlan, approval: { verdict: 'rejected', reason: 'wrong call', createdAt: '2026-08-25T10:30:00Z' } } }),
      { now: NOW },
    )
    expect(m.phases[2].status).toBe('failed')
    expect(m.phases[2].detail).toBe('Rejected')
    expect(m.now.tone).toBe('you')
  })
})

const ev = (eventType: string, at: string, summary = eventType): TimelineEvent => ({ id: `${eventType}-${at}`, eventType, summary, occurredAt: at }) as TimelineEvent

describe('milestonesFrom — the history rail', () => {
  it('folds a run and its results into one milestone, and collapses identical back-to-back runs', () => {
    const events = [
      ev('IncidentOpened', '2026-10-05T12:36:00Z', 'FailedAttachVolume'),
      ev('InvestigationStarted', '2026-10-07T09:35:00Z'),
      ev('AnalysisCompleted', '2026-10-07T09:36:00Z', 'gate reasoning'),
      ev('RecommendationReady', '2026-10-07T09:36:00Z', 'Recommended: DeleteResource'),
      ev('InvestigationStarted', '2026-10-07T09:37:00Z'),
      ev('AnalysisCompleted', '2026-10-07T09:38:00Z', 'gate reasoning'),
      ev('RecommendationReady', '2026-10-07T09:38:00Z', 'Recommended: DeleteResource'),
      ev('ApprovalGranted', '2026-10-08T10:00:00Z', 'Approved'),
    ]
    const m = milestonesFrom(events)
    expect(m.map((x) => x.title)).toEqual(['Detected', 'Investigated 2×', 'Approved'])
    expect(m[1].detail).toBe('Recommended: DeleteResource')
    expect(m[1].from).toBe('2026-10-07T09:35:00Z')
    expect(m[1].to).toBe('2026-10-07T09:38:00Z')
  })

  it('keeps runs with different outcomes apart', () => {
    const m = milestonesFrom([
      ev('InvestigationStarted', '2026-10-07T09:35:00Z'),
      ev('RecommendationReady', '2026-10-07T09:36:00Z', 'Recommended: RestartPod'),
      ev('InvestigationStarted', '2026-10-07T10:35:00Z'),
      ev('AnalysisFailed', '2026-10-07T10:36:00Z', 'model timed out'),
    ])
    expect(m.map((x) => `${x.title}:${x.detail}:${x.tone}`)).toEqual([
      'Investigated:Recommended: RestartPod:argus',
      'Investigated:failed:bad',
    ])
  })

  it('names an event type it does not know rather than dropping it', () => {
    const m = milestonesFrom([ev('SomethingNew', '2026-10-07T09:35:00Z', 'a new kind of event')])
    expect(m[0].title).toBe('Something New')
    expect(m[0].detail).toBe('a new kind of event')
  })
})
