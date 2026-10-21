import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, within, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { explainStage, validateStage, nextActionSummary, executeStage, approveStage } from './incidentLifecycle'
import type { Analysis, AnalysisStep, ApprovalQueueItem, IncidentDetail, IncidentReopenCause, ObjectOwnership, RemediationPlan, ToolCall } from '../api/types'
import { CAP_INCIDENT_REANALYSE, CAP_REMEDIATION_APPROVE, CAP_REPO_READ, CAP_REPO_WRITE, CAP_REMEDIATION_EXECUTE_PR } from '../api/capabilities'

// BACKLOG D8 A1. These tests exist because the lifecycle rail and the prose
// beside it independently described the SAME fact at two different strengths,
// and a reader resolves that kind of conflict in favour of the green tick.
//
// Two instances, both fixed, both pinned here:
//
//   1. Step 2 was `analysis ? 'done' : 'current'`, so a PARTIAL run rendered as
//      a completed step while AnalysisConclusion — reading the same
//      analysis.status — called it "Investigation incomplete".
//   2. Step 6 claimed "Confirmed resolved — no recurrence within the re-check
//      window" where nextActionSummary said of the identical state "not a
//      positive re-check, only an absence of new findings".
//
// Neither was catchable by any element-level check: each sentence is defensible
// on its own, and the violation exists only in the pair. So the assertions below
// deliberately test the PAIR, not the individual strings.

/** Minimal Analysis with only the fields these stage functions read. */
function analysis(over: Partial<Analysis>): Analysis {
  return {
    id: 'an_test',
    status: 'complete',
    causalChain: [],
    ruledOut: [],
    rootCause: null,
    confidence: null,
    partialReason: null,
    suggestedNextSteps: null,
    plan: null,
    ...over,
  } as unknown as Analysis
}

/** Minimal IncidentDetail carrying just a state and an analysis. */
function incident(state: string, an: Analysis | null, extra: Partial<IncidentDetail> = {}): IncidentDetail {
  return { id: 'inc_test', state, analysis: an, findings: [], ...extra } as unknown as IncidentDetail
}

describe('explainStage — a partial investigation is never a completed step', () => {
  it('reports done only for a complete analysis', () => {
    expect(explainStage(analysis({ status: 'complete' })).state).toBe('done')
  })

  it('does NOT report done for a partial analysis', () => {
    const partial = explainStage(analysis({ status: 'partial' }))
    // The specific regression: any state that renders as a finished step.
    expect(partial.state).not.toBe('done')
    // 'current', not 'blocked': blocked renders --danger red, which every other
    // use of it in this file reserves for a real failure (Rejected, Failed,
    // Recurred) — and red would contradict AnalysisConclusion's amber
    // "incomplete" badge, recreating the same defect in the other direction.
    // Not 'unreachable' either, since re-analyzing can still finish the run.
    expect(partial.state).toBe('current')
  })

  it('says in the step text that the run stopped early', () => {
    // The evidence count alone is true of a partial run too, which is exactly
    // how it sat under a green tick unchallenged. The text has to carry the
    // qualification, not just the state class.
    expect(explainStage(analysis({ status: 'partial' })).text).toMatch(/stopped before reaching a conclusion/i)
    expect(explainStage(analysis({ status: 'complete' })).text).not.toMatch(/stopped/i)
  })

  it('is current, not done, when no analysis has run at all', () => {
    expect(explainStage(null).state).toBe('current')
  })

  it('agrees with the amber-badge framing rather than contradicting it', () => {
    // AnalysisConclusion renders "Investigation incomplete" for exactly this
    // input. The rail must not simultaneously call it finished.
    const partial = explainStage(analysis({ status: 'partial' }))
    expect(partial.state === 'done' && /incomplete/i.test('Investigation incomplete')).toBe(false)
  })
})

// A Reopened incident is NOT proof that the fix failed. Correlation runs at the
// WORKLOAD tier when a Pod's owner is known (gateway.correlationIdentity.tier),
// so every Pod of a Deployment shares one incident — and a merged fix can hold
// perfectly while the incident reopens because a DIFFERENT Pod of that workload
// started failing.
//
// Observed live on inc_01m0xfwwjjgk1hexrsnqc00m7e: the fixed Pod's findings
// stopped at the minute the pull request merged and it was replaced by a healthy
// one; the replacement Pod then reported a different fault, correlated onto the
// same incident, and reopened it. The UI said "the fix did not hold". It had.
//
// Pinned here because the failure is a SENTENCE, not a state: `state` is
// 'blocked' in all three cases below and always was, so nothing about the rail's
// colour would have caught this. The assertions are about what is CLAIMED.
describe('validateStage — Reopened does not mean the fix failed', () => {
  const reopenedBy = (over: Partial<IncidentReopenCause>): IncidentDetail =>
    ({
      id: 'inc_test',
      state: 'Reopened',
      analysis: null,
      findings: [],
      reopenedBy: { occurredAt: '2026-08-27T15:09:13Z', sameObject: false, ...over },
    }) as unknown as IncidentDetail

  it('does NOT claim the fix failed when a DIFFERENT object recurred', () => {
    const text = validateStage(
      reopenedBy({ sameObject: false, objectName: 'nolimits-6679f7f545-w2xmp', reason: 'FailedToRetrieveImagePullSecret' }),
    ).text
    expect(text).not.toMatch(/did not hold/i)
    // and it must say whose failure it actually is, or the reader cannot act
    expect(text).toMatch(/nolimits-6679f7f545-w2xmp/)
    expect(text).toMatch(/separate failure/i)
  })

  it('DOES claim the fix failed when the SAME object recurred', () => {
    // The other direction matters just as much: softening this into "a separate
    // failure" for a genuine regression would hide a real one.
    const text = validateStage(reopenedBy({ sameObject: true, reason: 'ErrImagePull' })).text
    expect(text).toMatch(/did not hold/i)
    expect(text).toMatch(/same object/i)
  })

  it('claims neither when there is no record of what recurred', () => {
    // An incident reopened before the timeline existed has no honest answer, and
    // defaulting to either claim would be inventing one.
    const text = validateStage({
      id: 'inc_test', state: 'Reopened', analysis: null, findings: [], reopenedBy: null,
    } as unknown as IncidentDetail).text
    expect(text).not.toMatch(/did not hold/i)
    expect(text).not.toMatch(/separate failure/i)
    expect(text).toMatch(/unknown/i)
  })

  it('keeps the step blocked in every case — this is a wording fix, not a downgrade', () => {
    for (const inc of [
      reopenedBy({ sameObject: false, objectName: 'other-pod' }),
      reopenedBy({ sameObject: true }),
    ]) {
      expect(validateStage(inc).state).toBe('blocked')
    }
  })
})

describe('validateStage — an absence of findings is not a confirmation', () => {
  const resolvedAfterSuccess = incident(
    'Resolved',
    analysis({ plan: { execution: { outcome: 'succeeded' } } } as Partial<Analysis>),
    { resolutionKind: 'remediated' },
  )

  it('never claims the resolution was "confirmed"', () => {
    const text = validateStage(resolvedAfterSuccess).text
    // ValidationSweeper observes that no new findings arrived. That is not a
    // re-check that the symptom cleared, and the earlier wording said it was.
    expect(text).not.toMatch(/confirmed/i)
  })

  it('describes what actually happened — no new findings in the window', () => {
    expect(validateStage(resolvedAfterSuccess).text).toMatch(/no new findings/i)
  })

  it('agrees in strength with nextActionSummary about the same state', () => {
    // The pair is the point. Both read the same execution outcome, so both must
    // describe an absence; if either regains a positive claim, they diverge
    // again and this fails.
    const rail = validateStage(resolvedAfterSuccess).text
    const prose = nextActionSummary(resolvedAfterSuccess)
    expect(prose).toMatch(/not a positive re-check|absence of new findings/i)
    expect(rail).not.toMatch(/confirmed/i)
  })

  // Reported live: a merged pull request that held for the whole re-check
  // window still showed "Closed by hand — ARGUS applied no fix, so it
  // validated nothing" — because the PR channel never populates
  // plan.execution (nothing ran in-place), and the rail used to key off that
  // field alone. incident.resolutionKind is the backend's own unified answer
  // (internal/orchestrator/db.go's deriveResolutionKind: a succeeded
  // execution row OR a merged PR, either counts as "remediated") — reused
  // here instead of re-deriving the OR a second, incomplete way.
  it('credits a merged pull request the same as a succeeded in-place execution', () => {
    const resolvedAfterMergedPR = incident('Resolved', analysis({ plan: null }), { resolutionKind: 'remediated' })
    expect(validateStage(resolvedAfterMergedPR).text).toMatch(/no new findings/i)
    expect(validateStage(resolvedAfterMergedPR).text).not.toMatch(/closed by hand/i)
  })

  it('refuses to credit ARGUS for a self_healed close, and does not claim a human did it either', () => {
    // Pinned so the rewording above cannot collapse the two Resolved paths
    // into one claim — AND so the wording cannot drift back to "closed by
    // hand". resolutionKind is derived, not chosen: the stale-object sweeper's
    // automatic closures are stamped self_healed too, and measured on
    // 2026-09-09 every self_healed incident in the dev database had no human
    // actor at all. Claiming a person did it is as wrong as crediting ARGUS.
    const selfHealed = incident('Resolved', analysis({ plan: null }), { resolutionKind: 'self_healed' })
    const text = validateStage(selfHealed).text
    expect(text).toMatch(/no ARGUS fix linked|nothing to validate/i)
    expect(text).not.toMatch(/closed by hand/i)
  })
})

// BACKLOG.md C8 / BUGS.md 104: a mutating tunnel call whose own result was
// indeterminate (disconnect/timeout, not an explicit tool error) and whose
// follow-up verify against the live cluster could not confirm the change
// either way lands on outcome:'unknown' — never 'failed'. Pinned exactly
// like the Reopened-sentence pair above: the specific regression this
// guards is the rail and the prose both asserting "failed" for a case that
// was only ever "unconfirmed", the identical class of one-fact-two-claims
// bug the Reopened tests above exist to catch.
describe('validateStage/nextActionSummary — an indeterminate execution is never worded as a failure', () => {
  const unknownOutcome = incident(
    'ExecutionUnknown',
    analysis({ plan: { execution: { outcome: 'unknown', error: 'gateway: cluster disconnected while awaiting a tool result', executedAt: '2026-08-30T12:00:00Z' } } } as Partial<Analysis>),
  )

  it('never claims the execution failed', () => {
    expect(validateStage(unknownOutcome).text).not.toMatch(/\bfailed\b/i)
    expect(nextActionSummary(unknownOutcome)).not.toMatch(/\bfailed\b/i)
  })

  it('says the outcome is unknown/unconfirmed, not silently blank', () => {
    expect(validateStage(unknownOutcome).text).toMatch(/unknown|unconfirmed|could not.*confirm/i)
    expect(nextActionSummary(unknownOutcome)).toMatch(/unknown|unconfirmed|could not.*confirm/i)
  })

  it('tells the operator to check the cluster rather than assuming it needs redoing', () => {
    expect(nextActionSummary(unknownOutcome)).toMatch(/check the cluster/i)
  })

  it('still stops the rail (this stage did not cleanly complete), matching the confirmed-failure case', () => {
    expect(validateStage(unknownOutcome).state).toBe('blocked')
  })

  it('is worded differently from a confirmed failure at the same stage', () => {
    const confirmedFailure = incident(
      'Failed',
      analysis({ plan: { execution: { outcome: 'failed', error: 'admission webhook denied the request', executedAt: '2026-08-30T12:00:00Z' } } } as Partial<Analysis>),
    )
    expect(validateStage(confirmedFailure).text).toMatch(/\bfailed\b/i)
    expect(validateStage(unknownOutcome).text).not.toBe(validateStage(confirmedFailure).text)
  })
})

// BACKLOG.md D9 B3: a pull request that was approved, opened, and then
// closed unmerged used to keep reading "Pull request opened" here forever —
// executeStage's OpenPR branch keyed only on the approval verdict, never on
// incident.pullRequest.closedUnmergedAt (migration 000060) — a direct,
// on-page contradiction of RepositoryChangePanel's own "Closed without
// merging" a few inches below it.
describe('executeStage — a closed-unmerged pull request is not "opened" forever (BACKLOG.md D9 B3)', () => {
  it('does not claim "Pull request opened" once it closed unmerged', () => {
    const closedUnmerged = {
      id: 'inc_test',
      state: 'AwaitingApproval',
      analysis: analysis({
        plan: { actionType: 'OpenPR', approval: { verdict: 'approved', createdAt: '2026-08-25T09:00:00Z' } },
      } as Partial<Analysis>),
      pullRequest: { number: 7, closedUnmergedAt: '2026-08-26T09:00:00Z' },
      findings: [],
    } as unknown as IncidentDetail
    const result = executeStage(closedUnmerged)
    expect(result.text).not.toMatch(/opened/i)
    expect(result.text).toMatch(/closed/i)
    expect(result.state).toBe('blocked')
  })

  it('still says "Pull request opened" for one that is genuinely still open', () => {
    const stillOpen = {
      id: 'inc_test',
      state: 'AwaitingMerge',
      analysis: analysis({
        plan: { actionType: 'OpenPR', approval: { verdict: 'approved', createdAt: '2026-08-25T09:00:00Z' } },
      } as Partial<Analysis>),
      pullRequest: { number: 7 },
      findings: [],
    } as unknown as IncidentDetail
    expect(executeStage(stillOpen).text).toMatch(/pull request opened/i)
  })
})

// PROJECT.md B160: on inc_01m20nrjgf99axm8tpgrbb406j (state Resolved, route
// pullRequest, PR #103 merged, resolution_kind remediated), the Apply card
// read "Waiting for approval" directly above PullRequestRecord rendering
// that very same merged pull request — a direct, on-page contradiction.
//
// Root cause: executeStage's OpenPR branch recognised "done" only via
// plan.approval?.verdict === 'approved' (a remediation_approval_decisions
// row) or the transient incidentState === 'AwaitingMerge' — and
// remediation_approval_decisions held ZERO rows for every live PR-route
// incident on the dev stack this was diagnosed on, while MergeSweeper and
// ValidationSweeper had already moved the incident on through Validating
// and into Resolved. Neither of the two signals this branch checked was
// still true, so it fell all the way through to the generic
// pending/"Waiting for approval" default at the bottom of the function.
//
// These pin the fix — a merged pull request (incident.pullRequest.mergedAt,
// the durable record MergeSweeper itself writes) is now checked directly —
// and the guard that keeps it from over-claiming for a Resolved incident
// that got there some other way, or a fresh, undecided cycle sitting behind
// a stale pull request left over from an earlier one.
describe('executeStage — a merged pull request is not "waiting for approval" once the incident has moved on (PROJECT.md B160)', () => {
  const openPrNoDecisionRow = (state: string, extra: Partial<IncidentDetail> = {}): IncidentDetail =>
    incident(
      state,
      analysis({ plan: { actionType: 'OpenPR', gateOutcome: 'AutoApprove' } } as Partial<Analysis>),
      { pullRequest: { number: 103, mergedAt: '2026-09-08T14:17:04Z' }, ...extra },
    )

  it('reports done, not "waiting for approval", once Resolved with resolutionKind remediated — no approval decision row exists', () => {
    const resolved = openPrNoDecisionRow('Resolved', { resolutionKind: 'remediated' })
    const result = executeStage(resolved)
    expect(result.state).toBe('done')
    expect(result.text).not.toMatch(/waiting for approval/i)
    expect(result.text).toMatch(/merged/i)
  })

  it('reports done while still Validating — the merge already happened even though the re-check window has not finished', () => {
    const result = executeStage(openPrNoDecisionRow('Validating'))
    expect(result.state).toBe('done')
    expect(result.text).toMatch(/merged/i)
  })

  it('does NOT report done for a Resolved incident that closed some other way (resolutionKind self_healed)', () => {
    // Guards the fix from over-claiming: resolutionKind is the backend's own
    // answer to "did a merge actually close this", computed once at the
    // moment Resolved was entered. A Resolved incident that got there
    // without this pull request closing it must not borrow "done" from an
    // unrelated pull request record still sitting on the row.
    const resolved = openPrNoDecisionRow('Resolved', { resolutionKind: 'self_healed' })
    expect(executeStage(resolved).state).not.toBe('done')
  })

  it('still reports pending for a genuinely undecided plan, even with a merged pull request left over from an earlier cycle on the same incident', () => {
    // incident.pullRequest is one record per INCIDENT, not per plan — an
    // incident that reopened and is back at AwaitingApproval on a fresh,
    // undecided plan must not read "done" off a stale pull request from the
    // cycle before it.
    const freshCycle = incident(
      'AwaitingApproval',
      analysis({ plan: { actionType: 'OpenPR', gateOutcome: 'NeedsApproval' } } as Partial<Analysis>),
      { pullRequest: { number: 50, mergedAt: '2026-01-01T00:00:00Z' } },
    )
    const result = executeStage(freshCycle)
    expect(result.state).toBe('pending')
    expect(result.text).toMatch(/waiting for approval/i)
  })

  // The row's own "what done looks like": exercised for both routes, not
  // only the in-place one. The in-place branch already keys off a durable,
  // state-independent record (plan.execution.outcome, scoped to this exact
  // plan id) rather than incidentState, so it was already correct here —
  // this pins that fact so it cannot silently regress while the OpenPR
  // branch above is being brought up to the same standard.
  it('the in-place route already reports done the same way once Resolved — the baseline the PR route above now matches', () => {
    const resolved = incident(
      'Resolved',
      analysis({ plan: { actionType: 'ScaleDeployment', execution: { outcome: 'succeeded' } } } as Partial<Analysis>),
      { resolutionKind: 'remediated' },
    )
    const result = executeStage(resolved)
    expect(result.state).toBe('done')
    expect(result.text).toMatch(/applied/i)
  })
})

// BACKLOG.md D9 B5/B6: ExecutionUnknown/Failed with no execution row at all
// used to fall through to a generic message unrelated to what actually
// happened — "Waiting for approval" (as if nothing had run yet) for
// ExecutionUnknown, and "No remediation to execute yet" (as if nothing had
// happened at all) for Failed.
describe('executeStage — ExecutionUnknown/Failed with no execution row get an honest message (BACKLOG.md D9 B5/B6)', () => {
  it('ExecutionUnknown with no execution row says the outcome is unknown, not "waiting for approval"', () => {
    const noRecord = {
      id: 'inc_test',
      state: 'ExecutionUnknown',
      analysis: analysis({ plan: { actionType: 'ScaleDeployment' } } as Partial<Analysis>),
      findings: [],
    } as unknown as IncidentDetail
    const result = executeStage(noRecord)
    expect(result.text).not.toMatch(/waiting for approval/i)
    expect(result.text).toMatch(/unknown/i)
  })

  it('Failed with no execution row says something failed, not "no remediation to execute yet"', () => {
    const noRecord = {
      id: 'inc_test',
      state: 'Failed',
      analysis: analysis({ plan: { actionType: 'ScaleDeployment' } } as Partial<Analysis>),
      findings: [],
    } as unknown as IncidentDetail
    const result = executeStage(noRecord)
    expect(result.text).not.toMatch(/no remediation to execute yet/i)
    expect(result.text).toMatch(/failed/i)
  })
})

// BACKLOG.md D9 B8: gateReason used to print as a bare sentence with no word
// "gate" in it, at two of the three places it appears on the incident detail
// screen — a reader could not tell a GATE, specifically, had refused
// something.
describe('executeStage/approveStage — a blocked gate is framed as a gate, not a bare sentence (BACKLOG.md D9 B8)', () => {
  const blocked = {
    id: 'inc_test',
    state: 'AwaitingApproval',
    analysis: analysis({ plan: { actionType: 'ScaleDeployment', gateOutcome: 'Blocked', gateReason: 'Confidence below policy minimum' } } as Partial<Analysis>),
    findings: [],
  } as unknown as IncidentDetail

  it('executeStage names the gate', () => {
    expect(executeStage(blocked).text).toMatch(/gate/i)
    expect(executeStage(blocked).text).toMatch(/Confidence below policy minimum/)
  })

  it('approveStage names the gate', () => {
    expect(approveStage(blocked).text).toMatch(/gate/i)
    expect(approveStage(blocked).text).toMatch(/Confidence below policy minimum/)
  })

  it('nextActionSummary names the gate', () => {
    expect(nextActionSummary(blocked)).toMatch(/gate/i)
  })
})

// BACKLOG D8 Group A (A3, A4, A6, A7, A8, A9) — the rendered page, not just the
// pure lifecycle functions above. These pin the structural moves this pass
// made: the ownership caveat split out of stage 3 into stage 1
// (RecommendationChannels/ManagedByContext's own doc comments), stage 3
// leading with the two channels and a rendered diff before ownership
// provenance, and ApprovalDecisionCard mounted inline at stage 4 rather than
// only linked out to /approvals.

const mockGetIncident = vi.fn()
const mockAnalyzeIncident = vi.fn()
const mockGetApprovals = vi.fn()
const mockPreviewRepositoryChange = vi.fn()
const mockOpenRepositoryChange = vi.fn()
const mockGetIncidentTimeline = vi.fn()
const mockGetEvidence = vi.fn()
// Mocked (rather than left to `actual`, unlike the rest of this file's mocks)
// only for the paired-route panel tests below, which click the real
// ApprovalDecisionCard's Approve button — every other test in this file never
// clicks it, so it was never needed until now. Mirrors
// ApprovalDecisionCard.test.tsx's own mockApproveIncident/mockRejectIncident.
const mockApproveIncident = vi.fn()
const mockRejectIncident = vi.fn()
// LinkHelmReleaseForm's own reads/writes — a Helm release has no
// Application/Kustomization CR for ARGUS to read a repo from automatically,
// so this is the discover/confirm/decline trio (BACKLOG.md F30) that
// replaced the old hand-typed "which repo, which path" declaration.
const mockDiscoverRepositoryLink = vi.fn()
const mockConfirmRepositoryLink = vi.fn()
const mockDeclineRepositoryLink = vi.fn()

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    getIncident: (...args: unknown[]) => mockGetIncident(...args),
    getApprovals: (...args: unknown[]) => mockGetApprovals(...args),
    previewRepositoryChange: (...args: unknown[]) => mockPreviewRepositoryChange(...args),
    openRepositoryChange: (...args: unknown[]) => mockOpenRepositoryChange(...args),
    getIncidentTimeline: (...args: unknown[]) => mockGetIncidentTimeline(...args),
    getEvidence: (...args: unknown[]) => mockGetEvidence(...args),
    approveIncident: (...args: unknown[]) => mockApproveIncident(...args),
    rejectIncident: (...args: unknown[]) => mockRejectIncident(...args),
    discoverRepositoryLink: (...args: unknown[]) => mockDiscoverRepositoryLink(...args),
    confirmRepositoryLink: (...args: unknown[]) => mockConfirmRepositoryLink(...args),
    declineRepositoryLink: (...args: unknown[]) => mockDeclineRepositoryLink(...args),
    analyzeIncident: (...args: unknown[]) => mockAnalyzeIncident(...args),
    // Never invoked in these tests (no button is clicked), but every mutation
    // hook still needs a real function reference to call useMutation with.
    resolveIncident: vi.fn(),
    dismissIncident: vi.fn(),
    tolerateIncident: vi.fn(),
  }
})

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ accessToken: 'test-token' }),
}))

const grantedCapabilities = new Set<string>()
vi.mock('../auth/useCapabilities', () => ({
  useHasCapability: (capability: string) => grantedCapabilities.has(capability),
}))

import { IncidentDetailPage } from './IncidentDetailPage'

// Helm has no Application/Kustomization CR the way Argo CD/Flux do, so a
// Helm-managed object with no configured object mapping has ownership but no
// `repo` at all — the exact state LinkHelmReleaseForm exists for.
const helmOwnershipNoRepo: ObjectOwnership = {
  managedBy: 'helm',
  sourceKind: 'Release',
  sourceName: 'shop-apps-helm',
  sourceNamespace: 'shop',
  objectGvk: 'apps/v1/Deployment',
  objectNamespace: 'shop',
  objectName: 'shop-apps-helm-api',
}

const argocdOwnership: ObjectOwnership = {
  managedBy: 'argocd',
  sourceKind: 'Application',
  sourceName: 'payments',
  sourceNamespace: 'argocd',
  objectGvk: 'apps/v1/Deployment',
  objectNamespace: 'payments',
  objectName: 'payments-api',
  repo: {
    url: 'https://github.com/example/payments-manifests',
    path: 'apps/payments',
    revision: 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678',
    pinned: true,
  },
}

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
  createdAt: '2026-08-25T09:00:00Z',
}

// The paired route's second recommendation (BACKLOG D8, F17's
// `pullRequest+inPlace` route) — an OpenPR plan proposed alongside scalePlan
// for the SAME underlying fix, linked server-side via
// sibling_of_recommendation_id and carried on the wire as
// analysis.pairedPlan (internal/api/analyze.go).
const openPrPlan: RemediationPlan = {
  id: 'plan_openpr',
  actionType: 'OpenPR',
  targetGvk: 'apps/v1/Deployment',
  targetNamespace: 'payments',
  targetName: 'payments-api',
  // Whole files, the only grammar a repository change has since 2026-08-28 —
  // internal/remediation.OpenPRParams' `repository` + `files: [{path, content}]`.
  params: {
    repository: 'example/payments-manifests',
    files: [
      {
        path: 'apps/payments/deployment.yaml',
        content: 'apiVersion: apps/v1\nkind: Deployment\nspec:\n  replicas: 3\n',
      },
    ],
  },
  reversible: true,
  riskLevel: 'low',
  effectiveRiskLevel: 'low',
  summary: 'Open a pull request setting payments-api replicas to 3',
  gateOutcome: 'NeedsApproval',
  gateReason: 'Confidence below the auto-approve threshold',
  createdAt: '2026-08-25T09:00:00Z',
}

function detailIncident(over: Partial<IncidentDetail> = {}): IncidentDetail {
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
    objectGvk: 'apps/v1/Deployment',
    objectNamespace: 'payments',
    objectName: 'payments-api',
    analysis: {
      id: 'an_1',
      status: 'complete',
      causalChain: [],
      ruledOut: [],
      rootCause: { statement: 'OOMKilled repeatedly' },
      confidence: 0.8,
      partialReason: null,
      suggestedNextSteps: null,
      model: 'test-model',
      iterations: 1,
      createdAt: '2026-08-25T09:00:00Z',
      tokensBilledIn: 100,
      tokensCacheRead: 0,
      tokensOut: 50,
      costUsd: 0,
      costBasis: 'metered',
      incidentState: 'AwaitingApproval',
      stateReason: '',
      plan: scalePlan,
    },
    findings: [],
    findingGroups: [],
    ownership: argocdOwnership,
    evidence: null,
    unattendedBatch: null,
    priorIncidents: [],
    analysisStartedAt: null,
    analysisBackend: null,
    analysisModel: null,
    analysisError: null,
    ...over,
  } as IncidentDetail
}

function approvalItemFor(incidentId: string, plan: RemediationPlan): ApprovalQueueItem {
  return {
    incidentId,
    clusterId: 'cl_1',
    clusterDisplayName: 'prod-eu',
    fingerprint: 'fp_1',
    severity: 'high',
    firstSeen: '2026-08-25T09:00:00Z',
    lastSeen: '2026-08-25T09:30:00Z',
    occurrenceCount: 4,
    plan,
    confidence: 0.8,
    rootCauseStatement: 'OOMKilled repeatedly',
    causalChain: [],
    ruledOut: [],
    alreadyApproved: false,
  }
}

function renderPage(incidentId = 'inc_1') {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/incidents/${incidentId}`]}>
        <Routes>
          <Route path="/incidents/:id" element={<IncidentDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

// "What happened" lives in the side rail's History card since the lifecycle
// redesign (2026-10-12). Opens it and returns its own panel, so assertions
// cannot match the history milestones above it.
async function openWhatHappened(): Promise<HTMLElement> {
  const rail = await screen.findByRole('complementary', { name: /Facts and history/i })
  const button = within(rail).getByRole('button', { name: /^What happened$/i })
  fireEvent.click(button)
  return document.getElementById(button.getAttribute('aria-controls')!) as HTMLElement
}

function factsRail(): HTMLElement {
  return screen.getByRole('complementary', { name: /Facts and history/i })
}

beforeEach(() => {
  mockGetIncident.mockReset()
  mockAnalyzeIncident.mockReset()
  mockGetApprovals.mockReset()
  mockPreviewRepositoryChange.mockReset()
  mockOpenRepositoryChange.mockReset()
  mockGetIncidentTimeline.mockReset().mockResolvedValue({ events: [] })
  mockGetEvidence.mockReset()
  mockApproveIncident.mockReset()
  mockRejectIncident.mockReset()
  mockDiscoverRepositoryLink.mockReset()
  mockConfirmRepositoryLink.mockReset()
  mockDeclineRepositoryLink.mockReset()
  mockDiscoverRepositoryLink.mockResolvedValue({
    status: 'none',
    candidates: [],
    releaseName: '',
    namespace: '',
    otherClusters: [],
  })
  grantedCapabilities.clear()
  grantedCapabilities.add(CAP_REMEDIATION_APPROVE)
})

// --- The summary strip names the owning workload (B174) ---
//
// Modelled on `inc_01m2wxrehvyhh9b44tzgaa93qs`, still in the development
// database: an OOMKill whose fix targeted the Deployment, whose rollout then
// deleted the Pod, and which stayed keyed on that Pod. Presentation only —
// `object_key` and the fingerprint are untouched, and no API field was added
// (`workloadKey` was already on the wire).
describe('IncidentDetailPage — the owning workload heads the summary strip (B174)', () => {
  const OOM_ON_A_POD = detailIncident({
    state: 'Resolved',
    resolutionKind: 'remediated',
    objectGvk: 'v1/Pod',
    objectNamespace: 'argus-e2e-rke2',
    objectName: 'checkout-oom-6d99b45595-fw7v8',
    workloadKey: 'apps/v1/Deployment|argus-e2e-rke2|checkout-oom',
    openingReason: 'OOMKilled',
  })

  it('heads the page with the Deployment, and keeps the Pod as a meta fact', async () => {
    mockGetIncident.mockResolvedValue(OOM_ON_A_POD)
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    const { container } = renderPage()
    await screen.findByText('checkout-oom')

    const strip = container.querySelector('.incident-summary-strip')!
    expect(strip.querySelector('.identity-block-name')?.textContent).toBe('checkout-oom')
    expect(strip.querySelector('.identity-block-kind')?.textContent).toBe('Deployment · argus-e2e-rke2')
    // The Pod is still on the page — it is the evidence the finding named —
    // but as supporting detail beside the cluster, not as the heading.
    const meta = strip.querySelector('.incident-summary-meta')!
    expect(meta.textContent).toContain('Observed on')
    expect(meta.textContent).toContain('Pod checkout-oom-6d99b45595-fw7v8')
  })

  // The wording must not vary with state. ARGUS never re-reads the Pod, so
  // neither "it is gone" nor "it is currently failing" is a fact it holds.
  it('words the Pod identically whether the incident is open or closed', async () => {
    mockGetIncident.mockResolvedValue(OOM_ON_A_POD)
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    const closed = renderPage()
    await screen.findByText('checkout-oom')
    const closedText = closed.container.querySelector('.incident-summary-meta')!.textContent
    const closedTitle = within(closed.container.querySelector('.incident-summary-meta') as HTMLElement)
      .getByText('Pod checkout-oom-6d99b45595-fw7v8')
      .getAttribute('title')
    closed.unmount()

    mockGetIncident.mockResolvedValue(detailIncident({
      state: 'Detected',
      objectGvk: 'v1/Pod',
      objectNamespace: 'argus-e2e-rke2',
      objectName: 'checkout-oom-6d99b45595-fw7v8',
      workloadKey: 'apps/v1/Deployment|argus-e2e-rke2|checkout-oom',
      openingReason: 'OOMKilled',
      analysis: null,
    }))
    const open = renderPage()
    await screen.findByText('checkout-oom')
    const openMeta = open.container.querySelector('.incident-summary-meta') as HTMLElement
    expect(openMeta.textContent).toContain('Observed on')
    expect(within(openMeta).getByText('Pod checkout-oom-6d99b45595-fw7v8').getAttribute('title')).toBe(closedTitle)
    expect(closedText).toContain('Observed on')
    // Past tense, hedged, in both: the caveat is the point.
    expect(closedTitle).toMatch(/may be gone/)
  })

  it('leaves an incident with no owner exactly as it was — no invented owner, no dash', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({
      objectGvk: 'cert-manager.io/v1/Certificate',
      objectNamespace: 'cattle-system',
      objectName: 'rancher-ingress',
      openingReason: 'CertificateExpiryImminent',
      analysis: null,
    }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    const { container } = renderPage()
    await screen.findByText('rancher-ingress')

    const strip = container.querySelector('.incident-summary-strip')!
    expect(strip.querySelector('.identity-block-name')?.textContent).toBe('rancher-ingress')
    expect(strip.querySelector('.identity-block-kind')?.textContent).toBe('Certificate · cattle-system')
    expect(strip.querySelector('.incident-summary-meta')!.textContent).not.toContain('Observed on')
  })
})

describe('IncidentDetailPage — loading skeleton (BACKLOG D8 A6)', () => {
  it('renders a skeleton shaped like the loaded page: spine, argument and rail', async () => {
    // Never resolves within the test, so the page stays in its loading state.
    mockGetIncident.mockReturnValue(new Promise(() => {}))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    const { container } = renderPage()
    // Four phases and the outcome, then the argument column and the rail.
    expect(container.querySelectorAll('.lc-spine-skeleton > .lc-phase')).toHaveLength(5)
    expect(container.querySelectorAll('.lc-body .lc-main > .card').length).toBeGreaterThan(0)
    expect(container.querySelectorAll('.lc-body .lc-rail > .card').length).toBeGreaterThan(0)
  })
})

describe('IncidentDetailPage — ownership context moved to stage 1 (BACKLOG D8 A3)', () => {
  it('states which controller manages the object in the Detection stage, not bundled into Recommendation', async () => {
    mockGetIncident.mockResolvedValue(detailIncident())
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const detectionStage = await screen.findByRole('region', { name: /^What broke$/i })
    expect(within(detectionStage).getByText(/Managed by Argo CD/i)).toBeTruthy()

    // The write action belongs at stage 3, not stage 1 — the whole point of
    // A3 is that these two facts no longer arrive in the same box.
    expect(within(detectionStage).queryByText(/Propose this fix as a pull request/i)).toBeNull()
  })

  // PROJECT.md D13: a chip, not a bordered callout that restates the object
  // the finding line directly above already named.
  it('names only the owner, not the object again, and does not render as a callout', async () => {
    mockGetIncident.mockResolvedValue(detailIncident())
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const detectionStage = await screen.findByRole('region', { name: /^What broke$/i })
    const owner = within(detectionStage).getByText(/Managed by Argo CD/i).closest('p')!
    expect(owner.className).not.toMatch(/detail-callout/)
    // The gvk and namespace/name are on the finding line; saying them twice in
    // adjacent lines is what made this block read as long.
    expect(owner.textContent).not.toMatch(/apps\/v1\/Deployment/)
    expect(owner.textContent).not.toMatch(/payments-api/)
  })
})

// PROJECT.md item 14 — a swept detection and a forwarded Kubernetes event
// used to render identically, so the one capability an operator's existing
// tooling does NOT have ("ARGUS noticed this without any event being emitted")
// was invisible on the screen that is supposed to argue for it.
//
// Three things these tests pin, in order of how badly each would fail:
//
//   1. The distinction is made at all, in words as well as a badge colour.
//   2. It is attached to a FINDING, never asserted of the incident. Measured
//      against the live database, 14 of 139 incidents carry findings from more
//      than one detector — a single incident-level badge would be false for
//      one incident in ten, which is worse than the silence it replaced.
//   3. An unrecognised detector id gets NO claim rather than a defaulted one.
//      `smoketest-detector` and `test-detector` are real ids in real
//      databases; bucketing either as "found where kubectl could not" would
//      invent a fact about the product's headline capability.
function findingFixture(over: Partial<IncidentDetail['findings'][number]> = {}) {
  return {
    id: 'fnd_1',
    detectorId: 'k8s-sweep',
    gvk: 'apps/v1/Deployment',
    namespace: 'payments',
    objectName: 'payments-api',
    reason: 'DeploymentReplicasUnavailable',
    message: '1 of 3 replicas unavailable for 12m',
    severity: 'high',
    occurrenceCount: 4,
    occurredAt: '2026-08-25T09:30:00Z',
    ...over,
  } as IncidentDetail['findings'][number]
}

describe('IncidentDetailPage — swept vs event-backed detection (PROJECT.md item 14)', () => {
  it('says a sweep finding was ARGUS’s own check, not something the event stream announced', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({ findings: [findingFixture()] }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const detectionStage = await screen.findByRole('region', { name: /^What broke$/i })
    expect(within(detectionStage).getByText('ARGUS check')).toBeTruthy()
    // The badge colour is never the only carrier — the sentence has to say it.
    expect(within(detectionStage).getByText(/periodic sweep of object state/i)).toBeTruthy()
    // And it must not overstate: the agent's own code says these conditions do
    // not RELIABLY announce themselves, not that no event can ever exist.
    expect(detectionStage.textContent).not.toMatch(/never|no event exists|kubectl cannot/i)
  })

  it('says a forwarded Warning event is one the operator’s own tooling can see too', async () => {
    mockGetIncident.mockResolvedValue(
      detailIncident({ findings: [findingFixture({ detectorId: 'k8s-warning-events', reason: 'BackOff' })] }),
    )
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const detectionStage = await screen.findByRole('region', { name: /^What broke$/i })
    expect(within(detectionStage).getByText('Kubernetes event')).toBeTruthy()
    expect(within(detectionStage).queryByText('ARGUS check')).toBeNull()
    expect(within(detectionStage).getByText(/kubectl get events/i)).toBeTruthy()
  })

  it('does NOT claim a single-source incident is single-source — it makes no absence claim at all', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({ findings: [findingFixture()] }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const detectionStage = await screen.findByRole('region', { name: /^What broke$/i })
    await within(detectionStage).findByText('ARGUS check')
    // `findings` is a bounded slice (newest few per reason), so "every finding
    // here came from the sweep" is not a claim the payload can support.
    expect(detectionStage.textContent).not.toMatch(/also carries findings from the other kind/i)
    expect(detectionStage.textContent).not.toMatch(/all findings|every finding|only from/i)
  })

  it('says so when one incident correlates findings from BOTH kinds, rather than picking one', async () => {
    mockGetIncident.mockResolvedValue(
      detailIncident({
        findings: [
          // Newest first, as the hub orders them — this is the one the card prints.
          findingFixture({ id: 'fnd_2', detectorId: 'k8s-sweep', occurredAt: '2026-08-25T09:30:00Z' }),
          findingFixture({
            id: 'fnd_1',
            detectorId: 'k8s-warning-events',
            reason: 'BackOff',
            occurredAt: '2026-08-25T09:10:00Z',
          }),
        ],
      }),
    )
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const detectionStage = await screen.findByRole('region', { name: /^What broke$/i })
    expect(within(detectionStage).getByText('ARGUS check')).toBeTruthy()
    expect(within(detectionStage).getByText(/also carries findings from the other kind/i)).toBeTruthy()
  })

  it('makes no claim at all for a detector id this build has never heard of', async () => {
    mockGetIncident.mockResolvedValue(
      detailIncident({ findings: [findingFixture({ detectorId: 'smoketest-detector' })] }),
    )
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const detectionStage = await screen.findByRole('region', { name: /^What broke$/i })
    // The finding itself still renders; only the provenance claim is withheld.
    expect(within(detectionStage).getByText(/1 of 3 replicas unavailable/i)).toBeTruthy()
    expect(within(detectionStage).queryByText('ARGUS check')).toBeNull()
    expect(within(detectionStage).queryByText('Kubernetes event')).toBeNull()
  })

  it('names the detector in each event of the findings history instead of printing its wire id', async () => {
    mockGetIncidentTimeline.mockResolvedValue({ events: [] })
    mockGetIncident.mockResolvedValue(
      detailIncident({
        findings: [findingFixture()],
        findingGroups: [
          {
            reason: 'DeploymentReplicasUnavailable',
            count: 1,
            firstSeen: '2026-08-25T09:30:00Z',
            lastSeen: '2026-08-25T09:30:00Z',
          },
        ],
      }),
    )
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    await screen.findByRole('region', { name: /^What broke$/i })
    const detectionStage = await openWhatHappened()

    expect(await within(detectionStage).findByText(/via ARGUS sweep/i)).toBeTruthy()
    // "Never render a raw API identifier as a user-facing value."
    expect(within(detectionStage).queryByText(/detector k8s-sweep/i)).toBeNull()
  })
})

// PROJECT.md T7 — "a recurrence reuses what was learned rather than
// starting from zero." The owner's decided mechanism is LINK: a recurrence
// opens a brand-new incident carrying priorIncidents, computed by the hub
// via a join on object_key (internal/api/incidents.go's
// priorIncidentLinksFor) — this only checks that the page actually renders
// what the hub sends, not that the join itself is correct (that is
// internal/orchestrator/recurrence_db_test.go and
// internal/api/incidents_db_test.go's job).
describe('IncidentDetailPage — prior occurrences on this object (PROJECT.md T7)', () => {
  it('renders nothing when there are no prior incidents on this object', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({ priorIncidents: [] }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    await screen.findByRole('region', { name: /^What broke$/i })
    // Deliberately absent, not an empty state — a first occurrence (the
    // overwhelming majority of incidents) must not carry a permanently-empty
    // disclosure on every incident page.
    expect(screen.queryByText(/Prior occurrences/i)).toBeNull()
  })

  it('surfaces what was learned, and a rejection reason, from a prior closed incident on the same object', async () => {
    mockGetIncident.mockResolvedValue(
      detailIncident({
        priorIncidents: [
          {
            incidentId: 'inc_prior_1',
            state: 'Dismissed',
            firstSeen: '2026-08-01T09:00:00Z',
            resolvedAt: '2026-08-01T09:30:00Z',
            rootCause: 'OOMKilled — memory limit set too low for the JVM heap',
            confidence: 0.7,
            rejectedPlan: {
              actionType: 'ScaleDeployment',
              reason: 'scaling replicas does not fix a per-pod OOM',
              rejectedAt: '2026-08-01T09:15:00Z',
            },
          },
        ],
      }),
    )
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    await screen.findByRole('region', { name: /^What broke$/i })
    const detectionStage = factsRail()
    const toggle = within(detectionStage).getByRole('button', { name: /Prior occurrences \(1\)/i })
    fireEvent.click(toggle)

    // "What was learned" — the prior incident's own analysis conclusion,
    // not re-derived, not re-investigated.
    expect(within(detectionStage).getByText(/OOMKilled — memory limit set too low/i)).toBeTruthy()
    // The rejection reason, read back rather than lost — the specific gap
    // PROJECT.md T7 names ("0 rejection reasons have ever been read back").
    expect(within(detectionStage).getByText(/ScaleDeployment plan was refused/i)).toBeTruthy()
    expect(within(detectionStage).getByText(/scaling replicas does not fix a per-pod OOM/i)).toBeTruthy()
    // The state badge names the word, never colour alone (design system
    // non-negotiable): "Dismissed" must be in the text.
    expect(within(detectionStage).getByText(/Dismissed/i)).toBeTruthy()
  })

  it('says a prior incident closed with no analysis honestly, rather than inventing a root cause', async () => {
    mockGetIncident.mockResolvedValue(
      detailIncident({
        priorIncidents: [
          { incidentId: 'inc_prior_2', state: 'Expired', firstSeen: '2026-07-01T09:00:00Z' },
        ],
      }),
    )
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    await screen.findByRole('region', { name: /^What broke$/i })
    const detectionStage = factsRail()
    fireEvent.click(within(detectionStage).getByRole('button', { name: /Prior occurrences \(1\)/i }))

    expect(within(detectionStage).getByText(/Closed with no analysis recorded/i)).toBeTruthy()
    expect(within(detectionStage).getByText(/Expired/i)).toBeTruthy()
  })
})

describe('IncidentDetailPage — stage 3 leads with the channel choice and a rendered diff (BACKLOG D8 A4/A7)', () => {
  it('shows both channels, the in-place diff, and the pull-request action, with ownership provenance last', async () => {
    mockGetIncident.mockResolvedValue(detailIncident())
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const recommendationStage = await screen.findByRole('region', { name: /^Fix$/i })
    const html = recommendationStage.innerHTML

    // Both routes offered as explicit options (incident lifecycle redesign:
    // one option card per route, the route itself stated once above them).
    expect(within(recommendationStage).getByRole('region', { name: 'ARGUS runs it' })).toBeTruthy()
    expect(within(recommendationStage).getByRole('region', { name: 'Pull request' })).toBeTruthy()

    // A4: plan.params rendered as a real diff, not left invisible.
    expect(within(recommendationStage).getByText(/spec\.replicas: 3/)).toBeTruthy()

    // A7: the pull-request action (RepositoryChangePanel) sits under the
    // choice, and ownership provenance (the repository URL) comes after it —
    // not first, and not repeated from stage 1.
    const actionIndex = html.indexOf('Propose this fix as a pull request')
    const provenanceIndex = html.indexOf('payments-manifests')
    expect(actionIndex).toBeGreaterThan(-1)
    expect(provenanceIndex).toBeGreaterThan(actionIndex)

    // Not fabricated a second "Managed by" claim on this stage — that lives
    // in stage 1 now.
    expect(within(recommendationStage).queryByText(/^Managed by Argo CD/)).toBeNull()
  })

  it('still renders the in-place diff for an unmanaged object with no GitOps ownership at all', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({ ownership: null }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const recommendationStage = await screen.findByRole('region', { name: /^Fix$/i })
    expect(within(recommendationStage).getByText(/spec\.replicas: 3/)).toBeTruthy()
    expect(within(recommendationStage).getByText(/no GitOps controller reports owning this object/i)).toBeTruthy()
  })

  // PROJECT.md D13. The three below pin the shortening of this card, because
  // the DOM alone cannot: a closed <details> keeps its children, so every
  // getByText above passes whether the provenance is shown or hidden.
  it('collapses the repository provenance, and keeps every action outside the collapse', async () => {
    mockGetIncident.mockResolvedValue(detailIncident())
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const recommendationStage = await screen.findByRole('region', { name: /^Fix$/i })
    const disclosure = within(recommendationStage)
      .getByText(/Why this route/i)
      .closest('details')
    expect(disclosure).toBeTruthy()
    expect(disclosure!.hasAttribute('open')).toBe(false)

    // Provenance is inside it; the pull-request action and both route chips
    // are not. Hiding a control behind a disclosure would be a worse defect
    // than the length this collapse fixes.
    expect(disclosure!.textContent).toMatch(/payments-manifests/)
    expect(disclosure!.textContent).not.toMatch(/Propose this fix as a pull request/)
    expect(disclosure!.textContent).not.toMatch(/Change the source/)
    expect(disclosure!.textContent).not.toMatch(/Change the cluster/)
  })

  it('states the revert consequence once on the card, not once per block', async () => {
    mockGetIncident.mockResolvedValue(detailIncident())
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const recommendationStage = await screen.findByRole('region', { name: /^Fix$/i })
    // The in-place chip owns this sentence — it is the consequence of the
    // action it sits beside. The provenance trailer used to repeat it as
    // prose a few lines below, on the same card.
    expect(within(recommendationStage).getAllByText(/reverts it on the next reconcile/i)).toHaveLength(1)
    expect(within(recommendationStage).queryByText(/reconciles that object back to what Git says/i)).toBeNull()
    // What survives in the trailer is the half nothing else says: where the
    // durable version of the change belongs.
    expect(within(recommendationStage).getByText(/Make the same change in the manifest/i)).toBeTruthy()
  })

  it('warns that a Helm upgrade undoes a manual fix even when no repository is linked yet', async () => {
    // The caveat used to key off ownership.repo, so a Helm release with no
    // object mapping — ownership known, repo null — fell through to the
    // unmanaged wording and told the operator nothing about the upgrade that
    // will wipe what they just ran.
    const base = detailIncident({ ownership: helmOwnershipNoRepo })
    mockGetIncident.mockResolvedValue({
      ...base,
      analysis: { ...base.analysis!, suggestedNextSteps: ['kubectl -n shop scale deploy/shop-apps-helm-api --replicas=3'] },
    })
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const recommendationStage = await screen.findByRole('region', { name: /^Fix$/i })
    expect(within(recommendationStage).getByText(/next helm upgrade rewrites that object/i)).toBeTruthy()
    expect(within(recommendationStage).queryByText(/check it against your own knowledge of this cluster/i)).toBeNull()
  })
})

describe('IncidentDetailPage — approval inline at stage 4 (BACKLOG D8 A8)', () => {
  it('mounts the real ApprovalDecisionCard when the queue has this incident', async () => {
    mockGetIncident.mockResolvedValue(detailIncident())
    mockGetApprovals.mockResolvedValue({ approvals: [approvalItemFor('inc_1', scalePlan)] })
    renderPage()

    const approveStage = await screen.findByRole('region', { name: /^Fix$/i })
    // ApprovalDecisionCard's own Approve/Reject controls, not just a link out.
    // findByRole (not getByRole): the card only appears once GET /approvals
    // resolves, a render after the incident's own region first appears.
    expect(await within(approveStage).findByRole('button', { name: /^Approve$/i })).toBeTruthy()
    expect(within(approveStage).getByRole('button', { name: /^Reject$/i })).toBeTruthy()
    expect(within(approveStage).queryByText(/Review it in the approval queue/i)).toBeNull()
  })

  it('falls back to the queue link when nothing matches (already decided, or race with the queue)', async () => {
    mockGetIncident.mockResolvedValue(detailIncident())
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const approveStage = await screen.findByRole('region', { name: /^Fix$/i })
    expect(await within(approveStage).findByRole('link', { name: /Review it in the approval queue/i })).toBeTruthy()
    expect(within(approveStage).queryByRole('button', { name: /^Approve$/i })).toBeNull()
  })

  it('never calls GET /approvals for a viewer without remediation:approve', async () => {
    grantedCapabilities.clear()
    mockGetIncident.mockResolvedValue(detailIncident())
    renderPage()

    await screen.findByRole('region', { name: /^Fix$/i })
    expect(mockGetApprovals).not.toHaveBeenCalled()
  })

  // BACKLOG.md D9 U3: this used to render NEITHER a control nor a statement
  // that one exists — the query above is skipped, approvalItem stays
  // undefined, and the page fell straight to the plain status line. Now a
  // disabled Approve/Reject pair renders with the capability named in
  // visible text, matching lld/11 §6's disabled-not-hidden rule for the
  // highest-stakes control on the screen.
  it('renders a disabled Approve/Reject pair with the capability named, rather than nothing, for a viewer without remediation:approve', async () => {
    grantedCapabilities.clear()
    mockGetIncident.mockResolvedValue(detailIncident())
    renderPage()

    const approveStage = await screen.findByRole('region', { name: /^Fix$/i })
    const approveButton = await within(approveStage).findByRole('button', { name: /^Approve$/i })
    const rejectButton = within(approveStage).getByRole('button', { name: /^Reject$/i })
    expect((approveButton as HTMLButtonElement).disabled).toBe(true)
    expect((rejectButton as HTMLButtonElement).disabled).toBe(true)
    // Visible, not just a `title` — unreachable by keyboard/touch otherwise.
    const argusOption = within(approveStage).getByRole('region', { name: 'ARGUS runs it' })
    expect(within(argusOption).getAllByText(new RegExp(CAP_REMEDIATION_APPROVE)).length).toBeGreaterThan(0)
    expect(mockGetApprovals).not.toHaveBeenCalled()
  })
})

// BACKLOG D8's paired-route panel — F17 landed the backend half
// (incidents.route/route_reason/applier, remediation_recommendations
// .sibling_of_recommendation_id) on 2026-08-25, but nothing between there and
// the wire ever surfaced the second plan (internal/api/analyze.go's
// PairedPlan closes that gap in this same task), so an operator previously
// had no way to see BOTH halves of a paired route at once, let alone
// recognise them as one fix offered two ways. `analysis.pairedPlan` is what
// tells this page to render the linked panel instead of a single plain
// ApprovalDecisionCard.
function pairedDetailIncident(over: Partial<IncidentDetail> = {}): IncidentDetail {
  const base = detailIncident(over)
  return { ...base, analysis: base.analysis ? { ...base.analysis, pairedPlan: openPrPlan } : base.analysis }
}

describe('IncidentDetailPage — paired-route approval panel (BACKLOG D8, F17)', () => {
  it('renders both routes linked, not two disconnected cards', async () => {
    mockGetIncident.mockResolvedValue(pairedDetailIncident())
    mockGetApprovals.mockResolvedValue({ approvals: [approvalItemFor('inc_1', scalePlan)] })
    renderPage()

    const approveStage = await screen.findByRole('region', { name: /^Fix$/i })
    // A shared frame naming this as one fix offered two ways, not two
    // unrelated cards that happen to sit near each other.
    expect(within(approveStage).getByText(/ARGUS proposed this fix on both routes at once/i)).toBeTruthy()
    // The in-place route: the real, live ApprovalDecisionCard (embedded) —
    // its own Approve/Reject controls are present and functional.
    expect(within(approveStage).getByRole('region', { name: 'ARGUS runs it' })).toBeTruthy()
    expect(await within(approveStage).findByRole('button', { name: /^Approve$/i })).toBeTruthy()
    expect(within(approveStage).getByRole('button', { name: /^Reject$/i })).toBeTruthy()
    // The pull request route: labelled, linked, and showing its OWN proposed
    // change — not the in-place plan's summary repeated. Scoped to the
    // pull-request <li> itself.
    //
    // What it shows is the FILE it would change, not a field and a value: an
    // OpenPR plan carries whole files, and this payload does not carry the file
    // as it is at the synced commit, so there is no diff that could honestly be
    // drawn here. Naming the file and pointing at the panel that computes the
    // real diff is the whole of what is true at this point — which is why the
    // in-place half still gets a `.diff-pair` and this half does not.
    const prRoute = within(approveStage).getByRole('region', { name: 'Pull request' })
    expect(prRoute).toBeTruthy()
    expect(within(prRoute!).getByText(openPrPlan.summary)).toBeTruthy()
    expect(within(prRoute!).getByText(/Changes apps\/payments\/deployment\.yaml in example\/payments-manifests/i)).toBeTruthy()
    // And it invents nothing: no before/after pair, because no before is known.
    expect(prRoute!.querySelector('.diff-pair')).toBeNull()
    // Honest about what today's single decision actually covers — never a
    // second live Approve button that would either silently decide the wrong
    // plan or 409 on click.
    expect(within(approveStage).getByText(/deciding this pull request independently isn't available from this screen yet/i)).toBeTruthy()
    expect(within(approveStage).getAllByRole('button', { name: /^Approve$/i })).toHaveLength(1)
  })

  it('approving the in-place route does not orphan the pull request route\'s own UI state', async () => {
    mockGetIncident.mockResolvedValue(pairedDetailIncident())
    mockGetApprovals.mockResolvedValue({ approvals: [approvalItemFor('inc_1', scalePlan)] })
    mockApproveIncident.mockResolvedValue({
      incidentId: 'inc_1',
      planId: scalePlan.id,
      verdict: 'approved',
      incidentState: 'Executing',
      message: 'Approved and executing.',
    })
    renderPage()

    const approveStage = await screen.findByRole('region', { name: /^Fix$/i })
    const approveButton = await within(approveStage).findByRole('button', { name: /^Approve$/i })
    fireEvent.click(approveButton)

    // The in-place card's own success note appears...
    await within(approveStage).findByText(/Approved and executing\./i)
    expect(mockApproveIncident).toHaveBeenCalledTimes(1)
    // ...and the pull request route's information is still there, unchanged
    // and unremoved — approving the in-place plan is a fact about ONE plan,
    // not an event that should make the other plan's own content disappear.
    const prRoute = within(approveStage).getByRole('region', { name: 'Pull request' })
    expect(within(prRoute).getByText(openPrPlan.summary)).toBeTruthy()
    expect(within(prRoute).getByText(/deciding this pull request independently isn't available from this screen yet/i)).toBeTruthy()
  })

  it('the single-plan (non-paired) case still renders exactly as before — no regression', async () => {
    // The exact fixture the pre-existing "mounts the real ApprovalDecisionCard"
    // test above uses: no analysis.pairedPlan at all.
    mockGetIncident.mockResolvedValue(detailIncident())
    mockGetApprovals.mockResolvedValue({ approvals: [approvalItemFor('inc_1', scalePlan)] })
    renderPage()

    const approveStage = await screen.findByRole('region', { name: /^Fix$/i })
    expect(await within(approveStage).findByRole('button', { name: /^Approve$/i })).toBeTruthy()
    expect(within(approveStage).getByRole('button', { name: /^Reject$/i })).toBeTruthy()
    // None of the paired-panel framing leaks into the ordinary single-plan case.
    expect(within(approveStage).queryByText(/ARGUS proposed this fix on both routes at once/i)).toBeNull()
    expect(within(approveStage).queryByText(/In-place — decide below/i)).toBeNull()
    expect(within(approveStage).queryByText(/Pull request — proposed alongside/i)).toBeNull()
    expect(within(approveStage).queryByText(/Not decidable from here yet/i)).toBeNull()
  })
})

describe('IncidentDetailPage — unattended batch hold notice at stage 4 (BACKLOG.md R3)', () => {
  it('renders nothing when the incident was never part of a batch', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({ unattendedBatch: null }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const approveStage = await screen.findByRole('region', { name: /^Fix$/i })
    expect(within(approveStage).queryByText(/batch/i)).toBeNull()
  })

  it('explains a held wave-2 incident waiting on wave 1', async () => {
    mockGetIncident.mockResolvedValue(
      detailIncident({
        unattendedBatch: {
          batchId: 'batch_1',
          fleetGroupId: 'fg_1',
          actionType: 'ScaleDeployment',
          waveNumber: 2,
          batchStatus: 'wave1_pending',
          wave1Size: 1,
          totalSize: 4,
          held: true,
        },
      }),
    )
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const approveStage = await screen.findByRole('region', { name: /^Fix$/i })
    expect(within(approveStage).getByText(/Held — batch wave 2/i)).toBeTruthy()
    expect(within(approveStage).getByText(/waiting on wave 1's outcome/i)).toBeTruthy()
  })

  it('explains a batch blocked because wave 1 did not hold', async () => {
    mockGetIncident.mockResolvedValue(
      detailIncident({
        unattendedBatch: {
          batchId: 'batch_1',
          fleetGroupId: 'fg_1',
          actionType: 'ScaleDeployment',
          waveNumber: 2,
          batchStatus: 'blocked',
          wave1Size: 1,
          totalSize: 4,
          held: true,
        },
      }),
    )
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const approveStage = await screen.findByRole('region', { name: /^Fix$/i })
    expect(within(approveStage).getByText(/did not hold/i)).toBeTruthy()
  })

  it('reports wave 1 as the canary rather than "held"', async () => {
    mockGetIncident.mockResolvedValue(
      detailIncident({
        unattendedBatch: {
          batchId: 'batch_1',
          fleetGroupId: 'fg_1',
          actionType: 'ScaleDeployment',
          waveNumber: 1,
          batchStatus: 'wave1_pending',
          wave1Size: 1,
          totalSize: 4,
          held: false,
        },
      }),
    )
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const approveStage = await screen.findByRole('region', { name: /^Fix$/i })
    expect(within(approveStage).getByText(/Batch wave 1 of 4/i)).toBeTruthy()
    expect(within(approveStage).queryByText(/^Held/)).toBeNull()
  })

  it('reports a released batch as cleared, not held', async () => {
    mockGetIncident.mockResolvedValue(
      detailIncident({
        unattendedBatch: {
          batchId: 'batch_1',
          fleetGroupId: 'fg_1',
          actionType: 'ScaleDeployment',
          waveNumber: 2,
          batchStatus: 'released',
          wave1Size: 1,
          totalSize: 4,
          held: false,
        },
      }),
    )
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const approveStage = await screen.findByRole('region', { name: /^Fix$/i })
    expect(within(approveStage).getByText(/Batch cleared/i)).toBeTruthy()
  })
})

// PROJECT.md T14: "the UI names the exact gate and current reason from the
// SAME backend decision that enforced it ... tests prove the displayed
// reason changes with the enforcing gate and is never independently
// re-derived in React." These tests render the page from nothing but
// `data.automationGate` (the wire field GET /incidents/{id} carries straight
// back from incidents.automation_gate/automation_gate_reason — see
// api/types.ts's own doc comment) and check the DOM. Nothing here computes a
// gate or a reason; if AutomationGateNotice ever grew logic that derived one
// instead of rendering the prop, these assertions would still pass for the
// WRONG reason — the gate-flip tests below are what actually rules that out,
// by proving two different backend inputs produce two different rendered
// sentences.
describe('IncidentDetailPage — automation gate notice (PROJECT.md T14)', () => {
  const autoApprovePlan: RemediationPlan = {
    ...scalePlan,
    gateOutcome: 'AutoApprove',
    gateReason: 'risk "low" is within this policy\'s ceiling "low", reversible=true, and confidence 0.90 meets the 0.40 threshold',
  }

  it('renders nothing at stage 4 when no automatic execution is currently gated', async () => {
    mockGetIncident.mockResolvedValue(
      detailIncident({
        analysis: { ...detailIncident().analysis!, plan: autoApprovePlan },
        automationGate: null,
      } as Partial<IncidentDetail>),
    )
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const approveStage = await screen.findByRole('region', { name: /^Fix$/i })
    expect(within(approveStage).queryByText(/Circuit breaker/i)).toBeNull()
    expect(within(approveStage).queryByText(/budget/i)).toBeNull()
  })

  it('names the circuit breaker and its exact reason when that is the enforcing gate', async () => {
    mockGetIncident.mockResolvedValue(
      detailIncident({
        analysis: { ...detailIncident().analysis!, plan: autoApprovePlan },
        automationGate: {
          gate: 'circuit_breaker',
          reason:
            'the circuit breaker for this cluster tripped: 2 remediation(s) on it failed or were reverted in the last hour, at or above the limit of 2. Unattended execution is stopped for this cluster until an operator resets it; approving changes by hand still works.',
          at: '2026-09-18T10:00:00Z',
        },
      } as Partial<IncidentDetail>),
    )
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const approveStage = await screen.findByRole('region', { name: /^Fix$/i })
    expect(within(approveStage).getByText(/Circuit breaker open/i)).toBeTruthy()
    expect(within(approveStage).getByText(/the circuit breaker for this cluster tripped: 2 remediation/i)).toBeTruthy()
  })

  // The gate-flip test itself: same page, same plan, only the enforcing gate
  // changed — from circuit_breaker to blast_radius — and the rendered
  // sentence changes with it. A component that hardcoded one reason string,
  // or that re-derived a reason from settings/plan fields instead of reading
  // `automationGate` straight off the wire, could not pass both halves of
  // this test.
  it('renders a DIFFERENT reason when the enforcing gate is the blast-radius budget instead', async () => {
    mockGetIncident.mockResolvedValue(
      detailIncident({
        analysis: { ...detailIncident().analysis!, plan: autoApprovePlan },
        automationGate: {
          gate: 'blast_radius',
          reason: 'the fleet has run 10 unattended remediations in the last hour (limit 10), so this one needs a human',
          at: '2026-09-18T10:05:00Z',
        },
      } as Partial<IncidentDetail>),
    )
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const approveStage = await screen.findByRole('region', { name: /^Fix$/i })
    expect(within(approveStage).getByText(/Unattended budget spent/i)).toBeTruthy()
    expect(within(approveStage).getByText(/the fleet has run 10 unattended remediations/i)).toBeTruthy()
    // The OTHER gate's label/reason must not be left over from a stale render.
    expect(within(approveStage).queryByText(/Circuit breaker open/i)).toBeNull()
    expect(within(approveStage).queryByText(/the circuit breaker for this cluster tripped/i)).toBeNull()
  })

  it('defers to BatchHoldNotice rather than double-rendering the same batch_hold fact', async () => {
    mockGetIncident.mockResolvedValue(
      detailIncident({
        analysis: { ...detailIncident().analysis!, plan: autoApprovePlan },
        automationGate: {
          gate: 'batch_hold',
          reason: "waiting on wave 1's outcome before this incident is allowed to auto-execute",
          at: '2026-09-18T10:00:00Z',
        },
        unattendedBatch: {
          batchId: 'batch_1',
          fleetGroupId: 'fg_1',
          actionType: 'ScaleDeployment',
          waveNumber: 2,
          batchStatus: 'wave1_pending',
          wave1Size: 1,
          totalSize: 4,
          held: true,
        },
      } as Partial<IncidentDetail>),
    )
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const approveStage = await screen.findByRole('region', { name: /^Fix$/i })
    // BatchHoldNotice's own richer wording (wave number, total size) is present...
    expect(within(approveStage).getByText(/Held — batch wave 2/i)).toBeTruthy()
    // ...and the generic notice's badge is not duplicated beside it.
    expect(within(approveStage).queryByText(/Held for a batch wave/i)).toBeNull()
  })

  it('names why this incident has not been auto-analyzed, at stage 2, before any analysis exists', async () => {
    mockGetIncident.mockResolvedValue(
      detailIncident({
        state: 'Detected',
        analysis: null,
        automationGate: {
          gate: 'daily_spend_ceiling',
          reason:
            "today's measured spend ($12.5000) has reached the configured daily ceiling ($12.0000); automatic investigation is paused fleet-wide until it resets at UTC midnight or the ceiling is raised — a person can still run POST /incidents/{id}/analyze manually",
          at: '2026-09-18T10:00:00Z',
        },
      } as Partial<IncidentDetail>),
    )
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const analysisStage = await screen.findByRole('region', { name: /^Why$/i })
    expect(within(analysisStage).getByText(/Daily spend ceiling reached/i)).toBeTruthy()
    expect(within(analysisStage).getByText(/today's measured spend \(\$12.5000\) has reached/i)).toBeTruthy()
  })
})

describe('IncidentDetailPage — stage 5 reports one route, not both (BACKLOG D8 A9)', () => {
  it('labels the OpenPR route as a merge, never alongside an in-place label', async () => {
    mockGetIncident.mockResolvedValue(
      detailIncident({
        state: 'AwaitingMerge',
        analysis: {
          ...detailIncident().analysis!,
          plan: { ...scalePlan, actionType: 'OpenPR', approval: { verdict: 'approved', createdAt: '2026-08-25T09:05:00Z' } },
        },
      }),
    )
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const applyStage = await screen.findByRole('region', { name: /^Fix$/i })
    // The pull request is the route; no in-place option is offered beside it.
    expect(within(applyStage).getByRole('region', { name: 'Pull request' })).toBeTruthy()
    expect(within(applyStage).queryByRole('region', { name: 'ARGUS runs it' })).toBeNull()
    // And the spine names the route on its Fix phase.
    expect(screen.getByRole('list', { name: 'Incident lifecycle' }).textContent).toMatch(/Pull request/)
  })
})

// BACKLOG D8 A10 — a per-stage info affordance, disclosed on hover/focus, not
// a modal and not a click-to-stay-open toggle. HelpTip is the primitive: it
// already exists (RepositoryChangePanel's field labels, UsersPage's role
// badges) and its explanatory text is the trigger button's own aria-label, so
// a screen reader announces it on focus regardless of hover state — no
// separate assertion on hover mechanics is needed here, only that each stage
// got its OWN sentence rather than one generic string copy-pasted six times.
describe('IncidentDetailPage — the four questions in order (incident lifecycle redesign)', () => {
  it('answers what broke, why and how to fix it as labelled sections, in that order, with no card for a phase not reached', async () => {
    mockGetIncident.mockResolvedValue(detailIncident())
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const broke = await screen.findByRole('region', { name: /^What broke$/i })
    const why = screen.getByRole('region', { name: /^Why$/i })
    const fix = screen.getByRole('region', { name: /^Fix$/i })
    // DOCUMENT_POSITION_FOLLOWING (4): the four-question order (screens.md).
    expect(broke.compareDocumentPosition(why) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(why.compareDocumentPosition(fix) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    // Nothing has run, so there is no "Did it hold" card to be empty.
    expect(screen.queryByRole('region', { name: /^Did it hold$/i })).toBeNull()
    // The spine still shows all four phases and the outcome, in words.
    const spine = screen.getByRole('list', { name: 'Incident lifecycle' })
    for (const name of ['Detected', 'Diagnosed', 'Fix', 'Holding', 'Outcome']) {
      expect(within(spine).getByText(name)).toBeTruthy()
    }
    // Not a modal.
    expect(screen.queryByRole('dialog')).toBeNull()
  })
})

// The pull-request channel's diffs are supposed to read as real git-style +/-
// diffs, both while previewing (before anything is branched) and after the pull
// request is actually opened. These pin the concrete regression BACKLOG D8 B3
// fixed — a raw, uncoloured <pre> dump is not the same thing as UnifiedDiff's
// marked-up rows even when the text is identical — and, since the change is now
// a set of WHOLE FILES, that each file gets its own diff on one review surface.
describe('IncidentDetailPage — every file in a repository change renders its own git-style diff', () => {
  beforeEach(() => {
    grantedCapabilities.add(CAP_REPO_WRITE)
    grantedCapabilities.add(CAP_REMEDIATION_EXECUTE_PR)
  })

  const DEPLOYMENT = 'apps/payments/deployment.yaml'
  const VALUES = 'apps/payments/values.yaml'
  const SYNCED = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678'

  // An incident whose analysis proposed a two-file repository change. The panel
  // seeds an editor per file from this and previews it on open, so the operator
  // sees both diffs without pressing anything — an approval is only meaningful
  // if the approver saw what they were approving.
  const openPrIncident = () =>
    detailIncident({
      analysis: {
        ...detailIncident().analysis!,
        plan: {
          ...scalePlan,
          actionType: 'OpenPR',
          params: {
            repository: 'example/payments-manifests',
            files: [
              { path: DEPLOYMENT, content: 'apiVersion: apps/v1\nkind: Deployment\nspec:\n  replicas: 3\n' },
              { path: VALUES, content: 'replicaCount: 3\n' },
            ],
          },
        },
      },
    })

  const fileResult = (path: string, from: string, to: string, over: Record<string, unknown> = {}) => ({
    path,
    created: false,
    unchanged: false,
    diff: `--- a/${path}\n+++ b/${path}\n@@ -10,1 +10,1 @@\n-${from}\n+${to}\n`,
    linesAdded: 1,
    linesRemoved: 1,
    lineCount: 40,
    documentCount: 1,
    parsed: true,
    checks: [`${path} re-parses as valid YAML (1 document(s))`],
    advisories: [],
    ...over,
  })

  const verification = (files: ReturnType<typeof fileResult>[]) => ({
    files,
    filesChanged: files.filter((f) => !f.unchanged).length,
    linesAdded: 2,
    linesRemoved: 2,
    checks: files.flatMap((f) => f.checks),
    advisories: files.flatMap((f) => f.advisories),
    label: 'argus/verified-locally',
    caveat: 'It makes NO claim that only the intended thing changed.',
  })

  it('previews both files on open, each with its own +/- styled rows and its own editable content', async () => {
    mockGetIncident.mockResolvedValue(openPrIncident())
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    mockPreviewRepositoryChange.mockResolvedValue({
      incidentId: 'inc_1',
      repository: 'https://github.com/example/payments-manifests.git',
      syncedRevision: SYNCED,
      baseBranch: 'main',
      branch: 'argus/inc-1-fix',
      verification: verification([
        fileResult(DEPLOYMENT, 'replicas: 1', 'replicas: 3'),
        fileResult(VALUES, 'replicaCount: 1', 'replicaCount: 3'),
      ]),
    })
    renderPage()

    const recommendationStage = await screen.findByRole('region', { name: /^Fix$/i })
    fireEvent.click(
      within(recommendationStage).getByRole('button', { name: /Propose this fix as a pull request/i }),
    )

    // No form to fill in first: the proposal is previewed as soon as the panel
    // opens, because a form the operator must complete before ARGUS will show
    // them the diff gets the whole flow backwards.
    await waitFor(() => expect(mockPreviewRepositoryChange).toHaveBeenCalledTimes(1))
    expect(mockPreviewRepositoryChange.mock.calls[0][1].files.map((f: { path: string }) => f.path)).toEqual([
      DEPLOYMENT,
      VALUES,
    ])

    // Each file's own diff, as real markup (UnifiedDiff's table) rather than
    // text in a <pre> — one per file, on one review surface.
    const added = await within(recommendationStage).findByText('replicas: 3')
    expect(added.closest('tr')?.className).toContain('unified-diff-add')
    expect(within(recommendationStage).getByText('replicas: 1').closest('tr')?.className).toContain(
      'unified-diff-del',
    )
    const diffs = recommendationStage.querySelectorAll('.unified-diff')
    expect(diffs).toHaveLength(2)
    // Scoped to the second file's own diff: "replicaCount: 3" is also the
    // content of its textarea, and the point of this assertion is that the
    // second file gets a diff of its own rather than sharing the first's.
    expect(within(diffs[1] as HTMLElement).getByText('replicaCount: 3').closest('tr')?.className).toContain(
      'unified-diff-add',
    )

    // And each file's whole content is editable in place — the change IS the
    // content, so there is no separate "view the full file" disclosure to find.
    expect(
      (within(recommendationStage).getByRole('textbox', { name: new RegExp(VALUES) }) as HTMLTextAreaElement)
        .value,
    ).toBe('replicaCount: 3\n')
  })

  it('after the pull request is opened, every committed file still renders through the same component, advisories included', async () => {
    mockGetIncident.mockResolvedValue(openPrIncident())
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    mockPreviewRepositoryChange.mockResolvedValue({
      incidentId: 'inc_1',
      repository: 'https://github.com/example/payments-manifests.git',
      syncedRevision: SYNCED,
      baseBranch: 'main',
      branch: 'argus/inc-1-fix',
      verification: verification([
        fileResult(DEPLOYMENT, 'replicas: 1', 'replicas: 3'),
        fileResult(VALUES, 'replicaCount: 1', 'replicaCount: 3'),
      ]),
    })
    mockOpenRepositoryChange.mockResolvedValue({
      incidentId: 'inc_1',
      repository: 'example/payments-manifests',
      pullRequestNumber: 42,
      url: 'https://github.com/example/payments-manifests/pull/42',
      branch: 'argus/inc-1-fix',
      baseBranch: 'main',
      commitSha: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
      commits: ['deadbeefdeadbeefdeadbeefdeadbeefdeadbeef'],
      syncedRevision: SYNCED,
      verification: verification([
        fileResult(DEPLOYMENT, 'replicas: 1', 'replicas: 3'),
        // A templated file ARGUS did not render: an ADVISORY now, not a
        // refusal, and the reviewer has to be told in words.
        fileResult(VALUES, 'replicaCount: 1', 'replicaCount: 3', {
          parsed: false,
          documentCount: 0,
          checks: [],
          advisories: [
            `${VALUES} is templated (it contains Go template markers), so ARGUS did not render it and makes no claim about what it renders to`,
          ],
        }),
      ]),
      message: 'ok',
    })
    renderPage()

    const recommendationStage = await screen.findByRole('region', { name: /^Fix$/i })
    fireEvent.click(
      within(recommendationStage).getByRole('button', { name: /Propose this fix as a pull request/i }),
    )
    await waitFor(() => expect(mockPreviewRepositoryChange).toHaveBeenCalledTimes(1))
    fireEvent.click(within(recommendationStage).getByRole('button', { name: /^Open pull request$/i }))

    // The committed change comes through UnifiedDiff exactly like the preview
    // did, per file, visible without an extra click.
    const added = await within(recommendationStage).findByText('replicas: 3')
    expect(added.closest('tr')?.className).toContain('unified-diff-add')
    expect(recommendationStage.querySelectorAll('.unified-diff')).toHaveLength(2)
    expect(within(recommendationStage).queryByText(/The one line that changed/i)).toBeNull()

    // The advisory travels with the record of what was opened, in full, and
    // stated as something ARGUS could not check rather than as a failure.
    expect(within(recommendationStage).getByText(/is templated \(it contains Go template markers\)/)).toBeTruthy()
    expect(recommendationStage.querySelector('.repo-change-advisories')).toBeTruthy()
    expect(recommendationStage.querySelector('.form-error')).toBeNull()
    // And the caveat the reviewer sees on the pull request itself.
    expect(within(recommendationStage).getByText(/makes NO claim that only the intended thing changed/i)).toBeTruthy()
  })
})

// BACKLOG.md B1 — GET .../timeline, rendered inside the "What happened"
// disclosure inside stage 1 (the exact slot D8 reserved for "the incident's
// history, which no stage produces" — see WhatHappenedDisclosure's own
// comment for why it lives there rather than as a new section).
describe('IncidentDetailPage — real timeline inside "What happened" (BACKLOG.md B1)', () => {
  it('fetches the timeline once, for the history rail, and opening "What happened" reuses it', async () => {
    mockGetIncident.mockResolvedValue(detailIncident())
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    mockGetIncidentTimeline.mockResolvedValue({ events: [] })
    renderPage()

    await screen.findByRole('region', { name: /^What broke$/i })
    await waitFor(() => expect(mockGetIncidentTimeline).toHaveBeenCalledTimes(1))
    await openWhatHappened()
    expect(mockGetIncidentTimeline).toHaveBeenCalledTimes(1)
  })

  it('renders events in the order the hub returns them, with real relative timestamps', async () => {
    const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(new Date('2026-08-25T10:00:00Z').getTime())
    mockGetIncident.mockResolvedValue(detailIncident({ findingGroups: [], findings: [] }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    mockGetIncidentTimeline.mockResolvedValue({
      events: [
        { id: 'evt_1', eventType: 'IncidentOpened', summary: 'CrashLoop: container exited', occurredAt: '2026-08-25T09:00:00Z' },
        { id: 'evt_2', eventType: 'InvestigationStarted', summary: 'Investigation started', occurredAt: '2026-08-25T09:05:00Z' },
        { id: 'evt_3', eventType: 'AnalysisCompleted', summary: 'Analysis completed', occurredAt: '2026-08-25T09:08:00Z' },
      ],
    })
    renderPage()

    await screen.findByRole('region', { name: /^What broke$/i })
    const detectionStage = await openWhatHappened()

    await within(detectionStage).findByText('Analysis completed')
    expect(mockGetIncidentTimeline).toHaveBeenCalledWith('inc_1', 'test-token')

    // Server order (oldest first) preserved verbatim — the page never
    // re-sorts, per lld/11-ui-design.md §4's own ordering contract.
    const summaries = ['CrashLoop: container exited', 'Investigation started', 'Analysis completed']
    for (let i = 1; i < summaries.length; i++) {
      const prevNode = within(detectionStage).getByText(summaries[i - 1])
      const node = within(detectionStage).getByText(summaries[i])
      // DOCUMENT_POSITION_FOLLOWING (4): prevNode is followed by node.
      expect(prevNode.compareDocumentPosition(node) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    }

    // Real relative timestamps, computed against the current instant —
    // 09:00 is exactly 1h before the mocked "now" of 10:00.
    expect(within(detectionStage).getByText('1h ago')).toBeTruthy()

    nowSpy.mockRestore()
  })

  // BACKLOG.md D6's re-audit (2026-08-29): before this, "Approved" and
  // "Execution succeeded" carried no indication of which recommendation they
  // were deciding — a real gap on an incident whose history has more than one
  // recommendation (a rejected-then-reanalyzed plan is simulated here: two
  // different action types, two different planIds, in the same chronology).
  it('ties an approval/execution event back to which recommendation it decided', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({ findingGroups: [], findings: [] }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    mockGetIncidentTimeline.mockResolvedValue({
      events: [
        {
          id: 'evt_1',
          eventType: 'RecommendationReady',
          summary: 'Recommended: ScaleDeployment',
          detail: { planId: 'plan_1', actionType: 'ScaleDeployment' },
          occurredAt: '2026-08-25T09:00:00Z',
        },
        {
          id: 'evt_2',
          eventType: 'ApprovalRejected',
          summary: 'Rejected: wrong call',
          detail: { planId: 'plan_1', reason: 'wrong call' },
          occurredAt: '2026-08-25T09:05:00Z',
        },
        {
          id: 'evt_3',
          eventType: 'RecommendationReady',
          summary: 'Recommended: RestartPod',
          detail: { planId: 'plan_2', actionType: 'RestartPod' },
          occurredAt: '2026-08-25T09:10:00Z',
        },
        {
          id: 'evt_4',
          eventType: 'ApprovalGranted',
          summary: 'Approved',
          detail: { planId: 'plan_2' },
          occurredAt: '2026-08-25T09:12:00Z',
        },
        {
          id: 'evt_5',
          eventType: 'ExecutionOutcome',
          summary: 'Execution succeeded',
          detail: { planId: 'plan_2', outcome: 'succeeded' },
          occurredAt: '2026-08-25T09:14:00Z',
        },
      ],
    })
    renderPage()

    await screen.findByRole('region', { name: /^What broke$/i })
    const detectionStage = await openWhatHappened()
    await within(detectionStage).findByText('Execution succeeded')

    // The FIRST recommendation's rejection is tied back to ScaleDeployment too
    // — shown uniformly for every decision/outcome event with a resolvable
    // plan, not only when the chronology happens to be ambiguous.
    const rejected = within(detectionStage).getByText('Rejected: wrong call').closest('li')
    expect(rejected?.textContent).toMatch(/ScaleDeployment/)

    // The SECOND recommendation's approval and outcome are each tied back to
    // RestartPod — the plan they actually concern — even though neither
    // summary says so on its own.
    const approved = within(detectionStage).getByText('Approved').closest('li')
    expect(approved?.textContent).toMatch(/RestartPod/)
    const outcome = within(detectionStage).getByText('Execution succeeded').closest('li')
    expect(outcome?.textContent).toMatch(/RestartPod/)
  })

  it('states plainly when no timeline events are recorded, rather than hiding the section', async () => {
    mockGetIncident.mockResolvedValue(detailIncident())
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    mockGetIncidentTimeline.mockResolvedValue({ events: [] })
    renderPage()

    await screen.findByRole('region', { name: /^What broke$/i })
    const detectionStage = await openWhatHappened()

    expect(await within(detectionStage).findByText(/No timeline events recorded/i)).toBeTruthy()
  })

  it('renders a fetch failure as an explicit error, not a silent empty timeline', async () => {
    mockGetIncident.mockResolvedValue(detailIncident())
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    mockGetIncidentTimeline.mockRejectedValue(new Error('network error'))
    renderPage()

    await screen.findByRole('region', { name: /^What broke$/i })
    const detectionStage = await openWhatHappened()

    const alert = await within(detectionStage).findByRole('alert')
    expect(alert.textContent).toMatch(/Could not load the timeline/i)
  })
})

// BACKLOG.md B2 — evidence drill-down. GET .../evidence/{evId}, lazily, from
// a causal-chain tool-call chip; and the cli-backend gap handled by
// construction (an empty causalChain means no chip is ever mounted).
describe('IncidentDetailPage — evidence drill-down per causal-chain link (BACKLOG.md B2)', () => {
  const stepWithEvidence: AnalysisStep = {
    step: 1,
    hypothesis: 'Checking recent events for the pod',
    finding: 'Pod was OOMKilled twice in the last hour',
    toolCalls: [
      {
        tool: 'get_events',
        args: { namespace: 'payments', name: 'payments-api-abc123' },
        result: null,
        error: null,
        evidenceId: 'ev_123',
      },
    ],
  }

  function analysisWithChain(): Analysis {
    return {
      ...detailIncident().analysis!,
      causalChain: [stepWithEvidence],
    } as Analysis
  }

  it('fetches and displays the real evidence record only once its chip is opened', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({ analysis: analysisWithChain() }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    mockGetEvidence.mockResolvedValue({
      id: 'ev_123',
      incidentId: 'inc_1',
      tool: 'get_events',
      outcome: 'ok',
      args: { namespace: 'payments', name: 'payments-api-abc123' },
      result: { items: ['Back-off restarting failed container'] },
      redacted: true,
      capturedAt: '2026-08-25T09:10:00Z',
    })
    renderPage()

    const analysisStage = await screen.findByRole('region', { name: /^Why$/i })
    // Not fetched before the chip is clicked.
    expect(mockGetEvidence).not.toHaveBeenCalled()

    fireEvent.click(within(analysisStage).getByRole('button', { name: /^events$/i }))

    expect(mockGetEvidence).toHaveBeenCalledWith('inc_1', 'ev_123', 'test-token')
    expect(await within(analysisStage).findByText(/Back-off restarting failed container/)).toBeTruthy()
    // B2's own scoping note: never imply the operator is seeing the raw
    // object — the redaction marker must actually be stated.
    expect(within(analysisStage).getByText(/redacted before this leaves the cluster/i)).toBeTruthy()
  })

  it('falls back to the inline copy already on the wire if the evidence fetch fails', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({
      analysis: {
        ...analysisWithChain(),
        causalChain: [
          {
            ...stepWithEvidence,
            toolCalls: [{ ...stepWithEvidence.toolCalls[0], result: { inline: 'copy' } }],
          },
        ],
      },
    }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    mockGetEvidence.mockRejectedValue(new Error('not found'))
    renderPage()

    const analysisStage = await screen.findByRole('region', { name: /^Why$/i })
    fireEvent.click(within(analysisStage).getByRole('button', { name: /^events$/i }))

    // The fetch was attempted and failed, but the chip still shows the real
    // (inline) content rather than a broken or empty panel.
    expect(await within(analysisStage).findByText(/"copy"/)).toBeTruthy()
  })

  it('renders no evidence chips for a cli-backend analysis, which never carries a causal chain', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({
      analysis: { ...detailIncident().analysis!, causalChain: [] } as Analysis,
    }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const analysisStage = await screen.findByRole('region', { name: /^Why$/i })
    expect(within(analysisStage).queryByText(/No investigation steps were recorded/i)).toBeTruthy()
    // Query by the chip's own class rather than an accessible-name regex —
    // this stage's HelpTip explanation itself mentions "events" in prose, so
    // a name-based query would collide with it.
    expect(analysisStage.querySelectorAll('.evidence-chip')).toHaveLength(0)
    expect(mockGetEvidence).not.toHaveBeenCalled()
  })
})

// BACKLOG.md C10 — the causal chain's provenance must render distinctly for
// a self-reported (cli backend) chain vs. a hub-observed (api backend) one,
// plainly next to the heading, never only in a tooltip — and a self-reported
// citation the hub could not corroborate must be marked, never rendered as
// if it were verified evidence.
describe('IncidentDetailPage — causal chain provenance (BACKLOG.md C10)', () => {
  const oneStep: AnalysisStep = {
    step: 1,
    hypothesis: 'container exceeding memory limit',
    finding: 'OOMKilled 4 times in 25 minutes',
    toolCalls: [
      { tool: 'get_events', args: {}, result: null, error: null, corroborated: 'unchecked' },
      { tool: 'get_logs', args: {}, result: null, error: null, corroborated: 'unverified' },
    ],
  }

  it('labels a self-reported chain plainly, next to the heading', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({
      analysis: {
        ...detailIncident().analysis!,
        causalChain: [oneStep],
        causalChainProvenance: 'self-reported',
      } as Analysis,
    }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const analysisStage = await screen.findByRole('region', { name: /^Why$/i })
    // Visible text, not only a title attribute — "plainly", per the task.
    expect(within(analysisStage).getByText('Self-reported')).toBeTruthy()
    expect(within(analysisStage).queryByText('Hub-observed')).toBeNull()
  })

  it('labels a hub-observed chain distinctly from a self-reported one', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({
      analysis: {
        ...detailIncident().analysis!,
        causalChain: [oneStep],
        causalChainProvenance: 'hub-observed',
      } as Analysis,
    }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const analysisStage = await screen.findByRole('region', { name: /^Why$/i })
    expect(within(analysisStage).getByText('Hub-observed')).toBeTruthy()
    expect(within(analysisStage).queryByText('Self-reported')).toBeNull()
  })

  it('treats an absent provenance (a pre-C10 row) as hub-observed, never as unlabeled or self-reported', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({
      analysis: {
        ...detailIncident().analysis!,
        causalChain: [oneStep],
        causalChainProvenance: undefined,
      } as Analysis,
    }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const analysisStage = await screen.findByRole('region', { name: /^Why$/i })
    expect(within(analysisStage).getByText('Hub-observed')).toBeTruthy()
  })

  it('shows no provenance label at all when there is no chain to label', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({
      analysis: { ...detailIncident().analysis!, causalChain: [], causalChainProvenance: 'self-reported' } as Analysis,
    }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const analysisStage = await screen.findByRole('region', { name: /^Why$/i })
    await within(analysisStage).findByText(/No investigation steps were recorded/i)
    expect(within(analysisStage).queryByText('Self-reported')).toBeNull()
    expect(within(analysisStage).queryByText('Hub-observed')).toBeNull()
  })

  it('marks an unverified self-reported citation distinctly from an unchecked one (PROJECT.md B151)', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({
      analysis: {
        ...detailIncident().analysis!,
        causalChain: [oneStep],
        causalChainProvenance: 'self-reported',
      } as Analysis,
    }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const analysisStage = await screen.findByRole('region', { name: /^Why$/i })
    // The get_logs citation (corroborated: 'unverified' — the tool was never
    // actually called) is marked "unverified" — the fabrication this
    // mechanism exists to catch must not be silently rendered as if it were
    // the same as the real one.
    expect(within(analysisStage).getAllByText('unverified')).toHaveLength(1)
    // The get_events citation (corroborated: 'unchecked' — the call
    // happened, but the finding states no checkable value) is not left
    // unmarked either — that limit must be legible in the collapsed view,
    // not just on expand.
    expect(within(analysisStage).getAllByText('unchecked')).toHaveLength(1)

    // Opening the flagged citation states plainly that it is unverified, not
    // a bare "null" where evidence would normally be.
    fireEvent.click(within(analysisStage).getByRole('button', { name: /^pod logs/i }))
    expect(await within(analysisStage).findByText(/no record of the hub ever serving this tool call/i)).toBeTruthy()

    // The unchecked citation, opened, says the call was confirmed served
    // but nothing checkable was cited — never a bare "null".
    fireEvent.click(within(analysisStage).getByRole('button', { name: /^events/i }))
    expect(await within(analysisStage).findByText(/confirmed the hub actually served this tool call/i)).toBeTruthy()
  })

  it('marks a contradicted citation as the strongest signal, and a genuinely corroborated one distinctly (PROJECT.md B151)', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({
      analysis: {
        ...detailIncident().analysis!,
        causalChain: [{
          ...oneStep,
          toolCalls: [
            { tool: 'get_events', args: {}, result: null, error: null, corroborated: 'corroborated' },
            { tool: 'get_logs', args: {}, result: null, error: null, corroborated: 'contradicted' },
          ],
        }],
        causalChainProvenance: 'self-reported',
      } as Analysis,
    }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const analysisStage = await screen.findByRole('region', { name: /^Why$/i })
    expect(within(analysisStage).getAllByText('corroborated')).toHaveLength(1)
    expect(within(analysisStage).getAllByText('contradicted')).toHaveLength(1)

    fireEvent.click(within(analysisStage).getByRole('button', { name: /^pod logs/i }))
    expect(await within(analysisStage).findByText(/does not match what that call actually returned/i)).toBeTruthy()

    fireEvent.click(within(analysisStage).getByRole('button', { name: /^events/i }))
    expect(await within(analysisStage).findByText(/every specific value the finding above cites matches/i)).toBeTruthy()
  })

  it('never marks a hub-observed chain\'s calls with any B151 verdict, even though corroborated is absent there', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({
      analysis: {
        ...detailIncident().analysis!,
        // A real hub-observed record never sets `corroborated` at all — this
        // is the exact case ToolCallRecord's own doc comment warns must not
        // be read as any of the four self-reported states.
        causalChain: [{ ...oneStep, toolCalls: [{ tool: 'get_events', args: {}, result: null, error: null }] }],
        causalChainProvenance: 'hub-observed',
      } as Analysis,
    }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const analysisStage = await screen.findByRole('region', { name: /^Why$/i })
    await within(analysisStage).findByText(/test-model/)
    expect(within(analysisStage).queryByText('unverified')).toBeNull()
    expect(within(analysisStage).queryByText('unchecked')).toBeNull()
    expect(within(analysisStage).queryByText('contradicted')).toBeNull()
    expect(within(analysisStage).queryByText('corroborated')).toBeNull()
  })
})

// PROJECT.md T15 — the bounded "recent changes" list, and the two DIFFERENT
// empty states it must render: null ("no evidence was ever gathered for
// this incident" — must render as nothing, matching EvidenceGathered's own
// convention for the sibling `evidence` field) versus non-null-with-empty-
// items ("we looked at the evidence we have and found nothing relevant" —
// must render as an explicit sentence). Collapsing the two into one would
// be exactly the fabricated-fact failure mode this feature exists to avoid.
describe('IncidentDetailPage — recent changes (PROJECT.md T15)', () => {
  it('renders nothing when recentChanges is null — no evidence was ever gathered', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({ recentChanges: null }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const analysisStage = await screen.findByRole('region', { name: /^Why$/i })
    expect(within(analysisStage).queryByText('Recent changes')).toBeNull()
  })

  it('renders an explicit "no recorded change" sentence, naming the window, when recentChanges has no items', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({
      recentChanges: { items: [], windowHours: 24, truncated: false },
    }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const analysisStage = await screen.findByRole('region', { name: /^Why$/i })
    expect(within(analysisStage).getByText('Recent changes')).toBeTruthy()
    expect(
      within(analysisStage).getByText(/No recorded change in the 24h before this incident's first finding/i),
    ).toBeTruthy()
  })

  it('renders a chronological, source-labelled list of real changes, with a readable category label', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({
      recentChanges: {
        windowHours: 24,
        truncated: false,
        items: [
          {
            time: '2026-08-25T07:00:00Z',
            category: 'rollout_created',
            source: 'get_events',
            objectKind: 'ReplicaSet',
            objectNamespace: 'payments',
            objectName: 'payments-api-abc123',
            reason: 'SuccessfulCreate',
            message: 'Created pod: payments-api-abc123-xyz',
          },
          {
            time: '2026-08-25T08:30:00Z',
            category: 'replica_change',
            source: 'get_events',
            objectKind: 'Deployment',
            objectNamespace: 'payments',
            objectName: 'payments-api',
            reason: 'ScalingReplicaSet',
            message: 'Scaled up replica set payments-api-abc123 to 3 from 1',
          },
        ],
      },
    }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const analysisStage = await screen.findByRole('region', { name: /^Why$/i })
    // Never the raw category string.
    expect(within(analysisStage).queryByText('rollout_created')).toBeNull()
    expect(within(analysisStage).queryByText('replica_change')).toBeNull()
    // The readable labels, and the object identity, and the verbatim event
    // message (source-labelled: which tool this came from).
    expect(within(analysisStage).getByText(/New replica set\/pod created/i)).toBeTruthy()
    expect(within(analysisStage).getByText(/Replica count changed/i)).toBeTruthy()
    expect(within(analysisStage).getAllByText(/payments-api-abc123/).length).toBeGreaterThan(0)
    expect(within(analysisStage).getByText(/Scaled up replica set payments-api-abc123 to 3 from 1/)).toBeTruthy()
    expect(within(analysisStage).getAllByText('events').length).toBeGreaterThan(0)
    // Chronological — the earlier rollout creation appears before the later
    // scaling event in the rendered DOM order.
    const html = analysisStage.innerHTML
    expect(html.indexOf('New replica set/pod created')).toBeLessThan(html.indexOf('Replica count changed'))
    // Never the "no recorded change" sentence when real items exist.
    expect(within(analysisStage).queryByText(/No recorded change/i)).toBeNull()
    // Not flagged as truncated — no over-cap note should appear.
    expect(within(analysisStage).queryByText(/Showing the most recent changes only/i)).toBeNull()
  })

  it('states the cap when the list was truncated, rather than letting it read as complete', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({
      recentChanges: {
        windowHours: 24,
        truncated: true,
        items: [
          {
            time: '2026-08-25T08:30:00Z',
            category: 'warning_event',
            source: 'get_events',
            objectKind: 'Pod',
            objectNamespace: 'payments',
            objectName: 'payments-api-1',
            reason: 'BackOff',
            message: 'Back-off restarting failed container',
          },
        ],
      },
    }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const analysisStage = await screen.findByRole('region', { name: /^Why$/i })
    expect(within(analysisStage).getByText(/Showing the most recent changes only/i)).toBeTruthy()
  })
})

// BACKLOG.md C6 — nothing distinguished a human-triggered analysis from
// internal/autoanalyze.Poller's unattended one anywhere an operator could
// see it. analysis.triggeredBy (migration 000074) is now on the wire; this
// only checks the page actually renders it, understated, in the same
// field-hint metadata line as model/tokens/cost.
describe('IncidentDetailPage — auto-investigated indicator (BACKLOG.md C6)', () => {
  it('flags an automatically-triggered analysis', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({
      analysis: { ...detailIncident().analysis!, triggeredBy: 'auto' } as Analysis,
    }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const analysisStage = await screen.findByRole('region', { name: /^Why$/i })
    expect(within(analysisStage).getByText(/auto-investigated/i)).toBeTruthy()
  })

  it('says nothing extra for a manually-triggered analysis', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({
      analysis: { ...detailIncident().analysis!, triggeredBy: 'manual' } as Analysis,
    }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const analysisStage = await screen.findByRole('region', { name: /^Why$/i })
    await within(analysisStage).findByText(/test-model/)
    expect(within(analysisStage).queryByText(/auto-investigated/i)).toBeNull()
  })

  it('says nothing extra when triggeredBy is absent (a pre-migration row)', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({
      analysis: { ...detailIncident().analysis!, triggeredBy: undefined } as Analysis,
    }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const analysisStage = await screen.findByRole('region', { name: /^Why$/i })
    await within(analysisStage).findByText(/test-model/)
    expect(within(analysisStage).queryByText(/auto-investigated/i)).toBeNull()
  })
})

// BACKLOG.md D9 B2: Stage 4 used to show BOTH the rail's dashed "never
// going to happen" marker AND the box's own "Not yet" chip plus "Unlocks
// when there is a plan..." text at once, for a complete investigation that
// found no executable fix — the box's lockedReason keyed only on
// `!data.analysis?.plan`, disagreeing with the state ('unreachable', "never")
// the dashed marker itself reads.
describe('IncidentDetailPage — Approve stage does not show both "never" and "not yet" at once (BACKLOG.md D9 B2)', () => {
  it('shows the honest "nothing to approve" text, not the "Not yet" chip, when the investigation completed with no fix', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({
      state: 'Diagnosed',
      analysis: { ...detailIncident().analysis!, plan: null } as Analysis,
    }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    // PROJECT.md D13 superseded the original assertion. This test was written
    // for BACKLOG.md D9 B2 — an Approve card showing BOTH a dashed "never"
    // marker and a "Not yet" chip — and asserted the card's honest text
    // instead. The three trailing cards now FOLD into one line when nothing
    // was executed, so that contradiction is impossible by construction
    // rather than by wording, and there is no Approve region to inspect.
    //
    // The stronger property is asserted instead: the fold happened, and no
    // "Not yet" chip survives anywhere on the page for an incident that will
    // never reach approval.
    // Lifecycle redesign: an open diagnosed incident shows its Fix section
    // (the fix, if one is needed, is a person's) — with no Approve control
    // and no "Not yet" chip anywhere, since approval will never come.
    const fix = await screen.findByRole('region', { name: /^Fix$/i })
    expect(within(fix).queryByRole('button', { name: /^Approve$/i })).toBeNull()
    expect(screen.queryByText(/^Not yet$/i)).toBeNull()
  })

  it('still shows "Not yet" for the genuinely-not-yet case (no analysis at all)', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({ state: 'Detected', analysis: null }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    // No Fix card before a diagnosis: the spine says the phase comes later.
    await screen.findByRole('region', { name: /^Why$/i })
    expect(screen.queryByRole('region', { name: /^Fix$/i })).toBeNull()
    expect(screen.getByRole('list', { name: 'Incident lifecycle' }).textContent).toMatch(/After diagnosis/)
  })
})

// BACKLOG.md D9 "the one that matters most": route/routeReason were computed
// hub-side and stored on the incident, but never reached the browser — the
// UI re-derived "Pull request / In place" purely from plan.actionType, which
// is null for exactly the `guidance` route (no plan at all) where the reason
// matters most.
describe('IncidentDetailPage — the route reason reaches the browser (BACKLOG.md D9, "the one that matters most")', () => {
  it('renders routeReason in the Recommendation stage even with no plan at all (the guidance route)', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({
      analysis: { ...detailIncident().analysis!, plan: null, rootCause: { statement: 'Missing ConfigMap' } } as Analysis,
      route: 'guidance',
      routeReason: 'ownership could not be determined for this object — ARGUS will not guess between a live patch and a pull request it cannot confirm applies',
    } as Partial<IncidentDetail>))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const recommendationStage = await screen.findByRole('region', { name: /^Fix$/i })
    expect(within(recommendationStage).getByText(/ownership could not be determined/i)).toBeTruthy()
    expect(within(recommendationStage).getByText(/Guidance only/i)).toBeTruthy()
  })

  it('renders nothing extra when route/routeReason are absent (a pre-routing incident)', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({ route: null, routeReason: null } as Partial<IncidentDetail>))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const recommendationStage = await screen.findByRole('region', { name: /^Fix$/i })
    expect(within(recommendationStage).queryByText(/Guidance only|Pull request:|In place:/i)).toBeNull()
  })
})

// BACKLOG.md D9 U5: the root-cause statement, the plan and the next steps
// carried no path back to the tool calls that support them — only the
// per-step chips inside the causal chain did.
describe('IncidentDetailPage — a path from the headline claim back to its evidence (BACKLOG.md D9 U5)', () => {
  it('links from the Recommendation stage back to the causal chain, naming the real step count', async () => {
    const step: AnalysisStep = {
      step: 1,
      hypothesis: 'container exceeding memory limit',
      finding: 'OOMKilled 4 times in 25 minutes',
      toolCalls: [{ tool: 'get_events', args: {}, result: null, error: null, corroborated: 'unchecked' }],
    }
    mockGetIncident.mockResolvedValue(detailIncident({
      analysis: { ...detailIncident().analysis!, causalChain: [step] } as Analysis,
    }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const recommendationStage = await screen.findByRole('region', { name: /^Fix$/i })
    const link = within(recommendationStage).getByRole('link', { name: /step causal chain/i })
    expect(link.getAttribute('href')).toBe('#causal-chain')
  })

  it('renders nothing when there is no causal chain to link to', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({
      analysis: { ...detailIncident().analysis!, causalChain: [], plan: null } as Analysis,
    }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const recommendationStage = await screen.findByRole('region', { name: /^Fix$/i })
    expect(within(recommendationStage).queryByRole('link', { name: /step causal chain/i })).toBeNull()
  })
})

// BACKLOG.md D9 U6: PullRequestRecord used to render "#63" with no way to
// click through to the pull request the operator is waiting on.
describe('IncidentDetailPage — the pull request number is a real link when a URL is known (BACKLOG.md D9 U6)', () => {
  it('renders the PR number as a link when pullRequest.url is present', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({
      state: 'AwaitingMerge',
      pullRequest: { number: 63, url: 'https://github.com/example/payments-manifests/pull/63' },
    } as Partial<IncidentDetail>))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const applyStage = await screen.findByRole('region', { name: /^Fix$/i })
    const link = within(applyStage).getByRole('link', { name: /#63/ })
    expect(link.getAttribute('href')).toBe('https://github.com/example/payments-manifests/pull/63')
  })

  it('renders the bare number, not a broken link, when pullRequest.url is absent (a pre-migration pull request)', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({
      state: 'AwaitingMerge',
      pullRequest: { number: 63 },
    } as Partial<IncidentDetail>))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const applyStage = await screen.findByRole('region', { name: /^Fix$/i })
    expect(within(applyStage).getByText(/#63/)).toBeTruthy()
    expect(within(applyStage).queryByRole('link', { name: /#63/ })).toBeNull()
  })
})

// BACKLOG.md D9 U1/U2: six states used to appear as nothing but a coloured
// badge. Investigating specifically looked identical to Detected unless THIS
// browser tab happened to launch the analysis.
describe('IncidentDetailPage — states with words (BACKLOG.md D9 U1/U2)', () => {
  // PROJECT.md D13. These two pin the collapse, because nothing else does:
  // a closed <details> keeps its children in the DOM, so every existing
  // getByText assertion about chain content passes whether it is open or shut.
  // Without these the collapse could silently regress to always-open (or
  // always-closed) and the suite would stay green.
  it('collapses the causal chain by default, but keeps provenance visible', async () => {
    // A step of its own rather than a shared fixture: the only thing this test
    // needs from a chain is that it is non-empty, because the provenance badge
    // renders on that condition alone.
    const oneChainStep: AnalysisStep = {
      step: 1,
      hypothesis: 'Checking recent events for the pod',
      finding: 'Pod was OOMKilled twice in the last hour',
      toolCalls: [],
    }
    const base = detailIncident({ state: 'Diagnosed' })
    mockGetIncident.mockResolvedValue({
      ...base,
      analysis: { ...base.analysis!, causalChain: [oneChainStep] },
    })
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const disclosure = (await screen.findByText('Causal chain')).closest('details')
    expect(disclosure).toBeTruthy()
    expect(disclosure!.hasAttribute('open')).toBe(false)

    // The summary must still carry what stops a reader over-trusting the
    // conclusion — the provenance badge and the step count are deliberately
    // OUTSIDE the collapse.
    const summary = disclosure!.querySelector('summary')!
    expect(summary.textContent).toMatch(/step/i)
    expect(summary.textContent).toMatch(/self-reported|hub-observed/i)
  })

  it('opens the causal chain when the reader arrived via the evidence link', async () => {
    // Stage 3 links to #causal-chain. Landing on a collapsed section after
    // following a link that promised evidence would be worse than the problem
    // the collapse solves, and browsers do not open a <details> on fragment
    // navigation.
    const originalHash = window.location.hash
    window.location.hash = '#causal-chain'
    try {
      mockGetIncident.mockResolvedValue(detailIncident({ state: 'Diagnosed' }))
      mockGetApprovals.mockResolvedValue({ approvals: [] })
      renderPage()

      const disclosure = (await screen.findByText('Causal chain')).closest('details')
      expect(disclosure!.hasAttribute('open')).toBe(true)
    } finally {
      window.location.hash = originalHash
    }
  })

  it('explains Diagnosed, mentioning the guidance route', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({ state: 'Diagnosed' }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    await screen.findByRole('region', { name: /^Fix$/i })
    expect(screen.getByText(/nothing ARGUS can execute automatically/i)).toBeTruthy()
  })

  // NeedsHumanInvestigation means TWO different things and the sentence has to
  // follow which one. These two tests are the pair; this one used to assert
  // "now yours to look into by hand" against a fixture carrying a COMPLETE
  // analysis with a real root cause, so it was pinning a false claim — the
  // investigation had not "stopped without a clear cause" at all. A live
  // incident in exactly that shape (gwas-db, 2026-09-09, 95% confidence) is
  // what surfaced it.
  it('explains NeedsHumanInvestigation as no PLAN when a cause was reached', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({ state: 'NeedsHumanInvestigation' }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    await screen.findByRole('region', { name: /^Fix$/i })
    expect(screen.getByText(/reached a cause, but proposed nothing ARGUS can execute/i)).toBeTruthy()
    expect(screen.queryByText(/stopped without a clear cause/i)).toBeNull()
  })

  it('explains NeedsHumanInvestigation as no CAUSE when the investigation reached none', async () => {
    mockGetIncident.mockResolvedValue(
      detailIncident({
        state: 'NeedsHumanInvestigation',
        analysis: { ...detailIncident().analysis!, rootCause: null },
      }),
    )
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    await screen.findByRole('region', { name: /^Fix$/i })
    expect(screen.getByText(/now yours to look into by hand/i)).toBeTruthy()
  })

  it('shows the investigating banner for a server-side analysis this tab never triggered', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({ state: 'Investigating', analysis: null }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const analysisStage = await screen.findByRole('region', { name: /^Why$/i })
    // Not the plain "Not analyzed yet" empty state Detected would show.
    expect(within(analysisStage).queryByText(/not analyzed yet/i)).toBeNull()
    expect(within(analysisStage).getByText(/investigating/i)).toBeTruthy()
    expect(within(analysisStage).getByText(/started automatically or from another tab/i)).toBeTruthy()
  })
})

// PROJECT.md M1: POST /analyze answers 202 once the run is claimed and the
// investigation continues server-side. The page must read the 202 as
// "started", keep showing Investigating from the incident's own state, and
// take a failure from the incident (analysisError), not from the POST.
describe('IncidentDetailPage — asynchronous analyze (PROJECT.md M1)', () => {
  const startedAt = new Date(Date.now() - 2 * 60 * 1000).toISOString()

  it('treats a 202 as started and keeps showing Investigating from the incident state', async () => {
    grantedCapabilities.add(CAP_INCIDENT_REANALYSE)
    try {
      mockGetIncident.mockResolvedValueOnce(detailIncident({ state: 'Detected', analysis: null }))
      mockGetIncident.mockResolvedValue(
        detailIncident({ state: 'Investigating', analysis: null, analysisStartedAt: startedAt, analysisBackend: 'api' }),
      )
      mockAnalyzeIncident.mockResolvedValue({ incidentId: 'inc_1', state: 'Investigating', startedAt, backend: 'api' })
      mockGetApprovals.mockResolvedValue({ approvals: [] })
      renderPage()

      fireEvent.click(await screen.findByRole('button', { name: 'Analyze incident' }))

      const analysisStage = await screen.findByRole('region', { name: /^Why$/i })
      await waitFor(() => expect(within(analysisStage).getByText(/Started/)).toBeTruthy())
      expect(within(analysisStage).getByText(/2 minutes ago|2m ago|2 min/i)).toBeTruthy()
      // This tab started it — not the "started elsewhere" sentence.
      expect(within(analysisStage).queryByText(/started automatically or from another tab/i)).toBeNull()
      const button = screen.getByRole('button', { name: 'Investigating…' })
      expect((button as HTMLButtonElement).disabled).toBe(true)
      // A 202 is not an error.
      expect(screen.queryByRole('alert')).toBeNull()
      expect(mockAnalyzeIncident).toHaveBeenCalledTimes(1)
    } finally {
      grantedCapabilities.delete(CAP_INCIDENT_REANALYSE)
    }
  })

  it('shows a failed background run from the incident, not the POST', async () => {
    grantedCapabilities.add(CAP_INCIDENT_REANALYSE)
    try {
      mockGetIncident.mockResolvedValue(
        detailIncident({
          state: 'Detected',
          analysis: null,
          analysisStartedAt: startedAt,
          analysisError: 'could not complete the AI investigation: argument list too long',
        }),
      )
      mockGetApprovals.mockResolvedValue({ approvals: [] })
      renderPage()

      const alert = await screen.findByRole('alert')
      expect(alert.textContent).toMatch(/last analysis did not complete/i)
      expect(alert.textContent).toMatch(/argument list too long/)
      expect((screen.getByRole('button', { name: 'Analyze incident' }) as HTMLButtonElement).disabled).toBe(false)
    } finally {
      grantedCapabilities.delete(CAP_INCIDENT_REANALYSE)
    }
  })
})

// LinkHelmReleaseForm — a plain Helm release has no Application/Kustomization
// CR the way Argo CD/Flux do, so ownership.repo stays empty forever unless an
// operator confirms a discovered, render-proven link once (BACKLOG.md F30).
// These pin the incident-level discover/confirm/decline flow that replaced
// the old hand-typed "which repo, which path" form.
describe('IncidentDetailPage — LinkHelmReleaseForm (discovering and confirming a repository link)', () => {
  it('is not shown for an Argo CD-managed object, which resolves its repo automatically', async () => {
    mockGetIncident.mockResolvedValue(detailIncident())
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    await screen.findByRole('region', { name: /^Fix$/i })
    expect(screen.queryByText(/Link this Helm release to a repository/i)).toBeNull()
    expect(mockDiscoverRepositoryLink).not.toHaveBeenCalled()
  })

  it('pre-fills one proven candidate and links it for this cluster with one click', async () => {
    grantedCapabilities.add(CAP_REPO_READ)
    grantedCapabilities.add(CAP_REPO_WRITE)
    mockDiscoverRepositoryLink.mockResolvedValue({
      status: 'proven',
      candidates: [{ bindingId: 'rb_1', repoUrl: 'https://gitlab.internal.example/shop/shop-apps-helm.git', chartPath: 'charts/shop-apps', valuesFile: '' }],
      releaseName: 'shop-apps-helm',
      namespace: 'shop',
      otherClusters: [],
    })
    mockConfirmRepositoryLink.mockResolvedValue({})
    mockGetIncident.mockResolvedValue(detailIncident({ ownership: helmOwnershipNoRepo }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const recommendationStage = await screen.findByRole('region', { name: /^Fix$/i })
    expect(within(recommendationStage).getByText(/Link this Helm release to a repository/i)).toBeTruthy()
    expect(await within(recommendationStage).findByText('charts/shop-apps')).toBeTruthy()
    expect(within(recommendationStage).getByText('https://gitlab.internal.example/shop/shop-apps-helm.git')).toBeTruthy()
    // No widen offer — discovery reported no other cluster running this release.
    expect(within(recommendationStage).queryByText(/all \d+ clusters running/i)).toBeNull()

    fireEvent.click(within(recommendationStage).getByRole('button', { name: 'Link for this cluster' }))

    await waitFor(() => expect(mockConfirmRepositoryLink).toHaveBeenCalledTimes(1))
    const [incidentId, body] = mockConfirmRepositoryLink.mock.calls[0]
    expect(incidentId).toBe('inc_1')
    expect(body).toEqual({ bindingId: 'rb_1', path: 'charts/shop-apps', scope: undefined })

    // A confirmation replaces the candidate list — and is honest that THIS
    // incident's own route needs a re-analyze to pick up the new link.
    expect(await within(recommendationStage).findByText(/re-analyze/i)).toBeTruthy()
    expect(within(recommendationStage).queryByRole('button', { name: 'Link for this cluster' })).toBeNull()
  })

  // PROJECT.md B189: internal/api/objectmapping_link_endpoints.go declares
  // OtherClusters as a plain []otherClusterRunningRelease with no omitempty and
  // never assigns it in manifest mode, so Go marshals it as JSON null — which
  // the hand-written type claimed could not happen, and which took the whole
  // panel down when this component read .length off it.
  it('survives a discovery whose otherClusters/candidates arrive as null, not []', async () => {
    grantedCapabilities.add(CAP_REPO_READ)
    grantedCapabilities.add(CAP_REPO_WRITE)
    mockDiscoverRepositoryLink.mockResolvedValue({
      status: 'proven',
      candidates: [{ bindingId: 'rb_1', repoUrl: 'https://gitlab.internal.example/shop/shop-apps-helm.git', chartPath: 'charts/shop-apps', valuesFile: '' }],
      releaseName: 'shop-apps-helm',
      namespace: 'shop',
      otherClusters: null,
    })
    mockGetIncident.mockResolvedValue(detailIncident({ ownership: helmOwnershipNoRepo }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const recommendationStage = await screen.findByRole('region', { name: /^Fix$/i })
    expect(await within(recommendationStage).findByText('charts/shop-apps')).toBeTruthy()
    // Null is read as "no other cluster", so no widen offer — never a crash.
    expect(within(recommendationStage).queryByText(/all \d+ clusters running/i)).toBeNull()
    expect(within(recommendationStage).getByRole('button', { name: 'Link for this cluster' })).toBeTruthy()
  })

  it('sends the values file as the path, not the chart directory, when one proved the match', async () => {
    grantedCapabilities.add(CAP_REPO_READ)
    grantedCapabilities.add(CAP_REPO_WRITE)
    mockDiscoverRepositoryLink.mockResolvedValue({
      status: 'proven',
      candidates: [{ bindingId: 'rb_1', repoUrl: 'https://gitlab.internal.example/shop/shop-apps-helm.git', chartPath: 'charts/shop-apps', valuesFile: 'envs/prod/values-prod.yaml' }],
      releaseName: 'shop-apps-helm',
      namespace: 'shop',
      otherClusters: [],
    })
    mockConfirmRepositoryLink.mockResolvedValue({})
    mockGetIncident.mockResolvedValue(detailIncident({ ownership: helmOwnershipNoRepo }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const recommendationStage = await screen.findByRole('region', { name: /^Fix$/i })
    fireEvent.click(await within(recommendationStage).findByRole('button', { name: 'Link for this cluster' }))

    await waitFor(() => expect(mockConfirmRepositoryLink).toHaveBeenCalledTimes(1))
    expect(mockConfirmRepositoryLink.mock.calls[0][1]).toEqual({
      bindingId: 'rb_1',
      path: 'envs/prod/values-prod.yaml',
      scope: undefined,
    })
  })

  // Regression test for a real live finding (2026-09-09, against the actual
  // shop-apps-helm repository): a chart living at the repository root has
  // chartPath === '' — a real, valid candidate, not a missing one — and the
  // backend's confirm-repository-link 400s on an empty path, since '' reads
  // as "nothing chosen" rather than "the repository root". '.', not '',
  // must be sent, and the proof sentence must not render a blank <code></code>.
  it('sends "." for a chart at the repository root, never an empty path', async () => {
    grantedCapabilities.add(CAP_REPO_READ)
    grantedCapabilities.add(CAP_REPO_WRITE)
    mockDiscoverRepositoryLink.mockResolvedValue({
      status: 'proven',
      candidates: [{ bindingId: 'rb_1', repoUrl: 'https://gitlab.internal.example/shop/shop-apps-helm.git', chartPath: '', valuesFile: '' }],
      releaseName: 'shop-apps-helm',
      namespace: 'shop',
      otherClusters: [],
    })
    mockConfirmRepositoryLink.mockResolvedValue({})
    mockGetIncident.mockResolvedValue(detailIncident({ ownership: helmOwnershipNoRepo }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const recommendationStage = await screen.findByRole('region', { name: /^Fix$/i })
    expect(await within(recommendationStage).findByText(/\(repository root\)/i)).toBeTruthy()

    fireEvent.click(within(recommendationStage).getByRole('button', { name: 'Link for this cluster' }))

    await waitFor(() => expect(mockConfirmRepositoryLink).toHaveBeenCalledTimes(1))
    expect(mockConfirmRepositoryLink.mock.calls[0][1]).toEqual({
      bindingId: 'rb_1',
      path: '.',
      scope: undefined,
    })
  })

  it('offers a named widen option when other clusters run the same release, and never a blind AllClusters', async () => {
    grantedCapabilities.add(CAP_REPO_READ)
    grantedCapabilities.add(CAP_REPO_WRITE)
    mockDiscoverRepositoryLink.mockResolvedValue({
      status: 'proven',
      candidates: [{ bindingId: 'rb_1', repoUrl: 'https://gitlab.internal.example/shop/shop-apps-helm.git', chartPath: 'charts/shop-apps', valuesFile: '' }],
      releaseName: 'shop-apps-helm',
      namespace: 'shop',
      otherClusters: [
        { clusterId: 'cl_2', clusterDisplayName: 'shop-staging' },
        { clusterId: 'cl_3', clusterDisplayName: 'shop-prod' },
      ],
    })
    mockConfirmRepositoryLink.mockResolvedValue({})
    mockGetIncident.mockResolvedValue(detailIncident({ ownership: helmOwnershipNoRepo }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const recommendationStage = await screen.findByRole('region', { name: /^Fix$/i })
    const widenButton = await within(recommendationStage).findByRole('button', {
      name: 'Link for all 3 clusters running shop-apps-helm',
    })
    // The clusters it would cover are named, not left as a bare "all clusters" claim.
    expect(widenButton.title).toMatch(/shop-staging/)
    expect(widenButton.title).toMatch(/shop-prod/)

    fireEvent.click(widenButton)
    await waitFor(() => expect(mockConfirmRepositoryLink).toHaveBeenCalledTimes(1))
    expect(mockConfirmRepositoryLink.mock.calls[0][1]).toEqual({
      bindingId: 'rb_1',
      path: 'charts/shop-apps',
      scope: { type: 'AllClusters' },
    })
  })

  it('presents every candidate and picks none when the discovery is ambiguous', async () => {
    grantedCapabilities.add(CAP_REPO_READ)
    grantedCapabilities.add(CAP_REPO_WRITE)
    mockDiscoverRepositoryLink.mockResolvedValue({
      status: 'ambiguous',
      candidates: [
        { bindingId: 'rb_1', repoUrl: 'https://gitlab.internal.example/shop/shop-apps-helm.git', chartPath: 'charts/shop-apps', valuesFile: '' },
        { bindingId: 'rb_2', repoUrl: 'https://gitlab.internal.example/shop/shop-apps-fork.git', chartPath: 'charts/shop-apps', valuesFile: '' },
      ],
      releaseName: 'shop-apps-helm',
      namespace: 'shop',
      otherClusters: [],
    })
    mockGetIncident.mockResolvedValue(detailIncident({ ownership: helmOwnershipNoRepo }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const recommendationStage = await screen.findByRole('region', { name: /^Fix$/i })
    expect(await within(recommendationStage).findByText(/ARGUS found 2 repositories/i)).toBeTruthy()
    expect(within(recommendationStage).getByText('https://gitlab.internal.example/shop/shop-apps-helm.git')).toBeTruthy()
    expect(within(recommendationStage).getByText('https://gitlab.internal.example/shop/shop-apps-fork.git')).toBeTruthy()
    // No widen offer while ambiguous — which repository is right is still unresolved.
    expect(within(recommendationStage).queryByText(/all \d+ clusters running/i)).toBeNull()
    expect(within(recommendationStage).getAllByRole('button', { name: 'Link for this cluster' })).toHaveLength(2)
  })

  it('reports a real negative, distinct from could-not-verify, when no repository renders the object', async () => {
    grantedCapabilities.add(CAP_REPO_READ)
    mockDiscoverRepositoryLink.mockResolvedValue({
      status: 'none',
      candidates: [],
      releaseName: 'cert-manager',
      namespace: 'cert-manager',
      otherClusters: [],
    })
    mockGetIncident.mockResolvedValue(detailIncident({ ownership: { ...helmOwnershipNoRepo, sourceName: 'cert-manager', sourceNamespace: 'cert-manager' } }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const recommendationStage = await screen.findByRole('region', { name: /^Fix$/i })
    expect(await within(recommendationStage).findByText(/no registered repository renders this object/i)).toBeTruthy()
    expect(within(recommendationStage).queryByText(/could not verify/i)).toBeNull()
  })

  it('reports could-not-verify, never conflated with the real negative, when nothing could be rendered', async () => {
    grantedCapabilities.add(CAP_REPO_READ)
    mockDiscoverRepositoryLink.mockResolvedValue({
      status: 'degraded',
      candidates: [],
      degraded: 'no render sandbox is configured on this hub, so a link cannot be proven by rendering',
      releaseName: 'shop-apps-helm',
      namespace: 'shop',
      otherClusters: [],
    })
    mockGetIncident.mockResolvedValue(detailIncident({ ownership: helmOwnershipNoRepo }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const recommendationStage = await screen.findByRole('region', { name: /^Fix$/i })
    expect(await within(recommendationStage).findByText(/Could not verify — no render sandbox is configured/i)).toBeTruthy()
    expect(within(recommendationStage).queryByText(/no registered repository renders this object/i)).toBeNull()
  })

  it('shows a quiet notice, with no controls, once this release has been declined', async () => {
    grantedCapabilities.add(CAP_REPO_READ)
    mockDiscoverRepositoryLink.mockResolvedValue({
      status: 'declined',
      candidates: [],
      releaseName: 'shop-apps-helm',
      namespace: 'shop',
      otherClusters: [],
    })
    mockGetIncident.mockResolvedValue(detailIncident({ ownership: helmOwnershipNoRepo }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const recommendationStage = await screen.findByRole('region', { name: /^Fix$/i })
    expect(await within(recommendationStage).findByText(/previously declined/i)).toBeTruthy()
    expect(within(recommendationStage).queryByRole('button', { name: /link|ask again/i })).toBeNull()
  })

  it('records a decline and does not claim anything was linked', async () => {
    grantedCapabilities.add(CAP_REPO_READ)
    grantedCapabilities.add(CAP_REPO_WRITE)
    mockDiscoverRepositoryLink.mockResolvedValue({
      status: 'proven',
      candidates: [{ bindingId: 'rb_1', repoUrl: 'https://gitlab.internal.example/shop/shop-apps-helm.git', chartPath: 'charts/shop-apps', valuesFile: '' }],
      releaseName: 'shop-apps-helm',
      namespace: 'shop',
      otherClusters: [],
    })
    mockDeclineRepositoryLink.mockResolvedValue(undefined)
    mockGetIncident.mockResolvedValue(detailIncident({ ownership: helmOwnershipNoRepo }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const recommendationStage = await screen.findByRole('region', { name: /^Fix$/i })
    fireEvent.click(await within(recommendationStage).findByRole('button', { name: /don't ask again/i }))

    await waitFor(() => expect(mockDeclineRepositoryLink).toHaveBeenCalledWith('inc_1', 'test-token'))
    expect(within(recommendationStage).queryByText(/^Linked /i)).toBeNull()
  })

  it('disables the confirm and decline controls, not hidden, without repo:write', async () => {
    grantedCapabilities.add(CAP_REPO_READ)
    mockDiscoverRepositoryLink.mockResolvedValue({
      status: 'proven',
      candidates: [{ bindingId: 'rb_1', repoUrl: 'https://gitlab.internal.example/shop/shop-apps-helm.git', chartPath: 'charts/shop-apps', valuesFile: '' }],
      releaseName: 'shop-apps-helm',
      namespace: 'shop',
      otherClusters: [],
    })
    mockGetIncident.mockResolvedValue(detailIncident({ ownership: helmOwnershipNoRepo }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const recommendationStage = await screen.findByRole('region', { name: /^Fix$/i })
    expect(await within(recommendationStage).findByRole('button', { name: 'Link for this cluster' })).toHaveProperty('disabled', true)
    expect(within(recommendationStage).getByRole('button', { name: /don't ask again/i })).toHaveProperty('disabled', true)
  })

  it('disables the whole control, not hidden, without repo:read', async () => {
    mockGetIncident.mockResolvedValue(detailIncident({ ownership: helmOwnershipNoRepo }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const recommendationStage = await screen.findByRole('region', { name: /^Fix$/i })
    expect(await within(recommendationStage).findByText(new RegExp(CAP_REPO_READ))).toBeTruthy()
    expect(mockDiscoverRepositoryLink).not.toHaveBeenCalled()
  })

  // BACKLOG.md F30 owner decision 2026-09-09: a plain-manifest object — no
  // Helm release, no Argo CD/Flux controller — is matched the SAME way, by
  // rendering (here: parsing), with no operator-typed label selector.
  // `ownership` is null for this case (ObjectOwnership's own doc comment:
  // an unmanaged object is deliberately never summarized), so this whole
  // path is proof the form does not depend on `ownership` to appear or to
  // know what it is offering to link.
  it('is offered for an unmanaged plain-manifest object, discovers it by parsing (not rendering), and links it with one click', async () => {
    grantedCapabilities.add(CAP_REPO_READ)
    grantedCapabilities.add(CAP_REPO_WRITE)
    mockDiscoverRepositoryLink.mockResolvedValue({
      status: 'proven',
      candidates: [{ bindingId: 'rb_2', repoUrl: 'https://github.com/example/plain-manifests', chartPath: 'apps/nolimits/deployment.yaml' }],
      mode: 'manifest',
      releaseName: '',
      namespace: '',
      objectGvk: 'apps/v1/Deployment',
      objectNamespace: 'shop',
      objectName: 'nolimits',
      otherClusters: [],
    })
    mockConfirmRepositoryLink.mockResolvedValue({})
    // ownership: null — the exact state a plain-manifest object with no
    // controller and no Helm release reaches (see ObjectOwnership's own doc
    // comment); the default fixture's plan (scalePlan) is still an in-place
    // fix, so RecommendationChannels renders on that half alone.
    mockGetIncident.mockResolvedValue(detailIncident({ ownership: null }))
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    const recommendationStage = await screen.findByRole('region', { name: /^Fix$/i })
    expect(await within(recommendationStage).findByText(/Link this object to a repository/i)).toBeTruthy()
    expect(within(recommendationStage).getByText('Parsed — proven match')).toBeTruthy()
    expect(within(recommendationStage).getByText('apps/nolimits/deployment.yaml')).toBeTruthy()
    expect(within(recommendationStage).getByText('https://github.com/example/plain-manifests')).toBeTruthy()

    fireEvent.click(within(recommendationStage).getByRole('button', { name: 'Link for this cluster' }))

    await waitFor(() => expect(mockConfirmRepositoryLink).toHaveBeenCalledTimes(1))
    const [incidentId, body] = mockConfirmRepositoryLink.mock.calls[0]
    expect(incidentId).toBe('inc_1')
    // The exact file that was parsed and proven — never a typed label
    // selector or a release name, since a plain-manifest object has none.
    expect(body).toEqual({ bindingId: 'rb_2', path: 'apps/nolimits/deployment.yaml', scope: undefined })

    expect(await within(recommendationStage).findByText(/re-analyze/i)).toBeTruthy()
  })

  it('is not offered for an Argo CD-managed object even when its repo is somehow unresolved', async () => {
    mockGetIncident.mockResolvedValue(
      detailIncident({ ownership: { ...argocdOwnership, repo: undefined } }),
    )
    mockGetApprovals.mockResolvedValue({ approvals: [] })
    renderPage()

    await screen.findByRole('region', { name: /^Fix$/i })
    expect(mockDiscoverRepositoryLink).not.toHaveBeenCalled()
  })
})

// PROJECT.md #12 — the numbered 1-6 rail at the top of the page used to be
// accurate but not navigable: it named the right stage ("4 Approve — waiting
// on you") several screens above the control it was talking about, with no
// way to jump there. LifecycleRail already renders each entry as a real
// `<a href="#stage-N">` (see that component's own comment on why: keyboard-
// reachable, focusable, and works with the browser's own back/forward,
// unlike a div with an onClick) and StageCard's `<section id="stage-N">`
// carries `aria-labelledby`, giving it an implicit "region" landmark and
// name. What these tests pin down is the wiring between the two: every rail
// entry's href resolves to a section that actually exists on the page, and
// that section is a legitimate focus target — the two would this file did
// not previously mount before B172's own investigation reported that a
// pointer at #stage-4 that could not be assigned focus would land the
// browser's native scroll-to-fragment algorithm on the viewport instead,
// leaving a screen-reader user with a silent jump.
describe('IncidentDetailPage — lifecycle rail entries are real jump links (PROJECT.md #12)', () => {
  it('renders all six rail entries as links whose href targets an existing, focusable stage section', async () => {
    mockGetIncident.mockResolvedValue(detailIncident())
    mockGetApprovals.mockResolvedValue({ approvals: [approvalItemFor('inc_1', scalePlan)] })
    const { container } = renderPage()

    // Wait for the real page (not the loading skeleton) to have rendered —
    // the skeleton renders its own, non-link `.lifecycle-step` placeholders
    // with the identical box model (see LifecycleRail's own skeleton
    // comment), so asserting against the skeleton would prove nothing.
    await screen.findByRole('region', { name: /^Fix$/i })

    // Lifecycle redesign: the spine's phase names link to their cards — one
    // per card on the page (this incident has no "Did it hold" card yet).
    const railLinks = container.querySelectorAll('.lc-spine .lc-name a')
    expect(railLinks).toHaveLength(3)

    railLinks.forEach((link) => {
      // A real <a href>, not a div/onClick — this is what makes it keyboard-
      // reachable (native Tab order) and operable with Enter/Space without
      // any handler of this app's own.
      expect(link.tagName).toBe('A')
      const href = link.getAttribute('href')!
      expect(href).toMatch(/^#incident-/)

      const target = container.querySelector(href)
      expect(target).toBeTruthy()
      // tabIndex={-1}: out of normal Tab order (the rail is how you reach a
      // stage in order), but a legitimate focus target for the browser's own
      // scroll-to-fragment algorithm — which is what lets a click on this
      // link both scroll to and announce the section it names, with no JS
      // scroll handler of this app's own to fake or get wrong.
      expect(target?.getAttribute('tabindex')).toBe('-1')
      target?.dispatchEvent(new Event('focus'))
      ;(target as HTMLElement).focus()
      expect(document.activeElement).toBe(target)
    })
  })

  it("clicking a rail entry navigates — the click is never intercepted by a handler of this app's own", async () => {
    mockGetIncident.mockResolvedValue(detailIncident())
    mockGetApprovals.mockResolvedValue({ approvals: [approvalItemFor('inc_1', scalePlan)] })
    const { container } = renderPage()
    await screen.findByRole('region', { name: /^Fix$/i })

    const approveLink = container.querySelector('a[href="#incident-fix"]')
    expect(approveLink).toBeTruthy()
    expect(approveLink!.getAttribute('href')).toBe('#incident-fix')

    // fireEvent.click returns false only if something called
    // preventDefault() on the click. LifecycleRail carries no onClick at
    // all (see that component's own comment: "the whole step is the
    // control, so it is an <a> rather than a click handler on a div") — so
    // this click is left to the browser's real, native same-document
    // fragment navigation (which is what runs the scroll-to-fragment/focus
    // algorithm outside this environment), not simulated or intercepted by
    // any JS of this app's own.
    const notPrevented = fireEvent.click(approveLink!)
    expect(notPrevented).toBe(true)
  })
})

/** A minimal, valid ToolCall for corroboration fixtures below. */
function toolCall(over: Partial<ToolCall> = {}): ToolCall {
  return { tool: 'get_events', args: {}, result: {}, error: null, ...over }
}

/** A minimal, valid AnalysisStep carrying the given tool calls. */
function stepWithCalls(calls: ToolCall[]): AnalysisStep {
  return { step: 1, hypothesis: 'Checked recent events', finding: 'Found the relevant event', toolCalls: calls }
}

// PROJECT.md #7 — the approval card used to headline a bare, precise-looking
// "95% confidence (high)" for a figure that is the model's own unchecked
// self-report (InsightsPage's "Confidence calibration curve" is listed as
// planned, not built — nothing yet grades this number against a real
// outcome). The fix keeps the band as the one honest word this figure
// supports, moves the exact percentage to `title` (this product's existing
// place for a precise value behind a humanised one), and pairs it with
// evidence quality — the part of "how much should I trust this" that ARGUS
// actually verified, by re-checking each cited tool call against its own
// record of what it served (PROJECT.md B151). These tests exercise
// ApprovalDecisionCard as it is actually mounted here, at stage 4, rather
// than in isolation — this component is also ApprovalsPage's own row, so a
// change to it is a change to both screens' confidence line at once.
describe('IncidentDetailPage — the approval card states confidence as a band, not a bare percentage (PROJECT.md #7)', () => {
  it('shows the confidence band, the exact percentage only in a title, and a real citation count when every citation corroborated', async () => {
    mockGetIncident.mockResolvedValue(detailIncident())
    const item = approvalItemFor('inc_1', scalePlan)
    item.confidence = 0.82
    item.causalChainProvenance = 'self-reported'
    item.causalChain = [
      stepWithCalls([
        toolCall({ tool: 'get_events', corroborated: 'corroborated' }),
        toolCall({ tool: 'describe_resource', corroborated: 'corroborated' }),
      ]),
    ]
    mockGetApprovals.mockResolvedValue({ approvals: [item] })
    renderPage()

    const approveStage = await screen.findByRole('region', { name: /^Fix$/i })

    // The band is the headline; the old "82% confidence (high)" string is
    // gone entirely, not just reworded — asserting its absence is the point,
    // since a regression here would very plausibly re-add the number beside
    // the word rather than instead of it.
    const confidenceBadge = await within(approveStage).findByText('High confidence')
    expect(within(approveStage).queryByText(/82%\s*confidence/i)).toBeNull()
    // The exact figure is still genuinely available, just demoted to a title
    // — never deleted outright.
    expect(confidenceBadge.getAttribute('title')).toMatch(/82%/)

    // Evidence quality: the SAME per-citation verdicts, counted, not a
    // second independent score — 2 of this incident's 2 citations were
    // corroborated, and the line says exactly that rather than repeating the
    // word "corroborated" with no count the way the old single-badge version
    // did.
    expect(within(approveStage).getByText('2 of 2 citations corroborated')).toBeTruthy()
  })

  it('leads with "contradicted" over a mix of states, and states the count rather than only the worst word', async () => {
    mockGetIncident.mockResolvedValue(detailIncident())
    const item = approvalItemFor('inc_1', scalePlan)
    item.confidence = 0.6
    item.causalChainProvenance = 'self-reported'
    item.causalChain = [
      stepWithCalls([
        toolCall({ tool: 'get_events', corroborated: 'corroborated' }),
        toolCall({ tool: 'describe_resource', corroborated: 'contradicted' }),
        toolCall({ tool: 'get_logs', corroborated: 'unchecked' }),
      ]),
    ]
    mockGetApprovals.mockResolvedValue({ approvals: [item] })
    renderPage()

    const approveStage = await screen.findByRole('region', { name: /^Fix$/i })
    await within(approveStage).findByText('Medium confidence')
    // One contradicted citation must be impossible to miss regardless of how
    // many others corroborated cleanly (PROJECT.md D12) — worded as a count
    // against the real total, not "contradicted" alone with no sense of how
    // much of the evidence that implicates.
    expect(within(approveStage).getByText('1 of 3 citations contradicted')).toBeTruthy()
  })

  it('never renders "0 of 0 corroborated" for an incident with no cited tool calls', async () => {
    mockGetIncident.mockResolvedValue(detailIncident())
    const item = approvalItemFor('inc_1', scalePlan)
    item.confidence = 0.9
    item.causalChain = []
    mockGetApprovals.mockResolvedValue({ approvals: [item] })
    renderPage()

    const approveStage = await screen.findByRole('region', { name: /^Fix$/i })
    await within(approveStage).findByText('High confidence')
    expect(within(approveStage).queryByText(/0 of 0/i)).toBeNull()
    expect(within(approveStage).queryByText(/corroborated/i)).toBeNull()
    expect(within(approveStage).getByText('No evidence cited')).toBeTruthy()
  })

  it('says the evidence was directly observed, not corroborated, for a hub-observed chain — never "0 of N corroborated"', async () => {
    mockGetIncident.mockResolvedValue(detailIncident())
    const item = approvalItemFor('inc_1', scalePlan)
    item.confidence = 0.9
    // No causalChainProvenance set — 'hub-observed' by construction, the api
    // backend's own case (ToolCall.corroborated is always absent there).
    item.causalChain = [stepWithCalls([toolCall({ tool: 'get_events' }), toolCall({ tool: 'get_logs' })])]
    mockGetApprovals.mockResolvedValue({ approvals: [item] })
    renderPage()

    const approveStage = await screen.findByRole('region', { name: /^Fix$/i })
    await within(approveStage).findByText('High confidence')
    expect(within(approveStage).queryByText(/of 2 citations/i)).toBeNull()
    expect(within(approveStage).getByText('Hub-observed')).toBeTruthy()
  })

  it('says corroboration was never recorded for a self-reported chain stored before that check existed', async () => {
    mockGetIncident.mockResolvedValue(detailIncident())
    const item = approvalItemFor('inc_1', scalePlan)
    item.confidence = 0.9
    item.causalChainProvenance = 'self-reported'
    // Calls present, but none carry `corroborated` — the pre-PROJECT.md B151
    // shape.
    item.causalChain = [stepWithCalls([toolCall({ tool: 'get_events' })])]
    mockGetApprovals.mockResolvedValue({ approvals: [item] })
    renderPage()

    const approveStage = await screen.findByRole('region', { name: /^Fix$/i })
    await within(approveStage).findByText('High confidence')
    expect(within(approveStage).queryByText(/0 of/i)).toBeNull()
    expect(within(approveStage).getByText('Evidence quality not recorded')).toBeTruthy()
  })
})
