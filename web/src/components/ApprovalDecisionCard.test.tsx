import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ApprovalQueueItem, RemediationPlan } from '../api/types'
import { CAP_REMEDIATION_APPROVE, CAP_REMEDIATION_REJECT } from '../api/capabilities'

// BACKLOG P3. ApprovalsPage.test.tsx already exercises ApprovalDecisionCard
// indirectly through real queue data — the approve/reject mutations, the
// capability-gated Approve button, the reject-reason form. What it does NOT
// reach is the card's own two guardrail-refusal branches, both of which only
// appear after a first Approve attempt comes back refused from the hub:
//
//   - scale-from-zero: internal/api/remediation_exec.go's checkScaleFromZero
//     refuses to scale a workload up from a live replica count of 0 without
//     an explicit "yes, turn it back on" confirmation.
//   - GitOps-managed: migration 000049's supersededByUrl-adjacent guardrail —
//     approving an in-place plan against an object GitOps also owns is
//     refused until the operator explicitly accepts the revert-on-next-sync
//     risk ("Apply anyway — I will fix the source").
//
// Both are recognized by the ApiError's RFC 9457 `type`, never by matching
// message text (this file's own comment on refusalFromError), and the retry
// carries back the exact confirmationToken the refusal minted — so these
// tests pin the overrides object each confirm button actually sends, not
// just that "a button appeared."

const mockApproveIncident = vi.fn()
const mockRejectIncident = vi.fn()

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    approveIncident: (...args: unknown[]) => mockApproveIncident(...args),
    rejectIncident: (...args: unknown[]) => mockRejectIncident(...args),
  }
})

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ accessToken: 'test-token' }),
}))

const capabilities = new Set<string>([CAP_REMEDIATION_APPROVE, CAP_REMEDIATION_REJECT])
vi.mock('../auth/useCapabilities', () => ({
  useHasCapability: (capability: string) => capabilities.has(capability),
}))

import { ApprovalDecisionCard, ApprovalActionsWithoutQueue, needsApproveConfirmation } from './ApprovalDecisionCard'
import { ApiError, PROBLEM_GITOPS_MANAGED_REFUSED, PROBLEM_SCALE_FROM_ZERO_REFUSED } from '../api/client'

function scaleItem(over: Partial<ApprovalQueueItem> = {}): ApprovalQueueItem {
  return {
    incidentId: 'inc_scale',
    clusterId: 'cl_1',
    clusterDisplayName: 'prod-eu',
    fingerprint: 'fp_scale',
    severity: 'high',
    firstSeen: '2026-08-25T09:00:00Z',
    lastSeen: '2026-08-25T09:30:00Z',
    occurrenceCount: 4,
    plan: {
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
    },
    confidence: 0.8,
    rootCauseStatement: 'OOMKilled',
    causalChain: [],
    ruledOut: [],
    alreadyApproved: false,
    ...over,
  }
}

function renderCard(item: ApprovalQueueItem) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <ApprovalDecisionCard items={[item]} />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  mockApproveIncident.mockReset()
  mockRejectIncident.mockReset()
  capabilities.clear()
  capabilities.add(CAP_REMEDIATION_APPROVE)
  capabilities.add(CAP_REMEDIATION_REJECT)
})

// Finding 11's sibling instance. The row's "Waiting" figure is the age of the
// DECISION, so it must come from the plan, not from the incident's firstSeen —
// which on a long-running fault is weeks older and made this row claim an
// approver had ignored it since the fault was detected.
describe('ApprovalDecisionCard — the row age is the age of the wait', () => {
  it('measures the wait from the plan, not from the much older incident', () => {
    renderCard(
      scaleItem({
        firstSeen: '2026-07-15T00:00:00Z',
        plan: { ...scaleItem().plan, createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString() },
      }),
    )
    expect(screen.getByText(/Waiting 2h · 4 occurrences/i)).toBeTruthy()
  })

  it('states that the wait is not recorded rather than borrowing the incident age', () => {
    renderCard(
      scaleItem({
        firstSeen: '2026-07-15T00:00:00Z',
        plan: { ...scaleItem().plan, createdAt: '' },
      }),
    )
    expect(screen.getByText(/Waiting time not recorded · 4 occurrences/i)).toBeTruthy()
  })
})

describe('ApprovalDecisionCard — core fields render regardless of route', () => {
  it('renders the target, risk, route sentence, and the before/after diff', () => {
    renderCard(scaleItem())
    expect(screen.getByText('payments-api')).toBeTruthy()
    expect(screen.getByText('low risk')).toBeTruthy()
    expect(screen.getByText(/Approving patches the live object in this cluster now/i)).toBeTruthy()
    expect(screen.getByText('spec.replicas: 3')).toBeTruthy()
  })
})

// PROJECT.md D12 / #7: the evidence-quality line must be visible in the
// COLLAPSED view (no expand needed) whenever a self-reported causal chain
// carries a contradicted/unverified/unchecked citation. Unlike the old
// single-word badge this replaced, it now ALWAYS renders something — a
// hub-observed chain or an empty one used to render nothing at all here,
// which read as "nothing to report" rather than the true "nothing to check"
// (or "nothing was directly observed here, so there is nothing to
// cross-check" for the hub-observed case). "Why ARGUS proposed this" still
// carries the per-step detail, including ruled-out hypotheses.
describe('ApprovalDecisionCard — PROJECT.md D12/#7: evidence quality is visible without expanding', () => {
  it('shows a red, counted "contradicted" line in the collapsed view, and names it in the disclosure', () => {
    renderCard(
      scaleItem({
        causalChainProvenance: 'self-reported',
        causalChain: [
          {
            step: 1,
            hypothesis: 'sidecar env is wrong',
            finding: 'LOG_LEVEL should be debug',
            toolCalls: [
              { tool: 'describe_resource', args: {}, result: { LOG_LEVEL: 'info' }, error: null, corroborated: 'contradicted' },
            ],
          },
        ],
      }),
    )
    expect(screen.getByText('1 of 1 citation contradicted')).toBeTruthy()
    fireEvent.click(screen.getByText(/Why ARGUS proposed this/))
    expect(screen.getByText(/sidecar env is wrong/)).toBeTruthy()
    expect(screen.getByText(/describe_resource: contradicted/)).toBeTruthy()
  })

  it('says the chain was hub-observed rather than naming a corroboration count that would not mean anything there', () => {
    renderCard(
      scaleItem({
        causalChainProvenance: 'hub-observed',
        causalChain: [
          {
            step: 1,
            hypothesis: 'checked directly',
            finding: 'confirmed via describe_resource',
            toolCalls: [{ tool: 'describe_resource', args: {}, result: {}, error: null }],
          },
        ],
      }),
    )
    expect(screen.queryByText(/citation/)).toBeNull()
    expect(screen.getByText('Hub-observed')).toBeTruthy()
  })

  it('says no evidence was cited, rather than a fabricated "0 of 0", for an empty causal chain', () => {
    renderCard(scaleItem({ causalChainProvenance: 'self-reported', causalChain: [] }))
    expect(screen.queryByText(/0 of 0/)).toBeNull()
    expect(screen.getByText('No evidence cited')).toBeTruthy()
  })

  it('lists a ruled-out hypothesis inside the disclosure', () => {
    renderCard(
      scaleItem({
        causalChain: [],
        ruledOut: [{ hypothesis: 'ConfigMap missing', reason: 'confirmed present via describe_resource' }],
      }),
    )
    fireEvent.click(screen.getByText(/Why ARGUS proposed this/))
    expect(screen.getByText(/ConfigMap missing/)).toBeTruthy()
    expect(screen.getByText(/confirmed present via describe_resource/)).toBeTruthy()
  })
})

// BACKLOG D11 #1 — the worst defect the owner found: the risk badge showed
// the model's DECLARED risk even when internal/remediation's deterministic
// gate had overridden it, so the one element an approver glances at could
// flatly contradict the gate text right below it.
describe('ApprovalDecisionCard — BACKLOG D11 #1: the risk badge shows what the gate enforced', () => {
  it('badges the gate-ENFORCED risk, not the model-declared one, and states the declared value separately when they disagree', () => {
    renderCard(
      scaleItem({
        plan: {
          ...scaleItem().plan,
          riskLevel: 'low',
          effectiveRiskLevel: 'high',
          gateReason:
            'blocked from auto-approval by a hard safety floor: risk=high and reversible=false — high-risk, ' +
            'irreversible actions are never auto-approved regardless of confidence or policy',
        },
      }),
    )
    expect(screen.getByText('high risk')).toBeTruthy()
    expect(screen.queryByText('low risk')).toBeNull()
    expect(screen.getByText(/model declared low/i)).toBeTruthy()
  })

  it('shows only the enforced badge, with no "model declared" note, when the gate and the model agree', () => {
    renderCard(scaleItem())
    expect(screen.getByText('low risk')).toBeTruthy()
    expect(screen.queryByText(/model declared/i)).toBeNull()
  })
})

describe('ApprovalDecisionCard — BACKLOG D11 #3: the gate reason reads as a phrase first', () => {
  it('splits a nested gate reason into a glanceable headline, with the elaboration reachable but not inline', () => {
    renderCard(
      scaleItem({
        plan: {
          ...scaleItem().plan,
          gateReason:
            'blocked from auto-approval by a hard safety floor: risk=high and reversible=false — high-risk, ' +
            'irreversible actions are never auto-approved regardless of confidence or policy',
        },
      }),
    )
    expect(
      screen.getByText(/blocked from auto-approval by a hard safety floor: risk=high and reversible=false/i),
    ).toBeTruthy()
    // Not deleted (BACKLOG D11's "do not fix this by hiding the honesty"
    // constraint) — reachable behind an explicit disclosure.
    expect(screen.getByText('Full gate reasoning')).toBeTruthy()
    expect(screen.getByText(/irreversible actions are never auto-approved/i)).toBeTruthy()
  })

  it('shows a short reason whole, with no expand control, when there is nothing left to nest', () => {
    renderCard(
      scaleItem({
        plan: { ...scaleItem().plan, gateReason: "confidence 0.32 is below this policy's auto-approve threshold 0.40" },
      }),
    )
    expect(screen.getByText(/confidence 0.32 is below this policy's auto-approve threshold 0.40/i)).toBeTruthy()
    expect(screen.queryByText('Full gate reasoning')).toBeNull()
  })
})

describe('ApprovalDecisionCard — BACKLOG D11 #5: readable labels, never the raw wire value', () => {
  it('renders the action type and the gate outcome in plain language', () => {
    renderCard(scaleItem())
    expect(screen.queryByText('ScaleDeployment')).toBeNull()
    expect(screen.getByText('Scale deployment')).toBeTruthy()
    expect(screen.queryByText('NeedsApproval')).toBeNull()
    expect(screen.getByText(/Needs your approval/i)).toBeTruthy()
  })
})

describe('ApprovalDecisionCard — BACKLOG D11 #4: what happens if I decline or do nothing', () => {
  it('states the verified consequence once, for a decision still awaiting one', () => {
    renderCard(scaleItem())
    expect(screen.getByText(/the incident is dismissed/i)).toBeTruthy()
    expect(screen.getByText(/re-notifies at 48 hours/i)).toBeTruthy()
  })

  it('omits the consequence note once the decision is already made — there is nothing left to decline', () => {
    renderCard(scaleItem({ alreadyApproved: true }))
    expect(screen.queryByText(/the incident is dismissed/i)).toBeNull()
  })

  it('never claims "it never auto-approves" for a gate outcome that CAN auto-execute unattended', () => {
    // internal/api/unattended.go's RunUnattendedExecutor sweeps exactly
    // gate_outcome='AutoApprove' rows sitting at AwaitingApproval and
    // executes them with no human — asserting "it never auto-approves" here
    // would be false for this exact row.
    renderCard(scaleItem({ plan: { ...scaleItem().plan, gateOutcome: 'AutoApprove' } }))
    expect(screen.queryByText(/it never auto-approves/i)).toBeNull()
    expect(screen.getByText(/eligible for unattended execution/i)).toBeTruthy()
  })
})

// BACKLOG D11 #6: "three orphaned-pod deletions is one judgement about a
// policy, not three about pods." ApprovalDecisionCard trusts its `items`
// prop as already grouped (ApprovalsPage's own job); this exercises what the
// card does with more than one same-shape item.
describe('ApprovalDecisionCard — BACKLOG D11 #6: a collapsed group of same-shape decisions', () => {
  function podDeleteItem(over: Partial<ApprovalQueueItem> = {}): ApprovalQueueItem {
    const plan: RemediationPlan = {
      id: 'plan_pod_a',
      // internal/remediation.ActionType's real wire value — RemediationActionType
      // (api/types.ts) is a known-stale union that omits it; see
      // ACTION_TYPE_LABEL's own comment in ApprovalDecisionCard.tsx.
      actionType: 'DeleteResource' as unknown as RemediationPlan['actionType'],
      targetGvk: 'v1/Pod',
      targetNamespace: 'kube-system',
      targetName: 'orphaned-pod-a',
      params: {},
      reversible: false,
      riskLevel: 'high',
      effectiveRiskLevel: 'high',
      summary: 'Delete kube-system/orphaned-pod-a',
      gateOutcome: 'NeedsApproval',
      gateReason:
        'DeleteResource is approval-only by construction: it is never auto-approved at any confidence, under any policy',
      createdAt: '2026-08-25T09:00:00Z',
    }
    return {
      incidentId: 'inc_pod_a',
      clusterId: 'cl_1',
      clusterDisplayName: 'prod-eu',
      fingerprint: 'fp_pod_a',
      severity: 'low',
      firstSeen: '2026-08-25T09:00:00Z',
      lastSeen: '2026-08-25T09:30:00Z',
      occurrenceCount: 1,
      plan,
      confidence: 0.9,
      rootCauseStatement: 'Completed pod with no owner reference.',
      causalChain: [],
      ruledOut: [],
      alreadyApproved: false,
      ...over,
    }
  }

  it('renders the shared explanation once, and one identity plus one live Approve/Reject pair per member', () => {
    const itemA = podDeleteItem()
    const itemB = podDeleteItem({
      incidentId: 'inc_pod_b',
      fingerprint: 'fp_pod_b',
      plan: { ...podDeleteItem().plan, id: 'plan_pod_b', targetName: 'orphaned-pod-b', summary: 'Delete kube-system/orphaned-pod-b' },
    })
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <ApprovalDecisionCard items={[itemA, itemB]} />
        </MemoryRouter>
      </QueryClientProvider>,
    )

    expect(screen.getByText('2 matching decisions')).toBeTruthy()
    // The shared action-type badge appears exactly once, not once per pod.
    expect(screen.getAllByText('Delete resource').length).toBe(1)
    // Each member still gets its own identity and its own live decision.
    expect(screen.getByText('orphaned-pod-a')).toBeTruthy()
    expect(screen.getByText('orphaned-pod-b')).toBeTruthy()
    expect(screen.getAllByRole('button', { name: /^Approve$/i }).length).toBe(2)
  })
})

describe('ApprovalDecisionCard — the scale-from-zero refusal-and-confirm branch', () => {
  it('a first Approve that the hub refuses for scale-from-zero shows the hub\'s own message and a dedicated confirm button, not the plain Approve button', async () => {
    mockApproveIncident.mockRejectedValueOnce(
      new ApiError(
        'Refused',
        409,
        'payments-api is currently at 0 replicas — this looks intentionally switched off',
        PROBLEM_SCALE_FROM_ZERO_REFUSED,
        'tok_scale_zero',
      ),
    )
    renderCard(scaleItem())

    fireEvent.click(screen.getByRole('button', { name: /^Approve$/i }))

    const banner = await screen.findByRole('alert')
    expect(banner.textContent).toMatch(/currently at 0 replicas/i)
    expect(screen.queryByRole('button', { name: /^Approve$/i })).toBeNull()
    expect(screen.getByRole('button', { name: /Yes — turn it back on/i })).toBeTruthy()
    expect(screen.getByRole('button', { name: /Leave it switched off/i })).toBeTruthy()
  })

  it('confirming resubmits with confirmScaleFromZero and the exact confirmationToken the refusal minted', async () => {
    mockApproveIncident.mockRejectedValueOnce(
      new ApiError('Refused', 409, 'at 0 replicas', PROBLEM_SCALE_FROM_ZERO_REFUSED, 'tok_scale_zero'),
    )
    mockApproveIncident.mockResolvedValueOnce({
      incidentId: 'inc_scale',
      planId: 'plan_scale',
      verdict: 'approved',
      incidentState: 'Validating',
      message: 'Scaled payments-api to 3 replicas.',
    })
    renderCard(scaleItem())

    fireEvent.click(screen.getByRole('button', { name: /^Approve$/i }))
    await screen.findByRole('button', { name: /Yes — turn it back on/i })

    fireEvent.click(screen.getByRole('button', { name: /Yes — turn it back on/i }))

    await waitFor(() =>
      expect(mockApproveIncident).toHaveBeenNthCalledWith(2, 'inc_scale', 'test-token', {
        confirmScaleFromZero: true,
        confirmationToken: 'tok_scale_zero',
      }),
    )
    expect(await screen.findByText(/Scaled payments-api to 3 replicas/i)).toBeTruthy()
  })

  it('declining clears the refusal banner and returns to the plain Approve/Reject buttons', async () => {
    mockApproveIncident.mockRejectedValueOnce(
      new ApiError('Refused', 409, 'at 0 replicas', PROBLEM_SCALE_FROM_ZERO_REFUSED, 'tok_scale_zero'),
    )
    renderCard(scaleItem())

    fireEvent.click(screen.getByRole('button', { name: /^Approve$/i }))
    await screen.findByRole('button', { name: /Leave it switched off/i })

    fireEvent.click(screen.getByRole('button', { name: /Leave it switched off/i }))

    expect(await screen.findByRole('button', { name: /^Approve$/i })).toBeTruthy()
    expect(screen.queryByRole('button', { name: /Yes — turn it back on/i })).toBeNull()
    expect(screen.queryByRole('alert')).toBeNull()
    expect(mockApproveIncident).toHaveBeenCalledTimes(1)
  })
})

describe('ApprovalDecisionCard — the GitOps-managed refusal-and-confirm branch', () => {
  it('a first Approve refused as GitOps-managed offers "Apply anyway" rather than the scale-from-zero wording', async () => {
    mockApproveIncident.mockRejectedValueOnce(
      new ApiError(
        'Refused',
        409,
        'payments-api is managed by Argo CD application payments-prod',
        PROBLEM_GITOPS_MANAGED_REFUSED,
        'tok_gitops',
      ),
    )
    renderCard(scaleItem())

    fireEvent.click(screen.getByRole('button', { name: /^Approve$/i }))

    const banner = await screen.findByRole('alert')
    expect(banner.textContent).toMatch(/managed by Argo CD application payments-prod/i)
    expect(screen.getByRole('button', { name: /Apply anyway — I will fix the source/i })).toBeTruthy()
    expect(screen.getByRole('button', { name: /Cancel — fix the source instead/i })).toBeTruthy()
    expect(screen.queryByRole('button', { name: /Yes — turn it back on/i })).toBeNull()
  })

  it('confirming resubmits with confirmGitOpsManaged and that refusal\'s own confirmationToken', async () => {
    mockApproveIncident.mockRejectedValueOnce(
      new ApiError('Refused', 409, 'managed by GitOps', PROBLEM_GITOPS_MANAGED_REFUSED, 'tok_gitops'),
    )
    mockApproveIncident.mockResolvedValueOnce({
      incidentId: 'inc_scale',
      planId: 'plan_scale',
      verdict: 'approved',
      incidentState: 'Validating',
      message: 'Applied despite GitOps management.',
    })
    renderCard(scaleItem())

    fireEvent.click(screen.getByRole('button', { name: /^Approve$/i }))
    await screen.findByRole('button', { name: /Apply anyway — I will fix the source/i })

    fireEvent.click(screen.getByRole('button', { name: /Apply anyway — I will fix the source/i }))

    await waitFor(() =>
      expect(mockApproveIncident).toHaveBeenNthCalledWith(2, 'inc_scale', 'test-token', {
        confirmGitOpsManaged: true,
        confirmationToken: 'tok_gitops',
      }),
    )
    expect(await screen.findByText(/Applied despite GitOps management/i)).toBeTruthy()
  })

  it('a refusal-confirm button is disabled with the missing-capability reason if approve capability is lost mid-flow, matching the plain Approve button\'s own rule', async () => {
    mockApproveIncident.mockRejectedValueOnce(
      new ApiError('Refused', 409, 'managed by GitOps', PROBLEM_GITOPS_MANAGED_REFUSED, 'tok_gitops'),
    )
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    // A named component, not a saved JSX literal: rerender() with the exact
    // same element object lets React bail out of the whole subtree (same
    // props, same reference), which would make this "pass" without
    // useHasCapability ever being re-evaluated — a false negative that told
    // nothing about the real disabled logic. <Tree /> forces a fresh element
    // each call, matching how a real prop/context change would actually
    // trigger a re-render.
    function Tree() {
      return (
        <QueryClientProvider client={queryClient}>
          <MemoryRouter>
            <ApprovalDecisionCard items={[scaleItem()]} />
          </MemoryRouter>
        </QueryClientProvider>
      )
    }
    const { rerender } = render(<Tree />)

    fireEvent.click(screen.getByRole('button', { name: /^Approve$/i }))
    await screen.findByRole('button', { name: /Apply anyway — I will fix the source/i })

    // Reached the refusal state while still capable; now the grant is lost
    // (e.g. an admin revoked it mid-session) and the tree re-renders — the
    // confirm button must go the same disabled-with-a-reason route the plain
    // Approve button already takes, never a silent re-enable.
    capabilities.delete(CAP_REMEDIATION_APPROVE)
    rerender(<Tree />)

    const confirmButton = screen.getByRole('button', { name: /Apply anyway — I will fix the source/i })
    expect(confirmButton).toHaveProperty('disabled', true)
  })
})

describe('ApprovalDecisionCard — already-decided and superseded states never show live buttons', () => {
  it('a superseded plan explains the pull request supersedes it, with no Approve/Reject buttons', () => {
    renderCard(scaleItem({ supersededByUrl: 'https://github.com/example/repo/pull/42' }))
    expect(screen.getByText(/Superseded by a pull request/i)).toBeTruthy()
    expect(screen.queryByRole('button', { name: /^Approve$/i })).toBeNull()
    expect(screen.queryByRole('button', { name: /^Reject$/i })).toBeNull()
  })

  it('an already-approved plan shows the decided badge, not live buttons', () => {
    renderCard(scaleItem({ alreadyApproved: true }))
    expect(screen.getByText(/Approved · pull request open/i)).toBeTruthy()
    expect(screen.queryByRole('button', { name: /^Approve$/i })).toBeNull()
  })
})

// Live QA, 2026-10-11: on a cluster with no remediation agent connected the
// Approve button was enabled and fired an execution that could only fail at
// the dry run. The "may this plan execute" gate is the hub's
// executionBlockedReason, rendered beside the disabled button — and worded as a
// fact about the cluster, never as a missing capability.
describe('ApprovalDecisionCard — the may-this-plan-execute gate', () => {
  const blocked = 'lab-dev has no remediation agent connected, so ARGUS cannot change anything on it.'

  it('disables Approve and states the backend reason beside it', () => {
    renderCard(scaleItem({ executionBlockedReason: blocked }))
    const approve = screen.getByRole('button', { name: 'Approve' }) as HTMLButtonElement
    expect(approve.disabled).toBe(true)
    // One line beside the button, the hub's full sentence one click away.
    const note = screen.getByRole('note')
    expect(note.textContent).toMatch(/Cannot execute yet — lab-dev has no remediation agent connected/)
    expect(screen.queryByText(/You do not hold/)).toBeNull()
    fireEvent.click(approve)
    expect(mockApproveIncident).not.toHaveBeenCalled()
  })

  it('disables Preview change for the same reason', () => {
    renderCard(scaleItem({ executionBlockedReason: blocked }))
    expect((screen.getByRole('button', { name: 'Preview change' }) as HTMLButtonElement).disabled).toBe(true)
  })

  it('keeps Approve enabled when nothing blocks execution', () => {
    renderCard(scaleItem())
    expect((screen.getByRole('button', { name: 'Approve' }) as HTMLButtonElement).disabled).toBe(false)
  })
})

function deleteItem(over: Partial<RemediationPlan> = {}): ApprovalQueueItem {
  return scaleItem({
    plan: {
      ...scaleItem().plan,
      actionType: 'DeleteResource',
      targetGvk: 'v1/Pod',
      targetNamespace: 'apps',
      targetName: 'gwas-frontend-86c9b566b8-thvcf',
      params: {},
      reversible: false,
      riskLevel: 'high',
      effectiveRiskLevel: 'high',
      summary: 'Delete apps/gwas-frontend-86c9b566b8-thvcf',
      ...over,
    } as RemediationPlan,
  })
}

describe('ApprovalDecisionCard — a high-risk or irreversible plan confirms first', () => {
  it('opens a confirmation restating the verb, the target and that it cannot be undone', async () => {
    mockApproveIncident.mockResolvedValue({ message: 'Executed' })
    renderCard(deleteItem())
    fireEvent.click(screen.getByRole('button', { name: 'Approve' }))
    expect(mockApproveIncident).not.toHaveBeenCalled()
    const dialog = screen.getByRole('dialog')
    expect(dialog.textContent).toMatch(/delete Pod apps\/gwas-frontend-86c9b566b8-thvcf/)
    expect(dialog.textContent).toMatch(/prod-eu/)
    expect(dialog.textContent).toMatch(/cannot be undone/i)
    fireEvent.click(screen.getByRole('button', { name: 'Approve and delete' }))
    await waitFor(() => expect(mockApproveIncident).toHaveBeenCalledWith('inc_scale', 'test-token', {}))
  })

  it('cancelling sends nothing', () => {
    renderCard(deleteItem())
    fireEvent.click(screen.getByRole('button', { name: 'Approve' }))
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(mockApproveIncident).not.toHaveBeenCalled()
  })

  it('a low-risk reversible plan stays a single click', async () => {
    mockApproveIncident.mockResolvedValue({ message: 'Executed' })
    renderCard(scaleItem())
    fireEvent.click(screen.getByRole('button', { name: 'Approve' }))
    expect(screen.queryByRole('dialog')).toBeNull()
    await waitFor(() => expect(mockApproveIncident).toHaveBeenCalledTimes(1))
  })

  it('says a DeleteResource approval deletes, not patches', () => {
    renderCard(deleteItem())
    expect(screen.getByText(/Approving deletes this object from the cluster now/)).toBeTruthy()
    expect(screen.queryByText(/Approving patches the live object/)).toBeNull()
  })
})

describe('needsApproveConfirmation', () => {
  it('asks for high risk or irreversible in-place plans only', () => {
    const base = scaleItem().plan
    expect(needsApproveConfirmation(base)).toBe(false)
    expect(needsApproveConfirmation({ ...base, effectiveRiskLevel: 'high' })).toBe(true)
    expect(needsApproveConfirmation({ ...base, reversible: false })).toBe(true)
    expect(needsApproveConfirmation({ ...base, actionType: 'OpenPR', reversible: false, effectiveRiskLevel: 'high' })).toBe(false)
  })
})

// The incident page's decision pair for a viewer without remediation:approve
// (GET /approvals needs that capability, so there is no queue item to render).
describe('ApprovalActionsWithoutQueue', () => {
  function renderPair() {
    const queryClient = new QueryClient()
    return render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <ApprovalActionsWithoutQueue incidentId="inc_1" />
        </MemoryRouter>
      </QueryClientProvider>,
    )
  }

  it('names the capability each route needs and links nowhere the viewer cannot open', () => {
    capabilities.clear()
    renderPair()
    expect(screen.getByRole('button', { name: 'Approve' }).getAttribute('title')).toBe(`Missing capability: ${CAP_REMEDIATION_APPROVE}`)
    expect(screen.getByRole('button', { name: 'Reject' }).getAttribute('title')).toBe(`Missing capability: ${CAP_REMEDIATION_REJECT}`)
    expect(screen.queryByRole('link')).toBeNull()
  })

  it('lets a viewer who holds only remediation:reject reject', () => {
    capabilities.clear()
    capabilities.add(CAP_REMEDIATION_REJECT)
    renderPair()
    const reject = screen.getByRole('button', { name: 'Reject' }) as HTMLButtonElement
    expect(reject.disabled).toBe(false)
    fireEvent.click(reject)
    expect(screen.getByLabelText(/Reason for rejecting/)).toBeTruthy()
  })
})
