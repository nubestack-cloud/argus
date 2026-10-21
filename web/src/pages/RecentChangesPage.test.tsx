import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

import type { Change, ChangesResponse } from '../api/types'
import {
  CAP_ANALYSIS_READ,
  CAP_INCIDENT_READ,
  CAP_REMEDIATION_EXECUTE_INPLACE,
  CAP_REMEDIATION_ROLLBACK,
} from '../api/capabilities'

// The front door for undo. What these tests hold onto, in order of how much
// damage getting it wrong would do:
//
//  1. The undo control is DISABLED WITH THE MISSING CAPABILITY NAMED, never
//     hidden (lld/11 §6). Hiding it is the safety-critical finding in this
//     codebase, and the specific way it gets reintroduced is a refactor
//     "tidying" the disabled branch into a conditional render.
//  2. An undo the hub would refuse is not offered, and the hub's own reason is
//     shown instead of a paraphrase of it.
//  3. The three empty states read differently. "No changes in this window" and
//     "ARGUS has never changed anything" are different facts with different
//     next actions, and collapsing them is the most common half-built case
//     here.
//  4. No fabricated zero, and no unlabelled partial.

const mockListChanges = vi.fn()
const mockGetClusters = vi.fn()
const mockRollbackExecution = vi.fn()

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    listChanges: (...args: unknown[]) => mockListChanges(...args),
    getClusters: (...args: unknown[]) => mockGetClusters(...args),
    rollbackExecution: (...args: unknown[]) => mockRollbackExecution(...args),
  }
})

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ accessToken: 'test-token' }),
}))

const capabilities = new Set<string>()
vi.mock('../auth/useCapabilities', () => ({
  useHasCapability: (capability: string) => capabilities.has(capability),
  // `resolved: true` mirrors the loaded state; the unresolved case is the
  // AppShell's concern (it is what stops "No access" flashing on every load)
  // and is asserted there.
  useMissingCapabilities: (caps: string[]) => ({
    resolved: true,
    missing: caps.filter((c) => !capabilities.has(c)),
  }),
}))

import { RecentChangesPage } from './RecentChangesPage'

function inPlaceChange(over: Partial<Change> = {}): Change {
  return {
    id: 'exec_1',
    kind: 'inPlace',
    status: 'landed',
    changedAt: new Date(Date.now() - 3600_000).toISOString(),
    clusterId: 'cl_1',
    clusterName: 'prod-eu',
    incidentId: 'inc_1',
    summary: 'Scale payments/payments-api to 3 replicas',
    targetGvk: 'apps/v1/Deployment',
    targetNamespace: 'payments',
    targetName: 'payments-api',
    outcome: 'succeeded',
    unattended: false,
    actorEmail: 'admin@example.com',
    undo: { available: true, executionId: 'exec_1', description: 'scale back to 1 replica(s)' },
    ...over,
  }
}

function response(over: Partial<ChangesResponse> = {}): ChangesResponse {
  return {
    changes: [inPlaceChange()],
    windowHours: 168,
    limit: 50,
    truncated: false,
    hasAnyChanges: true,
    ...over,
  }
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/changes']}>
        <RecentChangesPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  capabilities.clear()
  capabilities.add(CAP_INCIDENT_READ)
  capabilities.add(CAP_ANALYSIS_READ)
  capabilities.add(CAP_REMEDIATION_ROLLBACK)
  capabilities.add(CAP_REMEDIATION_EXECUTE_INPLACE)
  mockGetClusters.mockResolvedValue({ clusters: [{ id: 'cl_1', displayName: 'prod-eu' }] })
  mockListChanges.mockResolvedValue(response())
})

describe('RecentChangesPage — the undo control', () => {
  it('offers the undo, and the confirmation names the target and the exact consequence', async () => {
    renderPage()
    const undo = await screen.findByRole('button', { name: /Undo…/ })
    expect(undo).toHaveProperty('disabled', false)

    fireEvent.click(undo)
    const dialog = await screen.findByRole('dialog')
    // A one-click mutation of a production cluster is the thing this must not
    // be: the dialog has to state the cluster, the object and the value.
    expect(dialog.textContent).toMatch(/scale back to 1 replica\(s\)/)
    expect(dialog.textContent).toMatch(/payments\/payments-api/)
    expect(dialog.textContent).toMatch(/prod-eu/)
    // And it must not imply the incident is fixed by undoing it.
    expect(dialog.textContent).toMatch(/does not fix the original problem/i)
    expect(mockRollbackExecution).not.toHaveBeenCalled()
  })

  it('sends the rollback only on the confirming click, addressed by execution id', async () => {
    mockRollbackExecution.mockResolvedValue({
      executionId: 'exec_1',
      incidentId: 'inc_1',
      incidentState: 'Reopened',
      undid: 'scaled back to 1 replica(s)',
      message: 'ok',
    })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /Undo…/ }))
    fireEvent.click(await screen.findByRole('button', { name: /^Yes — / }))
    await waitFor(() => expect(mockRollbackExecution).toHaveBeenCalledTimes(1))
    expect(mockRollbackExecution.mock.calls[0][0]).toBe('exec_1')
  })

  it('renders the hub’s refusal in full when the undo fails, never a summary of it', async () => {
    const { ApiError } = await import('../api/client')
    mockRollbackExecution.mockRejectedValue(
      new ApiError(
        'Something else has changed this since ARGUS did',
        409,
        'ARGUS set this to "3" and it is now "5". Undoing would replace that with scale back to 1 replica(s).',
        'https://argus.io/errors/undo-value-changed',
      ),
    )
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /Undo…/ }))
    fireEvent.click(await screen.findByRole('button', { name: /^Yes — / }))
    expect(await screen.findByRole('alert')).toHaveProperty(
      'textContent',
      'ARGUS set this to "3" and it is now "5". Undoing would replace that with scale back to 1 replica(s).',
    )
  })

  it('DISABLES the undo and names the missing capabilities in human words — never hides it', async () => {
    capabilities.delete(CAP_REMEDIATION_ROLLBACK)
    capabilities.delete(CAP_REMEDIATION_EXECUTE_INPLACE)
    renderPage()
    const undo = await screen.findByRole('button', { name: /Undo…/ })
    expect(undo).toHaveProperty('disabled', true)

    // Human wording (item 13a), and the raw constants still present, because a
    // support request for "permission to undo things" is not actionable and a
    // request for `remediation:rollback` is.
    const reason = undo.getAttribute('title') ?? ''
    expect(reason).toMatch(/do not have permission/i)
    expect(reason).toMatch(/roll back a remediation/i)
    expect(reason).toContain('remediation:rollback')
    expect(reason).toContain('remediation:execute:inplace')
    // Readable without hovering: a title alone is unreachable by keyboard and
    // touch.
    expect(screen.getAllByText(new RegExp('remediation:rollback')).length).toBeGreaterThan(0)
  })

  it('shows the hub’s own refusal instead of a control when the change cannot be undone', async () => {
    mockListChanges.mockResolvedValue(
      response({
        changes: [
          inPlaceChange({
            outcome: 'failed',
            error: 'the apply was rejected',
            undo: {
              available: false,
              reason: 'This execution did not succeed, so there is nothing to undo',
              detail: 'execution exec_1 has outcome "failed". Re-analyse the incident.',
            },
          }),
        ],
      }),
    )
    renderPage()
    expect(await screen.findByText(/This execution did not succeed/)).toBeTruthy()
    // The detail carries the next action, so it is not dropped.
    expect(screen.getByText(/Re-analyse the incident\./)).toBeTruthy()
    expect(screen.queryByRole('button', { name: /Undo…/ })).toBeNull()
  })

  it('never offers an in-cluster undo for a merged pull request', async () => {
    mockListChanges.mockResolvedValue(
      response({
        changes: [
          {
            id: 'pr:inc_2',
            kind: 'pullRequest',
            status: 'landed',
            changedAt: new Date(Date.now() - 7200_000).toISOString(),
            clusterId: 'cl_1',
            clusterName: 'prod-eu',
            incidentId: 'inc_2',
            summary: 'Merged pull request #103 — apps/web/deployment.yaml',
            pullRequestNumber: 103,
            pullRequestUrl: 'https://example.invalid/pr/103',
            filePaths: ['apps/web/deployment.yaml'],
            unattended: false,
            undo: {
              available: false,
              reason: 'ARGUS cannot undo a merged pull request',
              detail: 'Reverting the merge commit is the reversal, and ARGUS does not open revert pull requests.',
            },
          },
        ],
      }),
    )
    renderPage()
    expect(await screen.findByText('ARGUS cannot undo a merged pull request')).toBeTruthy()
    expect(screen.queryByRole('button', { name: /Undo…/ })).toBeNull()
    // The channel is a word, not only a colour.
    expect(screen.getByText('Pull request')).toBeTruthy()
  })

  // An open pull request is on this feed (see internal/api/changes.go's header
  // for why), and every claim the merged row makes has to invert for it. These
  // assert the inversions individually rather than snapshotting the row,
  // because each one was a separate false statement the cell used to make
  // unconditionally.
  it('never presents an OPEN pull request as something that changed the cluster', async () => {
    mockListChanges.mockResolvedValue(
      response({
        changes: [
          {
            id: 'pr:inc_3',
            kind: 'pullRequest',
            status: 'proposed',
            proposedAt: new Date(Date.now() - 7200_000).toISOString(),
            clusterId: 'cl_1',
            clusterName: 'prod-eu',
            incidentId: 'inc_3',
            summary: 'Pull request #104 open, not yet merged — apps/api/deployment.yaml',
            targetGvk: 'apps/v1/Deployment',
            targetNamespace: 'argus-gitops-rke2',
            targetName: 'api',
            pullRequestNumber: 104,
            pullRequestUrl: 'https://example.invalid/pr/104',
            filePaths: ['apps/api/deployment.yaml'],
            unattended: false,
            undo: {
              available: false,
              reason: 'Nothing to undo — this has not changed anything',
              detail: 'This pull request is still open, so the cluster is unchanged and there is nothing to reverse.',
            },
          },
        ],
      }),
    )
    renderPage()
    // Gate on something only the ROW can produce. The page intro also contains
    // the words "Open — not merged" (it explains the badge), and it renders
    // immediately — so awaiting that string resolves against the intro while
    // the table is still a skeleton, and every synchronous assertion after it
    // runs too early.
    expect(await screen.findByText('argus-gitops-rke2/api')).toBeTruthy()
    // Not "Merged", which this cell used to render for every pull-request row.
    expect(within(screen.getByRole('table')).getByText('Open — not merged')).toBeTruthy()
    expect(screen.queryByText('Merged')).toBeNull()
    // Nobody applied it, and that is not the same as "not recorded here".
    expect(screen.getByText('Nobody yet')).toBeTruthy()
    expect(screen.queryByText('Not recorded here')).toBeNull()
    // The timestamp is labelled as an OPENED-at, never as a changed-at.
    expect(screen.getByText(/Opened/)).toBeTruthy()
    expect(screen.queryByText(/Changed/)).toBeNull()
    // Still reachable: the link to go and merge it is the point of listing it.
    expect(screen.getByRole('link', { name: '#104' }).getAttribute('href')).toBe('https://example.invalid/pr/104')
  })

  it('leads a repository change with the WORKLOAD, keeping the file beside it', async () => {
    mockListChanges.mockResolvedValue(
      response({
        changes: [
          {
            id: 'pr:inc_4',
            kind: 'pullRequest',
            status: 'landed',
            changedAt: new Date(Date.now() - 3600_000).toISOString(),
            clusterId: 'cl_1',
            clusterName: 'prod-eu',
            incidentId: 'inc_4',
            summary: 'Merged pull request #105 — apps/api/deployment.yaml',
            targetGvk: 'apps/v1/Deployment',
            targetNamespace: 'argus-gitops-rke2',
            targetName: 'api',
            pullRequestNumber: 105,
            filePaths: ['apps/api/deployment.yaml'],
            unattended: false,
            undo: { available: false, reason: 'ARGUS cannot undo a merged pull request' },
          },
        ],
      }),
    )
    renderPage()
    // "What changed on production" is answered with the workload, the same way
    // an in-place row answers it — not with a path the reader has to resolve.
    expect(await screen.findByText('argus-gitops-rke2/api')).toBeTruthy()
    // And the file is still there, because it is what physically changed.
    // getAllBy: the path appears on the identity line AND inside the hub's own
    // summary sentence, which is two correct renderings of one fact rather
    // than a duplicate to remove.
    expect(screen.getAllByText(/apps\/api\/deployment\.yaml/).length).toBeGreaterThan(0)
  })
})

describe('RecentChangesPage — the four states', () => {
  it('distinguishes "nothing has ever happened" from "nothing in this window"', async () => {
    mockListChanges.mockResolvedValue(response({ changes: [], hasAnyChanges: false }))
    const first = renderPage()
    expect(await screen.findByText(/has not changed anything yet/i)).toBeTruthy()
    first.unmount()

    mockListChanges.mockResolvedValue(response({ changes: [], hasAnyChanges: true }))
    renderPage()
    const windowEmpty = await screen.findByText(/No changes in the last 7 days/i)
    expect(windowEmpty).toBeTruthy()
    // The way out is stated, which is what makes it a different state and not
    // the same message with different words.
    expect(windowEmpty.textContent).toMatch(/widen the window/i)
  })

  it('renders the error’s problem detail, and an em dash rather than a zero count', async () => {
    const { ApiError } = await import('../api/client')
    mockListChanges.mockRejectedValue(
      new ApiError('Could not load recent changes', 500, '', 'https://argus.io/errors/internal'),
    )
    renderPage()
    expect(await screen.findByRole('alert')).toHaveProperty('textContent', 'Could not load recent changes')
    // A zero here would claim ARGUS changed nothing. It did not answer at all.
    expect(screen.queryByText(/0 changes/)).toBeNull()
    expect(screen.getByText('—')).toBeTruthy()
  })

  it('states the window with the count, and labels a truncated page as partial', async () => {
    mockListChanges.mockResolvedValue(response({ truncated: true }))
    renderPage()
    // "items", not "changes": a truncated page can hold merged changes and open
    // pull requests together, and the header counts what is on the list.
    expect(await screen.findByText(/More than 1 items in the last 7 days — showing the 1 most recent/)).toBeTruthy()
  })

  it('renders Restricted, not a zero, when the viewer may not read the list', async () => {
    capabilities.delete(CAP_ANALYSIS_READ)
    renderPage()
    expect(await screen.findByText('Restricted')).toBeTruthy()
    const alert = screen.getByRole('alert')
    expect(alert.textContent).toMatch(/do not have permission/i)
    expect(alert.textContent).toContain('analysis:read')
    // And the list is not fetched at all.
    expect(mockListChanges).not.toHaveBeenCalled()
  })
})

describe('RecentChangesPage — filters are request parameters', () => {
  it('sends the window and the cluster to the hub rather than filtering a capped page', async () => {
    renderPage()
    await screen.findByRole('button', { name: /Undo…/ })
    expect(mockListChanges.mock.calls[0][0]).toEqual({ windowHours: 168, clusterId: undefined })

    fireEvent.change(screen.getByLabelText('Time window'), { target: { value: '24' } })
    await waitFor(() =>
      expect(mockListChanges).toHaveBeenCalledWith({ windowHours: 24, clusterId: undefined }, 'test-token'),
    )

    fireEvent.change(screen.getByLabelText('Filter by cluster'), { target: { value: 'cl_1' } })
    await waitFor(() =>
      expect(mockListChanges).toHaveBeenCalledWith({ windowHours: 24, clusterId: 'cl_1' }, 'test-token'),
    )
  })
})
