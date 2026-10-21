import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

import type { OwnershipRepo, RemediationPlan } from '../api/types'
import { CAP_REMEDIATION_APPROVE, CAP_REMEDIATION_EXECUTE_PR, CAP_REPO_WRITE } from '../api/capabilities'
import { ApiError, PROBLEM_NOT_FOUND } from '../api/client'

// A repository change is a set of WHOLE FILES — one or many — against any
// repository kind. What these tests are for is not "a textarea works": it is
// that the panel makes exactly the claims the hub made and no more. Three
// things in particular, because each was a real dishonesty this rewrite removed
// or a real cap it lifted:
//
//   1. Nothing anywhere says "verified: only X changed". That claim does not
//      exist any more, and a UI implying it would be claiming a check that did
//      not run.
//   2. ADVISORIES (a templated file ARGUS did not render, a changed document
//      count, a file that no longer declares the object) reach the operator as
//      visible prose beside the file they qualify, and read as "could not
//      check", never as a refusal.
//   3. A created file and an unchanged file are ordinary outcomes and are shown
//      as such.

const mockGetRepositoryFile = vi.fn()
const mockPreviewRepositoryChange = vi.fn()
const mockOpenRepositoryChange = vi.fn()

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    getRepositoryFile: (...args: unknown[]) => mockGetRepositoryFile(...args),
    previewRepositoryChange: (...args: unknown[]) => mockPreviewRepositoryChange(...args),
    openRepositoryChange: (...args: unknown[]) => mockOpenRepositoryChange(...args),
  }
})

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ accessToken: 'test-token' }),
}))

const capabilities = new Set<string>()
vi.mock('../auth/useCapabilities', () => ({
  useHasCapability: (capability: string) => capabilities.has(capability),
}))

import { RepositoryChangePanel } from './RepositoryChangePanel'

const REVISION = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2'
const DEPLOYMENT = 'apps/payments/deployment.yaml'
const VALUES = 'apps/payments/values.yaml'

function pinnedRepo(over: Partial<OwnershipRepo> = {}): OwnershipRepo {
  return {
    url: 'https://github.com/example/gitops.git',
    path: 'apps/payments',
    branch: 'main',
    revision: REVISION,
    pinned: true,
    ...over,
  }
}

function renderPanel(over: Partial<OwnershipRepo> = {}, plan: RemediationPlan | null = null) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <RepositoryChangePanel incidentId="inc_1" repo={pinnedRepo(over)} plan={plan} />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  mockGetRepositoryFile.mockReset()
  mockPreviewRepositoryChange.mockReset()
  mockOpenRepositoryChange.mockReset()
  capabilities.clear()
  capabilities.add(CAP_REPO_WRITE)
  capabilities.add(CAP_REMEDIATION_APPROVE)
  capabilities.add(CAP_REMEDIATION_EXECUTE_PR)
})

const PROPOSED_DEPLOYMENT =
  'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: payments-api\nspec:\n  replicas: 3\n'

// An OpenPR plan as the wire now carries it: whole files, no field and no value.
const openPrPlan = (files = [{ path: DEPLOYMENT, content: PROPOSED_DEPLOYMENT }]): RemediationPlan =>
  ({
    id: 'plan_1',
    actionType: 'OpenPR',
    params: { repository: 'example/gitops', files },
  }) as unknown as RemediationPlan

function fileResult(over: Record<string, unknown> = {}) {
  return {
    path: DEPLOYMENT,
    created: false,
    unchanged: false,
    diff: '@@ -5,2 +5,2 @@\n spec:\n-  replicas: 1\n+  replicas: 3\n',
    linesAdded: 1,
    linesRemoved: 1,
    lineCount: 6,
    documentCount: 1,
    parsed: true,
    checks: [`${DEPLOYMENT} re-parses as valid YAML (1 document(s))`],
    advisories: [],
    ...over,
  }
}

function previewResponse(files = [fileResult()], over: Record<string, unknown> = {}) {
  const changed = files.filter((f) => !f.unchanged)
  return {
    incidentId: 'inc_1',
    repository: 'https://github.com/example/gitops.git',
    syncedRevision: REVISION,
    baseBranch: 'main',
    branch: 'argus/fix-inc_1',
    verification: {
      files,
      filesChanged: changed.length,
      linesAdded: changed.reduce((n, f) => n + f.linesAdded, 0),
      linesRemoved: changed.reduce((n, f) => n + f.linesRemoved, 0),
      checks: files.flatMap((f) => f.checks),
      advisories: files.flatMap((f) => f.advisories),
      label: 'argus/verified-locally',
      caveat:
        'ARGUS computed these diffs from the files at the pinned synced commit and the content proposed for them. It makes NO claim that only the intended thing changed.',
      ...(over.verification as object),
    },
    renderEvidence: { attempted: false, ...(over.renderEvidence as object) },
  }
}

async function openFromPlan(files?: { path: string; content: string }[]) {
  renderPanel({}, openPrPlan(files))
  fireEvent.click(screen.getByRole('button', { name: /Propose this fix as a pull request/i }))
  await waitFor(() => expect(mockPreviewRepositoryChange).toHaveBeenCalledTimes(1))
}

describe('RepositoryChangePanel — whole files, one or many', () => {
  it('seeds the editors from the analysis\'s proposed files and previews them immediately, with no field inputs anywhere', async () => {
    mockPreviewRepositoryChange.mockResolvedValueOnce(previewResponse())
    await openFromPlan()

    // The proposal is in the editor, as content, ready to be edited.
    const editor = (await screen.findByRole('textbox', { name: new RegExp(DEPLOYMENT) })) as HTMLTextAreaElement
    expect(editor.value).toBe(PROPOSED_DEPLOYMENT)

    // The request is the new grammar: files with whole content, never a field.
    expect(mockPreviewRepositoryChange).toHaveBeenCalledWith(
      'inc_1',
      { files: [{ path: DEPLOYMENT, content: PROPOSED_DEPLOYMENT }] },
      'test-token',
    )

    // The diff ARGUS computed, as real +/- markup.
    expect(await screen.findByText('replicas: 3')).toBeTruthy()
    expect(screen.getByText('replicas: 3').closest('tr')?.className).toContain('unified-diff-add')

    // The retired grammar leaves no trace: no field/value inputs, and above all
    // no minimality claim.
    expect(screen.queryByPlaceholderText('spec/replicas')).toBeNull()
    expect(screen.queryByText(/Verified: only/i)).toBeNull()
    expect(screen.queryByText(/only .* changed \(/i)).toBeNull()
    expect(screen.queryByText(/Field within it/i)).toBeNull()
    expect(screen.queryByText(/New value/i)).toBeNull()
    // The caveat says the opposite, and it must be present: the pull request
    // carries the same sentence, so the operator and the reviewer read one
    // claim rather than two.
    expect(screen.getByText(/makes NO claim that only the intended thing changed/i)).toBeTruthy()
    // The current file is not re-read when the analysis already proposed one:
    // that would overwrite the proposal the operator came to look at.
    expect(mockGetRepositoryFile).not.toHaveBeenCalled()
  })

  it('renders each advisory as visible prose beside its file, worded as "could not check" rather than as a refusal', async () => {
    mockPreviewRepositoryChange.mockResolvedValueOnce(
      previewResponse([
        fileResult({
          parsed: false,
          documentCount: 0,
          checks: [],
          advisories: [
            `${DEPLOYMENT} is templated (it contains Go template markers), so ARGUS did not render it and makes no claim about what it renders to`,
            `${DEPLOYMENT} declared Deployment payments-api at the synced commit and no longer does — check that changing which object this file defines is intended`,
          ],
        }),
      ]),
    )
    await openFromPlan()

    // Both sentences reach the operator in full — not summarised, not counted,
    // and not behind a disclosure.
    expect(await screen.findByText(/is templated \(it contains Go template markers\)/)).toBeTruthy()
    expect(screen.getByText(/no longer does — check that changing which object/)).toBeTruthy()

    // They read as "ARGUS could not check", and they carry that meaning in
    // words rather than in the block's colour alone.
    const block = document.querySelector('.repo-change-advisories')
    expect(block).toBeTruthy()
    expect(block!.textContent).toMatch(/could not check/i)
    expect(block!.textContent).toMatch(/Nothing here stopped the change/i)

    // And they are NOT dressed as the refusal that stops a pull request.
    expect(block!.closest('.form-error')).toBeNull()
    expect(document.querySelector('.form-error')).toBeNull()
  })

  it('shows a created file and an unchanged file as ordinary outcomes, not as errors', async () => {
    mockPreviewRepositoryChange.mockResolvedValueOnce(
      previewResponse([
        fileResult({ path: DEPLOYMENT, unchanged: true, diff: '', linesAdded: 0, linesRemoved: 0 }),
        fileResult({ path: VALUES, created: true, linesRemoved: 0 }),
      ]),
    )
    await openFromPlan([
      { path: DEPLOYMENT, content: PROPOSED_DEPLOYMENT },
      { path: VALUES, content: 'replicaCount: 3\n' },
    ])

    expect(await screen.findByText(/Unchanged from the synced commit/i)).toBeTruthy()
    expect(screen.getByText(/New file — nothing exists at this path/i)).toBeTruthy()
    expect(document.querySelector('.form-error')).toBeNull()
    // The aggregate says how many of the submitted files actually move, which
    // is a different fact from either file's own diff.
    expect(screen.getByText(/1 of 2 file\(s\) would change/i)).toBeTruthy()
  })

  it('adds a second file by path and carries both into one preview and one pull request', async () => {
    mockPreviewRepositoryChange.mockResolvedValueOnce(previewResponse())
    await openFromPlan()

    mockGetRepositoryFile.mockResolvedValueOnce({
      incidentId: 'inc_1',
      repository: 'example/gitops',
      filePath: VALUES,
      filePathSource: 'named_by_caller',
      filesScanned: 0,
      syncedRevision: REVISION,
      content: 'replicaCount: 1\n',
    })
    fireEvent.change(screen.getByRole('textbox', { name: /Add another file/i }), { target: { value: VALUES } })
    fireEvent.click(screen.getByRole('button', { name: /Open this file/i }))

    await waitFor(() => expect(mockGetRepositoryFile).toHaveBeenCalledWith('inc_1', VALUES, 'test-token'))
    const second = (await screen.findByRole('textbox', { name: new RegExp(VALUES) })) as HTMLTextAreaElement
    expect(second.value).toBe('replicaCount: 1\n')

    // Adding a file invalidated the preview, so the stale single-file diff is
    // gone rather than sitting next to a two-file change.
    expect(document.querySelector('.unified-diff')).toBeNull()

    fireEvent.change(second, { target: { value: 'replicaCount: 3\n' } })

    mockOpenRepositoryChange.mockResolvedValueOnce({
      ...previewResponse([fileResult(), fileResult({ path: VALUES })]),
      // The open route reports the repository as owner/name (scm.Repo.String()),
      // where the preview route reports the URL it was resolved from.
      repository: 'example/gitops',
      pullRequestNumber: 42,
      url: 'https://github.com/example/gitops/pull/42',
      commitSha: 'deadbeefcafef00d1234',
      commits: ['deadbeefcafef00d1234', 'f00dcafedeadbeef5678'],
      message: 'Pull request opened.',
    })
    fireEvent.click(screen.getByRole('button', { name: /^Open pull request$/i }))

    await waitFor(() => expect(mockOpenRepositoryChange).toHaveBeenCalledTimes(1))
    expect(mockOpenRepositoryChange.mock.calls[0][1]).toEqual({
      files: [
        { path: DEPLOYMENT, content: PROPOSED_DEPLOYMENT },
        { path: VALUES, content: 'replicaCount: 3\n' },
      ],
    })

    // The record of what was opened names both files and repeats the caveat the
    // reviewer will read on the pull request itself.
    expect(await screen.findByText(/example\/gitops #42/i)).toBeTruthy()
    expect(screen.getByText(/makes NO claim that only the intended thing changed/i)).toBeTruthy()
  })

  it('shows nothing for render evidence when rendering was never attempted', async () => {
    mockPreviewRepositoryChange.mockResolvedValueOnce(previewResponse())
    await openFromPlan()

    await screen.findByText(/makes NO claim that only the intended thing changed/i)
    expect(screen.queryByText(/Rendered comparison/i)).toBeNull()
  })

  it('shows a warning banner, not a confident verdict, when the render was degraded', async () => {
    mockPreviewRepositoryChange.mockResolvedValueOnce(
      previewResponse(undefined, {
        renderEvidence: {
          attempted: true,
          degraded:
            'no Helm values-file list is available for this chart, so a render could only use the chart’s built-in defaults',
        },
      }),
    )
    await openFromPlan()

    const banner = await screen.findByText(/Rendered comparison inconclusive/i)
    expect(banner.closest('.banner-warning')).toBeTruthy()
    expect(banner.textContent).toMatch(/no Helm values-file list is available/i)
  })

  it('warns, rather than celebrates, a real render that found no effective change', async () => {
    mockPreviewRepositoryChange.mockResolvedValueOnce(
      previewResponse(undefined, {
        renderEvidence: { attempted: true, rendererKind: 'helm', effective: false, objectsCompared: 3 },
      }),
    )
    await openFromPlan()

    const banner = await screen.findByText(/compared 3 object/i)
    expect(banner.closest('.banner-warning')).toBeTruthy()
    expect(banner.textContent).toMatch(/Verify this is intentional/i)
  })

  it('shows a success banner for a confirmed effective change', async () => {
    mockPreviewRepositoryChange.mockResolvedValueOnce(
      previewResponse(undefined, {
        renderEvidence: {
          attempted: true,
          rendererKind: 'helm',
          effective: true,
          objectsCompared: 3,
          objectsChanged: ['Deployment/web'],
        },
      }),
    )
    await openFromPlan()

    const banner = await screen.findByText(/confirms an effective change/i)
    expect(banner.closest('.banner-success')).toBeTruthy()
    expect(banner.textContent).toMatch(/1 of 3 rendered object/i)
  })

  it('offers to create a file the repository does not have, and only on the structural not-found refusal', async () => {
    mockPreviewRepositoryChange.mockResolvedValueOnce(previewResponse())
    await openFromPlan()

    mockGetRepositoryFile.mockRejectedValueOnce(
      new ApiError(
        'That file does not exist at the synced commit',
        422,
        'apps/payments/hpa.yaml is not in the repository at a1b2c3d.',
        PROBLEM_NOT_FOUND,
      ),
    )
    fireEvent.change(screen.getByRole('textbox', { name: /Add another file/i }), {
      target: { value: 'apps/payments/hpa.yaml' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Open this file/i }))

    // The hub's own words, then the thing the grammar actually permits.
    expect(await screen.findByText(/is not in the repository at a1b2c3d/i)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: /as a new file instead/i }))

    const created = (await screen.findByRole('textbox', { name: /hpa\.yaml/i })) as HTMLTextAreaElement
    expect(created.value).toBe('')
    // An empty file is a deletion, which this channel cannot express — so the
    // controls are disabled WITH the reason on screen, not silently dead.
    expect(screen.getByRole('button', { name: /^Open pull request$/i })).toHaveProperty('disabled', true)
    expect(screen.getByText(/is empty\. A repository change carries each file's whole content/i)).toBeTruthy()
  })

  it('shows the hub\'s refusal in full and leaves the operator\'s content intact', async () => {
    mockPreviewRepositoryChange.mockResolvedValueOnce(previewResponse())
    await openFromPlan()

    mockOpenRepositoryChange.mockRejectedValueOnce(
      new ApiError(
        'This change would write a redaction marker into a file',
        422,
        'apps/payments/deployment.yaml would gain "[REDACTED]", which is what ARGUS substitutes for a value withheld from the model.',
        'https://argus.io/errors/redacted-value-echoed',
      ),
    )
    fireEvent.click(screen.getByRole('button', { name: /^Open pull request$/i }))

    expect(await screen.findByText(/would gain "\[REDACTED\]"/)).toBeTruthy()
    expect(document.querySelector('.form-error')).toBeTruthy()
    expect(
      (screen.getByRole('textbox', { name: new RegExp(DEPLOYMENT) }) as HTMLTextAreaElement).value,
    ).toBe(PROPOSED_DEPLOYMENT)
  })

  it('with no plan, reads the file ARGUS located and refuses to auto-preview content that proposes nothing', async () => {
    mockGetRepositoryFile.mockResolvedValueOnce({
      incidentId: 'inc_1',
      repository: 'example/gitops',
      filePath: DEPLOYMENT,
      filePathSource: 'located_by_argus',
      filesScanned: 3,
      syncedRevision: REVISION,
      content: 'apiVersion: apps/v1\nkind: Deployment\nspec:\n  replicas: 1\n',
    })
    renderPanel()
    fireEvent.click(screen.getByRole('button', { name: /Propose this fix as a pull request/i }))
    await waitFor(() => expect(mockGetRepositoryFile).toHaveBeenCalledWith('inc_1', undefined, 'test-token'))

    const editor = (await screen.findByRole('textbox', { name: new RegExp(DEPLOYMENT) })) as HTMLTextAreaElement
    expect(editor.value).toContain('replicas: 1')

    // Nothing has been edited, so this proposes no change — the buttons are
    // disabled and say why, rather than spending a request on a refusal that
    // would read as a fault.
    expect(mockPreviewRepositoryChange).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: /Preview the change/i })).toHaveProperty('disabled', true)
    expect(screen.getByText(/Nothing has been edited yet/i)).toBeTruthy()

    fireEvent.change(editor, { target: { value: editor.value.replace('replicas: 1', 'replicas: 3') } })
    expect(screen.getByRole('button', { name: /Preview the change/i })).toHaveProperty('disabled', false)
  })

  it('when discovery cannot pick a file, it says so and still lets the operator name one', async () => {
    mockGetRepositoryFile.mockRejectedValueOnce(
      new ApiError(
        'ARGUS could not determine which file to open',
        422,
        'Deployment payments-api is declared in no file under apps/payments.',
        'https://argus.io/errors/file-not-located',
      ),
    )
    renderPanel()
    fireEvent.click(screen.getByRole('button', { name: /Propose this fix as a pull request/i }))

    expect(await screen.findByText(/is declared in no file under apps\/payments/i)).toBeTruthy()
    expect(screen.getByRole('textbox', { name: /Add another file/i })).toBeTruthy()
    expect(screen.getByRole('button', { name: /^Open pull request$/i })).toHaveProperty('disabled', true)
    expect(screen.getByText(/No file is open yet\. Add one by path below/i)).toBeTruthy()
  })

  it('names the missing capabilities rather than hiding the control', () => {
    capabilities.delete(CAP_REMEDIATION_EXECUTE_PR)
    renderPanel()
    const cta = screen.getByRole('button', { name: /Propose this fix as a pull request/i })
    expect(cta).toHaveProperty('disabled', true)
    expect(screen.getByText(new RegExp(CAP_REMEDIATION_EXECUTE_PR))).toBeTruthy()
  })

  it('refuses up front when the controller reports no resolved commit', () => {
    renderPanel({ pinned: false, revision: 'main' })
    expect(screen.getByText(/not a resolved\s+commit/i)).toBeTruthy()
    expect(screen.queryByRole('button', { name: /Propose this fix as a pull request/i })).toBeNull()
  })
})
