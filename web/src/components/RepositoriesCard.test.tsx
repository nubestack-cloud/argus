import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// GitLab used to be a selectable-but-disabled option here, guarded by a
// comment claiming "no implementation ships yet" — stale by the time this
// file was written: internal/scm/gitlab.go is a real Provider, exercised in
// internal/scm/gitlab_test.go, and the store layer's implementedProviders map
// already accepted "gitlab" (internal/scm/store.go). The only thing actually
// missing was this form letting anyone pick it. These tests pin that it can
// be picked now, and that the credential guidance changes to match GitLab's
// own model (a group access token with the `api` scope — GitLab has no
// finer split between reading contents and opening merge requests the way a
// GitHub fine-grained PAT does), not GitHub's copy left showing underneath.

const mockGetRepositories = vi.fn()
const mockCreateRepository = vi.fn()
const mockUpdateRepository = vi.fn()
const mockDeleteRepository = vi.fn()
const mockCheckRepository = vi.fn()

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    getRepositories: (...args: unknown[]) => mockGetRepositories(...args),
    createRepository: (...args: unknown[]) => mockCreateRepository(...args),
    updateRepository: (...args: unknown[]) => mockUpdateRepository(...args),
    deleteRepository: (...args: unknown[]) => mockDeleteRepository(...args),
    checkRepository: (...args: unknown[]) => mockCheckRepository(...args),
  }
})

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ accessToken: 'test-token' }),
}))

import { RepositoriesCard } from './RepositoriesCard'

// Not getByLabelText: this field's <label> now also contains a HelpTip (a
// nested <button>), and @testing-library/dom's label-to-control resolution
// doesn't reliably follow the explicit htmlFor past that nested control —
// real browsers and screen readers do (a label's `for` always wins over
// wrapped content per the HTML living standard), so this is a query-tooling
// gap, not a real accessibility regression. Queried by id instead, which is
// exactly as stable since this field only ever renders once per dialog.
function defaultBranchInput(): HTMLInputElement {
  const el = document.getElementById('repo-default-branch')
  if (!el) throw new Error('expected #repo-default-branch to be in the document')
  return el as HTMLInputElement
}

function renderCard() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <RepositoriesCard canWrite />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  mockGetRepositories.mockReset()
  mockCreateRepository.mockReset()
  mockUpdateRepository.mockReset()
  mockDeleteRepository.mockReset()
  mockCheckRepository.mockReset()
  mockGetRepositories.mockResolvedValue({ repositories: [] })
})

describe('RepositoriesCard — provider choice', () => {
  it('offers GitLab as a real, selectable option rather than disabled roadmap text', async () => {
    renderCard()
    fireEvent.click(await screen.findByRole('button', { name: '+ Add repository' }))

    const option = screen.getByRole('option', { name: 'GitLab' }) as HTMLOptionElement
    expect(option.disabled).toBe(false)
    expect(option.textContent).not.toMatch(/not implemented/i)
  })

  it('submits provider "gitlab" to the create endpoint when GitLab is selected', async () => {
    mockCreateRepository.mockResolvedValue({})
    renderCard()
    fireEvent.click(await screen.findByRole('button', { name: '+ Add repository' }))

    fireEvent.change(screen.getByLabelText('Provider'), { target: { value: 'gitlab' } })
    fireEvent.change(screen.getByLabelText('Repository URL'), {
      target: { value: 'https://gitlab.example.com/platform/gitops.git' },
    })
    fireEvent.change(screen.getByLabelText('Access token'), { target: { value: 'glpat-fake-token' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add repository' }))

    await waitFor(() => expect(mockCreateRepository).toHaveBeenCalledTimes(1))
    const [body] = mockCreateRepository.mock.calls[0]
    expect(body.provider).toBe('gitlab')
    expect(body.url).toBe('https://gitlab.example.com/platform/gitops.git')
  })

  it('describes the GitLab credential as a scoped group access token, not GitHub\'s permission names', async () => {
    renderCard()
    fireEvent.click(await screen.findByRole('button', { name: '+ Add repository' }))

    // GitHub's copy is the default state — sanity-check it says what GitHub
    // actually needs before switching. Exact strings, not a regex: a regex
    // matches every ancestor whose combined textContent also happens to
    // contain it (every wrapping <div> up to <body>), which is not the same
    // node this test means to pin.
    expect(screen.getByText('Use a fine-grained token, scoped to this repository only.')).toBeTruthy()
    expect(screen.getByText('contents: write')).toBeTruthy()

    fireEvent.change(screen.getByLabelText('Provider'), { target: { value: 'gitlab' } })

    // GitHub-specific permission names must not linger once GitLab is chosen —
    // they don't exist on GitLab and would send a tester looking for the wrong
    // thing (internal/scm/gitlab.go's own doc comment on why `api` is the
    // narrowest scope GitLab has).
    expect(screen.queryByText('contents: write')).toBeNull()
    expect(screen.getByText("Use a group access token, scoped to this repository's group only.")).toBeTruthy()
    expect(screen.getByText('api')).toBeTruthy()
  })

  it('swaps the token and URL placeholders to GitLab-shaped examples', async () => {
    renderCard()
    fireEvent.click(await screen.findByRole('button', { name: '+ Add repository' }))
    fireEvent.change(screen.getByLabelText('Provider'), { target: { value: 'gitlab' } })

    expect(screen.getByLabelText('Access token').getAttribute('placeholder')).toBe('glpat-…')
    expect(screen.getByLabelText('Repository URL').getAttribute('placeholder')).toBe(
      'https://gitlab.com/your-group/platform-config.git',
    )
  })
})

// PUT /api/v1/repositories/{id} (updateRepository) is what closes the gap
// the create dialog's own rotate-by-repeating-the-URL trick left: fixing a
// typo'd default branch used to mean resending EVERY field, with a token, or
// the field you forgot to resend got silently wiped back to a create-time
// default. These pin the new "Edit…" dialog's actual contract: every field
// pre-filled from the real binding, the token genuinely optional, and the
// provider fixed (internal/api/repositories.go's updateRepositoryBindingRequest
// deliberately has no provider field at all).
describe('RepositoriesCard — editing an existing repository', () => {
  const EXISTING_BINDING = {
    id: 'rb_existing',
    provider: 'github' as const,
    url: 'https://github.com/example/platform-config.git',
    host: 'github.com',
    apiBaseUrl: '',
    defaultBranch: 'main',
    credentialStored: true,
    createdAt: '2026-01-01T00:00:00Z',
    objectMappings: [],
  }

  function renderCardWithExistingBinding() {
    mockGetRepositories.mockResolvedValue({ repositories: [EXISTING_BINDING] })
    return renderCard()
  }

  it('opens an edit dialog pre-filled from the binding, with the provider fixed rather than a dropdown', async () => {
    renderCardWithExistingBinding()
    fireEvent.click(await screen.findByRole('button', { name: 'Edit…' }))

    expect(await screen.findByText('Edit Git repository')).toBeTruthy()
    expect(screen.getByLabelText('Repository URL')).toHaveProperty('value', EXISTING_BINDING.url)
    expect(defaultBranchInput()).toHaveProperty('value', 'main')
    // No <select> for provider once editing — it's fixed, shown as text.
    // Exact string, not a regex: a regex would also match every ancestor
    // whose combined textContent happens to contain it.
    expect(screen.queryByRole('combobox')).toBeNull()
    expect(screen.getByText('GitHub (not editable — remove and re-add to switch providers)')).toBeTruthy()
  })

  it('submits without a token field when the operator leaves it blank — the stored credential must not be touched', async () => {
    mockUpdateRepository.mockResolvedValue({})
    renderCardWithExistingBinding()
    fireEvent.click(await screen.findByRole('button', { name: 'Edit…' }))

    fireEvent.change(defaultBranchInput(), { target: { value: 'release' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }))

    await waitFor(() => expect(mockUpdateRepository).toHaveBeenCalledTimes(1))
    const [id, body] = mockUpdateRepository.mock.calls[0]
    expect(id).toBe('rb_existing')
    expect(body.defaultBranch).toBe('release')
    expect(body.url).toBe(EXISTING_BINDING.url)
    expect('token' in body).toBe(false)
  })

  it('includes the token only when the operator actually types a new one', async () => {
    mockUpdateRepository.mockResolvedValue({})
    renderCardWithExistingBinding()
    fireEvent.click(await screen.findByRole('button', { name: 'Edit…' }))

    fireEvent.change(await screen.findByLabelText('Access token (optional)'), { target: { value: 'ghp_rotated' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }))

    await waitFor(() => expect(mockUpdateRepository).toHaveBeenCalledTimes(1))
    const [, body] = mockUpdateRepository.mock.calls[0]
    expect(body.token).toBe('ghp_rotated')
  })

  it('lets the URL itself be changed, unlike the create dialog\'s rotate-by-same-URL path', async () => {
    mockUpdateRepository.mockResolvedValue({})
    renderCardWithExistingBinding()
    fireEvent.click(await screen.findByRole('button', { name: 'Edit…' }))

    const newURL = 'https://github.com/example/renamed-repo.git'
    fireEvent.change(await screen.findByLabelText('Repository URL'), { target: { value: newURL } })
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }))

    await waitFor(() => expect(mockUpdateRepository).toHaveBeenCalledTimes(1))
    const [, body] = mockUpdateRepository.mock.calls[0]
    expect(body.url).toBe(newURL)
  })

  // The load-bearing regression test for removing the old editor
  // (BACKLOG.md F30): objectMappings must never be part of what an
  // unrelated edit sends. UpdateRepositoryBindingRequest's own contract is
  // that a non-nil objectMappings REPLACES the stored list — sending `[]`
  // here would silently wipe every mapping F30's confirm-repository-link
  // may have already appended to this exact binding.
  it('never sends objectMappings on an update, even though the binding already has real mappings', async () => {
    mockUpdateRepository.mockResolvedValue({})
    mockGetRepositories.mockResolvedValue({
      repositories: [
        {
          ...EXISTING_BINDING,
          objectMappings: [{ releaseName: 'shop-apps', namespace: 'default', path: '.', scope: { type: 'Cluster', clusterId: 'cl_1' } }],
        },
      ],
    })
    renderCard()
    fireEvent.click(await screen.findByRole('button', { name: 'Edit…' }))
    fireEvent.change(defaultBranchInput(), { target: { value: 'release' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }))

    await waitFor(() => expect(mockUpdateRepository).toHaveBeenCalledTimes(1))
    const [, body] = mockUpdateRepository.mock.calls[0]
    expect('objectMappings' in body).toBe(false)
  })
})

// BACKLOG.md F30 removed the old hand-typed "Object mappings" editor from
// this dialog entirely: it predated Scope, so anything saved through it
// defaulted to matching every cluster silently (authz.Scope{} decodes as
// "AllClusters") — exactly the blind, no-proof link F30 exists to prevent.
// All new links now go through the render-proven discover/confirm/decline
// flow on the incident that actually needs one (LinkHelmReleaseForm,
// IncidentDetailPage.tsx). This pins the control's absence, not its
// behaviour — there is nothing left here to unit test beyond "it's gone".
describe('RepositoriesCard — no object-mapping editor', () => {
  it('does not offer to add or edit object mappings from this dialog', async () => {
    renderCard()
    fireEvent.click(await screen.findByRole('button', { name: '+ Add repository' }))

    expect(screen.queryByText(/Object mappings/i)).toBeNull()
    expect(screen.queryByRole('button', { name: '+ Add object mapping' })).toBeNull()
    expect(screen.queryByLabelText('Release name')).toBeNull()
    expect(screen.queryByLabelText('Labels')).toBeNull()
  })
})
