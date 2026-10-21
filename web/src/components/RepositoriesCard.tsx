import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import {
  ApiError,
  checkRepository,
  createRepository,
  deleteRepository,
  getRepositories,
  updateRepository,
} from '../api/client'
import type {
  CreateRepositoryBindingRequest,
  RepositoryBinding,
  UpdateRepositoryBindingRequest,
} from '../api/types'
import { useAuth } from '../auth/useAuth'
import { formatDateTime } from '../utils/time'
import { Dialog } from './Dialog'
import { HelpTip } from './HelpTip'
import { PanelHead } from './SettingsBlocks'

// Manages the Git repositories ARGUS may open a pull request against.
//
// Its own area rather than a section of "AI & automation", for the same reason
// the AI providers list is: this is a collection of connections with a per-item
// lifecycle (add, verify, remove), not one form with one save button.
//
// The credential model it exposes is REMEDIATION_ROADMAP.md D-R9's: one
// fine-grained token per repository, org-level rather than per-user,
// envelope-encrypted at rest, scoped to the repositories the operator names.
// The form says so, because "which token do I paste here" is the first question
// anyone will have and getting it wrong means pasting something far too powerful.

const EMPTY_FORM: CreateRepositoryBindingRequest = {
  provider: 'github',
  url: '',
  token: '',
  apiBaseUrl: '',
  defaultBranch: '',
  expiresAt: '',
}

// The one shared form's local state doubles as both requests' shape (create's
// is a strict superset of edit's — edit just never sends `provider` and never
// requires `token`), so one type and one piece of state cover both, the same
// way editingRole/create both feed CustomRolesCard's single form.
function formFromBinding(binding: RepositoryBinding): CreateRepositoryBindingRequest {
  return {
    provider: binding.provider,
    url: binding.url,
    token: '', // never pre-filled — the stored credential is write-only and never returned.
    apiBaseUrl: binding.apiBaseUrl ?? '',
    defaultBranch: binding.defaultBranch ?? '',
    expiresAt: toDateInputValue(binding.expiresAt),
  }
}

// <input type="date"> wants "YYYY-MM-DD"; the wire format is RFC 3339. Sliced
// rather than reformatted through Date, which would shift the date across a
// timezone boundary near midnight — the token's own expiry date, as the
// operator read it off the token, is what this field must keep showing.
function toDateInputValue(isoTimestamp?: string): string {
  return isoTimestamp ? isoTimestamp.slice(0, 10) : ''
}

// Warn this far ahead of a token expiring. A fine-grained token dies on a date,
// and when it does PR creation simply starts failing — so the point is to warn
// BEFORE, not to report the failures after (D-R9).
const EXPIRY_WARN_DAYS = 30

function expiryBadge(binding: RepositoryBinding) {
  if (binding.expiresInDays == null) return null
  if (binding.expiresInDays < 0) {
    return (
      <span className="badge badge-red" title={`Expired ${formatDateTime(binding.expiresAt!)}`}>
        credential expired
      </span>
    )
  }
  if (binding.expiresInDays <= EXPIRY_WARN_DAYS) {
    return (
      <span className="badge badge-amber" title={`Expires ${formatDateTime(binding.expiresAt!)}`}>
        expires in {binding.expiresInDays} day{binding.expiresInDays === 1 ? '' : 's'}
      </span>
    )
  }
  return (
    <span className="badge badge-gray" title={`Expires ${formatDateTime(binding.expiresAt!)}`}>
      expires in {binding.expiresInDays} days
    </span>
  )
}

function RepositoryRow({
  binding,
  canWrite,
  disabledReason,
  onEdit,
}: {
  binding: RepositoryBinding
  canWrite: boolean
  disabledReason?: string
  onEdit: (binding: RepositoryBinding) => void
}) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const [confirmingDelete, setConfirmingDelete] = useState(false)

  const check = useMutation({ mutationFn: () => checkRepository(binding.id, accessToken!) })
  const remove = useMutation({
    mutationFn: () => deleteRepository(binding.id, accessToken!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['repositories'] }),
  })

  return (
    <li className="ai-provider">
      <div className="ai-provider-identity">
        {/* A repository URL is arbitrary length and contains no spaces, so it needs
            to be breakable or it pushes the card wider than its column. */}
        <strong className="wrap-anywhere">{binding.url}</strong>
        <span className="field-hint">
          {binding.provider}
          {/* A self-hosted host is worth showing plainly: it is the difference
              between talking to github.com and to the customer's own GHES, and
              DESIGN.md §11.3 makes that a first-class configuration rather than
              an edge case. */}
          {binding.apiBaseUrl ? ` · self-hosted at ${binding.apiBaseUrl}` : ' · public API'}
          {binding.defaultBranch ? ` · base ${binding.defaultBranch}` : ''}
          {' · added '}
          {formatDateTime(binding.createdAt)}
        </span>
      </div>

      <div className="ai-provider-identity">
        {expiryBadge(binding)}
        {!binding.credentialStored && <span className="badge badge-red">no credential</span>}
      </div>

      <div className="ai-provider-actions">
        <button
          type="button"
          className="secondary"
          disabled={!canWrite || check.isPending}
          title={disabledReason ?? 'Ask the provider whether this credential still works'}
          onClick={() => check.mutate()}
        >
          {check.isPending ? 'Checking…' : 'Check credential'}
        </button>
        <button
          type="button"
          className="secondary"
          disabled={!canWrite}
          title={disabledReason ?? 'Change the URL, API base URL, default branch, or rotate the credential'}
          onClick={() => onEdit(binding)}
        >
          Edit…
        </button>
        {!confirmingDelete ? (
          <button
            type="button"
            className="secondary"
            disabled={!canWrite}
            title={disabledReason ?? 'Remove this repository and its stored credential'}
            onClick={() => setConfirmingDelete(true)}
          >
            Remove…
          </button>
        ) : (
          <span className="triage-actions">
            <button type="button" disabled={remove.isPending} onClick={() => remove.mutate()}>
              {remove.isPending ? 'Removing…' : 'Confirm'}
            </button>
            <button type="button" className="secondary" onClick={() => setConfirmingDelete(false)}>
              Cancel
            </button>
          </span>
        )}
      </div>

      {/* The provider's own words, not a paraphrase: its message distinguishes an
          expired token from an under-scoped one from a rate limit, and each has a
          different fix. Collapsing them into "check failed" throws away the only
          part that tells you what to do. */}
      {check.isError && (
        <p className="form-error inline-error" role="alert">
          {check.error instanceof ApiError ? check.error.detail || check.error.message : 'Could not check this credential.'}
        </p>
      )}
      {check.isSuccess && (
        <p className="field-hint">
          {/* Decorative only — the success is already stated by the text that follows, so the glyph
              is hidden from assistive tech rather than read out as "check mark". A bare glyph is
              never the only carrier of status here. */}
          <span aria-hidden="true">✓</span> {check.data.repository} — default branch{' '}
          <code>{check.data.defaultBranch}</code>. {check.data.message}
        </p>
      )}
      {remove.isError && (
        <p className="form-error inline-error" role="alert">
          {remove.error instanceof ApiError ? remove.error.message : 'Could not remove this repository.'}
        </p>
      )}
    </li>
  )
}

export function RepositoriesCard({ canWrite, disabledReason }: { canWrite: boolean; disabledReason?: string }) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  // 'new' opens the create dialog; a binding opens that binding's edit dialog;
  // null is closed. Same shape as CustomRolesCard's own dialogOpenFor, for the
  // identical reason: one form serves both, and this is what tells it which.
  const [dialogOpenFor, setDialogOpenFor] = useState<'new' | RepositoryBinding | null>(null)
  const [form, setForm] = useState<CreateRepositoryBindingRequest>(EMPTY_FORM)
  const [error, setError] = useState<string | null>(null)
  const editingBinding = dialogOpenFor !== 'new' ? dialogOpenFor : null

  const query = useQuery({
    queryKey: ['repositories'],
    queryFn: () => getRepositories(accessToken!),
    enabled: !!accessToken,
  })

  function closeDialog() {
    setDialogOpenFor(null)
    setError(null)
  }

  const create = useMutation({
    mutationFn: () => {
      // Empty optional fields are omitted rather than sent as "": the hub
      // treats an empty apiBaseUrl as "the public API", and sending "" for a
      // date would be a parse error. objectMappings is never sent from here
      // at all — BACKLOG.md F30 replaced this hand-typed editor with a
      // render-proven discover/confirm/decline flow on the incident that
      // actually needs a link (LinkHelmReleaseForm, IncidentDetailPage.tsx).
      // A new repository always starts with no mappings anyway (omitting
      // the field and sending an empty list are equivalent server-side).
      const body: CreateRepositoryBindingRequest = {
        provider: form.provider,
        url: form.url.trim(),
        token: form.token,
        ...(form.apiBaseUrl?.trim() ? { apiBaseUrl: form.apiBaseUrl.trim() } : {}),
        ...(form.defaultBranch?.trim() ? { defaultBranch: form.defaultBranch.trim() } : {}),
        ...(form.expiresAt?.trim() ? { expiresAt: new Date(form.expiresAt).toISOString() } : {}),
      }
      return createRepository(body, accessToken!)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['repositories'] })
      closeDialog()
      setForm(EMPTY_FORM)
    },
    onError: (e) => setError(e instanceof ApiError ? e.detail || e.message : e instanceof Error ? e.message : 'Something went wrong.'),
  })

  const update = useMutation({
    mutationFn: () => {
      // Every displayed field is sent back exactly as it stands — the form
      // was pre-filled from the real current values, so there is nothing to
      // diff. token is the one deliberate exception: it is never pre-filled
      // (write-only, never returned), so "the operator didn't touch it"
      // and "leave the stored credential alone" are the same observable
      // state, and omitting it here is what tells the hub not to rotate.
      // objectMappings is likewise OMITTED, deliberately — not sent as `[]`
      // — this is the load-bearing half of removing the old editor: F30's
      // confirm-repository-link may already have appended real, render-proven
      // mappings onto this binding, and UpdateRepositoryBindingRequest's own
      // contract is that a non-nil objectMappings REPLACES the stored list.
      // Sending `[]` here on an unrelated edit (rotating a token, fixing the
      // default branch) would silently wipe every confirmed link.
      const body: UpdateRepositoryBindingRequest = {
        url: form.url.trim(),
        apiBaseUrl: form.apiBaseUrl?.trim() ?? '',
        defaultBranch: form.defaultBranch?.trim() ?? '',
        expiresAt: form.expiresAt?.trim() ? new Date(form.expiresAt).toISOString() : '',
        ...(form.token ? { token: form.token } : {}),
      }
      return updateRepository(editingBinding!.id, body, accessToken!)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['repositories'] })
      closeDialog()
      setForm(EMPTY_FORM)
    },
    onError: (e) => setError(e instanceof ApiError ? e.detail || e.message : e instanceof Error ? e.message : 'Something went wrong.'),
  })

  const mutation = editingBinding ? update : create
  const repositories = query.data?.repositories ?? []

  return (
    <div className="card settings-panel">
      <PanelHead
        title="Git repositories"
        lede="Where ARGUS may propose a fix as a pull request."
        help="When a GitOps controller owns a broken object, changing the cluster directly is a stop-gap the next sync reverts — the durable fix belongs in the repository the object came from, and ARGUS already knows which one that is."
      />

      {query.isError && (
        <p className="form-error" role="alert">
          {query.error instanceof ApiError ? query.error.message : 'Could not load repositories.'}
        </p>
      )}

      {!query.isLoading && repositories.length === 0 && (
        <div className="ai-provider-empty">
          <strong>No repositories registered</strong>
          <p>
            Register a repository with a token and ARGUS can propose a fix there instead of only describing it.
          </p>
        </div>
      )}

      {repositories.length > 0 && (
        <ul className="ai-provider-list">
          {repositories.map((b) => (
            <RepositoryRow
              key={b.id}
              binding={b}
              canWrite={canWrite}
              disabledReason={disabledReason}
              onEdit={(binding) => {
                setForm(formFromBinding(binding))
                setError(null)
                setDialogOpenFor(binding)
              }}
            />
          ))}
        </ul>
      )}

      <button
        type="button"
        className="secondary"
        disabled={!canWrite}
        title={disabledReason}
        onClick={() => {
          setForm(EMPTY_FORM)
          setError(null)
          setDialogOpenFor('new')
        }}
      >
        + Add repository
      </button>

      {dialogOpenFor && (
      <Dialog title={editingBinding ? 'Edit Git repository' : 'Add a Git repository'} onClose={closeDialog}>
        <form
          onSubmit={(e) => {
            e.preventDefault()
            mutation.mutate()
          }}
        >
          <label htmlFor="repo-provider">Provider</label>
          {editingBinding ? (
            <>
              {/* Not editable: changing it changes what the stored token can
                  even authenticate as, which is a bigger change than an edit
                  form should invite — see updateRepositoryBindingRequest's
                  own doc comment (internal/api/repositories.go). */}
              <p id="repo-provider" className="field-hint">
                {editingBinding.provider === 'gitlab' ? 'GitLab' : 'GitHub'} (not editable — remove and re-add to
                switch providers)
              </p>
            </>
          ) : (
            <select
              id="repo-provider"
              value={form.provider}
              onChange={(e) => setForm({ ...form, provider: e.target.value as 'github' | 'gitlab' })}
            >
              <option value="github">GitHub</option>
              <option value="gitlab">GitLab</option>
            </select>
          )}

          <label htmlFor="repo-url">Repository URL</label>
          <input
            id="repo-url"
            type="url"
            required
            placeholder={
              form.provider === 'gitlab'
                ? 'https://gitlab.com/your-group/platform-config.git'
                : 'https://github.com/your-org/platform-config.git'
            }
            value={form.url}
            onChange={(e) => setForm({ ...form, url: e.target.value })}
          />
          <p className="field-hint">
            Must be <code>https</code>. This is matched against the repository ARGUS resolves from the
            cluster, so it has to be the same URL the GitOps controller uses.
          </p>

          <label htmlFor="repo-token">
            Access token {editingBinding && <span className="field-optional">(optional)</span>}
          </label>
          <input
            id="repo-token"
            type="password"
            required={!editingBinding}
            autoComplete="off"
            placeholder={editingBinding ? 'leave blank to keep the current credential' : form.provider === 'gitlab' ? 'glpat-…' : 'github_pat_…'}
            value={form.token}
            onChange={(e) => setForm({ ...form, token: e.target.value })}
          />
          {editingBinding && (
            <p className="field-hint">
              {editingBinding.credentialStored
                ? 'A credential is already stored for this repository. Only paste a new one if you are rotating it.'
                : 'No credential is stored yet — this repository cannot open a pull request until one is set.'}
            </p>
          )}
          {/* The most important copy on this screen. "Which token" is the first
              question anyone has, and the wrong answer is a classic PAT that can
              write to every repository the account can reach — an exposure that
              cannot be sized. The two providers' credential models genuinely
              differ (internal/scm/gitlab.go's own doc comment: GitLab has no
              finer split of "read contents" vs "open merge requests" the way a
              GitHub fine-grained PAT does — `api` is the narrowest scope that
              covers both, and that coarseness is GitLab's, not a choice made
              here), so this is two real copy blocks, not one generic one. */}
          {form.provider === 'gitlab' ? (
            <div className="consequence-notice" role="note">
              <strong>Use a group access token, scoped to this repository's group only.</strong>
              <p>
                It needs the <code>api</code> scope — GitLab has no narrower split between reading
                repository contents and opening merge requests, so this is the least-privileged scope that
                can do both. Do <em>not</em> use a personal access token — those can write to everything the
                account can reach, and that exposure cannot be sized or revoked per repository.
              </p>
              <p>
                Use a group access token, not one on your own account{' '}
                <HelpTip
                  label="group access tokens"
                  text="A group access token belongs to the group, not a person: it survives someone leaving, and many organisations forbid approving your own merge requests — which a token on your own account would make you do."
                />
              </p>
            </div>
          ) : (
            <div className="consequence-notice" role="note">
              <strong>Use a fine-grained token, scoped to this repository only.</strong>
              <p>
                It needs exactly two permissions: <code>contents: write</code> and{' '}
                <code>pull_requests: write</code>. Do <em>not</em> use a classic personal access token — those
                can write to everything the account can reach, and that exposure cannot be sized or revoked
                per repository.
              </p>
              <p>
                Put it on a dedicated machine user rather than your own account: it survives someone leaving,
                it keeps <code>git blame</code> honest, and many organisations forbid approving your own PRs —
                which a token on your account would make you do.
              </p>
            </div>
          )}

          <label htmlFor="repo-expires">
            Token expiry <span className="field-optional">(optional)</span>
          </label>
          <input
            id="repo-expires"
            type="date"
            value={form.expiresAt}
            onChange={(e) => setForm({ ...form, expiresAt: e.target.value })}
          />
          <p className="field-hint">
            A fine-grained token expires, and when it does pull-request creation simply starts failing. Tell
            ARGUS the date and it warns you beforehand instead.
          </p>

          <label htmlFor="repo-api-base">
            API base URL <span className="field-optional">(self-hosted only)</span>
            <HelpTip label="API base URL" text="Your instance's API root, not the site you browse to. GitHub Enterprise Server: https://ghe.internal.example/api/v3. Self-hosted GitLab: https://gitlab.internal.example/api/v4. Leave blank for the public github.com/gitlab.com API." />
          </label>
          <input
            id="repo-api-base"
            type="url"
            placeholder={
              form.provider === 'gitlab' ? 'https://gitlab.internal.example/api/v4' : 'https://ghe.internal.example/api/v3'
            }
            value={form.apiBaseUrl}
            onChange={(e) => setForm({ ...form, apiBaseUrl: e.target.value })}
          />
          <p className="field-hint">Leave blank for github.com. Set it for GitHub Enterprise Server or a self-hosted GitLab.</p>

          <label htmlFor="repo-default-branch">
            Default branch <span className="field-optional">(optional)</span>
            <HelpTip label="Default branch" text="The base branch ARGUS opens pull requests against. Left blank, ARGUS asks the provider which branch is default — but some self-hosted instances don't answer that reliably even for a repository with real commit history. Set this and ARGUS uses it directly, before ever asking the provider." />
          </label>
          <input
            id="repo-default-branch"
            type="text"
            placeholder="detected automatically"
            value={form.defaultBranch}
            onChange={(e) => setForm({ ...form, defaultBranch: e.target.value })}
          />
          <p className="field-hint">Leave blank to let ARGUS ask the provider; set it if "Check credential" reports no default branch.</p>

          {error && (
            <p className="form-error" role="alert">
              {error}
            </p>
          )}

          <div className="modal-actions">
            <button type="button" className="secondary" onClick={closeDialog}>
              Cancel
            </button>
            <button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? (editingBinding ? 'Saving…' : 'Adding…') : editingBinding ? 'Save changes' : 'Add repository'}
            </button>
          </div>
        </form>
      </Dialog>
      )}
    </div>
  )
}
