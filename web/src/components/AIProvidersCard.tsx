import { useState } from 'react'
import type { FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ApiError,
  activateAIProvider,
  createAIProvider,
  deleteAIProvider,
  getAIProviders,
  testAIProvider,
  updateAIProvider,
} from '../api/client'
import type {
  AIProvider,
  AIProviderRequest,
  AIProviderTestResult,
  LlmProviderKind,
} from '../api/types'
import { useAuth } from '../auth/useAuth'
import { Dialog } from './Dialog'
import { PanelHead } from './SettingsBlocks'

// Manages the set of configured AI providers and which one is active
// (migration 000034 / internal/api/ai_providers.go). Rendered on its own
// Settings tab: this is an inventory with a per-item lifecycle, not a form with
// one save button like the rest of Settings.
//
// Add/edit happens in a dialog rather than inline, and adding is two steps —
// choose the kind, then configure it. The kind isn't a detail among the other
// fields: it decides which fields exist at all, and the two options are
// genuinely different products (call an API ourselves vs. drive a CLI in a
// separate runner). A dropdown buried mid-form made that look incidental, and
// an inline form that grew and shrank pushed the list around while reading it.
//
// "Active" is the load-bearing concept and is stated plainly, because the
// failure mode worth designing against is an operator carefully editing a
// provider that isn't the one being used.

interface KindOption {
  kind: LlmProviderKind
  title: string
  blurb: string
}

const KIND_OPTIONS: KindOption[] = [
  {
    kind: 'api',
    title: 'Direct API',
    blurb:
      'ARGUS calls an OpenAI-compatible endpoint itself and drives the investigation. The recommended default: cost and token usage are measurable, and every step of the reasoning is recorded.',
  },
  {
    kind: 'cli',
    title: 'Agent CLI',
    blurb:
      'A separate runner drives Claude Code or Codex, and ARGUS serves it read-only cluster tools. Reaches Bedrock, Vertex, corporate gateways and seat-based plans — but per-step reasoning and per-investigation cost are not recorded.',
  },
]

const EMPTY_FORM: AIProviderRequest = {
  name: '',
  kind: 'api',
  baseUrl: '',
  model: '',
  runnerUrl: '',
  agent: 'claude',
}

type DialogState =
  // Closed.
  | { mode: 'closed' }
  // Adding, step 1: which kind?
  | { mode: 'choose-kind' }
  // Adding or editing, step 2: the fields for that kind. id is set when editing.
  | { mode: 'configure'; id?: string }

// The connection test's three states, carrying the id of the provider they
// belong to.
//
// One slot rather than a map, deliberately: the test COSTS MONEY on an api
// provider, so testing one provider and then another should replace the result
// rather than accumulate a wall of stale verdicts an operator might read as
// current. Only one test can be in flight at a time for the same reason (see
// `busy`) — a second click while one is pending would be a second charge.
type TestState =
  | { id: string; status: 'pending' }
  | { id: string; status: 'passed'; result: AIProviderTestResult }
  // summary is the hub's problem title, detail its problem detail. Both are
  // shown: the summary names WHICH failure it was ("The provider rejected the
  // API key (HTTP 401)") and the detail says what to do about it. Collapsing
  // them into one line, or dropping the detail, throws away the entire point
  // of the feature.
  | { id: string; status: 'failed'; summary: string; detail: string }

export function AIProvidersCard({
  canWrite,
  disabledReason,
  cliBackendAvailable,
}: {
  canWrite: boolean
  disabledReason?: string
  // Whether this HUB can serve a `cli` provider at all — it needs an MCP
  // listener, off unless ARGUS_MCP_ADDR is set. Passed in rather than fetched
  // again: the parent already holds GET /admin/settings.
  cliBackendAvailable: boolean
}) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()

  const [dialog, setDialog] = useState<DialogState>({ mode: 'closed' })
  const [form, setForm] = useState<AIProviderRequest>(EMPTY_FORM)
  // Secrets are write-only: the API never returns them, so an empty input means
  // "leave unchanged" rather than "clear". Kept out of `form` so it can be
  // omitted from the request entirely.
  const [secret, setSecret] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null)
  const [test, setTest] = useState<TestState | null>(null)

  const query = useQuery({
    queryKey: ['ai-providers'],
    queryFn: () => getAIProviders(accessToken!),
    enabled: !!accessToken && canWrite,
  })

  const onSettled = () => {
    queryClient.invalidateQueries({ queryKey: ['ai-providers'] })
    // The active provider is what GET /admin/settings' llm section reflects.
    queryClient.invalidateQueries({ queryKey: ['settings'] })
  }
  const fail = (e: unknown) => setError(e instanceof ApiError ? e.message : 'Something went wrong.')

  const closeDialog = () => {
    setDialog({ mode: 'closed' })
    setForm(EMPTY_FORM)
    setSecret('')
    setError(null)
  }

  const saveMutation = useMutation({
    mutationFn: (body: AIProviderRequest) => {
      const editingId = dialog.mode === 'configure' ? dialog.id : undefined
      return editingId
        ? updateAIProvider(editingId, body, accessToken!)
        : createAIProvider(body, accessToken!)
    },
    onSuccess: () => {
      // Any stored verdict is now about a configuration that no longer
      // exists. Leaving a green tick beside a provider whose base URL just
      // changed would be worse than showing nothing.
      setTest(null)
      closeDialog()
    },
    onError: fail,
    onSettled,
  })

  const activateMutation = useMutation({
    mutationFn: (id: string) => activateAIProvider(id, accessToken!),
    onSuccess: () => setError(null),
    onError: fail,
    onSettled,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteAIProvider(id, accessToken!),
    onSuccess: () => {
      setConfirmDeleteId(null)
      setError(null)
      setTest(null)
    },
    onError: fail,
    onSettled,
  })

  // The connection test. Note what is NOT here: no `useQuery`, no `retry`, no
  // `onSettled` invalidation. It is a mutation purely so that it can only ever
  // run from a click — on an api provider this sends a real, billable request
  // to a paid endpoint, and a query would re-run it on mount, on refocus and
  // on reconnect. React Query retries failed mutations zero times by default,
  // which is exactly what is wanted: a failed test is an answer, not something
  // to try harder at.
  const testMutation = useMutation({
    mutationFn: (id: string) => testAIProvider(id, accessToken!),
    onMutate: (id: string) => setTest({ id, status: 'pending' }),
    onSuccess: (result, id) => setTest({ id, status: 'passed', result }),
    onError: (e: unknown, id) =>
      setTest({
        id,
        status: 'failed',
        // The hub's own words, not a paraphrase. Its classification
        // distinguishes a wrong base URL from a bad key from a rate limit from
        // an unreachable host, and each has a different fix — the same
        // reasoning as the repository credential check.
        summary: e instanceof ApiError ? e.message : 'Could not test this provider.',
        detail:
          e instanceof ApiError && e.detail
            ? e.detail
            : 'The hub could not be reached, so nothing was tested.',
      }),
  })

  const providers = query.data?.providers ?? []
  // testMutation is included so a provider cannot be edited, activated or
  // deleted out from under an in-flight test — and, more importantly, so the
  // Test button itself cannot be double-clicked into two paid requests.
  const busy =
    saveMutation.isPending ||
    activateMutation.isPending ||
    deleteMutation.isPending ||
    testMutation.isPending

  function chooseKind(kind: LlmProviderKind) {
    setForm({ ...EMPTY_FORM, kind })
    setSecret('')
    setError(null)
    setDialog({ mode: 'configure' })
  }

  function openEdit(p: AIProvider) {
    setForm({
      name: p.name,
      kind: p.kind,
      baseUrl: p.baseUrl,
      model: p.model,
      runnerUrl: p.runnerUrl,
      agent: p.agent || 'claude',
    })
    setSecret('')
    setError(null)
    setDialog({ mode: 'configure', id: p.id })
  }

  function submit(event: FormEvent) {
    event.preventDefault()
    const body: AIProviderRequest =
      form.kind === 'api'
        ? { name: form.name, kind: 'api', baseUrl: form.baseUrl, model: form.model }
        : { name: form.name, kind: 'cli', runnerUrl: form.runnerUrl, agent: form.agent }
    // Omitted entirely when blank — the backend reads absent as "leave the
    // stored secret alone", which is what lets an operator rename a provider
    // without re-pasting its key.
    if (secret) {
      if (form.kind === 'api') body.apiKey = secret
      else body.runnerToken = secret
    }
    saveMutation.mutate(body)
  }

  if (!canWrite) {
    return (
      <>
        <h2>AI providers</h2>
        <p className="field-hint">{disabledReason ?? 'You do not have permission to view AI providers.'}</p>
      </>
    )
  }

  const editing = dialog.mode === 'configure' && !!dialog.id
  const kindLabel = KIND_OPTIONS.find((o) => o.kind === form.kind)?.title ?? form.kind

  return (
    <>
      <PanelHead
        title="AI providers"
        lede={
          <>
            <strong>Exactly one is active</strong>; every investigation uses it.
          </>
        }
        help="Configure as many providers as you like — API endpoints, agent-CLI runners, or both. Exactly one is active, and the active one is what every investigation uses. Switching takes effect on the next investigation; no restart."
      />

      {query.isLoading && <p className="field-hint">Loading providers…</p>}
      {query.isError && (
        <p className="form-error" role="alert">
          Could not load AI providers.
        </p>
      )}

      {/* !isError matters: providers falls back to [] on failure, so without it
          a failed fetch rendered the definite claim "No providers configured"
          directly under "Could not load AI providers" — two contradictory
          statements, the second of which would lead an operator to add a
          duplicate. */}
      {!query.isLoading && !query.isError && providers.length === 0 && (
        <div className="ai-provider-empty">
          <strong>No providers configured</strong>
          <p>
            Analysis will report "AI provider not configured" until you add one. The first provider
            you add becomes the active one automatically.
          </p>
        </div>
      )}

      {/* A `cli` provider can be configured perfectly and still be unusable,
          because the missing piece is a hub-level env var rather than anything
          about the provider. Nothing said so, so an operator could activate one
          and only discover it on clicking Analyze — via an error that blamed the
          provider's base URL, which a CLI provider does not even have. This is
          the same "make the absence visible" fix as the automation cost warning
          in SettingsPage. */}
      {!cliBackendAvailable && (query.data?.providers ?? []).some((p) => p.kind === 'cli' && p.active) && (
        <div className="consequence-notice" role="alert">
          <strong>The active provider cannot run on this hub.</strong>
          <p>
            A CLI runner needs an MCP listener this hub was not started with, so analysis will fail. Set{' '}
            <code>ARGUS_MCP_ADDR</code> on the hub and restart it, or activate an API provider below.
          </p>
        </div>
      )}

      {providers.length > 0 && (
      <ul className="ai-provider-list">
          {providers.map((p) => (
            <li key={p.id} className={p.active ? 'ai-provider ai-provider-active' : 'ai-provider'}>
              <div className="ai-provider-identity">
                <strong>{p.name}</strong>
                <span className={p.active ? 'badge badge-green' : 'badge badge-gray'}>
                  {p.active ? 'active' : 'inactive'}
                </span>
                <span className="badge badge-blue">{p.kind === 'api' ? 'Direct API' : 'Agent CLI'}</span>
              </div>
              <div className="ai-provider-detail">
                {p.kind === 'api' ? (
                  <>
                    <span>{p.baseUrl || '—'}</span>
                    <span>{p.model || 'no model set'}</span>
                    <span className={p.apiKeySet ? undefined : 'text-muted'}>
                      {p.apiKeySet ? 'API key set' : 'no API key'}
                    </span>
                  </>
                ) : (
                  <>
                    <span>{p.runnerUrl || '—'}</span>
                    <span>{p.agent || 'claude'}</span>
                    <span className={p.runnerTokenSet ? undefined : 'text-muted'}>
                      {p.runnerTokenSet ? 'runner token set' : 'no runner token'}
                    </span>
                  </>
                )}
              </div>
              <div className="ai-provider-actions">
                {!p.active && (
                  <button type="button" onClick={() => activateMutation.mutate(p.id)} disabled={busy}>
                    Use this
                  </button>
                )}
                {/* Available on every provider, not just the active one: the
                    whole value is testing a provider BEFORE trusting it with an
                    incident. The title states the cost, because this is the only
                    control in Settings that spends money when clicked. */}
                <button
                  type="button"
                  className="secondary"
                  onClick={() => testMutation.mutate(p.id)}
                  disabled={busy}
                  title={
                    p.kind === 'api'
                      ? 'Send one tiny request (a few tens of tokens) to this endpoint and report what happened'
                      : 'Check the runner is reachable, authenticated and has this CLI installed — no model is called'
                  }
                >
                  {testMutation.isPending && test?.id === p.id ? 'Testing…' : 'Test connection'}
                </button>
                <button type="button" className="secondary" onClick={() => openEdit(p)} disabled={busy}>
                  Edit
                </button>
                {confirmDeleteId === p.id ? (
                  <>
                    <button
                      type="button"
                      className="danger"
                      onClick={() => deleteMutation.mutate(p.id)}
                      disabled={busy}
                    >
                      Confirm delete
                    </button>
                    <button type="button" className="secondary" onClick={() => setConfirmDeleteId(null)}>
                      Cancel
                    </button>
                  </>
                ) : (
                  <button type="button" className="secondary" onClick={() => setConfirmDeleteId(p.id)} disabled={busy}>
                    Delete
                  </button>
                )}
              </div>
              {/* Pending / pass / fail, all three rendered in the same slot so the
                  verdict appears where the button that produced it is. The
                  hub's summary and detail are shown verbatim on failure — a
                  paraphrase would lose exactly the part that says which of a
                  dozen misconfigurations this was. */}
              {test?.id === p.id && test.status === 'pending' && (
                <p className="provider-test-result is-pending" role="status">
                  Testing…{' '}
                  {p.kind === 'api'
                    ? 'sending one short prompt to the endpoint.'
                    : 'checking the runner, its token and its installed CLI.'}
                </p>
              )}
              {test?.id === p.id && test.status === 'passed' && (
                <div className="provider-test-result is-pass" role="status">
                  <strong>{test.result.summary}</strong>
                  <p>{test.result.detail}</p>
                  {test.result.caveat && <p className="provider-test-caveat">{test.result.caveat}</p>}
                  <p className="provider-test-caveat">
                    {/* Reported rather than assumed: it is the evidence that the
                        cost claim above the button is true, and it is the only
                        place the provider's own accounting is ever visible. */}
                    {test.result.model && <>Answered as <code>{test.result.model}</code>. </>}
                    {test.result.latencyMs > 0 && <>Took {test.result.latencyMs} ms. </>}
                    {test.result.tokensIn !== undefined && test.result.tokensIn > 0 && (
                      <>
                        Cost {test.result.tokensIn} prompt and {test.result.tokensOut ?? 0} completion
                        tokens.
                      </>
                    )}
                  </p>
                </div>
              )}
              {test?.id === p.id && test.status === 'failed' && (
                <div className="provider-test-result is-fail" role="alert">
                  <strong>{test.summary}</strong>
                  <p>{test.detail}</p>
                </div>
              )}
              {confirmDeleteId === p.id && p.active && (
                // Said explicitly because it's the one destructive case with a
                // non-obvious consequence: nothing becomes active, and analysis
                // stops until another provider is selected.
                <p className="form-error">
                  This is the active provider. Deleting it leaves no provider active, and analysis
                  will stop until you select another.
                </p>
              )}
            </li>
          ))}
        </ul>
      )}

      {error && dialog.mode === 'closed' && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}

      <div className="settings-actions-row">
        <button type="button" onClick={() => setDialog({ mode: 'choose-kind' })} disabled={busy}>
          Add a provider
        </button>
      </div>

      {dialog.mode === 'choose-kind' && (
        <Dialog title="Add an AI provider" onClose={closeDialog}>
          <p className="field-hint">
            These are two different ways of reaching a model, not two settings of the same thing.
            Pick one to continue.
          </p>
          <div className="kind-choice-list">
            {KIND_OPTIONS.map((opt) => (
              <button key={opt.kind} type="button" className="kind-choice" onClick={() => chooseKind(opt.kind)}>
                <strong>{opt.title}</strong>
                <span>{opt.blurb}</span>
              </button>
            ))}
          </div>
        </Dialog>
      )}

      {dialog.mode === 'configure' && (
        <Dialog title={editing ? `Edit ${form.name || 'provider'}` : `New ${kindLabel} provider`} onClose={closeDialog}>
          <form onSubmit={submit}>
            {!editing && (
              // A way back to step 1 without losing the dialog — the kind is a
              // real decision and changing your mind shouldn't mean cancelling.
              <button type="button" className="link-button" onClick={() => setDialog({ mode: 'choose-kind' })}>
                ← Choose a different kind
              </button>
            )}

            <label htmlFor="providerName">Name</label>
            <input
              id="providerName"
              type="text"
              required
              autoFocus
              placeholder={form.kind === 'api' ? 'e.g. Production API' : 'e.g. Claude runner'}
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
            <p className="field-hint">Only a label, so you can tell your providers apart.</p>

            {editing && (
              <>
                <label htmlFor="providerKind">Kind</label>
                <select
                  id="providerKind"
                  value={form.kind}
                  onChange={(e) => setForm({ ...form, kind: e.target.value as LlmProviderKind })}
                >
                  {KIND_OPTIONS.map((o) => (
                    <option key={o.kind} value={o.kind}>
                      {o.title}
                    </option>
                  ))}
                </select>
              </>
            )}

            {form.kind === 'api' ? (
              <>
                <label htmlFor="providerBaseUrl">Base URL</label>
                <input
                  id="providerBaseUrl"
                  type="text"
                  required
                  placeholder="https://api.openai.com/v1"
                  value={form.baseUrl ?? ''}
                  onChange={(e) => setForm({ ...form, baseUrl: e.target.value })}
                />
                <label htmlFor="providerModel">Model</label>
                <input
                  id="providerModel"
                  type="text"
                  placeholder="claude-sonnet-5"
                  value={form.model ?? ''}
                  onChange={(e) => setForm({ ...form, model: e.target.value })}
                />
                <label htmlFor="providerSecret">API key</label>
                <input
                  id="providerSecret"
                  type="password"
                  autoComplete="new-password"
                  placeholder={editing ? 'Leave blank to keep the stored key' : 'Optional'}
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                />
                <p className="field-hint">
                  Optional — a local endpoint such as Ollama may not need one. Never shown again once
                  saved.
                </p>
              </>
            ) : (
              <>
                <label htmlFor="providerRunnerUrl">Runner URL</label>
                <input
                  id="providerRunnerUrl"
                  type="text"
                  required
                  placeholder="http://argus-cli-runner:8090"
                  value={form.runnerUrl ?? ''}
                  onChange={(e) => setForm({ ...form, runnerUrl: e.target.value })}
                />
                <label htmlFor="providerAgent">Which CLI the runner drives</label>
                <select
                  id="providerAgent"
                  value={form.agent ?? 'claude'}
                  onChange={(e) => setForm({ ...form, agent: e.target.value })}
                >
                  <option value="claude">Claude Code</option>
                  <option value="codex">Codex CLI</option>
                </select>
                <label htmlFor="providerSecret">Runner token</label>
                <input
                  id="providerSecret"
                  type="password"
                  autoComplete="new-password"
                  placeholder={editing ? 'Leave blank to keep the stored token' : 'Optional'}
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                />
                <p className="field-hint">
                  Must match the runner's own <code>ARGUS_CLI_RUNNER_TOKEN</code>. The model
                  credential itself lives in the runner's environment, not here.
                </p>
              </>
            )}

            {error && (
              <p className="form-error" role="alert">
                {error}
              </p>
            )}

            <div className="settings-actions-row">
              <button type="submit" disabled={busy}>
                {saveMutation.isPending ? 'Saving…' : editing ? 'Save changes' : 'Add provider'}
              </button>
              <button type="button" className="secondary" onClick={closeDialog}>
                Cancel
              </button>
            </div>
          </form>
        </Dialog>
      )}
    </>
  )
}
