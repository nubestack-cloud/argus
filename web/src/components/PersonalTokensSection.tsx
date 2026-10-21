import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { ApiError, createPersonalToken, listPersonalTokens, revokePersonalToken } from '../api/client'
import type { PersonalToken } from '../api/types'
import { CAP_CLUSTER_INSPECT, CAP_CLUSTER_READ, CAP_INCIDENT_READ, CAP_MCP_USE } from '../api/capabilities'
import { missingCapabilityMessage } from '../api/capabilityInfo'
import { useAuth } from '../auth/useAuth'
import { useHasCapability, useMissingCapabilities } from '../auth/useCapabilities'
import { CopyButton } from './CopyButton'
import { Dialog } from './Dialog'
import { HelpTip } from './HelpTip'
import { SkeletonLines } from './Skeleton'
import { Tabs } from './Tabs'
import { formatDateTime, formatRelativeTime } from '../utils/time'

// Settings → AI tools & tokens (PROJECT.md AD3).
//
// A person's OWN credentials for pointing their AI tool (Claude Code, Cursor,
// VS Code) at the hub's MCP endpoint. Two cards, stacked, because they answer
// two different questions in the order someone arrives with them:
//
//   1. "Which tokens can act as me, and how do I make or kill one?" — the
//      list, the create form and the one-time reveal of a new secret.
//   2. "How do I connect a tool, and what will it be able to do?" — the
//      endpoint, a setup snippet per client, and what this person's own role
//      lets a connected tool reach.
//
// Every number and state here is the hub's: status is computed server-side
// (no clock comparison in the browser), the active-token ceiling is served,
// and "what a tool can reach" reads the viewer's effective permissions.

const TOKEN_PLACEHOLDER = '<your-token>'

// Offered lifetimes. Bounded by the hub's own maxDays at render time, so a
// lowered ceiling never offers a choice the hub would refuse.
const LIFETIME_DAYS = [7, 30, 90, 180, 365]

function describeDays(days: number): string {
  if (days === 365) return '1 year'
  if (days >= 30 && days % 30 === 0) return `${days / 30} month${days === 30 ? '' : 's'} (${days} days)`
  return `${days} days`
}

// The URL a client outside the browser must use: in a production build the
// hub serves this page, so its own origin; under the Vite dev server the hub
// is VITE_API_BASE_URL (the same reasoning as EnrollTokenModal's apiUrl).
function mcpEndpointUrl(): string {
  const base = (import.meta.env.VITE_API_BASE_URL as string | undefined) || window.location.origin
  return `${base.replace(/\/+$/, '')}/api/v1/mcp`
}

type ClientId = 'claude' | 'cursor' | 'vscode'

function snippetFor(client: ClientId, url: string, token: string): string {
  switch (client) {
    case 'claude':
      // Continuation lines rather than one long line, so the whole command is
      // readable without scrolling; bash and zsh both accept it as pasted.
      return `claude mcp add --transport http argus \\\n  ${url} \\\n  --header "Authorization: Bearer ${token}"`
    case 'cursor':
      return JSON.stringify(
        { mcpServers: { argus: { url, headers: { Authorization: `Bearer ${token}` } } } },
        null,
        2,
      )
    case 'vscode':
      // VS Code prompts for the token once and keeps it in its secret store,
      // so the token never sits in a file that may be committed. That is
      // VS Code's documented pattern for a credential (`inputs` +
      // `${input:id}`), and the reason this snippet never embeds the secret.
      return JSON.stringify(
        {
          inputs: [{ type: 'promptString', id: 'argus-token', description: 'ARGUS personal access token', password: true }],
          servers: {
            argus: { type: 'http', url, headers: { Authorization: 'Bearer ${input:argus-token}' } },
          },
        },
        null,
        2,
      )
  }
}

const CLIENT_HINTS: Record<ClientId, string> = {
  claude:
    'Run this in a terminal. It adds ARGUS for the current project; add --scope user to make it available in every project.',
  cursor:
    'Add this to ~/.cursor/mcp.json to use ARGUS in every project. A project’s own .cursor/mcp.json works too — keep the token out of version control.',
  vscode:
    'Add this to .vscode/mcp.json (or your user MCP configuration). VS Code asks for the token the first time the server starts and stores it securely, so it is not written into the file.',
}

function errorText(error: unknown, fallback: string): string {
  if (error instanceof ApiError) return error.detail ? `${error.message} — ${error.detail}` : error.message
  return fallback
}

function daysUntil(iso: string): number {
  return Math.ceil((new Date(iso).getTime() - Date.now()) / 86_400_000)
}

function StatusBadge({ token }: { token: PersonalToken }) {
  if (token.status === 'revoked') return <span className="badge badge-gray">Revoked</span>
  if (token.status === 'expired') return <span className="badge badge-gray">Expired</span>
  return <span className="badge badge-green">Active</span>
}

// A date, not a timestamp: a token's life is counted in days, and seconds
// here are noise. The full instant is on the cell's title.
function formatDay(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })
}

function ExpiryCell({ token }: { token: PersonalToken }) {
  if (token.status === 'revoked' && token.revokedAt) {
    return <span title={formatDateTime(token.revokedAt)}>Revoked {formatDay(token.revokedAt)}</span>
  }
  const days = daysUntil(token.expiresAt)
  return (
    <span className="pat-expiry">
      <span title={formatDateTime(token.expiresAt)}>{formatDay(token.expiresAt)}</span>
      {/* A token about to lapse is still a working credential; the words are
          the warning, so the tool it is configured in does not stop without
          notice. */}
      {token.status === 'active' && days <= 7 && (
        <span className="badge badge-amber">
          in {days} day{days === 1 ? '' : 's'}
        </span>
      )}
    </span>
  )
}

function TokenTable({ tokens, onRevoke }: { tokens: PersonalToken[]; onRevoke?: (t: PersonalToken) => void }) {
  return (
    <div className="table-scroll">
      <table className="data-table pat-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Status</th>
            <th>Created</th>
            <th>Last used</th>
            <th>{onRevoke ? 'Expires' : 'Ended'}</th>
            <th>
              Ends with <HelpTip label="Ends with" text="The last four characters of the token, so you can match a row to the token configured in a tool. The rest of it is never stored." />
            </th>
            {onRevoke && (
              <th>
                <span className="visually-hidden">Actions</span>
              </th>
            )}
          </tr>
        </thead>
        <tbody>
          {tokens.map((t) => (
            <tr key={t.id}>
              <td className="pat-name" data-label="Name">{t.name}</td>
              <td data-label="Status">
                <StatusBadge token={t} />
              </td>
              <td data-label="Created">
                <span title={formatDateTime(t.createdAt)}>{formatRelativeTime(t.createdAt)}</span>
              </td>
              <td data-label="Last used">
                {t.lastUsedAt ? (
                  <span title={formatDateTime(t.lastUsedAt)}>{formatRelativeTime(t.lastUsedAt)}</span>
                ) : (
                  'Never'
                )}
              </td>
              <td data-label={onRevoke ? 'Expires' : 'Ended'}>
                <ExpiryCell token={t} />
              </td>
              <td data-label="Ends with">
                <code>…{t.hint}</code>
              </td>
              {onRevoke && (
                <td className="pat-actions">
                  <button type="button" className="secondary" onClick={() => onRevoke(t)}>
                    Revoke…
                  </button>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function PersonalTokensSection() {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const canCreate = useHasCapability(CAP_MCP_USE)
  const reach = useMissingCapabilities([CAP_MCP_USE, CAP_CLUSTER_READ, CAP_INCIDENT_READ, CAP_CLUSTER_INSPECT])

  const query = useQuery({
    queryKey: ['personal-tokens'],
    queryFn: () => listPersonalTokens(accessToken!),
    enabled: !!accessToken,
  })

  const [name, setName] = useState('')
  const [days, setDays] = useState<number | null>(null)
  // The just-created secret. Held in component state only — never in the
  // query cache, never in storage — and dropped on "Done" or navigation.
  const [revealed, setRevealed] = useState<{ name: string; secret: string; expiresAt: string } | null>(null)
  const [confirming, setConfirming] = useState<PersonalToken | null>(null)
  const [client, setClient] = useState<ClientId>('claude')

  const create = useMutation({
    mutationFn: () =>
      createPersonalToken({ name: name.trim(), expiresInDays: days ?? query.data?.defaultDays ?? 90 }, accessToken!),
    onSuccess: (res) => {
      setRevealed({ name: res.token.name, secret: res.secret, expiresAt: res.token.expiresAt })
      setName('')
      queryClient.invalidateQueries({ queryKey: ['personal-tokens'] })
    },
  })
  const revoke = useMutation({
    mutationFn: (id: string) => revokePersonalToken(id, accessToken!),
    onSuccess: () => {
      setConfirming(null)
      queryClient.invalidateQueries({ queryKey: ['personal-tokens'] })
    },
  })

  const tokens = query.data?.tokens ?? []
  const active = tokens.filter((t) => t.status === 'active')
  const inactive = tokens.filter((t) => t.status !== 'active')
  const maxActive = query.data?.maxActive
  const atCeiling = maxActive != null && active.length >= maxActive

  const createBlockedReason = !canCreate
    ? missingCapabilityMessage([CAP_MCP_USE])
    : atCeiling
      ? `You already hold ${maxActive} active tokens, the most one person may hold. Revoke one you no longer use first.`
      : undefined
  const maxDays = query.data?.maxDays ?? 365
  const lifetimeOptions = LIFETIME_DAYS.filter((d) => d <= maxDays)
  const selectedDays = days ?? query.data?.defaultDays ?? 90

  const url = mcpEndpointUrl()
  const snippetToken = revealed && client !== 'vscode' ? revealed.secret : TOKEN_PLACEHOLDER
  const snippet = snippetFor(client, url, snippetToken)

  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (createBlockedReason || !name.trim()) return
    create.mutate()
  }

  const reachRow = (cap: string, what: string) => {
    let answer: string
    if (!reach.resolved) answer = '—'
    // mcp:use first: without it no token works at all, whatever else is held.
    else if (reach.missing.includes(CAP_MCP_USE)) answer = `No — needs ${CAP_MCP_USE}`
    else if (reach.missing.includes(cap)) answer = `No — needs ${cap}`
    else answer = 'Yes'
    return (
      <div key={cap}>
        <dt>{what}</dt>
        <dd>{answer}</dd>
      </div>
    )
  }

  return (
    <div className="settings-section" role="tabpanel">
      <div className="card settings-panel pat-card">
        <div className="card-head">
          <h2>Personal access tokens</h2>
          <HelpTip
            label="Personal access tokens"
            text="A token lets an MCP client — an AI tool on your machine — call ARGUS's read-only tools as you. It reaches only what your own role reaches, checked on every call, and stops working when it expires, when you revoke it, or when your account is disabled."
          />
          {query.data && (
            <span className="card-head-meta">
              {active.length} of {maxActive} active
            </span>
          )}
        </div>
        <p className="field-hint">
          Each token lets one AI tool use ARGUS as you, read-only. Every call it makes is in the audit log under your
          name.
        </p>

        {revealed && (
          <div className="pat-reveal" role="status">
            <p>
              <strong>Copy “{revealed.name}” now.</strong> ARGUS keeps only a hash of it, so this is the only time it
              can be shown. It expires on {formatDay(revealed.expiresAt)}.
            </p>
            <div className="code-block-row">
              <code className="code-block">{revealed.secret}</code>
              <CopyButton text={revealed.secret} label="Copy token" />
            </div>
            <p className="field-hint">The setup snippets under “Connect an AI tool” now include it.</p>
            <div>
              <button type="button" className="secondary" onClick={() => setRevealed(null)}>
                Done — I have copied it
              </button>
            </div>
          </div>
        )}

        {query.isLoading && <SkeletonLines count={4} />}
        {query.isError && (
          <p className="form-error" role="alert">
            {errorText(query.error, 'Could not load your tokens.')}
          </p>
        )}

        {query.data && active.length === 0 && (
          <p className="empty-state">
            {inactive.length === 0
              ? canCreate
                ? 'You have no tokens yet. Create one below for each AI tool you want to connect.'
                : 'You have no tokens.'
              : `You have no active tokens. ${inactive.length} expired or revoked ${inactive.length === 1 ? 'token is' : 'tokens are'} listed below.`}
          </p>
        )}
        {active.length > 0 && <TokenTable tokens={active} onRevoke={setConfirming} />}

        {inactive.length > 0 && (
          <details className="pat-inactive">
            <summary>
              Expired and revoked <span className="pat-summary-count">· {inactive.length}</span>
            </summary>
            <TokenTable tokens={inactive} />
          </details>
        )}

        {revoke.isError && !confirming && (
          <p className="form-error" role="alert">
            {errorText(revoke.error, 'Could not revoke that token.')}
          </p>
        )}

        <form className="pat-create-form" onSubmit={submit}>
          <h3>Create a token</h3>
          <div className="pat-create-fields">
            <div className="pat-field">
              <label htmlFor="pat-name">Name</label>
              <input
                id="pat-name"
                required
                maxLength={100}
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Which tool and machine, e.g. Claude Code on my laptop"
                disabled={!!createBlockedReason}
                title={createBlockedReason}
              />
            </div>
            <div className="pat-field">
              <label htmlFor="pat-lifetime">Expires after</label>
              <select
                id="pat-lifetime"
                value={selectedDays}
                onChange={(e) => setDays(Number(e.target.value))}
                disabled={!!createBlockedReason}
                title={createBlockedReason}
              >
                {lifetimeOptions.map((d) => (
                  <option key={d} value={d}>
                    {describeDays(d)}
                    {d === query.data?.defaultDays ? ' — default' : ''}
                  </option>
                ))}
              </select>
            </div>
            <div className="pat-field pat-submit">
              <button
                type="submit"
                disabled={!!createBlockedReason || create.isPending || !name.trim()}
                title={createBlockedReason}
              >
                {create.isPending ? 'Creating…' : 'Create token'}
              </button>
            </div>
          </div>
          {createBlockedReason && <p className="field-hint">{createBlockedReason}</p>}
          {create.isError && (
            <p className="form-error" role="alert">
              {errorText(create.error, 'Could not create the token.')}
            </p>
          )}
        </form>
      </div>

      <div className="card settings-panel pat-card">
        <div className="card-head">
          <h2>Connect an AI tool</h2>
          <HelpTip
            label="MCP"
            text="MCP (Model Context Protocol) is how AI tools such as Claude Code, Cursor and VS Code call outside tools. ARGUS serves its read-only investigation tools over MCP at the endpoint below."
          />
        </div>
        <div className="pat-field">
          <span className="pat-label" id="pat-endpoint-label">
            MCP endpoint
          </span>
          <div className="code-block-row">
            <code className="code-block" aria-labelledby="pat-endpoint-label">
              {url}
            </code>
            <CopyButton text={url} label="Copy URL" />
          </div>
        </div>

        <Tabs
          label="AI tool"
          active={client}
          onChange={(id) => setClient(id as ClientId)}
          tabs={[
            { id: 'claude', label: 'Claude Code' },
            { id: 'cursor', label: 'Cursor' },
            { id: 'vscode', label: 'VS Code' },
          ]}
        >
          <div className="pat-snippet">
            <p className="field-hint">{CLIENT_HINTS[client]}</p>
            <div className="code-block-row">
              <pre className="code-block">{snippet}</pre>
              <CopyButton text={snippet} label="Copy" />
            </div>
            <p className="field-hint">
              {client === 'vscode'
                ? 'Paste your token when VS Code asks for it.'
                : revealed
                  ? `Includes the token you just created (“${revealed.name}”).`
                  : canCreate
                    ? `Replace ${TOKEN_PLACEHOLDER} with a token — create one above; it is shown only once.`
                    : `Replace ${TOKEN_PLACEHOLDER} with a token. Creating one needs ${CAP_MCP_USE}.`}
            </p>
          </div>
        </Tabs>

        <h3>What a connected tool can reach</h3>
        <dl className="check-rows pat-reach">
          {reachRow(CAP_CLUSTER_READ, 'Clusters and their status')}
          {reachRow(CAP_INCIDENT_READ, 'Incidents, AI analyses and signals')}
          {reachRow(CAP_CLUSTER_INSPECT, 'Live objects: describe, events, logs, relationships, traces')}
          <div>
            <dt>Changing anything — approvals, remediation, settings</dt>
            <dd>Never. The endpoint offers read-only tools only.</dd>
          </div>
        </dl>
        <p className="field-hint">
          Decided by your own role on every call.{' '}
          <HelpTip
            label="token access"
            text="Checked against your role on every call, and only on the clusters it covers — so a change to your access applies to your tools at once. Log reads, like every other call, are recorded in the audit log."
          />
        </p>
      </div>

      {confirming && (
        <Dialog title="Revoke this token?" onClose={() => setConfirming(null)}>
          <p>
            <strong>{confirming.name}</strong> (ends with <code>…{confirming.hint}</code>) stops working on its next
            request. Any AI tool configured with it loses access to ARGUS until you give it a new token. This cannot be
            undone.
          </p>
          {revoke.isError && (
            <p className="form-error" role="alert">
              {errorText(revoke.error, 'Could not revoke that token.')}
            </p>
          )}
          <div className="modal-actions">
            <button type="button" className="secondary" onClick={() => setConfirming(null)}>
              Cancel
            </button>
            <button
              type="button"
              className="danger"
              disabled={revoke.isPending}
              onClick={() => revoke.mutate(confirming.id)}
            >
              {revoke.isPending ? 'Revoking…' : `Revoke “${confirming.name}”`}
            </button>
          </div>
        </Dialog>
      )}
    </div>
  )
}
