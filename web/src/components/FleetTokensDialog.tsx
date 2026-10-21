import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ApiError, createEnrollmentToken, listFleetTokens, revokeFleetToken } from '../api/client'
import type { CreateEnrollmentTokenResponse, FleetToken } from '../api/types'
import { CAP_CLUSTER_ACCEPT } from '../api/capabilities'
import { useAuth } from '../auth/useAuth'
import { useHasCapability } from '../auth/useCapabilities'
import { formatDateTime } from '../utils/time'
import { HUB_URL_PLACEHOLDER, TOKEN_SECRET } from '../utils/agentInstall'
import { CopyButton } from './CopyButton'
import { Dialog } from './Dialog'

/**
 * What a GitOps rollout of the agent needs for every cluster: the token in a
 * Secret (from your secret manager, never committed in plain text), and the
 * agent chart's values. `displayName` is the one per-cluster value; an Argo CD
 * ApplicationSet or Flux templating fills it in.
 */
export function fleetRolloutSnippet(token: string, install: CreateEnrollmentTokenResponse['agentInstall']): string {
  return [
    '# 1. In every cluster: the token, as a Secret (create it from your secret manager).',
    'kubectl create namespace argus-system',
    `kubectl -n argus-system create secret generic ${TOKEN_SECRET} --from-literal=token=${token}`,
    '',
    `# 2. The agent chart, ${install.chartRef}${install.chartVersion ? ` version ${install.chartVersion}` : ''}, with these values:`,
    'hub:',
    `  apiUrl: ${install.hubApiUrl ?? HUB_URL_PLACEHOLDER}`,
    'enrollment:',
    '  tokenSecretRef:',
    `    name: ${TOKEN_SECRET}`,
    'displayName: <cluster name>',
    '# argus-system already exists (it holds the Secret), so the chart must not create it.',
    'namespace:',
    '  create: false',
  ].join('\n')
}

export function fleetTokenState(t: FleetToken, now = Date.now()): 'Revoked' | 'Expired' | 'Used up' | 'Active' {
  if (t.revokedAt) return 'Revoked'
  if (new Date(t.expiresAt).getTime() <= now) return 'Expired'
  if (t.redemptions >= t.maxRedemptions) return 'Used up'
  return 'Active'
}

const STATE_BADGE: Record<ReturnType<typeof fleetTokenState>, string> = {
  Active: 'badge badge-green',
  Revoked: 'badge badge-gray',
  Expired: 'badge badge-gray',
  'Used up': 'badge badge-amber',
}

function problemText(err: unknown): string {
  if (err instanceof ApiError) return err.detail ? `${err.message} — ${err.detail}` : err.message
  return 'Something went wrong. Please try again.'
}

/**
 * Fleet tokens: one long-lived, revocable token shared by every cluster a
 * GitOps rollout enrolls, optionally accepting them by itself. The dialog
 * lists them (what each is, how far through its allowance, whether it still
 * works) and issues new ones; a token is shown once, when issued.
 */
export function FleetTokensDialog({ onClose }: { onClose: () => void }) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const canAccept = useHasCapability(CAP_CLUSTER_ACCEPT)
  const [name, setName] = useState('')
  const [days, setDays] = useState(90)
  const [maxRedemptions, setMaxRedemptions] = useState(1000)
  const [autoAccept, setAutoAccept] = useState(false)
  const [issued, setIssued] = useState<CreateEnrollmentTokenResponse | null>(null)

  const tokens = useQuery({
    queryKey: ['fleet-tokens'],
    queryFn: () => listFleetTokens(accessToken!),
    enabled: !!accessToken,
  })
  const create = useMutation({
    mutationFn: () =>
      createEnrollmentToken({ ttlClass: 'F', name, expiresInDays: days, maxRedemptions, autoAccept, scopeHint: {} }, accessToken!),
    onSuccess: (data) => {
      setIssued(data)
      void queryClient.invalidateQueries({ queryKey: ['fleet-tokens'] })
    },
  })
  const revoke = useMutation({
    mutationFn: (id: string) => revokeFleetToken(id, accessToken!),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['fleet-tokens'] }),
  })

  const items = tokens.data?.items ?? []

  return (
    <Dialog title="Fleet tokens" onClose={onClose}>
      {issued ? (
        <div className="token-result">
          <p>
            Fleet token issued, expires <strong>{formatDateTime(issued.expiresAt)}</strong>. Copy it now: it is not
            shown again.
          </p>
          <label>Fleet token</label>
          <div className="code-block-row">
            <code className="code-block">{issued.token}</code>
            <CopyButton text={issued.token} label="Copy" />
          </div>
          <label>Roll the agent out with it (Argo CD, Flux or any GitOps tool)</label>
          <div className="code-block-row">
            <pre className="code-block">{fleetRolloutSnippet(issued.token, issued.agentInstall)}</pre>
            <CopyButton text={fleetRolloutSnippet(issued.token, issued.agentInstall)} label="Copy" />
          </div>
          <div className="modal-actions">
            <button type="button" onClick={() => setIssued(null)}>
              Back to fleet tokens
            </button>
          </div>
        </div>
      ) : (
        <>
          <section aria-label="Fleet tokens">
            {tokens.isLoading && <p className="text-muted">Loading fleet tokens…</p>}
            {tokens.isError && (
              <p className="form-error" role="alert">
                {problemText(tokens.error)}
              </p>
            )}
            {!tokens.isLoading && !tokens.isError && items.length === 0 && (
              <p className="text-muted">No fleet tokens yet. Issue one below to enroll many clusters at once.</p>
            )}
            {items.length > 0 && (
              <div className="table-scroll">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Enrollments</th>
                      <th>Expires</th>
                      <th>Accepts</th>
                      <th>State</th>
                      <th>
                        <span className="visually-hidden">Actions</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((t) => {
                      const state = fleetTokenState(t)
                      const percent = Math.round((100 * t.redemptions) / t.maxRedemptions)
                      return (
                        <tr key={t.id}>
                          <td>{t.name}</td>
                          <td className="resource-usage-cell">
                            <div className="resource-usage">
                              <span className="meter-figure">
                                {t.redemptions} of {t.maxRedemptions}
                              </span>
                              <div className="resource-usage-track" role="img" aria-label={`${t.redemptions} of ${t.maxRedemptions} enrollments used`}>
                                <div className="resource-usage-fill resource-usage-fill-normal" style={{ width: `${Math.min(100, percent)}%` }} />
                              </div>
                            </div>
                          </td>
                          <td>{formatDateTime(t.expiresAt)}</td>
                          <td>{t.autoAccept ? 'Automatically' : 'After approval'}</td>
                          <td>
                            <span className={STATE_BADGE[state]}>{state}</span>
                          </td>
                          <td>
                            <button
                              type="button"
                              className="secondary"
                              disabled={state === 'Revoked' || revoke.isPending}
                              onClick={() => revoke.mutate(t.id)}
                            >
                              Revoke
                            </button>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
            {revoke.isError && (
              <p className="form-error" role="alert">
                {problemText(revoke.error)}
              </p>
            )}
          </section>

          <form
            onSubmit={(e) => {
              e.preventDefault()
              create.mutate()
            }}
          >
            <label htmlFor="fleetTokenName">New fleet token: name</label>
            <input id="fleetTokenName" value={name} required maxLength={100} placeholder="e.g. eu-production" onChange={(e) => setName(e.target.value)} />
            <label htmlFor="fleetTokenDays">Valid for (days, up to 365)</label>
            <input id="fleetTokenDays" type="number" min={1} max={365} value={days} onChange={(e) => setDays(Number(e.target.value) || 1)} />
            <label htmlFor="fleetTokenMax">Enrollments allowed (up to 10,000)</label>
            <input id="fleetTokenMax" type="number" min={1} max={10000} value={maxRedemptions} onChange={(e) => setMaxRedemptions(Number(e.target.value) || 1)} />
            <label className="checkbox-row" title={canAccept ? undefined : `Missing capability: ${CAP_CLUSTER_ACCEPT}`}>
              <input type="checkbox" checked={autoAccept} disabled={!canAccept} onChange={(e) => setAutoAccept(e.target.checked)} />
              Accept clusters that enroll with it automatically
            </label>
            {!canAccept && <p className="field-hint">Needs the {CAP_CLUSTER_ACCEPT} capability: an automatic accept is made on your behalf.</p>}
            {create.isError && (
              <p className="form-error" role="alert">
                {problemText(create.error)}
              </p>
            )}
            <div className="modal-actions">
              <button type="button" className="secondary" onClick={onClose}>
                Close
              </button>
              <button type="submit" disabled={create.isPending || name.trim() === ''}>
                {create.isPending ? 'Issuing…' : 'Issue fleet token'}
              </button>
            </div>
          </form>
        </>
      )}
    </Dialog>
  )
}
