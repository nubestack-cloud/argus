import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { createEnrollmentToken, ApiError } from '../api/client'
import type { CreateEnrollmentTokenResponse, TtlClass } from '../api/types'
import { useAuth } from '../auth/useAuth'
import { CopyButton } from './CopyButton'
import { Dialog } from './Dialog'
import { AgentInstallNotes } from './AgentInstallNotes'
import { agentInstallCommand } from '../utils/agentInstall'

// BUGS.md 72. These labels used to name DESIGN.md §6.1's four *onboarding
// paths* — "A — admin kubeconfig install", "B — self-service install
// command", "C — bulk enrollment" — which read as three different ways to
// enrol a cluster. They are not. `ttlClass` is the only thing they set, and
// the only thing a ttlClass decides (internal/authz/enrollment.go's
// `ttlClassDefaults`) is the token's lifetime and whether it may be redeemed
// more than once. Whichever one you picked, this modal then rendered a
// byte-identical `helm install`, because there is exactly one enrolment
// mechanism and there is deliberately only ever going to be one:
// **kubeconfig-based enrollment is decided against** (BACKLOG.md Q2,
// docs/DEPLOYMENT.md §3) precisely so the hub never holds a cluster
// credential, which DESIGN.md §3.1 calls the most important decision in the
// design. Path A's short TTL is justified in lld/03 §2 by "the bootstrap
// worker redeems it itself, immediately — no human copies this one", and
// that worker does not exist; offering it to a human who does copy it made
// the 15 minutes a trap rather than a tightening.
//
// So the labels now state the only axis that is real. The classes keep their
// wire values (A/B/C) because the hub, the audit record and lld/03 §2 all
// speak them; nothing about the API changed here.
const TTL_CLASS_LABELS: Record<TtlClass, string> = {
  A: 'Short-lived — expires in 15 minutes, one cluster',
  B: 'Standard — expires in 1 hour, one cluster',
  C: 'Bulk — expires in 24 hours, several clusters',
}

export function EnrollTokenModal({ onClose }: { onClose: () => void }) {
  const { accessToken } = useAuth()
  const [ttlClass, setTtlClass] = useState<TtlClass>('B')
  const [maxRedemptions, setMaxRedemptions] = useState(1)
  const [result, setResult] = useState<CreateEnrollmentTokenResponse | null>(null)

  const mutation = useMutation({
    mutationFn: () =>
      createEnrollmentToken(
        {
          ttlClass,
          maxRedemptions: ttlClass === 'C' ? maxRedemptions : 1,
          scopeHint: {},
        },
        accessToken!,
      ),
    onSuccess: (data) => setResult(data),
  })

  return (
    <Dialog title="Enroll a cluster" onClose={onClose}>
        {!result && (
          <form
            onSubmit={(e) => {
              e.preventDefault()
              mutation.mutate()
            }}
          >
            <label htmlFor="ttlClass">Token lifetime</label>
            <select
              id="ttlClass"
              value={ttlClass}
              onChange={(e) => setTtlClass(e.target.value as TtlClass)}
            >
              {Object.entries(TTL_CLASS_LABELS).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
            {/* Says the thing the old "Token type" labels implied the
                opposite of. There is one install path; this only chooses how
                long the token stays valid. */}
            <p className="field-hint">
              Every choice produces the same install command — this only sets how long the token
              stays valid. ARGUS has one enrollment path: the agent generates its own key in the
              target cluster and the hub issues it a certificate, so{' '}
              <strong>no kubeconfig or cluster credential ever reaches this hub</strong>.
            </p>

            {ttlClass === 'C' && (
              <>
                <label htmlFor="maxRedemptions">Max redemptions</label>
                <input
                  id="maxRedemptions"
                  type="number"
                  min={1}
                  value={maxRedemptions}
                  onChange={(e) => setMaxRedemptions(Number(e.target.value) || 1)}
                />
              </>
            )}

            {mutation.isError && (
              <p className="form-error" role="alert">
                {mutation.error instanceof ApiError
                  ? mutation.error.detail
                    ? `${mutation.error.message} — ${mutation.error.detail}`
                    : mutation.error.message
                  : 'Something went wrong. Please try again.'}
              </p>
            )}

            <button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? 'Generating…' : 'Generate token'}
            </button>
          </form>
        )}

        {result && (
          <div className="token-result">
            <p>
              Token generated, expires <strong>{new Date(result.expiresAt).toLocaleString()}</strong>.
            </p>

            <label>Enrollment token</label>
            <div className="code-block-row">
              <code className="code-block">{result.token}</code>
              <CopyButton text={result.token} label="Copy" />
            </div>

            <label>Run this against the target cluster (needs helm and access to that cluster)</label>
            <div className="code-block-row">
              <pre className="code-block">{agentInstallCommand(result.token, result.agentInstall)}</pre>
              <CopyButton text={agentInstallCommand(result.token, result.agentInstall)} label="Copy" />
            </div>
            <AgentInstallNotes install={result.agentInstall} />
            <p className="field-hint">
              Deploys the agent in-cluster with the least-privilege <code>argus-investigate</code>{' '}
              ServiceAccount — no kubeconfig ever reaches this hub.
            </p>
            <p className="field-hint">
              Enrolling many clusters? Issue one fleet token under <strong>Fleet tokens</strong> and roll the
              agent chart out with your GitOps tool.
            </p>

            <button type="button" onClick={onClose}>
              Done
            </button>
          </div>
        )}
    </Dialog>
  )
}
