import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { upgradeClusterAgent } from '../api/client'
import { CAP_AGENT_UPGRADE } from '../api/capabilities'
import { missingCapabilityMessage } from '../api/capabilityInfo'
import { useAuth } from '../auth/useAuth'
import { useMissingCapabilities } from '../auth/useCapabilities'
import { ConfirmDialog } from '../components/ConfirmDialog'

// The agent's image against the one this hub was released with, and the
// "Upgrade agent" action when the cluster's chart allows it (PROJECT.md AD10).
// The button is always there once the images differ: disabled, with the
// reason, when the viewer lacks agent:upgrade or the chart does not enable
// self-upgrade — in which case the helm command is the way, and it is shown.

const short = (img?: string | null) => {
  if (!img) return '—'
  const at = img.indexOf('@sha256:')
  return at > 0 ? `${img.slice(img.lastIndexOf('/', at) + 1, at)}@${img.slice(at + 8, at + 20)}` : img.slice(img.lastIndexOf('/') + 1)
}

export function AgentUpgradeControl({
  clusterId,
  agent,
  hubAgentImage,
}: {
  clusterId: string
  agent?: { image?: string; namespace?: string; selfUpgrade: boolean } | null
  hubAgentImage?: string | null
}) {
  const { accessToken } = useAuth()
  const qc = useQueryClient()
  const { resolved, missing } = useMissingCapabilities([CAP_AGENT_UPGRADE])
  const [confirming, setConfirming] = useState(false)
  const mutation = useMutation({
    mutationFn: () => upgradeClusterAgent(clusterId, accessToken!),
    onSuccess: () => {
      setConfirming(false)
      void qc.invalidateQueries({ queryKey: ['clusters', clusterId] })
    },
  })
  if (!hubAgentImage || !agent?.image) return null
  const current = agent.image === hubAgentImage
  const denied = resolved && missing.length > 0 ? missingCapabilityMessage(missing) : undefined
  const disabledReason = denied ?? (agent.selfUpgrade ? undefined : 'This cluster’s agent chart does not allow upgrades from the hub (selfUpgrade.enabled).')
  return (
    <div className="agent-upgrade">
      <dl className="kv-list">
        <dt>Running</dt>
        <dd className="fleet-mono" title={agent.image}>
          {short(agent.image)}
        </dd>
        <dt>Released with this hub</dt>
        <dd className="fleet-mono" title={hubAgentImage}>
          {short(hubAgentImage)}
        </dd>
      </dl>
      {current ? (
        <p className="field-hint">
          <span className="badge badge-green">Current</span> The agent runs the image this hub was released with.
        </p>
      ) : (
        <>
          <button type="button" className="secondary" disabled={!!disabledReason || mutation.isPending} title={disabledReason} onClick={() => setConfirming(true)}>
            Upgrade agent
          </button>
          {disabledReason && <p className="field-hint">{disabledReason}</p>}
          {!agent.selfUpgrade && (
            <pre className="code-block">{`helm upgrade argus-agent <agent chart> -n ${agent.namespace || 'argus-system'} --reuse-values --set image.digest=${hubAgentImage.split('@sha256:')[1] ? 'sha256:' + hubAgentImage.split('@sha256:')[1] : '<digest>'}`}</pre>
          )}
          {mutation.isSuccess && (
            <p className="field-hint" role="status">
              Accepted. The agent restarts onto the new image and reconnects within a minute or two.
            </p>
          )}
        </>
      )}
      {confirming && (
        <ConfirmDialog
          title="Upgrade this cluster's agent?"
          confirmLabel="Upgrade agent"
          pendingLabel="Upgrading…"
          tone="default"
          pending={mutation.isPending}
          error={mutation.error}
          onConfirm={() => mutation.mutate()}
          onCancel={() => setConfirming(false)}
        >
          <p>
            Both agent Deployments move to <span className="fleet-mono">{short(hubAgentImage)}</span> and restart. Detection pauses for the minute
            that takes; the change is recorded in the audit log.
          </p>
        </ConfirmDialog>
      )}
    </div>
  )
}
