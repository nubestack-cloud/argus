import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { decommissionCluster, ApiError } from '../api/client'
import { useAuth } from '../auth/useAuth'
import { Dialog } from './Dialog'

// Archiving is a one-way transition (lld/03-agent-protocol.md §4 — Archived
// is terminal, reachable only by explicit action) — type-the-name-to-confirm
// is the standard higher-friction pattern for exactly this shape of
// irreversible action (matches how most infra products guard cluster/repo
// deletion), replacing the plain window.confirm() this first slice shipped
// with.
export function ConfirmDecommissionModal({
  clusterId,
  displayName,
  onClose,
}: {
  clusterId: string
  displayName: string
  onClose: () => void
}) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const [typedName, setTypedName] = useState('')
  // Set once the decommission call succeeds, to switch this modal from the
  // confirm-by-typing form to a follow-up screen explaining what did and
  // didn't just happen (see the render branch below) — closing immediately
  // on success, as this used to, meant the "the agent is still running,
  // here's how to actually remove it" message had nowhere to be shown.
  const [decommissioned, setDecommissioned] = useState(false)

  const mutation = useMutation({
    mutationFn: () => decommissionCluster(clusterId, accessToken!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['clusters'] })
      setDecommissioned(true)
    },
  })

  const matches = typedName === displayName

  // Decommissioning only ever updates the hub's own records (and, as of
  // this increment, force-closes a live tunnel if one happened to be open
  // — internal/gateway.Gateway.Disconnect, called from
  // handleDecommissionCluster). It has no channel back into the cluster
  // itself: the argus-agent process keeps running and will keep retrying
  // its connection forever, getting refused every time
  // (lookupClusterBySerial's clusterState check), indistinguishable to it
  // from a network blip. The only real fix is a human removing it
  // in-cluster — this is that instruction, shown right where an operator
  // would otherwise wrongly assume "decommission" already did it. The
  // exact command mirrors the one this repo's own tooling actually runs
  // (cmd/argusctl/main.go's helmInstall / its printed manual-install
  // fallback, and EnrollTokenModal.tsx's install snippet): release name
  // "argus-agent", namespace "argus-system" (deploy/helm/argus-agent/
  // values.yaml's fixed namespace.name), `--kube-context` to pick the
  // target cluster.
  if (decommissioned) {
    return (
      <Dialog title="Cluster decommissioned" onClose={onClose}>
          <p>
            <strong>{displayName}</strong>&rsquo;s connection has been cut, and the hub will
            refuse it if it tries to reconnect.
          </p>
          <p>
            The agent is still running inside the cluster, though — decommissioning only updates
            the hub&rsquo;s own records, it cannot reach into the cluster to remove anything
            there. Left alone, it will keep retrying its connection forever. To fully remove it,
            run this against that cluster&rsquo;s own kubeconfig context:
          </p>
          <pre className="code-block">
            helm uninstall argus-agent -n argus-system --kube-context &lt;your-context&gt;
          </pre>

          <div className="modal-actions">
            <button type="button" onClick={onClose}>
              Done
            </button>
          </div>
      </Dialog>
    )
  }

  return (
    <Dialog title="Decommission cluster" onClose={onClose}>
        {/* prose-ok: an irreversible dialog's consequence statement */}
        <p>
          This permanently archives <strong>{displayName}</strong>. Its tunnel connection is cut
          immediately if it's currently open, and refused on any future attempt to reconnect — but
          the agent itself keeps running in-cluster until it's removed by hand (you'll be shown how,
          next). It will disappear from this list. This cannot be undone.
        </p>

        <form
          onSubmit={(e) => {
            e.preventDefault()
            if (matches) mutation.mutate()
          }}
        >
          <label htmlFor="confirm-name">
            Type <strong>{displayName}</strong> to confirm
          </label>
          <input
            id="confirm-name"
            type="text"
            value={typedName}
            onChange={(e) => setTypedName(e.target.value)}
            autoComplete="off"
            autoFocus
          />

          {mutation.isError && (
            <p className="form-error" role="alert">
              {mutation.error instanceof ApiError
                ? mutation.error.detail
                  ? `${mutation.error.message} — ${mutation.error.detail}`
                  : mutation.error.message
                : 'Something went wrong.'}
            </p>
          )}

          <div className="modal-actions">
            <button type="button" className="secondary" onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className="danger" disabled={!matches || mutation.isPending}>
              {mutation.isPending ? 'Decommissioning…' : 'Decommission'}
            </button>
          </div>
        </form>
    </Dialog>
  )
}
