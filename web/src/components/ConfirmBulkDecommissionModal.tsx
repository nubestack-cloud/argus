import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { decommissionCluster, ApiError } from '../api/client'
import { useAuth } from '../auth/useAuth'
import { Dialog } from './Dialog'
import { BulkResultList, type BulkActionResult } from './BulkActionBar'

// The bulk counterpart of ConfirmDecommissionModal.tsx. Reuses the exact
// same POST /clusters/{id}/decommission endpoint — once per selected
// cluster, via Promise.allSettled — rather than a new bulk backend route:
// that endpoint already handles dismissing a cluster's open incidents, the
// audit record, and the terminal-state check, and duplicating any of that
// server-side for a batch would be the exact "widened action surface" this
// codebase has a standing preference against.
//
// The single-item modal confirms by typing the cluster's own display name,
// which does not generalise to N clusters at once — asking someone to type
// eight names correctly is friction with no safety benefit. Typing the
// fixed phrase below keeps the same "deliberate, typed action" shape for an
// irreversible batch without pretending a list of names can be retyped.
const CONFIRM_PHRASE = 'DECOMMISSION'

// How many names this dialog names before falling back to "and N more" —
// long enough to be useful, short enough that a fifty-cluster selection
// doesn't turn the confirmation itself into an unscannable list. The
// remainder is stated, never silently dropped (anti-patterns.md's "no
// unlabelled partial").
const NAME_PREVIEW_LIMIT = 8

export function ConfirmBulkDecommissionModal({
  clusters,
  onClose,
}: {
  clusters: Array<{ id: string; displayName: string }>
  onClose: () => void
}) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const [typed, setTyped] = useState('')
  const [running, setRunning] = useState(false)
  const [results, setResults] = useState<BulkActionResult[] | null>(null)

  const matches = typed.trim().toUpperCase() === CONFIRM_PHRASE

  const runBulkDecommission = async () => {
    setRunning(true)
    const settled = await Promise.allSettled(
      clusters.map((cluster) => decommissionCluster(cluster.id, accessToken!)),
    )
    // Aggregated per-row, never collapsed to one pass/fail for the batch
    // (the task's own "no fabricated data" rule) — a cluster that failed
    // (already archived by someone else in the meantime, a network blip)
    // must say so by name, not vanish into a rounded total.
    setResults(
      settled.map((outcome, index) => {
        const cluster = clusters[index]
        if (outcome.status === 'fulfilled') {
          return { id: cluster.id, label: cluster.displayName, status: 'succeeded' as const }
        }
        const reason = outcome.reason
        const detail =
          reason instanceof ApiError
            ? reason.detail
              ? `${reason.message} — ${reason.detail}`
              : reason.message
            : 'Something went wrong.'
        return { id: cluster.id, label: cluster.displayName, status: 'failed' as const, detail }
      }),
    )
    setRunning(false)
    queryClient.invalidateQueries({ queryKey: ['clusters'] })
    queryClient.invalidateQueries({ queryKey: ['incidents'] })
  }

  if (results) {
    return (
      <Dialog title="Bulk decommission results" onClose={onClose}>
        <BulkResultList results={results} />
        <div className="modal-actions">
          <button type="button" onClick={onClose}>
            Done
          </button>
        </div>
      </Dialog>
    )
  }

  const previewNames = clusters.slice(0, NAME_PREVIEW_LIMIT).map((cluster) => cluster.displayName)
  const remainder = clusters.length - previewNames.length

  return (
    <Dialog title="Decommission clusters" onClose={onClose}>
      <p>
        This permanently archives <strong>{clusters.length}</strong>{' '}
        {clusters.length === 1 ? 'cluster' : 'clusters'}: {previewNames.join(', ')}
        {remainder > 0 ? `, and ${remainder} more` : ''}. Each one's tunnel connection is cut immediately if
        it's currently open, and refused on any future attempt to reconnect; each one's open incidents are
        dismissed. The agent itself keeps running in-cluster until removed by hand. This cannot be undone.
      </p>

      <form
        onSubmit={(event) => {
          event.preventDefault()
          if (matches && !running) runBulkDecommission()
        }}
      >
        <label htmlFor="confirm-bulk-decommission">
          Type <strong>{CONFIRM_PHRASE}</strong> to confirm
        </label>
        <input
          id="confirm-bulk-decommission"
          type="text"
          value={typed}
          onChange={(event) => setTyped(event.target.value)}
          autoComplete="off"
          autoFocus
        />

        <div className="modal-actions">
          <button type="button" className="secondary" onClick={onClose} disabled={running}>
            Cancel
          </button>
          <button type="submit" className="danger" disabled={!matches || running}>
            {running ? 'Decommissioning…' : `Decommission ${clusters.length}`}
          </button>
        </div>
      </form>
    </Dialog>
  )
}
