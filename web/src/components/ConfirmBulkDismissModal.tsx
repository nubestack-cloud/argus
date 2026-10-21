import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { dismissIncident, ApiError } from '../api/client'
import { useAuth } from '../auth/useAuth'
import { Dialog } from './Dialog'
import { BulkResultList, type BulkActionResult } from './BulkActionBar'

// The bulk counterpart of IncidentDetailPage.tsx's own "Dismiss…" control
// (TriageControls). Reuses POST /incidents/{id}/dismiss once per selected
// incident, via Promise.allSettled, rather than a new bulk endpoint — same
// reasoning as ConfirmBulkDecommissionModal.tsx.
//
// Dismiss, not resolve, is the bulk action offered here: dismiss is the
// conservative choice of the two close-out verdicts (it asserts nothing
// about the problem being fixed, only that it needs no ARGUS action), and
// the owner's own BUGS.md note named no specific incident action, only
// "bulk action like decommissioning the clusters" as an example on the
// other page — so the most clearly-safe existing action was picked rather
// than guessing at resolve, which asserts a stronger claim ("the problem is
// gone") that a bulk operator is in a worse position to actually know.
//
// One shared note applies to every selected incident, same requiredness as
// the single-incident dismiss (the hub 400s without one) — asking for N
// separate notes would make a bulk action slower than doing each one by
// hand, defeating the point of it.
const NAME_PREVIEW_LIMIT = 8

// Two exits, not one: `onCancel` (Cancel, ×, Escape, backdrop — nothing was
// done, so the caller keeps the selection the operator built) and `onDone`
// (after the results were shown, with the ids that were actually dismissed, so
// the caller drops exactly those and leaves any that failed selected for a
// retry). One shared onClose used to clear the selection on Cancel too.
export function ConfirmBulkDismissModal({
  incidents,
  onCancel,
  onDone,
}: {
  incidents: Array<{ id: string; label: string }>
  onCancel: () => void
  onDone: (dismissedIds: string[]) => void
}) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const [note, setNote] = useState('')
  const [running, setRunning] = useState(false)
  const [results, setResults] = useState<BulkActionResult[] | null>(null)

  const trimmedNote = note.trim()

  const runBulkDismiss = async () => {
    setRunning(true)
    const settled = await Promise.allSettled(
      incidents.map((incident) => dismissIncident(incident.id, trimmedNote, accessToken!)),
    )
    setResults(
      settled.map((outcome, index) => {
        const incident = incidents[index]
        if (outcome.status === 'fulfilled') {
          return { id: incident.id, label: incident.label, status: 'succeeded' as const }
        }
        const reason = outcome.reason
        const detail =
          reason instanceof ApiError
            ? reason.detail
              ? `${reason.message} — ${reason.detail}`
              : reason.message
            : 'Something went wrong.'
        return { id: incident.id, label: incident.label, status: 'failed' as const, detail }
      }),
    )
    setRunning(false)
    queryClient.invalidateQueries({ queryKey: ['incidents'] })
  }

  if (results) {
    const finish = () => onDone(results.filter((r) => r.status === 'succeeded').map((r) => r.id))
    return (
      <Dialog title="Bulk dismiss results" onClose={finish}>
        <BulkResultList results={results} />
        <div className="modal-actions">
          <button type="button" onClick={finish}>
            Done
          </button>
        </div>
      </Dialog>
    )
  }

  const previewNames = incidents.slice(0, NAME_PREVIEW_LIMIT).map((incident) => incident.label)
  const remainder = incidents.length - previewNames.length

  return (
    <Dialog title="Dismiss incidents" onClose={() => (running ? undefined : onCancel())}>
      <p>
        This closes <strong>{incidents.length}</strong> {incidents.length === 1 ? 'incident' : 'incidents'} with
        no action: {previewNames.join(', ')}
        {remainder > 0 ? `, and ${remainder} more` : ''}. Dismissing is final — if any of these problems is
        still present, its detector will open a new incident.
      </p>

      <form
        onSubmit={(event) => {
          event.preventDefault()
          if (trimmedNote && !running) runBulkDismiss()
        }}
      >
        <label htmlFor="confirm-bulk-dismiss-note">
          Why are these being dismissed? Required — dismissing records that {incidents.length === 1 ? 'a' : ''}{' '}
          real problem{incidents.length === 1 ? '' : 's'} will not be acted on, and the same note is recorded
          against every incident selected.
        </label>
        <textarea
          id="confirm-bulk-dismiss-note"
          rows={2}
          value={note}
          onChange={(event) => setNote(event.target.value)}
          placeholder="e.g. known-broken dev workloads, tracked in JIRA-1234"
          autoFocus
        />

        <div className="modal-actions">
          <button type="button" className="secondary" onClick={onCancel} disabled={running}>
            Cancel
          </button>
          <button type="submit" className="danger" disabled={!trimmedNote || running}>
            {running ? 'Dismissing…' : `Dismiss ${incidents.length}`}
          </button>
        </div>
      </form>
    </Dialog>
  )
}
