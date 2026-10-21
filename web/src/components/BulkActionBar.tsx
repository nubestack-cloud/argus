// Bulk-selection UI shared by ClustersPage and IncidentsPage — the owner's
// raw BUGS.md note ("a chclist selection style button on the clusters page
// and incidents page where we can select and perform bulk action like
// decommissioning the clusters"). Deliberately generic over WHAT the bulk
// action is: each page still owns its own confirm step (a typed
// confirmation for an irreversible cluster decommission, a required note
// for an incident dismissal) and still calls the exact same per-item
// endpoint a single-row action already calls, once per selected id — this
// component only renders "N selected, here are your actions" and "here is
// what happened to each one afterward," so a third bulk action never has to
// re-invent either.
import type { ReactNode } from 'react'

export interface BulkAction {
  label: string
  onClick: () => void
  disabled?: boolean
  disabledReason?: string
  danger?: boolean
}

// Renders nothing at zero selected — there is no "0 selected" state to
// design for, the bar simply isn't part of the page until a row is checked
// (matches the row-actions column, which also never shows an affordance
// with nothing to act on).
export function BulkActionBar({
  count,
  itemLabel,
  onClear,
  actions,
}: {
  count: number
  itemLabel: string
  onClear: () => void
  actions: BulkAction[]
}) {
  if (count === 0) return null
  return (
    <div className="bulk-action-bar" role="region" aria-label="Bulk actions for the selected rows">
      <span className="bulk-action-bar-count" aria-live="polite">
        {count} {itemLabel}
        {count === 1 ? '' : 's'} selected
      </span>
      <div className="bulk-action-bar-actions">
        {actions.map((action) => (
          <button
            key={action.label}
            type="button"
            className={action.danger ? 'danger' : 'secondary'}
            onClick={action.onClick}
            disabled={action.disabled}
            title={action.disabledReason}
          >
            {action.label}
          </button>
        ))}
        <button type="button" className="secondary" onClick={onClear}>
          Clear selection
        </button>
      </div>
    </div>
  )
}

export interface BulkActionResult {
  id: string
  label: string
  status: 'succeeded' | 'failed'
  detail?: string
}

// The per-row outcome of a bulk action — never a single pass/fail for the
// whole batch. Status is stated in words ("Succeeded"/"Failed — <reason>"),
// not colour alone, the same rule severity marks follow elsewhere; the
// colour here is a reinforcement of the word, never a replacement for it.
export function BulkResultList({ results, children }: { results: BulkActionResult[]; children?: ReactNode }) {
  const succeeded = results.filter((r) => r.status === 'succeeded').length
  const failed = results.length - succeeded
  return (
    <div className="bulk-result-list">
      <p className="bulk-result-summary">
        {succeeded} of {results.length} succeeded{failed > 0 ? `, ${failed} failed` : ''}.
      </p>
      <ul className="bulk-result-items">
        {results.map((result) => (
          <li
            key={result.id}
            className={result.status === 'failed' ? 'bulk-result-item-failed' : 'bulk-result-item-succeeded'}
          >
            <span className="bulk-result-item-label">{result.label}</span>
            <span className="bulk-result-item-status">
              {result.status === 'succeeded' ? 'Succeeded' : `Failed — ${result.detail ?? 'unknown error'}`}
            </span>
          </li>
        ))}
      </ul>
      {children}
    </div>
  )
}
