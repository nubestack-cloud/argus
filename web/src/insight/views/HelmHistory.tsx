import { formatDateTime, formatRelativeTime } from '../../utils/time'
import type { HelmStatusResult } from '../types'
import { HelpTip } from '../../components/HelpTip'

type Revision = NonNullable<HelmStatusResult['history']>[number]

/** When a revision was made: the agent's createdAt (the release record's own
 *  creation time, which Helm never rewrites), else Helm's modifiedAt label —
 *  which Helm also stamps on OLD revisions when it supersedes them, so every
 *  revision can carry the same date and it is said to be the label. */
function revisionTime(h: Revision): { at?: string; fromLabel: boolean } {
  if (h.createdAt) return { at: h.createdAt, fromLabel: false }
  return { at: h.updated, fromLabel: !!h.updated }
}

// A Helm release's revision history, newest first — shared by the object
// panel's Helm tab and the cluster Helm tab's release view.
export function HelmHistoryTable({ history }: { history: Revision[] }) {
  const rows = [...history].sort((a, b) => b.revision - a.revision)
  const anyLabelOnly = rows.some((h) => revisionTime(h).fromLabel)
  return (
    <div className="table-scroll">
      <table className="data-table">
        <caption className="insight-caption">Revision history</caption>
        <thead>
          <tr>
            <th scope="col" className="col-numeric">Revision</th>
            <th scope="col">Status</th>
            <th scope="col" className="col-time">Created</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((h) => {
            const t = revisionTime(h)
            return (
              <tr key={h.revision}>
                <td className="col-numeric">{h.revision}</td>
                <td>{h.status || '—'}</td>
                <td className="col-time">
                  {t.at ? (
                    <span title={formatDateTime(t.at)}>{formatRelativeTime(t.at)}</span>
                  ) : (
                    '—'
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
      {anyLabelOnly && (
        <p className="field-hint">
          Some times are Helm’s “modified” label, not when the revision was made.{' '}
          <HelpTip
            label="modified times"
            text="Helm rewrites the modified label on old revisions when it supersedes them. This agent build does not report the record’s creation time."
          />
        </p>
      )}
    </div>
  )
}
