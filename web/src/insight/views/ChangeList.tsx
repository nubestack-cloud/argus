import { useState } from 'react'
import type { ResourceChange, ResourceChangeGap } from '../../api/types'
import { ChevronIcon } from '../../components/icons'
import { formatDateTime } from '../../utils/time'
import { changeObjectLabel, changeWhat, groupChangesByOwner } from '../model'
import { defaultGroupFor } from '../kinds'
import type { ObjectRef } from '../panelUrl'

function clock(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  const sameDay = new Date().toDateString() === d.toDateString()
  const time = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  return sameDay ? time : `${d.toLocaleDateString([], { month: 'short', day: 'numeric' })} ${time}`
}

/** "Change history incomplete between … and …" — one line per gap. */
export function GapBanner({ gaps }: { gaps: readonly ResourceChangeGap[] }) {
  if (gaps.length === 0) return null
  return (
    <div className="banner banner-attention" role="note">
      {gaps.map((g, i) => (
        <p key={i} className="insight-gap-line">
          <strong>Change history incomplete</strong> between {formatDateTime(g.from)} and {formatDateTime(g.to)} — {g.reason}. A change made
          in that window would not be listed.
        </p>
      ))}
    </div>
  )
}

function ChangeRow({ change, clusterId, onOpen }: { change: ResourceChange; clusterId: string; onOpen?: (r: ObjectRef) => void }) {
  const label = changeObjectLabel(change)
  return (
    <li className="insight-change-row">
      <time className="insight-change-time" dateTime={change.observedAt} title={formatDateTime(change.observedAt)}>
        {clock(change.observedAt)}
      </time>{' '}
      {onOpen ? (
        <button
          type="button"
          className="link-button insight-inline-link"
          onClick={() =>
            onOpen({
              clusterId,
              kind: change.kind,
              apiGroup: change.apiGroup || defaultGroupFor(change.kind) || undefined,
              namespace: change.namespace,
              name: change.name,
            })
          }
        >
          {label}
        </button>
      ) : (
        <code>{label}</code>
      )}{' '}
      — {changeWhat(change)}
    </li>
  )
}

// Changes recorded by the agent's change stream (CI-S2), newest first and
// grouped by owner with a true count per group (CI-U4). The newest change of
// each group is always visible; the rest expand. Gaps in the stream are
// stated above the list, because an empty window with a gap in it is not
// "nothing changed".
export function ChangeList({
  changes,
  gaps,
  truncated,
  clusterId,
  onOpen,
  emptyText,
}: {
  changes: readonly ResourceChange[]
  gaps: readonly ResourceChangeGap[]
  truncated?: boolean
  clusterId: string
  onOpen?: (r: ObjectRef) => void
  emptyText: string
}) {
  const [open, setOpen] = useState<Record<string, boolean>>({})
  const groups = groupChangesByOwner(changes)
  return (
    <div className="insight-changes">
      <GapBanner gaps={gaps} />
      {groups.length === 0 ? (
        <p className="empty-state">{gaps.length > 0 ? `${emptyText} (outside the incomplete period above).` : emptyText}</p>
      ) : (
        <ul className="insight-change-groups">
          {groups.map((g) => {
            const [first, ...rest] = g.changes
            const expanded = open[g.key] ?? false
            return (
              <li key={g.key} className="insight-change-group">
                {g.changes.length > 1 && (
                  <button
                    type="button"
                    className="row-group-toggle insight-change-group-head"
                    aria-expanded={expanded}
                    onClick={() => setOpen((o) => ({ ...o, [g.key]: !expanded }))}
                  >
                    <ChevronIcon className="row-group-chevron" direction="right" />
                    <span>
                      <code>{g.label}</code> <span className="row-group-count">×{g.changes.length} changes</span>
                      <span className="field-hint"> {expanded ? '— hide older' : '— show older'}</span>
                    </span>
                  </button>
                )}
                <ul className="insight-change-rows">
                  <ChangeRow change={first} clusterId={clusterId} onOpen={onOpen} />
                  {expanded && rest.map((c) => <ChangeRow key={c.id} change={c} clusterId={clusterId} onOpen={onOpen} />)}
                </ul>
              </li>
            )
          })}
        </ul>
      )}
      {truncated && <p className="insight-note">Showing the most recent changes only — older changes exist in this window.</p>}
    </div>
  )
}
