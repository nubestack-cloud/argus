import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import type { Cluster, IncidentOverview } from '../api/types'
import { arcLengths } from '../utils/donut'
import { formatDateTime } from '../utils/time'
import { capRows, ESCALATION_HOURS, formatWait, SEVERITIES, WAIT_AXIS_HOURS, type QueueRow, type Severity } from './model'

// The Now band: what is waiting on a person, every cluster's open incidents as a
// ring, and the per-day activity chart.

const TICK_PATH = 'M2.4 6.4 4.9 8.9 9.6 3.2'

function Tick() {
  return (
    <svg width="14" height="14" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={TICK_PATH} />
    </svg>
  )
}

const ICON: Record<QueueRow['kind'], { glyph: ReactNode; word: string }> = {
  incident: { glyph: '!', word: 'Incident' },
  decision: { glyph: <Tick />, word: 'Approval' },
  cluster: { glyph: '◌', word: 'Cluster' },
}

const SINCE_WORD: Record<QueueRow['sinceMeaning'], string> = {
  plan: 'plan waiting',
  opened: 'open',
  heartbeat: 'silent',
}

export function WaitingQueue({ rows, limit, more, restMediumOrLow }: { rows: QueueRow[]; limit: number; more: number; restMediumOrLow: boolean }) {
  if (rows.length === 0) {
    return (
      <div className="ov-empty">
        <span className="ov-empty-mark" aria-hidden="true"><Tick /></span>
        <span>
          <strong>Nothing is waiting on a person.</strong> Every open incident is with ARGUS or a reviewer.
        </span>
      </div>
    )
  }
  const shown = rows.slice(0, limit)
  return (
    <ul className="ov-queue">
      {shown.map((r) => (
        <li key={r.key} className={r.severity ? `sev-${r.severity}` : 'sev-neutral'}>
          <Link to={r.href}>
            <span className={`ov-queue-icon ov-queue-icon-${r.kind}`} aria-hidden="true">{ICON[r.kind].glyph}</span>
            <span className="ov-queue-title">{r.title}</span>
            <span className="ov-queue-right">
              <span className="ov-queue-status">
                {r.status}
                {r.severity && ` · ${r.severity}`}
              </span>
              <span className="ov-agebar" title={r.since ? `${SINCE_WORD[r.sinceMeaning]} since ${formatDateTime(r.since)}` : undefined} aria-hidden="true">
                {r.hours !== null && <span className="ov-agebar-fill" style={{ width: `${(Math.min(r.hours, WAIT_AXIS_HOURS) / WAIT_AXIS_HOURS) * 100}%` }} />}
                {r.kind === 'decision' && ESCALATION_HOURS.map((h) => <span key={h} className="ov-agebar-tick" style={{ left: `${(h / WAIT_AXIS_HOURS) * 100}%` }} />)}
              </span>
              <span className="ov-queue-age">
                <span className="visually-hidden">{SINCE_WORD[r.sinceMeaning]} </span>
                {formatWait(r.hours)}
              </span>
            </span>
            <span className="ov-queue-context">
              <span className="visually-hidden">{ICON[r.kind].word}: </span>
              {r.context}
            </span>
          </Link>
        </li>
      ))}
      {more > 0 && (
        <li className="ov-queue-more">
          + {more} more{restMediumOrLow ? ', all medium or low' : ''} · <Link to="/incidents?status=requiresAction">show</Link>
        </li>
      )}
    </ul>
  )
}

const R = 40
const C = 2 * Math.PI * R

function MiniRing({ mix, total, label, stale }: { mix: Record<Severity, number>; total: number; label: string; stale: boolean }) {
  const visible = SEVERITIES.filter((s) => mix[s] > 0)
  const lengths = arcLengths(visible.map((s) => mix[s]), total, C)
  const offsets = lengths.map((_, i) => lengths.slice(0, i).reduce((a, b) => a + b, 0))
  return (
    <svg className="ov-mini-ring" viewBox="0 0 100 100" role="img" aria-label={label}>
      <circle cx="50" cy="50" r={R} className="ov-mini-ring-track" strokeDasharray={stale ? '4 4' : undefined} />
      {visible.map((s, i) => (
        <circle
          key={s}
          cx="50"
          cy="50"
          r={R}
          className={`ov-mini-ring-seg sev-${s}`}
          strokeDasharray={`${Math.max(lengths[i] - 1.5, 1)} ${C - lengths[i] + 1.5}`}
          strokeDashoffset={-offsets[i]}
          transform="rotate(-90 50 50)"
        />
      ))}
      {total ? (
        <text x="50" y="54" textAnchor="middle" dominantBaseline="middle" className="ov-mini-ring-value">{total}</text>
      ) : (
        <path className="ov-mini-ring-clear" d="M42 50.5 47.5 56 58 44" />
      )}
    </svg>
  )
}

const STATE_WORD: Record<string, { word: string; tone: string }> = {
  Active: { word: 'Active', tone: 'ok' },
  Degraded: { word: 'Degraded', tone: 'warn' },
  Disconnected: { word: 'Disconnected', tone: 'muted' },
  Provisioning: { word: 'Provisioning', tone: 'muted' },
  PendingApproval: { word: 'Pending approval', tone: 'muted' },
  IncompatibleVersion: { word: 'Incompatible', tone: 'bad' },
  Rejected: { word: 'Rejected', tone: 'bad' },
}

export function ClusterRings({ clusters, byCluster }: { clusters: Cluster[]; byCluster: IncidentOverview['byCluster'] }) {
  const byId = new Map(byCluster.map((c) => [c.clusterId, c]))
  const rank = (id: string) => {
    const c = byId.get(id)
    return c ? [c.critical, c.high, c.medium, c.low] : [0, 0, 0, 0]
  }
  const sorted = [...clusters].sort((a, b) => {
    const ra = rank(a.id)
    const rb = rank(b.id)
    for (let i = 0; i < 4; i++) if (ra[i] !== rb[i]) return rb[i] - ra[i]
    return a.displayName.localeCompare(b.displayName)
  })
  // Eight rings, worst first; the rest are one line, so 200 clusters do not
  // become fifty rows of rings.
  const { shown, rest } = capRows(sorted)
  const restOpen = rest.reduce((n, c) => n + (byId.get(c.id)?.open ?? 0), 0)
  const restSilent = rest.filter((c) => c.state !== 'Active' && c.state !== 'Degraded').length
  return (
    <>
      <ul className="ov-rings">
        {shown.map((c) => {
          const row = byId.get(c.id)
          const mix: Record<Severity, number> = { critical: row?.critical ?? 0, high: row?.high ?? 0, medium: row?.medium ?? 0, low: row?.low ?? 0 }
          const total = row?.open ?? 0
          const st = STATE_WORD[c.state] ?? { word: c.state, tone: 'muted' }
          const label = `${c.displayName}: ${total ? SEVERITIES.filter((s) => mix[s]).map((s) => `${mix[s]} ${s}`).join(', ') : 'no open incidents'}`
          return (
            <li key={c.id} className={c.state === 'Active' || c.state === 'Degraded' ? undefined : 'ov-ring-dim'}>
              <Link to={`/clusters/${encodeURIComponent(c.id)}`} title={label}>
                <MiniRing mix={mix} total={total} label={label} stale={c.state !== 'Active' && c.state !== 'Degraded'} />
                <span className="ov-ring-name">{c.displayName}</span>
                <span className="ov-ring-sub">
                  <span className={`ov-state-${st.tone}`}>{st.word}</span>
                  {row && row.requiresAction > 0 && <span className="ov-state-warn"> · {row.requiresAction} yours</span>}
                </span>
              </Link>
            </li>
          )
        })}
      </ul>
      {rest.length > 0 && (
        <p className="ov-rest">
          + {rest.length} more cluster{rest.length === 1 ? '' : 's'} · {restOpen ? `${restOpen} open` : 'nothing open'}
          {restSilent > 0 && ` · ${restSilent} not reporting`} · <Link to="/clusters">show all</Link>
        </p>
      )}
    </>
  )
}

// "29 Sep": day first and a three-letter month, as the design's axis has it
// (en-GB's own short month is "Sept").
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
function formatDay(date: string): string {
  const d = new Date(`${date}T00:00:00Z`)
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}`
}

// Incidents opened per UTC day, a column of severity segments each, from the
// hub's whole-set series (GET /incidents/overview), so no day undercounts.
//
// The segments are severity by colour within a bar, and a segment cannot carry
// its own text (a one-incident day is a few pixels tall). The counts stay
// reachable without colour: each bar prints its total, the legend prints each
// severity's window total as a word and a number, and the per-day split is in
// the bar's title and the chart's accessible description. Owner's decision,
// 2026-09-19: spotting which day a critical landed on is worth that trade.
export function IncidentActivity({ daily }: { daily: IncidentOverview['daily'] }) {
  const totals = daily.map((d) => SEVERITIES.reduce((n, s) => n + d.opened[s], 0))
  const max = Math.max(1, ...totals)
  const sum = totals.reduce((a, b) => a + b, 0)
  const bySeverity = SEVERITIES.map((s) => ({ s, n: daily.reduce((a, d) => a + d.opened[s], 0) }))
  const split = (d: IncidentOverview['daily'][number]) =>
    SEVERITIES.filter((s) => d.opened[s] > 0)
      .map((s) => `${d.opened[s]} ${s}`)
      .join(', ')
  const description =
    `${sum} incident${sum === 1 ? '' : 's'} opened during the last ${daily.length} days. ` +
    'Severity for the window: ' +
    bySeverity.map(({ s, n }) => `${n} ${s}`).join(', ') +
    '. By day: ' +
    daily.map((d, i) => `${formatDay(d.date)}, ${totals[i] ? `${totals[i]}: ${split(d)}` : 'none'}`).join('; ')
  const ticks = [...new Set([0, Math.round((daily.length - 1) / 2), daily.length - 1])]
  return (
    <div className="ov-activity">
      <div className="ov-activity-bars" role="img" aria-label={description}>
        {daily.map((d, i) => {
          const t = totals[i]
          const h = (t / max) * 86
          return (
            <div key={d.date} className="ov-activity-day">
              {t > 0 && <span className="ov-activity-total" style={{ bottom: `calc(${h}% + 2px)` }} aria-hidden="true">{t}</span>}
              {t > 0 && (
                <div className="ov-activity-bar" style={{ height: `${h}%` }} title={`${formatDay(d.date)}: ${t} opened — ${split(d)}`}>
                  {SEVERITIES.filter((s) => d.opened[s] > 0).map((s) => (
                    <span key={s} className={`ov-activity-seg sev-${s}`} style={{ height: `${(d.opened[s] / t) * 100}%` }} />
                  ))}
                </div>
              )}
            </div>
          )
        })}
      </div>
      <div className="ov-activity-axis" aria-hidden="true">
        {ticks.map((i) => (
          <span key={daily[i]?.date ?? i}>{daily[i] ? formatDay(daily[i].date) : ''}</span>
        ))}
      </div>
      <ul className="ov-legend">
        {bySeverity.map(({ s, n }) => (
          <li key={s} className={`sev-${s}`}>
            <span className="ov-legend-swatch" aria-hidden="true" />
            {s[0].toUpperCase() + s.slice(1)} <strong>{n}</strong>
          </li>
        ))}
      </ul>
    </div>
  )
}
