import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import type { AutomationWindowsResponse, Cluster } from '../api/types'
import { CAP_ORG_SETTINGS_WRITE } from '../api/capabilities'
import { formatDateTime, formatRelativeTime } from '../utils/time'
import { capRows, CARD_ROWS, groupPins, pinsFromSummary, RUNWAY_DAYS, windowSpans, type CertPin, type WindowSpan } from './model'
import type { CheckStatus, FleetChecks } from './useFleetData'

// Next 90 days: every dated thing in the fleet on one runway. Two sources have
// dates today: certificate expiry (each agent's certificate inventory) and the
// automation windows (their upcoming openings, computed by the hub from the
// same rule the sweeper uses). Kubernetes end-of-support dates are not known to
// the hub, so they are not drawn.

const TICKS = [0, 7, 30, 60, 90]
const at = (days: number) => `${(Math.max(0, Math.min(days, RUNWAY_DAYS)) / RUNWAY_DAYS) * 100}%`

// A pill and its name take roughly a month of runway at desktop width, so a
// group closer than that to the previous one on its level drops a level.
const LEVEL_GAP_DAYS = 28
const LEVEL_PX = 26
const LANE_PX = 40

/** The level each group sits on, so neighbouring labels never overlap. */
function levels(groups: readonly { days: number }[]): number[] {
  const lastAt: number[] = []
  return groups.map((g) => {
    const x = Math.max(0, g.days)
    let level = lastAt.findIndex((prev) => x - prev > LEVEL_GAP_DAYS)
    if (level === -1) level = lastAt.length
    lastAt[level] = x
    return level
  })
}

const pinTitle = (p: CertPin) => `${p.namespace}/${p.name} ${p.days <= 0 ? 'has expired' : `expires in ${p.days} days`}`

/** Lanes of certificates the card draws one by one; the rest are summed into
 *  the all-clusters lane above them. Two rows short of CARD_ROWS, for that
 *  lane and the freeze windows. */
const CERT_LANES = CARD_ROWS - 2

function PinLane({ name, sub, title, href, groups }: { name: string; sub: ReactNode; title?: string; href?: string; groups: { key: string; days: number; severity: string; label: string; text: string; title: string }[] }) {
  const lv = levels(groups)
  const rows = Math.max(1, ...lv.map((l) => l + 1))
  const height = Math.max(LANE_PX, rows * LEVEL_PX + 14)
  const label = (
    <>
      {name}
      <small>{sub}</small>
    </>
  )
  return (
    <div className="ov-lane">
      {href ? (
        <Link className="ov-lane-name" to={href} title={title}>{label}</Link>
      ) : (
        <span className="ov-lane-name ov-lane-name-sans" title={title}>{label}</span>
      )}
      <div className="ov-lane-track" style={{ height: `${height}px` }}>
        <span className="ov-lane-soon" style={{ width: at(30) }} aria-hidden="true" />
        {groups.map((g, i) => (
          <span
            key={g.key}
            className={`ov-pin sev-${g.severity}${g.days > 66 ? ' ov-pin-flip' : ''}`}
            style={{ left: at(g.days), top: `${height / 2 + (lv[i] - (rows - 1) / 2) * LEVEL_PX}px` }}
            title={g.title}
          >
            <span className="ov-pin-days">{g.label}</span>
            {g.text && <span className="ov-pin-name">{g.text}</span>}
          </span>
        ))}
      </div>
    </div>
  )
}

function clusterGroups(pins: CertPin[]) {
  return groupPins(pins).map((g) => ({
    key: g.pins.map((p) => `${p.namespace}/${p.name}`).join(','),
    days: g.days,
    severity: g.severity,
    label: g.days <= 0 ? 'expired' : `${g.days} d`,
    text: `${g.pins[0].name}${g.pins.length > 1 ? ` +${g.pins.length - 1}` : ''}`,
    title: g.pins.map(pinTitle).join('\n'),
  }))
}

// The all-clusters lane: every drawn certificate in the fleet, one pill per
// week of the runway carrying its count and coloured by the soonest in it.
function fleetGroups(pins: (CertPin & { cluster: string })[]) {
  const weeks = new Map<number, (CertPin & { cluster: string })[]>()
  for (const p of pins) {
    const w = Math.max(0, Math.floor(p.days / 7))
    weeks.set(w, [...(weeks.get(w) ?? []), p])
  }
  return [...weeks.entries()]
    .sort(([a], [b]) => a - b)
    .map(([w, ps]) => {
      const soonest = ps.reduce((m, p) => (p.days < m.days ? p : m))
      return {
        key: `w${w}`,
        days: soonest.days,
        severity: soonest.severity,
        label: `${ps.length}`,
        text: '',
        title: `${ps.length} certificate${ps.length === 1 ? '' : 's'} expiring in days ${w * 7}–${w * 7 + 6}:\n` +
          ps.slice(0, 12).map((p) => `${p.cluster}: ${pinTitle(p)}`).join('\n') + (ps.length > 12 ? `\n+ ${ps.length - 12} more` : ''),
      }
    })
}

const ago = (iso: string) => formatRelativeTime(iso)

const WEEKDAY = new Intl.DateTimeFormat('en-GB', { weekday: 'short' })
const HHMM = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit' })

/** "weekly Fri 18:00" from a window's own upcoming openings, in the reader's
 *  clock — the hub evaluates the cron, the browser only reads its answer. */
function cadence(windows: AutomationWindowsResponse['windows']): string {
  if (windows.length !== 1) return `${windows.length} schedules`
  const starts = (windows[0].upcoming ?? []).map((o) => new Date(o.start))
  if (starts.length === 0) return 'none upcoming'
  const first = starts[0]
  const gap = starts.length > 1 ? Math.round((starts[1].getTime() - first.getTime()) / 86_400_000) : null
  const when = `${WEEKDAY.format(first)} ${HHMM.format(first)}`
  return gap === 7 ? `weekly ${when}` : gap === 1 ? `daily ${HHMM.format(first)}` : `next ${when}`
}

function windowTitle(s: WindowSpan): string {
  return `${s.kind === 'freeze' ? 'Freeze' : 'Maintenance'} ${formatDateTime(s.startAt)} – ${formatDateTime(s.endAt)}${s.reason ? `: ${s.reason}` : ''}`
}

export function ComingDue({
  clusters,
  checks,
  checksAllowed,
  checksMissing,
  windows,
  windowsReadable,
  windowsError,
  nowMs,
}: {
  clusters: Cluster[]
  checks: FleetChecks
  checksAllowed: boolean | null
  checksMissing: string[]
  windows: AutomationWindowsResponse | undefined
  windowsReadable: boolean
  windowsError: boolean
  nowMs: number
}) {
  const spans = windows ? windowSpans(windows.windows, nowMs) : []
  const hasMaintenance = spans.some((s) => s.kind === 'maintenance')
  // A rule with one opening inside the runway is a one-off (a quarter-end
  // freeze); it is the one worth naming on the track.
  const perRule = new Map<string, number>()
  for (const s of spans) perRule.set(s.key.split(':')[0], (perRule.get(s.key.split(':')[0]) ?? 0) + 1)

  // Every cluster's certificate check, sorted into what the card can say.
  const due: { c: Cluster; pins: CertPin[]; dueTotal: number; unknown: number; status: Extract<CheckStatus<unknown>, { kind: 'ok' }> }[] = []
  let quiet = 0
  const unread: Cluster[] = []
  const failed: { c: Cluster; error: string }[] = []
  const unreadable: Cluster[] = []
  for (const c of clusters) {
    const s = checks.certificates(c.id)
    if (s.kind === 'unreadable') unreadable.push(c)
    else if (s.kind === 'unread') unread.push(c)
    else if (s.kind === 'error') failed.push({ c, error: s.error })
    else if (s.summary.dueTotal === 0) quiet += 1
    else due.push({ c, pins: pinsFromSummary(s.summary), dueTotal: s.summary.dueTotal, unknown: s.summary.unknown, status: s })
  }
  // Soonest first: the lanes worth a row are the ones running out of time.
  due.sort((a, b) => (a.pins[0]?.days ?? 999) - (b.pins[0]?.days ?? 999) || a.c.displayName.localeCompare(b.c.displayName))
  const { shown, rest } = capRows(due, CERT_LANES)
  const fleetPins = due.flatMap((d) => d.pins.map((p) => ({ ...p, cluster: d.c.displayName })))
  const fleetTotal = due.reduce((n, d) => n + d.dueTotal, 0)
  const partial = due.some((d) => d.dueTotal > d.pins.length)

  return (
    <div className="ov-runway">
      <div className="ov-runway-grid" aria-hidden="true">
        {TICKS.slice(1, -1).map((d) => <span key={d} style={{ left: at(d) }} />)}
      </div>
      <span className="ov-runway-today" aria-hidden="true" />
      {checksAllowed === false ? (
        <div className="ov-lane">
          <span className="ov-lane-name ov-lane-name-sans">Certificates</span>
          <div className="ov-lane-track"><span className="ov-lane-note">Needs {checksMissing.join(', ')} to read each cluster's certificates.</span></div>
        </div>
      ) : (
        <>
          {rest.length > 0 && (
            <PinLane
              name="All clusters"
              sub={`${fleetTotal} certs · ${due.length} clusters`}
              title={partial ? 'Each cluster lists at most its 25 soonest certificates; the counts here include only those.' : undefined}
              groups={fleetGroups(fleetPins)}
            />
          )}
          {shown.map(({ c, pins, dueTotal, unknown, status }) => (
            <PinLane
              key={c.id}
              name={c.displayName}
              href={`/clusters/${encodeURIComponent(c.id)}?tab=certificates`}
              title={status.failedSince ? `Read ${ago(status.at)}; the latest read failed: ${status.failure}` : undefined}
              sub={
                <>
                  {dueTotal} cert{dueTotal === 1 ? '' : 's'}
                  {unknown ? ` · ${unknown} unknown expiry` : ''}
                  {status.failedSince && ` · as of ${ago(status.at)}`}
                </>
              }
              groups={clusterGroups(pins)}
            />
          ))}
          {rest.length > 0 && (
            <div className="ov-lane">
              <span className="ov-lane-name ov-lane-name-sans">+ {rest.length} more</span>
              <div className="ov-lane-track">
                <span className="ov-lane-note" title={rest.map((d) => `${d.c.displayName}: ${d.dueTotal}`).join('\n')}>
                  {rest.length} more cluster{rest.length === 1 ? ' has' : 's have'} certificates due, counted in All clusters above · <Link to="/clusters">clusters</Link>
                </span>
              </div>
            </div>
          )}
          {(quiet > 0 || unread.length > 0 || failed.length > 0 || unreadable.length > 0 || clusters.length === 0) && (
            <div className="ov-lane">
              <span className="ov-lane-name ov-lane-name-sans">Certificates</span>
              <div className="ov-lane-track">
                <span className="ov-lane-note">
                  {[
                    clusters.length === 0 && { text: 'No cluster can answer a check right now' },
                    quiet > 0 && { text: quiet === clusters.length ? `None expires in the next ${RUNWAY_DAYS} days` : `Nothing due on ${quiet} more cluster${quiet === 1 ? '' : 's'}` },
                    unread.length > 0 && { text: `${unread.length} not read yet`, title: unread.map((c) => c.displayName).join(', ') },
                    failed.length > 0 && { text: `${failed.length} could not be read`, title: failed.map((f) => `${f.c.displayName}: ${f.error}`).join('\n') },
                    unreadable.length > 0 && { text: `${unreadable.length} need ${checksMissing.join(', ')}`, title: unreadable.map((c) => c.displayName).join(', ') },
                  ]
                    .filter((p): p is { text: string; title?: string } => !!p)
                    .map((p, i) => (
                      <span key={p.text} title={p.title}>
                        {i > 0 && ' · '}
                        {p.text}
                      </span>
                    ))}
                </span>
              </div>
            </div>
          )}
        </>
      )}
      <div className="ov-lane">
        <Link className="ov-lane-name ov-lane-name-sans" to="/settings?section=automation">
          {hasMaintenance ? 'Automation windows' : 'Freeze windows'}
          <small>
            whole fleet
            {windows && windows.windows.length > 0 && ` · ${cadence(windows.windows)}`}
            {hasMaintenance && ' · hatched: freeze'}
          </small>
        </Link>
        <div className="ov-lane-track">
          {!windowsReadable ? (
            <span className="ov-lane-note">Needs {CAP_ORG_SETTINGS_WRITE} to read.</span>
          ) : windowsError ? (
            <span className="ov-lane-note">— could not load the windows</span>
          ) : !windows ? (
            <span className="ov-lane-note">Loading…</span>
          ) : spans.length === 0 ? (
            <span className="ov-lane-note">No freeze or maintenance window opens in the next {RUNWAY_DAYS} days.</span>
          ) : (
            spans.map((s) => (
              <span key={s.key}>
                <span className={`ov-window ov-window-${s.kind}`} style={{ left: `${s.start * 100}%`, width: `${s.width * 100}%` }} title={windowTitle(s)} />
                {s.reason && perRule.get(s.key.split(':')[0]) === 1 && (
                  <span className="ov-window-label" style={{ left: `${s.start * 100}%` }} aria-hidden="true">{s.reason}</span>
                )}
              </span>
            ))
          )}
        </div>
      </div>
      <div className="ov-runway-axis" aria-hidden="true">
        <span />
        <div>
          {TICKS.map((d) => (
            <span key={d} style={{ left: at(d) }} className={d === 0 ? 'ov-runway-axis-today' : d === RUNWAY_DAYS ? 'ov-runway-axis-end' : undefined}>
              {d === 0 ? 'today' : `${d} d`}
            </span>
          ))}
        </div>
      </div>
    </div>
  )
}
