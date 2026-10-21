import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { Link, useNavigate } from 'react-router-dom'
import { getClusterTimeline } from '../api/client'
import { CAPABILITY_INFO } from '../api/capabilityInfo'
import type { ClusterTimeline as Timeline, TimelineMark, TimelineRow, TimelineSource } from '../api/types'
import { useAuth } from '../auth/useAuth'
import { EmptyState } from '../components/EmptyState'
import { HelpTip } from '../components/HelpTip'
import { SkeletonLines } from '../components/Skeleton'
import { urlBool, urlEnum, urlString, useUrlState } from '../hooks/useUrlState'
import { errorText } from '../insight/useInspect'
import { useOpenObject } from '../insight/useOpenObject'
import { LIVE_FALLBACK_MS } from '../realtime/refresh'
import {
  axisTicks,
  binMarks,
  binTotal,
  describeMark,
  describeSpan,
  findingTrails,
  incidentLeads,
  LEAD_LOOKBACK_MS,
  clampTipLine,
  isWarningEvent,
  markTarget,
  markTime,
  moreText,
  leadSummary,
  objectLabel,
  placeSpans,
  pos,
  rowCountsText,
  rowEvents,
  rowIncidentSummary,
  rowDomId,
  rowObject,
  SEV_CLASS,
  stateWord,
  severityWord,
  WINDOW_LABEL,
  WINDOW_MS,
  WINDOWS,
  type Bin,
  type IncidentLead,
  type MarkTarget,
  type TimelineWindow,
} from './timelineModel'

// Cluster detail → Timeline (PROJECT.md AD1): "what changed right before it
// broke". One row per object — the owning workload where the hub could
// resolve one — with incident spans as bands and changes/findings as marks on
// one time axis. Every filter is a request parameter, so the hub applies it
// before its row and mark caps; every cap that bites is stated beside the
// numbers it affects. Below ~640px the axis has no room to mean anything and
// the same rows render as a list of events.

const SOURCES: { id: TimelineSource; label: string }[] = [
  { id: 'changes', label: 'Changes' },
  { id: 'findings', label: 'Findings' },
  { id: 'incidents', label: 'Incidents' },
]

const SCHEMA = {
  tlw: urlEnum(WINDOWS, '6h' as TimelineWindow),
  tlns: urlString(''),
  // Hidden types, so the default (everything) is an empty parameter.
  tlhide: urlString(''),
  tlinc: urlBool(false),
}

const NARROW_PX = 640

export function ClusterTimeline({ clusterId }: { clusterId: string }) {
  const { accessToken } = useAuth()
  const [state, setState] = useUrlState(SCHEMA)
  const windowMs = WINDOW_MS[state.tlw]
  const hidden = useMemo(() => new Set(state.tlhide.split(',').filter(Boolean)), [state.tlhide])
  const types = SOURCES.map((s) => s.id).filter((id) => !hidden.has(id))

  const q = useQuery({
    queryKey: ['cluster-timeline', clusterId, state.tlw, state.tlns, types.join(','), state.tlinc],
    queryFn: async () => {
      const until = Date.now()
      return getClusterTimeline(
        clusterId,
        {
          since: new Date(until - windowMs).toISOString(),
          until: new Date(until).toISOString(),
          namespace: state.tlns || undefined,
          types,
          onlyIncidents: state.tlinc,
        },
        accessToken!,
      )
    },
    enabled: !!accessToken,
    refetchInterval: LIVE_FALLBACK_MS,
    placeholderData: keepPreviousData,
    retry: false,
  })

  const toggleType = (id: TimelineSource) => {
    const next = new Set(hidden)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    setState({ tlhide: [...next].join(',') }, { push: true })
  }
  const filtered = !!state.tlns || hidden.size > 0 || state.tlinc
  const clearFilters = () => setState({ tlns: '', tlhide: '', tlinc: false }, { push: true })

  const [width, setWidth] = useState(0)
  const rootRef = useRef<HTMLElement>(null)
  useLayoutEffect(() => {
    const el = rootRef.current
    if (!el) return
    setWidth(el.clientWidth)
    if (typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(() => setWidth(el.clientWidth))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  const narrow = width > 0 && width < NARROW_PX

  const data = q.data
  const namespaces = data?.namespaces ?? []

  return (
    <section className="tl" aria-label="Timeline" ref={rootRef}>
      <div className="tl-head">
        <h2>Timeline</h2>
        <HelpTip
          label="Timeline"
          text="Object changes the agent recorded, findings detectors reported (warning events included) and incidents, for this cluster on one time axis. Each row is an object, grouped under the workload that owns it; marks name the exact object they are about."
        />
        <div className="insight-range" role="group" aria-label="Time window">
          {WINDOWS.map((w) => (
            <button key={w} type="button" aria-pressed={state.tlw === w} onClick={() => setState({ tlw: w }, { push: true })}>
              {w}
            </button>
          ))}
        </div>
      </div>

      <div className="tl-filters">
        <div className="tl-ns">
          <label className="visually-hidden" htmlFor="tl-namespace">
            Namespace
          </label>
          <select id="tl-namespace" className="compact-select" value={state.tlns} onChange={(e) => setState({ tlns: e.target.value }, { push: true })}>
            <option value="">All namespaces</option>
            {state.tlns && !namespaces.includes(state.tlns) && <option value={state.tlns}>{state.tlns}</option>}
            {namespaces.map((ns) => (
              <option key={ns} value={ns}>
                {ns}
              </option>
            ))}
          </select>
        </div>
        {/* The legend is the filter: each source a chip with its count, at
            least one always on (an empty set would read as "nothing
            happened"). */}
        <div className="filter-chips" role="group" aria-label="Show">
          {SOURCES.map((s) => {
            const n = data ? sourceCount(data, s.id) : null
            return (
              <button
                key={s.id}
                type="button"
                className="filter-chip"
                aria-pressed={!hidden.has(s.id)}
                disabled={!hidden.has(s.id) && types.length === 1}
                onClick={() => toggleType(s.id)}
              >
                <Glyph kind={s.id} /> {s.label}
                {n != null && <span className="filter-chip-count">{n.toLocaleString()}</span>}
              </button>
            )
          })}
          <button type="button" className="filter-chip" aria-pressed={state.tlinc} onClick={() => setState({ tlinc: !state.tlinc }, { push: true })}>
            Only with an incident
          </button>
        </div>
        {data && data.rows.length > 0 && (
          <span className="panel-toolbar-meta">
            {data.totals.rows.toLocaleString()} objects
            {data.truncated.rows > 0 ? ` · showing ${data.rows.length} most active` : ''}
          </span>
        )}
      </div>

      {q.isLoading ? (
        <div aria-busy="true" aria-label="Loading the timeline">
          <SkeletonLines count={8} />
        </div>
      ) : q.isError && !data ? (
        <p className="form-error" role="alert">
          {errorText(q.error, 'The timeline could not be loaded.')}
        </p>
      ) : data ? (
        <TimelineBody
          data={data}
          clusterId={clusterId}
          windowLabel={WINDOW_LABEL[state.tlw]}
          windowMs={windowMs}
          narrow={narrow}
          width={width}
          filtered={filtered}
          onClearFilters={clearFilters}
          onWiden={state.tlw === '7d' ? undefined : () => setState({ tlw: '7d' }, { push: true })}
          refreshError={q.isError ? errorText(q.error, 'The latest refresh failed.') : null}
        />
      ) : null}

      <p className="card-foot-links">
        <Link to={`/changes?clusterId=${encodeURIComponent(clusterId)}`}>Change history →</Link>
        <Link to={`/signals?clusterId=${encodeURIComponent(clusterId)}`}>Signals from this cluster →</Link>
      </p>
    </section>
  )
}

/** What a source chip counts: changes, finding runs, incidents open in the window. */
function sourceCount(d: Timeline, id: TimelineSource): number | null {
  if (!d.types.includes(id)) return null
  if (id === 'changes') return d.totals.changes
  if (id === 'findings') return d.totals.findingRuns
  return d.totals.incidents
}

/** The legend glyph for a source; decoration beside its word, never alone. */
function Glyph({ kind }: { kind: TimelineSource }) {
  if (kind === 'changes') return <span className="tl-glyph tl-glyph-change" aria-hidden="true" />
  if (kind === 'findings') return <span className="tl-glyph tl-glyph-finding" aria-hidden="true" />
  return <span className="tl-glyph tl-glyph-incident" aria-hidden="true" />
}

function plural(n: number, word: string): string {
  return `${n.toLocaleString()} ${word}${n === 1 ? '' : 's'}`
}

function TimelineBody({
  data,
  clusterId,
  windowLabel,
  windowMs,
  narrow,
  width,
  filtered,
  onClearFilters,
  onWiden,
  refreshError,
}: {
  data: Timeline
  clusterId: string
  windowLabel: string
  windowMs: number
  narrow: boolean
  width: number
  filtered: boolean
  onClearFilters: () => void
  onWiden?: () => void
  refreshError: string | null
}) {
  const start = Date.parse(data.since)
  const end = Date.parse(data.until)
  const has = (t: TimelineSource) => data.types.includes(t)
  const t = data.totals
  const tr = data.truncated

  const parts: string[] = []
  if (has('changes')) parts.push(plural(t.changes, 'change'))
  if (has('findings')) parts.push(`${plural(t.findingRuns, 'finding')}${t.findingReports > t.findingRuns ? ` (${t.findingReports.toLocaleString()} reports)` : ''}`)
  if (has('incidents')) parts.push(`${plural(t.incidents, 'incident')} open at some point in it`)
  const asOf = new Date(end).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })

  // The lead needs incidents in the answer: hidden by the filter, or not
  // readable by this viewer (stated in the notes), it would read as "none".
  const leadable = has('incidents') && !data.restricted.some((r) => r.source === 'incidents')

  const notes: ReactNode[] = []
  for (const r of data.restricted) {
    notes.push(
      <>
        {r.source === 'findings' ? 'Findings' : 'Incidents'} are not shown: reading them needs{' '}
        {CAPABILITY_INFO[r.capability] ? `${CAPABILITY_INFO[r.capability].label} ` : ''}(<code>{r.capability}</code>) on this cluster.
      </>,
    )
  }
  if (tr.rows > 0) {
    notes.push(<>Objects with an incident come first; narrow by namespace or type to see the other {(t.rows - data.rows.length).toLocaleString()}.</>)
  }
  if (tr.changes > 0) notes.push(<>Only the newest {(t.changes - tr.changes).toLocaleString()} changes are drawn; {tr.changes.toLocaleString()} older ones in this window are not.</>)
  if (tr.findingRuns > 0) notes.push(<>Only the {(t.findingRuns - tr.findingRuns).toLocaleString()} most recent findings are drawn; {tr.findingRuns.toLocaleString()} more in this window are not.</>)
  if (tr.incidents > 0) notes.push(<>Only the {(t.incidents - tr.incidents).toLocaleString()} most recently active incidents are drawn; {tr.incidents.toLocaleString()} more are not.</>)
  for (const g of data.gaps) {
    notes.push(
      <>
        <span className="tl-gap-swatch" aria-hidden="true" /> Change history is incomplete from {markTime(g.from, windowMs)} to {markTime(g.to, windowMs)} ({g.reason || 'reason not recorded'}): changes
        made then may be missing.
      </>,
    )
  }

  return (
    <>
      {data.rows.length > 0 && (
        <p className="tl-summary visually-hidden">
          {windowLabel[0].toUpperCase() + windowLabel.slice(1)}: {parts.join(', ')} — across {plural(t.rows, 'object')}
          {data.namespace ? ` · namespace ${data.namespace}` : ''}
          {data.onlyIncidents ? ' · objects with an incident only' : ''} · as of {asOf}
        </p>
      )}
      {refreshError && (
        <p className="insight-note" role="status">
          Showing the previous result: {refreshError}
        </p>
      )}
      {notes.length > 0 && (
        <ul className="tl-notes">
          {notes.map((n, i) => (
            <li key={i} className="insight-note">
              {n}
            </li>
          ))}
        </ul>
      )}
      {data.rows.length === 0 ? (
        filtered ? (
          <EmptyState variant="insights">
            Nothing matches these filters in the {windowLabel}.{' '}
            <button type="button" className="link-button tl-inline-button" onClick={onClearFilters}>
              Clear filters
            </button>
          </EmptyState>
        ) : (
          <EmptyState variant="insights">
            No recorded activity in the {windowLabel}: no object changes were recorded
            {has('findings') ? ', no detector reported a finding' : ''}
            {has('incidents') ? ' and no incident was open' : ''}.
            {onWiden && (
              <>
                {' '}
                <button type="button" className="link-button tl-inline-button" onClick={onWiden}>
                  Look at the last 7 days
                </button>
              </>
            )}
          </EmptyState>
        )
      ) : narrow ? (
        <>
          {leadable && <IncidentLeads data={data} start={start} windowLabel={windowLabel} windowMs={windowMs} />}
          <EventList rows={data.rows} clusterId={clusterId} windowMs={windowMs} />
        </>
      ) : (
        <>
          {leadable && <IncidentLeads data={data} start={start} windowLabel={windowLabel} windowMs={windowMs} />}
          <Legend data={data} />
          <Chart data={data} clusterId={clusterId} start={start} end={end} windowMs={windowMs} width={width} />
        </>
      )}
    </>
  )
}

// ---------------------------------------------------------------- incident leads

const LEADS_SHOWN = 4
const LOOKBACK_MIN = LEAD_LOOKBACK_MS / 60_000

/** Brings a row into view and puts focus on its name, so a lead can say
 *  "this one" on the chart below. */
function showRow(key: string) {
  const el = document.getElementById(rowDomId(key))
  if (!el) return
  el.scrollIntoView?.({ block: 'center' })
  el.querySelector<HTMLElement>('.tl-label-name')?.focus({ preventScroll: true })
}

/** "≥ 3 changes" when some events in reach were thinned or not drawn. */
function countWords(n: number, word: string, atLeast: boolean): string {
  return `${atLeast && n > 0 ? '≥ ' : ''}${plural(n, word)}`
}

function ownText(l: IncidentLead): string {
  if (l.ownChanges === 0 && l.ownFindings === 0) {
    return l.atLeast ? 'no change or finding drawn on it' : 'no change or finding on it'
  }
  const parts: string[] = []
  if (l.ownChanges > 0) parts.push(countWords(l.ownChanges, 'change', l.atLeast))
  if (l.ownFindings > 0) parts.push(countWords(l.ownFindings, 'finding', l.atLeast && l.ownChanges === 0))
  return `${parts.join(' and ')} on it`
}

function IncidentLeads({ data, start, windowLabel, windowMs }: { data: Timeline; start: number; windowLabel: string; windowMs: number }) {
  // Lower bounds when the hub left changes or objects out: a nearby change
  // on an undrawn object cannot be counted, and "no other object changed"
  // could not be claimed.
  const partialRows = data.truncated.changes > 0 || data.truncated.rows > 0
  const { leads, earlier } = useMemo(() => incidentLeads(data.rows, start, partialRows), [data.rows, start, partialRows])
  const [all, setAll] = useState(false)
  const shown = all ? leads : leads.slice(0, LEADS_SHOWN)
  const summary = leadSummary({
    windowLabel,
    total: data.totals.incidents,
    openedTotal: (data.totals as { incidentsOpened?: number }).incidentsOpened,
    leadsDrawn: leads.length,
    earlierDrawn: earlier,
  })
  return (
    <section className="tl-leads" aria-label="Incidents opened in this window">
      <div className="tl-leads-head">
        <h3>{summary.heading}</h3>
        {leads.length > 0 && (
          <HelpTip
            label="Incident leads"
            text={`Each with what changed in the ${LOOKBACK_MIN} minutes before it opened (≥ where some events in reach are drawn as one mark or not drawn). Close in time is a lead to follow, not a cause — the incident’s own analysis argues the cause.`}
          />
        )}
        {summary.meta && <span className="tl-leads-meta">{summary.meta}</span>}
      </div>
      {summary.drawnNote && <p className="tl-leads-hint">{summary.drawnNote}</p>}
      {leads.length > 0 && (
        <>
          <ol className="tl-lead-list">
            {shown.map((l) => (
              <li key={l.span.incidentId} className={`tl-lead ${SEV_CLASS[l.span.severity] ?? 'sev-neutral'}`}>
                <div className="tl-lead-head">
                  <span className="tl-lead-sev">
                    <span className="severity-chip" aria-hidden="true" /> {severityWord(l.span.severity)} incident
                  </span>
                  <span className="tl-lead-when">
                    opened {markTime(l.span.from, windowMs)} · {l.span.to === null ? 'still open' : stateWord(l.span.state)}
                  </span>
                  <Link className="tl-lead-open" to={`/incidents/${encodeURIComponent(l.span.incidentId)}`}>
                    Open the incident →
                  </Link>
                </div>
                <p className="tl-lead-what">
                  {l.row.kind && <span className="preview-kind">{l.row.kind}</span>}{' '}
                  <button type="button" className="link-button insight-mono" onClick={() => showRow(l.row.key)} aria-label={`Show ${objectLabel(l.row)} on the timeline`}>
                    {l.row.name}
                  </button>
                  {l.row.namespace && <span className="text-muted"> · {l.row.namespace}</span>}
                  {l.span.summary && <span className="tl-lead-summary"> — {l.span.summary}</span>}
                </p>
                <p className="tl-lead-before">
                  <span className="tl-lead-label">Before it opened:</span> {ownText(l)}
                  {l.nearby.length > 0 ? (
                    <>
                      {'; elsewhere '}
                      {l.nearby.map((n, i) => (
                        <span key={n.row.key}>
                          {i > 0 ? ', ' : ''}
                          <button type="button" className="link-button" onClick={() => showRow(n.row.key)} aria-label={`Show ${objectLabel(n.row)} on the timeline`}>
                            {objectLabel(n.row)}
                          </button>{' '}
                          ({countWords(n.changes, 'change', l.atLeast)})
                        </span>
                      ))}
                      {l.nearbyMore > 0 ? `, and ${plural(l.nearbyMore, 'more object')}` : ''}.
                    </>
                  ) : (
                    l.atLeast ? '; no other drawn object changed.' : '; no other object changed.'
                  )}
                </p>
              </li>
            ))}
          </ol>
          {leads.length > LEADS_SHOWN && (
            <button type="button" className="link-button" aria-expanded={all} onClick={() => setAll((v) => !v)}>
              {all ? `Show the worst ${LEADS_SHOWN}` : `Show all ${leads.length}`}
            </button>
          )}
        </>
      )}
    </section>
  )
}

function Legend({ data }: { data: Timeline }) {
  const sevs = new Set(data.rows.flatMap((r) => r.spans.map((s) => s.severity)))
  const order = ['critical', 'high', 'medium', 'low'].filter((s) => sevs.has(s))
  const trails = data.rows.some((r) => r.marks.some((m) => m.type === 'finding' && m.until && m.until !== m.at))
  return (
    <ul className="tl-legend" aria-label="Legend">
      {data.types.includes('changes') && (
        <li>
          <Glyph kind="changes" /> change
        </li>
      )}
      {data.types.includes('findings') && (
        <li>
          <Glyph kind="findings" /> finding first reported
        </li>
      )}
      {trails && (
        <li>
          <span className="tl-legend-trail" aria-hidden="true" /> still being reported (dashed: since before this window)
        </li>
      )}
      {order.map((s) => (
        <li key={s} className={SEV_CLASS[s]}>
          <span className="tl-legend-band" aria-hidden="true" /> {severityWord(s)} incident
        </li>
      ))}
      {data.gaps.length > 0 && (
        <li>
          <span className="tl-gap-swatch" aria-hidden="true" /> change history missing
        </li>
      )}
      <li className="tl-legend-hint">Numbers on a mark count events too close to draw apart</li>
    </ul>
  )
}

// ---------------------------------------------------------------- chart

interface Tip {
  lines: string[]
  more: number
  rect: DOMRect
}

function Chart({ data, clusterId, start, end, windowMs, width }: { data: Timeline; clusterId: string; start: number; end: number; windowMs: number; width: number }) {
  // The track is the chart's width less the label column (see .tl-lane's
  // grid); measured from the first track so ticks and bins match it exactly.
  const [trackPx, setTrackPx] = useState(0)
  const bodyRef = useRef<HTMLOListElement>(null)
  useLayoutEffect(() => {
    const track = bodyRef.current?.querySelector<HTMLElement>('.tl-track')
    if (track) setTrackPx(track.clientWidth)
  }, [width, data])
  const ticks = useMemo(() => axisTicks(start, end, trackPx), [start, end, trackPx])
  const [tip, setTip] = useState<Tip | null>(null)
  const [open, setOpen] = useState<{ row: string; bin: string } | null>(null)
  const navigate = useNavigate()
  const openObject = useOpenObject()

  const go = useCallback(
    (target: MarkTarget) => {
      if (!target) return
      if ('object' in target) openObject(target.object)
      else navigate(`/incidents/${encodeURIComponent(target.incidentId)}`)
    },
    [navigate, openObject],
  )

  // Arrow Up/Down move between rows, landing on the event nearest the same time.
  const moveRow = (from: HTMLElement, delta: number) => {
    const lane = from.closest<HTMLElement>('.tl-lane')
    const lanes = Array.from(bodyRef.current?.querySelectorAll<HTMLElement>('.tl-lane') ?? [])
    const i = lane ? lanes.indexOf(lane) : -1
    const target = lanes[i + delta]
    if (!target) return
    const x = Number(from.dataset.x ?? '0')
    const items = Array.from(target.querySelectorAll<HTMLElement>('.tl-item'))
    if (items.length === 0) {
      target.querySelector<HTMLElement>('.tl-label-name')?.focus()
      return
    }
    items.sort((a, b) => Math.abs(Number(a.dataset.x) - x) - Math.abs(Number(b.dataset.x) - x))[0].focus()
  }

  return (
    <div className="tl-chart">
      <div className="tl-axis" aria-hidden="true">
        <span className="tl-axis-label">Object</span>
        <span className="tl-axis-track">
          {ticks.map((tk) => (
            <span key={tk.at} className="tl-tick" style={{ left: `${tk.x * 100}%` }}>
              {tk.label}
            </span>
          ))}
          <span className="tl-tick tl-tick-now">now</span>
        </span>
      </div>
      <ActivityStrip data={data} start={start} end={end} windowMs={windowMs} />
      <div className="tl-plot">
        <div className="tl-overlay" aria-hidden="true">
          {ticks.map((tk) => (
            <span key={tk.at} className="tl-gridline" style={{ left: `${tk.x * 100}%` }} />
          ))}
          {data.gaps.map((g) => {
            const x1 = pos(Date.parse(g.from), start, end)
            const x2 = pos(Date.parse(g.to), start, end)
            return <span key={g.from} className="tl-gap" style={{ left: `${x1 * 100}%`, width: `max(2px, ${(x2 - x1) * 100}%)` }} />
          })}
          <span className="tl-now" />
        </div>
        <ol className="tl-rows" ref={bodyRef} aria-label="Objects, those with an incident first, then by most recent activity">
          {data.rows.map((row) => (
            <Lane
              key={row.key}
              row={row}
              clusterId={clusterId}
              start={start}
              end={end}
              windowMs={windowMs}
              trackPx={trackPx}
              openBin={open?.row === row.key ? open.bin : null}
              onToggleBin={(bin) => setOpen((o) => (o?.row === row.key && o.bin === bin ? null : { row: row.key, bin }))}
              onGo={go}
              onTip={setTip}
              onMoveRow={moveRow}
            />
          ))}
        </ol>
      </div>
      {tip && <Tooltip tip={tip} />}
    </div>
  )
}

const STRIP_BINS = 48

/** The whole cluster's activity over the window as one strip above the
 *  rows (owner-approved cluster-pages design, 2026-10-11): changes and
 *  findings per bin, stacked, and a flag where each drawn incident opened.
 *  Counted over the events this answer drew, which the meta says. */
function ActivityStrip({ data, start, end, windowMs }: { data: Timeline; start: number; end: number; windowMs: number }) {
  const { bins, peak, flags } = useMemo(() => {
    const bins = Array.from({ length: STRIP_BINS }, () => ({ changes: 0, findings: 0 }))
    const flags: { x: number; severity: string; label: string; id: string }[] = []
    for (const row of data.rows) {
      for (const m of row.marks) {
        const i = Math.min(STRIP_BINS - 1, Math.floor(pos(Date.parse(m.at), start, end) * STRIP_BINS))
        const n = 1 + (m.more ?? 0)
        if (m.type === 'change') bins[i].changes += n
        else bins[i].findings += n
      }
      for (const sp of row.spans) {
        const from = Date.parse(sp.from)
        if (from >= start && from <= end) {
          flags.push({ x: pos(from, start, end), severity: sp.severity, id: sp.incidentId, label: `${severityWord(sp.severity)} incident opened ${markTime(sp.from, windowMs)} on ${objectLabel(row)}` })
        }
      }
    }
    const peak = Math.max(1, ...bins.map((b) => b.changes + b.findings))
    return { bins, peak, flags }
  }, [data.rows, start, end, windowMs])
  const total = bins.reduce((n, b) => n + b.changes + b.findings, 0)
  if (total === 0 && flags.length === 0) return null
  return (
    <div className="tl-activity">
      <div className="tl-activity-label">
        <span className="tl-activity-title">Whole cluster</span>
        <span className="text-muted">drawn events, peak {peak} per bin</span>
      </div>
      <div className="tl-activity-track" role="img" aria-label={`Activity over the window: ${total} drawn events, ${flags.length} incidents opened`}>
        {bins.map((b, i) => (
          <span key={i} className="tl-activity-bin" style={{ left: `${(i * 100) / STRIP_BINS}%`, width: `${100 / STRIP_BINS}%` }}>
            {b.findings > 0 && <span className="tl-activity-findings" style={{ height: `${(b.findings * 100) / peak}%` }} />}
            {b.changes > 0 && <span className="tl-activity-changes" style={{ height: `${(b.changes * 100) / peak}%` }} />}
          </span>
        ))}
        {flags.map((f) => (
          <Link key={f.id} className={`tl-activity-flag ${SEV_CLASS[f.severity] ?? 'sev-neutral'}`} style={{ left: `${f.x * 100}%` }} to={`/incidents/${encodeURIComponent(f.id)}`} title={f.label} aria-label={f.label} />
        ))}
      </div>
    </div>
  )
}

function Tooltip({ tip }: { tip: Tip }) {
  const ref = useRef<HTMLDivElement>(null)
  const [style, setStyle] = useState<{ top: number; left: number; maxWidth: number }>({ top: -9999, left: -9999, maxWidth: 360 })
  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    const maxWidth = Math.min(360, window.innerWidth - 16)
    const w = Math.min(el.offsetWidth, maxWidth)
    const h = el.offsetHeight
    let left = tip.rect.left + tip.rect.width / 2 - w / 2
    left = Math.max(8, Math.min(left, window.innerWidth - w - 8))
    let top = tip.rect.top - h - 6
    if (top < 8) top = tip.rect.bottom + 6
    setStyle({ top, left, maxWidth })
  }, [tip])
  const clamped = tip.lines.map(clampTipLine)
  return createPortal(
    <div ref={ref} className="help-tip-bubble tl-tip" aria-hidden="true" style={style}>
      {clamped.map((l, i) => (
        <p key={i}>{l.text}</p>
      ))}
      {tip.more > 0 ? (
        <p className="tl-tip-more">and {tip.more} more — select to list them</p>
      ) : (
        clamped.some((l) => l.cut) && <p className="tl-tip-more">Select to read in full</p>
      )}
    </div>,
    document.body,
  )
}

interface Item {
  key: string
  x: number
  kind: 'span' | 'bin'
}

function Lane({
  row,
  clusterId,
  start,
  end,
  windowMs,
  trackPx,
  openBin,
  onToggleBin,
  onGo,
  onTip,
  onMoveRow,
}: {
  row: TimelineRow
  clusterId: string
  start: number
  end: number
  windowMs: number
  trackPx: number
  openBin: string | null
  onToggleBin: (bin: string) => void
  onGo: (t: MarkTarget) => void
  onTip: (t: Tip | null) => void
  onMoveRow: (from: HTMLElement, delta: number) => void
}) {
  const bins = useMemo(() => binMarks(row.marks, start, end, trackPx), [row.marks, start, end, trackPx])
  const trails = useMemo(() => findingTrails(row.marks, start, end), [row.marks, start, end])
  const { placed, lanes } = useMemo(() => placeSpans(row.spans, start, end), [row.spans, start, end])
  const items: Item[] = useMemo(
    () =>
      [
        ...placed.map((p) => ({ key: `span:${p.span.incidentId}`, x: p.x1, kind: 'span' as const })),
        ...bins.map((b) => ({ key: `bin:${b.key}`, x: b.x, kind: 'bin' as const })),
      ].sort((a, b) => a.x - b.x),
    [placed, bins],
  )
  const [active, setActive] = useState(0)
  const activeKey = items[Math.min(active, items.length - 1)]?.key
  const itemRefs = useRef<Record<string, HTMLButtonElement | null>>({})
  const obj = rowObject(row, clusterId)
  const incident = rowIncidentSummary(row)
  const counts = rowCountsText(row)
  const openObject = useOpenObject()
  const detail = openBin ? bins.find((b) => b.key === openBin) : undefined

  const onKey = (e: KeyboardEvent<HTMLElement>) => {
    const i = items.findIndex((it) => it.key === activeKey)
    let next = -1
    if (e.key === 'ArrowRight') next = Math.min(i + 1, items.length - 1)
    else if (e.key === 'ArrowLeft') next = Math.max(i - 1, 0)
    else if (e.key === 'Home') next = 0
    else if (e.key === 'End') next = items.length - 1
    else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault()
      onTip(null)
      onMoveRow(e.target as HTMLElement, e.key === 'ArrowDown' ? 1 : -1)
      return
    } else if (e.key === 'Escape') {
      onTip(null)
      if (openBin) onToggleBin(openBin)
      return
    }
    if (next >= 0) {
      e.preventDefault()
      setActive(next)
      itemRefs.current[items[next].key]?.focus()
    }
  }

  const tipFor = (lines: string[], el: HTMLElement) => onTip({ lines: lines.slice(0, 4), more: Math.max(lines.length - 4, 0), rect: el.getBoundingClientRect() })

  return (
    <li className="tl-lane" id={rowDomId(row.key)}>
      <div className="tl-label">
        <div className="tl-label-head">
          {row.kind && <span className="preview-kind">{row.kind}</span>}
          {obj ? (
            <button type="button" className="link-button tl-label-name" onClick={() => openObject(obj)} aria-label={`Open ${row.kind} ${row.name}`}>
              {row.name}
            </button>
          ) : (
            <span className="tl-label-name tl-label-objectless">{row.objectless ? `No object named · ${row.name}` : row.name}</span>
          )}
        </div>
        <div className="tl-label-meta">
          {row.namespace && <span className="tl-label-ns">{row.namespace}</span>}
          {counts && <span>{counts}</span>}
        </div>
        {incident && (
          <div className={`tl-label-incident ${SEV_CLASS[incident.severity] ?? 'sev-neutral'}`}>
            <span className="severity-chip" aria-hidden="true" />
            {incident.text}
          </div>
        )}
        {(row.marksOmitted > 0 || row.spansOmitted > 0) && (
          <div className="tl-label-omitted">
            {row.marksOmitted > 0 && omittedText(row)}
            {row.marksOmitted > 0 && row.spansOmitted > 0 && ' · '}
            {row.spansOmitted > 0 && `${row.spansOmitted} older incident${row.spansOmitted === 1 ? '' : 's'} not drawn`}
          </div>
        )}
      </div>
      <div
        className="tl-track"
        role="group"
        aria-label={`Events on ${objectLabel(row)}`}
        onKeyDown={onKey}
        onMouseLeave={() => onTip(null)}
        // Incident bands stack above the row's time line, one lane each.
        style={{ ['--tl-lanes' as string]: lanes }}
      >
        {placed.map((p) => {
          const key = `span:${p.span.incidentId}`
          const wide = (p.x2 - p.x1) * trackPx >= 64
          return (
            <button
              key={key}
              ref={(el) => {
                itemRefs.current[key] = el
              }}
              type="button"
              className={`tl-item tl-span ${SEV_CLASS[p.span.severity] ?? 'sev-neutral'}`}
              data-x={p.x1}
              data-before={p.startsBefore || undefined}
              data-open={p.open || undefined}
              tabIndex={key === activeKey ? 0 : -1}
              style={{
                left: `${p.x1 * 100}%`,
                width: `max(6px, ${(p.x2 - p.x1) * 100}%)`,
                ['--tl-lane' as string]: p.lane,
              }}
              aria-label={`${describeSpan(p.span, windowMs)} Open the incident.`}
              onClick={() => onGo({ incidentId: p.span.incidentId })}
              onFocus={(e) => {
                setActive(items.findIndex((it) => it.key === key))
                tipFor([describeSpan(p.span, windowMs)], e.currentTarget)
              }}
              onBlur={() => onTip(null)}
              onMouseEnter={(e) => tipFor([describeSpan(p.span, windowMs)], e.currentTarget)}
            >
              {wide && <span className="tl-span-word">{severityWord(p.span.severity)}</span>}
            </button>
          )
        })}
        {trails.map((tr) => (
          <span
            key={tr.key}
            className="tl-trail"
            data-before={tr.fromBefore || undefined}
            aria-hidden="true"
            style={{ left: `${tr.x1 * 100}%`, width: `${(tr.x2 - tr.x1) * 100}%` }}
          />
        ))}
        {bins.map((b) => {
          const key = `bin:${b.key}`
          const lines = b.marks.map((m) => describeMark(m, row, windowMs))
          const total = binTotal(b)
          // One event opens its object directly; anything else lists first.
          const single = total === 1 ? markTarget(b.marks[0], clusterId) : null
          return (
            <button
              key={key}
              ref={(el) => {
                itemRefs.current[key] = el
              }}
              type="button"
              className="tl-item tl-mark"
              data-x={b.x}
              data-size={total >= 10 ? 'l' : total > 1 ? 'm' : undefined}
              data-change={b.hasChange || undefined}
              data-finding={b.hasFinding || undefined}
              data-from-before={(b.marks.length === 1 && b.marks[0].continuesFromBefore) || undefined}
              tabIndex={key === activeKey ? 0 : -1}
              // Clamped so a mark at the window's first instant (or at
              // "now") sits wholly on the track instead of half over the
              // label column; it is centred on its time everywhere else.
              style={{ left: `clamp(0.85rem, ${b.x * 100}%, calc(100% - 0.85rem))` }}
              aria-label={single ? `${lines[0]}. Open.` : `${total} events: ${lines.join('; ')}. List them.`}
              aria-expanded={single ? undefined : openBin === b.key}
              onClick={() => (single ? onGo(single) : onToggleBin(b.key))}
              onFocus={(e) => {
                setActive(items.findIndex((it) => it.key === key))
                tipFor(lines, e.currentTarget)
              }}
              onBlur={() => onTip(null)}
              onMouseEnter={(e) => tipFor(lines, e.currentTarget)}
            >
              {b.hasChange && <span className="tl-glyph tl-glyph-change" aria-hidden="true" />}
              {b.hasFinding && <span className="tl-glyph tl-glyph-finding" aria-hidden="true" />}
              {total > 1 && <span className="tl-mark-count">{total}</span>}
            </button>
          )
        })}
      </div>
      {detail && (
        <BinDetail
          bin={detail}
          row={row}
          clusterId={clusterId}
          windowMs={windowMs}
          onGo={onGo}
          onOpenRow={obj ? () => openObject(obj) : undefined}
          onClose={() => {
            onToggleBin(detail.key)
            // Back to the mark that opened the list, so Esc or Close never
            // drops a keyboard user at the top of the page.
            itemRefs.current[`bin:${detail.key}`]?.focus()
          }}
        />
      )}
    </li>
  )
}

function omittedText(row: TimelineRow): string {
  const n = row.marksOmitted
  return row.markBucketSeconds > 0
    ? `${n.toLocaleString()} more event${n === 1 ? '' : 's'} counted on nearby marks`
    : `${n.toLocaleString()} older event${n === 1 ? '' : 's'} not drawn`
}

function targetLabel(t: MarkTarget): string {
  if (!t) return ''
  if ('object' in t) return `Open ${t.object.kind}/${t.object.name}`
  return 'Open the incident'
}

function typeWord(m: TimelineMark): string {
  if (m.type === 'change') return m.op === 'add' ? 'Created' : m.op === 'delete' ? 'Deleted' : 'Changed'
  if (m.type === 'finding') return `${severityWord(m.severity)} ${isWarningEvent(m) ? 'warning event' : 'finding'}`
  if (m.type === 'incident-opened') return `${severityWord(m.severity)} incident opened`
  return 'Incident closed'
}

function BinDetail({
  bin,
  row,
  clusterId,
  windowMs,
  onGo,
  onOpenRow,
  onClose,
}: {
  bin: Bin
  row: TimelineRow
  clusterId: string
  windowMs: number
  onGo: (t: MarkTarget) => void
  onOpenRow?: () => void
  onClose: () => void
}) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    ref.current?.focus()
  }, [])
  return (
    <div
      className="tl-detail"
      ref={ref}
      tabIndex={-1}
      role="region"
      aria-label={`${bin.marks.length} events on ${objectLabel(row)}`}
      onKeyDown={(e) => {
        if (e.key === 'Escape') {
          e.stopPropagation()
          onClose()
        }
      }}
    >
      <div className="tl-detail-head">
        <strong>
          {binTotal(bin)} events around {markTime(bin.marks[0].at, windowMs)}
        </strong>
        {/* The events below that belong to this row's own object carry no
            link of their own (the row's name opens it), so the list says
            where to go next rather than ending here. */}
        {onOpenRow && (
          <button type="button" className="link-button tl-event-open" onClick={onOpenRow}>
            Open {row.kind ? `${row.kind}/` : ''}
            {row.name}
          </button>
        )}
        <button type="button" className="secondary tl-detail-close" onClick={onClose}>
          Close
        </button>
      </div>
      <EventItems marks={bin.marks} row={row} clusterId={clusterId} windowMs={windowMs} onGo={onGo} />
    </div>
  )
}

function EventItems({ marks, row, clusterId, windowMs, onGo }: { marks: TimelineMark[]; row: TimelineRow; clusterId: string; windowMs: number; onGo: (t: MarkTarget) => void }) {
  return (
    <ul className="tl-events">
      {marks.map((m) => {
        const own = m.object && !(m.object.kind === row.kind && m.object.name === row.name) ? objectLabel(m.object) : ''
        // The row's own object opens from the row's name; repeat the link only
        // for another object (a Pod under its Deployment) or an incident.
        const t = markTarget(m, clusterId)
        const target = t && 'object' in t && !own && !row.objectless ? null : t
        return (
          <li key={`${m.type}:${m.id}:${m.at}`} className={m.type === 'finding' || m.type.startsWith('incident') ? (SEV_CLASS[m.severity ?? ''] ?? 'sev-neutral') : undefined}>
            <span className="tl-event-time">{markTime(m.at, windowMs)}</span>
            <span className="tl-event-type">
              {m.type === 'change' ? <Glyph kind="changes" /> : m.type === 'finding' ? <Glyph kind="findings" /> : <Glyph kind="incidents" />} {typeWord(m)}
            </span>
            <span className="tl-event-what">
              {own && <span className="tl-event-object">{own}: </span>}
              {m.summary}
              {m.type === 'finding' && (m.reports ?? 1) > 1 && m.until && (
                <span className="tl-event-extra">
                  {' '}
                  — reported {m.reports}× until {markTime(m.until, windowMs)}
                </span>
              )}
              {m.continuesFromBefore && <span className="tl-event-extra"> — already being reported before this window</span>}
              {(m.more ?? 0) > 0 && <span className="tl-event-extra"> — {moreText(m, row)}, not listed singly</span>}
            </span>
            {target && (
              <button type="button" className="link-button tl-event-open" onClick={() => onGo(target)}>
                {targetLabel(target)}
              </button>
            )}
          </li>
        )
      })}
    </ul>
  )
}

// ---------------------------------------------------------------- narrow

const LIST_EVENTS = 5

function EventList({ rows, clusterId, windowMs }: { rows: TimelineRow[]; clusterId: string; windowMs: number }) {
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set())
  const navigate = useNavigate()
  const openObject = useOpenObject()
  const go = (t: MarkTarget) => {
    if (!t) return
    if ('object' in t) openObject(t.object)
    else navigate(`/incidents/${encodeURIComponent(t.incidentId)}`)
  }
  return (
    <ol className="tl-list" aria-label="Objects, those with an incident first, then by most recent activity">
      {rows.map((row) => {
        const obj = rowObject(row, clusterId)
        const counts = rowCountsText(row)
        const events = rowEvents(row).filter((m) => m.type !== 'incident-opened' && m.type !== 'incident-closed')
        return (
          <li key={row.key} className="tl-list-item" id={rowDomId(row.key)}>
            <div className="tl-label-head">
              {row.kind && <span className="preview-kind">{row.kind}</span>}
              {obj ? (
                <button type="button" className="link-button tl-label-name" onClick={() => openObject(obj)}>
                  {row.name}
                </button>
              ) : (
                <span className="tl-label-name tl-label-objectless">{row.objectless ? `No object named · ${row.name}` : row.name}</span>
              )}
            </div>
            <div className="tl-label-meta">
              {row.namespace && <span className="tl-label-ns">{row.namespace}</span>}
              {counts && <span>{counts}</span>}
            </div>
            {row.spans.length > 0 && (
              <ul className="tl-events">
                {row.spans.map((s) => (
                  <li key={s.incidentId} className={SEV_CLASS[s.severity] ?? 'sev-neutral'}>
                    <span className="tl-event-type">
                      <span className="severity-chip" aria-hidden="true" /> {severityWord(s.severity)} incident
                    </span>
                    <span className="tl-event-what">{describeSpan(s, windowMs).replace(/^[^:]*: /, '')}</span>
                    <button type="button" className="link-button tl-event-open" onClick={() => go({ incidentId: s.incidentId })}>
                      Open the incident
                    </button>
                  </li>
                ))}
              </ul>
            )}
            {events.length > 0 && (
              <EventItems marks={expanded.has(row.key) ? events : events.slice(0, LIST_EVENTS)} row={row} clusterId={clusterId} windowMs={windowMs} onGo={go} />
            )}
            {events.length > LIST_EVENTS && (
              <button
                type="button"
                className="link-button tl-list-more"
                aria-expanded={expanded.has(row.key)}
                onClick={() =>
                  setExpanded((prev) => {
                    const next = new Set(prev)
                    if (next.has(row.key)) next.delete(row.key)
                    else next.add(row.key)
                    return next
                  })
                }
              >
                {expanded.has(row.key) ? 'Show the newest 5' : `Show all ${events.length} events`}
              </button>
            )}
            {row.marksOmitted > 0 && <p className="tl-label-omitted">{omittedText(row)}</p>}
          </li>
        )
      })}
    </ol>
  )
}
