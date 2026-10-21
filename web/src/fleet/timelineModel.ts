// The cluster Timeline's pure half (PROJECT.md AD1): window presets, the time
// axis, mark positions and binning, incident-span lanes, and the words every
// mark is read as. ClusterTimeline.tsx renders; this decides. Nothing here
// invents a value: every count and time comes from GET /clusters/{id}/timeline.

import type { IncidentSeverity, IncidentState, TimelineMark, TimelineRow, TimelineSpan } from '../api/types'
import { SEVERITY_LABEL, SEVERITY_RANK, STATE_LABEL } from '../utils/incidents'
import type { ObjectRef } from '../insight/panelUrl'

export const WINDOWS = ['1h', '6h', '24h', '7d'] as const
export type TimelineWindow = (typeof WINDOWS)[number]

export const WINDOW_MS: Record<TimelineWindow, number> = {
  '1h': 3_600_000,
  '6h': 6 * 3_600_000,
  '24h': 24 * 3_600_000,
  '7d': 7 * 24 * 3_600_000,
}

export const WINDOW_LABEL: Record<TimelineWindow, string> = {
  '1h': 'last hour',
  '6h': 'last 6 hours',
  '24h': 'last 24 hours',
  '7d': 'last 7 days',
}

/** Position of t across [start, end], clamped to the track. */
export function pos(t: number, start: number, end: number): number {
  const span = Math.max(end - start, 1)
  return Math.min(Math.max((t - start) / span, 0), 1)
}

// ---------------------------------------------------------------- axis

const MIN = 60_000
const HOUR = 60 * MIN
const DAY = 24 * HOUR
const STEPS = [5 * MIN, 10 * MIN, 15 * MIN, 30 * MIN, HOUR, 2 * HOUR, 3 * HOUR, 6 * HOUR, 12 * HOUR, DAY, 2 * DAY]

export interface Tick {
  at: number
  x: number
  label: string
}

/**
 * Axis ticks at a whole local-time step, as many as fit the track at roughly
 * `minPx` apart — so the axis scales with width rather than overprinting at
 * 1024 or going sparse at 1440.
 */
export function axisTicks(start: number, end: number, widthPx: number, minPx = 84): Tick[] {
  const span = end - start
  if (span <= 0 || widthPx <= 0) return []
  const step = STEPS.find((s) => (widthPx * s) / span >= minPx) ?? STEPS[STEPS.length - 1]
  // Local-time alignment: an hourly tick sits on the hour in the viewer's zone.
  const offset = new Date(start).getTimezoneOffset() * MIN
  let t = Math.ceil((start - offset) / step) * step + offset
  const ticks: Tick[] = []
  while (t <= end) {
    // Leave the right edge to the "now" label (about one label's width).
    const x = pos(t, start, end)
    if ((1 - x) * widthPx > minPx * 0.8) ticks.push({ at: t, x, label: tickLabel(t, step) })
    t += step
  }
  return ticks
}

function tickLabel(t: number, step: number): string {
  const d = new Date(t)
  const day = d.toLocaleDateString(undefined, { weekday: 'short', day: 'numeric' })
  if (step >= DAY) return day
  const time = d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
  return d.getHours() === 0 && d.getMinutes() === 0 ? day : time
}

/** A time in the window, worded for a tooltip or list: time only within a day, else date and time. */
export function markTime(iso: string, windowMs: number, now = Date.now()): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  // Time alone only inside a short window and within the last day: an
  // incident span that opened days before a 1h window keeps its date.
  return windowMs <= DAY && Math.abs(now - d.getTime()) < 20 * HOUR
    ? d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
    : d.toLocaleString(undefined, { weekday: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

// ---------------------------------------------------------------- severity

export const SEV_CLASS: Record<string, string> = {
  critical: 'sev-critical',
  high: 'sev-high',
  medium: 'sev-medium',
  low: 'sev-low',
}

export function severityWord(s: string | undefined): string {
  if (!s) return 'Severity not set'
  return SEVERITY_LABEL[s as IncidentSeverity] ?? s
}

export function stateWord(s: string): string {
  return STATE_LABEL[s as IncidentState] ?? s
}

function rank(s: string | undefined): number {
  return s && s in SEVERITY_RANK ? SEVERITY_RANK[s as IncidentSeverity] : 9
}

/**
 * The row's incidents in words, worst first — "Critical · open, Medium ·
 * Dismissed" — so every band's severity is named beside it even when the band
 * is too narrow to print its own word. The chip colour is the worst one.
 * Null with no spans.
 */
export function rowIncidentSummary(row: TimelineRow, max = 3): { severity: string; text: string; open: boolean } | null {
  if (row.spans.length === 0) return null
  const sorted = [...row.spans].sort((a, b) => Number(b.to === null) - Number(a.to === null) || rank(a.severity) - rank(b.severity))
  const words = sorted.map((s) => `${severityWord(s.severity)} · ${s.to === null ? 'open' : stateWord(s.state)}`)
  const unique = [...new Set(words)]
  const shown = unique.slice(0, max)
  const extra = row.counts.incidents - row.spans.length + (unique.length - shown.length)
  const worst = [...row.spans].sort((a, b) => rank(a.severity) - rank(b.severity))[0]
  return {
    severity: worst.severity,
    open: sorted[0].to === null,
    text: `${shown.join(', ')}${extra > 0 ? ` (+${extra} more)` : ''}`,
  }
}

// ---------------------------------------------------------------- marks

export function isWarningEvent(m: TimelineMark): boolean {
  return m.detectorId === 'k8s-warning-events'
}

export function objectLabel(o: { kind: string; name: string } | undefined | null): string {
  if (!o) return ''
  return o.kind ? `${o.kind}/${o.name}` : o.name
}

export function formatStretch(seconds: number): string {
  if (seconds >= 2 * 3600) return `${Math.round(seconds / 3600)} h`
  return `${Math.max(1, Math.round(seconds / 60))} min`
}

/** "and 12 earlier changes in the 48 min before" — the events a thinned mark stands for. */
export function moreText(m: TimelineMark, row: TimelineRow): string {
  const n = m.more ?? 0
  if (n <= 0) return ''
  const what = m.type === 'finding' ? 'finding' : m.type === 'change' ? 'change' : 'event'
  return `and ${n} earlier ${what}${n === 1 ? '' : 's'} in the ${formatStretch(row.markBucketSeconds)} before`
}

/** How many events a bin stands for, counting thinned ones. */
export function binTotal(b: Bin): number {
  return b.marks.reduce((n, m) => n + 1 + (m.more ?? 0), 0)
}

/** One sentence for a mark: what, on which object, when — the tooltip and the accessible name. */
export function describeMark(m: TimelineMark, row: TimelineRow, windowMs: number): string {
  const more = moreText(m, row)
  return more ? `${describeOne(m, row, windowMs)} — ${more}` : describeOne(m, row, windowMs)
}

function describeOne(m: TimelineMark, row: TimelineRow, windowMs: number): string {
  const when = markTime(m.at, windowMs)
  const own = m.object && !(m.object.kind === row.kind && m.object.name === row.name) ? `${objectLabel(m.object)} ` : ''
  switch (m.type) {
    case 'change':
      return `${when} · change: ${own}${m.summary}`
    case 'finding': {
      const kind = isWarningEvent(m) ? 'warning event' : 'finding'
      const reports = m.reports ?? 1
      const until = m.until && reports > 1 ? `, reported ${reports}× until ${markTime(m.until, windowMs)}` : ''
      const before = m.continuesFromBefore ? ' (already being reported before this window)' : ''
      return `${when} · ${severityWord(m.severity)} ${kind}: ${own}${m.summary}${until}${before}`
    }
    case 'incident-opened':
      return `${when} · ${severityWord(m.severity)} incident opened: ${m.summary.replace(/^opened: /, '')}`
    case 'incident-closed':
      return `${when} · incident ${m.summary}`
    default:
      return `${when} · ${m.summary}`
  }
}

export function describeSpan(s: TimelineSpan, windowMs: number): string {
  const from = markTime(s.from, windowMs)
  const to = s.to === null ? 'still open' : `${s.endEstimated ? 'last seen' : stateWord(s.state).toLowerCase()} ${markTime(s.to, windowMs)}`
  return `${severityWord(s.severity)} incident: ${s.summary} — opened ${from}, ${to}. ${stateWord(s.state)}.`
}

/** Where a mark leads: its object in the inspector, else its incident. */
export type MarkTarget = { object: ObjectRef } | { incidentId: string } | null

export function markTarget(m: TimelineMark, clusterId: string): MarkTarget {
  if (m.object && m.object.kind && m.object.name) {
    return {
      object: {
        clusterId,
        kind: m.object.kind,
        apiGroup: m.object.apiGroup || undefined,
        namespace: m.object.namespace || undefined,
        name: m.object.name,
      },
    }
  }
  if (m.incidentId) return { incidentId: m.incidentId }
  return null
}

export function rowObject(row: TimelineRow, clusterId: string): ObjectRef | null {
  if (row.objectless || !row.kind || !row.name) return null
  return { clusterId, kind: row.kind, apiGroup: row.apiGroup || undefined, namespace: row.namespace || undefined, name: row.name }
}

export interface Bin {
  key: string
  /** Position of the bin's earliest mark, 0..1. */
  x: number
  marks: TimelineMark[]
  hasChange: boolean
  hasFinding: boolean
}

/** The drawn width of a bin in px: one glyph per type plus its count badge. */
export function binWidthPx(b: Pick<Bin, 'hasChange' | 'hasFinding' | 'marks'>): number {
  const total = b.marks.reduce((n, m) => n + 1 + (m.more ?? 0), 0)
  const glyphs = (b.hasChange ? 11 : 0) + (b.hasFinding ? 11 : 0)
  return Math.max(glyphs, 11) + (total > 1 ? 8 + String(total).length * 7 : 0) + 4
}

/**
 * Groups a row's change and finding marks that would overprint at this width
 * into one focusable bin with a count — a rollout's Deployment, ReplicaSet and
 * Pod changes in the same second are three facts, not one smudge. Two marks
 * merge when their drawn widths (glyphs plus count) would touch. Incident
 * openings and closings are drawn by their span, not as marks.
 */
export function binMarks(marks: readonly TimelineMark[], start: number, end: number, widthPx: number, padPx = 6): Bin[] {
  const pts = marks
    .filter((m) => m.type === 'change' || m.type === 'finding')
    .map((m) => ({ m, x: pos(Date.parse(m.at), start, end) }))
    .sort((a, b) => a.x - b.x)
  const bins: Bin[] = []
  const px = Math.max(widthPx, 1)
  for (const p of pts) {
    const last = bins[bins.length - 1]
    const single = { hasChange: p.m.type === 'change', hasFinding: p.m.type === 'finding', marks: [p.m] }
    if (last) {
      // Centre-anchored buttons touch when the gap is under half of each width.
      const reach = binWidthPx(last) / 2 + binWidthPx(single) / 2 + padPx
      if ((p.x - last.x) * px < reach) {
        last.marks.push(p.m)
        last.hasChange ||= single.hasChange
        last.hasFinding ||= single.hasFinding
        continue
      }
    }
    bins.push({ key: `${p.m.type}:${p.m.id}:${p.m.at}`, x: p.x, ...single })
  }
  return bins
}

export interface FindingTrail {
  key: string
  x1: number
  x2: number
  fromBefore: boolean
}

/** The "still being reported" line behind each finding run that lasted. */
export function findingTrails(marks: readonly TimelineMark[], start: number, end: number): FindingTrail[] {
  return marks
    .filter((m) => m.type === 'finding' && m.until && Date.parse(m.until) > Date.parse(m.at))
    .map((m) => ({
      key: `${m.id}:${m.at}`,
      x1: m.continuesFromBefore ? 0 : pos(Date.parse(m.at), start, end),
      x2: pos(Date.parse(m.until!), start, end),
      fromBefore: !!m.continuesFromBefore,
    }))
}

export interface PlacedSpan {
  span: TimelineSpan
  x1: number
  x2: number
  lane: number
  startsBefore: boolean
  open: boolean
}

/** Incident spans laid into lanes so overlapping incidents on one row stay separate. */
export function placeSpans(spans: readonly TimelineSpan[], start: number, end: number): { placed: PlacedSpan[]; lanes: number } {
  const sorted = [...spans].sort((a, b) => Date.parse(a.from) - Date.parse(b.from))
  const laneEnds: number[] = []
  const placed = sorted.map((s) => {
    const from = Date.parse(s.from)
    const to = s.to === null ? end : Date.parse(s.to)
    let lane = laneEnds.findIndex((e) => e <= from)
    if (lane < 0) {
      lane = laneEnds.length
      laneEnds.push(to)
    } else {
      laneEnds[lane] = to
    }
    return { span: s, x1: pos(from, start, end), x2: pos(to, start, end), lane, startsBefore: from < start, open: s.to === null }
  })
  return { placed, lanes: laneEnds.length }
}

/** "3 changes · 2 findings · 1 incident" for the label column; zeroes are left out, never printed. */
export function rowCountsText(row: TimelineRow): string {
  const c = row.counts
  const parts: string[] = []
  if (c.changes > 0) parts.push(`${c.changes} change${c.changes === 1 ? '' : 's'}`)
  if (c.findingRuns > 0) parts.push(`${c.findingRuns} finding${c.findingRuns === 1 ? '' : 's'}`)
  if (c.incidents > 0) parts.push(`${c.incidents} incident${c.incidents === 1 ? '' : 's'}`)
  return parts.join(' · ')
}

/** Every event on the row, newest first, for the narrow-screen list and the bin detail. */
export function rowEvents(row: TimelineRow): TimelineMark[] {
  return [...row.marks].sort((a, b) => Date.parse(b.at) - Date.parse(a.at))
}

// ---------------------------------------------------------------- incident leads

/** How far before an incident opened the lead looks for changes. */
export const LEAD_LOOKBACK_MS = 30 * MIN

export interface NearbyChange {
  row: TimelineRow
  /** Change marks on that row inside the look-back. */
  changes: number
}

export interface IncidentLead {
  span: TimelineSpan
  row: TimelineRow
  /** Change and finding marks on the incident's own row in the look-back
   *  before it opened. Marks only: a thinned mark's `more` events may fall
   *  before the look-back, so they make the count a lower bound instead. */
  ownChanges: number
  ownFindings: number
  /** Other rows with a change in the look-back, most changes first. */
  nearby: NearbyChange[]
  nearbyMore: number
  /** True when some events in reach were not drawn or were thinned, so the
   *  counts are lower bounds. */
  atLeast: boolean
}

function changesBetween(row: TimelineRow, from: number, to: number): { changes: number; findings: number; thinned: boolean } {
  let changes = 0
  let findings = 0
  let thinned = false
  for (const m of row.marks) {
    const t = Date.parse(m.at)
    if (t < from || t > to) continue
    if (m.type === 'change') changes += 1
    else if (m.type === 'finding') findings += 1
    else continue
    if ((m.more ?? 0) > 0) thinned = true
  }
  return { changes, findings, thinned }
}

/**
 * The Timeline's lead (owner review 2026-10-11): ARGUS's question is "what
 * changed right before it broke", so the tab opens with the incidents that
 * OPENED in the window, worst first, each with what changed on its own
 * object — and on any other object — in the half hour before. Closeness in
 * time is offered as a lead, never as a cause; the incident's own analysis
 * is where a cause is argued. Incidents already open when the window began
 * are counted in `earlier`, not led with: nothing in the window preceded
 * them.
 */
export function incidentLeads(
  rows: readonly TimelineRow[],
  start: number,
  truncatedChanges: boolean,
  lookbackMs = LEAD_LOOKBACK_MS,
  nearbyMax = 3,
): { leads: IncidentLead[]; earlier: number } {
  const seen = new Set<string>()
  const leads: IncidentLead[] = []
  let earlier = 0
  for (const row of rows) {
    for (const span of row.spans) {
      if (seen.has(span.incidentId)) continue
      seen.add(span.incidentId)
      const opened = Date.parse(span.from)
      if (opened < start) {
        earlier += 1
        continue
      }
      const from = opened - lookbackMs
      const own = changesBetween(row, from, opened)
      let thinned = own.thinned || row.marksOmitted > 0
      const nearbyAll: NearbyChange[] = []
      for (const other of rows) {
        if (other === row) continue
        const c = changesBetween(other, from, opened)
        if (c.thinned) thinned = true
        if (c.changes > 0) nearbyAll.push({ row: other, changes: c.changes })
      }
      nearbyAll.sort((a, b) => b.changes - a.changes || a.row.name.localeCompare(b.row.name))
      leads.push({
        span,
        row,
        ownChanges: own.changes,
        ownFindings: own.findings,
        nearby: nearbyAll.slice(0, nearbyMax),
        nearbyMore: Math.max(nearbyAll.length - nearbyMax, 0),
        atLeast: thinned || truncatedChanges || from < start,
      })
    }
  }
  leads.sort((a, b) => rank(a.span.severity) - rank(b.span.severity) || Date.parse(b.span.from) - Date.parse(a.span.from))
  return { leads, earlier }
}

export interface LeadSummary {
  heading: string
  /** How the heading's count relates to the header's "open at some point". */
  meta: string
  /** Set when some of the incidents that opened are on objects not drawn. */
  drawnNote: string | null
}

function n(count: number, word: string): string {
  return `${count.toLocaleString()} ${word}${count === 1 ? '' : 's'}`
}

/**
 * The lead section's counts, worded so they add up to the header's
 * "N incidents open at some point in it": opened in the window + already open
 * when it began = N, from the hub's exact totals. The leads themselves can
 * only be the incidents on objects the hub drew, so when fewer are listed
 * than opened, the note says how many and where the rest are. A hub that
 * predates `incidentsOpened` gets the drawn-only counts, named as such, with
 * the remainder stated rather than silently dropped.
 */
export function leadSummary(args: {
  windowLabel: string
  total: number
  openedTotal: number | undefined
  leadsDrawn: number
  earlierDrawn: number
}): LeadSummary {
  const { windowLabel, total, openedTotal, leadsDrawn, earlierDrawn } = args
  if (typeof openedTotal === 'number') {
    const before = Math.max(total - openedTotal, 0)
    const heading = openedTotal === 0 ? `No incident opened in the ${windowLabel}` : `${n(openedTotal, 'incident')} opened in the ${windowLabel}`
    const was = before === 1 ? 'was' : 'were'
    const meta =
      openedTotal === 0
        ? before > 0
          ? `${n(before, 'incident')} ${was} already open when it began.`
          : ''
        : `${before.toLocaleString()} more ${was} already open when it began — ${total.toLocaleString()} open at some point in it.`
    let drawnNote: string | null = null
    if (openedTotal > leadsDrawn) {
      const rest = openedTotal - leadsDrawn
      drawnNote =
        leadsDrawn === 0
          ? `None of them is drawn below — narrow by namespace to list ${openedTotal === 1 ? 'it' : 'them'}.`
          : `Listed: the ${leadsDrawn.toLocaleString()} drawn below. The other ${rest.toLocaleString()} ${rest === 1 ? 'is' : 'are'} on objects the timeline left out — narrow by namespace to see ${rest === 1 ? 'it' : 'them'}.`
    }
    return { heading, meta, drawnNote }
  }
  const drawn = leadsDrawn + earlierDrawn
  const heading =
    leadsDrawn === 0 ? `No incident on the objects drawn opened in the ${windowLabel}` : `${n(leadsDrawn, 'incident')} on the objects drawn opened in the ${windowLabel}`
  const meta = earlierDrawn > 0 ? `${earlierDrawn.toLocaleString()} more on them ${earlierDrawn === 1 ? 'was' : 'were'} already open when it began.` : ''
  const rest = total - drawn
  return { heading, meta, drawnNote: rest > 0 ? `The other ${n(rest, 'incident')} open in it ${rest === 1 ? 'is' : 'are'} on objects not drawn.` : null }
}

/** A DOM id for a row, so a lead can bring its row into view. */
export function rowDomId(key: string): string {
  return `tl-row-${key.replace(/[^A-Za-z0-9_-]/g, '_')}`
}

/** A tooltip line is a glance, not the finding: about two lines at the
 *  bubble's width, then an ellipsis. The full text is one select away. */
const TIP_LINE_CHARS = 140

export function clampTipLine(line: string): { text: string; cut: boolean } {
  const flat = line.replace(/\s+/g, ' ').trim()
  if (flat.length <= TIP_LINE_CHARS) return { text: flat, cut: false }
  const head = flat.slice(0, TIP_LINE_CHARS)
  const atSpace = head.lastIndexOf(' ')
  return { text: `${(atSpace > TIP_LINE_CHARS * 0.6 ? head.slice(0, atSpace) : head).trimEnd()}…`, cut: true }
}
