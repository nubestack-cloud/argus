// The fleet Overview's derivations: pure functions from API payloads to the
// figures and shapes the page draws. Kept apart from the components so every
// number on the page has a unit test, and so the page itself only arranges.
//
// Honesty rules applied throughout (reference/anti-patterns.md, Honesty):
// an absent figure is null and renders as "—", never 0; a figure computed over
// a subset says which subset; nothing here invents a value the payload does
// not carry.

import type { BarPart, BarTone } from '../components/SplitBar'
import type {
  ApprovalQueueItem,
  AutomationWindow,
  Cluster,
  ClusterDetail,
  FleetCertificatesSummary,
  GitOpsAppList,
  HelmReleaseList,
  Incident,
  IncidentOverview,
  IncidentState,
  NodeStatus,
  UpgradeScan,
} from '../api/types'
import type { CertificatesResult } from '../fleet/certificatesModel'
import { CERT_DEGRADED_DAYS, CERT_UNHEALTHY_DAYS } from '../fleet/certificatesModel'
import type { PostureCounts, PostureResult } from '../fleet/postureModel'
import { POSTURE_CATEGORIES } from '../fleet/postureModel'
import { isHelmProblem } from '../fleet/helmModel'
import { parseCPUCores, parseMemoryBytes, usageBand, type UsageBand } from '../fleet/resourceUsage'
import { approvalWaitStartedAt, STATE_LABEL } from '../utils/incidents'

export type Severity = 'critical' | 'high' | 'medium' | 'low'
export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low']
const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 }

// ---------------------------------------------------------------------------
// Where the open incidents are in the loop
// ---------------------------------------------------------------------------

export type StageKey = 'notInvestigated' | 'investigating' | 'yourMove' | 'decision' | 'inFlight' | 'watching' | 'didNotHold'

// Seven stages over every OPEN state. The words are STATE_LABEL's reader-facing
// ones where a stage is one state, and the stage's own name where it folds
// several. The split follows internal/orchestrator's dispositions: a stage is
// either all "requires action" or all "in progress", never a mix, so "your
// move" stages here add up to the hub's requiresAction count.
export const STAGES: readonly { key: StageKey; label: string; tone: BarTone; states: readonly IncidentState[]; yours: boolean }[] = [
  { key: 'notInvestigated', label: 'not investigated', tone: 'neutral', states: ['Detected'], yours: true },
  { key: 'investigating', label: 'investigating', tone: 'info', states: ['Investigating'], yours: false },
  { key: 'yourMove', label: 'your move', tone: 'high', states: ['RecommendationReady', 'NeedsHumanInvestigation', 'Diagnosed', 'PlanRejected'], yours: true },
  { key: 'decision', label: 'waiting on a decision', tone: 'medium', states: ['AwaitingApproval'], yours: true },
  { key: 'inFlight', label: 'in flight', tone: 'accent', states: ['Executing', 'AwaitingMerge'], yours: false },
  { key: 'watching', label: 'watching', tone: 'ok', states: ['Validating'], yours: false },
  { key: 'didNotHold', label: 'fix did not hold', tone: 'critical', states: ['Failed', 'ExecutionUnknown', 'ValidationUnknown', 'Reopened'], yours: true },
]

const STAGE_OF = new Map<string, StageKey>(STAGES.flatMap((s) => s.states.map((st) => [st, s.key] as const)))

/** The stage an open state belongs to. An unrecognised state lands in "your
 *  move", matching the hub's own fallback (orchestrator.DispositionOf treats
 *  an unclassified state as requiring action rather than hiding it). */
export function stageOf(state: string): StageKey {
  return STAGE_OF.get(state) ?? 'yourMove'
}

/** Every stage as a bar part, zeros included, in loop order. */
export function stageParts(byState: IncidentOverview['byState']): BarPart[] {
  const counts = new Map<StageKey, number>()
  for (const { state, count } of byState) {
    const k = stageOf(state)
    counts.set(k, (counts.get(k) ?? 0) + count)
  }
  return STAGES.map((s) => ({ tone: s.tone, value: counts.get(s.key) ?? 0, label: s.label }))
}

/** Open incidents by severity, summed over the per-cluster rows. */
export function severityTotals(byCluster: IncidentOverview['byCluster']): Record<Severity, number> {
  const t: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const c of byCluster) for (const s of SEVERITIES) t[s] += c[s]
  return t
}

/** The open-incident count at the end of each day, oldest first. */
export function openSeries(daily: IncidentOverview['daily']): number[] {
  return daily.map((d) => d.openAtEnd)
}

/** How much the open count moved across the window; null below two points. */
export function windowChange(daily: IncidentOverview['daily']): number | null {
  if (daily.length < 2) return null
  return daily[daily.length - 1].openAtEnd - daily[0].openAtEnd
}

// ---------------------------------------------------------------------------
// What is waiting on a person
// ---------------------------------------------------------------------------

// The points at which internal/orchestrator's ApprovalSweeper re-notifies about a
// pending approval. Drawn as ticks so the page and the e-mails agree about when
// a wait has gone on too long.
export const ESCALATION_HOURS = [48, 120] as const
/** The wait axis runs to the second escalation; anything older pins at its end. */
export const WAIT_AXIS_HOURS = 120

export type QueueKind = 'incident' | 'decision' | 'cluster'

export interface QueueRow {
  key: string
  kind: QueueKind
  /** null for a silent cluster, which has no severity of its own. */
  severity: Severity | null
  title: string
  context: string
  /** Whose move and what it is, in the reader's words. */
  status: string
  /** When the wait being measured began, and what that wait is. */
  since: string | null
  sinceMeaning: 'plan' | 'opened' | 'heartbeat'
  hours: number | null
  href: string
}

function hoursSince(iso: string | null | undefined, nowMs: number): number | null {
  if (!iso) return null
  const t = new Date(iso).getTime()
  if (Number.isNaN(t)) return null
  return Math.max(0, (nowMs - t) / 3_600_000)
}

function kindOf(gvk: string | undefined): string {
  if (!gvk) return ''
  const parts = gvk.split('/')
  return parts[parts.length - 1]
}

/**
 * The rows of "Waiting on a person": incidents that require action, with an
 * approval's own plan time when the incident is waiting on a decision (the wait
 * that ApprovalSweeper escalates on), and clusters that stopped reporting.
 *
 * Ordered by severity and then by how long each has waited. A silent cluster
 * sorts between critical and high: it has no severity, but every figure on the
 * page is blind to it until it reports again.
 */
export function queueRows(
  queue: readonly Incident[],
  approvals: readonly ApprovalQueueItem[],
  silentClusters: readonly Cluster[],
  nowMs: number,
): QueueRow[] {
  const planAt = new Map<string, string>()
  for (const a of approvals) {
    if (a.alreadyApproved) continue
    const at = approvalWaitStartedAt(a)
    if (at) planAt.set(a.incidentId, at)
  }
  const rows: QueueRow[] = queue.map((i) => {
    const decision = i.state === 'AwaitingApproval'
    const since = decision ? planAt.get(i.id) ?? null : i.firstSeen
    const kind = kindOf(i.objectGvk)
    return {
      key: i.id,
      kind: decision ? 'decision' : 'incident',
      severity: i.severity,
      title: i.objectName || i.openingReason || i.id,
      context: [kind, i.clusterDisplayName, i.objectNamespace, i.objectName && i.openingReason ? i.openingReason : '']
        .filter(Boolean)
        .join(' · '),
      status: STATE_LABEL[i.state] ?? i.state,
      since,
      sinceMeaning: decision ? 'plan' : 'opened',
      hours: hoursSince(since, nowMs),
      href: `/incidents/${encodeURIComponent(i.id)}`,
    }
  })
  for (const c of silentClusters) {
    rows.push({
      key: `cluster:${c.id}`,
      kind: 'cluster',
      severity: null,
      title: c.displayName,
      context: c.lastHeartbeatAt ? 'agent not reporting' : 'no heartbeat recorded',
      status: 'Not reporting',
      since: c.lastHeartbeatAt,
      sinceMeaning: 'heartbeat',
      hours: hoursSince(c.lastHeartbeatAt, nowMs),
      href: `/clusters/${encodeURIComponent(c.id)}`,
    })
  }
  const rank = (r: QueueRow) => (r.severity ? SEVERITY_RANK[r.severity] : 3.5)
  return rows.sort((a, b) => rank(b) - rank(a) || (b.hours ?? -1) - (a.hours ?? -1))
}

/** How long the oldest pending decision has waited, from its plan's own time. */
export function oldestDecisionHours(approvals: readonly ApprovalQueueItem[], nowMs: number): number | null {
  let worst: number | null = null
  for (const a of approvals) {
    if (a.alreadyApproved) continue
    const h = hoursSince(approvalWaitStartedAt(a), nowMs)
    if (h !== null && (worst === null || h > worst)) worst = h
  }
  return worst
}

/** "41 m", "6 h", "2 d 4 h": short enough for a tile, exact enough to compare. */
export function formatWait(hours: number | null): string {
  if (hours === null) return '—'
  if (hours < 1) return `${Math.max(1, Math.round(hours * 60))} m`
  if (hours < 48) return `${Math.floor(hours)} h`
  const d = Math.floor(hours / 24)
  const h = Math.floor(hours - d * 24)
  return h ? `${d} d ${h} h` : `${d} d`
}

// ---------------------------------------------------------------------------
// Nodes and capacity, from each cluster's last facts
// ---------------------------------------------------------------------------

export interface FleetNode {
  clusterId: string
  name: string
  ready: boolean
  /** used / allocatable, or null where the cluster has no metrics-server. */
  cpu: number | null
  memory: number | null
  /** The cluster is not Active, so this is its last reading. */
  stale: boolean
}

function ratio(used: number | null, capacity: number | null): number | null {
  return used === null || capacity === null || capacity <= 0 ? null : used / capacity
}

export function nodeRatios(n: NodeStatus): { cpu: number | null; memory: number | null } {
  return {
    cpu: ratio(parseCPUCores(n.cpuUsed), parseCPUCores(n.cpuAllocatable)),
    memory: ratio(parseMemoryBytes(n.memoryUsed), parseMemoryBytes(n.memoryAllocatable)),
  }
}

export function clusterNodes(detail: ClusterDetail): FleetNode[] {
  const stale = detail.state !== 'Active' && detail.state !== 'Degraded'
  return (detail.facts?.nodes ?? []).map((n) => ({ clusterId: detail.id, name: n.name, ready: n.ready, stale, ...nodeRatios(n) }))
}

export interface UsageTotal {
  /** used / allocatable over the nodes that reported both, or null. */
  ratio: number | null
  reportingNodes: number
  totalNodes: number
}

export interface FleetCapacity {
  cpu: UsageTotal
  memory: UsageTotal
  /** Clusters with at least one node reporting usage, of those with facts. */
  measuredClusters: number
  clustersWithFacts: number
  /** The cluster with the highest memory use, for the tile's one-line callout. */
  hottest: { clusterId: string; name: string; memory: number } | null
}

function sumUsage(nodes: readonly NodeStatus[], parse: (q?: string) => number | null, pick: (n: NodeStatus) => [string | undefined, string | undefined]) {
  let used = 0
  let cap = 0
  let reporting = 0
  for (const n of nodes) {
    const [u, c] = pick(n)
    const pu = parse(u)
    const pc = parse(c)
    if (pu === null || pc === null || pc <= 0) continue
    used += pu
    cap += pc
    reporting += 1
  }
  return { used, cap, reporting }
}

export function fleetCapacity(details: readonly ClusterDetail[]): FleetCapacity {
  const all: NodeStatus[] = []
  let measured = 0
  let withFacts = 0
  let hottest: FleetCapacity['hottest'] = null
  for (const d of details) {
    const nodes = d.facts?.nodes
    if (!d.facts) continue
    withFacts += 1
    all.push(...(nodes ?? []))
    const mem = sumUsage(nodes ?? [], parseMemoryBytes, (n) => [n.memoryUsed, n.memoryAllocatable])
    if (mem.reporting > 0) {
      measured += 1
      const r = mem.used / mem.cap
      if (!hottest || r > hottest.memory) hottest = { clusterId: d.id, name: d.displayName, memory: r }
    }
  }
  const cpu = sumUsage(all, parseCPUCores, (n) => [n.cpuUsed, n.cpuAllocatable])
  const mem = sumUsage(all, parseMemoryBytes, (n) => [n.memoryUsed, n.memoryAllocatable])
  return {
    cpu: { ratio: cpu.reporting ? cpu.used / cpu.cap : null, reportingNodes: cpu.reporting, totalNodes: all.length },
    memory: { ratio: mem.reporting ? mem.used / mem.cap : null, reportingNodes: mem.reporting, totalNodes: all.length },
    measuredClusters: measured,
    clustersWithFacts: withFacts,
    hottest,
  }
}

export function bandOf(r: number | null): UsageBand | null {
  return r === null ? null : usageBand(r)
}

// ---------------------------------------------------------------------------
// Upgrade ladder
// ---------------------------------------------------------------------------

/** "v1.29.8+rke2r1" → "1.29"; null when the string carries no major.minor. */
export function minorVersion(v: string | null | undefined): string | null {
  const m = /(\d+)\.(\d+)/.exec(v ?? '')
  return m ? `${Number(m[1])}.${Number(m[2])}` : null
}

function compareMinor(a: string, b: string): number {
  const [am, an] = a.split('.').map(Number)
  const [bm, bn] = b.split('.').map(Number)
  return am - bm || an - bn
}

export interface LadderRow {
  clusterId: string
  name: string
  /** The minor version the cluster runs, from its facts or, failing that, its scan. */
  current: string | null
  target: string | null
  verdict: string | null
  scannedAt: string | null
}

export function upgradeLadder(
  clusters: readonly Cluster[],
  details: ReadonlyMap<string, ClusterDetail>,
  scans: ReadonlyMap<string, UpgradeScan>,
): { columns: string[]; rows: LadderRow[] } {
  const rows: LadderRow[] = clusters.map((c) => {
    const scan = scans.get(c.id)
    const current = minorVersion(details.get(c.id)?.facts?.kubernetesVersion) ?? minorVersion(scan?.currentVersion)
    return {
      clusterId: c.id,
      name: c.displayName,
      current,
      target: scan ? minorVersion(scan.targetVersion) : null,
      verdict: scan?.verdict ?? null,
      scannedAt: scan?.scannedAt ?? null,
    }
  })
  const cols = new Set<string>()
  for (const r of rows) {
    if (r.current) cols.add(r.current)
    if (r.target) cols.add(r.target)
  }
  return { columns: [...cols].sort(compareMinor), rows }
}

// ---------------------------------------------------------------------------
// Coming due: certificates and automation windows over the next 90 days
// ---------------------------------------------------------------------------

export const RUNWAY_DAYS = 90

export interface CertPin {
  name: string
  namespace: string
  /** Whole days left; 0 or less is expired. */
  days: number
  severity: Severity
}

/** certexpiry's thresholds: under 7 days (or expired) critical, under 30 high. */
export function certSeverity(daysLeft: number): Severity {
  return daysLeft < CERT_UNHEALTHY_DAYS ? 'critical' : daysLeft < CERT_DEGRADED_DAYS ? 'high' : 'low'
}

/** The pins of the hub's stored certificate summary, soonest first. */
export function pinsFromSummary(s: FleetCertificatesSummary): CertPin[] {
  return s.due
    .map((c) => ({ name: c.name, namespace: c.namespace, days: c.daysLeft, severity: certSeverity(c.daysLeft) }))
    .sort((a, b) => a.days - b.days)
}

/** Certificates expiring inside the runway, soonest first, with the counts the
 *  lane needs to stay honest about what it did not draw. */
export function certificatePins(result: CertificatesResult | undefined | null): { pins: CertPin[]; unknown: number; later: number } {
  const pins: CertPin[] = []
  let unknown = 0
  let later = 0
  for (const c of result?.certificates ?? []) {
    if (typeof c.daysLeft !== 'number') {
      unknown += 1
      continue
    }
    if (c.daysLeft > RUNWAY_DAYS) {
      later += 1
      continue
    }
    pins.push({ name: c.name, namespace: c.namespace, days: Math.floor(c.daysLeft), severity: certSeverity(c.daysLeft) })
  }
  pins.sort((a, b) => a.days - b.days)
  return { pins, unknown, later }
}

export interface PinGroup {
  /** The soonest expiry in the group. */
  days: number
  severity: Severity
  pins: CertPin[]
}

/** Pins expiring within `gapDays` of each other share one pill, so several
 *  certificates renewed together read as one mark with a count. */
export function groupPins(pins: readonly CertPin[], gapDays = 2): PinGroup[] {
  const groups: PinGroup[] = []
  for (const p of [...pins].sort((a, b) => a.days - b.days)) {
    const g = groups[groups.length - 1]
    if (g && p.days - g.pins[g.pins.length - 1].days <= gapDays) {
      g.pins.push(p)
      if (SEVERITY_RANK[p.severity] > SEVERITY_RANK[g.severity]) g.severity = p.severity
    } else {
      groups.push({ days: p.days, severity: p.severity, pins: [p] })
    }
  }
  return groups
}

export interface WindowSpan {
  key: string
  kind: 'freeze' | 'maintenance'
  /** Offset and width as fractions of the runway, clamped to it. */
  start: number
  width: number
  startAt: string
  endAt: string
  reason: string
}

export function windowSpans(windows: readonly AutomationWindow[], nowMs: number): WindowSpan[] {
  const horizon = RUNWAY_DAYS * 86_400_000
  const out: WindowSpan[] = []
  for (const w of windows) {
    for (const o of w.upcoming ?? []) {
      const s = new Date(o.start).getTime()
      const e = new Date(o.end).getTime()
      if (Number.isNaN(s) || Number.isNaN(e) || e <= nowMs || s >= nowMs + horizon) continue
      const from = Math.max(0, (s - nowMs) / horizon)
      const to = Math.min(1, (e - nowMs) / horizon)
      out.push({ key: `${w.id}:${o.start}`, kind: w.kind, start: from, width: Math.max(to - from, 0.004), startAt: o.start, endAt: o.end, reason: w.reason ?? '' })
    }
  }
  return out.sort((a, b) => a.start - b.start)
}

// ---------------------------------------------------------------------------
// Posture and delivery
// ---------------------------------------------------------------------------

export type PostureCategory = (typeof POSTURE_CATEGORIES)[number]

/** Danger/warning/passing per category, or null when the agent's answer has no
 *  per-category summary (an older agent) — never zeros standing in for it. */
export function postureByCategory(result: PostureResult | undefined | null): Record<PostureCategory, PostureCounts> | null {
  const cats = result?.summary?.categories
  if (!cats) return null
  const out = {} as Record<PostureCategory, PostureCounts>
  for (const c of POSTURE_CATEGORIES) out[c] = cats[c] ?? { danger: 0, warning: 0, passing: 0 }
  return out
}

export interface DeliveryMarks {
  /** One entry per release/app the agent listed: true when it is failing. */
  helm: boolean[] | null
  helmTotal: number | null
  helmTruncated: boolean
  gitops: boolean[] | null
  gitopsTotal: number | null
  gitopsTruncated: boolean
}

export function deliveryMarks(helm: HelmReleaseList | undefined | null, gitops: GitOpsAppList | undefined | null): DeliveryMarks {
  const helmRows = helm?.releases ?? null
  const apps = gitops?.apps ?? null
  return {
    helm: helmRows ? helmRows.map(isHelmProblem) : null,
    helmTotal: helm ? helm.total : null,
    helmTruncated: !!helm?.truncated,
    gitops: apps ? apps.map((a) => !!a.problem) : null,
    gitopsTotal: gitops ? gitops.counts.total : null,
    gitopsTruncated: !!gitops && (apps?.length ?? 0) < gitops.counts.total,
  }
}

// ---------------------------------------------------------------------------
// Hexagons
// ---------------------------------------------------------------------------

/** A pointy-top hexagon's path, centred on (cx, cy). */
export function hexPath(cx: number, cy: number, r: number): string {
  let d = ''
  for (let i = 0; i < 6; i++) {
    const a = (Math.PI / 180) * (60 * i - 30)
    d += `${i ? 'L' : 'M'}${(cx + r * Math.cos(a)).toFixed(2)},${(cy + r * Math.sin(a)).toFixed(2)}`
  }
  return `${d}Z`
}

/** Offset-row honeycomb positions for `count` cells, `cols` per row. */
export function hexGrid(count: number, cols: number, r: number): { cells: { cx: number; cy: number }[]; width: number; height: number } {
  const w = Math.sqrt(3) * r
  const h = 1.5 * r
  const cells = Array.from({ length: count }, (_, i) => {
    const row = Math.floor(i / cols)
    const col = i % cols
    return { cx: w / 2 + col * w + (row % 2 ? w / 2 : 0), cy: r + row * h }
  })
  const rows = Math.max(1, Math.ceil(count / cols))
  return { cells, width: cols * w + (rows > 1 ? w / 2 : 0), height: rows * h + r / 2 }
}

// ---------------------------------------------------------------------------
// Capacity bands (the B2 design's own four, not resourceUsage's 50/75/90)
// ---------------------------------------------------------------------------

export type CapacityBand = 'low' | 'mid' | 'high' | 'critical'

export const CAPACITY_BANDS: readonly { band: CapacityBand; label: string }[] = [
  { band: 'low', label: 'under 50%' },
  { band: 'mid', label: '50–80%' },
  { band: 'high', label: '80–90%' },
  { band: 'critical', label: '90% and over' },
]

export function capacityBand(r: number): CapacityBand {
  return r >= 0.9 ? 'critical' : r >= 0.8 ? 'high' : r >= 0.5 ? 'mid' : 'low'
}

/** A gauge arc is the accent until 80%, then high, then critical from 90%. */
export function gaugeTone(r: number): 'accent' | 'high' | 'critical' {
  return r >= 0.9 ? 'critical' : r >= 0.8 ? 'high' : 'accent'
}

// ---------------------------------------------------------------------------
// Fleet scale
// ---------------------------------------------------------------------------

/** The most rows any fleet card draws before it summarises the rest in one
 *  line and links to the full list — the design's own size, and what keeps
 *  each band about a screen tall at 200 clusters. */
export const CARD_ROWS = 8

/** Split ranked rows into the ones drawn and the rest the card summarises. */
export function capRows<T>(rows: readonly T[], cap = CARD_ROWS): { shown: T[]; rest: T[] } {
  return { shown: rows.slice(0, cap), rest: rows.slice(cap) }
}
