import { useId, useState } from 'react'
import type { MouseEvent, ReactNode } from 'react'
import { Link } from 'react-router-dom'
import type { Cluster, ClusterDetail } from '../api/types'
import { toVerdict } from '../components/VerdictBadge'
import { readInsightFacts } from '../fleet/clusterSummary'
import { POSTURE_CATEGORIES } from '../fleet/postureModel'
import { classifyDetectorStatus } from '../utils/detectors'
import { formatRelativeTime } from '../utils/time'
import {
  CAPACITY_BANDS,
  capacityBand,
  capRows,
  CARD_ROWS,
  clusterNodes,
  hexGrid,
  hexPath,
  type CapacityBand,
  type FleetNode,
  type LadderRow,
} from './model'
import { rungOf, RUNG_WORD, type Rung } from './summaries'
import type { CheckStatus, FleetChecks } from './useFleetData'

// Standing: debt with no due date, one shape per concern. Each card draws at
// most CARD_ROWS rows, worst first, and sums the rest in one line with a link
// to the full list — the same rule on every card, so 200 clusters cost the
// page no more height than eight.

const tab = (id: string, name: string) => `/clusters/${encodeURIComponent(id)}?tab=${name}`

/** A cell's answer while a stored check has nothing to show: one short
 *  phrase, the reason on hover — every row of a disconnected fleet repeating a
 *  sentence turns the card into a paragraph. */
function checkPending(s: CheckStatus<unknown>, missing: string): ReactNode {
  if (s.kind === 'unread') return 'Not read yet'
  if (s.kind === 'unreadable') return `Needs ${missing}`
  if (s.kind === 'error') return <span title={s.error}>— could not read</span>
  return null
}

/** "as of 2 h ago" on a row whose latest read failed after a good one. */
function staleNote(s: CheckStatus<unknown>): { text: string; title: string } | null {
  if (s.kind !== 'ok' || !s.failedSince) return null
  return { text: `as of ${formatRelativeTime(s.at)}`, title: `The latest read failed: ${s.failure}` }
}

/** The one line under a capped card: how many more, and what they add up to. */
function RestLine({ count, children, to }: { count: number; children?: ReactNode; to: string }) {
  if (count <= 0) return null
  return (
    <p className="ov-rest">
      + {count} more cluster{count === 1 ? '' : 's'}
      {children}
      {' · '}
      <Link to={to}>show all</Link>
    </p>
  )
}

// ---------------------------------------------------------------------------
// Upgrade ladder
// ---------------------------------------------------------------------------

interface LadderLine {
  key: string
  name: string
  title?: string
  href: string
  current: string | null
  target: string | null
  rung: Rung
  scannedAt: string | null
  count: number
}

const RUNG_ORDER: Record<Rung, number> = { blocked: 0, review: 1, ready: 2, none: 3 }

export function UpgradeLadder({ columns, rows }: { columns: string[]; rows: LadderRow[] }) {
  if (rows.length === 0) return <p className="ov-card-note">No cluster is reporting.</p>
  const n = Math.max(columns.length, 1)
  const at = (v: string) => `${((columns.indexOf(v) + 0.5) / n) * 100}%`
  const order = (l: LadderLine) => (l.target ? RUNG_ORDER[l.rung] : 4)
  const perCluster: LadderLine[] = rows.map((r) => ({
    key: r.clusterId,
    name: r.name,
    href: tab(r.clusterId, 'upgrade'),
    current: r.current,
    target: r.target,
    rung: r.target ? rungOf(toVerdict(r.verdict)) : 'none',
    scannedAt: r.scannedAt,
    count: 1,
  }))
  // Past a card's worth of clusters, one row per version path instead: a
  // fleet sits on a handful of versions, so 200 clusters become a few rows
  // ("1.29 → 1.30 · Blocked · 12 clusters") without dropping any of them.
  let lines = perCluster
  if (rows.length > CARD_ROWS) {
    const cohorts = new Map<string, LadderLine & { names: string[] }>()
    for (const l of perCluster) {
      const k = `${l.current}|${l.target}|${l.target ? l.rung : 'unscanned'}`
      const c = cohorts.get(k)
      if (c) {
        c.count += 1
        c.names.push(l.name)
      } else cohorts.set(k, { ...l, key: k, names: [l.name] })
    }
    lines = [...cohorts.values()].map((c) => ({
      ...c,
      name: c.count === 1 ? c.names[0] : `${c.count} clusters`,
      title: c.count === 1 ? undefined : c.names.slice(0, 30).join(', ') + (c.count > 30 ? ` +${c.count - 30} more` : ''),
      href: c.count === 1 ? c.href : '/clusters',
      scannedAt: c.count === 1 ? c.scannedAt : null,
    }))
  }
  const sorted = [...lines].sort((a, b) => order(a) - order(b) || b.count - a.count || a.name.localeCompare(b.name))
  const { shown, rest } = capRows(sorted)
  return (
    <>
      <div className="ov-ladder">
        <span />
        <div className="ov-ladder-head" style={{ gridTemplateColumns: `repeat(${n}, 1fr)` }}>
          {columns.map((c) => <span key={c}>{c}</span>)}
        </div>
        {shown.map((l) => {
          const who = l.count === 1 ? l.name : `${l.count} clusters`
          const describe = l.current
            ? `${who} run${l.count === 1 ? 's' : ''} ${l.current}${l.target ? `; upgrade to ${l.target}: ${RUNG_WORD[l.rung]}` : '; not scanned'}`
            : `${who}: version not reported`
          return (
            <Link key={l.key} className="ov-ladder-row" to={l.href} aria-label={describe} title={l.title}>
              <span className={l.count === 1 ? 'ov-ladder-name' : 'ov-ladder-name ov-ladder-cohort'}>{l.name}</span>
              <span className={`ov-ladder-track ov-ladder-${l.rung}`} style={{ backgroundSize: `${100 / n}% 100%` }}>
                {l.current && l.target && l.target !== l.current && (
                  <span className="ov-ladder-arrow" style={{ left: at(l.current), width: `calc(${at(l.target)} - ${at(l.current)})` }} />
                )}
                {l.current && <span className="ov-ladder-from" style={{ left: at(l.current) }} title={`runs ${l.current}`} />}
                {l.target && (
                  <span className="ov-ladder-to" style={{ left: at(l.target) }}>
                    <span className={`ov-verd ov-verd-${l.rung}`}>{RUNG_WORD[l.rung]}</span>
                  </span>
                )}
                {!l.target && (
                  <span className="ov-ladder-note" style={{ left: l.current ? `calc(${at(l.current)} + 12px)` : '0' }}>
                    {l.current ? 'Not scanned' : 'Version not reported'}
                  </span>
                )}
                {l.target && l.scannedAt && <span className="visually-hidden">scanned {formatRelativeTime(l.scannedAt)}</span>}
              </span>
            </Link>
          )
        })}
      </div>
      {rest.length > 0 && (
        <p className="ov-rest">
          + {rest.length} more version path{rest.length === 1 ? '' : 's'} ({rest.reduce((n, l) => n + l.count, 0)} clusters) · <Link to="/clusters">show all</Link>
        </p>
      )}
      <div className="ov-legend ov-legend-row" aria-hidden="true">
        <span><span className="ov-ladder-key" />runs today</span>
        <span>arrow ends at the scanned target, with the verdict</span>
      </div>
    </>
  )
}

// ---------------------------------------------------------------------------
// Posture
// ---------------------------------------------------------------------------

export function PostureHeatmap({
  clusters,
  checks,
  details,
  missing,
}: {
  clusters: Cluster[]
  checks: FleetChecks
  details: Map<string, ClusterDetail>
  missing: string
}) {
  const all = clusters.map((c) => {
    const status = checks.posture(c.id)
    const cats = status.kind === 'ok' ? status.summary.categories : null
    const danger = cats ? POSTURE_CATEGORIES.reduce((n, k) => n + (cats[k]?.danger ?? 0), 0) : -1
    const warning = cats ? POSTURE_CATEGORIES.reduce((n, k) => n + (cats[k]?.warning ?? 0), 0) : 0
    return { c, status, cats, danger, warning }
  })
  all.sort((a, b) => b.danger - a.danger || b.warning - a.warning || a.c.displayName.localeCompare(b.c.displayName))
  // Within a card's worth, every cluster is a row, pending ones included.
  // Past it, rows are the worst clusters that answered; the rest — answered
  // or not — are counted in the line beneath.
  const ranked = all.length > CARD_ROWS ? all.filter((r) => r.cats) : all
  const { shown } = capRows(ranked)
  const shownIds = new Set(shown.map((r) => r.c.id))
  const rest = all.filter((r) => !shownIds.has(r.c.id))
  const restRead = rest.filter((r) => r.cats)
  const restOther = rest.length - restRead.length
  const max = Math.max(1, ...shown.flatMap((r) => (r.cats ? POSTURE_CATEGORIES.map((k) => r.cats![k]?.danger ?? 0) : [])))
  return (
    <>
      <div className="ov-scroll">
        <table className="data-table ov-heat">
          <thead>
            <tr>
              <th scope="col">Cluster</th>
              {POSTURE_CATEGORIES.map((k) => <th key={k} scope="col">{k}</th>)}
              <th scope="col">NetworkPolicy</th>
            </tr>
          </thead>
          <tbody>
            {shown.map(({ c, status, cats }) => {
              const np = readInsightFacts(details.get(c.id)?.facts).summary?.networkPolicyCoverage
              const share = np && np.totalWorkloads > 0 ? np.coveredWorkloads / np.totalWorkloads : null
              const stale = staleNote(status)
              return (
                <tr key={c.id}>
                  <th scope="row">
                    <Link to={tab(c.id, 'posture')} title={stale?.title}>{c.displayName}</Link>
                    {stale && <small className="ov-stale">{stale.text}</small>}
                  </th>
                  {cats
                    ? POSTURE_CATEGORIES.map((k) => {
                        const v = cats[k] ?? { danger: 0, warning: 0, passing: 0 }
                        // Intensity steps with the danger count; the count is printed in the
                        // cell, so the tint only repeats it.
                        const step = v.danger === 0 ? 0 : Math.min(4, Math.ceil((v.danger / max) * 4))
                        return (
                          <td key={k} className={`ov-heat-cell ov-heat-${step}`} title={`${k}: ${v.danger} danger, ${v.warning} warning, ${v.passing} passing`}>
                            <strong>{v.danger}</strong>
                            <span>{v.warning} warn</span>
                          </td>
                        )
                      })
                    : (
                      <td colSpan={POSTURE_CATEGORIES.length} className="ov-heat-pending">
                        {checkPending(status, missing)}
                      </td>
                    )}
                  <td className="ov-heat-np">
                    {share === null ? (
                      <span className="text-muted">—</span>
                    ) : (
                      <span className="ov-meter" title={`${np!.coveredWorkloads} of ${np!.totalWorkloads} workloads selected by a NetworkPolicy`}>
                        <span className="ov-meter-track"><span className="ov-meter-fill" style={{ width: `${share * 100}%` }} /></span>
                        <strong>{Math.round(share * 100)}%</strong>
                      </span>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      <RestLine count={rest.length} to="/clusters">
        {restRead.length > 0 &&
          ` · ${restRead.reduce((n, r) => n + r.danger, 0)} danger · ${restRead.reduce((n, r) => n + r.warning, 0)} warning`}
        {restOther > 0 && ` · ${restOther} not read`}
      </RestLine>
    </>
  )
}

// ---------------------------------------------------------------------------
// Capacity
// ---------------------------------------------------------------------------

export type CapacityMetric = 'memory' | 'cpu'

/** The Memory | CPU switch, which the design puts in the card's header. */
export function MetricSwitch({ value, onChange }: { value: CapacityMetric; onChange: (m: CapacityMetric) => void }) {
  return (
    <div className="segmented ov-honey-switch" role="group" aria-label="Colour nodes by">
      <button type="button" aria-pressed={value === 'memory'} onClick={() => onChange('memory')}>Memory</button>
      <button type="button" aria-pressed={value === 'cpu'} onClick={() => onChange('cpu')}>CPU</button>
    </div>
  )
}

const HEX_R = 9.5
const fmtPct = (v: number | null) => (v === null ? 'not measured' : `${Math.round(v * 100)}%`)

type Tip = { x: number; y: number; node: FleetNode; cluster: string }

export function CapacityHoneycomb({ clusters, details, metric }: { clusters: Cluster[]; details: Map<string, ClusterDetail>; metric: CapacityMetric }) {
  const hatchId = `ov-hatch-${useId().replace(/[^a-zA-Z0-9_-]/g, '')}`
  const [tip, setTip] = useState<Tip | null>(null)
  const meanOf = (nodes: FleetNode[]) => {
    const v = nodes.map((n) => n[metric]).filter((x): x is number => x !== null)
    return v.length ? v.reduce((a, x) => a + x, 0) / v.length : null
  }
  const all = clusters
    .map((c) => ({ c, d: details.get(c.id) }))
    .filter((g): g is { c: Cluster; d: ClusterDetail } => !!g.d?.facts)
    .map(({ c, d }) => {
      const nodes = clusterNodes(d)
      return { c, nodes, mean: meanOf(nodes) }
    })
  // Past a card's worth, the hottest clusters on the chosen metric are drawn
  // node by node and every node of the fleet is still counted by band below.
  const ranked = all.length > CARD_ROWS ? [...all].sort((a, b) => (b.mean ?? -1) - (a.mean ?? -1) || a.c.displayName.localeCompare(b.c.displayName)) : all
  const { shown: groups, rest } = capRows(ranked)
  const fleetBands = new Map<CapacityBand | 'unmeasured', number>()
  let notReady = 0
  let fleetNodes = 0
  for (const g of all)
    for (const n of g.nodes) {
      const v = n[metric]
      const k = v === null ? 'unmeasured' : capacityBand(v)
      fleetBands.set(k, (fleetBands.get(k) ?? 0) + 1)
      if (!n.ready) notReady += 1
      fleetNodes += 1
    }
  // A hover card with every figure for the node under the pointer; the
  // group's own line and its accessible label carry the same facts.
  const onMove = (e: MouseEvent<HTMLDivElement>) => {
    const el = (e.target as Element).closest('[data-node]')
    if (!el) return setTip(null)
    const [gi, ni] = (el.getAttribute('data-node') ?? '').split('/').map(Number)
    const g = groups[gi]
    if (!g?.nodes[ni]) return setTip(null)
    setTip({ x: Math.min(e.clientX + 14, window.innerWidth - 200), y: e.clientY + 14, node: g.nodes[ni], cluster: g.c.displayName })
  }
  return (
    <>
      {groups.length === 0 ? (
        <p className="ov-card-note">No cluster has reported its nodes.</p>
      ) : (
        <div className="ov-honey" onMouseMove={onMove} onMouseLeave={() => setTip(null)}>
          {groups.map(({ c, nodes, mean }, gi) => {
            const cols = Math.max(2, Math.ceil(Math.sqrt(nodes.length * 1.6)))
            const grid = hexGrid(nodes.length, cols, HEX_R)
            const w = cols * Math.sqrt(3) * HEX_R + (Math.sqrt(3) * HEX_R) / 2 + 3
            const h = grid.height + 3
            return (
              <Link key={c.id} className={nodes[0]?.stale ? 'ov-honey-group ov-ring-dim' : 'ov-honey-group'} to={`/clusters/${encodeURIComponent(c.id)}`}>
                <span className="ov-honey-name">{c.displayName}</span>
                <svg
                  width={w.toFixed(0)}
                  height={h.toFixed(0)}
                  viewBox={`0 0 ${w.toFixed(1)} ${h.toFixed(1)}`}
                  role="img"
                  aria-label={`${c.displayName}: ${nodes.length} nodes, ${metric === 'cpu' ? 'CPU' : 'memory'} ${mean === null ? 'not measured' : `${Math.round(mean * 100)}% on average`}`}
                >
                  <defs>
                    <pattern id={`${hatchId}-${gi}`} width="4" height="4" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
                      <rect width="4" height="4" className="ov-hatch-ground" />
                      <rect width="1.5" height="4" className="ov-hatch-line" />
                    </pattern>
                  </defs>
                  {nodes.map((n, i) => {
                    const cx = grid.cells[i].cx + 1.5
                    const cy = grid.cells[i].cy + 1.5
                    const v = n[metric]
                    return (
                      <g key={n.name}>
                        <path
                          className={v === null ? 'ov-hex' : `ov-hex ov-cap-${capacityBand(v)}`}
                          style={v === null ? { fill: `url(#${hatchId}-${gi})` } : undefined}
                          d={hexPath(cx, cy, HEX_R - 0.8)}
                          data-node={`${gi}/${i}`}
                        />
                        {!n.ready && <path className="ov-hex-x" d={`M${cx - 3.5},${cy - 3.5}L${cx + 3.5},${cy + 3.5}M${cx + 3.5},${cy - 3.5}L${cx - 3.5},${cy + 3.5}`} />}
                      </g>
                    )
                  })}
                </svg>
                <span className="ov-honey-sub">
                  {nodes.length} node{nodes.length === 1 ? '' : 's'} · {mean === null ? 'not measured' : `${Math.round(mean * 100)}%`}
                </span>
              </Link>
            )
          })}
        </div>
      )}
      {rest.length > 0 && (
        <p className="ov-rest">
          + {rest.length} more cluster{rest.length === 1 ? '' : 's'} · all {fleetNodes} nodes:{' '}
          {CAPACITY_BANDS.map((b) => `${fleetBands.get(b.band) ?? 0} ${b.label}`).join(' · ')}
          {fleetBands.get('unmeasured') ? ` · ${fleetBands.get('unmeasured')} not measured` : ''}
          {notReady ? ` · ${notReady} NotReady` : ''} · <Link to="/clusters">show all</Link>
        </p>
      )}
      <div className="ov-cap-legend" aria-hidden="true">
        {CAPACITY_BANDS.map((b) => (
          <span key={b.band}><i className={`ov-cap-${b.band}`} />{b.label}</span>
        ))}
        <span><i className="ov-cap-unmeasured" />not measured</span>
        <span>✕ NotReady</span>
      </div>
      {tip && (
        <div className="ov-tip" style={{ left: tip.x, top: tip.y }} aria-hidden="true">
          <b>{tip.node.name}</b>
          <br />
          {tip.cluster}
          <br />
          CPU {fmtPct(tip.node.cpu)} · memory {fmtPct(tip.node.memory)}
          <br />
          {tip.node.ready ? 'Ready' : <span className="ov-state-bad">NotReady</span>}
        </div>
      )}
    </>
  )
}

// ---------------------------------------------------------------------------
// Delivery and agents
// ---------------------------------------------------------------------------

// One square per listed release or app, the failing ones first, up to a
// row's worth; a cluster with hundreds says "+N" rather than wrapping on.
const MAX_SQUARES = 40

function Squares({ listed, bad, kind }: { listed: number; bad: number; kind: 'helm' | 'gitops' }) {
  const drawn = Math.min(listed, MAX_SQUARES)
  return (
    <>
      {Array.from({ length: drawn }, (_, i) => (
        <span key={i} className={i < bad ? 'ov-sq ov-sq-bad' : `ov-sq ov-sq-${kind}`} />
      ))}
      {listed > drawn && <span className="ov-sq-more">+{listed - drawn}</span>}
    </>
  )
}

const DETECTOR_WORD: Record<string, string> = { warningEvents: 'events', podConditions: 'pod', sweep: 'sweep' }

export function DeliveryAgents({
  clusters,
  liveIds,
  checks,
  details,
  missing,
}: {
  clusters: Cluster[]
  liveIds: Set<string>
  checks: FleetChecks
  details: Map<string, ClusterDetail>
  missing: string
}) {
  const current = clusters.filter((c) => c.compatibility.verdict === 'current')
  const outdated = clusters.filter((c) => c.compatibility.verdict === 'upgrade_recommended')
  const required = clusters.filter((c) => c.compatibility.verdict === 'upgrade_required')
  const unknown = clusters.length - current.length - outdated.length - required.length
  // A detector's own last report, never inferred from a quiet incident list.
  const failingDetectors = clusters.flatMap((c) => {
    const dets = details.get(c.id)?.facts?.detectors
    if (!dets) return []
    const bad = Object.entries(dets)
      .filter(([, s]) => {
        const level = classifyDetectorStatus(s)
        return level === 'error' || level === 'blocked'
      })
      .map(([k]) => DETECTOR_WORD[k] ?? k)
    return bad.length ? [{ c, bad }] : []
  })
  const { shown: detShown, rest: detRest } = capRows(failingDetectors, 3)
  const names = (cs: Cluster[]) => {
    const { shown, rest } = capRows(cs, 3)
    return shown.map((c) => c.displayName).join(', ') + (rest.length ? ` +${rest.length}` : '')
  }

  const rows = clusters
    .filter((c) => liveIds.has(c.id))
    .map((c) => {
      const h = checks.helm(c.id)
      const g = checks.gitops(c.id)
      const hs = h.kind === 'ok' ? h.summary : null
      const gs = g.kind === 'ok' ? g.summary : null
      const failing = (hs?.failing ?? 0) + (gs?.problems ?? 0)
      return { c, h, g, hs, gs, failing, read: !!(hs || gs) }
    })
  // Failing first, then the ones with nothing to show, then the healthy.
  rows.sort((a, b) => b.failing - a.failing || Number(b.read) - Number(a.read) || a.c.displayName.localeCompare(b.c.displayName))
  const ranked = rows.length > CARD_ROWS ? rows.filter((r) => r.read) : rows
  const { shown } = capRows(ranked)
  const shownIds = new Set(shown.map((r) => r.c.id))
  const rest = rows.filter((r) => !shownIds.has(r.c.id))
  const restFailing = rest.reduce((n, r) => n + r.failing, 0)
  const restOk = rest.filter((r) => r.read).reduce((n, r) => n + (r.hs?.total ?? 0) + (r.gs?.total ?? 0) - r.failing, 0)
  const restUnread = rest.filter((r) => !r.read).length

  return (
    <>
      {rows.length === 0 ? (
        <p className="ov-card-note">No cluster can answer a check right now.</p>
      ) : (
        <div className="ov-waffle">
          {shown.map(({ c, h, g, hs, gs, failing }) => {
            const pending = !hs && !gs ? checkPending(h.kind !== 'ok' ? h : g, missing) : null
            const stale = staleNote(h) ?? staleNote(g)
            return (
              <Link key={c.id} className="ov-waffle-row" to={tab(c.id, failing && (gs?.problems ?? 0) > 0 ? 'gitops' : 'helm')} title={stale?.title}>
                <span className="ov-waffle-name">{c.displayName}</span>
                {pending ? (
                  <span className="ov-lane-note">{pending}</span>
                ) : (
                  <span
                    className="ov-waffle-marks"
                    role="img"
                    aria-label={`${c.displayName}: ${hs ? `${hs.total} Helm releases, ${hs.failing} failing` : 'Helm releases not read'}; ${gs ? `${gs.total} GitOps apps, ${gs.problems} with a problem` : 'GitOps apps not read'}`}
                  >
                    {hs && <Squares listed={hs.listed} bad={hs.failing} kind="helm" />}
                    <span className="ov-waffle-gap" />
                    {gs && <Squares listed={gs.listed} bad={gs.problems} kind="gitops" />}
                  </span>
                )}
                <span className="ov-waffle-count">
                  {failing > 0 ? <span className="ov-state-bad">{failing} failing</span> : hs || gs ? `${(hs?.total ?? 0) + (gs?.total ?? 0)} ok` : ''}
                  {(hs?.truncated || gs?.truncated) && ' · partial'}
                  {stale && ` · ${stale.text}`}
                </span>
              </Link>
            )
          })}
        </div>
      )}
      <RestLine count={rest.length} to="/clusters">
        {restFailing > 0 ? <> · <span className="ov-state-bad">{restFailing} failing</span></> : ''}
        {restOk > 0 && ` · ${restOk} ok`}
        {restUnread > 0 && ` · ${restUnread} not read`}
      </RestLine>
      <div className="ov-legend ov-legend-row" aria-hidden="true">
        <span><span className="ov-legend-swatch ov-sq-helm" />Helm release</span>
        <span><span className="ov-legend-swatch ov-sq-gitops" />GitOps app</span>
        <span><span className="ov-legend-swatch ov-sq-bad" />failing / error (✕)</span>
      </div>
      <div className="ov-agents">
        <div>
          <div className="ov-agents-label">Agents · {clusters.length} cluster{clusters.length === 1 ? '' : 's'}</div>
          <span
            className="ov-agents-bar"
            role="img"
            aria-label={`${current.length} current, ${outdated.length} outdated, ${required.length} upgrade required, ${unknown} unknown`}
          >
            {current.length > 0 && <span className="sev-low" style={{ flex: current.length }} />}
            {outdated.length > 0 && <span className="sev-high" style={{ flex: outdated.length }} />}
            {required.length > 0 && <span className="sev-critical" style={{ flex: required.length }} />}
            {unknown > 0 && <span className="sev-neutral" style={{ flex: unknown }} />}
          </span>
        </div>
        <div className="ov-agents-text">
          <strong>{current.length}</strong> current
          {outdated.length > 0 && (
            <>
              {' · '}
              <span className="ov-state-warn">{outdated.length} outdated</span> <span className="mono">{names(outdated)}</span>
            </>
          )}
          {required.length > 0 && (
            <>
              {' · '}
              <span className="ov-state-bad">{required.length} upgrade required</span> <span className="mono">{names(required)}</span>
            </>
          )}
          {unknown > 0 && ` · ${unknown} unknown`}
          {detShown.map(({ c, bad }) => (
            <span key={c.id} className="ov-agents-line">
              <span className="ov-state-warn">{c.displayName}</span> {bad.join(' and ')} detector{bad.length === 1 ? '' : 's'} failing
            </span>
          ))}
          {detRest.length > 0 && (
            <span className="ov-agents-line" title={detRest.map((d) => `${d.c.displayName}: ${d.bad.join(', ')}`).join('\n')}>
              + {detRest.length} more cluster{detRest.length === 1 ? '' : 's'} with a detector failing
            </span>
          )}
        </div>
      </div>
    </>
  )
}
