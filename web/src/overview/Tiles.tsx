import { Link } from 'react-router-dom'
import type { IncidentOverview } from '../api/types'
import {
  ESCALATION_HOURS,
  formatWait,
  gaugeTone,
  hexGrid,
  hexPath,
  openSeries,
  stageOf,
  STAGES,
  WAIT_AXIS_HOURS,
  windowChange,
  type FleetCapacity,
  type FleetNode,
  type QueueRow,
  type StageKey,
} from './model'

// The four tiles across the top of the Overview. Each carries its own graphic,
// and each graphic is drawn from a figure that is printed beside it, so nothing
// is read from shape or colour alone.

const pct = (r: number) => `${Math.round(r * 100)}%`

function Sparkline({ values, label }: { values: number[]; label: string }) {
  if (values.length < 2) return null
  const w = 120
  const h = 40
  const max = Math.max(...values)
  const min = Math.min(...values)
  const x = (i: number) => (i * w) / (values.length - 1)
  const y = (v: number) => h - 3 - ((v - min) / (max - min || 1)) * (h - 8)
  const pts = values.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`)
  return (
    <svg className="ov-spark" viewBox={`0 0 ${w} ${h}`} role="img" aria-label={label}>
      <path className="ov-spark-area" d={`M0,${h} L${pts.join(' L')} L${w},${h} Z`} />
      <path className="ov-spark-line" d={`M${pts.join(' L')}`} />
      <circle className="ov-spark-dot" cx={w} cy={y(values[values.length - 1])} r="2.6" />
    </svg>
  )
}

function Unavailable({ reason }: { reason: string }) {
  return <span className="ov-tile-value ov-tile-value-muted" title={reason}>—</span>
}

// The stage key's words are the design's short ones; STAGES keeps the longer
// reader-facing labels for the accessible description.
const STAGE_SHORT: Record<StageKey, string> = {
  notInvestigated: 'not investigated',
  investigating: 'investigating',
  yourMove: 'your move',
  decision: 'decision',
  inFlight: 'in flight',
  watching: 'watching',
  didNotHold: 'did not hold',
}

function StageBar({ byState }: { byState: IncidentOverview['byState'] }) {
  const counts = new Map<StageKey, number>()
  for (const { state, count } of byState) counts.set(stageOf(state), (counts.get(stageOf(state)) ?? 0) + count)
  const stages = STAGES.map((s) => ({ ...s, n: counts.get(s.key) ?? 0 }))
  return (
    <>
      <span className="ov-stagebar" role="img" aria-label={`Open incidents by where they are in the loop: ${stages.map((s) => `${s.n} ${s.label}`).join(', ')}`}>
        {stages.filter((s) => s.n > 0).map((s) => (
          <span key={s.key} className={`ov-stage-${s.key}`} style={{ flex: s.n }} />
        ))}
      </span>
      <span className="ov-stage-key" aria-hidden="true">
        {stages.map((s) => (
          <span key={s.key} className={`ov-stage-${s.key}`}>
            <i />
            <b>{s.n}</b>
            {STAGE_SHORT[s.key]}
          </span>
        ))}
      </span>
    </>
  )
}

export function OpenIncidentsTile({
  open,
  overview,
  days,
}: {
  open: number | undefined
  overview: IncidentOverview | undefined
  days: number
}) {
  const change = overview ? windowChange(overview.daily) : null
  return (
    <Link className="ov-tile" to="/incidents">
      <span className="ov-tile-label">
        Open incidents
        {change !== null && (
          <span className={change > 0 ? 'ov-tile-change ov-state-warn' : 'ov-tile-change'}>
            {change === 0 ? 'no change' : `${change > 0 ? '▲' : '▼'} ${Math.abs(change)}`} in {days} d
          </span>
        )}
      </span>
      <span className="ov-tile-row">
        {open == null ? <Unavailable reason="The incident counts could not be loaded." /> : <span className="ov-tile-value">{open}</span>}
        {overview && <Sparkline values={openSeries(overview.daily)} label={`Open incidents at the end of each of the last ${days} days`} />}
      </span>
      {overview ? <StageBar byState={overview.byState} /> : <span className="ov-tile-note">Where they are in the loop could not be loaded.</span>}
    </Link>
  )
}

export function WaitingTile({
  requiresAction,
  decisions,
  rows,
  oldestHours,
  oldestComplete,
}: {
  /** Open incidents whose next move is a person's, whole set (decisions included). */
  requiresAction: number | undefined
  /** Open incidents waiting on a decision (AwaitingApproval), whole set. */
  decisions: number | undefined
  /** The fetched rows, to draw one dot each. */
  rows: QueueRow[]
  oldestHours: number | null
  /** The fetched rows are the whole set, so their oldest is the oldest. */
  oldestComplete: boolean
}) {
  const dotted = rows.filter((r) => r.kind !== 'cluster' && r.hours !== null)
  const shown = dotted.length
  const total = requiresAction ?? 0
  // The hub's requiresAction includes the decisions; the design prints the
  // two apart ("6, +3 waiting on a decision"), so the figure is the rest.
  const yours = requiresAction == null ? null : Math.max(0, requiresAction - (decisions ?? 0))
  return (
    <Link className="ov-tile" to="/incidents?status=requiresAction">
      <span className="ov-tile-label">
        Your move
        {decisions != null && decisions > 0 && <span className="ov-tile-change ov-state-muted">+{decisions} waiting on a decision</span>}
      </span>
      <span className="ov-tile-row">
        {yours == null ? (
          <Unavailable reason="The incident counts could not be loaded." />
        ) : (
          <span className={yours > 0 ? 'ov-tile-value ov-tile-value-warn' : 'ov-tile-value'}>{yours}</span>
        )}
      </span>
      <span
        className="ov-waits"
        role="img"
        aria-label={`${shown} waiting items by age${shown < total ? ` (the ${shown} worst of ${total})` : ''}; marks at 48 hours and 5 days`}
      >
        <span className="ov-waits-axis" />
        {ESCALATION_HOURS.map((h) => (
          <span key={h} className="ov-waits-tick" style={{ left: `${(h / WAIT_AXIS_HOURS) * 100}%` }}>
            <span>{h === 48 ? '48 h' : '5 d'}</span>
          </span>
        ))}
        {dotted.map((r) => (
          <span
            key={r.key}
            className={r.kind === 'decision' ? 'ov-waits-dot ov-waits-dot-decision' : 'ov-waits-dot'}
            style={{ left: `${(Math.min(r.hours ?? 0, WAIT_AXIS_HOURS) / WAIT_AXIS_HOURS) * 100}%` }}
            title={`${r.kind === 'decision' ? 'waiting on a decision' : 'your move'}, ${formatWait(r.hours)}`}
          />
        ))}
      </span>
      <span className="ov-stage-key">
        <span><i className="ov-key-dot" aria-hidden="true" />your move</span>
        <span><i className="ov-key-ring" aria-hidden="true" />waiting on a decision</span>
        {oldestHours !== null && (
          <span>
            {oldestComplete ? 'oldest' : 'oldest drawn'} <b>{formatWait(oldestHours)}</b>
          </span>
        )}
        {shown < total && <span>{shown} of {total} drawn</span>}
      </span>
    </Link>
  )
}

// The design's fixed 20 columns: a fleet's nodes read as one field of cells
// at a constant size, whatever the count, rather than a few huge hexagons.
const NODE_COLS = 20
const NODE_R = 6.2
const MAX_HEXES = NODE_COLS * 8

export function NodesTile({ nodes, missingFacts, staleNames }: { nodes: FleetNode[] | null; missingFacts: number; staleNames: string[] }) {
  if (nodes === null) {
    return (
      <div className="ov-tile">
        <span className="ov-tile-label">Nodes ready</span>
        <span className="ov-tile-note">Loading each cluster's last report…</span>
      </div>
    )
  }
  const ready = nodes.filter((n) => n.ready).length
  const notReady = nodes.length - ready
  // Eight rows of hexagons at most. Past that the ones that need a look —
  // NotReady, then last readings — are drawn first, so a cap never hides one.
  const ordered = nodes.length > MAX_HEXES ? [...nodes].sort((a, b) => Number(a.ready) - Number(b.ready) || Number(b.stale) - Number(a.stale)) : nodes
  const drawn = ordered.slice(0, MAX_HEXES)
  const grid = hexGrid(drawn.length, NODE_COLS, NODE_R)
  const sub =
    nodes.length > MAX_HEXES
      ? `${drawn.length} of ${nodes.length} drawn${notReady ? ', every NotReady among them' : ''}`
      : missingFacts > 0
      ? `nodes not available for ${missingFacts} cluster${missingFacts === 1 ? '' : 's'}`
      : staleNames.length > 0
        ? `grey: ${staleNames.join(', ')}, last reading`
        : 'one hexagon per node'
  return (
    <Link className="ov-tile" to="/clusters">
      <span className="ov-tile-label">
        Nodes ready
        {notReady > 0 && <span className="ov-tile-change ov-tile-change-bad">{notReady} NotReady</span>}
      </span>
      <span className="ov-tile-row">
        {nodes.length === 0 ? (
          <Unavailable reason="No cluster has reported its nodes." />
        ) : (
          <span className="ov-tile-value">
            {ready}
            <small>/{nodes.length}</small>
          </span>
        )}
      </span>
      {nodes.length > 0 && (
        <svg
          className="ov-mini-honey"
          viewBox={`0 0 ${(NODE_COLS * Math.sqrt(3) * NODE_R + 2).toFixed(0)} ${(grid.height + 2).toFixed(0)}`}
          role="img"
          aria-label={`${nodes.length} nodes: ${ready} ready, ${notReady} NotReady`}
        >
          {drawn.map((n, i) => {
            const cx = grid.cells[i].cx + 1
            const cy = grid.cells[i].cy + 1
            return (
              <g key={`${n.clusterId}/${n.name}`}>
                <path className={n.ready ? (n.stale ? 'ov-hex-stale' : 'ov-hex-ready') : 'ov-hex-bad'} d={hexPath(cx, cy, NODE_R - 0.6)}>
                  <title>{`${n.name}: ${n.ready ? 'Ready' : 'NotReady'}${n.stale ? ' (last reading)' : ''}`}</title>
                </path>
                {!n.ready && <path className="ov-hex-x" d={`M${cx - 2.5},${cy - 2.5}L${cx + 2.5},${cy + 2.5}M${cx + 2.5},${cy - 2.5}L${cx - 2.5},${cy + 2.5}`} />}
              </g>
            )
          })}
        </svg>
      )}
      <span className="ov-tile-note">{sub}</span>
    </Link>
  )
}

function Gauge({ ratio, label }: { ratio: number | null; label: string }) {
  const r = 44
  const len = Math.PI * r
  return (
    <svg className="ov-gauge" viewBox="0 0 110 64" role="img" aria-label={ratio === null ? `${label}: not measured` : `${label}: ${pct(ratio)} used`}>
      <path className="ov-gauge-track" d="M11,56 A44,44 0 0 1 99,56" />
      {ratio !== null && (
        <path className={`ov-gauge-arc ov-gauge-${gaugeTone(ratio)}`} d="M11,56 A44,44 0 0 1 99,56" strokeDasharray={`${len * Math.min(ratio, 1)} ${len}`} />
      )}
      <text x="55" y="52" textAnchor="middle" className="ov-gauge-value">{ratio === null ? '—' : pct(ratio)}</text>
      <text x="55" y="63" textAnchor="middle" className="ov-gauge-label">{label}</text>
    </svg>
  )
}

export function CapacityTile({ capacity }: { capacity: FleetCapacity | null }) {
  return (
    <div className="ov-tile">
      <span className="ov-tile-label">
        Fleet capacity
        {capacity && capacity.clustersWithFacts > 0 && (
          <span
            className="ov-tile-change ov-state-muted"
            title="CPU and memory used against allocatable, summed over every node that reported both. A cluster without metrics-server reports no usage and is left out, not counted as idle."
          >
            {capacity.measuredClusters} of {capacity.clustersWithFacts} measured
          </span>
        )}
      </span>
      {capacity === null ? (
        <span className="ov-tile-note">Loading each cluster's last report…</span>
      ) : (
        <>
          <span className="ov-gauges">
            <Gauge ratio={capacity.cpu.ratio} label="CPU" />
            <Gauge ratio={capacity.memory.ratio} label="Memory" />
          </span>
          <span className="ov-tile-note">
            {capacity.hottest ? (
              <>
                highest: <span className="mono">{capacity.hottest.name}</span> memory {pct(capacity.hottest.memory)}
              </>
            ) : (
              'no cluster reports usage (metrics-server not installed)'
            )}
          </span>
        </>
      )}
    </div>
  )
}
