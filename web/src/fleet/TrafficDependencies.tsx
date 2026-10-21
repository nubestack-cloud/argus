import { endpointLabel, type TrafficFlow } from './trafficModel'
import { agoWords, changeWords, errorWords, flowsAround, formatAmount, type Measure, type Neighbour } from './trafficLevels'

// One workload's traffic: who calls it, it, what it calls. Every line carries
// its figure now, the change against the earlier window when one was read,
// and 5xx where measured — in words, so nothing rests on colour or on a
// line's thickness. Used by an incident's Traffic tab.

function Row({ n, m, comparison, max, onPick }: { n: Neighbour; m: Measure; comparison: boolean; max: number; onPick?: (ns: string, name: string) => void }) {
  const err = errorWords(n.flow)
  const change = changeWords(n.now, n.before)
  const isNew = comparison && !n.flow.stopped && n.flow.before == null
  const label = n.peer.namespace ? endpointLabel(n.peer) : `${n.peer.name} (node or outside)`
  const body = (
    <>
      <span className="tdeps-name fleet-mono">{label}</span>
      <span className="tdeps-figure tabular">{n.flow.stopped ? 'none now' : n.now != null ? formatAmount(n.now, m) : '—'}</span>
      <span className="tdeps-tags">
        {n.flow.stopped && <span className="badge badge-red">stopped</span>}
        {n.problem && err && <span className="badge badge-red">{err}</span>}
        {isNew && <span className="badge badge-gray">new</span>}
        {change && !n.flow.stopped && (
          <span className={`badge ${n.before != null && n.now != null && n.now <= n.before / 2 ? 'badge-amber' : 'badge-gray'}`}>{change}</span>
        )}
        {n.flow.directionUnknown && <span className="text-muted">direction unknown</span>}
      </span>
      <span className="resource-usage-track tdeps-bar" aria-hidden="true">
        <span className="coverage-fill" style={{ width: `${max > 0 ? Math.max(2, (100 * Math.max(n.now ?? 0, 0)) / max) : 0}%` }} />
      </span>
    </>
  )
  return (
    <li className={n.problem || n.flow.stopped ? 'tdeps-row fleet-row-problem' : 'tdeps-row'}>
      {onPick && n.peer.namespace ? (
        <button type="button" className="tdeps-pick" onClick={() => onPick(n.peer.namespace!, n.peer.name)} title={`Show ${n.peer.name}'s traffic`}>
          {body}
        </button>
      ) : (
        <div className="tdeps-pick">{body}</div>
      )}
    </li>
  )
}

function Side({ title, rows, m, comparison, max, onPick, limit }: { title: string; rows: Neighbour[]; m: Measure; comparison: boolean; max: number; onPick?: (ns: string, name: string) => void; limit: number }) {
  return (
    <section className="tdeps-side" aria-label={title}>
      <h4>
        {title} <span className="text-muted">({rows.length})</span>
      </h4>
      {rows.length === 0 ? (
        <p className="field-hint">None measured.</p>
      ) : (
        <ul>
          {rows.slice(0, limit).map((n) => (
            <Row key={`${n.peer.kind}:${endpointLabel(n.peer)}:${n.flow.port}:${n.flow.directionUnknown ? 'u' : 'd'}`} n={n} m={m} comparison={comparison} max={max} onPick={onPick} />
          ))}
          {rows.length > limit && <li className="field-hint">and {rows.length - limit} more in the flow table</li>}
        </ul>
      )}
    </section>
  )
}

export function TrafficDependencies({
  flows,
  namespace,
  name,
  comparisonSeconds,
  comparison,
  onPick,
  limit = 12,
  action,
}: {
  flows: readonly TrafficFlow[]
  namespace: string
  name: string
  comparisonSeconds?: number
  comparison: boolean
  onPick?: (ns: string, name: string) => void
  limit?: number
  action?: React.ReactNode
}) {
  const { callers, callees, measure } = flowsAround(flows, namespace, name)
  const max = Math.max(0, ...[...callers, ...callees].map((n) => n.now ?? 0))
  const sum = (rows: Neighbour[], k: 'now' | 'before') => rows.reduce<number | null>((s, n) => (n[k] == null ? s : (s ?? 0) + (n[k] as number)), null)
  const inNow = sum(callers, 'now')
  const outNow = sum(callees, 'now')
  const line = (v: number | null, b: number | null) => {
    if (v == null) return '—'
    const c = comparison ? changeWords(v, b) : null
    return `${formatAmount(v, measure)}${c ? ` · ${c} vs ${agoWords(comparisonSeconds)}` : ''}`
  }
  return (
    <div className="tdeps">
      <Side title={`Calls into ${name}`} rows={callers} m={measure} comparison={comparison} max={max} onPick={onPick} limit={limit} />
      <div className="tdeps-focus">
        <span className="eyebrow">{namespace}</span>
        <strong className="fleet-mono">{name}</strong>
        <dl className="kv-list">
          <dt>In</dt>
          <dd className="tabular">{line(inNow, sum(callers, 'before'))}</dd>
          <dt>Out</dt>
          <dd className="tabular">{line(outNow, sum(callees, 'before'))}</dd>
        </dl>
        {action}
      </div>
      <Side title={`${name} calls`} rows={callees} m={measure} comparison={comparison} max={max} onPick={onPick} limit={limit} />
    </div>
  )
}
