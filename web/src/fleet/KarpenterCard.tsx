import { SplitBar } from '../components/SplitBar'
import { useInspect } from './useInspect'

// Karpenter capacity (PROJECT.md PG7), on a cluster whose agent has
// Karpenter's NodePools synced: each pool's limit against what it has
// provisioned, its NodeClaims by phase, and the pending demand no pool can
// take. A quantity Karpenter does not report is "—", never zero.

interface Ledger {
  pool: string
  limitCpu?: string
  limitMemory?: string
  provisionedCpu?: string
  provisionedMemory?: string
  nodes?: number
  claims: Record<string, number>
}
interface Demand {
  example: string
  pods: number
  verdicts: { pool: string; fits: boolean; reason?: string }[]
}
interface Capacity {
  pools: Ledger[]
  demand: Demand[]
}

const NO_ARGS = {}
const PHASES = ['Pending', 'Launched', 'Registered', 'Initialized', 'Ready', 'Terminating'] as const
const PHASE_TONE: Record<string, 'critical' | 'high' | 'medium' | 'ok' | 'info' | 'unknown'> = {
  Pending: 'medium',
  Launched: 'info',
  Registered: 'info',
  Initialized: 'info',
  Ready: 'ok',
  Terminating: 'unknown',
}

export function KarpenterCard({ clusterId }: { clusterId: string }) {
  const { query } = useInspect<Capacity>(clusterId, 'get_karpenter_capacity', NO_ARGS)
  const r = query.data?.result
  if (!r || r.pools.length === 0) return null
  const stuck = r.demand.filter((d) => !d.verdicts.some((v) => v.fits))
  return (
    <section className="card card-compact" aria-label="Karpenter capacity">
      <div className="card-head">
        <h3>Karpenter</h3>
        <span className="card-head-meta">
          {r.pools.length} NodePool{r.pools.length === 1 ? '' : 's'}
          {stuck.length > 0 ? ` · ${stuck.reduce((n, d) => n + d.pods, 0)} pending pods no pool can take` : ''}
        </span>
      </div>
      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th>Pool</th>
              <th className="num">CPU provisioned / limit</th>
              <th className="num">Memory provisioned / limit</th>
              <th>NodeClaims</th>
            </tr>
          </thead>
          <tbody>
            {r.pools.map((p) => (
              <tr key={p.pool}>
                <td className="fleet-mono">{p.pool}</td>
                <td className="num">
                  {p.provisionedCpu ?? '—'} / {p.limitCpu ?? 'no limit'}
                </td>
                <td className="num">
                  {p.provisionedMemory ?? '—'} / {p.limitMemory ?? 'no limit'}
                </td>
                <td>
                  <SplitBar
                    label={`${p.pool} NodeClaims by phase`}
                    parts={PHASES.map((ph) => ({ tone: PHASE_TONE[ph], value: p.claims[ph] ?? 0, label: ph.toLowerCase() }))}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {stuck.length > 0 && (
        <ul className="insight-plain-list" aria-label="Pending pods no pool can take">
          {stuck.map((d) => (
            <li key={d.example}>
              <span className="fleet-mono">{d.example}</span>
              {d.pods > 1 ? ` and ${d.pods - 1} like it` : ''} —{' '}
              <span className="field-hint">{d.verdicts.map((v) => `${v.pool}: ${v.reason}`).join('; ')}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
