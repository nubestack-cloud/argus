import { useMemo } from 'react'
import { urlEnum, useUrlState } from '../hooks/useUrlState'
import { BarList, Segmented, SplitBar } from '../components/SplitBar'
import { InspectFrame, type ClusterLiveness } from './InspectFrame'
import { MetricsSourceLine } from './MetricsSourceLine'
import { RightsizingSection } from './RightsizingSection'
import { COST_BASIS_LABEL, costUnavailableReason, formatCost, type CostResult } from './costModel'
import { useInspect } from './useInspect'
import { TimeSeriesChart } from '../charts/TimeSeriesChart'

// Cluster detail → Cost (docs/CLUSTER_INSIGHT_SPECS.md CI-S14). Hourly spend
// per namespace from OpenCost's metrics in Prometheus. The currency is
// whatever OpenCost was configured with and is never converted or guessed, so
// no symbol is printed. Unavailable is a stated reason; an unmeasured figure
// is "—" — never $0.00 (argus-context lesson 9).

const SCHEMA = { cwin: urlEnum(['1', '6', '24'] as const, '1') }

function Money({ v }: { v: number | null | undefined }) {
  if (v === null || v === undefined) {
    return (
      <span className="quantity quantity-unknown">
        — <span className="visually-hidden">not measured</span>
      </span>
    )
  }
  return <span className="quantity">{formatCost(v)}</span>
}

function Percent({ v }: { v: number | null | undefined }) {
  if (v === null || v === undefined) {
    return (
      <span className="quantity quantity-unknown">
        — <span className="visually-hidden">not measured</span>
      </span>
    )
  }
  return <span className="quantity">{v.toLocaleString(undefined, { maximumFractionDigits: 1 })}%</span>
}

/** A namespace's cost split into what is used and what is requested but
 *  idle; null parts are unmeasured and not drawn. */
function nsParts(n: { hourlyCost?: number | null; idleCost?: number | null }) {
  const idle = n.idleCost ?? 0
  const used = Math.max(0, (n.hourlyCost ?? 0) - idle)
  return [
    { tone: 'accent' as const, value: Math.round(used * 100) / 100, label: 'used' },
    { tone: 'unknown' as const, value: Math.round(idle * 100) / 100, label: 'requested but idle' },
  ]
}

export function CostPanel({ clusterId, liveness }: { clusterId: string; liveness: ClusterLiveness }) {
  const [state, setState] = useUrlState(SCHEMA)
  const args = useMemo(() => ({ windowHours: Number(state.cwin) }), [state.cwin])
  const { query, capabilityResolved, missing } = useInspect<CostResult>(clusterId, 'get_cost_summary', args)
  return (
    <section aria-label="Cost">
      <InspectFrame label="Cost" help="Hourly cost per namespace exactly as OpenCost or Kubecost reports it, in that tool's own currency and list prices — not your bill. ARGUS prices nothing itself, so without one of them there is no figure. Idle is cost requested but not used." query={query} capabilityResolved={capabilityResolved} missing={missing} liveness={liveness} skeletonColumns={7}>
        {(result) => {
          const s = result?.summary
          if (!s || !s.available) {
            const notConfigured = s?.reason === 'not_configured' || (s?.reason === 'no_metrics' && /no Prometheus is configured/i.test(s?.detail ?? ''))
            return (
              <MetricsSourceLine what="Cost" notConfigured={notConfigured} reason={costUnavailableReason(s, result?.detectedPrometheus)} detected={result?.detectedPrometheus} />
            )
          }
          const rows = s.namespaces ?? []
          const idleShare = s.totalHourlyCost && s.totalUnusedRequestCost != null ? (s.totalUnusedRequestCost * 100) / s.totalHourlyCost : null
          const cpu = rows.reduce((n, r) => n + (r.cpuCost ?? 0), 0)
          const mem = rows.reduce((n, r) => n + (r.memoryCost ?? 0), 0)
          return (
            <>
              <div className="cost-tiles">
                <div className="card card-compact">
                  <div className="metric-tile-label">Cluster, per hour</div>
                  <div className="metric-tile-value">
                    <Money v={s.totalHourlyCost} />
                  </div>
                  <span className="text-muted cost-tile-note">
                    last {state.cwin === '1' ? 'hour' : `${state.cwin} hours`}
                    {s.hourlyCostBasis ? ` · ${COST_BASIS_LABEL[s.hourlyCostBasis] ?? s.hourlyCostBasis}` : ''}
                  </span>
                </div>
                <div className="card card-compact">
                  <div className="metric-tile-label">Idle (requested, unused)</div>
                  <div className="metric-tile-value">
                    <Percent v={idleShare} />
                  </div>
                  {idleShare != null && (
                    <SplitBar
                      legend={false}
                      label="Cluster cost"
                      parts={[
                        { tone: 'accent', value: Math.round(100 - idleShare), label: '% used' },
                        { tone: 'unknown', value: Math.round(idleShare), label: '% idle' },
                      ]}
                    />
                  )}
                </div>
                <div className="card card-compact">
                  <div className="metric-tile-label">CPU vs memory</div>
                  {cpu + mem > 0 ? (
                    <SplitBar
                      tall
                      label="Namespace cost by resource"
                      parts={[
                        { tone: 'info', value: Math.round((cpu * 100) / (cpu + mem)), label: '% CPU' },
                        { tone: 'ok', value: Math.round((mem * 100) / (cpu + mem)), label: '% memory' },
                      ]}
                    />
                  ) : (
                    <span className="text-muted">— not measured</span>
                  )}
                </div>
              </div>
              {(s.trend ?? []).length > 1 && (
                <TimeSeriesChart
                  title="Cluster spend per hour, last 7 days"
                  unit="currency"
                  series={[
                    {
                      labels: { source: s.source === 'kubecost' ? 'Kubecost' : 'OpenCost' },
                      dataPoints: (s.trend ?? []).map((p) => ({ timestamp: Date.parse(p.time) / 1000, value: p.hourlyCost })),
                    },
                  ]}
                  stepSeconds={21600}
                />
              )}
              <p className="text-muted cost-totals">
                {s.source === 'kubecost' ? 'From Kubecost · ' : ''}
                Allocated <Money v={s.totalAllocatedCost} /> · storage <Money v={s.totalStorageCost} /> · unrequested node capacity{' '}
                <Money v={s.totalUnallocatedCost} /> · efficiency <Percent v={s.clusterEfficiency} />
                {(s.missing ?? []).length > 0 ? ` · not measured: ${(s.missing ?? []).join(', ')}` : ''}
              </p>
              {s.truncated && (
                <p className="truncation-notice" role="status">
                  Showing the {rows.length} most expensive of {s.totalNamespaces ?? 'more'} namespaces.
                </p>
              )}
              <div className="card">
                <div className="card-head">
                  <h3>By namespace</h3>
                  <span className="card-head-meta">per hour · used + idle</span>
                  <Segmented
                    label="Averaged over"
                    options={[
                      { id: '1', label: '1h' },
                      { id: '6', label: '6h' },
                      { id: '24', label: '24h' },
                    ]}
                    value={state.cwin}
                    onChange={(cwin) => setState({ cwin }, { push: true })}
                  />
                </div>
                {rows.length === 0 ? (
                  <p className="empty-state">OpenCost reported no namespace allocations in this window.</p>
                ) : (
                  <>
                    <BarList label="Cost per namespace" rows={rows.map((n) => ({ key: n.name, name: n.name, parts: nsParts(n) }))} />
                    <ul className="split-legend" aria-hidden="true">
                      <li>
                        <span className="split-swatch" data-tone="accent" /> used
                      </li>
                      <li>
                        <span className="split-swatch" data-tone="unknown" /> requested but idle
                      </li>
                    </ul>
                  </>
                )}
              </div>
              {rows.length > 0 && (
                <details className="cost-details">
                  <summary>Every figure per namespace</summary>
                  <div className="table-scroll">
                    <table className="cluster-table list-table">
                      <thead>
                        <tr>
                          <th>Namespace</th>
                          <th className="col-numeric">Per hour</th>
                          <th className="col-numeric">CPU</th>
                          <th className="col-numeric">Memory</th>
                          <th className="col-numeric">Storage</th>
                          <th className="col-numeric">Efficiency</th>
                          <th className="col-numeric">Idle</th>
                        </tr>
                      </thead>
                      <tbody>
                        {rows.map((n) => (
                          <tr key={n.name}>
                            <td className="fleet-mono">{n.name}</td>
                            <td className="col-numeric">
                              <Money v={n.hourlyCost} />
                            </td>
                            <td className="col-numeric">
                              <Money v={n.cpuCost} />
                            </td>
                            <td className="col-numeric">
                              <Money v={n.memoryCost} />
                            </td>
                            <td className="col-numeric">
                              <Money v={n.storageCost} />
                            </td>
                            <td className="col-numeric">
                              <Percent v={n.efficiency} />
                            </td>
                            <td className="col-numeric">
                              <Money v={n.idleCost} />
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </details>
              )}
            </>
          )
        }}
      </InspectFrame>
      <RightsizingSection clusterId={clusterId} liveness={liveness} />
    </section>
  )
}
