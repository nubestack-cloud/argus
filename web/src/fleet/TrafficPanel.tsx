import { useMemo } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { GraphCanvas } from '../graph/GraphCanvas'
import type { GraphNode } from '../graph/types'
import { urlEnum, urlString, useUrlState } from '../hooks/useUrlState'
import { withObjectPanel } from '../insight/panelUrl'
import { SortIcon } from '../components/icons'
import { FilterChips, Segmented } from '../components/SplitBar'
import type { NamespaceTopology } from '../api/types'
import { InspectFrame, type ClusterLiveness } from './InspectFrame'
import { MetricsSourceLine } from './MetricsSourceLine'
import {
  GRAPH_FLOW_CAP,
  TRAFFIC_SOURCE_LABEL,
  buildTrafficGraph,
  busiestFlows,
  endpointLabel,
  errorPercent,
  flowId,
  formatBytesRate,
  formatRate,
  isProblemFlow,
  sortFlows,
  trafficUnavailableReason,
  type TrafficResult,
  type TrafficSortKey,
} from './trafficModel'
import { useInspect } from './useInspect'

// Cluster detail → Traffic (docs/CLUSTER_INSIGHT_SPECS.md CI-S13). Which
// workloads talk to which, from the mesh/eBPF metrics already in Prometheus.
// Every edge carries its rate and 5xx share in text; an edge with errors is
// also dashed, so a problem is never colour alone. The table under the graph
// is the same data, complete and sortable, for anyone who cannot use the
// canvas. Unavailable traffic states the agent's reason.

const WINDOWS = ['5', '15', '60'] as const
const NS_INDEX_ARGS = {}
const SCHEMA = {
  tns: urlString(''),
  twin: urlEnum(WINDOWS, '15'),
  tsort: urlEnum(['src', 'dst', 'requests', 'errors', 'bytes'] as const, 'requests'),
  tdir: urlEnum(['asc', 'desc'] as const, 'desc'),
}

function SortHeader({
  label,
  k,
  active,
  dir,
  onSort,
  className,
}: {
  label: string
  k: TrafficSortKey
  active: TrafficSortKey
  dir: 'asc' | 'desc'
  onSort: (k: TrafficSortKey) => void
  className?: string
}) {
  const isActive = k === active
  return (
    <th className={className} aria-sort={isActive ? (dir === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button type="button" className="cluster-sort-button" onClick={() => onSort(k)}>
        {label}
        {isActive && <SortIcon direction={dir} />}
      </button>
    </th>
  )
}

export function TrafficPanel({ clusterId, liveness }: { clusterId: string; liveness: ClusterLiveness }) {
  const [state, setState] = useUrlState(SCHEMA)
  const [params, setParams] = useSearchParams()
  const navigate = useNavigate()
  const args = useMemo(
    () => ({ ...(state.tns ? { namespace: state.tns } : {}), windowMinutes: Number(state.twin) }),
    [state.tns, state.twin],
  )
  const { query, capabilityResolved, missing } = useInspect<TrafficResult>(clusterId, 'get_traffic', args)
  // The namespace list is the Map tab's index read (same query key), asked
  // for only once traffic is known to be available.
  const available = !!query.data?.result?.available
  const index = useInspect<NamespaceTopology>(clusterId, 'get_namespace_topology', NS_INDEX_ARGS, available)
  const namespaces = (index.query.data?.result?.namespaces ?? []).map((n) => n.name).sort()
  const onSort = (k: TrafficSortKey) => {
    if (k === state.tsort) setState({ tdir: state.tdir === 'asc' ? 'desc' : 'asc' })
    else setState({ tsort: k, tdir: k === 'src' || k === 'dst' ? 'asc' : 'desc' })
  }
  const openNode = (n: GraphNode) => {
    // A Pod or Service opens in the inspector. A "Workload" is a metrics
    // label, not a kind — guessing Deployment would be inventing a fact — so
    // it goes to object search, which finds whatever kind carries that name.
    // An external peer has nothing to open.
    if (n.kind === 'Pod' || n.kind === 'Service') {
      setParams(withObjectPanel(params, { clusterId, kind: n.kind, namespace: n.namespace, name: n.name }))
    } else if (n.kind !== 'External') {
      navigate(`/search?q=${encodeURIComponent(`${n.namespace ? `ns:${n.namespace} ` : ''}${n.name}`)}`)
    }
  }

  return (
    <section aria-label="Traffic">
      <InspectFrame label="Traffic" help="Which workloads talk to which, from service-mesh or eBPF metrics already in this cluster’s Prometheus, over the chosen window. Each edge carries its request rate and 5xx share. Unavailable when no supported metrics source is installed." query={query} capabilityResolved={capabilityResolved} missing={missing} liveness={liveness} skeletonColumns={5}>
        {(result) => {
          if (!result?.available) {
            const notConfigured = result?.reasonCode === 'not_configured' || /no Prometheus is configured/i.test(result?.reason ?? '')
            return <MetricsSourceLine what="Traffic" notConfigured={notConfigured} reason={trafficUnavailableReason(result)} detected={result?.detectedPrometheus} />
          }
          const flows = result.flows ?? []
          const graphFlows = busiestFlows(flows)
          const graph = buildTrafficGraph(graphFlows)
          const sorted = sortFlows(flows, state.tsort, state.tdir)
          return (
            <>
              <div className="panel-toolbar">
                <label className="visually-hidden" htmlFor="traffic-ns">
                  Namespace
                </label>
                <select id="traffic-ns" className="compact-select" value={state.tns} onChange={(e) => setState({ tns: e.target.value }, { push: true })}>
                  <option value="">All namespaces</option>
                  {(namespaces.includes(state.tns) || !state.tns ? namespaces : [state.tns, ...namespaces]).map((n) => (
                    <option key={n} value={n}>
                      {n}
                    </option>
                  ))}
                </select>
                <Segmented
                  label="Window"
                  options={[
                    { id: '5', label: '5m' },
                    { id: '15', label: '15m' },
                    { id: '60', label: '1h' },
                  ]}
                  value={state.twin}
                  onChange={(twin) => setState({ twin }, { push: true })}
                />
                <FilterChips<'requests' | 'errors'>
                  label="Order"
                  options={[
                    { id: 'requests', label: 'Busiest first' },
                    { id: 'errors', label: 'Errors first' },
                  ]}
                  value={state.tsort === 'errors' ? 'errors' : 'requests'}
                  onChange={(k) => setState({ tsort: k, tdir: 'desc' }, { push: true })}
                />
                <span className="panel-toolbar-meta">edge width = requests/s · dashed = 5xx errors</span>
              </div>
              <p className="text-muted fleet-count-line">
                From {TRAFFIC_SOURCE_LABEL[result.source ?? ''] ?? result.source ?? 'an unnamed source'}, averaged over{' '}
                {result.windowSeconds ? `${Math.round(result.windowSeconds / 60)} minutes` : `${state.twin} minutes`}
                {state.tns ? `, namespace ${state.tns}` : ''}. {flows.length} {flows.length === 1 ? 'flow' : 'flows'}
                {result.truncated ? ` of ${result.totalFlows ?? 'more'} (the agent caps the list)` : ''}.
              </p>
              {(result.missing ?? []).length > 0 && (
                <p className="fleet-scope-note" role="note">
                  Not measured: {(result.missing ?? []).join('; ')}.
                </p>
              )}
              {(result.notes ?? []).map((n) => (
                <p key={n} className="text-muted fleet-count-line">
                  {n}
                </p>
              ))}
              {flows.length === 0 ? (
                <p className="empty-state">
                  {state.tns
                    ? `No traffic was measured in namespace ${state.tns} in this window. Clear the namespace to see the whole cluster.`
                    : 'No traffic was measured in this window.'}
                </p>
              ) : (
                <>
                  {flows.length > GRAPH_FLOW_CAP && (
                    <p className="truncation-notice" role="status">
                      The graph draws the {GRAPH_FLOW_CAP} busiest flows; the table below lists all {flows.length}.
                    </p>
                  )}
                  <GraphCanvas
                    nodes={graph.nodes}
                    edges={graph.edges}
                    edgeLabels={graph.edgeLabels}
                    problemEdges={graph.problemEdges}
                    edgeWidths={graph.edgeWidths}
                    grouping="namespace"
                    height="auto"
                    onOpen={openNode}
                    label={`Traffic between workloads on this cluster, ${graph.edges.length} flows`}
                  />
                  <div className="table-scroll fleet-table-gap">
                    <table className="cluster-table list-table">
                      <caption className="visually-hidden">Traffic flows, sortable</caption>
                      <thead>
                        <tr>
                          <SortHeader label="Source" k="src" active={state.tsort} dir={state.tdir} onSort={onSort} />
                          <SortHeader label="Destination" k="dst" active={state.tsort} dir={state.tdir} onSort={onSort} />
                          <th className="col-shrink">Port</th>
                          <SortHeader label="Requests/s" k="requests" active={state.tsort} dir={state.tdir} onSort={onSort} className="col-numeric" />
                          <SortHeader label="5xx" k="errors" active={state.tsort} dir={state.tdir} onSort={onSort} className="col-numeric" />
                          <SortHeader label="Bytes/s" k="bytes" active={state.tsort} dir={state.tdir} onSort={onSort} className="col-numeric" />
                        </tr>
                      </thead>
                      <tbody>
                        {sorted.map((f) => {
                          const pct = errorPercent(f)
                          return (
                            <tr key={flowId(f)} className={isProblemFlow(f) ? 'fleet-row-problem' : undefined}>
                              <td className="fleet-mono">
                                {endpointLabel(f.src)} <span className="text-muted">{f.src.kind}</span>
                              </td>
                              <td className="fleet-mono">
                                {endpointLabel(f.dst)} <span className="text-muted">{f.dst.kind}</span>
                                {f.directionUnknown && <span className="text-muted"> (direction unknown)</span>}
                              </td>
                              <td className="col-shrink">
                                {f.port || '—'} {f.protocol}
                              </td>
                              <td className="col-numeric">{f.requestRate == null ? <span className="text-muted">—</span> : formatRate(f.requestRate)}</td>
                              <td className="col-numeric">
                                {pct == null ? (
                                  <span className="text-muted">not measured</span>
                                ) : (
                                  <>
                                    {formatRate(pct)}%{isProblemFlow(f) ? ' (errors)' : ''}
                                  </>
                                )}
                              </td>
                              <td className="col-numeric">{f.bytesRate == null ? <span className="text-muted">—</span> : formatBytesRate(f.bytesRate)}</td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </>
          )
        }}
      </InspectFrame>
    </section>
  )
}
