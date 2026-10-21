import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useMutation } from '@tanstack/react-query'
import { ApiError, proposeRightsizing } from '../api/client'
import { CAP_REMEDIATION_EXECUTE_INPLACE } from '../api/capabilities'
import { missingCapabilityMessage } from '../api/capabilityInfo'
import { useAuth } from '../auth/useAuth'
import { useMissingCapabilities } from '../auth/useCapabilities'
import { urlString, useUrlState } from '../hooks/useUrlState'
import { SplitBar } from '../components/SplitBar'
import type { NamespaceTopology } from '../api/types'
import { InspectFrame, type ClusterLiveness } from './InspectFrame'
import { useInspect } from './useInspect'

// Cluster detail → Cost → Rightsizing (PROJECT.md PG8): each container's
// requests against its measured p95 over seven days, from the agent's
// Prometheus (cAdvisor) — no OpenCost needed. Read-only: a recommendation
// becomes a change only as a PatchResourceLimits plan an investigation
// proposes and a person approves.

export interface RightsizingRow {
  kind: string
  workload: string
  container: string
  pods: number
  podLevel?: boolean
  cpuRequestMilli?: number
  memRequestBytes?: number
  memLimitBytes?: number
  cpuP95Milli?: number
  memP95Bytes?: number
  memPeakBytes?: number
  recommendedCpuMilli?: number
  recommendedMemBytes?: number
  cpuVerdict?: string
  memVerdict?: string
  memLimitTooTight?: boolean
}

interface RightsizingResult {
  observedAt?: string
  coverage?: { group?: string; kind: string; state: string; reason?: string }[]
  available: boolean
  reason?: string
  window: string
  namespace: string
  rows: RightsizingRow[]
}

const SCHEMA = { rns: urlString('') }

const VERDICT: Record<string, { label: string; badge: string }> = {
  under: { label: 'Under', badge: 'badge badge-red' },
  over: { label: 'Over', badge: 'badge badge-amber' },
  noRequest: { label: 'No request', badge: 'badge badge-gray' },
  fits: { label: 'Fits', badge: 'badge badge-green' },
}

export function cpu(m: number | undefined): string {
  if (m === undefined) return '—'
  if (m > 0 && m < 1) return '<1m'
  return m >= 1000 ? `${(m / 1000).toLocaleString(undefined, { maximumFractionDigits: 2 })}` : `${Math.round(m)}m`
}

export function mem(b: number | undefined): string {
  if (b === undefined) return '—'
  const mi = b / (1 << 20)
  if (b > 0 && mi < 1) return '<1Mi'
  return mi >= 1024 ? `${(mi / 1024).toLocaleString(undefined, { maximumFractionDigits: 1 })}Gi` : `${Math.round(mi)}Mi`
}

/** The worst verdict of a row, for the summary bar. */
export function rowVerdict(r: RightsizingRow): string {
  const v = [r.cpuVerdict, r.memVerdict]
  if (v.includes('under') || r.memLimitTooTight) return 'under'
  if (v.includes('over')) return 'over'
  if (v.includes('noRequest')) return 'noRequest'
  return r.cpuVerdict || r.memVerdict ? 'fits' : ''
}

function Verdict({ v }: { v?: string }) {
  const w = v ? VERDICT[v] : undefined
  return w ? <span className={w.badge}>{w.label}</span> : <span className="text-muted">—</span>
}

/** Rows a resource change can be proposed for: a Deployment or StatefulSet
 *  container sized per container, whose requests are measurably off. */
export function proposable(r: RightsizingRow): boolean {
  if (r.podLevel || (r.kind !== 'Deployment' && r.kind !== 'StatefulSet')) return false
  return [r.cpuVerdict, r.memVerdict].some((v) => v === 'over' || v === 'under')
}

function ProposeButton({ clusterId, namespace, row }: { clusterId: string; namespace: string; row: RightsizingRow }) {
  const { accessToken } = useAuth()
  const { resolved, missing } = useMissingCapabilities([CAP_REMEDIATION_EXECUTE_INPLACE])
  const m = useMutation({
    mutationFn: () => proposeRightsizing(clusterId, { namespace, kind: row.kind, workload: row.workload, container: row.container }, accessToken!),
  })
  if (!proposable(row)) return null
  if (m.data) {
    return <Link to={`/incidents/${m.data.incidentId}`}>Awaiting approval</Link>
  }
  const denied = resolved && missing.length > 0 ? missingCapabilityMessage(missing) : undefined
  return (
    <>
      <button type="button" className="secondary" disabled={!!denied || m.isPending} title={denied} onClick={() => m.mutate()}>
        {m.isPending ? 'Proposing…' : 'Propose'}
      </button>
      {m.isError && (
        <span className="form-error" role="alert">
          {m.error instanceof ApiError ? m.error.detail || m.error.message : 'Could not propose this change.'}
        </span>
      )}
    </>
  )
}

export function RightsizingSection({ clusterId, liveness }: { clusterId: string; liveness: ClusterLiveness }) {
  const [state, setState] = useUrlState(SCHEMA)
  const index = useInspect<NamespaceTopology>(clusterId, 'get_namespace_topology', INDEX_ARGS)
  const namespaces = useMemo(() => (index.query.data?.result?.namespaces ?? []).map((n) => n.name).filter(Boolean) as string[], [index.query.data])
  const ns = state.rns || namespaces[0] || ''
  const args = useMemo(() => ({ namespace: ns }), [ns])
  const { query, capabilityResolved, missing } = useInspect<RightsizingResult>(clusterId, 'get_rightsizing', args, !!ns)
  return (
    <section aria-label="Rightsizing" className="rightsizing">
      <div className="panel-toolbar">
        <h3>Rightsizing</h3>
        <label className="visually-hidden" htmlFor="rightsizing-ns">
          Namespace
        </label>
        <select id="rightsizing-ns" className="compact-select" value={ns} onChange={(e) => setState({ rns: e.target.value }, { push: true })}>
          {namespaces.map((n) => (
            <option key={n} value={n}>
              {n}
            </option>
          ))}
        </select>
      </div>
      <InspectFrame
        label="Rightsizing"
        help="Each container's requests against its p95 CPU and memory over seven days, from the cluster's Prometheus. The recommendation is p95 plus 20% headroom, never below peak memory. Under means p95 is above the request; over means the request is at least twice the recommendation. Propose turns a row into a resource-requests change that waits for approval, like any other fix; only requests the container already has are changed."
        query={query}
        capabilityResolved={capabilityResolved}
        missing={missing}
        liveness={liveness}
        skeletonColumns={6}
      >
        {(r) => {
          if (!r.available) return <p className="empty-state">{r.reason || 'Rightsizing is not available on this cluster.'}</p>
          if (r.rows.length === 0) return <p className="empty-state">No running containers in {r.namespace}.</p>
          const count = (v: string) => r.rows.filter((x) => rowVerdict(x) === v).length
          return (
            <>
              <SplitBar
                tall
                label={`Containers in ${r.namespace} by sizing`}
                parts={[
                  { tone: 'critical', value: count('under'), label: 'under-provisioned' },
                  { tone: 'medium', value: count('over'), label: 'over-provisioned' },
                  { tone: 'unknown', value: count('noRequest'), label: 'no request' },
                  { tone: 'ok', value: count('fits'), label: 'fits' },
                ]}
              />
              <div className="table-scroll">
                <table className="cluster-table list-table">
                  <thead>
                    <tr>
                      <th>Workload · container</th>
                      <th className="col-numeric">CPU request</th>
                      <th className="col-numeric">p95</th>
                      <th className="col-numeric">Recommend</th>
                      <th className="col-shrink">CPU</th>
                      <th className="col-numeric">Memory request</th>
                      <th className="col-numeric">p95 · peak</th>
                      <th className="col-numeric">Recommend</th>
                      <th className="col-shrink">Memory</th>
                      <th className="col-shrink">
                        <span className="visually-hidden">Propose</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {r.rows.map((x) => (
                      <tr key={`${x.kind}/${x.workload}/${x.container}`}>
                        <td className="fleet-mono">
                          {x.kind} {x.workload} · {x.container}
                          {x.podLevel && <span className="field-hint"> (pod-level resources)</span>}
                        </td>
                        <td className="col-numeric">{cpu(x.cpuRequestMilli)}</td>
                        <td className="col-numeric">{cpu(x.cpuP95Milli)}</td>
                        <td className="col-numeric">{cpu(x.recommendedCpuMilli)}</td>
                        <td>
                          <Verdict v={x.cpuVerdict} />
                        </td>
                        <td className="col-numeric">{mem(x.memRequestBytes)}</td>
                        <td className="col-numeric">
                          {mem(x.memP95Bytes)} · {mem(x.memPeakBytes)}
                        </td>
                        <td className="col-numeric">{mem(x.recommendedMemBytes)}</td>
                        <td>
                          <Verdict v={x.memVerdict} />
                          {x.memLimitTooTight && (
                            <span className="badge badge-red" title={`Peak memory reached 90% of the ${mem(x.memLimitBytes)} limit`}>
                              Near limit
                            </span>
                          )}
                        </td>
                        <td>
                          <ProposeButton clusterId={clusterId} namespace={r.namespace} row={x} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )
        }}
      </InspectFrame>
    </section>
  )
}

const INDEX_ARGS = {}
