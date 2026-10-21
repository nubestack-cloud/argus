import { connectPrometheusHint, type DetectedPrometheus } from './metricsSource'

// Cost (docs/CLUSTER_INSIGHT_SPECS.md CI-S14), as get_cost_summary returns
// it: internal/agent/cost/cost.go CostSummary. Figures are hourly rates in
// whatever currency OpenCost is configured with — never converted, never
// prefixed with a currency symbol ARGUS does not know. A nil figure is
// unmeasured and renders "—", never 0.

export interface NamespaceCost {
  name: string
  hourlyCost: number
  cpuCost: number
  memoryCost: number
  storageCost?: number | null
  cpuUsageCost?: number | null
  memoryUsageCost?: number | null
  efficiency?: number | null
  idleCost?: number | null
}

export interface CostSummary {
  available: boolean
  reason?: string
  detail?: string
  window?: string
  /** "opencost" (Prometheus) or "kubecost"; absent from older agents. */
  source?: string
  /** Cluster hourly spend over the last 7 days, where the source keeps it. */
  trend?: { time: string; hourlyCost: number }[] | null
  totalHourlyCost?: number | null
  hourlyCostBasis?: string
  totalAllocatedCost?: number | null
  totalNodeCost?: number | null
  totalStorageCost?: number | null
  totalIdleCost?: number | null
  totalUnusedRequestCost?: number | null
  totalUnallocatedCost?: number | null
  clusterEfficiency?: number | null
  namespaces?: NamespaceCost[] | null
  totalNamespaces?: number
  truncated?: boolean
  missing?: string[] | null
}

export interface CostResult {
  observedAt?: string
  summary?: CostSummary | null
  /** Set when no Prometheus is configured and the agent found one itself. */
  detectedPrometheus?: DetectedPrometheus | null
}

/** Why cost is unavailable, as one accurate sentence per case. The agent's
 *  raw detail is not appended: for an unconfigured agent it repeated the
 *  case in config-key form, and for a failed query it is transport text. */
export function costUnavailableReason(s: CostSummary | null | undefined, detected?: DetectedPrometheus | null): string {
  // An agent from before the not_configured code reported "no_metrics" with
  // a detail saying no Prometheus was configured — the case that read as a
  // contradiction. Its detail is what it means.
  const reason = s?.reason === 'no_metrics' && /no Prometheus is configured/i.test(s.detail ?? '') ? 'not_configured' : s?.reason
  switch (reason) {
    case 'not_configured':
      return `No Prometheus is connected to this cluster’s agent, so OpenCost’s figures cannot be read. ${connectPrometheusHint(detected, 'cost')}`
    case 'no_metrics':
      return 'Prometheus answered, but it holds no OpenCost allocation metrics — OpenCost is not installed on this cluster, or Prometheus does not scrape it.'
    case 'unreachable':
      return 'The agent’s Prometheus did not answer, so cost could not be read. Check that Prometheus is running and reachable from the agent.'
    case 'query_error':
      return 'Prometheus rejected the OpenCost queries, so cost could not be read.'
    case 'invalid_request':
      return 'The agent rejected the request.'
    default:
      return 'The agent did not report why cost is unavailable.'
  }
}

/** An hourly figure: up to four decimals so a small namespace does not read
 *  as nothing, no currency symbol (see the file comment). */
export function formatCost(v: number): string {
  return v.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: v !== 0 && Math.abs(v) < 1 ? 4 : 2 })
}

export const COST_BASIS_LABEL: Record<string, string> = {
  allocated: 'sum of namespace allocations',
  node_capacity: 'node cost (it exceeded the allocations, so it includes unallocated capacity and excludes storage)',
}

export const COST_WINDOWS = [1, 6, 24] as const
