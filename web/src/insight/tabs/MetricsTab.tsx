import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getResourceChanges, getWorkloadMetrics } from '../../api/client'
import { useAuth } from '../../auth/useAuth'
import type { ChartAnnotation } from '../../charts/types'
import { unixSeconds } from '../../pages/incident-detail/insightModel'
import { InsightFooter, QueryBody } from '../InsightParts'
import { changeWhat, perPodResourceLines } from '../model'
import { MetricPanels, MetricRangePicker, type MetricRange } from '../views/MetricPanels'
import type { TabProps } from './common'

// ---------------------------------------------------------------- Metrics
//
// PROJECT.md AD7: CPU, memory, restarts and throttling for this pod or
// workload, ending now, from the cluster's Prometheus through the agent. The
// object's own recorded changes are drawn on the charts, so a step in memory
// can be read against the rollout that caused it.
export function MetricsTab({ target, cluster, describe }: TabProps) {
  const { accessToken } = useAuth()
  const [range, setRange] = useState<MetricRange>('6h')
  const namespace = target.namespace ?? ''
  const q = useQuery({
    queryKey: ['workload-metrics', target.clusterId, namespace, target.kind, target.name, range],
    queryFn: () => getWorkloadMetrics(target.clusterId, { kind: target.kind, namespace, name: target.name }, range, accessToken!),
    enabled: !!accessToken && namespace !== '',
    staleTime: 30_000,
    retry: false,
  })
  // The same query (and cache entry) the Changes tab makes.
  const changes = useQuery({
    queryKey: ['resource-changes', target.clusterId, namespace, target.kind, target.name],
    queryFn: () => getResourceChanges(target.clusterId, { namespace: target.namespace, kind: target.kind, name: target.name }, accessToken!),
    enabled: !!accessToken,
    staleTime: 30_000,
    retry: false,
  })
  const unavailable = q.data !== undefined && !q.data.available
  // The series are per pod, so each pod's own request and limit is the line
  // to read them against.
  const obj = describe.data?.result?.object
  const referenceLines = { cpu: perPodResourceLines(obj, 'cpu'), memory: perPodResourceLines(obj, 'memory') }
  return (
    <div className="insight-stack">
      <div className="insight-controls">
        <MetricRangePicker
          range={range}
          onChange={setRange}
          unavailableReason={unavailable ? q.data?.reason || 'the hub has no metrics source for this cluster' : undefined}
        />
      </div>
      <QueryBody query={q} lines={10} errorFallback="Resource usage could not be read.">
        {(m) => {
          const from = unixSeconds(m.start)
          const annotations: ChartAnnotation[] = (changes.data?.changes ?? [])
            .map((c) => ({ timestamp: unixSeconds(c.observedAt), label: changeWhat(c), kind: 'change' as const }))
            .filter((a) => a.timestamp >= from)
          return (
            <>
              <MetricPanels answer={m} annotations={annotations} referenceLines={referenceLines} />
              {m.available && <InsightFooter at={m.receivedAt} cluster={cluster} />}
            </>
          )
        }}
      </QueryBody>
    </div>
  )
}
