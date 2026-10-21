// What the cost and traffic tabs say when the agent has no metrics to read
// them from. One sentence per real case, the agent's setting named in words
// rather than as a values.yaml key, and — when the agent found a Prometheus
// Service in the cluster on its own (read-only, from its cache) — where it is.

export interface DetectedPrometheus {
  namespace: string
  name: string
  port?: number
  /** prometheus, thanos or victoriametrics; absent from older agents. */
  flavour?: string
}

const FLAVOUR_NAME: Record<string, string> = { prometheus: 'Prometheus', thanos: 'Thanos query', victoriametrics: 'VictoriaMetrics' }
export const flavourName = (d: DetectedPrometheus | null | undefined) => FLAVOUR_NAME[d?.flavour ?? ''] ?? 'Prometheus'

const SETTING = 'the Prometheus service setting in the argus-agent chart'

/** The "how to turn this on" sentence for an agent with no Prometheus. */
export function connectPrometheusHint(d: DetectedPrometheus | null | undefined, what: string): string {
  if (d?.name) {
    const where = `${d.namespace}/${d.name}${d.port ? `:${d.port}` : ''}`
    return `A Prometheus was found at ${where} — set it as the agent’s metrics source (${SETTING}) to enable ${what}.`
  }
  return `No Prometheus Service was found in the cluster either; install one, then name it in ${SETTING}.`
}
