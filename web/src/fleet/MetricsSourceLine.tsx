import { CopyButton } from '../components/CopyButton'
import { flavourName, type DetectedPrometheus } from './metricsSource'

// The Traffic and Cost tabs' unavailable state (owner-approved cluster-pages
// design, 2026-10-11): one status line saying what is missing, and — when
// the agent found a Prometheus on its own — the exact argus-agent chart
// values that connect it, ready to copy. Other reasons (unreachable, no
// traffic source) are the agent's own sentence on the same line.

export function MetricsSourceLine({
  what,
  notConfigured,
  reason,
  detected,
}: {
  /** "traffic" or "cost". */
  what: string
  notConfigured: boolean
  reason: string
  detected?: DetectedPrometheus | null
}) {
  const values = detected?.name
    ? [
        `metrics.prometheusService.namespace=${detected.namespace}`,
        `metrics.prometheusService.name=${detected.name}`,
        ...(detected.port && detected.port !== 9090 ? [`metrics.prometheusService.port=${detected.port}`] : []),
      ].join('\n')
    : ''
  return (
    <div className="metrics-source" role="note" aria-label={`${what} is not available`}>
      <div className="metrics-source-line">
        <span className="badge badge-gray">{notConfigured ? 'Not connected' : 'Unavailable'}</span>
        {notConfigured ? (
          <span>
            No metrics source on this agent.
            {detected?.name ? (
              <>
                {' '}
                {flavourName(detected)} found at{' '}
                <span className="fleet-mono">
                  {detected.namespace}/{detected.name}
                  {detected.port ? `:${detected.port}` : ''}
                </span>
                .
              </>
            ) : (
              ' No Prometheus Service was found in the cluster either; install one first.'
            )}
          </span>
        ) : (
          <span>{reason}</span>
        )}
        {values && (
          <span className="metrics-source-copy">
            <CopyButton text={values} label="Copy helm values" />
          </span>
        )}
      </div>
      {values && (
        <pre className="metrics-source-values" aria-label="argus-agent chart values">
          {values}
        </pre>
      )}
    </div>
  )
}
