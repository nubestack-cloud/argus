import { buildPathModel, HOP_STATE_LABEL, type HopState } from '../../pathtrace/model'
import { toPathTrace } from '../pathTrace'
import { Reproducer } from '../../components/Reproducer'
import type { TraceResult } from '../types'

const VERDICT_TONE: Record<string, string> = {
  healthy: 'badge-green',
  degraded: 'badge-amber',
  broken: 'badge-red',
  unknown: 'badge-gray',
}

// The chain dot's colour repeats the hop's state word, which is always
// printed beside it (never colour alone).
const HOP_SEV: Record<HopState, string> = {
  ok: 'sev-low',
  broken: 'sev-critical',
  degraded: 'sev-medium',
  unknown: 'sev-neutral',
  'after-break': 'sev-neutral',
}

const SEVERITY_WORD: Record<string, string> = { critical: 'Critical', warning: 'Warning', info: 'Info' }

// A path-shaped answer (CI-S3 / CI-U11): the headline first — which hop
// breaks and why — then the hop chain in traversal order with each hop's
// state in words, then each finding with the command that reproduces it.
export function PathTraceView({ trace, clusterName }: { trace: TraceResult; clusterName?: string }) {
  const model = buildPathModel(toPathTrace(trace))
  return (
    <div className="path-trace">
      <p className="path-trace-headline">
        <span className={`badge ${VERDICT_TONE[trace.verdict ?? 'unknown'] ?? 'badge-gray'}`}>{model.verdictLabel}</span>{' '}
        {model.headline}
      </p>
      <p className="field-hint">
        A static check: configuration and readiness were read, no traffic was sent.
      </p>
      <ol className="chain-list">
        {model.hops.map((hop, i) => (
          <li key={`${hop.role}-${i}`} className={`chain-node ${HOP_SEV[hop.state]}`}>
            <span className="chain-node-track" aria-hidden="true">
              <span className="chain-node-dot" />
            </span>
            <div className="chain-node-body">
              <p className="chain-node-text">
                <strong>{hop.label}</strong>
                {hop.namespace ? <span className="field-hint"> · {hop.namespace}</span> : null}
                {hop.role === 'upstream' ? <span className="field-hint"> · entry point</span> : null} —{' '}
                <span className={i === model.brokenHopIndex ? 'path-trace-break' : undefined}>{HOP_STATE_LABEL[hop.state]}</span>
              </p>
              {hop.findings.length > 0 && (
                <ul className="path-trace-findings">
                  {hop.findings.map((f, j) => (
                    // The message says it in words; the agent's finding code
                    // (netpol:advisory) is an identifier, not prose, so it is
                    // kept only as the hover title for anyone matching it to
                    // the agent's output.
                    <li key={j} title={f.code}>
                      <span className="path-trace-severity">{SEVERITY_WORD[f.severity] ?? f.severity}:</span> {f.message}{' '}
                      {f.command && <Reproducer command={f.command} clusterName={clusterName} />}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </li>
        ))}
      </ol>
      {model.truncated && <p className="insight-note">The trace hit its size cap — more hops exist than are shown.</p>}
    </div>
  )
}
