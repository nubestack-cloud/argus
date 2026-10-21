import type { PathTrace } from '../pathtrace/model'
import type { TraceResult } from './types'

/** Adapts the agent's wire trace to the model's input type. */
export function toPathTrace(r: TraceResult): PathTrace {
  return {
    subject: r.subject ?? { kind: 'Service', name: '' },
    upstreams: (r.upstreams ?? []).map((h) => ({ resource: h.resource, edge: h.edge })),
    downstream: (r.downstream ?? []).map((h) => ({ resource: h.resource, edge: h.edge })),
    verdict: (['healthy', 'degraded', 'broken', 'unknown'].includes(r.verdict ?? '') ? r.verdict : 'unknown') as PathTrace['verdict'],
    brokenAt: typeof r.brokenAt === 'number' ? r.brokenAt : -1,
    headline: r.headline,
    reason: r.reason,
    findings: (r.findings ?? []).map((f) => ({
      code: f.code,
      hop: f.hop,
      severity: (['critical', 'warning', 'info'].includes(f.severity) ? f.severity : 'info') as 'critical' | 'warning' | 'info',
      message: f.message,
      command: f.command,
    })),
    truncated: r.truncated,
  }
}

/** True when a tool result looks like a path trace (for evidence chips). */
export function isTraceResult(v: unknown): v is TraceResult {
  return !!v && typeof v === 'object' && 'verdict' in v && 'subject' in v
}
