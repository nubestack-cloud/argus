// Reading model for a `trace_service_path` result: the headline first ("Breaks
// at: Service payments — …"), then the hop chain in traversal order with the
// broken hop named in text. Pure; the renderer maps it onto `.chain-node*`.
//
// Wire semantics the model relies on:
//   - `downstream` runs from the subject (index 0) toward the pods, and
//     `brokenAt` indexes `downstream` only (-1 = no anchored hop).
//   - `upstreams` are parallel entries into the subject, judged independently:
//     one broken Ingress does not condemn a Service another Ingress still
//     reaches, so an upstream's own findings decide only its own state.
//   - The verdict is static: configuration and readiness were read, no traffic
//     was sent. A healthy verdict therefore reads "no break found", never
//     "reachable".

export type PathVerdict = 'healthy' | 'degraded' | 'broken' | 'unknown'
export type PathFindingSeverity = 'critical' | 'warning' | 'info'

export interface PathRef {
  group?: string
  kind: string
  namespace?: string
  name: string
}

export interface PathFinding {
  code: string
  /** Which hop the finding hangs on, for findings delivered in the top-level
   *  list: a number indexes `downstream`; a string is "upstream:N" or
   *  "downstream:N". Absent on findings nested in a hop. */
  hop?: number | string
  severity: PathFindingSeverity
  message: string
  /** Read-only command that reproduces the observation. */
  command?: string
}

export interface PathHopInput {
  resource: PathRef
  edge?: string
  findings?: PathFinding[]
}

export interface PathTrace {
  subject: PathRef
  upstreams?: PathHopInput[]
  downstream?: PathHopInput[]
  verdict: PathVerdict
  brokenAt: number
  headline?: string
  /** One sentence explaining a degraded/broken/unknown verdict. */
  reason?: string
  findings?: PathFinding[]
  truncated?: boolean
}

/**
 * ok          judged and nothing wrong
 * broken      traffic stops here
 * degraded    a warning here, or the anchor of a partial break
 * unknown     could not be judged (unknown verdict, no findings)
 * after-break past a break on the linear chain — never reached, not judged
 */
export type HopState = 'ok' | 'broken' | 'degraded' | 'unknown' | 'after-break'

export interface PathHop {
  label: string
  kind: string
  name: string
  namespace?: string
  role: 'upstream' | 'downstream'
  state: HopState
  findings: PathFinding[]
}

export interface PathModel {
  headline: string
  verdictLabel: string
  hops: PathHop[]
  /** Index into `hops` of the hop the headline names, or -1. */
  brokenHopIndex: number
  truncated: boolean
}

/** Text for each hop state — the broken hop is marked in words, not colour. */
export const HOP_STATE_LABEL: Record<HopState, string> = {
  ok: 'OK',
  broken: 'Breaks here',
  degraded: 'Degraded',
  unknown: 'Not verified',
  'after-break': 'Not reached',
}

const VERDICT_LABEL: Record<PathVerdict, string> = {
  healthy: 'No break found',
  degraded: 'Degraded',
  broken: 'Broken',
  unknown: 'Could not verify',
}

const SEVERITY_RANK: Record<PathFindingSeverity, number> = { critical: 0, warning: 1, info: 2 }

export function hopLabel(ref: PathRef): string {
  return ref.name ? `${ref.kind} ${ref.name}` : ref.kind
}

function sortBySeverity(findings: PathFinding[]): PathFinding[] {
  return [...findings].sort((a, b) => (SEVERITY_RANK[a.severity] ?? 3) - (SEVERITY_RANK[b.severity] ?? 3))
}

function worst(findings: readonly PathFinding[]): PathFinding | undefined {
  return findings.find(f => f.severity === 'critical') ?? findings.find(f => f.severity === 'warning')
}

/** Resolves a top-level finding's `hop` to [role, index], or null if it names
 *  no hop in this trace. */
function hopTarget(hop: PathFinding['hop'], upstreams: number, downstream: number): ['upstream' | 'downstream', number] | null {
  if (typeof hop === 'number') return Number.isInteger(hop) && hop >= 0 && hop < downstream ? ['downstream', hop] : null
  if (typeof hop !== 'string') return null
  // The agent's trace writes "downstream[0]" / "upstream[1]"; the
  // "downstream:0" form is accepted too.
  const m = /^(upstream|downstream)(?::(\d+)|\[(\d+)\])$/.exec(hop)
  if (!m) return null
  const i = Number(m[2] ?? m[3])
  const role = m[1] as 'upstream' | 'downstream'
  return i < (role === 'upstream' ? upstreams : downstream) ? [role, i] : null
}

function judgedState(findings: readonly PathFinding[], verdict: PathVerdict): HopState {
  if (findings.some(f => f.severity === 'critical')) return 'broken'
  if (findings.some(f => f.severity === 'warning')) return 'degraded'
  return verdict === 'unknown' ? 'unknown' : 'ok'
}

export function buildPathModel(trace: PathTrace): PathModel {
  const ups = trace.upstreams ?? []
  let downs = trace.downstream ?? []
  if (downs.length === 0) downs = [{ resource: trace.subject }]

  const upFindings = ups.map(h => [...(h.findings ?? [])])
  const downFindings = downs.map(h => [...(h.findings ?? [])])
  // Top-level findings naming no hop in this trace attach to the subject, so
  // nothing the tool reported is dropped from the view.
  for (const f of trace.findings ?? []) {
    const target = hopTarget(f.hop, ups.length, downs.length)
    if (target?.[0] === 'upstream') upFindings[target[1]].push(f)
    else downFindings[target ? target[1] : 0].push(f)
  }

  const brokenAt = Number.isInteger(trace.brokenAt) && trace.brokenAt >= 0 && trace.brokenAt < downs.length ? trace.brokenAt : -1
  const linearBreak = trace.verdict === 'broken' && brokenAt >= 0

  const hops: PathHop[] = [
    ...ups.map((h, i): PathHop => ({
      label: hopLabel(h.resource),
      kind: h.resource.kind,
      name: h.resource.name,
      namespace: h.resource.namespace,
      role: 'upstream',
      state: judgedState(upFindings[i], trace.verdict),
      findings: sortBySeverity(upFindings[i]),
    })),
    ...downs.map((h, i): PathHop => {
      let state = judgedState(downFindings[i], trace.verdict)
      if (i === brokenAt) state = trace.verdict === 'broken' ? 'broken' : state === 'broken' ? 'broken' : 'degraded'
      else if (linearBreak && i > brokenAt) state = 'after-break'
      return {
        label: hopLabel(h.resource),
        kind: h.resource.kind,
        name: h.resource.name,
        namespace: h.resource.namespace,
        role: 'downstream',
        state,
        findings: sortBySeverity(downFindings[i]),
      }
    }),
  ]

  let brokenHopIndex = brokenAt >= 0 ? ups.length + brokenAt : -1
  // A break with no downstream anchor (every entry into a healthy subject is
  // broken) is named at the first broken hop in traversal order.
  if (brokenHopIndex < 0 && trace.verdict === 'broken') brokenHopIndex = hops.findIndex(h => h.state === 'broken')

  return {
    headline: headlineFor(trace, hops, brokenHopIndex, upFindings, downFindings),
    verdictLabel: VERDICT_LABEL[trace.verdict] ?? VERDICT_LABEL.unknown,
    hops,
    brokenHopIndex,
    truncated: trace.truncated === true,
  }
}

function headlineFor(
  trace: PathTrace,
  hops: PathHop[],
  brokenHopIndex: number,
  upFindings: PathFinding[][],
  downFindings: PathFinding[][],
): string {
  // Upstream missing-reference findings concern a sibling backend route, not
  // this subject, so they never headline the path.
  const pathFindings = [
    ...downFindings.flat(),
    ...upFindings.flat().filter(f => !f.code.startsWith('missing_ref:')),
  ]
  const lead = trace.verdict === 'broken' ? 'Breaks at' : 'Degraded at'

  if (brokenHopIndex >= 0 && (trace.verdict === 'broken' || trace.verdict === 'degraded')) {
    const hop = hops[brokenHopIndex]
    const why = worst(hop.findings)?.message ?? trace.reason ?? worst(pathFindings)?.message
    return why ? `${lead}: ${hop.label} — ${why}` : `${lead}: ${hop.label}`
  }
  if (trace.verdict === 'broken' || trace.verdict === 'degraded') {
    // The reason leads over a server headline: a broken verdict beside an
    // optimistic headline would contradict itself.
    const why = trace.reason ?? worst(pathFindings)?.message ?? trace.headline
    return why ?? (trace.verdict === 'broken' ? 'Traffic cannot reach a ready pod' : 'Part of the path is degraded')
  }
  if (trace.verdict === 'unknown') {
    return trace.reason ?? trace.headline ?? 'Could not determine whether traffic reaches a ready pod'
  }
  return trace.headline ?? `No break found from ${hopLabel(trace.subject)} to its pods (configuration and readiness checked; no traffic sent)`
}
