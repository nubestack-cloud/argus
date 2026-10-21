// Best-practice posture checks (docs/CLUSTER_INSIGHT_SPECS.md CI-S4), as the
// get_posture_findings tool returns them: internal/agent/posture_detector.go
// postureResult + internal/agent/posture/{types,catalogue}.go.

export interface PostureFinding {
  kind: string
  group?: string
  namespace: string
  name: string
  checkID: string
  category: string
  severity: string
  message: string
  /** Set aside by an argus.io/ignore-checks annotation; in none of the counts. */
  excepted?: boolean
}

export interface PostureCheckMeta {
  id: string
  title: string
  category?: string
  defaultSeverity?: string
  description: string
  remediation: string
  frameworks?: string[]
  references?: { label: string; url: string }[]
}

export interface PostureResult {
  observedAt?: string
  coverage?: { group?: string; kind: string; state: string; reason?: string }[]
  truncated?: boolean
  checks?: Record<string, PostureCheckMeta> | null
  findings?: PostureFinding[] | null
  total?: number
  /** Danger / warning / passing counts, overall and per category, as the
   *  agent computed them over every object it checked (passing counts are
   *  only knowable there; findings carry failures alone). */
  summary?: PostureSummary | null
}

export interface PostureCounts {
  danger: number
  warning: number
  passing: number
}

export interface PostureSummary extends Partial<PostureCounts> {
  excepted?: number
  categories?: Record<string, PostureCounts> | null
}

export interface PostureGroup {
  checkId: string
  title: string
  category: string
  /** The worst severity among the group's rows. */
  severity: 'danger' | 'warning'
  meta?: PostureCheckMeta
  findings: PostureFinding[]
}

/**
 * One group per check (CI-U4 collapse), worst severity first, then most
 * objects, then title. A check missing from the catalogue still groups, under
 * its id — the row must not vanish because its description did.
 */
export function groupPosture(result: PostureResult | null | undefined): PostureGroup[] {
  const groups = new Map<string, PostureGroup>()
  for (const f of result?.findings ?? []) {
    if (f.excepted) continue
    let g = groups.get(f.checkID)
    if (!g) {
      const meta = result?.checks?.[f.checkID]
      g = {
        checkId: f.checkID,
        title: meta?.title || f.checkID,
        category: meta?.category || f.category,
        severity: 'warning',
        meta,
        findings: [],
      }
      groups.set(f.checkID, g)
    }
    if (f.severity === 'danger') g.severity = 'danger'
    g.findings.push(f)
  }
  return [...groups.values()].sort(
    (a, b) =>
      (a.severity === b.severity ? 0 : a.severity === 'danger' ? -1 : 1) ||
      b.findings.length - a.findings.length ||
      a.title.localeCompare(b.title),
  )
}

/** Every framework label the catalogue mentions, sorted. */
export function frameworksOf(result: PostureResult | null | undefined): string[] {
  const out = new Set<string>()
  for (const c of Object.values(result?.checks ?? {})) for (const f of c.frameworks ?? []) out.add(f)
  return [...out].sort()
}

/** Groups whose check is labelled with `framework` (all, when blank). */
export function filterByFramework(groups: PostureGroup[], framework: string): PostureGroup[] {
  if (!framework) return groups
  return groups.filter((g) => g.meta?.frameworks?.includes(framework))
}

/** Danger/warning in the product's severity words (the detector maps
 *  danger→high and warning→medium when it emits a signal). */
export const POSTURE_SEVERITY_LABEL: Record<string, string> = { danger: 'High', warning: 'Medium' }

export const POSTURE_CATEGORIES = ['Security', 'Reliability', 'Efficiency'] as const

export interface NamespacePosture {
  namespace: string
  danger: number
  warning: number
}

/** Findings per namespace, most findings first (danger breaks ties). */
export function postureByNamespace(findings: readonly PostureFinding[]): NamespacePosture[] {
  const m = new Map<string, NamespacePosture>()
  for (const f of findings) {
    if (f.excepted) continue
    const n = m.get(f.namespace) ?? { namespace: f.namespace, danger: 0, warning: 0 }
    if (f.severity === 'danger') n.danger++
    else n.warning++
    m.set(f.namespace, n)
  }
  return [...m.values()].sort((a, b) => b.danger + b.warning - (a.danger + a.warning) || b.danger - a.danger || a.namespace.localeCompare(b.namespace))
}
