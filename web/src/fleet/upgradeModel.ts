// Upgrade readiness (docs/CLUSTER_INSIGHT_SPECS.md CI-S5): the agent's scan
// result, as stored on the hub's upgrade_scans row. Shape: internal/agent/
// upgradeready/types.go ScanResults (plus the insight stamp the tool embeds).
import { toVerdict, type Verdict } from '../components/VerdictBadge'

export interface UpgradeResourceRef {
  group?: string
  kind: string
  namespace: string
  name: string
}

export interface UpgradeReference {
  title: string
  url: string
}

export interface UpgradeFinding {
  ruleID: string
  title: string
  level: string
  resource?: UpgradeResourceRef
  managedBy?: UpgradeResourceRef
  evidence?: { source: string; path: string; detail?: string }
  appliesFrom?: string
  impact: string
  remediation: string
  references?: UpgradeReference[] | null
}

export interface UpgradeCheck {
  id: string
  category: string
  title: string
  status: string
  summary: string
  evidenceNote?: string
  caveat?: string
  scope?: string
  inspected?: number
  appliesFrom?: string
  findings: UpgradeFinding[] | null
  findingsTotal?: number
  truncated?: boolean
  references?: UpgradeReference[] | null
  /** Counts by title over every finding, before the agent's cap (UX13). */
  groups?: { title: string; count: number; impact?: string; remediation?: string }[] | null
}

export interface UpgradeScanResult {
  currentVersion?: string
  targetVersion?: string
  reviewedThrough?: string
  verdict?: string
  summary?: {
    blocked: number
    warnings: number
    reviews: number
    passed: number
    unknown: number
    notApplicable: number
    findings: number
  }
  checks?: UpgradeCheck[] | null
  observedAt?: string
}

export function readScanResult(result: unknown): UpgradeScanResult | null {
  if (typeof result !== 'object' || result === null || Array.isArray(result)) return null
  return result as UpgradeScanResult
}

/** The order the spec reads checks in: what stops the upgrade first, what is
 *  fine last. Incomplete (we could not check) sits above Passed so a gap is
 *  never buried under the passes. */
export const VERDICT_GROUP_ORDER: Verdict[] = ['blocked', 'warning', 'review', 'incomplete', 'passed', 'notApplicable']

export interface CheckGroup {
  verdict: Verdict
  checks: UpgradeCheck[]
}

/** Checks grouped by verdict in VERDICT_GROUP_ORDER; empty groups omitted.
 *  Within a group the agent's own order is kept. */
export function groupChecks(checks: readonly UpgradeCheck[] | null | undefined): CheckGroup[] {
  const by = new Map<Verdict, UpgradeCheck[]>()
  for (const c of checks ?? []) {
    const v = toVerdict(c.status)
    const list = by.get(v) ?? []
    list.push(c)
    by.set(v, list)
  }
  return VERDICT_GROUP_ORDER.filter((v) => by.has(v)).map((verdict) => ({ verdict, checks: by.get(verdict)! }))
}

/** How many findings exist for a check, and how many the agent sent. The
 *  agent caps each check (findingsTotal is the pre-cap count). */
export function findingCounts(check: UpgradeCheck): { shown: number; total: number } {
  const shown = check.findings?.length ?? 0
  const total = Math.max(shown, check.findingsTotal ?? 0)
  return { shown, total }
}

/** The display cap per check before "show all". */
export const FINDINGS_DISPLAY_CAP = 20

const ERROR_SENTENCE: Record<number, string> = {
  429: 'This cluster was scanned less than a minute ago. Wait a minute and run it again.',
  502: 'The agent could not complete the scan.',
  503: 'The agent is not connected, so a scan cannot run now. The last stored scan is shown below.',
  400: 'The hub rejected the target version. Use the form "1.N", for example 1.33.',
}

/** The sentence to show when an on-demand scan request fails. The hub's own
 *  detail wins for a rejected target (it names the usable range) and is
 *  appended for an agent failure (it is the agent's reason). */
export function scanErrorMessage(status: number | undefined, detail?: string): string {
  if (status === 400 && detail) return detail
  if (status === 502) return detail ? `${ERROR_SENTENCE[502]} ${detail}` : ERROR_SENTENCE[502]
  if (status && ERROR_SENTENCE[status]) return ERROR_SENTENCE[status]
  return detail ? `The scan could not run: ${detail}` : 'The scan could not run.'
}

/** Whether a stored scan answers "the next upgrade" — its target is the minor
 *  right after the version it scanned from. Only such a scan feeds the
 *  Clusters list and the Overview; any other target is a one-off. Unknown
 *  versions are not claimed either way (null). */
export function isNextMinorScan(scan: { currentVersion?: string; targetVersion?: string } | null | undefined): boolean | null {
  const cur = /^v?(\d+)\.(\d+)/.exec(scan?.currentVersion ?? '')
  const tgt = /^v?(\d+)\.(\d+)/.exec(scan?.targetVersion ?? '')
  if (!cur || !tgt) return null
  return cur[1] === tgt[1] && Number(tgt[2]) === Number(cur[2]) + 1
}

/** "Deployment payments/api" — the readable identity of a finding's object. */
export function resourceLabel(r: UpgradeResourceRef): string {
  return `${r.kind} ${r.namespace ? `${r.namespace}/` : ''}${r.name}`
}

export interface FindingGroup {
  title: string
  impact?: string
  remediation?: string
  findings: UpgradeFinding[]
  /** The whole-set count from the agent; findings may be fewer past its cap. */
  total: number
}

/** A check's findings grouped by what they are (owner-approved cluster-pages
 *  design, 2026-10-11): 48 pods with node-local emptyDir data are one row
 *  with the impact and fix stated once, not 48 repetitions. Grouped over the
 *  findings the agent sent; the check's own total says how many exist. */
export function groupFindings(check: UpgradeCheck): FindingGroup[] {
  const by = new Map<string, FindingGroup>()
  // The agent's groups are counted over every finding, before its cap; the
  // findings it sent fill in the members. An older agent sends no groups, so
  // the count falls back to the findings at hand.
  for (const g of check.groups ?? []) {
    by.set(g.title, { title: g.title, impact: g.impact, remediation: g.remediation, findings: [], total: g.count })
  }
  for (const f of check.findings ?? []) {
    const key = f.title || f.ruleID || 'Finding'
    const g = by.get(key) ?? { title: key, impact: f.impact, remediation: f.remediation, findings: [], total: 0 }
    g.findings.push(f)
    if (!check.groups) g.total = g.findings.length
    by.set(key, g)
  }
  return [...by.values()].sort((a, b) => b.total - a.total || a.title.localeCompare(b.title))
}

/** Findings per namespace over the findings the agent sent, most first;
 *  cluster-scoped objects count under "cluster-wide". */
export function findingsByNamespace(check: UpgradeCheck): { namespace: string; count: number }[] {
  const m = new Map<string, number>()
  for (const f of check.findings ?? []) {
    const ns = f.resource?.namespace || 'cluster-wide'
    m.set(ns, (m.get(ns) ?? 0) + 1)
  }
  return [...m.entries()].map(([namespace, count]) => ({ namespace, count })).sort((a, b) => b.count - a.count || a.namespace.localeCompare(b.namespace))
}

/** The checks in strip order: what blocks first, passes last. */
export function stripOrder(checks: readonly UpgradeCheck[] | null | undefined): UpgradeCheck[] {
  const rank = (c: UpgradeCheck) => VERDICT_GROUP_ORDER.indexOf(toVerdict(c.status))
  return [...(checks ?? [])].sort((a, b) => rank(a) - rank(b))
}
