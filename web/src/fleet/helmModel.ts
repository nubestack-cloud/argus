import type { HelmReleaseList, HelmReleaseRow } from '../api/types'

// Helm releases (PROJECT.md AD5), as list_helm_releases returns them:
// internal/agent/tools_inventory.go. Release names come from annotations on
// cached objects; revision, status and updated from the newest release
// Secret's labels only (D-R12). Chart version and values are never read, so
// nothing here pretends to know them.

export type { HelmReleaseList, HelmReleaseRow }

// Shared by the Helm tab and the Overview's Checks row, so the preview and the
// tab are one cached read.
export const HELM_ARGS = {}

/** Helm's own status words, as a readable label and a badge tone. The tone
 *  repeats the word; it never replaces it. */
const HELM_STATUS: Record<string, { label: string; badge: string }> = {
  deployed: { label: 'Deployed', badge: 'badge badge-green' },
  failed: { label: 'Failed', badge: 'badge badge-red' },
  'pending-install': { label: 'Pending install', badge: 'badge badge-amber' },
  'pending-upgrade': { label: 'Pending upgrade', badge: 'badge badge-amber' },
  'pending-rollback': { label: 'Pending rollback', badge: 'badge badge-amber' },
  uninstalling: { label: 'Uninstalling', badge: 'badge badge-amber' },
  superseded: { label: 'Superseded', badge: 'badge badge-gray' },
  uninstalled: { label: 'Uninstalled', badge: 'badge badge-gray' },
  unknown: { label: 'Unknown', badge: 'badge badge-gray' },
}

export function helmStatus(status: string | undefined): { label: string; badge: string } | null {
  if (!status) return null
  return HELM_STATUS[status] ?? { label: status, badge: 'badge badge-gray' }
}

const HEALTH_WORD: Record<string, { label: string; badge: string }> = {
  healthy: { label: 'Healthy', badge: 'badge badge-green' },
  neutral: { label: 'Idle', badge: 'badge badge-gray' },
  degraded: { label: 'Degraded', badge: 'badge badge-amber' },
  unhealthy: { label: 'Unhealthy', badge: 'badge badge-red' },
  unknown: { label: 'Unknown', badge: 'badge badge-gray' },
}

export function healthWord(level: string | undefined): { label: string; badge: string } | null {
  if (!level) return null
  return HEALTH_WORD[level] ?? HEALTH_WORD.unknown
}

/** Failed or stuck by Helm's own status, or its graded objects are not healthy. */
export function isHelmProblem(r: HelmReleaseRow): boolean {
  return (
    r.status === 'failed' ||
    (r.status ?? '').startsWith('pending-') ||
    r.status === 'uninstalling' ||
    !!r.lastOperation ||
    r.health === 'degraded' ||
    r.health === 'unhealthy'
  )
}

/** Problems first, then namespace and name — the order a person scans for
 *  the one release that matters. The list is complete (not paged), so this
 *  sorts the whole set. */
export function sortReleases(rows: readonly HelmReleaseRow[]): HelmReleaseRow[] {
  return [...rows].sort((a, b) => {
    const pa = isHelmProblem(a) ? 0 : 1
    const pb = isHelmProblem(b) ? 0 : 1
    if (pa !== pb) return pa - pb
    return a.namespace.localeCompare(b.namespace) || a.name.localeCompare(b.name)
  })
}

/** The graded objects in words, worst first: "1 unhealthy · 4 healthy · 2 idle". */
export function gradedSummary(r: HelmReleaseRow): string {
  if (!r.graded) return 'nothing to grade'
  const c = r.healthCounts ?? {}
  const order = ['unhealthy', 'degraded', 'unknown', 'healthy', 'neutral'] as const
  return order
    .filter((k) => (c[k] ?? 0) > 0)
    .map((k) => `${c[k]} ${k === 'neutral' ? 'idle' : k === 'unknown' ? 'health unknown' : k}`)
    .join(' · ')
}

/** "12 objects: 5 ConfigMap, 4 Service, …" for a tooltip. */
export function objectKindsText(r: HelmReleaseRow): string {
  const kinds = (r.objectKinds ?? []).map((k) => `${k.count} ${k.kind}`).join(', ')
  return `${r.objects} object${r.objects === 1 ? '' : 's'}${kinds ? `: ${kinds}` : ''}`
}

/** The overview Checks row's figures, or null before an answer exists. */
export function helmChecks(
  result: HelmReleaseList | undefined,
): { total: number; problems: number; problemsAtLeast: boolean; unread: number } | null {
  if (!result) return null
  const rows = result.releases ?? []
  return {
    total: result.total,
    problems: rows.filter(isHelmProblem).length,
    // Counted over the releases the agent returned; past its cap, more may exist.
    problemsAtLeast: !!result.truncated,
    unread: rows.filter((r) => !r.status).length,
  }
}

/** The open incidents on a release's own objects. A member matches by kind,
 *  namespace and name; a Pod or ReplicaSet matches the member workload it
 *  was named from (Kubernetes names a Deployment's ReplicaSets and pods
 *  "<workload>-<hash>…" and a StatefulSet's pods "<workload>-<ordinal>"),
 *  which is the ownership the list response does not carry. Namespace must
 *  match in every case. */
export function incidentsForRelease<T extends { objectGvk?: string; objectNamespace?: string; objectName?: string; state: string }>(
  r: HelmReleaseRow,
  incidents: readonly T[],
): T[] {
  // A member's namespace is its own, which can differ from the release's
  // (a release recorded in default that installs into apps).
  const members = (r.members ?? []).map((m) => ({ ...m, ns: m.namespace ?? '' }))
  const workloads = members.filter((m) => ['Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet', 'Job', 'CronJob'].includes(m.kind))
  return incidents.filter((i) => {
    if (i.state === 'Resolved' || i.state === 'Dismissed' || !i.objectName) return false
    const name = i.objectName
    const ns = i.objectNamespace ?? ''
    const kind = (i.objectGvk ?? '').split('/').pop() ?? ''
    if (members.some((m) => m.kind === kind && m.name === name && m.ns === ns)) return true
    if (kind === 'Pod' || kind === 'ReplicaSet') return workloads.some((w) => w.ns === ns && name.startsWith(`${w.name}-`))
    return false
  })
}

/** Updated within the last `days` days, by the release record's own time. */
export function changedWithin(r: HelmReleaseRow, days: number, now = Date.now()): boolean {
  return !!r.updated && now - new Date(r.updated).getTime() <= days * 86_400_000
}
