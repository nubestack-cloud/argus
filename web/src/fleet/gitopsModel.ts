import type { GitOpsAppList, GitOpsAppRow } from '../api/types'

// GitOps applications (PROJECT.md AD5), as list_gitops_apps returns them:
// internal/agent/tools_inventory.go. Argo CD Applications and Flux
// Kustomizations / HelmReleases with the controller's own sync and health
// words, and the plain-language headline internal/gitopsinsight derives for
// a failed, drifted or stuck app.

export type { GitOpsAppList, GitOpsAppRow }

const SYNC: Record<string, { label: string; badge: string }> = {
  Synced: { label: 'Synced', badge: 'badge badge-green' },
  OutOfSync: { label: 'Out of sync', badge: 'badge badge-amber' },
  Unknown: { label: 'Unknown', badge: 'badge badge-gray' },
  Reconciling: { label: 'Reconciling', badge: 'badge badge-blue' },
}

const HEALTH: Record<string, { label: string; badge: string }> = {
  Healthy: { label: 'Healthy', badge: 'badge badge-green' },
  Progressing: { label: 'Progressing', badge: 'badge badge-blue' },
  Degraded: { label: 'Degraded', badge: 'badge badge-red' },
  Missing: { label: 'Missing', badge: 'badge badge-red' },
  Suspended: { label: 'Suspended', badge: 'badge badge-gray' },
  Unknown: { label: 'Unknown', badge: 'badge badge-gray' },
}

export function syncWord(s: string | undefined): { label: string; badge: string } | null {
  if (!s) return null
  return SYNC[s] ?? { label: s, badge: 'badge badge-gray' }
}

export function healthWord(s: string | undefined): { label: string; badge: string } | null {
  if (!s) return null
  return HEALTH[s] ?? { label: s, badge: 'badge badge-gray' }
}

export const TOOL_LABEL: Record<string, string> = { argocd: 'Argo CD', flux: 'Flux' }

export const KIND_LABEL: Record<string, string> = {
  'argoproj.io/Application': 'Argo CD Applications',
  'kustomize.toolkit.fluxcd.io/Kustomization': 'Flux Kustomizations',
  'helm.toolkit.fluxcd.io/HelmRelease': 'Flux HelmReleases',
}

/** "github.com/org/repo" from a clone URL: the scheme and ".git" carry
 *  nothing a reader uses to recognise the repository. */
export function shortRepo(url: string | undefined): string {
  if (!url) return ''
  return url.replace(/^[a-z+]+:\/\//i, '').replace(/^git@([^:]+):/, '$1/').replace(/\.git$/, '')
}

/** Where the desired state comes from, in one line: repository · path or
 *  chart · @ revision asked for. */
export function sourceText(a: GitOpsAppRow): string {
  const where = a.repoURL ? shortRepo(a.repoURL) : (a.sourceRef ?? '')
  const what = a.path || a.chart || ''
  const parts = [where, what].filter(Boolean)
  let text = parts.join(' · ')
  if (a.targetRevision) text += ` @ ${a.targetRevision}`
  if (a.sourceCount && a.sourceCount > 1) text += ` (+${a.sourceCount - 1} more source${a.sourceCount - 1 === 1 ? '' : 's'})`
  return text
}

const IN_CLUSTER = 'https://kubernetes.default.svc'

/** Destination namespace, plus the target cluster when it is not this one. */
export function destinationText(a: GitOpsAppRow): string {
  const ns = a.destinationNamespace || '—'
  if (!a.destinationServer || a.destinationServer === IN_CLUSTER || a.destinationServer === 'in-cluster') return ns
  return `${ns} on ${shortRepo(a.destinationServer)}`
}

/** Problems first (the agent already sorts so; kept here so a re-sort of
 *  the complete list cannot drop the order), then namespace and name. */
export function sortApps(rows: readonly GitOpsAppRow[]): GitOpsAppRow[] {
  return [...rows].sort((a, b) => {
    const pa = a.problem ? 0 : 1
    const pb = b.problem ? 0 : 1
    if (pa !== pb) return pa - pb
    return a.namespace.localeCompare(b.namespace) || a.name.localeCompare(b.name)
  })
}

export interface ProblemGroup {
  /** The controller-derived reason these apps share. */
  headline: string
  causes: string[]
  stuck: boolean
  apps: GitOpsAppRow[]
}

/** Problem apps grouped by the reason they fail, the largest group first:
 *  six apps behind one expired repository credential are one problem, said
 *  once with the six apps under it. Apps outside any problem are returned
 *  apart, for the quiet table. */
export function groupProblems(rows: readonly GitOpsAppRow[]): { groups: ProblemGroup[]; quiet: GitOpsAppRow[] } {
  const byReason = new Map<string, ProblemGroup>()
  const quiet: GitOpsAppRow[] = []
  for (const a of rows) {
    if (!a.problem) {
      quiet.push(a)
      continue
    }
    const headline = a.headline || `${syncWord(a.sync)?.label ?? 'Sync unknown'}, ${healthWord(a.health)?.label.toLowerCase() ?? 'health unknown'}.`
    let g = byReason.get(headline)
    if (!g) {
      g = { headline, causes: [], stuck: false, apps: [] }
      byReason.set(headline, g)
    }
    g.apps.push(a)
    g.stuck = g.stuck || !!a.stuck
    for (const c of a.causes ?? []) if (!g.causes.includes(c)) g.causes.push(c)
  }
  const groups = [...byReason.values()].sort((x, y) => y.apps.length - x.apps.length || x.headline.localeCompare(y.headline))
  return { groups, quiet }
}

/** The kinds the agent could not see (absent, forbidden, still syncing). */
export function missingKinds(result: GitOpsAppList): { label: string; state: string }[] {
  return (result.kinds ?? [])
    .filter((k) => k.state !== 'synced')
    .map((k) => ({ label: KIND_LABEL[`${k.group ?? ''}/${k.kind}`] ?? k.kind, state: k.state }))
}

export const KIND_STATE_TEXT: Record<string, string> = {
  absent: 'not installed on this cluster',
  forbidden: 'not readable by the agent',
  syncing: 'still loading on the agent',
  disabled: 'switched off on this agent',
  error: 'could not be read',
}

/** A controller headline split for reading (owner-approved cluster-pages
 *  design, 2026-10-11): the plain-language summary gitopsinsight wrote
 *  (before its first ": "), the controller's raw message after it, and the
 *  innermost clause of that message — where the actual error usually is
 *  ("…: authentication required: Invalid username or token"). Nothing here
 *  is matched against particular errors; it only cuts at the colons the
 *  controller itself used. */
export function splitHeadline(headline: string): { summary: string; raw: string; cause: string } {
  const i = headline.indexOf(': ')
  if (i < 0) return { summary: headline, raw: '', cause: '' }
  const summary = headline.slice(0, i)
  const raw = headline.slice(i + 2)
  const parts = raw.split(': ').map((p) => p.trim()).filter(Boolean)
  const cause = parts.length > 1 ? parts.slice(-2).join(': ') : ''
  return { summary, raw, cause }
}

/** The one word a problem group's chip carries: stuck, or the worst sync /
 *  health state its apps share. */
export function problemWord(g: ProblemGroup): { label: string; badge: string } {
  if (g.stuck) return { label: 'Stuck', badge: 'badge badge-red' }
  const bad = g.apps.find((a) => a.health === 'Degraded' || a.health === 'Missing')
  if (bad) return healthWord(bad.health) ?? { label: 'Degraded', badge: 'badge badge-red' }
  if (g.apps.some((a) => a.sync === 'OutOfSync')) return { label: 'Out of sync', badge: 'badge badge-amber' }
  if (g.apps.some((a) => a.sync === 'Unknown' || !a.sync)) return { label: 'Sync unknown', badge: 'badge badge-orange' }
  return { label: 'Needs attention', badge: 'badge badge-amber' }
}

/** The repository every app in the group reads from, when they share one. */
export function sharedRepo(apps: readonly GitOpsAppRow[]): string {
  const repos = new Set(apps.map((a) => shortRepo(a.repoURL) || a.sourceRef || ''))
  return repos.size === 1 ? [...repos][0] : ''
}

/** Path or chart, and the revision asked for: what an app deploys, without
 *  the repository (said once on the group, or in the row's title). */
export function pathAtRevision(a: GitOpsAppRow): string {
  const what = a.path || a.chart || a.sourceRef || ''
  return a.targetRevision ? `${what || '/'} @ ${a.targetRevision}` : what
}

export interface SyncHealthCounts {
  sync: { synced: number; outOfSync: number; unknown: number; reconciling: number }
  health: { healthy: number; progressing: number; degraded: number; suspended: number; unknown: number }
}

/** Sync from the agent's complete counts; health from the listed apps
 *  (the counts carry only degraded and suspended), so a truncated list
 *  says its health bar covers the listed apps only. */
export function syncHealthCounts(result: GitOpsAppList): SyncHealthCounts {
  const c = result.counts
  const synced = Math.max(0, c.total - c.outOfSync - c.syncUnknown - c.reconciling)
  const h = { healthy: 0, progressing: 0, degraded: 0, suspended: 0, unknown: 0 }
  for (const a of result.apps ?? []) {
    if (a.suspended || a.health === 'Suspended') h.suspended++
    else if (a.health === 'Healthy') h.healthy++
    else if (a.health === 'Progressing') h.progressing++
    else if (a.health === 'Degraded' || a.health === 'Missing') h.degraded++
    else h.unknown++
  }
  return { sync: { synced, outOfSync: c.outOfSync, unknown: c.syncUnknown, reconciling: c.reconciling }, health: h }
}
