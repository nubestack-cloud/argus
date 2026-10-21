// What the command palette offers (docs/CLUSTER_INSIGHT_SPECS.md CI-S18), as
// pure data so the list a query produces can be pinned in tests. Navigation
// only: nothing here mutates anything. A page the viewer lacks the capability
// for is listed disabled with that capability named — disabled, not hidden.
import type { Cluster, Incident, SearchResult } from '../api/types'
import {
  CAP_ANALYSIS_READ,
  CAP_AUDIT_READ,
  CAP_CLUSTER_INSPECT,
  CAP_CLUSTER_READ,
  CAP_INCIDENT_READ,
  CAP_INCIDENT_SILENCE,
  CAP_REMEDIATION_APPROVE,
  CAP_USER_READ,
} from '../api/capabilities'
import { missingCapabilityMessage } from '../api/capabilityInfo'
import type { ObjectRef } from '../insight/panelUrl'
import { compareHref } from '../compare/compareUrl'
import { rankEntries, type ScoredEntry } from './score'

export type PaletteCategory = 'Pages' | 'Incidents' | 'Clusters' | 'Objects' | 'Search'

export interface PaletteEntry extends ScoredEntry {
  id: string
  category: PaletteCategory
  /** Where Enter goes. */
  to?: string
  /** Or: the object Enter opens in the inspector. */
  object?: ObjectRef
  disabledReason?: string
}

// The same destinations and gates as the app's navigation rail
// (components/AppShell.tsx NAV_REQUIRED_CAPABILITIES) — keep the two in step.
export const PALETTE_PAGES: { to: string; label: string; caps: string[]; terms?: string[] }[] = [
  { to: '/overview', label: 'Overview', caps: [], terms: ['home', 'fleet', 'dashboard'] },
  { to: '/clusters', label: 'Clusters', caps: [CAP_CLUSTER_READ] },
  { to: '/incidents', label: 'Incidents', caps: [CAP_INCIDENT_READ], terms: ['problems'] },
  { to: '/signals', label: 'Signals', caps: [CAP_INCIDENT_READ], terms: ['findings', 'posture', 'risks'] },
  { to: '/approvals', label: 'Approvals', caps: [CAP_REMEDIATION_APPROVE], terms: ['pending actions', 'queue'] },
  { to: '/tolerations', label: 'Tolerations', caps: [CAP_INCIDENT_SILENCE], terms: ['silence', 'mute'] },
  { to: '/search', label: 'Search objects', caps: [CAP_CLUSTER_INSPECT], terms: ['find'] },
  { to: '/changes', label: 'Recent Changes', caps: [CAP_INCIDENT_READ, CAP_ANALYSIS_READ], terms: ['undo', 'rollback'] },
  { to: '/audit-log', label: 'Audit Log', caps: [CAP_AUDIT_READ] },
  { to: '/insights', label: 'Insights', caps: [CAP_INCIDENT_READ, CAP_ANALYSIS_READ], terms: ['reports'] },
  { to: '/users', label: 'Users', caps: [CAP_USER_READ], terms: ['people', 'roles'] },
  { to: '/settings', label: 'Settings', caps: [], terms: ['configuration', 'preferences'] },
]

export const ALL_PAGE_CAPS = [...new Set(PALETTE_PAGES.flatMap((p) => p.caps))]

/** Page entries; `missing` is null while permissions are unresolved, when
 *  nothing is marked (a claim about the viewer's role before it is known
 *  would be false). */
export function pageEntries(missing: ReadonlySet<string> | null): PaletteEntry[] {
  return PALETTE_PAGES.map((p) => {
    const lacks = missing ? p.caps.filter((c) => missing.has(c)) : []
    return {
      id: `page:${p.to}`,
      label: p.label,
      category: 'Pages',
      to: p.to,
      searchTerms: p.terms,
      priorityBonus: 10,
      disabledReason: lacks.length ? missingCapabilityMessage(lacks) : undefined,
    }
  })
}

/**
 * "Compare objects" (PROJECT.md AD4). The compare page is not a nav item, so
 * it is not in PALETTE_PAGES; when an object panel is open it starts from
 * that object as A, with B's picker open.
 */
export function compareEntry(from: ObjectRef | null, missing: ReadonlySet<string> | null): PaletteEntry {
  const lacks = missing?.has(CAP_CLUSTER_INSPECT) ? [CAP_CLUSTER_INSPECT] : []
  return {
    id: 'page:/compare',
    label: 'Compare objects',
    sublabel: from ? `Starting from ${from.kind} ${from.name}` : undefined,
    category: 'Pages',
    to: compareHref(from),
    searchTerms: ['diff', 'side by side', 'replica'],
    priorityBonus: 10,
    disabledReason: lacks.length ? missingCapabilityMessage(lacks) : undefined,
  }
}

export function incidentEntries(incidents: readonly Incident[]): PaletteEntry[] {
  return incidents.map((i) => ({
    id: `incident:${i.id}`,
    label: i.objectName || i.openingReason || i.fingerprint.slice(0, 12),
    sublabel: [i.openingReason, i.clusterDisplayName, i.severity, i.state].filter(Boolean).join(' · '),
    category: 'Incidents',
    to: `/incidents/${i.id}`,
    searchTerms: [i.id, i.clusterDisplayName],
  }))
}

/** The few most recently seen incidents, for an empty query. */
export function recentIncidents(incidents: readonly Incident[], n = 5): Incident[] {
  return [...incidents].sort((a, b) => (a.lastSeen < b.lastSeen ? 1 : a.lastSeen > b.lastSeen ? -1 : 0)).slice(0, n)
}

export function clusterEntries(clusters: readonly Cluster[]): PaletteEntry[] {
  return clusters.map((c) => ({
    id: `cluster:${c.id}`,
    label: c.displayName,
    sublabel: c.state,
    category: 'Clusters',
    to: `/clusters/${c.id}`,
    searchTerms: [c.id],
  }))
}

export function objectEntries(hits: SearchResult['hits']): PaletteEntry[] {
  return hits.map((h, i) => ({
    id: `object:${h.clusterId}:${h.kind}:${h.namespace ?? ''}/${h.name}:${i}`,
    label: h.name,
    sublabel: [h.kind, h.namespace, h.clusterName, h.status].filter(Boolean).join(' · '),
    category: 'Objects',
    object: {
      clusterId: h.clusterId,
      kind: h.kind,
      apiGroup: h.apiGroup || undefined,
      namespace: h.namespace || undefined,
      name: h.name,
    },
  }))
}

/** Ranked local matches cap; object hits keep the server's own order. */
export const LOCAL_RESULT_CAP = 20

/**
 * The palette's list for a query. Blank: every page, then recent incidents.
 * Otherwise: pages, incidents and clusters ranked together by palette/score,
 * then the object-search hits (ranked by the hub, which also matched fields
 * — labels, images — that the label here does not show), then a link to the
 * full search page.
 */
export function paletteResults(
  query: string,
  sources: { pages: PaletteEntry[]; incidents: PaletteEntry[]; recent: PaletteEntry[]; clusters: PaletteEntry[]; objects: PaletteEntry[]; canSearch: boolean },
): PaletteEntry[] {
  const q = query.trim()
  if (!q) return [...sources.pages, ...sources.recent]
  const local = rankEntries([...sources.pages, ...sources.incidents, ...sources.clusters], q).slice(0, LOCAL_RESULT_CAP)
  const out = [...local, ...sources.objects]
  if (sources.canSearch && q.length >= 2) {
    out.push({ id: 'search:all', label: `Search every cluster for “${q}”`, category: 'Search', to: `/search?q=${encodeURIComponent(q)}` })
  }
  return out
}
