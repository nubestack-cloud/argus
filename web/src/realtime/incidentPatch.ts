import type { QueryClient, QueryKey } from '@tanstack/react-query'
import type { Incident } from '../api/types'
import { markFresh } from './freshRows'

// Patch-in-place for IncidentUpdated (docs/CLUSTER_INSIGHT_SPECS.md CI-U8).
// The event names one incident; instead of invalidating every cached incident
// list (a refetch of up to 500 rows per list, and a table that re-renders
// under the reader), the one incident is fetched and written into each cached
// list page that already holds it. Its row keeps its position, the list
// keeps its scroll, and the row is marked fresh.
//
// What a patch cannot do honestly, it does not attempt: an incident in no
// cached list is new (or newly matches a filter), and where it belongs in a
// server-sorted, server-filtered list is the server's answer — so the caller
// falls back to invalidating the lists. Likewise a list filtered by `state`
// whose patched row no longer matches is invalidated rather than left showing
// a row its own filter excludes.

interface ListData {
  incidents: Incident[]
}

function isListData(v: unknown): v is ListData {
  return typeof v === 'object' && v !== null && Array.isArray((v as ListData).incidents)
}

/** An incident LIST key: ['incidents'] or ['incidents', {filters}] — not the
 *  detail ['incidents', id] or its sub-keys. */
export function isIncidentListKey(key: QueryKey): boolean {
  if (key[0] !== 'incidents') return false
  if (key.length === 1) return true
  return key.length === 2 && typeof key[1] === 'object' && key[1] !== null
}

/**
 * The list with `fresh` written over the row of the same id — only the fields
 * the list row already carries, so a detail payload's extra fields never leak
 * into list rows. Returns null when the list does not hold the incident.
 */
export function patchListData<T extends ListData>(data: T, fresh: Partial<Incident> & { id: string }): T | null {
  const i = data.incidents.findIndex((r) => r.id === fresh.id)
  if (i < 0) return null
  const row = data.incidents[i]
  const merged = { ...row } as Record<string, unknown>
  for (const k of Object.keys(row)) {
    if (k in fresh) merged[k] = (fresh as Record<string, unknown>)[k]
  }
  const incidents = data.incidents.slice()
  incidents[i] = merged as unknown as Incident
  return { ...data, incidents }
}

/**
 * Writes `incident` into every cached list holding it. Returns how it went:
 * `patched` lists were updated in place; `stale` lists (a state filter the
 * row no longer matches) were invalidated; `found` is false when no cached
 * list held it at all — the caller then refreshes the lists.
 */
export function patchIncidentLists(queryClient: QueryClient, incident: Incident): { found: boolean; patched: number } {
  let found = false
  let patched = 0
  for (const [key, data] of queryClient.getQueriesData({ predicate: (q) => isIncidentListKey(q.queryKey) })) {
    if (!isListData(data)) continue
    const next = patchListData(data, incident)
    if (!next) continue
    found = true
    const filters = key[1] as { state?: string } | undefined
    if (filters?.state && filters.state !== incident.state) {
      void queryClient.invalidateQueries({ queryKey: key, exact: true })
      continue
    }
    queryClient.setQueryData(key, next)
    patched++
  }
  if (patched > 0) markFresh([incident.id])
  return { found, patched }
}

/**
 * Builds the patcher the event invalidator calls with an incident id. It
 * refreshes that incident's own detail queries (prefix ['incidents', id]) as
 * before, then patches the lists. Resolves false when the lists still need a
 * refetch: the fetch failed, or no cached list held the incident.
 */
export function createIncidentPatcher(
  queryClient: QueryClient,
  fetchIncident: (id: string) => Promise<Incident>,
): (id: string) => Promise<boolean> {
  return async (id: string) => {
    void queryClient.invalidateQueries({ queryKey: ['incidents', id] })
    let incident: Incident
    try {
      incident = await fetchIncident(id)
    } catch {
      return false
    }
    return patchIncidentLists(queryClient, incident).found
  }
}
