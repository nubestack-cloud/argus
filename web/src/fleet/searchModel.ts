// Object search across the fleet (docs/CLUSTER_INSIGHT_SPECS.md CI-S12):
// GET /api/v1/search's hits, grouped by cluster, plus the sentence that says
// which clusters did not answer — results from a partial fan-out must read
// as partial (CI-U2).
import type { SearchResult } from '../api/types'

export type SearchHit = SearchResult['hits'][number]

export interface ClusterHits {
  clusterId: string
  clusterName: string
  hits: SearchHit[]
}

/** Hits grouped by cluster: clusters ordered by their best hit's score (the
 *  server's ranking), hits within a cluster kept in server order. */
export function groupHitsByCluster(hits: readonly SearchHit[]): ClusterHits[] {
  const groups = new Map<string, ClusterHits>()
  for (const h of hits) {
    let g = groups.get(h.clusterId)
    if (!g) {
      g = { clusterId: h.clusterId, clusterName: h.clusterName, hits: [] }
      groups.set(h.clusterId, g)
    }
    g.hits.push(h)
  }
  const best = (g: ClusterHits) => Math.max(...g.hits.map((h) => h.score))
  return [...groups.values()].sort((a, b) => best(b) - best(a) || a.clusterName.localeCompare(b.clusterName))
}

function names(refs: { name: string }[]): string {
  return refs.map((r) => r.name).join(', ')
}

/**
 * What the fan-out did NOT cover, as sentences — empty when every cluster in
 * scope answered. Failed (timed out or errored) and disconnected are named
 * separately because they mean different things: one may answer next time,
 * the other cannot be asked at all right now.
 */
export function coverageSentences(r: Pick<SearchResult, 'clustersFailed' | 'clustersDisconnected'>): string[] {
  const out: string[] = []
  const failed = r.clustersFailed ?? []
  const disconnected = r.clustersDisconnected ?? []
  if (failed.length > 0) {
    out.push(
      `${failed.length} ${failed.length === 1 ? 'cluster' : 'clusters'} did not answer in time (${names(failed)}) — results may be incomplete.`,
    )
  }
  if (disconnected.length > 0) {
    out.push(
      `${disconnected.length} ${disconnected.length === 1 ? 'cluster is' : 'clusters are'} disconnected and could not be searched (${names(disconnected)}).`,
    )
  }
  return out
}

/** The object-search grammar the agent understands (internal/agent/objsearch). */
export const SEARCH_GRAMMAR: { token: string; meaning: string }[] = [
  { token: 'kind:Deployment', meaning: 'only objects of this kind' },
  { token: 'ns:payments', meaning: 'only this namespace' },
  { token: 'label:app=api', meaning: 'objects carrying this label' },
  { token: 'image:nginx', meaning: 'workloads running a matching image' },
]
