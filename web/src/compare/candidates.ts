import type { ObjectRef } from '../insight/panelUrl'
import type { KubeObject } from '../insight/types'
import { sameKind, sameObject } from './compareUrl'

// What the picker offers before anything is typed, and how typed results
// are ordered. Pure, so the "sensible defaults" are pinned in tests: a Pod's
// sibling replicas (healthy first — the usual question is "what does the
// working one have that this one does not"), and for anything else the
// same-named object in other namespaces and clusters (staging against
// production), then its neighbours in the same namespace.

/** One search hit, from the fleet search or one cluster's search_objects. */
export interface SearchHit {
  clusterId: string
  clusterName?: string
  kind: string
  apiGroup?: string
  namespace?: string
  name: string
  status?: string
}

export type CandidateGroup = 'siblings' | 'sameName' | 'sameNamespace' | 'search'

export const GROUP_LABEL: Record<CandidateGroup, string> = {
  siblings: 'Sibling replicas',
  sameName: 'Same name in other namespaces or clusters',
  sameNamespace: 'Same namespace',
  search: 'Matches',
}

export interface Candidate {
  ref: ObjectRef
  clusterName?: string
  status?: string
  group: CandidateGroup
}

function refOf(h: SearchHit): ObjectRef {
  return { clusterId: h.clusterId, kind: h.kind, apiGroup: h.apiGroup || undefined, namespace: h.namespace || undefined, name: h.name }
}

/**
 * A Pod's replica family: the controller that made it and the name prefix
 * its siblings share. A ReplicaSet's name is "<deployment>-<pod-template-
 * hash>", so the family is the Deployment's — pods of the previous rollout
 * are siblings too, and often the most useful ones to compare against.
 */
export function podFamily(obj: KubeObject | null | undefined): { owner: string; ownerKind: string; prefix: string } | null {
  const refs = obj?.metadata?.ownerReferences ?? []
  const ctl = refs.find((r) => r.controller) ?? refs[0]
  if (!ctl?.name || !ctl.kind) return null
  const hash = obj?.metadata?.labels?.['pod-template-hash']
  if (ctl.kind === 'ReplicaSet' && hash && ctl.name.endsWith(`-${hash}`)) {
    return { owner: ctl.name, ownerKind: ctl.kind, prefix: ctl.name.slice(0, -hash.length - 1) }
  }
  return { owner: ctl.name, ownerKind: ctl.kind, prefix: ctl.name }
}

/** The status words search reports for something working: a running or
 *  finished pod, a fully ready workload. Anything else (Pending,
 *  CrashLoopBackOff, "1/3 ready", no status) is not claimed healthy. */
export function isHealthyStatus(status: string | undefined): boolean {
  if (!status) return false
  if (status === 'Running' || status === 'Succeeded' || status === 'Completed' || status === 'Bound' || status === 'Active') return true
  const m = /^(\d+)\/(\d+) ready$/.exec(status)
  return !!m && m[1] === m[2] && Number(m[2]) > 0
}

function distinctFrom(anchor: ObjectRef, others: readonly ObjectRef[]) {
  return (c: Candidate) => !sameObject(c.ref, anchor) && sameKind(c.ref, anchor) && !others.some((o) => sameObject(o, c.ref))
}

/** Sibling replicas of Pod `a`: same cluster and namespace, name in the
 *  family prefix. Healthy first, then the same ReplicaSet, then by name. */
export function siblingCandidates(a: ObjectRef, obj: KubeObject | null | undefined, hits: readonly SearchHit[]): Candidate[] {
  const fam = podFamily(obj)
  if (!fam) return []
  const sameOwner = (n: string) => n.startsWith(`${fam.owner}-`)
  return hits
    .filter((h) => h.clusterId === a.clusterId && (h.namespace ?? '') === (a.namespace ?? '') && h.name.startsWith(`${fam.prefix}-`))
    .map((h): Candidate => ({ ref: refOf(h), clusterName: h.clusterName, status: h.status, group: 'siblings' }))
    .filter(distinctFrom(a, []))
    .sort(
      (x, y) =>
        Number(isHealthyStatus(y.status)) - Number(isHealthyStatus(x.status)) ||
        Number(sameOwner(y.ref.name)) - Number(sameOwner(x.ref.name)) ||
        x.ref.name.localeCompare(y.ref.name),
    )
}

/** Objects of `a`'s kind with exactly its name elsewhere. Same cluster
 *  first (another namespace), then other clusters, by cluster then namespace. */
export function sameNameCandidates(a: ObjectRef, hits: readonly SearchHit[]): Candidate[] {
  return hits
    .filter((h) => h.name === a.name)
    .map((h): Candidate => ({ ref: refOf(h), clusterName: h.clusterName, status: h.status, group: 'sameName' }))
    .filter(distinctFrom(a, []))
    .sort(
      (x, y) =>
        Number(y.ref.clusterId === a.clusterId) - Number(x.ref.clusterId === a.clusterId) ||
        (x.clusterName ?? x.ref.clusterId).localeCompare(y.clusterName ?? y.ref.clusterId) ||
        (x.ref.namespace ?? '').localeCompare(y.ref.namespace ?? ''),
    )
}

/** Other objects of `a`'s kind in its namespace, healthy first. Anything
 *  already offered in an earlier group is left out. */
export function sameNamespaceCandidates(a: ObjectRef, hits: readonly SearchHit[], already: readonly ObjectRef[]): Candidate[] {
  return hits
    .filter((h) => h.clusterId === a.clusterId && (h.namespace ?? '') === (a.namespace ?? ''))
    .map((h): Candidate => ({ ref: refOf(h), clusterName: h.clusterName, status: h.status, group: 'sameNamespace' }))
    .filter(distinctFrom(a, already))
    .sort((x, y) => Number(isHealthyStatus(y.status)) - Number(isHealthyStatus(x.status)) || x.ref.name.localeCompare(y.ref.name))
}

/**
 * Typed search results, nearest first: same cluster and namespace as the
 * anchor (the other side), then same cluster, then everything else in the
 * hub's own score order. Restricted to the anchor's kind when there is one.
 */
export function rankSearch(anchor: ObjectRef | null, hits: readonly SearchHit[]): Candidate[] {
  const near = (c: Candidate) => {
    if (!anchor) return 0
    if (c.ref.clusterId !== anchor.clusterId) return 0
    return (c.ref.namespace ?? '') === (anchor.namespace ?? '') ? 2 : 1
  }
  return hits
    .map((h, i): Candidate & { i: number } => ({ ref: refOf(h), clusterName: h.clusterName, status: h.status, group: 'search', i }))
    .filter((c) => !anchor || sameKind(c.ref, anchor))
    .sort((x, y) => near(y) - near(x) || x.i - y.i)
    .map(({ ref, clusterName, status, group }) => ({ ref, clusterName, status, group }))
}

/** The search_objects / fleet-search query for a kind and free text. */
export function searchQuery(kind: string | undefined, text: string, namespace?: string): string {
  return [kind ? `kind:${kind}` : '', namespace ? `ns:${namespace}` : '', text.trim()].filter(Boolean).join(' ')
}
