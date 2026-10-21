// The object inspector's open state lives in the URL (?panel=obj:<cluster>:
// <group>/<kind>:<namespace>/<name>), so any page opens it by setting one
// search parameter, a link reproduces it, and the list underneath keeps its
// own scroll, filters and selection (docs/CLUSTER_INSIGHT_SPECS.md CI-F3,
// CI-U7). ObjectInspectorHost (mounted once in AppShell) reads it.

export interface ObjectRef {
  clusterId: string
  kind: string
  apiGroup?: string
  namespace?: string
  name: string
}

export const PANEL_PARAM = 'panel'

export function encodeObjectPanel(o: ObjectRef): string {
  const gk = `${o.apiGroup ?? ''}/${o.kind}`
  return `obj:${o.clusterId}:${gk}:${o.namespace ?? ''}/${o.name}`
}

export function decodeObjectPanel(v: string | null): ObjectRef | null {
  if (!v || !v.startsWith('obj:')) return null
  const rest = v.slice(4)
  const first = rest.indexOf(':')
  const second = rest.indexOf(':', first + 1)
  if (first < 1 || second < 0) return null
  const clusterId = rest.slice(0, first)
  const gk = rest.slice(first + 1, second)
  const nsName = rest.slice(second + 1)
  const slash = gk.lastIndexOf('/')
  const nsSlash = nsName.indexOf('/')
  if (slash < 0 || nsSlash < 0) return null
  const kind = gk.slice(slash + 1)
  const name = nsName.slice(nsSlash + 1)
  if (!kind || !name) return null
  return {
    clusterId,
    apiGroup: gk.slice(0, slash) || undefined,
    kind,
    namespace: nsName.slice(0, nsSlash) || undefined,
    name,
  }
}

/** Returns a copy of params with the panel opened on o (or closed when null). */
export function withObjectPanel(params: URLSearchParams, o: ObjectRef | null): URLSearchParams {
  const next = new URLSearchParams(params)
  if (o) next.set(PANEL_PARAM, encodeObjectPanel(o))
  else {
    next.delete(PANEL_PARAM)
    next.delete('ptab')
  }
  return next
}

/** Parses an agent GVK string ("apps/v1/Deployment", "v1/Pod") into group and kind. */
export function splitGVK(gvk: string): { apiGroup?: string; kind: string } {
  const parts = gvk.split('/')
  const kind = parts[parts.length - 1]
  return { apiGroup: parts.length === 3 ? parts[0] : undefined, kind }
}
