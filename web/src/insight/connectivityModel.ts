// What the Connectivity tab traces from. A Service, Ingress or route is its
// own entry point; a Pod or workload is reached THROUGH the Services and
// Ingresses that route to it, which the agent's neighbourhood holds two hops
// out (Pod → owning workload → Service). Pure, so it is tested without a DOM.

import { PATH_KINDS } from './kinds'
import type { NeighborhoodResult } from './types'

export interface EntryPoint {
  kind: string
  namespace: string
  name: string
}

// Services first (a NetworkPolicy check needs one as its destination), then
// Ingress, then the Gateway API kinds; by name within a kind.
const ENTRY_RANK: Record<string, number> = { Service: 0, Ingress: 1, HTTPRoute: 2, GRPCRoute: 3, Gateway: 4 }

export function entryPointsFrom(r: NeighborhoodResult | null | undefined): EntryPoint[] {
  const seen = new Set<string>()
  const out: EntryPoint[] = []
  for (const n of r?.nodes ?? []) {
    if (!PATH_KINDS.has(n.kind) || !n.namespace) continue
    const key = `${n.kind}/${n.namespace}/${n.name}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push({ kind: n.kind, namespace: n.namespace, name: n.name })
  }
  return out.sort((a, b) => (ENTRY_RANK[a.kind] ?? 9) - (ENTRY_RANK[b.kind] ?? 9) || a.name.localeCompare(b.name))
}

export const NETPOL_VERDICT_WORD = { allowed: 'Allowed', denied: 'Denied', unknown: 'Unknown' } as const
export const NETPOL_EFFECT_WORD = {
  admits: 'admits',
  doesNotAdmit: 'does not admit',
  undecidable: 'cannot decide',
  notApplicable: 'does not apply',
} as const
