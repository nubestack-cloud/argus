import type { KubeObject } from '../insight/types'
import { podFamily } from './candidates'

// Per-instance differences: fields that ALWAYS differ between two replicas
// of one workload because each pod is a separate instance — its name, the
// IPs and CNI annotations it was assigned, the random suffix on its injected
// service-account token volume, and (between two rollouts) the ReplicaSet
// it came from. Comparing two siblings, they bury the one difference that
// matters. Hiding them is an option (on by default for two pods of one
// workload), and every hidden field is counted in the page's note so
// nothing is silently dropped. nodeName and everything else stay.

type Json = null | boolean | number | string | Json[] | { [k: string]: Json }
type Obj = Record<string, Json>

function isObj(v: unknown): v is Obj {
  return !!v && typeof v === 'object' && !Array.isArray(v)
}

export type InstanceCategory = 'name' | 'generateName' | 'ips' | 'cni' | 'tokenVolume' | 'revision'

export const INSTANCE_LABEL: Record<InstanceCategory, string> = {
  name: 'pod name',
  generateName: 'generateName',
  ips: 'pod and host IPs',
  cni: 'CNI-assigned annotations',
  tokenVolume: 'service-account token volume suffix',
  revision: 'ReplicaSet owner and pod-template-hash',
}

export interface InstanceHidden {
  category: InstanceCategory
  /** Distinct field paths hidden, across both sides. */
  count: number
}

/** A and B came from different ReplicaSets of one Deployment. */
export interface Revision {
  deployment: string
  replicaSetA: string
  replicaSetB: string
}

const CNI_PREFIXES = ['cni.projectcalico.org/', 'k8s.v1.cni.cncf.io/']
const IP_FIELDS = ['podIP', 'podIPs', 'hostIP', 'hostIPs']
const TOKEN_VOLUME = /^kube-api-access-[a-z0-9]{5}$/
/** What a token volume's random name reads as once hidden — the same on
 *  both sides, so a pod that has the volume against one that does not
 *  (automountServiceAccountToken) still shows as a difference. */
export const TOKEN_VOLUME_PLACEHOLDER = 'kube-api-access-(per-pod suffix)'

/** Two pods of the same owning workload: same cluster and namespace, and
 *  the same replica family (candidates.ts podFamily). The default for the
 *  "Ignore per-instance differences" option. */
export function sameWorkloadPods(
  a: { clusterId: string; namespace?: string },
  b: { clusterId: string; namespace?: string },
  objA: KubeObject | null | undefined,
  objB: KubeObject | null | undefined,
): boolean {
  if (objA?.kind !== 'Pod' || objB?.kind !== 'Pod') return false
  if (a.clusterId !== b.clusterId || (a.namespace ?? '') !== (b.namespace ?? '')) return false
  const fa = podFamily(objA)
  const fb = podFamily(objB)
  return !!fa && !!fb && fa.prefix === fb.prefix
}

/** Different ReplicaSets of one Deployment, read from the original objects
 *  (the stripped ones may have lost metadata to "spec only"). */
export function revisionOf(objA: KubeObject, objB: KubeObject): Revision | null {
  const fa = podFamily(objA)
  const fb = podFamily(objB)
  if (!fa || !fb || fa.ownerKind !== 'ReplicaSet' || fb.ownerKind !== 'ReplicaSet') return null
  // podFamily only strips a suffix that equals the pod-template-hash label,
  // so prefix !== owner means the owner name is "<deployment>-<hash>".
  if (fa.prefix === fa.owner || fb.prefix === fb.owner) return null
  if (fa.prefix !== fb.prefix || fa.owner === fb.owner) return null
  return { deployment: fa.prefix, replicaSetA: fa.owner, replicaSetB: fb.owner }
}

function hideOne(v: Obj, revision: Revision | null, side: 'a' | 'b', seen: Map<InstanceCategory, Set<string>>): Obj {
  const o = JSON.parse(JSON.stringify(v)) as Obj
  const mark = (c: InstanceCategory, path: string) => {
    if (!seen.has(c)) seen.set(c, new Set())
    seen.get(c)!.add(path)
  }
  const md = isObj(o.metadata) ? o.metadata : null
  if (md) {
    if ('name' in md) {
      delete md.name
      mark('name', 'metadata.name')
    }
    if ('generateName' in md) {
      delete md.generateName
      mark('generateName', 'metadata.generateName')
    }
    if (isObj(md.annotations)) {
      for (const k of Object.keys(md.annotations)) {
        if (CNI_PREFIXES.some((p) => k.startsWith(p))) {
          delete md.annotations[k]
          mark('cni', `metadata.annotations.${k}`)
        }
      }
      if (Object.keys(md.annotations).length === 0) delete md.annotations
    }
    if (revision) {
      const rs = side === 'a' ? revision.replicaSetA : revision.replicaSetB
      if (isObj(md.labels) && 'pod-template-hash' in md.labels) {
        delete md.labels['pod-template-hash']
        mark('revision', 'metadata.labels.pod-template-hash')
        if (Object.keys(md.labels).length === 0) delete md.labels
      }
      if (Array.isArray(md.ownerReferences)) {
        for (const ref of md.ownerReferences) {
          if (isObj(ref) && ref.kind === 'ReplicaSet' && ref.name === rs) {
            delete ref.name
            mark('revision', 'metadata.ownerReferences[ReplicaSet].name')
          }
        }
      }
    }
  }
  if (isObj(o.status)) {
    for (const f of IP_FIELDS) {
      if (f in o.status) {
        delete o.status[f]
        mark('ips', `status.${f}`)
      }
    }
  }
  if (isObj(o.spec)) {
    const spec = o.spec
    if (Array.isArray(spec.volumes)) {
      spec.volumes.forEach((vol, i) => {
        if (isObj(vol) && typeof vol.name === 'string' && TOKEN_VOLUME.test(vol.name)) {
          vol.name = TOKEN_VOLUME_PLACEHOLDER
          mark('tokenVolume', `spec.volumes[${i}].name`)
        }
      })
    }
    for (const list of ['initContainers', 'containers', 'ephemeralContainers']) {
      const cs = spec[list]
      if (!Array.isArray(cs)) continue
      for (const c of cs) {
        if (!isObj(c) || !Array.isArray(c.volumeMounts)) continue
        for (const m of c.volumeMounts) {
          if (isObj(m) && typeof m.name === 'string' && TOKEN_VOLUME.test(m.name)) {
            m.name = TOKEN_VOLUME_PLACEHOLDER
            mark('tokenVolume', `spec.${list}[${String(c.name)}].volumeMounts.name`)
          }
        }
      }
    }
  }
  return o
}

/**
 * Both stripped values with per-instance fields hidden, what was hidden
 * (by category, with a count of distinct field paths across both sides),
 * and the revision pair when A and B came from different ReplicaSets of
 * one Deployment — which is itself meaningful and is said in words.
 */
export function hideInstanceFields(
  va: Obj,
  vb: Obj,
  objA: KubeObject,
  objB: KubeObject,
): { a: Obj; b: Obj; hidden: InstanceHidden[]; revision: Revision | null } {
  const revision = revisionOf(objA, objB)
  const seen = new Map<InstanceCategory, Set<string>>()
  const a = hideOne(va, revision, 'a', seen)
  const b = hideOne(vb, revision, 'b', seen)
  const order: InstanceCategory[] = ['revision', 'name', 'generateName', 'cni', 'ips', 'tokenVolume']
  const hidden = order.filter((c) => seen.has(c)).map((c) => ({ category: c, count: seen.get(c)!.size }))
  return { a, b, hidden, revision }
}
