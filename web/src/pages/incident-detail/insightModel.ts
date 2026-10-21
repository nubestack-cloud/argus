// Pure decisions for the incident page's cluster-insight sections: which
// object the relationship map is centred on, whether the incident is a
// Pending pod (CI-S9) or a GitOps incident (CI-S7/S15), and which GitOps
// object a quick action targets. Kept apart from the JSX so each is tested.

import type { IncidentDetail } from '../../api/types'
import { defaultGroupFor, GITOPS_KINDS, isGitOpsKind, parseGvk, quickActionFor } from '../../insight/kinds'
import type { ObjectRef } from '../../insight/panelUrl'
import { parseWorkloadKey } from '../../utils/incidents'

type IncidentFields = Pick<IncidentDetail, 'clusterId' | 'objectGvk' | 'objectNamespace' | 'objectName' | 'workloadKey'>

/** The object the detector named (often a Pod), or null when none. */
export function incidentObject(incident: IncidentFields): ObjectRef | null {
  const name = incident.objectName ?? ''
  if (!name) return null
  const gvk = parseGvk(incident.objectGvk)
  if (!gvk.kind) return null
  return {
    clusterId: incident.clusterId,
    kind: gvk.kind,
    apiGroup: gvk.group ?? (defaultGroupFor(gvk.kind) || undefined),
    namespace: incident.objectNamespace || undefined,
    name,
  }
}

/**
 * The object a reader thinks of this incident as being about: the owning
 * workload when the agent resolved one (a Pod is replaced by the fix that
 * resolves it), otherwise the object itself — the same rule the page heading
 * follows (utils/incidents incidentIdentity).
 */
export function incidentSubject(incident: IncidentFields): ObjectRef | null {
  const key = incident.workloadKey ?? ''
  const piped = key.split('|')
  if (piped.length === 3 && piped[2]) {
    const gvk = parseGvk(piped[0])
    if (gvk.kind) {
      return {
        clusterId: incident.clusterId,
        kind: gvk.kind,
        apiGroup: gvk.group ?? (defaultGroupFor(gvk.kind) || undefined),
        namespace: piped[1] || incident.objectNamespace || undefined,
        name: piped[2],
      }
    }
  }
  const owner = parseWorkloadKey(incident.workloadKey)
  if (owner.name && owner.kind) {
    return {
      clusterId: incident.clusterId,
      kind: owner.kind,
      apiGroup: defaultGroupFor(owner.kind) || undefined,
      namespace: owner.namespace || incident.objectNamespace || undefined,
      name: owner.name,
    }
  }
  return incidentObject(incident)
}

const PENDING_REASON = /pending|unschedul|failedscheduling/i

/** The Pod to explain when this incident is a pod that will not schedule. */
export function pendingPod(incident: IncidentFields & Pick<IncidentDetail, 'openingReason' | 'findingGroups'>): ObjectRef | null {
  const obj = incidentObject(incident)
  if (!obj || obj.kind !== 'Pod' || !obj.namespace) return null
  const reasons = [incident.openingReason ?? '', ...(incident.findingGroups ?? []).map((g) => g.reason)]
  return reasons.some((r) => PENDING_REASON.test(r) && !/pvc/i.test(r)) ? obj : null
}

/**
 * The GitOps controller object behind this incident: the Argo Application /
 * Flux object the ownership facts name, or the incident object itself when
 * it is one. Null for an incident with no Argo/Flux involvement (Helm alone
 * is not a GitOps controller here).
 */
export function gitOpsSource(incident: IncidentFields & Pick<IncidentDetail, 'ownership'>): ObjectRef | null {
  const o = incident.ownership
  if (o && (o.managedBy === 'argocd' || o.managedBy === 'flux') && o.sourceKind && o.sourceName) {
    return {
      clusterId: incident.clusterId,
      kind: o.sourceKind,
      apiGroup: GITOPS_KINDS[o.sourceKind],
      namespace: o.sourceNamespace || undefined,
      name: o.sourceName,
    }
  }
  const obj = incidentObject(incident)
  if (obj && isGitOpsKind(obj.kind, obj.apiGroup)) return obj
  return null
}

/** The quick action a GitOps source offers, with the target it needs. */
export function gitOpsQuickAction(source: ObjectRef | null) {
  if (!source || !source.namespace) return null
  const qa = quickActionFor(source.kind)
  return qa ? { ...qa, namespace: source.namespace, name: source.name } : null
}

/** Unix seconds for an ISO time, or NaN. */
export function unixSeconds(iso: string): number {
  return Date.parse(iso) / 1000
}

/** Prometheus step string ("30s", "2m", "1h") → seconds; undefined if unreadable. */
export function stepSeconds(step: string | undefined): number | undefined {
  const m = /^(\d+(?:\.\d+)?)(s|m|h)$/.exec(step ?? '')
  if (!m) return undefined
  return Number(m[1]) * (m[2] === 'h' ? 3600 : m[2] === 'm' ? 60 : 1)
}
