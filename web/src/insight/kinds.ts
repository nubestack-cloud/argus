// Kind knowledge the object inspector and the evidence helpers share: which
// API group/version a kind lives in (the agent's tools take a full
// "group/version/Kind" string), how kubectl names it, and which kinds a given
// inspector tab means anything for. Pure, so it is tested without rendering.

import type { QuickAction } from '../api/client'

interface GroupVersion {
  group: string
  version: string
}

// The kinds the agent's describe/owner-chain tools are known to serve
// (internal/agent/tools.go supportedGVKs), plus the Gateway API and Flux
// source kinds the insight tools read. A kind outside this table is still
// asked for — the agent resolves unknown kinds through discovery — with a
// v1 guess and the group the caller already knows.
const KNOWN: Record<string, GroupVersion> = {
  Pod: { group: '', version: 'v1' },
  Service: { group: '', version: 'v1' },
  ConfigMap: { group: '', version: 'v1' },
  Secret: { group: '', version: 'v1' },
  ServiceAccount: { group: '', version: 'v1' },
  PersistentVolumeClaim: { group: '', version: 'v1' },
  PersistentVolume: { group: '', version: 'v1' },
  Endpoints: { group: '', version: 'v1' },
  Node: { group: '', version: 'v1' },
  Namespace: { group: '', version: 'v1' },
  ResourceQuota: { group: '', version: 'v1' },
  Deployment: { group: 'apps', version: 'v1' },
  ReplicaSet: { group: 'apps', version: 'v1' },
  StatefulSet: { group: 'apps', version: 'v1' },
  DaemonSet: { group: 'apps', version: 'v1' },
  Job: { group: 'batch', version: 'v1' },
  CronJob: { group: 'batch', version: 'v1' },
  EndpointSlice: { group: 'discovery.k8s.io', version: 'v1' },
  HorizontalPodAutoscaler: { group: 'autoscaling', version: 'v2' },
  Ingress: { group: 'networking.k8s.io', version: 'v1' },
  NetworkPolicy: { group: 'networking.k8s.io', version: 'v1' },
  PodDisruptionBudget: { group: 'policy', version: 'v1' },
  StorageClass: { group: 'storage.k8s.io', version: 'v1' },
  Role: { group: 'rbac.authorization.k8s.io', version: 'v1' },
  RoleBinding: { group: 'rbac.authorization.k8s.io', version: 'v1' },
  ClusterRole: { group: 'rbac.authorization.k8s.io', version: 'v1' },
  ClusterRoleBinding: { group: 'rbac.authorization.k8s.io', version: 'v1' },
  Gateway: { group: 'gateway.networking.k8s.io', version: 'v1' },
  HTTPRoute: { group: 'gateway.networking.k8s.io', version: 'v1' },
  GRPCRoute: { group: 'gateway.networking.k8s.io', version: 'v1' },
  Certificate: { group: 'cert-manager.io', version: 'v1' },
  Application: { group: 'argoproj.io', version: 'v1alpha1' },
  ApplicationSet: { group: 'argoproj.io', version: 'v1alpha1' },
  Kustomization: { group: 'kustomize.toolkit.fluxcd.io', version: 'v1' },
  HelmRelease: { group: 'helm.toolkit.fluxcd.io', version: 'v2' },
  GitRepository: { group: 'source.toolkit.fluxcd.io', version: 'v1' },
  HelmRepository: { group: 'source.toolkit.fluxcd.io', version: 'v1' },
  OCIRepository: { group: 'source.toolkit.fluxcd.io', version: 'v1beta2' },
}

/** The API group a kind normally lives in, or undefined when unknown. */
export function defaultGroupFor(kind: string): string | undefined {
  return KNOWN[kind]?.group
}

/** The agent's "[group/]version/Kind" form ("apps/v1/Deployment", "v1/Pod"). */
export function gvkString(kind: string, apiGroup?: string): string {
  const known = KNOWN[kind]
  const group = apiGroup ?? known?.group ?? ''
  const version = known && known.group === group ? known.version : 'v1'
  return group ? `${group}/${version}/${kind}` : `${version}/${kind}`
}

/**
 * Parses both GVK wire forms ARGUS stores: "apps/v1/Deployment" / "v1/Pod",
 * and client-go's "apps/v1, Kind=Deployment". Group is undefined for core.
 */
export function parseGvk(gvk: string | null | undefined): { group?: string; version?: string; kind: string } {
  if (!gvk) return { kind: '' }
  const comma = /^(.*),\s*Kind=(.+)$/.exec(gvk)
  if (comma) {
    const gv = comma[1].trim().split('/')
    return gv.length === 2
      ? { group: gv[0] || undefined, version: gv[1], kind: comma[2].trim() }
      : { version: gv[0] || undefined, kind: comma[2].trim() }
  }
  const parts = gvk.split('/').filter(Boolean)
  if (parts.length >= 3) return { group: parts[0], version: parts[1], kind: parts[parts.length - 1] }
  if (parts.length === 2) return { version: parts[0], kind: parts[1] }
  return { kind: parts[0] ?? '' }
}

// Groups kubectl resolves a bare lowercase kind for without qualification.
const BUILTIN_GROUPS = new Set([
  '',
  'apps',
  'batch',
  'autoscaling',
  'policy',
  'networking.k8s.io',
  'discovery.k8s.io',
  'storage.k8s.io',
  'rbac.authorization.k8s.io',
])

/** How kubectl names a kind: "deployment", or "application.argoproj.io". */
export function kubectlResource(kind: string, apiGroup?: string): string {
  const group = apiGroup ?? defaultGroupFor(kind) ?? ''
  const lower = kind.toLowerCase()
  return BUILTIN_GROUPS.has(group) ? lower : `${lower}.${group}`
}

export const PATH_KINDS: ReadonlySet<string> = new Set(['Service', 'Ingress', 'HTTPRoute', 'GRPCRoute', 'Gateway'])
export const WORKLOAD_KINDS: ReadonlySet<string> = new Set(['Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet', 'Job'])
export const PERMISSION_KINDS: ReadonlySet<string> = new Set(['ServiceAccount', 'Pod', 'Deployment', 'StatefulSet', 'DaemonSet'])

// The GitOps controller kinds get_gitops_insight summarises directly
// (internal/agent/tools_insight_more.go gitOpsKinds).
export const GITOPS_KINDS: Readonly<Record<string, string>> = {
  Application: 'argoproj.io',
  ApplicationSet: 'argoproj.io',
  Kustomization: 'kustomize.toolkit.fluxcd.io',
  HelmRelease: 'helm.toolkit.fluxcd.io',
  GitRepository: 'source.toolkit.fluxcd.io',
  OCIRepository: 'source.toolkit.fluxcd.io',
  HelmRepository: 'source.toolkit.fluxcd.io',
}

export function isGitOpsKind(kind: string, apiGroup?: string): boolean {
  const g = GITOPS_KINDS[kind]
  return g !== undefined && (apiGroup === undefined || apiGroup === '' || apiGroup === g)
}

/** True when an object's labels/annotations say a GitOps controller manages
 *  it — the same markers the agent's gitOpsManaged checks. */
export function hasGitOpsMarkers(labels: Record<string, string> = {}, annotations: Record<string, string> = {}): boolean {
  if ('argocd.argoproj.io/tracking-id' in annotations) return true
  return Object.keys(labels).some(
    (k) =>
      k.startsWith('kustomize.toolkit.fluxcd.io/') ||
      k.startsWith('helm.toolkit.fluxcd.io/') ||
      k === 'argocd.argoproj.io/instance',
  )
}

// The closed set of hub quick actions (internal/api/quick_actions.go), one
// per GitOps kind. ApplicationSet has none: its Applications are refreshed,
// not the set.
const QUICK_ACTIONS: Record<string, { action: QuickAction; label: string }> = {
  Application: { action: 'argoRefresh', label: 'Request Argo refresh' },
  Kustomization: { action: 'fluxReconcileKs', label: 'Request Flux reconcile' },
  HelmRelease: { action: 'fluxReconcileHr', label: 'Request Flux reconcile' },
  GitRepository: { action: 'fluxReconcileGit', label: 'Request Flux reconcile' },
  HelmRepository: { action: 'fluxReconcileHelm', label: 'Request Flux reconcile' },
  OCIRepository: { action: 'fluxReconcileOci', label: 'Request Flux reconcile' },
}

export function quickActionFor(kind: string): { action: QuickAction; label: string } | null {
  return QUICK_ACTIONS[kind] ?? null
}
