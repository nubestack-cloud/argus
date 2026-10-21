// "Check it yourself" (docs/CLUSTER_INSIGHT_SPECS.md CI-U9): a pure mapping
// from one agent tool call to a read-only command an operator can run with
// their own credentials to re-derive the same evidence outside ARGUS.
//
// Commands never carry `--context`: the caller names the cluster in words
// beside them (components/Reproducer), so a pasted command cannot silently
// target whichever context happens to be current. Every command is read-only
// (get/describe/logs/auth can-i/helm history) — nothing here mutates.
//
// Returns null when no honest command exists (an unknown tool, or arguments
// missing the identity a command needs). A guessed command is worse than none.

import { gvkString, kubectlResource, parseGvk } from '../insight/kinds'
import type { ObjectRef } from '../insight/panelUrl'

type Args = Record<string, unknown>

function str(v: unknown): string {
  return typeof v === 'string' ? v.trim() : ''
}

// Shell-quotes a value only when it needs it, so the common case
// (`kubectl -n payments get pod api-1`) stays readable.
function q(v: string): string {
  return /^[A-Za-z0-9._:/=@%+,-]+$/.test(v) ? v : `'${v.replace(/'/g, `'\\''`)}'`
}

function ns(namespace: string): string {
  return namespace ? `-n ${q(namespace)} ` : ''
}

function getYaml(kind: string, group: string | undefined, namespace: string, name: string): string | null {
  if (!kind || !name) return null
  return `kubectl ${ns(namespace)}get ${kubectlResource(kind, group)} ${q(name)} -o yaml`
}

export function reproducerFor(tool: string, args: Args | null | undefined): string | null {
  const a = args ?? {}
  const namespace = str(a.namespace)
  const name = str(a.name)
  switch (tool) {
    case 'describe_resource':
    case 'get_owner_chain':
    case 'get_gitops_ownership': {
      const p = parseGvk(str(a.gvk))
      return getYaml(p.kind, p.group, namespace, name)
    }
    case 'get_events': {
      const target = str(a.involvedObjectName) || name
      if (!target) return namespace ? `kubectl ${ns(namespace)}get events` : null
      return `kubectl ${ns(namespace)}get events --field-selector involvedObject.name=${q(target)}`
    }
    case 'get_logs': {
      const pod = str(a.pod) || name
      if (!pod || !namespace) return null
      const container = str(a.container)
      const tail = typeof a.tailLines === 'number' && a.tailLines > 0 ? ` --tail=${a.tailLines}` : ''
      return `kubectl ${ns(namespace)}logs ${q(pod)}${container ? ` -c ${q(container)}` : ''}${a.previous === true ? ' --previous' : ''}${tail}`
    }
    case 'query_metrics': {
      const promql = str(a.promql) || str(a.query)
      return promql || null
    }
    case 'get_neighborhood':
    case 'get_gitops_insight':
    case 'get_policy_findings': {
      const kind = str(a.kind)
      const group = str(a.apiGroup) || str(a.group) || undefined
      return getYaml(kind, group, namespace, name)
    }
    case 'trace_service_path': {
      const kind = str(a.kind)
      if (kind === 'Service' && name) {
        return `kubectl ${ns(namespace)}get endpointslices -l kubernetes.io/service-name=${q(name)}`
      }
      return getYaml(kind, undefined, namespace, name)
    }
    case 'list_resources': {
      const kind = str(a.kind) || parseGvk(str(a.gvk)).kind
      if (!kind) return null
      const selector = str(a.labelSelector)
      return `kubectl ${ns(namespace)}get ${kubectlResource(kind, parseGvk(str(a.gvk)).group)}${selector ? ` -l ${q(selector)}` : ''}`
    }
    case 'get_subject_permissions': {
      const kind = str(a.kind)
      if (!name) return null
      if (kind === 'ServiceAccount') {
        if (!namespace) return null
        return `kubectl auth can-i --list -n ${q(namespace)} --as=system:serviceaccount:${namespace}:${name}`
      }
      if (kind === 'User') return `kubectl auth can-i --list --as=${q(name)}`
      if (kind === 'Group') return `kubectl auth can-i --list --as=argus-check --as-group=${q(name)}`
      return null
    }
    case 'explain_scheduling': {
      const pod = str(a.pod) || name
      if (!pod || !namespace) return null
      return `kubectl ${ns(namespace)}get events --field-selector involvedObject.name=${q(pod)},reason=FailedScheduling`
    }
    case 'get_drain_impact': {
      const node = str(a.node)
      return node ? `kubectl drain ${q(node)} --ignore-daemonsets --delete-emptydir-data --dry-run=server` : null
    }
    case 'diagnose_autoscaler':
      return name && namespace ? `kubectl ${ns(namespace)}describe hpa ${q(name)}` : null
    case 'diagnose_rollout':
      return name && namespace ? `kubectl ${ns(namespace)}get deployment ${q(name)} -o jsonpath='{.spec.strategy}'` : null
    case 'get_helm_release_status':
      return name && namespace ? `helm ${ns(namespace)}history ${q(name)}` : null
    case 'evaluate_network_policy': {
      const dst = (a.destination ?? {}) as Args
      const dns = str(dst.namespace)
      return dns ? `kubectl ${ns(dns)}get networkpolicy -o yaml` : null
    }
    default:
      return null
  }
}

/**
 * The object a tool call was about, when its arguments name one, so the
 * evidence chip can open it in the inspector. Null for calls that name no
 * single object (a list, a metrics query).
 */
export function objectRefFromToolCall(tool: string, args: Args | null | undefined, clusterId: string): ObjectRef | null {
  const a = args ?? {}
  const namespace = str(a.namespace) || undefined
  switch (tool) {
    case 'describe_resource':
    case 'get_owner_chain':
    case 'get_gitops_ownership': {
      const p = parseGvk(str(a.gvk))
      const name = str(a.name)
      if (!p.kind || !name) return null
      return { clusterId, kind: p.kind, apiGroup: p.group || undefined, namespace, name }
    }
    case 'get_events': {
      const kind = str(a.involvedObjectKind)
      const name = str(a.involvedObjectName)
      if (!kind || !name) return null
      return { clusterId, kind, namespace, name }
    }
    case 'get_logs': {
      const pod = str(a.pod)
      return pod ? { clusterId, kind: 'Pod', namespace, name: pod } : null
    }
    case 'explain_scheduling': {
      const pod = str(a.pod)
      return pod ? { clusterId, kind: 'Pod', namespace, name: pod } : null
    }
    case 'get_drain_impact': {
      const node = str(a.node)
      return node ? { clusterId, kind: 'Node', name: node } : null
    }
    case 'diagnose_autoscaler': {
      const name = str(a.name)
      return name ? { clusterId, kind: 'HorizontalPodAutoscaler', apiGroup: 'autoscaling', namespace, name } : null
    }
    case 'diagnose_rollout': {
      const name = str(a.name)
      return name ? { clusterId, kind: 'Deployment', apiGroup: 'apps', namespace, name } : null
    }
    case 'get_neighborhood':
    case 'trace_service_path':
    case 'get_gitops_insight':
    case 'get_policy_findings':
    case 'get_subject_permissions': {
      const kind = str(a.kind)
      const name = str(a.name)
      if (!kind || !name || kind === 'User' || kind === 'Group') return null
      return { clusterId, kind, apiGroup: str(a.apiGroup) || str(a.group) || undefined, namespace, name }
    }
    default:
      return null
  }
}

/** The describe_resource arguments for an inspector object. */
export function describeArgs(o: Pick<ObjectRef, 'kind' | 'apiGroup' | 'namespace' | 'name'>): Args {
  return { gvk: gvkString(o.kind, o.apiGroup), namespace: o.namespace ?? '', name: o.name }
}
