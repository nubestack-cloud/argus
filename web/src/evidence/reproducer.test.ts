import { describe, expect, it } from 'vitest'
import { describeArgs, objectRefFromToolCall, reproducerFor } from './reproducer'

describe('reproducerFor', () => {
  it('describe_resource → kubectl get -o yaml, namespaced and core', () => {
    expect(reproducerFor('describe_resource', { gvk: 'apps/v1/Deployment', namespace: 'payments', name: 'api' })).toBe(
      'kubectl -n payments get deployment api -o yaml',
    )
    expect(reproducerFor('describe_resource', { gvk: 'v1/Pod', namespace: 'payments', name: 'api-1' })).toBe(
      'kubectl -n payments get pod api-1 -o yaml',
    )
  })

  it('qualifies a CRD kind with its group and omits -n for cluster-scoped objects', () => {
    expect(reproducerFor('describe_resource', { gvk: 'argoproj.io/v1alpha1/Application', namespace: 'argocd', name: 'shop' })).toBe(
      'kubectl -n argocd get application.argoproj.io shop -o yaml',
    )
    expect(reproducerFor('describe_resource', { gvk: 'v1/Node', name: 'worker-1' })).toBe('kubectl get node worker-1 -o yaml')
  })

  it('get_events → field selector on the involved object name', () => {
    expect(
      reproducerFor('get_events', { namespace: 'payments', involvedObjectKind: 'Pod', involvedObjectName: 'api-1' }),
    ).toBe('kubectl -n payments get events --field-selector involvedObject.name=api-1')
  })

  it('get_logs → logs with container and --previous only when asked', () => {
    expect(reproducerFor('get_logs', { namespace: 'payments', pod: 'api-1', container: 'app' })).toBe(
      'kubectl -n payments logs api-1 -c app',
    )
    expect(reproducerFor('get_logs', { namespace: 'payments', pod: 'api-1', container: 'app', previous: true, tailLines: 200 })).toBe(
      'kubectl -n payments logs api-1 -c app --previous --tail=200',
    )
    expect(reproducerFor('get_logs', { pod: 'api-1' })).toBeNull()
  })

  it('query_metrics → the PromQL itself', () => {
    expect(reproducerFor('query_metrics', { promql: 'up{job="x"}' })).toBe('up{job="x"}')
    expect(reproducerFor('query_metrics', { query: 'sum(rate(a[5m]))' })).toBe('sum(rate(a[5m]))')
    expect(reproducerFor('query_metrics', {})).toBeNull()
  })

  it('get_neighborhood / get_owner_chain → the object as YAML', () => {
    expect(reproducerFor('get_neighborhood', { kind: 'Deployment', apiGroup: 'apps', namespace: 'p', name: 'api' })).toBe(
      'kubectl -n p get deployment api -o yaml',
    )
    expect(reproducerFor('get_owner_chain', { gvk: 'v1/Pod', namespace: 'p', name: 'api-1', direction: 'up' })).toBe(
      'kubectl -n p get pod api-1 -o yaml',
    )
  })

  it('trace_service_path on a Service lists its endpoint slices', () => {
    expect(reproducerFor('trace_service_path', { kind: 'Service', namespace: 'p', name: 'api' })).toBe(
      'kubectl -n p get endpointslices -l kubernetes.io/service-name=api',
    )
  })

  it('get_subject_permissions impersonates the service account read-only', () => {
    expect(reproducerFor('get_subject_permissions', { kind: 'ServiceAccount', namespace: 'p', name: 'api' })).toBe(
      'kubectl auth can-i --list -n p --as=system:serviceaccount:p:api',
    )
  })

  it('quotes values that need it and refuses an unknown tool', () => {
    expect(reproducerFor('get_events', { namespace: 'p', involvedObjectName: "a b'c" })).toBe(
      `kubectl -n p get events --field-selector involvedObject.name='a b'\\''c'`,
    )
    expect(reproducerFor('scale_deployment', { namespace: 'p', name: 'x' })).toBeNull()
    expect(reproducerFor('describe_resource', null)).toBeNull()
  })
})

describe('objectRefFromToolCall', () => {
  it('reads gvk-shaped args', () => {
    expect(objectRefFromToolCall('describe_resource', { gvk: 'apps/v1/Deployment', namespace: 'p', name: 'api' }, 'c1')).toEqual({
      clusterId: 'c1',
      kind: 'Deployment',
      apiGroup: 'apps',
      namespace: 'p',
      name: 'api',
    })
  })

  it('reads kind-shaped and pod-shaped args', () => {
    expect(objectRefFromToolCall('get_logs', { namespace: 'p', pod: 'api-1' }, 'c1')).toEqual({
      clusterId: 'c1',
      kind: 'Pod',
      namespace: 'p',
      name: 'api-1',
    })
    expect(objectRefFromToolCall('get_events', { namespace: 'p', involvedObjectKind: 'Pod', involvedObjectName: 'x' }, 'c1')?.name).toBe('x')
  })

  it('names no object for list and metrics calls, or a User subject', () => {
    expect(objectRefFromToolCall('query_metrics', { promql: 'up' }, 'c1')).toBeNull()
    expect(objectRefFromToolCall('get_subject_permissions', { kind: 'User', name: 'alice' }, 'c1')).toBeNull()
  })
})

describe('describeArgs', () => {
  it('fills the version the agent needs', () => {
    expect(describeArgs({ kind: 'HorizontalPodAutoscaler', namespace: 'p', name: 'api' })).toEqual({
      gvk: 'autoscaling/v2/HorizontalPodAutoscaler',
      namespace: 'p',
      name: 'api',
    })
    expect(describeArgs({ kind: 'Pod', name: 'x' })).toEqual({ gvk: 'v1/Pod', namespace: '', name: 'x' })
  })
})
