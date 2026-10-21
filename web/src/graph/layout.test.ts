import { describe, expect, it, vi } from 'vitest'
import {
  applyHierarchicalLayout,
  buildHierarchicalElkGraph,
  buildInterGroupEdges,
  createLayoutRunner,
  ELK_OPTIONS_GROUP_LEVEL,
  ELK_OPTIONS_WITHIN_GROUP,
  getGroupKey,
  groupHealth,
  NODE_SIZE,
  propagateGroups,
  runTwoPhaseLayout,
  WorkerUnavailableError,
  type ElkGraph,
  type ElkLayoutFn,
  type LayoutResult,
} from './layout'
import type { GraphEdge, GraphNode, NodeStatus } from './types'

function deployment(ns: string, name: string, extra: Partial<GraphNode> = {}): GraphNode {
  return { id: `deployment/${ns}/${name}`, kind: 'Deployment', namespace: ns, name, status: 'healthy', ...extra }
}

function node(kind: string, ns: string, name: string, extra: Partial<GraphNode> = {}): GraphNode {
  return { id: `${kind.toLowerCase()}/${ns}/${name}`, kind, namespace: ns, name, status: 'healthy', ...extra }
}

const edge = (id: string, source: string, target: string, type = 'routes-to'): GraphEdge => ({ id, source, target, type })

// Every id ELK will see as a layoutable shape: top-level children plus group
// members. An edge endpoint outside this set makes ELK reject the graph.
function validEndpointIds(g: ElkGraph): Set<string> {
  const ids = new Set<string>()
  for (const child of g.children) {
    ids.add(child.id)
    for (const c of child.children ?? []) ids.add(c.id)
  }
  return ids
}

/** A stand-in for ELK: lays children out left to right with fixed spacing and
 *  records every graph it was asked to lay out. */
function fakeElk(): { layout: ElkLayoutFn; calls: ElkGraph[] } {
  const calls: ElkGraph[] = []
  const layout: ElkLayoutFn = async graph => {
    calls.push(graph)
    const children = graph.children.map((c, i) => ({ id: c.id, x: 10 + i * 300, y: 20, width: c.width, height: c.height }))
    return { id: graph.id, width: 10 + graph.children.length * 300, height: 150, children }
  }
  return { layout, calls }
}

describe('getGroupKey', () => {
  it('reads the namespace or the group field by mode', () => {
    const n = deployment('shop', 'web', { group: 'storefront' })
    expect(getGroupKey(n, 'none')).toBeNull()
    expect(getGroupKey(n, 'namespace')).toBe('shop')
    expect(getGroupKey(n, 'group')).toBe('storefront')
    expect(getGroupKey(node('Namespace', '', 'shop'), 'namespace')).toBeNull()
  })
})

describe('propagateGroups', () => {
  it('lets a node inherit its neighbour’s group within a namespace, transitively', () => {
    const d = deployment('shop', 'web', { group: 'storefront' })
    const rs = node('ReplicaSet', 'shop', 'web-1')
    const pod = node('Pod', 'shop', 'web-1-a')
    const keys = propagateGroups([d, rs, pod], [edge('e1', d.id, rs.id), edge('e2', rs.id, pod.id)])
    expect(keys.get(rs.id)).toBe('storefront')
    expect(keys.get(pod.id)).toBe('storefront')
  })

  it('does not propagate across namespaces or into a node touching two groups', () => {
    const a = deployment('shop', 'a', { group: 'A' })
    const b = deployment('shop', 'b', { group: 'B' })
    const shared = node('ConfigMap', 'shop', 'shared')
    const other = node('Service', 'other', 'svc')
    const keys = propagateGroups([a, b, shared, other], [edge('e1', a.id, shared.id), edge('e2', b.id, shared.id), edge('e3', a.id, other.id)])
    expect(keys.has(shared.id)).toBe(false)
    expect(keys.has(other.id)).toBe(false)
  })

  it('groups connected unlabelled nodes under their most representative member and leaves singletons alone', () => {
    const svc = node('Service', 'shop', 'api')
    const d = deployment('shop', 'api-server')
    const lone = node('ConfigMap', 'shop', 'lone')
    const keys = propagateGroups([svc, d, lone], [edge('e1', svc.id, d.id)])
    expect(keys.get(svc.id)).toBe('api-server')
    expect(keys.get(d.id)).toBe('api-server')
    expect(keys.has(lone.id)).toBe(false)
  })
})

describe('buildHierarchicalElkGraph', () => {
  it('puts members inside their group with the within-group options', () => {
    const nodes = [deployment('app1', 'web'), deployment('app1', 'api'), deployment('app2', 'db')]
    const { elkGraph, groupMap, nodeToGroup } = buildHierarchicalElkGraph(nodes, [], 'namespace')
    const app1 = elkGraph.children.find(c => c.id === 'group-namespace-app1')!
    expect(app1.children?.map(c => c.id)).toEqual(['deployment/app1/web', 'deployment/app1/api'])
    expect(app1.children?.[0]).toMatchObject({ width: NODE_SIZE.width, height: NODE_SIZE.height })
    expect(app1.layoutOptions).toMatchObject(ELK_OPTIONS_WITHIN_GROUP)
    expect(app1.layoutOptions?.['elk.padding']).toContain('top=')
    expect(groupMap.get('app2')).toEqual(['deployment/app2/db'])
    expect(nodeToGroup.get('deployment/app1/api')).toBe('group-namespace-app1')
  })

  it('keeps edges between groups referencing plain member ids', () => {
    const nodes = [deployment('app1', 'web'), deployment('app2', 'api')]
    const { elkGraph } = buildHierarchicalElkGraph(nodes, [edge('e1', 'deployment/app1/web', 'deployment/app2/api')], 'namespace')
    const valid = validEndpointIds(elkGraph)
    for (const e of elkGraph.edges) {
      expect(valid.has(e.sources[0])).toBe(true)
      expect(valid.has(e.targets[0])).toBe(true)
    }
    expect(elkGraph.edges.flatMap(e => [...e.sources, ...e.targets])).toEqual(['deployment/app1/web', 'deployment/app2/api'])
  })

  it('produces no dangling endpoints with no grouping', () => {
    const nodes = [deployment('app1', 'web'), deployment('app1', 'api')]
    const { elkGraph } = buildHierarchicalElkGraph(nodes, [edge('e1', 'deployment/app1/web', 'deployment/app1/api')], 'none')
    expect(elkGraph.children.every(c => !c.children)).toBe(true)
    const valid = validEndpointIds(elkGraph)
    for (const e of elkGraph.edges) {
      expect(valid.has(e.sources[0])).toBe(true)
      expect(valid.has(e.targets[0])).toBe(true)
    }
  })

  it('drops edges to unknown nodes, self-loops and duplicate pairs', () => {
    const nodes = [deployment('app1', 'web'), deployment('app1', 'api')]
    const { elkGraph } = buildHierarchicalElkGraph(
      nodes,
      [
        edge('e1', 'deployment/app1/web', 'deployment/app1/api'),
        edge('e2', 'deployment/app1/web', 'deployment/app1/api', 'selects'),
        edge('e3', 'deployment/app1/web', 'deployment/app1/web'),
        edge('e4', 'deployment/app1/web', 'ghost'),
      ],
      'namespace',
    )
    expect(elkGraph.edges.map(e => e.id)).toEqual(['e1'])
  })

  it('leaves nodes with no group key at the top level', () => {
    const nodes = [deployment('app1', 'web'), node('Node', '', 'worker-1')]
    const { elkGraph } = buildHierarchicalElkGraph(nodes, [], 'namespace')
    expect(elkGraph.children.map(c => c.id)).toEqual(['group-namespace-app1', 'node//worker-1'])
  })

  it('uses propagated keys in group mode', () => {
    const d = deployment('shop', 'web', { group: 'storefront' })
    const pod = node('Pod', 'shop', 'web-a')
    const { groupMap } = buildHierarchicalElkGraph([d, pod], [edge('e1', d.id, pod.id)], 'group')
    expect(groupMap.get('storefront')).toEqual([d.id, pod.id])
  })
})

describe('buildInterGroupEdges — group-level connectivity', () => {
  // Two namespaces' groups (storefront: web + cart; billing: ledger) and one
  // ungrouped node, the way buildHierarchicalElkGraph reports them.
  const nodeToGroup = new Map([
    ['deployment/storefront/web', 'group-namespace-storefront'],
    ['deployment/storefront/cart', 'group-namespace-storefront'],
    ['deployment/billing/ledger', 'group-namespace-billing'],
  ])
  const metaIds = new Set(['group-namespace-storefront', 'group-namespace-billing', 'node//worker-3'])
  const link = (from: string, to: string) => buildInterGroupEdges([{ id: 'x', sources: [from], targets: [to] }], nodeToGroup, metaIds)

  it('lifts a member to its group, and leaves an ungrouped node as itself', () => {
    expect(link('deployment/storefront/cart', 'deployment/billing/ledger')).toEqual([
      { id: 'inter-group-namespace-storefront->group-namespace-billing', sources: ['group-namespace-storefront'], targets: ['group-namespace-billing'] },
    ])
    expect(link('node//worker-3', 'deployment/storefront/web')[0]).toMatchObject({ sources: ['node//worker-3'], targets: ['group-namespace-storefront'] })
  })

  it('has nothing to say about an edge inside one group, or to an id it does not place', () => {
    expect(link('deployment/storefront/web', 'deployment/storefront/cart')).toEqual([])
    expect(link('group-namespace-billing', 'deployment/elsewhere/unknown')).toEqual([])
  })

  it('collapses several member edges between the same two groups into one', () => {
    const out = buildInterGroupEdges(
      [
        { id: 'a', sources: ['deployment/storefront/web'], targets: ['deployment/billing/ledger'] },
        { id: 'b', sources: ['deployment/storefront/cart'], targets: ['deployment/billing/ledger'] },
        { id: 'c', sources: ['deployment/billing/ledger'], targets: ['deployment/storefront/web'] },
      ],
      nodeToGroup,
      metaIds,
    )
    // The reverse direction is a different pair and stays.
    expect(out.map(e => `${e.sources[0]} > ${e.targets[0]}`)).toEqual([
      'group-namespace-storefront > group-namespace-billing',
      'group-namespace-billing > group-namespace-storefront',
    ])
  })
})

describe('runTwoPhaseLayout', () => {
  const nodes = [deployment('app1', 'web'), deployment('app1', 'api'), deployment('app2', 'db'), node('Node', '', 'n1')]
  const edges = [
    edge('e1', 'deployment/app1/web', 'deployment/app1/api'),
    edge('e2', 'deployment/app1/api', 'deployment/app2/db'),
  ]

  it('lays out each group with only its own edges, then places groups with the group-level options', async () => {
    const { elkGraph } = buildHierarchicalElkGraph(nodes, edges, 'namespace')
    const elk = fakeElk()
    const result = await runTwoPhaseLayout(elk.layout, { elkGraph, hideGroupHeader: false })

    expect(elk.calls.map(c => c.id)).toEqual(['group-namespace-app1', 'group-namespace-app2', 'meta-root'])
    expect(elk.calls[0].edges.map(e => e.id)).toEqual(['e1'])
    expect(elk.calls[1].edges).toEqual([])
    const meta = elk.calls[2]
    expect(meta.layoutOptions).toMatchObject(ELK_OPTIONS_GROUP_LEVEL)
    expect(meta.children.map(c => c.id)).toEqual(['group-namespace-app1', 'group-namespace-app2', 'node//n1'])
    expect(meta.edges).toEqual([{ id: 'inter-group-namespace-app1->group-namespace-app2', sources: ['group-namespace-app1'], targets: ['group-namespace-app2'] }])

    expect(result.groupLayouts.map(g => g.groupKey)).toEqual(['app1', 'app2'])
    expect(result.ungroupedNodes.map(n => n.id)).toEqual(['node//n1'])
    expect(result.positions.map(([id]) => id)).toEqual(['group-namespace-app1', 'group-namespace-app2', 'node//n1'])
  })

  it('flows the way it is asked at both levels — DOWN for a narrow panel, RIGHT by default', async () => {
    const { elkGraph } = buildHierarchicalElkGraph(nodes, edges, 'namespace')
    const down = fakeElk()
    await runTwoPhaseLayout(down.layout, { elkGraph, hideGroupHeader: false, direction: 'DOWN' })
    expect(down.calls.map(c => c.layoutOptions?.['elk.direction'])).toEqual(['DOWN', 'DOWN', 'DOWN'])
    const right = fakeElk()
    await runTwoPhaseLayout(right.layout, { elkGraph, hideGroupHeader: false })
    expect(right.calls.map(c => c.layoutOptions?.['elk.direction'])).toEqual(['RIGHT', 'RIGHT', 'RIGHT'])
  })

  it('widens a group to fit its header unless the header is hidden', async () => {
    const { elkGraph } = buildHierarchicalElkGraph([deployment('a-very-long-namespace-name', 'x')], [], 'namespace')
    const shown = await runTwoPhaseLayout(fakeElk().layout, { elkGraph, hideGroupHeader: false })
    const hidden = await runTwoPhaseLayout(fakeElk().layout, { elkGraph, hideGroupHeader: true })
    expect(shown.groupLayouts[0].width).toBe(Math.max(500, 'a-very-long-namespace-name'.length * 16 + 200))
    expect(hidden.groupLayouts[0].width).toBe(310)
  })
})

describe('createLayoutRunner', () => {
  const request = { elkGraph: buildHierarchicalElkGraph([deployment('a', 'b')], [], 'none').elkGraph, hideGroupHeader: false }
  const workerResult: LayoutResult = { groupLayouts: [], ungroupedNodes: [], positions: [['from-worker', { x: 0, y: 0 }]] }

  it('runs small graphs on the main thread and large ones in the worker', async () => {
    const worker = vi.fn(async () => workerResult)
    const run = createLayoutRunner({ mainThread: fakeElk().layout, worker })
    await run(request, 39)
    expect(worker).not.toHaveBeenCalled()
    expect(await run(request, 40)).toBe(workerResult)
    expect(worker).toHaveBeenCalledTimes(1)
  })

  it('falls back to the main thread for good once the worker is unavailable', async () => {
    const worker = vi.fn(async (): Promise<LayoutResult> => {
      throw new WorkerUnavailableError()
    })
    const run = createLayoutRunner({ mainThread: fakeElk().layout, worker })
    const first = await run(request, 100)
    expect(first.positions.map(([id]) => id)).toEqual(['deployment/a/b'])
    await run(request, 100)
    expect(worker).toHaveBeenCalledTimes(1)
  })

  it('propagates a layout error from inside the worker', async () => {
    const run = createLayoutRunner({ mainThread: fakeElk().layout, worker: async () => { throw new Error('bad graph') } })
    await expect(run(request, 100)).rejects.toThrow('bad graph')
  })

  it('uses the main thread when no worker is available', async () => {
    const run = createLayoutRunner({ mainThread: fakeElk().layout })
    expect((await run(request, 1000)).positions).toHaveLength(1)
  })
})

describe('applyHierarchicalLayout', () => {
  const nodes = [
    deployment('app1', 'web', { status: 'unhealthy', statusReason: '0/3 ready' }),
    deployment('app1', 'api', { status: 'degraded' }),
    deployment('app2', 'db'),
    node('Node', '', 'n1'),
  ]
  const edges = [edge('e1', 'deployment/app1/web', 'deployment/app2/db')]
  const runner = createLayoutRunner({ mainThread: fakeElk().layout })

  it('emits group boxes with health roll-ups and members positioned inside them', async () => {
    const graph = buildHierarchicalElkGraph(nodes, edges, 'namespace')
    const { nodes: out, positions, error } = await applyHierarchicalLayout(graph, nodes, 'namespace', runner)
    expect(error).toBeUndefined()
    const group = out.find(n => n.id === 'group-namespace-app1')!
    expect(group.type).toBe('group')
    expect(group.data).toMatchObject({ name: 'app1', nodeCount: 2, worstStatus: 'unhealthy', unhealthyCount: 2 })
    const web = out.find(n => n.id === 'deployment/app1/web')!
    expect(web).toMatchObject({ type: 'resource', parentId: 'group-namespace-app1', extent: 'parent' })
    expect(web.data).toMatchObject({ node: { statusReason: '0/3 ready' } })
    const groupPos = positions.get('group-namespace-app1')!
    expect(positions.get('deployment/app1/web')).toEqual({ x: groupPos.x + web.position.x, y: groupPos.y + web.position.y })
    expect(out.find(n => n.id === 'node//n1')).toMatchObject({ type: 'resource' })
    expect(out.find(n => n.id === 'node//n1')?.parentId).toBeUndefined()
  })

  it('omits the group box and uses absolute positions when the header is hidden', async () => {
    const single = [deployment('app1', 'web'), deployment('app1', 'api')]
    const graph = buildHierarchicalElkGraph(single, [], 'namespace', true)
    const { nodes: out, positions } = await applyHierarchicalLayout(graph, single, 'namespace', runner, true)
    expect(out.every(n => n.type === 'resource' && n.parentId === undefined)).toBe(true)
    for (const n of out) expect(positions.get(n.id)).toEqual(n.position)
  })

  it('returns an error and no nodes when layout fails', async () => {
    const failing = createLayoutRunner({ mainThread: async () => { throw new Error('elk exploded') } })
    const graph = buildHierarchicalElkGraph(nodes, edges, 'namespace')
    const result = await applyHierarchicalLayout(graph, nodes, 'namespace', failing)
    expect(result.nodes).toEqual([])
    expect(result.error).toBe('Layout failed: elk exploded')
  })
})

describe('groupHealth', () => {
  const of = (...statuses: NodeStatus[]) => statuses.map((status, i) => deployment('x', `n${i}`, { status }))

  it('rolls up to the least healthy member', () => {
    expect(groupHealth(of('healthy', 'degraded', 'unknown')).worstStatus).toBe('degraded')
    expect(groupHealth(of('healthy', 'neutral')).worstStatus).toBe('healthy')
    expect(groupHealth(of('neutral', 'neutral')).worstStatus).toBe('neutral')
    expect(groupHealth(of('unhealthy', 'degraded', 'healthy')).unhealthyCount).toBe(2)
  })
})
