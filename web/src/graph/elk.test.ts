import { describe, expect, it } from 'vitest'
import { elkLayout } from './elk'
import { applyHierarchicalLayout, buildHierarchicalElkGraph, createLayoutRunner } from './layout'
import type { GraphNode } from './types'

const n = (ns: string, name: string): GraphNode => ({ id: `${ns}/${name}`, kind: 'Deployment', namespace: ns, name, status: 'healthy' })

// One end-to-end run against the real ELK, so the option sets are known to be
// accepted and the two phases compose into non-overlapping groups.
describe('layout with ELK', () => {
  it('places two connected groups without overlap', async () => {
    const nodes = [n('a', 'web'), n('a', 'api'), n('b', 'db')]
    const edges = [
      { id: 'e1', source: 'a/web', target: 'a/api', type: 'routes-to' },
      { id: 'e2', source: 'a/api', target: 'b/db', type: 'routes-to' },
    ]
    const graph = buildHierarchicalElkGraph(nodes, edges, 'namespace')
    const { nodes: out, error } = await applyHierarchicalLayout(graph, nodes, 'namespace', createLayoutRunner({ mainThread: elkLayout }))
    expect(error).toBeUndefined()
    const box = (id: string) => {
      const g = out.find(x => x.id === id)!
      return { x: g.position.x, w: Number(g.style?.width) }
    }
    const a = box('group-namespace-a')
    const b = box('group-namespace-b')
    expect(b.x).toBeGreaterThanOrEqual(a.x + a.w)
    const web = out.find(x => x.id === 'a/web')!
    const api = out.find(x => x.id === 'a/api')!
    expect(api.position.x).toBeGreaterThan(web.position.x)
  })
})
