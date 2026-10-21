// The one binding to elkjs. The bundled build runs the algorithm in the
// calling thread: on the main thread for small graphs, and inside
// layout.worker.ts for large ones. Loaded on first use so pages without a
// graph never download it.

import type { ElkLayoutFn, ElkLayoutNode } from './layout'

type ElkInstance = { layout: (graph: never) => Promise<unknown> }

let elk: Promise<ElkInstance> | null = null

export const elkLayout: ElkLayoutFn = async graph => {
  elk ??= import('elkjs/lib/elk.bundled.js').then(m => new m.default() as unknown as ElkInstance)
  return (await (await elk).layout(graph as never)) as ElkLayoutNode
}
