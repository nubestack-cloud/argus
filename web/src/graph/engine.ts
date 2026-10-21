// The app's layout entry point: binds the pure layout code to a real ELK
// (main thread, elk.ts) and to the layout worker, choosing between them by
// graph size (see createLayoutRunner).

import { elkLayout } from './elk'
import {
  applyHierarchicalLayout,
  buildHierarchicalElkGraph,
  createLayoutRunner,
  WorkerUnavailableError,
  type LayoutDirection,
  type LayoutRequest,
  type LayoutResult,
  type PositionedGraph,
} from './layout'
import type { GraphEdge, GraphNode, GroupingMode } from './types'

export interface LayoutWorkerRequest {
  requestId: number
  request: LayoutRequest
}

export type LayoutWorkerResponse =
  | { requestId: number; result: LayoutResult; error?: undefined }
  | { requestId: number; error: string; result?: undefined }

let worker: Worker | null = null
let nextRequestId = 0
const pending = new Map<number, { resolve: (r: LayoutResult) => void; reject: (e: Error) => void }>()

function failWorker(): void {
  for (const p of pending.values()) p.reject(new WorkerUnavailableError())
  pending.clear()
  worker?.terminate()
  worker = null
}

function getWorker(): Worker {
  if (worker) return worker
  const w = new Worker(new URL('./layout.worker.ts', import.meta.url), { type: 'module' })
  w.onmessage = (e: MessageEvent<LayoutWorkerResponse>) => {
    const p = pending.get(e.data.requestId)
    if (!p) return
    pending.delete(e.data.requestId)
    if (e.data.error !== undefined) p.reject(new Error(e.data.error))
    else p.resolve(e.data.result)
  }
  // A worker-level error (script failed to load, CSP) means the worker cannot
  // run at all; the runner then stays on the main thread.
  w.onerror = () => failWorker()
  worker = w
  return w
}

function layoutInWorker(request: LayoutRequest): Promise<LayoutResult> {
  return new Promise((resolve, reject) => {
    try {
      const requestId = ++nextRequestId
      pending.set(requestId, { resolve, reject })
      getWorker().postMessage({ requestId, request } satisfies LayoutWorkerRequest)
    } catch {
      failWorker()
      reject(new WorkerUnavailableError())
    }
  })
}

const runner = createLayoutRunner({
  mainThread: elkLayout,
  worker: typeof Worker === 'undefined' ? undefined : layoutInWorker,
})

/** Builds and lays out a graph for the canvas. */
export function layoutGraph(
  nodes: readonly GraphNode[],
  edges: readonly GraphEdge[],
  mode: GroupingMode,
  hideGroupHeader = false,
  direction: LayoutDirection = 'RIGHT',
): Promise<PositionedGraph> {
  const graph = buildHierarchicalElkGraph(nodes, edges, mode, hideGroupHeader)
  return applyHierarchicalLayout(graph, nodes, mode, runner, hideGroupHeader, direction)
}
