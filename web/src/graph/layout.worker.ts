// Runs the two-phase layout off the main thread for large graphs. Same code
// path as the main thread (runTwoPhaseLayout); only the thread differs.

import { elkLayout } from './elk'

// elk.bundled.js decides it is ELK's own worker script when it loads where
// `document` is undefined and `self` is defined — exactly this worker — and
// then replaces self.onmessage with its own dispatcher instead of exporting
// the ELK class. Our handler is gone after the first (lazy) import and the
// layout never answers, so every graph of WORKER_NODE_THRESHOLD nodes or more
// stayed a skeleton. A stand-in `document` makes it take its module branch,
// the same one it takes on the main thread. Set at module evaluation, before
// elk.ts's dynamic import of elkjs can run.
;(globalThis as { document?: unknown }).document ??= {}
import { runTwoPhaseLayout } from './layout'
import type { LayoutWorkerRequest, LayoutWorkerResponse } from './engine'

self.onmessage = async (e: MessageEvent<LayoutWorkerRequest>) => {
  const { requestId, request } = e.data
  let response: LayoutWorkerResponse
  try {
    response = { requestId, result: await runTwoPhaseLayout(elkLayout, request) }
  } catch (err) {
    response = { requestId, error: err instanceof Error ? err.message : String(err) }
  }
  self.postMessage(response)
}
