// The graph shapes every ARGUS node/edge view draws (relationship map, traffic
// map, path overlays). Producers fill these; layout and rendering read only
// these.

/** Health of one object. The renderer always prints it as text beside any
 *  colour, so a status is never carried by colour alone. */
export type NodeStatus = 'healthy' | 'degraded' | 'unhealthy' | 'neutral' | 'unknown'

export interface GraphNode {
  /** Unique within one graph; edges reference it. */
  id: string
  kind: string
  apiGroup?: string
  namespace?: string
  name: string
  status: NodeStatus
  /** Short text explaining a non-healthy status, e.g. "0/3 ready". */
  statusReason?: string
  /** Grouping key for `grouping: 'group'` (an app label, an owner). Nodes
   *  without one inherit it from same-namespace neighbours. */
  group?: string
}

export interface GraphEdge {
  id: string
  source: string
  target: string
  /** Relationship type, named in the edge legend (e.g. "owns", "selects",
   *  "routes-to", "mounts"). */
  type: string
}

/** How nodes are boxed: not at all, by namespace, or by `GraphNode.group`. */
export type GroupingMode = 'none' | 'namespace' | 'group'
