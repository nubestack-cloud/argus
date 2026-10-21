// Hierarchical graph layout over ELK. Two phases: each group's members are laid
// out inside the group, then groups (and ungrouped nodes) are placed relative
// to each other from the edges that cross between them.
//
// Everything here is pure or takes the ELK call as a parameter, so it is
// testable without elkjs and the same two-phase code runs on the main thread
// and in the layout worker. Binding to a real ELK instance lives in elk.ts and
// engine.ts.

import type { Node } from '@xyflow/react'
import type { GraphEdge, GraphNode, GroupingMode, NodeStatus } from './types'

// ---------------------------------------------------------------------------
// ELK shapes and options
// ---------------------------------------------------------------------------

interface Box {
  width?: number
  height?: number
}

/** A node handed to ELK: a leaf, or a compound node whose children ELK places inside it. */
export interface ElkNode extends Box {
  id: string
  labels?: Array<{ text: string }>
  layoutOptions?: Record<string, string>
  children?: ElkNode[]
}

/** ELK's edge shape: lists of endpoints, though every edge here has one of each. */
export interface ElkEdge {
  id: string
  sources: string[]
  targets: string[]
}

export interface ElkGraph {
  id: string
  layoutOptions: Record<string, string>
  children: ElkNode[]
  edges: ElkEdge[]
}

/** What ELK hands back for a node: where it put it, and its laid-out children. */
export interface ElkLayoutNode extends Box {
  id: string
  x?: number
  y?: number
  children?: ElkLayoutNode[]
}

/** One ELK layout call. */
export type ElkLayoutFn = (graph: ElkGraph) => Promise<ElkLayoutNode>

/**
 * Both phases run ELK's layered algorithm left to right, keeping the order the
 * nodes and edges were given in and routing edges orthogonally; they differ
 * only in spacing. Within a group nodes sit closer, and the gap between an
 * edge and the next layer is set so a group stays compact; between groups the
 * gaps are wider so the boxes read as separate.
 */
function layered(nodeGap: number, layerGap: number, extra: Record<string, string> = {}): Readonly<Record<string, string>> {
  return Object.freeze({
    'elk.algorithm': 'layered',
    'elk.direction': 'RIGHT',
    'elk.edgeRouting': 'ORTHOGONAL',
    'elk.layered.considerModelOrder.strategy': 'NODES_AND_EDGES',
    'elk.layered.nodePlacement.strategy': 'NETWORK_SIMPLEX',
    'elk.spacing.nodeNode': String(nodeGap),
    'elk.layered.spacing.nodeNodeBetweenLayers': String(layerGap),
    ...extra,
  })
}

/** Options for laying out the members of one group. */
export const ELK_OPTIONS_WITHIN_GROUP = layered(40, 85, { 'elk.layered.spacing.edgeNodeBetweenLayers': '25' })

/** Options for placing groups and ungrouped nodes relative to each other. */
export const ELK_OPTIONS_GROUP_LEVEL = layered(80, 120)

/** Size every resource node is laid out at; the node renderer must match. */
export const NODE_SIZE = { width: 260, height: 84 } as const

export interface GroupPadding {
  top: number
  left: number
  bottom: number
  right: number
}

/** Room inside a group box for its header above the members. */
export const GROUP_PADDING: GroupPadding = { top: 64, left: 30, bottom: 30, right: 30 }
/** When there is only one group the header is not drawn. */
export const GROUP_PADDING_NO_HEADER: GroupPadding = { top: 30, left: 30, bottom: 30, right: 30 }

const GROUP_ID_PREFIX = 'group-'

export function groupId(mode: GroupingMode, key: string): string {
  return `${GROUP_ID_PREFIX}${mode}-${key}`
}

// ---------------------------------------------------------------------------
// Grouping
// ---------------------------------------------------------------------------

/** The group a node belongs to on its own, before propagation. */
export function getGroupKey(node: GraphNode, mode: GroupingMode): string | null {
  if (mode === 'namespace') return node.namespace || null
  if (mode === 'group') return node.group || null
  return null
}

// Lower is more representative when naming a group after one of its members.
const KIND_PRIORITY: Record<string, number> = {
  Deployment: 1, StatefulSet: 2, DaemonSet: 3, CronJob: 4, Job: 5,
  Service: 6, HTTPRoute: 6, GRPCRoute: 6, Gateway: 7, Ingress: 7,
  ReplicaSet: 8, Pod: 9,
  ConfigMap: 10, Secret: 10, ServiceAccount: 10, PersistentVolumeClaim: 10, HorizontalPodAutoscaler: 10,
}

function pickGroupName(nodes: GraphNode[]): string {
  const sorted = [...nodes].sort((a, b) => (KIND_PRIORITY[a.kind] ?? 99) - (KIND_PRIORITY[b.kind] ?? 99))
  return sorted[0].name
}

/**
 * Group keys for `grouping: 'group'`. A node without its own `group` inherits
 * the one group key among its same-namespace neighbours (repeatedly, up to 10
 * hops); a node touching two different groups stays out of both. Connected
 * unlabelled nodes then form a group named after their most representative
 * member; an unlabelled singleton stays ungrouped.
 */
export function propagateGroups(nodes: readonly GraphNode[], edges: readonly GraphEdge[]): Map<string, string> {
  const byId = new Map(nodes.map(n => [n.id, n]))
  const adjacent = new Map<string, Set<string>>(nodes.map(n => [n.id, new Set<string>()]))
  for (const e of edges) {
    const s = byId.get(e.source)
    const t = byId.get(e.target)
    if (s && t && s.namespace === t.namespace) {
      adjacent.get(e.source)!.add(e.target)
      adjacent.get(e.target)!.add(e.source)
    }
  }

  const keys = new Map<string, string>()
  for (const n of nodes) if (n.group) keys.set(n.id, n.group)

  for (let changed = true, round = 0; changed && round < 10; round++) {
    changed = false
    for (const n of nodes) {
      if (keys.has(n.id)) continue
      const seen = new Set<string>()
      for (const other of adjacent.get(n.id)!) {
        const k = keys.get(other)
        if (k) seen.add(k)
      }
      if (seen.size === 1) {
        keys.set(n.id, [...seen][0])
        changed = true
      }
    }
  }

  const visited = new Set<string>()
  for (const start of nodes) {
    if (keys.has(start.id) || visited.has(start.id)) continue
    const component: GraphNode[] = []
    const queue = [start.id]
    visited.add(start.id)
    while (queue.length > 0) {
      const id = queue.shift()!
      component.push(byId.get(id)!)
      for (const other of adjacent.get(id)!) {
        if (!visited.has(other) && !keys.has(other)) {
          visited.add(other)
          queue.push(other)
        }
      }
    }
    if (component.length > 1) {
      const name = pickGroupName(component)
      for (const n of component) keys.set(n.id, name)
    }
  }
  return keys
}

// ---------------------------------------------------------------------------
// ELK graph
// ---------------------------------------------------------------------------

export interface HierarchicalGraph {
  elkGraph: ElkGraph
  /** Group key → member node ids. */
  groupMap: Map<string, string[]>
  /** Node id → group id. */
  nodeToGroup: Map<string, string>
}

/**
 * The ELK input: one child per group holding its members, plus ungrouped nodes
 * at the top level. Edges are deduplicated by endpoint pair; self-loops and
 * edges naming a node not in the graph are dropped, since a single dangling
 * endpoint makes ELK reject the whole graph.
 */
export function buildHierarchicalElkGraph(
  nodes: readonly GraphNode[],
  edges: readonly GraphEdge[],
  mode: GroupingMode,
  hideGroupHeader = false,
): HierarchicalGraph {
  const groupMap = new Map<string, string[]>()
  const nodeToGroup = new Map<string, string>()
  const propagated = mode === 'group' ? propagateGroups(nodes, edges) : null

  if (mode !== 'none') {
    for (const node of nodes) {
      const key = propagated ? propagated.get(node.id) ?? null : getGroupKey(node, mode)
      if (!key) continue
      const members = groupMap.get(key)
      if (members) members.push(node.id)
      else groupMap.set(key, [node.id])
      nodeToGroup.set(node.id, groupId(mode, key))
    }
  }

  const children: ElkNode[] = []
  const padding = hideGroupHeader ? GROUP_PADDING_NO_HEADER : GROUP_PADDING
  for (const [key, memberIds] of groupMap) {
    children.push({
      id: groupId(mode, key),
      children: memberIds.map(id => ({ id, width: NODE_SIZE.width, height: NODE_SIZE.height })),
      layoutOptions: {
        ...ELK_OPTIONS_WITHIN_GROUP,
        'elk.padding': `[left=${padding.left}, top=${padding.top}, right=${padding.right}, bottom=${padding.bottom}]`,
      },
      labels: [{ text: key }],
    })
  }
  for (const node of nodes) {
    if (!nodeToGroup.has(node.id)) children.push({ id: node.id, width: NODE_SIZE.width, height: NODE_SIZE.height })
  }

  const valid = new Set<string>()
  for (const child of children) {
    valid.add(child.id)
    for (const c of child.children ?? []) valid.add(c.id)
  }
  // One ELK edge per ordered pair of known, distinct endpoints; the first
  // edge seen for a pair lends it its id.
  const byPair = new Map<string, ElkEdge>()
  for (const { id, source, target } of edges) {
    const pair = `${source}->${target}`
    if (source !== target && valid.has(source) && valid.has(target) && !byPair.has(pair)) {
      byPair.set(pair, { id, sources: [source], targets: [target] })
    }
  }
  const elkEdges = [...byPair.values()]

  return { elkGraph: { id: 'root', layoutOptions: {}, children, edges: elkEdges }, groupMap, nodeToGroup }
}

/**
 * Edges of the group-level graph. Each endpoint is mapped to its meta node — a
 * group member to its group, an ungrouped node to itself — and edges inside
 * one meta node, between unknown ids, or repeating a pair already seen are
 * dropped.
 */
export function buildInterGroupEdges(
  edges: readonly ElkEdge[],
  nodeToGroup: ReadonlyMap<string, string>,
  metaIds: ReadonlySet<string>,
): ElkEdge[] {
  const lift = (id: string) => nodeToGroup.get(id) ?? id
  const byPair = new Map<string, ElkEdge>()
  for (const { sources, targets } of edges) {
    const [from, to] = [lift(sources[0]), lift(targets[0])]
    const pair = `${from}->${to}`
    if (from !== to && metaIds.has(from) && metaIds.has(to) && !byPair.has(pair)) {
      byPair.set(pair, { id: `inter-${pair}`, sources: [from], targets: [to] })
    }
  }
  return [...byPair.values()]
}

// ---------------------------------------------------------------------------
// Two-phase layout
// ---------------------------------------------------------------------------

/** Which way the layered layout flows. RIGHT suits a wide canvas (the
 *  incident page); DOWN suits a narrow, tall one (the object panel), where a
 *  left-to-right graph has to shrink until its text is unreadable. */
export type LayoutDirection = 'RIGHT' | 'DOWN'

export interface LayoutRequest {
  elkGraph: ElkGraph
  hideGroupHeader: boolean
  direction?: LayoutDirection
}

export interface GroupLayout {
  groupId: string
  groupKey: string
  width: number
  height: number
  /** Member positions relative to the group's top-left corner. */
  children: Array<{ id: string; x: number; y: number }>
}

export interface LayoutResult {
  groupLayouts: GroupLayout[]
  ungroupedNodes: Array<{ id: string; width: number; height: number }>
  /** Top-left of every group and ungrouped node. */
  positions: Array<[string, { x: number; y: number }]>
}

/** Runs both phases with the given ELK call. Shared by the main thread and the
 *  worker, so the two cannot drift. */
export async function runTwoPhaseLayout(layout: ElkLayoutFn, { elkGraph, hideGroupHeader, direction = 'RIGHT' }: LayoutRequest): Promise<LayoutResult> {
  const nodeToGroup = new Map<string, string>()
  for (const child of elkGraph.children) {
    if (child.id.startsWith(GROUP_ID_PREFIX) && child.children) {
      for (const c of child.children) nodeToGroup.set(c.id, child.id)
    }
  }
  const intraEdges = new Map<string, ElkEdge[]>()
  for (const e of elkGraph.edges) {
    const g = nodeToGroup.get(e.sources[0])
    if (g && g === nodeToGroup.get(e.targets[0])) {
      const list = intraEdges.get(g)
      if (list) list.push(e)
      else intraEdges.set(g, [e])
    }
  }

  const groupLayouts: GroupLayout[] = []
  const ungroupedNodes: LayoutResult['ungroupedNodes'] = []
  for (const child of elkGraph.children) {
    if (!child.id.startsWith(GROUP_ID_PREFIX) || !child.children?.length) {
      ungroupedNodes.push({ id: child.id, width: child.width ?? NODE_SIZE.width, height: child.height ?? NODE_SIZE.height })
      continue
    }
    const groupKey = child.labels?.[0]?.text ?? child.id
    // Wide enough for the header text.
    const minWidth = hideGroupHeader ? 300 : Math.max(500, groupKey.length * 16 + 200)
    const laid = await layout({
      id: child.id,
      layoutOptions: { ...(child.layoutOptions ?? ELK_OPTIONS_WITHIN_GROUP), 'elk.direction': direction },
      children: child.children,
      edges: intraEdges.get(child.id) ?? [],
    })
    groupLayouts.push({
      groupId: child.id,
      groupKey,
      width: hideGroupHeader ? laid.width || 300 : Math.max(laid.width || 300, minWidth),
      height: laid.height || 200,
      children: (laid.children ?? []).map(c => ({ id: c.id, x: c.x ?? 0, y: c.y ?? 0 })),
    })
  }

  const metaChildren: ElkNode[] = [
    ...groupLayouts.map(g => ({ id: g.groupId, width: g.width, height: g.height })),
    ...ungroupedNodes.map(n => ({ id: n.id, width: n.width, height: n.height })),
  ]
  const meta = await layout({
    id: 'meta-root',
    layoutOptions: { ...ELK_OPTIONS_GROUP_LEVEL, 'elk.direction': direction },
    children: metaChildren,
    edges: buildInterGroupEdges(elkGraph.edges, nodeToGroup, new Set(metaChildren.map(c => c.id))),
  })
  const positions: LayoutResult['positions'] = (meta.children ?? []).map(c => [c.id, { x: c.x ?? 0, y: c.y ?? 0 }])
  return { groupLayouts, ungroupedNodes, positions }
}

// ---------------------------------------------------------------------------
// Engine selection
// ---------------------------------------------------------------------------

/** Below this many nodes the layout runs on the main thread: a worker
 *  round-trip costs more than laying out a small graph inline. */
export const WORKER_NODE_THRESHOLD = 40

/** Thrown by a worker transport that cannot run at all (failed to load,
 *  blocked by CSP), as opposed to a layout that failed inside the worker. */
export class WorkerUnavailableError extends Error {
  constructor(message = 'layout worker unavailable') {
    super(message)
    this.name = 'WorkerUnavailableError'
  }
}

export type LayoutRunner = (request: LayoutRequest, nodeCount: number) => Promise<LayoutResult>

/**
 * Routes a layout to the worker for large graphs and to the main thread for
 * small ones. Once the worker proves unavailable every later layout stays on
 * the main thread rather than failing each time.
 */
export function createLayoutRunner(deps: {
  mainThread: ElkLayoutFn
  worker?: (request: LayoutRequest) => Promise<LayoutResult>
  threshold?: number
}): LayoutRunner {
  const threshold = deps.threshold ?? WORKER_NODE_THRESHOLD
  let workerUsable = deps.worker !== undefined
  return async (request, nodeCount) => {
    if (!workerUsable || nodeCount < threshold) return runTwoPhaseLayout(deps.mainThread, request)
    try {
      return await deps.worker!(request)
    } catch (err) {
      if (!(err instanceof WorkerUnavailableError)) throw err
      workerUsable = false
      return runTwoPhaseLayout(deps.mainThread, request)
    }
  }
}

// ---------------------------------------------------------------------------
// Positioned nodes for the canvas
// ---------------------------------------------------------------------------

const STATUS_RANK: Record<NodeStatus, number> = { unhealthy: 0, degraded: 1, unknown: 2, healthy: 3, neutral: 4 }

export type GroupNodeData = {
  mode: GroupingMode
  name: string
  nodeCount: number
  /** Least healthy member status; an all-neutral group stays neutral. */
  worstStatus: NodeStatus
  /** Members that are unhealthy or degraded. */
  unhealthyCount: number
}

export type ResourceNodeData = { node: GraphNode }

export type GroupFlowNode = Node<GroupNodeData, 'group'>
export type ResourceFlowNode = Node<ResourceNodeData, 'resource'>
export type LaidOutNode = GroupFlowNode | ResourceFlowNode

export function groupHealth(members: readonly GraphNode[]): { worstStatus: NodeStatus; unhealthyCount: number } {
  let worstStatus: NodeStatus = 'healthy'
  let worstRank = Infinity
  let unhealthyCount = 0
  for (const n of members) {
    const rank = STATUS_RANK[n.status] ?? STATUS_RANK.unknown
    if (rank < worstRank) {
      worstRank = rank
      worstStatus = n.status
    }
    if (n.status === 'unhealthy' || n.status === 'degraded') unhealthyCount++
  }
  return { worstStatus, unhealthyCount }
}

export interface PositionedGraph {
  nodes: LaidOutNode[]
  /** Absolute top-left of every group and node. */
  positions: Map<string, { x: number; y: number }>
  error?: string
}

/**
 * Turns a layout result into canvas nodes. Group members are positioned
 * relative to their group (`parentId`); with the header hidden the group box
 * is not emitted and members take absolute positions.
 */
export function toPositionedGraph(
  result: LayoutResult,
  nodes: readonly GraphNode[],
  groupMap: ReadonlyMap<string, string[]>,
  mode: GroupingMode,
  hideGroupHeader: boolean,
): PositionedGraph {
  const byId = new Map(nodes.map(n => [n.id, n]))
  const placed = new Map(result.positions)
  const out: LaidOutNode[] = []
  const positions = new Map<string, { x: number; y: number }>()

  for (const group of result.groupLayouts) {
    const pos = placed.get(group.groupId) ?? { x: 0, y: 0 }
    positions.set(group.groupId, pos)
    const members = (groupMap.get(group.groupKey) ?? []).map(id => byId.get(id)).filter((n): n is GraphNode => !!n)
    if (!hideGroupHeader) {
      out.push({
        id: group.groupId,
        type: 'group',
        position: pos,
        data: { mode, name: group.groupKey, nodeCount: members.length, ...groupHealth(members) },
        style: { width: group.width, height: group.height },
        zIndex: -1,
      })
    }
    for (const child of group.children) {
      const node = byId.get(child.id)
      if (!node) continue
      const abs = { x: pos.x + child.x, y: pos.y + child.y }
      positions.set(child.id, abs)
      out.push(
        hideGroupHeader
          ? { id: child.id, type: 'resource', position: abs, data: { node } }
          : { id: child.id, type: 'resource', position: { x: child.x, y: child.y }, parentId: group.groupId, extent: 'parent', data: { node } },
      )
    }
  }
  for (const u of result.ungroupedNodes) {
    const node = byId.get(u.id)
    if (!node) continue
    const pos = placed.get(u.id) ?? { x: 0, y: 0 }
    positions.set(u.id, pos)
    out.push({ id: u.id, type: 'resource', position: pos, data: { node } })
  }
  return { nodes: out, positions }
}

/**
 * Lays out a hierarchical graph and returns canvas nodes. A layout failure is
 * returned as `error` with no nodes, for the canvas's error state — never a
 * half-placed graph.
 */
export async function applyHierarchicalLayout(
  graph: HierarchicalGraph,
  nodes: readonly GraphNode[],
  mode: GroupingMode,
  runner: LayoutRunner,
  hideGroupHeader = false,
  direction: LayoutDirection = 'RIGHT',
): Promise<PositionedGraph> {
  try {
    const result = await runner({ elkGraph: graph.elkGraph, hideGroupHeader, direction }, nodes.length)
    return toPositionedGraph(result, nodes, graph.groupMap, mode, hideGroupHeader)
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    return { nodes: [], positions: new Map(), error: `Layout failed: ${message}` }
  }
}
