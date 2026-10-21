import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type Edge,
  type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { toPng } from 'html-to-image'
import { layoutGraph } from './engine'
import { NODE_SIZE, type GroupFlowNode, type LaidOutNode, type LayoutDirection, type ResourceFlowNode } from './layout'
import type { GraphEdge, GraphNode, GroupingMode, NodeStatus } from './types'

// GraphCanvas draws a node/edge graph (docs/CLUSTER_INSIGHT_SPECS.md CI-F4)
// for the relationship map, the traffic map and path overlays. Health is
// always printed as a word on the node; colour only repeats it. Every edge
// type is named in a legend. Nodes are keyboard-focusable and Enter or Space
// opens them (onOpen). The mouse wheel scrolls the page; Ctrl/⌘ + wheel (or a
// pinch) zooms, so a tall graph never traps the page's scroll.

export const STATUS_WORD: Record<NodeStatus, string> = {
  healthy: 'Healthy',
  degraded: 'Degraded',
  unhealthy: 'Unhealthy',
  neutral: '',
  unknown: 'Unknown',
}

type ResourceData = ResourceFlowNode['data'] & {
  focus?: boolean
  focusTag?: string
  onOpen?: (n: GraphNode) => void
  vertical?: boolean
}

function ResourceNodeView({ data }: NodeProps<ResourceFlowNode>) {
  const d = data as ResourceData
  const n = d.node
  const word = STATUS_WORD[n.status]
  return (
    <div
      className={`graph-node graph-node-${n.status}${d.focus ? ' graph-node-focus' : ''}`}
      tabIndex={0}
      role="button"
      aria-label={`${n.kind} ${n.namespace ? n.namespace + '/' : ''}${n.name}${word ? ', ' + word : ''}${n.statusReason ? ', ' + n.statusReason : ''}${d.focus && d.focusTag ? ', ' + d.focusTag : ''}`}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          d.onOpen?.(n)
        }
      }}
    >
      <Handle type="target" position={d.vertical ? Position.Top : Position.Left} isConnectable={false} />
      <span className="graph-node-kind">
        {n.kind}
        {d.focus && d.focusTag && <span className="graph-node-tag">{d.focusTag}</span>}
      </span>
      <span className="graph-node-name" title={n.name}>
        {n.name}
      </span>
      {(word || n.statusReason) && (
        <span className="graph-node-status">
          {word}
          {word && n.statusReason ? ' · ' : ''}
          {n.statusReason}
        </span>
      )}
      <Handle type="source" position={d.vertical ? Position.Bottom : Position.Right} isConnectable={false} />
    </div>
  )
}

function GroupNodeView({ data }: NodeProps<GroupFlowNode>) {
  return (
    <div className="graph-group">
      <span className="graph-group-name">{data.name}</span>
      <span className="graph-group-meta">
        {data.nodeCount} objects{data.unhealthyCount > 0 ? ` · ${data.unhealthyCount} not healthy` : ''}
      </span>
    </div>
  )
}

const nodeTypes = { resource: ResourceNodeView, group: GroupNodeView }

export interface GraphCanvasProps {
  nodes: readonly GraphNode[]
  edges: readonly GraphEdge[]
  grouping?: GroupingMode
  /** Node to anchor visually (the incident's object, the inspected object). */
  focusId?: string
  /** Words printed on the focus node saying what it is in THIS context —
   *  "this incident" on the incident page, "this object" in the object
   *  panel. Omitted: the node is outlined but carries no tag. */
  focusTag?: string
  /** Optional per-edge text (e.g. "12 req/s · 3% 5xx"), keyed by edge id. */
  edgeLabels?: Record<string, string>
  /** Edges drawn dashed as problems (e.g. with errors); the label says why. */
  problemEdges?: ReadonlySet<string>
  /** Optional per-edge stroke width in px (e.g. scaled to request rate); the
   *  label still prints the number, so width only repeats it. */
  edgeWidths?: Record<string, number>
  /** Called when a node is clicked or activated with Enter. */
  onOpen?: (node: GraphNode) => void
  /** Accessible name for the whole graph. */
  label: string
  /** A fixed height, or 'auto' to size the canvas to the laid-out graph at a
   *  readable zoom (see autoCanvasHeight). */
  height?: number | 'auto'
  /** Which way the graph flows; DOWN for a narrow, tall container. */
  direction?: LayoutDirection
  /** Exposed so callers can export the rendered graph (CI-U12). */
  containerRef?: React.RefObject<HTMLDivElement | null>
  /** Set to a function that renders the graph alone — fitted to its nodes,
   *  no zoom controls or grid, on a solid background — as a PNG data URL. */
  exportRef?: React.MutableRefObject<(() => Promise<string>) | null>
}

// Auto height (owner, 2026-10-11): a fixed-height canvas shrank a tall graph
// until its nodes were unreadable and left a small one floating in empty
// space. Instead the canvas takes the height the graph needs when fitted to
// the available width, at no less than AUTO_MIN_ZOOM (below that node text is
// not legible, so a very wide graph pans sideways instead of shrinking), and
// within AUTO_MIN_HEIGHT..AUTO_MAX_HEIGHT so one huge graph cannot push the
// rest of the panel off screen.
export const AUTO_MIN_ZOOM = 0.6
const AUTO_PADDING = 24
const AUTO_MIN_HEIGHT = 200
const AUTO_MAX_HEIGHT = 1100

/** The laid-out graph's extent, from top-level nodes only (a grouped node's
 *  position is relative to its group, whose own box already contains it). */
export function graphBounds(nodes: readonly LaidOutNode[]): { width: number; height: number; x: number; y: number } | null {
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity
  for (const n of nodes) {
    if (n.parentId) continue
    const w = n.type === 'group' ? Number(n.style?.width ?? 0) : NODE_SIZE.width
    const h = n.type === 'group' ? Number(n.style?.height ?? 0) : NODE_SIZE.height
    minX = Math.min(minX, n.position.x)
    minY = Math.min(minY, n.position.y)
    maxX = Math.max(maxX, n.position.x + w)
    maxY = Math.max(maxY, n.position.y + h)
  }
  return Number.isFinite(minX) ? { width: maxX - minX, height: maxY - minY, x: minX, y: minY } : null
}

/** The canvas height and zoom for a graph of `bounds` in `available` px. */
export function autoCanvasHeight(bounds: { width: number; height: number }, available: number): { height: number; zoom: number } {
  const fit = (available - 2 * AUTO_PADDING) / Math.max(bounds.width, 1)
  const zoom = Math.min(1, Math.max(AUTO_MIN_ZOOM, fit))
  const height = Math.round(bounds.height * zoom + 2 * AUTO_PADDING)
  return { height: Math.min(AUTO_MAX_HEIGHT, Math.max(AUTO_MIN_HEIGHT, height)), zoom }
}

/** The export image's size and the viewport transform that draws the graph
 *  inside it at 1:1 with EXPORT_MARGIN on every side. Computed directly rather
 *  than through getViewportForBounds, which scales the graph to fill the frame
 *  and so spent the margin on zoom — the left edge sat at 0 and the right was
 *  cut off. */
export const EXPORT_MARGIN = 48
export function exportFrame(bounds: { x: number; y: number; width: number; height: number }): {
  width: number
  height: number
  transform: string
} {
  const width = Math.ceil(bounds.width + EXPORT_MARGIN * 2)
  const height = Math.ceil(bounds.height + EXPORT_MARGIN * 2)
  return { width, height, transform: `translate(${EXPORT_MARGIN - bounds.x}px, ${EXPORT_MARGIN - bounds.y}px) scale(1)` }
}

/** Copies the computed stroke of every edge path and arrowhead under `root`
 *  onto the element itself, returning a function that restores the original
 *  inline styles. */
export function inlineSvgStrokes(root: Element): () => void {
  const touched: Array<[SVGElement, string | null]> = []
  root.querySelectorAll<SVGElement>('.react-flow__edge-path, .react-flow__arrowhead polyline').forEach((el) => {
    const cs = getComputedStyle(el)
    touched.push([el, el.getAttribute('style')])
    if (cs.stroke) el.style.stroke = cs.stroke
    if (cs.strokeWidth) el.style.strokeWidth = cs.strokeWidth
    if (cs.strokeDasharray) el.style.strokeDasharray = cs.strokeDasharray
    el.style.fill = cs.fill && el.tagName.toLowerCase() === 'polyline' ? cs.fill : 'none'
  })
  return () => {
    for (const [el, style] of touched) {
      if (style === null) el.removeAttribute('style')
      else el.setAttribute('style', style)
    }
  }
}

function CanvasInner(props: GraphCanvasProps) {
  const { nodes, edges, grouping = 'none', focusId, focusTag, edgeLabels, problemEdges, edgeWidths, onOpen, label, height = 420 } = props
  // Auto height may turn a DOWN graph sideways (see the layout effect): a
  // wide fan-out — one ServiceAccount used by eight pods — laid out DOWN is a
  // single row far wider than a side panel, so at a legible zoom most of it
  // sat outside the canvas. Laid out RIGHT the same row becomes a column the
  // canvas grows to fit.
  // Keyed to the node array it was decided for, so a new graph starts again
  // from the caller's direction.
  const [turnedFor, setTurnedFor] = useState<readonly GraphNode[] | null>(null)
  const direction: LayoutDirection = turnedFor === nodes ? 'RIGHT' : (props.direction ?? 'RIGHT')
  const [laid, setLaid] = useState<LaidOutNode[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const localRef = useRef<HTMLDivElement>(null)
  const ref = props.containerRef ?? localRef
  const flow = useReactFlow()
  const auto = height === 'auto'
  const [available, setAvailable] = useState<number | null>(null)

  // The canvas's own width, for auto height. Measured on the wrapper, which
  // exists while the layout is still running, so the first ReactFlow render
  // already has its final size and fitView runs once against it.
  const wrapRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!auto || !wrapRef.current) return
    const el = wrapRef.current
    const measure = () => setAvailable(el.clientWidth)
    measure()
    const ro = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(measure)
    ro?.observe(el)
    return () => ro?.disconnect()
  }, [auto])

  useEffect(() => {
    if (!props.exportRef) return
    props.exportRef.current = async () => {
      const viewport = ref.current?.querySelector<HTMLElement>('.react-flow__viewport')
      const nodes = flow.getNodes()
      if (!viewport || nodes.length === 0) throw new Error('nothing to export')
      // The instance's getNodesBounds resolves a grouped node's position to
      // absolute; the free function reads it as relative to its group and
      // crops every graph that has groups.
      const bounds = flow.getNodesBounds(nodes)
      const { width, height, transform } = exportFrame(bounds)
      const background = getComputedStyle(document.documentElement).getPropertyValue('--surface').trim() || undefined
      // html-to-image clones the DOM without React Flow's stylesheet, and an
      // edge's stroke comes only from that stylesheet (.react-flow__edge-path
      // reads --xy-edge-stroke), so every edge line vanished from the image
      // and only the labels — which carry inline styles — survived. Resolve
      // each edge's and arrowhead's computed stroke onto the element for the
      // duration of the capture, then put back what was there.
      const restore = inlineSvgStrokes(viewport)
      try {
        return await toPng(viewport, {
          backgroundColor: background,
          width,
          height,
          pixelRatio: 2,
          style: { width: `${width}px`, height: `${height}px`, transform },
        })
      } finally {
        restore()
      }
    }
    return () => {
      if (props.exportRef) props.exportRef.current = null
    }
  }, [props.exportRef, flow, ref])

  // Auto height lays out only once the canvas width is known — the direction
  // choice below needs it.
  const measured = !auto || available !== null
  useEffect(() => {
    if (!measured) return
    let cancelled = false
    setError(null)
    layoutGraph(nodes, edges, grouping, false, direction)
      .then((g) => {
        if (cancelled) return
        if (g.error) setError(String(g.error))
        // Auto height, a DOWN layout, and still wider than the canvas at the
        // smallest legible zoom: lay it out RIGHT instead (once — RIGHT is
        // never turned back), so every node is on the canvas.
        const b = auto && available !== null && direction === 'DOWN' ? graphBounds(g.nodes) : null
        if (b && available !== null && b.width * AUTO_MIN_ZOOM + 2 * AUTO_PADDING > available) {
          setTurnedFor(nodes)
          return
        }
        setLaid(g.nodes)
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : 'layout failed')
      })
    return () => {
      cancelled = true
    }
    // `available` is read, not tracked: re-laying out on every resize would
    // flicker, and the choice only needs the width at first layout.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes, edges, grouping, direction, measured])

  const flowNodes = useMemo(
    () =>
      (laid ?? []).map((n) =>
        n.type === 'resource'
          ? ({ ...n, data: { ...n.data, focus: n.data.node.id === focusId, focusTag, onOpen, vertical: direction === 'DOWN' } } as LaidOutNode)
          : n,
      ),
    [laid, focusId, focusTag, onOpen, direction],
  )

  const rootStyle = typeof document === 'undefined' ? null : getComputedStyle(document.documentElement)
  const labelBg = rootStyle?.getPropertyValue('--surface').trim() ?? ''
  const labelInk = rootStyle?.getPropertyValue('--text').trim() ?? ''
  const flowEdges: Edge[] = useMemo(
    () =>
      edges.map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        label: edgeLabels?.[e.id] ?? e.type,
        className: problemEdges?.has(e.id) ? 'graph-edge graph-edge-problem' : 'graph-edge',
        style: edgeWidths?.[e.id] ? { strokeWidth: edgeWidths[e.id] } : undefined,
        // Inline and resolved from the theme: the PNG export clones SVG
        // without React Flow's stylesheet variables (an unresolved label
        // background came out as a black box), and the label ink must follow
        // the background in dark mode.
        labelBgStyle: labelBg ? { fill: labelBg } : undefined,
        labelStyle: labelInk ? { fill: labelInk } : undefined,
        markerEnd: { type: MarkerType.ArrowClosed },
      })),
    [edges, edgeLabels, problemEdges, edgeWidths, labelBg, labelInk],
  )

  const types = useMemo(() => Array.from(new Set(edges.map((e) => e.type))).sort(), [edges])

  const bounds = auto && laid ? graphBounds(laid) : null
  const sized = auto && bounds && available ? autoCanvasHeight(bounds, available) : null
  const canvasHeight = auto ? (sized?.height ?? 320) : height
  const overflowViewport =
    sized && bounds && available && (bounds.width * sized.zoom + 2 * AUTO_PADDING > available || bounds.height * sized.zoom + 2 * AUTO_PADDING > canvasHeight + 1)
      ? { x: AUTO_PADDING - bounds.x * sized.zoom, y: AUTO_PADDING - bounds.y * sized.zoom, zoom: sized.zoom }
      : undefined

  if (error && !laid) {
    return <p className="form-error">The graph could not be laid out: {error}</p>
  }
  return (
    <div ref={wrapRef}>
      <div ref={ref} className="graph-canvas" style={{ height: canvasHeight }} role="group" aria-label={label}>
        {laid === null || (auto && !sized) ? (
          <div className="skeleton" style={{ height: '100%' }} aria-label="Laying out graph" />
        ) : (
          <ReactFlow
            nodes={flowNodes}
            edges={flowEdges}
            nodeTypes={nodeTypes}
            // Auto height already chose a zoom; holding fitView to it keeps a
            // very wide graph legible (it pans) instead of shrinking it. When
            // that zoom is still too wide for the canvas, start at the graph's
            // top-left corner rather than its middle, so the first boxes are
            // whole and the reader pans in one direction.
            fitView={!overflowViewport}
            defaultViewport={overflowViewport}
            fitViewOptions={sized ? { minZoom: sized.zoom, maxZoom: 1, padding: 0.04 } : undefined}
            minZoom={0.2}
            nodesDraggable={false}
            nodesConnectable={false}
            // The node's own content (ResourceNodeView) is the focus target,
            // a role="button" with Enter/Space. React Flow's focusable wrapper
            // around it took the Tab stop instead, so a keyboard user landed
            // on a role="group" whose Enter did nothing.
            nodesFocusable={false}
            edgesFocusable={false}
            // The wheel belongs to the page. Zoom is Ctrl/⌘ + wheel (React
            // Flow's zoomActivationKeyCode), a pinch, or the +/− controls.
            zoomOnScroll={false}
            preventScrolling={false}
            elementsSelectable
            proOptions={{ hideAttribution: true }}
            onNodeClick={(_, n) => {
              if (n.type === 'resource') onOpen?.((n as ResourceFlowNode).data.node)
            }}
          >
            <Background />
            <Controls showInteractive={false} />
          </ReactFlow>
        )}
      </div>
      {types.length > 0 && (
        <p className="graph-legend">
          <span className="graph-legend-label">Edges:</span> {types.join(' · ')}
          {problemEdges && problemEdges.size > 0 ? ' · dashed = problem (see label)' : ''}
          {' · Ctrl/⌘ + scroll to zoom'}
        </p>
      )}
    </div>
  )
}

export function GraphCanvas(props: GraphCanvasProps) {
  return (
    <ReactFlowProvider>
      <CanvasInner {...props} />
    </ReactFlowProvider>
  )
}

/** Maps the agent's health words (topology/health packages) onto NodeStatus. */
export function toNodeStatus(s: string | undefined): NodeStatus {
  switch ((s ?? '').toLowerCase()) {
    case 'healthy':
    case 'ok':
    case 'running':
    case 'ready':
      return 'healthy'
    case 'degraded':
    case 'warning':
    case 'pending':
      return 'degraded'
    case 'unhealthy':
    case 'failed':
    case 'error':
      return 'unhealthy'
    case 'neutral':
      return 'neutral'
    default:
      return 'unknown'
  }
}
