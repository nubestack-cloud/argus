import { describe, expect, it } from 'vitest'
import { AUTO_MIN_ZOOM, autoCanvasHeight, graphBounds } from './GraphCanvas'
import { NODE_SIZE, type LaidOutNode } from './layout'

const resource = (id: string, x: number, y: number, parentId?: string) =>
  ({ id, type: 'resource', position: { x, y }, parentId, data: { node: {} } }) as unknown as LaidOutNode

describe('graphBounds', () => {
  it('spans the top-level nodes, ignoring positions relative to a group', () => {
    const b = graphBounds([
      resource('a', 0, 0),
      resource('b', 400, 300),
      { id: 'g', type: 'group', position: { x: 0, y: 500 }, style: { width: 900, height: 200 }, data: {} } as unknown as LaidOutNode,
      resource('inside', 5000, 5000, 'g'),
    ])
    expect(b).toEqual({ width: 900, height: 700, x: 0, y: 0 })
  })

  it('is null for an empty graph', () => {
    expect(graphBounds([])).toBeNull()
  })
})

describe('autoCanvasHeight', () => {
  it('grows with a tall graph instead of shrinking it into a fixed box', () => {
    const tall = autoCanvasHeight({ width: NODE_SIZE.width, height: 900 }, 600)
    expect(tall.zoom).toBe(1)
    expect(tall.height).toBeGreaterThan(900)
  })

  it('keeps a small graph compact', () => {
    expect(autoCanvasHeight({ width: 260, height: 84 }, 600).height).toBe(200)
  })

  it('never shrinks below a legible zoom; a very wide graph pans instead', () => {
    const wide = autoCanvasHeight({ width: 4000, height: 300 }, 600)
    expect(wide.zoom).toBe(AUTO_MIN_ZOOM)
    expect(wide.height).toBe(Math.round(300 * AUTO_MIN_ZOOM + 48))
  })

  it('caps the height so one huge graph cannot push the panel off screen', () => {
    expect(autoCanvasHeight({ width: 260, height: 5000 }, 600).height).toBe(1100)
  })
})

describe('the auto viewport of a graph wider than its canvas', () => {
  it('keeps the minimum zoom when fitting would shrink text below it', () => {
    // 4000px of graph in a 1100px canvas: fitting needs 0.26, below the
    // floor, so the canvas pans — and GraphCanvas then starts at the
    // top-left (overflowViewport) rather than the middle.
    const { zoom } = autoCanvasHeight({ width: 4000, height: 900 }, 1100)
    expect(zoom).toBe(AUTO_MIN_ZOOM)
    expect(4000 * zoom).toBeGreaterThan(1100)
  })
})

