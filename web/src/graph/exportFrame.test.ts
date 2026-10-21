import { describe, expect, it } from 'vitest'
import { EXPORT_MARGIN, exportFrame, inlineSvgStrokes } from './GraphCanvas'

// Live QA, 2026-10-11: the exported PNG had no edge lines (only their labels)
// and its right side was cut off.
describe('exportFrame', () => {
  it('frames the graph at 1:1 with the margin on every side', () => {
    const f = exportFrame({ x: 100, y: -20, width: 1000, height: 400 })
    expect(f.width).toBe(1000 + 2 * EXPORT_MARGIN)
    expect(f.height).toBe(400 + 2 * EXPORT_MARGIN)
    // The graph's left edge lands at the margin, so its right edge lands at
    // width - margin: nothing is cut off and nothing is scaled.
    expect(f.transform).toBe(`translate(${EXPORT_MARGIN - 100}px, ${EXPORT_MARGIN + 20}px) scale(1)`)
  })
})

describe('inlineSvgStrokes', () => {
  it('puts each edge path’s computed stroke on the element for the capture, then restores it', () => {
    const root = document.createElement('div')
    root.innerHTML =
      '<style>.react-flow__edge-path{stroke:rgb(1, 2, 3);stroke-width:2px}</style>' +
      '<svg><path class="react-flow__edge-path" d="M0 0L10 10"></path>' +
      '<path class="react-flow__edge-path" style="opacity: 0.5" d="M0 0L5 5"></path></svg>'
    document.body.appendChild(root)
    const [a, b] = Array.from(root.querySelectorAll('path'))
    const restore = inlineSvgStrokes(root)
    expect(a.style.stroke).toBe('rgb(1, 2, 3)')
    expect(a.style.fill).toBe('none')
    expect(b.style.stroke).toBe('rgb(1, 2, 3)')
    restore()
    expect(a.getAttribute('style')).toBeNull()
    expect(b.getAttribute('style')).toBe('opacity: 0.5')
    root.remove()
  })
})
