import { describe, expect, it } from 'vitest'
import { ANNOTATION_LABEL_ROWS, layoutAnnotations, truncateAnnotationLabel } from './annotations'
import type { ChartAnnotation } from './types'

const t0 = 1_788_679_000
const domain = { minTs: t0, maxTs: t0 + 1800 }
const plot = { left: 84, right: 960 }
const toX = (ts: number) => 84 + ((ts - t0) / 1800) * 876

describe('layoutAnnotations', () => {
  it('places markers inside the time window and drops those outside', () => {
    const annotations: ChartAnnotation[] = [
      { timestamp: t0 + 600, label: 'image v1.4→v1.5', kind: 'change' },
      { timestamp: t0 + 9_000, label: 'outside', kind: 'change' },
      { timestamp: Number.NaN, label: 'not a time', kind: 'change' },
    ]
    const placed = layoutAnnotations(annotations, toX, domain, plot)
    expect(placed.map(p => p.annotation.label)).toEqual(['image v1.4→v1.5'])
    expect(placed[0].label?.row).toBe(0)
  })

  it('stacks overlapping labels into rows and hides labels past the row limit', () => {
    const crowded: ChartAnnotation[] = Array.from({ length: ANNOTATION_LABEL_ROWS + 1 }, (_, i) => ({
      timestamp: t0 + i * 5,
      label: `Change ${i}`,
      kind: 'change',
    }))
    const placed = layoutAnnotations(crowded, toX, domain, plot)
    expect(placed.map(p => p.label?.row ?? 'hidden')).toEqual([0, 1, 2, 'hidden'])
    const far: ChartAnnotation[] = [
      { timestamp: t0, label: 'opened', kind: 'opened' },
      { timestamp: t0 + 1200, label: 'second', kind: 'change' },
    ]
    expect(layoutAnnotations(far, toX, domain, plot).map(p => p.label?.row)).toEqual([0, 0])
  })

  it('sorts by time regardless of input order', () => {
    const placed = layoutAnnotations(
      [
        { timestamp: t0 + 1200, label: 'later', kind: 'change' },
        { timestamp: t0, label: 'earlier', kind: 'opened' },
      ],
      toX,
      domain,
      plot,
    )
    expect(placed.map(p => p.annotation.label)).toEqual(['earlier', 'later'])
  })

  it('keeps a label near the right edge inside the plot', () => {
    const [p] = layoutAnnotations([{ timestamp: t0 + 1800, label: 'opened', kind: 'opened' }], toX, domain, plot)
    expect(p.label!.x + p.label!.width).toBeLessThanOrEqual(plot.right)
  })

  it('truncates a long label', () => {
    expect(truncateAnnotationLabel('ConfigMap a-very-long-configmap-name-that-goes-on')).toBe('ConfigMap a-very-long-confi…')
    expect(truncateAnnotationLabel('short')).toBe('short')
  })
})
