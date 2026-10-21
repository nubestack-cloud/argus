import type { ChartAnnotation } from './types'

/** A marker in plot coordinates, with its label's place — or null when no row had room, so only the line is drawn. */
export interface PlacedAnnotation {
  annotation: ChartAnnotation
  x: number
  label: { text: string; x: number; width: number; row: number } | null
}

export const ANNOTATION_LABEL_MAX_CHARS = 28
export const ANNOTATION_LABEL_ROWS = 3

// Label geometry in viewBox units: an estimate of the label font's average
// glyph width plus padding, how far right of its line a label starts, and the
// least space between two labels sharing a row.
const GLYPH_WIDTH = 6.5
const LABEL_PADDING = 10
const LABEL_OFFSET = 4
const LABEL_GAP = 6

export function truncateAnnotationLabel(label: string): string {
  if (label.length <= ANNOTATION_LABEL_MAX_CHARS) return label
  return label.slice(0, ANNOTATION_LABEL_MAX_CHARS - 1) + '…'
}

/**
 * Places marker labels so none overlap. Left to right, each label goes in the
 * topmost of ANNOTATION_LABEL_ROWS rows that is clear where it starts, pulled
 * left only as far as the plot edge; with every row taken it is hidden, and
 * its line, tooltip and table row still carry it. Markers outside the time
 * window are left out.
 */
export function layoutAnnotations(
  annotations: readonly ChartAnnotation[],
  toX: (timestamp: number) => number,
  domain: { minTs: number; maxTs: number },
  plot: { left: number; right: number },
): PlacedAnnotation[] {
  // Where each row next has room, in x.
  const clearFrom = Array<number>(ANNOTATION_LABEL_ROWS).fill(-Infinity)
  return annotations
    .filter(a => Number.isFinite(a.timestamp) && domain.minTs <= a.timestamp && a.timestamp <= domain.maxTs)
    .map(annotation => ({ annotation, x: toX(annotation.timestamp) }))
    .sort((a, b) => a.x - b.x)
    .map(({ annotation, x }) => {
      const text = truncateAnnotationLabel(annotation.label)
      const width = text.length * GLYPH_WIDTH + LABEL_PADDING
      const labelX = Math.max(plot.left, Math.min(x + LABEL_OFFSET, plot.right - width))
      const row = clearFrom.findIndex(free => free <= labelX)
      if (row < 0) return { annotation, x, label: null }
      clearFrom[row] = labelX + width + LABEL_GAP
      return { annotation, x, label: { text, x: labelX, width, row } }
    })
}
