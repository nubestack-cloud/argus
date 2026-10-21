import type { TimeSeriesPoint } from './types'

/**
 * The measured point nearest `timestamp`; gaps are never chosen. Given the
 * series' evaluation step, a point more than half a step away does not count
 * — the cursor is then over a missing evaluation, and showing a neighbour's
 * value there would invent one.
 */
export function nearestSample(
  points: readonly TimeSeriesPoint[],
  timestamp: number,
  stepSeconds?: number,
): { timestamp: number; value: number } | null {
  const measured = points.filter((p): p is { timestamp: number; value: number } => p.value != null)
  if (measured.length === 0) return null
  const best = measured.reduce((a, b) => (Math.abs(b.timestamp - timestamp) < Math.abs(a.timestamp - timestamp) ? b : a))
  if (stepSeconds !== undefined && Math.abs(best.timestamp - timestamp) > stepSeconds / 2) return null
  return { timestamp: best.timestamp, value: best.value }
}
