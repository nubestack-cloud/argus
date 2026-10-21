// Pure helpers behind TimeSeriesChart.
import type { TimeSeries } from './types'

/** Rounds up to 1, 2, 2.5 or 5 × 10ⁿ — a tick-friendly axis top. */
export function niceCeil(v: number): number {
  if (!(v > 0)) return 1
  const mag = 10 ** Math.floor(Math.log10(v))
  for (const m of [1, 2, 2.5, 5, 10]) if (m * mag >= v) return m * mag
  return 10 * mag
}

/** Splits a series into drawable runs, breaking at every gap. */
export function seriesRuns(points: TimeSeries['dataPoints']): { timestamp: number; value: number }[][] {
  const runs: { timestamp: number; value: number }[][] = []
  let cur: { timestamp: number; value: number }[] = []
  for (const p of points) {
    if (p.value == null || !Number.isFinite(p.value)) {
      if (cur.length) runs.push(cur)
      cur = []
    } else {
      cur.push({ timestamp: p.timestamp, value: p.value })
    }
  }
  if (cur.length) runs.push(cur)
  return runs
}
