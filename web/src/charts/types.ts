// The shapes the time-series chart draws. Any producer of timestamped numbers
// can feed it; the incident metrics route was the first.

/** One sample: Unix seconds, and the value — absent or null for a gap. */
export type TimeSeriesPoint = { timestamp: number; value?: number | null }

/**
 * One line on the chart. Points are in time order; a gap point breaks the
 * line and is skipped in arithmetic, never drawn or counted as zero — a
 * missing sample is not a measured one.
 */
export type TimeSeries = { labels: Record<string, string>; dataPoints: TimeSeriesPoint[] }

/**
 * A horizontal line at a container's CPU or memory request or limit. The Y
 * axis grows to keep every reference line in view, and each carries its
 * label in text.
 */
export type ReferenceLine = { kind: 'request' | 'limit'; value: number; label: string }

/**
 * A vertical marker at one instant — the incident opening, or a recorded
 * change such as a new image. It marks the time and says nothing about
 * whether it explains the series around it.
 */
export type ChartAnnotation = {
  kind: 'opened' | 'change'
  /** Unix seconds, the same clock as TimeSeriesPoint.timestamp. */
  timestamp: number
  label: string
}
