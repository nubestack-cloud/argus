// Axis geometry and tick choice for the time-series chart. Pure, so tick
// choices are tested without rendering.

export interface ChartLayout {
  width: number
  height: number
  /** Space around the plot for tick labels, in viewBox units. */
  margin: { top: number; right: number; bottom: number; left: number }
  fontSize: number
  /** Gaps between Y ticks (one fewer than the ticks). */
  yIntervals: number
  /** Gaps between X ticks. */
  xIntervals: number
}

/**
 * The chart's viewBox. Given the container's measured width, the viewBox is
 * that width, so text and height stay a fixed size in pixels as the plot
 * widens and only the tick count grows. Before the first measurement a fixed
 * 1000-unit box stands in.
 */
export function chartLayout(renderedWidth = 0): ChartLayout {
  if (renderedWidth <= 0) {
    return { width: 1000, height: 300, margin: { top: 10, right: 40, bottom: 30, left: 84 }, fontSize: 11, yIntervals: 4, xIntervals: 6 }
  }
  return {
    width: renderedWidth,
    height: 240,
    margin: { top: 12, right: 14, bottom: 28, left: 60 },
    fontSize: 12,
    yIntervals: 2,
    xIntervals: renderedWidth >= 760 ? 4 : 2,
  }
}

/** Units whose values are whole numbers, so their axis must be too. */
export function isCountUnit(unit: string): boolean {
  return ['count', 'restarts'].includes(unit)
}

/**
 * The top of a whole-number axis: the smallest step of 1, 2 or 5 times a
 * power of ten that covers `max` in `intervals` steps, then `max` rounded up
 * to a multiple of it. 0 and 1 give 1, 3 gives 3, 18 gives 20.
 */
export function integerAxisTop(max: number, intervals: number): number {
  const top = Math.max(1, Math.ceil(max))
  const perGap = top / Math.max(1, intervals)
  const decade = 10 ** Math.floor(Math.log10(perGap))
  const step = Math.max(1, [1, 2, 5, 10].map(b => b * decade).find(s => s >= perGap) ?? 10 * decade)
  return step * Math.ceil(top / step)
}

/**
 * Tick values from yMin to yMax. A whole-number axis from zero ticks in whole
 * steps and always ends on yMax; any other axis divides the range evenly.
 */
export function yAxisValues(yMin: number, yMax: number, intervals: number, integer: boolean): number[] {
  if (!integer || yMin !== 0) {
    return Array.from({ length: intervals + 1 }, (_, i) => yMin + ((yMax - yMin) / intervals) * i)
  }
  const raw = yMax / intervals
  const step = Number.isInteger(raw) ? raw : Math.max(1, Math.ceil(raw))
  const ticks = Array.from({ length: Math.floor(yMax / step) + 1 }, (_, i) => i * step)
  return ticks.at(-1) === yMax ? ticks : [...ticks, yMax]
}
