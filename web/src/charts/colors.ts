// Colours and names for the series of a multi-series chart.
//
// A colour is a reference to one of index.css's `--chart-*` fill tokens,
// never a literal, so both themes follow the stylesheet. Two tokens are kept
// out of the rotation: `--chart-critical`, because a series is not a severity
// and red would read as one, and `--chart-medium`, which is 1.67:1 on a light
// surface and allowed only beside a direct label (tokens.md). Every series is
// also named in the legend and in the table fallback, so colour never has to
// tell series apart by itself; past four series the colours repeat.
export const SERIES_COLOR_TOKENS: readonly string[] = ['--chart-info', '--chart-low', '--chart-high', '--chart-neutral']

export function seriesColor(index: number): string {
  const n = SERIES_COLOR_TOKENS.length
  return `var(${SERIES_COLOR_TOKENS.at(index % n)})`
}

/** The translucent area under the line of the same index. */
export function seriesFill(index: number): string {
  return `color-mix(in srgb, ${seriesColor(index)} 14%, transparent)`
}

const everyLabel = (labels: Record<string, string>, i: number) => {
  const pairs = Object.entries(labels)
  return pairs.length ? pairs.map(([k, v]) => `${k}=${v}`).join(', ') : `series-${i}`
}

/**
 * One name per series. The pod, instance or node is what an operator knows a
 * series by; but when an aggregation dropped it, or two series share it (two
 * containers of one pod), the names would collide, so then every series is
 * named by all its labels.
 */
export function seriesDisplayLabels(series: readonly { labels: Record<string, string> }[]): string[] {
  const short = series.map(({ labels }, i) => labels.pod || labels.instance || labels.node || everyLabel(labels, i))
  return new Set(short).size === short.length ? short : series.map(({ labels }, i) => everyLabel(labels, i))
}

/**
 * Drops what every label shares, back to the last "-" or "/" in that shared
 * part, so the legend shows what differs:
 *   payments-849bd668f9-4tzkg, payments-849bd668f9-5z79f → 4tzkg, 5z79f
 * When that would leave a label empty or two the same, the full labels are
 * kept: long and right beats short and misleading.
 */
export function computeShortLabels(labels: string[]): string[] {
  if (labels.length < 2) return labels
  let common = 0
  while (labels.every(l => common < l.length && l[common] === labels[0][common])) common++
  const shared = labels[0].slice(0, common)
  const sep = Math.max(shared.lastIndexOf('-'), shared.lastIndexOf('/'))
  const cut = sep > 0 ? sep + 1 : common
  const rest = labels.map(l => l.slice(cut))
  return rest.includes('') || new Set(rest).size < rest.length ? labels : rest
}
