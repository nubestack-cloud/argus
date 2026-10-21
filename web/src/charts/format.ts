// Short, readable renderings of chart values and times, sized for axis labels
// and tooltips.

export type MetricUnit = 'percent' | 'cores' | 'bytes' | 'bytes/s' | 'count' | 'restarts' | 'seconds' | ''

// Each rung: values below `under` are divided by `div`, shown with `digits`
// decimals and `suffix`. The last rung of a ladder has under = Infinity.
type Rung = { under: number; div: number; digits: number; suffix: string }
const rung = (under: number, div: number, digits: number, suffix: string): Rung => ({ under, div, digits, suffix })

function climb(value: number, ladder: readonly Rung[]): string {
  const r = ladder.find(r => value < r.under) ?? ladder[ladder.length - 1]
  return (value / r.div).toFixed(r.digits) + r.suffix
}

const KiB = 1024
const binary = (unit: string): Rung[] => [
  rung(KiB, 1, 0, ` ${unit}`),
  rung(KiB ** 2, KiB, 1, ` Ki${unit}`),
  rung(KiB ** 3, KiB ** 2, 1, ` Mi${unit}`),
  rung(Infinity, KiB ** 3, 2, ` Gi${unit}`),
]

// Values smaller than the first rung of a unit are stated as a bound instead
// of being rounded to a zero that was never measured.
const formatters: Record<string, (v: number) => string> = {
  percent: v => v.toFixed(v < 1 ? 2 : 1) + '%',
  cores: v => (v < 0.0001 ? '< 0.1m' : climb(v, [rung(0.001, 0.001, 1, 'm'), rung(1, 0.001, 0, 'm'), rung(Infinity, 1, 2, '')])),
  bytes: v => (v < 1 ? '< 1 B' : climb(v, binary('B'))),
  'bytes/s': v => (v < 1 ? '< 1 B/s' : climb(v, binary('B/s'))),
  count: v => climb(v, [rung(10_000, 1, 0, ''), rung(1e6, 1e3, 1, 'k'), rung(Infinity, 1e6, 1, 'M')]),
  'req/s': v => (v < 0.01 ? '< 0.01/s' : climb(v, [rung(10, 1, 2, '/s'), rung(10_000, 1, 0, '/s'), rung(Infinity, 1e3, 1, 'k/s')])),
  seconds: v =>
    climb(v, [
      rung(0.001, 1e-6, 0, 'µs'),
      rung(0.01, 0.001, 2, 'ms'),
      rung(1, 0.001, 0, 'ms'),
      rung(10, 1, 2, 's'),
      rung(60, 1, 1, 's'),
      rung(3600, 60, 1, 'm'),
      rung(Infinity, 3600, 1, 'h'),
    ]),
}
formatters.restarts = formatters.count

// A unitless value: exponent form when tiny, SI prefixes when large.
const plain = (v: number) =>
  v < 0.01
    ? v.toExponential(1)
    : climb(v, [rung(1, 1, 3, ''), rung(100, 1, 2, ''), rung(10_000, 1, 0, ''), rung(1e6, 1e3, 1, 'k'), rung(1e9, 1e6, 1, 'M'), rung(Infinity, 1e9, 2, 'G')])

export function formatMetricValue(value: number, unit: MetricUnit | string): string {
  if (value === 0) return '0'
  if (value < 0) return '-' + formatMetricValue(-value, unit)
  return (formatters[unit] ?? plain)(value)
}

/** Hour and minute in the viewer's locale, from Unix seconds. */
export function formatTimestamp(unix: number): string {
  return new Date(unix * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}
