import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { ANNOTATION_LABEL_ROWS, layoutAnnotations } from './annotations'
import { chartLayout, integerAxisTop, isCountUnit, yAxisValues } from './axis'
import { computeShortLabels, seriesColor, seriesDisplayLabels } from './colors'
import { formatMetricValue, formatTimestamp } from './format'
import { nearestSample } from './nearestSample'
import { niceCeil, seriesRuns } from './series'
import type { ChartAnnotation, ReferenceLine, TimeSeries } from './types'

// TimeSeriesChart — the line-chart primitive (docs/CLUSTER_INSIGHT_SPECS.md
// CI-S8). SVG, theme-following (every colour is a var(--*) token), and
// honest about absence:
//   - a missing sample breaks the line; it is never drawn as zero;
//   - a chart with no samples at all is not drawn — the caller gets a
//     sentence saying so, because an empty chart reads as a measured zero;
//   - every series is named in a text legend (colour is never the only way
//     to tell series apart) and in the table fallback;
//   - markers ("opened", a recorded change) are labelled in text and listed
//     again under the table, so a label hidden for space is still reachable.
// The plot is one keyboard stop: ←/→ move a cursor sample by sample, Home/End
// jump, Esc clears, and the readout below announces the nearest sample of
// each series at that instant.

export interface TimeSeriesChartProps {
  title: string
  unit: string
  series: readonly TimeSeries[]
  annotations?: readonly ChartAnnotation[]
  referenceLines?: readonly ReferenceLine[]
  /** Evaluation step; limits how far a cursor may snap to a sample. */
  stepSeconds?: number
  /** Time window to draw (Unix seconds); defaults to the samples' extent. */
  domain?: { minTs: number; maxTs: number }
}

const ANNOTATION_ROW_HEIGHT = 14

function useMeasuredWidth(fallback: number) {
  const ref = useRef<HTMLDivElement>(null)
  const [width, setWidth] = useState(fallback)
  useEffect(() => {
    const el = ref.current
    if (!el || typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver((entries) => {
      const w = Math.floor(entries[0]?.contentRect.width ?? 0)
      if (w > 0) setWidth(w)
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  return [ref, width] as const
}

export function TimeSeriesChart({ title, unit, series, annotations = [], referenceLines = [], stepSeconds, domain }: TimeSeriesChartProps) {
  const [wrapRef, width] = useMeasuredWidth(640)
  const [asTable, setAsTable] = useState(false)
  const [cursor, setCursor] = useState<number | null>(null)
  const descId = useId()

  const names = useMemo(() => computeShortLabels(seriesDisplayLabels(series)), [series])
  const values = useMemo(
    () => series.flatMap((s) => s.dataPoints.map((p) => p.value).filter((v): v is number => v != null && Number.isFinite(v))),
    [series],
  )
  const times = useMemo(() => {
    const set = new Set<number>()
    for (const s of series) for (const p of s.dataPoints) if (p.value != null && Number.isFinite(p.value)) set.add(p.timestamp)
    return [...set].sort((a, b) => a - b)
  }, [series])

  if (values.length === 0) {
    return (
      <div className="ts-chart">
        <p className="ts-chart-title">{title}</p>
        <p className="empty-state">No samples were returned for this window. That is an absence of data, not a measured zero.</p>
      </div>
    )
  }

  const layout = chartLayout(width)
  const reserve = annotations.length > 0 ? ANNOTATION_LABEL_ROWS * ANNOTATION_ROW_HEIGHT : 0
  const height = layout.height + reserve
  const left = layout.margin.left
  const right = width - layout.margin.right
  const top = layout.margin.top + reserve
  const bottom = height - layout.margin.bottom

  let minTs = domain?.minTs ?? times[0]
  let maxTs = domain?.maxTs ?? times[times.length - 1]
  if (maxTs <= minTs) {
    minTs -= stepSeconds ?? 60
    maxTs += stepSeconds ?? 60
  }
  const integer = isCountUnit(unit)
  const peak = Math.max(...values, ...referenceLines.map((r) => r.value))
  const yMin = Math.min(0, ...values)
  const yMax = integer ? integerAxisTop(peak, layout.yIntervals) : niceCeil(peak * 1.05)
  const yTicks = yAxisValues(yMin, yMax, layout.yIntervals, integer && yMin === 0)
  const toX = (ts: number) => left + ((ts - minTs) / (maxTs - minTs)) * (right - left)
  const toY = (v: number) => bottom - ((v - yMin) / (yMax - yMin || 1)) * (bottom - top)
  const xTicks = Array.from({ length: layout.xIntervals + 1 }, (_, i) => minTs + ((maxTs - minTs) / layout.xIntervals) * i)
  const placed = layoutAnnotations(annotations, toX, { minTs, maxTs }, { left, right })

  const cursorTs = cursor === null ? null : times[cursor]
  const readings =
    cursorTs === null
      ? []
      : series.map((s, i) => ({ name: names[i], sample: nearestSample(s.dataPoints, cursorTs, stepSeconds) }))

  const nearestIndex = (ts: number) => {
    let best = 0
    for (let i = 1; i < times.length; i++) if (Math.abs(times[i] - ts) < Math.abs(times[best] - ts)) best = i
    return best
  }

  const label = `${title}: ${series.length} series from ${formatTimestamp(minTs)} to ${formatTimestamp(maxTs)}, peak ${formatMetricValue(Math.max(...values), unit)}${
    annotations.length ? `, ${annotations.length} marker${annotations.length === 1 ? '' : 's'}` : ''
  }`

  return (
    <div className="ts-chart" ref={wrapRef}>
      <div className="ts-chart-head">
        <p className="ts-chart-title">{title}</p>
        <button type="button" className="secondary ts-chart-toggle" aria-pressed={asTable} onClick={() => setAsTable((v) => !v)}>
          {asTable ? 'View as chart' : 'View as table'}
        </button>
      </div>
      <ul className="ts-chart-legend">
        {series.map((_, i) => (
          <li key={i}>
            <span className="ts-chart-swatch" style={{ background: seriesColor(i) }} aria-hidden="true" />
            <span className="insight-mono">{names[i]}</span>
          </li>
        ))}
      </ul>
      {asTable ? (
        <ChartTable title={title} unit={unit} series={series} names={names} times={times} annotations={annotations} />
      ) : (
        <>
          <svg
            className="ts-chart-svg"
            width={width}
            height={height}
            viewBox={`0 0 ${width} ${height}`}
            role="img"
            aria-label={label}
            aria-describedby={descId}
            tabIndex={0}
            onKeyDown={(e) => {
              if (e.key === 'ArrowRight') setCursor((c) => (c === null ? 0 : Math.min(times.length - 1, c + 1)))
              else if (e.key === 'ArrowLeft') setCursor((c) => (c === null ? times.length - 1 : Math.max(0, c - 1)))
              else if (e.key === 'Home') setCursor(0)
              else if (e.key === 'End') setCursor(times.length - 1)
              else if (e.key === 'Escape') setCursor(null)
              else return
              e.preventDefault()
            }}
            onMouseMove={(e) => {
              const box = e.currentTarget.getBoundingClientRect()
              const x = ((e.clientX - box.left) / (box.width || 1)) * width
              if (x < left || x > right) return
              setCursor(nearestIndex(minTs + ((x - left) / (right - left)) * (maxTs - minTs)))
            }}
            onMouseLeave={() => setCursor(null)}
          >
            {yTicks.map((v) => (
              <g key={`y${v}`}>
                <line className="ts-chart-grid" x1={left} x2={right} y1={toY(v)} y2={toY(v)} />
                <text className="ts-chart-axis" x={left - 6} y={toY(v)} textAnchor="end" dominantBaseline="middle">
                  {formatMetricValue(v, unit)}
                </text>
              </g>
            ))}
            {xTicks.map((ts, i) => (
              <text key={`x${i}`} className="ts-chart-axis" x={toX(ts)} y={bottom + 18} textAnchor={i === 0 ? 'start' : i === xTicks.length - 1 ? 'end' : 'middle'}>
                {formatTimestamp(ts)}
              </text>
            ))}
            <line className="ts-chart-baseline" x1={left} x2={right} y1={bottom} y2={bottom} />
            {referenceLines.map((r, i) => (
              <g key={`r${i}`}>
                <line className="ts-chart-ref" x1={left} x2={right} y1={toY(r.value)} y2={toY(r.value)} />
                <text className="ts-chart-axis" x={right} y={toY(r.value) - 4} textAnchor="end">
                  {r.label} {formatMetricValue(r.value, unit)}
                </text>
              </g>
            ))}
            {series.map((s, i) =>
              seriesRuns(s.dataPoints).map((run, j) =>
                run.length === 1 ? (
                  <circle key={`${i}-${j}`} cx={toX(run[0].timestamp)} cy={toY(run[0].value)} r={2} style={{ fill: seriesColor(i) }} />
                ) : (
                  <path
                    key={`${i}-${j}`}
                    className="ts-chart-line"
                    style={{ stroke: seriesColor(i) }}
                    d={run.map((p, k) => `${k === 0 ? 'M' : 'L'}${toX(p.timestamp).toFixed(1)},${toY(p.value).toFixed(1)}`).join('')}
                  />
                ),
              ),
            )}
            {placed.map((a, i) => (
              <g key={`a${i}`}>
                <line
                  className={a.annotation.kind === 'opened' ? 'ts-chart-marker ts-chart-marker-opened' : 'ts-chart-marker'}
                  x1={a.x}
                  x2={a.x}
                  y1={top}
                  y2={bottom}
                />
                {a.label && (
                  <text className="ts-chart-marker-label" x={a.label.x} y={layout.margin.top + a.label.row * ANNOTATION_ROW_HEIGHT + 10}>
                    {a.label.text}
                  </text>
                )}
              </g>
            ))}
            {cursorTs !== null && (
              <g>
                <line className="ts-chart-cursor" x1={toX(cursorTs)} x2={toX(cursorTs)} y1={top} y2={bottom} />
                {readings.map((r, i) =>
                  r.sample ? (
                    <circle key={i} className="ts-chart-cursor-dot" cx={toX(r.sample.timestamp)} cy={toY(r.sample.value)} r={4} style={{ stroke: seriesColor(i) }} />
                  ) : null,
                )}
              </g>
            )}
          </svg>
          <div className="ts-chart-readout" id={descId} aria-live="polite">
            {cursorTs === null ? (
              <span className="field-hint">Hover the chart, or focus it and use ← and → to read each sample.</span>
            ) : (
              <>
                <strong>{formatTimestamp(cursorTs)}</strong>
                {readings.map((r, i) => (
                  <span key={i}>
                    {' · '}
                    <span className="insight-mono">{r.name}</span> {r.sample ? formatMetricValue(r.sample.value, unit) : 'no sample'}
                  </span>
                ))}
              </>
            )}
          </div>
          {placed.some((a) => a.label === null) && (
            <p className="field-hint">Some marker labels did not fit; every marker is listed in the table view.</p>
          )}
        </>
      )}
    </div>
  )
}

function ChartTable({
  title,
  unit,
  series,
  names,
  times,
  annotations,
}: {
  title: string
  unit: string
  series: readonly TimeSeries[]
  names: string[]
  times: number[]
  annotations: readonly ChartAnnotation[]
}) {
  const byTs = series.map((s) => new Map(s.dataPoints.filter((p) => p.value != null).map((p) => [p.timestamp, p.value as number])))
  return (
    <div className="insight-stack">
      <div className="table-scroll ts-chart-table">
        <table className="list-table">
          <caption className="visually-hidden">{title}</caption>
          <thead>
            <tr>
              <th scope="col">Time</th>
              {names.map((n, i) => (
                <th key={i} scope="col" className="col-numeric insight-mono">
                  {n}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {times.map((ts) => (
              <tr key={ts}>
                <td>{formatTimestamp(ts)}</td>
                {byTs.map((m, i) => {
                  const v = m.get(ts)
                  return (
                    <td key={i} className="col-numeric">
                      {v === undefined ? '—' : formatMetricValue(v, unit)}
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {annotations.length > 0 && (
        <ul className="insight-plain-list">
          {[...annotations]
            .sort((a, b) => a.timestamp - b.timestamp)
            .map((a, i) => (
              <li key={i}>
                <strong>{formatTimestamp(a.timestamp)}</strong> — {a.label}
              </li>
            ))}
        </ul>
      )}
    </div>
  )
}
