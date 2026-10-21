import { arcLengths } from '../utils/donut'
import { ABSENCE_TEXT } from './clusterOverviewModel'
import type { RingModel, RingTone } from './ringsModel'

// A part-to-whole ring for the cluster Overview (Pods / Workloads / Nodes).
// components.md allows a donut only with direct labels and counts, and that
// is what the legend under it is: every slice is a glyph, a count and a WORD,
// so the colour repeats the text and never carries the state alone. The
// glyph is aria-hidden; the legend is ordinary text a screen reader reads.

const TONE_FILL: Record<RingTone, string> = {
  ok: 'var(--chart-low)',
  warn: 'var(--chart-medium)',
  bad: 'var(--chart-critical)',
  info: 'var(--chart-info)',
  neutral: 'var(--chart-neutral)',
}

const R = 40
const C = 2 * Math.PI * R

export function Ring({ model }: { model: RingModel }) {
  const { title, total } = model
  if (total === null) {
    return (
      <section className="card card-compact ring-card" aria-label={title}>
        <svg className="ring" viewBox="0 0 100 100" role="img" aria-label={`${title}: ${ABSENCE_TEXT[model.absence ?? 'unknown']}`}>
          <circle cx="50" cy="50" r={R} className="ring-track" />
          <text x="50" y="57" textAnchor="middle" className="ring-value">—</text>
        </svg>
        <h3 className="ring-title">{title}</h3>
        <p className="ring-legend text-muted">{ABSENCE_TEXT[model.absence ?? 'unknown']}</p>
      </section>
    )
  }
  const visible = model.segments.filter((s) => s.count > 0)
  const lengths = arcLengths(
    visible.map((s) => s.count),
    total,
    C,
  )
  const offsets = lengths.reduce<number[]>((acc, _l, i) => [...acc, i === 0 ? 0 : acc[i - 1] + lengths[i - 1]], [])
  // The legend below is real text; the ring's own name is just the total.
  const sentence = `${title}: ${model.partial ? 'at least ' : ''}${total} in total`
  return (
    <section className="card card-compact ring-card" aria-label={title}>
      <svg className="ring" viewBox="0 0 100 100" role="img" aria-label={sentence}>
        <circle cx="50" cy="50" r={R} className="ring-track" />
        {visible.map((s, i) => (
          <circle
            key={s.key}
            cx="50"
            cy="50"
            r={R}
            className="ring-seg"
            stroke={TONE_FILL[s.tone]}
            strokeDasharray={`${lengths[i]} ${C - lengths[i]}`}
            strokeDashoffset={-offsets[i]}
            transform="rotate(-90 50 50)"
          />
        ))}
        <text x="50" y="57" textAnchor="middle" className="ring-value">
          {model.partial ? `≥${total}` : total}
        </text>
      </svg>
      <h3 className="ring-title">{title}</h3>
      <ul className="ring-legend">
        {model.segments
          .filter((s) => s.count > 0 || s.tone === 'bad' || s.tone === 'ok')
          .map((s) => (
            // A zero problem part keeps its word and count but drops the
            // danger colour: "0 failed" is not a problem to draw in red.
            <li key={s.key} data-tone={s.tone === 'bad' && s.count === 0 ? undefined : s.tone}>
              <span className="ring-glyph" aria-hidden="true">{{ check: '✓', half: '◐', circle: '○', cross: '✕', dot: '·' }[s.glyph]}</span> {s.count} {s.word}
            </li>
          ))}
      </ul>
      {model.notes.length > 0 && (
        <p className="ring-notes">{model.notes.join(' · ')}</p>
      )}
    </section>
  )
}
