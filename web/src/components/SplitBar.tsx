import type { ReactNode } from 'react'

// Shared chart primitives for the cluster tabs (PROJECT.md UX1, the
// 2026-10-11 cluster-pages design). Each draws a fact that has a shape —
// a whole split into states, or one value per name — instead of writing it
// out as a sentence (anti-patterns.md, "Document-shaped UI").
//
// Every segment's meaning is a WORD in the legend or the row, never the
// colour alone: --chart-medium in particular is 1.67:1 against the surface
// and is only legal with a direct label (tokens.md).

export type BarTone = 'critical' | 'high' | 'medium' | 'ok' | 'info' | 'neutral' | 'accent' | 'unknown'

export interface BarPart {
  tone: BarTone
  value: number
  /** The word for this part: "critical", "out of sync", "could not check". */
  label: string
}

function describe(parts: readonly BarPart[]): string {
  return parts.map((p) => `${p.value} ${p.label}`).join(', ')
}

/** A stacked bar of one whole split into parts, with a legend of glyph +
 *  count + word per part. A part with value 0 is not drawn but stays in the
 *  legend when `showZero` is set — "0 out of sync" is a fact worth stating. */
export function SplitBar({
  parts,
  label,
  tall = false,
  legend = true,
  showZero = false,
}: {
  parts: readonly BarPart[]
  /** What the whole is, for the accessible name: "Open incidents by severity". */
  label: string
  tall?: boolean
  legend?: boolean
  showZero?: boolean
}) {
  const total = parts.reduce((n, p) => n + p.value, 0)
  const shown = showZero ? parts : parts.filter((p) => p.value > 0)
  return (
    <div className="split">
      <div className={tall ? 'split-bar split-bar-tall' : 'split-bar'} role="img" aria-label={`${label}: ${describe(shown)}`}>
        {total > 0 &&
          parts
            .filter((p) => p.value > 0)
            .map((p) => <span key={p.label} className="split-seg" data-tone={p.tone} style={{ width: `${(p.value * 100) / total}%` }} />)}
      </div>
      {legend && <SplitLegend parts={shown} />}
    </div>
  )
}

export function SplitLegend({ parts }: { parts: readonly BarPart[] }) {
  return (
    <ul className="split-legend" aria-hidden="true">
      {parts.map((p) => (
        <li key={p.label}>
          <span className="split-swatch" data-tone={p.tone} />
          <strong>{p.value.toLocaleString()}</strong> {p.label}
        </li>
      ))}
    </ul>
  )
}

export interface BarListRow {
  key: string
  name: ReactNode
  /** Accessible text for the name when `name` is not plain text. */
  nameText?: string
  parts: readonly BarPart[]
  onSelect?: () => void
  selected?: boolean
}

/** One bar per name on a shared scale (the largest row's total fills the
 *  track), the total printed at the right. Rows with `onSelect` are buttons,
 *  so a bar list can be a filter. */
export function BarList({ rows, label, max }: { rows: readonly BarListRow[]; label: string; max?: number }) {
  const top = max ?? Math.max(1, ...rows.map((r) => r.parts.reduce((n, p) => n + p.value, 0)))
  return (
    <ul className="bar-list" aria-label={label}>
      {rows.map((r) => {
        const total = r.parts.reduce((n, p) => n + p.value, 0)
        const body = (
          <>
            <span className="bar-list-name">{r.name}</span>
            <span className="bar-list-track" role="img" aria-label={`${r.nameText ?? (typeof r.name === 'string' ? r.name : r.key)}: ${describe(r.parts.filter((p) => p.value > 0))}`}>
              {r.parts
                .filter((p) => p.value > 0)
                .map((p) => (
                  <span key={p.label} className="split-seg" data-tone={p.tone} style={{ width: `${(p.value * 100) / top}%` }} />
                ))}
            </span>
            <span className="bar-list-value">{total.toLocaleString()}</span>
          </>
        )
        return (
          <li key={r.key}>
            {r.onSelect ? (
              <button type="button" className="bar-list-row" aria-pressed={!!r.selected} onClick={r.onSelect}>
                {body}
              </button>
            ) : (
              <div className="bar-list-row">{body}</div>
            )}
          </li>
        )
      })}
    </ul>
  )
}

export interface ChipOption<T extends string> {
  id: T
  label: string
  count?: number | null
}

/** Filter chips: one choice from a few, each with its count. A chip whose
 *  count is 0 stays enabled — choosing it shows the honest empty state. */
export function FilterChips<T extends string>({
  options,
  value,
  onChange,
  label,
}: {
  options: readonly ChipOption<T>[]
  value: T
  onChange: (v: T) => void
  label: string
}) {
  return (
    <div className="filter-chips" role="group" aria-label={label}>
      {options.map((o) => (
        <button key={o.id} type="button" className="filter-chip" aria-pressed={o.id === value} onClick={() => onChange(o.id)}>
          {o.label}
          {o.count != null && <span className="filter-chip-count">{o.count.toLocaleString()}</span>}
        </button>
      ))}
    </div>
  )
}

/** A segmented control for 2–5 mutually exclusive options (a window, a
 *  category). Replaces a full-width select for a short fixed list.
 *
 *  `disabled`/`disabledReason` are optional — every pre-existing call site
 *  omits them and is unaffected — added so a capability-gated screen can
 *  disable-with-a-reason (lld/11 §6) rather than hide the control, the same
 *  discipline every other input in this codebase already follows. */
export function Segmented<T extends string>({
  options,
  value,
  onChange,
  label,
  disabled,
  disabledReason,
}: {
  options: readonly { id: T; label: string }[]
  value: T
  onChange: (v: T) => void
  label: string
  disabled?: boolean
  disabledReason?: string
}) {
  return (
    <div className="segmented" role="group" aria-label={label}>
      {options.map((o) => (
        <button
          key={o.id}
          type="button"
          aria-pressed={o.id === value}
          onClick={() => onChange(o.id)}
          disabled={disabled}
          title={disabled ? disabledReason : undefined}
        >
          {o.label}
        </button>
      ))}
    </div>
  )
}
