export type Certainty = 'exact' | 'atLeast' | 'atMost' | 'unknown'

const WORDS: Record<Exclude<Certainty, 'exact' | 'unknown'>, { mark: string; word: string }> = {
  atLeast: { mark: '≥', word: 'at least' },
  atMost: { mark: '≤', word: 'at most' },
}

// Quantity renders a number whose source may be partial (docs/CLUSTER_INSIGHT_SPECS.md
// CI-U1). "Unknown" is a dash plus the word, never 0; a lower bound reads
// "≥ 12" visually and "at least 12" to a screen reader. Use it wherever the
// count comes from a capped list, a partial scan, or a source that may be
// unavailable.
export function Quantity({
  value,
  certainty = 'exact',
  unit,
  format = (n) => n.toLocaleString(),
  unknownLabel = 'unknown',
}: {
  value: number | null | undefined
  certainty?: Certainty
  unit?: string
  format?: (n: number) => string
  unknownLabel?: string
}) {
  if (value === null || value === undefined || certainty === 'unknown' || Number.isNaN(value)) {
    return (
      <span className="quantity quantity-unknown" aria-label={unknownLabel}>
        — <span className="visually-hidden">{unknownLabel}</span>
      </span>
    )
  }
  const text = `${format(value)}${unit ? ` ${unit}` : ''}`
  if (certainty === 'exact') {
    return <span className="quantity">{text}</span>
  }
  const q = WORDS[certainty]
  return (
    <span className="quantity" aria-label={`${q.word} ${text}`}>
      <span className="quantity-qualifier" aria-hidden="true">
        {q.mark}
      </span>
      <span aria-hidden="true">{text}</span>
    </span>
  )
}
