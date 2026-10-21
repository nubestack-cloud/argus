import { splitRedacted } from '../model'

// Read-only text in a `.code-view` with line numbers, where every value the
// agent redacted at capture time is marked — never shown as blank, which
// would read as "this field is empty". Plain text interpolation only: the
// content is cluster-derived and untrusted.
export function CodeLines({
  lines,
  wrap = false,
  label,
  numbered = true,
}: {
  lines: readonly string[]
  wrap?: boolean
  label: string
  numbered?: boolean
}) {
  return (
    <pre className={`code-view${wrap ? ' code-view-wrap' : ''}`} aria-label={label} tabIndex={0}>
      {lines.map((line, i) => (
        <span key={i} className="code-view-line">
          {numbered && (
            <span className="code-view-lineno" aria-hidden="true">
              {i + 1}
            </span>
          )}
          {splitRedacted(line).map((seg, j) =>
            seg.redacted ? (
              <span key={j} className="redacted-marker" title="Redacted by the cluster agent before it left the cluster. ARGUS never received this value.">
                ‹redacted›
              </span>
            ) : (
              <span key={j}>{seg.text}</span>
            ),
          )}
          {'\n'}
        </span>
      ))}
    </pre>
  )
}
