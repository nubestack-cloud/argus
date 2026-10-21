import { classifyDiffLine } from '../utils/diff'

// A unified diff, rendered the way a reviewer expects to see one.
//
// The diff text comes from the hub (internal/gitops's unifiedDiff), so this only
// classifies and colours it — it never computes a diff itself. That split matters:
// the hub's diff is the one it verified and the one that goes in the pull request
// body, so a second, client-side derivation could disagree with the thing being
// committed.
//
// Deliberately not a dependency. A diff viewer library would bring syntax
// highlighting, side-by-side modes and a theme system for a payload that is a
// handful of lines of YAML with one change in it — and every one of those features
// is a way for what a reviewer sees to drift from the bytes the hub verified.

export function UnifiedDiff({ diff, ariaLabel }: { diff: string; ariaLabel?: string }) {
  // trimEnd only: leading whitespace is significant in YAML, and a diff whose
  // indentation has been "tidied" is a misleading diff.
  const lines = diff.replace(/\n+$/, '').split('\n')

  const added = lines.filter((l) => classifyDiffLine(l) === 'add').length
  const removed = lines.filter((l) => classifyDiffLine(l) === 'del').length

  return (
    <div className="unified-diff" role="group" aria-label={ariaLabel ?? 'Proposed change'}>
      <div className="unified-diff-summary">
        <span className="unified-diff-stat unified-diff-stat-add">+{added}</span>
        <span className="unified-diff-stat unified-diff-stat-del">−{removed}</span>
        <span className="field-hint">
          {added === 1 && removed === 1
            ? 'one line changed'
            : `${added} added, ${removed} removed`}
        </span>
      </div>
      {/* A table rather than a <pre>: it gives each line a cell that can carry its
          own background across the full width, which a <pre> cannot do without
          wrapping every line in a span anyway. Line numbers are deliberately absent
          — the hub's diff is a small window with context, and numbering it from 1
          would imply the file starts here. */}
      <table className="unified-diff-body">
        <tbody>
          {lines.map((line, i) => {
            const kind = classifyDiffLine(line)
            return (
              <tr key={i} className={`unified-diff-line unified-diff-${kind}`}>
                <td className="unified-diff-marker" aria-hidden="true">
                  {kind === 'add' ? '+' : kind === 'del' ? '−' : ''}
                </td>
                <td className="unified-diff-code">
                  {/* The marker character is stripped from the displayed text
                      because it is shown in its own column; without this the line
                      reads "++ replicas: 3". Context lines in a unified diff start
                      with a single space, which is removed for the same reason. */}
                  <code>{kind === 'add' || kind === 'del' ? line.slice(1) : line.replace(/^ /, '')}</code>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
