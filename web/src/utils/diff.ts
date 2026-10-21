// Classifying the lines of a unified diff.
//
// Its own module rather than part of UnifiedDiff.tsx: exporting a non-component
// from a component file defeats React fast refresh (oxlint says so), and this is
// the part worth testing independently — the ordering inside it is subtle enough
// to have a test of its own.
//
// It only ever CLASSIFIES text the hub produced. It never computes a diff: the
// hub's diff is the one it verified and the one that goes in the pull request body,
// so a client-side derivation could disagree with the thing being committed.

export type DiffLineKind = 'add' | 'del' | 'hunk' | 'meta' | 'context'

export function classifyDiffLine(line: string): DiffLineKind {
  // Order matters. `---` and `+++` are the unified-diff FILE HEADERS and they start
  // with the same characters as a deletion and an addition, so a naive
  // startsWith('+')/startsWith('-') check paints both headers as changes — which
  // makes a one-line change render as three additions and three deletions, and the
  // +/- counts wrong on every diff.
  if (line.startsWith('+++') || line.startsWith('---')) return 'meta'
  if (line.startsWith('@@')) return 'hunk'
  if (line.startsWith('+')) return 'add'
  if (line.startsWith('-')) return 'del'
  return 'context'
}
