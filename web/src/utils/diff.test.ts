import { describe, expect, it } from 'vitest'

// Pure string classification, so it is tested directly rather than through the
// DOM — the interesting cases would be obscured by rendering.
import { classifyDiffLine } from '../utils/diff'

describe('classifyDiffLine', () => {
  it('does not mistake file headers for changes', () => {
    // The bug this exists for: `---` and `+++` are the unified-diff file headers
    // and they start with the same characters as a deletion and an addition. A
    // naive startsWith('+')/startsWith('-') order paints both headers as changes,
    // so a one-line change renders as three additions and three deletions and the
    // +/- counts are wrong on every diff.
    expect(classifyDiffLine('--- a/apps/web/deployment.yaml')).toBe('meta')
    expect(classifyDiffLine('+++ b/apps/web/deployment.yaml')).toBe('meta')
  })

  it('classifies the real change lines', () => {
    expect(classifyDiffLine('-  replicas: 2')).toBe('del')
    expect(classifyDiffLine('+  replicas: 3')).toBe('add')
  })

  it('classifies hunk headers and context', () => {
    expect(classifyDiffLine('@@ -4,7 +4,7 @@')).toBe('hunk')
    expect(classifyDiffLine('   name: web')).toBe('context')
    // A blank context line is still context, not something else.
    expect(classifyDiffLine('')).toBe('context')
  })

  it('treats a line whose content happens to start with a marker correctly', () => {
    // A YAML list item is "- item", so a CONTEXT line containing a list entry
    // arrives as " - item" (leading space from the diff format). If the leading
    // space were trimmed before classifying, every unchanged list entry in a
    // manifest would render as a deletion.
    expect(classifyDiffLine(' - name: sidecar')).toBe('context')
  })
})
