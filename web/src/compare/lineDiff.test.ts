import { describe, expect, it } from 'vitest'
import { diffLines, foldRows, isFold, splitRows, tokenize, unifiedRows, wordDiff, type Row } from './lineDiff'

const kinds = (ops: { kind: string }[]) => ops.map((o) => o.kind).join(' ')

describe('diffLines', () => {
  it('aligns unchanged lines and marks the rest', () => {
    const { ops, aligned } = diffLines(['a', 'b', 'c', 'd'], ['a', 'x', 'c', 'd', 'e'])
    expect(aligned).toBe(true)
    expect(kinds(ops)).toBe('equal del add equal equal add')
    expect(ops[1]).toEqual({ kind: 'del', a: 1 })
    expect(ops[2]).toEqual({ kind: 'add', b: 1 })
    expect(ops.at(-1)).toEqual({ kind: 'add', b: 4 })
  })

  it('handles identical and empty inputs', () => {
    expect(kinds(diffLines(['a', 'b'], ['a', 'b']).ops)).toBe('equal equal')
    expect(kinds(diffLines([], ['a']).ops)).toBe('add')
    expect(kinds(diffLines(['a'], []).ops)).toBe('del')
  })

  it('finds the longest common run inside a changed middle', () => {
    const { ops } = diffLines(['h', 'x1', 'k1', 'k2', 'x2', 't'], ['h', 'k1', 'y', 'k2', 't'])
    expect(ops.filter((o) => o.kind === 'equal').map((o) => o.a)).toEqual([0, 2, 3, 5])
  })

  it('does not try to align a middle too large to compute, and says so', () => {
    const a = Array.from({ length: 2001 }, (_, i) => `a${i}`)
    const b = Array.from({ length: 2001 }, (_, i) => `b${i}`)
    const { ops, aligned } = diffLines(a, b)
    expect(aligned).toBe(false)
    expect(ops.filter((o) => o.kind === 'del')).toHaveLength(2001)
    expect(ops.filter((o) => o.kind === 'add')).toHaveLength(2001)
  })
})

describe('rows', () => {
  const { ops } = diffLines(['k', 'a1', 'a2', 'z'], ['k', 'b1', 'z'])

  it('pairs removed and added lines side by side, leaving the extra alone', () => {
    expect(splitRows(ops)).toEqual([
      { kind: 'equal', a: 0, b: 0 },
      { kind: 'change', a: 1, b: 1 },
      { kind: 'del', a: 2 },
      { kind: 'equal', a: 3, b: 2 },
    ])
  })

  it('lists removed then added in unified, each knowing its partner', () => {
    expect(unifiedRows(ops)).toEqual([
      { kind: 'equal', a: 0, b: 0 },
      { kind: 'del', a: 1, pairB: 1 },
      { kind: 'del', a: 2, pairB: undefined },
      { kind: 'add', b: 1, pairA: 1 },
      { kind: 'equal', a: 3, b: 2 },
    ])
  })
})

describe('foldRows', () => {
  const eq = (i: number): Row => ({ kind: 'equal', a: i, b: i })
  const rows: Row[] = [...Array.from({ length: 10 }, (_, i) => eq(i)), { kind: 'change', a: 10, b: 10 }, ...Array.from({ length: 10 }, (_, i) => eq(11 + i))]

  it('keeps context next to a change and folds the rest with a true count', () => {
    const items = foldRows(rows, 3)
    const folds = items.filter(isFold)
    expect(folds.map((f) => f.rows.length)).toEqual([7, 7])
    expect(items.filter((i) => !isFold(i))).toHaveLength(7)
    expect(folds[0].id).toBe(0)
    expect(folds[1].id).toBe(14)
  })

  it('leaves an expanded fold open', () => {
    const items = foldRows(rows, 3, new Set([0]))
    expect(items.filter(isFold)).toHaveLength(1)
    expect(items.filter((i) => !isFold(i))).toHaveLength(14)
  })

  it('does not fold a run shorter than the minimum', () => {
    const short: Row[] = [eq(0), eq(1), eq(2), eq(3), { kind: 'del', a: 4 }]
    expect(foldRows(short, 3).some(isFold)).toBe(false)
  })

  it('folds a middle run between two changes', () => {
    const mid: Row[] = [{ kind: 'del', a: 0 }, ...Array.from({ length: 9 }, (_, i) => eq(1 + i)), { kind: 'add', b: 10 }]
    const folds = foldRows(mid, 3).filter(isFold)
    expect(folds).toHaveLength(1)
    expect(folds[0].rows.map((r) => r.a)).toEqual([4, 5, 6])
  })
})

describe('wordDiff', () => {
  it('highlights only the changed words', () => {
    const w = wordDiff('    image: r/app:1', '    image: r/app:2')!
    expect(w.a.filter((s) => s.changed).map((s) => s.text)).toEqual(['1'])
    expect(w.b.filter((s) => s.changed).map((s) => s.text)).toEqual(['2'])
  })

  it('treats a redaction marker as one token, never half-highlighted', () => {
    expect(tokenize('value: "[REDACTED]"')).toContain('[REDACTED]')
    const w = wordDiff('value: "[REDACTED]"', 'value: plain')!
    expect(w.a.find((s) => s.changed)?.text).toContain('[REDACTED]')
    expect(w.a.some((s) => !s.changed && s.text.includes('REDACTED'))).toBe(false)
  })

  it('returns null when the two lines share no word', () => {
    expect(wordDiff('alpha', 'beta')).toBeNull()
  })
})
