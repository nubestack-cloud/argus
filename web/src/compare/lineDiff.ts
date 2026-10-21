import type { CompareLayout } from './compareUrl'

// A plain longest-common-subsequence line diff, and a word diff for the lines
// a change pairs up. No dependency: the inputs are two YAML renderings of
// Kubernetes objects (hundreds of lines), well inside what a dynamic
// programme handles, and every rule here — redaction markers as one token,
// folding, pairing — is ours to pin in tests.

export type OpKind = 'equal' | 'del' | 'add'

/** One line of the edit script; `a`/`b` are 0-based line indices. */
export interface Op {
  kind: OpKind
  a?: number
  b?: number
}

export interface LineDiff {
  ops: Op[]
  /** False when the changed middle was too large to align line by line and
   *  is shown as removed-then-added instead. */
  aligned: boolean
}

/** Above this many DP cells (changed lines on A × on B) the middle is not
 *  aligned: 4M cells is ~8 MB of Uint16 and well under a second. */
export const MAX_ALIGN_CELLS = 4_000_000

/** LCS over two sequences with a predicate; returns index pairs in order. */
function lcsPairs<T>(a: readonly T[], b: readonly T[], eq: (x: T, y: T) => boolean): [number, number][] {
  const n = a.length
  const m = b.length
  const w = m + 1
  const dp = new Uint16Array((n + 1) * w)
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i * w + j] = eq(a[i], b[j]) ? dp[(i + 1) * w + j + 1] + 1 : Math.max(dp[(i + 1) * w + j], dp[i * w + j + 1])
    }
  }
  const out: [number, number][] = []
  let i = 0
  let j = 0
  while (i < n && j < m) {
    if (eq(a[i], b[j])) {
      out.push([i, j])
      i++
      j++
    } else if (dp[(i + 1) * w + j] >= dp[i * w + j + 1]) i++
    else j++
  }
  return out
}

export function diffLines(a: readonly string[], b: readonly string[]): LineDiff {
  let pre = 0
  while (pre < a.length && pre < b.length && a[pre] === b[pre]) pre++
  let suf = 0
  while (suf < a.length - pre && suf < b.length - pre && a[a.length - 1 - suf] === b[b.length - 1 - suf]) suf++

  const ops: Op[] = []
  for (let i = 0; i < pre; i++) ops.push({ kind: 'equal', a: i, b: i })
  const midA = a.slice(pre, a.length - suf)
  const midB = b.slice(pre, b.length - suf)
  let aligned = true
  if (midA.length * midB.length > MAX_ALIGN_CELLS || midA.length > 65535 || midB.length > 65535) {
    aligned = false
    midA.forEach((_, i) => ops.push({ kind: 'del', a: pre + i }))
    midB.forEach((_, j) => ops.push({ kind: 'add', b: pre + j }))
  } else {
    let i = 0
    let j = 0
    for (const [pi, pj] of lcsPairs(midA, midB, (x, y) => x === y)) {
      while (i < pi) ops.push({ kind: 'del', a: pre + i++ })
      while (j < pj) ops.push({ kind: 'add', b: pre + j++ })
      ops.push({ kind: 'equal', a: pre + i++, b: pre + j++ })
    }
    while (i < midA.length) ops.push({ kind: 'del', a: pre + i++ })
    while (j < midB.length) ops.push({ kind: 'add', b: pre + j++ })
  }
  for (let k = 0; k < suf; k++) ops.push({ kind: 'equal', a: a.length - suf + k, b: b.length - suf + k })
  return { ops, aligned }
}

// ---------------------------------------------------------------- rows

/**
 * One displayed row. Side by side, a removed line and an added line at the
 * same position in a change block share a row (`change`); unified, they are
 * separate `del`/`add` rows that still know their partner (`pairA`/`pairB`)
 * so both can carry word highlights.
 */
export interface Row {
  kind: 'equal' | 'del' | 'add' | 'change'
  a?: number
  b?: number
  /** Unified only: the line on the other side this one was paired with. */
  pairA?: number
  pairB?: number
}

function blocks(ops: readonly Op[], onEqual: (op: Op) => void, onBlock: (dels: number[], adds: number[]) => void) {
  let dels: number[] = []
  let adds: number[] = []
  const flush = () => {
    if (dels.length || adds.length) onBlock(dels, adds)
    dels = []
    adds = []
  }
  for (const op of ops) {
    if (op.kind === 'equal') {
      flush()
      onEqual(op)
    } else if (op.kind === 'del') dels.push(op.a!)
    else adds.push(op.b!)
  }
  flush()
}

export function splitRows(ops: readonly Op[]): Row[] {
  const rows: Row[] = []
  blocks(
    ops,
    (op) => rows.push({ kind: 'equal', a: op.a, b: op.b }),
    (dels, adds) => {
      const n = Math.max(dels.length, adds.length)
      for (let i = 0; i < n; i++) {
        if (i < dels.length && i < adds.length) rows.push({ kind: 'change', a: dels[i], b: adds[i] })
        else if (i < dels.length) rows.push({ kind: 'del', a: dels[i] })
        else rows.push({ kind: 'add', b: adds[i] })
      }
    },
  )
  return rows
}

export function unifiedRows(ops: readonly Op[]): Row[] {
  const rows: Row[] = []
  blocks(
    ops,
    (op) => rows.push({ kind: 'equal', a: op.a, b: op.b }),
    (dels, adds) => {
      dels.forEach((a, i) => rows.push({ kind: 'del', a, pairB: adds[i] }))
      adds.forEach((b, i) => rows.push({ kind: 'add', b, pairA: dels[i] }))
    },
  )
  return rows
}

// ---------------------------------------------------------------- folding

export interface Fold {
  fold: true
  /** Stable id: the index of the first hidden row. */
  id: number
  rows: Row[]
}

export type Item = Row | Fold

export function isFold(i: Item): i is Fold {
  return 'fold' in i
}

/**
 * Diff-only view: runs of unchanged rows keep `context` rows next to each
 * change and fold the rest into one "N unchanged lines" item. A fold that
 * would hide fewer than `minFold` rows is shown instead — an expander that
 * reveals one line costs more than the line. Folds whose id is in
 * `expanded` are left open.
 */
export function foldRows(rows: readonly Row[], context = 3, expanded: ReadonlySet<number> = new Set(), minFold = 2): Item[] {
  const out: Item[] = []
  let i = 0
  while (i < rows.length) {
    if (rows[i].kind !== 'equal') {
      out.push(rows[i++])
      continue
    }
    let j = i
    while (j < rows.length && rows[j].kind === 'equal') j++
    const keepBefore = i === 0 ? 0 : context
    const keepAfter = j === rows.length ? 0 : context
    const hideStart = i + keepBefore
    const hideEnd = j - keepAfter
    if (hideEnd - hideStart >= minFold && !expanded.has(hideStart)) {
      for (let k = i; k < hideStart; k++) out.push(rows[k])
      out.push({ fold: true, id: hideStart, rows: rows.slice(hideStart, hideEnd) })
      for (let k = hideEnd; k < j; k++) out.push(rows[k])
    } else {
      for (let k = i; k < j; k++) out.push(rows[k])
    }
    i = j
  }
  return out
}

// ---------------------------------------------------------------- word diff

export interface Segment {
  text: string
  changed: boolean
}

/** Words, runs of whitespace, single punctuation — and a redaction marker as
 *  ONE token, so a marker is never half-highlighted. */
export function tokenize(line: string): string[] {
  const re = /\[REDACTED\]|\s+|[A-Za-z0-9_]+|[^\sA-Za-z0-9_]/g
  return line.match(re) ?? []
}

function merge(tokens: { text: string; changed: boolean }[]): Segment[] {
  const out: Segment[] = []
  for (const t of tokens) {
    const last = out[out.length - 1]
    if (last && last.changed === t.changed) last.text += t.text
    else out.push({ ...t })
  }
  return out
}

const MAX_WORD_TOKENS = 400

/**
 * The parts of a paired removed/added line that differ. Returns null when
 * the two lines share no word at all (the whole line is the change, and
 * highlighting every token would add nothing) or are too long to align.
 */
export function wordDiff(a: string, b: string): { a: Segment[]; b: Segment[] } | null {
  const ta = tokenize(a)
  const tb = tokenize(b)
  if (ta.length > MAX_WORD_TOKENS || tb.length > MAX_WORD_TOKENS) return null
  const pairs = lcsPairs(ta, tb, (x, y) => x === y)
  const shared = pairs.some(([i]) => /[A-Za-z0-9_]/.test(ta[i]))
  if (!shared) return null
  const ka = new Set(pairs.map(([i]) => i))
  const kb = new Set(pairs.map(([, j]) => j))
  return {
    a: merge(ta.map((t, i) => ({ text: t, changed: !ka.has(i) }))),
    b: merge(tb.map((t, j) => ({ text: t, changed: !kb.has(j) }))),
  }
}

// ---------------------------------------------------------------- items

/** The fold (if any) hiding line `line` of `side`, for the page's jump. */
export function foldContaining(items: readonly Item[], side: 'a' | 'b', line: number): number | null {
  for (const it of items) if (isFold(it) && it.rows.some((r) => r[side] === line)) return it.id
  return null
}

export function buildItems(ops: readonly Op[], layout: CompareLayout, fold: boolean, expanded: ReadonlySet<number>): Item[] {
  const rows = layout === 'split' ? splitRows(ops) : unifiedRows(ops)
  return fold ? foldRows(rows, 3, expanded) : rows
}

