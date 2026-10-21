import { Fragment, useMemo, type ReactNode } from 'react'
import { splitRedacted } from '../insight/model'
import type { CompareLayout } from './compareUrl'
import { buildItems, isFold, wordDiff, type Op, type Row, type Segment } from './lineDiff'

// The two YAML documents as a diff: side by side (A left, B right) or
// unified. Every changed line carries a visible − or + marker AND a tint,
// plus a screen-reader word ("removed", "added") — colour is never the only
// carrier. The words that changed inside a paired line are underlined as
// well as tinted. Text is cluster-derived and untrusted: plain
// interpolation only.

const REDACTED_TITLE = 'Redacted by the cluster agent before it left the cluster. ARGUS never received this value.'

function Text({ text, segments }: { text: string; segments?: Segment[] | null }) {
  const parts = segments ?? [{ text, changed: false }]
  return (
    <>
      {parts.map((seg, i) => {
        const inner = splitRedacted(seg.text).map((r, j) =>
          r.redacted ? (
            <span key={j} className="redacted-marker" title={REDACTED_TITLE}>
              ‹redacted›
            </span>
          ) : (
            <Fragment key={j}>{r.text}</Fragment>
          ),
        )
        return seg.changed ? (
          <span key={i} className="compare-word">
            {inner}
          </span>
        ) : (
          <Fragment key={i}>{inner}</Fragment>
        )
      })}
    </>
  )
}

const MARK: Record<'del' | 'add', { glyph: string; word: string }> = {
  del: { glyph: '−', word: 'removed' },
  add: { glyph: '+', word: 'added' },
}

function Marker({ kind }: { kind: 'del' | 'add' | null }) {
  if (!kind) return <span className="compare-marker" aria-hidden="true" />
  return (
    <span className="compare-marker">
      <span aria-hidden="true">{MARK[kind].glyph}</span>
      <span className="visually-hidden">{MARK[kind].word}</span>
    </span>
  )
}

function LineNo({ n }: { n: number | undefined }) {
  return (
    <span className="compare-lineno" aria-hidden="true">
      {n === undefined ? '' : n + 1}
    </span>
  )
}

export interface DiffViewProps {
  a: readonly string[]
  b: readonly string[]
  ops: readonly Op[]
  layout: CompareLayout
  /** Fold unchanged runs (diff-only). */
  fold: boolean
  expanded: ReadonlySet<number>
  onExpand: (foldId: number) => void
  /** The row a change-summary click targets, highlighted until the next. */
  target: { side: 'a' | 'b'; line: number } | null
  labelA: string
  labelB: string
}

export function DiffView({ a, b, ops, layout, fold, expanded, onExpand, target, labelA, labelB }: DiffViewProps) {
  const items = useMemo(() => buildItems(ops, layout, fold, expanded), [ops, layout, fold, expanded])

  const isTarget = (r: Row) => !!target && r[target.side] === target.line

  const words = (r: Row): { a: Segment[] | null; b: Segment[] | null } => {
    const ai = r.a ?? r.pairA
    const bi = r.b ?? r.pairB
    if (ai === undefined || bi === undefined || r.kind === 'equal') return { a: null, b: null }
    const w = wordDiff(a[ai], b[bi])
    return { a: w?.a ?? null, b: w?.b ?? null }
  }

  const rowProps = (r: Row) => ({
    className: `compare-row compare-row-${r.kind}${isTarget(r) ? ' compare-row-target' : ''}`,
    'data-a': r.a,
    'data-b': r.b,
    tabIndex: -1,
    role: 'row',
  })

  const renderRow = (r: Row, key: number): ReactNode => {
    const w = words(r)
    if (layout === 'split') {
      const leftKind = r.kind === 'del' || r.kind === 'change' ? 'del' : null
      const rightKind = r.kind === 'add' || r.kind === 'change' ? 'add' : null
      return (
        <div key={key} {...rowProps(r)}>
          <div role="cell" className={`compare-cell${leftKind ? ' compare-cell-del' : r.a === undefined ? ' compare-cell-empty' : ''}`}>
            <LineNo n={r.a} />
            <Marker kind={leftKind} />
            <span className="compare-code">{r.a !== undefined && <Text text={a[r.a]} segments={w.a} />}</span>
          </div>
          <div role="cell" className={`compare-cell${rightKind ? ' compare-cell-add' : r.b === undefined ? ' compare-cell-empty' : ''}`}>
            <LineNo n={r.b} />
            <Marker kind={rightKind} />
            <span className="compare-code">{r.b !== undefined && <Text text={b[r.b]} segments={w.b} />}</span>
          </div>
        </div>
      )
    }
    const kind = r.kind === 'del' ? 'del' : r.kind === 'add' ? 'add' : null
    const text = r.a !== undefined && r.kind !== 'add' ? a[r.a] : b[r.b!]
    return (
      <div key={key} {...rowProps(r)}>
        <div role="cell" className={`compare-cell${kind ? ` compare-cell-${kind}` : ''}`}>
          <LineNo n={r.kind === 'add' ? undefined : r.a} />
          <LineNo n={r.kind === 'del' ? undefined : r.b} />
          <Marker kind={kind} />
          <span className="compare-code">
            <Text text={text} segments={r.kind === 'del' ? w.a : r.kind === 'add' ? w.b : null} />
          </span>
        </div>
      </div>
    )
  }

  return (
    <div className={`compare-diff compare-diff-${layout}`} role="table" aria-label={`Differences between ${labelA} and ${labelB}`} tabIndex={0}>
      {layout === 'split' && (
        <div className="compare-row compare-row-head" role="row">
          <div role="columnheader" className="compare-col-head">
            <span className="compare-side-tag">A</span> {labelA}
          </div>
          <div role="columnheader" className="compare-col-head">
            <span className="compare-side-tag">B</span> {labelB}
          </div>
        </div>
      )}
      {items.map((it, i) =>
        isFold(it) ? (
          <div key={`f${it.id}`} className="compare-row compare-row-fold" role="row">
            <div role="cell" className="compare-cell">
              <button type="button" className="link-button compare-fold" onClick={() => onExpand(it.id)}>
                Show {it.rows.length} unchanged line{it.rows.length === 1 ? '' : 's'}
              </button>
            </div>
          </div>
        ) : (
          renderRow(it, i)
        ),
      )}
    </div>
  )
}
