import { decodeObjectPanel, encodeObjectPanel, PANEL_PARAM, type ObjectRef } from '../insight/panelUrl'

// The Compare page's whole state lives in its URL (/compare?a=…&b=…), each
// side in the object panel's own encoding (obj:<cluster>:<group>/<kind>:
// <namespace>/<name>), so a comparison can span clusters and a link
// reproduces it — the two objects and how they are being viewed.

export type CompareLayout = 'split' | 'unified'

export interface CompareState {
  a: ObjectRef | null
  b: ObjectRef | null
  layout: CompareLayout
  /** Show unchanged lines instead of folding them (diff-only is the default). */
  showAll: boolean
  specOnly: boolean
  includeStatus: boolean
  /** Hide per-instance differences (compare/instance.ts). null = the
   *  default: on for two pods of one workload, off otherwise. */
  ignoreInstance: boolean | null
  /** Which side's picker opens on arrival (the object panel's "Compare…"). */
  pick: 'a' | 'b' | null
}

export const COMPARE_PATH = '/compare'

export function readCompare(params: URLSearchParams): CompareState {
  const pick = params.get('pick')
  return {
    a: decodeObjectPanel(params.get('a')),
    b: decodeObjectPanel(params.get('b')),
    layout: params.get('view') === 'unified' ? 'unified' : 'split',
    showAll: params.get('all') === '1',
    specOnly: params.get('spec') === '1',
    includeStatus: params.get('status') === '1',
    ignoreInstance: params.get('inst') === '1' ? true : params.get('inst') === '0' ? false : null,
    pick: pick === 'a' || pick === 'b' ? pick : null,
  }
}

/** Search params for a state; defaults are left out so links stay short.
 *  Anything else already in `base` (an open object panel) is kept. */
export function writeCompare(s: CompareState, base?: URLSearchParams): URLSearchParams {
  const p = new URLSearchParams(base)
  const set = (k: string, v: string | null) => (v === null ? p.delete(k) : p.set(k, v))
  set('a', s.a ? encodeObjectPanel(s.a) : null)
  set('b', s.b ? encodeObjectPanel(s.b) : null)
  set('view', s.layout === 'unified' ? 'unified' : null)
  set('all', s.showAll ? '1' : null)
  set('spec', s.specOnly ? '1' : null)
  set('status', s.includeStatus ? '1' : null)
  set('inst', s.ignoreInstance === null ? null : s.ignoreInstance ? '1' : '0')
  set('pick', s.pick)
  return p
}

/** The link the object panel's "Compare…" and the palette open: A fixed,
 *  B's picker open. */
export function compareHref(a: ObjectRef | null, b: ObjectRef | null = null): string {
  const s: CompareState = { a, b, layout: 'split', showAll: false, specOnly: false, includeStatus: false, ignoreInstance: null, pick: a && !b ? 'b' : null }
  const q = writeCompare(s).toString()
  return q ? `${COMPARE_PATH}?${q}` : COMPARE_PATH
}

/** The object open in the inspector on the current page, if any — the
 *  palette's "Compare objects" starts from it. */
export function panelObject(search: string): ObjectRef | null {
  return decodeObjectPanel(new URLSearchParams(search).get(PANEL_PARAM))
}

/** Same kind means same API group and kind; a Deployment is never compared
 *  with a StatefulSet, and apps/Deployment never with another group's. */
export function sameKind(a: ObjectRef, b: ObjectRef): boolean {
  return a.kind === b.kind && (a.apiGroup ?? '') === (b.apiGroup ?? '')
}

export function sameObject(a: ObjectRef, b: ObjectRef): boolean {
  return encodeObjectPanel(a) === encodeObjectPanel(b)
}
