import { useCallback, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'

// A field in a URL-state schema: how to read it from the query string and
// what it is when absent. Defaults are omitted from the URL, so a shared
// link carries only what differs (docs/CLUSTER_INSIGHT_SPECS.md CI-U5).
//
// parse/serialize are declared as methods, not function-typed properties, on
// purpose: method parameters are bivariant, which is what lets a concrete
// UrlField<'a' | 'b'> sit in a Record<string, UrlField<unknown>> schema. As
// properties, strictFunctionTypes rejected every typed field, so no schema
// with a non-unknown field type could be passed to useUrlState at all.
export interface UrlField<T> {
  parse(raw: string): T | undefined
  serialize(v: T): string
  default: T
}

export const urlString = (def = ''): UrlField<string> => ({
  parse: (r) => r,
  serialize: (v) => v,
  default: def,
})

export const urlEnum = <T extends string>(allowed: readonly T[], def: T): UrlField<T> => ({
  // An unknown value is dropped, not an error: an old or hand-edited link
  // still opens, at the default.
  parse: (r) => (allowed as readonly string[]).includes(r) ? (r as T) : undefined,
  serialize: (v) => v,
  default: def,
})

export const urlInt = (def: number, min = 0): UrlField<number> => ({
  parse: (r) => {
    const n = Number.parseInt(r, 10)
    return Number.isFinite(n) && n >= min ? n : undefined
  },
  serialize: (v) => String(v),
  default: def,
})

export const urlBool = (def = false): UrlField<boolean> => ({
  parse: (r) => (r === '1' || r === 'true' ? true : r === '0' || r === 'false' ? false : undefined),
  serialize: (v) => (v ? '1' : '0'),
  default: def,
})

type Schema = Record<string, UrlField<unknown>>
type Values<S extends Schema> = { [K in keyof S]: S[K] extends UrlField<infer T> ? T : never }

// useUrlState keeps a page's view state — filters, sort, page, open panel,
// active tab — in the query string, typed by a schema. `set` merges a
// partial update; `push` controls history (discrete changes push, typing
// replaces). Keys outside the schema are preserved untouched.
// react-router's functional setSearchParams computes from the params of the
// RENDER that created it, not from the latest write, so two updates in one
// event handler — two `set` calls, or two hooks on one page each writing its
// own key — used to keep only the last one. Writes made in the same tick are
// composed here instead: each starts from the previous one's result while the
// location it was based on is still current, and the record is dropped once
// the handler's synchronous work is over, so it can never resurrect an old
// write after a later navigation.
let pendingWrite: { base: string; value: URLSearchParams } | null = null

/** Applies `edit` to the current query string, composing with any other
 *  write made earlier in the same event handler. */
export function useSearchParamsWriter() {
  const [params, setParams] = useSearchParams()
  const write = useCallback(
    (edit: (next: URLSearchParams) => void, opts: { push?: boolean } = {}) => {
      const base = params.toString()
      const start = pendingWrite && pendingWrite.base === base ? pendingWrite.value : params
      const next = new URLSearchParams(start)
      edit(next)
      const fresh = pendingWrite === null
      pendingWrite = { base, value: next }
      if (fresh) queueMicrotask(() => (pendingWrite = null))
      setParams(next, { replace: !opts.push })
    },
    [params, setParams],
  )
  return [params, write] as const
}

export function useUrlState<S extends Schema>(schema: S) {
  const [params, write] = useSearchParamsWriter()

  const values = useMemo(() => {
    const out: Record<string, unknown> = {}
    for (const [k, f] of Object.entries(schema)) {
      const raw = params.get(k)
      const parsed = raw === null ? undefined : f.parse(raw)
      out[k] = parsed === undefined ? f.default : parsed
    }
    return out as Values<S>
  }, [params, schema])

  const set = useCallback(
    (update: Partial<Values<S>>, opts: { push?: boolean } = {}) => {
      write((next) => {
        for (const [k, v] of Object.entries(update)) {
          const f = schema[k]
          if (!f) continue
          const s = v === undefined ? undefined : f.serialize(v)
          if (s === undefined || s === f.serialize(f.default)) next.delete(k)
          else next.set(k, s)
        }
      }, opts)
    },
    [schema, write],
  )

  return [values, set] as const
}

/**
 * One URL-backed value with a useState-shaped API, for migrating a page's
 * existing `useState` filters to the URL (CI-U5) without rewriting every call
 * site: the setter takes a value or an updater, unknown values read as the
 * default, and the default is omitted from the URL. Replaces history (a
 * filter change is not a page visit).
 */
export function useUrlParam<T extends string>(key: string, def: T, allowed?: readonly T[]) {
  const [params, write] = useSearchParamsWriter()
  const raw = params.get(key)
  const value = (raw !== null && (!allowed || (allowed as readonly string[]).includes(raw)) ? raw : def) as T
  const set = useCallback(
    (next: T | ((current: T) => T)) => {
      write((p) => {
        const currentRaw = p.get(key)
        const current = (currentRaw !== null && (!allowed || (allowed as readonly string[]).includes(currentRaw)) ? currentRaw : def) as T
        const v = typeof next === 'function' ? (next as (c: T) => T)(current) : next
        if (v === def) p.delete(key)
        else p.set(key, v)
      })
    },
    // `allowed` is expected to be a module constant, so this stays stable.
    [write, key, def, allowed],
  )
  return [value, set] as const
}
