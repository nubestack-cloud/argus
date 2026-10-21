import { isMap, isScalar, isSeq, parseDocument, stringify, type Node as YamlNode } from 'yaml'
import { REDACTED } from '../insight/model'
import type { KubeObject } from '../insight/types'

// What the Compare page diffs: the agent's redacted describe_resource object
// with the fields that differ between ANY two objects (bookkeeping the API
// server or ARGUS adds) taken out, so what is left to differ is what someone
// configured or what the object is doing. Pure functions, so the rules are
// pinned in tests rather than in the page.

export interface CompareOptions {
  /** Keep `status` (hidden by default: two replicas always differ there). */
  includeStatus: boolean
  /** Drop apiVersion, kind and metadata — what is left is the spec (or a
   *  ConfigMap's data), the part a person wrote. */
  specOnly: boolean
}

/** Fields removed from metadata, in the words the page lists them under. */
const METADATA_NOISE = ['managedFields', 'resourceVersion', 'uid', 'generation', 'creationTimestamp', 'selfLink'] as const
const LAST_APPLIED = 'kubectl.kubernetes.io/last-applied-configuration'

/** The noise that was actually present and removed, for the page's note. */
export type StrippedField =
  | (typeof METADATA_NOISE)[number]
  | 'last-applied-configuration'
  | 'ownerReferences uid'
  | 'status'
  | 'metadata'
  | 'relative times'

type Json = null | boolean | number | string | Json[] | { [k: string]: Json }

function isObj(v: unknown): v is Record<string, Json> {
  return !!v && typeof v === 'object' && !Array.isArray(v)
}

// The agent adds a "<field>SecondsSince" (or, for a future timestamp,
// "<field>SecondsUntil") sibling beside every timestamp it returns
// (internal/agent/relative_time.go) so a model need not do date arithmetic.
// It is not part of the object and it changes every second, so it is always
// removed — whatever the options. Only a key whose base field sits beside it
// is a helper; a real field that happens to end the same way is kept.
const RELATIVE_SUFFIXES = ['SecondsSince', 'SecondsUntil'] as const

function isRelativeHelper(k: string, siblings: Record<string, unknown>): boolean {
  return RELATIVE_SUFFIXES.some((sfx) => k.endsWith(sfx) && k.length > sfx.length && k.slice(0, -sfx.length) in siblings)
}

function dropRelativeTimes(v: Json, hit: { found: boolean }): Json {
  if (Array.isArray(v)) return v.map((x) => dropRelativeTimes(x, hit))
  if (!isObj(v)) return v
  const out: Record<string, Json> = {}
  for (const [k, x] of Object.entries(v)) {
    if (isRelativeHelper(k, v)) {
      hit.found = true
      continue
    }
    out[k] = dropRelativeTimes(x, hit)
  }
  return out
}

/** A copy of an agent-described object without the agent's relative-time
 *  helper fields — the object as the API server holds it, for showing and
 *  copying as YAML. Never mutates its input. */
export function withoutRelativeTimes<T>(obj: T): T {
  return dropRelativeTimes(obj as unknown as Json, { found: false }) as unknown as T
}

/**
 * The object with comparison noise removed, and the list of what was
 * removed. Never mutates its input (the same object is the panel's cache).
 */
export function stripNoise(obj: KubeObject, opts: CompareOptions): { value: Record<string, Json>; stripped: StrippedField[] } {
  const stripped = new Set<StrippedField>()
  const rel = { found: false }
  const o = dropRelativeTimes(JSON.parse(JSON.stringify(obj)) as Json, rel) as Record<string, Json>
  if (rel.found) stripped.add('relative times')

  if (isObj(o.metadata)) {
    const md = o.metadata
    for (const f of METADATA_NOISE) {
      if (f in md) {
        delete md[f]
        stripped.add(f)
      }
    }
    if (isObj(md.annotations) && LAST_APPLIED in md.annotations) {
      delete md.annotations[LAST_APPLIED]
      stripped.add('last-applied-configuration')
      if (Object.keys(md.annotations).length === 0) delete md.annotations
    }
    if (Array.isArray(md.ownerReferences)) {
      for (const ref of md.ownerReferences) {
        if (isObj(ref) && 'uid' in ref) {
          delete ref.uid
          stripped.add('ownerReferences uid')
        }
      }
    }
  }
  if (!opts.includeStatus && 'status' in o) {
    delete o.status
    stripped.add('status')
  }
  if (opts.specOnly) {
    if ('metadata' in o) stripped.add('metadata')
    delete o.apiVersion
    delete o.kind
    delete o.metadata
  }
  return { value: o, stripped: [...stripped] }
}

/** The YAML both columns show. Keys sorted so two objects line up even when
 *  their sources emitted fields in different orders. */
export function toYaml(v: unknown): string {
  return stringify(v, { lineWidth: 0, sortMapEntries: true }).replace(/\n$/, '')
}

// ---------------------------------------------------------------- field diff

/** One step of a field path: a map key, a list index, or a list item matched
 *  by its `name` (containers, env, volumes, ports). */
export type PathSeg = { key: string } | { index: number } | { name: string }

export type FieldChangeKind = 'changed' | 'onlyA' | 'onlyB'

export interface FieldChange {
  path: PathSeg[]
  kind: FieldChangeKind
}

export interface FieldDiff {
  changes: FieldChange[]
  /** Leaves equal on both sides only as redaction markers — the values
   *  underneath were never received and may differ. */
  redactedEqual: number
}

function namedItems(arr: Json[]): Map<string, Json> | null {
  if (arr.length === 0) return null
  const m = new Map<string, Json>()
  for (const x of arr) {
    if (!isObj(x) || typeof x.name !== 'string' || m.has(x.name)) return null
    m.set(x.name, x)
  }
  return m
}

function isScalarList(arr: Json[]): boolean {
  return arr.every((x) => x === null || typeof x !== 'object')
}

function same(a: Json, b: Json): boolean {
  return JSON.stringify(a) === JSON.stringify(b)
}

function countRedactedLeaves(v: Json): number {
  if (typeof v === 'string') return v.includes(REDACTED) ? 1 : 0
  if (Array.isArray(v)) return v.reduce<number>((n, x) => n + countRedactedLeaves(x), 0)
  if (isObj(v)) return Object.values(v).reduce<number>((n, x) => n + countRedactedLeaves(x), 0)
  return 0
}

/**
 * Field-level differences between two stripped objects. Lists of named items
 * are matched by name, so one inserted env var reports as one entry rather
 * than every later index; lists of scalars (args, command) report as one
 * changed field. A value the agent redacted compares as its marker text: two
 * markers are equal (and counted in `redactedEqual`), a marker against a
 * different string is a difference.
 */
export function diffFields(a: Json, b: Json): FieldDiff {
  const changes: FieldChange[] = []
  let redactedEqual = 0
  const walk = (x: Json | undefined, y: Json | undefined, path: PathSeg[]) => {
    if (x === undefined && y === undefined) return
    if (x === undefined) return void changes.push({ path, kind: 'onlyB' })
    if (y === undefined) return void changes.push({ path, kind: 'onlyA' })
    if (isObj(x) && isObj(y)) {
      const keys = [...new Set([...Object.keys(x), ...Object.keys(y)])].sort()
      for (const k of keys) walk(x[k], y[k], [...path, { key: k }])
      return
    }
    if (Array.isArray(x) && Array.isArray(y)) {
      if (same(x, y)) {
        redactedEqual += countRedactedLeaves(x)
        return
      }
      if (isScalarList(x) && isScalarList(y)) return void changes.push({ path, kind: 'changed' })
      const nx = namedItems(x)
      const ny = namedItems(y)
      // One named item a side under different names — the usual shape of
      // two workloads' single container ("api" vs "edge") — is the same slot
      // renamed: compare it by position, so the summary names the image or
      // limit that differs rather than "container only in A / only in B".
      if (nx && ny && nx.size === 1 && ny.size === 1 && !ny.has([...nx.keys()][0])) {
        walk(x[0], y[0], [...path, { index: 0 }])
        return
      }
      if (nx && ny) {
        const names = [...nx.keys(), ...[...ny.keys()].filter((n) => !nx.has(n))]
        for (const n of names) walk(nx.get(n), ny.get(n), [...path, { name: n }])
        return
      }
      for (let i = 0; i < Math.max(x.length, y.length); i++) walk(x[i], y[i], [...path, { index: i }])
      return
    }
    if (same(x, y)) {
      redactedEqual += countRedactedLeaves(x)
      return
    }
    changes.push({ path, kind: 'changed' })
  }
  walk(a, b, [])
  return { changes, redactedEqual }
}

/** "spec.template.spec.containers[app].env[TOKEN].value" */
export function pathText(path: readonly PathSeg[]): string {
  let s = ''
  for (const seg of path) {
    if ('key' in seg) s += (s ? '.' : '') + seg.key
    else if ('name' in seg) s += `[${seg.name}]`
    else s += `[${seg.index}]`
  }
  return s || '(whole object)'
}

/** The short word a change is summarised by: its last key, with a named list
 *  item reading as "env NODE_ENV". */
export function changeLabel(path: readonly PathSeg[]): string {
  for (let i = path.length - 1; i >= 0; i--) {
    const seg = path[i]
    if ('key' in seg) {
      const next = path[i + 1]
      return next && 'name' in next && i + 1 === path.length - 1 ? `${seg.key} ${next.name}` : seg.key
    }
  }
  return pathText(path)
}

/**
 * The change summary's headline: "7 fields differ: image, replicas, 2 env
 * entries, …". Labels repeat for the same key on different items, so they
 * are grouped by key with a count; at most `max` groups are named.
 */
export function summaryHeadline(changes: readonly FieldChange[], max = 6): string {
  if (changes.length === 0) return 'No fields differ'
  const groups = new Map<string, number>()
  for (const c of changes) {
    const key = changeLabel(c.path).split(' ')[0]
    groups.set(key, (groups.get(key) ?? 0) + 1)
  }
  const words = [...groups.entries()].map(([k, n]) => (n > 1 ? `${n} × ${k}` : k))
  const shown = words.slice(0, max).join(', ')
  const more = words.length > max ? ', …' : ''
  return `${changes.length} field${changes.length === 1 ? ' differs' : 's differ'}: ${shown}${more}`
}

export type ChangeGroupKey = 'spec' | 'identity' | 'status'

export interface ChangeGroup {
  key: ChangeGroupKey
  title: string
  changes: FieldChange[]
}

const GROUP_TITLE: Record<ChangeGroupKey, string> = {
  spec: 'Spec — what the objects are told to do',
  identity: 'Identity — names, labels, annotations and selectors',
  status: 'Status — what the cluster reports',
}

/** Which part of an object a changed field belongs to. Selectors and the
 *  pod template's labels are identity: they say which object is which, not
 *  how it runs. */
export function changeGroup(path: readonly PathSeg[]): ChangeGroupKey {
  const keys = path.filter((p): p is { key: string } => 'key' in p).map((p) => p.key)
  if (keys[0] === 'status') return 'status'
  if (keys[0] === 'metadata' || keys.includes('selector')) return 'identity'
  if (keys[0] === 'spec' && keys[1] === 'template' && keys[2] === 'metadata') return 'identity'
  return 'spec'
}

/**
 * The summary's changes in the order a "why is A broken and B not" reader
 * wants them (owner review 2026-10-11): spec differences first — they can
 * change behaviour — then identity, then status. Empty groups are left out;
 * order within a group is kept.
 */
export function groupChanges(changes: readonly FieldChange[]): ChangeGroup[] {
  const order: ChangeGroupKey[] = ['spec', 'identity', 'status']
  return order
    .map((key) => ({ key, title: GROUP_TITLE[key], changes: changes.filter((c) => changeGroup(c.path) === key) }))
    .filter((g) => g.changes.length > 0)
}

/** The first `cap` changes across the groups, in group order; a group left
 *  with none is dropped. `changes` keeps each group's full list for its count. */
export function capGroups(groups: readonly ChangeGroup[], cap: number): (ChangeGroup & { shown: FieldChange[] })[] {
  const out: (ChangeGroup & { shown: FieldChange[] })[] = []
  let left = cap
  for (const g of groups) {
    if (left <= 0) break
    const shown = g.changes.slice(0, left)
    left -= shown.length
    out.push({ ...g, shown })
  }
  return out
}

// ---------------------------------------------------------------- path → line

/**
 * Where a field path starts in YAML produced by toYaml, as a 0-based line,
 * so a change in the summary can scroll the diff to it. When the full path
 * is not present (a field only the other side has), the deepest ancestor
 * that is present is returned; null only for an empty document.
 */
export function lineOfPath(yamlText: string, path: readonly PathSeg[]): number | null {
  const doc = parseDocument(yamlText)
  const starts = [0]
  for (let i = 0; i < yamlText.length; i++) if (yamlText[i] === '\n') starts.push(i + 1)
  const lineAt = (offset: number) => {
    let lo = 0
    let hi = starts.length - 1
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1
      if (starts[mid] <= offset) lo = mid
      else hi = mid - 1
    }
    return lo
  }
  let node = doc.contents as YamlNode | null
  if (!node) return null
  let line: number | null = node.range ? lineAt(node.range[0]) : 0
  for (const seg of path) {
    if ('key' in seg && isMap(node)) {
      const items = node.items as { key: unknown; value: unknown }[]
      const pair = items.find((p) => isScalar(p.key) && String(p.key.value) === seg.key)
      if (!pair) break
      const k = pair.key as YamlNode
      if (k.range) line = lineAt(k.range[0])
      node = (pair.value as YamlNode | null) ?? null
    } else if ('index' in seg && isSeq(node)) {
      const item = node.items[seg.index] as YamlNode | undefined
      if (!item) break
      if (item.range) line = lineAt(item.range[0])
      node = item
    } else if ('name' in seg && isSeq(node)) {
      const item = node.items.find((it) => isMap(it) && it.items.some((p) => isScalar(p.key) && p.key.value === 'name' && isScalar(p.value) && p.value.value === seg.name)) as
        | YamlNode
        | undefined
      if (!item) break
      if (item.range) line = lineAt(item.range[0])
      node = item
    } else break
    if (!node) break
  }
  return line
}
