import { useEffect, useRef, useState, type ReactNode } from 'react'
import { useSearchParams } from 'react-router-dom'
import { CAP_CLUSTER_INSPECT } from '../api/capabilities'
import { missingCapabilityMessage } from '../api/capabilityInfo'
import type { InspectResult } from '../api/client'
import { useMissingCapabilities } from '../auth/useCapabilities'
import { EmptyState } from '../components/EmptyState'
import { Freshness } from '../components/Freshness'
import { Reproducer } from '../components/Reproducer'
import { SkeletonLines } from '../components/Skeleton'
import { ComparePicker } from '../compare/ComparePicker'
import { readCompare, sameKind, sameObject, writeCompare, type CompareLayout, type CompareState } from '../compare/compareUrl'
import { DiffView } from '../compare/DiffView'
import { buildItems, foldContaining } from '../compare/lineDiff'
import { compareReads, type Comparison } from '../compare/compare'
import { INSTANCE_LABEL, sameWorkloadPods } from '../compare/instance'
import { capGroups, groupChanges, lineOfPath, pathText, summaryHeadline, type FieldChange, type StrippedField } from '../compare/normalize'
import { describeArgs, reproducerFor } from '../evidence/reproducer'
import { CapabilityNotice } from '../insight/InsightParts'
import type { ObjectRef } from '../insight/panelUrl'
import { objectHealth } from '../insight/summaryModel'
import type { DescribeResult } from '../insight/types'
import { errorText, useClusterFreshness, useInspect, type ClusterFreshness } from '../insight/useInspect'
import { useOpenObject } from '../insight/useOpenObject'
import { StatusBanner } from '../insight/views/ObjectSummary'

// Compare two objects of one kind (PROJECT.md AD4): a broken replica against
// a healthy one, staging against production. Each side is the agent's
// redacted describe_resource read — the same call and cache entry the object
// panel makes — with bookkeeping fields stripped, diffed line by line, and
// summarised field by field. Reached from the object panel's "Compare…" and
// the command palette; the whole state is in the URL (compare/compareUrl.ts).

const NARROW_QUERY = '(max-width: 720px)'

/** Below ~720px two code columns are unreadable; the diff falls back to
 *  unified there whatever the URL asks for. */
function useNarrow(): boolean {
  const supported = typeof window !== 'undefined' && typeof window.matchMedia === 'function'
  const [narrow, setNarrow] = useState(() => supported && window.matchMedia(NARROW_QUERY).matches)
  useEffect(() => {
    if (!supported) return
    const mq = window.matchMedia(NARROW_QUERY)
    const on = () => setNarrow(mq.matches)
    mq.addEventListener?.('change', on)
    return () => mq.removeEventListener?.('change', on)
  }, [supported])
  return narrow
}

type DescribeQuery = {
  data?: InspectResult<DescribeResult>
  isLoading: boolean
  isError: boolean
  error: unknown
}

const STRIPPED_WORDS: Record<StrippedField, string> = {
  managedFields: 'managedFields',
  resourceVersion: 'resourceVersion',
  uid: 'uid',
  generation: 'generation',
  creationTimestamp: 'creationTimestamp',
  selfLink: 'selfLink',
  'last-applied-configuration': 'the last-applied annotation',
  'ownerReferences uid': 'owner reference uids',
  status: 'status',
  metadata: 'metadata',
  'relative times': 'ARGUS’s “seconds since” helper fields',
}

const CHANGE_WORD: Record<FieldChange['kind'], string> = {
  changed: 'differs',
  onlyA: 'only in A',
  onlyB: 'only in B',
}

function kindText(r: ObjectRef): string {
  return r.apiGroup ? `${r.kind} (${r.apiGroup})` : r.kind
}

function refLabel(r: ObjectRef): string {
  return r.namespace ? `${r.namespace}/${r.name}` : r.name
}

// ---------------------------------------------------------------- one side

function SideCard({
  side,
  target,
  query,
  cluster,
  canInspect,
  inspectReason,
  onChoose,
  onOpen,
}: {
  side: 'a' | 'b'
  target: ObjectRef | null
  query: DescribeQuery
  cluster: ClusterFreshness
  canInspect: boolean
  inspectReason?: string
  onChoose: () => void
  onOpen: (r: ObjectRef) => void
}) {
  const tag = side.toUpperCase()
  const obj = query.data?.result?.object
  const health = objectHealth(obj)
  return (
    <section className="card card-compact compare-side" aria-label={`Object ${tag}`}>
      <div className="card-head">
        <span className="compare-side-tag" aria-hidden="true">
          {tag}
        </span>
        <h2>{target ? target.kind : 'Not chosen'}</h2>
        {target && <span className="card-head-meta">{cluster.name}</span>}
      </div>
      {target ? (
        <p className="compare-side-name insight-mono">{refLabel(target)}</p>
      ) : (
        <p className="compare-side-name text-muted">Choose the object to put on side {tag}.</p>
      )}
      {target &&
        (!canInspect ? null : query.isLoading ? (
          <div aria-busy="true" aria-label={`Reading ${tag}`}>
            <SkeletonLines count={2} />
          </div>
        ) : query.isError ? (
          <p className="form-error" role="alert">
            {errorText(query.error, `The agent could not describe ${tag}.`)}
          </p>
        ) : query.data && !obj ? (
          <p className="insight-note">The agent returned no object — it may have been deleted.</p>
        ) : health ? (
          <StatusBanner health={health} />
        ) : null)}
      <div className="compare-side-foot">
        {target && query.data && <Freshness at={query.data.receivedAt} stale={cluster.stale} staleReason={cluster.staleReason} />}
        <span className="compare-side-actions">
          {target && (
            <button type="button" className="link-button" onClick={() => onOpen(target)}>
              Open in panel
            </button>
          )}
          <button type="button" className="secondary" onClick={onChoose} disabled={!canInspect} title={canInspect ? undefined : inspectReason}>
            {target ? 'Change…' : 'Choose…'}
          </button>
        </span>
      </div>
    </section>
  )
}

// ---------------------------------------------------------------- result

const CHANGE_CAP = 12

function CompareResult({
  cmp,
  layout,
  fold,
  labelA,
  labelB,
}: {
  cmp: Comparison
  layout: CompareLayout
  fold: boolean
  labelA: string
  labelB: string
}) {
  const [expanded, setExpanded] = useState<Set<number>>(() => new Set())
  const [target, setTarget] = useState<{ side: 'a' | 'b'; line: number } | null>(null)
  const [allChanges, setAllChanges] = useState(false)
  const diffRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!target) return
    const el = diffRef.current?.querySelector<HTMLElement>(`[data-${target.side}="${target.line}"]`)
    el?.scrollIntoView?.({ block: 'center' })
    el?.focus({ preventScroll: true })
  }, [target, expanded])

  const jump = (c: FieldChange) => {
    const side = c.kind === 'onlyB' ? 'b' : 'a'
    const line = lineOfPath(side === 'a' ? cmp.yamlA : cmp.yamlB, c.path)
    if (line === null) return
    const f = foldContaining(buildItems(cmp.ops, layout, fold, expanded), side, line)
    if (f !== null) setExpanded((prev) => new Set(prev).add(f))
    setTarget({ side, line })
  }

  const hidden = cmp.stripped.map((s) => STRIPPED_WORDS[s])
  // Grouped spec → identity → status, and capped across the groups in that
  // order, so the cap drops identity noise before it drops a spec change.
  const shownGroups = capGroups(groupChanges(cmp.changes), allChanges ? Infinity : CHANGE_CAP)
  const instanceTotal = cmp.instanceHidden.reduce((n, h) => n + h.count, 0)
  const instanceNote =
    instanceTotal > 0
      ? `Per-instance differences hidden — ${instanceTotal} field${instanceTotal === 1 ? '' : 's'}: ${cmp.instanceHidden
          .map((h) => `${INSTANCE_LABEL[h.category]} (${h.count})`)
          .join(', ')}. Untick “Ignore per-instance differences” to see them.`
      : null
  const revision = cmp.revision

  if (cmp.changes.length === 0 && cmp.added === 0 && cmp.removed === 0 && !revision) {
    return (
      <EmptyState variant="insights">
        No differences between A and B
        {cmp.stripped.includes('status') ? ' (status not compared)' : ''}.
        {cmp.redactedEqual > 0 &&
          ` ${cmp.redactedEqual} redacted value${cmp.redactedEqual === 1 ? ' matches' : 's match'} only as a redaction marker — ARGUS never received ${cmp.redactedEqual === 1 ? 'it' : 'them'}, so the real value${cmp.redactedEqual === 1 ? '' : 's'} may still differ.`}
        {hidden.length > 0 && ` Hidden on both sides: ${hidden.join(', ')}.`}
        {instanceNote && ` ${instanceNote}`}
      </EmptyState>
    )
  }

  return (
    <>
      <section className="card card-compact compare-summary" aria-label="What differs">
        <div className="card-head">
          <h2>What differs</h2>
          <span className="card-head-meta">
            −{cmp.removed} +{cmp.added} lines
          </span>
        </div>
        {revision && (
          <p className="insight-lead">
            Different revisions of Deployment <span className="insight-mono">{revision.deployment}</span> (ReplicaSet{' '}
            <span className="insight-mono">{revision.replicaSetA}</span> vs <span className="insight-mono">{revision.replicaSetB}</span>)
          </p>
        )}
        <p className="insight-lead">{revision && cmp.changes.length === 0 ? 'No other fields differ' : summaryHeadline(cmp.changes)}</p>
        {shownGroups.map((g) => (
          <div key={g.key} className="compare-change-group">
            <h3 className="compare-change-group-title">
              {g.title} <span className="text-muted">· {g.changes.length}</span>
            </h3>
            <ul className="compare-change-list">
              {g.shown.map((c, i) => (
                <li key={i}>
                  <button type="button" className="link-button insight-inline-link" onClick={() => jump(c)} title={`Show ${pathText(c.path)} in the diff`}>
                    {pathText(c.path)}
                  </button>
                  <span className={`compare-change-kind compare-change-${c.kind}`}>{CHANGE_WORD[c.kind]}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
        {cmp.changes.length > CHANGE_CAP && (
          <button type="button" className="link-button" onClick={() => setAllChanges((v) => !v)}>
            {allChanges ? 'Show fewer' : `Show all ${cmp.changes.length}`}
          </button>
        )}
        {cmp.redactedEqual > 0 && (
          <p className="insight-note">
            <span className="redacted-marker">‹redacted›</span> {cmp.redactedEqual} value{cmp.redactedEqual === 1 ? ' is' : 's are'} redacted on both sides and
            {cmp.redactedEqual === 1 ? ' is' : ' are'} not counted as differing: the cluster agent removed {cmp.redactedEqual === 1 ? 'it' : 'them'} before
            anything left the cluster, so ARGUS can only compare the markers — the real values may differ.
          </p>
        )}
        {(hidden.length > 0 || instanceNote) && (
          <p className="field-hint">
            {hidden.length > 0 && `Hidden on both sides: ${hidden.join(', ')}.`}
            {hidden.length > 0 && instanceNote && ' '}
            {instanceNote}
          </p>
        )}
        {!cmp.aligned && (
          <p className="insight-note">These objects are too large to align line by line; the changed region is shown as removed, then added.</p>
        )}
      </section>
      <div ref={diffRef} className="compare-diff-wrap">
        <DiffView
          a={cmp.linesA}
          b={cmp.linesB}
          ops={cmp.ops}
          layout={layout}
          fold={fold}
          expanded={expanded}
          onExpand={(id) => setExpanded((prev) => new Set(prev).add(id))}
          target={target}
          labelA={labelA}
          labelB={labelB}
        />
      </div>
    </>
  )
}

// ---------------------------------------------------------------- page

export function ComparePage() {
  const [params, setParams] = useSearchParams()
  const state = readCompare(params)
  const update = (patch: Partial<CompareState>, replace = true) =>
    setParams((prev) => writeCompare({ ...readCompare(prev), ...patch }, prev), { replace })

  const cap = useMissingCapabilities([CAP_CLUSTER_INSPECT])
  const canInspect = cap.resolved && cap.missing.length === 0
  const inspectReason = cap.resolved && !canInspect ? missingCapabilityMessage(cap.missing) : undefined

  const { a, b } = state
  const qa = useInspect<DescribeResult>(a?.clusterId ?? '', 'describe_resource', a ? describeArgs(a) : {}, canInspect && !!a)
  const qb = useInspect<DescribeResult>(b?.clusterId ?? '', 'describe_resource', b ? describeArgs(b) : {}, canInspect && !!b)
  const clusterA = useClusterFreshness(a?.clusterId ?? '')
  const clusterB = useClusterFreshness(b?.clusterId ?? '')
  const open = useOpenObject()

  const narrow = useNarrow()
  const layout: CompareLayout = narrow ? 'unified' : state.layout
  const picking = state.pick

  const kindsDiffer = !!a && !!b && !sameKind(a, b)
  const objA = qa.data?.result?.object
  const objB = qb.data?.result?.object
  const includeStatus = state.includeStatus && !state.specOnly
  const specOnly = state.specOnly
  const dataA = qa.data
  const dataB = qb.data
  // Not memoised: the page re-renders only when a read or the URL changes,
  // and a few-hundred-line diff is well under a frame.
  // Per-instance differences are hidden by default only for two pods of one
  // workload (siblings always differ there); the URL can say otherwise.
  const ignoreInstance = state.ignoreInstance ?? (!!a && !!b && sameWorkloadPods(a, b, objA, objB))
  const cmp = kindsDiffer ? null : compareReads(dataA, dataB, { includeStatus, specOnly, ignoreInstance })

  const pickSide = (side: 'a' | 'b') => update({ pick: side }, true)
  const onPick = (r: ObjectRef) => update(picking === 'a' ? { a: r, pick: null } : { b: r, pick: null }, false)
  const swap = () => update({ a: b, b: a })

  const labelA = a ? `${refLabel(a)} · ${clusterA.name}` : 'A'
  const labelB = b ? `${refLabel(b)} · ${clusterB.name}` : 'B'
  const otherForPick = picking === 'a' ? b : a
  const otherObj = picking === 'a' ? objB : objA
  const otherCluster = picking === 'a' ? clusterB.name : clusterA.name

  let body: ReactNode
  if (!cap.resolved) {
    body = (
      <div aria-busy="true" aria-label="Checking permissions">
        <SkeletonLines count={6} />
      </div>
    )
  } else if (!canInspect) {
    body = <CapabilityNotice message={inspectReason ?? ''} />
  } else if (!a || !b) {
    body = (
      <EmptyState variant="insights">
        {!a && !b
          ? 'Choose two objects of one kind to compare — a broken replica against a healthy one, or staging against production. An object’s panel has a Compare… action that fills in A for you.'
          : `Choose ${a ? 'B' : 'A'} to compare against ${refLabel((a ?? b)!)}.`}
      </EmptyState>
    )
  } else if (kindsDiffer) {
    body = (
      <p className="banner banner-warning" role="alert">
        A is of kind {kindText(a)} and B is of kind {kindText(b)}. Compare only works on two objects of one kind — change one side.
      </p>
    )
  } else if (sameObject(a, b)) {
    body = <p className="insight-note">A and B are the same object. Change one side to compare it with something else.</p>
  } else if (qa.isLoading || qb.isLoading) {
    body = (
      <div aria-busy="true" aria-label="Reading both objects">
        <SkeletonLines count={14} />
      </div>
    )
  } else if (qa.isError || qb.isError || (qa.data && !objA) || (qb.data && !objB)) {
    const which = [qa.isError || (qa.data && !objA) ? 'A' : null, qb.isError || (qb.data && !objB) ? 'B' : null].filter(Boolean).join(' and ')
    body = <p className="insight-note">Nothing to compare until {which} can be read — see above.</p>
  } else if (cmp) {
    body = (
      <CompareResult
        key={`${state.specOnly}/${includeStatus}/${ignoreInstance}/${layout}/${state.showAll}`}
        cmp={cmp}
        layout={layout}
        fold={!state.showAll}
        labelA={labelA}
        labelB={labelB}
      />
    )
  }

  const showControls = !!cmp && !kindsDiffer
  const cmdA = a ? reproducerFor('describe_resource', describeArgs(a)) : null
  const cmdB = b ? reproducerFor('describe_resource', describeArgs(b)) : null

  return (
    <div className="page compare-page">
      <header className="page-header">
        <div>
          <h1>Compare objects</h1>
          <p className="text-muted">Two objects of one kind, each read live from its cluster&apos;s agent, with bookkeeping fields hidden.</p>
        </div>
      </header>

      <div className="compare-sides">
        <SideCard
          side="a"
          target={a}
          query={qa}
          cluster={clusterA}
          canInspect={canInspect}
          inspectReason={inspectReason}
          onChoose={() => pickSide('a')}
          onOpen={open}
        />
        <button type="button" className="secondary compare-swap" onClick={swap} disabled={!a && !b} aria-label="Swap A and B">
          <span aria-hidden="true">⇄</span> Swap
        </button>
        <SideCard
          side="b"
          target={b}
          query={qb}
          cluster={clusterB}
          canInspect={canInspect}
          inspectReason={inspectReason}
          onChoose={() => pickSide('b')}
          onOpen={open}
        />
      </div>

      {showControls && (
        <div className="insight-controls compare-controls">
          <span className="insight-range" role="group" aria-label="Layout">
            <button
              type="button"
              aria-pressed={layout === 'split'}
              disabled={narrow}
              title={narrow ? 'Too narrow for two columns — widen the window to compare side by side.' : undefined}
              onClick={() => update({ layout: 'split' })}
            >
              Side by side
            </button>
            <button type="button" aria-pressed={layout === 'unified'} onClick={() => update({ layout: 'unified' })}>
              Unified
            </button>
          </span>
          <label className="checkbox-row">
            <input type="checkbox" checked={!state.showAll} onChange={(e) => update({ showAll: !e.target.checked })} /> Only changed lines
          </label>
          <label className="checkbox-row">
            <input type="checkbox" checked={state.specOnly} onChange={(e) => update({ specOnly: e.target.checked })} /> Spec only
          </label>
          <label className="checkbox-row" title={state.specOnly ? 'Spec only already hides status.' : undefined}>
            <input
              type="checkbox"
              checked={includeStatus}
              disabled={state.specOnly}
              onChange={(e) => update({ includeStatus: e.target.checked })}
            />{' '}
            Include status
          </label>
          <label className="checkbox-row">
            <input type="checkbox" checked={ignoreInstance} onChange={(e) => update({ ignoreInstance: e.target.checked })} /> Ignore per-instance differences
          </label>
          {narrow && <span className="field-hint">Unified — the window is too narrow for side by side.</span>}
        </div>
      )}

      <div className="insight-stack compare-body">{body}</div>

      {(cmdA || cmdB) && canInspect && (
        <div className="insight-footer compare-footer">
          {a && cmdA && <Reproducer command={cmdA} clusterName={clusterA.name} label="Read A yourself" />}
          {b && cmdB && <Reproducer command={cmdB} clusterName={clusterB.name} label="Read B yourself" />}
        </div>
      )}

      {picking && canInspect && (
        <ComparePicker
          side={picking}
          current={picking === 'a' ? a : b}
          other={otherForPick}
          otherObject={otherObj}
          otherClusterName={otherCluster}
          onPick={onPick}
          onClose={() => update({ pick: null })}
        />
      )}
    </div>
  )
}
