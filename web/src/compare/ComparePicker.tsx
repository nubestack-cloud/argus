import { useEffect, useMemo, useRef, useState } from 'react'
import { useDebouncedValue } from '../hooks/useDebouncedValue'
import { useQuery } from '@tanstack/react-query'
import { searchObjects } from '../api/client'
import { useAuth } from '../auth/useAuth'
import { Dialog } from '../components/Dialog'
import { Quantity } from '../components/Quantity'
import { SkeletonLines } from '../components/Skeleton'
import { apiErrorText } from '../fleet/apiErrorText'
import type { ObjectRef } from '../insight/panelUrl'
import type { KubeObject } from '../insight/types'
import { useInspect } from '../insight/useInspect'
import {
  GROUP_LABEL,
  isHealthyStatus,
  podFamily,
  rankSearch,
  sameNameCandidates,
  sameNamespaceCandidates,
  searchQuery,
  siblingCandidates,
  type Candidate,
  type SearchHit,
} from './candidates'
import { sameObject } from './compareUrl'

// Choose one side of a comparison. Before anything is typed it offers the
// likely partner for the other side (candidates.ts); typed text searches
// every cluster the viewer may inspect for objects of the same kind. Both
// sources are the agents' object caches via existing read-only searches.

const GROUP_CAP = 12
const DEBOUNCE_MS = 300

interface ClusterSearch {
  hits?: Omit<SearchHit, 'clusterId' | 'clusterName'>[]
  truncated?: boolean
  incompleteKinds?: string[]
}

const CAPPED = 'The search stopped at its result cap, so more may exist — type a name to narrow it.'

function fleetPartial(d: { truncated?: boolean; clustersQueried: number; clustersAnswered: number } | undefined): string | undefined {
  if (!d) return undefined
  if (d.clustersAnswered < d.clustersQueried) return `${d.clustersQueried - d.clustersAnswered} of ${d.clustersQueried} clusters did not answer, so more may exist.`
  return d.truncated ? CAPPED : undefined
}

function CandidateList({
  label,
  partial,
  items,
  current,
  other,
  otherSide,
  onPick,
}: {
  label: string
  /** Why this list may be missing candidates (a capped search, a cluster
   *  that did not answer); its count then reads as a lower bound. */
  partial?: string
  items: Candidate[]
  current: ObjectRef | null
  other: ObjectRef | null
  otherSide: 'A' | 'B'
  onPick: (r: ObjectRef) => void
}) {
  const [all, setAll] = useState(false)
  const shown = all ? items : items.slice(0, GROUP_CAP)
  return (
    <section className="compare-pick-group" aria-label={label}>
      <h3 className="compare-pick-group-label">
        {label}{' '}
        <span className="text-muted">
          · <Quantity value={items.length} certainty={partial ? 'atLeast' : 'exact'} />
        </span>
      </h3>
      {partial && <p className="field-hint">{partial}</p>}
      <ul className="preview-list">
        {shown.map((c) => {
          const isOther = !!other && sameObject(other, c.ref)
          const isCurrent = !!current && sameObject(current, c.ref)
          const healthy = isHealthyStatus(c.status)
          return (
            <li key={`${c.ref.clusterId}/${c.ref.namespace}/${c.ref.name}`}>
              <button
                type="button"
                className="compare-pick-row preview-row preview-row-stacked"
                disabled={isOther}
                title={isOther ? `This is already ${otherSide}` : undefined}
                aria-current={isCurrent ? 'true' : undefined}
                onClick={() => onPick(c.ref)}
              >
                <span className="preview-dot" data-tone={c.status ? (healthy ? 'ok' : 'warn') : undefined} aria-hidden="true" />
                <span className="preview-name insight-mono">{c.ref.name}</span>
                <span className="preview-context">{[c.ref.namespace, c.clusterName ?? c.ref.clusterId].filter(Boolean).join(' · ')}</span>
                <span className="preview-status">{isOther ? `already ${otherSide}` : isCurrent ? 'current' : c.status || 'No status reported'}</span>
              </button>
            </li>
          )
        })}
      </ul>
      {items.length > GROUP_CAP && (
        <button type="button" className="link-button" onClick={() => setAll((v) => !v)}>
          {all ? 'Show fewer' : `Show all ${items.length}`}
        </button>
      )}
    </section>
  )
}

export function ComparePicker({
  side,
  current,
  other,
  otherObject,
  otherClusterName,
  onPick,
  onClose,
}: {
  side: 'a' | 'b'
  current: ObjectRef | null
  /** The other side — fixes the kind and anchors the suggestions. */
  other: ObjectRef | null
  otherObject: KubeObject | null | undefined
  otherClusterName: string
  onPick: (r: ObjectRef) => void
  onClose: () => void
}) {
  const { accessToken } = useAuth()
  const [text, setText] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)
  // Dialog focuses its close button in its own effect; this runs after it.
  useEffect(() => {
    inputRef.current?.focus()
  }, [])
  const debounced = useDebouncedValue(text.trim(), DEBOUNCE_MS)
  const typed = debounced.length >= 2
  const kind = other?.kind
  const isPod = kind === 'Pod' && !other?.apiGroup
  const family = isPod ? podFamily(otherObject) : null

  // Suggestions, read only while nothing is typed.
  const clusterId = other?.clusterId ?? ''
  const nsArgs = { query: searchQuery(kind, family?.prefix ?? ''), namespace: other?.namespace ?? '', limit: 50 }
  const nearby = useInspect<ClusterSearch>(clusterId, 'search_objects', nsArgs, !!other && !typed)
  const elsewhere = useQuery({
    queryKey: ['compare-same-name', kind, other?.name],
    queryFn: () => searchObjects(searchQuery(kind, other!.name), accessToken!),
    enabled: !!accessToken && !!other && !isPod && !typed,
    staleTime: 30_000,
    retry: false,
  })
  const search = useQuery({
    queryKey: ['compare-search', kind ?? '', debounced],
    queryFn: () => searchObjects(searchQuery(kind, debounced), accessToken!),
    enabled: !!accessToken && typed,
    staleTime: 30_000,
    retry: false,
  })

  const groups = useMemo(() => {
    if (!other) return []
    const local: SearchHit[] = (nearby.data?.result?.hits ?? []).map((h) => ({ ...h, clusterId: other.clusterId, clusterName: otherClusterName }))
    const r = nearby.data?.result
    const localPartial = r?.truncated || (r?.incompleteKinds?.length ?? 0) > 0 ? CAPPED : undefined
    if (isPod && family) return [{ label: `${GROUP_LABEL.siblings} of ${family.prefix}`, items: siblingCandidates(other, otherObject, local), partial: localPartial }]
    if (isPod) return [{ label: `${GROUP_LABEL.sameNamespace} (${other.namespace ?? ''})`, items: sameNamespaceCandidates(other, local, []), partial: localPartial }]
    const same = sameNameCandidates(other, elsewhere.data?.hits ?? [])
    const ns = sameNamespaceCandidates(other, local, same.map((c) => c.ref))
    return [
      { label: GROUP_LABEL.sameName, items: same, partial: fleetPartial(elsewhere.data) },
      { label: `${GROUP_LABEL.sameNamespace} (${other.namespace ?? 'cluster scope'})`, items: ns, partial: localPartial },
    ]
  }, [other, otherObject, otherClusterName, nearby.data, elsewhere.data, isPod, family])

  const matches = useMemo(() => rankSearch(other, search.data?.hits ?? []), [other, search.data])
  const sideName = side.toUpperCase() as 'A' | 'B'
  const otherSide = side === 'a' ? 'B' : 'A'
  const pending = text.trim() !== debounced || search.isFetching
  const suggestionsLoading = !typed && (nearby.isLoading || (!isPod && elsewhere.isLoading))

  return (
    <Dialog title={`Choose object ${sideName}`} onClose={onClose} className="compare-pick-dialog">
      <label className="compare-pick-field">
        <span>{kind ? `Search ${kind} objects on every cluster you can inspect` : 'Search objects on every cluster you can inspect'}</span>
        <input
          type="search"
          ref={inputRef}
          value={text}
          placeholder="Name, namespace (ns:apps), label (l:app=web) or image"
          onChange={(e) => setText(e.target.value)}
        />
      </label>
      {kind && (
        <p className="field-hint">
          Only {kind} objects are offered: {otherSide} is a {kind}, and a comparison needs two objects of one kind.
        </p>
      )}
      <div className="compare-pick-results" aria-live="polite">
        {typed ? (
          search.isLoading || pending ? (
            <div aria-busy="true" aria-label="Searching">
              <SkeletonLines count={4} />
            </div>
          ) : search.isError ? (
            <p className="form-error" role="alert">
              Search failed: {apiErrorText(search.error, 'no answer from the hub')}
            </p>
          ) : (
            <>
              {matches.length === 0 ? (
                <p className="empty-state">
                  No {kind ?? 'object'} matches “{debounced}”{kind ? ` — only ${kind} objects are searched` : ''}.
                  {fleetPartial(search.data) ? ` ${fleetPartial(search.data)}` : ''}
                </p>
              ) : (
                <CandidateList label={GROUP_LABEL.search} partial={fleetPartial(search.data)} items={matches} current={current} other={other} otherSide={otherSide} onPick={onPick} />
              )}
            </>
          )
        ) : !other ? (
          <p className="empty-state">Type at least two characters to search every cluster you can inspect.</p>
        ) : suggestionsLoading ? (
          <div aria-busy="true" aria-label="Loading suggestions">
            <SkeletonLines count={5} />
          </div>
        ) : nearby.isError && (isPod || elsewhere.isError) ? (
          <p className="form-error" role="alert">
            Suggestions could not be read. Type a name to search instead.
          </p>
        ) : groups.every((g) => g.items.length === 0) ? (
          <p className="empty-state">
            {isPod && family
              ? `No other replicas of ${family.prefix} were found. Type a name to search for another ${kind}.`
              : `No other ${kind} objects were found nearby. Type a name to search every cluster.`}
          </p>
        ) : (
          groups
            .filter((g) => g.items.length > 0)
            .map((g) => <CandidateList key={g.label} label={g.label} partial={g.partial} items={g.items} current={current} other={other} otherSide={otherSide} onPick={onPick} />)
        )}
      </div>
    </Dialog>
  )
}
