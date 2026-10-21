import type { ReactNode } from 'react'
import type { UseQueryResult } from '@tanstack/react-query'
import type { InspectResult } from '../api/client'
import { apiErrorText } from './apiErrorText'
import { missingCapabilityMessage } from '../api/capabilityInfo'
import { Freshness } from '../components/Freshness'
import { HelpTip } from '../components/HelpTip'
import { SkeletonLines, SkeletonTableRows } from '../components/Skeleton'
import { CACHE_STATE_LABEL, kindLabel, type CacheKindState } from './clusterSummary'

/** The staleness every agent-sourced view on a cluster page shares: data from
 *  a cluster that is not Active is stated as stale (CI-U10). */
export interface ClusterLiveness {
  stale: boolean
  staleReason?: string
}

/** "Incomplete: Ingress (Forbidden to the agent), …" — the kinds an answer
 *  needed and did not have. Empty when the inputs were complete. */
export function CoverageNote({ coverage }: { coverage?: CacheKindState[] | null }) {
  const gaps = (coverage ?? []).filter((c) => c.state !== 'synced')
  if (gaps.length === 0) return null
  return (
    <p className="fleet-coverage-note" role="note">
      <span className="badge badge-amber">Partial</span>
      <span>
        could not use{' '}
        {gaps.map((g, i) => (
          <span key={`${g.group}/${g.kind}`}>
            {i > 0 ? ', ' : ''}
            {kindLabel(g)} ({(CACHE_STATE_LABEL[g.state] ?? g.state).toLowerCase()}
            {g.reason ? `: ${g.reason}` : ''})
          </span>
        ))}
      </span>
    </p>
  )
}

// The four states every inspect-backed tab shares (lld/11 §7): capability
// unresolved/denied, loading, error, populated. The populated body is the
// caller's; this owns the freshness stamp, the coverage gaps and Refresh.
export function InspectFrame<T extends { observedAt?: string; coverage?: CacheKindState[] | null }>({
  label,
  query,
  capabilityResolved,
  missing,
  liveness,
  skeletonColumns = 4,
  help,
  children,
}: {
  label: string
  /** One or two sentences on what this view contains and where its numbers
   *  come from, shown as a HelpTip beside the freshness stamp. */
  help?: string
  query: UseQueryResult<InspectResult<T>>
  capabilityResolved: boolean
  missing: string[]
  liveness: ClusterLiveness
  skeletonColumns?: number
  children: (result: T) => ReactNode
}) {
  if (capabilityResolved && missing.length > 0) {
    return (
      <p className="banner banner-warning" role="note">
        {label} runs a live read on this cluster&apos;s agent. {missingCapabilityMessage(missing)}
      </p>
    )
  }
  if (!capabilityResolved || query.isLoading) {
    return (
      <div aria-busy="true" aria-label={`Loading ${label.toLowerCase()}`}>
        <SkeletonLines count={1} widths={['12rem']} />
        <div className="table-scroll">
          <table className="cluster-table list-table">
            <tbody>
              <SkeletonTableRows columns={skeletonColumns} rows={5} />
            </tbody>
          </table>
        </div>
      </div>
    )
  }
  if (query.isError || !query.data) {
    return (
      <div className="fleet-inline-error">
        <p className="form-error" role="alert">
          {apiErrorText(query.error, `${label} could not be read from the agent.`)}
        </p>
        <button type="button" className="secondary" onClick={() => void query.refetch()}>
          Try again
        </button>
      </div>
    )
  }
  const result = query.data.result
  return (
    <div className="fleet-inspect">
      <div className="fleet-inspect-meta">
        {/* The stamp reads as one phrase at the left — what this is, and how
            old — with Refresh alone at the right. */}
        <div className="fleet-inspect-stamp">
          {help && <HelpTip label={label} text={help} />}
          <Freshness at={result?.observedAt ?? query.data.receivedAt} stale={liveness.stale} staleReason={liveness.staleReason} />
        </div>
        <button
          type="button"
          className="secondary fleet-refresh"
          onClick={() => void query.refetch()}
          disabled={query.isFetching}
          aria-label={`Refresh ${label.toLowerCase()} from the agent`}
        >
          {query.isFetching ? 'Refreshing…' : 'Refresh'}
        </button>
      </div>
      <CoverageNote coverage={result?.coverage} />
      {children(result)}
    </div>
  )
}
