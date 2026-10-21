import type { ReactNode } from 'react'
import type { UseQueryResult } from '@tanstack/react-query'
import { Freshness } from '../components/Freshness'
import { Reproducer } from '../components/Reproducer'
import { SkeletonLines } from '../components/Skeleton'
import { coverageNote } from './model'
import type { CoverageEntry } from './types'
import { errorText, isObjectNotFound, type ClusterFreshness } from './useInspect'

// The furniture every insight view carries (docs/CLUSTER_INSIGHT_SPECS.md
// CI-U9/CI-U10/CI-U2): how old the answer is — stale when the cluster is not
// Active — what it could not see, whether it was capped, and the command
// that re-derives it.
export function InsightFooter({
  at,
  cluster,
  coverage,
  truncated,
  truncatedText = 'This answer hit its size cap — more exists than is shown.',
  command,
}: {
  at: string | null | undefined
  cluster: ClusterFreshness
  coverage?: CoverageEntry[] | null
  truncated?: boolean
  truncatedText?: string
  command?: string | null
}) {
  const incomplete = coverageNote(coverage)
  return (
    <div className="insight-footer">
      <Freshness at={at} stale={cluster.stale} staleReason={cluster.staleReason} />
      {incomplete && (
        <p className="insight-note">
          <span className="badge badge-gray">Incomplete</span> {incomplete}
        </p>
      )}
      {truncated && <p className="insight-note">{truncatedText}</p>}
      {command && <Reproducer command={command} clusterName={cluster.name} />}
    </div>
  )
}

// The loading and error states of one query, so each view renders only its
// populated and empty states. Loading is a skeleton of roughly the view's
// height, never a spinner.
export function QueryBody<T>({
  query,
  lines = 4,
  errorFallback,
  notFound,
  children,
}: {
  query: Pick<UseQueryResult<T>, 'data' | 'isLoading' | 'isError' | 'error' | 'isFetching'>
  lines?: number
  errorFallback?: string
  /** What to say when the agent answered that the object does not exist —
   *  an empty state, not an error. Defaults to the agent's own reason. */
  notFound?: ReactNode
  children: (data: T) => ReactNode
}) {
  if (query.isLoading) {
    return (
      <div aria-busy="true" aria-label="Loading">
        <SkeletonLines count={lines} />
      </div>
    )
  }
  if (query.isError && isObjectNotFound(query.error)) {
    return <p className="empty-state">{notFound ?? errorText(query.error)}</p>
  }
  if (query.isError) {
    return (
      <p className="form-error" role="alert">
        {errorText(query.error, errorFallback)}
      </p>
    )
  }
  if (query.data === undefined) return null
  return <>{children(query.data)}</>
}

/** A data view the viewer may not open — said in place, never hidden. */
export function CapabilityNotice({ message }: { message: string }) {
  return <p className="insight-note insight-restricted">Restricted — {message}</p>
}
