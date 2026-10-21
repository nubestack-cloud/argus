import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getFleetSummary } from '../api/client'
import type {
  Cluster,
  ClusterDetail,
  FleetCertificatesSummary,
  FleetClusterSummary,
  FleetGitOpsSummary,
  FleetHelmSummary,
  FleetPostureSummary,
} from '../api/types'
import { CAP_CLUSTER_INSPECT } from '../api/capabilities'
import { useAuth } from '../auth/useAuth'
import { useMissingCapabilities } from '../auth/useCapabilities'
import { SLOW_FALLBACK_MS } from '../realtime/refresh'

// The Overview's fleet sections read ONE aggregate, GET /api/v1/fleet/summary:
// every readable cluster's facts digest plus the hub's stored fleet checks
// (internal/fleetchecks), which a hub worker re-reads from each connected
// agent every few minutes. Opening the page therefore calls no agent at all,
// whatever the fleet's size; the price is that a check is up to one interval
// old, and every card says how old.

/** A cluster that has reported facts at some point and is still part of the fleet. */
export function hasFacts(c: Cluster): boolean {
  return c.state === 'Active' || c.state === 'Degraded' || c.state === 'Disconnected'
}

/** One stored check for one cluster, as the cards read it. */
export type CheckStatus<T> =
  /** The viewer lacks cluster:inspect on this cluster. */
  | { kind: 'unreadable' }
  /** The hub has not read it yet (a new cluster, or a hub just started). */
  | { kind: 'unread' }
  /** Every read so far has failed. */
  | { kind: 'error'; error: string; at: string | null }
  /** The last good answer; `failedSince` when a later read failed. */
  | { kind: 'ok'; summary: T; at: string; failedSince: string | null; failure: string | null }

type CheckName = 'certificates' | 'posture' | 'helm' | 'gitops'

interface StoredCheck {
  summary: unknown
  summaryAt: string | null
  error: string | null
  errorAt: string | null
}

function statusOf<T>(c: FleetClusterSummary | undefined, name: CheckName): CheckStatus<T> {
  if (!c?.checksReadable) return { kind: 'unreadable' }
  const s = (c.checks as Record<string, StoredCheck | undefined>)[name]
  if (!s) return { kind: 'unread' }
  if (s.summary == null || !s.summaryAt) return { kind: 'error', error: s.error ?? 'the agent did not answer', at: s.errorAt }
  const failedLater = s.error && s.errorAt && s.errorAt > s.summaryAt
  return { kind: 'ok', summary: s.summary as T, at: s.summaryAt, failedSince: failedLater ? s.errorAt : null, failure: failedLater ? s.error : null }
}

export interface FleetChecks {
  certificates: (id: string) => CheckStatus<FleetCertificatesSummary>
  posture: (id: string) => CheckStatus<FleetPostureSummary>
  helm: (id: string) => CheckStatus<FleetHelmSummary>
  gitops: (id: string) => CheckStatus<FleetGitOpsSummary>
}

export interface FleetData {
  /** Each readable cluster with its facts digest, shaped as ClusterDetail. */
  details: Map<string, ClusterDetail>
  loading: boolean
  error: unknown
  /** How often the hub re-reads each cluster, in seconds. */
  intervalSeconds: number | null
  /** False only when the viewer cannot read the checks of any cluster here. */
  checksAllowed: boolean | null
  /** The capability that would let them, for the card that says so. */
  checksMissing: string[]
  checks: FleetChecks
}

export function useFleetData(clusters: readonly Cluster[]): FleetData {
  const { accessToken } = useAuth()
  const { missing } = useMissingCapabilities([CAP_CLUSTER_INSPECT])
  const q = useQuery({
    queryKey: ['fleet-summary'],
    queryFn: () => getFleetSummary(accessToken!),
    enabled: !!accessToken,
    // The hub refreshes the checks on its own interval; polling faster than
    // a minute or two would only re-read the same rows.
    refetchInterval: SLOW_FALLBACK_MS,
  })

  const byId = useMemo(() => new Map((q.data?.clusters ?? []).map((c) => [c.clusterId, c])), [q.data])
  const details = useMemo(() => {
    const m = new Map<string, ClusterDetail>()
    for (const c of clusters) {
      const s = byId.get(c.id)
      if (s) m.set(c.id, { ...c, facts: (s.facts ?? null) as ClusterDetail['facts'], factsUpdatedAt: s.factsUpdatedAt ?? null } as ClusterDetail)
    }
    return m
  }, [clusters, byId])

  const shown = clusters.filter((c) => byId.has(c.id))
  const checksAllowed = q.data ? (shown.length === 0 ? null : shown.some((c) => byId.get(c.id)!.checksReadable)) : null

  return {
    details,
    loading: q.isLoading,
    error: q.isError ? q.error : null,
    intervalSeconds: q.data?.intervalSeconds ?? null,
    checksAllowed,
    checksMissing: missing.length ? missing : [CAP_CLUSTER_INSPECT],
    checks: {
      certificates: (id) => statusOf(byId.get(id), 'certificates'),
      posture: (id) => statusOf(byId.get(id), 'posture'),
      helm: (id) => statusOf(byId.get(id), 'helm'),
      gitops: (id) => statusOf(byId.get(id), 'gitops'),
    },
  }
}

/** The oldest read among the checks a card drew, for its "as of" line. */
export function oldestRead(statuses: CheckStatus<unknown>[]): string | null {
  let oldest: string | null = null
  for (const s of statuses) if (s.kind === 'ok' && (oldest === null || s.at < oldest)) oldest = s.at
  return oldest
}
