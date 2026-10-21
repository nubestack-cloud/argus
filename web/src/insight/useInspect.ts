import { useQuery } from '@tanstack/react-query'
import { ApiError, getCluster, inspectCluster, PROBLEM_OBJECT_NOT_FOUND } from '../api/client'
import { useAuth } from '../auth/useAuth'
import { formatRelativeTime } from '../utils/time'

// One agent tool call on behalf of the signed-in person (POST
// /clusters/{id}/inspect/{tool}), cached per (cluster, tool, args). Callers
// pass `enabled: false` until the view that needs it is actually shown, so a
// tab's read runs the first time it is opened and not on panel mount.
export function useInspect<T>(clusterId: string, tool: string, args: Record<string, unknown>, enabled = true) {
  const { accessToken } = useAuth()
  return useQuery({
    queryKey: ['inspect', clusterId, tool, args],
    queryFn: () => inspectCluster<T>(clusterId, tool, args, accessToken!),
    enabled: enabled && !!accessToken && !!clusterId,
    // Live reads are cheap to repeat but not free (each is a tunnel round
    // trip to the agent); 30 s matches the hub's own neighbourhood cache.
    staleTime: 30_000,
    retry: false,
  })
}

export interface ClusterFreshness {
  /** Display name, or the id when the cluster could not be read. */
  name: string
  /** True when the cluster is known not to be Active — its data may be old. */
  stale: boolean
  staleReason?: string
}

// The cluster an inspection ran against: its name for the panel subtitle and
// the reproducer's "run against …", and whether its data should be stamped
// stale (CI-U10). Same query key as ClusterDetailPage, so one fetch serves
// both. A failed read degrades to the id and no stale claim — this hook must
// not invent a state it could not read.
export function useClusterFreshness(clusterId: string): ClusterFreshness {
  const { accessToken } = useAuth()
  const { data } = useQuery({
    queryKey: ['clusters', clusterId],
    queryFn: () => getCluster(clusterId, accessToken!),
    enabled: !!accessToken && !!clusterId,
    staleTime: 30_000,
    retry: false,
  })
  if (!data) return { name: clusterId, stale: false }
  const stale = data.state !== 'Active'
  const heartbeat = data.lastHeartbeatAt
    ? `last heartbeat ${formatRelativeTime(data.lastHeartbeatAt)}`
    : 'no heartbeat recorded'
  return {
    name: data.displayName || clusterId,
    stale,
    staleReason: stale ? `cluster is ${data.state}, ${heartbeat}` : undefined,
  }
}

/** True when the agent answered that the object asked about does not exist. */
export function isObjectNotFound(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404 && err.type === PROBLEM_OBJECT_NOT_FOUND
}

/** The RFC 9457 title and detail when actionable, else a generic sentence. */
export function errorText(err: unknown, fallback = 'The request failed.'): string {
  if (isObjectNotFound(err)) {
    const detail = (err as ApiError).detail
    return detail ? `Not on the cluster — ${detail}` : 'Not on the cluster — the agent found no such object.'
  }
  if (err instanceof ApiError) {
    if (err.status >= 500 && err.status !== 502 && err.status !== 503) return `${fallback} (${err.message})`
    return err.detail ? `${err.message} — ${err.detail}` : err.message
  }
  return fallback
}
