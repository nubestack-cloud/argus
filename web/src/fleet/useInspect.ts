import { useQuery } from '@tanstack/react-query'
import { inspectCluster, type InspectResult } from '../api/client'
import { CAP_CLUSTER_INSPECT } from '../api/capabilities'
import { useAuth } from '../auth/useAuth'
import { useMissingCapabilities } from '../auth/useCapabilities'

// One read-only agent tool run for a cluster tab (POST /clusters/{id}/
// inspect/{tool}). On demand, not polled: each call is a live agent round
// trip, so a tab asks once when shown and again only when its arguments
// change or the viewer presses Refresh. The capability is resolved first so
// "not checked yet" never reads as "not allowed" (useMissingCapabilities).
export function useInspect<T>(clusterId: string | undefined, tool: string, args: Record<string, unknown>, enabled = true) {
  const { accessToken } = useAuth()
  const { resolved, missing } = useMissingCapabilities([CAP_CLUSTER_INSPECT])
  const allowed = resolved && missing.length === 0
  const query = useQuery<InspectResult<T>>({
    queryKey: ['cluster-inspect', clusterId, tool, args],
    queryFn: () => inspectCluster<T>(clusterId!, tool, args, accessToken!),
    enabled: enabled && !!accessToken && !!clusterId && allowed,
    staleTime: 60_000,
    retry: false,
  })
  return { query, capabilityResolved: resolved, missing }
}
