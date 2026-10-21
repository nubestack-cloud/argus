import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getFleetUpgradeScans } from '../api/client'
import type { UpgradeScan } from '../api/types'
import { useAuth } from '../auth/useAuth'
import { SLOW_FALLBACK_MS } from '../realtime/refresh'

// The fleet's latest upgrade scans (docs/CLUSTER_INSIGHT_SPECS.md CI-S5), for
// the Clusters list's upgrade column (FleetUpgradeColumn.tsx).

export function useFleetUpgradeScans() {
  const { accessToken } = useAuth()
  const query = useQuery({
    queryKey: ['upgrade-scans'],
    queryFn: () => getFleetUpgradeScans(accessToken!),
    enabled: !!accessToken,
    // Scans run once a day per cluster or on demand; nobody watches this
    // change, so it rides the slow fallback.
    refetchInterval: SLOW_FALLBACK_MS,
  })
  const byCluster = useMemo(() => {
    const m = new Map<string, UpgradeScan>()
    for (const s of query.data?.scans ?? []) m.set(s.clusterId, s)
    return m
  }, [query.data])
  return { query, byCluster }
}

/** The column heading: "Upgrade to 1.N" when every stored scan targets the
 *  same release, otherwise a heading that does not claim one. */
export function upgradeColumnHeading(scans: Iterable<UpgradeScan>): string {
  const targets = new Set<string>()
  for (const s of scans) targets.add(s.targetVersion)
  return targets.size === 1 ? `Upgrade to ${[...targets][0]}` : 'Next upgrade'
}
