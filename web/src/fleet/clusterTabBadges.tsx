import { useQuery } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { getLatestUpgradeScan } from '../api/client'
import type { Incident } from '../api/types'
import { useAuth } from '../auth/useAuth'
import type { GitOpsAppList } from './gitopsModel'
import type { PostureResult } from './postureModel'
import { totalWarnings, type NetworkPolicyMap } from './netpolModel'
import { useInspect } from './useInspect'

// The problem count on a cluster tab (owner-approved cluster-pages design,
// 2026-10-11): the tab row says where to look before anything is clicked.
// Each badge reads a query its own tab already makes — the same query key,
// so opening the tab reuses the answer instead of asking the agent twice —
// and a badge whose source is unknown is simply absent, never a 0.

export type TabBadgeTone = 'critical' | 'high' | 'medium' | 'neutral'

export interface TabBadge {
  text: string
  /** Read after the tab name by a screen reader: "70 open incidents". */
  spoken: string
  tone: TabBadgeTone
}

const NO_ARGS = {}

export function useClusterTabBadges({
  clusterId,
  incidents,
  metrics,
  kubecost = false,
  inspectAllowed,
}: {
  clusterId: string | undefined
  incidents: readonly Incident[]
  /** facts.metrics — whether the agent has a Prometheus it may read. */
  metrics: { checked?: boolean; allowed?: boolean } | null | undefined
  /** facts.agent.kubecost — Kubecost is the cost source, so Cost needs no Prometheus. */
  kubecost?: boolean
  inspectAllowed: boolean
}): Partial<Record<string, TabBadge>> {
  const { accessToken } = useAuth()
  const gitops = useInspect<GitOpsAppList>(clusterId, 'list_gitops_apps', NO_ARGS, inspectAllowed)
  const posture = useInspect<PostureResult>(clusterId, 'get_posture_findings', NO_ARGS, inspectAllowed)
  const netpol = useInspect<NetworkPolicyMap>(clusterId, 'get_network_policy_map', NO_ARGS, inspectAllowed)
  const upgrade = useQuery({
    queryKey: ['upgrade-scan', clusterId],
    queryFn: () => getLatestUpgradeScan(clusterId!, accessToken!),
    enabled: !!accessToken && !!clusterId,
  })

  const out: Partial<Record<string, TabBadge>> = {}

  const open = incidents.filter((i) => !['Resolved', 'Dismissed'].includes(i.state))
  if (open.length > 0) {
    const tone: TabBadgeTone = open.some((i) => i.severity === 'critical') ? 'critical' : open.some((i) => i.severity === 'high') ? 'high' : 'medium'
    out.incidents = { text: String(open.length), spoken: `${open.length} open`, tone }
  }

  const apps = gitops.query.data?.result?.apps
  if (apps) {
    const problems = apps.filter((a) => a.problem).length
    if (problems > 0) out.gitops = { text: String(problems), spoken: `${problems} with a problem`, tone: 'high' }
  }

  const verdict = upgrade.data?.scan?.verdict
  if (verdict === 'blocked') out.upgrade = { text: 'Blocked', spoken: 'blocked', tone: 'critical' }
  else if (verdict === 'warning') out.upgrade = { text: 'Warning', spoken: 'warning', tone: 'medium' }

  const danger = posture.query.data?.result?.summary?.danger
  if (typeof danger === 'number' && danger > 0) out.posture = { text: String(danger), spoken: `${danger} danger findings`, tone: 'high' }

  const warnings = totalWarnings(netpol.query.data?.result?.namespaces)
  if (warnings) out.netpol = { text: String(warnings), spoken: `${warnings} network policy warnings`, tone: 'high' }

  // Traffic and Cost both read through the agent's Prometheus; with none
  // configured (or the proxy grant missing) neither can show anything.
  if (metrics && !(metrics.checked && metrics.allowed)) {
    out.traffic = { text: 'off', spoken: 'no metrics source', tone: 'neutral' }
    if (!kubecost) out.cost = { text: 'off', spoken: 'no metrics source', tone: 'neutral' }
  }
  return out
}

export function TabLabel({ label, badge }: { label: string; badge?: TabBadge }): ReactNode {
  if (!badge) return label
  return (
    <>
      {label}
      <span className="tab-badge" data-tone={badge.tone}>
        <span aria-hidden="true">{badge.text}</span>
        <span className="visually-hidden">, {badge.spoken}</span>
      </span>
    </>
  )
}
