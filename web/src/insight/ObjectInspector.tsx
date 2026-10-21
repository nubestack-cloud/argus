import { useCallback, type ReactNode } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { CAP_CLUSTER_INSPECT, CAP_CLUSTER_READ } from '../api/capabilities'
import { missingCapabilityMessage } from '../api/capabilityInfo'
import { useHasCapability } from '../auth/useCapabilities'
import { SidePanel } from '../components/SidePanel'
import { Tabs, type TabDef } from '../components/Tabs'
import { describeArgs } from '../evidence/reproducer'
import { compareHref } from '../compare/compareUrl'
import { CapabilityNotice } from './InsightParts'
import { isInspectorTab, TAB_LABEL, tabsFor, type InspectorTab } from './model'
import { decodeObjectPanel, encodeObjectPanel, PANEL_PARAM, withObjectPanel, type ObjectRef } from './panelUrl'
import type { DescribeResult } from './types'
import { useClusterFreshness, useInspect } from './useInspect'
import { AutoscalerTab, GitOpsTab, HelmTab, PermissionsTab, PolicyTab, RolloutTab, SchedulingTab, DrainTab } from './tabs/AnalysisTabs'
import { ConnectivityTab } from './tabs/ConnectivityTab'
import { LogsTab } from './tabs/LogsTab'
import { MetricsTab } from './tabs/MetricsTab'
import { ChangesTab, EventsTab, RelatedTab, SummaryTab, YamlTab } from './tabs/ObjectTabs'
import type { TabProps } from './tabs/common'

export const TAB_PARAM = 'ptab'

// ObjectInspectorHost (mounted once in AppShell) renders the object
// inspector whenever the URL carries ?panel=obj:… (docs/CLUSTER_INSIGHT_SPECS.md
// CI-S6). Any page opens it by setting that one parameter, so a link or a
// refresh reproduces the open panel and its tab (?ptab=).
export function ObjectInspectorHost() {
  const [params] = useSearchParams()
  const target = decodeObjectPanel(params.get(PANEL_PARAM))
  if (!target) return null
  // Keyed by the object so re-targeting starts every tab fresh.
  return <ObjectInspector key={encodeObjectPanel(target)} target={target} />
}

const TAB_VIEW: Record<InspectorTab, (p: TabProps) => ReactNode> = {
  summary: SummaryTab,
  yaml: YamlTab,
  events: EventsTab,
  logs: LogsTab,
  metrics: MetricsTab,
  changes: ChangesTab,
  related: RelatedTab,
  path: ConnectivityTab,
  permissions: PermissionsTab,
  policy: PolicyTab,
  gitops: GitOpsTab,
  helm: HelmTab,
  autoscaler: AutoscalerTab,
  rollout: RolloutTab,
  scheduling: SchedulingTab,
  drain: DrainTab,
}

export function ObjectInspector({ target }: { target: ObjectRef }) {
  const [params, setParams] = useSearchParams()
  const navigate = useNavigate()
  const canInspect = useHasCapability(CAP_CLUSTER_INSPECT)
  const canRead = useHasCapability(CAP_CLUSTER_READ)
  const cluster = useClusterFreshness(target.clusterId)
  // One describe read serves Summary, YAML, the Logs container list, the
  // Permissions service account, and the tabs that depend on the object's
  // content (GitOps markers, Helm annotation, Pending phase).
  const describe = useInspect<DescribeResult>(target.clusterId, 'describe_resource', describeArgs(target), canInspect)

  const close = useCallback(() => setParams((prev) => withObjectPanel(prev, null)), [setParams])
  const open = useCallback(
    (r: ObjectRef) =>
      setParams((prev) => {
        const next = withObjectPanel(prev, r)
        next.delete(TAB_PARAM)
        return next
      }),
    [setParams],
  )

  // Each tab names the capability it needs; Changes reads the hub's stored
  // history (cluster:read), every other tab reads the live cluster
  // (cluster:inspect). Disabled, never hidden.
  // Every applicable tab, in tabsFor's order of importance; the row scrolls
  // when it does not fit.
  const ids = tabsFor(target.kind, target.apiGroup, describe.data?.result?.object)
  const tabs: TabDef[] = ids.map((id) => {
    const needed = id === 'changes' ? (canRead ? null : CAP_CLUSTER_READ) : canInspect ? null : CAP_CLUSTER_INSPECT
    return { id, label: TAB_LABEL[id], disabledReason: needed ? missingCapabilityMessage([needed]) : undefined }
  })
  const requested = params.get(TAB_PARAM)
  const firstEnabled = tabs.find((t) => !t.disabledReason)?.id as InspectorTab | undefined
  const active: InspectorTab =
    isInspectorTab(requested) && tabs.some((t) => t.id === requested && !t.disabledReason) ? requested : (firstEnabled ?? 'summary')
  const activeDef = tabs.find((t) => t.id === active)

  const setTab = (id: string) =>
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev)
        if (id === 'summary') next.delete(TAB_PARAM)
        else next.set(TAB_PARAM, id)
        return next
      },
      { replace: true },
    )

  const View = TAB_VIEW[active]
  // Compare… (PROJECT.md AD4) opens the compare page with this object as A
  // and B's picker open on its likely partners (sibling replicas for a Pod,
  // the same name elsewhere for anything else).
  const compareAction = (
    <button
      type="button"
      className="secondary"
      disabled={!canInspect}
      title={canInspect ? 'Compare this object with another of its kind' : missingCapabilityMessage([CAP_CLUSTER_INSPECT])}
      onClick={() => navigate(compareHref(target))}
    >
      Compare…
    </button>
  )
  return (
    <SidePanel
      actions={compareAction}
      title={
        <>
          {target.kind} <span className="insight-mono">{target.name}</span>
        </>
      }
      subtitle={[target.namespace, cluster.name].filter(Boolean).join(' · ')}
      onClose={close}
    >
      <Tabs tabs={tabs} active={active} onChange={setTab} label={`${target.kind} ${target.name} details`}>
        {activeDef?.disabledReason ? (
          <CapabilityNotice message={activeDef.disabledReason} />
        ) : (
          <View target={target} cluster={cluster} describe={describe} open={open} setTab={setTab} />
        )}
      </Tabs>
    </SidePanel>
  )
}
