// The incident page's cluster-insight sections (docs/CLUSTER_INSIGHT_SPECS.md
// CI-S1, S2, S7, S8, S9, S15). Every one supports question 2 — "why" — and
// sits BELOW the causal chain inside the Analysis stage (screens.md's
// four-question order): the chain is the argument, these are the evidence a
// reader opens to check it. Heavy sections are collapsed and fetch nothing
// until opened; the two that answer the incident's own question directly
// (why a Pending pod will not schedule, what Git says for a GitOps failure)
// open by default.
import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ApiError, getIncidentMetrics, getIncidentPrecedingChanges, requestQuickAction } from '../../api/client'
import { CAP_CLUSTER_INSPECT, CAP_REMEDIATION_EXECUTE_INPLACE } from '../../api/capabilities'
import { missingCapabilityMessage } from '../../api/capabilityInfo'
import type { IncidentDetail } from '../../api/types'
import { isClosedIncidentState } from '../../utils/incidents'
import { useAuth } from '../../auth/useAuth'
import { useHasCapability } from '../../auth/useCapabilities'
import { Freshness } from '../../components/Freshness'
import type { ChartAnnotation } from '../../charts/types'
import { GraphCanvas } from '../../graph/GraphCanvas'
import type { GraphNode } from '../../graph/types'
import { reproducerFor } from '../../evidence/reproducer'
import { CapabilityNotice, InsightFooter, QueryBody } from '../../insight/InsightParts'
import { changeObjectLabel, changeWhat, graphPartialNote, neighborhoodGraph } from '../../insight/model'
import type { GitOpsInsightResult, NeighborhoodResult, SchedulingResult } from '../../insight/types'
import { isObjectNotFound, useClusterFreshness, useInspect } from '../../insight/useInspect'
import { useOpenObject } from '../../insight/useOpenObject'
import { ChangeList } from '../../insight/views/ChangeList'
import { GitOpsInsightView, DriftTable } from '../../insight/views/GitOpsInsightView'
import { SchedulingView } from '../../insight/views/SchedulingView'
import { MetricPanels, MetricRangePicker, type MetricRange } from '../../insight/views/MetricPanels'
import { gitOpsQuickAction, gitOpsSource, incidentObject, incidentSubject, pendingPod, unixSeconds } from './insightModel'
import { TrafficDependencies } from '../../fleet/TrafficDependencies'
import { isHostFlow } from '../../fleet/trafficLevels'
import { trafficUnavailableReason, type TrafficResult } from '../../fleet/trafficModel'

// Inside EvidenceTabs a section is a tab panel: the tab is its title, so the
// section renders its hint and body with no disclosure of its own.
const TabbedSection = createContext(false)

function Section({
  title,
  hint,
  defaultOpen = false,
  children,
}: {
  title: string
  hint?: ReactNode
  defaultOpen?: boolean
  children: () => ReactNode
}) {
  // Mounted on first open and kept mounted, so closing does not throw away
  // what was read and re-opening does not re-fetch.
  const [opened, setOpened] = useState(defaultOpen)
  const tabbed = useContext(TabbedSection)
  if (tabbed) {
    return (
      <div className="insight-section-body">
        {hint && <p className="field-hint insight-tab-hint">{hint}</p>}
        {children()}
      </div>
    )
  }
  return (
    <details className="insight-section" open={defaultOpen} onToggle={(e) => e.currentTarget.open && setOpened(true)}>
      <summary>
        <h3>{title}</h3>
        {hint && <span className="field-hint">{hint}</span>}
      </summary>
      {opened && <div className="insight-section-body">{children()}</div>}
    </details>
  )
}

// ---------------------------------------------------------------- CI-S1

function safeFilePart(s: string): string {
  return s.replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '') || 'object'
}

export function AffectedObjects({ incident }: { incident: IncidentDetail }) {
  const subject = incidentSubject(incident)
  const canInspect = useHasCapability(CAP_CLUSTER_INSPECT)
  if (!subject) return null
  return (
    <Section title="Affected objects" defaultOpen hint={`What ${subject.kind} ${subject.name} owns, uses and is reached by`}>
      {() =>
        canInspect ? (
          <AffectedObjectsBody incident={incident} />
        ) : (
          <CapabilityNotice message={missingCapabilityMessage([CAP_CLUSTER_INSPECT])} />
        )
      }
    </Section>
  )
}

function AffectedObjectsBody({ incident }: { incident: IncidentDetail }) {
  const subject = incidentSubject(incident)!
  const cluster = useClusterFreshness(incident.clusterId)
  const open = useOpenObject()
  const canvasRef = useRef<HTMLDivElement>(null)
  const exportRef = useRef<(() => Promise<string>) | null>(null)
  const [exportError, setExportError] = useState<string | null>(null)
  const args = { kind: subject.kind, apiGroup: subject.apiGroup ?? '', namespace: subject.namespace ?? '', name: subject.name, hops: 1 }
  const q = useInspect<NeighborhoodResult>(incident.clusterId, 'get_neighborhood', args)

  const exportPng = async () => {
    setExportError(null)
    if (!exportRef.current) return
    try {
      const url = await exportRef.current()
      const a = document.createElement('a')
      a.href = url
      a.download = `${safeFilePart(incident.clusterDisplayName)}-${safeFilePart(`${subject.kind}-${subject.name}`)}-${new Date().toISOString().slice(0, 10)}.png`
      document.body.appendChild(a)
      a.click()
      a.remove()
    } catch {
      setExportError('The image could not be produced in this browser.')
    }
  }

  return (
    <QueryBody
      query={q}
      lines={8}
      errorFallback="The agent could not read this object's relationships."
      notFound={`${subject.kind} ${subject.name} is no longer on the cluster, so there are no relationships to show.`}
    >
      {(res) => {
        const r = res.result
        const g = neighborhoodGraph(r)
        const partial = graphPartialNote(r)
        const openNode = (n: GraphNode) => {
          if (n.kind === 'PodGroup') return
          open({ clusterId: incident.clusterId, kind: n.kind, apiGroup: n.apiGroup || undefined, namespace: n.namespace, name: n.name })
        }
        return (
          <div className="insight-stack">
            {partial && <p className="insight-note">{partial}</p>}
            {g.nodes.length <= 1 ? (
              <p className="empty-state">
                No related objects were found one step from {subject.kind} {subject.name}
                {partial ? ' among the kinds the agent could read' : ''}.
              </p>
            ) : (
              <>
                <div className="insight-controls">
                  <button type="button" className="secondary" onClick={exportPng}>
                    Export as PNG
                  </button>
                  <span className="field-hint">Select a node to inspect it.</span>
                </div>
                {exportError && (
                  <p className="form-error" role="alert">
                    {exportError}
                  </p>
                )}
                <GraphCanvas
                  nodes={g.nodes}
                  edges={g.edges}
                  focusId={g.rootId}
                  focusTag="this incident"
                  onOpen={openNode}
                  label={`Objects related to ${subject.kind} ${subject.name}`}
                  height={360}
                  containerRef={canvasRef}
                  exportRef={exportRef}
                />
              </>
            )}
            <InsightFooter at={r.observedAt ?? res.receivedAt} cluster={cluster} coverage={r.coverage} command={reproducerFor('get_neighborhood', args)} />
          </div>
        )
      }}
    </QueryBody>
  )
}

// ---------------------------------------------------------------- CI-S2

function usePrecedingChanges(incidentId: string, enabled: boolean) {
  const { accessToken } = useAuth()
  return useQuery({
    queryKey: ['incidents', incidentId, 'preceding-changes'],
    queryFn: () => getIncidentPrecedingChanges(incidentId, accessToken!),
    enabled: enabled && !!accessToken,
    staleTime: 30_000,
    retry: false,
  })
}

export function PrecedingChanges({ incident }: { incident: IncidentDetail }) {
  return (
    <Section title="Changes before this incident" hint="Recorded by the agent on this object, its owners and its neighbours">
      {() => <PrecedingChangesBody incident={incident} />}
    </Section>
  )
}

function PrecedingChangesBody({ incident }: { incident: IncidentDetail }) {
  const q = usePrecedingChanges(incident.id, true)
  const open = useOpenObject()
  const cluster = useClusterFreshness(incident.clusterId)
  return (
    <QueryBody query={q} lines={5} errorFallback="The change history could not be read.">
      {(data) => (
        <div className="insight-stack">
          {data.since && <p className="field-hint">Window: from {new Date(data.since).toLocaleString()} to now, newest first.</p>}
          <ChangeList
            changes={data.changes}
            gaps={data.gaps}
            truncated={data.truncated}
            clusterId={incident.clusterId}
            onOpen={open}
            emptyText="No recorded change to these objects in the window before this incident"
          />
          <div className="insight-footer">
            <Freshness at={q.dataUpdatedAt ? new Date(q.dataUpdatedAt) : null} stale={cluster.stale} staleReason={cluster.staleReason} />
          </div>
        </div>
      )}
    </QueryBody>
  )
}

// ---------------------------------------------------------------- CI-S8

export function ResourceUsage({ incident }: { incident: IncidentDetail }) {
  return (
    <Section title="Resource usage" hint="CPU, memory, restarts and throttling around the incident">
      {() => <ResourceUsageBody incident={incident} />}
    </Section>
  )
}

function ResourceUsageBody({ incident }: { incident: IncidentDetail }) {
  const { accessToken } = useAuth()
  const [range, setRange] = useState<MetricRange>('6h')
  const cluster = useClusterFreshness(incident.clusterId)
  const q = useQuery({
    queryKey: ['incidents', incident.id, 'metrics', range],
    queryFn: () => getIncidentMetrics(incident.id, range, accessToken!),
    enabled: !!accessToken,
    staleTime: 30_000,
    retry: false,
  })
  const changes = usePrecedingChanges(incident.id, true)
  const unavailable = q.data !== undefined && !q.data.available
  return (
    <div className="insight-stack">
      <div className="insight-controls">
        <MetricRangePicker
          range={range}
          onChange={setRange}
          unavailableReason={unavailable ? q.data?.reason || 'the hub has no metrics source for this cluster' : undefined}
        />
      </div>
      <QueryBody query={q} lines={10} errorFallback="Resource usage could not be read.">
        {(m) => {
          const annotations: ChartAnnotation[] = [{ timestamp: unixSeconds(m.openedAt), label: 'opened', kind: 'opened' }]
          for (const c of changes.data?.changes ?? []) {
            annotations.push({ timestamp: unixSeconds(c.observedAt), label: `${changeObjectLabel(c)}: ${changeWhat(c)}`, kind: 'change' })
          }
          return (
            <>
              <MetricPanels answer={m} annotations={annotations} />
              {m.available && <InsightFooter at={m.receivedAt} cluster={cluster} />}
            </>
          )
        }}
      </QueryBody>
    </div>
  )
}

// ---------------------------------------------------------------- CI-S9

// A pod that no longer exists has nothing left to schedule. The hub answers
// an inspection whose object the agent reported missing with a 404 of type
// object-not-found (PROBLEM_OBJECT_NOT_FOUND) — recognised here so the section
// says that in plain words and folds away, instead of sitting open on an
// error. The agent's own "… not found" sentence is still accepted as a
// fallback for a 502 from a hub that predates that mapping.
export function isObjectGoneError(error: unknown): boolean {
  if (isObjectNotFound(error)) return true
  if (!(error instanceof ApiError) || error.status !== 502) return false
  return /\bnot found\.?$/i.test((error.detail ?? '').trim())
}

export function WhyNotScheduled({ incident }: { incident: IncidentDetail }) {
  const pod = pendingPod(incident)
  const canInspect = useHasCapability(CAP_CLUSTER_INSPECT)
  // Set once the agent reports the pod gone; the section then re-mounts
  // collapsed with that fact as its hint.
  const [gone, setGone] = useState(false)
  if (!pod) return null
  return (
    <Section
      key={gone ? 'gone' : 'live'}
      title="Why it isn't scheduled"
      hint={gone ? `Pod ${pod.name} no longer exists — nothing left to schedule` : `Pod ${pod.name}, checked against every node`}
      // Open by default only while it can still answer the incident's
      // question: on a closed incident, or once the pod is gone, it is
      // history and starts folded.
      defaultOpen={!gone && !isClosedIncidentState(incident.state)}
    >
      {() =>
        canInspect ? (
          <WhyNotScheduledBody incident={incident} namespace={pod.namespace!} pod={pod.name} onGone={() => setGone(true)} />
        ) : (
          <CapabilityNotice message={missingCapabilityMessage([CAP_CLUSTER_INSPECT])} />
        )
      }
    </Section>
  )
}

function WhyNotScheduledBody({
  incident,
  namespace,
  pod,
  onGone,
}: {
  incident: IncidentDetail
  namespace: string
  pod: string
  onGone: () => void
}) {
  const cluster = useClusterFreshness(incident.clusterId)
  const args = { namespace, pod }
  const q = useInspect<SchedulingResult>(incident.clusterId, 'explain_scheduling', args)
  const objectGone = q.isError && isObjectGoneError(q.error)
  useEffect(() => {
    if (objectGone) onGone()
  }, [objectGone, onGone])
  if (objectGone) {
    return (
      <p className="empty-state">
        Pod {namespace}/{pod} no longer exists, so there is nothing left to schedule. Its replacement, if any, has a new
        name.
      </p>
    )
  }
  return (
    <QueryBody query={q} lines={6} errorFallback="The agent could not explain this pod's scheduling — it may already be scheduled or deleted.">
      {(res) => (
        <div className="insight-stack">
          <SchedulingView result={res.result} />
          <InsightFooter
            at={res.result.observedAt ?? res.receivedAt}
            cluster={cluster}
            coverage={res.result.coverage}
            truncated={res.result.truncated}
            command={reproducerFor('explain_scheduling', args)}
          />
        </div>
      )}
    </QueryBody>
  )
}

// ---------------------------------------------------------------- CI-S7 + CI-S15

export function GitVsCluster({ incident }: { incident: IncidentDetail }) {
  const source = gitOpsSource(incident)
  const canInspect = useHasCapability(CAP_CLUSTER_INSPECT)
  if (!source) return null
  return (
    <Section title="Git vs cluster" hint={`${source.kind} ${source.name}`} defaultOpen>
      {() => (
        <div className="insight-stack">
          {canInspect ? <GitVsClusterBody incident={incident} /> : <CapabilityNotice message={missingCapabilityMessage([CAP_CLUSTER_INSPECT])} />}
          <QuickActions incident={incident} />
        </div>
      )}
    </Section>
  )
}

function GitVsClusterBody({ incident }: { incident: IncidentDetail }) {
  const source = gitOpsSource(incident)!
  const object = incidentObject(incident)
  const cluster = useClusterFreshness(incident.clusterId)
  const srcArgs = { group: source.apiGroup ?? '', kind: source.kind, namespace: source.namespace ?? '', name: source.name }
  const src = useInspect<GitOpsInsightResult>(incident.clusterId, 'get_gitops_insight', srcArgs)
  // Drift is a property of the MANAGED object, so it is a second read when
  // the incident's object is not itself the controller object.
  const objIsSource = !!object && object.kind === source.kind && object.name === source.name
  const objArgs = object ? { group: object.apiGroup ?? '', kind: object.kind, namespace: object.namespace ?? '', name: object.name } : {}
  const drift = useInspect<GitOpsInsightResult>(incident.clusterId, 'get_gitops_insight', objArgs, !!object && !objIsSource)
  return (
    <div className="insight-stack">
      <QueryBody query={src} lines={6} errorFallback={`The agent could not read ${source.kind} ${source.name}.`}>
        {(res) => (
          <>
            <GitOpsInsightView result={res.result} showDrift={objIsSource} />
            <InsightFooter
              at={res.result.observedAt ?? res.receivedAt}
              cluster={cluster}
              coverage={res.result.coverage}
              command={reproducerFor('get_gitops_insight', srcArgs)}
            />
          </>
        )}
      </QueryBody>
      {object && !objIsSource && (
        <div>
          <p className="field-hint">
            Desired versus live for {object.kind} {object.name}
          </p>
          <QueryBody query={drift} lines={3} errorFallback={`Drift for ${object.kind} ${object.name} could not be read.`}>
            {(res) => (res.result.drift ? <DriftTable drift={res.result.drift} /> : <p className="empty-state">The agent returned no drift result for this object.</p>)}
          </QueryBody>
        </div>
      )}
    </div>
  )
}

export function QuickActions({ incident }: { incident: IncidentDetail }) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const canExecute = useHasCapability(CAP_REMEDIATION_EXECUTE_INPLACE)
  const qa = gitOpsQuickAction(gitOpsSource(incident))
  const mutation = useMutation({
    mutationFn: () => requestQuickAction(incident.id, { action: qa!.action, namespace: qa!.namespace, name: qa!.name }, accessToken!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['incidents', incident.id] }),
  })
  if (!qa) return null
  const missing = canExecute ? '' : missingCapabilityMessage([CAP_REMEDIATION_EXECUTE_INPLACE])
  const err = mutation.error
  return (
    <div className="insight-stack">
      <div className="insight-controls">
        <button type="button" className="secondary" disabled={!canExecute || mutation.isPending || mutation.isSuccess} title={missing || undefined} onClick={() => mutation.mutate()}>
          {mutation.isPending ? 'Requesting…' : qa.label}
        </button>
        <span className="field-hint">
          Asks the controller to re-read {qa.name}; it changes no desired state and goes through the normal approval flow.
        </span>
      </div>
      {missing && <p className="field-hint">{missing}</p>}
      {mutation.isSuccess && (
        <p className="insight-note" role="status">
          {mutation.data.gateOutcome === 'NeedsApproval' ? (
            <>
              Requested — awaiting approval. <Link to="/approvals">Open the approval queue →</Link>
            </>
          ) : mutation.data.gateOutcome === 'Blocked' ? (
            <>Requested, but policy blocked it: {mutation.data.gateReason}</>
          ) : (
            <>
              Requested — policy approved it automatically ({mutation.data.gateReason}); it runs through the in-place channel.{' '}
              <Link to="/approvals">Approval queue →</Link>
            </>
          )}
        </p>
      )}
      {mutation.isError && (
        <p className="form-error" role="alert">
          {err instanceof ApiError && err.status === 409
            ? `Analyse first — quick actions attach to this incident's analysis, and there is none yet.${err.detail ? ` (${err.detail})` : ''}`
            : err instanceof ApiError
              ? `${err.message}${err.detail ? ` — ${err.detail}` : ''}`
              : 'The request failed.'}
        </p>
      )}
    </div>
  )
}

// ---------------------------------------------------------------- traffic

// Who calls the incident's workload and what it calls, from the cluster's
// traffic source (Beyla, Istio or Hubble metrics in Prometheus): the callers
// are who feels this incident, the callees are dependencies that may be its
// cause. Without a traffic source it says so, so an empty list never reads as
// "nobody calls it".
// Kinds that never send or receive traffic themselves. Anything else in a
// namespace may: a traffic source names an operator's own workload (a
// CloudNativePG Cluster, say) by its controller, not by a built-in kind.
const NO_TRAFFIC_KINDS = new Set([
  'ConfigMap', 'Secret', 'PersistentVolumeClaim', 'ServiceAccount', 'Role', 'RoleBinding', 'NetworkPolicy',
  'ResourceQuota', 'LimitRange', 'PodDisruptionBudget', 'HorizontalPodAutoscaler', 'Ingress', 'HTTPRoute',
  'Certificate', 'CertificateRequest', 'Kustomization', 'HelmRelease', 'GitRepository', 'HelmRepository',
  'OCIRepository', 'Application', 'ApplicationSet', 'IngressRoute', 'Middleware', 'PolicyReport',
])

export function trafficSubject(incident: IncidentDetail): { namespace: string; name: string; kind: string } | null {
  const s = incidentSubject(incident)
  return s && s.namespace && !NO_TRAFFIC_KINDS.has(s.kind) ? { namespace: s.namespace, name: s.name, kind: s.kind } : null
}

export function IncidentTraffic({ incident }: { incident: IncidentDetail }) {
  const subject = trafficSubject(incident)
  const canInspect = useHasCapability(CAP_CLUSTER_INSPECT)
  if (!subject) return null
  return (
    <Section title="Traffic" hint={`Who calls ${subject.name} and what it calls, over the last 15 minutes against an hour earlier`}>
      {() => (canInspect ? <IncidentTrafficBody incident={incident} /> : <CapabilityNotice message={missingCapabilityMessage([CAP_CLUSTER_INSPECT])} />)}
    </Section>
  )
}

function IncidentTrafficBody({ incident }: { incident: IncidentDetail }) {
  const subject = trafficSubject(incident)!
  const cluster = useClusterFreshness(incident.clusterId)
  const q = useInspect<TrafficResult>(incident.clusterId, 'get_traffic', { namespace: subject.namespace, windowMinutes: 15, compareMinutes: 60 })
  return (
    <QueryBody query={q} lines={4} errorFallback="Traffic could not be read.">
      {(res) => {
        const r = res.result
        if (!r.available) return <p className="field-hint">{trafficUnavailableReason(r)}</p>
        return (
          <div className="insight-stack">
            <TrafficDependencies
              flows={r.flows ?? []}
              namespace={subject.namespace}
              name={subject.name}
              comparison={!!r.comparisonAvailable}
              comparisonSeconds={r.comparisonSeconds}
              limit={8}
            />
            <p className="field-hint">
              {(r.flows ?? []).some(isHostFlow) ? 'Node and probe traffic is included here. ' : ''}
              <Link to={`/clusters/${incident.clusterId}?tab=traffic&tns=${encodeURIComponent(subject.namespace)}&tfocus=${encodeURIComponent(`${subject.namespace}/${subject.name}`)}`}>
                Open on the Traffic tab
              </Link>
            </p>
            <InsightFooter at={r.observedAt ?? res.receivedAt} cluster={cluster} truncated={r.truncated} />
          </div>
        )
      }}
    </QueryBody>
  )
}

// ---------------------------------------------------------------- assembly


// The evidence beneath a diagnosis as tabs, one visible at a time (incident
// lifecycle redesign, 2026-10-12) — the same sections IncidentInsightSections
// stacks as disclosures, each mounted on first selection and kept mounted, so
// switching back does not re-fetch. Which tabs exist is decided by the same
// predicates the sections themselves use to render nothing.
export function EvidenceTabs({ incident }: { incident: IncidentDetail }) {
  const tabs: Array<{ id: string; label: string; el: ReactNode }> = []
  if (pendingPod(incident)) tabs.push({ id: 'scheduling', label: 'Scheduling', el: <WhyNotScheduled incident={incident} /> })
  if (gitOpsSource(incident)) tabs.push({ id: 'git', label: 'Git vs cluster', el: <GitVsCluster incident={incident} /> })
  if (incidentSubject(incident)) tabs.push({ id: 'objects', label: 'Affected objects', el: <AffectedObjects incident={incident} /> })
  if (trafficSubject(incident)) tabs.push({ id: 'traffic', label: 'Traffic', el: <IncidentTraffic incident={incident} /> })
  tabs.push({ id: 'changes', label: 'Changes before', el: <PrecedingChanges incident={incident} /> })
  tabs.push({ id: 'usage', label: 'Resource usage', el: <ResourceUsage incident={incident} /> })
  const [active, setActive] = useState(tabs[0].id)
  const [visited, setVisited] = useState<Set<string>>(() => new Set([tabs[0].id]))
  const select = (id: string) => {
    setActive(id)
    setVisited((v) => (v.has(id) ? v : new Set(v).add(id)))
  }
  return (
    <div className="evidence-tabs">
      <div className="tabs evidence-tablist" role="tablist" aria-label="Evidence">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            id={`evidence-tab-${t.id}`}
            aria-selected={active === t.id}
            aria-controls={`evidence-panel-${t.id}`}
            className="tabs-tab"
            onClick={() => select(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>
      <TabbedSection.Provider value>
        {tabs.map((t) =>
          visited.has(t.id) ? (
            <div
              key={t.id}
              role="tabpanel"
              id={`evidence-panel-${t.id}`}
              aria-labelledby={`evidence-tab-${t.id}`}
              className="evidence-panel"
              hidden={active !== t.id}
            >
              {t.el}
            </div>
          ) : null,
        )}
      </TabbedSection.Provider>
    </div>
  )
}
