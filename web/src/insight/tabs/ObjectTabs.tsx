import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { stringify } from 'yaml'
import { getResourceChanges } from '../../api/client'
import { useAuth } from '../../auth/useAuth'
import { CopyButton } from '../../components/CopyButton'
import { Freshness } from '../../components/Freshness'
import { Quantity } from '../../components/Quantity'
import { GraphCanvas } from '../../graph/GraphCanvas'
import type { GraphNode } from '../../graph/types'
import { formatDateTime, formatRelativeTime } from '../../utils/time'
import { describeArgs, reproducerFor } from '../../evidence/reproducer'
import { InsightFooter, QueryBody } from '../InsightParts'
import { WORKLOAD_KINDS } from '../kinds'
import { conditionsOf, countRedacted, graphPartialNote, neighborhoodGraph } from '../model'
import { neighborhoodArgs, objectHealth, replicaBar } from '../summaryModel'
import {
  ConditionChecklist,
  ConnectedCard,
  ContainersTable,
  IngressRoutesCard,
  ObjectFacts,
  PodsCard,
  ReplicaBarView,
  ServiceCard,
  StatusBanner,
} from '../views/ObjectSummary'
import type { EventResult, NeighborhoodResult } from '../types'
import { useInspect } from '../useInspect'
import { withoutRelativeTimes } from '../../compare/normalize'
import { ChangeList } from '../views/ChangeList'
import { CodeLines } from '../views/CodeLines'
import type { TabProps } from './common'
import { HelpTip } from '../../components/HelpTip'

// ---------------------------------------------------------------- Summary

// Status first, then "is it healthy and why not" (replicas, conditions), then
// the containers, then previews that open the deeper tabs (pods, connected),
// then the plain facts — owner review 2026-10-10, PROJECT.md UX1. The status
// header is only drawn when the object reports a health signal; a ConfigMap
// gets no "Healthy" it never claimed.
export function SummaryTab({ target, cluster, describe, open, setTab }: TabProps) {
  const isWorkload = WORKLOAD_KINDS.has(target.kind)
  const nbArgs = neighborhoodArgs(target)
  // The same call (and cache entry) the Related tab makes.
  const neighborhood = useInspect<NeighborhoodResult>(target.clusterId, 'get_neighborhood', nbArgs, describe.isSuccess)
  return (
    <QueryBody query={describe} lines={8} errorFallback="The agent could not describe this object.">
      {(res) => {
        const obj = res.result?.object
        if (!obj) return <p className="empty-state">The agent returned no object — it may have been deleted.</p>
        const health = objectHealth(obj)
        const bar = replicaBar(obj)
        const hasConditions = conditionsOf(obj).length > 0
        return (
          <div className="insight-stack">
            {health && <StatusBanner health={health} />}
            {(bar || hasConditions) && (
              <div className="summary-pair">
                {bar && (
                  <section className="card card-compact" aria-label="Replicas">
                    <p className="metric-tile-label">Replicas</p>
                    <ReplicaBarView bar={bar} />
                  </section>
                )}
                {hasConditions && (
                  <section className="card card-compact" aria-label="Conditions">
                    <p className="metric-tile-label">Conditions</p>
                    <ConditionChecklist obj={obj} />
                  </section>
                )}
              </div>
            )}
            <ContainersTable obj={obj} isPod={target.kind === 'Pod'} />
            {target.kind === 'Ingress' && <IngressRoutesCard obj={obj} target={target} open={open} />}
            {target.kind === 'Service' && <ServiceCard obj={obj} target={target} />}
            {isWorkload && (
              <PodsCard
                query={neighborhood}
                onOpen={(name) => open({ clusterId: target.clusterId, kind: 'Pod', namespace: target.namespace, name })}
              />
            )}
            <ConnectedCard
              query={neighborhood}
              onOpen={(n) => open({ clusterId: target.clusterId, kind: n.kind, apiGroup: n.apiGroup || undefined, namespace: n.namespace, name: n.name })}
              onOpenRelated={() => setTab?.('related')}
            />
            <ObjectFacts obj={obj} target={target} open={open} />
            <InsightFooter at={res.receivedAt} cluster={cluster} command={reproducerFor('describe_resource', describeArgs(target))} />
          </div>
        )
      }}
    </QueryBody>
  )
}

// ---------------------------------------------------------------- YAML

function withoutManagedFields(obj: unknown): unknown {
  if (!obj || typeof obj !== 'object') return obj
  const o = obj as { metadata?: Record<string, unknown> }
  if (!o.metadata || !('managedFields' in o.metadata)) return obj
  const metadata = { ...o.metadata }
  delete metadata.managedFields
  return { ...o, metadata }
}

export function YamlTab({ target, cluster, describe }: TabProps) {
  const [wrap, setWrap] = useState(false)
  const [showManaged, setShowManaged] = useState(false)
  const obj = describe.data?.result?.object
  const hasManaged = !!(obj as { metadata?: { managedFields?: unknown } } | undefined)?.metadata?.managedFields
  const text = useMemo(() => {
    if (!obj) return ''
    // managedFields is API-server bookkeeping that buries the spec; hidden by
    // default, one click away. The agent's *SecondsSince/*SecondsUntil
    // helpers are not part of the object at all, so they are never shown or
    // copied (Compare drops them the same way).
    const plain = withoutRelativeTimes(obj)
    const view = showManaged ? plain : withoutManagedFields(plain)
    return stringify(view, { lineWidth: 0 })
  }, [obj, showManaged])
  return (
    <QueryBody query={describe} lines={12} errorFallback="The agent could not describe this object.">
      {(res) => {
        if (!res.result?.object) return <p className="empty-state">The agent returned no object — it may have been deleted.</p>
        const redacted = countRedacted(text)
        return (
          <div className="insight-stack">
            <div className="insight-controls">
              <CopyButton text={text} label="Copy YAML" />
              <label className="checkbox-row">
                <input type="checkbox" checked={wrap} onChange={(e) => setWrap(e.target.checked)} /> Wrap long lines
              </label>
              {hasManaged && (
                <label className="checkbox-row">
                  <input type="checkbox" checked={showManaged} onChange={(e) => setShowManaged(e.target.checked)} /> Show managedFields
                </label>
              )}
            </div>
            {redacted > 0 && (
              <p className="insight-note">
                <span className="redacted-marker">‹redacted›</span> marks {redacted} value{redacted === 1 ? '' : 's'} the cluster agent removed at capture time,
                before anything left the cluster. ARGUS never received {redacted === 1 ? 'it' : 'them'}, so {redacted === 1 ? 'it' : 'they'} cannot be shown here.
              </p>
            )}
            <CodeLines lines={text.replace(/\n$/, '').split('\n')} wrap={wrap} label={`${target.kind} ${target.name} as YAML`} />
            <InsightFooter at={res.receivedAt} cluster={cluster} command={reproducerFor('describe_resource', describeArgs(target))} />
          </div>
        )
      }}
    </QueryBody>
  )
}

// ---------------------------------------------------------------- Events

export function EventsTab({ target, cluster }: TabProps) {
  const args = { namespace: target.namespace ?? '', involvedObjectKind: target.kind, involvedObjectName: target.name }
  const q = useInspect<EventResult[] | null>(target.clusterId, 'get_events', args)
  return (
    <QueryBody query={q} lines={5} errorFallback="The agent could not read events for this object.">
      {(res) => {
        const events = [...(res.result ?? [])].sort((a, b) => Date.parse(b.lastTimestamp ?? '') - Date.parse(a.lastTimestamp ?? ''))
        return (
          <div className="insight-stack">
            {events.length === 0 ? (
              <p className="empty-state">
                No events for this object. Kubernetes keeps events for about an hour by default, so an empty list does not mean nothing ever happened.
              </p>
            ) : (
              <div className="table-scroll">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th scope="col">Type</th>
                      <th scope="col">Reason</th>
                      <th scope="col">Message</th>
                      <th scope="col" className="col-numeric">Count</th>
                      <th scope="col">Last seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {events.map((e, i) => (
                      <tr key={i}>
                        <td>
                          <span className={`badge ${e.type === 'Warning' ? 'badge-amber' : 'badge-gray'}`}>{e.type || 'Unknown'}</span>
                        </td>
                        <td>{e.reason || '—'}</td>
                        <td className="insight-wrap">{e.message || '—'}</td>
                        <td className="col-numeric">
                          <Quantity value={e.count} />
                        </td>
                        <td>
                          {e.lastTimestamp ? <span title={formatDateTime(e.lastTimestamp)}>{formatRelativeTime(e.lastTimestamp)}</span> : '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <InsightFooter at={res.receivedAt} cluster={cluster} command={reproducerFor('get_events', args)} />
          </div>
        )
      }}
    </QueryBody>
  )
}

// ---------------------------------------------------------------- Changes

export function ChangesTab({ target, cluster, open }: TabProps) {
  const { accessToken } = useAuth()
  const q = useQuery({
    queryKey: ['resource-changes', target.clusterId, target.namespace ?? '', target.kind, target.name],
    queryFn: () => getResourceChanges(target.clusterId, { namespace: target.namespace, kind: target.kind, name: target.name }, accessToken!),
    enabled: !!accessToken,
    staleTime: 30_000,
    retry: false,
  })
  return (
    <QueryBody query={q} lines={5} errorFallback="The change history could not be read.">
      {(data) => (
        <div className="insight-stack">
          <ChangeList
            changes={data.changes}
            gaps={data.gaps}
            truncated={data.truncated}
            clusterId={target.clusterId}
            onOpen={open}
            emptyText="No recorded change to this object in the retained history"
          />
          <div className="insight-footer">
            <Freshness at={q.dataUpdatedAt ? new Date(q.dataUpdatedAt) : null} stale={cluster.stale} staleReason={cluster.staleReason} />
            <p className="field-hint">
              Recorded by the agent as changes happen.{' '}
              <HelpTip
                label="what is recorded"
                text="Spec and metadata edits, and the status transitions that matter — replica counts, conditions, health and sync. Routine status churn (heartbeats, timestamps) is not kept."
              />
            </p>
          </div>
        </div>
      )}
    </QueryBody>
  )
}

// ---------------------------------------------------------------- Related

export function RelatedTab({ target, cluster, open }: TabProps) {
  const args = neighborhoodArgs(target)
  const q = useInspect<NeighborhoodResult>(target.clusterId, 'get_neighborhood', args)
  const graph = useMemo(() => (q.data ? neighborhoodGraph(q.data.result) : null), [q.data])
  const openNode = (n: GraphNode) => {
    if (n.kind === 'PodGroup') return
    open({ clusterId: target.clusterId, kind: n.kind, apiGroup: n.apiGroup || undefined, namespace: n.namespace, name: n.name })
  }
  return (
    <QueryBody query={q} lines={8} errorFallback="The agent could not read this object's relationships.">
      {(res) => {
        const r = res.result
        const partial = graphPartialNote(r)
        const others = (graph?.nodes ?? []).filter((n) => n.id !== graph?.rootId)
        return (
          <div className="insight-stack">
            {partial && <p className="insight-note">{partial}</p>}
            {r.unmapped && others.length === 0 ? (
              <p className="empty-state">{r.note || `Relationships for ${target.kind} are not mapped yet.`} The YAML tab shows the references it carries.</p>
            ) : others.length === 0 ? (
              <p className="empty-state">No related objects were found one step from this object{partial ? ' among the kinds the agent could read' : ''}.</p>
            ) : (
              <>
                <GraphCanvas
                  nodes={graph!.nodes}
                  edges={graph!.edges}
                  focusId={graph!.rootId}
                  focusTag="this object"
                  onOpen={openNode}
                  label={`Objects related to ${target.kind} ${target.name}`}
                  height="auto"
                  direction="DOWN"
                />
                <ul className="insight-plain-list">
                  {others.map((n) => (
                    <li key={n.id}>
                      {n.kind === 'PodGroup' ? (
                        <span>
                          {n.kind} {n.name}
                        </span>
                      ) : (
                        <button type="button" className="link-button insight-inline-link" onClick={() => openNode(n)}>
                          {n.kind} {n.namespace ? `${n.namespace}/` : ''}
                          {n.name}
                        </button>
                      )}{' '}
                      <span className="field-hint">
                        {n.status === 'neutral' ? '' : n.status === 'unknown' ? 'health unknown' : n.status}
                        {n.statusReason ? ` · ${n.statusReason}` : ''}
                      </span>
                    </li>
                  ))}
                </ul>
              </>
            )}
            <InsightFooter at={r.observedAt ?? res.receivedAt} cluster={cluster} coverage={r.coverage} command={reproducerFor('get_neighborhood', args)} />
          </div>
        )
      }}
    </QueryBody>
  )
}
