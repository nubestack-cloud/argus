import { Fragment } from 'react'
import { HelpTip } from '../../components/HelpTip'
import { Quantity } from '../../components/Quantity'
import { SkeletonLines } from '../../components/Skeleton'
import { formatDateTime, formatRelativeTime } from '../../utils/time'
import { parseGvk } from '../kinds'
import { conditionsOf, containersOf, HELM_RELEASE_ANNOTATION, podPhase, replicasOf, serviceAccountOf, statusCount, type ContainerFact } from '../model'
import type { ObjectRef } from '../panelUrl'
import {
  connectedObjects,
  endpointCounts,
  HEALTH_TONE,
  ingressFacts,
  NODE_STATUS_WORD,
  replicaBar,
  serviceFacts,
  sortedConditions,
  workloadPods,
  type ObjectHealth,
  type PodRow,
  type ReplicaBar,
} from '../summaryModel'
import type { DescribeResult, KubeObject, NeighborhoodResult } from '../types'
import { errorText, useInspect } from '../useInspect'

// The object panel's Summary (owner review 2026-10-10, PROJECT.md UX1): status
// first, then the few views that answer "is it healthy and why not", then
// previews that open the deeper tabs, then the plain facts. Every view here
// reads the one describe_resource result, except Pods and Connected, which
// read the same get_neighborhood call the Related tab makes (identical args,
// so one request serves both).

const TONE_BADGE: Record<string, string> = {
  green: 'badge badge-green',
  orange: 'badge badge-orange',
  red: 'badge badge-red',
  blue: 'badge badge-blue',
  amber: 'badge badge-amber',
  gray: 'badge badge-gray',
}

export function StatusBanner({ health }: { health: ObjectHealth }) {
  const tone = HEALTH_TONE[health.word]
  return (
    <div className="status-banner" data-tone={tone}>
      <span className={TONE_BADGE[tone]}>{health.word}</span>
      <span className="status-banner-reason">{health.reason}</span>
    </div>
  )
}

export function ReplicaBarView({ bar }: { bar: ReplicaBar }) {
  const label =
    bar.existing === bar.desired
      ? `${bar.ready} of ${bar.desired} replicas ready${bar.notReady ? `, ${bar.notReady} not ready` : ''}`
      : `${bar.existing} replicas exist for ${bar.desired} desired: ${bar.ready} ready, ${bar.notReady} not ready`
  return (
    <>
      <div className="replica-bar" role="img" aria-label={label}>
        {bar.ready > 0 && (
          <span className="replica-bar-seg" data-tone="ok" style={{ flexGrow: bar.ready }}>
            {bar.ready} ready
          </span>
        )}
        {bar.notReady > 0 && (
          <span className="replica-bar-seg" data-tone="warn" style={{ flexGrow: bar.notReady }}>
            {bar.notReady} not ready
          </span>
        )}
      </div>
      <p className="field-hint">{bar.detail}</p>
    </>
  )
}

export function ConditionChecklist({ obj }: { obj: KubeObject }) {
  const conditions = sortedConditions(conditionsOf(obj))
  return (
    <ul className="check-list">
      {conditions.map((c) => (
        <li key={c.type} className="check-list-item" data-verdict={c.verdict}>
          <span className="check-list-mark" aria-hidden="true">{{ failing: '✕', unknown: '?', ok: '✓' }[c.verdict]}</span>
          <span className="check-list-body">
            <span>
              <strong>{c.type}</strong> <span className="check-list-state">is {c.status}</span>
              {c.reason ? <span className="text-muted"> · {c.reason}</span> : null}
            </span>
            {c.message ? <span className="check-list-message">{c.message}</span> : null}
          </span>
        </li>
      ))}
    </ul>
  )
}

function reqLimit(c: ContainerFact, key: 'cpu' | 'memory') {
  const req = c.requests[key]
  const lim = c.limits[key]
  return (
    <span title={`request ${req ?? 'not set'} · limit ${lim ?? 'not set'}`}>
      {req ?? <span className="text-muted">none</span>} / {lim ?? <span className="text-muted">none</span>}
    </span>
  )
}

export function ContainersTable({ obj, isPod }: { obj: KubeObject; isPod: boolean }) {
  const containers = containersOf(obj)
  if (containers.length === 0) return null
  return (
    <section className="card card-compact" aria-label="Containers">
      <div className="card-head">
        <h3>Containers</h3>
        <span className="card-head-meta">{containers.length}</span>
      </div>
      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Image</th>
              <th scope="col" className="col-numeric">CPU request / limit</th>
              <th scope="col" className="col-numeric">Memory request / limit</th>
              {isPod && (
                <>
                  <th scope="col">Ready</th>
                  <th scope="col" className="col-numeric">Restarts</th>
                  <th scope="col">State</th>
                </>
              )}
            </tr>
          </thead>
          <tbody>
            {containers.map((c) => (
              <tr key={`${c.init}-${c.name}`}>
                <td>
                  {c.name}
                  {c.init ? <span className="field-hint"> (init)</span> : null}
                </td>
                <td className="insight-mono insight-wrap">{c.image || '—'}</td>
                <td className="col-numeric">{reqLimit(c, 'cpu')}</td>
                <td className="col-numeric">{reqLimit(c, 'memory')}</td>
                {isPod && (
                  <>
                    <td>{c.ready === undefined ? '—' : c.ready ? 'Ready' : 'Not ready'}</td>
                    <td className="col-numeric">
                      <Quantity value={c.restartCount} />
                    </td>
                    <td>{c.state ?? '—'}</td>
                  </>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}

const POD_TONE: Record<PodRow['status'], string> = {
  healthy: 'ok',
  degraded: 'warn',
  unhealthy: 'bad',
  neutral: 'neutral',
  unknown: 'neutral',
}

interface NeighborhoodQuery {
  data?: { result: NeighborhoodResult; receivedAt: string }
  isLoading: boolean
  isError: boolean
  error: unknown
}

export function PodsCard({
  query,
  onOpen,
}: {
  query: NeighborhoodQuery
  onOpen: (name: string) => void
}) {
  const pods = workloadPods(query.data?.result)
  return (
    <section className="card card-compact" aria-label="Pods">
      <div className="card-head">
        <h3>Pods</h3>
        {query.data && <span className="card-head-meta">{pods.total}</span>}
      </div>
      {query.isLoading ? (
        <div aria-busy="true" aria-label="Loading pods">
          <SkeletonLines count={2} />
        </div>
      ) : query.isError ? (
        <p className="form-error" role="alert">
          {errorText(query.error, 'The agent could not list this workload’s pods.')}
        </p>
      ) : pods.total === 0 ? (
        <p className="empty-state">No pods are running for this workload.</p>
      ) : (
        <>
          <ul className="preview-list">
            {pods.rows.map((p) => (
              <li key={p.name} className="preview-row preview-row-stacked">
                <span className="preview-dot" data-tone={POD_TONE[p.status]} aria-hidden="true" />
                <button type="button" className="link-button preview-name insight-mono" onClick={() => onOpen(p.name)} title={p.name}>
                  {p.name}
                </button>
                <span className="preview-context">
                  {[p.phase, p.restarts !== undefined ? `${p.restarts} restart${p.restarts === 1 ? '' : 's'}` : null, p.node]
                    .filter(Boolean)
                    .join(' · ') || (p.grouped ? 'details in Related' : '—')}
                </span>
                <span className="preview-status">
                  {NODE_STATUS_WORD[p.status]}
                  {p.reason ? ` · ${p.reason}` : ''}
                </span>
              </li>
            ))}
          </ul>
          {pods.total > pods.rows.length && (
            <p className="field-hint">
              Showing {pods.rows.length} of {pods.total} pods — the agent lists the worst first and counts the rest.
            </p>
          )}
        </>
      )}
    </section>
  )
}

export function ConnectedCard({
  query,
  onOpen,
  onOpenRelated,
}: {
  query: NeighborhoodQuery
  onOpen: (n: { kind: string; apiGroup?: string; namespace?: string; name: string }) => void
  onOpenRelated: () => void
}) {
  const nodes = connectedObjects(query.data?.result)
  const shown = nodes.slice(0, 6)
  return (
    <section className="card card-compact" aria-label="Connected objects">
      <div className="card-head">
        <h3>Connected</h3>
        <HelpTip
          label="Connected"
          text="Objects one step from this one — what owns it, what it owns, the Services and policies that select it, and what it mounts — as the agent's live relationship index reports them."
        />
        <button type="button" className="link-button card-head-meta" onClick={onOpenRelated}>
          Open Related →
        </button>
      </div>
      {query.isLoading ? (
        <div aria-busy="true" aria-label="Loading connected objects">
          <SkeletonLines count={1} />
        </div>
      ) : query.isError ? (
        // A preview, not the answer: a failed relationship read must not put
        // a red error at the top of every Summary (most often it is a kind the
        // agent cannot map). The reason is one click away on Related.
        <p className="empty-state">Relationships could not be read for this object — Related has the agent’s reason.</p>
      ) : query.data?.result?.unmapped && nodes.length === 0 ? (
        <p className="empty-state">{query.data.result.note || 'Relationships for this kind are not mapped yet.'}</p>
      ) : nodes.length === 0 ? (
        <p className="empty-state">Nothing is connected one step from this object.</p>
      ) : (
        <>
          <ul className="connected-chips">
            {shown.map((n) => (
              <li key={n.id}>
                <button type="button" className="connected-chip" data-tone={POD_TONE[n.status]} onClick={() => onOpen(n)}>
                  <span className="text-muted">{n.kind}</span>
                  <span className="insight-mono">{n.name}</span>
                  <span className="visually-hidden">, {NODE_STATUS_WORD[n.status]}</span>
                </button>
              </li>
            ))}
          </ul>
          {nodes.length > shown.length && <p className="field-hint">+{nodes.length - shown.length} more in Related</p>}
        </>
      )}
    </section>
  )
}

/** The plain facts line under the previews: node, service account, owners,
 *  Helm release, age, then the labels in a disclosure. */
export function ObjectFacts({
  obj,
  target,
  open,
}: {
  obj: KubeObject
  target: ObjectRef
  open: (r: ObjectRef) => void
}) {
  const meta = obj.metadata ?? {}
  const labels = Object.entries(meta.labels ?? {})
  const owners = meta.ownerReferences ?? []
  const sa = serviceAccountOf(obj)
  const helm = meta.annotations?.[HELM_RELEASE_ANNOTATION]
  const nodeName = typeof obj.spec?.nodeName === 'string' ? obj.spec.nodeName : undefined
  const phase = podPhase(obj)
  // The replica bar is drawn only when the ready count is known; when it is
  // not, the counts still appear here, unknown ones as "—".
  const replicas = replicaBar(obj) ? null : replicasOf(obj)
  return (
    <>
      <dl className="object-facts">
        {phase && (
          <div>
            <dt>Phase</dt>
            <dd>{phase}</dd>
          </div>
        )}
        {replicas && (
          <div>
            <dt>Replicas</dt>
            <dd>
              <Quantity value={statusCount(obj, replicas.ready)} /> ready of <Quantity value={replicas.desired} /> desired ·{' '}
              <Quantity value={statusCount(obj, replicas.updated)} /> updated · <Quantity value={statusCount(obj, replicas.available)} /> available
            </dd>
          </div>
        )}
        {nodeName && (
          <div>
            <dt>Node</dt>
            <dd>
              <button type="button" className="link-button insight-inline-link" onClick={() => open({ clusterId: target.clusterId, kind: 'Node', name: nodeName })}>
                {nodeName}
              </button>
            </dd>
          </div>
        )}
        {sa && target.kind !== 'ServiceAccount' && (
          <div>
            <dt>Service account</dt>
            <dd>
              <button
                type="button"
                className="link-button insight-inline-link"
                onClick={() => open({ clusterId: target.clusterId, kind: 'ServiceAccount', namespace: target.namespace, name: sa })}
              >
                {sa}
              </button>
            </dd>
          </div>
        )}
        {owners.length > 0 && (
          <div>
            <dt>Owned by</dt>
            <dd>
              {owners.map((o, i) => {
                const gv = parseGvk(`${o.apiVersion ?? 'v1'}/${o.kind ?? ''}`)
                return (
                  <button
                    key={i}
                    type="button"
                    className="link-button insight-inline-link"
                    onClick={() => open({ clusterId: target.clusterId, kind: o.kind ?? '', apiGroup: gv.group, namespace: target.namespace, name: o.name ?? '' })}
                  >
                    {o.kind} {o.name}
                  </button>
                )
              })}
            </dd>
          </div>
        )}
        {helm && (
          <div>
            <dt>Helm release</dt>
            <dd>
              <code>{helm}</code> <span className="field-hint">— revision and status on the Helm tab</span>
            </dd>
          </div>
        )}
        <div>
          <dt>Created</dt>
          <dd>
            {meta.creationTimestamp ? (
              <span title={formatDateTime(meta.creationTimestamp)}>{formatRelativeTime(meta.creationTimestamp)}</span>
            ) : (
              '—'
            )}
          </dd>
        </div>
      </dl>
      <details className="object-labels">
        <summary>Labels · {labels.length}</summary>
        {labels.length > 0 ? (
          <dl className="kv-list insight-mono">
            {labels.map(([k, v]) => (
              <Fragment key={k}>
                <dt>{k}</dt>
                <dd>{v}</dd>
              </Fragment>
            ))}
          </dl>
        ) : (
          <p className="empty-state">No labels.</p>
        )}
      </details>
    </>
  )
}

type OpenRef = (r: ObjectRef) => void

/** An Ingress's routing table: which host and path go to which Service and
 *  port, and whether TLS covers the host — from the Ingress's own spec. */
export function IngressRoutesCard({ obj, target, open }: { obj: KubeObject; target: ObjectRef; open: OpenRef }) {
  const f = ingressFacts(obj)
  if (!f) return null
  const openSvc = (name: string) => open({ clusterId: target.clusterId, kind: 'Service', namespace: target.namespace, name })
  return (
    <section className="card card-compact" aria-label="Routing">
      <div className="card-head">
        <h3>Routing</h3>
        <span className="card-head-meta">
          {f.className ? `class ${f.className}` : 'no ingress class set'}
          {f.addresses.length > 0 ? ` · address ${f.addresses.join(', ')}` : ' · no address assigned yet'}
        </span>
      </div>
      {f.routes.length === 0 ? (
        <p className="empty-state">
          This Ingress defines no rules
          {f.defaultBackend?.service ? `; every request goes to its default backend, Service ${f.defaultBackend.service}${f.defaultBackend.port ? `:${f.defaultBackend.port}` : ''}.` : '.'}
        </p>
      ) : (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">Host</th>
                <th scope="col">Path</th>
                <th scope="col">Backend</th>
                <th scope="col">TLS</th>
              </tr>
            </thead>
            <tbody>
              {f.routes.map((r, i) => (
                <tr key={i}>
                  <td className="insight-mono insight-wrap">{r.host}</td>
                  <td className="insight-mono insight-wrap">
                    {r.path}
                    {r.pathType ? <span className="field-hint"> ({r.pathType})</span> : null}
                  </td>
                  <td className="insight-wrap">
                    {r.service ? (
                      <button type="button" className="link-button insight-inline-link insight-mono" onClick={() => openSvc(r.service!)}>
                        {r.service}
                        {r.port ? `:${r.port}` : ''}
                      </button>
                    ) : (
                      (r.resource ?? <span className="text-muted">no backend</span>)
                    )}
                  </td>
                  <td>{r.tls ? <>Yes{r.tlsSecret ? <span className="field-hint"> · secret {r.tlsSecret}</span> : null}</> : 'No'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {f.routes.length > 0 && f.defaultBackend?.service && (
        <p className="field-hint">
          Anything no rule matches goes to Service {f.defaultBackend.service}
          {f.defaultBackend.port ? `:${f.defaultBackend.port}` : ''}.
        </p>
      )}
    </section>
  )
}

/** A Service's type, ports, selector and how many endpoints are ready — the
 *  last from the Endpoints object the endpoint controller keeps, read once
 *  when the card shows. */
export function ServiceCard({ obj, target }: { obj: KubeObject; target: ObjectRef }) {
  const f = serviceFacts(obj)
  const endpoints = useInspect<DescribeResult>(
    target.clusterId,
    'describe_resource',
    { gvk: 'v1/Endpoints', namespace: target.namespace ?? '', name: target.name },
    !!f && f.type !== 'ExternalName',
  )
  if (!f) return null
  const counts = endpointCounts(endpoints.data?.result?.object)
  return (
    <section className="card card-compact" aria-label="Service">
      <div className="card-head">
        <h3>Service</h3>
        <span className="card-head-meta">{f.type}</span>
      </div>
      <dl className="kv-list">
        {f.type === 'ExternalName' ? (
          <>
            <dt>External name</dt>
            <dd className="insight-mono">{f.externalName ?? '—'}</dd>
          </>
        ) : (
          <>
            <dt>Cluster IP</dt>
            <dd className="insight-mono">{f.clusterIP ?? '—'}</dd>
          </>
        )}
        {f.addresses.length > 0 && (
          <>
            <dt>External address</dt>
            <dd className="insight-mono">{f.addresses.join(', ')}</dd>
          </>
        )}
        <dt>Ports</dt>
        <dd className="insight-mono">
          {f.ports.length === 0
            ? '—'
            : f.ports
                .map(
                  (p) =>
                    `${p.name ? `${p.name} ` : ''}${p.port ?? '?'}${p.targetPort && p.targetPort !== String(p.port) ? `→${p.targetPort}` : ''}/${p.protocol}${p.nodePort ? ` (node ${p.nodePort})` : ''}`,
                )
                .join(', ')}
        </dd>
        <dt>Selector</dt>
        <dd className="insight-mono">
          {f.selector ? f.selector.map(([k, v]) => `${k}=${v}`).join(', ') : <span className="text-muted">none — its endpoints are not chosen by labels</span>}
        </dd>
        {f.type !== 'ExternalName' && (
          <>
            <dt>Endpoints</dt>
            <dd>
              {endpoints.isLoading ? (
                <span className="text-muted">Loading…</span>
              ) : endpoints.isError ? (
                <span className="text-muted" title={errorText(endpoints.error, '')}>
                  — the agent could not read this Service’s Endpoints
                </span>
              ) : counts ? (
                <>
                  <Quantity value={counts.ready} /> ready
                  {counts.notReady > 0 ? (
                    <>
                      , <Quantity value={counts.notReady} /> not ready
                    </>
                  ) : null}
                  {counts.ready === 0 ? <span className="text-muted"> — traffic to this Service has nowhere to go</span> : null}
                </>
              ) : (
                '—'
              )}
            </dd>
          </>
        )}
      </dl>
    </section>
  )
}
