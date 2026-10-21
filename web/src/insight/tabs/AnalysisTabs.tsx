import { reproducerFor } from '../../evidence/reproducer'
import { Fragment } from 'react'
import { Quantity } from '../../components/Quantity'
import { SplitBar } from '../../components/SplitBar'
import { InsightFooter, QueryBody } from '../InsightParts'
import { defaultGroupFor } from '../kinds'
import { HELM_NAMESPACE_ANNOTATION, HELM_RELEASE_ANNOTATION, serviceAccountOf } from '../model'
import { HelmHistoryTable } from '../views/HelmHistory'
import type {
  AutoscalerResult,
  GitOpsInsightResult,
  HelmStatusResult,
  PermissionsResult,
  PolicyResult,
  RolloutResult,
  SchedulingResult,
} from '../types'
import { useInspect } from '../useInspect'
import { GitOpsInsightView } from '../views/GitOpsInsightView'
import { PermissionsView } from '../views/PermissionsView'
import { SchedulingView } from '../views/SchedulingView'
import type { TabProps } from './common'

// ---------------------------------------------------------------- Permissions

export function PermissionsTab({ target, cluster, describe, open }: TabProps) {
  const isSA = target.kind === 'ServiceAccount'
  const sa = isSA ? target.name : serviceAccountOf(describe.data?.result?.object)
  const args = { kind: 'ServiceAccount', namespace: target.namespace ?? '', name: sa ?? '' }
  const q = useInspect<PermissionsResult>(target.clusterId, 'get_subject_permissions', args, !!sa)
  if (!isSA && !sa) {
    return (
      <QueryBody query={describe} errorFallback="The agent could not describe this object, so its service account is unknown.">
        {() => <p className="empty-state">This object names no service account.</p>}
      </QueryBody>
    )
  }
  return (
    <div className="insight-stack">
      {!isSA && (
        <p className="insight-lead">
          Runs as service account{' '}
          <button
            type="button"
            className="link-button insight-inline-link"
            onClick={() => open({ clusterId: target.clusterId, kind: 'ServiceAccount', namespace: target.namespace, name: sa! })}
          >
            {sa}
          </button>
          . What that identity may do:
        </p>
      )}
      <QueryBody query={q} lines={8} errorFallback="The agent could not compute these permissions.">
        {(res) => (
          <>
            <PermissionsView result={res.result} />
            <InsightFooter at={res.result.observedAt ?? res.receivedAt} cluster={cluster} coverage={res.result.coverage} command={reproducerFor('get_subject_permissions', args)} />
          </>
        )}
      </QueryBody>
    </div>
  )
}

// ---------------------------------------------------------------- Policy

const RESULT_TONE: Record<string, string> = { fail: 'badge-red', error: 'badge-red', warn: 'badge-amber', pass: 'badge-green', skip: 'badge-gray' }

export function PolicyTab({ target, cluster }: TabProps) {
  const args = { group: target.apiGroup ?? defaultGroupFor(target.kind) ?? '', kind: target.kind, namespace: target.namespace ?? '', name: target.name }
  const q = useInspect<PolicyResult>(target.clusterId, 'get_policy_findings', args)
  return (
    <QueryBody query={q} lines={5} errorFallback="The agent could not read policy reports.">
      {(res) => {
        const findings = res.result.findings ?? []
        const incomplete = (res.result.coverage ?? []).length > 0
        return (
          <div className="insight-stack">
            {findings.length === 0 ? (
              <p className="empty-state">
                {incomplete
                  ? 'No policy report names this object — but no policy engine reports were readable, so this is not a clean result.'
                  : 'No policy report names this object.'}
              </p>
            ) : (
              <div className="table-scroll">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th scope="col">Result</th>
                      <th scope="col">Policy / rule</th>
                      <th scope="col">Severity</th>
                      <th scope="col">Message</th>
                    </tr>
                  </thead>
                  <tbody>
                    {findings.map((f, i) => (
                      <tr key={i}>
                        <td>
                          <span className={`badge ${RESULT_TONE[(f.result ?? '').toLowerCase()] ?? 'badge-gray'}`}>{f.result || 'unknown'}</span>
                        </td>
                        <td className="insight-mono insight-wrap">
                          {f.policy || '—'}
                          {f.rule ? ` / ${f.rule}` : ''}
                          {f.source ? <span className="field-hint"> ({f.source})</span> : null}
                        </td>
                        <td>{f.severity || '—'}</td>
                        <td className="insight-wrap">{f.message || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <InsightFooter
              at={res.result.observedAt ?? res.receivedAt}
              cluster={cluster}
              coverage={res.result.coverage}
              truncated={res.result.truncated}
              command={reproducerFor('get_policy_findings', args)}
            />
          </div>
        )
      }}
    </QueryBody>
  )
}

// ---------------------------------------------------------------- GitOps

export function GitOpsTab({ target, cluster }: TabProps) {
  const args = { group: target.apiGroup ?? defaultGroupFor(target.kind) ?? '', kind: target.kind, namespace: target.namespace ?? '', name: target.name }
  const q = useInspect<GitOpsInsightResult>(target.clusterId, 'get_gitops_insight', args)
  return (
    <QueryBody query={q} lines={8} errorFallback="The agent could not read GitOps state for this object.">
      {(res) => (
        <div className="insight-stack">
          <GitOpsInsightView result={res.result} />
          <InsightFooter
            at={res.result.observedAt ?? res.receivedAt}
            cluster={cluster}
            coverage={res.result.coverage}
            truncated={res.result.truncated}
            command={reproducerFor('get_gitops_insight', args)}
          />
        </div>
      )}
    </QueryBody>
  )
}

// ---------------------------------------------------------------- Helm

export function HelmTab({ target, cluster, describe }: TabProps) {
  const annotations = describe.data?.result?.object?.metadata?.annotations ?? {}
  const release = annotations[HELM_RELEASE_ANNOTATION] ?? ''
  const args = { namespace: annotations[HELM_NAMESPACE_ANNOTATION] || target.namespace || '', name: release }
  const q = useInspect<HelmStatusResult>(target.clusterId, 'get_helm_release_status', args, !!release)
  if (!release) return <p className="empty-state">This object carries no Helm release annotation.</p>
  return (
    <QueryBody query={q} lines={6} errorFallback="The agent could not read this Helm release.">
      {(res) => {
        const r = res.result
        const history = [...(r.history ?? [])].sort((a, b) => b.revision - a.revision)
        const latest = history[0]
        const op = r.analysis?.lastOperation
        return (
          <div className="insight-stack">
            <p className="insight-lead">
              Release <code>{r.release || release}</code>
              {typeof r.latestRevision === 'number' ? `, revision ${r.latestRevision}` : ''}
              {latest ? `, status ${latest.status}` : ', status not reported'}.
            </p>
            {op?.message && (
              <p className={op.status === 'recovered' ? 'field-hint' : 'insight-note'}>
                <span className={`badge ${op.status === 'recovered' ? 'badge-gray' : 'badge-amber'}`}>{(op.status ?? 'note').replace(/_/g, ' ')}</span> {op.message}
              </p>
            )}
            {!!r.hookJobs?.length && (
              <div>
                <p className="field-hint">
                  Lifecycle hook Jobs (inferred — matched by namespace and app.kubernetes.io/instance, not an ownership proof)
                </p>
                <ul className="inventory-object-list">
                  {r.hookJobs.map((h) => (
                    <li key={`${h.namespace}/${h.name}`} className="fleet-mono">
                      {h.name} — {h.hook}, {h.phase.toLowerCase()}
                      {(h.reason || h.message) && <span className="text-muted">: {[h.reason, h.message].filter(Boolean).join(' — ')}</span>}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {history.length > 0 ? (
              <HelmHistoryTable history={history} />
            ) : (
              <p className="empty-state">No revision history was readable for this release.</p>
            )}
            {r.note && <p className="field-hint">{r.note}</p>}
            <InsightFooter at={r.observedAt ?? res.receivedAt} cluster={cluster} coverage={r.coverage} command={reproducerFor('get_helm_release_status', args)} />
          </div>
        )
      }}
    </QueryBody>
  )
}

// ---------------------------------------------------------------- Autoscaler

const HPA_STATE_WORD: Record<string, string> = {
  ok: 'Scaling normally',
  scaling_up: 'Scaling up',
  scaling_down: 'Scaling down',
  limited_max: 'Held at maximum',
  limited_min: 'Held at minimum',
  metrics_unavailable: 'Metrics unavailable',
  metrics_incomplete: 'Metrics incomplete',
  unable_to_scale: 'Unable to scale',
  scaled_to_zero: 'Scaled to zero',
  disabled: 'Scaling disabled',
  pinned: 'Pinned (min = max)',
  stale: 'Status is stale',
  stabilized: 'Stabilising',
  unknown: 'Unknown',
}

export function AutoscalerTab({ target, cluster }: TabProps) {
  const args = { namespace: target.namespace ?? '', name: target.name }
  const q = useInspect<AutoscalerResult>(target.clusterId, 'diagnose_autoscaler', args)
  return (
    <QueryBody query={q} lines={6} errorFallback="The agent could not diagnose this autoscaler.">
      {(res) => {
        const d = res.result.diagnosis
        if (!d) return <p className="empty-state">The agent returned no diagnosis for this autoscaler.</p>
        return (
          <div className="insight-stack">
            <p className="insight-lead">
              <span className="badge badge-gray">{HPA_STATE_WORD[d.state ?? 'unknown'] ?? d.state}</span> {d.summary}
            </p>
            <dl className="kv-list">
              <dt>Target</dt>
              <dd>{d.target?.kind && d.target.name ? `${d.target.kind} ${d.target.name}` : '—'}</dd>
              <dt>Replicas</dt>
              <dd>
                <Quantity value={d.bounds?.current} /> current → <Quantity value={d.bounds?.desired} /> desired (min <Quantity value={d.bounds?.min} />, max{' '}
                <Quantity value={d.bounds?.max} />)
              </dd>
            </dl>
            {d.metrics && d.metrics.length > 0 && (
              <div className="table-scroll">
                <table className="data-table">
                  <caption className="insight-caption">Metrics</caption>
                  <thead>
                    <tr>
                      <th scope="col">Metric</th>
                      <th scope="col">Current</th>
                      <th scope="col">Target</th>
                      <th scope="col">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.metrics.map((m, i) => (
                      <tr key={i}>
                        <td>
                          {m.name || '—'} <span className="field-hint">({m.type})</span>
                        </td>
                        <td>{m.current || '—'}</td>
                        <td>{m.target || '—'}</td>
                        <td>{m.status || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {d.reasons && d.reasons.length > 0 && (
              <ul className="insight-plain-list">
                {d.reasons.map((r, i) => (
                  <li key={i}>
                    {r.message}
                    {r.detail ? <span className="field-hint"> — {r.detail}</span> : null}
                  </li>
                ))}
              </ul>
            )}
            <InsightFooter at={res.result.observedAt ?? res.receivedAt} cluster={cluster} coverage={res.result.coverage} command={reproducerFor('diagnose_autoscaler', args)} />
          </div>
        )
      }}
    </QueryBody>
  )
}

// ---------------------------------------------------------------- Rollout

const ROLLOUT_WORD: Record<string, { label: string; badge: string }> = {
  stuck: { label: 'Stuck', badge: 'badge badge-red' },
  inProgress: { label: 'In progress', badge: 'badge badge-blue' },
  paused: { label: 'Paused', badge: 'badge badge-amber' },
  atRisk: { label: 'At risk', badge: 'badge badge-amber' },
  safe: { label: 'Safe', badge: 'badge badge-green' },
  complete: { label: 'Complete', badge: 'badge badge-green' },
  notApplicable: { label: 'Not applicable', badge: 'badge badge-gray' },
  unknown: { label: 'Unknown', badge: 'badge badge-gray' },
}

// "Is this Deployment's rollout healthy, and would the next one take it
// down?" Live progress leads: a rollout stuck on ProgressDeadlineExceeded is
// the verdict whatever the replica count, with the pods holding it up. The
// availability policy (maxSurge/maxUnavailable against the replica count) is
// the second question, and a one-replica caveat is a note under it.
export function RolloutTab({ target, cluster }: TabProps) {
  const args = { namespace: target.namespace ?? '', name: target.name }
  const q = useInspect<RolloutResult>(target.clusterId, 'diagnose_rollout', args)
  return (
    <QueryBody query={q} lines={5} errorFallback="The agent could not diagnose this rollout.">
      {(res) => {
        const r = res.result
        const word = ROLLOUT_WORD[r.verdict ?? ''] ?? ROLLOUT_WORD.unknown
        const p = r.progress
        const stuckPods = p?.notReadyPods ?? []
        const policy = r.policyVerdict ? (ROLLOUT_WORD[r.policyVerdict] ?? ROLLOUT_WORD.unknown) : null
        // An older agent sends only atRisk/safe/notApplicable with no reason
        // for the first two; say what those mean.
        const fallback =
          r.verdict === 'atRisk'
            ? 'A rollout of this Deployment can take every replica down at once.'
            : r.verdict === 'safe'
              ? 'A rollout keeps at least one replica available.'
              : 'This check could not be completed.'
        return (
          <div className="insight-stack">
            <p className="insight-lead">
              <span className={word.badge}>{word.label}</span> {r.reason || fallback}
            </p>
            {stuckPods.length > 0 && (
              <ul className="insight-plain-list" aria-label="Pods holding the rollout up">
                {stuckPods.map((pod) => (
                  <li key={pod.name}>
                    <span className="insight-mono">{pod.name}</span>{' '}
                    <span className="field-hint">
                      {[pod.phase, pod.waiting, pod.node ? `on ${pod.node}` : null].filter(Boolean).join(' · ')}
                    </span>
                  </li>
                ))}
              </ul>
            )}
            <dl className="kv-list">
              <dt>Strategy</dt>
              <dd>{r.strategy || '—'}</dd>
              <dt>Replicas</dt>
              <dd>
                {p ? (
                  <>
                    <Quantity value={p.desired ?? r.replicas} /> desired · <Quantity value={p.updated} /> updated · <Quantity value={p.ready} /> ready ·{' '}
                    <Quantity value={p.available} /> available
                  </>
                ) : (
                  <Quantity value={r.replicas} />
                )}
              </dd>
              {p?.newReplicaSet && (
                <>
                  <dt>New ReplicaSet</dt>
                  <dd className="insight-mono">{p.newReplicaSet}</dd>
                </>
              )}
              {p?.conditionReason && (
                <>
                  <dt>Progressing</dt>
                  <dd>
                    {p.conditionReason}
                    {p.conditionMessage ? <span className="field-hint"> — {p.conditionMessage}</span> : null}
                  </dd>
                </>
              )}
              {r.risk && (
                <>
                  <dt>maxSurge / maxUnavailable</dt>
                  <dd className="insight-mono">
                    {r.risk.maxSurge ?? '—'} / {r.risk.maxUnavailable ?? '—'}
                  </dd>
                </>
              )}
              {policy && r.policyVerdict !== r.verdict && (
                <>
                  <dt>Next rollout</dt>
                  <dd>
                    <span className={policy.badge}>{policy.label}</span> {r.policyReason}
                  </dd>
                </>
              )}
            </dl>
            {r.risk?.message && <p>{r.risk.message}</p>}
            {r.risk?.remediation && <p className="field-hint">Suggested change: {r.risk.remediation}</p>}
            {(r.notes ?? []).map((n, i) => (
              <p key={i} className="field-hint">
                {n}
              </p>
            ))}
            <InsightFooter at={r.observedAt ?? res.receivedAt} cluster={cluster} coverage={r.coverage} command={reproducerFor('diagnose_rollout', args)} />
          </div>
        )
      }}
    </QueryBody>
  )
}

// ---------------------------------------------------------------- Scheduling

export function SchedulingTab({ target, cluster }: TabProps) {
  const args = { namespace: target.namespace ?? '', pod: target.name }
  const q = useInspect<SchedulingResult>(target.clusterId, 'explain_scheduling', args)
  return (
    <QueryBody query={q} lines={6} errorFallback="The agent could not explain this pod's scheduling.">
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

// ---------------------------------------------------------------- Drain impact

interface DrainImpact {
  observedAt?: string
  coverage?: { group?: string; kind: string; state: string; reason?: string }[]
  truncated?: boolean
  node: string
  unschedulable: boolean
  evicted: number
  workloads: { kind: string; namespace: string; name: string; evicted: number; readyElsewhere: number }[]
  unavailable?: string[]
  pdbs?: { namespace: string; name: string; podsOnNode: number; disruptionsAllowed: number; blocks: boolean }[]
  emptyDirData?: { namespace: string; name: string; emptyDirs?: string[] }[]
  noController?: { namespace: string; name: string }[]
  stays?: string[]
}

/** What draining this node would do (PROJECT.md PG12). Read-only. */
export function DrainTab({ target, cluster }: TabProps) {
  const args = { node: target.name }
  const q = useInspect<DrainImpact>(target.clusterId, 'get_drain_impact', args)
  return (
    <QueryBody query={q} lines={6} errorFallback="The agent could not work out this node's drain impact.">
      {(res) => {
        const r = res.result
        const pods = (w: DrainImpact['workloads'][number]) => w.evicted
        const keeps = r.workloads.filter((w) => w.readyElsewhere > 0).reduce((n, w) => n + pods(w), 0)
        const loses = r.workloads.filter((w) => w.readyElsewhere === 0).reduce((n, w) => n + pods(w), 0)
        const orphans = r.noController?.length ?? 0
        const blocking = (r.pdbs ?? []).filter((p) => p.blocks)
        return (
          <div className="insight-stack">
            <p className="insight-lead">
              {r.unschedulable && <span className="badge badge-amber">Cordoned</span>} Draining evicts <Quantity value={r.evicted} /> pods
              {blocking.length > 0 ? `; ${blocking.length} disruption budget${blocking.length === 1 ? '' : 's'} would hold it` : ''}.
            </p>
            {r.evicted > 0 && (
              <SplitBar
                tall
                label="Evicted pods by what happens to their workload"
                parts={[
                  { tone: 'ok', value: keeps, label: 'workload stays up elsewhere' },
                  { tone: 'critical', value: loses, label: 'workload has no ready replica elsewhere' },
                  { tone: 'high', value: orphans, label: 'no controller, not recreated' },
                ]}
              />
            )}
            {r.workloads.length > 0 && (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Workload</th>
                    <th className="num">Evicted</th>
                    <th className="num">Ready elsewhere</th>
                  </tr>
                </thead>
                <tbody>
                  {r.workloads.map((w) => (
                    <tr key={`${w.namespace}/${w.kind}/${w.name}`}>
                      <td className="insight-mono">
                        {w.kind} {w.namespace}/{w.name}
                      </td>
                      <td className="num">
                        <Quantity value={w.evicted} />
                      </td>
                      <td className="num">
                        {w.readyElsewhere === 0 ? <span className="badge badge-red">None</span> : <Quantity value={w.readyElsewhere} />}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {(r.pdbs ?? []).length > 0 && (
              <dl className="kv-list">
                {(r.pdbs ?? []).map((p) => (
                  <Fragment key={`${p.namespace}/${p.name}`}>
                    <dt className="insight-mono">
                      PDB {p.namespace}/{p.name}
                    </dt>
                    <dd>
                      {p.blocks ? <span className="badge badge-red">Holds the drain</span> : <span className="badge badge-green">Allows</span>}{' '}
                      <Quantity value={p.podsOnNode} /> pods here, <Quantity value={p.disruptionsAllowed} /> disruptions allowed
                    </dd>
                  </Fragment>
                ))}
              </dl>
            )}
            {(r.emptyDirData ?? []).length > 0 && (
              <ul className="insight-plain-list" aria-label="emptyDir data lost">
                {(r.emptyDirData ?? []).map((p) => (
                  <li key={`${p.namespace}/${p.name}`}>
                    <span className="insight-mono">
                      {p.namespace}/{p.name}
                    </span>{' '}
                    <span className="field-hint">loses emptyDir {(p.emptyDirs ?? []).join(', ')}</span>
                  </li>
                ))}
              </ul>
            )}
            {orphans > 0 && (
              <ul className="insight-plain-list" aria-label="Pods with no controller">
                {(r.noController ?? []).map((p) => (
                  <li key={`${p.namespace}/${p.name}`}>
                    <span className="insight-mono">
                      {p.namespace}/{p.name}
                    </span>{' '}
                    <span className="field-hint">no controller — not recreated</span>
                  </li>
                ))}
              </ul>
            )}
            {(r.stays ?? []).length > 0 && (
              <details>
                <summary>{(r.stays ?? []).length} pods stay (DaemonSet and static pods)</summary>
                <ul className="insight-plain-list">
                  {(r.stays ?? []).map((s) => (
                    <li key={s} className="insight-mono">
                      {s}
                    </li>
                  ))}
                </ul>
              </details>
            )}
            <InsightFooter
              at={r.observedAt ?? res.receivedAt}
              cluster={cluster}
              coverage={r.coverage}
              truncated={r.truncated}
              command={reproducerFor('get_drain_impact', args)}
            />
          </div>
        )
      }}
    </QueryBody>
  )
}
