import { Fragment, useId, useMemo, useState } from 'react'
import { HelpTip } from '../components/HelpTip'
import { ChevronIcon } from '../components/icons'
import { SkeletonLines } from '../components/Skeleton'
import { HelmHistoryTable } from '../insight/views/HelmHistory'
import type { HelmStatusResult } from '../insight/types'
import { apiErrorText } from './apiErrorText'
import { Quantity } from '../components/Quantity'
import { formatDateTime, formatRelativeTime } from '../utils/time'
import { FilterChips, SplitBar } from '../components/SplitBar'
import { urlEnum, urlString, useUrlState } from '../hooks/useUrlState'
import type { Incident } from '../api/types'
import { SEVERITY_LABEL } from '../utils/incidents'
import { InspectFrame, type ClusterLiveness } from './InspectFrame'
import {
  HELM_ARGS,
  changedWithin,
  gradedSummary,
  incidentsForRelease,
  healthWord,
  helmStatus,
  isHelmProblem,
  objectKindsText,
  sortReleases,
  type HelmReleaseList,
  type HelmReleaseRow,
} from './helmModel'
import { useInspect } from './useInspect'
import { useOpenObjectTab } from './useOpenObjectTab'

// Cluster detail → Helm (PROJECT.md AD5). Which Helm releases this cluster
// runs and whether any is failed, stuck pending or running unhealthy
// objects. Read-only by design: there is no upgrade, rollback or uninstall
// control here — a change to a release goes through an incident's approved
// plan. Status is Helm's own word from release metadata; a release whose
// metadata could not be read says why instead of showing a status.

/** Rows shown before "Show all": enough for a typical cluster's releases. */
const INITIAL_ROWS = 25

type ReleaseMember = NonNullable<HelmReleaseRow['members']>[number]

/** The release view a row opens (owner QA, 2026-10-11). A release is a set of
 *  objects plus a revision history, so that is what opening one shows — in
 *  place, under its row. Opening one member workload instead (what this used
 *  to do) answered a question about one object and hid the rest of the
 *  release; each member still opens in the inspector from here. */
function ReleaseDetail({ clusterId, r }: { clusterId: string; r: HelmReleaseRow }) {
  const open = useOpenObjectTab()
  const args = useMemo(() => ({ namespace: r.namespace, name: r.name }), [r.namespace, r.name])
  const { query } = useInspect<HelmStatusResult>(clusterId, 'get_helm_release_status', args)
  const members: ReleaseMember[] = r.members ?? []
  const history = query.data?.result?.history ?? []
  const hookJobs = query.data?.result?.hookJobs ?? []
  return (
    <div className="helm-release-detail">
      {hookJobs.length > 0 && (
        <section aria-label={`Lifecycle hook Jobs for release ${r.name}`}>
          <h4 className="fleet-group-heading">
            Lifecycle hook Jobs <span className="text-muted">· {hookJobs.length}</span>
            <HelpTip
              label="Inferred match"
              text="Hook Jobs don't reliably carry this release's own annotations, so these are matched by namespace plus the app.kubernetes.io/instance label — correct for the overwhelming majority of charts, but a label match, not an ownership proof."
            />
          </h4>
          <ul className="inventory-object-list">
            {hookJobs.map((h) => (
              <li key={`${h.namespace}/${h.name}`}>
                <button
                  type="button"
                  className="link-button fleet-mono"
                  title="Open this Job in the inspector"
                  onClick={() => open({ clusterId, kind: 'Job', apiGroup: 'batch', namespace: h.namespace, name: h.name })}
                >
                  Job {h.name}
                </button>
                <span className="text-muted"> — {h.hook}, {h.phase.toLowerCase()}</span>
                {(h.reason || h.message) && <span className="text-muted">: {[h.reason, h.message].filter(Boolean).join(' — ')}</span>}
              </li>
            ))}
          </ul>
        </section>
      )}
      <section aria-label={`Objects in release ${r.name}`}>
        <h4 className="fleet-group-heading">
          Objects in this release <span className="text-muted">· {r.objects}</span>
        </h4>
        {members.length > 0 ? (
          <>
            <ul className="inventory-object-list">
              {members.map((m) => {
                const w = healthWord(m.health)
                return (
                  <li key={`${m.kind}/${m.namespace}/${m.name}`}>
                    <button
                      type="button"
                      className="link-button fleet-mono"
                      title="Open this object in the inspector"
                      onClick={() => open({ clusterId, kind: m.kind, apiGroup: m.apiGroup || undefined, namespace: m.namespace || undefined, name: m.name }, 'helm')}
                    >
                      {m.kind} {m.name}
                    </button>
                    {m.namespace && m.namespace !== r.namespace ? <span className="text-muted"> · {m.namespace}</span> : null}
                    {w ? <span className="text-muted"> — {w.label}</span> : null}
                  </li>
                )
              })}
            </ul>
            {(r.membersTruncated || members.length < r.objects) && (
              <p className="field-hint">
                Showing {members.length} of {r.objects} — the agent lists the least healthy first. Every one carries the release’s annotations.
              </p>
            )}
          </>
        ) : (
          <p className="field-hint">
            {objectKindsText(r) || `${r.objects} object${r.objects === 1 ? '' : 's'}, kinds not reported`}. This agent build does not list them by name
            {r.mainObject ? '; the main one is ' : '.'}
            {r.mainObject && (
              <button
                type="button"
                className="link-button fleet-mono"
                onClick={() =>
                  open(
                    { clusterId, kind: r.mainObject!.kind, apiGroup: r.mainObject!.apiGroup || undefined, namespace: r.mainObject!.namespace || undefined, name: r.mainObject!.name },
                    'helm',
                  )
                }
              >
                {r.mainObject.kind} {r.mainObject.name}
              </button>
            )}
          </p>
        )}
      </section>
      <section aria-label={`Revision history of release ${r.name}`}>
        {query.isLoading ? (
          <div aria-busy="true" aria-label="Loading revision history">
            <SkeletonLines count={3} />
          </div>
        ) : query.isError ? (
          <p className="form-error" role="alert">
            {apiErrorText(query.error, 'The agent could not read this release’s history.')}
          </p>
        ) : history.length > 0 ? (
          <HelmHistoryTable history={history} />
        ) : (
          <p className="empty-state">No revision history was readable for this release.</p>
        )}
      </section>
    </div>
  )
}

function MemberHealth({ r }: { r: HelmReleaseRow }) {
  const c = r.healthCounts ?? {}
  return (
    <div className="helm-objects">
      {r.graded ? (
        <SplitBar
          legend={false}
          label={`${r.name} objects by health`}
          parts={[
            { tone: 'critical', value: c.unhealthy ?? 0, label: 'unhealthy' },
            { tone: 'high', value: c.degraded ?? 0, label: 'degraded' },
            { tone: 'unknown', value: c.unknown ?? 0, label: 'health unknown' },
            { tone: 'ok', value: c.healthy ?? 0, label: 'healthy' },
            { tone: 'neutral', value: c.neutral ?? 0, label: 'idle' },
          ]}
        />
      ) : null}
      <span className="text-muted helm-objects-line" title={objectKindsText(r)}>
        {r.objects} object{r.objects === 1 ? '' : 's'} · {gradedSummary(r)}
      </span>
    </div>
  )
}

function OpenIncidents({ incidents }: { incidents: readonly Incident[] }) {
  if (incidents.length === 0) return <span className="text-muted">—</span>
  const worst = incidents.some((i) => i.severity === 'critical') ? 'critical' : incidents.some((i) => i.severity === 'high') ? 'high' : 'medium'
  return (
    <span className={`severity-cell sev-${worst} helm-incidents`} title={incidents.map((i) => `${SEVERITY_LABEL[i.severity] ?? i.severity}: ${i.objectName}`).join('\n')}>
      <span className="severity-chip" aria-hidden="true" />
      <strong>{incidents.length}</strong>
      <span className="text-muted">{incidents.every((i) => i.severity === worst) ? SEVERITY_LABEL[worst]?.toLowerCase() : `worst ${SEVERITY_LABEL[worst]?.toLowerCase()}`}</span>
    </span>
  )
}

function ReleaseRow({ clusterId, r, incidents }: { clusterId: string; r: HelmReleaseRow; incidents: readonly Incident[] }) {
  const open = useOpenObjectTab()
  const [expanded, setExpanded] = useState(false)
  const detailId = useId()
  const status = helmStatus(r.status)
  const health = healthWord(r.health)
  const problem = isHelmProblem(r)
  const problems = r.problems ?? []
  const hasNotes = !!(r.statusUnavailable || r.lastOperation || problems.length > 0)
  return (
    <Fragment>
      <tr className={incidents.length > 0 || problem ? 'sev-critical' : 'sev-neutral'}>
        <td className="severity-rule">
          <div className="identity-block">
            <button
              type="button"
              className="link-button identity-block-name helm-release-toggle"
              aria-expanded={expanded}
              aria-controls={detailId}
              title={expanded ? 'Hide this release’s objects and history' : 'Show this release’s objects and revision history'}
              onClick={() => setExpanded((v) => !v)}
            >
              <ChevronIcon size={12} direction={expanded ? 'down' : 'right'} />
              {r.name}
            </button>
            <span className="identity-block-kind">{r.namespace}</span>
          </div>
        </td>
        <td className="col-shrink">
          {status ? <span className={status.badge}>{status.label}</span> : <span className="badge badge-gray">Status not read</span>}
          {health && r.health !== 'healthy' && r.health !== 'neutral' && <span className={`${health.badge} helm-health-word`}>{health.label}</span>}
        </td>
        <td className="col-numeric">
          <Quantity value={r.revision ?? null} certainty={r.revisionLowerBound ? 'atLeast' : 'exact'} unknownLabel="not read" />
        </td>
        <td className="col-time">
          {r.updated ? <span title={formatDateTime(r.updated)}>{formatRelativeTime(r.updated)}</span> : <span className="text-muted">—</span>}
        </td>
        <td className="helm-objects-col">
          <MemberHealth r={r} />
        </td>
        <td className="col-shrink">
          <OpenIncidents incidents={incidents} />
        </td>
      </tr>
      {(hasNotes || expanded) && (
        <tr className="inventory-detail-row">
          <td colSpan={6}>
            {r.statusUnavailable && <p className="field-hint">Status not read: {r.statusUnavailable}.</p>}
            {r.lastOperation && (
              <p className="inventory-headline">
                <strong>{(r.lastOperation as { message?: string }).message ?? 'The newest revision did not complete.'}</strong>
              </p>
            )}
            {problems.length > 0 && (
              <ul className="inventory-object-list">
                {problems.map((p) => {
                  const w = healthWord(p.health)
                  return (
                    <li key={`${p.kind}/${p.namespace}/${p.name}`}>
                      <button
                        type="button"
                        className="link-button fleet-mono"
                        title="Open this object in the inspector"
                        onClick={() => open({ clusterId, kind: p.kind, apiGroup: p.apiGroup || undefined, namespace: p.namespace || undefined, name: p.name }, 'helm')}
                      >
                        {p.kind} {p.name}
                      </button>{' '}
                      <span className="text-muted">
                        — {w?.label ?? p.health}
                        {p.reason ? ` (${p.reason})` : ''}
                      </span>
                    </li>
                  )
                })}
              </ul>
            )}
            <div id={detailId} hidden={!expanded}>
              {expanded && <ReleaseDetail clusterId={clusterId} r={r} />}
            </div>
          </td>
        </tr>
      )}
    </Fragment>
  )
}

type HelmFilter = 'all' | 'incident' | 'notDeployed' | 'recent'

const SCHEMA = {
  hf: urlEnum(['all', 'incident', 'notDeployed', 'recent'] as const, 'all'),
  hns: urlString(''),
}

export function HelmPanel({ clusterId, liveness, incidents = [] }: { clusterId: string; liveness: ClusterLiveness; incidents?: readonly Incident[] }) {
  const { query, capabilityResolved, missing } = useInspect<HelmReleaseList>(clusterId, 'list_helm_releases', HELM_ARGS)
  const [showAll, setShowAll] = useState(false)
  const [state, setState] = useUrlState(SCHEMA)
  // Releases behind an open incident first, then Helm's own problems.
  const rows = useMemo(() => {
    const withInc = sortReleases(query.data?.result?.releases ?? []).map((r) => ({ r, inc: incidentsForRelease(r, incidents) }))
    return withInc.sort((a, b) => (b.inc.length > 0 ? 1 : 0) - (a.inc.length > 0 ? 1 : 0))
  }, [query.data, incidents])
  return (
    <section aria-label="Helm releases">
      <InspectFrame
        label="Helm releases"
        help="Releases are found from the meta.helm.sh annotations on objects the agent can see. Revision, status and when it last changed come from the labels on each release’s newest Helm record; Objects counts the annotated objects and grades the workloads among them."
        query={query}
        capabilityResolved={capabilityResolved}
        missing={missing}
        liveness={liveness}
        skeletonColumns={4}
      >
        {(result) => {
          const total = result?.total ?? rows.length
          const unread = rows.filter(({ r }) => !r.status).length
          const counts: Record<HelmFilter, number> = {
            all: rows.length,
            incident: rows.filter((x) => x.inc.length > 0).length,
            notDeployed: rows.filter(({ r }) => r.status && r.status !== 'deployed').length,
            recent: rows.filter(({ r }) => changedWithin(r, 7)).length,
          }
          const namespaces = [...new Set(rows.map(({ r }) => r.namespace))].sort()
          const filtered = rows.filter(
            ({ r, inc }) =>
              (!state.hns || r.namespace === state.hns) &&
              (state.hf === 'all' ||
                (state.hf === 'incident' && inc.length > 0) ||
                (state.hf === 'notDeployed' && !!r.status && r.status !== 'deployed') ||
                (state.hf === 'recent' && changedWithin(r, 7))),
          )
          const visible = showAll ? filtered : filtered.slice(0, INITIAL_ROWS)
          return (
            <>
              <div className="panel-toolbar">
                <FilterChips<HelmFilter>
                  label="Show releases"
                  value={state.hf}
                  onChange={(hf) => setState({ hf }, { push: true })}
                  options={[
                    { id: 'all', label: 'All', count: counts.all },
                    { id: 'incident', label: 'With an open incident', count: counts.incident },
                    { id: 'notDeployed', label: 'Not deployed', count: counts.notDeployed },
                    { id: 'recent', label: 'Changed in 7d', count: counts.recent },
                  ]}
                />
                <label className="visually-hidden" htmlFor="helm-namespace">
                  Namespace
                </label>
                <select id="helm-namespace" className="compact-select" value={state.hns} onChange={(e) => setState({ hns: e.target.value }, { push: true })}>
                  <option value="">Any namespace</option>
                  {namespaces.map((n) => (
                    <option key={n} value={n}>
                      {n}
                    </option>
                  ))}
                </select>
                <span className="panel-toolbar-meta">
                  from release labels only{' '}
                  <HelpTip
                    label="What this list reads"
                    text="Read-only, from Helm’s release metadata: chart versions, values and manifests are not read. Upgrades, rollbacks and uninstalls are changes, and go through an incident’s approved plan rather than this list. Open incidents are matched to a release through its own objects and the pods and ReplicaSets named after them."
                  />
                  {unread > 0 ? ` · status not read for ${unread}` : ''}
                </span>
              </div>
              {result?.truncated && (
                <p className="truncation-notice" role="status">
                  The agent lists at most {rows.length} releases; {total} exist. Every release past the cap is left out of this table.
                </p>
              )}
              {rows.length === 0 ? (
                <p className="empty-state">
                  No object the agent can see carries Helm’s release annotations, so no Helm release was found on this cluster.
                </p>
              ) : filtered.length === 0 ? (
                <p className="empty-state">No release matches these filters.</p>
              ) : (
                <>
                  <div className="table-scroll">
                    <table className="cluster-table list-table helm-table">
                      <caption className="visually-hidden">Helm releases, those behind an open incident first</caption>
                      <thead>
                        <tr>
                          <th className="helm-release-col">Release</th>
                          <th className="col-shrink">Status</th>
                          <th className="col-numeric">Rev</th>
                          <th className="col-time">Updated</th>
                          <th className="helm-objects-col">
                            Objects by health{' '}
                            <HelpTip
                              label="Objects"
                              text="The objects the agent can see that carry this release’s annotations. Health is graded for workloads and volume claims only; idle means scaled to zero or completed."
                            />
                          </th>
                          <th className="col-shrink">Open incidents</th>
                        </tr>
                      </thead>
                      <tbody>
                        {visible.map(({ r, inc }) => (
                          <ReleaseRow key={`${r.namespace}/${r.name}`} clusterId={clusterId} r={r} incidents={inc} />
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {filtered.length > INITIAL_ROWS && (
                    <p className="inventory-more">
                      <button type="button" className="secondary" onClick={() => setShowAll((v) => !v)} aria-expanded={showAll}>
                        {showAll ? `Show the first ${INITIAL_ROWS}` : `Show all ${filtered.length} releases`}
                      </button>
                    </p>
                  )}
                </>
              )}
            </>
          )
        }}
      </InspectFrame>
    </section>
  )
}
