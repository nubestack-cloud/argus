import { Fragment, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Quantity } from '../components/Quantity'
import { BarList, Segmented, SplitBar } from '../components/SplitBar'
import { urlEnum, urlString, useUrlState } from '../hooks/useUrlState'
import { withObjectPanel } from '../insight/panelUrl'
import { InspectFrame, type ClusterLiveness } from './InspectFrame'
import {
  POSTURE_CATEGORIES,
  filterByFramework,
  frameworksOf,
  groupPosture,
  postureByNamespace,
  type PostureGroup,
  type PostureResult,
} from './postureModel'
import { useInspect } from './useInspect'

// Cluster detail → Posture (docs/CLUSTER_INSIGHT_SPECS.md CI-S4; owner-
// approved cluster-pages design, 2026-10-11). Best-practice risks, never
// incidents. "Where is this cluster weakest?" is answered first by two
// charts — danger/warning/passing per category from the agent's own summary,
// and findings per namespace — then one row per check with how many objects
// it fired on (CI-U4), expandable to why it matters, the fix and the
// objects, each of which opens the inspector. The category filter is a tool
// argument (the agent filters); framework and namespace narrow the returned
// findings. All of it, and the expanded checks, live in the URL (CI-U5).

const SCHEMA = {
  pcat: urlEnum(['', ...POSTURE_CATEGORIES] as const, ''),
  pfw: urlString(''),
  pns: urlString(''),
  pexp: urlString(''),
}

const SEV_CLASS: Record<string, string> = { danger: 'sev-critical', warning: 'sev-high' }

function catOrder(c: string): number {
  const i = (POSTURE_CATEGORIES as readonly string[]).indexOf(c)
  return i < 0 ? POSTURE_CATEGORIES.length : i
}

// The posture tab's own words, the same ones the category bars use: a row
// reading "High" beside a bar segment reading "danger" would be one fact in
// two vocabularies.
const SEV_WORD: Record<string, string> = { danger: 'Danger', warning: 'Warning' }

function GroupRows({
  clusterId,
  group,
  expanded,
  partial,
  onToggle,
  maxObjects,
}: {
  clusterId: string
  group: PostureGroup
  expanded: boolean
  partial: boolean
  onToggle: () => void
  maxObjects: number
}) {
  const [params, setParams] = useSearchParams()
  const bodyId = `posture-${group.checkId}`
  return (
    <Fragment>
      <tr className={SEV_CLASS[group.severity]}>
        <td className="severity-rule">
          <div className="identity-block">
            <button
              type="button"
              className="link-button identity-block-name fleet-expander"
              aria-expanded={expanded}
              aria-controls={bodyId}
              onClick={onToggle}
            >
              <span aria-hidden="true">{expanded ? '▾' : '▸'}</span> {group.title}
            </button>
          </div>
        </td>
        <td className="col-shrink">
          <span className="severity-cell">
            <span className="severity-chip" aria-hidden="true" />
            {SEV_WORD[group.severity] ?? group.severity}
          </span>
        </td>
        <td className="col-shrink">{group.category}</td>
        <td className="posture-objects-col">
          <span className="posture-objects">
            <span className="bar-list-track" aria-hidden="true">
              <span className="split-seg" data-tone={group.severity === 'danger' ? 'critical' : 'high'} style={{ width: `${(group.findings.length * 100) / maxObjects}%` }} />
            </span>
            <span className="posture-objects-count">
              <Quantity value={group.findings.length} certainty={partial ? 'atLeast' : 'exact'} />
            </span>
          </span>
        </td>
        <td>
          {(group.meta?.frameworks ?? []).length ? (
            <span className="posture-frameworks">
              {(group.meta?.frameworks ?? []).map((f) => (
                <span key={f} className="badge badge-gray">
                  {f}
                </span>
              ))}
            </span>
          ) : (
            <span className="text-muted">—</span>
          )}
        </td>
      </tr>
      {expanded && (
        <tr id={bodyId} className="fleet-group-body">
          <td colSpan={5}>
            {group.meta?.description && <p className="fleet-remediation">{group.meta.description}</p>}
            {group.meta?.remediation && (
              <p className="fleet-remediation">
                <strong>Remediation:</strong> {group.meta.remediation}
              </p>
            )}
            <ul className="fleet-object-list">
              {group.findings.map((f) => (
                <li key={`${f.kind}/${f.namespace}/${f.name}`}>
                  <button
                    type="button"
                    className="link-button fleet-mono"
                    title="Open this object in the inspector"
                    onClick={() =>
                      setParams(
                        withObjectPanel(params, {
                          clusterId,
                          kind: f.kind,
                          apiGroup: f.group || undefined,
                          namespace: f.namespace || undefined,
                          name: f.name,
                        }),
                      )
                    }
                  >
                    {f.kind} {f.namespace ? `${f.namespace}/` : ''}
                    {f.name}
                  </button>
                  <span className="text-muted"> — {f.message}</span>
                </li>
              ))}
            </ul>
            {group.meta?.references && group.meta.references.length > 0 && (
              <p className="fleet-references">
                <span className="text-muted">References: </span>
                {group.meta.references.map((r, i) => (
                  <span key={r.url}>
                    {i > 0 ? ' · ' : ''}
                    <a href={r.url} target="_blank" rel="noreferrer noopener">
                      {r.label}
                    </a>
                  </span>
                ))}
              </p>
            )}
          </td>
        </tr>
      )}
    </Fragment>
  )
}

export function PosturePanel({ clusterId, liveness }: { clusterId: string; liveness: ClusterLiveness }) {
  const [state, setState] = useUrlState(SCHEMA)
  const args = useMemo(() => (state.pcat ? { category: state.pcat } : {}), [state.pcat])
  const { query, capabilityResolved, missing } = useInspect<PostureResult>(clusterId, 'get_posture_findings', args)
  const expanded = useMemo(() => new Set(state.pexp ? state.pexp.split(',') : []), [state.pexp])
  const toggle = (id: string) => {
    const next = new Set(expanded)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    setState({ pexp: [...next].join(',') }, { push: true })
  }

  return (
    <section aria-label="Posture checks">
      <InspectFrame label="Posture checks" help="Best-practice checks the agent runs over the objects it has cached — security, reliability and efficiency. They describe risk, not breakage: a posture finding never opens an incident. Danger is the severity the detector reports as high, warning as medium. An object or namespace annotated argus.io/ignore-checks (check IDs, or *) sets those checks aside: listed at the bottom, counted nowhere. Each row is one check, with how many objects it fired on; open it for why it matters, the fix and the objects." query={query} capabilityResolved={capabilityResolved} missing={missing} liveness={liveness} skeletonColumns={5}>
        {(result) => {
          const frameworks = frameworksOf(result)
          const partial = !!result?.truncated
          const returned = result?.findings?.length ?? 0
          const filtered = !!state.pcat || !!state.pfw || !!state.pns
          const scoped = state.pns ? { ...result, findings: (result?.findings ?? []).filter((f) => f.namespace === state.pns) } : result
          const groups = filterByFramework(groupPosture(scoped), state.pfw)
          const maxObjects = Math.max(1, ...groups.map((g) => g.findings.length))
          const byNs = postureByNamespace(result?.findings ?? [])
          const excepted = (scoped?.findings ?? []).filter((f) => f.excepted)
          const cats = Object.entries(result?.summary?.categories ?? {}).sort(
            ([a], [b]) => catOrder(a) - catOrder(b) || a.localeCompare(b),
          )
          return (
            <>
              <div className="chart-card-grid">
                <div className="card card-compact">
                  <div className="card-head">
                    <h3>By category</h3>
                    <span className="card-head-meta">danger · warning · passing</span>
                  </div>
                  {cats.length === 0 ? (
                    <p className="text-muted">This agent does not report pass counts per category.</p>
                  ) : (
                    <div className="posture-cats">
                      {cats.map(([c, v]) => (
                        <div key={c} className="posture-cat">
                          <strong>{c}</strong>
                          <SplitBar
                            tall
                            label={`${c} checks`}
                            parts={[
                              { tone: 'critical', value: v.danger, label: 'danger' },
                              { tone: 'high', value: v.warning, label: 'warning' },
                              { tone: 'ok', value: v.passing, label: 'passing' },
                            ]}
                            showZero
                          />
                        </div>
                      ))}
                    </div>
                  )}
                </div>
                <div className="card card-compact">
                  <div className="card-head">
                    <h3>By namespace</h3>
                    <span className="card-head-meta">
                      <Quantity value={returned} certainty={partial ? 'atLeast' : 'exact'} /> findings
                    </span>
                  </div>
                  {byNs.length === 0 ? (
                    <p className="text-muted">No findings to place.</p>
                  ) : (
                    <BarList
                      label="Findings by namespace — select one to filter"
                      rows={byNs.slice(0, 8).map((n) => ({
                        key: n.namespace,
                        name: n.namespace || 'cluster-scoped',
                        parts: [
                          { tone: 'critical', value: n.danger, label: 'danger' },
                          { tone: 'high', value: n.warning, label: 'warning' },
                        ],
                        selected: state.pns === n.namespace,
                        onSelect: () => setState({ pns: state.pns === n.namespace ? '' : n.namespace, pexp: '' }, { push: true }),
                      }))}
                    />
                  )}
                </div>
              </div>
              <div className="panel-toolbar">
                <Segmented
                  label="Category"
                  options={[{ id: '', label: 'All' }, ...POSTURE_CATEGORIES.map((c) => ({ id: c, label: c }))]}
                  value={state.pcat}
                  onChange={(v) => setState({ pcat: v as typeof state.pcat, pexp: '' }, { push: true })}
                />
                <label className="visually-hidden" htmlFor="posture-framework">
                  Framework
                </label>
                <select id="posture-framework" className="compact-select" value={state.pfw} onChange={(e) => setState({ pfw: e.target.value }, { push: true })}>
                  <option value="">Any framework</option>
                  {frameworks.map((f) => (
                    <option key={f} value={f}>
                      {f}
                    </option>
                  ))}
                </select>
                <label className="visually-hidden" htmlFor="posture-namespace">
                  Namespace
                </label>
                <select id="posture-namespace" className="compact-select" value={state.pns} onChange={(e) => setState({ pns: e.target.value, pexp: '' }, { push: true })}>
                  <option value="">Any namespace</option>
                  {byNs.map((n) => (
                    <option key={n.namespace} value={n.namespace}>
                      {n.namespace || 'cluster-scoped'}
                    </option>
                  ))}
                </select>
              </div>
              {partial && (
                <p className="truncation-notice" role="status">
                  The agent returned {returned} of {result?.total ?? 'more'} findings, so each count below is a lower bound.
                  Narrow by category to see the rest.
                </p>
              )}
              {groups.length === 0 ? (
                <p className="empty-state">
                  {filtered
                    ? 'No posture check fired for these filters. Clear the category, framework or namespace filter to see every check.'
                    : 'No posture check fired on this cluster. Ignored namespaces (kube-system and the like) and disabled checks are not scanned.'}
                </p>
              ) : (
                <div className="table-scroll">
                  <table className="cluster-table list-table scan-table">
                    <thead>
                      <tr>
                        <th>Check</th>
                        <th className="col-shrink">Severity</th>
                        <th className="col-shrink">Category</th>
                        <th>Objects</th>
                        <th>Frameworks</th>
                      </tr>
                    </thead>
                    <tbody>
                      {groups.map((g) => (
                        <GroupRows
                          key={g.checkId}
                          clusterId={clusterId}
                          group={g}
                          partial={partial}
                          maxObjects={maxObjects}
                          expanded={expanded.has(g.checkId)}
                          onToggle={() => toggle(g.checkId)}
                        />
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {excepted.length > 0 && (
                <details>
                  <summary>
                    {excepted.length} set aside by <code>argus.io/ignore-checks</code>
                  </summary>
                  <ul className="fleet-object-list">
                    {excepted.map((f) => (
                      <li key={`${f.checkID}/${f.kind}/${f.namespace}/${f.name}`}>
                        <span className="fleet-mono">
                          {f.kind} {f.namespace ? `${f.namespace}/` : ''}
                          {f.name}
                        </span>{' '}
                        · {result?.checks?.[f.checkID]?.title || f.checkID}
                      </li>
                    ))}
                  </ul>
                </details>
              )}
            </>
          )
        }}
      </InspectFrame>
    </section>
  )
}
