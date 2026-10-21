import { Fragment, useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import type { Incident } from '../api/types'
import { StateBadge as IncidentStateBadge } from '../components/IncidentBadges'
import { SkeletonTableRows } from '../components/Skeleton'
import { FilterChips, SplitBar, type BarPart } from '../components/SplitBar'
import { TablePagination } from '../components/TablePagination'
import { urlEnum, urlString, useUrlState } from '../hooks/useUrlState'
import { incidentIdentity, incidentObservedObject, observedObjectTitle, SEVERITY_LABEL } from '../utils/incidents'
import { usePagination } from '../utils/pagination'
import { formatDateTime, formatRelativeTime } from '../utils/time'
import { useRowNavigation } from './useRowNavigation'

// Cluster detail → Incidents (owner-approved cluster-pages design,
// 2026-10-11). "Which of this cluster's incidents need me?" The open set's
// mix comes first as two bars — severity, and where each incident is in
// ARGUS's loop — then the list, open by default, with look-alike incidents
// (same kind, namespace, reason, severity and state: thirteen pods of one
// fault) grouped into one row with a count that expands to its members.
// Everything is computed over this cluster's own list, which GET
// /incidents?clusterId= returns whole up to the hub's cap; past the cap the
// footer says "of N+".

const CLOSED = new Set(['Resolved', 'Dismissed'])
const isOpen = (i: Incident) => !CLOSED.has(i.state)
const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }
const SEV_CLASS: Record<string, string> = { low: 'sev-low', medium: 'sev-medium', high: 'sev-high', critical: 'sev-critical' }

/** Where an open incident is in the loop, in five words a person acts on. */
const STAGE: Record<string, 'detected' | 'investigating' | 'person' | 'approval' | 'fixing'> = {
  Detected: 'detected',
  Reopened: 'detected',
  Investigating: 'investigating',
  NeedsHumanInvestigation: 'person',
  Diagnosed: 'person',
  PlanRejected: 'person',
  Failed: 'person',
  ExecutionUnknown: 'person',
  ValidationUnknown: 'person',
  Expired: 'person',
  RecommendationReady: 'approval',
  AwaitingApproval: 'approval',
  Executing: 'fixing',
  AwaitingMerge: 'fixing',
  Validating: 'fixing',
}

const SCHEMA = {
  iv: urlEnum(['open', 'resolved', 'all'] as const, 'open'),
  isev: urlEnum(['', 'critical', 'high', 'medium', 'low'] as const, ''),
  ins: urlString(''),
  igrp: urlEnum(['1', '0'] as const, '1'),
  iexp: urlString(''),
}

interface Group {
  key: string
  items: Incident[]
}

function groupKey(i: Incident): string {
  const kind = (i.objectGvk ?? '').split('/').pop() ?? ''
  return [kind, i.objectNamespace ?? '', i.openingReason ?? '', i.severity, i.state].join('|')
}

function groupLookAlikes(incidents: readonly Incident[], enabled: boolean): Group[] {
  if (!enabled) return incidents.map((i) => ({ key: i.id, items: [i] }))
  const by = new Map<string, Group>()
  for (const i of incidents) {
    const k = groupKey(i)
    const g = by.get(k) ?? { key: k, items: [] }
    g.items.push(i)
    by.set(k, g)
  }
  return [...by.values()]
}

const latest = (xs: readonly Incident[]) => xs.reduce((a, b) => (a.lastSeen > b.lastSeen ? a : b))
const earliest = (xs: readonly Incident[]) => xs.reduce((a, b) => (a.firstSeen < b.firstSeen ? a : b))

type RowNavProps = Partial<ReturnType<ReturnType<typeof useRowNavigation>['rowProps']>> & { active?: boolean }

function IncidentRow({ incident, nested, nav }: { incident: Incident; nested?: boolean; nav?: RowNavProps }) {
  const navigate = useNavigate()
  const { active, ...rowProps } = nav ?? {}
  const identity = incidentIdentity(incident)
  const observed = incidentObservedObject(incident)
  const faultLine = [identity.fault, observed?.label].filter(Boolean).join(' · ')
  return (
    <tr
      {...rowProps}
      className={[SEV_CLASS[incident.severity] ?? 'sev-neutral', 'fleet-row-clickable', nested ? 'incident-group-member' : '', active ? 'fleet-row-active' : '']
        .filter(Boolean)
        .join(' ')}
      onClick={(e) => {
        if ((e.target as HTMLElement).closest('a,button')) return
        navigate(`/incidents/${incident.id}`)
      }}
    >
      <td className="severity-rule">
        <div className="identity-block">
          <Link
            className="identity-block-name"
            to={`/incidents/${incident.id}`}
            title={[incident.workloadKey ?? `${incident.objectGvk ?? ''} ${incident.objectNamespace ?? ''}`.trim(), `Fingerprint ${incident.fingerprint}`]
              .filter(Boolean)
              .join('\n')}
          >
            {identity.name}
          </Link>
          {identity.kind && <div className="identity-block-kind">{identity.kind}</div>}
          {faultLine && (
            <div className="identity-block-fault" title={observed ? observedObjectTitle(observed) : undefined}>
              {faultLine}
            </div>
          )}
        </div>
      </td>
      <td className="col-shrink">
        <span className="severity-cell">
          <span className="severity-chip" aria-hidden="true" />
          {SEVERITY_LABEL[incident.severity] ?? incident.severity}
        </span>
      </td>
      <td className="col-shrink">
        <IncidentStateBadge state={incident.state} resolutionKind={incident.resolutionKind} />
      </td>
      <td className="col-numeric">{incident.occurrenceCount}</td>
      <td className="col-time" title={formatDateTime(incident.firstSeen)}>
        {formatRelativeTime(incident.firstSeen).replace(/ ago$/, '')}
      </td>
      <td className="col-time" title={formatDateTime(incident.lastSeen)}>
        {formatRelativeTime(incident.lastSeen)}
      </td>
    </tr>
  )
}

function GroupRows({ g, expanded, onToggle, nav, total }: { g: Group; expanded: boolean; onToggle: () => void; nav: RowNavProps; total?: number }) {
  if (g.items.length === 1 && !(total && total > 1)) return <IncidentRow incident={g.items[0]} nav={nav} />
  // The server's count over the whole matching set (UX13); the loaded
  // members can be fewer past the list cap, and the row says so.
  const count = Math.max(total ?? 0, g.items.length)
  const { active, ...rowProps } = nav
  const first = g.items[0]
  const kind = (first.objectGvk ?? '').split('/').pop() || 'object'
  const occ = g.items.reduce((n, i) => n + i.occurrenceCount, 0)
  const last = latest(g.items)
  const firstSeen = earliest(g.items)
  return (
    <Fragment>
      <tr {...rowProps} className={`${SEV_CLASS[first.severity] ?? 'sev-neutral'} incident-group-row${active ? ' fleet-row-active' : ''}`}>
        <td className="severity-rule">
          <div className="identity-block">
            <button type="button" className="link-button identity-block-name" aria-expanded={expanded} onClick={onToggle}>
              <span aria-hidden="true">{expanded ? '▾' : '▸'}</span> {count} {kind}s
              {count > g.items.length ? ` (${g.items.length} loaded)` : ''}
            </button>
            <div className="identity-block-kind incident-group-names" title={g.items.map((i) => i.objectName).join('\n')}>
              {g.items
                .slice(0, 4)
                .map((i) => i.objectName)
                .join(', ')}
              {g.items.length > 4 ? ' …' : ''}
            </div>
            <div className="identity-block-fault">
              {first.objectNamespace} — {first.openingReason ?? 'no reason recorded'}
            </div>
          </div>
        </td>
        <td className="col-shrink">
          <span className="severity-cell">
            <span className="severity-chip" aria-hidden="true" />
            {SEVERITY_LABEL[first.severity] ?? first.severity}
          </span>
        </td>
        <td className="col-shrink">
          <IncidentStateBadge state={first.state} resolutionKind={first.resolutionKind} />
        </td>
        <td className="col-numeric">{occ}</td>
        <td className="col-time" title={formatDateTime(firstSeen.firstSeen)}>
          {formatRelativeTime(firstSeen.firstSeen).replace(/ ago$/, '')}
        </td>
        <td className="col-time" title={formatDateTime(last.lastSeen)}>
          {formatRelativeTime(last.lastSeen)}
        </td>
      </tr>
      {expanded && g.items.map((i) => <IncidentRow key={i.id} incident={i} nested />)}
    </Fragment>
  )
}

export function ClusterIncidentsTab({
  clusterId,
  incidents,
  loading,
  error,
  truncated,
  groupCounts,
}: {
  clusterId: string
  incidents: readonly Incident[]
  loading: boolean
  error: string | null
  truncated: boolean
  groupCounts?: readonly { key: string; count: number }[]
}) {
  const totals = useMemo(() => new Map((groupCounts ?? []).map((g) => [g.key, g.count])), [groupCounts])
  const [state, setState] = useUrlState(SCHEMA)
  const open = useMemo(() => incidents.filter(isOpen), [incidents])
  // Fixed for the life of the tab, so "closed in 7d" does not shift between renders.
  const [weekAgo] = useState(() => Date.now() - 7 * 86_400_000)
  const resolved7 = useMemo(() => incidents.filter((i) => !isOpen(i) && new Date(i.resolvedAt ?? i.lastSeen).getTime() >= weekAgo), [incidents, weekAgo])
  const namespaces = useMemo(() => [...new Set(incidents.map((i) => i.objectNamespace ?? '').filter(Boolean))].sort(), [incidents])
  const shown = useMemo(() => {
    const base = state.iv === 'open' ? open : state.iv === 'resolved' ? resolved7 : incidents
    return [...base]
      .filter((i) => (!state.isev || i.severity === state.isev) && (!state.ins || i.objectNamespace === state.ins))
      .sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9) || (a.lastSeen < b.lastSeen ? 1 : -1))
  }, [state.iv, state.isev, state.ins, open, resolved7, incidents])
  const groups = useMemo(() => groupLookAlikes(shown, state.igrp === '1'), [shown, state.igrp])
  const { visibleItems, pagination } = usePagination(groups, 10)
  const expanded = new Set(state.iexp ? state.iexp.split(',') : [])
  const toggle = (k: string) => {
    const next = new Set(expanded)
    if (next.has(k)) next.delete(k)
    else next.add(k)
    setState({ iexp: [...next].join(',') })
  }

  // j/k and Enter as on the Incidents worklist: Enter opens a single
  // incident, or expands a group.
  const navigate = useNavigate()
  const rowNav = useRowNavigation({
    count: visibleItems.length,
    onOpen: (i) => {
      const g = visibleItems[i]
      if (!g) return
      if (g.items.length === 1) navigate(`/incidents/${g.items[0].id}`)
      else toggle(g.key)
    },
    enabled: true,
    clickToOpen: false,
  })

  const sev = (s: string) => open.filter((i) => i.severity === s).length
  const stage = (st: string) => open.filter((i) => STAGE[i.state] === st).length
  const sevParts: BarPart[] = [
    { tone: 'critical', value: sev('critical'), label: 'critical' },
    { tone: 'high', value: sev('high'), label: 'high' },
    { tone: 'medium', value: sev('medium'), label: 'medium' },
    ...(sev('low') ? [{ tone: 'ok' as const, value: sev('low'), label: 'low' }] : []),
  ]
  const stageParts: BarPart[] = [
    { tone: 'info', value: stage('detected'), label: 'detected, not investigated' },
    { tone: 'accent', value: stage('investigating'), label: 'investigating' },
    { tone: 'high', value: stage('person'), label: 'needs a person' },
    { tone: 'medium', value: stage('approval'), label: 'awaiting approval' },
    { tone: 'ok', value: stage('fixing'), label: 'being fixed' },
  ]

  const head = (
    <thead>
      <tr>
        <th>Incident</th>
        <th className="col-shrink">Severity</th>
        <th className="col-shrink">State</th>
        <th className="col-numeric">Occurrences</th>
        <th className="col-time">Open for</th>
        <th className="col-time">Last seen</th>
      </tr>
    </thead>
  )

  return (
    <section aria-label="Incidents on this cluster" className="cluster-incidents">
      <div className="section-heading-row">
        <h2>Incidents</h2>
        <Link to={`/incidents?clusterId=${encodeURIComponent(clusterId)}`}>Open incident worklist →</Link>
      </div>
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      {loading ? (
        <section className="list-card">
          <div className="table-scroll">
            <table className="cluster-table list-table" aria-busy="true">
              {head}
              <tbody>
                <SkeletonTableRows columns={6} />
              </tbody>
            </table>
          </div>
        </section>
      ) : incidents.length === 0 && !error ? (
        <p className="empty-state">No incidents have been recorded for this cluster.</p>
      ) : (
        <>
          <div className="chart-card-grid">
            <div className="card card-compact">
              <div className="card-head">
                <h3>Open by severity</h3>
                <span className="card-head-meta">
                  {open.length}
                  {truncated ? '+' : ''} open
                </span>
              </div>
              <SplitBar tall label="Open incidents by severity" parts={sevParts} showZero />
            </div>
            <div className="card card-compact">
              <div className="card-head">
                <h3>Where they are in the loop</h3>
                <span className="card-head-meta">open</span>
              </div>
              <SplitBar tall label="Open incidents by stage" parts={stageParts} />
            </div>
          </div>
          <div className="panel-toolbar">
            <FilterChips<'open' | 'resolved' | 'all'>
              label="Show"
              value={state.iv}
              onChange={(iv) => setState({ iv, iexp: '' }, { push: true })}
              options={[
                { id: 'open', label: 'Open', count: open.length },
                { id: 'resolved', label: 'Closed in 7d', count: resolved7.length },
                { id: 'all', label: 'All', count: incidents.length },
              ]}
            />
            <label className="visually-hidden" htmlFor="ci-sev">
              Severity
            </label>
            <select id="ci-sev" className="compact-select" value={state.isev} onChange={(e) => setState({ isev: e.target.value as typeof state.isev, iexp: '' }, { push: true })}>
              <option value="">Any severity</option>
              {(['critical', 'high', 'medium', 'low'] as const).map((s) => (
                <option key={s} value={s}>
                  {SEVERITY_LABEL[s]}
                </option>
              ))}
            </select>
            <label className="visually-hidden" htmlFor="ci-ns">
              Namespace
            </label>
            <select id="ci-ns" className="compact-select" value={state.ins} onChange={(e) => setState({ ins: e.target.value, iexp: '' }, { push: true })}>
              <option value="">Any namespace</option>
              {namespaces.map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
            <button type="button" className="filter-chip" aria-pressed={state.igrp === '1'} onClick={() => setState({ igrp: state.igrp === '1' ? '0' : '1', iexp: '' })}>
              Group look-alikes
            </button>
          </div>
          {groups.length === 0 ? (
            <p className="empty-state">No incident on this cluster matches these filters.</p>
          ) : (
            <section className="list-card">
              <div className="table-scroll">
                <table className="cluster-table list-table">
                  {head}
                  <tbody {...rowNav.containerProps}>
                    {visibleItems.map((g, i) => (
                      <GroupRows
                        key={g.key}
                        g={g}
                        expanded={expanded.has(g.key)}
                        onToggle={() => toggle(g.key)}
                        nav={{ ...rowNav.rowProps(i), active: rowNav.activeIndex === i }}
                        // "Closed in 7 days" is a time window the server count does not apply.
                        total={state.iv === 'resolved' || state.igrp !== '1' ? undefined : totals.get(g.key)}
                      />
                    ))}
                  </tbody>
                </table>
              </div>
              <TablePagination {...pagination} truncated={truncated} />
            </section>
          )}
        </>
      )}
    </section>
  )
}
