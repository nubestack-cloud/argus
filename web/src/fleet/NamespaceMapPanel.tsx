import { useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { toPng } from 'html-to-image'
import type { Incident, NamespaceIndexRow } from '../api/types'
import { SEVERITY_LABEL } from '../utils/incidents'
import { formatRelativeTime } from '../utils/time'
import { urlString, useUrlState } from '../hooks/useUrlState'
import { SkeletonLines } from '../components/Skeleton'
import { InspectFrame, type ClusterLiveness } from './InspectFrame'
import { apiErrorText } from './apiErrorText'
import {
  ATTACHED_LABEL,
  ATTACHED_SHORT,
  DEFAULT_FILTERS,
  KIND_FILTERS,
  LANES,
  LANE_LABEL,
  MAP_DEFAULT_CAP,
  MAP_MAX_CAP,
  buildNamespaceMap,
  cardIncidents,
  cardMatches,
  defaultNamespace,
  mapPartialNote,
  mapStatusCounts,
  type Health,
  type KindFilter,
  type MapCard,
  type MapNode,
  type NamespaceMapModel,
  namespaceOptionLabel,
  openIncidentsByNamespace,
  safeFilePart,
  type NamespaceTopology,
} from './namespaceMapModel'
import { useInspect } from './useInspect'
import { useOpenObjectTab } from './useOpenObjectTab'

// Cluster detail → Map (PROJECT.md AD6). How one namespace's objects are
// wired, as a card per workload in fixed lanes (namespaceMapModel.ts says
// why it is not a zoomable canvas), with every object's health in words.
// Cards that need attention come first and open; healthy ones collapse to a
// line when there are many. One namespace at a time on purpose: a
// whole-cluster map is unreadable at any real size. ?mapns= carries the
// namespace, so any page (an incident's namespace, say) can link straight to
// a map.

const SCHEMA = { mapns: urlString('') }
const SEV_CLASS: Record<string, string> = { critical: 'sev-critical', high: 'sev-high', medium: 'sev-medium', low: 'sev-low' }
const INDEX_ARGS = {}

export function NamespaceMapPanel({
  clusterId,
  clusterName,
  incidents,
  liveness,
}: {
  clusterId: string
  clusterName: string
  incidents: readonly Incident[]
  liveness: ClusterLiveness
}) {
  const [state, setState] = useUrlState(SCHEMA)
  const [cap, setCap] = useState(MAP_DEFAULT_CAP)
  const index = useInspect<NamespaceTopology>(clusterId, 'get_namespace_topology', INDEX_ARGS)
  const namespaces = useMemo(() => index.query.data?.result?.namespaces ?? [], [index.query.data])
  const open = useMemo(() => openIncidentsByNamespace(incidents), [incidents])
  const fallback = useMemo(() => defaultNamespace(incidents, namespaces), [incidents, namespaces])
  const ns = state.mapns || fallback?.name || ''
  const args = useMemo(() => (ns ? { namespace: ns, ...(cap !== MAP_DEFAULT_CAP ? { cap } : {}) } : null), [ns, cap])
  const graphQuery = useInspect<NamespaceTopology>(clusterId, 'get_namespace_topology', args ?? { namespace: '' }, !!args)
  const openObject = useOpenObjectTab()
  const [filters, setFilters] = useState<ReadonlySet<KindFilter>>(DEFAULT_FILTERS)
  const graphResult = graphQuery.query.data?.result
  const model = useMemo(() => (graphResult ? buildNamespaceMap(graphResult, filters) : null), [graphResult, filters])

  const openNode = (n: MapNode) => {
    if (!n.openable) return
    openObject({ clusterId, kind: n.kind, apiGroup: n.apiGroup || undefined, namespace: n.namespace, name: n.name })
  }

  const denied = index.capabilityResolved && index.missing.length > 0

  const maxPods = Math.max(1, ...namespaces.map((n) => n.pods ?? 0))

  return (
    <section aria-label="Namespace map" className={denied ? undefined : 'nsmap-layout'}>
      {!denied && (
        <NamespaceRail
          namespaces={namespaces}
          open={open}
          selected={ns}
          maxPods={maxPods}
          loading={index.query.isLoading}
          truncated={!!index.query.data?.result?.namespacesTruncated}
          why={!state.mapns && fallback ? `Opened on ${fallback.name}: ${fallback.why}.` : ''}
          onSelect={(name) => {
            setCap(MAP_DEFAULT_CAP)
            setState({ mapns: name }, { push: true })
          }}
        />
      )}
      <div className="nsmap-main">
      {!ns && !denied ? (
        index.query.isError ? (
          <div className="fleet-inline-error">
            <p className="form-error" role="alert">
              {apiErrorText(index.query.error, 'The namespace list could not be read from the agent.')}
            </p>
            <button type="button" className="secondary" onClick={() => void index.query.refetch()}>
              Try again
            </button>
          </div>
        ) : !index.capabilityResolved || index.query.isLoading || !index.query.data ? (
          <div aria-busy="true" aria-label="Loading namespaces">
            <SkeletonLines count={1} widths={['12rem']} />
            <div className="skeleton map-skeleton" />
          </div>
        ) : (
          <p className="empty-state">The agent reported no namespaces, so there is nothing to map.</p>
        )
      ) : (
        <InspectFrame
          label="Namespace map"
          help="Every workload in this namespace, laid out the same way: how traffic reaches it (Ingress or route, then Service), the workload, and its pods, with the policies, budgets and autoscalers that guard it as badges. Workloads with an open incident or a part not healthy come first, drawn in full; healthy ones are one line each. Health is live; an incident stays open until it is resolved, so a workload can be healthy now with an incident still open."
          query={graphQuery.query}
          capabilityResolved={graphQuery.capabilityResolved}
          missing={graphQuery.missing}
          liveness={liveness}
          skeletonColumns={4}
        >
          {(r) => {
            const partial = mapPartialNote(r)
            const canDrawMore = !!r.omittedNodes && cap < MAP_MAX_CAP
            return (
              <div className="map-body">
                {partial && (
                  <p className="fleet-scope-note" role="note">
                    {partial}{' '}
                    {canDrawMore && (
                      <button type="button" className="link-button" onClick={() => setCap(MAP_MAX_CAP)}>
                        Draw up to {MAP_MAX_CAP} objects
                      </button>
                    )}
                  </p>
                )}
                {model && model.cards.length > 0 ? (
                  <MapBody
                    model={model}
                    namespace={r.namespace ?? ns}
                    incidents={incidents}
                    openIncidents={open.get(r.namespace ?? ns) ?? 0}
                    clusterNodes={r.clusterNodes ?? 0}
                    filters={filters}
                    onFilters={setFilters}
                    onOpen={openNode}
                    fileName={`${safeFilePart(clusterName)}-${safeFilePart(ns)}-map-${new Date().toISOString().slice(0, 10)}.png`}
                  />
                ) : (
                  <p className="empty-state">
                    Namespace {r.namespace} has nothing the map draws{partial ? ' among the kinds the agent could list' : ''}: no Service,
                    workload, pod or route.
                  </p>
                )}
              </div>
            )
          }}
        </InspectFrame>
      )}
      </div>
    </section>
  )
}

const RAIL_SHOWN = 14

/** Every namespace as a row: its pods as a bar on one scale and its open
 *  incidents as a number, worst first — a namespace is chosen by comparing
 *  them, which a dropdown cannot show. */
function NamespaceRail({
  namespaces,
  open,
  selected,
  maxPods,
  loading,
  truncated,
  why,
  onSelect,
}: {
  namespaces: readonly NamespaceIndexRow[]
  open: Map<string, number>
  selected: string
  maxPods: number
  loading: boolean
  truncated: boolean
  why: string
  onSelect: (name: string) => void
}) {
  const [query, setQuery] = useState('')
  const [all, setAll] = useState(false)
  const sorted = useMemo(
    () => [...namespaces].sort((a, b) => (open.get(b.name) ?? 0) - (open.get(a.name) ?? 0) || (b.pods ?? 0) - (a.pods ?? 0) || a.name.localeCompare(b.name)),
    [namespaces, open],
  )
  const needle = query.trim().toLowerCase()
  const matching = needle ? sorted.filter((n) => n.name.toLowerCase().includes(needle)) : sorted
  const shown = all || needle ? matching : matching.slice(0, RAIL_SHOWN)
  // The selected namespace stays visible even when it is past the cut.
  const withSelected = selected && !shown.some((n) => n.name === selected) ? [...shown, ...matching.filter((n) => n.name === selected)] : shown
  return (
    <aside className="card card-compact nsmap-rail" aria-label="Namespaces">
      <div className="card-head">
        <h3>Namespaces</h3>
        <span className="card-head-meta">pods · incidents</span>
      </div>
      <label className="visually-hidden" htmlFor="nsmap-ns-find">
        Find a namespace
      </label>
      <input id="nsmap-ns-find" type="search" className="nsmap-search" placeholder="Find a namespace" value={query} onChange={(e) => setQuery(e.target.value)} />
      {loading && namespaces.length === 0 ? (
        <SkeletonLines count={6} />
      ) : (
        <ul className="nsmap-rail-list">
          {selected && !namespaces.some((n) => n.name === selected) && namespaces.length > 0 && (
            <li>
              <button type="button" className="nsmap-rail-row" aria-pressed title="Not in the agent’s namespace list">
                <span className="nsmap-rail-name">{selected}</span>
                <span className="text-muted nsmap-rail-unlisted">not listed</span>
                <span className="nsmap-rail-inc">{open.get(selected) || '–'}</span>
              </button>
            </li>
          )}
          {withSelected.map((n) => {
            const inc = open.get(n.name) ?? 0
            return (
              <li key={n.name}>
                <button
                  type="button"
                  className="nsmap-rail-row"
                  aria-pressed={n.name === selected}
                  title={namespaceOptionLabel(n, inc)}
                  onClick={() => onSelect(n.name)}
                >
                  <span className="nsmap-rail-name">{n.name}</span>
                  <span className="bar-list-track" aria-hidden="true">
                    <span
                      className="split-seg"
                      data-tone={n.notHealthy ? 'high' : 'ok'}
                      style={{ width: `${((n.pods ?? 0) * 100) / maxPods}%` }}
                    />
                  </span>
                  <span className={inc ? 'nsmap-rail-inc nsmap-rail-inc-open' : 'nsmap-rail-inc'}>{inc || '–'}</span>
                </button>
              </li>
            )
          })}
        </ul>
      )}
      {!needle && matching.length > RAIL_SHOWN && (
        <button type="button" className="link-button nsmap-rail-more" aria-expanded={all} onClick={() => setAll((v) => !v)}>
          {all ? 'Show fewer' : `Show all ${matching.length}`}
        </button>
      )}
      {(why || truncated) && (
        <p className="field-hint nsmap-rail-why">
          {why}
          {truncated ? ' The list holds the 500 largest namespaces.' : ''}
        </p>
      )}
    </aside>
  )
}

const HEALTH_WORD: Record<Health, string> = {
  healthy: 'Healthy',
  degraded: 'Degraded',
  unhealthy: 'Unhealthy',
  neutral: 'Idle',
  unknown: 'Health unknown',
}
const HEALTH_BADGE: Record<Health, string> = {
  healthy: 'badge badge-green',
  degraded: 'badge badge-amber',
  unhealthy: 'badge badge-red',
  neutral: 'badge badge-gray',
  unknown: 'badge badge-gray',
}

function NodeChip({ n, onOpen, match, relation }: { n: MapNode; onOpen: (n: MapNode) => void; match: boolean; relation?: string }) {
  // Neutral (completed, scaled to zero) reads by its reason, not as "Idle".
  const word = n.health === 'neutral' && n.reason ? n.reason : HEALTH_WORD[n.health]
  const reason = n.health === 'neutral' ? undefined : n.reason
  const body = (
    <>
      <span className="nsmap-node-kind">
        {relation ? `${relation} · ` : ''}
        {n.kind === 'PodGroup' ? 'Pods' : n.kind}
      </span>
      <span className="nsmap-node-name">{n.name}</span>
      <span className="nsmap-node-status">
        {word}
        {reason ? ` · ${reason}` : ''}
        {n.detail ? <span className="text-muted"> · {n.detail}</span> : null}
      </span>
    </>
  )
  const cls = `nsmap-node${match ? ' nsmap-node-match' : ''}`
  return n.openable ? (
    <button type="button" className={cls} data-health={n.health} onClick={() => onOpen(n)} title={`Open ${n.kind} ${n.name}`}>
      {body}
    </button>
  ) : (
    <span className={cls} data-health={n.health}>
      {body}
    </span>
  )
}

/** One dot per pod (to a dozen), coloured by its group's health and named
 *  in the dot row's label. */
function PodDots({ card }: { card: MapCard }) {
  const groups = card.lanes.pods
  if (groups.length === 0 || card.pods === 0) return null
  const dots: Health[] = []
  for (const g of groups) {
    const n = g.kind === 'PodGroup' ? Math.max(1, Number(/\d+/.exec(g.detail ?? '')?.[0] ?? 1)) : 1
    for (let i = 0; i < n && dots.length < 12; i++) dots.push(g.health)
  }
  return (
    <span className="nsmap-dots" role="img" aria-label={`${card.pods} pod${card.pods === 1 ? '' : 's'}: ${groups.map((g) => HEALTH_WORD[g.health].toLowerCase()).join(', ')}`}>
      {dots.map((h, i) => (
        <span key={i} className="nsmap-dot" data-health={h} />
      ))}
      {card.pods > 12 && <span className="nsmap-dot-more">+{card.pods - 12}</span>}
    </span>
  )
}

function Guards({ card, onOpen }: { card: MapCard; onOpen: (n: MapNode) => void }) {
  if (card.attached.length === 0) return null
  return (
    <span className="nsmap-guards">
      {card.attached.map((n) => (
        <button
          key={n.id}
          type="button"
          className="nsmap-guard"
          data-health={n.health}
          title={`${ATTACHED_LABEL[n.kind] ?? 'attached'} · ${n.kind} ${n.name} · ${HEALTH_WORD[n.health]}${n.detail ? ` · ${n.detail}` : ''}`}
          onClick={() => onOpen(n)}
          disabled={!n.openable}
        >
          {ATTACHED_SHORT[n.kind] ?? n.kind}
          {n.kind === 'PodDisruptionBudget' && n.detail ? ` ${/\d+/.exec(n.detail)?.[0] ?? ''}` : ''}
        </button>
      ))}
    </span>
  )
}

/** A workload drawn in full: its chain from entry to pods as connected
 *  boxes, guards as badges, and — when it has one — the open incident on it
 *  beside its live health, because the two can differ. */
function Card({
  card,
  incidents,
  onCollapse,
  onOpen,
  query,
}: {
  card: MapCard
  incidents: readonly Incident[]
  onCollapse: () => void
  onOpen: (n: MapNode) => void
  query: string
}) {
  const needle = query.trim().toLowerCase()
  const isMatch = (n: MapNode) => needle !== '' && n.name.toLowerCase().includes(needle)
  const worst = incidents[0]
  return (
    <article className="nsmap-card" data-health={card.health} data-incident={worst ? worst.severity : undefined} aria-label={`${card.kind ?? ''} ${card.title}`.trim()}>
      <header className="nsmap-card-head">
        <button type="button" className="nsmap-card-toggle" aria-expanded onClick={onCollapse}>
          <span aria-hidden="true">▾</span>
          <span className="nsmap-card-title">{card.title}</span>
        </button>
        {card.kind && <span className="nsmap-card-kind">{card.kind}</span>}
        {worst ? (
          <>
            <span className={`severity-cell ${SEV_CLASS[worst.severity] ?? ''}`}>
              <span className="severity-chip" aria-hidden="true" />
              {incidents.length === 1 ? `${SEVERITY_LABEL[worst.severity]} incident open` : `${incidents.length} incidents open, worst ${SEVERITY_LABEL[worst.severity]?.toLowerCase()}`}
            </span>
            <span className={HEALTH_BADGE[card.health]}>{card.health === 'healthy' ? 'Healthy now' : HEALTH_WORD[card.health]}</span>
            <span className="text-muted nsmap-card-since">detected {formatRelativeTime(worst.firstSeen)}</span>
            <Link className="nsmap-card-link" to={`/incidents/${encodeURIComponent(worst.id)}`}>
              Incident →
            </Link>
          </>
        ) : (
          <span className={HEALTH_BADGE[card.health]}>{HEALTH_WORD[card.health]}</span>
        )}
        <span className="nsmap-card-count">
          {card.pods > 0 ? `${card.pods} pod${card.pods === 1 ? '' : 's'} · ` : ''}
          {card.total} object{card.total === 1 ? '' : 's'}
        </span>
      </header>
      <div className="nsmap-chain">
        {LANES.map((lane) => (
          <div key={lane} className="nsmap-lane" data-lane={lane} data-empty={card.lanes[lane].length === 0 ? '' : undefined}>
            {card.lanes[lane].length === 0 ? (
              <span className="nsmap-lane-empty" aria-label={`No ${LANE_LABEL[lane].toLowerCase()}`}>
                no {LANE_LABEL[lane].toLowerCase()}
              </span>
            ) : (
              card.lanes[lane].map((n) => (
                <div key={n.id} className="nsmap-node-wrap">
                  <NodeChip n={n} onOpen={onOpen} match={isMatch(n)} />
                  {lane === 'pods' && n === card.lanes.pods[0] && <PodDots card={card} />}
                </div>
              ))
            )}
            {lane === 'workload' && <Guards card={card} onOpen={onOpen} />}
          </div>
        ))}
      </div>
    </article>
  )
}

/** A healthy workload in one line: its chain as a glyph, a dot per pod, its
 *  guards, its health word. Selecting it draws it in full. */
function MiniRow({ card, onExpand, onOpen }: { card: MapCard; onExpand: () => void; onOpen: (n: MapNode) => void }) {
  const workload = card.lanes.workload[0]
  return (
    <li className="nsmap-mini">
      <button type="button" className="nsmap-mini-name" aria-expanded={false} onClick={onExpand} title={`Draw ${card.title} in full`}>
        <span aria-hidden="true">▸</span> {card.title}
      </button>
      <span className="nsmap-mini-chain" aria-hidden="true">
        {card.lanes.entry.length > 0 && (
          <>
            <span className="nsmap-mini-box">{card.lanes.entry[0].kind === 'Ingress' ? 'Ing' : 'Route'}</span>→
          </>
        )}
        {card.lanes.service.length > 0 && (
          <>
            <span className="nsmap-mini-box">Svc{card.lanes.service.length > 1 ? ` ×${card.lanes.service.length}` : ''}</span>→
          </>
        )}
        <span className="nsmap-mini-box">
          {workload ? `${card.kind ?? workload.kind}${workload.detail ? ` ${workload.detail.replace(/ ready$/, '')}` : ''}` : card.title}
        </span>
        {card.pods > 0 && '→'}
      </span>
      <PodDots card={card} />
      <Guards card={card} onOpen={onOpen} />
      <span className="nsmap-mini-health">{HEALTH_WORD[card.health]}</span>
    </li>
  )
}

function MapBody({
  model,
  namespace,
  incidents,
  openIncidents,
  clusterNodes,
  filters,
  onFilters,
  onOpen,
  fileName,
}: {
  model: NamespaceMapModel
  namespace: string
  incidents: readonly Incident[]
  /** Open incidents in this namespace. The map shows LIVE health, which can be
   *  fine while incidents are still open (the object recovered, nobody closed
   *  them), so the header names both. */
  openIncidents: number
  clusterNodes: number
  filters: ReadonlySet<KindFilter>
  onFilters: (f: ReadonlySet<KindFilter>) => void
  onOpen: (n: MapNode) => void
  fileName: string
}) {
  const [query, setQuery] = useState('')
  const [overrides, setOverrides] = useState<Record<string, boolean>>({})
  const [exportError, setExportError] = useState<string | null>(null)
  const mapRef = useRef<HTMLDivElement>(null)
  const counts = mapStatusCounts(model.cards)
  const pods = model.cards.reduce((n, c) => n + c.pods, 0)
  const byCard = useMemo(() => new Map(model.cards.map((c) => [c.key, cardIncidents(c, namespace, incidents)])), [model.cards, namespace, incidents])
  const visible = model.cards.filter((c) => cardMatches(c, query))
  const attention = (c: MapCard) => c.problem || (byCard.get(c.key)?.length ?? 0) > 0
  const isExpanded = (c: MapCard) => overrides[c.key] ?? (query.trim() !== '' || attention(c))
  const full = visible.filter(isExpanded)
  const mini = visible.filter((c) => !isExpanded(c))
  const notHealthyNow = counts.workloadsNotHealthy

  const toggleFilter = (f: KindFilter) => {
    const next = new Set(filters)
    if (next.has(f)) next.delete(f)
    else next.add(f)
    onFilters(next)
  }

  const exportPng = async () => {
    setExportError(null)
    if (!mapRef.current) return
    try {
      const background = getComputedStyle(document.documentElement).getPropertyValue('--bg').trim() || undefined
      const url = await toPng(mapRef.current, { backgroundColor: background, pixelRatio: 2 })
      const a = document.createElement('a')
      a.href = url
      a.download = fileName
      document.body.appendChild(a)
      a.click()
      a.remove()
    } catch {
      setExportError('The image could not be produced in this browser.')
    }
  }

  return (
    <>
      <div className="nsmap-head">
        <h3>{namespace}</h3>
        <span className="text-muted">
          {counts.workloads} workload{counts.workloads === 1 ? '' : 's'} · {pods} pod{pods === 1 ? '' : 's'}
          {clusterNodes ? ` · ${clusterNodes} node${clusterNodes === 1 ? '' : 's'}` : ''}
        </span>
        <span className="nsmap-head-status" role="status">
          {openIncidents > 0 && (
            <span className="severity-cell sev-critical">
              <span className="severity-chip" aria-hidden="true" />
              {openIncidents} open incident{openIncidents === 1 ? '' : 's'}
            </span>
          )}
          <span className={notHealthyNow ? 'nsmap-head-bad' : 'text-muted'}>
            {openIncidents > 0 ? ', ' : ''}
            {notHealthyNow} not healthy now
          </span>
        </span>
      </div>
      <div className="nsmap-toolbar">
        <div className="nsmap-filters" role="group" aria-label="Show kinds">
          {KIND_FILTERS.map((f) => (
            <button
              key={f.id}
              type="button"
              className="nsmap-filter"
              aria-pressed={filters.has(f.id)}
              // None of this kind exist here: nothing to show or hide.
              disabled={model.filterCounts[f.id] === 0}
              title={model.filterCounts[f.id] === 0 ? `No ${f.label.toLowerCase()} in this namespace` : undefined}
              onClick={() => toggleFilter(f.id)}
            >
              <span className="nsmap-filter-mark" aria-hidden="true" />
              {f.label} <span className="nsmap-filter-count">{model.filterCounts[f.id]}</span>
            </button>
          ))}
        </div>
        <div className="nsmap-actions">
          <label className="visually-hidden" htmlFor="nsmap-search">
            Find a workload or object
          </label>
          <input
            id="nsmap-search"
            type="search"
            className="nsmap-search"
            placeholder="Find a workload or object"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <button type="button" className="secondary" onClick={() => setOverrides(Object.fromEntries(model.cards.map((c) => [c.key, true])))}>
            Expand all
          </button>
          <button type="button" className="secondary" onClick={exportPng}>
            Export as PNG
          </button>
        </div>
      </div>
      {exportError && (
        <p className="form-error" role="alert">
          {exportError}
        </p>
      )}
      <div ref={mapRef} className="nsmap">
        {visible.length === 0 ? (
          <p className="empty-state">
            No workload or object in {namespace} matches “{query.trim()}”.{' '}
            <button type="button" className="link-button" onClick={() => setQuery('')}>
              Clear the search
            </button>
          </p>
        ) : (
          <>
            {full.length > 0 && (
              <>
                <h4 className="nsmap-section">
                  {query.trim() ? `Matching “${query.trim()}”` : full.every(attention) ? 'Needs attention' : 'Drawn in full'} · {full.length}
                </h4>
                <div className="nsmap-lane-head" aria-hidden="true">
                  {LANES.map((l) => (
                    <span key={l}>{LANE_LABEL[l]}</span>
                  ))}
                </div>
                <div className="nsmap-cards">
                  {full.map((c) => (
                    <Card
                      key={c.key}
                      card={c}
                      incidents={byCard.get(c.key) ?? []}
                      onCollapse={() => setOverrides((o) => ({ ...o, [c.key]: false }))}
                      onOpen={onOpen}
                      query={query}
                    />
                  ))}
                </div>
              </>
            )}
            {mini.length > 0 && (
              <>
                <h4 className="nsmap-section">
                  {mini.every((c) => !attention(c)) ? 'Healthy, no incident' : 'Collapsed'} · {mini.length}
                </h4>
                <ul className="nsmap-minis">
                  {mini.map((c) => (
                    <MiniRow key={c.key} card={c} onOpen={onOpen} onExpand={() => setOverrides((o) => ({ ...o, [c.key]: true }))} />
                  ))}
                </ul>
              </>
            )}
            {model.shared.length > 0 && (
              <p className="nsmap-shared">
                <span className="text-muted">Shared: </span>
                {model.shared.map((x, i) => (
                  <span key={x.node.id}>
                    {i > 0 ? ' · ' : ''}
                    <button type="button" className="link-button fleet-mono" onClick={() => onOpen(x.node)}>
                      {x.node.kind} {x.node.name}
                    </button>{' '}
                    <span className="text-muted">
                      guards {x.workloads} workloads · {HEALTH_WORD[x.node.health]}
                    </span>
                  </span>
                ))}
              </p>
            )}
          </>
        )}
      </div>
    </>
  )
}
