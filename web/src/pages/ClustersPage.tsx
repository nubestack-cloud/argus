import { useState } from 'react'
import { ListFreshness } from '../components/ListFreshness'
import { Link, useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { acceptCluster, renameCluster, getClusterGroups, getClusters, getIncidents, ApiError } from '../api/client'
import { CAP_CLUSTER_ACCEPT, CAP_CLUSTER_DELETE, CAP_CLUSTER_ONBOARD } from '../api/capabilities'
import type { Cluster, ClusterState } from '../api/types'
import { useAuth } from '../auth/useAuth'
import { useHasCapability } from '../auth/useCapabilities'
import { formatDateTime, formatRelativeTime } from '../utils/time'
import { EnrollTokenModal } from '../components/EnrollTokenModal'
import { FleetTokensDialog } from '../components/FleetTokensDialog'
import { ConfirmDecommissionModal } from '../components/ConfirmDecommissionModal'
import { ConfirmBulkDecommissionModal } from '../components/ConfirmBulkDecommissionModal'
import { BulkActionBar } from '../components/BulkActionBar'
import { SkeletonTableRows } from '../components/Skeleton'
import { HelpTip } from '../components/HelpTip'
import { EmptyState } from '../components/EmptyState'
import { PlusIcon, SearchIcon, SortIcon } from '../components/icons'
// Paging is shared with IncidentsPage and ClusterDetailPage now (BUGS.md 57):
// this page and IncidentsPage held character-identical copies of it, and the
// third list that needed it made that a bad way to keep them identical.
import { TablePagination } from '../components/TablePagination'
import { isClosedIncidentState } from '../utils/incidents'
import { isReportingToArgus } from '../utils/clusters'
import { ClusterStateBadge } from '../components/ClusterBadges'
import { FleetCoverageBanner } from '../components/FleetCoverageBanner'
import { AgentCompatibilityBadge } from '../components/AgentCompatibilityBadge'
import { CLUSTER_FAULT_LINE, CLUSTER_STATE_LABEL, COMPATIBILITY_VERDICT_LABEL } from '../api/types'
import type { AgentCompatibilityVerdict } from '../api/types'
import { useUrlPagination } from '../fleet/useUrlPagination'
import { useRowNavigation } from '../fleet/useRowNavigation'
import { shortClusterId } from '../utils/clusters'
import { Dialog } from '../components/Dialog'
import { ActionMenu } from '../components/ActionMenu'
import { LIVE_FALLBACK_MS } from '../realtime/refresh'
import { useUrlParam } from '../hooks/useUrlState'
import { UpgradeVerdictCell } from '../fleet/FleetUpgradeColumn'
import { upgradeColumnHeading, useFleetUpgradeScans } from '../fleet/fleetUpgrade'

type ColorFamily = 'green' | 'amber' | 'blue' | 'red' | 'gray'
// `unreported` replaced a narrower `disconnected` view, and `retired` is new.
//
// `disconnected` matched exactly one state, which turned out to be the wrong
// question: an operator asking "what can't ARGUS see?" also needs the
// Provisioning cluster that never finished enrolling and the one this hub
// refuses on version grounds. `unreported` is the complement of Active
// (isReportingToArgus), which is the same set FleetCoverageBanner counts —
// deliberately the same expression, so the banner's number and this view's
// count cannot drift apart. Nothing became unreachable: the state <select>
// still offers "Disconnected" on its own.
//
// `retired` is the route to decommissioned clusters (`archived_at IS NOT
// NULL`), which had no route at all before — the state existed, the hub
// filtered them out of every response, and the UI could not show one.
type QuickView = 'all' | 'attention' | 'pending' | 'unreported' | 'retired'

// The same five values, as data, so ?view= can be validated against them
// without a second hand-maintained list that would drift from the type.
const QUICK_VIEWS: QuickView[] = ['all', 'attention', 'pending', 'unreported', 'retired']
type SortKey = 'name' | 'state' | 'version' | 'compatibility' | 'incidents' | 'heartbeat'
type SortDirection = 'asc' | 'desc'
const SORT_KEYS: SortKey[] = ['name', 'state', 'version', 'compatibility', 'incidents', 'heartbeat']
const SORT_DIRECTIONS: SortDirection[] = ['asc', 'desc']

const STATE_COLOR: Record<ClusterState, ColorFamily> = {
  PendingApproval: 'amber',
  Provisioning: 'blue',
  Active: 'green',
  Degraded: 'amber',
  Disconnected: 'gray',
  IncompatibleVersion: 'red',
  Rejected: 'red',
  Archived: 'gray',
}

const STATE_ORDER: ClusterState[] = [
  'PendingApproval',
  'Degraded',
  'Disconnected',
  'IncompatibleVersion',
  'Provisioning',
  'Active',
  'Rejected',
  'Archived',
]

const ATTENTION_STATES: ReadonlyArray<ClusterState> = [
  'PendingApproval',
  'Degraded',
  'Disconnected',
  'IncompatibleVersion',
  'Rejected',
]
const TERMINAL_CLUSTER_STATES: ReadonlyArray<ClusterState> = ['Archived', 'Rejected']

// T16. Most-needing-attention first, matching STATE_ORDER's own convention
// just above (PendingApproval/Degraded/Disconnected before Active) — the
// same reasoning applies: an ascending sort or a top-to-bottom filter list
// should read as "what needs looking at" first, not alphabetically.
const COMPATIBILITY_VERDICT_ORDER: AgentCompatibilityVerdict[] = [
  'upgrade_required',
  'upgrade_recommended',
  'unknown',
  'current',
]

// A cluster has no severity, so the rule on the row's left edge (BACKLOG D7;
// .design/ListAndQueue.dc.html, archetype A) is derived from the one signal it
// does have — its state — through the SAME colour family the state badge in
// the next column uses. Deriving it from STATE_COLOR rather than writing a
// second state->severity table is the point: the rule and the badge are two
// marks for one fact and can never come to disagree about it.
//
// Blue (Provisioning) maps to neutral because there is no `.sev-blue`, and a
// cluster mid-enrollment is genuinely "not yet a health signal" rather than a
// fifth severity — which is exactly what `.sev-neutral` is for.
const SEVERITY_RULE_CLASS: Record<ColorFamily, string> = {
  green: 'sev-low',
  amber: 'sev-medium',
  red: 'sev-critical',
  gray: 'sev-neutral',
  blue: 'sev-neutral',
}

// CLUSTER_FAULT_LINE itself now lives in api/types.ts, beside
// CLUSTER_STATE_LABEL (BACKLOG D7i) — ClusterDetailPage needed the same
// per-state fault sentence this page already computed, and a page-local
// const isn't importable from a sibling page without either duplicating it
// (the exact drift D7f's ROLE_LABELS/CLUSTER_STATE_LABEL merges were about)
// or reaching into this file directly.

function AcceptButton({ clusterId, disabledReason }: { clusterId: string; disabledReason?: string }) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const mutation = useMutation({
    mutationFn: () => acceptCluster(clusterId, accessToken!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['clusters'] }),
  })

  return (
    <div className="cluster-accept-action">
      <button
        type="button"
        className="cluster-row-primary-action"
        onClick={() => mutation.mutate()}
        disabled={mutation.isPending || !!disabledReason}
        title={disabledReason}
      >
        {mutation.isPending ? 'Accepting…' : 'Accept'}
      </button>
      {mutation.isError && (
        <span className="form-error cluster-row-error" role="alert">
          {mutation.error instanceof ApiError ? mutation.error.message : 'Accept failed.'}
        </span>
      )}
    </div>
  )
}

function RenameClusterModal({
  clusterId,
  currentName,
  onClose,
}: {
  clusterId: string
  currentName: string
  onClose: () => void
}) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const [displayName, setDisplayName] = useState(currentName)

  const mutation = useMutation({
    mutationFn: () => renameCluster(clusterId, displayName.trim(), accessToken!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['clusters'] })
      onClose()
    },
  })

  const trimmed = displayName.trim()

  return (
    <Dialog title="Rename cluster" onClose={onClose}>
        <form
          onSubmit={(event) => {
            event.preventDefault()
            if (trimmed) mutation.mutate()
          }}
        >
          <label htmlFor="rename-cluster-name">Display name</label>
          <input
            id="rename-cluster-name"
            type="text"
            value={displayName}
            onChange={(event) => setDisplayName(event.target.value)}
            autoComplete="off"
            autoFocus
            maxLength={200}
          />

          {mutation.isError && (
            <p className="form-error" role="alert">
              {mutation.error instanceof ApiError
                ? mutation.error.detail
                  ? `${mutation.error.message} — ${mutation.error.detail}`
                  : mutation.error.message
                : 'Something went wrong.'}
            </p>
          )}

          <div className="modal-actions">
            <button type="button" className="secondary" onClick={onClose}>
              Cancel
            </button>
            <button type="submit" disabled={!trimmed || mutation.isPending}>
              {mutation.isPending ? 'Saving…' : 'Save'}
            </button>
          </div>
        </form>
    </Dialog>
  )
}

function ClusterQuickView({ cluster, incidentCount, onClose }: { cluster: Cluster; incidentCount?: number; onClose: () => void }) {
  return (
    <Dialog title="Cluster summary" onClose={onClose}>
        <dl className="fact-list">
          <dt>Name</dt>
          <dd>{cluster.displayName}</dd>
          <dt>State</dt>
          <dd><ClusterStateBadge withDot state={cluster.state} /></dd>
          <dt>Agent version</dt>
          <dd>{cluster.agentVersion ?? '—'}</dd>
          <dt>Compatibility</dt>
          <dd><AgentCompatibilityBadge compatibility={cluster.compatibility} /></dd>
          <dt>Open incidents</dt>
          <dd>{incidentCount ?? 'Unavailable'}</dd>
          <dt>Last heartbeat</dt>
          <dd title={cluster.lastHeartbeatAt ?? undefined}>{formatRelativeTime(cluster.lastHeartbeatAt)}</dd>
          <dt>Created</dt>
          <dd title={formatDateTime(cluster.createdAt)}>{formatDateTime(cluster.createdAt)}</dd>
        </dl>

        <div className="modal-actions">
          <Link to={`/clusters/${cluster.id}`} onClick={onClose}>View full cluster →</Link>
        </div>
    </Dialog>
  )
}

function SortableHeader({
  label,
  sortKey,
  activeKey,
  direction,
  onSort,
  className,
}: {
  label: string
  sortKey: SortKey
  activeKey: SortKey
  direction: SortDirection
  onSort: (key: SortKey) => void
  className?: string
}) {
  const active = sortKey === activeKey
  return (
    <th className={className} aria-sort={active ? (direction === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button type="button" className="cluster-sort-button" onClick={() => onSort(sortKey)}>
        {label}
        <SortIcon direction={active ? direction : undefined} />
      </button>
    </th>
  )
}

export function ClustersPage() {
  const { accessToken } = useAuth()
  const navigate = useNavigate()
  const [enrollOpen, setEnrollOpen] = useState(false)
  const [fleetTokensOpen, setFleetTokensOpen] = useState(false)
  const [quickViewCluster, setQuickViewCluster] = useState<Cluster | null>(null)
  const [renamingCluster, setRenamingCluster] = useState<Cluster | null>(null)
  const [decommissioningCluster, setDecommissioningCluster] = useState<Cluster | null>(null)
  // Bulk selection (BUGS.md's owner note). Ids only, not full Cluster
  // objects — the selected set survives a refetch (on every cluster event,
  // and on clustersQuery's fallback interval) that way, since ids are stable
  // and a Cluster object from the previous fetch would go stale under it.
  const [selectedClusterIds, setSelectedClusterIds] = useState<Set<string>>(new Set())
  const [bulkDecommissioning, setBulkDecommissioning] = useState(false)
  // Seeded from ?view=, so a quick view is a real address rather than a
  // selection only reachable by clicking. The Overview's coverage banner links
  // straight to ?view=unreported, and before this it navigated here and landed
  // on an unfiltered list — a control that said "Show them" and showed
  // everything.
  //
  // Validated against QUICK_VIEWS rather than cast: the value arrives from the
  // URL bar, so an unrecognised one falls back to 'all' instead of selecting a
  // tab that does not exist and filtering every row out. Read once, as the
  // initial value — this is a starting point, not a binding, so clicking
  // another tab afterwards does not have to fight the address.
  // CI-U5: every filter, the sort and the page live in the URL, so a link
  // reproduces the view. useUrlParam keeps these useState-shaped; an
  // unrecognised value (an old or hand-edited link) reads as the default.
  const [quickView, setQuickView] = useUrlParam<QuickView>('view', 'all', QUICK_VIEWS)
  const [search, setSearch] = useUrlParam<string>('q', '')
  const [stateFilter, setStateFilter] = useUrlParam<ClusterState | ''>('state', '')
  const [versionFilter, setVersionFilter] = useUrlParam<string>('version', '')
  const [compatibilityFilter, setCompatibilityFilter] = useUrlParam<AgentCompatibilityVerdict | ''>('compat', '')
  const [groupFilter, setGroupFilter] = useUrlParam<string>('group', '')
  const [sortKey, setSortKey] = useUrlParam<SortKey>('sort', 'name', SORT_KEYS)
  const [sortDirection, setSortDirection] = useUrlParam<SortDirection>('dir', 'asc', SORT_DIRECTIONS)

  const canOnboard = useHasCapability(CAP_CLUSTER_ONBOARD)
  const canAccept = useHasCapability(CAP_CLUSTER_ACCEPT)
  const canDecommission = useHasCapability(CAP_CLUSTER_DELETE)

  // ClusterUpdated (accept, decommission, health demotion, heartbeat
  // recovery, first enroll) and IncidentUpdated drive both queries below;
  // the intervals are the fallback for an undelivered event — see
  // realtime/refresh.ts.
  const clustersQuery = useQuery({
    queryKey: ['clusters'],
    queryFn: () => getClusters(accessToken!),
    enabled: !!accessToken,
    refetchInterval: LIVE_FALLBACK_MS,
  })
  // The retired fleet, fetched separately and NEVER merged into the array
  // above. Two queries rather than one `?archived=include` call because the
  // separation is the feature: `clusters` below is the live fleet by
  // construction, so no count, quick view, filter or banner on this page can
  // accidentally include a decommissioned cluster — there is no partition
  // step that could be got wrong, and the hub's own default is what keeps
  // every OTHER screen's cluster picker clean for the same reason.
  //
  // No refetchInterval: a cluster becomes retired only through an explicit
  // decommission, and every path that performs one invalidates ['clusters'],
  // which prefix-matches this key and refetches it. Polling a list that
  // changes a handful of times a year every five seconds would be waste.
  const archivedClustersQuery = useQuery({
    queryKey: ['clusters', 'archived'],
    queryFn: () => getClusters(accessToken!, 'only'),
    enabled: !!accessToken,
  })
  const incidentsQuery = useQuery({
    queryKey: ['incidents'],
    queryFn: () => getIncidents(accessToken!),
    enabled: !!accessToken,
    refetchInterval: LIVE_FALLBACK_MS,
  })
  // CI-S5: each cluster's latest stored upgrade scan, for the upgrade column.
  const upgradeScans = useFleetUpgradeScans()
  const upgradeHeading = upgradeColumnHeading(upgradeScans.byCluster.values())
  const upgradeShowTarget = upgradeHeading === 'Next upgrade'
  // BACKLOG.md S3: cluster groups exist now (Settings → Roles & access
  // manages them). Read-only here, on purpose — this screen's own mode is
  // triage scan, not administration, so it gets a filter and a quiet
  // per-row line, never a management control.
  const clusterGroupsQuery = useQuery({
    queryKey: ['clusterGroups'],
    queryFn: () => getClusterGroups(accessToken!),
    enabled: !!accessToken,
  })

  // The live fleet. Every count, filter and banner on this page derives from
  // this array, and the hub guarantees it holds no retired cluster.
  const clusters = clustersQuery.data?.clusters ?? []
  const archivedClusters = archivedClustersQuery.data?.clusters ?? []
  // Retired clusters are shown, never merged: the table swaps its source
  // array rather than filtering one combined list, so "the retired view" and
  // "the fleet" cannot leak into each other. Both routes in — the quick view
  // and picking Archived in the state <select> — land here, so neither is a
  // control that silently matches nothing.
  const showingRetired = quickView === 'retired' || stateFilter === 'Archived'
  // Which query the table is actually waiting on — the retired view is fed
  // by its own request, so a skeleton driven by the live-fleet query alone
  // would show an empty table body while the retired list is still in
  // flight, which reads as "there are none".
  const listLoading = showingRetired ? archivedClustersQuery.isLoading : clustersQuery.isLoading
  const clusterGroups = clusterGroupsQuery.data?.clusterGroups ?? []
  // Every group this cluster belongs to, by name — most clusters belong to
  // none, which is why the identity cell below only ever adds a line when
  // this is non-empty rather than always reserving the space.
  const groupNamesByClusterId = new Map<string, string[]>()
  for (const group of clusterGroups) {
    for (const clusterId of group.clusterIds) {
      const names = groupNamesByClusterId.get(clusterId) ?? []
      names.push(group.name)
      groupNamesByClusterId.set(clusterId, names)
    }
  }
  const incidents = incidentsQuery.data?.incidents ?? []
  // BACKLOG D7c. GET /incidents is capped (defaultIncidentPageLimit) and says so
  // with nextCursor. This page never read it, so on a busy fleet the column
  // silently undercounted — and a cluster whose incidents all fell past the cap
  // rendered a literal `0`, which is the worst possible answer: indistinguishable
  // from "this cluster is healthy". A count over a truncated fetch is a floor,
  // not a total, and has to say so.
  const incidentsTruncated = !!incidentsQuery.data?.nextCursor
  const openIncidentCounts = incidents.reduce<Record<string, number>>((counts, incident) => {
    // Not closed, rather than "needs action": this column is how much live
    // incident load a cluster is carrying, which includes the ones ARGUS is
    // mid-investigation on. isClosedIncidentState (utils/incidents.ts) is the
    // one definition of closed, shared with the overview and the incident list.
    if (!isClosedIncidentState(incident.state)) {
      counts[incident.clusterId] = (counts[incident.clusterId] ?? 0) + 1
    }
    return counts
  }, {})

  // Every count here is over the LIVE fleet except `retired`, which is the
  // only one over the retired list — the two sets are disjoint by
  // construction (see the two queries above), so no row is counted twice and
  // a decommissioned cluster cannot inflate "Needs attention" or
  // "Not reporting".
  const quickViewCounts: Record<QuickView, number> = {
    all: clusters.length,
    attention: clusters.filter((cluster) => ATTENTION_STATES.includes(cluster.state)).length,
    pending: clusters.filter((cluster) => cluster.state === 'PendingApproval').length,
    unreported: clusters.filter((cluster) => !isReportingToArgus(cluster)).length,
    retired: archivedClusters.length,
  }
  // A count from a query that has not succeeded is an em dash, never a
  // number — ListFreshness's rule for the header, applied to the one count
  // on this page that comes from its own independently-failable request. A
  // `0` beside "Retired" would assert that nothing has ever been
  // decommissioned, which a failed fetch is no evidence of.
  const quickViewCountUnknown: Record<QuickView, boolean> = {
    all: clustersQuery.isLoading,
    attention: clustersQuery.isLoading,
    pending: clustersQuery.isLoading,
    unreported: clustersQuery.isLoading,
    retired: archivedClustersQuery.isLoading || archivedClustersQuery.isError,
  }
  const versions = Array.from(
    new Set(
      (showingRetired ? archivedClusters : clusters)
        .map((cluster) => cluster.agentVersion)
        .filter((version): version is string => !!version),
    ),
  ).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))

  // The version list is derived from the current clusters, so a selected
  // version can stop existing under the filter's feet — the last cluster on
  // v0.3.1 upgrades or is decommissioned, and `versionFilter` still holds
  // "v0.3.1". The <select> then has no matching <option> and renders blank
  // ("All agent versions"), while the filter keeps excluding every row: a
  // "0 results" table under a filter bar that says nothing is filtered.
  // Falling back to '' the moment the value leaves the option list keeps the
  // control and the result set describing the same thing. Same shape as
  // OverviewPage's effectiveScope, which solves this for its cluster picker.
  // stateFilter needs no equivalent — it's a fixed enum, not data-derived.
  const effectiveVersionFilter = versionFilter && versions.includes(versionFilter) ? versionFilter : ''
  // The compatibility verdicts present in the listed fleet — the dropdown is
  // offered only when there is more than one to choose between.
  const verdicts = Array.from(
    new Set((showingRetired ? archivedClusters : clusters).map((cluster) => cluster.compatibility.verdict)),
  )

  const normalizedSearch = search.trim().toLocaleLowerCase()
  const filteredClusters = (showingRetired ? archivedClusters : clusters)
    .filter((cluster) => {
      if (quickView === 'attention' && !ATTENTION_STATES.includes(cluster.state)) return false
      if (quickView === 'pending' && cluster.state !== 'PendingApproval') return false
      // The same predicate FleetCoverageBanner counts with, imported rather
      // than restated — the banner's "N of M are not reporting" and this
      // view's N are one expression evaluated twice, not two rules.
      if (quickView === 'unreported' && isReportingToArgus(cluster)) return false
      if (stateFilter && cluster.state !== stateFilter) return false
      if (effectiveVersionFilter && cluster.agentVersion !== effectiveVersionFilter) return false
      if (compatibilityFilter && cluster.compatibility.verdict !== compatibilityFilter) return false
      if (groupFilter && !(groupNamesByClusterId.get(cluster.id) ?? []).includes(groupFilter)) return false
      if (!normalizedSearch) return true
      return [cluster.displayName, cluster.id, cluster.agentVersion ?? ''].some((value) =>
        value.toLocaleLowerCase().includes(normalizedSearch),
      )
    })
    .sort((left, right) => {
      let comparison = 0
      if (sortKey === 'name') comparison = left.displayName.localeCompare(right.displayName)
      if (sortKey === 'state') comparison = STATE_ORDER.indexOf(left.state) - STATE_ORDER.indexOf(right.state)
      if (sortKey === 'version') comparison = (left.agentVersion ?? '').localeCompare(right.agentVersion ?? '', undefined, { numeric: true })
      if (sortKey === 'compatibility') {
        comparison =
          COMPATIBILITY_VERDICT_ORDER.indexOf(left.compatibility.verdict) -
          COMPATIBILITY_VERDICT_ORDER.indexOf(right.compatibility.verdict)
      }
      if (sortKey === 'incidents') comparison = (openIncidentCounts[left.id] ?? 0) - (openIncidentCounts[right.id] ?? 0)
      if (sortKey === 'heartbeat') {
        comparison = (left.lastHeartbeatAt ? Date.parse(left.lastHeartbeatAt) : 0) - (right.lastHeartbeatAt ? Date.parse(right.lastHeartbeatAt) : 0)
      }
      if (comparison === 0) comparison = left.displayName.localeCompare(right.displayName)
      return sortDirection === 'asc' ? comparison : -comparison
    })

  const { visibleItems: visibleClusters, resetToFirstPage: resetPageOnly, pagination } = useUrlPagination(filteredClusters)
  // Wraps usePagination's own resetToFirstPage so every existing call site
  // (search box, every filter <select>, every quick-view button, and
  // changeSort below) also clears the bulk selection for free — narrowing or
  // reordering the table out from under a set of checked ids would otherwise
  // leave "N selected" describing rows the operator can no longer see. Page
  // navigation on its own (TablePagination's onPageChange) deliberately does
  // NOT go through this, so paging through a selection keeps it intact.
  const resetToFirstPage = () => {
    resetPageOnly()
    setSelectedClusterIds(new Set())
  }
  const changeSort = (nextKey: SortKey) => {
    if (sortKey === nextKey) {
      setSortDirection((current) => (current === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortKey(nextKey)
      setSortDirection(nextKey === 'incidents' || nextKey === 'heartbeat' ? 'desc' : 'asc')
    }
    resetToFirstPage()
  }

  const clearFilters = () => {
    setQuickView('all')
    setSearch('')
    setStateFilter('')
    setVersionFilter('')
    setCompatibilityFilter('')
    setGroupFilter('')
    resetToFirstPage()
  }

  // A cluster already Archived/Rejected 409s from handleDecommissionCluster
  // (already in a terminal state) — excluded from selection entirely, with
  // its checkbox disabled and titled, rather than silently included and left
  // to fail with no explanation (the task's own "no fabricated data" rule).
  const isBulkDecommissionEligible = (cluster: Cluster) => !TERMINAL_CLUSTER_STATES.includes(cluster.state)
  const eligibleVisibleClusters = visibleClusters.filter(isBulkDecommissionEligible)
  // Row click, j/k and Enter open a cluster, the same as the Incidents,
  // Signals and Search lists.
  const rowNav = useRowNavigation({
    count: listLoading ? 0 : visibleClusters.length,
    onOpen: (i) => {
      const c = visibleClusters[i]
      if (c) navigate(`/clusters/${c.id}`)
    },
    clickToOpen: true,
  })
  const allVisibleEligibleSelected =
    eligibleVisibleClusters.length > 0 && eligibleVisibleClusters.every((cluster) => selectedClusterIds.has(cluster.id))
  const someVisibleEligibleSelected = eligibleVisibleClusters.some((cluster) => selectedClusterIds.has(cluster.id))

  const toggleClusterSelected = (clusterId: string) => {
    setSelectedClusterIds((current) => {
      const next = new Set(current)
      if (next.has(clusterId)) next.delete(clusterId)
      else next.add(clusterId)
      return next
    })
  }

  // Selects/deselects every ELIGIBLE row currently on screen — never a
  // terminal-state one, and never a row filtered or paginated out of view,
  // which "select all" should not reach behind the operator's back.
  const toggleSelectAllVisible = () => {
    setSelectedClusterIds((current) => {
      const next = new Set(current)
      if (allVisibleEligibleSelected) {
        for (const cluster of eligibleVisibleClusters) next.delete(cluster.id)
      } else {
        for (const cluster of eligibleVisibleClusters) next.add(cluster.id)
      }
      return next
    })
  }

  const selectedClusters = clusters.filter((cluster) => selectedClusterIds.has(cluster.id))

  return (
    <div className="page list-page">
      <header className="page-header list-page-header">
        <div>
          <h1>Clusters</h1>
          {/* Shared with Incidents and Overview: "Live" is only claimed when
              the last fetch succeeded, and a count the query does not have
              renders as an em dash rather than a confident 0. */}
          <ListFreshness
            isError={clustersQuery.isError}
            isFetching={clustersQuery.isFetching}
            updatedAt={clustersQuery.dataUpdatedAt}
            hasData={clustersQuery.data !== undefined}
            count={clusters.length}
            countLabel={clusters.length === 1 ? 'cluster' : 'clusters'}
          />
        </div>
        <div className="page-header-actions">
          <button
            type="button"
            className="secondary"
            onClick={() => setFleetTokensOpen(true)}
            disabled={!canOnboard}
            title={canOnboard ? 'One token for a GitOps rollout to many clusters' : `Missing capability: ${CAP_CLUSTER_ONBOARD}`}
          >
            Fleet tokens
          </button>
          <button
            type="button"
            onClick={() => setEnrollOpen(true)}
            disabled={!canOnboard}
            title={canOnboard ? undefined : `Missing capability: ${CAP_CLUSTER_ONBOARD}`}
          >
            <PlusIcon />
            Enroll a cluster
          </button>
        </div>
      </header>

      {clustersQuery.isError && (
        <p className="form-error" role="alert">
          {clustersQuery.error instanceof ApiError
            ? clustersQuery.error.detail
              ? `${clustersQuery.error.message} — ${clustersQuery.error.detail}`
              : clustersQuery.error.message
            : 'Failed to load clusters.'}
        </p>
      )}

      {/* "Nothing has ever been enrolled" and "the whole fleet has been
          retired" are different facts, and only the first one earns the
          enroll prompt — an install whose clusters are all decommissioned
          still has a retired list to look at, so the page below must not be
          hidden for it. */}
      {!clustersQuery.isLoading && !clustersQuery.isError && clusters.length === 0 && archivedClusters.length === 0 && (
        <EmptyState variant="clusters">No clusters yet. Enroll one to get started.</EmptyState>
      )}

      {(clustersQuery.isLoading || clusters.length > 0 || archivedClusters.length > 0) && !clustersQuery.isError && (
        <>
          {/* The partial-view statement, above the filters: it is a fact
              about the fleet, not about the current view, so it stays put
              whichever quick view is selected. It renders nothing when the
              whole live fleet is reporting, and nothing while the counts
              are unknown — see the component. */}
          {!clustersQuery.isLoading && (
            <FleetCoverageBanner
              clusters={clusters}
              onShowNotReporting={() => {
                setQuickView('unreported')
                setStateFilter('')
                resetToFirstPage()
              }}
            />
          )}


          <section className="list-card" aria-label="Cluster list">
            <div className="list-toolbar">
              {/* The list's views, at the start of its own filter bar (owner, 2026-10-12,
                  "List Filter Layouts" option A): one bar for views and filters, not two. */}
              <nav className="list-quick-views list-quick-views-inbar" aria-label="Cluster quick views">
                {([
                  ['all', 'All'],
                  ['attention', 'Needs attention'],
                  ['pending', 'Pending approval'],
                  ['unreported', 'Not reporting'],
                  ['retired', 'Retired'],
                ] as Array<[QuickView, string]>).map(([value, label]) => (
                  <button
                    key={value}
                    type="button"
                    className={quickView === value ? 'active' : ''}
                    aria-pressed={quickView === value}
                    onClick={() => {
                      setQuickView(value)
                      // Leaving the retired view with stateFilter still on
                      // 'Archived' would silently hold the table there, since
                      // that filter is itself a route into it.
                      if (stateFilter === 'Archived' && value !== 'retired') setStateFilter('')
                      resetToFirstPage()
                    }}
                  >
                    {label}
                    <span
                      className="list-quick-count"
                      title={
                        quickViewCountUnknown[value] && !clustersQuery.isLoading
                          ? 'This count is unknown: the last request for it failed'
                          : undefined
                      }
                    >
                      {quickViewCountUnknown[value] ? '—' : quickViewCounts[value]}
                    </span>
                  </button>
                ))}
              </nav>

              <label className="list-search-field">
                <span className="visually-hidden">Search clusters</span>
                <SearchIcon />
                <input
                  type="search"
                  placeholder="Search by name, ID, or version"
                  value={search}
                  onChange={(event) => {
                    setSearch(event.target.value)
                    resetToFirstPage()
                  }}
                />
              </label>

              {/* No state <select> (owner, 2026-10-12, "List Filter Layouts" option
                  C): the views above already reach every state worth filtering on
                  — Pending approval and Retired directly, Degraded and
                  Disconnected through Needs attention. A ?state= value from an
                  old link is still honoured, and shown as a removable chip so a
                  filter is never applied without being visible. */}
              {stateFilter && (
                <span className="list-active-filter">
                  State: {CLUSTER_STATE_LABEL[stateFilter] ?? stateFilter}
                  <button
                    type="button"
                    aria-label="Clear the state filter"
                    title="Clear the state filter"
                    onClick={() => {
                      setStateFilter('')
                      resetToFirstPage()
                    }}
                  >
                    ×
                  </button>
                </span>
              )}

              {/* Only the filters that can filter: a version or compatibility
                  dropdown with one possible value narrows nothing, so each
                  appears once the fleet has more than one value for it (or a
                  value is already selected, so it can be cleared). */}
              {(versions.length > 1 || !!effectiveVersionFilter) && (
                <label className="list-filter-field clusters-version-filter">
                  <span className="visually-hidden">Filter by agent version</span>
                  <select
                    value={effectiveVersionFilter}
                    onChange={(event) => {
                      setVersionFilter(event.target.value)
                      resetToFirstPage()
                    }}
                  >
                    <option value="">All agent versions</option>
                    {versions.map((version) => <option key={version} value={version}>{version}</option>)}
                  </select>
                </label>
              )}

              {/* T16: the fleet-wide compatibility verdict is filterable the
                  same way version is — a plain <select> driven by the one enum
                  the hub's version policy emits, not a bespoke control. */}
              {(verdicts.length > 1 || !!compatibilityFilter) && (
                <label className="list-filter-field">
                  <span className="visually-hidden">Filter by agent compatibility</span>
                  <select
                    value={compatibilityFilter}
                    onChange={(event) => {
                      setCompatibilityFilter(event.target.value as AgentCompatibilityVerdict | '')
                      resetToFirstPage()
                    }}
                  >
                    <option value="">All compatibility</option>
                    {COMPATIBILITY_VERDICT_ORDER.map((verdict) => (
                      <option key={verdict} value={verdict}>{COMPATIBILITY_VERDICT_LABEL[verdict]}</option>
                    ))}
                  </select>
                </label>
              )}

              {/* BACKLOG.md S3. Only rendered once a group exists at all —
                  an install with no cluster groups gets no dead control. */}
              {clusterGroups.length > 0 && (
                <label className="list-filter-field">
                  <span className="visually-hidden">Filter by cluster group</span>
                  <select
                    value={groupFilter}
                    onChange={(event) => {
                      setGroupFilter(event.target.value)
                      resetToFirstPage()
                    }}
                  >
                    <option value="">All groups</option>
                    {clusterGroups.map((group) => (
                      <option key={group.id} value={group.name}>
                        {group.name}
                      </option>
                    ))}
                  </select>
                </label>
              )}

              {/* BACKLOG D7b. aria-live announced "0 results" during the initial
                  load, before anything had been fetched — the quick-view counts
                  just above already guard with '—' for exactly this reason. */}
              <span className="list-result-count" aria-live="polite">
                {listLoading
                  ? '…'
                  : `${filteredClusters.length} ${filteredClusters.length === 1 ? 'result' : 'results'}`}
              </span>
            </div>

            <BulkActionBar
              count={selectedClusterIds.size}
              itemLabel="cluster"
              onClear={() => setSelectedClusterIds(new Set())}
              actions={[
                {
                  label: `Decommission…`,
                  onClick: () => setBulkDecommissioning(true),
                  disabled: !canDecommission,
                  disabledReason: canDecommission ? undefined : `Missing capability: ${CAP_CLUSTER_DELETE}`,
                  danger: true,
                },
              ]}
            />

            <div className="table-scroll">
              <table className="cluster-table list-table scan-table" aria-busy={listLoading}>
                <thead>
                  <tr>
                    {/* Selection is harmless to render for a viewer without
                        cluster:delete (lld/11 §6's disabled-not-hidden rule
                        is about the ACTION, not the checkbox) — only the
                        bulk-action button above is capability-gated. */}
                    <th className="list-select-heading">
                      <input
                        type="checkbox"
                        className="row-select-checkbox"
                        aria-label="Select all eligible clusters on this page"
                        checked={allVisibleEligibleSelected}
                        ref={(el) => {
                          if (el) el.indeterminate = someVisibleEligibleSelected && !allVisibleEligibleSelected
                        }}
                        disabled={eligibleVisibleClusters.length === 0}
                        title={eligibleVisibleClusters.length === 0 ? 'No eligible clusters on this page' : undefined}
                        onChange={toggleSelectAllVisible}
                      />
                    </th>
                    <SortableHeader label="Cluster" sortKey="name" activeKey={sortKey} direction={sortDirection} onSort={changeSort} />
                    <SortableHeader label="State" sortKey="state" activeKey={sortKey} direction={sortDirection} onSort={changeSort} />
                    <SortableHeader label="Agent version" sortKey="version" activeKey={sortKey} direction={sortDirection} onSort={changeSort} />
                    <SortableHeader label="Compatibility" sortKey="compatibility" activeKey={sortKey} direction={sortDirection} onSort={changeSort} />
                    <SortableHeader label="Open incidents" sortKey="incidents" activeKey={sortKey} direction={sortDirection} onSort={changeSort} className="col-numeric" />
                    <SortableHeader label="Last heartbeat" sortKey="heartbeat" activeKey={sortKey} direction={sortDirection} onSort={changeSort} className="col-time" />
                    {/* Not sortable: a verdict is a closed set with no
                        order the server ranks by, and the column is a
                        pointer into the cluster's Upgrade readiness tab. */}
                    <th className="col-shrink">
                      {upgradeHeading}{' '}
                      <HelpTip
                        label="the upgrade column"
                        text="Each cluster’s latest stored upgrade-readiness verdict for the next Kubernetes minor version. The hub scans each connected cluster daily; Not scanned means no scan has run, not that it passed. Open a verdict for the checks behind it."
                      />
                    </th>
                    <th className="list-actions-heading table-pinned-actions"><span className="visually-hidden">Actions</span></th>
                  </tr>
                </thead>
                <tbody {...rowNav.containerProps}>
                  {listLoading && <SkeletonTableRows columns={9} />}
                  {!listLoading && visibleClusters.map((cluster, rowIndex) => {
                    const openIncidentCount = openIncidentCounts[cluster.id] ?? 0
                    const eligible = isBulkDecommissionEligible(cluster)
                    const nav = rowNav.rowProps(rowIndex)
                    return (
                      <tr
                        key={cluster.id}
                        {...nav}
                        className={[
                          SEVERITY_RULE_CLASS[STATE_COLOR[cluster.state]] ?? 'sev-neutral',
                          cluster.state === 'PendingApproval' ? 'cluster-row-pending' : '',
                          'fleet-row-clickable',
                          nav['aria-current'] ? 'fleet-row-active' : '',
                        ].filter(Boolean).join(' ')}
                      >
                        <td>
                          <input
                            type="checkbox"
                            className="row-select-checkbox"
                            aria-label={`Select ${cluster.displayName}`}
                            checked={selectedClusterIds.has(cluster.id)}
                            disabled={!eligible}
                            title={eligible ? undefined : `Already ${CLUSTER_STATE_LABEL[cluster.state]} — cannot be decommissioned again`}
                            onChange={() => toggleClusterSelected(cluster.id)}
                          />
                        </td>
                        {/* `.severity-rule` reads the --sev-fill the <tr>'s
                            `.sev-*` class set (index.css, "SEVERITY, once"),
                            and carries no padding of its own so it drops onto
                            the padding `.list-table td:first-child`
                            already provides. */}
                        <td className="severity-rule">
                          {/* `.identity-block` is the D7 vocabulary; the page's
                              own `.cluster-identity` stays alongside it for the
                              two things the shared class does not define — the
                              column's max-width and the link chrome
                              (`.cluster-identity a`: no underline at rest,
                              accent + underline on hover, ellipsis). The two
                              elements differ on purpose: `.cluster-identity
                              span` adds monospace and one-line ellipsis, which
                              is what the ID line wants and what the fault line
                              must not have — so the fault line is a <div>,
                              outside that selector, rather than the
                              vocabulary's <span>. */}
                          <div className="cluster-identity identity-block">
                            <Link className="identity-block-name" to={`/clusters/${cluster.id}`}>{cluster.displayName}</Link>
                            {/* The tail, not the head: a ULID's first characters
                                are its creation time, so clusters enrolled the
                                same day shared one truncated "cl_01m3p". The
                                last eight are random and tell them apart; the
                                whole id is the title and on the detail page. */}
                            <span className="identity-block-kind" title={cluster.id}>ID {shortClusterId(cluster.id)}</span>
                            {/* BACKLOG.md S3. Only a cluster that actually belongs
                                to a group gets this line — the common case (no
                                groups configured, or this cluster in none) adds
                                nothing rather than reserving space for an empty
                                fact. Managed from Settings → Roles & access, not
                                here — this screen's mode is triage, not admin. */}
                            {(groupNamesByClusterId.get(cluster.id) ?? []).length > 0 && (
                              <span className="identity-block-kind">
                                Group: {(groupNamesByClusterId.get(cluster.id) ?? []).join(', ')}
                              </span>
                            )}
                            {/* WHEN it was retired, which is the fact a
                                retirement list is actually consulted for
                                ("was this one taken out before or after the
                                incident I am reading about?"). The date
                                comes from the hub's archivedAt, never
                                inferred from the state string. */}
                            {cluster.archivedAt && (
                              <span className="identity-block-kind" title={formatDateTime(cluster.archivedAt)}>
                                Retired {formatRelativeTime(cluster.archivedAt)}
                              </span>
                            )}
                            {CLUSTER_FAULT_LINE[cluster.state] && (
                              <div className="identity-block-fault">{CLUSTER_FAULT_LINE[cluster.state]}</div>
                            )}
                          </div>
                        </td>
                        <td><ClusterStateBadge withDot state={cluster.state} /></td>
                        <td><span className="cluster-version">{cluster.agentVersion ?? '—'}</span></td>
                        <td><AgentCompatibilityBadge withDot compatibility={cluster.compatibility} /></td>
                        <td className="col-numeric">
                          {incidentsQuery.isLoading || incidentsQuery.isError ? (
                            <span
                              className="text-muted"
                              title={incidentsQuery.isLoading ? 'Incident counts are loading' : 'Incident counts are unavailable'}
                            >
                              —
                            </span>
                          ) : openIncidentCount > 0 ? (
                            <Link
                              className="cluster-incident-count"
                              to={`/clusters/${cluster.id}`}
                              title={incidentsTruncated ? 'At least this many — the incident list was truncated' : undefined}
                            >
                              {openIncidentCount}{incidentsTruncated ? '+' : ''}
                            </Link>
                          ) : incidentsTruncated ? (
                            // Not `0`. The count came from a truncated fetch, so
                            // "none found in what we loaded" is all this can
                            // honestly say — and a bare 0 would read as healthy.
                            <Link
                              className="text-muted"
                              to={`/clusters/${cluster.id}`}
                              title="The incident list was truncated, so a zero here is not proof this cluster has none"
                            >
                              —
                            </Link>
                          ) : (
                            <span className="cluster-incident-zero">0</span>
                          )}
                        </td>
                        <td className="col-time" title={cluster.lastHeartbeatAt ? formatDateTime(cluster.lastHeartbeatAt) : undefined}>
                          {formatRelativeTime(cluster.lastHeartbeatAt)}
                        </td>
                        <td className="col-shrink">
                          <UpgradeVerdictCell
                            clusterId={cluster.id}
                            scan={upgradeScans.byCluster.get(cluster.id)}
                            loading={upgradeScans.query.isLoading}
                            failed={upgradeScans.query.isError}
                            showTarget={upgradeShowTarget}
                          />
                        </td>
                        <td className="table-pinned-actions">
                          <div className="cluster-row-actions">
                            {cluster.state === 'PendingApproval' && (
                              <AcceptButton
                                clusterId={cluster.id}
                                disabledReason={canAccept ? undefined : `Missing capability: ${CAP_CLUSTER_ACCEPT}`}
                              />
                            )}
                            <ActionMenu
                              ariaLabel={`Actions for ${cluster.displayName}`}
                              items={[
                                { label: 'View details', onClick: () => navigate(`/clusters/${cluster.id}`) },
                                { label: 'Quick view', onClick: () => setQuickViewCluster(cluster) },
                                {
                                  label: 'Rename',
                                  onClick: () => setRenamingCluster(cluster),
                                  disabled: !canOnboard,
                                  disabledReason: canOnboard ? undefined : `Missing capability: ${CAP_CLUSTER_ONBOARD}`,
                                },
                                // Disabled, not omitted, on a cluster that is
                                // already terminal — matching this row's own
                                // checkbox two columns to the left, which has
                                // always said WHY rather than silently
                                // disappearing. It mattered less while
                                // Archived rows were unreachable; now that
                                // the Retired view renders a table of them, a
                                // menu with the action missing reads as "this
                                // build cannot do that" rather than "this one
                                // is already done".
                                //
                                // There is deliberately nothing beneath it:
                                // retiring a cluster removes it from the
                                // fleet and leaves its incidents, audit rows
                                // and history intact. No delete, no purge.
                                {
                                  label: 'Decommission',
                                  onClick: () => setDecommissioningCluster(cluster),
                                  disabled: !canDecommission || TERMINAL_CLUSTER_STATES.includes(cluster.state),
                                  disabledReason: !canDecommission
                                    ? `Missing capability: ${CAP_CLUSTER_DELETE}`
                                    : TERMINAL_CLUSTER_STATES.includes(cluster.state)
                                      ? `Already ${CLUSTER_STATE_LABEL[cluster.state]} — nothing left to decommission`
                                      : undefined,
                                  danger: true,
                                },
                              ]}
                            />
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>

            {/* Three distinct reasons the table can be empty, and they must
                not be collapsed (components.md's four-states rule): the
                retired list could not be fetched at all; nothing has ever
                been decommissioned; or the filters match nothing. Only the
                last one has "clear the filters" as its fix, and the first
                must never render as an emptiness the operator could read as
                a fact. */}
            {showingRetired && archivedClustersQuery.isError && (
              <div className="list-filter-empty">
                <strong>The retired clusters could not be loaded</strong>
                <span>
                  {archivedClustersQuery.error instanceof ApiError
                    ? archivedClustersQuery.error.detail
                      ? `${archivedClustersQuery.error.message} — ${archivedClustersQuery.error.detail}`
                      : archivedClustersQuery.error.message
                    : 'The request for decommissioned clusters failed. This is not a statement that there are none.'}
                </span>
              </div>
            )}
            {showingRetired &&
              !archivedClustersQuery.isError &&
              !archivedClustersQuery.isLoading &&
              archivedClusters.length === 0 && (
                <div className="list-filter-empty">
                  <strong>No cluster has been decommissioned</strong>
                  <span>Retired clusters are kept here — they are removed from the fleet, never deleted.</span>
                </div>
              )}
            {!listLoading &&
              filteredClusters.length === 0 &&
              !(showingRetired && (archivedClustersQuery.isError || archivedClusters.length === 0)) && (
                <div className="list-filter-empty">
                  <strong>No clusters match these filters</strong>
                  <span>Try a different search or clear the active filters.</span>
                  <button type="button" className="secondary" onClick={clearFilters}>Clear filters</button>
                </div>
              )}

            <TablePagination {...pagination} />
          </section>
        </>
      )}

      {enrollOpen && <EnrollTokenModal onClose={() => setEnrollOpen(false)} />}
      {fleetTokensOpen && <FleetTokensDialog onClose={() => setFleetTokensOpen(false)} />}
      {quickViewCluster && (
        <ClusterQuickView
          cluster={quickViewCluster}
          incidentCount={
            incidentsQuery.isLoading || incidentsQuery.isError
              ? undefined
              : openIncidentCounts[quickViewCluster.id] ?? 0
          }
          onClose={() => setQuickViewCluster(null)}
        />
      )}
      {renamingCluster && (
        <RenameClusterModal
          clusterId={renamingCluster.id}
          currentName={renamingCluster.displayName}
          onClose={() => setRenamingCluster(null)}
        />
      )}
      {decommissioningCluster && (
        <ConfirmDecommissionModal
          clusterId={decommissioningCluster.id}
          displayName={decommissioningCluster.displayName}
          onClose={() => setDecommissioningCluster(null)}
        />
      )}
      {bulkDecommissioning && (
        <ConfirmBulkDecommissionModal
          clusters={selectedClusters.map((cluster) => ({ id: cluster.id, displayName: cluster.displayName }))}
          onClose={() => {
            setBulkDecommissioning(false)
            setSelectedClusterIds(new Set())
          }}
        />
      )}
    </div>
  )
}
