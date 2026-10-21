import type { ClusterState } from '../api/types'
import { CLUSTER_STATE_LABEL } from '../api/types'

// The cluster-state vocabulary shared by every screen that renders one — the
// counterpart to IncidentBadges, and promoted here for the same reason
// (BACKLOG D7f).
//
// Three files held parallel state tables before this: ClustersPage's
// STATE_COLOR/STATE_LABEL, ClusterDetailPage's CLUSTER_STATE_BADGE_CLASS, and a
// third mapping on OverviewPage. They had **already diverged** — ClusterDetail
// rendered the raw wire value, so the same cluster read "IncompatibleVersion"
// there and "Incompatible version" on the list. A raw enum is never a
// user-facing label (see components.md, a rule generalised from a real bug), and
// two hand-maintained copies of one vocabulary is how the next divergence
// happens.

type ColorFamily = 'green' | 'amber' | 'blue' | 'red' | 'gray'

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

// `withDot` because the two callers genuinely want different density, not
// different vocabulary: a list row carries the dot so a scan down the column has
// a mark to follow, while a detail header has one badge and does not need it.
// The word is present either way — state is never carried by colour alone
// (lld/11 §8, WCAG 2.1 AA).
export function ClusterStateBadge({ state, withDot = false }: { state: ClusterState; withDot?: boolean }) {
  const family = STATE_COLOR[state]
  const badge = <span className={`badge badge-${family}`}>{CLUSTER_STATE_LABEL[state]}</span>
  if (!withDot) return badge
  return (
    <span className="badge-with-dot">
      <span className={`status-dot status-dot-${family}`} aria-hidden="true" />
      {badge}
    </span>
  )
}
