import type { Cluster } from '../api/types'

/**
 * The single definition of "ARGUS is currently receiving this cluster's
 * findings", shared by the Clusters page's "Not reporting" quick view and by
 * FleetCoverageBanner's count — deliberately one expression evaluated twice
 * rather than two rules that would eventually disagree about which rows they
 * mean. Same reason and same shape as `isClosedIncidentState` in
 * `utils/incidents.ts`.
 *
 * It is the complement of `Active`, and that choice is the whole point:
 *
 *  - A narrower set (Disconnected alone) understates the hole. A cluster
 *    stuck in Provisioning, or one whose agent this hub refuses on version
 *    grounds, is exactly as unobserved as one that stopped dialling in.
 *  - The complement of Active is the only definition an operator can audit
 *    from the screen itself: the State column is right there, and
 *    notReporting + active = total with no third bucket to reconcile.
 *  - A state added to the enum later is classified as NOT reporting until
 *    someone says otherwise, which is the safe direction to be wrong in —
 *    overstating a coverage gap costs attention, understating one costs an
 *    incident nobody saw.
 *
 * Retired (Archived) clusters never reach this function. They are excluded
 * upstream, by the hub: `GET /clusters` with no `?archived=` is the live
 * fleet, and the retired list arrives through a separate request. A
 * decommissioned cluster is not a gap in coverage — it is the absence of a
 * cluster — so counting one here would be the fastest way to teach operators
 * to ignore the banner.
 */
export function isReportingToArgus(cluster: Cluster): boolean {
  return cluster.state === 'Active'
}

/** A cluster id short enough for a list cell but still telling clusters
 *  apart: "cl_…" and the id's last eight characters. Ids are prefixed ULIDs
 *  (internal/domain.NewID) whose leading characters encode the creation time,
 *  so a head-truncation reads the same for clusters enrolled close together;
 *  the tail is the random part. */
export function shortClusterId(id: string): string {
  const us = id.indexOf('_')
  const prefix = us > 0 ? id.slice(0, us + 1) : ''
  const body = id.slice(prefix.length)
  return body.length <= 10 ? id : `${prefix}…${body.slice(-8)}`
}
