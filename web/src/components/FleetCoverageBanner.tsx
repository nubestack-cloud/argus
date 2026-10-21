import type { Cluster } from '../api/types'
import { CLUSTER_STATE_LABEL } from '../api/types'
import { isReportingToArgus } from '../utils/clusters'

/**
 * FleetCoverageBanner says, in words, that the fleet list is a partial view.
 *
 * WHY IT EXISTS. An external reviewer found an instance where 10 of 21
 * clusters were Disconnected and nothing on the screen said so: every row
 * rendered at the same weight, a disconnected cluster carried a neutral grey
 * badge with no more visual claim on attention than "Active", and the
 * incident list beneath it looked complete. It was not complete. ARGUS is
 * blind on a cluster that is not reporting — no findings arrive, so no
 * incidents open, so the absence of incidents reads as health. That
 * inference is the defect; this banner exists to block it.
 *
 * WHAT COUNTS AS "NOT REPORTING" — `utils/clusters.isReportingToArgus` is
 * the one definition, shared with the page's quick view so it filters on
 * exactly the set this banner counts. Read that function's comment for why
 * it is the complement of `Active`. The breakdown line here carries the
 * precision the headline gives up, naming each contributing state and its
 * count — so "4 of those are merely mid-enrollment" is visible rather than
 * hidden inside one number.
 *
 * RETIRED CLUSTERS ARE NOT IN THIS COUNT, and that is the most important
 * thing about it. A decommissioned cluster is not reporting *on purpose*; it
 * is not a gap in coverage, it is the absence of a cluster. Inflating this
 * banner with the fleet's entire retirement history would be the fastest way
 * to make operators learn to ignore it. The exclusion is structural rather
 * than a filter written here: `clusters` is whatever `GET /clusters` returns
 * with no `?archived=`, which the hub defines as the live fleet, and the
 * retired list arrives through a separate request that never reaches this
 * component. There is no `state === 'Archived'` test below, because there is
 * nothing here for it to match.
 *
 * HONESTY. The banner makes a claim about counts, so it renders only when
 * both counts are known — the caller passes the fetched array, and a page
 * whose cluster fetch failed or has not landed has no array and therefore no
 * banner. That is the same rule ListFreshness applies in the list header
 * ("a count the query does not have is an em dash, never 0"), taken to its
 * conclusion for a whole sentence rather than a single figure: an em dash in
 * "— of — clusters are not reporting" would be noise, so the honest form of
 * an unknown partial-view claim is to not make it. The header's
 * ListFreshness is already saying "Not updating" in that case.
 *
 * It also makes no claim about the clusters it is NOT counting beyond the one
 * that is true — they are reporting. Anything stronger ("the rest are
 * healthy") would be a second, unearned assertion.
 */

export function FleetCoverageBanner({
  clusters,
  onShowNotReporting,
}: {
  /**
   * The LIVE fleet — `GET /clusters` with no `?archived=`. Passing a list
   * that includes retired clusters would silently inflate both numbers.
   */
  clusters: Cluster[]
  onShowNotReporting: () => void
}) {
  const notReporting = clusters.filter((cluster) => !isReportingToArgus(cluster))
  if (notReporting.length === 0) return null

  // Ordered by how many clusters each state accounts for, so the dominant
  // cause reads first; the label is always the human one, never the wire
  // enum (components.md's rule, generalised from a real bug).
  const byState = new Map<Cluster['state'], number>()
  for (const cluster of notReporting) {
    byState.set(cluster.state, (byState.get(cluster.state) ?? 0) + 1)
  }
  const breakdown = Array.from(byState.entries())
    .sort((left, right) => right[1] - left[1] || CLUSTER_STATE_LABEL[left[0]].localeCompare(CLUSTER_STATE_LABEL[right[0]]))
    .map(([state, count]) => `${count} ${CLUSTER_STATE_LABEL[state]}`)
    .join(' · ')

  return (
    <div className="banner banner-attention banner-with-action" role="status">
      <div>
        {/* The state is in the sentence, not only in the banner's colour —
            the amber is an addition to the words (lld/11 §8, WCAG 2.1 AA). */}
        <strong>
          {notReporting.length} of {clusters.length} clusters are not reporting to ARGUS.
        </strong>{' '}
        {/* The claim is deliberately about NEW problems, not all problems.
            Incidents opened while a cluster was still reporting stay in the
            list after it goes quiet — on this instance 13 open incidents
            belong to Disconnected clusters — so "nothing wrong on them can
            appear here" would be false, and falsifiable in one click. What
            is true, and what the operator needs, is that the stream has
            stopped: anything going wrong there NOW is invisible. */}
        <span>
          ARGUS is not receiving findings from them, so anything that goes wrong there now stays
          invisible until they reconnect. {breakdown}.
        </span>
      </div>
      <button
        type="button"
        className="banner-action"
        onClick={onShowNotReporting}
        aria-label="Show the clusters that are not reporting"
      >
        Show them
      </button>
    </div>
  )
}
