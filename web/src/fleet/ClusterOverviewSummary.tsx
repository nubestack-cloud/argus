import { Fragment } from 'react'
import type { Incident, NodeStatus } from '../api/types'
import { Freshness } from '../components/Freshness'
import { HelpTip } from '../components/HelpTip'
import { SplitBar } from '../components/SplitBar'
import { SkeletonLines } from '../components/Skeleton'
import {
  CACHE_STATE_LABEL,
  cacheSyncing,
  kindLabel,
  overviewSummary,
  realInstant,
  readClusterCoverage,
  readInsightFacts,
  unsyncedKinds,
  type CacheKindState,
  type ClusterSummary,
  type ObjectCacheFacts,
} from './clusterSummary'
import {
  ABSENCE_TEXT,
  inventoryGroups,
  readCapacity,
  type InventoryItem,
} from './clusterOverviewModel'
import { ChangesCard, ChecksCard, NeedsAttentionCard } from './ClusterPreviews'
import type { ClusterLiveness } from './InspectFrame'
import { clusterUsage, utilizationFillClass } from './resourceUsage'
import { formatDateTime, formatRelativeTime } from '../utils/time'
import { Ring } from './Ring'
import { nodesRing, podsRing, resourceRows, workloadsRing } from './ringsModel'

// Cluster detail → Overview (docs/CLUSTER_INSIGHT_SPECS.md CI-S11; owner
// reviews 2026-10-10 and 2026-10-11, PROJECT.md UX1). Mode B, question 1
// ("what is broken?") for the cluster as a whole.
//
// The top row is three rings — Pods, Workloads, Nodes — each with its
// breakdown in words under it, and the Resource use card with used and
// requested against allocatable (the owner's choice: a "health ledger" was
// tried in their place on 2026-10-11 and they asked for the rings back). Below
// them, every object count grouped by what the objects are for, problem counts
// in words. Every figure comes from the agent's own summary or the node
// inventory; a kind the agent could not list says so in place of a number.

function InventoryEntry({ item }: { item: InventoryItem }) {
  if (item.value === null) {
    return (
      <li>
        <strong>—</strong> {item.label} <span className="text-muted">— {ABSENCE_TEXT[item.absence ?? 'unknown'].toLowerCase()}</span>
      </li>
    )
  }
  return (
    <li>
      <strong className="tabular">{item.value}</strong> {item.label}
      {item.detail?.map((d) => (
        <Fragment key={d.text}>
          <span className="text-muted"> · </span>
          <span className={d.problem ? 'inventory-problem' : 'text-muted'}>{d.text}</span>
        </Fragment>
      ))}
    </li>
  )
}

// The Resource use card as the owner chose it (restored 2026-10-11): used and
// requested against allocatable, one labelled bar each, the percentage always
// printed beside the bar so the band colour is never the only carrier.
function ResourceUseCard({ nodes, summary }: { nodes: NodeStatus[] | null; summary: ClusterSummary | null }) {
  const rows = resourceRows(nodes ? clusterUsage(nodes) : null, readCapacity(summary), summary?.cacheState === 'syncing')
  return (
    <section className="card card-compact resource-use-card" aria-label="Resource use">
      <div className="card-head">
        <h3>Resource use</h3>
        <HelpTip
          label="Resource use"
          text="Used is live consumption from metrics-server, summed over the nodes that report it. Requested is what scheduled, unfinished pods asked for, summed by the agent from its object cache. Both are measured against the nodes' allocatable capacity, so requested near 100% means new pods will not fit even when usage is low."
        />
      </div>
      {rows.map((r) => {
        const percent = r.ratio === null ? null : Math.round(r.ratio * 100)
        return (
          <div key={r.key} className="meter-row">
            <div className="meter-head">
              <span>{r.label}</span>
              <span className="meter-figure">
                {r.figure}
                {percent !== null ? ` · ${percent}%` : ''}
              </span>
            </div>
            {r.ratio !== null && percent !== null ? (
              <div className="resource-usage-track" role="img" aria-label={`${r.label}: ${r.figure}, ${percent}%`}>
                <div className={utilizationFillClass(r.ratio)} style={{ width: `${Math.min(100, percent)}%` }} />
              </div>
            ) : null}
            {r.note && <small className="meter-note">{r.note}</small>}
          </div>
        )
      })}
    </section>
  )
}

// Every object count the agent reports, grouped by purpose, under the rings.
function ObjectInventory({ summary }: { summary: ClusterSummary | null }) {
  const counts = summary?.resourceCounts
  const c = counts ?? {}
  // One click away rather than a full card under the rings (owner-approved
  // cluster-pages design, 2026-10-11); the summary line keeps the headline
  // counts and says when any group has a problem part.
  const headline = [
    c.deployments && `${c.deployments.total} Deployments`,
    typeof c.services === 'number' && `${c.services} Services`,
    typeof c.namespaces === 'number' && `${c.namespaces} Namespaces`,
    c.pvcs && `${c.pvcs.total} PVCs${c.pvcs.pending ? ` (${c.pvcs.pending} pending)` : ''}`,
  ].filter(Boolean)
  return (
    <details className="card card-compact object-inventory-card" aria-label="Objects">
      <summary>
        <span className="object-inventory-title">Objects by kind</span>
        {headline.length > 0 && <span className="text-muted object-inventory-headline">{headline.join(' · ')}</span>}
      </summary>
      <div className="inventory-groups">
        {inventoryGroups(counts).map((g) => (
          <section key={g.title} className="inventory-group" aria-label={`${g.title} objects`}>
            <h4 className="metric-tile-label">{g.title}</h4>
            <ul>
              {g.items.map((item) => (
                <InventoryEntry key={item.key} item={item} />
              ))}
            </ul>
          </section>
        ))}
      </div>
    </details>
  )
}

/** The Overview tab's loading shape, so the page does not reflow when the
 *  cluster arrives (ClusterDetailPage renders it). */
export function ClusterOverviewSkeleton() {
  return (
    <>
      <div className="ring-row" aria-hidden="true">
        {Array.from({ length: 3 }, (_, i) => (
          <div key={i} className="card ring-card">
            <SkeletonLines count={3} />
          </div>
        ))}
        <div className="card card-compact resource-use-card">
          <SkeletonLines count={8} widths={['30%', '100%', '30%', '100%', '30%', '100%', '30%', '100%']} />
        </div>
      </div>
      <div className="card card-compact object-inventory-card">
        <SkeletonLines count={3} />
      </div>
      <div className="overview-pair">
        <div className="card card-compact">
          <SkeletonLines count={5} />
        </div>
        <div className="card card-compact">
          <SkeletonLines count={5} />
        </div>
      </div>
      <div className="card card-compact checks-card">
        <SkeletonLines count={3} />
      </div>
    </>
  )
}

export function ClusterOverviewSummary({
  clusterId,
  facts,
  nodes,
  incidents,
}: {
  clusterId: string
  facts: unknown
  factsUpdatedAt: string | null
  liveness: ClusterLiveness
  /** facts.nodes, or null when the agent has sent no inventory yet. */
  nodes: NodeStatus[] | null
  incidents: {
    items: Incident[]
    openCount: number | undefined
    loading: boolean
    error: unknown
    truncated: boolean
    onShowAll: () => void
  }
}) {
  const raw = readInsightFacts(facts)
  // A just-restarted agent reports before its object cache has read the
  // cluster: say that, rather than "not visible" or "needs a newer build".
  const syncing = cacheSyncing(raw.summary, raw.objectCache)
  const summary = overviewSummary(raw.summary, syncing)
  return (
    <section className="fleet-overview" aria-label="Cluster health summary">
      {syncing && (
        <p className="empty-state" role="status">
          The agent is still reading the cluster
          {syncing.startedAt ? (
            <>
              {' '}
              (started <span title={formatDateTime(syncing.startedAt)}>{formatRelativeTime(syncing.startedAt)}</span>)
            </>
          ) : null}{' '}
          — figures appear when its first sync completes.
        </p>
      )}
      {!summary && (
        <p className="empty-state">No health summary yet: an older agent, or its object cache has not finished its first sync.</p>
      )}
      <div className="ring-row">
        <Ring model={podsRing(summary?.resourceCounts)} />
        <Ring model={workloadsRing(summary?.resourceCounts)} />
        <Ring model={nodesRing(summary)} />
        <ResourceUseCard nodes={nodes} summary={summary} />
      </div>
      <ObjectInventory summary={summary} />
      {/* The two live previews side by side at equal height (their footers
          pinned to the bottom), then Checks across the full width with its
          rows in two columns. A 2×2 grid left holes, because a grid row is as
          tall as its taller card and Checks is much taller than its
          neighbour. */}
      <div className="overview-pair">
        <NeedsAttentionCard
          clusterId={clusterId}
          incidents={incidents.items}
          openCount={incidents.openCount}
          loading={incidents.loading}
          error={incidents.error}
          truncated={incidents.truncated}
          onShowAll={incidents.onShowAll}
        />
        <ChangesCard clusterId={clusterId} incidents={incidents.items} incidentsTruncated={incidents.truncated} />
      </div>
      <ChecksCard clusterId={clusterId} summary={summary} />
    </section>
  )
}

/** The object cache as a meter, then the kinds that are not synced grouped
 *  by why (forbidden, not installed, still syncing …), each kind named. */
function CacheCoverage({ cache }: { cache: ObjectCacheFacts | null }) {
  if (!cache) {
    return (
      <section className="card card-compact" aria-label="Object cache">
        <div className="card-head">
          <h3>Object cache</h3>
        </div>
        <p className="text-muted">— Not reported: an older agent build, or the cache is disabled. The cluster-insight tabs depend on it.</p>
      </section>
    )
  }
  const gaps = unsyncedKinds(cache)
  const synced = cache.kinds.length - gaps.length
  const pct = cache.kinds.length ? Math.round((synced * 100) / cache.kinds.length) : null
  const byState = new Map<string, CacheKindState[]>()
  for (const g of gaps) byState.set(g.state, [...(byState.get(g.state) ?? []), g])
  return (
    <section className="card card-compact" aria-label="Object cache">
      <div className="card-head">
        <h3>Object cache</h3>
        <HelpTip
          label="Object cache"
          text="The kinds the agent keeps a live copy of. The Map, GitOps, Helm, Posture and Certificates tabs answer from it; an answer that needs a kind listed here as not synced says so."
        />
        <span className="card-head-meta">
          {synced} of {cache.kinds.length} synced{realInstant(cache.syncedAt) ? '' : ' · initial sync not finished'}
        </span>
      </div>
      <div className="meter-row">
        <div className="meter-head">
          <span>Kinds synced</span>
          <span className="meter-figure">
            <strong className="tabular">{synced}</strong> of {cache.kinds.length}
            {pct !== null ? ` · ${pct}%` : ''}
          </span>
        </div>
        {pct !== null && (
          <div className="resource-usage-track" role="img" aria-label={`${synced} of ${cache.kinds.length} kinds synced`}>
            <div className="coverage-fill" style={{ width: `${pct}%` }} />
          </div>
        )}
      </div>
      {gaps.length === 0 ? (
        <p className="text-muted cache-gap-none">Every watched kind is synced.</p>
      ) : (
        <ul className="cache-gaps">
          {[...byState.entries()].map(([state, kinds]) => (
            <li key={state}>
              <span className={state === 'forbidden' || state === 'error' ? 'badge badge-red' : 'badge badge-gray'}>
                {kinds.length} {(CACHE_STATE_LABEL[state] ?? state).toLowerCase()}
              </span>
              <span className="cache-gap-kinds">
                {kinds.map((k, i) => (
                  <span key={kindLabel(k)} title={`${kindLabel(k)}${k.reason ? ` — ${k.reason}` : ''}`}>
                    {i > 0 ? ', ' : ''}
                    {k.kind}
                  </span>
                ))}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

// WatchCoverageCard is PROJECT.md E11's answer to "how much of this cluster
// is the agent watching": the grant-shaped count (kinds the agent may
// get/list/watch, out of the kinds the API server serves) and, separately,
// what the last sweep actually read. The two count at different granularity
// (tunnel.SweepCoverage's comment), so they are shown side by side and never
// combined into one figure. Unchecked is "unknown", never 0 of 0.
export function WatchCoverageCard({ facts, liveness }: { facts: unknown; liveness?: ClusterLiveness }) {
  const cov = readClusterCoverage(facts)
  const sweep = cov?.lastSweep
  const percent = cov?.checked && cov.kindsServed > 0 ? Math.round((cov.kindsReadable / cov.kindsServed) * 100) : null
  return (
    <section className="card card-compact" aria-label="Watch coverage">
      <div className="card-head">
        <h3>Watch coverage</h3>
        <HelpTip
          label="Watch coverage"
          text="How many of the resource kinds this cluster's API server serves the agent is allowed to get, list and watch, from its own RBAC. Kinds it cannot read produce no findings, so a narrow grant looks like a quiet cluster. The last sweep counts what the agent actually managed to read on its most recent pass."
        />
      </div>
      {!cov ? (
        <p className="text-muted">— Not reported by this agent (a build older than the coverage report).</p>
      ) : !cov.checked ? (
        <p>
          <strong>Unknown</strong> <span className="text-muted">— the agent could not run the check{cov.error ? `: ${cov.error}` : '.'}</span>
        </p>
      ) : (
        <div className="meter-row">
          <div className="meter-head">
            <span>
              Watching <strong className="tabular">{cov.kindsReadable}</strong> of <strong className="tabular">{cov.kindsServed}</strong> resource kinds
            </span>
            <span className="meter-figure">{percent === null ? '—' : `${percent}%`}</span>
          </div>
          {percent !== null && (
            <div className="resource-usage-track" role="img" aria-label={`Watching ${cov.kindsReadable} of ${cov.kindsServed} resource kinds, ${percent}%`}>
              <div className="coverage-fill" style={{ width: `${Math.min(100, percent)}%` }} />
            </div>
          )}
          {cov.kindsServed > cov.kindsReadable && (
            <small className="meter-note">{cov.kindsServed - cov.kindsReadable} kinds are not readable by the agent's identity.</small>
          )}
        </div>
      )}
      {cov && (
        <div className="watch-sweep">
          {sweep ? (
            <>
              <SplitBar
                tall
                label="Last sweep, resource kinds"
                parts={[
                  { tone: 'accent', value: sweep.kindsRead, label: 'read' },
                  { tone: 'critical', value: sweep.kindsForbidden, label: 'forbidden by RBAC' },
                  { tone: 'high', value: sweep.kindsFailed, label: 'failed this pass' },
                  { tone: 'medium', value: sweep.kindsNotAffordable, label: 'skipped by the memory guard' },
                  { tone: 'unknown', value: sweep.kindsNotServed, label: 'CRD not installed' },
                  { tone: 'neutral', value: sweep.kindsNotListed, label: 'never listed by design (Secrets)' },
                ]}
              />
              <p className="watch-sweep-line text-muted">
                Last sweep <Freshness at={sweep.at} stale={liveness?.stale} staleReason={liveness?.staleReason} />
              </p>
            </>
          ) : (
            <p className="text-muted">No sweep pass has completed yet.</p>
          )}
        </div>
      )}
      {cov?.deniedSample && cov.deniedSample.length > 0 && (
        <details className="object-labels">
          <summary>
            Denied kinds · {cov.deniedSample.length}
            {cov.deniedSampleTruncated ? ' shown, more exist' : ''}
          </summary>
          <ul className="fleet-gap-list insight-mono">
            {cov.deniedSample.map((k) => (
              <li key={k}>{k}</li>
            ))}
          </ul>
        </details>
      )}
    </section>
  )
}

// AgentCoverageSection is the Agent tab's "what the agent can see": which
// watched kinds are synced, and why the rest are not.
export function AgentCoverageSection({ facts, liveness }: { facts: unknown; liveness?: ClusterLiveness }) {
  const { objectCache } = readInsightFacts(facts)
  return (
    <section aria-label="What the agent can see" className="agent-grid">
      <WatchCoverageCard facts={facts} liveness={liveness} />
      <CacheCoverage cache={objectCache} />
    </section>
  )
}

/** When the Overview's figures were computed, for the tab row's right end:
 *  the agent's summary time, else the facts snapshot. */
export function OverviewFreshness({ facts, factsUpdatedAt, liveness }: { facts: unknown; factsUpdatedAt: string | null; liveness: ClusterLiveness }) {
  const raw = readInsightFacts(facts)
  const summary = overviewSummary(raw.summary, cacheSyncing(raw.summary, raw.objectCache))
  const at = summary?.computedAt ?? factsUpdatedAt
  // Stale keeps the full Freshness wording (it names why); fresh is short so
  // the tab row keeps its room.
  if (liveness.stale || !at) return <Freshness at={at ?? undefined} stale={liveness.stale} staleReason={liveness.staleReason} />
  return (
    <span className="text-muted" title={`Figures computed ${formatDateTime(at)}`}>
      as of {formatRelativeTime(at)}
    </span>
  )
}
