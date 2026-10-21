// Insights — the last of lld/11-ui-design.md §15.1's ten named screens with
// no backend or UI at all before this task: "Recurring issue classes,
// calibration curves, autonomy readiness per class, cost per incident, top
// noisy namespaces." Deliberately scoped down from that full description —
// see GET /api/v1/insights' own doc comment (internal/api/insights.go) for
// the full reasoning. In short: everything below except the last section is
// real SQL aggregation over incidents/findings/analyses, tables STATUS.md
// §25/§28 confirm are genuinely populated by the real investigation loop
// today. Calibration curves and per-class autonomy readiness are rendered
// as an explicit "not built yet" state instead of a fabricated chart — both
// need real data (shadow-mode history, real approve/reject decisions) that
// doesn't exist anywhere in this codebase yet.
import type { ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { getClusters, getInsights, getInsightsRemediationQuality, getSpendToday, ApiError } from '../api/client'
import type {
  DailyTrendPoint,
} from '../api/types'
import { useAuth } from '../auth/useAuth'
import { useHasCapability } from '../auth/useCapabilities'
import { CAP_REMEDIATION_APPROVE, CAP_SPEND_READ } from '../api/capabilities'
import { formatDateTime, formatRelativeTime } from '../utils/time'
import { SkeletonLines } from '../components/Skeleton'
import { HelpTip } from '../components/HelpTip'
import { Segmented, SplitBar } from '../components/SplitBar'
import { useState } from 'react'
import type { InsightsResponse, RemediationQualityResponse as InsightsRemediationQuality, SpendToday as SpendTodayResponse } from '../api/types'
import { EmptyState } from '../components/EmptyState'
import { SLOW_FALLBACK_MS } from '../realtime/refresh'

// Raw wire values (internal/remediation.ActionType's closed set —
// internal/remediation/plan.go's validActionTypes, now eleven entries, not
// the six this comment originally said: StructuredPatch/AnnotateResource/
// LabelResource/DeleteResource/CreateResource all landed after this map was
// first written — confirmed against the live dev deployment's own real
// remediation_recommendations rows while building this page, which is what
// caught this map originally missing half of them) — never rendered
// directly (components.md's "always the readable label, never the raw enum
// value" rule, established after IncidentBadges.tsx hit this as a real
// bug). Local to this page rather than a shared map: RemediationPlanCard
// predates that rule and renders actionType/gateOutcome raw today (a known,
// separate gap — BACKLOG D8), which this addition should not copy.
const ACTION_TYPE_LABEL: Record<string, string> = {
  ScaleDeployment: 'Scale deployment',
  RestartPod: 'Restart pod',
  PatchResourceLimits: 'Patch resource limits',
  RevertContainerImage: 'Revert container image',
  OpenPR: 'Open pull request',
  PatchField: 'Patch field',
  StructuredPatch: 'Structured patch',
  AnnotateResource: 'Annotate resource',
  LabelResource: 'Label resource',
  DeleteResource: 'Delete resource',
  CordonNode: 'Cordon node',
  DrainNode: 'Drain node',
  CreateResource: 'Create resource',
}

function actionTypeLabel(actionType: string): string {
  return ACTION_TYPE_LABEL[actionType] ?? actionType
}

// Same badge-by-risk mapping RemediationPlanCard already uses for
// plan.riskLevel, reused here rather than invented afresh.
function riskBadgeClass(riskLevel: string): string {
  if (riskLevel === 'high') return 'badge badge-red'
  if (riskLevel === 'medium') return 'badge badge-amber'
  return 'badge badge-blue'
}

// --- Investigation outcomes: complete vs. partial (bound-hit), avg iterations ---

// `.metric-tile` + `.tone-*`, not the page's own former `.insights-kpi-*` —
// index.css's D7/D8 vocabulary already names Insights as one of the pages
// still on the pre-refresh tile ("`.metric-tile` | `.stat-tile` (Overview,
// Insights)"), and a hand-rolled inset-shadow accent system duplicated the
// exact job a left-rule already does elsewhere in this app.
//
// BACKLOG D7h: this used to fold onto `.sev-*` (sev-low/sev-medium/
// sev-neutral) — the ORDINAL severity ramp, which claims an ordering
// ("how bad is this") these tiles do not have. A completion rate is not
// less severe than a token count. `.tone-*` is the non-severity equivalent,
// reusing `.pipeline-cell`'s own `--tone-ink`/`--tone-meta` idiom rather than
// inventing a second one.

function formatPercent(rate: number | null): string {
  if (rate === null) return '—'
  return `${Math.round(rate * 100)}%`
}

function formatAvg(n: number | null): string {
  if (n === null) return '—'
  return n.toFixed(1)
}

// --- Cost/tokens: a 14-day investigations-per-day trend, same bar-chart
// construction as OverviewPage.tsx's ActivitySparkline (plain CSS-height
// divs, no SVG needed for a bar chart the way a proportion-of-whole donut
// needs stroke-dasharray arcs), just fed by a server-aggregated series
// instead of a client-side reduce over an already-fetched list.

function InvestigationTrend({ trend }: { trend: DailyTrendPoint[] }) {
  const max = Math.max(1, ...trend.map((p) => p.investigations))
  const totalInvestigations = trend.reduce((sum, p) => sum + p.investigations, 0)

  return (
    <div className="sparkline">
      <div
        className="sparkline-bars"
        role="img"
        aria-label={`${totalInvestigations} investigation${totalInvestigations === 1 ? '' : 's'} run in the last ${trend.length} days`}
      >
        {trend.map((p) => (
          <div
            key={p.day}
            className={`sparkline-bar ${p.investigations === 0 ? 'sparkline-bar-empty' : ''}`}
            title={`${p.day}: ${p.investigations} investigation${p.investigations === 1 ? '' : 's'}, ${p.totalTokens.toLocaleString()} tokens`}
            style={{ height: `${Math.max(4, (p.investigations / max) * 100)}%` }}
          />
        ))}
      </div>
      <p className="sparkline-caption">
        {totalInvestigations} investigation{totalInvestigations === 1 ? '' : 's'} run in the last {trend.length} days
      </p>
    </div>
  )
}

// --- Recurring issue classes: incidents grouped by exact fingerprint ---

// --- New issue classes: BUGS.md 121 part (b). Same fingerprint shape and
// the exact same table vocabulary as IssueClassRow above (no new class,
// same columns) — reusing the row renderer would show "Last seen," which
// restates the table's own sort key rather than answering the one question
// this list exists for ("how new IS this"), so this variant swaps that one
// column for "First seen" instead. No per-row "New" badge: the section's
// own heading and section-note already say what makes this list different,
// and repeating that on every row would be exactly the "same fact twice"
// the decoration test rules out. ---

// --- New noisy namespaces: BUGS.md 121 part (b)'s namespace-grouped
// counterpart. Same .rank-bar-list vocabulary as NamespaceRankBars below,
// with "since <first seen>" appended to the subvalue in place of nothing —
// the one extra fact ("new" tells you it's recent, this says how recent)
// that the all-time list has no reason to carry. ---

// --- Top noisy namespaces: a horizontal rank-bar list, the same "plain CSS
// bar, not an SVG chart" language as the sparkline above, just laid out
// sideways for a ranked top-N instead of a time series.

// --- Unstable clusters: incidents grouped by cluster, ranked by how many
// are currently Reopened or Failed. Same table vocabulary as the issue-class
// table above (list-card/table-scroll/cluster-table), not a new primitive. ---

// --- Recommendations frequently rejected / automation candidates: both read
// GET /api/v1/insights/remediation-quality, gated on remediation:approve
// (narrower than the rest of this page's incident:read + analysis:read) —
// see api/client.ts's getInsightsRemediationQuality doc comment. Omitted
// entirely for a viewer who lacks the capability, the same "simply omit the
// tile" precedent this page already established for the spend-today tile
// below, rather than disabled-with-a-tooltip: there is no control to
// disable here, only data the viewer isn't allowed to see. ---

// --- Explicitly not built: calibration curves, autonomy readiness per class ---

function NotBuiltCard({ label, reason }: { label: string; reason: string }) {
  return (
    <details className="not-built-card">
      <summary>{label} <span className="badge badge-gray">Planned</span></summary>
      <p className="empty-state">{reason}</p>
    </details>
  )
}

export function InsightsPage() {
  const { accessToken } = useAuth()
  const [searchParams, setSearchParams] = useSearchParams()
  const clusterId = searchParams.get('clusterId') ?? ''
  const requestedDays = Number(searchParams.get('days'))
  const days: 14 | 30 | 90 = requestedDays === 30 || requestedDays === 90 ? requestedDays : 14

  const clustersQuery = useQuery({
    queryKey: ['clusters'],
    queryFn: () => getClusters(accessToken!),
    enabled: !!accessToken,
  })

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['insights', { clusterId: clusterId || undefined, days }],
    queryFn: () => getInsights(accessToken!, { clusterId: clusterId || undefined, days }),
    enabled: !!accessToken,
    // Event-backed like the list screens, but deliberately throttled on the
    // way in: this is five aggregate GROUP BY queries over potentially every
    // incident/finding/analysis this tenant has ever had, not a bounded list
    // fetch, so realtime/refresh.ts holds ['insights'] to one refresh per 30s
    // however many events arrive. The interval is the fallback under that.
    refetchInterval: SLOW_FALLBACK_MS,
  })

  // "Today's real spend" tile below — a separate query from `data` above,
  // gated on spend:read specifically (narrower than incident:read +
  // analysis:read, which gate the rest of this page): a viewer holds those
  // two but not spend:read (authz-spec §5's matrix), so this tile is simply
  // omitted for them rather than the whole page erroring — see
  // api/capabilities.ts's CAP_SPEND_READ doc comment for why this is the
  // first real use anywhere in this codebase of a capability that's been
  // declared since the first authz pass but never implemented until now.
  const canReadSpend = useHasCapability(CAP_SPEND_READ)
  const spendQuery = useQuery({
    queryKey: ['spend-today'],
    queryFn: () => getSpendToday(accessToken!),
    enabled: !!accessToken && canReadSpend,
    refetchInterval: SLOW_FALLBACK_MS,
  })

  // "Recommendations frequently rejected" / "automation candidates" below —
  // gated on remediation:approve, narrower than incident:read + analysis:read
  // (see api/client.ts's getInsightsRemediationQuality doc comment). BOTH
  // sections always render their heading and section-note; only the body
  // differs by capability (a "Restricted" empty state, never an omission) —
  // anti-patterns.md's "capability-gated DATA, not just gated controls" rule
  // is explicit that a number/section the viewer may not see must say so in
  // place, never disappear so the page looks complete without it. The query
  // itself still only fires with the capability held, so a viewer who lacks
  // it never even generates the request.
  const canReadRemediationQuality = useHasCapability(CAP_REMEDIATION_APPROVE)
  const remediationQualityQuery = useQuery({
    queryKey: ['insights-remediation-quality', { clusterId: clusterId || undefined, days }],
    queryFn: () => getInsightsRemediationQuality(accessToken!, { clusterId: clusterId || undefined, days }),
    enabled: !!accessToken && canReadRemediationQuality,
    refetchInterval: SLOW_FALLBACK_MS,
  })

  const hasAnyData =
    !!data &&
    (data.investigationOutcomes.totalAnalyses > 0 ||
      data.issueClasses.length > 0 ||
      data.noisyNamespaces.length > 0 ||
      data.unstableClusters.length > 0)
  // BACKLOG D7b. hasAnyData passes on issue classes alone, so a window with
  // findings but NO analyses rendered "Total investigations 0", "Reached a
  // conclusion 0", "Hit a bound 0", "Avg. tokens 0" and "$0.00" as facts. Five
  // fabricated zeros — and the two fields beside them that correctly render `—`
  // are what made the hard zeros read as measured. Gated per section instead:
  // the investigation tiles need investigations, not merely any data at all.
  const hasInvestigations = !!data && data.investigationOutcomes.totalAnalyses > 0

  return (
    <div className="page list-page insights-page">
      <header className="page-header list-page-header">
        <div>
          <h1>Insights</h1>
          <p className="list-live-status">
            <span>{days}-day scope</span>
            <span aria-hidden="true">·</span>
            <span>{isLoading ? 'Loading…' : 'Refreshes every 30 seconds'}</span>
          </p>
        </div>
        <div className="insights-scope-controls" aria-label="Insight scope">
          <label>
            <span>Cluster</span>
            <select value={clusterId} onChange={(event) => {
              const next = new URLSearchParams(searchParams)
              if (event.target.value) next.set('clusterId', event.target.value)
              else next.delete('clusterId')
              setSearchParams(next, { replace: true })
            }}>
              <option value="">All clusters</option>
              {(clustersQuery.data?.clusters ?? []).map((cluster) => (
                <option key={cluster.id} value={cluster.id}>{cluster.displayName}</option>
              ))}
            </select>
          </label>
          <label>
            <span>Date range</span>
            <select value={days} onChange={(event) => {
              const next = new URLSearchParams(searchParams)
              next.set('days', event.target.value)
              setSearchParams(next, { replace: true })
            }}>
              <option value={14}>Last 14 days</option>
              <option value={30}>Last 30 days</option>
              <option value={90}>Last 90 days</option>
            </select>
          </label>
        </div>
      </header>

      {/* BACKLOG D7g. 3 sections and 8 tiles stood in for the 5 sections this
          page actually renders once loaded — plus a sparkline card and a
          rank-bar panel neither of which had any placeholder at all. Same
          order as the loaded state below, same section count, so nothing
          appears or disappears at load. Keep the two in step: this block and
          the loaded block are the same sequence twice, and the whole point of
          the placeholder is that the page does not reflow when data lands. */}
      {isLoading && (
        <div aria-busy="true" aria-label="Loading insights" className="insights-grid">
          <div className="chart-card-grid">
            <div className="card card-compact"><SkeletonLines count={4} /></div>
            <div className="card card-compact"><SkeletonLines count={4} /></div>
          </div>
          <div className="card card-compact"><SkeletonLines count={6} /></div>
          <div className="chart-card-grid">
            <div className="card card-compact"><SkeletonLines count={5} /></div>
            <div className="card card-compact"><SkeletonLines count={5} /></div>
          </div>
        </div>
      )}

      {isError && (
        <p className="form-error" role="alert">
          {error instanceof ApiError
            ? error.detail
              ? `${error.message} — ${error.detail}`
              : error.message
            : 'Failed to load insights.'}
        </p>
      )}

      {!isLoading && !isError && data && !hasAnyData && (
        <EmptyState variant="insights">
          No incidents or analyses recorded yet — insights build up as the fleet is investigated over time.
        </EmptyState>
      )}

      {!isLoading && !isError && data && hasAnyData && (
        <InsightsBody
          data={data}
          days={days}
          clusterId={clusterId}
          hasInvestigations={hasInvestigations}
          spend={canReadSpend ? spendQuery.data : undefined}
          quality={{
            allowed: canReadRemediationQuality,
            isLoading: remediationQualityQuery.isLoading,
            error: remediationQualityQuery.isError
              ? remediationQualityQuery.error instanceof ApiError
                ? remediationQualityQuery.error.message
                : 'Failed to load remediation quality data.'
              : null,
            data: remediationQualityQuery.data,
          }}
        />
      )}
    </div>
  )
}

/** The kind without its API group and version: "Pod", not "v1/Pod". */
function shortKind(gvk: string): string {
  return gvk.split('/').pop() || gvk
}

function InsightCard({ title, help, meta, aside, children }: { title: string; help?: string; meta?: ReactNode; aside?: ReactNode; children: ReactNode }) {
  return (
    <section className="card card-compact insights-card" aria-label={title}>
      <div className="card-head">
        <h3>{title}</h3>
        {help && <HelpTip label={title} text={help} />}
        {meta && <span className="card-head-meta">{meta}</span>}
        {aside}
      </div>
      {children}
    </section>
  )
}

// Insights, regrouped (owner, 2026-10-12: "what's needed and what is
// redundant"). Four questions, one card each, every figure drawn:
//   - is investigation working, and what does it cost;
//   - what keeps happening (recurring issue classes, with the new ones one
//     toggle away instead of a second near-identical table);
//   - where the noise comes from (namespaces, all-time or new, one toggle);
//   - which clusters carry the load, and which fixes people reject or would
//     automate.
// Every section note became a HelpTip; the planned-but-not-built list moved
// into a disclosure at the foot.
function InsightsBody({
  data,
  days,
  clusterId,
  hasInvestigations,
  spend,
  quality,
}: {
  data: InsightsResponse
  days: number
  clusterId: string
  hasInvestigations: boolean
  spend: SpendTodayResponse | undefined
  quality: { allowed: boolean; isLoading: boolean; error: string | null; data: InsightsRemediationQuality | undefined }
}) {
  const [issueView, setIssueView] = useState<'recurring' | 'new'>('recurring')
  const [nsView, setNsView] = useState<'noisiest' | 'new'>('noisiest')
  const io = data.investigationOutcomes
  const ct = data.costAndTokens
  const issues = issueView === 'recurring' ? data.issueClasses : data.newIssueClasses
  const maxOcc = Math.max(1, ...issues.map((i) => i.totalOccurrences))
  const scopeHint = clusterId ? ' Try All clusters or a wider date range.' : ''
  const measurableSpend = spend ? spend.spendCountable && spend.pricingConfigured : false

  return (
    <div className="insights-grid">
      <div className="chart-card-grid">
        <InsightCard
          title="Investigations"
          help="Real results for the selected scope: how many investigations reached a confident conclusion versus hit a bound (max iterations or time limit) first, and how many tool-calling round-trips a typical one takes."
          meta={hasInvestigations ? `${io.totalAnalyses} in ${days} days` : `none in ${days} days`}
        >
          {hasInvestigations ? (
            <>
              <SplitBar
                tall
                label="Investigation outcomes"
                showZero
                parts={[
                  { tone: 'ok', value: io.completeCount, label: 'reached a conclusion' },
                  { tone: 'high', value: io.partialCount, label: 'hit a bound' },
                ]}
              />
              <div className="insights-figures">
                <div>
                  <span className="metric-tile-label">Concluded</span>
                  <strong>{formatPercent(io.completeRate)}</strong>
                </div>
                <div>
                  <span className="metric-tile-label">Avg. tool round-trips</span>
                  <strong>{formatAvg(io.avgIterations)}</strong>
                </div>
              </div>
              <InvestigationTrend trend={ct.dailyTrend} />
            </>
          ) : (
            <p className="text-muted">No investigation ran in this scope, so there is nothing to rate.</p>
          )}
        </InsightCard>

        <InsightCard title="Tokens and cost" help={ct.costTrackingNote} meta="per investigation">
          {hasInvestigations ? (
            <>
              <SplitBar
                tall
                label="Average tokens per investigation"
                parts={[
                  { tone: 'accent', value: Math.round(ct.avgTokensBilledIn), label: 'billed in' },
                  { tone: 'neutral', value: Math.round(ct.avgTokensCacheRead), label: 'cache read' },
                  { tone: 'info', value: Math.round(ct.avgTokensOut), label: 'out' },
                ]}
              />
              <dl className="insights-kv">
                <dt>Total cost</dt>
                <dd>
                  {ct.totalCostUsd > 0 ? `$${ct.totalCostUsd.toFixed(2)}` : '—'}
                  {ct.unmeasuredCostCount > 0 && <span className="text-muted"> · {ct.unmeasuredCostCount} with no cost data</span>}
                </dd>
              </dl>
            </>
          ) : (
            <p className="text-muted">— no investigations, so no tokens or cost in this scope.</p>
          )}
          {spend && (() => {
            const ceilingSuffix =
              spend.dailySpendCeilingUsd == null
                ? 'no ceiling'
                : spend.ceilingBreached
                  ? `$${spend.dailySpendCeilingUsd.toFixed(2)} ceiling reached`
                  : spend.ceilingEnforceable
                    ? `of $${spend.dailySpendCeilingUsd.toFixed(2)} ceiling`
                    : `$${spend.dailySpendCeilingUsd.toFixed(2)} ceiling not enforced`
            // One label/value row under Total cost, not a figure of its own:
            // when spend is not measured there is no figure, and a large "—"
            // under an uppercase sentence read as a broken tile.
            return (
              <dl className="insights-kv">
                <dt>Org spend today</dt>
                <dd className={spend.ceilingBreached ? 'insights-spend-breached' : undefined}>
                  {measurableSpend ? (
                    <>
                      <strong>${spend.todaySpendUsd.toFixed(4)}</strong>
                      <span className="text-muted"> · {ceilingSuffix}</span>
                    </>
                  ) : (
                    <>
                      —
                      <span className="text-muted">
                        {' '}
                        not measured, {!spend.spendCountable ? 'subscription provider' : 'no price table'} · {ceilingSuffix}
                      </span>
                    </>
                  )}
                </dd>
              </dl>
            )
          })()}
        </InsightCard>
      </div>

      <InsightCard
        title="What keeps happening"
        help={`Incidents grouped by their exact fingerprint (namespace, kind, object name and reason). Recurring ranks the selected ${days} days; New lists issue classes with no occurrence before the last ${data.newSignalWindowDays} days — a pattern the recurring ranking cannot show once older, louder classes outrank it.`}
        aside={
          <Segmented
            label="Issue classes"
            value={issueView}
            onChange={setIssueView}
            options={[
              { id: 'recurring', label: `Recurring · ${data.issueClasses.length}` },
              { id: 'new', label: `New in ${data.newSignalWindowDays}d · ${data.newIssueClasses.length}` },
            ]}
          />
        }
      >
        {issues.length === 0 ? (
          <p className="text-muted">
            {issueView === 'recurring'
              ? clusterId
                ? `No recurring issue classes for this cluster in the last ${days} days. Try All clusters or a wider date range.`
                : `No recurring issue classes in the last ${days} days.`
              : clusterId
                ? `No new issue classes for this cluster in the last ${data.newSignalWindowDays} days. Try All clusters.`
                : `No new issue classes in the last ${data.newSignalWindowDays} days — nothing has started happening for the first time recently.`}
          </p>
        ) : (
          <div className="table-scroll">
            <table className="data-table insights-issues">
              <thead>
                <tr>
                  <th>Object</th>
                  <th>Reason</th>
                  <th className="col-numeric">Incidents</th>
                  <th className="col-numeric">Clusters</th>
                  <th>Occurrences</th>
                  <th className="col-time">{issueView === 'recurring' ? 'Last seen' : 'First seen'}</th>
                </tr>
              </thead>
              <tbody>
                {issues.map((c) => {
                  const identity = [c.sampleNamespace, c.sampleObjectName].filter(Boolean).join('/')
                  const when = issueView === 'recurring' ? c.lastSeen : c.firstSeen
                  return (
                    <tr key={c.fingerprint}>
                      <td>
                        <Link
                          to={`/incidents?q=${encodeURIComponent(c.fingerprint)}`}
                          title={`Fingerprint ${c.fingerprint} — opens a search of recent incidents, which is capped, so it may list fewer than ${c.incidentCount}`}
                          className="insights-object"
                        >
                          {identity || 'cluster-scoped'}
                        </Link>{' '}
                        <span className="kind">{shortKind(c.sampleGvk)}</span>
                      </td>
                      <td>{c.sampleReason ?? '—'}</td>
                      <td className="col-numeric">{c.incidentCount}</td>
                      <td className="col-numeric">{c.clusterCount}</td>
                      <td className="insights-occ">
                        <span className="bar-list-track" aria-hidden="true">
                          <span className="split-seg" data-tone="accent" style={{ width: `${(c.totalOccurrences * 100) / maxOcc}%` }} />
                        </span>
                        <span className="num">{c.totalOccurrences.toLocaleString()}</span>
                      </td>
                      <td className="col-time" title={formatDateTime(when)}>
                        {formatRelativeTime(when)}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </InsightCard>

      <div className="chart-card-grid">
        <InsightCard
          title="Where the noise comes from"
          help={`Namespaces ranked by finding volume. Noisiest covers the selected ${days} days; New lists namespaces with no findings before the last ${data.newSignalWindowDays} days. Select one to search its incidents.`}
          aside={
            <Segmented
              label="Namespaces"
              value={nsView}
              onChange={setNsView}
              options={[
                { id: 'noisiest', label: 'Noisiest' },
                { id: 'new', label: `New · ${data.newNoisyNamespaces.length}` },
              ]}
            />
          }
        >
          {(nsView === 'noisiest' ? data.noisyNamespaces : data.newNoisyNamespaces).length === 0 ? (
            <p className="text-muted">
              {nsView === 'noisiest'
                ? clusterId
                  ? `No namespaced findings for this cluster in the last ${days} days. Try All clusters or a wider date range.`
                  : `No namespaced findings in the last ${days} days.`
                : clusterId
                  ? `No new noisy namespaces for this cluster in the last ${data.newSignalWindowDays} days. Try All clusters.`
                  : `No new noisy namespaces in the last ${data.newSignalWindowDays} days.`}
            </p>
          ) : (
            <ul className="insights-ns">
              {(nsView === 'noisiest' ? data.noisyNamespaces : data.newNoisyNamespaces).map((n) => {
                const max = Math.max(1, ...(nsView === 'noisiest' ? data.noisyNamespaces : data.newNoisyNamespaces).map((x) => x.findingCount))
                return (
                  <li key={n.namespace || '(cluster-scoped)'}>
                    <Link className="insights-ns-name" to={`/incidents?q=${encodeURIComponent(n.namespace)}`} title={`Search incidents in ${n.namespace || 'cluster-scoped objects'}`}>
                      {n.namespace || 'cluster-scoped'}
                    </Link>
                    <span className="bar-list-track" aria-hidden="true">
                      <span className="split-seg" data-tone="neutral" style={{ width: `${Math.max(2, (n.findingCount * 100) / max)}%` }} />
                    </span>
                    <span className="insights-ns-meta">
                      <strong>{n.findingCount.toLocaleString()}</strong> findings · {n.incidentCount} incident{n.incidentCount === 1 ? '' : 's'}
                      {nsView === 'new' && typeof (n as unknown as { firstSeen?: unknown }).firstSeen === 'string' ? (
                        <>
                          {' '}
                          · since{' '}
                          <span title={formatDateTime((n as unknown as { firstSeen: string }).firstSeen)}>
                            {formatRelativeTime((n as unknown as { firstSeen: string }).firstSeen)}
                          </span>
                        </>
                      ) : null}
                    </span>
                  </li>
                )
              })}
            </ul>
          )}
        </InsightCard>

        <InsightCard
          title="Incidents by cluster"
          help="Each cluster's incidents in the selected scope: reopened or failed outright, still open, and the rest closed. Ranked by reopened/failed, then by volume — a real count, not a trained instability score."
          meta={`${days} days`}
        >
          {data.unstableClusters.length === 0 ? (
            <p className="text-muted">No incidents in the last {days} days.{scopeHint}</p>
          ) : (
            <>
            <ul className="split-legend insights-legend" aria-hidden="true">
              <li><span className="split-swatch" data-tone="critical" /> reopened/failed</li>
              <li><span className="split-swatch" data-tone="high" /> open</li>
              <li><span className="split-swatch" data-tone="ok" /> closed</li>
            </ul>
            <ul className="insights-ns">
              {data.unstableClusters.map((c) => {
                const max = Math.max(1, ...data.unstableClusters.map((x) => x.totalIncidents))
                const open = Math.max(0, c.openCount - c.reopenedOrFailedCount)
                const closed = Math.max(0, c.totalIncidents - c.openCount)
                return (
                  <li key={c.clusterId}>
                    <Link className="insights-ns-name" to={`/incidents?clusterId=${encodeURIComponent(c.clusterId)}`} title="View this cluster's incidents">
                      {c.clusterDisplayName}
                    </Link>
                    <span className="bar-list-track" role="img" aria-label={`${c.clusterDisplayName}: ${c.reopenedOrFailedCount} reopened or failed, ${c.openCount} open, ${c.totalIncidents} total`}>
                      <span className="split-seg" data-tone="critical" style={{ width: `${(c.reopenedOrFailedCount * 100) / max}%` }} />
                      <span className="split-seg" data-tone="high" style={{ width: `${(open * 100) / max}%` }} />
                      <span className="split-seg" data-tone="ok" style={{ width: `${(closed * 100) / max}%` }} />
                    </span>
                    <span className="insights-ns-meta">
                      <strong>{c.reopenedOrFailedCount}</strong> reopened/failed · <strong>{c.openCount}</strong> open · <strong>{c.totalIncidents}</strong> total
                    </span>
                  </li>
                )
              })}
            </ul>
            </>
          )}
        </InsightCard>
      </div>

      <div className="chart-card-grid">
        <QualityCard kind="rejected" days={days} scopeHint={scopeHint} quality={quality} />
        <QualityCard kind="automation" days={days} scopeHint={scopeHint} quality={quality} />
      </div>

      {data.notBuilt.length > 0 && (
        <details className="insights-notbuilt">
          <summary>Not measured yet · {data.notBuilt.length}</summary>
          <div className="not-built-grid">
            {data.notBuilt.map((n) => (
              <NotBuiltCard key={n.id} label={n.label} reason={n.reason} />
            ))}
          </div>
        </details>
      )}
    </div>
  )
}

function QualityCard({
  kind,
  days,
  scopeHint,
  quality,
}: {
  kind: 'rejected' | 'automation'
  days: number
  scopeHint: string
  quality: { allowed: boolean; isLoading: boolean; error: string | null; data: InsightsRemediationQuality | undefined }
}) {
  const rejected = kind === 'rejected'
  const title = rejected ? 'Fixes people reject' : 'Automation candidates'
  const help = rejected
    ? 'Proposed remediations grouped by action and target kind, kept only when at least one was rejected in the selected scope — a real rejection rate and a pointer to the recipe or policy worth revisiting.'
    : 'Action, target kind and risk combinations that still need a human approval, with every decision made on one. A 100% approval rate over a real sample is the strongest case for promoting it to auto-approve.'
  const rows = rejected ? quality.data?.frequentlyRejected : quality.data?.automationCandidates
  return (
    <InsightCard title={title} help={help} meta={`${days} days`}>
      {!quality.allowed ? (
        <p className="text-muted">Restricted — viewing this needs the remediation:approve capability.</p>
      ) : quality.error ? (
        <p className="form-error" role="alert">
          {quality.error}
        </p>
      ) : quality.isLoading ? (
        <SkeletonLines count={3} />
      ) : !rows || rows.length === 0 ? (
        <p className="text-muted">
          {rejected
            ? scopeHint
              ? `No rejected recommendations for this cluster in the last ${days} days.${scopeHint}`
              : `No rejected recommendations in the last ${days} days.`
            : scopeHint
              ? `No decided approvals for this cluster in the last ${days} days.${scopeHint}`
              : `No decided approvals in the last ${days} days.`}
        </p>
      ) : rejected ? (
        <ul className="insights-quality">
          {quality.data!.frequentlyRejected.map((r) => (
            <li key={`${r.actionType}|${r.targetGvk}`}>
              <span>
                <strong>{actionTypeLabel(r.actionType)}</strong> <span className="kind">{shortKind(r.targetGvk)}</span>
              </span>
              <SplitBar
                legend={false}
                label={`${actionTypeLabel(r.actionType)} decisions`}
                parts={[
                  { tone: 'critical', value: r.rejectedCount, label: 'rejected' },
                  { tone: 'ok', value: Math.max(0, r.decidedCount - r.rejectedCount), label: 'approved' },
                ]}
              />
              <span className="text-muted insights-quality-meta">
                {r.rejectedCount} of {r.decidedCount} rejected ({formatPercent(r.rejectionRate)}) · {formatRelativeTime(r.lastRejectedAt)}
              </span>
              <span className="insights-quality-reason">{r.sampleRejectionReason ? `“${r.sampleRejectionReason}”` : '(no reason given)'}</span>
            </li>
          ))}
        </ul>
      ) : (
        <ul className="insights-quality">
          {quality.data!.automationCandidates.map((c) => (
            <li key={`${c.actionType}|${c.targetGvk}|${c.riskLevel}`}>
              <span>
                <strong>{actionTypeLabel(c.actionType)}</strong> <span className="kind">{shortKind(c.targetGvk)}</span>{' '}
                <span className={riskBadgeClass(c.riskLevel)}>{c.riskLevel} risk</span>
              </span>
              <SplitBar
                legend={false}
                label={`${actionTypeLabel(c.actionType)} decisions`}
                parts={[
                  { tone: 'ok', value: c.approvedCount, label: 'approved' },
                  { tone: 'critical', value: Math.max(0, c.decidedCount - c.approvedCount), label: 'rejected' },
                ]}
              />
              <span className="text-muted insights-quality-meta">
                {c.approvedCount} of {c.decidedCount} approved ({formatPercent(c.approvalRate)}) · {formatRelativeTime(c.lastDecidedAt)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </InsightCard>
  )
}
