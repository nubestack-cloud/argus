// First slice of the incident-detail screen: the incident's own summary
// fields, its raw findings ("what's broken"), a real causal-chain analysis
// ("why"), a real chronological timeline (BACKLOG.md B1), and lazy per-call
// evidence drill-down (BACKLOG.md B2). Still deliberately NOT
// lld/11-ui-design.md §4's full IncidentDetail contract — `/plans` does not
// exist on the backend yet. Extend this page, don't mistake it for the
// finished screen, once it does.
//
// PROJECT.md P25: this file used to hold every panel below inline (3448
// lines). They now live in ./incident-detail/, grouped by the question each
// one answers — this file keeps only the page shell: routing/query wiring,
// the summary strip, and the layout that assembles the panels.
//
// Layout (incident lifecycle redesign, owner-approved 2026-10-12): identity,
// the lifecycle spine (four phases and an outcome, pages/incidentPhases.ts),
// one line saying whose move it is, then the argument in the four-question
// order — What broke, Why, Fix, Did it hold — with facts and history in a
// side rail. Cards for phases that have not started are not drawn.
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { analyzeIncident, getApprovals, getIncident, getIncidentTimeline, ApiError } from '../api/client'
import {
  CAP_INCIDENT_REANALYSE,
  CAP_INCIDENT_TRIAGE,
  CAP_INCIDENT_SILENCE,
  CAP_REMEDIATION_APPROVE,
} from '../api/capabilities'
import type { IncidentDetail } from '../api/types'
import { useAuth } from '../auth/useAuth'
import { useHasCapability } from '../auth/useCapabilities'
import { formatDateTime, formatRelativeTime } from '../utils/time'
import { SkeletonLines } from '../components/Skeleton'
import { SeverityBadge, StateBadge } from '../components/IncidentBadges'
import { MoreIcon } from '../components/icons'
import {
  incidentObservedObject,
  isClosedIncidentState,
  observedObjectTitle,
  stateLabelFor,
} from '../utils/incidents'
import { nothingWasExecuted, resolvedIdentity, validateStage, latestFinding } from './incidentLifecycle'
import { phaseModel } from './incidentPhases'
import { LIVE_FALLBACK_MS } from '../realtime/refresh'
import { AnalyzeButton, DownloadReportButton, AnalysisView } from './incident-detail/AnalysisPanel'
import { ManagedByContext, DetectionSourceContext, AutomationGateNotice } from './incident-detail/OwnershipContext'
import { WhatHappenedDisclosure, PriorOccurrences } from './incident-detail/TimelinePanel'
import { TriageControls } from './incident-detail/TriagePanel'
import { EvidenceTabs } from './incident-detail/InsightSections'
import { LifecycleSpine, NowLineBar } from './incident-detail/LifecycleSpine'
import { HistoryRail } from './incident-detail/HistoryRail'
import { FixSection } from './incident-detail/FixSection'
import { buildIncidentSummaryMarkdown } from './incidentReport'
import { CopyButton } from '../components/CopyButton'

// Severity as a `.sev-*` class on a CONTAINER, which sets --sev-fill/--sev-tint
// for a mark inside it to read — the mechanism `.severity-rule` uses, applied
// here to the identity row's dot. Always alongside the severity badge's word,
// never instead of it (lld/11 §8).
const SEVERITY_TINT: Record<IncidentDetail['severity'], string> = {
  critical: 'sev-critical',
  high: 'sev-high',
  medium: 'sev-medium',
  low: 'sev-low',
}

export function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const canReanalyse = useHasCapability(CAP_INCIDENT_REANALYSE)
  const canTriage = useHasCapability(CAP_INCIDENT_TRIAGE)
  const canTolerate = useHasCapability(CAP_INCIDENT_SILENCE)
  const canApprove = useHasCapability(CAP_REMEDIATION_APPROVE)

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['incidents', id],
    queryFn: () => getIncident(id!, accessToken!),
    enabled: !!accessToken && !!id,
    // Every state change to THIS incident publishes IncidentUpdated, which
    // invalidates the ['incidents'] prefix and so this key (realtime/
    // refresh.ts). The interval is the fallback for an undelivered event.
    refetchInterval: LIVE_FALLBACK_MS,
  })

  // BACKLOG D8 A8 (ask 1): the same GET /approvals the queue page uses,
  // reused here rather than a new endpoint — this incident's plan carries no
  // `alreadyApproved`/`supersededByUrl` on its own (those are computed only
  // for the queue query, against remediation_approval_decisions/
  // superseded_by_url), so fetching the one canonical value is what keeps
  // this mount and the queue's from ever describing one plan two ways.
  //
  // GET /approvals itself requires remediation:approve (see api/client.ts's
  // own doc comment on getApprovals) — skipped entirely without that
  // capability rather than fired and left to 403, matching the queue page's
  // own whole-page gate for the same endpoint.
  const approvalsQuery = useQuery({
    queryKey: ['approvals'],
    queryFn: () => getApprovals(accessToken!),
    enabled: !!accessToken && canApprove,
    refetchInterval: LIVE_FALLBACK_MS,
  })
  const approvalItem = approvalsQuery.data?.approvals.find((item) => item.incidentId === id)

  const analyzeMutation = useMutation({
    mutationFn: () => analyzeIncident(id!, accessToken!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['incidents', id] }),
  })

  // BACKLOG.md D9 U2: `analyzeMutation.isPending` alone is only true in the
  // ONE browser tab that clicked Analyze — a server-side auto-analysis
  // (BACKLOG.md C12 just enabled it) or a re-analysis launched from another
  // tab left this tab's Analysis card looking identical to Detected's empty
  // state, with nothing on screen saying an investigation was actually
  // running. `data.state` is the server's own fact, true in every tab, and
  // the query above is refreshed by the same IncidentUpdated event the state
  // change publishes — so this reads investigatingNow within a round trip of
  // the transition in every tab, not just the one that caused it.
  const investigatingNow = analyzeMutation.isPending || data?.state === 'Investigating'
  // PROJECT.md M1: the POST answers 202 the moment the run is claimed, so
  // isPending is only that round trip. "This tab started it" is the run whose
  // start the 202 reported being the one the incident now shows.
  const startedHere =
    analyzeMutation.isPending ||
    (!!analyzeMutation.data && analyzeMutation.data.startedAt === data?.analysisStartedAt)

  // The timeline the history rail shows (same query key, one request): the
  // page reads one fact from it — whether a person closed this incident, which
  // resolutionKind cannot distinguish from the symptom stopping on its own.
  const timelineQuery = useQuery({
    queryKey: ['incidents', id, 'timeline'],
    queryFn: () => getIncidentTimeline(id!, accessToken!),
    enabled: !!accessToken && !!id,
    // Shared with HistoryRail and "What happened"; IncidentUpdated
    // invalidates the ['incidents'] prefix, so this never goes stale silently.
    staleTime: 30_000,
  })
  const resolvedByPerson =
    !!data &&
    data.state === 'Resolved' &&
    data.resolutionKind !== 'remediated' &&
    !!timelineQuery.data?.events.some((e) => e.eventType === 'IncidentResolved')

  const finding = data ? latestFinding(data.findings) : null
  // The four phases, the outcome and "whose move" — derived once from the
  // stage functions (pages/incidentPhases.ts) so the spine, the now line and
  // the cards below read one set of answers.
  const model = data
    ? phaseModel(data, {
        investigating: investigatingNow,
        canApprove,
        executionBlockedReason: approvalItem?.executionBlockedReason,
        resolvedByPerson,
      })
    : null
  // Computed once: "is this incident history?" — isClosedIncidentState is the
  // shared definition; a local state list would be the third copy of it.
  const incidentIsHistorical = !!data && isClosedIncidentState(data.state)
  // The Fix section appears once there is a diagnosis to act on (or a plan
  // from a run that stopped early). A closed incident where nothing was ever
  // executed folds it to one line instead (PROJECT.md D13's majority case).
  const showFix =
    !!data?.analysis &&
    !investigatingNow &&
    (data.analysis.status === 'complete' || !!data.analysis.plan) &&
    !(incidentIsHistorical && nothingWasExecuted(data) && !data.pullRequest)
  // "Did it hold" appears only once something was applied and watched (or the
  // watch already ended in a recurrence); before that the spine shows it as
  // ahead, and an empty card would say nothing.
  const holdState = data ? validateStage(data).state : 'pending'
  const showHold =
    !!data &&
    data.state !== 'AwaitingMerge' &&
    ((holdState === 'current' || holdState === 'blocked') && (!!data.analysis?.plan?.execution || data.state === 'Validating' || data.state === 'Reopened' || data.state === 'ValidationUnknown') ||
      (data.state === 'Resolved' && data.resolutionKind === 'remediated'))
  const identity = data ? resolvedIdentity(data) : { name: '', kind: '', fault: '', faultLine: '' }
  const faultLine = identity.faultLine
  // B174: the heading above is now the owning WORKLOAD wherever the agent
  // resolved one (incidentIdentity, which resolvedIdentity wraps). The Pod
  // that carried the symptom is real evidence and stays on the page — as a
  // fact in the meta row, not as the heading — because on a Deployment-owned
  // fault the rollout that fixes it replaces that Pod, and a page headed by
  // a name that no longer resolves sends the reader to `kubectl describe` on
  // nothing. Null when the object is its own subject; there the heading
  // already names it and a second mention would be one fact twice.
  const observedObject = data ? incidentObservedObject(data) : null
  // Σ of every reason's TRUE count — findingGroups exists precisely so this is
  // not derived from the bounded findings slice.
  const totalEvents = data ? data.findingGroups.reduce((sum, group) => sum + group.count, 0) : 0
  const maxReasonCount = data ? Math.max(1, ...data.findingGroups.map((g) => g.count)) : 1

  return (
    <div className="page incident-detail-page">
      {isLoading && (
        // Shaped like the loaded page: the header strip, the spine's four
        // phases and outcome, the "now" line, then the argument and the rail.
        <>
          <div className="incident-summary-strip" aria-hidden="true">
            <SkeletonLines count={3} />
          </div>
          <div className="lc-spine lc-spine-skeleton" aria-hidden="true">
            {[1, 2, 3, 4, 5].map((n) => (
              <div key={n} className="lc-phase">
                <span className="skeleton" style={{ width: '60%', height: '0.8rem' }} />
                <span className="skeleton" style={{ width: '40%', height: '0.7rem', marginTop: '6px' }} />
              </div>
            ))}
          </div>
          <div className="lc-body">
            <div className="lc-main">
              <div className="card" aria-hidden="true"><SkeletonLines count={4} /></div>
              <div className="card" aria-hidden="true"><SkeletonLines count={8} /></div>
              <div className="card" aria-hidden="true"><SkeletonLines count={8} /></div>
            </div>
            <div className="lc-rail">
              <div className="card" aria-hidden="true"><SkeletonLines count={4} /></div>
              <div className="card" aria-hidden="true"><SkeletonLines count={6} /></div>
            </div>
          </div>
        </>
      )}

      {isError && (
        <p className="form-error" role="alert">
          {error instanceof ApiError
            ? error.detail
              ? `${error.message} — ${error.detail}`
              : error.message
            : 'Failed to load incident.'}
        </p>
      )}

      {data && model && (
        <>
          {/* IDENTITY — what broke, in words. The <h1> is the object, never the
              fingerprint (BACKLOG D8 A2). One primary action, Close out, and
              the rest behind ⋯ (incident lifecycle redesign, 2026-10-12). */}
          <div className="incident-summary-strip">
            <div className="incident-summary-head">
              <div className="incident-summary-identity">
                {/* The severity dot is an ADDITION to the severity badge's
                    word, never a replacement (lld/11 §8), hence aria-hidden. */}
                <div className={`identity-block identity-block-inline ${SEVERITY_TINT[data.severity] ?? 'sev-neutral'}`}>
                  <span className="identity-block-severity" aria-hidden="true" />
                  <h1 className="identity-block-name" title={data.workloadKey ?? data.objectGvk ?? undefined}>{identity.name}</h1>
                  {identity.kind && <span className="identity-block-kind">{identity.kind}</span>}
                </div>
                <div className="incident-summary-badges">
                  <SeverityBadge severity={data.severity} />
                  <StateBadge
                    state={data.state}
                    resolutionKind={resolvedByPerson ? undefined : data.resolutionKind}
                    label={resolvedByPerson ? 'Resolved · by a person' : stateLabelFor(data.state, data.analysis)}
                  />
                </div>
                {/* Clamped; the full sentence is in What broke, unclamped. */}
                <p className="incident-summary-fault" title={faultLine}>{faultLine}</p>
              </div>

              <div className="incident-summary-actions">
                <AnalyzeButton
                  mutation={analyzeMutation}
                  hasAnalysis={!!data.analysis}
                  investigating={investigatingNow}
                  runError={data.analysisError}
                  disabledReason={canReanalyse ? undefined : `Missing capability: ${CAP_INCIDENT_REANALYSE}`}
                />
                <TriageControls
                  incidentId={id!}
                  state={data.state}
                  disabledReason={canTriage ? undefined : `Missing capability: ${CAP_INCIDENT_TRIAGE}`}
                  toleranceDisabledReason={canTolerate ? undefined : `Missing capability: ${CAP_INCIDENT_SILENCE}`}
                />
                <MoreActions>
                  <DownloadReportButton incident={data} />
                  {/* CI-U12: a short Markdown summary for a channel or ticket. */}
                  <CopyButton
                    text={buildIncidentSummaryMarkdown(data, `${window.location.origin}/incidents/${encodeURIComponent(data.id)}`)}
                    label="Copy summary"
                  />
                </MoreActions>
              </div>
            </div>

            <div className="incident-summary-meta">
              <span>Cluster <Link to={`/clusters/${data.clusterId}`}>{data.clusterDisplayName}</Link></span>
              {/* "Observed on", past tense, the same wording in every state:
                  ARGUS never re-reads the Pod, so a branch claiming it is gone
                  or still failing would be a guess (B174). */}
              {observedObject && (
                <span>
                  Observed on <strong title={observedObjectTitle(observedObject)}>{observedObject.label}</strong>
                </span>
              )}
              <span>First seen <strong title={formatDateTime(data.firstSeen)}>{formatRelativeTime(data.firstSeen)}</strong></span>
              <span>Last seen <strong title={formatDateTime(data.lastSeen)}>{formatRelativeTime(data.lastSeen)}</strong></span>
              {/* findingGroups, not findings.length — findings is a bounded
                  slice and never a count. */}
              <span>Events <strong>{totalEvents.toLocaleString()}</strong> across {data.findingGroups.length} reason{data.findingGroups.length === 1 ? '' : 's'}</span>
              {/* PROJECT.md IN5: objects that joined this incident, e.g. the
                  pods waiting on one Secret's producer. */}
              {(data.objectsFolded ?? 0) > 1 && (
                <span>
                  Objects <strong>{data.objectsFolded}</strong>
                </span>
              )}
              {data.fleetGroupId && (
                <Link className="incident-summary-scope" to={`/incidents?fleetGroupId=${encodeURIComponent(data.fleetGroupId)}`}>
                  Also occurring on other clusters →
                </Link>
              )}
            </div>
          </div>

          {/* THE SPINE — four phases and the outcome, each phase's state read
              from the stage functions (pages/incidentPhases.ts). */}
          <LifecycleSpine
            phases={model.phases}
            outcome={model.outcome}
            targets={{
              detected: 'incident-broke',
              diagnosed: 'incident-why',
              fix: showFix ? 'incident-fix' : undefined,
              holding: showHold ? 'incident-hold' : undefined,
            }}
          />

          {/* WHOSE MOVE — one line, with a link to where the move is made. */}
          <NowLineBar now={model.now} />

          <div className="lc-body">
            <div className="lc-main">
              {/* WHAT BROKE */}
              <section className="card lc-card" id="incident-broke" tabIndex={-1} aria-labelledby="incident-broke-h">
                <div className="lc-card-head">
                  <h2 id="incident-broke-h">What broke</h2>
                  <span className="field-hint">{totalEvents.toLocaleString()} occurrence{totalEvents === 1 ? '' : 's'}</span>
                </div>
                <p className="lc-finding">
                  {finding ? `${finding.gvk} ${finding.namespace}/${finding.objectName}: ${finding.message}` : `No finding recorded — incident ${data.fingerprint.slice(0, 12)}`}
                </p>
                {finding && <DetectionSourceContext finding={finding} findings={data.findings} />}
                {data.ownership && <ManagedByContext ownership={data.ownership} />}
                {data.findingGroups.length > 0 && (
                  <ul className="lc-reasons" aria-label="Occurrences by reason">
                    {data.findingGroups.map((g) => (
                      <li key={g.reason}>
                        <span className="lc-reason-name">{g.reason}</span>
                        <span className="lc-reason-bar" aria-hidden="true">
                          <span style={{ width: `${Math.max(2, (g.count / maxReasonCount) * 100)}%` }} />
                        </span>
                        <span className="lc-reason-count">{g.count.toLocaleString()}</span>
                      </li>
                    ))}
                  </ul>
                )}
                {data.workloadGroupId && (
                  <p className="detail-callout">
                    <Link to={`/incidents?workloadGroupId=${encodeURIComponent(data.workloadGroupId)}`}>
                      This{data.openingReason ? ` ${data.openingReason}` : ''} is also happening on other pods of the same workload →
                    </Link>
                  </p>
                )}
                {/* Cross-object correlation (BACKLOG.md A3b) — read-only. */}
                {data.objectGroupId && (
                  <p className="detail-callout">
                    <Link to={`/incidents?objectGroupId=${encodeURIComponent(data.objectGroupId)}`}>
                      This may be the same underlying outage as a failure on a related object →
                    </Link>
                  </p>
                )}
              </section>

              {/* WHY */}
              <section className="card lc-card" id="incident-why" tabIndex={-1} aria-labelledby="incident-why-h">
                <div className="lc-card-head">
                  <h2 id="incident-why-h">Why</h2>
                  {data.analysis && (
                    <span className="field-hint">
                      {data.analysis.causalChain.length} step{data.analysis.causalChain.length === 1 ? '' : 's'}
                    </span>
                  )}
                </div>
                {investigatingNow && (
                  <div className="analysis-investigating" aria-live="polite">
                    <p>
                      Investigating — gathering live evidence from the cluster (events, logs, resource
                      descriptions, owner chains). This can take a few minutes.
                      {data.analysisStartedAt && (
                        <>
                          {' Started '}
                          <span title={formatDateTime(data.analysisStartedAt)}>
                            {formatRelativeTime(data.analysisStartedAt)}
                          </span>
                          .
                        </>
                      )}
                      {/* BACKLOG.md D9 U2: said plainly when this tab did not start it. */}
                      {!startedHere &&
                        ' This was started automatically or from another tab — this page updates on its own when it finishes.'}
                    </p>
                    <SkeletonLines count={3} />
                  </div>
                )}
                {!investigatingNow && data.analysis && (
                  <AnalysisView
                    analysis={data.analysis}
                    evidence={data.evidence}
                    recentChanges={data.recentChanges}
                    incidentId={data.id}
                    clusterId={data.clusterId}
                    clusterName={data.clusterDisplayName}
                  />
                )}
                {!investigatingNow && !data.analysis && (
                  <>
                    <p className="empty-state">
                      Not analyzed yet — run an investigation to gather live evidence from the cluster
                      and build a step-by-step causal chain.
                    </p>
                    {/* PROJECT.md T14: why this has not been auto-analyzed. */}
                    {data.automationGate && <AutomationGateNotice gate={data.automationGate} />}
                  </>
                )}
                {/* The evidence beneath the diagnosis, one view at a time. */}
                <EvidenceTabs incident={data} />
              </section>

              {/* FIX — only once there is a diagnosis to act on. A closed
                  incident that never reached a fix says so in one line. */}
              {showFix ? (
                <FixSection
                  incident={data}
                  approvalItem={approvalItem}
                  approvalsLoading={approvalsQuery.isLoading}
                  canApprove={canApprove}
                  hideManualSteps={analyzeMutation.isPending}
                />
              ) : (
                incidentIsHistorical &&
                data.analysis && (
                  <p className="lc-ghost">
                    <strong>Fix</strong> · No fix was executed — nothing to approve, apply or validate.
                  </p>
                )
              )}

              {/* DID IT HOLD — only once something was applied or watched. */}
              {showHold && (
                <section className="card lc-card" id="incident-hold" tabIndex={-1} aria-labelledby="incident-hold-h">
                  <div className="lc-card-head">
                    <h2 id="incident-hold-h">Did it hold</h2>
                  </div>
                  <p>{validateStage(data).text}</p>
                  {/* On a sibling-object reopen, name both objects: the fixed
                      one stopped reporting; another is failing now. */}
                  {data.reopenedBy && !data.reopenedBy.sameObject && (
                    <div className="verification-chip-row">
                      <span className="verification-chip verification-chip-neutral">
                        Fixed object: {identity.name || 'this object'} — stopped reporting
                      </span>
                      <span className="verification-chip verification-chip-neutral">
                        Now failing: {data.reopenedBy.objectName ?? 'another object'}
                        {data.reopenedBy.reason ? ` — ${data.reopenedBy.reason}` : ''}
                      </span>
                    </div>
                  )}
                  <p className="field-hint">
                    No new findings is not a positive re-check — this watches the detector, it does not re-read the object.
                  </p>
                </section>
              )}
            </div>

            {/* THE RAIL — facts and history beside the argument. */}
            <aside className="lc-rail" aria-label="Facts and history">
              <section className="card lc-rail-card" aria-labelledby="incident-facts-h">
                <div className="lc-card-head">
                  <h2 id="incident-facts-h">Facts</h2>
                </div>
                <dl className="lc-facts">
                  <dt>Cluster</dt>
                  <dd><Link to={`/clusters/${data.clusterId}`}>{data.clusterDisplayName}</Link></dd>
                  {data.ownership && (
                    <>
                      <dt>Managed by</dt>
                      <dd>
                        {data.ownership.sourceKind} {data.ownership.sourceNamespace ? `${data.ownership.sourceNamespace}/` : ''}
                        {data.ownership.sourceName}
                      </dd>
                    </>
                  )}
                  {data.workloadKey && (
                    <>
                      <dt>Workload</dt>
                      <dd>{workloadLabel(data.workloadKey)}</dd>
                    </>
                  )}
                  <dt>First seen</dt>
                  <dd title={formatDateTime(data.firstSeen)}>{formatDateTime(data.firstSeen)}</dd>
                  {data.resolvedAt && (
                    <>
                      <dt>Closed</dt>
                      <dd title={formatDateTime(data.resolvedAt)}>{formatDateTime(data.resolvedAt)}</dd>
                    </>
                  )}
                  {data.analysis && (
                    <>
                      <dt>Investigated</dt>
                      <dd>
                        {formatRelativeTime(data.analysis.createdAt)}
                        {data.analysis.triggeredBy === 'auto' ? ' · automatically' : ''}
                      </dd>
                    </>
                  )}
                </dl>
                <PriorOccurrences items={data.priorIncidents ?? []} />
              </section>
              <HistoryRail incidentId={data.id}>
                <WhatHappenedDisclosure groups={data.findingGroups} findings={data.findings} incidentId={data.id} />
              </HistoryRail>
            </aside>
          </div>
        </>
      )}
    </div>
  )
}

// workloadKey is "gvk|namespace|name" on the wire; the reader wants
// "Deployment apps/gwas-frontend". Anything not in that shape is shown as is.
function workloadLabel(key: string): string {
  const [gvk, ns, name] = key.split('|')
  if (!gvk || !name) return key
  return `${gvk.split('/').pop()} ${ns ? `${ns}/` : ''}${name}`
}

// The secondary actions — the report and the summary — behind one button, so
// the header carries one primary action and Close out (redesign, 2026-10-12).
// The menu stays mounted while closed so a Copy that just succeeded can still
// show its confirmation; it is hidden, not unmounted.
function MoreActions({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onDoc)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDoc)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])
  return (
    <div className="more-actions" ref={ref}>
      <button
        type="button"
        className="secondary more-actions-trigger"
        aria-haspopup="true"
        aria-expanded={open}
        aria-label="More actions"
        onClick={() => setOpen((o) => !o)}
      >
        <MoreIcon />
      </button>
      <div className="more-actions-menu" hidden={!open}>
        {children}
      </div>
    </div>
  )
}
