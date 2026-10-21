import { useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'
import {
  ApiError,
  acceptCluster,
  createEnrollmentToken,
  getApprovals,
  getAutomationWindows,
  getCircuitBreaker,
  getClusters,
  getIncidentCounts,
  getIncidentOverview,
  getIncidentQueue,
  getSettings,
  getSpendToday,
} from '../api/client'
import type { AutomationWindowsResponse, AutonomySettings, CircuitBreakerResponse, Cluster, ClusterState, CreateEnrollmentTokenResponse } from '../api/types'
import { CAP_CLUSTER_ACCEPT, CAP_CLUSTER_ONBOARD, CAP_ORG_SETTINGS_WRITE, CAP_REMEDIATION_APPROVE, CAP_SPEND_READ } from '../api/capabilities'
import { useAuth } from '../auth/useAuth'
import { useHasCapability } from '../auth/useCapabilities'
import { EnrollTokenModal } from '../components/EnrollTokenModal'
import { AgentInstallNotes } from '../components/AgentInstallNotes'
import { agentInstallCommand } from '../utils/agentInstall'
import { FleetCoverageBanner } from '../components/FleetCoverageBanner'
import { CopyButton } from '../components/CopyButton'
import { HelpTip } from '../components/HelpTip'
import { Segmented } from '../components/SplitBar'
import { SkeletonCard, SkeletonLines, SkeletonTiles } from '../components/Skeleton'
import { formatRelativeTime } from '../utils/time'
import { spendTileState } from '../utils/spend'
import { isLiveStreamDegraded, useLiveStatus } from '../realtime/liveStatus'
import { CLOCK_POLL_MS, LIVE_FALLBACK_MS, SLOW_FALLBACK_MS, STATIC_POLL_MS } from '../realtime/refresh'
import { useFleetUpgradeScans } from '../fleet/fleetUpgrade'
import { CapacityTile, NodesTile, OpenIncidentsTile, WaitingTile } from '../overview/Tiles'
import { ClusterRings, IncidentActivity, WaitingQueue } from '../overview/NowBand'
import { ComingDue } from '../overview/ComingDue'
import { VersionSkew } from '../overview/VersionSkew'
import { comingDueSummary, deliverySummary, ladderSummary, postureSummary } from '../overview/summaries'
import {
  CapacityHoneycomb,
  DeliveryAgents,
  MetricSwitch,
  PostureHeatmap,
  UpgradeLadder,
  type CapacityMetric,
} from '../overview/Standing'
import { hasFacts, oldestRead, useFleetData } from '../overview/useFleetData'
import { clusterNodes, fleetCapacity, formatWait, queueRows, upgradeLadder } from '../overview/model'

// The fleet Overview: one pane for every cluster, arranged by when things have
// consequences. NOW is the incident work (where the open incidents are in the
// loop, what is waiting on a person, each cluster's open incidents); NEXT 90
// DAYS is every dated item in the fleet; STANDING is debt with no due date —
// upgrade readiness, posture, capacity, delivery and agents.
//
// Incident figures come from the hub's whole-set aggregates (GET
// /incidents/overview and the counts on GET /incidents), never from counting a
// fetched page. The fleet sections read each cluster's last facts and its
// agent's live checks; useFleetData says what that costs.

function formatDuration(milliseconds: number): string {
  const minutes = Math.max(1, Math.round(milliseconds / 60_000))
  if (minutes < 60) return `${minutes}m`
  const hours = Math.round(minutes / 60)
  if (hours < 48) return `${hours}h`
  return `${Math.round(hours / 24)}d`
}

function queryErrorMessage(error: unknown, fallback: string): string {
  if (!(error instanceof ApiError)) return fallback
  return error.detail ? `${error.message} — ${error.detail}` : error.message
}

function OverviewSkeleton() {
  // The same shape as what arrives — four tiles, then the Now band's two
  // columns — so the page does not reflow when the data lands.
  return (
    <>
      <SkeletonTiles count={4} />
      <div className="ov-now" aria-hidden="true">
        <div className="card"><SkeletonLines count={6} /></div>
        <SkeletonCard lines={4} />
      </div>
    </>
  )
}

// mostAdvancedCluster picks which cluster OnboardingWizard's step
// determination should track when more than one exists mid-onboarding
// (e.g. a second enrollment started before the first finished) — the one
// that's gotten furthest, not just the first one in whatever order the API
// happened to return. Active/Degraded/Disconnected all rank equally: each
// means this cluster reached Active at some point, which is what the
// wizard's step 4 (waiting for a heartbeat) is actually watching for — a
// later flap to Degraded/Disconnected doesn't undo that milestone.
const CLUSTER_PROGRESS_RANK: Record<ClusterState, number> = {
  Active: 4,
  Degraded: 4,
  Disconnected: 4,
  Provisioning: 3,
  PendingApproval: 2,
  IncompatibleVersion: 1,
  Rejected: 1,
  Archived: 0,
}

function mostAdvancedCluster(clusters: Cluster[]): Cluster | null {
  if (clusters.length === 0) return null
  return clusters.reduce((best, c) => (CLUSTER_PROGRESS_RANK[c.state] > CLUSTER_PROGRESS_RANK[best.state] ? c : best), clusters[0])
}

// OnboardingWizard replaces a purely descriptive step list with one that
// tracks the real cluster it's walking the user through — 06-ideas-for-
// additions item 16's "guided path: connect first cluster, install agent,
// accept cluster, verify heartbeat." Exactly 4 steps, ending at "verify
// heartbeat" — getting a cluster to Active is this component's whole job,
// full stop; it does not try to also represent "waiting for the first
// finding" as a step, since the parent unmounts this entire card the
// moment that job is done (see OverviewPage's own fleetOnboarded check).
// An earlier version gated that on "org has never seen an incident"
// instead, which meant a healthy, connected, zero-incident fleet stayed
// trapped displaying "First run: connect your first cluster" forever —
// exactly backwards, since a quiet fleet is the good outcome. "Load sample
// data instead" lives in the footer, available from step 1 onward, rather
// than gated behind reaching a final step — it's an escape hatch from
// waiting on real infrastructure, not a reward for finishing. Re-derives
// its current step from live data every render rather than remembering
// "step N" in its own state rather than a client-side illusion of progress
// that could drift from what's actually true.
// Exported (BACKLOG P3) so its own test file can render exactly this
// component with plain props, matching the pattern ClusterDetailPage.tsx
// already established for DetectionCard/RemediationAuthorityCard: a
// presentational-plus-mutations subcomponent pulled out of a big page is
// tested directly rather than through the whole page's seven queries.
export function OnboardingWizard({
  clusters,
  canOnboard,
  canAccept,
}: {
  clusters: Cluster[]
  canOnboard: boolean
  canAccept: boolean
}) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const [tokenResult, setTokenResult] = useState<CreateEnrollmentTokenResponse | null>(null)
  const [advancedEnrollOpen, setAdvancedEnrollOpen] = useState(false)

  const tokenMutation = useMutation({
    mutationFn: () => createEnrollmentToken({ ttlClass: 'B', maxRedemptions: 1, scopeHint: {} }, accessToken!),
    onSuccess: (data) => setTokenResult(data),
  })
  const acceptMutation = useMutation({
    mutationFn: (clusterId: string) => acceptCluster(clusterId, accessToken!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['clusters'] }),
  })
  const cluster = mostAdvancedCluster(clusters)

  // Steps 1-2 (create token, install agent) stay "current" until a cluster
  // actually shows up — POST /enroll publishes ClusterUpdated (internal/api/
  // enroll.go), which refreshes this page's own clustersQuery, so a real
  // agent's first check-in surfaces here in about as long as the round trip
  // takes, no separate wizard-owned polling loop needed. Caps at 4: the parent
  // (OverviewPage) never renders this component once any cluster has
  // actually reached Active (fleetOnboarded), so "stepIndex 4" here always
  // means "still Provisioning," never "already succeeded" — there's no
  // "done" state to render for step 4 the way steps 1-3 have one.
  let stepIndex = 1
  if (cluster) {
    if (cluster.state === 'PendingApproval') stepIndex = 3
    else stepIndex = 4
  } else if (tokenResult) {
    stepIndex = 2
  }

  return (
    <section className="card overview-onboarding-card" aria-labelledby="overview-onboarding-title">
      <div className="overview-onboarding-hero">
        <p className="eyebrow">First run</p>
        <h2 id="overview-onboarding-title">Connect your first cluster</h2>
        <p>Enrol an agent, accept it, and see its first heartbeat. Or load sample data to look around first.</p>
      </div>

      <ol className="overview-onboarding-steps">
        <li className={stepIndex > 1 ? 'onboarding-step-done' : 'onboarding-step-current'}>
          <span>1</span>
          <div>
            <strong>Create an enrollment token</strong>
            {stepIndex === 1 && (
              <>
                <p>A one-hour, single-use token authorizes exactly one agent install.</p>
                <div className="overview-onboarding-actions">
                  <button type="button" onClick={() => tokenMutation.mutate()} disabled={!canOnboard || tokenMutation.isPending} title={canOnboard ? undefined : `Missing capability: ${CAP_CLUSTER_ONBOARD}`}>
                    {tokenMutation.isPending ? 'Generating…' : 'Generate token'}
                  </button>
                  <button type="button" className="overview-action overview-action-secondary" onClick={() => setAdvancedEnrollOpen(true)} disabled={!canOnboard}>
                    Advanced options…
                  </button>
                </div>
                {tokenMutation.isError && (
                  <p className="form-error inline-error" role="alert">
                    {tokenMutation.error instanceof ApiError ? tokenMutation.error.message : 'Could not generate a token.'}
                  </p>
                )}
              </>
            )}
            {stepIndex > 1 && <p>Done.</p>}
          </div>
        </li>

        <li className={stepIndex > 2 ? 'onboarding-step-done' : stepIndex === 2 ? 'onboarding-step-current' : 'onboarding-step-pending'}>
          <span>2</span>
          <div>
            <strong>Install the agent</strong>
            {stepIndex === 2 && tokenResult && (
              <>
                <p>Run this against the target cluster (needs helm and kubectl):</p>
                <div className="code-block-row">
                  <pre className="code-block">{agentInstallCommand(tokenResult.token, tokenResult.agentInstall)}</pre>
                  <CopyButton text={agentInstallCommand(tokenResult.token, tokenResult.agentInstall)} label="Copy" />
                </div>
                <AgentInstallNotes install={tokenResult.agentInstall} />
                <p className="field-hint">
                  This page updates when the agent first calls in. For many clusters, issue one fleet token
                  under Clusters and roll the agent chart out with your GitOps tool.
                </p>
              </>
            )}
            {stepIndex <= 1 && <p>Generate a token first.</p>}
            {stepIndex > 2 && <p>Agent connected.</p>}
          </div>
        </li>

        <li className={stepIndex > 3 ? 'onboarding-step-done' : stepIndex === 3 ? 'onboarding-step-current' : 'onboarding-step-pending'}>
          <span>3</span>
          <div>
            <strong>Accept the cluster</strong>
            {stepIndex === 3 && cluster && (
              <>
                <p>
                  <strong>{cluster.displayName}</strong> is pending approval — accepting it lets its mTLS
                  tunnel come online.
                </p>
                <div className="overview-onboarding-actions">
                  <button
                    type="button"
                    onClick={() => acceptMutation.mutate(cluster.id)}
                    disabled={!canAccept || acceptMutation.isPending}
                    title={canAccept ? undefined : `Missing capability: ${CAP_CLUSTER_ACCEPT}`}
                  >
                    {acceptMutation.isPending ? 'Accepting…' : 'Accept cluster'}
                  </button>
                </div>
                {acceptMutation.isError && (
                  <p className="form-error inline-error" role="alert">
                    {acceptMutation.error instanceof ApiError ? acceptMutation.error.message : 'Accept failed.'}
                  </p>
                )}
              </>
            )}
            {stepIndex < 3 && <p>Waiting for the agent to connect.</p>}
            {stepIndex > 3 && <p>Accepted.</p>}
          </div>
        </li>

        <li className={stepIndex === 4 ? 'onboarding-step-current' : 'onboarding-step-pending'}>
          <span>4</span>
          <div>
            <strong>Verify heartbeat</strong>
            {stepIndex === 4 && (
              <p>Waiting for the agent's tunnel to report in, usually seconds after its pod runs. This card goes when it is Active.</p>
            )}
            {stepIndex < 4 && <p>Not yet reached.</p>}
          </div>
        </li>
      </ol>

      <div className="overview-onboarding-actions overview-onboarding-footer-actions">
        <Link to="/clusters" className="overview-action overview-action-secondary">
          Open Clusters page
        </Link>
      </div>
      {advancedEnrollOpen && <EnrollTokenModal onClose={() => setAdvancedEnrollOpen(false)} />}
    </section>
  )
}



// AutomationStatusCard answers the one question the rest of this page cannot:
// is the automatic machinery actually running? One line at the foot of the
// Overview, because a tripped breaker or an empty allowlist makes automation
// silently do nothing while the operator's mental model says it is running.
//
// A state pill plus four BOUND chips, and the four are not one on/off light on
// purpose: the namespace allowlist is scope, the blast-radius caps are volume,
// the breaker is outcome, the window is time, and each sees a failure the
// other three cannot (DESIGN.md §9.2; CircuitBreakerResponse's doc comment).
//
// Exported so this file's own test can render it with plain props.
export function AutomationStatusCard({ canManageSettings, unattendedEnabled, autonomy, breaker, windows, aside }: {
  canManageSettings: boolean
  unattendedEnabled: boolean
  autonomy?: AutonomySettings
  breaker?: CircuitBreakerResponse
  windows?: AutomationWindowsResponse
  /** Rendered at the right end of the line (the Overview puts spend there). */
  aside?: ReactNode
}) {
  // Everything here is behind org:settings:write, so a viewer sees an honest
  // "you cannot see this" rather than a line of falsely reassuring defaults.
  if (!canManageSettings) {
    return (
      <section className="card ov-guard" aria-label="Automation">
        <span className="ov-guard-label">Automation</span>
        <span className="ov-guard-summary">Your role cannot read the automation settings.</span>
        {aside}
      </section>
    )
  }

  const openTrip = breaker?.open?.[0]
  const freezeActive = windows ? !windows.automationOpenNow : false
  // Absent is empty, which is also the server's deny-everything default
  // (migration 000055: an empty allowlist denies rather than permits).
  const allowlist = autonomy?.unattendedNamespaces ?? []
  const namespaceSummary = allowlist.length === 0
    ? 'No namespace allowlisted'
    : `Namespaces: ${allowlist.slice(0, 3).join(', ')}${allowlist.length > 3 ? ` +${allowlist.length - 3} more` : ''}`
  // Is anything being held back right now? The empty allowlist counts, since
  // with it nothing can ever run even though execution is "on".
  const heldBack = !!openTrip || freezeActive || (unattendedEnabled && allowlist.length === 0)

  return (
    <section className={heldBack && unattendedEnabled ? 'card ov-guard ov-guard-held' : 'card ov-guard'} aria-label="Automation">
      <span className="ov-guard-label">Automation</span>
      <span
        className={`badge ${unattendedEnabled ? 'badge-green' : 'badge-gray'}`}
        title={unattendedEnabled ? (heldBack ? 'Unattended execution is on but currently held back.' : 'Unattended execution is running and unblocked.') : 'Nothing runs without a person, by configuration.'}
      >
        Unattended execution {unattendedEnabled ? (heldBack ? 'on · held back' : 'on') : 'off'}
      </span>
      <BoundChip permits={allowlist.length > 0} title={allowlist.length === 0 ? 'An empty allowlist denies: unattended execution may act in no namespace.' : allowlist.join(', ')}>
        {namespaceSummary}
      </BoundChip>
      {autonomy ? (
        <BoundChip permits>
          Blast radius {autonomy.effectiveMaxUnattendedPerCluster}/cluster · {autonomy.effectiveMaxUnattendedFleetWide}/fleet per{' '}
          {formatDuration(autonomy.effectiveUnattendedWindowSeconds * 1000)}
        </BoundChip>
      ) : (
        <BoundChip permits={false}>Blast radius caps not loaded</BoundChip>
      )}
      {/* Three breaker states, not two: `enabled: false` permits everything and
          reads worst as a green tick, so it sits with a tripped one. */}
      {breaker == null ? (
        <BoundChip permits={false}>Circuit breaker state unavailable</BoundChip>
      ) : openTrip ? (
        <BoundChip permits={false}>Circuit breaker open — {openTrip.reason}</BoundChip>
      ) : breaker.enabled === false ? (
        <BoundChip permits={false}>Circuit breaker disabled — failing changes stop nothing</BoundChip>
      ) : (
        <BoundChip permits>Circuit breaker closed</BoundChip>
      )}
      {windows == null ? (
        <BoundChip permits={false}>Freeze window state unavailable</BoundChip>
      ) : freezeActive ? (
        <BoundChip permits={false}>Change freeze in force — {windows.decisionReason}</BoundChip>
      ) : (
        <BoundChip permits>No freeze window active</BoundChip>
      )}
      {/* A tripped breaker is the one state here with a next step, so it alone
          carries a link; the rest of the line is a reading. */}
      {openTrip && (
        <Link to="/settings?section=automation" className="ov-guard-link">
          Reset the breaker <span aria-hidden="true">→</span>
        </Link>
      )}
      {aside}
    </section>
  )
}

// stroke="currentColor": the chip variants recolour by setting `color`, so a
// hardcoded stroke would leave a refusing bound wearing a green tick.
function BoundChip({ permits, title, children }: { permits: boolean; title?: string; children: ReactNode }) {
  return (
    <span className={permits ? 'ov-g ov-g-ok' : 'ov-g ov-g-no'} title={title}>
      {permits ? (
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M2.4 6.4 4.9 8.9 9.6 3.2" />
        </svg>
      ) : (
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" aria-hidden="true">
          <circle cx="6" cy="6" r="4.3" />
          <path d="M3 3 9 9" />
        </svg>
      )}
      <span>{children}</span>
    </span>
  )
}

/** Rows the queue fetches (each one a dot on the Waiting tile) and rows it lists. */
const QUEUE_FETCH = 50
const QUEUE_SHOWN = 6

function Band({ name, sub, now, children }: { name: string; sub: string; now?: boolean; children: ReactNode }) {
  return (
    <section className={now ? 'ov-band ov-band-now' : 'ov-band'} aria-label={name}>
      <div className="ov-band-label">
        <h2>{name}</h2>
        <span>{sub}</span>
      </div>
      <div className="ov-band-body">{children}</div>
    </section>
  )
}

export function OverviewPage() {
  const { accessToken, identityStatus, overviewDefaultWindowDays } = useAuth()
  const canApprove = useHasCapability(CAP_REMEDIATION_APPROVE)
  const canOnboard = useHasCapability(CAP_CLUSTER_ONBOARD)
  const canAccept = useHasCapability(CAP_CLUSTER_ACCEPT)
  const canManageSettings = useHasCapability(CAP_ORG_SETTINGS_WRITE)
  const canReadSpend = useHasCapability(CAP_SPEND_READ)
  const [clusterScope, setClusterScope] = useState('all')
  const [activityDays, setActivityDays] = useState(14)
  // Seeds the toggle from the org's configured default (Settings >
  // Appearance, PROJECT.md 2026-10-14) exactly once, the first moment it's
  // known — not a useState initializer, because overviewDefaultWindowDays is
  // whatever AuthContext's hub-shipped default (14) happens to be until GET
  // /users/me actually answers, and that answer arrives asynchronously after
  // this component has already rendered. Guarded by a ref rather than
  // re-applying on every change, so a visitor who has already switched the
  // toggle (to 14, say, overriding a 30-day default) doesn't get silently
  // reset back if this effect re-ran for an unrelated reason.
  const appliedDefaultWindowRef = useRef(false)
  useEffect(() => {
    if (identityStatus !== 'ready' || appliedDefaultWindowRef.current) return
    appliedDefaultWindowRef.current = true
    setActivityDays(overviewDefaultWindowDays)
  }, [identityStatus, overviewDefaultWindowDays])
  const [capMetric, setCapMetric] = useState<CapacityMetric>('memory')
  const navigate = useNavigate()

  // Every interval here is a FALLBACK. IncidentUpdated refreshes every
  // ['incidents', …] key (the overview and queue included), ['incident-counts']
  // and ['approvals']; ClusterUpdated refreshes ['clusters', …] — see
  // realtime/refresh.ts.
  const clustersQuery = useQuery({
    queryKey: ['clusters'],
    queryFn: () => getClusters(accessToken!),
    enabled: !!accessToken,
    refetchInterval: LIVE_FALLBACK_MS,
  })
  const clusters = clustersQuery.data?.clusters ?? []
  // A saved scope naming a cluster that has since gone falls back to the fleet,
  // so no figure is ever labelled with a cluster the page is not showing.
  const effectiveScope = clusterScope === 'all' || clusters.some((c) => c.id === clusterScope) ? clusterScope : 'all'
  const scopeId = effectiveScope === 'all' ? undefined : effectiveScope

  const incidentCountsQuery = useQuery({
    queryKey: ['incident-counts', effectiveScope],
    queryFn: () => getIncidentCounts(accessToken!, scopeId),
    enabled: !!accessToken,
    refetchInterval: LIVE_FALLBACK_MS,
  })
  const overviewQuery = useQuery({
    queryKey: ['incidents', 'overview', effectiveScope, activityDays],
    queryFn: () => getIncidentOverview(accessToken!, { clusterId: scopeId, days: activityDays }),
    enabled: !!accessToken,
    refetchInterval: LIVE_FALLBACK_MS,
  })
  const queueQuery = useQuery({
    queryKey: ['incidents', 'queue', effectiveScope],
    queryFn: () => getIncidentQueue(accessToken!, { clusterId: scopeId, limit: QUEUE_FETCH }),
    enabled: !!accessToken,
    refetchInterval: LIVE_FALLBACK_MS,
  })
  const approvalsQuery = useQuery({
    queryKey: ['approvals'],
    queryFn: () => getApprovals(accessToken!),
    enabled: !!accessToken && canApprove,
    refetchInterval: LIVE_FALLBACK_MS,
  })
  const spendQuery = useQuery({
    queryKey: ['spend-today'],
    queryFn: () => getSpendToday(accessToken!),
    enabled: !!accessToken && canReadSpend,
    refetchInterval: SLOW_FALLBACK_MS,
  })
  // GET /admin/settings requires org:settings:write; a viewer can neither read
  // nor fix an unconfigured provider, so they are not shown a card about it.
  const settingsQuery = useQuery({
    queryKey: ['settings'],
    queryFn: () => getSettings(accessToken!),
    enabled: !!accessToken && canManageSettings,
    refetchInterval: STATIC_POLL_MS,
  })
  const breakerQuery = useQuery({
    queryKey: ['circuit-breaker'],
    queryFn: () => getCircuitBreaker(accessToken!),
    enabled: !!accessToken && canManageSettings,
    refetchInterval: SLOW_FALLBACK_MS,
  })
  // A window opens because the clock reached it, with no server event to
  // publish, so this one keeps a genuinely short interval.
  const windowsQuery = useQuery({
    queryKey: ['automation-windows'],
    queryFn: () => getAutomationWindows(accessToken!),
    enabled: !!accessToken && canManageSettings,
    refetchInterval: CLOCK_POLL_MS,
  })

  const scopedClusters = scopeId ? clusters.filter((c) => c.id === scopeId) : clusters
  const liveClusters = scopedClusters.filter((c) => c.state !== 'Archived')
  const fleet = useFleetData(liveClusters)
  const { byCluster: scans } = useFleetUpgradeScans()

  const counts = incidentCountsQuery.data
  const overview = overviewQuery.data

  // Onboarding is done once any cluster has reached Active, independently of
  // whether an incident has happened: a quiet fleet is the good outcome.
  const fleetOnboarded = clusters.some((c) => CLUSTER_PROGRESS_RANK[c.state] >= 4)

  const isError = clustersQuery.isError || overviewQuery.isError
  // A settled failure wins over polling: with refetchInterval set, isLoading can
  // stay true across a failing backend, and a skeleton over a dead hub reads as
  // a quiet fleet.
  const isLoading = !isError && (clustersQuery.isLoading || overviewQuery.isLoading)
  const streamDown = isLiveStreamDegraded(useLiveStatus())
  const updatedAt = Math.min(...[clustersQuery.dataUpdatedAt, overviewQuery.dataUpdatedAt].filter((v) => v > 0))

  // Ages are measured from the clock that fetched the rows, not Date.now() in
  // render, so a wait cannot grow while the data behind it sits unchanged.
  const queueNow = queueQuery.dataUpdatedAt || clustersQuery.dataUpdatedAt
  const silent = liveClusters.filter((c) => c.state === 'Disconnected')
  const approvals = approvalsQuery.data?.approvals ?? []
  const rows = queueRows(queueQuery.data?.incidents ?? [], approvals, silent, queueNow)
  // Whole-set, or unknown: the fetched queue is capped, so its length is never
  // offered as the total.
  const waitingTotal = counts ? counts.requiresAction + silent.length : null
  // The queue is fetched worst-first and capped, so its oldest row is the
  // oldest wait only when every waiting item was fetched.
  const queueComplete = waitingTotal !== null && rows.length >= waitingTotal
  const oldestWait = rows.reduce<number | null>((m, r) => (r.hours !== null && (m === null || r.hours > m) ? r.hours : m), null)
  const queueMore = waitingTotal === null ? Math.max(0, rows.length - QUEUE_SHOWN) : Math.max(0, waitingTotal - Math.min(rows.length, QUEUE_SHOWN))
  const restMediumOrLow = queueComplete && rows.slice(QUEUE_SHOWN).every((r) => r.severity === 'medium' || r.severity === 'low')

  const withFacts = liveClusters.filter(hasFacts)
  const detailList = withFacts.map((c) => fleet.details.get(c.id)).filter((d): d is NonNullable<typeof d> => !!d)
  const factsSettled = !fleet.loading && !fleet.error
  const nodes = factsSettled ? detailList.flatMap(clusterNodes) : null
  const staleNames = detailList.filter((d) => d.facts && d.state !== 'Active' && d.state !== 'Degraded').map((d) => d.displayName)
  const missingFacts = withFacts.length - detailList.filter((d) => d.facts).length
  const capacity = factsSettled ? fleetCapacity(detailList) : null
  const ladder = upgradeLadder(withFacts, fleet.details, scans)
  const liveIds = new Set(liveClusters.filter((c) => c.state === 'Active' || c.state === 'Degraded').map((c) => c.id))
  const reachable = liveClusters.filter((c) => liveIds.has(c.id))
  const runwayNow = windowsQuery.dataUpdatedAt || queueNow
  // Each fleet card's count, then how old its stored checks are: they are the
  // hub's last reads, not this page's, so the card says when that was.
  const checked = (at: string | null) => (at ? `checked ${formatRelativeTime(at)}` : null)
  const meta = (...parts: (string | null)[]) => parts.filter(Boolean).join(' · ') || null
  const { checks } = fleet
  const checksOff = fleet.checksAllowed === false
  const dueMeta = checksOff
    ? null
    : meta(comingDueSummary(reachable, checks, windowsQuery.data, runwayNow), checked(oldestRead(reachable.map((c) => checks.certificates(c.id)))))
  const ladderMeta = fleet.loading ? null : ladderSummary(ladder.rows)
  const postureMeta = checksOff ? null : meta(postureSummary(reachable, checks), checked(oldestRead(reachable.map((c) => checks.posture(c.id)))))
  const deliveryMeta = checksOff
    ? null
    : meta(deliverySummary(reachable, checks), checked(oldestRead(reachable.flatMap((c) => [checks.helm(c.id), checks.gitops(c.id)]))))
  const missingInspect = fleet.checksMissing.join(', ')
  const fleetError = fleet.error ? (
    <p className="form-error inline-error" role="alert">{queryErrorMessage(fleet.error, 'Could not load the fleet summary.')}</p>
  ) : null
  const decisions = overview?.byState.find((s) => s.state === 'AwaitingApproval')?.count

  const spend = spendTileState({ canReadSpend, isLoading: spendQuery.isLoading, spend: spendQuery.data })
  const spendLine = (
    <span className="ov-spend">
      <span className="text-muted">Spend today</span>
      <strong>{spend.value}</strong>
      {spend.percent != null && (
        <span className="ov-meter-track" role="progressbar" aria-label="Daily LLM spend ceiling used" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(spend.percent)}>
          <span className="ov-meter-fill" style={{ width: `${spend.percent}%` }} />
        </span>
      )}
      {spend.note && <span className="text-muted">{spend.note}</span>}
    </span>
  )

  return (
    <div className="page fleet-overview-page">
      <header className="page-header fleet-overview-header ov-head">
        <div>
          <h1>Overview</h1>
          {/* "Live" is a claim about the data on screen and about the event
              stream; it is made only while both hold. */}
          <p className="ov-live">
            <span
              className={isError ? 'ov-live-state ov-live-off' : streamDown ? 'ov-live-state ov-live-poll' : 'ov-live-state'}
              title={streamDown && !isError ? 'Live updates are disconnected — this page is refreshing on a timer instead, so it can be up to a minute behind' : undefined}
            >
              {!isError && !streamDown && <span aria-hidden="true">● </span>}
              {isError ? 'Not updating' : streamDown ? 'Polling' : 'Live'}
            </span>
            <span>
              {Number.isFinite(updatedAt)
                ? `${isError ? 'last updated' : 'updated'} ${formatRelativeTime(new Date(updatedAt).toISOString())}`
                : isError ? 'never loaded' : 'connecting'}
            </span>
            {clusters.length > 0 && (
              <span>
                {clusters.length} cluster{clusters.length === 1 ? '' : 's'}
                {nodes && nodes.length > 0 && ` · ${nodes.length} node${nodes.length === 1 ? '' : 's'}`}
              </span>
            )}
          </p>
        </div>
        <div className="ov-ctl" aria-label="Overview scope">
          <label className="ov-sel">
            <span className="visually-hidden">Cluster scope</span>
            <select value={effectiveScope} onChange={(e) => setClusterScope(e.target.value)}>
              <option value="all">All clusters</option>
              {clusters.map((c) => <option key={c.id} value={c.id}>{c.displayName}</option>)}
            </select>
          </label>
          <Segmented
            label="Incident activity range"
            options={[{ id: '14', label: '14 d' }, { id: '30', label: '30 d' }]}
            value={String(activityDays) as '14' | '30'}
            onChange={(v) => setActivityDays(Number(v))}
          />
        </div>
      </header>

      {isLoading && <OverviewSkeleton />}

      {isError && (
        <div className="overview-error-stack">
          {clustersQuery.isError && <p className="form-error" role="alert">{queryErrorMessage(clustersQuery.error, 'Failed to load clusters.')}</p>}
          {overviewQuery.isError && <p className="form-error" role="alert">{queryErrorMessage(overviewQuery.error, 'Failed to load the incident overview.')}</p>}
        </div>
      )}

      {/* No AI provider is a step in the top bar's setup guide (SetupGuide.tsx),
          not a card here: a permanent card above the fleet could not be put
          away, and said what the guide already says. */}

      {!isLoading && !isError && (counts?.all ?? 0) === 0 && !fleetOnboarded && (
        <OnboardingWizard clusters={clusters} canOnboard={canOnboard} canAccept={canAccept} />
      )}

      {!isLoading && !isError && overview && ((counts?.all ?? 0) > 0 || fleetOnboarded) && (
        <div className="ov-body">
          {/* Coverage first: two silent clusters contribute zero incidents, and
              that zero reads as health unless this says otherwise. */}
          <FleetCoverageBanner clusters={liveClusters} onShowNotReporting={() => navigate('/clusters?view=unreported')} />

          <div className="ov-tiles">
            <OpenIncidentsTile open={counts?.open} overview={overview} days={activityDays} />
            <WaitingTile
              requiresAction={counts?.requiresAction}
              decisions={decisions}
              rows={rows}
              oldestHours={oldestWait}
              oldestComplete={queueComplete}
            />
            <NodesTile nodes={nodes} missingFacts={missingFacts} staleNames={staleNames} />
            <CapacityTile capacity={capacity} />
          </div>

          <div className="ov-horizons">
            <Band name="Now" sub="open incidents and what waits on a person" now>
              <div className="ov-now">
                <section className="card ov-card" aria-labelledby="ov-queue-title">
                  <div className="card-head">
                    <h3 id="ov-queue-title">Waiting on a person</h3>
                    <HelpTip
                      label="Waiting on a person"
                      text="Incidents whose next move is a person's, worst first, and clusters that stopped reporting. A plan waiting for approval is measured from when the plan was made; the dashed marks are the 48 h and 5 d points at which ARGUS re-notifies about it."
                    />
                    <span className="card-head-meta">
                      {waitingTotal ?? '—'} item{waitingTotal === 1 ? '' : 's'}
                      {oldestWait !== null && ` · ${queueComplete ? 'oldest' : 'oldest shown'} ${formatWait(oldestWait)}`}
                    </span>
                  </div>
                  {queueQuery.isError ? (
                    <p className="form-error inline-error" role="alert">{queryErrorMessage(queueQuery.error, 'Could not load the queue.')}</p>
                  ) : queueQuery.isLoading ? (
                    <SkeletonLines count={5} />
                  ) : (
                    <WaitingQueue rows={rows} limit={QUEUE_SHOWN} more={queueMore} restMediumOrLow={restMediumOrLow} />
                  )}
                </section>
                <div className="ov-side">
                  <section className="card ov-card" aria-labelledby="ov-rings-title">
                    <div className="card-head">
                      <h3 id="ov-rings-title">Clusters</h3>
                      <HelpTip label="Clusters" text="Each ring is one cluster's open incidents by severity, with the total inside; a tick means none are open. Worst first. Opens the cluster." />
                      <span className="card-head-meta">open incidents by severity</span>
                    </div>
                    {liveClusters.length === 0 ? (
                      <p className="ov-card-note">No cluster in this scope.</p>
                    ) : (
                      <ClusterRings clusters={liveClusters} byCluster={overview.byCluster} />
                    )}
                    <ul className="ov-legend">
                      {(['critical', 'high', 'medium', 'low'] as const).map((s) => (
                        <li key={s} className={`sev-${s}`}><span className="ov-legend-swatch" aria-hidden="true" />{s}</li>
                      ))}
                    </ul>
                  </section>
                  <section className="card ov-card ov-card-grow" aria-labelledby="ov-activity-title">
                    <div className="card-head">
                      <h3 id="ov-activity-title">Incidents opened</h3>
                      <span className="card-head-meta">
                        {overview.daily.reduce((n, d) => n + d.opened.critical + d.opened.high + d.opened.medium + d.opened.low, 0)} in {overview.days} days
                        {counts && ` · ${counts.resolvedLast7Days} resolved in 7`}
                      </span>
                    </div>
                    <IncidentActivity daily={overview.daily} />
                  </section>
                </div>
              </div>
            </Band>

            <Band name="Next 90 days" sub="everything in the fleet with a date">
              <section className="card ov-card" aria-labelledby="ov-due-title">
                <div className="card-head">
                  <h3 id="ov-due-title">Coming due</h3>
                  <HelpTip
                    label="Coming due"
                    text="Certificate expiry dates from each reachable cluster's certificate inventory, and when each freeze or maintenance window opens, computed by the hub from the same rule the automation sweeper uses. Kubernetes end-of-support dates are not known to ARGUS, so they are not drawn."
                  />
                  {dueMeta && <span className="card-head-meta">{dueMeta}</span>}
                </div>
                {fleetError ?? (fleet.loading ? <SkeletonLines count={3} /> : (
                <ComingDue
                  clusters={reachable}
                  checks={checks}
                  checksAllowed={fleet.checksAllowed}
                  checksMissing={fleet.checksMissing}
                  windows={windowsQuery.data}
                  windowsReadable={canManageSettings}
                  windowsError={windowsQuery.isError}
                  nowMs={runwayNow}
                />
                ))}
              </section>
            </Band>

            <Band name="Standing" sub="no due date; builds up until someone pays it down">
              <div className="ov-standing">
                <section className="card ov-card" aria-labelledby="ov-ladder-title">
                  <div className="card-head">
                    <h3 id="ov-ladder-title">Upgrade ladder</h3>
                    <HelpTip label="Upgrade ladder" text="Each row is a cluster: the dot is the Kubernetes minor version it runs, and the arrow ends at the version its latest upgrade scan checked, with that scan's verdict." />
                    {ladderMeta && <span className="card-head-meta">{ladderMeta}</span>}
                  </div>
                  {fleetError ?? (fleet.loading ? <SkeletonLines count={4} /> : <UpgradeLadder columns={ladder.columns} rows={ladder.rows} />)}
                </section>
                <section className="card ov-card" aria-labelledby="ov-posture-title">
                  <div className="card-head">
                    <h3 id="ov-posture-title">Posture</h3>
                    <HelpTip label="Posture" text="Danger findings (large) and warnings per posture category, from each agent's posture checks; a darker cell has more danger findings. The last column is the share of workloads a NetworkPolicy selects." />
                    {postureMeta && <span className="card-head-meta">{postureMeta}</span>}
                  </div>
                  {fleetError ?? (fleet.loading ? (
                    <SkeletonLines count={4} />
                  ) : checksOff ? (
                    <p className="ov-card-note">Needs {missingInspect} to read each cluster's posture checks.</p>
                  ) : (
                    <PostureHeatmap clusters={reachable} checks={checks} details={fleet.details} missing={missingInspect} />
                  ))}
                </section>
                <section className="card ov-card" aria-labelledby="ov-capacity-title">
                  <div className="card-head">
                    <h3 id="ov-capacity-title">Capacity</h3>
                    <MetricSwitch value={capMetric} onChange={setCapMetric} />
                    <span className="card-head-meta" title="Hatched means the cluster has no metrics-server, so usage is not measured.">one hexagon per node · hover for figures</span>
                  </div>
                  {fleetError ?? (fleet.loading ? <SkeletonLines count={4} /> : <CapacityHoneycomb clusters={withFacts} details={fleet.details} metric={capMetric} />)}
                </section>
                <section className="card ov-card" aria-labelledby="ov-delivery-title">
                  <div className="card-head">
                    <h3 id="ov-delivery-title">Delivery &amp; agents</h3>
                    <HelpTip label="Delivery and agents" text="One square per Helm release (green) and per GitOps application (teal) the agent listed; a red square with a cross is failing or in error. Below, every agent by version against this hub, and any application that runs different versions on different clusters." />
                    {deliveryMeta && <span className="card-head-meta">{deliveryMeta}</span>}
                  </div>
                  {checksOff && <p className="ov-card-note">Needs {missingInspect} to read each cluster's Helm releases and GitOps apps.</p>}
                  {fleetError ?? (fleet.loading ? (
                    <SkeletonLines count={4} />
                  ) : (
                    <DeliveryAgents
                      clusters={liveClusters}
                      liveIds={checksOff ? new Set() : liveIds}
                      checks={checks}
                      details={fleet.details}
                      missing={missingInspect}
                    />
                  ))}
                  {!fleet.loading && !fleetError && <VersionSkew scope={effectiveScope} />}
                </section>
              </div>
              <AutomationStatusCard
                canManageSettings={canManageSettings}
                unattendedEnabled={settingsQuery.data?.autonomy.unattendedExecutionEnabled ?? false}
                autonomy={settingsQuery.data?.autonomy}
                breaker={breakerQuery.data}
                windows={windowsQuery.data}
                aside={spendLine}
              />
            </Band>
          </div>
        </div>
      )}
    </div>
  )
}
