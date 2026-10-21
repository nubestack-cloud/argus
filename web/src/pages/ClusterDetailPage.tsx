// First slice of the cluster-detail screen: the cluster's own summary +
// facts, plus its own incidents (via the same GET /api/v1/incidents this
// codebase already has, scoped with ?clusterId=). Deliberately does NOT
// duplicate ClustersPage.tsx's Accept/Decommission actions here — those
// already exist on the list view and this is meant to stay a genuine
// "detail view," not a second place to perform the same actions.
import { Fragment, type ReactNode } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { getCluster, getIncidents, ApiError } from '../api/client'
import type {
  AgentCompatibility,
  ClusterDetection,
  ClusterFacts,
  ClusterDetectors,
  ClusterRemediation,
  FindingQueueStatus,
  NamespaceRemediation,
  NodeStatus,
} from '../api/types'
import { CLUSTER_FAULT_LINE } from '../api/types'
import { useAuth } from '../auth/useAuth'
import { formatDateTime, formatRelativeTime, formatSeconds, formatSecondsRange } from '../utils/time'
import { detectionLatency } from '../utils/detection'
import { classifyDetectorStatus, type DetectorRunLevel } from '../utils/detectors'
import { SkeletonLines, SkeletonTableRows } from '../components/Skeleton'
// The incident list below is paged with the same mechanism the two worklists
// use (BUGS.md 57) — one shared hook and one shared footer, not a third copy.
import { ClusterStateBadge } from '../components/ClusterBadges'
// AgentCompatibilityBadge IS shared (unlike ClusterStateBadge, see the
// comment above it) — T16 needs the identical verdict badge here and on
// ClustersPage's fleet column/filter, and a per-page copy is exactly the
// drift ClusterBadges.tsx's own header comment describes happening once
// already with cluster-state labels.
import { AgentCompatibilityBadge } from '../components/AgentCompatibilityBadge'
import { CopyButton } from '../components/CopyButton'
import { ChipMark } from '../components/icons'
import { HelpTip } from '../components/HelpTip'
// The INCIDENT badge is shared now (components/IncidentBadges.tsx). The
// CLUSTER state badge above stays local: it is a different enum with a
// different palette, and ClustersPage is the only other screen that renders it.
import { LIVE_FALLBACK_MS } from '../realtime/refresh'
import { CAP_CLUSTER_INSPECT } from '../api/capabilities'
import { missingCapabilityMessage } from '../api/capabilityInfo'
import { useMissingCapabilities } from '../auth/useCapabilities'
import { Tabs, type TabDef } from '../components/Tabs'
import { urlEnum, useUrlState } from '../hooks/useUrlState'
import { AgentCoverageSection, ClusterOverviewSkeleton, ClusterOverviewSummary, OverviewFreshness } from '../fleet/ClusterOverviewSummary'
import { UpgradeReadinessPanel } from '../fleet/UpgradeReadinessPanel'
import { PosturePanel } from '../fleet/PosturePanel'
import { CertificatesPanel } from '../fleet/CertificatesPanel'
import { TrafficPanel } from '../fleet/TrafficPanel'
import { NetworkPolicyPanel } from '../fleet/NetworkPolicyPanel'
import { CostPanel } from '../fleet/CostPanel'
import { MetricsSourceLine } from '../fleet/MetricsSourceLine'
import { AgentUpgradeControl } from '../fleet/AgentUpgradeControl'
import { KarpenterCard } from '../fleet/KarpenterCard'
import { readInsightFacts } from '../fleet/clusterSummary'
import { ClusterTimeline } from '../fleet/ClusterTimeline'
import { HelmPanel } from '../fleet/HelmPanel'
import { GitOpsPanel } from '../fleet/GitOpsPanel'
import { NamespaceMapPanel } from '../fleet/NamespaceMapPanel'
import { TabLabel, useClusterTabBadges } from '../fleet/clusterTabBadges'
import { ClusterIncidentsTab } from '../fleet/ClusterIncidentsTab'
import type { ClusterLiveness } from '../fleet/InspectFrame'
import {
  formatCPUQuantity,
  formatMemoryQuantity,
  formatQuantityNumber,
  parseCPUCores,
  parseMemoryBytes,
  utilizationFillClass,
} from '../fleet/resourceUsage'

const CLUSTER_TABS = [
  // Grouped by question (owner-approved cluster-pages design, 2026-10-11):
  // what is wrong now, what is deployed, what would stop a change, what it
  // costs to run, and the agent itself. AD5/AD6's Map sits with the
  // incidents it explains.
  { id: 'overview', label: 'Overview', inspect: false },
  { id: 'timeline', label: 'Timeline', inspect: false },
  { id: 'incidents', label: 'Incidents', inspect: false },
  { id: 'map', label: 'Map', inspect: true },
  { id: 'gitops', label: 'GitOps', inspect: true, groupStart: true },
  { id: 'helm', label: 'Helm', inspect: true },
  { id: 'certificates', label: 'Certificates', inspect: true },
  { id: 'upgrade', label: 'Upgrade', inspect: false, groupStart: true },
  { id: 'posture', label: 'Posture', inspect: true },
  { id: 'traffic', label: 'Traffic', inspect: true, groupStart: true },
  { id: 'netpol', label: 'Network policy', inspect: true },
  { id: 'cost', label: 'Cost', inspect: true },
  { id: 'agent', label: 'Agent', inspect: false, groupStart: true },
] as const
type ClusterTab = (typeof CLUSTER_TABS)[number]['id']
const TAB_SCHEMA = { tab: urlEnum(CLUSTER_TABS.map((t) => t.id) as ClusterTab[], 'overview' as ClusterTab) }


function ResourceUsage({
  used,
  allocatable,
  parse,
  format,
}: {
  used?: string
  allocatable?: string
  parse: (quantity?: string) => number | null
  format: (quantity?: string) => string
}) {
  const usedValue = parse(used)
  const capacity = parse(allocatable)
  // `capacity > 0` guards the division and the nonsense case of a node reporting
  // zero allocatable, where every ratio would be Infinity.
  const ratio = usedValue !== null && capacity !== null && capacity > 0 ? usedValue / capacity : null

  if (ratio === null) {
    return (
      <div className="resource-usage">
        <span className="resource-usage-value">{used ? format(used) : 'Not reported'}</span>
        <small className="resource-usage-capacity">
          {allocatable ? `of ${format(allocatable)} capacity` : 'capacity not reported'}
        </small>
      </div>
    )
  }

  const percent = Math.round(ratio * 100)
  return (
    <div className="resource-usage">
      <div className="resource-usage-head">
        <span className="resource-usage-value">{format(used)}</span>
        <span className="resource-usage-percent">{percent}%</span>
      </div>
      {/* role="img" with the whole sentence as its label: a screen reader gets
          "62% of 8 cores in use", not two unlabelled divs. The percentage is on
          screen as text as well, so this is a second route to the same fact
          rather than the only one. */}
      <div
        className="resource-usage-track"
        role="img"
        aria-label={`${percent}% of ${format(allocatable)} in use`}
      >
        <div className={utilizationFillClass(ratio)} style={{ width: `${Math.min(100, percent)}%` }} />
      </div>
      <small className="resource-usage-capacity">of {format(allocatable)}</small>
    </div>
  )
}


// A detector timing as a tile figure. formatSeconds already renders an absent
// or zero timing as "Not reported" — all three arrive omitempty, so a missing
// value and a real zero are indistinguishable on the wire and only one of them
// is possible — but the tile puts that word on the second line and leaves the
// figure slot as an em dash, so an absence never reads as a measurement.
function secondsFigure(seconds: number | undefined): { value: ReactNode; note?: string } {
  if (!seconds || seconds <= 0) {
    return { value: '—', note: 'Not reported' }
  }
  return { value: formatSeconds(seconds) }
}

// ChipMark moved to components/icons.tsx (2026-08-28) so RepositoryChangePanel's
// re-verification chips share the same glyph rather than drawing a second one.

// Renders one node's readiness and — only where the target cluster reports
// it — its resource usage. cpuUsed/memoryUsed are absent (not zero) on any
// cluster with no metrics-server installed; that's shown as "—", the same
// "not available" convention this page already uses for agentVersion/
// lastHeartbeatAt, never as a fabricated 0.
// DETECTOR_CATALOG mirrors internal/agent's three shipped detectors exactly
// (detector.go's warningEventsDetectorID, pod_conditions_detector.go's
// podConditionsDetectorID, sweep_detector.go's sweepDetectorID) — PROJECT.md
// T13's explicit scope: the fixed catalogue ARGUS ships today, never an
// extensible registry, and (see DetectionCoverageCard below) never a
// speculative coverage score computed over it.
const DETECTOR_CATALOG: { key: keyof ClusterDetectors; label: string; short: string; description: string }[] = [
  {
    key: 'warningEvents',
    label: 'Warning events',
    short: 'cluster-wide',
    description: 'Every Warning-type Kubernetes Event, cluster-wide.',
  },
  {
    key: 'podConditions',
    label: 'Pod conditions',
    short: 'CrashLoop, ImagePull, OOM, Pending',
    description: 'CrashLoopBackOff, ImagePullBackOff/ErrImagePull, OOMKilled, and pods stuck Pending.',
  },
  {
    key: 'sweep',
    label: 'Sweep',
    short: 'sustained conditions',
    description:
      'Periodic checks for sustained conditions the two watch-based detectors above cannot see: replica shortfalls, wedged PVCs, failed Jobs, NotReady/pressured nodes, blocked autoscalers, and more.',
  },
]

const DETECTOR_STATUS_LABEL: Record<DetectorRunLevel, string> = {
  running: 'Running',
  degraded: 'Degraded',
  blocked: 'Permission blocked',
  error: 'Error',
  unobserved: 'Not yet observed',
}

// Colour is never the only signal here (design system rule): every badge
// pairs one of these classes with DETECTOR_STATUS_LABEL's own word, never
// left to a reader to infer from the dot alone.
//
// Degraded and Permission blocked deliberately share amber rather than
// splitting onto amber/orange. Both mean "you are not seeing everything" —
// the same thing amber already carries on a Degraded cluster badge and on
// .banner-attention — and they are not comparable in severity: a denied read
// is a standing gap until RBAC changes, a hung check is one incomplete pass.
// Spreading them across two steps of the ramp would assert an ordering
// between them that nothing computes. The word is the carrier either way,
// which is exactly why sharing a hue is allowed here.
const DETECTOR_STATUS_BADGE_CLASS: Record<DetectorRunLevel, string> = {
  running: 'badge badge-green',
  degraded: 'badge badge-amber',
  blocked: 'badge badge-amber',
  error: 'badge badge-red',
  unobserved: 'badge badge-gray',
}

function FindingQueueSummary({ queue }: { queue?: FindingQueueStatus | null }) {
  const caveat =
    'Counted since this agent process started, as of the last heartbeat — a restart resets the total to zero, so this is a per-process figure, not a lifetime one for the cluster. The agent discards the oldest pending finding once the queue is full; only its own log names the object that was dropped.'
  if (!queue || typeof queue.dropped !== 'number') {
    return (
      <div className="agent-queue">
        <div className="metric-tile-label">Finding queue</div>
        <span className="text-muted" title="An agent build older than the field, or a cluster that has not heartbeated since. Unknown, not none.">
          — not reported
        </span>
      </div>
    )
  }
  const hasDepth = typeof queue.pending === 'number' && typeof queue.capacity === 'number' && queue.capacity > 0
  const pct = hasDepth ? Math.round(((queue.pending as number) * 100) / (queue.capacity as number)) : null
  return (
    <div className="agent-queue">
      <div className="metric-tile-label">
        Finding queue <HelpTip label="Finding queue" text={caveat} />
      </div>
      {hasDepth && (
        <div className="meter-row">
          <div className="meter-head">
            <span>
              <strong className="tabular">{formatQuantityNumber(queue.pending as number, 0)}</strong> of {formatQuantityNumber(queue.capacity as number, 0)}
            </span>
          </div>
          <div className="resource-usage-track" role="img" aria-label={`Queue ${queue.pending} of ${queue.capacity}`}>
            <div className={utilizationFillClass((pct ?? 0) / 100)} style={{ width: `${Math.min(100, pct ?? 0)}%` }} />
          </div>
        </div>
      )}
      {queue.dropped > 0 ? (
        <p className="banner banner-attention">
          {formatQuantityNumber(queue.dropped, 0)} findings discarded — they never reached the hub and are not retried.
        </p>
      ) : (
        <span className="text-muted agent-queue-note">none discarded</span>
      )}
    </div>
  )
}

function TimedOutChecksNote({ checks }: { checks: string[] }) {
  return (
    <>
      <div>
        {checks.length === 1 ? '1 check did not answer' : `${checks.length} checks did not answer`}{' '}
        in the most recent pass: {checks.join(', ')}.
      </div>
      <div className="text-muted" title="The pass itself completed, so the last successful run beside this is real — that much of it is simply missing. A clean pass clears this: it describes the latest pass, not a history.">
        The rest of the pass completed.
      </div>
    </>
  )
}

// DetectionCoverageCard is PROJECT.md T13: a cluster with zero recent
// findings is ambiguous today — genuinely quiet, or a detector that has
// been failing or RBAC-denied the whole time? — and nothing else on this
// page distinguishes those two. This card answers with facts the agent and
// hub already compute: each built-in detector's own last successful run,
// its most recent error, which of its required reads RBAC currently denies,
// and which of its checks did not answer at all in the last pass.
//
// It carries three "how much of this do we actually know" facts that used to
// be served and rendered nowhere (B177, B176's residual, P19's residual):
// how old the snapshot is (FactsFreshnessNote), whether findings were
// discarded before they reached the hub (FindingQueueSummary), and whether
// the last pass was complete (TimedOutChecksNote). They sit together on
// purpose — each one is a different way the same reassuring, quiet table can
// be lying by omission, and an operator who reads the table without them
// draws a conclusion the data does not support.
//
// No coverage percentage or score is computed or rendered anywhere in this
// file, deliberately — T13's own acceptance criterion rules it out. A
// number implying ARGUS knows how much of this cluster it inspects would be
// invented: ARGUS knows what its three fixed detectors are doing, nothing
// about resource types they don't look at.
//
// Read-only, like DetectionCard/RemediationAuthorityCard above: nothing
// here can be changed from this page. In particular this is NOT a
// detector enable/disable control — that already exists on the Settings
// page (a hub-side finding filter, unrelated to whether the detector is
// actually running), and duplicating it here under a different name would
// invite exactly the two-lists-that-can-drift problem this codebase's own
// conventions warn about.
export function DetectionCoverageCard({
  detectors,
  findingQueue,
  factsUpdatedAt,
  detection,
}: {
  detectors?: ClusterDetectors
  findingQueue?: FindingQueueStatus | null
  factsUpdatedAt?: string | null
  detection?: ClusterDetection
}) {
  const sweepEvery = detection?.sweepIntervalSeconds ? formatSeconds(detection.sweepIntervalSeconds) : null
  return (
    <section className="card card-compact agent-detection" aria-label="Detection">
      <div className="card-head">
        <h3>Detection</h3>
        <HelpTip
          label="Detection"
          text={`Whether each of the agent’s three built-in detectors is actually running, from the agent’s own last report, and whether the findings it raised reached the hub. ${
            detectors
              ? 'The times are the agent’s own clock as recorded in the facts snapshot — a detector that went quiet after it still reads here exactly as it did then.'
              : ''
          }`}
        />
        <span className="card-head-meta">
          {factsUpdatedAt ? (
            <>
              from the facts snapshot <span title={formatDateTime(factsUpdatedAt)}>{formatRelativeTime(factsUpdatedAt)}</span>
            </>
          ) : (
            'facts snapshot not reported'
          )}
        </span>
      </div>
      {detectors ? (
        <div className="table-scroll">
          <table className="cluster-table">
            <thead>
              <tr>
                <th>Detector</th>
                <th className="col-shrink">Status</th>
                <th className="col-time">Last run</th>
                <th className="col-shrink">Runs</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {DETECTOR_CATALOG.map((d) => {
                const status = detectors[d.key]
                const level = classifyDetectorStatus(status)
                const timedOut = status?.timedOutChecks ?? []
                return (
                  <tr key={d.key}>
                    <td>
                      <span className="identity-block-name" title={d.description}>
                        {d.label}
                      </span>{' '}
                      <span className="text-muted agent-detector-what">{d.short}</span>
                    </td>
                    <td className="col-shrink">
                      <span className={DETECTOR_STATUS_BADGE_CLASS[level]}>{DETECTOR_STATUS_LABEL[level]}</span>
                    </td>
                    <td className="col-time" title={status?.lastSuccessAt ? formatDateTime(status.lastSuccessAt) : undefined}>
                      {status?.lastSuccessAt ? formatRelativeTime(status.lastSuccessAt) : 'Never'}
                    </td>
                    <td className="col-shrink text-muted">{d.key === 'sweep' ? (sweepEvery ? `every ${sweepEvery}` : '—') : 'on watch'}</td>
                    <td>
                      {level === 'blocked' && status?.deniedReads && (
                        <>
                          RBAC denies:{' '}
                          {status.deniedReads.map((r, i) => (
                            <span key={r}>
                              {i > 0 ? ', ' : ''}
                              <code>{r}</code>
                            </span>
                          ))}
                        </>
                      )}
                      {level === 'error' && status?.error && (
                        <span title={status.errorAt ? formatDateTime(status.errorAt) : undefined}>{status.error}</span>
                      )}
                      {level === 'running' && '—'}
                      {level === 'unobserved' && 'No run reported yet.'}
                      {timedOut.length > 0 && <TimedOutChecksNote checks={timedOut} />}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="text-muted">
          — Per-detector run health not reported: this agent predates the field, so a quiet cluster here could mean healthy, disconnected or a
          failing detector.
        </p>
      )}
      <div className="agent-timing">
        <DetectionCard detection={detection} />
        <FindingQueueSummary queue={findingQueue} />
      </div>
    </section>
  )
}

export function DetectionCard({ detection }: { detection?: ClusterDetection }) {
  if (!detection || (!detection.sweepIntervalSeconds && !detection.sustainedThresholdSeconds && !detection.resendCooldownSeconds)) {
    return (
      <div className="agent-stat">
        <div className="metric-tile-label">Detection timing</div>
        <span
          className="text-muted"
          title="This agent predates the field. Read them from its ARGUS_SWEEP_INTERVAL_SECONDS, ARGUS_SWEEP_SUSTAINED_THRESHOLD_SECONDS and ARGUS_FINDING_RESEND_COOLDOWN_SECONDS environment variables."
        >
          — not reported
        </span>
      </div>
    )
  }
  const latency = detectionLatency(detection)
  const stat = (label: string, title: string, value: ReactNode) => (
    <div className="agent-stat" title={title}>
      <div className="metric-tile-label">{label}</div>
      <strong>{value}</strong>
    </div>
  )
  return (
    <>
      {stat('Sustained for', 'How long a condition must persist before it is reported, so transients aren’t raised as failures', secondsFigure(detection.sustainedThresholdSeconds).value)}
      {stat('Resend cooldown', 'How long before the same finding is reported again. The validation grace period is three times this, or 15 minutes, whichever is longer.', secondsFigure(detection.resendCooldownSeconds).value)}
      {latency &&
        stat(
          'Detection latency',
          'A fault is first observed at most one sweep after it starts, then reported at the first sweep past the threshold. Set per agent, not from here; faults the cluster timestamps itself are reported at the next sweep instead, so they are faster.',
          formatSecondsRange(latency.floorSeconds, latency.ceilingSeconds),
        )}
    </>
  )
}

const REMEDIATION_GRANTS: { label: string; enables: string; read: (r: ClusterRemediation) => boolean }[] = [
  { label: 'Scale / restart a Deployment', enables: 'patch on apps/deployments', read: r => r.canPatchDeployments },
  { label: 'Scale / restart a StatefulSet', enables: 'patch on apps/statefulsets', read: r => r.canPatchStatefulSets },
  { label: 'Restart a Pod', enables: 'delete on pods', read: r => r.canDeletePods },
]

// One capability, stated whether or not it is held. Both variants are the same
// `.verification-chip` at the same size and weight — the neutral one differs by
// two colours and nothing else, which is the whole point of that primitive:
// what this agent may NOT do sits in the same row as what it may, rather than
// being left for a reader to infer from an absence (PRODUCT_DIRECTION.md
// §"The refusals are the product"; the incident screen's verification row is
// the same idiom).
//
// The state word is its own element rather than only a colour and a glyph:
// nothing in the D7 vocabulary carries meaning by colour alone, and this row is
// read by an approver deciding whether an approval can be carried out at all.
function CapabilityChip({
  label,
  detail,
  granted,
}: {
  label: string
  detail: string
  granted: boolean
}) {
  return (
    <span
      className={granted ? 'verification-chip' : 'verification-chip verification-chip-neutral'}
      title={detail}
    >
      <ChipMark mark={granted ? 'granted' : 'denied'} />
      <span>{label}</span>
      <span aria-hidden="true">·</span>
      <span>{granted ? 'Granted' : 'Not granted'}</span>
    </span>
  )
}

// MetricsSourceCard says whether this agent can query a Prometheus-compatible
// endpoint, and when none is configured, which Service it found and the chart
// values that connect it (PROJECT.md PG13). Never applied by ARGUS: the RBAC
// grant names one Service, chosen by a person.
function MetricsSourceCard({ metrics }: { metrics?: ClusterFacts['metrics'] }) {
  if (!metrics) {
    return <p className="empty-state">This agent hasn't reported its metrics source — it predates the check.</p>
  }
  return (
    <div className="card detail-summary-card">
      <p className="eyebrow">Metrics source</p>
      {metrics.checked && metrics.allowed ? (
        <div className="verification-chip-row">
          <CapabilityChip
            label={metrics.external ? 'Query an external endpoint' : 'Query metrics'}
            detail={metrics.external ? 'The agent reached the configured external Prometheus-compatible endpoint.' : 'The API server lets this agent read the configured Service through its proxy.'}
            granted
          />
          {metrics.external && !metrics.scopedByLabel && (
            <span
              className="badge badge-amber"
              title={
                metrics.labelIgnored
                  ? "An extraLabel is set, but this endpoint returned series outside it, so it ignores the label: a shared endpoint returns every cluster's series to this cluster's queries."
                  : "No extraLabel is set, so a shared endpoint returns every cluster's series to this cluster's queries."
              }
            >
              {metrics.labelIgnored ? 'Label not enforced' : 'Not scoped to this cluster'}
            </span>
          )}
        </div>
      ) : (
        <MetricsSourceLine
          what="Metrics"
          notConfigured={!metrics.checked && !metrics.error}
          reason={metrics.error || 'A Service is configured, but the API server does not let this agent reach it through the proxy.'}
          detected={metrics.suggested}
        />
      )}
    </div>
  )
}

// RemediationAuthorityCard shows what this cluster's API server says the agent
// may change (BACKLOG B4).
//
// Three distinct states, and collapsing any two of them would mislead:
//
//   not reported  -> an agent too old to be asked. Unknown.
//   checked=false -> asked, but the answer never came. Also unknown, and NOT a
//                    denial: telling an approver "remediation unavailable" when
//                    nobody could ask is the failure this field exists to avoid.
//   checked=true  -> a real per-action answer.
//
// Read-only, like the detection card, and for the same reason: the hub cannot
// grant an agent RBAC. Enabling remediation is remediate.enabled at install time.
// What the hub can do — and what was missing — is tell an operator the truth about
// which clusters can carry out an approval before one is given.
export function RemediationAuthorityCard({ remediation }: { remediation?: ClusterRemediation }) {
  if (!remediation) {
    return (
      <p className="empty-state">
        This agent hasn't reported its remediation authority — it predates the check. Upgrade the
        agent, or read it from the cluster with{' '}
        <code>kubectl auth can-i patch deployments --as=system:serviceaccount:argus-system:argus-remediate</code>.
      </p>
    )
  }
  if (!remediation.checked) {
    return (
      <div className="card detail-summary-card">
        <p className="eyebrow">What this agent may change</p>
        {/* The unanswered case gets a chip of its own rather than prose alone:
            "nobody could ask" is a state, and stating it in the same row shape
            the real answers use is what keeps it from reading as a denial.
            `.verification-chip-row` (BACKLOG D7h): this used to reuse
            `.detail-header-meta`, this page's own generic wrapped-inline-row
            class, because no chip-row primitive existed yet — see the comment
            this replaced, on the granted-chips row below, which named that
            gap directly. */}
        <div className="verification-chip-row">
          <span className="verification-chip verification-chip-neutral">
            <ChipMark mark="unanswered" />
            <span>Not answered by the cluster</span>
          </span>
        </div>
        <p className="field-hint">
          <strong>Unknown.</strong> The agent could not ask the API server what it is allowed to
          change, so this is not a report that remediation is unavailable — only that the question
          went unanswered. Approvals for this cluster may still succeed or may fail at execution.
          {remediation.error ? <> Reason: <code>{remediation.error}</code></> : null}
        </p>
      </div>
    )
  }
  const anyGranted = REMEDIATION_GRANTS.some(g => g.read(remediation))
  // B170: the chart's own recommended, least-privilege install
  // (remediate.namespaces rather than remediate.allNamespaces) grants write
  // access scoped to a Role in each selected namespace, which correctly
  // answers false to the CLUSTER-scoped question above — so anyGranted alone
  // used to tell an approver "this cluster cannot remediate" on exactly the
  // recommended shape, while a plan targeting the namespace it WAS granted
  // would go on to execute. namespaces (per-namespace, independently
  // checked) is where that scoped grant actually surfaces.
  const namespaces = remediation.namespaces ?? []
  const grantedNamespaces = namespaces.filter(
    ns => ns.canPatchDeployments || ns.canPatchStatefulSets || ns.canDeletePods,
  )
  const anyNamespaceGranted = grantedNamespaces.length > 0
  return (
    <section className="card card-compact" aria-label="Remediation authority">
      <div className="card-head">
        <h3>Remediation authority</h3>
        <HelpTip
          label="Remediation authority"
          text="What this cluster’s API server says the agent may change — asked live, not read from the chart value that was meant to grant it, so it stays true if the two have drifted. Remediation is granted by the argus-agent chart’s remediate.enabled/remediate.namespaces values at install or upgrade time; the hub cannot grant it."
        />
      </div>
      {/* BACKLOG D7h. `.verification-chip-row` was built and unused anywhere
          in the app; this row of chips reused `.detail-header-meta` instead
          purely because nothing better existed at the time (see the comment
          this replaced). Now it does. */}
      <div className="verification-chip-row">
        {REMEDIATION_GRANTS.map(g => (
          <CapabilityChip
            key={g.label}
            label={g.label}
            detail={`Requires ${g.enables}, cluster-wide`}
            granted={g.read(remediation)}
          />
        ))}
      </div>
      <p className="field-hint">
        {anyGranted
          ? 'Cluster-wide, answered by the API server itself.'
          : anyNamespaceGranted
            ? `No cluster-wide write access; granted in ${grantedNamespaces.length} of ${namespaces.length} namespace${namespaces.length === 1 ? '' : 's'} checked, below.`
            : remediation.reporter === 'remediate'
              ? 'Plans can be approved here but will fail at execution.'
              : 'No remediation agent is connected. Plans can be approved here but will fail at execution.'}
      </p>
      <NamespaceRemediationTable namespaces={namespaces} truncated={remediation.namespacesTruncated ?? false} />
    </section>
  )
}

// NamespaceRemediationTable is RemediationAuthorityCard's per-namespace
// supplement (B170). Rendered only when the agent actually reported a
// breakdown — an absent/empty `namespaces` is "no breakdown available" per
// ClusterRemediation's own contract, not "checked every namespace and found
// nothing," so there is nothing honest to draw here in that case.
//
// Reuses `.table-scroll`/`.cluster-table` (the same primitive NodesList below
// uses) rather than a second chip row per namespace: three chips' full label
// text repeated once per namespace would not scan, where a namespace column
// beside three compact Granted/Not-granted cells does — the same
// column-per-check shape NodesList already uses for Ready/CPU/Memory.
function NamespaceRemediationTable({
  namespaces,
  truncated,
}: {
  namespaces: NamespaceRemediation[]
  truncated: boolean
}) {
  if (namespaces.length === 0) {
    return null
  }
  return (
    <>
      <p className="field-hint">
        <strong>Namespace-scoped grants ({namespaces.length}{truncated ? '+' : ''} checked):</strong>{' '}
        {truncated
          ? `showing the first ${namespaces.length} namespaces this agent found a remediation Role in, alphabetically — more may exist and were not checked this pass.`
          : 'every namespace this agent found a remediation Role in.'}
      </p>
      <div className="table-scroll">
        <table className="cluster-table">
          <thead>
            <tr>
              <th>Namespace</th>
              <th>Scale / restart Deployment</th>
              <th>Scale / restart StatefulSet</th>
              <th>Restart Pod</th>
            </tr>
          </thead>
          <tbody>
            {namespaces.map(ns => (
              <tr key={ns.namespace}>
                <td>
                  <code>{ns.namespace}</code>
                </td>
                <td>
                  <NamespaceGrantBadge granted={ns.canPatchDeployments} />
                </td>
                <td>
                  <NamespaceGrantBadge granted={ns.canPatchStatefulSets} />
                </td>
                <td>
                  <NamespaceGrantBadge granted={ns.canDeletePods} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}

// Same green/neutral-gray language CapabilityChip already uses for this exact
// fact (never red — "not granted" here is not a severity/error, it's the same
// neutral "not asserted" state `.verification-chip-neutral` draws elsewhere),
// and the same "Granted"/"Not granted" words, so a reader comparing the
// cluster-wide chip row above against this table sees one claim stated twice
// the same way, not two different-sounding claims about the same fact.
function NamespaceGrantBadge({ granted }: { granted: boolean }) {
  return <span className={granted ? 'badge badge-green' : 'badge badge-gray'}>{granted ? 'Granted' : 'Not granted'}</span>
}

// AgentCompatibilityCard is T16's full argument behind the badge the fact
// strip above already shows next to the agent version: WHY that verdict
// (compatibility.reason, in the hub's own words), WHAT is missing because of
// it (named capabilities this build cannot report — never a guess, only the
// entries internal/agentversion.Policy actually lists), and HOW to fix it
// (a copyable command, never a claim that ARGUS ran or will run it — see
// UpgradeCommand's own doc comment in internal/agentversion/policy.go for
// why it is a placeholder-filled generic form for every cluster today: the
// hub has no recorded Helm release name or namespace for any of them).
//
// Nothing here is computed — every value is read straight off
// cluster.compatibility, which came from ONE server-side evaluation
// (internal/agentversion.Policy.Evaluate, called once in
// internal/api/clusters.go's scanClusterSummary) shared with ClustersPage's
// fleet-wide column. A second comparison here would be exactly the drifting
// second policy T16 exists to prevent, so there isn't one.
export function AgentCompatibilityCard({ compatibility, children }: { compatibility: AgentCompatibility; children?: ReactNode }) {
  return (
    <section className="card card-compact" aria-label="Agent compatibility">
      <div className="card-head">
        <h3>Compatibility</h3>
      </div>
      <div className="verification-chip-row" title={compatibility.reason}>
        <AgentCompatibilityBadge compatibility={compatibility} />
        <span className="fleet-mono">{compatibility.agentVersion ?? '—'}</span>
        <span className="text-muted">
          hub supports ≥ {compatibility.minSupportedVersion}, recommends {compatibility.recommendedVersion}
        </span>
      </div>

      {/* Only ever non-empty for upgrade_recommended/upgrade_required — an
          unknown version gets no claimed gap (Compatibility's own doc
          comment) — and only ever the real, wire-verified entries
          Policy.Features lists, never an invented capability matrix. */}
      {compatibility.missingFeatures && compatibility.missingFeatures.length > 0 && (
        <>
          <p className="field-hint">
            <strong>Not available on this build, because of its version:</strong>
          </p>
          <dl className="fact-list">
            {compatibility.missingFeatures.map((feature) => (
              <Fragment key={feature.name}>
                <dt>{feature.name}</dt>
                <dd>
                  {feature.description} {feature.wireContract}
                </dd>
              </Fragment>
            ))}
          </dl>
        </>
      )}

      {/* Also only present for upgrade_recommended/upgrade_required — see
          Evaluate's own comment for why an unknown version gets no upgrade
          guidance: guidance implies a confident "upgrade from X," and X is
          exactly what's missing. */}
      {compatibility.upgrade && (
        <>
          <p className="field-hint">
            {compatibility.upgrade.note ??
              'A copyable command to upgrade this cluster’s agent — ARGUS prints it here; running it against the cluster is on you.'}
          </p>
          <pre className="code-block">{compatibility.upgrade.command}</pre>
          <CopyButton text={compatibility.upgrade.command} label="Copy" />
        </>
      )}
      {children}
    </section>
  )
}

function NodesList({ nodes }: { nodes: NodeStatus[] }) {
  if (nodes.length === 0) {
    return <p className="empty-state">No node inventory reported yet.</p>
  }
  // The cluster-wide roll-up of these rows is the Overview's Resource use
  // card, directly above (ClusterOverviewSummary.tsx), beside the requested
  // figures it is read against; this table answers "which node".
  return (
    <>
      <div className="table-scroll">
      <table className="cluster-table">
        <thead>
          {/* `col-shrink` on Status: it holds one badge, and without it the
              four columns split the (now uncapped) table width evenly and a
              5-character "Ready" got the same 400px as a utilization bar. The
              node name and the two usage columns are the ones that grow
              usefully. */}
          <tr>
            <th>Node</th>
            <th className="col-shrink">Status</th>
            <th>CPU usage</th>
            <th>Memory usage</th>
          </tr>
        </thead>
        <tbody>
          {nodes.map((node) => (
            <tr key={node.name}>
              <td>{node.name}</td>
              <td className="col-shrink">
                <span className={node.ready ? 'badge badge-green' : 'badge badge-red'}>
                  {node.ready ? 'Ready' : 'Not ready'}
                </span>
              </td>
              <td
                className="resource-usage-cell"
                title={`Raw CPU: ${node.cpuUsed ?? 'not reported'} used / ${node.cpuAllocatable ?? 'unknown'} allocatable`}
              >
                <ResourceUsage
                  used={node.cpuUsed}
                  allocatable={node.cpuAllocatable}
                  parse={parseCPUCores}
                  format={formatCPUQuantity}
                />
              </td>
              <td
                className="resource-usage-cell"
                title={`Raw memory: ${node.memoryUsed ?? 'not reported'} used / ${node.memoryAllocatable ?? 'unknown'} allocatable`}
              >
                <ResourceUsage
                  used={node.memoryUsed}
                  allocatable={node.memoryAllocatable}
                  parse={parseMemoryBytes}
                  format={formatMemoryQuantity}
                />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      </div>
    </>
  )
}

export function ClusterDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { accessToken } = useAuth()

  const {
    data: cluster,
    isLoading: clusterLoading,
    isError: clusterIsError,
    error: clusterError,
  } = useQuery({
    queryKey: ['clusters', id],
    queryFn: () => getCluster(id!, accessToken!),
    enabled: !!accessToken && !!id,
    // ClusterUpdated invalidates the ['clusters'] prefix, this key included
    // (realtime/refresh.ts); the interval is the fallback under it.
    refetchInterval: LIVE_FALLBACK_MS,
  })

  const {
    data: incidentsData,
    isLoading: incidentsLoading,
    isError: incidentsIsError,
    error: incidentsError,
  } = useQuery({
    queryKey: ['incidents', { clusterId: id }],
    queryFn: () => getIncidents(accessToken!, id!, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, 'lookalike'),
    enabled: !!accessToken && !!id,
    // Same reason as IncidentsPage — occurrence counts/states change
    // server-side without any action from whoever's looking at this screen,
    // which is exactly what IncidentUpdated announces.
    refetchInterval: LIVE_FALLBACK_MS,
  })

  const [{ tab }, setTabState] = useUrlState(TAB_SCHEMA)
  const inspect = useMissingCapabilities([CAP_CLUSTER_INSPECT])
  const inspectDenied = inspect.resolved && inspect.missing.length > 0 ? missingCapabilityMessage(inspect.missing) : undefined
  const tabBadges = useClusterTabBadges({
    clusterId: id,
    incidents: incidentsData?.incidents ?? [],
    metrics: cluster?.facts?.metrics,
    kubecost: cluster?.facts?.agent?.kubecost,
    inspectAllowed: inspect.resolved && inspect.missing.length === 0,
  })
  const clusterTabs: TabDef[] = CLUSTER_TABS.map((t) => ({
    id: t.id,
    label: <TabLabel label={t.label} badge={tabBadges[t.id]} />,
    disabledReason: t.inspect ? inspectDenied : undefined,
    groupStart: 'groupStart' in t ? t.groupStart : undefined,
  }))
  // CI-U10: everything the agent reported reads as stale while the cluster is
  // not Active, naming why and when it was last heard from.
  const liveness: ClusterLiveness = cluster
    ? {
        stale: cluster.state !== 'Active',
        staleReason:
          cluster.state !== 'Active'
            ? `${CLUSTER_FAULT_LINE[cluster.state] ?? cluster.state}; last heartbeat ${formatRelativeTime(cluster.lastHeartbeatAt)}`
            : undefined,
      }
    : { stale: false }

  const incidents = incidentsData?.incidents ?? []

  return (
    <div className="page detail-page cluster-detail-page">
      <header className="page-header">
        <div>
          <h1>{cluster?.displayName ?? 'Cluster'}</h1>
          {cluster && (
            // One line of identity and liveness instead of a meta line plus a
            // five-tile strip (owner-approved cluster-pages design,
            // 2026-10-11): the same five facts — state, agent version with its
            // compatibility verdict, heartbeat, facts age, Kubernetes version —
            // plus reachability and enrolment, at a fraction of the height,
            // so every tab starts higher. Heartbeat and facts age stay a pair:
            // a fresh heartbeat beside an old facts snapshot is a connected
            // agent whose inventory stopped being re-sent (B177).
            <div className="cluster-header-line">
              <ClusterStateBadge state={cluster.state} />
              {CLUSTER_FAULT_LINE[cluster.state] && <span className="cluster-header-fault">{CLUSTER_FAULT_LINE[cluster.state]}</span>}
              <ul className="cluster-header-facts" aria-label="Cluster facts">
                <li>
                  <span className="cluster-header-dot" data-live={cluster.state === 'Active'} aria-hidden="true" />
                  heartbeat{' '}
                  <strong title={cluster.lastHeartbeatAt ? formatDateTime(cluster.lastHeartbeatAt) : undefined}>
                    {cluster.lastHeartbeatAt ? formatRelativeTime(cluster.lastHeartbeatAt) : 'never'}
                  </strong>
                  {' · '}facts{' '}
                  <strong
                    title={
                      cluster.factsUpdatedAt
                        ? `${formatDateTime(cluster.factsUpdatedAt)} — when the hub last received this cluster's facts, on the hub's own clock. The agent re-sends its inventory every two minutes; everything on these tabs is that snapshot.`
                        : undefined
                    }
                  >
                    {cluster.factsUpdatedAt ? formatRelativeTime(cluster.factsUpdatedAt) : 'not reported'}
                  </strong>
                </li>
                <li>
                  Kubernetes <strong className="cluster-header-mono">{cluster.facts?.kubernetesVersion ?? 'not reported'}</strong>
                </li>
                <li>
                  agent <strong className="cluster-header-mono">{cluster.agentVersion ?? 'not reported'}</strong>{' '}
                  <AgentCompatibilityBadge compatibility={cluster.compatibility} />
                </li>
                <li>
                  <span title={formatDateTime(cluster.createdAt)}>enrolled {formatRelativeTime(cluster.createdAt)}</span>
                  {' · '}
                  {cluster.facts ? (cluster.facts.reachable ? 'API reachable' : 'API unreachable') : 'reachability unknown'}
                </li>
              </ul>
            </div>
          )}
        </div>
      </header>

      {/* BACKLOG D7g. This skeleton used to omit three whole sections the
          loaded page below inserts between the tiles and the node table —
          Incidents, Detection timing, Remediation authority — so the page
          grew from 2 sections to 5 the moment data arrived. Same order as
          the loaded state (D7i's reorder: the cluster's own incidents move
          up to sit right after its facts, ahead of its detector
          configuration and RBAC authority, matching mode B's "what is
          broken, then why, then nodes" — full ordering discussion below). */}
      {/* The skeleton is the Overview tab's shape — the default tab, and the
          one a cold load lands on: the header facts line, the tab row, the ring
          row with Resource use, the count strip, the four preview cards and
          the node table. A skeleton that stood in for sections the tab no
          longer shows would reflow the page one paint later. */}
      {clusterLoading && (
        <div aria-hidden="true">
          <div className="cluster-header-line">
            <SkeletonLines count={1} widths={['32rem']} />
          </div>
          <div className="tabs-bar">
            <SkeletonLines count={1} widths={['24rem']} />
          </div>
          <ClusterOverviewSkeleton />
          <section className="card card-compact nodes-card">
          <div className="card-head">
            <h3>Nodes</h3>
          </div>
          <div className="table-scroll">
            <table className="cluster-table" aria-busy="true">
              <thead>
                <tr>
                  <th>Node</th>
                  <th className="col-shrink">Status</th>
                  <th>CPU usage</th>
                  <th>Memory usage</th>
                </tr>
              </thead>
              <tbody>
                <SkeletonTableRows columns={4} />
              </tbody>
            </table>
          </div>
          </section>
        </div>
      )}

      {clusterIsError && (
        <p className="form-error" role="alert">
          {clusterError instanceof ApiError
            ? clusterError.detail
              ? `${clusterError.message} — ${clusterError.detail}`
              : clusterError.message
            : 'Failed to load cluster.'}
        </p>
      )}

      {cluster && (
        <>
          {/* docs/CLUSTER_INSIGHT_SPECS.md CI-S11/S5/S4/S16/S13/S14. The strip
              above is the cluster's identity and applies to every tab; each
              tab below is one question about it, and the active one is in
              the URL (?tab=) so a link reproduces the view. Overview keeps
              everything this page already showed, under the agent's own
              health summary. The four live-read tabs need cluster:inspect —
              disabled with the capability named when it is missing, never
              hidden. */}
          <Tabs
            tabs={clusterTabs}
            active={tab}
            onChange={(next) => setTabState({ tab: next as ClusterTab }, { push: true })}
            label="Cluster views"
            aside={tab === 'overview' ? <OverviewFreshness facts={cluster.facts} factsUpdatedAt={cluster.factsUpdatedAt} liveness={liveness} /> : undefined}
          >
          {tab === 'overview' && (
          <>
          <ClusterOverviewSummary
            clusterId={id!}
            facts={cluster.facts}
            factsUpdatedAt={cluster.factsUpdatedAt}
            liveness={liveness}
            nodes={cluster.facts ? cluster.facts.nodes : null}
            incidents={{
              items: incidents,
              openCount: incidentsData?.counts?.open,
              loading: incidentsLoading,
              error: incidentsIsError ? incidentsError : null,
              truncated: !!incidentsData?.nextCursor,
              onShowAll: () => setTabState({ tab: 'incidents' }, { push: true }),
            }}
          />
          {/* PROJECT.md PG7: only on a cluster whose agent has Karpenter's
              NodePools synced, so no other cluster pays for the read. */}
          {(readInsightFacts(cluster.facts).objectCache?.kinds ?? []).some((k) => k.group === 'karpenter.sh' && k.kind === 'NodePool' && k.state === 'synced') && (
            <KarpenterCard clusterId={id!} />
          )}

          {/* NODES FIRST — above the incident list, and above the two
              configuration sections it used to sit below.

              Below the config sections was plainly wrong: detector intervals
              and RBAC authority are how the agent is SET UP, and this is the
              cluster's live state — how much of it is left, and which node is
              running out. Mode B orders a detail page by what is broken, then
              why; a sweep interval is never the answer to "why is this cluster
              in trouble", and node capacity often is.

              Above the incidents, on the owner's call, and it reads better than
              the reverse: capacity is the cheapest available explanation for a
              list of OOMKilled and Pending incidents, so having it in view
              first means the reader arrives at that list already knowing
              whether the cluster is short of room. */}
          {/* In a card like every other block on this tab (owner, 2026-10-12). */}
          <section className="card card-compact nodes-card" aria-label="Node list">
            <div className="card-head">
              <h3>Nodes</h3>
              {cluster.facts && cluster.facts.nodes.length > 0 && (
                <span className="card-head-meta">
                  {cluster.facts.nodes.length} ·{' '}
                  {cluster.facts.nodes.every((n) => n.ready)
                    ? 'all Ready'
                    : `${cluster.facts.nodes.filter((n) => !n.ready).length} not ready`}
                </span>
              )}
            </div>
            {cluster.facts ? (
              <NodesList nodes={cluster.facts.nodes} />
            ) : (
              <p className="empty-state">
                No inventory reported yet — the agent hasn't completed its first sync.
              </p>
            )}
          </section>
          </>
          )}
          {tab === 'incidents' && (
            <ClusterIncidentsTab
              clusterId={id!}
              incidents={incidents}
              loading={incidentsLoading}
              truncated={!!incidentsData?.nextCursor}
              groupCounts={incidentsData?.lookalikeGroups}
              error={
                incidentsIsError
                  ? incidentsError instanceof ApiError
                    ? incidentsError.detail
                      ? `${incidentsError.message} — ${incidentsError.detail}`
                      : incidentsError.message
                    : 'Failed to load incidents for this cluster.'
                  : null
              }
            />
          )}
          {/* The Agent tab: how the agent is set up and what it can see —
              facts about ARGUS's own reach, not about what is broken, so they
              sit apart from the cluster's health (owner review 2026-10-10,
              PROJECT.md UX6). */}
          {tab === 'agent' && (
          <div className="agent-tab">
            <AgentCoverageSection facts={cluster.facts} liveness={liveness} />
            {/* T13: whether each detector actually runs comes before its
                timing — a configured interval means nothing if the detector
                behind it never started. */}
            <DetectionCoverageCard
              detectors={cluster.facts?.detectors}
              findingQueue={cluster.findingQueue}
              factsUpdatedAt={cluster.factsUpdatedAt}
              detection={cluster.facts?.detection}
            />
            <div className="agent-grid">
              <RemediationAuthorityCard remediation={cluster.facts?.remediation} />
              <MetricsSourceCard metrics={cluster.facts?.metrics} />
              <AgentCompatibilityCard compatibility={cluster.compatibility}>
                <AgentUpgradeControl clusterId={id!} agent={cluster.facts?.agent} hubAgentImage={cluster.hubAgentImage} />
              </AgentCompatibilityCard>
            </div>
          </div>
          )}
          {tab === 'upgrade' && <UpgradeReadinessPanel clusterId={id!} kubernetesVersion={cluster.facts?.kubernetesVersion} />}
          {tab === 'posture' && <PosturePanel clusterId={id!} liveness={liveness} />}
          {tab === 'certificates' && <CertificatesPanel clusterId={id!} liveness={liveness} />}
          {tab === 'traffic' && <TrafficPanel clusterId={id!} liveness={liveness} />}
          {tab === 'netpol' && <NetworkPolicyPanel clusterId={id!} liveness={liveness} />}
          {tab === 'cost' && <CostPanel clusterId={id!} liveness={liveness} />}
          {tab === 'timeline' && <ClusterTimeline clusterId={id!} />}
          {tab === 'map' && <NamespaceMapPanel clusterId={id!} clusterName={cluster.displayName} incidents={incidents} liveness={liveness} />}
          {tab === 'gitops' && <GitOpsPanel clusterId={id!} liveness={liveness} />}
          {tab === 'helm' && <HelmPanel clusterId={id!} liveness={liveness} incidents={incidents} />}
          </Tabs>
        </>
      )}
    </div>
  )
}
