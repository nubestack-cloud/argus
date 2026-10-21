import { useQuery } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { getResourceChanges } from '../api/client'
import type { Incident } from '../api/types'
import { useAuth } from '../auth/useAuth'
import { HelpTip } from '../components/HelpTip'
import { Quantity } from '../components/Quantity'
import { SkeletonLines } from '../components/Skeleton'
import { VerdictBadge, toVerdict } from '../components/VerdictBadge'
import { SplitBar } from '../components/SplitBar'
import { missingCapabilityMessage } from '../api/capabilityInfo'
import { errorText } from '../insight/useInspect'
import { incidentIdentity, SEVERITY_LABEL, STATE_LABEL } from '../utils/incidents'
import { formatDateTime, formatRelativeTime } from '../utils/time'
import { LIVE_FALLBACK_MS } from '../realtime/refresh'
import { gitopsControllerLabel, kindLabel, type ClusterSummary } from './clusterSummary'
import {
  certificatesExpiring,
  changeActivity,
  incidentsOpenedIn,
  openIncidentOn,
  opsText,
  postureDangerCount,
  recentlyClosed,
  SEV_CLASS,
  openAttentionGroups,
  windowGaps,
} from './clusterOverviewModel'
import type { CertificatesResult } from './certificatesModel'
import type { PostureResult } from './postureModel'
import { HELM_ARGS, helmChecks, type HelmReleaseList } from './helmModel'
import { useFleetUpgradeScans } from './fleetUpgrade'
import { useInspect } from './useInspect'

// The cluster Overview's preview cards (owner reviews 2026-10-10/11,
// PROJECT.md UX1): each one is a small answer that opens the tab holding the
// full view. They read data the page already has, or the same cached query
// the full tab makes, so opening the tab after the preview costs nothing
// extra.
//
// They are ARGUS's answers, not a generic "unhealthy list" and "recent
// activity": Needs attention says where each incident is in ARGUS's own loop
// (investigating, awaiting approval, …) beside its severity, and Changes puts
// the hour's change activity and the incidents that opened in it on one axis,
// then names which changed object already has an open incident — the
// "what changed right before it broke" question, asked from the summary.

const ROWS = 6
/** At most this many closed rows: enough to fill a quiet card, not so many
 *  that it outgrows the Changes card beside it. */
const CLOSED_ROWS = 3

function AttentionRow({ incident: i, closed }: { incident: Incident; closed?: boolean }) {
  const id = incidentIdentity(i)
  return (
    <li className={`attention-row ${SEV_CLASS[i.severity] ?? 'sev-neutral'}`} data-closed={closed || undefined}>
      <div className="attention-identity">
        <Link className="attention-name" to={`/incidents/${i.id}`}>
          {id.name}
        </Link>
        <span className="attention-meta">
          {/* identity.kind is "Kind · namespace" for whichever object the
              name is (the owning workload when the agent resolved one). */}
          {id.kind && <span className="identity-block-kind">{id.kind}</span>}
          {id.kind && id.fault ? ' — ' : ''}
          {id.fault}
        </span>
      </div>
      <div className="attention-status">
        <span className="attention-severity">
          <span className="severity-chip" aria-hidden="true" />
          {SEVERITY_LABEL[i.severity] ?? i.severity}
        </span>
        <span>
          <span className="attention-state">{STATE_LABEL[i.state] ?? i.state}</span> ·{' '}
          {closed && i.resolvedAt ? (
            <span title={`Closed ${formatDateTime(i.resolvedAt)}`}>{formatRelativeTime(i.resolvedAt)}</span>
          ) : (
            <span title={`Last seen ${formatDateTime(i.lastSeen)}`}>{formatRelativeTime(i.lastSeen)}</span>
          )}
        </span>
      </div>
    </li>
  )
}

/** Look-alike open incidents as one row: how many, a few names, where and
 *  why; it opens the Incidents tab filtered to them. */
function AttentionGroupRow({ clusterId, items }: { clusterId: string; items: Incident[] }) {
  const first = items[0]
  const kind = (first.objectGvk ?? '').split('/').pop() || 'object'
  const last = items.reduce((a, b) => (a.lastSeen > b.lastSeen ? a : b))
  const to = `/clusters/${encodeURIComponent(clusterId)}?tab=incidents&ins=${encodeURIComponent(first.objectNamespace ?? '')}&isev=${first.severity}`
  return (
    <li className={`attention-row ${SEV_CLASS[first.severity] ?? 'sev-neutral'}`}>
      <div className="attention-identity">
        <Link className="attention-name" to={to}>
          {items.length} {kind}s
        </Link>
        <span className="attention-meta attention-group-names" title={items.map((i) => i.objectName).join('\n')}>
          {items
            .slice(0, 3)
            .map((i) => i.objectName)
            .join(', ')}
        </span>
        <span className="attention-meta">
          {first.objectNamespace} — {first.openingReason ?? 'no reason recorded'}
        </span>
      </div>
      <div className="attention-status">
        <span className="attention-severity">
          <span className="severity-chip" aria-hidden="true" />
          {SEVERITY_LABEL[first.severity] ?? first.severity}
        </span>
        <span title={`Last seen ${formatDateTime(last.lastSeen)}`}>{formatRelativeTime(last.lastSeen)}</span>
      </div>
    </li>
  )
}

export function NeedsAttentionCard({
  clusterId,
  incidents,
  openCount,
  loading,
  error,
  truncated,
  onShowAll,
}: {
  clusterId: string
  incidents: Incident[]
  openCount: number | undefined
  loading: boolean
  error: unknown
  truncated: boolean
  onShowAll: () => void
}) {
  // Up to ROWS: about the depth of the Changes card beside it, so the pair
  // reads as one row rather than a short card next to a tall one.
  const groups = openAttentionGroups(incidents, ROWS)
  const top = groups.map((g) => g.items[0])
  const open = incidents.filter((i) => !['Resolved', 'Dismissed'].includes(i.state))
  const sevCount = (s: string) => open.filter((i) => i.severity === s).length
  // A quiet cluster: the rows the open list leaves empty show what ARGUS
  // closed most recently, rather than a hole beside the Changes card.
  const closed = loading || error ? [] : recentlyClosed(incidents, Math.min(ROWS - top.length, CLOSED_ROWS))
  return (
    <section className="card card-compact" aria-label="Needs attention">
      <div className="card-head">
        <h3>Needs attention</h3>
        {/* The whole-set open count from the hub, never this page's length. */}
        <span className="card-head-meta">{openCount === undefined ? '—' : `${openCount} open`}</span>
      </div>
      {loading ? (
        <div aria-busy="true" aria-label="Loading incidents">
          <SkeletonLines count={3} />
        </div>
      ) : error ? (
        <p className="form-error" role="alert">
          {errorText(error, 'Incidents for this cluster could not be loaded.')}
        </p>
      ) : top.length === 0 && closed.length === 0 ? (
        <p className="empty-state">No open incidents on this cluster.</p>
      ) : (
        <>
          {open.length > 0 && (
            <SplitBar
              tall
              label="Open incidents by severity"
              showZero
              parts={[
                { tone: 'critical', value: sevCount('critical'), label: 'critical' },
                { tone: 'high', value: sevCount('high'), label: 'high' },
                { tone: 'medium', value: sevCount('medium'), label: 'medium' },
                ...(sevCount('low') ? [{ tone: 'ok' as const, value: sevCount('low'), label: 'low' }] : []),
              ]}
            />
          )}
          {top.length > 0 ? (
            <ul className="attention-list">
              {groups.map((g) =>
                g.items.length === 1 ? <AttentionRow key={g.key} incident={g.items[0]} /> : <AttentionGroupRow key={g.key} clusterId={clusterId} items={g.items} />,
              )}
            </ul>
          ) : (
            <p className="attention-none">No open incidents on this cluster.</p>
          )}
          {closed.length > 0 && (
            <>
              <h4 className="attention-subhead">Recently closed</h4>
              <ul className="attention-list">
                {closed.map((i) => (
                  <AttentionRow key={i.id} incident={i} closed />
                ))}
              </ul>
            </>
          )}
          {truncated && <p className="field-hint">Ranked from the most recently active incidents fetched.</p>}
        </>
      )}
      <p className="card-foot-links">
        <button type="button" className="link-button" onClick={onShowAll}>
          {openCount === undefined ? 'All incidents on this cluster' : openCount === 1 ? 'The 1 open incident' : `All ${openCount} open incidents`} →
        </button>
        {/* What this cluster reported that did not become an incident. */}
        <Link to={`/signals?clusterId=${encodeURIComponent(clusterId)}`}>Signals from this cluster →</Link>
      </p>
    </section>
  )
}

const WINDOW_MS = 60 * 60 * 1000
const BINS = 12
/** Changed objects listed; the Needs attention card beside it lists ROWS. */
const CHANGED_OBJECTS = 4

/** "2 High, 1 Medium" — the severities of marks the caption does not name
 *  one by one, so no triangle is left with its colour as its only label. */
function severityTally(incidents: readonly Incident[]): string {
  const counts = new Map<string, number>()
  for (const i of incidents) counts.set(i.severity, (counts.get(i.severity) ?? 0) + 1)
  return [...counts.entries()].map(([sev, n]) => `${n} ${SEVERITY_LABEL[sev as Incident['severity']] ?? sev}`).join(', ')
}

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`
}

export function ChangesCard({ clusterId, incidents, incidentsTruncated }: { clusterId: string; incidents: Incident[]; incidentsTruncated: boolean }) {
  const { accessToken } = useAuth()
  const q = useQuery({
    queryKey: ['resource-changes-recent', clusterId],
    queryFn: async () => {
      const end = Date.now()
      const data = await getResourceChanges(clusterId, { since: new Date(end - WINDOW_MS).toISOString(), limit: 200 }, accessToken!)
      return { ...data, end }
    },
    enabled: !!accessToken,
    refetchInterval: LIVE_FALLBACK_MS,
    retry: false,
  })
  const end = q.data?.end ?? 0
  const start = end - WINDOW_MS
  const act = q.data ? changeActivity(q.data.changes, start, end, BINS, CHANGED_OBJECTS) : null
  const gaps = q.data ? windowGaps(q.data.gaps, start, end) : []
  const opened = q.data ? incidentsOpenedIn(incidents, start, end) : []
  const objectsTotal = act ? act.objects.length + act.hidden : 0
  const truncated = !!q.data?.truncated
  const binMinutes = WINDOW_MS / BINS / 60_000
  return (
    <section className="card card-compact" aria-label="Changes in the last 60 minutes">
      <div className="card-head">
        <h3>Changes</h3>
        <HelpTip
          label="Changes"
          text="Spec and metadata changes the agent recorded to objects on this cluster in the last hour, counted in 5-minute steps and grouped by the object that owns them, with the incidents that opened in the same hour marked under the same axis. Status-only updates are not recorded. Closeness in time is a lead to follow, not a diagnosis."
        />
        <span className="card-head-meta">
          {act && act.total > 0 ? (
            <>
              <Quantity value={act.total} certainty={truncated ? 'atLeast' : 'exact'} /> change{act.total === 1 ? '' : 's'} · {plural(objectsTotal, 'object')} ·
              last 60 min
            </>
          ) : (
            'last 60 min'
          )}
        </span>
      </div>
      {q.isLoading ? (
        <div aria-busy="true" aria-label="Loading changes">
          <SkeletonLines count={3} />
        </div>
      ) : q.isError ? (
        <p className="form-error" role="alert">
          {errorText(q.error, 'The change history could not be read.')}
        </p>
      ) : !act || (act.total === 0 && opened.length === 0) ? (
        <p className="empty-state">No changes recorded in the last 60 minutes.</p>
      ) : (
        <>
          <div
            className="activity"
            role="img"
            aria-label={`Changes per ${binMinutes} minutes over the last hour, oldest first: ${act.bins.join(', ')}.${
              opened.length ? ` ${plural(opened.length, 'incident')} opened in the same hour.` : ''
            }`}
          >
            <span className="activity-peak" aria-hidden="true">
              {act.peak > 0 ? act.peak : ''}
            </span>
            <div className="activity-bars" aria-hidden="true">
              {act.bins.map((n, i) => (
                <span key={i} className="activity-bin" title={`${n} change${n === 1 ? '' : 's'}, ${(BINS - i) * binMinutes}–${(BINS - i - 1) * binMinutes} min ago`}>
                  {n > 0 && <span className="activity-bar" style={{ height: `${Math.max(12, (n / act.peak) * 100)}%` }} />}
                </span>
              ))}
            </div>
            <div className="activity-incidents" aria-hidden="true">
              {opened.map(({ incident, at }) => (
                <span
                  key={incident.id}
                  className={`activity-incident ${SEV_CLASS[incident.severity] ?? 'sev-neutral'}`}
                  style={{ left: `${at * 100}%` }}
                  title={`${SEVERITY_LABEL[incident.severity] ?? incident.severity} incident opened ${formatDateTime(incident.firstSeen)}: ${incidentIdentity(incident).name}`}
                />
              ))}
            </div>
            <div className="activity-axis" aria-hidden="true">
              <span>60 min ago</span>
              <span>30</span>
              <span>now</span>
            </div>
          </div>
          <p className="activity-caption">
            {act.total === 0
              ? 'No changes recorded in this hour.'
              : `Bars: changes per ${binMinutes} minutes${act.peak > 0 ? `, ${act.peak} at the peak` : ''}${
                  truncated ? `, counted over the ${q.data?.changes.length ?? ''} most recent changes fetched` : ''
                }.`}
            {opened.length > 0 ? (
              <>
                {' '}
                <span className="activity-incident-key" aria-hidden="true" />{' '}
                {incidentsTruncated ? 'At least ' : ''}
                {plural(opened.length, 'incident')} opened in this hour:{' '}
                {opened
                  .slice(0, 3)
                  .map(({ incident }) => `${SEVERITY_LABEL[incident.severity] ?? incident.severity} ${incidentIdentity(incident).name}`)
                  .join(', ')}
                {opened.length > 3 ? `, and ${opened.length - 3} more (${severityTally(opened.slice(3).map((o) => o.incident))})` : ''}.
              </>
            ) : (
              ' No incident opened in this hour.'
            )}
          </p>
          {act.objects.length > 0 && (
            <ul className="changed-list">
              {act.objects.map((o) => {
                const inc = openIncidentOn(o, incidents)
                return (
                  <li key={o.key} className="changed-row">
                    <span className="changed-what">
                      {o.kind && <span className="preview-kind">{o.kind}</span>} <span className="changed-name insight-mono">{o.name}</span>
                    </span>
                    <span className="changed-count tabular">{plural(o.count, 'change')}</span>
                    <span className="changed-meta">
                      {opsText(o)}
                      {' · '}
                      <span title={formatDateTime(o.newest)}>latest {formatRelativeTime(o.newest)}</span>
                      {o.namespace ? ` · ${o.namespace}` : ''}
                    </span>
                    {inc && (
                      <Link to={`/incidents/${inc.id}`} className={`changed-incident ${SEV_CLASS[inc.severity] ?? 'sev-neutral'}`}>
                        <span className="severity-chip" aria-hidden="true" />
                        {SEVERITY_LABEL[inc.severity] ?? inc.severity} incident open on it
                      </Link>
                    )}
                  </li>
                )
              })}
            </ul>
          )}
        </>
      )}
      {gaps.length > 0 && <p className="insight-note">History has a gap in this window: {gaps.join('; ')}</p>}
      <p className="card-foot-links">
        <Link to={`/changes?clusterId=${encodeURIComponent(clusterId)}`}>
          {act && act.hidden > 0 ? `All changes, including ${act.hidden} more object${act.hidden === 1 ? '' : 's'}` : 'All recent changes'} →
        </Link>
        {/* PROJECT.md AD1: the same changes beside findings and incidents. */}
        <Link to={`/clusters/${encodeURIComponent(clusterId)}?tab=timeline`}>Open timeline →</Link>
      </p>
    </section>
  )
}

/** One Checks cell: a label, the answer drawn at one fixed height so every
 *  cell's answers line up, and a caption. A cell with a tab is one link. */
function CheckCell({ label, to, main, note, title }: { label: string; to?: string; main: ReactNode; note?: string; title?: string }) {
  const body = (
    <>
      <span className="check-cell-label">{label}</span>
      <span className="check-cell-main">{main}</span>
      <span className="check-cell-note">{note ?? '\u00a0'}</span>
    </>
  )
  return to ? (
    <Link className="check-cell check-cell-link" to={to} title={title}>
      {body}
    </Link>
  ) : (
    <div className="check-cell" title={title}>
      {body}
    </div>
  )
}

export function ChecksCard({ clusterId, summary }: { clusterId: string; summary: ClusterSummary | null }) {
  const { query: scansQuery, byCluster } = useFleetUpgradeScans()
  const scan = byCluster.get(clusterId)
  const posture = useInspect<PostureResult>(clusterId, 'get_posture_findings', POSTURE_ARGS)
  const certs = useInspect<CertificatesResult>(clusterId, 'list_certificates', CERT_ARGS)
  const helm = useInspect<HelmReleaseList>(clusterId, 'list_helm_releases', HELM_ARGS)
  const helmFigures = helmChecks(helm.query.data?.result)
  const danger = postureDangerCount(posture.query.data?.result)
  const expiring = certificatesExpiring(certs.query.data?.result)
  const np = summary?.networkPolicyCoverage
  const gitops = summary?.gitopsControllers
  const denied = posture.missing.length > 0 ? missingCapabilityMessage(posture.missing) : null
  const tabLink = (tab: string) => `/clusters/${encodeURIComponent(clusterId)}?tab=${tab}`
  const pSummary = posture.query.data?.result?.summary
  const certRows = certs.query.data?.result?.certificates ?? []
  const nextDays = certRows.filter((c) => typeof c.daysLeft === 'number').map((c) => c.daysLeft as number)
  const restricted = denied ? <span className="text-muted" title={denied}>Restricted</span> : null
  const pending = (q: { isLoading: boolean }, resolved: boolean) => (q.isLoading || !resolved ? <span className="text-muted">Checking…</span> : null)
  const failed = (q: { isError: boolean; error: unknown }) =>
    q.isError ? <span className="text-muted">— {errorText(q.error, 'the agent did not answer')}</span> : null
  return (
    <section className="card card-compact checks-card" aria-label="Checks">
      <div className="card-head">
        <h3>Checks</h3>
        <HelpTip
          label="Checks"
          text="The latest stored upgrade-readiness verdict, danger/warning/passing posture checks, certificates expiring within 30 days, Helm releases and how many are failed, pending or unhealthy, and how much of the cluster's workload a NetworkPolicy selects. Each opens its tab."
        />
        <span className="card-head-meta">
          <Link to={tabLink('gitops')}>GitOps</Link>:{' '}
          <span>
            {gitops
              ? gitops.length
                ? gitops.map(gitopsControllerLabel).join(', ')
                : 'None detected'
              : summary?.cacheState === 'syncing'
                ? 'still reading'
                : 'not reported'}
          </span>
        </span>
      </div>
      <div className="check-cells">
        <CheckCell label={scan ? `Upgrade to ${scan.targetVersion}` : 'Upgrade readiness'} to={tabLink('upgrade')}
          main={
            scansQuery.isLoading ? <span className="text-muted">Loading…</span>
            : scansQuery.isError ? <span className="text-muted">— could not load</span>
            : scan ? <VerdictBadge verdict={toVerdict(scan.verdict)} />
            : <span className="text-muted">Not scanned</span>
          }
          note={scan ? `scanned ${formatRelativeTime(scan.scannedAt)} · from ${scan.currentVersion || '?'}` : undefined}
        />
        <CheckCell label="Posture" to={tabLink('posture')}
          main={restricted ?? pending(posture.query, posture.capabilityResolved) ?? failed(posture.query) ??
            (pSummary && typeof pSummary.danger === 'number' ? (
              <SplitBar
                legend={false}
                label="Posture checks"
                parts={[
                  { tone: 'critical', value: pSummary.danger ?? 0, label: 'danger' },
                  { tone: 'high', value: pSummary.warning ?? 0, label: 'warning' },
                  { tone: 'ok', value: pSummary.passing ?? 0, label: 'passing' },
                ]}
              />
            ) : danger ? (
              <strong className="check-cell-figure"><Quantity value={danger.value} certainty={danger.atLeast ? 'atLeast' : 'exact'} /></strong>
            ) : '—')}
          note={pSummary && typeof pSummary.danger === 'number' ? `${pSummary.danger} danger · ${pSummary.warning} warning` : danger ? 'danger findings' : undefined}
        />
        <CheckCell label="Certificates ≤ 30 days" to={tabLink('certificates')}
          main={restricted ?? pending(certs.query, certs.capabilityResolved) ?? failed(certs.query) ??
            (expiring ? (
              <strong className="check-cell-figure"><Quantity value={expiring.value} certainty={expiring.atLeast ? 'atLeast' : 'exact'} /></strong>
            ) : '—')}
          note={expiring ? [`of ${certRows.length}`, nextDays.length ? `next in ${Math.min(...nextDays)}d` : '', expiring.unknown > 0 ? `${expiring.unknown} unknown` : ''].filter(Boolean).join(' · ') : undefined}
        />
        <CheckCell label="Helm releases" to={tabLink('helm')}
          main={restricted ?? pending(helm.query, helm.capabilityResolved) ?? failed(helm.query) ??
            (helmFigures ? (
              <>
                <strong className="check-cell-figure"><Quantity value={helmFigures.total} /></strong>
                {helmFigures.problems === 0 ? (
                  <span className="badge badge-green">none failing</span>
                ) : (
                  <span className="badge badge-red">
                    <Quantity value={helmFigures.problems} certainty={helmFigures.problemsAtLeast ? 'atLeast' : 'exact'} /> failing
                  </span>
                )}
              </>
            ) : '—')}
          note={helmFigures ? (helmFigures.unread > 0 ? `${helmFigures.unread} status not read` : 'every status read') : undefined}
        />
        <CheckCell label="NetworkPolicy"
          main={np ? (
            <SplitBar
              legend={false}
              label="Workloads selected by a NetworkPolicy"
              parts={[
                { tone: 'accent', value: np.coveredWorkloads, label: 'selected' },
                { tone: 'neutral', value: Math.max(0, np.totalWorkloads - np.coveredWorkloads), label: 'not selected' },
              ]}
            />
          ) : summary?.cacheState === 'syncing' ? <span className="text-muted">— still reading</span>
            : <span className="text-muted">— not computed</span>}
          note={np ? `${np.coveredWorkloads} of ${np.totalWorkloads} workloads selected` : undefined}
          title={np ? [
            `${np.policies} ${np.policies === 1 ? 'policy' : 'policies'}`,
            np.invalidPolicies ? `${np.invalidPolicies} could not be evaluated` : '',
            ...(np.notEvaluated ?? []).map((n) => `${n.count} ${kindLabel(n)} not evaluated`),
          ].filter(Boolean).join(' · ') : undefined}
        />
      </div>
    </section>
  )
}

// Shared with PosturePanel (no category) and CertificatesPanel, so the
// preview and the full tab are one cached read.
const POSTURE_ARGS = {}
const CERT_ARGS = {}
