// The timeline/findings-history group of the incident-detail screen: the
// horizontal lifecycle rail, the per-reason findings history, the real
// chronological timeline, and prior-occurrences-on-this-object — split out
// of IncidentDetailPage.tsx (PROJECT.md P25) with no behavior change. See
// that file's own header for the screen this panel belongs to.
import { useId, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { getIncidentTimeline } from '../../api/client'
import type { Finding, FindingReasonGroup, PriorIncidentLink, TimelineEvent } from '../../api/types'
import { useAuth } from '../../auth/useAuth'
import { formatDateTime, formatDurationBetween, formatRelativeTime } from '../../utils/time'
import { SkeletonLines } from '../../components/Skeleton'
import { ChevronIcon } from '../../components/icons'
import { SeverityBadge, StateBadge } from '../../components/IncidentBadges'
import { detectorShortLabel } from '../../utils/detectors'

// What a finding with no recorded reason renders as. The column is nullable and
// nothing writes NULL into it today, so this is a legacy-row guard: an empty
// bold span would read as a rendering fault rather than as missing data.
const NO_REASON_LABEL = 'Reason not recorded'


// The first→last window a reason has been happening in, or a single timestamp
// when both ends are the same instant.
//
// That collapse is not a cosmetic nicety: the sweep detectors report a
// condition's TRANSITION time as occurred_at, so an object that has been Pending
// for weeks has dozens of findings all stamped with the same moment (verified
// against the live database — one 84-finding incident has exactly one distinct
// occurred_at). "5h ago → 5h ago" reads as a rendering bug; one timestamp next
// to ×84 reads as the truth, which is that the condition has not changed since.
export function FindingEvent({ finding, showSeverity }: { finding: Finding; showSeverity: boolean }) {
  return (
    <div className="finding-event">
      {showSeverity && (
        <p className="finding-event-head">
          <SeverityBadge severity={finding.severity} />
        </p>
      )}
      <p>{finding.message}</p>
      <p className="field-hint">
        {finding.gvk} · {finding.namespace}/{finding.objectName} ·{' '}
        {/* The readable detector name, not the raw `k8s-sweep` wire id this
            line used to print: an API identifier is never the user-facing
            value, and the id told the reader nothing about the one thing
            that matters here — whether their own tooling would have seen
            this event too. Per EVENT, not per incident, because a single
            incident legitimately correlates findings from several detectors.
            `title` keeps the raw id reachable for anyone cross-referencing
            Settings → Detection, which is a correlation aid rather than the
            meaning; an unrecognised id falls back to printing itself, so
            nothing is ever hidden behind a label that does not exist. */}
        <span title={finding.detectorId}>via {detectorShortLabel(finding.detectorId)}</span> · occurred{' '}
        {finding.occurrenceCount}× ·{' '}
        <span title={formatDateTime(finding.occurredAt)}>{formatRelativeTime(finding.occurredAt)}</span>
      </p>
    </div>
  )
}

export function ReasonTimeRange({ group }: { group: FindingReasonGroup }) {
  if (group.firstSeen === group.lastSeen) {
    return <span title={formatDateTime(group.lastSeen)}>{formatRelativeTime(group.lastSeen)}</span>
  }
  return (
    <>
      <span title={formatDateTime(group.firstSeen)}>{formatRelativeTime(group.firstSeen)}</span>
      <span aria-hidden="true"> → </span>
      <span className="visually-hidden"> to </span>
      <span title={formatDateTime(group.lastSeen)}>{formatRelativeTime(group.lastSeen)}</span>
    </>
  )
}

// One reason: a summary line, and — when the reason has repeated — that line as
// a real <button aria-expanded> revealing its individual events.
//
// A reason with exactly one event renders that event directly, with no toggle:
// a disclosure control that reveals a single row asks for a click to tell the
// operator nothing they could not have been shown outright. The static summary
// line keeps the layout of the expandable ones so a mixed list still reads as
// one list.
//
// Counts and the time range come from the group, never from `events.length` —
// events is the newest handful, the group is the whole history.
//
// The panel is rendered only while open (rather than always present with
// `hidden` toggled) so its fade-in runs on the click that opened it. aria-expanded
// is what actually conveys the state; aria-controls is the advisory half of the
// pair, and it pointing at a not-yet-rendered panel while collapsed is the usual
// trade-off of this pattern.
export function FindingReasonRow({ group, events }: { group: FindingReasonGroup; events: Finding[] }) {
  const [expanded, setExpanded] = useState(false)
  const panelId = useId()
  const label = group.reason || NO_REASON_LABEL
  // events[0] is this reason's newest event: the hub orders findings newest
  // first and always sends at least one per reason it reports, so this is
  // populated in practice — guarded anyway, since a badge is not worth a blank
  // page if that ever stops being true.
  const newest = events[0] ?? null
  const repeated = group.count > 1

  const summary = (
    <>
      {newest && <SeverityBadge severity={newest.severity} />}
      <strong className="finding-group-reason">{label}</strong>
      {repeated && (
        <span className="finding-group-count" title={`${group.count} events recorded for this reason`}>
          ×{group.count}
        </span>
      )}
      <span className="finding-group-range">
        <ReasonTimeRange group={group} />
      </span>
    </>
  )

  if (!repeated) {
    return (
      <div className="finding-group">
        <div className="finding-group-summary">
          <span className="finding-group-chevron" aria-hidden="true" />
          {summary}
        </div>
        <div className="finding-group-events">
          {events.map((finding) => (
            <FindingEvent key={finding.id} finding={finding} showSeverity={false} />
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className="finding-group">
      <button
        type="button"
        className="finding-group-summary finding-group-toggle"
        aria-expanded={expanded}
        aria-controls={panelId}
        onClick={() => setExpanded((open) => !open)}
      >
        <ChevronIcon direction="right" size={14} className="finding-group-chevron" />
        {summary}
      </button>
      {expanded && (
        <div className="finding-group-events" id={panelId}>
          {events.map((finding) => (
            <FindingEvent key={finding.id} finding={finding} showSeverity />
          ))}
          {events.length < group.count && (
            <p className="field-hint finding-group-note">
              Showing the {events.length} most recent of {group.count} events for this reason. The hub keeps
              the older ones — this page loads only the newest.
            </p>
          )}
        </div>
      )}
    </div>
  )
}

// The whole history: a one-line summary of it, then one row per reason with the
// most recently seen reason first — the current symptom at the top, which is
// what an operator opening this page is looking for.
//
// Reason is the join key between the two payload fields, and the hub derives
// both from one ordered query pass, so the rows and their events cannot disagree
// about which symptom is current. Each row is keyed by reason too, so a poll
// that reorders the list (a quiet symptom recurring, and jumping to the top)
// carries any expanded state along with its row instead of dumping it on the
// row that took its place.
export function FindingsHistory({ groups, findings }: { groups: FindingReasonGroup[]; findings: Finding[] }) {
  if (groups.length === 0) {
    return <p className="empty-state">No findings recorded for this incident yet.</p>
  }

  const eventsByReason = new Map<string, Finding[]>()
  for (const finding of findings) {
    const existing = eventsByReason.get(finding.reason)
    if (existing) {
      existing.push(finding)
    } else {
      eventsByReason.set(finding.reason, [finding])
    }
  }

  // Summing the groups' own counts, not findings.length: this is the whole
  // history's size, and findings is a bounded slice of it.
  const totalEvents = groups.reduce((sum, group) => sum + group.count, 0)
  const anyRepeated = groups.some((group) => group.count > 1)

  return (
    <>
      <p className="field-hint">
        {totalEvents.toLocaleString()} event{totalEvents === 1 ? '' : 's'} across {groups.length} reason
        {groups.length === 1 ? '' : 's'}, most recent reason first.
        {anyRepeated && ' Open a reason to read its individual events.'}
      </p>
      <div className="finding-group-list">
        {groups.map((group) => (
          <FindingReasonRow key={group.reason} group={group} events={eventsByReason.get(group.reason) ?? []} />
        ))}
      </div>
    </>
  )
}

// BACKLOG.md D6's re-audit (2026-08-29): every RecommendationReady event
// already carries which action type it recommended (detail.actionType) under
// its own planId, and every later event on the SAME plan — ApprovalGranted/
// Rejected, ExecutionStarted/Outcome, PullRequestOpened/ProposalFailed —
// carries that identical planId in its own detail, but nothing read it back
// out. An incident with more than one recommendation in its history (a
// rejected-then-reanalyzed plan, or a paired in-place+PR plan, lld/08 §12.6)
// rendered "Approved"/"Execution succeeded" with no way to tell which
// recommendation it was for beyond inferring it from list order — the exact
// gap D6's own text named ("tying... the recommendation, the approval and
// the outcome into one chronological view"). Built once per open disclosure
// from data the endpoint already returns; no new event type, no new column,
// no backend change — the data was always there, just never read.
export function planActionTypes(events: TimelineEvent[]): Map<string, string> {
  const byPlan = new Map<string, string>()
  for (const event of events) {
    const planId = event.detail?.planId
    const actionType = event.detail?.actionType
    if (typeof planId === 'string' && typeof actionType === 'string' && !byPlan.has(planId)) {
      byPlan.set(planId, actionType)
    }
  }
  return byPlan
}

// Event types whose OWN summary already names the action type server-side
// (RecommendationReady: "Recommended: ScaleDeployment"; ParamsCorrectionAttempted:
// "Attempted to correct ScaleDeployment's proposed params: …") — repeating it
// in the metadata line below would just be noise, not new information.
const NAMES_OWN_ACTION_TYPE = new Set(['RecommendationReady', 'ParamsCorrectionAttempted'])

// One entry in the real chronology GET .../timeline returns (BACKLOG.md B1).
// Reuses `.chain-list`/`.chain-node` verbatim rather than inventing the
// `Timeline` primitive lld/11-ui-design.md §3 names but never specifies the
// markup for (argus-design-system's own components.md notes it as
// "specified but not built") — a flat, ordered, dot-and-line list is exactly
// what `.chain-node` already draws, and `CausalStep` above is proof this
// page already renders that shape correctly. `sev-neutral` throughout, same
// reasoning as CausalStep: a timeline event carries no severity of its own,
// only a fact and a time — colour-ranking these would be a fabricated
// signal, not a styling choice.
//
// `previous` lets this compute the gap since the prior event
// (formatDurationBetween) — lld/11-ui-design.md §4's own contract is
// "rendered in order, durations computed client-side from adjacent
// timestamps," so this is the endpoint's intended reading, not an addition
// to it. `actionType` (resolved by the caller via `planActionTypes`, keyed
// off this event's own detail.planId) is the D6 addition described above —
// omitted entirely when unresolvable (an event with no planId, or one whose
// plan's own RecommendationReady row predates this feature) rather than
// guessed at.
export function TimelineEventNode({
  event,
  previous,
  actionType,
}: {
  event: TimelineEvent
  previous?: TimelineEvent
  actionType?: string
}) {
  const gap = previous ? formatDurationBetween(previous.occurredAt, event.occurredAt) : null
  const showActionType = !!actionType && !NAMES_OWN_ACTION_TYPE.has(event.eventType)
  return (
    <li className="chain-node sev-neutral">
      <span className="chain-node-track" aria-hidden="true">
        <span className="chain-node-dot" />
      </span>
      <div className="chain-node-body">
        {/* summary is server-built prose that can embed a Finding's own
            reason/message text verbatim (the IncidentOpened event) or a
            human-typed rejection reason — untrusted cluster/user-derived
            content, same rule as FindingEvent's message above: plain JSX
            interpolation only. */}
        <p className="chain-node-text">{event.summary}</p>
        <p className="field-hint">
          <span title={formatDateTime(event.occurredAt)}>{formatRelativeTime(event.occurredAt)}</span>
          {gap && <span> · {gap} after the previous event</span>}
          {showActionType && <span> · {actionType}</span>}
        </p>
      </div>
    </li>
  )
}

// The history, collapsed by default, nested inside stage 1 rather than sitting
// below the six stage boxes as its own card (moved there directly on request,
// 2026-08-25). This is a real change to a deliberate earlier decision — the
// comment that used to sit where the standalone section was, and BACKLOG.md's
// D8 section, both said "What happened" sits OUTSIDE the six-box chain, below
// it, on the grounds that no stage produces it. That is still true; nesting it
// under Detection does not make it a seventh stage (it carries no stage
// number, and StageCard never renders it) — it changes only WHERE the
// non-stage history sits, from "after the chain" to "folded into the one
// stage it is most related to" (Detection: both are about the raw finding
// data, before any interpretation). Collapsed by default so a page that used
// to always show ×84 events now costs one click instead of a full card's
// worth of space on every load.
//
// Same disclosure idiom as `FindingReasonRow`'s own per-reason toggle
// (`.finding-group-summary`/`.finding-group-toggle`/`.finding-group-chevron`,
// reused verbatim below) rather than a second one — this is the outer level
// of the same pattern, not a new pattern.
//
// BACKLOG.md B1: this is the exact slot D8's own design reserved for "the
// incident's history, which no stage produces" — so the real timeline
// (GET .../timeline) lives HERE, inside this same disclosure, rather than as
// a new standalone section or a rebuilt `Timeline` component elsewhere on
// the page. Fetched lazily, only once this disclosure is actually opened
// (`enabled: open` on the query below) — matching the reason this disclosure
// is collapsed by default in the first place: a page that shows a real
// chronology for every incident should not fire that request on every load
// for a card most views never expand.
//
// The two sections below answer genuinely different questions and are kept
// as two labelled sub-sections rather than merged into one list: the
// timeline is what ARGUS itself did and when (nine specific transitions,
// oldest first); "by reason" is the raw finding history — every recurrence
// of the same condition, however many times it fired, which the timeline
// does not restate event-by-event (IncidentOpened records only the
// OPENING finding). Merging them would either drop the recurrence counts or
// flood the chronology with duplicate rows for a condition that fired 84
// times.
export function WhatHappenedDisclosure({
  groups,
  findings,
  incidentId,
}: {
  groups: FindingReasonGroup[]
  findings: Finding[]
  incidentId: string
}) {
  const [open, setOpen] = useState(false)
  const panelId = useId()
  const { accessToken } = useAuth()

  const timelineQuery = useQuery({
    queryKey: ['incidents', incidentId, 'timeline'],
    queryFn: () => getIncidentTimeline(incidentId, accessToken!),
    enabled: open && !!accessToken,
    // The history rail already fetched this key; opening the disclosure
    // reuses that response. A live IncidentUpdated still invalidates it.
    staleTime: 30_000,
  })
  const events = timelineQuery.data?.events ?? []
  const hasTimeline = events.length > 0
  const actionTypesByPlan = planActionTypes(events)

  return (
    <div className="detection-history">
      <button
        type="button"
        className="finding-group-summary finding-group-toggle detection-history-toggle"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((o) => !o)}
      >
        <ChevronIcon direction="right" size={14} className="finding-group-chevron" />
        <strong className="finding-group-reason">What happened</strong>
      </button>
      {open && (
        <div id={panelId} className="detection-history-panel">
          <div className="detection-history-section">
            <p className="eyebrow">Timeline</p>
            {timelineQuery.isLoading ? (
              <SkeletonLines count={3} />
            ) : timelineQuery.isError ? (
              <p className="form-error" role="alert">
                Could not load the timeline for this incident.
              </p>
            ) : hasTimeline ? (
              <ol className="chain-list">
                {events.map((event, i) => {
                  const planId = event.detail?.planId
                  return (
                    <TimelineEventNode
                      key={event.id}
                      event={event}
                      previous={events[i - 1]}
                      actionType={typeof planId === 'string' ? actionTypesByPlan.get(planId) : undefined}
                    />
                  )
                })}
              </ol>
            ) : (
              <p className="field-hint">
                No timeline events recorded for this incident — either it predates this feature, or
                nothing has happened to it yet beyond the opening finding above.
              </p>
            )}
          </div>
          <div className="detection-history-section">
            <p className="eyebrow">Findings by reason</p>
            <FindingsHistory groups={groups} findings={findings} />
          </div>
        </div>
      )}
    </div>
  )
}

// PriorOccurrences — PROJECT.md T7: "a recurrence reuses what was learned
// rather than starting from zero." The owner decided a recurrence LINKS
// rather than reopens (Resolved/Dismissed/Expired all stay terminal), so
// this incident is a genuinely new row; this panel is where the link
// actually surfaces to a reader, rather than being a fact only a database
// join could answer.
//
// Reuses the exact disclosure shape WhatHappenedDisclosure (immediately
// above) already uses for the same stage — `.detection-history` +
// `.finding-group-summary`/`.finding-group-toggle`/`.detection-history-toggle`
// button, `.detection-history-panel`/`.detection-history-section` body — so
// stage 1 reads as one family of "more history here" disclosures rather
// than introducing a second visual language for the same kind of fact. Each
// prior incident's own facts render as a `.fact-list` (the existing dt/dd
// grid AuditEventDetailModal and others already use), and consecutive ones
// pick up `.fact-list + .fact-list`'s existing divider rule for free.
//
// Deliberately renders nothing (not an empty state) when there is nothing to
// show: a first occurrence — still the overwhelming majority of incidents —
// would otherwise carry a permanently-empty disclosure on every single
// incident page, which is exactly the "spend nothing on a fact that isn't
// there" austerity this screen's mode calls for. Loading/error states are
// not this component's own to render — it derives entirely from the same
// GET /incidents/{id} the rest of the page already fetched, so IncidentDetailPage's
// existing top-level loading/error handling already covers it.
export function PriorOccurrences({ items }: { items: PriorIncidentLink[] }) {
  const [open, setOpen] = useState(false)
  const panelId = useId()

  if (items.length === 0) {
    return null
  }

  return (
    <div className="detection-history">
      <button
        type="button"
        className="finding-group-summary finding-group-toggle detection-history-toggle"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((o) => !o)}
      >
        <ChevronIcon direction="right" size={14} className="finding-group-chevron" />
        <strong className="finding-group-reason">Prior occurrences ({items.length})</strong>
      </button>
      {open && (
        <div id={panelId} className="detection-history-panel">
          <div className="detection-history-section">
            <p className="field-hint">
              Closed before on this object or another pod of its workload — what was learned last time.
            </p>
            {items.map((item) => (
              <dl className="fact-list" key={item.incidentId}>
                <dt>Closed</dt>
                <dd>
                  <StateBadge state={item.state} resolutionKind={item.resolutionKind} />{' '}
                  <Link to={`/incidents/${item.incidentId}`}>
                    <span title={formatDateTime(item.resolvedAt ?? item.firstSeen)}>
                      {formatRelativeTime(item.resolvedAt ?? item.firstSeen)}
                    </span>
                  </Link>
                </dd>
                <dt>Learned</dt>
                <dd>{item.rootCause ?? 'Closed with no analysis recorded.'}</dd>
                {item.rejectedPlan && (
                  <>
                    <dt>Rejected</dt>
                    <dd>
                      A {item.rejectedPlan.actionType} plan was refused: {item.rejectedPlan.reason}
                    </dd>
                  </>
                )}
              </dl>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
