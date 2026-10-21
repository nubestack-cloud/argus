import { Fragment, useEffect, useRef, useState } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { getClusters, getIncidents, ApiError } from '../api/client'
import type { Incident, IncidentSortDirection, IncidentSortKey, IncidentState } from '../api/types'
import { useAuth } from '../auth/useAuth'
import { useHasCapability } from '../auth/useCapabilities'
import { CAP_CLUSTER_READ, CAP_INCIDENT_TRIAGE } from '../api/capabilities'
import { missingCapabilityMessage } from '../api/capabilityInfo'
import { formatDateTime, formatRelativeTime } from '../utils/time'
import { SkeletonTableRows } from '../components/Skeleton'
import { EmptyState } from '../components/EmptyState'
import { ActionMenu } from '../components/ActionMenu'
import { Dialog } from '../components/Dialog'
import { BulkActionBar } from '../components/BulkActionBar'
import { ConfirmBulkDismissModal } from '../components/ConfirmBulkDismissModal'
import { usePhoneLayout } from '../hooks/usePhoneLayout'
import { ChevronIcon, SearchIcon, SortIcon } from '../components/icons'
// Paging is shared with ClustersPage and ClusterDetailPage now (BUGS.md 57) —
// this page's own copy of the arithmetic and the footer markup was the one the
// other two were derived from, so it is the one that had to stop being local.
import { TablePagination } from '../components/TablePagination'
import { useUrlPagination } from '../fleet/useUrlPagination'
import { useSearchParamsWriter, useUrlParam } from '../hooks/useUrlState'
import { useRowNavigation } from '../fleet/useRowNavigation'
import { useNewArrivals } from '../fleet/useNewArrivals'
import { useFreshIds } from '../realtime/freshRows'
// This page's own badges and their lookup maps, now shared with the three other
// screens that had copied them — see components/IncidentBadges.tsx and
// utils/incidents.ts. STATE_LABEL is imported here too because the state
// <select> lists the same readable labels the badges render, and the two must
// not diverge; SEVERITY_LABEL for the same reason, now that the severity cell
// renders the word itself rather than a badge (see the Severity column below).
import { SeverityBadge, StateBadge } from '../components/IncidentBadges'
import { ListFreshness } from '../components/ListFreshness'
// ROUTE_LABEL is the readable form of internal/resolution.Route's four wire
// values, and it already exists because the detail page renders the same
// fact — imported rather than re-declared so the Route column below and the
// detail page's route sentence can never call one route two things
// (components.md: "always the readable label, never the raw enum value").
import { ROUTE_LABEL } from './incidentLifecycle'
import {
  DETECTION_COUNT_HEADER,
  SEVERITY_LABEL,
  STATE_LABEL,
  collapseWorkloadSiblings,
  detectionCountTitle,
  incidentIdentity,
  incidentIdentityLabel,
  incidentObservedObject,
  incidentRequiresAction,
  isClosedIncidentState,
  observedObjectTitle,
  workloadGroupSummary,
} from '../utils/incidents'
import type { IncidentListRow, WorkloadGroupRow } from '../utils/incidents'
import { LIVE_FALLBACK_MS } from '../realtime/refresh'
import { IncidentsSectionTabs } from '../components/IncidentsSectionTabs'
import {
  countFor,
  DEFAULT_STATUS,
  legacyViewParams,
  SEVERITIES,
  SEVERITY_FILTER_LABEL,
  SEVERITY_FILTERS,
  statesFor,
  STATUS_HINT,
  STATUS_LABEL,
  STATUS_VIEWS,
  type Severity,
  type StatusView,
} from './incidentFilters'

// 'requiresAction' was 'open'. Not a rename of the same bucket: it counts the
// states where nothing happens until a person acts, rather than every state
// that is not terminal — see STATE_DISPOSITION in utils/incidents.ts and the
// `requiresAction` count the server now sends under that name.
// BACKLOG.md T2 (candidate 2): a second view mode on this same screen,
// grouping the identical scope (cluster/state/search) by fingerprint
// instead of listing one row per incident — "230 incidents, 12 distinct
// problems" made real rather than a wall of near-identical rows. A mode
// switch, not a new screen: same data, same filters, a different shape for
// answering a different question ("what's actually wrong" vs "which one do
// I act on next").
// BACKLOG P10: sorting moved server-side (internal/api/incidents.go's
// incidentSortSpecs) — these two are aliases, not a separate local
// vocabulary, so this page's sort keys can never drift from what ?sort=/
// ?direction= actually accept.
type SortKey = IncidentSortKey
type SortDirection = IncidentSortDirection
const SORT_KEYS: SortKey[] = ['failure', 'cluster', 'severity', 'state', 'occurrences', 'lastSeen', 'importance']
const SORT_DIRECTIONS: SortDirection[] = ['asc', 'desc']
const NO_INCIDENTS: Incident[] = []

// Every state an incident can actually be in, which is deliberately NOT every
// value IncidentState permits: RecommendationReady is unreachable (nothing in
// the state machine has an edge into it — see orchestrator's allowedTransitions),
// so offering it as a filter would only ever match nothing. Its label and badge
// remain defined so a historical row still renders.
const ALL_INCIDENT_STATES: IncidentState[] = [
  'Detected',
  'Investigating',
  'NeedsHumanInvestigation',
  // A finished investigation whose route is guidance — a real cause, nothing
  // ARGUS executes (orchestrator's StateDiagnosed). Reachable, and where the
  // "what should a human do" queue lives, so it must be filterable.
  'Diagnosed',
  'AwaitingApproval',
  'Executing',
  'AwaitingMerge',
  'Validating',
  'Resolved',
  'Failed',
  // BACKLOG.md C8 / BUGS.md 104: a real, reachable outcome
  // recordExecutionOutcome writes — see internal/orchestrator/state.go's
  // StateExecutionUnknown.
  'ExecutionUnknown',
  'ValidationUnknown',
  // A plan a human refused (internal/orchestrator's StatePlanRejected). Worth
  // filtering for on its own: "what did we propose that people said no to" is
  // the question that tells you the recommendations are wrong, not the fleet.
  'PlanRejected',
  'Reopened',
  'Dismissed',
  // Closed by the staleness sweeper when nobody acted on it (orchestrator's
  // StateExpired). Without it here `?state=Expired` silently became "All".
  'Expired',
]
const STATE_FILTERS: Array<IncidentState | ''> = ['', ...ALL_INCIDENT_STATES]

// Severity as a rule on the row's left edge instead of a coloured pill in the
// middle of it (BACKLOG D7; .design/ListAndQueue.dc.html, archetype A). The
// class goes on the <tr> because `.sev-*` only sets custom properties and those
// inherit — the `<td class="severity-rule">` inside picks up the fill without
// carrying a severity class of its own (index.css, "SEVERITY, once").
//
// The severity WORD stays on the row, in its own column: the rule is a border,
// invisible to a screen reader and to anyone who cannot separate the four
// fills, and lld/11-ui-design.md §8 forbids colour as the only signal. That
// column is also what keeps the severity sort sortable.
const SEVERITY_RULE_CLASS: Record<Incident['severity'], string> = {
  low: 'sev-low',
  medium: 'sev-medium',
  high: 'sev-high',
  critical: 'sev-critical',
}

// Bulk dismiss eligibility. Mirrors orchestrator.allowedTransitions'
// actual edges into Dismissed (internal/orchestrator/state.go) rather than
// guessing: the three closed states (Resolved/Dismissed, and — PROJECT.md
// T2 — Expired, whose only edge is to Detected on a genuine recurrence, not
// to Dismissed) have no path to Dismissed, and Investigating/Executing are
// the two IN-PROGRESS states with no edge to Dismissed either — a real
// analysis or execution is in flight and another writer owns the state, the
// same rule that stops a single-incident dismiss from that state
// (internal/api/incident_triage.go's own "wait for it to finish" message).
// Checked against the transition table so this can't quietly drift from
// what handleDismissIncident actually allows.
const DISMISS_INELIGIBLE_STATES: ReadonlyArray<IncidentState> = ['Resolved', 'Dismissed', 'Expired', 'Investigating', 'Executing']
function IncidentQuickView({ incident, onClose }: { incident: Incident; onClose: () => void }) {
  const identity = incidentIdentity(incident)
  const observed = incidentObservedObject(incident)
  return (
    <Dialog title="Incident summary" onClose={onClose}>
        <dl className="fact-list">
          {/* B174. This dialog's only identity used to be the 64-character
              fingerprint — it said which severity, state and cluster, and
              never what was broken. The row it opens from now leads with the
              owning workload, so the dialog names the same subject the same
              way rather than being the one surface on this page that still
              names nothing. `Workload` when an owner was resolved, `Object`
              when the object IS the subject: one label for both would claim
              an Ingress or a bare Pod has a controller. */}
          <dt>{observed ? 'Workload' : 'Object'}</dt>
          <dd>
            {identity.name}
            {identity.kind && <> <span className="text-muted">{identity.kind}</span></>}
          </dd>
          {/* Past tense, and the same caveat the list row carries: ARGUS does
              not re-check whether this Pod still exists. Rendered only when
              there is an owner above it to be supporting detail FOR — for an
              incident whose object is its own subject this would be the line
              above, repeated. */}
          {observed && (
            <>
              <dt>Observed on</dt>
              <dd title={observedObjectTitle(observed)}>{observed.label}</dd>
            </>
          )}
          <dt>Severity</dt>
          <dd><SeverityBadge severity={incident.severity} dot /></dd>
          <dt>State</dt>
          <dd><StateBadge state={incident.state} resolutionKind={incident.resolutionKind} /></dd>
          <dt>Cluster</dt>
          <dd>{incident.clusterDisplayName}</dd>
          <dt>Fingerprint</dt>
          <dd>
            <span className="fingerprint" title={incident.fingerprint}>{incident.fingerprint}</span>
          </dd>
          {/* Not "Occurrences". That word named two different counts across
              these screens — this one, and the incident detail page's "Prior
              occurrences on this object", which counts prior CLOSED INCIDENTS
              rather than detector reports on the live one. See
              DETECTION_COUNT_HEADER in utils/incidents.ts for what each query
              actually returns. The dialog has room for the sentence, so it
              carries it rather than only a tooltip. */}
          <dt>{DETECTION_COUNT_HEADER}</dt>
          <dd>
            {incident.occurrenceCount}{' '}
            <span className="text-muted">
              {incident.occurrenceCount === 1 ? 'report' : 'reports'} from a detector since this incident opened
            </span>
          </dd>
          <dt>Resolution route</dt>
          <dd>
            {/* No fabricated route: an incident that has never been
                investigated genuinely has none, and guessing one from the
                object's kind would be a claim ARGUS did not make. */}
            {incident.route
              ? (ROUTE_LABEL[incident.route] ?? incident.route)
              : <span className="text-muted">Not routed yet — decided when the incident is investigated</span>}
          </dd>
          <dt>First seen</dt>
          <dd title={formatDateTime(incident.firstSeen)}>{formatRelativeTime(incident.firstSeen)}</dd>
          <dt>Last seen</dt>
          <dd title={formatDateTime(incident.lastSeen)}>{formatRelativeTime(incident.lastSeen)}</dd>
          {incident.fleetGroupId && (
            <>
              <dt>Scope</dt>
              <dd>Also occurring on other clusters</dd>
            </>
          )}
          {incident.workloadGroupId && (
            <>
              <dt>Siblings</dt>
              <dd>
                Also occurring on other pods of the same workload
                {incident.openingReason ? ` (${incident.openingReason})` : ''}
              </dd>
            </>
          )}
          {incident.objectGroupId && (
            <>
              <dt>Related object</dt>
              <dd>May be the same underlying outage as a failure on a related object</dd>
            </>
          )}
        </dl>

        <div className="modal-actions">
          <Link to={`/incidents/${incident.id}`} onClick={onClose}>View full incident →</Link>
        </div>
    </Dialog>
  )
}

function SortableHeader({
  label,
  sortKey,
  activeKey,
  direction,
  onSort,
  className,
}: {
  label: string
  sortKey: SortKey
  activeKey: SortKey
  direction: SortDirection
  onSort: (key: SortKey) => void
  className?: string
}) {
  const active = sortKey === activeKey
  return (
    <th className={className} aria-sort={active ? (direction === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button type="button" className="cluster-sort-button" onClick={() => onSort(sortKey)}>
        {label}
        <SortIcon direction={active ? direction : undefined} />
      </button>
    </th>
  )
}

// The row highlight. Two ways in, and they are different claims: the state says
// this row is waiting on a person, the severity says it would matter if it
// were. A closed incident is neither, whatever its severity.
//
// The state half used to be a hand-kept ATTENTION_STATES list that had drifted
// from the same idea the server holds — it omitted Diagnosed, so a finished
// investigation with a live fault and nothing to execute was the one row on the
// page that could never be highlighted.
function isAttentionIncident(incident: Incident): boolean {
  if (isClosedIncidentState(incident.state)) return false
  return (
    incidentRequiresAction(incident.state) ||
    incident.severity === 'critical' ||
    incident.severity === 'high'
  )
}

// RouteCell renders incidents.route as the one thing it must be on a scan
// surface: a readable word, in `.route-badge` — the same primitive the detail
// page uses for the same fact.
//
// THIS REVERSES A RECORDED DECISION, 2026-09-23, at the owner's direction.
// The text-only form was chosen because "a row that carries four pills is
// scanned for colour rather than for content", and that argument is not wrong
// — it is why severity next door is a chip plus a plain word rather than a
// fifth pill, and why the tint here is by channel with no ordinal meaning
// ("pull request" is not worse than "in place"). What changed is the owner's
// read of the assembled row, which is the evidence that argument was really
// about. If the row starts scanning as a colour field again, this is the first
// thing to take back out.
//
// An unrouted incident renders an em dash, never a guess. ARGUS decides the
// route from ownership facts during investigation (ADR-18); before that it
// genuinely has no answer, and the overwhelming majority of rows on any real
// fleet are in that state. The title says so rather than leaving a bare dash
// to be read as "no route exists for this".
// ROUTE_BADGE_CLASS tints the pill by CHANNEL, not by severity — a pull
// request is not worse than an in-place patch, it is a different place the fix
// lands. Blue for the repository (matching every other `route-badge-blue` on
// the detail page, so one channel is one colour across the app), amber for
// guidance (the route that produces no change at all, which is the one worth
// noticing), neutral grey for in-place.
const ROUTE_BADGE_CLASS: Record<string, string> = {
  pullRequest: 'route-badge route-badge-blue',
  // The paired route lands a change in the repository too, so it takes the
  // repository's colour rather than the neutral default.
  'pullRequest+inPlace': 'route-badge route-badge-blue',
  guidance: 'route-badge route-badge-amber',
}

function RouteCell({ route }: { route: string | null | undefined }) {
  if (!route) {
    return (
      <td className="col-shrink">
        <span className="text-muted" title="Not routed yet — ARGUS decides the route from ownership facts when the incident is investigated">
          —
        </span>
      </td>
    )
  }
  return (
    <td className="col-shrink" title="How a fix for this incident would be applied — decided from ownership facts before anything was proposed">
      <span className={ROUTE_BADGE_CLASS[route] ?? 'route-badge'}>{ROUTE_LABEL[route] ?? route}</span>
    </td>
  )
}

// One incident, one row. Extracted from the map it used to be inline in so the
// collapsed-siblings work below could render the SAME row for a group's
// members as for an ungrouped incident — a second, nearly-identical row
// component for "the same incident, indented" is exactly the local variant
// reference/anti-patterns.md warns about.
function IncidentRow({
  incident,
  selected,
  eligible,
  child = false,
  onToggleSelect,
  onQuickView,
  onNavigate,
  navProps,
  fresh = false,
}: {
  incident: Incident
  selected: boolean
  eligible: boolean
  child?: boolean
  onToggleSelect: () => void
  onQuickView: () => void
  onNavigate: (to: string) => void
  /** CI-U6 roving focus (j/k, arrows, Enter opens the incident). */
  navProps?: ReturnType<ReturnType<typeof useRowNavigation>['rowProps']>
  /** CI-U8: changed by a live update in the last two seconds. */
  fresh?: boolean
}) {
  const phoneLayout = usePhoneLayout()
  const identity = incidentIdentity(incident)
  // B174: the owning workload now leads this cell, so the Pod that carried
  // the symptom moves onto the fault line as the supporting fact it is —
  // `OOMKilled · Pod checkout-oom-6d99b45595-fw7v8`. Null for the two thirds
  // of incidents that have no resolved owner; there the object is already the
  // headline and this line is the bare reason, exactly as before.
  //
  // On the fault line specifically, and NOT as a fourth line, because this
  // table is measured: `e2e/list-density.spec.ts` holds a row to 110px and
  // three lines of identity is 59px of that. Measured in Chromium at 1440 and
  // 1280 before writing this — a Pod name on the `--font-size-xs` fault line
  // is height-neutral against the same name on the `--font-size-base` name
  // line it came off, and 5px SHORTER once the name is long enough to wrap,
  // because the smaller face wraps into a shorter second line.
  const observed = incidentObservedObject(incident)
  const faultLine = [identity.fault, observed?.label].filter(Boolean).join(' · ')
  return (
    <tr
      {...navProps}
      className={[
        SEVERITY_RULE_CLASS[incident.severity] ?? 'sev-neutral',
        isAttentionIncident(incident) ? 'incident-row-attention' : '',
        child ? 'row-group-child' : '',
        navProps?.['aria-current'] ? 'fleet-row-active' : '',
        fresh ? 'row-fresh' : '',
      ].filter(Boolean).join(' ')}
    >
      <td>
        {/* aria-label uses incidentIdentityLabel, not identity.name: since
            the workload leads, every sibling Pod of one Deployment renders
            the same name, and thirteen checkboxes all announcing "Select
            incident checkout-oom" would leave a screen-reader user unable to
            tell which row they are on. The observed Pod is the part that
            differs, so it is what the label adds back. */}
        <input
          type="checkbox"
          className="row-select-checkbox"
          aria-label={`Select incident ${incidentIdentityLabel(incident)}`}
          checked={selected}
          disabled={!eligible}
          title={
            eligible
              ? undefined
              : incident.state === 'Investigating'
                ? 'An investigation is currently running on this incident — wait for it to finish, then close it'
                : incident.state === 'Executing'
                  ? 'A remediation is currently executing on this incident — wait for it to finish, then close it'
                  : `Already ${STATE_LABEL[incident.state]}`
          }
          onChange={onToggleSelect}
        />
      </td>
      {/* `.severity-rule` reads the --sev-fill the <tr>'s
          `.sev-*` class set, and deliberately carries no
          padding of its own so it drops onto the cell padding
          `.list-table td:first-child` already provides. */}
      <td className="severity-rule">
        {/* `.identity-block` is the D7 vocabulary; the page's
            own `.incident-identity` stays alongside it for the
            two things the shared class does not define — the
            column's width behaviour and the link chrome
            (`.incident-identity > a`: no underline at rest, accent +
            underline on hover, --font-size-base per BUGS.md 73). The kind
            and fault lines are <div>s rather than the vocabulary's
            <span>s so they stay clear of `.incident-identity > span`,
            which is the nowrap treatment written for the single meta line
            this block replaces. */}
        <div className="incident-identity identity-block">
          {/* The SUBJECT's name leads — the owning workload where the
              agent resolved one, the object itself where it did not
              (B174). The fingerprint is still the row's true identity,
              but it is not what a human scanning this list is looking
              for, so it stays in the tooltip and on the detail page.
              The tooltip now leads with the workload key when there is
              one, because that is what the name above it came from. */}
          <Link
            className="identity-block-name"
            to={`/incidents/${incident.id}`}
            // The rendered name leads the tooltip now, because the cell
            // truncates to one line per fact (B178) and a name long enough to
            // be cut is exactly the one someone needs to read in full.
            title={[
              identity.name,
              incident.workloadKey ?? `${incident.objectGvk ?? ''} ${incident.objectNamespace ?? ''}`.trim(),
              `Fingerprint ${incident.fingerprint}`,
            ].filter(Boolean).join('\n')}
          >
            {identity.name}
          </Link>
          {/* title for the same reason as the name above: this line now
              truncates rather than wrapping, and `Deployment · prod-eu-1/a-long-namespace`
              is a realistic thing to cut. */}
          {identity.kind && <div className="identity-block-kind" title={identity.kind}>{identity.kind}</div>}
          {/* The fault line carries the observed Pod when the workload leads.
              Two facts in one tooltip now, and the order matters: the line's
              own text first, because it truncates to one line (B178), then —
              only when there is an observed object — the caveat that it may no
              longer exist. The caveat still travels with the fact
              (observedObjectTitle), never with the row. */}
          {faultLine && (
            <div
              className="identity-block-fault"
              title={[faultLine, observed ? observedObjectTitle(observed) : ''].filter(Boolean).join('\n')}
            >
              {faultLine}
            </div>
          )}
          {/* Severity and state as WORDS inside the identity cell, rendered
              only in the phone layout. There the table scrolls sideways and its
              own Severity and State columns start off-screen, which left the
              row's left rule — colour — as the only severity signal in view.
              aria-hidden because the real columns are still in the row for a
              screen reader; this is a visual repeat of them. */}
          {phoneLayout && (
          <div className="incident-narrow-facts" aria-hidden="true">
            <span className="severity-cell">
              <span className="severity-chip" />
              {SEVERITY_LABEL[incident.severity] ?? incident.severity}
            </span>
            <StateBadge state={incident.state} resolutionKind={incident.resolutionKind} />
          </div>
          )}
        </div>
      </td>
      <td>
        {/* `title` because `.incident-cluster-link` clips with an ellipsis at
            `max-width: clamp(12rem, 14vw, 26rem)` — 202px at 1440, and the
            seeded fixture's own name already measures 215px, so this is the
            ordinary case and not a narrow-viewport edge. Truncated text has to
            stay recoverable (reference/components.md, layout resilience), and
            this is the same affordance B178 kept on every line of the identity
            block two cells to the left. */}
        <Link
          className="incident-cluster-link"
          title={incident.clusterDisplayName}
          to={`/clusters/${incident.clusterId}`}
        >
          {incident.clusterDisplayName}
        </Link>
      </td>
      {/* The word, not a pill: the colour of this fact now
          lives on the row's left rule, and rendering it twice
          is what archetype A set out to remove. The word
          itself stays — a border is invisible to a screen
          reader, this column is what keeps the severity sort
          sortable, and lld/11-ui-design.md §8 forbids colour
          as the only signal. Plain cell text rather than
          `.text-muted`: in this table muted grey is what an
          UNAVAILABLE value looks like (the em dash in the
          clusters list), and a severity is neither
          unavailable nor a second headline. */}
      {/* Chip AND word. The chip makes the column scannable; the word is what
          carries the meaning, and removing it would be the colour-alone
          violation this codebase treats as safety-critical. The chip takes
          `--sev-fill` from the row, the same value the rule at the row's left
          edge reads, so the two marks for one severity cannot disagree. */}
      <td className="col-shrink">
        <span className="severity-cell">
          <span className="severity-chip" aria-hidden="true" />
          {SEVERITY_LABEL[incident.severity] ?? incident.severity}
        </span>
      </td>
      <td className="col-shrink incidents-state-cell">
        <StateBadge state={incident.state} resolutionKind={incident.resolutionKind} />
        {/* The amber row wash (.incident-row-attention) used to be the ONLY
            signal that a row needs a human — status carried by colour alone,
            which is the first entry on this codebase's own never-downgrade
            list and is invisible to anyone who cannot distinguish the tint,
            to a screen reader, and in a screenshot. design-lint does not
            catch it because it checks glyphs and token values, not a
            row-level background. The word carries the meaning now; the wash
            is reinforcement. */}
        {isAttentionIncident(incident) && (
          <span className="badge badge-amber" title="Open, and either awaiting a human decision or high/critical severity">
            Needs you
          </span>
        )}
      </td>
      <RouteCell route={incident.route} />
      <td className="col-numeric">
        <span
          className={incident.occurrenceCount > 1 ? 'incident-occurrence-count active' : 'incident-occurrence-count'}
          title={detectionCountTitle(incident.occurrenceCount)}
        >
          {incident.occurrenceCount}
        </span>
      </td>
      {/* First seen used to be the tail of the identity cell's
          meta line. It is a second timestamp rather than a
          column of its own, so it joins the one that is
          already here. */}
      <td
        className="col-time"
        title={`Last seen ${formatDateTime(incident.lastSeen)}\nFirst seen ${formatDateTime(incident.firstSeen)}`}
      >
        {formatRelativeTime(incident.lastSeen)}
      </td>
      <td className="col-shrink">
        {incident.fleetGroupId && (
          <span className="badge badge-blue" title="Also occurring on other clusters">Fleet-wide</span>
        )}
        {incident.fleetGroupId && (incident.workloadGroupId || incident.objectGroupId) ? ' ' : null}
        {incident.workloadGroupId && (
          <span className="badge badge-blue" title="Also occurring on other pods of the same workload">
            Same workload
          </span>
        )}
        {/* workloadGroupId/objectGroupId never coexist on one
            incident (workload_key and related_workload_key are
            mutually exclusive — see incidentSummary's own doc
            comment), so no separator is needed between these
            two specifically; fleetGroupId is independent of
            both and already spaced above. */}
        {incident.objectGroupId && (
          <span className="badge badge-blue" title="May be the same underlying outage as a failure on a related object">
            Related object
          </span>
        )}
      </td>
      <td className="incident-actions-cell table-pinned-actions">
        <ActionMenu
          ariaLabel={`Actions for incident ${incidentIdentityLabel(incident)}`}
          items={[
            { label: 'View details', onClick: () => onNavigate(`/incidents/${incident.id}`) },
            { label: 'Quick view', onClick: onQuickView },
            { label: 'View cluster', onClick: () => onNavigate(`/clusters/${incident.clusterId}`) },
          ]}
        />
      </td>
    </tr>
  )
}

// The parent of a collapsed sibling group: one row standing in for the N
// incidents internal/replicagroup joined by (workload_key, opening_reason) on
// one cluster. `screens.md` mode A's "collapse near-identical rows to the
// interesting few plus a count", applied to the case that actually produces
// them here — thirteen Pods of one Deployment, all CrashLoopBackOff.
//
// The honesty constraint that shaped every cell: a row standing in for 13
// incidents must not assert a single value for a field the 13 disagree about.
// workloadGroupSummary computes that once (see its doc comment); this
// component only renders it, and where the members disagree the cell says
// "Mixed" and the operator expands. Severity is the one deliberate
// aggregation — the WORST of the group, because that is the only summary
// that cannot under-state urgency.
function WorkloadGroupHeadRow({
  row,
  expanded,
  truncated,
  selectedIncidentIds,
  isBulkDismissEligible,
  onToggleExpanded,
  onToggleSelectGroup,
  onFilterToGroup,
  onNavigate,
}: {
  row: WorkloadGroupRow
  expanded: boolean
  truncated: boolean
  selectedIncidentIds: Set<string>
  isBulkDismissEligible: (incident: Incident) => boolean
  onToggleExpanded: () => void
  onToggleSelectGroup: () => void
  onFilterToGroup: () => void
  onNavigate: (to: string) => void
}) {
  const summary = workloadGroupSummary(row)
  const panelId = `workload-group-${row.groupId}`
  const eligible = row.incidents.filter(isBulkDismissEligible)
  const selectedCount = eligible.filter((incident) => selectedIncidentIds.has(incident.id)).length
  const stateBreakdown = summary.stateCounts
    .map(({ state, count }) => `${count} ${STATE_LABEL[state]}`)
    .join('\n')
  // The count is a floor when the fetch was capped: a sibling past the cap is
  // not in this array, so the group is at least this big. `.figure-partial` is
  // the mark this page already uses for exactly that claim.
  const memberLabel = `${summary.memberCount} incidents`

  return (
    <tr className={[SEVERITY_RULE_CLASS[summary.severity] ?? 'sev-neutral', summary.anyRequiresAction ? 'incident-row-attention' : ''].filter(Boolean).join(' ')}>
      <td>
        <input
          type="checkbox"
          className="row-select-checkbox"
          aria-label={`Select the ${summary.memberCount} incidents on ${summary.name}`}
          checked={eligible.length > 0 && selectedCount === eligible.length}
          ref={(el) => {
            if (el) el.indeterminate = selectedCount > 0 && selectedCount < eligible.length
          }}
          disabled={eligible.length === 0}
          title={eligible.length === 0 ? 'None of these incidents can be dismissed from their current state' : undefined}
          onChange={onToggleSelectGroup}
        />
      </td>
      <td className="severity-rule">
        {/* The chevron and the identity are ONE control, the same shape
            TolerationsPage's expandable leading cell uses — pressing the row's
            name is how a table row opens everywhere else in this app. The
            classes are the shared `.row-group-*` ones rather than that page's
            `.toleration-*`: borrowing another screen's page-scoped class is a
            named anti-pattern, and this is now the third place the pattern
            appears. */}
        <button
          type="button"
          className="row-group-toggle"
          aria-expanded={expanded}
          aria-controls={panelId}
          onClick={onToggleExpanded}
          title={`${summary.memberCount} incidents on this workload, one per pod — ${expanded ? 'collapse' : 'expand'}`}
        >
          <ChevronIcon direction="right" size={14} className="row-group-chevron" />
          <span className="row-group-body">
            <span className="incident-identity identity-block">
              <span className="identity-block-name">{summary.name}</span>
              {summary.kind && <span className="identity-block-kind">{summary.kind}</span>}
              {summary.fault && <span className="identity-block-fault">{summary.fault}</span>}
            </span>
            {/* The count is the whole claim this row makes, so it is text in
                the row rather than a tooltip: an operator must never have to
                hover to learn that one line is standing in for thirteen. It
                is INSIDE the button so it is part of the control's accessible
                name too — a screen reader announcing only "checkout,
                collapsed" would be told a row exists and not that twelve
                incidents are behind it. */}
            <span className="row-group-count">
              {memberLabel}
              {truncated && (
                <span className="figure-partial" aria-label="or more, this list was truncated">+</span>
              )}
              {' · one per pod'}
            </span>
          </span>
        </button>
      </td>
      <td>
        {/* Unanimous by construction: internal/replicagroup groups within ONE
            cluster, so there is no aggregation happening here. `title` for the
            same reason as the single-incident row above — this cell clips. */}
        <Link
          className="incident-cluster-link"
          title={summary.clusterDisplayName}
          to={`/clusters/${summary.clusterId}`}
        >
          {summary.clusterDisplayName}
        </Link>
      </td>
      <td className="col-shrink" title={summary.severityUnanimous ? undefined : `The worst of the ${summary.memberCount} — expand to see each one's own severity`}>
        {SEVERITY_LABEL[summary.severity] ?? summary.severity}
        {!summary.severityUnanimous && <span className="text-muted"> (worst)</span>}
      </td>
      <td className="col-shrink incidents-state-cell">
        {summary.state ? (
          <StateBadge state={summary.state} />
        ) : (
          <span className="text-muted" title={stateBreakdown}>
            {summary.stateCounts.length} states
          </span>
        )}
        {summary.anyRequiresAction && (
          <span className="badge badge-amber" title="At least one of these is awaiting a human decision, or is high/critical severity">
            Needs you
          </span>
        )}
      </td>
      {summary.route === null ? (
        <td className="col-shrink">
          <span className="text-muted" title="These incidents did not all resolve to the same route — expand to see each one's own">
            Mixed
          </span>
        </td>
      ) : (
        <RouteCell route={summary.route} />
      )}
      <td className="col-numeric">
        <span
          className={summary.detectionCount > 1 ? 'incident-occurrence-count active' : 'incident-occurrence-count'}
          title={`${summary.detectionCount} detector reports across these ${summary.memberCount} incidents since they opened`}
        >
          {summary.detectionCount}
        </span>
      </td>
      <td
        className="col-time"
        title={`Last seen ${formatDateTime(summary.lastSeen)} (the most recent of the ${summary.memberCount})\nFirst seen ${formatDateTime(summary.firstSeen)} (the oldest)`}
      >
        {formatRelativeTime(summary.lastSeen)}
      </td>
      <td className="col-shrink">
        {/* No "Same workload" badge here: that is what this row IS, and the
            count beside the name already says it. Repeating it would be the
            same fact twice on one row. Fleet-wide is a different claim and is
            true of the group when it is true of any member. */}
        {summary.anyFleetGroup && (
          <span className="badge badge-blue" title="At least one of these is also occurring on other clusters">Fleet-wide</span>
        )}
      </td>
      <td className="incident-actions-cell table-pinned-actions">
        <ActionMenu
          ariaLabel={`Actions for the ${summary.memberCount}-incident group on ${summary.name}`}
          items={[
            {
              // Not the same as expanding: this re-asks the SERVER for the
              // group (?workloadGroupId=), so it reaches members that fell
              // past this page's fetch cap, which expanding in place cannot.
              label: `Show only this workload's ${summary.memberCount} incidents`,
              onClick: onFilterToGroup,
            },
            { label: 'View cluster', onClick: () => onNavigate(`/clusters/${summary.clusterId}`) },
          ]}
        />
      </td>
    </tr>
  )
}

export function IncidentsPage() {
  const { accessToken } = useAuth()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  // The coalescing writer: a filter change followed by resetToFirstPage in the
  // same handler must compose. Two plain setSearchParams calls would let the
  // second, built from the stale params, erase the first.
  const [, writeParams] = useSearchParamsWriter()
  const fleetGroupFilter = searchParams.get('fleetGroupId') ?? ''
  const workloadGroupFilter = searchParams.get('workloadGroupId') ?? ''
  // objectGroupId (BACKLOG.md A3b) is the cross-object counterpart of the
  // two group filters above — reached from IncidentDetailPage's "related
  // object" callout the same way fleetGroupId/workloadGroupId are reached
  // from their own callouts/badges.
  const objectGroupFilter = searchParams.get('objectGroupId') ?? ''
  const clusterFilter = searchParams.get('clusterId') ?? ''
  const [quickViewIncident, setQuickViewIncident] = useState<Incident | null>(null)
  // Bulk selection (BUGS.md's owner note). Ids only, same reasoning as
  // ClustersPage's selectedClusterIds — this list refetches under the
  // selection, on every incident event.
  const [selectedIncidentIds, setSelectedIncidentIds] = useState<Set<string>>(new Set())
  const [bulkDismissing, setBulkDismissing] = useState(false)
  const canTriage = useHasCapability(CAP_INCIDENT_TRIAGE)
  // The cluster filter's choices. Same query key as every other cluster list,
  // so it is usually already cached. Without cluster:read the control stays,
  // disabled with that reason, and a ?clusterId= link still filters.
  const canReadClusters = useHasCapability(CAP_CLUSTER_READ)
  const clustersQuery = useQuery({
    queryKey: ['clusters'],
    queryFn: () => getClusters(accessToken!),
    enabled: !!accessToken && canReadClusters,
  })
  // The two filter axes (pages/incidentFilters.ts): the lifecycle status,
  // Open by default because that is what a person opening this page is asking
  // about, and severity. Both in the URL, so a copied link reproduces the view.
  const [statusView, setStatusView] = useUrlParam<StatusView>('status', DEFAULT_STATUS, STATUS_VIEWS)
  const [severityFilter, setSeverityFilter] = useUrlParam<Severity | ''>('severity', '', SEVERITY_FILTERS)
  // An old ?view= link (the overview's "Waiting on you" tile, a bookmark) is
  // rewritten once to the axes that replaced it.
  const legacyView = searchParams.get('view')
  useEffect(() => {
    const mapped = legacyViewParams(legacyView)
    if (!mapped) return
    writeParams((next) => {
      next.delete('view')
      if (mapped.status && mapped.status !== DEFAULT_STATUS) next.set('status', mapped.status)
      if (mapped.severity) next.set('severity', mapped.severity)
    })
  }, [legacyView, writeParams])
  const [search, setSearch] = useUrlParam<string>('q', '')
  // BACKLOG P10: search moved server-side (?search=), so every keystroke now
  // costs a request rather than a client-side array scan. debouncedSearch is
  // what actually reaches the query — `search` itself still updates the input
  // instantly, so typing feels the same, but the network call (and the
  // refetch it triggers) waits until typing pauses.
  const [debouncedSearch, setDebouncedSearch] = useState(search)
  useEffect(() => {
    const handle = setTimeout(() => setDebouncedSearch(search.trim()), 300)
    return () => clearTimeout(handle)
  }, [search])
  const [stateFilter, setStateFilter] = useUrlParam<IncidentState | ''>('state', '', STATE_FILTERS)
  const [sortKey, setSortKey] = useUrlParam<SortKey>('sort', 'lastSeen', SORT_KEYS)
  const [sortDirection, setSortDirection] = useUrlParam<SortDirection>('dir', 'desc', SORT_DIRECTIONS)

  const incidentsQuery = useQuery({
    queryKey: [
      'incidents',
      {
        fleetGroupId: fleetGroupFilter || undefined,
        workloadGroupId: workloadGroupFilter || undefined,
        objectGroupId: objectGroupFilter || undefined,
        clusterId: clusterFilter || undefined,
        // The state dropdown used to narrow the ALREADY-FETCHED page,
        // so on a truncated response it hid rows this page held while
        // matching rows sat past the cap — "no incidents in this state" over
        // a prefix, indistinguishable from "none exist". ?state= is a
        // parameter the endpoint has always accepted (incidentScopeFilter in
        // internal/api/incidents.go), so it belongs in the request; being in
        // the queryKey too is what makes changing it REFETCH rather than
        // re-filter the stale page.
        state: stateFilter || undefined,
        severity: severityFilter || undefined,
        status: statusView === 'all' ? undefined : statusView,
        search: debouncedSearch || undefined,
        sortKey,
        sortDirection,
      },
    ],
    queryFn: () =>
      getIncidents(
        accessToken!,
        clusterFilter || undefined,
        stateFilter || undefined,
        fleetGroupFilter || undefined,
        workloadGroupFilter || undefined,
        debouncedSearch || undefined,
        sortKey,
        sortDirection,
        objectGroupFilter || undefined,
        severityFilter || undefined,
        statusView === 'all' ? undefined : statusView,
      ),
    // IncidentUpdated refreshes every ['incidents'] key, filtered variants
    // included (realtime/refresh.ts) — this is the fallback under it.
    refetchInterval: LIVE_FALLBACK_MS,
    // BACKLOG P10: search/sort now each mint a distinct queryKey, so without
    // this every debounced keystroke and every header click would flash the
    // whole table (and the quick-view counts) to the loading skeleton —
    // components.md's Skeleton is right for the FIRST load, but re-showing it
    // on every sort click would be a worse interaction than the client-side
    // re-sort it replaced. Keeping the previous page rendered while the new
    // one loads (isFetching still flips "Live" to "Updating…" above) matches
    // the "no layout jump" reasoning the Skeleton rule itself is based on.
    placeholderData: keepPreviousData,
    enabled: !!accessToken,
  })

  // CI-U8: rows a live refresh brought in while the reader is scrolled down
  // the list are held back behind a "N new — show" bar rather than shifting
  // every row under them.
  const listAnchorRef = useRef<HTMLElement | null>(null)
  const arrivals = useNewArrivals({
    rows: incidentsQuery.data?.incidents ?? NO_INCIDENTS,
    scope: JSON.stringify(incidentsQuery.data ? [clusterFilter, fleetGroupFilter, workloadGroupFilter, objectGroupFilter, stateFilter, severityFilter, statusView, debouncedSearch, sortKey, sortDirection] : null),
    settled: !!incidentsQuery.data && !incidentsQuery.isPlaceholderData,
    anchorRef: listAnchorRef,
  })
  const freshIds = useFreshIds()
  const incidents = arrivals.visible
  // The endpoint is bounded (?limit=), so this array can be a PREFIX of the
  // matching set. Every filter, the search and the sort run on the server over
  // the whole set, so a truncated list is incomplete but never wrong, and the
  // counts below are exact regardless.
  const truncated = !!incidentsQuery.data?.nextCursor
  const breakdown = incidentsQuery.data?.breakdown
  // What this view matches across the whole set; undefined (a dash, never a
  // fabricated zero) until the server has answered.
  const matchingCount = countFor(breakdown, statusView, severityFilter)
  // Everything in the scope (cluster, group, search, state) at all, used to
  // tell "nothing exists" from "nothing in this view".
  const scopeTotal = countFor(breakdown, 'all', '')
  const filteredIncidents = [...incidents]
  // No client-side .sort() here any more (BACKLOG P10): `incidents` already
  // arrives in ?sort=/?direction= order from the server, and .filter() above
  // preserves that relative order, so the rows this page renders are sorted
  // exactly as requested without re-deriving the comparator client-side.

  // --- Workload sibling collapse (the review's item 15) ---
  //
  // 52 of the development database's 225 incidents carry a workloadGroupId, in
  // four groups of thirteen: thirteen Pods of one Deployment, one incident
  // each, thirteen consecutive near-identical rows. Collapsed by default to
  // one row per workload, expandable inline.
  //
  // NOT collapsed when ?workloadGroupId= is the active scope: arriving from a
  // "Same workload" link is an explicit request for the members, and folding
  // them back up would make that link do nothing visible.
  //
  // The count the page's own header reports is unaffected — it counts
  // INCIDENTS (`incidents.length`), and collapsing changes how many rows
  // render, never how many incidents there are. The row/incident difference is
  // stated in the toolbar's result count below rather than left for the
  // operator to notice.
  const collapseSiblings = !workloadGroupFilter
  const [expandedParam, setExpandedParam] = useUrlParam<string>('expanded', '')
  const expandedGroups = new Set(expandedParam ? expandedParam.split(',') : [])
  const listRows: IncidentListRow[] = collapseSiblings
    ? collapseWorkloadSiblings(filteredIncidents)
    : filteredIncidents.map((incident) => ({ kind: 'incident', key: incident.id, incident }))
  const collapsedIncidentCount = listRows.reduce(
    (total, row) => total + (row.kind === 'workloadGroup' ? row.incidents.length : 0),
    0,
  )
  const collapsedGroupCount = listRows.filter((row) => row.kind === 'workloadGroup').length

  const { visibleItems: visibleRows, resetToFirstPage: resetPageOnly, pagination } = useUrlPagination(listRows)
  // Every incident the rows on this page stand for, collapsed groups included.
  // Bulk selection counts INCIDENTS, not rows — "select all on this page" that
  // silently skipped the members of a collapsed group would under-select by
  // twelve without saying so, and BulkActionBar's own count would then disagree
  // with what the operator thought they had picked.
  const visibleIncidents = visibleRows.flatMap((row) => (row.kind === 'incident' ? [row.incident] : row.incidents))

  const toggleGroupExpanded = (groupID: string) => {
    setExpandedParam((current) => {
      const next = new Set(current ? current.split(',') : [])
      if (next.has(groupID)) next.delete(groupID)
      else next.add(groupID)
      return [...next].join(',')
    })
  }

  // CI-U6: j/k step through the rows on this page in display order (a
  // group's members only while it is expanded); Enter on a focused row opens
  // the incident, or toggles a group.
  const navTargets: Array<{ key: string; open: () => void }> = []
  for (const row of visibleRows) {
    if (row.kind === 'incident') {
      navTargets.push({ key: row.incident.id, open: () => navigate(`/incidents/${row.incident.id}`) })
    } else {
      navTargets.push({ key: row.key, open: () => toggleGroupExpanded(row.groupId) })
      if (expandedGroups.has(row.groupId)) {
        for (const incident of row.incidents) navTargets.push({ key: incident.id, open: () => navigate(`/incidents/${incident.id}`) })
      }
    }
  }
  const navIndex = new Map(navTargets.map((t, i) => [t.key, i]))
  const rowNav = useRowNavigation({
    count: navTargets.length,
    onOpen: (i) => navTargets[i]?.open(),
    enabled: true,
  })

  // Wraps usePagination's own resetToFirstPage so every existing filter/
  // search/quick-view/sort call site also clears the bulk selection — see
  // ClustersPage's identical wrapper for why. Explicit page navigation
  // (TablePagination's onPageChange) does not go through this.
  const resetToFirstPage = () => {
    resetPageOnly()
    setSelectedIncidentIds(new Set())
  }

  // Re-asks the SERVER for this group rather than expanding in place, so it
  // reaches members that fell past the fetch cap. Sets the same
  // ?workloadGroupId= the detail page's "Same workload" callout already uses,
  // which also turns collapsing off (see collapseSiblings above).
  const filterToWorkloadGroup = (groupID: string) => {
    writeParams((next) => next.set('workloadGroupId', groupID))
    resetToFirstPage()
  }

  // Selecting a collapsed parent selects (or clears) every eligible member —
  // the row stands for them, so the checkbox has to act on them.
  const toggleGroupSelected = (row: WorkloadGroupRow) => {
    const eligible = row.incidents.filter(isBulkDismissEligible)
    const allSelected = eligible.length > 0 && eligible.every((incident) => selectedIncidentIds.has(incident.id))
    setSelectedIncidentIds((current) => {
      const next = new Set(current)
      for (const incident of eligible) {
        if (allSelected) next.delete(incident.id)
        else next.add(incident.id)
      }
      return next
    })
  }

  const changeSort = (nextKey: SortKey) => {
    if (sortKey === nextKey) {
      setSortDirection((current) => (current === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortKey(nextKey)
      setSortDirection(
        nextKey === 'severity' || nextKey === 'occurrences' || nextKey === 'lastSeen' ? 'desc' : 'asc',
      )
    }
    resetToFirstPage()
  }

  const setClusterFilter = (clusterId: string) => {
    writeParams((next) => {
      if (clusterId) next.set('clusterId', clusterId)
      else next.delete('clusterId')
    })
    resetToFirstPage()
  }


  // The toolbar's cluster <select>. A ?clusterId=
  // that is not in the list — an archived cluster reached from an old link —
  // still shows as the selected value rather than reading as "All clusters".
  const clusterOptions = clustersQuery.data?.clusters ?? []
  const clusterFilterField = (
    <label className="list-filter-field incidents-cluster-filter">
      <span className="visually-hidden">Filter by cluster</span>
      <select
        value={clusterFilter}
        onChange={(event) => setClusterFilter(event.target.value)}
        disabled={!canReadClusters}
        title={canReadClusters ? undefined : missingCapabilityMessage([CAP_CLUSTER_READ])}
      >
        <option value="">All clusters</option>
        {clusterFilter && !clusterOptions.some((c) => c.id === clusterFilter) && (
          <option value={clusterFilter}>Cluster {clusterFilter}</option>
        )}
        {clusterOptions.map((cluster) => (
          <option key={cluster.id} value={cluster.id}>
            {cluster.displayName}
          </option>
        ))}
      </select>
    </label>
  )

  // The group chip's ×: drops the fleet/workload/object group but keeps the
  // cluster choice, which has its own control now.
  const clearGroupFilter = () => {
    writeParams((next) => {
      next.delete('fleetGroupId')
      next.delete('workloadGroupId')
      next.delete('objectGroupId')
    })
    resetToFirstPage()
  }


  const clearScopeFilter = () => {
    writeParams((next) => {
      next.delete('fleetGroupId')
      next.delete('workloadGroupId')
      next.delete('objectGroupId')
      next.delete('clusterId')
    })
    resetToFirstPage()
  }


  const clearFilters = () => {
    setStatusView(DEFAULT_STATUS)
    setSeverityFilter('')
    setSearch('')
    // Clearing is an explicit action, not a keystroke — it should take effect
    // immediately rather than wait out the debounce above.
    setDebouncedSearch('')
    setStateFilter('')
    if (fleetGroupFilter || workloadGroupFilter || objectGroupFilter || clusterFilter) clearScopeFilter()
    resetToFirstPage()
  }

  // An incident already Investigating/Executing/Resolved/Dismissed 409s
  // from handleDismissIncident — excluded from selection entirely, with its
  // checkbox disabled and titled, rather than silently included and left to
  // fail with no explanation.
  const isBulkDismissEligible = (incident: Incident) => !DISMISS_INELIGIBLE_STATES.includes(incident.state)
  const eligibleVisibleIncidents = visibleIncidents.filter(isBulkDismissEligible)
  const allVisibleEligibleSelected =
    eligibleVisibleIncidents.length > 0 &&
    eligibleVisibleIncidents.every((incident) => selectedIncidentIds.has(incident.id))
  const someVisibleEligibleSelected = eligibleVisibleIncidents.some((incident) => selectedIncidentIds.has(incident.id))

  const toggleIncidentSelected = (incidentId: string) => {
    setSelectedIncidentIds((current) => {
      const next = new Set(current)
      if (next.has(incidentId)) next.delete(incidentId)
      else next.add(incidentId)
      return next
    })
  }

  const toggleSelectAllVisible = () => {
    setSelectedIncidentIds((current) => {
      const next = new Set(current)
      if (allVisibleEligibleSelected) {
        for (const incident of eligibleVisibleIncidents) next.delete(incident.id)
      } else {
        for (const incident of eligibleVisibleIncidents) next.add(incident.id)
      }
      return next
    })
  }

  const selectedIncidents = incidents.filter((incident) => selectedIncidentIds.has(incident.id))

  // BACKLOG P10: `incidents` is now the SERVER-searched set, so an active
  // ?search= can legitimately bring back zero rows without the fleet being
  // empty — debouncedSearch has to gate the true-empty-state check below the
  // same way the scope filters already do, or a search with no matches
  // would render "the fleet is quiet," which is a different and false claim.
  const scopeFiltered = !!fleetGroupFilter || !!workloadGroupFilter || !!objectGroupFilter || !!clusterFilter || !!debouncedSearch || !!stateFilter
  // Nothing exists at all, in any state: the one case for the page-level empty
  // state. "Nothing open" is not it, and neither is a filter matching nothing.
  const fleetQuiet = !incidentsQuery.isError && scopeTotal === 0 && !scopeFiltered
  const showList = !incidentsQuery.isError && !fleetQuiet
  const filtersAreDefault = statusView === DEFAULT_STATUS && !severityFilter && !scopeFiltered
  const stateOptions = statesFor(statusView, ALL_INCIDENT_STATES)

  return (
    <div className="page list-page incidents-page">
      <header className="page-header list-page-header">
        <div>
          <h1>Incidents</h1>
          {/* The page's most prominent number counts the rows that ARRIVED,
               not the rows that match — so on a truncated fetch it carries
               `.figure-partial` like every other figure derived from it
               (anti-patterns.md: the caveat travels with the number). Not
               swapped for the exact `counts.all`: that number is already on
               the All tab, and one total in two places is its own named
               failure. ListFreshness owns the "Live"-only-when-it-is and
               never-a-fabricated-zero rules, so this header cannot drift from
               Clusters' or Overview's. */}
          <ListFreshness
            isError={incidentsQuery.isError}
            isFetching={incidentsQuery.isFetching}
            updatedAt={incidentsQuery.dataUpdatedAt}
            hasData={incidentsQuery.data !== undefined}
            count={incidents.length}
            countLabel={incidents.length === 1 ? 'incident' : 'incidents'}
            countSuffix={
              truncated ? (
                <span className="figure-partial" aria-label="or more, this list was truncated">+</span>
              ) : null
            }
          />
        </div>
        {/* A cluster-only scope is shown by the toolbar's cluster select, so the
            header badge marks only the group scopes, which have no control. */}
        {(fleetGroupFilter || workloadGroupFilter || objectGroupFilter) && (
          <span className="badge badge-blue incidents-header-scope">
            {fleetGroupFilter ? 'Fleet-wide group' : workloadGroupFilter ? 'Same workload' : 'Related object'}
          </span>
        )}
      </header>
      <IncidentsSectionTabs />

      {incidentsQuery.isError && (
        <p className="form-error" role="alert">
          {incidentsQuery.error instanceof ApiError
            ? incidentsQuery.error.detail
              ? `${incidentsQuery.error.message} — ${incidentsQuery.error.detail}`
              : incidentsQuery.error.message
            : 'Failed to load incidents.'}
        </p>
      )}

      {fleetQuiet && <EmptyState variant="incidents">No incidents yet — the fleet is quiet.</EmptyState>}

      {showList && (
        <>

          {truncated && (
            <p className="truncation-notice" role="status">
              Showing the first {incidents.length} of {matchingCount ?? 'more'} matching incidents. The filters, the
              search and the sort run on the server, so these are the first rows of the whole set and every count is
              exact; a narrower filter reaches the rest.
              {collapsedGroupCount > 0 && (
                <>
                  {' '}
                  Sibling-pod rows are collapsed over these {incidents.length} too, so a collapsed row&apos;s
                  count is a floor — its own action re-asks the server for the whole workload.
                </>
              )}
            </p>
          )}

          {arrivals.heldCount > 0 && (
            <div className="fleet-new-bar" role="status">
              <button type="button" onClick={arrivals.showHeld}>
                {arrivals.heldCount} new {arrivals.heldCount === 1 ? 'incident' : 'incidents'} — show
              </button>
            </div>
          )}
          <section className="list-card incidents-list-card" aria-label="Incident list" ref={listAnchorRef}>
            <div className="list-toolbar incidents-toolbar">
              {/* The lifecycle status, the list's primary axis, as tabs at the
                  start of its one filter bar. Each count is what that tab would
                  show under every other active filter (incidentFilters.ts). */}
              <nav className="list-quick-views list-quick-views-inbar" aria-label="Incident status">
                {STATUS_VIEWS.map((value) => (
                  <button
                    key={value}
                    type="button"
                    className={statusView === value ? 'active' : ''}
                    aria-pressed={statusView === value}
                    title={STATUS_HINT[value]}
                    onClick={() => {
                      setStatusView(value)
                      // A state outside the new status would match nothing.
                      if (stateFilter && !statesFor(value, ALL_INCIDENT_STATES).includes(stateFilter)) setStateFilter('')
                      resetToFirstPage()
                    }}
                  >
                    {STATUS_LABEL[value]}
                    <span className="list-quick-count">{countFor(breakdown, value, severityFilter) ?? '—'}</span>
                  </button>
                ))}
              </nav>

              <label className="list-search-field incidents-search-field">
                <span className="visually-hidden">Search incidents</span>
                <SearchIcon />
                <input
                  type="search"
                  placeholder="Search incidents"
                  title="Matches the object, reason, cluster or fingerprint"
                  value={search}
                  onChange={(event) => {
                    setSearch(event.target.value)
                    resetToFirstPage()
                  }}
                />
              </label>

              {/* A deliberate second line: status and search, then the
                  dropdowns that narrow within it. Five tabs and three
                  dropdowns do not fit one line at 1440px, and an accidental
                  wrap stranded the last dropdown on a row of its own. */}
              <span className="list-toolbar-break" aria-hidden="true" />

              <label className="list-filter-field incidents-severity-filter">
                <span className="visually-hidden">Filter by severity</span>
                <select
                  value={severityFilter}
                  onChange={(event) => {
                    setSeverityFilter(event.target.value as Severity | '')
                    resetToFirstPage()
                  }}
                >
                  <option value="">All severities</option>
                  {SEVERITIES.map((severity) => {
                    const n = countFor(breakdown, statusView, severity)
                    return (
                      <option key={severity} value={severity}>
                        {SEVERITY_FILTER_LABEL[severity]}
                        {n === undefined ? '' : ` (${n})`}
                      </option>
                    )
                  })}
                </select>
              </label>

              <label className="list-filter-field incidents-state-filter">
                <span className="visually-hidden">Filter by state</span>
                <select
                  value={stateFilter}
                  onChange={(event) => {
                    setStateFilter(event.target.value as IncidentState | '')
                    resetToFirstPage()
                  }}
                >
                  <option value="">{statusView === 'all' ? 'All states' : `Any ${STATUS_LABEL[statusView].toLowerCase()} state`}</option>
                  {stateOptions.map((state) => (
                    <option key={state} value={state}>{STATE_LABEL[state]}</option>
                  ))}
                </select>
              </label>

              {clusterFilterField}

              {(fleetGroupFilter || workloadGroupFilter || objectGroupFilter) && (
                <span className="incidents-scope-filter">
                  {fleetGroupFilter
                    ? 'Fleet-wide group'
                    : workloadGroupFilter
                      ? 'Same workload'
                      : objectGroupFilter
                        ? 'Related object'
                        : null}
                  <button
                    type="button"
                    onClick={clearGroupFilter}
                    aria-label="Clear incident group filter"
                    title="Clear incident group filter"
                  >
                    ×
                  </button>
                </span>
              )}

              {/* The count is INCIDENTS matching this view across the whole
                  set (the server's breakdown), so it is exact even when the
                  rows below are a truncated prefix — no "at least" mark. When
                  sibling pods are collapsed, that is said beside it rather than
                  left for the operator to discover. */}
              {!filtersAreDefault && (
                <button type="button" className="link-button incidents-clear-filters" onClick={clearFilters}>
                  Clear filters
                </button>
              )}

              <span className="list-result-count" aria-live="polite">
                {matchingCount ?? '—'} matching {matchingCount === 1 ? 'incident' : 'incidents'}
                {collapsedGroupCount > 0 && (
                  <>
                    {' '}
                    <span
                      className="text-muted"
                      title={`${collapsedIncidentCount} of the rows on this page are sibling pods of ${collapsedGroupCount} ${collapsedGroupCount === 1 ? 'workload' : 'workloads'}, collapsed into one row each. Expand a row, or use its "show only this workload" action, to see them individually.`}
                    >
                      ({collapsedIncidentCount} collapsed into {collapsedGroupCount}{' '}
                      {collapsedGroupCount === 1 ? 'workload row' : 'workload rows'})
                    </span>
                  </>
                )}
              </span>
            </div>

            <BulkActionBar
              count={selectedIncidentIds.size}
              itemLabel="incident"
              onClear={() => setSelectedIncidentIds(new Set())}
              actions={[
                {
                  label: 'Dismiss…',
                  onClick: () => setBulkDismissing(true),
                  disabled: !canTriage,
                  disabledReason: canTriage ? undefined : `Missing capability: ${CAP_INCIDENT_TRIAGE}`,
                  danger: true,
                },
              ]}
            />

            <div className="table-scroll">
              <table className="cluster-table list-table incidents-table scan-table" aria-busy={incidentsQuery.isLoading}>
                <thead>
                  <tr>
                    {/* Selection itself is harmless for a viewer without
                        incident:triage — only the Dismiss… action above is
                        capability-gated (lld/11 §6's disabled-not-hidden
                        rule is about the action, not the checkbox). */}
                    <th className="list-select-heading">
                      <input
                        type="checkbox"
                        className="row-select-checkbox"
                        aria-label="Select all eligible incidents on this page"
                        checked={allVisibleEligibleSelected}
                        ref={(el) => {
                          if (el) el.indeterminate = someVisibleEligibleSelected && !allVisibleEligibleSelected
                        }}
                        disabled={eligibleVisibleIncidents.length === 0}
                        title={eligibleVisibleIncidents.length === 0 ? 'No eligible incidents on this page' : undefined}
                        onChange={toggleSelectAllVisible}
                      />
                    </th>
                    {/* `.col-identity` is what makes this the column surplus
                        width goes to (index.css) — identity is what an
                        operator scans for, and it was measuring NARROWER than
                        the State column, which holds two fixed-vocabulary
                        pills. */}
                    <SortableHeader label="Incident" sortKey="failure" activeKey={sortKey} direction={sortDirection} onSort={changeSort} className="col-identity" />
                    <SortableHeader label="Cluster" sortKey="cluster" activeKey={sortKey} direction={sortDirection} onSort={changeSort} />
                    <SortableHeader label="Severity" sortKey="severity" activeKey={sortKey} direction={sortDirection} onSort={changeSort} className="col-shrink" />
                    <SortableHeader label="State" sortKey="state" activeKey={sortKey} direction={sortDirection} onSort={changeSort} className="col-shrink" />
                    {/* Route has no sort key, for the same reason Scope has
                        none: the endpoint's ?sort= vocabulary is a closed set
                        (internal/api/incidents.go's incidentSortSpecs) and
                        route is not in it, so a clickable header here would
                        either 400 or sort the page rather than the set —
                        the exact client-side-sort-of-a-paginated-list this
                        page already refuses to do. */}
                    <th className="col-shrink">Route</th>
                    <SortableHeader label={DETECTION_COUNT_HEADER} sortKey="occurrences" activeKey={sortKey} direction={sortDirection} onSort={changeSort} className="col-numeric" />
                    <SortableHeader label="Last seen" sortKey="lastSeen" activeKey={sortKey} direction={sortDirection} onSort={changeSort} className="col-time" />
                    {/* Scope has no sort key — it is a per-row flag, not an
                        ordering. It was previously three words buried in the
                        identity cell's meta line, which the identity block no
                        longer has room for; archetype A gives it a column. */}
                    <th className="col-shrink">Scope</th>
                    <th className="list-actions-heading table-pinned-actions"><span className="visually-hidden">Actions</span></th>
                  </tr>
                </thead>
                <tbody {...rowNav.containerProps}>
                  {incidentsQuery.isLoading && <SkeletonTableRows columns={10} />}
                  {!incidentsQuery.isLoading && visibleRows.map((row) => {
                    if (row.kind === 'incident') {
                      return (
                        <IncidentRow
                          key={row.key}
                          incident={row.incident}
                          selected={selectedIncidentIds.has(row.incident.id)}
                          eligible={isBulkDismissEligible(row.incident)}
                          onToggleSelect={() => toggleIncidentSelected(row.incident.id)}
                          onQuickView={() => setQuickViewIncident(row.incident)}
                          onNavigate={navigate}
                          navProps={rowNav.rowProps(navIndex.get(row.incident.id) ?? 0)}
                          fresh={freshIds.has(row.incident.id)}
                        />
                      )
                    }
                    const expanded = expandedGroups.has(row.groupId)
                    return (
                      <Fragment key={row.key}>
                        <WorkloadGroupHeadRow
                          row={row}
                          expanded={expanded}
                          truncated={truncated}
                          selectedIncidentIds={selectedIncidentIds}
                          isBulkDismissEligible={isBulkDismissEligible}
                          onToggleExpanded={() => toggleGroupExpanded(row.groupId)}
                          onToggleSelectGroup={() => toggleGroupSelected(row)}
                          onFilterToGroup={() => filterToWorkloadGroup(row.groupId)}
                          onNavigate={navigate}
                        />
                        {expanded &&
                          row.incidents.map((incident) => (
                            <IncidentRow
                              key={incident.id}
                              incident={incident}
                              child
                              selected={selectedIncidentIds.has(incident.id)}
                              eligible={isBulkDismissEligible(incident)}
                              onToggleSelect={() => toggleIncidentSelected(incident.id)}
                              onQuickView={() => setQuickViewIncident(incident)}
                              onNavigate={navigate}
                              navProps={rowNav.rowProps(navIndex.get(incident.id) ?? 0)}
                              fresh={freshIds.has(incident.id)}
                            />
                          ))}
                      </Fragment>
                    )
                  })}
                </tbody>
              </table>
            </div>

            {!incidentsQuery.isLoading && filteredIncidents.length === 0 && (
              <div className="list-filter-empty">
                {statusView === 'open' && !severityFilter && !scopeFiltered ? (
                  // The default view, empty: nothing is open, which is good
                  // news rather than a filter to undo.
                  <>
                    <strong>Nothing is open</strong>
                    <span>
                      Every incident in this scope is closed
                      {scopeTotal !== undefined ? ` (${scopeTotal} in all)` : ''}.
                    </span>
                    <button type="button" className="secondary" onClick={() => { setStatusView('closed'); resetToFirstPage() }}>
                      Show closed
                    </button>
                  </>
                ) : (
                  <>
                    <strong>No incidents match this view</strong>
                    <span>
                      {fleetGroupFilter
                        ? 'This fleet-wide group has no member incidents in this view.'
                        : workloadGroupFilter
                          ? 'This workload group has no member incidents in this view.'
                          : objectGroupFilter
                            ? 'This related-object group has no member incidents in this view.'
                            : 'Try another status, a different search, or clear the filters.'}
                    </span>
                    <button type="button" className="secondary" onClick={clearFilters}>Clear filters</button>
                  </>
                )}
              </div>
            )}

            <TablePagination {...pagination} truncated={truncated} />
          </section>
        </>
      )}

      {quickViewIncident && (
        <IncidentQuickView incident={quickViewIncident} onClose={() => setQuickViewIncident(null)} />
      )}
      {bulkDismissing && (
        // incidentIdentityLabel for the same reason the row checkbox uses it:
        // a confirmation list naming thirteen distinct incidents
        // "checkout-oom" is not a confirmation of anything.
        <ConfirmBulkDismissModal
          incidents={selectedIncidents.map((incident) => ({ id: incident.id, label: incidentIdentityLabel(incident) }))}
          onCancel={() => setBulkDismissing(false)}
          onDone={(dismissedIds) => {
            setBulkDismissing(false)
            setSelectedIncidentIds((prev) => {
              const next = new Set(prev)
              for (const id of dismissedIds) next.delete(id)
              return next
            })
          }}
        />
      )}
    </div>
  )
}
