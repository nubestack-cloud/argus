import { Fragment, useEffect, useMemo, useState } from 'react'
import type { FormEvent, MouseEvent as ReactMouseEvent } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { ApiError, getClusters, getFindings } from '../api/client'
import type {
  FindingClass,
  FindingConfidence,
  FindingDisposition,
  FindingFilters,
  FindingImpact,
  FindingListItem,
  FindingPromotionRule,
  FindingSuppressionReason,
} from '../api/client'
import { CAP_AUDIT_READ, CAP_CLUSTER_READ, CAP_INCIDENT_READ } from '../api/capabilities'
import { missingCapabilityMessage } from '../api/capabilityInfo'
import { useAuth } from '../auth/useAuth'
import { useHasCapability } from '../auth/useCapabilities'
import { EmptyState } from '../components/EmptyState'
import { HelpTip } from '../components/HelpTip'
import { ListFreshness } from '../components/ListFreshness'
import { LIVE_FALLBACK_MS } from '../realtime/refresh'
import { FilterIcon, SearchIcon } from '../components/icons'
import { SkeletonTableRows } from '../components/Skeleton'
import { SEVERITY_LABEL } from '../utils/incidents'
import { formatDateTime, formatRelativeTime, fromDatetimeLocalValue, toDatetimeLocalValue } from '../utils/time'
import { Quantity } from '../components/Quantity'
import { splitGVK, withObjectPanel, type ObjectRef } from '../insight/panelUrl'
import { collapseSignals, pageIsWholeSet, readableSignalReason, type SignalRow } from '../fleet/signalsGrouping'
import { useRowNavigation } from '../fleet/useRowNavigation'
import { IncidentsSectionTabs } from '../components/IncidentsSectionTabs'

// PROJECT.md F31 — the visible half of GET /api/v1/findings
// (internal/api/findings.go).
//
// # Why this screen exists
//
// internal/gateway/promotion.go deliberately keeps risks and unverified
// anomalies as findings that never become incidents. Until this page existed,
// a finding appeared in the product only nested inside an incident that had
// already been opened: an operator could see everything ARGUS RAISED and
// nothing it noticed and chose not to raise. In a detection product that gap
// is the whole trust question, and it is the first one a sceptical SRE asks.
//
// So the screen's job is not "list a table". It is to make three things
// legible at once: what was observed, what ARGUS did with each observation,
// and — the part a list alone cannot carry — the rule that decided, plus what
// this list is structurally unable to show.
//
// # Design plan (argus-design-system, pass 1)
//
// MODE A, triage scan (reference/screens.md), with mode F's two distinct
// empty states. This is the fourth member of the incident-list/cluster-list/
// audit-log family and is literally the pre-incident half of the first: many
// rows, the operator hunting for the one that matters. So the leading cell is
// identity and never a coloured pill, severity is the row rule PLUS the word,
// the list is server-paginated and every filter is a query parameter, and
// counts come from the server's own aggregate rather than from the page.
//
// NOT mode D. The four disposition counts are real and exact, and the obvious
// thing to do with them is a four-tile row across the top — which is the
// named four-KPI ban, and invariant to the subject (every dashboard ever has
// total/assigned/unassigned/archived). They are rendered as the quick-view
// tab strip instead, where the count is also the control that re-scopes the
// server query. A count you can click to narrow to is doing work; a tile is
// not.
//
// # The three honesty obligations this screen carries
//
//  1. THE WINDOW. ?since= defaults to 7 days rather than meaning "all", and
//     the counts are scoped to it. The resolved window comes back in
//     `window`, and it is rendered from THAT rather than from the filter
//     inputs — otherwise the page would state the range it asked for, which
//     on a default load is nothing at all.
//  2. notRecorded. Three drop dispositions return from handleFinding before
//     any row is inserted, so those findings are in no table and appear at no
//     filter setting. A surface that exists to answer "what did you see and
//     not tell me" and silently omits them is worse than no surface, so the
//     clause is rendered at the same weight as the rule it qualifies —
//     .verification-chip-neutral beside .verification-chip, which is exactly
//     what that pair of primitives is for.
//  3. SUPPRESSED, AND (USUALLY NOW) WHY. A suppressed row cleared the
//     boundary and still has no incident, which exactly two things cause: a
//     toleration, or storm protection. Migration 000124 (PROJECT.md F31)
//     started recording which, at write time, onto the row itself — but only
//     going forward; it is never backfilled. So `finding.suppressionReason`
//     is shown when present, and a suppressed row still missing it (written
//     before the migration) keeps the old behaviour: say so plainly and point
//     at the audit log, where both paths have always written an event naming
//     the toleration or the storm window. Never guess which one from context.

// How often the list re-reads, as the FALLBACK safety net underneath the
// live event — realtime/refresh.ts's standing preference, same as every
// other list. PROJECT.md F31 closed the gap this page used to carry here:
// internal/gateway/finding.go's handleFinding now publishes FindingRecorded
// (internal/events' lighter-weight sibling to IncidentUpdated) for every
// finding it durably records, including retained and suppressed rows that
// touch no incident — see EVENT_REFRESHES.FindingRecorded. LIVE_FALLBACK_MS
// directly, not a locally-named copy of it, so this page cannot silently
// diverge from the app's one polling floor.
const SIGNALS_POLL_MS = LIVE_FALLBACK_MS

// One server page. Deliberately well under the route's 200 default and 1000
// cap: nothing on this screen filters or counts client-side, so the page size
// only has to be a page.
const PAGE_SIZE = 50

// `.sev-*` goes on the <tr> because those classes only set --sev-fill /
// --sev-tint custom properties, which inherit — so the `.severity-rule` cell
// at the row's left edge and the `.severity-chip` in the severity cell read
// one value and cannot disagree. Same shape as IncidentsPage/ClusterDetailPage.
const SEVERITY_RULE_CLASS: Record<string, string> = {
  low: 'sev-low',
  medium: 'sev-medium',
  high: 'sev-high',
  critical: 'sev-critical',
}

// The readable label for each wire disposition, plus the badge that carries
// it. components.md: never render a raw API identifier as a user-facing
// value. The raw word is still reachable — it is on each badge's title, and
// it is the value the ?disposition= filter sends — because
// internal/api/findings.go spells `retained_unpromoted` to match the
// argus_findings_processed_total label byte-for-byte on purpose, so an
// operator holding a Prometheus graph next to this page needs to be able to
// join the two.
//
// Colour is never the carrier here: every badge holds its own word.
const DISPOSITION_LABEL: Record<FindingDisposition, string> = {
  correlated: 'Raised',
  retained_unpromoted: 'Recorded, not raised',
  suppressed: 'Suppressed',
}

const DISPOSITION_BADGE_CLASS: Record<FindingDisposition, string> = {
  correlated: 'badge badge-blue',
  retained_unpromoted: 'badge badge-gray',
  suppressed: 'badge badge-amber',
}

const DISPOSITION_TITLE: Record<FindingDisposition, string> = {
  correlated:
    'correlated — this finding reached correlation and is part of an incident.',
  retained_unpromoted:
    'retained_unpromoted — the promotion boundary kept this as an observation. The same word the argus_findings_processed_total metric uses.',
  suppressed:
    'suppressed — this finding CLEARED the promotion boundary and still has no incident. A toleration or storm protection stopped it.',
}

// PROJECT.md F31: the readable word for `finding.suppressionReason`, present
// only on a suppressed row written after migration 000124. Absent (never a
// third, guessed value) is handled at the call site, not here — a row
// missing this field is a fact ("not recorded for this row"), not a fourth
// vocabulary member.
const SUPPRESSION_REASON_LABEL: Record<FindingSuppressionReason, string> = {
  toleration: 'Suppressed by a toleration',
  storm_protection: 'Suppressed by storm protection',
}

// The three closed vocabularies the route validates against
// (gateway.FindingClasses/FindingConfidences/FindingImpacts). Sending a value
// outside one is a 400 by design, so the filters are <select>s over exactly
// these rather than free text.
const CLASS_OPTIONS: FindingClass[] = ['fault', 'risk', 'anomaly']
const CONFIDENCE_OPTIONS: FindingConfidence[] = ['verified', 'inferred', 'unverified']
const IMPACT_OPTIONS: FindingImpact[] = ['unavailable', 'degraded', 'potential', 'none']

// The quick-view tabs, in the order an operator reads them: everything, then
// what was raised, then the two kinds of not-raised. `all` is not a
// disposition on the wire — it means "send no ?disposition=" — which is also
// why it reads counts.all rather than a fourth count.
type QuickView = 'all' | FindingDisposition

const QUICK_VIEWS: Array<[QuickView, string]> = [
  ['all', 'All'],
  ['correlated', DISPOSITION_LABEL.correlated],
  ['retained_unpromoted', DISPOSITION_LABEL.retained_unpromoted],
  ['suppressed', DISPOSITION_LABEL.suppressed],
]

function isQuickView(value: string | null): value is QuickView {
  return value === 'all' || value === 'correlated' || value === 'retained_unpromoted' || value === 'suppressed'
}

function oneOf<T extends string>(value: string | null, options: readonly T[]): T | '' {
  return value && (options as readonly string[]).includes(value) ? (value as T) : ''
}

// "class", "class and impact", "class, confidence and impact" — the row-level
// answer to "why did this stay a finding", read straight off promotion.unmet
// rather than re-derived from the three values against the rule. Re-deriving
// it here would be a second implementation of the boundary living in a
// browser, which is the drift internal/gateway/promotion.go's generated
// criteria exist to prevent.
function listCriteria(unmet: readonly string[]): string {
  if (unmet.length <= 1) return unmet.join('')
  return `${unmet.slice(0, -1).join(', ')} and ${unmet[unmet.length - 1]}`
}

// The evidence tuple reads as three bare words because the three vocabularies
// are disjoint (fault/risk/anomaly, verified/inferred/unverified,
// unavailable/degraded/potential/none), so no value is ambiguous about which
// dimension it belongs to and the labels would be pure repetition in a cell
// that has to stay one line tall.
function evidenceTuple(item: { class: string; confidence: string; impact: string }): string {
  return `${item.class} · ${item.confidence} · ${item.impact}`
}

// The promotion boundary itself, from the response, in every state where a
// response exists.
//
// It is the screen's premise — without it a list of things that were not
// raised is a list of unexplained decisions — so its one-sentence summary is
// always visible. The criteria, the not-recorded clause and the source sit in
// a disclosure under it (owner review 2026-10-10, PROJECT.md UX1: the full
// card was an essay above the list on every visit). Nothing was dropped: the
// same server text renders, one click deeper.
//
// Everything in it is server-derived. gateway.buildPromotionRule enumerates
// the gate's whole input domain and generates each criterion's prose FROM the
// accepted set, so a criterion cannot claim something its own values
// contradict. (`source` names the enforcing file for maintainers; it is not shown.)
function PromotionBoundary({ rule }: { rule: FindingPromotionRule }) {
  // One line, not a card (owner, 2026-10-12, tidy-up): the rule's own
  // sentence beside its name, and the criteria one click down in the same
  // element. A light note above the list, so the list starts higher.
  return (
    <section className="signals-boundary" aria-label="Promotion boundary">
      <details className="signals-boundary-details">
        <summary className="signals-boundary-line">
          <strong>What opens an incident</strong>
          <span className="signals-boundary-summary">{rule.summary}</span>
        </summary>
        <div className="signals-boundary-columns">
          <div>
            <div className="verification-chip-row">
              {rule.criteria.map((criterion) => (
                <span key={criterion.dimension} className="verification-chip">
                  {criterion.statement}
                </span>
              ))}
            </div>
            {/* rule.source (the hub file that enforces this) is deliberately
                not rendered: a source path is provenance for whoever maintains
                the hub, not something an operator can act on. */}
          </div>
          {/* anti-patterns.md, "state a refusal at the same size as a
              success": the caveat gets the same chip vocabulary as the
              criteria beside it. The sentence is the server's. */}
          <p className="signals-not-recorded">
            <span className="verification-chip verification-chip-neutral">Not recorded at all</span>
            <span>{rule.notRecorded}</span>
          </p>
        </div>
      </details>
    </section>
  )
}

// One row. Eight cells: the severity rule, identity, cluster, severity,
// disposition, the evidence tuple, the occurrence count, and when.
// The object a finding is about, for the inspector (CI-U7). Null when the
// detector named no object — there is nothing to open then.
function findingObject(f: FindingListItem): ObjectRef | null {
  if (!f.objectName) return null
  const { apiGroup, kind } = splitGVK(f.gvk)
  return { clusterId: f.clusterId, kind, apiGroup, namespace: f.namespace || undefined, name: f.objectName }
}

// Clicking a row opens the inspector — but not when the click landed on a
// control inside the row, which keeps its own meaning (the cluster link,
// "Open the incident", the audit-log link).
function isInteractiveTarget(e: ReactMouseEvent): boolean {
  return !!(e.target as HTMLElement).closest('a, button, input, select, textarea, summary')
}

type RowNavProps = ReturnType<ReturnType<typeof useRowNavigation>['rowProps']>

function FindingRow({
  finding,
  canReadAudit,
  child = false,
  navProps,
  onOpenObject,
}: {
  finding: FindingListItem
  canReadAudit: boolean
  child?: boolean
  navProps: RowNavProps
  onOpenObject: (ref: ObjectRef) => void
}) {
  const object = findingObject(finding)
  const readable = readableSignalReason(finding)
  // The object leads, because a scan down the left edge of a triage list is a
  // scan of what is broken. A finding with no object name is a real case —
  // internal/api/findings.go notes it is also what makes correlation fall
  // back to fingerprint-only — so the kind stands in rather than a blank.
  const name = finding.objectName ?? finding.gvk
  const kindLine = [finding.gvk, finding.namespace].filter(Boolean).join(' · ')
  const unmet = finding.promotion.unmet ?? []

  return (
    <tr
      {...navProps}
      id={child ? `signal-${finding.id}` : undefined}
      className={[
        SEVERITY_RULE_CLASS[finding.severity] ?? 'sev-neutral',
        child ? 'row-group-child' : '',
        object ? 'fleet-row-clickable' : '',
        navProps['aria-current'] ? 'fleet-row-active' : '',
      ]
        .filter(Boolean)
        .join(' ')}
      onClick={(e) => {
        if (object && !isInteractiveTarget(e)) onOpenObject(object)
      }}
    >
      {/* Carries no content of its own: `.severity-rule` paints the --sev-fill
          the <tr> set and drops onto the padding `.list-table td:first-child`
          already provides. */}
      <td className="severity-rule">
        <div className="identity-block">
          {/* CI-U7: the object opens in the side panel, over this list, so
              the list keeps its filters, page and scroll. A finding with no
              object name has nothing to open and stays plain text. */}
          {object ? (
            <button
              type="button"
              className="link-button identity-block-name fleet-expander"
              title={`Open ${finding.gvk} ${name} in the inspector\nFingerprint ${finding.fingerprint}`}
              onClick={() => onOpenObject(object)}
            >
              {name}
            </button>
          ) : (
            <span className="identity-block-name" title={`Fingerprint ${finding.fingerprint}`}>
              {name}
            </span>
          )}
          {kindLine && <span className="identity-block-kind">{kindLine}</span>}
          {/* The reason is the fault line because it is the closed vocabulary
              an operator scans for; the detector's free-text message is the
              detail behind it and rides in the title. Both are
              Kubernetes-derived and therefore untrusted — plain JSX
              interpolation only, never dangerouslySetInnerHTML (SR-17). */}
          <span
            className="identity-block-fault"
            title={[finding.reason, finding.message, `Detector ${finding.detectorId}`]
              .filter(Boolean)
              .join('\n')}
          >
            {readable}
          </span>
        </div>
      </td>
      <td>
        <Link to={`/clusters/${finding.clusterId}`}>{finding.clusterDisplayName}</Link>
      </td>
      {/* Chip AND word. The chip makes the column scannable, the word carries
          the meaning; dropping it would be the colour-alone violation this
          codebase treats as safety-critical. The chip reads --sev-fill from
          the row, the same value the rule at the other end reads. */}
      <td className="col-shrink">
        <span className="severity-cell">
          <span className="severity-chip" aria-hidden="true" />
          {SEVERITY_LABEL[finding.severity] ?? finding.severity}
        </span>
      </td>
      <td>
        <span className={DISPOSITION_BADGE_CLASS[finding.disposition]} title={DISPOSITION_TITLE[finding.disposition]}>
          {DISPOSITION_LABEL[finding.disposition]}
        </span>
        {finding.disposition === 'correlated' && finding.incidentId && (
          <span className="signals-why">
            <Link to={`/incidents/${finding.incidentId}`}>Open the incident</Link>
          </span>
        )}
        {/* A raised finding that today's boundary would NOT raise. Worth
            saying rather than hiding: the disposition is derived against
            today's gate on purpose (present tense — "would ARGUS raise
            this"), so a row can be both genuinely correlated and below the
            current bar, and that difference is exactly what an operator
            auditing a boundary change is looking for. */}
        {finding.disposition === 'correlated' && !finding.promotion.promotable && (
          <span className="signals-why">Today&apos;s boundary would not raise this</span>
        )}
        {finding.disposition === 'retained_unpromoted' && unmet.length > 0 && (
          <span className="signals-why">Missed on {listCriteria(unmet)}</span>
        )}
        {/* PROJECT.md F31: written at INSERT time (migration 000124) — see
            SUPPRESSION_REASON_LABEL's own doc comment. Present on every
            suppressed row created after that migration shipped. */}
        {finding.disposition === 'suppressed' && finding.suppressionReason && (
          <span className="signals-why">{SUPPRESSION_REASON_LABEL[finding.suppressionReason]}</span>
        )}
        {finding.disposition === 'suppressed' && !finding.suppressionReason && (
          <span className="signals-why">
            Cause not recorded for this row.{' '}
            {/* A row from before migration 000124 — the reason genuinely
                isn't on it. Disabled, not hidden (lld/11 §6): the audit log
                is where the toleration id or the storm-protection window
                actually is, and a reader without audit:read has to be able
                to see that the answer exists and ask for the grant — not
                conclude there is no answer. The deep link pre-fills the
                audit log's own resource filter with this object. */}
            {canReadAudit ? (
              <Link
                to={
                  finding.objectName
                    ? `/audit-log?resource=${encodeURIComponent(finding.objectName)}`
                    : '/audit-log'
                }
              >
                Look in the audit log
              </Link>
            ) : (
              <button
                type="button"
                className="link-button"
                disabled
                title={missingCapabilityMessage([CAP_AUDIT_READ])}
              >
                Look in the audit log
              </button>
            )}
          </span>
        )}
      </td>
      <td>
        {/* The EFFECTIVE tuple the boundary judged, which is the stored one
            except on a legacy generic row carrying migration 000092's column
            defaults. Both are shown when they differ: hiding the stored
            values would make this list unreconcilable with the database, and
            hiding the effective ones would make a row read "fault, verified,
            degraded — not raised", which reads as a bug rather than as the
            correction it is. */}
        <span className="signals-evidence">{evidenceTuple(finding.promotion)}</span>
        {finding.promotion.evidenceCorrected && (
          <span
            className="signals-why"
            title={
              'This row is stored with a pre-evidence default tuple on a legacy generic mechanism ' +
              '(migration 000092), so the boundary reads it as anomaly / unverified / none. The ' +
              'correction predates this screen; it is shown rather than applied silently.'
            }
          >
            Stored as {evidenceTuple(finding)} (corrected)
          </span>
        )}
      </td>
      <td className="col-numeric" title="How many times this detector reported this same fingerprint">
        {finding.occurrenceCount}
      </td>
      <td className="col-time" title={formatDateTime(finding.occurredAt)}>
        {formatRelativeTime(finding.occurredAt)}
      </td>
    </tr>
  )
}

const SEVERITY_ORDER: FindingListItem['severity'][] = ['critical', 'high', 'medium', 'low']

// One collapsed group of look-alike signals (CI-U4): same detector, reason
// and rule. The head row states how many rows it stands for — exactly when
// this page is the whole scoped set, as a lower bound "on this page"
// otherwise — and offers the server-side reason filter, which is where the
// exact count lives (the All tab).
function SignalGroupRow({
  group,
  expanded,
  exact,
  reasonFiltered,
  navProps,
  onToggle,
  onFilterToReason,
}: {
  group: Extract<SignalRow, { kind: 'group' }>
  expanded: boolean
  exact: boolean
  reasonFiltered: boolean
  navProps: RowNavProps
  onToggle: () => void
  onFilterToReason: () => void
}) {
  const first = group.findings[0]
  const clusters = new Map(group.findings.map((f) => [f.clusterId, f.clusterDisplayName]))
  const worst =
    SEVERITY_ORDER.find((sev) => group.findings.some((f) => f.severity === sev)) ?? first.severity
  const latest = group.findings.reduce((a, f) => (f.occurredAt > a ? f.occurredAt : a), first.occurredAt)
  const dispositions = new Map<FindingDisposition, number>()
  for (const f of group.findings) dispositions.set(f.disposition, (dispositions.get(f.disposition) ?? 0) + 1)
  const n = group.findings.length
  const bodyIds = group.findings.map((f) => `signal-${f.id}`).join(' ')
  return (
    <tr
      {...navProps}
      className={[
        SEVERITY_RULE_CLASS[worst] ?? 'sev-neutral',
        'fleet-group-head',
        'fleet-row-clickable',
        navProps['aria-current'] ? 'fleet-row-active' : '',
      ]
        .filter(Boolean)
        .join(' ')}
      onClick={(e) => {
        if (!isInteractiveTarget(e)) onToggle()
      }}
    >
      <td className="severity-rule">
        <div className="identity-block">
          <button
            type="button"
            className="link-button identity-block-name fleet-expander"
            aria-expanded={expanded}
            aria-controls={expanded ? bodyIds : undefined}
            onClick={onToggle}
          >
            <span aria-hidden="true">{expanded ? '▾' : '▸'}</span> {readableSignalReason(first)}
          </button>
          <span className="identity-block-kind">
            {first.detectorId}
            {first.ruleId ? ` · rule ${first.ruleId}` : ''}
          </span>
          <span className="identity-block-fault">
            <span className="row-group-count">
              ×<Quantity value={n} certainty={exact ? 'exact' : 'atLeast'} />
            </span>{' '}
            look-alike {n === 1 ? 'signal' : 'signals'}
            {exact ? '' : ' on this page'}
          </span>
          {!reasonFiltered && (
            <span className="fleet-group-actions">
              <button type="button" className="link-button" onClick={onFilterToReason}>
                Only this reason{exact ? '' : ' (exact count)'} →
              </button>
            </span>
          )}
        </div>
      </td>
      <td>
        {clusters.size === 1 ? (
          <Link to={`/clusters/${first.clusterId}`}>{first.clusterDisplayName}</Link>
        ) : (
          <span title={[...clusters.values()].join(', ')}>{clusters.size} clusters</span>
        )}
      </td>
      <td className="col-shrink">
        <span className="severity-cell">
          <span className="severity-chip" aria-hidden="true" />
          {SEVERITY_LABEL[worst] ?? worst}
          {group.findings.some((f) => f.severity !== worst) ? ' (highest)' : ''}
        </span>
      </td>
      <td>
        {[...dispositions.entries()].map(([d, count]) => (
          <span key={d} className="signals-why">
            <span className={DISPOSITION_BADGE_CLASS[d]} title={DISPOSITION_TITLE[d]}>
              {DISPOSITION_LABEL[d]}
            </span>{' '}
            ×{count}
          </span>
        ))}
      </td>
      {/* Evidence and the per-fingerprint count differ signal to signal, so
          the group row has no single value for them — a dash, with the reason
          on hover, rather than a placeholder sentence in each cell. */}
      <td>
        <span className="text-muted" title="Differs per signal — expand the group to see each">—</span>
      </td>
      <td className="col-numeric">
        <span className="text-muted" title="Counted per signal — expand the group to see each">—</span>
      </td>
      <td className="col-time" title={formatDateTime(latest)}>
        {formatRelativeTime(latest)}
      </td>
    </tr>
  )
}

export function SignalsPage() {
  const { accessToken } = useAuth()
  const [searchParams, setSearchParams] = useSearchParams()

  // The cluster picker is a <select> over real clusters, not a free-text id,
  // and it is gated on cluster:read — disabled with the missing capability
  // named, never removed. incident:read and cluster:read are independent
  // grants, so a role holding the first and not the second is a real
  // configuration, and for that viewer this control has to say why it cannot
  // be used rather than vanish.
  const canReadClusters = useHasCapability(CAP_CLUSTER_READ)
  const canReadAudit = useHasCapability(CAP_AUDIT_READ)
  const clustersQuery = useQuery({
    queryKey: ['clusters'],
    queryFn: () => getClusters(accessToken!),
    enabled: !!accessToken && canReadClusters,
  })

  const [quickView, setQuickView] = useState<QuickView>(() => {
    const raw = searchParams.get('disposition')
    return isQuickView(raw) ? raw : 'all'
  })

  // Draft inputs are separate from the applied filters in the query key so
  // typing a reason does not fire a request per keystroke. Every one of them
  // is a parameter the ROUTE accepts: narrowing a fetched page locally would
  // show this selection's share of the newest 50 findings rather than its own
  // set, which is a different and smaller answer.
  const [clusterInput, setClusterInput] = useState(searchParams.get('clusterId') ?? '')
  const [reasonInput, setReasonInput] = useState(searchParams.get('reason') ?? '')
  const [classInput, setClassInput] = useState<FindingClass | ''>(() => oneOf(searchParams.get('class'), CLASS_OPTIONS))
  const [confidenceInput, setConfidenceInput] = useState<FindingConfidence | ''>(() =>
    oneOf(searchParams.get('confidence'), CONFIDENCE_OPTIONS),
  )
  const [impactInput, setImpactInput] = useState<FindingImpact | ''>(() =>
    oneOf(searchParams.get('impact'), IMPACT_OPTIONS),
  )
  // The URL carries RFC 3339 (what the route takes); these two inputs are
  // datetime-local, i.e. local wall clock. Converted properly rather than
  // sliced — see toDatetimeLocalValue's own comment for the drift that caused.
  const [sinceInput, setSinceInput] = useState(() => toDatetimeLocalValue(searchParams.get('since')))
  const [untilInput, setUntilInput] = useState(() => toDatetimeLocalValue(searchParams.get('until')))
  const moreFilterCount = [classInput, confidenceInput, impactInput, untilInput].filter(Boolean).length
  const [moreFiltersOpen, setMoreFiltersOpen] = useState(() => moreFilterCount > 0)

  const [appliedFilters, setAppliedFilters] = useState<FindingFilters>(() => ({
    clusterId: searchParams.get('clusterId') || undefined,
    reason: searchParams.get('reason') || undefined,
    class: oneOf(searchParams.get('class'), CLASS_OPTIONS) || undefined,
    confidence: oneOf(searchParams.get('confidence'), CONFIDENCE_OPTIONS) || undefined,
    impact: oneOf(searchParams.get('impact'), IMPACT_OPTIONS) || undefined,
    since: searchParams.get('since') || undefined,
    until: searchParams.get('until') || undefined,
  }))

  // The window, as a preset. '' is the server's own default (seven days
  // back); a since= from a link is an exact instant, so it reads as Custom
  // rather than being guessed into the nearest preset.
  const [rangeInput, setRangeInput] = useState<'' | '24h' | '30d' | 'custom'>(() =>
    searchParams.get('since') ? 'custom' : '',
  )

  // Keyset pagination, matching the route's own scheme — and in the URL
  // (CI-U5), so a shared link opens the same page. Each repeated ?cursor= is
  // the nextCursor that led to the next page, in order: page 1 carries none,
  // page N carries N-1, and Previous drops the last one rather than being a
  // second kind of request.
  const cursorHistory = searchParams.getAll('cursor')
  const pageIndex = cursorHistory.length
  const cursor = cursorHistory[pageIndex - 1]
  // Expanded look-alike groups (CI-U4), also in the URL.
  const expandedGroups = new Set(searchParams.getAll('group'))

  const requestFilters: FindingFilters = useMemo(
    () => ({
      ...appliedFilters,
      disposition: quickView === 'all' ? undefined : quickView,
      cursor,
      limit: PAGE_SIZE,
    }),
    [appliedFilters, quickView, cursor],
  )

  // Not gated on useHasCapability: the route requires incident:read
  // server-side and its 403 is the authoritative answer. useHasCapability
  // returns false for a permissions request still in flight or failed exactly
  // as it does for a real denial, so gating the fetch on it would turn "not
  // checked yet" into a permanent "you do not have access" — the bug
  // AuditLogPage's own comment records.
  const { data, isLoading, isError, isFetching, error, dataUpdatedAt } = useQuery({
    queryKey: ['findings', requestFilters],
    queryFn: () => getFindings(accessToken!, requestFilters),
    enabled: !!accessToken,
    refetchInterval: SIGNALS_POLL_MS,
    // A filter, quick view or page change mints a new key. Keep the rows on
    // screen (header saying "Updating…") until the narrowed answer lands,
    // rather than dropping to an empty table and "0 findings" on every
    // change — the same trade Incidents and Approvals make.
    placeholderData: keepPreviousData,
  })

  const findings = data?.findings ?? []
  const counts = data?.counts
  const activeFilterEntries = Object.entries(appliedFilters).filter(([, value]) => !!value)
  const hasActiveFilters = activeFilterEntries.length > 0
  const isNarrowed = hasActiveFilters || quickView !== 'all'

  // CI-U4: look-alike rows on this page collapse to one row with a count.
  // Exact only when this page is the whole scoped set; otherwise a lower
  // bound, said so in the row.
  const signalRows: SignalRow[] = useMemo(() => collapseSignals(data?.findings ?? []), [data])
  const wholeSet = pageIsWholeSet(pageIndex, data?.nextCursor)

  // CI-U6: the rows j/k step through, in display order — group heads, and a
  // group's members only while it is expanded. Enter opens the object (or
  // toggles a group).
  const navTargets: Array<{ key: string; open: () => void }> = []
  for (const row of signalRows) {
    if (row.kind === 'single') {
      const ref = findingObject(row.finding)
      navTargets.push({ key: row.finding.id, open: () => ref && openObject(ref) })
    } else {
      navTargets.push({ key: row.key, open: () => toggleGroup(row.key) })
      if (expandedGroups.has(row.key)) {
        for (const f of row.findings) {
          const ref = findingObject(f)
          navTargets.push({ key: f.id, open: () => ref && openObject(ref) })
        }
      }
    }
  }
  const navIndex = new Map(navTargets.map((t, i) => [t.key, i]))
  const nav = useRowNavigation({ count: navTargets.length, onOpen: (i) => navTargets[i]?.open() })

  // Filter changes always return to page 1. Folded into writeSearchParams
  // (which drops every ?cursor=), so there is one URL write, not two racing.
  function resetPaging() {}

  function goToPage(next: string[]) {
    const params = new URLSearchParams(searchParams)
    params.delete('cursor')
    for (const c of next) params.append('cursor', c)
    setSearchParams(params)
  }

  function toggleGroup(key: string) {
    const params = new URLSearchParams(searchParams)
    const open = params.getAll('group')
    params.delete('group')
    for (const g of open.includes(key) ? open.filter((x) => x !== key) : [...open, key]) params.append('group', g)
    setSearchParams(params, { replace: true })
  }

  function openObject(ref: ObjectRef) {
    setSearchParams(withObjectPanel(searchParams, ref))
  }

  // Narrows to one group's reason on the SERVER, which is what turns the
  // group's page-local count into the exact one on the All tab.
  function filterToReason(reason: string) {
    const next: FindingFilters = { ...appliedFilters, reason }
    setReasonInput(reason)
    setAppliedFilters(next)
    writeSearchParams(next, quickView)
  }

  // Filters apply as they change — there is no Apply button (owner,
  // 2026-10-12: one filter bar, like Incidents). Each control writes its own
  // key; an emptied control removes it.
  function applyNow(patch: Partial<FindingFilters>) {
    const next: FindingFilters = { ...appliedFilters, ...patch }
    for (const key of Object.keys(next) as Array<keyof FindingFilters>) {
      if (!next[key]) delete next[key]
    }
    setAppliedFilters(next)
    writeSearchParams(next, quickView)
    resetPaging()
  }

  // Reason is typed, so it applies 400ms after the last keystroke (or at once
  // on Enter) rather than per character — every change is a server request.
  useEffect(() => {
    const trimmed = reasonInput.trim()
    if ((appliedFilters.reason ?? '') === trimmed) return
    const timer = setTimeout(() => applyNow({ reason: trimmed || undefined }), 400)
    return () => clearTimeout(timer)
    // applyNow is recreated each render; the reason text is the trigger.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reasonInput, appliedFilters.reason])

  function applyFilters(event: FormEvent) {
    event.preventDefault()
    applyNow({ reason: reasonInput.trim() || undefined })
  }

  function selectRange(range: '' | '24h' | '30d' | 'custom') {
    setRangeInput(range)
    if (range === 'custom') {
      setMoreFiltersOpen(true)
      return
    }
    const since = range === '' ? undefined : new Date(Date.now() - (range === '24h' ? 24 : 720) * 3600_000).toISOString()
    setSinceInput(toDatetimeLocalValue(since ?? null))
    applyNow({ since })
  }

  // One applied filter, removed from its chip.
  function removeFilter(key: keyof FindingFilters) {
    if (key === 'clusterId') setClusterInput('')
    if (key === 'reason') setReasonInput('')
    if (key === 'class') setClassInput('')
    if (key === 'confidence') setConfidenceInput('')
    if (key === 'impact') setImpactInput('')
    if (key === 'since') {
      setSinceInput('')
      setRangeInput('')
    }
    if (key === 'until') setUntilInput('')
    applyNow({ [key]: undefined })
  }

  function clearFilters() {
    setClusterInput('')
    setReasonInput('')
    setClassInput('')
    setConfidenceInput('')
    setImpactInput('')
    setSinceInput('')
    setUntilInput('')
    setRangeInput('')
    setAppliedFilters({})
    writeSearchParams({}, quickView)
    resetPaging()
  }

  function selectQuickView(next: QuickView) {
    setQuickView(next)
    writeSearchParams(appliedFilters, next)
    resetPaging()
  }

  // Rewrites the filter keys and drops paging and group expansion (both
  // belong to the old result set), but keeps everything else in the URL —
  // an open inspector panel (?panel=, ?ptab=) survives a filter change.
  function writeSearchParams(filters: FindingFilters, view: QuickView) {
    const params = new URLSearchParams(searchParams)
    for (const key of ['clusterId', 'reason', 'class', 'confidence', 'impact', 'since', 'until', 'disposition', 'cursor', 'group']) {
      params.delete(key)
    }
    Object.entries(filters).forEach(([key, value]) => {
      if (value) params.set(key, String(value))
    })
    if (view !== 'all') params.set('disposition', view)
    setSearchParams(params, { replace: true })
  }

  if (isError && error instanceof ApiError && error.status === 403) {
    return (
      <div className="page">
        <header className="page-header">
          <h1>Signals</h1>
        </header>
        <IncidentsSectionTabs />
        <p className="banner banner-warning" role="alert">
          You don&apos;t have access to view findings. Missing capability: {CAP_INCIDENT_READ}.
        </p>
      </div>
    )
  }

  const FILTER_LABEL: Record<string, string> = {
    clusterId: 'Cluster',
    reason: 'Reason',
    class: 'Class',
    confidence: 'Confidence',
    impact: 'Impact',
    since: 'Since',
    until: 'Until',
  }
  const clusterName = (id: string) => clustersQuery.data?.clusters.find((c) => c.id === id)?.displayName ?? id

  return (
    <div className="page list-page signals-page">
      <header className="page-header list-page-header">
        <div>
          <h1>Signals</h1>
          {/* PROJECT.md F31: ListFreshness, matching Incidents/Clusters. The
              count is the exact total over the window the server applied
              (counts.all, never one page's rows), and the window rides in the
              same line — it is what every count and row on this screen is
              scoped to. Until a response is in hand, the count of rows that
              arrived stands in, marked "+" when the page was truncated. */}
          <ListFreshness
            isError={isError}
            isFetching={isFetching}
            updatedAt={dataUpdatedAt}
            hasData={data !== undefined}
            count={counts ? counts.all : findings.length}
            countLabel={(counts ? counts.all : findings.length) === 1 ? 'finding' : 'findings'}
            countSuffix={
              counts && data?.window ? (
                <span className="signals-window">
                  {' '}recorded since{' '}
                  <time dateTime={data.window.since} title={formatDateTime(data.window.since)}>
                    {formatRelativeTime(data.window.since)}
                  </time>
                  {data.window.until && (
                    <>
                      {' '}until{' '}
                      <time dateTime={data.window.until} title={formatDateTime(data.window.until)}>
                        {formatRelativeTime(data.window.until)}
                      </time>
                    </>
                  )}
                  <HelpTip
                    label="the window"
                    text="The counts and the rows cover only findings recorded in this window, and they are exact over it. The findings table is the highest-volume table in this product, so this list is always bounded: with no Since set, the server looks seven days back, not at everything."
                  />
                </span>
              ) : data?.nextCursor ? (
                <span className="figure-partial" aria-label="or more, this list was truncated">+</span>
              ) : null
            }
          />
        </div>
      </header>
      <IncidentsSectionTabs />

      {data?.promotionRule && <PromotionBoundary rule={data.promotionRule} />}

      <section className="list-card signals-list-card" aria-label="Findings">
        <form onSubmit={applyFilters}>
          {/* One bar: the views, then the filters that apply as they change
              (owner, 2026-10-12 — the same layout as Incidents). */}
          <div className="list-toolbar signals-toolbar">
            <nav className="list-quick-views list-quick-views-inbar" aria-label="Disposition">
              {QUICK_VIEWS.map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  className={quickView === value ? 'active' : ''}
                  aria-pressed={quickView === value}
                  onClick={() => selectQuickView(value)}
                >
                  {label}
                  {/* Exact over the whole scoped set, from the server's own
                      aggregate — never findings.length, which is one page. An
                      em dash while no response is in hand: a fabricated zero
                      here would read as "ARGUS suppressed nothing". */}
                  <span className="list-quick-count">
                    {counts
                      ? value === 'all'
                        ? counts.all
                        : value === 'correlated'
                          ? counts.correlated
                          : value === 'retained_unpromoted'
                            ? counts.retainedUnpromoted
                            : counts.suppressed
                      : '—'}
                  </span>
                </button>
              ))}
            </nav>

            <label className="list-search-field signals-reason-field">
              <span className="visually-hidden">Reason</span>
              <SearchIcon />
              <input
                id="signals-reason"
                type="search"
                value={reasonInput}
                onChange={(event) => setReasonInput(event.target.value)}
                placeholder="Reason, e.g. CrashLoopBackOff"
                title="The detector's own reason, matched exactly and case-sensitively — a closed vocabulary (CrashLoopBackOff, ServiceNoEndpoints), so GenericConditionAnomaly:Ready never also matches GenericConditionAnomaly:ReadyReplicas."
              />
            </label>

            <label className="list-filter-field">
              <span className="visually-hidden">Cluster</span>
              <select
                id="signals-cluster"
                value={clusterInput}
                onChange={(event) => {
                  setClusterInput(event.target.value)
                  applyNow({ clusterId: event.target.value || undefined })
                }}
                disabled={!canReadClusters}
                title={canReadClusters ? undefined : missingCapabilityMessage([CAP_CLUSTER_READ])}
              >
                <option value="">All clusters</option>
                {(clustersQuery.data?.clusters ?? []).map((cluster) => (
                  <option key={cluster.id} value={cluster.id}>
                    {cluster.displayName}
                  </option>
                ))}
              </select>
            </label>

            <label className="list-filter-field">
              <span className="visually-hidden">Time range</span>
              <select
                id="signals-range"
                value={rangeInput}
                onChange={(event) => selectRange(event.target.value as '' | '24h' | '30d' | 'custom')}
              >
                <option value="24h">Last 24 hours</option>
                <option value="">Last 7 days</option>
                <option value="30d">Last 30 days</option>
                <option value="custom">Custom…</option>
              </select>
            </label>

            <button
              type="button"
              className="secondary signals-more-toggle"
              aria-expanded={moreFiltersOpen}
              aria-controls="signals-more-filters"
              onClick={() => setMoreFiltersOpen((open) => !open)}
            >
              <FilterIcon />
              <span aria-hidden="true">More{moreFilterCount > 0 ? ` · ${moreFilterCount}` : ''}</span>
              <span className="visually-hidden">
                More filters{moreFilterCount > 0 ? `, ${moreFilterCount} set` : ''}
              </span>
            </button>
          </div>

          {/* The evidence filters and an exact window, used far less than the
              bar above. Open by itself whenever one is set, so an active filter
              is never behind a closed control. */}
          <div id="signals-more-filters" className="filter-bar signals-more-filters" hidden={!moreFiltersOpen}>
            <div className="filter-field">
              <div className="filter-label-row">
                <label htmlFor="signals-class">Class</label>
                <HelpTip label="Class" text="What kind of signal the detector says this is: fault (something is broken now), risk (something could break) or anomaly (unusual, not yet known to be harmful). What opens an incident says which classes are raised." />
              </div>
              <select
                id="signals-class"
                value={classInput}
                onChange={(event) => {
                  setClassInput(event.target.value as FindingClass | '')
                  applyNow({ class: (event.target.value as FindingClass) || undefined })
                }}
              >
                <option value="">Any class</option>
                {CLASS_OPTIONS.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </div>

            <div className="filter-field">
              <div className="filter-label-row">
                <label htmlFor="signals-confidence">Confidence</label>
                <HelpTip label="Confidence" text="How well the detector’s evidence supports the finding: verified (observed directly), inferred (derived from other facts) or unverified." />
              </div>
              <select
                id="signals-confidence"
                value={confidenceInput}
                onChange={(event) => {
                  setConfidenceInput(event.target.value as FindingConfidence | '')
                  applyNow({ confidence: (event.target.value as FindingConfidence) || undefined })
                }}
              >
                <option value="">Any confidence</option>
                {CONFIDENCE_OPTIONS.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </div>

            <div className="filter-field">
              <div className="filter-label-row">
                <label htmlFor="signals-impact">Impact</label>
                <HelpTip label="Impact" text="The effect the detector observed on the workload: unavailable, degraded, potential (not affecting anything yet) or none." />
              </div>
              <select
                id="signals-impact"
                value={impactInput}
                onChange={(event) => {
                  setImpactInput(event.target.value as FindingImpact | '')
                  applyNow({ impact: (event.target.value as FindingImpact) || undefined })
                }}
              >
                <option value="">Any impact</option>
                {IMPACT_OPTIONS.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </div>

            <div className="filter-field">
              <label htmlFor="signals-since">Since</label>
              <input
                id="signals-since"
                type="datetime-local"
                value={sinceInput}
                onChange={(event) => {
                  setSinceInput(event.target.value)
                  setRangeInput(event.target.value ? 'custom' : '')
                  applyNow({ since: fromDatetimeLocalValue(event.target.value) })
                }}
              />
            </div>

            <div className="filter-field">
              <label htmlFor="signals-until">Until</label>
              <input
                id="signals-until"
                type="datetime-local"
                value={untilInput}
                onChange={(event) => {
                  setUntilInput(event.target.value)
                  applyNow({ until: fromDatetimeLocalValue(event.target.value) })
                }}
              />
            </div>
          </div>
        </form>

        {hasActiveFilters && (
          <div className="applied-filter-chips" aria-label="Applied filters">
            {activeFilterEntries.map(([key, value]) => (
              <span key={key} className="list-active-filter">
                {FILTER_LABEL[key] ?? key}:{' '}
                {key === 'clusterId'
                  ? clusterName(String(value))
                  : key === 'since' || key === 'until'
                    ? formatDateTime(String(value))
                    : String(value)}
                <button
                  type="button"
                  aria-label={`Remove the ${(FILTER_LABEL[key] ?? key).toLowerCase()} filter`}
                  title={`Remove the ${(FILTER_LABEL[key] ?? key).toLowerCase()} filter`}
                  onClick={() => removeFilter(key as keyof FindingFilters)}
                >
                  ×
                </button>
              </span>
            ))}
            {activeFilterEntries.length > 1 && (
              <button type="button" className="link-button" onClick={clearFilters}>
                Clear all
              </button>
            )}
          </div>
        )}

        {isError && (
          <p className="form-error" role="alert">
            {error instanceof ApiError
              ? error.detail
                ? `${error.message} — ${error.detail}`
                : error.message
              : 'Failed to load findings.'}
          </p>
        )}

        {isLoading && (
          <div className="table-scroll">
            <table className="cluster-table list-table scan-table signals-table" aria-busy="true">
              <SignalsTableHead />
              <tbody>
                <SkeletonTableRows columns={7} />
              </tbody>
            </table>
          </div>
        )}

        {/* Two empty states, and they say different things (lld/11 §7). One
            offers a way back; the other describes what would appear here.
            Note what the second does NOT say: "nothing has ever been
            recorded". Every request is bounded by a window, so the page
            cannot know that and does not claim it. */}
        {!isLoading && !isError && findings.length === 0 && (
          <EmptyState variant="audit">
            {isNarrowed
              ? 'No findings match these filters in this window. Widen Since, clear a filter, or switch back to All.'
              : 'Nothing has been recorded in this window. Every detection a cluster agent reports is written here, ' +
                'whether or not it opens an incident — so an empty list means no agent reported anything in this ' +
                'range. Try an earlier Since. Findings dropped before storage never appear at any setting; see ' +
                'what opens an incident, above.'}
          </EmptyState>
        )}

        {!isLoading && findings.length > 0 && (
          <div className="table-scroll">
            <table className="cluster-table list-table scan-table signals-table">
              <SignalsTableHead />
              <tbody {...nav.containerProps}>
                {signalRows.map((row) => {
                  if (row.kind === 'single') {
                    const index = navIndex.get(row.finding.id) ?? 0
                    return (
                      <FindingRow
                        key={row.key}
                        finding={row.finding}
                        canReadAudit={canReadAudit}
                        navProps={nav.rowProps(index)}
                        onOpenObject={openObject}
                      />
                    )
                  }
                  const expanded = expandedGroups.has(row.key)
                  return (
                    <Fragment key={row.key}>
                      <SignalGroupRow
                        group={row}
                        expanded={expanded}
                        exact={wholeSet}
                        reasonFiltered={!!appliedFilters.reason}
                        navProps={nav.rowProps(navIndex.get(row.key) ?? 0)}
                        onToggle={() => toggleGroup(row.key)}
                        onFilterToReason={() => filterToReason(row.findings[0].reason)}
                      />
                      {expanded &&
                        row.findings.map((finding) => (
                          <FindingRow
                            key={finding.id}
                            finding={finding}
                            child
                            canReadAudit={canReadAudit}
                            navProps={nav.rowProps(navIndex.get(finding.id) ?? 0)}
                            onOpenObject={openObject}
                          />
                        ))}
                    </Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Keyset paging states the page it is on and nothing else. It does
            not restate a total: the exact one for the current scope is
            already on the tab naming it, and the same count in two places is
            a named failure. */}
        <div className="list-pagination">
          <span className="pagination-status">Page {pageIndex + 1}</span>
          <div className="page-header-actions">
            <button
              type="button"
              className="secondary"
              onClick={() => goToPage(cursorHistory.slice(0, -1))}
              disabled={pageIndex === 0}
            >
              Previous
            </button>
            {/* Secondary, like Previous: "Apply filters" is this screen's one
                primary action (components.md, one primary per screen). */}
            <button
              type="button"
              className="secondary"
              onClick={() => {
                if (!data?.nextCursor) return
                goToPage([...cursorHistory, data.nextCursor])
              }}
              disabled={!data?.nextCursor}
            >
              Next
            </button>
          </div>
        </div>
      </section>
    </div>
  )
}

// Shared by the skeleton and the loaded table so the two cannot disagree about
// column count or width — components.md: a skeleton that does not match the
// eventual layout guarantees the jump it exists to prevent.
function SignalsTableHead() {
  return (
    <thead>
      <tr>
        <th>Signal</th>
        <th>Cluster</th>
        <th className="col-shrink">Severity</th>
        <th>What ARGUS did</th>
        <th>Evidence</th>
        <th className="col-numeric">Seen</th>
        <th className="col-time">Occurred</th>
      </tr>
    </thead>
  )
}
