import { useId, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { listTolerations, getToleration, removeToleration, ApiError } from '../api/client'
import type { Toleration, TolerationOrigin, SuppressedFindingGroup } from '../api/types'
import { CAP_INCIDENT_SILENCE } from '../api/capabilities'
import { useAuth } from '../auth/useAuth'
import { useHasCapability } from '../auth/useCapabilities'
import { formatDateTime, formatRelativeTime } from '../utils/time'
import { SkeletonTableRows, SkeletonLines } from '../components/Skeleton'
import { ChevronIcon } from '../components/icons'
// Paged with the same mechanism the other three lists use (BUGS.md 57) — one
// shared hook and one shared footer. This was the fourth list in the app and the
// only one that rendered its whole array: a toleration is never deleted by the
// product (only by a person, or by expiry), so this list only grows.
import { TablePagination } from '../components/TablePagination'
import { usePagination } from '../utils/pagination'
// The same components the incident screens render, not lookalikes of them: a
// toleration IS an incident that has been accepted, so the incident it came
// from, its severity and state, its root cause and the remediation ARGUS
// proposed all have to read exactly as they do on the incident detail page.
import { SeverityBadge, StateBadge } from '../components/IncidentBadges'
import { ConclusionBlock } from '../components/AnalysisConclusion'
import { RemediationPlanCard } from '../components/RemediationPlanCard'
import { IncidentsSectionTabs } from '../components/IncidentsSectionTabs'
import { HelpTip } from '../components/HelpTip'

// Read/manage surface for incident_tolerations (migration 000041) — every
// rule created via IncidentDetailPage's "Tolerate…" action lands here.
// Deliberately the only place a toleration can be removed: there is no
// "edit" affordance, matching grants' own revoke-and-recreate convention
// (internal/api/users.go's handleRevokeGrant) rather than an in-place PATCH.
//
// Reachable from the primary nav (AppShell.tsx) and from IncidentsPage's
// header. This comment previously said the nav entry was still missing because
// AppShell was mid-redesign by a concurrent session; that redesign has since
// landed and added it.

// Automatic tolerations written before 2026-10-11 carry an internal planning
// reference in their note ("Automatically suppressed (PROJECT.md T6): …"); the
// hub no longer writes it (internal/orchestrator/recurrence.go), and this
// strips it from the rows already stored so operators never see it.
function displayNote(note: string): string {
  return note.replace(/^Automatically suppressed \(PROJECT\.md T6\):/, 'Automatically suppressed:')
}

// tolerationLabel is the same "what failed" shape IncidentsPage uses, on
// purpose.
//
// A toleration IS an incident that has been accepted — same object, same reason
// — so presenting it in a different vocabulary made an operator translate
// between two views of one fact. Rendering it as `ServiceNoEndpoints ·
// rancher-monitoring-windows-exporter` means the rule reads as the thing it
// silences, and the "Tolerated" badge supplies the difference.
//
// "Every reason" is a scope, not a reason, so it is said as one rather than
// dressed up as a failure name.
function tolerationLabel(toleration: Toleration): string {
  const scope = toleration.allReasons ? 'Every reason' : (toleration.reasons ?? []).join(', ')
  if (scope && toleration.objectName) return `${scope} · ${toleration.objectName}`
  return scope || toleration.objectName || toleration.objectKey
}

// The note, restored to being content rather than trailing metadata.
//
// It had its own column until the row was reshaped to read like an incident
// (WORKLOG §130), which demoted it to a muted suffix on the metadata line —
// a downgrade for the one field whose entire job is explaining WHY something
// is being silenced, and the regression BUGS.md item 37(b) called out. It now
// opens the expanded panel, above the analysis and the suppressed findings,
// because it is the human decision those two are evidence for.
function ToleranceNote({ toleration }: { toleration: Toleration }) {
  return (
    <section className="toleration-detail-section">
      <p className="eyebrow">Why this was tolerated</p>
      {toleration.note ? (
        <p className="toleration-note">{displayNote(toleration.note)}</p>
      ) : (
        // The hub requires a note (internal/api/tolerations.go 400s without
        // one), so this is only reachable for a hand-inserted row — said
        // plainly rather than rendered as an empty paragraph.
        <p className="empty-state">No note was recorded for this rule.</p>
      )}
      <p className="field-hint">
        {/* "unknown" is only honest for a rule whose author was deleted. A rule
            ARGUS created for itself has no author BY DESIGN (migration 000112),
            and calling that unknown reads as lost provenance rather than as
            "the product did this" — which is exactly the fact an operator needs
            to decide whether to remove it. */}
        {toleration.autoCreated
          ? 'Suppressed automatically by ARGUS'
          : `Tolerated by ${toleration.createdByEmail || toleration.createdBy || 'unknown'}`}{' '}
        ·{' '}
        <span title={formatDateTime(toleration.createdAt)}>{formatRelativeTime(toleration.createdAt)}</span>
        {toleration.expiresAt ? ` · expires ${formatDateTime(toleration.expiresAt)}` : ' · never expires'}
      </p>
    </section>
  )
}

// The originating incident: what was detected, what ARGUS concluded about it,
// and what it had proposed doing — BUGS.md item 37(a).
//
// This is the half the suppressed-findings panel cannot supply. A finding
// carries a reason and a message; it does not carry why the condition is
// expected, and it does not carry the fix that was on the table when someone
// decided to accept it instead. Both live on the incident, and both are what
// makes a rule reviewable months later by someone who was not there.
function OriginIncidentSection({ toleration, origin }: { toleration: Toleration; origin: TolerationOrigin | null }) {
  if (!origin) {
    return (
      <section className="toleration-detail-section">
        <p className="eyebrow">The incident this came from</p>
        {/* Two genuinely different absences, said differently rather than
            collapsed into one vague line — see TolerationDetail in api/types.ts. */}
        {toleration.incidentId ? (
          <p className="empty-state">
            Incident <code>{toleration.incidentId}</code> is no longer stored. Incidents age out of the
            retention window, while a rule with no expiry outlives them — what the rule has suppressed
            since is below.
          </p>
        ) : (
          <p className="empty-state">
            No originating incident is recorded for this rule. ARGUS only began storing the link in
            migration 000044; older rules keep it only where the audit event that created them still
            names the incident.
          </p>
        )}
      </section>
    )
  }

  const { incident, analysis, ownership } = origin
  return (
    <section className="toleration-detail-section">
      <div className="toleration-origin-head">
        <p className="eyebrow">The incident this came from</p>
        <SeverityBadge severity={incident.severity} />
        <StateBadge state={incident.state} resolutionKind={incident.resolutionKind} />
        <Link to={`/incidents/${incident.id}`}>Open incident →</Link>
      </div>
      <p className="field-hint">
        {incident.occurrenceCount} occurrence{incident.occurrenceCount === 1 ? '' : 's'} before it was
        tolerated · first seen{' '}
        <span title={formatDateTime(incident.firstSeen)}>{formatRelativeTime(incident.firstSeen)}</span> · last
        seen <span title={formatDateTime(incident.lastSeen)}>{formatRelativeTime(incident.lastSeen)}</span>
      </p>

      {/* Where the real fix lives, stated on the RULE rather than only on the
          closed incident. Someone auditing muted rules is asking "should this
          still be silenced?", and the answer usually depends on whether the
          underlying manifest was ever corrected — which they cannot judge
          without knowing there is a manifest, and where. */}
      {ownership?.repo && (
        <div className="detail-callout">
          <p className="eyebrow">Where the real fix belongs</p>
          <p>
            This object is managed by <strong>{ownership.managedBy}</strong>
            {ownership.sourceName ? ` (${ownership.sourceKind} ${ownership.sourceName})` : ''}, so the
            condition being silenced here is defined in a repository — not in the cluster. Silencing
            it does not change that.
          </p>
          {/* Each field is a dt+dd pair wrapped in its own <div> — required by
              `.detail-fact-grid`'s `auto-fit` column layout (BACKLOG D7m):
              without the wrapper, auto-fit places dt/dd as independent grid
              items and wraps them wherever the column count lands, so a
              label and its OWN value can end up in different rows/columns
              entirely. The wrapper makes the PAIR the grid item, matching
              `RemediationPlanCard`'s existing `.detail-fact-grid` markup. */}
          <dl className="detail-fact-grid compact ownership-source">
            <div>
              <dt>Repository</dt>
              <dd>
                <code>{ownership.repo.url}</code>
              </dd>
            </div>
            {ownership.repo.path && (
              <div>
                <dt>Path</dt>
                <dd>
                  <code>{ownership.repo.path}</code>
                </dd>
              </div>
            )}
            {ownership.repo.revision && (
              <div>
                <dt>Synced commit</dt>
                <dd>
                  <code>
                    {ownership.repo.pinned
                      ? ownership.repo.revision.slice(0, 12)
                      : ownership.repo.revision}
                  </code>{' '}
                  {!ownership.repo.pinned && (
                    <span className="badge badge-gray">not pinned</span>
                  )}
                </dd>
              </div>
            )}
          </dl>
        </div>
      )}

      {analysis ? (
        <>
          <ConclusionBlock analysis={analysis} />
          {analysis.plan ? (
            <RemediationPlanCard analysis={analysis} />
          ) : (
            <p className="field-hint">
              {analysis.status === 'complete'
                ? 'ARGUS proposed no remediation for this: it executes a fixed set of typed actions against the live object, so a fault whose real fix is a manifest or chart change yields no plan. That is the usual outcome, not a gap.'
                : 'The investigation stopped before reaching a conclusion, so it never got as far as proposing a remediation.'}
            </p>
          )}
        </>
      ) : (
        <p className="empty-state">Never investigated: the note above is the whole reasoning behind this rule.</p>
      )}
    </section>
  )
}

// What this rule has actually been silencing, grouped by reason with the real
// finding message.
//
// The live half of the panel, and still the part that exposes the case worth
// acting on: a rule suppressing nothing. Grouped rather than listed flat for
// the same reason BUGS.md item 30 established for an incident's own findings —
// a condition suppressed 97 times has one thing to say, not 97.
function SuppressedSection({ groups }: { groups: SuppressedFindingGroup[] }) {
  return (
    <section className="toleration-detail-section">
      <p className="eyebrow">What this rule has suppressed</p>
      {groups.length === 0 ? (
        <p className="field-hint">Nothing suppressed yet: the condition has not recurred, or the rule no longer matches.</p>
      ) : (
        <ul className="toleration-suppressed-list">
          {groups.map((g) => (
            <li key={g.reason}>
              <div className="toleration-suppressed-head">
                <SeverityBadge severity={g.severity} />
                <strong>{g.reason}</strong>
                <span className="toleration-suppressed-count" title={`${g.count} findings suppressed by this rule`}>
                  ×{g.count}
                </span>
                <span className="toleration-object-meta">
                  {/* Identical timestamps render as one time rather than "x → x" —
                      sweep detectors stamp occurred_at with the condition's
                      transition time, so a single-moment range is normal. */}
                  {g.firstSeen === g.lastSeen
                    ? formatDateTime(g.firstSeen)
                    : `${formatDateTime(g.firstSeen)} → ${formatDateTime(g.lastSeen)}`}
                </span>
              </div>
              <p className="toleration-suppressed-message">{g.sampleMessage}</p>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

// The expanded row: the decision, the incident behind it, and what it has done
// since — one fetch (GET /tolerations/{id}), because the panel needs all three
// and none of them is useful alone.
//
// The note renders immediately from the row already in hand rather than waiting
// on that fetch: it is the most important thing here and it is already loaded,
// so making it appear with the spinner would be a self-inflicted delay.
function TolerationDetailPanel({ toleration }: { toleration: Toleration }) {
  const { accessToken } = useAuth()
  const query = useQuery({
    queryKey: ['tolerations', toleration.id],
    queryFn: () => getToleration(toleration.id, accessToken!),
    enabled: !!accessToken,
  })

  return (
    <div className="toleration-detail">
      <ToleranceNote toleration={toleration} />
      {/* BACKLOG D7g. 3 flat lines stood in for two whole sections — origin
          incident (an eyebrow, severity/state badges, a field-hint, and
          either a conclusion/plan or an empty state) and what's been
          suppressed (its own eyebrow plus a grouped list) — so the panel's
          shape changed the moment this query resolved. The headings are
          static, not data-dependent, so they render immediately rather than
          being invented for the skeleton. */}
      {query.isLoading && (
        <>
          <section className="toleration-detail-section" aria-hidden="true">
            <p className="eyebrow">The incident this came from</p>
            <SkeletonLines count={2} />
          </section>
          <section className="toleration-detail-section" aria-hidden="true">
            <p className="eyebrow">What this rule has suppressed</p>
            <SkeletonLines count={2} />
          </section>
        </>
      )}
      {query.isError && (
        <p className="form-error inline-error" role="alert">
          {query.error instanceof ApiError ? query.error.message : 'Could not load this rule’s detail.'}
        </p>
      )}
      {query.data && (
        <>
          <OriginIncidentSection toleration={toleration} origin={query.data.origin} />
          <SuppressedSection groups={query.data.suppressed} />
        </>
      )}
    </div>
  )
}

function ToleranceRow({ toleration }: { toleration: Toleration }) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const [confirming, setConfirming] = useState(false)
  const [expanded, setExpanded] = useState(false)
  const panelId = useId()

  const removeMutation = useMutation({
    mutationFn: () => removeToleration(toleration.id, accessToken!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['tolerations'] }),
  })

  const row = (
    <tr>
      {/* The row reads like an incident row — failure label, cluster, state,
          count — because that is what it is: an incident that has been
          accepted. The chevron expands to why it was accepted, what ARGUS had
          said about it, and what the rule has suppressed since. */}
      <td>
        <button
          type="button"
          className="toleration-toggle"
          aria-expanded={expanded}
          aria-controls={panelId}
          onClick={() => setExpanded((open) => !open)}
          title={`${toleration.objectGvk} ${toleration.objectNamespace}\n${toleration.objectKey}`}
        >
          <ChevronIcon direction="right" size={14} className="toleration-chevron" />
          {/* BACKLOG D7h. `.identity-block` (leading cell of a row: what is
              broken, before status colour) existed and this leading cell
              hand-rolled its own version instead — `.toleration-object` has
              no `max-width`/`min-width: 0` bound, so a long object name could
              push this column open exactly the way BUGS.md 68 already fixed
              for incident rows. */}
          <span className="identity-block">
            <span className="identity-block-name">{tolerationLabel(toleration)}</span>
            <span className="identity-block-kind">
              {[toleration.objectGvk, toleration.objectNamespace].filter(Boolean).join(' · ')}
            </span>
          </span>
        </button>
      </td>
      <td>
        <span className="audit-cell-truncate" title={toleration.clusterId}>
          {toleration.clusterDisplayName || toleration.clusterId}
        </span>
      </td>
      <td><span className="badge badge-amber">Tolerated</span></td>
      <td className="col-numeric">
        {/* The occurrences analogue, and the field that says whether the rule is
            earning its keep. Zero is the interesting value: a rule silencing
            nothing should probably be removed. */}
        <span
          className={toleration.suppressedCount > 0 ? 'incident-occurrence-count active' : 'incident-occurrence-count'}
          title={
            toleration.lastSuppressed
              ? `${toleration.suppressedCount} findings suppressed, most recently ${formatDateTime(toleration.lastSuppressed)}`
              : 'This rule has not suppressed anything yet'
          }
        >
          {toleration.suppressedCount}
        </span>
      </td>
      <td>
        <span className="toleration-object">
          <span>{formatDateTime(toleration.createdAt)}</span>
          {/* Who silenced this is part of "can I safely remove it?" — the
              question this page exists to answer. Falls back to the raw user id
              rather than blank, so a removed author still leaves a trace. */}
          <span
            className="toleration-object-meta"
            title={toleration.autoCreated ? 'Created automatically when an incident closed Dismissed or Expired' : toleration.createdBy}
          >
            {toleration.autoCreated
              ? 'by ARGUS'
              : `by ${toleration.createdByEmail || toleration.createdBy || 'unknown'}`}
          </span>
        </span>
      </td>
      <td>{toleration.expiresAt ? formatDateTime(toleration.expiresAt) : 'Never'}</td>
      <td className="table-pinned-actions">
        {!confirming ? (
          <button type="button" className="secondary" onClick={() => setConfirming(true)} disabled={removeMutation.isPending}>
            Remove…
          </button>
        ) : (
          <span className="triage-actions">
            <button type="button" onClick={() => removeMutation.mutate()} disabled={removeMutation.isPending}>
              {removeMutation.isPending ? 'Removing…' : 'Confirm'}
            </button>
            <button type="button" className="secondary" onClick={() => setConfirming(false)} disabled={removeMutation.isPending}>
              Cancel
            </button>
          </span>
        )}
        {removeMutation.isError && (
          <p className="form-error inline-error" role="alert">
            {removeMutation.error instanceof ApiError ? removeMutation.error.message : 'Could not remove toleration.'}
          </p>
        )}
      </td>
    </tr>
  )

  return (
    <>
      {row}
      {expanded && (
        <tr className="toleration-detail-row">
          <td colSpan={7} id={panelId}>
            <TolerationDetailPanel toleration={toleration} />
          </td>
        </tr>
      )}
    </>
  )
}

export function TolerationsPage() {
  const { accessToken } = useAuth()
  const canSilence = useHasCapability(CAP_INCIDENT_SILENCE)

  const { data, isLoading, isError, error, dataUpdatedAt } = useQuery({
    queryKey: ['tolerations'],
    queryFn: () => listTolerations(accessToken!),
    enabled: !!accessToken && canSilence,
  })

  const tolerations = data ?? []
  // Split because the endpoint and the suppressor disagree about "active": the
  // list returns every row WHERE removed_at IS NULL, while suppression stops at
  // expires_at <= now() (internal/gateway/toleration.go). So an expired rule is
  // still listed and silences nothing — counting it as active overstated what is
  // in force. expiresAt is on the payload, so this is computable client-side.
  // dataUpdatedAt, not Date.now(): reading the clock during render is impure —
  // the count would drift between re-renders that fetched nothing — and the
  // honest reference point is the moment this data was actually fetched, not the
  // moment React happened to re-render it.
  const isExpired = (t: (typeof tolerations)[number]) =>
    !!t.expiresAt && new Date(t.expiresAt).getTime() <= dataUpdatedAt
  const expiredCount = tolerations.filter(isExpired).length
  const activeCount = tolerations.length - expiredCount
  const { visibleItems: visibleTolerations, pagination } = usePagination(tolerations)

  return (
    <div className="page list-page">
      <header className="page-header list-page-header">
        <div>
          <h1>Tolerations</h1>
          <p className="list-live-status">
            {/* BACKLOG D7b. Three separate falsehoods lived in "{length} active
                rules": without incident:silence the query is disabled, so `data`
                is undefined and this read "0 active rules" — a reassuring zero
                where the honest answer is that the viewer may not see them; it
                read 0 during loading for the same reason; and the endpoint
                returns every row WHERE removed_at IS NULL with no expiry filter,
                while suppression stops at expires_at <= now(), so expired rules
                were counted as active. */}
            <span>
              {!canSilence ? (
                // BACKLOG D7h. The "Restricted" value slot: a capability-gated
                // count now reads visually as one — muted and italic — rather
                // than as plain text sitting in the same slot a real number
                // occupies.
                <span className="value-restricted">Requires {CAP_INCIDENT_SILENCE}</span>
              ) : isLoading ? (
                '…'
              ) : isError ? (
                // Never a count we do not have. With the query in error both
                // counts are 0 because there is no data, and "0 active, 0
                // expired" is a claim that nothing is silenced — on the one
                // screen whose entire subject is what ARGUS has stopped
                // watching. An em dash says "unknown"; a zero says "none".
                '—'
              ) : (
                `${activeCount} active, ${expiredCount} expired`
              )}
            </span>
          </p>
        </div>
      </header>
      <IncidentsSectionTabs />

      <p className="field-hint">
        Accepted conditions that no longer open incidents on their object.{' '}
        <HelpTip
          label="tolerations"
          text="A toleration stops a real, already-triaged, accepted condition from opening a new incident every time its detector re-fires — created from an incident's Tolerate… action. It does not affect an already-open incident on a different object, and it never suppresses a finding that names no object. Open a row to see why it was tolerated, what ARGUS had said about the original incident, and what the rule has silenced since. Remove a rule to resume normal detection for that object."
        />
      </p>

      {!canSilence && (
        <p className="form-error" role="alert">
          Missing capability: {CAP_INCIDENT_SILENCE}
        </p>
      )}

      {canSilence && isError && (
        <p className="form-error" role="alert">
          {error instanceof ApiError ? (error.detail ? `${error.message} — ${error.detail}` : error.message) : 'Failed to load tolerations.'}
        </p>
      )}

      {/* `.list-card` is the same wrapper Clusters/Users/Audit log/the cluster
          detail incident list all use around a `.list-table` + its footer —
          this page was rendering the bare `table-scroll`/`TablePagination`
          pair as siblings with no card around them. `.list-table` zeroes its
          own border/shadow/radius on the assumption a `.list-card` supplies
          them (index.css), and `.list-pagination` draws only a `border-top`
          on the same assumption (it's meant to read as the card's bottom
          edge, per ClusterDetailPage's own comment on this exact pattern) —
          so without the card this table rendered borderless and the footer
          floated underneath it as a detached rule, the one list on the app
          that didn't look like the other three. */}
      {canSilence && !isError && (
        <section className="list-card" aria-label="Toleration rules">
          <div className="table-scroll">
            <table className="cluster-table list-table tolerations-table">
              <thead>
                <tr>
                  <th>Silenced condition</th>
                  <th>Cluster</th>
                  <th>State</th>
                  <th className="col-numeric">Suppressed</th>
                  <th>Created</th>
                  <th>Expires</th>
                  <th className="table-pinned-actions"><span className="visually-hidden">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {isLoading && <SkeletonTableRows columns={7} />}
                {!isLoading && tolerations.length === 0 && (
                  <tr>
                    <td colSpan={7}>
                      <p className="empty-state">
                        No active tolerations. Create one from an incident's "Tolerate…" action.
                      </p>
                    </td>
                  </tr>
                )}
                {!isLoading && visibleTolerations.map((t) => <ToleranceRow key={t.id} toleration={t} />)}
              </tbody>
            </table>
          </div>

          {!isLoading && tolerations.length > 0 && <TablePagination {...pagination} />}
        </section>
      )}
    </div>
  )
}
