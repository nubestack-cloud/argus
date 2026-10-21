import { useState } from 'react'
import type { FormEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getAuditEvent, getAuditEvents, getClusters, ApiError } from '../api/client'
import type { AuditEventFilters, AuditEventSummary } from '../api/types'
import { CAP_AUDIT_READ, CAP_CLUSTER_READ } from '../api/capabilities'
import { useAuth } from '../auth/useAuth'
import { useHasCapability } from '../auth/useCapabilities'
import { formatDateTime, fromDatetimeLocalValue, toDatetimeLocalValue } from '../utils/time'
import { EmptyState } from '../components/EmptyState'
import { HelpTip } from '../components/HelpTip'
import { FilterIcon } from '../components/icons'
import { SkeletonTableRows } from '../components/Skeleton'
import { Dialog } from '../components/Dialog'
import { useSearchParams } from 'react-router-dom'

// Read-only view onto internal/api/audit.go's GET /api/v1/audit-events and
// GET /api/v1/audit-events/{id} — the first way to see the hash-chained
// audit_events table from the UI at all, short of `psql` or the standalone
// `argusctl audit verify` tool. Deliberately has no edit/delete affordance of
// any kind: the whole point of a hash chain is that it's append-only and
// tamper-evident, so this screen only ever reads it.

const PAGE_SIZE = 50

const OUTCOME_BADGE_CLASS: Record<AuditEventSummary['outcome'], string> = {
  success: 'badge badge-green',
  denied: 'badge badge-amber',
  error: 'badge badge-red',
}

function OutcomeBadge({ outcome }: { outcome: AuditEventSummary['outcome'] }) {
  return <span className={OUTCOME_BADGE_CLASS[outcome]}>{outcome}</span>
}

// A real, user-reported bug: every row with no resolvable actor identity
// (actorEmail/actorDisplayName/actorId all null) fell back to the single
// label "system" — correct for an actually-automated action (a cert
// issued over the mTLS tunnel, a background job), but actively misleading
// for a failed login attempt, which has no ActorID for a completely
// different reason: the credentials didn't resolve to anyone, not because
// nothing human was involved.
//
// The first fix (checking only "is actorAuthMethod set") over-corrected:
// a successful cluster enrollment or certificate issuance ALSO sets
// actorAuthMethod ("enrollment_token"/"poll_token"/"mtls_tunnel") even
// though nothing failed and there genuinely is no human actor — those are
// real, correct "system" rows, not failed authentication attempts. The
// actual distinguishing signal is outcome: "denied" + an attempted auth
// method means a real (if unsuccessful) authentication was attempted by
// someone unidentified; "success" with no actor means an already-trusted
// non-human caller (an agent's enrollment/poll token, its own mTLS
// tunnel) legitimately acted with no user behind it — "system" is the
// correct word for that, not "Unauthenticated".
function actorLabel(event: {
  actorEmail: string | null
  actorDisplayName: string | null
  actorId: string | null
  actorAuthMethod: string
  outcome: string
}): string {
  if (event.actorEmail) return event.actorEmail
  if (event.actorDisplayName) return event.actorDisplayName
  if (event.actorId) return event.actorId
  return event.actorAuthMethod && event.outcome === 'denied' ? 'Unauthenticated' : 'system'
}

// Renders one `details`/`scope` value for display. A scalar (string/number/
// boolean/null — anything a JSON leaf value decodes to) prints as plain text
// so an email or role reads as operator@example.org, not "operator@example.org"
// — but a nested object/array (e.g. a grant's scope, {type: "AllClusters"})
// is rendered as real JSON via JSON.stringify, never a bare template-literal
// interpolation (which for an object would print "[object Object]", the
// frontend's own analogue of the backend's Go-map-syntax bug this same round
// fixed in internal/api/audit.go's summarizeDetails/formatDetailValue).
function formatDetailValue(v: unknown): string {
  if (v !== null && typeof v === 'object') {
    return JSON.stringify(v)
  }
  return String(v)
}

// One row of a `.fact-list` — a raw `details`/`scope` key as its <dt>, the
// formatted value as its <dd>. Broken out so both entry lists below render
// one dt/dd pair per field (the actual `.fact-list` pattern every other
// structured-data view in this codebase uses — ClusterDetailPage's
// FactsList, this same modal's own "Timestamp"/"Actor"/... rows above),
// instead of the previous single <dd> holding every field joined into one
// comma-separated string.
function FactRow({ label, children }: { label: string; children: string }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </>
  )
}

// Renders one event's full record (GET /api/v1/audit-events/{id}) in a
// modal — fetched lazily, only once opened, rather than upfront for every
// row in the page (most rows never get opened, and audit-events can be a
// large table). `details`/`scope` are free-form JSON (varies per write path
// — see internal/api/audit.go's doc comment) rendered as a flat key/value
// list via plain JSX interpolation, same as ClusterDetailPage's FactsList —
// never dangerouslySetInnerHTML (SR-17): these values ultimately trace back
// to admin-entered request bodies, not cluster/repo-supplied text, but the
// "always plain JSX, never raw HTML" rule applies uniformly regardless of
// source.
//
// A modal, not an inline expand-in-place table row (which is what this used
// to be) — direct user feedback: seeing the expanded detail required
// scrolling in a way that felt broken. Confirmed live before picking a fix:
// at a completely ordinary 1280px viewport, this table's own columns
// (timestamp/actor/action/target/outcome/details) already need ~1010px,
// more than the ~912px .table-scroll's clientWidth gets in this page's
// layout — so .table-scroll (index.css; a real, different overflow bug's
// fix, kept as-is here) was already showing a horizontal scrollbar before
// any row was ever expanded. The old inline detail row was a <td colSpan=6>
// *inside* that same table, so its rendered width was capped to the table's
// own (overflowing) width too: reading the expanded fact-list meant
// scrolling the table sideways to reach the right portion of it, and
// scrolling the page down to find/re-find the row on a long (50-row) page —
// two scroll axes at once for one piece of content. A modal sidesteps this
// structurally rather than patching around it: it's a fixed-position
// overlay, not part of the table's box model, so its content always wraps
// into the full modal width and only ever needs `.modal`'s own vertical
// scroll (`max-height: 90vh; overflow-y: auto`) — the same modal chrome
// ChangePasswordModal/EnrollTokenModal/ConfirmDecommissionModal already use,
// not a new pattern. Recaps timestamp/action/outcome up top (from the
// already-fetched list row, no extra request) since the modal covers the
// row it's about, unlike the old inline version which didn't need to.
function AuditEventDetailModal({
  event,
  accessToken,
  onClose,
}: {
  event: AuditEventSummary
  accessToken: string
  onClose: () => void
}) {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['audit-event', event.id],
    queryFn: () => getAuditEvent(event.id, accessToken),
  })

  const detailEntries = Object.entries(data?.details ?? {})
  const scopeEntries = Object.entries(data?.scope ?? {})

  return (
    <Dialog title="Audit event details" onClose={onClose} className="modal-data">
        <dl className="fact-list">
          <dt>Timestamp</dt>
          <dd title={event.occurredAt}>{formatDateTime(event.occurredAt)}</dd>
          <dt>Actor</dt>
          <dd>{actorLabel(event)}</dd>
          {/* BUGS.md 69 fixed exactly this conflation in the table and left
              it standing here: the modal headed a row "Action" and rendered
              `capability`, which is NULL for every system-raised event, so
              the row the reader opened *for* the detail was the one that
              said "—". `action` is the server-derived label the list column
              already uses (internal/api/audit.go's auditActionLabel), so the
              two surfaces now name the same thing. Capability keeps its own
              row, because "which permission authorised this" is a real and
              different question. */}
          <dt>Action</dt>
          <dd>{event.action || '—'}</dd>
          <dt>Capability</dt>
          <dd>{event.capability ?? '—'}</dd>
          <dt>Target</dt>
          <dd>{event.clusterDisplayName ?? event.clusterId ?? '—'}</dd>
          <dt>Outcome</dt>
          <dd>
            <OutcomeBadge outcome={event.outcome} />
          </dd>
        </dl>

        {isLoading && <p className="field-hint">Loading more details…</p>}

        {isError && (
          <p className="form-error" role="alert">
            {error instanceof ApiError
              ? error.detail
                ? `${error.message} — ${error.detail}`
                : error.message
              : 'Failed to load this audit event.'}
          </p>
        )}

        {data && (
          <dl className="fact-list">
            <dt>Actor auth method</dt>
            <dd>{data.actorAuthMethod || '—'}</dd>
            <dt>Source IP</dt>
            <dd>{data.sourceIp ?? '—'}</dd>

            {scopeEntries.length > 0 &&
              scopeEntries.map(([k, v]) => (
                <FactRow key={`scope-${k}`} label={`scope.${k}`}>
                  {formatDetailValue(v)}
                </FactRow>
              ))}

            {detailEntries.length > 0 ? (
              detailEntries.map(([k, v]) => (
                <FactRow key={`detail-${k}`} label={k}>
                  {formatDetailValue(v)}
                </FactRow>
              ))
            ) : (
              <>
                <dt>Details</dt>
                <dd>none recorded for this event</dd>
              </>
            )}

            <dt>Previous hash</dt>
            <dd className="fingerprint" title={data.prevHash}>
              {data.prevHash}
            </dd>
            <dt>Hash</dt>
            <dd className="fingerprint" title={data.hash}>
              {data.hash}
            </dd>
          </dl>
        )}
    </Dialog>
  )
}

export function AuditLogPage() {
  const { accessToken } = useAuth()
  const [searchParams, setSearchParams] = useSearchParams()

  // Draft filter inputs are kept separate from appliedFilters (the ones
  // actually in the query key) so typing into "actor" doesn't fire a request
  // per keystroke — the form below commits them on submit, which also resets
  // pagination back to page 1, since a different filter means a different
  // result set the existing cursorHistory no longer describes.
  const initialOutcome = searchParams.get('outcome')
  const [actorInput, setActorInput] = useState(searchParams.get('actor') ?? '')
  const [capabilityInput, setCapabilityInput] = useState(searchParams.get('capability') ?? '')
  const [clusterInput, setClusterInput] = useState(searchParams.get('cluster') ?? '')
  const [resourceInput, setResourceInput] = useState(searchParams.get('resource') ?? '')
  const [outcomeInput, setOutcomeInput] = useState<AuditEventSummary['outcome'] | ''>(
    initialOutcome === 'success' || initialOutcome === 'denied' || initialOutcome === 'error' ? initialOutcome : '',
  )
  // The URL carries UTC ISO strings (what the API takes); these two inputs are
  // `datetime-local`, i.e. local wall clock. Converting properly rather than
  // slicing the first 16 characters off the ISO string — see
  // toDatetimeLocalValue's doc comment for the drift that caused.
  const [sinceInput, setSinceInput] = useState(() => toDatetimeLocalValue(searchParams.get('since')))
  const [untilInput, setUntilInput] = useState(() => toDatetimeLocalValue(searchParams.get('until')))
  const [appliedFilters, setAppliedFilters] = useState<AuditEventFilters>(() => ({
    actor: searchParams.get('actor') || undefined,
    capability: searchParams.get('capability') || undefined,
    cluster: searchParams.get('cluster') || undefined,
    resource: searchParams.get('resource') || undefined,
    outcome: initialOutcome === 'success' || initialOutcome === 'denied' || initialOutcome === 'error' ? initialOutcome : undefined,
    since: searchParams.get('since') || undefined,
    until: searchParams.get('until') || undefined,
  }))

  // The cluster filter is a select, not free text — internal/api/audit.go's
  // `cluster` param is an exact match against an opaque cluster_id, not
  // something an operator would type from memory. Gated on cluster:read
  // (disabled, not hidden, with the missing capability named — same
  // discipline as every other capability-gated control in this codebase):
  // audit:read is super-admin-only and cluster:read is held far more
  // broadly, so this is a defensive floor, not an expected real case.
  const canReadClusters = useHasCapability(CAP_CLUSTER_READ)
  const clustersQuery = useQuery({
    queryKey: ['clusters'],
    queryFn: () => getClusters(accessToken!),
    enabled: !!accessToken && canReadClusters,
  })
  const clusterOptions = clustersQuery.data?.clusters ?? []

  // Keyset pagination (matches internal/api/audit.go's limit/cursor scheme,
  // chosen there over limit/offset because this table can grow unbounded).
  // cursorHistory[0] is always undefined (page 1, no cursor); each entry
  // after it is the nextCursor that led to that page, so "Previous" is just
  // walking back down this array rather than a second kind of request.
  //
  // In the URL now (CI-U5): each repeated ?cursor= is one step of that
  // history, so page 1 carries none and a shared link opens the same page.
  const cursorHistory = searchParams.getAll('cursor')
  const pageIndex = cursorHistory.length
  const cursor = cursorHistory[pageIndex - 1]
  function goToCursors(next: string[]) {
    const params = new URLSearchParams(searchParams)
    params.delete('cursor')
    for (const c of next) params.append('cursor', c)
    setSearchParams(params)
  }

  // The event currently open in AuditEventDetailModal, or null when no
  // modal is showing — holding the whole summary row (not just its id) so
  // the modal can recap timestamp/action/outcome immediately, without
  // waiting on its own GET /audit-events/{id} round trip.
  const [detailEvent, setDetailEvent] = useState<AuditEventSummary | null>(null)

  // Not gated on canRead. GET /audit-events requires audit:read server-side
  // (internal/api/audit.go), so the server's own 403 is the authoritative
  // answer — and it's the only signal that actually means "denied."
  // useHasCapability returns false for a permissions request that is still in
  // flight or that failed, exactly as it does for a real denial (it is
  // deny-by-default on purpose), so gating the fetch on it and rendering the
  // denial banner from it turned "we haven't checked yet" into a flat "you
  // don't have access," permanently for anyone whose permissions request
  // failed. UsersPage/ApprovalsPage/SettingsPage all key their denial off a
  // real 403 for this reason; this now matches them.
  const { data, isLoading, isError, isFetching, error } = useQuery({
    queryKey: ['audit-events', appliedFilters, cursor],
    queryFn: () => getAuditEvents(accessToken!, { ...appliedFilters, cursor, limit: PAGE_SIZE }),
    enabled: !!accessToken,
  })

  const events = data?.auditEvents ?? []
  const hasActiveFilters = Object.values(appliedFilters).some(Boolean)

  function applyFilters(e: FormEvent) {
    e.preventDefault()
    const nextFilters: AuditEventFilters = {
      actor: actorInput.trim() || undefined,
      capability: capabilityInput.trim() || undefined,
      cluster: clusterInput || undefined,
      resource: resourceInput.trim() || undefined,
      outcome: outcomeInput || undefined,
      since: fromDatetimeLocalValue(sinceInput),
      until: fromDatetimeLocalValue(untilInput),
    }
    setAppliedFilters(nextFilters)
    const nextParams = new URLSearchParams()
    Object.entries(nextFilters).forEach(([key, value]) => { if (value) nextParams.set(key, String(value)) })
    // A fresh nextParams carries no ?cursor=, which is the return to page 1.
    setSearchParams(nextParams, { replace: true })
    setDetailEvent(null)
  }

  function clearFilters() {
    setActorInput('')
    setCapabilityInput('')
    setClusterInput('')
    setResourceInput('')
    setOutcomeInput('')
    setSinceInput('')
    setUntilInput('')
    setAppliedFilters({})
    setSearchParams({}, { replace: true })
    setDetailEvent(null)
  }

  function goNext() {
    if (!data?.nextCursor) return
    goToCursors([...cursorHistory, data.nextCursor])
    setDetailEvent(null)
  }

  function goPrev() {
    if (pageIndex === 0) return
    goToCursors(cursorHistory.slice(0, -1))
    setDetailEvent(null)
  }

  if (isError && error instanceof ApiError && error.status === 403) {
    return (
      <div className="page">
        <header className="page-header">
          <h1>Audit log</h1>
        </header>
        <p className="banner banner-warning" role="alert">
          You don't have access to view the audit log. Missing capability: {CAP_AUDIT_READ}.
        </p>
      </div>
    )
  }

  return (
    <div className="page list-page audit-page">
      <header className="page-header list-page-header">
        <div>
          <h1>Audit log</h1>
          <p className="list-live-status" aria-live="polite">
            {/* BACKLOG D7b. This read "{n} events" over a single keyset page
                capped at PAGE_SIZE, so on page 3 it said "50 events" about a log
                with hundreds. A cursor-paged table cannot know a total — so it
                says what it actually has rather than implying a count it never
                fetched. */}
            <span>
              {events.length} {events.length === 1 ? 'event' : 'events'} on this page
              {data?.nextCursor ? ' · more available' : ''}
            </span>
            <span aria-hidden="true">·</span>
            <span>{isFetching ? 'Updating…' : 'Latest first'}</span>
          </p>
        </div>
      </header>

      <section className="list-card audit-list-card" aria-label="Audit events">
        <form onSubmit={applyFilters}>
          <div className="filter-bar">
            <div className="filter-field">
              <label htmlFor="audit-actor">Actor (email or ID)</label>
              <input
                id="audit-actor"
                type="text"
                value={actorInput}
                onChange={(e) => setActorInput(e.target.value)}
                placeholder="e.g. admin@localhost"
              />
            </div>

            <div className="filter-field">
              <label htmlFor="audit-outcome">Outcome</label>
              <select id="audit-outcome" value={outcomeInput} onChange={(e) => setOutcomeInput(e.target.value as AuditEventSummary['outcome'] | '')}>
                <option value="">All outcomes</option>
                <option value="success">Success</option>
                <option value="denied">Denied</option>
                <option value="error">Error</option>
              </select>
            </div>

            <div className="filter-field">
              {/* "Capability", not "Action (capability)". This filter matches the
                  capability column, and the table's Action column no longer shows
                  capabilities — it shows what happened. Leaving the old label would
                  invite typing "Login Succeeded" in here and getting nothing. */}
              <label htmlFor="audit-capability">
                Capability
                <HelpTip label="Capability" text="The fine-grained permission string this app checks on a write, e.g. cluster:accept or user:manage. Enter one exactly (case-sensitive). Note this filters on the capability a person exercised, which is not the same as the Action column: events the system raises on its own have an action but no capability, so they cannot be found with this filter." />
              </label>
              <input
                id="audit-capability"
                type="text"
                list="audit-common-actions"
                value={capabilityInput}
                onChange={(e) => setCapabilityInput(e.target.value)}
                placeholder="e.g. cluster:accept"
              />
              <datalist id="audit-common-actions">
                <option value="cluster:accept" />
                <option value="cluster:decommission" />
                <option value="incident:reanalyse" />
                <option value="remediation:approve" />
                <option value="remediation:reject" />
                <option value="user:manage" />
                <option value="user:remove" />
                <option value="org:settings:write" />
              </datalist>
            </div>

            <div className="filter-field">
              <label htmlFor="audit-cluster">Cluster</label>
              <select
                id="audit-cluster"
                value={clusterInput}
                onChange={(e) => setClusterInput(e.target.value)}
                disabled={!canReadClusters}
                title={canReadClusters ? undefined : `Missing capability: ${CAP_CLUSTER_READ}`}
              >
                <option value="">All clusters</option>
                {clusterOptions.map((cluster) => (
                  <option key={cluster.id} value={cluster.id}>{cluster.displayName}</option>
                ))}
              </select>
            </div>

            <div className="filter-field">
              <label htmlFor="audit-resource">
                Resource
                <HelpTip label="Resource" text="Matches the Kubernetes object an event named directly, or the object of the incident an event references (e.g. a remediation approval or execution) — a namespace or object name is enough, the full gvk|namespace|name key isn't required. Events with no object at all — settings, sign-ins, user/grant changes, cluster lifecycle — have nothing to match and never appear here." />
              </label>
              <input
                id="audit-resource"
                type="text"
                value={resourceInput}
                onChange={(e) => setResourceInput(e.target.value)}
                placeholder="e.g. checkout-worker"
              />
            </div>

            <div className="filter-field">
              <label htmlFor="audit-since">Since</label>
              <input
                id="audit-since"
                type="datetime-local"
                value={sinceInput}
                onChange={(e) => setSinceInput(e.target.value)}
              />
            </div>

            <div className="filter-field">
              <label htmlFor="audit-until">Until</label>
              <input
                id="audit-until"
                type="datetime-local"
                value={untilInput}
                onChange={(e) => setUntilInput(e.target.value)}
              />
            </div>

            <div className="filter-actions">
              <button type="submit">
                <FilterIcon />
                Apply filters
              </button>
              <button type="button" className="secondary" onClick={clearFilters}>
                Clear filters
              </button>
            </div>
          </div>
        </form>
        {hasActiveFilters && (
          <div className="applied-filter-chips" aria-label="Applied filters">
            {Object.entries(appliedFilters).map(([key, value]) => value && <span key={key} className="badge badge-blue">{key}: {String(value)}</span>)}
          </div>
        )}

        {isLoading && (
        <div className="table-scroll">
          {/* BACKLOG D7g. Was a bare `cluster-table` — the loaded table below
              is `cluster-table list-table audit-table`, and the missing
              classes changed padding/border on the exact frame this skeleton
              exists to hold steady. */}
          <table className="cluster-table list-table audit-table" aria-busy="true">
            <thead>
              <tr>
                <th>Event</th>
                <th>Actor</th>
                <th>Outcome</th>
                <th className="col-time">When</th>
                <th className="table-pinned-actions">Details</th>
              </tr>
            </thead>
            <tbody>
              <SkeletonTableRows columns={5} />
            </tbody>
          </table>
        </div>
        )}

        {isError && (
        <p className="form-error" role="alert">
          {error instanceof ApiError
            ? error.detail
              ? `${error.message} — ${error.detail}`
              : error.message
            : 'Failed to load audit events.'}
        </p>
        )}

        {/* BACKLOG D7i. "No audit events match these filters" used to be the
            one message for both a real filtered-empty result AND a genuinely
            empty log — collapsing "try different filters" and "nothing has
            happened yet" into the same sentence for a reader who cannot tell
            which is true. `hasActiveFilters` (already computed above for the
            filter-chip row) is the honest signal to split on. */}
        {!isLoading && !isError && events.length === 0 && (
        <EmptyState variant="audit">
          {hasActiveFilters
            ? 'No audit events match these filters. Try a wider time range or clear a filter.'
            : 'No audit events recorded yet. Every write this API accepts — sign-ins, grants, approvals, settings changes — appears here as it happens.'}
        </EmptyState>
        )}

        {!isLoading && events.length > 0 && (
        <div className="table-scroll">
          <table className="cluster-table list-table audit-table">
            <thead>
              <tr>
                <th>Event</th>
                <th>Actor</th>
                <th>Outcome</th>
                <th className="col-time">When</th>
                <th className="table-pinned-actions">Details</th>
              </tr>
            </thead>
            <tbody>
              {events.map((ev) => (
                <tr key={ev.id}>
                  {/* BACKLOG D7h, then D7k. Mode A ("Audit log" is one of
                      screens.md's named triage-scan screens): the leading
                      cell is identity, not a timestamp. D7h originally folded
                      actor/action/target into one `.identity-block` — actor as
                      the name line, action as the "kind" line, target as the
                      "fault" line. Owner feedback (D7k): three stacked lines in
                      one cell read as cramped. The action/target pairing is
                      still worth keeping together (kind+fault below), but the
                      actor line now gets its own column, right after Event. */}
                  <td>
                    <div className="identity-block">
                      {/* The action, not the capability. Used to render
                          `capability`, which is NULL for every event the
                          system raises on its own — so it read "—" on
                          exactly the rows whose action name was interesting.
                          See auditActionLabel. */}
                      <span className="identity-block-kind">{ev.action || '—'}</span>
                      <span className="identity-block-fault">
                        {ev.clusterDisplayName ?? ev.clusterId ?? '—'}
                      </span>
                    </div>
                  </td>
                  <td>
                    {/* Plain text, not `.identity-block`: this is one string
                        (an email, a display name, an id, or "Unauthenticated"/
                        "system"), not an entity with a kind/fault pair, so the
                        block's stacked layout would just add empty lines.
                        `.audit-cell-truncate` (already in this file, used by
                        TolerationsPage for the same shape of problem — an
                        unpredictable-length string with no other cap) bounds
                        it with a title tooltip for the full value; the base
                        `.col-truncate`'s 110px is tuned for a table that
                        already shows the value in full on a second line
                        (`.users-table`), which this column doesn't. */}
                    <span className="audit-cell-truncate" title={actorLabel(ev)}>
                      {actorLabel(ev)}
                    </span>
                  </td>
                  <td>
                    <OutcomeBadge outcome={ev.outcome} />
                  </td>
                  <td className="col-time" title={ev.occurredAt}>
                    {formatDateTime(ev.occurredAt)}
                  </td>
                  {/* The button, and nothing else.
                      
                      This cell used to also carry `detailsSummary`, an inline preview
                      of the details blob, added on the reasoning that BUGS.md 27 had
                      removed raw content without restoring a readable replacement.
                      In practice it read as stray data rather than as a summary, and
                      for a concrete reason: it is a generic `key=value` dump of
                      whatever that write path happened to record, sorted
                      ALPHABETICALLY rather than by usefulness. On a
                      toleration-suppression row that put `detectorId=k8s-sweep`
                      first — which tells an operator nothing — while the one useful
                      field, `reason=ServiceNoEndpoints`, sat fifth and was truncated
                      away. It also put internal identifiers into a scan-level view: a
                      64-character fingerprint hash, a pipe-delimited object key, a
                      `tol_` id.
                      
                      The information it existed to provide is not lost. The action
                      name now populates the Action column, where the header already
                      promised it and where it is one value rather than the head of a
                      dump; the full blob is one click away in the modal, which is the
                      surface built for it. */}
                  <td className="audit-details-cell table-pinned-actions">
                    <button type="button" className="secondary" onClick={() => setDetailEvent(ev)}>
                      Details
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        )}

        <div className="list-pagination">
        <span className="pagination-status">Page {pageIndex + 1}</span>
        <div className="page-header-actions">
          <button type="button" className="secondary" onClick={goPrev} disabled={pageIndex === 0}>
            Previous
          </button>
          <button type="button" onClick={goNext} disabled={!data?.nextCursor}>
            Next
          </button>
        </div>
        </div>
      </section>

      {detailEvent && (
        <AuditEventDetailModal
          event={detailEvent}
          accessToken={accessToken!}
          onClose={() => setDetailEvent(null)}
        />
      )}
    </div>
  )
}
