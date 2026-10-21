import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { ApiError, getClusters, listChanges, rollbackExecution } from '../api/client'
import type { Change } from '../api/types'
import {
  CAP_ANALYSIS_READ,
  CAP_INCIDENT_READ,
  CAP_REMEDIATION_EXECUTE_INPLACE,
  CAP_REMEDIATION_ROLLBACK,
} from '../api/capabilities'
import { missingCapabilityMessage } from '../api/capabilityInfo'
import { useAuth } from '../auth/useAuth'
import { useMissingCapabilities } from '../auth/useCapabilities'
import { Dialog } from '../components/Dialog'
import { EmptyState } from '../components/EmptyState'
import { SkeletonTableRows } from '../components/Skeleton'
import { TablePagination } from '../components/TablePagination'
import { useUrlPagination } from '../fleet/useUrlPagination'
import { useSearchParamsWriter } from '../hooks/useUrlState'
import { formatDateTime, formatRelativeTime } from '../utils/time'
import { SLOW_FALLBACK_MS } from '../realtime/refresh'
import { HelpTip } from '../components/HelpTip'

// Recent changes — the front door for undo.
//
// # Why this screen exists
//
// Undo already worked. POST /api/v1/executions/{id}/rollback has been real
// since BACKLOG.md R1, and an incident's own remediation card has offered it
// since. But reaching it required already knowing WHICH INCIDENT made the
// change, and an operator's actual starting point is "something changed
// production on Tuesday". Incidents are listed by what broke; the audit log is
// an append-only record of every request including reads. Neither answers
// "what did ARGUS do to my clusters, and can I put it back".
//
// # Screen mode: A, triage scan (argus-design-system reference/screens.md)
//
// Time-ordered, densest-mode list; the reader is scanning for the one row that
// matters. Not a worklist — no row owes this viewer a decision, the undo is
// available rather than required — and not a fleet aggregate, so there is no
// tile row and no chart. The leading cell is identity (what was changed),
// never a coloured pill.
//
// Mode F (first-run/empty) supplies the three distinct empty states, which are
// three genuinely different facts and three different next actions:
//
//   - ARGUS has never changed anything (hasAnyChanges === false).
//   - It has, but not in this window.
//   - It has, but not on this cluster in this window.
//
// # Everything on this screen traces to a field
//
// The count is the returned array's own length with its window stated, and the
// truncation caveat travels with it. There is deliberately no "changes this
// week vs. last", no success rate and no mean-time-anything: nothing on the
// payload supports them, and the endpoint computes no aggregate.
//
// # The undo control
//
// Two gates, and they read differently because they are different problems
// (argus-design-system reference/components.md, the approval control's rule):
//
//   - MAY THIS VIEWER undo — capability. Disabled with the missing capability
//     named in human words, never hidden (lld/11 §6).
//   - MAY THIS CHANGE be undone — the hub's own answer, computed by
//     rollback.go's checkUndoable and carried on `change.undo`. Rendered
//     verbatim; this screen never paraphrases an undo refusal, because a
//     second copy of a safety rule is how one of them ends up wrong.
//
// The confirmation is a modal naming the specific cluster, the specific target
// and what the undo will set it back to. An undo is a real mutation of a
// production cluster reached from a list, not from the incident that explains
// it, so the incident card's inline arm-then-click is not enough here.

const WINDOW_OPTIONS = [
  { hours: 24, label: 'Last 24 hours' },
  { hours: 168, label: 'Last 7 days' },
  { hours: 720, label: 'Last 30 days' },
  { hours: 2160, label: 'Last 90 days' },
]

// Matches internal/api/changes.go's changesDefaultWindowHours. A week: long
// enough that "something changed on Tuesday" is answerable on a Friday.
const DEFAULT_WINDOW_HOURS = 168

function windowLabel(hours: number): string {
  return (WINDOW_OPTIONS.find((o) => o.hours === hours)?.label ?? `Last ${hours} hours`).toLowerCase()
}

// The identity cell. What was changed, before any status colour.
//
// An in-place change identifies itself by the object it patched; a repository
// change by the file it edited, because that is what actually changed — the
// object came back through the GitOps controller afterwards. Both carry the
// plain-language summary the hub rendered, never a raw action type.
function ChangeIdentity({ change }: { change: Change }) {
  const target = [change.targetNamespace, change.targetName].filter(Boolean).join('/')
  // targetGvk is "apps/v1/Deployment"; the kind is the readable part.
  const kind = (change.targetGvk ?? '').split('/').pop() ?? ''

  if (change.kind === 'pullRequest') {
    const [first, ...rest] = change.filePaths ?? []
    const more = rest.length > 0 ? ` · +${rest.length} more` : ''
    // The workload leads when the hub knows it, and the file moves to the
    // second line rather than being dropped. This row used to lead with the
    // path alone, and the asymmetry was the gap: an operator scanning "what
    // changed on production" read `argus-gitops-rke2/api` on an in-place row
    // and `apps/api/deployment.yaml` on a repository row, and had to already
    // know which workload that file declares to connect the two. Both now
    // answer the same question the same way, from the same stored columns.
    //
    // The file is NOT dropped, because it is still what physically changed —
    // the object came back through the GitOps controller afterwards, and the
    // reviewer who has to go and read the merge needs the path.
    //
    // Falls back to the old file-led shape when no OpenPR recommendation is
    // recorded (the self-service route's normal case). The fallback is a
    // different TRUE answer, never a placeholder standing where the workload
    // would be.
    if (target) {
      return (
        <div className="identity-block">
          <span className="identity-block-name">{target}</span>
          <span className="identity-block-kind">
            {kind || change.targetGvk}
            {first ? ` · ${first}${more}` : ' · via repository'}
          </span>
          <span className="identity-block-fault">{change.summary}</span>
        </div>
      )
    }
    return (
      <div className="identity-block">
        <span className="identity-block-name">{first ?? `Pull request #${change.pullRequestNumber ?? ''}`}</span>
        <span className="identity-block-kind">{first ? `Repository file${more}` : 'Repository change'}</span>
        <span className="identity-block-fault">{change.summary}</span>
      </div>
    )
  }
  return (
    <div className="identity-block">
      <span className="identity-block-name">{target || change.targetName || '—'}</span>
      <span className="identity-block-kind">{kind || change.targetGvk || 'Live object'}</span>
      <span className="identity-block-fault">{change.summary}</span>
    </div>
  )
}

// Outcome as a word first and a colour second — never colour alone
// (lld/11 §8). 'unknown' is amber and its own branch, not folded into failed:
// a change that could not be confirmed either way is not the same claim as one
// that definitely did not apply.
function OutcomeCell({ change }: { change: Change }) {
  if (change.kind === 'pullRequest') {
    // Branch on STATUS, not on kind. This cell rendered an unconditional green
    // "Merged" for every pull-request row, which was true while the feed
    // carried merged ones only and becomes a false claim the moment an open one
    // appears — the single most important fact on the row, asserted backwards.
    //
    // Grey, not amber: an open pull request is not a warning and not a degraded
    // outcome. It is work that has not happened. Amber on this screen already
    // means "ARGUS could not confirm this applied", and reusing it here would
    // put two unrelated meanings on one colour. The WORD carries it either way
    // — the badge is an addition to "Open", never a replacement for it.
    const proposed = change.status === 'proposed'
    return (
      <>
        <span className={proposed ? 'badge badge-gray' : 'badge badge-green'}>
          {proposed ? 'Open — not merged' : 'Merged'}
        </span>
        {change.pullRequestUrl && (
          <>
            {' '}
            <a href={change.pullRequestUrl} target="_blank" rel="noreferrer noopener">
              #{change.pullRequestNumber}
            </a>
          </>
        )}
        {proposed && <p className="field-hint">Nothing has changed on the cluster yet — merging it is what applies the change.</p>}
      </>
    )
  }
  if (change.outcome === 'succeeded') return <span className="badge badge-green">Applied</span>
  if (change.outcome === 'unknown') {
    return (
      <>
        <span className="badge badge-amber">Outcome unknown</span>
        <p className="field-hint">{change.error || 'ARGUS could not confirm whether this applied — check the cluster directly.'}</p>
      </>
    )
  }
  return (
    <>
      <span className="badge badge-red">Failed</span>
      {change.error && <p className="field-hint">{change.error}</p>}
    </>
  )
}

// Who. Three genuinely different answers, and a fabricated one would matter
// here more than almost anywhere: "who changed production" is the question
// this column exists for.
function AppliedByCell({ change }: { change: Change }) {
  if (change.unattended) {
    return (
      <>
        <span className="badge badge-blue">Unattended</span>
        <p className="field-hint">Applied by ARGUS with no human decision.</p>
      </>
    )
  }
  // "Who applied this" has no answer yet on a proposed row, and the honest
  // answer is that nobody has — which is a different statement from the
  // "not recorded here" below it, and the difference decides what the reader
  // does next. Answering the question at all here would be attributing an
  // application that has not happened.
  if (change.status === 'proposed') {
    return (
      <>
        <span className="text-muted">Nobody yet</span>
        <p className="field-hint">Whoever merges the pull request applies this.</p>
      </>
    )
  }
  if (change.actorEmail) return <span>{change.actorEmail}</span>
  return (
    <>
      <span className="text-muted">Not recorded here</span>
      <p className="field-hint">
        {change.kind === 'pullRequest'
          ? 'A change opened through the repository panel records its actor in the audit log rather than as an approval.'
          : 'No approval decision is stored against this execution.'}
      </p>
    </>
  )
}

// countLabel keeps "changed" and "proposed" as separate counts — see its call
// site. Landed and proposed are the only two statuses, so the two add up to the
// list and neither is a partial.
function countLabel(items: Change[], window: string): string {
  const proposed = items.filter((c) => c.status === 'proposed').length
  const landed = items.length - proposed
  const landedText = `${landed} change${landed === 1 ? '' : 's'}`
  if (proposed === 0) return `${landedText} in the ${window}`
  const proposedText = `${proposed} open pull request${proposed === 1 ? '' : 's'}`
  if (landed === 0) return `${proposedText} in the ${window}, nothing changed yet`
  return `${landedText} and ${proposedText} in the ${window}`
}

// The "When" column. See its call site for why the word is not optional.
function ChangedAtCell({ change }: { change: Change }) {
  const at = change.changedAt ?? change.proposedAt
  if (!at) return <span className="text-muted">Not recorded</span>
  return (
    <span title={formatDateTime(at)}>
      {/* Only the proposed row is labelled, and deliberately only that one.
          Labelling the landed row "Changed" to match would overstate a FAILED
          in-place execution, which is landed (it reached the cluster) but
          changed nothing — a word this column would be putting directly beside
          the Outcome cell's own "Failed". The landed row keeps the bare
          relative time it has always carried; Outcome is what qualifies it. */}
      {change.changedAt ? null : 'Opened '}
      {formatRelativeTime(at)}
    </span>
  )
}

function UndoCell({
  change,
  missingCapabilities,
  onUndo,
}: {
  change: Change
  missingCapabilities: string[]
  onUndo: (change: Change) => void
}) {
  if (!change.undo.available) {
    // The hub's own refusal, in full. Both halves are shown: the short reason
    // as the control's replacement, and the detail underneath, because the
    // detail is where the next action lives ("re-analyse the incident", "wait
    // for the in-flight execution", "revert the merge in the repository").
    return (
      <>
        <span className="text-muted">{change.undo.reason ?? 'No undo'}</span>
        {change.undo.detail && <p className="field-hint">{change.undo.detail}</p>}
      </>
    )
  }

  // Disabled, never hidden: a viewer who cannot undo still has to be able to
  // discover that the control exists and what to ask for.
  const capabilityReason = missingCapabilities.length > 0 ? missingCapabilityMessage(missingCapabilities) : undefined
  return (
    <>
      <button
        type="button"
        className="secondary"
        disabled={!!capabilityReason}
        title={capabilityReason ?? `Undo: ${change.undo.description}`}
        onClick={() => onUndo(change)}
      >
        Undo…
      </button>
      {capabilityReason ? (
        <p className="field-hint">{capabilityReason}</p>
      ) : (
        <p className="field-hint">{change.undo.description}</p>
      )}
    </>
  )
}

// The confirmation. Names the cluster, the target and the exact consequence,
// and says the thing an operator reaching for undo from a list most needs to
// hear: this reverses ARGUS's change, it does not fix the original problem.
function UndoDialog({ change, onClose }: { change: Change; onClose: () => void }) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const mutation = useMutation({
    mutationFn: () => rollbackExecution(change.undo.executionId!, {}, accessToken!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['changes'] })
      queryClient.invalidateQueries({ queryKey: ['incident', change.incidentId] })
      queryClient.invalidateQueries({ queryKey: ['incidents'] })
    },
  })

  if (mutation.isSuccess) {
    return (
      <Dialog title="Change undone" onClose={onClose}>
        <p>
          <span className="badge badge-gray">Undone</span> {mutation.data.undid} — incident{' '}
          <Link to={`/incidents/${change.incidentId}`}>{change.incidentId}</Link> is now{' '}
          {mutation.data.incidentState}.
        </p>
        <p className="field-hint">
          The original problem is still there. The undo reversed what ARGUS did; it did not
          re-diagnose anything.
        </p>
        <div className="modal-actions">
          <button type="button" onClick={onClose}>
            Close
          </button>
        </div>
      </Dialog>
    )
  }

  const target = [change.targetNamespace, change.targetName].filter(Boolean).join('/')
  return (
    <Dialog title="Undo this change?" onClose={onClose}>
      <p>
        ARGUS will <strong>{change.undo.description}</strong> on{' '}
        <strong>{target || change.targetName}</strong> in cluster{' '}
        <strong>{change.clusterName}</strong>.
      </p>
      {/* prose-ok: a live mutation's consequence statement, in its confirmation dialog */}
      <p className="field-hint">
        Those are the values ARGUS read off the live object immediately before it made the change.
        This is a real mutation of a running cluster: the hub re-resolves the target, takes a fresh
        resourceVersion precondition, re-checks every bound and dry-runs it first, and will refuse
        if something else has moved the field since.
      </p>
      <p className="field-hint">
        It reverses what ARGUS did. It does not fix the original problem, which will still be there
        afterwards — see{' '}
        <Link to={`/incidents/${change.incidentId}`}>the incident</Link> for what that was.
      </p>
      {mutation.isError && (
        // Shown in full. Every refusal here names something the operator needs
        // and that this screen could not know in advance: the value has moved,
        // the change is already gone, the agent is disconnected.
        <p className="form-error" role="alert">
          {mutation.error instanceof ApiError
            ? mutation.error.detail || mutation.error.message
            : 'Could not apply the undo.'}
        </p>
      )}
      <div className="modal-actions">
        <button type="button" className="secondary" disabled={mutation.isPending} onClick={onClose}>
          Cancel
        </button>
        <button type="button" className="danger" disabled={mutation.isPending} onClick={() => mutation.mutate()}>
          {mutation.isPending ? 'Applying…' : `Yes — ${change.undo.description}`}
        </button>
      </div>
    </Dialog>
  )
}

export function RecentChangesPage() {
  const { accessToken } = useAuth()
  const [searchParams] = useSearchParams()
  const [undoTarget, setUndoTarget] = useState<Change | null>(null)

  const clusterId = searchParams.get('clusterId') ?? ''
  const requestedWindow = Number(searchParams.get('windowHours'))
  const windowHours = WINDOW_OPTIONS.some((o) => o.hours === requestedWindow)
    ? requestedWindow
    : DEFAULT_WINDOW_HOURS

  // The read gate, checked here so the page can SAY why it is empty rather
  // than rendering a query error. Same pair the route enforces.
  const readGate = useMissingCapabilities([CAP_INCIDENT_READ, CAP_ANALYSIS_READ])
  const canRead = readGate.resolved && readGate.missing.length === 0

  // The undo gate is separate and is NOT a reason to hide anything: a viewer
  // who may read this list but not undo sees every row, with the control
  // disabled and the missing capability named.
  const undoGate = useMissingCapabilities([CAP_REMEDIATION_ROLLBACK, CAP_REMEDIATION_EXECUTE_INPLACE])

  const clustersQuery = useQuery({
    queryKey: ['clusters'],
    queryFn: () => getClusters(accessToken!),
    enabled: !!accessToken,
  })

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['changes', { windowHours, clusterId: clusterId || undefined }],
    queryFn: () => listChanges({ windowHours, clusterId: clusterId || undefined }, accessToken!),
    enabled: !!accessToken && canRead,
    // A change lands when an approval or a merge sweeper commits, not when the
    // viewer acts — and both of those publish IncidentUpdated, which refreshes
    // ['changes'] (realtime/refresh.ts). Slow fallback underneath: nobody is
    // waiting on this screen the way they wait on the approval queue.
    refetchInterval: SLOW_FALLBACK_MS,
  })

  const changes = data?.changes ?? []
  const [, writeParams] = useSearchParamsWriter()
  const { visibleItems, resetToFirstPage, pagination } = useUrlPagination(changes)

  function setParam(key: string, value: string) {
    // Through the composing writer: resetToFirstPage below writes the URL
    // too, and two plain setSearchParams calls in one handler keep only the
    // second (hooks/useUrlState.ts).
    writeParams((next) => {
      if (value) next.set(key, value)
      else next.delete(key)
    })
    // Narrowing the list while parked on page 3 otherwise shows an empty table
    // until the clamp catches up — usePagination's own note on this.
    resetToFirstPage()
  }

  return (
    <div className="page list-page">
      <header className="page-header list-page-header">
        <div>
          <h1>Recent changes</h1>
          <p className="list-live-status">
            <span>
              {!canRead ? (
                // A capability-gated count renders as restricted, never as a
                // reassuring zero.
                <span className="value-restricted">
                  {readGate.resolved ? 'Restricted' : 'Checking your access…'}
                </span>
              ) : isLoading ? (
                'Loading…'
              ) : isError ? (
                // Never a count we do not have: an em dash says "unknown",
                // a zero would say "ARGUS changed nothing".
                '—'
              ) : data?.truncated ? (
                `More than ${changes.length} items in the ${windowLabel(windowHours)} — showing the ${changes.length} most recent`
              ) : (
                // Counted separately, because they are not the same claim. A
                // single "4 changes" over a list holding three merged changes
                // and one open pull request asserts that ARGUS altered four
                // things, and one of them it has not touched at all. The
                // proposed clause appears only when there ARE proposals, so
                // the ordinary case reads exactly as it always has rather than
                // carrying a permanent "and 0 open".
                countLabel(changes, windowLabel(windowHours))
              )}
            </span>
          </p>
        </div>
      </header>

      <p className="field-hint">
        Every change ARGUS has made to a cluster, in place or by a merged pull request.{' '}
        <HelpTip
          label="what is listed"
          text="Pull requests still waiting to be merged are listed too, marked Open — not merged: those have changed nothing yet, and merging one is what applies it. Undoing a change reverses what ARGUS did; it does not fix the problem that prompted it."
        />
      </p>

      {!canRead && readGate.resolved && (
        <p className="form-error" role="alert">
          {missingCapabilityMessage(readGate.missing)}
        </p>
      )}

      {canRead && isError && (
        <p className="form-error" role="alert">
          {error instanceof ApiError
            ? error.detail
              ? `${error.message} — ${error.detail}`
              : error.message
            : 'Failed to load recent changes.'}
        </p>
      )}

      {canRead && !isError && (
        <section className="list-card" aria-label="Recent changes">
          <div className="list-toolbar">
            <label className="list-filter-field">
              <span className="visually-hidden">Filter by cluster</span>
              <select value={clusterId} onChange={(event) => setParam('clusterId', event.target.value)}>
                <option value="">All clusters</option>
                {(clustersQuery.data?.clusters ?? []).map((cluster) => (
                  <option key={cluster.id} value={cluster.id}>
                    {cluster.displayName}
                  </option>
                ))}
              </select>
            </label>
            <label className="list-filter-field">
              <span className="visually-hidden">Time window</span>
              <select value={windowHours} onChange={(event) => setParam('windowHours', event.target.value)}>
                {WINDOW_OPTIONS.map((option) => (
                  <option key={option.hours} value={option.hours}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>
            {/* Both filters above are request parameters, not a pass over the
                fetched array: the list is capped server-side, so narrowing it
                here would show the selection's share of the global
                most-recent-N rather than its own.

                No `.list-result-count` here, unlike the other list toolbars:
                the header above already states the count WITH its window and
                its truncation caveat, and a second copy of the same number is
                two figures that have to agree by hand. */}
          </div>

          <div className="table-scroll">
            <table className="cluster-table list-table">
              <thead>
                <tr>
                  {/* "What", not "What changed": the column now also heads
                      rows for pull requests that have NOT changed anything,
                      and a header is a claim about every row under it. */}
                  <th>What</th>
                  <th>How</th>
                  <th>Outcome</th>
                  <th>Cluster</th>
                  <th>Applied by</th>
                  <th>When</th>
                  <th>Undo</th>
                </tr>
              </thead>
              <tbody>
                {isLoading && <SkeletonTableRows columns={7} />}
                {!isLoading && changes.length === 0 && (
                  <tr>
                    <td colSpan={7}>
                      {/* Three different facts, three different messages. A
                          single "no changes" would tell a new install it has a
                          filter problem and an established one that nothing has
                          ever happened. */}
                      {data?.hasAnyChanges === false ? (
                        <EmptyState variant="incidents">
                          ARGUS has not changed anything yet. An applied remediation or a merged pull
                          request appears here.
                        </EmptyState>
                      ) : clusterId ? (
                        <p className="empty-state">
                          No changes on this cluster in the {windowLabel(windowHours)}. ARGUS has
                          changed something somewhere — widen the window, or{' '}
                          <button type="button" className="link-button" onClick={() => setParam('clusterId', '')}>
                            show all clusters
                          </button>
                          .
                        </p>
                      ) : (
                        <p className="empty-state">
                          No changes in the {windowLabel(windowHours)}. ARGUS has changed something
                          before now — widen the window above to find it.
                        </p>
                      )}
                    </td>
                  </tr>
                )}
                {!isLoading &&
                  visibleItems.map((change) => (
                    <tr key={change.id}>
                      <td>
                        <ChangeIdentity change={change} />
                      </td>
                      <td>
                        {/* The channel, which decides how the change can be
                            reversed at all — an in-place patch is undone in the
                            cluster, a merged pull request only in the
                            repository. Word plus badge, never colour alone. */}
                        <span
                          className={
                            change.kind === 'pullRequest' ? 'route-badge route-badge-blue' : 'route-badge route-badge-amber'
                          }
                        >
                          {change.kind === 'pullRequest' ? 'Pull request' : 'In place'}
                        </span>
                      </td>
                      <td>
                        <OutcomeCell change={change} />
                      </td>
                      <td>
                        <Link to={`/clusters/${change.clusterId}`}>{change.clusterName}</Link>
                      </td>
                      <td>
                        <AppliedByCell change={change} />
                      </td>
                      <td>
                        {/* Exactly one of the two timestamps is present, and
                            the WORD says which — "Merged 3h ago" and "Opened 3h
                            ago" are different facts and this column must not
                            render them identically. A row with neither (which
                            the hub cannot produce) says so rather than
                            formatting `undefined` into a plausible date. */}
                        <ChangedAtCell change={change} />
                        <p className="field-hint">
                          <Link to={`/incidents/${change.incidentId}`}>Open incident</Link>
                        </p>
                      </td>
                      <td>
                        <UndoCell
                          change={change}
                          missingCapabilities={undoGate.resolved ? undoGate.missing : [CAP_REMEDIATION_ROLLBACK, CAP_REMEDIATION_EXECUTE_INPLACE]}
                          onUndo={setUndoTarget}
                        />
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>

          {/* `truncated` so the footer reads "of 12+" rather than claiming a
              total the server never sent — the window holds more than the
              endpoint returned, and a bare "of 12" would be an unlabelled
              partial. */}
          {!isLoading && changes.length > 0 && (
            <TablePagination {...pagination} truncated={data?.truncated ?? false} />
          )}
        </section>
      )}

      {undoTarget && <UndoDialog change={undoTarget} onClose={() => setUndoTarget(null)} />}
    </div>
  )
}
