// The triage group of the incident-detail screen: the resolve/dismiss/
// tolerate close-out controls, the pull-request record, and the numbered
// StageCard shell every lifecycle stage renders inside — split out of
// IncidentDetailPage.tsx (PROJECT.md P25) with no behavior change. See that
// file's own header for the screen this panel belongs to.
import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { resolveIncident, dismissIncident, tolerateIncident, ApiError } from '../../api/client'
import type { IncidentPullRequest, IncidentState } from '../../api/types'
import { Dialog } from '../../components/Dialog'
import { ActionMenu } from '../../components/ActionMenu'
import { useAuth } from '../../auth/useAuth'
import { formatDateTime, formatRelativeTime } from '../../utils/time'
import { isClosedIncidentState } from '../../utils/incidents'

// TriageControls is the human close-out: "this is fixed" and "this needs no
// action". It exists because most incidents never produce a remediation plan
// to approve — five of the seven fault types driven end to end had no
// executable fix — so approve/reject could never be the only way to clear the
// list. Before these controls, an operator who fixed a problem by hand had no
// way to say so, and the incident list could only grow.
//
// Every close-out confirms in a dialog, because all three are terminal: a
// one-click "Mark resolved" in a menu closed incidents by accident. Dismiss
// requires a note (the hub 400s without one) because it means a real problem
// will be ignored; resolve's note is optional, matching the hub, because "I
// fixed it" is usually self-evident from the state change plus actor in the
// audit log.
export function TriageControls({
  incidentId,
  state,
  disabledReason,
  toleranceDisabledReason,
}: {
  incidentId: string
  // Narrowed from `string` so isClosedIncidentState below is checked against
  // the real vocabulary rather than against any string that happens to arrive.
  state: IncidentState
  disabledReason?: string
  toleranceDisabledReason?: string
}) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const [resolving, setResolving] = useState(false)
  const [dismissing, setDismissing] = useState(false)
  const [tolerating, setTolerating] = useState(false)
  const [note, setNote] = useState('')
  const [toleranceNote, setToleranceNote] = useState('')
  const [toleranceAllReasons, setToleranceAllReasons] = useState(false)
  const [toleranceExpiryDays, setToleranceExpiryDays] = useState('')

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['incidents', incidentId] })
    queryClient.invalidateQueries({ queryKey: ['incidents'] })
  }
  const resolveMutation = useMutation({
    mutationFn: () => resolveIncident(incidentId, accessToken!, note.trim() || undefined),
    onSuccess: () => { setResolving(false); setNote(''); invalidate() },
  })
  const dismissMutation = useMutation({
    mutationFn: () => dismissIncident(incidentId, note.trim(), accessToken!),
    onSuccess: () => { setDismissing(false); setNote(''); invalidate() },
  })
  const tolerateMutation = useMutation({
    mutationFn: () =>
      tolerateIncident(incidentId, accessToken!, {
        note: toleranceNote.trim(),
        allReasons: toleranceAllReasons,
        expiresInSeconds: toleranceExpiryDays ? Number(toleranceExpiryDays) * 24 * 60 * 60 : undefined,
      }),
    onSuccess: () => {
      setTolerating(false)
      setToleranceNote('')
      setToleranceAllReasons(false)
      setToleranceExpiryDays('')
      invalidate()
    },
  })
  const pending = resolveMutation.isPending || dismissMutation.isPending || tolerateMutation.isPending
  const err = resolveMutation.error ?? dismissMutation.error ?? tolerateMutation.error

  // Nothing to render on a closed incident — NOT a sentence explaining that.
  // This used to return a `.detail-note` paragraph, which landed inside
  // `.incident-summary-actions`: a full sentence in a row sized for two badges
  // and two buttons, so on every Resolved/Dismissed incident the whole action
  // group wrapped onto its own line and the sentence ran to the page's right
  // edge — the same "the buttons are nowhere near the layout" failure the head
  // row was just fixed for, in the state nobody had looked at.
  //
  // The state itself is already on screen in the StateBadge beside this. What
  // the sentence adds — that closing is final, and that recurrence opens a NEW
  // incident rather than reopening this one — is real and worth keeping, so it
  // moves to the strip's meta row, where this strip's sentences go.
  // An incident whose lifecycle is over gets no triage controls — every
  // closed state has no USER-FACING edge back into the open set (Resolved/
  // Dismissed have no edges at all; Expired's one edge, PROJECT.md T2, is a
  // recurring Finding re-attaching automatically, never a button here).
  // isClosedIncidentState is the shared definition; the local CLOSED_STATES
  // this replaced was the fourth copy of it in web/src.
  if (isClosedIncidentState(state)) return null

  // Hoisted out of the JSX so the Dialog above can render it as modal content.
  const toleranceForm = (
          <div className="triage-dismiss-form">
            {/* prose-ok: an irreversible dialog's consequence statement */}
            <label htmlFor="tolerate-note">
              Why is this being tolerated? Required — this closes the incident and stops future
              occurrences of this condition on the same object from opening new ones, until the rule
              is removed or expires.
            </label>
            <textarea
              id="tolerate-note"
              rows={2}
              value={toleranceNote}
              onChange={(e) => setToleranceNote(e.target.value)}
              placeholder="e.g. Windows exporter has no endpoints — expected until a Windows node joins the cluster"
            />
            <label className="triage-tolerance-checkbox">
              <input
                type="checkbox"
                checked={toleranceAllReasons}
                onChange={(e) => setToleranceAllReasons(e.target.checked)}
              />
              Silence every future issue on this object, not just the one(s) seen here
            </label>
            <label htmlFor="tolerate-expiry" className="triage-tolerance-expiry-label">
              Expires
              <select
                id="tolerate-expiry"
                value={toleranceExpiryDays}
                onChange={(e) => setToleranceExpiryDays(e.target.value)}
              >
                <option value="">Never</option>
                <option value="1">In 1 day</option>
                <option value="7">In 7 days</option>
                <option value="30">In 30 days</option>
                <option value="90">In 90 days</option>
              </select>
            </label>
            <div className="triage-actions">
              <button
                type="button"
                onClick={() => tolerateMutation.mutate()}
                disabled={pending || !toleranceNote.trim()}
                title={toleranceNote.trim() ? undefined : 'A note is required'}
              >
                {tolerateMutation.isPending ? 'Tolerating…' : 'Confirm tolerate'}
              </button>
              <button
                type="button"
                className="secondary"
                onClick={() => { setTolerating(false); setToleranceNote(''); setToleranceAllReasons(false); setToleranceExpiryDays('') }}
                disabled={pending}
              >
                Cancel
              </button>
            </div>
          </div>
  )

  // The resolve confirmation. The note is optional — the hub accepts an empty
  // one for resolve — but the dialog still states what resolving does, since
  // it cannot be undone.
  const resolveForm = (
          <div className="triage-dismiss-form">
            {/* prose-ok: an irreversible dialog's consequence statement */}
            <p>
              Resolving records that the underlying problem is gone — you fixed it, or the object no longer
              exists. It closes this incident and cannot be undone. If the problem is still there, its detector
              will open a new incident.
            </p>
            <label htmlFor="resolve-note">What fixed it? Optional — recorded in the audit log.</label>
            <textarea
              id="resolve-note"
              rows={2}
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="e.g. rolled back the image by hand"
            />
            <div className="triage-actions">
              <button type="button" onClick={() => resolveMutation.mutate()} disabled={pending}>
                {resolveMutation.isPending ? 'Resolving…' : 'Confirm resolve'}
              </button>
              <button type="button" className="secondary" onClick={() => { setResolving(false); setNote('') }} disabled={pending}>
                Cancel
              </button>
            </div>
          </div>
  )

  // Same — the dismiss note, which the API requires.
  const dismissForm = (
          <div className="triage-dismiss-form">
            <label htmlFor="dismiss-note">
              Why is this being dismissed? Required — dismissing is final, and records that a real
              problem will not be acted on.
            </label>
            <textarea
              id="dismiss-note"
              rows={2}
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="e.g. known-broken dev workload, tracked in JIRA-1234"
            />
            <div className="triage-actions">
              <button
                type="button"
                onClick={() => dismissMutation.mutate()}
                disabled={pending || !note.trim()}
                title={note.trim() ? undefined : 'A note is required'}
              >
                {dismissMutation.isPending ? 'Dismissing…' : 'Confirm dismiss'}
              </button>
              <button type="button" className="secondary" onClick={() => { setDismissing(false); setNote('') }} disabled={pending}>
                Cancel
              </button>
            </div>
          </div>
  )

  // The two note forms render in a Dialog, NOT inline (BACKLOG D8 layout fix).
  // They used to expand in place — inside `.incident-summary-strip`, which is
  // `position: sticky`. So choosing Dismiss grew the pinned header by the height
  // of a label, a textarea and a button row: it took over a third of the
  // viewport, stayed there while the reader scrolled, and silently invalidated
  // the strip-height offset `.question-card`'s `scroll-margin-top` is tuned to,
  // so every tracker link then landed its card underneath the header.
  //
  // A sticky element must have a bounded height, and "bounded" cannot mean "as
  // long as nobody opens the form". Moving the growth into a modal is what makes
  // the close-out controls safe to keep at the top, which is where they were
  // asked for.
  return (
    <div className="triage-controls">
      {(resolving || dismissing || tolerating) && (
        <Dialog
          title={tolerating ? 'Tolerate this condition' : dismissing ? 'Dismiss this incident' : 'Resolve this incident'}
          onClose={() => { setResolving(false); setDismissing(false); setTolerating(false) }}
        >
          {tolerating ? toleranceForm : dismissing ? dismissForm : resolveForm}
        </Dialog>
      )}
      {/* ONE "Close out ▾" menu, not three buttons. The three were each
          `secondary` and each as loud as the next, so the strip read as four
          equal options — three of which end the incident — sitting above the
          causal chain that is supposed to be read first. The four-question
          order says the screen should not offer the exit before the reason.
          A menu keeps all three one click from anywhere on the page (which is
          why they are in the strip at all) without making them the loudest
          thing on it, and matches the reviewed Option B mock, whose own
          annotation calls the menu deliberate for exactly this reason.

          `disabled` on an item rather than hiding it: a viewer without
          incident:triage should still discover the action exists, same as
          every other capability-gated control here (lld/11-ui-design.md §6). */}
      <ActionMenu
        ariaLabel="Close out this incident"
        label={pending ? 'Working…' : 'Close out'}
        items={[
          {
            label: 'Mark resolved…',
            onClick: () => setResolving(true),
            disabled: pending || !!disabledReason,
            disabledReason: disabledReason ?? 'Close this incident — the underlying problem is gone',
          },
          {
            label: 'Dismiss…',
            onClick: () => setDismissing(true),
            disabled: pending || !!disabledReason,
            disabledReason: disabledReason ?? 'Close this incident — real, but needs no action',
            danger: true,
          },
          {
            label: 'Tolerate…',
            onClick: () => setTolerating(true),
            disabled: pending || !!toleranceDisabledReason,
            disabledReason:
              toleranceDisabledReason ??
              'Close this incident AND stop future occurrences from opening new ones — for real, expected, accepted conditions',
            danger: true,
          },
        ]}
      />
      {/* BACKLOG.md D9 U4: ActionMenu's own disabled items carry their
          reason only as `title` (ActionMenu.tsx) — unreachable by keyboard
          or touch, and ActionMenu is a shared primitive used well beyond
          this screen, so the fix lives here rather than in that component.
          Only rendered for a genuinely MISSING capability, not for this
          menu's ordinary hover description (every item always carries a
          `disabledReason` string, capability or not — see the item list
          above) — disabledReason/toleranceDisabledReason, the props this
          component actually receives, are set by the caller only when the
          capability itself is absent. */}
      {(disabledReason || toleranceDisabledReason) && (
        <p className="field-hint">
          {disabledReason && <>You do not hold {disabledReason.replace('Missing capability: ', '')} on this cluster, so you cannot resolve or dismiss this incident. </>}
          {toleranceDisabledReason &&
            toleranceDisabledReason !== disabledReason &&
            <>You do not hold {toleranceDisabledReason.replace('Missing capability: ', '')} on this cluster, so you cannot tolerate this condition.</>}
        </p>
      )}
      {err && (
        <p className="form-error inline-error" role="alert">
          {err instanceof ApiError ? (err.detail ? `${err.message} — ${err.detail}` : err.message) : 'Something went wrong.'}
        </p>
      )}
    </div>
  )
}

// The pull request opened for this incident, rendered from the incident's own
// payload so it survives a reload.
//
// States it distinguishes, because they are genuinely different and the operator
// acts differently on each:
//   merged            the change is in the default branch; validation is next
//   closed unmerged   somebody rejected it — with their reason when one was given
//   open              still waiting on a human
//
// The post-merge verification target (fieldPath/expectedValue) is stated when
// there is one and stated as ABSENT when there is not, rather than silently
// omitted — "we will verify this" versus "you will have to look yourself" is
// exactly the kind of thing this product must not blur.
//
// Absent is now the ordinary case and present is the historical one, which is
// the opposite of how this read when it was written. A repository change is a
// set of whole-file edits, so there is no single field the hub could re-read
// after the merge; every route has left the column NULL since 2026-08-28. The
// present branch survives because it is still TRUE for pull requests opened by
// earlier builds — internal/api/pr_verify.go really does re-read that field on
// those incidents — and deleting it would replace a check that runs with a
// claim that none does.
export function PullRequestRecord({ pr }: { pr: IncidentPullRequest }) {
  const status = pr.mergedAt
    ? { label: `Merged ${formatRelativeTime(pr.mergedAt)}`, chip: 'verification-chip', title: formatDateTime(pr.mergedAt) }
    : pr.closedUnmergedAt
      ? {
          label: `Closed without merging ${formatRelativeTime(pr.closedUnmergedAt)}`,
          chip: 'verification-chip verification-chip-neutral',
          title: formatDateTime(pr.closedUnmergedAt),
        }
      : // Open, and HOW LONG it has been open (pr.openedAt, migration 000114).
        // The duration is the point, not decoration: this is the one state in
        // the product that is explicitly waiting on a human, and "waiting to be
        // merged" alone cannot distinguish a pull request opened two minutes ago
        // from one nobody has looked at in a week — which is exactly the
        // difference that decides whether the reader acts now.
        //
        // When openedAt is absent (a pull request opened before that migration
        // whose URL the backfill could not match) the label falls back to the
        // words it has always carried. NOT "opened just now", not "open for —":
        // an unknown age is not a zero age, and a fabricated one here would be
        // read as a fact about how long a colleague has been ignoring this.
        pr.openedAt
        ? {
            label: `Open — opened ${formatRelativeTime(pr.openedAt)}, waiting to be merged`,
            chip: 'verification-chip verification-chip-neutral',
            title: formatDateTime(pr.openedAt),
          }
        : { label: 'Open — waiting to be merged', chip: 'verification-chip verification-chip-neutral', title: undefined }
  return (
    <div className="detail-callout">
      <p className="eyebrow">Pull request</p>
      <div className="verification-chip-row">
        {/* BACKLOG.md D9 U6: this used to render the bare number with no way
            to click through to the pull request the operator is waiting
            on. pr.url is absent only for a pull request opened before
            migration 000089 — the badge still renders, just not as a link,
            which is the honest degradation rather than a fabricated href. */}
        {pr.url ? (
          <a className="route-badge route-badge-blue" href={pr.url} target="_blank" rel="noreferrer">
            #{pr.number}
          </a>
        ) : (
          <span className="route-badge route-badge-blue">#{pr.number}</span>
        )}
        <span className={status.chip} title={status.title}>{status.label}</span>
        {pr.fieldPath ? (
          <span className="verification-chip">
            Verifies <span className="mono">{pr.fieldPath}</span>
            {pr.expectedValue ? <> = <span className="mono">{pr.expectedValue}</span></> : null}
          </span>
        ) : (
          <span className="verification-chip verification-chip-neutral">
            No automatic post-merge check — a repository change is a set of whole-file edits, so there is no single field to re-read
          </span>
        )}
      </div>
      {pr.rejectionReason && <p className="field-hint">Reason given: {pr.rejectionReason}</p>}
    </div>
  )
}

