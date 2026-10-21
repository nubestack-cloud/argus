import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'

import { ApiError, preflightIncident } from '../api/client'
import type { DiffChange, PreflightResponse } from '../api/types'
import { useAuth } from '../auth/useAuth'
import { formatDateTime } from '../utils/time'

// PreflightPanel asks the cluster what a pending plan would do, and shows the
// answer.
//
// It exists because an action name and a risk badge describe "scale to 3"
// adequately and describe nothing else adequately. Approving a field change you
// cannot see is rubber-stamping, and the more capable ARGUS's remediation gets
// the more that matters.
//
// Two deliberate choices about *when* it runs:
//
//   - Only when asked. The approvals list refetches every five seconds; a
//     rehearsal on render would fire a dry-run patch per pending plan every five
//     seconds into the customer's API server for as long as the tab stayed open.
//   - Not cached across renders by react-query. The answer is a statement about
//     the cluster right now, and a diff quietly served from cache is a diff of a
//     cluster that may have moved on. A mutation, re-run explicitly, is the
//     honest model for that.

// renderValue formats a leaf for display. JSON rather than String(): `String()`
// turns an object into "[object Object]" and a null into "null" — and in a diff
// whose whole job is precision, a value rendered as "[object Object]" is worse
// than no diff at all.
function renderValue(value: unknown): string {
  if (value === undefined) return '—'
  if (typeof value === 'string') return value
  return JSON.stringify(value)
}

function ChangeRow({ change }: { change: DiffChange }) {
  return (
    <li className="preflight-change">
      <code className="preflight-change-path">{change.path}</code>
      <span className="preflight-change-values">
        {change.added ? (
          // "added" and "removed" are shown as such rather than as "— → value",
          // because an approver reads "this field did not exist before"
          // differently from "this value changed".
          <>
            <span className="preflight-tag preflight-tag-added">added</span>
            <code className="preflight-after">{renderValue(change.after)}</code>
          </>
        ) : change.removed ? (
          <>
            <span className="preflight-tag preflight-tag-removed">removed</span>
            <code className="preflight-before">{renderValue(change.before)}</code>
          </>
        ) : (
          <>
            <code className="preflight-before">{renderValue(change.before)}</code>
            <span className="preflight-arrow" aria-label="becomes">→</span>
            <code className="preflight-after">{renderValue(change.after)}</code>
          </>
        )}
      </span>
    </li>
  )
}

function PreflightResult({ result }: { result: PreflightResponse }) {
  const [showSuppressed, setShowSuppressed] = useState(false)
  const diff = result.diff
  const additional = diff?.additional ?? []
  const suppressed = diff?.suppressed ?? []

  return (
    <div className="preflight-result">
      <p className="preflight-attestation">
        The cluster evaluated this change at{' '}
        <strong title={result.attestedAt}>{formatDateTime(result.attestedAt)}</strong> and accepted it.
        Nothing was applied.
      </p>

      <p className="preflight-target">
        Applies to <code>{result.target.gvk}</code>{' '}
        <strong>
          {result.target.namespace}/{result.target.name}
        </strong>
      </p>

      {/* Leads the panel: what the cluster would do BEYOND the plan is the part
          the approver could not have worked out for themselves, so it must not
          sit below a list of things they already expected. */}
      {additional.length > 0 && (
        <div className="preflight-group preflight-group-attention">
          <h4>The cluster would also change these</h4>
          <p className="field-hint">
            Nothing in this plan asked for these. They come from the API server's own defaulting or from
            a mutating admission webhook in this cluster.
          </p>
          <ul className="preflight-change-list">
            {additional.map((c) => (
              <ChangeRow key={c.path} change={c} />
            ))}
          </ul>
        </div>
      )}

      {result.noChange ? (
        <p className="preflight-no-change" role="status">
          <strong>Nothing would change.</strong> The cluster accepted the change but the object already
          matches it — usually this means the fix is already applied and this plan is stale.
        </p>
      ) : diff ? (
        <div className="preflight-group">
          <h4>This plan changes</h4>
          <ul className="preflight-change-list">
            {diff.requested.map((c) => (
              <ChangeRow key={c.path} change={c} />
            ))}
          </ul>
        </div>
      ) : (
        <p className="field-hint">{result.diffUnavailable}</p>
      )}

      {result.blockedBy?.map((message) => (
        <p key={message} className="preflight-blocked">
          <strong>Approving will also ask you to confirm:</strong> {message}
        </p>
      ))}

      {result.notes?.map((note) => (
        <p key={note} className="field-hint">
          Note: {note}
        </p>
      ))}

      {suppressed.length > 0 && (
        <div className="preflight-suppressed">
          <button type="button" className="link-button" onClick={() => setShowSuppressed((v) => !v)}>
            {showSuppressed ? 'Hide' : 'Show'} {suppressed.length} hidden bookkeeping field
            {suppressed.length === 1 ? '' : 's'}
          </button>
          {/* Listed rather than merely counted: a filtered diff that will not say
              what it filtered asks to be trusted, and this panel's whole purpose
              is to replace trust with evidence. */}
          {showSuppressed && (
            <ul className="preflight-change-list preflight-suppressed-list">
              {suppressed.map((path) => (
                <li key={path}>
                  <code>{path}</code>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  )
}

// disabledReason: the plan cannot run on this cluster at all (no remediation
// agent connected — ApprovalQueueItem.executionBlockedReason). A rehearsal is a
// dry-run write sent to that same agent, so it is disabled for the same reason
// rather than offered only to fail; the card states the reason beside Approve.
export function PreflightPanel({ incidentId, disabledReason }: { incidentId: string; disabledReason?: string }) {
  const { accessToken } = useAuth()
  const mutation = useMutation({
    mutationFn: () => preflightIncident(incidentId, accessToken!),
  })

  return (
    <div className="preflight">
      <button
        type="button"
        className="secondary"
        disabled={mutation.isPending || !!disabledReason}
        title={
          disabledReason ??
          'Ask the cluster what this change would do. Runs a server-side dry run: full admission and validation, nothing applied.'
        }
        onClick={() => mutation.mutate()}
      >
        {mutation.isPending ? 'Asking the cluster…' : mutation.isSuccess ? 'Re-check' : 'Preview change'}
      </button>

      {mutation.isError && (
        // A refusal here is the most useful thing this panel produces: the
        // operator learns the change will not be accepted, in the cluster's own
        // words, without having approved anything. So it is shown in full
        // rather than truncated to a generic failure line.
        <p className="form-error inline-error" role="alert">
          {mutation.error instanceof ApiError
            ? mutation.error.detail || mutation.error.message
            : 'Could not evaluate this change.'}
        </p>
      )}

      {mutation.isSuccess && <PreflightResult result={mutation.data} />}
    </div>
  )
}
