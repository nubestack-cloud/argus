// The circuit breaker's operator surface (BACKLOG R2's second half).
//
// Why this card exists when the blast-radius cap has no card: a cap refuses and
// the next window lets the work through, so nothing accumulates that a person has
// to clear. A breaker STAYS tripped by design — that is what separates it from a
// rate limiter — which means unattended execution is off until somebody acts. A
// stopped automatic process that cannot be seen or restarted from the UI is worse
// than no automatic process at all, because the operator's mental model still says
// it is running.
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { getCircuitBreaker, resetCircuitBreaker, ApiError } from '../api/client'
import type { CircuitBreakerTrip } from '../api/types'
import { PanelHead } from './SettingsBlocks'
import { useAuth } from '../auth/useAuth'
import { formatDateTime, formatRelativeTime, formatSeconds } from '../utils/time'
import { SLOW_FALLBACK_MS } from '../realtime/refresh'

function TripRow({ trip, canWrite, disabledReason, onReset, resetting }: {
  trip: CircuitBreakerTrip
  canWrite: boolean
  disabledReason?: string
  onReset: (id: string, note: string) => void
  resetting: boolean
}) {
  const [note, setNote] = useState('')
  const [confirming, setConfirming] = useState(false)

  return (
    <div className="breaker-trip">
      <div className="breaker-trip-head">
        <span className="badge badge-red">
          {trip.fleetWide ? 'Fleet-wide' : trip.clusterName || trip.clusterId}
        </span>
        <span className="field-hint" title={formatDateTime(trip.trippedAt)}>
          tripped {formatRelativeTime(trip.trippedAt)}
        </span>
      </div>
      <p>{trip.reason}</p>
      {confirming ? (
        <div className="breaker-trip-reset">
          <label>
            Why is it safe to resume? <span className="field-hint">(optional, recorded in the audit log)</span>
            <input
              type="text"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="e.g. the failures were a deleted test workload, not a real fault"
            />
          </label>
          <div className="form-actions">
            <button type="button" onClick={() => onReset(trip.id, note)} disabled={resetting}>
              {resetting ? 'Resetting…' : 'Confirm reset'}
            </button>
            <button type="button" className="secondary" onClick={() => setConfirming(false)}>
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <button
          type="button"
          disabled={!canWrite}
          title={canWrite ? 'Allow unattended execution to resume' : disabledReason}
          onClick={() => setConfirming(true)}
        >
          Reset this breaker
        </button>
      )}
    </div>
  )
}

export function CircuitBreakerCard({ canWrite, disabledReason }: {
  canWrite: boolean
  disabledReason?: string
}) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const query = useQuery({
    queryKey: ['circuit-breaker'],
    queryFn: () => getCircuitBreaker(accessToken!),
    // A breaker can trip while this page is open, and an operator sitting on a
    // stale "nothing tripped" view is the exact wrong outcome. A trip only
    // ever follows a remediation outcome, and every one of those publishes
    // IncidentUpdated, so the trip reaches this card as an event; the
    // interval is the fallback (realtime/refresh.ts).
    refetchInterval: SLOW_FALLBACK_MS,
  })

  const reset = useMutation({
    mutationFn: ({ id, note }: { id: string; note: string }) => resetCircuitBreaker(id, note, accessToken!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['circuit-breaker'] }),
  })

  const data = query.data
  const open = data?.open ?? []

  return (
    <div className="card settings-panel">
      <PanelHead
        title="Circuit breaker"
        lede="Halts unattended execution after repeated bad outcomes, until a person resets it."
        help="Stops unattended execution when changes are not working — a failed remediation, or one that succeeded and was then reverted. The windows bound when automation may run and the blast-radius caps bound how much; this bounds it on whether it is working, which neither of the others can see. A person can still approve a remediation while a breaker is open. Resetting is deliberately manual: a breaker that re-closed on a timer would just be another rate limiter."
        aside={
          data &&
          (!data.enabled ? (
            <span className="badge badge-gray">disabled</span>
          ) : open.length > 0 ? (
            <span className="badge badge-red">{open.length} open</span>
          ) : (
            <span className="badge badge-green">closed</span>
          ))
        }
      />

      {data && !data.enabled && (
        <p className="field-hint">
          <strong>Disabled.</strong> Nothing stops unattended execution when its changes fail.
        </p>
      )}

      {data && data.enabled && (
        <div className="settings-effective">
          <span className="settings-effective-label">Trips after</span>
          <dl>
            <div>
              <dt>One cluster</dt>
              <dd>{data.maxPerCluster} bad</dd>
            </div>
            <div>
              <dt>Fleet-wide</dt>
              <dd>{data.maxFleetWide} bad</dd>
            </div>
            <div>
              <dt>Within</dt>
              <dd>{formatSeconds(data.windowSeconds)}</dd>
            </div>
          </dl>
        </div>
      )}

      {query.isPending && <p className="field-hint">Loading…</p>}
      {query.isError && (
        <p className="form-error">
          {query.error instanceof ApiError ? query.error.detail || query.error.message : 'Could not load the breaker state.'}
        </p>
      )}

      {reset.isError && (
        <p className="form-error">
          {reset.error instanceof ApiError
            ? reset.error.detail || reset.error.message
            : 'Could not reset the breaker.'}
        </p>
      )}

      {data && open.length === 0 && (
        <p className="empty-state">
          Nothing has tripped. Unattended execution is not being held back by a breaker.
        </p>
      )}

      {open.map((trip) => (
        <TripRow
          key={trip.id}
          trip={trip}
          canWrite={canWrite}
          disabledReason={disabledReason}
          resetting={reset.isPending}
          onReset={(id, note) => reset.mutate({ id, note })}
        />
      ))}

      {data && data.history.length > 0 && (
        <details className="breaker-history">
          <summary>Previously tripped ({data.history.length})</summary>
          <div className="table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>Scope</th>
                <th>Tripped</th>
                <th>Bad outcomes</th>
                <th>Reset by</th>
                <th>Note</th>
              </tr>
            </thead>
            <tbody>
              {data.history.map((t) => (
                <tr key={t.id}>
                  <td>{t.fleetWide ? 'Fleet-wide' : t.clusterName || t.clusterId}</td>
                  <td title={formatDateTime(t.trippedAt)}>{formatRelativeTime(t.trippedAt)}</td>
                  <td>{t.badOutcomes} / {t.threshold}</td>
                  <td>{t.resetByEmail || '—'}</td>
                  <td>{t.resetNote || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        </details>
      )}
    </div>
  )
}
