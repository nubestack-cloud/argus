import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import {
  ApiError,
  createAutomationWindow,
  deleteAutomationWindow,
  getAutomationWindows,
} from '../api/client'
import type { AutomationWindow, CreateAutomationWindowRequest } from '../api/types'
import { useAuth } from '../auth/useAuth'
import { HelpTip } from './HelpTip'
import { PanelHead } from './SettingsBlocks'
import { formatDateTime, formatRelativeTime } from '../utils/time'
import { CLOCK_POLL_MS } from '../realtime/refresh'

// Maintenance and freeze windows — Settings → AI & automation.
//
// # The asymmetry this UI has to teach, not hide
//
// A freeze forbids automation whenever it is open, whatever else is configured.
// A maintenance window is a permission — and an empty maintenance list therefore
// means *no time restriction*, not "nothing is permitted". That is a genuinely
// surprising rule, and the surprise has a bad failure mode in the other
// direction: reading it literally would silently stop automation everywhere the
// day this shipped. So the copy states it outright rather than leaving an
// operator to infer it from an empty table.
//
// # Why the verdict comes from the server
//
// "Would automation run right now?" is answered by the hub, using the same
// function the sweeper uses. Evaluating cron in the browser would mean two
// implementations of the one rule that decides whether a cluster gets changed
// without a human, and the moment they disagree the UI is lying.

const HOURS = [1, 2, 4, 8, 12, 24, 48, 72]

function describeDuration(seconds: number): string {
  const hours = seconds / 3600
  if (hours >= 24 && hours % 24 === 0) {
    const days = hours / 24
    return `${days} day${days === 1 ? '' : 's'}`
  }
  return `${hours} hour${hours === 1 ? '' : 's'}`
}

function WindowRow({ window: w, onRemove, canWrite, disabledReason }: {
  window: AutomationWindow
  onRemove: (id: string) => void
  canWrite: boolean
  disabledReason?: string
}) {
  return (
    <tr>
      <td>
        <span className={w.kind === 'freeze' ? 'badge badge-red' : 'badge badge-blue'}>
          {w.kind === 'freeze' ? 'Freeze' : 'Maintenance'}
        </span>
      </td>
      <td>
        <code>{w.schedule}</code>
        <span className="field-hint"> for {describeDuration(w.durationSeconds)}, {w.timezone}</span>
      </td>
      <td>
        {/* A malformed window is reported before its open/closed state, because a
            malformed FREEZE is treated as in force — so "why is nothing running"
            has to be answerable from this row. */}
        {w.invalidReason ? (
          <span className="badge badge-red" title={w.invalidReason}>
            Invalid — treated as in force
          </span>
        ) : w.openNow ? (
          <span className={w.kind === 'freeze' ? 'badge badge-red' : 'badge badge-green'}>Open now</span>
        ) : (
          <span className="badge badge-gray">Closed</span>
        )}
      </td>
      <td>{w.reason || <span className="field-hint">—</span>}</td>
      <td>
        <span title={formatDateTime(w.createdAt)}>{formatRelativeTime(w.createdAt)}</span>
      </td>
      <td>
        <button
          type="button"
          className="secondary"
          disabled={!canWrite}
          title={canWrite ? 'Remove this window' : disabledReason}
          onClick={() => onRemove(w.id)}
        >
          Remove
        </button>
      </td>
    </tr>
  )
}

export function AutomationWindowsCard({ canWrite, disabledReason }: {
  canWrite: boolean
  disabledReason?: string
}) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const query = useQuery({
    queryKey: ['automation-windows'],
    queryFn: () => getAutomationWindows(accessToken!),
    // The open/closed state changes with the clock, so a stale view here is
    // actively misleading — this is the one card whose data goes out of date
    // without anybody doing anything. That is also why no event can drive it:
    // nothing happens server-side when a window opens for anything to
    // publish, so this stays a genuinely short poll (PROJECT.md P16).
    refetchInterval: CLOCK_POLL_MS,
  })

  const [kind, setKind] = useState<'maintenance' | 'freeze'>('freeze')
  const [schedule, setSchedule] = useState('')
  const [hours, setHours] = useState(8)
  const [timezone, setTimezone] = useState('UTC')
  const [reason, setReason] = useState('')

  const create = useMutation({
    mutationFn: (body: CreateAutomationWindowRequest) => createAutomationWindow(body, accessToken!),
    onSuccess: () => {
      setSchedule('')
      setReason('')
      queryClient.invalidateQueries({ queryKey: ['automation-windows'] })
    },
  })
  const remove = useMutation({
    mutationFn: (id: string) => deleteAutomationWindow(id, accessToken!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['automation-windows'] }),
  })

  const windows = query.data?.windows ?? []
  const hasMaintenance = windows.some((w) => w.kind === 'maintenance')

  return (
    <div className="card settings-panel">
      <PanelHead
        title="Maintenance and freeze windows"
        lede="When unattended execution may run. A person can approve at any time."
        help={'These gate unattended execution only — a window never stands between an operator and a fix they have decided to make. A freeze blocks automation whenever it is open. If any maintenance window exists, automation runs only inside one; with none configured there is no time restriction at all, not "nothing is permitted".'}
      />

      {query.data && (
        <p className={query.data.automationOpenNow ? 'banner banner-info' : 'banner banner-warning'}>
          <strong>
            {query.data.automationOpenNow
              ? 'Automation is not blocked by time right now.'
              : 'Automation is blocked by time right now.'}
          </strong>{' '}
          {query.data.decisionReason}
        </p>
      )}

      {/* Only the "no maintenance window" case is spelled out on the card: it
          is the one a reader gets backwards (no window = no restriction). */}
      {!hasMaintenance && query.data && (
        <p className="field-hint">
          <strong>No maintenance windows</strong> — so no time restriction. Add one only to confine
          automation to specific hours.
        </p>
      )}

      {query.isError && (
        <p className="form-error" role="alert">
          {query.error instanceof ApiError ? query.error.detail || query.error.message : 'Could not load windows.'}
        </p>
      )}

      {windows.length > 0 && (
        <div className="table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>Kind</th>
                <th>Opens</th>
                <th>Right now</th>
                <th>Reason</th>
                <th>Added</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {windows.map((w) => (
                <WindowRow
                  key={w.id}
                  window={w}
                  onRemove={(id) => remove.mutate(id)}
                  canWrite={canWrite}
                  disabledReason={disabledReason}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {remove.isError && (
        <p className="form-error" role="alert">
          {remove.error instanceof ApiError ? remove.error.detail || remove.error.message : 'Could not remove that window.'}
        </p>
      )}

      <h3 className="settings-subhead">Add a window</h3>
      <form
        className="settings-window-form"
        onSubmit={(e) => {
          e.preventDefault()
          create.mutate({
            kind,
            schedule: schedule.trim(),
            durationSeconds: hours * 3600,
            timezone: timezone.trim() || 'UTC',
            ...(reason.trim() ? { reason: reason.trim() } : {}),
          })
        }}
      >
        <div className="settings-field">
          <label htmlFor="window-kind">
            Kind
            <HelpTip label="Kind" text="A freeze blocks unattended execution whenever it is open, whatever else is configured. A maintenance window permits it — and if any maintenance window exists, automation runs ONLY inside one." />
          </label>
          <select
            id="window-kind"
            value={kind}
            onChange={(e) => setKind(e.target.value as 'maintenance' | 'freeze')}
            disabled={!canWrite}
            title={disabledReason}
          >
            <option value="freeze">Freeze — block automation</option>
            <option value="maintenance">Maintenance — permit automation</option>
          </select>
        </div>

        <div className="settings-field">
          <label htmlFor="window-schedule">
            Opens at (cron)
            <HelpTip label="Opens at" text="Five fields: minute hour day-of-month month day-of-week. This is when the window STARTS, not when it applies — the duration below says how long it stays open. Same schedule-plus-duration model as Argo CD's sync windows. Examples: 0 9 * * 1-5 (9am on weekdays), 0 0 24 12 * (midnight on 24 December)." />
          </label>
          <input
            id="window-schedule"
            required
            value={schedule}
            onChange={(e) => setSchedule(e.target.value)}
            placeholder="0 9 * * 1-5"
            disabled={!canWrite}
            title={disabledReason}
          />
        </div>

        <div className="settings-field">
          <label htmlFor="window-duration">Stays open for</label>
          <select
            id="window-duration"
            value={hours}
            onChange={(e) => setHours(Number(e.target.value))}
            disabled={!canWrite}
            title={disabledReason}
          >
            {HOURS.map((h) => (
              <option key={h} value={h}>
                {describeDuration(h * 3600)}
              </option>
            ))}
          </select>
        </div>

        <div className="settings-field">
          <label htmlFor="window-timezone">
            Timezone
            <HelpTip label="Timezone" text="An IANA name such as Europe/London or UTC. It matters: a 9am window written in a zone that observes daylight saving stays 9am local on both sides of the change." />
          </label>
          <input
            id="window-timezone"
            value={timezone}
            onChange={(e) => setTimezone(e.target.value)}
            placeholder="UTC"
            disabled={!canWrite}
            title={disabledReason}
          />
        </div>

        <div className="settings-field">
          <label htmlFor="window-reason">
            Reason {kind === 'freeze' && <span className="badge badge-amber">required</span>}
            <HelpTip label="Reason" text="Shown wherever this window blocks something. Required for a freeze, because it is the text an operator reads when automation did not happen — and 'nothing ran and nobody said why' is what makes people switch a safety feature off." />
          </label>
          <input
            id="window-reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder={kind === 'freeze' ? 'December change freeze' : 'optional'}
            disabled={!canWrite}
            title={disabledReason}
          />
        </div>

        {create.isError && (
          <p className="form-error" role="alert">
            {create.error instanceof ApiError
              ? create.error.detail || create.error.message
              : 'Could not add that window.'}
          </p>
        )}

        <div className="form-actions">
          <button type="submit" disabled={!canWrite || create.isPending}>
            {create.isPending ? 'Adding…' : 'Add window'}
          </button>
        </div>
      </form>
    </div>
  )
}
