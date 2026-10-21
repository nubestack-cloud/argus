// Minimal relative-time formatter — good enough for a cluster list's
// "last heartbeat" column without pulling in a date library for this
// first slice.
export function formatRelativeTime(isoDate: string | null): string {
  if (!isoDate) {
    return 'never'
  }

  const then = new Date(isoDate).getTime()
  if (Number.isNaN(then)) {
    return 'never'
  }

  const diffSeconds = Math.round((Date.now() - then) / 1000)

  if (diffSeconds < 5) {
    return 'just now'
  }
  if (diffSeconds < 60) {
    return `${diffSeconds}s ago`
  }
  const diffMinutes = Math.round(diffSeconds / 60)
  if (diffMinutes < 60) {
    return `${diffMinutes}m ago`
  }
  const diffHours = Math.round(diffMinutes / 60)
  if (diffHours < 24) {
    return `${diffHours}h ago`
  }
  const diffDays = Math.round(diffHours / 24)
  return `${diffDays}d ago`
}

// formatDurationBetween is the "durations computed client-side from
// adjacent timestamps" half of lld/11-ui-design.md §4's timeline contract —
// internal/api/timeline.go guarantees only chronological order, never a
// computed gap. Returns null, not "+0s", for a non-positive or unparseable
// gap: two events written in the same transaction before migration 000067's
// clock_timestamp() fix could still share an instant on an incident analysed
// before that fix shipped, and "+0s" would assert a duration nothing
// actually measured.
export function formatDurationBetween(fromIso: string, toIso: string): string | null {
  const from = new Date(fromIso).getTime()
  const to = new Date(toIso).getTime()
  if (Number.isNaN(from) || Number.isNaN(to)) {
    return null
  }
  const diffSeconds = Math.round((to - from) / 1000)
  if (diffSeconds <= 0) {
    return null
  }
  return `+${formatSeconds(diffSeconds)}`
}

export function formatDateTime(isoDate: string): string {
  const d = new Date(isoDate)
  if (Number.isNaN(d.getTime())) {
    return isoDate
  }
  return d.toLocaleString()
}

// The two halves of talking to an `<input type="datetime-local">`, which is a
// LOCAL wall-clock control: the browser both renders and reports
// "YYYY-MM-DDTHH:mm" in the viewer's own timezone, with no offset attached.
// The API, correctly, speaks UTC ISO-8601.
//
// AuditLogPage used to convert only one way: applyFilters did
// `new Date(value).toISOString()` (right — the Date constructor reads a bare
// datetime-local string as local time), but rehydrating from the URL did
// `searchParams.get('since')?.slice(0, 16)`, which chops the "Z" off a UTC
// string and hands the raw UTC digits to a control that renders them as
// local. On any machine not on UTC the box then showed a time one offset off
// from the filter actually in force, and because Apply re-read that box, each
// reload+apply shifted the window by another offset — the filter walked.
// Both directions live here now so they can't drift apart again.
export function toDatetimeLocalValue(isoDate: string | null): string {
  if (!isoDate) {
    return ''
  }
  const d = new Date(isoDate)
  if (Number.isNaN(d.getTime())) {
    return ''
  }
  // Local getters, then a manual zero-padded assemble: toISOString() would
  // re-introduce the exact UTC-for-local substitution this function exists to
  // undo, and there is no toLocalISOString().
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

// The inverse: a datetime-local value (local wall clock) to a UTC ISO string
// for the API. Returns undefined for an empty or unparseable box so callers
// can drop the filter entirely rather than sending "Invalid Date".
export function fromDatetimeLocalValue(value: string): string | undefined {
  if (!value) {
    return undefined
  }
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) {
    return undefined
  }
  return d.toISOString()
}

// formatSeconds renders a detector interval the way an operator would say it
// out loud: "30s", "10m", "1h 30m". Sub-minute values keep their seconds
// because the detection timings genuinely live at that scale on a test cluster.
//
// Zero and negative are "Not reported", never "0s" — every timing this renders
// arrives from an agent as an omitempty field, so a missing value and a real
// zero are indistinguishable on the wire and only one of them is possible.
export function formatSeconds(seconds: number | undefined): string {
  if (!seconds || seconds <= 0) {
    return 'Not reported'
  }
  if (seconds < 60) {
    return `${seconds}s`
  }
  const minutes = Math.floor(seconds / 60)
  const rem = seconds % 60
  if (minutes < 60) {
    return rem ? `${minutes}m ${rem}s` : `${minutes}m`
  }
  const hours = Math.floor(minutes / 60)
  const remMin = minutes % 60
  return remMin ? `${hours}h ${remMin}m` : `${hours}h`
}

// formatSecondsRange renders a span in ONE unit chosen from the whole range,
// because formatting each end independently produces "1m-1m 30s" for a range
// straddling the minute boundary — correct, but noticeably harder to read at a
// glance than "60s-90s". The detection-latency range does straddle it at the
// timings a test cluster actually runs, so this is the common case, not an edge.
export function formatSecondsRange(floorSeconds: number, ceilingSeconds: number): string {
  if (ceilingSeconds < 120) {
    return `${floorSeconds}s–${ceilingSeconds}s`
  }
  if (ceilingSeconds < 3600 && floorSeconds % 60 === 0 && ceilingSeconds % 60 === 0) {
    return `${floorSeconds / 60}m–${ceilingSeconds / 60}m`
  }
  return `${formatSeconds(floorSeconds)}–${formatSeconds(ceilingSeconds)}`
}

// A gap as a reader says it — "1d 21h", "5h 52m", "15m" — for the incident
// lifecycle's phase durations and history gaps, where formatSeconds' "48h"
// for two days (and "168h" for a week) makes the reader do the arithmetic.
// Two units at most; null for a non-positive or unparseable gap, same rule as
// formatDurationBetween, so nothing is shown that nothing measured.
export function compactDuration(fromIso: string, toIso: string): string | null {
  const ms = new Date(toIso).getTime() - new Date(fromIso).getTime()
  if (Number.isNaN(ms) || ms <= 0) return null
  const m = Math.floor(ms / 60000)
  if (m < 1) return `${Math.max(1, Math.round(ms / 1000))}s`
  const d = Math.floor(m / 1440)
  const h = Math.floor((m % 1440) / 60)
  const min = m % 60
  if (d > 0) return h ? `${d}d ${h}h` : `${d}d`
  if (h > 0) return min ? `${h}h ${min}m` : `${h}h`
  return `${min}m`
}
