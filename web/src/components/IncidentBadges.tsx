import type { IncidentSeverity, IncidentState } from '../api/types'
import {
  RESOLUTION_KIND_LABEL,
  SEVERITY_BADGE_CLASS,
  SEVERITY_LABEL,
  STATE_BADGE_CLASS,
  STATE_LABEL,
} from '../utils/incidents'

// The incident severity and state badges, shared.
//
// These two components and their lookup maps were copied into four page
// modules — IncidentsPage, IncidentDetailPage, ApprovalsPage, ClusterDetailPage
// — each carrying a comment saying to factor them out once a third screen
// needed them. TolerationsPage is the fifth, and it needs them for a
// substantive reason rather than a cosmetic one: a toleration is an incident
// that has been accepted, so the incident it now shows has to render with the
// same badges, from the same maps (utils/incidents.ts), or one fact reads two
// ways in two places.
//
// Colour is never the only signal in either component (lld/11-ui-design.md §8):
// the severity or state word is always in the badge text.

// `dot` is the list-scanning variant (IncidentsPage's table, where a column of
// coloured dots is what makes triage-by-eye work); everything inline — fact
// grids, table cells that already carry other text, an expanded panel — uses
// the plain form, which is how those pages already rendered it.
//
// An unrecognised severity falls back to a neutral badge showing the raw value
// rather than an empty one. Reachable two ways: a hub newer than this bundle
// reporting a fifth severity, and a stored finding whose severity column is
// empty (findings.severity is NOT NULL, but the tolerations detail scans it
// defensively). Either way the value itself is the honest thing to show.
export function SeverityBadge({ severity, dot = false }: { severity: IncidentSeverity; dot?: boolean }) {
  const className = SEVERITY_BADGE_CLASS[severity] ?? 'badge-gray'
  if (!dot) {
    return <span className={`badge ${className}`}>{severity || 'unknown'}</span>
  }
  return (
    <span className="badge-with-dot incident-badge-with-dot">
      <span className={`status-dot incident-severity-dot-${severity}`} aria-hidden="true" />
      <span className={`badge ${className}`}>{SEVERITY_LABEL[severity] ?? severity ?? 'Unknown'}</span>
    </span>
  )
}

// Always the readable label ("Recommendation ready"), never the raw enum
// value. Three of the four copies this replaces rendered the raw
// `RecommendationReady`/`NeedsHumanInvestigation` spelling, which is an API
// identifier rather than something written for a reader — and having two house
// styles for one state was exactly the drift that made the toleration page read
// as a different product from the incident page (WORKLOG §130).
// resolutionKind (BACKLOG.md T2) is folded into the SAME badge's text —
// "Resolved · Remediated" / "Resolved · Self-healed" — rather than a second
// chip next to it: the colour stays exactly what it already was (green,
// still a closed-not-failed state), and the distinction is the WORD, the
// same "colour is never the only signal, and never duplicated either" rule
// the severity rule already follows. Omitted when absent (every state but
// Resolved, and a Resolved row written before migration 000091 backfilled
// it) — a bare "Resolved" is still honest, just less specific.
export function StateBadge({
  state,
  resolutionKind,
  label: override,
}: {
  state: IncidentState
  resolutionKind?: 'remediated' | 'self_healed'
  // The detail page passes stateLabelFor's analysis-aware label; list rows
  // use the plain per-state one.
  label?: string
}) {
  const label =
    state === 'Resolved' && resolutionKind
      ? `${STATE_LABEL[state]} · ${RESOLUTION_KIND_LABEL[resolutionKind]}`
      : override ?? STATE_LABEL[state] ?? state
  return <span className={`badge ${STATE_BADGE_CLASS[state] ?? 'badge-gray'}`}>{label}</span>
}
