import type { AgentCompatibility, AgentCompatibilityVerdict } from '../api/types'
import { COMPATIBILITY_VERDICT_LABEL } from '../api/types'

// T16. The one place an agent-compatibility Verdict becomes a badge —
// ClustersPage's fleet-wide column/filter and ClusterDetailPage's fact strip
// both render this, so the two screens cannot render the same verdict two
// different ways the way ClusterBadges.tsx's own header comment describes
// three older per-page state tables doing. The label always comes from the
// server (`compatibility.label`), not from a local re-lookup, so a caller
// here never needs its own copy of the wire->text mapping — VERDICT_COLOR
// below decides only the colour family, never the word.

type ColorFamily = 'green' | 'amber' | 'red' | 'gray'

// Same four-way severity vocabulary ClusterBadges/IncidentBadges already use
// (green/amber/red/gray) — 'current' reads like Active, 'upgrade_required'
// reads like Rejected/IncompatibleVersion, 'unknown' reads like Disconnected.
// No new colour family invented for this.
const VERDICT_COLOR: Record<AgentCompatibilityVerdict, ColorFamily> = {
  unknown: 'gray',
  current: 'green',
  upgrade_recommended: 'amber',
  upgrade_required: 'red',
}

// `withDot` mirrors ClusterStateBadge's own prop for the identical reason: a
// list column carries the dot so a scan down it has a mark to follow, a
// single badge in a fact strip does not need one. The word is present
// either way — colour is never the only signal (lld/11 §8, WCAG 2.1 AA).
export function AgentCompatibilityBadge({
  compatibility,
  withDot = false,
}: {
  compatibility: AgentCompatibility
  withDot?: boolean
}) {
  const family = VERDICT_COLOR[compatibility.verdict]
  // compatibility.label is the server's own word for this verdict
  // (internal/agentversion.VerdictLabel); COMPATIBILITY_VERDICT_LABEL is
  // used only as a fallback so a badge never renders blank if an older
  // cached response predates `label` being added to the wire payload.
  const label = compatibility.label || COMPATIBILITY_VERDICT_LABEL[compatibility.verdict]
  const badge = (
    <span className={`badge badge-${family}`} title={compatibility.reason}>
      {label}
    </span>
  )
  if (!withDot) return badge
  return (
    <span className="badge-with-dot">
      <span className={`status-dot status-dot-${family}`} aria-hidden="true" />
      {badge}
    </span>
  )
}
