import type { AutomationWindowsResponse, Cluster } from '../api/types'
import { toVerdict, type Verdict } from '../components/VerdictBadge'
import { POSTURE_CATEGORIES } from '../fleet/postureModel'
import { windowSpans, type LadderRow } from './model'
import type { FleetChecks } from './useFleetData'

// The one-line counts in the Overview's card headers. Each counts only what
// answered: a cluster whose check has not been read or failed adds nothing,
// and with nothing answered the header shows no count rather than a zero.

export type Rung = 'blocked' | 'review' | 'ready' | 'none'

// The ladder's words are an upgrade's: a scan with no known blockers is
// "Ready", and a warning is something to review before going.
export function rungOf(v: Verdict | null): Rung {
  return v === 'blocked' ? 'blocked' : v === 'warning' || v === 'review' ? 'review' : v === 'passed' ? 'ready' : 'none'
}
export const RUNG_WORD: Record<Rung, string> = { blocked: 'Blocked', review: 'Review', ready: 'Ready', none: 'Incomplete' }

/** "2 blocked · 1 review · 3 ready · 2 not scanned" for the card header. */
export function ladderSummary(rows: LadderRow[]): string | null {
  if (rows.length === 0) return null
  const n: Record<Rung | 'unscanned', number> = { blocked: 0, review: 0, ready: 0, none: 0, unscanned: 0 }
  for (const r of rows) n[r.target ? rungOf(toVerdict(r.verdict)) : 'unscanned'] += 1
  return [
    n.blocked && `${n.blocked} blocked`,
    n.review && `${n.review} review`,
    n.ready && `${n.ready} ready`,
    n.none && `${n.none} incomplete`,
    n.unscanned && `${n.unscanned} not scanned`,
  ]
    .filter(Boolean)
    .join(' · ')
}

/** "9 certificates · 4 inside 30 days · 13 freeze windows", over every
 *  cluster whose certificates have been read — not only the lanes drawn. */
export function comingDueSummary(
  clusters: Cluster[],
  checks: FleetChecks,
  windows: AutomationWindowsResponse | undefined,
  nowMs: number,
): string | null {
  const parts: string[] = []
  let answered = 0
  let certs = 0
  let soon = 0
  for (const c of clusters) {
    const s = checks.certificates(c.id)
    if (s.kind !== 'ok') continue
    answered += 1
    certs += s.summary.dueTotal
    soon += s.summary.due.filter((p) => p.daysLeft <= 30).length
  }
  if (answered > 0) parts.push(`${certs} certificate${certs === 1 ? '' : 's'}`, `${soon} inside 30 days`)
  if (windows) {
    const spans = windowSpans(windows.windows, nowMs)
    const freeze = spans.filter((s) => s.kind === 'freeze').length
    const maint = spans.length - freeze
    parts.push(`${freeze} freeze window${freeze === 1 ? '' : 's'}`)
    if (maint) parts.push(`${maint} maintenance`)
  }
  return parts.length ? parts.join(' · ') : null
}

/** "13 danger · 104 warning" over the clusters whose posture has been read. */
export function postureSummary(clusters: Cluster[], checks: FleetChecks): string | null {
  let danger = 0
  let warning = 0
  let answered = 0
  for (const c of clusters) {
    const s = checks.posture(c.id)
    if (s.kind !== 'ok') continue
    answered += 1
    // Summed over the categories the heatmap draws, so the header and the
    // cells below it always add up.
    for (const k of POSTURE_CATEGORIES) {
      danger += s.summary.categories[k]?.danger ?? 0
      warning += s.summary.categories[k]?.warning ?? 0
    }
  }
  return answered ? `${danger} danger · ${warning} warning` : null
}

/** "Helm 1 failing · GitOps 8 in error" over the clusters that have been read. */
export function deliverySummary(clusters: Cluster[], checks: FleetChecks): string | null {
  let h: number | null = null
  let g: number | null = null
  for (const c of clusters) {
    const hs = checks.helm(c.id)
    const gs = checks.gitops(c.id)
    if (hs.kind === 'ok') h = (h ?? 0) + hs.summary.failing
    if (gs.kind === 'ok') g = (g ?? 0) + gs.summary.problems
  }
  const parts = [h !== null && `Helm ${h} failing`, g !== null && `GitOps ${g} in error`].filter(Boolean)
  return parts.length ? parts.join(' · ') : null
}
