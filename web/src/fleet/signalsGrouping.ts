// Look-alike signal rows (docs/CLUSTER_INSIGHT_SPECS.md CI-U4) and the
// readable fault line for the cluster-insight detectors.
//
// Grouping runs over ONE server page — the findings route is keyset-paged and
// carries no per-group totals — so a group's size is exact only when that page
// is the whole scoped set (first page, no next cursor). Otherwise it is a
// lower bound, and the caller says so (CI-U1 atLeast) and offers the
// server-side reason filter, whose exact count is on the "All" tab.
import type { FindingListItem } from '../api/client'

export function signalGroupKey(f: Pick<FindingListItem, 'detectorId' | 'reason' | 'ruleId'>): string {
  return `${f.detectorId}|${f.reason}|${f.ruleId ?? ''}`
}

export type SignalRow =
  | { kind: 'single'; key: string; finding: FindingListItem }
  | { kind: 'group'; key: string; findings: FindingListItem[] }

/**
 * Collapses rows sharing (detector, reason, rule) into one group, placed where
 * its first member appeared, so the server's ordering (most recent first) is
 * kept for groups and singles alike. Keys seen once stay single rows.
 */
export function collapseSignals(findings: readonly FindingListItem[]): SignalRow[] {
  const byKey = new Map<string, FindingListItem[]>()
  for (const f of findings) {
    const k = signalGroupKey(f)
    const list = byKey.get(k)
    if (list) list.push(f)
    else byKey.set(k, [f])
  }
  const rows: SignalRow[] = []
  const placed = new Set<string>()
  for (const f of findings) {
    const k = signalGroupKey(f)
    const members = byKey.get(k)!
    if (members.length === 1) {
      rows.push({ kind: 'single', key: f.id, finding: f })
    } else if (!placed.has(k)) {
      placed.add(k)
      rows.push({ kind: 'group', key: k, findings: members })
    }
  }
  return rows
}

/** "HelmReleaseFailed" → "Helm release failed". */
export function humanizeReason(reason: string): string {
  const words = reason
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .split(/\s+/)
    .filter(Boolean)
  if (words.length === 0) return reason
  return [words[0], ...words.slice(1).map((w) => (/^[A-Z]{2,}$/.test(w) ? w : w.toLowerCase()))].join(' ')
}

/**
 * The fault line a person reads. The posture detector's reason is
 * "Posture<CheckId>" and its message starts "<check title> (<category>): …",
 * so the title is taken from the message; certificate and Helm reasons are
 * CamelCase words. Every other detector's reason is already the closed
 * vocabulary operators scan for, and is shown as is.
 */
export function readableSignalReason(f: Pick<FindingListItem, 'detectorId' | 'reason' | 'message'>): string {
  if (f.detectorId === 'k8s-posture') {
    const at = f.message.indexOf(' (')
    if (at > 0) return f.message.slice(0, at)
    return humanizeReason(f.reason.replace(/^Posture/, '')) || f.reason
  }
  if (f.detectorId === 'k8s-certificates' || f.detectorId === 'k8s-helm') return humanizeReason(f.reason)
  return f.reason || f.detectorId
}

/** Whether the rows on this page are the whole scoped set. */
export function pageIsWholeSet(pageIndex: number, nextCursor: string | null | undefined): boolean {
  return pageIndex === 0 && !nextCursor
}
