// The incident list's filters as data: one axis per control, every one of
// them applied by the server, and every count read from the same status ×
// severity matrix (`breakdown` on GET /incidents) so a number beside a control
// is what clicking it would show under every other active filter.
//
//   status    tabs      Open (default) · Needs action · In progress · Closed · All
//   severity  dropdown  Critical · High · Medium · Low
//   state     dropdown  the states inside the chosen status, to narrow further
//   cluster   dropdown
//
// Status is the lifecycle disposition (STATE_DISPOSITION), the one question a
// person opening this page is asking first: what is still going on. Severity
// used to sit on the same tab row as "Needs action", which mixed two axes and
// left no way to ask for "critical and needing action".
import type { IncidentsResponse, IncidentState } from '../api/types'
import { STATE_DISPOSITION, type IncidentDisposition } from '../utils/incidents'

export type StatusView = 'open' | 'requiresAction' | 'inProgress' | 'closed' | 'all'
export const STATUS_VIEWS: StatusView[] = ['open', 'requiresAction', 'inProgress', 'closed', 'all']
export const DEFAULT_STATUS: StatusView = 'open'
export const STATUS_LABEL: Record<StatusView, string> = {
  open: 'Open',
  requiresAction: 'Needs action',
  inProgress: 'In progress',
  closed: 'Closed',
  all: 'All',
}
export const STATUS_HINT: Record<StatusView, string> = {
  open: 'Everything whose lifecycle is not over: needs action plus in progress',
  requiresAction: 'Nothing happens until a person acts',
  inProgress: 'ARGUS or a reviewer owns the next move: investigating, executing, validating, awaiting merge',
  closed: 'Resolved, dismissed or expired',
  all: 'Every state',
}

export type Severity = 'critical' | 'high' | 'medium' | 'low'
export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low']
export const SEVERITY_FILTERS: Array<Severity | ''> = ['', ...SEVERITIES]
export const SEVERITY_FILTER_LABEL: Record<Severity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' }

export type Breakdown = NonNullable<IncidentsResponse['breakdown']>

export function statusIncludes(status: StatusView, disposition: IncidentDisposition): boolean {
  if (status === 'all') return true
  if (status === 'open') return disposition !== 'closed'
  return status === disposition
}

/** The states a state filter may offer under this status, in the given order. */
export function statesFor(status: StatusView, states: readonly IncidentState[]): IncidentState[] {
  return states.filter((s) => statusIncludes(status, STATE_DISPOSITION[s] ?? 'requiresAction'))
}

/**
 * Matching incidents for a status and severity, from the breakdown. Undefined
 * until the server has answered, so the control shows a dash rather than a
 * fabricated zero.
 */
export function countFor(breakdown: Breakdown | undefined, status: StatusView, severity: Severity | ''): number | undefined {
  if (!breakdown) return undefined
  let n = 0
  for (const cell of breakdown) {
    if (!statusIncludes(status, cell.status)) continue
    if (severity && cell.severity !== severity) continue
    n += cell.count
  }
  return n
}

/**
 * Old links used ?view= for a mixed set of tabs: requiresAction, or a
 * severity across every state. Rewritten once to the two axes that replaced
 * it, so a bookmark or the overview's tile still lands on the same set.
 */
export function legacyViewParams(view: string | null): { status?: StatusView; severity?: Severity } | null {
  if (!view) return null
  if (view === 'requiresAction') return { status: 'requiresAction' }
  if (view === 'all') return { status: 'all' }
  if ((SEVERITIES as string[]).includes(view)) return { status: 'all', severity: view as Severity }
  return {}
}
