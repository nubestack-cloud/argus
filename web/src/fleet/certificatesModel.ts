// Certificate expiry (docs/CLUSTER_INSIGHT_SPECS.md CI-S16), as
// list_certificates returns it: internal/agent/tools_certs_helm.go certsResult
// + internal/agent/certexpiry Cert. Secret contents are never read; a
// certificate with no known expiry has daysLeft absent — unknown, never 0.

// RequestChain is cert-manager's own renewal chain (PG5, 2026-10-13 parity
// review): the newest CertificateRequest this Certificate owns and, when
// ACME-backed, the newest Order and Challenge beneath it. Any stage can be
// the dead end — a non-ACME issuer never reaches an Order, for instance —
// so every field past requestName is legitimately absent, never guessed.
export interface RequestChain {
  requestName: string
  requestReady: boolean
  requestReason?: string
  requestMessage?: string
  orderName?: string
  orderState?: string
  orderReason?: string
  challengeName?: string
  challengeState?: string
  challengeReason?: string
}

export interface CertificateRow {
  name: string
  namespace: string
  issuer: string
  domains: string
  expiry?: string
  daysLeft?: number | null
  health: string
  source: string
  endpoint?: string
  // readyReason/readyMessage (PG5) are cert-manager's own Ready condition,
  // set only while it is not True — a healthy Certificate has nothing here.
  readyReason?: string
  readyMessage?: string
  requestChain?: RequestChain
}

export interface CertificatesResult {
  observedAt?: string
  coverage?: { group?: string; kind: string; state: string; reason?: string }[]
  truncated?: boolean
  certificates?: CertificateRow[] | null
  servedProbed?: boolean
  probeErrors?: number
  // uncoveredTLSSecrets (PG5): Ingress/Gateway TLS secretNames this scan
  // could explain neither from a Certificate nor a served-endpoint probe.
  // A real, bounded count — see the panel's own HelpTip for what it does
  // not claim to cover.
  uncoveredTLSSecrets?: number
}

/** Health as words (certexpiry's thresholds: < 7 days or expired is
 *  unhealthy, < 30 days degraded). */
export const CERT_HEALTH: Record<string, { label: string; badge: string }> = {
  healthy: { label: 'Valid 30+ days', badge: 'badge badge-green' },
  degraded: { label: 'Expires within 30 days', badge: 'badge badge-amber' },
  unhealthy: { label: 'Expires within 7 days or expired', badge: 'badge badge-red' },
  unknown: { label: 'Expiry unknown', badge: 'badge badge-gray' },
}

export function certHealth(h: string): { label: string; badge: string } {
  return CERT_HEALTH[h] ?? CERT_HEALTH.unknown
}

export const CERT_SOURCE_LABEL: Record<string, string> = {
  'cert-manager': 'cert-manager Certificate',
  served: 'Served by an Ingress',
}

/** Soonest expiry first; unknown expiry last (it is not "soonest"). */
export function sortCertificates(rows: readonly CertificateRow[]): CertificateRow[] {
  return [...rows].sort((a, b) => {
    const da = a.daysLeft ?? null
    const db = b.daysLeft ?? null
    if (da === null && db === null) return `${a.namespace}/${a.name}`.localeCompare(`${b.namespace}/${b.name}`)
    if (da === null) return 1
    if (db === null) return -1
    return da - db
  })
}

/** certexpiry's own thresholds, so the runway's zones and the row's word
 *  agree (anti-patterns.md, "one fact, one claim"). */
export const CERT_UNHEALTHY_DAYS = 7
export const CERT_DEGRADED_DAYS = 30
/** The runway's linear span; anything later is drawn at the far end. */
export const RUNWAY_DAYS = 365

/** A certificate's position on the runway, 0–100. Past a year it sits at
 *  the end, beyond the "1y" tick, rather than squeezing the near term. */
export function runwayX(days: number): number {
  if (days > RUNWAY_DAYS) return 97
  return (Math.max(0, days) * 92) / RUNWAY_DAYS
}

export interface RunwayPin {
  x: number
  rows: CertificateRow[]
  minDays: number
  maxDays: number
}

/** Certificates close enough to overlap on the runway share one pin with a
 *  count. Unknown expiry is not drawn (it has no position). */
export function runwayPins(rows: readonly CertificateRow[], gap = 3): RunwayPin[] {
  const known = sortCertificates(rows).filter((r) => r.daysLeft != null)
  const pins: RunwayPin[] = []
  for (const r of known) {
    const d = r.daysLeft as number
    const x = runwayX(d)
    const last = pins[pins.length - 1]
    if (last && x - last.x < gap) {
      last.rows.push(r)
      last.maxDays = d
    } else {
      pins.push({ x, rows: [r], minDays: d, maxDays: d })
    }
  }
  return pins
}

/** "a, b +1 more" → first domain and how many others. The agent already
 *  shortens long lists this way (certexpiry), so this only re-reads it. */
export function domainSummary(domains: string): { first: string; others: number } {
  const trimmed = domains.trim()
  if (!trimmed) return { first: '', others: 0 }
  const more = /\s\+(\d+) more$/.exec(trimmed)
  const listed = (more ? trimmed.slice(0, more.index) : trimmed).split(',').map((s) => s.trim()).filter(Boolean)
  return { first: listed[0] ?? '', others: listed.length - 1 + (more ? Number(more[1]) : 0) }
}
