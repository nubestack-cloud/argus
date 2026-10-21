import { useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { HelpTip } from '../components/HelpTip'
import { Quantity } from '../components/Quantity'
import { withObjectPanel } from '../insight/panelUrl'
import { formatDateTime } from '../utils/time'
import {
  CERT_DEGRADED_DAYS,
  CERT_UNHEALTHY_DAYS,
  certHealth,
  domainSummary,
  runwayPins,
  runwayX,
  sortCertificates,
  type CertificateRow,
  type CertificatesResult,
} from './certificatesModel'
import { InspectFrame, type ClusterLiveness } from './InspectFrame'
import { useInspect } from './useInspect'

// Cluster detail → Certificates (docs/CLUSTER_INSIGHT_SPECS.md CI-S16;
// owner-approved cluster-pages design, 2026-10-11). The question is "what
// expires next, and is anything close?", so the dominant element is a
// runway: every certificate on one time axis with the agent's own
// unhealthy/degraded thresholds drawn as zones. The table below it is
// soonest first. Days left is unknown — never 0 — when a certificate has
// not been issued yet; a health word appears only on a row that is not
// healthy (the runway and the bar already say "fine" for the rest).

const ARGS = {}

const TICKS: readonly [number, string][] = [
  [0, 'today'],
  [30, '30d'],
  [90, '90d'],
  [180, '180d'],
  [365, '1y'],
]

function pinLabel(p: ReturnType<typeof runwayPins>[number]): string {
  if (p.rows.length === 1) return `${p.rows[0].name} · ${p.minDays}d`
  return `${p.rows.length} certificates · ${p.minDays === p.maxDays ? `${p.minDays}d` : `${p.minDays}–${p.maxDays}d`}`
}

function pinTone(days: number): string {
  if (days < CERT_UNHEALTHY_DAYS) return 'critical'
  if (days < CERT_DEGRADED_DAYS) return 'medium'
  return 'ok'
}

function Runway({ rows }: { rows: readonly CertificateRow[] }) {
  const pins = runwayPins(rows)
  const known = rows.filter((r) => r.daysLeft != null)
  const unknown = rows.length - known.length
  const soon = known.filter((r) => (r.daysLeft as number) < CERT_DEGRADED_DAYS).length
  const next = known.length ? Math.min(...known.map((r) => r.daysLeft as number)) : null
  return (
    <div className="card cert-runway-card">
      <div className="card-head">
        <h3>Expiry runway</h3>
        <span className="card-head-meta">
          {rows.length} {rows.length === 1 ? 'certificate' : 'certificates'} ·{' '}
          {soon === 0 ? `none within ${CERT_DEGRADED_DAYS} days` : `${soon} within ${CERT_DEGRADED_DAYS} days`}
          {next != null && ` · next in ${next} ${next === 1 ? 'day' : 'days'}`}
          {unknown > 0 && ` · ${unknown} expiry unknown`}
        </span>
      </div>
      <div className="cert-runway" role="img" aria-label={pins.map(pinLabel).join('; ') || 'No certificate with a known expiry'}>
        <span className="cert-runway-zone" data-zone="unhealthy" style={{ width: `${runwayX(CERT_UNHEALTHY_DAYS)}%` }} />
        <span
          className="cert-runway-zone"
          data-zone="degraded"
          style={{ left: `${runwayX(CERT_UNHEALTHY_DAYS)}%`, width: `${runwayX(CERT_DEGRADED_DAYS) - runwayX(CERT_UNHEALTHY_DAYS)}%` }}
        />
        <span className="cert-runway-axis" />
        {pins.map((p, i) => (
          <span key={p.rows[0].name + i} className="cert-runway-pin" data-tone={pinTone(p.minDays)} style={{ left: `${p.x}%` }}>
            <span className="cert-runway-dot" />
            <span
              className={`cert-runway-label${p.x > 75 ? ' cert-runway-label-end' : p.x < 25 ? ' cert-runway-label-start' : ''}`}
              style={{ bottom: `${22 + (i % 3) * 15}px` }}
            >
              {pinLabel(p)}
            </span>
          </span>
        ))}
        {TICKS.map(([d, t]) => (
          <span key={t} className={d === 30 ? 'cert-runway-tick cert-runway-tick-minor' : 'cert-runway-tick'} style={{ left: `${runwayX(d)}%` }}>
            {t}
          </span>
        ))}
        <span className="cert-runway-tick cert-runway-tick-minor" style={{ left: '97%' }}>
          later
        </span>
      </div>
      <p className="cert-runway-caption">
        Days left. Red under {CERT_UNHEALTHY_DAYS}, amber under {CERT_DEGRADED_DAYS}; anything past a year is drawn at the end.
      </p>
    </div>
  )
}

function DaysLeft({ c }: { c: CertificateRow }) {
  if (c.daysLeft == null) return <Quantity value={null} unknownLabel="expiry unknown" />
  const d = c.daysLeft
  return (
    <div className="cert-days">
      <div className="cert-days-head">
        <strong>{d}d</strong>
        {c.expiry && (
          <span className="text-muted" title={formatDateTime(c.expiry)}>
            {new Date(c.expiry).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })}
          </span>
        )}
      </div>
      <span className="resource-usage-track" aria-hidden="true">
        <span className="split-seg" data-tone={pinTone(d)} style={{ width: `${Math.min(100, (Math.max(0, d) * 100) / 365)}%`, borderRadius: 4 }} />
      </span>
    </div>
  )
}

export function CertificatesPanel({ clusterId, liveness }: { clusterId: string; liveness: ClusterLiveness }) {
  const { query, capabilityResolved, missing } = useInspect<CertificatesResult>(clusterId, 'list_certificates', ARGS)
  const [params, setParams] = useSearchParams()
  const rows = useMemo(() => sortCertificates(query.data?.result?.certificates ?? []), [query.data])
  return (
    <section aria-label="Certificates">
      <InspectFrame label="Certificates" help="cert-manager Certificates the agent can read, plus the certificates Ingresses actually serve when served-certificate probing is enabled on this agent. Secret contents are never read; expiry comes from the Certificate status or the served certificate." query={query} capabilityResolved={capabilityResolved} missing={missing} liveness={liveness} skeletonColumns={4}>
        {(result) => (
          <>
            {rows.length > 0 && <Runway rows={rows} />}
            <div className="panel-toolbar">
              <span className="badge badge-gray">Source: {result?.servedProbed ? 'cert-manager and served endpoints' : 'cert-manager only'}</span>
              {!result?.servedProbed && (
                <span className="text-muted cert-probe-note">
                  Served-certificate probing off
                  <HelpTip
                    label="Served-certificate probing"
                    text="Set certExpiry.probeIngressHosts on the argus-agent chart to also read the certificates Ingresses serve from plain Secrets. Until then those are not listed."
                  />
                </span>
              )}
              {!!result?.probeErrors && (
                <span className="badge badge-amber">
                  {result.probeErrors} {result.probeErrors === 1 ? 'endpoint' : 'endpoints'} not probed
                </span>
              )}
              {result && (
                <span className="text-muted cert-probe-note">
                  {result.uncoveredTLSSecrets
                    ? `${result.uncoveredTLSSecrets} TLS ${result.uncoveredTLSSecrets === 1 ? 'secret' : 'secrets'} not covered`
                    : 'Every TLS secret this scan can see is covered'}
                  <HelpTip
                    label="TLS secret coverage"
                    text={
                      result.servedProbed
                        ? 'Counts Ingress/Gateway TLS secretNames with no cert-manager Certificate issuing them and no served-certificate probe reading them. A reachable endpoint presenting a certificate from some other source still counts as covered; an unreachable one does not.'
                        : 'Counts Ingress/Gateway TLS secretNames with no cert-manager Certificate issuing them. Served-certificate probing is off on this agent, so a plain TLS secret could still be covered once it is enabled — set certExpiry.probeIngressHosts on the argus-agent chart.'
                    }
                  />
                </span>
              )}
            </div>
            {result?.truncated && (
              <p className="truncation-notice" role="status">
                The agent capped this list; more certificates exist than are shown.
              </p>
            )}
            {rows.length === 0 ? (
              <p className="empty-state">
                {result?.servedProbed
                  ? 'No certificates found: no cert-manager Certificate exists and no Ingress host served one.'
                  : 'No cert-manager Certificate exists on this cluster.'}
              </p>
            ) : (
              <div className="table-scroll">
                <table className="cluster-table list-table">
                  <thead>
                    <tr>
                      <th>Certificate</th>
                      <th>Domains</th>
                      <th>Issuer</th>
                      <th className="cert-expires-col">Expires</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((c) => {
                      const health = certHealth(c.health)
                      const isCertManager = c.source === 'cert-manager'
                      const dom = domainSummary(c.domains ?? '')
                      return (
                        <tr key={`${c.source}/${c.namespace}/${c.name}/${c.endpoint ?? ''}`} className={`sev-${c.health === 'unhealthy' ? 'critical' : c.health === 'degraded' ? 'medium' : c.health === 'healthy' ? 'low' : 'neutral'}`}>
                          <td className="severity-rule">
                            <div className="identity-block">
                              {isCertManager ? (
                                <button
                                  type="button"
                                  className="link-button identity-block-name"
                                  title="Open this Certificate in the inspector"
                                  onClick={() =>
                                    setParams(
                                      withObjectPanel(params, {
                                        clusterId,
                                        kind: 'Certificate',
                                        apiGroup: 'cert-manager.io',
                                        namespace: c.namespace || undefined,
                                        name: c.name,
                                      }),
                                    )
                                  }
                                >
                                  {c.name}
                                </button>
                              ) : (
                                <span className="identity-block-name">{c.name}</span>
                              )}
                              <span className="identity-block-kind">
                                {[c.namespace, c.endpoint].filter(Boolean).join(' · ') || '—'}
                              </span>
                              {c.health !== 'healthy' && <span className={health.badge}>{health.label}</span>}
                              {(c.readyReason || c.readyMessage) && (
                                <span className="text-muted fleet-mono">
                                  {[c.readyReason, c.readyMessage].filter(Boolean).join(': ')}
                                </span>
                              )}
                              {c.requestChain && (
                                <details>
                                  <summary className="text-muted">Renewal chain</summary>
                                  <p className="fleet-mono">
                                    Request {c.requestChain.requestName}: {c.requestChain.requestReady ? 'Ready' : c.requestChain.requestReason || 'not Ready'}
                                    {c.requestChain.requestMessage && ` — ${c.requestChain.requestMessage}`}
                                    {c.requestChain.orderName && (
                                      <>
                                        ; Order {c.requestChain.orderName}: {c.requestChain.orderState || 'unknown'}
                                        {c.requestChain.orderReason && ` (${c.requestChain.orderReason})`}
                                      </>
                                    )}
                                    {c.requestChain.challengeName && (
                                      <>
                                        ; Challenge {c.requestChain.challengeName}: {c.requestChain.challengeState || 'unknown'}
                                        {c.requestChain.challengeReason && ` — ${c.requestChain.challengeReason}`}
                                      </>
                                    )}
                                  </p>
                                </details>
                              )}
                            </div>
                          </td>
                          <td className="fleet-wrap" title={c.domains || undefined}>
                            {dom.first || <span className="text-muted">—</span>}
                            {dom.others > 0 && <span className="badge badge-gray cert-domain-more">+{dom.others}</span>}
                          </td>
                          <td className="cert-issuer">{c.issuer || <span className="text-muted">—</span>}</td>
                          <td className="cert-expires-col">
                            <DaysLeft c={c} />
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </InspectFrame>
    </section>
  )
}
