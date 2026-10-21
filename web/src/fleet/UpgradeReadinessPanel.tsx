import { useId, useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { ApiError, getLatestUpgradeScan, runUpgradeScan } from '../api/client'
import type { UpgradeScanEnvelope } from '../api/types'
import { CAP_CLUSTER_READ } from '../api/capabilities'
import { missingCapabilityMessage } from '../api/capabilityInfo'
import { useAuth } from '../auth/useAuth'
import { useHasCapability } from '../auth/useCapabilities'
import { formatDateTime, formatRelativeTime } from '../utils/time'
import { HelpTip } from '../components/HelpTip'
import { SkeletonLines } from '../components/Skeleton'
import { VerdictBadge, toVerdict, verdictLabel, type Verdict } from '../components/VerdictBadge'
import { BarList } from '../components/SplitBar'
import { withObjectPanel } from '../insight/panelUrl'
import { apiErrorText } from './apiErrorText'
import { isValidTarget, nextMinor } from './clusterSummary'
import { useFleetUpgradeScans } from './fleetUpgrade'
import {
  FINDINGS_DISPLAY_CAP,
  findingCounts,
  findingsByNamespace,
  groupChecks,
  groupFindings,
  stripOrder,
  type FindingGroup,
  isNextMinorScan,
  readScanResult,
  resourceLabel,
  scanErrorMessage,
  type UpgradeCheck,
  type UpgradeFinding,
} from './upgradeModel'

// Cluster detail → Upgrade readiness (docs/CLUSTER_INSIGHT_SPECS.md CI-S5).
// The question: "if we upgrade this cluster to 1.N, what breaks?" The answer
// is ordered by what stops the upgrade (Blocked → … → Not applicable), every
// verdict is a word, "we could not check" is Incomplete and never Passed, and
// the catalogue boundary ("checks reviewed through 1.N") is always stated —
// a scan is only as good as the releases its checks were written for.

function FindingRow({ clusterId, finding }: { clusterId: string; finding: UpgradeFinding }) {
  const [params, setParams] = useSearchParams()
  const r = finding.resource
  return (
    <li className="upgrade-object">
      {r ? (
        <button
          type="button"
          className="link-button fleet-mono"
          onClick={() =>
            setParams(
              withObjectPanel(params, {
                clusterId,
                kind: r.kind,
                apiGroup: r.group || undefined,
                namespace: r.namespace || undefined,
                name: r.name,
              }),
            )
          }
          title="Open this object in the inspector"
        >
          {resourceLabel(r)}
        </button>
      ) : (
        <span className="text-muted">Cluster-wide</span>
      )}
      {finding.evidence?.path && (
        <span className="text-muted upgrade-evidence">
          {finding.evidence.source} <span className="fleet-mono">{finding.evidence.path}</span>
          {finding.evidence.detail ? ` — ${finding.evidence.detail}` : ''}
        </span>
      )}
    </li>
  )
}

/** One kind of finding: the impact and fix said once, the objects one click away. */
function FindingGroupCard({ clusterId, g }: { clusterId: string; g: FindingGroup }) {
  const [showAll, setShowAll] = useState(false)
  const visible = showAll ? g.findings : g.findings.slice(0, FINDINGS_DISPLAY_CAP)
  const n = Math.max(g.total, g.findings.length)
  const noun = g.findings[0]?.resource?.kind ? `${g.findings[0].resource.kind}${n === 1 ? '' : 's'}` : n === 1 ? 'object' : 'objects'
  return (
    <div className="upgrade-fgroup">
      <div className="upgrade-fgroup-head">
        <strong>{g.title}</strong>
        <span className="upgrade-fgroup-count">
          {n} {noun}
        </span>
      </div>
      <dl className="gitops-problem-lines">
        {g.impact && (
          <>
            <dt>Impact</dt>
            <dd>{g.impact}</dd>
          </>
        )}
        {g.remediation && (
          <>
            <dt>Fix</dt>
            <dd>{g.remediation}</dd>
          </>
        )}
      </dl>
      <details className="upgrade-objects">
        <summary>
          {n} {noun}
          {n > g.findings.length ? ` (${g.findings.length} listed)` : ''}
        </summary>
        <ul>
          {visible.map((f, i) => (
            <FindingRow key={`${f.ruleID}-${i}`} clusterId={clusterId} finding={f} />
          ))}
        </ul>
        {g.findings.length > FINDINGS_DISPLAY_CAP && (
          <button type="button" className="link-button" onClick={() => setShowAll((v) => !v)}>
            {showAll ? `Show the first ${FINDINGS_DISPLAY_CAP}` : `Show all ${g.findings.length}`}
          </button>
        )}
      </details>
    </div>
  )
}

function References({ refs }: { refs?: { title: string; url: string }[] | null }) {
  if (!refs || refs.length === 0) return null
  return (
    <p className="fleet-references">
      <span className="text-muted">References: </span>
      {refs.map((ref, i) => (
        <span key={ref.url}>
          {i > 0 ? ' · ' : ''}
          <a href={ref.url} target="_blank" rel="noreferrer noopener">
            {ref.title}
          </a>
        </span>
      ))}
    </p>
  )
}

/** A check that blocks, warns or needs review: its findings grouped by
 *  kind beside a by-namespace chart, the summary and caveat above. */
function ProblemCheck({ clusterId, check }: { clusterId: string; check: UpgradeCheck }) {
  const verdict = toVerdict(check.status)
  const { shown, total } = findingCounts(check)
  const groups = groupFindings(check)
  const byNs = findingsByNamespace(check)
  return (
    <section className={`card upgrade-check upgrade-check-${verdict}`} aria-label={`${verdictLabel(verdict)}: ${check.title}`}>
      <div className="upgrade-check-head">
        <VerdictBadge verdict={verdict} />
        <strong>{check.title}</strong>
        <span className="text-muted">{check.category}</span>
        {total > 0 && (
          <span className="upgrade-check-count">
            {total} {total === 1 ? 'finding' : 'findings'}
            {shown < total ? ` · ${shown} sent` : ''}
          </span>
        )}
      </div>
      {check.summary && <p className="upgrade-check-summary">{check.summary}</p>}
      {check.caveat && (
        <p className="fleet-caveat">
          <strong>Caveat:</strong> {check.caveat}
        </p>
      )}
      {groups.length > 0 && (
        <div className="upgrade-check-body">
          <div className="upgrade-fgroups">
            {groups.map((g) => (
              <FindingGroupCard key={g.title} clusterId={clusterId} g={g} />
            ))}
          </div>
          {byNs.length > 1 && (
            <div>
              <div className="metric-tile-label">Findings by namespace{shown < total ? ` · ${shown} sent` : ''}</div>
              <BarList
                label="Findings by namespace"
                rows={byNs.slice(0, 8).map((n) => ({ key: n.namespace, name: n.namespace, parts: [{ tone: verdict === 'blocked' ? 'critical' : 'high', value: n.count, label: 'findings' }] }))}
              />
            </div>
          )}
        </div>
      )}
      <References refs={check.references} />
    </section>
  )
}

/** The full check, for the passed / not-applicable lists opened on demand. */
function CheckItem({ check }: { check: UpgradeCheck }) {
  return (
    <li>
      <strong>{check.title}</strong> <span className="text-muted">{check.category}</span>
      {check.summary && <span className="text-muted"> — {check.summary}</span>}
    </li>
  )
}

export function UpgradeReadinessPanel({ clusterId, kubernetesVersion }: { clusterId: string; kubernetesVersion?: string }) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const canRun = useHasCapability(CAP_CLUSTER_READ)
  const inputId = useId()
  const listId = useId()

  const scanQuery = useQuery({
    queryKey: ['upgrade-scan', clusterId],
    queryFn: () => getLatestUpgradeScan(clusterId, accessToken!),
    enabled: !!accessToken,
  })
  const scan = scanQuery.data?.scan ?? null
  const result = readScanResult(scan?.result)
  const current = scan?.currentVersion || kubernetesVersion
  const suggested = nextMinor(current)
  const [target, setTarget] = useState('')
  const effectiveTarget = target.trim() || suggested || ''

  const run = useMutation({
    mutationFn: (t: string) => runUpgradeScan(clusterId, t, accessToken!),
    onSuccess: (data: UpgradeScanEnvelope) => {
      queryClient.setQueryData(['upgrade-scan', clusterId], data)
      void queryClient.invalidateQueries({ queryKey: ['upgrade-scans'] })
    },
  })

  // The hub is the authority on the usable range (it knows the catalogue's
  // reviewed release); the form only catches what it can see for itself.
  const notNewer = (() => {
    const t = /^1\.(\d{1,3})$/.exec(target.trim())
    const c = /^v?1\.(\d+)/.exec(current ?? '')
    return !!t && !!c && Number(t[1]) <= Number(c[1])
  })()
  const targetInvalid = target.trim() !== '' && (!isValidTarget(target) || notNewer)
  const { byCluster: nextByCluster } = useFleetUpgradeScans()
  const nextScan = nextByCluster.get(clusterId)
  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (targetInvalid) return
    run.mutate(target.trim())
  }

  const runError = run.error
  const groups = groupChecks(result?.checks)
  const suggestions = suggested ? [suggested, nextMinor(suggested)].filter(Boolean) : []

  const ordered = stripOrder(result?.checks)
  const blockers = groups.find((g) => g.verdict === 'blocked')?.checks.length ?? 0
  const problemGroups = groups.filter((g) => g.verdict === 'blocked' || g.verdict === 'warning' || g.verdict === 'review')
  const incomplete = groups.find((g) => g.verdict === 'incomplete')?.checks ?? []
  const quiet = groups.filter((g) => g.verdict === 'passed' || g.verdict === 'notApplicable')
  const count = (v: Verdict) => groups.find((g) => g.verdict === v)?.checks.length ?? 0

  const form = (
    <form className="upgrade-run" onSubmit={submit}>
      <label className="visually-hidden" htmlFor={inputId}>
        Target version
      </label>
      <input
        id={inputId}
        type="text"
        inputMode="decimal"
        list={listId}
        value={target}
        className="upgrade-target"
        placeholder={suggested ?? '1.N'}
        onChange={(e) => setTarget(e.target.value)}
        aria-invalid={targetInvalid}
        aria-describedby={targetInvalid ? `${inputId}-err` : undefined}
      />
      <datalist id={listId}>
        {suggestions.map((v) => (
          <option key={v} value={v!} />
        ))}
      </datalist>
      <button
        type="submit"
        disabled={!canRun || run.isPending || targetInvalid}
        title={canRun ? undefined : missingCapabilityMessage([CAP_CLUSTER_READ])}
      >
        {run.isPending ? 'Scanning…' : `Scan now${effectiveTarget ? ` for ${effectiveTarget}` : ''}`}
      </button>
      {targetInvalid && (
        <span id={`${inputId}-err`} className="form-error upgrade-target-err">
          {notNewer
            ? `Choose a version newer than the cluster's ${current}${suggested ? `, starting at ${suggested}` : ''}.`
            : `Use the form 1.N, for example ${suggested ?? '1.33'}.`}
        </span>
      )}
    </form>
  )

  return (
    <section className="fleet-upgrade" aria-label="Upgrade readiness">
      {runError && (
        <p className="form-error" role="alert">
          {runError instanceof ApiError ? scanErrorMessage(runError.status, runError.detail) : scanErrorMessage(undefined)}
        </p>
      )}

      {scanQuery.isLoading && (
        <div aria-busy="true" aria-label="Loading upgrade readiness">
          <SkeletonLines count={3} widths={['18rem', '24rem', '12rem']} />
          <SkeletonLines count={4} />
        </div>
      )}

      {scanQuery.isError && (
        <p className="form-error" role="alert">
          {apiErrorText(scanQuery.error, 'The latest upgrade scan could not be loaded.')}
        </p>
      )}

      {!scanQuery.isLoading && !scanQuery.isError && !scan && (
        <div className="card upgrade-head">
          <p className="empty-state">No upgrade scan has run for this cluster yet; the hub scans each connected cluster daily for the next minor.</p>
          {form}
        </div>
      )}

      {scan && (
        <>
          <div className="card upgrade-head">
            <div className="upgrade-verdict">
              <span className="metric-tile-label">
                Upgrade {scan.currentVersion || '?'} → {scan.targetVersion}{' '}
                <HelpTip
                  label="the upgrade verdict"
                  text="The agent’s checks of this cluster against the target Kubernetes minor version: APIs, component and node options the release removes, networking, storage and observability changes, the upgrade path and node health. Blocked means something must change first; Review needs a person to look; Could not check means a check could not run, never that it passed."
                />
              </span>
              <span className="upgrade-verdict-line">
                <span className="upgrade-verdict-badge">
                  <VerdictBadge verdict={toVerdict(scan.verdict)} />
                </span>
                {blockers > 0 ? (
                  <span className="text-muted">
                    by {blockers} {blockers === 1 ? 'check' : 'checks'}
                  </span>
                ) : toVerdict(scan.verdict) === 'passed' ? (
                  <span className="text-muted">no known blockers</span>
                ) : null}
              </span>
            </div>
            {ordered.length > 0 && (
              <div className="upgrade-strip-wrap">
                <ol className="upgrade-strip" aria-label="Every check, worst first">
                  {ordered.map((c) => {
                    const v = toVerdict(c.status)
                    return (
                      <li key={c.id} className="upgrade-strip-cell" data-verdict={v} title={`${c.title} — ${verdictLabel(v)}`}>
                        <span className="visually-hidden">
                          {c.title}: {verdictLabel(v)}
                        </span>
                      </li>
                    )
                  })}
                </ol>
                <ul className="split-legend" aria-hidden="true">
                  {(
                    [
                      ['blocked', 'critical', 'blocked'],
                      ['warning', 'high', 'warning'],
                      ['review', 'info', 'review'],
                      ['incomplete', 'unknown', 'could not check'],
                      ['passed', 'ok', 'passed'],
                      ['notApplicable', 'neutral', 'not applicable'],
                    ] as const
                  )
                    .filter(([v]) => count(v) > 0 || v === 'blocked' || v === 'passed')
                    .map(([v, tone, word]) => (
                      <li key={v}>
                        <span className="split-swatch" data-tone={tone} />
                        <strong>{count(v)}</strong> {word}
                      </li>
                    ))}
                </ul>
              </div>
            )}
            <div className="upgrade-head-side">
              <span className="text-muted upgrade-head-meta">
                scanned <span title={formatDateTime(scan.scannedAt)}>{formatRelativeTime(scan.scannedAt)}</span> · rules through {scan.reviewedThrough || '—'}
              </span>
              {form}
            </div>
          </div>
          {isNextMinorScan(scan) === false && (
            <p className="field-hint">
              A one-off scan for {scan.targetVersion}. The Clusters list and the Overview show the verdict for the next minor,{' '}
              {nextMinor(scan.currentVersion) ?? 'the next release'}:{' '}
              {nextScan ? (
                <>
                  <VerdictBadge verdict={toVerdict(nextScan.verdict)} /> scanned {formatRelativeTime(nextScan.scannedAt)}.
                </>
              ) : (
                'not scanned yet — the daily scan will run it, or run it now for that version.'
              )}
            </p>
          )}
          {groups.length === 0 ? (
            <p className="empty-state">The stored scan carries no check results.</p>
          ) : (
            <>
              {problemGroups.flatMap((g) => g.checks.map((c) => <ProblemCheck key={c.id} clusterId={clusterId} check={c} />))}
              {incomplete.length > 0 && (
                <section className="card card-compact" aria-label="Could not check">
                  <div className="card-head">
                    <h3>Could not check · {incomplete.length}</h3>
                    <HelpTip label="Could not check" text="An unchecked rule is never a pass: the agent could not collect what the check needs. Each row says what was missing." />
                  </div>
                  <div className="table-scroll">
                    <table className="cluster-table upgrade-unknown-table">
                      <tbody>
                        {incomplete.map((c) => (
                          <tr key={c.id}>
                            <td>
                              <strong>{c.title}</strong>
                            </td>
                            <td className="col-shrink text-muted">{c.category}</td>
                            <td className="text-muted">{c.caveat || c.summary}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              )}
              {quiet.map((g) => (
                <details key={g.verdict} className="card card-compact upgrade-quiet">
                  <summary>
                    <VerdictBadge verdict={g.verdict} /> <strong>{g.checks.length}</strong>
                    <span className="text-muted upgrade-quiet-names">{g.checks.map((c) => c.title).join(', ')}</span>
                  </summary>
                  <ul className="upgrade-quiet-list">
                    {g.checks.map((c) => (
                      <CheckItem key={c.id} check={c} />
                    ))}
                  </ul>
                </details>
              ))}
            </>
          )}
        </>
      )}
    </section>
  )
}
