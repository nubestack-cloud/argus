import { useMemo, useState } from 'react'
import { formatDateTime, formatRelativeTime } from '../utils/time'
import { SplitBar } from '../components/SplitBar'
import { InspectFrame, type ClusterLiveness } from './InspectFrame'
import {
  KIND_STATE_TEXT,
  TOOL_LABEL,
  destinationText,
  groupProblems,
  healthWord,
  missingKinds,
  pathAtRevision,
  problemWord,
  sharedRepo,
  sortApps,
  sourceText,
  splitHeadline,
  syncHealthCounts,
  syncWord,
  type GitOpsAppList,
  type GitOpsAppRow,
  type ProblemGroup,
} from './gitopsModel'
import { useInspect } from './useInspect'
import { useOpenObjectTab } from './useOpenObjectTab'

// Cluster detail → GitOps (PROJECT.md AD5; owner-approved cluster-pages
// design, 2026-10-11). Sync and health as two bars, then the question: what
// is wrong with the GitOps applications here, and why. Problems are grouped by
// the reason the controller reports — one reason, said once, with every app
// it affects under it — and the apps with nothing wrong follow in a quiet
// table. Read-only: no sync, refresh or suspend control; a reconcile request
// is a quick action on an incident's plan (D-R12), and a desired-state change
// is a pull request.

const ARGS = {}
const INITIAL_QUIET = 25

function AppName({ clusterId, a }: { clusterId: string; a: GitOpsAppRow }) {
  const open = useOpenObjectTab()
  return (
    <div className="identity-block">
      <button
        type="button"
        className="link-button identity-block-name"
        title={`Open ${TOOL_LABEL[a.tool] ?? a.tool} ${a.kind} ${a.namespace}/${a.name} at its GitOps tab`}
        onClick={() => open({ clusterId, kind: a.kind, apiGroup: a.apiGroup, namespace: a.namespace, name: a.name }, 'gitops')}
      >
        {a.name}
      </button>
      <span className="identity-block-kind" title={sourceText(a)}>
        {pathAtRevision(a) || `${TOOL_LABEL[a.tool] ?? a.tool} ${a.kind}`}
      </span>
    </div>
  )
}

function Badge({ word, empty }: { word: { label: string; badge: string } | null; empty: string }) {
  return word ? <span className={word.badge}>{word.label}</span> : <span className="text-muted">{empty}</span>
}

function LastSync({ a }: { a: GitOpsAppRow }) {
  return a.lastSync ? <span title={formatDateTime(a.lastSync)}>{formatRelativeTime(a.lastSync)}</span> : <span className="text-muted">—</span>
}

/** One application per row: name and what it deploys, sync, health,
 *  destination, last sync. */
function AppRows({ clusterId, apps, tone, caption }: { clusterId: string; apps: readonly GitOpsAppRow[]; tone: string; caption: string }) {
  return (
    <div className="table-scroll">
      <table className="cluster-table list-table gitops-table">
        <caption className="visually-hidden">{caption}</caption>
        <thead>
          <tr>
            <th>Application</th>
            <th className="col-shrink">Sync</th>
            <th className="col-shrink">Health</th>
            <th>Destination</th>
            <th className="col-time">Last sync</th>
          </tr>
        </thead>
        <tbody>
          {apps.map((a) => (
            <tr key={`${a.kind}/${a.namespace}/${a.name}`} className={tone}>
              <td className="severity-rule">
                <AppName clusterId={clusterId} a={a} />
              </td>
              <td className="col-shrink">
                <Badge word={syncWord(a.sync)} empty="—" />
              </td>
              <td className="col-shrink">
                <span className="gitops-state">
                  <Badge word={healthWord(a.health)} empty="—" />
                  {a.suspended && <span className="badge badge-gray">Suspended</span>}
                </span>
              </td>
              <td className="gitops-dest">{destinationText(a)}</td>
              <td className="col-time">
                <LastSync a={a} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/** One reason the controller reports, said once, then every app it affects. */
function ProblemCard({ clusterId, g }: { clusterId: string; g: ProblemGroup }) {
  const word = problemWord(g)
  const { summary, raw, cause } = splitHeadline(g.headline)
  const repo = sharedRepo(g.apps)
  return (
    <section className="card gitops-problem" aria-label={`${g.apps.length} application${g.apps.length === 1 ? '' : 's'}: ${g.headline}`}>
      <div className="gitops-problem-head">
        <span className={word.badge}>{word.label}</span>
        <strong className="gitops-problem-summary">
          {summary}
          {repo && <span className="gitops-problem-repo"> · {repo}</span>}
        </strong>
        <span className="gitops-problem-count">
          {g.apps.length} {g.apps.length === 1 ? 'app' : 'apps'}
        </span>
      </div>
      <dl className="gitops-problem-lines">
        {cause && (
          <>
            <dt>Cause</dt>
            <dd>{cause}</dd>
          </>
        )}
        {g.causes.length > 0 && (
          <>
            <dt>Next</dt>
            <dd>{g.causes.join(' ')}</dd>
          </>
        )}
      </dl>
      {raw && (
        <details className="gitops-raw">
          <summary>Controller message</summary>
          <p className="fleet-mono">{raw}</p>
        </details>
      )}
      <AppRows clusterId={clusterId} apps={g.apps} tone="sev-high" caption={`Applications affected: ${summary}`} />
    </section>
  )
}

/** "Flux not installed on this cluster" when every Flux kind shares one
 *  state, instead of a phrase per kind. */
function gapPhrases(gaps: readonly { label: string; state: string }[]): string[] {
  const flux = gaps.filter((g) => g.label.startsWith('Flux '))
  const fluxSame = flux.length > 1 && flux.every((g) => g.state === flux[0].state)
  const rest = fluxSame ? gaps.filter((g) => !g.label.startsWith('Flux ')) : gaps
  const out = rest.map((g) => `${g.label} ${KIND_STATE_TEXT[g.state] ?? g.state}`)
  if (fluxSame) out.push(`Flux ${KIND_STATE_TEXT[flux[0].state] ?? flux[0].state}`)
  return out
}

function Summary({ result }: { result: GitOpsAppList }) {
  const { sync, health } = syncHealthCounts(result)
  const tools = [...new Set((result.apps ?? []).map((a) => TOOL_LABEL[a.tool] ?? a.tool))]
  const gaps = missingKinds(result)
  return (
    <div className="card card-compact gitops-summary">
      <div className="card-head">
        <h3>
          {result.counts.total} {result.counts.total === 1 ? 'application' : 'applications'}
        </h3>
        <span className="card-head-meta">
          {[...tools, ...gapPhrases(gaps)].join(' · ')}
        </span>
      </div>
      <div className="chart-card-grid gitops-summary-grid">
        <div>
          <div className="metric-tile-label">Sync</div>
          <SplitBar
            tall
            label="Sync"
            showZero
            parts={[
              { tone: 'unknown', value: sync.unknown, label: 'unknown' },
              { tone: 'ok', value: sync.synced, label: 'synced' },
              { tone: 'high', value: sync.outOfSync, label: 'out of sync' },
              ...(sync.reconciling ? [{ tone: 'info' as const, value: sync.reconciling, label: 'reconciling' }] : []),
            ]}
          />
        </div>
        <div>
          <div className="metric-tile-label">Health{result.truncated ? ' · listed apps' : ''}</div>
          <SplitBar
            tall
            label="Health"
            showZero
            parts={[
              { tone: 'ok', value: health.healthy, label: 'healthy' },
              { tone: 'critical', value: health.degraded, label: 'degraded' },
              { tone: 'info', value: health.progressing, label: 'progressing' },
              ...(health.suspended ? [{ tone: 'neutral' as const, value: health.suspended, label: 'suspended' }] : []),
              ...(health.unknown ? [{ tone: 'unknown' as const, value: health.unknown, label: 'unknown' }] : []),
            ]}
          />
        </div>
      </div>
    </div>
  )
}

export function GitOpsPanel({ clusterId, liveness }: { clusterId: string; liveness: ClusterLiveness }) {
  const { query, capabilityResolved, missing } = useInspect<GitOpsAppList>(clusterId, 'list_gitops_apps', ARGS)
  const [showAll, setShowAll] = useState(false)
  const rows = useMemo(() => sortApps(query.data?.result?.apps ?? []), [query.data])
  const { groups, quiet } = useMemo(() => groupProblems(rows), [rows])
  return (
    <section aria-label="GitOps applications">
      <InspectFrame
        label="GitOps applications"
        help="Argo CD Applications and Flux Kustomizations and HelmReleases, with the sync and health their controller reports. Each problem is read from the controller’s own status and said once, with the applications it affects under it. Read-only: a sync or reconcile request is a quick action on an incident’s plan, and a change to desired state is a pull request — neither is offered here."
        query={query}
        capabilityResolved={capabilityResolved}
        missing={missing}
        liveness={liveness}
        skeletonColumns={5}
      >
        {(result) => {
          const gaps = missingKinds(result)
          const allMissing = gaps.length > 0 && gaps.length === (result.kinds ?? []).length
          const visibleQuiet = showAll ? quiet : quiet.slice(0, INITIAL_QUIET)
          if (allMissing) {
            return (
              <p className="empty-state">
                No GitOps controller this page reads is visible on this cluster —{' '}
                {gaps.map((g) => `${g.label} ${KIND_STATE_TEXT[g.state] ?? g.state}`).join(', ')}.
              </p>
            )
          }
          return (
            <>
              <Summary result={result} />
              {result.truncated && (
                <p className="truncation-notice" role="status">
                  The agent lists at most {rows.length} applications, problems first; the sync bar covers all {result.counts.total}.
                </p>
              )}
              {rows.length === 0 ? (
                <p className="empty-state">No Argo CD Application, Flux Kustomization or HelmRelease exists on this cluster.</p>
              ) : (
                <>
                  {groups.length > 0 && (
                    <div className="gitops-problems">
                      {groups.map((g) => (
                        <ProblemCard key={g.headline} clusterId={clusterId} g={g} />
                      ))}
                    </div>
                  )}
                  {quiet.length > 0 && (
                    <>
                      <h3 className="gitops-section-title">In sync and healthy · {quiet.length}</h3>
                      <AppRows clusterId={clusterId} apps={visibleQuiet} tone="sev-low" caption="GitOps applications with nothing reported wrong" />
                      {quiet.length > INITIAL_QUIET && (
                        <p className="inventory-more">
                          <button type="button" className="secondary" onClick={() => setShowAll((v) => !v)} aria-expanded={showAll}>
                            {showAll ? `Show the first ${INITIAL_QUIET}` : `Show all ${quiet.length} applications`}
                          </button>
                        </p>
                      )}
                    </>
                  )}
                  {groups.length === 0 && quiet.length > 0 && (
                    <p className="text-muted gitops-all-well">Every application is in sync and healthy by its controller’s own report.</p>
                  )}
                </>
              )}
            </>
          )
        }}
      </InspectFrame>
    </section>
  )
}
