import { useId, useMemo, useState } from 'react'
import { describeArgs, reproducerFor } from '../../evidence/reproducer'
import { InsightFooter, QueryBody } from '../InsightParts'
import { containersOf, filterLogLines } from '../model'
import { NODE_STATUS_WORD, neighborhoodArgs, workloadPods } from '../summaryModel'
import type { DescribeResult, NeighborhoodResult } from '../types'
import { useInspect } from '../useInspect'
import { CodeLines } from '../views/CodeLines'
import type { TabProps } from './common'

const TAIL_SIZES = [100, 500, 1000, 2000] as const

// Logs (CI-S6): a Pod's container logs, or — for a workload — a picker over
// the pods it owns first. The pods come from the same get_neighborhood read
// the Summary's Pods card uses (the agent draws a Deployment straight to its
// pods, past the ReplicaSets), so the two can never disagree about what a
// workload runs. Read on demand, tail-limited by the agent, and every read is
// written to the audit log by the hub (logs are the highest-residual-risk
// read even after redaction). The search box filters the lines already
// fetched; it is a find-in-page, not a server query.
export function LogsTab({ target, cluster, describe }: TabProps) {
  const isPod = target.kind === 'Pod'
  const nb = useInspect<NeighborhoodResult>(target.clusterId, 'get_neighborhood', neighborhoodArgs(target), !isPod)
  const owned = useMemo(() => workloadPods(nb.data?.result), [nb.data])
  const pods = owned.rows.map((p) => p.name)
  const [chosenPod, setChosenPod] = useState('')
  const pod = isPod ? target.name : chosenPod || pods[0] || ''

  if (!isPod && nb.isLoading) {
    return <QueryBody query={nb}>{() => null}</QueryBody>
  }
  if (!isPod && nb.isError) {
    return (
      <QueryBody query={nb} errorFallback="The agent could not list the pods this object owns.">
        {() => null}
      </QueryBody>
    )
  }
  if (!isPod && pods.length === 0) {
    return <p className="empty-state">This {target.kind} has no pods right now, so there are no logs to read.</p>
  }
  return (
    <div className="insight-stack">
      {!isPod && (
        <label className="insight-field">
          Pod
          <select value={pod} onChange={(e) => setChosenPod(e.target.value)}>
            {owned.rows.map((p) => (
              <option key={p.name} value={p.name}>
                {p.name} — {[p.phase, NODE_STATUS_WORD[p.status].toLowerCase()].filter(Boolean).join(', ')}
              </option>
            ))}
          </select>
        </label>
      )}
      {!isPod && owned.total > owned.rows.length && (
        <p className="field-hint">
          Listing {owned.rows.length} of {owned.total} pods — the agent names the worst first; the rest are on the Related tab.
        </p>
      )}
      <PodLogs key={pod} target={target} pod={pod} cluster={cluster} podDescribe={isPod ? describe.data?.result : undefined} />
    </div>
  )
}

function PodLogs({
  target,
  pod,
  cluster,
  podDescribe,
}: {
  target: TabProps['target']
  pod: string
  cluster: TabProps['cluster']
  podDescribe?: DescribeResult
}) {
  const namespace = target.namespace ?? ''
  // The container list comes from the Pod's own spec: the inspector's shared
  // describe read for a Pod, or one read of the chosen pod for a workload.
  const own = useInspect<DescribeResult>(target.clusterId, 'describe_resource', describeArgs({ kind: 'Pod', namespace, name: pod }), !podDescribe)
  const podObj = podDescribe?.object ?? own.data?.result?.object
  const containers = containersOf(podObj)
  const [container, setContainer] = useState('')
  const chosen = container || containers.find((c) => !c.init)?.name || containers[0]?.name || ''
  const [previous, setPrevious] = useState(false)
  const [tail, setTail] = useState<number>(500)
  const [search, setSearch] = useState('')
  const [wrap, setWrap] = useState(true)
  const searchId = useId()

  const fact = containers.find((c) => c.name === chosen)
  // What the pod's own status already says about whether there is a log to
  // read: a container still waiting to start (ContainerCreating,
  // ImagePullBackOff…) has never written one, and one that has never
  // restarted has no previous instance. Asking the agent anyway only returns
  // its refusal, so the answer is given here, from the status that decides it.
  const waitingReason = fact && !fact.ready && fact.state?.startsWith('waiting') && !fact.restartCount ? (/\((.+)\)/.exec(fact.state)?.[1] ?? 'waiting') : null
  const noPrevious = fact?.restartCount === 0
  const wantPrevious = previous && !noPrevious
  const args = {
    namespace,
    pod,
    container: chosen,
    previous: wantPrevious,
    tailLines: tail,
  }
  const logs = useInspect<{ lines?: string[] | null }>(target.clusterId, 'get_logs', args, !!pod && (!!podObj || own.isError) && !waitingReason)
  const lines = useMemo(() => logs.data?.result?.lines ?? [], [logs.data])
  const shown = useMemo(() => filterLogLines(lines, search), [lines, search])

  return (
    <div className="insight-stack">
      <div className="insight-controls" role="group" aria-label="Log options">
        <label className="insight-field">
          Container
          <select value={chosen} onChange={(e) => setContainer(e.target.value)} disabled={containers.length === 0}>
            {containers.length === 0 && <option value="">{own.isLoading ? 'Loading…' : 'default'}</option>}
            {containers.map((c) => (
              <option key={`${c.init}-${c.name}`} value={c.name}>
                {c.name}
                {c.init ? ' (init)' : ''}
              </option>
            ))}
          </select>
        </label>
        <label className="insight-field">
          Lines
          <select value={tail} onChange={(e) => setTail(Number(e.target.value))}>
            {TAIL_SIZES.map((n) => (
              <option key={n} value={n}>
                last {n}
              </option>
            ))}
          </select>
        </label>
        <label className="checkbox-row" title={noPrevious ? 'This container has not restarted, so there is no previous instance to read.' : undefined}>
          <input type="checkbox" checked={wantPrevious} disabled={noPrevious} onChange={(e) => setPrevious(e.target.checked)} /> Previous container
          {noPrevious ? <span className="field-hint"> (no restarts)</span> : null}
        </label>
        <label className="checkbox-row">
          <input type="checkbox" checked={wrap} onChange={(e) => setWrap(e.target.checked)} /> Wrap
        </label>
        <button type="button" className="secondary" onClick={() => logs.refetch()} disabled={logs.isFetching || !pod || !!waitingReason}>
          {logs.isFetching ? 'Reading…' : 'Refresh'}
        </button>
      </div>
      {!waitingReason && (
        <>
          <div className="insight-controls">
            <label className="insight-field insight-field-grow" htmlFor={searchId}>
              Find in these lines
            </label>
            <input id={searchId} type="search" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Text to match" />
          </div>
          <p className="field-hint">
            Reading logs is recorded in the audit log. Values the agent recognises as secrets are redacted before they leave the cluster.
          </p>
        </>
      )}
      {waitingReason ? (
        <p className="empty-state">
          Container {chosen} has not started yet ({waitingReason}), so it has written no logs. The Events tab says what it is waiting for.
        </p>
      ) : (
        <QueryBody query={logs} lines={10} errorFallback="The agent could not read these logs.">
          {(res) => {
            if (lines.length === 0) {
              return (
                <p className="empty-state">
                  {wantPrevious
                    ? 'No previous container logs — the container has not restarted, or its previous logs are gone.'
                    : 'The container wrote no log lines in the requested tail.'}
                </p>
              )
            }
            return (
              <>
                <p className="field-hint" aria-live="polite">
                  {search.trim()
                    ? `${shown.length} of ${lines.length} fetched lines match “${search.trim()}”.`
                    : `Last ${lines.length} line${lines.length === 1 ? '' : 's'}${lines.length >= tail ? ` (the requested tail — older lines exist)` : ''}.`}
                </p>
                {shown.length === 0 ? (
                  <p className="empty-state">
                    No fetched line matches “{search.trim()}”.{' '}
                    <button type="button" className="link-button insight-inline-link" onClick={() => setSearch('')}>
                      Clear the search
                    </button>
                  </p>
                ) : (
                  <CodeLines lines={shown} wrap={wrap} numbered={false} label={`Logs for ${pod}${chosen ? ` container ${chosen}` : ''}`} />
                )}
                <InsightFooter at={res.receivedAt} cluster={cluster} command={reproducerFor('get_logs', args)} />
              </>
            )
          }}
        </QueryBody>
      )}
    </div>
  )
}
