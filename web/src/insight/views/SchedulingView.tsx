import type { SchedulingResult } from '../types'

const CLASS_WORD: Record<string, string> = {
  InsufficientResource: 'Not enough free resources',
  UntoleratedTaint: 'Taint the pod does not tolerate',
  NodeAffinitySelector: 'Node selector or affinity does not match',
  PodAffinity: 'Pod affinity not satisfied',
  PodAntiAffinity: 'Pod anti-affinity conflict',
  TopologySpread: 'Topology spread constraint',
  VolumeNodeAffinity: 'Volume is bound to another zone or node',
  VolumeBinding: 'Volume cannot be bound',
  VolumeCount: 'Too many volumes on the node',
  NoPorts: 'Host port already in use',
  NodeUnschedulable: 'Node is cordoned',
  Other: 'Other',
}

// "Why won't this pod schedule?" (CI-S9): the agent's verdict sentence, then
// the nodes grouped by the reason they fail with a count per group (CI-U4),
// then the scheduler's own message as the evidence it was parsed from.
export function SchedulingView({ result }: { result: SchedulingResult }) {
  if (result.alreadyScheduled) {
    return (
      <div className="insight-stack">
        <p className="insight-lead">
          {result.verdict || `Already scheduled to ${result.nodeName ?? 'a node'}; this is not a scheduling problem.`}
        </p>
        <p className="field-hint">Bound but Pending means it waits on the node: a volume, an image or a container. The Events tab says which.</p>
      </div>
    )
  }
  const groups = [...(result.nodes ?? [])].sort((a, b) => b.count - a.count)
  const parsed = result.parsed ?? []
  return (
    <div className="insight-stack">
      {result.verdict && <p className="insight-lead">{result.verdict}</p>}
      {groups.length > 0 ? (
        <div className="table-scroll">
          <table className="data-table">
            <caption className="insight-caption">
              Nodes by reason{typeof result.nodesEvaluated === 'number' ? ` — ${result.nodesEvaluated} evaluated` : ''}
            </caption>
            <thead>
              <tr>
                <th scope="col" className="col-numeric">Nodes</th>
                <th scope="col">Reason</th>
                <th scope="col">Detail</th>
                <th scope="col">Examples</th>
              </tr>
            </thead>
            <tbody>
              {groups.map((g, i) => (
                <tr key={i}>
                  <td className="col-numeric">
                    <span className="row-group-count">{g.count}</span>
                  </td>
                  <td>{g.predicate === 'none' ? 'Passes these checks' : g.reason}</td>
                  <td className="insight-wrap">{g.detail || '—'}</td>
                  <td className="insight-mono insight-wrap">
                    {(g.examples ?? []).join(', ') || '—'}
                    {g.examples && g.examples.length < g.count ? ` (+${g.count - g.examples.length} more)` : ''}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="empty-state">No per-node evaluation was possible — the agent observed no nodes. Rely on the scheduler message below.</p>
      )}
      {(result.karpenter ?? []).length > 0 && (
        <div className="table-scroll">
          <table className="data-table">
            <caption className="insight-caption">Karpenter NodePools, in weight order — could a new node take this pod?</caption>
            <tbody>
              {(result.karpenter ?? []).map((v) => (
                <tr key={v.pool}>
                  <td className="insight-mono">{v.pool}</td>
                  <td>
                    <span className={v.fits ? 'badge badge-green' : 'badge badge-red'}>{v.fits ? 'Could launch' : 'Cannot'}</span>
                  </td>
                  <td className="insight-wrap">{v.reason || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {parsed.length > 0 && (
        <div>
          <p className="field-hint">What the scheduler reported</p>
          <ul className="insight-plain-list">
            {parsed.map((p, i) => (
              <li key={i}>
                {typeof p.nodeCount === 'number' ? <span className="row-group-count">{p.nodeCount} nodes</span> : null}{' '}
                {CLASS_WORD[p.class] ?? p.class}
                {p.detail ? ` — ${p.detail}` : ''}
              </li>
            ))}
          </ul>
        </div>
      )}
      {result.unsatisfiable && result.unsatisfiable.length > 0 && (
        <p className="insight-note">
          No node in the cluster can ever satisfy: {result.unsatisfiable.join('; ')}.
        </p>
      )}
      {typeof result.similarPendingPods === 'number' && result.similarPendingPods > 0 && (
        <p className="field-hint">
          {result.similarPendingPods} other pending pod{result.similarPendingPods === 1 ? '' : 's'} in this namespace share the same scheduling requirements, so
          the same answer applies to {result.similarPendingPods === 1 ? 'it' : 'them'}.
        </p>
      )}
      {result.schedulerMessage ? (
        <div>
          <p className="field-hint">Scheduler message</p>
          <pre className="code-view code-view-wrap">{result.schedulerMessage}</pre>
        </div>
      ) : (
        <p className="field-hint">No FailedScheduling event was found for this pod.</p>
      )}
    </div>
  )
}
