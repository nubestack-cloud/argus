import { useMemo, useState } from 'react'
import { urlString, useUrlState } from '../hooks/useUrlState'
import { SkeletonLines } from '../components/Skeleton'
import { FilterChips, SplitBar } from '../components/SplitBar'
import { VerdictBadge } from '../components/VerdictBadge'
import { HelpTip } from '../components/HelpTip'
import { InspectFrame, type ClusterLiveness } from './InspectFrame'
import { apiErrorText } from './apiErrorText'
import {
  ISOLATION_WORD,
  defaultPolicyNamespace,
  filterWorkloads,
  findingsFor,
  isolationOf,
  isolationParts,
  peerLabel,
  peerTone,
  sortFindings,
  sortWorkloads,
  type NetworkPolicyAllow,
  type NetworkPolicyFinding,
  type NetworkPolicyIndexRow,
  type NetworkPolicyMap,
  type NetworkPolicyWorkload,
  type WorkloadFilter,
} from './netpolModel'
import { useInspect } from './useInspect'
import { compareWithTraffic, groupUnseen } from './policyVsTraffic'
import { endpointLabel, trafficUnavailableReason, type TrafficResult } from './trafficModel'
import { formatAmount, measureOf, amount } from './trafficLevels'

// Cluster detail → Network policy. One namespace at a time, like the Map:
// for every workload, what can reach it and what it can reach, each policy
// selector resolved to what it matches now, with the recommendations the
// agent derives (internal/agent/netpolmap) above. Workloads a recommendation
// names come first and open; the rest are one line each. ?npns= carries the
// namespace.

const SCHEMA = { npns: urlString('') }
const NO_ARGS = {}
const RAIL_SHOWN = 14
const OPEN_ALL_UP_TO = 6

export function NetworkPolicyPanel({ clusterId, liveness }: { clusterId: string; liveness: ClusterLiveness }) {
  const [state, setState] = useUrlState(SCHEMA)
  const index = useInspect<NetworkPolicyMap>(clusterId, 'get_network_policy_map', NO_ARGS)
  const rows = useMemo(() => index.query.data?.result?.namespaces ?? [], [index.query.data])
  const fallback = defaultPolicyNamespace(rows)
  const ns = state.npns || fallback?.name || ''
  const args = useMemo(() => ({ namespace: ns }), [ns])
  const mapQuery = useInspect<NetworkPolicyMap>(clusterId, 'get_network_policy_map', args, !!ns)
  const denied = index.capabilityResolved && index.missing.length > 0

  return (
    <section aria-label="Network policy" className={denied ? undefined : 'nsmap-layout'}>
      {!denied && (
        <PolicyRail
          rows={rows}
          selected={ns}
          loading={index.query.isLoading}
          onSelect={(name) => setState({ npns: name }, { push: true })}
        />
      )}
      <div className="nsmap-main">
        {!ns && !denied ? (
          index.query.isError ? (
            <div className="fleet-inline-error">
              <p className="form-error" role="alert">
                {apiErrorText(index.query.error, 'The network policy index could not be read from the agent.')}
              </p>
              <button type="button" className="secondary" onClick={() => void index.query.refetch()}>
                Try again
              </button>
            </div>
          ) : !index.capabilityResolved || index.query.isLoading || !index.query.data ? (
            <div aria-busy="true" aria-label="Loading namespaces">
              <SkeletonLines count={4} />
            </div>
          ) : (
            <p className="empty-state">The agent reported no namespaces with pods or policies.</p>
          )
        ) : (
          <InspectFrame
            label={`Network policy in ${ns}`}
            help="What each workload's NetworkPolicies let in and out, with every selector resolved to the workloads, namespaces or node addresses it matches now. A connection between two workloads is judged from both ends: a rule one side allows but the other refuses is marked refused, because that traffic can never arrive. Predicted from the policy objects; the network plugin enforces them, and plugin-specific policies (Cilium, Calico) are not read."
            query={mapQuery.query}
            capabilityResolved={mapQuery.capabilityResolved}
            missing={mapQuery.missing}
            liveness={liveness}
            skeletonColumns={3}
          >
            {(r) => <PolicyMapBody map={r} clusterId={clusterId} />}
          </InspectFrame>
        )}
      </div>
    </section>
  )
}

function PolicyMapBody({ map, clusterId }: { map: NetworkPolicyMap; clusterId: string }) {
  const [filter, setFilter] = useState<WorkloadFilter>('all')
  const namespace = map.namespace ?? ''
  const workloads = useMemo(() => map.workloads ?? [], [map.workloads])
  const findings = useMemo(() => sortFindings(map.findings ?? []), [map.findings])
  const sorted = useMemo(() => sortWorkloads(workloads, findings), [workloads, findings])
  const shown = filterWorkloads(sorted, findings, filter)
  const withRecs = filterWorkloads(workloads, findings, 'recommendations').length
  const open = filterWorkloads(workloads, findings, 'open').length
  const policies = map.policies ?? []

  return (
    <div className="netpol-body">
      <p className="fleet-scope-note" role="note">
        {map.note}
      </p>
      {workloads.length === 0 ? (
        <p className="empty-state">
          No running pods in {namespace}
          {policies.length > 0 ? `, so its ${policies.length} ${policies.length === 1 ? 'policy applies' : 'policies apply'} to nothing yet.` : '.'}
        </p>
      ) : (
        <div className="card card-compact">
          <div className="card-head">
            <h3>Isolation</h3>
            <span className="card-head-meta">
              {workloads.length} {workloads.length === 1 ? 'workload' : 'workloads'} · {policies.length} {policies.length === 1 ? 'policy' : 'policies'}
              {map.workloadsTruncated ? ' · first 300 workloads' : ''}
            </span>
          </div>
          <SplitBar label="Workloads by isolation" parts={isolationParts(workloads)} showZero />
        </div>
      )}

      <div className="card card-compact">
        <div className="card-head">
          <h3>Recommendations</h3>
          <span className="card-head-meta">{findings.length === 0 ? 'none' : `${findings.length}, warnings first`}</span>
        </div>
        {findings.length === 0 ? (
          <p className="text-muted netpol-none">Nothing to recommend from the policies as written.</p>
        ) : (
          <div className="upgrade-fgroups">
            {findings.map((f) => (
              <FindingGroup key={f.code} f={f} />
            ))}
          </div>
        )}
      </div>

      {workloads.length > 0 && <PolicyVsTraffic map={map} clusterId={clusterId} />}

      {workloads.length > 0 && (
        <>
          <div className="panel-toolbar">
            <FilterChips<WorkloadFilter>
              label="Show workloads"
              value={filter}
              onChange={setFilter}
              options={[
                { id: 'all', label: 'All', count: workloads.length },
                { id: 'recommendations', label: 'With a recommendation', count: withRecs },
                { id: 'open', label: 'Accept from anyone', count: open },
              ]}
            />
          </div>
          {shown.length === 0 ? (
            <p className="empty-state">No workload in {namespace} matches this filter.</p>
          ) : (
            <ul className="netpol-workloads" aria-label={`Workloads in ${namespace}`}>
              {shown.map((w) => (
                <WorkloadRow
                  key={`${w.kind}/${w.name}`}
                  w={w}
                  namespace={namespace}
                  findings={findingsFor(w, findings)}
                  defaultOpen={!w.hostNetwork && w.policies.length > 0 && (findingsFor(w, findings).length > 0 || shown.length <= OPEN_ALL_UP_TO)}
                />
              ))}
            </ul>
          )}
        </>
      )}
    </div>
  )
}

function FindingGroup({ f }: { f: NetworkPolicyFinding }) {
  const n = f.objects.length + (f.more ?? 0)
  return (
    <div className="upgrade-fgroup">
      <div className="upgrade-fgroup-head">
        <VerdictBadge verdict={f.severity === 'warning' ? 'warning' : 'review'} />
        <strong>{f.title}</strong>
        <span className="upgrade-fgroup-count">{n}</span>
      </div>
      <dl className="gitops-problem-lines">
        <dt>Fix</dt>
        <dd>{f.fix}</dd>
      </dl>
      <details className="upgrade-objects">
        <summary>
          {n} {n === 1 ? 'object' : 'objects'}
        </summary>
        <ul>
          {f.objects.map((o) => (
            <li key={o}>{o}</li>
          ))}
          {f.more ? <li className="text-muted">and {f.more} more</li> : null}
        </ul>
      </details>
    </div>
  )
}

function WorkloadRow({
  w,
  namespace,
  findings,
  defaultOpen,
}: {
  w: NetworkPolicyWorkload
  namespace: string
  findings: NetworkPolicyFinding[]
  defaultOpen: boolean
}) {
  const iso = isolationOf(w)
  const warn = findings.some((f) => f.severity === 'warning')
  return (
    <li>
      <details className="netpol-wl" open={defaultOpen}>
        <summary className="netpol-wl-summary">
          <span className="netpol-wl-name">
            <span className="preview-kind">{w.kind}</span> {w.name}
          </span>
          <span className="netpol-wl-iso" data-iso={iso}>
            {ISOLATION_WORD[iso]}
          </span>
          <span className="netpol-wl-counts text-muted">
            {w.pods} {w.pods === 1 ? 'pod' : 'pods'} · {w.ingress.length}
            {w.ingressTruncated ? '+' : ''} in · {w.egress.length}
            {w.egressTruncated ? '+' : ''} out
          </span>
          {findings.length > 0 && (
            <VerdictBadge verdict={warn ? 'warning' : 'review'} reason={findings.map((f) => f.title).join('; ')} />
          )}
        </summary>
        {w.hostNetwork ? (
          <p className="netpol-wl-policies text-muted">
            These pods use the node’s network, so the network plugin does not apply NetworkPolicy to them.
          </p>
        ) : (
          <div className="netpol-flow">
            <PeerList dir="in" allows={w.ingress} truncated={!!w.ingressTruncated} namespace={namespace} />
            <div className="netpol-flow-center">
              <span aria-hidden="true">→</span>
              <span className="netpol-flow-self">{w.name}</span>
              <span aria-hidden="true">→</span>
            </div>
            <PeerList dir="out" allows={w.egress} truncated={!!w.egressTruncated} namespace={namespace} />
          </div>
        )}
        <p className="netpol-wl-policies text-muted">
          {w.policies.length === 0 ? 'No policy selects these pods.' : `Selected by ${w.policies.join(', ')}`}
        </p>
      </details>
    </li>
  )
}

const TONE_WORD: Record<string, string> = { blocked: 'refused', dead: 'matches nothing', open: 'open to all' }

function PeerList({
  dir,
  allows,
  truncated,
  namespace,
}: {
  dir: 'in' | 'out'
  allows: NetworkPolicyAllow[]
  truncated: boolean
  namespace: string
}) {
  const heading = dir === 'in' ? 'Can be reached from' : 'Can reach'
  return (
    <div className={`netpol-side netpol-side-${dir}`}>
      <div className="metric-tile-label">{heading}</div>
      <ul className="netpol-peers" aria-label={heading}>
        {allows.map((a, i) => {
          const tone = peerTone(a)
          const title = [a.peer.selector, a.policies?.length ? `Allowed by ${a.policies.join(', ')}` : ''].filter(Boolean).join(' · ')
          return (
            <li key={i} className="netpol-peer" data-tone={tone} title={title || undefined}>
              <span className="netpol-peer-name">{peerLabel(a.peer, dir, namespace)}</span>
              <span className="netpol-peer-ports">{a.ports.join(', ')}</span>
              {tone !== 'plain' && (
                <span className="netpol-peer-note">
                  {tone === 'blocked' ? `refused by ${(a.blockedBy ?? []).join(', ') || 'the other side'}` : TONE_WORD[tone]}
                </span>
              )}
            </li>
          )
        })}
      </ul>
      {truncated && <p className="text-muted netpol-truncated">First 40 shown.</p>}
    </div>
  )
}

function PolicyRail({
  rows,
  selected,
  loading,
  onSelect,
}: {
  rows: readonly NetworkPolicyIndexRow[]
  selected: string
  loading: boolean
  onSelect: (name: string) => void
}) {
  const [query, setQuery] = useState('')
  const [all, setAll] = useState(false)
  const maxWorkloads = Math.max(1, ...rows.map((r) => r.workloads))
  const needle = query.trim().toLowerCase()
  const matching = needle ? rows.filter((r) => r.name.toLowerCase().includes(needle)) : rows
  const shown = all || needle ? matching : matching.slice(0, RAIL_SHOWN)
  const withSelected = selected && !shown.some((r) => r.name === selected) ? [...shown, ...matching.filter((r) => r.name === selected)] : shown
  return (
    <aside className="card card-compact nsmap-rail" aria-label="Namespaces">
      <div className="card-head">
        <h3>Namespaces</h3>
        <span className="card-head-meta">workloads · warnings</span>
      </div>
      <label className="visually-hidden" htmlFor="netpol-ns-find">
        Find a namespace
      </label>
      <input id="netpol-ns-find" type="search" className="nsmap-search" placeholder="Find a namespace" value={query} onChange={(e) => setQuery(e.target.value)} />
      {loading && rows.length === 0 ? (
        <SkeletonLines count={6} />
      ) : (
        <ul className="nsmap-rail-list">
          {withSelected.map((r) => (
            <li key={r.name}>
              <button
                type="button"
                className="nsmap-rail-row"
                aria-pressed={r.name === selected}
                title={`${r.name}: ${r.workloads} workloads, ${r.policies} policies, ${r.open} accepting from anyone, ${r.warnings} warnings, ${r.reviews} to review`}
                onClick={() => onSelect(r.name)}
              >
                <span className="nsmap-rail-name">{r.name}</span>
                <span className="bar-list-track" aria-hidden="true">
                  <span className="split-seg" data-tone="neutral" style={{ width: `${(r.workloads * 100) / maxWorkloads}%` }} />
                </span>
                <span className={r.warnings ? 'nsmap-rail-inc nsmap-rail-inc-open' : 'nsmap-rail-inc'}>{r.warnings || '–'}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
      {!needle && matching.length > RAIL_SHOWN && (
        <button type="button" className="link-button nsmap-rail-more" onClick={() => setAll((v) => !v)}>
          {all ? `Show the first ${RAIL_SHOWN}` : `Show all ${matching.length}`}
        </button>
      )}
    </aside>
  )
}

// The policies against what the traffic source saw in the same namespace
// (policyVsTraffic.ts). Without a traffic source it says so in one line.
function PolicyVsTraffic({ map, clusterId }: { map: NetworkPolicyMap; clusterId: string }) {
  const namespace = map.namespace ?? ''
  const args = useMemo(() => ({ namespace, windowMinutes: 15 }), [namespace])
  const { query } = useInspect<TrafficResult>(clusterId, 'get_traffic', args, !!namespace)
  const r = query.data?.result
  if (query.isLoading) return <SkeletonLines count={2} />
  if (query.isError || !r) return null
  if (!r.available) {
    return (
      <p className="text-muted netpol-none">
        Not compared with traffic: {trafficUnavailableReason(r)}
      </p>
    )
  }
  const flows = r.flows ?? []
  const cmp = compareWithTraffic(map, flows, namespace)
  const m = measureOf(flows)
  return (
    <div className="card card-compact">
      <div className="card-head">
        <h3>Against observed traffic</h3>
        <HelpTip
          label="Against observed traffic"
          text="What the cluster's traffic source saw in this namespace over 15 minutes, checked against these policies. Seen but not allowed means the network plugin is not enforcing them, or ARGUS read them wrongly. Not seen in a short window is a hint for tightening, not proof a rule is unused. Traffic whose direction is unknown (DNS, mostly) is not judged."
        />
        <span className="card-head-meta">
          last 15 min · {cmp.checked} checked{cmp.undecided > 0 ? ` · ${cmp.undecided} could not be judged` : ''}
        </span>
      </div>
      <div className="incident-traffic">
        <div className="incident-traffic-list">
          <h4>
            Seen, but no rule allows it <span className="text-muted">({cmp.seenNotAllowed.length})</span>
          </h4>
          {cmp.seenNotAllowed.length === 0 ? (
            <p className="field-hint">{cmp.checked === 0 ? 'No observed traffic reached a workload whose policies restrict it.' : 'Every observed flow matched a rule.'}</p>
          ) : (
            <ul>
              {cmp.seenNotAllowed.slice(0, 10).map((x, i) => (
                <li key={i} className="fleet-row-problem">
                  <span className="fleet-mono">
                    {x.side === 'ingress' ? `${endpointLabel(x.peer)} → ${x.workload.name}` : `${x.workload.name} → ${endpointLabel(x.peer)}`}
                  </span>
                  <span className="tabular">{amount(x.flow, m) != null ? formatAmount(amount(x.flow, m) as number, m) : '—'} · not allowed</span>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="incident-traffic-list">
          <h4>
            Allowed, but not seen in 15 min <span className="text-muted">({cmp.allowedNotSeen.length})</span>
          </h4>
          {cmp.allowedNotSeen.length === 0 ? (
            <p className="field-hint">Every rule naming a workload or namespace carried traffic.</p>
          ) : (
            <ul>
              {groupUnseen(cmp.allowedNotSeen).slice(0, 8).map((g) => {
                const names = g.allows.map((a) => peerLabel(a.peer, g.side === 'ingress' ? 'in' : 'out', namespace))
                return (
                  <li key={`${g.workload.name}|${g.side}`}>
                    <span className="fleet-mono">
                      {g.workload.name} {g.side === 'ingress' ? '← from' : '→ to'} {names.slice(0, 2).join(', ')}
                      {names.length > 2 ? ` +${names.length - 2}` : ''}
                    </span>
                    <span className="text-muted tabular">
                      {g.allows.length} rule{g.allows.length === 1 ? '' : 's'}
                    </span>
                  </li>
                )
              })}
              {groupUnseen(cmp.allowedNotSeen).length > 8 && <li className="field-hint">and {groupUnseen(cmp.allowedNotSeen).length - 8} more workloads</li>}
            </ul>
          )}
        </div>
      </div>
    </div>
  )
}
