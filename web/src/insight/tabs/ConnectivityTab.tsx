import { useId, useState, type FormEvent } from 'react'
import { HelpTip } from '../../components/HelpTip'
import { reproducerFor } from '../../evidence/reproducer'
import { entryPointsFrom, NETPOL_EFFECT_WORD, NETPOL_VERDICT_WORD, type EntryPoint } from '../connectivityModel'
import { InsightFooter, QueryBody } from '../InsightParts'
import { PATH_KINDS } from '../kinds'
import { neighborhoodArgs } from '../summaryModel'
import type { NeighborhoodResult, NetpolResult, TraceResult } from '../types'
import { useInspect } from '../useInspect'
import { PathTraceView } from '../views/PathTraceView'
import type { TabProps } from './common'

// Connectivity (owner, 2026-10-11): "can traffic get to this?", answered two
// ways. The traffic path walks from an entry point (a Service, Ingress or
// route) to ready pods and names the first hop that breaks. The NetworkPolicy
// check predicts whether policy would admit a given source. Both are static
// reads of the agent's object cache — nothing here sends a packet — and each
// says so.

export function ConnectivityTab({ target, cluster }: TabProps) {
  const isEntry = PATH_KINDS.has(target.kind)
  // A Pod's Service hangs off its owning workload, so look two hops out.
  const nbArgs = { ...neighborhoodArgs(target), hops: 2 }
  const nb = useInspect<NeighborhoodResult>(target.clusterId, 'get_neighborhood', nbArgs, !isEntry)
  const self: EntryPoint = { kind: target.kind, namespace: target.namespace ?? '', name: target.name }
  const entries = isEntry ? [self] : entryPointsFrom(nb.data?.result)
  const [chosen, setChosen] = useState<string | null>(null)
  const entry = entries.find((e) => key(e) === chosen) ?? entries[0]

  return (
    <div className="insight-stack">
      <section className="connectivity-section" aria-label="Traffic path">
        <div className="card-head">
          <h3>Traffic path</h3>
          <HelpTip
            label="Traffic path"
            text="Walks from an entry point — a Service, Ingress or Gateway route — to the pods behind it and names the first hop that breaks: no selected pods, no ready endpoints, a target port no container declares, a missing backend. Read from the agent's cache; no traffic is sent."
          />
        </div>
        {isEntry ? (
          <TraceFrom entry={self} cluster={cluster} clusterId={target.clusterId} />
        ) : (
          <QueryBody query={nb} lines={3} errorFallback="The agent could not read what routes to this object.">
            {() =>
              entries.length === 0 ? (
                <p className="empty-state">
                  No Service, Ingress or route sends traffic to this {target.kind.toLowerCase()}, so nothing reaches it by name — only
                  directly by pod IP.
                </p>
              ) : (
                <>
                  {entries.length > 1 && (
                    <div className="connectivity-entries" role="group" aria-label="Trace from">
                      {entries.map((e) => (
                        <button
                          key={key(e)}
                          type="button"
                          className="secondary connectivity-entry"
                          aria-pressed={entry && key(e) === key(entry)}
                          onClick={() => setChosen(key(e))}
                        >
                          <span className="preview-kind">{e.kind}</span> {e.name}
                        </button>
                      ))}
                    </div>
                  )}
                  {entry && <TraceFrom entry={entry} cluster={cluster} clusterId={target.clusterId} />}
                </>
              )
            }
          </QueryBody>
        )}
      </section>

      <section className="connectivity-section" aria-label="NetworkPolicy check">
        <div className="card-head">
          <h3>Can traffic reach it?</h3>
          <HelpTip
            label="NetworkPolicy check"
            text="Predicts whether the cluster's NetworkPolicies would let a source reach this object, and which policies decide it. A static prediction from core NetworkPolicy objects: the network plugin enforces, and plugin-specific kinds (Cilium, Calico) are not evaluated, so Unknown never means open."
          />
        </div>
        <PolicyCheck target={target} cluster={cluster} services={entries.filter((e) => e.kind === 'Service')} />
      </section>
    </div>
  )
}

function key(e: EntryPoint) {
  return `${e.kind}/${e.namespace}/${e.name}`
}

interface ProbeStep {
  kind: string
  target: string
  ok: boolean
  detail: string
  millis: number
}
interface ProbeResult {
  vantage: string
  verdict: 'reachable' | 'partial' | 'unreachable'
  steps: ProbeStep[]
}

const PROBE_WORD: Record<ProbeResult['verdict'], { label: string; badge: string }> = {
  reachable: { label: 'Answered', badge: 'badge badge-green' },
  partial: { label: 'Partly answered', badge: 'badge badge-amber' },
  unreachable: { label: 'No answer', badge: 'badge badge-red' },
}
const STEP_WORD: Record<string, string> = { dns: 'DNS', 'tcp-service': 'Service IP', 'tcp-endpoint': 'Endpoint', http: 'HTTP' }

// PROJECT.md PG16: one round of real traffic along a Service's path, sent from
// the agent's own pod on request. Each step is drawn as a row with its word
// and time; the vantage sentence stays behind a HelpTip.
function ProbeView({ probe }: { probe: ProbeResult }) {
  const word = PROBE_WORD[probe.verdict]
  return (
    <section aria-label="Live probe">
      <p className="insight-lead">
        <span className={word.badge}>{word.label}</span> Live probe from the agent{' '}
        <HelpTip label="the probe's vantage point" text={probe.vantage} />
      </p>
      <table className="data-table">
        <tbody>
          {probe.steps.map((s, i) => (
            <tr key={i}>
              <td>{STEP_WORD[s.kind] ?? s.kind}</td>
              <td className="insight-mono">{s.target}</td>
              <td>
                <span className={s.ok ? 'badge badge-green' : 'badge badge-red'}>{s.ok ? 'OK' : 'Failed'}</span> {s.detail}
              </td>
              <td className="num">{s.millis} ms</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}

function TraceFrom({ entry, cluster, clusterId }: { entry: EntryPoint; cluster: TabProps['cluster']; clusterId: string }) {
  const [probe, setProbe] = useState(false)
  const args = { kind: entry.kind, namespace: entry.namespace, name: entry.name, ...(probe ? { probe: true } : {}) }
  const q = useInspect<TraceResult & { probe?: ProbeResult }>(clusterId, 'trace_service_path', args)
  return (
    <QueryBody query={q} lines={6} errorFallback="The agent could not trace this path.">
      {(res) => (
        <div className="insight-stack">
          <PathTraceView trace={res.result} clusterName={cluster.name} />
          {entry.kind === 'Service' &&
            (res.result.probe ? (
              <ProbeView probe={res.result.probe} />
            ) : (
              <p>
                <button type="button" className="secondary" disabled={probe && q.isFetching} onClick={() => setProbe(true)}>
                  {probe && q.isFetching ? 'Probing…' : 'Probe it now'}
                </button>{' '}
                <HelpTip
                  label="the live probe"
                  text="Resolves the Service name, connects to its cluster IP and up to five ready endpoints, and sends one HTTP GET where the port looks like HTTP — from the agent's own pod. Only status comes back, never a response body."
                />
              </p>
            ))}
          <InsightFooter at={res.result.observedAt ?? res.receivedAt} cluster={cluster} coverage={res.result.coverage} command={reproducerFor('trace_service_path', args)} />
        </div>
      )}
    </QueryBody>
  )
}

type Source = 'outside' | 'pod'

function PolicyCheck({ target, cluster, services }: { target: TabProps['target']; cluster: TabProps['cluster']; services: EntryPoint[] }) {
  const id = useId()
  const isPod = target.kind === 'Pod'
  // Destinations: the Services in front of this object, and a Pod as itself
  // (the agent needs a port for a Pod, since a Pod has no port list of its own).
  const destinations = [
    ...services.map((s) => ({ value: `Service/${s.name}`, kind: 'Service', name: s.name, namespace: s.namespace, label: `Service ${s.name}` })),
    ...(isPod ? [{ value: `Pod/${target.name}`, kind: 'Pod', name: target.name, namespace: target.namespace ?? '', label: `This pod` }] : []),
  ]
  const [source, setSource] = useState<Source>('outside')
  const [srcNamespace, setSrcNamespace] = useState(target.namespace ?? '')
  const [srcPod, setSrcPod] = useState('')
  const [dest, setDest] = useState('')
  const [port, setPort] = useState('')
  const [asked, setAsked] = useState<Record<string, unknown> | null>(null)

  const destination = destinations.find((d) => d.value === dest) ?? destinations[0]
  const portNumber = Number(port)
  const needsPort = destination?.kind === 'Pod'
  const invalid =
    !destination
      ? 'Nothing to check against: no Service routes to this object.'
      : source === 'pod' && (!srcNamespace.trim() || !srcPod.trim())
        ? 'Name the source pod and its namespace.'
        : needsPort && !(portNumber > 0)
          ? 'A pod has no port list of its own — give the port to check.'
          : port && !(portNumber > 0 && portNumber < 65536)
            ? 'Port must be a number from 1 to 65535.'
            : null

  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (invalid || !destination) return
    setAsked({
      source: source === 'outside' ? { external: true } : { namespace: srcNamespace.trim(), pod: srcPod.trim() },
      destination: { kind: destination.kind, namespace: destination.namespace, name: destination.name },
      ...(portNumber > 0 ? { port: portNumber } : {}),
    })
  }

  return (
    <div className="insight-stack">
      <form className="connectivity-form" onSubmit={submit}>
        <fieldset className="connectivity-source">
          <legend>From</legend>
          <label>
            <input type="radio" name={`${id}-src`} checked={source === 'outside'} onChange={() => setSource('outside')} /> Outside the cluster
          </label>
          <label>
            <input type="radio" name={`${id}-src`} checked={source === 'pod'} onChange={() => setSource('pod')} /> A pod
          </label>
          {source === 'pod' && (
            <div className="connectivity-pod-fields">
              <label>
                <span>Namespace</span>
                <input value={srcNamespace} onChange={(e) => setSrcNamespace(e.target.value)} />
              </label>
              <label>
                <span>Pod name</span>
                <input value={srcPod} onChange={(e) => setSrcPod(e.target.value)} placeholder="e.g. web-7d9c…" />
              </label>
            </div>
          )}
        </fieldset>
        <div className="connectivity-dest">
          <label>
            <span>To</span>
            <select value={destination?.value ?? ''} onChange={(e) => setDest(e.target.value)} disabled={destinations.length === 0}>
              {destinations.length === 0 && <option value="">No Service routes here</option>}
              {destinations.map((d) => (
                <option key={d.value} value={d.value}>
                  {d.label}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span>Port{needsPort ? '' : ' (optional)'}</span>
            <input inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value)} placeholder={needsPort ? 'required' : 'first port'} />
          </label>
          <button type="submit" disabled={Boolean(invalid)} title={invalid ?? undefined}>
            Check
          </button>
        </div>
        {invalid && destinations.length > 0 && <p className="field-hint">{invalid}</p>}
        {destinations.length === 0 && <p className="field-hint">{invalid}</p>}
      </form>
      {asked && <PolicyAnswer clusterId={target.clusterId} args={asked} cluster={cluster} />}
    </div>
  )
}

function PolicyAnswer({ clusterId, args, cluster }: { clusterId: string; args: Record<string, unknown>; cluster: TabProps['cluster'] }) {
  const q = useInspect<NetpolResult>(clusterId, 'evaluate_network_policy', args)
  return (
    <QueryBody query={q} lines={4} errorFallback="The agent could not evaluate NetworkPolicy for this traffic.">
      {(res) => {
        const r = res.result
        const v = r.verdict?.verdict ?? 'unknown'
        const deciding = r.verdict?.decidingPolicies ?? []
        const applying = (r.explanations ?? []).filter((x) => x.explanation.effect !== 'notApplicable')
        return (
          <div className="insight-stack">
            <p className="connectivity-verdict">
              <span className={`badge ${v === 'allowed' ? 'badge-green' : v === 'denied' ? 'badge-red' : 'badge-gray'}`}>{NETPOL_VERDICT_WORD[v]}</span>{' '}
              {v === 'denied'
                ? `Blocked by ${r.verdict?.direction === 'egress' ? 'the source’s egress' : r.verdict?.direction === 'ingress+egress' ? 'egress and ingress' : 'ingress'} policy.`
                : v === 'allowed'
                  ? 'Policy admits this traffic.'
                  : 'The static model cannot decide — this is not the same as open.'}
              {r.backends !== undefined && (
                <span className="text-muted">
                  {' '}
                  · {r.backends} backend pod{r.backends === 1 ? '' : 's'} evaluated
                </span>
              )}
            </p>
            {deciding.length > 0 && (
              <p>
                Deciding {deciding.length === 1 ? 'policy' : 'policies'}: <span className="insight-mono">{deciding.join(', ')}</span>
              </p>
            )}
            {applying.length > 0 ? (
              <div className="table-scroll">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th scope="col">Policy</th>
                      <th scope="col">Direction</th>
                      <th scope="col">Effect</th>
                      <th scope="col">Why</th>
                    </tr>
                  </thead>
                  <tbody>
                    {applying.map((x, i) => (
                      <tr key={`${x.policy}-${x.direction}-${i}`}>
                        <td className="insight-mono">{x.policy}</td>
                        <td>{x.direction}</td>
                        <td>{NETPOL_EFFECT_WORD[x.explanation.effect] ?? x.explanation.effect}</td>
                        <td>{x.explanation.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : v === 'allowed' ? (
              <p className="text-muted">No NetworkPolicy selects the pods involved, so none restricts this traffic.</p>
            ) : null}
            {r.note && <p className="field-hint">{r.note}</p>}
            <InsightFooter at={r.observedAt ?? res.receivedAt} cluster={cluster} coverage={r.coverage} truncated={r.truncated} command={reproducerFor('evaluate_network_policy', args)} />
          </div>
        )
      }}
    </QueryBody>
  )
}
