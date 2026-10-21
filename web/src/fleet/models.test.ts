import { describe, expect, it } from 'vitest'
import type { FindingListItem } from '../api/client'
import {
  countAbsence,
  isValidTarget,
  nextMinor,
  notReadyWorkloads,
  readInsightFacts,
  unsyncedKinds,
} from './clusterSummary'
import { findingCounts, groupChecks, isNextMinorScan, scanErrorMessage, type UpgradeCheck } from './upgradeModel'
import { filterByFramework, frameworksOf, groupPosture, type PostureResult } from './postureModel'
import { buildTrafficGraph, edgeLabel, errorPercent, sortFlows, type TrafficFlow } from './trafficModel'
import { costUnavailableReason, formatCost } from './costModel'
import { trafficUnavailableReason } from './trafficModel'
import { sortCertificates, type CertificateRow } from './certificatesModel'
import { collapseSignals, humanizeReason, pageIsWholeSet, readableSignalReason } from './signalsGrouping'
import { coverageSentences, groupHitsByCluster, type SearchHit } from './searchModel'
import { newIds } from './useNewArrivals'
import { stepIndex } from './useRowNavigation'
import { pageWindow } from './useUrlPagination'

describe('cluster summary facts', () => {
  it('reads summary and objectCache defensively', () => {
    expect(readInsightFacts(null)).toEqual({ summary: null, objectCache: null })
    expect(readInsightFacts({ nodeCount: 3 })).toEqual({ summary: null, objectCache: null })
    const r = readInsightFacts({ summary: { computedAt: 'x' }, objectCache: { syncedAt: 's', kinds: [] } })
    expect(r.summary?.computedAt).toBe('x')
    expect(r.objectCache?.kinds).toEqual([])
  })

  it('tells an unavailable count from an unreported one, and never returns zero for either', () => {
    const counts = { services: 4, unavailable: ['ingresses'] }
    expect(countAbsence(counts, 'services')).toBeNull()
    expect(countAbsence(counts, 'ingresses')).toBe('unavailable')
    expect(countAbsence(counts, 'pods')).toBe('unknown')
    expect(countAbsence(undefined, 'nodes')).toBe('unknown')
  })

  it('sums not-ready workloads over listed kinds; partial is a lower bound, none is unknown', () => {
    const r = { total: 3, ready: 2, notReady: 1, scaledToZero: 0 }
    expect(notReadyWorkloads({ deployments: r, statefulSets: r, daemonSets: r })).toMatchObject({ value: 3, certainty: 'exact', total: 9 })
    expect(notReadyWorkloads({ deployments: r, unavailable: ['statefulsets', 'daemonsets'] })).toMatchObject({
      value: 1,
      certainty: 'atLeast',
      missing: ['StatefulSets', 'DaemonSets'],
    })
    expect(notReadyWorkloads({ unavailable: ['deployments', 'statefulsets', 'daemonsets'] })).toMatchObject({ value: null, certainty: 'unknown' })
  })

  it('lists unsynced kinds problems first, absent CRDs last', () => {
    const kinds = unsyncedKinds({
      kinds: [
        { kind: 'Application', group: 'argoproj.io', state: 'absent' },
        { kind: 'Pod', state: 'synced' },
        { kind: 'Ingress', group: 'networking.k8s.io', state: 'forbidden' },
        { kind: 'Job', group: 'batch', state: 'syncing' },
      ],
    })
    expect(kinds.map((k) => k.kind)).toEqual(['Ingress', 'Job', 'Application'])
  })

  it('derives the next minor and validates targets the way the hub does', () => {
    expect(nextMinor('1.31.4+rke2r1')).toBe('1.32')
    expect(nextMinor('v1.29')).toBe('1.30')
    expect(nextMinor(undefined)).toBeNull()
    expect(isValidTarget('1.33')).toBe(true)
    expect(isValidTarget('1.33.1')).toBe(false)
    expect(isValidTarget('2.0')).toBe(false)
  })
})

describe('upgrade readiness model', () => {
  const check = (id: string, status: string, extra: Partial<UpgradeCheck> = {}): UpgradeCheck => ({
    id,
    category: 'API',
    title: id,
    status,
    summary: '',
    findings: [],
    ...extra,
  })

  it('groups Blocked → Warning → Review → Incomplete → Passed → Not applicable; unknown is Incomplete', () => {
    const groups = groupChecks([
      check('a', 'passed'),
      check('b', 'unknown'),
      check('c', 'not_applicable'),
      check('d', 'blocked'),
      check('e', 'review'),
      check('f', 'warning'),
      check('g', 'something-new'),
    ])
    expect(groups.map((g) => g.verdict)).toEqual(['blocked', 'warning', 'review', 'incomplete', 'passed', 'notApplicable'])
    expect(groups.find((g) => g.verdict === 'incomplete')?.checks.map((c) => c.id)).toEqual(['b', 'g'])
  })

  it('counts findings against the pre-cap total', () => {
    const f = { ruleID: 'r', title: 't', level: 'blocker', impact: '', remediation: '' }
    expect(findingCounts(check('a', 'blocked', { findings: [f, f], findingsTotal: 75, truncated: true }))).toEqual({ shown: 2, total: 75 })
    expect(findingCounts(check('a', 'blocked', { findings: null }))).toEqual({ shown: 0, total: 0 })
  })

  it('explains each scan-run failure', () => {
    expect(scanErrorMessage(429)).toMatch(/less than a minute ago/)
    expect(scanErrorMessage(503)).toMatch(/not connected/)
    expect(scanErrorMessage(502)).toMatch(/could not complete/)
    expect(scanErrorMessage(500, 'boom')).toBe('The scan could not run: boom')
  })

  it('shows the hub\'s range for a rejected target and the agent\'s reason for a failed scan', () => {
    const range = "ARGUS's upgrade checks are reviewed through Kubernetes 1.37, so a scan for 1.99 would have nothing reviewed to check; choose 1.34 to 1.37."
    expect(scanErrorMessage(400, range)).toBe(range)
    expect(scanErrorMessage(400)).toMatch(/form "1.N"/)
    expect(scanErrorMessage(502, 'The agent reported: invalid target.')).toBe('The agent could not complete the scan. The agent reported: invalid target.')
  })

  it('tells a next-minor scan from a one-off', () => {
    expect(isNextMinorScan({ currentVersion: '1.33', targetVersion: '1.34' })).toBe(true)
    expect(isNextMinorScan({ currentVersion: '1.33', targetVersion: '1.99' })).toBe(false)
    expect(isNextMinorScan({ currentVersion: '1.33', targetVersion: '1.35' })).toBe(false)
    expect(isNextMinorScan({ currentVersion: '', targetVersion: '1.34' })).toBeNull()
  })
})

describe('posture model', () => {
  const result: PostureResult = {
    checks: {
      privileged: { id: 'privileged', title: 'Privileged container', category: 'Security', description: '', remediation: 'Drop it', frameworks: ['CIS', 'NSA'] },
      limits: { id: 'limits', title: 'Missing limits', category: 'Efficiency', description: '', remediation: '', frameworks: ['CIS'] },
    },
    findings: [
      { kind: 'Deployment', namespace: 'a', name: 'x', checkID: 'limits', category: 'Efficiency', severity: 'warning', message: '' },
      { kind: 'Deployment', namespace: 'a', name: 'y', checkID: 'limits', category: 'Efficiency', severity: 'warning', message: '' },
      { kind: 'Pod', namespace: 'b', name: 'z', checkID: 'privileged', category: 'Security', severity: 'danger', message: '' },
      { kind: 'Pod', namespace: 'b', name: 'q', checkID: 'unknownCheck', category: 'Security', severity: 'warning', message: '' },
    ],
  }

  it('groups one row per check, danger first, and keeps checks missing from the catalogue', () => {
    const groups = groupPosture(result)
    expect(groups.map((g) => [g.checkId, g.findings.length])).toEqual([
      ['privileged', 1],
      ['limits', 2],
      ['unknownCheck', 1],
    ])
    expect(groups[2].title).toBe('unknownCheck')
  })

  it('filters by framework from the catalogue', () => {
    expect(frameworksOf(result)).toEqual(['CIS', 'NSA'])
    expect(filterByFramework(groupPosture(result), 'NSA').map((g) => g.checkId)).toEqual(['privileged'])
    expect(filterByFramework(groupPosture(result), '')).toHaveLength(3)
  })
})

describe('traffic model', () => {
  const ep = (name: string, kind = 'Workload') => ({ namespace: 'shop', name, kind })
  const flows: TrafficFlow[] = [
    { src: ep('web'), dst: ep('api'), port: 8080, protocol: 'http', requestRate: 12.34, errorRate: 0.26 },
    { src: ep('api'), dst: ep('db'), port: 5432, protocol: 'tcp', bytesRate: 2048 },
    { src: ep('web'), dst: ep('cache'), port: 6379, protocol: 'http', requestRate: 5, errorRate: null },
  ]

  it('derives 5xx share from rates and never invents one', () => {
    expect(errorPercent(flows[0])).toBeCloseTo(2.107, 2)
    expect(errorPercent(flows[1])).toBeNull()
    expect(errorPercent(flows[2])).toBeNull()
    expect(errorPercent({ ...flows[0], requestRate: 0, errorRate: 0 })).toBe(0)
  })

  it('labels edges in text', () => {
    expect(edgeLabel(flows[0])).toBe('12.3 req/s · 2.1% 5xx')
    expect(edgeLabel(flows[1])).toBe('2 KiB/s')
    expect(edgeLabel(flows[2])).toBe('5 req/s · 5xx not measured')
  })

  it('builds nodes from endpoints and marks only measured-error edges as problems', () => {
    const g = buildTrafficGraph(flows)
    expect(g.nodes.map((n) => n.name).sort()).toEqual(['api', 'cache', 'db', 'web'])
    expect(g.nodes.every((n) => n.status === 'neutral')).toBe(true)
    expect(g.edges).toHaveLength(3)
    expect([...g.problemEdges]).toHaveLength(1)
  })

  it('sorts unmeasured values last in both directions', () => {
    expect(sortFlows(flows, 'requests', 'desc').map((f) => f.dst.name)).toEqual(['api', 'cache', 'db'])
    expect(sortFlows(flows, 'requests', 'asc').map((f) => f.dst.name)).toEqual(['cache', 'api', 'db'])
  })
})

describe('cost and certificates', () => {
  it('states why cost is unavailable, with the agent detail', () => {
    expect(costUnavailableReason({ available: false, reason: 'no_metrics' })).toMatch(/OpenCost is not installed/)
    expect(costUnavailableReason({ available: false, reason: 'query_error', detail: 'timeout' })).toBe('Prometheus rejected the OpenCost queries, so cost could not be read.')
    // Owner QA 2026-10-11: one sentence per real case, no config key, and a
    // Prometheus the agent found in the cluster is named.
    const notConfigured = costUnavailableReason(
      { available: false, reason: 'not_configured', detail: 'no Prometheus is configured for this agent (metrics.prometheusService)' },
      { namespace: 'cattle-monitoring-system', name: 'rancher-monitoring-prometheus', port: 9090 },
    )
    expect(notConfigured).toContain('No Prometheus is connected to this cluster’s agent')
    expect(notConfigured).toContain('A Prometheus was found at cattle-monitoring-system/rancher-monitoring-prometheus:9090')
    expect(notConfigured).not.toMatch(/prometheusService|holds no OpenCost/)
    expect(costUnavailableReason({ available: false, reason: 'unreachable' })).toMatch(/did not answer/)
    // The pre-fix agent's contradictory pair reads as what it meant.
    expect(costUnavailableReason({ available: false, reason: 'no_metrics', detail: 'no Prometheus is configured for this agent (metrics.prometheusService)' })).toMatch(
      /^No Prometheus is connected/,
    )
    expect(trafficUnavailableReason({ available: false, reasonCode: 'not_configured', reason: 'x' })).toMatch(/No Prometheus Service was found in the cluster either/)
    expect(trafficUnavailableReason({ available: false, reasonCode: 'no_source', reason: 'Prometheus has no Istio, Beyla or OBI metrics.' })).toBe('Prometheus has no Istio, Beyla or OBI metrics.')
    expect(costUnavailableReason(null)).toMatch(/did not report why/)
  })

  it('formats small figures with enough precision, no currency symbol', () => {
    expect(formatCost(0.0123)).toBe('0.0123')
    expect(formatCost(12.5)).toBe('12.50')
    expect(formatCost(0)).toBe('0.00')
  })

  it('sorts certificates soonest first with unknown expiry last', () => {
    const c = (name: string, daysLeft?: number): CertificateRow => ({ name, namespace: 'n', issuer: '', domains: '', health: 'healthy', source: 'cert-manager', daysLeft })
    expect(sortCertificates([c('a'), c('b', 40), c('c', -2), c('d', 5)]).map((x) => x.name)).toEqual(['c', 'd', 'b', 'a'])
  })
})

describe('signals grouping', () => {
  const f = (id: string, over: Partial<FindingListItem> = {}) =>
    ({ id, detectorId: 'k8s-events', reason: 'BackOff', message: '', ...over }) as FindingListItem

  it('collapses look-alike rows where the first member appeared and leaves singles alone', () => {
    const rows = collapseSignals([f('1'), f('2', { reason: 'OOMKilled' }), f('3'), f('4', { ruleId: 'r1' })])
    expect(rows.map((r) => (r.kind === 'group' ? `g:${r.findings.map((x) => x.id).join('+')}` : r.finding.id))).toEqual(['g:1+3', '2', '4'])
  })

  it('reads posture, certificate and helm reasons as words', () => {
    expect(readableSignalReason({ detectorId: 'k8s-posture', reason: 'PosturePrivileged', message: 'Privileged container (Security): x' })).toBe(
      'Privileged container',
    )
    expect(readableSignalReason({ detectorId: 'k8s-posture', reason: 'PostureHostPath', message: 'odd' })).toBe('Host path')
    expect(readableSignalReason({ detectorId: 'k8s-helm', reason: 'HelmReleaseFailed', message: '' })).toBe('Helm release failed')
    expect(readableSignalReason({ detectorId: 'k8s-events', reason: 'CrashLoopBackOff', message: '' })).toBe('CrashLoopBackOff')
    expect(humanizeReason('CertificateExpiring')).toBe('Certificate expiring')
  })

  it('treats a group count as exact only on a complete first page', () => {
    expect(pageIsWholeSet(0, undefined)).toBe(true)
    expect(pageIsWholeSet(0, 'c1')).toBe(false)
    expect(pageIsWholeSet(1, undefined)).toBe(false)
  })
})

describe('object search model', () => {
  const hit = (clusterId: string, name: string, score: number): SearchHit => ({ clusterId, clusterName: clusterId.toUpperCase(), name, score, kind: 'Deployment' })

  it('groups by cluster, best-scoring cluster first', () => {
    const g = groupHitsByCluster([hit('a', 'x', 40), hit('b', 'y', 100), hit('a', 'z', 60)])
    expect(g.map((c) => [c.clusterId, c.hits.map((h) => h.name)])).toEqual([
      ['b', ['y']],
      ['a', ['x', 'z']],
    ])
  })

  it('names the clusters that did not answer, and nothing when all did', () => {
    expect(coverageSentences({ clustersFailed: [], clustersDisconnected: [] })).toEqual([])
    const s = coverageSentences({ clustersFailed: [{ id: '1', name: 'prod' }, { id: '2', name: 'dev' }], clustersDisconnected: [{ id: '3', name: 'edge' }] })
    expect(s[0]).toBe('2 clusters did not answer in time (prod, dev) — results may be incomplete.')
    expect(s[1]).toBe('1 cluster is disconnected and could not be searched (edge).')
  })
})

describe('list helpers', () => {
  it('finds rows new to the known set', () => {
    expect(newIds(['a', 'b', 'c'], new Set(['b']))).toEqual(['a', 'c'])
  })

  it('steps the active row, clamped, starting at the first', () => {
    expect(stepIndex(-1, 1, 5)).toBe(0)
    expect(stepIndex(-1, -1, 5)).toBe(0)
    expect(stepIndex(4, 1, 5)).toBe(4)
    expect(stepIndex(0, -1, 5)).toBe(0)
    expect(stepIndex(2, 1, 0)).toBe(-1)
  })

  it('clamps a URL page past the end', () => {
    expect(pageWindow(30, 5, 25)).toEqual({ totalPages: 2, currentPage: 2, firstResult: 26, lastResult: 30 })
    expect(pageWindow(0, 3, 25)).toEqual({ totalPages: 1, currentPage: 1, firstResult: 0, lastResult: 0 })
  })
})
