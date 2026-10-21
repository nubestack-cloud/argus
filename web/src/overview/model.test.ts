import { describe, expect, it } from 'vitest'
import type { ApprovalQueueItem, AutomationWindow, Cluster, ClusterDetail, Incident, IncidentState, UpgradeScan } from '../api/types'
import {
  certificatePins,
  deliveryMarks,
  fleetCapacity,
  formatWait,
  groupPins,
  hexGrid,
  minorVersion,
  postureByCategory,
  queueRows,
  severityTotals,
  STAGES,
  stageOf,
  stageParts,
  upgradeLadder,
  windowChange,
  windowSpans,
} from './model'

const NOW = Date.parse('2026-10-12T12:00:00Z')

const ALL_OPEN_STATES: IncidentState[] = [
  'Detected', 'Investigating', 'RecommendationReady', 'NeedsHumanInvestigation', 'AwaitingApproval', 'Executing',
  'AwaitingMerge', 'Validating', 'Failed', 'Reopened', 'Diagnosed', 'ExecutionUnknown', 'ValidationUnknown', 'PlanRejected',
]
// internal/orchestrator's requiresActionStates. The stages marked `yours` must
// cover exactly these, or the tile's stage bar and its "waiting on you" figure
// would count different things.
const REQUIRES_ACTION: IncidentState[] = [
  'Detected', 'RecommendationReady', 'NeedsHumanInvestigation', 'AwaitingApproval', 'PlanRejected', 'Diagnosed',
  'Failed', 'ExecutionUnknown', 'ValidationUnknown', 'Reopened',
]

describe('lifecycle stages', () => {
  it('places every open state in exactly one stage', () => {
    for (const s of ALL_OPEN_STATES) {
      expect(STAGES.filter((st) => st.states.includes(s))).toHaveLength(1)
    }
  })

  it('marks as "yours" exactly the states the hub counts as requiring action', () => {
    const yours = STAGES.filter((s) => s.yours).flatMap((s) => s.states)
    expect([...yours].sort()).toEqual([...REQUIRES_ACTION].sort())
  })

  it('sums states into stages, keeps zero stages, and files an unknown state under "your move"', () => {
    const parts = stageParts([
      { state: 'Detected', count: 3 },
      { state: 'Diagnosed', count: 2 },
      { state: 'RecommendationReady', count: 1 },
      { state: 'SomethingNew', count: 4 },
    ])
    expect(parts).toHaveLength(STAGES.length)
    expect(parts.find((p) => p.label === 'not investigated')?.value).toBe(3)
    expect(parts.find((p) => p.label === 'your move')?.value).toBe(7)
    expect(parts.find((p) => p.label === 'watching')?.value).toBe(0)
    expect(stageOf('SomethingNew')).toBe('yourMove')
  })
})

describe('severity totals and the open series', () => {
  it('sums each severity across clusters', () => {
    const t = severityTotals([
      { clusterId: 'a', critical: 1, high: 2, medium: 0, low: 1, open: 4, requiresAction: 2, fixNotHeld: 0 },
      { clusterId: 'b', critical: 0, high: 1, medium: 3, low: 0, open: 4, requiresAction: 1, fixNotHeld: 1 },
    ])
    expect(t).toEqual({ critical: 1, high: 3, medium: 3, low: 1 })
  })

  it('reports the change across the window, and nothing below two points', () => {
    const day = (openAtEnd: number) => ({ date: '2026-10-01', opened: { critical: 0, high: 0, medium: 0, low: 0 }, resolved: 0, openAtEnd })
    expect(windowChange([day(22), day(25), day(28)])).toBe(6)
    expect(windowChange([day(5)])).toBeNull()
  })
})

function incident(over: Partial<Incident>): Incident {
  return {
    id: 'inc_1', clusterId: 'cl_a', clusterDisplayName: 'prod-eu-1', fingerprint: 'fp', severity: 'high',
    state: 'Diagnosed', firstSeen: '2026-10-12T09:00:00Z', lastSeen: '2026-10-12T11:00:00Z', occurrenceCount: 1,
    ...over,
  } as Incident
}

describe('queueRows', () => {
  it('measures a decision from its plan time, everything else from when it opened, and orders by severity then wait', () => {
    const approvals = [{ incidentId: 'inc_dec', alreadyApproved: false, plan: { createdAt: '2026-10-10T08:00:00Z' } }] as unknown as ApprovalQueueItem[]
    const rows = queueRows(
      [
        incident({ id: 'inc_low', severity: 'low', firstSeen: '2026-10-01T12:00:00Z' }),
        incident({ id: 'inc_dec', severity: 'high', state: 'AwaitingApproval', firstSeen: '2026-10-01T12:00:00Z', objectName: 'kafka', objectGvk: 'apps/v1/StatefulSet' }),
        incident({ id: 'inc_crit', severity: 'critical', firstSeen: '2026-10-12T09:00:00Z' }),
      ],
      approvals,
      [{ id: 'cl_s', displayName: 'edge-01', lastHeartbeatAt: '2026-10-12T09:00:00Z' } as Cluster],
      NOW,
    )
    expect(rows.map((r) => r.key)).toEqual(['inc_crit', 'cluster:cl_s', 'inc_dec', 'inc_low'])
    const dec = rows.find((r) => r.key === 'inc_dec')!
    expect(dec.kind).toBe('decision')
    expect(dec.sinceMeaning).toBe('plan')
    expect(dec.hours).toBe(52)
    expect(dec.context).toContain('StatefulSet')
    expect(rows.find((r) => r.key === 'cluster:cl_s')?.severity).toBeNull()
  })

  it('leaves the wait unknown, not zero, for a decision whose plan time is missing', () => {
    const rows = queueRows([incident({ id: 'x', state: 'AwaitingApproval' })], [], [], NOW)
    expect(rows[0].hours).toBeNull()
  })

  it('formats waits the way the tiles print them', () => {
    expect(formatWait(null)).toBe('—')
    expect(formatWait(0.5)).toBe('30 m')
    expect(formatWait(6.2)).toBe('6 h')
    expect(formatWait(52)).toBe('2 d 4 h')
    expect(formatWait(48)).toBe('2 d')
  })
})

function detail(over: Partial<ClusterDetail>): ClusterDetail {
  return { id: 'cl_a', displayName: 'a', state: 'Active', facts: null, ...over } as ClusterDetail
}

describe('fleetCapacity', () => {
  it('sums only the nodes that reported usage and says how many clusters were measured', () => {
    const measured = detail({
      id: 'cl_m', displayName: 'measured',
      facts: { nodeCount: 2, reachable: true, nodes: [
        { name: 'n1', ready: true, cpuAllocatable: '4', memoryAllocatable: '8Gi', cpuUsed: '2', memoryUsed: '6Gi' },
        { name: 'n2', ready: true, cpuAllocatable: '4', memoryAllocatable: '8Gi', cpuUsed: '1', memoryUsed: '2Gi' },
      ] } as ClusterDetail['facts'],
    })
    const unmeasured = detail({
      id: 'cl_u', displayName: 'no-metrics-server',
      facts: { nodeCount: 1, reachable: true, nodes: [{ name: 'u1', ready: true, cpuAllocatable: '8', memoryAllocatable: '16Gi' }] } as ClusterDetail['facts'],
    })
    const cap = fleetCapacity([measured, unmeasured, detail({ id: 'cl_none' })])
    expect(cap.cpu.ratio).toBeCloseTo(3 / 8)
    expect(cap.memory.ratio).toBeCloseTo(0.5)
    expect(cap.cpu.reportingNodes).toBe(2)
    expect(cap.cpu.totalNodes).toBe(3)
    expect(cap.measuredClusters).toBe(1)
    expect(cap.clustersWithFacts).toBe(2)
    expect(cap.hottest?.name).toBe('measured')
  })

  it('returns no ratio at all when nothing reported usage', () => {
    expect(fleetCapacity([]).cpu.ratio).toBeNull()
  })
})

describe('upgradeLadder', () => {
  it('reads minor versions, prefers the facts over the scan for today, and sorts columns numerically', () => {
    expect(minorVersion('v1.29.8+rke2r1')).toBe('1.29')
    expect(minorVersion('nonsense')).toBeNull()
    const clusters = [{ id: 'a', displayName: 'a' }, { id: 'b', displayName: 'b' }, { id: 'c', displayName: 'c' }] as Cluster[]
    const details = new Map([['a', detail({ id: 'a', facts: { kubernetesVersion: 'v1.9.2', nodeCount: 0, reachable: true, nodes: [] } as ClusterDetail['facts'] })]])
    const scans = new Map([
      ['a', { clusterId: 'a', currentVersion: '1.9', targetVersion: '1.10', verdict: 'blocked', scannedAt: 'x' } as UpgradeScan],
      ['b', { clusterId: 'b', currentVersion: 'v1.10.1', targetVersion: 'v1.11.0', verdict: 'passed', scannedAt: 'y' } as UpgradeScan],
    ])
    const { columns, rows } = upgradeLadder(clusters, details, scans)
    expect(columns).toEqual(['1.9', '1.10', '1.11'])
    expect(rows.find((r) => r.clusterId === 'a')).toMatchObject({ current: '1.9', target: '1.10', verdict: 'blocked' })
    expect(rows.find((r) => r.clusterId === 'c')).toMatchObject({ current: null, target: null, verdict: null })
  })
})

describe('coming due', () => {
  it('pins certificates inside 90 days by urgency and counts what it could not draw', () => {
    const r = certificatePins({
      certificates: [
        { name: 'late', namespace: 'n', issuer: '', domains: '', health: '', source: '', daysLeft: 61 },
        { name: 'soon', namespace: 'n', issuer: '', domains: '', health: '', source: '', daysLeft: 6 },
        { name: 'mid', namespace: 'n', issuer: '', domains: '', health: '', source: '', daysLeft: 19 },
        { name: 'far', namespace: 'n', issuer: '', domains: '', health: '', source: '', daysLeft: 200 },
        { name: 'unknown', namespace: 'n', issuer: '', domains: '', health: '', source: '' },
      ],
    })
    expect(r.pins.map((p) => [p.name, p.severity])).toEqual([['soon', 'critical'], ['mid', 'high'], ['late', 'low']])
    expect(r.unknown).toBe(1)
    expect(r.later).toBe(1)
  })

  it('places window openings on the runway, clamped to it, and drops ones outside it', () => {
    const w = {
      id: 'w', kind: 'freeze', reason: 'release',
      upcoming: [
        { start: '2026-10-11T12:00:00Z', end: '2026-10-13T12:00:00Z' },
        { start: '2026-11-11T12:00:00Z', end: '2026-11-12T12:00:00Z' },
        { start: '2027-03-01T00:00:00Z', end: '2027-03-02T00:00:00Z' },
      ],
    } as unknown as AutomationWindow
    const spans = windowSpans([w], NOW)
    expect(spans).toHaveLength(2)
    expect(spans[0].start).toBe(0)
    expect(spans[0].width).toBeCloseTo(1 / 90)
    expect(spans[1].start).toBeCloseTo(30 / 90)
  })
})

describe('posture and delivery', () => {
  it('returns null rather than zeros when the agent sent no per-category summary', () => {
    expect(postureByCategory({ summary: { danger: 3 } })).toBeNull()
    expect(postureByCategory({ summary: { categories: { Security: { danger: 2, warning: 1, passing: 9 } } } })?.Reliability).toEqual({ danger: 0, warning: 0, passing: 0 })
  })

  it('marks each listed release and app, and says when the app list is shorter than the total', () => {
    const marks = deliveryMarks(
      { total: 2, releases: [{ status: 'deployed' }, { status: 'failed' }] } as never,
      { counts: { total: 5 }, apps: [{ problem: true }, { problem: false }] } as never,
    )
    expect(marks.helm).toEqual([false, true])
    expect(marks.gitops).toEqual([true, false])
    expect(marks.gitopsTruncated).toBe(true)
    expect(deliveryMarks(undefined, undefined).helm).toBeNull()
  })
})

describe('hexGrid', () => {
  it('offsets alternate rows and sizes the box to fit them', () => {
    const g = hexGrid(5, 3, 10)
    expect(g.cells).toHaveLength(5)
    expect(g.cells[3].cx).toBeGreaterThan(g.cells[0].cx)
    expect(g.height).toBeCloseTo(2 * 15 + 5)
  })
})

describe('groupPins', () => {
  it('merges certificates expiring within two days of each other and keeps the worst severity', () => {
    const p = (name: string, days: number, severity: 'critical' | 'high' | 'low') => ({ name, namespace: 'n', days, severity })
    const groups = groupPins([p('a', 84, 'low'), p('b', 6, 'critical'), p('c', 84, 'low'), p('d', 7, 'high'), p('e', 40, 'low')])
    expect(groups.map((g) => [g.days, g.severity, g.pins.length])).toEqual([[6, 'critical', 2], [40, 'low', 1], [84, 'low', 2]])
  })
})
