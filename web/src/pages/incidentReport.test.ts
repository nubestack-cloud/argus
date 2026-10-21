import { describe, expect, it } from 'vitest'
import { buildIncidentReportMarkdown, buildIncidentSummaryMarkdown, reportFileName } from './incidentReport'
import { resolvedIdentity } from './incidentLifecycle'
import type { Analysis, Finding, IncidentDetail, RemediationPlan } from '../api/types'

// PROJECT.md T17's acceptance line: "automated tests cover redaction and
// complete/partial/no-analysis incidents." These fixtures are deliberately
// minimal-but-complete IncidentDetail objects (every field the report reads
// gets a real value, not `as unknown as` past a missing one) so a test
// failure here means the GENERATOR disagrees with the page's own vocabulary,
// not that the fixture forgot a field.

function baseIncident(overrides: Partial<IncidentDetail> = {}): IncidentDetail {
  return {
    id: 'inc_01test000000000000000000',
    clusterId: 'cl_test',
    clusterDisplayName: 'test-cluster',
    fingerprint: 'abcdef0123456789abcdef0123456789',
    severity: 'high',
    state: 'Detected',
    firstSeen: '2026-09-01T00:00:00Z',
    lastSeen: '2026-09-01T01:00:00Z',
    occurrenceCount: 1,
    analysis: null,
    findings: [],
    findingGroups: [],
    ownership: null,
    evidence: null,
    recentChanges: null,
    unattendedBatch: null,
    pullRequest: null,
    reopenedBy: null,
    route: null,
    routeReason: null,
    automationGate: null,
    ...overrides,
  } as IncidentDetail
}

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'find_1',
    detectorId: 'det_1',
    gvk: 'v1/Pod',
    namespace: 'payments',
    objectName: 'checkout-worker-abc123',
    reason: 'CrashLoopBackOff',
    message: 'Back-off restarting failed container',
    severity: 'high',
    occurrenceCount: 3,
    occurredAt: '2026-09-01T00:00:00Z',
    ...overrides,
  }
}

function completeAnalysis(overrides: Partial<Analysis> = {}): Analysis {
  return {
    id: 'an_1',
    status: 'complete',
    model: 'test-model',
    causalChain: [],
    causalChainProvenance: 'hub-observed',
    ruledOut: [],
    iterations: 3,
    createdAt: '2026-09-01T00:05:00Z',
    tokensBilledIn: 100,
    tokensCacheRead: 0,
    tokensOut: 50,
    costUsd: 0,
    costBasis: 'unknown',
    triggeredBy: 'manual',
    incidentState: '',
    stateReason: '',
    plan: null,
    rootCause: { statement: 'The container repeatedly OOMKilled under load.' },
    confidence: 0.9,
    partialReason: null,
    suggestedNextSteps: null,
    ...overrides,
  } as Analysis
}

function partialAnalysis(overrides: Partial<Analysis> = {}): Analysis {
  return {
    id: 'an_2',
    status: 'partial',
    model: 'test-model',
    causalChain: [],
    causalChainProvenance: 'hub-observed',
    ruledOut: [],
    iterations: 8,
    createdAt: '2026-09-01T00:05:00Z',
    tokensBilledIn: 100,
    tokensCacheRead: 0,
    tokensOut: 50,
    costUsd: 0,
    costBasis: 'unknown',
    triggeredBy: 'manual',
    incidentState: '',
    stateReason: '',
    plan: null,
    rootCause: null,
    confidence: null,
    partialReason: 'time_limit',
    suggestedNextSteps: ['Check node disk pressure on the underlying node'],
    ...overrides,
  } as Analysis
}

function makePlan(overrides: Partial<RemediationPlan> = {}): RemediationPlan {
  return {
    id: 'plan_1',
    actionType: 'ScaleDeployment',
    targetGvk: 'apps/v1/Deployment',
    targetNamespace: 'payments',
    targetName: 'checkout-worker',
    params: { replicas: 4 },
    reversible: true,
    riskLevel: 'low',
    effectiveRiskLevel: 'low',
    summary: 'Scale payments/checkout-worker to 4 replicas',
    gateOutcome: 'NeedsApproval',
    gateReason: 'Scaling a workload needs a human the first time.',
    createdAt: '2026-09-01T00:06:00Z',
    ...overrides,
  } as RemediationPlan
}

describe('buildIncidentReportMarkdown — no-analysis incident', () => {
  const incident = baseIncident({ findings: [makeFinding()] })

  it('never fabricates a conclusion, a plan, or an executed stage', () => {
    const md = buildIncidentReportMarkdown(incident)
    expect(md).not.toMatch(/Root cause:/)
    expect(md).not.toMatch(/Proposed change/)
    // Not yet analyzed is a WAIT, not a "never will" — nothingWasExecuted only
    // folds stages 4-6 once a COMPLETE analysis has ruled out a plan (see that
    // function's own doc comment in incidentLifecycle.ts). An incident that
    // simply has not been analyzed yet still shows all six, each honestly
    // "not reached yet" rather than folded into a claim about a fix that was
    // never proposed at all.
    expect(md).toMatch(/4\. Approve — No remediation to approve yet/)
    expect(md).toMatch(/5\. Apply — No remediation to execute yet/)
    expect(md).toMatch(/6\. Validate — Nothing to validate yet/)
  })

  it('still reports the real finding, not a placeholder', () => {
    const md = buildIncidentReportMarkdown(incident)
    expect(md).toContain('CrashLoopBackOff')
    expect(md).toContain('checkout-worker-abc123')
  })

  it('names the incident the same way IncidentDetailPage does, from the same function', () => {
    const md = buildIncidentReportMarkdown(incident)
    expect(md).toContain(resolvedIdentity(incident).name)
  })

  it('with no finding at all, says so honestly rather than rendering nothing', () => {
    const md = buildIncidentReportMarkdown(baseIncident())
    expect(md).toMatch(/No finding recorded/)
  })
})

describe('buildIncidentReportMarkdown — partial analysis (hit a bound, no conclusion)', () => {
  const incident = baseIncident({
    state: 'NeedsHumanInvestigation',
    findings: [makeFinding()],
    analysis: partialAnalysis(),
  })

  it('says the investigation is incomplete and why, never a conclusion it never reached', () => {
    const md = buildIncidentReportMarkdown(incident)
    expect(md).toMatch(/Investigation incomplete/)
    expect(md).toMatch(/time limit/i)
    expect(md).not.toMatch(/Root cause:/)
  })

  it('carries the suggested next steps', () => {
    const md = buildIncidentReportMarkdown(incident)
    expect(md).toContain('Check node disk pressure on the underlying node')
  })

  it('does NOT fold stages 4-6 — a partial run can still produce a plan on re-analysis, so this is a real "not yet", not a "never" (see noExecutableFix\'s own doc comment: status \'partial\' is deliberately excluded)', () => {
    const md = buildIncidentReportMarkdown(incident)
    expect(md).not.toMatch(/No fix was executed/)
    expect(md).toMatch(/4\. Approve — No remediation to approve yet/)
    expect(md).toMatch(/5\. Apply — No remediation to execute yet/)
    expect(md).toMatch(/6\. Validate — Nothing to validate yet/)
  })
})

describe('buildIncidentReportMarkdown — complete analysis, no executable fix (the majority case)', () => {
  // PROJECT.md D13: measured 2026-09-09, 146 of 192 completed analyses ended
  // Diagnosed with no plan at all — a complete, real root cause that ARGUS
  // simply has no fixed action to express. THIS is the one case where
  // nothingWasExecuted folds stages 4-6, because the chain really does stop
  // at Recommendation rather than merely waiting.
  const incident = baseIncident({
    state: 'Diagnosed',
    findings: [makeFinding()],
    analysis: completeAnalysis({
      rootCause: { statement: 'The image tag points at a manifest that was never pushed.' },
      suggestedNextSteps: ['Push the missing image tag, or point the deployment at an existing one'],
    }),
  })

  it('states the real root cause', () => {
    const md = buildIncidentReportMarkdown(incident)
    expect(md).toContain('The image tag points at a manifest that was never pushed.')
  })

  it('folds stages 4-6 into the one honest "nothing was executed" line', () => {
    const md = buildIncidentReportMarkdown(incident)
    expect(md).toMatch(/No fix was executed — nothing to approve, apply or validate\./)
    expect(md).not.toMatch(/4\. Approve/)
  })
})

describe('buildIncidentReportMarkdown — complete analysis, plan approved and executed', () => {
  const plan = makePlan({
    gateOutcome: 'AutoApprove',
    approval: { verdict: 'approved', actorEmail: 'ops@example.com', createdAt: '2026-09-01T00:07:00Z' },
    execution: { outcome: 'succeeded', executedAt: '2026-09-01T00:08:00Z', id: 'exec_1' },
  })
  const incident = baseIncident({
    state: 'Resolved',
    resolutionKind: 'remediated',
    findings: [makeFinding()],
    analysis: completeAnalysis({ plan }),
    route: 'inPlace',
    routeReason: 'No GitOps controller owns this object, so an in-place patch is durable.',
  })

  it('renders the real root cause and confidence', () => {
    const md = buildIncidentReportMarkdown(incident)
    expect(md).toContain('The container repeatedly OOMKilled under load.')
    expect(md).toMatch(/90% confidence/)
  })

  it('renders the proposed change with the same before/after planChange derives on the page', () => {
    const md = buildIncidentReportMarkdown(incident)
    expect(md).toContain('Scale payments/checkout-worker to 4 replicas')
    expect(md).toContain('After: spec.replicas: 4')
  })

  it('renders the real approval and execution outcome, not a folded line', () => {
    const md = buildIncidentReportMarkdown(incident)
    expect(md).toMatch(/Decision: approved by ops@example\.com/)
    expect(md).toMatch(/Execution: succeeded/)
    expect(md).not.toMatch(/No fix was executed/)
  })

  it('renders all six lifecycle stages, none of them fabricated as unreached', () => {
    const md = buildIncidentReportMarkdown(incident)
    for (const label of ['1. Detection', '2. Analysis', '3. Recommendation', '4. Approve', '5. Apply', '6. Validate']) {
      expect(md).toContain(label)
    }
  })

  it('states the resolution kind honestly (remediated, not a bare "resolved")', () => {
    const md = buildIncidentReportMarkdown(incident)
    expect(md).toMatch(/ARGUS's own remediation is linked to this close/)
  })
})

describe('buildIncidentReportMarkdown — recentChanges null vs. empty are two different claims', () => {
  // recentChanges is only ever populated FROM an analysis's own gathered
  // evidence (internal/api/incidents.go's getRecentChanges reads only
  // analysis.causalChain and the stored tool-call ledger) — the real page
  // renders it inside the Analysis stage card (AnalysisView), never on an
  // incident with no analysis at all. `completeAnalysis()` here matches
  // that real precondition rather than testing a combination the API never
  // actually sends.
  const finding = makeFinding()
  const analysis = completeAnalysis()

  it('renders nothing when recentChanges is null (never recorded)', () => {
    const md = buildIncidentReportMarkdown(baseIncident({ findings: [finding], analysis, recentChanges: null }))
    expect(md).not.toMatch(/Recent changes/)
  })

  it('renders an explicit "looked and found nothing" sentence when items is empty', () => {
    const md = buildIncidentReportMarkdown(
      baseIncident({ findings: [finding], analysis, recentChanges: { items: [], windowHours: 6, truncated: false } }),
    )
    expect(md).toMatch(/Recent changes/)
    expect(md).toMatch(/No recorded change in the 6h before/)
  })

  it('renders the real, source-labelled items when present', () => {
    const md = buildIncidentReportMarkdown(
      baseIncident({
        findings: [finding],
        analysis,
        recentChanges: {
          items: [
            {
              time: '2026-08-31T23:55:00Z',
              category: 'replica_change',
              source: 'get_events',
              objectKind: 'Deployment',
              objectNamespace: 'payments',
              objectName: 'checkout-worker',
              reason: 'ScalingReplicaSet',
              message: 'Scaled up replica set to 1',
            },
          ],
          windowHours: 6,
          truncated: true,
        },
      }),
    )
    expect(md).toMatch(/Replica count changed/)
    expect(md).toMatch(/Scaled up replica set to 1/)
    expect(md).toMatch(/Showing the most recent changes only/)
  })
})

describe('buildIncidentReportMarkdown — repeated sightings of one change are listed once', () => {
  it('folds the same change seen by many tool calls into one line with its count', () => {
    const change = {
      time: '2026-08-31T23:55:00Z',
      category: 'replica_change' as const,
      source: 'get_events',
      objectKind: 'Deployment',
      objectNamespace: 'payments',
      objectName: 'checkout-worker',
      reason: 'ScalingReplicaSet',
      message: 'Scaled up replica set to 1',
    }
    const other = { ...change, message: 'Scaled down replica set to 0' }
    const items = Array.from({ length: 18 }, () => [change, other]).flat()
    const md = buildIncidentReportMarkdown(
      baseIncident({
        findings: [makeFinding()],
        analysis: completeAnalysis(),
        recentChanges: { items, windowHours: 6, truncated: false },
      }),
    )
    expect(md.match(/Scaled up replica set to 1/g)).toHaveLength(1)
    expect(md.match(/Scaled down replica set to 0/g)).toHaveLength(1)
    expect(md).toMatch(/seen 18 times/)
  })
})

describe('buildIncidentReportMarkdown — "About this report" speaks in user terms', () => {
  it('names no source file or internal package', () => {
    const md = buildIncidentReportMarkdown(baseIncident({ findings: [makeFinding()] }))
    const about = md.slice(md.indexOf('About this report'))
    expect(about).not.toMatch(/IncidentDetailPage|internal\/|\.tsx|GET \/api/)
    expect(about).toMatch(/removed inside the cluster/)
  })
})

describe('buildIncidentReportMarkdown — ownership caveat is never fabricated', () => {
  const finding = makeFinding()

  it('says nothing about ownership when it is unknown', () => {
    const md = buildIncidentReportMarkdown(baseIncident({ findings: [finding], ownership: null }))
    expect(md).not.toMatch(/Managed by/)
  })

  it('names the managing controller and its own revert caveat when known', () => {
    const md = buildIncidentReportMarkdown(
      baseIncident({
        findings: [finding],
        ownership: {
          managedBy: 'argocd',
          sourceKind: 'Application',
          sourceName: 'checkout',
          sourceNamespace: 'argocd',
          objectGvk: 'apps/v1/Deployment',
          objectNamespace: 'payments',
          objectName: 'checkout-worker',
        },
      }),
    )
    expect(md).toMatch(/Managed by Argo CD/)
    expect(md).toMatch(/Argo CD reconciles that object back to what Git says/)
  })
})

describe('buildIncidentReportMarkdown — automation gate renders verbatim, never invented', () => {
  const finding = makeFinding()

  it('renders nothing when no automatic path is gating this incident', () => {
    const md = buildIncidentReportMarkdown(baseIncident({ findings: [finding], automationGate: null }))
    expect(md).not.toMatch(/did not happen automatically/)
  })

  it('renders the exact reason the sweeper wrote, when one is set', () => {
    const md = buildIncidentReportMarkdown(
      baseIncident({
        findings: [finding],
        automationGate: { gate: 'namespace_scope', reason: 'payments is not in the allowed namespace list.', at: '2026-09-01T00:01:00Z' },
      }),
    )
    expect(md).toMatch(/Namespace not allowed/)
    expect(md).toContain('payments is not in the allowed namespace list.')
  })
})

describe('buildIncidentReportMarkdown — redaction: no raw per-call evidence ever appears', () => {
  it('never includes a tool call\'s raw args or result, only the tool name and how many times it was called', () => {
    const incident = baseIncident({
      findings: [makeFinding()],
      analysis: completeAnalysis({
        causalChain: [
          {
            step: 1,
            hypothesis: 'The container is being OOMKilled.',
            finding: 'Confirmed via pod status.',
            toolCalls: [
              {
                tool: 'get_logs',
                args: { credential: 'super-secret-token-should-never-appear' },
                result: 'raw log line containing bearer abc.def.ghi and a password=hunter2',
                error: null,
              },
              {
                tool: 'get_logs',
                args: {},
                result: 'another log line',
                error: null,
              },
            ],
          },
        ],
      }),
    })
    const md = buildIncidentReportMarkdown(incident)
    // The tool identity and count are legitimate report content — this is
    // what AnalysisView/EvidenceGathered already show unconditionally.
    expect(md).toContain('pod logs')
    expect(md).toMatch(/2 × pod logs/)
    // The raw per-call payload is NOT — see this file's own header comment
    // for why (it is behind a lazy, per-click fetch on the real page, never
    // bundled into a report built with no extra requests).
    expect(md).not.toContain('super-secret-token-should-never-appear')
    expect(md).not.toContain('bearer abc.def.ghi')
    expect(md).not.toContain('hunter2')
    expect(md).not.toContain('raw log line')
  })

  it('closes with an explicit statement that redaction happened agent-side, not here', () => {
    const md = buildIncidentReportMarkdown(baseIncident({ findings: [makeFinding()] }))
    expect(md).toMatch(/removed inside the cluster, by the ARGUS agent, before any data left it/)
    expect(md).toMatch(/performs no redaction of its own/)
  })
})

describe('reportFileName', () => {
  it('is deterministic for the same incident', () => {
    const incident = baseIncident()
    expect(reportFileName(incident)).toBe(reportFileName(incident))
  })

  it('changes when the incident state changes, so two pulls of the same incident are distinguishable', () => {
    const detected = baseIncident({ state: 'Detected' })
    const resolved = baseIncident({ state: 'Resolved', id: detected.id })
    expect(reportFileName(detected)).not.toBe(reportFileName(resolved))
  })

  it('is a safe, extension-bearing filename', () => {
    expect(reportFileName(baseIncident())).toMatch(/^incident-[\w-]+\.md$/)
  })
})

describe('buildIncidentSummaryMarkdown (CI-U12)', () => {
  const analysed = baseIncident({
    objectGvk: 'v1/Pod',
    objectNamespace: 'payments',
    objectName: 'api-1',
    analysis: {
      id: 'an_1',
      status: 'complete',
      rootCause: { statement: 'The container exceeds its 256Mi memory limit.' },
      confidence: 0.82,
      partialReason: null,
      suggestedNextSteps: null,
      plan: null,
      ruledOut: [],
      causalChain: [
        {
          step: 1,
          hypothesis: 'memory limit',
          finding: 'OOMKilled',
          toolCalls: [
            { tool: 'describe_resource', args: { gvk: 'v1/Pod', namespace: 'payments', name: 'api-1' }, result: null, error: null },
            { tool: 'describe_resource', args: { gvk: 'v1/Pod', namespace: 'payments', name: 'api-1' }, result: null, error: null },
            { tool: 'get_logs', args: { namespace: 'payments', pod: 'api-1', container: 'app', previous: true }, result: null, error: null },
          ],
        },
      ],
    } as unknown as Analysis,
  })

  it('matches the expected shape', () => {
    expect(buildIncidentSummaryMarkdown(analysed, 'https://argus.example/incidents/inc_1')).toMatchInlineSnapshot(`
      "**api-1**

      - Cluster: test-cluster
      - Object: Pod payments/api-1
      - Severity: high
      - State: Not investigated
      - AI: root cause — The container exceeds its 256Mi memory limit. (model's own confidence 82%)

      Evidence (run against test-cluster):
      - describe resource — Pod payments/api-1: \`kubectl -n payments get pod api-1 -o yaml\`
      - pod logs — Pod payments/api-1: \`kubectl -n payments logs api-1 -c app --previous\`

      Incident: https://argus.example/incidents/inc_1
      "
    `)
  })

  it('never presents a missing analysis as a root cause', () => {
    const md = buildIncidentSummaryMarkdown(baseIncident(), 'u')
    expect(md).toContain('- Root cause: not analysed yet')
    expect(md).not.toContain('AI:')
  })
})
