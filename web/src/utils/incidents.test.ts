import { describe, expect, it } from 'vitest'
import {
  SEVERITY_BADGE_CLASS,
  SEVERITY_LABEL,
  STATE_BADGE_CLASS,
  STATE_EXPLANATION,
  STATE_DISPOSITION,
  STATE_LABEL,
  incidentRequiresAction,
  isClosedIncidentState,
  partialReasonText,
  executesForReal,
  approvalWaitStartedAt,
  oldestPendingApprovalPlanAt,
  stateExplanation,
  kindFromObjectGvk,
  collapseWorkloadSiblings,
  detectionCountTitle,
  incidentIdentity,
  incidentIdentityLabel,
  incidentObservedObject,
  observedObjectTitle,
  parseWorkloadKey,
  workloadGroupSummary,
} from './incidents'
import type { WorkloadGroupRow } from './incidents'
import type { ApprovalQueueItem, Incident, IncidentSeverity, IncidentState, PartialReason, RemediationPlan } from '../api/types'

// These four maps are keyed by union types, so TypeScript already guarantees every
// member has an entry. What it does NOT guarantee is that the entry says anything —
// a `''` compiles fine and renders an unlabelled badge, and a state added to the
// union with a copy-pasted duplicate label is invisible to the compiler too.
//
// The real risk they guard is a state the backend can emit that the UI renders as
// blank. That has already happened once in this codebase: PartialReason was missing
// 'malformed_final_answer', so partialReasonText fell through and the sentence
// rendered empty (see its own comment).

const SEVERITIES: IncidentSeverity[] = ['low', 'medium', 'high', 'critical']

// Mirrors internal/api/incidents.go's validIncidentStates. Restated rather than
// imported because the point is to catch the UI drifting from the BACKEND's set —
// importing the UI's own list would make the test tautological.
const BACKEND_STATES: IncidentState[] = [
  'Detected',
  'Investigating',
  'RecommendationReady',
  'NeedsHumanInvestigation',
  'AwaitingApproval',
  'Executing',
  'AwaitingMerge',
  'Validating',
  'Resolved',
  'Failed',
  'Reopened',
  'Dismissed',
  'Diagnosed',
  'ExecutionUnknown',
  'ValidationUnknown',
  'PlanRejected',
  'Expired',
]

describe('severity presentation', () => {
  it.each(SEVERITIES)('%s has a non-empty label and badge class', (severity) => {
    expect(SEVERITY_LABEL[severity]?.trim()).toBeTruthy()
    expect(SEVERITY_BADGE_CLASS[severity]?.trim()).toBeTruthy()
  })

  it('gives each severity a distinct label, so two do not read alike', () => {
    const labels = SEVERITIES.map((s) => SEVERITY_LABEL[s])
    expect(new Set(labels).size).toBe(SEVERITIES.length)
  })
})

describe('incident state presentation', () => {
  // The drift guard: a state the hub can put an incident into must have a label
  // here, or the operator sees an empty cell for an incident that exists.
  it.each(BACKEND_STATES)('%s (a state the backend can emit) has a label and a badge class', (state) => {
    expect(STATE_LABEL[state]?.trim()).toBeTruthy()
    expect(STATE_BADGE_CLASS[state]?.trim()).toBeTruthy()
  })

  it('labels every state distinctly, so two states are never indistinguishable on screen', () => {
    const labels = BACKEND_STATES.map((s) => STATE_LABEL[s])
    expect(new Set(labels).size).toBe(BACKEND_STATES.length)
  })
})

describe('incident disposition', () => {
  // Mirrors internal/orchestrator/state.go's disposition table. Restated here
  // rather than imported for the same reason BACKEND_STATES is: the point is to
  // catch this client drifting from the server's answer, and importing the
  // client's own table would make the test tautological.
  const BACKEND_REQUIRES_ACTION: IncidentState[] = [
    'Detected',
    'RecommendationReady',
    'NeedsHumanInvestigation',
    'AwaitingApproval',
    'PlanRejected',
    'Diagnosed',
    'Failed',
    'ExecutionUnknown',
    'ValidationUnknown',
    'Reopened',
  ]
  const BACKEND_IN_PROGRESS: IncidentState[] = ['Investigating', 'Executing', 'AwaitingMerge', 'Validating']
  const BACKEND_CLOSED: IncidentState[] = ['Resolved', 'Dismissed', 'Expired']

  it.each(BACKEND_REQUIRES_ACTION)('%s is on a human, per the server', (state) => {
    expect(incidentRequiresAction(state)).toBe(true)
    expect(isClosedIncidentState(state)).toBe(false)
  })

  it.each(BACKEND_IN_PROGRESS)('%s is open and nobody owes work on it, per the server', (state) => {
    expect(incidentRequiresAction(state)).toBe(false)
    expect(isClosedIncidentState(state)).toBe(false)
  })

  it.each(BACKEND_CLOSED)('%s is closed, per the server', (state) => {
    expect(isClosedIncidentState(state)).toBe(true)
    expect(incidentRequiresAction(state)).toBe(false)
  })

  // The review's finding 9, on this side of the wire: this is the state where
  // "finished", "closed" and "needs a human" come apart, and the definition it
  // replaced could only say one thing about all three.
  it('Diagnosed is finished, not closed, and still needs a human', () => {
    expect(STATE_DISPOSITION.Diagnosed).toBe('requiresAction')
    expect(isClosedIncidentState('Diagnosed')).toBe(false)
  })

  // A hub newer than this bundle can send a state the union has never heard of.
  // It must surface, not vanish from every queue — same fallback the server
  // takes.
  it('an unknown state counts as needing action rather than disappearing', () => {
    expect(incidentRequiresAction('SomethingNewTheHubInvented' as IncidentState)).toBe(true)
    expect(isClosedIncidentState('SomethingNewTheHubInvented' as IncidentState)).toBe(false)
  })
})

// PROJECT.md T2: Expired must read as a DIFFERENT fact from Dismissed even
// though they share a badge colour on purpose (STATE_BADGE_CLASS's own
// comment) — the word is what carries the distinction here, matching this
// file's own established precedent for states that share a colour.
describe('Expired reads as a different fact from Dismissed (PROJECT.md T2)', () => {
  it('has its own distinct label and explanation, not a copy of Dismissed\'s', () => {
    expect(STATE_LABEL.Expired).toBe('Expired')
    expect(STATE_LABEL.Expired).not.toBe(STATE_LABEL.Dismissed)
    expect(STATE_EXPLANATION.Expired?.trim()).toBeTruthy()
    expect(STATE_EXPLANATION.Expired).not.toBe(STATE_EXPLANATION.Dismissed)
  })

  it('is closed, like Dismissed, but says a recurrence can still reopen it', () => {
    expect(isClosedIncidentState('Expired')).toBe(true)
    expect(incidentRequiresAction('Expired')).toBe(false)
    expect(STATE_EXPLANATION.Expired).toMatch(/reopen/i)
  })
})

// PROJECT.md T4's second live case (gwas-db): NeedsHumanInvestigation is
// reached BOTH by a bound-hit investigation that reached no conclusion at
// all AND by a complete investigation that persisted a real root cause but
// proposed nothing executable — STATE_EXPLANATION's static sentence is
// written for the first and is false for the second ("stopped without a
// clear cause" when a cause was, in fact, found and recorded). stateExplanation
// is the fix: it conditions the wording on whether analyses.root_cause
// actually carries a statement, the same "was a root cause persisted"
// question orchestrator's own self-heal sweep asks — not on anything the
// model's isFault verdict says, which this route never even sets.
describe('stateExplanation — NeedsHumanInvestigation reads differently depending on whether a root cause was persisted (PROJECT.md T4)', () => {
  it('keeps the bound-hit wording when no analysis reached a conclusion at all', () => {
    expect(stateExplanation('NeedsHumanInvestigation', null)).toBe(STATE_EXPLANATION.NeedsHumanInvestigation)
    expect(stateExplanation('NeedsHumanInvestigation', { status: 'partial', rootCause: null })).toBe(
      STATE_EXPLANATION.NeedsHumanInvestigation,
    )
    expect(stateExplanation('NeedsHumanInvestigation', null)).toMatch(/stopped without a clear cause/i)
  })

  it('switches to the "reached a cause" wording once a real root cause was persisted, and drops the false claim', () => {
    const text = stateExplanation('NeedsHumanInvestigation', {
      status: 'complete',
      rootCause: { statement: 'Multi-Attach cleared once the old pod finished terminating' },
    })
    expect(text).not.toMatch(/stopped without a clear cause/i)
    expect(text).toMatch(/reached a cause/i)
  })

  it('does not switch on a complete analysis whose rootCause statement is empty — a legacy row with nothing to show', () => {
    const text = stateExplanation('NeedsHumanInvestigation', { status: 'complete', rootCause: { statement: '   ' } })
    expect(text).toBe(STATE_EXPLANATION.NeedsHumanInvestigation)
  })

  it('leaves every other state on its own static STATE_EXPLANATION entry unchanged', () => {
    expect(stateExplanation('Diagnosed', null)).toBe(STATE_EXPLANATION.Diagnosed)
    expect(stateExplanation('Failed', null)).toBe(STATE_EXPLANATION.Failed)
  })
})

// The review's finding 6: rejecting a plan produces a state, and a state with
// no words is this codebase's known failure mode. Its badge must also not be
// the one that reads as closed.
describe('PlanRejected has words, not just a colour', () => {
  it('carries a label, a badge class and an explanation', () => {
    expect(STATE_LABEL.PlanRejected.trim()).toBeTruthy()
    expect(STATE_BADGE_CLASS.PlanRejected.trim()).toBeTruthy()
    expect(STATE_EXPLANATION.PlanRejected?.trim()).toBeTruthy()
  })

  it('says the fault is unchanged, since "rejected" alone reads as "dealt with"', () => {
    expect(STATE_EXPLANATION.PlanRejected).toMatch(/unchanged/i)
  })

  it('is not badged like a closed incident', () => {
    expect(STATE_BADGE_CLASS.PlanRejected).not.toBe(STATE_BADGE_CLASS.Dismissed)
    expect(STATE_BADGE_CLASS.PlanRejected).not.toBe(STATE_BADGE_CLASS.Resolved)
  })
})

describe('partialReasonText', () => {
  // Every value the backend emits. malformed_final_answer is in this list
  // deliberately: it was missing from the union once, the switch fell through, and
  // the sentence rendered blank on a real incident.
  const REASONS: PartialReason[] = ['iteration_limit', 'time_limit', 'malformed_final_answer']

  it.each(REASONS)('%s produces a real sentence', (reason) => {
    const text = partialReasonText(reason)
    expect(text.trim()).toBeTruthy()
    // A sentence for a human, not the enum echoed back.
    expect(text).not.toBe(reason)
    expect(text.length).toBeGreaterThan(20)
  })

  it('does not return the raw enum for an unknown reason', () => {
    // A backend that adds a fifth reason before the UI does must not print
    // "undefined" into a paragraph.
    const text = partialReasonText('something_new' as PartialReason)
    expect(text).not.toContain('undefined')
    expect(text.trim()).toBeTruthy()
  })
})

describe('executesForReal', () => {
  const plan = (actionType: string) => ({ actionType } as RemediationPlan)

  it('is false for OpenPR, which changes a repository rather than a cluster', () => {
    expect(executesForReal(plan('OpenPR'))).toBe(false)
  })

  it.each(['ScaleDeployment', 'RestartPod', 'PatchResourceLimits', 'RevertContainerImage'])(
    'is true for %s, which patches a live object',
    (actionType) => {
      expect(executesForReal(plan(actionType))).toBe(true)
    },
  )
})

// Finding 11. The pipeline strip's "oldest" figure is the age of the WAIT on
// an approver. It used to be derived from the incident's firstSeen, which is
// when the underlying fault was first DETECTED — a live incident first seen on
// 15 July carrying a plan proposed on 5 September was reported as ignored since
// July, overstating the neglect by seven weeks.
describe('oldestPendingApprovalPlanAt — the age of the wait, not of the fault', () => {
  function approval(over: Partial<ApprovalQueueItem> & { planCreatedAt?: string }): ApprovalQueueItem {
    const { planCreatedAt, ...rest } = over
    return {
      incidentId: 'inc_1',
      clusterId: 'cl_1',
      clusterDisplayName: 'prod-eu',
      fingerprint: 'fp_1',
      severity: 'high',
      firstSeen: '2026-07-15T00:00:00Z',
      lastSeen: '2026-09-05T00:00:00Z',
      occurrenceCount: 12,
      confidence: 0.8,
      rootCauseStatement: 'memory limit too low',
      causalChain: [],
      ruledOut: [],
      alreadyApproved: false,
      plan: {
        id: 'plan_1',
        actionType: 'ScaleDeployment',
        targetGvk: 'apps/v1/Deployment',
        targetNamespace: 'payments',
        targetName: 'payments-api',
        params: {},
        reversible: true,
        riskLevel: 'low',
        effectiveRiskLevel: 'low',
        summary: 'Scale payments-api to 4 replicas',
        gateOutcome: 'NeedsApproval',
        gateReason: 'risk=low',
        createdAt: planCreatedAt ?? '2026-09-05T00:00:00Z',
      } as RemediationPlan,
      ...rest,
    }
  }

  it('measures from the plan, not from the incident that long predates it', () => {
    expect(
      oldestPendingApprovalPlanAt([
        approval({ firstSeen: '2026-07-15T00:00:00Z', planCreatedAt: '2026-09-05T09:00:00Z' }),
      ]),
    ).toBe('2026-09-05T09:00:00Z')
  })

  it('picks the oldest PLAN, even when a different row has the older incident', () => {
    const oldIncidentNewPlan = approval({
      incidentId: 'inc_old',
      firstSeen: '2026-01-01T00:00:00Z',
      planCreatedAt: '2026-09-05T09:00:00Z',
    })
    const newIncidentOldPlan = approval({
      incidentId: 'inc_new',
      firstSeen: '2026-09-01T00:00:00Z',
      planCreatedAt: '2026-09-02T09:00:00Z',
    })
    expect(oldestPendingApprovalPlanAt([oldIncidentNewPlan, newIncidentOldPlan])).toBe('2026-09-02T09:00:00Z')
  })

  it('ignores rows already approved — they are not waiting on anyone', () => {
    expect(
      oldestPendingApprovalPlanAt([
        approval({ incidentId: 'inc_done', alreadyApproved: true, planCreatedAt: '2026-01-01T00:00:00Z' }),
        approval({ incidentId: 'inc_open', planCreatedAt: '2026-09-04T00:00:00Z' }),
      ]),
    ).toBe('2026-09-04T00:00:00Z')
  })

  it('returns null rather than a value nothing measured, for an empty or unusable queue', () => {
    expect(oldestPendingApprovalPlanAt([])).toBeNull()
    expect(oldestPendingApprovalPlanAt([approval({ planCreatedAt: '' })])).toBeNull()
    expect(oldestPendingApprovalPlanAt([approval({ planCreatedAt: 'not-a-date' })])).toBeNull()
  })

  // The single-row form, which ApprovalDecisionCard's own "Waiting …" line
  // reads. Same rule, same null: a row whose wait cannot be measured says so
  // rather than borrowing the incident's much older age.
  it('approvalWaitStartedAt takes the plan timestamp, or null when there is none to take', () => {
    expect(approvalWaitStartedAt(approval({ planCreatedAt: '2026-09-04T00:00:00Z' }))).toBe('2026-09-04T00:00:00Z')
    expect(approvalWaitStartedAt(approval({ planCreatedAt: 'not-a-date' }))).toBeNull()
    // Unlike oldestPendingApprovalPlanAt, this one does NOT skip an
    // already-approved row: the card still shows how long that row has sat
    // there, it just offers no Approve/Reject pair on it.
    expect(
      approvalWaitStartedAt(approval({ alreadyApproved: true, planCreatedAt: '2026-09-04T00:00:00Z' })),
    ).toBe('2026-09-04T00:00:00Z')
  })
})

// The two wire forms an objectGvk actually arrives in. The slash form is the
// agent's own convention (`internal/agent/tools.go`'s formatGVK); the comma
// form is what Kubernetes' GroupVersionKind.String() produces, and what
// anything hand-writing a payload reaches for — scripts/smoke-test.sh did, and
// put 8 rows of it in the dev database, where the identity cell rendered
// "v1, Kind=Pod · default" instead of "Pod · default".
describe('kindFromObjectGvk', () => {
  it('takes the last segment of the slash form', () => {
    expect(kindFromObjectGvk('apps/v1/Deployment')).toBe('Deployment')
    expect(kindFromObjectGvk('v1/Pod')).toBe('Pod')
    expect(kindFromObjectGvk('networking.k8s.io/v1/Ingress')).toBe('Ingress')
    expect(kindFromObjectGvk('argoproj.io/v1alpha1/Application')).toBe('Application')
  })

  it('takes the named Kind out of the comma form, prefix and all discarded', () => {
    expect(kindFromObjectGvk('apps/v1, Kind=Deployment')).toBe('Deployment')
    expect(kindFromObjectGvk('v1, Kind=Pod')).toBe('Pod')
    // No space after the comma — the form the Go tests in internal/knowledge use.
    expect(kindFromObjectGvk('apps/v1,Kind=Deployment')).toBe('Deployment')
    expect(kindFromObjectGvk('v1,Kind=Node')).toBe('Node')
  })

  it('degrades to empty rather than to a prefix', () => {
    expect(kindFromObjectGvk(undefined)).toBe('')
    expect(kindFromObjectGvk(null)).toBe('')
    expect(kindFromObjectGvk('')).toBe('')
    // A bare kind with no prefix is already the answer.
    expect(kindFromObjectGvk('Pod')).toBe('Pod')
  })
})

// --- Workload sibling collapse ---

function inc(over: Partial<Incident>): Incident {
  return {
    id: 'inc_x',
    clusterId: 'cl_1',
    clusterDisplayName: 'prod-eu',
    fingerprint: 'fp_x',
    severity: 'medium',
    state: 'Detected',
    firstSeen: '2026-08-20T10:00:00Z',
    lastSeen: '2026-08-20T10:00:00Z',
    occurrenceCount: 1,
    ...over,
  }
}

// --- Which object a human reads an incident as being about (B174) ---
//
// The two rows these are modelled on are real and still in the development
// database: `inc_01m2wxrehvyhh9b44tzgaa93qs` and
// `inc_01m2wxtyy17pwqjezhej850f1d`, both OOMKilled, both keyed on a Pod that
// the remediation's own rollout deleted, both carrying the Deployment that
// was actually fixed in `workload_key`.
describe('incidentIdentity — the owning workload leads', () => {
  const OOM_ON_A_POD = inc({
    objectGvk: 'v1/Pod',
    objectNamespace: 'argus-e2e-rke2',
    objectName: 'checkout-oom-6d99b45595-fw7v8',
    workloadKey: 'apps/v1/Deployment|argus-e2e-rke2|checkout-oom',
    openingReason: 'OOMKilled',
    state: 'Resolved',
  })

  it('names the owner, not the Pod that carried the symptom', () => {
    expect(incidentIdentity(OOM_ON_A_POD)).toEqual({
      name: 'checkout-oom',
      kind: 'Deployment · argus-e2e-rke2',
      fault: 'OOMKilled',
    })
  })

  it('keeps the Pod as the observed object, with no claim that it still exists', () => {
    const observed = incidentObservedObject(OOM_ON_A_POD)
    expect(observed).toEqual({ kind: 'Pod', name: 'checkout-oom-6d99b45595-fw7v8', label: 'Pod checkout-oom-6d99b45595-fw7v8' })
    // Past tense, and the caveat travels with the fact. The wording must not
    // depend on `state`: nothing re-reads the Pod, so "gone" and "currently
    // failing on" would both be claims ARGUS never verified.
    const title = observedObjectTitle(observed!)
    expect(title).toMatch(/carried the symptom when this incident was detected/)
    expect(title).toMatch(/may be gone/)
    expect(observedObjectTitle(incidentObservedObject({ ...OOM_ON_A_POD, state: 'Detected' })!)).toBe(title)
  })

  // The NULL case is the majority, not an edge: 166 of 190 incidents on the
  // development database have no workload_key — every Ingress, Node,
  // Certificate, Job and bare Pod.
  it('falls back to the object itself when no owner was resolved, inventing nothing', () => {
    const noOwner = inc({
      objectGvk: 'cert-manager.io/v1/Certificate',
      objectNamespace: 'cattle-system',
      objectName: 'rancher-ingress',
      openingReason: 'CertificateExpiryImminent',
    })
    expect(incidentIdentity(noOwner)).toEqual({
      name: 'rancher-ingress',
      kind: 'Certificate · cattle-system',
      fault: 'CertificateExpiryImminent',
    })
    // No owner means nothing extra to render — not an em dash where a name
    // belongs, and not a second copy of the object that is already the
    // headline.
    expect(incidentObservedObject(noOwner)).toBeNull()
    expect(incidentIdentityLabel(noOwner)).toBe('rancher-ingress')
  })

  it('reads the slash form too, since the database holds both', () => {
    const slashForm = inc({
      objectGvk: 'v1/Pod',
      objectNamespace: 'default',
      objectName: 'checkout-Expired',
      workloadKey: 'cl_01m2rdgt6ehpa7a9frdz4nec8c/apps/Deployment/default/checkout',
      openingReason: 'PodCrashLooping',
    })
    expect(incidentIdentity(slashForm).name).toBe('checkout')
    expect(incidentObservedObject(slashForm)?.label).toBe('Pod checkout-Expired')
  })

  // The hub splits object_key on `|`, so a SLASH-form object key arrives whole
  // in objectName with no gvk or namespace beside it — 36 rows on the dev
  // fleet, found by running these helpers over all 228 of them rather than
  // over fixtures. A Kubernetes object name cannot contain `/` (RFC 1123), so
  // the value is recoverable rather than something to print raw.
  it('recovers an object identity from a slash-form object key rather than printing it raw', () => {
    const rawKey = inc({
      objectName: 'cl_01m2rdgtevjamgje57j5m7ttd4/v1/Pod/default/checkout-Expired',
      workloadKey: 'cl_01m2rdgtevjamgje57j5m7ttd4/apps/Deployment/default/checkout',
      openingReason: 'CrashLoopBackOff',
    })
    expect(incidentObservedObject(rawKey)?.label).toBe('Pod checkout-Expired')

    // And the same value read as a headline, when nothing owns it — one field
    // must not be shown two ways in one column.
    const unowned = inc({ objectName: 'cl_01m2rdgtevjamgje57j5m7ttd4/v1/Pod/default/lonely', openingReason: 'OOMKilled' })
    expect(incidentIdentity(unowned)).toEqual({ name: 'lonely', kind: 'Pod · default', fault: 'OOMKilled' })
  })

  // A Node-owned static Pod: the owner is not always a Deployment, and the
  // kind line must say what the owner actually is rather than assuming.
  it('does not assume the owner is a Deployment', () => {
    const staticPod = inc({
      objectGvk: 'v1/Pod',
      objectNamespace: 'kube-system',
      objectName: 'kube-apiserver-argus-b163-control-plane',
      workloadKey: 'v1/Node|kube-system|argus-b163-control-plane',
      openingReason: 'PodCrashLooping',
    })
    expect(incidentIdentity(staticPod)).toMatchObject({ name: 'argus-b163-control-plane', kind: 'Node · kube-system' })
  })

  it('says nothing twice when the owner and the object are the same thing', () => {
    expect(
      incidentObservedObject(
        inc({
          objectGvk: 'apps/v1/Deployment',
          objectNamespace: 'payments',
          objectName: 'api',
          workloadKey: 'apps/v1/Deployment|payments|api',
        }),
      ),
    ).toBeNull()
  })

  // The regression this helper exists to prevent: with the workload leading,
  // every sibling Pod of one Deployment renders the same name, so a checkbox
  // label or a bulk-close list built from it alone would be ambiguous exactly
  // where it must not be.
  it('gives siblings distinguishable accessible labels', () => {
    const a = inc({ id: 'a', objectGvk: 'v1/Pod', objectName: 'checkout-1', workloadKey: 'apps/v1/Deployment|default|checkout' })
    const b = inc({ id: 'b', objectGvk: 'v1/Pod', objectName: 'checkout-2', workloadKey: 'apps/v1/Deployment|default|checkout' })
    expect(incidentIdentity(a).name).toBe(incidentIdentity(b).name)
    expect(incidentIdentityLabel(a)).toBe('checkout (Pod checkout-1)')
    expect(incidentIdentityLabel(b)).toBe('checkout (Pod checkout-2)')
  })

  it('still degrades to the failure label when the opening finding named no object at all', () => {
    const nothing = inc({ fingerprint: 'abcdef1234567890', openingReason: 'NodeNotReady' })
    expect(incidentIdentity(nothing)).toEqual({ name: 'NodeNotReady', kind: '', fault: '' })
    expect(incidentObservedObject(nothing)).toBeNull()
  })
})

describe('parseWorkloadKey', () => {
  // Both forms are genuinely on the wire — internal/gateway's
  // workloadCorrelationKey writes the pipe form, and the development database
  // also holds slash-form keys written by seeded fixtures.
  it('reads the pipe form internal/gateway writes', () => {
    expect(parseWorkloadKey('apps/v1/Deployment|payments|api')).toEqual({
      kind: 'Deployment',
      namespace: 'payments',
      name: 'api',
    })
  })

  it('reads a slash-form key, taking the LAST three segments', () => {
    expect(parseWorkloadKey('cl_01abc/apps/Deployment/default/checkout')).toEqual({
      kind: 'Deployment',
      namespace: 'default',
      name: 'checkout',
    })
  })

  it('degrades rather than guessing when there is nothing to parse', () => {
    expect(parseWorkloadKey(undefined)).toEqual({ kind: '', namespace: '', name: '' })
    expect(parseWorkloadKey('')).toEqual({ kind: '', namespace: '', name: '' })
    expect(parseWorkloadKey('checkout')).toEqual({ kind: '', namespace: '', name: 'checkout' })
  })
})

describe('collapseWorkloadSiblings', () => {
  it('keeps the server order and puts a group where its first member was', () => {
    const rows = collapseWorkloadSiblings([
      inc({ id: 'a' }),
      inc({ id: 'b', workloadGroupId: 'g1' }),
      inc({ id: 'c' }),
      inc({ id: 'd', workloadGroupId: 'g1' }),
    ])
    expect(rows.map((row) => (row.kind === 'incident' ? row.incident.id : `group:${row.groupId}`))).toEqual([
      'a',
      'group:g1',
      'c',
    ])
    const group = rows[1]
    expect(group.kind === 'workloadGroup' && group.incidents.map((i) => i.id)).toEqual(['b', 'd'])
  })

  it('does not collapse a group with a single member on this page', () => {
    // Its siblings may exist server-side but are not here, and a parent row
    // standing in for one incident spends a whole row saying nothing.
    const rows = collapseWorkloadSiblings([inc({ id: 'a', workloadGroupId: 'g1' }), inc({ id: 'b' })])
    expect(rows.every((row) => row.kind === 'incident')).toBe(true)
  })

  it('loses no incident — every input appears in exactly one row', () => {
    const input = [
      inc({ id: 'a', workloadGroupId: 'g1' }),
      inc({ id: 'b', workloadGroupId: 'g2' }),
      inc({ id: 'c', workloadGroupId: 'g1' }),
      inc({ id: 'd' }),
      inc({ id: 'e', workloadGroupId: 'g2' }),
    ]
    const flattened = collapseWorkloadSiblings(input).flatMap((row) =>
      row.kind === 'incident' ? [row.incident.id] : row.incidents.map((i) => i.id),
    )
    expect(flattened.sort()).toEqual(['a', 'b', 'c', 'd', 'e'])
  })
})

describe('workloadGroupSummary', () => {
  const group = (incidents: Incident[]): WorkloadGroupRow => ({
    kind: 'workloadGroup',
    key: 'g1',
    groupId: 'g1',
    incidents,
  })

  it('takes identity from the workload key, not from one pod', () => {
    const summary = workloadGroupSummary(
      group([
        inc({ id: 'a', objectName: 'checkout-abc', workloadKey: 'apps/v1/Deployment|default|checkout', openingReason: 'CrashLoopBackOff' }),
        inc({ id: 'b', objectName: 'checkout-def', workloadKey: 'apps/v1/Deployment|default|checkout', openingReason: 'CrashLoopBackOff' }),
      ]),
    )
    expect(summary.name).toBe('checkout')
    expect(summary.kind).toBe('Deployment · default')
    expect(summary.fault).toBe('CrashLoopBackOff')
    expect(summary.memberCount).toBe(2)
  })

  it('reports the WORST severity and says when the members disagree', () => {
    const mixed = workloadGroupSummary(group([inc({ id: 'a', severity: 'low' }), inc({ id: 'b', severity: 'critical' })]))
    expect(mixed.severity).toBe('critical')
    expect(mixed.severityUnanimous).toBe(false)

    const same = workloadGroupSummary(group([inc({ id: 'a', severity: 'high' }), inc({ id: 'b', severity: 'high' })]))
    expect(same.severity).toBe('high')
    expect(same.severityUnanimous).toBe(true)
  })

  it('refuses to pick one state when the members are in several', () => {
    const summary = workloadGroupSummary(
      group([inc({ id: 'a', state: 'Detected' }), inc({ id: 'b', state: 'AwaitingApproval' }), inc({ id: 'c', state: 'Detected' })]),
    )
    expect(summary.state).toBeNull()
    expect(summary.stateCounts).toEqual([
      { state: 'Detected', count: 2 },
      { state: 'AwaitingApproval', count: 1 },
    ])
  })

  it('treats a route only SOME members carry as a disagreement, not as the group route', () => {
    // "these two go via a pull request and the other eleven are unrouted" is
    // not "this group goes via a pull request".
    const partial = workloadGroupSummary(group([inc({ id: 'a', route: 'pullRequest' }), inc({ id: 'b' })]))
    expect(partial.route).toBeNull()

    const none = workloadGroupSummary(group([inc({ id: 'a' }), inc({ id: 'b' })]))
    expect(none.route).toBeUndefined()

    const unanimous = workloadGroupSummary(group([inc({ id: 'a', route: 'inPlace' }), inc({ id: 'b', route: 'inPlace' })]))
    expect(unanimous.route).toBe('inPlace')

    const conflicting = workloadGroupSummary(group([inc({ id: 'a', route: 'inPlace' }), inc({ id: 'b', route: 'guidance' })]))
    expect(conflicting.route).toBeNull()
  })

  it('sums detections and takes the widest time range', () => {
    const summary = workloadGroupSummary(
      group([
        inc({ id: 'a', occurrenceCount: 4, firstSeen: '2026-08-20T10:00:00Z', lastSeen: '2026-08-20T11:00:00Z' }),
        inc({ id: 'b', occurrenceCount: 7, firstSeen: '2026-08-19T10:00:00Z', lastSeen: '2026-08-20T15:00:00Z' }),
      ]),
    )
    expect(summary.detectionCount).toBe(11)
    expect(summary.firstSeen).toBe('2026-08-19T10:00:00Z')
    expect(summary.lastSeen).toBe('2026-08-20T15:00:00Z')
  })

  it('reports fleet-wide when ANY member is, since the claim is about the problem', () => {
    expect(workloadGroupSummary(group([inc({ id: 'a' }), inc({ id: 'b', fleetGroupId: 'fg1' })])).anyFleetGroup).toBe(true)
    expect(workloadGroupSummary(group([inc({ id: 'a' }), inc({ id: 'b' })])).anyFleetGroup).toBe(false)
  })
})

describe('detectionCountTitle', () => {
  it('names what the number counts, and what it does not', () => {
    expect(detectionCountTitle(1)).toMatch(/once by a detector since this incident opened/i)
    const many = detectionCountTitle(12)
    expect(many).toMatch(/Reported 12 times/i)
    // The whole point of the rename: it must not be read as the number of
    // prior incidents on this object, which is a different query.
    expect(many).toMatch(/not the number of prior incidents/i)
  })
})
