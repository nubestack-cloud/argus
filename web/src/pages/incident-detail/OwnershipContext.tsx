// The ownership/context group of the incident-detail screen: which
// controller manages the object, which kind of detection saw it, and why an
// automatic step (analysis or execution) hasn't happened yet — split out of
// IncidentDetailPage.tsx (PROJECT.md P25) with no behavior change. See that
// file's own header for the screen this panel belongs to.
import type { Finding, IncidentAutomationGate, ObjectOwnership, UnattendedBatchInfo } from '../../api/types'
import { detectionSourceFor, detectionSourceKinds } from '../../utils/detectors'
import { AUTOMATION_GATE_LABEL, OWNERSHIP_COPY } from '../incidentLifecycle'

// 'unreachable' is the state this panel was missing: a step that will never
// run for this incident, because the pipeline already finished. It is kept
// distinct from both of its neighbours on purpose — from 'pending', which
// promises the step is still coming, and from 'blocked', which is reserved for
// something that went wrong (a rejected plan, a gate refusal, a failed
// execution). "This fault has no automatically-executable fix" is neither: it
// is the correct, permanent, and most common outcome, so it must not be
// painted in danger colours (same discipline ConclusionBlock applies to a
// partial analysis) nor read as a stalled queue.
// OWNERSHIP_COPY moved to incidentLifecycle.ts (PROJECT.md T17) — see that
// file's own comment on why, and on the three other label tables it now
// holds alongside it.

// ManagedByContext — the identity half of the old FixDurabilityNotice
// (BACKLOG D8 A3). Which controller owns this object is a fact about the
// OBJECT, true before any fix is proposed and independent of whether one ever
// is, so it now sits in stage 1 (Detection / "what broke") beside the raw
// finding — not in stage 3, where it used to arrive bundled with the write
// action that opens a pull request. Deliberately just the identity claim: no
// revert/fix consequence, no repo/path/commit — those justify a CHOICE, and
// the choice is stage 3's question, not this one. Splitting the block wholesale
// into stage 3 (as it was) would have relocated the ordering bug rather than
// fixed it; this is the half that actually belongs at question 1.
export function ManagedByContext({ ownership }: { ownership: ObjectOwnership }) {
  const copy = OWNERSHIP_COPY[ownership.managedBy]
  // A hub newer than this bundle, reporting a fourth managing system: no
  // wording for it means no claim about it — the same silence as null, for the
  // same reason.
  if (!copy) return null
  // PROJECT.md D13: a chip on one hint line, not a bordered callout restating
  // the object. The finding line directly above already prints the gvk and the
  // namespace/name, so naming them again here was the same identity twice, in
  // a box heavy enough to read as a warning about a fix that has not been
  // proposed yet. What is genuinely new at stage 1 is only WHO owns it.
  return (
    <p className="field-hint">
      <span className="badge badge-amber">Managed by {copy.badge}</span> {copy.subject(ownership)}
    </p>
  )
}

// DetectionSourceContext — PROJECT.md item 14: which of ARGUS's two kinds of
// detection saw this, stated on the screen instead of left implicit in a raw
// `detector k8s-sweep` string inside a collapsed disclosure.
//
// Why this is worth a line on the busiest card in the product: 455 of the
// 1032 entries in issue-catalog/k8s-issue-catalog.yaml carry `silent: true`
// — 44% of the catalogued fault surface announces nothing an operator could
// grep for (SCHED-008, "total capacity exists, no single node fits", is a
// representative one). Those are the faults their existing tooling cannot
// find, and they are the whole argument for running ARGUS. Rendered
// identically to whatever a forwarded Warning event produced, the product's
// best capability was indistinguishable from `kubectl get events` with extra
// steps.
//
// That 44% is a property of the CATALOGUE, not of this install's data, and
// it is deliberately not rendered. The honest on-screen distribution would
// have to be over findings that actually OPENED an incident — the raw
// finding ratio is ~358k sweep to ~516 event, dominated by high-volume sweep
// findings that never promote, a true number telling a false story — and no
// endpoint returns that aggregate today. So: this component states a KIND,
// never a share.
//
// Same shape as ManagedByContext directly above — a badge on one hint line,
// deliberately not a bordered callout — because it is the same kind of fact
// at the same stage: provenance of the finding already printed above it,
// true independently of any proposed fix. And the same silence on an
// unrecognised detector id (`if (!source) return null`), for the same
// reason: no wording for it means no claim about it. `smoketest-detector`
// and `test-detector` are real ids in real databases, and bucketing one of
// them as "ARGUS found this where kubectl could not" would be an invented
// fact about the product's headline capability.
//
// TWO claims here, and the split is the whole honesty argument:
//
//  1. The badge and sentence describe THE FINDING PRINTED ABOVE, not the
//     incident. Detection source is a property of a finding, and object-level
//     correlation (migration 000036) deliberately attaches every symptom of
//     one broken object to a single incident — measured against the live
//     database, 14 of 139 incidents carry findings from more than one
//     detector, and 5 carry all three. A single badge on the incident would
//     therefore be false about one incident in ten.
//  2. The mixed note is a POSITIVE claim ("more than one source is present")
//     derived from findings that are actually in hand. Its negation is never
//     stated: `findings` is a bounded slice (the newest few per reason), so
//     "this incident is sweep-only" is an absence claim the payload cannot
//     support, and no count or share is rendered anywhere for the same
//     reason. See detectionSourceKinds' own comment.
//
// No distribution is shown here or anywhere else. The honest one is over
// findings that OPENED an incident, not over raw findings — the raw ratio is
// dominated by high-volume sweep findings that never promote — and no
// endpoint returns that aggregate today.
export function DetectionSourceContext({ finding, findings }: { finding: Finding; findings: Finding[] }) {
  const source = detectionSourceFor(finding.detectorId)
  if (!source) return null
  const mixed = detectionSourceKinds(findings.map((f) => f.detectorId)).size > 1
  // Two badge colours for the two kinds, never colour alone: the badge's own
  // words ("Kubernetes event" / "ARGUS check") carry the distinction, and the
  // sentence beside it carries the finer three-way split between detectors.
  // Gray for the event stream — it is the neutral, already-visible case;
  // blue for ARGUS's own checks, which is the one worth noticing. Neither is
  // a severity hue: the severity of this finding is stated by the badge on
  // the identity strip, and adding a second colour scale that looks like
  // severity but is not would be the drift the token rules exist to stop.
  return (
    <p className="field-hint">
      <span className={`badge ${source.sourceKind === 'argusCheck' ? 'badge-blue' : 'badge-gray'}`}>
        {source.sourceKind === 'argusCheck' ? 'ARGUS check' : 'Kubernetes event'}
      </span>{' '}
      {source.sentence}
      {mixed && (
        <>
          {' '}
          This incident also carries findings from the other kind of detection — open “What happened”
          under History to see which reason came from which.
        </>
      )}
    </p>
  )
}

// BatchHoldNotice — BACKLOG.md R3's own flagged UI gap: `GetIncidentBatchInfo`
// has embedded `unattendedBatch` on this endpoint's response since the batch
// gating shipped, but nothing under web/src/ read it, so an incident held
// pending a fleet-wide batch's wave 1 rendered no different from one that was
// simply never eligible for unattended execution at all.
//
// Sits in stage 4 (Approve) — this is a second, batch-level gate on the same
// question ApprovalDecisionCard's `gateReason` already answers per-plan (may
// this plan execute unattended right now), so it belongs beside that answer,
// not folded into stage 1's identity facts the way ManagedByContext is.
//
// The API sends batchStatus/waveNumber/held, not a prose reason (see this
// component's own note in api/types.ts) — the three sentences below mirror
// internal/orchestrator/batch.go's HoldReason() in user-facing language,
// switching on the same fields that Go function does, so the two cannot say
// different things about the same batch. `held` is always false for a wave-1
// member (it runs unconditionally, producing the signal wave 2 waits on) —
// handled first and separately, since calling wave 1 itself "held" would be
// wrong regardless of batchStatus.
// AUTOMATION_GATE_LABEL moved to incidentLifecycle.ts (PROJECT.md T17) —
// same reasoning as OWNERSHIP_COPY above.

// AutomationGateNotice — PROJECT.md T14: the UI's one and only rendering of
// "why isn't this happening automatically?", for both halves of the
// question (why hasn't this been auto-analyzed; why hasn't an auto-approved
// plan auto-executed). `gate` and `reason` are read straight off
// `data.automationGate`, which the API reads straight back from
// incidents.automation_gate/automation_gate_reason — written ONLY by the
// enforcing sweeper (internal/autoanalyze, internal/api/unattended.go) at
// the moment it refused. This component contains NO logic that decides
// which gate applied; it renders `reason` verbatim and uses `gate` only to
// pick a label string from the closed map above. Do not add a branch here
// that infers a reason from any OTHER field on `data` (settings, plan
// fields, etc.) — that is the exact re-derivation this task's brief calls
// the central trap.
export function AutomationGateNotice({ gate }: { gate: IncidentAutomationGate }) {
  return (
    <p className="detail-callout">
      <span className="badge badge-amber">{AUTOMATION_GATE_LABEL[gate.gate] ?? gate.gate}</span> {gate.reason}
    </p>
  )
}

export function BatchHoldNotice({ batch }: { batch: UnattendedBatchInfo }) {
  if (batch.waveNumber <= 1) {
    return (
      <p className="detail-callout">
        <span className="badge badge-blue">Batch wave 1 of {batch.totalSize}</span> This incident is the
        canary for a {batch.totalSize}-incident unattended {batch.actionType} batch — the remaining{' '}
        {batch.totalSize - batch.wave1Size} stay held until this wave's fix is confirmed to hold.
      </p>
    )
  }
  if (!batch.held) {
    return (
      <p className="detail-callout">
        <span className="badge badge-green">Batch cleared</span> Wave 1 of this {batch.totalSize}-incident
        unattended {batch.actionType} batch resolved cleanly, so this incident is eligible to auto-execute
        like normal.
      </p>
    )
  }
  const reason =
    batch.batchStatus === 'blocked'
      ? "wave 1's fix did not hold, so the rest of this batch stays held for a human rather than repeating the same fix"
      : batch.batchStatus === 'abandoned'
        ? 'wave 1 never reached a validated outcome in time, so this incident stays held for a human'
        : "waiting on wave 1's outcome before this incident is allowed to auto-execute"
  return (
    <p className="detail-callout">
      <span className="badge badge-amber">Held — batch wave {batch.waveNumber}</span> This incident is part
      of a {batch.totalSize}-incident unattended {batch.actionType} batch; {reason}.
    </p>
  )
}
