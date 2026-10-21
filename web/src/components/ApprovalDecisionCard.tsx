import { useId, useState } from 'react'
import type { ReactNode } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { HelpTip } from './HelpTip'

import {
  approveIncident,
  rejectIncident,
  ApiError,
  PROBLEM_SCALE_FROM_ZERO_REFUSED,
  PROBLEM_GITOPS_MANAGED_REFUSED,
} from '../api/client'
import type { ApprovalQueueItem, IncidentSeverity, RemediationPlan } from '../api/types'
import { CAP_REMEDIATION_APPROVE, CAP_REMEDIATION_REJECT } from '../api/capabilities'
import { useAuth } from '../auth/useAuth'
import { useHasCapability } from '../auth/useCapabilities'
import { formatDateTime, formatRelativeTime } from '../utils/time'
import { approvalWaitStartedAt, planChange, SEVERITY_RANK } from '../utils/incidents'
import { PreflightPanel } from './PreflightPanel'
import { Dialog } from './Dialog'
import { SeverityBadge } from './IncidentBadges'

// ONE DECISION, RENDERED AS A DECISION RATHER THAN A RECORD
// (.design/ListAndQueue.dc.html, "Archetype B · decision queue"; BACKLOG D7,
// restructured for D11).
//
// Everything an operator needs to say yes or no without leaving the page:
// which object is broken, which route the fix takes, the fault in one line,
// the change itself as a before/after, how long it has been waiting, what was
// already verified, and the two buttons.
//
// THE PROP IS A LIST, NOT ONE ITEM — BACKLOG D11 #6. A single card can now
// stand for MORE THAN ONE ApprovalQueueItem that share the same shape (same
// actionType, same target Kind, same gateReason string — ApprovalsPage's
// groupAndOrderApprovals decides that, this component never re-derives it):
// "delete these three orphaned pods" is one policy judgement, not three,
// and D11 found the old one-card-per-incident rendering repeating identical
// route/gate/risk explanations verbatim once per pod. Rendered ONCE, from
// `items[0]` as the shape's representative: the route, the action type, the
// enforced risk, the gate reasoning, the verification checks and the
// decline/ignore consequence — none of those vary within a group by
// construction. Rendered PER ITEM, inside `.approval-group-members`: the
// object identity, its own root-cause statement, its own proposed diff, its
// own confidence, and its own Approve/Reject pair — a shared judgement about
// the POLICY never collapses the individual, still-irreversible act of
// approving one specific object. `items.length === 1` (by far the common
// case — most queue entries are not duplicates of anything) renders
// identically to the pre-D11 single-item card, just with the honesty and
// hierarchy fixes below.
//
// WHY THIS IS A COMPONENT AND NOT JSX INSIDE ApprovalsPage. The approvals
// screen is the cross-incident view of a step that also lives inside a single
// incident's flow — the same decision, reached from the other direction.
// BACKLOG D8 puts this exact card on IncidentDetailPage, and it is meant to go
// there passing a one-element `items` array — a single incident's own plan
// is a group of one, not a different shape this component has to learn.
//
// Nothing here re-sorts, re-filters or re-derives anything the hub decided;
// ApprovalsPage's own grouping/ordering is a client-side refinement of the
// server's sort (see that file's own comment), never a replacement for it.

// index.css's D7/D8 severity classes. They set --sev-fill/--sev-tint, which
// `.severity-rule` reads to paint the card's left edge — severity as a rule on
// the entry's edge rather than as the leading badge, which is the whole point
// of the archetype (a scan down the queue is a scan of what is broken).
//
// Local to this file for now: this is the first screen restyled onto that
// vocabulary. utils/incidents.ts, which already owns SEVERITY_BADGE_CLASS and
// SEVERITY_LABEL, is the right home for it the moment a second screen needs it
// — one severity vocabulary, not two.
const SEVERITY_RULE_CLASS: Record<IncidentSeverity, string> = {
  low: 'sev-low',
  medium: 'sev-medium',
  high: 'sev-high',
  critical: 'sev-critical',
}

// internal/remediation.RiskLevel's three values — a distinct palette from
// severity's four (this is the PLAN's own blast-radius risk, not the
// incident's severity; the two are independent axes and can disagree, e.g.
// a critical-severity incident with a low-risk fix).
const RISK_BADGE_CLASS: Record<string, string> = {
  low: 'badge badge-blue',
  medium: 'badge badge-amber',
  high: 'badge badge-red',
}

// Worst-first, for picking one risk level out of a group's several members
// (BACKLOG D11 #6) the same way SEVERITY_RANK picks one severity — high
// always wins the badge, because a badge that showed the group's BEST case
// would understate exactly the member that most needs the approver's
// attention.
const RISK_ORDER: ReadonlyArray<'high' | 'medium' | 'low'> = ['high', 'medium', 'low']
function worstRiskLevel(levels: string[]): string {
  for (const level of RISK_ORDER) {
    if (levels.includes(level)) return level
  }
  return levels[0] ?? 'low'
}

// THE BADGE AN APPROVER ACTUALLY DECIDES FROM — BACKLOG D11 #1, this
// screen's worst defect. Shows the risk internal/remediation.Evaluate's gate
// actually ENFORCED (effectiveRiskLevel — the model's declared level raised
// to the deterministic per-action-type/target floor, internal/remediation/
// risk.go), never the bare declaration: a "low risk" badge sitting directly
// above gate text reading "risk=high and reversible=false" was the exact,
// observed bug, because the badge showed the value the floor OVERRODE.
//
// When the two disagree, that fact is not deleted (D11's own "do not fix
// this by hiding the honesty" constraint) — it is ranked below the badge, as
// a smaller "model declared X" note, same family as `.field-hint` used for
// every other secondary fact on this card. It is deliberately NOT a second
// badge the same size: two same-weight badges disagreeing is the exact
// contradiction this fix exists to remove, just relocated one element over.
// `declaredRiskLevel` is `null` rather than a value when a GROUP's members
// declared different levels — showing one member's declaration as if it
// spoke for the whole group would itself be a fabricated fact, so the note
// is omitted rather than guessed at; the enforced badge above it is always
// safe to show regardless, because it is already the group's worst case.
function RiskBadge({
  effectiveRiskLevel,
  declaredRiskLevel,
}: {
  effectiveRiskLevel: string
  declaredRiskLevel: string | null
}) {
  const overridden = declaredRiskLevel !== null && declaredRiskLevel !== effectiveRiskLevel
  return (
    <span className="risk-badge-group">
      <span
        className={RISK_BADGE_CLASS[effectiveRiskLevel] ?? 'badge badge-gray'}
        title={
          overridden
            ? `The model declared ${declaredRiskLevel} risk; ARGUS's deterministic gate enforces ${effectiveRiskLevel} risk regardless of that declaration — see the gate reasoning below.`
            : undefined
        }
      >
        {effectiveRiskLevel} risk
      </span>
      {overridden && <span className="field-hint risk-declared-note">model declared {declaredRiskLevel}</span>}
    </span>
  )
}

// Mirrors IncidentDetailPage.tsx's confidenceBadge (same thresholds, same
// three-tier color scheme) — duplicated locally rather than shared, matching
// this codebase's existing per-page convention for this kind of small badge
// helper (see e.g. IncidentsPage's own STATE_BADGE_CLASS).
//
// The number used to BE the label ("95% confidence (high)") — precision this
// figure has not earned. It is the model's own self-report, never checked
// against a real outcome (InsightsPage lists a "Confidence calibration
// curve" as planned, not built — there is nothing yet that this percentage
// is calibrated against). The parenthetical band restated the same claim in
// words, which does not fix it. The band word is now the whole headline; the
// exact percentage moves to `title`, this product's existing place for a
// precise value behind a humanised one (e.g. AnalysisView's token-count
// line). Thresholds and the underlying confidence value are unchanged — this
// is presentation only.
function confidenceBadge(confidence: number): { band: string; className: string; title: string } {
  const pct = Math.round(confidence * 100)
  const title = `${pct}% — the model's own self-reported estimate, not a probability calibrated against real outcomes.`
  if (confidence >= 0.75) return { band: 'High confidence', className: 'badge badge-green', title }
  if (confidence >= 0.4) return { band: 'Medium confidence', className: 'badge badge-amber', title }
  return { band: 'Low confidence', className: 'badge badge-red', title }
}

// "Waiting 40m", not "waiting 40m ago". formatRelativeTime is the app's single
// relative-time vocabulary and its thresholds are what every other screen
// shows, but its output is phrased as a point in the past and what matters
// here is a duration — staleness is the reason this number is on the card at
// all. The suffix is stripped only when it is actually present, so "just now"
// and "never" pass through untouched.
function waitedFor(isoDate: string): string {
  const relative = formatRelativeTime(isoDate)
  return relative.endsWith(' ago') ? relative.slice(0, -' ago'.length) : relative
}

// The row's age line: how long this DECISION has been waiting, plus how often
// the underlying fault has recurred while it did.
//
// When the plan carries no usable timestamp the wait is stated as not recorded
// rather than omitted or approximated from the incident's own age — an absent
// figure that is simply missing from the line reads as "no wait", which is the
// opposite of what an unknown means here.
function ApprovalRowAge({ item }: { item: ApprovalQueueItem }) {
  const waitStartedAt = approvalWaitStartedAt(item)
  const occurrences = `${item.occurrenceCount} occurrence${item.occurrenceCount === 1 ? '' : 's'}`
  if (!waitStartedAt) {
    return <span className="approval-row-age">Waiting time not recorded · {occurrences}</span>
  }
  return (
    <span className="approval-row-age" title={`Plan proposed ${formatDateTime(waitStartedAt)}`}>
      Waiting {waitedFor(waitStartedAt)} · {occurrences}
    </span>
  )
}

// The readable label for a plan's actionType — never the raw wire value.
// components.md states this rule by name, with "ScaleDeployment" as its own
// worked example of the violation; before this map existed, the badge below
// rendered exactly that raw enum. `RemediationActionType` (api/types.ts) is a
// known-stale union (utils/incidents.ts's planChange has its own comment on
// this) that omits DeleteResource/CreateResource/AnnotateResource/
// LabelResource/PatchField/StructuredPatch even though the backend and this
// very card's checksFor/routeOf/planChange already handle them — so this map
// is keyed loosely (Record<string, string>) and falls back to the raw value
// for anything genuinely unrecognised, the same defensive pattern
// SeverityBadge/StateBadge already use for an unrecognised enum.
const ACTION_TYPE_LABEL: Record<string, string> = {
  ScaleDeployment: 'Scale deployment',
  RestartPod: 'Restart pod',
  PatchResourceLimits: 'Change resource limits',
  RevertContainerImage: 'Revert container image',
  OpenPR: 'Pull request',
  DeleteResource: 'Delete resource',
  CordonNode: 'Cordon node',
  DrainNode: 'Drain node',
  CreateResource: 'Create resource',
  AnnotateResource: 'Annotate resource',
  LabelResource: 'Label resource',
  PatchField: 'Patch field',
  StructuredPatch: 'Structured patch',
}

// internal/remediation.Outcome's three values, read out loud rather than
// rendered raw — the same rule, and GateOutcome is components.md's OTHER
// worked example of the violation ("NeedsApproval" verbatim).
const GATE_OUTCOME_LABEL: Record<string, string> = {
  AutoApprove: 'Eligible for auto-approval',
  NeedsApproval: 'Needs your approval',
  Blocked: 'Blocked',
}

// BACKLOG D11 #3: "the gate reason is a single sentence with three nested
// clauses and two parentheticals... an approver cannot tell at a glance why
// this needs them." internal/remediation/gate.go's Evaluate builds every
// Reason from a closed set of Go format strings that share two structural
// markers this function splits ON — it never RE-DERIVES why from separate
// fields (components.md's own rule: "the UI never reconstructs 'why wasn't
// this auto-fixed' from separate signals" — risk/reversible/actionType are
// exactly those separate signals). It only decides which part of the ONE
// backend string is the glanceable headline and which part is elaboration a
// reader opens on demand — the text itself is never altered or paraphrased.
//
//   - Every "the model's declared risk was raised by the deterministic
//     floor" case appends the exact same parenthetical (gate.go's
//     `floorNote`), which always starts with the literal
//     ` (the plan declared "` and is always the string's last, most deeply
//     nested clause — split off first, into the detail half, never the
//     headline.
//   - Most remaining reasons put the answer to "why does this need a human"
//     before an em dash (" — ") and elaborate after it — e.g. gate.go's hard
//     safety-floor reason, "blocked from auto-approval by a hard safety
//     floor: risk=high and reversible=false — high-risk, irreversible
//     actions are never auto-approved regardless of confidence or policy",
//     is exactly BACKLOG D11's own quoted example of the unreadable text,
//     and splits into precisely the headline the ticket asked for.
//   - A reason with neither marker (e.g. "confidence 0.32 is below this
//     policy's auto-approve threshold 0.40") is already one short clause;
//     it renders whole, with no expand control, because an empty disclosure
//     is worse than none.
function splitGateReason(reason: string): { headline: string; detail: string | null } {
  const FLOOR_MARKER = ' (the plan declared '
  const floorIdx = reason.indexOf(FLOOR_MARKER)
  const withoutFloor = floorIdx === -1 ? reason : reason.slice(0, floorIdx)
  // floorIdx points at the marker's leading space; +2 skips that space and
  // the parenthetical's own opening "(" to land on its first real character,
  // and the parenthetical is always the string's own last character ")"
  // (gate.go appends floorNote via `...%s`, always at the end).
  const floorNote = floorIdx === -1 ? '' : reason.slice(floorIdx + 2, reason.length - 1)

  const DASH = ' — '
  const dashIdx = withoutFloor.indexOf(DASH)
  const headline = dashIdx === -1 ? withoutFloor : withoutFloor.slice(0, dashIdx)
  const elaboration = dashIdx === -1 ? '' : withoutFloor.slice(dashIdx + DASH.length)

  // Joined with ". ", not a bare space: elaboration and floorNote are each
  // already a complete clause on their own (verified against a real live
  // row's gate reason — a bare-space join reads as one run-on sentence,
  // "...or policy the plan declared..."), and floorNote's own leading "the"
  // is capitalised to open its own sentence rather than continuing the one
  // before it. Still the backend's own words, only repunctuated for the
  // seam between two clauses this function itself introduced by splitting.
  const detailParts = [elaboration, floorNote]
    .filter((part) => part !== '')
    .map((part, i) => (i === 0 ? part : part.charAt(0).toUpperCase() + part.slice(1)))
  return { headline, detail: detailParts.length > 0 ? detailParts.join('. ') : null }
}

// BACKLOG D11 #4: "what happens if I do nothing" was absent entirely, and it
// is the second question anyone asks. Verified against the actual state
// machine, not invented (internal/api/approvals.go's own doc comment;
// internal/orchestrator/approvalwatch.go and escalation.go):
//
//   - Reject always sets the incident to Dismissed, a real, terminal
//     decision — but not a permanent fix if the fault recurs, since
//     dismissing a plan never mutes the detector that opened it.
//   - Leaving a NeedsApproval/Blocked plan pending does nothing on its own:
//     ARGUS never auto-approves past that gate, and AwaitingApproval never
//     expires — but it does not go quiet either. ApprovalSweeper re-notifies
//     at 48 hours, then 5 days, then 12 days, then every week after that
//     (escalation.go's escalationTiers/escalationRepeatInterval), each
//     notice worded more urgently than the last, for as long as it waits.
//
// gateOutcome === 'AutoApprove' is the one case that CANNOT share that same
// "it never auto-approves" sentence — this exact row can still be sitting
// here (AwaitingApproval routes an AutoApprove verdict here exactly like a
// NeedsApproval one, per internal/api/unattended.go's own comment), and a
// separate, opt-in-per-namespace sweeper (RunUnattendedExecutor) picks up
// precisely `gate_outcome = 'AutoApprove'` rows here and executes them with
// no human at all. Asserting "it never auto-approves" for this row would be
// BACKLOG D11 #1's own defect in new words — a screen stating something the
// deterministic backend can contradict. This item carries no field saying
// whether unattended execution is actually enabled for its own cluster's
// namespace (that's a Settings-page fact, not a per-plan one), so this is
// hedged rather than asserted either way.
function declineOrIgnoreNote(gateOutcome: string): string {
  const declineSentence =
    'If you decline: the incident is dismissed — if the underlying fault is still there, its detector opens a ' +
    "new incident, since dismissing this plan doesn't mute detection. "
  if (gateOutcome === 'AutoApprove') {
    return (
      declineSentence +
      'If you leave it pending: this plan is eligible for unattended execution — ARGUS may execute it ' +
      "automatically with no further action if this cluster's namespace allows unattended execution; if it " +
      'does not, this waits here exactly like any other pending plan, and ARGUS re-notifies at 48 hours, then ' +
      '5 days, then 12 days, then weekly after that.'
    )
  }
  return (
    declineSentence +
    'If you leave it pending: nothing executes on its own — ARGUS re-notifies at 48 hours, then 5 days, then ' +
    '12 days, then weekly after that, for as long as it waits here; it never auto-approves and never expires.'
  )
}

// WHICH CHANNEL THE FIX TAKES, and the sentence that has to accompany the
// badge (index.css: "Always paired in the markup with the sentence saying why
// that route and not another — the badge alone is not the feature").
//
// Derived from the action type, because that is honestly all a route is today:
// BACKLOG F17 is the work that makes the route a decision code takes BEFORE
// the model proposes, at which point this reads whatever field that lands on
// instead. Until then, claiming anything about WHY this object took this route
// ("it is declared in Git") would be asserting something nothing verified — so
// both sentences state only what approving actually does, which is verified.
function routeOf(plan: RemediationPlan): { label: string; className: string; sentence: string } {
  if (plan.actionType === 'OpenPR') {
    return {
      label: 'Pull request',
      className: 'route-badge route-badge-blue',
      sentence:
        'Approving opens a pull request; the cluster changes only once it merges and the GitOps controller syncs it.',
    }
  }
  return {
    label: 'In-place',
    className: 'route-badge',
    sentence: `${inPlaceApproveEffect(plan.actionType)}; nothing is written to Git.`,
  }
}

// What approving an in-place plan does to the cluster, by action type. "Patches
// the live object" was said of every plan, including a DeleteResource whose
// approval removes the object outright — the one case where the wrong verb
// matters most.
export function inPlaceApproveEffect(actionType: string): string {
  switch (actionType) {
    case 'DeleteResource':
      return 'Approving deletes this object from the cluster now'
    case 'CreateResource':
      return 'Approving creates this object in the cluster now'
    case 'RestartPod':
      return 'Approving restarts the workload’s pods in this cluster now'
    default:
      return 'Approving patches the live object in this cluster now'
  }
}

// planChange/PlanChange now live in utils/incidents.ts (BACKLOG D8 A4/A7):
// IncidentDetailPage's stage 3 needs the identical before/after mapping for
// its own `.diff-pair`, and a component module is the wrong home for a
// function two screens share (see that file's own comment, and
// incidentLifecycle.ts's identical reasoning for the lifecycle rail).

// Said out loud rather than left to the absence of a red line: a lone green
// line is a diff convention for "this field is being added", which is a claim
// this page cannot make.
//
// `canPreflight` is passed rather than re-derived so the sentence can only
// point at the Preview control on an entry that actually renders one — an
// already-decided or superseded entry has no rehearsal button to send anyone to.
function beforeUnknownCaption(plan: RemediationPlan, canPreflight: boolean): string {
  if (plan.actionType === 'OpenPR') {
    return 'Only the new value is shown — the current one is whatever the manifest holds when the pull request is prepared.'
  }
  return canPreflight
    ? 'Only the new value is shown — the current one is read off the live object at execution. Preview change asks the cluster for it now.'
    : 'Only the new value is shown — the current one is read off the live object at execution.'
}

// WHAT WAS ALREADY VERIFIED, and — the part that matters — what was not.
// index.css's note on `.verification-chip-neutral` is the rule being followed
// here: the thing ARGUS cannot assert sits beside the thing it can, same row,
// same size, same weight. Both entries are facts carried by the payload or
// guaranteed by the execution path, never inferences about this plan.
function checksFor(plan: RemediationPlan): { verified: boolean; label: string; title: string }[] {
  return [
    plan.reversible
      ? {
          verified: true,
          label: 'Reversible',
          title:
            "ARGUS reads the object's current values immediately before it changes them and records them as the compensating action, so this can be undone from the incident afterwards.",
        }
      : {
          verified: false,
          label: 'No undo',
          title:
            'This action type has no compensating action — a restart cannot be un-restarted, and nothing here can put it back.',
        },
    plan.actionType === 'OpenPR'
      ? {
          verified: false,
          label: 'Not applied until merge',
          title:
            'Approving only opens the pull request. Whether the change reaches the cluster depends on the review and on the GitOps controller syncing it.',
        }
      : {
          verified: true,
          label: 'Refuses if the object has changed',
          title:
            "The plan is signed and carries the target's live resourceVersion; the agent re-verifies the signature and the precondition before it patches, so a plan derived from a stale view of the object fails instead of applying.",
        },
  ]
}

// The two marks a verification chip can wear, local to this file rather than
// added to components/icons.tsx. `stroke="currentColor"` is mandatory, not
// stylistic: `.verification-chip-neutral` recolours by setting `color`, so a
// hardcoded stroke would leave an unverified chip wearing a green tick.
function CheckMark() {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="m4 12.5 5 5L20 6.5" />
    </svg>
  )
}

function DashMark() {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.6"
      strokeLinecap="round"
      aria-hidden="true"
    >
      <path d="M5 12h14" />
    </svg>
  )
}

function VerificationChip({
  verified,
  title,
  children,
}: {
  verified: boolean
  title: string
  children: ReactNode
}) {
  return (
    <span className={verified ? 'verification-chip' : 'verification-chip verification-chip-neutral'} title={title}>
      {verified ? <CheckMark /> : <DashMark />}
      {children}
    </span>
  )
}

// Reject requires a reason (internal/api/approvals.go rejects an empty one
// with 400) — a small inline form rather than a native window.confirm,
// since a confirm dialog has no text-input affordance. Mirrors
// UsersPage.tsx's AddGrantForm's "click to reveal an inline form" pattern.
function RejectForm({
  incidentId,
  disabledReason,
  onDone,
}: {
  incidentId: string
  disabledReason?: string
  onDone: () => void
}) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const [reason, setReason] = useState('')
  // Several of these forms can be open at once (one per queue row), so the
  // label/input pairing needs a per-instance id, not a hardcoded one.
  const reasonId = useId()

  const mutation = useMutation({
    mutationFn: () => rejectIncident(incidentId, reason, accessToken!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['approvals'] })
      // Rejecting now moves the incident's state (AwaitingApproval ->
      // PlanRejected, internal/api/approvals.go), and this card is mounted on
      // the incident detail page as well as in the queue. Without this the
      // screen the operator is looking at keeps its stale "Awaiting approval"
      // badge and its live Approve button until the 5s poll catches up —
      // offering an action the API would now refuse. Same ['incidents'] prefix
      // the approve mutation below already invalidates, for the same reason.
      queryClient.invalidateQueries({ queryKey: ['incidents'] })
      onDone()
    },
  })

  return (
    <form
      className="inline-grant-form"
      onSubmit={(e) => {
        e.preventDefault()
        mutation.mutate()
      }}
    >
      {/* A real <label>, not just a placeholder. This is a required field on
          a destructive, audited action, and a placeholder is not an
          accessible name: it isn't announced as a label by every screen
          reader, and it disappears the moment the first character is typed,
          taking the only description of the field with it. Visually hidden
          rather than shown, so the inline row's layout is unchanged — the
          placeholder still carries the same wording on screen. `required`
          matches what the submit button already enforces (it stays disabled
          on an empty/whitespace reason), so the constraint is now announced,
          not just implied. */}
      <label className="visually-hidden" htmlFor={reasonId}>
        Reason for rejecting this remediation (required)
      </label>
      <input
        id={reasonId}
        type="text"
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        placeholder="Reason for rejecting (required)"
        required
        disabled={!!disabledReason || mutation.isPending}
        autoFocus
      />
      <button
        type="submit"
        className="danger"
        disabled={!!disabledReason || mutation.isPending || reason.trim() === ''}
        title={disabledReason}
      >
        {mutation.isPending ? 'Rejecting…' : 'Confirm reject'}
      </button>
      {/* BACKLOG.md D9 U4: `title` above is unreachable by keyboard/touch —
          RepositoryChangePanel's own comment names this rule (lld/11 §6). */}
      {disabledReason && <p className="field-hint">{disabledReason}</p>}
      <button type="button" className="secondary" onClick={onDone} disabled={mutation.isPending}>
        Cancel
      </button>
      {mutation.isError && (
        <p className="form-error inline-error" role="alert">
          {mutation.error instanceof ApiError ? mutation.error.message : 'Could not reject.'}
        </p>
      )}
    </form>
  )
}

// ApproveOverrides mirrors the approve endpoint's optional body. Both flags
// default to absent, and absent means "refuse" — a guardrail whose default is to
// decline needs nothing sent to express that.
//
// confirmationToken is part of this type rather than only of api/client's
// wider parameter type, because every override that gets built carries one and
// a type that omitted it would let a future edit drop the token silently:
// the call still compiles, the request still goes out, and the guardrail just
// refuses forever with no compile error to say why.
type ApproveOverrides = {
  confirmScaleFromZero?: boolean
  confirmGitOpsManaged?: boolean
  confirmationToken?: string
}

// Refusal is which guardrail declined, plus the hub's own wording for it. The
// message is never composed here: the hub read the live cluster state and knows
// what it found (which release owns the object, what the replica count is), so
// it writes the sentence and this only decides which question to ask.
type RefusalKind = 'scaleFromZero' | 'gitOpsManaged'
// confirmationToken is what makes this an actual proof of confirmation rather
// than a boolean either side could set: the hub only accepts the override
// when this exact token, minted by this exact refusal, comes back.
type Refusal = { kind: RefusalKind; message: string; confirmationToken: string }

// One entry per guardrail, deliberately NOT collapsed into a single generic
// "Confirm and proceed" button. The two decisions are unrelated — an operator
// who intends to turn a switched-off workload back on has not thereby agreed to
// have their fix reverted by the next Helm upgrade — so a shared button would
// let confirming one waive the other, which is exactly what the separate
// problem types on the server exist to prevent.
const REFUSALS: Record<
  RefusalKind,
  {
    // A function of the refusal being confirmed, not a static value: the
    // override is worthless without THIS refusal's own confirmationToken
    // riding along, so there is no static ApproveOverrides to hand out here.
    overrides: (r: Refusal) => ApproveOverrides
    confirmLabel: string
    pendingLabel: string
    declineLabel: string
    confirmTitle: string
  }
> = {
  scaleFromZero: {
    overrides: (r) => ({ confirmScaleFromZero: true, confirmationToken: r.confirmationToken }),
    confirmLabel: 'Yes — turn it back on',
    pendingLabel: 'Scaling back up…',
    declineLabel: 'Leave it switched off',
    confirmTitle: 'Confirm that you intend to turn this switched-off workload back on, and execute the scale now',
  },
  gitOpsManaged: {
    overrides: (r) => ({ confirmGitOpsManaged: true, confirmationToken: r.confirmationToken }),
    confirmLabel: 'Apply anyway — I will fix the source',
    pendingLabel: 'Applying…',
    declineLabel: 'Cancel — fix the source instead',
    confirmTitle:
      'Confirm that you accept this change is a stop-gap and will be reverted unless you also change the chart or manifest it comes from',
  },
}

// refusalFromError maps a refusal to its guardrail, and everything else to null.
// Null is what makes the row fall back to its plain error line — including a
// CONFIRMED attempt that then failed for an unrelated reason (cluster
// disconnected, absurd-jump bound, lost approve race), which must never be
// re-offered as "confirm again".
function refusalFromError(error: unknown): Refusal | null {
  if (!(error instanceof ApiError)) return null
  const message = error.detail || error.message
  const confirmationToken = error.confirmationToken
  if (error.type === PROBLEM_SCALE_FROM_ZERO_REFUSED) return { kind: 'scaleFromZero', message, confirmationToken }
  if (error.type === PROBLEM_GITOPS_MANAGED_REFUSED) return { kind: 'gitOpsManaged', message, confirmationToken }
  return null
}

// THE SCALE-FROM-ZERO CONFIRMATION, and why it is shaped as a retry rather
// than a checkbox.
//
// The hub refuses to scale a workload up from a live count of 0 replicas
// without an explicit human confirmation (internal/api/remediation_exec.go's
// checkScaleFromZero: a workload at zero is almost always switched off on
// purpose). Two honest UIs were possible for that confirmation, and this page
// takes the second:
//
//  1. A checkbox rendered on every ScaleDeployment row, worded conditionally
//     ("if this workload is currently at zero replicas…") — because the
//     browser genuinely cannot know the live replica count; only the hub, at
//     execution time, does. Rejected: it puts a speculative, usually-
//     irrelevant scary checkbox on every scale approval, which is exactly how
//     an operator learns to tick it by reflex before knowing whether it
//     applies. A guardrail that gets pre-armed on rows it doesn't apply to
//     stops being a guardrail.
//  2. This one: approve normally, and if the hub refuses, show ITS refusal
//     (which is authoritative — it just read spec.replicas from the API
//     server) and offer one separate, deliberate "yes, turn it back on"
//     button. The confirmation is therefore impossible to send before a
//     refusal exists, cannot be pre-ticked, states a fact rather than a
//     hypothetical, and costs the extra click only in the case that actually
//     warrants one.
//
// The refusal is recognized by its problem `type`, never by matching the
// message text, and the message shown is the hub's own words rather than a
// paraphrase this file would have to keep in sync.
/** The first clause of a hub sentence — "lab-dev has no remediation agent
 *  connected" — for a one-line statement; the whole sentence stays one
 *  click away beside it. Cut only at the hub's own punctuation. */
function firstClause(sentence: string): string {
  const m = /^(.*?)(?:, so |\. |; )/.exec(sentence)
  return (m ? m[1] : sentence).replace(/\.$/, '')
}

function ApprovalActions({ item }: { item: ApprovalQueueItem }) {
  const { accessToken } = useAuth()
  const queryClient = useQueryClient()
  const canApprove = useHasCapability(CAP_REMEDIATION_APPROVE)
  const canReject = useHasCapability(CAP_REMEDIATION_REJECT)
  const [rejecting, setRejecting] = useState(false)
  // The hub's own refusal text, when it declined to scale this workload up
  // from zero. Non-null is what switches this row into the confirm step; it is
  // per-row component state that dies with the row, so nothing about it can
  // survive into a later approval of anything else.
  const [refusal, setRefusal] = useState<Refusal | null>(null)
  // The confirm step for a high-risk or irreversible in-place plan — see
  // needsApproveConfirmation below. Per-row and dies with the row, like
  // `refusal`, so a confirmation can never carry over to another plan.
  const [confirming, setConfirming] = useState(false)

  const approveMutation = useMutation({
    // The flag is a mutation ARGUMENT rather than component state on purpose:
    // it is a property of one specific submission, so there is no persistent
    // "confirmed" bit anywhere that a later click could accidentally reuse.
    mutationFn: (overrides: ApproveOverrides) => approveIncident(item.incidentId, accessToken!, overrides),
    onError: (error) => {
      // Any other failure clears the confirm step and falls back to the plain
      // error line below — including a CONFIRMED attempt that then failed for
      // an unrelated reason (cluster disconnected, absurd-jump bound, lost
      // approve race), which must not be re-offered as "confirm again".
      setRefusal(refusalFromError(error))
    },
    onSuccess: () => {
      setRefusal(null)
      queryClient.invalidateQueries({ queryKey: ['approvals'] })
      // A ScaleDeployment/RestartPod approval now genuinely moves the
      // incident's state (AwaitingApproval -> Executing -> Validating/Failed)
      // — unlike the old execution-free behavior. Invalidating the
      // ['incidents'] prefix catches both IncidentsPage's list query
      // (['incidents', {...filters}]) and IncidentDetailPage's own
      // (['incidents', id]) — react-query matches by key prefix — rather
      // than either view keeping a stale AwaitingApproval until its own
      // polling interval happens to catch up.
      queryClient.invalidateQueries({ queryKey: ['incidents'] })
    },
  })

  // Checked BEFORE alreadyApproved: a superseded plan is the more specific and
  // more consequential fact, and it is the one that changes what the operator
  // should do next.
  if (item.supersededByUrl) {
    return (
      <div className="approval-superseded">
        <span
          className="badge badge-blue"
          title="ARGUS has proposed the durable fix at the object's source; approving this in-place plan is refused"
        >
          Superseded by a pull request
        </span>
        <p className="field-hint">
          The fix for this belongs in Git, and ARGUS has already proposed it:{' '}
          <a href={item.supersededByUrl} target="_blank" rel="noreferrer">
            {item.supersededByUrl.replace(/^https:\/\/(www\.)?/, '')}
          </a>
          . The in-place plan above was derived from the cluster as it was before that, so applying it
          now could undo the source fix rather than repeat it. Review the pull request; if it is wrong,
          re-analyse this incident so a new plan is derived from the current state.
        </p>
      </div>
    )
  }

  if (item.alreadyApproved) {
    // Only reachable for OpenPR today: approving it opens a pull request and
    // moves the incident to AwaitingMerge, not off this queue — GET
    // /approvals lists AwaitingMerge alongside AwaitingApproval (see its own
    // comment) specifically so the team can still see it here. A
    // ScaleDeployment/RestartPod plan that successfully commits to executing
    // moves the incident off AwaitingApproval immediately, so it leaves this
    // queue (and this branch) before a second render could ever show it here.
    return (
      <span
        className="badge badge-green"
        title="The pull request is open — once it merges and the GitOps controller syncs it, ARGUS moves this to validation on its own"
      >
        Approved · pull request open
      </span>
    )
  }

  if (rejecting) {
    return (
      <RejectForm
        incidentId={item.incidentId}
        disabledReason={canReject ? undefined : `Missing capability: ${CAP_REMEDIATION_REJECT}`}
        onDone={() => setRejecting(false)}
      />
    )
  }

  if (refusal) {
    // Deliberately NOT a pre-checked checkbox next to the original Approve
    // button: the operator is being asked a question they have now been given
    // the answer to (this workload is off), and the only way through is a
    // button whose label says what it does. `danger` styling because this
    // reverses a decision somebody made on purpose.
    return (
      <div className="approval-actions">
        <p className="banner banner-warning" role="alert">
          {refusal.message}
        </p>
        <div className="approval-actions">
          <button
            type="button"
            className="danger"
            disabled={!canApprove || approveMutation.isPending}
            title={REFUSALS[refusal.kind].confirmTitle}
            onClick={() => approveMutation.mutate(REFUSALS[refusal.kind].overrides(refusal))}
          >
            {approveMutation.isPending ? REFUSALS[refusal.kind].pendingLabel : REFUSALS[refusal.kind].confirmLabel}
          </button>
          <button
            type="button"
            className="secondary"
            disabled={approveMutation.isPending}
            onClick={() => {
              // reset() as well as clearing the banner: without it the row
              // falls back to the normal buttons with the mutation still in
              // its error state, and the generic error line would repeat the
              // refusal the operator just declined to act on.
              setRefusal(null)
              approveMutation.reset()
            }}
          >
            {REFUSALS[refusal.kind].declineLabel}
          </button>
        </div>
        {/* BACKLOG.md D9 U4: `title` above never carries the capability
            reason at all here (it's always confirmTitle, regardless of
            canApprove) — this is the only visible statement of why the
            confirm button is disabled for a viewer without
            remediation:approve. */}
        {!canApprove && <p className="field-hint">Missing capability: {CAP_REMEDIATION_APPROVE}</p>}
      </div>
    )
  }

  const executesOnApprove = item.plan.actionType !== 'OpenPR'
  // THE SECOND GATE — "may this plan execute" — as the hub computed it
  // (GET /approvals' executionBlockedReason: the cluster has no remediation
  // agent connected). Distinct from the capability gate above it and worded
  // as a fact about the cluster, never as a permissions problem; rendered
  // beside the disabled button rather than in its title alone.
  const blockedReason = executesOnApprove ? item.executionBlockedReason : undefined
  const confirmFirst = needsApproveConfirmation(item.plan)

  return (
    <div className="approval-actions">
      {confirming && (
        <ApproveConfirmDialog
          item={item}
          pending={approveMutation.isPending}
          onConfirm={() => approveMutation.mutate({}, { onSettled: () => setConfirming(false) })}
          onCancel={() => setConfirming(false)}
        />
      )}
      <button
        type="button"
        disabled={!canApprove || approveMutation.isPending || !!blockedReason}
        title={
          !canApprove
            ? `Missing capability: ${CAP_REMEDIATION_APPROVE}`
            : blockedReason
              ? `Cannot execute: ${blockedReason}`
              : executesOnApprove
                ? 'Approve and execute this plan against the cluster now'
                : 'Approve and open a pull request against the repository now'
        }
        // Never confirmed on a first attempt for a guardrail: if this target
        // is switched off, the hub says so and the confirm step above asks.
        // A high-risk or irreversible plan asks first, here, instead.
        onClick={() => (confirmFirst ? setConfirming(true) : approveMutation.mutate({}))}
      >
        {approveMutation.isPending
          ? executesOnApprove
            ? 'Approving and executing…'
            : 'Approving and opening pull request…'
          : 'Approve'}
      </button>
      <button
        type="button"
        className="secondary"
        disabled={!canReject}
        title={canReject ? 'Reject this plan and dismiss the incident' : `Missing capability: ${CAP_REMEDIATION_REJECT}`}
        onClick={() => setRejecting(true)}
      >
        Reject
      </button>
      {/* BACKLOG.md D9 U4: the two `title`s above are unreachable by
          keyboard/touch (lld/11 §6, RepositoryChangePanel's own comment) —
          this is the highest-stakes control pair in the product, so it gets
          the visible line rather than relying on hover alone. Only one line
          even when BOTH capabilities are missing: repeating "Missing
          capability: X" twice reads as two problems when it is one viewer
          lacking two related grants. */}
      {blockedReason && (
        <p className="approval-blocked" role="note">
          <span className="approval-blocked-mark" aria-hidden="true">✕</span>
          <span>
            <strong>Cannot execute yet</strong> — {firstClause(blockedReason)}{' '}
            <HelpTip label="Why it cannot execute" text={blockedReason} />
          </span>
        </p>
      )}
      {(!canApprove || !canReject) && (
        <p className="field-hint">
          You do not hold{' '}
          {[!canApprove && CAP_REMEDIATION_APPROVE, !canReject && CAP_REMEDIATION_REJECT].filter(Boolean).join(', ')}{' '}
          on this cluster, so {!canApprove && !canReject ? 'neither decision is' : 'that decision is not'} available to
          you here.
        </p>
      )}
      {approveMutation.isError && (
        <p className="form-error inline-error" role="alert">
          {approveMutation.error instanceof ApiError ? approveMutation.error.message : 'Could not approve.'}
        </p>
      )}
      {approveMutation.isSuccess && <p className="field-hint approval-success-note">{approveMutation.data.message}</p>}
    </div>
  )
}

// THE DECISION PAIR FOR A VIEWER WITHOUT remediation:approve, on the incident
// page. GET /approvals requires remediation:approve, so for this viewer there
// is no queue item to mount ApprovalDecisionCard from — but the controls still
// render, disabled-not-hidden, each naming the capability ITS route needs:
// approve needs remediation:approve, reject needs remediation:reject (a custom
// role can hold the second without the first, and then Reject works here).
// No link to /approvals: that page needs the capability this viewer lacks.
export function ApprovalActionsWithoutQueue({ incidentId }: { incidentId: string }) {
  const canApprove = useHasCapability(CAP_REMEDIATION_APPROVE)
  const canReject = useHasCapability(CAP_REMEDIATION_REJECT)
  const [rejecting, setRejecting] = useState(false)
  if (rejecting && canReject) {
    return <RejectForm incidentId={incidentId} onDone={() => setRejecting(false)} />
  }
  const missing = [!canApprove && CAP_REMEDIATION_APPROVE, !canReject && CAP_REMEDIATION_REJECT].filter(Boolean)
  return (
    <div className="approval-actions">
      <button type="button" disabled={!canApprove} title={canApprove ? undefined : `Missing capability: ${CAP_REMEDIATION_APPROVE}`}>
        Approve
      </button>
      <button
        type="button"
        className="secondary"
        disabled={!canReject}
        title={canReject ? 'Reject this plan and dismiss the incident' : `Missing capability: ${CAP_REMEDIATION_REJECT}`}
        onClick={() => setRejecting(true)}
      >
        Reject
      </button>
      {missing.length > 0 && (
        <p className="field-hint">
          You do not hold {missing.join(', ')} on this cluster, so{' '}
          {missing.length === 2 ? 'neither decision is' : 'that decision is not'} available to you here. Someone who
          holds {CAP_REMEDIATION_APPROVE} can decide it from the approval queue.
        </p>
      )}
    </div>
  )
}

// WHICH APPROVALS ASK "ARE YOU SURE" FIRST. A high-risk or irreversible
// in-place plan: approving it executes against a live cluster immediately,
// and for an irreversible one (DeleteResource, …) there is no rollback, so one
// stray click must not be enough. Low- and medium-risk reversible plans stay
// single-click — that was the design intent of this card (the whole decision
// is laid out above the button, and ARGUS can roll those back), and a confirm
// on every approval is how operators learn to click through confirms. OpenPR
// never asks: it opens a pull request, which is itself reviewed before merge.
export function needsApproveConfirmation(plan: RemediationPlan): boolean {
  if (plan.actionType === 'OpenPR') return false
  return plan.effectiveRiskLevel === 'high' || !plan.reversible
}

// The verb an approver is about to authorise, by action type — restated in the
// confirm dialog so "Approve" never stands in for what will actually happen.
export function approveVerb(actionType: string): string {
  switch (actionType) {
    case 'DeleteResource':
      return 'Delete'
    case 'ScaleDeployment':
      return 'Scale'
    case 'RestartPod':
      return 'Restart'
    case 'CreateResource':
      return 'Create'
    case 'RevertContainerImage':
      return 'Revert the image of'
    case 'AnnotateResource':
      return 'Annotate'
    case 'LabelResource':
      return 'Label'
    default:
      return 'Patch'
  }
}

function ApproveConfirmDialog({
  item,
  pending,
  onConfirm,
  onCancel,
}: {
  item: ApprovalQueueItem
  pending: boolean
  onConfirm: () => void
  onCancel: () => void
}) {
  const plan = item.plan
  const verb = approveVerb(plan.actionType)
  const kind = plan.targetGvk.split(/[,=/]/).pop()?.trim() || plan.targetGvk
  const target = `${plan.targetNamespace ? `${plan.targetNamespace}/` : ''}${plan.targetName}`
  return (
    <Dialog title={`${verb} ${kind} ${plan.targetName}?`} onClose={onCancel}>
      <p>
        Approving executes this now: <strong>{verb.toLowerCase()} {kind} {target}</strong> on{' '}
        <strong>{item.clusterDisplayName}</strong>.
      </p>
      <p>{plan.summary}</p>
      {!plan.reversible ? (
        <p className="banner banner-warning">This cannot be undone — ARGUS has no rollback for it.</p>
      ) : (
        <p className="field-hint">ARGUS rates this {plan.effectiveRiskLevel} risk.</p>
      )}
      <div className="triage-actions">
        <button type="button" className="danger" onClick={onConfirm} disabled={pending}>
          {pending ? 'Approving and executing…' : `Approve and ${verb.toLowerCase()}`}
        </button>
        <button type="button" className="secondary" onClick={onCancel} disabled={pending}>
          Cancel
        </button>
      </div>
    </Dialog>
  )
}

// PROJECT.md D12 / BACKLOG.md B172: the evidence-quality signal, in the
// collapsed view where an approver actually decides — never buried behind
// the "Why ARGUS proposed this" disclosure below. Mirrors IncidentDetailPage's
// own ToolCallChip palette exactly (badge-red/amber/gray/green, the same four
// words) so the same fact reads identically wherever it appears.
//
// This is the pairing the confidence badge above needs: confidence is the
// model's own UNCHECKED self-report, and evidence quality is the one part of
// "how much should I trust this" ARGUS actually verified — by re-checking
// every cited tool call against its own record of what it served (PROJECT.md
// B151, internal/llm.crossCheckCausalChain). It counts the SAME per-citation
// verdicts CausalChainDisclosure renders per step below; it never computes a
// second, independent quality score.
//
// Always renders something — never nothing, and never a fabricated "0 of 0".
// Three honest "nothing to grade" cases, each stated in its own words rather
// than folded into a misleading count:
//   - no cited tool calls at all ("No evidence cited")
//   - a hub-observed chain, where every call is real by construction and
//     there is nothing for ARGUS to cross-check ("Hub-observed") — this is
//     not a gap, it is a stronger evidentiary status than a checked citation,
//     and is worded as one
//   - a self-reported chain stored before PROJECT.md B151's cross-check
//     existed, which carries citations but no verdicts ("Evidence quality
//     not recorded")
// "contradicted" wins over every other state in the counted case regardless
// of how many citations corroborated cleanly — the whole point of PROJECT.md
// D12's brief: a contradicted citation must be impossible to approve past
// without noticing.
const CITATION_VERDICT_STYLE: Record<'contradicted' | 'unverified' | 'unchecked' | 'corroborated', { className: string; title: string }> = {
  contradicted: {
    className: 'badge badge-red',
    title:
      'At least one cited tool-call value does NOT match what that call actually returned — treat this analysis’s stated values as unreliable. See "Why ARGUS proposed this" below for which step.',
  },
  unverified: {
    className: 'badge badge-amber',
    title:
      'At least one cited tool call has no matching record of ever being served — shown as reported, not as evidence. See "Why ARGUS proposed this" below for which step.',
  },
  unchecked: {
    className: 'badge badge-gray',
    title: 'Every cited tool call happened for real, but none of them stated a specific value ARGUS could check.',
  },
  corroborated: {
    className: 'badge badge-green',
    title: 'Every cited tool call happened for real, and every specific value it cited matched the real result.',
  },
}
// CausalChainDisclosure's own per-step badges below key off this same map, so
// the two can never drift onto separate palettes for the same four words.
const CORROBORATION_BADGE = CITATION_VERDICT_STYLE

function evidenceQualitySummary(item: ApprovalQueueItem): { text: string; className: string; title: string } {
  const citations = item.causalChain.flatMap((step) => step.toolCalls)
  if (citations.length === 0) {
    return {
      text: 'No evidence cited',
      className: 'badge badge-gray',
      title: 'This analysis recorded no tool calls to check the confidence figure against.',
    }
  }
  if (item.causalChainProvenance !== 'self-reported') {
    return {
      text: 'Hub-observed',
      className: 'badge badge-gray',
      title:
        'ARGUS observed every one of these tool calls directly, in real time, as this investigation ran — there is nothing here for it to cross-check, since it dispatched every call itself.',
    }
  }
  const graded = citations.filter(
    (call): call is typeof call & { corroborated: NonNullable<typeof call.corroborated> } => call.corroborated != null,
  )
  if (graded.length === 0) {
    return {
      text: 'Evidence quality not recorded',
      className: 'badge badge-gray',
      title: 'This analysis predates per-citation corroboration checking, so no verdict is available for its cited tool calls.',
    }
  }
  const total = graded.length
  const plural = total === 1 ? '' : 's'
  const counts: Record<'contradicted' | 'unverified' | 'unchecked' | 'corroborated', number> = {
    contradicted: 0,
    unverified: 0,
    unchecked: 0,
    corroborated: 0,
  }
  for (const call of graded) counts[call.corroborated]++

  if (counts.contradicted > 0) {
    return { text: `${counts.contradicted} of ${total} citation${plural} contradicted`, ...CITATION_VERDICT_STYLE.contradicted }
  }
  if (counts.unverified > 0) {
    return { text: `${counts.unverified} of ${total} citation${plural} unverified`, ...CITATION_VERDICT_STYLE.unverified }
  }
  if (counts.corroborated > 0) {
    return {
      text: `${counts.corroborated} of ${total} citation${plural} corroborated`,
      className: CITATION_VERDICT_STYLE.corroborated.className,
      title:
        counts.corroborated === total
          ? CITATION_VERDICT_STYLE.corroborated.title
          : `${counts.corroborated} of ${total} cited tool calls happened for real and matched what they claimed; the rest stated nothing checkable.`,
    }
  }
  // Every graded citation is 'unchecked': real calls, nothing stated to check
  // them against. Never phrased as "0 of N corroborated" — that reads as a
  // failed check where none was possible, the exact fabricated-negative this
  // function exists to avoid.
  return { text: `${total} citation${plural} verified, none checkable`, ...CITATION_VERDICT_STYLE.unchecked }
}

function EvidenceQualityBadge({ item }: { item: ApprovalQueueItem }) {
  const summary = evidenceQualitySummary(item)
  return (
    <span className={summary.className} title={summary.title}>
      {summary.text}
    </span>
  )
}

// WHAT SUPPORTS THIS, and what ARGUS considered and ruled out — PROJECT.md
// D12's answer to "what evidence supports it" and "what did ARGUS decide NOT
// to do," both previously unreachable from this card at all (only a plain
// two-line-clamped rootCauseStatement, no path to the reasoning behind it,
// short of navigating away to the incident detail page's own "Why?"
// section). Collapsed by default, same `<details>` convention this card
// already uses for "Full gate reasoning" just below it — not a new pattern,
// and not a duplicate of ToolCallChip's own richer, per-call args/result
// drill-down (that stays IncidentDetailPage's own job): this is the
// decision-relevant summary, one line per step.
function CausalChainDisclosure({ item }: { item: ApprovalQueueItem }) {
  if (item.causalChain.length === 0 && item.ruledOut.length === 0) return null
  return (
    <details className="approval-gate-detail">
      <summary>Why ARGUS proposed this ({item.causalChain.length} step{item.causalChain.length === 1 ? '' : 's'})</summary>
      {item.causalChain.map((step) => (
        <p key={step.step} className="field-hint">
          <strong>{step.hypothesis}</strong> — {step.finding}
          {step.toolCalls
            .filter((call): call is typeof call & { corroborated: NonNullable<typeof call.corroborated> } =>
              item.causalChainProvenance === 'self-reported' && call.corroborated != null,
            )
            .map((call, i) => (
              <span key={i} className={CORROBORATION_BADGE[call.corroborated].className} title={CORROBORATION_BADGE[call.corroborated].title}>
                {' '}
                {call.tool}: {call.corroborated}
              </span>
            ))}
        </p>
      ))}
      {item.ruledOut.length > 0 && (
        <>
          <p className="field-hint">
            <strong>Considered and ruled out:</strong>
          </p>
          {item.ruledOut.map((r, i) => (
            <p key={i} className="field-hint">
              {r.hypothesis} — {r.reason}
            </p>
          ))}
        </>
      )}
    </details>
  )
}

// WHAT IS BROKEN, for one member of a decision — the object the fix lands
// on, which for a pod-template action is not the object the finding named (a
// CrashLooping Pod's fix is applied to its Deployment). The fingerprint stays
// on the link as its title rather than as the headline: it is a sha256, and a
// 64-character hex string is not an identity a human scans a queue by.
//
// BACKLOG D11 #2: the root-cause statement is a model-written paragraph
// (five to six sentences in the queue the owner reviewed), and used to render
// at full length on every card — a queue is for triage, not diagnosis. It is
// now clamped to two lines (`.approval-member-fault`, the same technique
// `.incident-summary-fault` already uses for an equally long kubelet
// message), which is honest rather than lossy specifically because the full
// statement is never further than the identity link right above it: opening
// the incident renders it in full, alongside the causal chain that produced
// it. `title` carries the whole thing too, as a hover supplement — never the
// only way to reach it, since the click-through is the real, keyboard- and
// touch-reachable path the two-line clamp promises.
function ApprovalMemberIdentity({ item }: { item: ApprovalQueueItem }) {
  const confidence = item.confidence != null ? confidenceBadge(item.confidence) : null
  return (
    <>
      <div className="approval-row-header">
        <div className="identity-block">
          <Link
            className="identity-block-name"
            to={`/incidents/${item.incidentId}`}
            title={`Open the incident · fingerprint ${item.fingerprint}`}
          >
            {item.plan.targetName || 'Unnamed target'}
          </Link>
          <span className="identity-block-kind">
            {item.plan.targetGvk} · <Link to={`/clusters/${item.clusterId}`}>{item.clusterDisplayName}</Link>
            {item.plan.targetNamespace ? `/${item.plan.targetNamespace}` : ''}
          </span>
          {item.rootCauseStatement && (
            <span className="identity-block-fault approval-member-fault" title={item.rootCauseStatement}>
              {item.rootCauseStatement}
            </span>
          )}
        </div>
        {/* The severity word, even though the card's left rule already carries
            the colour: index.css's severity block is explicit that nothing
            reading --sev-fill may carry severity by colour alone. */}
        <SeverityBadge severity={item.severity} />
        {confidence && (
          <span className={confidence.className} title={confidence.title}>
            {confidence.band}
          </span>
        )}
        <EvidenceQualityBadge item={item} />
        {/* The wait is measured from the PLAN, not from the incident's
            firstSeen this used to read. See utils/incidents.ts's
            approvalWaitStartedAt: a fault detected in July whose plan was
            proposed yesterday was showing "Waiting 52d" here, on the one number
            that decides which of these rows an approver opens first. */}
        <ApprovalRowAge item={item} />
      </div>
      <CausalChainDisclosure item={item} />
    </>
  )
}

// WHAT WILL CHANGE, for one member of a decision, plus everything about it
// that is genuinely per-object rather than shared with the rest of its group:
// the plain-language summary, the before/after diff, the rehearsal control,
// and the live Approve/Reject pair — approving one object is still its own
// irreversible act even when it shares a policy judgement with two others.
function ApprovalMemberChange({ item, withActions = true }: { item: ApprovalQueueItem; withActions?: boolean }) {
  const plan = item.plan
  const change = planChange(plan)
  // Derived once: it decides both whether the rehearsal control renders and
  // whether the diff's caption is allowed to point at it.
  const canPreflight = plan.actionType !== 'OpenPR' && !item.alreadyApproved && !item.supersededByUrl

  return (
    <>
      <p className="approval-member-summary">
        <strong>{plan.summary}</strong>
      </p>

      {(change.before !== undefined || change.after !== undefined) && (
        <div className="diff-pair">
          {/* The visually-hidden labels are required by the primitive: its
              −/+ markers are generated content, which is not dependable as an
              announced distinction, and the red/green is not either. */}
          {change.before !== undefined && (
            <div className="diff-pair-before">
              <span className="visually-hidden">Currently: </span>
              {change.before}
            </div>
          )}
          {change.after !== undefined && (
            <div className="diff-pair-after">
              <span className="visually-hidden">
                {change.before === undefined ? 'This change sets: ' : 'Changed to: '}
              </span>
              {change.after}
            </div>
          )}
        </div>
      )}
      {change.after !== undefined && change.before === undefined && (
        <p className="field-hint">{beforeUnknownCaption(plan, canPreflight)}</p>
      )}
      {change.note && <p className="field-hint">{change.note}</p>}

      {/* Deliberately a sibling of ApprovalActions rather than a control inside
          it. ApprovalActions runs a guardrail confirm/decline state machine, and
          the preview must stay completely outside it: previewing is not a step
          in approving, it never sends a confirmation token, and it must not be
          able to disturb a refusal the operator is part-way through answering.
          OpenPR has no cluster patch to rehearse, so it gets no button. */}
      {canPreflight && <PreflightPanel incidentId={item.incidentId} disabledReason={item.executionBlockedReason} />}

      {withActions && <ApprovalActions item={item} />}
    </>
  )
}

// See this file's own top-of-file comment for the `items` contract: one or
// more ApprovalQueueItems that already share one shape (ApprovalsPage's
// groupAndOrderApprovals decides that; `items[0]` is trusted here as the
// shape's representative for everything the grouping key implies is
// identical — action type, route, gate outcome/reason, verification checks).
// `embedded`: the incident page's mount (incident lifecycle redesign,
// 2026-10-12). The queue row stands alone, so it carries "what is broken"
// itself; on the incident page that context is already above the fix, so the
// embedded card is the same change and decision columns without it — one
// decision core, two shells, so the gates and their wording cannot drift.
export function ApprovalDecisionCard({ items, embedded = false }: { items: ApprovalQueueItem[]; embedded?: boolean }) {
  const representative = items[0]
  const plan = representative.plan
  const route = routeOf(plan)
  const { headline, detail } = splitGateReason(plan.gateReason)
  const checks = checksFor(plan)
  const actionLabel = ACTION_TYPE_LABEL[plan.actionType] ?? plan.actionType
  const gateLabel = GATE_OUTCOME_LABEL[plan.gateOutcome] ?? plan.gateOutcome

  // The badge shows the group's WORST case, never its best — see
  // worstRiskLevel's own comment. The "model declared X" note only names a
  // value when every member actually declared the same one; a group whose
  // members disagree shows the (always-safe) enforced badge with no
  // declared-value note, rather than picking one member's declaration to
  // speak for all of them.
  const effectiveRiskLevel = worstRiskLevel(items.map((i) => i.plan.effectiveRiskLevel))
  const declaredRiskLevel = items.every((i) => i.plan.riskLevel === representative.plan.riskLevel)
    ? representative.plan.riskLevel
    : null

  let worstSeverity: IncidentSeverity = representative.severity
  for (const item of items) {
    if (SEVERITY_RANK[item.severity] < SEVERITY_RANK[worstSeverity]) worstSeverity = item.severity
  }
  const severityClass = SEVERITY_RULE_CLASS[worstSeverity] ?? 'sev-neutral'

  // BACKLOG D11 #4's note is stated once per card/group, and only when at
  // least one member actually still has a decision to make — an
  // already-approved or fully-superseded item has nothing left to decline or
  // ignore, so restating the consequence there would be a fact about nothing.
  const anyActionable = items.some((item) => !item.alreadyApproved && !item.supersededByUrl)

  // Three columns (owner, 2026-10-12: the old card was "a huge card with a
  // ton of text"): WHAT is broken and why, THE CHANGE that would be made,
  // and the DECISION — both gates as a short checklist, the consequence in
  // one line, then the buttons. Every sentence the old card printed is still
  // reachable: the gate reasoning and the decline/leave consequence sit
  // behind a disclosure and a HelpTip.
  const decide = (
    <div className="approval-col approval-col-decide">
      <span className="approval-col-label">Decision</span>
      <ul className="approval-gates">
        <li className="approval-gate" data-tone={plan.gateOutcome === 'AutoApprove' ? 'ok' : 'attention'}>
          <span className="approval-gate-mark" aria-hidden="true">{plan.gateOutcome === 'AutoApprove' ? '✓' : '●'}</span>
          <span>
            <strong>{gateLabel}</strong> — {headline}
            {detail && (
              <details className="approval-gate-detail">
                <summary>Full gate reasoning</summary>
                <p className="field-hint">{detail}</p>
              </details>
            )}
          </span>
        </li>
      </ul>
      <p className="approval-effect">
        {route.sentence}
        {anyActionable && (
          <>
            {' '}
            <HelpTip label="If you decline or leave it" text={declineOrIgnoreNote(plan.gateOutcome)} />
          </>
        )}
      </p>
      <ApprovalActions item={representative} />
    </div>
  )

  return (
    <div
      className={
        embedded
          ? `approval-row approval-embedded${items.every((item) => item.alreadyApproved) ? ' approval-row-decided' : ''}`
          : `card approval-row severity-rule ${severityClass}${items.every((item) => item.alreadyApproved) ? ' approval-row-decided' : ''}`
      }
    >
      <div className={embedded ? 'approval-grid approval-grid-embedded' : 'approval-grid'}>
        {!embedded && (
          <div className="approval-col approval-col-what">
            <span className="approval-col-label">What is broken</span>
            <ApprovalMemberIdentity item={representative} />
          </div>
        )}
        <div className="approval-col approval-col-change">
          <span className="approval-col-label">The change</span>
          {/* Embedded, the identity column is gone (the incident page shows
              it above), but how much to trust the plan stays beside the
              decision: the model's confidence band and what the citation
              check found (PROJECT.md #7). */}
          {embedded && (
            <div className="approval-plan-summary">
              {representative.confidence != null && (
                <span className={confidenceBadge(representative.confidence).className} title={confidenceBadge(representative.confidence).title}>
                  {confidenceBadge(representative.confidence).band}
                </span>
              )}
              <EvidenceQualityBadge item={representative} />
            </div>
          )}
          <div className="approval-plan-summary">
            <span className={route.className}>{route.label}</span>
            <span className="badge badge-gray">{actionLabel}</span>
            <RiskBadge effectiveRiskLevel={effectiveRiskLevel} declaredRiskLevel={declaredRiskLevel} />
            {items.length > 1 && <span className="badge badge-blue">{items.length} matching decisions</span>}
          </div>
          <ApprovalMemberChange item={representative} withActions={false} />
          <div className="approval-plan-summary approval-checks">
            {checks.map((check) => (
              <VerificationChip key={check.label} verified={check.verified} title={check.title}>
                {check.label}
              </VerificationChip>
            ))}
          </div>
        </div>
        {decide}
      </div>

      {items.length > 1 && (
        <div className="approval-group-members">
          {items.slice(1).map((item) => (
            <div key={item.incidentId} className="approval-member approval-grid">
              <div className="approval-col approval-col-what">
                <ApprovalMemberIdentity item={item} />
              </div>
              <div className="approval-col approval-col-change">
                <ApprovalMemberChange item={item} withActions={false} />
              </div>
              <div className="approval-col approval-col-decide">
                <ApprovalActions item={item} />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
