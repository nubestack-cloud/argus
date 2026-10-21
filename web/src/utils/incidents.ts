import type {
  AnalysisStep,
  ApprovalQueueItem,
  Incident,
  IncidentSeverity,
  IncidentState,
  PartialReason,
  RemediationPlan,
  ToolCall,
} from '../api/types'

// The incident vocabulary shared by every screen that renders one: the badge
// palettes, the human labels, and two small derived predicates.
//
// Not in components/ on purpose — a module that exports both components and
// constants breaks Fast Refresh (the lint rule says so), and none of this is a
// component. The components that use it live in components/IncidentBadges.tsx,
// AnalysisConclusion.tsx and RemediationPlanCard.tsx.
//
// All of it was previously copied into individual pages, up to four times each,
// under a comment saying to factor it out once a third screen needed it.
// TolerationsPage is that screen and then some: a toleration is an incident
// that has been accepted, so the incident it was created from must read exactly
// as it does on the incident pages, or one fact acquires two house styles.

export const SEVERITY_BADGE_CLASS: Record<IncidentSeverity, string> = {
  low: 'badge-blue',
  medium: 'badge-amber',
  high: 'badge-orange',
  critical: 'badge-red',
}

export const SEVERITY_LABEL: Record<IncidentSeverity, string> = {
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
}

// Ordinal rank, worst first (0 = critical). GET /approvals' own ORDER BY
// (internal/api/approvals.go's approvalQueueQuery) uses this identical
// ordinal meaning server-side; this is the same ordering as a lookup rather
// than the array OverviewPage's own SEVERITY_ORDER iterates, for call sites
// that need to COMPARE or SORT rather than enumerate — ApprovalsPage's D11
// consequence ordering, and ApprovalDecisionCard's worst-of-the-group
// severity rule for a collapsed set of same-shape decisions.
export const SEVERITY_RANK: Record<IncidentSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
}

// The readable form of each state, used by the badge AND by IncidentsPage's
// state filter — one vocabulary, so a filter option and the badge it matches
// can never disagree.
export const STATE_LABEL: Record<IncidentState, string> = {
  // Owner decision 2026-10-12 (incident lifecycle redesign): the labels say
  // where the incident is and whose move it is, in the reader's words, not the
  // state machine's. The API keeps its own names; this is display only.
  Detected: 'Not investigated',
  Investigating: 'Investigating',
  RecommendationReady: 'Fix proposed',
  // Reached both when an investigation found no cause and when it found one
  // with nothing ARGUS can run; the detail page tells the two apart
  // (stateLabelFor), a list row cannot.
  NeedsHumanInvestigation: 'Needs a person',
  AwaitingApproval: 'Waiting on a decision',
  Executing: 'Running the fix',
  AwaitingMerge: 'Pull request open',
  Validating: 'Watching',
  Resolved: 'Resolved',
  Failed: 'Fix failed',
  Reopened: 'Reopened',
  Dismissed: 'Dismissed',
  // A complete investigation whose route is guidance — a real root cause,
  // nothing in-cluster for ARGUS to execute, so the next move is a person's.
  Diagnosed: 'Fix is yours',
  // BACKLOG.md C8 / BUGS.md 104: a mutating execution whose real outcome
  // could not be confirmed either way — never worded as a failure, which
  // would repeat the exact false negative this state exists to stop
  // asserting.
  ExecutionUnknown: 'Run not confirmed',
  ValidationUnknown: 'Fix applied, not confirmed',
  // The object of the verb is the point: rejecting the fix is not rejecting
  // the incident.
  PlanRejected: 'Fix rejected',
  Expired: 'Expired',
}

// The detail page's label, which can use what the investigation concluded:
// NeedsHumanInvestigation means "fix is yours" when a root cause was recorded
// and "inconclusive" when none was — two different next moves under one state.
export function stateLabelFor(state: IncidentState, analysis?: { status: string; rootCause?: unknown } | null): string {
  if (state === 'NeedsHumanInvestigation' && analysis) {
    return analysis.status === 'complete' && analysis.rootCause ? 'Fix is yours' : 'Inconclusive'
  }
  return STATE_LABEL[state] ?? state
}

// BACKLOG.md D9 U1: seven of these states — Detected, Investigating,
// RecommendationReady, NeedsHumanInvestigation, Diagnosed, ExecutionUnknown
// and Failed — used to appear on the incident detail screen as nothing but
// this coloured badge, with no sentence anywhere on the page saying what the
// state means or who owns the problem now. The other seven already get a
// full explanation elsewhere on that screen (the six StageCard boxes and
// their own derived text), which is why this map exists rather than a
// blanket "explain every state" rule — a sentence that only repeated what a
// StageCard already says would be the exact "second, narrower copy of the
// page" LifecycleRail's own comment describes as the failure this app keeps
// cutting back.
//
// Rendered once, next to StateBadge on the incident DETAIL page only (not on
// IncidentsPage's list rows, which are a scan surface — lld/11's own six
// screen modes distinguish a triage scan from a single-object argument, and
// a full sentence per row is the wrong amount of text for the former).
export const STATE_EXPLANATION: Partial<Record<IncidentState, string>> = {
  Detected: 'Recorded, not yet investigated — analyze it to find the cause. It may also be picked up automatically, if this severity is one of the severities configured for automatic analysis.',
  // BACKLOG.md D9 U2: an investigation in progress used to look identical to
  // Detected unless THIS browser tab happened to be the one that launched
  // it — a server-side auto-analysis in flight showed nothing distinguishing
  // it. This sentence is true regardless of which tab (or no tab) started
  // it, and the Analysis card below shows the same "investigating" state for
  // the same reason (see IncidentDetailPage's own comment on that card).
  Investigating: 'An investigation is running now, gathering live evidence from the cluster. This page updates automatically when it finishes.',
  RecommendationReady: 'Investigation complete, with a plan ARGUS can act on — review it in the Fix section below.',
  // Deliberately worded for the case where the investigation reached NO
  // conclusion. It is NOT the whole story: NeedsHumanInvestigation is also
  // where a COMPLETE investigation lands when it proposed no executable plan,
  // and for those this sentence's first half is simply false. A live example
  // (gwas-db, 2026-09-09) sat here with root_cause.status='complete' and a
  // real statement at 95% confidence while this text told the operator the
  // investigation "stopped without a clear cause".
  //
  // stateExplanation below is what resolves that — always call it rather than
  // indexing this map directly for a state whose meaning depends on the
  // analysis.
  NeedsHumanInvestigation: 'The investigation stopped without a clear cause or a plan — this is now yours to look into by hand.',
  // BACKLOG.md D9 U1's own example: Diagnosed must mention the guidance
  // route, because a green-adjacent amber badge with no sentence reads as
  // "still working on it" rather than "finished, and there is no automatic
  // fix".
  Diagnosed: 'Investigation complete, with a real cause identified — but nothing ARGUS can execute automatically. What to do about it, including the possibility that nothing needs doing, is in the Fix section below.',
  // BACKLOG.md C8 / BUGS.md 104: never worded as a failure, matching
  // STATE_LABEL's own comment for this state.
  ExecutionUnknown: 'ARGUS ran the approved change but lost track of whether it actually applied — check the cluster directly before deciding what to do next.',
  ValidationUnknown: 'The fix was applied, and ARGUS could not confirm it worked — it could neither re-read the changed value nor re-check the original fault. This is not a failure, and it is not a success: someone needs to look.',
  Failed: 'The remediation ran and failed — review the cause in the Fix section below before trying again.',
  // The sentence has to carry the fact the state name cannot: nothing about
  // the cluster changed. A reader who takes "rejected" as "dealt with" is
  // making exactly the mistake the old AwaitingApproval -> Dismissed
  // transition made for them.
  PlanRejected:
    'Someone reviewed the fix ARGUS proposed and refused it. Nothing was executed and the fault is unchanged — the reason they gave is in the Fix section below. Re-analyse for a different fix, propose one at the source, or close this out.',
  // PROJECT.md T2: the one sentence that has to carry the distinction from
  // Dismissed, since the badge alone cannot. Nobody looked at this incident
  // individually — a bulk cleanup closed it along with others whose
  // findings no longer meet the promotion bar — and it is not gone for
  // good: a real recurrence reopens it automatically.
  Expired:
    'Closed in bulk, not by an individual decision — ARGUS would no longer raise an incident for the finding(s) behind it. If the underlying issue happens again, this incident reopens on its own.',
}

// BACKLOG.md T2: "self-healed" and "remediated" used to both read as the
// same bare "Resolved" badge. RESOLUTION_KIND_LABEL is deliberately worded
// as what is KNOWN, not what is hoped: "remediated" means a succeeded
// execution or a merged pull request is linked to this close (a real,
// derivable fact — internal/orchestrator's deriveResolutionKind); it is not
// a claim that the underlying fault can never recur (StateReopened still
// exists for that). "Self-healed" means neither is linked — the symptom
// stopped, or a human closed it by hand, with no ARGUS action behind it —
// and is deliberately NOT worded as "fixed" for the same reason.
export const RESOLUTION_KIND_LABEL: Record<'remediated' | 'self_healed', string> = {
  remediated: 'Remediated',
  self_healed: 'Self-healed',
}

// The longer form, for IncidentDetailPage's stage card — one sentence
// saying what is actually known, not implied by the badge alone (lld/11
// §8's "colour/badge is never the only signal" extends naturally to "a
// two-word badge is never the only explanation" for a fact this load-bearing).
export const RESOLUTION_KIND_EXPLANATION: Record<'remediated' | 'self_healed', string> = {
  remediated: "ARGUS's own remediation is linked to this close — a succeeded execution or a merged pull request.",
  self_healed:
    'No ARGUS execution or merged pull request is linked to this close. The symptom stopped, or someone closed it by hand — ARGUS did not act.',
}

// stateExplanation is STATE_EXPLANATION plus the cases whose honest wording
// depends on what the analysis actually concluded.
//
// # Why a function rather than more map entries
//
// A state name is not always enough to say something true. Two states carry
// more than one meaning:
//
//   - NeedsHumanInvestigation is reached BOTH when an investigation reached no
//     conclusion AND when it reached a complete one and merely proposed no
//     executable plan. The map's sentence is written for the first and is
//     false for the second.
//   - Diagnosed is reached both when there is a real fault nobody can fix
//     automatically and when the investigation concluded there is nothing
//     wrong at all (the model's isFault verdict). Asserting "the guidance
//     below is the fix" is wrong for the second.
//
// The first is fixed here, because whether a root cause exists IS in the API.
// The second is only softened, not resolved: the isFault verdict is consumed
// server-side and never persisted or exposed (PROJECT.md T4), so the frontend
// genuinely cannot tell the two apart yet. Softening the claim is the honest
// response to not knowing — the alternative is asserting one of two readings
// at random.
//
// Callers should use this rather than indexing STATE_EXPLANATION. The map
// stays exported because it is the source of the unconditional text and its
// entries are asserted directly by tests.
export function stateExplanation(
  state: IncidentState,
  analysis?: { status?: string; rootCause?: { statement: string } | null } | null,
): string | undefined {
  if (state === 'NeedsHumanInvestigation') {
    const reachedACause =
      analysis?.status === 'complete' && !!analysis.rootCause?.statement.trim()
    if (reachedACause) {
      return 'The investigation reached a cause, but proposed nothing ARGUS can execute — the cause is in the Why section below, and acting on it is now yours.'
    }
  }
  return STATE_EXPLANATION[state]
}

export const STATE_BADGE_CLASS: Record<IncidentState, string> = {
  Detected: 'badge-blue',
  Investigating: 'badge-blue',
  RecommendationReady: 'badge-amber',
  NeedsHumanInvestigation: 'badge-amber',
  AwaitingApproval: 'badge-amber',
  Executing: 'badge-blue',
  AwaitingMerge: 'badge-blue',
  Validating: 'badge-blue',
  Resolved: 'badge-green',
  Failed: 'badge-red',
  Reopened: 'badge-amber',
  Dismissed: 'badge-gray',
  // Same family as NeedsHumanInvestigation: a human decides next steps,
  // it's just that the investigation itself succeeded rather than
  // hitting a bound.
  Diagnosed: 'badge-amber',
  // Amber, not red: red is reserved for a CONFIRMED bad outcome (Failed),
  // and this state's entire point is that the outcome is NOT confirmed —
  // the same "a human needs to check" family as NeedsHumanInvestigation/
  // AwaitingApproval/Reopened, not the same family as a definite failure.
  // Amber, matching ExecutionUnknown: both mean "we cannot tell", and red is
  // reserved for confirmed-bad. An unconfirmed fix is not a failed one.
  ExecutionUnknown: 'badge-amber',
  ValidationUnknown: 'badge-amber',
  // Amber, the "a human decides what happens next" family, alongside
  // NeedsHumanInvestigation and Diagnosed. Not red: red means a confirmed bad
  // outcome (Failed), and nothing failed here — a person made a decision and
  // the incident is exactly as broken as it was before. Not grey either, which
  // is Dismissed's colour and would read as closed, which is the whole bug.
  PlanRejected: 'badge-amber',
  // Same colour as Dismissed, deliberately — matching this map's own
  // existing precedent (Diagnosed/NeedsHumanInvestigation/AwaitingApproval/
  // PlanRejected already share badge-amber, distinguished by their label,
  // not a fourth shade of amber invented for each). Expired and Dismissed
  // are the same WEIGHT of fact — both closed, neither a red flag, neither
  // asking for follow-up — so the word ("Expired" vs "Dismissed") is what
  // has to carry the distinction PROJECT.md T2 asks for, not a new colour
  // this vocabulary has no slot for without inventing one.
  Expired: 'badge-gray',
}

// --- Disposition: is this incident closed, in flight, or somebody's to act on? ---
//
// Mirrors internal/orchestrator/state.go's disposition table, which is the
// source of truth and carries the per-state reasoning. Kept as an exhaustive
// Record so the compiler refuses a new IncidentState that nobody classified —
// the same mechanism STATE_LABEL and STATE_BADGE_CLASS already rely on.
//
// # Why this exists
//
// Four screens each held their own `['Resolved', 'Dismissed']` and called an
// incident "open" when it was neither. That answers a question about the state
// machine, not about the product: it counts an incident ARGUS is mid-analysis
// on identically to one waiting on an approver, and it leaves a finished
// Diagnosed incident sitting in the queue with nothing saying why it never
// moves. The server stopped deriving its queue from terminality (GET
// /incidents' `counts.requiresAction` and `?requiresAction=`); this is the
// same split on this side of the wire.
//
// The two questions, kept separate on purpose:
//   - 'closed'         the lifecycle is over. Hide the triage controls, stop
//                      counting it as an open incident on a cluster.
//   - 'inProgress'     open, and another writer owns the next move — an
//                      analysis, an execution, a validation grace period, or a
//                      reviewer working on a pull request outside ARGUS.
//   - 'requiresAction' nothing happens until a person acts.
export type IncidentDisposition = 'requiresAction' | 'inProgress' | 'closed'

export const STATE_DISPOSITION: Record<IncidentState, IncidentDisposition> = {
  Detected: 'requiresAction',
  Investigating: 'inProgress',
  RecommendationReady: 'requiresAction',
  NeedsHumanInvestigation: 'requiresAction',
  AwaitingApproval: 'requiresAction',
  Executing: 'inProgress',
  // Waiting on a person, but on a person working in the SCM, where the review
  // is already tracked and MergeSweeper advances the incident on its own once
  // the merge lands. Putting it in the ARGUS queue would ask an operator to
  // chase work that is queued somewhere it can actually be done. It stays
  // visible on the approvals worklist, which lists AwaitingMerge alongside
  // AwaitingApproval for exactly this reason.
  AwaitingMerge: 'inProgress',
  Validating: 'inProgress',
  Resolved: 'closed',
  Dismissed: 'closed',
  // Finished without being closed. ARGUS reached a real cause and has nothing
  // to execute; the fault is still in the cluster and the guidance is a
  // person's to apply. This is the state the old definition could not explain.
  Diagnosed: 'requiresAction',
  Failed: 'requiresAction',
  // A fix ARGUS believed held did not. Nothing else will act on it.
  Reopened: 'requiresAction',
  ExecutionUnknown: 'requiresAction',
  ValidationUnknown: 'requiresAction',
  PlanRejected: 'requiresAction',
  // PROJECT.md T2: closed, same as Resolved/Dismissed — nobody's queue
  // item. Mirrors internal/orchestrator/state.go's own closedStates
  // classification exactly (that file's own comment has the full argument
  // for why this is allowed to differ from state-machine terminality).
  Expired: 'closed',
}

// A state this bundle has never heard of — a hub newer than the browser tab —
// counts as needing action rather than disappearing from every queue. Same
// fallback the server takes, and for the same reason: an incident nobody can
// explain is recoverable, one nobody can see is not.
export function incidentRequiresAction(state: IncidentState): boolean {
  return (STATE_DISPOSITION[state] ?? 'requiresAction') === 'requiresAction'
}

// The lifecycle is over: Resolved, Dismissed, or (PROJECT.md T2) Expired.
// This is the question the triage controls and a cluster's open-incident
// count are asking, and it is genuinely different from the one above — see
// this block's doc comment.
export function isClosedIncidentState(state: IncidentState): boolean {
  return STATE_DISPOSITION[state] === 'closed'
}

// Why an investigation stopped short, said as what it means for the reader.
export function partialReasonText(reason: PartialReason): string {
  switch (reason) {
    case 'iteration_limit':
      return 'It reached its step limit before reaching a conclusion.'
    case 'time_limit':
      return 'It reached its time limit before reaching a conclusion.'
    // A real case the backend emits (internal/llm/cli_investigator.go) that
    // used to be missing from PartialReason, so this switch returned
    // undefined and the sentence rendered blank. Worded as what it means for
    // the reader — the evidence is real, only the write-up failed — rather
    // than as the raw enum value.
    case 'malformed_final_answer':
      return "It gathered evidence but its final write-up couldn't be read, so no conclusion was recorded."
    default: {
      // Unreachable for any value PartialReason allows — assigning to `never`
      // keeps that a compile error if a fifth reason is ever added without a
      // sentence here. The runtime fallback covers what the type system
      // can't: a hub newer than this bundle sending a reason it doesn't know.
      // A vague sentence beats the empty paragraph that used to render.
      const unhandled: never = reason
      void unhandled
      return 'It stopped before reaching a conclusion.'
    }
  }
}

// executesForReal is the same scope line internal/api/remediation_exec.go
// draws: OpenPR still only ever gets recorded, never executed (it needs the
// separate sandboxed rendering pipeline lld/09 specs — see
// PRODUCT_DIRECTION.md). ScaleDeployment/RestartPod are the two action types
// with a real Execute/Validate story; every caller keys off this same check
// rather than assuming every plan behaves alike.
export function executesForReal(plan: RemediationPlan): boolean {
  return plan.actionType !== 'OpenPR'
}

// planChange/PlanChange, moved here from ApprovalDecisionCard.tsx (BACKLOG D8
// A4/A7): IncidentDetailPage's stage 3 (Recommendation) needs the identical
// before/after mapping for the in-place channel's `.diff-pair` that the
// approval queue already renders for the same plan, and a component file is
// the wrong home for a function two screens share — re-deriving the
// actionType → change mapping a second time is how two screens end up
// describing one plan two different ways, and exporting a plain function
// from a component module trips Fast Refresh's only-export-components rule
// (see this file's own header comment, and incidentLifecycle.ts's identical
// reasoning for splitting the lifecycle rail's logic out of the page).

// THE CHANGE ITSELF, as `.diff-pair`'s two lines — and, for the actions that
// change no field a browser can name, the sentence that says so instead.
//
// `before` is present ONLY where the queue payload genuinely carries the
// current value (PatchField's expectCurrent). Every other action reads its
// current value off the live object at execution time and GET /approvals does
// not carry it. An em dash there would claim the field is currently unset,
// which is a different fact and usually a false one — the same discipline as
// never rendering an unavailable cost as $0.00.
export type PlanChange = {
  before?: string
  after?: string
  note?: string
}

// '' is kept rather than treated as absent: a plan that sets a field to the
// empty string is a real plan, and dropping the line would hide the change.
function paramString(params: Record<string, unknown>, key: string): string | undefined {
  const value = params[key]
  return typeof value === 'string' ? value : undefined
}

function displayValue(value: string): string {
  return value === '' ? '""' : value
}

// The files an OpenPR plan proposes, as the wire carries them
// (internal/orchestrator's openPRParamsRow: `files: [{path, content}]`).
//
// Lives here rather than in RepositoryChangePanel for the reason planChange
// does: two surfaces read it — the panel, which seeds an editor per file, and
// planChange below, which names them on the recommendation card — and a second
// hand-written parse is how two screens end up describing one plan differently.
//
// Defensive on every field because `params` is a `Record<string, unknown>` read
// out of a jsonb column: a plan written by an older build carried
// filePath/fieldPath/newValue and no `files` at all, and an entry missing a
// path or its content is not a file this UI can open. Both degrade to "nothing
// proposed", which the callers already state honestly, rather than to a row
// with an empty path in it.
export function proposedFilesFromPlan(
  plan?: RemediationPlan | null,
): { path: string; content: string }[] {
  if (!plan || plan.actionType !== 'OpenPR') return []
  const raw = (plan.params ?? {}).files
  if (!Array.isArray(raw)) return []
  const out: { path: string; content: string }[] = []
  for (const entry of raw) {
    if (!entry || typeof entry !== 'object') continue
    const { path, content } = entry as Record<string, unknown>
    if (typeof path !== 'string' || path.trim() === '') continue
    if (typeof content !== 'string') continue
    out.push({ path: path.trim(), content })
  }
  return out
}

export function planChange(plan: RemediationPlan): PlanChange {
  const params = plan.params ?? {}
  // Widened to string deliberately. api/types.ts documents
  // RemediationActionType as having fallen behind internal/remediation's own
  // closed set more than once, and PatchField — which this queue can genuinely
  // list, even though approving one currently 500s (BUGS.md 78) — is missing
  // from the union today. A switch over the union could not even mention it.
  const actionType: string = plan.actionType

  if (actionType === 'ScaleDeployment') {
    const replicas = params.replicas
    return typeof replicas === 'number' ? { after: `spec.replicas: ${replicas}` } : {}
  }

  if (actionType === 'RestartPod') {
    return {
      note: 'No field value changes: ARGUS stamps a restart annotation on the pod template, which rolls every pod in the workload.',
    }
  }

  if (actionType === 'PatchResourceLimits') {
    const container = paramString(params, 'container')
    const quantities: [string, string][] = [
      ['memoryLimit', 'limits.memory'],
      ['memoryRequest', 'requests.memory'],
      ['cpuLimit', 'limits.cpu'],
      ['cpuRequest', 'requests.cpu'],
    ]
    const parts: string[] = []
    for (const [key, path] of quantities) {
      const value = paramString(params, key)
      // Empty means "leave this one exactly as it is"
      // (remediation.PatchResourceLimitsParams), so an empty field is not a
      // change and must not appear in the after line.
      if (value) parts.push(`${path}=${value}`)
    }
    if (parts.length === 0) return {}
    return { after: `${container ? `containers[${container}].` : ''}resources: ${parts.join(', ')}` }
  }

  if (actionType === 'RevertContainerImage') {
    const container = paramString(params, 'container')
    // No after line, and that is the honest rendering: the plan names a
    // container and nothing else. The image is resolved by the hub from the
    // workload's own ReplicaSet history at approval time, precisely so no
    // model-supplied image can ever enter the system — so there is no value
    // here to put in a green line.
    return {
      note: `Sets ${container ? `container ${container}` : 'the container'}'s image back to the one its previous revision ran. The hub resolves that image from the workload's own rollout history when you approve, so the exact tag is not known yet.`,
    }
  }

  if (actionType === 'PatchField') {
    const fieldPath = paramString(params, 'fieldPath')
    const newValue = paramString(params, 'newValue')
    if (!fieldPath || newValue === undefined) return {}
    // The one action whose params carry a real current value: expectCurrent is
    // the value the execution refuses to proceed without matching.
    const expectCurrent = paramString(params, 'expectCurrent')
    return {
      before: expectCurrent ? `${fieldPath}: ${displayValue(expectCurrent)}` : undefined,
      after: `${fieldPath}: ${displayValue(newValue)}`,
    }
  }

  if (actionType === 'AnnotateResource' || actionType === 'LabelResource') {
    const key = paramString(params, 'key')
    const value = paramString(params, 'value')
    if (!key || value === undefined) return {}
    return { after: `${actionType === 'AnnotateResource' ? 'annotations' : 'labels'}[${key}]: ${displayValue(value)}` }
  }

  if (actionType === 'CreateResource') {
    // No "before" line: the whole point of this action is that the target
    // does not exist yet (ARGUS refuses to execute if one is found to exist
    // by the time this is approved). Data can hold values up to 64KB each,
    // so only the KEYS being set are shown here, not the values themselves —
    // showing every value could make one plan's card unreadably long.
    const data = params['data']
    const keys = data && typeof data === 'object' ? Object.keys(data as Record<string, unknown>) : []
    return {
      after: keys.length > 0 ? `data keys: ${keys.join(', ')}` : undefined,
      note: 'Creates a new object in the cluster with this data. This object does not exist today.',
    }
  }

  if (actionType === 'DeleteResource') {
    // No before/after line: this removes the whole object, there is no
    // single field to show a value for. The irreversibility is the one fact
    // that matters here, and it is said plainly rather than implied by a
    // risk badge alone (DESIGN.md §10.5).
    return {
      note: 'Permanently deletes this object from the cluster. This cannot be undone by ARGUS — recovery, if any, depends entirely on whatever recreates it afterwards.',
    }
  }

  if (actionType === 'OpenPR') {
    // No before/after line, and that is the honest rendering rather than a gap.
    // An OpenPR plan carries WHOLE FILES (internal/remediation.OpenPRParams,
    // rewritten 2026-08-28) — one or many, each with the content the file
    // should end up holding. There is no field and no value to put on two
    // lines, and the diff is ARGUS's to compute against the file at the pinned
    // synced commit, which this payload does not carry. Naming the files and
    // sending the reader to the panel that renders the real +/- diff is the
    // whole of what can be said here truthfully.
    const files = proposedFilesFromPlan(plan)
    const repository = paramString(params, 'repository')
    if (files.length === 0) {
      return { note: repository ? `A pull request against ${repository}.` : undefined }
    }
    const where = repository ? ` in ${repository}` : ''
    return {
      note:
        files.length === 1
          ? `Changes ${files[0].path}${where}. Open "Propose this fix as a pull request" to see the diff ARGUS computes against the synced commit.`
          : `Changes ${files.length} files${where}: ${files.map((f) => f.path).join(', ')}. Open "Propose this fix as a pull request" to see each diff.`,
    }
  }

  return {}
}

// Promoted here from IncidentsPage on 2026-08-25: the incident-detail screen's
// summary strip needs the same identity, and a second hand-maintained copy of
// "what do we call this incident" is how two screens end up naming the same
// incident differently.
// incidentFailureLabel is the "what actually failed" line for a row.
//
// BUGS.md item 35: this column used to render the raw 64-character fingerprint
// hash, so a row said only "some incident, on this cluster" — an operator
// scanning the list could not tell an OOMKill from a failed mount without
// opening each one. The reason and object were both already stored; neither was
// on this page.
//
// Degradation order and wording deliberately match OverviewPage's
// issueGroupTitle, so the same incident reads the same way in both places
// rather than having two house styles for one label.
export function incidentFailureLabel(incident: Incident): string {
  if (incident.openingReason && incident.objectName) return `${incident.openingReason} · ${incident.objectName}`
  if (incident.openingReason) return incident.openingReason
  if (incident.objectName) return incident.objectName
  // Reached when the opening finding named no object AND carried no reason —
  // rare, and the short hash is genuinely the only identity available.
  return `Incident ${incident.fingerprint.slice(0, 8)}`
}

// incidentIdentity splits a row's leading cell into the three lines of the
// identity block (index.css, "D7/D8 visual vocabulary" §6; the archetype A
// block of .design/ListAndQueue.dc.html): the SUBJECT's name, then what kind
// of object it is and where it lives, then what is wrong with it. Which
// object is the subject is B174's question — see the block above the function
// itself; the short answer is the owning workload when there is one.
//
// Same facts the old two-line cell carried, reordered so that a scan down this
// column is a scan of object names — the thing an operator recognises — rather
// than of reason strings all beginning with the same handful of words. The
// reason moves to its own line underneath, which is also where the design puts
// it.
//
// Every field but the fingerprint is optional on the wire (an incident whose
// opening finding named no object omits all three — see api/types.ts), so each
// line degrades on its own and an empty one is omitted rather than rendered
// blank.
/**
 * The Kind out of an `objectGvk`, in either form the field actually holds.
 *
 * The agent's own convention is SLASH form — `apps/v1/Deployment`, `v1/Pod`
 * (`internal/agent/tools.go`'s `formatGVK`, "the same wire convention callers
 * send in"). `split('/').pop()` was written for that and is right for it.
 *
 * It is not the only form on the wire. Kubernetes' `GroupVersionKind.String()`
 * produces COMMA form — `apps/v1, Kind=Deployment` — and anything hand-writing
 * a payload reaches for that instead, which is how 8 rows of
 * `v1, Kind=Pod` and `apps/v1, Kind=Deployment` ended up in the dev database.
 * On those, `split('/').pop()` returns `v1, Kind=Pod`: the identity cell then
 * renders the whole group/version prefix the comment below calls "noise in a
 * list", which is the opposite of what it is for.
 *
 * Handled here rather than only at the source because the rows already exist
 * and a list cell should not depend on every producer having been correct.
 * (`scripts/smoke-test.sh` was the producer, and is fixed too — its fixtures
 * were exercising a shape no agent emits.)
 */
export function kindFromObjectGvk(objectGvk: string | null | undefined): string {
  if (!objectGvk) return ''
  // Comma form first: the Kind is named explicitly, so there is nothing to
  // infer from position.
  const named = /,\s*Kind=(.+)$/.exec(objectGvk)
  if (named) return named[1].trim()
  return objectGvk.split('/').pop()?.trim() ?? ''
}

// --- Which object does a HUMAN read this incident as being about? (B174) ---
//
// An incident's machine identity is `incidents.object_key` — the object the
// detector named — and for most of the fault catalogue that is a **Pod**. A
// Pod is ephemeral. On a real OOMKill lifecycle driven end to end on
// 2026-09-19 the fix correctly targeted the Deployment, the rollout replaced
// the Pod, and two resolved incidents were left named after
// `checkout-oom-6d99b45595-fw7v8` — an object that no longer exists, so the
// screen was naming something the operator could no longer inspect.
//
// `incidents.workload_key` is the owner the AGENT already resolved at capture
// time (`internal/gateway/finding.go`'s workloadCorrelationKey) and it is what
// remediation actually acted on. It is already on the wire as `workloadKey`.
// So the owner leads every surface a human reads, and the Pod stays beside it
// as the evidence it is.
//
// **This is presentation only.** Nothing here re-keys, re-fingerprints or
// re-correlates: the incident is still the Pod's incident, `objectName`/
// `objectGvk` are still exactly what the fingerprint was built from, and
// `collapseWorkloadSiblings` below still groups on the server's own
// `workload_group_id`. Re-keying was considered and rejected as too entangled
// with deduplication and correlation to do as a display fix.
//
// Consistency note, and one reason the change is small: the COLLAPSED parent
// row already led with the workload (`workloadGroupSummary` has parsed
// `workload_key` for its own name since replica-level correlation shipped).
// Before this, a group's parent said `checkout-oom` and each of its thirteen
// children said a different Pod hash — parent and child naming the same thing
// two ways. They agree now.

/**
 * `objectName`/`objectGvk` as an object identity, for the rows where the hub
 * could not split them apart.
 *
 * internal/api splits `incidents.object_key` on `|` (migration 000036's
 * `gvk|namespace|name`). The development database also holds SLASH-form
 * object keys written by seeded fixtures — `cl_01.../v1/Pod/default/checkout-
 * Expired` — and those have no pipe, so the whole key arrives as `objectName`
 * with `objectGvk`/`objectNamespace` absent. 36 rows on the dev fleet, found
 * by running this file's helpers over all 228 of them.
 *
 * A real Kubernetes object name can never contain `/` (RFC 1123), so the
 * presence of one is a reliable tell that the value is a key rather than a
 * name. Parsed the same way `parseWorkloadKey` already parses the slash form
 * of the sibling column, for the same reason its comment gives: a list cell
 * should not depend on every producer having been correct.
 */
function objectIdentity(incident: Incident): { kind: string; namespace: string; name: string } {
  const name = incident.objectName ?? ''
  if (name.includes('/')) {
    const parsed = parseWorkloadKey(name)
    if (parsed.name) return parsed
  }
  return {
    kind: kindFromObjectGvk(incident.objectGvk),
    namespace: incident.objectNamespace ?? '',
    name,
  }
}

export function incidentIdentity(incident: Incident): { name: string; kind: string; fault: string } {
  const fault = incident.openingReason ?? ''

  // The owner leads when the agent resolved one. `workload_key` is
  // legitimately NULL for a bare Pod with no controller, and for every
  // node-level or cluster-scoped object — 166 of 190 incidents on the dev
  // database. There the object IS the subject and the rest of this function
  // is unchanged from what it always did: no invented owner, and no dash
  // standing where a name belongs.
  const owner = parseWorkloadKey(incident.workloadKey)
  if (owner.name) {
    return {
      name: owner.name,
      // The owner's own namespace, falling back to the object's: a Pod and
      // its controller are always co-namespaced, so this only matters for a
      // malformed two-part key that carries no namespace of its own.
      kind: [owner.kind, owner.namespace || incident.objectNamespace].filter(Boolean).join(' · '),
      fault,
    }
  }

  // The Kind only; the group/version prefix is noise in a list and stays in the
  // cell's title attribute. Both wire forms — see kindFromObjectGvk.
  const object = objectIdentity(incident)
  const kindLine = [object.kind, object.namespace].filter(Boolean).join(' · ')
  if (object.name) {
    return { name: object.name, kind: kindLine, fault }
  }
  // No object named: the failure label is the only identity there is, and it
  // already contains the reason, so a fault line would only repeat it.
  return { name: incidentFailureLabel(incident), kind: kindLine, fault: '' }
}

/**
 * The object that carried the symptom, returned ONLY when it is not already
 * the thing `incidentIdentity` put in the headline.
 *
 * `null` — never a placeholder, never an em dash — in the three cases where
 * there is nothing extra to say:
 *
 *  - No owner was resolved. The object is the subject and is already the
 *    headline; a second line repeating it would be one fact twice.
 *  - The opening finding named no object at all (the fingerprint-only
 *    correlation fallback).
 *  - Owner and object are the same object, which the same rule covers.
 *
 * **It deliberately makes no claim about whether that object still exists.**
 * ARGUS does not re-check: `state` records that the fault stopped being
 * reported, not that a controller replaced the replica, and the two are not
 * the same event — a Node-owned static Pod can outlive its own resolved
 * incident. So callers word this in the PAST TENSE, identically for every
 * state, rather than branching `Resolved` into "this pod is gone" (a claim
 * nothing verified) or an open state into "currently failing on" (the same
 * error in the other direction). One wording that is true in every state
 * beats two, one of which is a guess.
 */
export function incidentObservedObject(incident: Incident): { kind: string; name: string; label: string } | null {
  const owner = parseWorkloadKey(incident.workloadKey)
  const object = objectIdentity(incident)
  if (!owner.name || !object.name) return null
  // Same object under both keys: equal names, and kinds that either match or
  // are not both known well enough to tell them apart.
  if (owner.name === object.name && (!owner.kind || !object.kind || owner.kind === object.kind)) return null
  return { kind: object.kind, name: object.name, label: [object.kind, object.name].filter(Boolean).join(' ') }
}

// The sentence that travels with an observed object, wherever it is rendered.
// Shared so the list's tooltip and the detail page's tooltip cannot come to
// say two different things about the same Pod — and so the "may no longer
// exist" caveat cannot be dropped from one of them in a later edit.
export function observedObjectTitle(observed: { label: string }): string {
  return `${observed.label} carried the symptom when this incident was detected. ARGUS does not re-check whether it still exists — a controller replaces a failed replica, so this one may be gone.`
}

// A single speakable, UNIQUE name for an incident, for a screen-reader label
// or a confirmation list.
//
// `incidentIdentity(...).name` stopped being unique the moment the owner
// started leading: thirteen OOMKilled Pods of one Deployment are thirteen
// incidents that now all display `checkout-oom`, so a checkbox labelled
// "Select incident checkout-oom" thirteen times, or a bulk-close dialog
// listing the same word thirteen times, would be a real regression for anyone
// who cannot see the rows. The observed object is exactly the part that
// differs, so it is what disambiguates.
export function incidentIdentityLabel(incident: Incident): string {
  const { name } = incidentIdentity(incident)
  const observed = incidentObservedObject(incident)
  return observed ? `${name} (${observed.label})` : name
}

// --- The age of the WAIT on an approval, measured from the PLAN ---
//
// Both screens that show an approval's age used to derive it from the
// INCIDENT's firstSeen — when the fault was first detected — and label that as
// waiting. Those are different events and the gap between them is routinely
// weeks: a live incident first seen on 15 July carrying a plan proposed on
// 5 September had been waiting on a human for a day, while the fleet overview
// reported it as ignored since July and the approval row read "Waiting 52d".
// On a number whose only job is to convey urgency, overstating by that margin
// is worse than showing nothing.
//
// plan.createdAt is the right event and it is already on the wire
// (internal/api/approvals.go's approvalQueueQuery selects rr.created_at through
// buildPlanView). It is the moment the wait began rather than a proxy for it:
// orchestrator.ApplyAnalysisResult persists the plan and moves the incident to
// AwaitingApproval in the SAME transaction, and that query's LATERAL join picks
// the CURRENT plan — so a re-analysis correctly restarts the clock on the
// decision actually in front of the approver instead of dating it to a
// superseded proposal.
//
// Null, never a fallback to a weaker field, when the timestamp is absent or
// unparseable: formatRelativeTime renders an unparseable date as "never", and
// "Waiting never" is a claim about the queue that nothing measured. Callers
// say the figure is not recorded instead.
export function approvalWaitStartedAt(approval: ApprovalQueueItem): string | null {
  const createdAt = approval.plan?.createdAt
  if (!createdAt || Number.isNaN(new Date(createdAt).getTime())) return null
  return createdAt
}

// The oldest still-pending wait in the queue, for the fleet overview's
// "Awaiting approval" cell. Already-approved rows are excluded because nobody
// is waiting on them (see ApprovalQueueItem.alreadyApproved), and a row with no
// usable plan timestamp is dropped rather than allowed to win the reduce.
export function oldestPendingApprovalPlanAt(approvals: ApprovalQueueItem[]): string | null {
  return approvals
    .filter((approval) => !approval.alreadyApproved)
    .map(approvalWaitStartedAt)
    .filter((startedAt): startedAt is string => startedAt != null)
    .reduce<string | null>(
      (oldest, startedAt) => (oldest == null || new Date(startedAt) < new Date(oldest) ? startedAt : oldest),
      null,
    )
}

// PROJECT.md D12 — the approvals screen's own evidence-quality signal.
// worstCorroboration picks the single most serious ToolCall.corroborated
// value across an entire causal chain, worst-first, so a card that would
// otherwise need to render every step just to answer "can I trust this" can
// show ONE badge instead. "contradicted" always wins regardless of how many
// other steps corroborated cleanly — one real disagreement between a cited
// value and the tool result it claims to come from is disqualifying on its
// own, the exact gap PROJECT.md B151 found.
//
// Returns null (render nothing) for a 'hub-observed' chain — corroborated is
// meaningless there by construction (see ToolCall's own doc comment: the hub
// dispatched every call itself, so there is nothing to cross-check a self-
// report against) — and for a chain with no toolCalls at all (nothing was
// cited, so there is nothing to grade). A 'self-reported' chain that made
// tool calls but left every one 'unchecked' still returns 'unchecked': that
// is real information (nothing here was actually verified), not an absence.
type Corroboration = NonNullable<ToolCall['corroborated']>
const CORROBORATION_SEVERITY: Record<Corroboration, number> = {
  contradicted: 3,
  unverified: 2,
  unchecked: 1,
  corroborated: 0,
}
export function worstCorroboration(
  causalChain: AnalysisStep[],
  provenance: ApprovalQueueItem['causalChainProvenance'],
): Corroboration | null {
  if (provenance !== 'self-reported') return null
  let worst: Corroboration | null = null
  for (const step of causalChain) {
    for (const call of step.toolCalls) {
      if (!call.corroborated) continue
      if (worst === null || CORROBORATION_SEVERITY[call.corroborated] > CORROBORATION_SEVERITY[worst]) {
        worst = call.corroborated
      }
    }
  }
  return worst
}

// --- The two counts that were both called "occurrences" ---
//
// An external product review found two near-identically-named counts on the
// incident surfaces, and reading either name told you nothing about which one
// you were looking at. They are not variations of one number; they count
// different things over different sets, and confusing them at 3am inverts the
// decision:
//
//  1. `Incident.occurrenceCount` — incidents.occurrence_count, bumped by
//     `UPDATE incidents SET occurrence_count = occurrence_count + 1` every
//     time a Finding correlates onto this ALREADY-OPEN incident
//     (internal/gateway/finding.go). One Finding is one detector delivery,
//     never Kubernetes' own cumulative Event count (internal/agent/detector.go
//     pins OccurrenceCount: 1 for exactly that reason). So it counts **how
//     many times this one live fault has been re-reported since this incident
//     opened** — a rate signal about one object, and it is never bumped by
//     anything on a different object or in a different incident.
//     Rendered as **"Detections"**.
//
//  2. `IncidentDetail.priorIncidents` — internal/api's priorIncidentLinksFor,
//     which queries CLOSED incidents sharing this incident's object_key,
//     excluding this one. So it counts **how many separate times this object
//     has broken and been closed before**, which is a recurrence signal about
//     history, not about the live fault. Currently labelled "Prior occurrences
//     on this object" on the incident detail page, and NOT available on the
//     list endpoint at all — there is no per-row prior-incident count on
//     GET /incidents, and this file must not invent one.
//
// "Detections" is the list's word because it is what the number literally
// counts (detector deliveries) and shares no stem with "prior occurrences".
// Kept here rather than inline on one page so the next screen that renders
// occurrence_count picks up the same word instead of reintroducing the
// collision.
export const DETECTION_COUNT_HEADER = 'Detections'

export function detectionCountTitle(count: number): string {
  return count === 1
    ? 'Reported once by a detector since this incident opened'
    : `Reported ${count} times by a detector since this incident opened — not the number of prior incidents on this object`
}

// --- Workload sibling collapse (the incidents list) ---
//
// internal/replicagroup assigns one incidents.workload_group_id to every
// currently-open incident on ONE cluster sharing (workload_key,
// opening_reason) — two Pods of the same Deployment both OOMKilled are two
// incidents by design (they are independently trackable and independently
// fixable) and one problem to a human. On the development database that is 52
// of 225 incidents in 4 groups of 13: thirteen rows of one Deployment's pods,
// pushing everything else off the screen, on the product's most contested
// surface. `screens.md` mode A asks for exactly this — "collapse near-identical
// rows to the interesting few plus a count".
//
// This is a GROUPING of rows the server already chose and already ordered, not
// a client-side sort or filter: no incident is hidden from the count, the
// server's relative order is preserved (a group takes the position of its
// highest-ranked member), and every member is one expand away. The distinction
// matters because anti-patterns.md bans re-deriving a paginated list's order or
// membership on the client, and this does neither.
//
// A group of ONE is not a group. The correlation is per-cluster and
// server-side, so a page can legitimately hold a single member of a group
// whose siblings sit past the fetch cap (or in a different cluster scope);
// collapsing that into a "1 sibling" parent row would spend a whole row saying
// nothing, and the row's own "Same workload" scope badge already states the
// fact. Whether the page is truncated is the CALLER's to state — see
// IncidentsPage's result count.
export type SingleIncidentRow = { kind: 'incident'; key: string; incident: Incident }

export type WorkloadGroupRow = {
  kind: 'workloadGroup'
  key: string
  groupId: string
  // Server order, preserved. incidents[0] is the member the active sort
  // ranked highest, which is what fixes the group's position in the list.
  incidents: Incident[]
}

export type IncidentListRow = SingleIncidentRow | WorkloadGroupRow

export function collapseWorkloadSiblings(incidents: Incident[]): IncidentListRow[] {
  const sizes = new Map<string, number>()
  for (const incident of incidents) {
    if (!incident.workloadGroupId) continue
    sizes.set(incident.workloadGroupId, (sizes.get(incident.workloadGroupId) ?? 0) + 1)
  }

  const rows: IncidentListRow[] = []
  const groupRowByID = new Map<string, WorkloadGroupRow>()
  for (const incident of incidents) {
    const groupID = incident.workloadGroupId
    if (!groupID || (sizes.get(groupID) ?? 0) < 2) {
      rows.push({ kind: 'incident', key: incident.id, incident })
      continue
    }
    const existing = groupRowByID.get(groupID)
    if (existing) {
      existing.incidents.push(incident)
      continue
    }
    const row: WorkloadGroupRow = { kind: 'workloadGroup', key: groupID, groupId: groupID, incidents: [incident] }
    groupRowByID.set(groupID, row)
    rows.push(row)
  }
  return rows
}

// parseWorkloadKey splits incidents.workload_key into the parts an identity
// block needs.
//
// TWO forms are on the wire, and assuming either one alone renders garbage for
// the other. internal/gateway/finding.go's workloadCorrelationKey builds
// `WorkloadGVK|namespace|WorkloadName` — the pipe form, the same convention as
// object_key. The development database also holds slash-form keys
// (`cl_.../apps/Deployment/default/checkout`, written by seeded fixtures), and
// a list cell should not depend on every producer having been correct — the
// same reasoning kindFromObjectGvk already carries for objectGvk.
//
// Returns empty strings rather than guessing when a part is genuinely absent;
// callers degrade line by line the way incidentIdentity does.
export function parseWorkloadKey(workloadKey: string | null | undefined): { kind: string; namespace: string; name: string } {
  const empty = { kind: '', namespace: '', name: '' }
  if (!workloadKey) return empty
  const piped = workloadKey.split('|')
  if (piped.length === 3) {
    return { kind: kindFromObjectGvk(piped[0]), namespace: piped[1], name: piped[2] }
  }
  const parts = workloadKey.split('/').filter(Boolean)
  if (parts.length === 0) return empty
  if (parts.length === 1) return { kind: '', namespace: '', name: parts[0] }
  if (parts.length === 2) return { kind: '', namespace: parts[0], name: parts[1] }
  return { kind: parts[parts.length - 3], namespace: parts[parts.length - 2], name: parts[parts.length - 1] }
}

// WorkloadGroupSummary is every fact a collapsed parent row renders, derived
// once so the row cannot claim two different things about the same group.
//
// The honesty rule that shapes this type: a parent row standing in for 13
// incidents must not assert a single value for a field the 13 disagree about.
// Where they agree, the row says the value; where they do not, it says so and
// the operator expands. `severity` is the exception and is deliberately the
// WORST of the group rather than a "mixed" — that matches the incident
// digest's own `maxSeverity` column and is the only aggregation that cannot
// under-state urgency.
export type WorkloadGroupSummary = {
  memberCount: number
  // Identity. workload_key and opening_reason are part of the grouping key
  // (internal/replicagroup.Recompute), so these are true of every member by
  // construction, not by an aggregation this file performs.
  name: string
  kind: string
  fault: string
  clusterId: string
  clusterDisplayName: string
  // Worst of the group, never an average. severityUnanimous says whether the
  // word on the row describes all of them or only the worst.
  severity: IncidentSeverity
  severityUnanimous: boolean
  // null when the members are in more than one state — the row says "Mixed"
  // rather than picking one. stateCounts is the breakdown, worst-first by
  // nothing in particular: insertion order, which is the server's order.
  state: IncidentState | null
  stateCounts: Array<{ state: IncidentState; count: number }>
  // undefined: not one member carries a route (the ordinary case for an
  // un-investigated workload). null: the members disagree. Otherwise the one
  // route they share.
  route: string | null | undefined
  // The SUM of the members' own detection counts — see DETECTION_COUNT_HEADER
  // for what one detection is. A true sum over the members present in this
  // page, which is why the caller marks it partial when the page is truncated.
  detectionCount: number
  // Newest last_seen / oldest first_seen across the members.
  lastSeen: string
  firstSeen: string
  // True when ANY member is also part of a fleet-wide group. Not "all" — the
  // claim is "this problem is also on other clusters", and one member is
  // enough to make it true.
  anyFleetGroup: boolean
  // True when any member is one an operator would be told to look at, so the
  // collapsed row can carry the same attention mark its members would.
  anyRequiresAction: boolean
}

export function workloadGroupSummary(row: WorkloadGroupRow): WorkloadGroupSummary {
  const members = row.incidents
  const first = members[0]
  const identity = parseWorkloadKey(first.workloadKey)

  let severity: IncidentSeverity = first.severity
  let severityUnanimous = true
  const stateOrder: IncidentState[] = []
  const stateTally = new Map<IncidentState, number>()
  let route: string | null | undefined
  let sawRoute = false
  let detectionCount = 0
  let lastSeen = first.lastSeen
  let firstSeen = first.firstSeen
  let anyFleetGroup = false
  let anyRequiresAction = false

  for (const incident of members) {
    if (incident.severity !== first.severity) severityUnanimous = false
    if (SEVERITY_RANK[incident.severity] < SEVERITY_RANK[severity]) severity = incident.severity
    if (!stateTally.has(incident.state)) stateOrder.push(incident.state)
    stateTally.set(incident.state, (stateTally.get(incident.state) ?? 0) + 1)
    if (incident.route) {
      if (!sawRoute) {
        route = incident.route
        sawRoute = true
      } else if (route !== incident.route) {
        route = null
      }
    }
    detectionCount += incident.occurrenceCount
    if (incident.lastSeen > lastSeen) lastSeen = incident.lastSeen
    if (incident.firstSeen < firstSeen) firstSeen = incident.firstSeen
    if (incident.fleetGroupId) anyFleetGroup = true
    if (incidentRequiresAction(incident.state)) anyRequiresAction = true
  }

  // A route only SOME members carry is a disagreement, not a shared route:
  // "these three go via a pull request and the other ten are unrouted" is not
  // "this group goes via a pull request", and rendering it as one would be a
  // claim about ten incidents nothing has routed.
  if (sawRoute && members.some((incident) => !incident.route)) route = null

  return {
    memberCount: members.length,
    name: identity.name || (first.objectName ?? first.fingerprint.slice(0, 8)),
    kind: [identity.kind, identity.namespace].filter(Boolean).join(' · '),
    fault: first.openingReason ?? '',
    clusterId: first.clusterId,
    clusterDisplayName: first.clusterDisplayName,
    severity,
    severityUnanimous,
    state: stateOrder.length === 1 ? stateOrder[0] : null,
    stateCounts: stateOrder.map((state) => ({ state, count: stateTally.get(state) ?? 0 })),
    route,
    detectionCount,
    lastSeen,
    firstSeen,
    anyFleetGroup,
    anyRequiresAction,
  }
}
