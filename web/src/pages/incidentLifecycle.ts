// The incident lifecycle rail's logic, split out of IncidentDetailPage.tsx.
//
// Pure functions only — no JSX. Two reasons this is its own module rather than
// page-local:
//
//  1. BACKLOG D8 A1 needed these testable. Exporting them from the page file
//     tripped react-refresh's only-export-components rule (fast refresh breaks
//     when a component module also exports plain functions), and the existing
//     page test's precedent is exporting *components*, not helpers.
//  2. D8 A7 (the progressive step view) rebuilds the rail's presentation. Having
//     the state derivation already separated from the markup is what makes that
//     a presentation change rather than a rewrite of both at once.
//
// The honesty invariant these carry is pinned by IncidentDetailPage.test.tsx:
// where two of them describe the same underlying fact, they must agree in
// strength. See explainStage and validateStage for the two instances that did
// not, and why.
import type { Analysis, IncidentAutomationGate, IncidentDetail, ObjectOwnership, RecentChange } from '../api/types'
import { executesForReal, incidentIdentity, STATE_LABEL } from '../utils/incidents'
import { formatRelativeTime } from '../utils/time'

export type ResolutionStageState = 'done' | 'current' | 'pending' | 'blocked' | 'unreachable'

// The four small display-only label tables below (OWNERSHIP_COPY,
// AUTOMATION_GATE_LABEL, RECENT_CHANGE_LABELS, ROUTE_LABEL) moved here from
// IncidentDetailPage.tsx (PROJECT.md T17) so incidentReport.ts's Markdown
// generator and the page's own on-screen rendering read the SAME copy for
// each closed set, rather than each holding its own copy that could drift —
// exactly the "two evaluations that agree today and disagree later" trap
// this module's header comment already warns about for the stage functions
// below. Moving them here (a pure, non-JSX, page-adjacent module both files
// already import from) rather than exporting them from the page module
// avoids a circular import between the page and its own report generator.

// Per-managing-system wording for ManagedByContext's notice and the "Fix it
// manually" revert caveat (IncidentDetailPage.tsx). Three explicit entries
// rather than one sentence with the system's name interpolated: what reverts
// the change, and where the durable version of it belongs, genuinely differ
// between the three, and this is the one place an operator needs the
// specific answer instead of a generic gesture at "GitOps".
export const OWNERSHIP_COPY: Record<
  ObjectOwnership['managedBy'],
  { badge: string; subject: (o: ObjectOwnership) => string; revert: string; fix: string }
> = {
  argocd: {
    badge: 'Argo CD',
    subject: (o) => ['Argo CD', o.sourceKind, o.sourceName].filter(Boolean).join(' '),
    revert: 'Argo CD reconciles that object back to what Git says, usually within seconds of a change made on the cluster.',
    fix: 'Make the same change in the manifest this app syncs from, and let Argo CD apply it.',
  },
  flux: {
    badge: 'Flux',
    subject: (o) => ['Flux', o.sourceKind, o.sourceName].filter(Boolean).join(' '),
    revert: 'Flux reconciles that object back to what Git says on its next sync.',
    fix: 'Make the same change in the source this app syncs from, and let Flux apply it.',
  },
  helm: {
    badge: 'Helm',
    subject: (o) => ['Helm release', o.sourceName].filter(Boolean).join(' '),
    revert: 'The next helm upgrade rewrites that object from the chart and drops whatever changed on the cluster in between.',
    fix: "Make the same change in this release's chart values, so it survives the upgrade.",
  },
}

// AUTOMATION_GATE_LABEL is a display-only mirror of the closed gate set
// (`IncidentAutomationGate['gate']` in api/types.ts, which itself mirrors
// internal/api/automation_gate.go's AutomationGate consts) — a short noun
// phrase for the badge only. It is never a substitute for `reason`, which is
// the exact sentence the enforcing sweeper wrote.
export const AUTOMATION_GATE_LABEL: Record<IncidentAutomationGate['gate'], string> = {
  severity_not_selected: 'Severity not selected',
  daily_spend_ceiling: 'Daily spend ceiling reached',
  no_ai_provider: 'No AI provider configured',
  cluster_unreachable: 'Cluster unreachable',
  namespace_scope: 'Namespace not allowed',
  maintenance_window: 'Outside maintenance window',
  circuit_breaker: 'Circuit breaker open',
  blast_radius: 'Unattended budget spent',
  batch_hold: 'Held for a batch wave',
  unattended_execution_disabled: 'Unattended execution disabled',
}

// PROJECT.md T15: a closed, small vocabulary for `RecentChange.category`,
// rendered as a label rather than the raw wire value — components.md's
// "never render a raw API identifier as a user-facing value" rule
// (IncidentBadges' own precedent). Deliberately NOT "image changed" or
// "replica count changed": the underlying fact is the controller's own
// account of what it did (a pull, a scale event), never a diff against a
// stored prior value ARGUS does not have — see getRecentChanges' own doc
// comment in internal/api/incidents.go for why a spec snapshot is never
// presented as a change.
export const RECENT_CHANGE_LABELS: Record<RecentChange['category'], string> = {
  created: 'Object created',
  rollout_created: 'New replica set/pod created',
  replica_change: 'Replica count changed',
  image_pull: 'Container image pulled',
  warning_event: 'Warning event',
}

// dedupeRecentChanges folds the same change seen by several tool calls into
// one row (the investigation often reads one object many times), keeping the
// latest sighting and counting the rest, in the server's order.
export function dedupeRecentChanges(items: RecentChange[]): Array<{ change: RecentChange; seen: number }> {
  const byKey = new Map<string, { change: RecentChange; seen: number }>()
  for (const c of items) {
    const key = [c.category, c.objectKind, c.objectNamespace, c.objectName, c.message].join('\u0000')
    const prev = byKey.get(key)
    if (prev) {
      prev.seen += 1
      if (c.time > prev.change.time) prev.change = c
    } else {
      byKey.set(key, { change: c, seen: 1 })
    }
  }
  return Array.from(byKey.values())
}

// The readable form of internal/resolution.Route's four wire values — never
// render the raw identifier (components.md's own rule; IncidentBadges.tsx
// established it after it was a real bug). Not a Record<Route, string>
// keyed by the union: IncidentDetail.route is nullable on the wire (an
// incident that predates routing, or was never investigated), so a plain
// string-keyed object is the right shape here — callers fall back to a
// generic label for any key this map doesn't have.
export const ROUTE_LABEL: Record<string, string> = {
  pullRequest: 'Pull request',
  inPlace: 'In place',
  'pullRequest+inPlace': 'Both routes',
  guidance: 'Guidance only',
}

// A closed set of short, readable names for the MCP tools the investigation
// loop can call (llm.InvestigationToolSchemas) — used by EvidenceGathered's
// per-tool breakdown, RecentChangeNode's source label, and, since PROJECT.md
// T17, incidentReport.ts's Markdown generator. Not a closed TypeScript union:
// the tool surface is defined in Go and grows there, so an unrecognised key
// still has to render (see the fallback in toolLabel below) rather than break.
export const TOOL_LABELS: Record<string, string> = {
  get_events: 'events',
  get_logs: 'pod logs',
  describe_resource: 'describe resource',
  list_resources: 'list resources',
  get_owner_chain: 'owner chain',
  get_gitops_ownership: 'GitOps ownership',
}

export function toolLabel(tool: string) {
  return TOOL_LABELS[tool] ?? tool.replace(/^get_/, '').replace(/_/g, ' ')
}

export function latestFinding(findings: IncidentDetail['findings']) {
  return findings.reduce<IncidentDetail['findings'][number] | null>((latest, finding) => {
    if (!latest) return finding
    return new Date(finding.occurredAt).getTime() > new Date(latest.occurredAt).getTime() ? finding : latest
  }, null)
}

// resolvedIdentity/faultLine — moved out of IncidentDetailPage.tsx's own
// render body (PROJECT.md T17) so incidentReport.ts's Markdown generator
// names an incident exactly the way the page's own heading does, from one
// function instead of two copies of the same fallback chain.
//
// Shared with IncidentsPage via utils/incidents.incidentIdentity so one
// incident does not get two names in two places; THIS wrapper additionally
// falls back to the latest FINDING when the incident row names no object
// (IncidentsPage has no findings to fall back to, only the Incident row —
// see incidentIdentity's own callers). Seen live: an incident whose
// objectName/objectGvk were empty rendered "Incident b49a1f48" as its
// heading, while the Detection card immediately below it showed
// `v1/Pod argus-gitops-rke2/nolimits-6679f7f545-w2xmp` from the finding —
// the identity was one field away and the page showed a hash anyway.
export function resolvedIdentity(incident: IncidentDetail): { name: string; kind: string; fault: string; faultLine: string } {
  const finding = latestFinding(incident.findings)
  const fromIncident = incidentIdentity(incident)
  const identity = (() => {
    if (incident.objectName || !finding) return fromIncident
    const kind = finding.gvk?.split('/').pop() ?? ''
    return {
      name: finding.objectName || fromIncident.name,
      kind: [kind, finding.namespace].filter(Boolean).join(' · ') || fromIncident.kind,
      fault: finding.reason || fromIncident.fault,
    }
  })()
  // The plain-English fault, preferring the finding's own message over the
  // opening reason: the message says what actually happened, the reason only
  // names the category.
  const faultLine = finding?.message ?? identity.fault ?? ''
  return { ...identity, faultLine }
}

// explainSummary was here. Deleted rather than left exported-and-unused: it was
// a SECOND derivation of exactly what ConclusionBlock renders — the root-cause
// statement, or the partial reason, or "not run yet" — and the stage-2 card
// printed both, one under the other. Two functions computing one sentence is the
// setup for them to disagree, which is the failure the rest of this module is
// organised to prevent; one of them had to go, and ConclusionBlock is the one
// that handles a complete row with a null rootCause.

// The "no plan, and there never will be one" case — the distinction between
// "not yet" and "never" that the stages below key off.
//
// A *complete* analysis that proposed no plan is this pipeline's most common
// ending, not a step still in flight: of ten fault types driven end to end
// against a real cluster, exactly one had a fix ARGUS could execute. That is
// structural rather than a gap waiting to be filled — internal/remediation's
// ActionType set is ScaleDeployment/RestartPod/OpenPR, and OpenPR is only ever
// recorded, never executed (executesForReal above). So every fault whose real
// fix is a manifest or cluster change (wrong image tag, missing ConfigMap, bad
// resource units, no StorageClass) correctly yields no plan, and the operator
// needs to be told the loop is done, not that approval is coming.
//
// status 'partial' is deliberately excluded: that run hit an iteration or time
// bound, so re-analysing genuinely can still produce a plan. That one is the
// real "not yet".
export function noExecutableFix(analysis: Analysis | null): boolean {
  return analysis?.status === 'complete' && !analysis.plan
}

export function nextActionSummary(incident: IncidentDetail) {
  const analysis = incident.analysis
  if (!analysis) return 'Run an investigation to gather live evidence and build the causal chain.'
  if (analysis.status === 'partial') return 'Review the partial evidence and suggested next checks before acting.'
  const plan = analysis.plan
  if (!plan) {
    // Two different situations, and only the first one is finished. A recorded
    // root cause with no plan means the investigation succeeded and the fix is
    // simply outside what ARGUS executes, so this says what to do instead of
    // waiting. No root cause means the investigation itself came up empty (a
    // complete row can carry none — see CompleteAnalysis's doc comment), and
    // asserting a cause that isn't there is exactly the kind of definite claim
    // this app avoids elsewhere.
    // A linked repository changes the answer, and forgetting that produced a
    // straight contradiction on screen: this sentence said "apply that change
    // yourself" while the panel immediately below it offered a working "Propose
    // this fix as a pull request" button, because the branch above only ever
    // looked at `plan` — the IN-PLACE executable plan — and never at whether the
    // pull-request route was open. A reader believes the discouraging sentence
    // and goes off to do by hand what ARGUS was offering to do for them.
    //
    // "No executable plan" and "nothing ARGUS can do" are different facts. The
    // first is about patching the live object; the second is only true when the
    // source route is closed too.
    if (incident.ownership?.repo) {
      return analysis.rootCause
        ? 'ARGUS cannot patch the live object — no action in its fixed set expresses this change — but this workload is managed from a linked repository, so it can prepare the change as a pull request for you to review. Options are below.'
        : 'The investigation finished without a recorded root cause. This workload is managed from a linked repository, so a pull request can still be prepared by hand from the evidence below.'
    }
    return analysis.rootCause
      ? 'ARGUS identified a cause but cannot fix it automatically: no action in its fixed set expresses this change, and this needs a manifest or cluster change. No repository is linked for this workload, so if a change is needed, it is yours to make.'
      : 'The investigation finished without a recorded root cause or a proposed remediation — review the evidence below, or re-analyze.'
  }
  // BACKLOG.md D9 B8: framed as a GATE's own words, not a bare sentence —
  // this printed unframed on this page up to three times for one blocked
  // plan (here, in RemediationPlanCard's "Gate: Blocked" dt/dd pair, and in
  // approveStage's text below), and this occurrence and approveStage's own
  // carried no word "gate" at all, reading as ARGUS's own verdict rather
  // than a specific mechanism refusing something.
  if (plan.gateOutcome === 'Blocked') return `Blocked by ARGUS's gate: ${plan.gateReason}`

  // Checked before plan.execution below: a Reopened incident still carries
  // its old (now-stale) "succeeded" execution outcome — the fix really did
  // apply, it just didn't hold — so this has to take priority or the copy
  // would keep claiming success after ARGUS itself already detected the
  // opposite.
  //
  // Deliberately does NOT say "this recurred", which was true when only one
  // path could reopen an incident and is now wrong half the time. There are
  // two:
  //
  //   - internal/gateway/finding.go's handleFinding: this incident's own
  //     fingerprint recurred while Validating.
  //   - internal/orchestrator/validation.go's siblingStillFailing: another pod
  //     of the same workload is still failing since the fix. Here this
  //     incident's own object usually no longer EXISTS — a fix that patches a
  //     pod template rolls the pods away — so telling an operator it recurred
  //     sends them looking for a recurrence on a pod that is gone.
  //
  // The workloadGroupId callout further down the page ("also happening on
  // other pods of the same workload") is where they find the sibling, so this
  // sentence only has to stop asserting the wrong cause.
  if (incident.state === 'Reopened') {
    return 'The fault this fix targeted is still happening — either this exact symptom recurred, or another pod of the same workload is still failing. The remediation did not resolve the underlying problem; re-investigate before trying again.'
  }
  if (plan.execution) {
    if (plan.execution.outcome === 'succeeded') {
      return 'The remediation executed successfully — confirmed no recurrence yet, but this is not a positive re-check, only an absence of new findings.'
    }
    // BACKLOG.md C8 / BUGS.md 104: told apart from a confirmed failure —
    // the tunnel call's own result was indeterminate and a follow-up
    // verify couldn't resolve it either way, so "review the cause before
    // re-approving" (which presumes the fix did NOT happen) would be as
    // dishonest as the false "failed" this fix replaces.
    if (plan.execution.outcome === 'unknown') {
      return `The outcome of this execution could not be confirmed: ${plan.execution.error ?? 'the connection was lost while awaiting a result'}. Check the cluster directly before deciding whether to re-approve — the change may already have applied.`
    }
    return `Execution failed: ${plan.execution.error ?? 'unknown error'}. Review the cause before re-approving.`
  }
  // This line is the page's "what happens next", so a bare "Rejected: <reason>"
  // is not enough — it states a past decision and leaves the reader to assume
  // the incident was dealt with, which is the assumption the old
  // AwaitingApproval -> Dismissed transition made for them. The reason is
  // repeated here rather than left to the Recommendation card below because it
  // is the whole basis of the next decision: whoever reads this next has to
  // know a fix was proposed and why it was refused before proposing another.
  if (plan.approval?.verdict === 'rejected') {
    const who = plan.approval.actorEmail ? ` by ${plan.approval.actorEmail}` : ''
    const why = plan.approval.reason ? `: ${plan.approval.reason}` : '.'
    return `The proposed fix was rejected${who}${why} Nothing was executed, so the fault is unchanged — re-analyse for a different plan, propose one at the source, or close this incident out.`
  }
  if (incident.state === 'Executing') return 'ARGUS is executing the approved remediation now.'
  // Checked before every "go and approve it" line below, because in this state
  // approving is refused: the fix is a pull request ARGUS already opened, and the
  // in-place plan was derived from the cluster as it was before that. Telling
  // someone to approve something the API will 409 is worse than saying nothing.
  if (incident.state === 'AwaitingMerge') {
    return 'ARGUS has proposed the durable fix as a pull request — it takes effect when that is merged and the GitOps controller syncs it. The in-place plan below cannot be approved while that is pending, because it was derived from the cluster as it was before the fix.'
  }
  if (!executesForReal(plan)) {
    // BACKLOG.md D9 B4: this promised field-level verification ("verifies the
    // edit changes exactly the intended field") that has been false since the
    // whole-file repository-change grammar shipped 2026-08-28 — there is no
    // longer a single field to verify, only whole files (internal/api/
    // repository_change.go's own header comment, and changeCaveat there:
    // "makes NO claim that only the intended thing changed — review each
    // diff as carefully as you would review a hand-written patch"). Rewritten
    // to match what the channel actually guarantees today: a computed diff
    // for a human to review, not a proof of minimality.
    return 'ARGUS proposes this as a change to the repository the object came from, not as an in-place patch — use "Propose this fix as a pull request" above, which computes the diff against the file(s) as they are today for you to review before anything is opened. It does not verify that only the intended thing changed.'
  }
  // BACKLOG D8 A8 (ask 1): this used to send the reader elsewhere ("review it
  // in the approval queue") — the exact sentence the owner named as the bug,
  // because the decision now also lives right here, at stage 4, below.
  if (plan.gateOutcome === 'NeedsApproval') return 'Review the recommended remediation below — approving it executes it immediately.'
  // The remaining gate outcome is AutoApprove, and what happens next now depends
  // on a setting this component cannot see: with unattended execution enabled
  // (Settings, off by default) the sweeper may execute this without anyone
  // clicking, bounded by the blast-radius cap. So the copy states what is true
  // either way rather than promising a human will be involved — the previous
  // wording ("ARGUS never executes without a human") became false the day that
  // setting shipped.
  return 'The gate auto-approved this, so it is ready to run: approve it in the queue, or — if unattended execution is enabled for this installation — it runs on its own within the blast-radius cap.'
}

// executeStage/validateStage compute the last two resolution-path stages
// from the plan's real approval/execution state — these used to be
// hardcoded to "blocked"/"pending" with a permanent "not implemented" label
// (true before today), which would now be actively misleading for the two
// action types that really do execute.
//
// Both take the whole incident rather than (plan, state): each now needs the
// analysis too, to tell a plan that hasn't been proposed *yet* from one that
// never will be (noExecutableFix above).
//
// OpenPR gets its own branch in each rather than falling into the
// executesForReal(plan)-is-false case below: that check is still correct for
// its original purpose (does this plan run through the in-place
// patch-and-validate pipeline — see explainWhyInPlaceCannotBeApproved above),
// but approving an OpenPR plan really does open a pull request in the same
// call (internal/api/approvals.go's approveByOpeningPullRequest) — "not
// implemented" stopped being true the day that shipped, and kept being shown
// here anyway.
// explainStage — lifecycle step 2, the investigation.
//
// Keyed on analysis.status, NOT on `analysis != null`. The previous version was
// `analysis ? 'done' : 'current'`, which painted step 2 green the moment any
// analysis row existed — including a PARTIAL run, which AnalysisConclusion
// (reading the same analysis.status, thirty lines further down the same page)
// simultaneously labelled "Investigation incomplete" in amber. One fact, two
// strengths, one screen; a reader resolves that in favour of the green tick.
//
// Both now branch on the same discriminator, so they cannot drift apart without
// someone editing both — which is the point of deriving it once here rather than
// keeping two branches in step by memory.
//
// 'current' for a partial run, and the two states it is deliberately NOT are
// worth recording, because the first attempt at this fix got it wrong:
//
//   NOT 'blocked'. That renders --danger red with a filled red dot, and every
//   other use of 'blocked' in this file is a genuine failure or refusal —
//   Rejected, Failed, Recurred, gate Blocked, no execution path. A partial
//   investigation is none of those; it ran out of budget. Worse, red would
//   contradict AnalysisConclusion's AMBER "Investigation incomplete" badge for
//   the same fact — reintroducing the exact one-fact-two-strengths defect this
//   function exists to remove, just in the other direction.
//
//   NOT 'unreachable'. That is a dashed, muted dot meaning "this is not going
//   to happen" (index.css's own comment), and re-analyzing a partial run
//   genuinely can finish it.
//
// 'current' is the honest answer: the rail's vocabulary is green behind you,
// blue where you are, outlined ahead — and a partial investigation means you
// have not moved past this step. A partial run and a not-yet-started one share
// the state because in both cases the explain step is where the operator is;
// the step's own text is what distinguishes them.
//
// Exported for IncidentDetailPage.test.tsx, which pins the agreement above.
export function explainStage(analysis: Analysis | null): { state: ResolutionStageState; text: string } {
  if (!analysis) return { state: 'current', text: 'Investigation is the next step' }
  const steps = `${analysis.causalChain.length} evidence step${analysis.causalChain.length === 1 ? '' : 's'} gathered`
  // The evidence count alone is true of a partial run too, which is exactly how
  // it sat under a green tick unchallenged. The suffix is what makes the step's
  // own text disagree with a "done" reading.
  if (analysis.status === 'complete') return { state: 'done', text: steps }
  return { state: 'current', text: `${steps} — stopped before reaching a conclusion` }
}

export function executeStage(incident: IncidentDetail): { state: ResolutionStageState; text: string } {
  const plan = incident.analysis?.plan ?? null
  const incidentState = incident.state
  // BACKLOG.md D9 B5/B6: ExecutionUnknown and Failed can each be reached with
  // no execution row at all for this branch's later checks to key off — with
  // none, the branches below fell through to whatever they hit last: for
  // ExecutionUnknown that was the generic "Waiting for approval" at the very
  // end (a plan the gate is still waiting on, which is not what happened —
  // ARGUS already ran something and lost track of the result), and for
  // Failed it was `!plan`'s "No remediation to execute yet" (which reads as
  // nothing having happened at all, when in fact something failed outside
  // whatever got recorded). Checked first and honestly, against
  // incident.state rather than only plan.execution.outcome, so a real red
  // badge or a real "outcome unknown" state is never explained by a sentence
  // that contradicts it.
  if (incidentState === 'ExecutionUnknown' && !plan?.execution) {
    return {
      state: 'blocked',
      text: 'Outcome unknown: ARGUS could not confirm whether this executed, and kept no execution record to say more — check the cluster directly before deciding whether to re-approve.',
    }
  }
  if (incidentState === 'Failed' && !plan?.execution) {
    return {
      state: 'blocked',
      text: "This incident is marked Failed, but ARGUS kept no execution record to explain what happened — check the cluster and this incident's history directly.",
    }
  }
  if (!plan) {
    return noExecutableFix(incident.analysis)
      // Says what ARGUS cannot do, not what the fault needs. The previous
      // wording — "fixing this needs a manifest or cluster change ARGUS
      // cannot make" — asserts that a fix is required, which this branch
      // cannot know: it is also reached when the investigation concluded
      // nothing is wrong, and when a transient fault had already cleared.
      // Same correction as validateStage below; see PROJECT.md T4.
      ? {
          state: 'unreachable',
          text: 'Nothing for ARGUS to execute — it proposed no change it can apply to the live object',
        }
      : { state: 'pending', text: 'No remediation to execute yet' }
  }
  // BACKLOG.md D9 B8: framed as a GATE's own words, not a bare sentence — see
  // approveStage's identical framing below for why (this is one of the two
  // occurrences that used to render `plan.gateReason` unframed).
  if (plan.gateOutcome === 'Blocked') return { state: 'blocked', text: `Blocked by ARGUS's gate: ${plan.gateReason}` }
  if (plan.actionType === 'OpenPR') {
    // Opening the pull request IS this plan's execution, and it happens
    // inside the same approval call — there is no separate pending-then-run
    // step the way ScaleDeployment/RestartPod have one.
    if (plan.approval?.verdict === 'rejected') return { state: 'blocked', text: 'Rejected before a pull request was opened' }
    // BACKLOG.md D9 B3: checked BEFORE the approved/AwaitingMerge branch
    // below, which used to be the only thing this looked at — so a pull
    // request that was approved, opened, and then closed unmerged
    // (incident.pullRequest.closedUnmergedAt, migration 000060) kept
    // reading "Pull request opened" here, in green, forever — a direct,
    // on-page contradiction of RepositoryChangePanel's own "Closed without
    // merging" a few inches below it. mergewatch.go returns the incident to
    // AwaitingApproval when this happens, so the honest state here is
    // 'blocked' (this attempt did not reach a durable outcome), matching
    // Rejected's own state just above rather than the 'done' this used to
    // share with a genuinely merged/pending pull request.
    if (incident.pullRequest?.closedUnmergedAt) {
      return { state: 'blocked', text: 'The pull request was closed without merging — back in the approval queue for a fresh attempt' }
    }
    // PROJECT.md B160: this used to recognise "done" only from the approval
    // decision row (plan.approval?.verdict === 'approved') or the transient
    // AwaitingMerge state itself. Neither survives the merge: MergeSweeper
    // moves a merged PR's incident on into Validating, and ValidationSweeper
    // moves it on again into Resolved — and remediation_approval_decisions
    // held ZERO rows for every live PR-route incident on this dev stack when
    // this was diagnosed (approveByOpeningPullRequest logs a failed insert
    // there rather than failing the request — see its own doc comment — so
    // the decision row is best-effort bookkeeping, not a load-bearing record
    // of "did this merge"). So a merged, Resolved incident fell all the way
    // through to the final pending/"Waiting for approval" below, rendered
    // directly above PullRequestRecord showing that very same pull request,
    // merged — a direct on-page contradiction, observed live on
    // inc_01m20nrjgf99axm8tpgrbb406j.
    //
    // incident.pullRequest is the durable, per-incident record
    // MergeSweeper/ValidationSweeper themselves write to (pr_merged_at, set
    // atomically with the state transition — see mergewatch.go), so it is
    // read directly here rather than only through the decision row this
    // deployment shows is not reliably written.
    //
    // Still gated on incidentState, rather than trusting incident.pullRequest
    // alone: that field is one record per INCIDENT, not per plan, so an
    // incident that reopened, was re-analysed, and is back at
    // AwaitingApproval on a genuinely new, undecided plan must not read as
    // "done" off a stale pull request from the cycle before it. Resolved is
    // checked against incident.resolutionKind rather than bare state for the
    // same reason validateStage reuses it above: it is the backend's own
    // already-unified "did this merge close it" answer, computed once, at
    // the moment this (terminal) state was entered — not re-derived from a
    // field that could be stale by the time anyone reads it back.
    if (
      plan.approval?.verdict === 'approved' ||
      incidentState === 'AwaitingMerge' ||
      incidentState === 'Validating' ||
      (incidentState === 'Resolved' && incident.resolutionKind === 'remediated')
    ) {
      return incident.pullRequest?.mergedAt
        ? { state: 'done', text: 'Pull request merged' }
        : { state: 'done', text: 'Pull request opened' }
    }
    return { state: 'pending', text: 'Waiting for approval' }
  }
  if (!executesForReal(plan)) return { state: 'blocked', text: 'This action type has no automatic execution path' }
  if (plan.approval?.verdict === 'rejected') return { state: 'blocked', text: 'Rejected before execution' }
  if (plan.execution) {
    if (plan.execution.outcome === 'succeeded') return { state: 'done', text: 'Change applied to the cluster' }
    // BACKLOG.md C8 / BUGS.md 104: still 'blocked' (this stage did not
    // cleanly complete, matching the same "genuinely unknown" precedent
    // validateStage's Reopened-with-no-record branch already uses below) —
    // but the TEXT must never say "Failed", which would repeat exactly the
    // false negative this fix exists to stop asserting.
    if (plan.execution.outcome === 'unknown') {
      return { state: 'blocked', text: `Outcome unknown: ${plan.execution.error ?? 'could not confirm whether the change applied'}` }
    }
    return { state: 'blocked', text: `Failed: ${plan.execution.error ?? 'unknown error'}` }
  }
  if (incidentState === 'Executing') return { state: 'current', text: 'Executing now…' }
  return { state: 'pending', text: 'Waiting for approval' }
}

export function validateStage(incident: IncidentDetail): { state: ResolutionStageState; text: string } {
  const plan = incident.analysis?.plan ?? null
  const incidentState = incident.state
  if (plan?.execution?.outcome === 'failed') return { state: 'blocked', text: 'Execution failed before reaching validation' }
  // BACKLOG.md C8 / BUGS.md 104: checked separately from the confirmed
  // failure above — an indeterminate outcome never reaches Validating
  // either (orchestrator.StateExecuting's only edges are Validating,
  // Failed, ExecutionUnknown), but the text must say so honestly rather
  // than implying a confirmed failure stopped it.
  if (plan?.execution?.outcome === 'unknown') {
    return { state: 'blocked', text: `Outcome unknown before reaching validation: ${plan.execution.error ?? 'could not confirm whether the change applied'}` }
  }
  // Reopened is this stage's own negative outcome — checked before
  // 'Validating' below since an incident passes through Validating on its
  // way to either Resolved or Reopened; by the time it's Reopened, this
  // stage's real answer is "recurred," not "still waiting."
  if (incidentState === 'Reopened') {
    // "The fix did not hold" is a definite claim, and it was wrong in the very
    // case this branch was written for. Correlation runs at the WORKLOAD tier
    // when a Pod's owner is known (gateway.correlationIdentity.tier), so every
    // Pod of a Deployment shares one incident — which means a merged fix can
    // hold perfectly and the incident still reopen because a DIFFERENT Pod of
    // that workload started failing.
    //
    // Observed live on inc_01m0xfwwjjgk1hexrsnqc00m7e: the incident's own Pod
    // stopped reporting at the exact minute the pull request merged and was
    // replaced by a healthy one; the replacement Pod then reported a different
    // fault, correlated onto the same incident, and reopened it. Every layer
    // said the fix had failed. It had not — and the operator reasonably believed
    // the product over the cluster.
    //
    // The two cases are now told apart using the object the reopen actually
    // named (`reopenedBy`, computed hub-side from the ValidationOutcome timeline
    // event so one place owns the comparison). Where the answer is unknown — an
    // incident reopened before the timeline existed — this says only that it
    // recurred, which is all it can honestly say.
    const cause = incident.reopenedBy
    if (cause && !cause.sameObject) {
      const who = cause.objectName ?? 'another object'
      return {
        state: 'blocked',
        text: `Reopened by a different object in this workload — ${who}${cause.reason ? ` (${cause.reason})` : ''}. The object this fix targeted stopped reporting, so this is a separate failure rather than a regression of the fix.`,
      }
    }
    if (cause?.sameObject) {
      return {
        state: 'blocked',
        text: `Recurred on the same object — the fix did not hold${cause.reason ? ` (${cause.reason})` : ''}`,
      }
    }
    return { state: 'blocked', text: 'Recurred while validating — no record of which object, so whether the fix held is unknown' }
  }
  if (incidentState === 'Resolved') {
    // Only ValidationSweeper's Validating → Resolved promotion earns the "no
    // recurrence in the re-check window" claim, and that path is reachable
    // only after a successful execution OR a merged pull request
    // (internal/orchestrator/state.go's allowedTransitions — MergeSweeper
    // moves AwaitingMerge to Validating once a PR merges, and from there
    // ValidationSweeper treats it exactly like an in-place fix, per
    // mergewatch.go's own comment). Checking plan?.execution?.outcome alone
    // used to miss the PR channel entirely: a merged fix has nothing in
    // `execution` (nothing ran in-place), so this branch fell through to the
    // human-close-out text below even though ARGUS proposed and merged the
    // fix — see BUGS.md for the report. incident.resolutionKind is the
    // backend's own already-unified answer to "did ARGUS's remediation have
    // anything to do with this" (internal/orchestrator/db.go's
    // deriveResolutionKind: a succeeded execution row OR pr_merged_at), so
    // it is reused here rather than re-deriving the OR by hand. Resolved
    // with resolutionKind 'self_healed' is therefore a human close-out via
    // POST /incidents/{id}/resolve, or the symptom stopping on its own —
    // ARGUS re-checked nothing, and claiming a validation window it never
    // ran would credit the product with the operator's own work.
    // "Confirmed resolved" was the wording here and it overstated what the
    // sweeper did. ValidationSweeper observes an ABSENCE — no new findings
    // arrived during the window — which is not the same as re-checking that the
    // symptom cleared. This page's own nextActionSummary already says so of the
    // identical state ("not a positive re-check, only an absence of new
    // findings"), so the rail was contradicting the summary about one fact.
    // Both now describe the absence, and neither claims a confirmation.
    return incident.resolutionKind === 'remediated'
      ? { state: 'done', text: 'Resolved — no new findings during the re-check window' }
      // NOT "closed by hand". resolutionKind is derived, not chosen: any
      // transition into Resolved with no succeeded execution and no merged
      // pull request is stamped self_healed, whether a person clicked Resolve
      // or the stale-object sweeper closed it automatically. Measured
      // 2026-09-09: all 11 self_healed closures in the dev database had NO
      // human actor in their timeline at all — every one was the sweeper — so
      // the old wording was false for exactly the population it described.
      // This matches RESOLUTION_KIND_EXPLANATION.self_healed, which already
      // got it right.
      : {
          state: 'done',
          text: 'Closed with no ARGUS fix linked — the symptom stopped, or somebody closed it; either way there was nothing to validate',
        }
  }
  // Dismissed is terminal and deliberate: someone recorded that a real problem
  // will not be acted on. Nothing is pending here either, so this is the same
  // "never" as the no-executable-fix case below, not a wait.
  // Says nothing was VALIDATED, not that nothing was applied. allowedTransitions
  // lets Dismissed follow ExecutionUnknown and ValidationUnknown, and both of
  // those mean a change reached the cluster — ValidationUnknown explicitly
  // means "applied, and we could not confirm it". The old wording claimed no
  // fix was applied, which is false on exactly those two paths.
  if (incidentState === 'Dismissed') {
    return { state: 'unreachable', text: 'Dismissed — closed without validating the outcome' }
  }
  // PlanRejected reaches the same conclusion for the opposite reason: a fix was
  // proposed and a person refused it, so nothing was applied and there is
  // nothing to watch. 'unreachable', not 'pending' — this is not a wait, and
  // showing it as one would imply ARGUS is going to do something next when the
  // next move is entirely a human's.
  if (incidentState === 'PlanRejected') {
    return { state: 'unreachable', text: 'Nothing to validate — the proposed fix was refused, so nothing was applied' }
  }
  if (incidentState === 'Validating') return { state: 'current', text: 'Watching for recurrence — auto-resolves if none shows up' }
  if (incidentState === 'AwaitingMerge') {
    // internal/orchestrator.MergeSweeper polls this incident's pull request
    // and moves it to Validating itself once the provider reports it merged
    // AND the GitOps controller has synced past the merge commit — see
    // mergewatch.go. Until then this is a real wait, not ARGUS being idle.
    return {
      state: 'current',
      text: 'Awaiting merge — checked automatically; moves to validation once the pull request merges and the GitOps controller syncs it',
    }
  }
  if (!plan && noExecutableFix(incident.analysis)) {
    // Deliberately does NOT say "apply the fix yourself, then mark this
    // incident resolved", which is what stood here until 2026-09-09. That
    // instruction is false in two real cases this branch also covers: an
    // investigation that concluded nothing is wrong at all (the model's
    // isFault verdict), and a transient fault that had already cleared by the
    // time anyone read the analysis — two live examples on 2026-09-09,
    // gwas-frontend and gwas-db, both Multi-Attach during a rolling update,
    // both healthy again, both being told to go apply a fix. Neither had
    // anything to apply.
    //
    // What IS true in every case this branch reaches: ARGUS applied nothing,
    // so it has nothing of its own to re-check. Saying that, and leaving the
    // judgement to the operator, is honest for all three sub-cases at once.
    // Distinguishing them properly needs the isFault verdict persisted and
    // exposed — PROJECT.md T4.
    return {
      state: 'unreachable',
      text: 'Nothing for ARGUS to validate — it applied no change of its own, so there is nothing to re-check. Close this out when you are satisfied',
    }
  }
  return { state: 'pending', text: 'Nothing to validate yet' }
}


// Whether the fix will actually hold. ARGUS can patch a live object, and on a
// Helm- or GitOps-managed one that patch lasts until the next upgrade or
// reconcile and then vanishes, bringing the incident back with it. The
// investigation already establishes this (it calls get_gitops_ownership, and it
// reads the object's own Helm metadata), but until now the fact reached only the
// model, never the person deciding whether to apply the fix.
//
// Rendered ONCE, at the foot of this panel, rather than here and again inside
// RemediationPlanCard. This panel is always on the page, which matters because
// most incidents never produce a plan at all — "apply the manifest change
// yourself" is the most common outcome and the case where this caveat is worth
// the most — and it is also where the approve stage and the approvals link live.
// The same warning twice on one page reads as decoration.
//
// Showing nothing when ownership is null is the contract rather than a fallback:
// see ObjectOwnership in api/types.ts for why a warning over an object nothing
// manages would be the expensive mistake here.

// recommendStage — lifecycle step 3.
//
// 'unreachable', not 'done', in the no-fix case even though this step really did
// run to completion: a green "done" beside "no fix" reads as though a
// recommendation was produced. 'unreachable' says the chain stops here.
export function recommendStage(incident: IncidentDetail): { state: ResolutionStageState; text: string } {
  const analysis = incident.analysis
  const plan = analysis?.plan ?? null
  const noFix = noExecutableFix(analysis)
  const state: ResolutionStageState = !analysis ? 'pending' : plan ? 'done' : noFix ? 'unreachable' : 'current'
  const text = plan
    ? plan.summary
    : !analysis
      ? 'Waiting for analysis'
      : noFix
        ? 'No automatically-executable fix — no action in the fixed set ARGUS can execute expresses this change'
        : 'The investigation stopped early — re-analyze to try for a plan'
  return { state, text }
}

// approveStage — lifecycle step 4.
export function approveStage(incident: IncidentDetail): { state: ResolutionStageState; text: string } {
  const analysis = incident.analysis
  const plan = analysis?.plan ?? null
  const noFix = noExecutableFix(analysis)
  const state: ResolutionStageState =
    plan?.approval?.verdict === 'approved'
      ? 'done'
      : plan?.approval?.verdict === 'rejected'
        ? 'blocked'
        : plan?.gateOutcome === 'Blocked'
          ? 'blocked'
          : plan?.gateOutcome === 'NeedsApproval' || incident.state === 'AwaitingApproval'
            ? 'current'
            : noFix
              ? 'unreachable'
              : 'pending'
  const text = plan?.approval
    ? plan.approval.verdict === 'approved'
      ? `Approved${plan.approval.actorEmail ? ` by ${plan.approval.actorEmail}` : ''} · ${formatRelativeTime(plan.approval.createdAt)}`
      : `Rejected${plan.approval.actorEmail ? ` by ${plan.approval.actorEmail}` : ''}${plan.approval.reason ? `: ${plan.approval.reason}` : ''}`
    : plan
      // BACKLOG.md D9 B8: framed with the gate's own outcome, not a bare
      // sentence — see nextActionSummary's identical framing above for the
      // Blocked-only case; this occurrence also covers NeedsApproval/
      // AutoApprove (no decision recorded yet), where "gate" still needs
      // naming even though nothing was refused.
      ? `Gate (${plan.gateOutcome}): ${plan.gateReason}`
      : noFix
        ? 'Nothing to approve — ARGUS proposed no executable remediation'
        : 'No remediation to approve yet'
  return { state, text }
}

// detectStage — lifecycle step 1. Always done: the incident exists because
// something was detected.
export function detectStage(incident: IncidentDetail): { state: ResolutionStageState; text: string } {
  const finding = latestFinding(incident.findings)
  return {
    state: 'done',
    text: finding ? `${finding.reason} on ${finding.namespace}/${finding.objectName}` : 'Incident recorded',
  }
}

// lifecycleSteps — the six rail steps as data, so the rail component is markup
// only and the pairing of label → state → meta is unit-testable.
//
// `meta` is the second line under each dot in the reviewed Option B mock
// (`OptionB.dc.html`, "ARGUS Incident Screen Options"): "22m ago · sweep",
// "4 steps · 38s", "not reached". It is deliberately NOT each stage's `text` —
// that is the full sentence the stage's own box already carries, and repeating
// it here is exactly the "a second, narrower copy of the page" failure the rail
// was cut back from once already. The rule this keeps to: a meta is at most a
// few words, and every one of them is a fact already on the payload — a count,
// a route, a timestamp, or the plain name of a state. Nothing here asserts
// anything the box below it does not.
//
// The `unreachable` metas say "not applicable" rather than "not reached":
// the chain stops at that step for this incident, and "not reached" would read
// as a wait that will eventually end.
export interface LifecycleStep {
  n: number
  label: string
  state: ResolutionStageState
  meta: string
  // The plain-English question this stage answers — "What broke", "Why it
  // broke". Two to four words, never a sentence.
  //
  // It lives HERE, on the step, because two surfaces render it and they must
  // not each carry their own copy: the rail chip (so the strip says what you
  // will learn at each stop rather than only how far the incident got) and the
  // stage card's own heading. Before this it was five string literals passed
  // as props at the StageCard call sites and a sixth computed inline, with the
  // rail showing neither — so the rail and the cards could not agree, because
  // the rail had nothing to agree with.
  //
  // Stage 5's is the one that varies (a merge and a sync are not an execute
  // and a wait), which is the other reason this is computed alongside the
  // states rather than hardcoded per call site: the fact it varies on is the
  // plan, which lifecycleSteps already has.
  question: string
}

// nothingWasExecuted reports whether this incident never reached execution at
// all — no approval to give, nothing applied, nothing to validate.
//
// # Why this exists (PROJECT.md D13)
//
// It is the MAJORITY case, not an edge case: measured 2026-09-09, 146 of 192
// completed analyses ended in Diagnosed, and every one of those rendered three
// separate cards — Approve, Apply, Validate — each with its own heading and
// its own sentence, to communicate one fact between them: nothing ran. Three
// boxes of negative space on three incidents in four, on a page whose job is
// to make troubleshooting faster.
//
// A caller that gets true here should render ONE line in place of those three
// cards. Nothing is lost: the numbered rail still shows the incident stopped
// at step 3 of 6, which is the honest progress signal — the rail and the cards
// deliberately stop being one-to-one at that point.
//
// Keyed on all three stages being 'unreachable' rather than on a state name,
// so it follows the stages' own logic instead of duplicating it. A stage that
// is merely 'pending' (waiting, and may yet happen) must NOT fold — folding a
// wait would tell the operator nothing is coming when something is.
export function nothingWasExecuted(incident: IncidentDetail): boolean {
  return (
    approveStage(incident).state === 'unreachable' &&
    executeStage(incident).state === 'unreachable' &&
    validateStage(incident).state === 'unreachable'
  )
}

// `investigating` is the page's own "an analysis is running right now" fact
// (the incident is Investigating, or this tab just started one). Without it the
// Analysis step read "not run" for the whole of a run that was visibly under way.
export function lifecycleSteps(incident: IncidentDetail, investigating = false): LifecycleStep[] {
  const analysis = incident.analysis
  const plan = analysis?.plan ?? null

  const detect = detectStage(incident)
  const explain = explainStage(analysis)
  const recommend = recommendStage(incident)
  const approve = approveStage(incident)
  const execute = executeStage(incident)
  const validate = validateStage(incident)

  // The default for every step, keyed by state alone. Steps override it only
  // where a concrete fact is available and shorter than the generic word.
  const byState: Record<ResolutionStageState, string> = {
    done: 'done',
    current: 'in progress',
    pending: 'not reached',
    blocked: 'blocked',
    unreachable: 'not applicable',
  }

  const analysisMeta = investigating || incident.state === 'Investigating'
    ? 'running'
    : !analysis
    ? 'not run'
    : analysis.status === 'complete'
      ? `${analysis.causalChain.length} evidence step${analysis.causalChain.length === 1 ? '' : 's'}`
      : 'stopped early'

  // The route, not the plan's summary sentence — one or two words, and it is
  // the single fact that most changes what happens at steps 4 and 5.
  const recommendMeta = plan
    ? plan.actionType === 'OpenPR'
      ? 'pull request'
      : 'in-place change'
    : byState[recommend.state]

  const approveMeta =
    plan?.approval?.verdict === 'approved'
      ? 'approved'
      : plan?.approval?.verdict === 'rejected'
        ? 'rejected'
        : approve.state === 'current'
          ? 'waiting on you'
          : byState[approve.state]

  const executeMeta =
    execute.state === 'done'
      ? plan?.actionType === 'OpenPR'
        // Same fact as executeStage's own text just above — must agree in
        // strength, per this file's own header comment, or the rail's meta
        // line contradicts the card's body the same way B160 did.
        ? incident.pullRequest?.mergedAt
          ? 'pull request merged'
          : 'pull request opened'
        : 'applied'
      : execute.state === 'current'
        ? 'running now'
        : byState[execute.state]

  const validateMeta =
    incident.state === 'Reopened'
      // Distinguished for the same reason validateStage's own text is (see the
      // long note there): a bare "recurred" under the rail's Validate dot is
      // read as "your fix failed", and on a workload-tier reopen caused by a
      // sibling object that is not what happened.
      ? incident.reopenedBy && !incident.reopenedBy.sameObject
        ? 'another object'
        : 'recurred'
      : incident.state === 'AwaitingMerge'
        ? 'awaiting merge'
        : validate.state === 'current'
          ? 'watching'
          : validate.state === 'done'
            // STATE_LABEL, not `incident.state.toLowerCase()`. That was the raw
            // wire enum with its case flattened, which reads fine for `Resolved`
            // and becomes "needshumaninvestigation" the moment this branch is
            // reachable from any other state — the exact raw-identifier leak
            // IncidentBadges was fixed for, reintroduced one file over.
            ? (STATE_LABEL[incident.state] ?? incident.state)
            : byState[validate.state]

  // Stage 5 is the only question that varies, and it varies on the route:
  // there is nothing to apply yet, or a reviewer merges and a controller syncs,
  // or ARGUS patches and waits. Moved here from the StageCard call site so the
  // rail and the card cannot end up asking two different questions about the
  // same stage.
  const applyQuestion = !plan
    ? 'How the fix would apply'
    : incident.state === 'AwaitingMerge' || plan.actionType === 'OpenPR'
      ? 'Merge and sync'
      : 'Execute and wait'

  return [
    { n: 1, label: 'Detection', state: detect.state, meta: formatRelativeTime(incident.firstSeen), question: 'What broke' },
    { n: 2, label: 'Analysis', state: explain.state, meta: analysisMeta, question: 'Why it broke' },
    { n: 3, label: 'Recommendation', state: recommend.state, meta: recommendMeta, question: 'How do I fix it' },
    { n: 4, label: 'Approve', state: approve.state, meta: approveMeta, question: 'PR or run' },
    { n: 5, label: 'Apply', state: execute.state, meta: executeMeta, question: applyQuestion },
    { n: 6, label: 'Validate', state: validate.state, meta: validateMeta, question: 'Did it hold' },
  ]
}

// Whether ARGUS can open a pull request for this object, and why not when it
// cannot. Shared by RecommendationChannels and the incident page's Fix section
// so the two can never give different reasons.
export function prAvailability(ownership: ObjectOwnership | null): { available: boolean; reason: string } {
  const available = !!ownership?.repo && !!ownership.repo.pinned && !!ownership.repo.revision
  const reason = !ownership?.repo
    ? 'no GitOps controller reports owning this object'
    : !ownership.repo.revision
      ? 'the controller reports no synced commit'
      : !ownership.repo.pinned
        ? 'the controller reports a branch rather than a resolved commit, so the running commit is not known'
        : ''
  return { available, reason }
}
