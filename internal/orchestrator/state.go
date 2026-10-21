// Package orchestrator is the incident state machine
// lld/08-remediation-contracts.md §2's stateDiagram-v2 defines and
// STATUS.md/cmd/hub/main.go's own doc comment have reserved this exact
// package path for since before it existed ("internal/orchestrator can
// import internal/remediation later ... without this package ever needing
// to import back," internal/remediation/plan.go's own doc comment).
//
// This package now also wires the real ScaleDeployment/RestartPod
// execution path through Executing and Validating (internal/api/approvals.go's
// approve-and-execute flow): AwaitingApproval -> Executing commits in its
// own transaction before the tunnel call, and Executing -> Validating (on a
// successful patch) or Executing -> Failed (on any failure — bad signature,
// expired plan, stale resourceVersion, API error) is written in a second,
// separate transaction after the tunnel call returns. Deliberately never
// Executing -> Resolved directly: a Patch call returning success proves the
// mutation was accepted, not that the incident's underlying symptom is
// actually fixed — see StateValidating's own doc comment.
//
// The Validating -> Resolved/Reopened automated re-check this package's own
// doc comment used to call unbuilt future work is now real, leaning on
// exactly the two mechanisms that comment named:
//   - Reopened is event-driven: internal/gateway/finding.go's handleFinding
//     already re-attaches a recurring Finding (same cluster_id+fingerprint)
//     to any still-open incident; when that incident's state is Validating
//     at the moment of re-attachment, it now also calls SetState to
//     Reopened — the symptom came back, so the fix didn't actually hold.
//   - Resolved is a delayed re-check job: ValidationSweeper (validation.go)
//     periodically promotes a Validating incident to Resolved once enough
//     time has passed since its last successful execution with no
//     recurrence — the absence of a Reopened transition in that window
//     stands in for a real synthetic post-fix health check, which this
//     codebase has no separate mechanism for yet.
//
// AwaitingMerge (the OpenPR/GitOps channel) now has its own version of the
// same re-check, via MergeSweeper (mergewatch.go): it polls the provider for
// each AwaitingMerge incident's pull request, and once it reports merged AND
// the GitOps controller's synced revision has caught up to the merge commit,
// moves the incident to Validating — from there it is indistinguishable from
// an in-place fix, and ValidationSweeper's existing Resolved/Reopened
// machinery takes over unchanged. This closes "the merge happened and nobody
// told ARGUS, so a human had to notice and close it by hand" and "a PR merged
// but the GitOps controller never converged, so the incident sat waiting
// forever" — it says nothing about lld/09's separate gVisor-sandboxed
// rendering pipeline, which is about safely computing a diff before a PR
// opens, not about anything after.
package orchestrator

import (
	"strings"

	"argus/internal/logging"
)

// logger is this package's structured logger (PROJECT.md T22). Built through
// internal/logging.For so it resolves whatever handler chain cmd/hub
// installs, even though this var is initialized before main runs. Sweep
// loops and anything holding a context use the *Context methods, which is
// what carries the correlation id (T23) onto the record.
var logger = logging.For("orchestrator")

// State names, mirroring internal/migrations/000005_incidents_and_analysis
// .up.sql's incidents.state CHECK constraint exactly (also mirrored in
// internal/api/incidents.go's validIncidentStates) — plain string
// constants, not a new Go enum type, since every existing caller in this
// codebase (incidents.go, IncidentsPage.tsx) already treats incidents.state
// as a bare string and this package has no reason to be the first to
// diverge from that.
const (
	StateDetected                = "Detected"
	StateInvestigating           = "Investigating"
	StateRecommendationReady     = "RecommendationReady"
	StateNeedsHumanInvestigation = "NeedsHumanInvestigation"
	StateAwaitingApproval        = "AwaitingApproval"
	StateDismissed               = "Dismissed"

	// StateExpired is PROJECT.md T2's decided answer to "an incident nobody
	// actions": a distinct closed state for a BULK or AUTOMATIC closure —
	// a mechanical judgement about a whole candidate SET ("ARGUS would no
	// longer raise an incident for any of these"), never a considered
	// verdict on THIS one — as opposed to StateDismissed, which after this
	// change means only "a named person looked at this specific incident
	// and decided it did not need action."
	//
	// # The measured driver
	//
	// Of 69 organic incidents in the seven days to 2026-09-07, 50 ended
	// Dismissed — a label that, before this state existed, carried both
	// "correctly triaged away" and "nobody looked, it just aged out of
	// relevance" with no way to tell which. A queue whose closed reasons
	// cannot be told apart is not one a customer's own numbers can explain.
	//
	// # Why this could not just be Dismissed with a detail field
	//
	// internal/api/incident_promotion_reconcile.go's own header used to
	// argue exactly that — "the difference has no consumer a timeline
	// detail cannot serve" — while explicitly deferring the real question
	// to this decision (T2) rather than answering it silently. Now that it
	// is decided: a state a customer sees in their own queue, distinct at
	// the row level, is a stronger and more legible claim than a detail
	// field three clicks deep, and this codebase's own established habit
	// (ExecutionUnknown, ValidationUnknown, PlanRejected) is to add a
	// precisely-named state rather than let an existing one assert
	// something it does not mean.
	//
	// # Disposition: closed, but NOT terminal in the state-machine sense
	//
	// Classified DispositionClosed (closedStates below) — it does not sit
	// in anyone's queue. But unlike Resolved/Dismissed, it has ONE real
	// outgoing edge (below): a Finding re-attaching to an Expired incident
	// (internal/gateway/finding.go's handleFinding, which deliberately
	// does NOT exclude Expired from its own correlation predicates the way
	// it excludes Resolved/Dismissed) moves it to Detected — recurrence
	// reopens an expired incident, honestly, into the same state a brand
	// new incident starts in, rather than reusing Reopened (which asserts
	// "a fix ARGUS believed held did not," a fact that is not true here:
	// nothing was ever fixed, it just aged out).
	StateExpired = "Expired"

	// StateExecuting is set (its own transaction, before any tunnel call)
	// the moment an approval commits to actually executing a plan —
	// internal/api/approvals.go's handleApproveIncident. A durable "we
	// started this, here's exactly what was signed" record survives a
	// hub crash mid-execution, even though the cluster mutation it
	// describes may or may not have actually landed.
	StateExecuting = "Executing"

	// StateAwaitingMerge is where an incident goes once ARGUS has proposed the
	// durable fix as a pull request. The fix exists, it is reviewable, and
	// nothing more will happen inside ARGUS until a human merges it.
	//
	// # Why this state, rather than a column
	//
	// It was in incidents.state's CHECK constraint from migration 000005 and had
	// no Go constant for months. In the meantime the PR path shipped and left its
	// incidents in AwaitingApproval, distinguished only by
	// remediation_recommendations.superseded_at — a nullable column on a
	// different table. That worked exactly as long as every reader remembered to
	// join it, which was not long: the unattended sweeper's candidate query keys
	// on state alone, so it would have executed a plan the approve handler
	// refuses, unattended. On the live run that produced this state, that plan
	// would have set a working image back to a broken tag.
	//
	// So the rule this state exists to enforce is structural, not remembered: a
	// query asking "what may be executed?" filters on AwaitingApproval, and an
	// incident awaiting a merge is not in it. There is no edge from here to
	// Executing, and that absence is the safety property.
	//
	// # What it is NOT
	//
	// Not Validating. Validating means "we changed something, watch for
	// recurrence", and the recurrence check turns a returning symptom into
	// Reopened. Here the symptom is EXPECTED to keep recurring until the merge
	// syncs — the workload is still broken, that is why there is a pull request —
	// so treating recurrence as alarming would flip every pending PR to Reopened
	// inside one detector resend cooldown.
	//
	// # Deviation from lld/08 §2, stated rather than hidden
	//
	// lld/08 models this as Executing -> AwaitingMerge, treating the pull request
	// as an execution channel. This implementation enters it from
	// AwaitingApproval instead, because Executing carries a specific meaning
	// here: "the hub has committed to mutating this cluster and has signed a
	// plan to do it". Opening a pull request mutates nothing. Routing it through
	// Executing would make every "is anything executing?" query wrong.
	//
	// lld/08 also specifies AwaitingMerge -> Validating on a merge webhook. This
	// build polls rather than receives a webhook (MergeSweeper, mergewatch.go —
	// no public endpoint, no shared secret to provision, and it fits the
	// codebase's existing sweep-goroutine shape instead of adding a new one), but
	// the edge is real: once the provider reports the PR merged AND the
	// controller's synced revision has caught up to the merge commit, the
	// sweeper takes this transition itself. A human can still close the incident
	// by hand at any point before then — the edges to Resolved/Dismissed below
	// are exactly that — but is no longer the only way it ever happens.
	//
	// The same sweeper now also takes -> AwaitingApproval, the moment the
	// provider reports the pull request closed without merging (BUGS.md 82).
	// This map's own doc comment used to call that edge "legal and
	// untravelled" because nothing observed a close to travel it — that is no
	// longer true; see allowedTransitions[StateAwaitingMerge]'s comment.
	StateAwaitingMerge = "AwaitingMerge"

	// StateValidating is where a successful Patch lands — never
	// StateResolved directly — and, since MergeSweeper, where a merged AND
	// converged pull request lands too (mergewatch.go). See this package's own
	// doc comment for why: a 200 from Patch (or GitHub reporting a PR merged)
	// proves the mutation was accepted, not that the incident's actual symptom
	// is fixed. Both automated exits now exist (this comment claimed otherwise
	// long after they landed): ValidationSweeper promotes Validating ->
	// Resolved once the fix — an execution or a merge, either supplies the
	// clock-start — has stayed quiet for its grace period, and a recurring
	// Finding drives Validating -> Reopened via internal/gateway/finding.go.
	// This used to read "what is still absent is a real post-fix health
	// assertion for the merge case … so 'nothing recurred' is the only
	// evidence a GitOps-channel fix resolves on." That was true when written
	// and is not any more, corrected 2026-09-08. AppliedValueVerifier has a
	// merge leg: VerifyMergedPullRequest (internal/api/pr_verify.go) re-reads
	// every file the pull request changed AT the revision the GitOps
	// controller reports synced and compares it byte-for-byte against what
	// was proposed — a stricter assertion than the in-place route's single
	// field re-read, not a weaker one. RuleStillFires
	// (internal/api/rule_recheck.go) adds a third leg, re-running the opening
	// declarative rule against the live object.
	//
	// What IS still bounded: RuleStillFires only applies to an incident whose
	// opening finding came from a declarative rule, so one opened by a
	// hand-written Go checker or a watch-based detector has no re-runnable
	// check and rests on the other legs.
	//
	// There is a third exit: StateValidationUnknown, for an incident whose
	// assertion could not be MADE, repeatedly, past validationAssertionDeadline.
	// It exists because "nothing recurred" was previously enough to resolve an
	// incident even when every attempt to check the fix had failed — see that
	// state's own doc comment.
	StateValidating = "Validating"

	// StateFailed is where any execution failure lands — a bad signature,
	// an expired plan, a stale resourceVersion precondition, or any other
	// API error — always with the real reason persisted
	// (remediation_executions.error), never silently reverted back to
	// AwaitingApproval as if nothing had been attempted.
	StateFailed = "Failed"

	// StateExecutionUnknown is BACKLOG.md C8 / BUGS.md 104's fix: where a
	// mutating tunnel call lands when its OWN error is the
	// disconnect/timeout shape (gateway.ErrIndeterminate) and a follow-up
	// read of the live target (internal/execution's
	// resolveIndeterminateOutcome) could not confidently confirm the change
	// applied either. NOT a reuse of StateFailed, deliberately: BUGS.md 104's
	// own live reproduction is the reason — a real tunnel drop mid-patch left
	// the incident recorded as Failed in Postgres while the patch had, in
	// fact, already applied on the cluster, and nothing about that incident's
	// own record made the difference visible. Asserting StateFailed here
	// would repeat exactly the same lie in a new form: "definitely did not
	// work" is not what this situation is. This state says the honest
	// thing instead — "we could not confirm either way, an operator should
	// check the cluster directly" — which is the entire content of the
	// gap this closes.
	//
	// Reached the same way StateFailed is (recordExecutionOutcome, the
	// second, separately-committed transaction after Executing), so it
	// carries the same guarantee: it is never left hanging, always resolved
	// synchronously within the same HTTP request that committed Executing.
	// Its outgoing edges mirror StateFailed's exactly — a human can
	// re-investigate, route to a pull request, or close it out once they've
	// checked the cluster themselves — because from a triage point of view
	// this is the same kind of "an execution attempt did not cleanly
	// resolve, a human should look" state StateFailed already is; the two
	// differ only in what they assert about whether the mutation actually
	// applied.
	StateExecutionUnknown = "ExecutionUnknown"

	// StateResolved is set by ValidationSweeper once a Validating incident
	// has gone quiet (no recurring Finding) for validationGracePeriod —
	// this codebase's stand-in for a real synthetic post-fix health check,
	// which doesn't exist yet. A closed state (fleetgroup.ClosedStates) —
	// SetState recomputes this fingerprint's fleet group automatically.
	StateResolved = "Resolved"

	// StateReopened is set when a Finding with the same cluster_id+fingerprint
	// re-attaches to an incident that was Validating — the symptom recurred,
	// so whatever executed didn't actually hold. Set from
	// internal/gateway/finding.go's handleFinding, not from this package's
	// own DB-touching helpers, since the event that triggers it (a Finding
	// arriving) belongs to that package, not this one.
	StateReopened = "Reopened"

	// StateDiagnosed is lld/08-remediation-contracts.md §12.7's guidance
	// destination: a complete investigation whose route (internal/resolution)
	// is guidance — a real root cause, with suggestedNextSteps, but no
	// in-cluster action is available to propose at all. NOT a reuse of
	// NeedsHumanInvestigation, deliberately: that state means the
	// investigation itself did not reach a conclusion (a bound was hit) or
	// concluded with nothing to propose; this one means the investigation
	// SUCCEEDED and there is genuinely nothing to execute — opposite facts
	// about whether the analysis worked, which is exactly why §12.4 calls
	// guidance "a destination, not a fallthrough."
	//
	// No edge to AwaitingApproval or Executing, and that absence is the
	// safety property — the same structural argument this package already
	// makes for StateAwaitingMerge: a state nothing routes an executable
	// plan through cannot accidentally have one executed against it.
	//
	// # "Terminal" was the wrong word, and it cost six incidents
	//
	// This comment used to open by calling Diagnosed a "terminal state",
	// which read as a contradiction against the three outgoing edges
	// allowedTransitions gives it and against every counter in the codebase,
	// all of which treated it as open. On the development database that
	// mismatch was six completed diagnoses sitting in the open queue with no
	// explanation of why they never moved.
	//
	// Both halves were right about different questions, and the answer is
	// that they are different questions — see the disposition block at the
	// bottom of this file. Diagnosed is FINISHED (ARGUS will not act again on
	// its own) without being CLOSED (the fault is still live in the cluster),
	// and it requires action (a person has to apply the guidance, or close
	// the incident out). Terminality — "does this state have outgoing
	// edges?" — is a property of the state machine and says nothing about
	// whether anyone still owes this incident work.
	StateDiagnosed = "Diagnosed"

	// StatePlanRejected is where an incident goes when a human refuses the
	// plan ARGUS proposed for it (internal/api/approvals.go's
	// handleRejectIncident).
	//
	// # The bug it closes
	//
	// Rejection used to be encoded as AwaitingApproval -> Dismissed. Dismissed
	// means "this is real but needs no action from ARGUS" (see
	// internal/api/incident_triage.go's own doc comment) and it is terminal, so
	// one click on "this proposed fix is unsafe" silently became "this fault no
	// longer matters" — and the incident left the queue with the fault still
	// live in the cluster and nobody assigned to it. The one thing a rejection
	// definitely does NOT tell you is that the problem went away; it is
	// evidence the problem is still there and now needs a different answer.
	//
	// # Why not NeedsHumanInvestigation
	//
	// Because it asserts something false. That state means the investigation
	// itself stopped short — no clear cause, nothing to propose (its own UI
	// sentence says exactly that). Here the investigation SUCCEEDED, produced
	// a root cause AND a concrete plan, and a person read that plan and said
	// no. Routing a rejection there would repeat, in a new form, the same
	// class of lie migration 000081 (ExecutionUnknown) and 000094
	// (ValidationUnknown) each added a state to stop telling: a state that
	// claims one thing about the evidence while the record says another.
	//
	// # What it asserts, and what has to stay visible
	//
	// "A fix was proposed for this and a human refused it; the fault is
	// unchanged." The reason is already durable in
	// remediation_approval_decisions.reason and on the timeline
	// (EventApprovalRejected) — no new column, deliberately: this codebase has
	// already written two rejection reasons nobody read (grants.justification,
	// incidents.pr_rejection_reason) and a third would be worse than none.
	// What this state adds is that the incident stays where the reason can be
	// FOUND: in the open queue, badged as refused, with the rejected plan and
	// its reason on the incident's own page.
	//
	// # Exits
	//
	// Investigating (re-analyse: "find me a different fix" — the decision row
	// on the refused plan stands, and any new plan needs its own approval),
	// AwaitingMerge (propose the durable fix at the source instead), and the
	// two human triage exits. No edge to AwaitingApproval or Executing, for
	// StateAwaitingMerge's structural reason: the plan a human just refused
	// must not be reachable by an approve call, and it is not — the approve
	// handler requires AwaitingApproval.
	StatePlanRejected = "PlanRejected"

	// StateValidationUnknown is where a Validating incident lands when the
	// post-fix assertion could not be MADE — repeatedly, past a bound — as
	// opposed to having been made and come back negative.
	//
	// # The bug it closes
	//
	// ValidationSweeper started every candidate at targetState = Resolved and,
	// when AppliedValueVerifier returned an error (an unreachable cluster, an
	// action type whose field is not modelled, a tunnel failure), changed only
	// the explanatory sentence before committing Resolved anyway. A
	// disconnected cluster therefore turned "we could not tell" into "we
	// verified it worked" — the strongest claim this product makes, produced
	// from the weakest possible basis, and indistinguishable afterwards from a
	// genuinely verified fix.
	//
	// # Why a new state and not one of the eight already here
	//
	// The same argument migration 000081 made for StateExecutionUnknown, which
	// is this state's direct sibling. Resolved asserts the fix worked. Reopened
	// asserts it did not (and manufacturing a recurrence out of an unreachable
	// cluster is the mirror of the same lie, not a fix for it). Failed asserts
	// an execution failed. NeedsHumanInvestigation asserts the INVESTIGATION
	// stopped short, which is a different subject entirely. Every one of those
	// is a claim; this is the absence of one, and there was no state that said
	// so. ExecutionUnknown comes closest and is still wrong: it means the
	// mutation may never have applied, whereas here the execution succeeded and
	// it is the OUTCOME that could not be confirmed.
	//
	// # What reaching it means operationally
	//
	// The same "a human should look" family as ExecutionUnknown, and it is in
	// db.go's notifiableStates for that reason: an incident that quietly stops
	// being validated is exactly the thing an operator will never go looking
	// for on their own. Its exits mirror ExecutionUnknown's — re-investigate,
	// route to a pull request, or close it out once a human has checked the
	// cluster themselves.
	StateValidationUnknown = "ValidationUnknown"
)

// allowedTransitions is this state machine's COMPLETE edge set — the thing
// lld/08-remediation-contracts.md §2 has always specified as a diagram but
// nothing in this codebase actually enforced until now. SetState (db.go)
// consults it on every write and rejects anything not listed here; a state
// absent from the map, or present with an empty edge list, is terminal.
//
// WHY THIS EXISTS (the bug it closes): SetState used to be a bare
// `UPDATE incidents SET state = ...` with no look at the current state, and
// MarkInvestigating was documented as deliberately unconditional. Two
// concrete violations of §2, where Dismissed is terminal, followed directly:
//
//  1. An approver rejects a plan. Rejection was AwaitingApproval ->
//     Dismissed at the time (it is -> PlanRejected now); anyone holding
//     incident:reanalyse then re-analyzed the same incident, which walked it
//     Dismissed -> Investigating -> AwaitingApproval with a fresh plan, and a
//     second approver could execute that one. The rejection was silently
//     erased — no error, no audit trail of the resurrection. Note what the
//     fix here was and was not: an unlisted transition now fails loudly, so a
//     TERMINAL state cannot be revived. Re-analysing a PlanRejected incident
//     is a listed edge and is meant to work — the refusal stands on the plan
//     it was aimed at (remediation_approval_decisions), and the new plan
//     arrives needing its own approval.
//  2. An incident is Executing, i.e. a signed plan is in flight over the
//     tunnel right now (internal/execution's
//     executeApprovedPlan, between recordExecutingTransition and
//     recordExecutionOutcome). A concurrent re-analyze moved it to
//     AwaitingApproval with a NEW plan; the approve-and-execute path then
//     saw AwaitingApproval and alreadyApproved == false for that new plan
//     and proceeded — two concurrent mutations against the same workload,
//     which is exactly what §6's (unbuilt) per-target lock exists to
//     prevent.
//
// The edge set below is derived from what this codebase actually does, not
// transcribed from §2's diagram wholesale — every edge here has a real
// caller today:
//
//   - -> Investigating is MarkInvestigating, reachable from ANY state
//     EXCEPT Executing/Dismissed/Resolved. incident:reanalyse is a real,
//     already-exposed capability an operator can invoke on an incident in
//     any state, and "an investigation is running right now" is a true and
//     useful fact to record for a stale RecommendationReady, a
//     NeedsHumanInvestigation, a Failed execution, a Reopened symptom, or a
//     Validating incident an operator doesn't believe is really fixed. The
//     three exclusions are the whole point: Executing has a cluster
//     mutation in flight (case 2 above), and Dismissed/Resolved are
//     terminal (case 1).
//   - Investigating -> RecommendationReady/NeedsHumanInvestigation/
//     AwaitingApproval is ApplyAnalysisResult (db.go) persisting whatever
//     Advance decided. Investigating -> Investigating is deliberately legal:
//     two concurrent analyze requests on one incident both call
//     MarkInvestigating, and the second must not fail just because the
//     first already recorded the same true fact.
//   - AwaitingApproval -> Executing / -> PlanRejected are the approve and
//     reject halves of internal/api (internal/execution, approvals.go).
//   - Executing -> Validating / -> Failed is recordExecutionOutcome.
//   - Validating -> Resolved is ValidationSweeper (validation.go);
//     Validating -> Reopened is internal/gateway/finding.go's handleFinding.
//
// Deliberately NOT included, and why:
//
//   - RecommendationReady -> AwaitingApproval/Executing (§2 has both): no
//     code path exists for either. Advance never returns Executing (see its
//     doc comment) and nothing promotes a RecommendationReady incident into
//     the approval queue.
//   - Resolved -> Reopened (§2 has it): unreachable here, because
//     handleFinding's correlation predicate treats Resolved as CLOSED — a
//     recurrence after Resolved opens a brand-new incident rather than
//     reviving the old one. Resolved is therefore terminal in this
//     implementation, and this map says so instead of leaving it implied.
//   - Anything involving AwaitingMerge: the OpenPR/GitOps channel is
//     unbuilt (see this package's own doc comment), so there is no Go
//     constant for it and no edge to or from it. An incidents row somehow
//     sitting in that state has no entry in this map at all, so every
//     transition out of it is rejected — failing closed, which is the right
//     answer for a state nothing in this build knows how to advance.
//
// Adding a real transition to this codebase means adding its edge here. That
// is the intended cost: an unlisted transition fails loudly at the one
// function that writes incidents.state, rather than silently succeeding.
// The StateResolved/StateDismissed edges below are the HUMAN triage exits
// (internal/api/incident_triage.go). Before they existed, the only way out of
// the open set was the remediation path — Validating -> Resolved after a
// successful execution, or AwaitingApproval -> Dismissed via /reject — so an
// operator who fixed a problem by hand, or deleted the broken object outright,
// had no way to close its incident at all. It stayed open forever.
//
// That is not a hypothetical: a validation sweep across six fault types left
// ~30 permanently-open incidents for objects that no longer existed, because
// cleaning up a test scenario is exactly the same action as an operator fixing
// something manually (WORKLOG §88). An incident list that only ever grows is
// one an operator stops reading, which costs more than any single missed
// detection.
//
// Deliberately NOT added to StateInvestigating: an investigation in flight
// writes its own outcome transition when it finishes, and letting a human
// close the incident underneath it would make that write fail on a state that
// changed mid-analysis. A human waits for the analysis, then closes it.
var allowedTransitions = map[string][]string{
	StateDetected: {StateInvestigating, StateAwaitingMerge, StateResolved, StateDismissed, StateExpired},
	// No edge to RecommendationReady, deliberately. It is the one state in the
	// schema nothing can reach, and removing the edge is what makes that a
	// property rather than a coincidence.
	//
	// It used to be where an AutoApprove verdict landed, and it had no approval
	// path out — so the SAFEST class of plan (low risk, reversible, high
	// confidence) became the one class nobody could act on, reading as "no
	// remediation to approve yet". Advance now routes both verdicts to
	// AwaitingApproval. The state, its label and its badge stay defined so that a
	// row written before that fix still renders, but nothing can produce a new
	// one, and the UI no longer offers it as a filter that could only ever match
	// nothing.
	//
	// -> Detected is the automatic analyzer's failure path
	// (internal/autoanalyze's recordAnalysisFailure) and has exactly that one
	// caller. It exists because the alternative was worse in a way that was
	// observed live: investigateOne moved the incident to Investigating, the
	// investigation itself failed, and the incident was LEFT in Investigating —
	// which the candidate query excludes, so nothing ever retried it and
	// nothing ever moved it again. It read as "an investigation is running
	// now" (that is the literal sentence the UI renders for this state)
	// permanently, for an investigation that had already failed. Detected is
	// the honest destination: no analysis exists, nothing is running, and the
	// incident is exactly as un-investigated as before the attempt. The
	// attempt itself is not erased — it is on the timeline (InvestigationStarted
	// followed by AutoAnalysisFailed, carrying the real error) and in
	// incidents.auto_analysis_attempts/auto_analysis_last_error.
	//
	// Deliberately narrow: Investigating is the state that owns "another
	// writer is working on this", so this edge is normally only ever taken by
	// the writer that owns THAT work, in the same transaction, after its own
	// work has definitively failed.
	//
	// There is now a second caller, added 2026-09-05: cluster decommission
	// (internal/api/clusters.go) walks an Investigating incident through here
	// on its way to Dismissed. It qualifies on the same reasoning rather than
	// as an exception to it — severing the tunnel is what makes the in-flight
	// analysis definitively unable to finish, so "no analysis exists and
	// nothing is running" is exactly as true there as it is here. It routes
	// through this edge precisely so it does NOT need a direct
	// Investigating -> Dismissed edge, which would remove the protection this
	// comment describes from every other caller.
	StateInvestigating:           {StateDetected, StateInvestigating, StateNeedsHumanInvestigation, StateAwaitingApproval, StateDiagnosed},
	StateRecommendationReady:     {StateInvestigating, StateResolved, StateDismissed, StateExpired},
	StateNeedsHumanInvestigation: {StateInvestigating, StateAwaitingMerge, StateResolved, StateDismissed, StateExpired},
	// -> PlanRejected is the reject half of internal/api/approvals.go, and it
	// replaced -> Dismissed there. Dismissed stays reachable from here, but
	// only as what it always meant: a human triage close-out
	// (internal/api/incident_triage.go), not a verdict on a plan. See
	// StatePlanRejected's own doc comment.
	StateAwaitingApproval: {StateInvestigating, StateExecuting, StateAwaitingMerge, StatePlanRejected, StateDismissed, StateExpired, StateResolved},

	// Mirrors StateNeedsHumanInvestigation's exits: re-investigate, route the
	// fix to the repository instead, or close it out by hand. Deliberately no
	// edge back to AwaitingApproval — nothing may re-queue a plan a human has
	// already refused; a different plan comes from a new analysis, which
	// enters through Investigating like any other.
	StatePlanRejected: {StateInvestigating, StateAwaitingMerge, StateResolved, StateDismissed, StateExpired},

	// Five states can reach AwaitingMerge, and the three that CANNOT are the
	// interesting part.
	//
	// A repository change is an operator saying "the durable fix is this field in
	// this file", and that is a sensible thing to say from more than one place:
	// straight from a Detected incident with no analysis at all (found by
	// GITOPS_TEST_PLAN Phase 10 — the pull request opened and the incident stayed
	// Detected, which reads as "nothing has happened" while a PR is waiting); from
	// NeedsHumanInvestigation, where a person worked out what the model could not;
	// from Failed, where the in-place attempt did not work and the source is the
	// remaining option; and from Reopened, where it worked and did not hold — the
	// strongest possible argument for fixing the source instead.
	//
	// Not from Investigating or Executing: an analysis or a mutation is in flight
	// and another writer owns the state, the same rule that stops a human closing
	// an incident mid-analysis. Not from Validating either: something is being
	// watched there, and that watch is better informed than a state change made
	// while it runs.
	//
	// No edge to Executing, and that is the point — see StateAwaitingMerge.
	// AwaitingApproval is here because lld/08 §2 asks for it: a pull request
	// closed without merging returns the incident to the queue, where the
	// in-place channel is available again. **Implemented 2026-08-25** (BUGS.md
	// 82, DESIGN.md §12.3): MergeSweeper (mergewatch.go) now takes this edge
	// itself the moment the provider reports the pull request closed without
	// merging, recording the rejection reason on the incident
	// (pr_closed_unmerged_at/pr_rejection_reason, migration 000060) first. This
	// comment used to call the edge "legal and untravelled" — it no longer is,
	// though a human closing a PR and re-approving in place by hand remains a
	// real, still-legal path too; the sweeper is simply no longer the only way
	// it happens.
	//
	// Validating IS implemented, by MergeSweeper (mergewatch.go) — the poll this
	// package's own doc comment used to call "unbuilt". It only takes this edge
	// once the provider reports the PR merged AND the GitOps controller's synced
	// revision has caught up to the merge commit — merged-but-not-yet-converged
	// stays in AwaitingMerge, polled again next tick, which is exactly the
	// "repo-managed but nothing applies the repo" case answered rather than
	// assumed away.
	StateAwaitingMerge: {StateInvestigating, StateAwaitingApproval, StateValidating, StateResolved, StateDismissed, StateExpired},
	// StateExecutionUnknown is reachable from Executing exactly like Failed
	// is — see its own doc comment for why it exists as a distinct
	// destination rather than a Failed variant.
	StateExecuting: {StateValidating, StateFailed, StateExecutionUnknown},
	// -> ValidationUnknown is ValidationSweeper giving up on ASSERTING
	// anything, after retrying past validationAssertionDeadline — see
	// StateValidationUnknown's own doc comment. It sits alongside Resolved and
	// Reopened rather than replacing either: those two remain the outcomes for
	// an assertion that was actually made, positively or negatively.
	StateValidating:       {StateInvestigating, StateResolved, StateReopened, StateValidationUnknown, StateDismissed, StateExpired},
	StateFailed:           {StateInvestigating, StateAwaitingMerge, StateResolved, StateDismissed, StateExpired},
	StateExecutionUnknown: {StateInvestigating, StateAwaitingMerge, StateResolved, StateDismissed, StateExpired},
	// Mirrors StateExecutionUnknown's exits exactly, and for the same reason:
	// from a triage point of view both are "an attempt did not cleanly resolve
	// and a human should look", differing only in WHAT could not be confirmed.
	// No edge back to Validating — nothing re-arms a spent grace period, and a
	// human who wants another look re-investigates.
	StateValidationUnknown: {StateInvestigating, StateAwaitingMerge, StateResolved, StateDismissed, StateExpired},
	StateReopened:          {StateInvestigating, StateAwaitingMerge, StateResolved, StateDismissed, StateExpired},

	// lld/08 §12.7's diagram, verbatim: Diagnosed -> Investigating is
	// incident:reanalyse (a human disagrees that nothing is executable, or
	// ownership genuinely changed since); -> Resolved/Dismissed is human
	// triage, the same two exits every other open state already has. No
	// edge to AwaitingApproval or AwaitingMerge or Executing — see
	// StateDiagnosed's own doc comment for why that absence is the point.
	StateDiagnosed: {StateInvestigating, StateResolved, StateDismissed, StateExpired},

	// Terminal, per lld/08-remediation-contracts.md §2 (Dismissed) and this
	// implementation's own correlation rule (Resolved — see the doc comment
	// above). Listed explicitly with an empty edge set rather than simply
	// omitted, so a reader can tell "terminal on purpose" from "nobody has
	// written this state's edges yet."
	StateResolved:  {},
	StateDismissed: {},

	// StateExpired -> StateDetected is the ONE real edge — see StateExpired's
	// own doc comment for why Detected, not Reopened: a Finding re-attaching
	// here (handleFinding, internal/gateway/finding.go) means the fault came
	// back, and nothing has evaluated it since it aged out, which is exactly
	// as true as it is for a brand-new incident. Not empty, unlike
	// Resolved/Dismissed above — Expired is closed (DispositionClosed,
	// closedStates below) but not state-machine-terminal, the same kind of
	// split StateDiagnosed's own doc comment already argues terminality and
	// disposition are allowed to be.
	StateExpired: {StateDetected},
}

// CanTransition reports whether from -> to is one of allowedTransitions'
// edges. An unrecognized `from` (a state constant this package doesn't
// define, e.g. AwaitingMerge) can never transition anywhere — see
// allowedTransitions' doc comment for why failing closed is correct there.
func CanTransition(from, to string) bool {
	for _, allowed := range allowedTransitions[from] {
		if allowed == to {
			return true
		}
	}
	return false
}

// IsTerminalState reports whether state has no outgoing transitions at all —
// true for Dismissed and Resolved (and, incidentally, for any state this
// package doesn't know about). Exported so a caller can render "this
// incident is closed, there is nothing further to do" without duplicating
// the edge set.
//
// This answers a question about the STATE MACHINE and nothing else. It is not
// the way to ask whether an incident is still on anyone's plate — use
// Disposition/RequiresAction below, and read that block's doc comment for why
// the two came apart.
func IsTerminalState(state string) bool {
	return len(allowedTransitions[state]) == 0
}

// --- Disposition: who owes this incident work? ---
//
// The product question, kept deliberately separate from the state machine's
// own terminality above.
//
// # Why this exists
//
// Queue membership used to be derived from terminality: "open" meant "not
// Resolved and not Dismissed", written out as a literal pair in the API's
// counts query, in the incident list's filter, and in four copies in the
// frontend. That definition answers a question nobody was asking. It put
// Investigating and Executing — where ARGUS is mid-flight and a human can do
// nothing useful — in the same bucket as AwaitingApproval, and it made
// Diagnosed unexplainable: a finished investigation, correctly listed as open
// because the fault is still live, sitting in a queue with no indication of
// why it never moved. On the development database that was six incidents.
//
// Terminality cannot answer it, because "finished" and "closed" are not the
// same fact and neither is "needs a human" and "unresolved". Diagnosed is
// finished and open. Validating is unfinished and needs nobody. So the
// product concept gets its own name and its own table, and every counter,
// filter and badge that means "is this on someone's plate?" reads THIS rather
// than re-deriving an answer from the edge set.
//
// # Adding a state
//
// Classify it here. dispositionOf's fallback is deliberately RequiresAction —
// an unclassified state surfaces to a human rather than disappearing from
// the queue — but leaving a real state to that fallback is a bug, and
// TestEveryStateHasADisposition fails on it.
type Disposition string

const (
	// DispositionRequiresAction: nothing moves until a person does something.
	// Every state here is a request for attention, and they are not all the
	// same request — see STATE_EXPLANATION in web/src/utils/incidents.ts,
	// which is obliged to say which one each is.
	DispositionRequiresAction Disposition = "requiresAction"

	// DispositionInProgress: ARGUS, or a reviewer working outside ARGUS
	// (AwaitingMerge), owns the next move. The incident is open and unresolved
	// and it is nobody's queue item; a human intervening here is racing
	// another writer, which is exactly why the transition table refuses most
	// human actions from these states.
	DispositionInProgress Disposition = "inProgress"

	// DispositionClosed: the lifecycle is over. Coincides with
	// IsTerminalState today, and is written out separately anyway rather than
	// derived from it — the whole point of this block is that a state's
	// disposition is a product decision, not a consequence of which edges
	// somebody happened to add.
	DispositionClosed Disposition = "closed"
)

// requiresActionStates is the requires-action set, ordered so the SQL literal
// this file renders from it is stable across builds.
//
// The judgement calls, stated rather than buried:
//
//   - Detected: nothing has looked at it yet. Automatic analysis MAY pick it
//     up, but only for the severities an operator has enabled, so "someone
//     will get to it" is not a property of this state.
//   - RecommendationReady: unreachable for new rows (see allowedTransitions),
//     but a row written before that has a plan and nothing that will ever move
//     it. Leaving it out of the queue would strand it silently.
//   - Diagnosed: ARGUS is finished and the fault is still live. The guidance is
//     the fix and a person has to apply it — or close the incident out.
//   - PlanRejected: a person refused the proposed fix; the fault is unchanged
//     and now needs a different answer.
//   - Failed / ExecutionUnknown / ValidationUnknown: an attempt did not cleanly
//     resolve. The last two are explicitly "we could not tell" — they exist to
//     ask for a human and are in db.go's notifiableStates for the same reason.
//   - Reopened: a fix ARGUS believed held did not.
var requiresActionStates = []string{
	StateDetected,
	StateRecommendationReady,
	StateNeedsHumanInvestigation,
	StateAwaitingApproval,
	StatePlanRejected,
	StateDiagnosed,
	StateFailed,
	StateExecutionUnknown,
	StateValidationUnknown,
	StateReopened,
}

// inProgressStates: another writer owns the next move.
//
// AwaitingMerge is the arguable one. A human does have to merge the pull
// request, so it is "waiting on a person" in the plain sense — but that person
// is working in the SCM, the review is tracked there, and MergeSweeper
// advances the incident on its own once the merge lands and the controller
// converges. Putting it in the ARGUS queue would be asking an operator to
// chase work that is already queued somewhere it can actually be done. It
// stays visible where it belongs instead: GET /approvals lists AwaitingMerge
// alongside AwaitingApproval precisely so "should I merge this?" does not
// vanish (see approvals.go's approvalQueueQuery). A stalled pull request is a
// real gap and the honest place to close it is a staleness signal on that
// queue, not a permanent claim that every open PR needs attention right now.
var inProgressStates = []string{
	StateInvestigating,
	StateExecuting,
	StateAwaitingMerge,
	StateValidating,
}

var closedStates = []string{
	StateResolved,
	StateDismissed,
	StateExpired,
}

var stateDisposition = func() map[string]Disposition {
	m := make(map[string]Disposition, len(requiresActionStates)+len(inProgressStates)+len(closedStates))
	for _, s := range requiresActionStates {
		m[s] = DispositionRequiresAction
	}
	for _, s := range inProgressStates {
		m[s] = DispositionInProgress
	}
	for _, s := range closedStates {
		m[s] = DispositionClosed
	}
	return m
}()

// DispositionOf classifies one incident state. An unrecognized state — a row
// written by a newer hub, or a typo that survived the CHECK constraint —
// resolves to RequiresAction: surfacing an incident nobody can explain is
// recoverable, silently dropping it from every queue is not.
func DispositionOf(state string) Disposition {
	if d, ok := stateDisposition[state]; ok {
		return d
	}
	return DispositionRequiresAction
}

// RequiresAction reports whether this state is on a human's plate. This, not
// "not closed", is what an incident queue and its count are asking.
func RequiresAction(state string) bool {
	return DispositionOf(state) == DispositionRequiresAction
}

// IsClosed reports whether this incident's lifecycle is over.
//
// This USED to say it was the same set fleetgroup.IsClosedState uses, which
// "happens to have the same answer". That stopped being true when StateExpired
// landed (PROJECT.md T2, 2026-09-07): this set is
// {Resolved, Dismissed, Expired}; fleetgroup.ClosedStates is still
// {Resolved, Dismissed}. The two questions were always different — "is the
// lifecycle over?" versus "may a recurring finding re-attach here?" — and they
// now genuinely have different answers, deliberately so for correlation, since
// a recurrence must be able to re-attach to an Expired incident.
//
// Do not "reconcile" them by adding Expired to fleetgroup.ClosedStates without
// reading that package's correlation queries first. db.go's SetState used to
// branch on fleetgroup.IsClosedState instead of this function, so a
// transition into Expired stamped no resolved_at and skipped the group
// recompute (PROJECT.md B156) — fixed by making SetState call THIS function
// for both the resolved_at stamp and the group-recompute gate, which is the
// question it was actually asking in both places.
func IsClosed(state string) bool {
	return DispositionOf(state) == DispositionClosed
}

// RequiresActionStateSQL renders the requires-action set as a SQL IN-list
// literal — `('Detected', 'RecommendationReady', ...)` — for the one place a
// query has to filter on it (internal/api/incidents.go's row filter and counts
// query, which interpolate the SAME string so a tab's number and the rows
// beneath it cannot come to mean different things).
//
// Interpolated rather than parameterised because it is a list of a
// compile-time-fixed length whose every element is a constant declared at the
// top of this file. No caller supplies any part of it, so there is nothing
// here for a parameter to protect against; the alternative is generating N
// placeholders and threading N args through two differently-shaped queries.
func RequiresActionStateSQL() string {
	quoted := make([]string, 0, len(requiresActionStates))
	for _, s := range requiresActionStates {
		quoted = append(quoted, "'"+s+"'")
	}
	return "(" + strings.Join(quoted, ", ") + ")"
}

// ClosedStateSQL renders the CLOSED set as a SQL IN-list literal, for the same
// one reason RequiresActionStateSQL exists: internal/api/incidents.go's counts
// query needs "how many incidents are still open", and the honest definition of
// open is "not closed" — the complement of DispositionClosed, not a hand-written
// list of the states someone remembered.
//
// Read IsClosed's doc comment before reusing this anywhere near correlation:
// this set is {Resolved, Dismissed, Expired} and fleetgroup.ClosedStates is
// {Resolved, Dismissed}, deliberately, because a recurring finding must still be
// able to re-attach to an Expired incident. The two answer different questions
// and this one is "is the lifecycle over?".
//
// Interpolated rather than parameterised for RequiresActionStateSQL's reason,
// unchanged: every element is a constant declared at the top of this file and no
// caller supplies any part of it.
func ClosedStateSQL() string {
	quoted := make([]string, 0, len(closedStates))
	for _, s := range closedStates {
		quoted = append(quoted, "'"+s+"'")
	}
	return "(" + strings.Join(quoted, ", ") + ")"
}

// fixNotHeldStates is "ARGUS acted, and it did not demonstrably work" — the
// product's own quality signal, as distinct from "this is broken" (which is
// every open incident) and "this needs you" (requires-action, which includes
// incidents nothing has been tried on yet).
//
// The four are the outcomes of an attempt, not of a detection:
//   - Failed            the execution itself was refused or errored
//   - ExecutionUnknown  it was sent and the outcome could not be established
//   - ValidationUnknown it applied and validation could not establish the result
//   - Reopened          it applied, validated, and the symptom came back
//
// Deliberately NOT derived from a disposition: all four are requires-action
// today, so a disposition cannot separate them from a freshly-detected
// incident nobody has touched. This is a narrower, product-level question and
// it gets its own list, kept here beside the others so the state vocabulary
// stays in one file.
var fixNotHeldStates = []string{
	StateFailed,
	StateExecutionUnknown,
	StateValidationUnknown,
	StateReopened,
}

// FixNotHeldStateSQL renders fixNotHeldStates as a SQL IN-list literal, for
// internal/api/incidents.go's counts query. Interpolated for the same reason
// as the two above: every element is a constant declared in this file.
func FixNotHeldStateSQL() string {
	quoted := make([]string, 0, len(fixNotHeldStates))
	for _, s := range fixNotHeldStates {
		quoted = append(quoted, "'"+s+"'")
	}
	return "(" + strings.Join(quoted, ", ") + ")"
}
