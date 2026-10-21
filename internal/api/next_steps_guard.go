package api

import (
	"context"
	"log/slog"
	"regexp"

	"github.com/jackc/pgx/v5"

	"argus/internal/llm"
	"argus/internal/logging"
	"argus/internal/timeline"
)

// runnableCommandVerbRe matches the exact command-line tools
// internal/llm.SystemPrompt's own stepRules tell the model to use for the
// "write the EXACT command" variant of a suggestedNextSteps entry —
// anchored to the START of the entry (ignoring a little leading whitespace
// or wrapping punctuation, e.g. a backtick or quote), because stepRules'
// convention is that the ENTIRE entry IS the command, not a sentence that
// happens to mention one of these tools by name partway through ("Check
// whether kubectl access is configured..." must not count). BACKLOG.md F27
// itself asks for exactly this shape of heuristic ("a recognizable command
// verb ... as a sanity heuristic, but don't over-engineer a full
// command-parser"): this is deliberately not a shell parser, and it is
// never used to decide whether to EXECUTE anything — only whether to record
// an honest note when the model's answer gave the operator nothing to copy
// and run.
var runnableCommandVerbRe = regexp.MustCompile("^[\\s`'\"-]*(kubectl|git|helm|argocd|flux|kustomize)\\s+\\S")

// placeholderTokenRe matches the exact "<...>" bracket shape stepRules
// already warns the model against ("never a placeholder like <namespace> or
// <name>") — BACKLOG.md F27's own "no <placeholders>" language, checked
// mechanically here rather than trusted on the model's word alone.
var placeholderTokenRe = regexp.MustCompile(`<[^<>\n]{1,80}>`)

// stepLooksRunnable reports whether one suggestedNextSteps entry is a real,
// directly runnable command an operator could copy and execute as written,
// rather than prose advice or a field-path-and-value description. A
// deliberately narrow heuristic — see runnableCommandVerbRe's own doc
// comment for why a full parser is not the goal here.
func stepLooksRunnable(step string) bool {
	if placeholderTokenRe.MatchString(step) {
		return false
	}
	return runnableCommandVerbRe.MatchString(step)
}

// hasRunnableNextStep reports whether AT LEAST ONE entry in steps passes
// stepLooksRunnable — BACKLOG.md F27's own bar for the null-plan case: an
// operator with no proposedPlan and no pull request needs at least one
// command they can actually run, not only prose or a field path.
func hasRunnableNextStep(steps []string) bool {
	for _, s := range steps {
		if stepLooksRunnable(s) {
			return true
		}
	}
	return false
}

// FlagMissingRunnableNextStep is BACKLOG.md F27's mechanical enforcement
// point for the guidance half of that item. Prompting the model to give a
// real runnable command whenever no proposedPlan/proposedPairedPlan exists
// (internal/llm.SystemPrompt's noPlanRunnableCommandRule) is necessary but
// not sufficient on its own — this codebase's own convention
// (RefuseTruncatedRepositoryProposals, RefuseOrphanedRecreatedResourceProposals,
// both internal/api/repo_tools.go) is to also mechanically check the model's
// actual answer before trusting it, rather than rely on the prompt alone.
// This is that check for the null-plan/no-runnable-command case.
//
// Unlike those two guards, there is nothing here to REFUSE: a null
// proposedPlan is already the correct, honest state for this incident (the
// model was asked for one and, correctly, did not have a safe/expressible
// fix to offer), and there is no fabricated command this function could
// safely substitute in without violating this codebase's evidence
// discipline (DESIGN.md §8.1/§8.4 — never present a guess as a confident
// answer) or its "AI-assisted, never hardcoded per issue" rule (a
// per-issue-type templated command would be exactly the narrow, hardcoded
// mechanism this item exists to move away from). So a failed check does not
// mutate result: it only RECORDS the honest fact that the investigation
// concluded with nothing directly actionable to hand the operator, via one
// timeline.EventNoActionableNextStep row — rendered by the incident's
// existing, generic timeline UI (IncidentDetailPage's TimelineEventNode
// renders event.summary for any event type, so this needs no new UI
// surface) — and a hub log line.
//
// Deliberately NOT a retry loop, unlike openpr_correction.go's one-shot
// correction for a rejected pull request: that mechanism exists because a
// live repository's rejection is new information a second model call can
// react to (the exact rejection text). Here the model already had every
// piece of evidence it was going to get and already answered; asking again
// with no new information would not be expected to converge on a different
// answer, only spend a second call to possibly reproduce the same gap.
// BACKLOG.md F27 itself frames this fix as "Size S" — a single, honest,
// recorded note is the simpler and more honest choice than a loop with no
// new signal to act on.
//
// A no-op whenever result.Status != "complete" (a "partial" result's
// SuggestedNextSteps is this package's own generic bound-hit fallback, not
// the model's reasoned answer about this specific incident — flagging it
// here would be noise, not signal) or either result.ProposedPlan or
// result.ProposedPairedPlan is non-nil (some channel already exists; this
// guard is specifically about F27's no-repository, no-in-place-action case).
//
// Called from both internal/api/analyze.go and internal/autoanalyze.go,
// immediately after orchestrator.EnforceRoute — deliberately AFTER route
// enforcement rather than at the same point F25/BUGS.md 117's guards run
// (before it), because EnforceRoute is what can turn a route-illegal
// ProposedPlan back into nil; checking any earlier would flag an incident
// route enforcement was about to fix on its own, and this check needs the
// FINAL null-or-not state, not the model's raw, pre-enforcement answer.
func FlagMissingRunnableNextStep(ctx context.Context, tx pgx.Tx, tenantID, clusterID, incidentID string, result llm.Investigation) {
	if result.Status != "complete" {
		return
	}
	if result.ProposedPlan != nil || result.ProposedPairedPlan != nil {
		return
	}
	if hasRunnableNextStep(result.SuggestedNextSteps) {
		return
	}

	logger.WarnContext(ctx, "complete analysis proposed no plan and suggestedNextSteps contains no runnable command; recording an honest note rather than fabricating one",
		logging.IncidentID(incidentID), slog.Int("suggested_next_steps", len(result.SuggestedNextSteps)))

	if err := timeline.Record(ctx, tx, timeline.Event{
		TenantID:   tenantID,
		ClusterID:  clusterID,
		IncidentID: incidentID,
		Type:       timeline.EventNoActionableNextStep,
		Summary:    "ARGUS reached a conclusion but proposed no plan and gave no directly runnable command — the operator has prose or field-path guidance only.",
		Detail: map[string]any{
			"suggestedNextSteps": result.SuggestedNextSteps,
		},
	}); err != nil {
		// Logged, not returned/fatal: this is itself a "say what wasn't
		// achieved" note, not load-bearing for the analysis it describes —
		// losing the note is strictly worse observability, never a
		// correctness bug in the already-persisted analysis, so it must
		// not fail the whole request the way a lost analyses/incidents row
		// would.
		logger.ErrorContext(ctx, "recording the NoActionableNextStep timeline event failed", logging.IncidentID(incidentID), logging.Err(err))
	}
}
