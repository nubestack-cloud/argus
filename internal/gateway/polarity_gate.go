package gateway

// This file is BACKLOG.md E11 piece 3's hub-side gate: the one place a
// Finding carrying internal/agent's "GenericConditionAnomaly:<type>" reason
// prefix gets turned into an actual fire-or-drop decision, using
// internal/conditionpolarity.Resolve. See that package's own doc comment
// for the full architecture (why this runs hub-side, why the persisted
// cache is authoritative over a fresh local majority, why there's no TTL).
//
// Wired into handleFinding (finding.go) BEFORE the correlation transaction
// opens — same "resolved once, fresh, ahead of the transaction below"
// posture as that function's own settings.Resolve call, and for the same
// reason: this needs its own short transaction (Resolve's advisory lock is
// scoped to it) rather than sharing the one correlation opens afterward, so
// a polarity lookup/write can commit independently of whatever the
// correlation logic decides to do with the (possibly rewritten) Finding.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"argus/internal/conditionpolarity"
	"argus/internal/llm"
	"argus/internal/logging"
	"argus/internal/tunnel"
)

// genericConditionAnomalyReasonPrefix duplicates
// internal/agent/generic_predicates.go's constant of the same string value.
// Duplicated rather than imported — the hub does not, and should not,
// import internal/agent (a spoke-only package pulling in
// k8s.io/client-go/kubernetes and friends) — matching this codebase's
// existing argusRemediateFieldManager-style precedent for a small constant
// shared by value across that boundary.
const genericConditionAnomalyReasonPrefix = "GenericConditionAnomaly:"

// llmAsker adapts llm.Completer to conditionpolarity.ModelAsker — the one
// real call site; every other caller of that interface (this package's own
// tests, conditionpolarity's own tests) uses a fake instead.
//
// Completer, not the concrete *llm.Provider this used to hold directly
// (BACKLOG.md P13): Gateway.LLM is now the *llm.Router the investigation
// loop already dispatches through, so this Ask call reaches whichever
// provider kind (api or cli) is actually configured in Settings, instead of
// always going through Provider.Complete's api-only HTTP path.
type llmAsker struct{ completer llm.Completer }

func (a llmAsker) Ask(ctx context.Context, systemPrompt, userPrompt string) (text, model string, err error) {
	res, err := a.completer.Complete(ctx, systemPrompt, userPrompt)
	if err != nil {
		return "", "", err
	}
	return res.Text, res.Model, nil
}

// polarityUnverifiedMarker is prepended to f.Message whenever this gate
// cannot confidently resolve a verdict at all — BACKLOG.md E12's "fail open
// with a marker," never a silent drop. Grep-able on purpose, so an operator
// (or a future query) can find every Finding this gate could not vouch for,
// distinct from an ordinary Message.
const polarityUnverifiedMarker = "[polarity unverified]"

// markPolarityUnverified is E12's fail-OPEN path: instead of dropping a
// Finding this gate could not confidently classify, let it through with its
// severity floored to the lowest tier and a plain, operator-visible marker
// on the front of its Message. Non-negotiable 8 ("never present a guess as
// confident") governs asserting a root cause; it does not license silently
// asserting the OPPOSITE — that an object is fine — on evidence too weak to
// support either claim. A floored-severity, clearly-labelled Finding an
// operator can see and dismiss is recoverable; a dropped one is not.
func markPolarityUnverified(f *tunnel.Finding, reason string) {
	f.Severity = "low"
	f.Message = fmt.Sprintf("%s (%s) %s", polarityUnverifiedMarker, reason, f.Message)
}

// applyConditionPolarityGate inspects f and, if it carries
// genericConditionAnomalyReasonPrefix, resolves the durable polarity verdict
// for its (Kind, ConditionType) pair and decides whether the Finding should
// continue on to ordinary correlation at all — mutating f in place when it
// cannot confidently resolve one.
//
// Four outcomes, and only one of them drops anything:
//
//   - f's Reason doesn't match the prefix at all — not this predicate's
//     Finding, untouched, proceed normally. This is the overwhelmingly
//     common case for every OTHER detector/rule in this codebase.
//   - The polarity verdict says f.ConditionObservedValue IS the bad value —
//     proceed normally; this is a real anomaly.
//   - The polarity verdict says f.ConditionObservedValue is actually the
//     HEALTHY reading, resolved with actual confidence (a fresh or cached
//     statistical read, or a model-sourced verdict that has itself been
//     corroborated by a confident live sample at some point — see
//     conditionpolarity.Verdict.EverConfirmed) — this is the ONE case that
//     drops, and it is not a guess: something (real evidence, or an asked
//     model whose answer real evidence has since checked) affirmatively
//     said "healthy."
//   - Anything else — malformed Finding fields, an unparseable GVK, a DB
//     error, no model configured and too weak a local sample, an
//     unparseable model reply, or a cached model verdict that has NEVER
//     been checked against a confident live sample (BACKLOG.md E11's own
//     named-but-open gap in E12 — see ErrModelVerdictUnconfirmed) — is NOT
//     resolved as healthy; it is UNKNOWN. BACKLOG.md E12: dropping here
//     would assert "this object is fine" on weaker evidence than even a
//     rejected root-cause guess, in a place no operator can see it happen.
//     So this proceeds via markPolarityUnverified instead of dropping —
//     see that function's own doc comment.
//
// Returns proceed only; every failure mode above is handled internally
// (logged, and reflected in f if it changes what should happen to f) rather
// than returned as an error for a caller to decide what to do with — E12's
// whole point is that there must be no path left in this function's own
// caller where "an error happened" can still mean "drop the Finding."
func (g *Gateway) applyConditionPolarityGate(ctx context.Context, f *tunnel.Finding) (proceed bool) {
	condType, ok := genericConditionType(f.Reason)
	if !ok {
		return true
	}
	if f.ConditionType == "" || f.ConditionObservedValue == "" {
		// Malformed/older-agent Finding claiming this reason without the
		// fields this gate needs to compare against — unknown, not healthy.
		markPolarityUnverified(f, fmt.Sprintf("finding reason %q missing ConditionType/ConditionObservedValue", f.Reason))
		return true
	}

	kind := gvkKind(f.GVK)
	if kind == "" {
		markPolarityUnverified(f, fmt.Sprintf("could not parse a Kind out of GVK %q", f.GVK))
		return true
	}

	var asker conditionpolarity.ModelAsker
	if g.LLM != nil {
		asker = llmAsker{completer: g.LLM}
	}

	tx, err := g.db.Pool.Begin(ctx)
	if err != nil {
		// A hub-side infrastructure failure is not evidence the OBJECT is
		// healthy — proceeding unverified beats silencing a possibly-real
		// fault because the database happened to hiccup.
		logger.ErrorContext(ctx, "condition polarity gate: begin transaction failed; proceeding unverified rather than dropping the finding",
			slog.String("kind", kind), slog.String("condition_type", condType), logging.Err(err))
		markPolarityUnverified(f, "could not reach the polarity store")
		return true
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	verdict, err := conditionpolarity.Resolve(ctx, tx, asker, conditionpolarity.Sample{
		Kind:             kind,
		ConditionType:    condType,
		ObservedValue:    f.ConditionObservedValue,
		SampleCount:      f.ConditionSampleCount,
		MajorityValue:    f.ConditionMajorityValue,
		MajorityFraction: f.ConditionMajorityFraction,
	})
	if err != nil {
		if errors.Is(err, conditionpolarity.ErrModelNotConfigured) {
			logger.WarnContext(ctx, "condition polarity gate: too few live samples to infer locally and no model is configured; surfacing unverified rather than dropping",
				slog.String("kind", kind), slog.String("condition_type", condType), slog.String("namespace", f.Namespace), slog.String("object_name", f.ObjectName))
			markPolarityUnverified(f, fmt.Sprintf("too few live samples of %s/%s to infer polarity, and no model is configured to ask", kind, condType))
			return true
		}
		if errors.Is(err, conditionpolarity.ErrModelVerdictUnconfirmed) {
			// BACKLOG.md E11's own named-but-open gap in E12's fix: a
			// DIFFERENT reason to be unverified than the cases above — this
			// one has a cached model verdict, but it has never once been
			// checked against a confident live sample (see that error's own
			// doc comment). Given a distinct marker text on purpose, so an
			// operator (or a future query over Message) can tell "nobody has
			// ever been able to check this Kind's guess" apart from "no
			// model is configured right now" — they call for different
			// remediation (a stronger model tier or more live samples, vs.
			// just configuring one).
			logger.WarnContext(ctx, "condition polarity gate: the cached model verdict has never been corroborated by a confident live sample; surfacing unverified rather than trusting an uncorroborated guess",
				slog.String("kind", kind), slog.String("condition_type", condType), slog.String("namespace", f.Namespace), slog.String("object_name", f.ObjectName))
			markPolarityUnverified(f, fmt.Sprintf("cached model verdict for %s/%s has never been corroborated by enough live evidence to check it", kind, condType))
			return true
		}
		logger.ErrorContext(ctx, "condition polarity gate: resolving polarity failed; surfacing unverified rather than dropping",
			slog.String("kind", kind), slog.String("condition_type", condType), slog.String("namespace", f.Namespace), slog.String("object_name", f.ObjectName), logging.Err(err))
		markPolarityUnverified(f, fmt.Sprintf("could not resolve polarity for %s/%s: %v", kind, condType, err))
		return true
	}
	if err := tx.Commit(ctx); err != nil {
		logger.ErrorContext(ctx, "condition polarity gate: commit failed; surfacing unverified rather than dropping",
			slog.String("kind", kind), slog.String("condition_type", condType), slog.String("namespace", f.Namespace), slog.String("object_name", f.ObjectName), logging.Err(err))
		markPolarityUnverified(f, fmt.Sprintf("could not persist a polarity verdict for %s/%s: %v", kind, condType, err))
		return true
	}

	if f.ConditionObservedValue != verdict.BadValue {
		// The observed reading is the HEALTHY one per an ACTUALLY RESOLVED
		// verdict — silently drop. Not a guess: this is what "most objects
		// report the healthy value most of the time" looks like once
		// polarity is genuinely settled, the one case that legitimately
		// drops rather than surfacing unverified.
		return false
	}
	f.Confidence = tunnel.FindingConfidenceVerified
	return true
}

// genericConditionType strips genericConditionAnomalyReasonPrefix off a
// Finding's Reason, returning ("", false) for anything else.
func genericConditionType(reason string) (string, bool) {
	if len(reason) <= len(genericConditionAnomalyReasonPrefix) || reason[:len(genericConditionAnomalyReasonPrefix)] != genericConditionAnomalyReasonPrefix {
		return "", false
	}
	return reason[len(genericConditionAnomalyReasonPrefix):], true
}

// gvkKind extracts the bare Kind from a GVK string in this codebase's own
// "<group/version>/<Kind>" wire convention (e.g. "apps/v1/Deployment",
// "v1/Node") — the last "/"-delimited segment, always.
func gvkKind(gvk string) string {
	for i := len(gvk) - 1; i >= 0; i-- {
		if gvk[i] == '/' {
			return gvk[i+1:]
		}
	}
	return gvk
}
