// Package conditionpolarity is the hub-side half of BACKLOG.md E11 piece 3:
// deciding, for a Kubernetes condition TYPE on a given Kind, which literal
// value ("True" or "False") means "problem" — without ever hardcoding a
// polarity table, which this item's own text names as its anti-pattern
// (Ready=True is healthy, MemoryPressure=True is a problem; a naive rule
// gets one of the two backwards on arrival).
//
// # Why this lives hub-side, not in internal/agent
//
// internal/agent (the spoke) has no existing mechanism to call a model at
// all — every "ask the model" call site in this codebase
// (internal/llm.Provider.Complete, internal/llm's tool-calling investigation
// loop) runs hub-side or in cmd/cli-runner, and internal/agent's own doc
// comments treat that as a deliberate defence-in-depth boundary, not an
// accident. Giving the agent a second, direct egress path to a model
// endpoint would also bypass the ONE place cluster data is redacted before
// it leaves the cluster (non-negotiable 9: ToolExecutor.Execute and the
// tunnel Finding writer, both agent-side chokepoints) — a raw HTTP call to
// an LLM API from inside the customer's own network is exactly the kind of
// second, unredacted egress path that guarantee depends on not existing.
// So Mechanism 2 ("ask the model once, then cache the verdict") has to run
// where the model is already reachable: the hub, specifically
// internal/gateway's Finding-ingestion path, ahead of ordinary correlation.
//
// # Why the hub is the single authority, not just a fallback
//
// internal/agent's own checkGenericConditions (generic_predicates.go)
// computes Mechanism 1 ("learn it from the cluster") locally every sweep —
// it has the live object list right in front of it, so a majority-vote
// inference needs no round trip. But the agent has no way to read this
// package's persisted cache (there is no hub -> agent config-push channel
// for it, and building one was judged not worth it for this), so if the
// agent were allowed to decide fire-or-drop on its own local statistics
// alone, an agent's later, larger sample could silently disagree with an
// earlier MODEL verdict this package already cached and is treating as
// settled. So the agent instead ALWAYS forwards its best local read
// (Sample below) for anything that differs from its own local majority (or
// for which it has no local majority at all) — see tunnel.Finding's own doc
// comment — and Resolve is the one place that turns that observation into
// an actual fire-or-drop decision: an existing cached verdict always wins
// over a fresh local majority (which is exactly "when they disagree ... the
// model-asked-and-cached answer is the fallback" from this item's own
// text); Mechanism 1 only ever gets to WRITE the cache when there is no
// verdict yet and the agent's own sample clears this package's confidence
// bar; otherwise Mechanism 2 is asked, once, and its answer is what gets
// cached and returned.
//
// # BACKLOG.md E12 — a cached verdict is a PRIOR, not a fact, and must be
// revisable
//
// The doc comment above this one (still true for a STATISTICAL verdict —
// see below) originally argued no TTL was needed at all, on the grounds
// that a condition type's polarity is a stable fact about the Kind's own
// API. That argument does not hold for a MODEL-sourced verdict, because the
// thing that can be wrong is not the fact — it is the MODEL'S GUESS at the
// fact, and a small/weak model's guess is measurably unreliable (E12's own
// entry: 5 of 9 asked live got it backwards). A wrong guess that never
// expires and always outranks fresh cluster evidence is exactly the
// permanent, silent blind spot E12 exists to close. So, for a MODEL-sourced
// verdict specifically, two independent correction paths now exist:
//
//  1. A confident, contradicting live statistical sample overrides it
//     immediately (see the "cached.Source == model" branch in Resolve) —
//     real evidence about THIS cluster beats a guess about the world the
//     moment enough evidence exists, with no wait for a TTL.
//  2. Absent that, modelVerdictTTL bounds how long a never-contradicted
//     model guess is trusted before Resolve asks again — a defence against
//     a Kind/condition pair too rare to ever accumulate a confident local
//     sample, where path 1 above would otherwise never fire.
//
// A STATISTICAL verdict is unchanged by any of this and still never
// expires and is never overridden by a later sample: it was already real
// evidence about this cluster when it was cached (that is what
// "statistical" means here), so there is nothing for a later sample to
// correct it WITH that outranks what it already is.
//
// # BACKLOG.md E11 — a wrong cached MODEL verdict that never gets a chance
// to self-correct
//
// E12 (above) closed most of the blind spot but named one gap it did not
// reach: both of its correction paths need SOMETHING to compare the cached
// guess against — a confident live sample (path 1) or a fresh re-ask (the
// TTL, path 2) — and for a (Kind, ConditionType) pair that structurally
// never accumulates minStatisticalSampleCount live instances at once,
// path 1 can NEVER fire, and path 2 just re-asks the same model, which can
// (and, measured against a real weak model, does) reproduce the identical
// wrong guess every time the TTL rolls over. A verdict like that is
// trusted as fully resolved forever, on strictly less evidence than "a
// model was asked and nothing has ever checked its answer."
//
// The fix tracks, per pair, whether path 1 has EVER actually been reached
// for a model-sourced verdict — Verdict.EverConfirmed, persisted in
// condition_polarity.ever_confirmed (migration 000088) — rather than
// checking THIS call's sample confidence alone. Two shapes were weighed:
//
//   - Per-call: treat any resolve where the CURRENT sample isn't confident
//     as unverified, whenever the cached verdict is model-sourced. Simple,
//     but wrong in the common case: a Kind that usually has plenty of live
//     instances and a well-corroborated verdict would still get flagged
//     unverified every time its population happened to dip on one
//     particular call, for no reason connected to whether the verdict is
//     actually trustworthy.
//   - Historical (chosen): only a pair that has NEVER ONCE been
//     confident-checkable is flagged. A Kind having a temporarily quiet
//     day, whose verdict WAS corroborated at some point in the past, keeps
//     being trusted exactly as before. This is the more precise match for
//     the actual problem (a pair that is structurally, not incidentally,
//     unable to ever self-correct), at the cost of a schema column and a
//     little more bookkeeping in Resolve — a cost worth paying because the
//     alternative's false-positive rate scales with how rare the CONDITION
//     is, not with how wrong the GUESS is, which is precisely backwards.
//
// See ErrModelVerdictUnconfirmed and the "cached.Source == model &&
// !cached.EverConfirmed" branch in Resolve for the mechanism, and
// markConfirmed for how EverConfirmed actually gets set to true.
package conditionpolarity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"argus/internal/logging"

	"github.com/jackc/pgx/v5"
)

// logger is internal/conditionpolarity's package-local structured logger
// (PROJECT.md T22).
var logger = logging.For("conditionpolarity")

// modelVerdictTTL bounds how long an UNCONTRADICTED model-sourced verdict
// is trusted before Resolve re-derives it (re-tries a confident statistical
// read first, then re-asks the model if the sample still is not confident).
// A statistical verdict never expires (see the package doc comment above)
// — this constant applies to source="model" rows only.
//
// A week, not a day and not a month: this is the residual defence for a
// Kind/condition pair too rare to ever accumulate
// minStatisticalSampleCount live instances, where a fresh statistical
// override (the primary, immediate correction path) can never fire at all
// — so this bound trades a small amount of wasted re-asking against how
// long a wrong guess for such a pair can persist. Revisable; not load-bearing
// enough to need to be exact.
const modelVerdictTTL = 7 * 24 * time.Hour

// Sample is what internal/gateway's Finding-ingestion polarity gate passes
// in for one Finding carrying reason prefix "GenericConditionAnomaly:" —
// built directly from the tunnel.Finding fields internal/agent's
// checkGenericConditions populates. See that type's own doc comment for
// what each field means and why the agent, not this package, computes it.
type Sample struct {
	Kind             string
	ConditionType    string
	ObservedValue    string // "True" | "False"
	SampleCount      int
	MajorityValue    string // "" when the agent had no local majority to report
	MajorityFraction float64
}

// Verdict is this package's answer for one (Kind, ConditionType) pair: which
// literal condition value is the problem, and which mechanism produced the
// answer currently on record.
type Verdict struct {
	BadValue  string // "True" | "False"
	Source    string // "statistical" | "model"
	UpdatedAt time.Time
	// EverConfirmed is true once a live sample has ever cleared the
	// confidence bar and been checked against this verdict — for a
	// "statistical" verdict this is always true (it was real evidence the
	// moment it was cached); for a "model" verdict it starts false and
	// flips to true the first time Resolve's confident-sample branch gets
	// to run against it at all (whether that check agrees, in which case
	// this flag is what records it, or disagrees, in which case the row is
	// overwritten wholesale as "statistical" and this flag stops mattering
	// for it). See Resolve's own comments for why this, not a per-call
	// check, is the fix for BACKLOG.md E11's "never corroborated" gap.
	EverConfirmed bool
}

// minStatisticalSampleCount / minStatisticalConfidence are the bar a
// Sample's own agent-computed statistics must clear before this package
// trusts them enough to seed the persisted cache without asking the model —
// deliberately the SAME constants internal/agent/generic_predicates.go uses
// to decide whether to report a "confident" anomaly in the first place
// (minGenericPolaritySamples/genericPolarityMajorityFraction), duplicated
// here rather than imported: this package must not import internal/agent
// (a spoke-only package pulling in client-go/kubernetes types this hub-side
// package has no business depending on), matching the existing
// argusRemediateFieldManager-style precedent for a small constant shared by
// value across that boundary rather than by import.
const (
	minStatisticalSampleCount = 5
	minStatisticalConfidence  = 0.8
)

// ModelAsker is Mechanism 2's narrow seam onto a model — deliberately not
// *llm.Provider itself, so this package's decision logic is unit-testable
// with a fake and carries no dependency on internal/llm's own settings
// resolution. internal/gateway adapts *llm.Provider.Complete to this
// interface at the one real call site.
type ModelAsker interface {
	// Ask sends one system+user prompt pair and returns the model's raw
	// text reply plus the model name that answered (for model_name
	// bookkeeping) — mirrors internal/llm.Provider.Complete's shape without
	// requiring this package to import internal/llm.Result.
	Ask(ctx context.Context, systemPrompt, userPrompt string) (text, model string, err error)
}

// ErrModelNotConfigured is returned when Mechanism 1 cannot settle a Sample
// and asker is nil (no model configured) — the caller's job is to fail
// CLOSED on this (drop the Finding, open no incident, log clearly) rather
// than guess, matching non-negotiable 8: never present a guess as a
// confident diagnosis. A future sweep with more live samples, or an
// operator configuring a model, resolves it without any code change here.
var ErrModelNotConfigured = errors.New("condition polarity: not enough live samples to infer polarity locally, and no model is configured to ask")

// ErrModelVerdictUnconfirmed is returned when the cached verdict for this
// pair is source="model" AND has NEVER, across every past Resolve call for
// this pair, been checked against a confident live sample (see the
// Verdict.EverConfirmed field and this file's own doc comment's "E11 —
// a wrong cached model verdict that can never self-correct" section).
//
// This is deliberately NOT the same condition as "this call's sample isn't
// confident" — that is the ordinary, common case for a rare Kind having a
// quiet moment, and BACKLOG.md E11's own text flags a per-call version of
// this check as a real noise cost: it would mark a well-corroborated
// verdict unverified every time its live population happened to dip, for
// no reason connected to whether the verdict is actually trustworthy. This
// error fires only for a pair that has structurally NEVER had a chance to
// be checked — the actual case E12 left open (a Kind that never
// accumulates minStatisticalSampleCount live instances at once, so path 1
// in the package doc comment can never run at all for it) — which is a
// materially different, and much rarer, condition.
//
// The caller's job is the same as for ErrModelNotConfigured: fail OPEN
// (non-negotiable 8) — proceed with the Finding, severity floored, clearly
// marked as unverified, rather than trust a guess that has literally never
// been checked against anything real.
var ErrModelVerdictUnconfirmed = errors.New("condition polarity: cached model verdict has never been corroborated by a confident live sample")

// Resolve returns the durable polarity verdict for one (Sample.Kind,
// Sample.ConditionType) pair, and decides — but does not itself decide
// fire-or-drop for the caller's Finding; internal/gateway's polarity gate
// does that by comparing the returned Verdict.BadValue against
// Sample.ObservedValue.
//
// tx must already be an open transaction (internal/gateway's handleFinding
// polarity gate runs this on a short-lived transaction of its own, separate
// from the finding-correlation transaction that follows, exactly like
// settings.Resolve's own "resolved once, fresh, before opening the
// transaction below" pattern) — Resolve does not begin or commit one
// itself, so the caller controls the boundary and can roll back cleanly on
// any error without touching unrelated state.
func Resolve(ctx context.Context, tx pgx.Tx, asker ModelAsker, s Sample) (Verdict, error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, lockKey(s.Kind, s.ConditionType)); err != nil {
		return Verdict{}, fmt.Errorf("condition polarity: acquire advisory lock for %s/%s: %w", s.Kind, s.ConditionType, err)
	}

	cached, err := lookup(ctx, tx, s.Kind, s.ConditionType)
	if err != nil {
		return Verdict{}, err
	}

	sampleConfident := s.MajorityValue != "" && s.SampleCount >= minStatisticalSampleCount && s.MajorityFraction >= minStatisticalConfidence

	if cached != nil && cached.Source == "model" {
		// BACKLOG.md E12: a cached MODEL verdict is a guess, not a fact
		// about this cluster, so a confident, DISAGREEING live sample
		// overrides it immediately — see the package doc comment's "path
		// 1". Checked before the TTL below so a strong contradicting
		// sample corrects a guess right away rather than waiting out the
		// week.
		if sampleConfident {
			statisticalBad := otherValue(s.MajorityValue)
			if statisticalBad != cached.BadValue {
				logger.WarnContext(ctx, "live sample disagrees with the cached model verdict; evidence overrides the guess",
					slog.String("kind", s.Kind), slog.String("condition_type", s.ConditionType),
					slog.Int("sample_count", s.SampleCount), slog.Float64("majority_fraction", s.MajorityFraction),
					slog.String("majority_value", s.MajorityValue), slog.String("cached_bad_value", cached.BadValue),
					slog.Duration("model_asked_ago", time.Since(cached.UpdatedAt).Round(time.Second)))
				v := Verdict{BadValue: statisticalBad, Source: "statistical"}
				if err := upsert(ctx, tx, s.Kind, s.ConditionType, v, s.SampleCount, s.MajorityFraction, ""); err != nil {
					return Verdict{}, err
				}
				return v, nil
			}
			// The sample is confident but AGREES with the cached guess —
			// this IS the corroboration event BACKLOG.md E11's gap is
			// about: it is the one thing that can ever make Resolve's
			// confident-sample branch above reachable for this pair at
			// all, so record that it happened. A pair too rare to ever
			// produce a confident sample will never reach this line, which
			// is exactly why cached.EverConfirmed staying false for it is
			// the correct, distinguishing signal below.
			if !cached.EverConfirmed {
				logger.InfoContext(ctx, "live sample agrees with the cached model verdict; marking it corroborated by real evidence",
					slog.String("kind", s.Kind), slog.String("condition_type", s.ConditionType),
					slog.Int("sample_count", s.SampleCount), slog.Float64("majority_fraction", s.MajorityFraction),
					slog.String("majority_value", s.MajorityValue), slog.String("cached_bad_value", cached.BadValue))
				if err := markConfirmed(ctx, tx, s.Kind, s.ConditionType); err != nil {
					return Verdict{}, err
				}
				cached.EverConfirmed = true
			}
		}
		// No disagreement (or no confident sample to check against) — a
		// stale-past-TTL model guess is still worth re-deriving so a
		// pair too rare to ever build a confident local sample (path 1
		// above can never fire for it) is not stuck on one guess forever.
		// "cached = nil" falls through to the ordinary derive-and-store
		// logic below exactly as if this were the first-ever Resolve for
		// this pair.
		if time.Since(cached.UpdatedAt) > modelVerdictTTL {
			logger.InfoContext(ctx, "cached model verdict is past its TTL and uncontradicted; re-deriving rather than trusting it forever",
				slog.String("kind", s.Kind), slog.String("condition_type", s.ConditionType),
				slog.Duration("age", time.Since(cached.UpdatedAt).Round(time.Hour)), slog.Duration("ttl", modelVerdictTTL))
			cached = nil
		}
	}

	if cached != nil {
		if cached.Source == "model" && !cached.EverConfirmed {
			// BACKLOG.md E11's own named-but-open gap in E12's fix: this
			// pair's cached verdict is a one-time model guess that has
			// NEVER — not on this call, and not on any past call either —
			// been checked against a confident live sample. E12's two
			// correction paths (the immediate override above, and the TTL
			// re-derive below) both still apply here, but neither one is
			// enough on its own: the override can only run when a
			// confident sample EXISTS to compare against, and a Kind that
			// structurally never accumulates minStatisticalSampleCount
			// live instances at once can never produce one — the TTL
			// bounds how long the guess persists, but re-asks the SAME
			// model, which can (and, measured on the disposable cluster,
			// does — BACKLOG.md E11) reproduce the identical wrong answer
			// every 7 days forever. So a verdict that has never once been
			// checkable is not treated as authoritative enough to justify
			// a silent drop — fail toward reporting instead (the same
			// non-negotiable 8 principle E12 already applied to every
			// OTHER unresolvable case), by returning the same shape of
			// error as ErrModelNotConfigured so the caller's existing
			// fail-open handling covers this case for free.
			return Verdict{}, fmt.Errorf("condition polarity: %s/%s cached model verdict (bad=%s) has never been checked against a confident live sample: %w",
				s.Kind, s.ConditionType, cached.BadValue, ErrModelVerdictUnconfirmed)
		}
		return *cached, nil
	}

	if sampleConfident {
		v := Verdict{BadValue: otherValue(s.MajorityValue), Source: "statistical"}
		if err := upsert(ctx, tx, s.Kind, s.ConditionType, v, s.SampleCount, s.MajorityFraction, ""); err != nil {
			return Verdict{}, err
		}
		return v, nil
	}

	if asker == nil {
		return Verdict{}, ErrModelNotConfigured
	}
	badValue, modelName, err := askModelPolarity(ctx, asker, s.Kind, s.ConditionType)
	if err != nil {
		return Verdict{}, err
	}
	v := Verdict{BadValue: badValue, Source: "model"}
	if err := upsert(ctx, tx, s.Kind, s.ConditionType, v, 0, 0, modelName); err != nil {
		return Verdict{}, err
	}
	return v, nil
}

func lockKey(kind, conditionType string) string {
	return kind + "\x1f" + conditionType
}

func otherValue(v string) string {
	if v == "True" {
		return "False"
	}
	return "True"
}

func lookup(ctx context.Context, tx pgx.Tx, kind, conditionType string) (*Verdict, error) {
	var v Verdict
	err := tx.QueryRow(ctx,
		`SELECT bad_value, source, updated_at, ever_confirmed FROM condition_polarity WHERE kind = $1 AND condition_type = $2`,
		kind, conditionType,
	).Scan(&v.BadValue, &v.Source, &v.UpdatedAt, &v.EverConfirmed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("condition polarity: lookup %s/%s: %w", kind, conditionType, err)
	}
	return &v, nil
}

// upsert writes v as the current verdict for (kind, conditionType),
// overwriting whatever was there before. BACKLOG.md E12 turned this from a
// write-once INSERT (ON CONFLICT DO NOTHING) into a real upsert on purpose:
// Resolve now has two paths that must replace an existing row rather than
// leave it untouched — a confident, disagreeing statistical sample
// overriding a model guess, and a TTL-expired model guess being
// re-derived — and both rely on this function actually overwriting rather
// than silently no-op'ing on a row that's already there. The advisory lock
// Resolve takes before ever calling this still serializes every writer for
// this exact (kind, condition_type) pair, so this remains a single mutation
// under a held lock, not a racing UPDATE.
func upsert(ctx context.Context, tx pgx.Tx, kind, conditionType string, v Verdict, sampleCount int, confidence float64, modelName string) error {
	var confidencePtr *float64
	if v.Source == "statistical" {
		confidencePtr = &confidence
	}
	var modelNamePtr *string
	if modelName != "" {
		modelNamePtr = &modelName
	}
	// ever_confirmed: a "statistical" verdict (Mechanism 1, or E12's
	// confident-override path) WAS real evidence about this cluster the
	// moment it was cached, so it starts (and effectively stays) true —
	// there is nothing left for a later sample to corroborate it with. A
	// freshly-derived "model" verdict (Mechanism 2's first-ever ask for
	// this pair) has not been checked against anything live yet, so it
	// starts false; Resolve's own confident-sample branch is what later
	// flips this to true via markConfirmed, never this function.
	everConfirmed := v.Source == "statistical"
	_, err := tx.Exec(ctx, `
		INSERT INTO condition_polarity (kind, condition_type, bad_value, source, sample_count, confidence, model_name, ever_confirmed, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
		ON CONFLICT (kind, condition_type) DO UPDATE SET
			bad_value = EXCLUDED.bad_value,
			source = EXCLUDED.source,
			sample_count = EXCLUDED.sample_count,
			confidence = EXCLUDED.confidence,
			model_name = EXCLUDED.model_name,
			ever_confirmed = EXCLUDED.ever_confirmed,
			updated_at = EXCLUDED.updated_at`,
		kind, conditionType, v.BadValue, v.Source, sampleCount, confidencePtr, modelNamePtr, everConfirmed)
	if err != nil {
		return fmt.Errorf("condition polarity: upsert %s/%s: %w", kind, conditionType, err)
	}
	return nil
}

// markConfirmed flips ever_confirmed to true for (kind, conditionType)
// without touching bad_value/source/sample_count/model_name — called only
// from Resolve's confident-sample-AGREES branch, the one moment a
// model-sourced verdict actually gets checked against live evidence and
// survives unchanged. (The disagreeing case instead calls upsert wholesale,
// converting the row to source="statistical", which makes this column moot
// for it from then on.) Resolve already holds this pair's advisory lock
// before ever reaching here, so a bare UPDATE is safe — no other writer for
// this exact (kind, condition_type) can be running concurrently.
func markConfirmed(ctx context.Context, tx pgx.Tx, kind, conditionType string) error {
	_, err := tx.Exec(ctx, `UPDATE condition_polarity SET ever_confirmed = true WHERE kind = $1 AND condition_type = $2`, kind, conditionType)
	if err != nil {
		return fmt.Errorf("condition polarity: mark %s/%s corroborated: %w", kind, conditionType, err)
	}
	return nil
}

// askModelPolarity is Mechanism 2: ask the model one narrow, closed-form
// question and require an unambiguous one-word answer. Never guesses on an
// unparseable reply — returns an error instead, so the caller fails closed
// (non-negotiable 8) rather than caching a wrong answer forever.
func askModelPolarity(ctx context.Context, asker ModelAsker, kind, conditionType string) (badValue, modelName string, err error) {
	const system = "You answer exactly one narrow factual question about the Kubernetes API. Reply with exactly one word and nothing else: True or False. No punctuation, no explanation, no extra words."
	user := fmt.Sprintf(
		"A Kubernetes object of kind %q may report a status.conditions[] entry of type %q. "+
			"For THIS condition type on THIS kind, does a status value of \"True\" indicate a PROBLEM "+
			"(an unhealthy or abnormal state)? Reply \"True\" if status=True is the problem indicator. "+
			"Reply \"False\" if instead status=False is the problem indicator (meaning True is the healthy value). "+
			"Answer with exactly one word: True or False.",
		kind, conditionType)

	text, model, err := asker.Ask(ctx, system, user)
	if err != nil {
		return "", "", fmt.Errorf("condition polarity: ask model for %s/%s: %w", kind, conditionType, err)
	}
	parsed := strings.Trim(strings.TrimSpace(text), ".\"'` \t\r\n")
	switch strings.ToLower(parsed) {
	case "true":
		return "True", model, nil
	case "false":
		return "False", model, nil
	default:
		return "", "", fmt.Errorf("condition polarity: model returned an unparseable polarity answer for %s/%s: %q", kind, conditionType, text)
	}
}
