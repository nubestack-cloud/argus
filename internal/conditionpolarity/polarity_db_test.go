package conditionpolarity

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// testPool matches the ARGUS_TEST_DATABASE_URL convention every other
// DB-backed test in this codebase uses (e.g.
// internal/gateway/finding_db_test.go) — a clean skip on a machine with no
// test database, never a hard failure.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connString := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if connString == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping DB-backed condition_polarity test")
	}
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// cleanupPolarityRow deletes any row this test may have written for
// (kind, conditionType), so each test starts from "no cached verdict"
// regardless of what an earlier run left behind — this table has no
// invalidation/TTL by design (see this package's own doc comment), so tests
// have to do it themselves.
func cleanupPolarityRow(t *testing.T, pool *pgxpool.Pool, kind, conditionType string) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `DELETE FROM condition_polarity WHERE kind = $1 AND condition_type = $2`, kind, conditionType)
	if err != nil {
		t.Fatalf("cleanup condition_polarity row for %s/%s: %v", kind, conditionType, err)
	}
}

func TestResolve_ConfidentStatisticalSample_CachesAsBadValueOtherThanMajority(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	kind, condType := "E11TestWidget", "Ready"
	cleanupPolarityRow(t, pool, kind, condType)
	t.Cleanup(func() { cleanupPolarityRow(t, pool, kind, condType) })

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	sample := Sample{
		Kind: kind, ConditionType: condType, ObservedValue: "False",
		SampleCount: 5, MajorityValue: "True", MajorityFraction: 0.8,
	}
	// No asker: a confident statistical sample must never need one.
	v, err := Resolve(ctx, tx, nil, sample)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v.Source != "statistical" {
		t.Fatalf("expected source=statistical, got %q", v.Source)
	}
	if v.BadValue != "False" {
		t.Fatalf("expected bad value False (the minority reading), got %q", v.BadValue)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// A second, independent Resolve call must now find the cached row
	// rather than recomputing — verified by passing a sample that, taken at
	// face value, would suggest the OPPOSITE verdict, and confirming the
	// cache still wins.
	tx2, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx2.Rollback(ctx) //nolint:errcheck
	v2, err := Resolve(ctx, tx2, nil, Sample{Kind: kind, ConditionType: condType, ObservedValue: "True", SampleCount: 1})
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	// Compare BadValue/Source only, not UpdatedAt: v was returned by the
	// INSERT path, which never round-trips the DB's own now() back into the
	// struct, while v2 came from a real lookup — the two are never going to
	// carry an identical timestamp, and that is not what this test is
	// checking. What matters is that v2 is the SAME verdict as v, not a
	// freshly re-derived one from the (intentionally contradictory) second
	// sample.
	if v2.BadValue != v.BadValue || v2.Source != v.Source {
		t.Fatalf("expected the cached verdict to be returned unchanged, got %+v want %+v", v2, v)
	}
}

// TestResolve_ConfidentStatisticalSample_HandlesInvertedPolarityCorrectly is
// PROJECT.md's Gateway API item, item (c)'s own direct regression test: every
// existing statistical-path test up to this one uses MajorityValue: "True"
// (the ordinary "Ready=True is healthy" shape), so the OTHER direction —
// Gateway API's own `Conflicted` condition on `Gateway`/`HTTPRoute`, where
// `Conflicted=True` is the PROBLEM and most live objects correctly report
// `Conflicted=False` — had never actually been exercised. otherValue's own
// logic is symmetric by construction (it has no notion of which literal
// value "means" healthy, only which one the majority currently reports), so
// this is expected to pass without a code change — proving that, not just
// asserting it, is the point: a majority-vote mechanism is exactly the kind
// of code an untested inverted case could silently break without anyone
// noticing, since every other live condition type this project has tested
// against so far happens to share the same direction.
func TestResolve_ConfidentStatisticalSample_HandlesInvertedPolarityCorrectly(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	kind, condType := "Gateway", "Conflicted"
	cleanupPolarityRow(t, pool, kind, condType)
	t.Cleanup(func() { cleanupPolarityRow(t, pool, kind, condType) })

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// The realistic live shape: most Gateways do not conflict with each
	// other, so the majority correctly reports Conflicted=False.
	sample := Sample{
		Kind: kind, ConditionType: condType, ObservedValue: "True",
		SampleCount: 8, MajorityValue: "False", MajorityFraction: 0.875,
	}
	v, err := Resolve(ctx, tx, nil, sample)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v.Source != "statistical" {
		t.Fatalf("expected source=statistical, got %q", v.Source)
	}
	// This is the one assertion that matters: BadValue must be "True" —
	// the minority reading — NOT "False" from some hidden assumption that
	// False is always the safe/healthy default.
	if v.BadValue != "True" {
		t.Fatalf("expected bad value True (Conflicted=True is the problem, and it is the minority reading here), got %q — a majority-vote mechanism that silently assumed False is always healthy would produce exactly this wrong answer", v.BadValue)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func TestResolve_InsufficientSample_AsksModelAndCaches(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	kind, condType := "E11TestNode", "MemoryPressure"
	cleanupPolarityRow(t, pool, kind, condType)
	t.Cleanup(func() { cleanupPolarityRow(t, pool, kind, condType) })

	asker := fakeAsker{text: "True", model: "test-model-v1"}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	sample := Sample{Kind: kind, ConditionType: condType, ObservedValue: "True", SampleCount: 1}
	v, err := Resolve(ctx, tx, asker, sample)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v.Source != "model" || v.BadValue != "True" {
		t.Fatalf("expected model-sourced verdict True, got %+v", v)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Re-resolving with the SAME still-too-thin sample must not re-ask the
	// model either (a DIFFERENT, wrong-if-taken-at-face-value reply proves
	// it: if Resolve called this asker, v2 would come back "False" instead
	// of erroring) — but, since BACKLOG.md E11's own fix, it must ALSO no
	// longer hand back the cached verdict as if it had been checked:
	// EverConfirmed is still false (this pair has never once had a
	// confident sample to compare against), so this is exactly the
	// structural case ErrModelVerdictUnconfirmed exists for. Before that
	// fix this assertion read "expected the cached model verdict (True) to
	// win over a fresh ask" — that was the bug: a Kind this rare would
	// never have gotten another chance to correct a wrong guess.
	tx2, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx2.Rollback(ctx) //nolint:errcheck
	neverCalled := fakeAsker{text: "False"}
	_, err = Resolve(ctx, tx2, neverCalled, sample)
	if !errors.Is(err, ErrModelVerdictUnconfirmed) {
		t.Fatalf("expected ErrModelVerdictUnconfirmed for a never-corroborated cached model verdict re-resolved from another too-thin sample, got %v", err)
	}
}

func TestResolve_NoAskerAndInsufficientSample_ReturnsErrModelNotConfigured(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	kind, condType := "E11TestSolo", "Ready"
	cleanupPolarityRow(t, pool, kind, condType)
	t.Cleanup(func() { cleanupPolarityRow(t, pool, kind, condType) })

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	_, err = Resolve(ctx, tx, nil, Sample{Kind: kind, ConditionType: condType, ObservedValue: "False", SampleCount: 1})
	if !errors.Is(err, ErrModelNotConfigured) {
		t.Fatalf("expected ErrModelNotConfigured, got %v", err)
	}
}

// TestResolve_ConfidentContradictingSample_OverridesCachedModelVerdict is
// BACKLOG.md E12's own acceptance shape, exercised as a unit test: a wrong
// model-sourced verdict must not survive contact with a confident,
// disagreeing live sample. This is the exact mechanism the live disposable-
// cluster reproduction (CAPABILITIES.md) also proves end to end; this test
// pins the DB-level logic on its own, fast and without a cluster.
func TestResolve_ConfidentContradictingSample_OverridesCachedModelVerdict(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	kind, condType := "E11TestDeployment", "Available"
	cleanupPolarityRow(t, pool, kind, condType)
	t.Cleanup(func() { cleanupPolarityRow(t, pool, kind, condType) })

	// Seed a WRONG model verdict, exactly as a weak model asked once would:
	// "True" is the bad value, when in reality False (Available=False) is
	// the real problem indicator.
	tx0, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	seed, err := Resolve(ctx, tx0, fakeAsker{text: "True", model: "weak-model"}, Sample{
		Kind: kind, ConditionType: condType, ObservedValue: "False", SampleCount: 1,
	})
	if err != nil {
		t.Fatalf("seed Resolve: %v", err)
	}
	if seed.Source != "model" || seed.BadValue != "True" {
		t.Fatalf("seed: expected the wrong model verdict (bad=True) to be cached, got %+v", seed)
	}
	if err := tx0.Commit(ctx); err != nil {
		t.Fatalf("seed commit: %v", err)
	}

	// Now a confident, DISAGREEING live majority arrives: 9 of 10 instances
	// read True (healthy), one reads False — statistically, False is the
	// bad value, contradicting the cached model verdict's True.
	tx1, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx1.Rollback(ctx)                    //nolint:errcheck
	got, err := Resolve(ctx, tx1, nil, Sample{ // no asker: must not be needed
		Kind: kind, ConditionType: condType, ObservedValue: "False",
		SampleCount: 10, MajorityValue: "True", MajorityFraction: 0.9,
	})
	if err != nil {
		t.Fatalf("Resolve with contradicting evidence: %v", err)
	}
	if got.Source != "statistical" {
		t.Fatalf("expected the confident live sample to override the cache with a statistical verdict, got source=%q", got.Source)
	}
	if got.BadValue != "False" {
		t.Fatalf("expected the override to correct the bad value to False (the real minority reading), got %q", got.BadValue)
	}
	if err := tx1.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// The correction must have actually persisted — a third, independent
	// call with NO sample confidence at all must now see the CORRECTED
	// verdict, not the original wrong one.
	tx2, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx2.Rollback(ctx) //nolint:errcheck
	final, err := Resolve(ctx, tx2, nil, Sample{Kind: kind, ConditionType: condType, ObservedValue: "True", SampleCount: 1})
	if err != nil {
		t.Fatalf("final Resolve: %v", err)
	}
	if final.BadValue != "False" || final.Source != "statistical" {
		t.Fatalf("expected the persisted, corrected verdict on a later call, got %+v", final)
	}
}

// TestResolve_LowConfidenceContradictingSample_CachedModelVerdictStands
// confirms the override in the test above is genuinely gated on the SAME
// confidence bar Mechanism 1 always uses, not on mere disagreement: a
// sample that disagrees but does not clear minStatisticalSampleCount/
// minStatisticalConfidence must NOT trigger the override — the verdict is
// not silently REWRITTEN. Since BACKLOG.md E11's own fix, though, it is
// also not silently trusted as-is: this cached verdict has never once been
// checked against a confident sample (only ever-thinner, disagreeing ones),
// so it now surfaces as ErrModelVerdictUnconfirmed rather than standing
// unchanged and unremarked — the name predates that fix; kept because the
// "not overridden" half of the claim is still exactly what this pins.
func TestResolve_LowConfidenceContradictingSample_CachedModelVerdictStands(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	kind, condType := "E11TestHPA", "AbleToScale"
	cleanupPolarityRow(t, pool, kind, condType)
	t.Cleanup(func() { cleanupPolarityRow(t, pool, kind, condType) })

	tx0, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := Resolve(ctx, tx0, fakeAsker{text: "True", model: "weak-model"}, Sample{
		Kind: kind, ConditionType: condType, ObservedValue: "False", SampleCount: 1,
	}); err != nil {
		t.Fatalf("seed Resolve: %v", err)
	}
	if err := tx0.Commit(ctx); err != nil {
		t.Fatalf("seed commit: %v", err)
	}

	tx1, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx1.Rollback(ctx) //nolint:errcheck
	// Disagrees (implies bad=False), but only 2 samples and 0.5 fraction —
	// well below the confidence bar.
	_, err = Resolve(ctx, tx1, nil, Sample{
		Kind: kind, ConditionType: condType, ObservedValue: "False",
		SampleCount: 2, MajorityValue: "True", MajorityFraction: 0.5,
	})
	if !errors.Is(err, ErrModelVerdictUnconfirmed) {
		t.Fatalf("expected ErrModelVerdictUnconfirmed (not overridden, but also never corroborated), got %v", err)
	}
}

// TestResolve_StaleModelVerdict_ReDerivedNotTrustedForever proves the
// second, TTL-based correction path exists independently of the
// contradicting-evidence path above — for a pair too rare to ever
// accumulate a confident local sample, this is the only thing standing
// between a wrong model guess and permanence.
func TestResolve_StaleModelVerdict_ReDerivedNotTrustedForever(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	kind, condType := "E11TestRareCRD", "Synced"
	cleanupPolarityRow(t, pool, kind, condType)
	t.Cleanup(func() { cleanupPolarityRow(t, pool, kind, condType) })

	tx0, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := Resolve(ctx, tx0, fakeAsker{text: "True", model: "weak-model"}, Sample{
		Kind: kind, ConditionType: condType, ObservedValue: "False", SampleCount: 1,
	}); err != nil {
		t.Fatalf("seed Resolve: %v", err)
	}
	if err := tx0.Commit(ctx); err != nil {
		t.Fatalf("seed commit: %v", err)
	}

	// Backdate updated_at past the TTL directly — this package builds no
	// clock-injection seam for Resolve (a real wall-clock TTL has no
	// meaningful fake in a DB-backed test), so ageing the row this way is
	// the direct, honest way to prove the expiry branch without waiting a
	// literal week.
	if _, err := pool.Exec(ctx,
		`UPDATE condition_polarity SET updated_at = now() - interval '8 days' WHERE kind = $1 AND condition_type = $2`,
		kind, condType); err != nil {
		t.Fatalf("backdate updated_at: %v", err)
	}

	tx1, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx1.Rollback(ctx) //nolint:errcheck
	// Still no confident sample (SampleCount=1) — the TTL path, not the
	// contradicting-evidence path, must be what re-derives this.
	got, err := Resolve(ctx, tx1, fakeAsker{text: "False", model: "better-model"}, Sample{
		Kind: kind, ConditionType: condType, ObservedValue: "False", SampleCount: 1,
	})
	if err != nil {
		t.Fatalf("Resolve past TTL: %v", err)
	}
	if got.Source != "model" || got.BadValue != "False" {
		t.Fatalf("expected the stale, uncontradicted model verdict to be re-derived (asking again) past its TTL, got %+v", got)
	}
}

func TestResolve_AmbiguousSample_FallsBackToModel(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	kind, condType := "E11TestAmbiguous", "Ready"
	cleanupPolarityRow(t, pool, kind, condType)
	t.Cleanup(func() { cleanupPolarityRow(t, pool, kind, condType) })

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Enough samples, but below the confidence bar (0.6 < minStatisticalConfidence) —
	// Mechanism 1 must decline and fall through to Mechanism 2.
	sample := Sample{
		Kind: kind, ConditionType: condType, ObservedValue: "False",
		SampleCount: 10, MajorityValue: "True", MajorityFraction: 0.6,
	}
	v, err := Resolve(ctx, tx, fakeAsker{text: "False"}, sample)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v.Source != "model" {
		t.Fatalf("expected an ambiguous local sample to fall back to the model, got source=%q", v.Source)
	}
}

// TestResolve_NeverConfirmedModelVerdict_UnverifiedEvenAfterManyThinCalls is
// BACKLOG.md E11's own reproduction at the package level (the gateway-level
// reproduction is internal/gateway/polarity_gate_test.go's
// TestApplyConditionPolarityGate_UncorroboratedModelVerdict_RealFaultSurfaces):
// repeated Resolve calls for a pair that NEVER once produces a confident
// sample must keep surfacing ErrModelVerdictUnconfirmed — this is not a
// one-shot fluke of "the very next call," it holds no matter how many times
// the pair is resolved, because nothing about repetition alone corroborates
// a guess.
func TestResolve_NeverConfirmedModelVerdict_UnverifiedEvenAfterManyThinCalls(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	kind, condType := "E11TestForeverRareCRD", "Synced"
	cleanupPolarityRow(t, pool, kind, condType)
	t.Cleanup(func() { cleanupPolarityRow(t, pool, kind, condType) })

	tx0, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := Resolve(ctx, tx0, fakeAsker{text: "True", model: "weak-model"}, Sample{
		Kind: kind, ConditionType: condType, ObservedValue: "False", SampleCount: 1,
	}); err != nil {
		t.Fatalf("seed Resolve: %v", err)
	}
	if err := tx0.Commit(ctx); err != nil {
		t.Fatalf("seed commit: %v", err)
	}

	for i := 0; i < 3; i++ {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin call %d: %v", i, err)
		}
		func() {
			defer tx.Rollback(ctx) //nolint:errcheck
			_, err = Resolve(ctx, tx, nil, Sample{Kind: kind, ConditionType: condType, ObservedValue: "False", SampleCount: 1})
			if !errors.Is(err, ErrModelVerdictUnconfirmed) {
				t.Fatalf("call %d: expected ErrModelVerdictUnconfirmed to persist across repeated thin calls, got %v", i, err)
			}
		}()
	}
}

// TestResolve_ConfidentAgreeingSample_CorroboratesThenStandsDespiteLaterThinSample
// is the regression guard for the fix above, at the package level (mirrors
// internal/gateway/polarity_gate_test.go's
// TestApplyConditionPolarityGate_CorroboratedModelVerdict_StillDrops): once a
// confident live sample has agreed with a cached model verdict even ONE
// time, EverConfirmed is durably true, and a LATER call with a thin sample
// must return the verdict normally — not ErrModelVerdictUnconfirmed. This is
// what distinguishes the chosen "ever confirmed, historically" design from a
// bare per-call confidence check: a Kind that is usually well-populated but
// has one quiet call must not be spuriously flagged.
func TestResolve_ConfidentAgreeingSample_CorroboratesThenStandsDespiteLaterThinSample(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	kind, condType := "E11TestUsuallyPopulousCRD", "Synced"
	cleanupPolarityRow(t, pool, kind, condType)
	t.Cleanup(func() { cleanupPolarityRow(t, pool, kind, condType) })

	tx0, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	seed, err := Resolve(ctx, tx0, fakeAsker{text: "False", model: "some-model"}, Sample{
		Kind: kind, ConditionType: condType, ObservedValue: "True", SampleCount: 1,
	})
	if err != nil {
		t.Fatalf("seed Resolve: %v", err)
	}
	if seed.Source != "model" || seed.BadValue != "False" {
		t.Fatalf("seed: expected model-sourced verdict bad=False, got %+v", seed)
	}
	if err := tx0.Commit(ctx); err != nil {
		t.Fatalf("seed commit: %v", err)
	}

	// A confident sample arrives that AGREES with the cached guess: the
	// seed says bad_value=False, i.e. True is the healthy reading, so an
	// agreeing sample must report True as the confident MAJORITY (most
	// peers healthy) — otherValue("True") == "False" == cached.BadValue.
	tx1, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx1.Rollback(ctx) //nolint:errcheck
	confirmed, err := Resolve(ctx, tx1, nil, Sample{
		Kind: kind, ConditionType: condType, ObservedValue: "False",
		SampleCount: 10, MajorityValue: "True", MajorityFraction: 0.9,
	})
	if err != nil {
		t.Fatalf("confirming Resolve: %v", err)
	}
	if confirmed.Source != "model" || confirmed.BadValue != "False" || !confirmed.EverConfirmed {
		t.Fatalf("expected the agreeing confident sample to leave the verdict model-sourced but mark it EverConfirmed, got %+v", confirmed)
	}
	if err := tx1.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// A LATER call with a thin sample must still return the verdict
	// normally — this pair has been corroborated, even though this
	// particular call has nothing confident to check again.
	tx2, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx2.Rollback(ctx) //nolint:errcheck
	later, err := Resolve(ctx, tx2, nil, Sample{Kind: kind, ConditionType: condType, ObservedValue: "True", SampleCount: 1})
	if err != nil {
		t.Fatalf("later thin-sample Resolve: %v (expected the corroborated verdict to stand, not error)", err)
	}
	if later.BadValue != "False" || later.Source != "model" {
		t.Fatalf("expected the corroborated verdict to stand unchanged, got %+v", later)
	}
}
