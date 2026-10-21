package gateway

import (
	"strings"
	"testing"
)

// TestEarnedPromotionObservationQueryUsesTheObservationClock is the cheap
// half of PROJECT.md B155's guard, and it exists because of an explicit
// gap: every behavioural test of this criterion lives in
// earned_promotion_db_test.go, and those t.Skip cleanly on a machine with
// no ARGUS_TEST_DATABASE_URL — so on such a machine a revert to
// occurred_at would produce a fully green `go test ./...` while the
// criterion was once again permanently unsatisfiable for a stable
// condition.
//
// It asserts against earnedPromotionObservationQuery itself — the exact
// string earnedFaultPromotionEligible executes — rather than a second
// hand-copied query, so it cannot pass while the live path disagrees with
// it. What it deliberately does NOT do is re-state the whole query: only
// the one property B155 is about (which column the window and the lookback
// are computed from), leaving behaviour to the DB-backed tests.
func TestEarnedPromotionObservationQueryUsesTheObservationClock(t *testing.T) {
	q := earnedPromotionObservationQuery

	for _, want := range []string{"min(ingested_at)", "max(ingested_at)", "ingested_at >= $6"} {
		if !strings.Contains(q, want) {
			t.Errorf("earnedPromotionObservationQuery does not contain %q:\n%s", want, q)
		}
	}
	// occurred_at is the agent-supplied time the PROBLEM began — for a
	// condition, its own lastTransitionTime, which is constant for as long
	// as the condition does not flap. It must play no part in deciding how
	// long ARGUS has been OBSERVING the anomaly, in either the aggregate or
	// the lookback bound.
	if strings.Contains(q, "occurred_at") {
		t.Errorf("earnedPromotionObservationQuery mentions occurred_at — the sustained window and its lookback must both read ingested_at (PROJECT.md B155):\n%s", q)
	}
}
