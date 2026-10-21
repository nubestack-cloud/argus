package fleetgroup

import "testing"

// TestDecideGroupID_FewerThanTwoClusters covers Recompute's first branch:
// a fingerprint confined to 0 or 1 clusters is never grouped, regardless of
// whether it already carried a group id — this is the "does a group
// un-group when it drops to one cluster" judgment call Recompute's own doc
// comment says this file resolves in favor of "yes."
func TestDecideGroupID_FewerThanTwoClusters(t *testing.T) {
	if got := decideGroupID(0, nil); got != nil {
		t.Errorf("decideGroupID(0, nil) = %v, want nil", *got)
	}
	if got := decideGroupID(1, nil); got != nil {
		t.Errorf("decideGroupID(1, nil) = %v, want nil", *got)
	}
	// Even if this single remaining incident still carries a stale group id
	// from before the fingerprint shrank to one cluster, it must be cleared.
	if got := decideGroupID(1, map[string]bool{"fgrp_old": true}); got != nil {
		t.Errorf("decideGroupID(1, {fgrp_old}) = %v, want nil (a lone cluster must ungroup even if it still carries an old id)", *got)
	}
}

// TestDecideGroupID_TwoOrMoreNoExistingGroup covers "two previously-
// unrelated single-cluster incidents both now need to join the same
// group" — a brand new id is minted.
func TestDecideGroupID_TwoOrMoreNoExistingGroup(t *testing.T) {
	got := decideGroupID(2, map[string]bool{})
	if got == nil {
		t.Fatal("decideGroupID(2, {}) = nil, want a newly minted group id")
	}
	if *got == "" {
		t.Error("decideGroupID(2, {}) returned an empty id")
	}
}

// TestDecideGroupID_ReusesTheOneExistingGroup covers "a third cluster joins
// an existing group" — the single existing id is reused, not replaced.
func TestDecideGroupID_ReusesTheOneExistingGroup(t *testing.T) {
	got := decideGroupID(3, map[string]bool{"fgrp_existing": true})
	if got == nil || *got != "fgrp_existing" {
		t.Errorf("decideGroupID(3, {fgrp_existing}) = %v, want fgrp_existing", got)
	}
}

// TestDecideGroupID_MergesToLexicographicallySmallest covers the merge
// branch Recompute's doc comment says should be unreachable in practice
// but is still handled explicitly: when more than one distinct group id
// exists among a fingerprint's currently-open incidents, the
// lexicographically smallest (== oldest, since ids are ULIDs) wins.
func TestDecideGroupID_MergesToLexicographicallySmallest(t *testing.T) {
	got := decideGroupID(3, map[string]bool{"fgrp_bbb": true, "fgrp_aaa": true, "fgrp_ccc": true})
	if got == nil || *got != "fgrp_aaa" {
		t.Errorf("decideGroupID(3, {fgrp_bbb, fgrp_aaa, fgrp_ccc}) = %v, want fgrp_aaa (lexicographically smallest)", got)
	}
}

func TestIsClosedState(t *testing.T) {
	closed := []string{"Resolved", "Dismissed"}
	for _, s := range closed {
		if !IsClosedState(s) {
			t.Errorf("IsClosedState(%q) = false, want true", s)
		}
	}
	open := []string{"Detected", "Investigating", "RecommendationReady", "AwaitingApproval", "NeedsHumanInvestigation", "Reopened", ""}
	for _, s := range open {
		if IsClosedState(s) {
			t.Errorf("IsClosedState(%q) = true, want false", s)
		}
	}
}
