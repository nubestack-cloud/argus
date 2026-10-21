package replicagroup

import "testing"

// TestDecideGroupID_FewerThanTwoIncidents mirrors
// fleetgroup.TestDecideGroupID_FewerThanTwoClusters, re-scoped: a
// (workload, reason) pair with 0 or 1 currently-open incidents is never
// grouped, even if the lone incident still carries a stale group id from
// before a sibling closed.
func TestDecideGroupID_FewerThanTwoIncidents(t *testing.T) {
	if got := decideGroupID(0, nil); got != nil {
		t.Errorf("decideGroupID(0, nil) = %v, want nil", *got)
	}
	if got := decideGroupID(1, nil); got != nil {
		t.Errorf("decideGroupID(1, nil) = %v, want nil", *got)
	}
	if got := decideGroupID(1, map[string]bool{"wgrp_old": true}); got != nil {
		t.Errorf("decideGroupID(1, {wgrp_old}) = %v, want nil (a lone sibling must ungroup even if it still carries an old id)", *got)
	}
}

func TestDecideGroupID_TwoOrMoreNoExistingGroup(t *testing.T) {
	got := decideGroupID(2, map[string]bool{})
	if got == nil {
		t.Fatal("decideGroupID(2, {}) = nil, want a newly minted group id")
	}
	if *got == "" {
		t.Error("decideGroupID(2, {}) returned an empty id")
	}
}

func TestDecideGroupID_ReusesTheOneExistingGroup(t *testing.T) {
	got := decideGroupID(3, map[string]bool{"wgrp_existing": true})
	if got == nil || *got != "wgrp_existing" {
		t.Errorf("decideGroupID(3, {wgrp_existing}) = %v, want wgrp_existing", got)
	}
}

func TestDecideGroupID_MergesToLexicographicallySmallest(t *testing.T) {
	got := decideGroupID(3, map[string]bool{"wgrp_bbb": true, "wgrp_aaa": true, "wgrp_ccc": true})
	if got == nil || *got != "wgrp_aaa" {
		t.Errorf("decideGroupID(3, {wgrp_bbb, wgrp_aaa, wgrp_ccc}) = %v, want wgrp_aaa (lexicographically smallest)", got)
	}
}
