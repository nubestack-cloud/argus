package objectgroup

import "testing"

// TestDecideGroupID_FewerThanTwoIncidents mirrors
// replicagroup.TestDecideGroupID_FewerThanTwoIncidents/fleetgroup's own,
// re-scoped: an anchor workload touched by 0 or 1 currently-open incidents
// (whether that's just the workload's own incident with nothing pointing at
// it, or just a PVC/Service incident with the workload's own incident not
// open) is never grouped, even if the lone incident still carries a stale
// group id from before a sibling closed.
func TestDecideGroupID_FewerThanTwoIncidents(t *testing.T) {
	if got := decideGroupID(0, nil); got != nil {
		t.Errorf("decideGroupID(0, nil) = %v, want nil", *got)
	}
	if got := decideGroupID(1, nil); got != nil {
		t.Errorf("decideGroupID(1, nil) = %v, want nil", *got)
	}
	if got := decideGroupID(1, map[string]bool{"ogrp_old": true}); got != nil {
		t.Errorf("decideGroupID(1, {ogrp_old}) = %v, want nil (a lone member must ungroup even if it still carries an old id)", *got)
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
	got := decideGroupID(3, map[string]bool{"ogrp_existing": true})
	if got == nil || *got != "ogrp_existing" {
		t.Errorf("decideGroupID(3, {ogrp_existing}) = %v, want ogrp_existing", got)
	}
}

func TestDecideGroupID_MergesToLexicographicallySmallest(t *testing.T) {
	got := decideGroupID(3, map[string]bool{"ogrp_bbb": true, "ogrp_aaa": true, "ogrp_ccc": true})
	if got == nil || *got != "ogrp_aaa" {
		t.Errorf("decideGroupID(3, {ogrp_bbb, ogrp_aaa, ogrp_ccc}) = %v, want ogrp_aaa (lexicographically smallest)", got)
	}
}

// TestRecompute_EmptyAnchorIsNoOp documents Recompute's guard against being
// called with "" — every real call site (internal/gateway, internal/
// orchestrator) already checks this before calling, but Recompute must not
// trust that: passing a nil tx here would panic if the empty-string guard
// ever stopped short-circuiting before reaching it.
func TestRecompute_EmptyAnchorIsNoOp(t *testing.T) {
	if err := Recompute(nil, nil, "cl_test", ""); err != nil { //nolint:staticcheck // nil ctx/tx deliberately unused on the guarded path
		t.Errorf("Recompute with an empty anchor key returned %v, want nil (no-op, must not touch tx)", err)
	}
}
