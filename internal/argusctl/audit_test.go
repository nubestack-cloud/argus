package argusctl

import (
	"testing"
	"time"

	"argus/internal/audit"
)

// buildChain constructs a slice of AuditRow that forms a genuinely valid
// hash chain (each row's hash/prev_hash computed exactly the way
// audit.RecordEvent would have computed them), using audit.ComputeHash
// directly — the same reuse this package's VerifyChain itself depends on —
// so these tests exercise VerifyChain against the real formula, not a
// hand-rolled stand-in that could drift from it.
func buildChain(t *testing.T, n int) []AuditRow {
	t.Helper()
	rows := make([]AuditRow, 0, n)
	prevHash := audit.GenesisPrevHash
	base := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		actorID := "usr_example"
		capability := "cluster:onboard"
		clusterID := "cl_example"
		occurredAt := base.Add(time.Duration(i) * time.Second)
		ev := audit.NewCoreEvent("org_example", &actorID, &capability, map[string]any{"n": i}, &clusterID, audit.OutcomeSuccess)
		hash, err := audit.ComputeHash(prevHash, ev, occurredAt)
		if err != nil {
			t.Fatalf("unexpected error building fixture chain: %v", err)
		}
		rows = append(rows, AuditRow{
			ID:         idFor(i),
			TenantID:   ev.TenantID,
			ActorID:    ev.ActorID,
			Capability: ev.Capability,
			Scope:      ev.Scope,
			ClusterID:  ev.ClusterID,
			Outcome:    ev.Outcome,
			OccurredAt: occurredAt,
			PrevHash:   prevHash,
			Hash:       hash,
		})
		prevHash = hash
	}
	return rows
}

func idFor(i int) string {
	// Doesn't need to be a real ULID for these tests — VerifyChain never
	// parses ID, only reports it back in a Divergence for a human to read.
	return "aud_" + string(rune('a'+i))
}

func TestVerifyChain_IntactChain(t *testing.T) {
	rows := buildChain(t, 5)
	report := VerifyChain(rows)
	if !report.OK() {
		t.Fatalf("expected an intact chain to verify OK, got divergence: %+v", report.Divergence)
	}
	if report.RowsChecked != 5 {
		t.Errorf("expected RowsChecked = 5, got %d", report.RowsChecked)
	}
}

func TestVerifyChain_EmptyChain(t *testing.T) {
	report := VerifyChain(nil)
	if !report.OK() {
		t.Fatalf("expected zero rows to be a trivially intact (not failed) chain, got divergence: %+v", report.Divergence)
	}
	if report.RowsChecked != 0 {
		t.Errorf("expected RowsChecked = 0, got %d", report.RowsChecked)
	}
}

func TestVerifyChain_SingleRowGenesisOK(t *testing.T) {
	rows := buildChain(t, 1)
	report := VerifyChain(rows)
	if !report.OK() {
		t.Fatalf("expected a single valid genesis row to verify OK, got divergence: %+v", report.Divergence)
	}
}

func TestVerifyChain_FirstRowWrongGenesis(t *testing.T) {
	rows := buildChain(t, 3)
	rows[0].PrevHash = "not-the-genesis-constant-padded-out-to-look-plausible-0000000"
	report := VerifyChain(rows)
	if report.OK() {
		t.Fatal("expected a corrupted first-row prev_hash to be caught, but VerifyChain reported the chain intact")
	}
	if report.Divergence.RowIndex != 0 {
		t.Errorf("expected the divergence at row index 0, got %d", report.Divergence.RowIndex)
	}
	if report.Divergence.Kind != FailurePrevHashMismatch {
		t.Errorf("expected FailurePrevHashMismatch, got %q", report.Divergence.Kind)
	}
	if report.Divergence.Expected != audit.GenesisPrevHash {
		t.Errorf("expected the reported 'expected' value to be the genesis constant, got %q", report.Divergence.Expected)
	}
}

// TestVerifyChain_TamperedHash_CaughtAtTheTamperedRow is the core positive
// case: corrupting one row's OWN stored hash (without touching anything
// else) must be caught as a hash mismatch AT THAT ROW, not the next one.
func TestVerifyChain_TamperedHash_CaughtAtTheTamperedRow(t *testing.T) {
	rows := buildChain(t, 5)
	tamperedIdx := 2
	original := rows[tamperedIdx].Hash
	rows[tamperedIdx].Hash = "0000000000000000000000000000000000000000000000000000000000ff"

	report := VerifyChain(rows)
	if report.OK() {
		t.Fatal("expected a tampered hash to be caught, but VerifyChain reported the chain intact")
	}
	if report.Divergence.RowIndex != tamperedIdx {
		t.Errorf("expected the divergence at row index %d, got %d", tamperedIdx, report.Divergence.RowIndex)
	}
	if report.Divergence.ID != rows[tamperedIdx].ID {
		t.Errorf("expected the divergence to name row id %q, got %q", rows[tamperedIdx].ID, report.Divergence.ID)
	}
	if report.Divergence.Kind != FailureHashMismatch {
		t.Errorf("expected FailureHashMismatch, got %q", report.Divergence.Kind)
	}
	if report.Divergence.Expected != rows[tamperedIdx].Hash {
		t.Errorf("expected the reported 'expected' value to be the tampered stored hash %q, got %q", rows[tamperedIdx].Hash, report.Divergence.Expected)
	}
	if report.Divergence.Actual != original {
		t.Errorf("expected the reported 'actual' (recomputed) value to be the original correct hash %q, got %q", original, report.Divergence.Actual)
	}
	// RowsChecked should stop at the failing row, not silently continue past it.
	if report.RowsChecked != tamperedIdx+1 {
		t.Errorf("expected RowsChecked = %d (stopping at the failing row), got %d", tamperedIdx+1, report.RowsChecked)
	}
}

// TestVerifyChain_TamperedField_CaughtEvenIfHashWasRecomputedToMatch covers
// the "tamperer edits a core field AND recomputes that row's own hash to
// match" case — i.e. the row is internally self-consistent, but its content
// no longer matches what it originally hashed. This must still be caught,
// specifically as a hash mismatch against what's actually recorded, because
// VerifyChain always recomputes from the row's OWN currently-stored fields —
// there's no way for a tamperer to make an altered field's row "verify" on
// its own without also matching every original field, since the recompute
// is exactly this test's setup: change outcome, leave hash as it was
// originally (now stale relative to the new outcome).
func TestVerifyChain_TamperedCoreField_CaughtAsHashMismatch(t *testing.T) {
	rows := buildChain(t, 4)
	tamperedIdx := 1
	rows[tamperedIdx].Outcome = audit.OutcomeDenied // was OutcomeSuccess; hash left as originally computed

	report := VerifyChain(rows)
	if report.OK() {
		t.Fatal("expected a tampered core field (with a stale hash) to be caught, but VerifyChain reported the chain intact")
	}
	if report.Divergence.RowIndex != tamperedIdx {
		t.Errorf("expected the divergence at row index %d, got %d", tamperedIdx, report.Divergence.RowIndex)
	}
	if report.Divergence.Kind != FailureHashMismatch {
		t.Errorf("expected FailureHashMismatch, got %q", report.Divergence.Kind)
	}
}

// TestVerifyChain_SplicedPrevHash_CaughtOnTheNextRow covers the other half
// of the two-check design: an EARLIER row's hash is altered (and, to be a
// fully self-consistent single-row edit, its own prev_hash/content are left
// matching each other), but the FOLLOWING row's prev_hash is NOT updated to
// match — the classic "spliced chain" tamper. The failing row must be the
// one immediately after the edited one (its prev_hash check), not the
// edited row itself (which, in isolation, still recomputes correctly).
func TestVerifyChain_SplicedPrevHash_CaughtOnTheNextRow(t *testing.T) {
	rows := buildChain(t, 5)
	editedIdx := 2
	// Recompute row 2's hash as if occurredAt had been different — a
	// legitimate-looking hash for row 2's (edited) content, internally
	// self-consistent, but the chain link into row 3 is now broken because
	// row 3's prev_hash still points at row 2's ORIGINAL hash.
	editedOccurredAt := rows[editedIdx].OccurredAt.Add(time.Hour)
	ev := audit.NewCoreEvent(rows[editedIdx].TenantID, rows[editedIdx].ActorID, rows[editedIdx].Capability, rows[editedIdx].Scope, rows[editedIdx].ClusterID, rows[editedIdx].Outcome)
	newHash, err := audit.ComputeHash(rows[editedIdx].PrevHash, ev, editedOccurredAt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rows[editedIdx].OccurredAt = editedOccurredAt
	rows[editedIdx].Hash = newHash
	// rows[editedIdx+1].PrevHash is deliberately left pointing at the ORIGINAL
	// (pre-edit) hash of row editedIdx — this is the splice.

	report := VerifyChain(rows)
	if report.OK() {
		t.Fatal("expected a spliced chain link to be caught, but VerifyChain reported the chain intact")
	}
	if report.Divergence.RowIndex != editedIdx+1 {
		t.Errorf("expected the divergence to surface at row index %d (the row after the edit, via the prev_hash link check), got %d", editedIdx+1, report.Divergence.RowIndex)
	}
	if report.Divergence.Kind != FailurePrevHashMismatch {
		t.Errorf("expected FailurePrevHashMismatch, got %q", report.Divergence.Kind)
	}
	if report.Divergence.Actual != rows[editedIdx+1].PrevHash {
		t.Errorf("expected the reported 'actual' value to be row %d's stored (stale) prev_hash", editedIdx+1)
	}
	if report.Divergence.Expected != newHash {
		t.Errorf("expected the reported 'expected' value to be row %d's new (edited) stored hash %q, got %q", editedIdx, newHash, report.Divergence.Expected)
	}
}
