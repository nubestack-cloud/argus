package orchestrator

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/domain"
)

// BatchExecution's real behaviour — RLS-scoped writes across two tables, a
// unique-index-enforced "one batch per key" invariant, and a decision that
// has to hold under the ACTUAL FORCE ROW LEVEL SECURITY the hub runs under —
// is a property of live Postgres, not of Go (the pure decision logic already
// has exhaustive DB-free coverage in batch_test.go). Uses the same
// ARGUS_TEST_DATABASE_URL harness as breaker_db_test.go/db_test.go, under
// argus_app rather than the superuser, so these see the same RLS the hub
// does.

// batchGroupFixture creates n throwaway incidents, each on its OWN cluster
// (an incident's cluster_id is a foreign key, and a fleet group is
// specifically about the SAME fault on DIFFERENT clusters, so one cluster
// per incident is the only realistic shape), all sharing one fleet_group_id
// assigned directly rather than through internal/fleetgroup (which this
// package cannot import without a cycle, and which is not what is under
// test here — the same bypass setIncidentState/db_test.go already establish
// for state, applied to fleet_group_id instead).
func batchGroupFixture(t *testing.T, pool *pgxpool.Pool, n int) (tenantID, fleetGroupID string, clusterIDs, incidentIDs []string) {
	t.Helper()
	fleetGroupID = domain.NewID(domain.PrefixFleetGroup)

	for i := 0; i < n; i++ {
		tid, clusterID, incidentID, _ := testIncident(t, pool, StateAwaitingApproval)
		tenantID = tid
		clusterIDs = append(clusterIDs, clusterID)
		incidentIDs = append(incidentIDs, incidentID)

		ctx := context.Background()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if err := data.SetRequestScope(ctx, tx, tid, []string{clusterID}); err != nil {
			tx.Rollback(ctx) //nolint:errcheck
			t.Fatalf("scope: %v", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE incidents SET fleet_group_id = $2 WHERE id = $1`, incidentID, fleetGroupID); err != nil {
			tx.Rollback(ctx) //nolint:errcheck
			t.Fatalf("set fleet_group_id: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Errorf("cleanup: begin: %v", err)
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, clusterIDs); err != nil {
			t.Errorf("cleanup: scope: %v", err)
			return
		}
		if _, err := tx.Exec(ctx, `DELETE FROM unattended_batch_members WHERE incident_id = ANY($1)`, incidentIDs); err != nil {
			t.Errorf("cleanup: delete batch members: %v", err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM unattended_batches WHERE fleet_group_id = $1`, fleetGroupID); err != nil {
			t.Errorf("cleanup: delete batch: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Errorf("cleanup: commit: %v", err)
		}
	})

	return tenantID, fleetGroupID, clusterIDs, incidentIDs
}

// gatingFor runs ResolveBatchGating for the whole fixture in one transaction,
// exactly as internal/api/unattended.go's collectUnattended would (one
// RLS-scoped transaction covering the settings read, the candidate query and
// the batch gating call together).
func gatingFor(t *testing.T, pool *pgxpool.Pool, tenantID string, clusterIDs, incidentIDs []string, fleetGroupID, actionType string, now time.Time) map[string]BatchMembership {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, clusterIDs); err != nil {
		t.Fatalf("scope: %v", err)
	}

	candidates := make([]BatchCandidate, len(incidentIDs))
	for i, incidentID := range incidentIDs {
		fg := fleetGroupID
		candidates[i] = BatchCandidate{IncidentID: incidentID, ClusterID: clusterIDs[i], ActionType: actionType, FleetGroupID: &fg}
	}

	got, err := ResolveBatchGating(ctx, tx, tenantID, candidates, now)
	if err != nil {
		t.Fatalf("ResolveBatchGating: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return got
}

// TestResolveBatchGatingCreatesBatchAndHoldsWave2 is the core mechanism:
// four correlated candidates for the same action_type produce a batch whose
// wave 1 (waveOneSize(4) == 2) is immediately eligible and whose wave 2 is
// held.
func TestResolveBatchGatingCreatesBatchAndHoldsWave2(t *testing.T) {
	pool := testPool(t)
	tenantID, fleetGroupID, clusterIDs, incidentIDs := batchGroupFixture(t, pool, 4)

	membership := gatingFor(t, pool, tenantID, clusterIDs, incidentIDs, fleetGroupID, "ScaleDeployment", time.Now())

	if len(membership) != 4 {
		t.Fatalf("got membership for %d incidents, want all 4", len(membership))
	}

	var wave1, wave2 int
	for _, incidentID := range incidentIDs {
		m, ok := membership[incidentID]
		if !ok {
			t.Fatalf("incident %s has no batch membership at all", incidentID)
		}
		if m.BatchStatus != BatchStatusWave1Pending {
			t.Errorf("incident %s: batch status = %q, want %q immediately after creation", incidentID, m.BatchStatus, BatchStatusWave1Pending)
		}
		switch m.WaveNumber {
		case 1:
			wave1++
			if !m.Eligible() {
				t.Errorf("incident %s is wave 1 but not eligible — wave 1 must always be eligible, it is what produces the validation signal", incidentID)
			}
		case 2:
			wave2++
			if m.Eligible() {
				t.Errorf("incident %s is wave 2 of a batch still awaiting wave 1's outcome, but Eligible() is true — this would let wave 2 execute before the canary result is known", incidentID)
			}
		default:
			t.Errorf("incident %s has an invalid wave number %d", incidentID, m.WaveNumber)
		}
	}
	if wave1 != 2 || wave2 != 2 {
		t.Errorf("wave1=%d wave2=%d, want 2/2 for a 4-candidate batch (waveOneSize(4)==2)", wave1, wave2)
	}

	// Exactly one batch row for this key, however many members it has.
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, clusterIDs); err != nil {
		t.Fatalf("scope: %v", err)
	}
	var batchCount int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM unattended_batches WHERE fleet_group_id = $1`, fleetGroupID).Scan(&batchCount); err != nil {
		t.Fatalf("count batches: %v", err)
	}
	if batchCount != 1 {
		t.Errorf("batches for this fleet group = %d, want exactly 1", batchCount)
	}
}

// TestResolveBatchGatingTooFewCandidatesDoesNotBatch: two correlated
// incidents is the minimum for a batch (BatchStatus semantics require a real
// canary), but ONE eligible candidate sharing a fleet group with nothing
// else right now must not be held back waiting for a batch that doesn't
// exist.
func TestResolveBatchGatingTooFewCandidatesDoesNotBatch(t *testing.T) {
	pool := testPool(t)
	tenantID, fleetGroupID, clusterIDs, incidentIDs := batchGroupFixture(t, pool, 1)

	membership := gatingFor(t, pool, tenantID, clusterIDs, incidentIDs, fleetGroupID, "ScaleDeployment", time.Now())
	if len(membership) != 0 {
		t.Fatalf("a single candidate was batched (%v) — batching requires at least two simultaneously eligible candidates", membership)
	}
}

// TestResolveBatchGatingReleasesWave2OnWave1Success is the happy path this
// whole feature exists to automate safely: wave 1 holds, so wave 2 is let
// through without a human having to notice and release it by hand.
func TestResolveBatchGatingReleasesWave2OnWave1Success(t *testing.T) {
	pool := testPool(t)
	tenantID, fleetGroupID, clusterIDs, incidentIDs := batchGroupFixture(t, pool, 4)
	now := time.Now()

	membership := gatingFor(t, pool, tenantID, clusterIDs, incidentIDs, fleetGroupID, "ScaleDeployment", now)
	var wave1IDs, wave2IDs []string
	for _, incidentID := range incidentIDs {
		if membership[incidentID].WaveNumber == 1 {
			wave1IDs = append(wave1IDs, incidentID)
		} else {
			wave2IDs = append(wave2IDs, incidentID)
		}
	}
	if len(wave1IDs) == 0 || len(wave2IDs) == 0 {
		t.Fatalf("fixture did not produce both waves: wave1=%v wave2=%v", wave1IDs, wave2IDs)
	}

	// Wave 1 "executes" and its ValidationSweeper outcome comes back clean.
	for _, id := range wave1IDs {
		idx := indexOf(incidentIDs, id)
		setIncidentState(t, pool, tenantID, clusterIDs[idx], id, StateResolved)
	}

	// Re-run gating, as the next sweep tick would. resolveBatchOutcomes must
	// notice wave 1 held and release wave 2 in the SAME call that reports it.
	membership = gatingFor(t, pool, tenantID, clusterIDs, incidentIDs, fleetGroupID, "ScaleDeployment", now.Add(time.Minute))
	for _, id := range wave2IDs {
		m := membership[id]
		if m.BatchStatus != BatchStatusReleased {
			t.Errorf("wave-2 incident %s: batch status = %q, want %q now that every wave-1 incident resolved", id, m.BatchStatus, BatchStatusReleased)
		}
		if !m.Eligible() {
			t.Errorf("wave-2 incident %s is not eligible even though its batch is released", id)
		}
	}
	// Wave 1 members stay eligible too (they always were) and now also carry
	// the released status, since BatchMembership.BatchStatus is the batch's
	// current status regardless of which wave a member is in.
	for _, id := range wave1IDs {
		if !membership[id].Eligible() {
			t.Errorf("wave-1 incident %s stopped being eligible after release", id)
		}
	}
}

// TestResolveBatchGatingBlocksWave2OnWave1Failure is the safety-critical
// case BACKLOG.md R3 exists for: a wrong diagnosis must be caught after
// wave 1's few clusters, not discovered only after the whole batch already
// got the same wrong fix. Reopened is what ValidationSweeper actually writes
// when a fix does not hold (validation.go) — the exact signal this
// mechanism has to react to correctly.
func TestResolveBatchGatingBlocksWave2OnWave1Failure(t *testing.T) {
	pool := testPool(t)
	tenantID, fleetGroupID, clusterIDs, incidentIDs := batchGroupFixture(t, pool, 5)
	now := time.Now()

	membership := gatingFor(t, pool, tenantID, clusterIDs, incidentIDs, fleetGroupID, "RestartPod", now)
	var wave1IDs, wave2IDs []string
	for _, incidentID := range incidentIDs {
		if membership[incidentID].WaveNumber == 1 {
			wave1IDs = append(wave1IDs, incidentID)
		} else {
			wave2IDs = append(wave2IDs, incidentID)
		}
	}
	if len(wave1IDs) != 2 {
		t.Fatalf("waveOneSize(5) should be 2, got %d wave-1 members", len(wave1IDs))
	}

	// Wave 1's fix did NOT hold on ONE of its two clusters — that alone must
	// be decisive, even though the other wave-1 incident is still Resolved.
	setIncidentState(t, pool, tenantID, clusterIDs[indexOf(incidentIDs, wave1IDs[0])], wave1IDs[0], StateResolved)
	setIncidentState(t, pool, tenantID, clusterIDs[indexOf(incidentIDs, wave1IDs[1])], wave1IDs[1], StateReopened)

	membership = gatingFor(t, pool, tenantID, clusterIDs, incidentIDs, fleetGroupID, "RestartPod", now.Add(time.Minute))

	for _, id := range wave2IDs {
		m := membership[id]
		if m.BatchStatus != BatchStatusBlocked {
			t.Fatalf("wave-2 incident %s: batch status = %q, want %q — one wave-1 incident reopened, so the rest of the batch must NOT be released to repeat the same fix", id, m.BatchStatus, BatchStatusBlocked)
		}
		if m.Eligible() {
			t.Fatalf("SAFETY VIOLATION: wave-2 incident %s reports Eligible()==true after wave 1 failed validation — this is exactly the failure mode BACKLOG.md R3 exists to prevent: repeating a wrong fix across the rest of a correlated fleet", id)
		}
		if m.HoldReason() == "" {
			t.Errorf("wave-2 incident %s: HoldReason is empty, so an operator reading the sweep log gets no explanation for why it is stuck", id)
		}
	}

	// The batch stays blocked on a LATER tick too — it must not un-block
	// itself just because time passed, only a human resetting it should ever
	// move it off 'blocked' (this mechanism has no reset path at all, by
	// design: see batch.go's header on the human-approval escape valve).
	again := gatingFor(t, pool, tenantID, clusterIDs, incidentIDs, fleetGroupID, "RestartPod", now.Add(time.Hour))
	for _, id := range wave2IDs {
		if again[id].BatchStatus != BatchStatusBlocked {
			t.Errorf("wave-2 incident %s: batch un-blocked itself on a later tick (status=%q)", id, again[id].BatchStatus)
		}
	}
}

// TestResolveBatchGatingStragglerJoinsExistingBatchAsWave2 covers a fifth
// incident discovered on a LATER tick, after the batch already exists: it
// must join the existing batch as wave 2 rather than starting a second one,
// and must be held exactly like any other wave-2 member.
func TestResolveBatchGatingStragglerJoinsExistingBatchAsWave2(t *testing.T) {
	pool := testPool(t)
	tenantID, fleetGroupID, clusterIDs, incidentIDs := batchGroupFixture(t, pool, 3)
	now := time.Now()

	first := gatingFor(t, pool, tenantID, clusterIDs, incidentIDs, fleetGroupID, "ScaleDeployment", now)
	var firstBatchID string
	for _, m := range first {
		firstBatchID = m.BatchID
		break
	}

	// A fourth incident appears later, correlated to the same fleet group and
	// the same fix.
	strayTenantID, strayClusterID, strayIncidentID, _ := testIncident(t, pool, StateAwaitingApproval)
	if strayTenantID != tenantID {
		t.Fatalf("fixture produced a different tenant (%s != %s) — this codebase assumes a single organisation", strayTenantID, tenantID)
	}
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{strayClusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE incidents SET fleet_group_id = $2 WHERE id = $1`, strayIncidentID, fleetGroupID); err != nil {
		t.Fatalf("set fleet_group_id on straggler: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		tx, err := pool.Begin(ctx)
		if err != nil {
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		_ = data.SetRequestScope(ctx, tx, tenantID, []string{strayClusterID})
		_, _ = tx.Exec(ctx, `DELETE FROM unattended_batch_members WHERE incident_id = $1`, strayIncidentID)
		_ = tx.Commit(ctx)
	})

	allClusters := append(append([]string{}, clusterIDs...), strayClusterID)
	allIncidents := append(append([]string{}, incidentIDs...), strayIncidentID)
	second := gatingFor(t, pool, tenantID, allClusters, allIncidents, fleetGroupID, "ScaleDeployment", now.Add(time.Second))

	strayMembership, ok := second[strayIncidentID]
	if !ok {
		t.Fatalf("the straggler was never assigned any batch membership")
	}
	if strayMembership.BatchID != firstBatchID {
		t.Errorf("straggler joined batch %s, want the SAME batch %s the original group created — one batch per (fleet_group_id, action_type) key, ever", strayMembership.BatchID, firstBatchID)
	}
	if strayMembership.WaveNumber != 2 {
		t.Errorf("straggler was assigned wave %d, want 2 — a straggler never backfills wave 1", strayMembership.WaveNumber)
	}
	if strayMembership.Eligible() {
		t.Error("straggler is eligible immediately, before wave 1 (which it was never part of) has validated anything")
	}

	// The original members' assignment must be UNCHANGED by the straggler
	// joining — no reshuffling wave numbers after the fact.
	for id, before := range first {
		after := second[id]
		if after.WaveNumber != before.WaveNumber {
			t.Errorf("incident %s's wave number changed from %d to %d when a straggler joined", id, before.WaveNumber, after.WaveNumber)
		}
	}
}

// TestGetIncidentBatchInfoReflectsHeldState is the API-visible surface
// (internal/api/incidents.go's handleGetIncident): a held incident must be
// identifiable as such without inspecting the batch tables directly.
func TestGetIncidentBatchInfoReflectsHeldState(t *testing.T) {
	pool := testPool(t)
	tenantID, fleetGroupID, clusterIDs, incidentIDs := batchGroupFixture(t, pool, 3)
	now := time.Now()

	membership := gatingFor(t, pool, tenantID, clusterIDs, incidentIDs, fleetGroupID, "ScaleDeployment", now)
	var heldIncident string
	for id, m := range membership {
		if !m.Eligible() {
			heldIncident = id
			break
		}
	}
	if heldIncident == "" {
		t.Fatal("fixture produced no held (wave-2) incident to check")
	}

	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, clusterIDs); err != nil {
		t.Fatalf("scope: %v", err)
	}
	info, err := GetIncidentBatchInfo(ctx, tx, heldIncident)
	if err != nil {
		t.Fatalf("GetIncidentBatchInfo: %v", err)
	}
	if info == nil {
		t.Fatal("GetIncidentBatchInfo returned nil for an incident that is a batch member")
	}
	if !info.Held {
		t.Error("GetIncidentBatchInfo.Held is false for a wave-2 incident whose batch is still wave1_pending")
	}
	if info.FleetGroupID != fleetGroupID || info.ActionType != "ScaleDeployment" {
		t.Errorf("GetIncidentBatchInfo returned the wrong batch: fleetGroupID=%q actionType=%q", info.FleetGroupID, info.ActionType)
	}

	// An ordinary, never-batched incident must report nil, not a zero-valued
	// struct — the large majority case, and one this codebase's own
	// conventions treat as "not recorded" rather than "false"/"empty" (see
	// this package's own doc comments on honest nulls elsewhere).
	_, _, unbatchedIncident, _ := testIncident(t, pool, StateAwaitingApproval)
	info2, err := GetIncidentBatchInfo(ctx, tx, unbatchedIncident)
	if err != nil {
		t.Fatalf("GetIncidentBatchInfo (unbatched): %v", err)
	}
	if info2 != nil {
		t.Errorf("GetIncidentBatchInfo returned non-nil (%+v) for an incident that was never part of any batch", info2)
	}
}

func indexOf(haystack []string, needle string) int {
	for i, s := range haystack {
		if s == needle {
			return i
		}
	}
	return -1
}
