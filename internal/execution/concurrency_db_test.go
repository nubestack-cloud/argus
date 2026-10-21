package execution

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/orchestrator"
	"argus/internal/remediation"
)

// TestLockIncidentForDecision_BlocksConcurrentDecision is the deterministic
// proof behind BACKLOG.md G6's planId replay dedup: it does not fire two
// goroutines and hope they overlap, it DELIBERATELY holds one transaction's
// row lock open across a synchronization point and shows a second
// transaction's identical call genuinely blocks on it — the "deliberately-
// held transaction" this task's brief asks for — before ever letting the
// second one through.
func TestLockIncidentForDecision_BlocksConcurrentDecision(t *testing.T) {
	pool := authTestPool(t)
	tenantID, clusterID, incidentID, planID := timelineExecFixture(t, pool)
	ctx := context.Background()

	txA, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin A: %v", err)
	}
	defer txA.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, txA, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope A: %v", err)
	}
	if err := LockIncidentForDecision(ctx, txA, incidentID, planID); err != nil {
		t.Fatalf("A's first lock attempt should succeed (nothing decided yet): %v", err)
	}

	// B is launched now, while A's transaction is STILL OPEN and still
	// holding the incidents row's FOR UPDATE lock. B's own attempt at the
	// exact same lock is issued to Postgres for real; this is not simulated.
	bDone := make(chan error, 1)
	go func() {
		txB, err := pool.Begin(ctx)
		if err != nil {
			bDone <- err
			return
		}
		defer txB.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, txB, tenantID, []string{clusterID}); err != nil {
			bDone <- err
			return
		}
		bDone <- LockIncidentForDecision(ctx, txB, incidentID, planID)
	}()

	// Prove B is actually blocked, not merely slow: as long as A has neither
	// committed nor rolled back, Postgres GUARANTEES B's FOR UPDATE cannot
	// proceed — so seeing nothing on bDone here is not a timing gamble, it is
	// the one outcome that can happen while A's transaction is open.
	select {
	case err := <-bDone:
		t.Fatalf("B's lock attempt returned (err=%v) while A still held the row lock — the two decision paths are not actually serialized", err)
	case <-time.After(300 * time.Millisecond):
	}

	// A now completes its decision — exactly what recordExecutingTransition/
	// handleRejectIncident/approveByOpeningPullRequest do immediately after
	// this same lock call succeeds: record the decision, move the incident
	// out of AwaitingApproval, commit.
	if _, err := txA.Exec(ctx,
		`INSERT INTO remediation_approval_decisions (id, recommendation_id, incident_id, tenant_id, cluster_id, actor_id, verdict, reason)
		 VALUES ($1, $2, $3, $4, $5, $6, 'rejected', 'test')`,
		domain.NewID(domain.PrefixApproval), planID, incidentID, tenantID, clusterID, "usr_test"); err != nil {
		t.Fatalf("A: insert decision: %v", err)
	}
	if err := orchestrator.SetState(ctx, txA, incidentID, orchestrator.StateDismissed); err != nil {
		t.Fatalf("A: SetState: %v", err)
	}
	if err := txA.Commit(ctx); err != nil {
		t.Fatalf("A: commit: %v", err)
	}

	// B must now unblock (Postgres releases the row lock the instant A's
	// transaction ends) and must see the world AS IT NOW IS — decided,
	// exactly once — not the stale "still AwaitingApproval" snapshot that
	// existed at the moment B issued its query.
	select {
	case err := <-bDone:
		var alreadyDecided *ErrPlanAlreadyDecided
		if !errors.As(err, &alreadyDecided) {
			t.Fatalf("B's lock attempt, after A committed = %v, want an *ErrPlanAlreadyDecided", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("B never unblocked after A committed — the row lock leaked")
	}
}

// TestRecordExecutingTransition_ConcurrentApprovalsExactlyOneWins is the
// in-place approval counterpart of the reject test above: two goroutines,
// released from a shared barrier, both call recordExecutingTransition for
// the SAME planID. Exactly one may ever commit the
// AwaitingApproval -> Executing transition; the other must see it already
// decided, not race it through a second time.
func TestRecordExecutingTransition_ConcurrentApprovalsExactlyOneWins(t *testing.T) {
	pool := authTestPool(t)
	tenantID, clusterID, incidentID, planID := timelineExecFixture(t, pool)
	ctx := context.Background()

	s := &Executor{db: &data.DB{Pool: pool}}
	rc := Scope{TenantID: tenantID}
	actor := Actor{UserID: "usr_test", AuthMethod: "jwt"}

	barrier := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-barrier
			errs[i] = s.recordExecutingTransition(ctx, rc, incidentID, planID, clusterID, actor,
				false, false, "", nil, dryRunAttestation{At: time.Now()}, nil, executionAttempt{})
		}(i)
	}
	close(barrier)
	wg.Wait()

	var succeeded, conflicted int
	for i, err := range errs {
		switch {
		case err == nil:
			succeeded++
		default:
			var alreadyDecided *ErrPlanAlreadyDecided
			if errors.As(err, &alreadyDecided) {
				conflicted++
			} else {
				t.Errorf("goroutine %d: unexpected error %v, want nil or *ErrPlanAlreadyDecided", i, err)
			}
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("errs = %v — want exactly one nil and one *ErrPlanAlreadyDecided, got %d succeeded and %d conflicted", errs, succeeded, conflicted)
	}

	// Exactly one ApprovalGranted timeline event, never two.
	got := timelineEventTypesFor(t, pool, tenantID, clusterID, incidentID)
	approvalCount := 0
	for _, eventType := range got {
		if eventType == "ApprovalGranted" {
			approvalCount++
		}
	}
	if approvalCount != 1 {
		t.Fatalf("timeline events = %v — want exactly 1 ApprovalGranted, got %d", got, approvalCount)
	}
}

// scaleDeploymentPlanAgainst builds a minimal, valid ScaleDeployment plan
// targeting the given object. ScaleDeployment is used throughout this file's
// per-target lock tests specifically because executionTargetForLock's
// resolution for it is the plan's own target, unchanged — no
// get_owner_chain tunnel call, and therefore no gateway/agent fixture is
// needed to exercise acquireTargetLock in isolation.
func scaleDeploymentPlanAgainst(namespace, name string) remediation.RemediationPlan {
	return remediation.RemediationPlan{
		ActionType:      remediation.ActionScaleDeployment,
		TargetGVK:       "apps/v1/Deployment",
		TargetNamespace: namespace,
		TargetName:      name,
		Params:          remediation.ScaleDeploymentParams{Replicas: 3},
	}
}

// TestAcquireTargetLock_BlocksASecondPlanAgainstTheSameTarget is the
// per-target lock's own deterministic, deliberately-held-transaction proof —
// the direct counterpart of TestLockIncidentForDecision_BlocksConcurrentDecision
// above, for BACKLOG.md G6's other half.
func TestAcquireTargetLock_BlocksASecondPlanAgainstTheSameTarget(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	clusterID := domain.NewID(domain.PrefixCluster)
	planA := scaleDeploymentPlanAgainst("ns", "web")
	planB := scaleDeploymentPlanAgainst("ns", "web") // same target, a DIFFERENT plan/incident in the real caller
	s := &Executor{}

	txA, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin A: %v", err)
	}
	defer txA.Rollback(ctx) //nolint:errcheck
	if err := s.acquireTargetLock(ctx, txA, clusterID, planA); err != nil {
		t.Fatalf("A's lock attempt should succeed: %v", err)
	}

	bDone := make(chan error, 1)
	go func() {
		txB, err := pool.Begin(ctx)
		if err != nil {
			bDone <- err
			return
		}
		defer txB.Rollback(ctx) //nolint:errcheck
		bDone <- s.acquireTargetLock(ctx, txB, clusterID, planB)
	}()

	// While A's transaction is open, B's advisory lock attempt on the SAME
	// (cluster, gvk, namespace, name) key is GUARANTEED to block — this is
	// pg_advisory_xact_lock's own documented behaviour, not a timing hope.
	select {
	case err := <-bDone:
		t.Fatalf("B's target lock attempt returned (err=%v) while A still held it — two plans against the same object were not serialized", err)
	case <-time.After(300 * time.Millisecond):
	}

	if err := txA.Rollback(ctx); err != nil {
		t.Fatalf("A: rollback: %v", err)
	}

	select {
	case err := <-bDone:
		if err != nil {
			t.Fatalf("B's target lock attempt, after A released it = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("B never unblocked after A released the per-target lock")
	}
}

// TestAcquireTargetLock_ConcurrentPlansAgainstSameTargetNeverOverlap fires
// two real goroutines at acquireTargetLock for the SAME target, released
// together from a shared barrier, and proves — by tracking how many are
// simultaneously inside the region the lock is supposed to protect, with a
// deliberately-elongated hold so a broken lock would overlap in practice,
// not merely in theory — that the two never run concurrently.
func TestAcquireTargetLock_ConcurrentPlansAgainstSameTargetNeverOverlap(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	clusterID := domain.NewID(domain.PrefixCluster)
	plan := scaleDeploymentPlanAgainst("ns", "web")
	s := &Executor{}

	var mu sync.Mutex
	inCritical, maxConcurrent := 0, 0

	run := func(barrier <-chan struct{}) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		<-barrier
		if err := s.acquireTargetLock(ctx, tx, clusterID, plan); err != nil {
			return err
		}
		mu.Lock()
		inCritical++
		if inCritical > maxConcurrent {
			maxConcurrent = inCritical
		}
		mu.Unlock()
		time.Sleep(50 * time.Millisecond) // deliberately held, so a broken lock has a wide window to reveal itself
		mu.Lock()
		inCritical--
		mu.Unlock()
		return nil
	}

	barrier := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = run(barrier)
		}(i)
	}
	close(barrier)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	if maxConcurrent > 1 {
		t.Fatalf("both plans held the per-target lock at the same time (observed max concurrency %d) — the per-target lock did not serialize them", maxConcurrent)
	}
}
