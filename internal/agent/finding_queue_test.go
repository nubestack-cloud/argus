package agent

import (
	"context"
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"argus/internal/tunnel"
)

// sweepOfSize builds n distinct, already-sustained sweep candidates — the
// shape runOneSweep hands recordSweepCandidates on a cluster with n
// simultaneously-broken objects.
func sweepOfSize(n int) []sweepCandidate {
	out := make([]sweepCandidate, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, sweepCandidate{
			GVK:           "apps/v1/Deployment",
			Namespace:     "ns",
			Name:          fmt.Sprintf("obj-%04d", i),
			Reason:        "ReplicasUnavailable",
			Message:       "0/1 replicas available",
			Severity:      "high",
			SustainedFrom: time.Now().Add(-time.Hour),
			OccurredAt:    time.Now(),
		})
	}
	return out
}

// newRunningFindingQueue is the queue shape every session-level test needs
// now that runTunnelSession takes the queue rather than a bare channel: a
// real findingQueue with its pump running, torn down with the test. Tests
// push work in with q.In() exactly as a detector goroutine does.
func newRunningFindingQueue(t *testing.T) *findingQueue {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	q := newFindingQueue(findingQueueCapacity)
	go q.Run(ctx)
	return q
}

// TestSweepLargerThanBufferLosesNothing is PROJECT.md B176's falsification
// test. Against the pre-fix code — one 100-slot channel read directly by the
// tunnel writer, with a non-blocking send at the detector — a 300-finding
// sweep delivered 104 and lost 196. The drain here sleeps per finding on
// purpose: the real consumer does a TLS write per message while the producer
// only builds a struct, which is exactly the rate mismatch that emptied
// sweeps of 111-185 findings into a 100-slot buffer on the live rke2 agent.
func TestSweepLargerThanBufferLosesNothing(t *testing.T) {
	const sweepSize = 300

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	q := newFindingQueue(findingQueueCapacity)
	go q.Run(ctx)

	got := make(chan int, 1)
	go func() {
		seen := 0
		for {
			select {
			case <-q.Out():
				seen++
				time.Sleep(100 * time.Microsecond)
			case <-time.After(3 * time.Second):
				got <- seen
				return
			}
		}
	}()

	lastSent := map[string]time.Time{}
	recordSweepCandidates(sweepOfSize(sweepSize), time.Now(), map[string]struct{}{},
		map[string]time.Time{}, defaultSweepSustainedThreshold,
		q.In(), lastSent, defaultFindingResendCooldown)

	if seen := <-got; seen != sweepSize {
		t.Fatalf("sweep of %d findings: tunnel received %d — %d lost", sweepSize, seen, sweepSize-seen)
	}
	if len(lastSent) != sweepSize {
		t.Fatalf("sweep of %d findings: %d entered the resend cooldown — every delivered finding must", sweepSize, len(lastSent))
	}
	if _, dropped := q.Stats(); dropped != 0 {
		t.Fatalf("queue reported %d discards for a sweep well inside its %d capacity", dropped, findingQueueCapacity)
	}
}

// TestFindingsProducedWhileTunnelIsDownSurviveTheReconnect covers the other
// half of the same mechanism: between tunnel sessions there is no reader at
// all, so pre-fix the first sweep after a disconnect filled the 100-slot
// buffer and every finding after it was discarded — and stamped as sent.
func TestFindingsProducedWhileTunnelIsDownSurviveTheReconnect(t *testing.T) {
	const sweepSize = 250

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	q := newFindingQueue(findingQueueCapacity)
	go q.Run(ctx)

	// No consumer at all: this is a disconnected agent.
	lastSent := map[string]time.Time{}
	recordSweepCandidates(sweepOfSize(sweepSize), time.Now(), map[string]struct{}{},
		map[string]time.Time{}, defaultSweepSustainedThreshold,
		q.In(), lastSent, defaultFindingResendCooldown)

	// The reconnect: drain everything the queue held onto.
	seen := 0
	for seen < sweepSize {
		select {
		case <-q.Out():
			seen++
		case <-time.After(3 * time.Second):
			t.Fatalf("after reconnect only %d of %d findings produced while disconnected were delivered", seen, sweepSize)
		}
	}
}

// TestFindingQueueCoalescesRepeatsOfTheSameFingerprint is what keeps the
// capacity bound a function of how broken the cluster is rather than of how
// long the hub has been unreachable: the sweep interval and the resend
// cooldown are both 5 minutes by default, so a still-broken object is
// re-reported by every single sweep, and without coalescing a two-hour
// outage would queue 24 copies of each.
//
// Drives enqueue directly rather than through Run, so the assertion is
// about the data structure and not about when the pump happens to be
// scheduled.
func TestFindingQueueCoalescesRepeatsOfTheSameFingerprint(t *testing.T) {
	q := newFindingQueue(findingQueueCapacity)

	// Ten sweeps' worth of the same three broken objects, nothing draining.
	for i := 0; i < 10; i++ {
		for _, c := range sweepOfSize(3) {
			q.enqueue(tunnel.Finding{
				DetectorID:      sweepDetectorID,
				Fingerprint:     candidateFingerprint(c),
				GVK:             c.GVK,
				Namespace:       c.Namespace,
				ObjectName:      c.Name,
				Reason:          c.Reason,
				OccurrenceCount: 1,
			})
		}
	}

	if pending, _ := q.Stats(); pending != 3 {
		t.Fatalf("ten sweeps of the same 3 objects left %d pending findings — repeats are not being coalesced, so the queue grows with outage duration", pending)
	}

	// Nothing was lost: the surviving copy carries every observation.
	total := 0
	for _, f := range q.pending {
		total += f.OccurrenceCount
	}
	if total != 30 {
		t.Fatalf("coalesced OccurrenceCount total = %d, want 30 (3 objects x 10 sweeps)", total)
	}
}

// TestFindingQueueReportsWhatItDiscardsAtCapacity pins the behaviour AT the
// bound: the oldest pending finding goes, and the queue counts it rather
// than going quiet. This is the residual loss the fix does not remove, only
// move far out of reach — it must stay visible.
func TestFindingQueueReportsWhatItDiscardsAtCapacity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const capacity = 10
	q := newFindingQueue(capacity)
	go q.Run(ctx)

	for i := 0; i < capacity+5; i++ {
		q.In() <- tunnel.Finding{
			DetectorID:      sweepDetectorID,
			Fingerprint:     fmt.Sprintf("fp-%02d", i),
			GVK:             "apps/v1/Deployment",
			Namespace:       "ns",
			ObjectName:      fmt.Sprintf("obj-%02d", i),
			Reason:          "ReplicasUnavailable",
			OccurrenceCount: 1,
		}
	}

	deadline := time.After(3 * time.Second)
	for {
		pending, dropped := q.Stats()
		if dropped == 5 && pending == capacity {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("at capacity %d after %d sends: pending=%d dropped=%d, want pending=%d dropped=5", capacity, capacity+5, pending, dropped, capacity)
		default:
			time.Sleep(time.Millisecond)
		}
	}

	// Oldest-first: the survivors are the five newest fingerprints plus the
	// tail, never an arbitrary set.
	f := <-q.Out()
	if f.Fingerprint != "fp-05" {
		t.Fatalf("head of queue after 5 discards = %s, want fp-05 (oldest discarded first)", f.Fingerprint)
	}
}

// TestDroppedSweepFindingIsNotMarkedSent is B176's second half: a finding
// that was NOT delivered must not enter the resend cooldown as though it
// had been, or it is not retried on the next sweep either. Against the
// pre-fix code lastSent was stamped before the send was even attempted, so
// this failed.
func TestDroppedSweepFindingIsNotMarkedSent(t *testing.T) {
	// No queue behind it, and no room: the send cannot succeed.
	findingCh := make(chan tunnel.Finding, 1)
	findingCh <- tunnel.Finding{}

	restore := findingEmitTimeout
	findingEmitTimeout = 20 * time.Millisecond
	t.Cleanup(func() { findingEmitTimeout = restore })

	cand := sweepOfSize(1)[0]
	fp := candidateFingerprint(cand)
	lastSent := map[string]time.Time{}

	sendSweepFinding(cand, fp, time.Now(), findingCh, lastSent, defaultFindingResendCooldown)

	if _, stamped := lastSent[fp]; stamped {
		t.Fatalf("fingerprint %s was never delivered but was stamped into lastSent — the next sweep will suppress it as a duplicate", fp)
	}
}

// TestUndeliveredPodFindingIsRetriedOnTheNextPass is the same invariant for
// pod_conditions_detector.go, stated as the consequence that matters: the
// retry actually happens.
func TestUndeliveredPodFindingIsRetriedOnTheNextPass(t *testing.T) {
	restore := findingEmitTimeout
	findingEmitTimeout = 20 * time.Millisecond
	t.Cleanup(func() { findingEmitTimeout = restore })

	blocked := make(chan tunnel.Finding, 1)
	blocked <- tunnel.Finding{}

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "p1"}}
	lastSent := map[string]time.Time{}
	now := time.Now()

	sendPodFinding(pod, "CrashLoopBackOff", "back-off restarting", "high", now, now, "", "", blocked, lastSent, defaultFindingResendCooldown)
	if len(lastSent) != 0 {
		t.Fatalf("an undelivered pod finding entered the resend cooldown: %v", lastSent)
	}

	// Second pass, one second later — well inside the 5-minute cooldown the
	// pre-fix code would have started. It must be sent, not suppressed.
	open := make(chan tunnel.Finding, 1)
	sendPodFinding(pod, "CrashLoopBackOff", "back-off restarting", "high", now, now.Add(time.Second), "", "", open, lastSent, defaultFindingResendCooldown)

	select {
	case f := <-open:
		if f.Reason != "CrashLoopBackOff" {
			t.Fatalf("retried finding has reason %q", f.Reason)
		}
	default:
		t.Fatal("an undelivered finding was suppressed by the resend cooldown on the very next pass")
	}
	if len(lastSent) != 1 {
		t.Fatalf("the delivered retry did not enter the resend cooldown: %v", lastSent)
	}
}
