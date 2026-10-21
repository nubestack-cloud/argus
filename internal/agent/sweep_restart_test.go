package agent

// PROJECT.md P18's fourth acceptance criterion, answered rather than
// assumed: "a restart no longer produces a finding storm, or the storm is
// bounded by the same fingerprint coalescing B176 added."
//
// # What the board expected, and what the code actually does
//
// The board's reasoning was that an OOMKill mid-sweep discards the in-memory
// firstObserved/lastSent maps, so the next sweep re-reports everything and
// floods the hub. The first half of that is true — both maps are per-process
// and a restart empties them. The second half is not, and these tests are
// why:
//
//  1. defaultFindingResendCooldown and DefaultSweepInterval are BOTH five
//     minutes, so in steady state every sustained finding is already
//     re-sent by every single pass (shouldSend's `now.Sub(last) >= cooldown`
//     is satisfied exactly at the tick). A restart does not add a report
//     that a healthy agent was not already making.
//  2. For a candidate whose cluster gives no authoritative "since when",
//     an empty firstObserved makes the restarted agent report LATER, not
//     sooner — sustainedLongEnough has to observe it on two separate passes
//     first. The restart's effect there is a detection delay, which is the
//     opposite of a flood and is already documented on that function.
//  3. What does grow without bound during an outage — the same broken object
//     re-reported every five minutes for hours — is bounded by B176's
//     coalescing, which is per FINGERPRINT and therefore bounded by the
//     number of distinct broken objects, not by how long anything was down.
//     TestFindingQueueCoalescesRepeatsOfTheSameFingerprint already pins that
//     directly; the third test below pins the specific case P18 asks about.
//
// So the storm is bounded, and by exactly the mechanism the board guessed —
// but it is bounded at one report per distinct broken object per pass, which
// is the same volume the agent produces when it has not restarted at all.
// Nothing new was built for this; these tests exist so the claim is
// falsifiable rather than a paragraph someone believed.

import (
	"context"
	"fmt"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"argus/internal/tunnel"
)

// brokenDeployments returns n Deployments that have been Available=False for
// an hour — long enough that the cluster's own LastTransitionTime satisfies
// the sustained gate, so every one of them is reportable on the very first
// pass an agent makes. That is the worst case for a restart: nothing here
// has to wait for this process to observe it twice.
func brokenDeployments(n int) []k8sruntime.Object {
	out := make([]k8sruntime.Object, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: fmt.Sprintf("workload-%04d", i), UID: k8stypesUID(i)},
			Spec:       appsv1.DeploymentSpec{Replicas: int32ptr(3)},
			Status: appsv1.DeploymentStatus{
				ReadyReplicas: 0,
				Conditions: []appsv1.DeploymentCondition{{
					Type:               appsv1.DeploymentAvailable,
					Status:             corev1.ConditionFalse,
					Reason:             "MinimumReplicasUnavailable",
					LastTransitionTime: metav1.NewTime(time.Now().Add(-time.Hour)),
				}},
			},
		})
	}
	return out
}

func k8stypesUID(i int) types.UID { return types.UID(fmt.Sprintf("uid-%04d", i)) }

// drainFindings collects everything a sweep emits, so a test can count and
// inspect the burst instead of just its size.
func drainFindings(t *testing.T, run func(chan<- tunnel.Finding)) []tunnel.Finding {
	t.Helper()
	ch := make(chan tunnel.Finding, 4096)
	done := make(chan []tunnel.Finding, 1)
	go func() {
		var got []tunnel.Finding
		for f := range ch {
			got = append(got, f)
		}
		done <- got
	}()
	run(ch)
	close(ch)
	return <-done
}

// TestRestartReportsNoMoreThanASteadyStateSweep is the measurement behind
// this file's claim 1.
func TestRestartReportsNoMoreThanASteadyStateSweep(t *testing.T) {
	const broken = 50
	clientset := k8sfake.NewSimpleClientset(brokenDeployments(broken)...)

	sweep := func(lastSent, firstObserved map[string]time.Time) []tunnel.Finding {
		return drainFindings(t, func(ch chan<- tunnel.Finding) {
			if _, err := runOneSweep(context.Background(), clientset, nil, ch, lastSent, firstObserved,
				defaultFindingResendCooldown, defaultSweepSustainedThreshold, defaultTestCheckerTimeout, nil); err != nil {
				t.Fatalf("runOneSweep: %v", err)
			}
		})
	}

	// A running agent: one pass, then the cooldown elapses (modelled by
	// ageing what that pass recorded by exactly the cooldown, which is what
	// the next tick of a 5-minute ticker produces against a 5-minute
	// cooldown), then the next pass.
	lastSent, firstObserved := map[string]time.Time{}, map[string]time.Time{}
	first := sweep(lastSent, firstObserved)
	for fp, at := range lastSent {
		lastSent[fp] = at.Add(-defaultFindingResendCooldown)
	}
	steadyState := sweep(lastSent, firstObserved)

	// The same agent after an OOMKill: both maps gone.
	restart := sweep(map[string]time.Time{}, map[string]time.Time{})

	if len(first) != broken {
		t.Fatalf("first pass emitted %d findings, want one per broken object (%d)", len(first), broken)
	}
	if len(steadyState) != broken {
		t.Fatalf("a steady-state pass emitted %d findings, want %d — this test's premise (cooldown == sweep interval, so every pass re-reports) is wrong and the rest of it proves nothing", len(steadyState), broken)
	}
	if len(restart) > len(steadyState) {
		t.Fatalf("the pass after a restart emitted %d findings against a steady-state pass' %d — a restart IS a storm, and P18's fourth criterion needs something built for it", len(restart), len(steadyState))
	}
}

// TestRestartBurstIsOnePerObject is claim 3's first half: the burst itself
// carries no duplicates, so what bounds it is the number of distinct broken
// objects — which is also exactly what the finding queue's coalescing
// bounds it to if the tunnel is down when it arrives.
func TestRestartBurstIsOnePerObject(t *testing.T) {
	const broken = 50
	clientset := k8sfake.NewSimpleClientset(brokenDeployments(broken)...)

	burst := drainFindings(t, func(ch chan<- tunnel.Finding) {
		if _, err := runOneSweep(context.Background(), clientset, nil, ch, map[string]time.Time{}, map[string]time.Time{},
			defaultFindingResendCooldown, defaultSweepSustainedThreshold, defaultTestCheckerTimeout, nil); err != nil {
			t.Fatalf("runOneSweep: %v", err)
		}
	})

	seen := map[string]int{}
	for _, f := range burst {
		seen[f.Fingerprint]++
	}
	if len(seen) != broken {
		t.Fatalf("burst covered %d distinct fingerprints, want %d", len(seen), broken)
	}
	for fp, n := range seen {
		if n != 1 {
			t.Fatalf("fingerprint %s appeared %d times in one pass; a burst with duplicates would grow with checker count, not with cluster brokenness", fp, n)
		}
	}
}

// TestRepeatedRestartsDoNotGrowThePendingQueue is claim 3's second half, and
// the specific shape P18 worried about: an agent that is being OOMKilled is
// an agent that restarts repeatedly, each time re-reporting everything it
// has forgotten. If that stacked up, a disconnected tunnel would replay
// hours of it.
func TestRepeatedRestartsDoNotGrowThePendingQueue(t *testing.T) {
	const broken = 50
	clientset := k8sfake.NewSimpleClientset(brokenDeployments(broken)...)
	q := newFindingQueue(findingQueueCapacity)

	// Ten crash-restart cycles, each with the empty dedup state a fresh
	// process starts with, all while nothing is draining the queue.
	for restart := 0; restart < 10; restart++ {
		burst := drainFindings(t, func(ch chan<- tunnel.Finding) {
			if _, err := runOneSweep(context.Background(), clientset, nil, ch, map[string]time.Time{}, map[string]time.Time{},
				defaultFindingResendCooldown, defaultSweepSustainedThreshold, defaultTestCheckerTimeout, nil); err != nil {
				t.Fatalf("runOneSweep: %v", err)
			}
		})
		for _, f := range burst {
			q.enqueue(f)
		}
	}

	pending, _ := q.Stats()
	if pending != broken {
		t.Fatalf("ten restarts left %d pending findings for %d broken objects — B176's coalescing is not bounding the restart case and the hub would receive a replayed flood", pending, broken)
	}
}
