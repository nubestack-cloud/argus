package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"argus/internal/tunnel"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestSeverityForReasonMapping(t *testing.T) {
	cases := map[string]string{
		reasonOOMKilled:        "high",
		reasonCrashLoopBackOff: "high",
		reasonImagePullBackOff: "medium",
		reasonErrImagePull:     "medium",
		reasonPendingTimeout:   "medium",
	}
	for reason, want := range cases {
		if got := severityForReason(reason); got != want {
			t.Errorf("severityForReason(%q) = %q, want %q", reason, got, want)
		}
	}
}

func TestCheckContainerStatusCrashLoopBackOff(t *testing.T) {
	findingCh := make(chan tunnel.Finding, 1)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "payments-7d9-x8k2q", UID: "abc-123", ResourceVersion: "456"},
	}
	cs := corev1.ContainerStatus{
		Name: "app",
		State: corev1.ContainerState{
			Waiting: &corev1.ContainerStateWaiting{Reason: reasonCrashLoopBackOff, Message: "back-off restarting failed container"},
		},
	}

	now := time.Now()
	checkContainerStatus(pod, cs, now, "", "", findingCh, map[string]time.Time{}, defaultFindingResendCooldown)

	select {
	case f := <-findingCh:
		if f.DetectorID != podConditionsDetectorID || f.DetectorVersion != podConditionsDetectorVersion {
			t.Errorf("detector id/version = %q/%q, want %q/%q", f.DetectorID, f.DetectorVersion, podConditionsDetectorID, podConditionsDetectorVersion)
		}
		if f.GVK != "v1/Pod" {
			t.Errorf("GVK = %q, want %q", f.GVK, "v1/Pod")
		}
		if f.Reason != reasonCrashLoopBackOff {
			t.Errorf("Reason = %q, want %q", f.Reason, reasonCrashLoopBackOff)
		}
		if f.Severity != "high" {
			t.Errorf("Severity = %q, want %q", f.Severity, "high")
		}
		if f.Namespace != "default" || f.ObjectName != "payments-7d9-x8k2q" || f.ObjectUID != "abc-123" || f.ResourceVersion != "456" {
			t.Errorf("pod identity fields not carried through correctly: %+v", f)
		}
		if f.OccurrenceCount != 1 {
			t.Errorf("OccurrenceCount = %d, want 1", f.OccurrenceCount)
		}
		wantSubstr := `container "app"`
		if !strings.Contains(f.Message, wantSubstr) {
			t.Errorf("Message = %q, want it to name the specific container (%q)", f.Message, wantSubstr)
		}
	default:
		t.Fatal("a CrashLoopBackOff waiting container must produce a Finding")
	}
}

func TestCheckContainerStatusImagePullBackOffAndErrImagePull(t *testing.T) {
	for _, reason := range []string{reasonImagePullBackOff, reasonErrImagePull} {
		findingCh := make(chan tunnel.Finding, 1)
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod-x"}}
		cs := corev1.ContainerStatus{
			Name:  "worker",
			State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reason}},
		}

		checkContainerStatus(pod, cs, time.Now(), "", "", findingCh, map[string]time.Time{}, defaultFindingResendCooldown)

		select {
		case f := <-findingCh:
			if f.Reason != reason {
				t.Errorf("Reason = %q, want %q", f.Reason, reason)
			}
			if f.Severity != "medium" {
				t.Errorf("Severity for %q = %q, want %q", reason, f.Severity, "medium")
			}
		default:
			t.Fatalf("a %s waiting container must produce a Finding", reason)
		}
	}
}

func TestCheckContainerStatusIgnoresOtherWaitingReasons(t *testing.T) {
	findingCh := make(chan tunnel.Finding, 1)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod-x"}}
	cs := corev1.ContainerStatus{
		Name:  "app",
		State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}},
	}

	checkContainerStatus(pod, cs, time.Now(), "", "", findingCh, map[string]time.Time{}, defaultFindingResendCooldown)

	select {
	case f := <-findingCh:
		t.Fatalf("an unwatched waiting reason must never produce a Finding, got %+v", f)
	default:
	}
}

func TestCheckContainerStatusIgnoresRunningContainers(t *testing.T) {
	findingCh := make(chan tunnel.Finding, 1)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod-x"}}
	cs := corev1.ContainerStatus{
		Name:  "app",
		State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.Now()}},
	}

	checkContainerStatus(pod, cs, time.Now(), "", "", findingCh, map[string]time.Time{}, defaultFindingResendCooldown)

	select {
	case f := <-findingCh:
		t.Fatalf("a healthy Running container must never produce a Finding, got %+v", f)
	default:
	}
}

func TestCheckContainerStatusOOMKilled(t *testing.T) {
	findingCh := make(chan tunnel.Finding, 1)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod-x"}}
	finishedAt := metav1.NewTime(time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC))
	cs := corev1.ContainerStatus{
		Name: "app",
		State: corev1.ContainerState{
			Terminated: &corev1.ContainerStateTerminated{Reason: reasonOOMKilled, ExitCode: 137, FinishedAt: finishedAt},
		},
	}

	checkContainerStatus(pod, cs, time.Now(), "", "", findingCh, map[string]time.Time{}, defaultFindingResendCooldown)

	select {
	case f := <-findingCh:
		if f.Reason != reasonOOMKilled {
			t.Errorf("Reason = %q, want %q", f.Reason, reasonOOMKilled)
		}
		if f.Severity != "high" {
			t.Errorf("Severity = %q, want %q", f.Severity, "high")
		}
		if !f.OccurredAt.Equal(finishedAt.Time) {
			t.Errorf("OccurredAt = %v, want the terminated state's own FinishedAt %v", f.OccurredAt, finishedAt.Time)
		}
	default:
		t.Fatal("an OOMKilled terminated container must produce a Finding")
	}
}

func TestCheckContainerStatusIgnoresOtherTerminatedReasons(t *testing.T) {
	findingCh := make(chan tunnel.Finding, 1)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod-x"}}
	cs := corev1.ContainerStatus{
		Name:  "app",
		State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Completed", ExitCode: 0}},
	}

	checkContainerStatus(pod, cs, time.Now(), "", "", findingCh, map[string]time.Time{}, defaultFindingResendCooldown)

	select {
	case f := <-findingCh:
		t.Fatalf("a normal Completed termination must never produce a Finding, got %+v", f)
	default:
	}
}

func TestContainerConditionTimestampPrefersCurrentTerminatedFinishedAt(t *testing.T) {
	now := time.Now()
	finished := metav1.NewTime(now.Add(-time.Hour))
	cs := corev1.ContainerStatus{
		State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{FinishedAt: finished}},
	}
	got := containerConditionTimestamp(cs, now)
	if !got.Equal(finished.Time) {
		t.Errorf("containerConditionTimestamp = %v, want current Terminated.FinishedAt %v", got, finished.Time)
	}
}

func TestContainerConditionTimestampFallsBackToLastTerminationState(t *testing.T) {
	now := time.Now()
	lastFinished := metav1.NewTime(now.Add(-2 * time.Hour))
	cs := corev1.ContainerStatus{
		State:                corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reasonCrashLoopBackOff}},
		LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{FinishedAt: lastFinished}},
	}
	got := containerConditionTimestamp(cs, now)
	if !got.Equal(lastFinished.Time) {
		t.Errorf("containerConditionTimestamp = %v, want LastTerminationState fallback %v", got, lastFinished.Time)
	}
}

func TestContainerConditionTimestampFallsBackToNow(t *testing.T) {
	now := time.Now()
	cs := corev1.ContainerStatus{State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reasonCrashLoopBackOff}}}
	got := containerConditionTimestamp(cs, now)
	if !got.Equal(now) {
		t.Errorf("containerConditionTimestamp = %v, want the now fallback %v", got, now)
	}
}

func TestCheckPendingTimeoutBelowThreshold(t *testing.T) {
	findingCh := make(chan tunnel.Finding, 1)
	now := time.Now()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod-x", CreationTimestamp: metav1.NewTime(now.Add(-(podPendingTimeoutThreshold - time.Second)))},
		Status:     corev1.PodStatus{Phase: corev1.PodPending},
	}

	checkPendingTimeout(pod, now, "", "", findingCh, map[string]time.Time{}, defaultFindingResendCooldown)

	select {
	case f := <-findingCh:
		t.Fatalf("a Pod pending for just under the threshold must not produce a Finding yet, got %+v", f)
	default:
	}
}

func TestCheckPendingTimeoutAtExactThreshold(t *testing.T) {
	findingCh := make(chan tunnel.Finding, 1)
	now := time.Now()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod-x", CreationTimestamp: metav1.NewTime(now.Add(-podPendingTimeoutThreshold))},
		Status:     corev1.PodStatus{Phase: corev1.PodPending},
	}

	checkPendingTimeout(pod, now, "", "", findingCh, map[string]time.Time{}, defaultFindingResendCooldown)

	select {
	case f := <-findingCh:
		if f.Reason != reasonPendingTimeout {
			t.Errorf("Reason = %q, want %q", f.Reason, reasonPendingTimeout)
		}
		if f.Severity != "medium" {
			t.Errorf("Severity = %q, want %q", f.Severity, "medium")
		}
	default:
		t.Fatal("a Pod pending for exactly the threshold must produce a Finding (>=, not >)")
	}
}

func TestCheckPendingTimeoutAboveThreshold(t *testing.T) {
	findingCh := make(chan tunnel.Finding, 1)
	now := time.Now()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod-x", CreationTimestamp: metav1.NewTime(now.Add(-2 * podPendingTimeoutThreshold))},
		Status:     corev1.PodStatus{Phase: corev1.PodPending},
	}

	checkPendingTimeout(pod, now, "", "", findingCh, map[string]time.Time{}, defaultFindingResendCooldown)

	select {
	case f := <-findingCh:
		if !strings.Contains(f.Message, "Pending for") {
			t.Errorf("Message = %q, want it to state how long the pod has been pending", f.Message)
		}
	default:
		t.Fatal("a Pod well past the threshold must produce a Finding")
	}
}

func TestCheckPendingTimeoutIgnoresNonPendingPhase(t *testing.T) {
	findingCh := make(chan tunnel.Finding, 1)
	now := time.Now()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod-x", CreationTimestamp: metav1.NewTime(now.Add(-24 * time.Hour))},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}

	checkPendingTimeout(pod, now, "", "", findingCh, map[string]time.Time{}, defaultFindingResendCooldown)

	select {
	case f := <-findingCh:
		t.Fatalf("a long-lived but Running pod must never produce a PendingTimeout Finding, got %+v", f)
	default:
	}
}

func TestCheckPendingTimeoutIgnoresZeroCreationTimestamp(t *testing.T) {
	findingCh := make(chan tunnel.Finding, 1)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod-x"}, // CreationTimestamp deliberately left zero
		Status:     corev1.PodStatus{Phase: corev1.PodPending},
	}

	checkPendingTimeout(pod, time.Now(), "", "", findingCh, map[string]time.Time{}, defaultFindingResendCooldown)

	select {
	case f := <-findingCh:
		t.Fatalf("a zero CreationTimestamp must never be treated as an infinitely-long pending duration, got %+v", f)
	default:
	}
}

// TestHandleWatchedPodSetsWorkloadFields confirms the workload identity
// resolved once at the top of handleWatchedPod (BACKLOG.md's A3, migration
// 000042) actually lands on the emitted Finding — the end-to-end path
// workload_test.go's own tests don't cover, since those test
// resolveWorkloadFromOwnerRefs/resolveWorkloadForInvolvedObject in
// isolation.
func TestHandleWatchedPodSetsWorkloadFields(t *testing.T) {
	findingCh := make(chan tunnel.Finding, 1)
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: "payments-7d9c8f6b5", Namespace: "ns",
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "Deployment", Name: "payments", Controller: boolPtr(true)},
			},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns", Name: "payments-7d9c8f6b5-x8k2q",
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "payments-7d9c8f6b5", Controller: boolPtr(true)},
			},
		},
		Spec: corev1.PodSpec{Priority: int32Ptr(1000)},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "app", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: reasonOOMKilled}}},
			},
		},
	}

	handleWatchedPod(context.Background(), k8sfake.NewSimpleClientset(rs), pod, time.Now(), findingCh, map[string]time.Time{}, defaultFindingResendCooldown)

	select {
	case f := <-findingCh:
		if f.WorkloadGVK != "apps/v1/Deployment" || f.WorkloadName != "payments" {
			t.Errorf("WorkloadGVK/WorkloadName = %q/%q, want %q/%q", f.WorkloadGVK, f.WorkloadName, "apps/v1/Deployment", "payments")
		}
		// internal/importance's workload-criticality factor: this Pod's own
		// resolved spec.priority must land on the emitted Finding unchanged.
		if f.PodPriority == nil || *f.PodPriority != 1000 {
			t.Errorf("PodPriority = %v, want 1000", f.PodPriority)
		}
	default:
		t.Fatal("an OOMKilled container must produce a Finding")
	}
}

// TestHandleWatchedPodChecksInitContainers documents and locks in the
// deliberate choice to inspect InitContainerStatuses as well as
// ContainerStatuses — an init container stuck in CrashLoopBackOff blocks
// the whole Pod from ever starting its real containers.
func TestHandleWatchedPodChecksInitContainers(t *testing.T) {
	findingCh := make(chan tunnel.Finding, 1)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod-x"},
		Status: corev1.PodStatus{
			InitContainerStatuses: []corev1.ContainerStatus{
				{Name: "init", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reasonCrashLoopBackOff}}},
			},
		},
	}

	handleWatchedPod(context.Background(), k8sfake.NewSimpleClientset(), pod, time.Now(), findingCh, map[string]time.Time{}, defaultFindingResendCooldown)

	select {
	case f := <-findingCh:
		if f.Reason != reasonCrashLoopBackOff {
			t.Errorf("Reason = %q, want %q", f.Reason, reasonCrashLoopBackOff)
		}
		if !strings.Contains(f.Message, `container "init"`) {
			t.Errorf("Message = %q, want it to name the init container", f.Message)
		}
	default:
		t.Fatal("a CrashLoopBackOff init container must produce a Finding")
	}
}

// TestHandleWatchedPodDedupSuppressesRepeat mirrors detector.go's
// TestHandleWatchedEventSendsWarningEventOnce: a Pod stuck in
// CrashLoopBackOff delivers many MODIFIED watch events for the same
// underlying problem, and the resend-dedup cooldown must suppress all but
// the first within the cooldown window.
func TestHandleWatchedPodDedupSuppressesRepeat(t *testing.T) {
	findingCh := make(chan tunnel.Finding, 1)
	lastSent := map[string]time.Time{}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod-x"},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "app", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reasonCrashLoopBackOff}}},
			},
		},
	}

	handleWatchedPod(context.Background(), k8sfake.NewSimpleClientset(), pod, time.Now(), findingCh, lastSent, defaultFindingResendCooldown)
	select {
	case <-findingCh:
	default:
		t.Fatal("the first delivery of a CrashLoopBackOff pod must produce a Finding")
	}

	handleWatchedPod(context.Background(), k8sfake.NewSimpleClientset(), pod, time.Now(), findingCh, lastSent, defaultFindingResendCooldown)
	select {
	case f := <-findingCh:
		t.Fatalf("re-delivering the same pod/reason within the cooldown window must be suppressed, got %+v", f)
	default:
	}
}

func TestSendPodFindingGivesUpRatherThanWedgingWhenTheQueueNeverAccepts(t *testing.T) {
	// See TestHandleWatchedEventGivesUpRatherThanWedgingWhenTheQueueNeverAccepts
	// for why this state is not reachable while the pump is alive.
	findingCh := make(chan tunnel.Finding, 1)
	findingCh <- tunnel.Finding{}

	restore := findingEmitTimeout
	findingEmitTimeout = 20 * time.Millisecond
	t.Cleanup(func() { findingEmitTimeout = restore })

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod-x"}}

	lastSent := map[string]time.Time{}
	done := make(chan struct{})
	go func() {
		sendPodFinding(pod, reasonOOMKilled, "msg", "high", time.Now(), time.Now(), "", "", findingCh, lastSent, defaultFindingResendCooldown)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sendPodFinding blocked instead of giving up on a finding the queue would never accept")
	}

	// PROJECT.md B176: giving up is not the same as having sent it.
	if len(lastSent) != 0 {
		t.Fatalf("an undelivered finding entered the resend cooldown: %v", lastSent)
	}
}

// TestSendPodFindingFingerprintMatchesSharedAlgorithm confirms this
// detector's fingerprint is exactly computeFingerprint(namespace, "Pod",
// name, reason) — the shared, already-tested algorithm detector.go defines
// — rather than a silently-diverged second implementation.
func TestSendPodFindingFingerprintMatchesSharedAlgorithm(t *testing.T) {
	findingCh := make(chan tunnel.Finding, 1)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "worker-1"}}

	sendPodFinding(pod, reasonOOMKilled, "msg", "high", time.Now(), time.Now(), "", "", findingCh, map[string]time.Time{}, defaultFindingResendCooldown)

	f := <-findingCh
	want := computeFingerprint("payments", "Pod", "worker-1", reasonOOMKilled)
	if f.Fingerprint != want {
		t.Errorf("Fingerprint = %q, want %q (computeFingerprint(namespace, \"Pod\", name, reason))", f.Fingerprint, want)
	}
}
