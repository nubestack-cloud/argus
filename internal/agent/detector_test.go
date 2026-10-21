package agent

import (
	"context"
	"testing"
	"time"

	"argus/internal/tunnel"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestComputeFingerprintDeterministic(t *testing.T) {
	a := computeFingerprint("default", "Pod", "payments-7d9-x8k2q", "FailedScheduling")
	b := computeFingerprint("default", "Pod", "payments-7d9-x8k2q", "FailedScheduling")
	if a != b {
		t.Fatalf("computeFingerprint is not deterministic for identical inputs: %q != %q", a, b)
	}
	if a == "" {
		t.Fatal("computeFingerprint returned an empty string")
	}
}

func TestComputeFingerprintDiffersByField(t *testing.T) {
	base := computeFingerprint("default", "Pod", "payments-7d9-x8k2q", "FailedScheduling")

	cases := map[string]string{
		"namespace": computeFingerprint("other", "Pod", "payments-7d9-x8k2q", "FailedScheduling"),
		"kind":      computeFingerprint("default", "Deployment", "payments-7d9-x8k2q", "FailedScheduling"),
		"name":      computeFingerprint("default", "Pod", "payments-7d9-m3p1r", "FailedScheduling"),
		"reason":    computeFingerprint("default", "Pod", "payments-7d9-x8k2q", "BackOff"),
	}
	for field, fp := range cases {
		if fp == base {
			t.Errorf("changing only %s did not change the fingerprint (got the same value as the base case %q)", field, base)
		}
	}
}

// TestComputeFingerprintNoFieldBoundaryCollision guards the same bug class
// already found and fixed once in this codebase's audit hash chain
// (internal/audit/audit.go's computeHash, see its doc comment): naive
// concatenation with no delimiter lets a field-boundary shift produce an
// identical hash for genuinely different inputs.
func TestComputeFingerprintNoFieldBoundaryCollision(t *testing.T) {
	fp1 := computeFingerprint("ab", "c", "name", "reason")
	fp2 := computeFingerprint("a", "bc", "name", "reason")
	if fp1 == fp2 {
		t.Fatal("field-boundary collision: computeFingerprint(\"ab\",\"c\",\"name\",\"reason\") == computeFingerprint(\"a\",\"bc\",\"name\",\"reason\")")
	}
}

func TestShouldSendUnseenFingerprint(t *testing.T) {
	lastSent := map[string]time.Time{}
	if !shouldSend("fp-1", time.Now(), lastSent, defaultFindingResendCooldown) {
		t.Fatal("an unseen fingerprint must be sendable")
	}
}

func TestShouldSendWithinCooldown(t *testing.T) {
	now := time.Now()
	lastSent := map[string]time.Time{"fp-1": now}
	if shouldSend("fp-1", now.Add(1*time.Minute), lastSent, defaultFindingResendCooldown) {
		t.Fatal("a fingerprint last sent 1 minute ago must not be resendable within a 5-minute cooldown")
	}
}

func TestShouldSendAfterCooldownElapses(t *testing.T) {
	now := time.Now()
	lastSent := map[string]time.Time{"fp-1": now}
	if !shouldSend("fp-1", now.Add(defaultFindingResendCooldown+time.Second), lastSent, defaultFindingResendCooldown) {
		t.Fatal("a fingerprint last sent more than the cooldown ago must be resendable again")
	}
}

func TestShouldSendExactlyAtCooldownBoundary(t *testing.T) {
	now := time.Now()
	lastSent := map[string]time.Time{"fp-1": now}
	if !shouldSend("fp-1", now.Add(defaultFindingResendCooldown), lastSent, defaultFindingResendCooldown) {
		t.Fatal("a fingerprint exactly at the cooldown boundary must be resendable (>=, not >)")
	}
}

func TestShouldSendDoesNotMutateLastSent(t *testing.T) {
	now := time.Now()
	lastSent := map[string]time.Time{}
	shouldSend("fp-1", now, lastSent, defaultFindingResendCooldown)
	if _, ok := lastSent["fp-1"]; ok {
		t.Fatal("shouldSend must not itself record a send — that's the caller's job once it decides to proceed")
	}
}

func TestBuildFindingBasicFields(t *testing.T) {
	ts := metav1.NewTime(time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC))
	ev := &corev1.Event{
		InvolvedObject: corev1.ObjectReference{
			APIVersion:      "v1",
			Kind:            "Pod",
			Namespace:       "default",
			Name:            "payments-7d9-x8k2q",
			UID:             "abc-123",
			ResourceVersion: "456",
		},
		Reason:        "FailedScheduling",
		Message:       "0/3 nodes are available: insufficient cpu",
		Type:          corev1.EventTypeWarning,
		LastTimestamp: ts,
	}

	f := buildFinding(ev, "deadbeef")

	if f.DetectorID != warningEventsDetectorID {
		t.Errorf("DetectorID = %q, want %q", f.DetectorID, warningEventsDetectorID)
	}
	if f.DetectorVersion != warningEventsDetectorVersion {
		t.Errorf("DetectorVersion = %q, want %q", f.DetectorVersion, warningEventsDetectorVersion)
	}
	if f.Fingerprint != "deadbeef" {
		t.Errorf("Fingerprint = %q, want %q", f.Fingerprint, "deadbeef")
	}
	if f.GVK != "v1/Pod" {
		t.Errorf("GVK = %q, want %q", f.GVK, "v1/Pod")
	}
	if f.Namespace != "default" {
		t.Errorf("Namespace = %q, want %q", f.Namespace, "default")
	}
	if f.ObjectName != "payments-7d9-x8k2q" {
		t.Errorf("ObjectName = %q, want %q", f.ObjectName, "payments-7d9-x8k2q")
	}
	if f.ObjectUID != "abc-123" {
		t.Errorf("ObjectUID = %q, want %q", f.ObjectUID, "abc-123")
	}
	if f.ResourceVersion != "456" {
		t.Errorf("ResourceVersion = %q, want %q", f.ResourceVersion, "456")
	}
	if f.Reason != "FailedScheduling" {
		t.Errorf("Reason = %q, want %q", f.Reason, "FailedScheduling")
	}
	if f.Message != "0/3 nodes are available: insufficient cpu" {
		t.Errorf("Message = %q, want the event's message carried through unchanged", f.Message)
	}
	if f.OccurrenceCount != 1 {
		t.Errorf("OccurrenceCount = %d, want 1 (cumulative counting is a hub-side concern)", f.OccurrenceCount)
	}
	if f.Severity != "high" {
		t.Errorf("Severity = %q, want %q (warningEventSeverity classifies FailedScheduling as high)", f.Severity, "high")
	}
	if !f.OccurredAt.Equal(ts.Time) {
		t.Errorf("OccurredAt = %v, want LastTimestamp %v", f.OccurredAt, ts.Time)
	}
}

func TestBuildFindingGVKFallsBackToBareKindWhenAPIVersionEmpty(t *testing.T) {
	ev := &corev1.Event{
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "x"},
	}
	f := buildFinding(ev, "fp")
	if f.GVK != "Pod" {
		t.Errorf("GVK = %q, want bare kind %q when involvedObject.APIVersion is empty", f.GVK, "Pod")
	}
}

func TestBuildFindingGVKIncludesGroupForNonCoreKinds(t *testing.T) {
	ev := &corev1.Event{
		InvolvedObject: corev1.ObjectReference{APIVersion: "apps/v1", Kind: "Deployment", Name: "x"},
	}
	f := buildFinding(ev, "fp")
	if f.GVK != "apps/v1/Deployment" {
		t.Errorf("GVK = %q, want %q", f.GVK, "apps/v1/Deployment")
	}
}

func TestBuildFindingOccurredAtFallsBackToFirstTimestamp(t *testing.T) {
	first := metav1.NewTime(time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC))
	ev := &corev1.Event{
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "x"},
		FirstTimestamp: first,
		// LastTimestamp deliberately left zero.
	}
	f := buildFinding(ev, "fp")
	if !f.OccurredAt.Equal(first.Time) {
		t.Errorf("OccurredAt = %v, want FirstTimestamp fallback %v", f.OccurredAt, first.Time)
	}
}

func TestBuildFindingOccurredAtFallsBackToCreationTimestamp(t *testing.T) {
	created := metav1.NewTime(time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC))
	ev := &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{CreationTimestamp: created},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "x"},
		// Both LastTimestamp and FirstTimestamp deliberately left zero.
	}
	f := buildFinding(ev, "fp")
	if !f.OccurredAt.Equal(created.Time) {
		t.Errorf("OccurredAt = %v, want CreationTimestamp fallback %v", f.OccurredAt, created.Time)
	}
}

// TestHandleWatchedEventSetsWorkloadFieldsForAPod confirms
// resolveWorkloadForInvolvedObject's result actually lands on the emitted
// Finding for a Warning event whose InvolvedObject is a Pod owned (via a
// ReplicaSet) by a Deployment — the flagship case CAPABILITIES.md §5
// measured as "FailedMount x2 pods" contributing to 4 incidents for one
// missing ConfigMap (BACKLOG.md's A3).
func TestHandleWatchedEventSetsWorkloadFieldsForAPod(t *testing.T) {
	findingCh := make(chan tunnel.Finding, 1)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "web-7d9c8f6b5-x8k2q", Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "web-7d9c8f6b5", Controller: boolPtr(true)},
			},
		},
		Spec: corev1.PodSpec{Priority: int32Ptr(1000)},
	}
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: "web-7d9c8f6b5", Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "Deployment", Name: "web", Controller: boolPtr(true)},
			},
		},
	}
	ev := &corev1.Event{
		Type:           corev1.EventTypeWarning,
		InvolvedObject: corev1.ObjectReference{Namespace: "default", Kind: "Pod", Name: "web-7d9c8f6b5-x8k2q"},
		Reason:         "FailedMount",
	}

	handleWatchedEvent(context.Background(), k8sfake.NewSimpleClientset(pod, rs), ev, findingCh, map[string]time.Time{}, defaultFindingResendCooldown)

	select {
	case f := <-findingCh:
		if f.WorkloadGVK != "apps/v1/Deployment" || f.WorkloadName != "web" {
			t.Errorf("WorkloadGVK/WorkloadName = %q/%q, want %q/%q", f.WorkloadGVK, f.WorkloadName, "apps/v1/Deployment", "web")
		}
		// internal/importance's workload-criticality factor: the Pod's own
		// resolved spec.priority, read off the SAME Get this already pays
		// for, must land on the emitted Finding too.
		if f.PodPriority == nil || *f.PodPriority != 1000 {
			t.Errorf("PodPriority = %v, want 1000", f.PodPriority)
		}
	default:
		t.Fatal("a Warning-type event must produce a Finding")
	}
}

// TestHandleWatchedEventPodWithNoResolvedPriorityLeavesPodPriorityNil
// guards the absent-vs-zero contract tunnel.Finding.PodPriority documents:
// a Pod the priority admission plugin never stamped a value onto must
// produce a Finding with PodPriority nil, never a fabricated 0 that would
// silently rank it as the LEAST critical Pod in the fleet.
func TestHandleWatchedEventPodWithNoResolvedPriorityLeavesPodPriorityNil(t *testing.T) {
	findingCh := make(chan tunnel.Finding, 1)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "plain-pod", Namespace: "default"},
	}
	ev := &corev1.Event{
		Type:           corev1.EventTypeWarning,
		InvolvedObject: corev1.ObjectReference{Namespace: "default", Kind: "Pod", Name: "plain-pod"},
		Reason:         "FailedMount",
	}

	handleWatchedEvent(context.Background(), k8sfake.NewSimpleClientset(pod), ev, findingCh, map[string]time.Time{}, defaultFindingResendCooldown)

	select {
	case f := <-findingCh:
		if f.PodPriority != nil {
			t.Errorf("PodPriority = %v, want nil — this Pod's spec.priority was never resolved", *f.PodPriority)
		}
	default:
		t.Fatal("a Warning-type event must produce a Finding")
	}
}

// TestHandleWatchedEventStaleness covers WORKLOG §178: a watch opened with no
// resourceVersion replays every Event the API server still holds (an hour, by
// default) as a fresh delivery, so an agent restart re-reported an hour of
// history. That was seen re-sending a BackOff finding for an already-DELETED
// Pod, which reopened a Validating incident through the hub's ordinary
// recurrence path.
func TestHandleWatchedEventStaleness(t *testing.T) {
	warning := func(name string, ts time.Time) *corev1.Event {
		ev := &corev1.Event{
			Type:           corev1.EventTypeWarning,
			InvolvedObject: corev1.ObjectReference{Kind: "Pod", Namespace: "default", Name: name},
			Reason:         "BackOff",
			Message:        "back-off restarting failed container",
		}
		if !ts.IsZero() {
			ev.LastTimestamp = metav1.NewTime(ts)
		}
		return ev
	}
	now := time.Now()

	for _, tc := range []struct {
		name     string
		ev       *corev1.Event
		wantSend bool
	}{
		// A live problem's Event is delivered when its timestamp is bumped, so
		// this is what real detection looks like and it must not regress.
		{"fresh", warning("fresh-pod", now.Add(-30*time.Second)), true},
		// Inside the window: a CrashLoopBackOff at its capped 5-minute retry
		// interval is still a current fault.
		{"five minutes old", warning("backoff-pod", now.Add(-5*time.Minute)), true},
		// The replay case. An hour is the default event TTL, so this is exactly
		// what a restart used to forward.
		{"an hour old", warning("gone-pod", now.Add(-time.Hour)), false},
		{"just past the threshold", warning("old-pod", now.Add(-staleEventThreshold-time.Minute)), false},
		// Fails OPEN: with no timestamp at all the event cannot be PROVEN old,
		// and a detector must not discard input on an inference it cannot make.
		{"no timestamp at all", warning("undated-pod", time.Time{}), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findingCh := make(chan tunnel.Finding, 1)
			handleWatchedEvent(context.Background(), k8sfake.NewSimpleClientset(), tc.ev, findingCh, map[string]time.Time{}, defaultFindingResendCooldown)
			select {
			case <-findingCh:
				if !tc.wantSend {
					t.Errorf("an event %s was forwarded as a current problem", tc.name)
				}
			default:
				if tc.wantSend {
					t.Errorf("an event %s was dropped, but it is not provably stale", tc.name)
				}
			}
		})
	}
}

// TestHandleWatchedEventStaleEventDoesNotConsumeTheCooldown guards the ordering
// inside handleWatchedEvent: the staleness check runs BEFORE the fingerprint and
// the resend-cooldown map are touched. Otherwise a replayed old event would
// record a lastSent for its fingerprint and suppress the real, fresh event that
// arrives moments later for the same problem — turning a fix for spurious
// findings into a cause of missed ones.
func TestHandleWatchedEventStaleEventDoesNotConsumeTheCooldown(t *testing.T) {
	now := time.Now()
	lastSent := map[string]time.Time{}
	clientset := k8sfake.NewSimpleClientset()
	obj := corev1.ObjectReference{Kind: "Pod", Namespace: "default", Name: "same-pod"}

	stale := &corev1.Event{Type: corev1.EventTypeWarning, InvolvedObject: obj, Reason: "BackOff",
		LastTimestamp: metav1.NewTime(now.Add(-time.Hour))}
	fresh := &corev1.Event{Type: corev1.EventTypeWarning, InvolvedObject: obj, Reason: "BackOff",
		LastTimestamp: metav1.NewTime(now)}

	findingCh := make(chan tunnel.Finding, 2)
	handleWatchedEvent(context.Background(), clientset, stale, findingCh, lastSent, defaultFindingResendCooldown)
	if len(lastSent) != 0 {
		t.Fatalf("a stale event recorded a resend cooldown (%v) — it would suppress the real event for the same fingerprint", lastSent)
	}
	handleWatchedEvent(context.Background(), clientset, fresh, findingCh, lastSent, defaultFindingResendCooldown)
	select {
	case <-findingCh:
	default:
		t.Fatal("the fresh event for the same fingerprint was suppressed by the stale one")
	}
}

func TestHandleWatchedEventIgnoresNormalEvents(t *testing.T) {
	findingCh := make(chan tunnel.Finding, 1)
	ev := &corev1.Event{
		Type:           corev1.EventTypeNormal,
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "x"},
		Reason:         "Scheduled",
	}

	handleWatchedEvent(context.Background(), k8sfake.NewSimpleClientset(), ev, findingCh, map[string]time.Time{}, defaultFindingResendCooldown)

	select {
	case f := <-findingCh:
		t.Fatalf("a Normal-type event must never produce a Finding, got %+v", f)
	default:
	}
}

func TestHandleWatchedEventSendsWarningEventOnce(t *testing.T) {
	findingCh := make(chan tunnel.Finding, 1)
	lastSent := map[string]time.Time{}
	ev := &corev1.Event{
		Type:           corev1.EventTypeWarning,
		InvolvedObject: corev1.ObjectReference{Namespace: "default", Kind: "Pod", Name: "x"},
		Reason:         "FailedScheduling",
	}

	handleWatchedEvent(context.Background(), k8sfake.NewSimpleClientset(), ev, findingCh, lastSent, defaultFindingResendCooldown)

	select {
	case f := <-findingCh:
		if f.Reason != "FailedScheduling" {
			t.Errorf("Reason = %q, want %q", f.Reason, "FailedScheduling")
		}
	default:
		t.Fatal("a Warning-type event must produce a Finding")
	}

	// Re-delivering the identical (MODIFIED-style) event immediately after
	// must NOT produce a second Finding — this is exactly the resend-dedup
	// cooldown's job.
	handleWatchedEvent(context.Background(), k8sfake.NewSimpleClientset(), ev, findingCh, lastSent, defaultFindingResendCooldown)
	select {
	case f := <-findingCh:
		t.Fatalf("re-sending the same fingerprint within the cooldown window must be suppressed, got %+v", f)
	default:
	}
}

func TestHandleWatchedEventGivesUpRatherThanWedgingWhenTheQueueNeverAccepts(t *testing.T) {
	// A channel with no room and nothing draining it — i.e. the finding
	// queue's pump is gone. In production that only happens at process
	// shutdown, but a detector's watch loop must never be wedged by it.
	findingCh := make(chan tunnel.Finding, 1)
	findingCh <- tunnel.Finding{}

	restore := findingEmitTimeout
	findingEmitTimeout = 20 * time.Millisecond
	t.Cleanup(func() { findingEmitTimeout = restore })

	ev := &corev1.Event{
		Type:           corev1.EventTypeWarning,
		InvolvedObject: corev1.ObjectReference{Namespace: "default", Kind: "Pod", Name: "x"},
		Reason:         "FailedScheduling",
	}

	lastSent := map[string]time.Time{}
	done := make(chan struct{})
	go func() {
		handleWatchedEvent(context.Background(), k8sfake.NewSimpleClientset(), ev, findingCh, lastSent, defaultFindingResendCooldown)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleWatchedEvent blocked instead of giving up on a finding the queue would never accept")
	}

	// PROJECT.md B176: giving up is not the same as having sent it.
	if len(lastSent) != 0 {
		t.Fatalf("an undelivered finding entered the resend cooldown: %v", lastSent)
	}
}

func TestSeverityForEventReason(t *testing.T) {
	cases := map[string]string{
		"SystemOOM":                           "critical",
		"NodeNotReady":                        "critical",
		"Evicted":                             "high",
		"FailedScheduling":                    "high",
		"Unhealthy":                           "medium",
		"SomeReasonThisTableDoesNotKnowAbout": "medium",
		"":                                    "medium",
	}
	for reason, want := range cases {
		if got := severityForEventReason(reason); got != want {
			t.Errorf("severityForEventReason(%q) = %q, want %q", reason, got, want)
		}
	}
}

func TestBuildFindingDoesNotSumCumulativeEventSnapshots(t *testing.T) {
	ev := &corev1.Event{Count: 7, Series: &corev1.EventSeries{Count: 12}}
	if got := buildFinding(ev, "fp").OccurrenceCount; got != 1 {
		t.Fatalf("OccurrenceCount = %d, want 1 per delivered Finding", got)
	}
}

// Kyverno reports an Audit-mode violation as a Warning event, from its
// background scan and again at admission while letting the object through
// (live on rke2, 2026-10-15: nine incidents from two Audit policies). Each is
// a risk, recorded and never promoted; any other component's event is not.
func TestPolicyAuditEventsAreRisksNotFaults(t *testing.T) {
	ev := &corev1.Event{
		Type: corev1.EventTypeWarning, Reason: "PolicyViolation", ReportingController: "kyverno-scan",
		InvolvedObject: corev1.ObjectReference{Kind: "Deployment", APIVersion: "apps/v1", Namespace: "shop", Name: "api"},
	}
	if f := buildFinding(ev, "fp"); f.Class != tunnel.FindingClassRisk || f.Impact != tunnel.FindingImpactNone {
		t.Fatalf("audit scan finding = %s/%s, want risk/none", f.Class, f.Impact)
	}
	ev.ReportingController, ev.Source.Component = "", "gatekeeper-audit"
	if f := buildFinding(ev, "fp"); f.Class != tunnel.FindingClassRisk {
		t.Fatalf("gatekeeper audit finding = %s, want risk", f.Class)
	}
	ev.Source.Component = "kyverno-admission"
	if f := buildFinding(ev, "fp"); f.Class != tunnel.FindingClassRisk {
		t.Fatalf("audit-mode admission finding = %s, want risk", f.Class)
	}
	// The blocked change surfaces from the controller that made it.
	ev.Reason, ev.Source.Component = "FailedCreate", "replicaset-controller"
	if f := buildFinding(ev, "fp"); f.Class != tunnel.FindingClassFault || f.Impact != tunnel.FindingImpactDegraded {
		t.Fatalf("FailedCreate = %s/%s, want the ordinary fault", f.Class, f.Impact)
	}
}
