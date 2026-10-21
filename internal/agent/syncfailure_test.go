package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	k8sruntime "k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"argus/internal/tunnel"
)

// argoApp builds an Application in the shape a real one has. The nesting matters:
// the fields this check reads sit under status.operationState and status.sync, and
// an earlier guess that conditions carried the signal was wrong — a persistently
// failing Application had status.conditions EMPTY.
func argoApp(name, phase, message, syncStatus string, retries int64) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Application",
		"metadata":   map[string]any{"name": name, "namespace": "argocd", "uid": "uid-" + name},
		"status": map[string]any{
			"sync": map[string]any{"status": syncStatus, "revision": "0cafcf93cde536fcda5efeb9605c1ff3725e0877"},
			"operationState": map[string]any{
				"phase":      phase,
				"message":    message,
				"retryCount": retries,
			},
		},
	}}
	return u
}

func newArgoFake(objs ...runtime.Object) *dynfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	gvrToKind := map[k8sruntime.GroupVersionResource]string{
		argoApplicationsGVR: "ApplicationList",
	}
	return dynfake.NewSimpleDynamicClientWithCustomListKinds(scheme, addScheduleListKinds(gvrToKind), objs...)
}

func TestCheckArgoSyncFailed(t *testing.T) {
	now := time.Now()
	const apiRejection = `one or more objects failed to apply, reason: CronJob.batch "s1-syncfail" is invalid: spec.schedule: Invalid value: "not a cron expression": expected exactly 5 fields, found 4`

	for _, tc := range []struct {
		name string
		app  *unstructured.Unstructured
		fire bool
	}{
		{
			// THE MEASURED CASE, and the one a naive check misses. Argo keeps a
			// permanently failing sync at phase "Running" while it retries, so
			// waiting for "Failed" would wait forever on a manifest the API server
			// refuses every time.
			name: "retrying forever at phase Running",
			app:  argoApp("cron-bad", "Running", apiRejection, "OutOfSync", 3),
			fire: true,
		},
		{
			name: "terminal Failed",
			app:  argoApp("failed", "Failed", "sync failed", "OutOfSync", 0),
			fire: true,
		},
		{
			name: "terminal Error",
			app:  argoApp("errored", "Error", "comparison error", "OutOfSync", 0),
			fire: true,
		},
		{
			// Running with no retry yet is a sync in progress, not a failure. This
			// is what stops the check reporting every ordinary deploy.
			name: "in progress, nothing failed yet",
			app:  argoApp("in-flight", "Running", "", "OutOfSync", 0),
			fire: false,
		},
		{
			// A stale failure message from a previous attempt survives on the
			// object. Requiring OutOfSync as well means only a sync that is
			// genuinely not applied right now reports.
			name: "failed earlier but now Synced",
			app:  argoApp("recovered", "Failed", "an old failure", "Synced", 2),
			fire: false,
		},
		{
			name: "healthy",
			app:  argoApp("good", "Succeeded", "", "Synced", 0),
			fire: false,
		},
		{
			name: "never synced",
			app:  argoApp("fresh", "", "", "Unknown", 0),
			fire: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := checkArgoSyncFailed(context.Background(), newArgoFake(tc.app), now, defaultSweepSustainedThreshold)
			if err != nil {
				t.Fatalf("checkArgoSyncFailed: %v", err)
			}
			if tc.fire && len(out) != 1 {
				t.Fatalf("got %d candidates, want 1", len(out))
			}
			if !tc.fire {
				if len(out) != 0 {
					t.Fatalf("got %d candidates, want 0: %+v", len(out), out)
				}
				return
			}
			c := out[0]
			if c.Reason != reasonGitOpsSyncFailed {
				t.Errorf("Reason = %q", c.Reason)
			}
			if c.GVK != "argoproj.io/v1alpha1/Application" {
				t.Errorf("GVK = %q", c.GVK)
			}
			if c.Severity != "high" {
				t.Errorf("Severity = %q, want high — the cluster is not what the repository says", c.Severity)
			}
			// Argo records no "failing since" anywhere (operationState.startedAt
			// resets on every retry), so the observed-duration gate must apply.
			if !c.SustainedFrom.IsZero() {
				t.Error("SustainedFrom must be zero so the sustain gate applies")
			}
		})
	}
}

// The message must carry the API server's own rejection, because that text names
// the field, the value and the reason — the difference between "a sync failed" and
// something an operator can act on.
func TestCheckArgoSyncFailedMessageNamesTheCause(t *testing.T) {
	const rejection = `Job.batch "immut-job" is invalid: spec.template: field is immutable`
	out, err := checkArgoSyncFailed(context.Background(),
		newArgoFake(argoApp("immut", "Running", "one or more synchronization tasks completed unsuccessfully, reason: "+rejection, "OutOfSync", 4)),
		time.Now(), defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkArgoSyncFailed: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates", len(out))
	}
	for _, want := range []string{"field is immutable", "immut-job", "4 retries", "0cafcf93cde5"} {
		if !strings.Contains(out[0].Message, want) {
			t.Errorf("message does not contain %q:\n%s", want, out[0].Message)
		}
	}
}

// A cluster with no Argo CD at all must be silent, not an error — otherwise every
// such installation logs a failure every thirty seconds, which trains an operator
// to ignore this detector.
func TestCheckArgoSyncFailedIsSilentWithoutArgo(t *testing.T) {
	out, err := checkArgoSyncFailed(context.Background(), newArgoFake(), time.Now(), defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("an Argo-less cluster produced an error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("got %d candidates from an empty cluster", len(out))
	}
}

func TestArgoSyncIsFailing(t *testing.T) {
	for _, tc := range []struct {
		phase   string
		retries int64
		want    bool
	}{
		{"Failed", 0, true},
		{"Error", 0, true},
		// The load-bearing row: Running WITH a retry is the permanent-failure
		// state, and Running without one is an ordinary deploy in flight.
		{"Running", 1, true},
		{"Running", 0, false},
		{"Succeeded", 0, false},
		{"Succeeded", 5, false},
		{"Terminating", 0, false},
		{"", 0, false},
	} {
		if got := argoSyncIsFailing(tc.phase, tc.retries); got != tc.want {
			t.Errorf("argoSyncIsFailing(%q, %d) = %v, want %v", tc.phase, tc.retries, got, tc.want)
		}
	}
}

// TestDynamicSweepCheckerIsRegistered is a list-membership check, not an
// execution check — it caught checkArgoSyncFailed being written and unit
// tested but never wired to anything, and it would NOT have caught
// dynamicSweepCheckers itself being built and then never consulted by
// runOneSweep, which is exactly what BUGS.md 79 was: this list existed,
// checkArgoSyncFailed was correctly in it, and runOneSweep simply never
// iterated it. TestCheckArgoSyncFailedRunsFromRealSweepLoop below is the
// test that actually exercises runOneSweep's real path end to end and would
// have caught that.
func TestDynamicSweepCheckerIsRegistered(t *testing.T) {
	for _, c := range dynamicSweepCheckers {
		if c.name == "argo sync failed" {
			return
		}
	}
	t.Error("checkArgoSyncFailed is not in dynamicSweepCheckers, so it is tested but never runs")
}

// TestCheckArgoSyncFailedRunsFromRealSweepLoop is the fix for BUGS.md 79:
// checkArgoSyncFailed was registered in dynamicSweepCheckers but runOneSweep
// — the function the real ticker loop in runSweepDetector actually calls —
// only ever iterated sweepCheckers, so the dynamic list was dead: nothing in
// production ever ran an Argo sync-failure check no matter how many unit
// tests covered checkArgoSyncFailed in isolation.
//
// This drives runOneSweep itself (not checkArgoSyncFailed directly) with a
// fake dynamic client carrying a permanently-failing Application, exactly
// the shape TestCheckArgoSyncFailed already covers, and asserts a Finding
// comes out the other end of the real sweep-loop entry point. Run against
// the pre-fix code (runOneSweep with no dyn parameter, never consulting
// dynamicSweepCheckers) this test fails to even compile — the strongest
// possible proof that the old code path could not have produced this
// Finding, since there was no path from dynamicSweepCheckers to the wire at
// all.
func TestCheckArgoSyncFailedRunsFromRealSweepLoop(t *testing.T) {
	now := time.Now()
	const apiRejection = `one or more objects failed to apply, reason: CronJob.batch "s1-syncfail" is invalid: spec.schedule: Invalid value: "not a cron expression": expected exactly 5 fields, found 4`
	dyn := newArgoFake(argoApp("cron-bad", "Running", apiRejection, "OutOfSync", 3))
	clientset := k8sfake.NewSimpleClientset()

	findingCh := make(chan tunnel.Finding, 4)
	lastSent := map[string]time.Time{}
	firstObserved := map[string]time.Time{}

	// One sweep is enough: checkArgoSyncFailed sets SustainedFrom to zero and
	// relies on runOneSweep's own observed-duration gate (sustainedLongEnough),
	// same as every other no-authoritative-timestamp checker in this package —
	// so, like TestRunOneSweepGatesCandidatesWithNoAuthoritativeTimestamp, the
	// first sweep only records the observation.
	runOneSweep(context.Background(), clientset, dyn, findingCh, lastSent, firstObserved, defaultFindingResendCooldown, defaultSweepSustainedThreshold, defaultTestCheckerTimeout, nil)
	if len(findingCh) != 0 {
		t.Fatalf("first observation must not report yet; got %d findings", len(findingCh))
	}

	// Backdate the observation past the threshold, simulating the sync failure
	// persisting across sweeps, then sweep again through the same real entry
	// point.
	for fp := range firstObserved {
		firstObserved[fp] = now.Add(-defaultSweepSustainedThreshold - time.Minute)
	}
	runOneSweep(context.Background(), clientset, dyn, findingCh, lastSent, firstObserved, defaultFindingResendCooldown, defaultSweepSustainedThreshold, defaultTestCheckerTimeout, nil)

	select {
	case f := <-findingCh:
		if f.Reason != reasonGitOpsSyncFailed {
			t.Errorf("Reason = %q, want %q", f.Reason, reasonGitOpsSyncFailed)
		}
		if f.GVK != "argoproj.io/v1alpha1/Application" {
			t.Errorf("GVK = %q", f.GVK)
		}
		if f.ObjectName != "cron-bad" {
			t.Errorf("ObjectName = %q", f.ObjectName)
		}
		if !strings.Contains(f.Message, "s1-syncfail") {
			t.Errorf("message does not name the API server's rejection:\n%s", f.Message)
		}
	default:
		t.Fatal("runOneSweep's real path (the same one runSweepDetector's ticker calls) never produced a Finding for a sustained Argo sync failure")
	}
}

// TestCheckArgoSyncFailedRunsFromRealSweepLoopSkippedWithNilDynamicClient
// pins the soft-degrade contract runSweepDetector relies on when it can't
// build a dynamic client (or is running against a test/harness that passes
// nil deliberately, as every pre-existing test in sweep_detector_test.go
// does): dynamicSweepCheckers must be skipped, not panic on a nil
// dynamic.Interface.
func TestCheckArgoSyncFailedRunsFromRealSweepLoopSkippedWithNilDynamicClient(t *testing.T) {
	findingCh := make(chan tunnel.Finding, 4)
	runOneSweep(context.Background(), k8sfake.NewSimpleClientset(), nil, findingCh,
		map[string]time.Time{}, map[string]time.Time{}, defaultFindingResendCooldown, defaultSweepSustainedThreshold, defaultTestCheckerTimeout, nil)
	if len(findingCh) != 0 {
		t.Fatalf("a nil dynamic client must skip dynamicSweepCheckers silently, got %d findings", len(findingCh))
	}
}
