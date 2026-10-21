package agent

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	k8sruntime "k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

// newPolicyControllerFake builds a fake dynamic client that knows the
// ExecutionWindow CRD's list kind — mirrors syncfailure_test.go's
// newArgoFake for an identical reason (an arbitrary custom GVR has no list
// kind the fake client can infer on its own).
func newPolicyControllerFake(objs ...runtime.Object) *dynfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	gvrToKind := map[k8sruntime.GroupVersionResource]string{
		executionWindowGVR: "ExecutionWindowList",
	}
	return dynfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToKind, objs...)
}

func newPolicyControllerTestExecutor(objs ...runtime.Object) (*ToolExecutor, *dynfake.FakeDynamicClient) {
	dyn := newPolicyControllerFake(objs...)
	return NewToolExecutorForTestWithPolicyController(nil, nil, nil, dyn), dyn
}

// TestOpenExecutionWindowUnavailable pins the defence-in-depth answer for a
// cluster that never mounted the pack: a clean, named error, never a nil
// pointer panic — the same posture dry_run_patch's own
// errDryRunNotConfigured takes.
func TestOpenExecutionWindowUnavailable(t *testing.T) {
	var e *ToolExecutor // nil, exactly like a cluster with no reachable config at all
	_, _, err := e.openExecutionWindow(context.Background(), mustMarshal(map[string]any{"windows": []any{}}))
	if err == nil {
		t.Fatal("expected an error from a nil ToolExecutor")
	}

	e2 := NewToolExecutorForTest(nil, nil) // policyDynamic nil: pack not enabled
	_, _, err = e2.openExecutionWindow(context.Background(), mustMarshal(map[string]any{"windows": []any{}}))
	if err != errPolicyControllerNotConfigured {
		t.Fatalf("got %v, want errPolicyControllerNotConfigured", err)
	}
}

// TestOpenThenCloseExecutionWindow exercises the ordinary happy path: open
// creates the singleton with one entry, close removes it again, both via the
// exact tool-call args shapes internal/api/executionwindow.go sends.
func TestOpenThenCloseExecutionWindow(t *testing.T) {
	e, dyn := newPolicyControllerTestExecutor()
	ctx := context.Background()

	openArgs := mustMarshal(map[string]any{"windows": []map[string]any{{
		"planId": "plan_1", "targetApiGroup": "apps", "targetKind": "Deployment",
		"targetNamespace": "prod", "targetName": "web", "targetUid": "uid-web",
		"fieldPath": "spec.progressDeadlineSeconds",
	}}})
	out, truncated, err := e.openExecutionWindow(ctx, openArgs)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if truncated {
		t.Fatal("open_execution_window should never report truncated")
	}
	var openResult struct{ Opened, TotalOpen int }
	if err := json.Unmarshal(out, &openResult); err != nil {
		t.Fatalf("decode open result: %v", err)
	}
	if openResult.Opened != 1 || openResult.TotalOpen != 1 {
		t.Fatalf("open result = %+v, want Opened=1 TotalOpen=1", openResult)
	}

	entries, _, _, err := e.getExecutionWindowSpec(ctx)
	if err != nil {
		t.Fatalf("getExecutionWindowSpec: %v", err)
	}
	if len(entries) != 1 || entries[0].PlanID != "plan_1" || entries[0].FieldPath != "spec.progressDeadlineSeconds" {
		t.Fatalf("stored entries = %+v", entries)
	}
	if entries[0].OpenedAt == "" {
		t.Fatal("OpenedAt must be stamped by the agent itself, never left empty")
	}
	if entries[0].TargetUID != "uid-web" {
		t.Fatalf("TargetUID = %q, want uid-web", entries[0].TargetUID)
	}

	closeArgs := mustMarshal(map[string]any{"planId": "plan_1"})
	out, _, err = e.closeExecutionWindow(ctx, closeArgs)
	if err != nil {
		t.Fatalf("close: %v", err)
	}
	var closeResult struct{ Closed int }
	if err := json.Unmarshal(out, &closeResult); err != nil {
		t.Fatalf("decode close result: %v", err)
	}
	if closeResult.Closed != 1 {
		t.Fatalf("close result = %+v, want Closed=1", closeResult)
	}

	entries, _, _, err = e.getExecutionWindowSpec(ctx)
	if err != nil {
		t.Fatalf("getExecutionWindowSpec after close: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries after close = %+v, want none", entries)
	}
	_ = dyn
}

// TestCloseExecutionWindowIsIdempotent proves the property
// internal/api/executionwindow.go's unconditional `defer` depends on:
// closing a plan that was never opened (or already closed) is a clean
// zero-closed success, never an error.
func TestCloseExecutionWindowIsIdempotent(t *testing.T) {
	e, _ := newPolicyControllerTestExecutor() // singleton does not even exist yet
	out, _, err := e.closeExecutionWindow(context.Background(), mustMarshal(map[string]any{"planId": "plan_never_opened"}))
	if err != nil {
		t.Fatalf("close on a never-opened plan must not error: %v", err)
	}
	var result struct{ Closed int }
	_ = json.Unmarshal(out, &result)
	if result.Closed != 0 {
		t.Fatalf("Closed = %d, want 0", result.Closed)
	}
}

// TestOpenExecutionWindowIsIdempotentPerPlanAndField proves a re-sent open
// for the same (planId, fieldPath) refreshes rather than duplicates — a
// retried tunnel call (e.g. after a transient network error on the hub side)
// must not leave two entries permitting the same thing, which would make
// closing one leave the other still open.
func TestOpenExecutionWindowIsIdempotentPerPlanAndField(t *testing.T) {
	e, _ := newPolicyControllerTestExecutor()
	ctx := context.Background()
	entry := map[string]any{
		"planId": "plan_1", "targetKind": "Deployment", "targetName": "web",
		"targetUid": "uid-web", "fieldPath": "spec.progressDeadlineSeconds",
	}
	for i := 0; i < 3; i++ {
		if _, _, err := e.openExecutionWindow(ctx, mustMarshal(map[string]any{"windows": []map[string]any{entry}})); err != nil {
			t.Fatalf("open attempt %d: %v", i, err)
		}
	}
	entries, _, _, err := e.getExecutionWindowSpec(ctx)
	if err != nil {
		t.Fatalf("getExecutionWindowSpec: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries after 3 identical opens = %d, want exactly 1 (idempotent)", len(entries))
	}
}

// TestOpenExecutionWindowConcurrentDifferentTargets proves the design claim
// in internal/api/executionwindow.go's header: two concurrent windows for
// DIFFERENT targets on the same cluster both end up present, via the
// get-modify-update retry loop, rather than one clobbering the other.
func TestOpenExecutionWindowConcurrentDifferentTargets(t *testing.T) {
	e, dyn := newPolicyControllerTestExecutor()
	ctx := context.Background()

	// First open, to create the singleton, so both concurrent opens below
	// race on an UPDATE (the more contested path) rather than one of them
	// racing a CREATE.
	if _, _, err := e.openExecutionWindow(ctx, mustMarshal(map[string]any{"windows": []map[string]any{{
		"planId": "plan_0", "targetKind": "Deployment", "targetName": "seed", "targetUid": "uid-seed", "fieldPath": "spec.progressDeadlineSeconds",
	}}})); err != nil {
		t.Fatalf("seed open: %v", err)
	}

	// Inject exactly one spurious conflict on the first Update this test
	// issues after the seed, simulating a genuinely concurrent writer
	// winning the race once — the retry loop must recover from it.
	injected := false
	dyn.PrependReactor("update", "executionwindows", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if !injected {
			injected = true
			return true, nil, apierrors.NewConflict(executionWindowGVR.GroupResource(), executionWindowSingletonName, context.DeadlineExceeded)
		}
		return false, nil, nil
	})

	if _, _, err := e.openExecutionWindow(ctx, mustMarshal(map[string]any{"windows": []map[string]any{{
		"planId": "plan_a", "targetKind": "Deployment", "targetName": "a", "targetUid": "uid-a", "fieldPath": "spec.progressDeadlineSeconds",
	}}})); err != nil {
		t.Fatalf("open for target a (should retry past the injected conflict): %v", err)
	}
	if _, _, err := e.openExecutionWindow(ctx, mustMarshal(map[string]any{"windows": []map[string]any{{
		"planId": "plan_b", "targetKind": "StatefulSet", "targetName": "b", "targetUid": "uid-b", "fieldPath": "spec.revisionHistoryLimit",
	}}})); err != nil {
		t.Fatalf("open for target b: %v", err)
	}

	entries, _, _, err := e.getExecutionWindowSpec(ctx)
	if err != nil {
		t.Fatalf("getExecutionWindowSpec: %v", err)
	}
	byPlan := map[string]bool{}
	for _, e := range entries {
		byPlan[e.PlanID] = true
	}
	for _, want := range []string{"plan_0", "plan_a", "plan_b"} {
		if !byPlan[want] {
			t.Errorf("missing entry for %s after concurrent opens for different targets — entries: %+v", want, entries)
		}
	}
}

// TestSweepStaleExecutionWindows is the crash-safety backstop's own unit
// test: an entry stamped older than policyWindowTTL is removed by the
// sweep; one still fresh is left alone. This is what bounds an execution
// window's lifetime when the hub that opened it crashes or the tunnel drops
// before it ever asks to close it — see policywindow.go's header.
func TestSweepStaleExecutionWindows(t *testing.T) {
	now := time.Now().UTC()
	fresh := storedWindowEntry{
		windowRequestEntry: windowRequestEntry{PlanID: "plan_fresh", TargetName: "fresh", TargetUID: "uid-fresh", FieldPath: "spec.progressDeadlineSeconds"},
		OpenedAt:           now.Add(-1 * time.Minute).Format(time.RFC3339),
	}
	stale := storedWindowEntry{
		windowRequestEntry: windowRequestEntry{PlanID: "plan_stale", TargetName: "stale", TargetUID: "uid-stale", FieldPath: "spec.revisionHistoryLimit"},
		OpenedAt:           now.Add(-2 * policyWindowTTL).Format(time.RFC3339),
	}
	malformed := storedWindowEntry{
		windowRequestEntry: windowRequestEntry{PlanID: "plan_malformed", TargetName: "m", TargetUID: "uid-m", FieldPath: "spec.progressDeadlineSeconds"},
		OpenedAt:           "not-a-timestamp",
	}

	e, _ := newPolicyControllerTestExecutor()
	ctx := context.Background()
	if err := e.putExecutionWindowSpec(ctx, nil, "", false); err != nil {
		t.Fatalf("seed empty singleton: %v", err)
	}
	seedEntries := []storedWindowEntry{fresh, stale, malformed}
	_, rv, exists, err := e.getExecutionWindowSpec(ctx)
	if err != nil {
		t.Fatalf("get after seed: %v", err)
	}
	if err := e.putExecutionWindowSpec(ctx, seedEntries, rv, exists); err != nil {
		t.Fatalf("seed entries: %v", err)
	}

	removed, err := e.sweepStaleExecutionWindows(ctx, now)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if removed != 2 {
		t.Fatalf("removed = %d, want 2 (stale + malformed OpenedAt)", removed)
	}

	entries, _, _, err := e.getExecutionWindowSpec(ctx)
	if err != nil {
		t.Fatalf("get after sweep: %v", err)
	}
	if len(entries) != 1 || entries[0].PlanID != "plan_fresh" {
		t.Fatalf("entries after sweep = %+v, want only plan_fresh", entries)
	}
}

// TestSweepStaleExecutionWindowsNoWindowsIsANoOp guards against the sweeper
// writing an object into existence (or writing at all) when there is
// nothing to sweep — every ordinary tick, on every cluster that has never
// opened a window, must cost nothing.
func TestSweepStaleExecutionWindowsNoWindowsIsANoOp(t *testing.T) {
	e, dyn := newPolicyControllerTestExecutor()
	wrote := false
	dyn.PrependReactor("update", "executionwindows", func(k8stesting.Action) (bool, runtime.Object, error) {
		wrote = true
		return false, nil, nil
	})
	dyn.PrependReactor("create", "executionwindows", func(k8stesting.Action) (bool, runtime.Object, error) {
		wrote = true
		return false, nil, nil
	})
	if _, err := e.sweepStaleExecutionWindows(context.Background(), time.Now()); err != nil {
		t.Fatalf("sweep on an empty cluster: %v", err)
	}
	if wrote {
		t.Fatal("sweep must not write anything when the singleton does not exist and there is nothing to remove")
	}
}

// TestEnsureExecutionWindowBootstrapCreatesEmptySingleton pins the fix for
// the live-verified collateral-denial defect described in
// ensureExecutionWindowBootstrap's own comment: on a cluster where the
// object has never been created, the bootstrap must create it, empty,
// exactly once.
func TestEnsureExecutionWindowBootstrapCreatesEmptySingleton(t *testing.T) {
	e, dyn := newPolicyControllerTestExecutor()
	creates := 0
	dyn.PrependReactor("create", "executionwindows", func(k8stesting.Action) (bool, runtime.Object, error) {
		creates++
		return false, nil, nil // let the fake client's own default reactor actually perform the create
	})

	ensureExecutionWindowBootstrap(context.Background(), e)

	if creates != 1 {
		t.Fatalf("creates = %d, want exactly 1", creates)
	}
	entries, _, exists, err := e.getExecutionWindowSpec(context.Background())
	if err != nil {
		t.Fatalf("get after bootstrap: %v", err)
	}
	if !exists {
		t.Fatal("bootstrap did not create the singleton")
	}
	if len(entries) != 0 {
		t.Fatalf("entries after bootstrap = %+v, want empty", entries)
	}
}

// TestEnsureExecutionWindowBootstrapNeverOverwritesAnExistingObject guards
// the other half of the fix: an object that already exists — whether empty
// or holding a genuinely open window across an agent restart — must never
// be touched. A bootstrap that unconditionally wrote an empty list back
// would silently drop a real in-flight execution's window.
func TestEnsureExecutionWindowBootstrapNeverOverwritesAnExistingObject(t *testing.T) {
	e, dyn := newPolicyControllerTestExecutor()
	ctx := context.Background()
	if err := e.putExecutionWindowSpec(ctx, nil, "", false); err != nil {
		t.Fatalf("seed empty singleton: %v", err)
	}
	live := storedWindowEntry{
		windowRequestEntry: windowRequestEntry{PlanID: "plan_live", TargetName: "web", TargetUID: "uid-web", FieldPath: "spec.progressDeadlineSeconds"},
		OpenedAt:           time.Now().UTC().Format(time.RFC3339),
	}
	_, rv, exists, err := e.getExecutionWindowSpec(ctx)
	if err != nil {
		t.Fatalf("get after seed: %v", err)
	}
	if err := e.putExecutionWindowSpec(ctx, []storedWindowEntry{live}, rv, exists); err != nil {
		t.Fatalf("seed live entry: %v", err)
	}

	wrote := false
	dyn.PrependReactor("update", "executionwindows", func(k8stesting.Action) (bool, runtime.Object, error) {
		wrote = true
		return false, nil, nil
	})
	dyn.PrependReactor("create", "executionwindows", func(k8stesting.Action) (bool, runtime.Object, error) {
		wrote = true
		return false, nil, nil
	})

	ensureExecutionWindowBootstrap(ctx, e)

	if wrote {
		t.Fatal("bootstrap must never write to an object that already exists")
	}
	entries, _, _, err := e.getExecutionWindowSpec(ctx)
	if err != nil {
		t.Fatalf("get after bootstrap: %v", err)
	}
	if len(entries) != 1 || entries[0].PlanID != "plan_live" {
		t.Fatalf("entries after bootstrap = %+v, want the live entry untouched", entries)
	}
}

// TestEnsureExecutionWindowBootstrapIdleWhenNotConfigured mirrors
// TestRunExecutionWindowSweeperIdleWhenNotConfigured below: client.go starts
// this goroutine unconditionally too, so it must return promptly rather
// than retrying for a minute on a cluster that never mounted the pack.
func TestEnsureExecutionWindowBootstrapIdleWhenNotConfigured(t *testing.T) {
	done := make(chan struct{})
	go func() {
		ensureExecutionWindowBootstrap(context.Background(), nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ensureExecutionWindowBootstrap did not return promptly for an unconfigured executor")
	}

	e2 := NewToolExecutorForTest(nil, nil) // policyDynamic nil: pack not enabled
	done2 := make(chan struct{})
	go func() {
		ensureExecutionWindowBootstrap(context.Background(), e2)
		close(done2)
	}()
	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("ensureExecutionWindowBootstrap did not return promptly when the policy controller pack is not enabled")
	}
}

// TestRunExecutionWindowSweeperIdleWhenNotConfigured proves the sweeper
// returns promptly (rather than looping forever on a nil client) on a
// cluster that never mounted the pack — client.go starts this goroutine
// unconditionally, so it must be inert, not merely harmless-but-hanging.
func TestRunExecutionWindowSweeperIdleWhenNotConfigured(t *testing.T) {
	done := make(chan struct{})
	go func() {
		runExecutionWindowSweeper(context.Background(), nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runExecutionWindowSweeper did not return promptly for an unconfigured executor")
	}
}
