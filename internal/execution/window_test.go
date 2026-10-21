package execution

import (
	"errors"
	"testing"
)

// TestOpenExecutionWindowCoreAlwaysReturnsAWorkingCloser is this feature's
// most safety-critical unit test: it pins the exact contract
// ExecuteApprovedPlan's `defer closeWindow()` relies on for BACKLOG.md F14's
// "the re-lock must always happen" guarantee. See window.go's own
// doc comment on openExecutionWindowCore for the contract being tested.
func TestOpenExecutionWindowCoreAlwaysReturnsAWorkingCloser(t *testing.T) {
	t.Run("zero entries: open is never called, closer is a safe no-op", func(t *testing.T) {
		openCalled := false
		closeCalled := 0
		closer, err := openExecutionWindowCore(nil,
			func() error { openCalled = true; return nil },
			func() { closeCalled++ })
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if openCalled {
			t.Fatal("open must never be called when there is nothing to widen — every ScaleDeployment/RestartPod/PatchResourceLimits/RevertContainerImage plan must pay nothing for this mechanism")
		}
		closer()
		closer() // calling twice must still be safe
		if closeCalled != 0 {
			t.Fatalf("close must never be called when open never ran, got %d calls", closeCalled)
		}
	})

	t.Run("open fails: no-op closer, error surfaces, close is never attempted", func(t *testing.T) {
		wantErr := errors.New("tunnel unreachable")
		closeCalled := 0
		closer, err := openExecutionWindowCore([]executionWindowEntry{{PlanID: "p1"}},
			func() error { return wantErr },
			func() { closeCalled++ })
		if !errors.Is(err, wantErr) {
			t.Fatalf("got err %v, want %v", err, wantErr)
		}
		closer()
		if closeCalled != 0 {
			t.Fatalf("close must not be attempted for a window that never actually opened, got %d calls", closeCalled)
		}
	})

	t.Run("open succeeds: closer calls close exactly once, even if invoked repeatedly", func(t *testing.T) {
		closeCalled := 0
		closer, err := openExecutionWindowCore([]executionWindowEntry{{PlanID: "p1"}},
			func() error { return nil },
			func() { closeCalled++ })
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if closeCalled != 0 {
			t.Fatalf("close must not run before the closer is invoked, got %d calls", closeCalled)
		}
		// Simulates ExecuteApprovedPlan's own `defer closeWindow()` firing —
		// on the success path, on a PreparePlan failure, on a tunnel-call
		// failure, or (in Go) on a panic unwinding through the deferred
		// call. Whatever the reason this runs, it must close exactly once.
		closer()
		closer()
		closer()
		if closeCalled != 1 {
			t.Fatalf("closeCalled = %d, want exactly 1 — a window must be closed exactly once no matter how many times (or from how many code paths) the closer is invoked", closeCalled)
		}
	})
}

// TestGvkGroup pins gvkGroup's parsing of this codebase's GVK wire
// convention, including the core-group ("v1/ConfigMap") case that has no
// group segment at all.
func TestGvkGroup(t *testing.T) {
	cases := map[string]string{
		"apps/v1/Deployment": "apps",
		"v1/Pod":             "", // core group
		"malformed":          "",
	}
	for gvk, want := range cases {
		if got := gvkGroup(gvk); got != want {
			t.Errorf("gvkGroup(%q) = %q, want %q", gvk, got, want)
		}
	}
}
