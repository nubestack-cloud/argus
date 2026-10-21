package api

// Tests for BACKLOG.md F27's mechanical guard: stepLooksRunnable/
// hasRunnableNextStep's heuristic, pure and DB-free, live here.
// TestFlagMissingRunnableNextStep_* (next_steps_guard_db_test.go) covers the
// real timeline.Record side effect against a live Postgres.

import "testing"

func TestStepLooksRunnable(t *testing.T) {
	for _, tc := range []struct {
		name string
		step string
		want bool
	}{
		{
			name: "real kubectl command with namespace and object",
			step: "kubectl -n payments-prod scale deployment/checkout-api --replicas=3",
			want: true,
		},
		{
			name: "real git command",
			step: "git -C /repo revert abc1234",
			want: true,
		},
		{
			name: "real helm command",
			step: "helm upgrade checkout-api ./charts/checkout-api -n payments-prod --set replicaCount=3",
			want: true,
		},
		{
			name: "prose advice with no command at all",
			step: "Scale the deployment to an appropriate number of replicas once traffic recovers.",
			want: false,
		},
		{
			name: "field-path-and-value description, not a command",
			step: "Set spec.template.spec.containers[0].readinessProbe.initialDelaySeconds to 30 on deployment/checkout-api in payments-prod (currently 2)",
			want: false,
		},
		{
			name: "kubectl command with a placeholder namespace",
			step: "kubectl -n <namespace> scale deployment/checkout-api --replicas=3",
			want: false,
		},
		{
			name: "kubectl command with a placeholder object name",
			step: "kubectl -n payments-prod scale deployment/<name> --replicas=3",
			want: false,
		},
		{
			name: "mentions kubectl descriptively but is not itself an invocation",
			step: "Check whether kubectl access is configured for this cluster before attempting a manual fix.",
			want: false,
		},
		{
			name: "empty string",
			step: "",
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := stepLooksRunnable(tc.step); got != tc.want {
				t.Errorf("stepLooksRunnable(%q) = %v, want %v", tc.step, got, tc.want)
			}
		})
	}
}

func TestHasRunnableNextStep(t *testing.T) {
	if hasRunnableNextStep(nil) {
		t.Error("hasRunnableNextStep(nil) = true, want false")
	}
	if hasRunnableNextStep([]string{}) {
		t.Error("hasRunnableNextStep([]string{}) = true, want false")
	}
	if hasRunnableNextStep([]string{"Restart the pod once the underlying disk pressure clears."}) {
		t.Error("hasRunnableNextStep with only prose advice = true, want false")
	}
	if !hasRunnableNextStep([]string{
		"Restart the pod once the underlying disk pressure clears.",
		"kubectl -n payments-prod delete pod checkout-api-7f9c8-abcde",
	}) {
		t.Error("hasRunnableNextStep with one real command among prose steps = false, want true — only ONE runnable entry is required")
	}
}
