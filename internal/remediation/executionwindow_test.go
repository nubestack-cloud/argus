package remediation

import "testing"

// TestFieldPathNeedsExecutionWindow pins the Go-side mirror of the standing
// admission policy's four unconditionally-permitted field groups (see this
// file's own header comment for why this table must be kept in lockstep with
// validatingadmissionpolicy.yaml by hand). Each case here corresponds to a
// concrete path fieldpaths.go/patchfield.go actually produces.
func TestFieldPathNeedsExecutionWindow(t *testing.T) {
	cases := []struct {
		name       string
		kind       string
		fieldPath  string
		wantNeeded bool
	}{
		{"deployment replicas", "Deployment", "spec.replicas", false},
		{"deployment pod template annotations", "Deployment", "spec.template.metadata.annotations", false},
		{"deployment container image", "Deployment", "spec.template.spec.containers[web].image", false},
		{"deployment container memory limit", "Deployment", "spec.template.spec.containers[web].resources.limits.memory", false},
		{"deployment container cpu request", "Deployment", "spec.template.spec.containers[web].resources.requests.cpu", false},
		{"deployment progressDeadlineSeconds needs a window", "Deployment", "spec.progressDeadlineSeconds", true},
		{"deployment paused needs a window", "Deployment", "spec.paused", true},
		{"deployment serviceAccountName needs a window (and isn't windowable)", "Deployment", "spec.template.spec.serviceAccountName", true},

		{"statefulset replicas", "StatefulSet", "spec.replicas", false},
		{"statefulset container image is NOT base-allowed (StatefulSet image stays shut)", "StatefulSet", "spec.template.spec.containers[web].image", true},
		{"statefulset revisionHistoryLimit needs a window", "StatefulSet", "spec.revisionHistoryLimit", true},

		{"unknown kind always needs a window", "DaemonSet", "spec.replicas", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FieldPathNeedsExecutionWindow(tc.kind, tc.fieldPath); got != tc.wantNeeded {
				t.Errorf("FieldPathNeedsExecutionWindow(%q, %q) = %v, want %v", tc.kind, tc.fieldPath, got, tc.wantNeeded)
			}
		})
	}
}

// TestFieldPathIsWindowable pins the closed set of fields this feature's
// first cut actually wired a CEL clause for — anything else needing a
// window must be refused before a tunnel round trip is spent on it.
func TestFieldPathIsWindowable(t *testing.T) {
	cases := []struct {
		kind, fieldPath string
		want            bool
	}{
		{"Deployment", "spec.progressDeadlineSeconds", true},
		{"Deployment", "spec.template.spec.serviceAccountName", false},
		{"StatefulSet", "spec.revisionHistoryLimit", true},
		{"StatefulSet", "spec.progressDeadlineSeconds", false}, // StatefulSet has no such field
		{"Service", "spec.ports.0.targetPort", false},
	}
	for _, tc := range cases {
		if got := FieldPathIsWindowable(tc.kind, tc.fieldPath); got != tc.want {
			t.Errorf("FieldPathIsWindowable(%q, %q) = %v, want %v", tc.kind, tc.fieldPath, got, tc.want)
		}
	}
}

func TestFieldPathsNeedingExecutionWindow(t *testing.T) {
	paths := []string{
		"spec.replicas",
		"spec.progressDeadlineSeconds",
		"spec.template.metadata.annotations",
	}
	got := FieldPathsNeedingExecutionWindow("Deployment", paths)
	if len(got) != 1 || got[0] != "spec.progressDeadlineSeconds" {
		t.Fatalf("FieldPathsNeedingExecutionWindow = %v, want exactly [spec.progressDeadlineSeconds]", got)
	}
}

func TestGVKKind(t *testing.T) {
	if got := GVKKind("apps/v1/Deployment"); got != "Deployment" {
		t.Errorf("GVKKind(apps/v1/Deployment) = %q, want Deployment", got)
	}
	if got := GVKKind("Deployment"); got != "Deployment" {
		t.Errorf("GVKKind(Deployment) = %q, want Deployment (no slash: pass through)", got)
	}
}
