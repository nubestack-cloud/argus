package api

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"argus/internal/gateway"
	"argus/internal/gitops"
)

// --- readinessNeverSucceeded: the mechanical signal at the center of BUGS.md 114 ---

// TestReadinessNeverSucceeded_ReportedFixtureShape reproduces the exact live
// shape BUGS.md 114 was found on: argus-r60-depl17's single-container Pod,
// 900 seconds into a `sleep 900 && touch /tmp/ready` startup delay, whose
// readinessProbe has never once succeeded. Its Ready condition is False and
// has never transitioned since the pod started — this is the case the guard
// exists to catch, and confirms it does.
func TestReadinessNeverSucceeded_ReportedFixtureShape(t *testing.T) {
	start := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
	pod := livePodStatus{
		containerNames:      []string{"app"},
		creationTime:        start,
		startTime:           timePtr(start.Add(1 * time.Second)),
		readyStatus:         "False",
		readyLastTransition: start.Add(1 * time.Second), // set once at creation, never since
	}
	// 900 real seconds have passed (the sleep has not finished), which this
	// signal does not even need to know about — the point is that
	// lastTransitionTime never moved.
	never, known := pod.readinessNeverSucceeded("app")
	if !known {
		t.Fatalf("expected known=true for a single-container pod naming the container asked about")
	}
	if !never {
		t.Fatalf("expected never=true — the reported fixture's container has never passed its readiness probe")
	}
}

// TestReadinessNeverSucceeded_LegitimateFlappingIsNotNever is the negative
// case BUGS.md 114 explicitly asks be left alone: a container that WAS ready
// at some point and is now flapping. Its Ready condition's lastTransitionTime
// is materially later than the pod's start, proving at least one
// False->True->False round trip already happened — raising failureThreshold
// here is a legitimate tolerance increase, not an inert change.
func TestReadinessNeverSucceeded_LegitimateFlappingIsNotNever(t *testing.T) {
	start := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
	pod := livePodStatus{
		containerNames:      []string{"app"},
		creationTime:        start,
		startTime:           timePtr(start.Add(1 * time.Second)),
		readyStatus:         "False",
		readyLastTransition: start.Add(45 * time.Minute), // flipped long after creation
	}
	never, known := pod.readinessNeverSucceeded("app")
	if !known {
		t.Fatalf("expected known=true")
	}
	if never {
		t.Fatalf("expected never=false — a lastTransitionTime this far after creation proves the container was ready at some point")
	}
}

func TestReadinessNeverSucceeded_CurrentlyReadyIsNotNever(t *testing.T) {
	start := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
	pod := livePodStatus{
		containerNames:      []string{"app"},
		creationTime:        start,
		readyStatus:         "True",
		readyLastTransition: start.Add(2 * time.Second),
	}
	never, known := pod.readinessNeverSucceeded("app")
	if !known || never {
		t.Fatalf("readinessNeverSucceeded(currently True) = (never=%v, known=%v), want (false, true)", never, known)
	}
}

func TestReadinessNeverSucceeded_MultiContainerPodIsUnknown(t *testing.T) {
	// Ready/ContainersReady is an aggregate across every container in the
	// pod, and there is no per-container transition history to attribute a
	// False aggregate to one specific container — this must report unknown
	// rather than guess.
	pod := livePodStatus{
		containerNames:      []string{"app", "sidecar"},
		creationTime:        time.Now(),
		readyStatus:         "False",
		readyLastTransition: time.Now(),
	}
	if _, known := pod.readinessNeverSucceeded("app"); known {
		t.Fatalf("expected known=false for a multi-container pod")
	}
}

func TestReadinessNeverSucceeded_WrongContainerNameIsUnknown(t *testing.T) {
	pod := livePodStatus{
		containerNames:      []string{"other"},
		creationTime:        time.Now(),
		readyStatus:         "False",
		readyLastTransition: time.Now(),
	}
	if _, known := pod.readinessNeverSucceeded("app"); known {
		t.Fatalf("expected known=false when the pod's one container is not the one asked about")
	}
}

func TestReadinessNeverSucceeded_NoReadyConditionAtAllIsUnknown(t *testing.T) {
	pod := livePodStatus{containerNames: []string{"app"}}
	if _, known := pod.readinessNeverSucceeded("app"); known {
		t.Fatalf("expected known=false when no Ready/ContainersReady condition was reported")
	}
}

func timePtr(t time.Time) *time.Time { return &t }

// --- decodeLivePodStatus: the describe_resource decoding half ---

func TestDecodeLivePodStatus_PrefersContainersReadyOverReady(t *testing.T) {
	raw := []byte(`{
		"metadata": {"creationTimestamp": "2026-08-28T10:00:00Z"},
		"spec": {"containers": [{"name": "app"}]},
		"status": {
			"startTime": "2026-08-28T10:00:01Z",
			"conditions": [
				{"type": "Ready", "status": "True", "lastTransitionTime": "2026-08-28T10:05:00Z"},
				{"type": "ContainersReady", "status": "False", "lastTransitionTime": "2026-08-28T10:00:01Z"}
			]
		}
	}`)
	got, err := decodeLivePodStatus(raw)
	if err != nil {
		t.Fatalf("decodeLivePodStatus: %v", err)
	}
	if got.readyStatus != "False" {
		t.Fatalf("readyStatus = %q, want ContainersReady's value (\"False\"), not Ready's", got.readyStatus)
	}
	if len(got.containerNames) != 1 || got.containerNames[0] != "app" {
		t.Fatalf("containerNames = %v, want [\"app\"]", got.containerNames)
	}
}

func TestDecodeLivePodStatus_FallsBackToReadyWhenNoContainersReady(t *testing.T) {
	raw := []byte(`{
		"metadata": {"creationTimestamp": "2026-08-28T10:00:00Z"},
		"spec": {"containers": [{"name": "app"}]},
		"status": {
			"conditions": [
				{"type": "Ready", "status": "False", "lastTransitionTime": "2026-08-28T10:00:00Z"}
			]
		}
	}`)
	got, err := decodeLivePodStatus(raw)
	if err != nil {
		t.Fatalf("decodeLivePodStatus: %v", err)
	}
	if got.readyStatus != "False" {
		t.Fatalf("readyStatus = %q, want \"False\" from the Ready condition", got.readyStatus)
	}
}

func TestDecodeLivePodStatus_MalformedJSON(t *testing.T) {
	if _, err := decodeLivePodStatus([]byte("not json")); err == nil {
		t.Fatal("expected an error decoding malformed JSON")
	}
}

// --- matchLabelsSelector ---

func TestMatchLabelsSelector(t *testing.T) {
	spec := map[string]any{
		"selector": map[string]any{
			"matchLabels": map[string]any{"app": "depl17-recreate", "tier": "web"},
		},
	}
	sel, ok := matchLabelsSelector(spec)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if sel != "app=depl17-recreate,tier=web" {
		t.Fatalf("selector = %q, want sorted \"app=depl17-recreate,tier=web\"", sel)
	}
}

func TestMatchLabelsSelector_MissingOrEmptyIsNotOK(t *testing.T) {
	for _, spec := range []map[string]any{
		{},
		{"selector": "not a map"},
		{"selector": map[string]any{}},
		{"selector": map[string]any{"matchLabels": map[string]any{}}},
		{"selector": map[string]any{"matchLabels": "not a map"}},
	} {
		if _, ok := matchLabelsSelector(spec); ok {
			t.Errorf("matchLabelsSelector(%+v) = ok=true, want false", spec)
		}
	}
}

// --- checkReadinessThresholdNotInert's degrade-gracefully path ---

// TestCheckReadinessThresholdNotInert_UnreachableClusterDoesNotBlock exercises
// the wired guard for real, against a genuine *gateway.Gateway with no
// cluster ever connected — the same "not connected" shape
// TestResolveIndeterminateOutcome_ReReadFailureReturnsUnknownNeverFailed
// (remediation_exec_test.go) uses for the identical reason: there is no fake
// tunnel harness in this package, and a disconnected real gateway exercises
// the same code path a flaky one would. The file carries a raise that WOULD
// be refused if live state could confirm it (see probe_threshold_test.go's
// identical fixture) — this asserts that when the live check cannot run at
// all, checkReadinessThresholdNotInert proceeds rather than blocking, per
// this file's own documented "false positives are worse than an occasional
// miss" posture.
func TestCheckReadinessThresholdNotInert_UnreachableClusterDoesNotBlock(t *testing.T) {
	s := &Server{gw: gateway.NewGateway(nil, nil, nil)}
	object := gitops.ObjectRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "argus-r60-depl17", Name: "depl17-recreate"}
	changed := []gitops.FileChange{{
		Path:     "depl17-recreate.yaml",
		Original: []byte(depl17ManifestForGuardTest(1)),
		Content:  []byte(depl17ManifestForGuardTest(180)),
	}}
	if err := s.checkReadinessThresholdNotInert(context.Background(), "cl_not_connected", object, changed); err != nil {
		t.Fatalf("expected no error when the cluster cannot be reached to verify, got: %v", err)
	}
}

func depl17ManifestForGuardTest(failureThreshold int) string {
	b, _ := json.Marshal(failureThreshold) // reuse int -> string formatting, avoids importing fmt just for this
	return `apiVersion: apps/v1
kind: Deployment
metadata:
  name: depl17-recreate
  namespace: argus-r60-depl17
spec:
  template:
    spec:
      containers:
      - name: app
        image: busybox
        readinessProbe:
          exec:
            command: ["test", "-f", "/tmp/ready"]
          failureThreshold: ` + string(b) + "\n"
}
