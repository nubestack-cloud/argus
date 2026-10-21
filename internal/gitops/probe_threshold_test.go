package gitops

import "testing"

// depl17ManifestBefore/After mirror BUGS.md 114's real fixture
// (argus-r60-depl17, DEPL-017): a single-container Deployment whose
// readinessProbe.failureThreshold the model's OpenPR plan raised 1 -> 180.
const depl17ManifestBefore = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: depl17-recreate
  namespace: argus-r60-depl17
spec:
  replicas: 3
  strategy:
    type: Recreate
  template:
    spec:
      containers:
      - name: app
        image: busybox
        command: ["sh", "-c", "sleep 900 && touch /tmp/ready && sleep infinity"]
        readinessProbe:
          exec:
            command: ["test", "-f", "/tmp/ready"]
          periodSeconds: 5
          failureThreshold: 1
`

const depl17ManifestAfter = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: depl17-recreate
  namespace: argus-r60-depl17
spec:
  replicas: 3
  strategy:
    type: Recreate
  template:
    spec:
      containers:
      - name: app
        image: busybox
        command: ["sh", "-c", "sleep 900 && touch /tmp/ready && sleep infinity"]
        readinessProbe:
          exec:
            command: ["test", "-f", "/tmp/ready"]
          periodSeconds: 5
          failureThreshold: 180
`

var depl17Object = ObjectRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "argus-r60-depl17", Name: "depl17-recreate"}

func TestDetectReadinessFailureThresholdRaises_FindsTheReportedFixtureShape(t *testing.T) {
	raises := DetectReadinessFailureThresholdRaises([]byte(depl17ManifestBefore), []byte(depl17ManifestAfter), depl17Object)
	if len(raises) != 1 {
		t.Fatalf("expected exactly one raise, got %d: %+v", len(raises), raises)
	}
	r := raises[0]
	if r.ContainerName != "app" || r.OldValue != 1 || r.NewValue != 180 {
		t.Fatalf("unexpected raise: %+v", r)
	}
}

func TestDetectReadinessFailureThresholdRaises_NoChangeIsNotARaise(t *testing.T) {
	if raises := DetectReadinessFailureThresholdRaises([]byte(depl17ManifestBefore), []byte(depl17ManifestBefore), depl17Object); raises != nil {
		t.Fatalf("expected no raises for an unchanged file, got %+v", raises)
	}
}

func TestDetectReadinessFailureThresholdRaises_LoweringIsNotARaise(t *testing.T) {
	// The gate's own confidence in a plan says nothing about direction —
	// only an INCREASE is the shape BUGS.md 114 is about. A plan that
	// lowers failureThreshold is a different, unrelated change and must not
	// trip this detector.
	raises := DetectReadinessFailureThresholdRaises([]byte(depl17ManifestAfter), []byte(depl17ManifestBefore), depl17Object)
	if raises != nil {
		t.Fatalf("expected no raises when the value goes down, got %+v", raises)
	}
}

func TestDetectReadinessFailureThresholdRaises_LivenessProbeIsNotDetected(t *testing.T) {
	// This detector is deliberately scoped to readinessProbe only — see this
	// package's probe_threshold.go header for why the "never succeeded
	// means inert" reasoning does not hold for livenessProbe.
	before := `apiVersion: apps/v1
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
        livenessProbe:
          exec:
            command: ["true"]
          failureThreshold: 1
`
	after := `apiVersion: apps/v1
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
        livenessProbe:
          exec:
            command: ["true"]
          failureThreshold: 180
`
	if raises := DetectReadinessFailureThresholdRaises([]byte(before), []byte(after), depl17Object); raises != nil {
		t.Fatalf("expected livenessProbe to be ignored, got %+v", raises)
	}
}

func TestDetectReadinessFailureThresholdRaises_NoObjectIdentityYieldsNothing(t *testing.T) {
	if raises := DetectReadinessFailureThresholdRaises([]byte(depl17ManifestBefore), []byte(depl17ManifestAfter), ObjectRef{}); raises != nil {
		t.Fatalf("expected no raises with no object identity to anchor to, got %+v", raises)
	}
}

func TestDetectReadinessFailureThresholdRaises_ObjectDeclaredTwiceIsAmbiguousAndSkipped(t *testing.T) {
	twice := depl17ManifestBefore + "---\n" + depl17ManifestBefore
	if raises := DetectReadinessFailureThresholdRaises([]byte(twice), []byte(depl17ManifestAfter), depl17Object); raises != nil {
		t.Fatalf("expected no raises when the object is declared twice (ambiguous), got %+v", raises)
	}
}

func TestDetectReadinessFailureThresholdRaises_UnparseableContentYieldsNothing(t *testing.T) {
	if raises := DetectReadinessFailureThresholdRaises([]byte("not: valid: yaml: at: all: ["), []byte(depl17ManifestAfter), depl17Object); raises != nil {
		t.Fatalf("expected no raises when the original does not parse, got %+v", raises)
	}
}

func TestDetectReadinessFailureThresholdRaises_ContainerAddedHasNothingToCompare(t *testing.T) {
	before := `apiVersion: apps/v1
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
`
	after := `apiVersion: apps/v1
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
      - name: sidecar
        image: busybox
        readinessProbe:
          exec:
            command: ["true"]
          failureThreshold: 180
`
	if raises := DetectReadinessFailureThresholdRaises([]byte(before), []byte(after), depl17Object); raises != nil {
		t.Fatalf("expected a newly-added container's probe to have nothing to compare against, got %+v", raises)
	}
}

func TestDetectReadinessFailureThresholdRaises_NestedUnderJobTemplateIsFound(t *testing.T) {
	// findNamedContainers walks the whole document for any "containers:"
	// sequence rather than a hardcoded path, so a CronJob's
	// spec.jobTemplate.spec.template.spec.containers is found the same way
	// a Deployment's spec.template.spec.containers is.
	before := `apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly
  namespace: argus-r60-depl17
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: worker
            image: busybox
            readinessProbe:
              exec:
                command: ["true"]
              failureThreshold: 1
`
	after := `apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly
  namespace: argus-r60-depl17
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: worker
            image: busybox
            readinessProbe:
              exec:
                command: ["true"]
              failureThreshold: 180
`
	object := ObjectRef{APIVersion: "batch/v1", Kind: "CronJob", Namespace: "argus-r60-depl17", Name: "nightly"}
	raises := DetectReadinessFailureThresholdRaises([]byte(before), []byte(after), object)
	if len(raises) != 1 || raises[0].ContainerName != "worker" || raises[0].OldValue != 1 || raises[0].NewValue != 180 {
		t.Fatalf("expected one raise for worker 1->180, got %+v", raises)
	}
}
