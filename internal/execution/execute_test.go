package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"argus/internal/gateway"
	"argus/internal/objdiff"
	"argus/internal/remediation"

	"argus/internal/authz"
)

func TestGvkKind(t *testing.T) {
	cases := map[string]string{
		"apps/v1/Deployment": "Deployment",
		"v1/Pod":             "Pod",
		"Deployment":         "Deployment",
	}
	for gvk, want := range cases {
		if got := gvkKind(gvk); got != want {
			t.Errorf("gvkKind(%q) = %q, want %q", gvk, got, want)
		}
	}
}

func TestExecutionToolForAction(t *testing.T) {
	if tool, ok := ToolForAction(remediation.ActionScaleDeployment); !ok || tool != "scale_deployment" {
		t.Errorf("ToolForAction(ScaleDeployment) = (%q, %v), want (\"scale_deployment\", true)", tool, ok)
	}
	if tool, ok := ToolForAction(remediation.ActionRestartPod); !ok || tool != "restart_pod" {
		t.Errorf("ToolForAction(RestartPod) = (%q, %v), want (\"restart_pod\", true)", tool, ok)
	}
	if tool, ok := ToolForAction(remediation.ActionPatchResourceLimits); !ok || tool != "patch_resource_limits" {
		t.Errorf("ToolForAction(PatchResourceLimits) = (%q, %v), want (\"patch_resource_limits\", true)", tool, ok)
	}
	if tool, ok := ToolForAction(remediation.ActionRevertContainerImage); !ok || tool != "revert_container_image" {
		t.Errorf("ToolForAction(RevertContainerImage) = (%q, %v), want (\"revert_container_image\", true)", tool, ok)
	}
	if tool, ok := ToolForAction(remediation.ActionPatchField); !ok || tool != "patch_field" {
		t.Errorf("ToolForAction(PatchField) = (%q, %v), want (\"patch_field\", true) — BUGS.md 78", tool, ok)
	}
	if _, ok := ToolForAction(remediation.ActionOpenPR); ok {
		t.Errorf("ToolForAction(OpenPR) = ok, want !ok — OpenPR execution is explicitly out of scope")
	}
}

// --- PatchField: live-value read and rollback capture (BUGS.md 78) ---------

func TestReadLiveFieldValue(t *testing.T) {
	live := json.RawMessage(`{
		"spec": {
			"ports": [{"targetPort": 8080}, {"targetPort": "http"}],
			"selector": {"app": "api"}
		}
	}`)

	cases := []struct {
		name      string
		fieldPath string
		want      any
		wantFound bool
	}{
		{"numeric value through a list index", "spec.ports[0].targetPort", float64(8080), true},
		{"string value through a list index", "spec.ports[1].targetPort", "http", true},
		{"map key whose name is not known in advance", "spec.selector.app", "api", true},
		{"absent field", "spec.selector.missing", nil, false},
		{"absent list index", "spec.ports[5].targetPort", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, found, err := readLiveFieldValue(live, c.fieldPath)
			if err != nil {
				t.Fatalf("readLiveFieldValue(%q): %v", c.fieldPath, err)
			}
			if found != c.wantFound {
				t.Fatalf("readLiveFieldValue(%q) found = %v, want %v", c.fieldPath, found, c.wantFound)
			}
			if found && got != c.want {
				t.Errorf("readLiveFieldValue(%q) = %v, want %v", c.fieldPath, got, c.want)
			}
		})
	}
}

// TestReadLiveFieldValue_FailsClosedOnAShapeMismatch mirrors
// findPodTemplateContainer's own "a container entry that isn't an object is an
// error, never a silent skip" reasoning: addressing a list with a non-numeric
// segment, or indexing into a scalar, means this function does not understand
// the object's shape, and that must surface as an error rather than as
// "not found" — the two are different facts (the field only reads as absent
// when the walk understood every step and simply didn't find it there).
func TestReadLiveFieldValue_FailsClosedOnAShapeMismatch(t *testing.T) {
	live := json.RawMessage(`{"spec": {"ports": [{"targetPort": 8080}], "replicas": 3}}`)

	if _, _, err := readLiveFieldValue(live, "spec.ports.notAnIndex.targetPort"); err == nil {
		t.Error("readLiveFieldValue: want an error addressing a list with a non-numeric segment, got nil")
	}
	if _, _, err := readLiveFieldValue(live, "spec.replicas.nested"); err == nil {
		t.Error("readLiveFieldValue: want an error indexing into a scalar, got nil")
	}
}

func TestRollbackForPatchField_CapturesTheLiveValue(t *testing.T) {
	rollback, err := rollbackForPatchField("spec.ports[0].targetPort", "8080")
	if err != nil {
		t.Fatalf("rollbackForPatchField: %v", err)
	}
	if rollback.ActionType != remediation.ActionPatchField {
		t.Errorf("rollback action type = %q, want PatchField", rollback.ActionType)
	}
	var restore remediation.PatchFieldParams
	if err := json.Unmarshal(rollback.Params, &restore); err != nil {
		t.Fatalf("decode rollback params: %v", err)
	}
	want := remediation.PatchFieldParams{FieldPath: "spec.ports[0].targetPort", NewValue: "8080"}
	if restore != want {
		t.Errorf("rollback params = %+v, want %+v", restore, want)
	}
	if err := restore.Validate(); err != nil {
		t.Errorf("rollback params do not validate as a plan: %v", err)
	}
	if rollback.Description == "" {
		t.Error("rollback has no human-readable description")
	}
}

// TestRollbackForPatchField_RefusesWhenTheUndoWouldBeInvalid: PatchField
// cannot express "clear this field" (PatchFieldParams.Validate refuses an
// empty NewValue) — the state a genuinely absent live value would produce —
// so building a rollback from one must fail rather than sign an
// uncommittable plan into the envelope.
func TestRollbackForPatchField_RefusesWhenTheUndoWouldBeInvalid(t *testing.T) {
	if _, err := rollbackForPatchField("spec.ports[0].targetPort", ""); err == nil {
		t.Fatal("rollbackForPatchField(..., \"\") = nil error, want a refusal — PatchField cannot undo into an empty value")
	}
}

// --- StructuredPatch: rollback generalized to N operations ------------------

// TestRollbackForStructuredPatch_CapturesAllLiveValues is F14's own note made
// concrete: BACKLOG.md F11 "makes rollback mechanically derivable per path."
// One CompensatingAction reversing every operation, built purely from the
// live values PreparePlan's ActionStructuredPatch branch already read — no
// per-field-name special-casing anywhere in this function.
func TestRollbackForStructuredPatch_CapturesAllLiveValues(t *testing.T) {
	ops := []remediation.StructuredPatchOp{
		{FieldPath: "spec.progressDeadlineSeconds", NewValue: "900"},
		{FieldPath: "spec.ports[0].targetPort", NewValue: "9090"},
	}
	currentValues := map[string]string{
		remediation.NormaliseFieldPath("spec.progressDeadlineSeconds"): "600",
		remediation.NormaliseFieldPath("spec.ports[0].targetPort"):     "8080",
	}

	rollback, err := rollbackForStructuredPatch(ops, currentValues)
	if err != nil {
		t.Fatalf("rollbackForStructuredPatch: %v", err)
	}
	if rollback.ActionType != remediation.ActionStructuredPatch {
		t.Errorf("rollback action type = %q, want StructuredPatch", rollback.ActionType)
	}

	var restore remediation.StructuredPatchParams
	if err := json.Unmarshal(rollback.Params, &restore); err != nil {
		t.Fatalf("decode rollback params: %v", err)
	}
	want := remediation.StructuredPatchParams{Ops: []remediation.StructuredPatchOp{
		{FieldPath: "spec.progressDeadlineSeconds", NewValue: "600"},
		{FieldPath: "spec.ports[0].targetPort", NewValue: "8080"},
	}}
	if len(restore.Ops) != len(want.Ops) {
		t.Fatalf("rollback params = %+v, want %+v", restore, want)
	}
	for i := range want.Ops {
		if restore.Ops[i] != want.Ops[i] {
			t.Errorf("rollback op %d = %+v, want %+v", i, restore.Ops[i], want.Ops[i])
		}
	}
	if err := restore.Validate(); err != nil {
		t.Errorf("rollback params do not validate as a plan: %v", err)
	}
	if rollback.Description == "" {
		t.Error("rollback has no human-readable description")
	}
	for _, op := range want.Ops {
		if !strings.Contains(rollback.Description, op.FieldPath) || !strings.Contains(rollback.Description, op.NewValue) {
			t.Errorf("description %q does not mention restoring %s to %q", rollback.Description, op.FieldPath, op.NewValue)
		}
	}
}

// TestRollbackForStructuredPatch_RefusesWhenAValueWasNeverCaptured is the
// programming-error guard: building a rollback for an operation this
// function was never handed a live value for must fail loudly rather than
// sign a partial (and therefore silently incomplete) undo.
func TestRollbackForStructuredPatch_RefusesWhenAValueWasNeverCaptured(t *testing.T) {
	ops := []remediation.StructuredPatchOp{
		{FieldPath: "spec.progressDeadlineSeconds", NewValue: "900"},
		{FieldPath: "spec.ports[0].targetPort", NewValue: "9090"},
	}
	// Only one of the two operations has a captured value.
	currentValues := map[string]string{
		remediation.NormaliseFieldPath("spec.progressDeadlineSeconds"): "600",
	}
	if _, err := rollbackForStructuredPatch(ops, currentValues); err == nil {
		t.Fatal("rollbackForStructuredPatch = nil error, want a refusal — one operation has no captured live value to restore")
	}
}

// TestRollbackForStructuredPatch_RefusesWhenTheUndoWouldBeInvalid mirrors
// PatchField's own equivalent test: StructuredPatch cannot express "clear
// this field" either (PatchFieldParams.Validate, reused per-operation, refuses
// an empty NewValue), so a rollback built from a captured empty value must
// fail rather than sign an uncommittable plan into the envelope.
func TestRollbackForStructuredPatch_RefusesWhenTheUndoWouldBeInvalid(t *testing.T) {
	ops := []remediation.StructuredPatchOp{{FieldPath: "spec.ports[0].targetPort", NewValue: "9090"}}
	currentValues := map[string]string{remediation.NormaliseFieldPath("spec.ports[0].targetPort"): ""}
	if _, err := rollbackForStructuredPatch(ops, currentValues); err == nil {
		t.Fatal("rollbackForStructuredPatch(..., \"\") = nil error, want a refusal — StructuredPatch cannot undo into an empty value")
	}
}

// --- AnnotateResource/LabelResource: literal-key metadata reads and rollback

// TestReadLiveMetadataValue exercises the direct-map-lookup reader
// PreparePlan uses instead of readLiveFieldValue for these two action
// types, specifically BECAUSE the key can contain "." and "/" — the exact
// shape readLiveFieldValue's dot-splitting would mis-handle.
func TestReadLiveMetadataValue(t *testing.T) {
	live := json.RawMessage(`{
		"metadata": {
			"annotations": {"argus.io/incident-id": "inc_01test", "kubectl.kubernetes.io/last-applied-configuration": "{}"},
			"labels": {"app": "web"}
		}
	}`)

	cases := []struct {
		name      string
		mapName   string
		key       string
		want      string
		wantFound bool
	}{
		{"annotation key with a dot and a slash", "annotations", "argus.io/incident-id", "inc_01test", true},
		{"another real annotation key with dots", "annotations", "kubectl.kubernetes.io/last-applied-configuration", "{}", true},
		{"absent annotation key", "annotations", "argus.io/last-remediated-at", "", false},
		{"label key", "labels", "app", "web", true},
		{"absent label key", "labels", "argus.io/remediated", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, found, err := readLiveMetadataValue(live, c.mapName, c.key)
			if err != nil {
				t.Fatalf("readLiveMetadataValue(%q, %q): %v", c.mapName, c.key, err)
			}
			if found != c.wantFound {
				t.Fatalf("readLiveMetadataValue(%q, %q) found = %v, want %v", c.mapName, c.key, found, c.wantFound)
			}
			if found && got != c.want {
				t.Errorf("readLiveMetadataValue(%q, %q) = %q, want %q", c.mapName, c.key, got, c.want)
			}
		})
	}
}

// TestReadLiveMetadataValue_NoMetadataAtAll is the common case for a
// freshly-created object: neither map exists, and that must read as "not
// found", never as an error — the same has()-guard discipline this
// codebase's admission-policy CEL applies for the identical reason.
func TestReadLiveMetadataValue_NoMetadataAtAll(t *testing.T) {
	live := json.RawMessage(`{"spec": {"replicas": 1}}`)
	_, found, err := readLiveMetadataValue(live, "annotations", "argus.io/incident-id")
	if err != nil {
		t.Fatalf("readLiveMetadataValue: %v", err)
	}
	if found {
		t.Error("found = true on an object with no metadata.annotations at all")
	}
}

// TestAnnotateOrLabelKeyValue is the CHECKED type assertion every other
// PreparePlan branch also carries — a zero-value/wrong-type params struct
// must be reported, never silently read as an empty-string key.
func TestAnnotateOrLabelKeyValue(t *testing.T) {
	plan := remediation.RemediationPlan{
		ActionType: remediation.ActionAnnotateResource,
		Params:     remediation.AnnotateResourceParams{Key: "argus.io/incident-id", Value: "inc_01test"},
	}
	key, value, err := annotateOrLabelKeyValue(plan)
	if err != nil {
		t.Fatalf("annotateOrLabelKeyValue: %v", err)
	}
	if key != "argus.io/incident-id" || value != "inc_01test" {
		t.Errorf("got (%q, %q), want (%q, %q)", key, value, "argus.io/incident-id", "inc_01test")
	}

	wrongType := remediation.RemediationPlan{ActionType: remediation.ActionAnnotateResource, Params: remediation.LabelResourceParams{Key: "x", Value: "y"}}
	if _, _, err := annotateOrLabelKeyValue(wrongType); err == nil {
		t.Error("annotateOrLabelKeyValue accepted params of the wrong concrete type")
	}
}

// TestRollbackForAnnotateOrLabel_CapturesTheLiveValue mirrors
// TestRollbackForPatchField_CapturesTheLiveValue's structure exactly.
func TestRollbackForAnnotateOrLabel_CapturesTheLiveValue(t *testing.T) {
	rollback, err := rollbackForAnnotateOrLabel(remediation.ActionAnnotateResource, "argus.io/incident-id", "inc_00old")
	if err != nil {
		t.Fatalf("rollbackForAnnotateOrLabel: %v", err)
	}
	if rollback.ActionType != remediation.ActionAnnotateResource {
		t.Errorf("rollback action type = %q, want AnnotateResource", rollback.ActionType)
	}
	var restore remediation.AnnotateResourceParams
	if err := json.Unmarshal(rollback.Params, &restore); err != nil {
		t.Fatalf("decode rollback params: %v", err)
	}
	want := remediation.AnnotateResourceParams{Key: "argus.io/incident-id", Value: "inc_00old"}
	if restore != want {
		t.Errorf("rollback params = %+v, want %+v", restore, want)
	}
	if rollback.Description == "" {
		t.Error("rollback has no human-readable description")
	}
}

// TestRollbackForAnnotateOrLabel_RefusesWhenTheUndoWouldBeInvalid mirrors
// PatchField's own equivalent: a live value that cannot itself pass
// Validate (here, an empty string — the live value's own shape-check
// failure mode, since an absent key never reaches this function at all;
// see PreparePlan's own branch) must refuse rather than sign an
// uncommittable rollback into the envelope.
func TestRollbackForAnnotateOrLabel_RefusesWhenTheUndoWouldBeInvalid(t *testing.T) {
	if _, err := rollbackForAnnotateOrLabel(remediation.ActionAnnotateResource, "argus.io/incident-id", ""); err == nil {
		t.Fatal("rollbackForAnnotateOrLabel(..., \"\") = nil error, want a refusal")
	}
	// LabelResource's rollback goes through the stricter label-value grammar
	// too — a live value that happens to violate it (should not occur in
	// practice, since it would mean a human or another controller set an
	// invalid label, but the function must still fail closed) is refused
	// the same way.
	if _, err := rollbackForAnnotateOrLabel(remediation.ActionLabelResource, "argus.io/remediated", "not a valid label value!"); err == nil {
		t.Fatal("rollbackForAnnotateOrLabel with an invalid label value = nil error, want a refusal")
	}
}

// --- PatchResourceLimits: live-state bounds and rollback capture ------------

// workloadSpec builds the `spec` map fetchPrecondition returns for a
// two-container workload — the same shape describe_resource produces, since
// that is where the real one comes from.
func workloadSpec(containers ...map[string]any) map[string]any {
	items := make([]any, 0, len(containers))
	for _, c := range containers {
		items = append(items, c)
	}
	return map[string]any{
		"template": map[string]any{
			"spec": map[string]any{"containers": items},
		},
	}
}

func testContainer(name, memLimit, memRequest, cpuLimit, cpuRequest string) map[string]any {
	limits := map[string]any{}
	requests := map[string]any{}
	if memLimit != "" {
		limits["memory"] = memLimit
	}
	if cpuLimit != "" {
		limits["cpu"] = cpuLimit
	}
	if memRequest != "" {
		requests["memory"] = memRequest
	}
	if cpuRequest != "" {
		requests["cpu"] = cpuRequest
	}
	return map[string]any{
		"name":      name,
		"image":     "registry.example.com/" + name + ":1.0.0",
		"resources": map[string]any{"limits": limits, "requests": requests},
	}
}

func TestLiveContainerResources(t *testing.T) {
	spec := workloadSpec(
		testContainer("app", "32Mi", "32Mi", "500m", "100m"),
		testContainer("sidecar", "64Mi", "", "", ""),
	)

	live, err := liveContainerResources(spec, "app")
	if err != nil {
		t.Fatalf("liveContainerResources(app) = %v, want nil", err)
	}
	want := containerResources{MemoryLimit: "32Mi", MemoryRequest: "32Mi", CPULimit: "500m", CPURequest: "100m"}
	if live != want {
		t.Errorf("live = %+v, want %+v", live, want)
	}

	// An unset field comes back empty, distinctly from zero — the state that
	// makes checkResourceLimitsBound refuse to introduce one.
	sidecar, err := liveContainerResources(spec, "sidecar")
	if err != nil {
		t.Fatalf("liveContainerResources(sidecar) = %v, want nil", err)
	}
	if sidecar.MemoryLimit != "64Mi" || sidecar.CPULimit != "" || sidecar.MemoryRequest != "" {
		t.Errorf("sidecar = %+v, want only MemoryLimit set", sidecar)
	}
}

// TestLiveContainerResources_FailsClosed covers every shape this must refuse
// rather than interpret. The unknown-container case is the one that matters
// most: a strategic-merge patch keyed on an unmatched container name adds a
// container instead of failing.
func TestLiveContainerResources_FailsClosed(t *testing.T) {
	cases := []struct {
		name      string
		spec      map[string]any
		container string
	}{
		{"no container by that name", workloadSpec(testContainer("app", "32Mi", "", "", "")), "typo"},
		{"no spec.template", map[string]any{"replicas": 2}, "app"},
		{"no spec.template.spec", map[string]any{"template": map[string]any{}}, "app"},
		{"no containers list", map[string]any{"template": map[string]any{"spec": map[string]any{}}}, "app"},
		{"empty containers list", workloadSpec(), "app"},
		{"malformed container entry", map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{"not-an-object"}}}}, "app"},
		{"non-string quantity", map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{
			map[string]any{"name": "app", "resources": map[string]any{"limits": map[string]any{"memory": 33554432}}},
		}}}}, "app"},
	}
	for _, c := range cases {
		if _, err := liveContainerResources(c.spec, c.container); err == nil {
			t.Errorf("%s: liveContainerResources() = nil error, want a refusal", c.name)
		}
	}
}

func TestCheckResourceLimitsBound(t *testing.T) {
	live := containerResources{MemoryLimit: "32Mi", MemoryRequest: "32Mi", CPULimit: "500m", CPURequest: "100m"}

	cases := []struct {
		name    string
		live    containerResources
		params  remediation.PatchResourceLimitsParams
		wantErr bool
	}{
		{
			name:   "raise the memory limit — the fault this action exists for",
			live:   live,
			params: remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: "256Mi"},
		},
		{
			name:   "raise limit and request together within 4x",
			live:   live,
			params: remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: "256Mi", MemoryRequest: "128Mi"},
		},
		{
			name:   "hold the memory limit exactly where it is",
			live:   live,
			params: remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: "32Mi"},
		},
		{
			name:   "lower the cpu limit — throttling, not death, so allowed",
			live:   live,
			params: remediation.PatchResourceLimitsParams{Container: "app", CPULimit: "200m"},
		},
		{
			name:    "lower the memory limit",
			live:    live,
			params:  remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: "16Mi"},
			wantErr: true,
		},
		{
			name:    "raise the memory request more than 4x",
			live:    live,
			params:  remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: "1Gi", MemoryRequest: "256Mi"},
			wantErr: true,
		},
		{
			name:    "raise the request above the limit already in force",
			live:    live,
			params:  remediation.PatchResourceLimitsParams{Container: "app", MemoryRequest: "64Mi"},
			wantErr: true,
		},
		{
			name:    "lower the cpu limit below the live cpu request",
			live:    live,
			params:  remediation.PatchResourceLimitsParams{Container: "app", CPULimit: "50m"},
			wantErr: true,
		},
		{
			name:    "introduce a limit that is not set today",
			live:    containerResources{MemoryRequest: "32Mi"},
			params:  remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: "256Mi"},
			wantErr: true,
		},
		{
			name:    "live value is unreadable",
			live:    containerResources{MemoryLimit: "thirty-two megs"},
			params:  remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: "256Mi"},
			wantErr: true,
		},
	}
	for _, c := range cases {
		err := checkResourceLimitsBound(c.live, c.params, false)
		if c.wantErr && err == nil {
			t.Errorf("%s: checkResourceLimitsBound() = nil, want an error", c.name)
		}
		if !c.wantErr && err != nil {
			t.Errorf("%s: checkResourceLimitsBound() = %v, want nil", c.name, err)
		}
	}
}

// TestCheckResourceLimitsBound_RequestCeilingIsExactForMillicores guards the
// Quantity.Value() rounding trap: Value() on "100m" returns 1 (whole cores,
// rounded up), which would have made the 4x request ceiling read as "4 cores"
// for every small CPU request and let a 40x increase through.
func TestCheckResourceLimitsBound_RequestCeilingIsExactForMillicores(t *testing.T) {
	live := containerResources{CPULimit: "4", CPURequest: "100m"}

	ok := remediation.PatchResourceLimitsParams{Container: "app", CPURequest: "400m"} // exactly 4x
	if err := checkResourceLimitsBound(live, ok, false); err != nil {
		t.Errorf("cpuRequest 100m -> 400m: got %v, want nil (exactly at the 4x ceiling)", err)
	}
	tooBig := remediation.PatchResourceLimitsParams{Container: "app", CPURequest: "500m"} // 5x
	if err := checkResourceLimitsBound(live, tooBig, false); err == nil {
		t.Error("cpuRequest 100m -> 500m: got nil, want an error (5x is above the ceiling)")
	}
}

// TestCheckResourceLimitsBoundWrapsItsSentinel is BUGS.md 95's confirmed,
// live-reproduced case: on rke2, a memoryRequest 7.5x the container's live
// value was correctly refused by this function inside PreparePlan, entirely
// before ExecuteApprovedPlan ever contacted the agent — yet
// handleApproveIncident's dispatch had no sentinel to catch it and fell
// through to the generic 502 remediation-execution-failed, indistinguishable
// from a real, attempted-and-failed cluster execution. Every refusal path
// this function has (introducing a field, lowering a memory limit, the
// request ceiling, request-over-limit) must wrap ErrResourceLimitsBoundRefused
// so that dispatch (internal/api/approvals.go) can tell them apart.
func TestCheckResourceLimitsBoundWrapsItsSentinel(t *testing.T) {
	live := containerResources{MemoryLimit: "1Gi", MemoryRequest: "20Mi"}
	// The exact shape BUGS.md 95 reproduced: a memoryRequest far more than
	// maxRequestIncreaseFactor times the live 20Mi request.
	tooBig := remediation.PatchResourceLimitsParams{Container: "app", MemoryRequest: "150Mi"}
	err := checkResourceLimitsBound(live, tooBig, false)
	if err == nil {
		t.Fatal("checkResourceLimitsBound(20Mi -> 150Mi) = nil, want a refusal")
	}
	if !errors.Is(err, ErrResourceLimitsBoundRefused) {
		t.Errorf("refusal %v does not wrap ErrResourceLimitsBoundRefused — handleApproveIncident's dispatch would misclassify this as a 502", err)
	}

	// checkRequestUnderLimit's own refusal, reached through
	// checkResourceLimitsBound rather than called directly — the sentinel
	// wrap lives at the checkResourceLimitsBound call site precisely so this
	// path is covered too, without checkRequestUnderLimit needing to know
	// about it.
	overLimit := containerResources{MemoryLimit: "32Mi", MemoryRequest: "16Mi"}
	overLimitPlan := remediation.PatchResourceLimitsParams{Container: "app", MemoryRequest: "64Mi"}
	err = checkResourceLimitsBound(overLimit, overLimitPlan, false)
	if err == nil {
		t.Fatal("checkResourceLimitsBound(request above limit) = nil, want a refusal")
	}
	if !errors.Is(err, ErrResourceLimitsBoundRefused) {
		t.Errorf("checkRequestUnderLimit refusal %v does not wrap ErrResourceLimitsBoundRefused", err)
	}
}

// TestRollbackForResourceLimits_CapturesExactlyWhatIsOverwritten: the undo
// must restore the fields this plan changes, to the values they held, and
// mention nothing else — a rollback that re-asserted untouched fields would
// revert unrelated concurrent changes when applied.
func TestRollbackForResourceLimits_CapturesExactlyWhatIsOverwritten(t *testing.T) {
	live := containerResources{MemoryLimit: "32Mi", MemoryRequest: "32Mi", CPULimit: "500m", CPURequest: "100m"}
	params := remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: "256Mi", CPURequest: "200m"}

	rollback, err := rollbackForResourceLimits("app", live, params)
	if err != nil {
		t.Fatalf("rollbackForResourceLimits: %v", err)
	}
	if rollback.ActionType != remediation.ActionPatchResourceLimits {
		t.Errorf("rollback action type = %q, want PatchResourceLimits", rollback.ActionType)
	}
	var restore remediation.PatchResourceLimitsParams
	if err := json.Unmarshal(rollback.Params, &restore); err != nil {
		t.Fatalf("decode rollback params: %v", err)
	}
	want := remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: "32Mi", CPURequest: "100m"}
	if restore != want {
		t.Errorf("rollback params = %+v, want %+v (only the overwritten fields, at their live values)", restore, want)
	}
	// The rollback must itself be a valid plan of the same action type —
	// otherwise the change is one this mechanism could not undo.
	if err := restore.Validate(); err != nil {
		t.Errorf("rollback params do not validate as a plan: %v", err)
	}
	if rollback.Description == "" {
		t.Error("rollback has no human-readable description")
	}
}

// TestRollbackForResourceLimits_RefusesWhenTheUndoWouldBeInvalid: a captured
// undo that is not a well-formed plan is refused before the change is made
// rather than discovered afterwards.
//
// Rewritten 2026-09-17 (T5). This test used to assert the opposite of its
// first case: that a live 4Mi memory limit made the whole change unexecutable,
// because the undo restoring 4Mi failed the action's 16Mi absolute minimum.
// Walking the approval path live showed what that costs — a container
// OOMKilled under a 4Mi limit is the canonical thing this action exists to
// fix, and ARGUS refused to fix it, with a 502 that read as a cluster failure.
// Two things make the old position untenable rather than merely inconvenient:
// the minimum is a rule about what ARGUS may PROPOSE and an undo proposes
// nothing (remediation.PatchResourceLimitsParams.ValidateRestore), and the
// rationale it was refused on — "this change could not be undone" — was
// already false for every memory-limit raise regardless of the value, because
// checkResourceLimitsBound rule 2 refuses any plan that lowers a memory limit
// and an undo of a raise is exactly that. So the old rule declined a class of
// legitimate fixes to protect an undo path that does not exist for this field.
// What remains checked here is that a genuinely unusable undo still refuses.
func TestRollbackForResourceLimits_RefusesWhenTheUndoWouldBeInvalid(t *testing.T) {
	// A live value below the action's own absolute minimum is NOT a refusal
	// any more: it is an observed fact about the container, and recording it
	// is what an undo is for.
	live := containerResources{MemoryLimit: "4Mi"}
	params := remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: "256Mi"}
	rollback, err := rollbackForResourceLimits("app", live, params)
	if err != nil {
		t.Fatalf("rollbackForResourceLimits() with a live 4Mi limit = %v, want a captured undo restoring 4Mi", err)
	}
	var restore remediation.PatchResourceLimitsParams
	if err := json.Unmarshal(rollback.Params, &restore); err != nil {
		t.Fatalf("decode rollback params: %v", err)
	}
	if restore.MemoryLimit != "4Mi" {
		t.Errorf("rollback restores memoryLimit %q, want the live 4Mi", restore.MemoryLimit)
	}

	// Still refused: a live value that is not a quantity at all cannot be
	// restored, and the relaxation above must not have turned every malformed
	// live value into a silently accepted undo.
	unreadable := containerResources{MemoryLimit: "four megabytes"}
	if _, err := rollbackForResourceLimits("app", unreadable, params); err == nil {
		t.Error("rollbackForResourceLimits() with an unparseable live limit = nil error, want a refusal")
	}
	// Still refused: a live value above the action's maximum is a value this
	// mechanism genuinely cannot set, minimums or not.
	absurd := containerResources{MemoryLimit: "128Gi"}
	if _, err := rollbackForResourceLimits("app", absurd, params); err == nil {
		t.Error("rollbackForResourceLimits() with a live limit above the maximum = nil error, want a refusal")
	}
}

func TestPatchResourceLimitsKinds(t *testing.T) {
	if !patchResourceLimitsKinds["Deployment"] || !patchResourceLimitsKinds["StatefulSet"] {
		t.Error("patchResourceLimitsKinds must cover Deployment and StatefulSet")
	}
	// DaemonSet has a pod template but neither the ClusterRole nor the
	// admission policy covers it — see the constant's own comment.
	if patchResourceLimitsKinds["DaemonSet"] {
		t.Error("patchResourceLimitsKinds must not include DaemonSet")
	}
}

func TestCheckScaleBound(t *testing.T) {
	cases := []struct {
		name      string
		current   float64
		requested int
		wantErr   bool
	}{
		{"modest increase", 2, 4, false},
		{"scale to zero", 3, 0, false},
		{"generous but sane ceiling with low current", 1, 50, false},
		{"huge jump relative to current and the floor", 2, 501, true},
		{"negative replicas", 2, -1, true},
		{"within 5x of a larger current count", 20, 100, false},
		{"beyond 5x of a larger current count", 20, 101, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := map[string]any{"replicas": tc.current}
			err := checkScaleBound(spec, tc.requested)
			if (err != nil) != tc.wantErr {
				t.Errorf("checkScaleBound(current=%v, requested=%d) error = %v, wantErr %v", tc.current, tc.requested, err, tc.wantErr)
			}
		})
	}
}

// TestCheckScaleBoundWrapsItsSentinel is BUGS.md 95's regression test for
// this guardrail: handleApproveIncident's dispatch (internal/api/approvals.go) tells "we
// refused this plan on our own pre-flight terms" apart from "the cluster
// failed to execute it" purely via errors.Is against ErrScaleBoundRefused,
// never by matching the message text — so a refusal that stopped wrapping
// the sentinel would silently fall back to the generic 502
// remediation-execution-failed, exactly the bug this entry reports.
func TestCheckScaleBoundWrapsItsSentinel(t *testing.T) {
	spec := map[string]any{"replicas": float64(2)}
	err := checkScaleBound(spec, 501)
	if err == nil {
		t.Fatal("checkScaleBound(current=2, requested=501) = nil, want a refusal")
	}
	if !errors.Is(err, ErrScaleBoundRefused) {
		t.Errorf("refusal %v does not wrap ErrScaleBoundRefused — handleApproveIncident's dispatch would misclassify this as a 502", err)
	}
}

// TestLiveReplicaCount pins the one property the guardrail below depends on:
// "unknown" and "zero" are different answers. A spec that carries no numeric
// replicas must report known=false, NOT (0, true) — reporting zero would make
// an unreadable object look exactly like a deliberately switched-off one, and
// reporting known=true would let it past a check that is supposed to stop.
func TestLiveReplicaCount(t *testing.T) {
	cases := []struct {
		name      string
		spec      map[string]any
		want      int
		wantKnown bool
	}{
		{"float64 as encoding/json produces it", map[string]any{"replicas": float64(3)}, 3, true},
		{"float64 zero", map[string]any{"replicas": float64(0)}, 0, true},
		{"int, as a hand-built spec map", map[string]any{"replicas": 2}, 2, true},
		{"json.Number", map[string]any{"replicas": json.Number("5")}, 5, true},
		{"unparseable json.Number", map[string]any{"replicas": json.Number("1.5")}, 0, false},
		{"missing field", map[string]any{"paused": true}, 0, false},
		{"nil spec", nil, 0, false},
		{"string instead of a number", map[string]any{"replicas": "2"}, 0, false},
		{"null", map[string]any{"replicas": nil}, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, gotKnown := liveReplicaCount(tc.spec)
			if got != tc.want || gotKnown != tc.wantKnown {
				t.Errorf("liveReplicaCount(%v) = (%d, %v), want (%d, %v)", tc.spec, got, gotKnown, tc.want, tc.wantKnown)
			}
		})
	}
}

// TestCheckScaleFromZero is the guardrail itself: a workload live at zero
// replicas is treated as deliberately switched off, and only an explicit
// human confirmation turns it back on. Every refusal must carry
// ErrScaleFromZeroRefused, since that sentinel — not the message text — is
// what the handler and the UI branch on.
func TestCheckScaleFromZero(t *testing.T) {
	cases := []struct {
		name      string
		spec      map[string]any
		requested int
		confirmed bool
		wantErr   bool
	}{
		// The case this exists for, and its one permitted escape hatch.
		{"live zero, scale up, unconfirmed", map[string]any{"replicas": float64(0)}, 1, false, true},
		{"live zero, scale up, confirmed", map[string]any{"replicas": float64(0)}, 1, true, false},
		{"live zero, scale up to many, unconfirmed", map[string]any{"replicas": float64(0)}, 3, false, true},

		// Ordinary scaling on a workload that is actually running is
		// untouched — the guardrail must be invisible here.
		{"2 -> 4 (the normal case)", map[string]any{"replicas": float64(2)}, 4, false, false},
		{"1 -> 1 (no change)", map[string]any{"replicas": float64(1)}, 1, false, false},

		// Scaling DOWN, including to zero, is not this check's business: it
		// takes capacity away rather than reversing a decision to switch
		// something off.
		{"3 -> 0", map[string]any{"replicas": float64(3)}, 0, false, false},
		{"already zero, still zero", map[string]any{"replicas": float64(0)}, 0, false, false},

		// FAIL CLOSED: an unreadable live count must not be assumed non-zero.
		{"missing replicas, scale up, unconfirmed", map[string]any{}, 1, false, true},
		{"unparseable replicas, scale up, unconfirmed", map[string]any{"replicas": "two"}, 1, false, true},
		{"nil spec, scale up, unconfirmed", nil, 1, false, true},
		{"missing replicas, scale up, confirmed", map[string]any{}, 1, true, false},
		{"missing replicas, scale down", map[string]any{}, 0, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkScaleFromZero(tc.spec, tc.requested, tc.confirmed)
			if (err != nil) != tc.wantErr {
				t.Fatalf("checkScaleFromZero(%v, %d, confirmed=%v) error = %v, wantErr %v", tc.spec, tc.requested, tc.confirmed, err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, ErrScaleFromZeroRefused) {
				t.Errorf("error %v does not wrap ErrScaleFromZeroRefused — handleApproveIncident and the UI both branch on that sentinel", err)
			}
		})
	}
}

// TestConfirmScaleFromZeroDoesNotBypassScaleBound guards the composition
// ExecuteApprovedPlan relies on: confirmScaleFromZero overrides exactly ONE
// guardrail, and the absurd-jump bound is not it. A confirmed 0->500 is still
// a plan-authoring bug and must still be refused — if this ever passes,
// someone has turned the confirmation into a general "execute it anyway".
func TestConfirmScaleFromZeroDoesNotBypassScaleBound(t *testing.T) {
	spec := map[string]any{"replicas": float64(0)}
	if err := checkScaleFromZero(spec, 500, true); err != nil {
		t.Fatalf("checkScaleFromZero with confirmation = %v, want nil (its own check is satisfied)", err)
	}
	if err := checkScaleBound(spec, 500); err == nil {
		t.Error("checkScaleBound(current=0, requested=500) = nil, want an error — the sanity bound must still reject an absurd jump a human confirmed")
	}
	if errors.Is(checkScaleBound(spec, 500), ErrScaleFromZeroRefused) {
		t.Error("checkScaleBound's refusal wraps ErrScaleFromZeroRefused — the two refusals must stay distinguishable, since only one of them is fixable by confirming")
	}
}

func TestRestartablePodTemplateKinds(t *testing.T) {
	want := []string{"Deployment", "StatefulSet", "DaemonSet"}
	for _, k := range want {
		if !restartablePodTemplateKinds[k] {
			t.Errorf("restartablePodTemplateKinds[%q] = false, want true", k)
		}
	}
	if restartablePodTemplateKinds["Pod"] {
		t.Errorf("restartablePodTemplateKinds[%q] = true, want false — a bare Pod has no /spec/template to patch", "Pod")
	}
}

// --- RevertContainerImage: resolving the previous revision -------------------

// workloadSpecWithImages builds the `spec` map fetchPrecondition returns for a
// pod template whose containers carry images — the same shape
// describe_resource produces for a Deployment and for each of its ReplicaSets,
// which is why one builder serves both here.
func workloadSpecWithImages(containers ...map[string]any) map[string]any {
	items := make([]any, 0, len(containers))
	for _, c := range containers {
		items = append(items, c)
	}
	return map[string]any{"template": map[string]any{"spec": map[string]any{"containers": items}}}
}

func imagedContainer(name, image string) map[string]any {
	return map[string]any{"name": name, "image": image}
}

func TestLiveContainerImage(t *testing.T) {
	spec := workloadSpecWithImages(
		imagedContainer("app", "registry.example.com/app:1.2.3"),
		imagedContainer("sidecar", "registry.example.com/log-shipper:0.9.0"),
	)
	got, err := liveContainerImage(spec, "app")
	if err != nil {
		t.Fatalf("liveContainerImage(app) = %v, want nil", err)
	}
	if got != "registry.example.com/app:1.2.3" {
		t.Errorf("liveContainerImage(app) = %q, want the app image", got)
	}
	if got, err := liveContainerImage(spec, "sidecar"); err != nil || got != "registry.example.com/log-shipper:0.9.0" {
		t.Errorf("liveContainerImage(sidecar) = (%q, %v), want the sidecar image", got, err)
	}
}

// TestLiveContainerImage_FailsClosed: every shape this must refuse rather than
// interpret. The unknown-container case matters most for the same reason it
// does for resources — a merge-key patch on an unmatched name APPENDS — and the
// empty-image case matters because that value is also the rollback.
func TestLiveContainerImage_FailsClosed(t *testing.T) {
	cases := []struct {
		name      string
		spec      map[string]any
		container string
	}{
		{"no container by that name", workloadSpecWithImages(imagedContainer("app", "app:1")), "typo"},
		{"no spec.template", map[string]any{"replicas": 2}, "app"},
		{"no containers list", map[string]any{"template": map[string]any{"spec": map[string]any{}}}, "app"},
		{"empty containers list", workloadSpecWithImages(), "app"},
		{"malformed container entry", map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{"not-an-object"}}}}, "app"},
		{"container with no image", workloadSpecWithImages(map[string]any{"name": "app"}), "app"},
		{"container with an empty image", workloadSpecWithImages(imagedContainer("app", "")), "app"},
		{"container with a whitespace image", workloadSpecWithImages(imagedContainer("app", "   ")), "app"},
		{"image is not a string", workloadSpecWithImages(map[string]any{"name": "app", "image": 42}), "app"},
	}
	for _, c := range cases {
		if _, err := liveContainerImage(c.spec, c.container); err == nil {
			t.Errorf("%s: liveContainerImage() = nil error, want a refusal", c.name)
		}
	}
}

// rsRevision is a shorthand for one entry of a hand-built rollout history.
func rsRevision(name string, revision int64, image string) replicaSetRevision {
	return replicaSetRevision{Name: name, Revision: revision, Image: image, HasContainer: true}
}

// TestResolvePreviousImage_PicksTheHighestDifferingRevision is the happy path
// and the skip rule in one: revision 4 is current (its image matches live),
// revision 3 exists but ran the same image (a resources-only rollout), so the
// answer is revision 2 — the last revision that actually changed the image.
func TestResolvePreviousImage_PicksTheHighestDifferingRevision(t *testing.T) {
	live := "registry.example.com/app:1.3.0"
	revisions := []replicaSetRevision{
		rsRevision("app-aaa", 2, "registry.example.com/app:1.2.0"),
		rsRevision("app-ddd", 4, live),
		rsRevision("app-ccc", 3, live), // same image as current: env/resources changed, not the image
		rsRevision("app-999", 1, "registry.example.com/app:1.1.0"),
	}

	image, from, err := resolvePreviousImage(revisions, "app", live)
	if err != nil {
		t.Fatalf("resolvePreviousImage() = %v, want nil", err)
	}
	if image != "registry.example.com/app:1.2.0" {
		t.Errorf("image = %q, want the 1.2.0 image from revision 2", image)
	}
	if from != "app-aaa" {
		t.Errorf("fromReplicaSet = %q, want app-aaa — the refusal messages and the audit trail name the revision", from)
	}
}

// TestResolvePreviousImage_OrdersByRevisionNotByInputOrder: the input arrives in
// whatever order get_owner_chain listed the ReplicaSets, which is not revision
// order. Reverting to the wrong (older) release because of that would be silent.
func TestResolvePreviousImage_OrdersByRevisionNotByInputOrder(t *testing.T) {
	live := "app:3"
	revisions := []replicaSetRevision{
		rsRevision("rs-1", 1, "app:1"),
		rsRevision("rs-3", 3, live),
		rsRevision("rs-2", 2, "app:2"),
	}
	image, from, err := resolvePreviousImage(revisions, "app", live)
	if err != nil {
		t.Fatalf("resolvePreviousImage() = %v, want nil", err)
	}
	if image != "app:2" || from != "rs-2" {
		t.Errorf("resolved (%q, %q), want (\"app:2\", \"rs-2\") — the immediately previous revision, not the oldest", image, from)
	}
}

// TestResolvePreviousImage_Refusals covers every case this must fail closed on,
// each with the real-world situation it corresponds to.
func TestResolvePreviousImage_Refusals(t *testing.T) {
	live := "app:2"
	cases := []struct {
		name      string
		revisions []replicaSetRevision
		live      string
		wantIn    string // substring the message must carry, so the refusal is actionable
	}{
		{
			// A workload that has never been rolled: one ReplicaSet, revision 1.
			// This is the first-ever-deployment case, and it must read as
			// "nothing to revert to", not as an error about something broken.
			name:      "first-ever deployment has only one revision",
			revisions: []replicaSetRevision{rsRevision("app-aaa", 1, live)},
			live:      live,
			wantIn:    "only one revision",
		},
		{
			// revisionHistoryLimit: 0, or a history pruned by a cluster admin.
			name:      "no ReplicaSets at all",
			revisions: nil,
			live:      live,
			wantIn:    "no rollout history",
		},
		{
			// Every older revision ran the same image: the last change to this
			// workload was not an image change, so there is nothing to revert.
			name: "every previous revision runs the same image",
			revisions: []replicaSetRevision{
				rsRevision("app-ccc", 3, live),
				rsRevision("app-bbb", 2, live),
				rsRevision("app-aaa", 1, live),
			},
			live:   live,
			wantIn: "same image",
		},
		{
			// A paused rollout: the Deployment's template has an image no
			// ReplicaSet has yet. Reverting here would undo a pending change
			// nobody asked ARGUS to touch.
			name: "history and live state disagree about the current image",
			revisions: []replicaSetRevision{
				rsRevision("app-bbb", 2, "app:1"),
				rsRevision("app-aaa", 1, "app:0"),
			},
			live:   live,
			wantIn: "disagree",
		},
		{
			// The container was added or renamed since that revision, so
			// "its previous image" is not a question about this container.
			name: "container did not exist in the previous revision",
			revisions: []replicaSetRevision{
				rsRevision("app-bbb", 2, live),
				{Name: "app-aaa", Revision: 1, HasContainer: false},
			},
			live:   live,
			wantIn: "did not exist in revision 1",
		},
		{
			name: "container is missing from the current revision",
			revisions: []replicaSetRevision{
				{Name: "app-bbb", Revision: 2, HasContainer: false},
				rsRevision("app-aaa", 1, "app:1"),
			},
			live:   live,
			wantIn: "current revision",
		},
		{
			name: "previous revision records an empty image",
			revisions: []replicaSetRevision{
				rsRevision("app-bbb", 2, live),
				{Name: "app-aaa", Revision: 1, HasContainer: true, Image: ""},
			},
			live:   live,
			wantIn: "no image",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			image, from, err := resolvePreviousImage(c.revisions, "app", c.live)
			if err == nil {
				t.Fatalf("resolvePreviousImage() = (%q, %q, nil), want a refusal", image, from)
			}
			if image != "" {
				t.Errorf("refusal also returned image %q, want empty", image)
			}
			if !strings.Contains(err.Error(), c.wantIn) {
				t.Errorf("refusal %q does not contain %q, so an operator cannot tell what to do about it", err, c.wantIn)
			}
			// BUGS.md 95: every refusal above is a pure judgement over
			// revision data already read from the cluster (never a network
			// call, never a mutation attempt), so it belongs in the same 409
			// "we understood perfectly and are declining" class as the two
			// existing guardrails, not the generic 502 handleApproveIncident
			// otherwise falls back to for an unclassified PreparePlan error.
			if !errors.Is(err, ErrImageRevertRefused) {
				t.Errorf("refusal %v does not wrap ErrImageRevertRefused — handleApproveIncident's dispatch would misclassify this as a 502", err)
			}
		})
	}
}

// TestRollbackForContainerImage_RestoresTheCurrentImage: the undo of "go back a
// revision" is "come back to the image that is running now", captured before
// the mutation because afterwards it is gone.
func TestRollbackForContainerImage_RestoresTheCurrentImage(t *testing.T) {
	rollback, err := rollbackForContainerImage("app", "registry.example.com/app:1.3.0")
	if err != nil {
		t.Fatalf("rollbackForContainerImage: %v", err)
	}
	if rollback.ActionType != remediation.ActionRevertContainerImage {
		t.Errorf("rollback action type = %q, want RevertContainerImage", rollback.ActionType)
	}
	var restore remediation.RevertContainerImageExecParams
	if err := json.Unmarshal(rollback.Params, &restore); err != nil {
		t.Fatalf("decode rollback params: %v", err)
	}
	want := remediation.RevertContainerImageExecParams{Container: "app", Image: "registry.example.com/app:1.3.0"}
	if restore != want {
		t.Errorf("rollback params = %+v, want %+v", restore, want)
	}
	if err := restore.Validate(); err != nil {
		t.Errorf("rollback params do not validate as an executable plan: %v", err)
	}
	if rollback.Description == "" {
		t.Error("rollback has no human-readable description")
	}
}

// TestRollbackForContainerImage_RefusesWhenTheUndoWouldBeInvalid: a live image
// this action would refuse to write cannot be an undo either, and finding that
// out before the change is the entire reason the rollback is captured first.
func TestRollbackForContainerImage_RefusesWhenTheUndoWouldBeInvalid(t *testing.T) {
	if _, err := rollbackForContainerImage("app", "not a valid image reference"); err == nil {
		t.Fatal("rollbackForContainerImage() = nil error, want a refusal for an unusable current image")
	}
}

func TestRevertContainerImageKinds(t *testing.T) {
	if !revertContainerImageKinds["Deployment"] {
		t.Error("revertContainerImageKinds must cover Deployment")
	}
	// A StatefulSet's and DaemonSet's revision history is ControllerRevisions,
	// which neither the agent nor this hub can read — so there is no way to
	// verify the revert target, and the action refuses rather than trusting it.
	for _, kind := range []string{"StatefulSet", "DaemonSet", "Pod"} {
		if revertContainerImageKinds[kind] {
			t.Errorf("revertContainerImageKinds[%q] = true, want false", kind)
		}
	}
}

// TestFindPodTemplateContainer_NotFoundIsDistinguishable pins the sentinel the
// history walk depends on: "this revision has no such container" must be
// tellable from "this object could not be read", or a malformed ReplicaSet
// would read as a revision in which the container simply didn't exist.
func TestFindPodTemplateContainer_NotFoundIsDistinguishable(t *testing.T) {
	spec := workloadSpecWithImages(imagedContainer("app", "app:1"))

	_, err := findPodTemplateContainer(spec, "absent")
	if err == nil {
		t.Fatal("findPodTemplateContainer(absent) = nil error, want a not-found error")
	}
	if !errors.Is(err, ErrContainerNotInPodTemplate) {
		t.Errorf("not-found error %v does not wrap ErrContainerNotInPodTemplate", err)
	}

	// A shape problem must NOT wrap the sentinel — it is a refusal everywhere,
	// including while walking history.
	_, err = findPodTemplateContainer(map[string]any{"replicas": 1}, "app")
	if err == nil {
		t.Fatal("findPodTemplateContainer(no template) = nil error, want an error")
	}
	if errors.Is(err, ErrContainerNotInPodTemplate) {
		t.Error("an unreadable object's error wraps ErrContainerNotInPodTemplate — a misread object would be treated as a revision without that container")
	}
}

// TestResolveOwnershipParsing covers the parsing half of the GitOps precedence
// guardrail — the half that decides whether a fix is allowed to proceed, so its
// failure modes matter more than its happy path. Calls the REAL
// parseOwnershipResult directly (extracted 2026-09-01 alongside
// liveGitOpsOwnership/BUGS.md 118 part (b) — see that function's own doc
// comment) rather than a parallel, hand-duplicated copy of its logic, so a
// future edit to the real parsing can't drift from what this test checks.
//
// The three-way return is the point: "" means genuinely unknown (refuse, because
// an unreadable answer is not evidence of absence), "none" means nothing owns it
// (allow), and anything else names the owner (refuse unless confirmed).
func TestResolveOwnershipParsing(t *testing.T) {
	for name, tc := range map[string]struct {
		raw         string
		wantManaged string
		wantSource  string
	}{
		"helm release with a named source": {
			`{"managed_by":"helm","app_ref":{"kind":"Release","name":"shop-apps","namespace":"default"}}`,
			"helm", "Release shop-apps",
		},
		"argocd application": {
			`{"managed_by":"argocd","app_ref":{"kind":"Application","name":"apps"}}`,
			"argocd", "Application apps",
		},
		"nothing owns it": {`{"managed_by":"none"}`, "none", ""},
		// Unparseable and empty must both read as UNKNOWN, not as "none" — the
		// difference decides whether a patch that will be reverted goes ahead.
		"unparseable":                {`not json`, "", ""},
		"empty object":               {`{}`, "", ""},
		"owner with no named source": {`{"managed_by":"flux"}`, "flux", ""},
	} {
		t.Run(name, func(t *testing.T) {
			gotManaged, gotSource := parseOwnershipResult([]byte(tc.raw))
			if gotManaged != tc.wantManaged || gotSource != tc.wantSource {
				t.Errorf("got (%q, %q), want (%q, %q)", gotManaged, gotSource, tc.wantManaged, tc.wantSource)
			}
		})
	}
}

// TestGitOpsRefusalIsItsOwnSentinel guards the distinctness that lets the UI
// offer the right confirmation. If these two collapsed to one error, a "yes,
// turn it back on" click would silently waive "yes, I accept this gets
// reverted" — two unrelated decisions from one button.
func TestGitOpsRefusalIsItsOwnSentinel(t *testing.T) {
	if errors.Is(ErrGitOpsManagedRefused, ErrScaleFromZeroRefused) ||
		errors.Is(ErrScaleFromZeroRefused, ErrGitOpsManagedRefused) {
		t.Error("the two refusal sentinels must stay distinct so each maps to its own problem type and confirmation")
	}
}

// TestDeleteResourcePVCRefusalIsItsOwnSentinel is BUGS.md 118 part (b)'s
// analogue of TestGitOpsRefusalIsItsOwnSentinel: ErrDeleteResourcePVCManagedRefused
// must not collapse into ErrGitOpsManagedRefused (which IS confirmable via
// confirmGitOpsManaged) or ErrNamespaceProtectedRefused (a different absolute
// wall, unrelated reason). Collapsing either would let internal/api/approvals.go's
// errors.Is dispatch match the wrong branch — either offering a confirmation
// this refusal must never accept, or reporting the wrong reason to an
// operator and to recordPolicyRefusal's audit trail.
func TestDeleteResourcePVCRefusalIsItsOwnSentinel(t *testing.T) {
	if errors.Is(ErrDeleteResourcePVCManagedRefused, ErrGitOpsManagedRefused) ||
		errors.Is(ErrGitOpsManagedRefused, ErrDeleteResourcePVCManagedRefused) {
		t.Error("ErrDeleteResourcePVCManagedRefused must stay distinct from ErrGitOpsManagedRefused — the latter IS confirmable and this must never be")
	}
	if errors.Is(ErrDeleteResourcePVCManagedRefused, ErrNamespaceProtectedRefused) ||
		errors.Is(ErrNamespaceProtectedRefused, ErrDeleteResourcePVCManagedRefused) {
		t.Error("ErrDeleteResourcePVCManagedRefused must stay distinct from ErrNamespaceProtectedRefused — same 'no override' shape, unrelated reason")
	}
}

// TestCheckLiveRiskFloorBoundWrapsItsSentinel is BUGS.md 101's regression
// test for the tier=data / PersistentVolumeClaim live risk-floor recheck:
// found live on rke2 via a tier=data-labelled Deployment refused correctly
// inside PreparePlan, but reported as the same 502 remediation-execution-failed
// a real cluster/agent failure would produce, because the refusal was a plain
// fmt.Errorf with no sentinel for internal/api/approvals.go's dispatch to recognize.
func TestCheckLiveRiskFloorBoundWrapsItsSentinel(t *testing.T) {
	// The exact live signal reproduced on rke2: no namespace annotation, just
	// a tier=data label on the target itself, evaluated against a plan the
	// gate originally floored at medium.
	err := checkLiveRiskFloorBound(map[string]string{"tier": "data"}, nil, "apps/v1/Deployment", "ns", "app", remediation.RiskMedium)
	if err == nil {
		t.Fatal("checkLiveRiskFloorBound(tier=data, originalFloor=medium) = nil, want a refusal")
	}
	if !errors.Is(err, ErrRiskFloorRecheckRefused) {
		t.Errorf("refusal %v does not wrap ErrRiskFloorRecheckRefused — internal/api/approvals.go's dispatch would misclassify this as a 502", err)
	}

	// The PVC case (PVC-014), reached through the same function's second
	// switch arm.
	volumes := []map[string]any{{"name": "data", "persistentVolumeClaim": map[string]any{"claimName": "app-data"}}}
	err = checkLiveRiskFloorBound(nil, volumes, "apps/v1/Deployment", "ns", "app", remediation.RiskMedium)
	if err == nil {
		t.Fatal("checkLiveRiskFloorBound(PVC-mounted, originalFloor=medium) = nil, want a refusal")
	}
	if !errors.Is(err, ErrRiskFloorRecheckRefused) {
		t.Errorf("PVC refusal %v does not wrap ErrRiskFloorRecheckRefused", err)
	}

	// Neither modifier applies, or the plan was already evaluated at (or
	// above) RiskHigh — nothing new for the live read to raise.
	if err := checkLiveRiskFloorBound(map[string]string{"tier": "data"}, nil, "apps/v1/Deployment", "ns", "app", remediation.RiskHigh); err != nil {
		t.Errorf("checkLiveRiskFloorBound(tier=data, originalFloor=high) = %v, want nil — already at the floor this would raise it to", err)
	}
	if err := checkLiveRiskFloorBound(map[string]string{"env": "prod"}, nil, "apps/v1/Deployment", "ns", "app", remediation.RiskMedium); err != nil {
		t.Errorf("checkLiveRiskFloorBound(no matching modifier) = %v, want nil", err)
	}
}

// TestInterpretAbsenceCheckResult exercises confirmTargetAbsentForCreate's
// three-way decision logic (internal/remediation/createresource.go's own
// header comment on ErrResourceNotFoundMessage names this exact brittleness)
// directly, with no gateway/cluster involved — the same testability reason
// TestCheckLiveRiskFloorBoundWrapsItsSentinel exists for its own sibling
// pure function.
func TestInterpretAbsenceCheckResult(t *testing.T) {
	t.Run("describe_resource succeeded: object already exists, refuse", func(t *testing.T) {
		err := interpretAbsenceCheckResult("v1/ConfigMap", "payments", "checkout-api-config", nil)
		if err == nil {
			t.Fatal("interpretAbsenceCheckResult(nil error) = nil, want a refusal — the object exists")
		}
		if !strings.Contains(err.Error(), "already exists") {
			t.Errorf("refusal %q does not say the object already exists", err.Error())
		}
	})

	t.Run("describe_resource failed with not-found text: confirmed absent, proceed", func(t *testing.T) {
		// The exact wrapped shape FetchPreconditionWithObject-style callers
		// see over the tunnel: sanitizeK8sErr's fixed string, wrapped by the
		// gateway/tool-call machinery with additional context on both sides.
		wrapped := fmt.Errorf("describe v1/ConfigMap payments/checkout-api-config: %w", errors.New(remediation.ErrResourceNotFoundMessage))
		if err := interpretAbsenceCheckResult("v1/ConfigMap", "payments", "checkout-api-config", wrapped); err != nil {
			t.Errorf("interpretAbsenceCheckResult(not-found error) = %v, want nil (confirmed absent)", err)
		}
	})

	t.Run("describe_resource failed for an unrelated reason: ambiguous, fail closed", func(t *testing.T) {
		err := interpretAbsenceCheckResult("v1/ConfigMap", "payments", "checkout-api-config", errors.New("permission denied"))
		if err == nil {
			t.Fatal("interpretAbsenceCheckResult(ambiguous error) = nil, want a refusal — absence could not be confirmed")
		}
		if !strings.Contains(err.Error(), "could not confirm") {
			t.Errorf("refusal %q does not say absence could not be confirmed", err.Error())
		}
	})
}

// TestCheckNamespaceNotProtectedWrapsItsSentinel is BUGS.md 101's regression
// test for the argus.io/protected namespace guardrail: found live on rke2,
// refused correctly inside PreparePlan (confirmed via
// remediation_approval_decisions/remediation_executions and kubectl showing
// nothing was signed, recorded, or sent) but reported as the same 502
// remediation-execution-failed a real cluster/agent failure would produce.
func TestCheckNamespaceNotProtectedWrapsItsSentinel(t *testing.T) {
	err := checkNamespaceNotProtected(map[string]string{"argus.io/protected": "true"}, "argus-e9-test-r4")
	if err == nil {
		t.Fatal("checkNamespaceNotProtected(argus.io/protected=true) = nil, want a refusal")
	}
	if !errors.Is(err, ErrNamespaceProtectedRefused) {
		t.Errorf("refusal %v does not wrap ErrNamespaceProtectedRefused — internal/api/approvals.go's dispatch would misclassify this as a 502", err)
	}
	if !strings.Contains(err.Error(), "argus-e9-test-r4") {
		t.Errorf("refusal %v does not name the protected namespace", err)
	}

	// NamespaceIsProtected's own doc comment: presence of the key is what
	// matters, not its value — an operator marking a namespace protected
	// should not also have to spell a magic value correctly. Confirmed here
	// rather than assumed, since it changes what "not protected" looks like
	// in this test: an unrelated annotation, not argus.io/protected=false.
	if err := checkNamespaceNotProtected(map[string]string{"team": "platform"}, "ns"); err != nil {
		t.Errorf("checkNamespaceNotProtected(unrelated annotation) = %v, want nil", err)
	}
	if err := checkNamespaceNotProtected(nil, "ns"); err != nil {
		t.Errorf("checkNamespaceNotProtected(no annotations) = %v, want nil", err)
	}
}

// TestPreparePlanRefusalSentinelsAreAllDistinct extends
// TestGitOpsRefusalIsItsOwnSentinel to the four sentinels added for BUGS.md
// 95 (checkScaleBound, checkResourceLimitsBound, findPodTemplateContainer's
// not-found case, resolvePreviousImage), the two sentinels added for BUGS.md
// 101 (PreparePlan's live risk-floor recheck and its argus.io/protected
// namespace guardrail), plus the two pre-existing guardrails. Every one of
// these eight maps to its own RFC 9457 problem `type` in internal/api/approvals.go's
// writePreparePlanExecutionError, keyed purely by errors.Is — if any two
// collapsed into one, that dispatch would report the wrong refusal (and,
// for the two guardrails, offer the wrong confirmation).
func TestPreparePlanRefusalSentinelsAreAllDistinct(t *testing.T) {
	sentinels := map[string]error{
		"ErrScaleFromZeroRefused":       ErrScaleFromZeroRefused,
		"ErrGitOpsManagedRefused":       ErrGitOpsManagedRefused,
		"ErrScaleBoundRefused":          ErrScaleBoundRefused,
		"ErrResourceLimitsBoundRefused": ErrResourceLimitsBoundRefused,
		"ErrContainerNotInPodTemplate":  ErrContainerNotInPodTemplate,
		"ErrImageRevertRefused":         ErrImageRevertRefused,
		"ErrRiskFloorRecheckRefused":    ErrRiskFloorRecheckRefused,
		"ErrNamespaceProtectedRefused":  ErrNamespaceProtectedRefused,
	}
	for aName, a := range sentinels {
		for bName, b := range sentinels {
			if aName == bName {
				continue
			}
			if errors.Is(a, b) {
				t.Errorf("%s wraps/matches %s via errors.Is — the two must stay distinct so each maps to its own problem type", aName, bName)
			}
		}
	}
}

// TestRiskFloorRecheckCatchesStatefulSetOwnedPod is WORKLOG §97's G3 finding,
// reproduced directly against remediation.RiskFloorFor/HigherRisk rather than
// through the full ExecuteApprovedPlan (which needs a live DB/gateway): a
// RestartPod/PatchResourceLimits/RevertContainerImage plan is authored against
// the finding's object — often a Pod — and only resolved to the workload that
// owns its template inside ExecuteApprovedPlan, AFTER the gate already
// evaluated and recorded a Decision against the pre-resolution target.
//
// A Pod is never in statefulTargetKinds, so a plan naming a Pod owned by a
// StatefulSet was gated at whatever floor the bare action implies — never
// DESIGN.md §9.3's higher StatefulSet floor. This pins that the two floors
// really do disagree in exactly the case that matters, which is what makes
// the ExecuteApprovedPlan recheck (using this same pair of calls) a real
// fix rather than a no-op.
func TestRiskFloorRecheckCatchesStatefulSetOwnedPod(t *testing.T) {
	asAuthored := remediation.RemediationPlan{
		ActionType: remediation.ActionRestartPod,
		TargetGVK:  "v1/Pod", TargetNamespace: "data",
	}
	asResolved := remediation.RemediationPlan{
		ActionType: remediation.ActionRestartPod,
		TargetGVK:  "apps/v1/StatefulSet", TargetNamespace: "data",
	}
	originalFloor := remediation.RiskFloorFor(asAuthored)
	resolvedFloor := remediation.RiskFloorFor(asResolved)

	if !remediation.HigherRisk(resolvedFloor, originalFloor) {
		t.Fatalf("resolved floor %q is not higher than the pre-resolution floor %q — "+
			"if this ever stops being true the recheck in ExecuteApprovedPlan silently does nothing",
			resolvedFloor, originalFloor)
	}

	// And the case that must NOT trigger a refusal: a Deployment-owned pod
	// resolves to a Deployment, and the floor is unchanged.
	depAuthored := remediation.RemediationPlan{ActionType: remediation.ActionRestartPod, TargetGVK: "v1/Pod", TargetNamespace: "apps"}
	depResolved := remediation.RemediationPlan{ActionType: remediation.ActionRestartPod, TargetGVK: "apps/v1/Deployment", TargetNamespace: "apps"}
	if remediation.HigherRisk(remediation.RiskFloorFor(depResolved), remediation.RiskFloorFor(depAuthored)) {
		t.Error("a Deployment-owned pod must not trigger the StatefulSet recheck refusal")
	}
}

// TestRiskFloorRecheckIgnoresProtectedNamespaceModifier guards against the
// recheck double-counting: the protected-namespace floor is unaffected by
// target resolution (namespace does not change when a Pod resolves to its
// owning workload), so the two floors compared must be equal in that case.
func TestRiskFloorRecheckIgnoresProtectedNamespaceModifier(t *testing.T) {
	authored := remediation.RemediationPlan{ActionType: remediation.ActionRestartPod, TargetGVK: "v1/Pod", TargetNamespace: "kube-system"}
	resolved := remediation.RemediationPlan{ActionType: remediation.ActionRestartPod, TargetGVK: "apps/v1/Deployment", TargetNamespace: "kube-system"}
	if remediation.HigherRisk(remediation.RiskFloorFor(resolved), remediation.RiskFloorFor(authored)) {
		t.Error("namespace-driven floor should not change across resolution when the namespace itself did not change")
	}
}

// TestGuardrailBooleanWithoutTokenIsIgnored is WORKLOG §97's G5 finding,
// exercised at the point the fix actually lives: a client that always sends
// confirmScaleFromZero/confirmGitOpsManaged: true, with no matching token (or
// with a token for the wrong guardrail/plan), must be treated exactly as if
// it had sent false. This is the property that makes the boolean alone
// insufficient — before this fix, the boolean was the whole story.
func TestGuardrailBooleanWithoutTokenIsIgnored(t *testing.T) {
	issuer := authz.NewGuardrailConfirmationIssuer()

	// The exact expression ExecuteApprovedPlan uses at both guardrail sites:
	// booleanFromRequest && Redeem(token, planID, guardrail).
	confirmed := func(rawBoolean bool, presentedToken, planID, guardrail string) bool {
		return rawBoolean && issuer.Redeem(presentedToken, planID, guardrail)
	}

	t.Run("true with no token at all", func(t *testing.T) {
		if confirmed(true, "", "plan_1", GuardrailScaleFromZero) {
			t.Fatal("a bare true with an empty token must not confirm")
		}
	})

	t.Run("true with a token for the WRONG plan (replay across incidents)", func(t *testing.T) {
		token, _ := issuer.Issue("plan_1", GuardrailScaleFromZero)
		if confirmed(true, token, "plan_2", GuardrailScaleFromZero) {
			t.Fatal("a token minted for plan_1 must not confirm plan_2 — this is the exact replay the finding described")
		}
	})

	t.Run("true with a token for the WRONG guardrail", func(t *testing.T) {
		token, _ := issuer.Issue("plan_1", GuardrailScaleFromZero)
		if confirmed(true, token, "plan_1", GuardrailGitOpsManaged) {
			t.Fatal("a scaleFromZero token must not confirm the gitOpsManaged guardrail on the same plan")
		}
	})

	t.Run("a scripted client that always sends true gets nowhere without a real refusal first", func(t *testing.T) {
		// No Issue call at all — simulating exactly the "this client always
		// sends true" case the review named.
		if confirmed(true, "whatever-the-client-feels-like-sending", "plan_1", GuardrailScaleFromZero) {
			t.Fatal("an unissued token must never confirm, regardless of the boolean")
		}
	})

	t.Run("the legitimate path still works", func(t *testing.T) {
		token, _ := issuer.Issue("plan_1", GuardrailScaleFromZero)
		if !confirmed(true, token, "plan_1", GuardrailScaleFromZero) {
			t.Fatal("the exact (planID, guardrail) pair a real refusal minted must confirm")
		}
	})
}

// TestIsDigestPinned covers the distinction WORKLOG §97's G4 finding turns
// on: a content digest names exact bytes, a tag does not, and this must tell
// the two apart correctly including the tricky case of a tag that merely
// contains the substring "sha256" without being an actual digest reference.
func TestIsDigestPinned(t *testing.T) {
	for _, c := range []struct {
		image string
		want  bool
	}{
		{"nginx@sha256:abc123def456", true},
		{"registry.example.com/app/api@sha256:0000000000000000000000000000000000000000000000000000000000000a", true},
		{"nginx:1.27-alpine", false},
		{"nginx:latest", false},
		{"nginx", false},
		{"registry.example.com/app:sha256isnotarealtag", false}, // contains "sha256" but not "@sha256:"
	} {
		if got := isDigestPinned(c.image); got != c.want {
			t.Errorf("isDigestPinned(%q) = %v, want %v", c.image, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// BACKLOG.md F12 — the dry-run gate's fail-closed behaviour.
//
// These cover the one case where getting it wrong is actively dangerous rather
// than merely broken: an agent that silently executed for real while the hub
// believed it was rehearsing. The hub cannot detect that from a successful
// response alone, so it requires positive confirmation.
// ---------------------------------------------------------------------------

func TestInterpretDryRunResult_AcceptsAConfirmedRehearsal(t *testing.T) {
	at := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	raw := json.RawMessage(`{"resourceVersion":"1234","dryRun":true,"object":{"kind":"Deployment"}}`)

	att, err := interpretDryRunResult(raw, at)
	if err != nil {
		t.Fatalf("a confirmed rehearsal was rejected: %v", err)
	}
	if !att.At.Equal(at) {
		t.Errorf("attestation timestamp = %v, want %v", att.At, at)
	}
	if len(att.Object) == 0 {
		t.Error("attestation carries no object, so F13 has nothing to diff")
	}
}

// The version-skew guard. An agent that predates SignedPlan.DryRun ignores the
// field, patches for real, and answers exactly like this — success, with a
// resourceVersion, and no echo. Accepting it would mean the hub mutated the
// cluster during what it reported as a rehearsal and then mutated it again.
func TestInterpretDryRunResult_RefusesAnAgentThatDidNotConfirmTheDryRun(t *testing.T) {
	cases := map[string]string{
		"an agent too old to know the field": `{"resourceVersion":"1234"}`,
		"an explicit false":                  `{"resourceVersion":"1234","dryRun":false}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := interpretDryRunResult(json.RawMessage(body), time.Now())
			if err == nil {
				t.Fatal("an unconfirmed dry run was accepted as attested — the hub would go on to execute after a response that may already have mutated the cluster")
			}
			// The operator has to be able to act on this, and the action is
			// specific: upgrade the agent. A generic failure would send them
			// looking at the plan instead.
			if !strings.Contains(err.Error(), "upgrade the ARGUS agent") {
				t.Errorf("refusal does not tell the operator what to do: %v", err)
			}
		})
	}
}

func TestInterpretDryRunResult_RefusesAnUnreadableResponse(t *testing.T) {
	if _, err := interpretDryRunResult(json.RawMessage(`not json`), time.Now()); err == nil {
		t.Fatal("an unreadable agent response was treated as a successful attestation")
	}
}

// TestStructuredPatchDryRun_ProducesACorrectMultiPathDiff is this task's
// requirement 3 end to end, using ONLY the pieces that are testable without a
// live cluster or a live model: it feeds a CONSTRUCTED agent dry-run response
// — shaped exactly like what a real "patch_structured" tool would need to
// return, covering N fields instead of one — through interpretDryRunResult
// (the pure half of attestByDryRun, F12's own dry-run gate) and then through
// objdiff.Compute (F13's diff machinery, the exact function
// handlePreflightIncident calls on prep.LiveObject/prep.Attestation.Object/
// .Patch). Neither function is StructuredPatch-aware — this test's whole
// point is that neither needs to be: they already work per-path, and a
// multi-op plan is just several paths at once.
func TestStructuredPatchDryRun_ProducesACorrectMultiPathDiff(t *testing.T) {
	liveObject := json.RawMessage(`{
		"spec": {
			"progressDeadlineSeconds": 600,
			"template": {"spec": {"containers": [
				{"name": "api", "resources": {"requests": {"cpu": "100m"}}}
			]}}
		}
	}`)

	// What a real "patch_structured" agent tool would echo back from a dry
	// run: dryRun:true (the version-skew guard interpretDryRunResult enforces),
	// the post-patch object, and the strategic-merge patch body that was sent —
	// one leaf per operation, exactly like patch_field's own single-leaf body
	// today.
	dryRunResponse := json.RawMessage(`{
		"dryRun": true,
		"object": {
			"spec": {
				"progressDeadlineSeconds": 900,
				"template": {"spec": {"containers": [
					{"name": "api", "resources": {"requests": {"cpu": "250m"}}}
				]}}
			}
		},
		"patch": {
			"spec": {
				"progressDeadlineSeconds": 900,
				"template": {"spec": {"containers": [
					{"name": "api", "resources": {"requests": {"cpu": "250m"}}}
				]}}
			}
		}
	}`)

	attestation, err := interpretDryRunResult(dryRunResponse, time.Now())
	if err != nil {
		t.Fatalf("interpretDryRunResult: %v", err)
	}

	diff, err := objdiff.Compute(liveObject, attestation.Object, attestation.Patch)
	if err != nil {
		t.Fatalf("objdiff.Compute: %v", err)
	}

	if diff.Empty() {
		t.Fatal("diff reports no change, want two requested changes")
	}
	if len(diff.Additional) != 0 {
		t.Errorf("diff.Additional = %v, want none — every changed field here was requested", paths(diff.Additional))
	}

	got := find(t, diff.Requested, "spec.progressDeadlineSeconds")
	if fmt.Sprint(got.Before) != "600" || fmt.Sprint(got.After) != "900" {
		t.Errorf("spec.progressDeadlineSeconds: before=%v after=%v, want 600 -> 900", got.Before, got.After)
	}
	got2 := find(t, diff.Requested, "spec.template.spec.containers[api].resources.requests.cpu")
	if fmt.Sprint(got2.Before) != "100m" || fmt.Sprint(got2.After) != "250m" {
		t.Errorf("container cpu request: before=%v after=%v, want 100m -> 250m", got2.Before, got2.After)
	}
	if len(diff.Requested) != 2 {
		t.Errorf("diff.Requested = %v, want exactly the two operations this plan named", paths(diff.Requested))
	}
}

// find is objdiff's own test helper, duplicated narrowly here rather than
// imported: internal/objdiff's find/paths are unexported test helpers of that
// package, not part of its public API, and this package already has its own
// small set of test-only helpers (workloadSpec, testContainer) rather than
// reaching into another package's test file.
func find(t *testing.T, changes []objdiff.Change, path string) objdiff.Change {
	t.Helper()
	for _, c := range changes {
		if c.Path == path {
			return c
		}
	}
	t.Fatalf("no change at %q; got %v", path, paths(changes))
	return objdiff.Change{}
}

func paths(changes []objdiff.Change) []string {
	out := make([]string, 0, len(changes))
	for _, c := range changes {
		out = append(out, c.Path)
	}
	return out
}

// The gate signs a dry-run twin rather than reusing the real plan's envelope.
// This asserts the two properties that makes that worth doing: the twin is
// identical in every field that describes the change, and it is a DIFFERENT
// signed plan — so neither can be substituted for the other in flight.
func TestDryRunTwin_DiffersOnlyByTheFlagAndIsSeparatelySigned(t *testing.T) {
	key := []byte("a-32-byte-per-cluster-test-key!!")
	content := remediation.PlanContent{
		RecommendationID: "plan_1",
		ActionType:       remediation.ActionScaleDeployment,
		TargetGVK:        "apps/v1/Deployment",
		TargetNamespace:  "default",
		TargetName:       "web",
		Params:           json.RawMessage(`{"replicas":4}`),
		ResourceVersion:  "100",
	}
	expiry := time.Now().Add(time.Minute)

	real, err := remediation.Sign(content, "clu_1", expiry, key)
	if err != nil {
		t.Fatalf("sign real: %v", err)
	}
	dryContent := content
	dryContent.DryRun = true
	dry, err := remediation.Sign(dryContent, "clu_1", expiry, key)
	if err != nil {
		t.Fatalf("sign dry: %v", err)
	}

	if real.Signature == dry.Signature {
		t.Error("the rehearsal and the real plan share a signature — one could be substituted for the other")
	}
	if dry.TargetName != real.TargetName || dry.TargetNamespace != real.TargetNamespace ||
		dry.TargetGVK != real.TargetGVK || dry.ActionType != real.ActionType ||
		string(dry.Params) != string(real.Params) || dry.ResourceVersion != real.ResourceVersion {
		t.Error("the rehearsal describes a different change from the plan it is supposed to be attesting")
	}
	// Both must verify on their own terms — the twin is a valid plan, not a
	// throwaway the agent would reject for an unrelated reason.
	if err := remediation.Verify(dry, "clu_1", key, time.Now()); err != nil {
		t.Errorf("the dry-run twin does not verify: %v", err)
	}
}

// plannedFieldPaths is the action table BACKLOG F11 requires the allowlist to be
// GENERATED from rather than hand-maintained beside. Every executable action type
// must appear, because an action missing from it produces no field-level
// contention check at all — it silently falls back to the object-level answer,
// which is the imprecision F16 item 1 exists to remove.
func TestPlannedFieldPathsCoversEveryExecutableAction(t *testing.T) {
	cases := []struct {
		name string
		plan remediation.RemediationPlan
		want []string
	}{
		{
			"scale",
			remediation.RemediationPlan{ActionType: remediation.ActionScaleDeployment, Params: remediation.ScaleDeploymentParams{Replicas: 3}},
			[]string{"spec.replicas"},
		},
		{
			"restart",
			remediation.RemediationPlan{ActionType: remediation.ActionRestartPod, Params: remediation.RestartPodParams{}},
			[]string{"spec.template.metadata.annotations"},
		},
		{
			"revert image",
			remediation.RemediationPlan{ActionType: remediation.ActionRevertContainerImage, Params: remediation.RevertContainerImageParams{Container: "web"}},
			[]string{"spec.template.spec.containers[web].image"},
		},
		{
			// One path per field actually set — not the whole resources block. A
			// controller can own the memory limit without owning the CPU request.
			"limits, one field",
			remediation.RemediationPlan{ActionType: remediation.ActionPatchResourceLimits, Params: remediation.PatchResourceLimitsParams{Container: "api", MemoryLimit: "256Mi"}},
			[]string{"spec.template.spec.containers[api].resources.limits.memory"},
		},
	}
	for _, tc := range cases {
		got, err := remediation.PlannedFieldPaths(tc.plan)
		if err != nil {
			t.Errorf("%s: PlannedFieldPaths: %v", tc.name, err)
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: path %d = %q, want %q", tc.name, i, got[i], tc.want[i])
			}
		}
	}

	// Two fields set produces two paths, in a stable order.
	both, err := remediation.PlannedFieldPaths(remediation.RemediationPlan{
		ActionType: remediation.ActionPatchResourceLimits,
		Params:     remediation.PatchResourceLimitsParams{Container: "api", MemoryLimit: "256Mi", CPURequest: "100m"},
	})
	if err != nil {
		t.Fatalf("PlannedFieldPaths: %v", err)
	}
	if len(both) != 2 {
		t.Errorf("a two-field limits patch produced %v, want one path per field", both)
	}

	// Every action type that EXECUTES against a cluster must yield paths.
	//
	// This loop used to hand-list four action types, which meant the assertion in
	// its own comment — "fails when a fifth action type is added and this table is
	// not" — was false: a fifth type simply would not have been visited. It now
	// enumerates remediation.AllActionTypes(), so the closed set drives it.
	//
	// The sibling assertion, that every action type has a TABLE ENTRY at all, lives
	// in internal/remediation/fieldpaths_test.go next to the table. This one is
	// narrower and different: an executing action must produce a non-empty list,
	// where OpenPR legitimately produces none.
	for _, at := range remediation.AllActionTypes() {
		if _, ok := ToolForAction(at); !ok {
			continue
		}
		params, ok := sampleParamsFor(at)
		if !ok {
			t.Errorf("action type %s executes against a cluster but this test has no sample params for it — add them, rather than letting the action go unchecked", at)
			continue
		}
		paths, err := remediation.PlannedFieldPaths(remediation.RemediationPlan{ActionType: at, Params: params})
		if err != nil {
			t.Errorf("action type %s executes against a cluster but PlannedFieldPaths refused it (%v), so its patch is never checked for field contention", at, err)
			continue
		}
		if len(paths) == 0 && !noFieldLevelClaimExecutingActions[at] {
			t.Errorf("action type %s executes against a cluster but plans no field paths, so its patch is never checked for field contention", at)
		}
	}
}

// noFieldLevelClaimExecutingActions is the deliberate, narrow exception to
// this test's own "executes => must plan field paths" rule above — three
// action types that genuinely execute against a cluster and just as
// genuinely have no NARROWER claim to make than "this object changed",
// each for its own reason documented in internal/remediation/fieldpaths.go:
//
//   - AnnotateResource/LabelResource: the key itself (e.g.
//     "argus.io/incident-id") routinely contains the "." this package's
//     path notation treats as a segment separator, so representing it as a
//     path would silently mis-split it rather than name it correctly.
//   - DeleteResource: removes the whole object, which has no field to name
//     at all.
//
// All three still get checkGitOpsPrecedence's OBJECT-level fallback message
// (fieldContentionDetail returns "" for an empty plannedPaths, which the
// caller already treats as "no field-level claim can be made" — see that
// function's own doc comment) — this exception says only that the FIELD-
// level precision F16 item 1 added is unavailable for these three, not that
// the GitOps-ownership guardrail itself is skipped for them.
var noFieldLevelClaimExecutingActions = map[remediation.ActionType]bool{
	remediation.ActionAnnotateResource: true,
	remediation.ActionLabelResource:    true,
	remediation.ActionDeleteResource:   true,
	// CreateResource: there is no existing object for a field-level claim to
	// be ABOUT — the whole point of a create. See fieldpaths.go's own
	// comment on this action type's entry for why this is the "correct
	// type, nothing narrower to say" case, same as DeleteResource, rather
	// than a claim this codebase forgot to write.
	remediation.ActionCreateResource: true,
}

// sampleParamsFor is minimal valid params per action type, for the loop above.
// Returns ok=false for an action type nobody has supplied params for, so a new
// executing action type is reported rather than skipped.
func sampleParamsFor(at remediation.ActionType) (remediation.ActionParams, bool) {
	switch at {
	case remediation.ActionScaleDeployment:
		return remediation.ScaleDeploymentParams{Replicas: 1}, true
	case remediation.ActionRestartPod:
		return remediation.RestartPodParams{}, true
	case remediation.ActionPatchResourceLimits:
		return remediation.PatchResourceLimitsParams{Container: "c", MemoryLimit: "1Gi"}, true
	case remediation.ActionRevertContainerImage:
		return remediation.RevertContainerImageParams{Container: "c"}, true
	case remediation.ActionPatchField:
		return remediation.PatchFieldParams{FieldPath: "spec.progressDeadlineSeconds", NewValue: "900"}, true
	case remediation.ActionStructuredPatch:
		return remediation.StructuredPatchParams{Ops: []remediation.StructuredPatchOp{
			{FieldPath: "spec.progressDeadlineSeconds", NewValue: "900"},
		}}, true
	case remediation.ActionAnnotateResource:
		return remediation.AnnotateResourceParams{Key: "argus.io/incident-id", Value: "inc_01test"}, true
	case remediation.ActionLabelResource:
		return remediation.LabelResourceParams{Key: "argus.io/remediated", Value: "true"}, true
	case remediation.ActionDeleteResource:
		return remediation.DeleteResourceParams{}, true
	case remediation.ActionCordonNode:
		return remediation.CordonNodeParams{Unschedulable: true}, true
	case remediation.ActionDrainNode:
		return remediation.DrainNodeParams{DeleteEmptyDirData: true}, true
	case remediation.ActionCreateResource:
		return remediation.CreateResourceParams{Data: map[string]string{"RETRY_LIMIT": "3"}}, true
	}
	return nil, false
}

// The two directions the enriched refusal must tell apart, on the encoding a real
// API server writes.
func TestFieldContentionDetailBothDirections(t *testing.T) {
	// operation "Update", which is what a real Argo CD installation writes — see
	// objdiff.DescribeContention on why that must not weaken the conclusion.
	const managed = `{"metadata":{"managedFields":[
	  {"manager":"argocd-controller","operation":"Update","fieldsV1":{"f:spec":{"f:replicas":{}}}}
	]}}`
	detail := fieldContentionDetail(json.RawMessage(managed), []string{"spec.replicas"})
	if !strings.Contains(detail, "argocd-controller") || !strings.Contains(detail, "spec.replicas") {
		t.Errorf("a contended field produced %q, want it to name both the field and the manager — that precision is the whole point of F16 item 1", detail)
	}
	// The reversion claim belongs here, where the caller already knows a
	// reconciling controller owns the object — not in objdiff, which cannot tell.
	if !strings.Contains(detail, "reverted") {
		t.Errorf("contended detail = %q, want it to say the patch is reverted: this function is only reached once object-level ownership has established that a reconciling controller owns it", detail)
	}

	// The same object, a field nothing owns. Must NOT claim contention, and must
	// not promise durability either.
	detail = fieldContentionDetail(json.RawMessage(managed), []string{"spec.paused"})
	if strings.Contains(detail, "argocd-controller") {
		t.Errorf("an uncontended field was attributed to a manager: %q", detail)
	}
	if !strings.Contains(detail, "probably") {
		t.Errorf("uncontended detail = %q — it must be hedged, because whether an unmanaged field survives depends on the controller's apply strategy, which ARGUS cannot see", detail)
	}

	// ARGUS's own manager is not contention.
	const ours = `{"metadata":{"managedFields":[
	  {"manager":"argus-remediate","operation":"Apply","fieldsV1":{"f:spec":{"f:replicas":{}}}}
	]}}`
	if d := fieldContentionDetail(json.RawMessage(ours), []string{"spec.replicas"}); strings.Contains(d, "argus-remediate") {
		t.Errorf("ARGUS's own previous patch was reported as contention: %q", d)
	}

	// No live object, or no known paths: fall back silently to the object-level
	// message rather than inventing a field-level claim.
	if d := fieldContentionDetail(nil, []string{"spec.replicas"}); d != "" {
		t.Errorf("no live object produced %q, want empty", d)
	}
	if d := fieldContentionDetail(json.RawMessage(managed), nil); d != "" {
		t.Errorf("no planned paths produced %q, want empty", d)
	}
}

// --- BACKLOG.md C8 / BUGS.md 104: verify-before-concluding -----------------
//
// verifyMutationApplied is the decision logic resolveIndeterminateOutcome
// leans on to turn "the tunnel call's own result was indeterminate" into a
// confident "succeeded" or an honest "still unknown" — never a confident
// "failed" (see resolveIndeterminateOutcome's own doc comment for why that
// asymmetry is deliberate). These tests exercise it directly, with no
// gateway/DB/network involved, matching this file's existing style for
// every other piece of PreparePlan/ExecuteApprovedPlan's decision logic.

func TestVerifyMutationApplied_ScaleDeployment(t *testing.T) {
	plan := remediation.RemediationPlan{ActionType: remediation.ActionScaleDeployment}
	prep := PlanPrep{ForwardApplied: "3"}

	t.Run("live replica count matches what was applied", func(t *testing.T) {
		matched, err := verifyMutationApplied(plan, prep, map[string]any{"replicas": float64(3)})
		if err != nil {
			t.Fatalf("verifyMutationApplied: %v", err)
		}
		if !matched {
			t.Error("matched = false, want true — the live object shows exactly the replica count this plan applied")
		}
	})

	t.Run("live replica count does not match", func(t *testing.T) {
		matched, err := verifyMutationApplied(plan, prep, map[string]any{"replicas": float64(1)})
		if err != nil {
			t.Fatalf("verifyMutationApplied: %v", err)
		}
		if matched {
			t.Error("matched = true, want false — the live count disagrees with what was applied")
		}
	})

	t.Run("no forwardApplied recorded is never confirmed", func(t *testing.T) {
		matched, err := verifyMutationApplied(plan, PlanPrep{}, map[string]any{"replicas": float64(3)})
		if err != nil {
			t.Fatalf("verifyMutationApplied: %v", err)
		}
		if matched {
			t.Error("matched = true, want false — nothing to compare against without a recorded forwardApplied value")
		}
	})

	t.Run("unreadable live replica count is never confirmed", func(t *testing.T) {
		matched, err := verifyMutationApplied(plan, prep, map[string]any{})
		if err != nil {
			t.Fatalf("verifyMutationApplied: %v", err)
		}
		if matched {
			t.Error("matched = true, want false — spec.replicas is missing from the live object")
		}
	})
}

func TestVerifyMutationApplied_RevertContainerImage(t *testing.T) {
	plan := remediation.RemediationPlan{
		ActionType: remediation.ActionRevertContainerImage,
		Params:     remediation.RevertContainerImageParams{Container: "app"},
	}
	prep := PlanPrep{ForwardApplied: "app@sha256:old"}
	liveSpecWithImage := func(image string) map[string]any {
		return map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"containers": []any{
						map[string]any{"name": "app", "image": image},
					},
				},
			},
		}
	}

	t.Run("live image matches the resolved revert target", func(t *testing.T) {
		matched, err := verifyMutationApplied(plan, prep, liveSpecWithImage("app@sha256:old"))
		if err != nil {
			t.Fatalf("verifyMutationApplied: %v", err)
		}
		if !matched {
			t.Error("matched = false, want true")
		}
	})

	t.Run("live image still shows the pre-revert value", func(t *testing.T) {
		matched, err := verifyMutationApplied(plan, prep, liveSpecWithImage("app@sha256:new"))
		if err != nil {
			t.Fatalf("verifyMutationApplied: %v", err)
		}
		if matched {
			t.Error("matched = true, want false")
		}
	})

	t.Run("container unreadable post-mutation is never confirmed, not an error", func(t *testing.T) {
		matched, err := verifyMutationApplied(plan, prep, map[string]any{})
		if err != nil {
			t.Fatalf("verifyMutationApplied: want a nil error (an unreadable container is 'unknown', not a hard failure), got %v", err)
		}
		if matched {
			t.Error("matched = true, want false")
		}
	})
}

func TestVerifyMutationApplied_PatchResourceLimits(t *testing.T) {
	plan := remediation.RemediationPlan{
		ActionType: remediation.ActionPatchResourceLimits,
		Params: remediation.PatchResourceLimitsParams{
			Container: "app", MemoryLimit: "200Mi", MemoryRequest: "150Mi",
		},
	}
	liveSpecWithResources := func(memLimit, memRequest string) map[string]any {
		return map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name": "app",
							"resources": map[string]any{
								"limits":   map[string]any{"memory": memLimit},
								"requests": map[string]any{"memory": memRequest},
							},
						},
					},
				},
			},
		}
	}

	t.Run("every set field matches", func(t *testing.T) {
		matched, err := verifyMutationApplied(plan, PlanPrep{}, liveSpecWithResources("200Mi", "150Mi"))
		if err != nil {
			t.Fatalf("verifyMutationApplied: %v", err)
		}
		if !matched {
			t.Error("matched = false, want true — this is exactly BUGS.md 104's own live reproduction (memoryLimit 200Mi, memoryRequest 150Mi)")
		}
	})

	t.Run("one set field disagrees", func(t *testing.T) {
		matched, err := verifyMutationApplied(plan, PlanPrep{}, liveSpecWithResources("200Mi", "100Mi"))
		if err != nil {
			t.Fatalf("verifyMutationApplied: %v", err)
		}
		if matched {
			t.Error("matched = true, want false — memoryRequest disagrees with what this plan set")
		}
	})

	t.Run("a field this plan did not set is never compared", func(t *testing.T) {
		// The plan above sets no CPU fields at all — whatever the live
		// object's CPU values are must never affect the verdict.
		spec := liveSpecWithResources("200Mi", "150Mi")
		spec["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["resources"].(map[string]any)["limits"].(map[string]any)["cpu"] = "999"
		matched, err := verifyMutationApplied(plan, PlanPrep{}, spec)
		if err != nil {
			t.Fatalf("verifyMutationApplied: %v", err)
		}
		if !matched {
			t.Error("matched = false, want true — an unset field's live value must never affect the verdict")
		}
	})
}

func TestVerifyMutationApplied_RestartPod(t *testing.T) {
	plan := remediation.RemediationPlan{ActionType: remediation.ActionRestartPod}
	before := json.RawMessage(`{"spec":{"template":{"metadata":{"annotations":{"argus.io/restartedAt":"2026-08-01T00:00:00Z"}}}}}`)

	t.Run("the restart annotation changed", func(t *testing.T) {
		after := map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{
					"annotations": map[string]any{"argus.io/restartedAt": "2026-08-30T12:00:00Z"},
				},
			},
		}
		matched, err := verifyMutationApplied(plan, PlanPrep{LiveObject: before}, after)
		if err != nil {
			t.Fatalf("verifyMutationApplied: %v", err)
		}
		if !matched {
			t.Error("matched = false, want true — the annotation's value changed, which is exactly what a real restart looks like")
		}
	})

	t.Run("the restart annotation is unchanged", func(t *testing.T) {
		after := map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{
					"annotations": map[string]any{"argus.io/restartedAt": "2026-08-01T00:00:00Z"},
				},
			},
		}
		matched, err := verifyMutationApplied(plan, PlanPrep{LiveObject: before}, after)
		if err != nil {
			t.Fatalf("verifyMutationApplied: %v", err)
		}
		if matched {
			t.Error("matched = true, want false — an unchanged annotation is not evidence of a restart")
		}
	})

	t.Run("the annotation is absent from the live re-read", func(t *testing.T) {
		matched, err := verifyMutationApplied(plan, PlanPrep{LiveObject: before}, map[string]any{})
		if err != nil {
			t.Fatalf("verifyMutationApplied: %v", err)
		}
		if matched {
			t.Error("matched = true, want false")
		}
	})
}

func TestVerifyMutationApplied_UnscopedActionTypeIsNeverConfirmed(t *testing.T) {
	// AnnotateResource is a real, executable action type, but BACKLOG.md
	// C8's verify step is scoped to the four action types BUGS.md 104 names
	// (ScaleDeployment/RestartPod/PatchResourceLimits/RevertContainerImage).
	// Anything else must come back "not confirmed," never an error and
	// never a false confirmation.
	plan := remediation.RemediationPlan{ActionType: remediation.ActionAnnotateResource}
	matched, err := verifyMutationApplied(plan, PlanPrep{}, map[string]any{"anything": "goes"})
	if err != nil {
		t.Fatalf("verifyMutationApplied: %v", err)
	}
	if matched {
		t.Error("matched = true, want false — this action type is out of this verify step's declared scope")
	}
}

func TestSpecFromLiveObject(t *testing.T) {
	spec, err := specFromLiveObject(json.RawMessage(`{"metadata":{"name":"x"},"spec":{"replicas":3}}`))
	if err != nil {
		t.Fatalf("specFromLiveObject: %v", err)
	}
	if got, ok := spec["replicas"].(float64); !ok || got != 3 {
		t.Errorf("spec[\"replicas\"] = %v, want 3", spec["replicas"])
	}

	if _, err := specFromLiveObject(json.RawMessage(`not json`)); err == nil {
		t.Error("specFromLiveObject on malformed JSON: want an error, got nil")
	}
}

func TestLiveRestartedAtAnnotation(t *testing.T) {
	spec := map[string]any{
		"template": map[string]any{
			"metadata": map[string]any{
				"annotations": map[string]any{"argus.io/restartedAt": "2026-08-30T12:00:00Z"},
			},
		},
	}
	if v, ok := liveRestartedAtAnnotation(spec); !ok || v != "2026-08-30T12:00:00Z" {
		t.Errorf("liveRestartedAtAnnotation = (%q, %v), want (\"2026-08-30T12:00:00Z\", true)", v, ok)
	}

	// Every level missing, in turn — none of these should panic, and all
	// must report "not found" rather than a stale/zero value.
	for _, spec := range []map[string]any{
		{},
		{"template": map[string]any{}},
		{"template": map[string]any{"metadata": map[string]any{}}},
		{"template": map[string]any{"metadata": map[string]any{"annotations": map[string]any{}}}},
		{"template": "not a map"},
	} {
		if v, ok := liveRestartedAtAnnotation(spec); ok {
			t.Errorf("liveRestartedAtAnnotation(%+v) = (%q, true), want ok=false", spec, v)
		}
	}
}

// TestResolveIndeterminateOutcome_ReReadFailureReturnsUnknownNeverFailed
// exercises resolveIndeterminateOutcome's own re-read step for real — a real
// *gateway.Gateway with no cluster ever connected, so the follow-up
// describe_resource call inside FetchPreconditionWithObject fails exactly
// the way it would if the same tunnel drop that made the original mutating
// call indeterminate was still ongoing moments later. This is the
// "connection still down" half of BACKLOG.md C8's own text ("A confident
// mismatch or a re-read failure (connection still down, object gone) ->
// unknown"): the outcome must be "unknown", carrying both the original and
// the follow-up error, and never "failed" — asserting a second guess on top
// of an already-indeterminate result is exactly what this fix exists to
// stop doing.
func TestResolveIndeterminateOutcome_ReReadFailureReturnsUnknownNeverFailed(t *testing.T) {
	s := &Executor{gw: gateway.NewGateway(nil, nil, nil)}
	plan := remediation.RemediationPlan{ActionType: remediation.ActionScaleDeployment}
	prep := PlanPrep{TargetGVK: "apps/v1/Deployment", TargetNamespace: "ns", TargetName: "web", ForwardApplied: "3"}
	originalErr := fmt.Errorf("gateway: cluster cl_1 disconnected while awaiting a tool result: %w", gateway.ErrIndeterminate)

	outcome, execError := s.resolveIndeterminateOutcome(context.Background(), "cl_1", plan, prep, originalErr)

	if outcome != "unknown" {
		t.Fatalf("outcome = %q, want %q — the re-read itself failed (cluster not connected), so this must never be asserted as \"failed\"", outcome, "unknown")
	}
	if !strings.Contains(execError, "disconnected") {
		t.Errorf("execError = %q, want it to preserve the original tunnel error", execError)
	}
	if !strings.Contains(execError, "not connected") {
		t.Errorf("execError = %q, want it to also explain that the follow-up verify read failed", execError)
	}
}

// TestCheckResourceLimitsBound_FactorFloorUnblocksAPathologicallySmallRequest
// is the defect found by walking the approval path live (T5, 2026-09-17): an
// nginx container with a 4Mi memory request/limit was OOMKilled on every
// start, the plan (request -> 64Mi, limit -> 128Mi) was right, the cluster's
// own dry run accepted it, and the hub refused it at approval time because
// 64Mi is 16x 4Mi. The factor bound had no absolute floor, so it was
// strictest exactly where the live value was most obviously wrong.
//
// What must hold after the fix, in both directions — the floor is a widening
// of a safety control, so the cases it must NOT widen are the point of this
// test as much as the case it must.
func TestCheckResourceLimitsBound_FactorFloorUnblocksAPathologicallySmallRequest(t *testing.T) {
	cases := []struct {
		name    string
		live    containerResources
		params  remediation.PatchResourceLimitsParams
		wantErr bool
	}{
		{
			// The live case. 16x, but 64Mi cannot leave a pod Pending on any
			// node that can run a kubelet.
			name:    "the T5 live case: 4Mi request raised to 64Mi under the floor",
			live:    containerResources{MemoryLimit: "4Mi", MemoryRequest: "4Mi"},
			params:  remediation.PatchResourceLimitsParams{Container: "web", MemoryRequest: "64Mi", MemoryLimit: "128Mi"},
			wantErr: false,
		},
		{
			// Exactly at the floor is inside it, matching how the factor
			// ceiling itself treats exactly-4x as permitted.
			name:    "exactly at the memory floor",
			live:    containerResources{MemoryLimit: "512Mi", MemoryRequest: "4Mi"},
			params:  remediation.PatchResourceLimitsParams{Container: "web", MemoryRequest: "128Mi"},
			wantErr: false,
		},
		{
			// Above the floor and above 4x: still refused. A jump of this
			// size from a 4Mi request is a capacity decision, not a symptom
			// fix.
			name:    "past the floor from a tiny request is still refused",
			live:    containerResources{MemoryLimit: "2Gi", MemoryRequest: "4Mi"},
			params:  remediation.PatchResourceLimitsParams{Container: "web", MemoryRequest: "1Gi"},
			wantErr: true,
		},
		{
			// BUGS.md 95's live case, unchanged by the floor: 150Mi is above
			// 128Mi, so the 4x factor still decides it.
			name:    "BUGS.md 95's 20Mi -> 150Mi is still refused",
			live:    containerResources{MemoryLimit: "1Gi", MemoryRequest: "20Mi"},
			params:  remediation.PatchResourceLimitsParams{Container: "app", MemoryRequest: "150Mi"},
			wantErr: true,
		},
		{
			// The unit slip the factor exists for, from a base low enough
			// that only the floor could have rescued it. It does not.
			name:    "the unit slip is still caught",
			live:    containerResources{MemoryLimit: "64Gi", MemoryRequest: "128Mi"},
			params:  remediation.PatchResourceLimitsParams{Container: "app", MemoryRequest: "32Gi"},
			wantErr: true,
		},
		{
			// CPU has its own floor, and it is a quarter core, not half: the
			// 100m -> 500m case that guards the MilliValue rounding trap must
			// still refuse.
			name:    "cpuRequest 100m -> 500m is still refused",
			live:    containerResources{CPULimit: "4", CPURequest: "100m"},
			params:  remediation.PatchResourceLimitsParams{Container: "app", CPURequest: "500m"},
			wantErr: true,
		},
		{
			name:    "cpuRequest 10m -> 250m is inside the cpu floor",
			live:    containerResources{CPULimit: "4", CPURequest: "10m"},
			params:  remediation.PatchResourceLimitsParams{Container: "app", CPURequest: "250m"},
			wantErr: false,
		},
		{
			// A limit is not scheduled against, so the floor must not have
			// become a back door that bounds one: raising a limit far beyond
			// the floor was always permitted and still is.
			name:    "a limit increase is still unbounded by the factor",
			live:    containerResources{MemoryLimit: "4Mi", MemoryRequest: "4Mi"},
			params:  remediation.PatchResourceLimitsParams{Container: "web", MemoryLimit: "2Gi"},
			wantErr: false,
		},
	}
	for _, c := range cases {
		err := checkResourceLimitsBound(c.live, c.params, false)
		if c.wantErr && err == nil {
			t.Errorf("%s: checkResourceLimitsBound() = nil, want a refusal", c.name)
		}
		if !c.wantErr && err != nil {
			t.Errorf("%s: checkResourceLimitsBound() = %v, want nil", c.name, err)
		}
		if c.wantErr && err != nil && !errors.Is(err, ErrResourceLimitsBoundRefused) {
			t.Errorf("%s: refusal %v does not wrap ErrResourceLimitsBoundRefused", c.name, err)
		}
	}
}
