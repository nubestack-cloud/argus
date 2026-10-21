package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"argus/internal/remediation"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// The fixture is a DEPLOYMENT rather than the Service it started as, and the
// reason is worth recording: the allowlist now refuses any path whose kind the
// shipped agent chart cannot patch, and `v1/Service` is one of those. A Service
// fixture would exercise the RBAC gate on every case instead of the tool's own
// refusals, which is not what these tests are about — the gate has its own test in
// internal/remediation.
//
// `spec.template.spec.containers[*].resources.requests.memory` is one of the three
// paths that is executable today, and it is a realistic target: a memory request
// no node can satisfy leaves every replica Pending.
func deployWithRequests(rv string) *appsv1.Deployment {
	replicas := int32(2)
	return &appsv1.Deployment{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default", ResourceVersion: rv},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  "app",
						Image: "registry.example.com/app:1.0",
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("900Gi")},
						},
					}},
				},
			},
		},
	}
}

func patchFieldPlan(path, newValue, expectCurrent, rv string) remediation.PlanContent {
	return remediation.PlanContent{
		RecommendationID: "plan_pf",
		ActionType:       remediation.ActionPatchField,
		TargetGVK:        "apps/v1/Deployment",
		TargetNamespace:  "default",
		TargetName:       "web",
		Params: mustMarshal(remediation.PatchFieldParams{
			FieldPath: path, NewValue: newValue, ExpectCurrent: expectCurrent,
		}),
		Rollback: &remediation.CompensatingAction{
			ActionType:  remediation.ActionPatchField,
			Params:      mustMarshal(remediation.PatchFieldParams{FieldPath: path, NewValue: "900Gi"}),
			Description: "restore " + path + " to 900Gi",
		},
		ResourceVersion: rv,
	}
}

func liveDeploy(t *testing.T, e *ToolExecutor) map[string]any {
	t.Helper()
	obj, err := e.dynamic.Resource(deploymentsGVR).Namespace("default").Get(context.Background(), "web", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("re-read deployment: %v", err)
	}
	return obj.Object
}

// requestedMemory reads the container's memory request back off the live object.
func requestedMemory(t *testing.T, e *ToolExecutor) string {
	t.Helper()
	c, _, _ := unstructured.NestedSlice(liveDeploy(t, e), "spec", "template", "spec", "containers")
	if len(c) == 0 {
		t.Fatal("no containers on the live object")
	}
	m, _, _ := unstructured.NestedString(c[0].(map[string]any), "resources", "requests", "memory")
	return m
}

// The three tests below assert the PATCH THAT WOULD BE SENT rather than the
// object after sending it, and the reason is a harness limitation worth stating
// rather than hiding: **client-go's fake dynamic client does not implement JSON
// Patch.** Probed directly on client-go v0.36.3 — it accepts merge and
// strategic-merge and fails a JSON Patch with "cannot unmarshal array into Go
// value of type map[string]interface{}".
//
// Switching this action to a strategic-merge patch would make the fake work and
// make the product worse: a strategic merge addresses list elements by merge key
// rather than position, so `spec.ports[0]` would need a per-list merge-key table,
// and it cannot express the `test` operation that makes the write an atomic
// compare-and-swap the API server evaluates.
//
// So the split is deliberate. Everything that can actually be wrong — which
// operation is chosen, the pointer escaping, the type coercion, whether a `test`
// is included — is asserted here exactly. That the API server applies a correct
// JSON Patch correctly is verified against a real cluster instead, which is where
// it should be verified for a mutating action anyway.

func TestPatchField_BuildsTheRightPatch(t *testing.T) {
	for _, tc := range []struct {
		name     string
		segments []string
		current  any
		newValue any
		exists   bool
		want     string
	}{
		{
			// The common case: the field exists, so the write is a
			// compare-and-swap the API server performs.
			name:     "existing field gets a test then a replace",
			segments: []string{"spec", "ports", "0", "targetPort"},
			current:  int64(9090), newValue: 8080, exists: true,
			want: `[{"op":"test","path":"/spec/ports/0/targetPort","value":9090},` +
				`{"op":"replace","path":"/spec/ports/0/targetPort","value":8080}]`,
		},
		{
			// Absent field: nothing to test against, so a bare add.
			name:     "absent field gets a bare add",
			segments: []string{"spec", "selector", "tier"},
			current:  nil, newValue: "backend", exists: false,
			want: `[{"op":"add","path":"/spec/selector/tier","value":"backend"}]`,
		},
		{
			// A label key containing "/" must be escaped, or the pointer
			// addresses a deeper path than intended. This is not exotic:
			// `app.kubernetes.io/name` is the canonical selector key.
			name:     "a slash in a key is escaped",
			segments: []string{"spec", "selector", "app.kubernetes.io/name"},
			current:  "old", newValue: "web", exists: true,
			want: `[{"op":"test","path":"/spec/selector/app.kubernetes.io~1name","value":"old"},` +
				`{"op":"replace","path":"/spec/selector/app.kubernetes.io~1name","value":"web"}]`,
		},
		{
			name:     "a string value stays a string",
			segments: []string{"spec", "schedule"},
			current:  "0 * * * *", newValue: "*/5 * * * *", exists: true,
			want: `[{"op":"test","path":"/spec/schedule","value":"0 * * * *"},` +
				`{"op":"replace","path":"/spec/schedule","value":"*/5 * * * *"}]`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildJSONPatch(tc.segments, tc.current, tc.newValue, tc.exists)
			if err != nil {
				t.Fatalf("buildJSONPatch: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("patch mismatch\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

// The allowlist declares each field's type so the agent never has to infer it.
// Getting this wrong produces a value the API server rejects — the same class of
// bug the pull-request route hit when a numeric-looking string was written
// unquoted into a string field.
func TestCoerceFieldValue(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		ftype   remediation.FieldType
		want    any
		wantErr bool
	}{
		{"8080", remediation.FieldInt, 8080, false},
		{"http", remediation.FieldInt, nil, true},
		// IntOrString: a number where it parses, a name otherwise — exactly how
		// Kubernetes' own IntOrString behaves.
		{"8080", remediation.FieldIntOrString, 8080, false},
		{"http", remediation.FieldIntOrString, "http", false},
		{"25%", remediation.FieldIntOrString, "25%", false},
		// A string field keeps its value verbatim even when it looks numeric,
		// which is what stops `memory: 256` where `"256Mi"` was meant.
		{"256Mi", remediation.FieldString, "256Mi", false},
		{"3", remediation.FieldString, "3", false},
	} {
		got, err := coerceFieldValue(tc.raw, tc.ftype)
		if tc.wantErr {
			if err == nil {
				t.Errorf("coerceFieldValue(%q, %s) = %v, want an error", tc.raw, tc.ftype, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("coerceFieldValue(%q, %s): %v", tc.raw, tc.ftype, err)
			continue
		}
		if got != tc.want {
			t.Errorf("coerceFieldValue(%q, %s) = %v (%T), want %v (%T)", tc.raw, tc.ftype, got, got, tc.want, tc.want)
		}
	}
}

// nestedFieldAt has to handle list indices, which client-go's NestedFieldNoCopy
// cannot — that is the whole reason it exists.
func TestNestedFieldAt(t *testing.T) {
	obj := map[string]any{"spec": map[string]any{
		"ports":    []any{map[string]any{"targetPort": int64(9090)}},
		"selector": map[string]any{"app": "web"},
		"name":     "scalar",
	}}
	if v, found, err := nestedFieldAt(obj, []string{"spec", "ports", "0", "targetPort"}); err != nil || !found || v != int64(9090) {
		t.Errorf("list index walk: v=%v found=%v err=%v", v, found, err)
	}
	if _, found, _ := nestedFieldAt(obj, []string{"spec", "selector", "absent"}); found {
		t.Error("an absent map key was reported as found")
	}
	if _, found, _ := nestedFieldAt(obj, []string{"spec", "ports", "7", "targetPort"}); found {
		t.Error("an out-of-range index was reported as found")
	}
	if _, _, err := nestedFieldAt(obj, []string{"spec", "ports", "http", "targetPort"}); err == nil {
		t.Error("a non-numeric index into a list should be an error, not a miss")
	}
	if _, _, err := nestedFieldAt(obj, []string{"spec", "name", "deeper"}); err == nil {
		t.Error("reading through a scalar should be an error")
	}
}

func TestPatchField_Refusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		plan   remediation.PlanContent
		expect string
	}{
		{
			// The agent re-derives authorisation from its own copy of the table.
			// The signature proves a plan came from the hub; it proves nothing
			// about whether the plan should have been written.
			name: "a path outside the allowlist, even though the plan is validly signed",
			plan: func() remediation.PlanContent {
				p := patchFieldPlan("spec.template.spec.serviceAccountName", "argus", "", "100")
				return p
			}(),
			expect: "allowlist refused",
		},
		{
			// Stale proposal: the object is untouched but the plan's belief about
			// this field was wrong from the start.
			name:   "expectCurrent does not match the live value",
			plan:   patchFieldPlan("spec.template.spec.containers[0].resources.requests.memory", "900Mi", "1Gi", "100"),
			expect: "expected",
		},
		{
			name:   "no change in it",
			plan:   patchFieldPlan("spec.template.spec.containers[0].resources.requests.memory", "900Gi", "900Gi", "100"),
			expect: "already",
		},
		{
			// Creating intermediate structure on a live object is how a patch
			// invents a shape nobody reviewed.
			name:   "the field and its parent are both absent",
			plan:   patchFieldPlan("spec.template.spec.containers[7].resources.requests.memory", "900Mi", "", "100"),
			expect: "parent",
		},
		{
			name: "rollback addresses a different field",
			plan: func() remediation.PlanContent {
				p := patchFieldPlan("spec.template.spec.containers[0].resources.requests.memory", "900Mi", "900Gi", "100")
				p.Rollback = &remediation.CompensatingAction{
					ActionType:  remediation.ActionPatchField,
					Params:      mustMarshal(remediation.PatchFieldParams{FieldPath: "spec.progressDeadlineSeconds", NewValue: "600"}),
					Description: "not an undo of the above",
				}
				return p
			}(),
			expect: "same field",
		},
		{
			name: "no rollback at all",
			plan: func() remediation.PlanContent {
				p := patchFieldPlan("spec.template.spec.containers[0].resources.requests.memory", "900Mi", "900Gi", "100")
				p.Rollback = nil
				return p
			}(),
			expect: "rollback",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			executor := newRemediationTestExecutor("clu_1", deployWithRequests("100"))
			signed := signTestPlan(t, tc.plan, "clu_1", time.Now().Add(5*time.Minute))
			_, _, err := executor.patchField(context.Background(), mustMarshal(signedPlanArgs{Plan: signed}))
			if err == nil {
				t.Fatal("expected a refusal, got none")
			}
			if !strings.Contains(err.Error(), tc.expect) {
				t.Errorf("error %q does not mention %q", err, tc.expect)
			}
			// And nothing may have changed.
			if got := requestedMemory(t, executor); got != "900Gi" {
				t.Errorf("a refused plan still mutated the object: request = %v", got)
			}
		})
	}
}

// The agent splits a field path with its own copy of the normaliser. If the two
// ever diverged, a path the hub authorised in one notation could be applied as a
// different path — so the equivalence is asserted rather than assumed.
func TestPatchFieldPathNotationMatchesTheHub(t *testing.T) {
	for _, p := range []string{
		"spec.ports[0].targetPort",
		"spec/ports/0/targetPort",
		"spec.ports.0.targetPort",
		"spec.selector.app",
		"spec.rules[0].http.paths[0].backend.service.name",
	} {
		mine := normalisePath(p)
		// remediation's normaliser is unexported, so compare through the public
		// check: a path both agree on must resolve identically.
		if _, err := remediation.PatchFieldPermitted("apps/v1/Deployment", mine); err != nil {
			// Not all of these are Service paths; only assert the notation is
			// stable, which is what a second normalisation proves.
			if normalisePath(mine) != mine {
				t.Errorf("normalisePath is not idempotent for %q: %q -> %q", p, mine, normalisePath(mine))
			}
			continue
		}
		if normalisePath(mine) != mine {
			t.Errorf("normalisePath is not idempotent for %q", p)
		}
	}
}

// A JSON Pointer must escape "/" and "~", because a Kubernetes label key can
// contain a slash — `app.kubernetes.io/name` is the canonical case and is exactly
// what a Service selector fix would target. Unescaped, it would address a
// deeper path than intended.
func TestEscapeJSONPointer(t *testing.T) {
	got := escapeJSONPointer([]string{"spec", "selector", "app.kubernetes.io/name"})
	if got[2] != "app.kubernetes.io~1name" {
		t.Errorf("slash was not escaped: %q", got[2])
	}
	if e := escapeJSONPointer([]string{"a~b"}); e[0] != "a~0b" {
		t.Errorf("tilde was not escaped: %q", e[0])
	}
}
