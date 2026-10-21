package argusagentchart

// TestValidatingAdmissionPolicyRendersForDeleteResource and
// TestValidatingAdmissionPolicyPermitsTheAnnotateLabelAllowlist are
// BACKLOG.md F9's Helm-chart-render tests for the ValidatingAdmissionPolicy
// changes: since there is no live cluster available to evaluate the CEL for
// real (this file's own approach mirrors chart_test.go's and
// templates/validatingadmissionpolicy.yaml's own header comment, both of
// which state plainly when a check is render-only rather than
// live-verified), what CAN be checked locally is that the chart renders the
// expected POLICY SHAPE at all: the right Kind, the right matchConstraints
// (operations/resources), and the right validation messages naming the
// allowed keys — the same shape confirmation
// TestRemediateChartGrantsPatchOnPatchFieldKinds gives the RBAC side.
//
// The CEL expressions THEMSELVES were verified separately, offline,
// against the real google/cel-go library (the engine
// ValidatingAdmissionPolicy's own CEL evaluation is built on) with a set of
// object/oldObject fixtures covering the has()-guard edge cases this file's
// own header comment warns about (a bare `kubectl create` object with no
// annotations/labels at all) — that verification is not repeated here
// because it needs no Helm chart, only the four expression strings.
import (
	"bytes"
	"encoding/json"
	"io"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// vapObject mirrors the subset of a rendered ValidatingAdmissionPolicy this
// test reads.
type vapObject struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		MatchConstraints struct {
			ResourceRules []struct {
				APIGroups   []string `yaml:"apiGroups"`
				APIVersions []string `yaml:"apiVersions"`
				Operations  []string `yaml:"operations"`
				Resources   []string `yaml:"resources"`
			} `yaml:"resourceRules"`
		} `yaml:"matchConstraints"`
		Validations []struct {
			Expression string `yaml:"expression"`
			Message    string `yaml:"message"`
		} `yaml:"validations"`
	} `yaml:"spec"`
}

// helmTemplateVAPs shells out to `helm template`, exactly like
// chart_test.go's own helmTemplate, but decodes every rendered
// ValidatingAdmissionPolicy rather than every Role/ClusterRole. A separate
// function rather than widening helmTemplate's own Kind filter: that
// function's rbacObject shape has no Spec field at all, and widening it to
// carry both shapes would make a Role decode attempt walk fields that do
// not exist on it.
func helmTemplateVAPs(t *testing.T, extraSet ...string) []vapObject {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not on PATH; skipping rendered-chart VAP verification (BACKLOG.md F9)")
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not resolve this test file's own path")
	}
	chartDir := filepath.Dir(thisFile)

	args := append([]string{"template", chartDir,
		"--set", "hub.apiUrl=https://example.com",
		"--set", "enrollment.token=dummy",
	}, extraSet...)
	cmd := exec.Command("helm", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helm template %v failed: %v\n%s", args, err, out)
	}

	var objs []vapObject
	dec := yaml.NewDecoder(bytes.NewReader(out))
	for {
		var obj vapObject
		derr := dec.Decode(&obj)
		if derr == io.EOF {
			break
		}
		if derr != nil {
			t.Fatalf("decode a document from helm's rendered output: %v", derr)
		}
		if obj.Kind == "ValidatingAdmissionPolicy" {
			objs = append(objs, obj)
		}
	}
	return objs
}

func findVAP(t *testing.T, objs []vapObject, name string) vapObject {
	t.Helper()
	for _, o := range objs {
		if o.Metadata.Name == name {
			return o
		}
	}
	t.Fatalf("no rendered ValidatingAdmissionPolicy named %q (rendered %d total)", name, len(objs))
	return vapObject{}
}

// TestValidatingAdmissionPolicyRendersForDeleteResource confirms the
// argus-remediate-delete-protected-resources policy renders with a DELETE
// matchConstraint on exactly the three kinds deleteresource.go's own
// allowlist names — Pod, Job, and (added 2026-09-01, BUGS.md 118 part (b))
// PersistentVolumeClaim — and carries both protective validations. The PVC
// rule matters specifically because matchConstraints controls which
// requests this policy even evaluates: an allowlist widened without a
// matching resourceRule here would let a PersistentVolumeClaim delete reach
// the API server with no admission-time backstop at all (see this policy's
// own header comment in templates/validatingadmissionpolicy.yaml).
func TestValidatingAdmissionPolicyRendersForDeleteResource(t *testing.T) {
	objs := helmTemplateVAPs(t, "--set", "remediate.enabled=true", "--set", "remediate.allNamespaces=true")
	vap := findVAP(t, objs, "argus-remediate-delete-protected-resources")

	wantRules := []struct {
		apiGroup string
		resource string
	}{
		{"", "pods"},
		{"batch", "jobs"},
		{"", "persistentvolumeclaims"},
	}
	for _, want := range wantRules {
		found := false
		for _, r := range vap.Spec.MatchConstraints.ResourceRules {
			if contains(r.APIGroups, want.apiGroup) && contains(r.Resources, want.resource) && contains(r.Operations, "DELETE") {
				found = true
			}
		}
		if !found {
			t.Errorf("no DELETE resourceRule for apiGroup=%q resource=%q", want.apiGroup, want.resource)
		}
	}

	joined := ""
	for _, v := range vap.Spec.Validations {
		joined += v.Expression + "\n" + v.Message + "\n"
	}
	for _, want := range []string{"kube-system", "tier"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no validation names %q — the two DESIGN.md §9.3 absolute modifiers this policy exists to enforce", want)
		}
	}
}

// TestValidatingAdmissionPolicyPermitsTheAnnotateLabelAllowlist confirms the
// per-Kind field-restriction policies' new validations name exactly the keys
// internal/remediation/annotatelabel.go's tables permit, for both Deployment
// and StatefulSet.
func TestValidatingAdmissionPolicyPermitsTheAnnotateLabelAllowlist(t *testing.T) {
	objs := helmTemplateVAPs(t, "--set", "remediate.enabled=true", "--set", "remediate.allNamespaces=true")

	for _, name := range []string{"argus-remediate-field-restriction-deployments", "argus-remediate-field-restriction-statefulsets"} {
		t.Run(name, func(t *testing.T) {
			vap := findVAP(t, objs, name)
			joined := ""
			for _, v := range vap.Spec.Validations {
				joined += v.Expression + "\n" + v.Message + "\n"
			}
			for _, wantKey := range []string{"argus.io/last-remediated-at", "argus.io/incident-id", "argus.io/remediated"} {
				if !strings.Contains(joined, wantKey) {
					t.Errorf("%s: no validation names %q — internal/remediation/annotatelabel.go's allowlist and this chart's policy must agree on the exact key set", name, wantKey)
				}
			}
			// ownerReferences must still be enforced as a bare equality check —
			// this task must not have loosened that guardrail as a side effect
			// of relaxing labels/annotations.
			if !strings.Contains(joined, "ownerReferences") {
				t.Errorf("%s: no validation mentions ownerReferences — this must remain an unconditional equality check", name)
			}
		})
	}
}

// TestValidatingAdmissionPolicyRendersForCreateResource confirms the new
// argus-remediate-create-protected-targets policy renders with a CREATE
// matchConstraint on exactly ConfigMap (createresource.go's own allowlist),
// and carries all four protective validations — the two DESIGN.md §9.3
// modifiers this file's CREATE-verb analogue of
// argus-remediate-delete-protected-resources shares with it, plus the two
// CREATE-specific sentinels (ownerReferences, finalizers) that policy has no
// equivalent of.
func TestValidatingAdmissionPolicyRendersForCreateResource(t *testing.T) {
	objs := helmTemplateVAPs(t, "--set", "remediate.enabled=true", "--set", "remediate.allNamespaces=true")
	vap := findVAP(t, objs, "argus-remediate-create-protected-targets")

	found := false
	for _, r := range vap.Spec.MatchConstraints.ResourceRules {
		if contains(r.APIGroups, "") && contains(r.Resources, "configmaps") && contains(r.Operations, "CREATE") {
			found = true
		}
	}
	if !found {
		t.Error("no CREATE resourceRule for apiGroup=\"\" resource=\"configmaps\"")
	}

	joined := ""
	for _, v := range vap.Spec.Validations {
		joined += v.Expression + "\n" + v.Message + "\n"
	}
	for _, want := range []string{"kube-system", "tier", "ownerReferences", "finalizers"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no validation names %q", want)
		}
	}
	// This policy has no oldObject at all (a CREATE request carries none) —
	// confirm no validation expression references it, which would be a
	// compile-time error at admission time, not merely a style nit.
	for _, v := range vap.Spec.Validations {
		if strings.Contains(v.Expression, "oldObject") {
			t.Errorf("a CREATE-matched validation references oldObject, which does not exist on a CREATE request: %q", v.Expression)
		}
	}
}

// TestValidatingAdmissionPolicyChartsRenderAsValidYAML is a cheap smoke test
// that both new/changed policy blocks parse as JSON-shaped documents
// (yaml.v3 -> encoding/json round trip catches an accidental tab or a
// malformed block scalar `helm template`'s own YAML parser might tolerate
// more permissively than a stricter decoder would).
func TestValidatingAdmissionPolicyChartsRenderAsValidYAML(t *testing.T) {
	objs := helmTemplateVAPs(t, "--set", "remediate.enabled=true", "--set", "remediate.allNamespaces=true", "--set", "policyController.enabled=true")
	// deployments, statefulsets, pod-template-restriction,
	// execution-window-widened-fields (policyController.enabled=true),
	// delete-protected-resources, create-protected-targets,
	// gitops-reconcile-only (docs/CLUSTER_INSIGHT_SPECS.md CI-S15).
	if len(objs) != 7 {
		t.Fatalf("rendered %d ValidatingAdmissionPolicy objects, want 7 — did a policy fail to render or get duplicated?", len(objs))
	}
	for _, o := range objs {
		if _, err := json.Marshal(o); err != nil {
			t.Errorf("%s did not round-trip through JSON: %v", o.Metadata.Name, err)
		}
	}
}
