package argusagentchart

// TestRemediateChartGrantsPatchOnPatchFieldKinds renders this chart with `helm
// template` and confirms the RBAC rows BACKLOG.md "still open" #9 (2026-08-29)
// added actually appear, with the right verbs, in both shapes this chart can
// render the write pack as. It exists because a Go unit test cannot exercise a
// Helm chart at all — internal/remediation/patchfield_test.go proves the
// allowlist believes these kinds are grantable, but nothing before this
// checked that the chart text actually grants them, in either the
// cluster-wide ClusterRole (templates/clusterrole.yaml) or the namespace-
// scoped Role (templates/remediate-role.yaml) that remediate.namespaces
// selects instead — and those two are supposed to be identical
// (remediate-role.yaml's own header: "if these two rule sets ever diverge,
// the divergence is the bug"), which this test also therefore checks.
//
// No live cluster involved — `helm template` only renders YAML locally, the
// same verification templates/validatingadmissionpolicy.yaml's own header
// comment cites for chart-level checks that don't need a real API server.
//
// Skips (rather than fails) when `helm` isn't on PATH, matching this repo's
// existing convention for environment-gated tests (e.g.
// internal/gitops/live_test.go, gated on ARGUS_GITOPS_LIVE) — CI
// (.github/workflows/ci.yml) does not install Helm today, so this exercises
// locally and wherever Helm is present, not yet as a CI gate.

import (
	"bytes"
	"io"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"gopkg.in/yaml.v3"
)

// rbacRule mirrors the subset of a Role/ClusterRole rule this test reads.
type rbacRule struct {
	APIGroups []string `yaml:"apiGroups"`
	Resources []string `yaml:"resources"`
	Verbs     []string `yaml:"verbs"`
}

// rbacObject mirrors the subset of a rendered Role/ClusterRole this test reads.
type rbacObject struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Rules []rbacRule `yaml:"rules"`
}

// helmTemplate shells out to `helm template` for this chart with the given
// extra --set values layered on top of the minimum every render needs
// (hub.apiUrl and enrollment.token — required and empty-string-invalid
// respectively per values.yaml), and returns every rendered object whose Kind
// is a Role or ClusterRole. t.Skip()s if helm isn't installed; t.Fatal()s on
// any other failure, since a chart that fails to render at all is exactly
// what this test exists to catch.
func helmTemplate(t *testing.T, extraSet ...string) []rbacObject {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not on PATH; skipping rendered-chart RBAC verification (BACKLOG.md \"still open\" #9)")
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

	var objs []rbacObject
	dec := yaml.NewDecoder(bytes.NewReader(out))
	for {
		var obj rbacObject
		derr := dec.Decode(&obj)
		if derr == io.EOF {
			break
		}
		if derr != nil {
			t.Fatalf("decode a document from helm's rendered output: %v", derr)
		}
		if obj.Kind == "Role" || obj.Kind == "ClusterRole" {
			objs = append(objs, obj)
		}
	}
	return objs
}

// findRole returns the first rendered Role/ClusterRole matching kind and name,
// failing the test if none rendered — a missing role is exactly the "the write
// grant silently isn't there" failure this test exists to catch, so it must
// not be reported as an empty rule set.
func findRole(t *testing.T, objs []rbacObject, kind, name string) rbacObject {
	t.Helper()
	for _, o := range objs {
		if o.Kind == kind && o.Metadata.Name == name {
			return o
		}
	}
	t.Fatalf("no rendered %s named %q (rendered %d Role/ClusterRole objects total)", kind, name, len(objs))
	return rbacObject{}
}

// hasRule reports whether rules contains an entry granting verb on resource
// within apiGroup — group/resource/verb may each be satisfied by a different
// rule's list entry, matching how the Kubernetes RBAC authorizer itself
// evaluates "is this verb allowed" (a resource's own rule doesn't need to be
// the same list element as the group's).
//
// Deliberately per-rule-conjunctive rather than a single OR of all list
// members across all three fields: a rule that grants group X, resource Y,
// verb Z must have all three together to authorise anything, so this checks
// group&&resource&&verb within one rule, then ORs across rules — anything
// looser would pass a chart where the group/resource/verb triple was split
// across unrelated rules that individually authorise nothing.
func hasRule(rules []rbacRule, apiGroup, resource, verb string) bool {
	for _, r := range rules {
		if contains(r.APIGroups, apiGroup) && contains(r.Resources, resource) && contains(r.Verbs, verb) {
			return true
		}
	}
	return false
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// TestRemediateChartGrantsPatchOnPatchFieldKinds is this file's one test —
// see the package doc comment above for the full "why".
func TestRemediateChartGrantsPatchOnPatchFieldKinds(t *testing.T) {
	// The five (apiGroup, resource) pairs BACKLOG.md "still open" #9
	// (2026-08-29) unblocked, matching internal/remediation/patchfield.go's
	// now-resolved NeedsGrant strings exactly.
	wants := []struct {
		name     string
		apiGroup string
		resource string
	}{
		{"Service", "", "services"},
		{"Ingress", "networking.k8s.io", "ingresses"},
		{"HorizontalPodAutoscaler", "autoscaling", "horizontalpodautoscalers"},
		{"PodDisruptionBudget", "policy", "poddisruptionbudgets"},
		{"CronJob", "batch", "cronjobs"},
	}

	t.Run("cluster-wide (remediate.allNamespaces)", func(t *testing.T) {
		objs := helmTemplate(t,
			"--set", "remediate.enabled=true",
			"--set", "remediate.allNamespaces=true",
		)
		role := findRole(t, objs, "ClusterRole", "argus-remediate")
		for _, w := range wants {
			t.Run(w.name, func(t *testing.T) {
				if !hasRule(role.Rules, w.apiGroup, w.resource, "patch") {
					t.Errorf("templates/clusterrole.yaml's argus-remediate ClusterRole does not grant patch on %s/%s", w.apiGroup, w.resource)
				}
			})
		}
		// PodDisruptionBudget is the one row whose NeedsGrant named
		// get/list/watch too — assert those explicitly rather than only patch.
		for _, verb := range []string{"get", "list", "watch"} {
			if !hasRule(role.Rules, "policy", "poddisruptionbudgets", verb) {
				t.Errorf("templates/clusterrole.yaml's argus-remediate ClusterRole does not grant %s on policy/poddisruptionbudgets", verb)
			}
		}
	})

	t.Run("namespace-scoped (remediate.namespaces)", func(t *testing.T) {
		objs := helmTemplate(t,
			"--set", "remediate.enabled=true",
			"--set", "remediate.namespaces={apps}",
		)
		role := findRole(t, objs, "Role", "argus-remediate")
		if role.Metadata.Namespace != "apps" {
			t.Errorf("rendered Role's namespace = %q, want %q", role.Metadata.Namespace, "apps")
		}
		for _, w := range wants {
			t.Run(w.name, func(t *testing.T) {
				if !hasRule(role.Rules, w.apiGroup, w.resource, "patch") {
					t.Errorf("templates/remediate-role.yaml's argus-remediate Role does not grant patch on %s/%s — it must mirror templates/clusterrole.yaml exactly (that file's own header comment: \"if these two rule sets ever diverge, the divergence is the bug\")", w.apiGroup, w.resource)
				}
			})
		}
	})

	t.Run("remediate disabled grants none of it", func(t *testing.T) {
		// The negative case: nothing here should render at all when the write
		// pack is off, matching every other opt-in identity in this chart.
		objs := helmTemplate(t) // remediate.enabled defaults to false
		for _, o := range objs {
			if o.Metadata.Name == "argus-remediate" {
				t.Fatalf("an argus-remediate %s rendered with remediate.enabled left at its default (false)", o.Kind)
			}
		}
	})
}
