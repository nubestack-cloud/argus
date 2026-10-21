package argusagentchart

// chart_metrics_test.go is BACKLOG.md C4's Helm-chart-render test for
// query_metrics' RBAC half (templates/metrics.yaml, values.yaml's
// metrics.prometheusService) — the same "no live cluster needed, `helm
// template` renders locally" verification chart_test.go's own header comment
// gives for the remediate/patchfield RBAC checks, applied here to a
// namespace-scoped Role+RoleBinding pair instead of a ClusterRole.
//
// Reuses chart_test.go's helmTemplate/findRole/hasRule/contains for the Role
// half (rbacObject already has everything a Role needs). The RoleBinding
// half and the "partial config" failure case need their own small decode
// shape, since rbacObject carries no Subjects/RoleRef fields — the same
// "separate function rather than widen an existing type for a different
// Kind's fields" choice chart_vap_test.go's own helmTemplateVAPs makes.

import (
	"bytes"
	"io"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"gopkg.in/yaml.v3"
)

// metricsRoleBindingObject mirrors the subset of a rendered RoleBinding this
// test reads.
type metricsRoleBindingObject struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Subjects []struct {
		Kind      string `yaml:"kind"`
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"subjects"`
	RoleRef struct {
		Kind string `yaml:"kind"`
		Name string `yaml:"name"`
	} `yaml:"roleRef"`
}

// metricsRoleWithNames is a Role decode that ALSO carries resourceNames per
// rule — chart_test.go's rbacRule/rbacObject deliberately omit that field
// (none of the roles that test reads use it), so this test needs its own
// shape to confirm the grant is narrowed to the ONE configured Service name,
// not left as a bare resource-type grant.
type metricsRoleWithNames struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Rules []struct {
		APIGroups     []string `yaml:"apiGroups"`
		Resources     []string `yaml:"resources"`
		Verbs         []string `yaml:"verbs"`
		ResourceNames []string `yaml:"resourceNames"`
	} `yaml:"rules"`
}

// helmTemplateRaw shells out to `helm template` and returns the raw rendered
// output (or the error `helm` itself returned) without decoding anything —
// the shape TestMetricsChartRefusesPartialConfig needs, since what it must
// observe is a FAILED render, which helmTemplate's own t.Fatalf-on-error
// behavior would turn into a test failure rather than a result to assert on.
func helmTemplateRaw(t *testing.T, extraSet ...string) ([]byte, error) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not on PATH; skipping rendered-chart verification (BACKLOG.md C4)")
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
	return cmd.CombinedOutput()
}

func decodeYAMLDocs[T any](t *testing.T, out []byte, keep func(kind string) bool) []T {
	t.Helper()
	var objs []T
	dec := yaml.NewDecoder(bytes.NewReader(out))
	for {
		var obj struct {
			Kind string `yaml:"kind"`
		}
		var raw yaml.Node
		derr := dec.Decode(&raw)
		if derr == io.EOF {
			break
		}
		if derr != nil {
			t.Fatalf("decode a document from helm's rendered output: %v", derr)
		}
		if err := raw.Decode(&obj); err != nil {
			t.Fatalf("decode a document's kind: %v", err)
		}
		if !keep(obj.Kind) {
			continue
		}
		var typed T
		if err := raw.Decode(&typed); err != nil {
			t.Fatalf("decode a %s document: %v", obj.Kind, err)
		}
		objs = append(objs, typed)
	}
	return objs
}

// TestMetricsChartGrantsProxyOnConfiguredService pins the positive case:
// with metrics.prometheusService set, the chart renders exactly the Role +
// RoleBinding pair templates/metrics.yaml describes, granting `get` on
// services/proxy narrowed to the configured Service name, bound to the
// ordinary argus-investigate ServiceAccount (never argus-dryrun/
// argus-remediate/argus-policy-controller).
func TestMetricsChartGrantsProxyOnConfiguredService(t *testing.T) {
	extraSet := []string{
		"--set", "metrics.prometheusService.namespace=cattle-monitoring-system",
		"--set", "metrics.prometheusService.name=rancher-monitoring-prometheus",
	}

	roleObjs := helmTemplate(t, extraSet...)
	role := findRole(t, roleObjs, "Role", "argus-investigate-metrics")
	if role.Metadata.Namespace != "cattle-monitoring-system" {
		t.Errorf("rendered Role's namespace = %q, want %q (the configured Prometheus namespace, not this chart's own agent namespace)", role.Metadata.Namespace, "cattle-monitoring-system")
	}
	if !hasRule(role.Rules, "", "services/proxy", "get") {
		t.Error("templates/metrics.yaml's argus-investigate-metrics Role does not grant get on services/proxy")
	}

	out, err := helmTemplateRaw(t, extraSet...)
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, out)
	}

	roleWithNames := decodeYAMLDocs[metricsRoleWithNames](t, out, func(k string) bool { return k == "Role" })
	found := false
	for _, r := range roleWithNames {
		if r.Metadata.Name != "argus-investigate-metrics" {
			continue
		}
		found = true
		for _, rule := range r.Rules {
			if !contains(rule.ResourceNames, "rancher-monitoring-prometheus") {
				t.Errorf("argus-investigate-metrics Role's rule %+v does not narrow resourceNames to the configured Service — this grant must not be a bare, unnamed services/proxy grant", rule)
			}
		}
	}
	if !found {
		t.Fatal("no rendered Role named argus-investigate-metrics carrying resourceNames")
	}

	bindings := decodeYAMLDocs[metricsRoleBindingObject](t, out, func(k string) bool { return k == "RoleBinding" })
	var binding *metricsRoleBindingObject
	for i := range bindings {
		if bindings[i].Metadata.Name == "argus-investigate-metrics" {
			binding = &bindings[i]
		}
	}
	if binding == nil {
		t.Fatal("no rendered RoleBinding named argus-investigate-metrics")
	}
	if binding.Metadata.Namespace != "cattle-monitoring-system" {
		t.Errorf("RoleBinding namespace = %q, want %q", binding.Metadata.Namespace, "cattle-monitoring-system")
	}
	if binding.RoleRef.Kind != "Role" || binding.RoleRef.Name != "argus-investigate-metrics" {
		t.Errorf("RoleBinding roleRef = %+v, want Role/argus-investigate-metrics", binding.RoleRef)
	}
	if len(binding.Subjects) != 1 || binding.Subjects[0].Kind != "ServiceAccount" || binding.Subjects[0].Name != "argus-investigate" || binding.Subjects[0].Namespace != "argus-system" {
		t.Errorf("RoleBinding subjects = %+v, want exactly the argus-investigate ServiceAccount in argus-system — never argus-dryrun/argus-remediate/argus-policy-controller", binding.Subjects)
	}
}

// TestMetricsChartRendersNothingWhenUnconfigured is the negative case: the
// default, unconfigured state must render neither object at all — matching
// every other opt-in identity/grant in this chart (dryRun, remediate,
// policyController all follow the identical "off by default, nothing
// rendered" rule, per TestRemediateChartGrantsPatchOnPatchFieldKinds's own
// "remediate disabled grants none of it" subtest).
func TestMetricsChartRendersNothingWhenUnconfigured(t *testing.T) {
	roleObjs := helmTemplate(t) // metrics.prometheusService.namespace/name default to ""
	for _, o := range roleObjs {
		if o.Metadata.Name == "argus-investigate-metrics" {
			t.Fatalf("an argus-investigate-metrics %s rendered with metrics.prometheusService left at its default (empty)", o.Kind)
		}
	}
}

// TestMetricsChartBindingFollowsTheRunningServiceAccount is PROJECT.md B172's
// acceptance criterion for this file: the argus-investigate-metrics
// RoleBinding must grant to whichever ServiceAccount the agent Deployment
// actually runs as, in BOTH the read-only and remediation-enabled
// configurations. Before the fix, this subject was hardcoded to
// .Values.serviceAccount.name — correct only in the read-only case — so
// query_metrics silently RBAC-denied on any cluster with remediate.enabled,
// which is exactly the shape TestIdentityBindingFollowsTheRunningServiceAccount
// (chart_identity_test.go) already guards for the identity Secret's own
// RoleBinding; this is the same guard for metrics.yaml's binding.
func TestMetricsChartBindingFollowsTheRunningServiceAccount(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  []string
	}{
		{"read-only", []string{
			"--set", "metrics.prometheusService.namespace=cattle-monitoring-system",
			"--set", "metrics.prometheusService.name=rancher-monitoring-prometheus",
		}},
		{"remediation enabled", []string{
			"--set", "metrics.prometheusService.namespace=cattle-monitoring-system",
			"--set", "metrics.prometheusService.name=rancher-monitoring-prometheus",
			"--set", "remediate.enabled=true",
			"--set", "remediate.allNamespaces=true",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplateRaw(t, tc.set...)
			if err != nil {
				t.Fatalf("helm template failed: %v\n%s", err, out)
			}

			// The INVESTIGATION Deployment specifically. query_metrics is a
			// read-only investigation tool, so its grant belongs to the
			// identity that serves investigation — and since PROJECT.md E11
			// this chart also renders a remediation Deployment, which has no
			// business reaching Prometheus.
			deployments := decodeYAMLDocs[identityDeploymentObject](t, out, func(k string) bool { return k == "Deployment" })
			var investigation *identityDeploymentObject
			for i := range deployments {
				if deployments[i].Metadata.Name == "argus-agent" {
					investigation = &deployments[i]
				}
			}
			if investigation == nil {
				t.Fatalf("no argus-agent Deployment rendered (got %d Deployments)", len(deployments))
			}
			runningAs := investigation.Spec.Template.Spec.ServiceAccountName

			bindings := decodeYAMLDocs[metricsRoleBindingObject](t, out, func(k string) bool { return k == "RoleBinding" })
			var binding *metricsRoleBindingObject
			for i := range bindings {
				if bindings[i].Metadata.Name == "argus-investigate-metrics" {
					binding = &bindings[i]
				}
			}
			if binding == nil {
				t.Fatal("no argus-investigate-metrics RoleBinding rendered")
			}
			if len(binding.Subjects) != 1 {
				t.Fatalf("argus-investigate-metrics RoleBinding has %d subjects, want exactly 1", len(binding.Subjects))
			}
			if binding.Subjects[0].Name != runningAs {
				t.Errorf("argus-investigate-metrics RoleBinding binds %q but the investigation Deployment runs as %q — query_metrics would RBAC-deny under this configuration (PROJECT.md B172)", binding.Subjects[0].Name, runningAs)
			}
		})
	}
}

// TestMetricsChartRefusesPartialConfig pins values.yaml's own stated
// contract: namespace and name must be set TOGETHER, and a partial pair
// (an operator who set one and forgot the other) must fail the render loudly
// rather than silently disable the tool or grant something unintended —
// the same "the chart refuses to guess" discipline
// templates/clusterrole.yaml's remediate.enabled guard already applies to a
// different partial-configuration mistake.
func TestMetricsChartRefusesPartialConfig(t *testing.T) {
	cases := [][]string{
		{"--set", "metrics.prometheusService.namespace=cattle-monitoring-system"},
		{"--set", "metrics.prometheusService.name=rancher-monitoring-prometheus"},
	}
	for _, extraSet := range cases {
		out, err := helmTemplateRaw(t, extraSet...)
		if err == nil {
			t.Errorf("helm template %v succeeded, want a refusal — namespace and name must be set together", extraSet)
			continue
		}
		if !bytes.Contains(out, []byte("must be set TOGETHER")) {
			t.Errorf("helm template %v failed, but not with the expected explanation; output:\n%s", extraSet, out)
		}
	}
}
