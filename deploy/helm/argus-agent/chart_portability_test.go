package argusagentchart

// The agent chart has to install on any conformant cluster: OpenShift's
// restricted policy (no fixed user IDs), and Kubernetes versions where the
// optional write paths' admission policies do not exist.

import (
	"strings"
	"testing"
)

func TestOpenShiftLeavesUserIDsToTheCluster(t *testing.T) {
	for _, set := range [][]string{
		{"--set", "openshift=true"},
		{"--api-versions", "security.openshift.io/v1"},
	} {
		out, err := helmTemplateRaw(t, append(set, "--set", "remediate.enabled=true", "--set", "remediate.namespaces={default}")...)
		if err != nil {
			t.Fatalf("helm template %v: %v\n%s", set, err, out)
		}
		for _, field := range []string{"runAsUser", "runAsGroup", "fsGroup"} {
			if strings.Contains(string(out), field) {
				t.Errorf("%v: rendered %s, which OpenShift's restricted policy refuses", set, field)
			}
		}
		if !strings.Contains(string(out), "runAsNonRoot: true") {
			t.Errorf("%v: dropped runAsNonRoot along with the IDs", set)
		}
	}
	out, err := helmTemplateRaw(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "runAsUser: 65532") {
		t.Error("off OpenShift the agent should keep its fixed non-root user")
	}
}

func TestWritePathsRefuseClustersWithoutAdmissionPolicies(t *testing.T) {
	for _, set := range [][]string{
		{"--set", "remediate.enabled=true", "--set", "remediate.namespaces={default}"},
		{"--set", "dryRun.enabled=true"},
	} {
		out, err := helmTemplateRaw(t, append(set, "--kube-version", "1.29.4")...)
		if err == nil || !strings.Contains(string(out), "needs Kubernetes 1.30") {
			t.Errorf("%v on 1.29: want a refusal naming 1.30, got err=%v\n%s", set, err, out)
		}
		if out, err := helmTemplateRaw(t, append(set, "--kube-version", "1.30.0")...); err != nil {
			t.Errorf("%v on 1.30: %v\n%s", set, err, out)
		}
	}
	if out, err := helmTemplateRaw(t, "--kube-version", "1.29.4"); err != nil {
		t.Errorf("a read-only agent must still install on 1.29: %v\n%s", err, out)
	}
}

// The aggregated view role must not render `rules`: the aggregation
// controller owns that field, and an upgrade that applies it conflicts
// (server-side apply, Helm 4) or blanks it (client-side, Helm 3).
func TestAggregatedViewRoleLeavesRulesToTheController(t *testing.T) {
	out, err := helmTemplateRaw(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	docs := strings.Split(string(out), "\n---")
	found := false
	for _, d := range docs {
		if !strings.Contains(d, "name: argus-investigate-view\n") || !strings.Contains(d, "\nkind: ClusterRole\n") {
			continue
		}
		found = true
		if !strings.Contains(d, "aggregationRule:") {
			t.Error("argus-investigate-view has no aggregationRule")
		}
		for _, line := range strings.Split(d, "\n") {
			if strings.HasPrefix(line, "rules:") {
				t.Errorf("argus-investigate-view renders %q; the aggregation controller owns rules", line)
			}
		}
	}
	if !found {
		t.Fatal("argus-investigate-view ClusterRole not rendered")
	}
}
