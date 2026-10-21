package argushubchart

// The hub chart has to install on any conformant cluster, OpenShift
// included: there the pods leave their user and group IDs to the cluster.

import (
	"strings"
	"testing"
)

func TestHubOnOpenShiftLeavesUserIDsToTheCluster(t *testing.T) {
	cli := []string{"--set", "cliRunner.enabled=true", "--set", "cliRunner.modelCredential.anthropicApiKey=k"}
	for _, set := range [][]string{
		append([]string{"--set", "global.openshift=true"}, cli...),
		append([]string{"--api-versions", "security.openshift.io/v1"}, cli...),
	} {
		out := renderMinimal(t, "argus-hub", append(set, "--set", "ingress.host=argus.example.org")...)
		for _, field := range []string{"runAsUser", "runAsGroup", "fsGroup"} {
			if strings.Contains(out, field) {
				t.Errorf("%v: rendered %s, which OpenShift's restricted policy refuses", set, field)
			}
		}
	}
	out := renderMinimal(t, "argus-hub", append(cli, "--set", "ingress.host=argus.example.org")...)
	for _, want := range []string{"runAsUser: 65532", "runAsUser: 999", "runAsUser: 1000"} {
		if !strings.Contains(out, want) {
			t.Errorf("off OpenShift, want %q", want)
		}
	}
}
