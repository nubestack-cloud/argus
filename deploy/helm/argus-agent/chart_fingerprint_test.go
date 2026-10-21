package argusagentchart

// chart_fingerprint_test.go covers PROJECT.md E11's `clusterFingerprint`
// value: the override that lets a second, differently-scoped agent enroll
// against a cluster that already has one, instead of being refused with the
// hub's 409 "already enrolled" (internal/api/enroll.go).
//
// The property worth a test is the DEFAULT, not the override. An agent that
// picks up an explicit fingerprint it was never given would enroll as a
// cluster record nobody asked for, and the derived sha256(kube-system UID)
// identity lld/03-agent-protocol.md §5 specifies would stop being what an
// ordinary install gets. So the absent case asserts the env var is not
// rendered at all — cmd/agent reads `os.Getenv("ARGUS_CLUSTER_FINGERPRINT")`
// and treats empty as "derive it", and an env var present with an empty
// value would take the same path, but rendering nothing keeps the Pod spec
// honest about which installs opted in.
//
// Reuses helmTemplateRaw/decodeYAMLDocs from chart_metrics_test.go and
// identityDeploymentObject from chart_identity_test.go, the same way every
// other test file in this package does.

import "testing"

const clusterFingerprintEnvVar = "ARGUS_CLUSTER_FINGERPRINT"

func agentContainerEnv(t *testing.T, extraSet ...string) map[string]string {
	t.Helper()
	out, err := helmTemplateRaw(t, extraSet...)
	if err != nil {
		t.Fatalf("helm template failed: %v", err)
	}
	deploys := decodeYAMLDocs[identityDeploymentObject](t, out, func(kind string) bool {
		return kind == "Deployment"
	})
	if len(deploys) != 1 {
		t.Fatalf("expected exactly one Deployment, got %d", len(deploys))
	}
	containers := deploys[0].Spec.Template.Spec.Containers
	if len(containers) != 1 {
		t.Fatalf("expected exactly one container, got %d", len(containers))
	}
	env := make(map[string]string, len(containers[0].Env))
	for _, e := range containers[0].Env {
		env[e.Name] = e.Value
	}
	return env
}

func TestClusterFingerprintEnvIsAbsentByDefault(t *testing.T) {
	env := agentContainerEnv(t)
	if v, ok := env[clusterFingerprintEnvVar]; ok {
		t.Fatalf("%s must not be rendered when clusterFingerprint is unset "+
			"(the agent derives sha256(kube-system UID) instead); got %q", clusterFingerprintEnvVar, v)
	}
}

func TestClusterFingerprintEnvIsRenderedWhenSet(t *testing.T) {
	const want = "a58ab8b5cb90865f3f41f9bd016fa20830c86ff5b6ac8170b59ee9263b70d2c8"
	env := agentContainerEnv(t, "--set", "clusterFingerprint="+want)
	got, ok := env[clusterFingerprintEnvVar]
	if !ok {
		t.Fatalf("%s was not rendered although clusterFingerprint was set", clusterFingerprintEnvVar)
	}
	if got != want {
		t.Fatalf("%s = %q, want %q", clusterFingerprintEnvVar, got, want)
	}
}
