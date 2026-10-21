package argushubchart

// chart_clirunner_test.go pins PROJECT.md AD2's chart half: the CLI runner is
// deployed when, and only when, there is a model credential for it — unless
// cliRunner.enabled forces it either way — and every piece that wires it
// (the runner Deployment and Service, its two Secrets, the hub's MCP
// listener env and port) follows that one decision together.

import (
	"strings"
	"testing"
)

type renderedObject struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
}

type runnerWiring struct {
	runnerDeployment bool
	runnerSecret     bool
	credentialSecret bool
	mcpEnv           bool
}

func renderRunnerWiring(t *testing.T, extraSet ...string) runnerWiring {
	t.Helper()
	out, err := helmTemplateRaw(t, extraSet...)
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, out)
	}
	var w runnerWiring
	for _, o := range decodeYAMLDocs[renderedObject](t, out, func(string) bool { return true }) {
		switch {
		case o.Kind == "Deployment" && strings.HasSuffix(o.Metadata.Name, "-cli-runner"):
			w.runnerDeployment = true
		case o.Kind == "Secret" && strings.HasSuffix(o.Metadata.Name, "-cli-runner"):
			w.runnerSecret = true
		case o.Kind == "Secret" && strings.HasSuffix(o.Metadata.Name, "-model-credential"):
			w.credentialSecret = true
		}
	}
	for _, e := range hubContainer(t, out).Env {
		if e.Name == "ARGUS_MCP_ADDR" {
			w.mcpEnv = true
		}
	}
	return w
}

func TestCLIRunnerOffWithoutCredential(t *testing.T) {
	w := renderRunnerWiring(t)
	if w != (runnerWiring{}) {
		t.Fatalf("default install (no credential) rendered runner pieces: %+v", w)
	}
}

func TestCLIRunnerFollowsCredential(t *testing.T) {
	w := renderRunnerWiring(t, "--set", "cliRunner.modelCredential.claudeCodeOauthToken=sk-ant-oat-example")
	want := runnerWiring{runnerDeployment: true, runnerSecret: true, credentialSecret: true, mcpEnv: true}
	if w != want {
		t.Fatalf("credential supplied under the auto default: got %+v, want %+v", w, want)
	}
}

func TestCLIRunnerFollowsExistingCredentialSecret(t *testing.T) {
	w := renderRunnerWiring(t, "--set", "cliRunner.modelCredential.existingSecret=my-model-credential")
	// The operator's own Secret replaces the chart's model-credential Secret.
	want := runnerWiring{runnerDeployment: true, runnerSecret: true, credentialSecret: false, mcpEnv: true}
	if w != want {
		t.Fatalf("existingSecret under the auto default: got %+v, want %+v", w, want)
	}
}

func TestCLIRunnerExplicitFalseWins(t *testing.T) {
	w := renderRunnerWiring(t, "--set", "cliRunner.enabled=false", "--set", "cliRunner.modelCredential.anthropicApiKey=sk-ant-example")
	if w != (runnerWiring{}) {
		t.Fatalf("enabled=false with a credential rendered runner pieces: %+v", w)
	}
}

// An existing release that enabled the runner keeps it: the value it set is
// what every upgrade mode reapplies, and true still means true.
func TestCLIRunnerExplicitTrueKept(t *testing.T) {
	w := renderRunnerWiring(t, "--set", "cliRunner.enabled=true", "--set", "cliRunner.modelCredential.openaiApiKey=sk-example")
	want := runnerWiring{runnerDeployment: true, runnerSecret: true, credentialSecret: true, mcpEnv: true}
	if w != want {
		t.Fatalf("enabled=true: got %+v, want %+v", w, want)
	}
}

func TestCLIRunnerRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  []string
		want string
	}{
		{"true without a credential", []string{"--set", "cliRunner.enabled=true"}, "cliRunner.enabled=true needs a model credential"},
		// The values schema answers first, naming the allowed values. Helm 3
		// and Helm 4 word it differently; both say "must be one of".
		{"unknown value", []string{"--set", "cliRunner.enabled=sometimes"}, "must be one of"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplateRaw(t, tc.set...)
			if err == nil {
				t.Fatalf("helm template succeeded; want a refusal containing %q", tc.want)
			}
			if !strings.Contains(string(out), tc.want) {
				t.Fatalf("refusal does not say %q:\n%s", tc.want, out)
			}
		})
	}
}
