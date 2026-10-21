package argushubchart

// chart_probes_test.go guards PROJECT.md B162 at the layer the defect actually
// lived at: the chart. The Go handlers were always separable — /readyz already
// existed and already checked the database — but BOTH probes pointed at
// /healthz, and /healthz pinged Postgres, so a momentary database interruption
// failed LIVENESS, kubelet killed the hub, and every enrolled cluster's mTLS
// tunnel died with it. No Go test could have caught that.
//
// Same "no live cluster needed, `helm template` renders locally" verification
// deploy/helm/argus-agent/chart_test.go's header comment establishes for this
// repo's other chart checks, including its convention of skipping (not
// failing) when `helm` is not on PATH.

import (
	"bytes"
	"io"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"gopkg.in/yaml.v3"
)

// probeObject mirrors the subset of a rendered Deployment these tests read.
type probeObject struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		Template struct {
			Spec struct {
				TerminationGracePeriodSeconds *int `yaml:"terminationGracePeriodSeconds"`
				Containers                    []struct {
					Name string `yaml:"name"`
					Env  []struct {
						Name  string `yaml:"name"`
						Value string `yaml:"value"`
					} `yaml:"env"`
					ReadinessProbe *httpProbe `yaml:"readinessProbe"`
					LivenessProbe  *httpProbe `yaml:"livenessProbe"`
				} `yaml:"containers"`
			} `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

type httpProbe struct {
	HTTPGet struct {
		Path string `yaml:"path"`
		Port string `yaml:"port"`
	} `yaml:"httpGet"`
	FailureThreshold *int `yaml:"failureThreshold"`
	PeriodSeconds    *int `yaml:"periodSeconds"`
}

func helmTemplateRaw(t *testing.T, extraSet ...string) ([]byte, error) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not on PATH; skipping rendered-chart verification")
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not resolve this test file's own path")
	}
	chartDir := filepath.Dir(thisFile)

	args := append([]string{"template", chartDir,
		// The one value with no default (values.yaml's `tunnel` comment).
		"--set", "tunnel.publicEndpoint=hub.example.com:8443",
	}, extraSet...)
	return runHelm(exec.Command("helm", args...))
}

// runHelm returns helm's stdout, the rendered manifests, when it succeeds,
// and stdout plus stderr when it fails, so a refusal's message is in hand.
// Helm logs to stderr on success too (a note about the symlinked local-agent
// subchart), which must not be parsed as a manifest.
func runHelm(cmd *exec.Cmd) ([]byte, error) {
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return append(out, stderr.Bytes()...), err
	}
	return out, nil
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

// hubContainer returns the rendered hub container, failing if the chart stops
// rendering exactly one Deployment carrying it.
func hubContainer(t *testing.T, out []byte) struct {
	Name string `yaml:"name"`
	Env  []struct {
		Name  string `yaml:"name"`
		Value string `yaml:"value"`
	} `yaml:"env"`
	ReadinessProbe *httpProbe `yaml:"readinessProbe"`
	LivenessProbe  *httpProbe `yaml:"livenessProbe"`
} {
	t.Helper()
	deployments := decodeYAMLDocs[probeObject](t, out, func(k string) bool { return k == "Deployment" })
	for _, d := range deployments {
		for _, c := range d.Spec.Template.Spec.Containers {
			if c.Name == "hub" {
				return c
			}
		}
	}
	t.Fatal("no container named `hub` in any rendered Deployment")
	panic("unreachable")
}

// TestLivenessAndReadinessProbeDifferentPaths is B162's regression, stated as
// the two properties that matter: liveness must be the process-only path, and
// readiness must be the path that depends on the database. Pointing both at
// one path is what made a Postgres blip a fleet-wide outage.
func TestLivenessAndReadinessProbeDifferentPaths(t *testing.T) {
	out, err := helmTemplateRaw(t)
	if err != nil {
		t.Fatalf("helm template (defaults) failed: %v\n%s", err, out)
	}
	c := hubContainer(t, out)

	if c.LivenessProbe == nil || c.ReadinessProbe == nil {
		t.Fatalf("hub container is missing a probe: liveness=%v readiness=%v", c.LivenessProbe, c.ReadinessProbe)
	}
	if got := c.LivenessProbe.HTTPGet.Path; got != "/healthz" {
		t.Errorf("livenessProbe path = %q, want /healthz — the process-only check (internal/api.handleHealthz)", got)
	}
	if got := c.ReadinessProbe.HTTPGet.Path; got != "/readyz" {
		t.Errorf("readinessProbe path = %q, want /readyz — the check that may depend on the database (internal/api.handleReadyz)", got)
	}
	if c.LivenessProbe.HTTPGet.Path == c.ReadinessProbe.HTTPGet.Path {
		t.Error("both probes point at the same path: a failure of whatever that path depends on then RESTARTS the hub, dropping every agent tunnel, instead of merely taking it out of the Service (PROJECT.md B162)")
	}
}

// TestShutdownBudgetFitsInsideTheTerminationGracePeriod is the arithmetic that
// must not drift: if terminationGracePeriodSeconds is shorter than the drain
// the hub is configured to perform, kubelet SIGKILLs it partway through and
// the graceful path is decoration. The template derives one from the other for
// exactly this reason; this test proves the derivation holds at a raised
// graceSeconds too, which is where a hardcoded number would have broken.
func TestShutdownBudgetFitsInsideTheTerminationGracePeriod(t *testing.T) {
	for _, tc := range []struct {
		name           string
		set            []string
		readinessDelay int
		grace          int
	}{
		{"defaults", nil, 3, 15},
		{"raised grace", []string{"--set", "shutdown.graceSeconds=60"}, 3, 60},
		{"no readiness delay", []string{"--set", "shutdown.readinessDelaySeconds=0"}, 0, 15},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplateRaw(t, tc.set...)
			if err != nil {
				t.Fatalf("helm template failed: %v\n%s", err, out)
			}
			deployments := decodeYAMLDocs[probeObject](t, out, func(k string) bool { return k == "Deployment" })
			var grace *int
			for _, d := range deployments {
				for _, c := range d.Spec.Template.Spec.Containers {
					if c.Name == "hub" {
						grace = d.Spec.Template.Spec.TerminationGracePeriodSeconds
					}
				}
			}
			if grace == nil {
				t.Fatal("the hub Deployment sets no terminationGracePeriodSeconds — it would default to 30s regardless of the configured drain budget")
			}
			// What cmd/hub/main.go's drainHub can actually spend: the
			// readiness delay, one grace budget for the HTTP phase, one for
			// the worker phase, plus wsDrainGrace (5s) five times: twice for
			// the background-investigation phase (wait, then cancel and let
			// each record its interruption) and once each for the WebSocket,
			// MCP-listener and tunnel phases.
			worstCase := tc.readinessDelay + 2*tc.grace + 25
			if *grace < worstCase {
				t.Errorf("terminationGracePeriodSeconds = %d, but the configured drain can take up to %ds — kubelet would SIGKILL the hub mid-drain", *grace, worstCase)
			}
		})
	}
}

// TestShutdownBudgetReachesTheContainer proves the values are not
// decoration: the hub reads its drain budget from the environment, so a chart
// that renders the grace period but not the variables would produce a pod
// whose grace period and whose actual drain disagree.
func TestShutdownBudgetReachesTheContainer(t *testing.T) {
	out, err := helmTemplateRaw(t, "--set", "shutdown.readinessDelaySeconds=7", "--set", "shutdown.graceSeconds=11")
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, out)
	}
	env := map[string]string{}
	for _, e := range hubContainer(t, out).Env {
		env[e.Name] = e.Value
	}
	for name, want := range map[string]string{
		"ARGUS_SHUTDOWN_READINESS_DELAY_SECONDS": "7",
		"ARGUS_SHUTDOWN_GRACE_SECONDS":           "11",
	} {
		if got, ok := env[name]; !ok {
			t.Errorf("%s is not set on the hub container — cmd/hub would silently use its own default instead of the chart's value", name)
		} else if got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}
