package argushubchart

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// renderMinimal renders the chart as a first install would, with nothing set
// but what is given: no tunnel address, no name override.
func renderMinimal(t *testing.T, release string, set ...string) string {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not on PATH")
	}
	_, file, _, _ := runtime.Caller(0)
	args := append([]string{"template", release, filepath.Dir(file), "--namespace", "argus-system"}, set...)
	out, err := runHelm(exec.Command("helm", args...))
	if err != nil {
		t.Fatalf("helm template %v: %v\n%s", set, err, out)
	}
	return string(out)
}

func envValue(rendered, name string) (string, bool) {
	i := strings.Index(rendered, "- name: "+name+"\n")
	if i < 0 {
		return "", false
	}
	rest := rendered[i:]
	j := strings.Index(rest, "value: ")
	line := rest[j+len("value: "):]
	return strings.Trim(strings.SplitN(line, "\n", 2)[0], `"`), true
}

// An install needs one value, ingress.host: agents then enroll and tunnel at
// that URL, through the same Ingress as the UI, and the objects are named
// after the release.
func TestMinimalInstall(t *testing.T) {
	out := renderMinimal(t, "argus-hub", "--set", "ingress.host=argus.example.org", "--set", "ingress.clusterIssuer=letsencrypt")
	if url, _ := envValue(out, "ARGUS_PUBLIC_API_URL"); url != "https://argus.example.org" {
		t.Errorf("public URL %q", url)
	}
	if _, set := envValue(out, "ARGUS_TUNNEL_PUBLIC_ENDPOINT"); set {
		t.Error("a tunnel address was set; agents should tunnel through the Ingress")
	}
	for _, want := range []string{
		"kind: Deployment\nmetadata:\n  name: argus-hub\n",
		`"cert-manager.io/cluster-issuer": "letsencrypt"`,
		`secretName: "argus-hub-tls"`,
		"host: \"argus.example.org\"",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered chart lacks %q", want)
		}
	}
}

// With no host, there is no Ingress, and agents reach the hub at its
// in-cluster Service, which serves the hub's own cluster.
func TestInstallWithoutIngressHost(t *testing.T) {
	out := renderMinimal(t, "argus")
	if strings.Contains(out, "kind: Ingress") {
		t.Error("an Ingress rendered without a host")
	}
	if url, _ := envValue(out, "ARGUS_PUBLIC_API_URL"); url != "http://argus-argus-hub.argus-system.svc:8080" {
		t.Errorf("public URL %q", url)
	}
}

// A dedicated tunnel address is still honoured.
func TestDedicatedTunnelAddress(t *testing.T) {
	out := renderMinimal(t, "argus-hub", "--set", "ingress.host=argus.example.org", "--set", "tunnel.publicEndpoint=tunnel.example.org:8443", "--set", "tunnel.service.type=LoadBalancer")
	if ep, _ := envValue(out, "ARGUS_TUNNEL_PUBLIC_ENDPOINT"); ep != "tunnel.example.org:8443" {
		t.Errorf("tunnel endpoint %q", ep)
	}
	if sans, _ := envValue(out, "ARGUS_TUNNEL_SANS"); !strings.HasPrefix(sans, "tunnel.example.org,") {
		t.Errorf("SANs %q", sans)
	}
}

// Bundled Postgres gets a memory-backed /dev/shm larger than the container
// runtime's 64Mi default, which concurrent parallel queries outgrow.
func TestBundledPostgresSharedMemory(t *testing.T) {
	out := renderMinimal(t, "argus-hub", "--set", "ingress.host=argus.example.org")
	for _, want := range []string{"mountPath: /dev/shm", "medium: Memory", `sizeLimit: "512Mi"`} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered chart lacks %q", want)
		}
	}
}

// renderIn renders the chart into namespace ns, returning helm's error text
// instead of failing, for refusals.
func renderIn(t *testing.T, ns string, set ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not on PATH")
	}
	_, file, _, _ := runtime.Caller(0)
	args := append([]string{"template", "argus-hub", filepath.Dir(file), "--namespace", ns}, set...)
	out, err := runHelm(exec.Command("helm", args...))
	return string(out), err
}

// A default install deploys this cluster's agent with the hub: it reaches the
// hub at its in-cluster Service and enrolls with the key the hub is given.
func TestLocalAgentByDefault(t *testing.T) {
	out, err := renderIn(t, "argus-system", "--set", "ingress.host=argus.example.org")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{
		"kind: Deployment\nmetadata:\n  name: argus-agent\n",
		"name: argus-local-enrollment",
		"- name: ARGUS_LOCAL_ENROLLMENT_KEY",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered chart lacks %q", want)
		}
	}
	if url, _ := envValue(out, "ARGUS_HUB_API_URL"); url != "http://argus-hub.argus-system.svc:8080" {
		t.Errorf("agent hub URL %q", url)
	}
	if ep, _ := envValue(out, "ARGUS_TUNNEL_ENDPOINT"); ep != "ws://argus-hub.argus-system.svc:8080/api/v1/agent/tunnel" {
		t.Errorf("agent tunnel endpoint %q", ep)
	}
	if strings.Contains(out, "kind: Namespace") {
		t.Error("the local agent created argus-system, which the hub release already lives in")
	}
}

// Without the agent's namespace, or when turned off, the hub renders no agent
// and no key.
func TestLocalAgentNotRendered(t *testing.T) {
	for name, tc := range map[string]struct {
		ns  string
		set []string
	}{
		"another namespace": {"monitoring", nil},
		"disabled":          {"argus-system", []string{"--set", "localAgent.enabled=false"}},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := renderIn(t, tc.ns, append([]string{"--set", "ingress.host=argus.example.org"}, tc.set...)...)
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			for _, unwanted := range []string{"name: argus-agent\n", "argus-local-enrollment", "ARGUS_LOCAL_ENROLLMENT_KEY"} {
				if strings.Contains(out, unwanted) {
					t.Errorf("rendered %q", unwanted)
				}
			}
		})
	}
}

// A renamed hub cannot be found by the agent's derived Service name, so the
// chart asks for the URL rather than install an agent that never connects.
func TestLocalAgentNeedsURLForARenamedHub(t *testing.T) {
	out, err := renderIn(t, "argus-system", "--set", "fullnameOverride=argus")
	if err == nil || !strings.Contains(out, "localAgent.hub.apiUrl") {
		t.Fatalf("expected a refusal naming localAgent.hub.apiUrl, got err=%v\n%s", err, out)
	}
	if out, err := renderIn(t, "argus-system", "--set", "fullnameOverride=argus", "--set", "localAgent.hub.apiUrl=http://argus.argus-system.svc:8080"); err != nil {
		t.Fatalf("with the URL set: %v\n%s", err, out)
	}
}

// Gateway API instead of the Ingress: an HTTPRoute to the API Service, and the
// hub's own URL (which agents are given) from its host.
func TestHTTPRouteInsteadOfIngress(t *testing.T) {
	out, err := renderIn(t, "argus-system", "--set", "httpRoute.host=argus.example.org",
		"--set", "httpRoute.parentRefs[0].name=public", "--set", "httpRoute.parentRefs[0].namespace=gateway-system")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"kind: HTTPRoute", "- \"argus.example.org\"", "name: public", "port: 8080"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered chart lacks %q", want)
		}
	}
	if strings.Contains(out, "kind: Ingress") {
		t.Error("an Ingress rendered beside the HTTPRoute")
	}
	if url, _ := envValue(out, "ARGUS_PUBLIC_API_URL"); url != "https://argus.example.org" {
		t.Errorf("public URL %q", url)
	}
}

// One address only, and a route needs a Gateway to attach to.
func TestHTTPRouteRefusals(t *testing.T) {
	for name, set := range map[string][]string{
		"both hosts":    {"--set", "ingress.host=a.example.org", "--set", "httpRoute.host=b.example.org", "--set", "httpRoute.parentRefs[0].name=public"},
		"no parentRefs": {"--set", "httpRoute.host=b.example.org"},
	} {
		if out, err := renderIn(t, "argus-system", set...); err == nil {
			t.Errorf("%s: rendered\n%s", name, out)
		}
	}
}
