package upgradeready

import (
	"maps"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestImageMinor(t *testing.T) {
	for image, want := range map[string]string{
		"registry.k8s.io/kube-proxy:v1.36.2":                                                         "1.36",
		"602401143452.dkr.ecr.eu-west-1.amazonaws.com/kube-proxy:v1.35.4-eksbuild.2":                 "1.35",
		"rancher/hardened-kube-proxy:v1.31.4-rke2r1-build20250115":                                   "1.31",
		"kube-proxy:v1.36.2@sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945": "1.36",
		"registry.local:5000/kube-proxy:1.34":                                                        "1.34",
		"registry.local:5000/kube-proxy":                                                             "",
		"kube-proxy:latest":                                                                          "",
		"kube-proxy@sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945":         "",
	} {
		v, ok := imageMinor(image)
		got := ""
		if ok {
			got = label(v)
		}
		if got != want {
			t.Errorf("%s: %q, want %q", image, got, want)
		}
	}
}

func TestCommandLineFlags(t *testing.T) {
	c := corev1.Container{
		Command: []string{"kube-apiserver", "--feature-gates=A=true,B=false", "--audit", "--v=2"},
		Args:    []string{"--feature-gates", "B=true, D", "--audit", "--enable-admission-plugins", "--disable-admission-plugins=X,Y"},
	}
	a := commandLine(c)
	if got := a.flag("--audit", true); len(got) != 2 || got[0] != (setting{"", "command"}) || got[1] != (setting{"", "args"}) {
		t.Errorf("bare flags: %+v", got)
	}
	if _, ok := a.first("--enable-admission-plugins"); ok {
		t.Error("a flag followed by another flag has no value")
	}
	if s, _ := a.first("--disable-admission-plugins"); s != (setting{"X,Y", "args"}) {
		t.Errorf("--disable-admission-plugins: %+v", s)
	}
	gates := a.featureGates()
	want := map[string]setting{"A": {"true", "command"}, "B": {"true", "args"}}
	if !maps.Equal(gates, want) {
		t.Errorf("gates %+v", gates)
	}
}

func TestManagerOf(t *testing.T) {
	for _, tc := range []struct {
		labels, annotations map[string]string
		want                *ResourceRef
	}{
		{map[string]string{"kustomize.toolkit.fluxcd.io/name": "apps", "kustomize.toolkit.fluxcd.io/namespace": "flux-system"}, nil,
			&ResourceRef{Group: "kustomize.toolkit.fluxcd.io", Kind: "Kustomization", Namespace: "flux-system", Name: "apps"}},
		{nil, map[string]string{"argocd.argoproj.io/tracking-id": "team-a_shop:apps/Deployment:shop/web"},
			&ResourceRef{Group: "argoproj.io", Kind: "Application", Namespace: "team-a", Name: "shop"}},
		{nil, map[string]string{"argocd.argoproj.io/tracking-id": "shop:apps/Deployment:shop/web"},
			&ResourceRef{Group: "argoproj.io", Kind: "Application", Name: "shop"}},
		{map[string]string{"argocd.argoproj.io/instance": "shop"}, map[string]string{"argocd.argoproj.io/tracking-id": "no-colon"},
			&ResourceRef{Group: "argoproj.io", Kind: "Application", Name: "shop"}},
		{nil, map[string]string{"meta.helm.sh/release-name": "redis", "meta.helm.sh/release-namespace": "cache"},
			&ResourceRef{Kind: "HelmRelease", Namespace: "cache", Name: "redis"}},
		{map[string]string{"helm.toolkit.fluxcd.io/name": "half"}, nil, nil},
	} {
		got := managerOf(&metav1.ObjectMeta{Labels: tc.labels, Annotations: tc.annotations})
		if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
			t.Errorf("%v %v: %+v, want %+v", tc.labels, tc.annotations, got, tc.want)
		}
	}
}

func TestMergeLabels(t *testing.T) {
	for _, tc := range []struct {
		labels []string
		ok     bool
	}{
		{[]string{"system_u:system_r:container_t:s0:c1,c2"}, true},
		{[]string{":::s0:c1", "system_u:::s0:c1"}, true},
		{[]string{":::s0:c1", ":::s0:c2"}, false},
		{[]string{"u:r:t:"}, false},
		{[]string{"broken"}, false},
	} {
		if _, ok := mergeLabels(tc.labels); ok != tc.ok {
			t.Errorf("%v: %v", tc.labels, ok)
		}
	}
}

func TestTimedOut(t *testing.T) {
	for msg, want := range map[string]bool{
		`Liveness probe failed: command timed out: "/bin/check" timed out after 1s`: true,
		`Readiness probe errored: rpc error: command timed out`:                     true,
		`  probe errored and resulted in unknown state: command timed out`:          true,
		`Liveness probe failed: HTTP probe failed with statuscode: 500`:             false,
		`Back-off restarting failed container`:                                      false,
	} {
		if timedOut(msg) != want {
			t.Errorf("%q: %v", msg, !want)
		}
	}
}

func TestMetricMatches(t *testing.T) {
	names := metricNames([]string{`sum(rate(container_tasks_state{state="x"}[5m])) + my_container_tasks_state + container_application_7 + container_application_hits:rate5m`})
	if got := (metricChange{name: "container_tasks_state"}).matches(names); !slices.Equal(got, []string{"container_tasks_state"}) {
		t.Errorf("exact: %v", got)
	}
	if got := (metricChange{name: "container_application_", prefix: true}).matches(names); !slices.Equal(got, []string{"container_application_hits:rate5m"}) {
		t.Errorf("prefix: %v", got)
	}
}

func TestBudgetState(t *testing.T) {
	b := budget("shop", "web", "web", 0, 3, 3)
	if stateOf(b) != budgetBlocks {
		t.Error("zero allowed with every pod healthy blocks")
	}
	b.Status.CurrentHealthy = 2
	if stateOf(b) != budgetAllows {
		t.Error("an unhealthy pod is not this state's block")
	}
	b.Generation = 9
	if stateOf(b) != budgetStale {
		t.Error("a status from an older generation is stale")
	}
	b.DeletionTimestamp = &metav1.Time{}
	if stateOf(b) != budgetAllows {
		t.Error("a budget being deleted is ignored")
	}
	_ = policyv1.AlwaysAllow
}

func TestHashedAtCapture(t *testing.T) {
	if !hashedAtCapture(hashed) || hashedAtCapture("sha256:abc") || hashedAtCapture("mode: ipvs") {
		t.Error("hash detection")
	}
}
