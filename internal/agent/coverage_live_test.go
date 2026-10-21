package agent

// Live measurement of PROJECT.md E11's coverage signal against a real API
// server, a real discovery surface and the chart's real argus-investigate
// ClusterRole — not a fake discoverer, and not cluster-admin.
//
// This is the number E11 exists to make visible: a scoped agent resolves a
// fraction of the kinds a cluster-admin-bound one does, and before this
// signal existed nothing an operator could reach distinguished that from a
// quiet cluster. A unit test cannot produce it, because the denominator is
// whatever the cluster actually serves — a stock kind cluster, a cluster
// with an operator estate, and a Rancher cluster all differ, and that is the
// point.
//
// Read-only. It creates nothing and deletes nothing: it runs the SAME
// discovery+RBAC intersection the agent runs, once as the test's own
// (cluster-admin) identity and once impersonating the agent's ServiceAccount.
// Impersonation rather than a minted token because the RBAC decision the API
// server makes is identical and it keeps this test to zero writes.
//
// Requires the chart's RBAC to be installed on the target cluster
// (argus-investigate's ClusterRole + ClusterRoleBinding). Run it against a
// disposable cluster:
//
//	ARGUS_AGENT_COVERAGE_LIVE=1 ARGUS_AGENT_COVERAGE_CONTEXT=kind-argus-disposable \
//	  go test ./internal/agent/ -run TestLiveCoverageUnderTheScopedIdentity -v

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const investigateUser = "system:serviceaccount:argus-system:argus-investigate"

// liveCoverageConfig resolves a kubeconfig for the named context, or skips.
func liveCoverageConfig(t *testing.T) *rest.Config {
	t.Helper()
	if os.Getenv("ARGUS_AGENT_COVERAGE_LIVE") == "" {
		t.Skip("set ARGUS_AGENT_COVERAGE_LIVE=1 (and ARGUS_AGENT_COVERAGE_CONTEXT) to run this against a real cluster")
	}
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatalf("resolve home: %v", err)
		}
		kubeconfig = filepath.Join(home, ".kube", "config")
	}
	overrides := &clientcmd.ConfigOverrides{}
	if ctxName := os.Getenv("ARGUS_AGENT_COVERAGE_CONTEXT"); ctxName != "" {
		overrides.CurrentContext = ctxName
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig}, overrides).ClientConfig()
	if err != nil {
		t.Fatalf("build client config: %v", err)
	}
	return cfg
}

// measureCoverage runs the production intersection as whoever cfg
// authenticates as.
func measureCoverage(t *testing.T, cfg *rest.Config) WatchSetCoverage {
	t.Helper()
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("clientset: %v", err)
	}
	_, cov, err := DiscoverWatchSet(context.Background(), cs.Discovery(), cs.AuthorizationV1().SelfSubjectRulesReviews())
	if err != nil {
		t.Fatalf("DiscoverWatchSet: %v", err)
	}
	return cov
}

// TestLiveCoverageUnderTheScopedIdentity measures the drop, and asserts the
// three things that must hold for the signal to be worth anything:
// the denominator is the same for both identities, the scoped identity sees
// materially less, and the gap is both counted exactly and sampled
// recognisably.
func TestLiveCoverageUnderTheScopedIdentity(t *testing.T) {
	adminCfg := liveCoverageConfig(t)

	scopedCfg := rest.CopyConfig(adminCfg)
	scopedCfg.Impersonate = rest.ImpersonationConfig{UserName: investigateUser}

	admin := measureCoverage(t, adminCfg)
	scoped := measureCoverage(t, scopedCfg)

	t.Logf("cluster-admin:      %d readable of %d served", admin.Readable, admin.Served)
	t.Logf("argus-investigate:  %d readable of %d served (%d denied, sample of %d: %v)",
		scoped.Readable, scoped.Served, scoped.Served-scoped.Readable, len(scoped.Denied), scoped.Denied)

	if admin.Served != scoped.Served {
		t.Errorf("the denominator differs between identities (%d vs %d) — Served must be what the API SERVER offers, independent of who is asking, or the ratio is meaningless",
			admin.Served, scoped.Served)
	}
	if admin.Readable != admin.Served {
		t.Errorf("cluster-admin resolves only %d of %d served kinds — the denominator is not measuring what a fully-granted agent would see", admin.Readable, admin.Served)
	}
	if scoped.Readable >= admin.Readable {
		t.Errorf("the scoped identity resolves %d kinds against cluster-admin's %d — if these are equal the chart's ClusterRole is not actually scoped, or this test is not impersonating",
			scoped.Readable, admin.Readable)
	}
	if scoped.Readable == 0 {
		t.Error("the scoped identity resolves nothing at all — that is not a narrow grant, it is a broken one (is argus-investigate's ClusterRoleBinding installed?)")
	}

	denied := scoped.Served - scoped.Readable
	if denied != len(scoped.Denied) && !scoped.DeniedTruncated {
		t.Errorf("%d resources are denied but the sample holds %d and does not report itself truncated", denied, len(scoped.Denied))
	}
	if len(scoped.Denied) == 0 {
		t.Error("nothing was sampled from a non-empty denied set — the gap would be a bare number with nothing to recognise it by")
	}
}
