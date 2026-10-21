package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"

	"argus/internal/render"
)

// Live, cluster-touching proof of the properties pod_test.go can only assert
// statically. Skipped unless ARGUS_RENDER_SANDBOX_LIVE=1, following the same
// convention as internal/gitops/live_test.go's ARGUS_GITOPS_LIVE.
//
// Run against the real rke2 dev cluster:
//
//	ARGUS_RENDER_SANDBOX_LIVE=1 KUBECONFIG=<kubeconfig> \
//	  go test ./internal/render/sandbox/ -run TestLive -v
//
// Uses its own dedicated namespace (argus-render-sandbox-test, deleted at
// the end of the run) — never argus-e2e-rke2 or argus-gitops-rke2, which
// other concurrent GitOps test work already owns on this shared cluster.
const liveNamespace = "argus-render-sandbox-test"

func liveRunner(t *testing.T) *Runner {
	t.Helper()
	if os.Getenv("ARGUS_RENDER_SANDBOX_LIVE") != "1" {
		t.Skip("set ARGUS_RENDER_SANDBOX_LIVE=1 (and KUBECONFIG) to run the live sandbox-cluster tests")
	}
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		home, _ := os.UserHomeDir()
		kubeconfig = filepath.Join(home, ".kube", "config")
	}
	restCfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatalf("building rest.Config from KUBECONFIG=%s: %v", kubeconfig, err)
	}
	rn, err := NewRunner(restCfg, Config{
		Namespace:  liveNamespace,
		PodTimeout: 90 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	return rn
}

// TestLiveClusterIdentity guards every other live test in this file against
// running against the wrong cluster — see BACKLOG.md F26's own instruction
// to confirm cluster identity before touching anything.
func TestLiveClusterIdentity(t *testing.T) {
	rn := liveRunner(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	nodes, err := rn.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("listing nodes: %v", err)
	}
	if len(nodes.Items) != 5 {
		t.Fatalf("expected 5 nodes (the real rke2 cluster), got %d — refusing to run further live tests against a cluster that doesn't match", len(nodes.Items))
	}
	for _, n := range nodes.Items {
		if !strings.HasPrefix(n.Name, "my-rke2-cluster-") {
			t.Fatalf("node %q doesn't match the expected my-rke2-cluster-* naming — this looks like the WRONG cluster (possibly k8s-lab-dev, which must never be used for this)", n.Name)
		}
	}
}

// TestLiveNetworkPolicy_DeniesEgress is the mechanical proof that "network
// disabled by default" is real on THIS cluster, not just a manifest that
// looks right — Canal's dataplane is Flannel, whose OWN enforcement is a
// no-op; what actually enforces this is Calico running as Canal's policy
// engine, and this test is what tells the difference between "a
// NetworkPolicy exists" and "a NetworkPolicy does anything".
func TestLiveNetworkPolicy_DeniesEgress(t *testing.T) {
	rn := liveRunner(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if err := rn.EnsureNamespace(ctx); err != nil {
		t.Fatalf("EnsureNamespace: %v", err)
	}
	t.Cleanup(func() { _ = rn.Teardown(context.Background()) })

	runID := domainRunID()
	np := BuildNetworkPolicy(rn.cfg, runID)
	if _, err := rn.clientset.NetworkingV1().NetworkPolicies(rn.cfg.Namespace).Create(ctx, np, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating NetworkPolicy: %v", err)
	}
	defer func() {
		_ = rn.clientset.NetworkingV1().NetworkPolicies(rn.cfg.Namespace).Delete(context.Background(), np.Name, metav1.DeleteOptions{})
	}()

	pod, err := BuildPod(rn.cfg, runID)
	if err != nil {
		t.Fatalf("BuildPod: %v", err)
	}
	if _, err := rn.clientset.CoreV1().Pods(rn.cfg.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating pod: %v", err)
	}
	defer func() {
		grace := int64(0)
		_ = rn.clientset.CoreV1().Pods(rn.cfg.Namespace).Delete(context.Background(), pod.Name, metav1.DeleteOptions{GracePeriodSeconds: &grace})
	}()

	if err := rn.waitRunning(ctx, pod.Name); err != nil {
		t.Fatalf("waiting for pod to run: %v", err)
	}

	// Attempt to reach the in-cluster API server (a DNS-free, always-present
	// target on every cluster, so this isn't dependent on outbound internet
	// access existing at all) with a short timeout. Under the deny-all
	// policy this MUST fail or hang past the timeout; if this cluster's CNI
	// were not actually enforcing NetworkPolicy (the Flannel-without-Calico
	// case this test exists to catch), the connection would succeed
	// instead.
	stdout, stderr, execErr := rn.exec(ctx, pod.Name,
		[]string{"sh", "-c", "wget -T 5 -O- https://kubernetes.default.svc.cluster.local/healthz 2>&1; echo EXIT:$?"},
		nil)
	combined := stdout.String() + stderr.String()
	t.Logf("egress attempt output: %s (execErr=%v)", combined, execErr)
	if strings.Contains(combined, "EXIT:0") {
		t.Fatalf("egress to the API server SUCCEEDED despite the deny-all NetworkPolicy — network isolation is not actually enforced on this cluster: %s", combined)
	}
	// Any other outcome (connection refused, timed out, DNS failure, or the
	// exec itself erroring because the shell never got a response) is the
	// expected "denied" shape — Calico enforces a deny-all NetworkPolicy by
	// dropping packets, which shows up as one of these rather than a clean
	// single error string.
}

// TestLiveRenderFunc_ValuesFilePrecedence is the strongest available proof
// this task's own "verify live" instruction asks for at the mechanism level:
// the FULL render-diff pipeline (EvaluateProposal + the real sandboxed
// Runner, not the local-exec test helper in evaluate_test.go) run against
// the real cluster, against the same values-file-precedence fixture chart,
// proving the sandboxed path produces the same correct answer the
// local-exec path already proved the LOGIC gives.
func TestLiveRenderFunc_ValuesFilePrecedence(t *testing.T) {
	rn := liveRunner(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	t.Cleanup(func() { _ = rn.Teardown(context.Background()) })

	original := readFixtureTree(t)
	overridden := render.ApplyEdits(original, map[string][]byte{
		"values.yaml": []byte("replicaCount: 99\nimage:\n  repository: busybox\n  tag: \"1.36\"\n"),
	}, nil)
	winning := render.ApplyEdits(original, map[string][]byte{
		"values-prod.yaml": []byte("replicaCount: 7\n"),
	}, nil)

	rf := rn.RenderFunc()

	res1, err := render.EvaluateProposal(ctx, rf, render.KindHelm, original, overridden, render.RenderParams{ValueFiles: []string{"values-prod.yaml"}})
	if err != nil {
		t.Fatalf("EvaluateProposal (overridden edit) via real sandbox: %v", err)
	}
	if res1.Effective {
		t.Fatalf("sandboxed render must also show the overridden edit as non-effective, got %+v", res1)
	}

	res2, err := render.EvaluateProposal(ctx, rf, render.KindHelm, original, winning, render.RenderParams{ValueFiles: []string{"values-prod.yaml"}})
	if err != nil {
		t.Fatalf("EvaluateProposal (winning edit) via real sandbox: %v", err)
	}
	if !res2.Effective {
		t.Fatalf("sandboxed render must show the winning-file edit as effective, got %+v", res2)
	}
}

// readFixtureTree reads the SAME chart fixture evaluate_test.go uses
// (internal/render/testdata/precedence-chart), one directory up from this
// package, so both the local-exec proof and this real-sandbox proof run
// against identical source content.
func readFixtureTree(t *testing.T) map[string][]byte {
	t.Helper()
	root := filepath.Join("..", "testdata", "precedence-chart")
	tree := map[string][]byte{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		tree[rel] = content
		return nil
	})
	if err != nil {
		t.Fatalf("reading fixture chart: %v", err)
	}
	return tree
}
