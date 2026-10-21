package agent

// Live run of the cluster inventory tools (PROJECT.md AD5/AD6) against a real
// cluster, AS the agent's own read-only identity (impersonating
// argus-investigate, the same RBAC the deployed agent has). Read-only: it
// starts an object cache, calls list_helm_releases, list_gitops_apps and
// get_namespace_topology through Execute (so capture-time redaction
// applies), and writes their JSON to a directory for inspection. It never
// prints a Secret: list_helm_releases reads release Secret labels only.
//
//	ARGUS_INVENTORY_LIVE=1 ARGUS_AGENT_COVERAGE_CONTEXT=default KUBECONFIG=<kubeconfig> \
//	ARGUS_INVENTORY_LIVE_OUT=/tmp/out ARGUS_INVENTORY_LIVE_NS=argus-system \
//	  go test ./internal/agent/ -run TestLiveInventoryTools -v

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"argus/internal/agent/objcache"
)

func TestLiveInventoryTools(t *testing.T) {
	if os.Getenv("ARGUS_INVENTORY_LIVE") == "" {
		t.Skip("set ARGUS_INVENTORY_LIVE=1 to run the inventory tools against a real cluster")
	}
	t.Setenv("ARGUS_AGENT_COVERAGE_LIVE", "1")
	cfg := rest.CopyConfig(liveCoverageConfig(t))
	cfg.Impersonate = rest.ImpersonationConfig{UserName: investigateUser}
	cfg.QPS, cfg.Burst = agentClientQPS, agentClientBurst // the deployed agent's limits
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := objcache.New(cs, dyn, newWatchSetResolver(ctx, cs), objcache.Options{})
	c.Start(ctx)
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) && c.SyncedAt().IsZero() {
		time.Sleep(200 * time.Millisecond)
	}
	exec := &ToolExecutor{typed: cs, dynamic: dyn, objects: c}

	outDir := os.Getenv("ARGUS_INVENTORY_LIVE_OUT")
	ns := os.Getenv("ARGUS_INVENTORY_LIVE_NS")
	calls := map[string]string{
		"list_helm_releases":     `{}`,
		"list_gitops_apps":       `{}`,
		"get_namespace_topology": `{}`,
	}
	if ns != "" {
		b, _ := json.Marshal(map[string]string{"namespace": ns})
		calls["get_namespace_topology_ns"] = string(b)
	}
	for name, args := range calls {
		tool := name
		if name == "get_namespace_topology_ns" {
			tool = "get_namespace_topology"
		}
		start := time.Now()
		raw, _, err := exec.Execute(ctx, tool, json.RawMessage(args))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		t.Logf("%s: %d bytes in %s", name, len(raw), time.Since(start).Round(time.Millisecond))
		if outDir != "" {
			if err := os.WriteFile(filepath.Join(outDir, name+".json"), raw, 0o600); err != nil {
				t.Error(err)
			}
		}
	}
}
