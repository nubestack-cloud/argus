package agent

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"argus/internal/agent/objcache"
)

// Right after an agent restarts, its first facts snapshot goes out before the
// object cache has listed anything. That summary must say "syncing" and carry
// no counts — not file every kind under `unavailable`, which the cluster page
// reads as "not visible to the agent" while the Nodes table lists the nodes.
func TestClusterSummaryWhileCacheSyncingCarriesNoFigures(t *testing.T) {
	c := objcache.New(k8sfake.NewSimpleClientset(), nil, testCacheResolver{}, objcache.Options{})
	var got map[string]any
	if err := json.Unmarshal(clusterSummaryFrom(c), &got); err != nil {
		t.Fatal(err)
	}
	if got["cacheState"] != "syncing" {
		t.Fatalf("cacheState = %v, want syncing (%v)", got["cacheState"], got)
	}
	if _, ok := got["cacheStartedAt"]; !ok {
		t.Error("a syncing summary must say when the cache started")
	}
	for _, k := range []string{"resourceCounts", "capacity", "networkPolicyCoverage", "nodeVersionSkew"} {
		if _, ok := got[k]; ok {
			t.Errorf("a syncing summary must carry no %s (%v)", k, got)
		}
	}
}

func TestClusterSummaryAfterFirstSyncCarriesCounts(t *testing.T) {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}, Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}}
	c := objcache.New(k8sfake.NewSimpleClientset(node), nil, testCacheResolver{}, objcache.Options{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Start(ctx)
	select {
	case <-c.FirstSync():
	case <-time.After(10 * time.Second):
		t.Fatal("cache never synced")
	}
	var got struct {
		CacheState     string `json:"cacheState"`
		ResourceCounts struct {
			Nodes       *struct{ Total int } `json:"nodes"`
			Unavailable []string             `json:"unavailable"`
		} `json:"resourceCounts"`
	}
	if err := json.Unmarshal(clusterSummaryFrom(c), &got); err != nil {
		t.Fatal(err)
	}
	if got.CacheState != "synced" || got.ResourceCounts.Nodes == nil || got.ResourceCounts.Nodes.Total != 1 {
		t.Fatalf("synced summary = %+v", got)
	}
	if len(got.ResourceCounts.Unavailable) != 0 {
		t.Errorf("unavailable = %v, want none once synced", got.ResourceCounts.Unavailable)
	}
}

// pendingFirstSync is what lets a session re-send facts the moment the first
// sync completes: a channel while syncing, nil once synced or with no cache.
func TestPendingFirstSync(t *testing.T) {
	prev := activeObjectCache.Load()
	t.Cleanup(func() { activeObjectCache.Store(prev) })

	activeObjectCache.Store(nil)
	if pendingFirstSync() != nil {
		t.Error("no cache: want nil")
	}
	c := objcache.New(k8sfake.NewSimpleClientset(), nil, testCacheResolver{}, objcache.Options{})
	activeObjectCache.Store(c)
	if pendingFirstSync() == nil {
		t.Fatal("unsynced cache: want a channel")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Start(ctx)
	<-c.FirstSync()
	if pendingFirstSync() != nil {
		t.Error("synced cache: want nil")
	}
}
