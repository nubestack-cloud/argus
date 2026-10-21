package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"argus/internal/agent/objcache"
)

// testCacheResolver treats every built-in kind as served and readable and
// every CRD kind as absent unless listed in dynamic.
type testCacheResolver struct {
	dynamic map[string]schema.GroupVersionResource // "group/Kind"
}

func (r testCacheResolver) Lookup(group, kind string, versions []string) (schema.GroupVersionResource, bool, string) {
	if gvr, ok := r.dynamic[group+"/"+kind]; ok {
		return gvr, true, ""
	}
	builtin := group == "" || group == "apps" || group == "batch" || group == "autoscaling" || group == "policy" ||
		strings.HasSuffix(group, ".k8s.io") && group != "apiextensions.k8s.io" && group != "apiregistration.k8s.io" && group != "gateway.networking.k8s.io"
	if !builtin {
		return schema.GroupVersionResource{}, false, objcache.StateAbsent
	}
	return schema.GroupVersionResource{Group: group, Version: versions[0], Resource: strings.ToLower(kind) + "s"}, true, ""
}

// attachObjectCache seeds typed with objs, starts an object cache over it
// (and the executor's dynamic client for the listed CRD kinds), waits for
// every started kind to sync, and installs it on exec.
func attachObjectCache(t *testing.T, exec *ToolExecutor, typed *k8sfake.Clientset, dynamic map[string]schema.GroupVersionResource, objs ...runtime.Object) *objcache.Cache {
	t.Helper()
	for _, o := range objs {
		if err := typed.Tracker().Add(o); err != nil {
			t.Fatalf("seed %T: %v", o, err)
		}
	}
	c := objcache.New(typed, exec.dynamic, testCacheResolver{dynamic: dynamic}, objcache.Options{})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c.Start(ctx)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		pending := false
		for _, k := range c.Status() {
			if k.State == objcache.StateSyncing {
				pending = true
			}
		}
		if !pending {
			exec.objects = c
			return c
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("object cache never synced: %+v", c.Status())
	return nil
}
