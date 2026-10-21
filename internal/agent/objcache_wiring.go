package agent

import (
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"argus/internal/agent/objcache"
	"argus/internal/logging"
	"argus/internal/tunnel"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
)

// activeObjectCache is the process's object cache (docs/CLUSTER_INSIGHT_SPECS.md
// CI-F1), nil when disabled, when this is a remediation-role agent, or when
// no cluster is reachable. Read by the facts refresh and the tool handlers.
var activeObjectCache atomic.Pointer[objcache.Cache]

// watchSetResolver answers objcache.Resolver from the agent's existing
// RBAC-narrowed discovery: readable = in DiscoverWatchSet's result (served
// with get+list+watch AND granted), forbidden = served but not granted,
// absent = not served at all. Built at cache start and again by
// rediscoverObjectKinds, which is how a CRD installed or a read granted later
// gets watched without a restart.
type watchSetResolver struct {
	readable map[schema.GroupVersionKind]bool
	gvr      map[schema.GroupVersionKind]schema.GroupVersionResource
	served   map[string]bool // "group/Kind"
}

func newWatchSetResolver(ctx context.Context, clientset kubernetes.Interface) *watchSetResolver {
	r := &watchSetResolver{
		readable: map[schema.GroupVersionKind]bool{},
		gvr:      map[schema.GroupVersionKind]schema.GroupVersionResource{},
		served:   map[string]bool{},
	}
	ws, _, err := DiscoverWatchSet(ctx, clientset.Discovery(), clientset.AuthorizationV1().SelfSubjectRulesReviews())
	if err != nil {
		logger.WarnContext(ctx, "object cache: watch-set discovery failed; every kind will report absent", logging.Err(err))
	}
	for gvk, dr := range ws {
		r.readable[gvk] = true
		r.gvr[gvk] = dr.GVR
	}
	// Served-but-not-readable is what turns "absent" into "forbidden". A
	// partial discovery failure leaves some groups unknown, which then
	// report absent — the conservative reading, since nothing is watched
	// either way.
	_, lists, _ := clientset.Discovery().ServerGroupsAndResources()
	for _, l := range lists {
		gv, err := schema.ParseGroupVersion(l.GroupVersion)
		if err != nil {
			continue
		}
		for _, res := range l.APIResources {
			if strings.Contains(res.Name, "/") {
				continue
			}
			r.served[gv.Group+"/"+res.Kind] = true
		}
	}
	return r
}

func (r *watchSetResolver) Lookup(group, kind string, versions []string) (schema.GroupVersionResource, bool, string) {
	for _, v := range versions {
		gvk := schema.GroupVersionKind{Group: group, Version: v, Kind: kind}
		if r.readable[gvk] {
			return r.gvr[gvk], true, ""
		}
	}
	// A readable kind under a version this cache does not handle is absent
	// for our purposes, as is a kind nobody serves.
	if r.served[group+"/"+kind] {
		for gvk := range r.readable {
			if gvk.Group == group && gvk.Kind == kind {
				return schema.GroupVersionResource{}, false, objcache.StateAbsent
			}
		}
		return schema.GroupVersionResource{}, false, objcache.StateForbidden
	}
	return schema.GroupVersionResource{}, false, objcache.StateAbsent
}

// startObjectCache builds and starts the cache from the tool executor's
// clients. Returns nil (and logs) when it cannot.
func startObjectCache(ctx context.Context, cfg Config, executor *ToolExecutor, hook objcacheHook) *objcache.Cache {
	if !cfg.ObjectCacheEnabled || executor == nil || executor.typed == nil {
		return nil
	}
	exclude := map[string]bool{}
	for _, k := range cfg.ObjectCacheExclude {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if !strings.Contains(k, "/") {
			k = "/" + k
		}
		exclude[k] = true
	}
	resolver := newWatchSetResolver(ctx, executor.typed)
	c := objcache.New(executor.typed, executor.dynamic, resolver, objcache.Options{
		Exclude:           exclude,
		LastAppliedHook:   hook.lastApplied,
		LastAppliedFilter: gitOpsManaged,
	})
	activeChangeStream.subscribe(c)
	c.Start(ctx)
	activeObjectCache.Store(c)
	executor.objects = c
	logger.InfoContext(ctx, "object cache started")
	go rediscoverObjectKinds(ctx, c, executor.typed)
	return c
}

// objectKindRediscovery is how often kinds that were absent or forbidden are
// looked up again: one discovery pass and one rules review, only while some
// kind is still missing.
const objectKindRediscovery = 3 * time.Minute

func rediscoverObjectKinds(ctx context.Context, c *objcache.Cache, clientset kubernetes.Interface) {
	t := time.NewTicker(objectKindRediscovery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if !c.NeedsRediscovery() {
			continue
		}
		if added := c.Rediscover(newWatchSetResolver(ctx, clientset)); len(added) > 0 {
			logger.InfoContext(ctx, "object cache now watching kinds that became available", slog.Any("kinds", added))
		}
	}
}

// objcacheHook lets later features observe objects at transform time
// without objcache knowing about them.
type objcacheHook struct {
	lastApplied func(group, kind string, obj *unstructured.Unstructured, lastApplied string)
}

// pendingFirstSync is the running cache's first-sync signal, or nil when
// there is no cache or its first sync already completed — a nil channel never
// fires in a select, so callers need no separate check.
func pendingFirstSync() <-chan struct{} {
	c := activeObjectCache.Load()
	if c == nil || !c.SyncedAt().IsZero() {
		return nil
	}
	return c.FirstSync()
}

// objectCacheFacts renders the cache status for ClusterFacts.
func objectCacheFacts() *tunnel.ClusterObjectCache {
	c := activeObjectCache.Load()
	if c == nil {
		return nil
	}
	out := &tunnel.ClusterObjectCache{SyncedAt: c.SyncedAt()}
	for _, k := range c.Status() {
		out.Kinds = append(out.Kinds, tunnel.CacheKindState{Group: k.Group, Kind: k.Kind, State: k.State, Reason: k.Reason})
	}
	return out
}
