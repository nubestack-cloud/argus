// Package objcache is the agent's in-memory, continuously updated copy of
// the cluster objects the cluster-insight tools read (docs/CLUSTER_INSIGHT_SPECS.md
// CI-F1): topology, path tracing, posture, scheduling explanation, change
// history and the rest answer from here instead of issuing API calls per
// request.
//
// Two properties every consumer relies on:
//
//   - Sensitive values never sit in the cache. The informer transform runs
//     before an object is stored and replaces every container env value and
//     every ConfigMap data/binaryData value with "sha256:<hex>" of the value,
//     and drops managedFields and the last-applied-configuration annotation.
//     The hash keeps "this value changed" detectable for change history
//     without the value itself being readable by anything downstream. This is
//     capture-time redaction (argus-context non-negotiable 9) applied one step
//     earlier than ToolExecutor.Execute, which still redacts every tool output
//     on top. Secrets are never cached at all.
//   - Missing is never silently empty. Each kind carries a State —
//     synced, syncing, forbidden, absent, disabled or error — and every
//     accessor returns ErrUnavailable (with that state) instead of an empty
//     list when the kind is not synced, so a consumer can tell "there are no
//     NetworkPolicies" from "this agent cannot see NetworkPolicies".
package objcache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// Kind states. A consumer that renders results must map anything other than
// StateSynced to "incomplete", never to "none found".
const (
	StateSynced    = "synced"
	StateSyncing   = "syncing"
	StateForbidden = "forbidden"
	StateAbsent    = "absent"
	StateDisabled  = "disabled"
	StateError     = "error"
)

// LastAppliedAnnotation is dropped by the transform; LastAppliedHook sees it
// first.
const LastAppliedAnnotation = "kubectl.kubernetes.io/last-applied-configuration"

// ErrUnavailable is returned (wrapped in *UnavailableError) by every accessor
// whose kind is not synced.
var ErrUnavailable = errors.New("kind not available in the object cache")

// UnavailableError says which kind and why.
type UnavailableError struct {
	Group, Kind, State string
}

func (e *UnavailableError) Error() string {
	return fmt.Sprintf("%s: %s/%s is %s", ErrUnavailable, e.Group, e.Kind, e.State)
}

func (e *UnavailableError) Unwrap() error { return ErrUnavailable }

// KindStatus is one kind's availability, reported to the hub in cluster
// facts and on every tool response as coverage.
type KindStatus struct {
	Group  string `json:"group,omitempty"`
	Kind   string `json:"kind"`
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// Change is one add/update/delete of a cached object, delivered to OnChange
// subscribers after the transform (so Old/New already carry hashed values).
// Adds observed during an informer's initial list are not delivered — they
// are the starting state, not changes.
type Change struct {
	Group string
	Kind  string
	Op    string // add | update | delete
	Old   any
	New   any
	At    time.Time
}

// Resolver answers, for a group/kind, which served resource to watch and
// whether this agent's RBAC allows get+list+watch on it. The agent
// implements it over its RBAC-narrowed discovery (internal/agent/discovery.go).
type Resolver interface {
	// Lookup returns the resource to watch. state is StateSynced-eligible
	// ("" or "ok") when the resource is served and readable, otherwise
	// StateAbsent or StateForbidden. versions is a preference order for
	// dynamic kinds; typed kinds pass their one version.
	Lookup(group, kind string, versions []string) (gvr schema.GroupVersionResource, namespaced bool, state string)
}

// Options configure a Cache.
type Options struct {
	// Exclude disables kinds by "group/Kind" (core group is ""), e.g.
	// "/ConfigMap" or "apps/ReplicaSet". Disabled kinds report StateDisabled.
	Exclude map[string]bool
	// LastAppliedHook, when set, is called by the transform with each object
	// that carries the last-applied annotation, before the annotation is
	// dropped. It must not retain the string; it runs on the informer path
	// and must be fast.
	LastAppliedHook func(group, kind string, obj *unstructured.Unstructured, lastApplied string)
	// LastAppliedFilter, when set, limits LastAppliedHook to objects it
	// accepts — checked on metadata alone, before the object is converted
	// to unstructured for the hook.
	LastAppliedFilter func(obj metav1.Object) bool
}

type entry struct {
	group, kind string
	informer    cache.SharedIndexInformer
	state       string
	reason      string
	// What register was given, kept so Rediscover can attach a kind that
	// was absent or forbidden when the cache was built.
	versions []string
	mk       func() cache.SharedIndexInformer
	gvrOut   *schema.GroupVersionResource
}

// Cache is safe for concurrent use.
type Cache struct {
	opts      Options
	typed     informers.SharedInformerFactory
	dyn       dynamicinformer.DynamicSharedInformerFactory
	mu        sync.RWMutex
	entries   map[string]*entry // "group/Kind"
	subsMu    sync.RWMutex
	subs      []func(Change)
	started   bool
	stop      <-chan struct{}
	startedAt time.Time
	allSynced time.Time
	// firstSync is closed when allSynced is first set, so a caller that
	// reported "still syncing" can re-report as soon as the figures exist
	// rather than on its next periodic pass.
	firstSync chan struct{}
	now       func() time.Time
}

func key(group, kind string) string { return group + "/" + kind }

// New builds a cache over the kinds in typedKinds and dynamicKinds that the
// resolver reports as served and readable. Nothing is watched until Start.
func New(typedClient kubernetes.Interface, dynClient dynamic.Interface, resolver Resolver, opts Options) *Cache {
	c := &Cache{
		opts:      opts,
		entries:   map[string]*entry{},
		firstSync: make(chan struct{}),
		now:       time.Now,
	}
	if typedClient != nil {
		c.typed = informers.NewSharedInformerFactory(typedClient, 0)
	}
	if dynClient != nil {
		c.dyn = dynamicinformer.NewDynamicSharedInformerFactory(dynClient, 0)
	}
	for _, tk := range typedKinds {
		c.register(tk.group, tk.kind, []string{tk.version}, resolver, func() cache.SharedIndexInformer {
			if c.typed == nil {
				return nil
			}
			return tk.informer(c.typed)
		})
	}
	for _, dk := range dynamicKinds {
		dk := dk
		var gvr schema.GroupVersionResource
		c.register(dk.group, dk.kind, dk.versions, resolver, func() cache.SharedIndexInformer {
			if c.dyn == nil {
				return nil
			}
			return c.dyn.ForResource(gvr).Informer()
		}, &gvr)
	}
	return c
}

func (c *Cache) register(group, kind string, versions []string, resolver Resolver, mk func() cache.SharedIndexInformer, gvrOut ...*schema.GroupVersionResource) {
	e := &entry{group: group, kind: kind, versions: versions, mk: mk}
	if len(gvrOut) > 0 {
		e.gvrOut = gvrOut[0]
	}
	c.entries[key(group, kind)] = e
	if c.opts.Exclude[key(group, kind)] {
		e.state = StateDisabled
		return
	}
	c.attach(e, resolver)
}

// attach resolves e and, when it is served and readable, gives it an
// informer. The caller holds c.mu, or the cache is not yet shared.
func (c *Cache) attach(e *entry, resolver Resolver) {
	group, kind, versions, mk := e.group, e.kind, e.versions, e.mk
	if resolver == nil {
		e.state = StateAbsent
		e.reason = "no resolver"
		return
	}
	gvr, _, state := resolver.Lookup(group, kind, versions)
	switch state {
	case "", "ok":
	default:
		e.state = state
		return
	}
	if e.gvrOut != nil {
		*e.gvrOut = gvr
	}
	inf := mk()
	if inf == nil {
		e.state = StateAbsent
		e.reason = "no client"
		return
	}
	e.informer = inf
	e.state = StateSyncing
	g, k := group, kind
	_ = inf.SetTransform(func(obj any) (any, error) { return c.transform(g, k, obj), nil })
	_ = inf.SetWatchErrorHandler(func(_ *cache.Reflector, err error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if isForbidden(err) {
			e.state = StateForbidden
		} else if e.state != StateSynced {
			e.state = StateError
		}
		e.reason = truncate(err.Error(), 200)
	})
	_, _ = inf.AddEventHandler(cache.ResourceEventHandlerDetailedFuncs{
		AddFunc: func(obj any, isInInitialList bool) {
			if isInInitialList {
				return
			}
			c.emit(Change{Group: g, Kind: k, Op: "add", New: obj, At: c.now()})
		},
		UpdateFunc: func(oldObj, newObj any) {
			c.emit(Change{Group: g, Kind: k, Op: "update", Old: oldObj, New: newObj, At: c.now()})
		},
		DeleteFunc: func(obj any) {
			if d, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				obj = d.Obj
			}
			c.emit(Change{Group: g, Kind: k, Op: "delete", Old: obj, At: c.now()})
		},
	})
}

// OnChange registers a subscriber. Subscribers run on informer goroutines and
// must not block; buffer and return.
func (c *Cache) OnChange(fn func(Change)) {
	c.subsMu.Lock()
	defer c.subsMu.Unlock()
	c.subs = append(c.subs, fn)
}

func (c *Cache) emit(ch Change) {
	c.subsMu.RLock()
	subs := c.subs
	c.subsMu.RUnlock()
	for _, fn := range subs {
		fn(ch)
	}
}

// Start begins watching and returns immediately; kinds move from syncing to
// synced as their initial list completes. Safe to call once.
func (c *Cache) Start(ctx context.Context) {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return
	}
	c.started = true
	c.stop = ctx.Done()
	c.startedAt = c.now()
	c.mu.Unlock()
	if c.typed != nil {
		c.typed.Start(ctx.Done())
	}
	if c.dyn != nil {
		c.dyn.Start(ctx.Done())
	}
	go c.watchSync(ctx)
}

// Rediscover re-resolves every kind that was absent or forbidden, so a CRD
// installed or a read granted after the agent started is watched without a
// restart. It returns the kinds it started watching.
func (c *Cache) Rediscover(resolver Resolver) []string {
	c.mu.Lock()
	var added []string
	for _, e := range c.entries {
		if e.informer != nil || (e.state != StateAbsent && e.state != StateForbidden) {
			continue
		}
		c.attach(e, resolver)
		if e.informer != nil {
			added = append(added, key(e.group, e.kind))
		}
	}
	started, stop := c.started, c.stop
	c.mu.Unlock()
	if len(added) > 0 && started {
		// Both factories start only the informers not already running.
		if c.typed != nil {
			c.typed.Start(stop)
		}
		if c.dyn != nil {
			c.dyn.Start(stop)
		}
	}
	sort.Strings(added)
	return added
}

// NeedsRediscovery reports whether any kind is absent or forbidden.
func (c *Cache) NeedsRediscovery() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, e := range c.entries {
		if e.informer == nil && (e.state == StateAbsent || e.state == StateForbidden) {
			return true
		}
	}
	return false
}

func (c *Cache) watchSync(ctx context.Context) {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		pending := 0
		c.mu.Lock()
		for _, e := range c.entries {
			if e.informer == nil {
				continue
			}
			if e.informer.HasSynced() {
				if e.state == StateSyncing || e.state == StateError {
					e.state = StateSynced
					e.reason = ""
				}
				continue
			}
			if e.state == StateSyncing {
				pending++
			}
		}
		if pending == 0 && c.allSynced.IsZero() {
			c.allSynced = c.now()
			close(c.firstSync)
		}
		c.mu.Unlock()
		if pending == 0 {
			// Keep observing at a slower rate so a kind that later turns
			// forbidden/errored and recovers is reflected.
			t.Reset(10 * time.Second)
		}
	}
}

// Status lists every kind the cache knows about, sorted.
func (c *Cache) Status() []KindStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]KindStatus, 0, len(c.entries))
	for _, e := range c.entries {
		out = append(out, KindStatus{Group: e.group, Kind: e.kind, State: e.state, Reason: e.reason})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Group != out[j].Group {
			return out[i].Group < out[j].Group
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

// State returns one kind's state ("" when the kind is not registered).
func (c *Cache) State(group, kind string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if e := c.entries[key(group, kind)]; e != nil {
		return e.state
	}
	return ""
}

// SyncedAt is when every started kind first finished its initial list (zero
// until then). Informers are live after that, so the data's age is "now"
// whenever the watched kinds are synced.
func (c *Cache) SyncedAt() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.allSynced
}

// StartedAt is when Start was called (zero before it).
func (c *Cache) StartedAt() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.startedAt
}

// FirstSync is closed once every started kind has finished its initial list —
// the moment SyncedAt becomes non-zero.
func (c *Cache) FirstSync() <-chan struct{} { return c.firstSync }

// Coverage returns the status of the named kinds that are NOT synced — what
// a tool response reports so its consumer can say the answer is partial.
func (c *Cache) Coverage(kinds ...[2]string) []KindStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []KindStatus
	for _, gk := range kinds {
		e := c.entries[key(gk[0], gk[1])]
		if e == nil {
			out = append(out, KindStatus{Group: gk[0], Kind: gk[1], State: StateAbsent})
			continue
		}
		if e.state != StateSynced {
			out = append(out, KindStatus{Group: e.group, Kind: e.kind, State: e.state, Reason: e.reason})
		}
	}
	return out
}

func (c *Cache) indexer(group, kind string) (cache.Indexer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e := c.entries[key(group, kind)]
	if e == nil {
		return nil, &UnavailableError{Group: group, Kind: kind, State: StateAbsent}
	}
	if e.state != StateSynced || e.informer == nil {
		return nil, &UnavailableError{Group: group, Kind: kind, State: e.state}
	}
	return e.informer.GetIndexer(), nil
}

func listTyped[T any](c *Cache, group, kind, ns string) ([]T, error) {
	idx, err := c.indexer(group, kind)
	if err != nil {
		return nil, err
	}
	var items []any
	if ns == "" {
		items = idx.List()
	} else {
		items, err = idx.ByIndex(cache.NamespaceIndex, ns)
		if err != nil {
			return nil, err
		}
	}
	out := make([]T, 0, len(items))
	for _, it := range items {
		if v, ok := it.(T); ok {
			out = append(out, v)
		}
	}
	return out, nil
}

func getTyped[T any](c *Cache, group, kind, ns, name string) (T, bool, error) {
	var zero T
	idx, err := c.indexer(group, kind)
	if err != nil {
		return zero, false, err
	}
	k := name
	if ns != "" {
		k = ns + "/" + name
	}
	it, ok, err := idx.GetByKey(k)
	if err != nil || !ok {
		return zero, false, err
	}
	v, ok := it.(T)
	return v, ok, nil
}

// Dynamic lists a dynamic kind ("" namespace = all).
func (c *Cache) Dynamic(group, kind, ns string) ([]*unstructured.Unstructured, error) {
	return listTyped[*unstructured.Unstructured](c, group, kind, ns)
}

// DynamicGet returns one dynamic object.
func (c *Cache) DynamicGet(group, kind, ns, name string) (*unstructured.Unstructured, bool, error) {
	return getTyped[*unstructured.Unstructured](c, group, kind, ns, name)
}

// transform is the capture-time redaction point; see the package comment.
func (c *Cache) transform(group, kind string, obj any) any {
	if d, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		d.Obj = c.transform(group, kind, d.Obj)
		return d
	}
	if mo, err := meta.Accessor(obj); err == nil {
		mo.SetManagedFields(nil)
		if ann := mo.GetAnnotations(); ann != nil {
			if la, ok := ann[LastAppliedAnnotation]; ok {
				if c.opts.LastAppliedHook != nil && (c.opts.LastAppliedFilter == nil || c.opts.LastAppliedFilter(mo)) {
					if u, ok := obj.(*unstructured.Unstructured); ok {
						c.opts.LastAppliedHook(group, kind, u, la)
					} else if u, err := toUnstructured(obj); err == nil {
						c.opts.LastAppliedHook(group, kind, u, la)
					}
				}
				delete(ann, LastAppliedAnnotation)
				mo.SetAnnotations(ann)
			}
		}
	}
	hashSensitive(obj)
	return obj
}

// HashValue is the representation the transform stores in place of a
// sensitive value.
func HashValue(v []byte) string {
	sum := sha256.Sum256(v)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
