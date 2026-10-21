package agent

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"argus/internal/tunnel"
)

// sweep_listcount_test.go measures what one sweep pass actually costs the
// API server, because PROJECT.md P17's acceptance is a call count and not a
// fixture assertion. Before the shared snapshot landed this printed 25 lists
// for the cluster below, with nine kinds listed two or three times in the
// same pass; it prints 14 now, one per kind.
//
// It is kept as a regression guard rather than deleted after the
// measurement: the failure mode it protects against is silent and easy to
// reintroduce — a new checker that calls the clientset directly, or an
// existing one that grows a second read — and nothing else in the suite
// would notice.

// defaultTestCheckerTimeout is the per-checker deadline every runOneSweep
// test passes. Generous on purpose: these tests drive a fake clientset that
// answers instantly, so the only thing a short value here could do is make
// them flaky on a loaded CI box. The timeout's own behaviour is tested
// directly in TestRunOneSweep_TimeoutIsRecordedAgainstTheNamedChecker.
const defaultTestCheckerTimeout = 30 * time.Second

// sweepCallCounter tallies every List and Get a sweep issues, by resource,
// and records the ResourceVersion each list asked for.
type sweepCallCounter struct {
	lists        map[string]int
	gets         map[string]int
	listVersions map[string]bool
}

func countingClientset(objs ...runtime.Object) (*k8sfake.Clientset, *sweepCallCounter) {
	cs := k8sfake.NewSimpleClientset(objs...)
	c := &sweepCallCounter{lists: map[string]int{}, gets: map[string]int{}, listVersions: map[string]bool{}}
	cs.PrependReactor("list", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		c.lists[action.GetResource().Resource]++
		if la, ok := action.(k8stesting.ListActionImpl); ok {
			c.listVersions[la.ListRestrictions.Fields.String()] = true
		}
		return false, nil, nil
	})
	cs.PrependReactor("get", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		c.gets[action.GetResource().Resource]++
		return false, nil, nil
	})
	return cs, c
}

func (c *sweepCallCounter) total(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func (c *sweepCallCounter) report() string {
	var lines []string
	for r, n := range c.lists {
		lines = append(lines, fmt.Sprintf("  list %-36s %d", r, n))
	}
	for r, n := range c.gets {
		lines = append(lines, fmt.Sprintf("  get  %-36s %d", r, n))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// populatedCluster holds one object of every kind the sweep checkers list,
// so that no checker short-circuits on an empty prior list — i.e. the cost a
// real, busy cluster actually pays, not the floor an empty one does. The
// webhook configuration points at the Service, which is what used to make
// checkWebhookBackingServiceUnreachable issue its own extra EndpointSlice
// list and Service get on top of everything else.
func populatedCluster() []runtime.Object {
	return []runtime.Object{
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "d"}},
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "rs"}},
		&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "sts"}},
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "ds"}},
		&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "pvc"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "p"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "svc"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n"}},
		&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "j"}},
		&autoscalingv2.HorizontalPodAutoscaler{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "hpa"},
			Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
				ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{Kind: "Deployment", APIVersion: "apps/v1", Name: "d"},
			},
		},
		&discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "es", Labels: map[string]string{"kubernetes.io/service-name": "svc"}}},
		&networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "ing"}},
		&admissionregistrationv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "vwc"},
			Webhooks: []admissionregistrationv1.ValidatingWebhook{{
				Name:         "v.example.com",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{Service: &admissionregistrationv1.ServiceReference{Namespace: "default", Name: "svc"}},
			}},
		},
		&admissionregistrationv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "mwc"}},
	}
}

// sweepListedKinds is every kind the typed sweep checkers read. The count
// below is the whole point: one list per entry, per pass, no matter how many
// checkers want it.
var sweepListedKinds = []string{
	"deployments", "replicasets", "statefulsets", "daemonsets", "pods",
	"persistentvolumeclaims", "services", "nodes", "jobs",
	"horizontalpodautoscalers", "endpointslices", "ingresses",
	"validatingwebhookconfigurations", "mutatingwebhookconfigurations",
}

func TestOneSweepListsEachKindExactlyOnce(t *testing.T) {
	cs, counter := countingClientset(populatedCluster()...)
	_, _ = runOneSweep(context.Background(), cs, nil, make(chan tunnel.Finding, 64),
		map[string]time.Time{}, map[string]time.Time{},
		defaultFindingResendCooldown, defaultSweepSustainedThreshold, defaultTestCheckerTimeout, nil)

	t.Logf("one sweep pass against a cluster with one object of every checked kind:\n%s\n  TOTAL lists: %d, gets: %d",
		counter.report(), counter.total(counter.lists), counter.total(counter.gets))

	for _, kind := range sweepListedKinds {
		if got := counter.lists[kind]; got != 1 {
			t.Errorf("%s listed %d time(s) in one sweep, want exactly 1 — a checker is reading past the shared snapshot (PROJECT.md P17(a))", kind, got)
		}
	}
	if got, want := counter.total(counter.lists), len(sweepListedKinds); got != want {
		t.Errorf("sweep issued %d List calls, want %d (one per kind in sweepListedKinds); by resource:\n%s", got, want, counter.report())
	}
	// Both of the sweep's former per-object reads — the HPA's scale-target
	// Deployment and the webhook's backing Service — are answered from the
	// snapshot now. Neither scales with cluster size any more.
	if got := counter.total(counter.gets); got != 0 {
		t.Errorf("sweep issued %d Get call(s), want 0:\n%s", got, counter.report())
	}
}

// TestSweepReadsAreServedFromTheWatchCache pins PROJECT.md P17(b): every
// read the snapshot makes asks for ResourceVersion "0", so the API server
// answers from its watch cache instead of doing a quorum read through to
// etcd. The fake clientset does not model the watch cache, so what this can
// prove is that the option is set on the request — which is the part that
// can regress.
func TestSweepReadsAreServedFromTheWatchCache(t *testing.T) {
	if sweepListOptions.ResourceVersion != "0" {
		t.Fatalf("sweepListOptions.ResourceVersion = %q, want \"0\" — every sweep read is a sustained-window check and none needs a quorum read (PROJECT.md P17(b))", sweepListOptions.ResourceVersion)
	}
	if got := sweepListOptionsFor("app=x"); got.ResourceVersion != "0" || got.LabelSelector != "app=x" {
		t.Errorf("sweepListOptionsFor lost a field: %+v", got)
	}
	if sweepListOptions.LabelSelector != "" {
		t.Error("sweepListOptionsFor must not mutate the shared sweepListOptions value")
	}
}

// --- PROJECT.md P28: the UNSTRUCTURED half of the same measurement ---
//
// The test above counts only what the typed clientset is asked for, because
// when it was written that was the only half a snapshot served. It is not
// the whole bill. A pass also issues, through the DYNAMIC client: one list
// per watched kind for generic_predicates.go, one per CRD-backed
// dynamicSweepChecker, one Limit:1 pod probe for the memory guard — and, at
// the time P28 was raised, one cluster-wide list PER DECLARATIVE RULE, 37 of
// them, including two full unstructured Pod lists and six Deployment lists.
//
// P28's acceptance is a measured before/after count, so this counts every
// list a pass issues on either client, with the real embedded rule set
// loaded.

// supportedGVKListKinds is the GVR -> list-kind map the fake dynamic client
// needs in order to answer a List for every kind a real pass reads. Without
// it the fake PANICS for an unregistered resource (see listOneResource),
// which the production code recovers and reports as a skipped kind — so a
// fixture that did not register everything would silently measure a much
// cheaper pass than a real cluster pays for.
func supportedGVKListKinds() map[schema.GroupVersionResource]string {
	out := make(map[schema.GroupVersionResource]string, len(supportedGVKs))
	for gvk, res := range supportedGVKs {
		out[res.gvr] = gvk.Kind + "List"
	}
	// The CRD-backed dynamicSweepCheckers read resources that are not in
	// supportedGVKs at all.
	out[argoApplicationsGVR] = "ApplicationList"
	return addScheduleListKinds(out)
}

func countingDynamicClient(objs ...runtime.Object) (*dynfake.FakeDynamicClient, *sweepCallCounter) {
	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), supportedGVKListKinds(), objs...)
	c := &sweepCallCounter{lists: map[string]int{}, gets: map[string]int{}, listVersions: map[string]bool{}}
	dyn.PrependReactor("list", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		c.lists[action.GetResource().Resource]++
		return false, nil, nil
	})
	return dyn, c
}

// unstructuredCluster is populatedCluster's dynamic-client counterpart: one
// object of every kind a declarative rule targets, so no rule short-circuits
// on an empty list. The three objects carrying a real label selector
// (Deployment, NetworkPolicy, PodDisruptionBudget) are what drive the
// per-object Pod lookups the selector-shaped comparators make.
func unstructuredCluster() []runtime.Object {
	obj := func(apiVersion, kind, ns, name string, spec map[string]any) *unstructured.Unstructured {
		u := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": apiVersion, "kind": kind,
			"metadata": map[string]any{"name": name, "uid": "uid-" + name},
		}}
		if ns != "" {
			_ = unstructured.SetNestedField(u.Object, ns, "metadata", "namespace")
		}
		if spec != nil {
			u.Object["spec"] = spec
		}
		return u
	}
	selector := map[string]any{"matchLabels": map[string]any{"app": "x"}}
	out := []runtime.Object{
		obj("apps/v1", "Deployment", "default", "d", map[string]any{"selector": selector}),
		obj("apps/v1", "StatefulSet", "default", "sts", nil),
		obj("apps/v1", "DaemonSet", "default", "ds", nil),
		obj("v1", "Pod", "default", "p", nil),
		obj("v1", "PersistentVolume", "", "pv", nil),
		obj("v1", "PersistentVolumeClaim", "default", "pvc", nil),
		obj("v1", "Node", "", "n", nil),
		obj("v1", "Namespace", "", "ns", nil),
		obj("v1", "ResourceQuota", "default", "rq", nil),
		obj("batch/v1", "Job", "default", "j", nil),
		obj("autoscaling/v2", "HorizontalPodAutoscaler", "default", "hpa", nil),
		obj("networking.k8s.io/v1", "NetworkPolicy", "default", "np", map[string]any{"podSelector": selector}),
		obj("policy/v1", "PodDisruptionBudget", "default", "pdb", map[string]any{"selector": selector}),
	}
	return out
}

func TestOneSweepListsEachKindOnceAcrossBothClients(t *testing.T) {
	rules, err := LoadRules("")
	if err != nil {
		t.Fatalf("loading the embedded rule set: %v", err)
	}
	cs, typed := countingClientset(populatedCluster()...)
	dyn, dynamicCounter := countingDynamicClient(unstructuredCluster()...)

	_, _ = runOneSweep(context.Background(), cs, dyn, make(chan tunnel.Finding, 4096),
		map[string]time.Time{}, map[string]time.Time{},
		defaultFindingResendCooldown, defaultSweepSustainedThreshold, defaultTestCheckerTimeout, rules)

	t.Logf("ONE SWEEP PASS, %d declarative rules loaded, one object of every kind:\n"+
		"  typed client   (sweep_snapshot.go):\n%s\n  dynamic client (generic predicates, CRD checkers, rules):\n%s\n"+
		"  TOTAL lists: typed %d + dynamic %d = %d",
		len(rules), typed.report(), dynamicCounter.report(),
		typed.total(typed.lists), dynamicCounter.total(dynamicCounter.lists),
		typed.total(typed.lists)+dynamicCounter.total(dynamicCounter.lists))

	for resource, n := range dynamicCounter.lists {
		if resource == "applications" {
			// The one kind still read twice, deliberately left alone:
			// checkArgoSyncFailed is a CRD-backed dynamicSweepChecker that
			// runs BEFORE the shared snapshot is built, so that an Argo CD
			// sync failure is still detected on a pass where the whole-
			// cluster unstructured read is refused for memory (PROJECT.md
			// P18). Argo Applications are a handful of objects on any
			// cluster; the trade is one small list for a check that keeps
			// working in the degraded mode.
			if n > 2 {
				t.Errorf("applications listed %d times, want at most 2 (the shared snapshot + checkArgoSyncFailed)", n)
			}
			continue
		}
		if resource == "pods" {
			// The memory guard's Limit:1 sizing probe is a second, deliberate
			// read of one object (sweepMemoryGuard.sizeCluster) — it is not a
			// cluster-wide list and is priced as one object, so it is allowed
			// on top of the one full Pod list.
			if n > 2 {
				t.Errorf("pods listed %d times through the dynamic client, want at most 2 (one cluster-wide list + the Limit:1 sizing probe) — PROJECT.md P28", n)
			}
			continue
		}
		if n > 1 {
			t.Errorf("%s listed %d times through the dynamic client in one pass, want 1 — every reader of a kind must share the pass' one list (PROJECT.md P28)", resource, n)
		}
	}
}

// --- PROJECT.md P17(c): pagination, and the choice not to use it ---

// TestEverySweepListTypeCanBePaged is the contract behind
// sweep_pagination.go's reflection. listPaged reaches a list's Continue
// token and Items slice by field name rather than through a type switch,
// because a type switch over sixteen concrete list types is a list that goes
// stale the first time someone adds a kind to sweep_snapshot.go and forgets.
//
// The cost of that choice is that a type which does not follow the
// Kubernetes list conventions would fail at RUNTIME, on a large cluster,
// under memory pressure — the worst possible place. This test is what pays
// that cost back: it fails at compile-plus-unit-test time instead.
func TestEverySweepListTypeCanBePaged(t *testing.T) {
	// Every list type the sweep pages: the fourteen typed kinds of
	// sweep_snapshot.go, plus the unstructured list both the many-kind pass
	// and the declarative-rule fallback read.
	lists := []any{
		&appsv1.DeploymentList{}, &appsv1.ReplicaSetList{}, &appsv1.StatefulSetList{}, &appsv1.DaemonSetList{},
		&corev1.PodList{}, &corev1.PersistentVolumeClaimList{}, &corev1.ServiceList{}, &corev1.NodeList{},
		&batchv1.JobList{}, &autoscalingv2.HorizontalPodAutoscalerList{}, &discoveryv1.EndpointSliceList{},
		&networkingv1.IngressList{}, &admissionregistrationv1.ValidatingWebhookConfigurationList{},
		&admissionregistrationv1.MutatingWebhookConfigurationList{},
		&unstructured.UnstructuredList{},
	}
	for _, list := range lists {
		if _, err := listContinue(list); err != nil {
			t.Errorf("%T: %v", list, err)
		}
		if err := appendSweepListItems(list, list); err != nil {
			t.Errorf("%T: %v", list, err)
		}
	}
	// And the negative case, so the helpers are not quietly succeeding on
	// anything at all.
	if err := appendSweepListItems(&corev1.Pod{}, &corev1.Pod{}); err == nil {
		t.Error("appendSweepListItems accepted a non-list object")
	}
}

// TestPaginatedReadFollowsContinueAndMergesPages drives listPaged over a
// fetch that behaves like a real API server does for a Limit request, and
// checks the three things a caller depends on: every object arrives, the
// order is preserved, and what comes back is one ordinary list rather than a
// wrapper.
func TestPaginatedReadFollowsContinueAndMergesPages(t *testing.T) {
	const total = 1250
	var requested []metav1.ListOptions
	fetch := func(_ context.Context, opts metav1.ListOptions) (*corev1.PodList, error) {
		requested = append(requested, opts)
		start := 0
		if opts.Continue != "" {
			fmt.Sscanf(opts.Continue, "at-%d", &start)
		}
		end := start + int(opts.Limit)
		if end > total {
			end = total
		}
		out := &corev1.PodList{}
		for i := start; i < end; i++ {
			out.Items = append(out.Items, corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("pod-%04d", i)}})
		}
		if end < total {
			out.Continue = fmt.Sprintf("at-%d", end)
			remaining := int64(total - end)
			out.RemainingItemCount = &remaining
		}
		return out, nil
	}

	got, err := listPaged(context.Background(), sweepReadPlan{paginate: true, perObject: typedLiveBytesPerObject, what: "pods"}, fetch)
	if err != nil {
		t.Fatalf("listPaged: %v", err)
	}
	if len(got.Items) != total {
		t.Fatalf("paginated read returned %d objects, want %d — a page was dropped, and a checker reading absence as a fact would report every one of them as gone", len(got.Items), total)
	}
	for i := range got.Items {
		if want := fmt.Sprintf("pod-%04d", i); got.Items[i].Name != want {
			t.Fatalf("item %d is %q, want %q — pages were merged out of order", i, got.Items[i].Name, want)
		}
	}
	if got.Continue != "" || got.RemainingItemCount != nil {
		t.Errorf("the merged list still advertises more to fetch (continue=%q, remaining=%v) — a caller that believed it would re-request objects this list already holds", got.Continue, got.RemainingItemCount)
	}
	if len(requested) != 3 {
		t.Fatalf("1250 objects at a page size of %d took %d requests, want 3", sweepPageSize, len(requested))
	}
	for i, opts := range requested {
		if opts.Limit != sweepPageSize {
			t.Errorf("request %d asked for Limit %d, want %d", i, opts.Limit, sweepPageSize)
		}
		// The API server ignores Limit when ResourceVersion is set, so a
		// paginated request that still asks for the watch cache silently
		// gets the whole collection back — the exact unbounded read
		// pagination exists to prevent, and invisible when it happens.
		if opts.ResourceVersion != "" {
			t.Errorf("request %d asked for the watch cache (resourceVersion=%q) AND a Limit — the API server honours only the former", i, opts.ResourceVersion)
		}
	}
}

// TestUnpaginatedPlanIsTheWatchCacheRead pins that the default path is
// untouched: one request, resourceVersion=0, no Limit. This is what every
// correctly-sized agent does for every read, so a regression here gives back
// everything P17(b) bought.
func TestUnpaginatedPlanIsTheWatchCacheRead(t *testing.T) {
	var requested []metav1.ListOptions
	fetch := func(_ context.Context, opts metav1.ListOptions) (*corev1.PodList, error) {
		requested = append(requested, opts)
		return &corev1.PodList{Items: []corev1.Pod{{}}}, nil
	}
	if _, err := listPaged(context.Background(), sweepReadPlan{}, fetch); err != nil {
		t.Fatalf("listPaged: %v", err)
	}
	if len(requested) != 1 {
		t.Fatalf("an unpaginated read made %d requests, want 1", len(requested))
	}
	if requested[0].ResourceVersion != "0" || requested[0].Limit != 0 {
		t.Errorf("unpaginated read asked for %+v, want resourceVersion=0 and no Limit", requested[0])
	}
}

// TestPaginatedReadStopsWhenTheServerSaysTheRestWillNotFit is the property
// that makes pagination a bound rather than a better guess: the guard's
// bytes-per-object constant is an assumption, but remainingItemCount is the
// server's own count, so a read whose objects turn out to be far heavier
// than assumed is stopped after a page instead of after all of them.
func TestPaginatedReadStopsWhenTheServerSaysTheRestWillNotFit(t *testing.T) {
	// A budget with room for the first page and nothing like room for the
	// 200,000 objects the server says are still to come.
	g := &sweepMemoryGuard{limit: 256 << 20, budget: 230 << 20}
	pages := 0
	fetch := func(_ context.Context, opts metav1.ListOptions) (*corev1.PodList, error) {
		pages++
		out := &corev1.PodList{Items: make([]corev1.Pod, sweepPageSize)}
		out.Continue = "more"
		remaining := int64(200000)
		out.RemainingItemCount = &remaining
		return out, nil
	}
	_, err := listPaged(context.Background(), sweepReadPlan{
		paginate: true, perObject: typedLiveBytesPerObject, what: "the cluster-wide Pod list", guard: g,
	}, fetch)
	if !errors.Is(err, errSweepMemoryBudget) {
		t.Fatalf("want a budget refusal once the server reported what was left, got %v", err)
	}
	if pages != 1 {
		t.Errorf("read continued for %d pages after the server said the rest would not fit, want 1", pages)
	}
	if !strings.Contains(err.Error(), "part-way through") {
		t.Errorf("a mid-read stop must say so, got %q", err)
	}
}
