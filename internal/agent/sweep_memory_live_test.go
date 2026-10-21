package agent

// Live, cluster-touching measurement of what ONE sweep pass costs this
// agent's own memory — PROJECT.md P18's acceptance asks for a measured
// objects-to-memory table, and no fake clientset can produce one: the number
// that matters is what decoding a real API server's real JSON list response
// leaves on the Go heap, which a fixture that hands back pre-built structs
// does not model at all.
//
// Skipped unless ARGUS_AGENT_SWEEP_MEM_LIVE=1, following the same convention
// sweep_listcount_live_test.go, rules_live_test.go, internal/gitops/
// live_test.go and internal/render/sandbox/runner_live_test.go already use.
//
// Run against a disposable kind cluster ONLY. The measurement half is
// read-only (it lists, it never writes); the LOADER half
// (TestLiveSyntheticObjectLoad, behind its own second env var) creates
// thousands of objects in one dedicated namespace and is the reason this
// file must never be pointed at a cluster anyone cares about:
//
//	# 1. load a synthetic cluster of 5,000 pods (+ proportional complement)
//	ARGUS_AGENT_SWEEP_MEM_LIVE=1 ARGUS_AGENT_SWEEP_MEM_PODS=5000 \
//	  KUBECONFIG=/path/to/disposable.kubeconfig \
//	  go test ./internal/agent/ -run TestLiveSyntheticObjectLoad -v -timeout 30m
//
//	# 2. measure one pass against it
//	ARGUS_AGENT_SWEEP_MEM_LIVE=1 KUBECONFIG=/path/to/disposable.kubeconfig \
//	  go test ./internal/agent/ -run TestLiveSweepMemoryFootprint -v -timeout 30m
//
// # Measure the identity, not just the cluster
//
// Point this at a kubeconfig whose credential is bound to the chart's own
// argus-investigate ClusterRole (deploy/helm/argus-agent/templates/
// clusterrole.yaml), not at cluster-admin. The unstructured half of a pass
// lists whatever ServerPreferredResources ∩ THIS IDENTITY'S RBAC discovers
// (generic_predicates.go's discovered watch set), so a cluster-admin
// kubeconfig measures a kind set no real agent ever lists — including
// Secrets — and overstates the peak by a wide margin. On the cluster the
// recorded table came from, the agent's own identity resolved 33 kinds and
// RBAC excluded 24 more that cluster-admin would have listed.
//
// Setting that identity up on a throwaway cluster is four commands — render
// the chart's ClusterRole, bind it to a ServiceAccount, mint a token, point
// a kubeconfig at it:
//
//	helm template argus-agent deploy/helm/argus-agent \
//	  --set hub.apiUrl=https://example.invalid --set enrollment.token=x \
//	  -s templates/clusterrole.yaml | kubectl apply -f -
//	kubectl create namespace argus-system
//	kubectl create serviceaccount argus-investigate -n argus-system
//	kubectl create clusterrolebinding argus-investigate \
//	  --clusterrole=argus-investigate \
//	  --serviceaccount=argus-system:argus-investigate
//	kubectl create token argus-investigate -n argus-system --duration=24h
//
// The LOADER needs write access and must therefore run under the cluster's
// admin kubeconfig, not that one.
//
// # What the two numbers mean
//
// A pass has two peaks, not one, and they do not overlap (runOneSweep drops
// the typed snapshot before the dynamic half — see runTypedSweepCheckers):
//
//   - the TYPED peak: all 14 typed lists of sweep_snapshot.go held at once.
//   - the UNSTRUCTURED peak: listWatchedKindObjects' map of every
//     supportedGVKs kind plus the discovered watch set, as
//     map[string]any trees.
//
// For each, three different things are measured, because they answer three
// different questions:
//
//   - retained: live heap the result holds, after a forced GC. This is what
//     "holding the whole object set" actually costs.
//   - churn: total bytes allocated while producing it, garbage included.
//     JSON decoding allocates several times what it retains, and with Go's
//     default GOGC=100 that garbage is what pushes RSS above the live set.
//   - peak in-use: the highest processMemoryInUse() sampled while the half
//     ran — the closest proxy this process has for what the kernel would
//     OOM-kill on, and therefore the number the chart default is sized
//     against.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"argus/internal/tunnel"
)

// syntheticNamespace is the one namespace the loader writes into and the
// only one it deletes. Named, not derived, so a cleanup run can always find
// what a previous load left behind.
const syntheticNamespace = "argus-p18-synthetic"

// liveMemRestConfig resolves the kubeconfig exactly the way
// sweep_listcount_live_test.go's own helper does, and applies the same
// production client tuning (PROJECT.md P20) so the measurement is of a
// client a real agent would have built.
func liveMemRestConfig(t *testing.T, qps float32, burst int) *rest.Config {
	t.Helper()
	if os.Getenv("ARGUS_AGENT_SWEEP_MEM_LIVE") != "1" {
		t.Skip("set ARGUS_AGENT_SWEEP_MEM_LIVE=1 (and a disposable-cluster KUBECONFIG/context) to measure a sweep pass' memory")
	}
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		home, _ := os.UserHomeDir()
		kubeconfig = filepath.Join(home, ".kube", "config")
	}
	rules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: os.Getenv("ARGUS_AGENT_SWEEP_MEM_CONTEXT")}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err != nil {
		t.Fatalf("building rest.Config: %v", err)
	}
	cfg.QPS = qps
	cfg.Burst = burst
	cfg.UserAgent = agentUserAgent()
	return cfg
}

// --- the measurement itself ---

// memMeasurement is one half of a pass, measured three ways. See this file's
// own doc comment for why one number is not enough.
type memMeasurement struct {
	retained uint64
	churn    uint64
	peak     uint64
}

func (m memMeasurement) String() string {
	return fmt.Sprintf("retained %s, churn %s, peak in-use %s", mib(m.retained), mib(m.churn), mib(m.peak))
}

// measureRetained runs build, samples processMemoryInUse() throughout, and
// reports what the returned value costs. The returned value is handed back
// so the caller can keep it alive across the measurement of the NEXT half
// (or deliberately drop it, which is what runOneSweep itself does).
func measureRetained(build func() any) (memMeasurement, any) {
	runtime.GC()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	baseline := processMemoryInUse()

	stop := make(chan struct{})
	var mu sync.Mutex
	peak := baseline
	go func() {
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				now := processMemoryInUse()
				mu.Lock()
				if now > peak {
					peak = now
				}
				mu.Unlock()
			}
		}
	}()

	v := build()

	close(stop)
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	runtime.GC()
	var settled runtime.MemStats
	runtime.ReadMemStats(&settled)
	runtime.KeepAlive(v)

	mu.Lock()
	observedPeak := peak
	mu.Unlock()

	m := memMeasurement{
		retained: saturatingSub(settled.HeapAlloc, before.HeapAlloc),
		churn:    saturatingSub(after.TotalAlloc, before.TotalAlloc),
		peak:     observedPeak,
	}
	return m, v
}

func TestLiveSweepMemoryFootprint(t *testing.T) {
	cfg := liveMemRestConfig(t, agentClientQPS, agentClientBurst)
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("building clientset: %v", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("building dynamic client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	// The real agent widens the unstructured half to the discovered watch
	// set at startup (runSweepDetector calls this once); measuring without
	// it would measure supportedGVKs' fixed set only, which is not what a
	// deployed agent lists. Restored so this global cannot leak into
	// another test in this package.
	prevCache := discoveredWatchSetCache.Load()
	t.Cleanup(func() { discoveredWatchSetCache.Store(prevCache) })
	enableDiscoveredWatchSet(clientset)

	t.Logf("agent memory limit as this process sees it: %s", sweepMemoryLimitDescription())

	// --- half 1: the typed snapshot, all 14 lists held at once ---
	var typedCounts map[string]int
	typed, held := measureRetained(func() any {
		snap := newSweepSnapshot(clientset)
		typedCounts = loadEveryTypedList(ctx, t, snap)
		return snap
	})
	reportHalf(t, "TYPED (14 lists of sweep_snapshot.go, held simultaneously)", typed, typedCounts)

	// Dropped exactly where runOneSweep drops it (runTypedSweepCheckers
	// returns), so the unstructured half below is measured from the same
	// baseline a real pass gives it. KeepAlive first, so what was just
	// reported is a measurement of something that was genuinely still
	// reachable while it was being measured.
	runtime.KeepAlive(held)
	held = nil
	runtime.GC()

	// --- half 2: the unstructured map of every watched kind ---
	unstructuredCounts := map[string]int{}
	unstructured, held := measureRetained(func() any {
		objs, err := listWatchedKindObjects(ctx, dyn, sweepReadPlan{})
		if err != nil {
			t.Errorf("listWatchedKindObjects: %v", err)
		}
		for kind, items := range objs.objects {
			unstructuredCounts[kind] = len(items)
		}
		return objs
	})
	reportHalf(t, "UNSTRUCTURED (listWatchedKindObjects: supportedGVKs + discovered watch set)", unstructured, unstructuredCounts)
	runtime.KeepAlive(held)
	held = nil
	runtime.GC()

	// --- the wire, for scaling this table to a cluster whose objects are
	// fatter or thinner than the synthetic ones ---
	raw, err := clientset.CoreV1().RESTClient().Get().AbsPath("/api/v1/pods").Param("resourceVersion", "0").DoRaw(ctx)
	if err != nil {
		t.Logf("could not measure the Pod list's wire size (%v) — the heap numbers above stand on their own", err)
		return
	}
	pods := typedCounts["Pod"]
	if pods > 0 {
		t.Logf("WIRE: the cluster-wide Pod list is %s of JSON for %d pods (%d bytes/pod on the wire)",
			mib(uint64(len(raw))), pods, len(raw)/pods)
	}
}

// reportHalf prints one half of a pass as the table row P18 asks for, plus
// the per-kind counts behind it so a reader can see WHICH kind dominates
// rather than having to trust that it is Pods.
func reportHalf(t *testing.T, label string, m memMeasurement, counts map[string]int) {
	t.Helper()
	total := 0
	for _, n := range counts {
		total += n
	}
	t.Logf("%s", label)
	t.Logf("  %d objects across %d kinds: %s", total, len(counts), m)
	if total > 0 {
		t.Logf("  %d bytes retained per object, %d bytes churned per object", m.retained/uint64(total), m.churn/uint64(total))
	}
	type kc struct {
		kind  string
		count int
	}
	ordered := make([]kc, 0, len(counts))
	for k, n := range counts {
		ordered = append(ordered, kc{k, n})
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].count != ordered[j].count {
			return ordered[i].count > ordered[j].count
		}
		return ordered[i].kind < ordered[j].kind
	})
	for _, o := range ordered {
		if o.count == 0 {
			continue
		}
		t.Logf("    %-32s %7d", o.kind, o.count)
	}
}

// loadEveryTypedList asks the snapshot for every kind it can cache, which is
// exactly what a pass in which every typed checker runs ends up holding at
// once — the property P17(a) introduced and the one this test exists to
// price.
func loadEveryTypedList(ctx context.Context, t *testing.T, snap *sweepSnapshot) map[string]int {
	t.Helper()
	counts := map[string]int{}
	loaders := []struct {
		kind string
		load func() (int, error)
	}{
		{"Deployment", func() (int, error) {
			l, err := snap.deployments(ctx)
			return itemsLen(err, func() int { return len(l.Items) })
		}},
		{"ReplicaSet", func() (int, error) {
			l, err := snap.replicaSets(ctx)
			return itemsLen(err, func() int { return len(l.Items) })
		}},
		{"StatefulSet", func() (int, error) {
			l, err := snap.statefulSets(ctx)
			return itemsLen(err, func() int { return len(l.Items) })
		}},
		{"DaemonSet", func() (int, error) {
			l, err := snap.daemonSets(ctx)
			return itemsLen(err, func() int { return len(l.Items) })
		}},
		{"Pod", func() (int, error) {
			l, err := snap.pods(ctx)
			return itemsLen(err, func() int { return len(l.Items) })
		}},
		{"PersistentVolumeClaim", func() (int, error) {
			l, err := snap.persistentVolumeClaims(ctx)
			return itemsLen(err, func() int { return len(l.Items) })
		}},
		{"Service", func() (int, error) {
			l, err := snap.services(ctx)
			return itemsLen(err, func() int { return len(l.Items) })
		}},
		{"Node", func() (int, error) {
			l, err := snap.nodes(ctx)
			return itemsLen(err, func() int { return len(l.Items) })
		}},
		{"Job", func() (int, error) {
			l, err := snap.jobs(ctx)
			return itemsLen(err, func() int { return len(l.Items) })
		}},
		{"HorizontalPodAutoscaler", func() (int, error) {
			l, err := snap.horizontalPodAutoscalers(ctx)
			return itemsLen(err, func() int { return len(l.Items) })
		}},
		{"EndpointSlice", func() (int, error) {
			l, err := snap.endpointSlices(ctx)
			return itemsLen(err, func() int { return len(l.Items) })
		}},
		{"Ingress", func() (int, error) {
			l, err := snap.ingresses(ctx)
			return itemsLen(err, func() int { return len(l.Items) })
		}},
		{"ValidatingWebhookConfiguration", func() (int, error) {
			l, err := snap.validatingWebhookConfigurations(ctx)
			return itemsLen(err, func() int { return len(l.Items) })
		}},
		{"MutatingWebhookConfiguration", func() (int, error) {
			l, err := snap.mutatingWebhookConfigurations(ctx)
			return itemsLen(err, func() int { return len(l.Items) })
		}},
	}
	for _, l := range loaders {
		n, err := l.load()
		if err != nil {
			t.Logf("  typed list %s failed: %v", l.kind, err)
			continue
		}
		counts[l.kind] = n
	}
	return counts
}

// itemsLen exists only so the 14 one-line loaders above can share the "don't
// dereference the list when the List failed" check.
func itemsLen(err error, count func() int) (int, error) {
	if err != nil {
		return 0, err
	}
	return count(), nil
}

func saturatingSub(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

// TestLiveSweepUnderMemoryLimit is PROJECT.md P18's third acceptance
// criterion, exercised on the real path rather than reasoned about: run
// runOneSweep — the actual entry point, with the guard armed from this
// process' actual cgroup limit — against a real cluster, and assert that the
// process either stays inside that limit or declines a read with a named
// reason. Being OOMKilled fails this test by never reporting at all.
//
// Meaningful ONLY inside a container with a memory limit, which is what
// makes containerMemoryLimit return one:
//
//	go test -c -o /tmp/agent.test ./internal/agent/            # CGO_ENABLED=0
//	docker run --rm --memory=768m --network kind \
//	  -v /tmp:/work -v /path/to/kubeconfig:/kubeconfig:ro \
//	  -e ARGUS_AGENT_SWEEP_MEM_LIVE=1 -e KUBECONFIG=/kubeconfig \
//	  busybox /work/agent.test -test.run TestLiveSweepUnderMemoryLimit -test.v
//
// Run outside a container it still runs, still reports, and simply has no
// limit to assert against — which it says rather than passing quietly.
func TestLiveSweepUnderMemoryLimit(t *testing.T) {
	cfg := liveMemRestConfig(t, agentClientQPS, agentClientBurst)
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("building clientset: %v", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("building dynamic client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	applyGoSoftMemoryLimit()
	prevCache, prevGuard := discoveredWatchSetCache.Load(), sweepMemoryGuardInstance
	t.Cleanup(func() { discoveredWatchSetCache.Store(prevCache); sweepMemoryGuardInstance = prevGuard })
	enableDiscoveredWatchSet(clientset)
	enableSweepMemoryGuard()

	limit, limited := containerMemoryLimit()
	t.Logf("container memory limit: %s", sweepMemoryLimitDescription())
	if limited {
		t.Logf("guard budget / Go soft memory limit: %s of a %s limit (%s reserved for non-heap), decode headroom %.1fx for one list and %.1fx for the many-kind pass, page size %d",
			mib(sweepMemoryGuardInstance.budget), mib(limit), mib(limit-sweepMemoryGuardInstance.budget),
			singleListDecodeHeadroomFactor, multiKindDecodeHeadroomFactor, sweepPageSize)
	}

	// Drained, not merely buffered: a pass on a broken cluster can produce
	// thousands of findings, and a blocked producer would measure the
	// emit timeout rather than the sweep.
	findingCh := make(chan tunnel.Finding, 4096)
	var findings int
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range findingCh {
			findings++
		}
	}()

	// Two passes by default: the first has no projection for the
	// unstructured half (nothing has measured it yet), the second does, and
	// they are the two different decisions the guard can make.
	passes := 2
	if n, err := strconv.Atoi(os.Getenv("ARGUS_AGENT_SWEEP_MEM_PASSES")); err == nil && n > 0 {
		passes = n
	}
	lastSent, firstObserved := map[string]time.Time{}, map[string]time.Time{}
	rules, err := LoadRules("")
	if err != nil {
		t.Fatalf("loading the embedded rule set: %v", err)
	}

	peakOverall := uint64(0)
	for pass := 1; pass <= passes; pass++ {
		stop := make(chan struct{})
		var mu sync.Mutex
		peak := processMemoryInUse()
		go func() {
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-stop:
					return
				case <-ticker.C:
					now := processMemoryInUse()
					mu.Lock()
					if now > peak {
						peak = now
					}
					mu.Unlock()
				}
			}
		}()

		start := time.Now()
		timedOut, sweepErr := runOneSweep(ctx, clientset, dyn, findingCh, lastSent, firstObserved,
			defaultFindingResendCooldown, defaultSweepSustainedThreshold, 2*time.Minute, rules)
		elapsed := time.Since(start)
		close(stop)
		mu.Lock()
		passPeak := peak
		mu.Unlock()
		if passPeak > peakOverall {
			peakOverall = passPeak
		}

		// The gap between what the Go heap holds and what the PROCESS holds
		// is the part no heap-based budget can see: binary text, runtime
		// metadata, goroutine stacks, HTTP read buffers. It is roughly
		// constant rather than proportional to the container limit, which is
		// why goSoftMemoryLimitFraction alone is not a safe reserve at small
		// limits — see sweepMemoryBudget.
		nonHeap := saturatingSub(processMemoryInUse(), liveHeapBytes())
		t.Logf("pass %d: %s, peak in-use %s, live heap after %s, non-heap %s, %d findings so far, timed out: %v",
			pass, elapsed.Round(time.Millisecond), mib(passPeak), mib(liveHeapBytes()), mib(nonHeap), findings, timedOut)
		if sweepErr != nil {
			t.Logf("pass %d returned: %v", pass, sweepErr)
		}
		if errors.Is(sweepErr, errSweepMemoryBudget) {
			t.Logf("pass %d: the TYPED half was refused — the hand-written checkers did not all run", pass)
		}
		// The guard's own counter is the total across both halves: a refusal
		// in the dynamic half is reported on the detector's run state rather
		// than returned, so counting only what runOneSweep returns would
		// report a degraded pass as a clean one.
		if sweepMemoryGuardInstance != nil && (sweepMemoryGuardInstance.refusals > 0 || sweepMemoryGuardInstance.paginated > 0) {
			t.Logf("pass %d: guard has refused %d read(s) and paginated %d in total; last detector-status error: %q",
				pass, sweepMemoryGuardInstance.refusals, sweepMemoryGuardInstance.paginated, sweepRunState.snapshot().Error)
		}
	}
	close(findingCh)
	<-done

	if !limited {
		t.Logf("no container memory limit visible — measured peak %s, but there is nothing to assert against. Run this inside a container with --memory to make it an assertion.", mib(peakOverall))
		return
	}
	refused, paginated := uint64(0), uint64(0)
	if sweepMemoryGuardInstance != nil {
		refused, paginated = sweepMemoryGuardInstance.refusals, sweepMemoryGuardInstance.paginated
	}
	t.Logf("RESULT: peak %s of a %s limit (%.0f%%), %d read(s) refused, %d paginated, %d finding(s) emitted",
		mib(peakOverall), mib(limit), 100*float64(peakOverall)/float64(limit), refused, paginated, findings)
	if peakOverall >= limit {
		t.Fatalf("peak memory %s reached the container limit %s — this agent would have been OOMKilled instead of refusing", mib(peakOverall), mib(limit))
	}
	if refused > 0 && sweepRunState.snapshot().Error == "" {
		t.Fatal("a read was refused but the detector's run state reports no error — an operator would see a quieter sweep with no reason given")
	}
}

// --- the loader ---

func TestLiveSyntheticObjectLoad(t *testing.T) {
	cfg := liveMemRestConfig(t, 400, 800)
	want, err := strconv.Atoi(os.Getenv("ARGUS_AGENT_SWEEP_MEM_PODS"))
	if err != nil {
		t.Skipf("set ARGUS_AGENT_SWEEP_MEM_PODS=<n> to (re)load %q with n synthetic pods; 0 deletes the namespace", syntheticNamespace)
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("building clientset: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
	defer cancel()

	deleteSyntheticNamespace(ctx, t, clientset)
	if want == 0 {
		return
	}
	createSyntheticNamespace(ctx, t, clientset)
	loadSyntheticObjects(ctx, t, clientset, want)
}

func deleteSyntheticNamespace(ctx context.Context, t *testing.T, clientset kubernetes.Interface) {
	t.Helper()
	err := clientset.CoreV1().Namespaces().Delete(ctx, syntheticNamespace, metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return
	}
	if err != nil {
		t.Fatalf("deleting %s: %v", syntheticNamespace, err)
	}
	for {
		_, err := clientset.CoreV1().Namespaces().Get(ctx, syntheticNamespace, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			t.Logf("deleted namespace %s", syntheticNamespace)
			return
		}
		if ctx.Err() != nil {
			t.Fatalf("waiting for %s to go away: %v", syntheticNamespace, ctx.Err())
		}
		time.Sleep(2 * time.Second)
	}
}

func createSyntheticNamespace(ctx context.Context, t *testing.T, clientset kubernetes.Interface) {
	t.Helper()
	_, err := clientset.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: syntheticNamespace, Labels: map[string]string{"argus.io/synthetic": "true"}},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("creating %s: %v", syntheticNamespace, err)
	}
}

// loadSyntheticObjects creates pods plus a proportional complement of the
// other kinds a real cluster carries alongside them, so the table is not a
// measurement of pods in isolation. The ratios are deliberately conservative
// (a real cluster has more ConfigMaps and ReplicaSets per pod than this).
func loadSyntheticObjects(ctx context.Context, t *testing.T, clientset kubernetes.Interface, pods int) {
	t.Helper()
	start := time.Now()
	createConcurrently(ctx, t, "ConfigMap", pods/5, func(i int) error {
		_, err := clientset.CoreV1().ConfigMaps(syntheticNamespace).Create(ctx, syntheticConfigMap(i), metav1.CreateOptions{})
		return err
	})
	createConcurrently(ctx, t, "Service", pods/10, func(i int) error {
		_, err := clientset.CoreV1().Services(syntheticNamespace).Create(ctx, syntheticService(i), metav1.CreateOptions{})
		return err
	})
	createConcurrently(ctx, t, "Deployment", pods/25, func(i int) error {
		_, err := clientset.AppsV1().Deployments(syntheticNamespace).Create(ctx, syntheticDeployment(i), metav1.CreateOptions{})
		return err
	})
	createConcurrently(ctx, t, "Pod", pods, func(i int) error {
		p, err := clientset.CoreV1().Pods(syntheticNamespace).Create(ctx, syntheticPod(i), metav1.CreateOptions{})
		if err != nil {
			return err
		}
		p.Status = syntheticPodStatus(p)
		_, err = clientset.CoreV1().Pods(syntheticNamespace).UpdateStatus(ctx, p, metav1.UpdateOptions{})
		return err
	})
	t.Logf("loaded %d pods (+complement) into %s in %s", pods, syntheticNamespace, time.Since(start).Round(time.Second))
}

func createConcurrently(ctx context.Context, t *testing.T, kind string, n int, create func(i int) error) {
	t.Helper()
	if n <= 0 {
		return
	}
	const workers = 24
	idx := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	var failures int
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range idx {
				if err := create(i); err != nil && !apierrors.IsAlreadyExists(err) {
					mu.Lock()
					failures++
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
				}
			}
		}()
	}
	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			break
		}
		idx <- i
	}
	close(idx)
	wg.Wait()
	if firstErr != nil {
		t.Fatalf("creating %s: %d of %d failed, first: %v", kind, failures, n, firstErr)
	}
	t.Logf("created %d %s", n, kind)
}

// syntheticPod is deliberately a REALISTICALLY SHAPED pod, not a minimal
// one: two containers with env/probes/mounts/resources, a service-account
// projection, labels and annotations. A minimal pod is ~1.5KiB of JSON and
// would understate every number in the table by roughly 4x.
//
// schedulerName names a scheduler that does not exist, which is what keeps
// this safe to run at five thousand: kube-scheduler never looks at these
// pods, no kubelet is ever asked to run one, and (because they stay UNBOUND)
// the pod GC controller's orphaned-pod path never deletes them either.
func syntheticPod(i int) *corev1.Pod {
	name := fmt.Sprintf("synthetic-%05d", i)
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: syntheticNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       fmt.Sprintf("workload-%03d", i%200),
				"app.kubernetes.io/instance":   fmt.Sprintf("workload-%03d-prod", i%200),
				"app.kubernetes.io/version":    "1.24.3",
				"app.kubernetes.io/component":  "api",
				"app.kubernetes.io/part-of":    "argus-p18-synthetic",
				"app.kubernetes.io/managed-by": "argus-p18-loader",
				"pod-template-hash":            fmt.Sprintf("%08d", i*7919%99999999),
			},
			Annotations: map[string]string{
				"prometheus.io/scrape":              "true",
				"prometheus.io/port":                "9102",
				"prometheus.io/path":                "/metrics",
				"checksum/config":                   fmt.Sprintf("%064x", i*2654435761),
				"kubectl.kubernetes.io/restartedAt": "2026-09-01T09:14:22Z",
			},
		},
		Spec: syntheticPodSpec(i),
	}
}

// syntheticPodSpec is shared by the bare pods and by the Deployment's own
// pod template, so the two cannot drift apart (and so the Deployment's
// template stays valid: a container's volumeMounts have to name volumes the
// same spec declares).
func syntheticPodSpec(i int) corev1.PodSpec {
	return corev1.PodSpec{
		SchedulerName:                 "argus-p18-no-such-scheduler",
		ServiceAccountName:            "default",
		RestartPolicy:                 corev1.RestartPolicyAlways,
		DNSPolicy:                     corev1.DNSClusterFirst,
		TerminationGracePeriodSeconds: ptrInt64(30),
		Tolerations: []corev1.Toleration{
			{Key: "node.kubernetes.io/not-ready", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute},
			{Key: "node.kubernetes.io/unreachable", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute},
		},
		Volumes: []corev1.Volume{
			{Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: fmt.Sprintf("synthetic-config-%04d", i%200)},
			}}},
			{Name: "scratch", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
			{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		},
		Containers: []corev1.Container{
			syntheticContainer("app", i),
			syntheticContainer("sidecar", i),
		},
	}
}

func syntheticContainer(name string, i int) corev1.Container {
	httpPort := int32(8080)
	if name != "app" {
		httpPort = 8081
	}
	return corev1.Container{
		Name:            name,
		Image:           fmt.Sprintf("registry.example.invalid/argus/%s:1.24.3", name),
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command:         []string{"/usr/local/bin/" + name},
		Args:            []string{"--config=/etc/app/config.yaml", "--log-level=info", "--metrics-addr=:9102"},
		Ports: []corev1.ContainerPort{
			{Name: name + "-http", ContainerPort: httpPort, Protocol: corev1.ProtocolTCP},
			{Name: name + "-metrics", ContainerPort: httpPort + 1022, Protocol: corev1.ProtocolTCP},
		},
		Env: []corev1.EnvVar{
			{Name: "POD_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}},
			{Name: "POD_NAMESPACE", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"}}},
			{Name: "NODE_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"}}},
			{Name: "LOG_FORMAT", Value: "json"},
			{Name: "REGION", Value: "eu-west-2"},
			{Name: "CLUSTER", Value: "argus-p18-synthetic"},
			{Name: "UPSTREAM_URL", Value: fmt.Sprintf("http://workload-%03d.svc.cluster.local:8080", i%200)},
			{Name: "FEATURE_FLAGS", Value: "a=1,b=0,c=1,d=1,e=0,f=1"},
		},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("128Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("512Mi"),
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: "config", MountPath: "/etc/app", ReadOnly: true},
			{Name: "scratch", MountPath: "/var/lib/app"},
			{Name: "tmp", MountPath: "/tmp"},
		},
		LivenessProbe: &corev1.Probe{
			ProbeHandler:        corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(httpPort)}},
			InitialDelaySeconds: 10, PeriodSeconds: 10, TimeoutSeconds: 2, FailureThreshold: 3, SuccessThreshold: 1,
		},
		ReadinessProbe: &corev1.Probe{
			ProbeHandler:        corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/readyz", Port: intstr.FromInt32(httpPort)}},
			InitialDelaySeconds: 5, PeriodSeconds: 10, TimeoutSeconds: 2, FailureThreshold: 3, SuccessThreshold: 1,
		},
		TerminationMessagePath:   "/dev/termination-log",
		TerminationMessagePolicy: corev1.TerminationMessageReadFile,
	}
}

// syntheticPodStatus is the other half of the realism: a real cluster's pods
// carry conditions and containerStatuses, which a created-but-never-run pod
// does not, and those are a meaningful share of a pod's decoded size.
func syntheticPodStatus(p *corev1.Pod) corev1.PodStatus {
	now := metav1.Now()
	st := corev1.PodStatus{
		Phase:     corev1.PodRunning,
		PodIP:     "10.244.3.17",
		PodIPs:    []corev1.PodIP{{IP: "10.244.3.17"}},
		HostIP:    "10.0.1.42",
		StartTime: &now,
		QOSClass:  corev1.PodQOSBurstable,
	}
	for _, ct := range []corev1.PodConditionType{corev1.PodInitialized, corev1.PodReady, corev1.ContainersReady, corev1.PodScheduled} {
		st.Conditions = append(st.Conditions, corev1.PodCondition{
			Type: ct, Status: corev1.ConditionTrue, LastTransitionTime: now,
		})
	}
	for _, c := range p.Spec.Containers {
		st.ContainerStatuses = append(st.ContainerStatuses, corev1.ContainerStatus{
			Name:         c.Name,
			Image:        c.Image,
			ImageID:      "registry.example.invalid/argus/" + c.Name + "@sha256:1f0e3dad99908345f7439f8ffabdffc418e1f0e3dad99908345f7439f8ffabdf",
			ContainerID:  "containerd://9b2c1f0e3dad99908345f7439f8ffabdffc418e1f0e3dad99908345f7439f8ff",
			Ready:        true,
			Started:      ptrBool(true),
			RestartCount: 0,
			State:        corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: now}},
		})
	}
	return st
}

func syntheticConfigMap(i int) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("synthetic-config-%04d", i),
			Namespace: syntheticNamespace,
			Labels:    map[string]string{"app.kubernetes.io/part-of": "argus-p18-synthetic"},
		},
		Data: map[string]string{
			"config.yaml": strings.Repeat(fmt.Sprintf("key%04d: value-%04d\n", i, i), 40),
			"log.json":    strings.Repeat(`{"level":"info","msg":"synthetic"}`+"\n", 10),
		},
	}
}

func syntheticService(i int) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("synthetic-svc-%04d", i),
			Namespace: syntheticNamespace,
			Labels:    map[string]string{"app.kubernetes.io/part-of": "argus-p18-synthetic"},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app.kubernetes.io/name": fmt.Sprintf("workload-%03d", i%200)},
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 80, TargetPort: intstr.FromString("app-http"), Protocol: corev1.ProtocolTCP},
				{Name: "metrics", Port: 9102, TargetPort: intstr.FromString("app-metrics"), Protocol: corev1.ProtocolTCP},
			},
		},
	}
}

func syntheticDeployment(i int) *appsv1.Deployment {
	labels := map[string]string{"app.kubernetes.io/name": fmt.Sprintf("workload-%03d", i%200)}
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("synthetic-deploy-%04d", i),
			Namespace: syntheticNamespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			// Zero replicas: the ReplicaSet this creates is real (and so is
			// its share of the typed half), but the controller never creates
			// pods for it, so the pod count stays exactly what the loader
			// created.
			Replicas: ptrInt32(0),
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec:       syntheticPodSpec(i),
			},
		},
	}
}

func ptrInt32(v int32) *int32 { return &v }
func ptrInt64(v int64) *int64 { return &v }
func ptrBool(v bool) *bool    { return &v }

// TestLiveTypedDecodeContentType is PROJECT.md P28's second half, measured
// rather than assumed: what does asking the API server for protobuf instead
// of JSON actually change about what a typed sweep half costs?
//
// It loads the SAME 14 cluster-wide typed lists twice against the same
// cluster, once with client-go's JSON default and once with the agent's own
// negotiated accept types, and reports both the transient allocation (the
// thing P18 found dominates a pass — 305Mi of decode churn at 5,000 pods)
// and the retained heap (which should barely move, since the structs at the
// end are identical either way).
//
//	ARGUS_AGENT_SWEEP_MEM_LIVE=1 ARGUS_AGENT_SWEEP_MEM_CONTEXT=kind-argus-disposable \
//	  go test ./internal/agent/ -run TestLiveTypedDecodeContentType -v
//
// Load the cluster first (TestLiveSyntheticObjectLoad) if the number is to
// mean anything — on an idle cluster both halves are noise.
func TestLiveTypedDecodeContentType(t *testing.T) {
	base := liveMemRestConfig(t, agentClientQPS, agentClientBurst)

	// What the server actually SENT, per accept header. Without this the
	// test cannot tell "protobuf is cheaper" from "the server ignored us and
	// this is measurement noise" — and the JSON fallback is the whole
	// safety story, so it matters which endpoints took it.
	served := map[string]map[string]int{}
	measure := func(accept string) (memMeasurement, map[string]int) {
		cfg := rest.CopyConfig(base)
		cfg.AcceptContentTypes = accept
		served[accept] = map[string]int{}
		cfg.Wrap(func(rt http.RoundTripper) http.RoundTripper {
			return &responseContentTypeRecorder{next: rt, seen: served[accept]}
		})
		clientset, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			t.Fatalf("building clientset: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		// One warm-up pass, discarded: the first list through a fresh client
		// also pays for the connection, the TLS handshake and the decoder's
		// own one-time setup, none of which is what this is measuring.
		newSweepSnapshot(clientset).pods(ctx)

		var counts map[string]int
		m, held := measureRetained(func() any {
			snap := newSweepSnapshot(clientset)
			counts = loadEveryTypedList(ctx, t, snap)
			return snap
		})
		runtime.KeepAlive(held)
		return m, counts
	}

	jsonM, counts := measure("application/json")
	runtime.GC()
	protoM, _ := measure(agentAcceptContentTypes)

	objects := 0
	for _, n := range counts {
		objects += n
	}
	t.Logf("DECODE CONTENT TYPE, %d objects across the 14 typed lists:", objects)
	for accept, seen := range served {
		t.Logf("  asked for %q, the API server replied with: %v", accept, seen)
	}
	t.Logf("  JSON     : churn %s, retained %s, peak %s", mib(jsonM.churn), mib(jsonM.retained), mib(jsonM.peak))
	t.Logf("  protobuf : churn %s, retained %s, peak %s", mib(protoM.churn), mib(protoM.retained), mib(protoM.peak))
	if jsonM.churn > 0 {
		t.Logf("  transient allocation: %s -> %s (%.0f%% of the JSON figure)",
			mib(jsonM.churn), mib(protoM.churn), 100*float64(protoM.churn)/float64(jsonM.churn))
	}
	if objects > 0 {
		t.Logf("  per object: JSON %d bytes of churn, protobuf %d bytes", jsonM.churn/uint64(objects), protoM.churn/uint64(objects))
	}

	// The cluster-wide Pod list on its own, repeated, because it is the
	// single read the whole memory story is about and the 13 other lists
	// above are rounding error next to it. Repeated because one sample of a
	// GC-sensitive number is not a measurement.
	podsOnly := func(accept string) (churn, retained uint64, wire int, elapsed time.Duration) {
		cfg := rest.CopyConfig(base)
		cfg.AcceptContentTypes = accept
		clientset, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			t.Fatalf("building clientset: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		clientset.CoreV1().Pods(metav1.NamespaceAll).List(ctx, sweepListOptions) // warm-up, discarded

		raw, err := clientset.CoreV1().RESTClient().Get().AbsPath("/api/v1/pods").
			Param("resourceVersion", "0").SetHeader("Accept", accept).DoRaw(ctx)
		if err == nil {
			wire = len(raw)
		}
		raw = nil

		const rounds = 3
		start := time.Now()
		for i := 0; i < rounds; i++ {
			m, held := measureRetained(func() any {
				list, err := clientset.CoreV1().Pods(metav1.NamespaceAll).List(ctx, sweepListOptions)
				if err != nil {
					t.Fatalf("listing pods: %v", err)
				}
				return list
			})
			churn += m.churn / rounds
			retained += m.retained / rounds
			runtime.KeepAlive(held)
			runtime.GC()
		}
		return churn, retained, wire, time.Since(start) / rounds
	}

	jChurn, jRet, jWire, jTime := podsOnly("application/json")
	pChurn, pRet, pWire, pTime := podsOnly(agentAcceptContentTypes)
	pods := counts["Pod"]
	t.Logf("THE POD LIST ALONE (%d pods, mean of 3):", pods)
	t.Logf("  JSON     : wire %s, churn %s, retained %s, %s per list", mib(uint64(jWire)), mib(jChurn), mib(jRet), jTime.Round(time.Millisecond))
	t.Logf("  protobuf : wire %s, churn %s, retained %s, %s per list", mib(uint64(pWire)), mib(pChurn), mib(pRet), pTime.Round(time.Millisecond))
	if jWire > 0 && jChurn > 0 {
		t.Logf("  wire %.0f%% of JSON, transient allocation %.0f%% of JSON, wall clock %.0f%% of JSON",
			100*float64(pWire)/float64(jWire), 100*float64(pChurn)/float64(jChurn), 100*float64(pTime)/float64(jTime))
	}

	// Deliberately not an assertion. The direction is not in doubt, but the
	// magnitude depends entirely on what is on the cluster, and a threshold
	// pinned here would fail on an idle one for no reason worth acting on.
}

// responseContentTypeRecorder tallies what the API server actually sent
// back, by media type — see TestLiveTypedDecodeContentType for why the
// measurement is not interpretable without it.
type responseContentTypeRecorder struct {
	next http.RoundTripper
	mu   sync.Mutex
	seen map[string]int
}

func (r *responseContentTypeRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.next.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	r.mu.Lock()
	r.seen[resp.Header.Get("Content-Type")]++
	r.mu.Unlock()
	return resp, err
}
