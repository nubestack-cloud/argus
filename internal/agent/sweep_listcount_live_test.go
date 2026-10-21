package agent

// Live, cluster-touching measurement of what one sweep pass costs a real API
// server — PROJECT.md P17's acceptance asks for exactly this, and a fake
// clientset cannot supply it. Skipped unless ARGUS_AGENT_SWEEP_LIVE=1,
// following the same convention rules_live_test.go, internal/gitops/
// live_test.go and internal/render/sandbox/runner_live_test.go already use.
//
// Run against the disposable kind cluster ONLY (RUNBOOK.md "The disposable
// kind cluster"). This is read-only — it lists, it never writes — but the
// kubeconfig context it picks up is whatever KUBECONFIG/--context resolves
// to, so point it deliberately:
//
//	ARGUS_AGENT_SWEEP_LIVE=1 ARGUS_AGENT_SWEEP_LIVE_CONTEXT=kind-argus-b163 \
//	  go test ./internal/agent/ -run TestLiveSweepAPIServerRequestCount -v
//
// What it measures: every HTTP request the sweep actually sends to the API
// server, counted by a transport wrapper on the agent's own rest.Config, plus
// the API server's own apiserver_request_total for the same resources as a
// cross-check.
//
// The transport count is the authoritative one. kube-apiserver's
// apiserver_request_total carries no userAgent label on current builds, so
// server-side counters cannot be attributed to this client and are
// contaminated by kube-controller-manager and anything else listing the same
// resources at the same time — they are logged here for corroboration, not
// asserted on.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"argus/internal/tunnel"
)

func liveSweepClientset(t *testing.T) (kubernetes.Interface, *requestCountingTransport) {
	t.Helper()
	if os.Getenv("ARGUS_AGENT_SWEEP_LIVE") != "1" {
		t.Skip("set ARGUS_AGENT_SWEEP_LIVE=1 (and a disposable-cluster KUBECONFIG/context) to measure a sweep against a real API server")
	}
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		home, _ := os.UserHomeDir()
		kubeconfig = filepath.Join(home, ".kube", "config")
	}
	rules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: os.Getenv("ARGUS_AGENT_SWEEP_LIVE_CONTEXT")}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err != nil {
		t.Fatalf("building rest.Config: %v", err)
	}

	// The same tuning every production client gets (PROJECT.md P20), so the
	// number this test prints is the number a real agent would produce.
	cfg.QPS = agentClientQPS
	cfg.Burst = agentClientBurst
	cfg.AcceptContentTypes = agentAcceptContentTypes
	cfg.UserAgent = agentUserAgent()
	cfg.RateLimiter = newReportingRateLimiter(agentClientQPS, agentClientBurst)

	counter := &requestCountingTransport{}
	cfg.Wrap(func(rt http.RoundTripper) http.RoundTripper {
		counter.next = rt
		return counter
	})

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("building clientset: %v", err)
	}
	return clientset, counter
}

// requestCountingTransport counts and describes every request the client
// sends — the ground truth for "what did one sweep cost the API server",
// measured where it cannot be confused with anyone else's traffic.
type requestCountingTransport struct {
	next http.RoundTripper

	// shared, when set, is where this transport records instead of in
	// itself — so a pass that uses two clients (typed and dynamic) is
	// counted as one pass rather than as two halves nobody adds up. label
	// is what distinguishes them once pooled: the typed and unstructured
	// halves legitimately read the same kind, because they need it in two
	// different representations, and a count that could not tell them apart
	// would read that as a duplicate.
	shared *requestCountingTransport
	label  string

	mu    sync.Mutex
	count int
	paths []string
}

func (c *requestCountingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	sink := c
	if c.shared != nil {
		sink = c.shared
	}
	label := c.label
	if label == "" {
		label = "typed"
	}
	sink.mu.Lock()
	sink.count++
	sink.paths = append(sink.paths, label+" "+req.URL.Path+"?"+req.URL.RawQuery)
	sink.mu.Unlock()
	return c.next.RoundTrip(req)
}

func (c *requestCountingTransport) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count, c.paths = 0, nil
}

func (c *requestCountingTransport) snapshot() (int, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count, append([]string(nil), c.paths...)
}

// apiserverListTotal sums apiserver_request_total over LIST requests for the
// resources the sweep reads. Logged as corroboration only — see this file's
// own doc comment for why it is not asserted on.
func apiserverListTotal(t *testing.T, clientset kubernetes.Interface) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	raw, err := clientset.CoreV1().RESTClient().Get().AbsPath("/metrics").DoRaw(ctx)
	if err != nil {
		t.Logf("could not read /metrics for corroboration (%v) — the transport count below stands on its own", err)
		return 0
	}
	watched := map[string]bool{}
	for _, k := range sweepListedKinds {
		watched[k] = true
	}
	total := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "apiserver_request_total{") || !strings.Contains(line, `verb="LIST"`) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		resource := ""
		if idx := strings.Index(line, `resource="`); idx >= 0 {
			rest := line[idx+len(`resource="`):]
			resource = rest[:strings.Index(rest, `"`)]
		}
		if !watched[resource] {
			continue
		}
		if v, err := strconv.ParseFloat(fields[len(fields)-1], 64); err == nil {
			total += int(v)
		}
	}
	return total
}

func TestLiveSweepAPIServerRequestCount(t *testing.T) {
	clientset, counter := liveSweepClientset(t)

	serverBefore := apiserverListTotal(t, clientset)
	counter.reset()

	timedOut, err := runOneSweep(context.Background(), clientset, nil, make(chan tunnel.Finding, 512),
		map[string]time.Time{}, map[string]time.Time{},
		defaultFindingResendCooldown, defaultSweepSustainedThreshold, sweepCheckerTimeout(DefaultSweepInterval), nil)

	sent, paths := counter.snapshot()
	serverAfter := apiserverListTotal(t, clientset)

	sort.Strings(paths)
	t.Logf("one sweep pass against %s: %d requests sent to the API server\n  %s\n  typed-checker error: %v; timed out: %v\n  (cross-check, contaminated by other clients: apiserver_request_total LIST on these resources moved by %d)",
		os.Getenv("ARGUS_AGENT_SWEEP_LIVE_CONTEXT"), sent, strings.Join(paths, "\n  "), err, timedOut, serverAfter-serverBefore)

	// The fixed, per-pass cost is the cluster-wide lists. Anything
	// namespace-scoped is the per-candidate correlation path
	// (objectref.go's related-workload lookup and its owner-chain Get),
	// which scales with the number of problems found, not with the size of
	// the cluster — so it is reported but not pinned.
	clusterWide := 0
	for _, p := range paths {
		if !strings.Contains(p, "/namespaces/") {
			clusterWide++
		}
	}
	t.Logf("cluster-wide lists: %d; per-candidate correlation reads: %d", clusterWide, sent-clusterWide)
	if clusterWide != len(sweepListedKinds) {
		t.Errorf("sweep made %d cluster-wide requests, want %d (one list per kind in sweepListedKinds)", clusterWide, len(sweepListedKinds))
	}
	for _, p := range paths {
		if strings.Contains(p, "/namespaces/") || strings.Contains(p, "resourceVersion=0") {
			continue
		}
		t.Errorf("cluster-wide sweep read %q did not ask for the watch cache (PROJECT.md P17(b))", p)
	}
	if err != nil {
		t.Errorf("a sweep against a healthy cluster should not return a checker error, got %v", err)
	}
}

// TestLiveSweepFullPassRequestCount is PROJECT.md P28's acceptance measured
// against a real API server: the WHOLE pass, both clients, with the real
// embedded rule set loaded — not the typed half the test above isolates.
//
//	ARGUS_AGENT_SWEEP_LIVE=1 ARGUS_AGENT_SWEEP_LIVE_CONTEXT=kind-argus-disposable \
//	  go test ./internal/agent/ -run TestLiveSweepFullPassRequestCount -v
//
// Read-only, like its neighbour, and subject to the same warning: point it
// at a disposable cluster deliberately.
func TestLiveSweepFullPassRequestCount(t *testing.T) {
	clientset, counter := liveSweepClientset(t)

	rules, err := LoadRules("")
	if err != nil {
		t.Fatalf("loading the embedded rule set: %v", err)
	}
	dyn := liveSweepDynamicClient(t, counter)

	counter.reset()
	timedOut, sweepErr := runOneSweep(context.Background(), clientset, dyn, make(chan tunnel.Finding, 4096),
		map[string]time.Time{}, map[string]time.Time{},
		defaultFindingResendCooldown, defaultSweepSustainedThreshold, sweepCheckerTimeout(DefaultSweepInterval), rules)

	sent, paths := counter.snapshot()
	sort.Strings(paths)

	lists, perObject, typedLists, dynamicLists := 0, 0, 0, 0
	for _, p := range paths {
		if strings.Contains(p, "/namespaces/") {
			perObject++
			continue
		}
		lists++
		if strings.HasPrefix(p, "dynamic ") {
			dynamicLists++
		} else {
			typedLists++
		}
	}
	t.Logf("ONE FULL SWEEP PASS against %s with %d declarative rules: %d requests\n  %s",
		os.Getenv("ARGUS_AGENT_SWEEP_LIVE_CONTEXT"), len(rules), sent, strings.Join(paths, "\n  "))
	t.Logf("cluster-wide reads: %d (typed %d + dynamic %d); namespace-scoped (per-candidate correlation) reads: %d; typed-checker error: %v; timed out: %v",
		lists, typedLists, dynamicLists, perObject, sweepErr, timedOut)

	// The same pass' rules, measured the way they used to read: each
	// listing its own GVK (runRulesWithOwnLists is that loop, kept as the
	// memory-refusal fallback, so this is the real code and not a
	// reconstruction of it). The difference between this and zero is what
	// P28 bought on THIS cluster.
	counter.reset()
	runRulesWithOwnLists(context.Background(), clientset, dyn, rules, make(chan tunnel.Finding, 4096),
		map[string]time.Time{}, map[string]time.Time{}, map[string]struct{}{}, time.Now(),
		defaultFindingResendCooldown, defaultSweepSustainedThreshold, sweepCheckerTimeout(DefaultSweepInterval))
	ruleReads, rulePaths := counter.snapshot()
	ruleScoped := 0
	for _, p := range rulePaths {
		if strings.Contains(p, "/namespaces/") {
			ruleScoped++
		}
	}
	t.Logf("for comparison: the same %d rules listing for themselves (the pre-P28 path, still the memory-refusal fallback) cost %d requests, %d of them namespace-scoped per-object Pod lookups — all of which are now zero",
		len(rules), ruleReads, ruleScoped)

	// PROJECT.md P17(c): the same pass again, with the memory guard armed at
	// a budget too small for the whole-cluster reads. This is the "after"
	// half of P17(c)'s call count, and it only exists on a CONSTRAINED
	// agent — a correctly-sized one takes the unpaginated path measured
	// above and its count is unchanged, which is the design and not an
	// omission.
	prevGuard := sweepMemoryGuardInstance
	t.Cleanup(func() { sweepMemoryGuardInstance = prevGuard })
	sweepMemoryGuardInstance = &sweepMemoryGuard{limit: 200 << 20, budget: sweepMemoryBudget(200 << 20)}
	counter.reset()
	constrainedStart := time.Now()
	runOneSweep(context.Background(), clientset, dyn, make(chan tunnel.Finding, 4096),
		map[string]time.Time{}, map[string]time.Time{},
		defaultFindingResendCooldown, defaultSweepSustainedThreshold, sweepCheckerTimeout(DefaultSweepInterval), rules)
	constrainedElapsed := time.Since(constrainedStart)
	constrainedReads, constrainedPaths := counter.snapshot()
	constrainedLists := 0
	for _, p := range constrainedPaths {
		if !strings.Contains(p, "/namespaces/") {
			constrainedLists++
		}
	}
	t.Logf("the SAME pass with the guard armed at a 200Mi limit (budget %s): %d requests, %d cluster-wide, %s wall clock; %d read(s) refused, %d paginated",
		mib(sweepMemoryGuardInstance.budget), constrainedReads, constrainedLists, constrainedElapsed.Round(time.Millisecond),
		sweepMemoryGuardInstance.refusals, sweepMemoryGuardInstance.paginated)

	// Nothing is pinned to an exact number here: the count depends on how
	// many kinds the cluster's discovery actually serves. What IS pinned is
	// the property P28 bought — no kind is read cluster-wide more than once
	// per pass, with the two documented exceptions (the memory guard's
	// Limit:1 pod probe, and checkArgoSyncFailed, which runs before the
	// shared snapshot exists so that it still works when the snapshot is
	// refused for memory).
	seen := map[string]int{}
	for _, p := range paths {
		if strings.Contains(p, "/namespaces/") {
			continue
		}
		seen[strings.SplitN(p, "?", 2)[0]]++
	}
	for path, n := range seen {
		limit := 1
		// The two documented exceptions, both on the dynamic client: the
		// memory guard's Limit:1 pod sizing probe, and checkArgoSyncFailed.
		if strings.HasPrefix(path, "dynamic ") && (strings.HasSuffix(path, "/pods") || strings.Contains(path, "applications")) {
			limit = 2
		}
		if n > limit {
			t.Errorf("%s was read %d times in one pass, want at most %d (PROJECT.md P28)", path, n, limit)
		}
	}
}

// liveSweepDynamicClient builds the dynamic client for the test above,
// counted through the same transport so both halves land in one number.
func liveSweepDynamicClient(t *testing.T, counter *requestCountingTransport) dynamic.Interface {
	t.Helper()
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		home, _ := os.UserHomeDir()
		kubeconfig = filepath.Join(home, ".kube", "config")
	}
	rules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: os.Getenv("ARGUS_AGENT_SWEEP_LIVE_CONTEXT")}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err != nil {
		t.Fatalf("building rest.Config: %v", err)
	}
	cfg.QPS, cfg.Burst, cfg.UserAgent = agentClientQPS, agentClientBurst, agentUserAgent()
	cfg.AcceptContentTypes = agentAcceptContentTypes
	cfg.Wrap(func(rt http.RoundTripper) http.RoundTripper {
		return &requestCountingTransport{next: rt, shared: counter, label: "dynamic"}
	})
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("building dynamic client: %v", err)
	}
	return dyn
}

// TestLiveWatchSetRefreshCost measures what one WatchSetCache refresh costs a
// real API server — PROJECT.md B177's TTL is a cost/staleness trade, and the
// cost half of it had never been measured against anything.
//
// The refresh is what DeniedReads is read from (detector_status.go), so this
// interval is the floor on how quickly a revoked Kubernetes permission
// becomes visible to an operator. Shortening it is only defensible if the
// number below is small, so the number below is measured rather than assumed.
//
//	ARGUS_AGENT_SWEEP_LIVE=1 ARGUS_AGENT_SWEEP_LIVE_CONTEXT=kind-argus-disposable \
//	  go test ./internal/agent/ -run TestLiveWatchSetRefreshCost -v
func TestLiveWatchSetRefreshCost(t *testing.T) {
	clientset, counter := liveSweepClientset(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Warm the client's own discovery negotiation so what is measured is a
	// steady-state refresh, not a first-ever call.
	cache := NewWatchSetCacheFromClientset(clientset)
	if _, err := cache.Get(ctx); err != nil {
		t.Fatalf("first watch-set fetch: %v", err)
	}

	const rounds = 3
	counter.reset()
	start := time.Now()
	for i := 0; i < rounds; i++ {
		// A fresh cache each round, so every round is a real refresh rather
		// than a cache hit.
		fresh := NewWatchSetCacheFromClientset(clientset)
		set, err := fresh.Get(ctx)
		if err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		if i == 0 {
			t.Logf("watch set resolves %d kind(s)", len(set))
		}
	}
	elapsed := time.Since(start)
	sent, paths := counter.snapshot()
	sort.Strings(paths)

	t.Logf("ONE WatchSetCache refresh against %s: %.1f requests, %s wall clock (measured over %d rounds)",
		os.Getenv("ARGUS_AGENT_SWEEP_LIVE_CONTEXT"), float64(sent)/rounds, (elapsed / rounds).Round(time.Millisecond), rounds)
	unique := map[string]int{}
	for _, p := range paths {
		unique[strings.SplitN(p, "?", 2)[0]]++
	}
	for path, n := range unique {
		t.Logf("    %-40s %d/round", path, n/rounds)
	}
	t.Logf("at the current DefaultWatchSetRefreshInterval (%s) that is %.1f requests/hour/agent; a 200-cluster fleet spreads it across 200 different API servers",
		DefaultWatchSetRefreshInterval, float64(sent)/rounds*float64(time.Hour)/float64(DefaultWatchSetRefreshInterval))
}

// --- PROJECT.md P17(c): what pagination actually costs and buys ---

// apiserverListDuration returns the API server's own cumulative LIST
// duration and count for one resource, from apiserver_request_duration_seconds.
//
// Same caveat as apiserverListTotal: these counters carry no userAgent label,
// so they include kube-controller-manager and anything else listing the same
// resource. The client-side wall clock reported alongside is the uncontaminated
// number; this is the API server's own view, which is the half P17(c)'s
// acceptance asks for and which no client-side timer can supply.
func apiserverListDuration(t *testing.T, clientset kubernetes.Interface, resource string) (seconds float64, count float64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, err := clientset.CoreV1().RESTClient().Get().AbsPath("/metrics").DoRaw(ctx)
	if err != nil {
		t.Logf("could not read /metrics (%v) — server-side duration unavailable this run", err)
		return 0, 0
	}
	want := `resource="` + resource + `"`
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.Contains(line, `verb="LIST"`) || !strings.Contains(line, want) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, err := strconv.ParseFloat(fields[len(fields)-1], 64)
		if err != nil {
			continue
		}
		switch {
		case strings.HasPrefix(line, "apiserver_request_duration_seconds_sum{"):
			seconds += v
		case strings.HasPrefix(line, "apiserver_request_duration_seconds_count{"):
			count += v
		}
	}
	return seconds, count
}

// TestLiveSweepPaginationCost is PROJECT.md P17(c)'s acceptance: a measured
// before/after call count AND API-server request duration, against a real
// cluster, for the two shapes a sweep read can take.
//
// "Before" is the P17(b) watch-cache read this replaces nothing of — it is
// still what a correctly-sized agent does. "After" is what the SAME read
// costs once the memory guard has downgraded it, which is the case that used
// to be a refusal (or, before B187 was fixed, an OOMKill). The point of
// measuring both is that the choice between them is a real trade and the
// design rests on knowing its size.
//
//	ARGUS_AGENT_SWEEP_LIVE=1 ARGUS_AGENT_SWEEP_LIVE_CONTEXT=kind-argus-disposable \
//	  go test ./internal/agent/ -run TestLiveSweepPaginationCost -v
func TestLiveSweepPaginationCost(t *testing.T) {
	clientset, counter := liveSweepClientset(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	run := func(label string, plan sweepReadPlan) int {
		t.Helper()
		// Two warm-ups, discarded: the first read of a kind on a cold watch
		// cache is not the steady state a sweep runs in every five minutes.
		for i := 0; i < 2; i++ {
			if _, err := listPaged(ctx, plan, func(ctx context.Context, opts metav1.ListOptions) (*corev1.PodList, error) {
				return clientset.CoreV1().Pods(metav1.NamespaceAll).List(ctx, opts)
			}); err != nil {
				t.Fatalf("%s warm-up: %v", label, err)
			}
		}
		serverBefore, serverCountBefore := apiserverListDuration(t, clientset, "pods")
		counter.reset()
		const rounds = 3
		start := time.Now()
		objects := 0
		for i := 0; i < rounds; i++ {
			list, err := listPaged(ctx, plan, func(ctx context.Context, opts metav1.ListOptions) (*corev1.PodList, error) {
				return clientset.CoreV1().Pods(metav1.NamespaceAll).List(ctx, opts)
			})
			if err != nil {
				t.Fatalf("%s: %v", label, err)
			}
			objects = len(list.Items)
		}
		elapsed := time.Since(start) / rounds
		sent, _ := counter.snapshot()
		serverAfter, serverCountAfter := apiserverListDuration(t, clientset, "pods")

		perRound := float64(sent) / rounds
		serverMs := 0.0
		if d := serverCountAfter - serverCountBefore; d > 0 {
			serverMs = (serverAfter - serverBefore) / d * 1000
		}
		t.Logf("%-28s %d objects | %.1f request(s)/read | %s client wall clock/read | %.0fms mean API-server LIST duration",
			label, objects, perRound, elapsed.Round(time.Millisecond), serverMs)
		return objects
	}

	whole := run("watch cache, unpaginated:", sweepReadPlan{})
	paged := run(fmt.Sprintf("paginated, %d/page:", sweepPageSize),
		sweepReadPlan{paginate: true, perObject: typedLiveBytesPerObject, what: "the cluster-wide Pod list"})

	// Both shapes must return the same cluster. A paginated read that
	// silently returned fewer objects would make every checker that reads
	// absence as a fact report the missing ones as gone.
	if whole != paged {
		t.Errorf("the watch-cache read saw %d pods and the paginated read saw %d — the two shapes must be interchangeable in what they return, only in what they cost", whole, paged)
	}
}
