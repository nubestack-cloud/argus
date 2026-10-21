package agent

// restconfig.go is this agent's one Kubernetes client configuration
// (PROJECT.md P20).
//
// # What was wrong
//
// Six files — facts.go, sweep_detector.go, tools.go, metrics_client.go,
// dryrun_client.go, policywindow_client.go — built clients across eleven
// NewForConfig call sites, each starting from its own fresh
// rest.InClusterConfig(). Nothing set QPS or Burst anywhere, so every one of
// those subsystems silently took client-go's defaults of 5 QPS / 10 burst
// (rest.DefaultQPS/DefaultBurst) AND its own independent token bucket and
// connection pool. Two things follow from that, and both are bad:
//
//  1. 5 QPS is far below what this agent actually does. One sweep pass is
//     dozens of reads back to back (14 typed lists after P17, one dynamic
//     list per watched kind for the shared unstructured snapshot the generic
//     predicates and every declarative rule now read — P28), and the
//     periodic capability discovery adds one request per API group-version
//     on top. At 5 QPS that is tens of seconds of pure client-side waiting
//     per pass, every pass, forever.
//  2. Client-side throttling is invisible. client-go does not return an
//     error when it throttles; it blocks. So a throttled investigation does
//     not look throttled, it looks like a slow cluster or a slow model, and
//     nothing in ARGUS's own telemetry said otherwise.
//
// # What this does
//
// loadKubeConfig resolves the cluster config once, tunes it once, and hands
// every caller a copy. The copy matters: dryrun_client.go and
// policywindow_client.go deliberately swap the credential for a different
// service account's token, and must not be able to mutate the shared base
// while doing it. rest.CopyConfig carries QPS, Burst, UserAgent and the
// RateLimiter pointer through, so those separate identities share this
// agent's one rate limiter — which is the point. They are separate
// credentials against the same API server, not a licence to double the load.
//
// The eleven call sites are unchanged and still call NewForConfig. Nothing
// had to be rewritten for them to stop being independently throttled,
// because loadKubeConfig was already the single chokepoint they all went
// through.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"os"
	"path/filepath"
	"sync"
	"time"

	"argus/internal/tunnel"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/flowcontrol"
)

const (
	// agentClientQPS/agentClientBurst replace client-go's 5/10 defaults for
	// every client this agent builds.
	//
	// # Burst: sized against the post-P17 sweep
	//
	// The largest uninterrupted run of requests this agent makes is one
	// sweep pass. After P17 that is 14 typed cluster-wide lists, plus one
	// dynamic list per watched kind for the shared unstructured snapshot
	// (~47 today, Secret excluded), plus the CRD-backed checkers — about 62
	// reads issued as fast as the API server answers them, measured on
	// sweep_listcount_test.go's fixture. It was ~100 before P28, when each
	// of the 37 declarative rules listed its own kind again; the burst was
	// sized for that and is deliberately left where it is, since headroom
	// above a measured peak is the point. A burst of 100 lets a healthy
	// sweep run without ever touching the limiter, which is what makes a
	// throttle log (see throttleReporter) meaningful: if it fires, something
	// is genuinely looping, not merely busy.
	//
	// # QPS: a ceiling, not a target
	//
	// Sustained demand is tiny — those ~100 reads are spread over a
	// 5-minute interval (0.3 QPS), the facts refresh is one small pass every
	// 2 minutes, and an investigation's tool loop is single-threaded by
	// construction. 50 QPS is therefore headroom for a burst to drain
	// promptly, not a load this agent is expected to sustain. It exists to
	// bound a runaway loop in ARGUS's own code, which is the only thing a
	// client-side limiter is actually good for: protecting the API server is
	// the job of its own API Priority and Fairness, which does it with
	// visibility and per-tenant fairness a client bucket cannot.
	//
	// Both are deliberately NOT operator-tunable. If an agent needs more
	// than this, the answer is to find out why it is making that many
	// requests — P17 is what that investigation produced last time — not to
	// raise the ceiling until the symptom stops.
	agentClientQPS   = 50.0
	agentClientBurst = 100

	// agentAcceptContentTypes asks every response this agent reads to come
	// back as protobuf, falling back to JSON (PROJECT.md P28).
	//
	// # What it is worth, measured — which is NOT what P28 expected
	//
	// P28 proposed this as a memory change: P18 had measured 305Mi of
	// transient typed-decode churn at 5,000 pods, and the guess was that
	// most of it was the JSON decoder building and discarding an
	// intermediate representation on the way in.
	//
	// It is not. Measured on a 2,015-pod cluster
	// (TestLiveTypedDecodeContentType, 2026-09-25), for the cluster-wide Pod
	// list alone:
	//
	//	              wire     transient alloc   retained   wall clock
	//	JSON          23Mi     109Mi             40Mi       1.327s
	//	protobuf      17Mi     105Mi             39Mi       0.359s
	//
	// Transient allocation moved by 4%, not by a large share. The churn is
	// dominated by allocating the typed structs THEMSELVES — every string,
	// slice and map in 2,000 PodSpecs — which both codecs must do
	// identically; the parse intermediate a JSON decoder adds on top is the
	// small part. So this does NOT buy the memory guard any room, and
	// sweep_memory.go's budget arithmetic is unchanged by it.
	//
	// What it does buy is real and worth keeping: 27% less on the wire, and
	// a decode 3.7x faster in wall clock. On a large cluster that is a
	// meaningful cut in how long a pass holds its peak and in what the API
	// server spends serialising for this agent — it is simply a latency and
	// bandwidth win rather than the memory win it was proposed as.
	//
	// # Why this is an ACCEPT header and not ContentType
	//
	// Content negotiation, deliberately: this lists protobuf first and JSON
	// second, so a server that cannot serve protobuf serves JSON and
	// client-go decodes whatever came back. Aggregated API servers and
	// anything CRD-backed are exactly that case — the apiextensions path
	// does not serve protobuf at all — so an agent that DEMANDED protobuf
	// would simply start failing reads on every cluster running a CRD it
	// cares about. Degrading per endpoint, silently and correctly, is the
	// only version of this worth shipping.
	//
	// ContentType (what this agent SENDS) is deliberately left at JSON. The
	// win here is entirely on the read path, and a protobuf request body
	// would fail against exactly the CRD-backed endpoints the executor
	// writes to.
	//
	// Note this affects the typed clientset only in practice:
	// dynamic.ConfigFor overrides both fields back to JSON for every dynamic
	// client, because unstructured objects cannot be decoded from protobuf
	// at all. So the unstructured half of a sweep — which is the LARGER half
	// (sweep_memory.go: roughly 3x the typed cost per object) — is
	// untouched by this and cannot be helped by it.
	agentAcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"

	// throttleWaitThreshold is how long a single request must sit in the
	// rate limiter before it counts as throttled. A token bucket hands back
	// sub-millisecond waits constantly under normal use; those are not
	// throttling in any sense an operator cares about. 10ms is well clear of
	// that noise and far below anything a human would notice, so a request
	// that crosses it was genuinely held back.
	throttleWaitThreshold = 10 * time.Millisecond

	// throttleLogInterval bounds how often the throttle report is logged.
	// The condition it reports is by definition high-frequency — that is
	// what throttling is — so logging per occurrence would bury the agent's
	// own log in exactly the situation an operator needs to read it. One
	// aggregated line a minute, carrying the count and the total time lost,
	// says more than a thousand individual ones.
	throttleLogInterval = time.Minute
)

// agentUserAgent is what this agent identifies itself as in every request's
// User-Agent header.
//
// Worth setting rather than leaving at client-go's default, which derives
// from the binary name and tells an API server operator nothing useful. When
// someone is looking at an apiserver_request_total breakdown or an audit log
// trying to work out which workload is generating read load, this is the
// string that answers it — and on a cluster where ARGUS is on trial, being
// the component that is easy to attribute is worth more than the two lines
// it costs.
func agentUserAgent() string {
	return fmt.Sprintf("argus-agent/%s (cluster-agent; read-only)", tunnel.AgentBuildVersion)
}

// resolveKubeConfig tries, in order: in-cluster config (the normal case when
// this binary actually runs as a Pod inside the target cluster), then
// $KUBECONFIG, then ~/.kube/config — the same order a well-behaved kubectl
// plugin would use. Returns an error whenever none of these produce a usable
// config; that's an expected, common case (someone testing the
// enrollment/tunnel flow with no live target cluster at all), not a fault.
func resolveKubeConfig() (*rest.Config, error) {
	// Test seam, nil in every production path: these tests need to drive
	// loadKubeConfig's sharing and memoization behaviour on a machine with
	// no cluster and no ~/.kube/config, and there is no other way in.
	if resolveKubeConfigForTest != nil {
		return resolveKubeConfigForTest()
	}
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}

	kubeconfigPath := os.Getenv("KUBECONFIG")
	if kubeconfigPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		kubeconfigPath = filepath.Join(home, ".kube", "config")
	}
	return clientcmd.BuildConfigFromFlags("", kubeconfigPath)
}

// resolveKubeConfigForTest is the seam resolveKubeConfig consults first.
// Nil in every production path — only internal/agent's own tests ever set
// it, and only for the duration of one test — because loadKubeConfig's
// sharing and memoization behaviour is otherwise unreachable on a machine
// with no cluster and no ~/.kube/config.
var resolveKubeConfigForTest func() (*rest.Config, error)

// errNoTestKubeConfig is what the test seam above returns for "no config
// resolves", named rather than constructed inline so the failure path can be
// asserted on.
var errNoTestKubeConfig = errors.New("no cluster config (test stub)")

var (
	kubeConfigMu   sync.Mutex
	kubeConfigBase *rest.Config
)

// loadKubeConfig returns this agent's shared, tuned cluster configuration —
// a copy per caller, all of them backed by one rate limiter.
//
// Only a SUCCESSFUL resolution is memoized. A failure is returned and
// nothing is cached, so an agent that started before its kubeconfig was
// readable still picks it up on the next attempt rather than being wedged
// for the life of the process by one early miss.
func loadKubeConfig() (*rest.Config, error) {
	kubeConfigMu.Lock()
	defer kubeConfigMu.Unlock()

	if kubeConfigBase == nil {
		cfg, err := resolveKubeConfig()
		if err != nil {
			return nil, err
		}
		cfg.QPS = agentClientQPS
		cfg.Burst = agentClientBurst
		cfg.AcceptContentTypes = agentAcceptContentTypes
		cfg.UserAgent = agentUserAgent()
		// Set explicitly rather than left for NewForConfig to derive from
		// QPS/Burst: a limiter derived there is built PER CLIENT, which is
		// the exact behaviour this change exists to end. One instance here,
		// carried by rest.CopyConfig into every client, means all of them
		// draw from one bucket.
		cfg.RateLimiter = newReportingRateLimiter(agentClientQPS, agentClientBurst)
		kubeConfigBase = cfg
	}
	return rest.CopyConfig(kubeConfigBase), nil
}

// reportingRateLimiter is flowcontrol's token bucket with one addition: it
// notices when it actually made a caller wait, and says so.
//
// This is the whole of P20's "log when the client is being throttled rather
// than merely slow". client-go's own throttling notice is a klog V(3) line
// that this binary does not enable, so before this the condition was
// literally unobservable from inside ARGUS: a sweep that took four minutes
// because of our own token bucket and a sweep that took four minutes because
// the API server was struggling produced identical, silent output.
type reportingRateLimiter struct {
	flowcontrol.RateLimiter
	reporter *throttleReporter
}

func newReportingRateLimiter(qps float32, burst int) flowcontrol.RateLimiter {
	return &reportingRateLimiter{
		RateLimiter: flowcontrol.NewTokenBucketRateLimiter(qps, burst),
		reporter:    &throttleReporter{qps: qps, burst: burst},
	}
}

func (r *reportingRateLimiter) Wait(ctx context.Context) error {
	start := time.Now()
	err := r.RateLimiter.Wait(ctx)
	r.reporter.observe(time.Since(start))
	return err
}

func (r *reportingRateLimiter) Accept() {
	start := time.Now()
	r.RateLimiter.Accept()
	r.reporter.observe(time.Since(start))
}

// throttleReporter accumulates throttled waits and logs an aggregate at most
// once per throttleLogInterval.
type throttleReporter struct {
	qps   float32
	burst int

	mu         sync.Mutex
	waits      int
	total      time.Duration
	windowFrom time.Time
}

// observe records one request's time in the limiter, and logs the window's
// accumulated total when it is time to.
//
// Called on the request path of every Kubernetes call this agent makes, so
// the fast path — a wait below the threshold, which is nearly all of them —
// does nothing but one comparison.
//
// Reporting is driven by arriving waits, not by a timer: an accumulated
// window is logged by the next throttled request after the interval elapses,
// so a burst that throttles briefly and then stops entirely may sit
// unreported until the next one. That is the right trade. The condition
// worth logging is sustained throttling, which by definition keeps supplying
// waits; a single 15ms delay that never recurs is not news, and a background
// goroutine to announce it would cost more than the information is worth.
func (t *throttleReporter) observe(waited time.Duration) {
	if waited < throttleWaitThreshold {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	if t.windowFrom.IsZero() {
		t.windowFrom = now
	}
	t.waits++
	t.total += waited

	if now.Sub(t.windowFrom) < throttleLogInterval {
		return
	}
	logger.Warn("kubernetes client-side throttling — this agent's own limiter, not the API server rejecting anything; if steady, something in the agent is making more requests than it should, and raising the limit only hides it",
		slog.Int("delayed_requests", t.waits), slog.Duration("total_wait", t.total.Round(time.Millisecond)),
		slog.Duration("window", now.Sub(t.windowFrom).Round(time.Second)), slog.Float64("qps", float64(t.qps)), slog.Int("burst", t.burst))
	t.waits, t.total, t.windowFrom = 0, 0, now
}
