package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/flowcontrol"
)

// TestLoadKubeConfig_SharesOneTunedConfig is PROJECT.md P20's acceptance at
// the level that matters: every caller gets the tuned limits, and every
// caller gets the SAME rate limiter. Sharing the numbers but not the bucket
// would leave each subsystem independently throttled, which is the bug.
func TestLoadKubeConfig_SharesOneTunedConfig(t *testing.T) {
	withStubKubeConfig(t, &rest.Config{Host: "https://example.invalid"})

	first, err := loadKubeConfig()
	if err != nil {
		t.Fatalf("loadKubeConfig: %v", err)
	}
	second, err := loadKubeConfig()
	if err != nil {
		t.Fatalf("loadKubeConfig (second): %v", err)
	}

	if first == second {
		t.Fatal("each caller must get its own *rest.Config copy — dryrun_client.go and policywindow_client.go mutate theirs to swap the credential")
	}
	for _, cfg := range []*rest.Config{first, second} {
		if cfg.QPS != agentClientQPS {
			t.Errorf("QPS = %v, want %v (client-go's silent 5 QPS default is what P20 exists to remove)", cfg.QPS, agentClientQPS)
		}
		if cfg.Burst != agentClientBurst {
			t.Errorf("Burst = %d, want %d", cfg.Burst, agentClientBurst)
		}
		if !strings.HasPrefix(cfg.UserAgent, "argus-agent/") {
			t.Errorf("UserAgent = %q, want it to identify this agent to an API server operator", cfg.UserAgent)
		}
		if cfg.RateLimiter == nil {
			t.Fatal("RateLimiter must be set explicitly, or NewForConfig builds a separate one per client")
		}
	}
	if first.RateLimiter != second.RateLimiter {
		t.Error("both configs must carry the SAME limiter instance, or every subsystem is throttled independently again")
	}
}

// TestLoadKubeConfig_DoesNotMemoizeAFailure guards the one way a memoized
// config could make things worse: an agent that starts before its kubeconfig
// is readable must not be wedged for the life of the process.
func TestLoadKubeConfig_DoesNotMemoizeAFailure(t *testing.T) {
	withStubKubeConfig(t, nil)

	if _, err := loadKubeConfig(); err == nil {
		t.Fatal("expected an error when no config resolves")
	}

	resolveKubeConfigForTest = func() (*rest.Config, error) { return &rest.Config{Host: "https://example.invalid"}, nil }
	if _, err := loadKubeConfig(); err != nil {
		t.Fatalf("a later attempt must succeed once the config becomes resolvable, got %v", err)
	}
}

// TestReportingRateLimiter_LogsOnlyRealThrottling proves the reporter counts
// waits that actually held a request back and ignores the sub-millisecond
// ones a token bucket produces constantly — otherwise the log it exists to
// produce would fire on a perfectly healthy agent and mean nothing.
func TestReportingRateLimiter_LogsOnlyRealThrottling(t *testing.T) {
	r := &throttleReporter{qps: agentClientQPS, burst: agentClientBurst}

	r.observe(throttleWaitThreshold / 2)
	if r.waits != 0 {
		t.Errorf("a wait below the threshold must not count as throttling, waits = %d", r.waits)
	}

	r.observe(throttleWaitThreshold * 3)
	if r.waits != 1 {
		t.Errorf("waits = %d, want 1", r.waits)
	}
	if r.total != throttleWaitThreshold*3 {
		t.Errorf("total = %s, want %s", r.total, throttleWaitThreshold*3)
	}

	// Once the window is old enough, the next throttled wait logs the
	// accumulated report and starts a fresh window.
	r.windowFrom = time.Now().Add(-2 * throttleLogInterval)
	r.observe(throttleWaitThreshold * 2)
	if r.waits != 0 || r.total != 0 {
		t.Errorf("after logging, the window must reset; waits = %d, total = %s", r.waits, r.total)
	}
}

// TestReportingRateLimiter_MeasuresTheWait proves the wrapper actually times
// the underlying limiter rather than reporting a constant: a bucket with one
// token and a slow refill makes the second request wait, and that wait is
// what gets observed.
func TestReportingRateLimiter_MeasuresTheWait(t *testing.T) {
	limiter := &reportingRateLimiter{
		RateLimiter: flowcontrol.NewTokenBucketRateLimiter(20, 1),
		reporter:    &throttleReporter{qps: 20, burst: 1},
	}

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := limiter.Wait(ctx); err != nil {
			t.Fatalf("Wait: %v", err)
		}
	}

	limiter.reporter.mu.Lock()
	defer limiter.reporter.mu.Unlock()
	if limiter.reporter.waits == 0 {
		t.Fatal("draining a 1-token bucket at 20 QPS must register as throttling; the wrapper is not measuring the underlying limiter")
	}
}

func withStubKubeConfig(t *testing.T, cfg *rest.Config) {
	t.Helper()
	kubeConfigMu.Lock()
	prev := kubeConfigBase
	kubeConfigBase = nil
	kubeConfigMu.Unlock()

	if cfg != nil {
		resolveKubeConfigForTest = func() (*rest.Config, error) { return rest.CopyConfig(cfg), nil }
	} else {
		resolveKubeConfigForTest = func() (*rest.Config, error) { return nil, errNoTestKubeConfig }
	}

	t.Cleanup(func() {
		resolveKubeConfigForTest = nil
		kubeConfigMu.Lock()
		kubeConfigBase = prev
		kubeConfigMu.Unlock()
	})
}

// TestLoadKubeConfig_NegotiatesProtobufWithAJSONFallback is PROJECT.md P28's
// cheap adjacent win. Two properties matter and only one is obvious:
//
//  1. protobuf is asked for FIRST, so a typed list off a built-in kind
//     decodes from the wire format instead of from JSON;
//  2. JSON is still in the list, so an endpoint that cannot serve protobuf —
//     every CRD-backed one — serves JSON and this agent reads it. An agent
//     that demanded protobuf would fail reads on every cluster running a CRD
//     it detects against, which is most of them.
func TestLoadKubeConfig_NegotiatesProtobufWithAJSONFallback(t *testing.T) {
	withStubKubeConfig(t, &rest.Config{Host: "https://example.invalid"})

	cfg, err := loadKubeConfig()
	if err != nil {
		t.Fatalf("loadKubeConfig: %v", err)
	}
	accepted := strings.Split(cfg.AcceptContentTypes, ",")
	if len(accepted) < 2 || accepted[0] != "application/vnd.kubernetes.protobuf" {
		t.Errorf("AcceptContentTypes = %q, want protobuf first", cfg.AcceptContentTypes)
	}
	if !strings.Contains(cfg.AcceptContentTypes, "application/json") {
		t.Errorf("AcceptContentTypes = %q must keep a JSON fallback — CRD-backed endpoints do not serve protobuf", cfg.AcceptContentTypes)
	}
	if cfg.ContentType != "" && cfg.ContentType != "application/json" {
		t.Errorf("ContentType = %q: what this agent SENDS stays JSON — the win is on the read path, and a protobuf request body fails against the CRD endpoints the executor writes to", cfg.ContentType)
	}
}

// TestDynamicClientIsUnaffectedByProtobuf pins the reason the change above
// is safe to make on the one shared base config: client-go's own
// dynamic.ConfigFor overrides both content-type fields back to JSON, because
// unstructured objects cannot be decoded from protobuf at all. If that ever
// stopped being true, every unstructured read in a sweep would start failing
// and this is the test that would say so.
func TestDynamicClientIsUnaffectedByProtobuf(t *testing.T) {
	withStubKubeConfig(t, &rest.Config{Host: "https://example.invalid"})

	cfg, err := loadKubeConfig()
	if err != nil {
		t.Fatalf("loadKubeConfig: %v", err)
	}
	dynCfg := dynamic.ConfigFor(cfg)
	if strings.Contains(dynCfg.AcceptContentTypes, "protobuf") || strings.Contains(dynCfg.ContentType, "protobuf") {
		t.Fatalf("the dynamic client would ask for protobuf (accept %q, content-type %q), which cannot decode into unstructured objects",
			dynCfg.AcceptContentTypes, dynCfg.ContentType)
	}
}
