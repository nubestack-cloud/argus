package agent

// client_facts_refresh_test.go is PROJECT.md B177's falsification: before the
// periodic refresh existed, an established tunnel session sent ClusterFacts
// exactly once, in its initial InventoryDelta, and the 30s Heartbeat carried
// AgentVersion and CertExpiresAt and nothing else. Every consumer of facts —
// detector run health, and DeniedReads, the signal whose entire job is to
// tell an operator that RBAC is blocking a detector — was therefore frozen at
// the instant of the last reconnect.
//
// Both tests below fail against that code and pass with the refresh: the
// first proves a detector's own run health reaches the wire again without a
// reconnect, the second proves a read revoked mid-session does. Neither needs
// a hub, and neither reconnects: one net.Pipe, one runTunnelSession, and the
// agent state changed underneath it exactly the way a real cluster changes it.

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"argus/internal/tunnel"
)

// shortenFactsRefresh narrows the production interval for the duration of one
// test so a refresh can be observed in milliseconds rather than minutes, and
// restores it afterwards. factsRefreshInterval is a production constant in
// every other respect — see its doc comment for why it is two minutes.
func shortenFactsRefresh(t *testing.T, d time.Duration) {
	t.Helper()
	previous := factsRefreshInterval
	factsRefreshInterval = d
	t.Cleanup(func() { factsRefreshInterval = previous })
}

// nextInventoryDelta reads messages off the wire until an InventoryDelta
// arrives, ignoring anything else a live session may legitimately interleave
// (a Heartbeat, a Finding). Fails the test rather than blocking forever: the
// connection carries its own deadline.
func nextInventoryDelta(t *testing.T, dec *json.Decoder) *tunnel.InventoryDelta {
	t.Helper()
	for {
		var msg tunnel.ClientMessage
		if err := dec.Decode(&msg); err != nil {
			t.Fatalf("decode message off the tunnel while waiting for an InventoryDelta: %v", err)
		}
		if msg.InventoryDelta != nil {
			return msg.InventoryDelta
		}
	}
}

// startSessionOverPipe wires runTunnelSession to one end of a net.Pipe and
// hands back a decoder reading the other end — the same harness shape
// client_test.go's existing session tests use.
func startSessionOverPipe(t *testing.T) *json.Decoder {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close() })
	t.Cleanup(func() { serverConn.Close() })

	findingQ := newRunningFindingQueue(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() {
		_, _ = runTunnelSession(ctx, Config{AgentVersion: "test"}, clientConn, &x509.Certificate{}, findingQ, nil)
	}()

	if err := serverConn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	return json.NewDecoder(serverConn)
}

// TestRunTunnelSessionRefreshesDetectorStatusWithoutReconnect is the first
// half of B177, measured live on the standing rke2 agent: the facts snapshot
// is taken before the sweep detector's first tick, so the sweep reported a
// zero LastSuccessAt — rendered "Not yet observed" — for the whole session,
// while sweeping normally. A detector that records a success after the
// session opened must reach the hub on this session, not on the next one.
func TestRunTunnelSessionRefreshesDetectorStatusWithoutReconnect(t *testing.T) {
	resetDetectorRunStates()
	t.Cleanup(resetDetectorRunStates)
	shortenFactsRefresh(t, 100*time.Millisecond)

	dec := startSessionOverPipe(t)

	// The connect-time snapshot: nothing has swept yet, exactly like a real
	// agent whose sweep ticker has not fired for the first time.
	initial := nextInventoryDelta(t, dec)
	if initial.Facts.Detectors == nil {
		t.Fatalf("initial InventoryDelta carried no Detectors at all: %+v", initial.Facts)
	}
	if !initial.Facts.Detectors.Sweep.LastSuccessAt.IsZero() {
		t.Fatalf("expected the connect-time snapshot to report a zero sweep LastSuccessAt, got %v", initial.Facts.Detectors.Sweep.LastSuccessAt)
	}

	// The sweep detector completes a pass, the way runSweepDetector's own
	// goroutine records one.
	swept := time.Now().UTC().Truncate(time.Second)
	sweepRunState.recordSuccess(swept)

	refreshed := nextInventoryDelta(t, dec)
	if !refreshed.FullResync {
		t.Errorf("a refresh must be a full resync like the initial send — the hub replaces cluster_facts wholesale — got FullResync=false")
	}
	if refreshed.Facts.Detectors == nil {
		t.Fatalf("refreshed InventoryDelta carried no Detectors at all: %+v", refreshed.Facts)
	}
	if got := refreshed.Facts.Detectors.Sweep.LastSuccessAt; !got.Equal(swept) {
		t.Fatalf("sweep LastSuccessAt on the refresh = %v, want %v — the hub is still being told the connect-time snapshot, so a healthy detector reads as never observed for the whole session", got, swept)
	}
}

// revocableReviewer is a rulesReviewCreator whose answer can be changed
// mid-test, standing in for an operator revoking a ClusterRole rule while the
// agent is connected. Mutex-guarded because WatchSetCache.Get is called from
// the session's refresh goroutine while the test writes from its own.
type revocableReviewer struct {
	mu    sync.Mutex
	rules []authorizationv1.ResourceRule
}

func (r *revocableReviewer) set(rules []authorizationv1.ResourceRule) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules = rules
}

func (r *revocableReviewer) Create(_ context.Context, _ *authorizationv1.SelfSubjectRulesReview, _ metav1.CreateOptions) (*authorizationv1.SelfSubjectRulesReview, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return &authorizationv1.SelfSubjectRulesReview{
		Status: authorizationv1.SubjectRulesReviewStatus{ResourceRules: r.rules},
	}, nil
}

// sweepRulesExcept grants every read the sweep detector requires except the
// named labels.
func sweepRulesExcept(excluded ...string) []authorizationv1.ResourceRule {
	skip := map[string]bool{}
	for _, label := range excluded {
		skip[label] = true
	}
	var rules []authorizationv1.ResourceRule
	for _, r := range requiredDetectorReads[sweepDetectorID] {
		if skip[r.label] {
			continue
		}
		rules = append(rules, fullRule(r.group, r.resource))
	}
	return rules
}

// TestRunTunnelSessionRefreshesDeniedReadsWithoutReconnect is B177's second
// half, and the one measured most directly: revoking `ingresses` on the live
// rke2 agent produced three 403 log lines per sweep and no hub-side change
// whatsoever across two sweeps; a single pod restart later the hub showed
// deniedReads: ["ingresses"] immediately. The mechanism worked; only its
// delivery did not. Here the revocation happens mid-session and must reach
// the wire without the session ending.
func TestRunTunnelSessionRefreshesDeniedReadsWithoutReconnect(t *testing.T) {
	resetDetectorRunStates()
	t.Cleanup(resetDetectorRunStates)
	shortenFactsRefresh(t, 100*time.Millisecond)

	reviewer := &revocableReviewer{rules: sweepRulesExcept()}
	// A TTL far below the refresh interval, so this test measures the
	// DELIVERY lag B177 is about and not discoveredWatchSetCache's own
	// DefaultWatchSetRefreshInterval, which is a separate (15 minute) floor
	// on how fast the agent itself notices a revocation.
	discoveredWatchSetCache.Store(NewWatchSetCache(&fakeDiscoverer{lists: sweepRequiredResourceLists()}, reviewer, time.Millisecond))
	t.Cleanup(func() { discoveredWatchSetCache.Store(nil) })

	dec := startSessionOverPipe(t)

	initial := nextInventoryDelta(t, dec)
	if initial.Facts.Detectors == nil {
		t.Fatalf("initial InventoryDelta carried no Detectors at all: %+v", initial.Facts)
	}
	if got := initial.Facts.Detectors.Sweep.DeniedReads; len(got) != 0 {
		t.Fatalf("expected no denied reads while RBAC grants everything sweep needs, got %v", got)
	}

	// The revocation.
	reviewer.set(sweepRulesExcept("ingresses"))

	deadline := time.Now().Add(15 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatal("no InventoryDelta reported the revoked read before the deadline — the hub cannot learn that a detector is RBAC-blocked without a tunnel reconnect")
		}
		delta := nextInventoryDelta(t, dec)
		if delta.Facts.Detectors == nil {
			continue
		}
		denied := delta.Facts.Detectors.Sweep.DeniedReads
		if len(denied) == 0 {
			continue // the cache had not re-reviewed yet; keep reading
		}
		if len(denied) != 1 || denied[0] != "ingresses" {
			t.Fatalf("denied reads = %v, want exactly [ingresses]", denied)
		}
		return
	}
}

// TestStartFactsRefreshKeepsOnlyTheNewestSnapshot pins the coalescing rule
// startFactsRefresh's channel depends on: ClusterFacts is absolute state, not
// an event stream, so a snapshot the session has not managed to send yet is
// superseded rather than queued. Without this a session that stalled would
// spend its recovery sending facts that were already wrong.
func TestStartFactsRefreshKeepsOnlyTheNewestSnapshot(t *testing.T) {
	resetDetectorRunStates()
	t.Cleanup(resetDetectorRunStates)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := startFactsRefresh(ctx, Config{}, 5*time.Millisecond)

	// Let several refreshes accumulate with nothing reading the channel.
	first := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	sweepRunState.recordSuccess(first)
	time.Sleep(60 * time.Millisecond)

	newest := time.Now().UTC().Truncate(time.Second)
	sweepRunState.recordSuccess(newest)

	deadline := time.After(10 * time.Second)
	for {
		select {
		case facts := <-out:
			if facts.Detectors == nil {
				t.Fatal("refreshed facts carried no Detectors")
			}
			got := facts.Detectors.Sweep.LastSuccessAt
			if got.Equal(newest) {
				return
			}
			if got.Equal(first) {
				// Only acceptable if it was already buffered before the
				// second recordSuccess; the very next one must be newest.
				continue
			}
			t.Fatalf("unexpected sweep LastSuccessAt %v, want %v or %v", got, newest, first)
		case <-deadline:
			t.Fatal("no snapshot carrying the newest detector state arrived")
		}
	}
}

// TestStartFactsRefreshNonPositiveIntervalNeverSends covers the defensive
// branch: a non-positive interval would panic time.NewTicker, so it must
// instead leave the session with exactly its pre-B177 behaviour — one
// InventoryDelta on connect and no refreshes.
func TestStartFactsRefreshNonPositiveIntervalNeverSends(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := startFactsRefresh(ctx, Config{}, 0)
	select {
	case facts := <-out:
		t.Fatalf("expected no refresh at all with a non-positive interval, got %+v", facts)
	case <-time.After(200 * time.Millisecond):
	}
}
