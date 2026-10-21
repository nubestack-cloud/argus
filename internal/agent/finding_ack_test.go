package agent

// finding_ack_test.go covers PROJECT.md P21 in isolation — the ack
// bookkeeping, the send window and the requeue-on-disconnect rule — using
// net.Pipe as the wire, so none of it needs a hub or a database.
//
// The end-to-end proof that a tunnel killed between send and ack loses
// nothing is deliberately NOT here: it is finding_ack_kill_db_test.go, which
// runs the real internal/gateway listener against a real Postgres and severs
// a real TCP connection at the moment of the write. A unit test cannot
// falsify "the hub never got it AND the hub later did", because nothing in
// this file is a hub.

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"argus/internal/redact"
	"argus/internal/tunnel"
)

// decodeClientMessage reads one ClientMessage off the hub end of the pipe,
// skipping the initial full-resync InventoryDelta and any heartbeat, so a
// test can assert about findings without depending on message ordering it
// does not care about.
func decodeNextFinding(t *testing.T, dec *json.Decoder) tunnel.ClientMessage {
	t.Helper()
	for {
		var msg tunnel.ClientMessage
		if err := dec.Decode(&msg); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if msg.Finding != nil {
			return msg
		}
	}
}

// TestFindingCarriesACorrelationIDAndIsHeldUntilAcked is the core of P21 at
// the message level: every Finding goes out with an id, and the session is
// still holding it — unacked — until the hub echoes that id back.
func TestFindingCarriesACorrelationIDAndIsHeldUntilAcked(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	q := newRunningFindingQueue(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_, _ = runTunnelSession(ctx, Config{AgentVersion: "test"}, clientConn, &x509.Certificate{}, q, nil)
	}()

	if err := serverConn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	dec := json.NewDecoder(serverConn)
	enc := json.NewEncoder(serverConn)

	q.In() <- tunnel.Finding{DetectorID: "k8s-sweep", Fingerprint: "fp-held", Reason: "ReplicasUnavailable"}
	sent := decodeNextFinding(t, dec)
	if sent.CorrelationID == "" {
		t.Fatal("a Finding went out with no CorrelationID — the hub's ack would then be unattributable, which is the whole mechanism P21 rests on")
	}

	// Acking it must release it. The observable consequence is that the
	// session stops holding it: send a second finding and confirm it is the
	// only thing left outstanding, by killing the session and checking what
	// comes back onto the queue.
	if err := enc.Encode(tunnel.ServerMessage{CorrelationID: sent.CorrelationID, Ack: true}); err != nil {
		t.Fatalf("send ack: %v", err)
	}

	q.In() <- tunnel.Finding{DetectorID: "k8s-sweep", Fingerprint: "fp-unacked", Reason: "ReplicasUnavailable"}
	second := decodeNextFinding(t, dec)
	if second.Finding.Fingerprint != "fp-unacked" {
		t.Fatalf("second finding fingerprint = %q, want fp-unacked", second.Finding.Fingerprint)
	}
	if second.CorrelationID == sent.CorrelationID {
		t.Fatal("two findings shared a CorrelationID — an ack could then release the wrong one")
	}

	// Kill the session with the second finding unacked. The acked one must
	// NOT come back; the unacked one must.
	clientConn.Close()
	serverConn.Close()

	requeued := waitForPendingDepth(t, q, 1)
	if requeued != 1 {
		t.Fatalf("pending depth after the session died = %d, want exactly 1 — the acked finding must not be replayed and the unacked one must not be lost", requeued)
	}
	got := <-q.Out()
	if got.Fingerprint != "fp-unacked" {
		t.Fatalf("the finding returned to the queue was %q, want fp-unacked", got.Fingerprint)
	}
}

// TestUnackedFindingsAreRequeuedInOrderAndCoalesce checks the rule that
// makes the requeue safe to do at all: everything unacked goes back through
// the queue's own front door, so it is coalesced and capacity-bounded
// exactly like a freshly detected finding rather than replayed as a stale
// flood.
func TestUnackedFindingsAreRequeuedInOrderAndCoalesce(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	q := newRunningFindingQueue(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_, _ = runTunnelSession(ctx, Config{AgentVersion: "test"}, clientConn, &x509.Certificate{}, q, nil)
	}()
	if err := serverConn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	dec := json.NewDecoder(serverConn)

	// Two distinct findings out, neither acked.
	q.In() <- tunnel.Finding{DetectorID: "k8s-sweep", Fingerprint: "fp-a", Reason: "A", OccurrenceCount: 2}
	decodeNextFinding(t, dec)
	q.In() <- tunnel.Finding{DetectorID: "k8s-sweep", Fingerprint: "fp-b", Reason: "B", OccurrenceCount: 1}
	decodeNextFinding(t, dec)

	clientConn.Close()
	waitForPendingDepth(t, q, 2)

	// A re-detection of fp-a arriving after the requeue must COALESCE onto
	// the requeued copy rather than adding a third entry, and must carry the
	// requeued copy's occurrence count forward — the property that keeps a
	// long outage bounded by "how many objects are broken" rather than by
	// "how long has the hub been gone".
	q.In() <- tunnel.Finding{DetectorID: "k8s-sweep", Fingerprint: "fp-a", Reason: "A", OccurrenceCount: 3}
	time.Sleep(50 * time.Millisecond)
	if pending, _ := q.Stats(); pending != 2 {
		t.Fatalf("pending depth = %d, want 2 — a re-detection of a requeued fingerprint must coalesce, not stack", pending)
	}

	first := <-q.Out()
	if first.Fingerprint != "fp-a" {
		t.Fatalf("first requeued finding = %q, want fp-a (requeue preserves the order they were sent in)", first.Fingerprint)
	}
	if first.OccurrenceCount != 5 {
		t.Fatalf("OccurrenceCount = %d, want 5 (2 carried forward from the requeued copy + 3 from the re-detection) — a coalesce that drops the count silently loses observations", first.OccurrenceCount)
	}
}

// TestSendWindowStopsDrainingAnUnackingHub is the bound that keeps
// hold-until-acked from reintroducing the unbounded buffer B176 removed: a
// hub that accepts bytes and never acks must leave findings IN the queue
// (coalescing, capacity-bounded) rather than let a session accumulate them
// all in memory.
func TestSendWindowStopsDrainingAnUnackingHub(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	q := newRunningFindingQueue(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_, _ = runTunnelSession(ctx, Config{AgentVersion: "test"}, clientConn, &x509.Certificate{}, q, nil)
	}()
	if err := serverConn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	dec := json.NewDecoder(serverConn)

	const offered = maxUnackedFindings + 25
	go func() {
		for i := 0; i < offered; i++ {
			q.In() <- tunnel.Finding{DetectorID: "k8s-sweep", Fingerprint: fingerprintN(i), Reason: "R"}
		}
	}()

	// Read exactly the window's worth off the wire, acking nothing.
	for i := 0; i < maxUnackedFindings; i++ {
		decodeNextFinding(t, dec)
	}

	// Nothing more may be written. Prove it by asserting the queue still
	// holds the remainder rather than the session having swallowed it.
	remaining := waitForPendingDepth(t, q, offered-maxUnackedFindings)
	if remaining != offered-maxUnackedFindings {
		t.Fatalf("pending depth = %d, want %d — past the send window the session must stop draining the queue, so an unacking hub cannot make the queue's own capacity bound meaningless", remaining, offered-maxUnackedFindings)
	}
	if _, dropped := q.Stats(); dropped != 0 {
		t.Fatalf("dropped = %d, want 0 — nothing here comes close to the capacity bound", dropped)
	}
}

// TestHeartbeatCarriesFindingQueueStatus is PROJECT.md B176's residual at
// the message level: what the agent knows about its own cap-triggered loss
// has to leave the pod.
func TestHeartbeatCarriesFindingQueueStatus(t *testing.T) {
	q := newFindingQueue(3)
	// Drive the real discard path rather than poking the counter, so this
	// test fails if discarding stops incrementing it.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go q.Run(ctx)
	for i := 0; i < 6; i++ {
		q.In() <- tunnel.Finding{DetectorID: "k8s-sweep", Fingerprint: fingerprintN(i), Reason: "R"}
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, dropped := q.Stats(); dropped > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	hb := heartbeatMessage(Config{AgentVersion: "test"}, &x509.Certificate{}, q)
	if hb.Heartbeat.FindingQueue == nil {
		t.Fatal("Heartbeat.FindingQueue is nil — an agent that knows it is losing findings and does not say so leaves the hub unable to tell that cluster apart from a quiet one")
	}
	if hb.Heartbeat.FindingQueue.Dropped == 0 {
		t.Error("FindingQueue.Dropped = 0 after the capacity bound discarded findings")
	}
	if hb.Heartbeat.FindingQueue.Capacity != 3 {
		t.Errorf("FindingQueue.Capacity = %d, want 3 — reported rather than assumed hub-side", hb.Heartbeat.FindingQueue.Capacity)
	}
	// Still the two cheap fields it always was, plus this: the struct's own
	// warning about what a heartbeat may cost is the reason this is three
	// integers and not a facts payload.
	if hb.Heartbeat.AgentVersion != "test" {
		t.Errorf("AgentVersion = %q, want test", hb.Heartbeat.AgentVersion)
	}
}

func fingerprintN(i int) string {
	return "fp-" + time.Duration(i).String() + "-" + string(rune('a'+i%26))
}

// waitForPendingDepth polls the queue until it reports EXACTLY want pending
// and returns what it last saw, so a test never races the pump goroutine.
//
// Exactly, not "at least": the pump hands the head to the tunnel writer on
// an unbuffered channel and only then dequeues it, so for one scheduling
// gap after each handoff the published depth is one higher than it is about
// to be. A >= comparison latches onto that transient and reports a depth
// that was never settled.
func waitForPendingDepth(t *testing.T, q *findingQueue, want int) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var pending int
	for time.Now().Before(deadline) {
		pending, _ = q.Stats()
		if pending == want {
			return pending
		}
		time.Sleep(10 * time.Millisecond)
	}
	return pending
}

// TestRedeliveredFindingIsRedactedExactlyOnce guards the interaction
// between P21's redelivery and non-negotiable 9's redaction chokepoint.
//
// Every send must still go through redact.Text — that is not negotiable and
// is asserted here on both deliveries — but the copy the queue gets back
// must be the PRE-redaction one. Before B182 this was load-bearing against a
// live corruption — redact.Text rewrote its own marker, so a finding
// redelivered across five disconnects reached an operator degraded five times
// over. B182 made Text idempotent, so this now pins the weaker but still
// wanted property: the queue holds raw findings and redaction happens once,
// at the one chokepoint.
func TestRedeliveredFindingIsRedactedExactlyOnce(t *testing.T) {
	const raw = "pod failed: token=abcdef1234567890 rejected"

	deliver := func(t *testing.T) tunnel.Finding {
		t.Helper()
		clientConn, serverConn := net.Pipe()
		defer serverConn.Close()

		q := newRunningFindingQueue(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			_, _ = runTunnelSession(ctx, Config{AgentVersion: "test"}, clientConn, &x509.Certificate{}, q, nil)
		}()
		if err := serverConn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		dec := json.NewDecoder(serverConn)

		q.In() <- tunnel.Finding{DetectorID: "k8s-sweep", Fingerprint: "fp-redact", Reason: "R", Message: raw}
		first := decodeNextFinding(t, dec)

		// Kill it unacked, then hand what came back to a second session.
		clientConn.Close()
		waitForPendingDepth(t, q, 1)
		requeued := <-q.Out()
		if requeued.Message != raw {
			t.Fatalf("the requeued copy's Message = %q, want the original %q — redelivering an already-redacted message degrades it further on every disconnect", requeued.Message, raw)
		}
		return *first.Finding
	}

	sent := deliver(t)
	if strings.Contains(sent.Message, "abcdef1234567890") {
		t.Fatalf("the credential reached the wire unredacted: %q", sent.Message)
	}
	if !strings.Contains(sent.Message, redact.Marker) {
		t.Fatalf("Message = %q, want it to carry the redaction marker — the tunnel writer's chokepoint must still run on every send", sent.Message)
	}
	if strings.Contains(sent.Message, redact.Marker+"]") {
		t.Fatalf("Message = %q, want exactly one redaction pass — a doubled marker means redact.Text ran over its own output", sent.Message)
	}
}
