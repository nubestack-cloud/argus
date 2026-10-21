package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"argus/internal/tunnel"
)

// TestEffectiveFindingResendCooldown pins the "configured wins if positive,
// else the default" precedence rule cmd/agent/main.go's
// findingResendCooldownFromEnv and detector.go's defaultFindingResendCooldown
// both rely on.
func TestEffectiveFindingResendCooldown(t *testing.T) {
	cases := []struct {
		name       string
		configured time.Duration
		want       time.Duration
	}{
		{"positive override wins", 30 * time.Second, 30 * time.Second},
		{"zero falls back to default", 0, defaultFindingResendCooldown},
		{"negative falls back to default", -5 * time.Second, defaultFindingResendCooldown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := effectiveFindingResendCooldown(c.configured); got != c.want {
				t.Errorf("effectiveFindingResendCooldown(%v) = %v, want %v", c.configured, got, c.want)
			}
		})
	}
}

// TestRunTunnelSessionForwardsFindings exercises exactly the wiring this
// package's detector work added to runTunnelSession: a Finding pushed onto
// findingCh while a session is active must be encoded onto the connection
// as ClientMessage{Finding: ...}, using the same json.Encoder the initial
// InventoryDelta and Heartbeats already use — there is only ever one
// goroutine (runTunnelSession's own) calling enc.Encode, which is what makes
// sharing one net.Conn/json.Encoder across message types safe. Uses
// net.Pipe as the "wire," so this needs neither a live cluster nor a live
// hub.
func TestRunTunnelSessionForwardsFindings(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	findingQ := newRunningFindingQueue(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sessionErrCh := make(chan error, 1)
	go func() {
		_, err := runTunnelSession(ctx, Config{AgentVersion: "test"}, clientConn, &x509.Certificate{}, findingQ, nil)
		sessionErrCh <- err
	}()

	if err := serverConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	dec := json.NewDecoder(serverConn)

	// The first message off the wire is always the initial full-resync
	// InventoryDelta — client.go's existing, unchanged behaviour, checked
	// here only to establish ordering before the Finding assertion below.
	var first tunnel.ClientMessage
	if err := dec.Decode(&first); err != nil {
		t.Fatalf("decode initial message: %v", err)
	}
	if first.InventoryDelta == nil {
		t.Fatalf("expected the first message off the wire to carry InventoryDelta, got %+v", first)
	}

	want := tunnel.Finding{DetectorID: "k8s-warning-events", DetectorVersion: "v1", Fingerprint: "abc123", Reason: "FailedScheduling"}
	findingQ.In() <- want

	var second tunnel.ClientMessage
	if err := dec.Decode(&second); err != nil {
		t.Fatalf("decode finding message: %v", err)
	}
	if second.Finding == nil {
		t.Fatalf("expected the second message off the wire to carry a Finding, got %+v", second)
	}
	if second.Finding.Fingerprint != want.Fingerprint || second.Finding.Reason != want.Reason || second.Finding.DetectorID != want.DetectorID {
		t.Fatalf("Finding not forwarded correctly over the tunnel: got %+v, want %+v", second.Finding, want)
	}

	cancel()
	select {
	case err := <-sessionErrCh:
		if err != context.Canceled {
			t.Fatalf("runTunnelSession returned %v after ctx cancellation, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runTunnelSession did not return promptly after ctx cancellation")
	}
}

// TestRunTunnelSession_TerminalSignal proves the agent-side half of the
// reconnect-storm fix at the lowest level that can see it: given a
// ServerMessage carrying Terminal (what internal/gateway/server.go's
// handleConn now sends for an Archived/Rejected cluster, right before
// closing), runTunnelSession returns that reason rather than treating it as
// an ordinary read error — this is what lets serveTunnelForever tell "the
// hub told us to stop trying" apart from "the connection just died," which
// is the entire point of the wire field. Uses net.Pipe, like
// TestRunTunnelSessionForwardsFindings above — no TLS/CA needed to exercise
// this half of the contract.
func TestRunTunnelSession_TerminalSignal(t *testing.T) {
	for _, reason := range []string{tunnel.TerminalReasonArchived, tunnel.TerminalReasonRejected} {
		t.Run(reason, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			findingQ := newRunningFindingQueue(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			type result struct {
				terminal string
				err      error
			}
			resultCh := make(chan result, 1)
			go func() {
				terminal, err := runTunnelSession(ctx, Config{AgentVersion: "test"}, clientConn, &x509.Certificate{}, findingQ, nil)
				resultCh <- result{terminal, err}
			}()

			if err := serverConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatalf("set deadline: %v", err)
			}
			// Drain the initial full-resync InventoryDelta runTunnelSession
			// always sends first — same ordering TestRunTunnelSessionForwardsFindings
			// establishes — before playing the hub's part.
			var first tunnel.ClientMessage
			if err := json.NewDecoder(serverConn).Decode(&first); err != nil {
				t.Fatalf("decode initial message: %v", err)
			}

			// The real hub sends Terminal ALONE and then closes — see
			// tunnel.ServerMessage.Terminal's own doc comment and
			// server.go's handleConn.
			if err := json.NewEncoder(serverConn).Encode(tunnel.ServerMessage{Terminal: reason}); err != nil {
				t.Fatalf("encode terminal signal: %v", err)
			}
			serverConn.Close()

			select {
			case res := <-resultCh:
				if res.err != nil {
					t.Fatalf("runTunnelSession returned err=%v alongside terminal=%q, want nil error — a terminal signal is an orderly end, not a failure", res.err, res.terminal)
				}
				if res.terminal != reason {
					t.Fatalf("runTunnelSession returned terminal=%q, want %q", res.terminal, reason)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("runTunnelSession did not return promptly after the terminal signal")
			}
		})
	}
}

// TestRunTunnelSession_PlainEOFIsNotTerminal is TestRunTunnelSession_TerminalSignal's
// negative case: a connection that just ends — no ServerMessage.Terminal at
// all, exactly what a hub restart or network blip looks like on the wire —
// must NOT be reported as a terminal reason. Getting this backwards (treating
// every disconnect as terminal) would be worse than the bug this feature
// fixes: it would push an ordinary, transient disconnect into the ~30 minute
// backoff too.
func TestRunTunnelSession_PlainEOFIsNotTerminal(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	findingQ := newRunningFindingQueue(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type result struct {
		terminal string
		err      error
	}
	resultCh := make(chan result, 1)
	go func() {
		terminal, err := runTunnelSession(ctx, Config{AgentVersion: "test"}, clientConn, &x509.Certificate{}, findingQ, nil)
		resultCh <- result{terminal, err}
	}()

	if err := serverConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	var first tunnel.ClientMessage
	if err := json.NewDecoder(serverConn).Decode(&first); err != nil {
		t.Fatalf("decode initial message: %v", err)
	}
	// No ServerMessage at all — just hang up, like a hub process restarting.
	serverConn.Close()

	select {
	case res := <-resultCh:
		if res.terminal != "" {
			t.Fatalf("runTunnelSession returned terminal=%q for a plain disconnect with no ServerMessage.Terminal, want empty", res.terminal)
		}
		if res.err == nil {
			t.Fatal("runTunnelSession returned a nil error for a plain disconnect, want a read error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runTunnelSession did not return promptly after the plain disconnect")
	}
}

// generateSelfSignedCertForTest returns a minimal self-signed ECDSA cert/key
// pair for the two TLS integration tests below (TestServeTunnelForever_*).
// Deliberately independent of internal/gateway.DevCA: this package cannot
// import internal/gateway (gateway already imports agent, in
// tunnel_roundtrip_test.go, so the reverse import would cycle), and a
// self-signed leaf used as its own trust anchor is sufficient here — these
// tests only need a real net.Conn+TLS handshake to drive
// serveTunnelForever's actual dial loop, not a realistic PKI.
func generateSelfSignedCertForTest(t *testing.T, commonName string, ips []net.IP) (certPEM, keyPEM []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return certPEM, keyPEM
}

// TestServeTunnelForever_TerminalSignalBacksOffLong is this feature's
// end-to-end proof on the agent side: a hub that sends the terminal signal on
// every connection must NOT be hammered on the normal 5s/60s-capped ladder —
// serveTunnelForever must wait tunnelTerminalBackoff (~30 minutes) before its
// next attempt instead. Waiting out the real 30 minutes in a test is
// obviously infeasible, so this asserts the negative that actually matters:
// no second connection attempt arrives within a window well past where the
// FAST ladder would have already retried (tunnelBackoffInitial=5s, plus up to
// 20% jitter — so by 8s a fast-ladder retry would essentially always have
// already happened). Then cancels ctx and confirms serveTunnelForever unblocks
// immediately, proving the long wait is interruptible rather than a bare
// time.Sleep.
func TestServeTunnelForever_TerminalSignalBacksOffLong(t *testing.T) {
	serverCertPEM, serverKeyPEM := generateSelfSignedCertForTest(t, "test-hub", []net.IP{net.ParseIP("127.0.0.1")})
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("load server cert: %v", err)
	}
	agentCertPEM, agentKeyPEM := generateSelfSignedCertForTest(t, "test-agent", nil)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var connCount int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&connCount, 1)
			go func(c net.Conn) {
				defer c.Close()
				// Real handleConn behaviour: send Terminal alone, then close
				// — no read of anything the agent sent first.
				_ = json.NewEncoder(c).Encode(tunnel.ServerMessage{Terminal: tunnel.TerminalReasonArchived})
			}(conn)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	cfg := Config{AgentVersion: "test", TLSServerNameOverride: "127.0.0.1"}
	findingQ := newRunningFindingQueue(t)

	sessionErrCh := make(chan error, 1)
	go func() {
		sessionErrCh <- serveTunnelForever(ctx, cfg, ln.Addr().String(), agentCertPEM, agentKeyPEM, serverCertPEM, findingQ, nil)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for atomic.LoadInt32(&connCount) < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&connCount); got < 1 {
		t.Fatalf("no connection attempt observed within 3s (got %d)", got)
	}

	// tunnelBackoffInitial is 5s, jittered up to +20% — by 8s a fast-ladder
	// retry would essentially always have already landed.
	time.Sleep(8 * time.Second)
	if got := atomic.LoadInt32(&connCount); got != 1 {
		t.Fatalf("connection attempts = %d after 8s following a terminal signal, want exactly 1 — the agent retried on (or near) the fast ladder instead of backing off to tunnelTerminalBackoff", got)
	}

	cancel()
	select {
	case err := <-sessionErrCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("serveTunnelForever returned %v after ctx cancellation, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serveTunnelForever did not return promptly after ctx cancellation — the long backoff wait must still respect ctx.Done()")
	}
}

// TestServeTunnelForever_PlainDisconnectRetriesPromptly is
// TestServeTunnelForever_TerminalSignalBacksOffLong's negative case: a hub
// that never sends a terminal signal — indistinguishable, on the wire, from a
// hub restart or a network blip — must NOT push the agent onto the long
// backoff. serveTunnelForever must keep using its normal fast ladder, so a
// second connection attempt should arrive well within a few multiples of
// tunnelBackoffInitial (5s).
func TestServeTunnelForever_PlainDisconnectRetriesPromptly(t *testing.T) {
	serverCertPEM, serverKeyPEM := generateSelfSignedCertForTest(t, "test-hub", []net.IP{net.ParseIP("127.0.0.1")})
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("load server cert: %v", err)
	}
	agentCertPEM, agentKeyPEM := generateSelfSignedCertForTest(t, "test-agent", nil)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var connCount int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&connCount, 1)
			go func(c net.Conn) {
				// Complete the handshake, then hang up with no message at
				// all — a plain disconnect, never a terminal signal.
				if tlsConn, ok := c.(*tls.Conn); ok {
					_ = tlsConn.Handshake()
				}
				c.Close()
			}(conn)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := Config{AgentVersion: "test", TLSServerNameOverride: "127.0.0.1"}
	findingQ := newRunningFindingQueue(t)

	go func() {
		_ = serveTunnelForever(ctx, cfg, ln.Addr().String(), agentCertPEM, agentKeyPEM, serverCertPEM, findingQ, nil)
	}()

	// tunnelBackoffInitial is 5s (+20% jitter); allow generous headroom for
	// two full round trips before declaring this stuck on a long backoff.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&connCount) >= 2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("only %d connection attempt(s) within 15s of plain disconnects, want at least 2 — a hub restart/network blip must still reconnect promptly, not fall onto the terminal-signal long backoff", atomic.LoadInt32(&connCount))
}

// TestEffectiveSweepTimings covers the same "configured wins if positive,
// else the default" precedence for the sweep detector's two timing policies.
// Worth its own test rather than trusting symmetry with the cooldown helper:
// a sweep whose interval silently fell back to 5 minutes when an operator
// asked for 30 seconds looks exactly like a detector that is simply slow, and
// nothing else in the system would report the difference.
func TestEffectiveSweepTimings(t *testing.T) {
	for _, c := range []struct {
		name       string
		configured time.Duration
		want       time.Duration
		got        func(time.Duration) time.Duration
	}{
		{"interval configured", 30 * time.Second, 30 * time.Second, effectiveSweepInterval},
		{"interval zero falls back", 0, DefaultSweepInterval, effectiveSweepInterval},
		{"interval negative falls back", -time.Second, DefaultSweepInterval, effectiveSweepInterval},
		{"threshold configured", 45 * time.Second, 45 * time.Second, effectiveSweepSustainedThreshold},
		{"threshold zero falls back", 0, defaultSweepSustainedThreshold, effectiveSweepSustainedThreshold},
		{"threshold negative falls back", -time.Hour, defaultSweepSustainedThreshold, effectiveSweepSustainedThreshold},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := c.got(c.configured); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}
