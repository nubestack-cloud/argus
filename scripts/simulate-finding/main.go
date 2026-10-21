// Command simulate-finding is a throwaway test-support tool, not a product
// binary (hence living under scripts/, not cmd/) — it exists solely so
// scripts/smoke-test.sh can exercise internal/gateway's Finding-ingestion +
// incident-correlation path end to end against a live hub, without waiting
// on the parallel task building the real spoke-side detector that would
// normally send these messages. The wire contract (internal/tunnel.Finding,
// ClientMessage) is fixed regardless of which side sends it, so importing
// that package directly (rather than hand-rolling the JSON shape here) means
// this tool can never silently drift from the real wire format.
//
// It deliberately does the bare minimum of an agent's tunnel session: dial
// mTLS with an already-issued leaf cert (from the same enroll/accept/poll
// flow scripts/smoke-test.sh already drives via plain REST calls), optionally
// send one full-resync InventoryDelta (-send-inventory, to promote the
// cluster to Active first, the same way a real agent's first message would),
// then send each Finding in a supplied JSON array as its own ClientMessage,
// waiting for each one's Ack before sending the next. No Heartbeat, no
// reconnect/backoff logic — none of which this test needs.
//
// Usage:
//
//	go run ./scripts/simulate-finding \
//	  -addr localhost:8443 -cert cert.pem -key key.pem -ca ca.pem \
//	  -findings findings.json
//
// findings.json is a JSON array of internal/tunnel.Finding objects. Prints
// one line per acked finding, then a final "SUMMARY sent=N acked=N" line;
// exits non-zero on any dial, send, or ack failure (including an explicit
// {"error": "..."} ServerMessage).
//
// # Logging: deliberately NOT converted to internal/logging (PROJECT.md T22)
//
// T22 converts the hub's and agent's log.Printf call sites to structured slog
// records. The programs under scripts/ are excluded from that, permanently and
// on purpose — this is a decision, not a gap:
//
//   - They are dev/CI tooling, `go run` and `go build` throwaways. Nothing
//     under deploy/ or the Dockerfile builds them into a shipped image, so
//     none of their output ever reaches a support bundle or a log shipper,
//     which is the operability defect T22 exists to fix.
//   - None of them calls logging.Setup(), so their output is plain text read
//     by the person who just ran them. Converting would make it JSON, which
//     is strictly worse at a terminal, and the structured fields it would buy
//     (request_id, incident_id, cluster_id, actor_id) do not exist here:
//     there is no request, no actor, and no hub-side correlation to join to.
//   - CI reads some of this output as text (.github/workflows/eval.yml tees
//     and greps the eval harness's), so the format is an interface.
//
// The standard `log` package is the right tool for a terminal program. Use it
// here; use internal/logging under cmd/ and internal/.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"argus/internal/tunnel"
)

// tunnelClient bundles the connection and codecs sendAndAwaitAck needs —
// just enough state to send one ClientMessage and block for its
// ServerMessage ack, matching internal/gateway's own one-message-then-ack
// loop (internal/gateway/server.go's handleConn) from the other side.
type tunnelClient struct {
	conn    net.Conn
	enc     *json.Encoder
	dec     *json.Decoder
	timeout time.Duration
}

// sendAndAwaitAck writes msg, then blocks for the hub's matching
// ServerMessage response, failing if it's missing, mismatched, or reports an
// explicit error.
func (c *tunnelClient) sendAndAwaitAck(msg tunnel.ClientMessage) error {
	if err := c.conn.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	if err := c.enc.Encode(msg); err != nil {
		return fmt.Errorf("send message (correlationId=%s): %w", msg.CorrelationID, err)
	}

	if err := c.conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return fmt.Errorf("set read deadline: %w", err)
	}
	var resp tunnel.ServerMessage
	if err := c.dec.Decode(&resp); err != nil {
		return fmt.Errorf("read ack (correlationId=%s): %w", msg.CorrelationID, err)
	}
	if resp.Error != "" {
		return fmt.Errorf("hub reported an error (correlationId=%s): %s", msg.CorrelationID, resp.Error)
	}
	if !resp.Ack || resp.CorrelationID != msg.CorrelationID {
		return fmt.Errorf("unexpected response (correlationId=%s): %+v", msg.CorrelationID, resp)
	}
	return nil
}

func main() {
	addr := flag.String("addr", "localhost:8443", "hub tunnel address (host:port)")
	certPath := flag.String("cert", "", "path to the already-issued leaf certificate PEM (required)")
	keyPath := flag.String("key", "", "path to the matching private key PEM (required)")
	caPath := flag.String("ca", "", "path to the dev CA's root certificate PEM (required)")
	findingsPath := flag.String("findings", "-", `path to a JSON file containing an array of tunnel.Finding objects, or "-" for stdin`)
	serverName := flag.String("server-name", "", "TLS ServerName override; defaults to the host part of -addr")
	timeout := flag.Duration("timeout", 10*time.Second, "dial timeout and per-message ack-wait timeout")
	sendInventory := flag.Bool("send-inventory", false, "send one full-resync InventoryDelta before the findings — the same message a real agent sends first, and the only thing that promotes a Provisioning cluster to Active (internal/gateway's handleInventoryDelta); set this to exercise the findings as an Active cluster rather than a Provisioning one")
	flag.Parse()

	if *certPath == "" || *keyPath == "" || *caPath == "" {
		fmt.Fprintln(os.Stderr, "simulate-finding: -cert, -key, and -ca are all required")
		os.Exit(2)
	}

	findings, err := loadFindings(*findingsPath)
	if err != nil {
		log.Fatalf("simulate-finding: %v", err)
	}
	if len(findings) == 0 {
		log.Fatalf("simulate-finding: no findings to send")
	}

	tlsConfig, err := buildTLSConfig(*certPath, *keyPath, *caPath, *addr, *serverName)
	if err != nil {
		log.Fatalf("simulate-finding: %v", err)
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: *timeout}, "tcp", *addr, tlsConfig)
	if err != nil {
		log.Fatalf("simulate-finding: dial %s: %v", *addr, err)
	}
	defer conn.Close()

	client := &tunnelClient{
		conn:    conn,
		enc:     json.NewEncoder(conn),
		dec:     json.NewDecoder(conn),
		timeout: *timeout,
	}

	if *sendInventory {
		if err := client.sendAndAwaitAck(tunnel.ClientMessage{
			CorrelationID: "simulate-finding-inventory",
			InventoryDelta: &tunnel.InventoryDelta{
				Facts:      tunnel.ClusterFacts{Nodes: []tunnel.NodeStatus{}, Reachable: false},
				FullResync: true,
			},
		}); err != nil {
			log.Fatalf("simulate-finding: initial inventory delta: %v", err)
		}
		fmt.Println("acked initial InventoryDelta (promotes Provisioning -> Active)")
	}

	acked := 0
	for i := range findings {
		f := findings[i]
		correlationID := fmt.Sprintf("simulate-finding-%d", i)

		if err := client.sendAndAwaitAck(tunnel.ClientMessage{
			CorrelationID: correlationID,
			Finding:       &f,
		}); err != nil {
			log.Fatalf("simulate-finding: finding %d (fingerprint=%s): %v", i, f.Fingerprint, err)
		}

		acked++
		fmt.Printf("acked %d/%d fingerprint=%s correlationId=%s\n", acked, len(findings), f.Fingerprint, correlationID)
	}

	fmt.Printf("SUMMARY sent=%d acked=%d\n", len(findings), acked)
}

func loadFindings(path string) ([]tunnel.Finding, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("read findings input: %w", err)
	}

	var findings []tunnel.Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, fmt.Errorf("parse findings JSON (expected an array of tunnel.Finding objects): %w", err)
	}
	return findings, nil
}

func buildTLSConfig(certPath, keyPath, caPath, addr, serverNameOverride string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load client cert/key: %w", err)
	}

	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no certificates found in %s", caPath)
	}

	serverName := serverNameOverride
	if serverName == "" {
		if host, _, err := net.SplitHostPort(addr); err == nil {
			serverName = host
		} else {
			serverName = addr
		}
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}, nil
}
