// fakeagent.go is this harness's stand-in for a real cluster: it dials the
// exact same mTLS tunnel a real cmd/agent process would (same wire types,
// same handshake), using an already-issued leaf cert from enroll.go's REST
// flow — scripts/simulate-finding's dial pattern, ported and extended.
//
// The difference from a real agent (and from simulate-finding, which only
// ever sends, never receives): once connected, this file answers every
// unsolicited ToolRequest the hub's real internal/gateway.CallTool sends
// with whatever the CURRENT golden case's fixture says to answer, instead
// of running internal/agent.ToolExecutor against a real (in this sandbox,
// unreachable) Kubernetes API. This is the piece that makes "the loop's
// tool calls get real, scenario-appropriate answers instead of always
// 'not found'" (this task's brief) true — every other hop (hub HTTP API,
// gateway dispatch-and-correlate, the mTLS tunnel itself) is the real,
// unmodified production code path.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"argus/internal/tunnel"
)

// fakeAgent owns one live tunnel connection and answers ToolRequests
// against whatever GoldenCase is currently set — SetCase is called by
// main.go immediately before each POST /analyze so the very next
// ToolRequest (which can arrive any time after that call returns) is
// answered against the right fixture. A single connection is reused across
// every golden case in one harness run (matching a real cluster staying
// connected across many incidents) rather than reconnecting per case.
type fakeAgent struct {
	conn    net.Conn
	enc     *json.Encoder
	dec     *json.Decoder
	current atomic.Pointer[GoldenCase]

	stopOnce sync.Once
	stopped  chan struct{}
}

func dialFakeAgent(addr, serverName string, certPEM, keyPEM []byte, caPEM string, dialTimeout time.Duration) (*fakeAgent, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load issued cert/key pair: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, fmt.Errorf("no certificates found in the hub's CA response")
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: dialTimeout}, "tcp", addr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("dial tunnel at %s: %w", addr, err)
	}

	fa := &fakeAgent{
		conn:    conn,
		enc:     json.NewEncoder(conn),
		dec:     json.NewDecoder(conn),
		stopped: make(chan struct{}),
	}
	return fa, nil
}

// sendInitialInventory sends the one full-resync InventoryDelta a real
// agent's first message always is (internal/gateway's handleInventoryDelta
// is the only thing that promotes a Provisioning cluster to Active) and
// waits for its ack.
func (fa *fakeAgent) sendInitialInventory() error {
	msg := tunnel.ClientMessage{
		CorrelationID: "eval-harness-inventory",
		InventoryDelta: &tunnel.InventoryDelta{
			Facts:      tunnel.ClusterFacts{Nodes: []tunnel.NodeStatus{}, Reachable: false},
			FullResync: true,
		},
	}
	if err := fa.conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	if err := fa.enc.Encode(msg); err != nil {
		return fmt.Errorf("send initial InventoryDelta: %w", err)
	}
	if err := fa.conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	var resp tunnel.ServerMessage
	if err := fa.dec.Decode(&resp); err != nil {
		return fmt.Errorf("read InventoryDelta ack: %w", err)
	}
	if resp.Error != "" || !resp.Ack {
		return fmt.Errorf("hub did not ack the initial InventoryDelta: %+v", resp)
	}
	// Clear the deadlines set above — the tool-responder loop below owns
	// this connection's read/write timing from here on and manages its own.
	_ = fa.conn.SetReadDeadline(time.Time{})
	_ = fa.conn.SetWriteDeadline(time.Time{})
	return nil
}

// SetCase points the tool responder at gc — called once per golden case,
// before that case's POST /analyze goes out.
func (fa *fakeAgent) SetCase(gc *GoldenCase) {
	fa.current.Store(gc)
}

// Serve is the tool-responder loop: read a ServerMessage, and if it carries
// a ToolRequest, answer it against whatever case is currently set. Runs
// until the connection closes or the harness calls Close. Real tool calls
// within one investigation are issued sequentially (internal/llm/toolloop.go
// calls its ToolCallback once per tool_call in a loop, never concurrently),
// so a single-goroutine read-decide-write cycle needs no locking beyond the
// atomic case pointer.
func (fa *fakeAgent) Serve() {
	for {
		var sm tunnel.ServerMessage
		if err := fa.dec.Decode(&sm); err != nil {
			select {
			case <-fa.stopped:
			default:
				log.Printf("eval-harness: fake agent connection read loop ending: %v", err)
			}
			return
		}
		if sm.ToolRequest == nil {
			continue // Acks for messages this file never sends after the handshake, or an error frame — nothing to do.
		}

		gc := fa.current.Load()
		var data json.RawMessage
		var errMsg string
		if gc == nil {
			errMsg = "eval-harness: no golden case is currently active"
		} else {
			data, errMsg = gc.ToolResponse(sm.ToolRequest.Tool, sm.ToolRequest.Args)
		}

		reply := tunnel.ClientMessage{
			ToolResult: &tunnel.ToolResult{
				CorrelationID: sm.ToolRequest.CorrelationID,
				Data:          data,
				Error:         errMsg,
				Truncated:     false,
			},
		}
		if err := fa.enc.Encode(reply); err != nil {
			log.Printf("eval-harness: failed to send tool result: %v", err)
			return
		}
	}
}

func (fa *fakeAgent) Close() {
	fa.stopOnce.Do(func() { close(fa.stopped) })
	_ = fa.conn.Close()
}
