package gateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/data"
	"argus/internal/events"
	"argus/internal/llm"
	"argus/internal/logging"
	"argus/internal/metrics"
	"argus/internal/resourcechanges"
	"argus/internal/tunnel"
)

// logger is this package's structured logger (PROJECT.md T22). Package-level
// and built through internal/logging.For, so it resolves whatever handler
// chain cmd/hub installs even though this var is initialized before main
// runs. Call sites that have a context use the *Context methods, which is
// what carries the correlation id (T23) onto the record.
var logger = logging.For("gateway")

// serverCertValidity is the gateway's own TLS server cert lifetime — matches
// lld/03-agent-protocol.md §3's leaf-cert ceiling (90 days), since the
// gateway's cert is, mechanically, just another leaf this same dev CA issues.
const serverCertValidity = 90 * 24 * time.Hour

// maxTunnelMessageBytes bounds one newline-delimited JSON message on the
// tunnel — generous relative to today's Heartbeat/InventoryDelta payloads
// (internal/tunnel.ClusterFacts' MVP subset is tiny), but bounded so a
// malformed or hostile peer can't make the gateway buffer unboundedly.
const maxTunnelMessageBytes = 1 << 20 // 1 MiB

// Gateway is the hub's Agent Gateway (lld/03-agent-protocol.md §6): the mTLS
// tunnel listener agents connect to after enrollment, handling Heartbeat,
// InventoryDelta, Finding, and (as of this increment) ToolResult messages
// over internal/tunnel's newline-delimited-JSON MVP transport — plus, going
// the other direction, CallTool (tools.go), which proactively sends a
// ToolRequest to an already-connected agent.
type Gateway struct {
	db     *data.DB
	ca     *DevCA
	events *events.Bus // shared with internal/api.Server (both constructed from the same *events.Bus in cmd/hub/main.go) — see that package's doc comment. Published to on every real state change this package causes: new/updated incidents (finding.go), health-monitor demotion and heartbeat-driven recovery (health.go, server.go's handleHeartbeat).

	// connsMu guards conns, the registry of live tunnel connections tools.go's
	// CallTool looks up against — keyed by (clusterID, role) since
	// PROJECT.md E11, so one cluster can hold an investigation connection
	// and a remediation connection at once. It was keyed by cluster alone,
	// which is exactly what made two separate ServiceAccounts on two
	// separate connections unbuildable: the second connection replaced the
	// first rather than joining it. Populated by
	// serveClientMessages on connect, removed on disconnect — see
	// registerConn/unregisterConn in tools.go.
	connsMu sync.Mutex
	conns   map[connKey]*agentConn

	// retryMu guards retryBudgets, CallToolWithRetry's per-cluster,
	// rolling-window retry counters (tools.go's takeRetryBudget) — a
	// separate mutex from connsMu since a retry-budget check has nothing to
	// do with the connection registry and shouldn't contend with it.
	retryMu      sync.Mutex
	retryBudgets map[string]*clusterRetryWindow

	// now stands in for time.Now everywhere in this package that needs the
	// current time for something testable (currently only
	// takeRetryBudget's rolling-window reset) — set to time.Now by
	// NewGateway, overridable in a white-box test the same way
	// internal/mcp.Store's own "now func() time.Time" field is, so a test
	// can cross a retryBudgetWindow boundary without an actual 5-minute
	// sleep.
	now func() time.Time

	// LLM is BACKLOG.md E11 piece 3's Mechanism 2 seam — polarity_gate.go's
	// handleGenericConditionAnomaly uses it (wrapped as a
	// conditionpolarity.ModelAsker) to ask the model, once per unseen
	// (kind, condition type) pair, which literal condition value means
	// "problem." Deliberately an exported field set AFTER construction
	// (cmd/hub/main.go: "gw.LLM = investigator"), not a NewGateway parameter:
	// widening NewGateway's positional signature would have forced every one
	// of the seven existing call sites across internal/gateway's and
	// internal/api's test files to change for a dependency most of them
	// never exercise. nil is a fully supported value (no model configured,
	// or a test that doesn't set this) — handleGenericConditionAnomaly
	// treats it as "Mechanism 2 unavailable" and fails closed rather than
	// panicking or guessing.
	//
	// Typed as llm.Completer (the one-shot "system+user prompt in, text out"
	// seam), not the concrete *llm.Provider it used to hold — BACKLOG.md
	// P13: this gate's real call site failed on every deployment whose
	// configured provider is `cli` (which is every deployment that actually
	// runs investigations), because *llm.Provider.Complete has no cli-kind
	// path at all. cmd/hub/main.go now sets this to the SAME *llm.Router the
	// investigation loop already dispatches through, so a provider-kind
	// change made in Settings takes effect here too, on the very next
	// Finding, with no hub restart.
	LLM llm.Completer

	// findingSem bounds how many Findings, across every cluster connection
	// this gateway is serving, are being processed CONCURRENTLY at once —
	// see serveClientMessages' Finding case and processFindingAsync for why
	// Finding handling happens off each connection's own read loop in the
	// first place (BUGS.md 131: a burst of Findings whose polarity gate
	// needed a synchronous, LLM-backed conditionpolarity.Resolve ask —
	// applyConditionPolarityGate, polarity_gate.go — each took several
	// seconds, and because the ORIGINAL code ran handleFinding inline on
	// the same goroutine that also has to keep scanning this connection for
	// its next Heartbeat, a big enough burst delayed that Heartbeat's
	// processing past health.go's disconnectedThreshold, demoting a
	// perfectly healthy, still-heartbeating cluster to Disconnected).
	//
	// Acquired INSIDE the spawned per-Finding goroutine, never from the
	// read loop itself — a full semaphore must never block scanning the
	// next message off the wire, only bound how many Findings are being
	// worked on at once (so a sweep-driven burst of dozens can't spawn
	// unbounded goroutines that all hammer cmd/cli-runner, whose own
	// maxInFlight is far smaller, or hold open a DB connection each). A nil
	// channel (a Gateway built via a bare struct literal rather than
	// NewGateway — several *_db_test.go files in this package do this, but
	// none of them call serveClientMessages) is treated as "unbounded" by
	// acquireFindingSlot/releaseFindingSlot below rather than deadlocking.
	findingSem chan struct{}

	// lnMu guards ln and shuttingDown, PROJECT.md B162's graceful-shutdown
	// state for the tunnel listener. ln is set by ListenAndServeTLS once its
	// listener exists and is what Shutdown closes to stop accepting new agent
	// connections; shuttingDown covers the race where Shutdown is called
	// before (or during) ListenAndServeTLS, so a listener that comes up after
	// the shutdown decision is closed immediately rather than serving
	// forever. Deliberately a separate mutex from connsMu — Shutdown takes
	// both, in this order, and nothing else takes this one.
	lnMu         sync.Mutex
	ln           net.Listener
	shuttingDown bool

	// tlsMu guards tlsConfig, the mTLS configuration the TLS listener and
	// the WebSocket transport share (PrepareTLS).
	tlsMu     sync.Mutex
	tlsConfig *tls.Config
}

// maxConcurrentFindingProcessing sizes Gateway.findingSem. Chosen as a small
// multiple of cmd/cli-runner's own maxInFlight (2, per its startup log) —
// large enough that an ordinary handful of concurrent Findings across a few
// clusters is never artificially serialized, small enough that a sweep's
// worth of dozens of Findings for one cluster (the BUGS.md 131 shape) can't
// pile up more concurrent model-asking work than the runner behind it can
// usefully absorb anyway. Not load-bearing enough to need to be exact.
const maxConcurrentFindingProcessing = 8

// acquireFindingSlot/releaseFindingSlot guard Gateway.findingSem — see that
// field's own doc comment for why this exists and why a nil channel (an
// unbounded Gateway, matching every construction path this package's test
// files use for anything OTHER than serveClientMessages) is handled rather
// than deadlocking.
func (g *Gateway) acquireFindingSlot() {
	if g.findingSem == nil {
		return
	}
	g.findingSem <- struct{}{}
}

func (g *Gateway) releaseFindingSlot() {
	if g.findingSem == nil {
		return
	}
	<-g.findingSem
}

// NewGateway constructs a Gateway. Doesn't start listening — call
// ListenAndServeTLS for that.
func NewGateway(db *data.DB, ca *DevCA, bus *events.Bus) *Gateway {
	return &Gateway{
		db:           db,
		ca:           ca,
		events:       bus,
		conns:        make(map[connKey]*agentConn),
		retryBudgets: make(map[string]*clusterRetryWindow),
		now:          time.Now,
		findingSem:   make(chan struct{}, maxConcurrentFindingProcessing),
	}
}

// ListenAndServeTLS starts the mTLS tunnel listener on addr, issuing the
// gateway's own server certificate (for the given SANs) from ca first. Blocks
// until the listener returns a non-recoverable error (e.g. the caller closed
// it, or the address is unusable).
func (g *Gateway) ListenAndServeTLS(addr string, sans []string) error {
	tlsConfig, err := g.PrepareTLS(sans)
	if err != nil {
		return err
	}

	ln, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	// PROJECT.md B162: published so Shutdown can close it. If Shutdown
	// already ran (a SIGTERM during startup), don't start accepting at all —
	// otherwise this loop would outlive the drain that was supposed to end it.
	g.lnMu.Lock()
	if g.shuttingDown {
		g.lnMu.Unlock()
		_ = ln.Close()
		return nil
	}
	g.ln = ln
	g.lnMu.Unlock()
	logger.Info("mTLS tunnel listener started", slog.String("addr", addr))

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			logger.Error("accepting a tunnel connection failed", logging.Err(err))
			continue
		}
		go g.handleConn(conn)
	}
}

// PrepareTLS issues the gateway's server certificate for sans (plus
// tunnel.GatewayServerName, which an agent tunnelling through a WebSocket
// verifies) and returns the mTLS configuration both transports share. The
// first call decides; later calls return the same configuration.
func (g *Gateway) PrepareTLS(sans []string) (*tls.Config, error) {
	g.tlsMu.Lock()
	defer g.tlsMu.Unlock()
	if g.tlsConfig != nil {
		return g.tlsConfig, nil
	}
	names := append([]string{tunnel.GatewayServerName}, sans...)
	certPEM, keyPEM, err := g.ca.IssueServerCert(names, serverCertValidity)
	if err != nil {
		return nil, fmt.Errorf("issue gateway server cert: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load gateway server cert: %w", err)
	}
	g.tlsConfig = &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    g.ca.ClientCAPool(),
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	return g.tlsConfig, nil
}

// ServeTunnelConn runs one agent's tunnel over an already-established byte
// stream, a WebSocket from the hub's API, exactly as the TLS listener runs
// one: the same mTLS handshake, the same cluster lookup, the same message
// loop. It blocks until the session ends. PrepareTLS must have run.
func (g *Gateway) ServeTunnelConn(conn net.Conn) {
	g.tlsMu.Lock()
	cfg := g.tlsConfig
	g.tlsMu.Unlock()
	g.lnMu.Lock()
	closing := g.shuttingDown
	g.lnMu.Unlock()
	if cfg == nil || closing {
		_ = conn.Close()
		return
	}
	g.handleConn(tls.Server(conn, cfg))
}

// Shutdown is PROJECT.md B162's tunnel half of a graceful SIGTERM: stop
// accepting new agent connections, then close the ones that are open so every
// agent learns immediately that this hub is gone, rather than holding a socket
// to a dead process until its own read deadline expires.
//
// Closing each connection is what "drains" it, and it is the right thing to
// do rather than a severing: the agent's reconnect loop
// (internal/agent/client.go's serveTunnelForever) treats a session ending as
// a normal event and redials with backoff, and every in-flight CallTool on a
// closed connection fails immediately with a clear "disconnected" error
// (agentConn.markClosed) instead of waiting out toolCallTimeout. It must
// therefore run LAST in the drain, after the HTTP and worker phases — an
// in-flight investigation still needs its cluster's tunnel to finish.
//
// Returns the number of agent connections that were open. ctx bounds the
// wait for the listener goroutine to notice; there is nothing to wait for
// beyond that, because each connection's own goroutine returns as soon as its
// read fails.
func (g *Gateway) Shutdown(ctx context.Context) int {
	g.lnMu.Lock()
	g.shuttingDown = true
	ln := g.ln
	g.ln = nil
	g.lnMu.Unlock()

	if ln != nil {
		// ListenAndServeTLS' accept loop returns nil on net.ErrClosed — see
		// its own errors.Is check.
		_ = ln.Close()
	}

	g.connsMu.Lock()
	// Every role's connection, not one per cluster: a draining shutdown that
	// left a cluster's remediation connection open would be worse than one
	// that closed nothing.
	open := make([]*agentConn, 0, len(g.conns))
	for _, ac := range g.conns {
		open = append(open, ac)
	}
	g.connsMu.Unlock()

	for _, ac := range open {
		ac.close()
	}

	// Each closed connection's read loop unregisters itself; give them a
	// moment to do so, purely so the log line below and any last
	// ClusterUpdated event reflect reality. Not load-bearing — the process is
	// leaving either way.
	deadline := time.NewTimer(50 * time.Millisecond)
	defer deadline.Stop()
	select {
	case <-deadline.C:
	case <-ctx.Done():
	}
	return len(open)
}

// handleConn owns one agent connection end to end: completing the mTLS
// handshake, identifying the cluster by its peer cert's serial number, and
// then dispatching newline-delimited tunnel.ClientMessage values until the
// connection closes or an unexpected message/error occurs. There is no HTTP
// response channel here — this is a raw TCP/TLS stream — so errors are only
// ever logged server-side, never "returned" to a client that has no way to
// receive them.
func (g *Gateway) handleConn(conn net.Conn) {
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		logger.Warn("a non-TLS connection reached the tunnel handler; closing it")
		return
	}
	if err := tlsConn.Handshake(); err != nil {
		logger.Warn("TLS handshake failed", slog.String("peer", conn.RemoteAddr().String()), logging.Err(err))
		return
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		logger.Warn("no peer certificate presented; closing", slog.String("peer", conn.RemoteAddr().String()))
		return
	}
	serial := state.PeerCertificates[0].SerialNumber.String()

	ctx := context.Background()
	clusterID, clusterState, err := g.lookupClusterBySerial(ctx, serial)
	if err != nil {
		logger.Error("looking up a cluster by certificate serial failed",
			slog.String("cert_serial", serial), logging.Err(err))
		return
	}
	if clusterID == "" {
		// No cluster matches this serial — don't guess, just close.
		logger.Warn("no cluster matches this certificate serial; closing",
			slog.String("cert_serial", serial), slog.String("peer", conn.RemoteAddr().String()))
		return
	}
	// A previously-issued cert is still cryptographically valid even after a
	// cluster is decommissioned (this one-tier dev CA has no CRL/OCSP) — the
	// state check here, not certificate validity, is what actually severs a
	// decommissioned cluster's tunnel. Flagged as a related gap when
	// heartbeat-timeout detection was built; closed now, alongside
	// decommissioning itself, since a "decommission" that still quietly
	// accepts and acks tunnel traffic wouldn't mean anything.
	if clusterState == "Archived" || clusterState == "Rejected" {
		// Tell the agent WHY, on the wire, before severing it — see
		// tunnel.ServerMessage.Terminal's own doc comment for the reconnect-
		// storm this fixes. Best-effort: if the write itself fails (the peer
		// already hung up, a mid-handshake network drop), the close below
		// still happens and an older-agent-equivalent bare EOF is exactly
		// what that agent sees either way, so a failed send here is not a
		// reason to change what already happens next.
		reason := tunnel.TerminalReasonArchived
		if clusterState == "Rejected" {
			reason = tunnel.TerminalReasonRejected
		}
		if err := json.NewEncoder(conn).Encode(tunnel.ServerMessage{Terminal: reason}); err != nil {
			logger.Error("failed to send the terminal signal before closing a tunnel connection",
				logging.ClusterID(clusterID), slog.String("reason", reason), logging.Err(err))
		}
		logger.Warn("cluster connected while in a state that may not hold a tunnel; closing",
			logging.ClusterID(clusterID), slog.String("peer", conn.RemoteAddr().String()),
			slog.String("cluster_state", clusterState))
		return
	}
	logger.Info("cluster connected",
		logging.ClusterID(clusterID), slog.String("peer", conn.RemoteAddr().String()))

	if err := g.serveClientMessages(ctx, clusterID, conn); err != nil {
		logger.Warn("tunnel session ended with an error", logging.ClusterID(clusterID), logging.Err(err))
		return
	}
	logger.Info("cluster disconnected", logging.ClusterID(clusterID))
}

// serveClientMessages owns one connected agent's message loop: register it
// in the gateway's connection registry (tools.go — so CallTool, invoked
// from a completely different goroutine, can find and write to it), then
// read and dispatch newline-delimited ClientMessages until the connection
// closes or an unexpected message/error occurs, replying with an Ack to
// each in turn. This is handleConn's original loop verbatim, with one
// addition (the ToolResult case, routed to the registry instead of a
// per-message-type handler) and the connection-registry lifecycle wrapped
// around it.
//
// Split out from handleConn specifically so it can be exercised directly in
// tests with a fixed clusterID, without needing a live Postgres for the
// cert-serial-to-cluster-ID lookup handleConn's own prologue depends on —
// that lookup, and the Heartbeat/InventoryDelta/Finding handlers this loop
// still calls, are unchanged and already covered elsewhere (STATUS.md); this
// increment's own tests exercise the new ToolResult/registry/CallTool path
// this function adds.
func (g *Gateway) serveClientMessages(ctx context.Context, clusterID string, conn net.Conn) error {
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), maxTunnelMessageBytes)

	// PROJECT.md E11. The connection registers IMMEDIATELY, as
	// tunnel.RoleAll, and is re-keyed if and when a tunnel.Hello names a
	// narrower role. Deliberately not the other way round — reading the
	// first message before registering was tried and is wrong: dialling only
	// completes the mTLS handshake, so an agent that connects and then waits
	// to be addressable (which every one of this package's round-trip tests
	// does, and which is a perfectly reasonable thing for an agent to do)
	// would never be registered at all. Registration must be a property of
	// the CONNECTION existing, not of it having spoken.
	//
	// The window that costs: between registering and the first message (which
	// is what carries the Hello) arriving — one network round trip, and in
	// practice that message is already in the socket buffer — an investigate-only connection answers as RoleAll and
	// could be handed a write tool. What happens then is a 403 from the
	// cluster's API server, because the agent serving that connection holds
	// no write RBAC. That is the whole design: routing decides WHERE a
	// request goes, the cluster's own RBAC decides whether it may happen,
	// and no width of this window can turn the first into the second. The
	// cost of the race is a confusing error, never an unauthorised write.
	ac := newAgentConn(clusterID, tunnel.RoleAll, conn, json.NewEncoder(conn))

	g.registerConn(clusterID, ac)
	defer func() {
		g.unregisterConn(clusterID, ac)
		// Unblocks any CallTool still waiting on this connection with a
		// clean "disconnected" error instead of leaving it to time out.
		ac.markClosed()
	}()

	// helloSeen makes the Hello first-message-only rule enforceable: a role
	// is the registry key, and re-keying a connection something is already
	// holding would move it out from under an in-flight CallTool.
	helloSeen := false

	for scanner.Scan() {
		var msg tunnel.ClientMessage
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
			return fmt.Errorf("malformed message: %w", err)
		}

		// PROJECT.md E11's role declaration. Handled BEFORE the payload
		// switch and outside it, because a Hello is a MODIFIER on a message,
		// never a message of its own — an agent rides it on whatever its
		// first real payload happens to be (the initial InventoryDelta for
		// an investigation agent, the first Heartbeat for a remediation
		// one). That is what makes it additive in both directions: a hub
		// that predates roles sees an ordinary InventoryDelta carrying one
		// unknown field, which encoding/json discards, and serves the agent
		// exactly as before. A Hello sent as a lone message would instead
		// hit that hub's "message with no recognized payload" branch and
		// close the connection — which is precisely the kind of wire change
		// this protocol is not allowed to make.
		if msg.Hello != nil {
			if helloSeen {
				logger.Warn("agent declared a tunnel connection role after this connection had already carried traffic; ignoring it — a connection's role is fixed once it is in use",
					logging.ClusterID(clusterID), slog.String("declared_role", msg.Hello.Role))
			} else {
				g.rekeyConn(clusterID, ac, resolveHelloRole(clusterID, msg.Hello.Role))
			}
		}
		helloSeen = true

		var ackErr error
		switch {
		case msg.Heartbeat != nil:
			// PROJECT.md E11: a remediation connection's heartbeat keeps its
			// own socket proven alive (and is acked like any other message),
			// but it must NOT vouch for this cluster's health. Detection is
			// the investigation agent's job, and letting the write agent
			// hold a cluster in Active while the read agent is dead would
			// manufacture exactly the false "quiet cluster" this item's
			// coverage signal exists to expose.
			if ac.role == tunnel.RoleRemediate {
				if msg.Heartbeat.Remediation != nil {
					ackErr = g.storeRemediationAuthority(ctx, clusterID, msg.Heartbeat.Remediation)
				}
				break
			}
			ackErr = g.handleHeartbeat(ctx, clusterID, msg.Heartbeat)
		case msg.InventoryDelta != nil:
			// Same reasoning, and belt-and-braces: a remediation agent does
			// not gather facts and never sends this. Ignored rather than
			// trusted, so a future change on the agent side cannot silently
			// start overwriting the investigation agent's facts — including
			// its coverage figure — with a write agent's view.
			if ac.role == tunnel.RoleRemediate {
				break
			}
			ackErr = g.handleInventoryDelta(ctx, clusterID, msg.InventoryDelta)
		case msg.ChangeBatch != nil:
			// CI-S2. Only the investigation identity has an object cache, so a
			// remediation connection's batch is ignored rather than trusted.
			if ac.role == tunnel.RoleRemediate {
				break
			}
			ackErr = g.handleChangeBatch(ctx, clusterID, msg.ChangeBatch)
		case msg.Finding != nil:
			// Dispatched to its own goroutine and NOT awaited here — see
			// processFindingAsync's doc comment and BUGS.md 131. Mirrors the
			// discipline internal/agent/client.go's runTunnelSession already
			// applies to ToolRequest execution on the AGENT side ("a slow
			// tool call ... must never stall reading the next message off
			// the wire, including a heartbeat ack") — this loop never had
			// the matching discipline for Findings until now, and
			// handleFinding's own model-backed polarity gate
			// (applyConditionPolarityGate) is exactly the kind of call that
			// can legitimately take seconds. `continue` skips this
			// iteration's shared ack-send below; processFindingAsync sends
			// (or, on failure, tears down the connection in place of) that
			// ack itself once handleFinding actually finishes.
			go g.processFindingAsync(ctx, clusterID, ac, conn, msg.Finding, msg.CorrelationID)
			continue
		case msg.ToolResult != nil:
			// A ToolResult that matches no in-flight CallTool (the caller
			// already timed out and moved on, or the agent sent a stray/
			// duplicate) is a normal race, not a protocol violation — the
			// connection stays open either way. Logged, not silently
			// dropped: a real concurrency bug once made this fire for
			// results that had NOT actually timed out (see WORKLOG.md §114
			// and CallTool's own "register before send" doc comment) — a log
			// line here is what would have made that visible immediately
			// instead of only via a client-side "context deadline
			// exceeded" thirty seconds later.
			if !ac.deliver(*msg.ToolResult) {
				logger.Warn("tool result for an unknown or expired correlation id; the caller had most likely already timed out",
					logging.ClusterID(clusterID), slog.String("tunnel_correlation_id", msg.ToolResult.CorrelationID))
			}
		default:
			// A message carrying a Hello and nothing else would land here.
			// Deliberately still an error: this hub does not need agents to
			// send one, and accepting a payload-free message would make the
			// "Hello rides a real message" rule unenforced on the one side
			// that can enforce it.
			return errors.New("message with no recognized payload")
		}
		if ackErr != nil {
			return ackErr
		}

		if err := ac.send(tunnel.ServerMessage{CorrelationID: msg.CorrelationID, Ack: true, HubFeatures: hubFeatures}); err != nil {
			return fmt.Errorf("write ack: %w", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("connection read error: %w", err)
	}
	return nil
}

// processFindingAsync runs handleFinding for exactly one Finding OFF
// serveClientMessages' own read loop, bounded by Gateway.findingSem, then
// sends that Finding's ack itself (mirroring serveClientMessages' own
// shared ack-send tail) — or, on failure, closes conn in place of
// serveClientMessages' own "return the error, let handleConn's deferred
// cleanup run" path, since a goroutine that is no longer the one being
// `return`ed from cannot make serveClientMessages itself return an error.
// Closing conn is equivalent in effect: scanner.Scan() in the (still
// running) read loop then fails, serveClientMessages returns a
// "connection read error", and handleConn's deferred cleanup
// (unregisterConn/markClosed) runs exactly as it would have for a
// synchronous handleFinding error — see BUGS.md 131 and this function's own
// call site (serveClientMessages' Finding case) for why this exists: a
// Finding whose polarity gate needs a synchronous, LLM-backed model ask
// (applyConditionPolarityGate, internal/conditionpolarity.Resolve) can take
// several real seconds, and running that inline on the connection's own read
// goroutine — the same goroutine that must also keep scanning for this
// cluster's next Heartbeat — let a sweep-driven burst of such Findings
// delay Heartbeat processing long enough to demote a perfectly healthy,
// still-heartbeating cluster to Disconnected.
//
// ctx is serveClientMessages' own ctx (today always context.Background(),
// per handleConn) — this Finding's processing is scoped to the tunnel
// connection's lifetime, not to the specific read-loop iteration that
// happened to receive it, so outliving that iteration is correct, not a
// leak. conn.Close() below is what actually severs it if the connection
// itself goes away first.
func (g *Gateway) processFindingAsync(ctx context.Context, clusterID string, ac *agentConn, conn net.Conn, f *tunnel.Finding, correlationID string) {
	// PROJECT.md T11's queue-depth metric: incremented for the FULL
	// lifetime of this goroutine, not just the window between
	// acquireFindingSlot/releaseFindingSlot below — a Finding waiting for a
	// free slot (findingSem is already at maxConcurrentFindingProcessing)
	// is exactly the backlog this metric exists to show, and capping the
	// gauge at findingSem's own small size (8) would hide the one scenario
	// (BUGS.md 131's storm) this metric is most useful for catching.
	metrics.FindingProcessingInflight.Inc()
	defer metrics.FindingProcessingInflight.Dec()

	g.acquireFindingSlot()
	defer g.releaseFindingSlot()

	if err := g.handleFinding(ctx, clusterID, f); err != nil {
		logger.Error("finding processing failed; closing the tunnel connection",
			logging.ClusterID(clusterID), logging.Err(err))
		// Covers every one of handleFinding's own early `return
		// fmt.Errorf(...)` paths generically, in one place, rather than an
		// "error" increment at each of the many call sites inside it — see
		// findingOutcome's own doc comment in finding.go for why a
		// successful disposition is instead recorded at handleFinding's own
		// single success return.
		metrics.FindingsProcessedTotal.Inc("error")
		_ = conn.Close()
		return
	}
	if err := ac.send(tunnel.ServerMessage{CorrelationID: correlationID, Ack: true}); err != nil {
		logger.Error("writing the finding ack failed", logging.ClusterID(clusterID), logging.Err(err))
		_ = conn.Close()
	}
}

// lookupClusterBySerial resolves a cluster's id and current state from its
// issued leaf cert's serial number (SignCSR's returned serial, stored in
// clusters.cert_serial at enroll-status time). Returns clusterID == "" if no
// cluster matches — the caller must treat that as "close the connection,"
// never guess. state is returned alongside id so the caller can also refuse a
// cert that's still cryptographically valid but belongs to a cluster that's
// since been decommissioned (this one-tier dev CA has no CRL/OCSP, so a
// state check is the only thing that can sever that tunnel).
func (g *Gateway) lookupClusterBySerial(ctx context.Context, serial string) (clusterID, state string, err error) {
	tx, err := g.db.Pool.Begin(ctx)
	if err != nil {
		return "", "", fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		return "", "", fmt.Errorf("resolve organisation: %w", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		return "", "", fmt.Errorf("set request scope: %w", err)
	}

	err = tx.QueryRow(ctx, `SELECT id, state FROM clusters WHERE cert_serial = $1`, serial).Scan(&clusterID, &state)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", nil
		}
		return "", "", fmt.Errorf("query cluster by cert serial: %w", err)
	}
	return clusterID, state, nil
}

// handleHeartbeat implements lld/03-agent-protocol.md §6's Heartbeat handling
// for this MVP's field subset: bump last_heartbeat_at and record the reported
// agent_version. Also implements §4/§7's "heartbeat resumes" transitions
// (Degraded->Active, Disconnected->Active) — receiving ANY heartbeat is
// itself the recovery signal, so this is the only code that needs to handle
// that half of the state machine; the demotion half (Active->Degraded,
// Degraded->Disconnected) is health.go's polling sweep, since there's no
// message to react to for "the agent went quiet."
//
// A cluster in any other state (Active itself, or anything else — e.g.
// Archived, Rejected, PendingApproval, Provisioning) is left alone: a
// heartbeat is only a recovery signal for the two states the health sweep
// can put a cluster into, never a way to resurrect it out of some other
// lifecycle state. (Whether the gateway should even be accepting a tunnel
// connection at all from an Archived cluster is a separate question this
// function doesn't address — see the health.go doc comment.)
func (g *Gateway) handleHeartbeat(ctx context.Context, clusterID string, hb *tunnel.Heartbeat) error {
	tx, err := g.db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		return fmt.Errorf("resolve organisation: %w", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		return fmt.Errorf("set request scope: %w", err)
	}

	// Read the pre-update state first, purely so the log line below can say
	// what actually recovered — the UPDATE's own CASE expression below is
	// what actually decides the new state, from the authoritative row at
	// UPDATE time, not from this read.
	//
	// The previously-stored drop total comes back in the same read for the
	// same kind of reason: it is only needed to decide whether this
	// heartbeat carries NEWS (the agent has discarded findings since we last
	// heard), which the stored value alone cannot answer. Nullable, because
	// an agent that predates tunnel.Heartbeat.FindingQueue never reported
	// one — see migration 000118.
	var previousState string
	var previousDropped *int
	if err := tx.QueryRow(ctx, `SELECT state, finding_queue_dropped FROM clusters WHERE id = $1`, clusterID).Scan(&previousState, &previousDropped); err != nil {
		return fmt.Errorf("look up cluster state: %w", err)
	}

	// PROJECT.md B176's residual. Passed straight through as three nullable
	// integers: nil for an agent that predates the field, which stores NULL
	// and stays distinguishable from a genuine zero for every reader. The
	// hub deliberately derives nothing from them here — they are the agent's
	// own counters, and the one place that knows WHICH object was discarded
	// is still that agent's log, by design (see FindingQueueStatus' own doc
	// comment on why no object identity crosses the tunnel for this).
	var qPending, qDropped, qCapacity *int
	if hb.FindingQueue != nil {
		qPending, qDropped, qCapacity = &hb.FindingQueue.Pending, &hb.FindingQueue.Dropped, &hb.FindingQueue.Capacity
	}

	if _, err := tx.Exec(ctx,
		`UPDATE clusters
		 SET last_heartbeat_at = now(),
		     agent_version = $2,
		     finding_queue_pending = $3,
		     finding_queue_dropped = $4,
		     finding_queue_capacity = $5,
		     state = CASE WHEN state IN ('Degraded', 'Disconnected') THEN 'Active' ELSE state END
		 WHERE id = $1`,
		clusterID, hb.AgentVersion, qPending, qDropped, qCapacity); err != nil {
		return fmt.Errorf("update heartbeat: %w", err)
	}

	recovered := previousState == "Degraded" || previousState == "Disconnected"
	if recovered {
		logger.Info("cluster returned to Active: its heartbeat resumed",
			logging.ClusterID(clusterID), slog.String("previous_state", previousState))
	}

	// Logged hub-side, once per increase rather than once per heartbeat, so
	// the fact reaches an operator reading hub logs and not only one reading
	// that agent's pod log — which is the entire point of carrying it over
	// the tunnel. A decrease is an agent restart (the counter is per-process
	// and resets to zero), not a recovery, so it is deliberately not
	// reported as one.
	if qDropped != nil && (previousDropped == nil || *qDropped > *previousDropped) {
		logger.Warn("this cluster's agent has discarded findings at its queue capacity bound since it started: findings from this cluster are being LOST. That agent's own log names which objects",
			logging.ClusterID(clusterID), slog.Int("dropped", *qDropped),
			slog.Int("queue_depth", derefInt(qPending)), slog.Int("queue_capacity", derefInt(qCapacity)))
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit heartbeat: %w", err)
	}
	if recovered && g.events != nil {
		g.events.Publish(events.ClusterUpdated(clusterID))
	}
	return nil
}

// handleInventoryDelta implements lld/03-agent-protocol.md §6/§8's
// InventoryDelta handling: upsert cluster_facts, and — per §4's stated
// transition ("first successful tunnel + inventory sync completes") — promote
// a Provisioning cluster to Active the first time this happens. This is the
// only place anything transitions a cluster INTO Active from Provisioning;
// handleHeartbeat above handles the Degraded/Disconnected->Active recovery
// transitions, and health.go's HealthMonitor handles the Active->Degraded and
// Degraded->Disconnected demotions on missed heartbeats.
func (g *Gateway) handleInventoryDelta(ctx context.Context, clusterID string, delta *tunnel.InventoryDelta) error {
	factsJSON, err := json.Marshal(delta.Facts)
	if err != nil {
		return fmt.Errorf("marshal cluster facts: %w", err)
	}

	tx, err := g.db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		return fmt.Errorf("resolve organisation: %w", err)
	}
	// Unlike clusters (id-keyed RLS, worked around by migration 000011's added
	// tenant_id policy — see its comment), cluster_facts is one of the
	// generic cluster_id-scoped tables from migration 000009's loop and has
	// ONLY that predicate — no tenant_id policy to fall back on. We already
	// know exactly which cluster this connection belongs to (resolved by
	// lookupClusterBySerial before any message is dispatched), so scope
	// narrowly to it rather than passing nil, which would fail cluster_facts'
	// WITH CHECK on INSERT.
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		return fmt.Errorf("set request scope: %w", err)
	}

	// Read the coverage this cluster last reported BEFORE overwriting it, so
	// the log line below can say what CHANGED. The same pattern, and the same
	// reason, as handleHeartbeat's pre-read of state/finding_queue_dropped:
	// the stored value alone cannot answer whether this payload carries news,
	// and an agent re-sends its whole facts payload every two minutes
	// forever (internal/agent's factsRefreshInterval). Without a comparison
	// this would either log nothing or log the same sentence 720 times a day
	// per cluster.
	//
	// A failure here is deliberately NOT fatal to the upsert: this read
	// exists only to decide whether to log, and losing a log line is not a
	// reason to drop a facts payload on the floor.
	var previousFacts json.RawMessage
	if err := tx.QueryRow(ctx, `SELECT facts FROM cluster_facts WHERE cluster_id = $1`, clusterID).Scan(&previousFacts); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		logger.Warn("could not read this cluster's previous facts to compare coverage against; proceeding with the upsert",
			logging.ClusterID(clusterID), logging.Err(err))
		previousFacts = nil
	}

	// The investigation agent can only describe its own, read-only identity.
	// While the remediation connection is up and has reported for itself,
	// its answer stands; once it goes away, the next refresh here replaces it.
	if g.IsConnectedForRole(clusterID, tunnel.RoleRemediate) {
		if prev := previousRemediation(previousFacts); prev != nil && prev.Reporter == tunnel.RoleRemediate {
			delta.Facts.Remediation = prev
			if factsJSON, err = json.Marshal(delta.Facts); err != nil {
				return fmt.Errorf("marshal cluster facts: %w", err)
			}
		}
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO cluster_facts (cluster_id, facts, updated_at)
		 VALUES ($1, $2, now())
		 ON CONFLICT (cluster_id) DO UPDATE SET facts = EXCLUDED.facts, updated_at = now()`,
		clusterID, factsJSON); err != nil {
		return fmt.Errorf("upsert cluster facts: %w", err)
	}

	logCoverageChange(clusterID, previousCoverage(previousFacts), delta.Facts.Coverage)

	if _, err := tx.Exec(ctx,
		`UPDATE clusters SET state = 'Active' WHERE id = $1 AND state = 'Provisioning'`,
		clusterID); err != nil {
		return fmt.Errorf("promote cluster to Active: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit inventory delta: %w", err)
	}
	return nil
}

// previousRemediation pulls the remediation block out of a stored facts blob,
// nil when there is none.
func previousRemediation(raw json.RawMessage) *tunnel.ClusterRemediation {
	if len(raw) == 0 {
		return nil
	}
	var parsed struct {
		Remediation *tunnel.ClusterRemediation `json:"remediation"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil
	}
	return parsed.Remediation
}

// storeRemediationAuthority records what the remediation identity reported it
// may change (tunnel.Heartbeat.Remediation) as this cluster's remediation
// facts. Only the remediation block is touched; a cluster with no facts row
// yet keeps none until the investigation agent's first inventory.
func (g *Gateway) storeRemediationAuthority(ctx context.Context, clusterID string, rem *tunnel.ClusterRemediation) error {
	rem.Reporter = tunnel.RoleRemediate
	remJSON, err := json.Marshal(rem)
	if err != nil {
		return fmt.Errorf("marshal remediation authority: %w", err)
	}
	tx, err := g.db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		return fmt.Errorf("resolve organisation: %w", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		return fmt.Errorf("set request scope: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE cluster_facts SET facts = jsonb_set(facts, '{remediation}', $2::jsonb) WHERE cluster_id = $1`,
		clusterID, remJSON); err != nil {
		return fmt.Errorf("store remediation authority: %w", err)
	}
	return tx.Commit(ctx)
}

// previousCoverage pulls just the coverage block out of a stored facts blob.
// Returns nil for no row, unparseable JSON, or an agent build that never
// reported coverage — all three mean the same thing to the one caller
// (logCoverageChange): there is no previous figure to compare against.
func previousCoverage(raw json.RawMessage) *tunnel.ClusterCoverage {
	if len(raw) == 0 {
		return nil
	}
	var parsed struct {
		Coverage *tunnel.ClusterCoverage `json:"coverage"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil
	}
	return parsed.Coverage
}

// logCoverageChange is PROJECT.md E11's coverage-loss signal on the HUB's own
// log — the surface an operator running ARGUS reads, as opposed to the
// cluster agent's pod log, which is inside the cluster being watched and is
// exactly where this fact was stranded before.
//
// Logged on CHANGE only, never per payload. The three transitions worth a
// line, and nothing else:
//
//   - the first report from a cluster whose agent can see less than the whole
//     cluster (there is no previous figure, and there is a gap);
//   - a DROP in what is readable — someone narrowed a ClusterRole, or a
//     chart upgrade reset one. This is the alarming direction and the reason
//     the whole signal exists: every symptom of it is an absence, so nothing
//     else in the system would ever mention it;
//   - a RISE, logged at info, because "coverage recovered" is what closes out
//     the warning above and an operator should not have to infer it from the
//     warning simply stopping.
//
// An unchecked coverage (the agent could not run the discovery/RBAC
// intersection) is reported once on the transition INTO that state and then
// stays quiet: it is a real degradation of the signal, but it is not a
// coverage number and must never be logged as one.
func logCoverageChange(clusterID string, prev, cur *tunnel.ClusterCoverage) {
	// An agent too old to report coverage at all. Silent: absence of the
	// field is "this build does not know", and a hub that announced it every
	// two minutes for every pre-E11 agent in a 200-cluster fleet would be
	// reporting its own upgrade backlog, not a cluster's coverage.
	if cur == nil {
		return
	}

	if !cur.Checked {
		if prev != nil && prev.Checked {
			logger.Warn("this cluster's agent can no longer determine how much of its cluster it is watching: its coverage figure is now unknown, so an absence of findings from it proves nothing either way",
				logging.ClusterID(clusterID), slog.String("reason", cur.Error))
		}
		return
	}

	denied := cur.KindsServed - cur.KindsReadable

	if prev == nil || !prev.Checked {
		if denied > 0 {
			logger.Warn("this cluster's agent is watching only part of its cluster: an absence of findings from the rest is not evidence that the rest is healthy",
				logging.ClusterID(clusterID),
				slog.Int("kinds_readable", cur.KindsReadable),
				slog.Int("kinds_served", cur.KindsServed),
				slog.Int("kinds_denied", denied),
				slog.Any("denied_sample", cur.DeniedSample))
		}
		return
	}

	switch {
	case cur.KindsReadable < prev.KindsReadable:
		logger.Warn("this cluster's agent has LOST read coverage: something narrowed its RBAC, and the kinds it can no longer read will now go unwatched in silence",
			logging.ClusterID(clusterID),
			slog.Int("kinds_readable_before", prev.KindsReadable),
			slog.Int("kinds_readable_now", cur.KindsReadable),
			slog.Int("kinds_served", cur.KindsServed),
			slog.Any("denied_sample", cur.DeniedSample))
	case cur.KindsReadable > prev.KindsReadable:
		logger.Info("this cluster's agent has gained read coverage",
			logging.ClusterID(clusterID),
			slog.Int("kinds_readable_before", prev.KindsReadable),
			slog.Int("kinds_readable_now", cur.KindsReadable),
			slog.Int("kinds_served", cur.KindsServed))
	}
}

// derefInt reads a nullable integer for a log line only, where a nil and a
// zero genuinely read the same. Never use it for anything a reader could
// mistake for a fact: everywhere else in this package, and everywhere in the
// API, nil means "not reported" and must stay distinguishable from 0.
func derefInt(v *int) int {
	if v == nil {
		return 0
	}
	return *v
}

// hubFeatures is advertised on every ack; see tunnel.ServerMessage.HubFeatures.
var hubFeatures = []string{tunnel.HubFeatureChangeBatch}

// handleChangeBatch stores one agent change batch (docs/CLUSTER_INSIGHT_SPECS.md
// CI-S2) scoped to the connection's own cluster, resolved from its
// certificate — never from the payload.
func (g *Gateway) handleChangeBatch(ctx context.Context, clusterID string, b *tunnel.ChangeBatch) error {
	tx, err := g.db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		return fmt.Errorf("resolve organisation: %w", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		return fmt.Errorf("set request scope: %w", err)
	}
	if _, err := resourcechanges.Insert(ctx, tx, tenantID, clusterID, b); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
