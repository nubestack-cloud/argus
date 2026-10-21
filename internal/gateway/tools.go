// tools.go implements the hub-side half of ADR-2's tool-call round trip
// (lld/14-adrs.md ADR-2, lld/07-analysis-contracts.md §2): a per-cluster
// registry of live tunnel connections, plus CallTool — the mechanism that
// lets the hub proactively send a ToolRequest to an already-connected agent
// and get back the correlated ToolResult, even with several calls to
// several clusters (or several concurrent calls to the same cluster) in
// flight at once.
//
// Nothing in this repo calls CallTool outside this package's own tests yet
// — the bounded, tool-calling investigation loop that would actually decide
// which tool to call and when is a separate, later piece of work. See
// STATUS.md for exactly what this does and doesn't unlock.
package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"argus/internal/logging"
	"argus/internal/metrics"

	"argus/internal/tunnel"
)

// toolCallTimeout bounds how long CallTool waits for a matching ToolResult
// once a ToolRequest has been sent — the only bound this increment adds. A
// tool call either gets its result inside this window or fails cleanly;
// there is deliberately no retry, no per-cluster/per-incident concurrency
// policy beyond this, and no persistence of in-flight or completed calls
// (see STATUS.md's "what this doesn't do yet" list).
//
// 12s, cut down from the original 30s judgment call (BACKLOG.md C11,
// 2026-09-02) using the real `mcp_tool_calls` distribution rather than
// another guess: of 1,473 successful calls, p50=10ms, p90=21ms, p99=621ms —
// the old 30s bought nothing for the calls that were always going to
// succeed, since virtually all of them return in under a second. 132 calls
// (7% of all calls) hung the full old toolCallTimeout+resultGraceWindow (or
// twice that, across a retry) for 6,180s of combined wall clock, recording
// zero evidence — the mechanism behind the measured 21%-ish of investigation
// attempts that finish with nothing recorded at all (BACKLOG.md C11's own
// entry). 12s was NOT picked as a flat multiple of p99 (10x621ms≈6.2s):
// the same query's tail shows four real, non-retried single-attempt
// successes above p99 — a `list_repo_files` at 6.5s and, on ONE real
// cluster during one ~30-minute window, `describe_resource` calls at 22.1s
// and 28.4s. 12s sits comfortably above the first (the ordinary tail) and
// deliberately does NOT try to cover the second (a genuine, but rare and
// correlated-to-one-incident, cluster-side slowdown) — chasing that outlier
// would mean barely cutting the timeout at all and losing most of the
// benefit this fix exists to deliver. The accepted cost, stated plainly:
// under a real, sustained slow-cluster condition, a call that would have
// eventually succeeded in the 12-28s range now fails instead (rare —
// 4 of 1,473 successful calls, ~0.27%, all from one correlated window on
// one cluster in the measured sample) — CallToolWithRetry's retry still
// gives such a call a second chance if the slowdown was transient, and
// the read-only investigation loop treats a timed-out tool call as
// ordinary evidence-gathering friction, not a fatal error, so the
// investigation itself is not lost, only that one piece of evidence.
// 12s+resultGraceWindow(5s)=17s per attempt, 34s worst case with one retry
// — down from 35s/70s, a ~51% cut in both the median and worst-case cost of
// a hung call, while every genuinely-fast call (99%+ of them) is completely
// unaffected.
//
// A var, not a const, ONLY so tools_retry_test.go can shrink it to make a
// timeout happen in milliseconds instead of 12s — mirrors the
// internal/mcp.Store "now func() time.Time" convention of trading a tiny
// bit of production immutability for a test that doesn't need a real clock.
// Nothing in this package's runtime code ever reassigns it.
var toolCallTimeout = 12 * time.Second

// resultGraceWindow is CallToolWithRetry's fix for the exact failure
// BUGS.md 96 recorded (BACKLOG.md C5): once a call's toolCallTimeout has
// elapsed with no result, wait this much LONGER on the very same
// correlation id before giving up for good. This costs nothing extra on
// the wire — no new ToolRequest is sent, it only keeps listening a bit
// longer for one already in flight — so it is applied unconditionally, on
// every attempt, never gated by the retry budget below. See
// callToolAttemptWithGrace's doc comment for the full mechanism. A var for
// the same test-speed reason as toolCallTimeout.
var resultGraceWindow = 5 * time.Second

// maxToolRetriesPerClusterWindow and toolRetryBudgetWindow bound
// CallToolWithRetry's one-retry-per-call behavior at the fleet level: how
// many total retries any calls against ONE cluster may spend within a
// rolling window, regardless of how many different investigations (or
// tool-loop iterations within one investigation) are hitting that cluster
// concurrently. See takeRetryBudget's doc comment for why this is scoped
// per CLUSTER rather than per investigation.
const (
	maxToolRetriesPerClusterWindow = 3
	toolRetryBudgetWindow          = 5 * time.Minute
)

// agentConn is the live, per-connection state the gateway keeps for exactly
// as long as one agent's tunnel connection is open. Its whole reason to
// exist is that CallTool, invoked from a different goroutine than the one
// running this connection's read loop (serveClientMessages), needs a way to
// (a) write a ToolRequest to this specific agent's connection without
// racing serveClientMessages' own ack writes, and (b) find out when the
// matching ToolResult (or a disconnect) happens.
type agentConn struct {
	clusterID string

	// role is what this connection declared itself to be (PROJECT.md E11's
	// tunnel.Hello), or tunnel.RoleAll for a connection that declared
	// nothing — which is every agent built before E11. Immutable after
	// newAgentConn: a connection's role is decided by its first message and
	// never changes, so nothing has to guard it.
	role string

	// conn is the underlying transport serveClientMessages' scanner reads
	// from. Its only use in this file is close(), below — the mechanism
	// Gateway.Disconnect uses to forcibly sever an already-open connection
	// (e.g. one whose cluster was just decommissioned), as opposed to the
	// gateway merely refusing a future reconnect (handleConn/
	// lookupClusterBySerial's clusterState check, in server.go).
	conn net.Conn

	// writeMu guards every write to enc: serveClientMessages' ack replies
	// and CallTool's ToolRequest sends now both write to the same
	// connection, from different goroutines. This is the gateway-side
	// mirror of the single-writer discipline internal/agent/client.go's
	// runTunnelSession doc comment calls out on the agent side — before
	// this file, handleConn's loop was the connection's only writer, so no
	// such guard was needed; CallTool is what makes the write side
	// concurrent for the first time.
	writeMu sync.Mutex
	enc     *json.Encoder

	pendingMu sync.Mutex
	pending   map[string]chan tunnel.ToolResult

	closed   chan struct{}
	closeOne sync.Once

	// connectedAt is when this tunnel session opened. Immutable after
	// newAgentConn. See ConnectedSince for why anything needs it.
	connectedAt time.Time
}

func newAgentConn(clusterID, role string, conn net.Conn, enc *json.Encoder) *agentConn {
	return &agentConn{
		clusterID:   clusterID,
		role:        role,
		conn:        conn,
		enc:         enc,
		pending:     make(map[string]chan tunnel.ToolResult),
		closed:      make(chan struct{}),
		connectedAt: time.Now(),
	}
}

// close closes the underlying net.Conn, which is what actually makes
// serveClientMessages' scanner.Scan() read loop return (with a read error)
// and run its deferred cleanup (unregisterConn + markClosed) — the same
// path an ordinary network-level disconnect already takes, just triggered
// here instead of waiting for one. Safe to call even if the peer has
// already closed its end, or if something else closes conn concurrently
// (e.g. handleConn's own deferred conn.Close()): net.Conn.Close() tolerates
// being called more than once, just returning an error on the later calls
// that nothing here needs to check.
func (a *agentConn) close() {
	_ = a.conn.Close()
}

func (a *agentConn) send(msg tunnel.ServerMessage) error {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	return a.enc.Encode(msg)
}

// markClosed unblocks every CallTool currently waiting on this connection.
// Called exactly once (closeOne), from serveClientMessages' deferred
// cleanup, whenever the read loop returns for any reason — a clean
// disconnect, a read error, or a malformed/unrecognized message that
// deliberately closes the connection. Without this, a CallTool in flight
// when the agent drops would just sit until toolCallTimeout instead of
// failing immediately with a clear "disconnected" error.
func (a *agentConn) markClosed() {
	a.closeOne.Do(func() { close(a.closed) })
}

// registerPending creates and registers the channel a ToolResult for
// correlationID will be delivered on. Split out from what used to be
// awaitResult's own first step, and MUST be called — by the caller,
// directly — before the matching ToolRequest is ever sent. See CallTool's
// own doc comment for why this ordering is load-bearing, not stylistic: a
// version of this file once registered the channel only after sending,
// inside awaitResult, which left a real window for a fast enough response to
// arrive and be dropped before anything was listening for it.
func (a *agentConn) registerPending(correlationID string) chan tunnel.ToolResult {
	ch := make(chan tunnel.ToolResult, 1)
	a.pendingMu.Lock()
	a.pending[correlationID] = ch
	a.pendingMu.Unlock()
	return ch
}

// unregisterPending removes correlationID's entry, if still present. Safe to
// call even if it was already removed (e.g. by a concurrent deliver that
// this same call is racing to observe) — deleting a missing map key is a
// no-op in Go. Callers must call this exactly once, via defer, right after
// registerPending — see waitForResult's own doc comment for why a late or
// duplicate ToolResult must find no stale channel afterward.
func (a *agentConn) unregisterPending(correlationID string) {
	a.pendingMu.Lock()
	delete(a.pending, correlationID)
	a.pendingMu.Unlock()
}

// waitForResult blocks on the channel registerPending returned until a
// matching ToolResult is delivered (deliver, below), the connection closes,
// or ctx is done. The caller (CallTool) is responsible for having already
// registered ch via registerPending, sent the matching ToolRequest, and
// deferred unregisterPending — this function only waits.
//
// Both failure branches wrap ErrIndeterminate (BACKLOG.md C8): by the time
// this is called, registerPending + send have already happened (CallTool's
// own doc comment — "register before send"), so a disconnect or a
// cancelled/expired ctx here means the ToolRequest may already have reached
// the agent and been fully applied; only the ACK is missing. That is a
// materially different fact from an explicit ToolResult.Error (the request
// definitely failed) or a send failure (the request never left the hub at
// all) — neither of which comes through this function. Every existing
// caller that only checked `err != nil` keeps working unchanged;
// errors.Is(err, ErrIndeterminate) is additive, not a replacement for the
// existing message.
func (a *agentConn) waitForResult(ctx context.Context, ch chan tunnel.ToolResult) (tunnel.ToolResult, error) {
	select {
	case res := <-ch:
		return res, nil
	case <-a.closed:
		return tunnel.ToolResult{}, fmt.Errorf("cluster %s disconnected while awaiting a tool result: %w", a.clusterID, ErrIndeterminate)
	case <-ctx.Done():
		return tunnel.ToolResult{}, fmt.Errorf("%w: %w", ctx.Err(), ErrIndeterminate)
	}
}

// ErrIndeterminate marks a CallTool/CallToolWithGrace/CallToolWithRetry
// failure whose disposition is genuinely unknown, as opposed to a definite
// one. "Definite" covers exactly two shapes: the tool itself reporting a
// result with a non-empty Error (the agent ran it and it failed), and a
// failure to ever get the ToolRequest onto the wire (cluster not connected,
// or the encode/write itself erroring) — in both, nothing happened on the
// cluster side that this hub doesn't already know about. Every OTHER
// failure this package returns — the connection dropping mid-wait, ctx
// being cancelled or its deadline expiring, the grace window
// (callToolAttemptWithGrace) also finding nothing — wraps this sentinel,
// because in every one of those cases the ToolRequest was already sent and
// there is no way to know whether the agent received, ran, and even fully
// applied it before whatever cut the wait short.
//
// This has never mattered for the read-only, six-tool investigation loop
// CallToolWithRetry serves (internal/gateway's own file comment) — a
// dropped read can simply be re-asked, so nobody needed to distinguish
// "failed" from "unknown" there. It matters for a MUTATING call
// (internal/api/remediation_exec.go's executeApprovedPlan): BUGS.md 104
// found a real tunnel drop mid-patch recorded as outcome:"failed" in
// Postgres while the patch had, in fact, already applied on the cluster.
// Check with errors.Is(err, ErrIndeterminate); every existing caller that
// only checks `err != nil` is completely unaffected, since %w preserves the
// original human-readable message underneath.
var ErrIndeterminate = errors.New("tool result indeterminate: the request may have reached the agent and been applied, but no result was received to confirm or deny it")

// deliver routes an incoming ToolResult to its awaiting CallTool caller, if
// one is still waiting, and reports whether it found one — server.go's
// serveClientMessages logs a miss and continues rather than closing the
// connection over it; deliver itself stays silent so it's usable from a
// test without a logger. A ToolResult whose CorrelationID matches nothing
// is not, on its own, a protocol error: the caller may have already timed
// out and moved on, or the agent may have sent a stray/duplicate. It is
// exactly the failure signature a real bug once produced for a DIFFERENT
// reason (a genuinely in-flight caller, not yet timed out, whose response
// arrived before it had registered — see CallTool's "register before send"
// doc comment) — which is why this is logged now rather than treated as
// always-benign. The buffered, non-blocking send means a caller that's
// already given up (waitForResult returned via ctx.Done()/closed, freeing
// nothing to read it) can never make this method block.
func (a *agentConn) deliver(res tunnel.ToolResult) (delivered bool) {
	a.pendingMu.Lock()
	ch, ok := a.pending[res.CorrelationID]
	a.pendingMu.Unlock()
	if !ok {
		return false
	}
	select {
	case ch <- res:
	default:
	}
	return true
}

// newCorrelationID generates the id ToolRequest/ToolResult pairs are
// matched on. Deliberately not a domain.NewID prefixed ULID: those
// identify persisted domain entities (lld/05-data-model.md §2), and this id
// is never persisted anywhere — it lives only as long as one CallTool
// invocation's in-memory wait.
func newCorrelationID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate correlation id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// IsConnected reports whether clusterID currently has a live tunnel
// connection registered. A cheap, read-only check callers can use to fail
// fast — internal/api/analyze.go's investigation loop uses this before
// starting a bounded, multi-turn tool-calling investigation against a
// cluster with no agent connected, rather than discovering the same fact
// only after CallTool's first attempt (and, worse, burning LLM turns on a
// tool-calling loop that has no chance of gathering any real evidence).
// This deliberately does not (and cannot) protect against a cluster that
// disconnects moments after this check returns true — CallTool's own
// per-call handling of that race is unchanged; this is a preflight
// optimization, not a replacement for it.
func (g *Gateway) IsConnected(clusterID string) bool {
	return g.IsConnectedForRole(clusterID, tunnel.RoleInvestigate)
}

// IsConnectedForRole is IsConnected narrowed to one connection role
// (PROJECT.md E11). IsConnected itself asks about RoleInvestigate, because
// every existing caller is asking the same question it always was — "can I
// gather evidence from this cluster" — and evidence gathering is the
// investigation connection's job. A cluster with only a remediation
// connection open is genuinely not ready for an investigation, and saying
// "connected" about it would start a tool-calling loop that could not read
// anything.
//
// Role resolution is getConn's, so a single pre-E11 RoleAll connection
// answers true for every role, exactly as it did before there were roles.
func (g *Gateway) IsConnectedForRole(clusterID, role string) bool {
	_, ok := g.getConn(clusterID, role)
	return ok
}

// ConnectedSince reports when clusterID's current investigation tunnel
// session opened, and false when it has none.
//
// "No finding arrived for the last N minutes" is evidence only if the agent
// that would have sent one was connected for all of those minutes. The hub
// keeps no connection history, and a hub restart or a tunnel drop silently
// empties the finding stream, so a caller judging quiet measures it from
// whichever is later: the last finding, or this.
func (g *Gateway) ConnectedSince(clusterID string) (time.Time, bool) {
	ac, ok := g.getConn(clusterID, tunnel.RoleInvestigate)
	if !ok {
		return time.Time{}, false
	}
	return ac.connectedAt, true
}

// Disconnect forcibly severs clusterID's live tunnel connection, if it has
// one, by closing the underlying net.Conn — which makes
// serveClientMessages' read loop return and run its usual deferred cleanup
// (unregisterConn + markClosed), exactly as if the agent had dropped the
// connection itself. internal/api's handleDecommissionCluster calls this
// right after committing a cluster's state to Archived: without it, a
// tunnel that happened to be open at the moment of decommission would keep
// running (heartbeats, etc.) until it eventually dropped on its own —
// handleConn/lookupClusterBySerial's clusterState check (server.go) only
// ever refuses a *new* connection attempt, it has no effect on one already
// in progress. Reports whether a live connection was actually found and
// closed; false (with no error — there's nothing to report as failed) is
// the ordinary case of decommissioning a cluster that had no open tunnel
// at the time.
// Now severs EVERY connection the cluster has, not just one: since
// PROJECT.md E11 a cluster may hold an investigate connection and a
// remediate connection at the same time, and decommissioning a cluster while
// leaving its write connection live would be the worst possible half of this
// operation.
func (g *Gateway) Disconnect(clusterID string) bool {
	// Snapshotted once, deliberately: closing a connection makes its own
	// read loop return and unregister it, so asking the registry again
	// afterwards would race that cleanup and report "nothing was connected"
	// about connections this call had just severed.
	open := g.connsFor(clusterID)
	for _, ac := range open {
		ac.close()
	}
	return len(open) > 0
}

// connKey is the gateway's connection-registry key — PROJECT.md E11.
//
// It used to be the cluster id alone, which is precisely what made two
// separate ServiceAccounts on two separate tunnel connections unbuildable:
// a second connection from the same cluster did not become a second entry,
// it REPLACED the first. The remediation agent connecting would silently
// evict the investigation agent, and vice versa, with nothing but a
// reconnect loop to show for it.
type connKey struct {
	clusterID string
	role      string
}

// notConnectedError is the one place "this cluster cannot serve this call"
// is worded, so the two dispatch paths cannot drift.
//
// The remediation case gets its own sentence deliberately. "Cluster X is not
// connected" is actively misleading when the cluster IS connected and
// reporting findings quite happily, and simply has no remediation agent —
// which after PROJECT.md E11 is the normal, correct state of every cluster
// that has not opted into writes. An operator reading it needs to know that
// enabling remediation is the action, not debugging a tunnel.
func notConnectedError(clusterID, role string) error {
	if role == tunnel.RoleRemediate {
		return fmt.Errorf("gateway: cluster %s has no remediation agent connected — remediation is opt-in per cluster (the argus-agent chart's remediate.enabled), and this cluster's investigation agent is deliberately incapable of writing", clusterID)
	}
	return fmt.Errorf("gateway: cluster %s is not connected", clusterID)
}

// getConn resolves one cluster's connection for a given role, with exactly
// one fallback: a connection that declared tunnel.RoleAll serves every role.
//
// That fallback is what makes this whole change invisible to an agent in the
// field. A pre-E11 agent sends no tunnel.Hello, registers as RoleAll, and
// answers a lookup for RoleInvestigate and for RoleRemediate alike — which
// is the truth about it, since it really is one process holding the union of
// both identities.
//
// The fallback is deliberately ONE-WAY. A RoleInvestigate connection never
// answers a lookup for RoleRemediate: that is the entire security property
// E11 exists to establish, and a "close enough" fallback in that direction
// would hand a write action to the read-only agent, which would then fail
// against RBAC — correctly, but as a confusing 403 at execution time instead
// of a clear "this cluster has no remediation agent connected".
func (g *Gateway) getConn(clusterID, role string) (*agentConn, bool) {
	g.connsMu.Lock()
	defer g.connsMu.Unlock()
	if ac, ok := g.conns[connKey{clusterID, role}]; ok {
		return ac, true
	}
	if role != tunnel.RoleAll {
		if ac, ok := g.conns[connKey{clusterID, tunnel.RoleAll}]; ok {
			return ac, true
		}
	}
	return nil, false
}

// connsFor returns every live connection a cluster has, in no particular
// order. Used by the operations that are about the CLUSTER rather than about
// one role — severing it, draining it at shutdown.
func (g *Gateway) connsFor(clusterID string) []*agentConn {
	g.connsMu.Lock()
	defer g.connsMu.Unlock()
	var out []*agentConn
	for k, ac := range g.conns {
		if k.clusterID == clusterID {
			out = append(out, ac)
		}
	}
	return out
}

func (g *Gateway) registerConn(clusterID string, ac *agentConn) {
	// Exactly one Inc per real connection lifetime — see unregisterConn's own
	// comment on why its matching Dec is unconditional too, regardless of
	// the map-replacement guard below (that guard is about which entry
	// CallTool's lookup sees, not about how many connections are actually
	// open). In-memory and exact: this gauge never needs a DB query and can
	// never disagree with reality the way a periodic collector's last-known
	// value can.
	metrics.TunnelConnectionsActive.Inc()
	g.connsMu.Lock()
	defer g.connsMu.Unlock()
	g.conns[connKey{clusterID, ac.role}] = ac
}

// resolveHelloRole maps a declared role string onto one this hub knows.
//
// An unrecognised value is served as tunnel.RoleAll rather than refused —
// see tunnel.Hello's own doc comment — but said out loud, because the
// likeliest cause is an agent newer than this hub, and a fleet mid-upgrade
// is exactly when someone needs to see that.
func resolveHelloRole(clusterID, declared string) string {
	switch declared {
	case tunnel.RoleInvestigate, tunnel.RoleRemediate, tunnel.RoleAll:
		return declared
	default:
		logger.Warn("agent declared a tunnel connection role this hub does not recognise; serving it as a general-purpose connection",
			logging.ClusterID(clusterID), slog.String("declared_role", declared))
		return tunnel.RoleAll
	}
}

// rekeyConn moves an already-registered connection from the tunnel.RoleAll
// key it registered under to the role its tunnel.Hello declared
// (PROJECT.md E11). A no-op when the declared role IS RoleAll, which is the
// pre-E11 shape and the overwhelmingly common one for now.
//
// Deliberately NOT an unregister followed by a register: those carry the
// active-connections gauge's Inc/Dec, and this is one connection changing
// its key, not one closing and another opening. Doing it as a pair would
// make the gauge dip to zero for a cluster that never disconnected.
//
// The delete is guarded on the entry still being THIS connection, for the
// same fast-reconnect reason unregisterConn's own delete is: a newer
// connection for the same cluster may already have taken the RoleAll key,
// and this one must not evict it on the way past.
func (g *Gateway) rekeyConn(clusterID string, ac *agentConn, role string) {
	g.connsMu.Lock()
	defer g.connsMu.Unlock()
	if ac.role == role {
		return
	}
	oldKey := connKey{clusterID, ac.role}
	if g.conns[oldKey] == ac {
		delete(g.conns, oldKey)
	}
	newKey := connKey{clusterID, role}
	// The investigate and remediate identities for one cluster deliberately
	// share a single hub-issued mTLS client certificate (E11's design — see
	// deploy/helm/argus-agent/templates/identity-secret.yaml's own comment),
	// told apart only by which role a tunnel.Hello self-declares, not by
	// separate credentials. So anything already holding that certificate —
	// a compromised investigate pod, which per that same chart legitimately
	// has get/update RBAC on the shared identity Secret — can open a second
	// connection declaring itself "remediate" and land here, silently
	// evicting whatever real connection this cluster's remediate role was
	// already being served by. This can't refuse that outright (the same
	// path is also how an entirely ordinary restart/redeploy of that role's
	// pod re-establishes its connection), but a slot that already held a
	// DIFFERENT live connection is a genuinely rare event either way — worth
	// an operator-visible signal rather than a silent takeover. Found in a
	// whole-repo review pass (2026-09-27).
	if evicted, ok := g.conns[newKey]; ok && evicted != ac {
		logger.Warn("tunnel connection role slot taken over by a different connection — the previous connection serving this cluster/role is now unreachable",
			logging.ClusterID(clusterID), slog.String("role", role))
	}
	ac.role = role
	g.conns[newKey] = ac
	logger.Info("tunnel connection role declared",
		logging.ClusterID(clusterID), slog.String("role", role))
}

// unregisterConn removes clusterID's registry entry only if it still points
// at ac. This matters on a fast reconnect: if a new connection for the same
// cluster has already registered its own agentConn by the time the old
// connection's cleanup runs, the old cleanup must not delete the new
// connection's live entry out from under it.
func (g *Gateway) unregisterConn(clusterID string, ac *agentConn) {
	// Unconditional, unlike the map delete below — see this function's own
	// doc comment: a fast reconnect can mean THIS ac was already replaced in
	// the map by a newer one, but ac's own connection still really existed
	// and really just closed, so it still owes exactly one Dec matching
	// registerConn's Inc.
	metrics.TunnelConnectionsActive.Dec()
	g.connsMu.Lock()
	defer g.connsMu.Unlock()
	key := connKey{clusterID, ac.role}
	if g.conns[key] == ac {
		delete(g.conns, key)
	}
}

// ToolError is a tool call the agent answered with a failure of its own —
// as opposed to the call never arriving or never being answered. Message is
// the agent's reason exactly as it sent it, which the agent has already passed
// through capture-time redaction (ToolExecutor.Execute), so a caller acting
// for a person may show it; Error keeps the wording every log line and
// existing caller already expects.
type ToolError struct {
	ClusterID string
	Tool      string
	Message   string
}

func (e *ToolError) Error() string {
	return fmt.Sprintf("gateway: cluster %s: tool %q failed: %s", e.ClusterID, e.Tool, e.Message)
}

// CallTool sends a ToolRequest for tool/args to clusterID's live tunnel
// connection and blocks until the matching ToolResult arrives, the
// connection drops, ctx is cancelled, or toolCallTimeout elapses —
// whichever comes first. Returns the tool's raw Data on success; a non-nil
// error covers every other case (cluster not connected, send failure,
// disconnect mid-call, timeout, or the tool itself reporting
// ToolResult.Error) uniformly — callers of this function get one thing to
// check, not several different failure shapes to distinguish.
//
// This is the exact signature a later task's LLM investigation loop is
// expected to call once per evidence-gathering hop (ADR-2,
// lld/07-analysis-contracts.md §2) — pinning it now is this task's point.
//
// REGISTER BEFORE SEND, deliberately, not the other way round: this closes a
// real race found live (not in a test — see WORKLOG.md §114), where two or more
// investigations against the SAME cluster overlap and call CallTool
// concurrently. The old code sent the ToolRequest first and only registered
// the pending channel afterward, inside what awaitResult used to do as its
// first step. Under concurrent callers contending on writeMu/pendingMu, Go's
// scheduler can delay a goroutine between its send returning and it reaching
// the registration step — long enough, in practice, for a fast agent's
// ToolResult to round-trip back and be read by serveClientMessages BEFORE
// anything was listening for it. deliver's map lookup then finds nothing,
// silently drops a perfectly good result, and the caller times out 30s
// later for a tool call the agent had already answered correctly. Since the
// channel is now registered before the request is even sent, there is no
// window during which a response can arrive unheard.
func (g *Gateway) CallTool(ctx context.Context, clusterID, tool string, args json.RawMessage) (json.RawMessage, error) {
	// PROJECT.md T24's tool-call latency/error metric. The outcome is set
	// at each return branch rather than inferred from the error afterwards:
	// "not connected", "the agent never answered" and "the tool itself
	// failed" are three different operational stories, and only the code
	// that took the branch knows which one it is for certain — recovering
	// that from an error string later is exactly the kind of guess that
	// makes a dashboard lie. The pessimistic default means a branch added
	// later without a thought about metrics is counted as an error rather
	// than as a success.
	start := time.Now()
	outcome := metrics.ToolOutcomeError
	defer func() { observeToolCall(ctx, clusterID, tool, outcome, start) }()

	// PROJECT.md E11: which connection serves this tool is decided by the
	// tool name, through the one classification both sides import
	// (tunnel.RoleForTool) — never by anything the caller passes in. A write
	// action can only ever be sent to a RoleRemediate connection; every
	// read-only tool goes to the RoleInvestigate one. On a cluster still
	// running a single pre-E11 agent, both resolve to its RoleAll connection
	// and nothing about this call changes.
	role := tunnel.RoleForTool(tool)
	ac, ok := g.getConn(clusterID, role)
	if !ok {
		outcome = metrics.ToolOutcomeNotConnected
		return nil, notConnectedError(clusterID, role)
	}

	correlationID, err := newCorrelationID()
	if err != nil {
		return nil, fmt.Errorf("gateway: %w", err)
	}

	ch := ac.registerPending(correlationID)
	defer ac.unregisterPending(correlationID)

	if err := ac.send(tunnel.ServerMessage{ToolRequest: &tunnel.ToolRequest{
		CorrelationID: correlationID,
		Tool:          tool,
		Args:          args,
	}}); err != nil {
		return nil, fmt.Errorf("gateway: send tool request to cluster %s: %w", clusterID, err)
	}

	callCtx, cancel := context.WithTimeout(ctx, toolCallTimeout)
	defer cancel()

	result, err := ac.waitForResult(callCtx, ch)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			outcome = metrics.ToolOutcomeTimeout
		}
		return nil, fmt.Errorf("gateway: tool call to cluster %s (tool=%s): %w", clusterID, tool, err)
	}
	if result.Error != "" {
		return nil, &ToolError{ClusterID: clusterID, Tool: tool, Message: result.Error}
	}
	outcome = metrics.ToolOutcomeSuccess
	return result.Data, nil
}

// observeToolCall is the one place a dispatched tunnel tool call is both
// measured (PROJECT.md T24) and logged (T22/T23).
//
// Both, together, in a deferred call at the top of each dispatch function,
// because an outcome recorded in one place and logged in another is how a
// metric and a log line come to disagree — and because a branch added
// later gets both for free rather than one of them. DEBUG, since a single
// investigation makes four or five of these: the metric is what an
// operator alerts on, and the log line is what they turn up to
// reconstruct one specific investigation by its correlation id.
func observeToolCall(ctx context.Context, clusterID, tool, outcome string, start time.Time) {
	elapsed := time.Since(start)
	metrics.ObserveToolCall(tool, outcome, elapsed)
	logger.DebugContext(ctx, "tunnel tool call",
		logging.ClusterID(clusterID), slog.String("tool", tool),
		slog.String("outcome", outcome),
		slog.Int64("duration_ms", elapsed.Milliseconds()))
}

// clusterRetryWindow is takeRetryBudget's per-cluster counter: how many
// CallToolWithRetry retries have been spent against this cluster since
// windowStart. Reset (not incremented past) once toolRetryBudgetWindow has
// elapsed since windowStart — a fixed-window counter, not a sliding one:
// simpler to reason about and to test, and "at most
// maxToolRetriesPerClusterWindow retries per rolling ~5 minutes" doesn't
// need sliding-window precision to do its job, which is purely "a
// genuinely dead agent must not let retries pile up," not rate accounting.
type clusterRetryWindow struct {
	windowStart time.Time
	used        int
}

// takeRetryBudget reports whether clusterID may spend one more retry right
// now, consuming it if so. Scoped per CLUSTER, deliberately, not per
// investigation or per incident: CallToolWithRetry's callers (the read-only
// investigation loop, wired in both the api and cli backends) have no
// natural shared object to hang a per-investigation budget on that would
// reach across the cli backend's independent, per-HTTP-request MCP tool
// calls without a much larger plumbing change through internal/mcp (which
// this fix deliberately does not touch — see this package's own file
// comment on staying decoupled from the tunnel layer's callers). A
// per-cluster cap is also arguably the SAFER bound for the actual failure
// this exists to prevent: "a real prolonged outage on one cluster" is a
// per-cluster event, and capping total retry volume against that one
// cluster — across however many concurrent investigations happen to be
// hitting it — is exactly what stops them from piling up retries on top of
// each other during that outage, which a purely per-investigation cap
// would not (each investigation would still think it has its own fresh
// allowance). The cost is the reverse case: two unrelated, healthy-enough
// investigations against the same cluster that each hit one unlucky blip
// could, in a rare worst case, exhaust each other's retry allowance. That
// is judged an acceptable trade — a missed retry still falls back to
// CallTool's ordinary single-attempt failure, exactly today's behavior,
// never a hard error a caller couldn't already get.
func (g *Gateway) takeRetryBudget(clusterID string) bool {
	g.retryMu.Lock()
	defer g.retryMu.Unlock()

	now := g.now()
	w, ok := g.retryBudgets[clusterID]
	if !ok || now.Sub(w.windowStart) >= toolRetryBudgetWindow {
		w = &clusterRetryWindow{windowStart: now}
		g.retryBudgets[clusterID] = w
	}
	if w.used >= maxToolRetriesPerClusterWindow {
		return false
	}
	w.used++
	return true
}

// callToolAttemptWithGrace is CallTool's send/wait logic, duplicated here
// (not shared via refactor) so CallTool's own behavior — and every
// existing caller of it, including internal/api/remediation_exec.go's
// mutating plan submissions and rollback.go's compensating actions, which
// this fix deliberately leaves untouched — stays byte-for-byte what it was
// before this file existed. The one addition is the grace window: when
// toolCallTimeout elapses with nothing delivered yet, this keeps listening
// on the SAME correlation id (registerPending's channel, not yet
// unregistered) for up to resultGraceWindow longer before finally giving
// up. That is the direct mechanism for BUGS.md 96 — the agent had already
// computed and sent the correct answer, and only a stalled transport
// delayed its arrival past the hub's own deadline; deliver() (server.go)
// can still find and fill this channel during the grace window exactly as
// it would have during the original wait.
//
// Returns the same (data, error) shape CallTool does, plus a third value:
// whether the failure is the specific "we waited and nothing came, even
// after grace" kind CallToolWithRetry is willing to spend a retry on, as
// opposed to a failure (not connected, ctx already done before the call
// even started, or the tool itself reporting an error) that retrying could
// not possibly fix.
func (g *Gateway) callToolAttemptWithGrace(ctx context.Context, clusterID, tool string, args json.RawMessage) (json.RawMessage, error, bool) {
	// One ATTEMPT is one observation, deliberately: CallToolWithRetry can
	// run this twice, and both attempts really did go on the wire and
	// really did cost the investigation time. Counting the retry as part of
	// one long call would hide the retry rate, which is the thing worth
	// alerting on. See CallTool for why the outcome is set per branch.
	start := time.Now()
	outcome := metrics.ToolOutcomeError
	defer func() { observeToolCall(ctx, clusterID, tool, outcome, start) }()

	// Bail before spending a request at all if the caller has already given
	// up — sending would only add load for an answer nobody will read, and
	// there is nothing to gain from a grace wait when the calling
	// investigation itself is already done.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("gateway: tool call to cluster %s (tool=%s): %w", clusterID, tool, err), false
	}

	// Same role routing as CallTool — see its comment.
	role := tunnel.RoleForTool(tool)
	ac, ok := g.getConn(clusterID, role)
	if !ok {
		outcome = metrics.ToolOutcomeNotConnected
		return nil, notConnectedError(clusterID, role), false
	}

	correlationID, err := newCorrelationID()
	if err != nil {
		return nil, fmt.Errorf("gateway: %w", err), false
	}

	ch := ac.registerPending(correlationID)
	defer ac.unregisterPending(correlationID)

	if err := ac.send(tunnel.ServerMessage{ToolRequest: &tunnel.ToolRequest{
		CorrelationID: correlationID,
		Tool:          tool,
		Args:          args,
	}}); err != nil {
		return nil, fmt.Errorf("gateway: send tool request to cluster %s: %w", clusterID, err), false
	}

	callCtx, cancel := context.WithTimeout(ctx, toolCallTimeout)
	defer cancel()

	result, waitErr := ac.waitForResult(callCtx, ch)
	if waitErr != nil {
		if !errors.Is(waitErr, context.DeadlineExceeded) {
			// A clean disconnect, or ctx itself (not merely the derived
			// toolCallTimeout) ending — neither is "the answer might still
			// be coming," so there is nothing a grace wait would catch.
			return nil, fmt.Errorf("gateway: tool call to cluster %s (tool=%s): %w", clusterID, tool, waitErr), false
		}
		// toolCallTimeout elapsed with nothing delivered. unregisterPending
		// (deferred above) has not run yet, so ch is still exactly what
		// deliver() looks up by correlationID — keep waiting on it a bit
		// longer rather than giving up the instant the original deadline
		// passes.
		select {
		case result = <-ch:
			// A correct, on-time-computed result that only the transport
			// delayed past toolCallTimeout — fall through to the ordinary
			// success/failure handling below instead of discarding it.
		case <-time.After(resultGraceWindow):
			outcome = metrics.ToolOutcomeTimeout
			return nil, fmt.Errorf("gateway: tool call to cluster %s (tool=%s): %w", clusterID, tool, waitErr), true
		case <-ac.closed:
			return nil, fmt.Errorf("gateway: tool call to cluster %s (tool=%s): cluster %s disconnected while awaiting a tool result: %w", clusterID, tool, clusterID, ErrIndeterminate), true
		}
	}
	if result.Error != "" {
		return nil, &ToolError{ClusterID: clusterID, Tool: tool, Message: result.Error}, false
	}
	outcome = metrics.ToolOutcomeSuccess
	return result.Data, nil, false
}

// CallToolWithRetry is CallTool plus two bounded resilience behaviors added
// for BACKLOG.md C5 / BUGS.md 96 (a transient tunnel stall delayed an
// agent's correct, on-time answer past the hub's 30s toolCallTimeout, which
// discarded it outright and burned the whole investigation's time budget
// for zero usable evidence):
//
//  1. Late-result acceptance (callToolAttemptWithGrace, above) — always
//     applied, on every attempt, and never gated by the retry budget: it
//     sends no new request, so it cannot itself cause a pile-up.
//  2. One bounded retry — a single fresh ToolRequest (a new correlation id;
//     newCorrelationID is called again inside the second
//     callToolAttemptWithGrace) — spent only if takeRetryBudget grants it,
//     which caps total retries per CLUSTER within toolRetryBudgetWindow
//     regardless of how many calls or investigations are asking. A
//     genuinely dead/unresponsive agent exhausts that budget quickly and
//     every call past that point fails exactly as fast as CallTool always
//     did — this never turns a dead agent into an indefinite retry loop.
//
// This is a NEW method, not a change to CallTool, specifically so every
// existing CallTool caller — dry-run attestation, execution windows,
// GitOps-ownership checks used from the approval/merge paths — keeps
// CallTool's original single-attempt, no-grace semantics completely
// unchanged. CallToolWithRetry is wired ONLY into the read-only, six-tool
// investigation loop's tool callback (both backends: internal/api/analyze.go
// and internal/autoanalyze/autoanalyze.go for the api backend,
// cmd/hub/main.go's MCP ToolFunc closure for the cli backend) — argus-context's
// non-negotiable #1 is what makes both behaviors above actually safe there:
// every one of those six tools
// (get_events/get_logs/describe_resource/list_resources/get_owner_chain/
// get_gitops_ownership) is read-only, so re-running one on retry, or
// accepting whichever of two runs' results arrives first, can never
// duplicate or corrupt a side effect — there isn't one to duplicate.
//
// remediation execution's mutating calls (internal/api/remediation_exec.go's
// executeApprovedPlan, rollback.go's compensating actions) use
// CallToolWithGrace, below, instead — the grace half of this fix, minus the
// retry half a MUTATION cannot safely take.
//
// BACKLOG.md C11's second half — making the retry budget aware of the
// INVESTIGATION's remaining time, not just this method's own window — is
// deliberately NOT a new parameter here. ctx already carries that
// information once a caller derives it from the investigation's own
// deadline rather than a fresh per-call timeout: callToolAttemptWithGrace's
// context.WithTimeout(ctx, toolCallTimeout) takes whichever of the two
// deadlines is sooner, so an investigation with little time left
// automatically SHORTENS every subsequent attempt's wait, and
// callToolAttemptWithGrace's leading ctx.Err() check SKIPS the retry
// outright once ctx's own deadline has passed — proven by
// tools_retry_outer_context_test.go's
// TestCallToolWithRetry_TooShortOuterDeadlineDefeatsRetry (that test guards
// the failure mode of an outer deadline sized too SMALL for even one
// attempt; the identical composition is what makes an investigation-sized
// deadline correctly bound this method as it runs low, from the other
// direction). Both real callers of this method now do exactly that:
// internal/api/analyze.go's workCtx (manual/api-backend investigations) and,
// since this same fix, internal/autoanalyze/autoanalyze.go's toolCtx
// (unattended investigations) — see either call site's own comment. The
// cli backend (cmd/hub/main.go's MCP ToolFunc closure) is a stated,
// deliberate exception: its ctx is the incoming HTTP request context of one
// MCP tool-call from an EXTERNAL coding-agent CLI subprocess this repo does
// not own (cmd/cli-runner spawns it via exec.CommandContext, bound to ITS
// OWN process deadline) — there is no in-process Go context spanning that
// whole investigation on the hub side to derive a shrinking deadline from,
// and mcp.Grant.ExpiresAt is a flat token-lifetime TTL (mcp.DefaultTokenTTL,
// 15 minutes), not a per-investigation remaining-time signal, so deriving a
// ctx from it would not actually reflect how much investigation time is
// left. Threading real awareness through would need a cross-process
// protocol change (the external CLI's own MCP client would have to set a
// shrinking per-request deadline), which is out of scope here — recorded as
// an open gap, not silently assumed fixed.
func (g *Gateway) CallToolWithRetry(ctx context.Context, clusterID, tool string, args json.RawMessage) (json.RawMessage, error) {
	data, err, timedOut := g.callToolAttemptWithGrace(ctx, clusterID, tool, args)
	if err == nil || !timedOut {
		return data, err
	}
	if !g.takeRetryBudget(clusterID) {
		return data, err
	}
	data, err, _ = g.callToolAttemptWithGrace(ctx, clusterID, tool, args)
	return data, err
}

// CallToolWithGrace is CallTool plus ONLY the late-result acceptance half of
// CallToolWithRetry's fix — never the retry half. BACKLOG.md C8 (BUGS.md
// 104): a mutating call (scale_deployment/restart_pod/patch_resource_limits/
// revert_container_image) cannot safely take CallToolWithRetry's retry,
// because resending a mutation risks applying it twice (the exact reason C5
// kept every mutating call site on plain CallTool to begin with — see
// callToolAttemptWithGrace's own doc comment). But the grace half costs
// nothing extra on the wire — it sends no second request, it only keeps
// listening on the correlation id the first request already used — so there
// is no reason a mutating call site should not get it too: it is the cheap
// half of resilience a mutating call can take for free, catching exactly
// the case where the agent's real ToolResult was only delayed past
// toolCallTimeout by a slow transport, not lost outright.
//
// This alone does NOT close BUGS.md 104's own reproduction (a SIGKILL that
// takes the whole agent process down mid-call loses the ACK for good — no
// amount of listening longer on a connection that already reported
// disconnected will produce a result nobody is left alive to send). What it
// catches is the narrower, cheaper case: a transient stall on an otherwise
// healthy connection. For everything else, the caller must still treat an
// error wrapping ErrIndeterminate as "unknown," never "failed" — see
// internal/api/remediation_exec.go's resolveIndeterminateOutcome, which is
// what actually closes the gap this can't.
func (g *Gateway) CallToolWithGrace(ctx context.Context, clusterID, tool string, args json.RawMessage) (json.RawMessage, error) {
	data, err, _ := g.callToolAttemptWithGrace(ctx, clusterID, tool, args)
	return data, err
}
