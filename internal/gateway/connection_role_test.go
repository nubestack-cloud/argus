package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"argus/internal/tunnel"
)

// connection_role_test.go covers PROJECT.md E11's deliverable: the
// (clusterID, role)-keyed connection registry, and the routing that makes a
// read-only investigation connection structurally unable to be handed a
// write action.
//
// No database and no TLS: the registry is plain in-memory state, and
// exercising it directly is what lets these tests be about the ONE thing
// they are about.

func testGateway() *Gateway {
	return &Gateway{
		conns:        make(map[connKey]*agentConn),
		retryBudgets: make(map[string]*clusterRetryWindow),
	}
}

// registerRole registers a connection for clusterID under role, and returns
// it plus the pipe end a caller can read the hub's writes from.
func registerRole(t *testing.T, g *Gateway, clusterID, role string) *agentConn {
	t.Helper()
	hubSide, agentSide := net.Pipe()
	t.Cleanup(func() { hubSide.Close(); agentSide.Close() })
	// Drain, so a send in a test never blocks on an unread pipe.
	go func() { _, _ = io.Copy(io.Discard, agentSide) }()
	ac := newAgentConn(clusterID, role, hubSide, json.NewEncoder(hubSide))
	g.registerConn(clusterID, ac)
	return ac
}

// TestRegistryHoldsBothRolesForOneCluster is the defect this key change
// exists to fix. Keyed by cluster alone, a remediation agent connecting
// EVICTED the investigation agent — which is precisely why two
// ServiceAccounts on two connections could not be built.
func TestRegistryHoldsBothRolesForOneCluster(t *testing.T) {
	g := testGateway()
	inv := registerRole(t, g, "cl_1", tunnel.RoleInvestigate)
	rem := registerRole(t, g, "cl_1", tunnel.RoleRemediate)

	got, ok := g.getConn("cl_1", tunnel.RoleInvestigate)
	if !ok || got != inv {
		t.Error("the investigation connection was displaced by the remediation one registering — the old cluster-only key is back")
	}
	got, ok = g.getConn("cl_1", tunnel.RoleRemediate)
	if !ok || got != rem {
		t.Error("the remediation connection is not addressable")
	}
}

// TestInvestigationConnectionNeverServesAWriteAction is the security
// property, at the routing layer. It is deliberately ONE-WAY: a RoleAll
// connection serves everything, but a RoleInvestigate one must never be
// found by a lookup for RoleRemediate, no matter how convenient a fallback
// would be.
func TestInvestigationConnectionNeverServesAWriteAction(t *testing.T) {
	g := testGateway()
	registerRole(t, g, "cl_1", tunnel.RoleInvestigate)

	if _, ok := g.getConn("cl_1", tunnel.RoleRemediate); ok {
		t.Fatal("a lookup for the remediation role resolved to the investigation connection — the hub would dispatch a write action to the read-only agent")
	}
	if _, ok := g.getConn("cl_1", tunnel.RoleInvestigate); !ok {
		t.Fatal("the investigation connection is not addressable for its own role")
	}
}

// TestLegacyConnectionServesEveryRole is the backward-compatibility half. An
// agent built before roles sends no tunnel.Hello, registers as RoleAll, and
// must keep serving every request exactly as it did — a hub upgrade must not
// break a fleet whose agents are upgraded on their operator's schedule.
func TestLegacyConnectionServesEveryRole(t *testing.T) {
	g := testGateway()
	legacy := registerRole(t, g, "cl_legacy", tunnel.RoleAll)

	for _, role := range []string{tunnel.RoleInvestigate, tunnel.RoleRemediate, tunnel.RoleAll} {
		got, ok := g.getConn("cl_legacy", role)
		if !ok || got != legacy {
			t.Errorf("a pre-E11 RoleAll connection does not answer a lookup for %q — every cluster not yet upgraded would stop working", role)
		}
	}
}

// TestRoleForToolClassifiesEveryAgentTool pins the classification both sides
// import, and pins the DIRECTION of a mistake in it: a tool nobody
// classified routes to the investigation connection, where the cluster's own
// RBAC refuses it. The opposite default would hand an unclassified tool the
// write connection.
func TestRoleForToolClassifiesEveryAgentTool(t *testing.T) {
	writes := []string{
		"scale_deployment", "restart_pod", "patch_resource_limits",
		"revert_container_image", "patch_field", "annotate_resource",
		"label_resource", "delete_resource", "create_resource",
		"open_execution_window", "close_execution_window",
	}
	for _, tool := range writes {
		if got := tunnel.RoleForTool(tool); got != tunnel.RoleRemediate {
			t.Errorf("RoleForTool(%q) = %q, want %q — a mutating tool routed to the read-only connection", tool, got, tunnel.RoleRemediate)
		}
	}

	reads := []string{
		"get_events", "get_logs", "describe_resource", "list_resources",
		"get_owner_chain", "get_gitops_ownership", "get_resource_schema",
		"list_nodeport_allocations", "reevaluate_rule", "query_metrics",
		// dry_run_patch submits write verbs but is an INVESTIGATION tool the
		// model may call, restricted to dryRun=All by an admission policy
		// scoped to its own separate identity. Routing it to the remediation
		// connection would put a model-reachable tool on the connection the
		// model must never reach.
		"dry_run_patch",
	}
	for _, tool := range reads {
		if got := tunnel.RoleForTool(tool); got != tunnel.RoleInvestigate {
			t.Errorf("RoleForTool(%q) = %q, want %q", tool, got, tunnel.RoleInvestigate)
		}
	}

	if got := tunnel.RoleForTool("a_tool_nobody_classified"); got != tunnel.RoleInvestigate {
		t.Errorf("an unclassified tool routes to %q — forgetting to classify a new write tool must send it to the read-only connection, where RBAC refuses it, not to the write one", got)
	}
}

// TestDisconnectSeversEveryRole: decommissioning a cluster while leaving its
// WRITE connection live would be the worst possible half of this operation.
func TestDisconnectSeversEveryRole(t *testing.T) {
	g := testGateway()
	registerRole(t, g, "cl_1", tunnel.RoleInvestigate)
	registerRole(t, g, "cl_1", tunnel.RoleRemediate)
	registerRole(t, g, "cl_other", tunnel.RoleInvestigate)

	if !g.Disconnect("cl_1") {
		t.Fatal("Disconnect reported nothing to sever on a cluster with two live connections")
	}
	if len(g.connsFor("cl_other")) != 1 {
		t.Error("Disconnect severed another cluster's connection")
	}
}

// TestRekeyPreservesTheConnection covers the registration ordering: a
// connection registers as RoleAll the instant it exists (so a connected
// agent is addressable without having spoken) and re-keys when its first
// message declares a role.
func TestRekeyPreservesTheConnection(t *testing.T) {
	g := testGateway()
	ac := registerRole(t, g, "cl_1", tunnel.RoleAll)

	// Before the Hello: addressable for every role, as a legacy agent is.
	if _, ok := g.getConn("cl_1", tunnel.RoleRemediate); !ok {
		t.Fatal("a freshly registered connection is not addressable")
	}

	g.rekeyConn("cl_1", ac, tunnel.RoleInvestigate)

	if _, ok := g.getConn("cl_1", tunnel.RoleRemediate); ok {
		t.Error("after declaring itself the investigation connection, it still answers a write lookup")
	}
	got, ok := g.getConn("cl_1", tunnel.RoleInvestigate)
	if !ok || got != ac {
		t.Error("the re-keyed connection is not addressable under its declared role")
	}
	if len(g.connsFor("cl_1")) != 1 {
		t.Errorf("re-keying left %d registry entries for one connection — it must MOVE, not duplicate", len(g.connsFor("cl_1")))
	}
}

// TestUnregisterAfterRekeyRemovesTheRightEntry: the deferred cleanup runs
// long after the re-key, and must delete the key the connection actually
// ended up under.
func TestUnregisterAfterRekeyRemovesTheRightEntry(t *testing.T) {
	g := testGateway()
	ac := registerRole(t, g, "cl_1", tunnel.RoleAll)
	g.rekeyConn("cl_1", ac, tunnel.RoleRemediate)
	g.unregisterConn("cl_1", ac)

	if n := len(g.connsFor("cl_1")); n != 0 {
		t.Errorf("%d registry entries survive after unregister — a stale entry means CallTool writes to a closed connection", n)
	}
}

// TestNotConnectedErrorNamesTheRealCause: "cluster X is not connected" is
// actively misleading about a cluster that is connected and reporting
// findings and simply has no remediation agent — which after E11 is the
// normal state of every cluster that has not opted into writes.
func TestNotConnectedErrorNamesTheRealCause(t *testing.T) {
	err := notConnectedError("cl_1", tunnel.RoleRemediate)
	if err == nil {
		t.Fatal("notConnectedError returned nil")
	}
	if !strings.Contains(err.Error(), "remediation") {
		t.Errorf("a missing remediation agent reports %q, which reads as a tunnel problem rather than as an opt-in that was never taken", err)
	}
	if strings.Contains(notConnectedError("cl_1", tunnel.RoleInvestigate).Error(), "remediation") {
		t.Error("an ordinary disconnect is being reported as a remediation opt-in problem")
	}
}

// ---------------------------------------------------------------------------
// Round trip over a real mTLS connection: PROJECT.md E11's Hello handshake and
// role routing, through the real serveClientMessages path rather than against
// the registry map. Reuses tunnel_roundtrip_test.go's harness — see that
// file's package doc comment for the one scope decision (a fixed clusterID,
// so no database is involved).
// ---------------------------------------------------------------------------

// roleAnnouncingAgent is a minimal agent that declares role on its FIRST
// message — never as a message of its own, exactly as the real agents do,
// because a lone Hello would hit a pre-E11 hub's "message with no
// recognized payload" branch and get the connection closed.
//
// The carrier here is a ToolResult for nothing, where the real agents use
// their initial InventoryDelta (investigation) or first Heartbeat
// (remediation). That is this harness' constraint, not the mechanism's: this
// file's gateway has no database, and both of those handlers write to one
// (see tunnel_roundtrip_test.go's package doc comment for the same scope
// decision). A ToolResult nobody is waiting for is handled, logged and
// acked without touching a database, which makes it the one real payload
// available here — and the Hello mechanism is carrier-agnostic by design, so
// what is under test is unaffected.
func roleAnnouncingAgent(conn net.Conn, role string, served chan<- string) {
	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	first := tunnel.ClientMessage{ToolResult: &tunnel.ToolResult{CorrelationID: "not-a-real-call"}}
	if role != "" {
		first.Hello = &tunnel.Hello{Role: role}
	}
	if err := enc.Encode(first); err != nil {
		return
	}

	for {
		var msg tunnel.ServerMessage
		if err := dec.Decode(&msg); err != nil {
			return
		}
		if msg.ToolRequest == nil {
			continue
		}
		select {
		case served <- role:
		default:
		}
		_ = enc.Encode(tunnel.ClientMessage{ToolResult: &tunnel.ToolResult{
			CorrelationID: msg.ToolRequest.CorrelationID,
			Data:          json.RawMessage(`{"servedBy":"` + role + `"}`),
		}})
	}
}

// TestLiveRoleRoutingOverARealConnection is the whole mechanism end to end:
// two agents, one cluster, two declared roles, over two real mTLS
// connections — and each tool call arriving at the peer that is meant to
// serve it.
func TestLiveRoleRoutingOverARealConnection(t *testing.T) {
	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("dev CA: %v", err)
	}
	gw := testGateway()
	const clusterID = "cl_role_routing"
	addr := newTestGateway(t, gw, ca, clusterID)

	invServed := make(chan string, 4)
	remServed := make(chan string, 4)
	go roleAnnouncingAgent(dialTestAgent(t, addr, ca, "investigate"), tunnel.RoleInvestigate, invServed)
	go roleAnnouncingAgent(dialTestAgent(t, addr, ca, "remediate"), tunnel.RoleRemediate, remServed)

	waitForRole(t, gw, clusterID, tunnel.RoleInvestigate)
	waitForRole(t, gw, clusterID, tunnel.RoleRemediate)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	raw, err := gw.CallTool(ctx, clusterID, "describe_resource", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("read tool call failed: %v", err)
	}
	if got := string(raw); !strings.Contains(got, tunnel.RoleInvestigate) {
		t.Errorf("describe_resource was served by %s, want the investigation connection", got)
	}

	raw, err = gw.CallTool(ctx, clusterID, "scale_deployment", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("write action call failed: %v", err)
	}
	if got := string(raw); !strings.Contains(got, tunnel.RoleRemediate) {
		t.Errorf("scale_deployment was served by %s — a write action reached the read-only connection", got)
	}

	if len(remServed) != 1 {
		t.Errorf("the remediation connection served %d calls, want exactly 1 (the write) — a read reaching it would mean the investigation path's evidence is being gathered by the write identity", len(remServed))
	}
}

// TestWriteActionHasNowhereToGoWithoutARemediationAgent is the state every
// cluster that has not opted into writes is now in, and it must be a clean,
// explanatory refusal rather than a dispatch that dies against RBAC.
func TestWriteActionHasNowhereToGoWithoutARemediationAgent(t *testing.T) {
	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("dev CA: %v", err)
	}
	gw := testGateway()
	const clusterID = "cl_investigate_only"
	addr := newTestGateway(t, gw, ca, clusterID)

	served := make(chan string, 4)
	go roleAnnouncingAgent(dialTestAgent(t, addr, ca, "investigate"), tunnel.RoleInvestigate, served)
	waitForRole(t, gw, clusterID, tunnel.RoleInvestigate)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := gw.CallTool(ctx, clusterID, "scale_deployment", json.RawMessage(`{}`)); err == nil {
		t.Fatal("a write action was dispatched to a cluster whose only connection is the read-only investigation agent")
	} else if !strings.Contains(err.Error(), "remediation") {
		t.Errorf("refused with %q, which reads as a tunnel fault rather than as an opt-in nobody took", err)
	}
	if len(served) != 0 {
		t.Error("the investigation connection received a write action")
	}

	// And it is still fully usable for what it IS for.
	if _, err := gw.CallTool(ctx, clusterID, "describe_resource", json.RawMessage(`{}`)); err != nil {
		t.Errorf("the investigation connection stopped serving reads: %v", err)
	}
}

// TestALegacyAgentStillServesBothOverARealConnection is the wire-level
// backward-compatibility proof: an agent that sends no Hello at all (every
// build before E11) registers as RoleAll and answers both routes.
func TestALegacyAgentStillServesBothOverARealConnection(t *testing.T) {
	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("dev CA: %v", err)
	}
	gw := testGateway()
	const clusterID = "cl_legacy_wire"
	addr := newTestGateway(t, gw, ca, clusterID)

	served := make(chan string, 4)
	go roleAnnouncingAgent(dialTestAgent(t, addr, ca, "legacy"), "", served)
	waitForRole(t, gw, clusterID, tunnel.RoleAll)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, tool := range []string{"describe_resource", "scale_deployment"} {
		if _, err := gw.CallTool(ctx, clusterID, tool, json.RawMessage(`{}`)); err != nil {
			t.Errorf("a pre-E11 agent could not serve %s: %v — upgrading the hub would break every cluster not yet upgraded", tool, err)
		}
	}
}

// waitForRole blocks until clusterID has a connection registered under
// exactly role (not resolved through the RoleAll fallback), or fails.
func waitForRole(t *testing.T, gw *Gateway, clusterID, role string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		gw.connsMu.Lock()
		_, ok := gw.conns[connKey{clusterID, role}]
		gw.connsMu.Unlock()
		if ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no connection registered for cluster %s under role %q", clusterID, role)
}
