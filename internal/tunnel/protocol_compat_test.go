package tunnel

// protocol_compat_test.go is the check this package has never had and
// needs most: internal/tunnel is imported by BOTH halves of the system, and
// a hub and an agent are routinely different builds (an operator upgrades
// the hub; 200+ agents follow whenever their charts do). Every field added
// here is therefore a protocol change, and "additive" has to mean two
// things at once:
//
//   - a NEW build talking to an OLD one must produce bytes the old decoder
//     reads exactly as it did before — which, for encoding/json, means the
//     new field must be ABSENT from the wire when it is unset, not present
//     and empty;
//   - an OLD build talking to a NEW one must decode into the documented
//     "absent means unknown" value, never into a zero that reads as a fact.
//
// The three fields this file covers are the ones added for PROJECT.md P21
// (Finding acks), P19's residual (DetectorStatus.TimedOutChecks) and B176's
// residual (Heartbeat.FindingQueue).

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestHeartbeatFromAnOlderAgentHasNoFindingQueue is B176's residual, old
// agent -> new hub: the absence must survive as nil, because the hub's whole
// contract is that "this agent cannot tell us" and "this agent has never
// dropped a finding" are different answers.
func TestHeartbeatFromAnOlderAgentHasNoFindingQueue(t *testing.T) {
	const oldWire = `{"heartbeat":{"agentVersion":"0.1.0-mvp","certExpiresAt":"2026-12-01T00:00:00Z"}}`

	var msg ClientMessage
	if err := json.Unmarshal([]byte(oldWire), &msg); err != nil {
		t.Fatalf("a new hub could not decode an old agent's heartbeat: %v", err)
	}
	if msg.Heartbeat == nil {
		t.Fatal("heartbeat did not decode at all")
	}
	if msg.Heartbeat.FindingQueue != nil {
		t.Fatalf("FindingQueue = %+v, want nil — an agent that never reported one must not decode into a zeroed struct claiming an empty queue and no losses", msg.Heartbeat.FindingQueue)
	}
	if msg.Heartbeat.AgentVersion != "0.1.0-mvp" {
		t.Errorf("AgentVersion = %q, want the old agent's own value untouched", msg.Heartbeat.AgentVersion)
	}
}

// TestHeartbeatWithoutFindingQueueIsByteIdenticalForAnOlderHub is the same
// field, new agent -> old hub: a heartbeat that has nothing to report must
// put nothing on the wire.
func TestHeartbeatWithoutFindingQueueIsByteIdenticalForAnOlderHub(t *testing.T) {
	hb := ClientMessage{Heartbeat: &Heartbeat{AgentVersion: AgentBuildVersion, CertExpiresAt: time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)}}
	out, err := json.Marshal(hb)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(out), "findingQueue") {
		t.Fatalf("an unset FindingQueue still appeared on the wire: %s", out)
	}

	// And when it IS set, it is purely additive: an old hub decodes the
	// message it always could and ignores the rest.
	hb.Heartbeat.FindingQueue = &FindingQueueStatus{Pending: 12, Dropped: 3, Capacity: 5000}
	out, err = json.Marshal(hb)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var oldHubView struct {
		Heartbeat *struct {
			AgentVersion  string    `json:"agentVersion"`
			CertExpiresAt time.Time `json:"certExpiresAt"`
		} `json:"heartbeat"`
	}
	if err := json.Unmarshal(out, &oldHubView); err != nil {
		t.Fatalf("an old hub could not decode a new agent's heartbeat: %v", err)
	}
	if oldHubView.Heartbeat == nil || oldHubView.Heartbeat.AgentVersion != AgentBuildVersion {
		t.Fatalf("an old hub decoded %+v, want the heartbeat it has always read", oldHubView.Heartbeat)
	}
}

// TestDetectorStatusTimedOutChecksIsAdditiveBothWays is P19's residual. The
// paired assertion matters as much as either half: an agent that predates
// the field still records the same fact in Error behind the stable prefix,
// so a new hub reading an old agent loses nothing, and an old hub reading a
// new agent keeps reading exactly that prefix.
func TestDetectorStatusTimedOutChecksIsAdditiveBothWays(t *testing.T) {
	const oldWire = `{"lastSuccessAt":"2026-09-20T10:00:00Z","error":"sweep checker timeout: pvc pending (no response within 30s; the other 21 of 22 checks in this pass still ran)","errorAt":"2026-09-20T10:00:00Z"}`

	var fromOldAgent DetectorStatus
	if err := json.Unmarshal([]byte(oldWire), &fromOldAgent); err != nil {
		t.Fatalf("a new hub could not decode an old agent's DetectorStatus: %v", err)
	}
	if fromOldAgent.TimedOutChecks != nil {
		t.Errorf("TimedOutChecks = %v, want nil for an agent that predates the field", fromOldAgent.TimedOutChecks)
	}
	if !strings.HasPrefix(fromOldAgent.Error, "sweep checker timeout: ") {
		t.Errorf("Error = %q, want the old agent's prefixed timeout text intact — that prefix is the only timeout signal such an agent has", fromOldAgent.Error)
	}

	clean := DetectorStatus{LastSuccessAt: time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)}
	out, err := json.Marshal(clean)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(out), "timedOutChecks") {
		t.Fatalf("an empty TimedOutChecks still appeared on the wire: %s", out)
	}

	withTimeout := DetectorStatus{
		LastSuccessAt:  time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC),
		Error:          "sweep checker timeout: pvc pending (no response within 30s; the other 21 of 22 checks in this pass still ran)",
		ErrorAt:        time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC),
		TimedOutChecks: []string{"pvc pending"},
	}
	out, err = json.Marshal(withTimeout)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var oldHubView struct {
		LastSuccessAt time.Time `json:"lastSuccessAt"`
		Error         string    `json:"error"`
		ErrorAt       time.Time `json:"errorAt"`
	}
	if err := json.Unmarshal(out, &oldHubView); err != nil {
		t.Fatalf("an old hub could not decode a new agent's DetectorStatus: %v", err)
	}
	if !strings.HasPrefix(oldHubView.Error, "sweep checker timeout: ") {
		t.Fatalf("an old hub sees Error = %q — a new agent must keep writing the prefixed text, or upgrading the agent would take a working signal away from an unrebuilt hub", oldHubView.Error)
	}
}

// TestFindingCorrelationIDRoundTripsThroughAnOlderHub is P21's backward
// compatibility, and it rests on something that was already true: the hub
// has always echoed ClientMessage.CorrelationID back on its Ack. A hub that
// predates P21 therefore acks a correlated finding correctly WITHOUT ANY
// HUB CHANGE — which is why P21 needed no new ServerMessage field at all.
func TestFindingCorrelationIDRoundTripsThroughAnOlderHub(t *testing.T) {
	msg := ClientMessage{CorrelationID: "fnd-abc123-7", Finding: &Finding{DetectorID: "k8s-sweep", Fingerprint: "fp-1"}}
	out, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// An older hub's decode: the two fields serveClientMessages has always
	// read, and the ack it has always built from them.
	var oldHubView struct {
		CorrelationID string          `json:"correlationId"`
		Finding       json.RawMessage `json:"finding"`
	}
	if err := json.Unmarshal(out, &oldHubView); err != nil {
		t.Fatalf("an old hub could not decode a correlated finding: %v", err)
	}
	if oldHubView.CorrelationID != "fnd-abc123-7" {
		t.Fatalf("an old hub read correlationId = %q, want the agent's id verbatim so its echo is attributable", oldHubView.CorrelationID)
	}
	ack, err := json.Marshal(ServerMessage{CorrelationID: oldHubView.CorrelationID, Ack: true})
	if err != nil {
		t.Fatalf("marshal ack: %v", err)
	}
	var backAtAgent ServerMessage
	if err := json.Unmarshal(ack, &backAtAgent); err != nil {
		t.Fatalf("decode ack: %v", err)
	}
	if !backAtAgent.Ack || backAtAgent.CorrelationID != "fnd-abc123-7" {
		t.Fatalf("ack round trip = %+v, want ack=true with the same id", backAtAgent)
	}

	// The other direction: an agent that predates P21 sends no id, and the
	// ack for it carries none — which a P21 agent must treat as "an ack for
	// something nobody is waiting on" rather than matching it to anything.
	out, err = json.Marshal(ClientMessage{Finding: &Finding{DetectorID: "k8s-sweep", Fingerprint: "fp-1"}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(out), "correlationId") {
		t.Fatalf("an unset CorrelationID still appeared on the wire: %s", out)
	}
}

// ---------------------------------------------------------------------------
// PROJECT.md E11: ClientMessage.Hello and ClusterFacts.Coverage.
// ---------------------------------------------------------------------------

// oldClientMessage is the ClientMessage shape a hub built before E11
// compiles against — no Hello field at all. Decoding a new agent's bytes
// into this is the actual "old peer" test, not a paraphrase of one.
type oldClientMessage struct {
	CorrelationID  string          `json:"correlationId,omitempty"`
	Heartbeat      *Heartbeat      `json:"heartbeat,omitempty"`
	InventoryDelta *InventoryDelta `json:"inventoryDelta,omitempty"`
	Finding        *Finding        `json:"finding,omitempty"`
	ToolResult     *ToolResult     `json:"toolResult,omitempty"`
}

// TestHelloRidesARealMessageSoAnOldHubStillDispatchesIt is the
// load-bearing compatibility claim for E11's wire change, and the reason the
// role is NOT sent as a message of its own.
//
// A pre-E11 hub's dispatch is a switch over the payload fields with a
// `default: return errors.New("message with no recognized payload")` that
// CLOSES the connection. A lone Hello would hit that branch: every agent
// that declared a role would be disconnected by every hub not yet upgraded.
// Carried on a real message instead, the unknown field is discarded and the
// old hub handles the payload exactly as before.
func TestHelloRidesARealMessageSoAnOldHubStillDispatchesIt(t *testing.T) {
	newWire, err := json.Marshal(ClientMessage{
		Hello:          &Hello{Role: RoleInvestigate},
		InventoryDelta: &InventoryDelta{Facts: ClusterFacts{NodeCount: 3, Reachable: true}, FullResync: true},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var old oldClientMessage
	if err := json.Unmarshal(newWire, &old); err != nil {
		t.Fatalf("a pre-E11 hub could not decode a role-declaring agent's message: %v", err)
	}
	if old.InventoryDelta == nil {
		t.Fatal("the old shape lost the InventoryDelta — the old hub would fall through to 'message with no recognized payload' and sever the connection")
	}
	if old.InventoryDelta.Facts.NodeCount != 3 {
		t.Errorf("NodeCount = %d, want 3 — the payload must survive the unknown field beside it", old.InventoryDelta.Facts.NodeCount)
	}
}

// TestAMessageFromAnOlderAgentHasNoHello is the other direction: an agent
// that predates roles sends no hello key, and a new hub must read that as
// "declared nothing" (treated as RoleAll), never as a declared empty role.
func TestAMessageFromAnOlderAgentHasNoHello(t *testing.T) {
	const oldWire = `{"inventoryDelta":{"facts":{"nodeCount":1,"reachable":true},"fullResync":true}}`

	var msg ClientMessage
	if err := json.Unmarshal([]byte(oldWire), &msg); err != nil {
		t.Fatalf("a new hub could not decode an old agent's inventory: %v", err)
	}
	if msg.Hello != nil {
		t.Errorf("Hello = %+v on a message that never carried one — absent must stay absent, so the hub falls back to RoleAll rather than to a role named \"\"", msg.Hello)
	}
	if msg.InventoryDelta == nil {
		t.Fatal("the inventory did not decode")
	}
}

// TestHelloIsAbsentFromTheWireWhenUnset: a new agent that declares no role
// (the RoleAll default, and every agent that has not been reconfigured) must
// produce bytes byte-identical in shape to what it produced before the field
// existed.
func TestHelloIsAbsentFromTheWireWhenUnset(t *testing.T) {
	b, err := json.Marshal(ClientMessage{Heartbeat: &Heartbeat{AgentVersion: "x"}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "hello") {
		t.Errorf("an unset Hello still appears on the wire: %s", b)
	}
}

// TestCoverageFromAnOlderAgentIsAbsentNotZero is the E11 coverage signal's
// half of the same discipline. "This agent is too old to report coverage"
// and "this agent watches 0 of 0 kinds" are opposite claims, and rendering
// the second for the first is exactly the fabricated-zero mistake this
// codebase already refuses to make for costs and counts.
func TestCoverageFromAnOlderAgentIsAbsentNotZero(t *testing.T) {
	const oldFacts = `{"nodeCount":2,"reachable":true,"nodes":[]}`

	var facts ClusterFacts
	if err := json.Unmarshal([]byte(oldFacts), &facts); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if facts.Coverage != nil {
		t.Errorf("Coverage = %+v for an agent that never reported one, want nil", facts.Coverage)
	}

	b, err := json.Marshal(ClusterFacts{NodeCount: 2, Reachable: true})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "coverage") {
		t.Errorf("an unset Coverage still appears on the wire: %s", b)
	}
}

// TestCheckedCoverageReportsAGenuineZero is the complement, and the reason
// Checked exists as a separate field: an agent whose RBAC really does grant
// nothing must be able to say so, distinguishably from one that could not
// look.
func TestCheckedCoverageReportsAGenuineZero(t *testing.T) {
	b, err := json.Marshal(ClusterFacts{Coverage: &ClusterCoverage{Checked: true, KindsServed: 216}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"kindsReadable":0`) {
		t.Errorf("a checked coverage of 0 readable kinds omits the zero: %s — a consumer would read it as 'not reported' and show nothing, for the most alarming state this signal has", b)
	}
}
