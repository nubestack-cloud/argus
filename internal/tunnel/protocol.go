// Package tunnel defines the wire messages exchanged between the spoke agent
// (internal/agent, cmd/agent) and the hub's Agent Gateway (internal/gateway)
// over the mTLS-authenticated tunnel connection described in
// lld/03-agent-protocol.md §6.
//
// Scoped-down MVP transport: newline-delimited JSON over a mutually
// authenticated TLS connection (crypto/tls), not gRPC/protobuf yet. This is a
// deliberate, documented simplification — see STATUS.md and
// lld/03-agent-protocol.md's addendum. Finding (added once the Detection
// Controller landed) was the first of the fuller message set to actually
// exist; ToolRequest/ToolResult (owned by analysis-contracts, lld/07 §2) are
// the second — the hub-side dispatch-and-correlate mechanism and the
// agent-side executor for a four-tool subset now exist (internal/gateway's
// CallTool, internal/agent's ToolExecutor), though nothing in this repo
// calls CallTool yet — see STATUS.md for exactly what this does and doesn't
// unlock. ExecutionPlan/ConfigUpdate (owned by remediation-contracts) still
// have nothing to carry — no remediation layer exists in this repo yet.
// Adding a message type is additive (a new field here plus a new case in
// each side's dispatch loop), not a breaking wire change. Revisit real
// gRPC/protobuf when chunked binary ToolResult payloads or cross-language
// tool servers actually need it.
package tunnel

import (
	"encoding/json"
	"time"
)

// ClientMessage is sent agent -> hub. Exactly one of the payload fields is
// set per message.
type ClientMessage struct {
	// CorrelationID is echoed back verbatim on the hub's Ack for this
	// message (internal/gateway's serveClientMessages and, for a Finding,
	// processFindingAsync), which is what turns the Ack from a bare
	// "something arrived" into "THIS message was accepted".
	//
	// The agent sets it on every Finding and leaves it empty on
	// Heartbeat/InventoryDelta/ToolResult, so an Ack carrying an empty
	// CorrelationID is exactly "an ack for a message nobody is waiting on"
	// (PROJECT.md P21 — see internal/agent/finding_queue.go's
	// findingInflight, which holds each sent Finding until its own id comes
	// back and re-queues whatever is still unacked when a session dies).
	// Deliberately NOT a domain.NewID prefixed ULID, for the same reason
	// internal/gateway's newCorrelationID isn't: it names a message in
	// flight, not a persisted entity, and is never stored anywhere.
	//
	// Backward compatible in both directions: a hub that predates P21 still
	// echoes whatever it was sent (that echo is what P21 builds on and is
	// unchanged here), and an agent that predates it still sends an empty
	// id, which a hub echoes just as harmlessly as before.
	CorrelationID string `json:"correlationId,omitempty"`
	// Hello, when set, is the first message on a connection and declares
	// what that connection is for (PROJECT.md E11). Never set on any
	// subsequent message. Absent from every message an agent older than
	// ConnectionRole sends, which is exactly how the hub tells the two
	// shapes apart — see Hello's own doc comment.
	Hello          *Hello          `json:"hello,omitempty"`
	Heartbeat      *Heartbeat      `json:"heartbeat,omitempty"`
	InventoryDelta *InventoryDelta `json:"inventoryDelta,omitempty"`
	Finding        *Finding        `json:"finding,omitempty"`
	ToolResult     *ToolResult     `json:"toolResult,omitempty"`
	// ChangeBatch carries field-level object changes from the agent's object
	// cache (docs/CLUSTER_INSIGHT_SPECS.md CI-S2). Best-effort and unacked:
	// anything lost is reported as a Gap rather than redelivered.
	ChangeBatch *ChangeBatch `json:"changeBatch,omitempty"`
}

// HubFeatureChangeBatch is the HubFeatures entry for ChangeBatch.
const HubFeatureChangeBatch = "changeBatch"

// ChangeBatch is one flush of the agent's change buffer.
type ChangeBatch struct {
	Changes []ResourceChange `json:"changes,omitempty"`
	Gaps    []ChangeGap      `json:"gaps,omitempty"`
}

// ResourceChange is one add/update/delete of a tracked object. Values in
// Fields are short (agent-truncated) and already redacted at capture.
type ResourceChange struct {
	ObservedAt time.Time     `json:"observedAt"`
	Kind       string        `json:"kind"`
	APIGroup   string        `json:"apiGroup,omitempty"`
	Namespace  string        `json:"namespace,omitempty"`
	Name       string        `json:"name"`
	UID        string        `json:"uid,omitempty"`
	OwnerKind  string        `json:"ownerKind,omitempty"`
	OwnerName  string        `json:"ownerName,omitempty"`
	Op         string        `json:"op"`
	Fields     []ChangeField `json:"fields,omitempty"`
	Summary    string        `json:"summary,omitempty"`
}

// ChangeField is one changed field path with its old and new value.
type ChangeField struct {
	Path     string `json:"path"`
	OldValue any    `json:"oldValue,omitempty"`
	NewValue any    `json:"newValue,omitempty"`
}

// ChangeGap is a window in which changes were lost.
type ChangeGap struct {
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	Reason string    `json:"reason"`
}

// ToolRequest is the hub asking an already-connected agent to run one
// read-only diagnostic tool against its target cluster, per
// lld/07-analysis-contracts.md §2 and ADR-2's hub-side-loop decision
// (lld/14-adrs.md). CorrelationID is scoped to this request/response pair
// specifically (distinct from ClientMessage/ServerMessage's own top-level
// CorrelationID field, which is echoed back on an Ack and, since PROJECT.md
// P21, is what the agent's finding queue matches a delivery against — a
// separate id space from this one, flowing the other way, and never mixed
// with it) — internal/gateway.Gateway.CallTool generates one per
// call and uses it to route the eventual ToolResult back to the right
// waiting caller, even with several calls in flight concurrently.
//
// Tool is one of the small subset this increment's agent-side executor
// implements (internal/agent.ToolExecutor): "get_events", "get_logs",
// "describe_resource", "get_owner_chain". Args is that tool's own input
// shape (see internal/agent/tools.go's per-tool argument structs) — kept as
// raw JSON here so adding a new tool never requires a protocol.go change,
// only a new case in the executor's dispatch and a matching one in whatever
// hub-side code eventually calls CallTool for it.
type ToolRequest struct {
	CorrelationID string          `json:"correlationId"`
	Tool          string          `json:"tool"`
	Args          json.RawMessage `json:"args"`
}

// ToolResult is the agent's reply to a ToolRequest, carried back on the next
// ClientMessage. Exactly one of Data/Error is set: Data on success (that
// tool's own JSON output shape, lld/07-analysis-contracts.md §2's per-tool
// column), Error on any failure (unknown tool name, args that didn't parse,
// RBAC-denied, resource-not-found, or any other cluster-API error) — always
// a short, clean message (internal/agent/tools.go's sanitizeK8sError), never
// a raw Kubernetes client error string, stack trace, or anything that could
// carry a credential. Truncated is always present, even when false, per
// lld/07 §2's envelope discipline (distinguishing "nothing was truncated"
// from "this tool doesn't report truncation").
type ToolResult struct {
	CorrelationID string          `json:"correlationId"`
	Data          json.RawMessage `json:"data,omitempty"`
	Error         string          `json:"error,omitempty"`
	Truncated     bool            `json:"truncated"`
}

// Finding is the detection layer's output, carried over the tunnel exactly
// as lld/03-agent-protocol.md §6 sketches it. Field set matches
// lld/06-detection-framework.md §2's normalized Signal schema AND
// internal/migrations/000004_findings.up.sql's columns one-for-one — those
// two documents (plus this struct) are meant to never drift apart; extend
// all three together, not just one.
//
// Deliberately NOT included yet, because nothing currently populates them
// correctly: environment (cluster-label derived) and arbitrary labels
// (eventually allowlisted by policy). Add them when their producer exists.
const (
	FindingClassFault   = "fault"
	FindingClassRisk    = "risk"
	FindingClassAnomaly = "anomaly"

	FindingConfidenceVerified   = "verified"
	FindingConfidenceInferred   = "inferred"
	FindingConfidenceUnverified = "unverified"

	FindingImpactUnavailable = "unavailable"
	FindingImpactDegraded    = "degraded"
	FindingImpactPotential   = "potential"
	FindingImpactNone        = "none"
)

type Finding struct {
	DetectorID      string    `json:"detectorId"`
	DetectorVersion string    `json:"detectorVersion"`
	Fingerprint     string    `json:"fingerprint"`
	GVK             string    `json:"gvk"`
	Namespace       string    `json:"namespace,omitempty"`
	ObjectName      string    `json:"objectName"`
	ObjectUID       string    `json:"objectUid"`
	ResourceVersion string    `json:"resourceVersion"`
	Reason          string    `json:"reason"`
	Message         string    `json:"message"`
	OccurrenceCount int       `json:"occurrenceCount"`
	Severity        string    `json:"severity"` // "low" | "medium" | "high" | "critical" — lld/06-detection-framework.md §2
	OccurredAt      time.Time `json:"occurredAt"`
	// Class, Confidence, and Impact describe what the detector actually proved.
	// They are deliberately independent of GVK and Reason so the hub can make
	// one generic promotion decision for built-in kinds, CRDs, and future
	// detector plugins alike. Empty means an older agent using the legacy
	// contract; the hub preserves that agent's previous incident behavior.
	Class      string `json:"class,omitempty"`      // fault | risk | anomaly
	Confidence string `json:"confidence,omitempty"` // verified | inferred | unverified
	Impact     string `json:"impact,omitempty"`     // unavailable | degraded | potential | none
	// WorkloadGVK/WorkloadName identify the workload that OWNS this Finding's
	// object, when it's a Pod whose agent-side detector could resolve one —
	// e.g. "apps/v1/Deployment"/"myapp" for a Pod owned (possibly via an
	// intermediate ReplicaSet) by a Deployment named myapp. Both empty for
	// anything that isn't a Pod, or a bare Pod with no controller.
	// internal/agent/workload.go resolves these agent-side (cheaply, from the
	// Pod's own OwnerReferences, already in hand at detection time); the hub
	// joins them into a display/grouping key
	// (internal/gateway/finding.go's workloadCorrelationKey) rather than
	// having the agent send an opaque joined string, mirroring GVK/Namespace/
	// ObjectName's own split above. See BACKLOG.md's A3 entry and migration
	// 000042 for what this enables: replica-level correlation, grouping
	// several pods' independent incidents for the same underlying fault
	// without merging their state.
	WorkloadGVK  string `json:"workloadGvk,omitempty"`
	WorkloadName string `json:"workloadName,omitempty"`

	// PodPriority is this Finding's own object's resolved spec.priority — set
	// ONLY when GVK is "v1/Pod" and the agent already had the full *corev1.Pod
	// object in hand at Finding-build time (pod_conditions_detector.go's
	// buildPodFinding, sweep_detector.go's checkPodPendingTimeout, and
	// detector.go's handleWatchedEvent via workload.go's
	// resolveWorkloadForInvolvedObject — the same three call sites that
	// already populate WorkloadGVK/WorkloadName above from a Pod object).
	// Deliberately the resolved INTEGER (PodSpec.Priority), never
	// PriorityClassName: the integer is what the API server's priority
	// admission plugin already stamps onto the Pod from its PriorityClassName
	// (or leaves nil if that plugin never ran), so reading it needs no
	// further resolution of a cluster-scoped PriorityClass object — see
	// internal/agent/generic_predicates.go's own doc comment on why
	// PriorityClassName specifically was NOT resolved generically for a
	// different predicate (it names a KIND-less bare string, the integer
	// does not). internal/importance's WorkloadCriticality factor is this
	// field, carried through unchanged.
	//
	// nil means "unknown", never zero, and covers three genuinely different
	// cases the wire cannot and need not distinguish (same convention as
	// ClusterRemediation/ClusterDetectors above): an agent older than this
	// field, a Finding whose object isn't a Pod, and a real Pod whose own
	// spec.priority the API server itself left unset (the priority admission
	// plugin disabled, or a very old Kubernetes version). A consumer must
	// treat all three as "no criticality signal" and contribute nothing to a
	// score built from this — never fabricate a low-priority zero for any of
	// them.
	//
	// Purely additive, same posture as WorkloadGVK/RuleID/Condition* above.
	PodPriority *int32 `json:"podPriority,omitempty"`

	// RelatedWorkloadGVK/RelatedWorkloadName identify a workload this
	// Finding's own object is NOT part of, but is causally linked to via a
	// reference this codebase has to resolve itself — BACKLOG.md's A3b
	// ("cross-object correlation"): a Service's spec.selector matched
	// against the Pods it targets, or a PersistentVolumeClaim matched
	// against the Pod(s) that mount it via
	// spec.volumes[*].persistentVolumeClaim.claimName. Set only by the two
	// sweep checks that need it (checkPVCPending, checkServiceNoEndpoints in
	// internal/agent/sweep_detector.go), via
	// internal/agent/objectref.go's resolveRelatedWorkload* helpers, which
	// find the matching Pod(s) and then resolve their owning workload with
	// the exact same resolveWorkloadFromOwnerRefs walk WorkloadGVK/
	// WorkloadName themselves use.
	//
	// Deliberately a SEPARATE pair of fields from WorkloadGVK/WorkloadName
	// above, not a reuse of them, even though both ultimately name "a
	// workload": internal/gateway/finding.go's correlationIdentity treats a
	// shared WorkloadName as grounds to MERGE two Findings onto the same
	// incident, and A3b's design brief is explicit that cross-object
	// correlation must stay read-only/display-only — see
	// internal/objectgroup's package doc for the full argument. Reusing the
	// merge-tier field here would silently fold a PVC's or a Service's own
	// incident into the Pod's, which is exactly the behavior A3a was
	// deliberately walked back from for POD siblings (see BACKLOG.md's A3a
	// history) and A3b must not reintroduce for cross-object siblings.
	RelatedWorkloadGVK  string `json:"relatedWorkloadGvk,omitempty"`
	RelatedWorkloadName string `json:"relatedWorkloadName,omitempty"`

	// RuleID is BACKLOG.md E9's declarative Rule.ID (internal/agent/rules.go)
	// when this Finding was produced by evaluateRule — empty for every
	// Finding from the 17 hand-written Go checkers, the two watch-based
	// detectors, or a rule set that predates this field.
	//
	// Added for BACKLOG.md V3 (the synthetic post-fix health check): a
	// Finding produced through the rule engine already carries
	// DetectorID "k8s-sweep" (the shared sweep-detector id, not the specific
	// rule), so without this field there is no reliable way for the hub to
	// know WHICH rule opened an incident and therefore nothing to re-run.
	// Reason was considered and rejected as a substitute identifier: it is a
	// per-rule fixed string (rules.go's Rule.Reason), but LoadRules only
	// enforces uniqueness on Rule.ID, not Reason — an operator-authored rules
	// file (or a hand-written checker's own reasonXxx constant) can collide
	// with it, and reverse-engineering an identifier from a display string
	// never designed to be one is exactly the "fragile" case V3's own task
	// description warned about. RuleID is set once, directly, at the only
	// place that actually knows it (evaluateRule) — no reconstruction needed
	// anywhere downstream.
	//
	// Purely additive, like WorkloadGVK/DryRun/Detection before it: an agent
	// older than this field omits it (empty string, indistinguishable from
	// "not a rule finding"), and a hub older than this field ignores it —
	// nothing here is a breaking wire change either direction.
	RuleID string `json:"ruleId,omitempty"`

	// ConditionType/ConditionObservedValue/ConditionSampleCount/
	// ConditionMajorityValue/ConditionMajorityFraction carry BACKLOG.md E11's
	// kind-agnostic status.conditions[] predicate's own polarity evidence —
	// set only by internal/agent's checkGenericConditions (reason
	// "GenericConditionAnomaly"), empty/zero for every other Finding.
	//
	// This Finding's Reason alone is not enough for the hub to decide
	// fire-or-drop: E11 piece 3 explicitly forbids a hardcoded polarity table
	// ("Ready=True good, MemoryPressure=True bad"), so the agent cannot know
	// on its own whether ConditionObservedValue is the *problem* reading or
	// the *healthy* one — only that it differs from what most live peers of
	// the same Kind currently report for the same condition Type (or, when
	// there are too few peers to have an opinion, that there is no local
	// majority to compare against at all). The hub is the one place that can
	// hold a durable, cross-cluster, cross-sweep verdict
	// (internal/conditionpolarity's persisted cache, seeded by these very
	// samples or, failing that, asked of the model once) — so the agent
	// always forwards its own best local read, and the hub's polarity gate
	// (internal/gateway/finding.go, ahead of ordinary correlation) is the
	// only place that turns "differs from a local sample" into "is actually
	// the bad value" before an incident is ever opened.
	//
	// ConditionSampleCount/ConditionMajorityValue/ConditionMajorityFraction
	// describe the CLUSTER-WIDE sample this specific agent process saw this
	// sweep (Mechanism 1, "learn it from the cluster") — a genuine
	// statistical read, not a guess, and the hub trusts and persists it
	// (source="statistical") exactly when it clears the same confidence bar
	// the agent itself uses to decide whether to report at all
	// (minGenericPolaritySamples/genericPolarityMajorityFraction in
	// internal/agent/generic_predicates.go). Below that bar
	// ConditionSampleCount is small and ConditionMajorityFraction is
	// meaningless (there was no real majority to compute), and the hub falls
	// back to Mechanism 2 (asking the model once, then caching the answer)
	// instead of trusting it.
	//
	// Purely additive, same posture as RuleID above.
	ConditionType             string  `json:"conditionType,omitempty"`
	ConditionObservedValue    string  `json:"conditionObservedValue,omitempty"`
	ConditionSampleCount      int     `json:"conditionSampleCount,omitempty"`
	ConditionMajorityValue    string  `json:"conditionMajorityValue,omitempty"`
	ConditionMajorityFraction float64 `json:"conditionMajorityFraction,omitempty"`

	// ConditionParentPath is PROJECT.md B154's own addition: WHERE under
	// status this condition was found, when it is not the conventional
	// top-level status.conditions[] — e.g. "listeners[0] (plain)" for a
	// Gateway's per-listener condition, or "parents[0] (gw-listener-conflict)"
	// for an HTTPRoute's per-parent one. Empty for a top-level condition,
	// which is still the common case and needs no extra clause. See
	// internal/agent/generic_predicates.go's findConditionGroups — the
	// condition itself is still located by SHAPE (an array of objects
	// carrying type/status/reason/message, at any depth under status), never
	// by a per-kind path table; this field only carries the human-readable
	// answer to "which one" once shape-matching has already found it, so an
	// operator is never left staring at an object-level verdict with no way
	// to tell which child of it is actually broken.
	//
	// Purely additive, same posture as RuleID/Condition*/References above.
	ConditionParentPath string `json:"conditionParentPath,omitempty"`

	// References is PROJECT.md B153's reference-direction impact signal —
	// added for the SAME reason RelatedWorkloadGVK/Name exist (A3b's
	// cross-object correlation), but generic across every kind rather than
	// the two hand-built cases that pair covers: every {kind, name} pair
	// this Finding's OWN object names anywhere in its top-level fields
	// (except metadata — matches checkGenericDanglingReference's own
	// exclusion, B148), reusing that predicate's exact extraction
	// (internal/agent's findObjectReferences), NOT a second, hand-maintained
	// per-kind table of what points at what. Populated for EVERY Finding
	// checkGenericObjectHealth's dispatcher produces, on every predicate
	// (not only checkGenericDanglingReference's own), because the whole
	// point is answering it from the OTHER side later: "does some OTHER
	// object's Fault-classed finding carry a reference back to THIS
	// anomalous object" (internal/gateway's earned-promotion impact check) —
	// a question the hub can only answer if the referencing object's own
	// Finding already says what it points at, not just what's wrong with it.
	//
	// Deliberately spec/status-level named references only (the same shape
	// findObjectReferences already matches) — NOT get_owner_chain's
	// ownerReferences walk, which is a separate, differently-shaped
	// relationship (garbage-collection ownership, not a spec-level pointer)
	// this field does not attempt to fold in.
	//
	// Purely additive, same posture as RuleID/Condition* above: an agent
	// older than this field omits it, and a hub older than this field
	// ignores it.
	References []ObjectReference `json:"references,omitempty"`
}

// ObjectReference is one {kind, namespace, name} pointer a Finding's own
// object carries in its spec/status — see Finding.References' own doc
// comment for what populates this and why.
type ObjectReference struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	// Role is how the referring object relates to this one, when that is more
	// than "uses": ReferenceRoleProduces marks an object this one creates and
	// keeps (a cert-manager Certificate's Secret). Empty means "depends on".
	Role string `json:"role,omitempty"`
}

// ReferenceRoleProduces: the referring object produces the referenced one,
// so a fault in the producer is the cause of a fault in anything waiting on
// what it produces (PROJECT.md IN5).
const ReferenceRoleProduces = "produces"

// ServerMessage is sent hub -> agent. Exactly one of Ack/Error/ToolRequest/
// Terminal is meaningfully set on any given message (Ack and Error remain
// mutually exclusive as before; ToolRequest is the unsolicited case — the
// hub proactively asking the agent to do something; Terminal is the fourth
// case, sent alone, immediately before the hub closes a connection it will
// never serve — see Terminal's own doc comment).
type ServerMessage struct {
	// CorrelationID is the ClientMessage.CorrelationID this message is
	// answering, echoed verbatim. Empty for an unsolicited ToolRequest or
	// Terminal, and for an Ack of a ClientMessage that carried no id.
	CorrelationID string `json:"correlationId,omitempty"`
	// Ack means the hub has ACCEPTED the ClientMessage named by
	// CorrelationID — for a Finding specifically, that handleFinding
	// completed without error and the finding is durable hub-side, since
	// internal/gateway's processFindingAsync sends this only after that
	// returns and closes the connection instead of acking when it fails.
	// PROJECT.md P21 is what gave that guarantee a consumer: the agent's
	// finding queue treats an un-acked finding as still pending and
	// redelivers it on the next session, so "no ack" now costs a duplicate
	// rather than the finding itself.
	Ack         bool         `json:"ack,omitempty"`
	Error       string       `json:"error,omitempty"`
	ToolRequest *ToolRequest `json:"toolRequest,omitempty"`

	// HubFeatures, on an Ack, names optional message types this hub accepts
	// beyond the original protocol. An agent sends such a message only after
	// it has seen the feature named here — an older hub drops a connection
	// that sends a payload it does not recognise, so this is what keeps a
	// newer agent compatible with an older hub.
	HubFeatures []string `json:"hubFeatures,omitempty"`

	// Terminal, when non-empty, replaces a bare connection close with an
	// explanation: this cluster's own state (internal/gateway/server.go's
	// handleConn, checked immediately after the mTLS handshake succeeds,
	// before any message loop starts) forbids the tunnel outright, and the
	// hub is about to close this connection for that reason alone — not a
	// restart, not a network blip, and not something an immediate retry will
	// fix. One of TerminalReasonArchived/TerminalReasonRejected below.
	//
	// Without this, a severed agent sees a bare EOF indistinguishable from
	// "the hub process restarted" and retries every few seconds forever —
	// measured on one real deployment at 302 reconnect attempts in 10
	// minutes for a single decommissioned cluster, roughly 43,000 log lines
	// a day, and the same for every other decommissioned/rejected cluster in
	// the fleet simultaneously.
	//
	// This is the ONLY message the hub sends on a connection it is about to
	// sever this way: no Ack/Error/ToolRequest alongside it, and no
	// ClientMessage is read in response — handleConn writes it and closes,
	// before any per-connection state (internal/gateway's agentConn, the
	// tools.go connection registry) is even created.
	//
	// Purely additive, the same absent-means-unknown-or-older-agent posture
	// as AgentBuildVersion/ClusterRemediation/ClusterDetectors above: empty
	// is indistinguishable between "not a terminal message" (every
	// ServerMessage before this field existed, and every ordinary Ack/Error/
	// ToolRequest today) and "an older agent build that doesn't know to look
	// for it" — both correctly do nothing differently, so that agent falls
	// back to today's plain-EOF-and-retry-in-5s behavior, unaffected. What
	// changes is only what a build that DOES understand this field does with
	// a non-empty value — see internal/agent/client.go's runTunnelSession.
	Terminal string `json:"terminal,omitempty"`
}

// TerminalReasonArchived/TerminalReasonRejected are the two values
// ServerMessage.Terminal carries — the same two states
// internal/gateway/server.go's handleConn already refuses a tunnel for
// (clusterState == "Archived" || "Rejected"). Kept as the cluster's own state
// string (lowercased) rather than a new, separately-numbered enum, so an
// operator correlating an agent log line against the hub's clusters.state
// column never has to translate between two different vocabularies for the
// same fact.
const (
	TerminalReasonArchived = "archived"
	TerminalReasonRejected = "rejected"
)

// Heartbeat is the MVP subset of lld/03-agent-protocol.md §6's Heartbeat
// message. resource_pressure/local_queue_depth are deferred — nothing
// populates them yet (no detection layer, no local buffering to report on).
//
// Deliberately does NOT carry cluster facts, and must not grow them: it
// fires every 30s precisely because it is two cheap fields, whereas one
// facts pass is several API-server round trips (and up to ~68 on a cluster
// with the maximum namespace allowlist). Facts get their own, slower sender
// — see InventoryDelta and internal/agent's factsRefreshInterval. Anything
// added here is paid for twice a minute, per cluster, forever.
type Heartbeat struct {
	AgentVersion  string    `json:"agentVersion"`
	CertExpiresAt time.Time `json:"certExpiresAt"`

	// FindingQueue is this agent's own finding-queue depth and its running
	// total of findings discarded at the queue's capacity bound —
	// PROJECT.md B176's recorded residual: at the 5,000 hard cap the loss
	// was loud in the agent's log and reached nobody, so the hub's view of
	// a cluster stayed indistinguishable between "nothing is wrong" and
	// "this agent has been dropping findings for an hour".
	//
	// This is the one thing added to Heartbeat since the struct's own
	// "anything added here is paid for twice a minute, per cluster,
	// forever" warning, and it is added deliberately against it. That
	// warning is about COST — one facts pass is several API-server round
	// trips — and these three numbers cost a mutex-guarded read of two
	// ints that the queue already maintains (findingQueue.Stats): no
	// cluster call, no allocation beyond the struct. It is carried here
	// rather than on ClusterFacts because it is the one thing on this
	// connection that is urgent and must not depend on a facts gather
	// completing: an agent whose queue is overflowing is exactly an agent
	// under enough load for that gather to be slow or timing out.
	//
	// Omitted entirely (nil) by an agent older than this field — the same
	// nil-means-unknown convention every optional ClusterFacts field uses.
	// The hub must not substitute a zero for it: "this agent has never
	// dropped a finding" and "this agent cannot tell us" are different
	// answers, and rendering the second as the first is exactly the
	// fabricated zero this codebase refuses elsewhere.
	FindingQueue *FindingQueueStatus `json:"findingQueue,omitempty"`

	// Remediation is sent only on a remediation connection's heartbeat: what
	// the argus-remediate identity may change, asked of the API server by that
	// identity. The investigation agent's own facts can only ever describe the
	// read-only identity, so without this a split install reported no write
	// authority at all. Carried every few heartbeats, not every one, and nil
	// in between.
	Remediation *ClusterRemediation `json:"remediation,omitempty"`
}

// FindingQueueStatus is one agent's finding-queue occupancy, as that agent
// reports it — see Heartbeat.FindingQueue.
//
// All three fields are the agent's own view at the instant the heartbeat
// was built. Nothing here is a hub-side derivation, and nothing here is
// cluster data: these are counters about ARGUS's own internal plumbing, so
// this field can never become a path for unredacted cluster state (there is
// no object identity, namespace, name, message or reason anywhere in it —
// the agent log is deliberately still the only place that names WHICH
// object was discarded).
type FindingQueueStatus struct {
	// Pending is how many distinct findings are waiting to be sent right
	// now — including the ones already written to a previous, dead tunnel
	// and not yet acked, which the queue holds rather than loses
	// (PROJECT.md P21). A depth that stays near Capacity is the early
	// warning that Dropped is about to start climbing.
	Pending int `json:"pending"`
	// Dropped is the running total of findings this agent has discarded at
	// its capacity bound SINCE THE AGENT PROCESS STARTED — monotonic within
	// one agent lifetime and reset to 0 by a restart, which a consumer must
	// account for rather than reading a decrease as a recovery.
	Dropped int `json:"dropped"`
	// Capacity is the bound Dropped is counted against
	// (internal/agent's findingQueueCapacity), reported rather than assumed
	// hub-side so a depth is readable as a fraction of the real bound even
	// after an agent build changes it.
	Capacity int `json:"capacity"`
}

// AgentBuildVersion is the version the agent binary reports in AgentVersion
// above, and the value the hub's own compatibility policy
// (internal/agentversion) is expressed against.
//
// It lives HERE, in the package both halves already import, because it is a
// wire value with two readers that must never disagree: cmd/agent stamps it
// into every Heartbeat, and the hub compares it against a supported range.
// It was previously a private literal in cmd/agent/main.go that the hub side
// could not see, so the policy carried a hand-copied duplicate of it and a
// test "pinned" the two together by hardcoding the same string a third time —
// which would have kept passing after a release bumped the agent and left the
// policy behind, guarding nothing. One constant, no copies, drift impossible.
const AgentBuildVersion = "0.2.1"

// InventoryDelta carries a whole ClusterFacts payload. FullResync is always
// true, from both of the agent's senders: one on connect, one on a timer
// while connected (internal/agent's inventoryMessage is the single
// constructor both use, and factsRefreshInterval is the cadence). Neither
// diffs anything — every field is re-gathered from scratch and the hub's
// handleInventoryDelta replaces the stored cluster_facts row wholesale — so
// there is exactly one shape here and no merge semantics to get wrong.
//
// The periodic sender exists because there was none (PROJECT.md B177):
// facts reached the hub once per tunnel session, so everything derived from
// them — detector run health, and DeniedReads, the signal whose job is to
// say RBAC is blocking a detector — was frozen at the last reconnect and
// could be arbitrarily old while reading as current. Deliberately NOT folded
// into Heartbeat: the heartbeat is every 30s and exists to be cheap, while
// gathering facts costs several API-server round trips.
//
// FullResync is kept as a field rather than assumed, because a genuine
// change-triggered delta (informer-driven, false here) remains the obvious
// later optimisation; a consumer must not start reading "delta" as "the
// whole truth" in the meantime.
type InventoryDelta struct {
	Facts      ClusterFacts `json:"facts"`
	FullResync bool         `json:"fullResync"`
}

// ClusterFacts is a deliberate subset of lld/03-agent-protocol.md §8's full
// ClusterFacts schema — only what this increment's agent can gather without
// adding the full discovery/informer surface. Extending this struct toward
// the full schema (distribution, node_topology, installed_crds, ...) is
// additive, not a breaking change.
type ClusterFacts struct {
	KubernetesVersion string `json:"kubernetesVersion,omitempty"`
	NodeCount         int    `json:"nodeCount"`
	// Nodes is per-node status/resource information, using only the
	// get/list RBAC already granted to argus-investigate (core/v1 Nodes, and
	// metrics.k8s.io's pods/nodes — see deploy/helm/argus-agent/templates/
	// clusterrole.yaml). Empty (not null) whenever Reachable is false, and
	// also empty on a reachable cluster where even the node list call
	// failed (GatherFacts already reports Reachable: false in that case).
	Nodes []NodeStatus `json:"nodes"`
	// Reachable is false when the agent has no working kubeconfig/in-cluster
	// config — the agent still enrolls and heartbeats in that case (useful for
	// running this MVP without a live target cluster), it just reports no facts.
	Reachable bool `json:"reachable"`

	// Detection is the agent's RESOLVED detector timings — what this spoke is
	// actually doing, not what the hub thinks it should be doing.
	//
	// BACKLOG D5: these are per-agent environment variables by deliberate design
	// (a spoke that has lost the hub must keep detecting on last-known policy), so
	// the hub cannot know them and an operator reading the Settings page cannot
	// tell what any cluster's detection latency is. It varies by an order of
	// magnitude — CAPABILITIES.md §6 measured 61 seconds at 30/60 against roughly
	// ten to fifteen minutes at the shipped 300/600 defaults.
	//
	// Reported rather than configured, which keeps the design property intact: the
	// hub observes what the spoke decided, and cannot overrule it.
	//
	// Omitted entirely by an agent older than this field, so every consumer must
	// handle zero — see ClusterDetection.
	Detection *ClusterDetection `json:"detection,omitempty"`

	// Remediation is what the API SERVER says this agent is allowed to change,
	// asked directly rather than inferred from the chart value that was supposed
	// to grant it. See ClusterRemediation.
	//
	// Omitted entirely by an agent older than this field.
	Remediation *ClusterRemediation `json:"remediation,omitempty"`

	// DryRun is what the API SERVER says this agent may change under
	// dryRun=All only, as reported by the cluster itself — BACKLOG.md C4's
	// dry_run_patch half, and the same "ask, don't infer from the chart
	// value" discipline ClusterRemediation above already established for
	// B4. See ClusterDryRun.
	//
	// Omitted entirely by an agent older than this field, or by one whose
	// operator never set values.yaml's dryRun.enabled — both look identical
	// on the wire (nil), and both mean the same thing to a consumer: do not
	// offer dry_run_patch for this cluster.
	DryRun *ClusterDryRun `json:"dryRun,omitempty"`

	// Metrics is what the API SERVER says this agent may read from a
	// configured Prometheus service's proxy subresource — BACKLOG.md C4's
	// query_metrics half, gathered and gated the same "ask, don't infer from
	// the chart value" way DryRun is. See ClusterMetrics.
	//
	// Omitted entirely by an agent older than this field, or by one whose
	// operator never set values.yaml's metrics.prometheusService — both look
	// identical on the wire (nil), and both mean the same thing to a
	// consumer: do not offer query_metrics for this cluster.
	Metrics *ClusterMetrics `json:"metrics,omitempty"`
	// Agent is what this agent says about its own install (PROJECT.md AD10):
	// the image it runs, and whether its chart lets the hub upgrade it. Both
	// come from the chart, so they say what was configured, not what RBAC
	// would allow — an upgrade the cluster refuses still fails loudly.
	Agent *ClusterAgentInstall `json:"agent,omitempty"`

	// Detectors is this agent's own reported run health for each of ARGUS's
	// three built-in detectors — PROJECT.md T13. See ClusterDetectors.
	//
	// Omitted entirely by an agent older than this field — the same
	// nil-means-unknown convention every other optional field on this struct
	// already uses.
	Detectors *ClusterDetectors `json:"detectors,omitempty"`

	// Coverage is HOW MUCH of this cluster this agent can actually see —
	// PROJECT.md E11. See ClusterCoverage.
	//
	// Omitted entirely by an agent older than this field, same
	// nil-means-unknown convention as every other optional field here.
	Coverage *ClusterCoverage `json:"coverage,omitempty"`

	// ObjectCache is the availability of each kind in the agent's object
	// cache (internal/agent/objcache): what the cluster-insight tools and
	// views can answer from, and — for every kind not "synced" — why not.
	// Nil from an agent without the cache or with it disabled.
	ObjectCache *ClusterObjectCache `json:"objectCache,omitempty"`

	// Summary is the cluster health summary the agent computes from its
	// object cache (internal/agent/clustersummary.Summary — resource counts,
	// node version skew, NetworkPolicy coverage, GitOps controllers). Carried
	// as raw JSON so this wire package does not depend on the agent's
	// analysis packages; the hub stores and serves it as-is.
	Summary json.RawMessage `json:"summary,omitempty"`
}

// ClusterObjectCache reports the agent object cache's per-kind state.
type ClusterObjectCache struct {
	// SyncedAt is when every watched kind first finished its initial list;
	// zero while still syncing.
	SyncedAt time.Time        `json:"syncedAt,omitempty"`
	Kinds    []CacheKindState `json:"kinds"`
}

// CacheKindState is one kind's state: synced, syncing, forbidden, absent,
// disabled or error.
type CacheKindState struct {
	Group  string `json:"group,omitempty"`
	Kind   string `json:"kind"`
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// ClusterCoverage is the answer to "how much of this cluster is this agent
// watching, out of how much there is" — PROJECT.md E11.
//
// # The question it exists to answer
//
// ClusterDetectors above tells an operator whether each detector RAN.
// Coverage tells them what it ran OVER. Those are different, and the second
// one had no reporter at all: a cluster whose agent is scoped to a narrow
// ClusterRole resolves a fraction of the kinds a cluster-admin-bound one
// does (measured live 2026-09-26: 44 of 216 on a stock kind cluster), and
// every symptom of that is an ABSENCE — fewer findings, a quieter fleet
// page, an incident that never opens. A quiet cluster and a cluster where
// four fifths stopped being watched produce the same silence.
//
// tunnel.DetectorStatus.DeniedReads cannot close that gap and must not be
// stretched to try: it reports a fixed 14-entry catalogue of reads the
// built-in detectors are hardcoded to need (internal/agent's
// requiredDetectorReads), so it can never name the other 172, and a
// non-empty DeniedReads renders the whole detector as BLOCKED. A sweep that
// is running perfectly well over a narrower grant is not blocked, and
// reporting it as blocked would trade one wrong signal for another.
//
// # Two independent measurements, deliberately both
//
// Grant-shaped (KindsServed/KindsReadable) is what RBAC PERMITS, from the
// same ServerPreferredResources ∩ SelfSubjectRulesReview intersection
// internal/agent/discovery.go already computes for the watch set — no extra
// API calls. It is available as soon as the agent starts, before any sweep
// has run, and it is the number that moves when someone edits a ClusterRole.
//
// LastSweep is what the agent ACTUALLY READ on its most recent pass
// (PROJECT.md B185's positive read record). It catches everything the grant
// cannot: the memory guard declining a read (P18/P17(c)), a transient list
// failure, a kind the API server stopped serving. A grant can say "readable"
// about a kind no pass has managed to read for an hour.
//
// Neither subsumes the other, so a consumer that renders only one is showing
// half the answer.
//
// # Zero-value discipline
//
// Checked false means the agent could not run the check (discovery or the
// rules review failed, or no sweep has completed yet for LastSweep) — NOT
// "coverage is zero". A consumer must render an unchecked coverage as
// unknown, never as 0 of 0 and never as a clean bill of health, exactly as
// ClusterRemediation.Checked and DetectorStatus's zero value already
// require.
type ClusterCoverage struct {
	// Checked is true when the grant-shaped intersection below actually
	// completed. False leaves KindsServed/KindsReadable meaningless — read
	// Error for why.
	Checked bool `json:"checked"`

	// KindsServed is how many distinct resources this cluster's API server
	// both advertises AND says support get+list+watch — the denominator, and
	// what a cluster-admin-bound agent would resolve. Counted at the same
	// granularity as KindsReadable so the two are comparable.
	KindsServed int `json:"kindsServed"`

	// KindsReadable is how many of those this agent's own identity actually
	// holds get+list+watch on. The gap (KindsServed - KindsReadable) is the
	// part of the cluster nothing is watching.
	KindsReadable int `json:"kindsReadable"`

	// DeniedSample names some of the denied resources as "group/resource"
	// ("velero.io/backups", "/secrets" for a core-group resource), sorted,
	// so the gap is inspectable and not just a number. BOUNDED — see
	// DeniedSampleTruncated. Never the whole list on a cluster with many
	// CRDs: this rides the facts refresh every two minutes, and an unbounded
	// list would grow the payload with the very thing it reports on.
	//
	// These are API type identifiers (RFC 1123 subdomain charset), not
	// cluster-authored freeform text — the same class as KubernetesVersion,
	// and the reason this field needs no redaction pass. See
	// internal/agent/client.go's inventoryMessage comment, which is the
	// standing reminder for exactly this judgement.
	DeniedSample []string `json:"deniedSample,omitempty"`

	// DeniedSampleTruncated is true when DeniedSample is a prefix of a
	// longer list. Distinguishes "these are all of them" from "these are the
	// first few", which a consumer must not guess at from the length.
	DeniedSampleTruncated bool `json:"deniedSampleTruncated,omitempty"`

	// Error explains why Checked is false. Empty when Checked is true.
	Error string `json:"error,omitempty"`

	// LastSweep is what the most recent sweep pass actually read — see
	// SweepCoverage. Nil when no pass has completed a shared snapshot yet
	// (a freshly started agent, or one whose memory guard refused the
	// unstructured half outright), which is "not yet observed", not zero.
	LastSweep *SweepCoverage `json:"lastSweep,omitempty"`
}

// SweepCoverage is one sweep pass' own positive record of which watched
// kinds it managed to read — PROJECT.md B185's kindReadOK/kindForbidden/
// kindNotServed/kindNotAffordable states, counted.
//
// Every field except KindsRead is a reason a kind's contents are UNKNOWN to
// this agent right now. That distinction is the whole point of B185: an
// object of an unread kind being absent from the snapshot is a fact about
// the agent, not about the cluster, and the predicates already refuse to
// draw conclusions from it. This reports the same thing to an operator.
//
// The counts are per Kind name as the snapshot records them, so they are
// directly comparable with each other but NOT with ClusterCoverage's
// grant-shaped counts above, which count resources at discovery
// granularity. Two numbers that mean different things are deliberately not
// forced into one.
type SweepCoverage struct {
	// At is when the pass that produced these counts finished, on the
	// agent's own clock. Zero is impossible here: a nil *SweepCoverage is
	// how "no pass yet" is reported.
	At time.Time `json:"at"`
	// KindsRead is how many kinds this pass listed successfully. An empty
	// successful list counts here — "read and empty" is a real fact and a
	// different one from "not read".
	KindsRead int `json:"kindsRead"`
	// KindsForbidden is how many RBAC denied. The count E11 narrows the
	// grant to make non-zero on purpose, and the one an operator acts on by
	// editing a ClusterRole.
	KindsForbidden int `json:"kindsForbidden"`
	// KindsNotServed is how many this cluster's API server does not serve at
	// all — no CRD installed. Expected and benign on every cluster that
	// does not run the controller in question; never an error.
	KindsNotServed int `json:"kindsNotServed"`
	// KindsNotAffordable is how many the sweep memory guard declined
	// (PROJECT.md P18/P17(c)). These are readable kinds this agent could not
	// afford this pass — the actionable response is a higher memory limit,
	// not an RBAC change.
	KindsNotAffordable int `json:"kindsNotAffordable"`
	// KindsFailed is how many failed for any other reason (a transient API
	// error mid-pass, a deadline that expired part-way through the build).
	KindsFailed int `json:"kindsFailed"`
	// KindsNotListed is how many are deliberately never listed — Secret is
	// the standing example (non-negotiable 9). Reported so it is visibly a
	// CHOICE rather than silently indistinguishable from a denial.
	KindsNotListed int `json:"kindsNotListed"`
}

// ClusterDryRun is one agent's dry-run-restricted write authority — whether
// the opt-in argus-dryrun ServiceAccount's token was actually mounted into
// this agent AND the cluster's own RBAC grants it the verbs dry_run_patch
// needs, asked directly of the API server rather than inferred from the
// values.yaml toggle that was supposed to grant it (the exact failure mode
// BACKLOG B4 named for ClusterRemediation, and equally possible here: a
// hand-edited RoleBinding, a chart upgrade that reset dryRun.enabled to
// false, a mount that silently failed).
//
// This is deliberately a SEPARATE identity's answer, not a second question
// asked of ClusterRemediation's clientset. argus-dryrun and argus-remediate
// (when both are enabled) are two different ServiceAccounts specifically so
// that the ValidatingAdmissionPolicy binding argus-dryrun to "dryRun=All
// only" can never end up also matching argus-remediate's real, unrestricted
// writes — matchConditions is scoped by exact identity, and RBAC is
// additive, so merging the two into one identity would either silently
// block real remediation (if the dry-run-only policy also caught it) or
// silently stop being a restriction (if it didn't). See
// deploy/helm/argus-agent/templates/dryrun.yaml's header comment for the
// full reasoning.
type ClusterDryRun struct {
	// Checked is true when the dry-run identity's own SelfSubjectAccessReview
	// actually completed. False means "unknown" — either the argus-dryrun
	// pack was never enabled on this cluster (the expected, default case,
	// Error empty) or the check itself failed unexpectedly (Error set) — not
	// "denied". A consumer that cannot tell those apart must still treat
	// !Checked as "do not offer the tool", which is the safe direction
	// either way.
	Checked bool `json:"checked"`
	// Allowed is the API server's own answer to "can the argus-dryrun
	// identity patch a Deployment", asked the same cluster-scoped way
	// gatherRemediationAuthority already does for argus-remediate. A
	// namespace-scoped-only grant (not this pack's shipped shape, but not
	// impossible on a hand-edited cluster) answers false here, which
	// understates the real authority — the safe direction, matching
	// ClusterRemediation's own documented choice.
	Allowed bool `json:"allowed"`
	// Error explains why Checked is false when the cause was an actual
	// failure (an unreachable authorization endpoint, a malformed mount)
	// rather than the pack simply being disabled. Empty in the disabled
	// case.
	Error string `json:"error,omitempty"`
}

// ClusterMetrics is one agent's Prometheus query authority — BACKLOG.md C4's
// query_metrics half — as reported by the cluster it runs in, mirroring
// ClusterDryRun's own "ask the API server, don't infer from the chart value"
// discipline exactly: whether values.yaml's metrics.prometheusService was
// configured AND the API server actually grants this agent's own identity
// `get` on that specific Service's `proxy` subresource.
//
// Unlike ClusterDryRun, this is NOT a separate identity's answer — query_metrics
// reaches Prometheus through this agent's own primary client (the same
// argus-investigate RBAC every other read-only tool uses, narrowly widened by a
// namespace-scoped Role naming this one Service — see
// deploy/helm/argus-agent/templates/metrics.yaml), so the authorization check
// asks with that same client rather than building a second one the way
// gatherClusterDryRunAuthority has to.
type ClusterMetrics struct {
	// Checked is true when the SelfSubjectAccessReview actually completed.
	// False means "unknown" — either metrics.prometheusService was never
	// configured on this cluster (the expected, default case, Error empty) or
	// the check itself failed unexpectedly (Error set) — never "denied". A
	// consumer that cannot tell those apart must still treat !Checked as "do
	// not offer the tool", the same safe-direction rule ClusterDryRun.Checked
	// documents.
	Checked bool `json:"checked"`
	// Allowed is the API server's own answer to "can this agent's identity get
	// the configured Service's proxy subresource".
	Allowed bool `json:"allowed"`
	// Error explains why Checked is false when the cause was an actual
	// failure (an unreachable authorization endpoint, a bad kubeconfig)
	// rather than metrics.prometheusService simply being unset. Empty in the
	// unset case.
	Error string `json:"error,omitempty"`
	// External is true when the agent queries a Prometheus-compatible URL
	// outside the cluster (metrics.external, PROJECT.md PG17) rather than a
	// Service through the API server proxy. ScopedByLabel says the extraLabel
	// sent with every query was observed to be enforced: with it set, the
	// endpoint returned this cluster's series and none carrying another value.
	// LabelIgnored says an extraLabel is configured but the endpoint returned
	// series outside it, as plain Prometheus and Thanos do.
	External      bool `json:"external,omitempty"`
	ScopedByLabel bool `json:"scopedByLabel,omitempty"`
	LabelIgnored  bool `json:"labelIgnored,omitempty"`
	// Suggested is a Prometheus-compatible Service the agent found in the
	// cluster when none is configured, so the operator can set
	// metrics.prometheusService to it. Never applied automatically: the RBAC
	// grant names one Service, chosen by a person.
	Suggested *MetricsCandidate `json:"suggested,omitempty"`
}

// ClusterAgentInstall is the agent's own image and self-upgrade setting.
type ClusterAgentInstall struct {
	Image       string `json:"image,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	SelfUpgrade bool   `json:"selfUpgrade"`
	// Kubecost says the chart names a Kubecost API as the cost source
	// (PROJECT.md PG22), which needs no Prometheus.
	Kubecost bool `json:"kubecost,omitempty"`
}

// MetricsCandidate is a Service that answers the Prometheus HTTP API at its
// root: a Prometheus server, a Thanos query or a VictoriaMetrics single node.
type MetricsCandidate struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Port      int32  `json:"port"`
	Flavour   string `json:"flavour,omitempty"`
}

// ClusterRemediation is one agent's WRITE authority, as reported by the cluster
// it runs in.
//
// BACKLOG B4: whether an agent has remediation RBAC is set by the Helm value
// remediate.enabled at install time, and nothing surfaced it afterwards — so the
// console that approves remediations for a fleet could not see which clusters in
// that fleet could actually carry one out. An operator found out when an approval
// failed.
//
// This is deliberately NOT a report of the chart value. The agent asks the API
// server with a SelfSubjectAccessReview, so what arrives here is the cluster's own
// answer and stays true when the two have drifted — a hand-edited
// ClusterRoleBinding, a chart upgrade that reset the value, an admission policy
// layered on top. A claim about permissions sourced from anything other than the
// authority that enforces them is a claim that can be wrong while looking right.
//
// Checked distinguishes "asked, and the answer was no" from "never asked", which
// three false booleans cannot. Treat !Checked as unknown and say so, rather than
// telling an operator that remediation is unavailable when nobody looked.
//
// CanPatchDeployments/CanPatchStatefulSets/CanDeletePods above are deliberately
// the CLUSTER-SCOPED answer only (gatherRemediationAuthority's own comment says
// so): a namespace-scoped grant — deploy/helm/argus-agent/values.yaml's
// recommended, least-privilege remediate.namespaces shape — answers false here,
// which understates it. Namespaces below is where that understatement gets
// corrected: it does not replace these three fields, it supplements them.
type ClusterRemediation struct {
	// Checked is true when the SelfSubjectAccessReviews actually completed. False
	// means the answer below is absent, not negative.
	Checked bool `json:"checked"`
	// CanPatchDeployments covers ScaleDeployment and the annotation-bump restart.
	CanPatchDeployments bool `json:"canPatchDeployments"`
	// CanPatchStatefulSets is the same authority on the other scalable workload.
	CanPatchStatefulSets bool `json:"canPatchStatefulSets"`
	// CanDeletePods covers RestartPod, which deletes rather than patches and so is
	// a genuinely separate grant an operator can hold without the others.
	CanDeletePods bool `json:"canDeletePods"`
	// Error is why Checked is false, for display. Empty when Checked.
	Error string `json:"error,omitempty"`
	// Reporter is "remediate" when the separately deployed remediation
	// identity asked these questions about itself (Heartbeat.Remediation).
	// Empty means the investigation agent asked about its own identity, which
	// on a split install is read-only by design and answers false everywhere.
	Reporter string `json:"reporter,omitempty"`

	// Namespaces is the per-namespace breakdown behind the three fleet-wide
	// fields above, one entry per namespace the agent found a namespace-scoped
	// argus-remediate Role bound in (deploy/helm/argus-agent/templates/
	// remediate-role.yaml's shape) — each checked with the SAME three
	// SelfSubjectAccessReviews, namespace-scoped instead of cluster-scoped.
	//
	// Omitted by an agent that predates this field, AND by one that looked and
	// found no namespace-scoped Role for its own identity — those two cases are
	// indistinguishable on the wire (Go's omitempty drops a nil and an empty
	// slice alike). That is deliberate: a consumer that cannot tell "unchecked"
	// from "checked, found none" apart must still treat an absent/empty
	// Namespaces the same safe way, as "no per-namespace breakdown available" —
	// never as "this agent may change nothing anywhere." The three fleet-wide
	// fields above are unaffected either way and remain the fallback answer.
	Namespaces []NamespaceRemediation `json:"namespaces,omitempty"`
	// NamespacesTruncated is true when this agent found more candidate
	// namespaces than facts.go's maxNamespaceRemediationChecks checks in one
	// pass — Namespaces above is then a prefix (alphabetically first), not the
	// complete set, and any consumer stating a count derived from it must say
	// so rather than presenting the prefix as exhaustive.
	NamespacesTruncated bool `json:"namespacesTruncated,omitempty"`
}

// NamespaceRemediation is one namespace's write authority, asked the identical
// "ask the API server, don't infer from a chart value" way ClusterRemediation's
// own three fleet-wide fields are — the same three SelfSubjectAccessReviews,
// with ResourceAttributes.Namespace set to this namespace instead of left
// cluster-scoped.
type NamespaceRemediation struct {
	Namespace            string `json:"namespace"`
	CanPatchDeployments  bool   `json:"canPatchDeployments"`
	CanPatchStatefulSets bool   `json:"canPatchStatefulSets"`
	CanDeletePods        bool   `json:"canDeletePods"`
}

// ClusterDetection is one agent's resolved detector timings, in seconds.
//
// Zero means "this agent did not report it", not "zero seconds". Consumers must
// treat zero as unknown: BACKLOG B2's grace-period derivation falls back to its
// own default rather than computing against a zero, because a zero cooldown would
// make the derived window collapse.
type ClusterDetection struct {
	// SweepIntervalSeconds is how often the five-minute-style sweep runs.
	SweepIntervalSeconds int `json:"sweepIntervalSeconds,omitempty"`
	// SustainedThresholdSeconds is how long a swept condition must persist before
	// it becomes a Finding. The dominant term in "how long until ARGUS notices".
	SustainedThresholdSeconds int `json:"sustainedThresholdSeconds,omitempty"`
	// ResendCooldownSeconds is how often the SAME fingerprint is re-reported.
	// BACKLOG B2 needs this one specifically: validationGracePeriod's rationale is
	// "3x the resend cooldown", and that relationship breaks silently when an
	// operator changes the cooldown.
	ResendCooldownSeconds int `json:"resendCooldownSeconds,omitempty"`
}

// ClusterDetectors is one agent's own reported run health for each of
// ARGUS's three built-in detectors (PROJECT.md T13) — internal/agent's
// warning-events watch (detector.go), pod-conditions watch
// (pod_conditions_detector.go), and the periodic sweep (sweep_detector.go).
// Deliberately a fixed struct over the shipped catalogue, not a map keyed by
// an open-ended detector ID: T13's own scope excludes a detector-authoring
// registry, and a fixed shape is what makes "did we forget one" a compile
// error rather than a silent omission.
//
// Exists to answer a question none of ClusterFacts' other fields can: a
// cluster with zero recent findings is ambiguous — genuinely quiet, or a
// detector that has been failing/RBAC-denied the whole time? Each
// DetectorStatus below carries that detector's own last-success timestamp,
// most recent error, and denied reads, so a consumer can tell "confirmed
// running, nothing to report" apart from "never confirmed" apart from
// "confirmed broken" — never inferred from an absence of findings, which is
// consistent with all three.
//
// Omitted entirely (nil) by an agent older than this field — the same
// nil-means-unknown convention Detection/Remediation/DryRun/Metrics above
// already use. An agent that HAS this field always populates all three
// (there is no partial report: every build that sends ClusterDetectors sends
// one DetectorStatus per catalogue entry, even if that status is itself the
// all-zero "never observed" value) — see factsWithDetection in
// internal/agent/client.go.
type ClusterDetectors struct {
	WarningEvents DetectorStatus `json:"warningEvents"`
	PodConditions DetectorStatus `json:"podConditions"`
	Sweep         DetectorStatus `json:"sweep"`
}

// DetectorStatus is one built-in detector's own reported run health.
//
// The absent/zero-value contract, matching ClusterRemediation.Checked's own
// documented discipline exactly: a DetectorStatus with a zero LastSuccessAt
// and an empty Error is NOT a claim that this detector is failing — it is
// "this agent has not completed a run of it yet" (a freshly started agent,
// or one whose GatherFacts call raced ahead of the detector's first
// success). Never render the zero value as "healthy" OR as "failing" —
// render it as unknown/not-yet-observed, exactly like an absent pointer
// field elsewhere in this struct.
type DetectorStatus struct {
	// LastSuccessAt is the last time this detector completed a run with no
	// failure: for the two watch-based detectors (warning-events,
	// pod-conditions), the last time its watch was confirmed open and
	// receiving from the API server; for the sweep detector, the last sweep
	// pass in which no checker FAILED. Zero means "never" — see this
	// type's own doc comment for why that must not be read as "failing".
	//
	// "No checker failed" is deliberately not the same as "every checker
	// answered" (PROJECT.md P19's residual). A pass in which a checker ran
	// out of time still advances this field, and names that checker in
	// TimedOutChecks below; a pass in which a checker returned an error
	// does not advance it at all. Before TimedOutChecks existed the wire
	// had one field for both, so the only safe reading was the strict one
	// ("every checker succeeded") and a single slow List on a large cluster
	// froze this timestamp indefinitely — a detector that was running fine
	// and reporting findings the whole time looked, to the hub, like one
	// that had not run since. The two facts are now separate fields, so
	// each can mean exactly one thing: this one is "the sweep loop is
	// alive and nothing it asked for was refused", and TimedOutChecks is
	// "…but this much of the last pass is missing".
	LastSuccessAt time.Time `json:"lastSuccessAt,omitempty"`

	// Error is this detector's most recent run failure (a watch that ended
	// in error, a sweep pass with at least one failing checker), and ErrorAt
	// is when it happened. Both empty when no failure has ever been
	// recorded. Deliberately NOT cleared by a later success — an operator
	// needs "this failed at T, and has since recovered" to stay visible
	// rather than being silently overwritten the moment things start working
	// again; compare ErrorAt against LastSuccessAt to tell whether the most
	// recent attempt was the success or the failure.
	Error   string    `json:"error,omitempty"`
	ErrorAt time.Time `json:"errorAt,omitempty"`

	// TimedOutChecks names the checkers that did not answer within the
	// per-checker timeout during this detector's MOST RECENT pass — the
	// sweep detector's own checker names (internal/agent's sweepCheckers:
	// "service no endpoints", "pvc pending", …), never a GVR or a raw
	// error string. Empty for the two watch-based detectors, which have no
	// per-checker structure to report.
	//
	// PROJECT.md P19's residual, and the one field on this struct whose
	// contract is "the last pass", not "ever": a clean pass CLEARS it,
	// deliberately unlike Error/ErrorAt, which are never cleared. That is
	// the whole point — Error answers "has this ever gone wrong, and
	// when", and this answers "is a check hanging right now", which is the
	// question an operator staring at a quiet cluster actually has. A
	// consumer must therefore not treat a non-empty TimedOutChecks as
	// history: it is a live statement about the pass that ended at
	// LastSuccessAt.
	//
	// Absent/empty is, as everywhere else on this struct, two cases the
	// wire does not distinguish and a consumer must not: "the last pass
	// was complete" and "this agent predates the field". Read it together
	// with Error, which an agent of ANY build still fills in behind
	// internal/agent's stable "sweep checker timeout: " prefix for exactly
	// this case — that prefix is what a hub older than this field has, and
	// it is deliberately still written so such a hub loses nothing.
	TimedOutChecks []string `json:"timedOutChecks,omitempty"`

	// DeniedReads names the required reads (in this detector's own terms —
	// "events", "pods", "jobs", not a raw GVR) that this agent's
	// argus-investigate identity's RBAC does not currently grant, sourced
	// from internal/agent/discovery.go's existing capability-discovery
	// mechanism (ServerPreferredResources() intersected with a
	// SelfSubjectRulesReview) — never a new SelfSubjectAccessReview issued
	// just for this. Nil/empty means either "nothing is denied" or "the
	// discovered watch set was not available yet to check against" —
	// indistinguishable on the wire, like ClusterRemediation.Namespaces, and
	// a consumer must treat both the same safe way: never read an
	// absent/empty DeniedReads as a clean bill of health on its own: check
	// LastSuccessAt/Error too.
	DeniedReads []string `json:"deniedReads,omitempty"`
}

// NodeStatus is one node's readiness and resource picture. CPUAllocatable/
// MemoryAllocatable come straight from the Node object's own
// status.allocatable (always present on any node the API server returns,
// regardless of whether metrics-server is installed) and are reported
// verbatim as Kubernetes resource.Quantity strings (e.g. "4", "3920m",
// "16374636Ki") — the same units kubectl describe node shows, not a
// reinvented unit.
//
// CPUUsed/MemoryUsed come from metrics.k8s.io's NodeMetrics (usage.cpu/
// usage.memory, same Quantity string convention) and are nil whenever that
// API isn't available — most commonly because the target cluster doesn't
// run metrics-server. That is an expected, common, non-error condition: a
// node lacking metrics data degrades to Ready-only info with usage fields
// omitted, never an error and never a reason to drop the node or the whole
// facts payload.
type NodeStatus struct {
	Name              string  `json:"name"`
	Ready             bool    `json:"ready"`
	CPUAllocatable    string  `json:"cpuAllocatable,omitempty"`
	MemoryAllocatable string  `json:"memoryAllocatable,omitempty"`
	CPUUsed           *string `json:"cpuUsed,omitempty"`
	MemoryUsed        *string `json:"memoryUsed,omitempty"`
}

// ConnectionRole names what one tunnel connection is FOR — PROJECT.md E11.
//
// # Why the wire needs this at all
//
// Non-negotiable 1 asks for three separable service identities, and names
// the reason: "a compromised investigation path must never gain write access
// by itself." Until E11 the chart satisfied the letter of that (writes are
// opt-in, and the base argus-investigate ClusterRole holds no write verb)
// while breaking the spirit of it whenever remediation was enabled: one
// ServiceAccount was bound to the UNION of argus-investigate and
// argus-remediate, so the model's read-only tool loop ran under an identity
// that could also write. It was merely not TOLD to write.
//
// The fix is two identities on two connections — and the moment there are
// two connections from one cluster, the hub needs to know which is which.
// Its registry was keyed by cluster alone, so the second connection simply
// replaced the first.
//
// # What this is, and what it is NOT
//
// A declared role is ROUTING, not authorization. The hub uses it to address
// the right connection: a read-only tool goes to the investigate connection,
// a remediation action to the remediate one. It is emphatically NOT the
// thing that stops the investigation path writing — an agent that lied here
// would gain nothing, because what it can actually do to a cluster is
// decided by the ServiceAccount token its own process holds and by that
// cluster's RBAC, neither of which this string can influence.
//
// That division is the point. The security property lives in the cluster,
// where it is enforced by the API server; the wire carries only enough for
// the hub to send each request to the peer that is meant to serve it. Never
// add a check that trusts this field to decide whether something is ALLOWED
// — that would be non-negotiable 3's mistake ("MCP is an integration
// protocol, not an authorization boundary") in a new place.
const (
	// RoleInvestigate is a connection served by an identity holding
	// argus-investigate only: list/get/watch, no Secrets, no pods/exec, and
	// no create/update/patch/delete of any kind. Every read-only tool goes
	// here.
	RoleInvestigate = "investigate"

	// RoleRemediate is a connection served by the separately-deployed
	// argus-remediate identity. The only connection the hub will ever send a
	// write action to.
	RoleRemediate = "remediate"

	// RoleAll is what a connection that declared no role is treated as: one
	// agent process serving every request, which is exactly the pre-E11
	// shape. Kept, and kept working, because internal/tunnel is imported by
	// both sides and an agent in the field is upgraded on its operator's
	// schedule, not the hub's — a hub that stopped serving these would break
	// every cluster that had not been upgraded yet.
	//
	// A RoleAll connection is a correctness fallback, not a security one: it
	// is the union identity E11 exists to retire, and an operator running it
	// has the trade-off values.yaml's header describes, unchanged.
	RoleAll = "all"
)

// Hello is the first message a role-aware agent sends on a newly opened
// tunnel connection, before any Heartbeat/InventoryDelta/Finding.
//
// Optional by construction. An agent that predates it simply never sends
// one and its first message is whatever it always was; the hub then treats
// the connection as RoleAll. That is what makes this additive: a new hub
// serves an old agent, and an old hub ignores an unknown "hello" field
// entirely (encoding/json discards unknown fields by default), so a new
// agent talking to an old hub degrades to exactly the previous behaviour
// rather than failing to connect.
type Hello struct {
	// Role is one of the ConnectionRole constants above. An unrecognised
	// value is treated as RoleAll by the hub rather than rejected: a future
	// agent naming a role this hub has never heard of is better served as a
	// general-purpose connection than refused outright.
	Role string `json:"role"`
}

// writeToolRoles is the set of tool names that mutate a cluster, and so may
// only ever be dispatched to a RoleRemediate connection.
//
// Derived from internal/agent/tools.go's own dispatch switch and
// internal/remediation/plan.go's validActionTypes — the eleven typed
// remediation actions, minus the two that never reach an agent (OpenPR is a
// hub-side pull request; StructuredPatch is carried as patch_field), plus
// the two ExecutionWindow CRD writes that bracket an execution.
//
// Kept HERE, in the package both sides import, rather than in the hub or the
// agent alone, for the same reason internal/resolution.PermittedActionTypes
// is one list read by both the prompt builder and the parse-time check: two
// copies of a security-relevant classification drift, and the direction they
// drift in is always the permissive one. A tool absent from this map routes
// to RoleInvestigate, so FORGETTING to classify a new write tool sends it to
// the read-only connection, where the cluster's own RBAC refuses it. That is
// the safe direction of the mistake, and it is chosen deliberately over a
// default that would hand an unclassified tool the write connection.
var writeToolRoles = map[string]bool{
	"scale_deployment":       true,
	"restart_pod":            true,
	"patch_resource_limits":  true,
	"revert_container_image": true,
	"patch_field":            true,
	"annotate_resource":      true,
	"label_resource":         true,
	"delete_resource":        true,
	"create_resource":        true,
	// The ExecutionWindow CRD writes (PROJECT.md F14) that narrow the
	// standing ValidatingAdmissionPolicy around one execution. They are
	// served by the argus-policy-controller identity, whose token is mounted
	// beside the remediation identity, and they only ever happen bracketing
	// a remediation — so they belong on that connection, not on the
	// investigation one.
	"open_execution_window":  true,
	"close_execution_window": true,
	// PROJECT.md AD10: the remediate identity patches the agent's own two
	// Deployments to a new image, under a Role naming them both.
	"upgrade_agent": true,
	// PROJECT.md PG15: the node actions, under remediate.nodeOps' grant.
	"cordon_node": true,
	"drain_node":  true,
}

// RoleForTool says which connection role must serve a given tool.
//
// dry_run_patch is deliberately NOT a write tool here even though it submits
// write verbs: it is an INVESTIGATION tool the model may call, it runs under
// the separate argus-dryrun credential, and a ValidatingAdmissionPolicy
// scoped to that exact username restricts it to dryRun=All requests, so
// nothing it submits is ever persisted. Routing it to the remediation
// connection would put a tool the model can call on the connection the model
// must never reach.
func RoleForTool(tool string) string {
	if writeToolRoles[tool] {
		return RoleRemediate
	}
	return RoleInvestigate
}
