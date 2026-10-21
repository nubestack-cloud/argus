// Package events is the hub's live-update fan-out: a single, in-process,
// in-memory pub/sub bus that internal/api's WebSocket endpoint (GET
// /ws/events) reads from, and that every place in this codebase which
// actually changes an incident's or cluster's state (internal/gateway's
// finding/heartbeat handling, internal/gateway's health-monitor sweep,
// internal/api's cluster accept/decommission and incident analyze/approve/
// reject handlers, internal/autoanalyze's poller) publishes into.
//
// This is deliberately NOT the full pub/sub design lld/10-api-spec.md §5
// eventually calls for (per-connection subscription scope resolved against
// effective permissions, a bounded replay buffer keyed by a monotonic
// per-connection sequence number, a 60s scope-revalidation sweep) — that
// design is real and worth building once this codebase has anything that
// actually needs per-cluster subscription scoping (grants are AllClusters-
// only in the UI today; see lld/11-ui-design.md's open-decisions history)
// or runs more than one hub replica. DESIGN.md's own
// eventual design additionally expects this to ride on NATS JetStream
// once that infrastructure exists — it deliberately doesn't yet
// (docker-compose.yaml has it commented out), so building this bus on top
// of it now would be exactly the "add infra before the code that needs it"
// mistake this codebase has otherwise avoided throughout. What's here
// instead is the smallest real, working thing lld/11-ui-design.md §5's
// actual requirement ("IncidentUpdated events... trigger an in-place
// refetch... never a full page reload") needs: a mutex-guarded fan-out to
// every currently-connected WebSocket client, broadcasting to all of them
// (there is exactly one tenant, and every authenticated user can already
// see every cluster/incident per the AllClusters-only grant model above, so
// "broadcast to every connected client" and "broadcast to every client
// whose scope covers this event" are the same thing today).
//
// KNOWN, DELIBERATE LIMITATION: this bus lives entirely in one hub
// process's memory. An event published a moment before the hub restarts,
// or published on a different replica than a given browser tab's
// WebSocket happens to be connected to (this codebase runs exactly one hub
// replica today — see lld/12-deployment-design.md — so that second case
// doesn't arise yet, but would the moment it did), is simply never
// delivered to that tab. This is an accepted gap, not a bug to fix here:
// every event this bus carries is a minimal, non-authoritative "go refetch
// X" hint (per lld/11-ui-design.md §5's own framing), and every screen that
// consumes one keeps its existing REST polling running underneath as a
// slower fallback specifically so a missed/undelivered event never means a
// permanently stale page — only a page that waits for its next poll tick
// instead of updating immediately. Revisit if/when a second hub replica or
// real pub/sub infrastructure (NATS JetStream, per 04's eventual design)
// exists.
package events

import (
	"sync"
	"time"
)

// Event type names. Chosen to match lld/11-ui-design.md §5's own naming
// where it names one (IncidentUpdated); ClusterUpdated is this codebase's
// sensible extension of the same pattern to cluster lifecycle/health
// changes, which §5 doesn't separately name but which the same "trigger an
// in-place refetch" reasoning applies to just as directly.
//
// ScopeNarrowed (lld/10-api-spec.md §5, lld/11-ui-design.md §5) is
// deliberately NOT implemented here: it exists to tell a connected client
// that a grant revocation mid-session has shrunk which clusters they can
// see. Nothing in this codebase resolves per-cluster grant scope for any
// route yet (see internal/api/middleware.go's requireAuth doc comment, and
// insights.go's), and the UI only ever presents AllClusters-shaped grants
// (an explicit, earlier scope decision — see lld/11-ui-design.md's open
// decisions) — so there is no "narrower" to notify anyone about yet. Add it
// alongside whichever change actually introduces cluster-scoped grants in
// the UI, not before.
// TypeFindingRecorded (PROJECT.md F31) is deliberately lighter-weight than
// IncidentUpdated: it fires for EVERY finding handleFinding durably records,
// including the two thirds of them that never touch an incident at all
// (retained_unpromoted, suppressed) — see FindingRecorded's own doc comment
// for why IncidentUpdated alone leaves those rows with nothing published,
// and web/src/pages/SignalsPage.tsx for the one screen that reads them.
const (
	TypeIncidentUpdated = "IncidentUpdated"
	TypeClusterUpdated  = "ClusterUpdated"
	TypeFindingRecorded = "FindingRecorded"
)

// Event is the wire shape sent to every connected WebSocket client — IDs
// only, deliberately (lld/11-ui-design.md §5 frames this as "trigger an
// in-place refetch," never "replace the fetch with the WS payload"): the
// frontend always re-fetches the affected resource through its existing,
// fully-authorized REST call, and never treats this payload itself as
// authoritative data. IncidentID/ClusterID are both omitempty since a
// ClusterUpdated event carries no IncidentID and vice versa.
type Event struct {
	Type       string    `json:"type"`
	IncidentID string    `json:"incidentId,omitempty"`
	ClusterID  string    `json:"clusterId,omitempty"`
	OccurredAt time.Time `json:"occurredAt"`
}

// IncidentUpdated builds an IncidentUpdated event. Fire this whenever a new
// finding is correlated to an existing incident (or opens a new one), an
// incident's state changes, a new analysis is persisted, or an approval/
// rejection is recorded — see internal/gateway/finding.go's handleFinding,
// internal/api/analyze.go's handleAnalyzeIncident,
// internal/api/approvals.go's handleApproveIncident/handleRejectIncident,
// and internal/autoanalyze's investigateOne.
func IncidentUpdated(incidentID, clusterID string) Event {
	return Event{Type: TypeIncidentUpdated, IncidentID: incidentID, ClusterID: clusterID, OccurredAt: time.Now()}
}

// FindingRecorded builds a FindingRecorded event. Fire this at the end of
// EVERY successful handleFinding commit — whether the finding correlated to
// an incident, was retained unpromoted, or was suppressed by a toleration or
// storm protection — not only the subset IncidentUpdated already covers.
// IncidentUpdated stays published alongside it, unchanged, when a finding
// actually touched an incident; the two are independent hints, and a screen
// that cares only about incidents has no reason to also subscribe to this
// one. clusterID is enough for SignalsPage's refetch: this event, like
// IncidentUpdated, carries no data of its own and only tells a connected
// client which of its already-authorized queries to re-run.
func FindingRecorded(clusterID string) Event {
	return Event{Type: TypeFindingRecorded, ClusterID: clusterID, OccurredAt: time.Now()}
}

// ClusterUpdated builds a ClusterUpdated event. Fire this on accept,
// decommission, health-monitor state demotion (Active->Degraded,
// Degraded/Active->Disconnected), and heartbeat-driven recovery
// (Degraded/Disconnected->Active) — see internal/api/clusters.go's
// handleAcceptCluster/handleDecommissionCluster, internal/gateway/health.go's
// sweep, and internal/gateway/server.go's handleHeartbeat.
func ClusterUpdated(clusterID string) Event {
	return Event{Type: TypeClusterUpdated, ClusterID: clusterID, OccurredAt: time.Now()}
}

// subscriberBufferSize bounds how many not-yet-delivered events one
// subscriber can accumulate before Publish starts dropping THAT
// subscriber's events specifically — never blocking Publish itself, and
// never affecting any other subscriber. 16 is generous relative to this
// codebase's actual event rate (state changes on incidents/clusters, not a
// high-frequency stream) while still bounding memory for a client that's
// stopped reading (a browser tab that's asleep, a half-closed TCP
// connection the read side hasn't noticed yet).
const subscriberBufferSize = 16

// Bus is a single hub-side in-memory event fan-out: every Publish call
// delivers (or, for a stalled subscriber, best-effort attempts to deliver —
// see subscriberBufferSize) one Event to every currently-Subscribed
// channel. Safe for concurrent use; mu guards subs/next exactly as this
// package's own doc comment promises ("a simple fan-out to connected WS
// clients, guarded by a mutex").
type Bus struct {
	mu   sync.Mutex
	subs map[int64]chan Event
	next int64
}

// NewBus constructs an empty Bus, ready to Publish/Subscribe against
// immediately.
func NewBus() *Bus {
	return &Bus{subs: make(map[int64]chan Event)}
}

// Subscribe registers a new subscriber and returns a receive-only channel
// of every Event published from this point on, plus an unsubscribe
// function the caller MUST call exactly once when done (typically in a
// defer immediately after Subscribe returns) to release the subscription
// and let this Bus stop tracking it. The returned channel is closed by
// unsubscribe, never independently — a subscriber's range/receive loop can
// rely on channel closure to mean "unsubscribed," not "the bus itself
// stopped."
func (b *Bus) Subscribe() (<-chan Event, func()) {
	b.mu.Lock()
	id := b.next
	b.next++
	ch := make(chan Event, subscriberBufferSize)
	b.subs[id] = ch
	b.mu.Unlock()

	var once sync.Once
	unsubscribe := func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			if existing, ok := b.subs[id]; ok {
				delete(b.subs, id)
				close(existing)
			}
		})
	}
	return ch, unsubscribe
}

// Publish delivers e to every currently-subscribed channel. Never blocks:
// a subscriber whose buffered channel is already full (subscriberBufferSize)
// simply misses this one event rather than stalling every other
// subscriber, or the publishing call site itself, on a reader that isn't
// keeping up — see this package's doc comment for why that's an acceptable
// trade for this codebase's actual event shape (a minimal, non-
// authoritative refetch hint, with REST polling as an always-present
// fallback).
//
// Subscribe/unsubscribe and Publish all take the same mutex, so a Publish
// in progress can never observe a channel being closed out from under it
// (unsubscribe cannot proceed until Publish's current pass over subs
// releases the lock) — this is what makes it safe for Publish to send on a
// channel it just read from subs without a separate closed-channel check.
func (b *Bus) Publish(e Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// SubscriberCount reports how many subscribers are currently registered —
// exposed for tests and for a future health/metrics endpoint, not used by
// any production decision today.
func (b *Bus) SubscriberCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs)
}
