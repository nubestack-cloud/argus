package agent

// finding_queue.go decouples the three detector goroutines
// (detector.go's warning-event watch, pod_conditions_detector.go's pod
// watch, sweep_detector.go's periodic sweep) from the single goroutine that
// writes them onto the tunnel (client.go's runTunnelSession).
//
// PROJECT.md B176. What used to sit here was one 100-slot channel plus a
// non-blocking send: a Finding that arrived with the buffer full was
// discarded, logged as a bare fingerprint, and — because each detector
// stamped lastSent[fp] BEFORE attempting the send — entered the 5-minute
// resend cooldown as though it had been delivered, so the next sweep
// suppressed it as a duplicate. Measured on the real rke2 agent: 571
// discarded findings in one log, 545 of them inside four hours, against
// sweeps of 111-185 findings.
//
// The mechanism is a producer/consumer RATE mismatch, not a stalled reader,
// and that matters for the fix. In every one of those minutes the tunnel was
// healthy, heartbeats were acked, and there was NO tool traffic at all: a
// sweep builds its whole batch in a tight in-memory loop while the tunnel
// writer has to do a TLS write per finding, so the producer put ~185 findings
// into a 100-slot channel in the time the consumer drained about a dozen.
// Raising the buffer only moves that cliff; the loss is quadratic in nothing
// and linear in "how broken is the cluster", which is exactly the moment the
// product must not go quiet.
//
// So the queue is no longer the handoff. A pump goroutine (Run, below) sits
// between the two: it drains the producer channel at memory speed into a
// FIFO it owns, and offers the head of that FIFO to the tunnel writer. A
// detector can never outrun a consumer that only has to do a slice append,
// and a disconnected tunnel no longer means "no reader" — the pump keeps
// accepting while nothing is being sent, so findings produced during a
// reconnect survive it instead of being discarded 100 at a time.
//
// Two properties keep that from becoming an unbounded buffer in a pod with a
// 256Mi limit (deploy/helm/argus-agent/values.yaml):
//
//   - Coalescing by fingerprint. The resend cooldown and the sweep interval
//     are both 5 minutes by default, so a persistently-broken object is
//     re-reported by every single sweep. While the tunnel is down those
//     repeats would otherwise stack up and be replayed as a stale flood on
//     reconnect. A finding whose fingerprint is already pending REPLACES the
//     pending copy in place — newest object state wins, queue position is
//     kept (so no detector's findings can be starved by another's), and the
//     OccurrenceCount of the copy it replaced is carried forward so the count
//     of observations is not silently lost. The queue is therefore bounded by
//     the number of distinct simultaneously-broken objects in the cluster,
//     not by how long the hub has been unreachable.
//   - A hard cap (findingQueueCapacity). At the cap the OLDEST pending
//     finding is discarded — it is the most stale, and the newest report of
//     the same problem is the one worth having — and the discard is logged
//     with the object's identity and reason rather than a bare fingerprint,
//     plus a running total. See findingQueueCapacity for what that bound
//     actually costs in practice.
//
// Delivery is held open until the hub says it took the finding
// (PROJECT.md P21). Taking a finding off Out() is no longer the end of this
// queue's responsibility for it: the tunnel session stamps it with a
// correlation id, records it in a findingInflight (below), and only
// considers it delivered when the hub echoes that id back on an Ack — which
// internal/gateway only sends once handleFinding has actually returned
// without error. Everything still unacked when a session dies goes straight
// back onto this queue, where it coalesces and is bounded exactly like a
// freshly detected finding, and is redelivered by the next session. What
// used to be "one finding lost per disconnect, re-derived by the next
// sweep" is now "one finding redelivered per disconnect".
//
// The cost of that, stated plainly, is at-least-once rather than
// exactly-once: an ack lost in flight (the connection dying between the
// hub's write and the agent's read) means the hub sees that finding twice.
// That is the safe direction and it is not a new shape of traffic — the
// resend cooldown already re-reports a persistently-broken object every
// five minutes, so the hub's correlation path (internal/gateway/finding.go,
// keyed on fingerprint) has always had to be duplicate-tolerant. The
// visible effect of a duplicate is an occurrence count that counts one
// observation twice, which is a far smaller lie than a finding that never
// arrives at all.

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"argus/internal/tunnel"
)

const (
	// findingHandoffBufferSize is the producer-facing channel's buffer. It
	// is small on purpose: it is not where findings wait, it only absorbs
	// the gap between a producer's send and the pump being scheduled. The
	// real queue is the pump's own FIFO.
	findingHandoffBufferSize = 256

	// findingQueueCapacity bounds how many DISTINCT pending fingerprints
	// the pump will hold before it starts discarding the oldest.
	//
	// What happens at the bound, stated plainly: beyond 5,000 distinct
	// broken objects with nowhere to send them, ARGUS resumes losing
	// findings, oldest first, and says so in the agent log with the object
	// and a running total — it does not go quiet. That bound is not the
	// same kind of number as the 100-slot buffer it replaces. The 100 was
	// reached by an ordinary sweep on an ordinary cluster (111-185
	// findings, i.e. it was exceeded roughly every five minutes). 5,000 is
	// 27x the worst real sweep measured, and because of the coalescing
	// above it is NOT consumed by time: a three-hour outage on the rke2
	// cluster leaves the queue holding the same ~185 entries it held after
	// the first sweep, not 185 x 36. Reaching it requires a cluster in
	// which five thousand distinct objects are simultaneously and
	// sustainedly broken, which is a different event from the one this
	// defect is about.
	//
	// Sized against memory, not taste: the agent pod's limit is 256Mi and a
	// Finding is dominated by its Message (cluster-authored text, typically
	// well under 1KiB). 5,000 of them is single-digit megabytes. A cap ten
	// times larger would trade a bound nobody hits for an OOMKill, which
	// loses the whole queue AND restarts the agent.
	findingQueueCapacity = 5000

	// findingHighWaterLogStep is how far the pending depth must climb
	// before the pump logs another high-water line. A queue that is
	// growing is the early warning for the cap above; a queue that is
	// growing and logging once per finding is just noise.
	findingHighWaterLogStep = 500
)

// findingEmitTimeout bounds how long a detector goroutine will wait for room
// on the handoff channel before giving up on a finding.
//
// Under normal operation this is unreachable: the pump's only blocking
// operation is offering the FIFO head to the tunnel, and it selects on the
// handoff channel in the same statement, so room appears within a scheduling
// quantum whether or not the tunnel is up. The wait exists so that a pump
// that is genuinely gone (its context cancelled at process shutdown) can
// never wedge a detector's watch loop forever — the failure mode the old
// non-blocking send was reaching for, without the cost of discarding a
// finding the instant a burst outpaces a TLS write.
//
// A var rather than a const only so tests can drive the give-up path
// directly instead of waiting it out.
var findingEmitTimeout = 5 * time.Second

// emitFinding delivers f to the finding queue and reports whether it was
// accepted. Callers MUST NOT record f's fingerprint into their lastSent
// cooldown map unless this returns true — a finding that was not delivered
// is not a finding that was sent, and treating it as one is the half of
// B176 that turned a transient overflow into permanent silence for that
// object until its fingerprint changed.
func emitFinding(f tunnel.Finding, findingCh chan<- tunnel.Finding) bool {
	select {
	case findingCh <- f:
		return true
	default:
	}
	timer := time.NewTimer(findingEmitTimeout)
	defer timer.Stop()
	select {
	case findingCh <- f:
		return true
	case <-timer.C:
		logger.Warn("finding queue did not accept a finding in time — dropping; it will be re-reported by the next sweep because it is NOT entering the resend cooldown",
			slog.Duration("timeout", findingEmitTimeout), slog.String("detector_id", f.DetectorID), slog.String("gvk", f.GVK),
			slog.String("namespace", f.Namespace), slog.String("name", f.ObjectName), slog.String("reason", f.Reason), slog.String("fingerprint", f.Fingerprint))
		return false
	}
}

// findingQueue is the pump described at the top of this file. Everything
// except Stats is touched by exactly one goroutine (Run's), which is why
// pending/index/base carry no locking.
type findingQueue struct {
	in  chan tunnel.Finding
	out chan tunnel.Finding

	capacity int

	// pending is the FIFO; pending[0] is the next finding offered to the
	// tunnel. index maps a pending fingerprint to its ABSOLUTE sequence
	// number, and base is the absolute sequence of pending[0] — absolute
	// numbering so that dequeuing the head does not require rewriting every
	// other entry's position.
	pending []tunnel.Finding
	index   map[string]int
	base    int

	highWater int

	mu         sync.Mutex
	dropped    int
	pendingLen int
}

func newFindingQueue(capacity int) *findingQueue {
	return &findingQueue{
		// Unbuffered out: a finding stays in pending, and stays
		// coalescable, until the tunnel writer has actually taken it.
		in:       make(chan tunnel.Finding, findingHandoffBufferSize),
		out:      make(chan tunnel.Finding),
		capacity: capacity,
		index:    make(map[string]int),
	}
}

// In is the producer end, handed to every detector goroutine.
func (q *findingQueue) In() chan<- tunnel.Finding { return q.in }

// Out is the consumer end, handed to serveTunnelForever and read by
// runTunnelSession's select loop. It outlives any single tunnel session, so
// a finding offered while no session is up simply waits for the next one.
func (q *findingQueue) Out() <-chan tunnel.Finding { return q.out }

// Stats reports the current pending depth and the running total of findings
// this queue has had to discard at its capacity bound. Safe to call from any
// goroutine.
func (q *findingQueue) Stats() (pending, dropped int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.pendingLen, q.dropped
}

// Run is the pump. It never blocks on the tunnel while a producer has work
// for it: both cases are in one select, so accepting from in is always
// available regardless of whether anything is reading out.
func (q *findingQueue) Run(ctx context.Context) {
	for {
		if len(q.pending) == 0 {
			select {
			case <-ctx.Done():
				return
			case f := <-q.in:
				q.enqueue(f)
			}
			continue
		}
		select {
		case <-ctx.Done():
			return
		case f := <-q.in:
			q.enqueue(f)
		case q.out <- q.pending[0]:
			q.dequeue()
		}
	}
}

// enqueue appends f, coalescing onto an already-pending finding with the
// same fingerprint, and enforcing the capacity bound by discarding the
// oldest entry.
func (q *findingQueue) enqueue(f tunnel.Finding) {
	if f.Fingerprint != "" {
		if seq, ok := q.index[f.Fingerprint]; ok && seq >= q.base && seq-q.base < len(q.pending) {
			prior := q.pending[seq-q.base]
			if f.OccurrenceCount < 1 {
				f.OccurrenceCount = 1
			}
			if prior.OccurrenceCount > 0 {
				f.OccurrenceCount += prior.OccurrenceCount
			}
			q.pending[seq-q.base] = f
			return
		}
	}

	if len(q.pending) >= q.capacity {
		q.discardOldest()
	}

	if f.Fingerprint != "" {
		q.index[f.Fingerprint] = q.base + len(q.pending)
	}
	q.pending = append(q.pending, f)
	q.noteDepth()
}

// discardOldest removes pending[0] because the queue is at capacity, and
// says so with enough detail for an operator to know WHICH object stopped
// being reported — the old log line carried a fingerprint and nothing else,
// which is unresolvable without the hub.
func (q *findingQueue) discardOldest() {
	victim := q.pending[0]
	q.removeHead()

	q.mu.Lock()
	q.dropped++
	total := q.dropped
	q.mu.Unlock()

	logger.Warn("finding queue at capacity — discarding the oldest finding",
		slog.Int("capacity", q.capacity), slog.String("detector_id", victim.DetectorID), slog.String("gvk", victim.GVK),
		slog.String("namespace", victim.Namespace), slog.String("name", victim.ObjectName), slog.String("reason", victim.Reason),
		slog.String("fingerprint", victim.Fingerprint), slog.Int("total_discarded", total))
}

// dequeue removes the head after the tunnel writer has taken it.
func (q *findingQueue) dequeue() {
	q.removeHead()
	q.noteDepth()
}

func (q *findingQueue) removeHead() {
	head := q.pending[0]
	if head.Fingerprint != "" {
		if seq, ok := q.index[head.Fingerprint]; ok && seq == q.base {
			delete(q.index, head.Fingerprint)
		}
	}
	// Re-slicing keeps the head O(1); appending past the end periodically
	// reallocates, which is what releases the consumed prefix. Bounded by
	// capacity, so the transient retention is bounded too.
	q.pending = q.pending[1:]
	q.base++
	if len(q.pending) == 0 {
		// Reset so a long-lived quiet agent does not keep a capacity-sized
		// backing array (and a stale index) alive forever.
		q.pending = nil
		q.index = make(map[string]int)
	}
}

// noteDepth publishes the pending depth for Stats and logs each new
// high-water step, which is the only early warning an operator gets before
// the capacity bound starts discarding.
func (q *findingQueue) noteDepth() {
	depth := len(q.pending)

	q.mu.Lock()
	q.pendingLen = depth
	q.mu.Unlock()

	if depth >= q.highWater+findingHighWaterLogStep {
		q.highWater = depth - depth%findingHighWaterLogStep
		logger.Warn("finding queue depth rising — findings are being produced faster than the tunnel is draining them, or the tunnel is down; nothing is being lost yet",
			slog.Int("depth", depth), slog.Int("capacity", q.capacity))
	}
	if depth == 0 {
		q.highWater = 0
	}
}

// maxUnackedFindings bounds how many findings one tunnel session will put on
// the wire before it stops taking new ones off the queue and waits for acks
// to catch up — the send window PROJECT.md P21's hold-until-acked rule needs
// in order not to reintroduce the unbounded buffer B176 removed.
//
// Without it, a hub that accepts bytes but stops acking (a stalled
// handleFinding, a Postgres that has gone away, findingSem saturated by a
// storm) would let a sweep hand the session all 5,000 queued findings, every
// one of which the session must then hold in memory IN ADDITION to whatever
// the queue itself is holding — the queue's own cap would bound nothing,
// because the findings would no longer be in the queue. With the window, an
// unacking hub simply stops the session draining, findings stay in the
// queue, and the queue's existing coalescing and capacity bound keep doing
// exactly what they already do.
//
// 64 rather than 1: the hub processes findings concurrently
// (internal/gateway's findingSem, 8 at a time) and acks each as it finishes,
// so a window of one would serialise a sweep's whole batch behind a full
// round trip each and make a 185-finding sweep take 185 round trips. 64 is
// comfortably above that concurrency, so acks return faster than the window
// fills on a healthy hub, and it is small enough that the memory a session
// can hold outside the queue stays trivial next to the queue's own bound.
const maxUnackedFindings = 64

// findingInflight is one tunnel session's record of the findings it has
// written but not yet had acked — the "held until the hub acks its
// correlation id" half of PROJECT.md P21.
//
// Touched by exactly one goroutine (runTunnelSession's own select loop:
// add on send, ack on an incoming Ack routed to it, returnAll on the way
// out), which is why nothing here is locked — the same single-writer
// discipline that lets that loop own the session's json.Encoder.
//
// Lives in this file rather than in client.go because it is part of the
// queue's contract, not the session's: the queue is what promises a
// detected finding reaches the hub, and this is where that promise is kept
// across a disconnect. A session ending is not a reason to drop anything —
// returnAll puts every unacked finding back into the queue it came from.
type findingInflight struct {
	// tag distinguishes one session's ids from another's, so a stray ack
	// decoded from a previous connection could never match an id minted by
	// this one. Not a security property (the tunnel is mTLS and a new
	// session is a new connection) — purely so that a log line naming a
	// correlation id is unambiguous when read across a reconnect.
	tag   string
	seq   uint64
	order []string
	byID  map[string]tunnel.Finding
}

func newFindingInflight() *findingInflight {
	tag, err := randomHex(4)
	if err != nil {
		// A correlation id only has to be unique within this process, so a
		// failed crypto/rand read is no reason to refuse to send findings —
		// the clock is a perfectly good tiebreaker for that job.
		tag = strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return &findingInflight{tag: tag, byID: make(map[string]tunnel.Finding)}
}

// add records f as sent-but-unacked and returns the correlation id the hub
// must echo for it. Call it immediately BEFORE the encode, not after: a
// finding recorded only on a successful write is a finding lost by exactly
// the failure this exists to survive.
//
// f is stored by value, and the caller passes it BEFORE applying the
// tunnel writer's redaction pass — see that call site in client.go for why
// (this predates B182's idempotency fix, and survives it: redacting once at
// the single egress chokepoint keeps the queue's contents raw, so a later
// pattern change reaches a redelivered finding too). Egress is unaffected:
// the redaction statement is still the last thing before the encode, on
// every send.
func (i *findingInflight) add(f tunnel.Finding) string {
	i.seq++
	id := fmt.Sprintf("fnd-%s-%d", i.tag, i.seq)
	i.order = append(i.order, id)
	i.byID[id] = f
	return id
}

// ack marks the finding named by id as delivered and reports whether this
// session was in fact waiting on that id. False is normal, not an error: the
// hub acks heartbeats and inventory deltas too (with the empty id those
// carry), and a duplicate or late ack matches nothing.
func (i *findingInflight) ack(id string) bool {
	if id == "" {
		return false
	}
	if _, ok := i.byID[id]; !ok {
		return false
	}
	delete(i.byID, id)
	for n, pending := range i.order {
		if pending == id {
			i.order = append(i.order[:n], i.order[n+1:]...)
			break
		}
	}
	return true
}

// drainAcks applies every ack already waiting on ch, without blocking.
// Used on the way out of a session: an ack the read goroutine decoded a
// moment before the connection died is information this agent already has,
// and throwing it away would cost a redelivery for nothing.
func (i *findingInflight) drainAcks(ch <-chan string) {
	for {
		select {
		case id := <-ch:
			i.ack(id)
		default:
			return
		}
	}
}

func (i *findingInflight) len() int { return len(i.byID) }

// returnAll puts every still-unacked finding back on q, oldest first, and
// reports how many. Called on the way out of a session — normal end, read
// error, terminal signal or process shutdown alike; a finding the hub never
// confirmed is pending regardless of WHY the session ended.
//
// Back onto q.In(), deliberately, rather than into some session-spanning
// side buffer: In() is the one door through which coalescing, the capacity
// bound and the depth/drop accounting all apply, so a redelivered finding is
// subject to exactly the same rules as a freshly detected one. In
// particular, if the same object has been re-detected while the tunnel was
// down, the newer report wins and carries the older one's occurrence count
// forward — which is the behaviour that keeps a long outage from replaying
// as a stale flood.
//
// Not a drop path: if ctx is already done the process itself is shutting
// down and the queue is going away with it, so there is nowhere to put
// these and nothing that could send them.
func (i *findingInflight) returnAll(ctx context.Context, q *findingQueue) int {
	returned := 0
	for _, id := range i.order {
		f, ok := i.byID[id]
		if !ok {
			continue
		}
		select {
		case q.In() <- f:
			returned++
		case <-ctx.Done():
			i.order = nil
			i.byID = make(map[string]tunnel.Finding)
			return returned
		}
	}
	i.order = nil
	i.byID = make(map[string]tunnel.Finding)
	return returned
}
