package agent

// sweep_memory.go is PROJECT.md P18: this agent holds whole cluster-wide
// object lists in memory during a sweep, inside a pod with a memory limit,
// and until this file existed nothing connected those two facts.
//
// # Why an OOMKill is the worst possible failure here
//
// It is not a clean error. The kernel takes the process mid-pass, which
// discards sweep_detector.go's in-memory firstObserved/lastSent maps and
// finding_queue.go's pending FIFO. The agent comes back with no memory of
// what it had already reported, so the next pass re-reports everything that
// is still broken — a detection OUTAGE that presents to an operator as a
// detection FLOOD. Refusing a pass and saying so is strictly better: the
// process survives, the dedup state survives, and the reason is a sentence
// an operator can read on the cluster's own detector status
// (tunnel.DetectorStatus.Error) instead of a `Reason: OOMKilled` with no
// attribution to anything ARGUS did.
//
// # The three mechanisms here, in the order they engage
//
//  1. A Go soft memory limit (applyGoSoftMemoryLimit), set from the pod's own
//     cgroup limit at startup. Without it the Go GC targets 2x the live heap
//     and cheerfully grows RSS past a container limit it knows nothing about;
//     with it, the runtime collects harder as it approaches the limit instead
//     of letting the kernel decide. This alone converts a large class of
//     OOMKills into "the agent is slow for a few seconds".
//  2. The sweep memory guard (sweepMemoryGuard), which refuses to START a
//     read it can already tell will not fit, with a named reason. This is
//     the part that turns an unsurvivable pass into a survivable,
//     attributable, partial one: at 256Mi on a 5,000-pod cluster the 17
//     hand-written checks still run, and so do the declarative rules — which
//     since PROJECT.md P28 read the shared unstructured snapshot when there
//     is room for it and fall back to listing their own kinds, priced one at
//     a time, when there is not. Either way the operator is told which reads
//     did not happen.
//  3. The chart default (deploy/helm/argus-agent/values.yaml), sized against
//     the measured table in sweep_memory_live_test.go so that at the
//     documented cluster ceiling nothing is refused at all — 2 is what
//     happens ABOVE that ceiling, not a routine part of a pass.
//
// The guard is NOT a substitute for bounding the read itself. Pagination
// (PROJECT.md P17(c)) is what would make a single cluster-wide list fit in a
// fixed working set; until it lands, the honest position is "measured
// ceiling, documented, refused past it", which is what this file implements.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"argus/internal/logging"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

const (
	// goSoftMemoryLimitFraction is how much of the container's memory limit
	// the Go runtime is told it may use (GOMEMLIMIT). The remainder covers
	// what the Go heap accounting does not: the binary's own text and data,
	// thread stacks, and the kernel's page-cache charges against this
	// cgroup. 0.9 is the conventional headroom for a Go server with no cgo
	// and no large mmap'd files, which describes this agent exactly.
	goSoftMemoryLimitFraction = 0.9

	// minNonHeapReserve is the floor under that remainder, in bytes.
	//
	// A fraction is the wrong shape for this quantity and only looks right
	// at comfortable limits. What it has to cover — the mapped binary, the
	// Go runtime's own structures, goroutine stacks, the HTTP client's read
	// buffers — barely changes with the container limit, so at 1Gi the 10%
	// is a hundred megabytes of slack and at 200Mi it is twenty, which is
	// LESS than the thing it is reserving for.
	//
	// Measured on the 2,030-pod cluster (sweep_memory_live_test.go now
	// reports it every pass): immediately after a collection, with a 13Mi
	// live heap, this process held 28Mi that was not heap. Reserving 32Mi
	// makes the guard's budget something the runtime can actually defend at
	// a 200Mi limit, where a 20Mi reserve made it arithmetically impossible
	// — the agent was told it could use 180Mi of a 200Mi limit while 28Mi of
	// that limit was already spoken for, and PROJECT.md B187's OOMKill was
	// partly that, not only the headroom factor.
	//
	// 32Mi is also exactly 10% of 320Mi, so the two rules meet without a
	// discontinuity: at and above that limit the fraction governs and
	// nothing about the guard's behaviour changes, which is why this cannot
	// regress the 320Mi and 512Mi measurements the factors were calibrated
	// against.
	minNonHeapReserve = 32 << 20

	// The decode headroom factors are how much memory a read TRANSIENTLY
	// needs relative to the live heap it ends up holding. Decoding a
	// Kubernetes list allocates roughly 2.66x what it retains — measured
	// both ways on the 2,030-pod cluster below, 117Mi of allocation for a
	// 44Mi typed result and 514Mi for a 193Mi unstructured one — and the
	// runtime can only collect that garbage if there is room to collect it
	// in.
	//
	// # There are two factors because one number provably cannot cover both
	//
	// PROJECT.md B187 asked whether the TYPED and UNSTRUCTURED halves need
	// separate factors. Measured, they do not: the allocation-to-retention
	// ratio is 2.66x for both (the halves differ in bytes per OBJECT —
	// typedLiveBytesPerObject vs unstructuredLiveBytesPerObject — which was
	// already priced separately). What actually needs two numbers is the
	// SHAPE of the read:
	//
	//   - One cluster-wide List, decoded inside a single json.Unmarshal of a
	//     single response body. The collector cannot get ahead of it, so the
	//     whole allocation volume is effectively in flight at once.
	//   - A read assembled from many per-kind Lists (listWatchedKindObjects'
	//     21 of them). There is a collection point between every kind, so
	//     only one kind's garbage is ever in flight and the peak tracks the
	//     RETAINED total rather than the allocated one.
	//
	// Both numbers below come from the same live 2,030-pod cluster, measured
	// in a container at a real cgroup limit (sweep_memory_live_test.go's
	// TestLiveSweepUnderMemoryLimit, 2026-09-25), because that is the only
	// configuration in which the Go soft memory limit is actually engaged.
	//
	// singleListDecodeHeadroomFactor: the declarative-rule fallback path's
	// one unstructured cluster-wide Pod list retains ~99Mi and peaked at
	// 243-255Mi, flat across container limits from 240Mi to 304Mi —
	// 2.47x. Rounded up to the measured 2.66x allocation ratio, because
	// rounding the other way is the OOMKill this file exists to prevent.
	//
	// The old single factor of 1.4 was this number, measured on the
	// many-kind read and then applied to single lists as well. That is
	// precisely the bug B187 reports: at a 200Mi limit on this cluster the
	// guard refused the many-kind half (correctly) and then admitted the
	// fallback loop's single Pod list at 99Mi x 1.4 = 139Mi against a 180Mi
	// budget — a read whose real cost is ~245Mi. The agent was killed
	// instead of refusing. With 2.6 that read needs 258Mi and is refused.
	singleListDecodeHeadroomFactor = 2.6

	// multiKindDecodeHeadroomFactor prices listWatchedKindObjects' one
	// all-or-nothing read of every watched kind. Measured at a 320Mi
	// container limit: 198Mi projected, 197Mi actually retained, 266-270Mi
	// peak in-use across two passes — 1.36x, and the pass completes with
	// nothing refused. 1.4 is the round number just above it, and it is the
	// same 1.4 that was here before; what changed is that it now applies
	// only to the read it was measured on.
	//
	// Checked for over-refusal, which is the failure mode a too-large factor
	// causes: at 512Mi the same half peaks at 363-395Mi and must NOT be
	// refused. It is not (198 x 1.4 = 277Mi against a 461Mi budget). At
	// 2.6 it would have been, which is the direct evidence that one factor
	// cannot honestly cover both shapes.
	multiKindDecodeHeadroomFactor = 1.4
)

// errSweepMemoryBudget is the sentinel every refusal in this file wraps, so
// a caller can tell "this agent declined to perform the read" from "the API
// server refused it" — two completely different operator actions (give the
// agent more memory / fix RBAC) that would otherwise arrive as the same
// opaque check failure.
var errSweepMemoryBudget = errors.New("sweep refused to protect the agent's memory limit")

// --- reading the container's own limit ---

// cgroupMemoryLimitPaths are read in order; the first that yields a finite
// number wins. cgroup v2's memory.max is the normal case on any cluster a
// current Kubernetes runs on, and inside a container it is the POD's limit
// rather than the host's, because the container has its own cgroup
// namespace. The v1 path is kept for older node OSes, where "no limit" is
// spelled as a number near 2^63 rather than as "max".
var cgroupMemoryLimitPaths = []string{
	"/sys/fs/cgroup/memory.max",
	"/sys/fs/cgroup/memory/memory.limit_in_bytes",
}

// cgroupUnlimited is the threshold above which a cgroup v1 limit is "no
// limit at all" rather than a real ceiling. The kernel reports
// PAGE_COUNTER_MAX there, which varies with page size, so this compares
// against a generous power of two rather than an exact constant.
const cgroupUnlimited = uint64(1) << 62

// containerMemoryLimit returns this process' own cgroup memory limit and
// whether one is actually set. A host-run agent (RUNBOOK.md's host-run hub
// setup, a developer's laptop, a `go test`) has no limit, which is reported
// honestly as false rather than as some invented default — every consumer
// here treats "unknown" as "do not guard", because a guard built on a
// fabricated limit would refuse real work for no reason.
func containerMemoryLimit() (uint64, bool) {
	for _, path := range cgroupMemoryLimitPaths {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		text := strings.TrimSpace(string(raw))
		if text == "max" {
			return 0, false
		}
		v, err := strconv.ParseUint(text, 10, 64)
		if err != nil || v == 0 || v >= cgroupUnlimited {
			continue
		}
		return v, true
	}
	return 0, false
}

// --- reading what this process currently holds ---

// processMemoryInUse returns the bytes the Go runtime currently holds from
// the operating system: everything it has mapped, minus what it has already
// handed back. That is deliberately NOT the live heap — the live heap is
// what a GC would keep, and the kernel does not OOM-kill on what a GC would
// keep. It kills on what is mapped and resident right now, which includes
// every byte of decode garbage produced since the last collection.
//
// Cheap enough to call before each list in a pass: runtime/metrics reads
// these two classes from counters the runtime already maintains, with no
// stop-the-world (unlike runtime.ReadMemStats, which is why this does not
// use it).
func processMemoryInUse() uint64 {
	samples := []metrics.Sample{
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
	}
	metrics.Read(samples)
	if samples[0].Value.Kind() != metrics.KindUint64 || samples[1].Value.Kind() != metrics.KindUint64 {
		return 0
	}
	total, released := samples[0].Value.Uint64(), samples[1].Value.Uint64()
	if released > total {
		return 0
	}
	return total - released
}

// liveHeapBytes returns the bytes the last completed garbage collection
// found still reachable — the part of this process' memory that CANNOT be
// reclaimed no matter how hard the runtime tries.
//
// This, not processMemoryInUse, is what the guard decides on, and the
// distinction is the whole reason both exist. Total in-use memory includes
// decode garbage, and a Go runtime under a soft memory limit collects that
// garbage rather than growing — measured on the 5,000-pod synthetic cluster
// (sweep_memory_live_test.go), the same unstructured half peaked at 1069Mi
// with no soft limit and at 620Mi with one, holding an identical 465Mi live.
// Refusing on the 1069 would decline passes the runtime can comfortably
// complete; refusing on the 465 declines exactly the passes where there is
// not enough irreducible room left, which is the condition that actually
// ends in an OOMKill.
//
// Fresh enough to decide on: it is exact as of the last GC, and a pass that
// is allocating hard enough to matter triggers GCs constantly. admit forces
// one before it refuses anything, so a stale reading can delay a refusal but
// cannot cause one.
func liveHeapBytes() uint64 {
	sample := []metrics.Sample{{Name: "/gc/heap/live:bytes"}}
	metrics.Read(sample)
	if sample[0].Value.Kind() != metrics.KindUint64 {
		return 0
	}
	return sample[0].Value.Uint64()
}

// mib renders a byte count the way an operator reading a log line or a
// detector status wants it, since every number this file reports is compared
// by eye against a Helm limit written as "512Mi".
func mib(bytes uint64) string {
	return fmt.Sprintf("%.0fMi", float64(bytes)/(1<<20))
}

// --- the Go soft memory limit ---

// sweepMemoryBudget is the heap ceiling this process may work to, given its
// container memory limit: the limit less a reserve for everything the Go
// heap accounting does not cover.
//
// The reserve is whichever is LARGER of goSoftMemoryLimitFraction's share
// and minNonHeapReserve — see minNonHeapReserve for why a fraction alone is
// unsafe at small limits. One function rather than the same arithmetic in
// two places, because the Go soft memory limit and the sweep guard's budget
// MUST be the same number: the guard's whole premise is that it refuses
// reads the runtime cannot rescue, and it can only know which those are if
// it is measuring against the ceiling the runtime is actually enforcing.
//
// A limit smaller than the reserve returns zero, which disables every check
// in this file rather than producing a negative budget. An agent configured
// with less memory than its own runtime needs has a problem this guard
// cannot solve and should not pretend to.
func sweepMemoryBudget(limit uint64) uint64 {
	reserve := uint64(float64(limit) * (1 - goSoftMemoryLimitFraction))
	if reserve < minNonHeapReserve {
		reserve = minNonHeapReserve
	}
	if limit <= reserve {
		return 0
	}
	return limit - reserve
}

// applyGoSoftMemoryLimit tells the Go runtime about the container limit the
// runtime otherwise cannot see. Called once, from Run.
//
// Does nothing in two cases, both deliberate:
//
//   - GOMEMLIMIT is already set in the environment. An operator who has
//     tuned this explicitly outranks a default computed from a cgroup file,
//     and silently overriding them would make their setting a lie.
//   - There is no container limit (a host-run agent). There is nothing to
//     derive a soft limit from, and inventing one would make a developer's
//     agent collect against a ceiling nobody asked for.
func applyGoSoftMemoryLimit() {
	if os.Getenv("GOMEMLIMIT") != "" {
		logger.Info("GOMEMLIMIT is set in the environment — leaving the Go soft memory limit exactly as configured")
		return
	}
	limit, ok := containerMemoryLimit()
	if !ok {
		logger.Info("no container memory limit visible (host-run, or an unlimited cgroup) — no Go soft memory limit set and the sweep memory guard is inactive")
		return
	}
	soft := sweepMemoryBudget(limit)
	debug.SetMemoryLimit(int64(soft))
	logger.Info("Go soft memory limit set from the container limit — this is also the sweep guard's ceiling; the difference is reserved for what the Go heap accounting cannot see",
		slog.String("container_limit", mib(limit)), slog.String("soft_limit", mib(soft)), slog.String("reserved", mib(limit-soft)))
}

// sweepMemoryLimitDescription is what the live measurement harness prints so
// a recorded table always says which limit it was measured under.
func sweepMemoryLimitDescription() string {
	limit, ok := containerMemoryLimit()
	if !ok {
		return "none (host-run or unlimited cgroup)"
	}
	return mib(limit)
}

// --- the guard ---

// sweepMemoryGuard decides whether a sweep pass may start one more read.
//
// # Two inputs, because one is not enough
//
// Measuring alone is not enough. "Is there room right now" can only stop a
// pass AFTER the read that had no room has already been paid for, which
// bounds the peak at "budget plus one list" — and on a large cluster one
// list is the whole problem, so the very first pass after a restart would
// still be the pass that dies.
//
// Predicting alone is not enough either. Counting every kind before reading
// it would cost an extra API request per kind per pass, undoing much of what
// P17(a) just bought, and a bytes-per-object constant is a lie on any
// cluster whose objects are fatter than the ones it was measured against. A
// ConfigMap alone ranges over three orders of magnitude.
//
// So the guard uses both, and pays for prediction only where it buys the
// most:
//
//   - It prices PODS, from one Limit: 1 probe per pass whose
//     remainingItemCount gives the whole count for the cost of one object
//     (sizeCluster). Pods are the most numerous kind on essentially every
//     cluster and the heaviest per object, so every read that enumerates
//     them — the typed Pod list, the unstructured pass, and a declarative
//     rule over v1/Pod on the fallback path that still lists for itself —
//     can be refused before it allocates anything.
//   - Everything else is admitted against the live heap as it stands, which
//     bounds a surprise at "budget plus that one list" rather than "budget
//     plus everything after it".
//
// # Live heap, not resident memory
//
// Both decisions are made on the LIVE heap (liveHeapBytes), never on total
// resident memory, and decodeHeadroomFactor is what converts one to the
// other. See those two for why; the short version is that a Go runtime under
// a soft memory limit will collect its way out of transient garbage but can
// do nothing at all about a live set that does not fit.
//
// # What it remembers between passes
//
// One number: what the last pass' unstructured half actually held. That half
// is the larger of the two and is a single, all-or-nothing call
// (listWatchedKindObjects lists every watched kind, and the predicates fed
// by it CANNOT run on a partial map — checkGenericDanglingReference would
// report every reference into a kind that was skipped as a dangling
// reference), so it is the one place where an exact measurement of the last
// pass is worth keeping alongside the estimate.
//
// Not mutex-protected: exactly like sweep_snapshot.go's cachedList, one
// instance is touched by one goroutine (runSweepDetector's), and anything
// that makes the sweep concurrent has to revisit both.
type sweepMemoryGuard struct {
	// limit is the container memory limit; budget is the live heap a pass
	// may reach, which is the Go soft memory limit itself (see
	// enableSweepMemoryGuard). Both zero when no limit is visible, which
	// disables every check in this file.
	limit  uint64
	budget uint64

	// lastUnstructuredHalf is the live heap the previous pass'
	// listWatchedKindObjects call was still holding when it finished. Zero
	// until a pass has completed one.
	lastUnstructuredHalf uint64

	// lastKindCounts is how many objects each kind returned on the previous
	// pass, keyed by Kind. This is the guard's second forward-looking input
	// and the one that generalises past Pods: the Limit: 1 probe below can
	// only afford to count ONE kind per pass, so every other kind used to be
	// unpriceable and therefore unable to be paginated or refused before the
	// fact. Feeding a pass' own measured counts into the next pass costs
	// nothing — the objects were already counted — and means a cluster whose
	// heaviest kind is not Pods is priced from its second pass onwards.
	//
	// Same single-goroutine ownership as everything else here; see the
	// struct's doc comment.
	lastKindCounts map[string]int64

	// podCount is this cluster's pod count as of the start of the current
	// pass, from one Limit: 1 probe (see sizeCluster). It is the guard's
	// only forward-looking input: Pods are both the most numerous kind on
	// essentially every cluster and the heaviest per object, so every read
	// that enumerates them can be priced BEFORE it is issued rather than
	// discovered halfway through. Zero means "not known this pass", which
	// downgrades every projection to the plain "is there room right now"
	// check.
	podCount int64

	// forcedGCThisPass stops a pass that is genuinely out of room from
	// paying for a confirming collection once per refused read — see admit.
	forcedGCThisPass bool

	// refusals counts every read this guard has declined, for the log line
	// that reports one — a single refusal and a permanent refusal are very
	// different operator situations and the count is what distinguishes them.
	refusals uint64

	// paginated counts every read this guard downgraded from a watch-cache
	// read to a paginated one (PROJECT.md P17(c)). Reported alongside
	// refusals because it is the signal BETWEEN "everything is fine" and
	// "this cluster is being swept less completely than it should be": an
	// agent that paginates every pass is one whose memory limit is below
	// what its cluster needs, and it is paying extra API-server requests to
	// stay complete. Rising here is an invitation to raise the limit; rising
	// in refusals is a demand.
	paginated uint64
}

// sweepMemoryGuardInstance is nil until enableSweepMemoryGuard is called,
// which runSweepDetector does once at startup from the real, deployed
// process. Package-level for the same reason generic_predicates.go's
// discoveredWatchSetCache is: threading it through runOneSweep and every
// checker signature would make ~70 call sites (almost all of them tests)
// carry an argument they have no use for. A nil guard is a silent no-op
// everywhere, so every existing unit test keeps exercising the unguarded
// path unless it deliberately opts in.
var sweepMemoryGuardInstance *sweepMemoryGuard

// enableSweepMemoryGuard arms the guard from this process' own cgroup limit.
// A process with no visible limit gets no guard at all, and says so once.
func enableSweepMemoryGuard() {
	limit, ok := containerMemoryLimit()
	if !ok {
		sweepMemoryGuardInstance = nil
		return
	}
	sweepMemoryGuardInstance = &sweepMemoryGuard{
		limit: limit,
		// The guard's ceiling IS the Go soft memory limit, deliberately, not
		// a third number below it: the soft limit is what the runtime is
		// already enforcing, and a read that would push the live heap past
		// it is precisely a read the runtime cannot rescue. What keeps a
		// pass clear of that ceiling is the decode headroom factor for the
		// SHAPE of the read being considered — see admit.
		budget: sweepMemoryBudget(limit),
	}
	if sweepMemoryGuardInstance.budget == 0 {
		logger.Warn("container memory limit is at or below what this process needs outside its heap — the memory guard cannot produce a usable budget and is inactive; this agent needs a larger limit (deploy/helm/argus-agent/values.yaml)",
			slog.String("container_limit", mib(limit)), slog.String("non_heap_reserve", mib(minNonHeapReserve)))
		return
	}
	logger.Info("sweep detector memory guard armed — a read is refused when what this agent already holds, plus the projected decode headroom, would pass its budget; a single list that does not fit unpaginated is retried in pages before it is refused",
		slog.Float64("single_list_headroom_factor", singleListDecodeHeadroomFactor), slog.Float64("many_kind_headroom_factor", multiKindDecodeHeadroomFactor),
		slog.String("budget", mib(sweepMemoryGuardInstance.budget)), slog.String("limit", mib(limit)), slog.Int("page_size", sweepPageSize))
}

// admit reports whether there is room to start a read that will add
// projected bytes of LIVE heap (pass 0 when there is no estimate, which is
// the common case) and, while running, up to factor times that in total
// memory. The returned error wraps errSweepMemoryBudget and reads as a
// complete sentence, because it is surfaced verbatim to an operator through
// tunnel.DetectorStatus.Error.
//
// factor is one of the two measured constants at the top of this file, or —
// for a read that has already been downgraded to pagination — the much
// smaller effective factor pagedHeadroomFactor computes. Passing it in
// rather than reading a package constant is what stops a caller silently
// pricing a single list at the many-kind rate, which is exactly the
// substitution B187 was.
//
// A nil guard, or one with no limit to guard against, admits everything.
func (g *sweepMemoryGuard) admit(what string, projected uint64, factor float64) error {
	live, ok := g.fits(projected, factor)
	if ok {
		return nil
	}
	return g.refuse(what, projected, factor, live)
}

// fits is admit without the refusal: it answers "is there room" and reports
// the live-heap reading it decided on, leaving the caller to decide whether
// that is a refusal at all.
//
// Split out for planRead (sweep_pagination.go), which asks the same question
// up to twice about the same read — once unpaginated, once paginated — and
// must not have that counted as two refusals. One read the agent could not
// perform is one refusal, however many shapes it was tried in; the count is
// what an operator reads to tell a one-off from a standing fault.
//
// ok is true for a nil guard and for one with no limit, which is what makes
// every check in this file a silent no-op on a host-run agent.
func (g *sweepMemoryGuard) fits(projected uint64, factor float64) (live uint64, ok bool) {
	if g == nil || g.budget == 0 {
		return 0, true
	}
	needed := uint64(float64(projected) * factor)
	if live = liveHeapBytes(); live+needed <= g.budget {
		return live, true
	}
	// The cheap reading says no. Before acting on it, make it exact: the
	// live-heap metric is only as fresh as the last collection, so a pass
	// that has just dropped a large list (exactly what the typed half does
	// before the dynamic half runs) can still be reading the size it was
	// before. One forced collection per PASS is a price worth paying to
	// never decline a pass that would have fitted — and only one, so that a
	// pass which is genuinely out of room does not pay for a collection per
	// read it declines.
	if !g.forcedGCThisPass {
		g.forcedGCThisPass = true
		runtime.GC()
		if live = liveHeapBytes(); live+needed <= g.budget {
			return live, true
		}
	}
	return live, false
}

// refuse counts one declined read and builds the sentence an operator reads
// on the cluster's detector status. Called once per read that could not be
// performed in any shape — never once per shape tried.
func (g *sweepMemoryGuard) refuse(what string, projected uint64, factor float64, live uint64) error {
	needed := uint64(float64(projected) * factor)
	g.refusals++
	projection := ""
	if projected > 0 {
		projection = fmt.Sprintf(" and the read ahead needs an estimated %s (%s of objects, plus the %.0f%% headroom decoding them needs),", mib(needed), mib(projected), (factor-1)*100)
	}
	return fmt.Errorf("%w: skipped %s because this agent is holding %s that cannot be freed%s against a %s budget (its %s container memory limit, less %s reserved for what the Go heap accounting cannot see). Raise the agent's memory limit (deploy/helm/argus-agent/values.yaml sizes the default against a measured table) or this cluster is swept less completely than it should be. Reads refused so far: %d",
		errSweepMemoryBudget, what, mib(live), projection, mib(g.budget), mib(g.limit), mib(g.limit-g.budget), g.refusals)
}

// planTypedList is the check every cluster-wide typed list in a pass goes
// through (sweep_snapshot.go's cachedList.get). See planList.
func (g *sweepMemoryGuard) planTypedList(kind string) (sweepReadPlan, error) {
	return g.planList("the cluster-wide "+kind+" list", kind, typedLiveBytesPerObject)
}

// planUnstructuredList is planTypedList for a STAND-ALONE read that decodes
// into unstructured map trees instead of typed structs — the same objects at
// roughly two and a half times the live size, which is why the two have
// different bytes-per-object constants.
//
// "Stand-alone" is load-bearing: this is the declarative-rule fallback loop's
// own list (runRulesWithOwnLists), priced at singleListDecodeHeadroomFactor
// because nothing collects between it and anything else. The per-kind reads
// INSIDE listWatchedKindObjects are a different shape and go through
// admitUnstructuredKindInHalf.
func (g *sweepMemoryGuard) planUnstructuredList(kind, what string) (sweepReadPlan, error) {
	return g.planList(what, kind, unstructuredLiveBytesPerObject)
}

// admitUnstructuredKindInHalf is the incremental per-kind backstop inside
// listWatchedKindObjects' many-kind read.
//
// # Why the increment is priced at 1.0 and not at either headroom factor
//
// The half has ALREADY been admitted as a unit by planUnstructuredHalf,
// which reserved multiKindDecodeHeadroomFactor's worth of transient room for
// the whole read. Charging a headroom factor again, per kind, on top of a
// live heap that by then holds most of the half, double-counts that same
// reservation — and it does so most heavily at the end of the half, where
// the live heap is largest and the remaining kinds are the ones most likely
// to be refused for no reason.
//
// That is not theoretical. Measured at a 320Mi limit on the 2,030-pod
// cluster: mid-half, holding 186Mi, this check priced a 97Mi kind at 136Mi
// and refused it against a 288Mi budget — discarding a half that completes
// at a 271-283Mi peak, and taking the whole pass' generic predicates with
// it. Pricing the increment at what it actually retains admits it (186 + 97
// = 283) and the pass completes.
//
// What the backstop is still for is unchanged: on a first pass, with no
// measured projection to refuse on up front, it is the only thing standing
// between a cluster several times the documented ceiling and an OOMKill. It
// stops before the kind whose OBJECTS do not fit, which is the irreducible
// part and the part no transient allowance can rescue.
//
// Never paginates: there is no per-kind budget left to escalate against —
// the plan for the whole half already decided that, and a half that does not
// fit is refused as a half.
func (g *sweepMemoryGuard) admitUnstructuredKindInHalf(kind, what string) error {
	if g == nil {
		return nil
	}
	return g.admit(what, g.projectFor(kind, unstructuredLiveBytesPerObject), 1)
}

// planUnstructuredHalf is admit for generic_predicates.go's one
// all-or-nothing read of every watched kind.
//
// Projects from whichever of the two available estimates is LARGER: what the
// last pass actually held (exact, but describes a cluster that may since
// have grown) and what this pass' pod count implies (crude, but current).
// Taking the larger is the only safe direction — under-projecting here is
// the OOMKill this whole file exists to prevent.
//
// Returns a plan rather than a bare admission because the half can be
// downgraded to pagination like any other read: the kinds inside it are
// listed one page at a time, which bounds the in-flight decode to one page
// per kind instead of one whole kind. What pagination CANNOT do for this
// read is shrink the 197Mi of objects it must hold all at once, so a half
// that does not fit even paginated is still refused.
func (g *sweepMemoryGuard) planUnstructuredHalf() (sweepReadPlan, error) {
	if g == nil {
		return sweepReadPlan{}, nil
	}
	projected := g.lastUnstructuredHalf
	if estimate := g.projectFor("Pod", unstructuredLiveBytesPerObject*unstructuredObjectsPerPod); estimate > projected {
		projected = estimate
	}
	return g.planRead("the generic kind-agnostic predicate pass (every watched kind, as unstructured objects)",
		projected, unstructuredLiveBytesPerObject, multiKindDecodeHeadroomFactor)
}

// beginDynamicHalf tells the guard that the typed half of a pass has ended
// and its snapshot has gone out of scope, which re-arms the one forced
// collection admit is allowed per phase.
//
// Without this, the two halves of a pass compete for a single forced GC, and
// the typed half almost always wins it — it runs first, and its own first
// budget check is the one that spends it. The dynamic half is then left
// deciding the largest read in the whole pass against a live-heap reading
// taken BEFORE the typed snapshot was dropped, which overstates what this
// agent is holding by the entire size of that snapshot.
//
// Measured consequence at a 320Mi limit on the 2,030-pod cluster: the
// many-kind half was priced against a stale 199Mi live heap instead of the
// real 4Mi, downgraded to pagination it did not need, and then stopped
// part-way through — on every pass after the first, while the first pass ran
// it whole. An operator would see the generic predicates run every other
// pass for no visible reason.
//
// The cost is one extra forced collection per sweep pass — five minutes
// apart by default, and only on an agent that has a memory limit at all.
func (g *sweepMemoryGuard) beginDynamicHalf() {
	if g == nil {
		return
	}
	g.forcedGCThisPass = false
}

// projectFor prices a read of kind from the best count this guard has: this
// pass' Pod probe, or what that kind actually returned on the previous pass,
// whichever is LARGER.
//
// Taking the larger is the only safe direction — a kind that has grown since
// the last pass is exactly the case where the stale number would admit the
// read that kills the agent, and the Pod probe is refreshed every pass
// precisely so that one kind cannot go stale.
//
// A kind seen on no previous pass still projects zero, which is honest: this
// guard has no count for it and an invented one would refuse real work on a
// cluster whose shape it guessed wrong. Their backstop is the incremental
// check — every read is admitted against the live heap as it stands, so a
// surprise costs the budget plus that one list, never the budget plus
// everything after it. That gap now closes after one pass instead of never,
// which is what lets a cluster with fifty thousand Services get the same
// treatment Pods have always had.
func (g *sweepMemoryGuard) projectFor(kind string, perObject uint64) uint64 {
	if g == nil {
		return 0
	}
	count := g.lastKindCounts[kind]
	if kind == "Pod" && g.podCount > count {
		count = g.podCount
	}
	if count <= 0 {
		return 0
	}
	return uint64(count) * perObject
}

// recordKindCount remembers how many objects one kind actually returned, so
// the next pass can price a read of it before issuing it. Called from the two
// chokepoints every cluster-wide sweep read goes through: cachedList.get for
// the typed half and listWatchedKindObjects for the unstructured one.
//
// Deliberately representation-agnostic — one count per kind, whichever half
// read it — because a count is a property of the cluster and the bytes per
// object is a property of how it was decoded. projectFor multiplies by
// whichever constant its caller is asking about.
//
// A zero count is recorded like any other: a kind that had no objects last
// pass genuinely projects nothing, and pretending otherwise would refuse
// reads on an empty cluster.
func (g *sweepMemoryGuard) recordKindCount(kind string, n int) {
	if g == nil || g.budget == 0 || kind == "" {
		return
	}
	if g.lastKindCounts == nil {
		g.lastKindCounts = make(map[string]int64)
	}
	g.lastKindCounts[kind] = int64(n)
}

const (
	// typedLiveBytesPerObject is what one object costs in LIVE heap as a
	// typed client-go struct. Measured on the synthetic cluster in
	// sweep_memory_live_test.go: 107Mi retained across 6,420 objects at
	// 5,000 pods, 54Mi across 3,220 at 2,500, 22Mi across 1,300 at 1,000 —
	// 17.5-17.8KiB per object, flat across the whole range.
	typedLiveBytesPerObject = 18 * 1024

	// unstructuredLiveBytesPerObject is the same object decoded into an
	// unstructured map tree instead: 460Mi across 9,587 objects at 5,000
	// pods, 230Mi across 4,907 at 2,500 — 46-50KiB, again flat.
	//
	// Roughly 3x the typed cost, which is the single most important fact in
	// this file: the peak of a pass is the unstructured half, not the typed
	// snapshot P17(a) made contiguous.
	unstructuredLiveBytesPerObject = 50 * 1024

	// unstructuredObjectsPerPod scales a pod count to the whole watched set
	// for the one read that lists every kind at once. Measured at 1.9 on the
	// synthetic cluster (9,587 objects for 5,009 pods); 2 is the round
	// number just above it. Deliberately crude — the per-kind check inside
	// listWatchedKindObjects is what backstops a cluster whose ratio is
	// nothing like this one.
	unstructuredObjectsPerPod = 2
)

// clusterSizeProbeGVR is the one resource sizeCluster counts. Pods are both
// the most numerous kind on essentially every cluster and the heaviest per
// object, so they are the single best predictor of a pass' cost.
var clusterSizeProbeGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

// sizeCluster refreshes podCount for the pass that is about to run, and
// resets the per-pass bookkeeping. Called once per pass, from runOneSweep.
//
// The probe is one request returning ONE object, whose remainingItemCount
// carries the rest of the count — about the cheapest question a client can
// ask a Kubernetes API server, and the reason this is affordable every pass
// rather than once per process. Refreshing it every pass matters: a cluster
// that has doubled since this agent started is exactly the case where a
// stale count would admit the pass that kills it.
//
// A failed probe leaves podCount at zero (no projection, incremental checks
// only) rather than reusing a stale one — this agent should not decline to
// sweep on the strength of a number it could not confirm.
func (g *sweepMemoryGuard) sizeCluster(ctx context.Context, dyn dynamic.Interface) {
	if g == nil || g.budget == 0 {
		return
	}
	g.forcedGCThisPass = false
	g.podCount = 0
	if dyn == nil {
		return
	}
	probeCtx, cancel := context.WithTimeout(ctx, clusterSizeProbeTimeout)
	defer cancel()
	// Deliberately NOT sweepListOptions' ResourceVersion: "0": the API
	// server ignores Limit for a watch-cache read and would hand back every
	// pod on the cluster — the exact allocation this probe exists to avoid
	// making. One object through etcd is the cheaper of the two by far.
	list, err := dyn.Resource(clusterSizeProbeGVR).Namespace(metav1.NamespaceAll).List(probeCtx, metav1.ListOptions{Limit: 1})
	if err != nil {
		logger.Warn("could not size this cluster before sweeping it — proceeding with the incremental memory checks as this pass' only guard", logging.Err(err))
		return
	}
	pods := int64(len(list.Items))
	if remaining := list.GetRemainingItemCount(); remaining != nil {
		pods += *remaining
	}
	g.podCount = pods
}

// clusterSizeProbeTimeout bounds the one-object probe above. Short on
// purpose: it reads a single object, and an API server that cannot answer
// that in ten seconds is not one whose full object set this agent should be
// about to ask for anyway.
const clusterSizeProbeTimeout = 10 * time.Second

// recordUnstructuredHalf remembers what the half that just completed cost in
// LIVE heap, so the next pass can project it. before is what
// admitUnstructuredHalf measured.
//
// Forces a collection first, and must be called while that half's objects
// are still reachable: the number wanted here is "how much of this is
// irreducible", which is only knowable after the garbage around it is gone.
// That is one extra GC per sweep pass — five minutes apart by default, and
// only on an agent that actually has a memory limit to guard.
//
// A non-positive delta (a GC landed mid-half and freed more than this half
// allocated) is not recorded as zero: that would replace a real estimate
// with a meaningless one and admit the next pass on no projection at all.
// The previous estimate is kept instead.
func (g *sweepMemoryGuard) recordUnstructuredHalf(before uint64) {
	if g == nil {
		return
	}
	runtime.GC()
	after := liveHeapBytes()
	if after <= before {
		return
	}
	g.lastUnstructuredHalf = after - before
}
