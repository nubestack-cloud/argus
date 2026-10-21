package agent

// sweep_unstructured_snapshot.go is the sweep's per-pass, list-once view of
// every watched kind as unstructured objects — sweep_snapshot.go's
// counterpart for the half of a pass that does not use the typed clientset
// (PROJECT.md P17(a) for the typed half, P28 for this one).
//
// # What it replaced
//
// The unstructured reads in a pass used to come from two places that had
// never been introduced to each other:
//
//   - generic_predicates.go listed every supportedGVKs kind (plus the
//     discovered watch set) once, and shared that one map across all six of
//     its predicates. That part was already list-once.
//   - Every declarative rule in rules/default-rules.yaml listed its OWN GVK,
//     cluster-wide, independently — 37 more lists in a pass that had just
//     listed all of those kinds anyway, including two full Pod lists and six
//     Deployment lists. Measured 2026-09-25 on the one-object-per-kind
//     fixture in sweep_listcount_test.go: 85 dynamic lists per pass, of
//     which 37 were rules re-reading kinds the predicate pass already held.
//
// Both now read this. A kind is listed once per pass however many rules and
// predicates want it.
//
// # Why a read record, and not just a map
//
// A map of "Kind -> objects" cannot answer the one question both consumers
// actually need answered: is this kind EMPTY, or did this agent fail to read
// it? Those are opposite facts, and reading one as the other is a
// false-positive generator:
//
//   - checkGenericDanglingReference treats an empty index entry as "that
//     object does not exist" and reports the reference into it as broken.
//     For a kind RBAC denies, every reference into it becomes a fabricated
//     incident — and it gets worse exactly as an operator narrows the grant
//     (PROJECT.md B185).
//   - A declarative rule reading an empty list produces no candidates, which
//     is indistinguishable from "this rule checked and found nothing wrong".
//
// So every read is recorded positively: a kind is usable only if a List for
// it actually completed this pass. Everything else — RBAC denied it, the API
// server does not serve it, the memory guard refused it, it failed, it is
// deliberately never listed — is recorded with the reason, and consumers
// that would otherwise read absence as fact say nothing instead. That
// replaces the hand-maintained genericPredicateExcludedKinds special case
// for Secret with a general mechanism: Secret is now simply a kind this
// agent records as not read, exactly like one a ClusterRole leaves out.
//
// # Lifetime
//
// One pass, then discarded — see runUnstructuredSweepHalf, which owns it in
// its own scope for the same reason runTypedSweepCheckers owns the typed
// snapshot in its (PROJECT.md P18: a pass' peak must never be the SUM of the
// two halves). It is not a cache across passes and holds no state between
// them.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"argus/internal/logging"
	"sync"
	"sync/atomic"
	"time"

	"argus/internal/tunnel"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// kindReadState is what happened when this pass tried to read one watched
// kind. Every state except kindReadOK means "this agent does not know what
// is in this kind right now", which is deliberately NOT the same claim as
// "this kind is empty" — see this file's doc comment.
type kindReadState int

const (
	// kindReadOK: a List for this kind completed. Its objects are in the
	// snapshot, and an object of this kind that is not in it genuinely does
	// not exist on the cluster (as of a watch-cache read, see
	// sweepListOptions).
	kindReadOK kindReadState = iota

	// kindNotServed: the API server does not serve this kind at all — no
	// CRD installed, the common and expected case for every CRD-backed rule
	// on a cluster that does not run that controller.
	kindNotServed

	// kindForbidden: RBAC denies this agent list on this kind. PROJECT.md
	// B185's case, and the one that gets more common as E11 narrows the
	// grant.
	kindForbidden

	// kindNotAffordable: the sweep memory guard declined the read (PROJECT.md
	// P18). The kind is readable; this agent could not afford to read it
	// this pass.
	kindNotAffordable

	// kindReadFailed: any other failure — a transient API error, or the
	// fake dynamic client's missing-list-kind panic in tests.
	kindReadFailed

	// kindNotListed: deliberately never listed. Secret is the standing
	// example: its ClusterRole grant is "get" only, never "list"/"watch"
	// (tools.go's own comment on that entry), and non-negotiable 9 makes
	// scanning a Secret's fields the wrong thing to build regardless.
	kindNotListed
)

// kindReadResult is one kind's outcome plus the sentence an operator would
// need to understand it. reason is empty only for kindReadOK.
type kindReadResult struct {
	state  kindReadState
	reason string
}

// unstructuredSnapshot is one pass' shared unstructured view: the objects
// that were read, and a positive record of what was read at all.
//
// Keyed by BARE Kind rather than full GVK, matching what every consumer
// needs — a condition type's meaning is a property of the Kind's API, a
// reference names a Kind, and a rule's GVK is validated against
// supportedGVKs at load time. Two API groups sharing a Kind name collapse
// into one entry, the same accepted limitation kindIsNamespaced already
// documents; the read record resolves such a collision in the conservative
// direction (see record).
//
// Not mutex-protected, exactly like sweep_snapshot.go's cachedList: one
// snapshot belongs to one pass, built and read on one goroutine.
type unstructuredSnapshot struct {
	objects map[string][]*unstructured.Unstructured
	reads   map[string]kindReadResult

	// existence is checkGenericDanglingReference's lookup table, built once
	// on first use rather than eagerly — a pass that emits no candidates
	// with references never pays for it.
	existence map[string]map[string]bool
}

func newUnstructuredSnapshot() *unstructuredSnapshot {
	return &unstructuredSnapshot{
		objects: make(map[string][]*unstructured.Unstructured),
		reads:   make(map[string]kindReadResult),
	}
}

// record notes one kind's outcome. A kind that resolves to several GVKs (see
// the type's own comment) keeps the WORST outcome recorded for it, never the
// best: if any GVK behind a Kind name could not be read, nothing may treat
// that Kind's contents as complete.
func (s *unstructuredSnapshot) record(kind string, result kindReadResult) {
	if prev, ok := s.reads[kind]; ok && prev.state != kindReadOK {
		return
	}
	s.reads[kind] = result
}

// add appends one completed List's objects. Callers pass the items of a
// single List; add never implies the read succeeded, so record is still
// required — an empty successful list is a real and different fact from a
// list that never happened.
func (s *unstructuredSnapshot) add(kind string, objs []*unstructured.Unstructured) {
	if len(objs) == 0 {
		return
	}
	s.objects[kind] = append(s.objects[kind], objs...)
}

// readable reports whether this pass actually read this kind, and so whether
// the absence of an object of this kind from the snapshot is a fact about
// the cluster rather than a fact about this agent.
//
// False for a kind nothing ever attempted, which is the right answer for the
// same reason: an unattempted kind's contents are unknown.
func (s *unstructuredSnapshot) readable(kind string) bool {
	r, ok := s.reads[kind]
	return ok && r.state == kindReadOK
}

// coverage counts this pass' read record by outcome — PROJECT.md E11's
// second, independent coverage measurement (the first being the grant-shaped
// one in discovery.go).
//
// This is the honest one, and it is honest precisely because it is a
// POSITIVE record (B185): every count here is something that actually
// happened to a List this pass issued, not an inference from a grant. A kind
// RBAC says is readable but that the memory guard declined, or that the
// build's deadline expired before reaching, is readable and unread — and
// only this side of the measurement can say so.
//
// Returns nil when nothing was recorded at all, which is "no pass has
// produced a snapshot", not "a pass read nothing".
func (s *unstructuredSnapshot) coverage(at time.Time) *tunnel.SweepCoverage {
	if len(s.reads) == 0 {
		return nil
	}
	cov := &tunnel.SweepCoverage{At: at}
	for _, r := range s.reads {
		switch r.state {
		case kindReadOK:
			cov.KindsRead++
		case kindForbidden:
			cov.KindsForbidden++
		case kindNotServed:
			cov.KindsNotServed++
		case kindNotAffordable:
			cov.KindsNotAffordable++
		case kindNotListed:
			cov.KindsNotListed++
		default:
			// kindReadFailed and anything added later. Counted as failed
			// rather than dropped: an outcome nobody classified is still an
			// unread kind, and silently omitting it would overstate
			// coverage, which is the one direction this signal must never
			// err in.
			cov.KindsFailed++
		}
	}
	return cov
}

// lastSweepCoverage holds the most recent pass' coverage for the facts
// gatherer to read — the same "the detector's own goroutine writes, the
// fact-gathering pass reads" split detector_status.go's detectorRunState
// already establishes, and for the same reason: the two run on different
// goroutines at different cadences (one sweep interval, one facts refresh).
//
// Deliberately NOT folded into sweepRunState. That record's fields are all
// "did this detector run", and a consumer of it renders a non-empty
// DeniedReads as BLOCKED; coverage is "what did it run over", which on a
// correctly scoped agent is a normal, healthy, non-zero number. Merging them
// would make a narrower grant look like a broken detector.
var lastSweepCoverage struct {
	mu  sync.Mutex
	cov *tunnel.SweepCoverage
}

// recordSweepCoverage publishes one pass' coverage. Called with nil by
// nothing: a pass that produced no snapshot leaves the previous pass'
// figure standing, because "the last time we managed to look, this is what
// we saw" is more useful than blanking it — and the caller records the
// refusal itself on the detector's error field, where a refusal belongs.
func recordSweepCoverage(cov *tunnel.SweepCoverage) {
	if cov == nil {
		return
	}
	lastSweepCoverage.mu.Lock()
	defer lastSweepCoverage.mu.Unlock()
	lastSweepCoverage.cov = cov
}

// snapshotSweepCoverage reads the most recent pass' coverage, or nil when no
// pass has produced one yet. The value is copied, so a caller cannot mutate
// what the next reader sees.
func snapshotSweepCoverage() *tunnel.SweepCoverage {
	lastSweepCoverage.mu.Lock()
	defer lastSweepCoverage.mu.Unlock()
	if lastSweepCoverage.cov == nil {
		return nil
	}
	c := *lastSweepCoverage.cov
	return &c
}

// unreadableReason is the operator-facing sentence for a kind that was not
// read, and "" for one that was. Used verbatim in log lines and in the
// detector status an operator reads, so it says what happened and what it
// means rather than naming an enum.
func (s *unstructuredSnapshot) unreadableReason(kind string) string {
	r, ok := s.reads[kind]
	if !ok {
		return fmt.Sprintf("%s is not in this agent's watched set, so this pass never listed it", kind)
	}
	if r.state == kindReadOK {
		return ""
	}
	return r.reason
}

// readState exposes the recorded outcome, for the callers that treat "the
// cluster does not serve this kind" differently from "this agent could not
// read it" — a rule over a CRD nobody installed is not a problem, a rule
// over a kind RBAC denies is.
func (s *unstructuredSnapshot) readState(kind string) kindReadState {
	r, ok := s.reads[kind]
	if !ok {
		return kindReadFailed
	}
	return r.state
}

// objectsOf returns the objects of one kind, or nil. Callers must treat what
// comes back as READ-ONLY — it is shared with every other predicate and rule
// in the pass, so mutating an item (or sorting a slice in place) corrupts a
// later reader's view rather than just its own.
//
// nil is ambiguous on its own and is deliberately not the whole answer: pair
// it with readable(kind) before concluding anything from emptiness.
func (s *unstructuredSnapshot) objectsOf(kind string) []*unstructured.Unstructured {
	return s.objects[kind]
}

// objectsOfGVK is objectsOf narrowed to one apiVersion, for a caller that
// knows the exact GroupVersion it means (a declarative rule does — its GVK
// is validated against supportedGVKs at load time). Two API groups sharing a
// Kind name merge into one snapshot entry, and evaluating a rule's condition
// against the wrong group's objects would report a candidate under a GVK it
// does not belong to.
func (s *unstructuredSnapshot) objectsOfGVK(gvk schema.GroupVersionKind) []*unstructured.Unstructured {
	all := s.objects[gvk.Kind]
	apiVersion := gvk.GroupVersion().String()
	// The overwhelmingly common case is that every object in the slice is
	// the right one; check before allocating a filtered copy.
	mismatch := false
	for _, o := range all {
		if o.GetAPIVersion() != apiVersion {
			mismatch = true
			break
		}
	}
	if !mismatch {
		return all
	}
	out := make([]*unstructured.Unstructured, 0, len(all))
	for _, o := range all {
		if o.GetAPIVersion() == apiVersion {
			out = append(out, o)
		}
	}
	return out
}

// existenceIndex turns this pass' already-listed objects into
// checkGenericDanglingReference's lookup table: Kind -> set of
// "namespace/name" (cluster-scoped objects use "" for namespace, so the key
// is "/name" — exactly what a reference to a cluster-scoped kind should be
// checked against too, since kindIsNamespaced tells the caller not to
// qualify those with a namespace in the first place).
//
// Only kinds that were actually READ get an entry. A kind this agent could
// not read has no index at all, which is what makes "I do not know" a
// different lookup from "I know it is not there".
func (s *unstructuredSnapshot) existenceIndex() map[string]map[string]bool {
	if s.existence != nil {
		return s.existence
	}
	idx := make(map[string]map[string]bool, len(s.objects))
	for kind, objs := range s.objects {
		if !s.readable(kind) {
			continue
		}
		set := make(map[string]bool, len(objs))
		for _, o := range objs {
			set[o.GetNamespace()+"/"+o.GetName()] = true
		}
		idx[kind] = set
	}
	s.existence = idx
	return idx
}

// genericPredicateExcludedKinds are supportedGVKs entries the sweep must
// never List. Secret is the one entry: its ClusterRole grant is "get" only,
// deliberately never "list"/"watch" (tools.go's own comment on that entry) —
// a List call here would not just find nothing, it would be an RBAC-forbidden
// error logged every single sweep, and even if it were granted,
// non-negotiable 9 makes scanning a Secret's own fields for more references
// the wrong thing to build regardless.
//
// This is no longer also the mechanism that keeps the dangling-reference
// predicate quiet about Secrets. It used not to be one at all: a kind listed
// here was simply missing from the object map, which the predicate read as
// "no such object exists" and reported every reference into as broken. The
// snapshot's read record is what fixes that, generally, for every kind this
// agent cannot read — including the ones no list like this will ever
// anticipate (PROJECT.md B185). What stays here is only the DECISION not to
// read Secrets, which is a policy about what this agent fetches.
var genericPredicateExcludedKinds = map[schema.GroupVersionKind]bool{
	secretGVK: true,
}

// listWatchedKindObjects lists every currently-live instance of every
// namespaced-or-cluster-scoped kind in supportedGVKs (minus
// genericPredicateExcludedKinds), plus the discovered watch set, into one
// snapshot.
//
// Returns an error in exactly one case: the sweep memory guard refused to
// start another kind's List (PROJECT.md P18). That is not a per-kind failure
// and cannot be skipped over like one — the caller must discard what was
// built so far, because a partial snapshot is a partially-priced read, and
// the whole point of a refusal is to stop paying. Returning nil alongside
// the error is deliberate: it makes the partial map garbage immediately.
//
// Every OTHER failure returns no error, and is RECORDED rather than merely
// logged: one kind's List failure (a CRD not installed — the common,
// expected case; a transient API error; a kind an operator's RBAC happens to
// restrict beyond the chart's default) leaves that kind marked unreadable in
// the snapshot, and every consumer that would otherwise read its absence as
// a fact about the cluster stays silent about it instead. Partial results
// are still better than an all-or-nothing failure for a detector whose whole
// premise is "works on whatever is actually present" — but a partial result
// now says which part is missing, which is the difference between a degraded
// sweep and a lying one (PROJECT.md B185).
func listWatchedKindObjects(ctx context.Context, dyn dynamic.Interface, plan sweepReadPlan) (*unstructuredSnapshot, error) {
	snap := newUnstructuredSnapshot()
	var refusal error
	// Returns false when the pass must stop entirely, true to carry on —
	// including after an ordinary per-kind failure, which is recorded and
	// skipped.
	listInto := func(gvk schema.GroupVersionKind, res supportedResource) bool {
		if genericPredicateExcludedKinds[gvk] {
			snap.record(gvk.Kind, kindReadResult{state: kindNotListed,
				reason: fmt.Sprintf("%s is deliberately never listed by this agent (its grant is get-only, and its contents must never be scanned), so nothing this pass says about %s objects is based on reading them", gvk.Kind, gvk.Kind)})
			return true
		}
		// PROJECT.md P18: checked per kind, so the worst case is "the budget
		// plus one kind's list" rather than "the budget plus every kind
		// left". The first pass of a process has no measured projection to
		// refuse on up front (see admitUnstructuredHalf), which is exactly
		// when this incremental check is the only thing standing between a
		// cluster three times the documented ceiling and an OOMKill.
		if err := sweepMemoryGuardInstance.admitUnstructuredKindInHalf(gvk.Kind, "the generic kind-agnostic predicate pass, part-way through (stopped before listing "+gvk.Kind+")"); err != nil {
			refusal = err
			return false
		}
		list, err := listOneResource(ctx, dyn, res, plan)
		if err != nil {
			switch {
			case errors.Is(err, errSweepMemoryBudget):
				// A PAGINATED read that ran out of budget part-way through
				// (PROJECT.md P17(c)): the guard re-checks against the
				// server's own remainingItemCount after each page, so a kind
				// whose objects turn out heavier than projected is stopped
				// mid-read rather than at the end.
				//
				// This is the same refusal the pre-read check above produces
				// and has to be handled the same way — stop the half, return
				// the reason — not as a per-kind failure. Treated as one, it
				// would be logged and skipped: the pass would carry on
				// spending the budget it had just been told it was out of,
				// and the operator would get a quieter sweep with nothing on
				// the detector status to explain it.
				refusal = err
				return false
			case meta.IsNoMatchError(err), apierrors.IsNotFound(err):
				// CRD not installed on this cluster — normal, not an error
				// (matches checkArgoSyncFailed's own reasoning: logging this
				// would just train an operator to ignore this detector).
				snap.record(gvk.Kind, kindReadResult{state: kindNotServed,
					reason: fmt.Sprintf("this cluster's API server does not serve %s at all (no CRD installed)", gvk.Kind)})
			case apierrors.IsForbidden(err):
				logger.Warn("generic kind-agnostic predicates: listing a kind is forbidden (RBAC), skipping this kind this sweep",
					slog.String("kind", gvk.Kind), logging.Err(err))
				snap.record(gvk.Kind, kindReadResult{state: kindForbidden,
					reason: fmt.Sprintf("RBAC denies this agent list on %s, so this pass cannot tell an absent %s from one it is not allowed to see — the agent's ClusterRole needs get,list,watch on it", gvk.Kind, gvk.Kind)})
			case errors.Is(err, errFakeDynamicClientMissingListKind):
				// Test-only: a hand-built fake dynamic client
				// (k8s.io/client-go/dynamic/fake) that didn't register this
				// particular resource's list kind panics instead of
				// returning an ordinary error — a real API server never
				// does this. See listOneResource's own doc comment; not
				// logged, since almost every existing fake-client test
				// fixture in this package only registers the handful of
				// resources ITS OWN scenario needs, and this pass looks at
				// all of them.
				snap.record(gvk.Kind, kindReadResult{state: kindReadFailed,
					reason: fmt.Sprintf("listing %s failed this pass", gvk.Kind)})
			default:
				logger.Warn("generic kind-agnostic predicates: listing a kind failed, skipping this kind this sweep",
					slog.String("kind", gvk.Kind), logging.Err(err))
				snap.record(gvk.Kind, kindReadResult{state: kindReadFailed,
					reason: fmt.Sprintf("listing %s failed this pass (%v)", gvk.Kind, err)})
			}
			return true
		}
		snap.record(gvk.Kind, kindReadResult{state: kindReadOK})
		// PROJECT.md P17(c): the same count feedback the typed half does in
		// cachedList.get — see sweepMemoryGuard.recordKindCount.
		sweepMemoryGuardInstance.recordKindCount(gvk.Kind, len(list.Items))
		items := make([]*unstructured.Unstructured, len(list.Items))
		for i := range list.Items {
			items[i] = &list.Items[i]
		}
		snap.add(gvk.Kind, items)
		return true
	}

	for gvk, res := range supportedGVKs {
		if !listInto(gvk, res) {
			return nil, refusal
		}
	}

	// BACKLOG.md E11 piece 1, wired in as a measured rollout (HANDOFF.md
	// 2026-09-02): discoveredWatchSetCache is nil unless
	// enableDiscoveredWatchSet has been called (runSweepDetector does this
	// once, from a real clientset, at agent startup) — a nil cache is a
	// silent no-op, so an agent built before this wiring, or one whose
	// discovery/RBAC-review call fails, behaves exactly as before: only
	// supportedGVKs' fixed ~30 kinds. This is deliberately scoped to ONLY
	// the kind-agnostic detection loop — supportedGVKs itself, and every
	// OTHER consumer of it (describe_resource/list_resources' MCP surface,
	// PatchField's allowlist, rule validation, the ownership walk), is
	// completely untouched. Widening THOSE to arbitrary discovered kinds is
	// a materially different, larger decision (can the model
	// introspect/patch a kind nobody has reviewed?) that this
	// detection-only rollout does not make.
	if wsc := discoveredWatchSetCache.Load(); wsc != nil {
		discovered, err := wsc.Get(ctx)
		if err != nil {
			logger.Warn("generic kind-agnostic predicates: discovered watch set unavailable this sweep, falling back to supportedGVKs only", logging.Err(err))
		} else {
			for gvk, dr := range discovered {
				if _, alreadyWatched := supportedGVKs[gvk]; alreadyWatched {
					// Already listed above via supportedGVKs — that map's
					// own curated entry (and any genericPredicateExcludedKinds
					// exclusion) takes precedence; never list a kind twice.
					continue
				}
				if !listInto(gvk, supportedResource{gvr: dr.GVR, namespaced: dr.Namespaced}) {
					return nil, refusal
				}
			}
		}
	}
	return snap, nil
}

// discoveredWatchSetCache is nil until enableDiscoveredWatchSet is called.
// Package-level rather than threaded through dynamicSweepChecker's shared
// function signature (every OTHER dynamic checker — checkArgoSyncFailed and
// friends — would have to accept and ignore an argument they have no use
// for) — the same "a package var only this file's own logic consults"
// pattern supportedGVKs itself already is.
//
// atomic.Pointer, not a bare *WatchSetCache: the one write below happens
// once, in runSweepDetector's own goroutine at startup, but it is read from
// at least three OTHER goroutines — this file's own sweep pass, the
// facts-refresh loop (detector_status.go/coverage.go), and tool dispatch
// (tools.go/tools_list.go, on whatever goroutine is serving that call).
// A bare pointer read/write here is a real data race under the Go memory
// model (found in a whole-repo review pass, 2026-09-27) even though a
// pointer-sized write/read is very unlikely to tear in practice on typical
// hardware — this closes it for real rather than leaving it correct only by
// accident of the current runtime.
var discoveredWatchSetCache atomic.Pointer[WatchSetCache]

// enableDiscoveredWatchSet wires BACKLOG.md E11 piece 1 into piece 2/3's
// detection loop. Called once, from runSweepDetector, with the real typed
// clientset already built there — never called in a test, so
// discoveredWatchSetCache stays nil (the safe, pre-E11-piece-1 default)
// unless a real agent process actually starts sweeping.
func enableDiscoveredWatchSet(clientset kubernetes.Interface) {
	discoveredWatchSetCache.Store(NewWatchSetCacheFromClientset(clientset))
}

// errFakeDynamicClientMissingListKind is listOneResource's sentinel for the
// one failure mode that is a test-harness artifact, not a real cluster
// condition — see that function's doc comment.
var errFakeDynamicClientMissingListKind = errors.New("dynamic client panicked while listing (fake client missing a registered list kind)")

// listOneResource lists one supportedGVKs resource, recovering from a panic
// rather than letting it escape.
//
// This pass is the only caller in this package to List EVERY supportedGVKs
// entry at once (every other dynamicSweepChecker targets one specific, known
// resource). k8s.io/client-go/dynamic/fake's test double requires every
// resource it will ever be asked to List to be pre-registered via
// NewSimpleDynamicClientWithCustomListKinds, and PANICS (not an error
// return) for anything unregistered — "coding error: you must register
// resource to list kind ...". A real API server never does this; it returns
// a normal NotFound/NoMatch error for a kind it doesn't serve. Rather than
// hunting down and widening every existing fake-dynamic-client fixture
// across this package's test files (each deliberately registers only the
// handful of resources its own scenario needs, and widening all of them to
// the full ~30-entry supportedGVKs set for every test would be a lot of
// unrelated test churn for no behavioral gain), this recovers the panic and
// reports it through the exact same "skip this kind this sweep" path every
// other listing failure already takes.
func listOneResource(ctx context.Context, dyn dynamic.Interface, res supportedResource, plan sweepReadPlan) (list *unstructured.UnstructuredList, err error) {
	defer func() {
		if r := recover(); r != nil {
			list, err = nil, fmt.Errorf("%w: %v", errFakeDynamicClientMissingListKind, r)
		}
	}()
	// The plan, not a bare ListOptions: an unpaginated plan is
	// sweepListOptions verbatim, served from the API server's watch cache
	// rather than read through to etcd (PROJECT.md P17(b)), and a paginated
	// one gives that up deliberately to bound the read (PROJECT.md P17(c) —
	// the two are mutually exclusive, see sweep_pagination.go).
	//
	// This is the heaviest read path in the whole sweep — one list per
	// supportedGVKs kind, every pass — and every predicate and rule fed by
	// it goes through recordSweepCandidates, so nothing it produces can fire
	// before sustainedLongEnough has seen it across passes. That includes
	// checkGenericDanglingReference, whose existence index is the one thing
	// here that a stale read could in principle get wrong: a reference to an
	// object created moments ago cannot be reported as dangling, because a
	// first observation never reports at all.
	return listPaged(ctx, plan, func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		if res.namespaced {
			return dyn.Resource(res.gvr).Namespace(metav1.NamespaceAll).List(ctx, opts)
		}
		return dyn.Resource(res.gvr).List(ctx, opts)
	})
}

// kindIsNamespaced looks up whether a bare Kind name is namespaced, per
// supportedGVKs — an O(len(supportedGVKs)) scan rather than a second index,
// which is fine given this is only ever called once per discovered
// reference (a handful per sweep at most, not once per object). Returns
// known=false when no supportedGVKs entry has this Kind at all, which
// checkGenericDanglingReference treats as "cannot verify," not "dangling."
//
// Ambiguous when two different API groups share a Kind name: returns the
// first match encountered (Go map iteration order is unspecified) — an
// accepted, documented limitation. supportedGVKs has no such collision
// today, so this cannot misfire in practice against the kinds this agent
// actually watches; it would only matter if piece 1's discovery mechanism
// later widens the watch set to include two same-named CRD Kinds.
func kindIsNamespaced(kind string) (namespaced, known bool) {
	for gvk, res := range supportedGVKs {
		if gvk.Kind == kind {
			return res.namespaced, true
		}
	}
	return false, false
}
