package agent

// This file is BACKLOG.md E11 piece 2 ("predicates that do not know what the
// kind is") plus the agent-side half of piece 3 (Mechanism 1, "learn it from
// the cluster"). It is deliberately scoped to run against the kinds
// supportedGVKs (tools.go) ALREADY watches — E11's own sequencing note says
// to "build piece 2 against the kinds already watched first ... [t]hen turn
// on discovery," and this file does exactly that: it does not add a single
// entry to supportedGVKs, and it does not call any Kubernetes discovery API.
// Piece 1 (ServerPreferredResources ∩ RBAC) is separate, out-of-scope work
// that widens the KEYS this file iterates over — nothing here needs to
// change when that lands, which is the whole point of building the
// predicate as "walk whatever supportedGVKs currently holds" rather than as
// a fixed list of kinds.
//
// # Why this is ONE checker over one shared list, not five
//
// Each of the six predicates below (conditions, generation-vs-
// observedGeneration, deletionTimestamp age, dangling reference, peer
// outlier, admission-policy type checking) is written and tested as its own
// function, taking the SAME
// already-listed object set — but they are wired into dynamicSweepCheckers
// through one dispatcher (checkGenericObjectHealth) rather than six. E11's own
// "cost, stated honestly" section warns that kind-agnostic detection is
// noisier BY CONSTRUCTION; the one thing squarely inside this file's control
// is not making it more EXPENSIVE by construction too. Listing every
// supportedGVKs kind once and sharing that one snapshot across all five
// predicates (via listWatchedKindObjects) costs exactly what checkArgoSyncFailed
// already costs for one CRD, not five times that. Since PROJECT.md P28 that
// same snapshot also serves every declarative rule, so the argument now
// holds across two subsystems rather than one file.
//
// # Predicate 4's real reach (read this before assuming it does more)
//
// "Reference integrity, generalized" is the hardest of the five to make
// genuinely kind-agnostic, and this implementation does NOT claim to reach
// every reference shape in the catalogue. What it actually does: walk
// spec/status (bounded recursion) for any nested map value carrying string
// fields "kind" AND "name" — the exact shape every core Kubernetes
// ObjectReference-family type already uses (corev1.ObjectReference,
// corev1.TypedLocalObjectReference, autoscalingv2.CrossVersionObjectReference
// — HPA's own spec.scaleTargetRef is a real, live example). Optional
// "namespace"/"apiVersion" siblings are read when present; when namespace is
// absent on a namespaced target kind, the referring object's OWN namespace is
// assumed (same-namespace convention, matching K8s's own default for e.g.
// HPA's scaleTargetRef). If the target Kind isn't one supportedGVKs already
// watches, this predicate says NOTHING — silence, not a false claim of
// dangling-ness, because it genuinely cannot verify. The same silence now
// covers a kind this agent DOES watch but could not read this pass
// (PROJECT.md B185) — see checkGenericDanglingReference's own doc comment.
//
// What this does NOT reach, honestly: a bare string field named for what it
// references with no accompanying "kind" sibling (e.g. spec.serviceAccountName,
// spec.storageClassName, spec.priorityClassName) — resolving those would need
// a hardcoded field-name -> target-kind table, which is this item's own named
// anti-pattern. It also does not scan metadata.ownerReferences (a stale
// ownerReference is a real but different, rarer fault — Kubernetes' own
// garbage collector usually resolves it well inside any sustained-window this
// agent would apply, so it was left out rather than half-handled). And it
// resolves a target Kind name ambiguously if two different API groups both
// use that Kind name (e.g. two unrelated CRDs both called "Certificate") —
// kindIsNamespaced below returns the first match, an accepted, documented
// limitation rather than an oversight.
//
// # Predicate 5's chosen signal
//
// "Peer-relative outlier" could compare many things about sibling objects.
// This implementation compares exactly one: the SET of (condition type,
// condition status) pairs an object reports — its "conditions shape" — among
// objects of the same Kind, in the same namespace, sharing the same
// controlling owner. That was chosen because it is the one signal every
// object already carries the raw material for (status.conditions[], the
// same field predicate 1 reads) with zero additional kind-specific
// assumptions — a restart-count comparison was considered and rejected for
// this file specifically because it only means anything for Pods
// (status.containerStatuses[].restartCount), which is a kind-AWARE
// enhancement, not a kind-agnostic one; it would belong here as an
// explicitly Pod-specific addition layered on top, not as this predicate's
// general case, and was left for future work rather than blurring the two.
import (
	"fmt"
	"sort"
	"strings"
	"time"

	"argus/internal/tunnel"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	// genericConditionAnomalyReasonPrefix / genericDanglingReferenceReasonPrefix
	// carry a per-condition-type / per-target-kind suffix rather than being
	// plain fixed strings like every other reasonXxx constant in this
	// package. That's deliberate: candidateFingerprint (sweep_detector.go)
	// keys on (namespace, kind, name, Reason) alone, and a single object can
	// legitimately carry TWO distinct generic findings of the same predicate
	// at once (a Node reporting both MemoryPressure and DiskPressure as
	// anomalous; an object with two separate dangling references to two
	// different kinds) — a bare fixed Reason would collide the two into one
	// fingerprint and silently drop one. Embedding the condition
	// type/target kind also makes the Finding's Reason more informative on
	// its own, not just fingerprint-safe.
	genericConditionAnomalyReasonPrefix    = "GenericConditionAnomaly:"
	genericDanglingReferenceReasonPrefix   = "GenericDanglingReference:"
	reasonGenericObservedGenerationStale   = "GenericObservedGenerationStale"
	reasonGenericStuckFinalizer            = "GenericStuckFinalizer"
	reasonGenericPeerConditionShapeOutlier = "GenericPeerConditionShapeOutlier"

	// minGenericPolaritySamples / genericPolarityMajorityFraction are this
	// file's stated, revisable heuristic for Mechanism 1 ("learn it from the
	// cluster") — matching this package's existing convention
	// (defaultSweepSustainedThreshold's own doc comment) of naming a
	// judgment call as one rather than dressing it up as derived. E11's own
	// text illustrates the idea with "95% of live instances," which this
	// deliberately does not copy verbatim: requiring 95% would mean needing
	// ~20 live peers before this mechanism can ever reach a verdict, and most
	// real fleets have far fewer than 20 instances of most Kinds in one
	// cluster (a StatefulSet, a CRD instance, an HPA). A sample of 5 with an
	// 80% (4-of-5) majority is still "overwhelming, not a coin flip" while
	// staying reachable for the population sizes this agent actually sees.
	// Below the sample floor, or without a clear majority even above it,
	// this file forwards the observation and lets the hub's polarity gate
	// (internal/conditionpolarity, Mechanism 2) decide instead of guessing.
	minGenericPolaritySamples       = 5
	genericPolarityMajorityFraction = 0.8

	// minPeerGroupSize is predicate 5's own, separate floor: fewer than 3
	// siblings gives "majority" no real meaning (2-of-2 disagreeing has no
	// majority at all; 1-of-1 has nothing to compare against).
	minPeerGroupSize = 3

	// blastRadiusLowFraction / blastRadiusHighFraction: see
	// blastRadiusSeverity's own doc comment (BUGS.md, 2026-09-04 — T1's
	// original affectedCount-only version over-promoted a small minority of
	// a large population to "high"). Named judgment calls, same convention
	// as minGenericPolaritySamples above. 0.10 keeps "roughly one in ten or
	// fewer" at "low" even when that's more than a single object; 0.40
	// requires affected peers to be a genuinely large chunk of the known
	// population — not the majority (this function is never called for a
	// majority reading), but close enough to it that "one outlier" is
	// clearly the wrong description.
	blastRadiusLowFraction  = 0.10
	blastRadiusHighFraction = 0.40

	// genericDanglingReferenceSeverity — see its own doc comment below,
	// next to blastRadiusSeverity/observedGenerationLagSeverity/
	// stuckFinalizerSeverity, for why this one predicate is a REASONED
	// constant rather than a signal-driven function like the other four
	// (BACKLOG.md T1, 2026-09-04).
	genericDanglingReferenceSeverity = "medium"

	// reasonGenericAdmissionPolicyTypeCheckWarning / its severity — PROJECT.md
	// B149. A fixed, reasoned constant rather than a computed one, same
	// justification as genericDanglingReferenceSeverity just above: there is
	// no natural "how many objects are affected" axis for a single broken
	// CEL expression, because what it affects is every FUTURE write its
	// matchConstraints scope covers, an unbounded, not-yet-existing
	// population rather than a countable, already-existing one. "high," not
	// "medium": this predicate's own doc comment explains why a failing
	// admission policy is a categorically higher-consequence class of bug
	// than a dangling reference (a broken pointer to one other object) is.
	reasonGenericAdmissionPolicyTypeCheckWarning = "GenericAdmissionPolicyTypeCheckWarning"
	genericAdmissionPolicyTypeCheckSeverity      = "high"
)

// --- Severity assignment (BACKLOG.md T1, 2026-09-04) ---
//
// Before this pass, all five predicates in this file hardcoded a literal
// severity ("medium" on four of them, "low" on the fifth) regardless of what
// they had actually observed — the exact enumeration failure T1 found sitting
// at the front of the whole lifecycle: severity gates whether auto-analysis
// ever looks at an incident at all (internal/autoanalyze's
// meetsSelectedSeverities), so a predicate that always says "medium" is
// throwing away the one thing that could make that gate meaningful.
//
// Each function below turns a signal the calling predicate ALREADY computes
// (a count, a fraction, a duration) into a severity, rather than adding a new
// per-reason or per-kind lookup table — the latter would just be this same
// mistake with extra steps (T1's own words). None of this needs a kind, a
// kind's condition semantics, or a model call: every input here is a bare
// number already in scope at the call site.
//
// blastRadiusSeverity is shared by predicate 1 (checkGenericConditions) and
// predicate 5 (checkGenericPeerOutlier) because both ask the identical
// question — "of the peers this predicate can currently see, what SHARE
// simultaneously share THIS object's anomalous reading?" — just over a
// different notion of "peer" (same-kind cluster-wide vs. same-owner
// same-namespace siblings). That is exactly the blast-radius framing T1 itself
// uses ("one pod of twenty versus every replica"), just applied to conditions
// and condition-shapes instead of pods — and internal/orchestrator/
// blastradius.go is this codebase's own precedent for turning a real
// count/ratio into a named, justified threshold rather than asserting a
// severity outright, even though that file counts unattended EXECUTIONS, a
// different thing, and isn't reused directly here.
//
// The population floor (minGenericPolaritySamples, 5) and the proportion
// thresholds (blastRadiusLowFraction/blastRadiusHighFraction) are this
// function's own judgment calls, same convention as everywhere else in this
// file — see blastRadiusSeverity's own doc comment for why count alone
// wasn't enough.
// blastRadiusSeverity turns an affected-peer count into a severity relative
// to the known population it was drawn from (totalCount), not the raw count
// alone.
//
// The original (2026-09-04, BACKLOG.md T1) version took only affectedCount:
// anything above 4 was unconditionally "high," so 5 objects sharing an
// anomalous reading out of 6 total and 5 out of 1000 total scored identically.
// Live-tested the same day against a controlled 30-object fixture on rke2 (5
// anomalous, 25 healthy — a real 16.7% minority): the old version reported
// "high" for it, which is the exact over-promotion this rewrite fixes —
// confirmed live, not just by inspection (BUGS.md, T1 follow-up). "One pod of
// twenty is not the same as twenty of twenty": severity now reflects what
// share of the population is affected, not how many objects that share
// happens to be.
//
// Both call sites structurally cap the proportion this can ever see below
// 50% (checkGenericConditions requires an 80%-confident majority, so its
// minority is always < 20%; checkGenericPeerOutlier requires best*2 >
// len(members), so its minority is always < 50%) — this function doesn't
// assume that, but it explains why "high" is reachable in practice mainly
// from predicate 5's larger sibling groups, not predicate 1.
func blastRadiusSeverity(affectedCount, totalCount int) string {
	switch {
	case affectedCount <= 1:
		// Exactly one object carries this reading right now — the "one pod
		// of twenty" case. Isolated, and the common shape for a single
		// object's own transient or object-specific fault. True regardless
		// of totalCount: one object is one object.
		return "low"
	case totalCount < minGenericPolaritySamples:
		// Too small a population to have a meaningful proportion — the same
		// "not enough peers to have an opinion" floor this file uses
		// elsewhere (minGenericPolaritySamples). A confident verdict for a
		// population this size is the hub's own polarity gate's job, not
		// this heuristic's; caps here at "medium," never "high."
		return "medium"
	default:
		proportion := float64(affectedCount) / float64(totalCount)
		switch {
		case proportion < blastRadiusLowFraction:
			// A handful of objects, but a small slice of a much larger
			// population — e.g. 5 of 1000. Worth recording, not worth
			// escalating past what one isolated object would get.
			return "low"
		case proportion < blastRadiusHighFraction:
			// A real pattern, not noise — but not yet the bulk of the known
			// population.
			return "medium"
		default:
			// A large share of everything this file knows about shares this
			// exact anomalous reading, simultaneously — closer to "every
			// replica" than to "one pod of twenty."
			return "high"
		}
	}
}

// observedGenerationLagSeverity turns predicate 2's own already-computed
// signal — metadata.generation minus status.observedGeneration, i.e. how many
// spec changes a controller has failed to even acknowledge — into a
// severity. Deliberately does NOT also weigh how long the gap has persisted:
// this predicate has no authoritative "since when" timestamp for the gap
// itself (see checkGenericObservedGenerationLag's own doc comment — the
// shared firstObserved/sustainedLongEnough mechanism already requires ANY
// report here to have persisted for a full sustainedThreshold before it ever
// reaches this function), and threading per-object first-seen state into this
// one predicate, just to add a second axis, is more machinery than a cheap
// first step calls for. The lag count alone is real, already in scope, and
// already gated by persistence — good enough for this pass.
func observedGenerationLagSeverity(lag int64) string {
	switch {
	case lag <= 1:
		// The single most-recent edit not yet processed. The most common,
		// weakest signal this predicate can report — legitimate rapid
		// edits produce exactly this shape while a controller is still
		// catching up, which is also why this can only ever be reported
		// after surviving the sustained-window gate above, not the instant
		// it appears.
		return "low"
	case lag <= 3:
		// Two or three edits have piled up while the controller had a full
		// sustainedThreshold window to process even the first one. A
		// healthy controller does not fall behind by multiple changes in
		// that much time.
		return "medium"
	default:
		// Four or more unacknowledged changes is not "briefly behind" by
		// any reading — the controller has stopped keeping up with, or
		// stopped reconciling, this object entirely.
		return "high"
	}
}

// stuckFinalizerSeverity turns predicate 3's own already-computed signal —
// how long deletion has been blocked — into a severity, scaled against
// sustainedThreshold (the same agent-configurable window
// checkGenericStuckFinalizer already gates on) rather than an absolute
// wall-clock duration, so this stays meaningful regardless of how an operator
// has tuned that window and needs no change when a new kind starts carrying
// finalizers.
func stuckFinalizerSeverity(age, sustainedThreshold time.Duration) string {
	// checkGenericStuckFinalizer only ever calls this once age >=
	// sustainedThreshold — the earliest point this predicate reports at all
	// — so "medium" already means "confirmed stuck, not a fluke," not
	// "maybe stuck."
	if age < 3*sustainedThreshold {
		return "medium"
	}
	// A working finalizer controller reconciles in seconds to low minutes,
	// not in multiples of an already-generous sustained window. Past 3x the
	// threshold there is no real ambiguity left, and no "critical" tier
	// above this: this predicate is kind-agnostic and has no way to know
	// whether the blocked object is business-critical, so it deliberately
	// stops escalating rather than guessing higher than it can justify.
	return "high"
}

// checkGenericObjectHealth runs all six predicates over one already-built
// snapshot — see this file's own doc comment for why one List pass feeds all
// six instead of six independent passes.
//
// No longer a dynamicSweepChecker with its own client and its own listing:
// since PROJECT.md P28 the snapshot it reads is the SAME one the declarative
// rules read, built once per pass by runUnstructuredSweepHalf, which also
// owns its lifetime and the memory accounting that used to live here. This
// function now does no I/O at all, which is why it can no longer fail.
func checkGenericObjectHealth(snap *unstructuredSnapshot, now time.Time, sustainedThreshold time.Duration) []sweepCandidate {
	objectsByKind := snap.objects
	var out []sweepCandidate
	out = append(out, checkGenericConditions(objectsByKind, now, sustainedThreshold)...)
	out = append(out, checkGenericObservedGenerationLag(objectsByKind, now)...)
	out = append(out, checkGenericStuckFinalizer(objectsByKind, now, sustainedThreshold)...)
	out = append(out, checkGenericDanglingReference(snap, now)...)
	out = append(out, checkGenericPeerOutlier(objectsByKind, now)...)
	out = append(out, checkGenericAdmissionPolicyTypeChecking(objectsByKind, now)...)
	attachOutboundReferences(out, objectsByKind)
	return out
}

// attachOutboundReferences is PROJECT.md B153's reference-direction impact
// signal (see tunnel.Finding.References' own doc comment for the full
// argument). Runs once, here, across EVERY candidate this dispatcher
// produced, regardless of which predicate emitted it — reusing
// findObjectReferences (checkGenericDanglingReference's own extraction,
// B148) rather than a second, hand-maintained notion of what a reference
// looks like. Deliberately a single pass over `out` rather than folding
// this into each predicate individually: every predicate already has to
// re-look-up its own object in objectsByKind for other reasons, so doing it
// once here is strictly less work, not more, and guarantees every future
// predicate gets this field for free without remembering to wire it.
func attachOutboundReferences(out []sweepCandidate, objectsByKind map[string][]*unstructured.Unstructured) {
	for i := range out {
		kind := gvkKindSuffix(out[i].GVK)
		obj := findObjectByIdentity(objectsByKind[kind], out[i].Namespace, out[i].Name)
		if obj == nil {
			continue
		}
		var refs []objectRef
		for key, val := range obj.Object {
			if key == "metadata" {
				continue
			}
			findObjectReferences(val, 0, &refs)
		}
		produced := producedReferences(obj)
		if len(refs) == 0 && len(produced) == 0 {
			continue
		}
		out[i].References = make([]tunnel.ObjectReference, 0, len(refs)+len(produced))
		out[i].References = append(out[i].References, produced...)
		for _, r := range refs {
			// Same defaulting rule checkGenericDanglingReference itself
			// applies: a reference naming no namespace means "the referring
			// object's own namespace" for a namespaced kind (Gateway API's
			// own convention for parentRefs, and most core
			// ObjectReference-family types) — recorded here explicitly
			// rather than left empty, since the hub-side impact check needs
			// to match this against the REAL Gateway/GatewayClass/etc.'s
			// own namespace, not an unresolved blank.
			ns := r.namespace
			if namespaced, known := kindIsNamespaced(r.kind); ns == "" && known && namespaced {
				ns = obj.GetNamespace()
			}
			out[i].References = append(out[i].References, tunnel.ObjectReference{Kind: r.kind, Namespace: ns, Name: r.name})
		}
	}
}

// gvkKindSuffix extracts the bare Kind from this codebase's own
// "<group/version>/<Kind>" wire convention — the last "/"-delimited segment.
func gvkKindSuffix(gvk string) string {
	for i := len(gvk) - 1; i >= 0; i-- {
		if gvk[i] == '/' {
			return gvk[i+1:]
		}
	}
	return gvk
}

// findObjectByIdentity is a small linear scan — objectsByKind's own lists
// are already scoped to one Kind and, per sweep, small (this agent's own
// supportedGVKs set, not a whole cluster's worth of Pods), so a map index
// buys nothing a handful of comparisons doesn't already give for free.
func findObjectByIdentity(objs []*unstructured.Unstructured, namespace, name string) *unstructured.Unstructured {
	for _, o := range objs {
		if o.GetNamespace() == namespace && o.GetName() == name {
			return o
		}
	}
	return nil
}

// --- Predicate 1: status.conditions[] health, kind-agnostic, with
// Mechanism-1 polarity inference (BACKLOG.md E11 pieces 2 and 3). ---

// conditionTally is one (kind, condition type) pair's live vote count this
// sweep — Mechanism 1's raw material.
type conditionTally struct {
	trueCount, falseCount int
}

// observedCondition is one object's one condition, carried from the tally
// pass to the emit pass so the tally (which needs every instance, healthy or
// not) is computed once, fully, before any candidate is decided.
type observedCondition struct {
	obj            *unstructured.Unstructured
	kind           string
	condType       string
	value          string // "True" | "False" — "Unknown"/malformed never reach here
	lastTransition time.Time
	// parentPath is where under status this condition was found, when it is
	// not the conventional top-level status.conditions[] — see
	// findConditionGroups' own doc comment (PROJECT.md B154).
	parentPath string
}

// conditionGroup is one array of condition-shaped objects found somewhere
// under an object's status, together with a human-readable label for WHERE
// it was found (empty for the conventional top-level status.conditions[]).
type conditionGroup struct {
	label string
	conds []any
}

// findConditionGroups walks v — typically an object's own status subtree —
// looking for arrays of condition-shaped objects (see looksLikeConditionArray)
// at ANY depth, not just the conventional top-level status.conditions[].
// This is PROJECT.md B154's fix: checkGenericConditions used to read exactly
// one path (unstructured.NestedSlice(o, "status", "conditions")), so any kind
// that reports its real diagnosis per-child — Gateway API's
// status.listeners[].conditions, HTTPRoute's status.parents[].conditions,
// and any future CRD following the same convention — was partly or wholly
// invisible. Conditions are found by SHAPE (does this array's every element
// carry type/status/reason/message?), never by a per-kind table of where to
// look, so a new CRD needs zero new code here to be seen the same way.
//
// path accumulates a positional description ("listeners[0]", "parents[0]")
// as recursion descends through maps and slices; it is not itself the
// group's label — describeContainer turns it into one, preferring a real
// name over a bare index. Recursion stops descending into an array once it
// is recognized as a condition array: its elements are conditions, not
// further containers to search.
func findConditionGroups(v any, path string) []conditionGroup {
	switch val := v.(type) {
	case map[string]any:
		var groups []conditionGroup
		for key, sub := range val {
			if arr, ok := sub.([]any); ok && looksLikeConditionArray(arr) {
				groups = append(groups, conditionGroup{label: describeContainer(val, path), conds: arr})
				continue
			}
			childPath := key
			if path != "" {
				childPath = path + "." + key
			}
			groups = append(groups, findConditionGroups(sub, childPath)...)
		}
		return groups
	case []any:
		var groups []conditionGroup
		for i, item := range val {
			groups = append(groups, findConditionGroups(item, fmt.Sprintf("%s[%d]", path, i))...)
		}
		return groups
	default:
		return nil
	}
}

// looksLikeConditionArray is the shape test findConditionGroups matches
// against, deliberately independent of the array's own key name (real
// status subresources always call it "conditions", but this never keys on
// that string): non-empty, and every element is a map carrying a non-empty
// string "type", a string "status" that is one of the three values the
// Kubernetes API convention ever sets, and at least one of "reason"/
// "message" — the rest of a real metav1.Condition-shaped object. Requiring
// ALL elements to match, not just one, keeps this from misfiring on an
// array that merely happens to contain one condition-shaped object among
// otherwise-unrelated ones.
func looksLikeConditionArray(arr []any) bool {
	if len(arr) == 0 {
		return false
	}
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			return false
		}
		typ, hasType := m["type"].(string)
		status, hasStatus := m["status"].(string)
		if !hasType || typ == "" || !hasStatus {
			return false
		}
		if status != "True" && status != "False" && status != "Unknown" {
			return false
		}
		_, hasReason := m["reason"]
		_, hasMessage := m["message"]
		if !hasReason && !hasMessage {
			return false
		}
	}
	return true
}

// describeContainer turns a condition group's own container object (the map
// that held the condition array under some key) into a human-readable
// label: a real name when one can be found, the bare positional path
// otherwise. Empty for the top-level status object itself (path == "" and
// no name), matching the conventional top-level status.conditions[] case,
// which needs no extra clause on a Finding.
func describeContainer(container map[string]any, path string) string {
	name := containerName(container)
	switch {
	case path == "" && name == "":
		return ""
	case name != "":
		return fmt.Sprintf("%s (%s)", path, name)
	default:
		return path
	}
}

// containerName looks for a human-readable identifier on a condition
// group's own container — checked generically, never via a per-kind key
// path: a direct string "name" field first (matches Gateway API's own
// status.listeners[] entries, which name their listener directly), then a
// string "name" field one level into any nested map (matches HTTPRoute's
// status.parents[] entries, which name their parent one level down, under
// their own "parentRef").
func containerName(container map[string]any) string {
	if name, ok := container["name"].(string); ok && name != "" {
		return name
	}
	for _, sub := range container {
		if nested, ok := sub.(map[string]any); ok {
			if name, ok := nested["name"].(string); ok && name != "" {
				return name
			}
		}
	}
	return ""
}

// checkGenericConditions walks status.conditions[] on every object this
// sweep listed and flags an object whose condition value differs from what
// the overwhelming majority of its SAME-KIND live peers currently report for
// the SAME condition type — Mechanism 1, "learn it from the cluster." It
// never hardcodes which literal value ("True"/"False") is the bad one for
// any condition type: MemoryPressure=True and Ready=False both get caught
// the identical way, by being the minority reading, not by name.
//
// Three outcomes per (kind, conditionType) pair, computed fresh every sweep
// since the live population can change sweep to sweep:
//
//   - Too few live peers (< minGenericPolaritySamples) to have a local
//     opinion at all — every instance is forwarded, unconditionally, letting
//     the hub's polarity gate (internal/conditionpolarity, Mechanism 2)
//     decide. This is the ONLY path a brand-new or low-population CRD kind's
//     condition ever takes, and it is intentional: a single live instance is
//     definitionally 100% of "its own majority," so a same-sweep local
//     comparison can never flag it no matter how broken it is.
//   - Enough peers, and a confident majority (>= genericPolarityMajorityFraction)
//     — the minority reading(s) are forwarded as anomalies, matching
//     Mechanism 1 exactly.
//   - Enough peers, but no confident majority either way — a genuinely mixed
//     population this mechanism has no local basis to call. Deliberately
//     SKIPPED rather than forwarding every instance: E11's own cost warning
//     ("noisier by construction") is exactly why re-reporting a condition
//     type that is persistently, legitimately split across the fleet, every
//     sweep, forever, would be the wrong trade.
func checkGenericConditions(objectsByKind map[string][]*unstructured.Unstructured, now time.Time, sustainedThreshold time.Duration) []sweepCandidate {
	tallies := make(map[string]*conditionTally) // key: kind + "\x1f" + conditionType
	var observed []observedCondition

	for kind, objs := range objectsByKind {
		for _, o := range objs {
			if kind == "Pod" && terminalPodPhases[podPhase(o)] {
				// BUGS.md 137: this is the predicate the bug actually
				// describes — a cluster-wide majority/minority tally over
				// EVERY Pod of the given condition type. A completed Job's
				// Ready=False (reason PodCompleted) is correct and
				// permanent, but against a cluster where most pods are
				// long-running and Ready=True, every completed pod becomes
				// a forever-minority the moment it finishes — observed live
				// as three real incidents, one 79 days old, with 643/736/741
				// occurrences. Excluded from the tally entirely: a terminal
				// pod is not part of the population "most pods are
				// long-running and Ready=True" describes, on either side of
				// the count. See checkGenericPeerOutlier's identical
				// exclusion for the same-owner-siblings version of this.
				continue
			}
			status, ok := o.Object["status"]
			if !ok {
				continue
			}
			// Every condition array found anywhere under status — the
			// conventional top-level status.conditions[] AND any nested,
			// per-child one (status.listeners[].conditions,
			// status.parents[].conditions) — is tallied into the SAME
			// (kind, conditionType) bucket, uniformly, regardless of depth.
			// A multi-listener object therefore contributes one vote per
			// listener rather than one vote per object; this is a
			// deliberate simplification (findConditionGroups' own doc
			// comment on "no per-kind table" applies here too — special-
			// casing population weighting per nesting depth would be
			// exactly the kind of per-shape knowledge this predicate exists
			// to avoid), and harmless in practice: a real fault's own
			// object population is typically small enough on any single
			// cluster to fail open into the low-population branch below
			// regardless (see minGenericPolaritySamples).
			for _, group := range findConditionGroups(status, "") {
				for _, raw := range group.conds {
					cm, ok := raw.(map[string]any)
					if !ok {
						continue
					}
					condType, _ := cm["type"].(string)
					value, _ := cm["status"].(string)
					if condType == "" || (value != "True" && value != "False") {
						// "Unknown," or a malformed condition, carries no
						// polarity signal either mechanism can use.
						continue
					}
					key := kind + "\x1f" + condType
					t := tallies[key]
					if t == nil {
						t = &conditionTally{}
						tallies[key] = t
					}
					if value == "True" {
						t.trueCount++
					} else {
						t.falseCount++
					}
					var lastTransition time.Time
					if ts, _ := cm["lastTransitionTime"].(string); ts != "" {
						if parsed, err := time.Parse(time.RFC3339, ts); err == nil {
							lastTransition = parsed
						}
					}
					observed = append(observed, observedCondition{obj: o, kind: kind, condType: condType, value: value, lastTransition: lastTransition, parentPath: group.label})
				}
			}
		}
	}

	var out []sweepCandidate
	for _, oc := range observed {
		t := tallies[oc.kind+"\x1f"+oc.condType]
		total := t.trueCount + t.falseCount

		var majorityValue string
		var majorityFraction float64
		flagged := false

		switch {
		case total < minGenericPolaritySamples:
			flagged = true
		default:
			trueFrac := float64(t.trueCount) / float64(total)
			falseFrac := float64(t.falseCount) / float64(total)
			switch {
			case trueFrac >= genericPolarityMajorityFraction:
				majorityValue, majorityFraction = "True", trueFrac
			case falseFrac >= genericPolarityMajorityFraction:
				majorityValue, majorityFraction = "False", falseFrac
			default:
				continue // no confident local majority — see doc comment
			}
			flagged = oc.value != majorityValue
		}
		if !flagged {
			continue
		}

		var transition metav1.Time
		if !oc.lastTransition.IsZero() {
			transition = metav1.NewTime(oc.lastTransition)
		}
		sustainedFrom, report := conditionSustainedFrom(transition, now, sustainedThreshold)
		if !report {
			continue
		}

		// BACKLOG.md T1 (2026-09-04): severity is blastRadiusSeverity of how
		// many live peers currently share THIS object's own reading —
		// affectedCount below — not a flat "medium" for every anomaly this
		// predicate ever reports. Two branches, matching the two ways flagged
		// became true above:
		//   - No confident majority exists yet (majorityValue == "", the
		//     low-population fail-open path): there is no minority/majority
		//     split to measure, so affectedCount is simply total, i.e. a
		//     100% "proportion" by construction — this branch only ever
		//     runs below minGenericPolaritySamples (5), which
		//     blastRadiusSeverity explicitly caps at "medium" regardless of
		//     proportion; the hub's own polarity gate, not this heuristic,
		//     carries the real verdict for a population this small.
		//   - A confident majority exists: affectedCount is the raw count of
		//     live peers reading the SAME value oc does — the minority size
		//     in absolute terms, which is the number of objects a wrong
		//     verdict here would actually be about.
		affectedCount := total
		if majorityValue != "" {
			if oc.value == "True" {
				affectedCount = t.trueCount
			} else {
				affectedCount = t.falseCount
			}
		}

		out = append(out, sweepCandidate{
			GVK: oc.obj.GetAPIVersion() + "/" + oc.kind, Namespace: oc.obj.GetNamespace(), Name: oc.obj.GetName(),
			UID: string(oc.obj.GetUID()), ResourceVersion: oc.obj.GetResourceVersion(),
			Reason:        genericConditionAnomalyReasonPrefix + oc.condType,
			Message:       genericConditionMessage(oc, total, majorityValue, majorityFraction),
			Severity:      blastRadiusSeverity(affectedCount, total),
			Class:         tunnel.FindingClassAnomaly,
			Confidence:    tunnel.FindingConfidenceUnverified,
			Impact:        tunnel.FindingImpactNone,
			SustainedFrom: sustainedFrom,
			OccurredAt:    firstNonZeroTime(sustainedFrom, now),

			ConditionType:             oc.condType,
			ConditionObservedValue:    oc.value,
			ConditionSampleCount:      total,
			ConditionMajorityValue:    majorityValue,
			ConditionMajorityFraction: majorityFraction,
			ConditionParentPath:       oc.parentPath,
		})
	}
	return out
}

// genericConditionMessage's parenthetical "(at ...)" clause is PROJECT.md
// B154's own "done when" requirement: an operator reading only the message
// (never the structured ConditionParentPath field) must still be able to
// tell WHICH listener or parent is broken, not just which object.
func genericConditionMessage(oc observedCondition, total int, majorityValue string, majorityFraction float64) string {
	where := ""
	if oc.parentPath != "" {
		where = fmt.Sprintf(" (at %s)", oc.parentPath)
	}
	if majorityValue == "" {
		return fmt.Sprintf("%s condition %s%s reads %s, and only %d live %s instance(s) exist cluster-wide — too few to tell locally whether that is normal; the hub will resolve this against its persisted polarity cache or ask the model once",
			oc.kind, oc.condType, where, oc.value, total, oc.kind)
	}
	return fmt.Sprintf("%s condition %s%s reads %s, but %.0f%% of %d live %s instance(s) cluster-wide read %s — this object is the outlier, not the norm",
		oc.kind, oc.condType, where, oc.value, majorityFraction*100, total, oc.kind, majorityValue)
}

// --- Predicate 2: metadata.generation vs status.observedGeneration. ---

// checkGenericObservedGenerationLag flags an object whose controller has
// stopped converging — its own generation has moved past what the
// controller last observed/acted on. Absent today (BACKLOG.md E11's own
// table); kind-agnostic because it reads the exact same two field paths
// regardless of Kind, and only ever fires for a Kind whose controller
// actually publishes status.observedGeneration in the first place (most do
// not skip it silently; a kind that never sets the field at all is simply
// never a candidate, not a false negative this predicate could fix).
//
// No authoritative "since when" timestamp exists for this gap on the object
// itself — SustainedFrom is left zero so the shared firstObserved gate
// (sustainedLongEnough) decides based on how long THIS detector has actually
// observed the lag, the same honest fallback checkStatefulSetReplicas/
// checkDaemonSetReplicas already use for the identical reason.
func checkGenericObservedGenerationLag(objectsByKind map[string][]*unstructured.Unstructured, now time.Time) []sweepCandidate {
	var out []sweepCandidate
	for kind, objs := range objectsByKind {
		for _, o := range objs {
			gen := o.GetGeneration()
			if gen == 0 {
				continue // this kind doesn't track generation at all
			}
			observedGen, found, _ := unstructured.NestedInt64(o.Object, "status", "observedGeneration")
			if !found || observedGen >= gen {
				continue // controller doesn't publish the field, or has converged
			}
			lag := gen - observedGen
			out = append(out, sweepCandidate{
				GVK: o.GetAPIVersion() + "/" + kind, Namespace: o.GetNamespace(), Name: o.GetName(),
				UID: string(o.GetUID()), ResourceVersion: o.GetResourceVersion(),
				Reason: reasonGenericObservedGenerationStale,
				Message: fmt.Sprintf("metadata.generation is %d but status.observedGeneration is %d — the controller responsible for this object's spec has not processed the last %d change(s), or has stopped reconciling it",
					gen, observedGen, lag),
				// BACKLOG.md T1 (2026-09-04): severity is a function of the
				// lag itself — see observedGenerationLagSeverity's own doc
				// comment for why duration isn't also factored in here.
				Severity:   observedGenerationLagSeverity(lag),
				OccurredAt: now,
			})
		}
	}
	return out
}

// --- Predicate 3: metadata.deletionTimestamp age (stuck finalizer). ---

// checkGenericStuckFinalizer flags an object that has carried a
// deletionTimestamp for at least sustainedThreshold and still exists —
// deletion is blocked by a finalizer nothing is removing, on ANY kind, not
// just the kinds this repo happens to special-case today. Absent today
// (BACKLOG.md E11's own table).
//
// deletionTimestamp IS an authoritative timestamp (unlike predicate 2), so
// this applies the threshold directly and sets SustainedFrom to the real
// value, exactly like checkPVCPending's own use of a trustworthy creation
// timestamp.
func checkGenericStuckFinalizer(objectsByKind map[string][]*unstructured.Unstructured, now time.Time, sustainedThreshold time.Duration) []sweepCandidate {
	var out []sweepCandidate
	for kind, objs := range objectsByKind {
		for _, o := range objs {
			dt := o.GetDeletionTimestamp()
			if dt == nil || dt.IsZero() {
				continue
			}
			age := now.Sub(dt.Time)
			if age < sustainedThreshold {
				continue
			}
			out = append(out, sweepCandidate{
				GVK: o.GetAPIVersion() + "/" + kind, Namespace: o.GetNamespace(), Name: o.GetName(),
				UID: string(o.GetUID()), ResourceVersion: o.GetResourceVersion(),
				Reason: reasonGenericStuckFinalizer,
				Message: fmt.Sprintf("has carried a deletionTimestamp for %s and still exists — deletion is blocked by finalizer(s) %v that nothing is removing",
					age.Round(time.Second), o.GetFinalizers()),
				// BACKLOG.md T1 (2026-09-04): severity scales with how long
				// deletion has actually been blocked, relative to this
				// agent's own sustainedThreshold — see
				// stuckFinalizerSeverity's own doc comment.
				Severity:      stuckFinalizerSeverity(age, sustainedThreshold),
				SustainedFrom: dt.Time,
				OccurredAt:    dt.Time,
			})
		}
	}
	return out
}

// checkGenericAdmissionPolicyTypeChecking is PROJECT.md B149's detection
// mechanism: a ValidatingAdmissionPolicy whose own status.typeChecking field
// — populated by the API server itself, the moment the policy is created or
// changed, from the SAME OpenAPI schema internal/agent/resourceschema.go's
// get_resource_schema tool reads (B147) — reports that one of its CEL
// expressions cannot possibly match anything on the resource kind(s) it is
// scoped to (a typo'd field, a field that belongs to a different kind
// entirely). Confirmed live 2026-09-06 against this project's own rke2 test
// cluster: `object.spec.bogusField` against a ConfigMap (which has no spec)
// populated exactly this shape, immediately, with no sweep delay needed —
// this is not indirect evidence the way a stuck finalizer's age is; the API
// server has already made the determination.
//
// # Why this matters enough to build, per B149's own framing
//
// A failing admission policy or webhook blocks EVERY write its
// matchConstraints/rules scope covers — silently: there is no Kubernetes
// Event for a rejected admission (the object is never created, so there is
// no object to attach an event to), and the only visibility today is a
// caller noticing their own write failed, one at a time, with no
// cluster-wide signal tying repeated failures back to the one
// misconfigured policy responsible for all of them. High blast radius,
// currently completely silent.
//
// # What this deliberately does NOT catch (an honest, named boundary)
//
// status.typeChecking is STATIC analysis — it flags an expression that is
// provably wrong given the matched resource's own schema, at policy-authoring
// time. It cannot and does not catch a RUNTIME-only CEL evaluation failure
// against a specific denied object (the exact live shape a genuinely dynamic
// field access like `object.data.someKey` produces when `someKey` happens to
// be absent on ONE particular object but not the type generally) — that
// failure mode has no watchable Kubernetes object or status field anywhere;
// observing it would need cluster audit-log access, which is separately
// scoped, much higher-privilege work this read-only agent identity
// deliberately does not have. Recorded as a real, deliberate limitation, not
// silently overclaimed: this predicate closes the STATIC half of B149, not
// the whole of it.
func checkGenericAdmissionPolicyTypeChecking(objectsByKind map[string][]*unstructured.Unstructured, now time.Time) []sweepCandidate {
	var out []sweepCandidate
	for _, o := range objectsByKind["ValidatingAdmissionPolicy"] {
		warnings, ok, err := unstructured.NestedSlice(o.Object, "status", "typeChecking", "expressionWarnings")
		if err != nil || !ok || len(warnings) == 0 {
			continue
		}
		first, _ := warnings[0].(map[string]any)
		fieldRef, _ := first["fieldRef"].(string)
		warning, _ := first["warning"].(string)
		out = append(out, sweepCandidate{
			GVK: o.GetAPIVersion() + "/ValidatingAdmissionPolicy", Namespace: "", Name: o.GetName(),
			UID: string(o.GetUID()), ResourceVersion: o.GetResourceVersion(),
			Reason: reasonGenericAdmissionPolicyTypeCheckWarning,
			Message: fmt.Sprintf("this cluster's own type-checking of %d CEL expression(s) in this policy reports at least one that cannot match its own matched resource kind — first: %s: %s (every write this policy's matchConstraints scope covers is at risk of being wrongly denied or, if failurePolicy is Ignore, wrongly waved through)",
				len(warnings), fieldRef, warning),
			Severity:   genericAdmissionPolicyTypeCheckSeverity,
			OccurredAt: now,
		})
	}
	return out
}

// --- Predicate 4: reference integrity, generalized. ---

// objectRef is one {kind, name[, namespace]}-shaped map value found while
// walking an object's spec/status — see this file's own doc comment for
// exactly how far this generalizes and what it deliberately does not reach.
type objectRef struct {
	kind, name, namespace string
}

// findObjectReferences recursively walks v (a decoded JSON value: map,
// slice, or scalar) looking for any map that carries non-empty string
// fields "kind" and "name" together — the shape every core Kubernetes
// ObjectReference-family type already uses. Bounded to depth 8, which is far
// deeper than any real spec/status nests in practice; the bound exists only
// so a pathological object can never cause unbounded recursion.
func findObjectReferences(v any, depth int, out *[]objectRef) {
	if depth > 8 {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		kind, kindOK := t["kind"].(string)
		name, nameOK := t["name"].(string)
		if kindOK && nameOK && kind != "" && name != "" {
			ns, _ := t["namespace"].(string)
			*out = append(*out, objectRef{kind: kind, name: name, namespace: ns})
		}
		for _, vv := range t {
			findObjectReferences(vv, depth+1, out)
		}
	case []any:
		for _, vv := range t {
			findObjectReferences(vv, depth+1, out)
		}
	}
}

// checkGenericDanglingReference flags an object naming, via the
// kind+name convention above, another object that does not currently exist
// — BACKLOG.md E11's generalization of selectorMatchesNoPods's own narrower
// pattern (a Pod-selector-specific check) to arbitrary kind+name references.
// The most common config-fault shape in the issue catalogue, per E11's own
// table, and today built only per-kind.
//
// # It reports "does not exist", never "I could not look" (PROJECT.md B185)
//
// This predicate reads the ABSENCE of an object as a fact, so it may only
// speak about a kind this pass actually read. Two separate guards enforce
// that, and both are silences rather than findings: kindIsNamespaced's
// known=false for a kind outside this agent's watched set, and
// unstructuredSnapshot.readable for one inside it that was not read — RBAC
// denied, not served, refused by the memory guard, or never listed by
// policy. Without the second, narrowing the agent's ClusterRole by one kind
// turns every reference into that kind, across the whole cluster, into a
// fabricated broken-reference finding, and the product gets less truthful
// exactly as an operator makes it less privileged.
//
// No sustained-window gate: unlike a condition or a replica shortfall, a
// reference either names something that exists right now or it doesn't —
// there is no "briefly, normally true during a rollout" transient state to
// wait out the way there is for the other four predicates (the object being
// referenced, once created, either matches immediately or the reference was
// wrong from the start). SustainedFrom is left zero, so the shared
// firstObserved gate still applies via sustainedLongEnough — a dangling
// reference must still be OBSERVED for sustainedThreshold before being
// reported, exactly like every other kind-agnostic predicate in this file,
// so a reference to an object that is simply being created in the same
// apply/rollout (a HPA applied a moment before its target Deployment) is not
// reported as broken.
//
// # Severity (BACKLOG.md T1, 2026-09-04) — a reasoned constant, not a
// leftover copy-paste
//
// The other four predicates in this file turn a real, already-computed
// signal (a population count, a lag, an age) into severity. This one
// deliberately does not, and that is a considered answer, not an oversight:
// a dangling reference is a binary property of ONE relationship (the target
// exists right now, or it doesn't), and unlike a condition anomaly or a
// peer-shape outlier there is no natural "how many objects are affected by
// the SAME thing" count sitting in scope here — every dangling reference is
// its own independent fact about its own referring object, at the moment
// this predicate looks. (A cross-object tally — "how many other objects
// reference this exact missing target" — was considered and rejected for
// this pass: it would need a second full pass over every reference this
// sweep found just to add one axis, which is more machinery than a cheap
// first step earns, when the constant below is already a defensible floor.)
//
// "medium," not "low": a dangling reference usually means something a spec
// depends on cannot be resolved, which is more than cosmetic even when
// nothing crashes outright (an HPA whose scaleTargetRef is gone simply never
// scales anything, silently). "medium," not "high"/"critical": this
// predicate cannot tell a genuine typo from an object that is mid-rollout in
// a way its own sustained-window gate (see above) hasn't fully filtered, and
// it has no kind-specific knowledge of how consequential THIS particular
// reference is to treat every instance as an emergency by default.
func checkGenericDanglingReference(snap *unstructuredSnapshot, now time.Time) []sweepCandidate {
	var out []sweepCandidate
	existenceIndex := snap.existenceIndex()
	for kind, objs := range snap.objects {
		for _, o := range objs {
			var refs []objectRef
			// PROJECT.md B148: every top-level key except metadata, not just
			// spec/status. Confirmed live 2026-09-06 (breadth-campaign
			// RBAC-004 fixture): a RoleBinding's own subjects/roleRef sit at
			// the TOP LEVEL, as siblings of apiVersion/kind/metadata — they
			// are not nested under a spec or a status at all, which most
			// built-in kinds have but which is a convention, not a rule the
			// API enforces on every kind. A hardcoded two-key allowlist is
			// exactly the enumeration problem this predicate exists to
			// generalize away from; scanning everything except metadata
			// covers RoleBinding and any future kind with the identical
			// top-level shape without adding a third named key, a fourth,
			// and so on.
			//
			// metadata is the one deliberate exclusion, not an oversight:
			// metadata.ownerReferences also carries a kind+name pair
			// findObjectReferences would happily match, but owner-reference
			// garbage collection is a different Kubernetes mechanism with
			// different semantics — a stale ownerReference can be a
			// deliberate, correct state (an object orphaned on purpose via
			// --cascade=orphan), not a fault this predicate should flag.
			for key, val := range o.Object {
				if key == "metadata" {
					continue
				}
				findObjectReferences(val, 0, &refs)
			}
			for _, r := range refs {
				namespaced, known := kindIsNamespaced(r.kind)
				if !known {
					// Cannot verify — this agent has no watch on that kind at
					// all. Silence, not a claim of dangling-ness.
					continue
				}
				if !snap.readable(r.kind) {
					// PROJECT.md B185: this agent watches that kind but did
					// not actually read it this pass — RBAC denies it, the
					// API server does not serve it, the memory guard refused
					// it, or it is one this agent deliberately never lists
					// (Secret). An empty existence index for such a kind is a
					// fact about THIS AGENT, not about the cluster, and
					// reporting a reference into it as broken would
					// manufacture an incident out of a permission boundary —
					// worse the narrower the grant, which is the direction
					// E11 is moving. Same silence as an unknown kind above,
					// for the same reason: it genuinely cannot verify.
					//
					// Deliberately NOT a finding of its own here. "This
					// agent cannot read Kind X" is one fact about the agent's
					// configuration, not one per reference into X; it is
					// reported once per pass on the detector's own run state
					// (runUnstructuredSweepHalf) where an operator can act on
					// it, instead of as a flood of per-object findings that
					// look like cluster faults.
					continue
				}
				ns := r.namespace
				if ns == "" && namespaced {
					ns = o.GetNamespace()
				}
				if existenceIndex[r.kind][ns+"/"+r.name] {
					continue
				}
				out = append(out, sweepCandidate{
					GVK: o.GetAPIVersion() + "/" + kind, Namespace: o.GetNamespace(), Name: o.GetName(),
					UID: string(o.GetUID()), ResourceVersion: o.GetResourceVersion(),
					Reason:     genericDanglingReferenceReasonPrefix + r.kind,
					Message:    fmt.Sprintf("references a %s named %q that does not currently exist%s", r.kind, r.name, danglingRefNamespaceClause(ns, namespaced)),
					Severity:   genericDanglingReferenceSeverity,
					Class:      tunnel.FindingClassAnomaly,
					Confidence: tunnel.FindingConfidenceUnverified,
					Impact:     tunnel.FindingImpactNone,
					OccurredAt: now,
				})
			}
		}
	}
	return out
}

func danglingRefNamespaceClause(namespace string, namespaced bool) string {
	if !namespaced || namespace == "" {
		return ""
	}
	return fmt.Sprintf(" in namespace %q", namespace)
}

// --- Predicate 5: peer-relative outlier. ---

// checkGenericPeerOutlier flags an object whose status.conditions[] "shape"
// (the sorted set of type=status pairs it reports) differs from the majority
// shape among its SIBLINGS — same Kind, same namespace, same controlling
// owner — with no per-kind knowledge of what a "normal" shape looks like.
// Absent today (BACKLOG.md E11's own table). See this file's own doc comment
// for why conditions-shape was chosen as the concrete signal over e.g. a
// restart-count comparison.
//
// Requires at least minPeerGroupSize siblings and a genuine majority (more
// than half sharing one shape) before calling anything an outlier — with
// only 2 siblings disagreeing, or 3 siblings in 3 different shapes, there is
// no "normal" to diverge from.
//
// No sustained-window gate for the same reason predicate 4 has none: a
// conditions-shape mismatch is evaluated fresh against this sweep's own
// snapshot each time (there is no "since when" for a relative comparison
// across several objects), and the shared firstObserved gate still requires
// it to be observed for sustainedThreshold before being reported.
// terminalPodPhases are the two Pod-specific phases (BUGS.md 137) where
// status.conditions reading e.g. Ready=False is the expected, permanent
// outcome, not a live symptom — a completed Job/CronJob/one-off pod. Only
// meaningful for kind=="Pod"; status.phase's value set means something
// different for every other kind that has one (PVC, PV, Namespace).
var terminalPodPhases = map[string]bool{"Succeeded": true, "Failed": true}

func podPhase(o *unstructured.Unstructured) string {
	phase, _, _ := unstructured.NestedString(o.Object, "status", "phase")
	return phase
}

func checkGenericPeerOutlier(objectsByKind map[string][]*unstructured.Unstructured, now time.Time) []sweepCandidate {
	type sibling struct {
		obj   *unstructured.Unstructured
		shape string
	}
	groups := make(map[string][]sibling)

	for kind, objs := range objectsByKind {
		for _, o := range objs {
			if kind == "Pod" && terminalPodPhases[podPhase(o)] {
				// BUGS.md 137: a completed Job/CronJob/one-off pod's
				// Ready=False (reason PodCompleted) is the correct,
				// permanent reading, not a divergence from its still-running
				// siblings — comparing it against them made it a permanent
				// "minority of one," forever, on every sweep (observed live:
				// three incidents with 643/736/741 occurrences, one 79 days
				// old). Scoped to kind=="Pod" specifically: status.phase
				// means something else entirely for a PVC/PV, so this is a
				// deliberate, narrow exception to this file's
				// kind-agnostic rule, not a precedent for more of them — a
				// terminal pod's OWN conditions are still visible to
				// predicates 1-4, just not compared against non-terminal
				// peers it can structurally never match.
				continue
			}
			owner := controllingOwnerUID(o.GetOwnerReferences())
			if owner == "" {
				continue // nothing to compare it against as a "sibling set"
			}
			key := kind + "\x1f" + o.GetNamespace() + "\x1f" + owner
			groups[key] = append(groups[key], sibling{obj: o, shape: conditionsShape(o)})
		}
	}

	var out []sweepCandidate
	for _, members := range groups {
		if len(members) < minPeerGroupSize {
			continue
		}
		shapeCounts := make(map[string]int)
		for _, m := range members {
			shapeCounts[m.shape]++
		}
		var majorityShape string
		best := 0
		// Deterministic tie-break (lexicographically smallest shape wins a
		// tie) so this function's output doesn't depend on Go's unspecified
		// map iteration order — irrelevant to correctness (a tie is rejected
		// below regardless of which shape "wins" it) but keeps this
		// reproducible for tests.
		var shapes []string
		for shape := range shapeCounts {
			shapes = append(shapes, shape)
		}
		sort.Strings(shapes)
		for _, shape := range shapes {
			if shapeCounts[shape] > best {
				best, majorityShape = shapeCounts[shape], shape
			}
		}
		if best*2 <= len(members) {
			// No genuine majority — a 2-vs-2 split, or every sibling in its
			// own distinct shape. Nothing to call "normal."
			continue
		}
		for _, m := range members {
			if m.shape == majorityShape {
				continue
			}
			// BACKLOG.md T1 (2026-09-04): severity is blastRadiusSeverity of
			// how many siblings in THIS group currently share m's own
			// off-majority shape (shapeCounts[m.shape], already computed
			// above to find majorityShape) — not a flat "low" for every
			// outlier regardless of whether it's alone in its reading or
			// one of several siblings reporting the identical divergent
			// shape. By construction (the majority guard just above) this
			// count is always less than half of len(members), so it shares
			// blastRadiusSeverity's exact "one pod of twenty vs. a real
			// chunk of the fleet" reasoning with predicate 1, just applied
			// to conditions-shape membership instead of a single condition's
			// value.
			out = append(out, sweepCandidate{
				GVK: m.obj.GetAPIVersion() + "/" + m.obj.GetKind(), Namespace: m.obj.GetNamespace(), Name: m.obj.GetName(),
				UID: string(m.obj.GetUID()), ResourceVersion: m.obj.GetResourceVersion(),
				Reason: reasonGenericPeerConditionShapeOutlier,
				Message: fmt.Sprintf("this object's status.conditions[] shape (%q) differs from %d of its %d sibling(s) sharing the same owner and namespace, which read (%q)",
					m.shape, best, len(members), majorityShape),
				Severity:   blastRadiusSeverity(shapeCounts[m.shape], len(members)),
				Class:      tunnel.FindingClassAnomaly,
				Confidence: tunnel.FindingConfidenceInferred,
				Impact:     tunnel.FindingImpactNone,
				OccurredAt: now,
			})
		}
	}
	return out
}

func controllingOwnerUID(refs []metav1.OwnerReference) string {
	for _, r := range refs {
		if r.Controller != nil && *r.Controller {
			return string(r.UID)
		}
	}
	return ""
}

func conditionsShape(o *unstructured.Unstructured) string {
	conds, found, _ := unstructured.NestedSlice(o.Object, "status", "conditions")
	if !found {
		return "<no-conditions>"
	}
	var parts []string
	for _, raw := range conds {
		cm, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		t, _ := cm["type"].(string)
		s, _ := cm["status"].(string)
		if t == "" {
			continue
		}
		parts = append(parts, t+"="+s)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}
