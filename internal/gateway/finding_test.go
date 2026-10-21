package gateway

import (
	"strings"
	"testing"
	"time"

	"argus/internal/domain"
	"argus/internal/tunnel"
)

// TestNextLastSeen covers handleFinding's out-of-order-delivery guard: an
// incident's last_seen must advance when a finding genuinely happened later
// than what's recorded, and must never regress when it didn't.
func TestNextLastSeen(t *testing.T) {
	base := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name              string
		currentLastSeen   time.Time
		findingOccurredAt time.Time
		want              time.Time
	}{
		{
			name:              "later finding advances last_seen",
			currentLastSeen:   base,
			findingOccurredAt: base.Add(5 * time.Minute),
			want:              base.Add(5 * time.Minute),
		},
		{
			name:              "earlier finding (out-of-order delivery) does not regress last_seen",
			currentLastSeen:   base,
			findingOccurredAt: base.Add(-5 * time.Minute),
			want:              base,
		},
		{
			name:              "identical timestamp is a no-op, not treated as an advance",
			currentLastSeen:   base,
			findingOccurredAt: base,
			want:              base,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nextLastSeen(tt.currentLastSeen, tt.findingOccurredAt)
			if !got.Equal(tt.want) {
				t.Errorf("nextLastSeen(%v, %v) = %v, want %v", tt.currentLastSeen, tt.findingOccurredAt, got, tt.want)
			}
		})
	}
}

// TestIsClosedIncidentState guards the exact two-state "closed" boundary
// this increment's correlation rule uses — every other state in
// incidents.state's CHECK constraint (including ones nothing in this
// codebase can transition an incident into yet, like Investigating or
// AwaitingApproval) must count as still-open.
func TestIsClosedIncidentState(t *testing.T) {
	closed := []string{"Resolved", "Dismissed"}
	for _, s := range closed {
		if !isClosedIncidentState(s) {
			t.Errorf("isClosedIncidentState(%q) = false, want true", s)
		}
	}

	open := []string{
		"Detected", "Investigating", "RecommendationReady", "NeedsHumanInvestigation",
		"AwaitingApproval", "Executing", "AwaitingMerge", "Validating", "Failed", "Reopened",
		"", "resolved", "dismissed", // case-sensitivity / empty-string guards
	}
	for _, s := range open {
		if isClosedIncidentState(s) {
			t.Errorf("isClosedIncidentState(%q) = true, want false", s)
		}
	}
}

// TestIsDetectorDisabled covers handleFinding's hub-side detector
// enable/disable filter — see finding.go's doc comment for why this is a
// hub-side filter, not agent-side suppression.
func TestIsDetectorDisabled(t *testing.T) {
	cases := []struct {
		name        string
		detectorID  string
		disabledIDs []string
		want        bool
	}{
		{"nil disabled list disables nothing", "k8s-warning-events", nil, false},
		{"empty disabled list disables nothing", "k8s-warning-events", []string{}, false},
		{"matching id is disabled", "k8s-warning-events", []string{"k8s-warning-events"}, true},
		{"non-matching id is not disabled", "k8s-pod-conditions", []string{"k8s-warning-events"}, false},
		{"matches among several", "k8s-pod-conditions", []string{"k8s-warning-events", "k8s-pod-conditions"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsDetectorDisabled(c.detectorID, c.disabledIDs); got != c.want {
				t.Errorf("IsDetectorDisabled(%q, %v) = %v, want %v", c.detectorID, c.disabledIDs, got, c.want)
			}
		})
	}
}

// TestIsRuleDisabled covers handleFinding's hub-side RULE-level
// enable/disable filter (BUGS.md 111) — mirrors TestIsDetectorDisabled
// exactly, plus the one case that filter has no equivalent for: an empty
// RuleID (every hand-written Go detector finding) must never match, even if
// the disabled set somehow contained "".
func TestIsRuleDisabled(t *testing.T) {
	cases := []struct {
		name        string
		ruleID      string
		disabledIDs []string
		want        bool
	}{
		{"nil disabled list disables nothing", "pdb-blocks-all-disruptions", nil, false},
		{"empty disabled list disables nothing", "pdb-blocks-all-disruptions", []string{}, false},
		{"matching id is disabled", "pdb-blocks-all-disruptions", []string{"pdb-blocks-all-disruptions"}, true},
		{"non-matching id is not disabled", "hpa-pegged-at-max-replicas", []string{"pdb-blocks-all-disruptions"}, false},
		{"matches among several", "hpa-pegged-at-max-replicas", []string{"pdb-blocks-all-disruptions", "hpa-pegged-at-max-replicas"}, true},
		{"empty RuleID never matches, even against an empty string entry", "", []string{""}, false},
		{"empty RuleID never matches a non-empty disabled set either", "", []string{"pdb-blocks-all-disruptions"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsRuleDisabled(c.ruleID, c.disabledIDs); got != c.want {
				t.Errorf("IsRuleDisabled(%q, %v) = %v, want %v", c.ruleID, c.disabledIDs, got, c.want)
			}
		})
	}
}

// TestStormProtectionConfigured guards the precondition
// stormProtectionShouldSuppress relies on: both the ceiling and the window
// must be positive for storm protection to be considered "on" at all — a
// nil or non-positive value in either field means "off," matching
// migration 000025's default and internal/api/settings.go's validation
// (which rejects one being set without the other before either ever
// reaches this far).
func TestStormProtectionConfigured(t *testing.T) {
	ptr := func(n int) *int { return &n }
	cases := []struct {
		name            string
		maxNewIncidents *int
		windowSeconds   *int
		want            bool
	}{
		{"both nil: off", nil, nil, false},
		{"max nil, window set: off", nil, ptr(300), false},
		{"max set, window nil: off", ptr(20), nil, false},
		{"both positive: on", ptr(20), ptr(300), true},
		{"max zero: off", ptr(0), ptr(300), false},
		{"window zero: off", ptr(20), ptr(0), false},
		{"max negative: off", ptr(-1), ptr(300), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := StormProtectionConfigured(c.maxNewIncidents, c.windowSeconds); got != c.want {
				t.Errorf("StormProtectionConfigured(%v, %v) = %v, want %v", c.maxNewIncidents, c.windowSeconds, got, c.want)
			}
		})
	}
}

// TestStormProtectionShouldSuppress pins the >= (not >) boundary: a cluster
// that has produced EXACTLY the ceiling's worth of new incidents in the
// window must already be suppressed, not allowed one more — "at most N"
// means N total, not N+1.
func TestStormProtectionShouldSuppress(t *testing.T) {
	cases := []struct {
		name            string
		countInWindow   int
		maxNewIncidents int
		want            bool
	}{
		{"below ceiling: not suppressed", 5, 20, false},
		{"just below ceiling: not suppressed", 19, 20, false},
		{"exactly at ceiling: suppressed", 20, 20, true},
		{"above ceiling: suppressed", 25, 20, true},
		{"zero count, small ceiling: not suppressed", 0, 1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := StormProtectionShouldSuppress(c.countInWindow, c.maxNewIncidents); got != c.want {
				t.Errorf("StormProtectionShouldSuppress(%d, %d) = %v, want %v", c.countInWindow, c.maxNewIncidents, got, c.want)
			}
		})
	}
}

// TestStormProtectionWindowStart pins the rolling-window arithmetic: the
// window start is exactly now minus windowSeconds, no off-by-one, no
// truncation to a coarser unit.
func TestStormProtectionWindowStart(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

	got := StormProtectionWindowStart(now, 300)
	want := now.Add(-5 * time.Minute)
	if !got.Equal(want) {
		t.Errorf("StormProtectionWindowStart(%v, 300) = %v, want %v", now, got, want)
	}

	// A zero window collapses to "now" itself — only an incident created
	// at this exact instant would count, which is the correct degenerate
	// case (not tested via the exported entry point, since
	// stormProtectionConfigured already treats windowSeconds<=0 as "storm
	// protection is off" before this function would ever be called with
	// one, but the arithmetic itself should still behave sanely).
	if got := StormProtectionWindowStart(now, 0); !got.Equal(now) {
		t.Errorf("StormProtectionWindowStart(%v, 0) = %v, want %v (now, unchanged)", now, got, now)
	}
}

// TestStormProtectionWindowStartIncidentIDIsMonotonic pins the property the
// whole storm-protection count now rests on: the id bound has to order the
// same way time does, since the SQL compares incident ids as bytes. If a
// later windowStart didn't produce a lexicographically greater bound, the
// window would silently include or exclude the wrong incidents.
func TestStormProtectionWindowStartIncidentIDIsMonotonic(t *testing.T) {
	base := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	prev := StormProtectionWindowStartIncidentID(base)
	for _, step := range []time.Duration{time.Millisecond, time.Second, time.Minute, time.Hour, 24 * time.Hour, 365 * 24 * time.Hour} {
		next := StormProtectionWindowStartIncidentID(base.Add(step))
		if !(next > prev) {
			t.Errorf("StormProtectionWindowStartIncidentID(base+%v) = %q, which does not sort after the previous bound %q", step, next, prev)
		}
		prev = next
	}
}

// TestStormProtectionWindowStartIncidentIDBracketsRealIncidentIDs is the
// regression test for the bug itself, expressed without a database: an id
// minted right now by the same domain.NewID call handleFinding uses must
// fall INSIDE a window that started in the past and OUTSIDE one that starts
// in the future — on the hub's clock alone, with no reference to any
// agent-supplied timestamp. The old predicate compared the window against
// incidents.first_seen, which carries the AGENT's clock, so an agent running
// behind (or replaying a backlog after a reconnect) stamped every new
// incident outside the window and the ceiling never engaged.
func TestStormProtectionWindowStartIncidentIDBracketsRealIncidentIDs(t *testing.T) {
	now := time.Now()
	realID := domain.NewID(domain.PrefixIncident)

	// A window that opened five minutes ago must contain an incident minted
	// just now.
	if lower := StormProtectionWindowStartIncidentID(now.Add(-5 * time.Minute)); !(realID >= lower) {
		t.Errorf("a freshly minted incident id %q sorts below the bound %q for a window that opened 5 minutes ago — it would not be counted", realID, lower)
	}
	// A window that opens five minutes from now must not.
	if lower := StormProtectionWindowStartIncidentID(now.Add(5 * time.Minute)); realID >= lower {
		t.Errorf("a freshly minted incident id %q sorts at or above the bound %q for a window that has not opened yet", realID, lower)
	}
	// The same-millisecond edge: zero entropy makes the bound the smallest
	// id of its millisecond, so an incident minted in that very millisecond
	// counts as inside the window rather than being lost to rounding.
	if lower := StormProtectionWindowStartIncidentID(now); !(realID >= lower) {
		t.Errorf("a freshly minted incident id %q sorts below the bound %q for a window opening this very millisecond — the zero-entropy floor should make it count", realID, lower)
	}
	// Byte comparison only orders ULIDs correctly when they're the same
	// width, which they always are (canonical 26-character encoding).
	if lower := StormProtectionWindowStartIncidentID(now); len(lower) != len(realID) {
		t.Errorf("bound %q and a real incident id %q have different lengths (%d vs %d)", lower, realID, len(lower), len(realID))
	}
}

// TestStormProtectionWindowStartIncidentIDShape guards the two structural
// assumptions the SQL comparison makes: the bound is the same prefixed,
// lowercase, fixed-width shape domain.NewID produces, and an out-of-range
// windowStart degrades to the lowest possible id (counting everything, i.e.
// erring towards suppressing) rather than to something that sorts above real
// ids and silently counts nothing.
func TestStormProtectionWindowStartIncidentIDShape(t *testing.T) {
	got := StormProtectionWindowStartIncidentID(time.Now())
	wantPrefix := domain.PrefixIncident + "_"
	if !strings.HasPrefix(got, wantPrefix) {
		t.Errorf("bound %q does not start with %q", got, wantPrefix)
	}
	if body := strings.TrimPrefix(got, wantPrefix); len(body) != 26 {
		t.Errorf("bound body %q is %d characters, want 26 (a canonical ULID)", body, len(body))
	}
	if got != strings.ToLower(got) {
		t.Errorf("bound %q is not lowercase; domain.NewID lowercases its ULIDs, and a mixed-case bound would not compare correctly against real ids", got)
	}

	// Pre-epoch: ulid.Timestamp wraps such a time into an unrepresentable
	// value, and the fallback must be the floor, not something arbitrary.
	preEpoch := StormProtectionWindowStartIncidentID(time.Date(1969, 1, 1, 0, 0, 0, 0, time.UTC))
	if preEpoch != wantPrefix+strings.Repeat("0", 26) {
		t.Errorf("pre-epoch bound = %q, want the all-zero floor %q", preEpoch, wantPrefix+strings.Repeat("0", 26))
	}
	if !(domain.NewID(domain.PrefixIncident) >= preEpoch) {
		t.Error("the out-of-range fallback bound must sort at or below every real incident id, so it counts everything rather than nothing")
	}
}

// TestObjectCorrelationKey covers the key that decides whether two findings
// describe the same thing — migration 000036's whole premise.
func TestObjectCorrelationKey(t *testing.T) {
	for _, c := range []struct {
		name string
		f    tunnel.Finding
		want string
	}{
		{
			// The measured case: one pod, three symptoms from two detectors.
			// All three must produce the SAME key, or they stay three incidents.
			name: "namespaced object",
			f:    tunnel.Finding{GVK: "v1/Pod", Namespace: "argus-e2e", ObjectName: "badimage-d7848ffd"},
			want: "v1/Pod|argus-e2e|badimage-d7848ffd",
		},
		{
			// Cluster-scoped: the empty namespace segment is intended, not a
			// defect — it is still a stable, distinct key.
			name: "cluster-scoped object",
			f:    tunnel.Finding{GVK: "Node", ObjectName: "worker-0"},
			want: "Node||worker-0",
		},
		{
			// "" means "fall back to fingerprint correlation", NOT "group all
			// object-less findings together" — that would merge unrelated
			// problems, which is worse than the duplication being fixed.
			name: "no object name",
			f:    tunnel.Finding{GVK: "v1/Pod", Namespace: "default"},
			want: "",
		},
		{
			name: "whitespace-only object name is treated as absent",
			f:    tunnel.Finding{GVK: "v1/Pod", Namespace: "default", ObjectName: "   "},
			want: "",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := objectCorrelationKey(&c.f); got != c.want {
				t.Errorf("objectCorrelationKey() = %q, want %q", got, c.want)
			}
		})
	}
}

// TestObjectCorrelationKeyDistinguishesObjects guards the other direction:
// over-merging would be a far worse bug than the duplication this fixes, so
// anything that is genuinely a different object must key differently.
func TestObjectCorrelationKeyDistinguishesObjects(t *testing.T) {
	base := tunnel.Finding{GVK: "v1/Pod", Namespace: "app", ObjectName: "web-1"}
	baseKey := objectCorrelationKey(&base)

	for _, other := range []tunnel.Finding{
		{GVK: "v1/Pod", Namespace: "app", ObjectName: "web-2"},             // sibling replica
		{GVK: "v1/Pod", Namespace: "other", ObjectName: "web-1"},           // same name, other namespace
		{GVK: "apps/v1/Deployment", Namespace: "app", ObjectName: "web-1"}, // same name, different kind
	} {
		if got := objectCorrelationKey(&other); got == baseKey {
			t.Errorf("%+v collided with base key %q — distinct objects must not merge", other, baseKey)
		}
	}

	// Two symptoms on the SAME object must collide — that is the point.
	sameObject := tunnel.Finding{GVK: "v1/Pod", Namespace: "app", ObjectName: "web-1", Reason: "OOMKilled"}
	if got := objectCorrelationKey(&sameObject); got != baseKey {
		t.Errorf("same object with a different reason keyed %q, want %q — reasons must not split the key", got, baseKey)
	}
}

// TestSeverityRank pins the escalation ladder. The default-lowest rule matters:
// object correlation means one incident absorbs many findings, and an
// unrecognized severity must never be able to escalate an incident.
func TestSeverityRank(t *testing.T) {
	if !(severityRank("critical") > severityRank("high") &&
		severityRank("high") > severityRank("medium") &&
		severityRank("medium") > severityRank("low")) {
		t.Error("severity ladder is not strictly ordered critical > high > medium > low")
	}
	for _, unknown := range []string{"", "URGENT", "sev1", "info"} {
		if severityRank(unknown) >= severityRank("low") {
			t.Errorf("severityRank(%q) must rank below every known severity so it cannot escalate an incident", unknown)
		}
	}
}

// TestCorrelationIdentityTiers covers the tier order and, more importantly, the
// invariant that makes the type exist at all: the advisory lock and the lookup
// must always be talking about the SAME key.
//
// Getting that wrong is invisible in normal use and only breaks under
// concurrency — two pods of one workload taking different locks, both seeing no
// rows, both inserting — so it needs a test that asserts the pairing directly
// rather than one that exercises a single finding at a time.
func TestCorrelationIdentityTiers(t *testing.T) {
	const (
		cluster  = "cl_test"
		workload = "apps/v1/Deployment|prod|web"
		object   = "v1/Pod|prod|web-abc123"
		fp       = "fp_deadbeef"
	)

	tests := []struct {
		name     string
		id       correlationIdentity
		wantTier string
		wantLock string
	}{
		{
			// A pod finding: the agent resolved its owner, so the whole
			// workload is one incident.
			name:     "workload wins over object and fingerprint",
			id:       correlationIdentity{clusterID: cluster, workloadKey: workload, objectKey: object, fingerprint: fp},
			wantTier: "workload",
			wantLock: cluster + ":wl:" + workload,
		},
		{
			// A Deployment/Node/PVC/Service/Ingress finding: names an object,
			// but no owning workload was resolved. Unchanged behaviour.
			name:     "object wins over fingerprint when there is no workload",
			id:       correlationIdentity{clusterID: cluster, objectKey: object, fingerprint: fp},
			wantTier: "object",
			wantLock: cluster + ":obj:" + object,
		},
		{
			name:     "fingerprint is the fallback when the finding names nothing",
			id:       correlationIdentity{clusterID: cluster, fingerprint: fp},
			wantTier: "fingerprint",
			wantLock: cluster + ":" + fp,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.id.tier(); got != tc.wantTier {
				t.Errorf("tier() = %q, want %q", got, tc.wantTier)
			}
			if got := tc.id.lockKey(); got != tc.wantLock {
				t.Errorf("lockKey() = %q, want %q", got, tc.wantLock)
			}
		})
	}

	// Two pods of ONE workload must take the SAME lock. This is the race the
	// lock exists for: without it both findings see no open incident and both
	// insert, and one fault becomes two incidents at exactly the moment a
	// workload starts failing on several replicas at once.
	podA := correlationIdentity{clusterID: cluster, workloadKey: workload, objectKey: "v1/Pod|prod|web-aaa", fingerprint: "fp_a"}
	podB := correlationIdentity{clusterID: cluster, workloadKey: workload, objectKey: "v1/Pod|prod|web-bbb", fingerprint: "fp_b"}
	if podA.lockKey() != podB.lockKey() {
		t.Errorf("two pods of one workload take different locks (%q vs %q) — concurrent first findings would both insert", podA.lockKey(), podB.lockKey())
	}

	// The same workload name on a different cluster is a different workload.
	otherCluster := correlationIdentity{clusterID: "cl_other", workloadKey: workload}
	if otherCluster.lockKey() == podA.lockKey() {
		t.Error("two clusters running the same workload name share a lock — unrelated clusters would serialize against each other")
	}

	// Tier prefixes keep the namespaces apart: a workload key and an object key
	// that happen to be the same string must not collide.
	same := "apps/v1/Deployment|prod|web"
	asWorkload := correlationIdentity{clusterID: cluster, workloadKey: same}
	asObject := correlationIdentity{clusterID: cluster, objectKey: same}
	if asWorkload.lockKey() == asObject.lockKey() {
		t.Error("an identical string used as a workload key and as an object key produces one lock — the tier prefix is not doing its job")
	}
}
