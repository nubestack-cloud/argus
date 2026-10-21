package audit

import (
	"strings"
	"testing"
	"time"
)

// occurredAtFixed is a fixed instant used throughout these tests so hash
// values are reproducible across runs — ComputeHash is pure/DB-free, matching
// this codebase's existing convention (see internal/authz's *_test.go files)
// of testing the pure-logic half of a DB-touching feature without a database.
var occurredAtFixed = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

func fixedEvent() Event {
	actorID := "usr_01example"
	capability := "cluster:onboard"
	clusterID := "cl_01example"
	return Event{
		TenantID:        "org_01example",
		ActorID:         &actorID,
		ActorAuthMethod: "password",
		SourceIP:        "203.0.113.5",
		Capability:      &capability,
		Scope:           map[string]any{"clusterId": "cl_01example"},
		ClusterID:       &clusterID,
		Outcome:         OutcomeSuccess,
		Details:         map[string]any{"note": "never hashed"},
	}
}

func TestComputeHash_Reproducible(t *testing.T) {
	ev := fixedEvent()

	h1, err := ComputeHash(GenesisPrevHash, ev, occurredAtFixed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h2, err := ComputeHash(GenesisPrevHash, ev, occurredAtFixed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h1 != h2 {
		t.Errorf("ComputeHash is not deterministic for identical inputs: %q != %q", h1, h2)
	}
	if len(h1) != 64 {
		t.Errorf("expected a 64-character hex SHA-256 digest, got %d characters: %q", len(h1), h1)
	}
}

func TestComputeHash_GenesisConstant(t *testing.T) {
	if len(GenesisPrevHash) != 64 {
		t.Fatalf("expected GenesisPrevHash to be 64 characters (matching a SHA-256 hex digest's length), got %d: %q", len(GenesisPrevHash), GenesisPrevHash)
	}
	for i, c := range GenesisPrevHash {
		if c != '0' {
			t.Fatalf("expected GenesisPrevHash to be all zeros, found %q at index %d in %q", c, i, GenesisPrevHash)
		}
	}

	// The genesis row's hash is still just ComputeHash applied with
	// prevHash == GenesisPrevHash — there's no special-cased hash formula for
	// "the first row," only a special-cased prevHash input. Exercise it the
	// same way RecordEvent does when it finds no existing rows.
	ev := fixedEvent()
	h, err := ComputeHash(GenesisPrevHash, ev, occurredAtFixed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == "" {
		t.Error("expected a non-empty hash for the genesis case")
	}
}

func TestComputeHash_DetailsExcludedFromHash(t *testing.T) {
	base := fixedEvent()
	baseHash, err := ComputeHash(GenesisPrevHash, base, occurredAtFixed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	changed := base
	changed.Details = map[string]any{"totally": "different", "more": []any{1, 2, 3}}
	gotHash, err := ComputeHash(GenesisPrevHash, changed, occurredAtFixed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if baseHash != gotHash {
		t.Errorf("changing Details must not change the hash (details is deliberately excluded, lld/05-data-model.md §7), but %q != %q", baseHash, gotHash)
	}
}

// TestComputeHash_ActorAuthMethodAndSourceIPExcludedFromHash locks in a
// second, less obvious exclusion: the LLD's hash formula (lld/05-data-model.md
// §7, migration 000008's comment) lists exactly eight inputs — prev_hash,
// tenant_id, actor_id, capability, scope, cluster_id, outcome, occurred_at —
// and ActorAuthMethod/SourceIP are NOT among them, even though they're real
// Event fields that do get persisted (as actor_auth_method/source_ip
// columns). It would be an easy, silent mistake to fold them into the hash
// input "for completeness" later; this test exists so that regresses loudly.
func TestComputeHash_ActorAuthMethodAndSourceIPExcludedFromHash(t *testing.T) {
	base := fixedEvent()
	baseHash, err := ComputeHash(GenesisPrevHash, base, occurredAtFixed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	changed := base
	changed.ActorAuthMethod = "jwt"   // base uses "password"
	changed.SourceIP = "198.51.100.9" // base uses 203.0.113.5
	gotHash, err := ComputeHash(GenesisPrevHash, changed, occurredAtFixed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if baseHash != gotHash {
		t.Errorf("changing ActorAuthMethod/SourceIP must not change the hash (neither is one of the LLD's core hashed fields), but %q != %q", baseHash, gotHash)
	}
}

func TestComputeHash_ChangingAnyCoreFieldChangesTheHash(t *testing.T) {
	base := fixedEvent()
	baseHash, err := ComputeHash(GenesisPrevHash, base, occurredAtFixed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	otherActor, otherCap, otherCluster := "usr_different", "cluster:accept", "cl_different"

	cases := map[string]func(Event) Event{
		"tenantId":     func(e Event) Event { e.TenantID = "org_different"; return e },
		"actorId":      func(e Event) Event { e.ActorID = &otherActor; return e },
		"actorId(nil)": func(e Event) Event { e.ActorID = nil; return e },
		"capability":   func(e Event) Event { e.Capability = &otherCap; return e },
		"scope":        func(e Event) Event { e.Scope = map[string]any{"clusterId": "something-else"}; return e },
		"clusterId":    func(e Event) Event { e.ClusterID = &otherCluster; return e },
		"outcome":      func(e Event) Event { e.Outcome = OutcomeDenied; return e },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := ComputeHash(GenesisPrevHash, mutate(base), occurredAtFixed)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == baseHash {
				t.Errorf("changing field %q did not change the resulting hash", name)
			}
		})
	}

	t.Run("prevHash", func(t *testing.T) {
		otherPrevHash := strings.Repeat("1", 64)
		got, err := ComputeHash(otherPrevHash, base, occurredAtFixed)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == baseHash {
			t.Error("changing prevHash did not change the resulting hash")
		}
	})

	t.Run("occurredAt", func(t *testing.T) {
		got, err := ComputeHash(GenesisPrevHash, base, occurredAtFixed.Add(time.Second))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == baseHash {
			t.Error("changing occurredAt did not change the resulting hash")
		}
	})
}

// TestComputeHash_DelimiterPreventsConcatenationCollision exercises exactly
// the collision the LLD's original, delimiter-less formula was vulnerable to
// (see computeHash's doc comment and lld/05-data-model.md's 2026-08-19
// addendum): actor_id="ab" + capability="c" must NOT hash identically to
// actor_id="a" + capability="bc" once every other field lines up the same.
func TestComputeHash_DelimiterPreventsConcatenationCollision(t *testing.T) {
	actorAB, capC := "ab", "c"
	actorA, capBC := "a", "bc"

	e1 := Event{TenantID: "t", ActorID: &actorAB, Capability: &capC, Outcome: OutcomeSuccess}
	e2 := Event{TenantID: "t", ActorID: &actorA, Capability: &capBC, Outcome: OutcomeSuccess}

	h1, err := ComputeHash(GenesisPrevHash, e1, occurredAtFixed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h2, err := ComputeHash(GenesisPrevHash, e2, occurredAtFixed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if h1 == h2 {
		t.Error("expected the delimiter between fields to prevent this field-boundary collision, but the two differently-split inputs hashed identically")
	}
}

func TestValidOutcome(t *testing.T) {
	for _, good := range []string{OutcomeSuccess, OutcomeDenied, OutcomeError} {
		if !validOutcome(good) {
			t.Errorf("expected %q to be a valid outcome", good)
		}
	}
	for _, bad := range []string{"", "SUCCESS", "pending", "denied "} {
		if validOutcome(bad) {
			t.Errorf("expected %q to be rejected as an invalid outcome", bad)
		}
	}
}

// TestNewCoreEvent_MatchesManuallyBuiltEvent locks in the contract SR-15's
// verification tool (cmd/argusctl's `audit verify`, internal/argusctl/audit.go)
// depends on: an Event built from NewCoreEvent's row-scan-shaped arguments
// must hash identically to the equivalent Event RecordEvent would have built
// from the same logical values, since the whole point of exporting
// ComputeHash/adding NewCoreEvent is to let the verifier reuse this exact
// formula rather than a second, driftable one.
func TestNewCoreEvent_MatchesManuallyBuiltEvent(t *testing.T) {
	actorID := "usr_01example"
	capability := "cluster:onboard"
	clusterID := "cl_01example"
	scope := map[string]any{"clusterId": "cl_01example"}

	viaConstructor := NewCoreEvent("org_01example", &actorID, &capability, scope, &clusterID, OutcomeSuccess)
	viaLiteral := Event{
		TenantID:   "org_01example",
		ActorID:    &actorID,
		Capability: &capability,
		Scope:      scope,
		ClusterID:  &clusterID,
		Outcome:    OutcomeSuccess,
	}

	got, err := ComputeHash(GenesisPrevHash, viaConstructor, occurredAtFixed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want, err := ComputeHash(GenesisPrevHash, viaLiteral, occurredAtFixed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("NewCoreEvent produced a different hash than the equivalent literal Event: %q != %q", got, want)
	}
}

func TestDerefOrEmpty(t *testing.T) {
	if got := derefOrEmpty(nil); got != "" {
		t.Errorf("derefOrEmpty(nil) = %q, want empty string", got)
	}
	s := "value"
	if got := derefOrEmpty(&s); got != "value" {
		t.Errorf("derefOrEmpty(&%q) = %q, want %q", s, got, s)
	}
}
