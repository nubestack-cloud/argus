package api

import "testing"

// parseOwnershipFacts already had no test file before BACKLOG.md F19 widened
// ownershipWire with app_ref/labels — these confirm the widening is
// decode-only and does not change RepoKnown/ApplierRaw/SourceEditable for
// the ordinary "no repo, no operator mapping" case, which is what every
// existing ResolveRoute classification (internal/orchestrator/routing_test.go)
// depends on continuing to see.
func TestParseOwnershipFacts_NewFieldsDoNotAffectRepoKnown(t *testing.T) {
	raw := []byte(`{
		"managed_by": "helm",
		"app_ref": {"kind": "Release", "name": "payments", "namespace": "prod"},
		"labels": {"app": "payments", "team": "checkout"}
	}`)
	facts := parseOwnershipFacts(raw)
	if !facts.Determined {
		t.Fatal("Determined = false, want true")
	}
	if facts.ManagedBy != "helm" {
		t.Errorf("ManagedBy = %q, want helm", facts.ManagedBy)
	}
	if facts.RepoKnown {
		t.Error("RepoKnown = true, want false — no repo block was present on the wire")
	}
}

func TestParseOwnershipFacts_RepoKnownStillSetWhenRepoPresent(t *testing.T) {
	raw := []byte(`{"managed_by": "argocd", "repo": {"repo_url": "https://github.com/x/y", "applier": "gitopsController"}}`)
	facts := parseOwnershipFacts(raw)
	if !facts.RepoKnown {
		t.Fatal("RepoKnown = false, want true when repo.repo_url is present")
	}
	if facts.ApplierRaw != "gitopsController" {
		t.Errorf("ApplierRaw = %q, want gitopsController", facts.ApplierRaw)
	}
}

// matchObjectMapping's very first branch — no release identity AND no
// labels to check at all — must return cleanly WITHOUT ever touching tx or
// scmStore, both nil here (either would panic if called). This is the
// "kubectl-applied object with no labels ARGUS could read" case, and it
// must fall through exactly like "no operator mapping configured" rather
// than erroring.
func TestMatchObjectMapping_NothingToMatchOnNeverTouchesStore(t *testing.T) {
	raw := []byte(`{"managed_by": "none"}`)
	_, _, ok := matchObjectMapping(nil, nil, nil, "", raw)
	if ok {
		t.Fatal("matchObjectMapping reported a match with nothing to match on")
	}
}

func TestMatchObjectMapping_MalformedWireReturnsCleanly(t *testing.T) {
	_, _, ok := matchObjectMapping(nil, nil, nil, "", []byte(`{not json`))
	if ok {
		t.Fatal("matchObjectMapping reported a match against unparseable wire bytes")
	}
}

// TestDryRunAvailableFromFacts is BACKLOG.md C4's gating decision, unit
// tested the same way parseOwnershipFacts is above it: the pure half of a
// DB-touching function, so the actual logic ("Checked AND Allowed, fail
// closed on anything else") has real coverage without a Postgres instance.
func TestDryRunAvailableFromFacts(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"checked and allowed -> available", `{"reachable": true, "dryRun": {"checked": true, "allowed": true}}`, true},
		{"checked but NOT allowed -> unavailable", `{"reachable": true, "dryRun": {"checked": true, "allowed": false}}`, false},
		{"not checked (pack disabled, the default) -> unavailable", `{"reachable": true, "dryRun": {"checked": false}}`, false},
		{"dryRun field entirely absent (older agent, or never enabled) -> unavailable", `{"reachable": true}`, false},
		{"checked but an error was reported -> unavailable, never treated as denied-but-fine", `{"reachable": true, "dryRun": {"checked": false, "allowed": false, "error": "some transient failure"}}`, false},
		{"malformed JSON -> fails closed, not a panic", `{not json`, false},
		{"empty facts blob -> fails closed", ``, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := dryRunAvailableFromFacts([]byte(tc.raw))
			if got != tc.want {
				t.Errorf("dryRunAvailableFromFacts(%s) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestMetricsAvailableFromFacts is BACKLOG.md C4's other gating decision,
// unit tested the identical way TestDryRunAvailableFromFacts is above it —
// same pure-half split, same "Checked AND Allowed, fail closed on anything
// else" logic, applied to query_metrics instead of dry_run_patch.
func TestMetricsAvailableFromFacts(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"checked and allowed -> available", `{"reachable": true, "metrics": {"checked": true, "allowed": true}}`, true},
		{"checked but NOT allowed -> unavailable", `{"reachable": true, "metrics": {"checked": true, "allowed": false}}`, false},
		{"not checked (never configured, the default) -> unavailable", `{"reachable": true, "metrics": {"checked": false}}`, false},
		{"metrics field entirely absent (older agent, or never configured) -> unavailable", `{"reachable": true}`, false},
		{"checked but an error was reported -> unavailable, never treated as denied-but-fine", `{"reachable": true, "metrics": {"checked": false, "allowed": false, "error": "some transient failure"}}`, false},
		{"malformed JSON -> fails closed, not a panic", `{not json`, false},
		{"empty facts blob -> fails closed", ``, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := metricsAvailableFromFacts([]byte(tc.raw))
			if got != tc.want {
				t.Errorf("metricsAvailableFromFacts(%s) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// A Helm release with no app_ref at all (should not happen given
// internal/agent/tools.go always sets one for ManagedBy "helm", but a
// defensive decode elsewhere in this pipeline should not assume it) must
// not panic on a nil AppRef, and — with no labels either — falls through
// the same "nothing to match on" path as the "none" case above.
func TestMatchObjectMapping_HelmWithoutAppRefFallsThroughCleanly(t *testing.T) {
	raw := []byte(`{"managed_by": "helm"}`)
	_, _, ok := matchObjectMapping(nil, nil, nil, "", raw)
	if ok {
		t.Fatal("matchObjectMapping reported a match for a helm result with no app_ref and no labels")
	}
}
