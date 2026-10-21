package api

import (
	"testing"

	"argus/internal/agent"
)

// TestKnownRuleIDsMatchesDefaultRulesYAML guards knownRuleIDs (settings.go)
// against drift from the real rule catalogue it hand-copies — BUGS.md 111's
// fix explicitly avoided a production-code import of internal/agent from
// internal/api (see knownRuleIDs' own doc comment for why: hub and
// cluster-agent are kept as separate binaries with no Go dependency either
// direction), which means nothing stops the hand-maintained list here from
// silently falling out of sync with internal/agent/rules/default-rules.yaml
// as rules are added, renamed or removed — UNLESS a test checks it.
//
// This file is deliberately the one place internal/api imports
// internal/agent at all: a TEST-ONLY import is a much lower-stakes crossing
// of that boundary than a production one (this file contributes nothing to
// the built hub binary — go build never compiles _test.go files into it —
// and calls nothing except a pure, read-only parser), so it gets to use the
// real thing — agent.LoadRules("") — rather than a second, independently
// fallible YAML reader that could itself drift from the real rule schema
// (e.g. by missing a field LoadRules' own validateRule enforces).
// agent.LoadRules("") returns exactly the rules
// internal/agent/rules/default-rules.yaml embeds and every agent ships with
// by default (see that function's own doc comment) — already parsed and
// validated (unique, non-empty IDs; a recognized GVK; a valid severity),
// which is a stronger guarantee than this test could get from parsing the
// YAML by hand.
//
// A failure here means exactly one thing: default-rules.yaml changed and
// knownRuleIDs (and, for a REMOVED or RENAMED rule, any comment that quotes
// the old count) was not updated to match — fix it by editing knownRuleIDs,
// never by weakening this test.
func TestKnownRuleIDsMatchesDefaultRulesYAML(t *testing.T) {
	rules, err := agent.LoadRules("")
	if err != nil {
		t.Fatalf("agent.LoadRules(\"\"): %v", err)
	}
	if len(rules) == 0 {
		t.Fatalf("agent.LoadRules(\"\") returned zero rules — the embedded default rule set should never be empty")
	}

	actual := make(map[string]bool, len(rules))
	for _, r := range rules {
		actual[r.ID] = true
	}

	for id := range actual {
		if !knownRuleIDs[id] {
			t.Errorf("default-rules.yaml has rule %q, which knownRuleIDs (internal/api/settings.go) does not list — add it", id)
		}
	}
	for id := range knownRuleIDs {
		if !actual[id] {
			t.Errorf("knownRuleIDs (internal/api/settings.go) lists %q, which default-rules.yaml no longer has — remove it", id)
		}
	}
	if len(knownRuleIDs) != len(actual) {
		t.Errorf("knownRuleIDs has %d entries, default-rules.yaml has %d real rules — sets differ in size even if the per-id checks above did not catch why", len(knownRuleIDs), len(actual))
	}
}
