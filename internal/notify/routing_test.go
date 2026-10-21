package notify

import (
	"strings"
	"testing"
)

// defaultRouting is the routing table an install that has never written a rule
// has: the synthetic default rule and nothing else. Every DB-backed test in
// this package that used to pass a bare URL to sweepIncidents/sweepTransitions
// passes this instead, which keeps those tests asserting exactly what they
// asserted before PROJECT.md F32 — that the single configured webhook receives
// the notification.
func defaultRouting(url string) RoutingTable {
	return RoutingTable{rules: []Rule{defaultRule(url)}}
}

// tableOf builds a routing table from stored rules plus the default, in the
// order LoadRouting would have produced, so a test states its rules the way an
// operator would rather than constructing the struct by hand.
func tableOf(defaultURL string, members map[string]map[string]bool, rules ...Rule) RoutingTable {
	SortRulesForDisplay(rules)
	return RoutingTable{rules: append(rules, defaultRule(defaultURL)), members: members}
}

func dest(name, url string) Destination {
	return Destination{ID: "itg_" + name, Name: name, Kind: DestinationKindWebhook, URL: url}
}

// TestTransitionOf pins the derivation of a rule-matchable token from every
// notify_key shape the three callers of NotifyTransition actually write. If
// this drifts, rules silently stop matching, which is the failure this package
// cannot afford — so the cases are the literal formats, not paraphrases.
func TestTransitionOf(t *testing.T) {
	cases := map[string]string{
		// internal/orchestrator.SetState — state plus an RFC3339Nano instant.
		"Reopened@2026-09-25T12:00:00.123456789Z":         "Reopened",
		"AwaitingApproval@2026-09-25T12:00:00.123456789Z": "AwaitingApproval",
		"Failed@2026-09-25T12:00:00Z":                     "Failed",
		"ExecutionUnknown@2026-09-25T12:00:00Z":           "ExecutionUnknown",
		"ValidationUnknown@2026-09-25T12:00:00Z":          "ValidationUnknown",
		// mergewatch.go / approvalwatch.go — a literal prefix plus an
		// escalation tier from internal/orchestrator/escalation.go.
		"AwaitingMerge:StalePR:48h":  "AwaitingMerge",
		"AwaitingApproval:Stale:96d": "AwaitingApproval",
		"AwaitingMerge:StalePR:w3":   "AwaitingMerge",
		"AwaitingApproval:Stale:5d":  "AwaitingApproval",
		// A shape nothing writes today: returned whole, so it matches no
		// transition-scoped rule and falls through to the default rather than
		// being attributed to a state it never named.
		"SomethingNew": "SomethingNew",
		"":             "",
	}
	for key, want := range cases {
		if got := TransitionOf(key); got != want {
			t.Errorf("TransitionOf(%q) = %q, want %q", key, got, want)
		}
	}
}

// TestKnownTransitionsAreWellFormedTokens checks the list can only contain
// things TransitionOf could ever produce. An entry containing '@' or ':' would
// be permanently unmatchable — the API would accept a rule naming it and that
// rule would never fire.
func TestKnownTransitionsAreWellFormedTokens(t *testing.T) {
	seen := map[string]bool{}
	for _, tr := range KnownTransitions {
		if tr == "" {
			t.Error("KnownTransitions contains an empty token")
		}
		if seen[tr] {
			t.Errorf("KnownTransitions contains %q twice", tr)
		}
		seen[tr] = true
		if TransitionOf(tr+"@2026-09-25T12:00:00Z") != tr {
			t.Errorf("KnownTransitions entry %q is not a token TransitionOf can produce", tr)
		}
	}
	// F32 names Reopened explicitly: a reopened incident is a real operator
	// event, and a rule has to be able to select on it.
	if !seen["Reopened"] {
		t.Error("Reopened is not in KnownTransitions, so no rule can route it (PROJECT.md F32)")
	}
	if !seen[TransitionNewIncident] {
		t.Errorf("%q is not in KnownTransitions, so no rule can route the new-incident queue", TransitionNewIncident)
	}
}

// TestDefaultRuleMatchesEverything is F32's "no deployment changes behaviour on
// upgrade" acceptance, stated as a test: an install with no rules routes every
// combination of cluster, severity and transition to the one configured URL.
func TestDefaultRuleMatchesEverything(t *testing.T) {
	table := defaultRouting("https://hooks.example/global")
	for _, transition := range append([]string{"", "SomethingUnknown"}, KnownTransitions...) {
		for _, severity := range append([]string{"", "nonsense"}, Severities...) {
			rule, ok := table.Match(Notification{ClusterID: "cl_anything", Severity: severity, Transition: transition})
			if !ok {
				t.Fatalf("nothing matched for severity=%q transition=%q", severity, transition)
			}
			if !rule.IsDefault() {
				t.Fatalf("severity=%q transition=%q matched %q, want the default rule", severity, transition, rule.Name)
			}
			if rule.Destination.URL != "https://hooks.example/global" {
				t.Fatalf("default rule routed to %q, want the configured webhook", rule.Destination.URL)
			}
		}
	}
}

// TestMatchFirstRuleWins covers the three matchers individually and together,
// and the ordering that decides between two rules that both match.
func TestMatchFirstRuleWins(t *testing.T) {
	members := map[string]map[string]bool{
		"cl_prod": {"clg_platform": true},
		"cl_dev":  {"clg_sandbox": true},
	}
	platform := Rule{ID: "nr_1", Name: "platform", Priority: 10, ClusterGroupID: "clg_platform",
		Destination: dest("platform", "https://hooks.example/platform"), Enabled: true}
	pages := Rule{ID: "nr_2", Name: "pages", Priority: 5, MinSeverity: "high", Transition: "Reopened",
		Destination: dest("pager", "https://hooks.example/pager"), Enabled: true}
	table := tableOf("https://hooks.example/global", members, platform, pages)

	cases := []struct {
		name string
		in   Notification
		want string
	}{
		{"high Reopened anywhere takes the lower-priority-number rule first",
			Notification{ClusterID: "cl_prod", Severity: "high", Transition: "Reopened"}, "pages"},
		{"critical is above the high minimum",
			Notification{ClusterID: "cl_dev", Severity: "critical", Transition: "Reopened"}, "pages"},
		{"medium is below the high minimum, so the group rule takes it",
			Notification{ClusterID: "cl_prod", Severity: "medium", Transition: "Reopened"}, "platform"},
		{"the wrong transition falls past the pager rule",
			Notification{ClusterID: "cl_prod", Severity: "critical", Transition: "Failed"}, "platform"},
		{"a cluster in no matching group falls through to the default",
			Notification{ClusterID: "cl_dev", Severity: "medium", Transition: "Failed"}, "Default"},
		{"a cluster with no membership at all falls through to the default",
			Notification{ClusterID: "cl_unknown", Severity: "medium", Transition: "Failed"}, "Default"},
		{"an unrecognised severity ranks below every minimum and falls through",
			Notification{ClusterID: "cl_dev", Severity: "", Transition: "Reopened"}, "Default"},
		{"the new-incident token is routable like any other",
			Notification{ClusterID: "cl_prod", Severity: "low", Transition: TransitionNewIncident}, "platform"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule, ok := table.Match(tc.in)
			if !ok {
				t.Fatal("nothing matched, but the default rule should always match")
			}
			if rule.Name != tc.want {
				t.Errorf("matched %q, want %q", rule.Name, tc.want)
			}
		})
	}
}

// TestDisabledRuleFallsThroughRatherThanDropping is the property that makes
// "disabled" safe to offer at all: silencing a rule must move its traffic on to
// the next rule, never stop it.
func TestDisabledRuleFallsThroughRatherThanDropping(t *testing.T) {
	members := map[string]map[string]bool{"cl_prod": {"clg_platform": true}}
	table := tableOf("https://hooks.example/global", members,
		Rule{ID: "nr_1", Name: "platform", ClusterGroupID: "clg_platform",
			Destination: dest("platform", "https://hooks.example/platform"), Enabled: false})

	rule, ok := table.Match(Notification{ClusterID: "cl_prod", Severity: "critical", Transition: "Reopened"})
	if !ok || !rule.IsDefault() {
		t.Fatalf("a disabled rule's traffic went to %+v, want the default rule", rule)
	}
}

// TestDeliverable is the "is anything configured at all" question the sweep
// asks before it claims a single row — the successor to the old
// NotifyWebhookConfigured check, and the thing that stops an unconfigured
// install stamping claims it cannot honour.
func TestDeliverable(t *testing.T) {
	if defaultRouting("").Deliverable() {
		t.Error("an install with no webhook URL and no rules reported itself deliverable")
	}
	if !defaultRouting("https://hooks.example/global").Deliverable() {
		t.Error("an install with only the legacy webhook URL reported itself undeliverable")
	}
	ruleOnly := tableOf("", nil, Rule{ID: "nr_1", Name: "team", Enabled: true,
		Destination: dest("team", "https://hooks.example/team")})
	if !ruleOnly.Deliverable() {
		t.Error("an install with a rule but no default URL reported itself undeliverable")
	}
	disabledOnly := tableOf("", nil, Rule{ID: "nr_1", Name: "team", Enabled: false,
		Destination: dest("team", "https://hooks.example/team")})
	if disabledOnly.Deliverable() {
		t.Error("an install whose only rule is disabled reported itself deliverable")
	}
}

// TestRulesAndDefaultAreSeparable pins the split the admin API depends on:
// Rules() is the editable set and never includes the synthetic default, which
// an operator must not be able to delete or repoint.
func TestRulesAndDefaultAreSeparable(t *testing.T) {
	table := tableOf("https://hooks.example/global", nil,
		Rule{ID: "nr_1", Name: "team", Enabled: true, Destination: dest("team", "https://x/1")})
	if got := len(table.Rules()); got != 1 {
		t.Fatalf("Rules() returned %d rules, want 1", got)
	}
	if table.Rules()[0].IsDefault() {
		t.Error("Rules() included the synthetic default rule")
	}
	if !table.Default().IsDefault() {
		t.Error("Default() did not return the synthetic default rule")
	}
	if got := len(defaultRouting("").Rules()); got != 0 {
		t.Errorf("an install with no stored rules reported %d editable rules, want 0", got)
	}
}

func TestValidateRoutingUpdate(t *testing.T) {
	url := func(s string) *string { return &s }
	ok := RoutingUpdate{
		Destinations: []DestinationInput{{Name: "platform", URL: url("https://hooks.example/platform")}},
		Rules: []RuleInput{{Name: "prod pages", Destination: "platform", MinSeverity: "high",
			Transition: "Reopened", Enabled: true}},
	}
	if err := ValidateRoutingUpdate(ok); err != nil {
		t.Fatalf("a valid configuration was rejected: %v", err)
	}
	// An empty configuration is valid and means "route everything by the
	// default rule" — the state every install upgrades into.
	if err := ValidateRoutingUpdate(RoutingUpdate{}); err != nil {
		t.Fatalf("the empty configuration was rejected: %v", err)
	}

	bad := []struct {
		name string
		upd  RoutingUpdate
		want string
	}{
		{"unnamed destination", RoutingUpdate{Destinations: []DestinationInput{{URL: url("https://x/1")}}}, "needs a name"},
		{"duplicate destination", RoutingUpdate{Destinations: []DestinationInput{
			{Name: "a", URL: url("https://x/1")}, {Name: "a", URL: url("https://x/2")}}}, "duplicate destination"},
		{"non-http destination", RoutingUpdate{Destinations: []DestinationInput{
			{Name: "a", URL: url("file:///etc/passwd")}}}, "http or https"},
		{"hostless destination", RoutingUpdate{Destinations: []DestinationInput{
			{Name: "a", URL: url("https://")}}}, "must include a host"},
		{"empty destination url", RoutingUpdate{Destinations: []DestinationInput{
			{Name: "a", URL: url("  ")}}}, "must not be empty"},
		{"unnamed rule", RoutingUpdate{
			Destinations: []DestinationInput{{Name: "a", URL: url("https://x/1")}},
			Rules:        []RuleInput{{Destination: "a"}}}, "needs a name"},
		{"rule names an absent destination", RoutingUpdate{
			Rules: []RuleInput{{Name: "r", Destination: "nope"}}}, "not in this configuration"},
		{"unknown severity", RoutingUpdate{
			Destinations: []DestinationInput{{Name: "a", URL: url("https://x/1")}},
			Rules:        []RuleInput{{Name: "r", Destination: "a", MinSeverity: "urgent"}}}, "minSeverity"},
		{"unknown transition", RoutingUpdate{
			Destinations: []DestinationInput{{Name: "a", URL: url("https://x/1")}},
			Rules:        []RuleInput{{Name: "r", Destination: "a", Transition: "Reopend"}}}, "transition"},
		{"duplicate rule name", RoutingUpdate{
			Destinations: []DestinationInput{{Name: "a", URL: url("https://x/1")}},
			Rules:        []RuleInput{{Name: "r", Destination: "a"}, {Name: "r", Destination: "a"}}}, "duplicate rule"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRoutingUpdate(tc.upd)
			if err == nil {
				t.Fatal("accepted, want rejected")
			}
			var invalidErr *InvalidRoutingError
			if !asInvalid(err, &invalidErr) {
				t.Fatalf("rejected with %T, want *InvalidRoutingError so the API can answer 400", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("message %q does not mention %q", err.Error(), tc.want)
			}
		})
	}
}

// asInvalid keeps the errors.As import out of the table above without hiding
// what is being checked.
func asInvalid(err error, target **InvalidRoutingError) bool {
	e, ok := err.(*InvalidRoutingError)
	if ok {
		*target = e
	}
	return ok
}
