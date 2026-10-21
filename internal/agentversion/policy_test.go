package agentversion

import (
	"strings"
	"testing"

	"argus/internal/tunnel"
)

func strPtr(s string) *string { return &s }

// TestEvaluateChangingThePolicyChangesTheVerdict is the T16 acceptance
// criterion's core claim, proven directly: the SAME agent version gets a
// DIFFERENT verdict under a different VersionPolicy, because Evaluate is a
// pure function of (policy, agentVersion) and nothing else. If a second,
// hand-rolled comparison ever creeps in anywhere else in this codebase, it
// would not move when this policy moves — this test is what would still
// pass while that drift went unnoticed, so internal/api/clusters_test.go
// repeats the same shape at the API layer (see
// TestScanClusterSummaryDerivesCompatibilityFromServerPolicy there).
func TestEvaluateChangingThePolicyChangesTheVerdict(t *testing.T) {
	agentVersion := strPtr("0.5.0")

	lenient := VersionPolicy{MinSupportedVersion: "0.1.0", RecommendedVersion: "0.5.0"}
	if got := lenient.Evaluate(agentVersion).Verdict; got != VerdictCurrent {
		t.Fatalf("under the lenient policy, verdict = %q, want %q", got, VerdictCurrent)
	}

	strict := VersionPolicy{MinSupportedVersion: "1.0.0", RecommendedVersion: "2.0.0"}
	if got := strict.Evaluate(agentVersion).Verdict; got != VerdictUpgradeRequired {
		t.Fatalf("under the strict policy, verdict = %q, want %q", got, VerdictUpgradeRequired)
	}

	middle := VersionPolicy{MinSupportedVersion: "0.1.0", RecommendedVersion: "1.0.0"}
	if got := middle.Evaluate(agentVersion).Verdict; got != VerdictUpgradeRecommended {
		t.Fatalf("under the middle policy, verdict = %q, want %q", got, VerdictUpgradeRecommended)
	}
}

func TestEvaluateVerdictBoundaries(t *testing.T) {
	policy := VersionPolicy{MinSupportedVersion: "1.2.0", RecommendedVersion: "1.5.0"}

	cases := []struct {
		version string
		want    Verdict
	}{
		{"1.1.9", VerdictUpgradeRequired},
		{"1.2.0", VerdictUpgradeRecommended}, // exactly at the floor: supported, not recommended
		{"1.4.9", VerdictUpgradeRecommended},
		{"1.5.0", VerdictCurrent}, // exactly at the recommended version
		{"1.9.0", VerdictCurrent},
		{"v1.5.0", VerdictCurrent}, // leading "v" tolerated
	}
	for _, c := range cases {
		got := policy.Evaluate(strPtr(c.version)).Verdict
		if got != c.want {
			t.Errorf("Evaluate(%q).Verdict = %q, want %q", c.version, got, c.want)
		}
	}
}

// TestEvaluateNeverGivesAConfidentVerdictForAnUnknownVersion is the other
// half of the acceptance criterion: an absent or unparseable version must
// never present as "current," "upgrade_recommended" or "upgrade_required" —
// all three are confident claims about a version this function does not
// have. It also must not fabricate a list of missing features, which would
// be a confident claim by another name.
func TestEvaluateNeverGivesAConfidentVerdictForAnUnknownVersion(t *testing.T) {
	policy := VersionPolicy{
		MinSupportedVersion: "1.0.0",
		RecommendedVersion:  "2.0.0",
		Features:            []Feature{{Name: "f", MinVersion: "2.0.0", WireContract: "omitted below 2.0.0"}},
	}

	for _, agentVersion := range []*string{nil, strPtr(""), strPtr("   "), strPtr("not-a-version"), strPtr("garbage-1")} {
		c := policy.Evaluate(agentVersion)
		if c.Verdict != VerdictUnknown {
			t.Errorf("Evaluate(%v).Verdict = %q, want %q", agentVersion, c.Verdict, VerdictUnknown)
		}
		if len(c.MissingFeatures) != 0 {
			t.Errorf("Evaluate(%v).MissingFeatures = %v, want none — an unknown version must not get a claimed feature gap", agentVersion, c.MissingFeatures)
		}
		if c.Upgrade != nil {
			t.Errorf("Evaluate(%v).Upgrade = %+v, want nil — an unknown version must not get confident upgrade guidance", agentVersion, c.Upgrade)
		}
		if c.Reason == "" {
			t.Errorf("Evaluate(%v).Reason is empty — an unknown verdict must still say why", agentVersion)
		}
		if c.Label != VerdictLabel[VerdictUnknown] {
			t.Errorf("Evaluate(%v).Label = %q, want the Unknown label — status is never colour-only", agentVersion, c.Label)
		}
	}
}

func TestEvaluateNamesMissingFeaturesOnlyWhenTheVersionIsKnownAndBelowThreshold(t *testing.T) {
	policy := VersionPolicy{
		MinSupportedVersion: "1.0.0",
		RecommendedVersion:  "3.0.0",
		Features: []Feature{
			{Name: "old-feature", MinVersion: "1.0.0", WireContract: "always present at or above 1.0.0"},
			{Name: "new-feature", MinVersion: "2.5.0", WireContract: "omitted below 2.5.0"},
		},
	}

	// Below both feature thresholds and below MinSupportedVersion: missing everything.
	below := policy.Evaluate(strPtr("0.9.0"))
	if below.Verdict != VerdictUpgradeRequired {
		t.Fatalf("0.9.0 verdict = %q, want %q", below.Verdict, VerdictUpgradeRequired)
	}
	if len(below.MissingFeatures) != 2 {
		t.Fatalf("0.9.0 MissingFeatures = %v, want both features named", below.MissingFeatures)
	}

	// Supported but only below the newer feature's threshold.
	mid := policy.Evaluate(strPtr("2.0.0"))
	if mid.Verdict != VerdictUpgradeRecommended {
		t.Fatalf("2.0.0 verdict = %q, want %q", mid.Verdict, VerdictUpgradeRecommended)
	}
	if len(mid.MissingFeatures) != 1 || mid.MissingFeatures[0].Name != "new-feature" {
		t.Fatalf("2.0.0 MissingFeatures = %v, want only new-feature", mid.MissingFeatures)
	}

	// At the recommended version: current, and current gets no missing
	// features and no upgrade guidance at all — there is nothing to
	// recommend upgrading to.
	current := policy.Evaluate(strPtr("3.0.0"))
	if current.Verdict != VerdictCurrent {
		t.Fatalf("3.0.0 verdict = %q, want %q", current.Verdict, VerdictCurrent)
	}
	if len(current.MissingFeatures) != 0 {
		t.Fatalf("3.0.0 MissingFeatures = %v, want none", current.MissingFeatures)
	}
	if current.Upgrade != nil {
		t.Fatalf("3.0.0 Upgrade = %+v, want nil", current.Upgrade)
	}
}

func TestUpgradeCommandGenericFormWhenReleaseContextUnknown(t *testing.T) {
	guidance := UpgradeCommand(ReleaseContext{}, "")
	if guidance.ReleaseContextKnown {
		t.Fatalf("ReleaseContextKnown = true with an empty ReleaseContext")
	}
	if !strings.Contains(guidance.Command, "<release-name>") || !strings.Contains(guidance.Command, "<namespace>") {
		t.Fatalf("command does not show placeholders when the release is unknown: %s", guidance.Command)
	}
	if guidance.Note == "" {
		t.Fatalf("an unknown release context must explain itself, not silently show placeholders")
	}
	// Never claim ARGUS performed or will perform the upgrade.
	for _, phrase := range []string{"ARGUS will upgrade", "ARGUS has upgraded", "ARGUS is upgrading"} {
		if strings.Contains(guidance.Command+guidance.Note, phrase) {
			t.Fatalf("guidance claims ARGUS performs the upgrade: %q", phrase)
		}
	}
}

func TestUpgradeCommandUsesKnownReleaseContext(t *testing.T) {
	guidance := UpgradeCommand(ReleaseContext{ReleaseName: "my-release", Namespace: "my-ns"}, "")
	if !guidance.ReleaseContextKnown {
		t.Fatalf("ReleaseContextKnown = false with a fully populated ReleaseContext")
	}
	if !strings.Contains(guidance.Command, "helm upgrade my-release") || !strings.Contains(guidance.Command, "--namespace my-ns") {
		t.Fatalf("command does not use the known release/namespace: %s", guidance.Command)
	}
	if guidance.Note != "" {
		t.Fatalf("a known release context should not carry the generic-form disclaimer: %q", guidance.Note)
	}
}

// TestPolicyFeaturesAreHonest guards against a fabricated capability matrix:
// every entry the real Policy ships must name a wire contract, and this
// repeats the one entry T16 asked for verbatim rather than inventing more.
func TestPolicyFeaturesAreHonest(t *testing.T) {
	if len(Policy.Features) != 1 {
		t.Fatalf("Policy.Features has %d entries, want exactly the one verified capability (per-namespace remediation breakdown) — do not add an unverified one", len(Policy.Features))
	}
	f := Policy.Features[0]
	if f.WireContract == "" {
		t.Fatalf("feature %q has no WireContract", f.Name)
	}
	if _, ok := parseVersion(f.MinVersion); !ok {
		t.Fatalf("feature %q has an unparseable MinVersion %q", f.Name, f.MinVersion)
	}
}

// TestDefaultPolicyMatchesTheOnlyRealAgentBuild is a sanity check against
// reality, not just the abstract Evaluate contract above: cmd/agent/main.go's
// own `agentVersion` constant is "0.1.0-mvp" and always has been (see
// Policy's doc comment) — a real, currently-connected fleet must read as
// current under the shipped Policy, not as some other verdict nobody could
// act on.
func TestDefaultPolicyMatchesTheOnlyRealAgentBuild(t *testing.T) {
	// tunnel.AgentBuildVersion is the constant cmd/agent actually stamps into
	// every Heartbeat, not a copy of it — so this asserts a real relationship.
	// Hardcoding the string here (as this test first did) would have kept
	// passing after a release bumped the agent and left Policy behind.
	c := Policy.Evaluate(strPtr(tunnel.AgentBuildVersion))
	if c.Verdict != VerdictCurrent {
		t.Fatalf("the only agent version this codebase has ever shipped evaluates to %q under the real Policy, want %q", c.Verdict, VerdictCurrent)
	}
}

func TestParseVersionTolerance(t *testing.T) {
	cases := []struct {
		raw string
		ok  bool
	}{
		{"0.1.0-mvp", true},
		{"v1.2.3", true},
		{"1.2.3+build.5", true},
		{"1", true},
		{"1.2", true},
		{"", false},
		{"   ", false},
		{"mvp", false},
		{"-mvp", false},
	}
	for _, c := range cases {
		_, ok := parseVersion(c.raw)
		if ok != c.ok {
			t.Errorf("parseVersion(%q) ok = %v, want %v", c.raw, ok, c.ok)
		}
	}
}

// The printed upgrade installs the published agent chart at the hub's own
// release version, not a path into a source checkout.
func TestUpgradeCommandUsesThePublishedChart(t *testing.T) {
	t.Setenv("ARGUS_AGENT_CHART_REF", "")
	t.Setenv("ARGUS_AGENT_CHART_VERSION", "0.2.0")
	cmd := UpgradeCommand(ReleaseContext{}, "").Command
	for _, want := range []string{"oci://registry-1.docker.io/nubestack/argus-agent-chart", "--version 0.2.0"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("upgrade command lacks %q:\n%s", want, cmd)
		}
	}
	if strings.Contains(cmd, "deploy/helm") {
		t.Errorf("upgrade command points into a source checkout:\n%s", cmd)
	}
}
