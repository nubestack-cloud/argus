package agentversion

import "testing"

// withRestoredPolicy saves Policy and restores it via t.Cleanup, so a test
// that calls ConfigureFromEnv (which mutates the package-level Policy var in
// place) cannot leak a changed threshold into any test that runs after it in
// this package.
func withRestoredPolicy(t *testing.T) {
	t.Helper()
	saved := Policy
	t.Cleanup(func() { Policy = saved })
}

func TestConfigureFromEnv_OverridesBothThresholds(t *testing.T) {
	withRestoredPolicy(t)
	Policy = VersionPolicy{MinSupportedVersion: "0.1.0", RecommendedVersion: "0.1.0"}

	t.Setenv("ARGUS_AGENT_MIN_SUPPORTED_VERSION", "0.2.0")
	t.Setenv("ARGUS_AGENT_RECOMMENDED_VERSION", "0.3.0")

	ConfigureFromEnv()

	if Policy.MinSupportedVersion != "0.2.0" {
		t.Errorf("MinSupportedVersion = %q, want %q", Policy.MinSupportedVersion, "0.2.0")
	}
	if Policy.RecommendedVersion != "0.3.0" {
		t.Errorf("RecommendedVersion = %q, want %q", Policy.RecommendedVersion, "0.3.0")
	}
}

func TestConfigureFromEnv_MakesDriftObservableWithoutASecondAgentBuild(t *testing.T) {
	// This is the actual point of P22's env-var slice: proving a drift
	// verdict is reachable today, against the one real agent version this
	// codebase ships, with no second published build required.
	withRestoredPolicy(t)
	Policy = VersionPolicy{MinSupportedVersion: "0.1.0-mvp", RecommendedVersion: "0.1.0-mvp"}

	t.Setenv("ARGUS_AGENT_RECOMMENDED_VERSION", "0.2.0")

	ConfigureFromEnv()

	agentVersion := strPtr("0.1.0-mvp")
	got := Policy.Evaluate(agentVersion)
	if got.Verdict != VerdictUpgradeRecommended {
		t.Fatalf("verdict = %q, want %q — the whole point of the override is that this flips without a new agent build", got.Verdict, VerdictUpgradeRecommended)
	}
}

func TestConfigureFromEnv_UnsetChangesNothing(t *testing.T) {
	withRestoredPolicy(t)
	Policy = VersionPolicy{MinSupportedVersion: "0.1.0-mvp", RecommendedVersion: "0.1.0-mvp"}

	ConfigureFromEnv()

	if Policy.MinSupportedVersion != "0.1.0-mvp" {
		t.Errorf("MinSupportedVersion changed with no env var set: got %q", Policy.MinSupportedVersion)
	}
	if Policy.RecommendedVersion != "0.1.0-mvp" {
		t.Errorf("RecommendedVersion changed with no env var set: got %q", Policy.RecommendedVersion)
	}
}

func TestConfigureFromEnv_UnparseableValueIsIgnored(t *testing.T) {
	withRestoredPolicy(t)
	Policy = VersionPolicy{MinSupportedVersion: "0.1.0-mvp", RecommendedVersion: "0.1.0-mvp"}

	t.Setenv("ARGUS_AGENT_MIN_SUPPORTED_VERSION", "not-a-version")
	t.Setenv("ARGUS_AGENT_RECOMMENDED_VERSION", "also-not-a-version")

	ConfigureFromEnv()

	if Policy.MinSupportedVersion != "0.1.0-mvp" {
		t.Errorf("MinSupportedVersion = %q, want the default kept because the override was unparseable", Policy.MinSupportedVersion)
	}
	if Policy.RecommendedVersion != "0.1.0-mvp" {
		t.Errorf("RecommendedVersion = %q, want the default kept because the override was unparseable", Policy.RecommendedVersion)
	}
}
