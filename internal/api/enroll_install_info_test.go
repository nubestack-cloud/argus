package api

import "testing"

// The UI prints the agent install command from this, so an address the hub
// was not given must arrive as null — never a guessed localhost.
func TestAgentInstallInfoIsNullWhereTheHubWasNotTold(t *testing.T) {
	t.Setenv("ARGUS_AGENT_CHART_REF", "")
	t.Setenv("ARGUS_AGENT_CHART_VERSION", "")
	t.Setenv("ARGUS_PUBLIC_API_URL", "")
	got := currentAgentInstallInfo()
	if got.ChartRef != defaultAgentChartRef || got.ChartVersion != nil || got.HubAPIURL != nil {
		t.Fatalf("got %+v, want the default chart and nulls", got)
	}
}

func TestAgentInstallInfoReadsTheHubsDeployment(t *testing.T) {
	t.Setenv("ARGUS_AGENT_CHART_REF", "oci://registry.example/argus-agent-chart")
	t.Setenv("ARGUS_AGENT_CHART_VERSION", "0.2.0")
	t.Setenv("ARGUS_PUBLIC_API_URL", " https://argus.example.com/ ")
	got := currentAgentInstallInfo()
	if got.ChartRef != "oci://registry.example/argus-agent-chart" || got.ChartVersion == nil || *got.ChartVersion != "0.2.0" ||
		got.HubAPIURL == nil || *got.HubAPIURL != "https://argus.example.com" {
		t.Fatalf("got %+v", got)
	}
}
