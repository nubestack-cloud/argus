package llm

import (
	"encoding/json"
	"testing"
)

// PROJECT.md IN6: every recorded call is counted once, refused and failed
// reads are told apart, and a conclusion reached mostly without its reads is
// marked so the confidence can be capped.
func TestEvidenceCoverage(t *testing.T) {
	denied, timeout := "permission denied", "tool call timed out"
	chain := []CausalStep{{ToolCalls: []ToolCallRecord{
		{Tool: "describe_resource", Result: json.RawMessage(`{"object":{"kind":"Pod","metadata":{"name":"web"}}}`)},
		{Tool: "list_resources", Result: json.RawMessage(`{"items":[],"truncated":false}`)},
		{Tool: "get_logs", Error: &denied},
		{Tool: "get_events", Error: &timeout},
	}}}
	c := coverageFromChain(chain, toolAvailability{dryRun: true})
	if c.Answered != 1 || c.Empty != 1 || c.Denied != 1 || c.Failed != 1 {
		t.Fatalf("coverage = %+v", c)
	}
	if len(c.NotOffered) != 2 || c.NotOffered[0] != "metrics" || c.NotOffered[1] != "repository" {
		t.Errorf("notOffered = %v, want metrics and repository", c.NotOffered)
	}
	if !c.mostlyMissing() {
		t.Error("two missing reads against one answered should count as mostly missing")
	}
	if (&EvidenceCoverage{Answered: 5, Denied: 1}).mostlyMissing() {
		t.Error("one refused read among five answered is not mostly missing")
	}
}
