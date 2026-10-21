package llm

import (
	"encoding/json"
	"testing"
	"time"
)

// --- toolResultHasEvidence: unit coverage of the per-call shape heuristic ---

func TestToolResultHasEvidence(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"empty events array", `{"events":[]}`, false},
		{"populated events array", `{"events":[{"reason":"OOMKilling"}]}`, true},
		{"empty items array (list_resources)", `{"items":[],"returned":0,"totalMatched":0,"truncated":false}`, false},
		{"populated items array", `{"items":[{"name":"web-0"}],"returned":1}`, true},
		{"empty log lines", `{"lines":[]}`, false},
		{"populated log lines", `{"lines":["panic: nil pointer"]}`, true},
		{"empty nodeport allocations", `{"allocations":[],"returned":0}`, false},
		{"populated nodeport allocations", `{"allocations":[{"port":30080}]}`, true},
		{"describe_resource with a real object and no events", `{"object":{"kind":"Pod"},"events":[]}`, true},
		{"describe_resource with a null object and no events", `{"object":null,"events":[]}`, false},
		{"unresolved owner chain", `{"resolved":false}`, false},
		{"resolved owner chain", `{"resolved":true,"gvk":"apps/v1/ReplicaSet"}`, true},
		{"gitops ownership, managed", `{"managed_by":"argocd"}`, true},
		{"gitops ownership, explicitly none — still a fact", `{"managed_by":"none"}`, true},
		{"nodeport availability check", `{"available":false}`, true},
		{"totally empty object", `{}`, true},
		{"unrecognised shape (e.g. query_metrics)", `{"result":[{"value":[1,2]}]}`, true},
		{"malformed JSON", `not json`, true},
		{"top-level array", `[{"resolved":true}]`, true},
		{"empty top-level array (get_events/get_owner_chain found nothing)", `[]`, false},
		{"top-level array with only a dangling reference — still a fact", `[{"gvk":"apps/v1/ReplicaSet","name":"x","resolved":false}]`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := toolResultHasEvidence(json.RawMessage(c.raw))
			if got != c.want {
				t.Errorf("toolResultHasEvidence(%s) = %v, want %v", c.raw, got, c.want)
			}
		})
	}
}

// --- investigationGatheredNoEvidence (cli backend: []RecordedToolCall) ---

func TestInvestigationGatheredNoEvidence(t *testing.T) {
	t.Run("zero recorded calls is out of scope, not a clamp trigger", func(t *testing.T) {
		if investigationGatheredNoEvidence(nil) {
			t.Error("want false: no calls at all is a different failure mode (not checking), not this backstop's job")
		}
	})
	t.Run("every call errored", func(t *testing.T) {
		real := []RecordedToolCall{
			{Tool: "get_events", Outcome: "error"},
			{Tool: "describe_resource", Outcome: "error"},
		}
		if !investigationGatheredNoEvidence(real) {
			t.Error("want true: nothing but errors was ever returned")
		}
	})
	t.Run("every call succeeded but came back empty", func(t *testing.T) {
		real := []RecordedToolCall{
			{Tool: "get_events", Outcome: "ok", Result: json.RawMessage(`{"events":[]}`)},
			{Tool: "list_resources", Outcome: "ok", Result: json.RawMessage(`{"items":[],"returned":0}`)},
		}
		if !investigationGatheredNoEvidence(real) {
			t.Error("want true: two real calls, neither returned anything usable")
		}
	})
	t.Run("one call among several actually returned something", func(t *testing.T) {
		real := []RecordedToolCall{
			{Tool: "get_events", Outcome: "ok", Result: json.RawMessage(`{"events":[]}`)},
			{Tool: "get_logs", Outcome: "ok", Result: json.RawMessage(`{"lines":["OOMKilled"]}`)},
		}
		if investigationGatheredNoEvidence(real) {
			t.Error("want false: the get_logs call found something real")
		}
	})
	t.Run("a real call with no captured result content resolves to has-evidence", func(t *testing.T) {
		real := []RecordedToolCall{
			{Tool: "get_events", Outcome: "ok", Result: nil},
		}
		if investigationGatheredNoEvidence(real) {
			t.Error("want false: unknown/uncaptured content must not be treated as empty")
		}
	})
}

// --- apiToolCallsGatheredNoEvidence (api backend: []CausalStep) ---

func TestAPIToolCallsGatheredNoEvidence(t *testing.T) {
	t.Run("no tool calls at all is out of scope", func(t *testing.T) {
		if apiToolCallsGatheredNoEvidence(nil) {
			t.Error("want false: zero tool calls is a different failure mode entirely")
		}
	})
	t.Run("all calls empty or errored", func(t *testing.T) {
		errMsg := "not found"
		chain := []CausalStep{
			{Step: 1, ToolCalls: []ToolCallRecord{
				{Tool: "get_events", Result: json.RawMessage(`{"events":[]}`)},
				{Tool: "describe_resource", Error: &errMsg},
			}},
		}
		if !apiToolCallsGatheredNoEvidence(chain) {
			t.Error("want true: nothing usable was ever returned across the whole chain")
		}
	})
	t.Run("one step, one call, real evidence", func(t *testing.T) {
		chain := []CausalStep{
			{Step: 1, ToolCalls: []ToolCallRecord{
				{Tool: "get_events", Result: json.RawMessage(`{"events":[{"reason":"BackOff"}]}`)},
			}},
		}
		if apiToolCallsGatheredNoEvidence(chain) {
			t.Error("want false: the events call found something real")
		}
	})
}

// --- end-to-end: the api backend's own investigate() loop ---

// TestInvestigateClampsConfidenceWhenEveryProbeCameBackEmpty is PROJECT.md
// E21's own regression test: a scripted model that calls two tools, gets
// nothing usable back from either, and STILL concludes with a high
// confidence and a proposedPlan — exactly the fabrication a real model was
// measured making on 2026-09-26 (7 of 8 fixtures where every tool probe
// returned empty evidence). The deterministic backstop (evidence_gate.go)
// must clamp the confidence and drop the plan regardless of what the model
// itself reported.
func TestInvestigateClampsConfidenceWhenEveryProbeCameBackEmpty(t *testing.T) {
	script := []scriptedTurn{
		{
			Content:   "HYPOTHESIS: check recent events for the object",
			ToolCalls: []toolCall{tc(t, "call_1", "get_events", map[string]string{"namespace": "default"})},
		},
		{
			Content:   "FINDING: no events found\nHYPOTHESIS: check whether the workload even exists",
			ToolCalls: []toolCall{tc(t, "call_2", "list_resources", map[string]string{"namespace": "default", "kind": "Pod"})},
		},
		{
			Content: `{"rootCause": {"statement": "CrashLoopBackOff on worker-0 — the reported condition is the explanation.", "isFault": true}, "confidence": 0.9, "ruledOut": [], "proposedPlan": {"actionType": "RestartPod", "targetGvk": "v1/Pod", "targetNamespace": "default", "targetName": "worker-0", "params": {}, "reversible": true, "riskLevel": "low"}}`,
		},
	}
	srv, _ := newFakeLLMServer(t, script)
	fake := &fakeToolCallback{
		results: map[int]json.RawMessage{
			0: json.RawMessage(`{"events":[]}`),
			1: json.RawMessage(`{"items":[],"returned":0,"totalMatched":0,"truncated":false}`),
		},
	}

	result, err := investigate(t.Context(), srv.Client(), srv.URL, "", "fake-model",
		"system prompt", "user prompt", fake.callback(), 8, time.Minute, toolAvailability{dryRun: false})
	if err != nil {
		t.Fatalf("investigate: %v", err)
	}
	if result.Status != "complete" {
		t.Fatalf("Status = %q, want complete (a clamp is not a partial result — the model DID conclude, just dishonestly)", result.Status)
	}
	if result.Confidence == nil || *result.Confidence > noEvidenceConfidenceCeiling {
		t.Fatalf("Confidence = %v, want <= %.2f — every probe came back empty, so the model's self-reported 0.9 must be clamped",
			result.Confidence, noEvidenceConfidenceCeiling)
	}
	if result.ProposedPlan != nil {
		t.Errorf("ProposedPlan = %+v, want nil — a plan proposed on zero corroborating evidence must not survive the clamp", result.ProposedPlan)
	}
	// The model's own root cause statement is left untouched: this is a
	// confidence/plan clamp, not a rewrite of what it said.
	if result.RootCause == nil || result.RootCause.Statement == "" {
		t.Fatal("RootCause should still carry the model's own statement, just at a corrected confidence")
	}
}

// TestInvestigateDoesNotClampWhenEvidenceWasReal is the negative control for
// the above: a scripted model that calls one tool, gets a REAL populated
// result back, and concludes with high confidence and a plan — this must
// pass through unclamped, or the backstop would be over-triggering on
// legitimate, well-evidenced conclusions.
func TestInvestigateDoesNotClampWhenEvidenceWasReal(t *testing.T) {
	script := []scriptedTurn{
		{
			Content:   "HYPOTHESIS: check recent events for the object",
			ToolCalls: []toolCall{tc(t, "call_1", "get_events", map[string]string{"namespace": "default"})},
		},
		{
			Content: `{"rootCause": {"statement": "worker-0 was OOMKilled"}, "confidence": 0.9, "ruledOut": [], "proposedPlan": {"actionType": "RestartPod", "targetGvk": "v1/Pod", "targetNamespace": "default", "targetName": "worker-0", "params": {}, "reversible": true, "riskLevel": "low"}}`,
		},
	}
	srv, _ := newFakeLLMServer(t, script)
	fake := &fakeToolCallback{
		results: map[int]json.RawMessage{
			0: json.RawMessage(`{"events":[{"reason":"OOMKilling","message":"Memory cgroup out of memory"}]}`),
		},
	}

	result, err := investigate(t.Context(), srv.Client(), srv.URL, "", "fake-model",
		"system prompt", "user prompt", fake.callback(), 8, time.Minute, toolAvailability{dryRun: false})
	if err != nil {
		t.Fatalf("investigate: %v", err)
	}
	if result.Confidence == nil || *result.Confidence != 0.9 {
		t.Fatalf("Confidence = %v, want the model's real 0.9 — real evidence was gathered, nothing should be clamped", result.Confidence)
	}
	if result.ProposedPlan == nil {
		t.Fatal("ProposedPlan is nil, want the scripted plan preserved — real evidence backed this conclusion")
	}
}
