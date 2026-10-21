package llm

import (
	"encoding/json"
	"testing"
)

// TestCrossCheckCausalChainCatchesFabricatedToolCall is BACKLOG.md C10's
// load-bearing test: a self-reported causal chain that cites a tool call the
// hub never actually served must come back marked unverified, never silently
// rendered as if it were checked. Without this check, asking the cli
// backend's model to self-report a causal chain would reintroduce exactly
// the fabrication cli_investigator.go's own comment used to refuse to
// produce.
func TestCrossCheckCausalChainCatchesFabricatedToolCall(t *testing.T) {
	wire := []causalChainStepWire{
		{
			Hypothesis: "the container was OOMKilled",
			// get_events really happened (below); get_secrets is a tool this
			// investigation never had access to at all, and was never called —
			// exactly the kind of citation a model might invent to look more
			// thorough than it actually was.
			ToolCalls: []string{"get_events", "get_secrets"},
			Finding:   "confirmed via events",
		},
	}
	real := []RecordedToolCall{
		{Tool: "get_events", Outcome: "ok"},
	}

	chain := crossCheckCausalChain(wire, real)
	if len(chain) != 1 || len(chain[0].ToolCalls) != 2 {
		t.Fatalf("chain = %+v, want 1 step with 2 tool call citations", chain)
	}

	got := chain[0].ToolCalls
	// The Finding cites no checkable value ("confirmed via events" has no
	// key=value shape), so the real, matched call reads "unchecked" — a real
	// call with nothing to check, never "corroborated" on call-existence
	// alone (PROJECT.md B151's own hard constraint).
	if got[0].Tool != "get_events" || got[0].Corroborated != toolCallVerdictUnchecked {
		t.Errorf("get_events citation = %+v, want Corroborated: %q (it really was called, but nothing checkable was cited)", got[0], toolCallVerdictUnchecked)
	}
	if got[1].Tool != "get_secrets" || got[1].Corroborated != toolCallVerdictUnverified {
		t.Errorf("get_secrets citation = %+v, want Corroborated: %q — this call was NEVER served and must not be rendered as evidence", got[1], toolCallVerdictUnverified)
	}
	if got[1].Error != nil {
		t.Errorf("unverified citation Error = %v, want nil — there is nothing honest to report about a call that never happened", *got[1].Error)
	}
}

// TestCrossCheckCausalChainConsumesEachRealCallAtMostOnce pins the greedy,
// per-tool-name matching rule: citing a real tool MORE times than it was
// actually called must not let one real occurrence vouch for an unbounded
// number of claimed repeats. Citing it three times when it was only served
// once matches exactly the first citation.
func TestCrossCheckCausalChainConsumesEachRealCallAtMostOnce(t *testing.T) {
	wire := []causalChainStepWire{
		{Hypothesis: "h1", ToolCalls: []string{"get_logs", "get_logs", "get_logs"}},
	}
	real := []RecordedToolCall{
		{Tool: "get_logs", Outcome: "ok"},
	}

	chain := crossCheckCausalChain(wire, real)
	got := chain[0].ToolCalls
	if len(got) != 3 {
		t.Fatalf("got %d tool call entries, want 3", len(got))
	}
	unverified := 0
	for _, c := range got {
		if c.Corroborated == toolCallVerdictUnverified {
			unverified++
		}
	}
	if unverified != 2 {
		t.Errorf("unverified count = %d, want exactly 2 (one real call cannot vouch for three claimed calls)", unverified)
	}
}

// TestCrossCheckCausalChainReportsRealOutcomeNotTheModelsClaim confirms a
// matched citation's Error reflects the REAL recorded outcome from the
// ledger — never anything the model said, since the wire format doesn't even
// carry a model-claimed outcome (see causalChainStepWire's own doc comment on
// why: trusting the model's account of whether its own call succeeded would
// be exactly the kind of unverifiable claim this mechanism exists to stop
// accepting).
func TestCrossCheckCausalChainReportsRealOutcomeNotTheModelsClaim(t *testing.T) {
	wire := []causalChainStepWire{
		{Hypothesis: "h1", ToolCalls: []string{"get_owner_chain"}},
	}
	real := []RecordedToolCall{
		{Tool: "get_owner_chain", Outcome: "error"},
	}

	chain := crossCheckCausalChain(wire, real)
	call := chain[0].ToolCalls[0]
	if call.Corroborated != toolCallVerdictUnchecked {
		t.Fatalf("Corroborated = %q, want %q — this tool really was called, but it failed, so there is nothing to value-check", call.Corroborated, toolCallVerdictUnchecked)
	}
	if call.Error == nil {
		t.Fatal("Error = nil, want the real recorded failure surfaced")
	}
}

// TestCrossCheckCausalChainEmptyLedgerUnverifiesEverything: an investigation
// the hub recorded NO tool calls for at all (e.g. the ledger read failed, or
// genuinely nothing was ever dispatched) must not corroborate any citation —
// there is nothing to check it against, so nothing can be verified.
func TestCrossCheckCausalChainEmptyLedgerUnverifiesEverything(t *testing.T) {
	wire := []causalChainStepWire{
		{Hypothesis: "h1", ToolCalls: []string{"get_events"}},
	}
	chain := crossCheckCausalChain(wire, nil)
	if chain[0].ToolCalls[0].Corroborated != toolCallVerdictUnverified {
		t.Errorf("Corroborated = %q with an empty ledger, want %q", chain[0].ToolCalls[0].Corroborated, toolCallVerdictUnverified)
	}
}

// TestCrossCheckCausalChainStepNumbersAndTextSurvive confirms the ordinary,
// well-behaved case is not accidentally broken by the corroboration logic:
// step numbers are 1-based and sequential, and hypothesis/finding text is
// carried through trimmed.
func TestCrossCheckCausalChainStepNumbersAndTextSurvive(t *testing.T) {
	wire := []causalChainStepWire{
		{Hypothesis: "  first hypothesis  ", ToolCalls: []string{"get_events"}, Finding: "  first finding  "},
		{Hypothesis: "second hypothesis", ToolCalls: nil, Finding: "second finding"},
	}
	real := []RecordedToolCall{{Tool: "get_events", Outcome: "ok"}}

	chain := crossCheckCausalChain(wire, real)
	if len(chain) != 2 {
		t.Fatalf("got %d steps, want 2", len(chain))
	}
	if chain[0].Step != 1 || chain[1].Step != 2 {
		t.Errorf("step numbers = %d, %d, want 1, 2", chain[0].Step, chain[1].Step)
	}
	if chain[0].Hypothesis != "first hypothesis" || chain[0].Finding != "first finding" {
		t.Errorf("step 0 = %+v, want trimmed hypothesis/finding", chain[0])
	}
	if len(chain[1].ToolCalls) != 0 {
		t.Errorf("step 1 ToolCalls = %+v, want empty (no citations)", chain[1].ToolCalls)
	}
}

// TestCrossCheckCausalChainValueAgreement_CorroboratesAMatch is PROJECT.md
// B151's positive case: a Finding that cites a specific value which DOES
// match the real captured result reads "corroborated" — a strictly stronger
// claim than the old bool ever supported.
func TestCrossCheckCausalChainValueAgreement_CorroboratesAMatch(t *testing.T) {
	wire := []causalChainStepWire{
		{
			Hypothesis: "the sidecar's log level was raised",
			Finding:    "describe_resource shows the sidecar container has LOG_LEVEL=debug",
			ToolCalls:  []string{"describe_resource"},
		},
	}
	real := []RecordedToolCall{
		{Tool: "describe_resource", Outcome: "ok", Result: json.RawMessage(`{
			"spec": {"containers": [{"name": "sidecar", "env": [{"name": "LOG_LEVEL", "value": "debug"}]}]}
		}`)},
	}

	chain := crossCheckCausalChain(wire, real)
	got := chain[0].ToolCalls[0]
	if got.Corroborated != toolCallVerdictCorroborated {
		t.Errorf("Corroborated = %q, want %q — the cited value genuinely matches the real result", got.Corroborated, toolCallVerdictCorroborated)
	}
}

// TestCrossCheckCausalChainValueAgreement_CatchesTheB151Shape is the direct
// regression test for PROJECT.md B151's own live defect: a causal-chain step
// citing a specific value that does NOT match what the real tool call
// actually returned must read "contradicted", never "corroborated" — this
// is exactly the gap that let a live CreateResource execution write
// factually wrong data past a step the old mechanism had already marked
// corroborated (true only ever meant "the call happened").
func TestCrossCheckCausalChainValueAgreement_CatchesTheB151Shape(t *testing.T) {
	wire := []causalChainStepWire{
		{
			Hypothesis: "the ConfigMap should hold the sidecar's real env values",
			Finding:    "the sidecar container has env values LOG_LEVEL=debug, MAX_RETRIES=5, FEATURE_FLAG=on",
			ToolCalls:  []string{"describe_resource"},
		},
	}
	// The REAL object, as it actually was live: LOG_LEVEL=info and
	// MAX_RETRIES=3 — two of the three cited values are wrong, exactly
	// B151's own live shape (FEATURE_FLAG=on is the one that happens to
	// agree).
	real := []RecordedToolCall{
		{Tool: "describe_resource", Outcome: "ok", Result: json.RawMessage(`{
			"spec": {"containers": [{"name": "sidecar", "env": [
				{"name": "LOG_LEVEL", "value": "info"},
				{"name": "MAX_RETRIES", "value": "3"},
				{"name": "FEATURE_FLAG", "value": "on"}
			]}]}
		}`)},
	}

	chain := crossCheckCausalChain(wire, real)
	got := chain[0].ToolCalls[0]
	if got.Corroborated != toolCallVerdictContradicted {
		t.Fatalf("Corroborated = %q, want %q — 2 of 3 cited values disagree with the real result", got.Corroborated, toolCallVerdictContradicted)
	}
}

// TestCrossCheckCausalChainValueAgreement_UncheckedWithNoContent is the
// honest-degradation case: a real, matched call whose content was never
// captured (an older row predating migration 000099, or a partial write —
// see internal/api.ListMCPToolCalls' own doc comment) must read "unchecked",
// never silently "corroborated" just because the call itself happened.
func TestCrossCheckCausalChainValueAgreement_UncheckedWithNoContent(t *testing.T) {
	wire := []causalChainStepWire{
		{Hypothesis: "h1", Finding: "LOG_LEVEL=debug", ToolCalls: []string{"describe_resource"}},
	}
	real := []RecordedToolCall{
		{Tool: "describe_resource", Outcome: "ok"}, // Result deliberately nil
	}

	chain := crossCheckCausalChain(wire, real)
	got := chain[0].ToolCalls[0]
	if got.Corroborated != toolCallVerdictUnchecked {
		t.Errorf("Corroborated = %q, want %q — the citation states a checkable value but no content exists to check it against", got.Corroborated, toolCallVerdictUnchecked)
	}
}

// TestToolCallVerdictUnmarshalJSON_LegacyBool is PROJECT.md B158's own
// regression test. Before toolCallVerdict existed (pre-B151),
// ToolCallRecord.Corroborated was a bare bool, and analyses written by that
// older binary persisted "corroborated": true/false literally in
// analyses.causal_chain. A newer hub decoding that JSON straight into this
// string-typed field with the default unmarshaler fails outright (json:
// cannot unmarshal bool into Go struct field ...toolCalls.corroborated of
// type llm.toolCallVerdict) — which is exactly what made 8 live incidents
// permanently 500 on GET /api/v1/incidents/{id} (handleGetIncident ->
// analysisFromRow's json.Unmarshal(causalChainJSON, ...) fails, and the
// whole lookup fails with it, not just the one bad field).
//
// This pins the decode of a single toolCallVerdict field in isolation. See
// TestToolCallVerdictUnmarshalJSON_WithinFullCausalChain below for the same
// fix exercised through the actual failing shape: unmarshaling a whole
// []CausalStep, as handleGetIncident really does.
func TestToolCallVerdictUnmarshalJSON_LegacyBool(t *testing.T) {
	cases := []struct {
		name string
		json string
		want toolCallVerdict
	}{
		// The old bool asserted call EXISTENCE only ("a call of this name was
		// actually served") — it never claimed anything about whether cited
		// values agreed with the real result, because value-agreement
		// checking (B151) did not exist yet. toolCallVerdictCorroborated now
		// positively asserts that check happened and held, so retroactively
		// stamping an old `true` row "corroborated" would claim a check that
		// never ran. toolCallVerdictUnchecked is the honest, non-overclaiming
		// home for "the call genuinely happened, nothing is asserted about
		// its values" — see that constant's own doc comment.
		{name: "true maps to unchecked, not corroborated", json: `true`, want: toolCallVerdictUnchecked},
		// The old bool false meant the cited tool was never actually served
		// at all — the call-fabrication case. PROJECT.md B151's own text
		// states this mapping explicitly: "unverified ... unchanged in
		// meaning from the old bool's false".
		{name: "false maps to unverified", json: `false`, want: toolCallVerdictUnverified},
		// The modern string shape must keep decoding exactly as before —
		// this fix must not regress the current, already-correct case.
		{name: "modern string corroborated", json: `"corroborated"`, want: toolCallVerdictCorroborated},
		{name: "modern string contradicted", json: `"contradicted"`, want: toolCallVerdictContradicted},
		{name: "modern string unchecked", json: `"unchecked"`, want: toolCallVerdictUnchecked},
		{name: "modern string unverified", json: `"unverified"`, want: toolCallVerdictUnverified},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got toolCallVerdict
			if err := json.Unmarshal([]byte(tc.json), &got); err != nil {
				t.Fatalf("Unmarshal(%s) returned error, want a tolerant decode: %v", tc.json, err)
			}
			if got != tc.want {
				t.Errorf("Unmarshal(%s) = %q, want %q", tc.json, got, tc.want)
			}
		})
	}
}

// TestToolCallVerdictUnmarshalJSON_WithinFullCausalChain reproduces B158's
// actual live failure shape rather than the isolated field: a full
// causal_chain JSON array, exactly as analysisFromRow
// (internal/api/analyze.go) unmarshals it straight from Postgres, containing
// an old row's bare-bool "corroborated": true/false nested inside
// toolCalls. Before the fix, this specific json.Unmarshal call is the one
// that failed and took the entire incident lookup down with it — an
// isolated-field test alone wouldn't prove the fix reaches the real decode
// path.
func TestToolCallVerdictUnmarshalJSON_WithinFullCausalChain(t *testing.T) {
	raw := []byte(`[
		{
			"step": 1,
			"hypothesis": "old row from a pre-B151 hub",
			"finding": "confirmed via events",
			"toolCalls": [
				{"tool": "get_events", "args": null, "error": null, "corroborated": true},
				{"tool": "get_secrets", "args": null, "error": null, "corroborated": false}
			]
		}
	]`)

	var chain []CausalStep
	if err := json.Unmarshal(raw, &chain); err != nil {
		t.Fatalf("Unmarshal legacy-bool causal_chain returned error, want a successful tolerant decode (this is exactly what made incident lookups 500): %v", err)
	}
	if len(chain) != 1 || len(chain[0].ToolCalls) != 2 {
		t.Fatalf("chain = %+v, want 1 step with 2 tool calls", chain)
	}
	if got := chain[0].ToolCalls[0].Corroborated; got != toolCallVerdictUnchecked {
		t.Errorf("get_events (legacy true) Corroborated = %q, want %q", got, toolCallVerdictUnchecked)
	}
	if got := chain[0].ToolCalls[1].Corroborated; got != toolCallVerdictUnverified {
		t.Errorf("get_secrets (legacy false) Corroborated = %q, want %q", got, toolCallVerdictUnverified)
	}
}
