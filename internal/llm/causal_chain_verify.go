package llm

// BACKLOG.md C10 — cross-checking the cli backend's self-reported causal
// chain against the hub's own record of what it actually served.
//
// The problem this file exists to solve: cli_investigator.go used to set
// CausalChain: []CausalStep{} unconditionally, with a comment explaining that
// inventing a chain "would be worse than showing nothing, because it would
// look like evidence." That instinct was correct — a model's own prose
// account of its reasoning is not evidence on its own, because there is
// nothing stopping it from describing a tool call more thoroughly, or more
// favourably, than what it actually did. What makes it safe to report at all
// is verifying it against something the hub controls: mcp_tool_calls, the
// same ledger that already produces the "N tool calls, M failed" evidence
// summary (internal/api/evidence.go's getEvidenceSummary) — every MCP tool
// call this investigation's own token was ever used to make, recorded
// server-side at the moment it happened, independent of anything the model
// later says about it.

import (
	"context"
	"encoding/json"
	"strings"
)

// RecordedToolCall is one real, hub-recorded MCP tool call — ground truth for
// cross-checking a self-reported causal chain. Tool/Outcome mirror
// mcp_tool_calls' own columns exactly ("ok"/"error" per migration 000037's
// CHECK constraint); this package never touches that table directly (see
// ToolCallLedger's own comment), so the exact spelling is trusted from
// whatever the injected ledger function returns rather than re-declared as
// package-level constants here.
//
// Args/Result (PROJECT.md B151, migration 000099) are the real content that
// same call actually sent/returned — nil when no content was captured for
// this position (an older row predating this mechanism, a partial write, or
// the call itself errored, in which case Result is always nil). See
// internal/api.ListMCPToolCalls' own doc comment for exactly how these are
// matched back to the right call, and checkValueAgreement for how a nil
// Result is handled (always "unchecked", never treated as a mismatch).
type RecordedToolCall struct {
	Tool    string
	Outcome string
	Args    json.RawMessage
	Result  json.RawMessage
}

// toolCallVerdict is PROJECT.md B151's replacement for the old bare
// Corroborated bool — see ToolCallRecord.Corroborated's own doc comment for
// what each value means and why a bool could no longer say it honestly.
type toolCallVerdict string

const (
	// toolCallVerdictCorroborated: the call happened for real, AND at least
	// one checkable value claim was found in the Finding, AND every one of
	// them matched the real result.
	toolCallVerdictCorroborated toolCallVerdict = "corroborated"
	// toolCallVerdictContradicted: the call happened for real, but at least
	// one checkable value claim did NOT match the real result — the exact
	// shape that let B151's wrong values through undetected.
	toolCallVerdictContradicted toolCallVerdict = "contradicted"
	// toolCallVerdictUnchecked: the call happened for real, but no
	// checkable value claim exists in the Finding text, or no real content
	// was captured to check one against. Never rendered as agreement.
	toolCallVerdictUnchecked toolCallVerdict = "unchecked"
	// toolCallVerdictUnverified: the cited tool was never actually called
	// this investigation at all (or every real call of it was already
	// claimed by an earlier citation) — the fabrication-of-a-CALL case,
	// distinct from a value disagreement on a call that did happen.
	toolCallVerdictUnverified toolCallVerdict = "unverified"
)

// UnmarshalJSON is PROJECT.md B158's backward-compatibility fix. Before this
// type existed (pre-B151), ToolCallRecord.Corroborated was a bare bool, and
// analyses written by that older binary persisted "corroborated": true/false
// literally — rows this newer, string-typed field cannot decode with the
// default unmarshaler (json: cannot unmarshal bool into Go struct field
// ...toolCalls.corroborated of type llm.toolCallVerdict), which fails the
// WHOLE analysis lookup and makes the incident page 500 permanently, for
// every row a migration can reach AND every one it can't (a customer's own
// database, never touched by this repo's migrations at all). So this decodes
// both shapes rather than only the current one.
//
// The bool->string mapping is deliberately NOT true->corroborated,
// false->unverified's mirror image — it is picked from what the old bool
// actually asserted, not from which new label sounds closest:
//
//   - The old crossCheckCausalChain (see this file's git history) set the
//     bool true whenever a citation matched a real, unclaimed call in
//     mcp_tool_calls — call EXISTENCE only. It made no claim whatsoever about
//     whether the Finding's cited values agreed with what that call actually
//     returned, because value-agreement checking (PROJECT.md B151) did not
//     exist yet. toolCallVerdictCorroborated now POSITIVELY asserts that
//     value agreement was checked and held. Labelling an old `true` row
//     "corroborated" would claim a check that never ran — exactly the kind
//     of overclaim this whole mechanism exists to refuse (see
//     toolCallVerdictUnchecked's own doc comment: "never rendered as
//     agreement... the honest default, not a weaker synonym for
//     corroborated"). So true decodes to toolCallVerdictUnchecked: the call
//     genuinely happened, nothing about its values is asserted either way.
//   - The old bool false meant the cited tool was never actually served at
//     all this investigation — the call-fabrication case. PROJECT.md B151's
//     own text is explicit that this is "unchanged in meaning from the old
//     bool's false", i.e. toolCallVerdictUnverified.
func (v *toolCallVerdict) UnmarshalJSON(data []byte) error {
	var asBool bool
	if err := json.Unmarshal(data, &asBool); err == nil {
		if asBool {
			*v = toolCallVerdictUnchecked
		} else {
			*v = toolCallVerdictUnverified
		}
		return nil
	}
	var asString string
	if err := json.Unmarshal(data, &asString); err != nil {
		return err
	}
	*v = toolCallVerdict(asString)
	return nil
}

// ToolCallLedger looks up every MCP tool call the hub actually recorded
// serving for one incident (mcp_tool_calls, scoped to clusterID/incidentID).
// Wired by cmd/hub to internal/api.ListMCPToolCalls — this package must not
// import internal/api or a database driver directly, the same reasoning
// ToolCallback and TokenMinter already follow for the opposite direction
// (dispatching a call rather than reading back what was dispatched).
//
// A nil ToolCallLedger (CLIInvestigator built without one) means the cli
// backend cannot honestly ask for or verify a causal chain at all — see
// Investigate's own handling, which asks for CausalChain in the prompt only
// when a ledger is wired, and never reports one that could not be checked.
type ToolCallLedger func(ctx context.Context, clusterID, incidentID string) ([]RecordedToolCall, error)

// crossCheckCausalChain converts the cli backend's self-reported causal chain
// (wire, straight off the model's final answer, unverified) into the
// persisted/rendered CausalStep shape, checking every cited tool call
// against real — the real, hub-recorded calls this investigation's token
// actually made, AND (PROJECT.md B151) the real content those calls actually
// returned.
//
// The call-existence matching rule, stated precisely because it is a
// correctness property this whole feature depends on: matching is per TOOL
// NAME, greedy, and consumes one real occurrence per citation. A citation
// naming a tool with at least one remaining, unclaimed real call of that name
// is matched to it, and that real occurrence is removed from the pool so it
// cannot also match a second citation — citing a real tool three times when
// it was only actually called once matches the first and leaves the other
// two ToolCallRecordUnverified, rather than letting one real call vouch for
// an unbounded number of claimed repeats. A citation naming a tool with no
// remaining real occurrence is ToolCallRecordUnverified and carries no Error,
// because there is nothing honest to say about a call that was never served.
//
// Deliberately NOT matched against the model's own claimed outcome (there is
// none on the wire — see causalChainStepWire's doc comment): a matched
// citation's Error is set from the REAL recorded outcome, never from anything
// the model said, because trusting the model's account of whether its own
// call succeeded is exactly the kind of unverifiable claim this function
// exists to stop accepting at face value.
//
// The VALUE-agreement half, layered on top of a call-existence match only
// (checking values against a call that never happened at all would have
// nothing real to check against): extractValueClaims reads whatever the
// step's own Finding prose states in a checkable key=value shape, and
// checkValueAgreement compares those claims against the matched call's real
// Result content. Corroborated only when at least one claim was found AND
// every one of them matched; Contradicted when at least one did not — the
// exact shape that let B151's wrong values through undetected before this
// existed; Unchecked when no checkable claim exists in the prose, or no
// real content was captured for this call. Never Corroborated on the strength
// of call-existence alone — that is the hard constraint this whole mechanism
// exists to hold.
func crossCheckCausalChain(wire []causalChainStepWire, real []RecordedToolCall) []CausalStep {
	available := map[string][]RecordedToolCall{} // tool name -> queue of real, unclaimed calls
	for _, r := range real {
		available[r.Tool] = append(available[r.Tool], r)
	}

	chain := make([]CausalStep, 0, len(wire))
	for i, s := range wire {
		finding := strings.TrimSpace(s.Finding)
		claims := extractValueClaims(finding)
		step := CausalStep{
			Step:       i + 1,
			Hypothesis: strings.TrimSpace(s.Hypothesis),
			Finding:    finding,
			ToolCalls:  make([]ToolCallRecord, 0, len(s.ToolCalls)),
		}
		for _, toolName := range s.ToolCalls {
			toolName = strings.TrimSpace(toolName)
			if toolName == "" {
				continue
			}
			record := ToolCallRecord{Tool: toolName}
			queue := available[toolName]
			if len(queue) == 0 {
				record.Corroborated = toolCallVerdictUnverified
				step.ToolCalls = append(step.ToolCalls, record)
				continue
			}
			matched := queue[0]
			available[toolName] = queue[1:]
			if matched.Outcome == "error" {
				errMsg := "the hub recorded this call as having failed"
				record.Error = &errMsg
				record.Corroborated = toolCallVerdictUnchecked
				step.ToolCalls = append(step.ToolCalls, record)
				continue
			}
			verdict, _ := checkValueAgreement(claims, matched.Result)
			record.Corroborated = verdict
			step.ToolCalls = append(step.ToolCalls, record)
		}
		chain = append(chain, step)
	}
	return chain
}
