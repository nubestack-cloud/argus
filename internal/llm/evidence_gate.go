package llm

// evidence_gate.go is the deterministic half of PROJECT.md E21's fix.
//
// A real-model measurement on 2026-09-26 found that on 7 of 8 fixtures where
// every tool probe returned empty evidence, the model still asserted a
// complete root cause above the eval-harness's own 0.40 "could not
// determine" ceiling (scripts/eval-harness/score.go's scoreCorrectness).
// SystemPrompt already told it to prefer an honest "could not determine"
// over a confident guess (see the phraseHonestUncertainty paragraph this
// change also strengthens) — but a prompt is a request, not a control: it
// can only make the right answer more likely, never guarantee it, and non-
// negotiable 8 ("if the root cause isn't well-supported, say 'could not
// determine,' never present a guess as a confident diagnosis") is exactly
// the kind of promise this codebase does not leave to a model's discretion
// alone when a cheap, reliable check can hold it instead.
//
// So this is a second, independent line of defense, checked against the
// same kind of ground truth crossCheckCausalChain (causal_chain_verify.go)
// already uses instead of the model's own account of what it did: the REAL
// recorded tool call results (ToolCallRecord for the api backend, which
// built them itself this same loop; RecordedToolCall from the hub's
// mcp_tool_calls ledger for the cli backend, which never drove the loop
// itself and so has no other way to know). A model that invents a root
// cause on empty evidence has no reason to also invent a causal chain that
// admits it — this reads what the tools actually returned, not what the
// model claims.
//
// What it does, and does not, do: when every real tool call this
// investigation made carried no usable signal, a "complete" verdict's
// confidence is clamped to noEvidenceConfidenceCeiling and any proposed
// plan is dropped — never left silently disagreeing with the clamped-down
// confidence value, exactly for the reason non-negotiable 8 states it that
// way: an operator (or the autonomy gate) reading a low-confidence "complete"
// analysis alongside an actionable plan would see the plan as at least a
// candidate to review; there is nothing here to review. The root cause
// STATEMENT is left exactly as the model wrote it — this is a confidence and
// plan clamp, not a rewrite of what the model said, so an operator reading
// the incident still sees the model's own reasoning, now correctly flagged
// as unsupported rather than hidden.
//
// What decides "no usable signal" is deliberately conservative in both
// directions it can be wrong:
//   - A false negative (calling a genuinely empty investigation
//     "had evidence") only forfeits this one backstop; the prompt is still
//     the first line of defense, exactly as it was before this file existed.
//   - A false positive (clamping a genuinely well-supported conclusion)
//     would misinform an operator, which is worse — so every shape this file
//     does not specifically recognise resolves toward "assume evidence",
//     never toward "assume empty".

import "encoding/json"

// noEvidenceConfidenceCeiling is the confidence a "complete" verdict is
// clamped to when nothing real was gathered to support it. It intentionally
// matches scripts/eval-harness/score.go's own default
// MaxConfidenceForInsufficient (0.4), minus a real margin rather than
// sitting exactly on the boundary — a value clamped AT the grader's own
// ceiling would pass by coincidence of rounding, not because the number
// means anything as a confidence. 0.3 reads, to a human, as what it is:
// "next to nothing to go on."
const noEvidenceConfidenceCeiling = 0.3

// investigationGatheredNoEvidence reports whether at least one real tool
// call was made this investigation (via c.ledger, mcp_tool_calls) AND NONE
// of them returned anything to reason from — see this file's own doc
// comment. Only meaningful when the ledger read itself succeeded; callers
// must not call this with a ledger read that errored (there is nothing
// honest to conclude from calls this process could not see).
//
// Deliberately narrower than "nothing was gathered": an investigation that
// made zero tool calls at all and concluded immediately is a different
// failure mode (not checking anything before answering) from the one this
// backstop exists for (checking, and being told nothing, then answering
// anyway) — PROJECT.md E21 measured the second. Folding the first in here
// too would also clamp a handful of unrelated, deliberately minimal test
// fixtures that script an immediate conclusion to exercise something else
// entirely (parsing, plan extraction) with no bearing on evidence honesty.
func investigationGatheredNoEvidence(real []RecordedToolCall) bool {
	if len(real) == 0 {
		return false
	}
	for _, r := range real {
		if r.Outcome == "error" {
			continue
		}
		if len(r.Result) == 0 {
			// A real, successful call with no captured content — an older
			// row predating migration 000099, or a partial write (see
			// RecordedToolCall's own doc comment). Unknown, not empty:
			// resolve toward "assume evidence" per this file's stated bias.
			return false
		}
		if toolResultHasEvidence(r.Result) {
			return false
		}
	}
	return true
}

// apiToolCallsGatheredNoEvidence is investigationGatheredNoEvidence's
// equivalent for the api backend, which builds its own ToolCallRecords
// directly in the same loop that dispatched them (toolloop.go's investigate)
// rather than reading them back from a ledger afterwards. Same evidence
// test (and the same "at least one call was actually made" scope — see
// investigationGatheredNoEvidence's doc comment) over the causal chain's
// flattened tool calls rather than a []RecordedToolCall.
func apiToolCallsGatheredNoEvidence(chain []CausalStep) bool {
	madeACall := false
	for _, step := range chain {
		for _, c := range step.ToolCalls {
			madeACall = true
			if c.Error != nil {
				continue
			}
			if len(c.Result) == 0 {
				return false
			}
			if toolResultHasEvidence(c.Result) {
				return false
			}
		}
	}
	return madeACall
}

// toolResultHasEvidence inspects one real tool call's successful result
// payload for the handful of "this collection came back populated" signals
// every current read-only tool's JSON result carries (internal/agent/tools.go
// — get_events' "events", list_resources'/list_nodeport_allocations' "items"/
// "allocations", get_logs' "lines"), generically by field name rather than
// per tool, so a new tool following the same array-of-results convention is
// covered without this file needing to know its name.
//
// Every field it does not recognise, and every ambiguous case, resolves to
// true (assume evidence) per this file's stated bias — see the doc comment
// above.
func toolResultHasEvidence(raw json.RawMessage) bool {
	// get_events and get_owner_chain both marshal their result as a bare
	// top-level JSON array (internal/agent/tools_events.go's/tools_ownerchain.go's
	// mustMarshal(results)/mustMarshal(nodes)), not an object with a named
	// array field — the two are indistinguishable to a human reading the
	// tool schemas, but json.Unmarshal into the map below fails outright on
	// an array, which used to send BOTH tools straight into the "not a JSON
	// object — assume evidence" fallback below, for every call, empty or
	// not. get_events is the tool the system prompt tells the model to try
	// first on almost any investigation, so this silently defeated the
	// clamp for the single most common "found nothing" shape. An empty
	// top-level array is exactly the same kind of real, specific
	// nothing-here signal as an empty "events"/"items" field below (a real,
	// recognized emptiness, not an unenumerated shape) — so it resolves to
	// false the same way; a non-empty array (an event, or an owner-chain
	// node — resolved or not, since a dangling reference is itself a fact
	// worth reasoning from, see ownerChainNode's own doc comment) resolves
	// to true, matching every other recognized-array field below.
	var genericArr []json.RawMessage
	if err := json.Unmarshal(raw, &genericArr); err == nil {
		return len(genericArr) > 0
	}

	var generic map[string]json.RawMessage
	if err := json.Unmarshal(raw, &generic); err != nil {
		// Not a JSON object this function knows how to read (or invalid) —
		// assume evidence rather than risk a false "nothing here" verdict.
		return true
	}

	// recognized tracks whether this payload matched ANY shape this function
	// knows how to read at all, empty or not — the two failure directions
	// need different defaults. A recognised-but-empty result (an events call
	// that came back "events": []) is real, specific evidence of absence,
	// so it resolves to false. A shape this function has never seen before
	// (query_metrics, dry_run_patch, a future tool) must NOT resolve to
	// false by the same reasoning — that would misreport "unenumerated" as
	// "empty" — so it resolves to true (assume evidence) instead.
	recognized := false

	for _, arrField := range []string{"events", "items", "lines", "allocations"} {
		v, ok := generic[arrField]
		if !ok {
			continue
		}
		recognized = true
		var arr []json.RawMessage
		if json.Unmarshal(v, &arr) != nil {
			// Present but not the array shape expected — don't guess.
			return true
		}
		if len(arr) > 0 {
			return true
		}
	}

	// describe_resource / get_owner_chain: a real object payload is evidence
	// on its own, even when that same result's "events" array is empty.
	if v, ok := generic["object"]; ok {
		recognized = true
		if len(v) > 0 && string(v) != "null" {
			return true
		}
	}
	if v, ok := generic["resolved"]; ok {
		recognized = true
		var resolved bool
		if json.Unmarshal(v, &resolved) == nil && resolved {
			return true
		}
	}
	// get_gitops_ownership: a definite answer either way ("argocd", "flux",
	// "fleet", "helm", or the clean "none") is itself a fact worth reasoning
	// from — it is the ABSENCE of this field, not the value "none", that
	// means nothing came back, so no need to touch `recognized` when it is
	// missing.
	if v, ok := generic["managed_by"]; ok && len(v) > 0 {
		return true
	}
	if v, ok := generic["available"]; ok && len(v) > 0 {
		return true
	}

	if !recognized {
		// No recognised field was present at all: an unenumerated tool
		// shape (query_metrics, dry_run_patch, list_repo_files/
		// read_repo_file, or a future tool this file was never updated
		// for). Assume evidence.
		return true
	}
	// Every recognised field this payload carried was empty/false/null.
	return false
}
