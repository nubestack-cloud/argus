package llm

// PROJECT.md B151 — value-agreement corroboration.
//
// crossCheckCausalChain (causal_chain_verify.go) already answers "did the
// hub actually serve a call of this name" — call EXISTENCE. This file
// answers the harder, more consequential question: do the SPECIFIC values a
// causal-chain step's Finding prose cites match what that real call actually
// returned? A live CreateResource execution wrote factually wrong data to a
// real cluster object past a step marked "corroborated": true, and that
// label was never wrong about call existence — it was wrong about implying
// anything at all about the cited VALUES, which is a claim call-existence
// checking can never support.
//
// # Why extraction, not a second model call
//
// The Finding is free prose ("the sidecar has LOG_LEVEL=debug"); the real
// Result is structured JSON. Two honest ways to compare them exist: ask
// another model to judge agreement (a new cost, and a new "is the judge
// itself trustworthy" question — exactly the kind of unverifiable claim this
// whole feature exists to stop trusting), or extract whatever the prose
// states in a deterministic, checkable shape and compare that shape against
// the real data. This file takes the second path. It is deliberately
// NARROW — it only extracts prose that already states a value in one of a
// few common shapes (key=value, key: value, key is/was value) — and that
// narrowness is a FEATURE, not a shortcut around the check: a Finding that
// makes no checkable claim at all correctly produces no claims, which
// valueAgreementVerdict reads as "unchecked", never as "corroborated". The
// hard constraint this whole file exists to satisfy is "do not narrow what
// counts as a citation to make the check pass" — this narrows what counts
// as an EXTRACTABLE CLAIM, which is the opposite move: it makes "unchecked"
// MORE common, not less, whenever a claim cannot be confidently read off the
// prose, rather than inventing a looser match that would let more prose
// through as if verified.

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// valueClaim is one key=value assertion read off a Finding's free prose.
type valueClaim struct {
	Key   string
	Value string
}

// valueClaimPatterns cover the shapes an investigation's own system prompt
// produces when a model states a specific value it observed. Deliberately
// only two, and deliberately NOT a "key is/was value" pattern: that shape is
// indistinguishable from ordinary English ("the pod is running", "the
// replicas field is 3" — which anchors on "field", not "replicas") far too
// often to trust, and a false claim extracted from ordinary narrative prose
// risks a false "contradicted" verdict — a worse failure than under-
// extracting, since it would cry wolf on a step that was never asserting
// anything checkable at all. `=` and `:` both require an explicit,
// deliberate punctuation marker a model uses when it means to cite a
// specific field's value, not a copula that shows up in almost every
// sentence.
var valueClaimPatterns = []*regexp.Regexp{
	// LOG_LEVEL=debug, replicas=3, app.kubernetes.io/version=1.2.3
	regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_.\-/]*)\s*=\s*"?([A-Za-z0-9_.\-:/]+)"?`),
	// replicas: 3, "LOG_LEVEL": "debug" (with or without the JSON-style quotes)
	regexp.MustCompile(`"?([A-Za-z_][A-Za-z0-9_.\-]*)"?\s*:\s*"?([A-Za-z0-9_.\-:/]+)"?`),
}

// extractValueClaims reads finding for anything shaped like a specific,
// checkable value assertion. Returns no claims (nil) for prose that never
// states one — the correct, honest input to a step that must read
// "unchecked", not "corroborated".
func extractValueClaims(finding string) []valueClaim {
	seen := map[string]bool{}
	var claims []valueClaim
	for _, pattern := range valueClaimPatterns {
		for _, m := range pattern.FindAllStringSubmatch(finding, -1) {
			key, val := strings.TrimSpace(m[1]), strings.TrimSpace(m[2])
			if key == "" || val == "" {
				continue
			}
			dedupeKey := strings.ToLower(key) + "=" + strings.ToLower(val)
			if seen[dedupeKey] {
				continue
			}
			seen[dedupeKey] = true
			claims = append(claims, valueClaim{Key: key, Value: val})
		}
	}
	return claims
}

// flattenJSONValues walks any decoded JSON value and records every leaf
// value under every plausible key name for it, case-preserved but matched
// case-insensitively by the caller. Two structural shapes are recognized:
//
//   - An ordinary object leaf: {"key": "value"} contributes key -> value
//     directly, at any depth.
//   - Kubernetes' own name/value pair array convention:
//     [{"name": "LOG_LEVEL", "value": "debug"}, ...] — used for env vars and
//     more — contributes LOG_LEVEL -> debug as a VIRTUAL key, because that is
//     the only way to answer "does this object have a value named X" for the
//     single most common shape a causal-chain Finding actually cites
//     (container env vars). This is a general structural pattern (any object
//     with sibling "name"/"value" keys in an array), not a hardcoded env-var
//     special case — the same shape covers e.g. args-as-flags or
//     resourceFieldRef-style entries without any new code.
func flattenJSONValues(v any, out map[string]string) {
	switch t := v.(type) {
	case map[string]any:
		nameValueHandled := false
		if name, ok := t["name"].(string); ok {
			if val, ok := t["value"].(string); ok {
				out[name] = val
				nameValueHandled = true
			}
		}
		for k, child := range t {
			// Once this object's own "name"/"value" pair has already been
			// captured under its virtual key above, re-adding them here as
			// literal "name"/"value" keys would pollute the flat map: real
			// Kubernetes objects have many fields literally named "name" at
			// different levels (metadata.name, containers[].name,
			// ownerReferences[].name, every OTHER env entry), and Go's
			// randomized map iteration means whichever one this loop visits
			// last, across every name/value pair in the whole tree, silently
			// wins — a corroboration verdict that could read "corroborated"
			// in one run and "contradicted" in the next for identical
			// stored evidence. Skipping them here costs nothing real: they
			// are already flattened, correctly, under their own name.
			if nameValueHandled && (k == "name" || k == "value") {
				continue
			}
			if s, ok := child.(string); ok {
				out[k] = s
			} else {
				flattenJSONValues(child, out)
			}
		}
	case []any:
		for _, child := range t {
			flattenJSONValues(child, out)
		}
	}
}

// checkValueAgreement compares claims (already extracted from a Finding)
// against result (the real, hub-captured JSON a corroborated tool call
// actually returned). result may be nil/empty — e.g. content was never
// captured for this call, an older row predating this mechanism, or the
// real call itself errored — in which case this always returns
// toolCallVerdictUnchecked, honestly, rather than guessing.
func checkValueAgreement(claims []valueClaim, result json.RawMessage) (toolCallVerdict, []string) {
	if len(claims) == 0 || len(result) == 0 {
		return toolCallVerdictUnchecked, nil
	}
	var decoded any
	if err := json.Unmarshal(result, &decoded); err != nil {
		return toolCallVerdictUnchecked, nil
	}
	flat := map[string]string{}
	flattenJSONValues(decoded, flat)
	if len(flat) == 0 {
		return toolCallVerdictUnchecked, nil
	}

	var mismatches []string
	checked := 0
	for _, claim := range claims {
		real, ok := lookupCaseInsensitive(flat, claim.Key)
		if !ok {
			// This specific claim's key was never observed in the real
			// result at all — not evidence of disagreement (the Finding may
			// be citing a DIFFERENT tool call's result within the same
			// step), so it does not count as checked either way.
			continue
		}
		checked++
		if !strings.EqualFold(strings.TrimSpace(real), strings.TrimSpace(claim.Value)) && !numericallyEqual(real, claim.Value) {
			mismatches = append(mismatches, claim.Key+"="+claim.Value+" (real: "+claim.Key+"="+real+")")
		}
	}
	if checked == 0 {
		return toolCallVerdictUnchecked, nil
	}
	if len(mismatches) > 0 {
		return toolCallVerdictContradicted, mismatches
	}
	return toolCallVerdictCorroborated, nil
}

// lookupCaseInsensitive is a small helper since Kubernetes field/env names
// are conventionally uppercase and prose citing them is not always.
func lookupCaseInsensitive(m map[string]string, key string) (string, bool) {
	if v, ok := m[key]; ok {
		return v, true
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

// numericallyEqual treats "3" and "3.0" (or "3" vs "3 ") as equal even
// though EqualFold would not — a plan citing "replicas=3" against a real
// value serialized as "3" from a different numeric path should not read as
// a mismatch over formatting alone.
func numericallyEqual(a, b string) bool {
	af, aerr := strconv.ParseFloat(strings.TrimSpace(a), 64)
	bf, berr := strconv.ParseFloat(strings.TrimSpace(b), 64)
	return aerr == nil && berr == nil && af == bf
}

// PROJECT.md B161 — the follow-on named by B151's own honest limit.
//
// checkValueAgreement above answers "does the model's own Finding PROSE
// agree with the real result of the ONE tool call it cited" — and by
// construction it can only check a value the Finding text actually
// mentioned. B151's real defect was invisible to it for exactly that
// reason: the executed plan's CreateResource wrote
// {LOG_LEVEL: info, MAX_RETRIES: 3, FEATURE_FLAG: on} against a real sidecar
// holding {LOG_LEVEL: debug, MAX_RETRIES: 5, FEATURE_FLAG: on}, but the real
// step-2 Finding read "...has env values for LOG_LEVEL, MAX_RETRIES, and
// FEATURE_FLAG, documenting what keys the ConfigMap should hold" — it named
// the KEYS, never the wrong VALUES, so extractValueClaims correctly found
// nothing checkable there at all.
//
// CheckPlanValueAgreement is the sharper, more targeted check that gap
// implies: compare the EXECUTED PLAN's own parameter values directly
// against the evidence gathered during this incident's investigation
// (ListMCPToolCalls' RecordedToolCall.Result, the hub's own server-recorded
// content) — never against Finding text, never against anything the model
// said about either side. planValues is deliberately a plain
// map[string]string, not a remediation.CreateResourceParams, so this package
// never needs to import internal/remediation: the caller (the executed-plan
// path in internal/api) is the one place that already knows which action
// type's params reduce to this shape.
//
// # Silence is not disagreement
//
// A CreateResource plan legitimately introduces values evidence never
// mentions — that is what "create" means, and most of a real ConfigMap's
// keys will have no prior observation at all. So a plan key with NO
// observed value anywhere in evidence is not counted as checked either way
// — exactly checkValueAgreement's own rule for a claim naming a key the
// real result never mentions (see its own comment) — silence must never
// read as contradiction, or this would refuse every legitimate create,
// including the correct one B151's own incident needed. A key IS counted as
// checked once at least one real tool call observed SOME value for it, and
// it agrees if the plan's value matches ANY one of those observations
// (evidence can legitimately observe the same key more than once, e.g. two
// separate describe_resource calls in one investigation) — it contradicts
// only when every observation disagrees. Applied to B151's own real values:
// LOG_LEVEL and MAX_RETRIES each have exactly one observation (the
// describe_resource result) and the plan disagrees with it on both, so both
// are reported; FEATURE_FLAG's one observation matches, so it is correctly
// NOT reported, matching the "correct by coincidence" note in that
// incident's own record.
//
// # Generic mechanism, deliberately narrow wiring
//
// The comparison itself (flatten evidence, look up a key case-insensitively,
// compare case/format-insensitively) is the same general machinery
// checkValueAgreement already uses, and nothing about it is specific to
// CreateResource — any action type whose params reduce to a flat
// map[string]string of named values could use it. What IS deliberately
// scoped to CreateResource for now is the CALLER: CreateResourceParams.Data
// is the one action type's params that already ARE exactly this shape
// today. ScaleDeployment carries one integer, PatchField one field/value
// pair (both trivially the same idea, but with only one key there is
// nothing this multi-key mismatch reporting adds over a direct comparison),
// and PatchResourceLimits' fields are Kubernetes quantities ("128Mi" vs
// "134217728") for which case/format-insensitive STRING equality is the
// wrong comparison — extending there would need unit-aware parsing, not a
// wiring change, so it is left as future work rather than done partially
// here.
//
// A read failure or absence of any recorded evidence at all (the common
// case for an api-backend investigation, which does not write to this
// ledger — see internal/mcp/server.go's handleToolCall) is the caller's to
// handle; this function itself treats "no evidence" the same as "nothing
// observed" (see below) and returns no contradiction, honestly, rather than
// guessing.
func CheckPlanValueAgreement(planValues map[string]string, evidence []RecordedToolCall) (contradicted bool, mismatches []string) {
	if len(planValues) == 0 || len(evidence) == 0 {
		return false, nil
	}
	observed := flattenAllEvidence(evidence)
	if len(observed) == 0 {
		return false, nil
	}

	// Sorted so a mismatch list (surfaced in an error message and asserted
	// on in tests) has a stable order rather than reshuffling with Go's
	// randomised map iteration from one run to the next.
	keys := make([]string, 0, len(planValues))
	for k := range planValues {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		planVal := planValues[key]
		observedVals, ok := lookupCaseInsensitiveMulti(observed, key)
		if !ok {
			// Never observed anywhere in evidence: not evidence of
			// disagreement (see this function's own doc comment) — a
			// legitimate new value, so it does not count as checked.
			continue
		}
		agrees := false
		for _, ov := range observedVals {
			if strings.EqualFold(strings.TrimSpace(ov), strings.TrimSpace(planVal)) || numericallyEqual(ov, planVal) {
				agrees = true
				break
			}
		}
		if !agrees {
			mismatches = append(mismatches, key+"="+planVal+" (evidence observed: "+key+"="+strings.Join(observedVals, " | ")+")")
		}
	}
	return len(mismatches) > 0, mismatches
}

// flattenAllEvidence pools every real, hub-recorded tool call's Result for
// one incident's investigation into a single key -> [every observed value]
// map. Multi-valued deliberately: two different real tool calls may
// legitimately report different values for the same key (e.g. a resource
// observed at two different points in one investigation), and
// CheckPlanValueAgreement's own rule is that the plan agrees if it matches
// ANY one of them — collapsing to a single "last one wins" value here would
// silently make matching order-dependent instead.
//
// A call with no captured Result (nil/empty — an older row, a failed call,
// or content simply never captured for this backend) contributes nothing,
// the same "absent content is unchecked, never a mismatch" rule
// checkValueAgreement already follows.
func flattenAllEvidence(evidence []RecordedToolCall) map[string][]string {
	observed := map[string][]string{}
	for _, call := range evidence {
		if len(call.Result) == 0 {
			continue
		}
		var decoded any
		if err := json.Unmarshal(call.Result, &decoded); err != nil {
			continue
		}
		flat := map[string]string{}
		flattenJSONValues(decoded, flat)
		for k, v := range flat {
			observed[k] = append(observed[k], v)
		}
	}
	return observed
}

// lookupCaseInsensitiveMulti is lookupCaseInsensitive's counterpart for
// flattenAllEvidence's multi-valued map.
func lookupCaseInsensitiveMulti(m map[string][]string, key string) ([]string, bool) {
	if v, ok := m[key]; ok {
		return v, true
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}
