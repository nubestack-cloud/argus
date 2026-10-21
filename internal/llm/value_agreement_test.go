package llm

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExtractValueClaims(t *testing.T) {
	for _, tc := range []struct {
		name    string
		finding string
		want    []valueClaim
	}{
		{
			name:    "no checkable claim at all",
			finding: "the sidecar container has env values for LOG_LEVEL, MAX_RETRIES, and FEATURE_FLAG",
			want:    nil,
		},
		{
			name:    "key=value",
			finding: "the container has LOG_LEVEL=debug set",
			want:    []valueClaim{{Key: "LOG_LEVEL", Value: "debug"}},
		},
		{
			name:    "key: value",
			finding: "replicas: 3 in the spec",
			want:    []valueClaim{{Key: "replicas", Value: "3"}},
		},
		{
			// Deliberately NOT extracted: "X is Y" is indistinguishable from
			// ordinary English far too often to trust (see
			// valueClaimPatterns' own doc comment) — this sentence states a
			// value a human would read as replicas=3, but no pattern here
			// claims to catch it, and that is the correct, conservative
			// choice over a regex that would also fire on plain narration.
			name:    "key is value is deliberately not extracted",
			finding: "the replicas field is 3",
			want:    nil,
		},
		{
			name:    "plain narrative sentence extracts nothing checkable",
			finding: "the pod is running and healthy",
			want:    nil,
		},
		{
			name:    "duplicate claims are deduplicated",
			finding: "LOG_LEVEL=debug, and separately LOG_LEVEL=debug again",
			want:    []valueClaim{{Key: "LOG_LEVEL", Value: "debug"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := extractValueClaims(tc.finding)
			if len(got) != len(tc.want) {
				t.Fatalf("extractValueClaims(%q) = %+v, want %+v", tc.finding, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("claim %d = %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestFlattenJSONValues_ObjectLeaves(t *testing.T) {
	var decoded any
	if err := json.Unmarshal([]byte(`{"replicas": "3", "nested": {"ready": "true"}}`), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	flat := map[string]string{}
	flattenJSONValues(decoded, flat)
	if flat["replicas"] != "3" {
		t.Errorf("flat[replicas] = %q, want 3", flat["replicas"])
	}
	if flat["ready"] != "true" {
		t.Errorf("flat[ready] = %q, want true (nested object leaves must still flatten)", flat["ready"])
	}
}

func TestFlattenJSONValues_KubernetesNameValueArray(t *testing.T) {
	var decoded any
	if err := json.Unmarshal([]byte(`{
		"spec": {"containers": [{"name": "sidecar", "env": [
			{"name": "LOG_LEVEL", "value": "info"},
			{"name": "MAX_RETRIES", "value": "3"}
		]}]}
	}`), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	flat := map[string]string{}
	flattenJSONValues(decoded, flat)
	if flat["LOG_LEVEL"] != "info" {
		t.Errorf("flat[LOG_LEVEL] = %q, want info — the name/value array convention must produce a virtual key", flat["LOG_LEVEL"])
	}
	if flat["MAX_RETRIES"] != "3" {
		t.Errorf("flat[MAX_RETRIES] = %q, want 3", flat["MAX_RETRIES"])
	}
}

// TestFlattenJSONValues_NameValuePairsDoNotPolluteLiteralKeys is the
// regression guard for a nondeterminism bug found in a whole-repo review
// pass (2026-09-27): the name/value array convention below used to ALSO let
// the generic per-key loop re-add the same object's own "name"/"value" as
// literal flat keys, so two different name/value pairs anywhere in the tree
// raced over who last wrote flat["name"]/flat["value"] — nondeterministic
// because Go randomizes map iteration order. Run several times (t.Run in a
// loop would still only ever see one iteration order per run of `go test`;
// the real bug depended on map iteration order actually varying between
// processes) to catch a regression that reintroduces the pollution outright,
// which is deterministic and would fail on any single run.
func TestFlattenJSONValues_NameValuePairsDoNotPolluteLiteralKeys(t *testing.T) {
	var decoded any
	if err := json.Unmarshal([]byte(`{
		"spec": {"containers": [{"name": "sidecar", "env": [
			{"name": "LOG_LEVEL", "value": "info"},
			{"name": "MAX_RETRIES", "value": "3"}
		]}]}
	}`), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	flat := map[string]string{}
	flattenJSONValues(decoded, flat)
	// The container object itself has a bare "name" (no sibling "value"), so
	// it is NOT part of the array convention and legitimately, deterministically
	// flattens to a literal key — there is only one such object in this tree,
	// so no race is possible over this one.
	if flat["name"] != "sidecar" {
		t.Errorf(`flat["name"] = %q, want "sidecar" (the container's own name, the only object in this tree with "name" and no "value")`, flat["name"])
	}
	// "value", unlike "name" above, has no such lone legitimate source in this
	// tree — only the two env entries carry it, and both are name/value-array
	// shaped, so both must be excluded from the generic loop. Its presence at
	// all would mean the pollution is back.
	if v, ok := flat["value"]; ok {
		t.Errorf(`flat["value"] = %q, want absent — both objects with a "value" key are name/value-array pairs (LOG_LEVEL, MAX_RETRIES), so this key can only be nondeterministic pollution from whichever the map iteration visited last`, v)
	}
	// The virtual keys and the container's own genuinely-named "name" field
	// (which has no sibling "value", so it is NOT part of the convention)
	// must still flatten correctly — this fix must not have cost real
	// coverage while closing the pollution.
	if flat["LOG_LEVEL"] != "info" || flat["MAX_RETRIES"] != "3" {
		t.Errorf("virtual name/value keys regressed: flat = %+v", flat)
	}
}

func TestCheckValueAgreement(t *testing.T) {
	realEnv := json.RawMessage(`{"spec": {"containers": [{"name": "sidecar", "env": [
		{"name": "LOG_LEVEL", "value": "info"},
		{"name": "MAX_RETRIES", "value": "3"},
		{"name": "FEATURE_FLAG", "value": "on"}
	]}]}}`)

	t.Run("no claims is unchecked", func(t *testing.T) {
		verdict, _ := checkValueAgreement(nil, realEnv)
		if verdict != toolCallVerdictUnchecked {
			t.Errorf("verdict = %q, want %q", verdict, toolCallVerdictUnchecked)
		}
	})

	t.Run("nil result is unchecked even with claims", func(t *testing.T) {
		verdict, _ := checkValueAgreement([]valueClaim{{Key: "LOG_LEVEL", Value: "debug"}}, nil)
		if verdict != toolCallVerdictUnchecked {
			t.Errorf("verdict = %q, want %q", verdict, toolCallVerdictUnchecked)
		}
	})

	t.Run("matching claim is corroborated", func(t *testing.T) {
		verdict, mismatches := checkValueAgreement([]valueClaim{{Key: "LOG_LEVEL", Value: "info"}}, realEnv)
		if verdict != toolCallVerdictCorroborated {
			t.Errorf("verdict = %q, want %q (mismatches: %v)", verdict, toolCallVerdictCorroborated, mismatches)
		}
	})

	t.Run("the exact B151 shape: two of three cited values are wrong", func(t *testing.T) {
		claims := []valueClaim{
			{Key: "LOG_LEVEL", Value: "debug"}, // wrong: real is "info"
			{Key: "MAX_RETRIES", Value: "5"},   // wrong: real is "3"
			{Key: "FEATURE_FLAG", Value: "on"}, // correct, by coincidence
		}
		verdict, mismatches := checkValueAgreement(claims, realEnv)
		if verdict != toolCallVerdictContradicted {
			t.Fatalf("verdict = %q, want %q", verdict, toolCallVerdictContradicted)
		}
		if len(mismatches) != 2 {
			t.Errorf("mismatches = %v, want exactly 2 (LOG_LEVEL and MAX_RETRIES, not FEATURE_FLAG)", mismatches)
		}
	})

	t.Run("a claim naming a key the real result never mentions does not count as checked", func(t *testing.T) {
		verdict, _ := checkValueAgreement([]valueClaim{{Key: "SOME_OTHER_KEY", Value: "x"}}, realEnv)
		if verdict != toolCallVerdictUnchecked {
			t.Errorf("verdict = %q, want %q — this key was never observed, which is not evidence of disagreement", verdict, toolCallVerdictUnchecked)
		}
	})

	t.Run("numeric formatting differences do not count as a mismatch", func(t *testing.T) {
		verdict, mismatches := checkValueAgreement([]valueClaim{{Key: "MAX_RETRIES", Value: "3.0"}}, realEnv)
		if verdict != toolCallVerdictCorroborated {
			t.Errorf("verdict = %q, want %q (mismatches: %v) — 3 and 3.0 are the same number", verdict, toolCallVerdictCorroborated, mismatches)
		}
	})

	t.Run("case-insensitive key lookup", func(t *testing.T) {
		verdict, _ := checkValueAgreement([]valueClaim{{Key: "log_level", Value: "info"}}, realEnv)
		if verdict != toolCallVerdictCorroborated {
			t.Errorf("verdict = %q, want %q", verdict, toolCallVerdictCorroborated)
		}
	})

	t.Run("an ordinary colon-shaped sentence never produces a false contradiction", func(t *testing.T) {
		// "Result: it failed" extracts Key="Result" Value="it" — a spurious
		// claim from ordinary prose, not a real field citation. Because
		// "Result" is never a key anywhere in the real result, this must
		// stay unchecked, never contradicted — the end-to-end safety net
		// extractValueClaims' own narrow patterns are deliberately backed by.
		claims := extractValueClaims("Result: it failed to start")
		verdict, _ := checkValueAgreement(claims, realEnv)
		if verdict == toolCallVerdictContradicted {
			t.Errorf("verdict = %q for an ordinary sentence with no real field citation, want anything but contradicted (claims extracted: %+v)", verdict, claims)
		}
	})
}

// TestCheckPlanValueAgreement is PROJECT.md B161: unlike TestCheckValueAgreement
// above, none of these cases route through a Finding, extractValueClaims, or
// any model prose at all — the two inputs are a plan's own raw parameter
// values and the hub's own recorded evidence, exactly what
// CheckPlanValueAgreement's own doc comment says this mechanism is for.
func TestCheckPlanValueAgreement(t *testing.T) {
	// b151RealEvidence is the real describe_resource result from B151's own
	// live incident (fixture b130cr-cr-verify2, analysis
	// an_01m1wn06yb49vd62pk6n2kde90, confirmed via kubectl and Postgres at
	// the time and recorded verbatim in PROJECT.md's B151/B161 rows): the
	// sidecar container's real env was LOG_LEVEL=debug, MAX_RETRIES=5,
	// FEATURE_FLAG=on. The live database row for this exact incident no
	// longer exists (checked directly against the dev Postgres for this
	// task: remediation_executions/analyses have no exec_01m1wn0729bs9kwfvj9vkjzz1m
	// or an_01m1wn06yb49vd62pk6n2kde90 row today — the dev DB has been
	// reset/pruned since that 2026-09-07 session), so this reconstructs the
	// incident from its own written record rather than a live re-query,
	// using the exact real/wrong values PROJECT.md documents.
	b151RealEvidence := []RecordedToolCall{
		{
			Tool:    "describe_resource",
			Outcome: "ok",
			Result: json.RawMessage(`{"spec": {"containers": [{"name": "sidecar", "env": [
				{"name": "LOG_LEVEL", "value": "debug"},
				{"name": "MAX_RETRIES", "value": "5"},
				{"name": "FEATURE_FLAG", "value": "on"}
			]}]}}`),
		},
	}

	t.Run("B151's own live incident: the executed CreateResource plan's wrong values are caught", func(t *testing.T) {
		// The exact executed plan (CreateResourceParams.Data,
		// exec_01m1wn0729bs9kwfvj9vkjzz1m per PROJECT.md) — wrong on
		// LOG_LEVEL and MAX_RETRIES, right on FEATURE_FLAG "by coincidence".
		// The real step-2 Finding text ("...has env values for LOG_LEVEL,
		// MAX_RETRIES, and FEATURE_FLAG, documenting what keys the
		// ConfigMap should hold") never cited any of these VALUES, which is
		// exactly why checkValueAgreement above could not have caught this
		// — this function never looks at the Finding at all.
		planValues := map[string]string{
			"LOG_LEVEL":    "info",
			"MAX_RETRIES":  "3",
			"FEATURE_FLAG": "on",
		}
		contradicted, mismatches := CheckPlanValueAgreement(planValues, b151RealEvidence)
		if !contradicted {
			t.Fatalf("contradicted = false, want true — B151's own real defect (LOG_LEVEL/MAX_RETRIES wrong) must be caught")
		}
		if len(mismatches) != 2 {
			t.Fatalf("mismatches = %v, want exactly 2 (LOG_LEVEL and MAX_RETRIES, not FEATURE_FLAG which agrees)", mismatches)
		}
		joined := strings.Join(mismatches, " ")
		if !strings.Contains(joined, "LOG_LEVEL") || !strings.Contains(joined, "MAX_RETRIES") {
			t.Errorf("mismatches = %v, want LOG_LEVEL and MAX_RETRIES named", mismatches)
		}
		if strings.Contains(joined, "FEATURE_FLAG") {
			t.Errorf("mismatches = %v, must not include FEATURE_FLAG — it agrees with evidence", mismatches)
		}
	})

	// Negative control: without this case, a check that contradicts on
	// EVERY plan (or on every plan touching a key evidence happens to
	// mention) would pass the case above too — this is what proves the
	// check is discriminating, not merely always refusing.
	t.Run("negative control: a plan whose values agree with evidence passes cleanly", func(t *testing.T) {
		planValues := map[string]string{
			"LOG_LEVEL":    "debug",
			"MAX_RETRIES":  "5",
			"FEATURE_FLAG": "on",
		}
		contradicted, mismatches := CheckPlanValueAgreement(planValues, b151RealEvidence)
		if contradicted {
			t.Fatalf("contradicted = true, want false — every value here genuinely matches evidence (mismatches: %v)", mismatches)
		}
		if len(mismatches) != 0 {
			t.Errorf("mismatches = %v, want none", mismatches)
		}
	})

	t.Run("a legitimate create introducing a brand-new key is never refused", func(t *testing.T) {
		// CreateResource's whole purpose is creating something that did not
		// exist before — most of a real ConfigMap's keys will have no
		// prior observation anywhere in evidence, and that must never read
		// as contradiction (see CheckPlanValueAgreement's own "silence is
		// not disagreement" doc comment). NEW_FEATURE_TOGGLE never appears
		// in b151RealEvidence at all.
		planValues := map[string]string{"NEW_FEATURE_TOGGLE": "enabled"}
		contradicted, mismatches := CheckPlanValueAgreement(planValues, b151RealEvidence)
		if contradicted {
			t.Fatalf("contradicted = true for a key evidence never mentions, want false (mismatches: %v)", mismatches)
		}
	})

	t.Run("a plan agreeing with just one of several observations of a key is not contradicted", func(t *testing.T) {
		// Two real tool calls disagreeing about the same key (a resource
		// observed at two different points) — the plan's value matches the
		// second one. CheckPlanValueAgreement's rule is "agrees with ANY
		// observation", so this must not read as a mismatch.
		evidence := []RecordedToolCall{
			{Tool: "describe_resource", Outcome: "ok", Result: json.RawMessage(`{"LOG_LEVEL": "debug"}`)},
			{Tool: "describe_resource", Outcome: "ok", Result: json.RawMessage(`{"LOG_LEVEL": "info"}`)},
		}
		contradicted, _ := CheckPlanValueAgreement(map[string]string{"LOG_LEVEL": "info"}, evidence)
		if contradicted {
			t.Errorf("contradicted = true, want false — the plan's value matches the second observation")
		}
	})

	t.Run("no evidence at all is never treated as contradiction", func(t *testing.T) {
		contradicted, _ := CheckPlanValueAgreement(map[string]string{"LOG_LEVEL": "info"}, nil)
		if contradicted {
			t.Errorf("contradicted = true with no evidence at all, want false")
		}
	})

	t.Run("no plan values is never treated as contradiction", func(t *testing.T) {
		contradicted, _ := CheckPlanValueAgreement(nil, b151RealEvidence)
		if contradicted {
			t.Errorf("contradicted = true with no plan values at all, want false")
		}
	})

	t.Run("a call with no captured result contributes nothing, never a false match or mismatch", func(t *testing.T) {
		evidence := []RecordedToolCall{{Tool: "describe_resource", Outcome: "ok", Result: nil}}
		contradicted, _ := CheckPlanValueAgreement(map[string]string{"LOG_LEVEL": "info"}, evidence)
		if contradicted {
			t.Errorf("contradicted = true against a call with no captured result, want false")
		}
	})

	t.Run("numeric formatting differences do not count as a mismatch", func(t *testing.T) {
		evidence := []RecordedToolCall{{Tool: "describe_resource", Outcome: "ok", Result: json.RawMessage(`{"replicas": "3"}`)}}
		contradicted, mismatches := CheckPlanValueAgreement(map[string]string{"replicas": "3.0"}, evidence)
		if contradicted {
			t.Errorf("contradicted = true, want false (mismatches: %v) — 3 and 3.0 are the same number", mismatches)
		}
	})

	t.Run("case-insensitive key lookup", func(t *testing.T) {
		evidence := []RecordedToolCall{{Tool: "describe_resource", Outcome: "ok", Result: json.RawMessage(`{"LOG_LEVEL": "info"}`)}}
		contradicted, _ := CheckPlanValueAgreement(map[string]string{"log_level": "info"}, evidence)
		if contradicted {
			t.Errorf("contradicted = true, want false — key lookup must be case-insensitive")
		}
	})
}
