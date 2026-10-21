package llm

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"argus/internal/remediation"
	"argus/internal/resolution"
)

// TestEveryPermittedActionTypeIsReachable is this session's structural fix
// for the pattern three separate features shipped broken under (PROJECT.md
// B140, B142): each passed code review and its own unit tests while having
// no real path from the model to the code that was supposed to execute it.
// B142 specifically was AnnotateResource/LabelResource/CreateResource
// carrying a real tool definition in the model-facing prompt, a risk floor,
// and an admission-policy allowlist entry — but no case in
// parseProposedPlan's switch, so Params stayed nil and every plan of those
// three types was rejected before its own type-specific checks ever ran. A
// unit test proved parseProposedPlan correctly handled the six PRE-EXISTING
// action types; nothing proved the newly-declared ones reached it at all.
//
// This test derives its expectations from the REAL, live
// resolution.PermittedActionTypes lists — every action type offered on any
// route — rather than a second, hand-maintained list that could silently
// drift from them the same way parseProposedPlan's own switch did. Adding a
// new action type to PermittedActionTypes without adding a matching case
// here fails this test immediately, on the next `go test`, not on the next
// live incident that happens to choose it.
//
// # The parse-reachability probe
//
// Every wire params struct in this file is a plain (non-pointer) Go struct
// assigned directly into the remediation.ActionParams interface, so decoding
// even an EMPTY JSON params object ({}) into it and assigning the result
// always produces a non-nil interface value — a switch case that is MISSING
// is the only way Params can stay nil for a well-formed proposedPlan. That
// means this test needs no per-action sample data (itself a hand-maintained
// list to keep in sync); the action type's own name is enough.
//
// # The correction-reachability probe
//
// Not every action type needs a correction case: RestartPod and
// DeleteResource each carry a genuinely EMPTY params struct (nothing to
// correct — CorrectPlanParams's own doc comment names RestartPod as exactly
// this case), so paramsSchemaHint correctly has no entry for either. Rather
// than hand-listing those two as an exception (a second list to keep in
// sync with remediation's own struct definitions), this test reflects on
// the CONCRETE Params value the parse probe above already produced: a
// params type with zero fields has nothing a correction call could change,
// so it is exempt; a params type with at least one field must have a
// correction case, or a model-proposed plan of that type which is rejected
// once (a dry-run refusal, or an analyze-time Blocked plan) can never be
// retried through CorrectPlanParams at all.
func TestEveryPermittedActionTypeIsReachable(t *testing.T) {
	seen := map[string]bool{}
	for _, route := range []resolution.Route{resolution.RoutePullRequest, resolution.RouteInPlace, resolution.RoutePaired} {
		for _, actionType := range resolution.PermittedActionTypes(route) {
			if seen[actionType] {
				continue
			}
			seen[actionType] = true

			t.Run(actionType, func(t *testing.T) {
				raw := json.RawMessage(fmt.Sprintf(
					`{"actionType": %q, "targetGvk": "v1/ConfigMap", "targetNamespace": "ns", "targetName": "obj", "params": {}}`,
					actionType))
				plan := parseProposedPlan(raw)
				if plan == nil {
					t.Fatalf("parseProposedPlan returned nil for actionType %q", actionType)
				}
				if plan.Params == nil {
					t.Fatalf("Params is nil for actionType %q — parseProposedPlan's switch has no case for it (or its case leaves Params unset), so RemediationPlan.Validate will reject every plan of this type before its own checks ever run (this is exactly B142's shape)", actionType)
				}

				numFields := reflect.TypeOf(plan.Params).NumField()
				hint, correctable := paramsSchemaHint(remediation.ActionType(actionType))
				if numFields == 0 {
					if correctable {
						t.Errorf("actionType %q has a zero-field params type but paramsSchemaHint still offers a correction hint (%q) — harmless, but likely stale now that this type carries no fields", actionType, hint)
					}
					return
				}
				if !correctable {
					t.Fatalf("actionType %q has %d params field(s) but paramsSchemaHint has no case for it — a rejected plan of this type (a dry-run refusal, or an analyze-time Blocked plan) can never be retried through CorrectPlanParams", actionType, numFields)
				}

				corrected, err := parseCorrectedParams(remediation.ActionType(actionType), `{"params": {}}`)
				if err != nil {
					t.Fatalf("parseCorrectedParams(%q, {}): %v — paramsSchemaHint offers a correction shape for this type but parseCorrectedParams's own switch cannot decode it", actionType, err)
				}
				if corrected == nil {
					t.Fatalf("parseCorrectedParams(%q, {}) returned a nil params with no error", actionType)
				}
			})
		}
	}
	if len(seen) == 0 {
		t.Fatal("no action types collected from resolution.PermittedActionTypes across any route — test setup itself is broken")
	}
}
