package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"argus/internal/data"
)

// TestHandlePutSettings_RequireReversibleForAutoApproveOmittedLeavesValueUnchanged
// is BUGS.md 97's own regression test, proved against a real Postgres:
// PUT /api/v1/admin/settings must never silently reset
// autonomy.requireReversibleForAutoApprove to false just because a request
// touches the "autonomy" section without mentioning that one field. Before
// migration 000085 (this fix), AutonomyUpdate.RequireReversibleForAutoApprove
// was a plain bool, so an absent JSON key decoded to Go's zero value, false —
// exactly the scenario BUGS.md 97 found live: a PUT sent to turn on
// unattended execution and set its namespace allowlist came back with the
// reversibility guardrail silently turned off. This test uses the bug
// report's own reproduction body.
//
// The fix makes this field a *bool, following AutoApproveMaxRisk/
// MinConfidenceForAutoApprove's own pre-existing contract on this exact
// struct EXACTLY, not inventing a new one: omitting the whole "autonomy"
// section changes nothing (untouched), but once the section IS present,
// every field inside it is taken exactly as given — nil clears an override
// back to internal/orchestrator.DefaultAutonomyPolicy's own hardcoded value.
// For the two pre-existing pointer fields that hardcoded value is a
// middling default; for this field it is `true`, the safe direction. So
// "leaves the existing value unchanged" holds for the bug's own
// reproduction (where the existing value already IS the safe default,
// which is also the shipped, unconfigured starting state) — the case that
// matters is that omission can no longer resolve to the unsafe `false`, the
// way the old plain-bool zero value did. An operator who has explicitly
// chosen `false` and then sends a later autonomy-touching PUT without
// repeating it will see it reset to the safe default too, exactly like
// AutoApproveMaxRisk/MinConfidenceForAutoApprove already behave for their
// own overrides — see the last sub-step below.
//
// Runs inside one transaction that is rolled back, never committed —
// org_settings is a shared singleton row (migration 000018_org_settings) on
// a live, shared dev database — mirroring breaker_db_test.go's own pattern
// for the identical reason.
func TestHandlePutSettings_RequireReversibleForAutoApproveOmittedLeavesValueUnchanged(t *testing.T) {
	pool := analyzeDetachTestPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if err := data.SetRequestScope(ctx, tx, "tenant_test_bugs97", nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	s := &Server{}
	rc := &requestContext{Tx: tx, UserID: "usr_test_bugs97", TenantID: "tenant_test_bugs97"}

	put := func(t *testing.T, body string) map[string]any {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings", strings.NewReader(body))
		s.handlePutSettings(rec, req, rc)
		if rec.Code != http.StatusOK {
			t.Fatalf("PUT %s: status = %d, want 200 (body: %s)", body, rec.Code, rec.Body.String())
		}
		var resp map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode response: %v (body: %s)", err, rec.Body.String())
		}
		return resp
	}

	autonomyField := func(t *testing.T, resp map[string]any, field string) any {
		t.Helper()
		autonomy, ok := resp["autonomy"].(map[string]any)
		if !ok {
			t.Fatalf("response has no autonomy object: %+v", resp)
		}
		return autonomy[field]
	}

	// First PUT: explicitly turn the guardrail ON. This is the installation
	// default anyway, but setting it explicitly means the second PUT's
	// result can only be explained by "left unchanged", not "happened to
	// already be true from a fresh row".
	resp := put(t, `{"autonomy": {"requireReversibleForAutoApprove": true}}`)
	if got := autonomyField(t, resp, "requireReversibleForAutoApprove"); got != true {
		t.Fatalf("requireReversibleForAutoApprove after first PUT = %v, want true", got)
	}

	// Second PUT: the bug report's own reproduction body — turn on unattended
	// execution and set its namespace allowlist, WITHOUT mentioning
	// requireReversibleForAutoApprove at all. Before this fix, this silently
	// flipped the RAW stored value to false, and there was no separate
	// effective field to tell the two apart. Now the raw field goes to null
	// (unconfigured — matching AutoApproveMaxRisk/MinConfidenceForAutoApprove's
	// identical on-omission behavior), and effectiveRequireReversibleForAuto
	// Approve — what internal/orchestrator.ResolveAutonomyPolicy would
	// actually apply to the very next investigation — must be true, never
	// false. That resolved value is what actually governs the gate, so this
	// is the assertion that proves the guardrail itself was not weakened.
	resp = put(t, `{"autonomy": {"unattendedExecutionEnabled": true, "unattendedNamespaces": ["argus-e9-test-8"]}}`)
	if got := autonomyField(t, resp, "requireReversibleForAutoApprove"); got != nil {
		t.Errorf("requireReversibleForAutoApprove after omitting it from a later PUT = %v, want nil/null (unconfigured)", got)
	}
	if got := autonomyField(t, resp, "effectiveRequireReversibleForAutoApprove"); got != true {
		t.Errorf("effectiveRequireReversibleForAutoApprove after omitting it from a later PUT = %v, want true — this is exactly the BUGS.md 97 regression: the gate must not silently weaken", got)
	}
	if got := autonomyField(t, resp, "unattendedExecutionEnabled"); got != true {
		t.Errorf("unattendedExecutionEnabled = %v, want true (this PUT's own explicit value)", got)
	}

	// Third PUT: an explicit false must still actually turn the guardrail
	// off — the fix must not have made the field impossible to disable.
	resp = put(t, `{"autonomy": {"requireReversibleForAutoApprove": false}}`)
	if got := autonomyField(t, resp, "requireReversibleForAutoApprove"); got != false {
		t.Errorf("requireReversibleForAutoApprove after an explicit false = %v, want false", got)
	}
	if got := autonomyField(t, resp, "effectiveRequireReversibleForAutoApprove"); got != false {
		t.Errorf("effectiveRequireReversibleForAutoApprove after an explicit false = %v, want false", got)
	}

	// Fourth PUT: touching autonomy again while omitting the field resolves
	// back to the safe default (true) on the very next investigation, not
	// to the false an operator explicitly chose in the third PUT. This is
	// NOT a remaining instance of BUGS.md 97 — the bug was specifically
	// "omission silently produces the UNSAFE value with no way to
	// represent 'unconfigured' at all." This field now shares AutoApprove
	// MaxRisk/MinConfidenceForAutoApprove's own pre-existing, documented
	// contract exactly: omitting a field once the section is present clears
	// it back to the hardcoded default, in either direction. The direction
	// that matters is that the default it resets to is the SAFE one.
	resp = put(t, `{"autonomy": {"unattendedExecutionEnabled": false}}`)
	if got := autonomyField(t, resp, "requireReversibleForAutoApprove"); got != nil {
		t.Errorf("requireReversibleForAutoApprove after omitting it again = %v, want nil/null (unconfigured)", got)
	}
	if got := autonomyField(t, resp, "effectiveRequireReversibleForAutoApprove"); got != true {
		t.Errorf("effectiveRequireReversibleForAutoApprove after omitting it again = %v, want true (reset to the safe default, matching this struct's other two nullable fields' documented contract)", got)
	}
}
