package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"argus/internal/llm"
	"argus/internal/settings"
)

// TestPutSettingsRequestPointerSemantics is the DB-free unit test the task
// brief asked for explicitly: given raw JSON bodies, confirm decoding into
// putSettingsRequest produces the documented three-way distinction —
// section/field absent, section/field present as "", section/field present
// with a real value — with no database or HTTP server involved at all. This
// is exactly the ambiguity PUT /api/v1/admin/settings exists to resolve
// correctly (see putLLMSettingsRequest/putNotifySettingsRequest's doc
// comments): a UI that never saw the real secret back from GET must still
// be able to update baseUrl without accidentally clearing apiKey.
func TestPutSettingsRequestPointerSemantics(t *testing.T) {
	mustDecode := func(t *testing.T, body string) putSettingsRequest {
		var req putSettingsRequest
		if err := json.Unmarshal([]byte(body), &req); err != nil {
			t.Fatalf("unmarshal %q: %v", body, err)
		}
		return req
	}

	t.Run("llm section entirely absent leaves LLM nil", func(t *testing.T) {
		req := mustDecode(t, `{"notify": {"webhookUrl": "https://example.invalid/hook"}}`)
		if req.LLM != nil {
			t.Errorf("LLM = %+v, want nil (section was absent from the body)", req.LLM)
		}
		if req.Notify == nil || req.Notify.WebhookURL == nil || *req.Notify.WebhookURL != "https://example.invalid/hook" {
			t.Errorf("Notify = %+v, want webhookUrl set to the given URL", req.Notify)
		}
	})

	t.Run("apiKey absent from a present llm section means leave unchanged (nil)", func(t *testing.T) {
		req := mustDecode(t, `{"llm": {"baseUrl": "http://example.invalid/v1", "model": "m"}}`)
		if req.LLM == nil {
			t.Fatal("LLM = nil, want a present section")
		}
		if req.LLM.APIKey != nil {
			t.Errorf("APIKey = %v, want nil (absent from the JSON body means leave the stored key unchanged)", *req.LLM.APIKey)
		}
		if req.LLM.BaseURL != "http://example.invalid/v1" || req.LLM.Model != "m" {
			t.Errorf("BaseURL/Model = %q/%q, want the given values passed through", req.LLM.BaseURL, req.LLM.Model)
		}
	})

	t.Run("apiKey present as empty string means explicitly clear it", func(t *testing.T) {
		req := mustDecode(t, `{"llm": {"baseUrl": "http://example.invalid/v1", "model": "m", "apiKey": ""}}`)
		if req.LLM == nil || req.LLM.APIKey == nil {
			t.Fatalf("LLM = %+v, want a present, non-nil APIKey pointer", req.LLM)
		}
		if *req.LLM.APIKey != "" {
			t.Errorf("APIKey = %q, want empty string (explicit clear)", *req.LLM.APIKey)
		}
	})

	t.Run("apiKey present with a real value means set it", func(t *testing.T) {
		req := mustDecode(t, `{"llm": {"baseUrl": "http://example.invalid/v1", "model": "m", "apiKey": "sk-real-secret"}}`)
		if req.LLM == nil || req.LLM.APIKey == nil || *req.LLM.APIKey != "sk-real-secret" {
			t.Fatalf("LLM = %+v, want APIKey == \"sk-real-secret\"", req.LLM)
		}
	})

	t.Run("webhookUrl absent from a present notify section means leave unchanged (nil)", func(t *testing.T) {
		req := mustDecode(t, `{"notify": {}}`)
		if req.Notify == nil {
			t.Fatal("Notify = nil, want a present section")
		}
		if req.Notify.WebhookURL != nil {
			t.Errorf("WebhookURL = %v, want nil (absent means leave unchanged)", *req.Notify.WebhookURL)
		}
	})

	t.Run("webhookUrl present as empty string means explicitly clear it", func(t *testing.T) {
		req := mustDecode(t, `{"notify": {"webhookUrl": ""}}`)
		if req.Notify == nil || req.Notify.WebhookURL == nil {
			t.Fatalf("Notify = %+v, want a present, non-nil WebhookURL pointer", req.Notify)
		}
		if *req.Notify.WebhookURL != "" {
			t.Errorf("WebhookURL = %q, want empty string (explicit clear)", *req.Notify.WebhookURL)
		}
	})

	t.Run("all sections entirely absent leaves all nil", func(t *testing.T) {
		req := mustDecode(t, `{}`)
		if req.LLM != nil || req.Notify != nil || req.Analysis != nil {
			t.Errorf("req = %+v, want every section nil for an empty body", req)
		}
	})

	t.Run("analysis section absent leaves Analysis nil", func(t *testing.T) {
		req := mustDecode(t, `{"llm": {"baseUrl": "http://example.invalid/v1", "model": "m"}}`)
		if req.Analysis != nil {
			t.Errorf("Analysis = %+v, want nil (section was absent from the body)", req.Analysis)
		}
	})

	t.Run("analysis present with explicit numbers sets both fields", func(t *testing.T) {
		req := mustDecode(t, `{"analysis": {"maxIterations": 3, "timeLimitSeconds": 90}}`)
		if req.Analysis == nil || req.Analysis.MaxIterations == nil || *req.Analysis.MaxIterations != 3 {
			t.Fatalf("Analysis = %+v, want MaxIterations == 3", req.Analysis)
		}
		if req.Analysis.TimeLimitSeconds == nil || *req.Analysis.TimeLimitSeconds != 90 {
			t.Errorf("TimeLimitSeconds = %v, want 90", req.Analysis.TimeLimitSeconds)
		}
	})

	t.Run("analysis present with explicit nulls means clear both overrides", func(t *testing.T) {
		req := mustDecode(t, `{"analysis": {"maxIterations": null, "timeLimitSeconds": null}}`)
		if req.Analysis == nil {
			t.Fatal("Analysis = nil, want a present section")
		}
		if req.Analysis.MaxIterations != nil || req.Analysis.TimeLimitSeconds != nil {
			t.Errorf("Analysis = %+v, want both fields nil (explicit clear)", req.Analysis)
		}
	})

	t.Run("automation section absent leaves Automation nil", func(t *testing.T) {
		req := mustDecode(t, `{"llm": {"baseUrl": "http://example.invalid/v1", "model": "m"}}`)
		if req.Automation != nil {
			t.Errorf("Automation = %+v, want nil (section was absent from the body)", req.Automation)
		}
	})

	t.Run("automation present with a severities array decodes it verbatim", func(t *testing.T) {
		req := mustDecode(t, `{"automation": {"autoAnalysisEnabled": true, "autoAnalysisSeverities": ["high", "critical"]}}`)
		if req.Automation == nil {
			t.Fatal("Automation = nil, want a present section")
		}
		if !req.Automation.Enabled {
			t.Errorf("Enabled = false, want true")
		}
		if len(req.Automation.Severities) != 2 || req.Automation.Severities[0] != "high" || req.Automation.Severities[1] != "critical" {
			t.Errorf("Severities = %v, want [high critical]", req.Automation.Severities)
		}
	})

	t.Run("automation present with an empty severities array means nothing selected", func(t *testing.T) {
		req := mustDecode(t, `{"automation": {"autoAnalysisEnabled": true, "autoAnalysisSeverities": []}}`)
		if req.Automation == nil {
			t.Fatal("Automation = nil, want a present section")
		}
		if len(req.Automation.Severities) != 0 {
			t.Errorf("Severities = %v, want empty (nothing selected)", req.Automation.Severities)
		}
	})

	t.Run("automation present with severities key entirely absent decodes to a nil slice", func(t *testing.T) {
		req := mustDecode(t, `{"automation": {"autoAnalysisEnabled": false}}`)
		if req.Automation == nil {
			t.Fatal("Automation = nil, want a present section")
		}
		if req.Automation.Severities != nil {
			t.Errorf("Severities = %v, want nil", req.Automation.Severities)
		}
	})

	t.Run("retention section absent leaves Retention nil", func(t *testing.T) {
		req := mustDecode(t, `{"llm": {"baseUrl": "http://example.invalid/v1", "model": "m"}}`)
		if req.Retention != nil {
			t.Errorf("Retention = %+v, want nil (section was absent from the body)", req.Retention)
		}
	})

	t.Run("retention present with explicit numbers sets all three fields", func(t *testing.T) {
		req := mustDecode(t, `{"retention": {"auditRetentionDays": 365, "incidentRetentionDays": 180, "findingRetentionDays": 30}}`)
		if req.Retention == nil {
			t.Fatal("Retention = nil, want a present section")
		}
		if req.Retention.AuditRetentionDays == nil || *req.Retention.AuditRetentionDays != 365 {
			t.Errorf("AuditRetentionDays = %v, want 365", req.Retention.AuditRetentionDays)
		}
		if req.Retention.IncidentRetentionDays == nil || *req.Retention.IncidentRetentionDays != 180 {
			t.Errorf("IncidentRetentionDays = %v, want 180", req.Retention.IncidentRetentionDays)
		}
		if req.Retention.FindingRetentionDays == nil || *req.Retention.FindingRetentionDays != 30 {
			t.Errorf("FindingRetentionDays = %v, want 30", req.Retention.FindingRetentionDays)
		}
	})

	t.Run("retention present with explicit nulls means keep forever (clear all three)", func(t *testing.T) {
		req := mustDecode(t, `{"retention": {"auditRetentionDays": null, "incidentRetentionDays": null, "findingRetentionDays": null}}`)
		if req.Retention == nil {
			t.Fatal("Retention = nil, want a present section")
		}
		if req.Retention.AuditRetentionDays != nil || req.Retention.IncidentRetentionDays != nil || req.Retention.FindingRetentionDays != nil {
			t.Errorf("Retention = %+v, want all three fields nil (explicit clear back to keep-forever)", req.Retention)
		}
	})

	t.Run("detection section absent leaves Detection nil", func(t *testing.T) {
		req := mustDecode(t, `{"llm": {"baseUrl": "http://example.invalid/v1", "model": "m"}}`)
		if req.Detection != nil {
			t.Errorf("Detection = %+v, want nil (section was absent from the body)", req.Detection)
		}
	})

	t.Run("detection present with disabled ids and a storm-protection pair decodes verbatim", func(t *testing.T) {
		req := mustDecode(t, `{"detection": {"disabledDetectorIds": ["k8s-warning-events"], "stormProtectionMaxNewIncidents": 20, "stormProtectionWindowSeconds": 300}}`)
		if req.Detection == nil {
			t.Fatal("Detection = nil, want a present section")
		}
		if len(req.Detection.DisabledDetectorIDs) != 1 || req.Detection.DisabledDetectorIDs[0] != "k8s-warning-events" {
			t.Errorf("DisabledDetectorIDs = %v, want [k8s-warning-events]", req.Detection.DisabledDetectorIDs)
		}
		if req.Detection.StormProtectionMaxNewIncidents == nil || *req.Detection.StormProtectionMaxNewIncidents != 20 {
			t.Errorf("StormProtectionMaxNewIncidents = %v, want 20", req.Detection.StormProtectionMaxNewIncidents)
		}
		if req.Detection.StormProtectionWindowSeconds == nil || *req.Detection.StormProtectionWindowSeconds != 300 {
			t.Errorf("StormProtectionWindowSeconds = %v, want 300", req.Detection.StormProtectionWindowSeconds)
		}
	})

	t.Run("detection present with explicit nulls means no ceiling (clear both)", func(t *testing.T) {
		req := mustDecode(t, `{"detection": {"disabledDetectorIds": [], "stormProtectionMaxNewIncidents": null, "stormProtectionWindowSeconds": null}}`)
		if req.Detection == nil {
			t.Fatal("Detection = nil, want a present section")
		}
		if req.Detection.StormProtectionMaxNewIncidents != nil || req.Detection.StormProtectionWindowSeconds != nil {
			t.Errorf("Detection = %+v, want both storm-protection fields nil (explicit clear)", req.Detection)
		}
	})

	t.Run("autonomy section absent leaves Autonomy nil", func(t *testing.T) {
		req := mustDecode(t, `{"llm": {"baseUrl": "http://example.invalid/v1", "model": "m"}}`)
		if req.Autonomy != nil {
			t.Errorf("Autonomy = %+v, want nil (section was absent from the body)", req.Autonomy)
		}
	})

	t.Run("autonomy present with explicit values decodes verbatim", func(t *testing.T) {
		req := mustDecode(t, `{"autonomy": {"autoApproveMaxRisk": "medium", "minConfidenceForAutoApprove": 0.75, "requireReversibleForAutoApprove": false}}`)
		if req.Autonomy == nil {
			t.Fatal("Autonomy = nil, want a present section")
		}
		if req.Autonomy.AutoApproveMaxRisk == nil || *req.Autonomy.AutoApproveMaxRisk != "medium" {
			t.Errorf("AutoApproveMaxRisk = %v, want \"medium\"", req.Autonomy.AutoApproveMaxRisk)
		}
		if req.Autonomy.MinConfidenceForAutoApprove == nil || *req.Autonomy.MinConfidenceForAutoApprove != 0.75 {
			t.Errorf("MinConfidenceForAutoApprove = %v, want 0.75", req.Autonomy.MinConfidenceForAutoApprove)
		}
		if req.Autonomy.RequireReversibleForAutoApprove == nil || *req.Autonomy.RequireReversibleForAutoApprove {
			t.Errorf("RequireReversibleForAutoApprove = %v, want false", req.Autonomy.RequireReversibleForAutoApprove)
		}
	})

	t.Run("autonomy present with explicit nulls means clear all three nullable overrides", func(t *testing.T) {
		req := mustDecode(t, `{"autonomy": {"autoApproveMaxRisk": null, "minConfidenceForAutoApprove": null, "requireReversibleForAutoApprove": null}}`)
		if req.Autonomy == nil {
			t.Fatal("Autonomy = nil, want a present section")
		}
		if req.Autonomy.AutoApproveMaxRisk != nil || req.Autonomy.MinConfidenceForAutoApprove != nil || req.Autonomy.RequireReversibleForAutoApprove != nil {
			t.Errorf("Autonomy = %+v, want all three nullable fields nil (explicit clear back to the hardcoded default)", req.Autonomy)
		}
	})

	// BUGS.md 97's regression test at the decode layer: before migration
	// 000085, requireReversibleForAutoApprove was a plain bool on
	// putAutonomySettingsRequest, so a request that included "autonomy" but
	// simply omitted the key decoded to Go's zero value, false — silently
	// weakening the guardrail with nothing in the request that said so. Now
	// it's a *bool like its siblings, so an omitted key decodes to nil, the
	// same "not configured, fall back to the safe default" state an
	// explicit null produces.
	t.Run("autonomy present but requireReversibleForAutoApprove omitted decodes to nil, not false", func(t *testing.T) {
		req := mustDecode(t, `{"autonomy": {"unattendedExecutionEnabled": true, "unattendedNamespaces": ["argus-e9-test-8"]}}`)
		if req.Autonomy == nil {
			t.Fatal("Autonomy = nil, want a present section")
		}
		if req.Autonomy.RequireReversibleForAutoApprove != nil {
			t.Errorf("RequireReversibleForAutoApprove = %v, want nil (key omitted from the request body, not explicitly set to false)", *req.Autonomy.RequireReversibleForAutoApprove)
		}
	})
}

// TestValidateAutonomySettingsRequest exercises the autonomy-section
// validation rules directly — no database needed since every case is
// rejected before settings.Update is ever called. Mirrors
// TestValidateDetectionSettingsRequest's shape. Every case here is a
// deliberately PERMISSIVE-LOOKING input (the most permissive risk ceiling,
// the lowest confidence floor, reversibility not required) that this
// function's job is only to accept or reject on FORMAT, never on whether it
// would weaken internal/remediation.Evaluate's hard safety floor — that
// floor is untouched by anything this file validates, since it runs inside
// Evaluate unconditionally, before any AutonomyPolicy field is consulted
// (see TestOrchestratorResolveAutonomyPolicyCannotWeakenSafetyFloor in
// internal/orchestrator for the test that actually proves that end-to-end).
func TestValidateAutonomySettingsRequest(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"unknown risk level rejected", `{"autonomy":{"autoApproveMaxRisk":"critical"}}`, true},
		{"empty-string risk level rejected", `{"autonomy":{"autoApproveMaxRisk":""}}`, true},
		{"forbidden tier rejected (not modeled by internal/remediation.RiskLevel)", `{"autonomy":{"autoApproveMaxRisk":"forbidden"}}`, true},
		{"known risk levels accepted", `{"autonomy":{"autoApproveMaxRisk":"high"}}`, false},
		{"null risk level accepted (clears to the hardcoded default)", `{"autonomy":{"autoApproveMaxRisk":null}}`, false},
		{"confidence below 0 rejected", `{"autonomy":{"minConfidenceForAutoApprove":-0.01}}`, true},
		{"confidence above 1 rejected", `{"autonomy":{"minConfidenceForAutoApprove":1.01}}`, true},
		{"confidence of exactly 0 accepted (the most permissive valid value)", `{"autonomy":{"minConfidenceForAutoApprove":0}}`, false},
		{"confidence of exactly 1 accepted", `{"autonomy":{"minConfidenceForAutoApprove":1}}`, false},
		{"null confidence accepted (clears to the hardcoded default)", `{"autonomy":{"minConfidenceForAutoApprove":null}}`, false},
		{"requireReversibleForAutoApprove false accepted (a plain bool, nothing to validate)", `{"autonomy":{"requireReversibleForAutoApprove":false}}`, false},
		{"the most permissive-looking combination is still accepted on format alone", `{"autonomy":{"autoApproveMaxRisk":"high","minConfidenceForAutoApprove":0,"requireReversibleForAutoApprove":false}}`, false},

		// The blast-radius caps (migration 000046). Zero is the case that
		// matters: it is the number an operator types meaning "never", and
		// orchestrator.ResolveUnattendedLimits reads any non-positive value as
		// "unconfigured, use the default" — so accepting it would silently turn
		// "never" into 3. This is the only layer that can tell the two apart.
		{"zero per-cluster cap rejected (would silently become the default)", `{"autonomy":{"maxUnattendedPerCluster":0}}`, true},
		{"zero fleet-wide cap rejected", `{"autonomy":{"maxUnattendedFleetWide":0}}`, true},
		{"zero window rejected", `{"autonomy":{"unattendedWindowSeconds":0}}`, true},
		{"negative per-cluster cap rejected", `{"autonomy":{"maxUnattendedPerCluster":-1}}`, true},
		{"null caps accepted (fall back to the conservative defaults)", `{"autonomy":{"maxUnattendedPerCluster":null,"maxUnattendedFleetWide":null,"unattendedWindowSeconds":null}}`, false},
		{"a coherent explicit cap set accepted", `{"autonomy":{"unattendedExecutionEnabled":true,"maxUnattendedPerCluster":2,"maxUnattendedFleetWide":8,"unattendedWindowSeconds":1800}}`, false},
		{"per-cluster equal to fleet-wide accepted (reachable, if only by one cluster)", `{"autonomy":{"maxUnattendedPerCluster":5,"maxUnattendedFleetWide":5}}`, false},

		// An unreachable cap is refused rather than accepted and ignored. Both
		// forms are checked, because the resolved comparison is what catches the
		// second — and the second is the likelier mistake, since leaving the
		// fleet field blank looks like leaving it unconstrained.
		{"per-cluster above an explicit fleet-wide cap rejected", `{"autonomy":{"maxUnattendedPerCluster":20,"maxUnattendedFleetWide":10}}`, true},
		{"per-cluster above the DEFAULT fleet-wide cap rejected too", `{"autonomy":{"maxUnattendedPerCluster":20}}`, true},
		{"raising both together accepted", `{"autonomy":{"maxUnattendedPerCluster":20,"maxUnattendedFleetWide":50}}`, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var req putSettingsRequest
			if err := json.Unmarshal([]byte(c.body), &req); err != nil {
				t.Fatalf("unmarshal %q: %v", c.body, err)
			}
			err := validateAutonomySettingsRequest(req.Autonomy)
			if c.wantErr && err == nil {
				t.Errorf("validateAutonomySettingsRequest(%+v) = nil error, want a validation error", req.Autonomy)
			}
			if !c.wantErr && err != nil {
				t.Errorf("validateAutonomySettingsRequest(%+v) = %v, want no error", req.Autonomy, err)
			}
		})
	}
}

// TestValidateCostSettingsRequest exercises validateCostSettingsRequest's
// documented rules directly: the all-or-nothing price-field set, each
// price's zero-or-positive floor, and the ceiling's strictly-positive
// floor.
func TestValidateCostSettingsRequest(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"all three prices null accepted (no pricing configured)", `{"cost":{}}`, false},
		{"all three prices set accepted", `{"cost":{"pricePerMillionInputTokens":2,"pricePerMillionCachedTokens":0.2,"pricePerMillionOutputTokens":10}}`, false},
		{"only input set rejected (partial price table)", `{"cost":{"pricePerMillionInputTokens":2}}`, true},
		{"input and cached set, output missing, rejected", `{"cost":{"pricePerMillionInputTokens":2,"pricePerMillionCachedTokens":0.2}}`, true},
		{"negative input price rejected", `{"cost":{"pricePerMillionInputTokens":-1,"pricePerMillionCachedTokens":0,"pricePerMillionOutputTokens":0}}`, true},
		{"zero prices accepted (a real, valid free price)", `{"cost":{"pricePerMillionInputTokens":0,"pricePerMillionCachedTokens":0,"pricePerMillionOutputTokens":0}}`, false},
		{"positive ceiling accepted", `{"cost":{"dailySpendCeilingUsd":10}}`, false},
		{"null ceiling accepted (disables the ceiling)", `{"cost":{"dailySpendCeilingUsd":null}}`, false},
		{"zero ceiling rejected", `{"cost":{"dailySpendCeilingUsd":0}}`, true},
		{"negative ceiling rejected", `{"cost":{"dailySpendCeilingUsd":-5}}`, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var req putSettingsRequest
			if err := json.Unmarshal([]byte(c.body), &req); err != nil {
				t.Fatalf("unmarshal %q: %v", c.body, err)
			}
			err := validateCostSettingsRequest(req.Cost)
			if c.wantErr && err == nil {
				t.Errorf("validateCostSettingsRequest(%+v) = nil error, want a validation error", req.Cost)
			}
			if !c.wantErr && err != nil {
				t.Errorf("validateCostSettingsRequest(%+v) = %v, want no error", req.Cost, err)
			}
		})
	}
}

// TestSettingsResponseFromConfigCostPricingConfigured pins
// costSettingsView.PricingConfigured's derivation from
// settings.Config.CostPricingConfigured() — true only once all three price
// fields are set, mirroring the equivalent effective-value tests above for
// analysis/autonomy.
func TestSettingsResponseFromConfigCostPricingConfigured(t *testing.T) {
	t.Run("unconfigured: false, all null", func(t *testing.T) {
		resp := settingsResponseFromConfig(settings.Config{}, false)
		if resp.Cost.PricingConfigured {
			t.Errorf("PricingConfigured = true, want false when no price field is set")
		}
		if resp.Cost.PricePerMillionInputTokens != nil || resp.Cost.PricePerMillionCachedTokens != nil || resp.Cost.PricePerMillionOutputTokens != nil {
			t.Errorf("expected all three price fields nil, got %+v", resp.Cost)
		}
	})

	t.Run("configured: true, real values echoed back", func(t *testing.T) {
		in, cached, out, ceiling := 2.0, 0.2, 10.0, 25.0
		cfg := settings.Config{
			PricePerMillionInputTokens:  &in,
			PricePerMillionCachedTokens: &cached,
			PricePerMillionOutputTokens: &out,
			DailySpendCeilingUsd:        &ceiling,
		}
		resp := settingsResponseFromConfig(cfg, false)
		if !resp.Cost.PricingConfigured {
			t.Errorf("PricingConfigured = false, want true when all three price fields are set")
		}
		if resp.Cost.PricePerMillionInputTokens == nil || *resp.Cost.PricePerMillionInputTokens != 2.0 {
			t.Errorf("PricePerMillionInputTokens = %v, want 2.0", resp.Cost.PricePerMillionInputTokens)
		}
		if resp.Cost.DailySpendCeilingUsd == nil || *resp.Cost.DailySpendCeilingUsd != 25.0 {
			t.Errorf("DailySpendCeilingUsd = %v, want 25.0", resp.Cost.DailySpendCeilingUsd)
		}
	})
}

// TestHandlePutSettingsDetectionValidation exercises the detection-section
// validation rules directly against handlePutSettings' own logic — no
// database needed since every case is rejected before settings.Update is
// ever called. Mirrors this file's existing "reject up front with a clear
// 400" checks for analysis/automation/retention, applied to detection's two
// new rules: unknown/duplicate detector IDs, and a mismatched
// storm-protection pair.
func TestValidateDetectionSettingsRequest(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"unknown detector id rejected", `{"detection":{"disabledDetectorIds":["not-a-real-detector"]}}`, true},
		{"duplicate detector id rejected", `{"detection":{"disabledDetectorIds":["k8s-warning-events","k8s-warning-events"]}}`, true},
		{"known detector ids accepted", `{"detection":{"disabledDetectorIds":["k8s-warning-events","k8s-pod-conditions"]}}`, false},
		// BUGS.md 83: the sweep detector (internal/agent/sweep_detector.go's
		// sweepDetectorID) had no valid settings ID at all, so an operator
		// could not disable it the way the other two detectors already could
		// be. k8s-sweep alone, and alongside the other two, must both be
		// accepted now that knownDetectorIDs and migration 000066's widened
		// CHECK constraint both admit it — and a still-unknown third value
		// must still be rejected, not accidentally let through by a
		// too-loose fix.
		{"sweep detector id accepted alone", `{"detection":{"disabledDetectorIds":["k8s-sweep"]}}`, false},
		{"sweep detector id accepted alongside the other two", `{"detection":{"disabledDetectorIds":["k8s-warning-events","k8s-pod-conditions","k8s-sweep"]}}`, false},
		{"an unrelated third id is still rejected", `{"detection":{"disabledDetectorIds":["k8s-sweep","still-not-a-real-detector"]}}`, true},
		{"max set without window rejected", `{"detection":{"stormProtectionMaxNewIncidents":20}}`, true},
		{"window set without max rejected", `{"detection":{"stormProtectionWindowSeconds":300}}`, true},
		{"both set together accepted", `{"detection":{"stormProtectionMaxNewIncidents":20,"stormProtectionWindowSeconds":300}}`, false},
		{"both null accepted (disable storm protection)", `{"detection":{"stormProtectionMaxNewIncidents":null,"stormProtectionWindowSeconds":null}}`, false},
		{"non-positive max rejected", `{"detection":{"stormProtectionMaxNewIncidents":0,"stormProtectionWindowSeconds":300}}`, true},
		{"non-positive window rejected", `{"detection":{"stormProtectionMaxNewIncidents":20,"stormProtectionWindowSeconds":0}}`, true},

		// BUGS.md 111: disabledRuleIds is the new rule-level control, validated
		// against knownRuleIDs the same way disabledDetectorIds is validated
		// against knownDetectorIDs above — unknown/duplicate rejected, known
		// ones (including several sharing the same shared "k8s-sweep"
		// DetectorID) accepted, and a mix of valid detector ids AND valid rule
		// ids in the same request accepted, since the two sets are unrelated.
		{"unknown rule id rejected", `{"detection":{"disabledRuleIds":["not-a-real-rule"]}}`, true},
		{"duplicate rule id rejected", `{"detection":{"disabledRuleIds":["pdb-blocks-all-disruptions","pdb-blocks-all-disruptions"]}}`, true},
		{"known rule id accepted alone", `{"detection":{"disabledRuleIds":["pdb-blocks-all-disruptions"]}}`, false},
		{"known rule ids accepted together", `{"detection":{"disabledRuleIds":["pdb-blocks-all-disruptions","hpa-pegged-at-max-replicas"]}}`, false},
		{"a still-unknown rule id alongside a known one is rejected", `{"detection":{"disabledRuleIds":["pdb-blocks-all-disruptions","not-a-real-rule"]}}`, true},
		{"detector ids and rule ids together accepted", `{"detection":{"disabledDetectorIds":["k8s-sweep"],"disabledRuleIds":["pdb-blocks-all-disruptions"]}}`, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var req putSettingsRequest
			if err := json.Unmarshal([]byte(c.body), &req); err != nil {
				t.Fatalf("unmarshal %q: %v", c.body, err)
			}
			err := validateDetectionSettingsRequest(req.Detection)
			if c.wantErr && err == nil {
				t.Errorf("validateDetectionSettingsRequest(%+v) = nil error, want a validation error", req.Detection)
			}
			if !c.wantErr && err != nil {
				t.Errorf("validateDetectionSettingsRequest(%+v) = %v, want no error", req.Detection, err)
			}
		})
	}
}

// TestSettingsResponseFromConfigNeverLeaksSecrets is a second belt-and-
// suspenders check, pure and DB-free: given a settings.Config carrying real
// secret VALUES, the response type built from it exposes only the two
// documented booleans, never the underlying strings — the field names on
// llmSettingsView/notifySettingsView are the only thing that could
// accidentally regress this, so this test locks the shape, not just the
// booleans' correctness.
func TestSettingsResponseFromConfigNeverLeaksSecrets(t *testing.T) {
	cfg := settings.Config{
		LLMBaseURL:              "http://real-base/v1",
		LLMModel:                "real-model",
		LLMAPIKey:               "sk-super-secret",
		LLMAPIKeySet:            true,
		NotifyWebhookURL:        "https://hooks.slack.com/services/T0/B0/reallysecrettoken",
		NotifyWebhookConfigured: true,
		// The CLI backend's own secret (migration 000033) gets the same
		// treatment as the two above: a real value in, only a boolean out.
		CLIRunnerURL:      "http://argus-cli-runner:8090",
		CLIRunnerToken:    "runner-token-also-super-secret",
		CLIRunnerTokenSet: true,
		CLIAgent:          "claude",
	}
	resp := settingsResponseFromConfig(cfg, false)

	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	// Every secret value from cfg above, asserted absent from the serialized
	// response by value rather than only by comparing against `want` — a
	// newly-added leaky field would otherwise only be caught if someone
	// remembered to update the golden string.
	for _, secret := range []string{"sk-super-secret", "reallysecrettoken", "runner-token-also-super-secret"} {
		if strings.Contains(string(body), secret) {
			t.Errorf("response JSON leaked secret %q: %s", secret, body)
		}
	}
	// providerKind is "api" though cfg left it empty — settingsResponseFromConfig
	// normalizes it, so a client never has to interpret "".
	want := `{"llm":{"baseUrl":"http://real-base/v1","model":"real-model","apiKeySet":true,"providerKind":"api","cliRunnerUrl":"http://argus-cli-runner:8090","cliAgent":"claude","cliRunnerTokenSet":true,"cliBackendAvailable":false},"notify":{"webhookConfigured":true},` +
		`"analysis":{"maxIterations":null,"timeLimitSeconds":null,"effectiveMaxIterations":8,"effectiveTimeLimitSeconds":180,"retrievalEnabled":false},` +
		`"automation":{"autoAnalysisEnabled":false,"autoAnalysisSeverities":[]},` +
		`"retention":{"auditRetentionDays":null,"incidentRetentionDays":null,"findingRetentionDays":null},` +
		`"detection":{"disabledDetectorIds":[],"stormProtectionMaxNewIncidents":null,"stormProtectionWindowSeconds":null,"disabledRuleIds":[]},` +
		`"autonomy":{"autoApproveMaxRisk":null,"minConfidenceForAutoApprove":null,"requireReversibleForAutoApprove":null,"unattendedExecutionEnabled":false,"maxUnattendedPerCluster":null,"maxUnattendedFleetWide":null,"unattendedWindowSeconds":null,"unattendedNamespaces":[],"effectiveMaxUnattendedPerCluster":3,"effectiveMaxUnattendedFleetWide":10,"effectiveUnattendedWindowSeconds":3600,"effectiveAutoApproveMaxRisk":"low","effectiveMinConfidenceForAutoApprove":0.9,"effectiveRequireReversibleForAutoApprove":true},` +
		`"cost":{"pricePerMillionInputTokens":null,"pricePerMillionCachedTokens":null,"pricePerMillionOutputTokens":null,"pricingConfigured":false,"spendCountable":true,"dailySpendCeilingUsd":null,"ceilingEnforceable":false,"todaySpendUsd":0,"ceilingBreached":false},` +
		`"appearance":{"loginStyle":"aperture","styles":["aperture","sentinel"],"primaryColorId":"teal","primaryColorOptions":["teal","blue","violet","slate","forest"],"overviewDefaultWindowDays":14},` +
		`"general":{"minPasswordLength":0,"sessionIdleTimeoutMinutes":null},` +
		// The egress allowlist section. Empty, and rendered as [] rather
		// than null — an operator client must never have to tell "no
		// exceptions configured" apart from "this field is missing".
		`"outbound":{"privateDestinations":[]},` +
		`"posture":{"disabledChecks":[],"ignoredNamespaces":[]}}`
	if string(body) != want {
		t.Errorf("response JSON = %s, want exactly the documented shape with no secret values:\n%s", body, want)
	}
}

// TestSettingsResponseFromConfigAnalysisEffectiveValue confirms
// analysisSettingsView's two pairs of fields: MaxIterations/TimeLimitSeconds
// mirror Config's raw (nil-if-unconfigured) pointers verbatim, while
// EffectiveMaxIterations/EffectiveTimeLimitSeconds are always a concrete
// number — the resolved override when one is configured, else
// internal/llm's own DefaultMaxIterations/DefaultTimeLimit.
func TestSettingsResponseFromConfigAnalysisEffectiveValue(t *testing.T) {
	t.Run("unconfigured: null with the hardcoded default as effective", func(t *testing.T) {
		resp := settingsResponseFromConfig(settings.Config{}, false)
		if resp.Analysis.MaxIterations != nil || resp.Analysis.TimeLimitSeconds != nil {
			t.Errorf("Analysis = %+v, want both raw fields nil", resp.Analysis)
		}
		if resp.Analysis.EffectiveMaxIterations != 8 || resp.Analysis.EffectiveTimeLimitSeconds != 180 {
			t.Errorf("Effective* = (%d, %d), want the documented defaults (8, 180)",
				resp.Analysis.EffectiveMaxIterations, resp.Analysis.EffectiveTimeLimitSeconds)
		}
	})

	t.Run("configured: echoed back verbatim as both raw and effective", func(t *testing.T) {
		maxIter, timeLimit := 3, 90
		resp := settingsResponseFromConfig(settings.Config{
			AnalysisMaxIterations:    &maxIter,
			AnalysisTimeLimitSeconds: &timeLimit,
		}, false)
		if resp.Analysis.MaxIterations == nil || *resp.Analysis.MaxIterations != 3 {
			t.Errorf("MaxIterations = %v, want 3", resp.Analysis.MaxIterations)
		}
		if resp.Analysis.EffectiveMaxIterations != 3 {
			t.Errorf("EffectiveMaxIterations = %d, want 3", resp.Analysis.EffectiveMaxIterations)
		}
		if resp.Analysis.TimeLimitSeconds == nil || *resp.Analysis.TimeLimitSeconds != 90 {
			t.Errorf("TimeLimitSeconds = %v, want 90", resp.Analysis.TimeLimitSeconds)
		}
		if resp.Analysis.EffectiveTimeLimitSeconds != 90 {
			t.Errorf("EffectiveTimeLimitSeconds = %d, want 90", resp.Analysis.EffectiveTimeLimitSeconds)
		}
	})
}

// TestSettingsResponseFromConfigAutomationSeverities confirms
// automationSettingsView's AutoAnalysisSeverities: Config's raw value is
// echoed back verbatim when non-empty, and — the one normalization
// settingsResponseFromConfig applies to this field — a nil Config value
// becomes an empty JSON array `[]`, never a JSON `null`, so a client never
// has to special-case null vs. empty for this field (see
// automationSettingsView's doc comment).
func TestSettingsResponseFromConfigAutomationSeverities(t *testing.T) {
	t.Run("nil Config severities becomes an empty (non-null) array on the wire", func(t *testing.T) {
		resp := settingsResponseFromConfig(settings.Config{AutoAnalysisEnabled: true, AutoAnalysisSeverities: nil}, false)
		if resp.Automation.AutoAnalysisSeverities == nil {
			t.Fatal("AutoAnalysisSeverities = nil, want a non-nil empty slice (marshals to [], not null)")
		}
		if len(resp.Automation.AutoAnalysisSeverities) != 0 {
			t.Errorf("AutoAnalysisSeverities = %v, want empty", resp.Automation.AutoAnalysisSeverities)
		}
		body, err := json.Marshal(resp.Automation)
		if err != nil {
			t.Fatalf("marshal automation view: %v", err)
		}
		want := `{"autoAnalysisEnabled":true,"autoAnalysisSeverities":[]}`
		if string(body) != want {
			t.Errorf("automation JSON = %s, want %s", body, want)
		}
	})

	t.Run("a real, non-empty set is echoed back verbatim", func(t *testing.T) {
		resp := settingsResponseFromConfig(settings.Config{
			AutoAnalysisEnabled:    true,
			AutoAnalysisSeverities: []string{"high", "critical"},
		}, false)
		if len(resp.Automation.AutoAnalysisSeverities) != 2 ||
			resp.Automation.AutoAnalysisSeverities[0] != "high" ||
			resp.Automation.AutoAnalysisSeverities[1] != "critical" {
			t.Errorf("AutoAnalysisSeverities = %v, want [high critical]", resp.Automation.AutoAnalysisSeverities)
		}
	})
}

// TestSettingsResponseFromConfigAutonomyEffectiveValue mirrors
// TestSettingsResponseFromConfigAnalysisEffectiveValue exactly, applied to
// autonomySettingsView's Effective* pair: unconfigured (nil) DB fields
// resolve to internal/orchestrator.DefaultAutonomyPolicy's own conservative
// values, never to "never auto-approve" — the one thing that would make
// this section's null different from every null-means-off field elsewhere
// in this response.
func TestSettingsResponseFromConfigAutonomyEffectiveValue(t *testing.T) {
	t.Run("unconfigured: raw fields nil, effective fields fall back to DefaultAutonomyPolicy", func(t *testing.T) {
		resp := settingsResponseFromConfig(settings.Config{}, false)
		if resp.Autonomy.AutoApproveMaxRisk != nil || resp.Autonomy.MinConfidenceForAutoApprove != nil || resp.Autonomy.RequireReversibleForAutoApprove != nil {
			t.Errorf("Autonomy = %+v, want all three raw nullable fields nil", resp.Autonomy)
		}
		if resp.Autonomy.EffectiveAutoApproveMaxRisk != "low" {
			t.Errorf("EffectiveAutoApproveMaxRisk = %q, want the documented default \"low\"", resp.Autonomy.EffectiveAutoApproveMaxRisk)
		}
		if resp.Autonomy.EffectiveMinConfidenceForAutoApprove != 0.90 {
			t.Errorf("EffectiveMinConfidenceForAutoApprove = %v, want the documented default 0.90", resp.Autonomy.EffectiveMinConfidenceForAutoApprove)
		}
		// BUGS.md 97's fix, pinned at the response layer: an unconfigured
		// RequireReversibleForAutoApprove now resolves to the DEFAULT's
		// true, matching its two siblings, rather than a plain-bool zero
		// value that would render as false with no indication it was ever
		// unconfigured.
		if !resp.Autonomy.EffectiveRequireReversibleForAutoApprove {
			t.Errorf("EffectiveRequireReversibleForAutoApprove = false, want the documented default true")
		}
	})

	t.Run("configured: echoed back verbatim as both raw and effective", func(t *testing.T) {
		risk := "high"
		conf := 0.5
		requireReversible := false
		resp := settingsResponseFromConfig(settings.Config{
			AutonomyAutoApproveMaxRisk:              &risk,
			AutonomyMinConfidenceForAutoApprove:     &conf,
			AutonomyRequireReversibleForAutoApprove: &requireReversible,
		}, false)
		if resp.Autonomy.AutoApproveMaxRisk == nil || *resp.Autonomy.AutoApproveMaxRisk != "high" {
			t.Errorf("AutoApproveMaxRisk = %v, want \"high\"", resp.Autonomy.AutoApproveMaxRisk)
		}
		if resp.Autonomy.EffectiveAutoApproveMaxRisk != "high" {
			t.Errorf("EffectiveAutoApproveMaxRisk = %q, want \"high\"", resp.Autonomy.EffectiveAutoApproveMaxRisk)
		}
		if resp.Autonomy.MinConfidenceForAutoApprove == nil || *resp.Autonomy.MinConfidenceForAutoApprove != 0.5 {
			t.Errorf("MinConfidenceForAutoApprove = %v, want 0.5", resp.Autonomy.MinConfidenceForAutoApprove)
		}
		if resp.Autonomy.EffectiveMinConfidenceForAutoApprove != 0.5 {
			t.Errorf("EffectiveMinConfidenceForAutoApprove = %v, want 0.5", resp.Autonomy.EffectiveMinConfidenceForAutoApprove)
		}
		if resp.Autonomy.RequireReversibleForAutoApprove == nil || *resp.Autonomy.RequireReversibleForAutoApprove {
			t.Errorf("RequireReversibleForAutoApprove = %v, want false", resp.Autonomy.RequireReversibleForAutoApprove)
		}
		if resp.Autonomy.EffectiveRequireReversibleForAutoApprove {
			t.Errorf("EffectiveRequireReversibleForAutoApprove = true, want false (explicit DB override)")
		}
	})
}

// cliBackendAvailable drives a UI warning, so its fail-safe direction matters:
// an investigator that cannot answer must read as "unavailable" (warn) rather
// than "available" (stay silent about a real misconfiguration).
func TestCLIBackendAvailableFailsToWarning(t *testing.T) {
	// A provider that does not implement the reporter — every test fake, and
	// any future backend that forgets the method.
	s := &Server{llmProvider: noopInvestigator{}}
	if s.cliBackendAvailable() {
		t.Error("an investigator that cannot report availability was treated as available; the safe default is false, so the UI warns")
	}

	s = &Server{llmProvider: cliReporterStub{available: true}}
	if !s.cliBackendAvailable() {
		t.Error("a reporter saying the CLI backend IS wired was not believed")
	}
	s = &Server{llmProvider: cliReporterStub{available: false}}
	if s.cliBackendAvailable() {
		t.Error("a reporter saying the CLI backend is NOT wired was not believed")
	}
}

// noopInvestigator satisfies llm.Investigator and nothing else — standing in
// for every backend and test fake that does not report availability.
type noopInvestigator struct{}

func (noopInvestigator) Investigate(context.Context, llm.Target, string, string, llm.ToolCallback) (llm.Investigation, error) {
	return llm.Investigation{}, nil
}

type cliReporterStub struct {
	noopInvestigator
	available bool
}

func (c cliReporterStub) CLIBackendAvailable() bool { return c.available }

// TestValidateOutboundSettingsRequest is the API edge of the operator
// allowlist of private outbound destinations (migration 000115, owner
// decision 2026-09-19). It asserts the handler rejects exactly what the dial
// path would refuse, which it achieves by delegating to the dial path's own
// parser rather than restating the rules — so these cases double as a
// statement of what an operator may and may not enter.
func TestValidateOutboundSettingsRequest(t *testing.T) {
	if err := validateOutboundSettingsRequest(nil); err != nil {
		t.Errorf("an absent section must be valid, got: %v", err)
	}
	if err := validateOutboundSettingsRequest(&putOutboundSettingsRequest{}); err != nil {
		t.Errorf("an empty list (every exception removed) must be valid, got: %v", err)
	}

	valid := &putOutboundSettingsRequest{PrivateDestinations: []putOutboundPrivateDestination{
		{Destination: "10.20.0.0/16", Reason: "self-hosted vLLM subnet"},
		{Destination: "ghe.internal.example.test", Reason: "internal GitHub Enterprise"},
		{Destination: "192.168.4.9", Reason: "build cache"},
	}}
	if err := validateOutboundSettingsRequest(valid); err != nil {
		t.Errorf("a well-formed allowlist must be accepted, got: %v", err)
	}

	for _, tc := range []struct {
		name string
		req  *putOutboundSettingsRequest
	}{
		{"cloud metadata address", &putOutboundSettingsRequest{PrivateDestinations: []putOutboundPrivateDestination{{Destination: "169.254.169.254", Reason: "operator insists"}}}},
		{"cloud metadata hostname", &putOutboundSettingsRequest{PrivateDestinations: []putOutboundPrivateDestination{{Destination: "metadata.google.internal", Reason: "operator insists"}}}},
		{"range containing cloud metadata", &putOutboundSettingsRequest{PrivateDestinations: []putOutboundPrivateDestination{{Destination: "169.254.0.0/16", Reason: "link-local"}}}},
		{"everything", &putOutboundSettingsRequest{PrivateDestinations: []putOutboundPrivateDestination{{Destination: "0.0.0.0/0", Reason: "just let it through"}}}},
		{"a public address", &putOutboundSettingsRequest{PrivateDestinations: []putOutboundPrivateDestination{{Destination: "8.8.8.8", Reason: "dns"}}}},
		{"no reason", &putOutboundSettingsRequest{PrivateDestinations: []putOutboundPrivateDestination{{Destination: "10.0.0.1"}}}},
		{"a pasted URL", &putOutboundSettingsRequest{PrivateDestinations: []putOutboundPrivateDestination{{Destination: "https://ghe.internal.example.test/api/v3", Reason: "ghes"}}}},
		{"a duplicate", &putOutboundSettingsRequest{PrivateDestinations: []putOutboundPrivateDestination{
			{Destination: "10.0.0.1", Reason: "a"},
			{Destination: "10.0.0.1", Reason: "b"},
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateOutboundSettingsRequest(tc.req); err == nil {
				t.Fatal("expected a 400-worthy validation error, got nil")
			}
		})
	}
}

// TestOutboundAuditDestinations distinguishes the three states an audit
// reader has to tell apart: the section was not touched, it was cleared to
// nothing, and it was set to something.
func TestOutboundAuditDestinations(t *testing.T) {
	if got := outboundAuditDestinations(nil); got != nil {
		t.Errorf("an absent section must record nil, got %#v", got)
	}
	if got := outboundAuditDestinations(&putOutboundSettingsRequest{}); got == nil || len(got) != 0 {
		t.Errorf("a cleared list must record an empty list, not nil, got %#v", got)
	}
	got := outboundAuditDestinations(&putOutboundSettingsRequest{PrivateDestinations: []putOutboundPrivateDestination{
		{Destination: "10.20.0.0/16", Reason: "self-hosted vLLM subnet"},
	}})
	if len(got) != 1 || got[0] != "10.20.0.0/16" {
		t.Errorf("audit destinations = %#v, want the one destination", got)
	}
	// The reason is deliberately not duplicated into the audit row — it
	// lives on org_settings and on the settings screen.
	for _, d := range got {
		if strings.Contains(d, "vLLM") {
			t.Errorf("audit destinations carried the free-text reason: %#v", got)
		}
	}
}
