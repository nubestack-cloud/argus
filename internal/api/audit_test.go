package api

import (
	"strings"
	"testing"
)

// TestSummarizeDetailsNestedValue locks in the fix for a real, user-reported
// bug: a live GET /api/v1/audit-events call showed detailsSummary rendering
// as "...initialGrantScope=map[type:AllClusters]" — Go's own fmt "%v" debug
// syntax for a map, leaking straight into user-facing text. That happens
// because `details` has round-tripped through json.Unmarshal into
// map[string]any by the time summarizeDetails sees it (scanAuditEventSummary/
// handleGetAuditEvent), so any value that started life as a nested struct or
// map (handleCreateUser's "initialGrantScope": authz.Scope{...},
// handleCreateGrant's "scope": req.Scope) comes back as a nested
// map[string]any, not a string — exactly reproduced here without a database,
// since summarizeDetails/formatDetailValue are pure functions.
func TestSummarizeDetailsNestedValue(t *testing.T) {
	details := map[string]any{
		"action":            "create_user",
		"createdUserId":     "usr_01m0ea13v10at9mcb270g2agtr",
		"email":             "operator@example.org",
		"initialGrantRole":  "viewer",
		"initialGrantScope": map[string]any{"type": "AllClusters"},
	}

	got := summarizeDetails(nil, details)

	if want := "map[type:AllClusters]"; strings.Contains(got, want) {
		t.Errorf("summarizeDetails(%+v) = %q, still leaks Go's map debug syntax %q", details, got, want)
	}
	if want := `initialGrantScope={"type":"AllClusters"}`; !strings.Contains(got, want) {
		t.Errorf("summarizeDetails(%+v) = %q, want it to contain %q", details, got, want)
	}
	if want := "Create User"; !strings.Contains(got, want) {
		t.Errorf("summarizeDetails(%+v) = %q, want it to contain humanized action %q", details, got, want)
	}
	// Scalars stay exactly as before: plain text, no quoting/escaping added.
	if want := "email=operator@example.org"; !strings.Contains(got, want) {
		t.Errorf("summarizeDetails(%+v) = %q, want it to contain %q", details, got, want)
	}
}

func TestSummarizeDetailsHidesCertificateSerialNoise(t *testing.T) {
	details := map[string]any{
		"certSerial": "290795540067739197299943689041050853122",
	}

	got := summarizeDetails(nil, details)

	if strings.Contains(got, "290795540067739197299943689041050853122") || strings.Contains(got, "certSerial") {
		t.Fatalf("summarizeDetails(%+v) = %q, want no raw certificate serial artifact", details, got)
	}
	if got != "Certificate issued" {
		t.Fatalf("summarizeDetails(%+v) = %q, want %q", details, got, "Certificate issued")
	}
}

// TestSummarizeDetailsSettingsWrite locks in the fix for a second real,
// user-reported "weird text" complaint: PUT /api/v1/admin/settings' audit
// row showed detailsSummary as a wall of sorted camelCase booleans
// (analysisMaxIterationsChanged=false, automationSectionProvided=true, ...)
// — every one of handlePutSettings' own flags dumped alphabetically, none
// of it meaningful at a glance. This never hit the "action"/"event"
// special-case above because handlePutSettings' Details map never sets
// either key — summarizeDetails now dispatches on the event's own real
// Capability column instead.
func TestSummarizeDetailsHidesClusterFingerprintNoise(t *testing.T) {
	details := map[string]any{
		"clusterFingerprint": "c6c460b165393a911f8922d748cea7f2de997b85afbf314837d05fc0b5feab18",
	}

	got := summarizeDetails(nil, details)

	if strings.Contains(got, "c6c460b165393a911f8922d748cea7f2de997b85afbf314837d05fc0b5feab18") {
		t.Fatalf("summarizeDetails(%+v) = %q, want no raw fingerprint hash in the summary", details, got)
	}
	if got != "Cluster enrollment attempted" {
		t.Fatalf("summarizeDetails(%+v) = %q, want %q", details, got, "Cluster enrollment attempted")
	}
}

func TestSummarizeDetailsSettingsWrite(t *testing.T) {
	capability := "org:settings:write"
	details := map[string]any{
		"llmSectionProvided":              false,
		"llmApiKeyChanged":                false,
		"notifySectionProvided":           false,
		"notifyWebhookChanged":            false,
		"analysisSectionProvided":         false,
		"analysisMaxIterationsChanged":    false,
		"analysisTimeLimitSecondsChanged": false,
		"automationSectionProvided":       true,
		"retentionSectionProvided":        false,
		"detectionSectionProvided":        false,
		"autonomySectionProvided":         false,
		"costSectionProvided":             true,
	}

	got := summarizeDetails(&capability, details)

	for _, leaked := range []string{"SectionProvided", "Changed=", "analysisMaxIterations"} {
		if strings.Contains(got, leaked) {
			t.Errorf("summarizeDetails(%+v) = %q, still leaks a raw internal flag name %q", details, got, leaked)
		}
	}
	if want := "automatic investigation"; !strings.Contains(got, want) {
		t.Errorf("summarizeDetails(%+v) = %q, want it to name the changed section %q", details, got, want)
	}
	if want := "cost"; !strings.Contains(got, want) {
		t.Errorf("summarizeDetails(%+v) = %q, want it to name the changed section %q", details, got, want)
	}
	if strings.Contains(got, "notifications") || strings.Contains(got, "AI provider") {
		t.Errorf("summarizeDetails(%+v) = %q, named a section that was NOT provided", details, got)
	}
}

func TestSummarizeDetailsSettingsWriteSensitiveChange(t *testing.T) {
	capability := "org:settings:write"
	details := map[string]any{
		"llmSectionProvided": true,
		"llmApiKeyChanged":   true,
	}

	got := summarizeDetails(&capability, details)

	if want := "AI provider API key"; !strings.Contains(got, want) {
		t.Errorf("summarizeDetails(%+v) = %q, want it to call out the API key change %q", details, got, want)
	}
}

func TestSummarizeDetailsSettingsWriteNoSectionChanged(t *testing.T) {
	capability := "org:settings:write"
	details := map[string]any{
		"llmSectionProvided":        false,
		"automationSectionProvided": false,
	}

	got := summarizeDetails(&capability, details)

	if got == "" {
		t.Errorf("summarizeDetails(%+v) = %q, want a non-empty summary even when nothing was actually changed", details, got)
	}
}

func TestFormatDetailValue(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"string scalar", "viewer", "viewer"},
		{"bool scalar", true, "true"},
		{"number scalar (JSON decodes to float64)", float64(3), "3"},
		{"nil", nil, "<nil>"},
		{"nested object", map[string]any{"type": "AllClusters"}, `{"type":"AllClusters"}`},
		{"nested object with more fields", map[string]any{"type": "Cluster", "clusterId": "cl_abc"}, `{"clusterId":"cl_abc","type":"Cluster"}`},
		{"nested array", []any{"a", "b"}, `["a","b"]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatDetailValue(tc.in); got != tc.want {
				t.Errorf("formatDetailValue(%#v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
