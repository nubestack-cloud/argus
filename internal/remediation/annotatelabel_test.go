package remediation

import (
	"errors"
	"strings"
	"testing"

	"argus/internal/redact"
)

// TestAnnotationPermitted mirrors TestPatchFieldPermitted's structure: a
// (kind, key, value) triple is either permitted (the exact allowed value/
// pattern) or refused, and the refusal must name what was wrong.
func TestAnnotationPermitted(t *testing.T) {
	for _, tc := range []struct {
		name      string
		gvk       string
		key       string
		value     string
		permitted bool
	}{
		{"deployment timestamp, valid RFC3339", "apps/v1/Deployment", "argus.io/last-remediated-at", "2026-08-29T00:00:00Z", true},
		{"deployment timestamp, garbage value", "apps/v1/Deployment", "argus.io/last-remediated-at", "not-a-timestamp", false},
		{"deployment incident id, valid", "apps/v1/Deployment", "argus.io/incident-id", "inc_01test", true},
		{"deployment incident id, missing prefix", "apps/v1/Deployment", "argus.io/incident-id", "01test", false},
		{"statefulset timestamp, valid", "apps/v1/StatefulSet", "argus.io/last-remediated-at", "2026-08-29T00:00:00Z", true},
		{"unlisted key on deployment", "apps/v1/Deployment", "argus.io/whatever", "x", false},
		{"listed key, unlisted kind", "v1/ConfigMap", "argus.io/incident-id", "inc_01test", false},
		{"listed key, unlisted kind (pod)", "v1/Pod", "argus.io/incident-id", "inc_01test", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := AnnotationPermitted(tc.gvk, tc.key, tc.value)
			if tc.permitted && err != nil {
				t.Errorf("expected permitted, got error: %v", err)
			}
			if !tc.permitted && err == nil {
				t.Errorf("%s=%s on %s was PERMITTED and must not be", tc.key, tc.value, tc.gvk)
			}
		})
	}
}

func TestLabelPermitted(t *testing.T) {
	for _, tc := range []struct {
		name      string
		gvk       string
		key       string
		value     string
		permitted bool
	}{
		{"deployment remediated=true", "apps/v1/Deployment", "argus.io/remediated", "true", true},
		{"deployment remediated=false, not the allowed value", "apps/v1/Deployment", "argus.io/remediated", "false", false},
		{"statefulset remediated=true", "apps/v1/StatefulSet", "argus.io/remediated", "true", true},
		{"unlisted key", "apps/v1/Deployment", "team", "payments", false},
		{"listed key, unlisted kind", "v1/Service", "argus.io/remediated", "true", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LabelPermitted(tc.gvk, tc.key, tc.value)
			if tc.permitted && err != nil {
				t.Errorf("expected permitted, got error: %v", err)
			}
			if !tc.permitted && err == nil {
				t.Errorf("%s=%s on %s was PERMITTED and must not be", tc.key, tc.value, tc.gvk)
			}
		})
	}
}

// TestAnnotateLabelAllowlistsAreReviewable mirrors
// TestPatchFieldAllowlistIsReviewable: every entry has a real justification,
// a fully-qualified GVK, a recognised risk level, and — the constraint
// specific to this mechanism — an actual value constraint, never "any
// value".
func TestAnnotateLabelAllowlistsAreReviewable(t *testing.T) {
	check := func(t *testing.T, kind string, entries []metadataAllowlistEntry) {
		seen := map[string]bool{}
		for _, e := range entries {
			key := e.GVK + " " + e.Key
			if seen[key] {
				t.Errorf("%s is listed twice — two rows for one permission means two places to revoke it", key)
			}
			seen[key] = true

			if strings.TrimSpace(e.Why) == "" {
				t.Errorf("%s has no justification; an entry nobody could explain is an entry nobody reviewed", key)
			}
			if len(e.Why) < 40 {
				t.Errorf("%s's justification is too short to be one: %q", key, e.Why)
			}
			if e.GVK == "" || !strings.Contains(e.GVK, "/") {
				t.Errorf("%s has no fully-qualified GVK; a bare kind would match across API groups", key)
			}
			if e.Risk != RiskLow && e.Risk != RiskMedium && e.Risk != RiskHigh {
				t.Errorf("%s has risk %q, which is not a level", key, e.Risk)
			}
			if len(e.AllowedValues) == 0 && e.ValuePattern == nil {
				t.Errorf("%s declares no value constraint — this would be an arbitrary-write escape hatch", key)
			}
			if strings.TrimSpace(e.Key) == "" {
				t.Errorf("%s %s has an empty key", kind, e.GVK)
			}
		}
		if len(entries) == 0 {
			t.Fatalf("the %s allowlist is empty", kind)
		}
	}
	t.Run("annotate", func(t *testing.T) { check(t, "annotate", AnnotateAllowlistEntries()) })
	t.Run("label", func(t *testing.T) { check(t, "label", LabelAllowlistEntries()) })
}

// TestAnnotateLabelUnconstrainedEntryNeverMatches is annotatelabel.go's own
// stated invariant, made mechanical: an entry with neither AllowedValues nor
// ValuePattern must refuse EVERY value, not fall back to "anything goes".
func TestAnnotateLabelUnconstrainedEntryNeverMatches(t *testing.T) {
	table := []metadataAllowlistEntry{
		{GVK: "apps/v1/Deployment", Key: "argus.io/unconstrained", Risk: RiskLow, Why: "test fixture only, deliberately carries no AllowedValues/ValuePattern"},
	}
	for _, v := range []string{"", "anything", "true", "argus.io/incident-id"} {
		if _, err := annotationOrLabelPermitted(table, "annotation", "apps/v1/Deployment", "argus.io/unconstrained", v); err == nil {
			t.Errorf("an unconstrained allowlist entry permitted value %q — it must refuse every value", v)
		}
	}
}

// TestAnnotateResourceParamsValidate / TestLabelResourceParamsValidate cover
// the shape-only bound each params type carries on its own, independent of
// any allowlist — positive and negative cases, matching this package's
// existing convention (e.g. plan_test.go's PatchResourceLimitsParams
// coverage).
func TestAnnotateResourceParamsValidate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		params  AnnotateResourceParams
		wantErr bool
	}{
		{"valid", AnnotateResourceParams{Key: "argus.io/incident-id", Value: "inc_01test"}, false},
		{"empty key", AnnotateResourceParams{Key: "", Value: "x"}, true},
		{"malformed key", AnnotateResourceParams{Key: "not a valid key!", Value: "x"}, true},
		{"empty value", AnnotateResourceParams{Key: "argus.io/incident-id", Value: ""}, true},
		{"multi-line value", AnnotateResourceParams{Key: "argus.io/incident-id", Value: "line1\nline2"}, true},
		{"value too long", AnnotateResourceParams{Key: "argus.io/incident-id", Value: strings.Repeat("x", maxAnnotationOrLabelValueLength+1)}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.params.Validate()
			if tc.wantErr && err == nil {
				t.Error("expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

func TestLabelResourceParamsValidate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		params  LabelResourceParams
		wantErr bool
	}{
		{"valid", LabelResourceParams{Key: "argus.io/remediated", Value: "true"}, false},
		{"empty key", LabelResourceParams{Key: "", Value: "true"}, true},
		{"empty value", LabelResourceParams{Key: "argus.io/remediated", Value: ""}, true},
		// Kubernetes label VALUES have a stricter shape than annotation
		// values (63 chars, no ':' etc.) — this must be caught even though
		// AnnotateResourceParams' own shape check would accept it.
		{"value violates label-value grammar", LabelResourceParams{Key: "argus.io/remediated", Value: "not:a:valid:label:value"}, true},
		{"value too long for a label", LabelResourceParams{Key: "argus.io/remediated", Value: strings.Repeat("a", 64)}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.params.Validate()
			if tc.wantErr && err == nil {
				t.Error("expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

// TestAnnotateLabelEchoesRedactionMarkerIsRefused is BUGS.md 112's guard,
// carried into this mechanism the same way OpenPRParams/PatchFieldParams
// already carry it — see annotatelabel.go's own comment for why this is
// kept unconditionally even though no entry in today's allowlist reaches a
// redacted field class.
func TestAnnotateLabelEchoesRedactionMarkerIsRefused(t *testing.T) {
	p := AnnotateResourceParams{Key: "argus.io/incident-id", Value: redact.Marker}
	err := p.Validate()
	if err == nil {
		t.Fatal("expected a redaction-marker refusal, got nil")
	}
	if !errors.Is(err, ErrNewValueEchoesRedactionMarker) {
		t.Errorf("error does not wrap ErrNewValueEchoesRedactionMarker: %v", err)
	}
}

// TestAnnotateResourceIsApprovalOnly / TestLabelResourceIsApprovalOnly /
// TestDeleteResourceIsApprovalOnly (the last defined in deleteresource_test.go)
// are this package's mechanical guard against risk.go's neverAutoApprove
// silently losing an entry.
func TestAnnotateResourceIsApprovalOnly(t *testing.T) {
	if !NeverAutoApprove(ActionAnnotateResource) {
		t.Error("AnnotateResource can auto-approve; the value is always chosen by whoever authored the plan, never derived from the API")
	}
}

func TestLabelResourceIsApprovalOnly(t *testing.T) {
	if !NeverAutoApprove(ActionLabelResource) {
		t.Error("LabelResource can auto-approve; the value is always chosen by whoever authored the plan, never derived from the API")
	}
}
