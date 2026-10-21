package api

// Pure-Go tests for diagnostics.go's redaction chokepoint and pure derivation
// logic — no database needed. The adversarial, end-to-end proof against a
// real configured/env-sourced secret lives in diagnostics_db_test.go; these
// tests are the "did we forget a field" guard the task's own instructions
// warn a narrower test would miss: sanitizeDiagnosticsBundle is exercised
// with a known secret planted in EVERY field it is supposed to scrub, not
// just one.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"argus/internal/redact"
	"argus/internal/tunnel"
)

// TestSanitizeDiagnosticsTextRedactsKnownSecretsAndPatterns is adversarial by
// construction: every case plants a value that, if it leaked, would be a
// real credential disclosure, and asserts the exact secret substring is
// gone from the output — not merely that SOME redaction happened.
func TestSanitizeDiagnosticsTextRedactsKnownSecretsAndPatterns(t *testing.T) {
	const configuredSecret = "sk-ant-oat01-configured-secret-do-not-leak"

	cases := []struct {
		name         string
		input        string
		knownSecrets []string
		mustNotHave  []string
		mustHave     []string
	}{
		{
			name:         "exact known secret value (a configured API key resolved by GetProbeConfig)",
			input:        "provider call failed: unauthorized, key=" + configuredSecret,
			knownSecrets: []string{configuredSecret},
			mustNotHave:  []string{configuredSecret},
		},
		{
			name:        "bearer credential in a header-ish string",
			input:       "request failed: Authorization: Bearer sk-live-abcdEFGH12345678",
			mustNotHave: []string{"sk-live-abcdEFGH12345678"},
		},
		{
			name:        "JWT",
			input:       "token rejected: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PYnyRvLPPqp8",
			mustNotHave: []string{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PYnyRvLPPqp8"},
		},
		{
			name:        "AWS access key id",
			input:       "denied for AKIAABCDEFGHIJKLMNOP on bucket read",
			mustNotHave: []string{"AKIAABCDEFGHIJKLMNOP"},
		},
		{
			// The exact scenario T18's own instructions name: "a failed
			// provider connection can echo a URL containing credentials."
			name:        "credential embedded in a connection URL's userinfo",
			input:       "dial failed: https://svc-account:hunter2-supersecret@git.example.com/org/repo.git: connection refused",
			mustNotHave: []string{"hunter2-supersecret"},
			mustHave:    []string{"svc-account", "git.example.com"}, // the diagnostic part survives
		},
		{
			name:        "PEM private key block",
			input:       "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJ...fake...\n-----END RSA PRIVATE KEY-----",
			mustNotHave: []string{"MIIBogIBAAJ"},
		},
		{
			name:        "credential-implying key=value in freeform text",
			input:       "connection string: postgres_password=Tr0ub4dor&3 host=db",
			mustNotHave: []string{"Tr0ub4dor&3"},
		},
		{
			name:     "plain diagnostic text is left readable",
			input:    "watch closed: context deadline exceeded",
			mustHave: []string{"watch closed", "context deadline exceeded"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeDiagnosticsText(tc.input, tc.knownSecrets)
			for _, secret := range tc.mustNotHave {
				if strings.Contains(got, secret) {
					t.Errorf("sanitizeDiagnosticsText(%q) = %q, still contains secret %q", tc.input, got, secret)
				}
			}
			for _, want := range tc.mustHave {
				if !strings.Contains(got, want) {
					t.Errorf("sanitizeDiagnosticsText(%q) = %q, want it to still contain %q", tc.input, got, want)
				}
			}
		})
	}
}

// TestSanitizeDiagnosticsTextTruncatesLongFields proves the per-field length
// bound diagnosticsFieldMaxRunes actually runs, independent of the bundle's
// list-length caps (this is the OTHER half of "size-bounded" — a single
// pathologically long error string must not make the bundle unbounded).
func TestSanitizeDiagnosticsTextTruncatesLongFields(t *testing.T) {
	long := strings.Repeat("x", diagnosticsFieldMaxRunes+250)
	got := sanitizeDiagnosticsText(long, nil)
	if runes := []rune(got); len(runes) > diagnosticsFieldMaxRunes+1 { // +1 for the ellipsis rune
		t.Fatalf("sanitizeDiagnosticsText did not bound length: got %d runes, want <= %d", len(runes), diagnosticsFieldMaxRunes+1)
	}
	if !strings.HasSuffix(got, "…") {
		start := len(got) - 10
		if start < 0 {
			start = 0
		}
		t.Fatalf("sanitizeDiagnosticsText(long) = %q, want a truncation marker", got[start:])
	}
}

// TestSanitizeDiagnosticsBundleScrubsEveryField is the guard the task's own
// instructions call for explicitly: "A test that only checks a field was
// omitted proves nothing about the fields you forgot." One known secret is
// planted into every single freeform field sanitizeDiagnosticsBundle is
// documented to touch, the bundle is marshaled to the exact JSON bytes a
// caller would receive, and the secret must not appear ANYWHERE in that
// output — not field-by-field, but in the raw bytes, so a field this test
// doesn't even know the name of still fails loudly if it leaks.
func TestSanitizeDiagnosticsBundleScrubsEveryField(t *testing.T) {
	const secret = "sk-adversarial-plant-0001"

	bundle := diagnosticsBundle{
		Clusters: []diagnosticsCluster{
			{
				ID: "cl_1", DisplayName: "prod " + secret, State: "Active",
				Detectors: &diagnosticsDetectors{
					WarningEvents: diagnosticsDetectorStatus{Status: "failing", Error: "watch failed: " + secret, DeniedReads: []string{"events:" + secret}},
					PodConditions: diagnosticsDetectorStatus{Status: "unknown"},
					Sweep:         diagnosticsDetectorStatus{Status: "ok"},
				},
			},
		},
		AIProviders: []diagnosticsAIProvider{
			{
				ID: "aip_1", Name: "test", Kind: "api",
				BaseURL: "https://" + secret + "@example.com/v1", RunnerURL: secret, Model: secret,
				ConnectivityChecked: true, ConnectivitySummary: secret, ConnectivityDetail: secret, ConnectivityCaveat: secret,
			},
		},
		Repositories: []diagnosticsRepository{
			{ID: "repo_1", Provider: "github", Host: secret, ConnectivityChecked: true, ConnectivitySummary: "clone failed: " + secret},
		},
		RecentInternalErrors: []diagnosticsInternalError{
			{OccurredAt: "2026-09-18T00:00:00Z", Action: secret, Summary: "failed: " + secret},
		},
	}

	sanitizeDiagnosticsBundle(&bundle, []string{secret})

	body, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(body), secret) {
		t.Fatalf("sanitized bundle JSON still contains the planted secret %q:\n%s", secret, body)
	}
	if !strings.Contains(string(body), redact.Marker) {
		t.Fatalf("sanitized bundle JSON has no redaction marker at all — expected %q to appear where the secret was", redact.Marker)
	}
}

func TestDiagnosticsStatusForNeverInfersHealthFromAbsence(t *testing.T) {
	now := time.Now().UTC()

	t.Run("never observed", func(t *testing.T) {
		got := diagnosticsStatusFor(tunnel.DetectorStatus{})
		if got.Status != "unknown" {
			t.Errorf("Status = %q, want %q for a zero-value DetectorStatus", got.Status, "unknown")
		}
		if got.LastSuccessAt != "" || got.Error != "" {
			t.Errorf("got = %+v, want no success/error fields for never-observed", got)
		}
	})

	t.Run("clean success", func(t *testing.T) {
		got := diagnosticsStatusFor(tunnel.DetectorStatus{LastSuccessAt: now})
		if got.Status != "ok" {
			t.Errorf("Status = %q, want %q", got.Status, "ok")
		}
	})

	t.Run("currently failing", func(t *testing.T) {
		got := diagnosticsStatusFor(tunnel.DetectorStatus{
			LastSuccessAt: now.Add(-time.Hour),
			Error:         "jobs: forbidden",
			ErrorAt:       now,
			DeniedReads:   []string{"jobs"},
		})
		if got.Status != "failing" {
			t.Errorf("Status = %q, want %q", got.Status, "failing")
		}
		if got.Error == "" {
			t.Errorf("Error not carried through")
		}
	})

	t.Run("recovered — error stays visible but status is ok", func(t *testing.T) {
		got := diagnosticsStatusFor(tunnel.DetectorStatus{
			LastSuccessAt: now,
			Error:         "jobs: forbidden",
			ErrorAt:       now.Add(-time.Hour),
		})
		if got.Status != "ok" {
			t.Errorf("Status = %q, want %q (last success is AFTER last error)", got.Status, "ok")
		}
		// DetectorStatus's own doc comment: error is deliberately NOT
		// cleared by a later success, so an operator can still see "this
		// failed at T and has since recovered".
		if got.Error == "" {
			t.Errorf("recovered detector lost its Error entirely — should stay visible alongside the ok status")
		}
	})
}

func TestBuildDiagnosticsManifestStatesWhatWasOmitted(t *testing.T) {
	t.Run("probe not requested", func(t *testing.T) {
		m := buildDiagnosticsManifest(diagnosticsBundle{}, false)
		if !containsFieldPrefix(m.Omitted, "live AI-provider") {
			t.Errorf("manifest omitted list does not explain that connectivity checks were not run: %+v", m.Omitted)
		}
		for _, want := range []string{
			"AI provider API keys / CLI runner tokens",
			"repository credentials",
			"Kubernetes Secret contents",
			"raw workload/pod logs",
			"process environment variables",
		} {
			if !containsFieldPrefix(m.Omitted, want) {
				t.Errorf("manifest omitted list is missing the always-omitted entry %q: %+v", want, m.Omitted)
			}
		}
	})

	t.Run("probe requested", func(t *testing.T) {
		m := buildDiagnosticsManifest(diagnosticsBundle{}, true)
		if containsFieldPrefix(m.Omitted, "live AI-provider") {
			t.Errorf("probe=true must not claim connectivity checks were omitted: %+v", m.Omitted)
		}
		found := false
		for _, s := range m.Included {
			if strings.Contains(s, "live connectivity results") {
				found = true
			}
		}
		if !found {
			t.Errorf("manifest included list does not mention the live connectivity results that were actually requested: %+v", m.Included)
		}
	})
}

func containsFieldPrefix(omissions []diagnosticsOmission, prefix string) bool {
	for _, o := range omissions {
		if strings.HasPrefix(o.Field, prefix) {
			return true
		}
	}
	return false
}
