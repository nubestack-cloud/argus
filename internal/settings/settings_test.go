package settings

import "testing"

func fakeGetenv(vals map[string]string) func(string) string {
	return func(k string) string { return vals[k] }
}

func strPtr(s string) *string { return &s }

// TestResolvePrecedence pins Resolve's documented rule: the DB row's column
// wins if non-null/non-empty, else the env var, else empty/unconfigured —
// exercised directly against the pure resolve() helper, no database needed.
func TestResolvePrecedence(t *testing.T) {
	env := fakeGetenv(map[string]string{
		"ARGUS_LLM_BASE_URL":       "http://env-base/v1",
		"ARGUS_LLM_MODEL":          "env-model",
		"ARGUS_LLM_API_KEY":        "env-api-key",
		"ARGUS_NOTIFY_WEBHOOK_URL": "https://env-webhook.example/hook",
	})

	t.Run("DB row set overrides env", func(t *testing.T) {
		row := dbRow{
			LLMBaseURL:       strPtr("http://db-base/v1"),
			LLMModel:         strPtr("db-model"),
			LLMAPIKey:        strPtr("db-api-key"),
			NotifyWebhookURL: strPtr("https://db-webhook.example/hook"),
		}
		cfg := resolve(row, env)
		if cfg.LLMBaseURL != "http://db-base/v1" {
			t.Errorf("LLMBaseURL = %q, want DB value", cfg.LLMBaseURL)
		}
		if cfg.LLMModel != "db-model" {
			t.Errorf("LLMModel = %q, want DB value", cfg.LLMModel)
		}
		if cfg.LLMAPIKey != "db-api-key" || !cfg.LLMAPIKeySet {
			t.Errorf("LLMAPIKey = %q LLMAPIKeySet = %v, want db-api-key/true", cfg.LLMAPIKey, cfg.LLMAPIKeySet)
		}
		if cfg.NotifyWebhookURL != "https://db-webhook.example/hook" || !cfg.NotifyWebhookConfigured {
			t.Errorf("NotifyWebhookURL = %q NotifyWebhookConfigured = %v, want DB value/true", cfg.NotifyWebhookURL, cfg.NotifyWebhookConfigured)
		}
	})

	t.Run("DB row NULL falls back to env", func(t *testing.T) {
		cfg := resolve(dbRow{}, env)
		if cfg.LLMBaseURL != "http://env-base/v1" {
			t.Errorf("LLMBaseURL = %q, want env fallback", cfg.LLMBaseURL)
		}
		if cfg.LLMModel != "env-model" {
			t.Errorf("LLMModel = %q, want env fallback", cfg.LLMModel)
		}
		if cfg.LLMAPIKey != "env-api-key" || !cfg.LLMAPIKeySet {
			t.Errorf("LLMAPIKey = %q LLMAPIKeySet = %v, want env-api-key/true", cfg.LLMAPIKey, cfg.LLMAPIKeySet)
		}
		if cfg.NotifyWebhookURL != "https://env-webhook.example/hook" || !cfg.NotifyWebhookConfigured {
			t.Errorf("NotifyWebhookURL = %q NotifyWebhookConfigured = %v, want env fallback/true", cfg.NotifyWebhookURL, cfg.NotifyWebhookConfigured)
		}
	})

	t.Run("DB row set to empty string treated as unset, falls back to env", func(t *testing.T) {
		row := dbRow{LLMBaseURL: strPtr(""), LLMAPIKey: strPtr(""), NotifyWebhookURL: strPtr("")}
		cfg := resolve(row, env)
		if cfg.LLMBaseURL != "http://env-base/v1" {
			t.Errorf("LLMBaseURL = %q, want env fallback (empty-string DB value should not win)", cfg.LLMBaseURL)
		}
		if cfg.LLMAPIKey != "env-api-key" {
			t.Errorf("LLMAPIKey = %q, want env fallback", cfg.LLMAPIKey)
		}
		if cfg.NotifyWebhookURL != "https://env-webhook.example/hook" {
			t.Errorf("NotifyWebhookURL = %q, want env fallback", cfg.NotifyWebhookURL)
		}
	})

	t.Run("neither DB nor env set means unconfigured", func(t *testing.T) {
		cfg := resolve(dbRow{}, fakeGetenv(nil))
		if cfg.LLMBaseURL != "" || cfg.LLMAPIKeySet {
			t.Errorf("expected fully unconfigured LLM, got %+v", cfg)
		}
		if cfg.NotifyWebhookURL != "" || cfg.NotifyWebhookConfigured {
			t.Errorf("expected fully unconfigured notify webhook, got %+v", cfg)
		}
	})

	t.Run("DB and env independently resolved per field", func(t *testing.T) {
		// DB sets the base URL only; model/apiKey/webhook fall back to env.
		row := dbRow{LLMBaseURL: strPtr("http://db-base/v1")}
		cfg := resolve(row, env)
		if cfg.LLMBaseURL != "http://db-base/v1" {
			t.Errorf("LLMBaseURL = %q, want DB value", cfg.LLMBaseURL)
		}
		if cfg.LLMModel != "env-model" {
			t.Errorf("LLMModel = %q, want env fallback even though LLMBaseURL came from the DB", cfg.LLMModel)
		}
	})
}

// TestResolveGatesLLMFieldsOnProviderKind is BUGS.md 125's fix, pinned at
// the pure resolve() level (no database needed, same as TestResolvePrecedence
// above): LLMBaseURL/LLMModel/LLMAPIKey must come back empty for a
// "cli"-kind row no matter what its base_url/model/api_key columns (or the
// matching env vars) hold, because those three columns are meaningless
// baggage for a cli provider — migration 000034's ai_providers_kind_fields
// CHECK never requires them empty for kind="cli". Before this fix, resolve()
// copied them into Config unconditionally, which is what let
// *llm.Provider.Complete attempt a real HTTP call against a stale/leftover
// base_url instead of cleanly reporting ErrNotConfigured.
func TestResolveGatesLLMFieldsOnProviderKind(t *testing.T) {
	env := fakeGetenv(map[string]string{
		"ARGUS_LLM_BASE_URL": "http://env-base/v1",
		"ARGUS_LLM_MODEL":    "env-model",
		"ARGUS_LLM_API_KEY":  "env-api-key",
	})

	t.Run("kind=cli with stale api-shaped DB columns resolves LLMBaseURL/LLMModel/LLMAPIKey empty", func(t *testing.T) {
		row := dbRow{
			LLMProviderKind: strPtr("cli"),
			LLMBaseURL:      strPtr("http://smoketest-llm.invalid/v2"),
			LLMModel:        strPtr("stale-model"),
			LLMAPIKey:       strPtr("stale-api-key"),
			CLIRunnerURL:    strPtr("http://argus-runner:8090"),
		}
		cfg := resolve(row, fakeGetenv(nil))
		if cfg.LLMBaseURL != "" {
			t.Errorf("LLMBaseURL = %q, want empty — a cli-kind provider's base_url is stale baggage, not a real endpoint", cfg.LLMBaseURL)
		}
		if cfg.LLMModel != "" {
			t.Errorf("LLMModel = %q, want empty for a cli-kind provider", cfg.LLMModel)
		}
		if cfg.LLMAPIKey != "" || cfg.LLMAPIKeySet {
			t.Errorf("LLMAPIKey = %q LLMAPIKeySet = %v, want empty/false for a cli-kind provider", cfg.LLMAPIKey, cfg.LLMAPIKeySet)
		}
		// CLIRunnerURL is the cli-kind provider's REAL access mechanism and
		// must be entirely unaffected by this gate.
		if cfg.CLIRunnerURL != "http://argus-runner:8090" {
			t.Errorf("CLIRunnerURL = %q, want the row's runner_url untouched", cfg.CLIRunnerURL)
		}
	})

	t.Run("kind=cli also suppresses the api-shaped env vars, not just the DB columns", func(t *testing.T) {
		row := dbRow{LLMProviderKind: strPtr("cli"), CLIRunnerURL: strPtr("http://argus-runner:8090")}
		cfg := resolve(row, env)
		if cfg.LLMBaseURL != "" || cfg.LLMModel != "" || cfg.LLMAPIKey != "" {
			t.Errorf("expected all three LLM fields empty for a cli-kind provider even with env vars set, got LLMBaseURL=%q LLMModel=%q LLMAPIKey=%q",
				cfg.LLMBaseURL, cfg.LLMModel, cfg.LLMAPIKey)
		}
	})

	t.Run("kind=api (explicit or defaulted from empty) is unaffected by the gate", func(t *testing.T) {
		row := dbRow{
			LLMProviderKind: strPtr("api"),
			LLMBaseURL:      strPtr("http://real-endpoint.example/v1"),
			LLMModel:        strPtr("real-model"),
			LLMAPIKey:       strPtr("real-api-key"),
		}
		cfg := resolve(row, fakeGetenv(nil))
		if cfg.LLMBaseURL != "http://real-endpoint.example/v1" || cfg.LLMModel != "real-model" || cfg.LLMAPIKey != "real-api-key" {
			t.Errorf("an api-kind provider's own LLM fields must pass through unchanged, got LLMBaseURL=%q LLMModel=%q LLMAPIKey=%q",
				cfg.LLMBaseURL, cfg.LLMModel, cfg.LLMAPIKey)
		}

		// No LLMProviderKind at all (row.LLMProviderKind nil) normalizes to
		// "api" (NormalizeProviderKind's own contract) and must behave
		// identically — this is the shape every pre-existing test above
		// (TestResolvePrecedence) already relies on continuing to work.
		defaulted := resolve(dbRow{LLMBaseURL: strPtr("http://real-endpoint.example/v1")}, fakeGetenv(nil))
		if defaulted.LLMBaseURL != "http://real-endpoint.example/v1" {
			t.Errorf("an unset LLMProviderKind must default to api and pass LLMBaseURL through, got %q", defaulted.LLMBaseURL)
		}
	})
}

func intPtr(n int) *int { return &n }

// TestResolveAnalysisBoundsPrecedence pins the same DB-overrides-env rule
// TestResolvePrecedence exercises for the LLM/notify fields, applied to
// AnalysisMaxIterations/AnalysisTimeLimitSeconds — plus the two extra edge
// cases those fields don't have to worry about: a non-positive or
// unparseable value (from either source) is treated as absent rather than
// propagated, and "neither source configured it" resolves to nil (not a
// hardcoded default — that third tier is deliberately applied one layer up,
// in internal/llm/toolloop.go's resolveBounds; see Config's doc comment).
func TestResolveAnalysisBoundsPrecedence(t *testing.T) {
	env := fakeGetenv(map[string]string{
		"ARGUS_ANALYSIS_MAX_ITERATIONS":     "20",
		"ARGUS_ANALYSIS_TIME_LIMIT_SECONDS": "600",
	})

	t.Run("DB row set overrides env", func(t *testing.T) {
		cfg := resolve(dbRow{AnalysisMaxIterations: intPtr(5), AnalysisTimeLimitSeconds: intPtr(60)}, env)
		if cfg.AnalysisMaxIterations == nil || *cfg.AnalysisMaxIterations != 5 {
			t.Errorf("AnalysisMaxIterations = %v, want 5 (DB value)", cfg.AnalysisMaxIterations)
		}
		if cfg.AnalysisTimeLimitSeconds == nil || *cfg.AnalysisTimeLimitSeconds != 60 {
			t.Errorf("AnalysisTimeLimitSeconds = %v, want 60 (DB value)", cfg.AnalysisTimeLimitSeconds)
		}
	})

	t.Run("DB row NULL falls back to env", func(t *testing.T) {
		cfg := resolve(dbRow{}, env)
		if cfg.AnalysisMaxIterations == nil || *cfg.AnalysisMaxIterations != 20 {
			t.Errorf("AnalysisMaxIterations = %v, want 20 (env fallback)", cfg.AnalysisMaxIterations)
		}
		if cfg.AnalysisTimeLimitSeconds == nil || *cfg.AnalysisTimeLimitSeconds != 600 {
			t.Errorf("AnalysisTimeLimitSeconds = %v, want 600 (env fallback)", cfg.AnalysisTimeLimitSeconds)
		}
	})

	t.Run("neither DB nor env set resolves to nil, not a hardcoded default", func(t *testing.T) {
		cfg := resolve(dbRow{}, fakeGetenv(nil))
		if cfg.AnalysisMaxIterations != nil || cfg.AnalysisTimeLimitSeconds != nil {
			t.Errorf("expected both nil (fully unconfigured), got %+v/%v", cfg.AnalysisMaxIterations, cfg.AnalysisTimeLimitSeconds)
		}
	})

	t.Run("DB row set to zero or negative is treated as absent, falls back to env", func(t *testing.T) {
		cfg := resolve(dbRow{AnalysisMaxIterations: intPtr(0), AnalysisTimeLimitSeconds: intPtr(-5)}, env)
		if cfg.AnalysisMaxIterations == nil || *cfg.AnalysisMaxIterations != 20 {
			t.Errorf("AnalysisMaxIterations = %v, want env fallback (20); a non-positive DB value should not win", cfg.AnalysisMaxIterations)
		}
		if cfg.AnalysisTimeLimitSeconds == nil || *cfg.AnalysisTimeLimitSeconds != 600 {
			t.Errorf("AnalysisTimeLimitSeconds = %v, want env fallback (600); a non-positive DB value should not win", cfg.AnalysisTimeLimitSeconds)
		}
	})

	t.Run("env var unparseable or non-positive is treated as absent, resolves to nil", func(t *testing.T) {
		badEnv := fakeGetenv(map[string]string{
			"ARGUS_ANALYSIS_MAX_ITERATIONS":     "not-a-number",
			"ARGUS_ANALYSIS_TIME_LIMIT_SECONDS": "-5",
		})
		cfg := resolve(dbRow{}, badEnv)
		if cfg.AnalysisMaxIterations != nil || cfg.AnalysisTimeLimitSeconds != nil {
			t.Errorf("expected both nil on invalid env input, got %+v/%v", cfg.AnalysisMaxIterations, cfg.AnalysisTimeLimitSeconds)
		}
	})
}

func TestFirstNonNilPositiveInt(t *testing.T) {
	cases := []struct {
		name  string
		dbVal *int
		env   string
		want  *int
	}{
		{"nil db, valid env", nil, "42", intPtr(42)},
		{"nil db, empty env", nil, "", nil},
		{"nil db, invalid env", nil, "nope", nil},
		{"nil db, non-positive env", nil, "0", nil},
		{"positive db, env also set", intPtr(7), "42", intPtr(7)},
		{"non-positive db, env set", intPtr(-1), "42", intPtr(42)},
		{"non-positive db, no env", intPtr(0), "", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := firstNonNilPositiveInt(c.dbVal, c.env)
			switch {
			case c.want == nil && got != nil:
				t.Errorf("firstNonNilPositiveInt(%v, %q) = %v, want nil", c.dbVal, c.env, *got)
			case c.want != nil && got == nil:
				t.Errorf("firstNonNilPositiveInt(%v, %q) = nil, want %v", c.dbVal, c.env, *c.want)
			case c.want != nil && got != nil && *got != *c.want:
				t.Errorf("firstNonNilPositiveInt(%v, %q) = %v, want %v", c.dbVal, c.env, *got, *c.want)
			}
		})
	}
}

// TestResolveAutoAnalysisHasNoEnvFallback pins the documented difference
// between AutoAnalysisEnabled/AutoAnalysisSeverities and every other field
// resolve() computes: there is no env-var tier at all, so the DB row's value
// (even its zero value) is always what comes out, never anything from
// getenv.
func TestResolveAutoAnalysisHasNoEnvFallback(t *testing.T) {
	// A non-nil getenv that would return a value for any key, to prove
	// resolve() never even consults it for these two fields.
	env := fakeGetenv(map[string]string{
		"ARGUS_AUTO_ANALYSIS_ENABLED":    "true",
		"ARGUS_AUTO_ANALYSIS_SEVERITIES": "high,critical",
	})

	t.Run("DB false/empty resolves to false/empty regardless of env", func(t *testing.T) {
		cfg := resolve(dbRow{}, env)
		if cfg.AutoAnalysisEnabled {
			t.Errorf("AutoAnalysisEnabled = true, want false (no env fallback tier exists for this field)")
		}
		if len(cfg.AutoAnalysisSeverities) != 0 {
			t.Errorf("AutoAnalysisSeverities = %v, want empty (no env fallback tier exists for this field)", cfg.AutoAnalysisSeverities)
		}
	})

	t.Run("DB true/severities value passes through as-is", func(t *testing.T) {
		cfg := resolve(dbRow{AutoAnalysisEnabled: true, AutoAnalysisSeverities: []string{"high", "critical"}}, env)
		if !cfg.AutoAnalysisEnabled {
			t.Errorf("AutoAnalysisEnabled = false, want true (DB value)")
		}
		if !equalStringSlices(cfg.AutoAnalysisSeverities, []string{"high", "critical"}) {
			t.Errorf("AutoAnalysisSeverities = %v, want [high critical] (DB value)", cfg.AutoAnalysisSeverities)
		}
	})

	t.Run("DB nil/empty severities means nothing is selected, not an error and not \"everything\"", func(t *testing.T) {
		cfg := resolve(dbRow{AutoAnalysisEnabled: true, AutoAnalysisSeverities: nil}, env)
		if !cfg.AutoAnalysisEnabled {
			t.Errorf("AutoAnalysisEnabled = false, want true")
		}
		if len(cfg.AutoAnalysisSeverities) != 0 {
			t.Errorf("AutoAnalysisSeverities = %v, want empty (\"nothing selected\" — deliberately NOT \"all severities\", see Config's doc comment)", cfg.AutoAnalysisSeverities)
		}
	})
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestResolveRetentionHasNoEnvFallbackAndDefaultsToForever pins the two
// documented properties of AuditRetentionDays/IncidentRetentionDays/
// FindingRetentionDays that make this feature safe-by-default: (1) there is
// no env-var tier at all, so an unrelated env var can never turn on
// retention; (2) an all-nil DB row (the shipped default, migration 000021)
// resolves to all-nil, i.e. "keep forever" — never a hardcoded number of
// days.
func TestResolveRetentionHasNoEnvFallbackAndDefaultsToForever(t *testing.T) {
	env := fakeGetenv(map[string]string{
		"ARGUS_AUDIT_RETENTION_DAYS":    "30",
		"ARGUS_INCIDENT_RETENTION_DAYS": "30",
		"ARGUS_FINDING_RETENTION_DAYS":  "30",
	})

	t.Run("shipped default (all-nil DB row) means keep forever, regardless of env", func(t *testing.T) {
		cfg := resolve(dbRow{}, env)
		if cfg.AuditRetentionDays != nil || cfg.IncidentRetentionDays != nil || cfg.FindingRetentionDays != nil {
			t.Errorf("expected all three retention fields nil (keep forever) by default, got audit=%v incident=%v finding=%v",
				cfg.AuditRetentionDays, cfg.IncidentRetentionDays, cfg.FindingRetentionDays)
		}
	})

	t.Run("an explicit DB value passes through as-is", func(t *testing.T) {
		cfg := resolve(dbRow{
			AuditRetentionDays:    intPtr(365),
			IncidentRetentionDays: intPtr(180),
			FindingRetentionDays:  intPtr(30),
		}, env)
		if cfg.AuditRetentionDays == nil || *cfg.AuditRetentionDays != 365 {
			t.Errorf("AuditRetentionDays = %v, want 365", cfg.AuditRetentionDays)
		}
		if cfg.IncidentRetentionDays == nil || *cfg.IncidentRetentionDays != 180 {
			t.Errorf("IncidentRetentionDays = %v, want 180", cfg.IncidentRetentionDays)
		}
		if cfg.FindingRetentionDays == nil || *cfg.FindingRetentionDays != 30 {
			t.Errorf("FindingRetentionDays = %v, want 30", cfg.FindingRetentionDays)
		}
	})
}

// TestResolveDetectionHasNoEnvFallback pins the same two documented
// properties TestResolveAutoAnalysisHasNoEnvFallback and
// TestResolveRetentionHasNoEnvFallbackAndDefaultsToForever already pin for
// their respective fields, applied to DisabledDetectorIDs/
// StormProtectionMaxNewIncidents/StormProtectionWindowSeconds: (1) there is
// no env-var tier at all, so an unrelated env var can never disable a
// detector or turn on storm protection; (2) an all-empty/all-nil DB row (the
// shipped default, migration 000025) resolves to "nothing disabled, no
// ceiling" — today's actual, unchanged behavior.
func TestResolveDetectionHasNoEnvFallback(t *testing.T) {
	env := fakeGetenv(map[string]string{
		"ARGUS_DISABLED_DETECTOR_IDS":              "k8s-warning-events",
		"ARGUS_STORM_PROTECTION_MAX_NEW_INCIDENTS": "5",
		"ARGUS_STORM_PROTECTION_WINDOW_SECONDS":    "60",
	})

	t.Run("shipped default (empty/nil DB row) means nothing disabled, no ceiling, regardless of env", func(t *testing.T) {
		cfg := resolve(dbRow{}, env)
		if len(cfg.DisabledDetectorIDs) != 0 {
			t.Errorf("DisabledDetectorIDs = %v, want empty (no env fallback tier exists for this field)", cfg.DisabledDetectorIDs)
		}
		if cfg.StormProtectionMaxNewIncidents != nil || cfg.StormProtectionWindowSeconds != nil {
			t.Errorf("expected both storm-protection fields nil (no ceiling) by default, got max=%v window=%v",
				cfg.StormProtectionMaxNewIncidents, cfg.StormProtectionWindowSeconds)
		}
	})

	t.Run("an explicit DB value passes through as-is", func(t *testing.T) {
		cfg := resolve(dbRow{
			DisabledDetectorIDs:            []string{"k8s-pod-conditions"},
			StormProtectionMaxNewIncidents: intPtr(20),
			StormProtectionWindowSeconds:   intPtr(300),
		}, env)
		if !equalStringSlices(cfg.DisabledDetectorIDs, []string{"k8s-pod-conditions"}) {
			t.Errorf("DisabledDetectorIDs = %v, want [k8s-pod-conditions] (DB value)", cfg.DisabledDetectorIDs)
		}
		if cfg.StormProtectionMaxNewIncidents == nil || *cfg.StormProtectionMaxNewIncidents != 20 {
			t.Errorf("StormProtectionMaxNewIncidents = %v, want 20 (DB value)", cfg.StormProtectionMaxNewIncidents)
		}
		if cfg.StormProtectionWindowSeconds == nil || *cfg.StormProtectionWindowSeconds != 300 {
			t.Errorf("StormProtectionWindowSeconds = %v, want 300 (DB value)", cfg.StormProtectionWindowSeconds)
		}
	})
}

// TestResolveAutonomyHasNoEnvFallback pins the same "no env-var tier"
// property TestResolveAutoAnalysisHasNoEnvFallback/
// TestResolveDetectionHasNoEnvFallback already pin for their fields, applied
// to AutonomyAutoApproveMaxRisk/AutonomyMinConfidenceForAutoApprove/
// AutonomyRequireReversibleForAutoApprove — plus the one property that makes
// this trio different from every "opt-in, nil-means-off" field above: an
// all-nil/zero-value DB row does NOT resolve to "never auto-approve" here.
// resolve() itself has no further-default tier to apply (Config's own doc
// comment explains why: that tier lives one layer up, in
// internal/orchestrator.ResolveAutonomyPolicy, mirroring
// AnalysisMaxIterations/AnalysisTimeLimitSeconds' identical split) — this
// test only pins that resolve() passes the raw DB values through untouched,
// nil and all. AutonomyRequireReversibleForAutoApprove joined the other two
// as a *bool in migration 000085 (BUGS.md 97), so all three now share
// exactly the same nil-passes-through-untouched assertion shape.
func TestResolveAutonomyHasNoEnvFallback(t *testing.T) {
	env := fakeGetenv(map[string]string{
		"ARGUS_AUTONOMY_AUTO_APPROVE_MAX_RISK":           "high",
		"ARGUS_AUTONOMY_MIN_CONFIDENCE_FOR_AUTO_APPROVE": "0.1",
	})

	t.Run("unconfigured DB row resolves to nil/nil/nil regardless of env", func(t *testing.T) {
		cfg := resolve(dbRow{}, env)
		if cfg.AutonomyAutoApproveMaxRisk != nil {
			t.Errorf("AutonomyAutoApproveMaxRisk = %v, want nil (no env fallback tier exists for this field)", *cfg.AutonomyAutoApproveMaxRisk)
		}
		if cfg.AutonomyMinConfidenceForAutoApprove != nil {
			t.Errorf("AutonomyMinConfidenceForAutoApprove = %v, want nil (no env fallback tier exists for this field)", *cfg.AutonomyMinConfidenceForAutoApprove)
		}
		if cfg.AutonomyRequireReversibleForAutoApprove != nil {
			t.Errorf("AutonomyRequireReversibleForAutoApprove = %v, want nil (no env fallback tier exists for this field, and this test's zero-value dbRow does not represent the DB's real NOT NULL DEFAULT true column)", *cfg.AutonomyRequireReversibleForAutoApprove)
		}
	})

	t.Run("an explicit DB value passes through as-is", func(t *testing.T) {
		risk := "medium"
		conf := 0.75
		requireReversible := true
		cfg := resolve(dbRow{
			AutonomyAutoApproveMaxRisk:              &risk,
			AutonomyMinConfidenceForAutoApprove:     &conf,
			AutonomyRequireReversibleForAutoApprove: &requireReversible,
		}, env)
		if cfg.AutonomyAutoApproveMaxRisk == nil || *cfg.AutonomyAutoApproveMaxRisk != "medium" {
			t.Errorf("AutonomyAutoApproveMaxRisk = %v, want \"medium\" (DB value)", cfg.AutonomyAutoApproveMaxRisk)
		}
		if cfg.AutonomyMinConfidenceForAutoApprove == nil || *cfg.AutonomyMinConfidenceForAutoApprove != 0.75 {
			t.Errorf("AutonomyMinConfidenceForAutoApprove = %v, want 0.75 (DB value)", cfg.AutonomyMinConfidenceForAutoApprove)
		}
		if cfg.AutonomyRequireReversibleForAutoApprove == nil || !*cfg.AutonomyRequireReversibleForAutoApprove {
			t.Errorf("AutonomyRequireReversibleForAutoApprove = %v, want true (DB value)", cfg.AutonomyRequireReversibleForAutoApprove)
		}
	})
}

func floatPtr(f float64) *float64 { return &f }

// TestResolveCostHasNoEnvFallback pins the same "no env-var tier" property
// TestResolveAutonomyHasNoEnvFallback already pins for its fields, applied
// to PricePerMillionInputTokens/PricePerMillionCachedTokens/
// PricePerMillionOutputTokens/DailySpendCeilingUsd: an all-nil DB row (the
// shipped default, migration 000029) resolves to all-nil — "no pricing
// configured, no ceiling" — regardless of any env var, and an explicit DB
// value passes through untouched.
func TestResolveCostHasNoEnvFallback(t *testing.T) {
	env := fakeGetenv(map[string]string{
		"ARGUS_PRICE_PER_MILLION_INPUT_TOKENS": "2.00",
		"ARGUS_DAILY_SPEND_CEILING_USD":        "50",
	})

	t.Run("shipped default (all-nil DB row) means no pricing, no ceiling, regardless of env", func(t *testing.T) {
		cfg := resolve(dbRow{}, env)
		if cfg.PricePerMillionInputTokens != nil || cfg.PricePerMillionCachedTokens != nil || cfg.PricePerMillionOutputTokens != nil {
			t.Errorf("expected all three price fields nil by default, got in=%v cached=%v out=%v",
				cfg.PricePerMillionInputTokens, cfg.PricePerMillionCachedTokens, cfg.PricePerMillionOutputTokens)
		}
		if cfg.DailySpendCeilingUsd != nil {
			t.Errorf("DailySpendCeilingUsd = %v, want nil (no env fallback tier exists for this field)", *cfg.DailySpendCeilingUsd)
		}
	})

	t.Run("an explicit DB value passes through as-is", func(t *testing.T) {
		cfg := resolve(dbRow{
			PricePerMillionInputTokens:  floatPtr(2.5),
			PricePerMillionCachedTokens: floatPtr(0.25),
			PricePerMillionOutputTokens: floatPtr(10),
			DailySpendCeilingUsd:        floatPtr(25),
		}, env)
		if cfg.PricePerMillionInputTokens == nil || *cfg.PricePerMillionInputTokens != 2.5 {
			t.Errorf("PricePerMillionInputTokens = %v, want 2.5 (DB value)", cfg.PricePerMillionInputTokens)
		}
		if cfg.PricePerMillionCachedTokens == nil || *cfg.PricePerMillionCachedTokens != 0.25 {
			t.Errorf("PricePerMillionCachedTokens = %v, want 0.25 (DB value)", cfg.PricePerMillionCachedTokens)
		}
		if cfg.PricePerMillionOutputTokens == nil || *cfg.PricePerMillionOutputTokens != 10 {
			t.Errorf("PricePerMillionOutputTokens = %v, want 10 (DB value)", cfg.PricePerMillionOutputTokens)
		}
		if cfg.DailySpendCeilingUsd == nil || *cfg.DailySpendCeilingUsd != 25 {
			t.Errorf("DailySpendCeilingUsd = %v, want 25 (DB value)", cfg.DailySpendCeilingUsd)
		}
	})
}

// TestCostPricingConfigured pins the documented all-or-nothing rule: only
// true when all three price fields are non-nil, false for zero, one, or two
// of them set.
func TestCostPricingConfigured(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want bool
	}{
		{"none set", Config{}, false},
		{"only input set", Config{PricePerMillionInputTokens: floatPtr(1)}, false},
		{"input and cached set, output missing", Config{
			PricePerMillionInputTokens:  floatPtr(1),
			PricePerMillionCachedTokens: floatPtr(0.1),
		}, false},
		{"all three set", Config{
			PricePerMillionInputTokens:  floatPtr(1),
			PricePerMillionCachedTokens: floatPtr(0.1),
			PricePerMillionOutputTokens: floatPtr(5),
		}, true},
		{"all three set, one is zero (a real, valid free price)", Config{
			PricePerMillionInputTokens:  floatPtr(0),
			PricePerMillionCachedTokens: floatPtr(0),
			PricePerMillionOutputTokens: floatPtr(0),
		}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.cfg.CostPricingConfigured(); got != c.want {
				t.Errorf("CostPricingConfigured() = %v, want %v", got, c.want)
			}
		})
	}
}

// TestComputeCostUSD pins the exact dollar-figure math for known token
// counts and a known price config — the core "given known token counts and
// a price config, the exact expected dollar figure" unit test this
// feature's whole value proposition rests on.
func TestComputeCostUSD(t *testing.T) {
	t.Run("pricing not configured returns exactly 0 regardless of token counts", func(t *testing.T) {
		cfg := Config{PricePerMillionInputTokens: floatPtr(2)} // partial, not all three
		if got := cfg.ComputeCostUSD(1_000_000, 1_000_000, 1_000_000); got != 0 {
			t.Errorf("ComputeCostUSD() = %v, want 0 (pricing not fully configured)", got)
		}
	})

	t.Run("known token counts and price config produce the exact expected dollar figure", func(t *testing.T) {
		// $2/Mtok input, $0.20/Mtok cached, $10/Mtok output — 04-consolidated-
		// design.md §16.3's own worked example rates.
		cfg := Config{
			PricePerMillionInputTokens:  floatPtr(2.0),
			PricePerMillionCachedTokens: floatPtr(0.20),
			PricePerMillionOutputTokens: floatPtr(10.0),
		}
		// 300,000 billed-in tokens @ $2/Mtok = $0.60
		// 700,000 cache-read tokens @ $0.20/Mtok = $0.14
		// 6,000 output tokens @ $10/Mtok = $0.06
		// total = $0.80
		got := cfg.ComputeCostUSD(300_000, 700_000, 6_000)
		want := 0.80
		if diff := got - want; diff > 1e-9 || diff < -1e-9 {
			t.Errorf("ComputeCostUSD(300000, 700000, 6000) = %v, want %v", got, want)
		}
	})

	t.Run("zero tokens with configured pricing costs exactly 0", func(t *testing.T) {
		cfg := Config{
			PricePerMillionInputTokens:  floatPtr(2.0),
			PricePerMillionCachedTokens: floatPtr(0.20),
			PricePerMillionOutputTokens: floatPtr(10.0),
		}
		if got := cfg.ComputeCostUSD(0, 0, 0); got != 0 {
			t.Errorf("ComputeCostUSD(0,0,0) = %v, want 0", got)
		}
	})
}

// TestSpendCeilingActive pins the documented "both a ceiling AND real
// pricing must be configured" rule — a ceiling alone, with no pricing, must
// never look active (cost_usd would always be 0, so a ceiling check against
// it would be meaningless).
func TestSpendCeilingActive(t *testing.T) {
	fullPricing := Config{
		PricePerMillionInputTokens:  floatPtr(2),
		PricePerMillionCachedTokens: floatPtr(0.2),
		PricePerMillionOutputTokens: floatPtr(10),
	}

	cases := []struct {
		name string
		cfg  Config
		want bool
	}{
		{"no ceiling, no pricing", Config{}, false},
		{"ceiling set, pricing NOT configured", Config{DailySpendCeilingUsd: floatPtr(10)}, false},
		{"pricing configured, no ceiling", fullPricing, false},
		{"both ceiling and pricing configured", func() Config {
			cfg := fullPricing
			cfg.DailySpendCeilingUsd = floatPtr(10)
			return cfg
		}(), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.cfg.SpendCeilingActive(); got != c.want {
				t.Errorf("SpendCeilingActive() = %v, want %v", got, c.want)
			}
		})
	}
}

// TestSpendCeilingEnforceable pins the claim T8 exists to make honest: a
// configured ceiling plus configured pricing is NOT enough to call the ceiling
// a working control, because a CLI/subscription provider's spend is not
// countable at all (ActiveProviderSpendCountable's doc comment).
//
// It also pins the deliberate asymmetry with SpendCeilingActive: the last case
// is enforceable == false while active == true, which is exactly the state the
// UI has to report and the state enforcement must NOT stop checking.
func TestSpendCeilingEnforceable(t *testing.T) {
	fullPricing := func() Config {
		return Config{
			PricePerMillionInputTokens:  floatPtr(2),
			PricePerMillionCachedTokens: floatPtr(0.2),
			PricePerMillionOutputTokens: floatPtr(10),
		}
	}
	withCeiling := func(kind string) Config {
		cfg := fullPricing()
		cfg.DailySpendCeilingUsd = floatPtr(10)
		cfg.LLMProviderKind = kind
		return cfg
	}

	cases := []struct {
		name           string
		cfg            Config
		wantCountable  bool
		wantEnforce    bool
		wantStillCheck bool // SpendCeilingActive — enforcement is unchanged
	}{
		// "" is what an unset kind normalizes to, and it normalizes to api.
		{"api provider, pricing and ceiling set", withCeiling(ProviderKindAPI), true, true, true},
		{"unset provider kind normalizes to api", withCeiling(""), true, true, true},
		{"api provider, no pricing", func() Config {
			return Config{LLMProviderKind: ProviderKindAPI, DailySpendCeilingUsd: floatPtr(10)}
		}(), true, false, false},
		{"api provider, no ceiling", func() Config {
			cfg := fullPricing()
			cfg.LLMProviderKind = ProviderKindAPI
			return cfg
		}(), true, false, false},
		// The T8 case: everything an operator can configure IS configured,
		// and the ceiling still cannot fire.
		{"cli provider, pricing and ceiling set", withCeiling(ProviderKindCLI), false, false, true},
		{"cli provider, no pricing", func() Config {
			return Config{LLMProviderKind: ProviderKindCLI, DailySpendCeilingUsd: floatPtr(10)}
		}(), false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.cfg.ActiveProviderSpendCountable(); got != c.wantCountable {
				t.Errorf("ActiveProviderSpendCountable() = %v, want %v", got, c.wantCountable)
			}
			if got := c.cfg.SpendCeilingEnforceable(); got != c.wantEnforce {
				t.Errorf("SpendCeilingEnforceable() = %v, want %v", got, c.wantEnforce)
			}
			if got := c.cfg.SpendCeilingActive(); got != c.wantStillCheck {
				t.Errorf("SpendCeilingActive() = %v, want %v — enforcement must not change", got, c.wantStillCheck)
			}
		})
	}
}

func TestFirstNonEmpty(t *testing.T) {
	cases := []struct {
		name  string
		dbVal *string
		env   string
		want  string
	}{
		{"nil db, env set", nil, "env", "env"},
		{"empty db, env set", strPtr(""), "env", "env"},
		{"non-empty db, env set", strPtr("db"), "env", "db"},
		{"nil db, env empty", nil, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := firstNonEmpty(c.dbVal, c.env); got != c.want {
				t.Errorf("firstNonEmpty(%v, %q) = %q, want %q", c.dbVal, c.env, got, c.want)
			}
		})
	}
}
