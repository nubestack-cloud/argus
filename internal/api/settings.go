package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/llm"
	"argus/internal/logging"
	"argus/internal/orchestrator"
	"argus/internal/outbound"
	"argus/internal/settings"
)

// This file implements GET/PUT /api/v1/admin/settings — the runtime-editable
// home for the AI-provider and notification-webhook config that used to be
// env-var-only, read once at hub startup (internal/llm.NewProviderFromEnv,
// internal/notify.NewWebhookNotifierFromEnv). See internal/settings for the
// resolution/update logic both routes are thin HTTP wrappers around.
//
// Both routes require org:settings:write (authz/permissions.go) — there is
// no separate read capability in the catalogue, and that's the correct,
// minimal choice here, not an oversight: this config includes real secrets
// (an LLM API key; a Slack incoming-webhook URL, which embeds a bearer-
// equivalent token in its path), so "who can see whether it's configured"
// and "who can change it" are appropriately the same gate. org:settings:write
// is deliberately super-admin-only (authz/permissions.go's
// builtinRoleCapabilities excludes it from tenant-admin, per
// lld/02-authz-spec.md §5's explicit note) — this file doesn't grant it any
// more broadly than that.

// settingsResponse is the shared shape both handlers return — GET as its own
// response, PUT reflecting the new state after applying the request. Never
// carries llmApiKey or notifyWebhookUrl's actual values, only whether each is
// set — see llmSettingsView/notifySettingsView. analysis has no such secret
// to hide (see analysisSettingsView's own doc comment) — it echoes the
// actual configured/effective numbers straight back.
type settingsResponse struct {
	LLM        llmSettingsView        `json:"llm"`
	Notify     notifySettingsView     `json:"notify"`
	Analysis   analysisSettingsView   `json:"analysis"`
	Automation automationSettingsView `json:"automation"`
	Retention  retentionSettingsView  `json:"retention"`
	Detection  detectionSettingsView  `json:"detection"`
	Autonomy   autonomySettingsView   `json:"autonomy"`
	Cost       costSettingsView       `json:"cost"`
	Appearance appearanceSettingsView `json:"appearance"`
	General    generalSettingsView    `json:"general"`
	Outbound   outboundSettingsView   `json:"outbound"`
	Posture    postureSettingsView    `json:"posture"`
}

// postureSettingsView is the organisation's posture exceptions (CI-P9 d),
// applied to every cluster on top of each agent's own chart values. Both
// lists are non-nil on the wire.
type postureSettingsView struct {
	DisabledChecks    []string `json:"disabledChecks"`
	IgnoredNamespaces []string `json:"ignoredNamespaces"`
}

// outboundSettingsView is the operator's named exceptions to
// internal/outbound's default-deny on private destinations, for the
// AI-provider and repository HTTP clients only (migration 000115, owner
// decision 2026-09-19).
//
// Nothing here is a secret: an allowlist entry is an address and a written
// justification, and the justification is the point — it is echoed back in
// full, unlike llm.apiKey, because an exception an operator cannot read back
// is one nobody can review.
//
// A top-level section rather than a field on "llm", even though the AI
// provider is one of its two consumers, because the other consumer is
// internal/scm: the list is a property of the hub's egress posture, not of
// which model is configured, and nesting it under either consumer would
// imply it applies to only that one.
type outboundSettingsView struct {
	// PrivateDestinations is never null on the wire — an empty list is
	// rendered as [], the same normalisation automationSettingsView applies
	// to its severities, so a client never has to tell "no exceptions" apart
	// from "field missing".
	PrivateDestinations []outboundPrivateDestinationView `json:"privateDestinations"`
}

type outboundPrivateDestinationView struct {
	Destination string `json:"destination"`
	Reason      string `json:"reason"`
}

// appearanceSettingsView is the sign-in screen's style, the app-wide primary
// colour, and the Overview page's default time window — grouped together
// because all three are small, non-secret, closed-set display choices with no
// further fallback tier (PROJECT.md, 2026-10-14). LoginStyle alone configures
// something a NOT-yet-authenticated visitor sees, which is why it alone is
// also served by GET /api/v1/auth/sso/providers — the login page cannot read
// this endpoint, since reading it is what signing in is for. PrimaryColorID
// and OverviewDefaultWindowDays instead ride on GET /api/v1/users/me, which
// every authenticated user (not just one holding org:settings:write) can
// read — see handleMe's doc comment.
//
// `styles`/`primaryColorOptions` ship the valid values with the current one so
// the Settings UI cannot drift from the hub's own list: a value added in Go
// appears in the selector without a frontend change, and one removed stops
// being offered.
type appearanceSettingsView struct {
	LoginStyle                string   `json:"loginStyle"`
	Styles                    []string `json:"styles"`
	PrimaryColorID            string   `json:"primaryColorId"`
	PrimaryColorOptions       []string `json:"primaryColorOptions"`
	OverviewDefaultWindowDays int      `json:"overviewDefaultWindowDays"`
}

func normalisedLoginStyle(s string) string {
	if settings.ValidLoginStyle(s) {
		return s
	}
	return settings.DefaultLoginStyle
}

func normalisedPrimaryColorID(s string) string {
	if settings.ValidPrimaryColorID(s) {
		return s
	}
	return settings.DefaultPrimaryColorID
}

func normalisedOverviewWindow(d int) int {
	if settings.ValidOverviewDefaultWindowDays(d) {
		return d
	}
	return settings.OverviewDefaultWindowDaysValues[0]
}

// generalSettingsView is the two account-security floors PROJECT.md's
// 2026-10-14 entry added — see migration 000131's doc comment for why each
// used to be a hardcoded constant and what changing it now actually does.
type generalSettingsView struct {
	MinPasswordLength int `json:"minPasswordLength"`
	// SessionIdleTimeoutMinutes is null when there is no idle limit — today's
	// exact behaviour, a refresh token good for its full 30-day lifetime
	// regardless of activity.
	SessionIdleTimeoutMinutes *int `json:"sessionIdleTimeoutMinutes"`
}

type llmSettingsView struct {
	BaseURL   string `json:"baseUrl"`
	Model     string `json:"model"`
	APIKeySet bool   `json:"apiKeySet"`

	// ProviderKind is "api" or "cli" (lld/14-adrs.md ADR-17), always
	// concrete — internal/settings.Resolve normalizes the never-configured
	// case to "api", so a client never has to interpret "".
	//
	// CLIRunnerTokenSet mirrors APIKeySet's contract for the runner
	// credential: whether it's set, never what it's set to. CLIRunnerURL and
	// CLIAgent aren't secret and are returned in full.
	ProviderKind      string `json:"providerKind"`
	CLIRunnerURL      string `json:"cliRunnerUrl"`
	CLIAgent          string `json:"cliAgent"`
	CLIRunnerTokenSet bool   `json:"cliRunnerTokenSet"`

	// CLIBackendAvailable is whether this HUB can serve a `cli` provider at
	// all — it needs an MCP listener (ARGUS_MCP_ADDR), which is off by default.
	//
	// Reported because a `cli` provider can be configured perfectly and still
	// be unusable, and nothing told anyone: the UI let an operator activate one
	// and the failure appeared only on clicking Analyze, as an error blaming the
	// provider's base URL. That is a hub-level fact the client cannot infer, so
	// the hub has to state it.
	//
	// Reads false when the investigator does not implement the reporting
	// interface (test fakes). False is the safe direction: it warns about a
	// problem that may not exist rather than staying silent about one that does.
	CLIBackendAvailable bool `json:"cliBackendAvailable"`
}

type notifySettingsView struct {
	WebhookConfigured bool `json:"webhookConfigured"`
}

// analysisSettingsView is the investigation loop's bounds
// (internal/llm/toolloop.go's Investigate) — a separate top-level section
// rather than nested under "llm", even though both ultimately configure the
// same AI-investigation feature: "llm" is specifically the provider
// connection (endpoint/model/credential), while these two are the loop's own
// turn/time budget, unrelated to which provider is configured and
// meaningful even before one is. Keeping them apart also means a client can
// PUT one without needing to know or resend the other.
//
// MaxIterations/TimeLimitSeconds are the literal org_settings column
// values — null means "not configured in the DB, falling back to the env
// var or internal/llm's hardcoded default," never "unset and broken" (see
// this file's doc comment and internal/settings.Config's for the precedent
// this follows). Effective* is always a concrete number: the value actually
// in force for the very next analysis, whichever tier it came from — the UI
// renders this as a placeholder/hint so "using the fallback" always shows
// what that fallback currently resolves to, not just a bare null.
type analysisSettingsView struct {
	MaxIterations             *int `json:"maxIterations"`
	TimeLimitSeconds          *int `json:"timeLimitSeconds"`
	EffectiveMaxIterations    int  `json:"effectiveMaxIterations"`
	EffectiveTimeLimitSeconds int  `json:"effectiveTimeLimitSeconds"`
	// RetrievalEnabled is the literal org_settings column value, echoed
	// straight back — not a secret, and unlike MaxIterations/TimeLimitSeconds
	// there is no separate "effective" pair to compute (no env-var or
	// hardcoded-default fallback tier exists for this field at all — see
	// settings.Config's own doc comment). Defaults to false: retrieval was
	// measured at 31% higher cost with no measurable confidence benefit on
	// one real repeated fault, an inconclusive result that must not ship as
	// an unconditional cost increase.
	RetrievalEnabled bool `json:"retrievalEnabled"`
}

// automationSettingsView is the "automatic investigation" toggle
// (internal/autoanalyze) — a top-level sibling of llm/notify/analysis, not
// nested under any of them: it's a genuinely distinct concern (whether an
// incident gets analyzed at all without a human clicking "Analyze," not how
// the provider connects or how long one analysis loop is allowed to run).
//
// AutoAnalysisEnabled/AutoAnalysisSeverities are the literal org_settings
// column values, echoed straight back — neither is a secret, and unlike
// analysisSettingsView there's no separate "effective" pair to compute.
//
// AutoAnalysisSeverities replaces migration 000020's single
// autoAnalysisMinSeverity threshold (removed by migration
// 000024_auto_analysis_severities) with a checklist: the wire shape is a
// plain string array of whichever of low/medium/high/critical are selected,
// never a null — an empty array `[]` is itself a complete, self-describing
// value ("nothing selected, so nothing is auto-analyzed"; see
// settings.Config's AutoAnalysisSeverities doc comment for why that's the
// deliberately safe reading, not "every severity qualifies" the way the old
// field's null used to mean). AutoAnalysisSeverities is always non-nil on
// the wire (settingsResponseFromConfig normalizes a nil Config field to an
// empty slice before marshaling) so a client never has to special-case null
// vs. empty array for this field.
type automationSettingsView struct {
	AutoAnalysisEnabled    bool     `json:"autoAnalysisEnabled"`
	AutoAnalysisSeverities []string `json:"autoAnalysisSeverities"`
}

// retentionSettingsView is how long to keep audit_events / incidents /
// findings before internal/partition's daily maintenance job drops that
// table's oldest partitions entirely (migration 000021_retention_settings's
// header comment has the full rationale) — a top-level sibling of
// llm/notify/analysis/automation, not nested under any of them: retention is
// a data-lifecycle policy, unrelated to how the AI provider connects, how
// long one investigation runs, or whether investigation happens at all.
//
// All three fields are the literal org_settings column values, echoed
// straight back — none is a secret. null means "keep forever," and
// (unlike analysisSettingsView's MaxIterations/TimeLimitSeconds) that is
// also the shipped default, not a fallback to some other configured tier —
// there is no "effective" pair to compute here because there is no third
// tier to resolve against; null on the wire means exactly what it says.
type retentionSettingsView struct {
	AuditRetentionDays    *int `json:"auditRetentionDays"`
	IncidentRetentionDays *int `json:"incidentRetentionDays"`
	FindingRetentionDays  *int `json:"findingRetentionDays"`
}

// knownDetectorIDs is the closed set of internal/tunnel.Finding.DetectorID
// values this hub currently knows about — must exactly match
// internal/agent/detector.go's warningEventsDetectorID,
// internal/agent/pod_conditions_detector.go's podConditionsDetectorID,
// internal/agent/sweep_detector.go's sweepDetectorID, and migration
// 000026_detection_settings' CHECK constraint as widened by 000066
// (BUGS.md 83). There is no single
// shared Go constant across the agent/hub module boundary to enforce this
// automatically (the agent and hub are separate deployables — see that
// migration's comment), so this hand-maintained list, like
// validAutoAnalysisSeverities above, gets a real 400 at the API boundary
// for a typo'd or future-not-yet-known detector ID rather than either
// silently failing the DB's CHECK constraint with an opaque 500, or
// (should the CHECK constraint ever loosen) storing a value handleFinding's
// set-membership check would just silently never match against any real
// finding.
var knownDetectorIDs = map[string]bool{
	"k8s-warning-events": true,
	"k8s-pod-conditions": true,
	"k8s-sweep":          true,
}

// knownRuleIDs is the closed set of internal/tunnel.Finding.RuleID values
// this hub currently knows about — BUGS.md 111's rule-level enable/disable
// control, alongside knownDetectorIDs above. Unlike knownDetectorIDs (three
// hand-written detector IDs that change rarely), rule IDs come from
// internal/agent/rules/default-rules.yaml — a 36-entry (as of this writing)
// and actively growing catalogue that lives in the AGENT's package, not the
// hub's. internal/api deliberately does NOT import internal/agent to derive
// this set at runtime: hub and cluster-agent are kept as separate binaries
// with no Go dependency either direction (CLAUDE.md's "Hub (server)" vs
// "Cluster agent (spoke)" split; confirmed by grep before this change — no
// internal/api file imported internal/agent), and a runtime import for one
// read-only lookup would be the first crack in that boundary. So, like
// knownDetectorIDs, this is a hand-maintained literal list, validated at the
// API boundary for a clear 400 on a typo'd or unknown rule ID rather than an
// opaque 500 off a DB CHECK constraint (this table deliberately has no such
// constraint for rule IDs — see migration 000084's comment for why).
//
// The hand-maintained copy is kept honest by
// TestKnownRuleIDsMatchesDefaultRulesYAML (settings_ruleids_test.go), which
// calls agent.LoadRules("") — the actual embedded-YAML parser, not a second
// hand-rolled YAML reader — and asserts this set is EXACTLY the real rule ID
// set, so a rule added, renamed or removed in default-rules.yaml without a
// matching edit here fails CI immediately rather than silently drifting.
// That test file is the one place a test-only import of internal/agent is
// acceptable (see its own doc comment for why that's lower-stakes than a
// production import).
var knownRuleIDs = map[string]bool{
	"pdb-blocks-all-disruptions":                true,
	"networkpolicy-selects-no-pods":             true,
	"resourcequota-at-hard-limit":               true,
	"certificate-expiry-imminent":               true,
	"pdb-selector-matches-no-pods":              true,
	"persistentvolume-released-stuck":           true,
	"persistentvolume-stuck-terminating":        true,
	"persistentvolumeclaim-stuck-terminating":   true,
	"pod-stuck-terminating":                     true,
	"hpa-pegged-at-max-replicas":                true,
	"flux-kustomization-reconciliation-stalled": true,
	"flux-helmrelease-reconciliation-stalled":   true,
	"namespace-stuck-terminating":               true,
	"velero-backup-partially-failed":            true,
	"argo-application-health-degraded":          true,
	"flux-gitrepository-reconciliation-stalled": true,
	"deployment-paused":                         true,
	"deployment-observedgeneration-behind":      true,
	"daemonset-rollout-stalled":                 true,
	"statefulset-rollout-stalled":               true,
	"persistentvolume-failed":                   true,
	"deployment-rollout-stalled":                true,
	"deployment-scaled-to-zero":                 true,
	"deployment-revision-history-limit-zero":    true,
	"pod-evicted-not-cleaned-up":                true,
	"node-cordoned-sustained":                   true,
	"argo-application-out-of-sync":              true,
	"argo-application-sync-unknown":             true,
	"flux-kustomization-suspended":              true,
	"flux-helmrelease-suspended":                true,
	"flux-gitrepository-suspended":              true,
	"velero-backup-failed":                      true,
	"velero-restore-partially-failed":           true,
	"velero-restore-failed":                     true,
	"statefulset-partition-blocks-rollout":      true,
	// BACKLOG.md E10 (2026-09-01): the format's first two new predicate
	// kinds, "posture audit of a healthy object" (comparatorNotPresent) and
	// "a property of a SET of objects" (comparatorAllPodsSameValue).
	"job-missing-active-deadline-seconds": true,
	"deployment-all-replicas-single-node": true,
	// BACKLOG.md E10/AK1 (2026-09-04): the cheapest open work named in that
	// item — a default rule for an already-built comparator (notPresent),
	// not a new predicate kind, so it does not reopen the "do not extend
	// further" decision.
	"statefulset-missing-pvc-retention-policy": true,
}

// detectionSettingsView is the detection layer's first real, hub-side,
// live-editable configuration (internal/settings.Config's doc comment and
// migration 000026_detection_settings have the full rationale) — a
// top-level sibling of llm/notify/analysis/automation/retention, not nested
// under any of them: it configures which detectors' output the hub accepts
// at all, and how many brand-new incidents a single cluster may produce in
// a rolling window, neither of which is about the AI provider, the
// investigation loop, automatic investigation, or data retention.
//
// DisabledDetectorIDs/StormProtectionMaxNewIncidents/
// StormProtectionWindowSeconds are the literal org_settings column values,
// echoed straight back — none is a secret. DisabledDetectorIDs is always a
// non-nil (possibly empty) array on the wire, matching
// AutomationSettings.AutoAnalysisSeverities' precedent. The two
// storm-protection fields are both null (unlimited, the shipped default) or
// both a positive number — see putSettingsRequest's validation for why a
// mismatched pair is rejected before it can ever be stored.
//
// This is a genuinely partial slice of lld/06-detection-framework.md's
// fuller design (the RemediationPolicy CRD, a cluster-side controller,
// true per-detector precedence resolution) — see this file's and
// internal/gateway/finding.go's doc comments for exactly what's real here
// and what isn't.
// DisabledRuleIDs is BUGS.md 111's rule-level control, alongside
// DisabledDetectorIDs above — see internal/settings.Config's DisabledRuleIDs
// doc comment for the full rationale. Same non-nil-on-the-wire normalization
// as DisabledDetectorIDs.
type detectionSettingsView struct {
	DisabledDetectorIDs            []string `json:"disabledDetectorIds"`
	StormProtectionMaxNewIncidents *int     `json:"stormProtectionMaxNewIncidents"`
	StormProtectionWindowSeconds   *int     `json:"stormProtectionWindowSeconds"`
	DisabledRuleIDs                []string `json:"disabledRuleIds"`
}

// autonomySettingsView is the DB-backed override for
// internal/orchestrator.DefaultAutonomyPolicy — the gap WORKLOG.md §50
// flagged explicitly ("no DB-backed config exists yet") and migration
// 000028_autonomy_policy closes. A top-level sibling of
// llm/notify/analysis/automation/retention/detection, not nested under any
// of them: this configures internal/remediation.Evaluate's autonomy
// CEILING for internal/orchestrator.Advance's gate, unrelated to the AI
// provider, the investigation loop's bounds, whether investigation happens
// automatically, data retention, or the detection layer.
//
// AutoApproveMaxRisk/MinConfidenceForAutoApprove are the literal
// org_settings column values, echoed straight back — neither is a secret.
// null means "not configured in the DB" — unlike DetectionSettings'
// null-means-off convention, this null does NOT mean "never auto-approve";
// it means "fall back to internal/orchestrator.DefaultAutonomyPolicy's own
// conservative value," mirroring AnalysisSettings' maxIterations/
// timeLimitSeconds null-means-consult-a-further-tier convention (see
// internal/settings.Config's AutonomyAutoApproveMaxRisk doc comment).
// EffectiveAutoApproveMaxRisk/EffectiveMinConfidenceForAutoApprove are
// always a concrete value — whatever ResolveAutonomyPolicy would actually
// apply to the very next investigation — the same "show what the fallback
// currently resolves to" pattern AnalysisSettings' Effective* pair already
// established.
//
// RequireReversibleForAutoApprove is now (BUGS.md 97, migration 000085) a
// *bool, following AutoApproveMaxRisk/MinConfidenceForAutoApprove's exact
// contract rather than standing apart from it: null means "not configured
// in the DB" and EffectiveRequireReversibleForAutoApprove is the concrete
// value ResolveAutonomyPolicy would actually apply (DefaultAutonomyPolicy's
// true when null). It used to be a plain bool, echoed straight back, on the
// theory that the column was NOT NULL DEFAULT true so there was no
// "unconfigured" state worth representing — but that meant a PUT whose
// "autonomy" section omitted this key decoded to false, the permissive
// direction, and silently weakened the gate. See that bug entry for the
// live incident this caused.
//
// This section does NOT configure, and cannot weaken,
// internal/remediation.Evaluate's hard, non-configurable high-risk+
// irreversible safety floor (WORKLOG.md §31) — that check runs
// unconditionally, before any AutonomyPolicy field is consulted. See
// handlePutSettings' validation and internal/orchestrator.ResolveAutonomyPolicy's
// own doc comment for the full reasoning.
type autonomySettingsView struct {
	AutoApproveMaxRisk              *string  `json:"autoApproveMaxRisk"`
	MinConfidenceForAutoApprove     *float64 `json:"minConfidenceForAutoApprove"`
	RequireReversibleForAutoApprove *bool    `json:"requireReversibleForAutoApprove"`
	// UnattendedExecutionEnabled is TRUE auto-approve: an AutoApprove verdict
	// actually executing without a human (BUGS.md 39). false unless deliberately
	// turned on, which preserves the invariant every other doc states.
	UnattendedExecutionEnabled bool `json:"unattendedExecutionEnabled"`
	// The blast-radius caps, which ship WITH the switch rather than after it
	// (DESIGN.md §10.5). null means "the conservative fallback", never "no
	// limit" — so Effective* below is what the UI must show, exactly as it
	// already does for the risk and confidence floors.
	MaxUnattendedPerCluster *int `json:"maxUnattendedPerCluster"`
	MaxUnattendedFleetWide  *int `json:"maxUnattendedFleetWide"`
	UnattendedWindowSeconds *int `json:"unattendedWindowSeconds"`
	// Namespaces unattended execution may act in. Empty means nowhere —
	// see migration 000055 for why an empty allowlist denies.
	UnattendedNamespaces                 []string `json:"unattendedNamespaces"`
	EffectiveMaxUnattendedPerCluster     int      `json:"effectiveMaxUnattendedPerCluster"`
	EffectiveMaxUnattendedFleetWide      int      `json:"effectiveMaxUnattendedFleetWide"`
	EffectiveUnattendedWindowSeconds     int      `json:"effectiveUnattendedWindowSeconds"`
	EffectiveAutoApproveMaxRisk          string   `json:"effectiveAutoApproveMaxRisk"`
	EffectiveMinConfidenceForAutoApprove float64  `json:"effectiveMinConfidenceForAutoApprove"`
	// EffectiveRequireReversibleForAutoApprove joins the other two Effective
	// fields above (BUGS.md 97, migration 000085) now that
	// RequireReversibleForAutoApprove is nullable too.
	EffectiveRequireReversibleForAutoApprove bool `json:"effectiveRequireReversibleForAutoApprove"`
}

// costSettingsView is the operator-configured LLM pricing table and the
// hard daily spend ceiling (DESIGN.md §16.4) — a top-level
// sibling of llm/notify/analysis/automation/retention/detection/autonomy,
// not nested under "llm": it's a genuinely distinct concern (turning
// already-real token counts into a real dollar figure, and capping how
// much of that a day may accumulate), unrelated to which provider endpoint
// is configured. Closes the gap WORKLOG.md §28/§49 both documented rather
// than papered over — analyses.cost_usd has always been a real, honest 0
// because no per-model USD pricing table existed anywhere in this
// codebase — together with internal/authz.CapSpendRead/CapSpendManage,
// declared in the capability catalogue from the start but never
// implemented by anything until now (see this file's handleGetSpendToday
// sibling, spend.go, for CapSpendRead's first real use).
//
// PricePerMillionInputTokens/PricePerMillionCachedTokens/
// PricePerMillionOutputTokens are the literal org_settings column values,
// echoed straight back — none is a secret. All three are null (the shipped
// default) until an operator sets them; internal/settings.Config's
// ComputeCostUSD (called from internal/api.PersistAnalysis, analyze.go)
// treats "not all three set" as "no pricing table configured" and computes
// a real, honest cost_usd of exactly 0 — never a guessed, hardcoded
// per-model rate. PricingConfigured mirrors that same
// internal/settings.Config.CostPricingConfigured() check so the UI never
// has to re-derive "are all three set" from three raw nullable numbers
// itself.
//
// DailySpendCeilingUsd is null by default too ("no ceiling," today's actual
// unbounded behavior, unchanged until an operator sets one) — see
// internal/autoanalyze's own doc comment for exactly how a configured
// ceiling is enforced on the automatic path, and internal/api/analyze.go's
// handleAnalyzeIncident doc comment for why the manual path deliberately
// does NOT block on it.
//
// TodaySpendUsd is NOT an org_settings column — it's the real, current
// answer to "how much have we actually spent today" (spend.go's
// TodaySpendUSD), computed the exact same way SpendCeilingBreached checks
// it, so an operator watching this screen sees the same number the ceiling
// check itself compares against, not a second, possibly-drifted copy of
// that logic. handleGetSettings/handlePutSettings both populate it via a
// real query against `analyses` (rc.Tx-scoped — see those handlers) after
// building the rest of this struct from cfg alone.
// SpendCountable/CeilingEnforceable answer the question this section could
// not answer before: whether the ceiling configured here is a control that can
// actually fire. Pricing being configured is necessary and NOT sufficient —
// under a CLI/subscription provider every real analysis records a notional
// cost that spend.go's TodaySpend deliberately excludes from the sum the
// ceiling checks, so the ceiling cannot be reached however low it is set. See
// internal/settings.Config.ActiveProviderSpendCountable/
// SpendCeilingEnforceable for the mechanism, and why the second is descriptive
// only and does not gate enforcement.
//
// Reported here, rather than left for the screen to infer from
// llm.providerKind, for exactly PricingConfigured's own reason: a claim a
// guardrail is working is not something the UI should re-derive from raw
// fields, because the two derivations drift and only one of them is the one
// enforcement uses. CeilingEnforceable describes the SAVED ceiling;
// SpendCountable is independent of it, which is what lets the screen state the
// enforcement consequence of a ceiling the operator is still typing.
type costSettingsView struct {
	PricePerMillionInputTokens  *float64 `json:"pricePerMillionInputTokens"`
	PricePerMillionCachedTokens *float64 `json:"pricePerMillionCachedTokens"`
	PricePerMillionOutputTokens *float64 `json:"pricePerMillionOutputTokens"`
	PricingConfigured           bool     `json:"pricingConfigured"`
	SpendCountable              bool     `json:"spendCountable"`
	DailySpendCeilingUsd        *float64 `json:"dailySpendCeilingUsd"`
	CeilingEnforceable          bool     `json:"ceilingEnforceable"`
	TodaySpendUsd               float64  `json:"todaySpendUsd"`
	// CeilingBreached is SpendCeilingBreached's own answer, not "is
	// todaySpendUsd >= dailySpendCeilingUsd" — those differ, and the
	// difference is the point. The screen used to compute the comparison
	// itself, which meant it could render "ceiling reached" on a total the
	// hub's check was not even looking at (no pricing configured, so
	// SpendCeilingActive is false and nothing is ever blocked) while the
	// hub's own enforcement did nothing. Same reason as TodaySpendUsd: set
	// by the handlers, not by settingsResponseFromConfig, because it needs
	// a real query against `analyses`.
	CeilingBreached bool `json:"ceilingBreached"`
}

func settingsResponseFromConfig(cfg settings.Config, cliBackendAvailable bool) settingsResponse {
	effectiveMaxIterations := llm.DefaultMaxIterations
	if cfg.AnalysisMaxIterations != nil {
		effectiveMaxIterations = *cfg.AnalysisMaxIterations
	}
	effectiveTimeLimitSeconds := int(llm.DefaultTimeLimit.Seconds())
	if cfg.AnalysisTimeLimitSeconds != nil {
		effectiveTimeLimitSeconds = *cfg.AnalysisTimeLimitSeconds
	}

	// Normalized to a non-nil (possibly empty) slice before marshaling —
	// see outboundSettingsView's doc comment; same reason as the severities
	// below.
	privateDestinations := make([]outboundPrivateDestinationView, 0, len(cfg.OutboundPrivateDestinations))
	for _, d := range cfg.OutboundPrivateDestinations {
		privateDestinations = append(privateDestinations, outboundPrivateDestinationView{Destination: d.Destination, Reason: d.Reason})
	}

	// Normalized to a non-nil (possibly empty) slice before marshaling —
	// see automationSettingsView's doc comment for why this field is never
	// null on the wire.
	autoAnalysisSeverities := cfg.AutoAnalysisSeverities
	if autoAnalysisSeverities == nil {
		autoAnalysisSeverities = []string{}
	}
	// Same normalisation, same reason: a JSON `null` where the client expects a
	// list makes every consumer handle two shapes for one meaning. For this field
	// it matters a little more than usual, because `[]` is the *load-bearing*
	// value — it is what says "no namespace is permitted" — and rendering that as
	// `null` invites a reader to see "unset" instead.
	unattendedNamespaces := cfg.AutonomyUnattendedNamespaces
	if unattendedNamespaces == nil {
		unattendedNamespaces = []string{}
	}

	// Same non-nil-on-the-wire normalization as autoAnalysisSeverities above
	// — see detectionSettingsView's doc comment.
	disabledDetectorIDs := cfg.DisabledDetectorIDs
	if disabledDetectorIDs == nil {
		disabledDetectorIDs = []string{}
	}
	// Same non-nil-on-the-wire normalization, for BUGS.md 111's rule-level
	// sibling field.
	disabledRuleIDs := cfg.DisabledRuleIDs
	if disabledRuleIDs == nil {
		disabledRuleIDs = []string{}
	}

	// The autonomy section's Effective* pair: whatever
	// orchestrator.ResolveAutonomyPolicy would actually apply to the very
	// next investigation, computed the exact same way ApplyAnalysisResult
	// does — this is what lets the UI show "using the fallback: low / 0.90"
	// even while the raw fields are null, the same pattern
	// EffectiveMaxIterations/EffectiveTimeLimitSeconds above already
	// established.
	effectivePolicy := orchestrator.ResolveAutonomyPolicy(cfg)
	effectiveUnattended := orchestrator.ResolveUnattendedLimits(
		cfg.AutonomyUnattendedExecutionEnabled, cfg.AutonomyMaxUnattendedPerCluster,
		cfg.AutonomyMaxUnattendedFleetWide, cfg.AutonomyUnattendedWindowSeconds)

	return settingsResponse{
		LLM: llmSettingsView{
			BaseURL:   cfg.LLMBaseURL,
			Model:     cfg.LLMModel,
			APIKeySet: cfg.LLMAPIKeySet,
			// Normalized again here, not just trusted from Config: Resolve
			// already does it, but this function is also called with
			// hand-built Configs (tests, and any future caller), and
			// ProviderKind's documented contract is that a client never sees
			// "". Cheap to guarantee at the boundary that promises it.
			ProviderKind:      settings.NormalizeProviderKind(cfg.LLMProviderKind),
			CLIRunnerURL:      cfg.CLIRunnerURL,
			CLIAgent:          cfg.CLIAgent,
			CLIRunnerTokenSet: cfg.CLIRunnerTokenSet,
			// Not from cfg: this is a property of how the HUB was started, not
			// of what an admin saved.
			CLIBackendAvailable: cliBackendAvailable,
		},
		Appearance: appearanceSettingsView{
			// Normalised again rather than passed through. settings.Resolve
			// guarantees a valid value, but this function is a pure mapping
			// from whatever Config it is handed (its own tests construct one
			// directly), and a Settings page whose style selector has nothing
			// selected is worse than one showing the default it is in fact
			// serving.
			LoginStyle:                normalisedLoginStyle(cfg.LoginStyle),
			Styles:                    settings.LoginStyles,
			PrimaryColorID:            normalisedPrimaryColorID(cfg.PrimaryColorID),
			PrimaryColorOptions:       settings.PrimaryColorIDs,
			OverviewDefaultWindowDays: normalisedOverviewWindow(cfg.OverviewDefaultWindowDays),
		},
		General: generalSettingsView{
			MinPasswordLength:         cfg.MinPasswordLength,
			SessionIdleTimeoutMinutes: cfg.SessionIdleTimeoutMinutes,
		},
		Notify: notifySettingsView{
			WebhookConfigured: cfg.NotifyWebhookConfigured,
		},
		Analysis: analysisSettingsView{
			MaxIterations:             cfg.AnalysisMaxIterations,
			TimeLimitSeconds:          cfg.AnalysisTimeLimitSeconds,
			EffectiveMaxIterations:    effectiveMaxIterations,
			EffectiveTimeLimitSeconds: effectiveTimeLimitSeconds,
			RetrievalEnabled:          cfg.RetrievalEnabled,
		},
		Automation: automationSettingsView{
			AutoAnalysisEnabled:    cfg.AutoAnalysisEnabled,
			AutoAnalysisSeverities: autoAnalysisSeverities,
		},
		Retention: retentionSettingsView{
			AuditRetentionDays:    cfg.AuditRetentionDays,
			IncidentRetentionDays: cfg.IncidentRetentionDays,
			FindingRetentionDays:  cfg.FindingRetentionDays,
		},
		Detection: detectionSettingsView{
			DisabledDetectorIDs:            disabledDetectorIDs,
			StormProtectionMaxNewIncidents: cfg.StormProtectionMaxNewIncidents,
			StormProtectionWindowSeconds:   cfg.StormProtectionWindowSeconds,
			DisabledRuleIDs:                disabledRuleIDs,
		},
		Autonomy: autonomySettingsView{
			AutoApproveMaxRisk:              cfg.AutonomyAutoApproveMaxRisk,
			MinConfidenceForAutoApprove:     cfg.AutonomyMinConfidenceForAutoApprove,
			RequireReversibleForAutoApprove: cfg.AutonomyRequireReversibleForAutoApprove,
			UnattendedExecutionEnabled:      cfg.AutonomyUnattendedExecutionEnabled,
			MaxUnattendedPerCluster:         cfg.AutonomyMaxUnattendedPerCluster,
			MaxUnattendedFleetWide:          cfg.AutonomyMaxUnattendedFleetWide,
			UnattendedWindowSeconds:         cfg.AutonomyUnattendedWindowSeconds,
			UnattendedNamespaces:            unattendedNamespaces,
			// Effective*, like the risk/confidence pair above: what would
			// actually apply, so the UI can show "using the fallback: 3 / 10 /
			// 1h" while the raw fields are null. A blank field here means the
			// fallback, never "unlimited", and this is what makes that visible.
			EffectiveMaxUnattendedPerCluster:         effectiveUnattended.MaxPerCluster,
			EffectiveMaxUnattendedFleetWide:          effectiveUnattended.MaxFleetWide,
			EffectiveUnattendedWindowSeconds:         int(effectiveUnattended.Window.Seconds()),
			EffectiveAutoApproveMaxRisk:              string(effectivePolicy.AutoApproveMaxRisk),
			EffectiveMinConfidenceForAutoApprove:     effectivePolicy.MinConfidenceForAutoApprove,
			EffectiveRequireReversibleForAutoApprove: effectivePolicy.RequireReversibleForAutoApprove,
		},
		// TodaySpendUsd is deliberately left at its zero value here —
		// settingsResponseFromConfig is pure and DB-free (see
		// TestSettingsResponseFromConfigNeverLeaksSecrets et al.), but
		// today's real spend needs a live query against `analyses`.
		// handleGetSettings/handlePutSettings both set it on the returned
		// response themselves, right after calling this function.
		Outbound: outboundSettingsView{PrivateDestinations: privateDestinations},
		Posture:  postureSettingsView{DisabledChecks: nonNilStrings(cfg.PostureDisabledChecks), IgnoredNamespaces: nonNilStrings(cfg.PostureIgnoredNamespaces)},
		Cost: costSettingsView{
			PricePerMillionInputTokens:  cfg.PricePerMillionInputTokens,
			PricePerMillionCachedTokens: cfg.PricePerMillionCachedTokens,
			PricePerMillionOutputTokens: cfg.PricePerMillionOutputTokens,
			PricingConfigured:           cfg.CostPricingConfigured(),
			SpendCountable:              cfg.ActiveProviderSpendCountable(),
			DailySpendCeilingUsd:        cfg.DailySpendCeilingUsd,
			CeilingEnforceable:          cfg.SpendCeilingEnforceable(),
		},
	}
}

// handleGetSettings is GET /api/v1/admin/settings. Requires
// org:settings:write (see this file's doc comment for why GET uses the
// write capability). Reads via the pool directly (settings.Resolve accepts
// either) rather than rc.Tx — org_settings carries no RLS, and a plain read
// has no atomicity to preserve with anything else in this request, unlike
// the PUT handler below.
func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	cfg, err := settings.Resolve(ctx, s.db.Pool)
	if err != nil {
		logger.ErrorContext(ctx, "resolving the settings failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not read settings", "")
		return
	}
	resp := settingsResponseFromConfig(cfg, s.cliBackendAvailable())
	// TodaySpendUsd needs a real query against `analyses`, which carries
	// RLS (unlike org_settings, which settings.Resolve just read via the
	// bare pool above) — rc.Tx is already tenant-scoped by requireAuth, so
	// it's used here instead of s.db.Pool for this one query.
	todaySpend, err := TodaySpendUSD(ctx, rc.Tx)
	if err != nil {
		logger.ErrorContext(ctx, "computing today's spend failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not read settings", "")
		return
	}
	resp.Cost.TodaySpendUsd = todaySpend
	resp.Cost.CeilingBreached = SpendCeilingBreached(cfg, todaySpend)
	writeJSON(w, http.StatusOK, resp)
}

// putLLMSettingsRequest is the "llm" section of a PUT request body.
// BaseURL/Model are plain strings, always overwritten if this section is
// present at all — they aren't secret and GET already returns them in full,
// so there's no "leave unchanged" ambiguity worth adding pointer semantics
// for (see internal/settings.LLMUpdate's doc comment). APIKey follows the
// documented pointer contract: the key ABSENT from the JSON body (nil)
// means leave the stored value unchanged; present as "" means explicitly
// clear it.
type putLLMSettingsRequest struct {
	BaseURL string  `json:"baseUrl"`
	Model   string  `json:"model"`
	APIKey  *string `json:"apiKey"`

	// ProviderKind/CLIRunnerURL/CLIAgent follow BaseURL/Model's
	// always-overwrite contract; CLIRunnerToken follows APIKey's pointer
	// contract, being the other secret in this section. Validated by
	// validateLLMSettingsRequest before it reaches internal/settings.
	ProviderKind   string  `json:"providerKind"`
	CLIRunnerURL   string  `json:"cliRunnerUrl"`
	CLIAgent       string  `json:"cliAgent"`
	CLIRunnerToken *string `json:"cliRunnerToken"`
}

// validateLLMSettingsRequest rejects an unrecognized provider kind or agent
// at the edge, with a precise message naming the accepted values.
//
// internal/settings.Update validates the kind again before writing. That
// duplication is deliberate: a bad kind in the column would make every
// subsequent investigation fail org-wide (internal/llm.Router treats an
// unknown kind as a hard error rather than falling back), which is too sharp
// an edge to guard in only one layer.
func validateLLMSettingsRequest(l *putLLMSettingsRequest) error {
	if k := l.ProviderKind; k != "" && k != settings.ProviderKindAPI && k != settings.ProviderKindCLI {
		return fmt.Errorf("llm.providerKind must be %q or %q", settings.ProviderKindAPI, settings.ProviderKindCLI)
	}
	if a := l.CLIAgent; a != "" && a != "claude" && a != "codex" {
		return fmt.Errorf(`llm.cliAgent must be "claude" or "codex"`)
	}
	// Deliberately NOT enforcing "cliRunnerUrl must be set when providerKind
	// is cli": an admin switching kinds in two steps (pick cli, then paste the
	// URL) is a normal flow, and the runtime error from internal/llm.Router is
	// already clear about what is missing. Rejecting the intermediate state
	// would make the UI harder to use without making anything safer.
	return nil
}

// putNotifySettingsRequest is the "notify" section of a PUT request body.
// WebhookURL follows the same absent-vs-empty-string pointer contract as
// putLLMSettingsRequest.APIKey.
type putNotifySettingsRequest struct {
	WebhookURL *string `json:"webhookUrl"`
}

// putAppearanceSettingsRequest is the "appearance" section of a PUT body.
// All three fields are required when the section is present — there is no
// "unset it" case for any of them, because an install always serves SOME
// login screen, SOME primary colour and SOME Overview default, and "none" is
// not a value for any of the three.
type putAppearanceSettingsRequest struct {
	LoginStyle                string `json:"loginStyle"`
	PrimaryColorID            string `json:"primaryColorId"`
	OverviewDefaultWindowDays int    `json:"overviewDefaultWindowDays"`
}

// putGeneralSettingsRequest is the "general" section of a PUT body —
// migration 000131's two account-security floors. MinPasswordLength is
// required when the section is present (not a secret, no "leave unchanged"
// state). SessionIdleTimeoutMinutes follows analysis.maxIterations' contract
// instead: a number sets an explicit idle limit, JSON null (or the key
// absent) explicitly clears it back to "no idle limit".
type putGeneralSettingsRequest struct {
	MinPasswordLength         int  `json:"minPasswordLength"`
	SessionIdleTimeoutMinutes *int `json:"sessionIdleTimeoutMinutes"`
}

// putAnalysisSettingsRequest is the "analysis" section of a PUT request
// body — the investigation loop's bounds. MaxIterations/TimeLimitSeconds are
// plain, always-taken-as-given *int fields once "analysis" is present at
// all: a number sets an explicit override, JSON null explicitly clears it
// back to the env-var/hardcoded-default fallback. Unlike apiKey/webhookUrl
// there's no third "field absent within the object, leave just this one
// unchanged" state to support — these aren't secrets, so (per
// internal/settings.AnalysisUpdate's doc comment) there's no reason to want
// that, and 0/negative already have no valid meaning as a real override.
type putAnalysisSettingsRequest struct {
	MaxIterations    *int `json:"maxIterations"`
	TimeLimitSeconds *int `json:"timeLimitSeconds"`
	// RetrievalEnabled mirrors putAutomationSettingsRequest.Enabled's shape:
	// a plain bool, always taken exactly as given whenever "analysis" is
	// present at all — not a secret, so there is no "leave unchanged" state
	// worth adding.
	RetrievalEnabled bool `json:"retrievalEnabled"`
}

// putAutomationSettingsRequest is the "automation" section of a PUT request
// body — whether newly-detected incidents are automatically investigated,
// and which severities qualify (internal/autoanalyze). Enabled/Severities
// are plain, always-taken-as-given fields once "automation" is present at
// all, the same as putAnalysisSettingsRequest and for the same reason:
// neither is a secret, so there's no "leave just this one field unchanged"
// state worth adding.
//
// Severities replaces the old single MinSeverity threshold with a checklist:
// a plain []string of whichever of low/medium/high/critical the admin
// checked. Absent/null decodes to a nil slice, treated identically to an
// explicit empty array `[]` by handlePutSettings below — either way means
// "nothing selected," which (per internal/settings.AutomationUpdate's doc
// comment) means nothing is eligible for auto-analysis, not "every severity
// qualifies" the way the old field's null used to mean. This is a real,
// valid selection in its own right, not an error state.
type putAutomationSettingsRequest struct {
	Enabled    bool     `json:"autoAnalysisEnabled"`
	Severities []string `json:"autoAnalysisSeverities"`
}

// putRetentionSettingsRequest is the "retention" section of a PUT request
// body. All three fields are plain, always-taken-as-given *int fields once
// "retention" is present at all, the same shape as
// putAnalysisSettingsRequest and for the same reason: none of these is a
// secret, so there's no "leave just this one field unchanged" state worth
// adding. A number sets an explicit, opt-in retention window in days; JSON
// null explicitly clears it back to "keep forever" — which, per
// internal/settings.RetentionUpdate's doc comment, is also this feature's
// shipped default, not a fallback to some other tier.
type putRetentionSettingsRequest struct {
	AuditRetentionDays    *int `json:"auditRetentionDays"`
	IncidentRetentionDays *int `json:"incidentRetentionDays"`
	FindingRetentionDays  *int `json:"findingRetentionDays"`
}

// putDetectionSettingsRequest is the "detection" section of a PUT request
// body — see detectionSettingsView's doc comment. All three fields are
// plain, always-taken-as-given fields once "detection" is present at all,
// the same shape as putRetentionSettingsRequest and for the same reason:
// none of these is a secret. DisabledDetectorIDs absent/null decodes to a
// nil slice, treated identically to an explicit empty array — either way
// means "nothing disabled." StormProtectionMaxNewIncidents/WindowSeconds
// follow putRetentionSettingsRequest's null-means-"no ceiling" contract
// exactly, except the two fields must be set or cleared together — see
// handlePutSettings' validation.
type putDetectionSettingsRequest struct {
	DisabledDetectorIDs            []string `json:"disabledDetectorIds"`
	StormProtectionMaxNewIncidents *int     `json:"stormProtectionMaxNewIncidents"`
	StormProtectionWindowSeconds   *int     `json:"stormProtectionWindowSeconds"`
	// DisabledRuleIDs is BUGS.md 111's rule-level control — same
	// absent/null-decodes-to-nil-treated-as-empty contract as
	// DisabledDetectorIDs above, validated against knownRuleIDs by
	// validateDetectionSettingsRequest below.
	DisabledRuleIDs []string `json:"disabledRuleIds"`
}

// putAutonomySettingsRequest is the "autonomy" section of a PUT request
// body — see autonomySettingsView's doc comment. AutoApproveMaxRisk/
// MinConfidenceForAutoApprove/RequireReversibleForAutoApprove are all plain,
// always-taken-as-given *pointer* fields once "autonomy" is present at all,
// the same shape as putRetentionSettingsRequest and for the same reason:
// none of the three is a secret, so there's no "leave just this one field
// unchanged" state worth adding. A real value sets an explicit override;
// JSON null (or the key simply absent, which this package does not
// distinguish from null) explicitly clears it back to
// internal/orchestrator.DefaultAutonomyPolicy's own hardcoded value (NOT
// "never auto-approve" for AutoApproveMaxRisk — see internal/settings.Config's
// AutonomyAutoApproveMaxRisk doc comment for exactly why this null means
// something different from DetectionSettings' null; for
// RequireReversibleForAutoApprove that hardcoded value is true, the safe
// direction).
//
// RequireReversibleForAutoApprove used to be a plain bool, matching
// putAutomationSettingsRequest.Enabled's shape on the theory that it had no
// "unconfigured" state to represent. BUGS.md 97: that meant a request that
// included "autonomy" while omitting this one key decoded to false — the
// permissive direction for this specific field, since it's the belt-and-
// suspenders check on top of the risk ceiling — silently weakening a safety
// gate with no warning. It is now a *pointer, matching its two siblings.
type putAutonomySettingsRequest struct {
	AutoApproveMaxRisk              *string  `json:"autoApproveMaxRisk"`
	MinConfidenceForAutoApprove     *float64 `json:"minConfidenceForAutoApprove"`
	RequireReversibleForAutoApprove *bool    `json:"requireReversibleForAutoApprove"`
	UnattendedExecutionEnabled      bool     `json:"unattendedExecutionEnabled"`
	MaxUnattendedPerCluster         *int     `json:"maxUnattendedPerCluster"`
	MaxUnattendedFleetWide          *int     `json:"maxUnattendedFleetWide"`
	UnattendedWindowSeconds         *int     `json:"unattendedWindowSeconds"`
	// Namespaces unattended execution may act in. Omitted or empty means nowhere;
	// see migration 000055 for why an empty allowlist denies rather than permits.
	UnattendedNamespaces []string `json:"unattendedNamespaces"`
}

// putCostSettingsRequest is the "cost" section of a PUT request body — see
// costSettingsView's doc comment. All four fields are plain, always-taken-
// as-given *float64 fields once "cost" is present at all, the same shape as
// putRetentionSettingsRequest and for the same reason: none of these is a
// secret. A real value sets an explicit price/ceiling; JSON null explicitly
// clears it back to "no pricing configured" / "no ceiling" — there is no
// further fallback tier for either, unlike e.g. analysis.maxIterations'
// env-var/hardcoded-default tiers.
type putCostSettingsRequest struct {
	PricePerMillionInputTokens  *float64 `json:"pricePerMillionInputTokens"`
	PricePerMillionCachedTokens *float64 `json:"pricePerMillionCachedTokens"`
	PricePerMillionOutputTokens *float64 `json:"pricePerMillionOutputTokens"`
	DailySpendCeilingUsd        *float64 `json:"dailySpendCeilingUsd"`
}

// validAutoApproveMaxRiskLevels is internal/remediation.RiskLevel's closed
// low/medium/high set, re-checked here for the same reason
// validAutoAnalysisSeverities is: a clear 400 at the API boundary instead of
// an opaque 500 off migration 000028's own CHECK constraint. Deliberately
// excludes "forbidden" — DESIGN.md §9.3's fourth risk tier
// has no representative action type in internal/remediation's closed
// ActionType set yet (see plan.go's own comment), so it stays unmodeled
// here too, matching internal/remediation.RiskLevel's actual Go-level enum
// exactly rather than the fuller table in the design doc.
var validAutoApproveMaxRiskLevels = map[string]bool{
	"low": true, "medium": true, "high": true,
}

// validAutoAnalysisSeverities is the four-value severity enum this codebase
// uses everywhere else (internal/tunnel/protocol.go's Finding.Severity doc
// comment; mirrored in migration 000024_auto_analysis_severities' CHECK
// constraint) — re-checked here too so a typo'd severity gets a clear 400 at
// the API boundary instead of silently failing the DB's CHECK constraint
// with an opaque 500, or (if the CHECK constraint is ever loosened) silently
// storing a value internal/autoanalyze's set-membership check doesn't
// recognize and would then just never match.
var validAutoAnalysisSeverities = map[string]bool{
	"low": true, "medium": true, "high": true, "critical": true,
}

// putSettingsRequest: LLM/Notify/Analysis/Automation are themselves pointers
// to a struct, so a request that omits an entire section ({"notify": {...}}
// with no "llm"/"analysis"/"automation" key at all) leaves that whole
// section untouched, not just its secret field. Provide "llm" at all, and
// baseUrl/model are taken as given (a key missing WITHIN that object decodes
// to "", clearing it — see putLLMSettingsRequest's doc comment for why
// that's the deliberate, documented behavior for those two fields
// specifically).
type putSettingsRequest struct {
	LLM        *putLLMSettingsRequest        `json:"llm"`
	Notify     *putNotifySettingsRequest     `json:"notify"`
	Analysis   *putAnalysisSettingsRequest   `json:"analysis"`
	Automation *putAutomationSettingsRequest `json:"automation"`
	Retention  *putRetentionSettingsRequest  `json:"retention"`
	Detection  *putDetectionSettingsRequest  `json:"detection"`
	Autonomy   *putAutonomySettingsRequest   `json:"autonomy"`
	Cost       *putCostSettingsRequest       `json:"cost"`
	Appearance *putAppearanceSettingsRequest `json:"appearance"`
	General    *putGeneralSettingsRequest    `json:"general"`
	Outbound   *putOutboundSettingsRequest   `json:"outbound"`
	Posture    *putPostureSettingsRequest    `json:"posture"`
}

// putPostureSettingsRequest is the "posture" section: both lists taken
// exactly as given whenever the section is present.
type putPostureSettingsRequest struct {
	DisabledChecks    []string `json:"disabledChecks"`
	IgnoredNamespaces []string `json:"ignoredNamespaces"`
}

var (
	postureCheckIDPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)
	postureNamespacePattern = regexp.MustCompile(`^\*?[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?-?\*?$`)
)

// validatePostureSettingsRequest checks the shape only: check IDs are the
// agent's to define, so an ID no agent knows simply matches nothing.
func validatePostureSettingsRequest(p *putPostureSettingsRequest) error {
	if p == nil {
		return nil
	}
	if len(p.DisabledChecks) > 200 || len(p.IgnoredNamespaces) > 200 {
		return fmt.Errorf("at most 200 entries per list")
	}
	for _, c := range p.DisabledChecks {
		if !postureCheckIDPattern.MatchString(c) {
			return fmt.Errorf("%q is not a check ID", c)
		}
	}
	for _, ns := range p.IgnoredNamespaces {
		if !postureNamespacePattern.MatchString(ns) || ns == "*" {
			return fmt.Errorf("%q is not a namespace name or a prefix*/ *suffix pattern", ns)
		}
	}
	return nil
}

// putOutboundSettingsRequest is the "outbound" section of a PUT request body.
//
// Follows the per-SECTION contract every other list-valued section uses:
// present the section at all and privateDestinations is taken exactly as
// given, including an empty or absent list clearing every exception back to
// plain default-deny. There is deliberately no per-entry merge — removing an
// exception is the operation that matters most on a list of security
// exceptions, and a merge semantics would make it unexpressible.
type putOutboundSettingsRequest struct {
	PrivateDestinations []putOutboundPrivateDestination `json:"privateDestinations"`
}

type putOutboundPrivateDestination struct {
	Destination string `json:"destination"`
	Reason      string `json:"reason"`
}

// validateOutboundSettingsRequest rejects a malformed allowlist at the edge,
// with the message internal/outbound itself produced.
//
// It delegates to outbound.ParseAllowlist rather than restating the rules,
// which is the whole point: the code that decides whether an entry is
// acceptable at the API boundary is the same code that decides whether it
// permits a dial. A second implementation here would be a place for the two
// to disagree, and the disagreement that matters — the API accepting
// something the dialler then treats differently — is exactly the kind that
// shows up as a support ticket rather than as a test failure.
func validateOutboundSettingsRequest(o *putOutboundSettingsRequest) error {
	if o == nil {
		return nil
	}
	entries := make([]outbound.AllowlistEntry, 0, len(o.PrivateDestinations))
	for _, d := range o.PrivateDestinations {
		entries = append(entries, outbound.AllowlistEntry{Destination: d.Destination, Reason: d.Reason})
	}
	if _, err := outbound.ParseAllowlist(entries); err != nil {
		return err
	}
	return nil
}

// validateAutonomySettingsRequest implements autonomySettingsView/
// putAutonomySettingsRequest's own documented validation rules: AutoApprove
// MaxRisk (if present) must be one of the real, closed risk levels, and
// MinConfidenceForAutoApprove (if present) must fall in [0,1] — the same
// range internal/remediation.Evaluate itself already enforces on a plan's
// confidence, re-checked here for a clear 400 instead of an opaque 500 off
// migration 000028's CHECK constraints. Pulled out as its own pure function,
// like validateDetectionSettingsRequest, so it's unit-testable with no HTTP
// request/response or database involved. A nil a (the "autonomy" section
// was absent from the request) is always valid: there's nothing to
// validate — and, not incidentally, nothing here can ever loosen
// internal/remediation.Evaluate's hard, non-configurable high-risk+
// irreversible safety floor, since that check has no field this section
// (or the AutonomyPolicy built from it) could set to disable it.
func validateAutonomySettingsRequest(a *putAutonomySettingsRequest) error {
	if a == nil {
		return nil
	}
	if a.AutoApproveMaxRisk != nil && !validAutoApproveMaxRiskLevels[*a.AutoApproveMaxRisk] {
		return fmt.Errorf("invalid autonomy.autoApproveMaxRisk: %q is not a known risk level (low, medium, high), or null to fall back to the default", *a.AutoApproveMaxRisk)
	}
	if a.MinConfidenceForAutoApprove != nil && (*a.MinConfidenceForAutoApprove < 0 || *a.MinConfidenceForAutoApprove > 1) {
		return fmt.Errorf("invalid autonomy.minConfidenceForAutoApprove: %v is outside the valid [0,1] range", *a.MinConfidenceForAutoApprove)
	}
	// The three blast-radius caps are rejected at zero and below rather than
	// quietly coerced, and the message says why: orchestrator.
	// ResolveUnattendedLimits treats a non-positive value as "fall back to the
	// default", so an operator who typed 0 meaning "never execute anything
	// unattended" would get 3 — the exact opposite of what they asked for, with
	// no error to tell them. Refusing here is the only place that reading can be
	// caught, since by the time the value reaches the resolver both intentions
	// look identical.
	for _, limit := range []struct {
		field string
		value *int
	}{
		{"maxUnattendedPerCluster", a.MaxUnattendedPerCluster},
		{"maxUnattendedFleetWide", a.MaxUnattendedFleetWide},
		{"unattendedWindowSeconds", a.UnattendedWindowSeconds},
	} {
		if limit.value != nil && *limit.value <= 0 {
			return fmt.Errorf("invalid autonomy.%s: %d is not a limit. Use null to fall back to the conservative default, "+
				"or clear unattendedExecutionEnabled to switch unattended execution off — a zero here would be read as "+
				"\"unconfigured\" and silently become the default", limit.field, *limit.value)
		}
	}
	// A cluster is part of the fleet, so a per-cluster cap above the fleet-wide
	// one is unreachable by construction: the fleet counter would always trip
	// first. Refused rather than accepted-and-ignored, because a number an
	// operator can see on the settings page that can never apply is worse than
	// no number at all.
	//
	// Compared on the RESOLVED values, not the raw ones — a per-cluster 20 with
	// the fleet cap left blank is just as unreachable as a per-cluster 20
	// against an explicit fleet 10, and checking only the both-set case would
	// wave the more likely of the two mistakes through.
	effective := orchestrator.ResolveUnattendedLimits(
		a.UnattendedExecutionEnabled, a.MaxUnattendedPerCluster, a.MaxUnattendedFleetWide, a.UnattendedWindowSeconds)
	if effective.MaxPerCluster > effective.MaxFleetWide {
		return fmt.Errorf("invalid autonomy caps: the per-cluster limit (%d) is above the fleet-wide limit (%d), "+
			"which can never take effect — a single cluster's executions all count towards the fleet total, so the "+
			"fleet limit would always be reached first. Raise the fleet-wide limit as well, or lower this one",
			effective.MaxPerCluster, effective.MaxFleetWide)
	}
	return nil
}

// validateCostSettingsRequest implements costSettingsView/
// putCostSettingsRequest's own documented validation rules: the three price
// fields must be either ALL null or ALL set — never a partial table, which
// would compute a systematically wrong cost (see migration
// 000029_cost_settings' comment) — each set price must be zero or positive,
// and dailySpendCeilingUsd, if set, must be a positive number. Pulled out as
// its own pure function, like validateDetectionSettingsRequest/
// validateAutonomySettingsRequest, so it's unit-testable with no HTTP
// request/response or database involved. A nil c (the "cost" section was
// absent from the request) is always valid: there's nothing to validate.
func validateCostSettingsRequest(c *putCostSettingsRequest) error {
	if c == nil {
		return nil
	}

	set := 0
	if c.PricePerMillionInputTokens != nil {
		set++
	}
	if c.PricePerMillionCachedTokens != nil {
		set++
	}
	if c.PricePerMillionOutputTokens != nil {
		set++
	}
	if set != 0 && set != 3 {
		return errors.New("invalid cost pricing: pricePerMillionInputTokens, pricePerMillionCachedTokens, and " +
			"pricePerMillionOutputTokens must all be set together, or all left null — a partial price table would " +
			"compute a systematically wrong cost, which is worse than the honest 0 that null leaves in place")
	}
	if c.PricePerMillionInputTokens != nil && *c.PricePerMillionInputTokens < 0 {
		return fmt.Errorf("invalid cost.pricePerMillionInputTokens: %v must be zero or a positive number, or null", *c.PricePerMillionInputTokens)
	}
	if c.PricePerMillionCachedTokens != nil && *c.PricePerMillionCachedTokens < 0 {
		return fmt.Errorf("invalid cost.pricePerMillionCachedTokens: %v must be zero or a positive number, or null", *c.PricePerMillionCachedTokens)
	}
	if c.PricePerMillionOutputTokens != nil && *c.PricePerMillionOutputTokens < 0 {
		return fmt.Errorf("invalid cost.pricePerMillionOutputTokens: %v must be zero or a positive number, or null", *c.PricePerMillionOutputTokens)
	}
	if c.DailySpendCeilingUsd != nil && *c.DailySpendCeilingUsd <= 0 {
		return fmt.Errorf("invalid cost.dailySpendCeilingUsd: %v must be a positive number, or null to disable the daily spend ceiling", *c.DailySpendCeilingUsd)
	}
	return nil
}

// validateDetectionSettingsRequest implements
// lld/06-detection-framework.md §7's own validation rule ("a
// dedup.windowSeconds of zero or unset alongside a nonzero minOccurrences
// ... is meaningless and silently never fires — better to reject than to
// ship a policy that looks configured but does nothing"), applied here to
// storm protection's identical shape, plus the detector-ID checklist
// validation automation's severities checklist already established the
// pattern for. Pulled out as its own pure function (unlike every sibling
// validation block in handlePutSettings, which write directly to the
// ResponseWriter) so it's unit-testable with no HTTP request/response or
// database involved at all — see settings_test.go. A nil d (the "detection"
// section was absent from the request) is always valid: there's nothing to
// validate.
func validateDetectionSettingsRequest(d *putDetectionSettingsRequest) error {
	if d == nil {
		return nil
	}

	seen := make(map[string]bool, len(d.DisabledDetectorIDs))
	for _, id := range d.DisabledDetectorIDs {
		if !knownDetectorIDs[id] {
			return fmt.Errorf("invalid detection.disabledDetectorIds: %q is not a known detector ID (k8s-warning-events, k8s-pod-conditions, k8s-sweep)", id)
		}
		if seen[id] {
			return fmt.Errorf("invalid detection.disabledDetectorIds: duplicate detector ID %q", id)
		}
		seen[id] = true
	}

	// BUGS.md 111: same unknown/duplicate rejection as disabledDetectorIds
	// above, against knownRuleIDs instead — a separate seen-set, since a rule
	// ID and a detector ID are never compared against each other.
	seenRules := make(map[string]bool, len(d.DisabledRuleIDs))
	for _, id := range d.DisabledRuleIDs {
		if !knownRuleIDs[id] {
			return fmt.Errorf("invalid detection.disabledRuleIds: %q is not a known rule ID", id)
		}
		if seenRules[id] {
			return fmt.Errorf("invalid detection.disabledRuleIds: duplicate rule ID %q", id)
		}
		seenRules[id] = true
	}

	maxSet := d.StormProtectionMaxNewIncidents != nil
	windowSet := d.StormProtectionWindowSeconds != nil
	if maxSet != windowSet {
		return errors.New("invalid detection storm-protection settings: stormProtectionMaxNewIncidents and stormProtectionWindowSeconds must be set together, or both left null to disable storm protection — a threshold with no window (or vice versa) would never apply")
	}
	if maxSet && *d.StormProtectionMaxNewIncidents <= 0 {
		return errors.New("invalid detection.stormProtectionMaxNewIncidents: must be a positive number, or null to disable storm protection")
	}
	if windowSet && *d.StormProtectionWindowSeconds <= 0 {
		return errors.New("invalid detection.stormProtectionWindowSeconds: must be a positive number of seconds, or null to disable storm protection")
	}
	return nil
}

// outboundAuditDestinations is the destination list recorded on the audit
// event for a settings write, or nil when the request did not carry the
// section at all (so "not touched" stays distinguishable from "cleared to
// nothing", which is recorded as an empty list).
func outboundAuditDestinations(o *putOutboundSettingsRequest) []string {
	if o == nil {
		return nil
	}
	out := make([]string, 0, len(o.PrivateDestinations))
	for _, d := range o.PrivateDestinations {
		out = append(out, d.Destination)
	}
	return out
}

// generalAuditMinPasswordLength/generalAuditIdleTimeout report nil (renders
// as JSON null in the audit row's Details) when "general" was not part of
// this request, so an audit reader can tell "left unchanged" apart from "set
// to a value that happens to print the same as some other request's".
func generalAuditMinPasswordLength(g *putGeneralSettingsRequest) *int {
	if g == nil {
		return nil
	}
	return &g.MinPasswordLength
}

func generalAuditIdleTimeout(g *putGeneralSettingsRequest) *int {
	if g == nil {
		return nil
	}
	return g.SessionIdleTimeoutMinutes
}

// handlePutSettings is PUT /api/v1/admin/settings. Requires
// org:settings:write. Applies settings.Update inside rc.Tx (atomic with the
// audit event below, and so the response reflects this request's own write
// even though it hasn't committed yet — see settings.Resolve's querier
// interface doc comment for why rc.Tx, not s.db.Pool, is used for that
// re-read).
func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	var req putSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}

	// A non-nil-but-non-positive maxIterations/timeLimitSeconds has no valid
	// meaning as a real override (matching internal/llm/toolloop.go's
	// resolveBounds and internal/settings' firstNonNilPositiveInt, which
	// both already treat such a value as absent) — rejecting it here up
	// front gives a clear 400 instead of silently storing a number that
	// would just be ignored on every future read.
	if req.Analysis != nil {
		if req.Analysis.MaxIterations != nil && *req.Analysis.MaxIterations <= 0 {
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request",
				"Invalid analysis.maxIterations", "Must be a positive number, or null to clear the override.")
			return
		}
		if req.Analysis.TimeLimitSeconds != nil && *req.Analysis.TimeLimitSeconds <= 0 {
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request",
				"Invalid analysis.timeLimitSeconds", "Must be a positive number, or null to clear the override.")
			return
		}
	}

	// Same "reject up front with a clear 400" treatment as the analysis
	// bounds check above, for the one field here that has real, checkable
	// constraints — Enabled has no invalid value (it's a plain bool), and a
	// nil/empty Severities is valid (see putAutomationSettingsRequest's doc
	// comment: "nothing selected" is a real, valid choice). What's rejected
	// here: any entry outside the known four-value enum, and any duplicate
	// entry — both would otherwise store a value internal/autoanalyze's
	// set-membership check either can't recognize or would apply redundantly,
	// so both get a clear, immediate 400 rather than silently through.
	if req.Automation != nil {
		seen := make(map[string]bool, len(req.Automation.Severities))
		for _, sev := range req.Automation.Severities {
			if !validAutoAnalysisSeverities[sev] {
				writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request",
					"Invalid automation.autoAnalysisSeverities",
					"Every entry must be one of low, medium, high, critical.")
				return
			}
			if seen[sev] {
				writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request",
					"Invalid automation.autoAnalysisSeverities",
					"Duplicate severity: "+sev+".")
				return
			}
			seen[sev] = true
		}
		// BACKLOG.md C12's first named defect, part 2: nothing rejected
		// autoAnalysisEnabled=true paired with an empty severity set. That
		// combination is not a contradiction the way, say, a malformed
		// severity value is — internal/autoanalyze.meetsSelectedSeverities'
		// own doc comment treats "enabled, nothing selected" as a real,
		// deliberately-supported state (equivalent to disabled, reachable by
		// unchecking every checklist box without touching the Enabled
		// toggle) — but it is a state an operator almost never intends to
		// reach on purpose, and the whole reason this entry exists is that
		// the hub was silently investigating nothing while every dashboard
		// implied automatic investigation was configured. So it is rejected
		// here as a distinct, clearly-worded 400 rather than accepted
		// silently, on the same "an operator who takes an action that does
		// nothing should be told, not left to infer it from a metrics
		// dashboard weeks later" reasoning as the daily-spend-ceiling log in
		// internal/autoanalyze.collectEligible. Checked with `seen` (the set
		// AFTER validation/dedup above), not len(req.Automation.Severities)
		// directly, so this fires for an all-invalid input too (already
		// rejected above by the per-entry check, but keeps this condition
		// correct in isolation rather than depending on check ordering).
		if req.Automation.Enabled && len(seen) == 0 {
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request",
				"Invalid automation settings",
				"automation.autoAnalysisEnabled is true but automation.autoAnalysisSeverities is empty — this would enable automatic investigation but select no severities to investigate, which never analyzes anything. Select at least one severity, or set autoAnalysisEnabled to false.")
			return
		}
	}

	// Same "reject up front with a clear 400" treatment as the analysis
	// bounds check above: a non-nil-but-non-positive retention value has no
	// sane meaning (see migration 000021's CHECK constraints and this file's
	// putRetentionSettingsRequest doc comment) — reject it here rather than
	// letting it fall through to the DB's own CHECK constraint as an opaque
	// 500.
	if req.Retention != nil {
		type namedRetentionField struct {
			name string
			days *int
		}
		for _, f := range []namedRetentionField{
			{"retention.auditRetentionDays", req.Retention.AuditRetentionDays},
			{"retention.incidentRetentionDays", req.Retention.IncidentRetentionDays},
			{"retention.findingRetentionDays", req.Retention.FindingRetentionDays},
		} {
			if f.days != nil && *f.days <= 0 {
				writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request",
					"Invalid "+f.name, "Must be a positive number of days, or null to keep forever.")
				return
			}
		}
	}

	// Same "reject up front with a clear 400" treatment as the checks above,
	// pulled into its own pure function (unlike the others) specifically so
	// it's unit-testable without an HTTP request/ResponseWriter at all — see
	// validateDetectionSettingsRequest's doc comment.
	if err := validateDetectionSettingsRequest(req.Detection); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", err.Error(), "")
		return
	}

	// Same "reject up front with a clear 400" treatment, for the "autonomy"
	// section's two checkable fields — see validateAutonomySettingsRequest's
	// own doc comment for why this can never weaken
	// internal/remediation.Evaluate's hard safety floor.
	if err := validateAutonomySettingsRequest(req.Autonomy); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", err.Error(), "")
		return
	}

	// Same "reject up front with a clear 400" treatment, for the "cost"
	// section's pricing-table-and-ceiling validation rules — see
	// validateCostSettingsRequest's own doc comment.
	if err := validateCostSettingsRequest(req.Cost); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", err.Error(), "")
		return
	}

	// Same "reject up front with a clear 400" treatment for the "outbound"
	// section — see validateOutboundSettingsRequest's own doc comment for
	// why it delegates to internal/outbound rather than restating the rules.
	if err := validatePostureSettingsRequest(req.Posture); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/validation", "Invalid posture settings", err.Error())
		return
	}
	if err := validateOutboundSettingsRequest(req.Outbound); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request",
			"Invalid outbound.privateDestinations", err.Error())
		return
	}

	// Same treatment for the "llm" section's provider-kind/agent enums — see
	// validateLLMSettingsRequest's own doc comment for why this is checked
	// here as well as in internal/settings.Update.
	if req.LLM != nil {
		if err := validateLLMSettingsRequest(req.LLM); err != nil {
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", err.Error(), "")
			return
		}
	}

	ctx := r.Context()

	var in settings.UpdateInput
	// Only consulted by settings.Update if req.LLM is non-nil AND no
	// provider is active yet (BUGS.md 92's create-and-activate path) — see
	// UpdateInput.TenantID's own doc comment.
	in.TenantID = rc.TenantID
	if req.LLM != nil {
		in.LLM = &settings.LLMUpdate{
			BaseURL:        req.LLM.BaseURL,
			Model:          req.LLM.Model,
			APIKey:         req.LLM.APIKey,
			ProviderKind:   req.LLM.ProviderKind,
			CLIRunnerURL:   req.LLM.CLIRunnerURL,
			CLIAgent:       req.LLM.CLIAgent,
			CLIRunnerToken: req.LLM.CLIRunnerToken,
		}
	}
	if req.Notify != nil {
		in.Notify = &settings.NotifyUpdate{WebhookURL: req.Notify.WebhookURL}
	}
	if req.Appearance != nil {
		// Rejected here with a 400 that NAMES the valid values, rather than
		// left to settings.Update's own re-validation (which would surface as a
		// 500). Both checks exist on purpose — see that function's comment.
		if !settings.ValidLoginStyle(req.Appearance.LoginStyle) {
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/validation",
				"Unknown login style",
				fmt.Sprintf("appearance.loginStyle must be one of: %s", strings.Join(settings.LoginStyles, ", ")))
			return
		}
		if !settings.ValidPrimaryColorID(req.Appearance.PrimaryColorID) {
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/validation",
				"Unknown primary color",
				fmt.Sprintf("appearance.primaryColorId must be one of: %s", strings.Join(settings.PrimaryColorIDs, ", ")))
			return
		}
		if !settings.ValidOverviewDefaultWindowDays(req.Appearance.OverviewDefaultWindowDays) {
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/validation",
				"Unsupported overview window",
				"appearance.overviewDefaultWindowDays must be 14 or 30")
			return
		}
		in.Appearance = &settings.AppearanceUpdate{
			LoginStyle:                req.Appearance.LoginStyle,
			PrimaryColorID:            req.Appearance.PrimaryColorID,
			OverviewDefaultWindowDays: req.Appearance.OverviewDefaultWindowDays,
		}
	}
	if req.General != nil {
		if req.General.MinPasswordLength < 8 || req.General.MinPasswordLength > 128 {
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/validation",
				"Invalid minimum password length",
				"general.minPasswordLength must be between 8 and 128")
			return
		}
		if req.General.SessionIdleTimeoutMinutes != nil {
			if m := *req.General.SessionIdleTimeoutMinutes; m < 5 || m > 10080 {
				writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/validation",
					"Invalid session idle timeout",
					"general.sessionIdleTimeoutMinutes must be between 5 and 10080, or null for no limit")
				return
			}
		}
		in.General = &settings.GeneralUpdate{
			MinPasswordLength:         req.General.MinPasswordLength,
			SessionIdleTimeoutMinutes: req.General.SessionIdleTimeoutMinutes,
		}
	}
	if req.Analysis != nil {
		in.Analysis = &settings.AnalysisUpdate{
			MaxIterations:    req.Analysis.MaxIterations,
			TimeLimitSeconds: req.Analysis.TimeLimitSeconds,
			RetrievalEnabled: req.Analysis.RetrievalEnabled,
		}
	}
	if req.Automation != nil {
		in.Automation = &settings.AutomationUpdate{
			Enabled:    req.Automation.Enabled,
			Severities: req.Automation.Severities,
		}
	}
	if req.Retention != nil {
		in.Retention = &settings.RetentionUpdate{
			AuditDays:    req.Retention.AuditRetentionDays,
			IncidentDays: req.Retention.IncidentRetentionDays,
			FindingDays:  req.Retention.FindingRetentionDays,
		}
	}
	if req.Detection != nil {
		in.Detection = &settings.DetectionUpdate{
			DisabledDetectorIDs:            req.Detection.DisabledDetectorIDs,
			StormProtectionMaxNewIncidents: req.Detection.StormProtectionMaxNewIncidents,
			StormProtectionWindowSeconds:   req.Detection.StormProtectionWindowSeconds,
			DisabledRuleIDs:                req.Detection.DisabledRuleIDs,
		}
	}
	if req.Autonomy != nil {
		in.Autonomy = &settings.AutonomyUpdate{
			AutoApproveMaxRisk:              req.Autonomy.AutoApproveMaxRisk,
			MinConfidenceForAutoApprove:     req.Autonomy.MinConfidenceForAutoApprove,
			RequireReversibleForAutoApprove: req.Autonomy.RequireReversibleForAutoApprove,
			UnattendedExecutionEnabled:      req.Autonomy.UnattendedExecutionEnabled,
			MaxUnattendedPerCluster:         req.Autonomy.MaxUnattendedPerCluster,
			MaxUnattendedFleetWide:          req.Autonomy.MaxUnattendedFleetWide,
			UnattendedWindowSeconds:         req.Autonomy.UnattendedWindowSeconds,
			UnattendedNamespaces:            req.Autonomy.UnattendedNamespaces,
		}
	}
	if req.Cost != nil {
		in.Cost = &settings.CostUpdate{
			PricePerMillionInputTokens:  req.Cost.PricePerMillionInputTokens,
			PricePerMillionCachedTokens: req.Cost.PricePerMillionCachedTokens,
			PricePerMillionOutputTokens: req.Cost.PricePerMillionOutputTokens,
			DailySpendCeilingUsd:        req.Cost.DailySpendCeilingUsd,
		}
	}

	if req.Posture != nil {
		in.Posture = &settings.PostureUpdate{DisabledChecks: req.Posture.DisabledChecks, IgnoredNamespaces: req.Posture.IgnoredNamespaces}
	}

	if req.Outbound != nil {
		destinations := make([]settings.OutboundPrivateDestination, 0, len(req.Outbound.PrivateDestinations))
		for _, d := range req.Outbound.PrivateDestinations {
			destinations = append(destinations, settings.OutboundPrivateDestination{Destination: d.Destination, Reason: d.Reason})
		}
		in.Outbound = &settings.OutboundUpdate{PrivateDestinations: destinations}
	}

	if err := settings.Update(ctx, rc.Tx, in); err != nil {
		logger.ErrorContext(ctx, "updating the settings failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not update settings", "")
		return
	}

	// Details records WHICH fields changed, never the secret values
	// themselves — details is free-form and excluded from the audit hash
	// input (internal/audit's doc comment), but "not part of the hash" is
	// not a reason to put a real secret in it anyway.
	capability := authz.CapOrgSettingsWrite
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		Outcome:         audit.OutcomeSuccess,
		Details: map[string]any{
			"llmSectionProvided":              req.LLM != nil,
			"llmApiKeyChanged":                req.LLM != nil && req.LLM.APIKey != nil,
			"notifySectionProvided":           req.Notify != nil,
			"notifyWebhookChanged":            req.Notify != nil && req.Notify.WebhookURL != nil,
			"analysisSectionProvided":         req.Analysis != nil,
			"analysisMaxIterationsChanged":    req.Analysis != nil && req.Analysis.MaxIterations != nil,
			"analysisTimeLimitSecondsChanged": req.Analysis != nil && req.Analysis.TimeLimitSeconds != nil,
			"analysisRetrievalEnabled":        req.Analysis != nil && req.Analysis.RetrievalEnabled,
			"automationSectionProvided":       req.Automation != nil,
			"retentionSectionProvided":        req.Retention != nil,
			"detectionSectionProvided":        req.Detection != nil,
			"autonomySectionProvided":         req.Autonomy != nil,
			"costSectionProvided":             req.Cost != nil,
			"appearanceSectionProvided":       req.Appearance != nil,
			// general's two fields are security floors, not secrets, and
			// recorded in full for the same reason the outbound allowlist's
			// destinations are below: "who changed the password minimum or
			// idle timeout, and to what" is exactly what an audit of this
			// setting needs to answer.
			"generalSectionProvided":           req.General != nil,
			"generalMinPasswordLength":         generalAuditMinPasswordLength(req.General),
			"generalSessionIdleTimeoutMinutes": generalAuditIdleTimeout(req.General),
			// The egress allowlist is the one section whose CONTENT belongs
			// in the audit trail rather than just a "was it provided" flag:
			// it is not a secret, and "who widened what the hub may dial,
			// and to what" is precisely the question an audit of this
			// setting has to answer. Recorded as the destinations only —
			// the reasons are in org_settings and on the settings screen,
			// and duplicating free text into every audit row buys nothing.
			"outboundSectionProvided":            req.Outbound != nil,
			"postureSectionProvided":             req.Posture != nil,
			"outboundPrivateDestinationsAllowed": outboundAuditDestinations(req.Outbound),
		},
	}); err != nil {
		logger.ErrorContext(ctx, "recording a settings change in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	cfg, err := settings.Resolve(ctx, rc.Tx)
	if err != nil {
		logger.ErrorContext(ctx, "resolving the settings after an update failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not read back updated settings", "")
		return
	}
	resp := settingsResponseFromConfig(cfg, s.cliBackendAvailable())
	todaySpend, err := TodaySpendUSD(ctx, rc.Tx)
	if err != nil {
		logger.ErrorContext(ctx, "computing today's spend after a settings update failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not read back updated settings", "")
		return
	}
	resp.Cost.TodaySpendUsd = todaySpend
	resp.Cost.CeilingBreached = SpendCeilingBreached(cfg, todaySpend)
	writeJSON(w, http.StatusOK, resp)
}
