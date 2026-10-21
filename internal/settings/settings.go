// Package settings resolves and updates ARGUS's org-wide, DB-backed,
// live-editable configuration for the AI provider (internal/llm), the
// notification webhook (internal/notify), and the investigation loop's own
// iteration/time bounds (also internal/llm, toolloop.go's Investigate) —
// DESIGN.md §16.2's "per-tenant, DB-backed config," scoped
// down to one organisation-wide row per the confirmed single-org deployment
// (§5.1).
//
// This is a small, standalone package (rather than living in internal/llm or
// internal/notify, or internal/api) specifically so it can be imported by
// all three without creating a cycle: internal/api already imports
// internal/llm and internal/notify, so if Resolve/Update lived inside either
// of those, internal/api's settings handler couldn't import it back cleanly
// without going through the package that also holds the HTTP-calling/
// webhook-posting logic. Living here, internal/llm and internal/notify both
// import internal/settings, and internal/api imports it too — a strict fan-
// out, no cycle.
package settings

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"argus/internal/logging"
	"argus/internal/outbound"
)

// logger is internal/settings' package-local structured logger (PROJECT.md T22).
var logger = logging.For("settings")

// singletonID is org_settings' one and only row id (migration
// 000018_org_settings.up.sql) — this package never queries or writes any
// other id.
const singletonID = "singleton"

// Provider kinds — lld/14-adrs.md ADR-17's two backend kinds, as stored in
// org_settings.llm_provider_kind and dispatched on by internal/llm.Router.
//
// ProviderKindAPI is the default and the only kind that existed before
// migration 000033: ARGUS owns the investigation loop
// (lld/07-analysis-contracts.md §2–§7). ProviderKindCLI delegates the loop to
// an external coding-agent CLI running in a separate runner process, which
// costs real guarantees — §10.3 of that document enumerates exactly which.
const (
	ProviderKindAPI = "api"
	ProviderKindCLI = "cli"
)

// NormalizeProviderKind maps the empty string to ProviderKindAPI and leaves
// everything else untouched (including unrecognized values, so the caller can
// report the actual bad value rather than a laundered one).
//
// The empty-string case is not defensive padding: org_settings' row predates
// migration 000033, so an existing deployment's column is genuinely NULL/”
// until someone writes it, and that state must mean "api" — the behaviour
// those deployments already had. A default that silently meant "cli" would
// change the backend of every existing install on upgrade.
func NormalizeProviderKind(kind string) string {
	if kind == "" {
		return ProviderKindAPI
	}
	return kind
}

// Config is the resolved, effective configuration for one call/request —
// never cached beyond that call, so a change written via Update is visible
// to the very next Resolve (see the package doc comment and each field's
// own comment for why).
// The sign-in screen's layouts. Adding one means adding it here, to the CHECK
// constraint on org_settings.login_style (latest: migration 000136), and to
// web's LoginPage.tsx and SettingsPage.tsx — all of them, or the value is
// either unstorable or unrenderable.
//
// "aperture" is first because it is the default, not because it is
// alphabetical. Two earlier styles were dropped by the owner rather than kept
// as dead options: "vigil", and "telemetry" (migration 000136 resets an
// install that had chosen it to the default).
const (
	LoginStyleAperture = "aperture"
	LoginStyleSentinel = "sentinel"
)

// DefaultLoginStyle is what an install serves before anyone chooses, and what
// an unrecognised stored value falls back to.
const DefaultLoginStyle = LoginStyleAperture

// LoginStyles is every valid value, in the order the Settings UI lists them.
var LoginStyles = []string{
	LoginStyleAperture,
	LoginStyleSentinel,
}

// ValidLoginStyle reports whether s is one of LoginStyles.
func ValidLoginStyle(s string) bool {
	for _, v := range LoginStyles {
		if v == s {
			return true
		}
	}
	return false
}

// The primary-colour presets — web/src/index.css's `[data-accent=...]`
// blocks, migration 000131's CHECK constraint, and this list all have to
// name the same five ids or a value is either unstorable or unrenderable,
// same three-way requirement LoginStyles' own doc comment describes.
const (
	PrimaryColorTeal   = "teal"
	PrimaryColorBlue   = "blue"
	PrimaryColorViolet = "violet"
	PrimaryColorSlate  = "slate"
	PrimaryColorForest = "forest"
)

// DefaultPrimaryColorID is the shipped brand teal, #3c7d7d — what an install
// serves before anyone chooses, and what an unrecognised stored value falls
// back to.
const DefaultPrimaryColorID = PrimaryColorTeal

// PrimaryColorIDs is every valid value, in the order the Settings UI lists
// them.
var PrimaryColorIDs = []string{
	PrimaryColorTeal,
	PrimaryColorBlue,
	PrimaryColorViolet,
	PrimaryColorSlate,
	PrimaryColorForest,
}

// ValidPrimaryColorID reports whether s is one of PrimaryColorIDs.
func ValidPrimaryColorID(s string) bool {
	for _, v := range PrimaryColorIDs {
		if v == s {
			return true
		}
	}
	return false
}

// OverviewDefaultWindowDaysValues is OverviewDefaultWindowDays' closed set —
// matching OverviewPage's segmented control, which has exactly two options.
var OverviewDefaultWindowDaysValues = []int{14, 30}

// ValidOverviewDefaultWindowDays reports whether d is one of
// OverviewDefaultWindowDaysValues.
func ValidOverviewDefaultWindowDays(d int) bool {
	for _, v := range OverviewDefaultWindowDaysValues {
		if v == d {
			return true
		}
	}
	return false
}

type Config struct {
	// LLMProviderKind is ProviderKindAPI or ProviderKindCLI, already
	// normalized by Resolve — a caller should never see "" here. Which of
	// the field groups below is actually load-bearing depends on it:
	// LLMBaseURL/LLMModel/LLMAPIKey for api, CLIRunner* for cli.
	LLMProviderKind string

	LLMBaseURL string
	LLMModel   string
	LLMAPIKey  string
	// LLMAPIKeySet is true if EITHER the DB row or the env var contributed a
	// non-empty key — internal/api/settings.go's GET response needs exactly
	// this boolean and must never echo LLMAPIKey itself back to a caller.
	LLMAPIKeySet bool

	// CLIRunnerURL is the base URL of the CLI-agent runner service
	// (lld/12-deployment-design.md §12.2 — a pod-local sidecar or its own
	// Deployment; this package takes no position on which, since both speak
	// the same authenticated HTTP protocol). Empty means "no runner
	// configured," which is what makes internal/llm.Router return
	// ErrNotConfigured rather than dialing nothing.
	CLIRunnerURL string
	// CLIRunnerToken is the bearer credential the hub presents to the runner
	// (B12's hub->runner direction). Secret: same never-echo-it-back contract
	// as LLMAPIKey, hence the paired ...Set boolean below.
	CLIRunnerToken    string
	CLIRunnerTokenSet bool
	// ActiveProviderID / ActiveProviderName identify which configured provider
	// (migration 000034's ai_providers) the fields above were resolved from.
	// Empty when no provider is active — either none is configured, or the
	// active one was deleted. Present so the UI and logs can say *which*
	// provider produced a result, which matters once several exist.
	ActiveProviderID   string
	ActiveProviderName string

	// CLIAgent selects which CLI the runner should invoke ("claude" |
	// "codex"). The runner validates this against what it actually has
	// installed and pinned (lld/12-deployment-design.md §12.4) — the hub
	// deliberately does not try to second-guess the runner's own inventory.
	CLIAgent string

	NotifyWebhookURL string

	// LoginStyle is which of the sign-in screen's layouts to serve. Always one
	// of LoginStyles — resolve() substitutes DefaultLoginStyle for an empty or
	// unrecognised stored value rather than passing it through, because this
	// string reaches an UNAUTHENTICATED endpoint and from there a DOM attribute
	// on the login page. Nothing downstream should have to re-validate it.
	LoginStyle string

	// PrimaryColorID selects one of index.css's named `data-accent` presets
	// (web/src/index.css's "Primary colour presets" block) — always one of
	// PrimaryColorIDs, same substitution contract as LoginStyle: resolve()
	// falls back to DefaultPrimaryColorID for an empty or unrecognised stored
	// value rather than passing it through, because this id reaches every
	// authenticated page via GET /users/me and becomes a DOM attribute there.
	// An id, never a stored colour — see migration 000131's doc comment for
	// why that matters.
	PrimaryColorID string

	// OverviewDefaultWindowDays is OverviewPage's "incidents opened" window
	// on first load — always 14 or 30 (OverviewDefaultWindowDaysValues),
	// matching the segmented control's own closed set; a user's in-session
	// toggle between them is unaffected and still purely client-side state.
	OverviewDefaultWindowDays int

	// NotifyWebhookConfigured mirrors LLMAPIKeySet's role for the webhook URL —
	// same "tell the caller whether it's set, never what it's set to" contract.
	NotifyWebhookConfigured bool

	// MinPasswordLength is the floor internal/api's handleChangePassword
	// enforces on a self-service password change (the one password-setting
	// path that has ever enforced a minimum at all — see migration 000131's
	// doc comment for why the admin-set/bootstrap paths are unaffected).
	// Always a positive int (NOT NULL DEFAULT 12, CHECK 8-128) — there is no
	// "unconfigured" state, so unlike most of this file's newer fields this
	// one needs no nil handling anywhere.
	MinPasswordLength int

	// SessionIdleTimeoutMinutes, when non-nil, is how long a refresh-token
	// chain may go un-rotated before authz.RotateRefreshTokenDetailed refuses
	// the next rotation and ends the session, exactly as if the token had
	// been reused (see migration 000131's doc comment for the full mechanism
	// and why no new column was needed to track "last used"). Nil means no
	// idle limit — today's exact behaviour, a refresh token good for its full
	// authz.RefreshTokenTTL regardless of activity — matching the nil-means-
	// off convention retention/detection/cost already use on this table.
	SessionIdleTimeoutMinutes *int

	// AnalysisMaxIterations / AnalysisTimeLimitSeconds are the investigation
	// loop's bounds (internal/llm/toolloop.go's Investigate) after DB-row/
	// env-var resolution — the same two knobs WORKLOG.md §25 documented as
	// ARGUS_ANALYSIS_MAX_ITERATIONS/ARGUS_ANALYSIS_TIME_LIMIT_SECONDS-only,
	// now closable through PUT /api/v1/admin/settings too.
	//
	// Pointers, not an int+bool pair like LLMAPIKeySet: these two aren't
	// secrets, so there's no reason to hide the actual configured value from
	// a GET the way LLMAPIKeySet/NotifyWebhookConfigured do — but "unset"
	// (neither the DB row nor the env var configured it) is still a real,
	// distinct state a caller needs to tell apart from "set to some value,"
	// so internal/api/settings.go's response can show an admin "this is an
	// explicit override" instead of "this is the fallback." nil is that
	// signal; a non-nil value is the effective override, already resolved
	// DB-row-first-then-env exactly like every other field on this struct.
	//
	// Deliberately does NOT fold in the third tier (internal/llm's own
	// hardcoded default) — nil here means "go consult that default," which
	// is what lets this package (imported BY internal/llm, per the package
	// doc comment's fan-out diagram) avoid importing internal/llm back just
	// to duplicate its defaultMaxIterations/defaultTimeLimit constants. See
	// internal/llm/toolloop.go's resolveBounds, which applies that last tier
	// immediately after calling Resolve — same call, so the net effect is
	// identical to the default living here: resolved fresh every
	// Investigate, no caching, no restart needed for a change to take
	// effect.
	AnalysisMaxIterations    *int
	AnalysisTimeLimitSeconds *int

	// RetrievalEnabled gates internal/knowledge.Store.RetrieveSimilar —
	// whether an investigation's prompt is augmented with prior similar
	// analyses, labelled prior belief, never evidence. false in every
	// installation that has not deliberately turned it on: measured live
	// (PROJECT.md, 2026-09-07) at 31% higher cost with no measurable
	// confidence benefit on one real repeated fault, which is an
	// inconclusive result, not a validated feature, and must not ship as an
	// unconditional cost increase. No env-var tier, same reasoning as
	// AutoAnalysisEnabled: a brand-new, DB-backed-from-day-one setting with
	// no prior deploy-time convention to preserve.
	RetrievalEnabled bool

	// AutoAnalysisEnabled / AutoAnalysisSeverities govern
	// internal/autoanalyze's poller: whether a newly-detected incident with
	// no analysis yet gets the exact same investigation
	// POST /api/v1/incidents/{id}/analyze already runs on a manual click,
	// run automatically instead, and (when enabled) which severities
	// qualify.
	//
	// Unlike every field above, these two have no env-var fallback tier at
	// all — a brand-new setting, DB-backed from day one, with no prior
	// ARGUS_AUTO_ANALYSIS_* env var whose behavior needs preserving. That
	// also means AutoAnalysisEnabled is a plain bool, not the
	// int+bool/pointer shape LLMAPIKeySet or AnalysisMaxIterations use:
	// there is no "unconfigured, consult some other source" third state to
	// represent here (see migration 000024's comment) — an installation
	// that never touched this setting and one that explicitly turned it off
	// resolve to the exact same false.
	//
	// AutoAnalysisSeverities replaces migration 000020's single
	// AutoAnalysisMinSeverity *string threshold (removed by migration
	// 000024) with a genuine set: the user asked directly for a checklist of
	// individually-selectable severities, not an ordered "this and above"
	// threshold, because a threshold cannot express e.g. "high and critical,
	// but explicitly not medium."
	//
	// THE ONE SUBTLE SEMANTIC DECISION IN THIS WHOLE FEATURE: a nil or empty
	// slice here, combined with AutoAnalysisEnabled == true, means "nothing
	// is selected, so nothing gets auto-analyzed" — NOT "every severity
	// qualifies." This is the OPPOSITE of what the old AutoAnalysisMinSeverity
	// == nil used to mean, and deliberately so: a blank checklist (every box
	// unchecked) reads visually as "nothing chosen yet," and the safe,
	// unsurprising behavior for that state is to do nothing, not to
	// silently auto-analyze every incident of every severity — the single
	// most dangerous possible interpretation of "I haven't configured
	// anything." An admin who wants every severity auto-analyzed must check
	// all four boxes explicitly, the same as selecting any other subset.
	// Every non-empty element is always one of the four-value severity enum
	// (low/medium/high/critical — mirrored in
	// internal/tunnel/protocol.go's Finding.Severity doc comment), enforced
	// by migration 000024's CHECK constraint and re-checked at the
	// PUT /api/v1/admin/settings boundary (internal/api/settings.go).
	AutoAnalysisEnabled    bool
	AutoAnalysisSeverities []string

	// AuditRetentionDays / IncidentRetentionDays / FindingRetentionDays
	// configure internal/partition's daily maintenance job — how many days
	// of history to keep in audit_events / incidents / findings before that
	// table's oldest partitions are dropped entirely (migration
	// 000021_retention_settings.up.sql has the full rationale).
	//
	// Like AutoAnalysisSeverities above, and unlike AnalysisMaxIterations,
	// there is no env-var fallback tier for any of these three — but unlike
	// AutoAnalysisSeverities, nil here does NOT mean "nothing selected." nil
	// means "keep forever": internal/partition never drops a partition of a
	// table whose retention column is nil, full stop. Nothing here or in
	// internal/partition ever implies a value. The one default is set once,
	// on a brand-new database, by authz.EnsureBootstrap: findings are kept
	// for DefaultFindingRetentionDays there, because they are most of the
	// database. An existing install keeps what it has; an admin changes any
	// of the three through PUT /api/v1/admin/settings. Do not add an env-var fallback
	// tier for these three without re-reading migration 000021's comment
	// first — an env var would reintroduce exactly the "silently starts
	// deleting data because of an unrelated deploy-time env change" risk
	// this design specifically avoids.
	AuditRetentionDays    *int
	IncidentRetentionDays *int
	FindingRetentionDays  *int

	// DisabledDetectorIDs / StormProtectionMaxNewIncidents /
	// StormProtectionWindowSeconds are the detection layer's first real,
	// hub-side, live-editable configuration — closing the gap STATUS.md's
	// Phase 1 row has repeatedly flagged: "the fuller detection framework
	// (RemediationPolicy CRD, dedup/storm-protection, multi-detector
	// precedence — today both detectors are hardcoded, not policy-driven)."
	// See migration 000026_detection_settings' header comment for the full
	// rationale, and internal/gateway/finding.go's handleFinding for how
	// these are actually enforced.
	//
	// DisabledDetectorIDs is a set of internal/tunnel.Finding.DetectorID
	// values whose findings handleFinding drops before they're ever
	// recorded or become an incident — a HUB-SIDE FILTER, not a signal that
	// reaches the agent: the agent keeps running the "disabled" detector and
	// keeps sending its findings exactly as before (there is no
	// hub-to-agent config-push path in internal/tunnel's protocol today —
	// see defaultFindingResendCooldown's doc comment in
	// internal/agent/detector.go for the identical limitation applied to a
	// different knob). Like AutoAnalysisSeverities, nil/empty means "nothing
	// is disabled," i.e. today's actual, unchanged behavior — never
	// defaulted to "everything disabled," and no env-var fallback tier (a
	// brand-new setting, DB-backed from day one).
	//
	// StormProtectionMaxNewIncidents / StormProtectionWindowSeconds cap how
	// many brand-new (never-seen-fingerprint) incidents a single cluster may
	// produce within a rolling window before handleFinding stops creating
	// further new incidents from that cluster for the remainder of the
	// window (existing incidents keep updating normally; the finding is
	// still recorded, just not correlated to a new incident — see
	// handleFinding). Like AuditRetentionDays et al., nil means "no ceiling"
	// — the shipped default, opt-in only, no env-var fallback tier — NOT a
	// hardcoded number that would silently start suppressing incident
	// creation on an unrelated upgrade. The two fields are set together or
	// cleared together in practice; internal/api/settings.go's PUT handler
	// rejects "one set, the other missing" with a 400 before either ever
	// reaches Update, per lld/06-detection-framework.md §7's identical
	// validation rule for its own dedup/window fields.
	DisabledDetectorIDs            []string
	StormProtectionMaxNewIncidents *int
	StormProtectionWindowSeconds   *int

	// DisabledRuleIDs is BUGS.md 111's fix: a HUB-SIDE FILTER exactly like
	// DisabledDetectorIDs above, but checked against
	// internal/tunnel.Finding.RuleID instead of Finding.DetectorID. It exists
	// because every rule-format finding from internal/agent/rules/default-
	// rules.yaml (33 rules and growing) is emitted by the sweep detector with
	// the SAME shared DetectorID ("k8s-sweep") -- disabling that one detector
	// ID silences all 33 rules AND every hand-written Go check in the same
	// detector at once, with no way to silence just one noisy rule. A rule's
	// own identity travels separately on Finding.RuleID (added by migration
	// 000071), so this field is the narrower knob: it is checked ALONGSIDE
	// DisabledDetectorIDs in internal/gateway/finding.go's handleFinding
	// (gateway.IsRuleDisabled, mirroring IsDetectorDisabled exactly), never
	// instead of it, and does not change DisabledDetectorIDs' own meaning or
	// behavior in any way.
	//
	// Like DisabledDetectorIDs, this is a hub-side-only filter -- the agent
	// keeps evaluating a "disabled" rule and keeps sending its findings
	// exactly as before, since internal/tunnel's protocol has no hub-to-agent
	// config-push path. And like DisabledDetectorIDs, nil/empty means
	// "nothing is disabled" -- today's actual, unchanged behavior -- never
	// defaulted to "everything disabled," with no env-var fallback tier (a
	// brand-new setting, DB-backed from day one). Finding.RuleID is empty for
	// every hand-written Go detector finding (only rule-format findings set
	// it), so an empty RuleID must never match anything in this set --
	// IsRuleDisabled guards that explicitly rather than relying on
	// DisabledRuleIDs never containing "".
	DisabledRuleIDs []string

	// AutonomyAutoApproveMaxRisk / AutonomyMinConfidenceForAutoApprove /
	// AutonomyRequireReversibleForAutoApprove are the DB-backed override for
	// internal/orchestrator.DefaultAutonomyPolicy — closing the gap
	// WORKLOG.md §50 flagged explicitly: internal/remediation.AutonomyPolicy
	// used to be a hardcoded constant with no DB-backed, live-editable path,
	// unlike every other piece of config in this package. See migration
	// 000028_autonomy_policy's header comment for the full column-level
	// rationale; this is the Go-side mirror of it.
	//
	// AutonomyAutoApproveMaxRisk is deliberately a plain *string, not
	// internal/remediation.RiskLevel: this package is imported BY
	// internal/llm and internal/notify (see the package doc comment's fan-
	// out diagram), and every other field on this struct already avoids
	// depending on a downstream package's domain type for the same reason
	// AnalysisMaxIterations avoids importing internal/llm's own bound
	// constants — internal/orchestrator (which already imports
	// internal/remediation) is responsible for casting this to
	// remediation.RiskLevel and applying internal/remediation.RiskLevel
	// .Valid() semantics; a nil or unrecognized value there safely never
	// matches any RiskLevel comparison, matching remediation.AutonomyPolicy
	// 's own zero-value "auto-approves nothing" safety net.
	//
	// Like AnalysisMaxIterations/AnalysisTimeLimitSeconds — NOT like
	// AutoAnalysisSeverities/DisabledDetectorIDs — nil here means "not
	// configured in the DB, consult a further hardcoded-default tier
	// downstream" (internal/orchestrator.DefaultAutonomyPolicy), not "this
	// nil value is itself the safe, final answer." That further tier is
	// itself already conservative (low risk, 0.90 confidence, reversibility
	// required) — see DefaultAutonomyPolicy's own doc comment — so an
	// installation that never touches this setting behaves exactly as it did
	// before this feature existed, not more permissively.
	//
	// No env-var tier for any of the three fields, same as
	// AutoAnalysisEnabled/DisabledDetectorIDs: a brand-new setting with no
	// prior ARGUS_AUTONOMY_* environment variable whose behavior needs
	// preserving.
	//
	// AutonomyRequireReversibleForAutoApprove is now (BUGS.md 97,
	// migration 000085) a *bool, following AutonomyAutoApproveMaxRisk/
	// AutonomyMinConfidenceForAutoApprove's exact contract rather than
	// AutoAnalysisEnabled's: nil means "not configured in the DB, consult
	// DefaultAutonomyPolicy's own conservative value" (true — the safe
	// direction), not "explicitly set to false". It used to be a plain
	// bool, reasoning that the column was NOT NULL DEFAULT true so there
	// was no unconfigured state to represent — but that meant a PUT whose
	// JSON body omitted the key decoded to the zero value, false, which
	// for this field is the *permissive* direction (it's the belt-and-
	// suspenders check on top of the risk ceiling), silently weakening the
	// gate. See BUGS.md 97 for the live incident this caused.
	AutonomyAutoApproveMaxRisk              *string
	AutonomyMinConfidenceForAutoApprove     *float64
	AutonomyRequireReversibleForAutoApprove *bool

	// AutonomyUnattendedExecutionEnabled is the switch for TRUE unattended
	// execution — an AutoApprove verdict actually running without a human
	// (BUGS.md 39, owner decision 2026-08-22). false in every installation that
	// has not deliberately turned it on, which preserves the invariant every
	// other doc describes: nothing reaches Executing without an approval.
	AutonomyUnattendedExecutionEnabled bool
	// The blast-radius caps that ship WITH that switch rather than after it —
	// DESIGN.md §10.5 requires them in the same release, and they are what stops
	// one wrong diagnosis becoming thirty wrong mutations across a correlated
	// fleet. nil means "fall back to orchestrator.DefaultUnattendedLimits", NOT
	// "no limit": a blank field meaning unlimited would be the worst possible
	// reading of an empty input on this screen.
	AutonomyMaxUnattendedPerCluster *int
	AutonomyMaxUnattendedFleetWide  *int
	AutonomyUnattendedWindowSeconds *int
	AutonomyUnattendedNamespaces    []string
	// AutonomyUnattendedNamespaces is the allowlist of namespaces unattended
	// execution may act in. **Empty means nowhere**, which is the whole point:
	// enabling unattended execution used to enable it everywhere, including
	// `kube-system` and every other namespace on every connected cluster
	// (measured — see migration 000055). An empty allowlist denying rather than
	// permitting is the same rule internal/gitops/clone.go applies to repository
	// hosts.
	//
	// A plain slice rather than a pointer: "not configured" and "configured to
	// nothing" both mean the same thing here — no namespace is permitted — so the
	// distinction a pointer would preserve carries no information.

	// The circuit breaker (BACKLOG R2's second half). Bounds unattended execution
	// on OUTCOME where the caps above bound volume and the automation windows
	// bound time — see internal/orchestrator/breaker.go for why none of the three
	// substitutes for the others.
	//
	// Enabled defaults to TRUE, unlike AutonomyUnattendedExecutionEnabled. That is
	// deliberate and is the opposite call from R2's maintenance windows: an empty
	// maintenance list had to mean "no restriction" because the literal reading
	// would have silently stopped all automation on every existing install. A
	// breaker only ever acts after repeated failures, so defaulting it on changes
	// behaviour for exactly the installations that should be stopped, and a safety
	// net that ships off is a safety net nobody turns on.
	//
	// nil means fall back to orchestrator.DefaultBreakerLimits, never "no limit".
	AutonomyBreakerEnabled       bool
	AutonomyBreakerPerCluster    *int
	AutonomyBreakerFleetWide     *int
	AutonomyBreakerWindowSeconds *int

	// PricePerMillionInputTokens / PricePerMillionCachedTokens /
	// PricePerMillionOutputTokens / DailySpendCeilingUsd close the gap
	// WORKLOG.md §28/§49 both documented rather than papered over:
	// analyses.cost_usd has always been a real, honest 0 because no
	// per-model USD pricing table existed anywhere in this codebase.
	// DESIGN.md §16.4's "hard spend ceilings" requirement,
	// and internal/authz.CapSpendRead/CapSpendManage (declared in the
	// capability catalogue since the very first authz pass, never
	// implemented by anything until now), both depend on a real cost number
	// existing first — this is that number's source.
	//
	// Deliberately NOT hardcoded to any real vendor's current per-token
	// rate: pricing moves, and a hardcoded rate card goes stale silently.
	// Instead, an operator sets these once for whichever model is
	// configured in the "llm" section above — see migration
	// 000029_cost_settings' header comment for the full rationale,
	// including the $/Mtok unit choice (matching §16.3's own worked cost
	// model) and why the three price fields are validated as an
	// all-or-nothing set at the API boundary (internal/api/settings.go's
	// validateCostSettingsRequest) rather than independently optional: a
	// partial price table would compute a systematically WRONG total,
	// worse than an honest 0.
	//
	// Like AutonomyAutoApproveMaxRisk above (not like
	// AutoAnalysisSeverities/DisabledDetectorIDs), nil here IS itself the
	// final, safe answer — there is no further hardcoded-default tier to
	// fall back to for "how much does a token cost," unlike "how many
	// iterations" or "which risk level." CostPricingConfigured/
	// ComputeCostUSD below are the only things that read these three
	// fields; see their own doc comments.
	//
	// DailySpendCeilingUsd nil means "no ceiling" — today's actual,
	// unbounded behavior, unchanged until an operator sets one explicitly,
	// matching DisabledDetectorIDs/StormProtection*'s identical
	// nil-means-off convention. SpendCeilingActive/internal/api
	// .SpendCeilingBreached are what actually enforce it — see those doc
	// comments for exactly how, and internal/autoanalyze/
	// internal/api/analyze.go for where.
	//
	// No env-var tier for any of the four fields — brand-new settings, like
	// every other section added after migration 000018's initial pass, with
	// no prior ARGUS_* variable whose behavior needs preserving.
	PricePerMillionInputTokens  *float64
	PricePerMillionCachedTokens *float64
	PricePerMillionOutputTokens *float64
	DailySpendCeilingUsd        *float64

	// OutboundPrivateDestinations is the operator's explicit allowlist of
	// private destinations the AI-provider and repository HTTP clients may
	// reach — migration 000115, and the owner's 2026-09-19 decision recorded
	// there and in internal/outbound's package comment.
	//
	// internal/outbound refuses loopback/link-local/RFC1918/RFC4193
	// destinations by default for those two boundaries, which is right for the
	// common case and wrong for a self-hosted vLLM or an internal GitHub
	// Enterprise Server. This is the named exception: an operator lists the
	// specific destinations they trust, each with a written reason, and
	// anything not listed stays refused. It is deliberately NOT a boolean —
	// see migration 000115's header for why a boolean would be the rejected
	// "allow private by default" option one click away.
	//
	// nil/empty means "nothing allowlisted", which is the shipped default and
	// today's exact behaviour — never "everything allowed", the same
	// nil-means-nothing-selected convention AutonomyUnattendedNamespaces and
	// DisabledDetectorIDs already use, and for the identical reason: the safe
	// reading of an empty list on a security setting is the restrictive one.
	// No env-var tier.
	//
	// Held as this package's own struct rather than as an
	// outbound.AllowlistEntry slice so that an unparseable stored value is a
	// problem for PrivateDestinationAllowlist's caller and not for Resolve —
	// every consumer of Config would otherwise start failing on a row a
	// hand-edit made invalid. Use PrivateDestinationAllowlist to get the
	// validated form.
	OutboundPrivateDestinations []OutboundPrivateDestination

	// PostureDisabledChecks and PostureIgnoredNamespaces apply to every
	// cluster's posture results on top of each agent's own chart values
	// (CI-P9 d): the hub passes them to get_posture_findings and drops
	// matching posture findings at ingestion. Ignored namespaces accept a
	// leading or trailing "*". Nil/empty means nothing extra.
	PostureDisabledChecks    []string
	PostureIgnoredNamespaces []string
}

// OutboundPrivateDestination is one entry of OutboundPrivateDestinations, and
// is exactly the jsonb object shape migration 000115 stores.
//
// Reason is required, not advisory: internal/outbound.ParseAllowlist rejects an
// entry without one, mirroring the panic NewClient already raises for a
// compile-time AllowPrivate with no Reason. An exception that cannot say why it
// exists cannot be reviewed later, which for an egress allowlist is the whole
// point of writing it down.
type OutboundPrivateDestination struct {
	Destination string `json:"destination"`
	Reason      string `json:"reason"`
}

// PrivateDestinationAllowlist parses OutboundPrivateDestinations into the
// validated form internal/outbound consumes.
//
// This is the third of three validation points and the only one that cannot be
// bypassed: internal/api rejects a bad PUT with a 400, internal/settings.Update
// re-validates before writing (a handler is one caller, not a gate), and this
// re-validates on every read, so a row edited directly in psql cannot smuggle
// an entry past the range and metadata rules. An error here means the stored
// list is invalid, and the caller must refuse the destination rather than fall
// back to allowing it — see internal/outbound.classify, which turns exactly
// this error into a refusal.
func (c Config) PrivateDestinationAllowlist() (outbound.Allowlist, error) {
	if len(c.OutboundPrivateDestinations) == 0 {
		return outbound.Allowlist{}, nil
	}
	entries := make([]outbound.AllowlistEntry, 0, len(c.OutboundPrivateDestinations))
	for _, d := range c.OutboundPrivateDestinations {
		entries = append(entries, outbound.AllowlistEntry{Destination: d.Destination, Reason: d.Reason})
	}
	return outbound.ParseAllowlist(entries)
}

// PrivateDestinationSource is the outbound.AllowlistSource the AI-provider
// (internal/llm) and repository (internal/scm) clients are wired with.
//
// It resolves the allowlist FRESH from q on every consultation rather than
// capturing it at client-construction time, because those clients are built
// once — at hub startup for the provider, per repository operation for scm —
// while this setting is edited at runtime through PUT /api/v1/admin/settings.
// That is the same no-restart-needed contract Resolve's own doc comment
// describes for every other field on Config. internal/outbound calls this only
// on the path to a refusal (an address that is private and not yet permitted),
// so an ordinary public destination never triggers the query.
func PrivateDestinationSource(q querier) outbound.AllowlistSource {
	return func(ctx context.Context) (outbound.Allowlist, error) {
		cfg, err := Resolve(ctx, q)
		if err != nil {
			return outbound.Allowlist{}, err
		}
		return cfg.PrivateDestinationAllowlist()
	}
}

// CostPricingConfigured reports whether an operator has set a real,
// complete per-token pricing table — all three of
// PricePerMillionInputTokens/PricePerMillionCachedTokens/
// PricePerMillionOutputTokens, never just some of them (see
// migration 000029's comment for why a partial table is treated the exact
// same as no table at all, rather than computing a partial, systematically
// wrong cost). internal/api/settings.go's validateCostSettingsRequest
// already rejects a partial set at the PUT boundary, so in practice this is
// "are all three non-nil," but this method re-checks all three anyway
// rather than trusting that invariant blindly — a defensive check costs
// nothing and protects against a row edited by hand (direct psql) outside
// the API.
func (c Config) CostPricingConfigured() bool {
	return c.PricePerMillionInputTokens != nil && c.PricePerMillionCachedTokens != nil && c.PricePerMillionOutputTokens != nil
}

// ComputeCostUSD is the one place this codebase turns real token counts
// (internal/llm.Investigation's TokensIn/TokensCacheRead/TokensOut, summed
// across every model round-trip an investigation made — see that struct's
// own doc comment) into a real dollar figure — internal/api.PersistAnalysis
// is ComputeCostUSD's sole caller, the same "one place this shape is
// defined" discipline that function's own doc comment already applies to
// the rest of the analyses row.
//
// Returns exactly 0 whenever CostPricingConfigured is false — an honest
// zero, matching the exact value this codebase already stored in every
// analyses row before this method existed, never a guessed or hardcoded
// per-model rate. When pricing IS configured, the three token counts are
// priced independently (a cached-read token is very likely NOT the same
// price as a full input token — that's the entire reason this is three
// fields, not one) and summed.
func (c Config) ComputeCostUSD(tokensIn, tokensCacheRead, tokensOut int) float64 {
	if !c.CostPricingConfigured() {
		return 0
	}
	const perMillion = 1_000_000.0
	return float64(tokensIn)/perMillion**c.PricePerMillionInputTokens +
		float64(tokensCacheRead)/perMillion**c.PricePerMillionCachedTokens +
		float64(tokensOut)/perMillion**c.PricePerMillionOutputTokens
}

// SpendCeilingActive reports whether a daily spend ceiling check is
// actually meaningful right now: a ceiling has been configured AND real
// pricing exists to compute a real total against. If pricing isn't
// configured, cost_usd is always 0 on every analyses row (ComputeCostUSD
// above), so a ceiling check against an always-0 total would either never
// fire (harmless but pointless) or, worse, look to an operator like a
// working spend control when it structurally cannot be one — treating "no
// pricing" as "the ceiling check is a no-op" is the honest behavior calling
// code (internal/api.SpendCeilingBreached and its callers) relies on this
// method to signal, not a silent bug to work around at each call site
// independently.
func (c Config) SpendCeilingActive() bool {
	return c.DailySpendCeilingUsd != nil && c.CostPricingConfigured()
}

// ActiveProviderSpendCountable reports whether the ACTIVE provider's
// investigations produce spend the daily ceiling can actually count.
//
// Under ProviderKindCLI they do not, and this is structural rather than a
// configuration mistake. The CLI runner labels its own runs
// (cmd/cli-runner's costBasisFor): under subscription auth the figure the CLI
// reports is NOTIONAL — "what this would have cost on the API" — so the run is
// persisted with analyses.cost_basis = 'subscription', and
// internal/api.TodaySpend deliberately sums only 'metered' rows, because
// feeding money that was never charged into a spend ceiling is the exact
// failure lld/07-analysis-contracts.md §10.5 exists to prevent. The
// consequence, which nothing reported until now: on a CLI/subscription
// provider the sum the ceiling checks can never grow from real activity, so
// the ceiling cannot fire however low it is set.
//
// Deliberately keyed on the provider KIND, not on "did today happen to have
// any unmeasured rows." The question a guardrail has to answer is "can this
// control ever stop anything," which is a property of how the configured
// provider bills, not of today's sample. A day with no investigations at all
// would otherwise report the ceiling as fine.
func (c Config) ActiveProviderSpendCountable() bool {
	return NormalizeProviderKind(c.LLMProviderKind) == ProviderKindAPI
}

// SpendCeilingEnforceable is the honest answer to "is the daily spend ceiling
// a working control right now" — a configured ceiling, real pricing to compute
// a total against, AND an active provider whose spend is countable at all.
//
// It is DESCRIPTIVE ONLY. It is deliberately NOT what
// internal/api.SpendCeilingBreached gates on, and SpendCeilingActive above is
// deliberately left alone: a deployment that switches from api to cli still
// has real 'metered' rows from earlier in the same UTC day, and those can
// legitimately breach. Making enforcement conditional on this method would
// silently remove a ceiling that can still fire — weakening a safety control
// to make a display honest, which is the wrong trade in that direction. So
// enforcement keeps checking whatever countable spend exists; this method only
// says whether an operator may rely on it.
//
// Reported by GET /api/v1/spend/today and the "cost" section of
// GET /api/v1/admin/settings so the Overview spend tile, the Insights spend
// tile and the Model pricing screen all derive the claim from one place rather
// than each re-deriving it from raw provider/pricing fields — the same reason
// CostPricingConfigured is reported as a boolean instead of leaving the UI to
// check three nullable numbers itself.
func (c Config) SpendCeilingEnforceable() bool {
	return c.SpendCeilingActive() && c.ActiveProviderSpendCountable()
}

// querier is the minimal subset of *pgxpool.Pool and pgx.Tx that Resolve
// needs — both types already implement QueryRow with this exact signature,
// so no adapter is needed. Accepting this interface (rather than requiring a
// bare *pgxpool.Pool) lets Resolve run two different ways that both matter:
//
//   - internal/llm.Provider.Complete and internal/notify.WebhookNotifier's
//     poll tick have no open request transaction at all — they pass the
//     pool directly.
//   - internal/api/settings.go's PUT handler calls Update and then needs to
//     build its response from the row it JUST wrote, inside the same
//     still-open, not-yet-committed request transaction (rc.Tx) — passing
//     the pool there would read the pre-update row (org_settings carries no
//     RLS, but an uncommitted write on one connection is still invisible to
//     a separate connection borrowed from the pool), silently echoing back
//     stale values in the PUT response. Passing rc.Tx itself avoids that.
type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	// Query is needed by providers.go's ListProviders, which is the only
	// multi-row read in this package; Resolve itself still uses QueryRow.
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// Resolve computes the effective configuration: the org_settings singleton
// row's column if it is non-null and non-empty (non-null and positive for
// the two analysis-bounds columns), else the corresponding
// ARGUS_LLM_BASE_URL / ARGUS_LLM_MODEL / ARGUS_LLM_API_KEY /
// ARGUS_NOTIFY_WEBHOOK_URL / ARGUS_ANALYSIS_MAX_ITERATIONS /
// ARGUS_ANALYSIS_TIME_LIMIT_SECONDS env var (the exact names already
// documented in README.md/.env.example — unchanged by this package, now
// seed defaults rather than the only source), else empty/unconfigured —
// nil, for the two analysis-bounds fields, meaning "go apply
// internal/llm/toolloop.go's own hardcoded default" (see Config's doc
// comment for why that third tier isn't resolved here).
//
// Deliberately not cached anywhere and safe to call on every use (one LLM
// call, one notify sweep tick, one settings-API request) — that per-call
// resolution is exactly what makes a change written through
// PUT /api/v1/admin/settings take effect without a hub restart.
func Resolve(ctx context.Context, q querier) (Config, error) {
	var baseURL, model, apiKey, webhookURL, loginStyle *string
	var providerKind, cliRunnerURL, cliRunnerToken, cliAgent *string
	var autonomyUnattendedNamespaces []string
	var activeProviderID, activeProviderName string
	var autoAnalysisSeverities, disabledDetectorIDs, disabledRuleIDs []string
	var analysisMaxIterations, analysisTimeLimitSeconds *int
	var retrievalEnabled bool
	var auditRetentionDays, incidentRetentionDays, findingRetentionDays *int
	var stormProtectionMaxNewIncidents, stormProtectionWindowSeconds *int
	var autoAnalysisEnabled bool
	var autonomyAutoApproveMaxRisk *string
	var autonomyMinConfidenceForAutoApprove *float64
	var autonomyRequireReversibleForAutoApprove *bool
	var autonomyUnattendedExecutionEnabled bool
	var autonomyMaxUnattendedPerCluster, autonomyMaxUnattendedFleetWide, autonomyUnattendedWindowSeconds *int
	var autonomyBreakerEnabled bool
	var autonomyBreakerPerCluster, autonomyBreakerFleetWide, autonomyBreakerWindowSeconds *int
	var pricePerMillionInputTokens, pricePerMillionCachedTokens, pricePerMillionOutputTokens, dailySpendCeilingUSD *float64
	var primaryColorID string
	var overviewDefaultWindowDays, minPasswordLength int
	var sessionIdleTimeoutMinutes *int
	// Scanned as raw jsonb bytes and unmarshalled below rather than into a
	// Go slice by pgx: a stored value that cannot be decoded must NOT fail
	// Resolve, which every investigation, notification sweep and settings
	// read goes through — see the unmarshal's own comment.
	var outboundPrivateAllowlist []byte
	var postureDisabledChecks, postureIgnoredNamespaces []string
	err := q.QueryRow(ctx,
		`SELECT p.base_url, p.model, p.api_key, s.notify_webhook_url, s.login_style,
		        p.kind, p.runner_url, p.runner_token, p.agent,
		        s.analysis_max_iterations, s.analysis_time_limit_seconds, s.retrieval_enabled,
		        s.auto_analysis_enabled, s.auto_analysis_severities,
		        s.audit_retention_days, s.incident_retention_days, s.finding_retention_days,
		        s.disabled_detector_ids, s.storm_protection_max_new_incidents, s.storm_protection_window_seconds,
		        s.disabled_rule_ids,
		        s.autonomy_auto_approve_max_risk, s.autonomy_min_confidence_for_auto_approve,
		        s.autonomy_require_reversible_for_auto_approve,
		        s.autonomy_unattended_execution_enabled,
		        s.autonomy_max_unattended_per_cluster,
		        s.autonomy_max_unattended_fleet_wide,
		        s.autonomy_unattended_window_seconds, s.autonomy_unattended_namespaces,
		        s.autonomy_breaker_enabled, s.autonomy_breaker_per_cluster,
		        s.autonomy_breaker_fleet_wide, s.autonomy_breaker_window_seconds,
		        s.price_per_million_input_tokens, s.price_per_million_cached_tokens, s.price_per_million_output_tokens,
		        s.daily_spend_ceiling_usd,
		        s.outbound_private_allowlist,
		        s.posture_disabled_checks, s.posture_ignored_namespaces,
		        s.primary_color_id, s.overview_default_window_days,
		        s.min_password_length, s.session_idle_timeout_minutes,
		        COALESCE(s.active_ai_provider_id, ''), COALESCE(p.name, '')
		   FROM org_settings s
		   -- LEFT JOIN, not an inner join: "no provider configured" is a
		   -- normal, expected state (a fresh install, or the active provider
		   -- was deleted), and it must resolve to a Config whose provider
		   -- fields are empty — which internal/llm already reports as
		   -- ErrNotConfigured — rather than to zero rows and an error.
		   LEFT JOIN ai_providers p ON p.id = s.active_ai_provider_id
		  WHERE s.id = $1`,
		singletonID,
	).Scan(&baseURL, &model, &apiKey, &webhookURL, &loginStyle,
		&providerKind, &cliRunnerURL, &cliRunnerToken, &cliAgent,
		&analysisMaxIterations, &analysisTimeLimitSeconds, &retrievalEnabled,
		&autoAnalysisEnabled, &autoAnalysisSeverities,
		&auditRetentionDays, &incidentRetentionDays, &findingRetentionDays,
		&disabledDetectorIDs, &stormProtectionMaxNewIncidents, &stormProtectionWindowSeconds,
		&disabledRuleIDs,
		&autonomyAutoApproveMaxRisk, &autonomyMinConfidenceForAutoApprove, &autonomyRequireReversibleForAutoApprove,
		&autonomyUnattendedExecutionEnabled, &autonomyMaxUnattendedPerCluster, &autonomyMaxUnattendedFleetWide, &autonomyUnattendedWindowSeconds, &autonomyUnattendedNamespaces,
		&autonomyBreakerEnabled, &autonomyBreakerPerCluster, &autonomyBreakerFleetWide, &autonomyBreakerWindowSeconds,
		&pricePerMillionInputTokens, &pricePerMillionCachedTokens, &pricePerMillionOutputTokens, &dailySpendCeilingUSD,
		&outboundPrivateAllowlist,
		&postureDisabledChecks, &postureIgnoredNamespaces,
		&primaryColorID, &overviewDefaultWindowDays,
		&minPasswordLength, &sessionIdleTimeoutMinutes,
		&activeProviderID, &activeProviderName)
	if err != nil {
		return Config{}, fmt.Errorf("settings: query org_settings: %w", err)
	}

	// A malformed stored allowlist resolves to "nothing allowlisted" rather
	// than to an error, and that is the safe direction in both senses: it
	// keeps every unrelated consumer of Config working (Resolve is on the
	// path of every investigation and every settings read), and the failure
	// mode it produces is a REFUSED private destination, not a permitted
	// one. Migration 000115's CHECK constraint makes this state hard to
	// reach through SQL at all; the handling is here because "hard to reach"
	// is not "unreachable", and the value is operator-supplied.
	var privateDestinations []OutboundPrivateDestination
	if len(outboundPrivateAllowlist) > 0 {
		if err := json.Unmarshal(outboundPrivateAllowlist, &privateDestinations); err != nil {
			logger.WarnContext(ctx, "org_settings.outbound_private_allowlist is not decodable; treating it as empty, so every private destination stays refused",
				logging.Err(err))
			privateDestinations = nil
		}
	}
	return resolve(dbRow{
		LLMBaseURL:                              baseURL,
		LLMModel:                                model,
		LLMAPIKey:                               apiKey,
		NotifyWebhookURL:                        webhookURL,
		LoginStyle:                              loginStyle,
		LLMProviderKind:                         providerKind,
		CLIRunnerURL:                            cliRunnerURL,
		CLIRunnerToken:                          cliRunnerToken,
		CLIAgent:                                cliAgent,
		ActiveProviderID:                        activeProviderID,
		ActiveProviderName:                      activeProviderName,
		AnalysisMaxIterations:                   analysisMaxIterations,
		AnalysisTimeLimitSeconds:                analysisTimeLimitSeconds,
		RetrievalEnabled:                        retrievalEnabled,
		AutoAnalysisEnabled:                     autoAnalysisEnabled,
		AutoAnalysisSeverities:                  autoAnalysisSeverities,
		AuditRetentionDays:                      auditRetentionDays,
		IncidentRetentionDays:                   incidentRetentionDays,
		FindingRetentionDays:                    findingRetentionDays,
		DisabledDetectorIDs:                     disabledDetectorIDs,
		StormProtectionMaxNewIncidents:          stormProtectionMaxNewIncidents,
		StormProtectionWindowSeconds:            stormProtectionWindowSeconds,
		DisabledRuleIDs:                         disabledRuleIDs,
		AutonomyAutoApproveMaxRisk:              autonomyAutoApproveMaxRisk,
		AutonomyMinConfidenceForAutoApprove:     autonomyMinConfidenceForAutoApprove,
		AutonomyRequireReversibleForAutoApprove: autonomyRequireReversibleForAutoApprove,
		AutonomyUnattendedExecutionEnabled:      autonomyUnattendedExecutionEnabled,
		AutonomyMaxUnattendedPerCluster:         autonomyMaxUnattendedPerCluster,
		AutonomyMaxUnattendedFleetWide:          autonomyMaxUnattendedFleetWide,
		AutonomyUnattendedWindowSeconds:         autonomyUnattendedWindowSeconds,
		AutonomyUnattendedNamespaces:            autonomyUnattendedNamespaces,
		AutonomyBreakerEnabled:                  autonomyBreakerEnabled,
		AutonomyBreakerPerCluster:               autonomyBreakerPerCluster,
		AutonomyBreakerFleetWide:                autonomyBreakerFleetWide,
		AutonomyBreakerWindowSeconds:            autonomyBreakerWindowSeconds,
		PricePerMillionInputTokens:              pricePerMillionInputTokens,
		PricePerMillionCachedTokens:             pricePerMillionCachedTokens,
		PricePerMillionOutputTokens:             pricePerMillionOutputTokens,
		DailySpendCeilingUsd:                    dailySpendCeilingUSD,
		OutboundPrivateDestinations:             privateDestinations,
		PostureDisabledChecks:                   postureDisabledChecks,
		PostureIgnoredNamespaces:                postureIgnoredNamespaces,
		PrimaryColorID:                          primaryColorID,
		OverviewDefaultWindowDays:               overviewDefaultWindowDays,
		MinPasswordLength:                       minPasswordLength,
		SessionIdleTimeoutMinutes:               sessionIdleTimeoutMinutes,
	}, os.Getenv), nil
}

// dbRow is exactly what Resolve scans out of org_settings' one row.
type dbRow struct {
	LLMBaseURL               *string
	LLMModel                 *string
	LLMAPIKey                *string
	NotifyWebhookURL         *string
	LoginStyle               *string
	LLMProviderKind          *string
	ActiveProviderID         string
	ActiveProviderName       string
	CLIRunnerURL             *string
	CLIRunnerToken           *string
	CLIAgent                 *string
	AnalysisMaxIterations    *int
	AnalysisTimeLimitSeconds *int
	RetrievalEnabled         bool
	AutoAnalysisEnabled      bool
	AutoAnalysisSeverities   []string
	AuditRetentionDays       *int
	IncidentRetentionDays    *int
	FindingRetentionDays     *int

	DisabledDetectorIDs            []string
	StormProtectionMaxNewIncidents *int
	StormProtectionWindowSeconds   *int
	DisabledRuleIDs                []string

	AutonomyAutoApproveMaxRisk              *string
	AutonomyMinConfidenceForAutoApprove     *float64
	AutonomyRequireReversibleForAutoApprove *bool
	AutonomyUnattendedExecutionEnabled      bool
	AutonomyMaxUnattendedPerCluster         *int
	AutonomyMaxUnattendedFleetWide          *int
	AutonomyUnattendedWindowSeconds         *int
	AutonomyUnattendedNamespaces            []string
	AutonomyBreakerEnabled                  bool
	AutonomyBreakerPerCluster               *int
	AutonomyBreakerFleetWide                *int
	AutonomyBreakerWindowSeconds            *int

	PricePerMillionInputTokens  *float64
	PricePerMillionCachedTokens *float64
	PricePerMillionOutputTokens *float64
	DailySpendCeilingUsd        *float64

	OutboundPrivateDestinations []OutboundPrivateDestination

	PostureDisabledChecks    []string
	PostureIgnoredNamespaces []string

	PrimaryColorID            string
	OverviewDefaultWindowDays int
	MinPasswordLength         int
	SessionIdleTimeoutMinutes *int
}

// resolve implements the DB-overrides-env-overrides-unconfigured precedence
// rule given an already-scanned row and an injectable getenv — the part of
// Resolve's logic that's testable with no database at all (see
// settings_test.go). Real callers always pass os.Getenv; tests pass a fake
// map-backed function.
func resolve(row dbRow, getenv func(string) string) Config {
	// Normalized here rather than at each call site, so no consumer ever
	// has to remember that "" means api (NormalizeProviderKind's own doc
	// comment explains why that mapping is load-bearing on upgrade). Needed
	// up front now, not just for the returned Config field, because it
	// gates the block immediately below (BUGS.md 125).
	providerKind := NormalizeProviderKind(firstNonEmpty(row.LLMProviderKind, getenv("ARGUS_LLM_PROVIDER_KIND")))

	// BUGS.md 125: LLMBaseURL/LLMModel/LLMAPIKey are meaningful only for an
	// "api"-kind provider — Config's own doc comment already says so
	// ("LLMBaseURL/LLMModel/LLMAPIKey for api, CLIRunner* for cli"), but
	// resolve() never enforced it. A "cli"-kind row's base_url/model/
	// api_key columns are pure leftover baggage (migration 000034's
	// ai_providers_kind_fields CHECK never requires them empty for
	// kind="cli", only RunnerURL non-empty), and surfacing that baggage
	// unconditionally is exactly what let a direct *llm.Provider.Complete
	// caller attempt a real HTTP call to a meaningless URL instead of
	// cleanly reporting ErrNotConfigured — the outcome Provider.Complete's
	// own doc comment already names as correct here. Zeroed outright for
	// any other kind, not merely left unread, so every Config consumer
	// (including a future direct Provider.Complete caller that bypasses
	// llm.Router/llm.Completer) sees the same "not configured for this
	// kind" answer regardless of what the row's leftover columns, or the
	// api-shaped env vars, happen to hold.
	var llmAPIKey, llmBaseURL, llmModel string
	if providerKind == ProviderKindAPI {
		llmAPIKey = firstNonEmpty(row.LLMAPIKey, getenv("ARGUS_LLM_API_KEY"))
		llmBaseURL = firstNonEmpty(row.LLMBaseURL, getenv("ARGUS_LLM_BASE_URL"))
		llmModel = firstNonEmpty(row.LLMModel, getenv("ARGUS_LLM_MODEL"))
	}
	webhookURL := firstNonEmpty(row.NotifyWebhookURL, getenv("ARGUS_NOTIFY_WEBHOOK_URL"))
	// Normalised HERE so no caller has to. An unrecognised value is treated as
	// unset rather than as an error: the column's CHECK constraint makes one
	// hard to create, but a rolled-back migration or a hand-edited row should
	// serve the default login screen, not a broken one.
	loginStyle := firstNonEmpty(row.LoginStyle, getenv("ARGUS_LOGIN_STYLE"))
	if !ValidLoginStyle(loginStyle) {
		loginStyle = DefaultLoginStyle
	}
	cliRunnerToken := firstNonEmpty(row.CLIRunnerToken, getenv("ARGUS_CLI_RUNNER_TOKEN"))

	// No env-var tier for any of these four — brand-new, DB-backed-from-day-one
	// settings with no prior deploy-time convention to preserve, same as
	// AutoAnalysisEnabled et al. above. primaryColorID and
	// overviewDefaultWindowDays are each re-validated against their closed set
	// here, same defensive posture as loginStyle immediately above: migration
	// 000131's CHECK constraints make an invalid stored value hard to reach,
	// not unreachable (a rolled-back migration or a hand-edited row), and both
	// values reach an authenticated page's DOM/initial state with nothing
	// downstream expecting to re-validate them.
	primaryColorID := row.PrimaryColorID
	if !ValidPrimaryColorID(primaryColorID) {
		primaryColorID = DefaultPrimaryColorID
	}
	overviewDefaultWindowDays := row.OverviewDefaultWindowDays
	if !ValidOverviewDefaultWindowDays(overviewDefaultWindowDays) {
		overviewDefaultWindowDays = OverviewDefaultWindowDaysValues[0]
	}

	return Config{
		LLMProviderKind: providerKind,

		LLMBaseURL:   llmBaseURL,
		LLMModel:     llmModel,
		LLMAPIKey:    llmAPIKey,
		LLMAPIKeySet: llmAPIKey != "",

		CLIRunnerURL:      firstNonEmpty(row.CLIRunnerURL, getenv("ARGUS_CLI_RUNNER_URL")),
		CLIRunnerToken:    cliRunnerToken,
		CLIRunnerTokenSet: cliRunnerToken != "",
		CLIAgent:          firstNonEmpty(row.CLIAgent, getenv("ARGUS_CLI_AGENT")),

		ActiveProviderID:   row.ActiveProviderID,
		ActiveProviderName: row.ActiveProviderName,

		NotifyWebhookURL:        webhookURL,
		NotifyWebhookConfigured: webhookURL != "",

		LoginStyle: loginStyle,

		PrimaryColorID:            primaryColorID,
		OverviewDefaultWindowDays: overviewDefaultWindowDays,
		// MinPasswordLength/SessionIdleTimeoutMinutes need no validation here:
		// the column CHECK constraints bound them, and unlike PrimaryColorID/
		// OverviewDefaultWindowDays there is no DOM-reaching closed set to
		// re-enforce defensively — an out-of-range value here is simply
		// unreachable through SQL at all.
		MinPasswordLength:         row.MinPasswordLength,
		SessionIdleTimeoutMinutes: row.SessionIdleTimeoutMinutes,

		AnalysisMaxIterations:    firstNonNilPositiveInt(row.AnalysisMaxIterations, getenv("ARGUS_ANALYSIS_MAX_ITERATIONS")),
		AnalysisTimeLimitSeconds: firstNonNilPositiveInt(row.AnalysisTimeLimitSeconds, getenv("ARGUS_ANALYSIS_TIME_LIMIT_SECONDS")),

		// No env-var tier for either field — see Config's doc comment for
		// why the DB row is the sole source, taken as-is. A nil/empty
		// row.AutoAnalysisSeverities passes straight through as nil/empty —
		// deliberately NOT defaulted to "every severity" here or anywhere
		// else, since (per Config's doc comment) that would recreate exactly
		// the dangerous-default risk this task's semantic decision was
		// designed to avoid.
		// No env-var tier, for the same reason AutoAnalysisEnabled below has
		// none: a brand-new, DB-backed-from-day-one setting with no prior
		// deploy-time convention to preserve. false really does mean
		// "unconfigured, and unconfigured is the safe default" here.
		RetrievalEnabled: row.RetrievalEnabled,

		AutoAnalysisEnabled:    row.AutoAnalysisEnabled,
		AutoAnalysisSeverities: row.AutoAnalysisSeverities,

		// Also no env-var tier, and unlike AutoAnalysisSeverities, nil
		// really does mean "unconfigured" here — it's just that
		// "unconfigured" and "the shipped default" are the same state for
		// these three (see Config's doc comment). Values already come back
		// positive-or-nil from the DB thanks to migration 000021's CHECK
		// constraints, so no extra validation is needed on read.
		AuditRetentionDays:    row.AuditRetentionDays,
		IncidentRetentionDays: row.IncidentRetentionDays,
		FindingRetentionDays:  row.FindingRetentionDays,

		// Also no env-var tier, for the same reason AutoAnalysisEnabled/
		// AutoAnalysisSeverities and the retention fields above have none —
		// see Config's doc comment. DisabledDetectorIDs passes through
		// nil/empty as "nothing disabled," never defaulted to "everything
		// disabled." StormProtectionMaxNewIncidents/WindowSeconds pass
		// through nil as "no ceiling," matching the retention fields'
		// nil-means-off convention exactly, not AnalysisMaxIterations'
		// nil-means-consult-a-further-fallback-tier convention (there is no
		// further tier here).
		DisabledDetectorIDs:            row.DisabledDetectorIDs,
		StormProtectionMaxNewIncidents: row.StormProtectionMaxNewIncidents,
		StormProtectionWindowSeconds:   row.StormProtectionWindowSeconds,
		// Same nil/empty-means-nothing-disabled pass-through as
		// DisabledDetectorIDs immediately above, for the identical reason —
		// see Config's own DisabledRuleIDs doc comment.
		DisabledRuleIDs: row.DisabledRuleIDs,

		// Also no env-var tier. AutonomyAutoApproveMaxRisk/
		// AutonomyMinConfidenceForAutoApprove pass through nil exactly like
		// AnalysisMaxIterations/AnalysisTimeLimitSeconds above — "unconfigured,
		// consult a further hardcoded-default tier downstream" — not like
		// DisabledDetectorIDs/AutoAnalysisSeverities' "nil is itself the final,
		// safe answer" (see Config's own doc comment for exactly why).
		// AutonomyRequireReversibleForAutoApprove now (BUGS.md 97, migration
		// 000085) passes through nil the same way as its two siblings above —
		// "unconfigured, consult DefaultAutonomyPolicy's own conservative
		// (true) value downstream" — rather than resolving to a concrete bool
		// here.
		AutonomyAutoApproveMaxRisk:              row.AutonomyAutoApproveMaxRisk,
		AutonomyMinConfidenceForAutoApprove:     row.AutonomyMinConfidenceForAutoApprove,
		AutonomyRequireReversibleForAutoApprove: row.AutonomyRequireReversibleForAutoApprove,
		AutonomyUnattendedExecutionEnabled:      row.AutonomyUnattendedExecutionEnabled,
		AutonomyMaxUnattendedPerCluster:         row.AutonomyMaxUnattendedPerCluster,
		AutonomyMaxUnattendedFleetWide:          row.AutonomyMaxUnattendedFleetWide,
		AutonomyUnattendedWindowSeconds:         row.AutonomyUnattendedWindowSeconds,
		AutonomyUnattendedNamespaces:            row.AutonomyUnattendedNamespaces,
		// No env-var tier for any of these four either: the breaker is a policy an
		// operator sets in the UI, and an env override would let a hub redeploy
		// silently re-arm unattended execution after a trip — the exact failure the
		// persisted trip row exists to prevent.
		AutonomyBreakerEnabled:       row.AutonomyBreakerEnabled,
		AutonomyBreakerPerCluster:    row.AutonomyBreakerPerCluster,
		AutonomyBreakerFleetWide:     row.AutonomyBreakerFleetWide,
		AutonomyBreakerWindowSeconds: row.AutonomyBreakerWindowSeconds,

		// Also no env-var tier, and like AutonomyAutoApproveMaxRisk/
		// AutonomyMinConfidenceForAutoApprove above (not like
		// DisabledDetectorIDs/AutoAnalysisSeverities), nil passes straight
		// through as nil — but unlike those two fields, nil here IS the
		// final answer (no further hardcoded-rate tier exists anywhere to
		// fall back to), not "consult a further tier downstream." See
		// Config's own doc comment for the full reasoning.
		PricePerMillionInputTokens:  row.PricePerMillionInputTokens,
		PricePerMillionCachedTokens: row.PricePerMillionCachedTokens,
		PricePerMillionOutputTokens: row.PricePerMillionOutputTokens,
		DailySpendCeilingUsd:        row.DailySpendCeilingUsd,

		// No env-var tier, and nil/empty passes straight through as "nothing
		// allowlisted" — never widened here or anywhere else. See Config's
		// own OutboundPrivateDestinations doc comment.
		OutboundPrivateDestinations: row.OutboundPrivateDestinations,

		PostureDisabledChecks:    row.PostureDisabledChecks,
		PostureIgnoredNamespaces: row.PostureIgnoredNamespaces,
	}
}

// firstNonEmpty returns *dbVal if it's non-nil and non-empty, else envVal
// (which may itself be "" — the caller treats that as "unconfigured," not
// specially here).
func firstNonEmpty(dbVal *string, envVal string) string {
	if dbVal != nil && *dbVal != "" {
		return *dbVal
	}
	return envVal
}

// firstNonNilPositiveInt is firstNonEmpty's analogue for
// AnalysisMaxIterations/AnalysisTimeLimitSeconds: the DB value wins if it's
// non-nil and positive, else the env var wins if it parses to a positive
// int, else nil ("unconfigured, let the caller's own hardcoded default
// apply" — see Config's doc comment). A non-positive or unparseable value,
// from either source, is treated exactly like "absent" rather than
// propagated or errored on — the same tolerance
// internal/llm/toolloop.go's resolveBounds already had for the env var
// alone, extended here to the DB value too so a stray bad row can never
// wedge every future analysis by making Resolve itself fail.
func firstNonNilPositiveInt(dbVal *int, envVal string) *int {
	if dbVal != nil && *dbVal > 0 {
		v := *dbVal
		return &v
	}
	if envVal != "" {
		if n, err := strconv.Atoi(envVal); err == nil && n > 0 {
			return &n
		}
	}
	return nil
}

// LLMUpdate carries the LLM half of a PUT /api/v1/admin/settings request.
// BaseURL/Model are plain strings that always overwrite the stored value —
// deliberately NOT pointers, unlike APIKey: those two fields aren't secret,
// GET already returns them in full, and there's no realistic "update the API
// key without knowing the base URL" scenario that would justify a
// leave-unchanged path for either (see internal/api/settings.go's request
// type for how the JSON shape enforces this: BaseURL/Model are non-pointer
// fields of a section that itself is a pointer — provide the "llm" object at
// all, and both fields are taken as given, including empty-string clears the
// stored override back to the env fallback; omit "llm" entirely, and this
// struct is nil, so Update leaves the whole LLM row untouched).
//
// APIKey follows the documented pointer semantics: nil means "field absent
// from the request body — leave the stored value unchanged"; non-nil (even
// pointing at "") means "field present — set it to exactly this," and ""
// explicitly clears the stored override back to the env fallback.
type LLMUpdate struct {
	BaseURL string
	Model   string
	APIKey  *string

	// ProviderKind/CLIRunnerURL/CLIAgent follow BaseURL/Model's
	// always-overwrite contract; CLIRunnerToken follows APIKey's pointer
	// contract, being the other secret in this section.
	//
	// Carried in the same section as BaseURL/Model rather than a new
	// top-level one because they answer the same question an admin is
	// already asking on that screen — "which model does this talk to, and
	// how" — and because a caller switching kinds almost always wants to set
	// the new kind's fields in the same request. ProviderKind is validated
	// against the two known kinds by internal/api before it reaches here
	// (Update does not silently accept an unknown kind: see its own
	// validation).
	ProviderKind   string
	CLIRunnerURL   string
	CLIAgent       string
	CLIRunnerToken *string
}

// AppearanceUpdate is the appearance half of a PUT request. All three fields
// are plain values rather than pointers, because none has a "clear it back to
// the env default" case worth expressing: an operator either sets every field
// in this section when they touch it (matching AnalysisUpdate/RetentionUpdate's
// per-SECTION contract, not LLMUpdate.APIKey's per-field one) or does not touch
// the section at all, and the section itself being nil already means "leave
// alone". PrimaryColorID and OverviewDefaultWindowDays joined LoginStyle here
// (PROJECT.md, 2026-10-14) rather than getting their own section, because they
// are the same kind of thing LoginStyle already is: a small, non-secret,
// closed-set Appearance choice with no further fallback tier.
type AppearanceUpdate struct {
	LoginStyle                string
	PrimaryColorID            string
	OverviewDefaultWindowDays int
}

// GeneralUpdate is the "general" section of a PUT request body — the two
// account-security floors that used to be hardcoded constants (migration
// 000131's doc comment has the full rationale for both). Follows
// AppearanceUpdate's per-SECTION contract: whenever this struct is non-nil at
// all, MinPasswordLength is taken exactly as given (there is no "leave
// unchanged" state for it — not a secret, and 0 has no valid meaning as an
// override, so a request that means to leave it alone simply omits the
// "general" section entirely). SessionIdleTimeoutMinutes follows
// AnalysisUpdate's contract instead: nil (JSON null, or the key absent — this
// package does not distinguish the two) explicitly clears the idle limit back
// to "none", which for this field is itself the final, safe state, not a
// further fallback tier.
type GeneralUpdate struct {
	MinPasswordLength         int
	SessionIdleTimeoutMinutes *int
}

// NotifyUpdate is the notify half of a PUT request, following the same
// pointer contract as LLMUpdate.APIKey.
type NotifyUpdate struct {
	WebhookURL *string
}

// AnalysisUpdate is the "analysis" section of a PUT request body — the
// investigation loop's bounds. Follows BaseURL/Model's contract, not
// APIKey's: MaxIterations/TimeLimitSeconds are taken exactly as given
// whenever this struct is non-nil at all, including nil (JSON null)
// explicitly clearing the stored override back to the env-var/hardcoded-
// default fallback. There's deliberately no third "leave this one field
// unchanged while touching the other" state the way APIKey has: unlike a
// secret, there's no reason to want that here, and 0/negative already have
// no valid meaning as an override (resolveBounds/firstNonNilPositiveInt
// both already treat a non-positive value as absent), so nil is a clean,
// unambiguous "clear" sentinel without needing a second one.
type AnalysisUpdate struct {
	MaxIterations    *int
	TimeLimitSeconds *int
	// RetrievalEnabled mirrors AutomationUpdate.Enabled's own shape: a plain
	// bool, always taken exactly as given whenever this struct is present
	// at all — not a secret, so no "leave unchanged" state is needed.
	RetrievalEnabled bool
}

// AutomationUpdate is the "automation" section of a PUT request body —
// whether newly-detected incidents are automatically investigated, and
// which severities qualify (internal/autoanalyze). Unlike every other
// *Update type in this file, there is no env-var fallback tier to preserve
// for either field — a brand-new setting, DB-backed from day one (see
// Config's doc comment) — so both fields are taken exactly as given
// whenever this struct is present at all, with no "leave this one field
// unchanged" state the way APIKey/WebhookURL have: neither field is a
// secret, so there's no reason to want that.
//
// Enabled is a plain bool: false is both "explicitly turned off" and "never
// configured," which is fine since those are the same effective state (see
// Config's doc comment). Severities is a set, not a threshold — replacing
// migration 000020's single MinSeverity *string with a checklist the user
// asked for directly (individually selectable severities, not an ordered
// "this and above" floor). Unlike MinSeverity's old nil-means-"every
// severity" sentinel, a nil/empty Severities means exactly what it looks
// like: nothing selected, so nothing is eligible for auto-analysis — see
// Config's AutoAnalysisSeverities doc comment for why that's the
// deliberately safe choice, not an oversight. There is no "leave unchanged"
// state to represent here either: whenever this struct is present at all,
// Severities is taken exactly as given, including nil/empty explicitly
// clearing the set back to "nothing selected."
type AutomationUpdate struct {
	Enabled    bool
	Severities []string
}

// RetentionUpdate is the "retention" section of a PUT request body — how
// long to keep audit_events / incidents / findings before internal/partition
// drops their oldest partitions (see Config's doc comment and migration
// 000021 for the full nil-means-forever rationale). Follows AnalysisUpdate's
// contract exactly, not APIKey's: all three fields are taken exactly as
// given whenever this struct is non-nil at all, including nil (JSON null)
// explicitly clearing an override back to the default — which for this
// section is "keep forever," not some other fallback tier, since none
// exists. There is deliberately no third "leave this one field unchanged"
// state: none of these are secrets, and a caller that wants to leave
// retention untouched simply omits the "retention" section entirely (see
// UpdateInput's doc comment).
type RetentionUpdate struct {
	AuditDays    *int
	IncidentDays *int
	FindingDays  *int
}

// DetectionUpdate is the "detection" section of a PUT request body — the
// detection layer's hub-side, live-editable config (see Config's doc
// comment and migration 000026_detection_settings for the full rationale).
// Follows RetentionUpdate's contract, not APIKey's: all three fields are
// taken exactly as given whenever this struct is non-nil at all — none of
// these is a secret, so there's no "leave just this one field unchanged"
// state worth adding. A nil/empty DisabledDetectorIDs clears the set back to
// "nothing disabled"; nil StormProtectionMaxNewIncidents/WindowSeconds
// clears the ceiling back to "unlimited," matching retention's
// nil-means-off convention. internal/api/settings.go's PUT handler validates
// DisabledDetectorIDs' entries against the known detector-ID set and
// rejects "one storm-protection field set, the other missing" before this
// struct is ever built — see that file's doc comment.
type DetectionUpdate struct {
	DisabledDetectorIDs            []string
	StormProtectionMaxNewIncidents *int
	StormProtectionWindowSeconds   *int
	// DisabledRuleIDs is BUGS.md 111's addition, following the identical
	// contract as DisabledDetectorIDs above (taken exactly as given whenever
	// Detection is non-nil at all; nil/empty clears the set back to "nothing
	// disabled") — see Config's DisabledRuleIDs doc comment for the full
	// rationale and internal/api/settings.go's doc comment for how its
	// entries are validated against the known rule-ID catalogue before ever
	// reaching this struct.
	DisabledRuleIDs []string
}

// AutonomyUpdate is the "autonomy" section of a PUT request body — the
// DB-backed override for internal/orchestrator.DefaultAutonomyPolicy (see
// migration 000028_autonomy_policy and Config's own doc comment for the full
// rationale). Follows AnalysisUpdate/RetentionUpdate's contract, not
// APIKey's: AutoApproveMaxRisk/MinConfidenceForAutoApprove/
// RequireReversibleForAutoApprove are all taken exactly as given whenever
// this struct is non-nil at all, including nil (JSON null, or the key
// simply absent — this package does not distinguish the two) explicitly
// clearing an override back to the further hardcoded-default fallback tier
// (internal/orchestrator.DefaultAutonomyPolicy) — there is no third "leave
// this one field unchanged" state to add, since none of the three is a
// secret.
//
// RequireReversibleForAutoApprove used to be a plain bool, mirroring
// AutomationUpdate.Enabled's shape on the theory that it had no
// "unconfigured" state to represent — but that meant a request that
// included the "autonomy" section while omitting this one key decoded to
// the zero value, false, which for this field is the *permissive*
// direction (BUGS.md 97): a real guardrail silently weakening with no
// warning, validation error, or "unchanged" semantics. It is now a *bool
// for exactly the same reason its two siblings above already are one: nil
// falls back to DefaultAutonomyPolicy's own true, not to an arbitrary,
// dangerous-direction zero value. See migration 000085 for the column-level
// change this required (it was NOT NULL DEFAULT true; a *bool needs a
// nullable column to have anywhere to put "unconfigured").
//
// internal/api/settings.go's PUT handler validates AutoApproveMaxRisk
// against internal/remediation.RiskLevel's closed low/medium/high set (no
// "forbidden" tier — see migration 000028's comment for why) and
// MinConfidenceForAutoApprove against the [0,1] range before this struct is
// ever built, exactly like every other numeric/enum field in this package.
type AutonomyUpdate struct {
	AutoApproveMaxRisk              *string
	MinConfidenceForAutoApprove     *float64
	RequireReversibleForAutoApprove *bool
	// UnattendedExecutionEnabled and its three caps travel together on purpose:
	// DESIGN.md §10.5 requires the blast-radius limits in the same release as
	// unattended mode, and a partial update that enabled the switch while
	// leaving the caps behind would be exactly the state that requirement
	// exists to forbid.
	UnattendedExecutionEnabled bool
	MaxUnattendedPerCluster    *int
	MaxUnattendedFleetWide     *int
	UnattendedWindowSeconds    *int
	// UnattendedNamespaces travels with the switch for the same reason the caps
	// do: enabling automation without saying where it may act is the state
	// migration 000055 exists to prevent, so the two cannot be set apart.
	UnattendedNamespaces []string
}

// BreakerUpdate is PUT /api/v1/admin/circuit-breaker's request body —
// BACKLOG.md R5, the write half of the breaker's threshold configuration
// that GET /api/v1/admin/circuit-breaker (internal/api/breaker.go) has
// always been able to read but never write. See Config's own
// AutonomyBreakerEnabled/.../WindowSeconds doc comment for what these four
// fields mean and why nil (in the DB) is "fall back to
// orchestrator.DefaultBreakerLimits", never "no limit".
//
// Deliberately NOT shaped like AutonomyUpdate above, even though both
// configure columns on the exact same org_settings row: AutonomyUpdate is
// the "autonomy" SECTION of the general PUT /api/v1/admin/settings request,
// so its own leave-unchanged granularity is "was the whole section present
// at all" — every field inside it is always taken exactly as given once the
// section exists, which is why BUGS.md 97 could happen (RequireReversibleFor
// AutoApprove has no pointer, so an absent key silently decoded to its
// zero value instead of "unchanged"). This type has no enclosing section
// of its own — a request to this dedicated endpoint's body IS this struct
// — so per-FIELD omission is the only mechanism available at all for saying
// "leave this one alone," and every field here is a pointer for exactly
// that reason: nil (the JSON key absent, or present as null — this package
// does not distinguish the two, matching LLMUpdate.APIKey/NotifyUpdate.
// WebhookURL's identical contract) means "leave the stored column
// unchanged"; non-nil means "set it to exactly this."
//
// This is why Update's SQL for this section uses COALESCE against the
// existing column rather than writing every field unconditionally the way
// every other section in this file does — see Update's implementation.
// Enabled gets the same pointer treatment despite the underlying column
// being NOT NULL DEFAULT true (no "unconfigured" state in the DATABASE):
// the pointer here is about whether THIS REQUEST touches the field, not
// about whether the column can hold NULL.
//
// There is deliberately no way, through this endpoint, to clear an explicit
// MaxPerCluster/MaxFleetWide/WindowSeconds override back to "fall back to
// the default" (the way NotifyUpdate.WebhookURL's "" clears back to the env
// fallback) — internal/api/breaker.go's validation rejects zero and
// negative values outright (ResolveBreakerLimits already treats a
// non-positive value as "unconfigured," so accepting one here would let an
// operator type 0 meaning "trip immediately" and silently get the default
// instead — the exact validateAutonomySettingsRequest precedent for the
// sibling maxUnattendedPerCluster/etc. fields), and there is no other
// sentinel value available for an int the way "" is for a string. An
// operator who wants to go back to the shipped default can set an explicit
// value equal to it (2 / 4 / 3600) — a real limitation, not an oversight,
// and one this endpoint shares with nothing else in this file, precisely
// because nothing else in this file has per-field (rather than per-section)
// leave-unchanged semantics.
type BreakerUpdate struct {
	Enabled       *bool
	MaxPerCluster *int
	MaxFleetWide  *int
	WindowSeconds *int
}

// CostUpdate is the "cost" section of a PUT request body — the
// operator-configured per-token pricing table and the daily spend ceiling
// (see Config's own doc comment and migration 000029_cost_settings for the
// full rationale). Follows AnalysisUpdate/RetentionUpdate's contract, not
// APIKey's: all four fields are taken exactly as given whenever this struct
// is non-nil at all, including nil (JSON null) explicitly clearing an
// override back to the default — "no pricing configured" / "no ceiling" for
// these four, since neither has any further fallback tier and neither is a
// secret worth a "leave this one field unchanged" state.
//
// internal/api/settings.go's PUT handler validates that the three price
// fields are either all-null or all-set (never a partial table) and that
// DailySpendCeilingUsd, if set, is a positive number, before this struct is
// ever built.
type CostUpdate struct {
	PricePerMillionInputTokens  *float64
	PricePerMillionCachedTokens *float64
	PricePerMillionOutputTokens *float64
	DailySpendCeilingUsd        *float64
}

// OutboundUpdate is the "outbound" section of a PUT request body — the
// operator's named exceptions to internal/outbound's default-deny on private
// destinations for the AI-provider and repository clients (migration 000115).
//
// Follows AnalysisUpdate/RetentionUpdate's per-SECTION contract, not
// LLMUpdate.APIKey's per-field one: whenever this struct is non-nil at all,
// PrivateDestinations is taken exactly as given, including nil/empty
// explicitly clearing the list back to "nothing allowlisted". There is no
// "leave one entry unchanged" state, because the list IS the setting — an
// operator edits it as a whole, and a partial-merge semantics would make it
// impossible to REMOVE an exception, which is the operation that matters most
// on a list of security exceptions.
//
// Validated by internal/outbound.ParseAllowlist at the API boundary for a
// clear 400, and again by Update before the write — see Update's own comment
// for why both.
type OutboundUpdate struct {
	PrivateDestinations []OutboundPrivateDestination
}

// UpdateInput is Update's argument: LLM/Notify/Analysis/Automation/Retention/
// Detection/Autonomy/Cost/Breaker are themselves pointers so a request that
// only mentions some sections (e.g. {"notify": {...}} with no "llm"/
// "analysis"/"automation"/"retention"/"detection"/"autonomy"/"cost" key at
// all) leaves the other sections completely untouched, not just their
// secret fields. Breaker is a section only in the sense that it is a
// pointer with the same "was it present in the caller's UpdateInput at all"
// gate as every other field here — internal/api never actually builds a
// PUT request that carries Breaker alongside the others, since it lives on
// its own dedicated endpoint (PUT /api/v1/admin/circuit-breaker), not inside
// PUT /api/v1/admin/settings' body. See BreakerUpdate's own doc comment for
// why its INTERNAL field semantics (per-field leave-unchanged) differ from
// every sibling *Update type's (per-section leave-unchanged).
type UpdateInput struct {
	// TenantID is only consulted when LLM is non-nil AND no provider is
	// active yet (BUGS.md 92): UpdateActiveProvider then creates the
	// installation's first ai_providers row via CreateProvider, which
	// requires a tenant id the same way every other provider-management
	// call already does (internal/api/ai_providers.go's own CreateProvider
	// call site passes rc.TenantID identically). Every other section
	// ignores this field entirely.
	TenantID   string
	LLM        *LLMUpdate
	Notify     *NotifyUpdate
	Appearance *AppearanceUpdate
	General    *GeneralUpdate
	Analysis   *AnalysisUpdate
	Automation *AutomationUpdate
	Retention  *RetentionUpdate
	Detection  *DetectionUpdate
	Autonomy   *AutonomyUpdate
	Cost       *CostUpdate
	Breaker    *BreakerUpdate
	Outbound   *OutboundUpdate
	Posture    *PostureUpdate
}

// PostureUpdate is the "posture" section of a PUT request body: both lists
// are taken exactly as given whenever the section is present.
type PostureUpdate struct {
	DisabledChecks    []string
	IgnoredNamespaces []string
}

// Update writes org_settings' singleton row inside the caller's transaction,
// per UpdateInput's documented pointer/section semantics. tx has no RLS
// scoping requirement to satisfy first (org_settings carries no row-level
// security at all — see migration 000018's comment), so any open
// transaction against the app pool works, scoped or not; internal/api's
// handler passes its already-open, tenant-scoped request transaction purely
// so this write commits atomically with the audit event describing it, not
// because org_settings itself needs that scope.
func Update(ctx context.Context, tx pgx.Tx, in UpdateInput) error {
	if in.LLM != nil {
		// Since migration 000034 there is no single provider on org_settings to
		// write — there are many rows in ai_providers and a pointer to the
		// active one. This section's documented meaning ("change the AI
		// configuration in use") maps onto "edit the active provider", which is
		// what keeps existing callers working unchanged (scripts/smoke-test.sh,
		// scripts/eval-harness). Managing the *set* of providers is the
		// dedicated /admin/ai-providers surface, not this one.
		if err := UpdateActiveProvider(ctx, tx, in.TenantID, *in.LLM); err != nil {
			return fmt.Errorf("settings: update active ai provider: %w", err)
		}
	}

	if in.Notify != nil {
		var webhookProvided bool
		var webhookURL *string
		if in.Notify.WebhookURL != nil {
			webhookProvided = true
			webhookURL = nilIfEmpty(*in.Notify.WebhookURL)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE org_settings SET
				notify_webhook_url = CASE WHEN $1 THEN $2::text ELSE notify_webhook_url END,
				updated_at = now()
			WHERE id = $3`,
			webhookProvided, webhookURL, singletonID); err != nil {
			return fmt.Errorf("settings: update notify settings: %w", err)
		}
	}

	if in.Appearance != nil {
		// Re-validated here, not just in the handler. This is the last code
		// between an operator's request and a string that an unauthenticated
		// page will render, and Update is callable from anywhere in the hub —
		// the API handler is one caller, not a gate.
		if !ValidLoginStyle(in.Appearance.LoginStyle) {
			return fmt.Errorf("settings: unknown login style %q", in.Appearance.LoginStyle)
		}
		if !ValidPrimaryColorID(in.Appearance.PrimaryColorID) {
			return fmt.Errorf("settings: unknown primary color id %q", in.Appearance.PrimaryColorID)
		}
		if !ValidOverviewDefaultWindowDays(in.Appearance.OverviewDefaultWindowDays) {
			return fmt.Errorf("settings: unsupported overview default window %d", in.Appearance.OverviewDefaultWindowDays)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE org_settings SET
				login_style = $1,
				primary_color_id = $2,
				overview_default_window_days = $3,
				updated_at = now()
			WHERE id = $4`,
			in.Appearance.LoginStyle, in.Appearance.PrimaryColorID, in.Appearance.OverviewDefaultWindowDays, singletonID); err != nil {
			return fmt.Errorf("settings: update appearance settings: %w", err)
		}
	}

	if in.General != nil {
		// Re-validated here too, same reasoning as Appearance above: Update is
		// callable from anywhere in the hub, and this is the last code between
		// an operator's request and the floor handleChangePassword actually
		// enforces. The column CHECK constraint (migration 000131) covers the
		// same range but only at the database boundary; failing here gives the
		// caller a real error rather than a constraint-violation 500.
		if in.General.MinPasswordLength < 8 || in.General.MinPasswordLength > 128 {
			return fmt.Errorf("settings: min password length %d out of range [8, 128]", in.General.MinPasswordLength)
		}
		if in.General.SessionIdleTimeoutMinutes != nil {
			if m := *in.General.SessionIdleTimeoutMinutes; m < 5 || m > 10080 {
				return fmt.Errorf("settings: session idle timeout %d minutes out of range [5, 10080]", m)
			}
		}
		if _, err := tx.Exec(ctx, `
			UPDATE org_settings SET
				min_password_length = $1,
				session_idle_timeout_minutes = $2,
				updated_at = now()
			WHERE id = $3`,
			in.General.MinPasswordLength, in.General.SessionIdleTimeoutMinutes, singletonID); err != nil {
			return fmt.Errorf("settings: update general settings: %w", err)
		}
	}

	if in.Analysis != nil {
		if _, err := tx.Exec(ctx, `
			UPDATE org_settings SET
				analysis_max_iterations = $1,
				analysis_time_limit_seconds = $2,
				retrieval_enabled = $3,
				updated_at = now()
			WHERE id = $4`,
			in.Analysis.MaxIterations, in.Analysis.TimeLimitSeconds, in.Analysis.RetrievalEnabled, singletonID); err != nil {
			return fmt.Errorf("settings: update analysis settings: %w", err)
		}
	}

	if in.Automation != nil {
		// A nil Severities is normalized to an empty (non-nil) slice before
		// this write: pgx encodes a nil []string parameter as SQL NULL, which
		// would violate auto_analysis_severities' NOT NULL constraint
		// (migration 000024) — "nothing selected" is stored as the empty
		// array '{}', never NULL, matching the column's own DEFAULT and
		// keeping "nil means empty" a Go-side convenience only, not something
		// that ever reaches the database as a literal NULL.
		severities := in.Automation.Severities
		if severities == nil {
			severities = []string{}
		}
		if _, err := tx.Exec(ctx, `
			UPDATE org_settings SET
				auto_analysis_enabled = $1,
				auto_analysis_severities = $2,
				updated_at = now()
			WHERE id = $3`,
			in.Automation.Enabled, severities, singletonID); err != nil {
			return fmt.Errorf("settings: update automation settings: %w", err)
		}
	}

	if in.Retention != nil {
		if _, err := tx.Exec(ctx, `
			UPDATE org_settings SET
				audit_retention_days    = $1,
				incident_retention_days = $2,
				finding_retention_days  = $3,
				updated_at = now()
			WHERE id = $4`,
			in.Retention.AuditDays, in.Retention.IncidentDays, in.Retention.FindingDays, singletonID); err != nil {
			return fmt.Errorf("settings: update retention settings: %w", err)
		}
	}

	if in.Detection != nil {
		// Same nil-to-empty-array normalization as Automation's Severities
		// above, and for the identical reason: pgx encodes a nil []string as
		// SQL NULL, which would violate disabled_detector_ids' NOT NULL
		// constraint (migration 000026) — "nothing disabled" is stored as
		// '{}', never NULL.
		disabled := in.Detection.DisabledDetectorIDs
		if disabled == nil {
			disabled = []string{}
		}
		// Same nil-to-empty-array normalization as disabled_detector_ids
		// immediately above, and for the identical reason: pgx encodes a nil
		// []string as SQL NULL, which would violate disabled_rule_ids' NOT
		// NULL constraint (migration 000084) — "nothing disabled" is stored
		// as '{}', never NULL.
		disabledRules := in.Detection.DisabledRuleIDs
		if disabledRules == nil {
			disabledRules = []string{}
		}
		if _, err := tx.Exec(ctx, `
			UPDATE org_settings SET
				disabled_detector_ids = $1,
				storm_protection_max_new_incidents = $2,
				storm_protection_window_seconds = $3,
				disabled_rule_ids = $4,
				updated_at = now()
			WHERE id = $5`,
			disabled, in.Detection.StormProtectionMaxNewIncidents, in.Detection.StormProtectionWindowSeconds, disabledRules, singletonID); err != nil {
			return fmt.Errorf("settings: update detection settings: %w", err)
		}
	}

	if in.Autonomy != nil {
		if _, err := tx.Exec(ctx, `
			UPDATE org_settings SET
				autonomy_auto_approve_max_risk = $1,
				autonomy_min_confidence_for_auto_approve = $2,
				autonomy_require_reversible_for_auto_approve = $3,
				autonomy_unattended_execution_enabled = $4,
				autonomy_max_unattended_per_cluster = $5,
				autonomy_max_unattended_fleet_wide = $6,
				autonomy_unattended_window_seconds = $7,
				-- coalesced to an empty array rather than allowed to be NULL: the
				-- column is NOT NULL, and "omitted from the request" must mean
				-- "no namespace permitted" rather than a constraint violation.
				autonomy_unattended_namespaces = coalesce($8::text[], '{}'),
				updated_at = now()
			WHERE id = $9`,
			in.Autonomy.AutoApproveMaxRisk, in.Autonomy.MinConfidenceForAutoApprove,
			in.Autonomy.RequireReversibleForAutoApprove,
			in.Autonomy.UnattendedExecutionEnabled, in.Autonomy.MaxUnattendedPerCluster,
			in.Autonomy.MaxUnattendedFleetWide, in.Autonomy.UnattendedWindowSeconds,
			in.Autonomy.UnattendedNamespaces,
			singletonID); err != nil {
			return fmt.Errorf("settings: update autonomy settings: %w", err)
		}
	}

	if in.Cost != nil {
		if _, err := tx.Exec(ctx, `
			UPDATE org_settings SET
				price_per_million_input_tokens = $1,
				price_per_million_cached_tokens = $2,
				price_per_million_output_tokens = $3,
				daily_spend_ceiling_usd = $4,
				updated_at = now()
			WHERE id = $5`,
			in.Cost.PricePerMillionInputTokens, in.Cost.PricePerMillionCachedTokens, in.Cost.PricePerMillionOutputTokens,
			in.Cost.DailySpendCeilingUsd, singletonID); err != nil {
			return fmt.Errorf("settings: update cost settings: %w", err)
		}
	}

	if in.Posture != nil {
		checks, namespaces := in.Posture.DisabledChecks, in.Posture.IgnoredNamespaces
		if checks == nil {
			checks = []string{}
		}
		if namespaces == nil {
			namespaces = []string{}
		}
		if _, err := tx.Exec(ctx, `
			UPDATE org_settings SET
				posture_disabled_checks = $1,
				posture_ignored_namespaces = $2,
				updated_at = now()
			WHERE id = $3`, checks, namespaces, singletonID); err != nil {
			return fmt.Errorf("settings: update posture settings: %w", err)
		}
	}

	if in.Outbound != nil {
		// Re-validated here, not only in the handler, for the same reason
		// Appearance's login style is: Update is callable from anywhere in
		// the hub, and the API handler is one caller rather than a gate.
		// This one matters more than the login style — the value being
		// written decides which private addresses the hub will dial — so it
		// goes through internal/outbound's own parser, the same code the
		// dial path uses, rather than a second copy of the rules that could
		// drift from it.
		entries := make([]outbound.AllowlistEntry, 0, len(in.Outbound.PrivateDestinations))
		for _, d := range in.Outbound.PrivateDestinations {
			entries = append(entries, outbound.AllowlistEntry{Destination: d.Destination, Reason: d.Reason})
		}
		if _, err := outbound.ParseAllowlist(entries); err != nil {
			return fmt.Errorf("settings: update outbound settings: %w", err)
		}
		// Marshalled to a jsonb array here rather than relying on pgx to
		// encode a Go slice: a nil slice would encode as SQL NULL, and the
		// column is NOT NULL — "nothing allowlisted" is stored as '[]', the
		// same nil-to-empty normalisation Automation's severities and
		// Detection's disabled IDs already apply for their text[] columns.
		list := in.Outbound.PrivateDestinations
		if list == nil {
			list = []OutboundPrivateDestination{}
		}
		encoded, err := json.Marshal(list)
		if err != nil {
			return fmt.Errorf("settings: encode outbound private allowlist: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE org_settings SET
				outbound_private_allowlist = $1::jsonb,
				updated_at = now()
			WHERE id = $2`,
			string(encoded), singletonID); err != nil {
			return fmt.Errorf("settings: update outbound settings: %w", err)
		}
	}

	if in.Breaker != nil {
		// COALESCE against the existing column, not an unconditional overwrite
		// like every section above: BreakerUpdate's own contract is per-FIELD
		// leave-unchanged (nil = don't touch this column), not per-section —
		// see that type's doc comment for why. pgx encodes a nil *bool/*int
		// parameter as SQL NULL, and COALESCE(NULL, existing) evaluates to
		// exactly the row's current value, so an omitted field genuinely never
		// reaches the database as a write at all, only as a no-op read of
		// itself.
		if _, err := tx.Exec(ctx, `
			UPDATE org_settings SET
				autonomy_breaker_enabled = COALESCE($1, autonomy_breaker_enabled),
				autonomy_breaker_per_cluster = COALESCE($2, autonomy_breaker_per_cluster),
				autonomy_breaker_fleet_wide = COALESCE($3, autonomy_breaker_fleet_wide),
				autonomy_breaker_window_seconds = COALESCE($4, autonomy_breaker_window_seconds),
				updated_at = now()
			WHERE id = $5`,
			in.Breaker.Enabled, in.Breaker.MaxPerCluster, in.Breaker.MaxFleetWide, in.Breaker.WindowSeconds,
			singletonID); err != nil {
			return fmt.Errorf("settings: update circuit breaker settings: %w", err)
		}
	}

	return nil
}

// nilIfEmpty maps "" to a nil *string — org_settings' documented convention
// (migration 000018's comment) is that a stored NULL, not an empty string,
// is what means "unset, fall back to the env var."
func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// PostureExcludes reports whether the organisation's posture settings turn
// off checkID, or leave namespace out of posture (CI-P9 d). A namespace
// pattern may start or end with "*", the agent's own convention.
func (c Config) PostureExcludes(namespace, checkID string) bool {
	for _, id := range c.PostureDisabledChecks {
		if strings.EqualFold(id, checkID) {
			return true
		}
	}
	if namespace == "" {
		return false
	}
	for _, p := range c.PostureIgnoredNamespaces {
		switch {
		case strings.HasSuffix(p, "*") && strings.HasPrefix(namespace, strings.TrimSuffix(p, "*")):
			return true
		case strings.HasPrefix(p, "*") && strings.HasSuffix(namespace, strings.TrimPrefix(p, "*")):
			return true
		case p == namespace:
			return true
		}
	}
	return false
}

// WithPostureArgs merges the organisation's posture settings into a
// get_posture_findings argument object, so the agent applies them on top of
// its own chart values. Arguments it cannot decode are returned unchanged.
func (c Config) WithPostureArgs(args json.RawMessage) json.RawMessage {
	if len(c.PostureDisabledChecks) == 0 && len(c.PostureIgnoredNamespaces) == 0 {
		return args
	}
	m := map[string]any{}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &m); err != nil {
			return args
		}
	}
	m["disabledChecks"] = c.PostureDisabledChecks
	m["ignoredNamespaces"] = c.PostureIgnoredNamespaces
	out, err := json.Marshal(m)
	if err != nil {
		return args
	}
	return out
}
