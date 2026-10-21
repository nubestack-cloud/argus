package agentversion

import (
	"log/slog"
	"os"

	"argus/internal/logging"
)

// logger is internal/agentversion's package-local structured logger
// (PROJECT.md T22).
var logger = logging.For("agentversion")

// ConfigureFromEnv is PROJECT.md P22's "the hub publishes the agent image it
// expects" half: it lets an operator move Policy's two thresholds away from
// their built-in defaults (see Policy's own doc comment) without a code
// change or a rebuild.
//
// Call once, at hub startup, before the API starts serving — Policy is a
// package-level var every request-path caller (internal/api/clusters.go's
// scanClusterSummary) reads directly, so anything set here is live for
// every request from the moment this returns.
//
// Why an env var and not (yet) a DB-backed, live-editable row in
// internal/settings, which is this codebase's usual home for "org-wide,
// live-editable configuration": internal/settings.Config is resolved fresh
// per request and already carries the LLM/notify/CLI-runner surface; folding
// two more fields into it needs a migration, a GET/PUT settings.go wire
// shape, and a Settings-page control, matching argus-add-screen's own
// plumbing rules. This env var is the tractable slice: it
// makes the expected version a real, externally-set config value today, and
// is what makes Evaluate's drift verdicts (VerdictUpgradeRecommended /
// VerdictUpgradeRequired) exercisable in a running hub before a second
// published agent image exists — set ARGUS_AGENT_RECOMMENDED_VERSION above
// whatever a dev agent reports and watch its own cluster row's verdict flip.
// Moving this into internal/settings once a second real agent build ships is
// still open — see PROJECT.md P22.
//
// An unset var changes nothing (today's default, verbatim). A SET-but-
// unparseable value (per parseVersion's own, deliberately permissive rules)
// is logged and ignored rather than failing hub startup — matching every
// other optional env var this binary reads (cmd/hub/main.go's envOrInt is
// the same shape). If the resulting MinSupportedVersion sorts above
// RecommendedVersion, that is logged too (Evaluate would then flag
// everything at or above the intended minimum as needing the recommended
// version it is also, contradictorily, being told is below minimum) but is
// still not fatal — an operator mid-edit of both is not a broken hub.
func ConfigureFromEnv() {
	if v := os.Getenv("ARGUS_AGENT_MIN_SUPPORTED_VERSION"); v != "" {
		if _, ok := parseVersion(v); ok {
			Policy.MinSupportedVersion = v
		} else {
			logger.Warn("ARGUS_AGENT_MIN_SUPPORTED_VERSION is not a parseable version; keeping the default",
				slog.String("value", v), slog.String("default", Policy.MinSupportedVersion))
		}
	}
	if v := os.Getenv("ARGUS_AGENT_RECOMMENDED_VERSION"); v != "" {
		if _, ok := parseVersion(v); ok {
			Policy.RecommendedVersion = v
		} else {
			logger.Warn("ARGUS_AGENT_RECOMMENDED_VERSION is not a parseable version; keeping the default",
				slog.String("value", v), slog.String("default", Policy.RecommendedVersion))
		}
	}

	minV, minOK := parseVersion(Policy.MinSupportedVersion)
	recV, recOK := parseVersion(Policy.RecommendedVersion)
	if minOK && recOK && recV.less(minV) {
		logger.Warn("agent version policy has a recommended version older than its own minimum supported version; verdicts from this policy will not make sense until one of the two env vars is corrected",
			slog.String("minSupportedVersion", Policy.MinSupportedVersion),
			slog.String("recommendedVersion", Policy.RecommendedVersion))
	}
}
