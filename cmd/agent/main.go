// The spoke (in-cluster) agent binary. Implements the enroll -> poll ->
// tunnel -> heartbeat lifecycle described in lld/03-agent-protocol.md,
// against internal/agent.Run.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"argus/internal/agent"
	"argus/internal/logging"
	"argus/internal/tunnel"
)

// agentVersion is sent in every Heartbeat (lld/03-agent-protocol.md §6).
// The value itself lives in internal/tunnel, alongside the Heartbeat field
// it travels in, so the hub's compatibility policy compares against the same
// constant this binary stamps rather than a hand-copied duplicate of it.
const agentVersion = tunnel.AgentBuildVersion

// logger is this binary's package-local structured logger (PROJECT.md T22).
var logger = logging.For("agent")

// fatal is the structured replacement for log.Fatalf: log at ERROR, then
// exit non-zero. The bridge cannot infer a level from a fatal's text, so an
// unconverted log.Fatalf came out at INFO.
func fatal(msg string, attrs ...any) {
	logger.Error(msg, attrs...)
	os.Exit(1)
}

func main() {
	// PROJECT.md T22, first statement in the process: install the structured
	// JSON logging chain and bridge the standard `log` package into it, so
	// this binary's own lines and internal/agent's remaining unconverted
	// ones leave the process through the same levelled, redacted handler
	// rather than in two different formats.
	logging.Setup()
	dataDir := envOr("ARGUS_AGENT_DATA_DIR", "./argus-agent-data")
	token := os.Getenv("ARGUS_ENROLLMENT_TOKEN")

	cfg := agent.Config{
		HubAPIURL: envOr("ARGUS_HUB_API_URL", "http://localhost:8080"),
		HubCAFile: os.Getenv("ARGUS_HUB_CA_FILE"), // appended to system roots; see agent.NewHubHTTPClient
		// Overrides the tunnel address the hub handed out at enrollment, so an
		// enrolled agent can move to another path (the hub's Ingress) without
		// enrolling again.
		TunnelEndpoint:        os.Getenv("ARGUS_TUNNEL_ENDPOINT"),
		Token:                 token,
		DisplayName:           os.Getenv("ARGUS_CLUSTER_DISPLAY_NAME"),
		DataDir:               dataDir,
		AgentVersion:          agentVersion,
		FindingResendCooldown: findingResendCooldownFromEnv(),

		SweepInterval:           sweepIntervalFromEnv(),
		SweepSustainedThreshold: sweepSustainedThresholdFromEnv(),
		// BACKLOG.md E9: optional override of the declarative rule set
		// embedded in this binary (internal/agent/rules/default-rules.yaml).
		// Empty (the common case) means "use the embedded default" — see
		// agent.Config.DetectionRulesPath's own doc comment for why this is
		// an agent-local file path rather than something the hub pushes.
		DetectionRulesPath: os.Getenv("ARGUS_DETECTION_RULES_FILE"),
		// BACKLOG.md C4: where the opt-in argus-dryrun ServiceAccount's
		// long-lived token is mounted (deploy/helm/argus-agent/templates/
		// dryrun.yaml's Secret volume, when values.yaml's dryRun.enabled is
		// true). Empty (the common case) means this cluster never opted in
		// — see agent.Config.DryRunTokenDir's own doc comment.
		DryRunTokenDir: os.Getenv("ARGUS_DRYRUN_TOKEN_DIR"),
		// BACKLOG.md F14: where the opt-in argus-policy-controller
		// ServiceAccount's long-lived token is mounted (deploy/helm/
		// argus-agent/templates/policycontroller.yaml's Secret volume, when
		// values.yaml's policyController.enabled is true). Empty (the common
		// case) means this cluster never opted in — see
		// agent.Config.PolicyControllerTokenDir's own doc comment.
		PolicyControllerTokenDir: os.Getenv("ARGUS_POLICY_CONTROLLER_TOKEN_DIR"),
		// BACKLOG.md C4: where this cluster's operator has pointed ARGUS at a
		// running Prometheus (deploy/helm/argus-agent's
		// metrics.prometheusService). Namespace/service empty (the common
		// case) means this cluster never configured it — see
		// agent.Config.PrometheusNamespace's own doc comment.
		PrometheusNamespace: os.Getenv("ARGUS_METRICS_PROMETHEUS_NAMESPACE"),
		PrometheusService:   os.Getenv("ARGUS_METRICS_PROMETHEUS_SERVICE"),
		PrometheusPort:      prometheusPortFromEnv(),
		// docs/CLUSTER_INSIGHT_SPECS.md CI-F1: on unless the chart's
		// objectCache.enabled turns it off.
		ObjectCacheEnabled:       os.Getenv("ARGUS_OBJECT_CACHE_ENABLED") != "false",
		ObjectCacheExclude:       splitCSV(os.Getenv("ARGUS_OBJECT_CACHE_EXCLUDE")),
		PostureEnabled:           os.Getenv("ARGUS_POSTURE_ENABLED") != "false",
		PostureInterval:          durationFromEnv("ARGUS_POSTURE_INTERVAL", time.Hour),
		PostureIgnoredNamespaces: splitCSV(os.Getenv("ARGUS_POSTURE_IGNORED_NAMESPACES")),
		PostureDisabledChecks:    splitCSV(os.Getenv("ARGUS_POSTURE_DISABLED_CHECKS")),
		PostureEmitWarnings:      os.Getenv("ARGUS_POSTURE_EMIT_WARNINGS") == "true",
		CertProbeServed:          os.Getenv("ARGUS_CERT_PROBE_SERVED") == "true",
		HelmStatusEnabled:        os.Getenv("ARGUS_HELM_STATUS_ENABLED") != "false",
		// PROJECT.md B163: the Secret this agent keeps its issued identity
		// in, so a node drain, eviction or `helm upgrade` does not lose this
		// cluster's enrollment and force a fresh token plus a repeat admin
		// accept. deploy/helm/argus-agent sets both by default; unset means
		// the old, ephemeral DataDir behaviour, which internal/agent warns
		// about on every start. ARGUS_AGENT_NAMESPACE is the pod's own
		// namespace, projected by the chart via fieldRef.
		IdentitySecretName:      os.Getenv("ARGUS_AGENT_IDENTITY_SECRET"),
		IdentitySecretNamespace: os.Getenv("ARGUS_AGENT_NAMESPACE"),
		// PROJECT.md E11: an explicit cluster fingerprint, overriding
		// internal/agent's default sha256(kube-system namespace UID). Empty
		// (the overwhelmingly common case) keeps that default, which is what
		// lld/03-agent-protocol.md §5 specifies and what every ordinary
		// install should use — agent.Config.Fingerprint has always accepted
		// one, but nothing ever populated it, so the derived value was in
		// practice the only value.
		//
		// Why this exists: sha256(kube-system UID) makes "one physical
		// cluster" and "one ARGUS cluster record" the same thing, and the
		// hub enforces that with a uniqueness check (internal/api/enroll.go's
		// 409 already-enrolled, backed by clusters_fingerprint_active_idx).
		// That is the right default, but it also makes it impossible to run a
		// SECOND agent against a cluster that already has one — which is
		// exactly what a staged identity rollout needs: bring a
		// differently-scoped agent up alongside the incumbent, compare what
		// each one sees, and only then retire the incumbent. Without this the
		// only way to change an agent's identity on a live cluster is to
		// convert it in place and hope, because the replacement cannot enroll
		// while the incumbent is connected.
		//
		// This bypasses no security control. The second agent still presents
		// a valid enrollment token, still gets its own hub-issued leaf
		// certificate from its own CSR, and still waits for an admin to
		// accept it. A fingerprint that collides with a live cluster's is
		// REJECTED by the same uniqueness check, so this cannot be used to
		// take over an existing cluster record — only to create a new one.
		// What it does cost is that two records can describe one physical
		// cluster, so both agents report the same objects and the same fault
		// opens an incident twice. That is an accepted, visible cost of a
		// side-by-side rollout, not something to leave set afterwards.
		Fingerprint: os.Getenv("ARGUS_CLUSTER_FINGERPRINT"),

		// PROJECT.md E11. Which of a cluster's tunnel connections this
		// process is: "investigate" (read-only tools, detection, facts),
		// "remediate" (approved signed plans only, no detection), or empty
		// for the pre-E11 single-process shape that serves both.
		//
		// Set by deploy/helm/argus-agent — one value per Deployment. It
		// grants nothing: what this process can do to the cluster is decided
		// by the ServiceAccount token kubelet mounted for it and by that
		// cluster's RBAC. See internal/agent.Config.Role.
		Role: os.Getenv("ARGUS_AGENT_ROLE"),
	}

	// Checked after cfg is built, not before: where an identity lives is now
	// a decision (internal/agent/identity.go), so whether one already exists
	// cannot be answered by looking in a fixed directory.
	// A remediation agent never enrolls — it adopts the identity its
	// investigation counterpart established in the shared store, and waits
	// for it (internal/agent's awaitSharedIdentity). Demanding an enrollment
	// token from it would be demanding a token it must never spend: spending
	// one would create a SECOND cluster record for one physical cluster.
	if cfg.Role != tunnel.RoleRemediate && token == "" && !agent.HasPersistedIdentity(cfg) {
		fmt.Fprintln(os.Stderr, "argus-agent: ARGUS_ENROLLMENT_TOKEN is required for first-time enrollment "+
			"(no persisted identity found)")
		fmt.Fprintln(os.Stderr, "usage: ARGUS_ENROLLMENT_TOKEN=<token> [ARGUS_HUB_API_URL=...] [ARGUS_CLUSTER_DISPLAY_NAME=...] [ARGUS_AGENT_DATA_DIR=...] [ARGUS_AGENT_IDENTITY_SECRET=... ARGUS_AGENT_NAMESPACE=...] go run ./cmd/agent")
		os.Exit(1)
	}

	// Checked at startup, not only at enrollment: an already-enrolled agent
	// never calls HubAPIURL, so a broken bundle would otherwise stay hidden
	// until the day it has to re-enroll.
	if _, err := agent.NewHubHTTPClient(cfg.HubCAFile); err != nil {
		fatal("ARGUS_HUB_CA_FILE is set but unusable", logging.Err(err))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("argus-agent starting",
		slog.String("version", agentVersion), slog.String("hub", cfg.HubAPIURL), slog.String("data_dir", cfg.DataDir))

	if err := agent.Run(ctx, cfg); err != nil {
		if ctx.Err() != nil {
			logger.Info("shutting down", logging.Err(ctx.Err()))
			return
		}
		fatal("unrecoverable error", logging.Err(err))
	}
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// findingResendCooldownFromEnv reads ARGUS_FINDING_RESEND_COOLDOWN_SECONDS,
// the agent-side, restart-required override for detector.go's
// defaultFindingResendCooldown (see that constant's doc comment for why this
// is deliberately an env var, not one of the hub's DB-backed live-editable
// settings). Absent, empty, unparseable, or non-positive all resolve to zero
// — agent.Config.FindingResendCooldown's documented "use the default"
// sentinel (internal/agent/client.go's effectiveFindingResendCooldown) —
// exactly mirroring internal/settings' own tolerance for a bad numeric
// override (treat it as absent, never fail startup over it).
func findingResendCooldownFromEnv() time.Duration {
	return positiveSecondsFromEnv("ARGUS_FINDING_RESEND_COOLDOWN_SECONDS")
}

// sweepIntervalFromEnv / sweepSustainedThresholdFromEnv are the same
// mechanism for the sweep detector's two timing policies — how often it
// samples, and how long a condition must persist before it is reported (see
// internal/agent/sweep_detector.go's defaultSweepSustainedThreshold for why
// those are operator policy rather than fixed properties of the code). Same
// zero-means-default sentinel, same tolerance for a bad value.
func sweepIntervalFromEnv() time.Duration {
	return positiveSecondsFromEnv("ARGUS_SWEEP_INTERVAL_SECONDS")
}

func sweepSustainedThresholdFromEnv() time.Duration {
	return positiveSecondsFromEnv("ARGUS_SWEEP_SUSTAINED_THRESHOLD_SECONDS")
}

// defaultPrometheusPort matches values.yaml's metrics.prometheusService.port
// default — used only when ARGUS_METRICS_PROMETHEUS_PORT is unset or
// unparseable, so a chart that sets namespace/service but somehow drops the
// port env var still resolves to something sane rather than silently
// disabling the tool (port<=0 is newMetricsProxyClient's own "not
// configured" sentinel).
const defaultPrometheusPort = 9090

// prometheusPortFromEnv reads ARGUS_METRICS_PROMETHEUS_PORT, the port the
// configured Prometheus Service listens on. Absent or unparseable both
// resolve to defaultPrometheusPort — a typo in the port must not silently
// disable query_metrics when a namespace/service WAS configured, mirroring
// this file's own tolerance for a bad numeric override elsewhere
// (positiveSecondsFromEnv). Non-positive values fall back the same way.
func prometheusPortFromEnv() int {
	raw := os.Getenv("ARGUS_METRICS_PROMETHEUS_PORT")
	if raw == "" {
		return defaultPrometheusPort
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port <= 0 {
		logger.Warn("ignoring an invalid ARGUS_METRICS_PROMETHEUS_PORT (must be a positive integer); using the default",
			slog.String("value", raw), slog.Int("default", defaultPrometheusPort))
		return defaultPrometheusPort
	}
	return port
}

// positiveSecondsFromEnv reads one positive-integer-seconds env var, returning
// zero — every caller's documented "use the default" sentinel — when it is
// absent, empty, unparseable or non-positive. A bad value is logged and
// ignored rather than fatal, mirroring internal/settings' own tolerance for a
// bad numeric override: a typo in one tuning knob must not stop an agent from
// detecting anything at all, which is the outcome that actually hurts.
func positiveSecondsFromEnv(name string) time.Duration {
	raw := os.Getenv(name)
	if raw == "" {
		return 0
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds <= 0 {
		logger.Warn("ignoring an invalid environment variable (must be a positive integer number of seconds); using the default",
			slog.String("env", name), slog.String("value", raw))
		return 0
	}
	return time.Duration(seconds) * time.Second
}

// splitCSV splits a comma-separated env value, dropping empty entries.
func splitCSV(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// durationFromEnv parses a Go duration ("1h", "30m"), falling back to def on
// an empty or unparseable value.
func durationFromEnv(name string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		slog.Warn("ignoring an invalid duration; using the default", slog.String("env", name), slog.String("value", v))
		return def
	}
	return d
}
