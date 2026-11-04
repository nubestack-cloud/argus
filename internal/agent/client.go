package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"argus/internal/logging"
	"argus/internal/redact"
	"argus/internal/tunnel"
)

// logger is this package's structured logger (PROJECT.md T22).
var logger = logging.For("agent")

// Config configures a single agent run (internal/agent.Run). All fields are
// resolved by cmd/agent/main.go from flags/env before calling Run — this
// package itself never reads the environment directly, so it stays testable
// and reusable outside the CLI entrypoint.
type Config struct {
	HubAPIURL      string // e.g. "http://localhost:8080" — the enrollment REST API.
	TunnelEndpoint string // Filled in from the enroll-status response, not user-supplied; may be empty until known.
	Token          string // Enrollment token (required for a first enrollment; unused on a restart with a persisted cert).
	Fingerprint    string // May be empty -> generated (and persisted) automatically.
	DisplayName    string // Optional advisory display name, per lld/03-agent-protocol.md §5.
	DataDir        string // Where key/cert/ca/fingerprint are persisted across restarts. Default "./argus-agent-data".
	AgentVersion   string // Sent in every Heartbeat.

	// HubCAFile, if set, is a PEM bundle appended to the system trust roots
	// for HTTPS calls to HubAPIURL — a hub behind a private CA. Empty means
	// system roots only. See NewHubHTTPClient. Set from ARGUS_HUB_CA_FILE.
	HubCAFile string

	// Role is what THIS agent process is for — one of tunnel.RoleInvestigate,
	// tunnel.RoleRemediate, or tunnel.RoleAll (PROJECT.md E11). Empty means
	// RoleAll, which is the pre-E11 single-process shape and stays the
	// default so an existing deployment's behaviour is unchanged by an
	// upgrade.
	//
	// This is not a permission. What this process can do to its cluster is
	// decided entirely by the ServiceAccount token it holds and that
	// cluster's RBAC; Role only tells the hub which of a cluster's
	// connections this one is, so read-only tools and write actions reach
	// the right peer. Setting it to RoleInvestigate does not make an agent
	// read-only — deploying it with the argus-investigate ServiceAccount
	// does, and that is the whole point of the separation.
	//
	// RoleRemediate additionally changes what this process RUNS: no
	// detectors, no sweep, no findings, no facts. See Run.
	Role string

	// TLSServerNameOverride, if set, is used as the tunnel TLS ServerName
	// instead of the host part of the resolved hub endpoint. Not part of the
	// documented contract — useful for testing against an endpoint whose
	// certificate SAN doesn't match the dial address (e.g. a docker-compose
	// service name vs. localhost port-forward).
	TLSServerNameOverride string

	// FindingResendCooldown overrides detector.go's
	// defaultFindingResendCooldown (5 minutes) — how often the *same*
	// fingerprint may be resent by either detector. Zero or negative means
	// "use the default." Set from ARGUS_FINDING_RESEND_COOLDOWN_SECONDS by
	// cmd/agent/main.go at process startup — see
	// defaultFindingResendCooldown's doc comment (internal/agent/detector.go)
	// for exactly why this is a real, working, but agent-side and
	// restart-required knob, not one of internal/settings' DB-backed,
	// live-editable settings: there is no hub-to-agent config-push path in
	// internal/tunnel's protocol today.
	FindingResendCooldown time.Duration

	// SweepInterval and SweepSustainedThreshold override
	// sweep_detector.go's DefaultSweepInterval / defaultSweepSustainedThreshold
	// — how often the sweep detector samples, and how long a condition must
	// have persisted before it is reported. Zero or negative means "use the
	// default", the same sentinel convention FindingResendCooldown uses, and
	// they are resolved by the same kind of pure helper below so the precedence
	// rule stays unit-testable. Set from ARGUS_SWEEP_INTERVAL_SECONDS /
	// ARGUS_SWEEP_SUSTAINED_THRESHOLD_SECONDS by cmd/agent.
	//
	// Agent-side and restart-required, deliberately: detection timing belongs
	// to the process doing the detecting, and a spoke that has lost contact
	// with the hub must keep detecting on its last known policy rather than
	// waiting to be told.
	SweepInterval           time.Duration
	SweepSustainedThreshold time.Duration

	// DetectionRulesPath, if set, is a path to a YAML file of declarative
	// detection rules (internal/agent/rules.go's Rule schema — BACKLOG.md
	// E9) that REPLACES the embedded default rule set. Empty means "use the
	// default set shipped with this binary" (internal/agent/rules/
	// default-rules.yaml). Set from ARGUS_DETECTION_RULES_FILE by cmd/agent.
	//
	// Agent-local, like SweepInterval/SweepSustainedThreshold above and for
	// the same reason (see rules.go's package doc): there is no
	// hub-to-agent config-push mechanism in internal/tunnel's protocol
	// today, and a spoke that has lost contact with the hub must keep
	// detecting on its last known rules rather than waiting to be told new
	// ones.
	DetectionRulesPath string

	// ObjectCacheEnabled starts the in-memory object cache the
	// cluster-insight tools read (docs/CLUSTER_INSIGHT_SPECS.md CI-F1).
	// ObjectCacheExclude names kinds not to watch, as "group/Kind" (core
	// group as "/Kind" or a bare "Kind"). Investigation-role agents only.
	ObjectCacheEnabled bool
	ObjectCacheExclude []string

	// Posture* configure the best-practice detector (CI-S4). Disabled
	// checks are check IDs; ignored namespaces accept a trailing "*".
	PostureEnabled           bool
	PostureInterval          time.Duration
	PostureIgnoredNamespaces []string
	PostureDisabledChecks    []string
	PostureEmitWarnings      bool
	// CertProbeServed enables the opt-in served-certificate probe (CI-S16);
	// HelmStatusEnabled the Helm release-status check (CI-S17).
	CertProbeServed   bool
	HelmStatusEnabled bool

	// DryRunTokenDir, if set, is the directory this agent expects the
	// opt-in argus-dryrun ServiceAccount's long-lived token to be mounted
	// into (deploy/helm/argus-agent/templates/dryrun.yaml's Secret volume,
	// when values.yaml's dryRun.enabled is true) — "<dir>/token" and,
	// optionally, "<dir>/ca.crt". Empty (the default, matching
	// ARGUS_DRYRUN_TOKEN_DIR unset) means this cluster never opted into the
	// pack; dry_run_patch is then simply unavailable, same as any other
	// agent older than the feature.
	//
	// This is a SEPARATE bearer credential from whatever ServiceAccount this
	// whole Deployment runs as (serviceAccountName, resolved by
	// rest.InClusterConfig() from the pod's own default-mounted token) —
	// deliberately, because the ValidatingAdmissionPolicy that restricts
	// argus-dryrun to dryRun=All requests is scoped by exact identity, and
	// RBAC is additive: if this agent's PRIMARY identity ever also held
	// argus-remediate's unrestricted write grant, folding argus-dryrun's
	// grant into that same identity would make the "dryRun=All only"
	// policy either block real remediation or stop restricting anything,
	// depending on which policy's matchConditions happened to catch the
	// request first. See internal/agent/dryrun_client.go.
	DryRunTokenDir string

	// PolicyControllerTokenDir, if set, is the directory this agent expects
	// the opt-in argus-policy-controller ServiceAccount's long-lived token
	// to be mounted into (deploy/helm/argus-agent/templates/
	// policycontroller.yaml's Secret volume, when values.yaml's
	// policyController.enabled is true) — "<dir>/token" and, optionally,
	// "<dir>/ca.crt". Empty (the default) means this cluster never opted
	// into BACKLOG.md F14's per-execution admission-policy widening;
	// open_execution_window/close_execution_window are then simply
	// unavailable, and any plan whose fields need widening is refused before
	// execution rather than silently attempted.
	//
	// A SEPARATE bearer credential from both the primary identity and
	// argus-dryrun, for the same additive-RBAC reason DryRunTokenDir's own
	// comment gives, applied to a different pair of controls: this
	// identity's entire value is that it can create/update/delete
	// ExecutionWindow objects and NOTHING else, and folding that grant into
	// either existing identity would either make argus-investigate
	// write-capable or let argus-remediate widen its own admission-policy
	// bound. See internal/agent/policywindow_client.go.
	PolicyControllerTokenDir string

	// PrometheusNamespace/PrometheusService/PrometheusPort are BACKLOG.md C4's
	// query_metrics half: where this cluster's operator has pointed ARGUS at
	// a running Prometheus, via values.yaml's metrics.prometheusService. All
	// three empty/zero (the default) means this cluster never configured it
	// — query_metrics is then simply unavailable, same as any other agent
	// older than the feature.
	//
	// Unlike DryRunTokenDir/PolicyControllerTokenDir above, this is NOT a
	// second credential: query_metrics reaches Prometheus through this
	// agent's own primary identity (argus-investigate), narrowly widened by a
	// namespace-scoped Role naming this one Service
	// (deploy/helm/argus-agent/templates/metrics.yaml) — there is no
	// ValidatingAdmissionPolicy-scoping reason to keep it separate the way
	// there is for dry_run_patch/open_execution_window, because this tool
	// never writes anything. See internal/agent/metrics_client.go.
	PrometheusNamespace string
	PrometheusService   string
	PrometheusPort      int

	// IdentitySecretName and IdentitySecretNamespace are PROJECT.md B163:
	// the Kubernetes Secret this agent keeps its issued identity in, so a
	// pod replacement does not lose the cluster's enrollment. Set from
	// ARGUS_AGENT_IDENTITY_SECRET / ARGUS_AGENT_NAMESPACE by cmd/agent, both
	// of which deploy/helm/argus-agent sets by default.
	//
	// An empty name selects the pre-B163 behaviour — identity in DataDir,
	// lost on any pod replacement — which is now something an operator has
	// to choose explicitly (identity.mode=ephemeral) and which logs a
	// warning on every start. A name that is set but unreachable is a
	// startup error, never a silent downgrade: see internal/agent/identity.go's
	// header for why.
	IdentitySecretName      string
	IdentitySecretNamespace string
}

const (
	certFileName           = "cert.pem"
	keyFileName            = "key.pem"
	caFileName             = "ca.pem"
	fingerprintFileName    = "fingerprint.txt"
	hubEndpointFileName    = "hub-endpoint.txt"
	planSigningKeyFileName = "plan-signing-key.bin"
	// clusterIDFileName persists the hub-assigned cluster ID (postEnroll's
	// response) — needed so a signed remediation plan's own ClusterID field
	// (internal/remediation.SignedPlan) can be checked against this agent's
	// actual identity at verify time (internal/agent/tools.go's
	// verifySignedPlan), not just implicitly trusted because the envelope
	// arrived over this agent's own tunnel connection.
	clusterIDFileName = "cluster-id.txt"

	heartbeatInterval = 30 * time.Second

	pollBackoffInitial = 5 * time.Second
	pollBackoffCap     = 30 * time.Second

	tunnelBackoffInitial = 5 * time.Second
	// tunnelBackoffCap bounds how long an agent waits between tunnel dials
	// once the hub is unreachable. Kept short because the usual outage is a
	// hub restart of 15-20 seconds: with a one-minute cap an agent that just
	// missed the new hub waited up to another minute (measured on rke2,
	// 2026-10-12). At 15 seconds, 200 clusters dial about 13 times a second
	// while a hub is down, jittered — nothing to a TLS listener.
	tunnelBackoffCap = 15 * time.Second

	// tunnelTerminalBackoff is how long this agent waits before its next
	// reconnect attempt after the hub told it (tunnel.ServerMessage.Terminal)
	// that this tunnel was severed because of this cluster's own state —
	// Archived or Rejected — rather than a transient failure. Deliberately
	// far longer than tunnelBackoffCap: measured on one real deployment, an
	// agent that could not tell "decommissioned" apart from "hub restarting"
	// produced 302 reconnect attempts in 10 minutes (roughly 43,000 log
	// lines/day from that one agent alone), and decommissioning a fleet of
	// clusters multiplies that by however many are now sitting in the same
	// loop. This agent does NOT exit on a terminal signal — Kubernetes
	// restarts this Deployment's pod on any exit, which would trade this
	// reconnect storm for a CrashLoopBackOff, which is worse.
	//
	// Recovery, if an operator later un-archives (or approves) this cluster:
	// the very next reconnect attempt is an entirely ordinary dial, and if
	// the hub no longer refuses it, the session proceeds normally and the
	// 30s heartbeat cadence resumes immediately — no restart, no re-
	// enrollment, no separate "recovered" signal needed. That next attempt
	// can be up to tunnelTerminalBackoff away, never sooner: this agent only
	// ever dials out and the hub has no channel to reach an agent that
	// isn't connected, so there is no cheaper way to notice a restore
	// faster without re-polling at a cadence that reintroduces the exact
	// storm this constant exists to stop. Kept at "about 30 minutes" rather
	// than shorter for that reason — a fleet-wide decommission (or a fleet-
	// wide accidental archive an operator then reverses) must not turn back
	// into per-cluster hammering just because the wait was shortened.
	//
	// A plain disconnect that carries NO terminal signal — a hub restart, a
	// network blip — never touches this constant: it keeps using the
	// existing tunnelBackoffInitial -> tunnelBackoffCap ladder below,
	// unchanged, so those cases still reconnect within seconds.
	tunnelTerminalBackoff = 30 * time.Minute

	// findingChannelBufferSize used to be the whole of the detector-to-tunnel
	// buffering story: one 100-slot channel with a non-blocking send at each
	// detector, so an ordinary sweep on an ordinary cluster (111-185
	// findings, measured) silently discarded everything past slot 100 — and
	// stamped the discards into the resend cooldown as though they had gone
	// out. PROJECT.md B176; the mechanism, the evidence and what replaced it
	// are documented in finding_queue.go, which now owns this path.
	//
	// The name survives only as the handoff channel's buffer, which is
	// findingHandoffBufferSize. Nothing should add a second meaning to it.
)

// factsWithDetection is GatherFacts plus this agent's RESOLVED detector timings.
//
// BACKLOG D5: the timings are per-agent environment variables by deliberate design
// — a spoke that has lost the hub must keep detecting on its last known policy —
// so the hub cannot know them, and an operator reading Settings could not tell what
// any cluster's detection latency actually was. It varies by an order of magnitude
// (CAPABILITIES.md §6: 61 seconds at 30/60 against ten to fifteen minutes at the
// shipped 300/600 defaults).
//
// Reported through the same three effective* resolvers the detectors themselves
// use, so what the hub is told is what the detectors are doing rather than a second
// reading of the same config. Reporting rather than accepting configuration keeps
// the design property intact: the hub observes, and cannot overrule.
func factsWithDetection(cfg Config) tunnel.ClusterFacts {
	facts := GatherFacts()
	facts.Detection = &tunnel.ClusterDetection{
		SweepIntervalSeconds:      int(effectiveSweepInterval(cfg.SweepInterval).Seconds()),
		SustainedThresholdSeconds: int(effectiveSweepSustainedThreshold(cfg.SweepSustainedThreshold).Seconds()),
		ResendCooldownSeconds:     int(effectiveFindingResendCooldown(cfg.FindingResendCooldown).Seconds()),
	}
	// BACKLOG.md C4: reported the same "ask the API server, don't infer from
	// the chart value" way ClusterRemediation already is above (gathered by
	// GatherFacts itself) — see gatherClusterDryRunAuthority's doc comment
	// for why this is a genuinely separate identity's answer rather than a
	// second question asked of the same clientset.
	facts.DryRun = gatherClusterDryRunAuthority(context.Background(), cfg.DryRunTokenDir)
	facts.ObjectCache = objectCacheFacts()
	facts.Summary = clusterSummaryJSON()
	// BACKLOG.md C4: query_metrics' half of the same discipline — asked with
	// this agent's own PRIMARY client, since (unlike dry_run_patch) there is
	// no second identity here to ask with instead. Built fresh from
	// loadKubeConfig() rather than threading toolExecutor's own typed client
	// through, because factsWithDetection can run before Run has built one
	// (or after a rebuild) and has never depended on it existing.
	if ext, err := newExternalMetricsClientFromEnv(); err == nil && ext != nil {
		facts.Metrics = externalMetricsAuthority(context.Background(), ext)
	} else {
		facts.Metrics = gatherClusterMetricsAuthorityFromConfig(context.Background(), cfg.PrometheusNamespace, cfg.PrometheusService, cfg.PrometheusPort)
	}
	facts.Agent = &tunnel.ClusterAgentInstall{Image: runningAgentImage(), Namespace: os.Getenv("ARGUS_POD_NAMESPACE"), Kubecost: os.Getenv("ARGUS_KUBECOST_URL") != "", SelfUpgrade: os.Getenv("ARGUS_SELF_UPGRADE") == "true"}
	if cfg.PrometheusService == "" && !facts.Metrics.External {
		if c := activeObjectCache.Load(); c != nil {
			if svcs, err := c.Services(""); err == nil {
				facts.Metrics.Suggested = detectMetricsService(svcs)
			}
		}
	}
	// PROJECT.md T13: each built-in detector's own reported run health — see
	// detector_status.go for the full mechanism (each detector's own
	// goroutine records its own success/error; denied reads are read off
	// the existing discovered-watch-set capability check, not a new
	// SelfSubjectAccessReview).
	facts.Detectors = snapshotClusterDetectors(context.Background())
	// PROJECT.md E11: how much of the cluster those detectors actually ran
	// over. Detectors above says whether each one RAN; this says what it ran
	// OVER, which on a scoped identity is the number that moves. Reuses the
	// same discovered-watch-set cache — no new API call — plus the sweep's
	// own positive read record. See coverage.go.
	facts.Coverage = snapshotClusterCoverage(context.Background())
	return facts
}

// factsRefreshInterval is how often an ESTABLISHED tunnel session re-gathers
// and re-sends this agent's ClusterFacts (PROJECT.md B177). It is a
// production constant; only client_facts_refresh_test.go's
// shortenFactsRefresh narrows it, so a refresh can be observed in
// milliseconds rather than minutes.
//
// Why not every heartbeat (30s), and why not never (the defect):
//
//   - The cost is the GATHER, not the send. One pass is a ServerVersion, a
//     node List, a metrics.k8s.io List and three SelfSubjectAccessReviews on
//     a stock cluster — measured at 8-27ms against a live kind cluster — and
//     up to ~68 API calls on a cluster whose operator listed the maximum 20
//     remediation namespaces (maxNamespaceRemediationChecks). Repeating that
//     four times a minute per agent, forever, to re-report numbers that
//     mostly do not change is waste; repeating it never is the bug.
//   - The freshest thing in the payload is each detector's own
//     LastSuccessAt, which a healthy watch re-affirms every
//     detectorSuccessHeartbeatInterval (1 minute). Refreshing at twice that
//     bounds the age of a healthy detector's reported last success at about
//     three minutes — recent enough that an operator reading the relative
//     time on the fleet page cannot mistake a working detector for a stalled
//     one, which is the misreading this whole signal exists to prevent.
//   - Measured wire cost of one refresh, as the encoded ClientMessage:
//     1,568 bytes for the live five-node rke2 cluster, 791 for a one-node
//     kind cluster (a Heartbeat, for scale, is 92). That is roughly
//     0.8 kB/min per agent and about 2.6 kB/s across a 200-cluster fleet,
//     plus one cluster_facts upsert per cluster per interval. Bandwidth is
//     not what makes this interval two minutes; the gather is.
//
// DeniedReads used to have a second, larger floor this interval could not
// lower: it is read from discoveredWatchSetCache, whose TTL was 15 minutes,
// so a revoked permission reached the hub within one refresh interval of the
// AGENT noticing it rather than one interval of the revocation (PROJECT.md
// B177). That cache's TTL is now deliberately SHORTER than this interval
// (DefaultWatchSetRefreshInterval, 1 minute), so every gather below re-reads
// it and DeniedReads is exactly as fresh as everything else in this payload.
// This interval is therefore the only floor on it, which is what makes the
// staleness an operator can reason about: one number, the same one that
// governs factsUpdatedAt beside it.
var factsRefreshInterval = 2 * time.Minute

// inventoryMessage is the ONE place a ClusterFacts payload becomes a wire
// message. Both senders — runTunnelSession's initial send on connect and its
// periodic refresh — go through it, so the two cannot drift into disagreeing
// about the shape they report (B177's "one shape, at most two senders").
// FullResync is true for both because both are exactly that: every field is
// re-gathered from scratch, nothing is diffed, and the hub's
// handleInventoryDelta replaces the stored facts row wholesale.
//
// Not redacted, and that is a considered answer rather than an omission
// (BACKLOG.md G8 covers the whole egress surface, so each path needs one).
// ClusterFacts is a closed struct of identifiers and numbers — Kubernetes
// version, node count, per-node name and allocatable CPU/memory quantities
// (tunnel.NodeStatus). It carries no object labels, no annotations and no
// cluster-authored freeform text, so there is no field class to drop and
// nothing for the pattern layer to find. Adding a freeform field here —
// node labels, a condition message, a distribution string read off the
// cluster — changes that, and this comment is the reminder to redact it
// when someone does.
//
// ClusterCoverage.DeniedSample (PROJECT.md E11) is the first field here whose
// contents are read off the cluster rather than counted, and it was checked
// against exactly that reminder before being added: its entries are API type
// identifiers of the form "group/resource", which Kubernetes constrains to
// the RFC 1123 subdomain charset (lowercase alphanumerics, "-", "."). They
// name which software is installed, not anything that software holds — the
// same class of fact as KubernetesVersion, which this payload has always
// carried. It is bounded (discovery.go's maxDeniedSample) so it cannot grow
// without limit, and it carries no object names, namespaces, labels or
// annotations. A future field that carries any of those does need redacting,
// and this paragraph does not license it. It now covers the refresh path too: a field added to
// ClusterFacts is sent every interval, not once per reconnect.
// effectiveRole resolves Config.Role to one of tunnel's three constants,
// defaulting an empty or unrecognised value to RoleAll — the pre-E11 shape.
// Defaulting rather than failing is deliberate: a typo'd role must not stop
// an agent connecting at all, and RoleAll is the behaviour it had before the
// field existed.
func effectiveRole(cfg Config) string {
	switch cfg.Role {
	case tunnel.RoleInvestigate, tunnel.RoleRemediate:
		return cfg.Role
	case tunnel.RoleAll, "":
		return tunnel.RoleAll
	default:
		logger.Warn("unrecognised connection role; running as general-purpose default", slog.String("role", cfg.Role), slog.String("default_role", tunnel.RoleAll))
		return tunnel.RoleAll
	}
}

func inventoryMessage(facts tunnel.ClusterFacts) tunnel.ClientMessage {
	return tunnel.ClientMessage{
		InventoryDelta: &tunnel.InventoryDelta{
			Facts:      facts,
			FullResync: true,
		},
	}
}

// startFactsRefresh runs the periodic gather off the session goroutine and
// hands each snapshot back over the returned channel, which runTunnelSession's
// select loop — the tunnel's single writer — encodes. Returns immediately.
//
// The gather makes several bounded API-server calls (factsTimeout each), so
// doing it inline in the select loop would stall heartbeats, findings and
// tool results behind a slow API server. It is NOT cancellable mid-gather:
// factsWithDetection builds its own context.Background() deadlines, so this
// goroutine can outlive a cancelled ctx by up to one gather (seconds) before
// noticing. It holds nothing and writes to nothing but its own channel by
// then, so that is harmless.
//
// Newest wins. The channel is buffered 1 and a snapshot the session has not
// yet sent is DISCARDED in favour of a fresher one rather than queued: these
// are absolute-state snapshots, not events, so the only one worth sending is
// the most recent, and a session that fell behind must never spend its
// recovery sending a backlog of superseded facts.
func startFactsRefresh(ctx context.Context, cfg Config, interval time.Duration) <-chan tunnel.ClusterFacts {
	out := make(chan tunnel.ClusterFacts, 1)
	if interval <= 0 {
		// Defensive: a non-positive interval would panic time.NewTicker.
		// Returning a channel nothing ever sends on leaves the session with
		// exactly its pre-B177 behaviour rather than crashing the agent.
		return out
	}
	// A session that opened before the object cache finished its first
	// sync sent a summary that says "syncing" and carries no figures; it
	// re-gathers the moment the sync completes instead of leaving that
	// state on the cluster page for up to a whole interval. nil (blocks
	// forever) when there is no cache or it had already synced.
	firstSync := pendingFirstSync()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			case <-firstSync:
				firstSync = nil
			}

			facts := factsWithDetection(cfg)
			if ctx.Err() != nil {
				return
			}
			// This goroutine is the channel's only sender, so after the
			// drain below the buffer always has room and neither send can
			// block. Both are written non-blocking anyway: a wedged send
			// here would silently stop every later refresh.
			select {
			case <-out:
			default:
			}
			select {
			case out <- facts:
			default:
			}
		}
	}()
	return out
}

// effectiveFindingResendCooldown resolves Config.FindingResendCooldown
// against detector.go's defaultFindingResendCooldown — configured wins if
// positive, else the default — pulled out as its own pure function so the
// precedence rule is unit-testable without spinning up Run's full agent
// lifecycle (see client_test.go).
func effectiveFindingResendCooldown(configured time.Duration) time.Duration {
	if configured > 0 {
		return configured
	}
	return defaultFindingResendCooldown
}

// effectiveSweepInterval / effectiveSweepSustainedThreshold resolve their
// Config fields against sweep_detector.go's defaults on the same
// "configured wins if positive" rule as effectiveFindingResendCooldown.
func effectiveSweepInterval(configured time.Duration) time.Duration {
	if configured > 0 {
		return configured
	}
	return DefaultSweepInterval
}

func effectiveSweepSustainedThreshold(configured time.Duration) time.Duration {
	if configured > 0 {
		return configured
	}
	return defaultSweepSustainedThreshold
}

// Run implements the full spoke lifecycle: enroll (if not already enrolled),
// poll for admin approval and cert issuance, then dial and serve the mTLS
// tunnel, reconnecting with backoff on any tunnel failure, until ctx is
// cancelled. Returns a non-nil error only for unrecoverable failures
// (rejected enrollment, bad token, ctx cancellation) — cmd/agent/main.go maps
// that to a non-zero exit code.
func Run(ctx context.Context, cfg Config) error {
	// PROJECT.md P18, first thing in the process' life because it changes how
	// every allocation below behaves: tell the Go runtime about the memory
	// limit the container has and the runtime otherwise cannot see. Without
	// it the GC targets twice the live heap and grows RSS straight through a
	// cgroup limit it knows nothing about, and the kernel — not this code —
	// decides what happens next, mid-sweep, taking the detectors' dedup
	// state with it. A no-op when there is no limit or when an operator has
	// set GOMEMLIMIT themselves; see applyGoSoftMemoryLimit.
	applyGoSoftMemoryLimit()

	// Created once, here, so it survives every tunnel reconnect below — a
	// fresh queue per connection would discard whatever the detectors
	// produced while disconnected. The detector goroutines started
	// immediately below each run for the lifetime of the process,
	// independent of whether a tunnel session currently exists: they all
	// feed findingQueue.In() (see internal/agent/detector.go,
	// internal/agent/pod_conditions_detector.go, and
	// internal/agent/sweep_detector.go), and runTunnelSession's select loop
	// reads findingQueue.Out(), which is that queue's only consumer
	// regardless of how many producer goroutines feed it.
	//
	// PROJECT.md B176: the pump goroutine between the two ends is the whole
	// point — a plain shared channel made the tunnel writer the direct
	// consumer of a burst producer, so an ordinary sweep outran it and the
	// overflow was discarded. finding_queue.go has the mechanism and the
	// evidence.
	findings := newFindingQueue(findingQueueCapacity)
	go findings.Run(ctx)

	// PROJECT.md E11. A remediation agent runs NO detection: no warning-event
	// watch, no pod-conditions watch, no sweep, no declarative rules.
	//
	// This is not an optimisation. The two agents run against the same
	// cluster and would see the same objects, so a remediation agent that
	// also detected would open a second incident for every fault — the exact
	// cost values.yaml's clusterFingerprint override warns about for a
	// side-by-side rollout, except here it would be permanent and
	// unavoidable. Detection belongs to the investigation identity, which is
	// the one that holds the read grant for it; this process holds a write
	// grant and a signed-plan verifier, and nothing else.
	//
	// The finding queue itself is still created and pumped above, because
	// heartbeatMessage reports its depth and a nil queue would mean special
	// cases in the session loop for a queue that is simply always empty.
	role := effectiveRole(cfg)
	detecting := role != tunnel.RoleRemediate

	findingCh := findings.In()
	cooldown := effectiveFindingResendCooldown(cfg.FindingResendCooldown)
	if detecting {
		go watchWarningEvents(ctx, findingCh, cooldown)
		go watchPodConditions(ctx, findingCh, cooldown)
	}

	// BACKLOG.md E9: resolve the declarative rule set once, here, same
	// lifetime as findingCh and toolExecutor below — a rules file typo must
	// not stop this agent from detecting anything at all (the 17 hand-written
	// checkers are unaffected either way), so a load failure is logged and
	// this agent runs with zero rule-based checks rather than failing to
	// start. See rules.go's LoadRules doc comment.
	var rules []Rule
	if detecting {
		loaded, err := LoadRules(cfg.DetectionRulesPath)
		if err != nil {
			logger.WarnContext(ctx, "detection rules load failed; continuing with zero declarative rule checks", logging.Err(err))
			loaded = nil
		}
		rules = loaded
		go runSweepDetector(ctx, findingCh, cooldown, effectiveSweepInterval(cfg.SweepInterval), effectiveSweepSustainedThreshold(cfg.SweepSustainedThreshold), rules)
	}

	// Built once, here, for the same reason findingCh is created once above:
	// it must survive every tunnel reconnect, and constructing it fresh per
	// connection would just repeat the same kubeconfig resolution GatherFacts
	// already did. A nil executor (no reachable cluster config) is a normal,
	// expected outcome this MVP supports — every ToolRequest then gets a
	// clean "no reachable cluster" ToolResult.Error instead of the agent
	// failing to start.
	toolExecutor, err := newToolExecutor(cfg.DryRunTokenDir, cfg.PolicyControllerTokenDir, cfg.PrometheusNamespace, cfg.PrometheusService, cfg.PrometheusPort)
	if err != nil {
		logger.WarnContext(ctx, "no reachable cluster config for the tool executor; tool requests will fail until reachable", logging.Err(err))
		toolExecutor = nil
	}

	// BACKLOG.md F14's crash-safety backstop: independent of whether the hub
	// is connected, ever asks to close a window, or has crashed outright,
	// this agent sweeps its own ExecutionWindow object on its own timer and
	// removes anything older than policyWindowTTL. Started here, alongside
	// the other background goroutines above, for the same reason they run
	// unconditionally for the process lifetime rather than only while a
	// tunnel session is up: the thing this sweep exists to bound is exactly
	// "the hub is not here to ask", so it must not depend on the hub being
	// here to start it. A no-op, logged once, when this cluster never
	// mounted the pack.
	// Bootstrap the ExecutionWindow singleton (see
	// ensureExecutionWindowBootstrap's own comment for the real,
	// live-verified defect this fixes) before the sweeper starts — the
	// sweeper only ever edits an existing object, and must never be the
	// thing that races to create it.
	go ensureExecutionWindowBootstrap(ctx, toolExecutor)
	go runExecutionWindowSweeper(ctx, toolExecutor)
	// BACKLOG.md V3: the same rule set runSweepDetector above just started
	// detecting with, so reevaluate_rule can look a hub-supplied rule ID back
	// up against the exact rule that is actually running in this process —
	// never a second, independently-loaded copy that could drift from it.
	// Safe on a nil toolExecutor (SetRules no-ops) and on a nil/empty rules
	// (reevaluateRule then reports every ruleId as unknown).
	toolExecutor.SetRules(rules)

	if detecting {
		if startObjectCache(ctx, cfg, toolExecutor, defaultObjcacheHook()) != nil {
			pc := postureConfig{Interval: cfg.PostureInterval, IgnoredNamespaces: cfg.PostureIgnoredNamespaces,
				DisabledChecks: cfg.PostureDisabledChecks, EmitWarnings: cfg.PostureEmitWarnings, HelmStatus: cfg.HelmStatusEnabled}
			certProbeServed = cfg.CertProbeServed
			postureCfgMu.Lock()
			activePostureConfig = pc
			postureCfgMu.Unlock()
			if cfg.PostureEnabled {
				go runPostureDetector(ctx, toolExecutor, findingCh, postureCooldown(pc.Interval), pc)
			}
		}
	}

	if cfg.DataDir == "" {
		cfg.DataDir = "./argus-agent-data"
	}
	// PROJECT.md B163: WHERE the identity lives is now a decision
	// (identity.go), not a fixed directory. Resolved before anything reads
	// it, and a configured-but-unreachable store fails here rather than
	// downgrading to an identity that a node drain destroys.
	store, err := newIdentityStore(cfg)
	if err != nil {
		return err
	}

	var certPEM, keyPEM, caPEM, planSigningKey []byte
	var clusterID string
	hubEndpoint := cfg.TunnelEndpoint

	certPEM, certFound, err := store.read(certFileName)
	if err != nil {
		return fmt.Errorf("read persisted cert: %w", err)
	}
	keyPEM, keyFound, err := store.read(keyFileName)
	if err != nil {
		return fmt.Errorf("read persisted key: %w", err)
	}
	caPEM, caFound, err := store.read(caFileName)
	if err != nil {
		return fmt.Errorf("read persisted ca: %w", err)
	}

	if certFound && keyFound && caFound {
		logger.InfoContext(ctx, "found persisted enrollment; skipping enrollment and connecting directly", slog.String("store", store.describe()))
		if hubEndpoint == "" {
			if persisted, found, err := store.read(hubEndpointFileName); err == nil && found {
				hubEndpoint = string(bytes.TrimSpace(persisted))
			}
		}
		// Older identities predate these two — their absence is not fatal
		// (the agent still runs, it just can't execute a signed
		// remediation plan until it re-enrolls), so both are plain,
		// non-fatal best-effort reads, unlike cert/key/ca above.
		if persisted, found, err := store.read(planSigningKeyFileName); err == nil && found {
			planSigningKey = persisted
		}
		if persisted, found, err := store.read(clusterIDFileName); err == nil && found {
			clusterID = string(bytes.TrimSpace(persisted))
		}
	} else if role == tunnel.RoleRemediate {
		// PROJECT.md E11. A remediation agent NEVER enrolls. It joins the
		// cluster record its investigation counterpart already established,
		// by reading the same identity store (the argus-agent-identity
		// Secret both Deployments mount), and it waits for that identity to
		// appear rather than creating one.
		//
		// Enrolling would be actively wrong in two ways. The hub keys a
		// cluster on its fingerprint — sha256 of the kube-system namespace
		// UID — so a second enrollment from the same cluster is refused with
		// 409 "already enrolled"; and working around that with
		// values.yaml's clusterFingerprint override would produce a SECOND
		// cluster record for one physical cluster, which is the thing that
		// override exists to warn about. One cluster, one record, two
		// connections is the whole shape of this item.
		//
		// Waiting rather than failing matters on a fresh install: both
		// Deployments start at once, and the investigation agent still has
		// to enroll and be accepted by a human before any identity exists.
		// That can take minutes or days. A remediation agent that exited
		// would CrashLoopBackOff through all of it.
		certPEM, keyPEM, caPEM, hubEndpoint, planSigningKey, clusterID, err = awaitSharedIdentity(ctx, cfg, store)
		if err != nil {
			return err
		}
	} else {
		certPEM, keyPEM, caPEM, hubEndpoint, planSigningKey, clusterID, err = enroll(ctx, cfg, store)
		if err != nil {
			return err
		}
	}

	hubEndpoint = effectiveTunnelEndpoint(cfg.TunnelEndpoint, hubEndpoint)
	if hubEndpoint == "" {
		return errors.New("agent: no hub tunnel endpoint known (neither persisted nor freshly enrolled) — cannot connect")
	}

	if toolExecutor != nil {
		if len(planSigningKey) == 0 || clusterID == "" {
			logger.WarnContext(ctx, "no remediation plan signing key/cluster id available; scale_deployment/restart_pod tool calls will be refused until re-enrollment")
		}
		// PROJECT.md E11: which role this process serves, so the executor can
		// refuse a misrouted write with a sentence instead of a 403. See
		// ToolExecutor.role — this is defence in depth in front of RBAC,
		// never a replacement for it.
		toolExecutor.SetConnectionRole(role)
		toolExecutor.SetRemediationCredentials(clusterID, planSigningKey)
	}

	return serveTunnelForever(ctx, cfg, hubEndpoint, certPEM, keyPEM, caPEM, findings, toolExecutor)
}

// enroll performs steps 1-4 of the flow: resolve/persist a fingerprint,
// generate and persist a key+CSR, POST /clusters/enroll, then poll
// /clusters/enroll/status until issued or rejected. Returns the issued
// cert/ca PEM, the hub tunnel endpoint, and (when the hub provided one) the
// per-cluster remediation plan signing key and this agent's own hub-assigned
// cluster ID on success.
// sharedIdentityPollInterval is how often a remediation agent re-checks the
// identity store for the identity its investigation counterpart is
// responsible for establishing.
//
// Deliberately not a backoff. The wait is unbounded in principle — it lasts
// until a human accepts the cluster on the hub — and the thing being polled
// is a Secret read in this agent's own namespace, not a hub round trip, so
// there is no remote resource to be gentle with. A fixed, short interval
// means a cluster that is accepted becomes remediable within seconds of the
// investigation agent writing its identity, rather than after whatever a
// backoff had grown to by then.
const sharedIdentityPollInterval = 10 * time.Second

// effectiveTunnelEndpoint decides where the tunnel is dialled. An explicit
// ARGUS_TUNNEL_ENDPOINT (the agent chart's hub.tunnelEndpoint, or the
// in-cluster address the hub chart gives its own embedded agent) wins on
// every path; the endpoint the hub advertised at enrollment, as persisted,
// is the fallback. It must be one rule for all three identity paths: when only
// the persisted path honoured the override, a freshly enrolled agent used the
// hub's public URL for its whole first life, so the hub's own agent
// hairpinned out through the Ingress and, behind a certificate it did not
// trust, could not connect at all until its pod was replaced.
func effectiveTunnelEndpoint(configured, learned string) string {
	if c := strings.TrimSpace(configured); c != "" {
		return c
	}
	return learned
}

// awaitSharedIdentity blocks until the identity store holds a complete
// enrollment, then returns it — PROJECT.md E11's "one cluster record, two
// connections" half.
//
// The investigation agent is the one that enrolls; this reads what it wrote.
// Both Deployments mount the same identity Secret (see
// deploy/helm/argus-agent/templates/identity-secret.yaml), so what the
// remediation agent presents on its tunnel connection is the same client
// certificate — which is exactly what makes the hub resolve both connections
// to the same cluster id, with no enrollment-API change at all.
//
// Requires a complete identity (cert + key + CA + a hub endpoint), and
// separately requires the plan signing key and cluster id: without those two
// this process could not verify a signed plan and would refuse every
// remediation it was sent (see tools.go's verifySignedPlan). Waiting for
// them is better than connecting and refusing everything, because the
// refusal would look like a bug and this wait says exactly what it is
// waiting for.
func awaitSharedIdentity(ctx context.Context, cfg Config, store identityStore) (certPEM, keyPEM, caPEM []byte, hubEndpoint string, planSigningKey []byte, clusterID string, err error) {
	logged := false
	for {
		cert, certFound, err := store.read(certFileName)
		if err != nil {
			return nil, nil, nil, "", nil, "", fmt.Errorf("read shared cert: %w", err)
		}
		key, keyFound, err := store.read(keyFileName)
		if err != nil {
			return nil, nil, nil, "", nil, "", fmt.Errorf("read shared key: %w", err)
		}
		ca, caFound, err := store.read(caFileName)
		if err != nil {
			return nil, nil, nil, "", nil, "", fmt.Errorf("read shared ca: %w", err)
		}

		endpoint := cfg.TunnelEndpoint
		if endpoint == "" {
			if persisted, found, rerr := store.read(hubEndpointFileName); rerr == nil && found {
				endpoint = string(bytes.TrimSpace(persisted))
			}
		}

		var signingKey []byte
		if persisted, found, rerr := store.read(planSigningKeyFileName); rerr == nil && found {
			signingKey = persisted
		}
		var id string
		if persisted, found, rerr := store.read(clusterIDFileName); rerr == nil && found {
			id = string(bytes.TrimSpace(persisted))
		}

		if certFound && keyFound && caFound && endpoint != "" && len(signingKey) > 0 && id != "" {
			logger.InfoContext(ctx, "adopted shared cluster identity; this remediation agent never enrolls, it joins the cluster record its investigation counterpart established", slog.String("store", store.describe()), logging.ClusterID(id))
			return cert, key, ca, endpoint, signingKey, id, nil
		}

		if !logged {
			logger.WarnContext(ctx, "waiting for the investigation agent to establish this cluster's identity; this agent does not enroll, it joins that record as its remediation connection", slog.String("store", store.describe()))
			logged = true
		}

		select {
		case <-ctx.Done():
			return nil, nil, nil, "", nil, "", ctx.Err()
		case <-time.After(sharedIdentityPollInterval):
		}
	}
}

func enroll(ctx context.Context, cfg Config, store identityStore) (certPEM, keyPEM, caPEM []byte, hubEndpoint string, planSigningKey []byte, clusterID string, err error) {
	if cfg.Token == "" {
		return nil, nil, nil, "", nil, "", errors.New("agent: no persisted enrollment found and no enrollment token provided (ARGUS_ENROLLMENT_TOKEN)")
	}

	fingerprint, err := resolveFingerprint(ctx, cfg, store)
	if err != nil {
		return nil, nil, nil, "", nil, "", fmt.Errorf("resolve cluster fingerprint: %w", err)
	}
	logger.InfoContext(ctx, "using cluster fingerprint", slog.String("fingerprint", fingerprint))

	keyPEM, csrPEM, err := GenerateKeyAndCSR(fingerprint)
	if err != nil {
		return nil, nil, nil, "", nil, "", fmt.Errorf("generate key/CSR: %w", err)
	}
	// Persist the key immediately, before any network call — if enroll fails
	// partway through, a retry reuses this key/fingerprint rather than
	// generating a fresh one and risking a fingerprint/CSR mismatch.
	if err := store.write(keyFileName, keyPEM, 0o600); err != nil {
		return nil, nil, nil, "", nil, "", fmt.Errorf("persist key: %w", err)
	}

	hubClient, err := NewHubHTTPClient(cfg.HubCAFile)
	if err != nil {
		return nil, nil, nil, "", nil, "", err
	}

	clusterID, pollToken, status, err := postEnroll(ctx, cfg, hubClient, fingerprint, string(csrPEM))
	if err != nil {
		return nil, nil, nil, "", nil, "", err
	}
	if status == "accepted" {
		logger.InfoContext(ctx, "enrolled and accepted automatically by the enrollment token", logging.ClusterID(clusterID))
	} else {
		logger.WarnContext(ctx, "enrolled; cluster is pendingApproval, waiting for an admin to accept", logging.ClusterID(clusterID))
	}
	if err := store.write(clusterIDFileName, []byte(clusterID), 0o644); err != nil {
		return nil, nil, nil, "", nil, "", fmt.Errorf("persist cluster id: %w", err)
	}

	certPEM, caPEM, hubEndpoint, planSigningKey, err = pollEnrollStatus(ctx, cfg, hubClient, pollToken)
	if err != nil {
		return nil, nil, nil, "", nil, "", err
	}

	if err := store.write(certFileName, certPEM, 0o644); err != nil {
		return nil, nil, nil, "", nil, "", fmt.Errorf("persist cert: %w", err)
	}
	if err := store.write(caFileName, caPEM, 0o644); err != nil {
		return nil, nil, nil, "", nil, "", fmt.Errorf("persist ca: %w", err)
	}
	if err := store.write(hubEndpointFileName, []byte(hubEndpoint), 0o644); err != nil {
		return nil, nil, nil, "", nil, "", fmt.Errorf("persist hub endpoint: %w", err)
	}
	// Best-effort, like the read path above: a missing key on the hub's
	// response (logged there, see buildIssuedEnrollStatusResponse) just
	// means this agent can't execute a remediation plan yet, not that
	// enrollment itself failed.
	if len(planSigningKey) > 0 {
		if err := store.write(planSigningKeyFileName, planSigningKey, 0o600); err != nil {
			return nil, nil, nil, "", nil, "", fmt.Errorf("persist plan signing key: %w", err)
		}
	}
	logger.InfoContext(ctx, "enrolled; connecting tunnel", slog.String("hub_endpoint", hubEndpoint))

	return certPEM, keyPEM, caPEM, hubEndpoint, planSigningKey, clusterID, nil
}

// resolveFingerprint reuses a persisted fingerprint across restarts
// (identity must stay stable), or picks a new one: the "real" algorithm per
// lld/03-agent-protocol.md §5 (sha256 of the target cluster's own
// kube-system namespace UID) when a live cluster is reachable, falling back
// to a persisted random value when it isn't — expected for this MVP when
// testing enrollment without a live target cluster.
func resolveFingerprint(ctx context.Context, cfg Config, store identityStore) (string, error) {
	if existing, found, err := store.read(fingerprintFileName); err == nil && found {
		return string(bytes.TrimSpace(existing)), nil
	}

	fingerprint := cfg.Fingerprint
	if fingerprint == "" {
		if uid, ok := KubeSystemUID(ctx); ok {
			sum := sha256.Sum256([]byte(uid))
			fingerprint = hex.EncodeToString(sum[:])
			logger.InfoContext(ctx, "derived cluster fingerprint from live kube-system namespace UID")
		} else {
			random, err := randomHex(16)
			if err != nil {
				return "", err
			}
			fingerprint = random
			logger.WarnContext(ctx, "no reachable cluster; generated a random fingerprint, persisted for future restarts")
		}
	}

	if err := store.write(fingerprintFileName, []byte(fingerprint), 0o644); err != nil {
		return "", fmt.Errorf("persist fingerprint: %w", err)
	}
	return fingerprint, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

type enrollRequest struct {
	Token              string `json:"token"`
	CSRPem             string `json:"csrPem"`
	ClusterFingerprint string `json:"clusterFingerprint"`
	DisplayName        string `json:"displayName,omitempty"`
}

type enrollResponse struct {
	ClusterID string `json:"clusterId"`
	Status    string `json:"status"`
	PollToken string `json:"pollToken"`
}

type enrollStatusResponse struct {
	Status         string `json:"status"`
	CertPem        string `json:"certPem"`
	CaPem          string `json:"caPem"`
	HubEndpoint    string `json:"hubEndpoint"`
	PlanSigningKey string `json:"planSigningKey,omitempty"` // base64-standard; see internal/api/enroll.go's enrollStatusResponse
}

func postEnroll(ctx context.Context, cfg Config, client *http.Client, fingerprint, csrPEM string) (clusterID, pollToken, status string, err error) {
	body, err := json.Marshal(enrollRequest{
		Token:              cfg.Token,
		CSRPem:             csrPEM,
		ClusterFingerprint: fingerprint,
		DisplayName:        cfg.DisplayName,
	})
	if err != nil {
		return "", "", "", err
	}

	url := cfg.HubAPIURL + "/api/v1/clusters/enroll"
	// A hub that is not answering yet (installed in the same release and still
	// starting, or restarting) is retried with the same backoff as the status
	// poll below; only an answer from the hub refusing the enrollment ends it.
	delay := enrollRetryInitial
	for attempt := 1; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return "", "", "", err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		var respBody []byte
		if err == nil {
			respBody, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
		}
		switch {
		case err != nil && isCertificateError(err):
			// A wrong or missing CA is configuration, not a hub still starting.
			return "", "", "", fmt.Errorf("POST %s: %w", url, err)
		case err != nil:
			logger.WarnContext(ctx, "the hub is not reachable yet; retrying enrollment", slog.Int("attempt", attempt), logging.Err(err), slog.Duration("retry_delay", delay))
		case resp.StatusCode >= 500:
			logger.WarnContext(ctx, "the hub could not take the enrollment yet; retrying", slog.String("status", resp.Status), slog.Int("attempt", attempt), slog.Duration("retry_delay", delay))
		case resp.StatusCode == http.StatusConflict:
			return "", "", "", fmt.Errorf("agent: enrollment rejected — a cluster with this fingerprint is already enrolled (409): %s", string(respBody))
		case resp.StatusCode != http.StatusCreated:
			return "", "", "", fmt.Errorf("agent: enroll request failed: %s %s: %s", resp.Status, url, string(respBody))
		default:
			var parsed enrollResponse
			if err := json.Unmarshal(respBody, &parsed); err != nil {
				return "", "", "", fmt.Errorf("parse enroll response: %w", err)
			}
			return parsed.ClusterID, parsed.PollToken, parsed.Status, nil
		}

		select {
		case <-ctx.Done():
			return "", "", "", ctx.Err()
		case <-time.After(jitter(delay)):
		}
		delay *= 2
		if delay > pollBackoffCap {
			delay = pollBackoffCap
		}
	}
}

// enrollRetryInitial is the first wait before retrying an enrollment the hub
// could not take; a variable so tests need not wait it out.
var enrollRetryInitial = pollBackoffInitial

// isCertificateError reports whether err is the hub's certificate failing
// verification, which retrying cannot fix.
func isCertificateError(err error) bool {
	var verr *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var host x509.HostnameError
	var invalid x509.CertificateInvalidError
	return errors.As(err, &verr) || errors.As(err, &unknown) || errors.As(err, &host) || errors.As(err, &invalid)
}

// pollEnrollStatus polls GET /clusters/enroll/status?pollToken=... with a
// jittered backoff (5s -> 30s cap, a simplified version of
// lld/03-agent-protocol.md §5's 5s->60s/24h-cap production spec) until the
// hub reports issued or rejected.
func pollEnrollStatus(ctx context.Context, cfg Config, client *http.Client, pollToken string) (certPEM, caPEM []byte, hubEndpoint string, planSigningKey []byte, err error) {
	delay := pollBackoffInitial
	attempt := 0

	url := fmt.Sprintf("%s/api/v1/clusters/enroll/status?pollToken=%s", cfg.HubAPIURL, pollToken)

	for {
		attempt++

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, nil, "", nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			logger.WarnContext(ctx, "poll enroll status failed; retrying", slog.Int("attempt", attempt), logging.Err(err), slog.Duration("retry_delay", delay))
		} else {
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				logger.WarnContext(ctx, "poll enroll status returned non-OK response; retrying", slog.String("status", resp.Status), slog.Int("attempt", attempt), slog.String("body", string(respBody)), slog.Duration("retry_delay", delay))
			} else {
				var parsed enrollStatusResponse
				if err := json.Unmarshal(respBody, &parsed); err != nil {
					return nil, nil, "", nil, fmt.Errorf("parse enroll status response: %w", err)
				}

				switch parsed.Status {
				case "issued":
					var key []byte
					if parsed.PlanSigningKey != "" {
						key, err = base64.StdEncoding.DecodeString(parsed.PlanSigningKey)
						if err != nil {
							return nil, nil, "", nil, fmt.Errorf("parse plan signing key: %w", err)
						}
					}
					return []byte(parsed.CertPem), []byte(parsed.CaPem), parsed.HubEndpoint, key, nil
				case "rejected":
					return nil, nil, "", nil, errors.New("agent: enrollment was rejected by the hub admin")
				case "pendingApproval":
					logger.WarnContext(ctx, "still pendingApproval, waiting for an admin to accept", slog.Duration("next_poll", delay))
				default:
					logger.WarnContext(ctx, "unexpected enroll status; will keep polling", slog.String("status", parsed.Status), slog.Duration("next_poll", delay))
				}
			}
		}

		select {
		case <-ctx.Done():
			return nil, nil, "", nil, ctx.Err()
		case <-time.After(jitter(delay)):
		}

		delay *= 2
		if delay > pollBackoffCap {
			delay = pollBackoffCap
		}
	}
}

// jitter returns d with up to +/-20% random variation, so many agents
// polling on the same schedule don't hammer the hub in lockstep.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	spread := int64(d) / 5 // 20%
	if spread <= 0 {
		return d
	}
	n, err := rand.Int(rand.Reader, big.NewInt(2*spread))
	if err != nil {
		return d
	}
	return d - time.Duration(spread) + time.Duration(n.Int64())
}

// serveTunnelForever dials and serves the mTLS tunnel, reconnecting with
// jittered backoff on any connection error, until ctx is cancelled. A
// connection error here never triggers re-enrollment — only a fresh tunnel
// dial, per lld/03-agent-protocol.md §7. findings is threaded through to
// runTunnelSession unchanged on every attempt — it's the same queue Run
// created once, not recreated per-connection, so Findings detected while
// reconnecting just accumulate until the next successful session drains
// them.
//
// The whole queue is passed rather than only its Out() channel because a
// session now has two things to say back to it: it reports the queue's depth
// and drop total on every heartbeat (PROJECT.md B176's residual), and it
// returns whatever the hub never acked when the session dies (PROJECT.md
// P21) — see findingInflight.
func serveTunnelForever(ctx context.Context, cfg Config, hubEndpoint string, certPEM, keyPEM, caPEM []byte, findings *findingQueue, toolExecutor *ToolExecutor) error {
	tlsConfig, leaf, err := buildTLSConfig(cfg, hubEndpoint, certPEM, keyPEM, caPEM)
	if err != nil {
		return fmt.Errorf("build TLS config: %w", err)
	}

	delay := tunnelBackoffInitial

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		logger.InfoContext(ctx, "dialing tunnel", slog.String("hub_endpoint", hubEndpoint))
		conn, err := dialTunnel(ctx, cfg, hubEndpoint, tlsConfig)
		if err != nil {
			logger.WarnContext(ctx, "tunnel dial failed; retrying", logging.Err(err), slog.Duration("retry_delay", delay))
		} else {
			logger.InfoContext(ctx, "tunnel connected", slog.String("hub_endpoint", hubEndpoint))
			delay = tunnelBackoffInitial // reset backoff after a successful connect
			terminal, sessionErr := runTunnelSession(ctx, cfg, conn, leaf, findings, toolExecutor)
			conn.Close()
			if terminal != "" {
				// The read loop already logged WHY (terminalReasonMessage) —
				// this is deliberately a completely separate wait from the
				// normal delay/backoff-doubling ladder below (see
				// tunnelTerminalBackoff's own doc comment): `continue` skips
				// that ladder entirely, so a run of terminal disconnects
				// never compounds past ~30 minutes the way the ladder's own
				// doubling would, and a later NON-terminal reconnect still
				// starts from tunnelBackoffInitial, already reset above.
				logger.WarnContext(ctx, "reconnecting after terminal signal with long backoff; see the terminal-signal log line above for why", slog.Duration("backoff", tunnelTerminalBackoff))
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(jitter(tunnelTerminalBackoff)):
				}
				continue
			}
			if sessionErr != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				logger.WarnContext(ctx, "tunnel session ended; reconnecting", logging.Err(sessionErr), slog.Duration("retry_delay", delay))
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(jitter(delay)):
		}

		delay *= 2
		if delay > tunnelBackoffCap {
			delay = tunnelBackoffCap
		}
	}
}

// tunnelHandshakeTimeout bounds connecting and the mTLS handshake, so a
// proxy that accepts the connection and then says nothing cannot stall the
// reconnect loop.
const tunnelHandshakeTimeout = 30 * time.Second

// dialTunnel opens the tunnel: a direct TLS connection to a host:port, or,
// for a ws(s):// endpoint, a WebSocket through whatever stands in front of the
// hub's API (honouring HTTPS_PROXY and the hub CA bundle, like enrollment)
// with the same mTLS session run inside it.
func dialTunnel(ctx context.Context, cfg Config, endpoint string, tlsConfig *tls.Config) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, tunnelHandshakeTimeout)
	defer cancel()
	if !tunnel.IsWebSocketEndpoint(endpoint) {
		d := tls.Dialer{Config: tlsConfig}
		return d.DialContext(ctx, "tcp", endpoint)
	}
	outer, err := hubTLSConfig(cfg.HubCAFile)
	if err != nil {
		return nil, err
	}
	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		TLSClientConfig:  outer,
		HandshakeTimeout: tunnelHandshakeTimeout,
		ReadBufferSize:   32 << 10,
		WriteBufferSize:  32 << 10,
	}
	ws, resp, err := dialer.DialContext(ctx, endpoint, nil)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("opening the tunnel WebSocket at %s: %w (HTTP %s)", endpoint, err, resp.Status)
		}
		return nil, fmt.Errorf("opening the tunnel WebSocket at %s: %w", endpoint, err)
	}
	conn := tls.Client(tunnel.NewWebSocketConn(ws), tlsConfig)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tunnel TLS handshake inside the WebSocket: %w", err)
	}
	return conn, nil
}

func buildTLSConfig(cfg Config, hubEndpoint string, certPEM, keyPEM, caPEM []byte) (*tls.Config, *x509.Certificate, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("load client cert/key: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("parse leaf cert: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, nil, errors.New("no certificates found in ca.pem")
	}

	serverName := cfg.TLSServerNameOverride
	if serverName == "" && tunnel.IsWebSocketEndpoint(hubEndpoint) {
		// The URL names the Ingress in front of the hub; the gateway's own
		// certificate is verified by the name every one of them carries.
		serverName = tunnel.GatewayServerName
	}
	if serverName == "" {
		if host, _, err := net.SplitHostPort(hubEndpoint); err == nil {
			serverName = host
		} else {
			serverName = hubEndpoint
		}
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}, leaf, nil
}

// toolResultChannelBufferSize bounds the channel carrying completed
// ToolResults from their (per-call) executor goroutines back to
// runTunnelSession's single writer. Sized well above "one tool call at a
// time" so several concurrent ToolRequests in flight (the hub is free to
// issue more than one before an earlier reply lands — nothing about this
// protocol requires it to wait) never blocks an executor goroutine on
// send; a producer still selects on ctx.Done() rather than blocking
// forever if this were ever exceeded.
const toolResultChannelBufferSize = 32

// logTerminalSignal is the one log line for a hub's deliberate, permanent
// close, written the moment it is known so an operator reading this agent's
// log learns why without needing hub access.
func logTerminalSignal(ctx context.Context, reason string) {
	logger.WarnContext(ctx, "hub sent terminal signal; backing off reconnect attempts instead of retrying immediately", slog.String("reason", terminalReasonMessage(reason)), slog.Duration("backoff", tunnelTerminalBackoff))
}

// terminalBeforeFirstWrite returns the Terminal reason the hub sent before
// this session's first message got through, or "". The hub sends Terminal
// and closes without reading anything, so when gathering the first message
// takes longer than that (facts from a real API server do), the write fails
// on a closed connection with the explanation still unread. Returned as a
// plain write error, a decommissioned cluster's agent would go back on the
// fast reconnect ladder instead of tunnelTerminalBackoff.
func terminalBeforeFirstWrite(ctx context.Context, conn net.Conn, dec *json.Decoder) string {
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	var msg tunnel.ServerMessage
	if err := dec.Decode(&msg); err != nil || msg.Terminal == "" {
		return ""
	}
	logTerminalSignal(ctx, msg.Terminal)
	return msg.Terminal
}

// runTunnelSession sends the initial full-resync InventoryDelta, then loops
// sending a Heartbeat every 30s (lld/03-agent-protocol.md §7), any Finding
// available on the finding queue, and any ToolResult produced by a tool
// execution started from an incoming ToolRequest, while concurrently reading
// ServerMessages (acks, errors, unsolicited ToolRequests, and a
// terminal-signal case), until the connection errors, the hub sends a
// terminal signal, or ctx is cancelled.
//
// A Finding taken off the queue is NOT considered delivered by having been
// written (PROJECT.md P21). It is stamped with a correlation id, held in
// this session's findingInflight, and only released when the hub echoes that
// id back on an Ack — which internal/gateway sends only after handleFinding
// has returned successfully. Everything still unacked when this function
// returns, for ANY reason, goes back on the queue (the deferred returnAll
// below), so a tunnel killed between the write and the ack costs a
// redelivery on the next session instead of the finding.
//
// Returns (terminalReason, err): terminalReason is non-empty (one of
// tunnel.TerminalReasonArchived/Rejected) exactly when this session ended
// because the hub explicitly said so — the caller (serveTunnelForever) backs
// off to tunnelTerminalBackoff instead of its normal ladder in that case, and
// only in that case. err is nil whenever terminalReason is set: a terminal
// signal is an orderly, informative end to the session, not a failure to
// report up as one.
//
// A ToolRequest is executed in its own goroutine (executeToolRequest), never
// inline in the read loop — a slow tool call (a large log tail, a
// multi-Kind owner-chain walk) must never stall reading the next message off
// the wire, including a heartbeat ack or a second, concurrent ToolRequest.
// toolExecutor may be nil (no reachable cluster) — executeToolRequest
// handles that by producing a ToolResult.Error, never a panic.
//
// enc (the json.Encoder wrapping conn) is written to from exactly this one
// goroutine (runTunnelSession's own) and nowhere else — the initial
// InventoryDelta send above, and the Heartbeat/Finding/ToolResult cases in
// the select loop below, are the only places anything is ever encoded onto
// the wire. That single-writer invariant is what makes sharing one
// net.Conn/json.Encoder across message types safe; a second concurrent
// writer would be a data race, not just a style concern — which is exactly
// why an executed tool's result is handed back over toolResultCh rather
// than encoded directly from its own goroutine.
func runTunnelSession(ctx context.Context, cfg Config, conn net.Conn, leaf *x509.Certificate, findings *findingQueue, toolExecutor *ToolExecutor) (terminalReason string, err error) {
	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	// PROJECT.md P21. Declared before the first Encode below and drained on
	// every exit path, including the initial-inventory failure return: a
	// session that dies early has nothing in flight yet, and the deferred
	// call correctly returns nothing, but wiring it here means no future
	// early return can be added that silently skips it.
	inflight := newFindingInflight()
	ackCh := make(chan string, maxUnackedFindings)
	defer func() {
		// Apply any ack that arrived but had not yet been picked up by the
		// select loop when the session ended. Without this, an ack decoded
		// microseconds before the connection died would be discarded and its
		// finding redelivered for no reason — correct, but a duplicate this
		// agent already had the information to avoid.
		inflight.drainAcks(ackCh)
		if returned := inflight.returnAll(ctx, findings); returned > 0 {
			logger.WarnContext(ctx, "tunnel session ended with finding(s) unacked by the hub; returned to the finding queue for redelivery, not lost and not entering the resend cooldown as delivered", slog.Int("returned", returned))
		}
	}()

	role := effectiveRole(cfg)

	// PROJECT.md E11. The role declaration rides the first real message,
	// never travels alone: a lone Hello would hit a pre-E11 hub's "message
	// with no recognized payload" branch and get the connection closed, so
	// sending one would be a BREAKING wire change dressed up as an additive
	// field. Carried this way it is genuinely additive in both directions —
	// an old hub discards the unknown "hello" key and serves this agent
	// exactly as it always did, and a new hub reads the role off a message
	// it was going to handle anyway.
	hello := &tunnel.Hello{Role: role}

	if role == tunnel.RoleRemediate {
		// A remediation agent gathers no facts and runs no detectors (see
		// Run), so it has no InventoryDelta to ride. Its first Heartbeat
		// carries the Hello instead, sent immediately rather than waiting
		// out the first heartbeatInterval — the hub cannot route a write
		// action to this connection until it knows what it is, so a
		// thirty-second window of "no remediation agent connected" on every
		// reconnect would be a real, visible outage of the write path.
		first := heartbeatMessage(cfg, leaf, findings)
		first.Hello = hello
		first.Heartbeat.Remediation = GatherOwnRemediationAuthority()
		if err := enc.Encode(first); err != nil {
			if reason := terminalBeforeFirstWrite(ctx, conn, dec); reason != "" {
				return reason, nil
			}
			return "", fmt.Errorf("send initial heartbeat: %w", err)
		}
		logger.InfoContext(ctx, "connected; this process runs no detectors and reports no facts, it exists only to execute approved, signed remediation plans", slog.String("role", role))
	} else {
		initial := inventoryMessage(factsWithDetection(cfg))
		initial.Hello = hello
		if err := enc.Encode(initial); err != nil {
			if reason := terminalBeforeFirstWrite(ctx, conn, dec); reason != "" {
				return reason, nil
			}
			return "", fmt.Errorf("send initial inventory: %w", err)
		}
		logger.InfoContext(ctx, "sent initial inventory", slog.String("role", role), slog.Bool("reachable", initial.InventoryDelta.Facts.Reachable), slog.Int("node_count", initial.InventoryDelta.Facts.NodeCount))
	}

	// PROJECT.md B177: that first InventoryDelta is a snapshot of the instant
	// this session opened, and until this refresh existed it was the ONLY
	// ClusterFacts payload a session ever sent — the 30s Heartbeat carries
	// AgentVersion and CertExpiresAt and nothing else. Everything derived
	// from facts was therefore frozen until the next reconnect: the snapshot
	// is taken before the sweep detector's first tick, so a perfectly healthy
	// sweep reported a zero LastSuccessAt ("Not yet observed" in the UI) for
	// the whole session, and DeniedReads — the operator-visible signal that
	// RBAC is blocking a detector — could not change at all while connected.
	// Measured live on 2026-09-19: revoking a read produced 403s in the agent
	// log every sweep and no hub-side change whatsoever until the pod was
	// restarted.
	//
	// refreshCtx, not ctx: ctx here is the agent's process-lifetime context
	// (serveTunnelForever passes the same one to every session), so a
	// refresher started with it would outlive the session it belongs to.
	refreshCtx, stopFactsRefresh := context.WithCancel(ctx)
	defer stopFactsRefresh()
	// Nil for a remediation connection, which blocks forever in the select
	// below — the idiom this loop already uses for findingSrc. A remediation
	// agent must never send facts: they would overwrite the investigation
	// agent's, including its coverage figure, with a view gathered by a
	// process that runs no detectors at all.
	var factsCh <-chan tunnel.ClusterFacts
	if role != tunnel.RoleRemediate {
		factsCh = startFactsRefresh(refreshCtx, cfg, factsRefreshInterval)
	}

	toolResultCh := make(chan tunnel.ToolResult, toolResultChannelBufferSize)

	readErrCh := make(chan error, 1)
	// terminalCh carries a single tunnel.TerminalReason* value the instant
	// the read loop decodes one — see ServerMessage.Terminal's own doc
	// comment. Buffered 1 and never blocked on: the hub sends Terminal alone
	// and then closes, so at most one value is ever produced, and the read
	// loop's very next dec.Decode call is expected to fail with EOF right
	// after (into readErrCh) — the select below prefers terminalCh so the
	// orderly explanation wins the race against that EOF, but either
	// ordering is handled.
	terminalCh := make(chan string, 1)
	// ackCh carries the correlation id off every Ack the read goroutine
	// decodes, so the finding this session is holding for that id can be
	// released by the ONE goroutine that owns inflight (the select loop
	// below) — never from the read goroutine, which would be a data race on
	// the same map the send case writes to.
	//
	// Buffered to the send window: at most maxUnackedFindings findings can be
	// awaiting an ack at once, so the hub can never produce more finding acks
	// than this holds, and a burst of them can never block the read loop (the
	// goroutine that must also stay free to decode the next ToolRequest).
	// Heartbeat/InventoryDelta acks carry an empty id and are discarded here
	// rather than queued, so they cannot consume the window either.
	//
	// Declared alongside inflight at the top of this function rather than
	// here, because the deferred requeue drains it: see that defer.
	go func() {
		for {
			var msg tunnel.ServerMessage
			if err := dec.Decode(&msg); err != nil {
				readErrCh <- err
				return
			}
			switch {
			case msg.Terminal != "":
				// Logged here, plainly, at the moment it's known — not
				// deferred to serveTunnelForever — so an operator reading
				// this agent's log learns WHY without needing hub access:
				// this is a deliberate, permanent close tied to this
				// cluster's own state, not a hub restart or network blip.
				logTerminalSignal(ctx, msg.Terminal)
				select {
				case terminalCh <- msg.Terminal:
				default:
				}
			case msg.ToolRequest != nil:
				req := *msg.ToolRequest
				logger.InfoContext(ctx, "tool request received", slog.String("correlation_id", req.CorrelationID), slog.String("tool", req.Tool))
				go func() {
					result := executeToolRequest(ctx, toolExecutor, req)
					select {
					case toolResultCh <- result:
					case <-ctx.Done():
					}
				}()
			case msg.Error != "":
				logger.ErrorContext(ctx, "hub reported error", slog.String("correlation_id", msg.CorrelationID), slog.String("hub_error", msg.Error))
			case msg.Ack:
				logger.InfoContext(ctx, "ack received", slog.String("correlation_id", msg.CorrelationID))
				for _, f := range msg.HubFeatures {
					if f == tunnel.HubFeatureChangeBatch {
						hubAcceptsChanges.Store(true)
					}
				}
				if msg.CorrelationID != "" {
					// Only a finding ack carries an id this session minted;
					// the heartbeat/inventory acks carry the empty id their
					// own ClientMessage did. Non-blocking by construction —
					// see ackCh's own sizing comment — but selected on
					// ctx.Done() anyway so a cancelled process can never
					// wedge this goroutine on a select loop that has already
					// returned.
					select {
					case ackCh <- msg.CorrelationID:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	ticker := time.NewTicker(heartbeatInterval)
	beats := 0
	defer ticker.Stop()
	// CI-S2's change stream flush. Remediation-role agents have no object
	// cache, so their stream is always empty and this is a no-op.
	changeTicker := time.NewTicker(changeFlushInterval)
	defer changeTicker.Stop()
	hubAcceptsChanges.Store(false)

	for {
		// The send window (PROJECT.md P21). A nil channel blocks forever in
		// a select, so leaving findingSrc nil is how this loop stops taking
		// findings off the queue once maxUnackedFindings of them are already
		// on the wire unacked — without stopping heartbeats, tool results or
		// inventory refreshes, which is exactly the point: a hub that has
		// stopped acking findings must not also stop this agent being
		// reachable, and the findings it is not draining must stay in the
		// queue (bounded, coalescing) rather than piling up in this session.
		var findingSrc <-chan tunnel.Finding
		if inflight.len() < maxUnackedFindings {
			findingSrc = findings.Out()
		}

		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case reason := <-terminalCh:
			return reason, nil
		case err := <-readErrCh:
			return "", fmt.Errorf("tunnel read: %w", err)
		case id := <-ackCh:
			// The hub has committed this finding (internal/gateway's
			// processFindingAsync acks only after handleFinding returns
			// without error), so this session can finally stop holding it.
			// An id that matches nothing is normal and silent — a late ack
			// from a finding this session already released, or an ack for a
			// message type that never enters the queue.
			inflight.ack(id)
		case f := <-findingSrc:
			// Capture-time redaction for the detection path, at the last
			// statement before the finding becomes bytes on the tunnel
			// (BACKLOG.md G8, BUGS.md 84). Message is the field that carries
			// verbatim cluster-authored text: every detector copies event
			// text, condition Reason/Message or Job failure text into it —
			// see sweep_detector.go's Message: lines and detector.go's
			// ev.Message.
			//
			// Filtered HERE rather than in each detector for the same reason
			// Execute wraps its own dispatch: there are three detectors and
			// twenty-one reachable conditions today, and a rule that depends
			// on each new one remembering to call this is the rule that
			// produced BUGS.md 84. Every finding reaches the hub through this
			// single channel, so this is the one statement that cannot be
			// bypassed by adding a detector.
			//
			// Only Message is freeform. The rest of the struct is identifiers
			// and enums the hub joins and indexes on — DetectorID, GVK,
			// Fingerprint, ObjectName, Namespace, Severity — and running the
			// pattern filter over those would risk corrupting a correlation
			// key to no benefit, since none of them can carry secret material.
			//
			// Recorded as in-flight BEFORE the encode, so a write that fails
			// halfway — or a connection severed the instant after it
			// succeeds — still leaves this session holding the finding
			// (PROJECT.md P21).
			//
			// Deliberately the PRE-redaction copy, even though the redacted
			// one is right there: f is a value, so the map keeps the message
			// as it arrived and the redaction below applies to this send
			// only. This was written when redact.Text was not idempotent
			// and a redelivered copy gained a stray "]" per pass; B182 fixed
			// that, so the queue is no longer holding the line against a
			// live corruption. Keep it anyway: redacting once, at the one
			// egress chokepoint, is a property worth not re-deriving, and a
			// raw queue means a future pattern change applies to a redelivery
			// too. Nothing about egress changes: the queue has always
			// held raw findings, and every send still goes through the one
			// redaction statement below, which remains the last thing that
			// happens before the finding becomes bytes.
			correlationID := inflight.add(f)
			f.Message = redact.Text(f.Message)
			if err := enc.Encode(tunnel.ClientMessage{CorrelationID: correlationID, Finding: &f}); err != nil {
				return "", fmt.Errorf("send finding: %w", err)
			}
			logger.InfoContext(ctx, "finding sent", slog.String("detector_id", f.DetectorID), slog.String("fingerprint", f.Fingerprint), slog.String("reason", f.Reason), slog.String("correlation_id", correlationID), slog.Int("awaiting_ack", inflight.len()))
		case res := <-toolResultCh:
			if err := enc.Encode(tunnel.ClientMessage{ToolResult: &res}); err != nil {
				return "", fmt.Errorf("send tool result: %w", err)
			}
			logger.InfoContext(ctx, "tool result sent", slog.String("correlation_id", res.CorrelationID), slog.String("tool_error", res.Error))
		case facts := <-factsCh:
			// PROJECT.md B177. Encoded HERE, from the session goroutine, for
			// the same single-writer reason a tool result is handed back over
			// toolResultCh rather than written from its own goroutine: the
			// gather runs off this goroutine (it makes several bounded
			// API-server calls and must never stall a heartbeat, a finding or
			// a tool result), but nothing except this loop ever touches enc.
			//
			// The same message the initial send above builds, from the same
			// gatherer, through the same constructor — see inventoryMessage.
			// There is one ClusterFacts shape and one hub-side handler
			// (internal/gateway.handleInventoryDelta, which upserts
			// cluster_facts wholesale), so a refresh cannot report a
			// different view of this cluster from a reconnect: it is the
			// same view, taken later.
			refresh := inventoryMessage(facts)
			if err := enc.Encode(refresh); err != nil {
				return "", fmt.Errorf("send inventory refresh: %w", err)
			}
			logger.InfoContext(ctx, "inventory refresh sent", slog.Bool("reachable", facts.Reachable), slog.Int("node_count", facts.NodeCount))
		case <-changeTicker.C:
			// Only once this hub has said it accepts change batches; until
			// then (or forever, against an older hub) they stay buffered,
			// and overflow becomes a gap record.
			if !hubAcceptsChanges.Load() {
				break
			}
			for i := 0; i < changeBatchesPerFlush; i++ {
				batch := activeChangeStream.drain()
				if batch == nil {
					break
				}
				if err := enc.Encode(tunnel.ClientMessage{ChangeBatch: batch}); err != nil {
					if len(batch.Changes) > 0 {
						activeChangeStream.recordGap(batch.Changes[0].ObservedAt, batch.Changes[len(batch.Changes)-1].ObservedAt, "send failed when the tunnel dropped")
					}
					return "", fmt.Errorf("send change batch: %w", err)
				}
			}
		case <-ticker.C:
			hb := heartbeatMessage(cfg, leaf, findings)
			beats++
			if role == tunnel.RoleRemediate && beats%remediationAuthorityEvery == 0 {
				hb.Heartbeat.Remediation = GatherOwnRemediationAuthority()
			}
			if err := enc.Encode(hb); err != nil {
				return "", fmt.Errorf("send heartbeat: %w", err)
			}
			logger.InfoContext(ctx, "heartbeat sent", slog.Time("cert_expires_at", leaf.NotAfter))
		}
	}
}

// heartbeatMessage builds the 30s Heartbeat. Split out of the select loop
// for the same reason inventoryMessage is: it is the single constructor for
// a wire message whose contents are now worth asserting on their own,
// without a test having to wait out a real heartbeat interval.
//
// PROJECT.md B176's residual is the reason there is anything to assert: the
// queue's depth and its running discard total ride the heartbeat, which is
// the only always-on channel this agent has, so cap-triggered loss stops
// being something only this pod's log knows. Two cheap int reads under the
// queue's own mutex — see tunnel.Heartbeat.FindingQueue for why that is
// worth the twice-a-minute cost that struct otherwise guards against.
// remediationAuthorityEvery is how many heartbeats pass between a remediation
// process re-asking what it may change: about the facts refresh cadence, since
// each ask is several SelfSubjectAccessReviews.
const remediationAuthorityEvery = 4

func heartbeatMessage(cfg Config, leaf *x509.Certificate, findings *findingQueue) tunnel.ClientMessage {
	pending, dropped := findings.Stats()
	return tunnel.ClientMessage{
		Heartbeat: &tunnel.Heartbeat{
			AgentVersion:  cfg.AgentVersion,
			CertExpiresAt: leaf.NotAfter,
			FindingQueue: &tunnel.FindingQueueStatus{
				Pending:  pending,
				Dropped:  dropped,
				Capacity: findings.capacity,
			},
		},
	}
}

// terminalReasonMessage turns a tunnel.ServerMessage.Terminal value into the
// plain, operator-facing sentence this agent logs when it receives one — see
// that field's own doc comment for what sends it and why. Falls back to
// naming the raw value for a reason string this build doesn't recognize (a
// newer hub start sending a third terminal reason this agent predates)
// rather than staying silent about it.
func terminalReasonMessage(reason string) string {
	switch reason {
	case tunnel.TerminalReasonArchived:
		return "this cluster has been decommissioned (state: Archived) in the hub"
	case tunnel.TerminalReasonRejected:
		return "this cluster's enrollment was rejected in the hub"
	default:
		return fmt.Sprintf("the hub closed this tunnel citing terminal state %q", reason)
	}
}

// executeToolRequest runs one ToolRequest to completion and always returns a
// well-formed ToolResult (CorrelationID always set, Truncated always
// present) — never an error return, since there is no way to "fail" sending
// a result back other than reporting the failure inside it. A nil executor
// (no reachable cluster) and an unknown tool name both come back as
// ToolResult.Error, exactly like any other tool-execution failure — the hub
// side has no way to distinguish "this agent has no cluster" from "this
// agent doesn't support this tool" from "the k8s API call failed," by
// design: none of those require different handling in this increment.
func executeToolRequest(ctx context.Context, executor *ToolExecutor, req tunnel.ToolRequest) tunnel.ToolResult {
	data, truncated, err := executor.Execute(ctx, req.Tool, req.Args)
	if err != nil {
		return tunnel.ToolResult{CorrelationID: req.CorrelationID, Error: err.Error(), Truncated: false}
	}
	return tunnel.ToolResult{CorrelationID: req.CorrelationID, Data: data, Truncated: truncated}
}
