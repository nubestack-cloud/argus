// The hub binary. One multi-entrypoint image, dispatched by subcommand (ADR-7) —
// not one image per service. Currently implements: migrate, api. orchestrator,
// gitops, and notify are stubs pending their own implementation passes.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"strconv"

	"argus/internal/agentversion"
	"argus/internal/api"
	"argus/internal/authz"
	"argus/internal/autoanalyze"
	"argus/internal/data"
	"argus/internal/events"
	"argus/internal/execution"
	"argus/internal/fleetchecks"
	"argus/internal/gateway"
	"argus/internal/knowledge"
	"argus/internal/llm"
	"argus/internal/logging"
	"argus/internal/mcp"
	"argus/internal/metrics"
	"argus/internal/notify"
	"argus/internal/orchestrator"
	"argus/internal/partition"
	"argus/internal/remediation"
	"argus/internal/render/sandbox"
	"argus/internal/repotools"
	"argus/internal/resourcechanges"
	"argus/internal/scm"
	"argus/internal/secretbox"
	"argus/internal/settings"
	"argus/internal/tunnel"
	"argus/internal/upgradescans"

	"github.com/jackc/pgx/v5/pgxpool"
	"k8s.io/client-go/tools/clientcmd"
)

// logger is this binary's package-local structured logger (PROJECT.md T22).
// component=hub on every record it writes.
var logger = logging.For("hub")

// fatal is the structured replacement for log.Fatalf: log at ERROR, then
// exit non-zero. Not a convenience — log.Fatalf's bridged record came out
// at INFO (the bridge infers a level from the text, and a fatal's text says
// nothing), so the one class of line an operator most needs to find by
// level was the one class that lied about it.
func fatal(msg string, attrs ...any) {
	logger.Error(msg, attrs...)
	os.Exit(1)
}

func main() {
	// PROJECT.md T22, first statement in the process: install the structured
	// JSON logging chain and bridge the standard `log` package into it.
	// Before any subcommand runs, so a migration's output is as structured
	// and as redacted as the hub's, and so no line this binary writes can
	// predate the handler.
	//
	// Every remaining unconverted log.Printf in the tree still comes out as
	// a levelled JSON record because of the bridge — see internal/logging's
	// package doc comment for what conversion buys on top of that (fields,
	// and the correlation id).
	logging.Setup()

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: hub <migrate|api|orchestrator|gitops|notify> [up|down]")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "migrate":
		// Uses the migration-owning role, NOT argus_app — argus_app has no
		// general DDL privileges (lld/02-authz-spec.md §10.2's non-owner-role
		// precondition would be meaningless if the app role could also
		// migrate the schema itself). The one deliberate, narrow exception is
		// migration 000022: argus_app owns findings/incidents/audit_events
		// specifically so internal/partition's daily job can create and drop
		// THEIR partitions at runtime — that's schema-shape management
		// Postgres has no separate grantable privilege for short of
		// ownership, and it does not extend to running migrations or altering
		// any other table (FORCE ROW LEVEL SECURITY on all three still
		// applies regardless of ownership, so row-level access is unaffected;
		// see migration 000022's comment for the full reasoning).
		runMigrate(requireEnv("ARGUS_MIGRATE_DATABASE_URL"))
	case "api":
		runAPI(requireEnv("ARGUS_DATABASE_URL"))
	case "hash-password":
		runHashPassword()
	case "orchestrator", "gitops", "notify":
		fatal("subcommand not yet implemented", slog.String("subcommand", os.Args[1]))
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		os.Exit(1)
	}
}

// runHashPassword prints an Argon2id hash for a password, in the same format
// authz.HashPassword produces (lld/02-authz-spec.md §8). Useful for an admin
// setting a user's password_hash directly, and for scripts/smoke-test.sh, which
// needs a second, non-admin test user without hand-crafting a hash.
func runHashPassword() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: hub hash-password <password>")
		os.Exit(1)
	}
	hash, err := authz.HashPassword(os.Args[2])
	if err != nil {
		fatal("hash-password failed", logging.Err(err))
	}
	fmt.Println(hash)
}

func runMigrate(connString string) {
	applied, err := data.RunMigrations(connString)
	if err != nil {
		fatal("migrate failed", logging.Err(err))
	}
	if applied {
		logger.Info("migrate: applied pending migrations")
	} else {
		logger.Info("migrate: already up to date, nothing to do")
	}

	// Folded in here rather than a separate step/container (there used to be
	// one — `hub-app-role` — removed once this made it redundant) — the
	// migration-owning connection this function already has is exactly what's
	// needed to ALTER ROLE, so a second container just to run one SQL statement
	// wasn't buying anything. Optional: only runs if the operator set it.
	if appPassword := os.Getenv("ARGUS_APP_PASSWORD"); appPassword != "" {
		if err := data.SetAppRolePassword(context.Background(), connString, appPassword); err != nil {
			fatal("migrate: could not set the argus_app password", logging.Err(err))
		}
		logger.Info("migrate: argus_app login password set")
	}
}

func runAPI(connString string) {
	// PROJECT.md P22: let ARGUS_AGENT_MIN_SUPPORTED_VERSION /
	// ARGUS_AGENT_RECOMMENDED_VERSION move agentversion.Policy's thresholds
	// away from their tunnel.AgentBuildVersion default before anything reads
	// it — see agentversion.ConfigureFromEnv's own doc comment.
	agentversion.ConfigureFromEnv()

	ctx := context.Background()

	// PROJECT.md B162's graceful-shutdown path. Three distinct contexts,
	// because they answer three different questions and collapsing them is
	// what produced the original defect (one uncancelled context.Background()
	// for everything, and a plain http.ListenAndServe, so a rollout severed
	// in-flight requests, agent tunnels, browser WebSockets and background
	// workers rather than draining any of them):
	//
	//   ctx          — startup only. Never cancelled; a half-built hub has
	//                  nothing to drain, so the fatal() paths below stay
	//                  exactly as they were.
	//   shutdownCtx  — cancelled by SIGTERM (kubelet's rollout signal) or
	//                  SIGINT (a developer's Ctrl-C). Nothing runs under it;
	//                  it is only the trigger the serve loop selects on.
	//   workerCtx    — what every background goroutine and the MCP listener
	//                  run under, cancelled deliberately at the worker phase
	//                  of the drain, AFTER the HTTP phase, because an
	//                  in-flight request may still need them.
	shutdownCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	workerCtx, stopWorkers := context.WithCancel(context.Background())
	defer stopWorkers()
	// workers counts every goroutine started with startWorker below, so the
	// drain can WAIT for them instead of assuming that cancelling their
	// context is the same thing as their having stopped.
	var workers sync.WaitGroup

	// lateCtx is for the one listener that must outlive the workers: the MCP
	// listener (ADR-17's cli backend reaches the hub's tools through it). A
	// worker-driven investigation — internal/autoanalyze's poller, not an
	// HTTP request — makes its tool calls back through that listener, so
	// stopping it in the same phase as the workers would cut off the very
	// work the worker phase is waiting to finish. It is stopped with the
	// tunnel instead, for the same reason the tunnel is last.
	lateCtx, stopLateListeners := context.WithCancel(context.Background())
	defer stopLateListeners()
	var lateListeners sync.WaitGroup

	// PROJECT.md P15: an explicitly sized pool, not pgxpool.New's
	// max(4, NumCPU) — see data.PoolConfig for what contends for it and where
	// the defaults come from. Logged because pool exhaustion presents as
	// unexplained latency, and the first question is always what the pool was
	// actually sized at in the deployment that is slow.
	poolCfg := data.PoolConfigFromEnv()
	db, err := data.Connect(ctx, connString, poolCfg)
	if err != nil {
		fatal("could not connect to postgres", logging.Err(err))
	}
	defer db.Close()
	logger.Info("postgres pool configured", slog.String("pool", poolCfg.String()))

	// Bootstrap runs as part of api startup (not a separate subcommand) so a fresh
	// install's first `hub api` run produces a usable super-admin without an extra
	// manual step. Idempotent — safe on every restart. Runs against the pool
	// directly (not through argus_app + RLS), since it INSERTs the very first rows
	// RLS would otherwise have nothing to scope against yet.
	if err := authz.EnsureBootstrap(ctx, db.Pool); err != nil {
		fatal("bootstrap failed", logging.Err(err))
	}

	if err := db.CheckRLSPreconditions(ctx); err != nil {
		logger.Error("refusing to start: the row-level-security preconditions are not met — see lld/01-threat-model.md SR-2 and internal/migrations/000009_row_level_security.up.sql",
			logging.Err(err))
		os.Exit(1)
	}

	// Signing/CA key material now persists across restarts (signing_keys
	// table, internal/migrations/000016_signing_keys.up.sql) instead of being
	// regenerated from scratch on every `hub api` startup — previously, a
	// restart invalidated every outstanding session, enrollment token, and
	// issued cluster certificate. Not real KMS/envelope-encrypted key
	// management (see NewPersistentTokenSigner's doc comment) — a real,
	// meaningful improvement over "invalidates every restart," not the final
	// answer. NewEphemeral* variants still exist, unchanged, for tests/
	// throwaway runs that shouldn't touch a real DB.
	signer, signerLoaded, err := authz.NewPersistentTokenSigner(ctx, db.Pool)
	if err != nil {
		fatal("could not load or create the JWT signing key", logging.Err(err))
	}
	if signerLoaded {
		logger.Info("loaded the persisted JWT signing key")
	} else {
		logger.Info("generated and persisted a new JWT signing key")
	}

	enrollmentSigner, enrollmentSignerLoaded, err := authz.NewPersistentEnrollmentSigner(ctx, db.Pool)
	if err != nil {
		fatal("could not load or create the enrollment token signing key", logging.Err(err))
	}
	if enrollmentSignerLoaded {
		logger.Info("loaded the persisted enrollment token signing key")
	} else {
		logger.Info("generated and persisted a new enrollment token signing key")
	}

	// The hub chart's local agent enrolls with a key the chart shares between
	// the two (authz/local_enrollment.go). A failure here leaves that one
	// cluster to be enrolled by hand; it never stops the hub.
	if key := strings.TrimSpace(os.Getenv("ARGUS_LOCAL_ENROLLMENT_KEY")); key != "" {
		if err := enrollmentSigner.SetLocalEnrollmentKey(key); err != nil {
			logger.Warn("ignoring the local enrollment key", logging.Err(err))
		} else if created, err := enrollmentSigner.EnsureLocalEnrollmentToken(ctx, db.Pool); err != nil {
			logger.Warn("could not register the local cluster's enrollment token; enroll this cluster from the UI instead", logging.Err(err))
		} else if created {
			logger.Info("registered the local cluster's single-use enrollment token")
		}
	}

	// Dev CA for the agent tunnel (internal/gateway): issues both the
	// gateway's own TLS server cert and every enrolled cluster's leaf cert.
	// Same persistence convention as the two signers above — see
	// gateway.NewPersistentDevCA's doc comment for why persisting the root
	// CERTIFICATE (not just its key) is what makes an already-enrolled
	// cluster's leaf cert keep working across a restart.
	ca, caLoaded, err := gateway.NewPersistentDevCA(ctx, db.Pool)
	if err != nil {
		fatal("could not load or create the dev CA root", logging.Err(err))
	}
	if caLoaded {
		logger.Info("loaded the persisted dev CA root")
	} else {
		logger.Info("generated and persisted a new dev CA root")
	}

	// Root key for signing remediation-execution plans (ScaleDeployment/
	// RestartPod, internal/remediation/sign.go) — same persistence
	// convention as the three signers above. Never handed to an agent
	// directly: internal/api/enroll.go derives a per-cluster key from this
	// root (remediation.DeriveClusterSigningKey) and hands out only that.
	planSigningRootKey, planSigningRootKeyLoaded, err := data.LoadOrCreateSigningKey(ctx, db.Pool, "plan_signing_key_root", remediation.GenerateRootSigningKeyMaterial)
	if err != nil {
		fatal("could not load or create the remediation plan signing root key", logging.Err(err))
	}
	if planSigningRootKeyLoaded {
		logger.Info("loaded the persisted remediation plan signing root key")
	} else {
		logger.Info("generated and persisted a new remediation plan signing root key")
	}

	// The KEK for envelope-encrypted secrets — today the Git provider token
	// (REMEDIATION_ROADMAP.md D-R9). Same persistence pattern as the signers
	// above, which already solves generate-once / survive-restarts / race-safe.
	//
	// DESIGN.md §18.6 permits a locally-held KEK "for evaluation only, with a
	// loud warning", and that warning is printed here rather than buried: with
	// the GitHub App dropped, what sits at rest is a live bearer token rather
	// than a signing key that is useless on its own, so a reader of these logs
	// should know exactly how well it is protected.
	secretKEK, secretKEKLoaded, err := data.LoadOrCreateSigningKey(ctx, db.Pool, secretbox.SigningKeyPurpose, secretbox.GenerateLocalKEK)
	if err != nil {
		fatal("could not load or create the secret-encryption key", logging.Err(err))
	}
	secretKeeper, err := secretbox.NewLocalKeeper(secretKEK)
	if err != nil {
		fatal("could not build the local secret keeper", logging.Err(err))
	}
	// Zeroed immediately: the Keeper copied it, and holding a second copy in
	// this scope for the process's lifetime would defeat the point.
	secretbox.Zero(secretKEK)
	if secretKEKLoaded {
		logger.Info("loaded the persisted secret-encryption key")
	} else {
		logger.Info("generated and persisted a new secret-encryption key")
	}
	if w := secretKeeper.LocalKEKWarning(); w != "" {
		logger.Warn("local KEK in use", slog.String("warning", w))
	}

	tunnelPublicEndpoint, err := chooseTunnelEndpoint(os.Getenv("ARGUS_TUNNEL_PUBLIC_ENDPOINT"), os.Getenv("ARGUS_PUBLIC_API_URL"))
	if err != nil {
		fatal("the tunnel endpoint is misconfigured", logging.Err(err))
	}
	logger.Info("agents will connect to the tunnel at this endpoint", slog.String("tunnel_endpoint", tunnelPublicEndpoint))

	// internal/llm's one-shot provider (see its package doc comment for what
	// this is and isn't). Always constructed now — whether a real endpoint
	// is configured is resolved fresh per call from internal/settings (DB
	// row, falling back to ARGUS_LLM_BASE_URL/_MODEL/_API_KEY), not fixed at
	// startup, so it can be set or changed later via
	// PUT /api/v1/admin/settings without a restart. POST /incidents/{id}/analyze
	// returns a clear 503 (llm.ErrNotConfigured) if nothing resolves to a
	// base URL at call time. The log line below is informational only — a
	// one-time snapshot at startup, not a gate on anything.
	llmProvider := llm.NewProvider(db.Pool)
	if startupCfg, err := settings.Resolve(ctx, db.Pool); err != nil {
		logger.Warn("could not resolve the AI provider settings at startup", logging.Err(err))
	} else if startupCfg.LLMBaseURL != "" {
		logger.Info("AI provider configured", slog.String("model", firstNonEmptyStr(startupCfg.LLMModel, "<no model set>")))
	} else {
		logger.Info("no AI provider configured yet (no org_settings row nor ARGUS_LLM_BASE_URL) — incident analysis will return 503 until one is set via PUT /api/v1/admin/settings")
	}

	// bus is constructed once, before either gw or srv, and shared between
	// them — internal/events' doc comment explains why this is a single
	// in-process fan-out rather than real pub/sub infrastructure. gw needs
	// it to publish IncidentUpdated/ClusterUpdated on finding ingestion,
	// health-monitor demotion, and heartbeat-driven recovery; srv needs the
	// SAME instance (not a second, empty one) so GET /ws/events actually
	// receives what gw publishes.
	bus := events.NewBus()

	// readLogRegistry is BACKLOG.md F28 finding 1's cross-backend bridge:
	// constructed once and passed to BOTH api.NewServer and autoanalyze.New,
	// the same "shared, built outside either" treatment bus gets just above
	// and for an analogous reason — internal/api.Server.CallRepoTool is the
	// only thing a cli-backend investigation's repository-tool calls ever
	// reach, regardless of whether a manual click (internal/api/analyze.go)
	// or this poller (internal/autoanalyze) started the investigation, so
	// both need a reference to the identical registry. See
	// repotools.ReadLogRegistry's own doc comment for the full reasoning.
	readLogRegistry := repotools.NewReadLogRegistry()

	// Declared before the MCP listener is built so that listener's ToolFunc can
	// close over it (BACKLOG.md F22: a repository tool is served by the API
	// server, not by the tunnel). Assigned further down, once every dependency
	// it needs exists; nothing can call through the closure before then,
	// because the process is not serving yet.
	var srv *api.Server

	// gw is constructed here, BEFORE srv, and threaded into api.NewServer —
	// deliberately reordered from this function's earlier shape (which built
	// srv first and only started the tunnel listener afterward, with nothing
	// in api ever holding a *gateway.Gateway reference at all). Now that
	// internal/api/analyze.go's investigation loop calls gw.CallTool/
	// gw.IsConnected directly, the Server needs the same Gateway instance the
	// tunnel listener runs on — not a second one, which would have its own,
	// empty connection registry and could never see any agent's live tunnel.
	gw := gateway.NewGateway(db, ca, bus)
	// gw.LLM (BACKLOG.md E11 piece 3's polarity gate seam,
	// internal/gateway/polarity_gate.go) is set further down, once
	// investigator (the *llm.Router below) exists — see that assignment's
	// own comment for why it now holds the Router rather than the bare
	// *llm.Provider this used to be set to here, straight after
	// construction. Deliberately still a post-construction field set outside
	// NewGateway's parameter list, for the same reason as before: widening
	// NewGateway's positional signature would force every one of the seven
	// existing gateway.NewGateway call sites in internal/gateway's and
	// internal/api's own tests to change for a dependency most of them never
	// exercise.

	// --- The two investigator backends (lld/14-adrs.md ADR-17) ---
	//
	// The api backend (llmProvider) is always wired. The cli backend is wired
	// only when an MCP listener address is configured, because it structurally
	// cannot work without one: the CLI reaches tools by calling back into the
	// hub, so with no listener there is nothing for it to call. When it isn't
	// wired, selecting "cli" in Settings yields a clear ErrNotConfigured rather
	// than a nil-pointer panic (see llm.NewRouter).
	resolveSettings := func(ctx context.Context) (settings.Config, error) {
		return settings.Resolve(ctx, db.Pool)
	}

	var cliBackend llm.Investigator
	// Its own listener, never the public API listener — lld/12-deployment-design.md
	// §12.6. Empty (the default) disables the whole surface.
	mcpAddr := os.Getenv("ARGUS_MCP_ADDR")
	if mcpAddr != "" {
		// The URL the *runner* uses to reach this listener, which is not
		// necessarily this listener's own bind address: a sidecar reaches it on
		// localhost, a separate Deployment via a Service DNS name. Configured
		// rather than derived for exactly that reason.
		mcpPublicURL := envOr("ARGUS_MCP_PUBLIC_URL", "http://127.0.0.1"+mcpAddr+"/mcp")

		tokenStore := mcp.NewStore(mcp.DefaultTokenTTL, nil)

		// The tool surface is projected from internal/llm's own fixed
		// toolDefinitions, so the api backend's tools and the cli backend's MCP
		// tools are one list by construction rather than two that could drift
		// (llm.InvestigationToolSchemas' own comment). All read-only: no
		// remediation action is reachable here.
		schemas := llm.InvestigationToolSchemas()
		tools := make([]mcp.Tool, 0, len(schemas))
		for _, s := range schemas {
			tools = append(tools, mcp.Tool{Name: s.Name, Description: s.Description, InputSchema: s.InputSchema})
		}

		mcpSrv := mcp.NewServer(tokenStore, tools,
			// CallToolWithRetry, not plain CallTool — BACKLOG.md C5 / BUGS.md
			// 96, the exact scenario reproduced against this cli backend: a
			// transient tunnel stall delayed an agent's correct, on-time
			// answer past the hub's 30s toolCallTimeout, discarding it and
			// burning cmd/cli-runner's whole process deadline for nothing.
			// Safe here because this server's whole tool surface is
			// read-only by construction (see this func's own comment, a few
			// lines up, on "All read-only: no remediation action is
			// reachable here") — gateway.CallToolWithRetry's doc comment has
			// the full reasoning.
			//
			// BACKLOG.md F22 piece 1: dispatched by tool NAME, the same seam
			// internal/api/analyze.go's callback uses. The two repository
			// tools are served hub-side (srv.CallRepoTool, scoped to the
			// grant's own incident); everything else goes over the tunnel.
			// srv is assigned below, after this closure is built, and is
			// never nil by the time an MCP request can arrive — the listener
			// only starts serving once the process is up.
			func(ctx context.Context, grant mcp.Grant, tool string, args json.RawMessage) (json.RawMessage, error) {
				if repotools.IsRepoTool(tool) {
					return srv.CallRepoTool(ctx, grant.ClusterID, grant.IncidentID, tool, args)
				}
				if tool == llm.RecentChangesToolName {
					return api.CallRecentChanges(ctx, db, grant.ClusterID, args)
				}
				return gw.CallToolWithRetry(ctx, grant.ClusterID, tool, args)
			},
			// Every tool call over B12 is logged with the cluster it was
			// scoped to. lld/07-analysis-contracts.md §10.4 asks for audit
			// parity with the api path; this is the observability half, and
			// the honest current limit is stated in STATUS.md rather than
			// implied to be more than it is.
			func(ctx context.Context, grant mcp.Grant, tool string, args json.RawMessage, err error) {
				if err != nil {
					logger.WarnContext(ctx, "MCP tool call FAILED",
						slog.String("tool", tool), logging.ClusterID(grant.ClusterID), logging.IncidentID(grant.IncidentID), logging.Err(err))
					return
				}
				logger.DebugContext(ctx, "MCP tool call ok",
					slog.String("tool", tool), logging.ClusterID(grant.ClusterID), logging.IncidentID(grant.IncidentID))
			},
			// The same fact, persisted (migration 000037) instead of only
			// logged. Without it the cli backend's analyses arrive as verdicts
			// with no visible work behind them — it contributes no causal chain
			// by design, because it never sees the intermediate turns, so the
			// tool calls it made back through this listener are the only record
			// that the investigation did anything at all.
			//
			// The error is logged here and goes nowhere else, which is the
			// whole point: mcp.RecordFunc cannot return one (see its doc
			// comment), so a database problem degrades an investigation's
			// evidence summary rather than the investigation.
			func(ctx context.Context, grant mcp.Grant, tool string, dur time.Duration, callErr error) {
				if err := api.RecordMCPToolCall(ctx, db.Pool, grant.ClusterID, grant.IncidentID, tool, dur, callErr); err != nil {
					logger.ErrorContext(ctx, "could not record the tool call (the tool call itself was unaffected)",
						slog.String("tool", tool), logging.ClusterID(grant.ClusterID), logging.IncidentID(grant.IncidentID), logging.Err(err))
				}
			},
			// PROJECT.md B151: the real content, persisted so a self-reported
			// causal-chain citation can be checked for VALUE agreement, not
			// only call existence — see mcp.RecordContentFunc's own doc
			// comment for why this is now captured where it never was
			// before. Same "logs its own failure, never fails the call"
			// posture as record just above.
			func(ctx context.Context, grant mcp.Grant, tool string, args, result json.RawMessage, callErr error) {
				if err := api.RecordMCPToolCallContent(ctx, db.Pool, grant.ClusterID, grant.IncidentID, tool, args, result, callErr); err != nil {
					logger.ErrorContext(ctx, "could not record the tool call content (the tool call itself was unaffected)",
						slog.String("tool", tool), logging.ClusterID(grant.ClusterID), logging.IncidentID(grant.IncidentID), logging.Err(err))
				}
			})

		// lateCtx, not the startup ctx and not workerCtx: see lateCtx's own
		// comment for why this listener outlives the worker phase.
		// mcp.Server.ListenAndServe already shuts its own http.Server down on
		// ctx.Done() (see its body) — it just never had a context that was
		// ever cancelled to do it with. PROJECT.md B162.
		startWorker(&lateListeners, "mcp listener", func() {
			if err := mcpSrv.ListenAndServe(lateCtx, mcpAddr); err != nil {
				logger.Warn("MCP listener stopped", logging.Err(err))
			}
		})

		// BACKLOG.md C10: the cross-check ledger, letting the cli backend read
		// back exactly the mcp_tool_calls rows the RecordFunc closure just above
		// writes, before it ever trusts a self-reported causal chain citing
		// them.
		toolCallLedger := func(ctx context.Context, clusterID, incidentID string) ([]llm.RecordedToolCall, error) {
			return api.ListMCPToolCalls(ctx, db.Pool, clusterID, incidentID)
		}
		cliBackend = llm.NewCLIInvestigator(tokenStore, mcpSrv.ToolNames(), mcpPublicURL, resolveSettings, toolCallLedger)
		logger.Info("CLI investigator backend available",
			slog.String("mcp_addr", mcpAddr), slog.String("mcp_public_url", mcpPublicURL))
	} else {
		logger.Info("CLI investigator backend not wired (ARGUS_MCP_ADDR unset) — this provider kind will return a configuration error if selected",
			slog.String("provider_kind", string(settings.ProviderKindCLI)))
	}

	// Router is what everything downstream holds, so a provider-kind change
	// through Settings takes effect on the very next investigation.
	investigator := llm.NewRouter(llmProvider, cliBackend, resolveSettings)

	// gw.LLM (BACKLOG.md E11 piece 3's polarity gate seam) is the SAME
	// Router, not the bare *llm.Provider it held before P13: Complete's real
	// callers (this gate, and BACKLOG.md F12b's plan-correction retry below)
	// need to dispatch on the configured provider kind the exact way
	// Investigate already does, or they are silently dead on any deployment
	// whose active provider is `cli` — see llm.Router.Complete's own doc
	// comment, and BUGS.md 125 for how this was found.
	gw.LLM = investigator

	// internal/knowledge's embedding provider, for related-analysis retrieval:
	// a self-hosted Ollama (bge-m3, 1024 dimensions by default). A missing
	// analysis_embeddings row is the correct "not embedded yet" state, so the
	// hub runs the same with or without one. ARGUS_EMBEDDINGS=off (the hub
	// chart's default, which ships no Ollama) leaves the store nil: nothing is
	// embedded, retrieval returns nothing, and no sweep retries an endpoint
	// that does not exist.
	var knowledgeStore *knowledge.Store
	if strings.EqualFold(strings.TrimSpace(os.Getenv("ARGUS_EMBEDDINGS")), "off") {
		logger.Info("related-analysis embeddings are off (ARGUS_EMBEDDINGS=off)")
	} else {
		embeddingDims := envOrInt("ARGUS_EMBEDDING_DIMS", knowledge.DefaultEmbeddingDims)
		embeddingProvider := knowledge.NewOllamaProvider(
			envOr("ARGUS_OLLAMA_URL", knowledge.DefaultOllamaURL),
			envOr("ARGUS_EMBEDDING_MODEL", knowledge.DefaultEmbeddingModel),
			embeddingDims,
		)
		knowledgeStore = knowledge.NewStore(db.Pool, embeddingProvider)
		logger.Info("knowledge embedding provider wired",
			slog.String("model", embeddingProvider.Model()), slog.Int("dims", embeddingProvider.Dimensions()))
	}

	// investigator (the *llm.Router) is ALSO what BACKLOG.md F12b's retry
	// loop uses to ask for a corrected params value on a dry-run rejection —
	// see internal/execution/correction.go's planCorrectionModel. Passed to
	// NewServer as a second argument, separately from the Investigator one,
	// only because the two call sites are typed against two different
	// narrow interfaces (Investigate vs CorrectPlanParams); it is the exact
	// same instance, not a second one. BACKLOG.md P13: this used to be the
	// concrete *llm.Provider instead, which meant the retry loop's only
	// working path was the api backend — silently dead under a cli-kind
	// provider (BUGS.md 125) — until CorrectPlanParams moved onto Router and
	// started going through Router.Complete's own dispatch.
	// BACKLOG.md F26: the render-and-diff sandbox. Off by default — matches
	// the CLI-backend idiom just above (log and leave nil rather than fail
	// startup) because this is an optional UPGRADE to an already-honest
	// "unproven" state, not something the hub needs to run at all. Points
	// at infrastructure the hub itself administers (never a customer
	// cluster reached through the tunnel — see internal/render/sandbox's
	// package comment) — a dedicated namespace on whatever cluster
	// ARGUS_RENDER_SANDBOX_KUBECONFIG names.
	var renderSandbox *sandbox.Runner
	if kubeconfig := os.Getenv("ARGUS_RENDER_SANDBOX_KUBECONFIG"); kubeconfig != "" {
		restCfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			logger.Warn("render sandbox not wired: ARGUS_RENDER_SANDBOX_KUBECONFIG could not be loaded — pull requests will state rendering as not attempted",
				slog.String("kubeconfig", kubeconfig), logging.Err(err))
		} else {
			ns := envOr("ARGUS_RENDER_SANDBOX_NAMESPACE", "argus-render-sandbox")
			rn, err := sandbox.NewRunner(restCfg, sandbox.Config{
				Namespace:        ns,
				RuntimeClassName: os.Getenv("ARGUS_RENDER_SANDBOX_RUNTIME_CLASS"), // empty unless the operator has installed one (e.g. gVisor) — see that package's doc comment
			})
			if err != nil {
				logger.Warn("render sandbox not wired — pull requests will state rendering as not attempted", logging.Err(err))
			} else {
				renderSandbox = rn
				logger.Info("render sandbox wired — pull requests will carry a render-and-diff evidence section where the source is a renderable Helm chart or Kustomize overlay",
					slog.String("namespace", ns))
			}
		}
	} else {
		logger.Info("render sandbox not wired (ARGUS_RENDER_SANDBOX_KUBECONFIG unset) — pull requests will state rendering as not attempted")
	}

	// PROJECT.md D14. Off unless explicitly switched on, and loud when it is:
	// the demo-data routes write fabricated analyses, approval decisions
	// attributed to the calling user by name, execution records and metered
	// spend into the same tables real ones live in, and nothing anywhere
	// excludes them from counts. The dev compose stack sets this so web/e2e
	// can seed its fixture through the real endpoints; a real deployment
	// must not.
	demoDataEnabled := envOr("ARGUS_ENABLE_DEMO_DATA", "") == "true"
	if demoDataEnabled {
		logger.Warn("ARGUS_ENABLE_DEMO_DATA=true — POST/DELETE /api/v1/demo-data are registered. This writes FABRICATED incidents, analyses, approval decisions and executions into the real tables, counted everywhere. Intended for the e2e fixture only; never set this on a real install")
	}

	srv = api.NewServer(db, signer, enrollmentSigner, ca, tunnelPublicEndpoint, investigator, investigator, gw, bus, planSigningRootKey, secretKeeper, knowledgeStore, renderSandbox, readLogRegistry, demoDataEnabled)

	// The mTLS tunnel listener runs alongside the HTTP API, not instead of
	// it — enrollment/status/accept are plain HTTP (see internal/api/enroll.go),
	// only the post-enrollment agent<->hub tunnel itself speaks this protocol.
	tunnelAddr := envOr("ARGUS_TUNNEL_ADDR", ":8443")
	tunnelSANs := strings.Split(envOr("ARGUS_TUNNEL_SANS", "localhost,127.0.0.1,hub-api"), ",")
	// Both tunnel transports, the TLS listener and the WebSocket on the API,
	// share one certificate; it must exist before the API serves the latter.
	if _, err := gw.PrepareTLS(tunnelSANs); err != nil {
		fatal("could not prepare the tunnel certificate", logging.Err(err))
	}
	// Not a startWorker: this listener is stopped by gw.Shutdown at the LAST
	// phase of the drain (PROJECT.md B162), not by workerCtx, because an
	// in-flight investigation and the sweepers both still need their
	// clusters' tunnels while the earlier phases drain. ListenAndServeTLS
	// returns nil once its listener is closed, so the fatal() here still
	// means only what it always meant: this hub could not listen at all.
	go func() {
		if err := gw.ListenAndServeTLS(tunnelAddr, tunnelSANs); err != nil {
			fatal("the tunnel gateway could not listen", logging.Err(err))
		}
	}()

	// Cluster health sweep (lld/03-agent-protocol.md §4/§7): demotes a
	// cluster off Active when its agent goes quiet (Active -> Degraded ->
	// Disconnected). Runs alongside the tunnel listener above as its own
	// goroutine, same pattern, for the same reason — no graceful-shutdown
	// mechanism exists anywhere in this codebase yet, so this doesn't invent
	// one just for this; context.Background() never gets cancelled here.
	hm := gateway.NewHealthMonitor(db, bus)
	startWorker(&workers, "cluster health monitor", func() { hm.Run(workerCtx, gateway.DefaultHealthCheckInterval) })

	// internal/orchestrator's automated re-check: promotes a Validating
	// incident to Resolved once it's gone quiet (no recurring Finding) for
	// validationGracePeriod. The other half of this same re-check —
	// recurrence flipping an incident to Reopened — is event-driven, wired
	// directly into internal/gateway/finding.go's handleFinding rather than
	// needing its own goroutine here. Same "no graceful shutdown exists
	// yet" rationale as hm.Run above.
	//
	// PROJECT.md T4: Run also sweeps Diagnosed/NeedsHumanInvestigation
	// incidents whose investigation genuinely concluded with nothing to
	// execute (never a bound-hit, inconclusive one) and closes them
	// self_healed on the SAME quiet-period floor once nothing has recurred —
	// see validation.go's sweepSelfHealing for why that is a second pass
	// rather than routed through Validating itself.
	vs := orchestrator.NewValidationSweeper(db, bus, srv)
	startWorker(&workers, "validation sweeper", func() {
		runExclusive(workerCtx, db.Pool, lockKeyValidationSweeper, "validation sweeper",
			func() { vs.Run(workerCtx, orchestrator.DefaultValidationSweepInterval) })
	})

	// The GitOps/OpenPR channel's own version of the same re-check: polls
	// every AwaitingMerge incident's pull request and, once the provider
	// reports it merged AND the GitOps controller has synced past the merge
	// commit, hands off to the exact same Validating machinery vs.Run drives
	// above — see internal/orchestrator/mergewatch.go and state.go's updated
	// doc comment for what this closes (state.go used to call this edge
	// "deliberately absent").
	ms := orchestrator.NewMergeSweeper(db, bus, srv)
	startWorker(&workers, "merge sweeper", func() {
		runExclusive(workerCtx, db.Pool, lockKeyMergeSweeper, "merge sweeper",
			func() { ms.Run(workerCtx, orchestrator.DefaultMergeSweepInterval) })
	})

	// BACKLOG.md T3: the other half of the same "escalate, don't just
	// notify once" gap mergewatch.go's own stale-PR branch closed for
	// AwaitingMerge — this sweeper does it for AwaitingApproval, the other
	// state where a finished plan sits waiting on a human who was told
	// exactly once, when it first arrived. No external checker/tunnel call
	// needed (see internal/orchestrator/approvalwatch.go's own doc
	// comment), so no dependency beyond db.
	as := orchestrator.NewApprovalSweeper(db)
	startWorker(&workers, "approval sweeper", func() {
		runExclusive(workerCtx, db.Pool, lockKeyApprovalSweeper, "approval sweeper",
			func() { as.Run(workerCtx, orchestrator.DefaultApprovalSweepInterval) })
	})

	// The one state nothing used to watch. Executing means "a signed plan is
	// in flight against a cluster right now", and the hub that dispatched it
	// is the only thing that ever wrote its outcome — so a client disconnect
	// or a hub restart left the incident there permanently, with the cluster
	// mutation having landed or not and nothing recording which. This sweeps
	// the durable attempt rows (migration 000093) whose dispatcher never came
	// back, verifies against the live cluster where it can, and records
	// ExecutionUnknown where it cannot. It sweeps once at startup as well as
	// on each tick, deliberately: a hub that just came up is the likeliest
	// moment for there to be an abandoned execution to finish.
	startWorker(&workers, "execution reconciler", func() {
		runExclusive(workerCtx, db.Pool, lockKeyExecutionReconciler, "execution reconciler",
			func() { srv.RunExecutionReconciler(workerCtx, execution.DefaultExecutionReconcileInterval) })
	})

	// internal/notify's webhook poller (see its package doc comment for what
	// this is and isn't — a deliberately small first slice of
	// DESIGN.md §13, not that whole design). Now always
	// started, same rationale as llmProvider above: whether a webhook URL is
	// configured is resolved fresh every sweep tick from internal/settings
	// (DB row, falling back to ARGUS_NOTIFY_WEBHOOK_URL), not fixed at
	// startup — an unconfigured webhook just means each tick is a no-op
	// until one is set via PUT /api/v1/admin/settings, so the poller itself
	// can no longer be conditionally skipped at startup without also
	// missing a webhook configured later, live.
	notifier := notify.NewWebhookNotifier(db)
	startWorker(&workers, "webhook notifier", func() { notifier.Run(workerCtx, notify.DefaultNotifyCheckInterval) })
	if startupCfg, err := settings.Resolve(ctx, db.Pool); err != nil {
		logger.Warn("could not resolve the notification settings at startup", logging.Err(err))
	} else if startupCfg.NotifyWebhookConfigured {
		logger.Info("notification webhook configured")
	} else {
		logger.Info("no notification webhook configured yet (no org_settings row nor ARGUS_NOTIFY_WEBHOOK_URL) — new incidents will not be notified until one is set via PUT /api/v1/admin/settings")
	}

	// internal/autoanalyze's poller (see its package doc comment for what
	// this is and how it relates to a manual POST /incidents/{id}/analyze
	// click). Same "always running, settings resolved fresh every tick"
	// shape as notifier/llmProvider above — whether auto-analysis is
	// enabled at all, and which severities qualify, is DB-backed and
	// live-editable via PUT /api/v1/admin/settings' "automation" section,
	// not fixed at hub startup, so this doesn't need its own startup-time
	// conditional the way an env-var-gated feature would.
	autoAnalyzer := autoanalyze.New(db, gw, investigator, bus, scm.NewStore(secretKeeper), knowledgeStore, readLogRegistry)
	// The stale sweep's cleared check re-runs the rule that opened an
	// incident through the same verifier the validation sweeper uses.
	autoAnalyzer.SetRuleChecker(srv)
	startWorker(&workers, "auto-analysis poller", func() {
		runExclusive(workerCtx, db.Pool, lockKeyAutoAnalysisPoller, "auto-analysis poller",
			func() { autoAnalyzer.Run(workerCtx, autoanalyze.DefaultPollInterval) })
	})
	// The stale-object sweeper, from the same poller but deliberately NOT gated on
	// the auto-analysis setting: closing an incident whose object no longer exists
	// costs no model tokens and is a lifecycle question, not an analysis one. A
	// live audit found 26 of 36 open incidents were about objects that had been
	// deleted, precisely because the existing check only ran inside automatic
	// investigation (see the package's RunStaleObjectSweeper comment).
	startWorker(&workers, "stale-object sweeper", func() {
		runExclusive(workerCtx, db.Pool, lockKeyStaleObjectSweeper, "stale-object sweeper",
			func() { autoAnalyzer.RunStaleObjectSweeper(workerCtx, autoanalyze.DefaultStaleSweepInterval) })
	})
	// BACKLOG.md L2 (storage half, decided 2026-08-30): catches up analyses
	// that predate this feature (BACKLOG.md H2's 247+ real ones) and retries
	// any embed attempt that failed (Ollama unreachable, etc.) — see
	// knowledgeStore's own RunBackfillSweep doc comment. Deliberately not
	// gated on any setting, same reasoning as the embedding provider
	// construction above: there is no "off" state for this, only "nothing to
	// do yet" once everything is caught up.
	startWorker(&workers, "knowledge backfill sweeper", func() {
		runExclusive(workerCtx, db.Pool, lockKeyKnowledgeBackfillSweeper, "knowledge backfill sweeper",
			func() { knowledgeStore.RunBackfillSweep(workerCtx, knowledge.DefaultBackfillSweepInterval) })
	})
	if startupCfg, err := settings.Resolve(ctx, db.Pool); err != nil {
		logger.Warn("could not resolve the automation settings at startup", logging.Err(err))
	} else if startupCfg.AutoAnalysisEnabled {
		logger.Info("automatic investigation enabled",
			slog.String("severities", severitiesOrNone(startupCfg.AutoAnalysisSeverities)))
	} else {
		logger.Info("automatic investigation disabled — incidents require a manual POST /incidents/{id}/analyze until enabled via PUT /api/v1/admin/settings")
	}

	// The unattended executor (internal/api/unattended.go). Same
	// always-running, settings-resolved-per-tick shape as everything above,
	// for the same reason: whether ARGUS may execute an auto-approved plan
	// without a human is DB-backed and live-editable, so gating the goroutine
	// on a startup-time read would mean the checkbox in Settings did nothing
	// until someone restarted the hub.
	//
	// The startup log line is not decoration. This is the one setting in the
	// product that lets the hub change a customer's clusters with nobody
	// watching, so whether it is on has to be visible in the place an operator
	// looks first when something changed and they do not know why.
	startWorker(&workers, "unattended executor", func() { srv.RunUnattendedExecutor(workerCtx, api.DefaultUnattendedSweepInterval) })
	if startupCfg, err := settings.Resolve(ctx, db.Pool); err != nil {
		logger.Warn("could not resolve the autonomy settings at startup", logging.Err(err))
	} else if startupCfg.AutonomyUnattendedExecutionEnabled {
		limits := orchestrator.ResolveUnattendedLimits(true, startupCfg.AutonomyMaxUnattendedPerCluster,
			startupCfg.AutonomyMaxUnattendedFleetWide, startupCfg.AutonomyUnattendedWindowSeconds)
		logger.Warn("UNATTENDED EXECUTION IS ENABLED — auto-approved plans will be executed against clusters with no human approval",
			slog.Int("max_per_cluster", limits.MaxPerCluster), slog.Int("max_fleet_wide", limits.MaxFleetWide),
			slog.Duration("window", limits.Window))
	} else {
		logger.Info("unattended execution disabled — every remediation requires a human approval")
	}

	// internal/partition's daily partition-maintenance job (see its package
	// doc comment for the real, previously-undiscovered problem it fixes:
	// findings/incidents/audit_events are all PARTITION BY RANGE, but until
	// this job existed nothing ever created a dated partition — every row
	// since this project began has landed in each table's `_default`
	// catch-all). Same always-running, "settings resolved fresh every
	// sweep" shape as notifier/autoAnalyzer above: whether/how long to
	// retain each table is DB-backed and live-editable via
	// PUT /api/v1/admin/settings' "retention" section, and defaults to nil
	// ("keep forever") — so this job runs unconditionally from hub startup,
	// with an unconfigured retention simply meaning that half of its work
	// is a no-op until an operator opts in. Ensuring this/next period's
	// partition (the other half) is never conditional on any setting at
	// all.
	partitionMaintainer := partition.NewMaintainer(db)
	startWorker(&workers, "partition maintainer", func() {
		runExclusive(workerCtx, db.Pool, lockKeyPartitionMaintainer, "partition maintainer",
			func() { partitionMaintainer.Run(workerCtx, partition.DefaultMaintenanceInterval) })
	})

	// PROJECT.md B157: deleting an incident (today, only DELETE
	// /api/v1/demo-data, or a DB-backed test's own cleanup) leaves every
	// child row that references it via incident_id behind forever — no
	// foreign key can catch this (see orchestrator.OrphanReaper's own doc
	// comment for why, citing migration 000053). Same always-running,
	// no-setting-to-gate-on shape as partitionMaintainer above: retroactive
	// housekeeping, not a user-visible correctness path.
	orphanReaper := orchestrator.NewOrphanReaper(db)
	startWorker(&workers, "orphan reaper", func() {
		runExclusive(workerCtx, db.Pool, lockKeyOrphanReaper, "orphan reaper",
			func() { orphanReaper.Run(workerCtx, orchestrator.DefaultOrphanReapInterval) })
	})

	// docs/CLUSTER_INSIGHT_SPECS.md CI-S2: bounded retention for the
	// field-level change history agents report.
	changeRetention := time.Duration(envInt("ARGUS_RESOURCE_CHANGES_RETENTION_DAYS", 14)) * 24 * time.Hour
	startWorker(&workers, "resource change retention", func() {
		runExclusive(workerCtx, db.Pool, lockKeyResourceChangeRetention, "resource change retention",
			func() { resourcechanges.RunRetention(workerCtx, db, changeRetention, time.Hour) })
	})

	// CI-S5: a daily upgrade-readiness scan per connected cluster.
	startWorker(&workers, "upgrade scan scheduler", func() {
		runExclusive(workerCtx, db.Pool, lockKeyUpgradeScanScheduler, "upgrade scan scheduler",
			func() { upgradescans.RunScheduler(workerCtx, db, gw, time.Hour) })
	})

	// The Overview's fleet checks (internal/fleetchecks): each connected
	// cluster's certificates, posture, Helm and GitOps answers, re-read on an
	// interval so the fleet page never calls every agent on load.
	startWorker(&workers, "fleet check scheduler", func() {
		runExclusive(workerCtx, db.Pool, lockKeyFleetCheckScheduler, "fleet check scheduler",
			func() { fleetchecks.RunScheduler(workerCtx, db, gw, fleetchecks.DefaultInterval) })
	})

	// PROJECT.md T24's runtime and connection-pool metrics. A worker rather
	// than a lazy scrape-time collector for one specific reason:
	// runtime.ReadMemStats briefly stops the world, and a scrape interval is
	// the operator's to choose — a 1s scrape must not be able to make this
	// process pause sixty times a minute. The pool half is P15's
	// data.DB.Stat finally having a consumer.
	//
	// Deliberately NOT wrapped in runExclusive (PROJECT.md P14): this reads
	// runtime.ReadMemStats and this process's OWN db.Stat() and sets local
	// Prometheus gauges — there is no shared row or shared action for two
	// replicas to duplicate. Each replica SHOULD report its own numbers;
	// electing one leader would instead make one replica's process metrics
	// silently vanish once a second replica existed.
	startWorker(&workers, "process metrics collector", func() {
		metrics.RunProcessCollector(workerCtx, metrics.DefaultProcessCollectInterval, func() metrics.DBPoolStat {
			st := db.Stat()
			return metrics.DBPoolStat{
				MaxConns:             st.MaxConns(),
				TotalConns:           st.TotalConns(),
				IdleConns:            st.IdleConns(),
				AcquiredConns:        st.AcquiredConns(),
				ConstructingConns:    st.ConstructingConns(),
				AcquireCount:         st.AcquireCount(),
				EmptyAcquireCount:    st.EmptyAcquireCount(),
				CanceledAcquireCount: st.CanceledAcquireCount(),
				AcquireDuration:      st.AcquireDuration(),
			}
		})
	})

	// Logged once at startup, like the metrics-auth mode and the unattended-
	// execution banner: "why am I not seeing debug lines" should be
	// answerable from the hub's own first few lines, not from reading
	// internal/logging.
	logger.Info("log level resolved (ARGUS_LOG_LEVEL); structured JSON output (set ARGUS_LOG_FORMAT=text for a human-readable local hub)",
		slog.String("level", logging.LevelFromEnv().String()))

	addr := envOr("ARGUS_API_ADDR", ":8080")
	// An explicit http.Server rather than http.ListenAndServe, for one
	// reason: ListenAndServe has no Shutdown (PROJECT.md B162). Timeouts are
	// deliberately NOT set beyond the header read: a ReadTimeout or
	// WriteTimeout here would break both the /ws/events hijack (an
	// arbitrarily long-lived connection) and POST /incidents/{id}/analyze,
	// whose investigation loop is bounded by its own
	// ARGUS_ANALYSIS_TIME_LIMIT_SECONDS rather than by the HTTP layer.
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- httpSrv.ListenAndServe() }()
	logger.Info("HTTP API listening", slog.String("addr", addr))

	select {
	case err := <-serveErr:
		// The listener failed on its own (port in use, etc.) — nothing to
		// drain, and the same fatal this function has always had.
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fatal("the HTTP API listener failed", logging.Err(err))
		}
		return
	case <-shutdownCtx.Done():
	}
	// Stop intercepting signals from here on: a SECOND SIGTERM/SIGINT during
	// the drain gets the default behaviour (immediate termination), which is
	// what an operator pressing Ctrl-C twice is asking for.
	stopSignals()
	drainHub(hubDrain{
		httpSrv:           httpSrv,
		srv:               srv,
		gw:                gw,
		stopWorkers:       stopWorkers,
		workers:           &workers,
		stopLateListeners: stopLateListeners,
		lateListeners:     &lateListeners,
	})
}

// hubDrain is everything drainHub has to shut down, named rather than
// positional because the ORDER the fields are used in is the load-bearing part
// (see drainHub) and a positional list of five shutdown hooks invites getting
// that order wrong at the call site.
type hubDrain struct {
	httpSrv *http.Server
	srv     *api.Server
	gw      *gateway.Gateway
	// stopWorkers cancels every goroutine started with startWorker under the
	// worker context; workers is what the drain waits on afterwards.
	stopWorkers func()
	workers     *sync.WaitGroup
	// stopLateListeners cancels the listeners that must outlive the workers
	// (today: the MCP listener). May be nil in a test that has none.
	stopLateListeners func()
	lateListeners     *sync.WaitGroup
}

// startWorker runs one background worker under the hub's worker WaitGroup, so
// the shutdown drain can wait for it to actually return rather than cancelling
// its context and hoping (PROJECT.md B162). Every one of these functions
// already returns on ctx.Done() — they had simply never been given a context
// that was cancelled.
func startWorker(wg *sync.WaitGroup, name string, run func()) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		run()
		logger.Info("background worker stopped", slog.String("worker", name))
	}()
}

// Advisory lock keys for runExclusive, one per sweeper that needs
// leader-election across hub replicas (PROJECT.md P14: replicaCount is no
// longer pinned to 1 — see deploy/helm/argus-hub/values.yaml). Never reuse a
// number across sweepers; a collision would let two unrelated sweepers take
// turns blocking each other instead of each having its own lock.
//
// Deliberately absent from this list: internal/notify's webhook poller
// (already safe — it claims individual rows with FOR UPDATE SKIP LOCKED, the
// same style internal/notify/notifier.go documents), the process metrics
// collector (reads runtime.ReadMemStats/db.Stat() and sets local Prometheus
// gauges — nothing shared to double-write; every replica SHOULD report its
// own), and internal/gateway's cluster health monitor plus internal/api's
// unattended executor — both out of scope for this pass, owned elsewhere.
const (
	lockKeyValidationSweeper        int64 = 100001
	lockKeyMergeSweeper             int64 = 100002
	lockKeyApprovalSweeper          int64 = 100003
	lockKeyExecutionReconciler      int64 = 100004
	lockKeyAutoAnalysisPoller       int64 = 100005
	lockKeyStaleObjectSweeper       int64 = 100006
	lockKeyKnowledgeBackfillSweeper int64 = 100007
	lockKeyPartitionMaintainer      int64 = 100008
	lockKeyOrphanReaper             int64 = 100009
	lockKeyResourceChangeRetention  int64 = 100010
	lockKeyUpgradeScanScheduler     int64 = 100011
	lockKeyFleetCheckScheduler      int64 = 100012
)

// runExclusive is PROJECT.md P14's fix for the sweepers that assumed exactly
// one hub process ever called them. Unlike internal/notify's webhook poller,
// none of these sweepers claim individual rows — each tick reads and acts on
// its whole candidate set in one pass, and turning that into a per-row claim
// for every one of them would be the invasive, high-risk rewrite this pass
// does not need: the goal is failover, not sharding sweep work across
// replicas (there is still only ever one active hub's worth of sweeping to
// do). So instead, exactly one replica at a time is allowed to run a given
// sweeper at all, decided by a session-scoped Postgres advisory lock
// (pg_try_advisory_lock) held on a dedicated connection for as long as that
// replica keeps running it:
//
//   - The winner holds the lock (and the connection) until shutdown, so
//     nothing else on this hub's own pool contends for it and an unlock
//     can't race a Release.
//   - A replica that doesn't win releases its connection immediately and
//     retries after a short delay — it never holds a connection open just
//     to keep failing a lock check.
//   - If the winner is killed outright, Postgres drops its session the
//     moment the TCP connection dies, which releases every advisory lock
//     that connection held — so a losing replica's very next retry picks
//     the sweeper back up with no coordination beyond that.
//   - On a clean shutdown (ctx cancelled), fn only returns once its own
//     Run(ctx, ...) loop has already stopped selecting on ctx.Done(), so the
//     explicit unlock below is cleanup on the happy path, and the
//     connection close right after is what actually guarantees release if
//     that unlock itself fails.
func runExclusive(ctx context.Context, pool *pgxpool.Pool, lockKey int64, name string, fn func()) {
	const retryDelay = 3 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		conn, err := pool.Acquire(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Warn("sweeper lock: could not acquire a database connection; retrying",
				slog.String("sweeper", name), logging.Err(err))
			if !sleepOrDone(ctx, retryDelay) {
				return
			}
			continue
		}

		var got bool
		lockErr := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", lockKey).Scan(&got)
		if lockErr != nil || !got {
			conn.Release()
			if lockErr != nil && ctx.Err() == nil {
				logger.Warn("sweeper lock: could not attempt the lock; retrying",
					slog.String("sweeper", name), logging.Err(lockErr))
			}
			if !sleepOrDone(ctx, retryDelay) {
				return
			}
			continue
		}

		logger.Info("sweeper lock acquired; this replica now runs it", slog.String("sweeper", name))
		fn()

		// fn only returns once ctx is done, so reaching here is shutdown,
		// never a lost race.
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if _, err := conn.Exec(unlockCtx, "SELECT pg_advisory_unlock($1)", lockKey); err != nil {
			logger.Warn("sweeper lock: could not release cleanly (harmless: it releases when this connection closes)",
				slog.String("sweeper", name), logging.Err(err))
		}
		cancel()
		conn.Conn().Close(context.Background())
		// Closing the underlying connection does not hand it back: the pool
		// still counts it as acquired until Release, and pool.Close() — the
		// hub's deferred db.Close() — waits for every acquired connection.
		// Without this every shutdown hung after "shutdown complete" until
		// the kubelet killed the pod at its grace period, which delayed the
		// replacement hub (and every agent's reconnect) by about a minute.
		// Release of a closed connection destroys it rather than reusing it.
		conn.Release()
		return
	}
}

// sleepOrDone waits for d, returning false immediately (without waiting) if
// ctx ends first — the shared "retry, but stop retrying at shutdown" wait
// used by runExclusive's two backoff points.
func sleepOrDone(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// drainHub is PROJECT.md B162's SIGTERM path, in the order the phases have to
// happen. Each phase depends on the ones after it still being up, which is
// why the order is the load-bearing part and not the individual calls:
//
//  1. Readiness off, then a pause. /readyz answers 503 immediately, so the
//     endpoints controller takes this pod out of its Service BEFORE the
//     listener stops accepting; the pause is how long that propagation is
//     given. Without it, requests are still being routed here when the
//     listener closes and arrive as connection-refused rather than as a
//     graceful drain. Liveness stays green throughout — see
//     internal/api.handleHealthz.
//  2. HTTP drain. http.Server.Shutdown stops accepting and waits for
//     in-flight requests to finish. Bounded: a long investigation request
//     must not be able to outlast the pod's termination grace period, so
//     after the grace window the remaining connections are closed.
//  3. WebSocket drain. Shutdown does not wait for, and cannot close, a
//     HIJACKED connection — every /ws/events feed is one. They get a real
//     1001 "going away" close frame from their own goroutines instead
//     (internal/api/shutdown.go).
//  4. Workers. Cancelled only now, after the HTTP phase: an in-flight
//     request may have been using them.
//  5. The MCP listener and the agent tunnels, last and together. A sweeper
//     or an in-flight investigation needs its cluster's tunnel — and, under
//     the cli backend, the MCP listener it calls tools back through — right
//     up to the moment it stops.
//
// The database pool is closed after this returns, by runAPI's own deferred
// db.Close() — nothing above may still be querying by then.
func drainHub(d hubDrain) {
	readinessDelay := time.Duration(envOrInt("ARGUS_SHUTDOWN_READINESS_DELAY_SECONDS", 3)) * time.Second
	grace := time.Duration(envOrInt("ARGUS_SHUTDOWN_GRACE_SECONDS", int(api.DefaultShutdownGrace/time.Second))) * time.Second
	logger.Info("shutdown signal received — draining. deploy/helm/argus-hub must allow at least the total below of termination grace for this to complete",
		slog.Duration("readiness_delay", readinessDelay), slog.Duration("grace_per_phase", grace),
		slog.Duration("total_required", readinessDelay+2*grace+5*wsDrainGrace))

	// Phase 1.
	d.srv.BeginShutdown()
	if readinessDelay > 0 {
		logger.Info("shutdown: /readyz now answers 503; waiting for endpoint removal before the API listener stops accepting",
			slog.Duration("readiness_delay", readinessDelay))
		time.Sleep(readinessDelay)
	}

	// Phase 2.
	httpCtx, cancelHTTP := context.WithTimeout(context.Background(), grace)
	if err := d.httpSrv.Shutdown(httpCtx); err != nil {
		logger.Warn("shutdown: the HTTP API did not drain within its grace period; remaining connections were closed",
			slog.Duration("grace", grace), logging.Err(err))
	} else {
		logger.Info("shutdown: HTTP API drained")
	}
	cancelHTTP()

	// Phase 2b. Background investigations (PROJECT.md M1): POST
	// /incidents/{id}/analyze answers 202 and runs the investigation after
	// the request has finished, so the HTTP drain above no longer waits for
	// one. A short wait (an investigation takes minutes, so a long one would
	// only delay the rollout), then cancelled — each records on its incident
	// that the hub restarted before it finished, within one more short
	// window, rather than leaving it Investigating. Before the workers and
	// tunnels stop, which a running investigation still needs.
	analysisCtx, cancelAnalyses := context.WithTimeout(context.Background(), wsDrainGrace)
	if !d.srv.DrainAnalyses(analysisCtx, wsDrainGrace) {
		logger.Warn("shutdown: background investigations were still running; they were cancelled and marked as interrupted on their incidents")
	}
	cancelAnalyses()

	// Phase 3.
	wsCtx, cancelWS := context.WithTimeout(context.Background(), wsDrainGrace)
	open, drained := d.srv.DrainWebSockets(wsCtx)
	cancelWS()
	if open > 0 {
		logger.Info("shutdown: closed live WebSocket feeds", slog.Int("open", open), slog.Bool("all_finished", drained))
	}

	// Phase 4.
	d.stopWorkers()
	waitFor(d.workers, grace, "background workers")

	// Phase 5.
	if d.stopLateListeners != nil {
		d.stopLateListeners()
		waitFor(d.lateListeners, wsDrainGrace, "the MCP listener")
	}
	tunnelCtx, cancelTunnel := context.WithTimeout(context.Background(), wsDrainGrace)
	closed := d.gw.Shutdown(tunnelCtx)
	cancelTunnel()
	logger.Info("shutdown: tunnel listener closed; each disconnected agent reconnects with backoff",
		slog.Int("agent_connections_closed", closed))
	logger.Info("shutdown complete")
}

// waitFor waits for one phase's goroutines, bounded, and says which phase ran
// out of time rather than leaving an operator to infer it from what the log
// stopped saying.
func waitFor(wg *sync.WaitGroup, within time.Duration, what string) {
	if wg == nil {
		return
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	timer := time.NewTimer(within)
	defer timer.Stop()
	select {
	case <-done:
		logger.Info("shutdown: phase stopped", slog.String("phase", what))
	case <-timer.C:
		logger.Warn("shutdown: a phase did not all stop within its bound; exiting anyway",
			slog.String("phase", what), slog.Duration("within", within))
	}
}

// wsDrainGrace bounds phase 3 (and, reused, phase 5's brief settle) of
// drainHub. Short by design: a WebSocket close frame is one write on a
// connection whose own goroutine is already selecting for it, and an agent
// connection needs only to be closed — neither is work that can legitimately
// take as long as an in-flight HTTP request might.
const wsDrainGrace = 5 * time.Second

func requireEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		fatal("a required environment variable is not set", slog.String("env", name))
	}
	return v
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// envOrInt is envOr's integer-parsing sibling — used only for
// ARGUS_EMBEDDING_DIMS today. An unset/empty value falls back silently (the
// normal case); a SET-but-unparseable value logs and falls back rather than
// failing startup over what is, in every default configuration, an
// already-correct value nobody needed to touch.
func envOrInt(name string, fallback int) int {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		logger.Warn("environment variable is not a valid integer; using the default",
			slog.String("env", name), slog.String("value", v), slog.Int("default", fallback))
		return fallback
	}
	return n
}

func firstNonEmptyStr(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}

// severitiesOrNone renders auto-analysis's configured severity set for the
// startup log line above — a nil/empty slice means "nothing selected, so
// nothing is eligible for auto-analysis" (see
// internal/settings.Config's AutoAnalysisSeverities doc comment for the
// deliberate reasoning), the opposite of what a nil minSeverity used to mean
// under migration 000020's now-superseded single-threshold column, so this
// says so explicitly rather than rendering a possibly-misleading blank.
func severitiesOrNone(severities []string) string {
	if len(severities) == 0 {
		return "none selected — auto-analysis is enabled but will not analyze anything until at least one severity is checked"
	}
	return strings.Join(severities, ", ")
}

// envInt reads a positive integer env var, falling back to def.
func envInt(name string, def int) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		logger.Warn("ignoring an invalid integer setting; using the default", slog.String("env", name), slog.String("value", v))
		return def
	}
	return n
}

// chooseTunnelEndpoint decides the tunnel address handed to agents at
// enrollment. An explicit ARGUS_TUNNEL_PUBLIC_ENDPOINT (host:port, or a ws(s)
// URL) wins. Otherwise the tunnel runs over a WebSocket on the hub's public
// API URL, through the same Ingress as the UI, which is the default for a
// Helm install. With neither (a hub on a laptop), agents dial localhost:8443.
func chooseTunnelEndpoint(explicit, publicAPIURL string) (string, error) {
	if e := strings.TrimSpace(explicit); e != "" {
		return e, nil
	}
	if u := strings.TrimSpace(publicAPIURL); u != "" {
		return tunnel.WebSocketEndpoint(u)
	}
	return "localhost:8443", nil
}
