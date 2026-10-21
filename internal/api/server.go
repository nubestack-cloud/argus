// Package api implements the hub's public HTTP surface (lld/10-api-spec.md).
//
// This is a Phase 0 skeleton: health/readiness checks and the bootstrap flow are
// real and load-bearing; the full endpoint set from lld/10-api-spec.md §9 is not
// yet implemented. See STATUS.md §3 for what's next.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/events"
	"argus/internal/execution"
	"argus/internal/gateway"
	"argus/internal/idp"
	"argus/internal/knowledge"
	"argus/internal/llm"
	"argus/internal/logging"
	"argus/internal/render/sandbox"
	"argus/internal/repotools"
	"argus/internal/scm"
	"argus/internal/secretbox"
)

type Server struct {
	db                   *data.DB
	signer               *authz.TokenSigner
	enrollmentSigner     *authz.EnrollmentSigner
	ca                   *gateway.DevCA
	tunnelPublicEndpoint string
	// scmStore persists repository bindings and their envelope-encrypted
	// credentials (REMEDIATION_ROADMAP.md D-R9, migration 000045).
	scmStore *scm.Store
	// idpStore persists external identity providers, their group-to-role
	// mappings, and in-flight login state (PROJECT.md S2, migration 000103).
	// Shares scmStore's secretbox keeper, so an OIDC client secret is
	// envelope-encrypted by the same path a Git credential is.
	idpStore *idp.Store
	// ssoHandoff carries an authenticated identity across the one gap an OIDC
	// callback cannot: its response is a browser redirect, while this
	// application authenticates with bearer tokens held in JavaScript. In-
	// process state with no external dependency, like wsTickets, so it is
	// constructed here rather than threaded through NewServer.
	ssoHandoff *authz.SSOHandoffIssuer
	// oidcCache holds discovered OIDC providers so a login does not pay a
	// discovery round trip and a cold JWKS cache every time. Keyed by
	// (provider id, issuer, client id) so editing any of those invalidates
	// the entry rather than silently authenticating against the old issuer;
	// invalidateOIDCCache drops entries on a settings write.
	oidcMu    sync.Mutex
	oidcCache map[string]*idp.Provider
	// checkouts is the bounded cache of sparse, shallow, pinned repository
	// clones the investigation's read-only repo tools read from (BACKLOG.md
	// F22 piece 1). In-process state with no external dependency, like
	// wsTickets below, so it is constructed here rather than threaded through
	// NewServer — and one per hub, so several investigations against the same
	// repository and commit share one fetch.
	checkouts          *repotools.Checkouts
	planSigningRootKey []byte           // internal/remediation's root key for signing ScaleDeployment/RestartPod execution plans; internal/api/enroll.go derives a per-cluster key from this and hands out only that, never this root itself.
	llmProvider        llm.Investigator // always non-nil; resolves DB-backed/env-fallback config fresh per call (internal/settings) — see llm.ErrNotConfigured for the "no provider configured at all" case, which handlers must still handle explicitly
	// planCorrector is BACKLOG.md F12b's model-facing primitive
	// (internal/execution's PlanCorrectionModel). Held as a second field
	// rather than derived from llmProvider only because the two are typed
	// against two different narrow interfaces (llm.Investigator vs
	// planCorrectionModel's CorrectPlanParams) — cmd/hub/main.go wires both
	// fields to the literal same *llm.Router instance. Before BACKLOG.md
	// P13 this held the concrete *llm.Provider directly, because
	// CorrectPlanParams was defined on *Provider and llmProvider's static
	// type (llm.Investigator) exposed no Complete-style single-shot call for
	// it to use — which meant the retry loop's only working path was the
	// api backend, silently dead under a cli-kind provider (BUGS.md 125).
	// CorrectPlanParams now lives on *llm.Router and dispatches through
	// Router.Complete, so this works under either provider kind. May still
	// be nil (a test build, or — in principle — a future deployment that
	// wires no AI provider at all), in which case preparePlanWithCorrection's
	// correct() closure reports "no AI provider configured" and the retry
	// loop surfaces the ORIGINAL dry-run rejection unchanged, exactly as if
	// this feature did not exist.
	planCorrector execution.PlanCorrectionModel
	// executor is internal/execution's engine: everything that prepares,
	// rehearses, signs, dispatches, records or undoes a change to a customer's
	// cluster (PROJECT.md P23). Built in NewServer from the fields above, which
	// is why it is not a constructor parameter — it holds no state of its own,
	// only the same dependencies this Server already has.
	//
	// Nil on a bare &Server{} (this package's test convention); reach it
	// through s.exec(), never directly, so such a test still gets a working
	// engine built from whatever fields it did set.
	executor        *execution.Executor
	gw              *gateway.Gateway                   // always non-nil; handleAnalyzeIncident's tool-calling investigation loop (analyze.go) calls gw.CallTool/gw.IsConnected against a specific incident's cluster ID — the same Gateway cmd/hub/main.go starts the tunnel listener on, not a second instance
	wsTickets       *authz.WSTicketIssuer              // short-lived, single-use tickets for the GET /ws/events upgrade handshake — see ws.go's package comment for why. Purely in-process state, no external dependency, so it's constructed here rather than threaded through NewServer's parameter list.
	guardrailTokens *authz.GuardrailConfirmationIssuer // same in-process, single-use shape as wsTickets, for a different problem: proving a remediation guardrail refusal genuinely happened before honouring the operator's override (WORKLOG §97 G5). See internal/authz/guardrail_confirmation.go.
	loginRateLimit  *authz.LoginRateLimiter            // in-process per-(email,IP) failed-login throttle — BACKLOG.md G7, WORKLOG §106. See internal/authz/login_rate_limit.go.
	events          *events.Bus                        // in-memory fan-out for IncidentUpdated/ClusterUpdated (ws.go); does not survive a restart and doesn't span multiple hub instances — a known, deliberate limitation at this project's current single-hub-instance stage, not a bug.
	mux             *http.ServeMux
	// knowledge is BACKLOG.md L2's storage half (2026-08-30 decision):
	// handleAnalyzeIncident calls knowledge.TriggerAsync AFTER its own
	// transaction commits, to embed the just-persisted analysis in the
	// background. Nil-safe (see Store.TriggerAsync's own doc comment) — a
	// test Server built as a bare &Server{} struct literal (this package's
	// own convention, see any *_test.go) leaves this nil and simply never
	// embeds anything, which is correct for a handler test that has no
	// database and no Ollama to call.
	knowledge *knowledge.Store
	// renderSandbox is BACKLOG.md F26's render-and-diff mechanism —
	// internal/api/render_evidence.go's evaluateRenderEffect is the only
	// caller. Nil is the expected default and is NOT a misconfiguration: it
	// means "no render-sandbox cluster has been given to this hub", and
	// every caller of evaluateRenderEffect degrades to exactly the
	// unproven-but-honestly-labeled behaviour this whole hub had before F26
	// — a render step must never become a new way for a pull request to
	// fail to open. Points at infrastructure the HUB administers, never a
	// customer cluster and never reached through internal/gateway's tunnel —
	// see internal/render/sandbox's package comment for why mixing that
	// path with the read-only agent's connection would be a non-negotiable
	// #1 violation, not a convenience.
	renderSandbox *sandbox.Runner
	// linkDiscoveryCache is BACKLOG.md F30's own "bound the cost" instruction:
	// a chart render only ever happens when an incident actually needs a
	// repository link AND the operator opens the discovery panel, and the
	// SAME (binding, commit, chart path, values file) is never re-rendered
	// once this process has already rendered it once — a second incident on
	// the same release, or the same operator reloading the page, reuses the
	// cached object list. Keyed by objectmapping_discovery.go's own
	// renderCacheKey. Deliberately unbounded (a sync.Map, not an LRU): this
	// process's lifetime is short relative to how many distinct chart/values
	// combinations a fleet actually has, and the far more important bound —
	// never rendering on a timer, never rendering fleet-wide up front — is
	// the discovery function's own "only when asked" call pattern, not this
	// map's eviction policy.
	linkDiscoveryCache sync.Map
	// readLogs is BACKLOG.md F28 finding 1's registry, letting CallRepoTool
	// (below, reached from the cli backend's MCP server rather than from a
	// Go closure) record into the SAME repotools.ReadLog
	// handleAnalyzeIncident/internal/autoanalyze built for this investigation
	// — see repotools.ReadLogRegistry's own doc comment for why a registry
	// keyed by incident id, rather than a Reader-attached log the way the api
	// backend already works, is what closes F25's own documented gap ("the
	// cli backend's tool calls reach internal/api.CallRepoTool through a
	// fresh *repotools.Reader per MCP call with no ReadLog attached").
	//
	// Unlike checkouts above, this is injected via NewServer rather than
	// constructed here: internal/autoanalyze.Poller needs the IDENTICAL
	// instance (CallRepoTool is only ever reached through this one *Server,
	// regardless of which caller started the investigation), so cmd/hub/main.go
	// builds one and passes it to both constructors — the same "shared,
	// constructed once outside either" treatment it already gives
	// internal/events.Bus, for the same reason.
	//
	// Nil-safe throughout (ReadLogRegistry's own methods tolerate a nil
	// receiver), so every existing test building a bare &Server{} is
	// unaffected — Begin/Get/End on a nil registry behave exactly like the
	// pre-F28 code that called repotools.NewReadLog() directly: correct,
	// just unshared.
	readLogs *repotools.ReadLogRegistry

	// demoDataEnabled gates whether POST/DELETE /api/v1/demo-data are
	// registered at all (PROJECT.md D14). False on every real deployment and
	// on every &Server{} a test builds; the dev compose stack sets
	// ARGUS_ENABLE_DEMO_DATA so web/e2e can still seed its fixture.
	demoDataEnabled bool

	// PROJECT.md B162's graceful-shutdown state — see shutdown.go for what
	// each of these is for and why the WebSocket drain cannot be done by
	// http.Server.Shutdown. All four are zero-value-safe, so a bare
	// &Server{} (this package's test convention) behaves exactly as it did
	// before: never shutting down, no drain channel, nothing registered.
	shuttingDown atomic.Bool
	wsDrain      chan struct{} // closed by DrainWebSockets; nil on a bare &Server{}, and a nil channel in a select blocks forever, which is the correct "never drains" behaviour there
	wsDrainOnce  sync.Once
	wsActive     sync.WaitGroup
	wsOpen       atomic.Int64 // live /ws/events connections, for the drain's log line only

	// analysisRuns is the lifetime context and wait group POST
	// /incidents/{id}/analyze's background investigations run under
	// (PROJECT.md M1, analyze_run.go). Zero-value-safe like the four above.
	analysisRuns analysisRuns
}

// cliBackendReporter is implemented by internal/llm.Router. Kept as a narrow,
// optional interface rather than widened into llm.Investigator so every test
// fake does not have to grow a method it has no opinion about.
type cliBackendReporter interface{ CLIBackendAvailable() bool }

// cliBackendAvailable reports whether this hub can serve a `cli` AI provider —
// it needs an MCP listener, which is off unless ARGUS_MCP_ADDR is set.
//
// Defaults to false when the investigator cannot answer. That is the safe
// direction: the field drives a warning, so an unknown reads as "warn" rather
// than as silence about a real misconfiguration.
func (s *Server) cliBackendAvailable() bool {
	r, ok := s.llmProvider.(cliBackendReporter)
	return ok && r.CLIBackendAvailable()
}

// planCorrector is passed separately from llmProvider (rather than derived
// from it) because the two are typed against different interfaces
// (llm.Investigator has no CorrectPlanParams method to satisfy
// planCorrectionModel with) — see the Server field's own doc comment for
// why cmd/hub/main.go in fact wires both to the same *llm.Router. May be
// nil; see the Server field's own doc comment for what that degrades to.
// demoDataEnabled is deliberately the LAST parameter and a plain bool rather
// than something read from the environment in here: internal/api reads no
// environment variables at all (config arrives from cmd/hub), and keeping it
// that way means a test or a future caller cannot switch demo data on by
// accident through an ambient variable.
func NewServer(db *data.DB, signer *authz.TokenSigner, enrollmentSigner *authz.EnrollmentSigner, ca *gateway.DevCA, tunnelPublicEndpoint string, llmProvider llm.Investigator, planCorrector execution.PlanCorrectionModel, gw *gateway.Gateway, bus *events.Bus, planSigningRootKey []byte, secretKeeper *secretbox.Keeper, knowledgeStore *knowledge.Store, renderSandbox *sandbox.Runner, readLogs *repotools.ReadLogRegistry, demoDataEnabled bool) *Server {
	s := &Server{
		demoDataEnabled:      demoDataEnabled,
		db:                   db,
		signer:               signer,
		enrollmentSigner:     enrollmentSigner,
		ca:                   ca,
		tunnelPublicEndpoint: tunnelPublicEndpoint,
		planSigningRootKey:   planSigningRootKey,
		scmStore:             scm.NewStore(secretKeeper),
		checkouts:            repotools.NewCheckouts(),
		llmProvider:          llmProvider,
		planCorrector:        planCorrector,
		gw:                   gw,
		idpStore:             idp.NewStore(secretKeeper),
		ssoHandoff:           authz.NewSSOHandoffIssuer(),
		oidcCache:            make(map[string]*idp.Provider),
		wsTickets:            authz.NewWSTicketIssuer(),
		guardrailTokens:      authz.NewGuardrailConfirmationIssuer(),
		loginRateLimit:       authz.NewLoginRateLimiter(),
		events:               bus, // the SAME *events.Bus cmd/hub/main.go passes to gateway.NewGateway — not a second, empty one; see that call site's comment.
		mux:                  http.NewServeMux(),
		knowledge:            knowledgeStore,
		renderSandbox:        renderSandbox,
		readLogs:             readLogs,            // BACKLOG.md F28 finding 1 — the SAME instance cmd/hub/main.go passes to autoanalyze.New, not a second, empty one; see the field's own doc comment.
		wsDrain:              make(chan struct{}), // PROJECT.md B162 — see shutdown.go. Only a real, serving hub needs it; a bare &Server{} leaves it nil and never drains.
	}
	s.executor = s.newExecutor()
	s.routes()
	// Logged once, here, at actual hub startup (not lazily on the first
	// scrape), so an operator whose hub has no ARGUS_METRICS_TOKEN learns
	// that GET /metrics is disabled from this log line rather than from a
	// 503 their scraper reports later. See internal/api/metrics.go's own
	// doc comment for the full reasoning.
	LogMetricsAuthMode()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /readyz", s.handleReadyz)
	// Not gated behind requireAuth like every route below: a Prometheus
	// scrape has no session to authenticate that way, and threading it
	// through the capability model would be the wrong shape for it, not
	// just unneeded. It is NOT unauthenticated, though — handleMetrics
	// carries its own MANDATORY bearer-token check against
	// ARGUS_METRICS_TOKEN, and with no token configured it serves 503
	// rather than falling back to serving openly. Registered
	// unconditionally on purpose: a disabled endpoint that answers 503 with
	// a problem body naming the missing variable is diagnosable, where an
	// unregistered one answering 404 reads as a routing bug. See
	// internal/api/metrics.go's doc comment.
	s.mux.HandleFunc("GET /metrics", s.handleMetrics)

	// Unauthenticated by necessity — there's no session yet to require. Every
	// other route below is wrapped with requireAuth, which is this codebase's
	// current stand-in for lld/02-authz-spec.md §10.1's "every route declares a
	// required capability, or it fails to register" rule — not yet enforced at
	// compile time or by lint, so reviewers must check this file directly when a
	// new route is added. See STATUS.md §3.
	s.mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/v1/auth/refresh", s.handleRefresh)
	// Unauthenticated by necessity, exactly like login/refresh above — see
	// handleLogout's doc comment for why (PROJECT.md B164).
	s.mux.HandleFunc("POST /api/v1/auth/logout", s.handleLogout)
	// Federated login (PROJECT.md S2). All four are deliberately
	// UNAUTHENTICATED — they are how somebody becomes authenticated — so each
	// resolves its tenant from data.SingleOrganisationID rather than from the
	// request. See auth_oidc.go's package comment for the flow and for why the
	// callback and the exchange are two endpoints.
	s.mux.HandleFunc("GET /api/v1/auth/sso/providers", s.handleSSOProviders)
	s.mux.HandleFunc("GET /api/v1/auth/sso/start", s.handleSSOStart)
	s.mux.HandleFunc("GET /api/v1/auth/sso/callback", s.handleSSOCallback)
	s.mux.HandleFunc("POST /api/v1/auth/sso/exchange", s.handleSSOExchange)

	// The one source of truth for "who am I" on every sign-in path —
	// password, federated, and a session restored from a refresh token
	// (PROJECT.md B165). No capability check; see handleMe's doc comment for
	// why, and for why the identity is not returned by the sign-in responses
	// instead.
	s.mux.HandleFunc("GET /api/v1/users/me",
		s.requireAuth(s.handleMe))
	s.mux.HandleFunc("GET /api/v1/users/me/effective-permissions",
		s.requireAuth(s.handleEffectivePermissions))
	// No capability check, same as the route above — authenticated as
	// yourself is always enough to change your own password
	// (internal/api/auth.go's handleChangePassword).
	s.mux.HandleFunc("PUT /api/v1/users/me/password",
		s.requireAuth(s.handleChangePassword))

	// Builtin-role reference (internal/api/roles.go) — backs SettingsPage's
	// "Roles" tab. GET only, no specific capability required; see that
	// file's doc comment for why (same "this isn't sensitive" reasoning as
	// effective-permissions immediately above).
	s.mux.HandleFunc("GET /api/v1/roles",
		s.requireAuth(s.handleListRoles))

	s.mux.HandleFunc("POST /api/v1/clusters/enrollment-tokens",
		s.requireAuth(s.requireCapability(authz.CapClusterOnboard, s.handleCreateEnrollmentToken)))
	s.mux.HandleFunc("GET /api/v1/clusters/fleet-tokens",
		s.requireAuth(s.requireCapability(authz.CapClusterOnboard, s.handleListFleetTokens)))
	s.mux.HandleFunc("DELETE /api/v1/clusters/fleet-tokens/{id}",
		s.requireAuth(s.requireCapability(authz.CapClusterOnboard, s.handleRevokeFleetToken)))

	// Enroll/EnrollStatus are unauthenticated by necessity, like the routes
	// above — the caller is an agent presenting a bearer enrollment token (or,
	// for EnrollStatus, a poll token), not a user with a session. See this
	// file's routes and lld/03-agent-protocol.md's addendum for why these are
	// plain REST rather than RPC at this stage: the agent has no client cert
	// yet at enroll time, so there's nothing to authenticate a tunnel-style
	// connection with.
	s.mux.HandleFunc("POST /api/v1/clusters/enroll", s.handleEnroll)
	s.mux.HandleFunc("GET /api/v1/clusters/enroll/status", s.handleEnrollStatus)
	// The agent tunnel over a WebSocket (agent_tunnel.go; the path is
	// tunnel.WebSocketPath, which a test pins), authenticated by
	// the mTLS session inside it rather than by anything HTTP carries.
	s.mux.HandleFunc("GET /api/v1/agent/tunnel", s.handleAgentTunnel)

	s.mux.HandleFunc("POST /api/v1/clusters/{id}/accept",
		s.requireAuth(s.requireCapability(authz.CapClusterAccept, s.handleAcceptCluster)))
	s.mux.HandleFunc("POST /api/v1/clusters/{id}/rename",
		s.requireAuth(s.requireCapability(authz.CapClusterOnboard, s.handleRenameCluster)))
	s.mux.HandleFunc("POST /api/v1/clusters/{id}/decommission",
		s.requireAuth(s.requireCapability(authz.CapClusterDelete, s.handleDecommissionCluster)))
	s.mux.HandleFunc("GET /api/v1/clusters",
		s.requireAuth(s.requireCapability(authz.CapClusterRead, s.handleListClusters)))
	s.mux.HandleFunc("GET /api/v1/clusters/{id}",
		s.requireAuth(s.requireCapability(authz.CapClusterRead, s.handleGetCluster)))
	// docs/CLUSTER_INSIGHT_SPECS.md CI-S6: one allowlisted read-only agent
	// tool per call, scoped to the cluster in the path (cluster_inspect.go).
	s.mux.HandleFunc("POST /api/v1/clusters/{id}/inspect/{tool}",
		s.requireAuth(s.requireCapability(authz.CapClusterInspect, s.handleClusterInspect)))
	// PROJECT.md AD7: the object panel's Metrics tab (incident_metrics.go).
	s.mux.HandleFunc("GET /api/v1/clusters/{id}/workload-metrics",
		s.requireAuth(s.requireCapability(authz.CapClusterInspect, s.handleWorkloadMetrics)))
	// docs/CLUSTER_INSIGHT_SPECS.md CI-S2 (resource_changes.go).
	s.mux.HandleFunc("GET /api/v1/clusters/{id}/resource-changes",
		s.requireAuth(s.requireCapability(authz.CapClusterRead, s.handleListResourceChanges)))
	s.mux.HandleFunc("GET /api/v1/incidents/{id}/preceding-changes",
		s.requireAuth(s.requireCapability(authz.CapIncidentRead, s.handleIncidentPrecedingChanges)))
	// PROJECT.md AD1 (cluster_timeline.go): changes, findings and incidents on
	// one time axis; findings/incidents additionally need incident:read.
	s.mux.HandleFunc("GET /api/v1/clusters/{id}/timeline",
		s.requireAuth(s.requireCapability(authz.CapClusterRead, s.handleClusterTimeline)))
	// CI-S5 (upgrade_scans.go).
	s.mux.HandleFunc("GET /api/v1/clusters/{id}/upgrade-scans/latest",
		s.requireAuth(s.requireCapability(authz.CapClusterRead, s.handleLatestUpgradeScan)))
	s.mux.HandleFunc("POST /api/v1/clusters/{id}/upgrade-scans",
		s.requireAuth(s.requireCapability(authz.CapClusterRead, s.handleRunUpgradeScan)))
	s.mux.HandleFunc("GET /api/v1/upgrade-scans/latest",
		s.requireAuth(s.requireCapability(authz.CapClusterRead, s.handleFleetUpgradeScans)))
	// The Overview's fleet aggregate (fleet_summary.go): every visible
	// cluster's facts digest and stored checks; check data only where the
	// viewer holds cluster:inspect on that cluster, checked inside.
	s.mux.HandleFunc("GET /api/v1/fleet/summary",
		s.requireAuth(s.requireCapability(authz.CapClusterRead, s.handleFleetSummary)))
	// CI-S12 (search.go): per-cluster cluster:inspect is checked inside.
	s.mux.HandleFunc("GET /api/v1/search",
		s.requireAuth(s.requireCapability(authz.CapClusterInspect, s.handleSearch)))
	// CI-S8 (incident_metrics.go).
	s.mux.HandleFunc("GET /api/v1/incidents/{id}/metrics",
		s.requireAuth(s.requireCapability(authz.CapIncidentRead, s.handleIncidentMetrics)))
	// CI-S15 (quick_actions.go): per-cluster in-place capability checked inside.
	// PROJECT.md PG19 (applications.go): per-cluster cluster:read checked inside.
	s.mux.HandleFunc("GET /api/v1/applications",
		s.requireAuth(s.requireCapability(authz.CapClusterRead, s.handleListApplications)))
	// PROJECT.md PG8 (rightsizing.go): per-cluster in-place capability checked inside.
	s.mux.HandleFunc("POST /api/v1/clusters/{id}/rightsizing/proposals",
		s.requireAuth(s.requireCapability(authz.CapRemediationExecInplace, s.handleRightsizingProposal)))
	// PROJECT.md AD10 (agent_upgrade.go): per-cluster capability checked inside.
	s.mux.HandleFunc("POST /api/v1/clusters/{id}/agent-upgrade",
		s.requireAuth(s.requireCapability(authz.CapAgentUpgrade, s.handleAgentUpgrade)))
	s.mux.HandleFunc("POST /api/v1/incidents/{id}/quick-actions",
		s.requireAuth(s.requireCapability(authz.CapRemediationExecInplace, s.handleIncidentQuickAction)))

	s.mux.HandleFunc("GET /api/v1/incidents",
		s.requireAuth(s.requireCapability(authz.CapIncidentRead, s.handleListIncidents)))
	// BACKLOG.md T2: the same incidents, grouped by fingerprint — see
	// incident_digest.go's own header comment. A literal path segment
	// ("digest") is more specific than "/incidents/{id}"'s wildcard at the
	// same position, so Go 1.22's ServeMux routes this here regardless of
	// registration order; still registered first, next to the endpoint it
	// mirrors, for a reader's sake rather than the router's.
	s.mux.HandleFunc("GET /api/v1/incidents/digest",
		s.requireAuth(s.requireCapability(authz.CapIncidentRead, s.handleListIncidentsDigest)))
	// The fleet Overview's whole-set incident aggregates (incident_overview.go).
	// Literal segment, so it wins over "/incidents/{id}" the same way "digest" does.
	s.mux.HandleFunc("GET /api/v1/incidents/overview",
		s.requireAuth(s.requireCapability(authz.CapIncidentRead, s.handleIncidentOverview)))
	s.mux.HandleFunc("GET /api/v1/incidents/{id}",
		s.requireAuth(s.requireCapability(authz.CapIncidentRead, s.handleGetIncident)))
	// BACKLOG.md B2, lld/11-ui-design.md §4: one tool call's full evidence,
	// fetched lazily rather than bundled into GET /incidents/{id}'s response.
	// Same capability as that route, deliberately — see handleGetEvidence's
	// own doc comment for why a second, stricter gate here would be
	// pointless (evidence.go).
	s.mux.HandleFunc("GET /api/v1/incidents/{id}/evidence/{evId}",
		s.requireAuth(s.requireCapability(authz.CapIncidentRead, s.handleGetEvidence)))
	// BACKLOG.md B1, lld/11-ui-design.md §4: the chronology of what ARGUS did
	// and when, for this one incident — question 4 of the four questions
	// GET /incidents/{id} already answers 1-3 of. Same capability as reading
	// the incident itself, for the same reason as the evidence route just
	// above: no scenario where someone can read an incident but should not
	// see its own history.
	s.mux.HandleFunc("GET /api/v1/incidents/{id}/timeline",
		s.requireAuth(s.requireCapability(authz.CapIncidentRead, s.handleGetIncidentTimeline)))
	s.mux.HandleFunc("POST /api/v1/incidents/{id}/analyze",
		s.requireAuth(s.requireCapability(authz.CapIncidentReanalyse, s.handleAnalyzeIncident)))

	// PROJECT.md F31: the findings surface — fleet-wide, with each finding's
	// evidence dimensions, its disposition, and the promotion rule that
	// decided it. Registered beside the incident list because it is the other
	// half of the same question: /incidents is what ARGUS raised, /findings is
	// everything it saw, including what it deliberately did not raise.
	//
	// Gated on the same incident:read as the incident list rather than a new
	// finding:read — a finding is the evidence an incident is made of, and
	// GET /incidents/{id} already returns findings under this capability. See
	// handleListFindings' own doc comment (findings.go).
	s.mux.HandleFunc("GET /api/v1/findings",
		s.requireAuth(s.requireCapability(authz.CapIncidentRead, s.handleListFindings)))

	// Approval queue (internal/api/approvals.go) — the first real UI/API
	// consumer of internal/remediation's plan/gate and
	// internal/orchestrator's state-machine wiring. GET is gated by the
	// SAME capability as the write actions below, deliberately — see that
	// file's own doc comment for why, matching org:settings:write's
	// established precedent just above.
	s.mux.HandleFunc("GET /api/v1/approvals",
		s.requireAuth(s.requireCapability(authz.CapRemediationApprove, s.handleListApprovals)))
	// remediation:approve is the FLOOR for the approve route, not the whole
	// check: approving a ScaleDeployment/RestartPod plan really does patch the
	// customer's cluster (internal/execution), so handleApproveIncident
	// additionally requires remediation:execute:inplace or
	// remediation:execute:pr depending on the approved plan's own action type.
	// That check can't live here — one route handles all three action types and
	// the required capability is a property of the plan, not the route. See
	// approvals.go's planApprovalGates for the full reasoning.
	s.mux.HandleFunc("POST /api/v1/incidents/{id}/approve",
		s.requireAuth(s.requireCapability(authz.CapRemediationApprove, s.handleApproveIncident)))
	s.mux.HandleFunc("POST /api/v1/incidents/{id}/reject",
		s.requireAuth(s.requireCapability(authz.CapRemediationReject, s.handleRejectIncident)))
	// Preview: rehearse a pending plan against the cluster and return the diff
	// the API server itself says would result (internal/api/preflight.go).
	// Same capability floor as approve, and the same per-action gate inside the
	// handler, for the reason given there: a preview makes ARGUS send a
	// dry-run patch, so it must not be available to a wider audience than the
	// approval it informs. POST because it is not free — see the handler.
	s.mux.HandleFunc("POST /api/v1/incidents/{id}/preflight",
		s.requireAuth(s.requireCapability(authz.CapRemediationApprove, s.handlePreflightIncident)))

	// Repository bindings: which Git repositories ARGUS may open a pull request
	// against, and the envelope-encrypted credential it uses
	// (internal/api/repositories.go, REMEDIATION_ROADMAP.md D-R9). repo:read and
	// repo:write have been in the capability catalogue since the beginning with
	// nothing behind them; this is what they now gate.
	s.mux.HandleFunc("GET /api/v1/repositories",
		s.requireAuth(s.requireCapability(authz.CapRepoRead, s.handleListRepositoryBindings)))
	s.mux.HandleFunc("POST /api/v1/repositories",
		s.requireAuth(s.requireCapability(authz.CapRepoWrite, s.handleCreateRepositoryBinding)))
	// A genuine partial update (url/apiBaseUrl/defaultBranch/objectMappings/
	// token, each independently optional) — see handleUpdateRepositoryBinding's
	// own doc comment for why the create path's rotate-by-repeating-the-URL
	// trick isn't enough on its own.
	s.mux.HandleFunc("PUT /api/v1/repositories/{id}",
		s.requireAuth(s.requireCapability(authz.CapRepoWrite, s.handleUpdateRepositoryBinding)))
	s.mux.HandleFunc("DELETE /api/v1/repositories/{id}",
		s.requireAuth(s.requireCapability(authz.CapRepoWrite, s.handleDeleteRepositoryBinding)))
	// Proves the credential works NOW, rather than letting an incident be the
	// first thing to discover it does not.
	s.mux.HandleFunc("POST /api/v1/repositories/{id}/check",
		s.requireAuth(s.requireCapability(authz.CapRepoWrite, s.handleCheckRepositoryBinding)))

	// The pull-request remediation channel (internal/api/repository_change.go).
	// A repository change is one or more WHOLE FILES; the single-field routes
	// and their free-form siblings were collapsed into these three on
	// 2026-08-28, when the field grammar was removed (internal/gitops/files.go).
	//
	// Three capabilities on every one of them, all at the route because there
	// is one action type here and the required set is therefore a property of
	// the route rather than of a stored plan (unlike POST .../approve, whose
	// per-action gate must live in the handler):
	//   - repo:write — it commits to a registered repository.
	//   - remediation:approve — it authorises a remediation, like every other
	//     route that does.
	//   - remediation:execute:pr — the PR channel's own execution capability,
	//     the same one approvals.go's planApprovalGates maps ActionOpenPR to.
	//     lld/02-authz-spec.md §6's headline grant, "may approve PRs but never
	//     touch a cluster in place", only stays meaningful if the route that
	//     actually opens a PR checks it.
	//
	// The read route carries them too, even though it writes nothing: it
	// returns real repository content, and handing that to a wider audience
	// than the people who may open the pull request would be a new exposure for
	// no gain. All three are re-checked PER CLUSTER inside
	// resolveRepoChangeTarget, which is the only place that knows which cluster
	// the incident belongs to (BACKLOG S1).
	//
	// Nested requireCapability, the pattern GET /insights established.
	s.mux.HandleFunc("GET /api/v1/incidents/{id}/repository-change/file",
		s.requireAuth(s.requireCapability(authz.CapRepoWrite,
			s.requireCapability(authz.CapRemediationApprove,
				s.requireCapability(authz.CapRemediationExecPR, s.handleGetRepositoryChangeFile)))))
	s.mux.HandleFunc("POST /api/v1/incidents/{id}/repository-change/preview",
		s.requireAuth(s.requireCapability(authz.CapRepoWrite,
			s.requireCapability(authz.CapRemediationApprove,
				s.requireCapability(authz.CapRemediationExecPR, s.handlePreviewRepositoryChange)))))
	s.mux.HandleFunc("POST /api/v1/incidents/{id}/repository-change",
		s.requireAuth(s.requireCapability(authz.CapRepoWrite,
			s.requireCapability(authz.CapRemediationApprove,
				s.requireCapability(authz.CapRemediationExecPR, s.handleOpenRepositoryChange)))))

	// Maintenance and freeze windows (internal/api/windows.go) — BACKLOG.md R2.
	// org:settings:write, the same capability as the autonomy policy these
	// constrain: whoever decides what may be auto-approved is who should decide
	// when. See windows.go for why this is deliberately not a new capability.
	s.mux.HandleFunc("GET /api/v1/admin/automation-windows",
		s.requireAuth(s.requireCapability(authz.CapOrgSettingsWrite, s.handleListAutomationWindows)))
	s.mux.HandleFunc("POST /api/v1/admin/automation-windows",
		s.requireAuth(s.requireCapability(authz.CapOrgSettingsWrite, s.handleCreateAutomationWindow)))
	s.mux.HandleFunc("DELETE /api/v1/admin/automation-windows/{id}",
		s.requireAuth(s.requireCapability(authz.CapOrgSettingsWrite, s.handleDeleteAutomationWindow)))

	// The circuit breaker (BACKLOG R2's second half). Same capability as the
	// windows above: whoever decides what may be auto-approved and when is who
	// should decide that it may resume after a trip.
	s.mux.HandleFunc("GET /api/v1/admin/circuit-breaker",
		s.requireAuth(s.requireCapability(authz.CapOrgSettingsWrite, s.handleGetBreaker)))
	// BACKLOG.md R5: the threshold-configuration half GET could always read
	// but nothing could ever write. Same capability as GET/reset above.
	s.mux.HandleFunc("PUT /api/v1/admin/circuit-breaker",
		s.requireAuth(s.requireCapability(authz.CapOrgSettingsWrite, s.handlePutBreaker)))
	s.mux.HandleFunc("POST /api/v1/admin/circuit-breaker/{id}/reset",
		s.requireAuth(s.requireCapability(authz.CapOrgSettingsWrite, s.handleResetBreaker)))

	// Undo one execution (internal/api/rollback.go) — BACKLOG.md R1. Two
	// capabilities at the route:
	//   - remediation:rollback — its own decision, and the capability that has been
	//     in the catalogue since the first authz pass with nothing behind it.
	//   - remediation:execute:inplace — this writes to a live cluster, and that is
	//     the capability naming that channel. lld/02-authz-spec.md §6's "may
	//     approve PRs but never touch a cluster in place" grant must not reach an
	//     undo either, or the restriction is only true of the forward direction.
	s.mux.HandleFunc("POST /api/v1/executions/{id}/rollback",
		s.requireAuth(s.requireCapability(authz.CapRemediationRollback,
			s.requireCapability(authz.CapRemediationExecInplace, s.handleRollbackExecution))))

	// The front door for the undo above (internal/api/changes.go): every change
	// ARGUS has made recently, across every incident, with each row carrying the
	// rollback path's OWN answer to "can this be undone". Until this existed the
	// undo was only reachable by someone who already knew which incident made
	// the change, which is not how "something changed production on Tuesday"
	// starts. Gated on incident:read AND analysis:read — exposure parity with
	// GET /incidents/{id}, which already serves every field on an in-place row
	// here; see changes.go's header for why that is the right pair rather than
	// remediation:approve.
	s.mux.HandleFunc("GET /api/v1/changes",
		s.requireAuth(s.requireCapability(authz.CapIncidentRead,
			s.requireCapability(authz.CapAnalysisRead, s.handleListChanges))))

	// Human incident close-out (internal/api/incident_triage.go). Distinct from
	// approve/reject above, which decide the fate of a proposed PLAN: these
	// decide the fate of the INCIDENT, and apply to the majority of incidents
	// that never produce a plan at all. Before these existed the only exits
	// from the open set were along the remediation path, so an operator who
	// fixed something by hand could never close its incident.
	s.mux.HandleFunc("POST /api/v1/incidents/{id}/resolve",
		s.requireAuth(s.requireCapability(authz.CapIncidentTriage, s.handleResolveIncident)))
	s.mux.HandleFunc("POST /api/v1/incidents/{id}/dismiss",
		s.requireAuth(s.requireCapability(authz.CapIncidentTriage, s.handleDismissIncident)))

	// The same close-out decision, made once for a set instead of one at a
	// time (internal/api/incident_promotion_reconcile.go): close the open
	// incidents whose entire finding history is one the current evidence
	// boundary would no longer promote. Same capability as dismiss on
	// purpose — it is the identical authority at a different throughput, not
	// a new one — and a dry run unless the body says {"apply": true}.
	// Registered on the collection rather than under /admin because the
	// capability that gates it is an incident capability; the two should
	// agree about what this is.
	s.mux.HandleFunc("POST /api/v1/incidents/reconcile-promotion",
		s.requireAuth(s.requireCapability(authz.CapIncidentTriage, s.handleReconcilePromotion)))

	// BACKLOG.md F30 piece 3 (objectmapping_link_endpoints.go): "ask once,
	// where the problem is met" — discover/prove a repository link for a
	// blocked Helm-managed incident, confirm one, or decline (never asked
	// again for the same cluster/release/namespace). Discover is repo:read
	// (it only renders in the sandbox, never writes); confirm/decline are
	// repo:write, the same capability RepositoriesCard's own editor already
	// requires for a repository_bindings write.
	s.mux.HandleFunc("POST /api/v1/incidents/{id}/discover-repository-link",
		s.requireAuth(s.requireCapability(authz.CapRepoRead, s.handleDiscoverRepositoryLink)))
	s.mux.HandleFunc("POST /api/v1/incidents/{id}/confirm-repository-link",
		s.requireAuth(s.requireCapability(authz.CapRepoWrite, s.handleConfirmRepositoryLink)))
	s.mux.HandleFunc("POST /api/v1/incidents/{id}/decline-repository-link",
		s.requireAuth(s.requireCapability(authz.CapRepoWrite, s.handleDeclineRepositoryLink)))

	// Tolerations (internal/api/tolerations.go) — the incident:silence "mute
	// switch" BACKLOG.md's A5 entry designed: suppress future new-incident
	// creation for one object rather than closing occurrences one at a time.
	s.mux.HandleFunc("POST /api/v1/incidents/{id}/tolerate",
		s.requireAuth(s.requireCapability(authz.CapIncidentSilence, s.handleTolerateIncident)))
	s.mux.HandleFunc("GET /api/v1/tolerations",
		s.requireAuth(s.requireCapability(authz.CapIncidentSilence, s.handleListTolerations)))
	// The expandable detail behind a toleration row: the incident it was
	// created from (with that incident's analysis and proposed remediation),
	// plus which findings this rule has actually suppressed. Same capability
	// as listing the rules — if you can see a rule you can see why it exists
	// and what it silences. Registered under the collection item path rather
	// than a /suppressed sub-path, because it is now the full read of one
	// rule, the same way GET /incidents/{id} is of one incident.
	s.mux.HandleFunc("GET /api/v1/tolerations/{id}",
		s.requireAuth(s.requireCapability(authz.CapIncidentSilence, s.handleGetToleration)))
	s.mux.HandleFunc("DELETE /api/v1/tolerations/{id}",
		s.requireAuth(s.requireCapability(authz.CapIncidentSilence, s.handleRemoveToleration)))

	// Insights (internal/api/insights.go) — read-only, fleet-wide aggregate
	// reporting over incidents/findings/analyses. Gated on BOTH
	// incident:read and analysis:read (nested requireCapability) since the
	// response genuinely reads both capabilities' tables — see insights.go's
	// own header comment for the full reasoning, including why this isn't
	// narrowed to any per-cluster scope (nothing in this codebase resolves
	// per-cluster grant scope yet, for any route).
	s.mux.HandleFunc("GET /api/v1/insights",
		s.requireAuth(s.requireCapability(authz.CapIncidentRead, s.requireCapability(authz.CapAnalysisRead, s.handleGetInsights))))

	// BACKLOG.md L4's remediation-recommendation-derived Insights analytics
	// (internal/api/insights_remediation.go) — "recommendations frequently
	// rejected" and "automation candidates." A separate route from GET
	// /api/v1/insights above with a DIFFERENT, narrower capability:
	// remediation:approve, the same one GET /api/v1/approvals already gates
	// read access to remediation_recommendations/remediation_approval_decisions
	// behind. A "viewer" role holds incident:read + analysis:read but not
	// remediation:approve (authz/permissions.go's builtinRoleCapabilities),
	// so this could not simply be two more fields on the response above
	// without widening who can see approval/rejection history — see that
	// file's own header comment for the full reasoning.
	s.mux.HandleFunc("GET /api/v1/insights/remediation-quality",
		s.requireAuth(s.requireCapability(authz.CapRemediationApprove, s.handleGetInsightsRemediationQuality)))

	// spend.go — real-time daily-spend/ceiling reporting, gated on
	// spend:read alone (deliberately narrower than org:settings:write below,
	// which gates the "cost" section that actually CONFIGURES pricing/the
	// ceiling): a resolver holds spend:read but not org:settings:write
	// (authz/permissions.go's builtinRoleCapabilities), so this is the
	// first real use anywhere in this codebase of a capability that's been
	// declared in the catalogue since the first authz pass but never
	// implemented by anything until now.
	s.mux.HandleFunc("GET /api/v1/spend/today",
		s.requireAuth(s.requireCapability(authz.CapSpendRead, s.handleGetSpendToday)))

	// org:settings:write gates BOTH read and write here — there's no
	// separate read capability in the catalogue, and settings.go's own doc
	// comment explains why that's the correct minimal choice for this
	// particular pair of routes, not an oversight. Deliberately
	// super-admin-only (authz/permissions.go's builtinRoleCapabilities
	// excludes it from tenant-admin) — see internal/api/settings.go.
	s.mux.HandleFunc("GET /api/v1/admin/settings",
		s.requireAuth(s.requireCapability(authz.CapOrgSettingsWrite, s.handleGetSettings)))
	s.mux.HandleFunc("PUT /api/v1/admin/settings",
		s.requireAuth(s.requireCapability(authz.CapOrgSettingsWrite, s.handlePutSettings)))

	// Notification routing (internal/api/notification_routing.go, PROJECT.md
	// F32) — which destination a notification goes to, by cluster group,
	// severity and transition. Same capability as /admin/settings, and for the
	// same reason: the single webhook URL these rules route around is already
	// behind CapOrgSettingsWrite, so a separate capability would let someone
	// repoint every notification in the fleet without being trusted to change
	// the one URL they are a generalisation of.
	s.mux.HandleFunc("GET /api/v1/admin/notification-routing",
		s.requireAuth(s.requireCapability(authz.CapOrgSettingsWrite, s.handleGetNotificationRouting)))
	s.mux.HandleFunc("PUT /api/v1/admin/notification-routing",
		s.requireAuth(s.requireCapability(authz.CapOrgSettingsWrite, s.handlePutNotificationRouting)))

	// AI providers (internal/api/ai_providers.go) — the management surface for
	// several configured providers, of which one is active. GET/PUT
	// /admin/settings' own "llm" section still works and now means "edit the
	// active provider"; these routes are how the *set* is managed.
	s.mux.HandleFunc("GET /api/v1/admin/ai-providers",
		s.requireAuth(s.requireCapability(authz.CapOrgSettingsWrite, s.handleListAIProviders)))
	s.mux.HandleFunc("POST /api/v1/admin/ai-providers",
		s.requireAuth(s.requireCapability(authz.CapOrgSettingsWrite, s.handleCreateAIProvider)))
	s.mux.HandleFunc("PUT /api/v1/admin/ai-providers/{id}",
		s.requireAuth(s.requireCapability(authz.CapOrgSettingsWrite, s.handleUpdateAIProvider)))
	s.mux.HandleFunc("DELETE /api/v1/admin/ai-providers/{id}",
		s.requireAuth(s.requireCapability(authz.CapOrgSettingsWrite, s.handleDeleteAIProvider)))
	s.mux.HandleFunc("POST /api/v1/admin/ai-providers/{id}/activate",
		s.requireAuth(s.requireCapability(authz.CapOrgSettingsWrite, s.handleActivateAIProvider)))
	// Connection test: the same "prove this integration works before an
	// incident depends on it" route POST /repositories/{id}/check already
	// establishes, for the other paid/credentialed integration. Same
	// org:settings:write gate as the rest of this group — it spends (a trivial
	// amount of) money, so there is no honest read-only version of it.
	s.mux.HandleFunc("POST /api/v1/admin/ai-providers/{id}/test",
		s.requireAuth(s.requireCapability(authz.CapOrgSettingsWrite, s.handleTestAIProvider)))

	// Diagnostics bundle (internal/api/diagnostics.go, PROJECT.md T18) — a
	// bounded, redacted support artifact: hub/agent versions, cluster
	// connection state, migration version, AI-provider/repository
	// configuration presence (and, opt-in via ?probe=true, a live
	// connectivity check of each), detector health, and recent
	// ARGUS-internal errors. Same org:settings:write gate and the same
	// reasoning as the AI-providers routes just above — see that file's
	// package comment.
	s.mux.HandleFunc("GET /api/v1/diagnostics/bundle",
		s.requireAuth(s.requireCapability(authz.CapOrgSettingsWrite, s.handleGetDiagnosticsBundle)))

	// Detection dry-run (internal/api/detection_dryrun.go) — read-only
	// simulation of a CANDIDATE "detection" settings section against real
	// historical findings/incidents, replaying the exact same decision
	// functions handleFinding uses live (internal/gateway's exported
	// IsDetectorDisabled/StormProtection* helpers). Gated on the SAME
	// org:settings:write capability as the settings routes just above,
	// per this task's own instruction: it's read-only, but it surfaces the
	// same operational-policy-shaped information writing detection settings
	// does, so it gets the same scope, not a broader read capability.
	s.mux.HandleFunc("POST /api/v1/detection/dry-run",
		s.requireAuth(s.requireCapability(authz.CapOrgSettingsWrite, s.handleDetectionDryRun)))

	// Demo/sample data (internal/api/demo_data.go) — REGISTERED ONLY WHEN
	// ARGUS_ENABLE_DEMO_DATA is set, which the dev compose stack does and no
	// real deployment should (PROJECT.md D14). On a normal install these two
	// routes do not exist at all: the mux has no pattern for them and the
	// request 404s before auth, which is the point — a capability check would
	// still have let any org:settings:write holder write fabricated root
	// causes, approval decisions attributed to themselves by name, execution
	// records claiming a cluster was changed, and metered spend, into the
	// same tables real ones live in, with nothing anywhere excluding them
	// from counts.
	//
	// What survives is a TEST FIXTURE, not a product feature: web/e2e seeds
	// its whole suite through these two routes against a real hub
	// (web/playwright.config.ts) precisely so the specs assert on real rows
	// rather than mocks. The capability gate below is unchanged and still
	// applies when the flag is on.
	if s.demoDataEnabled {
		s.mux.HandleFunc("POST /api/v1/demo-data",
			s.requireAuth(s.requireCapability(authz.CapOrgSettingsWrite, s.handleGenerateDemoData)))
		s.mux.HandleFunc("DELETE /api/v1/demo-data",
			s.requireAuth(s.requireCapability(authz.CapOrgSettingsWrite, s.handleClearDemoData)))
	}

	// Admin console: user/grant management (internal/api/users.go). Reads
	// require user:read; every write requires user:manage — both already
	// existed in the capability catalogue (authz/permissions.go), granted to
	// super-admin/tenant-admin, just unused by any route until now.
	s.mux.HandleFunc("GET /api/v1/users",
		s.requireAuth(s.requireCapability(authz.CapUserRead, s.handleListUsers)))
	s.mux.HandleFunc("POST /api/v1/users",
		s.requireAuth(s.requireCapability(authz.CapUserManage, s.handleCreateUser)))
	s.mux.HandleFunc("POST /api/v1/users/{id}/grants",
		s.requireAuth(s.requireCapability(authz.CapUserManage, s.handleCreateGrant)))
	s.mux.HandleFunc("DELETE /api/v1/users/{id}/grants/{grantId}",
		s.requireAuth(s.requireCapability(authz.CapUserManage, s.handleRevokeGrant)))
	// Admin password reset (internal/api/users.go's handleResetPassword) —
	// same user:manage capability as every other write in this admin console.
	s.mux.HandleFunc("POST /api/v1/users/{id}/reset-password",
		s.requireAuth(s.requireCapability(authz.CapUserManage, s.handleResetPassword)))
	// User lifecycle: disable/enable (internal/api/users.go's
	// handleDisableUser/handleEnableUser) — soft-disable, not hard delete;
	// see that file's doc comment for why. Same user:manage capability.
	s.mux.HandleFunc("POST /api/v1/users/{id}/disable",
		s.requireAuth(s.requireCapability(authz.CapUserManage, s.handleDisableUser)))
	s.mux.HandleFunc("POST /api/v1/users/{id}/enable",
		s.requireAuth(s.requireCapability(authz.CapUserManage, s.handleEnableUser)))
	// User removal is intentionally stricter than disable/enable: it is
	// super-admin-only (user:remove) and soft-removes the account while
	// preserving historical audit references.
	s.mux.HandleFunc("DELETE /api/v1/users/{id}",
		s.requireAuth(s.requireCapability(authz.CapUserRemove, s.handleRemoveUser)))

	// Custom roles (internal/api/custom_roles.go, BACKLOG.md S3): admin-
	// defined named bundles of the SAME capability catalogue above, never a
	// new permission. Reads require user:read (same floor as GET /users,
	// which a custom role's name/capability set is no more sensitive than);
	// every write requires role:manage, deliberately separate from
	// user:manage — see permissions.go's CapRoleManage doc comment for why
	// composing a bundle is gated apart from assigning an existing one.
	s.mux.HandleFunc("GET /api/v1/custom-roles",
		s.requireAuth(s.requireCapability(authz.CapUserRead, s.handleListCustomRoles)))
	s.mux.HandleFunc("POST /api/v1/custom-roles",
		s.requireAuth(s.requireCapability(authz.CapRoleManage, s.handleCreateCustomRole)))

	// Identity-provider administration (PROJECT.md S2). CapIdentityManage,
	// not CapOrgSettingsWrite: editing a group mapping re-authorises everyone
	// in a directory group on their next login, which is strictly more
	// powerful than any other setting — see CapIdentityManage's own comment.
	s.mux.HandleFunc("GET /api/v1/admin/identity-providers",
		s.requireAuth(s.requireCapability(authz.CapIdentityManage, s.handleListIdentityProviders)))
	s.mux.HandleFunc("POST /api/v1/admin/identity-providers",
		s.requireAuth(s.requireCapability(authz.CapIdentityManage, s.handleSaveIdentityProvider)))
	s.mux.HandleFunc("PUT /api/v1/admin/identity-providers/{id}",
		s.requireAuth(s.requireCapability(authz.CapIdentityManage, s.handleSaveIdentityProvider)))
	s.mux.HandleFunc("DELETE /api/v1/admin/identity-providers/{id}",
		s.requireAuth(s.requireCapability(authz.CapIdentityManage, s.handleDeleteIdentityProvider)))
	s.mux.HandleFunc("POST /api/v1/admin/identity-providers/{id}/group-mappings",
		s.requireAuth(s.requireCapability(authz.CapIdentityManage, s.handleAddIdentityGroupMapping)))
	s.mux.HandleFunc("DELETE /api/v1/admin/identity-providers/{id}/group-mappings/{mappingId}",
		s.requireAuth(s.requireCapability(authz.CapIdentityManage, s.handleDeleteIdentityGroupMapping)))
	s.mux.HandleFunc("PUT /api/v1/custom-roles/{id}",
		s.requireAuth(s.requireCapability(authz.CapRoleManage, s.handleUpdateCustomRole)))
	s.mux.HandleFunc("DELETE /api/v1/custom-roles/{id}",
		s.requireAuth(s.requireCapability(authz.CapRoleManage, s.handleDeleteCustomRole)))

	// Cluster groups and their membership (internal/api/cluster_groups.go,
	// BACKLOG.md S3). Reads require cluster:read (same floor as GET
	// /clusters); every write requires cluster:group:manage, modeled on
	// cluster:onboard/accept/delete's own "fleet-lifecycle action, admin
	// only" gating.
	s.mux.HandleFunc("GET /api/v1/cluster-groups",
		s.requireAuth(s.requireCapability(authz.CapClusterRead, s.handleListClusterGroups)))
	s.mux.HandleFunc("POST /api/v1/cluster-groups",
		s.requireAuth(s.requireCapability(authz.CapClusterGroupManage, s.handleCreateClusterGroup)))
	s.mux.HandleFunc("DELETE /api/v1/cluster-groups/{id}",
		s.requireAuth(s.requireCapability(authz.CapClusterGroupManage, s.handleDeleteClusterGroup)))
	s.mux.HandleFunc("POST /api/v1/cluster-groups/{id}/clusters",
		s.requireAuth(s.requireCapability(authz.CapClusterGroupManage, s.handleAddClusterToGroup)))
	s.mux.HandleFunc("DELETE /api/v1/cluster-groups/{id}/clusters/{clusterId}",
		s.requireAuth(s.requireCapability(authz.CapClusterGroupManage, s.handleRemoveClusterFromGroup)))

	// Audit log (internal/api/audit.go) — read-only, additive to (not a
	// replacement for) argusctl's independent hash-chain verification tool.
	// audit:read is deliberately super-admin-only, excluded even from
	// tenant-admin (authz/permissions.go's builtinRoleCapabilities, per
	// lld/02-authz-spec.md §5's explicit note).
	s.mux.HandleFunc("GET /api/v1/audit-events",
		s.requireAuth(s.requireCapability(authz.CapAuditRead, s.handleListAuditEvents)))
	// Registered before "/{id}" so a literal "/export" path segment can never
	// be swallowed by the "{id}" wildcard — Go 1.22+'s http.ServeMux prefers
	// the more specific pattern regardless of registration order, but the
	// order here still reads correctly to a human scanning this list.
	s.mux.HandleFunc("GET /api/v1/audit-events/export",
		s.requireAuth(s.requireCapability(authz.CapAuditRead, s.handleExportAuditEvents)))
	s.mux.HandleFunc("GET /api/v1/audit-events/{id}",
		s.requireAuth(s.requireCapability(authz.CapAuditRead, s.handleGetAuditEvent)))

	// Live-update WebSocket surface (ws.go) — see that file's package
	// comment for the ticket-based authentication scheme GET /ws/events
	// needs in place of the Authorization-header convention every other
	// route uses. POST .../ws/ticket is requireAuth-gated like any other
	// route; GET /ws/events deliberately is not (it authenticates via the
	// ticket itself) and deliberately sits outside /api/v1, matching the
	// existing convention of keeping non-REST surfaces (enrollment, the
	// tunnel listener) visually distinct from the versioned REST API.
	//
	// The ticket route requires a READ capability (either one — see
	// requireAnyCapability): the feed carries incident and cluster ids, so
	// "authenticated" alone was never the right bar for it. GET /ws/events
	// re-resolves the connecting user's grants at upgrade time and filters
	// events per subscriber (ws.go's wsEventScope) — the ticket gate is the
	// coarse "may you have a feed at all" check, not the whole story.
	s.mux.HandleFunc("POST /api/v1/ws/ticket",
		s.requireAuth(s.requireAnyCapability([]string{authz.CapIncidentRead, authz.CapClusterRead}, s.handleCreateWSTicket)))
	s.mux.HandleFunc("GET /ws/events", s.handleWSEvents)

	// ===== AD3 — MCP for people's own AI tools (personal_tokens.go, mcp_user.go)
	// A person's own tokens: list and revoke need only a session (revoking
	// your own credential must never be blocked by a missing capability);
	// minting one needs mcp:use.
	s.mux.HandleFunc("GET /api/v1/users/me/mcp-tokens",
		s.requireAuth(s.handleListPersonalTokens))
	s.mux.HandleFunc("POST /api/v1/users/me/mcp-tokens",
		s.requireAuth(s.requireCapability(authz.CapMCPUse, s.handleCreatePersonalToken)))
	s.mux.HandleFunc("DELETE /api/v1/users/me/mcp-tokens/{id}",
		s.requireAuth(s.handleRevokePersonalToken))
	// The user-facing MCP endpoint (Streamable HTTP). NOT wrapped in
	// requireAuth: it authenticates with a personal access token, which
	// requireAuth never accepts, and every tool call re-resolves the token
	// owner's grants and checks the tool's own capability (mcp_user.go).
	// GET and DELETE are registered so the transport's optional SSE stream
	// and session teardown get the handler's 405 rather than the catch-all
	// UI page below.
	userMCP := s.newUserMCPServer().Handler()
	s.mux.HandleFunc("POST /api/v1/mcp", userMCP)
	s.mux.HandleFunc("GET /api/v1/mcp", userMCP)
	s.mux.HandleFunc("DELETE /api/v1/mcp", userMCP)

	// Catch-all: the embedded web UI (static.go). Only ever reached by a
	// request that didn't match any of the more specific patterns above —
	// net/http's ServeMux always prefers the most specific match, regardless
	// of registration order.
	s.mux.HandleFunc("GET /", s.handleStatic)
}

// ServeHTTP is the hub's HTTP entry point. Every request goes through the
// observability wrapper first (internal/api/observability.go): it mints or
// adopts the request's correlation id and records PROJECT.md T24's request
// metrics. The wrapper is applied HERE rather than around each registration
// so it cannot be forgotten on a new route.
//
// Tests that drive s.mux directly bypass it, which is deliberate and safe —
// requireAuth mints an id of its own when it does not find one, so the
// correlation half behaves identically either way; only the metric is
// skipped, and a unit test is not traffic.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.observe(s.mux).ServeHTTP(w, r)
}

// handleHealthz is the LIVENESS probe target, and it therefore checks exactly
// one thing: that this process is still able to accept a connection, route it
// through the mux, and answer. Answering at all proves the listener goroutine
// and the scheduler are alive, which is the only question liveness is allowed
// to ask.
//
// It deliberately does NOT touch the database, and must never be changed back
// to. It used to `db.Pool.Ping` and answer 503 when Postgres was unreachable,
// while deploy/helm/argus-hub/templates/deployment.yaml pointed BOTH probes
// here — so a momentary database blip failed liveness, kubelet killed the hub,
// and every enrolled cluster's mTLS tunnel died with it. Detection stopped
// fleet-wide for a condition the hub could have ridden out (an agent keeps
// reconnecting with backoff, and internal/gateway re-registers it). That is
// PROJECT.md B162. Nor does it report the shutdown state: liveness has to stay
// green for the whole SIGTERM drain, or kubelet kills the process in the
// middle of it (see shutdown.go).
//
// "Is the database reachable, and are its RLS guarantees intact?" is a
// READINESS question, and lives in handleReadyz below.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// handleReadyz is the READINESS probe target: may this hub be sent traffic
// right now? Unlike liveness, this is allowed to depend on everything a
// request actually needs, and a 503 here removes the pod from its Service's
// endpoints without restarting anything.
//
// Three checks, in the order a failure should be diagnosed:
//
//  1. Draining. Once BeginShutdown has been called (SIGTERM, shutdown.go),
//     this hub wants no NEW requests even though it is still serving the ones
//     it has.
//  2. Database reachable. Ping, distinguished from check 3 so "Postgres is
//     down" and "Postgres is up but RLS is not forced" are not the same
//     answer — this is the check B162 moved off /healthz, where it was
//     costing the fleet its tunnels.
//  3. The SR-2 RLS preconditions (lld/01-threat-model.md). A hub that is up
//     but whose RLS guarantees don't hold is not ready to serve traffic.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if s.IsShuttingDown() {
		writeProblem(w, http.StatusServiceUnavailable, "https://argus.io/errors/shutting-down", "Shutting down", "")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	pingCtx, cancelPing := context.WithTimeout(ctx, 2*time.Second)
	defer cancelPing()
	if err := s.db.Pool.Ping(pingCtx); err != nil {
		// err.Error() can carry connection detail (host, port) from the pgx
		// driver (BACKLOG.md G6) — this route is unauthenticated by design
		// (kubelet/load-balancer probes never carry a bearer token), so
		// anything it reveals reaches anyone who can reach the port.
		logger.ErrorContext(ctx, "readiness check: database ping failed", logging.Err(err))
		writeProblem(w, http.StatusServiceUnavailable, "https://argus.io/errors/db-unreachable", "Database unreachable", "")
		return
	}

	if err := s.db.CheckRLSPreconditions(ctx); err != nil {
		// err.Error() can name the specific role/setting that failed
		// (BACKLOG.md G6) — this route is unauthenticated by design, same
		// reasoning as the ping above.
		logger.ErrorContext(ctx, "readiness check: RLS precondition check failed", logging.Err(err))
		writeProblem(w, http.StatusServiceUnavailable, "https://argus.io/errors/rls-preconditions-unmet", "RLS preconditions not met", "")
		return
	}
	w.WriteHeader(http.StatusOK)
}

// writeProblem writes an RFC 9457 problem+json response, per lld/10-api-spec.md §3.
func writeProblem(w http.ResponseWriter, status int, problemType, title, detail string) {
	writeProblemWithExtras(w, status, problemType, title, detail, nil)
}

// writeProblemWithExtras is writeProblem plus RFC 9457 extension members —
// fields beyond type/title/status/detail that the spec explicitly permits and
// that a specific error case needs to carry structured data a client can act
// on without parsing prose out of `detail`.
//
// Introduced for exactly one case (WORKLOG §97 G5): a remediation guardrail
// refusal carries a confirmationToken the client must echo back to prove the
// refusal was actually shown before its override is honoured — see
// internal/authz.GuardrailConfirmationIssuer. Kept general rather than a
// one-off "problem with a token" function, since RFC 9457 extension members
// are a real, reusable mechanism and the next case that needs one should not
// have to invent its own response shape.
func writeProblemWithExtras(w http.ResponseWriter, status int, problemType, title, detail string, extras map[string]any) {
	body := map[string]any{
		"type":   problemType,
		"title":  title,
		"status": status,
		"detail": detail,
	}
	// PROJECT.md T23: the correlation id, as an RFC 9457 extension member,
	// on EVERY problem response — so an operator reporting "it failed" can
	// quote one string that pins the exact request in the hub's logs and,
	// for an investigation, on its analyses row.
	//
	// Read back off the response header rather than passed in as a
	// parameter, and that is the only reason this lands on all ~700
	// writeProblem call sites without touching one of them: the id is
	// already on the header by the time any handler runs (observability.go
	// sets it for real traffic, requireAuth for a request that reached the
	// mux directly), and requireAuth copies it onto the buffered writer
	// handlers actually hold. A signature change would have been ~700 call
	// sites of mechanical churn plus every one a future route forgets.
	if requestID := w.Header().Get(RequestIDHeader); requestID != "" {
		body["requestId"] = requestID
	}
	for k, v := range extras {
		body[k] = v
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func nowRFC3339() string {
	return formatRFC3339(time.Now())
}

func formatRFC3339(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// exec returns the plan-preparation/execution engine (internal/execution).
//
// NewServer builds one eagerly and stores it; the fallback is for a test that
// builds a bare &Server{db: ..., gw: ...} struct literal, which is this
// package's convention and predates the split. Such a Server gets an engine
// built from exactly the fields it did set, so a handler test behaves the same
// way it did when these methods hung off *Server.
func (s *Server) exec() *execution.Executor {
	if s.executor != nil {
		return s.executor
	}
	return s.newExecutor()
}

// newExecutor wires internal/execution to this Server's dependencies. The
// evidence reader is passed as a closure rather than as a direct call, because
// internal/execution must not import internal/api — see execution.EvidenceLister.
func (s *Server) newExecutor() *execution.Executor {
	var evidence execution.EvidenceLister
	if s.db != nil {
		evidence = func(ctx context.Context, clusterID, incidentID string) ([]llm.RecordedToolCall, error) {
			return ListMCPToolCalls(ctx, s.db.Pool, clusterID, incidentID)
		}
	}
	return execution.New(s.db, s.gw, s.events, s.planSigningRootKey, s.guardrailTokens, s.planCorrector, evidence)
}

// humanActor is the ordinary execution actor: a person clicked approve (or
// undo) on a real request. The adapter from HTTP to internal/execution's
// Actor — which is why it stayed here when the rest of the execution path
// moved: internal/execution has no *http.Request and should not acquire one.
func humanActor(rc *requestContext, r *http.Request) execution.Actor {
	return execution.Actor{UserID: rc.UserID, AuthMethod: "jwt", SourceIP: clientIP(r)}
}

// scopeOf narrows a requestContext to what internal/execution takes: the
// already-RLS-scoped transaction and the tenant it is scoped to. Nothing else
// about a request crosses that boundary.
func scopeOf(rc *requestContext) execution.Scope {
	return execution.Scope{Tx: rc.Tx, TenantID: rc.TenantID}
}

// The two execution entry points cmd/hub wires directly, forwarded to
// internal/execution.
//
// They stay methods on *Server because that is what the hub composes its
// workers and its orchestrator dependencies out of — VerifyAppliedValue is one
// of three methods that together satisfy orchestrator.AppliedValueVerifier, and
// the other two (VerifyMergedPullRequest, RuleStillFires) genuinely live here.
// Forwarding, rather than moving the wiring, keeps "what the hub starts" in one
// readable place; it does not put the logic back in this package.

// VerifyAppliedValue re-reads what an execution changed — the in-place route's
// half of orchestrator.AppliedValueVerifier. See internal/execution's
// implementation for the held/detail/err contract.
func (s *Server) VerifyAppliedValue(ctx context.Context, executionID string) (bool, string, error) {
	return s.exec().VerifyAppliedValue(ctx, executionID)
}

// RunExecutionReconciler settles execution attempts whose dispatcher never came
// back — the crash-recovery half of the execution path. Blocks until ctx is
// done; started as a worker by cmd/hub.
func (s *Server) RunExecutionReconciler(ctx context.Context, interval time.Duration) {
	s.exec().RunExecutionReconciler(ctx, interval)
}
