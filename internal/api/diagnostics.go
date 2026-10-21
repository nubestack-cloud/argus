package api

// GET /api/v1/diagnostics/bundle — board item T18.
//
// A bounded, redacted support artifact: hub/agent versions, cluster
// connection state, the applied migration version, AI-provider/repository
// configuration presence (and, opt-in, a live connectivity probe of each),
// per-cluster detector health, and a short window of ARGUS's own recent
// internal errors. This is explicitly NOT centralized log aggregation,
// backup management, a telemetry product, or a remote-support channel — see
// this file's manifest builder for the boundary stated in the response
// itself, not just in this comment.
//
// # Gate
//
// org:settings:write — the same capability ai_providers.go's management
// routes use, and for the identical reason its own doc comment gives for
// reusing that capability rather than minting a new one: the ability to
// rewrite AI-provider/repository configuration already implies the ability
// to see whether it currently works, and org:settings:write is already
// org-only and reserved to super-admin/tenant-admin (authz/permissions.go's
// orgOnlyCapabilities, builtinRoleCapabilities) — exactly the audience a
// support bundle should have. A narrower read-only capability would be a
// fiction here for the same reason it would be for the provider test route:
// with ?probe=true this route spends AI-provider tokens and makes live
// outbound calls to configured Git hosts.
//
// # What never reaches this bundle, and how that is enforced
//
// Three separate mechanisms, layered rather than relied on individually:
//
//  1. Structural. This file never calls os.Getenv/os.Environ and never
//     reads a repository credential or AI-provider secret except through
//     settings.GetProbeConfig — and ONLY when ?probe=true, and ONLY to hand
//     it to llm.ProbeProvider/the SCM client for one live check, never to
//     put it in the response. A Postgres password (ARGUS_APP_PASSWORD) is
//     never touched by this file at all: there is no code path here that
//     could put it in the bundle, the same "drop the whole class" guarantee
//     internal/redact's package comment argues for over pattern-matching
//     alone.
//  2. Presence, not value. Every configuration flag in this bundle
//     (apiKeySet, runnerTokenSet, credentialStored) is a boolean this
//     codebase already computes for its settings/repositories UI
//     (settings.AIProvider, repositoryBindingView) — never the secret
//     itself.
//  3. Redaction as a backstop for everything else that is FREEFORM text
//     from outside this process — a connectivity probe's own error message,
//     a detector's reported failure, an audited action's details summary.
//     sanitizeDiagnosticsText below strips every exact value collected into
//     knownDiagnosticsSecrets (which includes a probed provider's real
//     APIKey/RunnerToken — the one case this file touches a real secret,
//     and the resolved value can be an env-var fallback
//     (ARGUS_LLM_API_KEY/ARGUS_CLI_RUNNER_TOKEN — settings.GetProbeConfig's
//     own orEnv fallback), which is exactly why the fallback value itself,
//     not just the DB column, is added to the scrub list), then runs
//     internal/redact's bounded pattern layer (PEM keys, JWTs, bearer
//     tokens, AWS key IDs, URL userinfo, credential-implying key=value) —
//     the same layer that already guards Finding.Message at the agent.
//
// # Bound
//
// Every list is capped at fetch time (maxDiagnosticsClusters/Providers/
// Repositories/RecentErrors below) and every free-text field is truncated
// to diagnosticsFieldMaxRunes runes — so the body is bounded by
// construction, not by hoping it stays small. maxDiagnosticsBundleBytes is
// a defense-in-depth backstop on top of that (mirrors
// audit_export.go's auditEventExportRowCap): should be unreachable given
// the per-section caps, and the request fails closed rather than emitting
// an unbounded body if it is somehow exceeded.
//
// # Live connectivity checks are opt-in (?probe=true), never automatic
//
// Matching handleTestAIProvider's own rule exactly (ai_providers.go): a
// provider check spends a small but real amount of money, and a repository
// check makes a live outbound call to a configured Git host. A bundle
// download is a much more casual, more frequent action than a deliberate
// per-provider "Test" click, so it must not carry that cost by default.
// probe=true is the explicit opt-in for a caller who wants live proof, not
// just configuration presence and last-observed state.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/buildinfo"
	"argus/internal/data"
	"argus/internal/llm"
	"argus/internal/logging"
	"argus/internal/redact"
	"argus/internal/scm"
	"argus/internal/settings"
	"argus/internal/tunnel"
)

const (
	// maxDiagnosticsClusters bounds the clusters section — see this file's
	// package comment on bounding.
	maxDiagnosticsClusters = 200
	// maxDiagnosticsProviders bounds the AI-providers section. The table this
	// reads (ai_providers) is operator-configured and small in every real
	// deployment; this is a backstop, not a expected limit.
	maxDiagnosticsProviders = 20
	// maxDiagnosticsRepositories mirrors maxDiagnosticsProviders for
	// repository_bindings.
	maxDiagnosticsRepositories = 20
	// maxDiagnosticsRecentErrors bounds how many outcome=error audit_events
	// rows this bundle carries — a short recent window for triage, never the
	// full audit trail (that is what /api/v1/audit-events/export is for, and
	// it requires its own, separate audit:read capability).
	maxDiagnosticsRecentErrors = 20
	// diagnosticsFieldMaxRunes bounds any single freeform text field (a
	// connectivity probe's summary/detail, a detector's error, an audited
	// action's details digest) after sanitization.
	diagnosticsFieldMaxRunes = 500
	// maxDiagnosticsBundleBytes is the defense-in-depth backstop described in
	// this file's package comment — NOT the primary bound, which is the
	// per-section caps above enforced before the body is ever built.
	maxDiagnosticsBundleBytes = 4 * 1024 * 1024
)

// diagnosticsBundle is the whole response body.
type diagnosticsBundle struct {
	GeneratedAt          string                     `json:"generatedAt"`
	Hub                  diagnosticsHub             `json:"hub"`
	Migration            diagnosticsMigration       `json:"migration"`
	Clusters             []diagnosticsCluster       `json:"clusters"`
	ClustersTruncated    bool                       `json:"clustersTruncated"`
	AIProviders          []diagnosticsAIProvider    `json:"aiProviders"`
	ProvidersTruncated   bool                       `json:"aiProvidersTruncated"`
	Repositories         []diagnosticsRepository    `json:"repositories"`
	ReposTruncated       bool                       `json:"repositoriesTruncated"`
	RecentInternalErrors []diagnosticsInternalError `json:"recentInternalErrors"`
	ErrorsTruncated      bool                       `json:"recentInternalErrorsTruncated"`
	Probed               bool                       `json:"probed"`
	Manifest             diagnosticsManifest        `json:"manifest"`
}

type diagnosticsHub struct {
	Version string `json:"version"`
}

// diagnosticsMigration is the applied golang-migrate state, read straight
// from schema_migrations (no ORM/wrapper around that table exists — this is
// the same table internal/data.RunMigrations manages). Known is false when
// the table couldn't be read at all (a fresh, unmigrated database — should
// not happen in a running hub, but distinguished from a real answer rather
// than reported as version 0).
type diagnosticsMigration struct {
	Version int64  `json:"version,omitempty"`
	Dirty   bool   `json:"dirty"`
	Known   bool   `json:"known"`
	Error   string `json:"error,omitempty"`
}

// diagnosticsCluster is one cluster's connection state plus its own reported
// detector health. Mirrors clusterSummary's own fields (clusters.go) for the
// parts that overlap, but is its own type: clusterSummary carries
// agentversion.Compatibility, which is a UI-facing verdict, not a
// diagnostic fact, and adding this file's Detectors field to that struct
// would leak this file's shape into every other consumer of
// clusterSummary.
type diagnosticsCluster struct {
	ID              string  `json:"id"`
	DisplayName     string  `json:"displayName"`
	State           string  `json:"state"`
	AgentVersion    *string `json:"agentVersion,omitempty"`
	LastHeartbeatAt *string `json:"lastHeartbeatAt,omitempty"`
	// FactsUpdatedAt is when the hub last received this cluster's
	// ClusterFacts payload — the age of everything in Detectors below. Nil
	// when no facts row exists at all (no inventory sync has ever
	// completed), never a fabricated zero time. See the query that fills it.
	FactsUpdatedAt *string `json:"factsUpdatedAt,omitempty"`
	// Detectors is nil when this agent's build predates detector-status
	// reporting, or its facts haven't synced yet — indistinguishable on the
	// wire, both meaning "no detector data available", never "healthy" and
	// never "failing". See tunnel.ClusterDetectors' own doc comment.
	Detectors *diagnosticsDetectors `json:"detectors,omitempty"`
}

type diagnosticsDetectors struct {
	WarningEvents diagnosticsDetectorStatus `json:"warningEvents"`
	PodConditions diagnosticsDetectorStatus `json:"podConditions"`
	Sweep         diagnosticsDetectorStatus `json:"sweep"`
}

// diagnosticsDetectorStatus never renders tunnel.DetectorStatus's zero value
// as healthy or failing — Status is explicitly "unknown" in that case. See
// diagnosticsStatusFor.
type diagnosticsDetectorStatus struct {
	Status        string `json:"status"` // "ok" | "degraded" | "failing" | "unknown"
	LastSuccessAt string `json:"lastSuccessAt,omitempty"`
	Error         string `json:"error,omitempty"`
	ErrorAt       string `json:"errorAt,omitempty"`
	// TimedOutChecks names the checks that did not answer in this
	// detector's most recent pass — PROJECT.md P19's residual, passed
	// through from tunnel.DetectorStatus. Unlike Error it describes only
	// that pass, so its absence here means the last pass was complete (or
	// that the agent predates the field), never that nothing ever hung.
	TimedOutChecks []string `json:"timedOutChecks,omitempty"`
	DeniedReads    []string `json:"deniedReads,omitempty"`
}

// diagnosticsAIProvider carries configuration PRESENCE (never a value — see
// this file's package comment) plus, only when probed, a live connectivity
// result. BaseURL/RunnerURL/Model are not secrets (they name an endpoint and
// a model, not a credential) and are already returned unredacted by
// aiProviderView; still passed through sanitizeDiagnosticsText for the same
// defense-in-depth reason everything else here is.
type diagnosticsAIProvider struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Active bool   `json:"active"`

	APIKeySet      bool `json:"apiKeySet"`
	RunnerTokenSet bool `json:"runnerTokenSet"`

	BaseURL   string `json:"baseUrl,omitempty"`
	Model     string `json:"model,omitempty"`
	RunnerURL string `json:"runnerUrl,omitempty"`

	ConnectivityChecked bool   `json:"connectivityChecked"`
	ConnectivityOK      bool   `json:"connectivityOk,omitempty"`
	ConnectivityKind    string `json:"connectivityKind,omitempty"`
	ConnectivitySummary string `json:"connectivitySummary,omitempty"`
	ConnectivityDetail  string `json:"connectivityDetail,omitempty"`
	ConnectivityCaveat  string `json:"connectivityCaveat,omitempty"`
}

type diagnosticsRepository struct {
	ID               string `json:"id"`
	Provider         string `json:"provider"`
	Host             string `json:"host"`
	CredentialStored bool   `json:"credentialStored"`

	ConnectivityChecked bool   `json:"connectivityChecked"`
	ConnectivityOK      bool   `json:"connectivityOk,omitempty"`
	ConnectivitySummary string `json:"connectivitySummary,omitempty"`
}

// diagnosticsInternalError is one recent outcome=error audit_events row,
// reduced to the same Action/DetailsSummary shape audit.go's own list view
// already computes (auditActionLabel/summarizeActionDetails) — reused
// rather than re-derived, so this file's summary can never read differently
// from what /api/v1/audit-events already shows for the same row.
type diagnosticsInternalError struct {
	OccurredAt string `json:"occurredAt"`
	Action     string `json:"action"`
	Capability string `json:"capability,omitempty"`
	ClusterID  string `json:"clusterId,omitempty"`
	Summary    string `json:"summary"`
}

// diagnosticsManifest is what makes the bundle trustworthy: not just what
// is in it, but a stated account of what was deliberately left out and why.
type diagnosticsManifest struct {
	Included        []string              `json:"included"`
	Omitted         []diagnosticsOmission `json:"omitted"`
	Truncated       bool                  `json:"truncated"`
	BundleSizeBytes int                   `json:"bundleSizeBytes"`
	MaxBundleBytes  int                   `json:"maxBundleBytes"`
}

type diagnosticsOmission struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

// handleGetDiagnosticsBundle is GET /api/v1/diagnostics/bundle. Requires
// org:settings:write — see this file's package comment.
func (s *Server) handleGetDiagnosticsBundle(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	probe := r.URL.Query().Get("probe") == "true"

	bundle := diagnosticsBundle{
		GeneratedAt: formatRFC3339(time.Now().UTC()),
		Hub:         diagnosticsHub{Version: buildinfo.Version()},
		Migration:   fetchDiagnosticsMigration(ctx, rc.Tx),
		Probed:      probe,
	}

	var knownSecrets []string

	providers, providersTruncated, providerSecrets, err := fetchDiagnosticsAIProviders(ctx, rc.Tx, probe)
	if err != nil {
		logger.ErrorContext(ctx, "collecting the AI-providers section of the diagnostics bundle failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not build the diagnostics bundle", "")
		return
	}
	bundle.AIProviders, bundle.ProvidersTruncated = providers, providersTruncated
	knownSecrets = append(knownSecrets, providerSecrets...)

	repos, reposTruncated, err := fetchDiagnosticsRepositories(ctx, rc.Tx, s.scmStore, probe)
	if err != nil {
		logger.ErrorContext(ctx, "collecting the repositories section of the diagnostics bundle failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not build the diagnostics bundle", "")
		return
	}
	bundle.Repositories, bundle.ReposTruncated = repos, reposTruncated

	recentErrors, errorsTruncated, err := fetchDiagnosticsRecentErrors(ctx, rc.Tx)
	if err != nil {
		logger.ErrorContext(ctx, "collecting the recent-errors section of the diagnostics bundle failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not build the diagnostics bundle", "")
		return
	}
	bundle.RecentInternalErrors, bundle.ErrorsTruncated = recentErrors, errorsTruncated

	// Clusters last: fetchDiagnosticsClusters widens this transaction's RLS
	// scope to this tenant's own cluster ids (see its own doc comment for
	// why cluster_facts needs that), and nothing queried above needs the
	// narrower default scope preserved afterward.
	clusters, clustersTruncated, err := fetchDiagnosticsClusters(ctx, rc)
	if err != nil {
		logger.ErrorContext(ctx, "collecting the clusters section of the diagnostics bundle failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not build the diagnostics bundle", "")
		return
	}
	bundle.Clusters, bundle.ClustersTruncated = clusters, clustersTruncated

	sanitizeDiagnosticsBundle(&bundle, knownSecrets)

	bundle.Manifest = buildDiagnosticsManifest(bundle, probe)
	body, err := json.Marshal(bundle)
	if err != nil {
		logger.ErrorContext(ctx, "marshalling the diagnostics bundle failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not build the diagnostics bundle", "")
		return
	}
	// The manifest reports its own size, which means marshaling twice: the
	// first pass is only to learn how big the body is.
	bundle.Manifest.BundleSizeBytes = len(body)
	bundle.Manifest.MaxBundleBytes = maxDiagnosticsBundleBytes
	body, err = json.Marshal(bundle)
	if err != nil {
		logger.ErrorContext(ctx, "marshalling the trimmed diagnostics bundle failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not build the diagnostics bundle", "")
		return
	}
	if len(body) > maxDiagnosticsBundleBytes {
		// Defense-in-depth backstop — see this file's package comment. Should
		// be unreachable given the per-section caps every fetch function
		// above already enforces.
		logger.WarnContext(ctx, "the diagnostics bundle exceeded its size bound",
			slog.Int("bytes", len(body)), slog.Int("max_bytes", maxDiagnosticsBundleBytes))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Diagnostics bundle exceeded its size bound", "")
		return
	}

	s.auditDiagnosticsBundle(r, rc, probe, bundle)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="argus-diagnostics_%s.json"`, time.Now().UTC().Format("20060102T150405Z")))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// auditDiagnosticsBundle records one audit row per bundle download —
// attributing it to a person, matching the discipline
// auditProviderChange/auditProviderTestOutcome already established for the
// other paid/credentialed action in this codebase. One row per download
// rather than one per probed provider/repository: granular per-probe audit
// rows would need their own schema decision this task does not need to
// make, and the counts below already say how many were probed.
func (s *Server) auditDiagnosticsBundle(r *http.Request, rc *requestContext, probed bool, bundle diagnosticsBundle) {
	capability := authz.CapOrgSettingsWrite
	details := map[string]any{
		"action":           "diagnostics:bundle",
		"probed":           probed,
		"clusterCount":     len(bundle.Clusters),
		"aiProviderCount":  len(bundle.AIProviders),
		"repositoryCount":  len(bundle.Repositories),
		"recentErrorCount": len(bundle.RecentInternalErrors),
		"bundleSizeBytes":  bundle.Manifest.BundleSizeBytes,
	}
	if err := audit.RecordEvent(r.Context(), rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		Outcome:         audit.OutcomeSuccess,
		Details:         details,
	}); err != nil {
		// Logged, not fatal — matching auditProviderChange's own reasoning:
		// the bundle is already built, and failing the download now would
		// report an error for something that succeeded.
		logger.ErrorContext(r.Context(), "recording a diagnostics-bundle read in the audit log failed", logging.Err(err))
	}
}

func fetchDiagnosticsMigration(ctx context.Context, tx pgx.Tx) diagnosticsMigration {
	var version int64
	var dirty bool
	if err := tx.QueryRow(ctx, `SELECT version, dirty FROM schema_migrations`).Scan(&version, &dirty); err != nil {
		return diagnosticsMigration{Error: "could not read the applied migration version"}
	}
	return diagnosticsMigration{Version: version, Dirty: dirty, Known: true}
}

// fetchDiagnosticsAIProviders returns the configured providers (presence
// only), plus, when probe is true, a live connectivity result for each and
// the real secret values GetProbeConfig resolved for them — the latter
// returned so the caller can add them to this bundle's redaction scrub
// list. Never fetches a real secret when probe is false.
func fetchDiagnosticsAIProviders(ctx context.Context, tx pgx.Tx, probe bool) ([]diagnosticsAIProvider, bool, []string, error) {
	providers, err := settings.ListProviders(ctx, tx)
	if err != nil {
		return nil, false, nil, fmt.Errorf("list ai providers: %w", err)
	}
	truncated := false
	if len(providers) > maxDiagnosticsProviders {
		providers = providers[:maxDiagnosticsProviders]
		truncated = true
	}

	var knownSecrets []string
	out := make([]diagnosticsAIProvider, 0, len(providers))
	for _, p := range providers {
		dp := diagnosticsAIProvider{
			ID: p.ID, Name: p.Name, Kind: p.Kind, Active: p.Active,
			APIKeySet: p.APIKeySet, RunnerTokenSet: p.RunnerTokenSet,
			BaseURL: p.BaseURL, Model: p.Model, RunnerURL: p.RunnerURL,
		}
		if probe {
			cfg, err := settings.GetProbeConfig(ctx, tx, p.ID)
			if err != nil {
				// Left ConnectivityChecked false — this is this bundle's own
				// lookup failing, not a fact about the provider.
				logger.WarnContext(ctx, "probing an AI provider's configuration failed", slog.String("provider_id", p.ID), logging.Err(err))
			} else {
				// Added regardless of whether the probe below actually uses
				// them (an empty string is a harmless no-op ReplaceAll) —
				// see this file's package comment on why the RESOLVED
				// value, not just the DB column, must be scrubbed.
				knownSecrets = append(knownSecrets, cfg.APIKey, cfg.RunnerToken)
				result := llm.ProbeProvider(ctx, nil, llm.ProbeTarget{
					Kind: cfg.Kind, BaseURL: cfg.BaseURL, Model: cfg.Model, APIKey: cfg.APIKey,
					RunnerURL: cfg.RunnerURL, RunnerToken: cfg.RunnerToken, Agent: cfg.Agent,
					// Same source the real provider path dials with — a
					// diagnostics bundle reporting a connectivity verdict the
					// product itself would not reach is worse than reporting
					// nothing. tx, not the pool: this runs inside the
					// request's own transaction like every other read here.
					PrivateDestinations: settings.PrivateDestinationSource(tx),
				})
				dp.ConnectivityChecked = true
				dp.ConnectivityOK = result.OK
				dp.ConnectivityKind = result.Kind
				dp.ConnectivitySummary = result.Summary
				dp.ConnectivityDetail = result.Detail
				dp.ConnectivityCaveat = result.Caveat
			}
		}
		out = append(out, dp)
	}
	return out, truncated, knownSecrets, nil
}

// fetchDiagnosticsRepositories mirrors fetchDiagnosticsAIProviders for
// repository_bindings, reusing the exact check handleCheckRepositoryBinding
// already performs (repositories.go) — a stored DefaultBranch is proven via
// ResolveRef, otherwise the provider's own DefaultBranch auto-detection is
// exercised instead. Never returns the decrypted credential: ProviderFor
// only ever hands this file a Provider/Repo pair, never the token itself.
func fetchDiagnosticsRepositories(ctx context.Context, tx pgx.Tx, scmStore *scm.Store, probe bool) ([]diagnosticsRepository, bool, error) {
	bindings, err := scmStore.ListBindings(ctx, tx)
	if err != nil {
		return nil, false, fmt.Errorf("list repository bindings: %w", err)
	}
	truncated := false
	if len(bindings) > maxDiagnosticsRepositories {
		bindings = bindings[:maxDiagnosticsRepositories]
		truncated = true
	}

	out := make([]diagnosticsRepository, 0, len(bindings))
	for _, b := range bindings {
		dr := diagnosticsRepository{
			ID: b.ID, Provider: b.Provider, Host: b.Host,
			CredentialStored: b.CredentialRef != "",
		}
		if probe {
			dr.ConnectivityChecked = true
			provider, repo, _, err := scmStore.ProviderFor(ctx, tx, b.URL)
			if err != nil {
				dr.ConnectivitySummary = err.Error()
			} else {
				branch := b.DefaultBranch
				var resolveErr error
				if branch != "" {
					_, resolveErr = provider.ResolveRef(ctx, repo, branch)
				} else {
					_, resolveErr = provider.DefaultBranch(ctx, repo)
				}
				if resolveErr != nil {
					dr.ConnectivitySummary = resolveErr.Error()
				} else {
					dr.ConnectivityOK = true
					dr.ConnectivitySummary = "credential can read this repository"
				}
			}
		}
		out = append(out, dr)
	}
	return out, truncated, nil
}

// fetchDiagnosticsRecentErrors reads the most recent outcome=error
// audit_events rows for this tenant (RLS-scoped through tx exactly like
// every other read in this codebase), reusing audit.go's own
// auditActionLabel/summarizeActionDetails so this file's summary can never
// read differently from what GET /api/v1/audit-events already shows for
// the same row.
func fetchDiagnosticsRecentErrors(ctx context.Context, tx pgx.Tx) ([]diagnosticsInternalError, bool, error) {
	rows, err := tx.Query(ctx, `
		SELECT ae.occurred_at, ae.capability, ae.cluster_id, ae.details
		  FROM audit_events ae
		 WHERE ae.outcome = 'error'
		 ORDER BY ae.occurred_at DESC, ae.id DESC
		 LIMIT $1`, maxDiagnosticsRecentErrors+1)
	if err != nil {
		return nil, false, fmt.Errorf("query recent internal errors: %w", err)
	}
	defer rows.Close()

	var out []diagnosticsInternalError
	for rows.Next() {
		var occurredAt time.Time
		var capability, clusterID *string
		var rawDetails []byte
		if err := rows.Scan(&occurredAt, &capability, &clusterID, &rawDetails); err != nil {
			return nil, false, fmt.Errorf("scan recent internal error: %w", err)
		}
		var details map[string]any
		_ = json.Unmarshal(rawDetails, &details) // best-effort; nil details still summarizes
		action := auditActionLabel(capability, details)
		out = append(out, diagnosticsInternalError{
			OccurredAt: formatRFC3339(occurredAt),
			Action:     action,
			Capability: derefOrEmptyStr(capability),
			ClusterID:  derefOrEmptyStr(clusterID),
			Summary:    summarizeActionDetails(action, details),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate recent internal errors: %w", err)
	}

	truncated := false
	if len(out) > maxDiagnosticsRecentErrors {
		out = out[:maxDiagnosticsRecentErrors]
		truncated = true
	}
	return out, truncated, nil
}

// fetchDiagnosticsClusters returns this tenant's clusters (connection state)
// plus each one's own reported detector health.
//
// Widens rc.Tx's RLS scope to exactly this tenant's own cluster ids before
// reading cluster_facts: that table's RLS policy is keyed SOLELY on
// app.accessible_cluster_ids with no tenant_id fallback (unlike `clusters`
// itself, which migration 000011 gave one — see handleGetCluster's own
// comment on this exact gap), and requireAuth leaves accessible_cluster_ids
// empty by default. Safe to widen to every id this tenant's own `clusters`
// rows just produced, with no per-cluster authz.HasCapabilityForCluster
// check: org:settings:write is an org-only capability
// (authz.orgOnlyCapabilities), so requireCapability above already
// establishes org-wide trust for this whole request — there is no narrower
// per-cluster grant of it to violate.
func fetchDiagnosticsClusters(ctx context.Context, rc *requestContext) ([]diagnosticsCluster, bool, error) {
	rows, err := rc.Tx.Query(ctx, `
		SELECT id, display_name, state, agent_version, last_heartbeat_at
		  FROM clusters WHERE archived_at IS NULL ORDER BY id LIMIT $1`, maxDiagnosticsClusters+1)
	if err != nil {
		return nil, false, fmt.Errorf("query clusters: %w", err)
	}

	type clusterRow struct {
		id, displayName, state string
		agentVersion           *string
		lastHeartbeatAt        *time.Time
	}
	var crs []clusterRow
	for rows.Next() {
		var cr clusterRow
		if err := rows.Scan(&cr.id, &cr.displayName, &cr.state, &cr.agentVersion, &cr.lastHeartbeatAt); err != nil {
			rows.Close()
			return nil, false, fmt.Errorf("scan cluster: %w", err)
		}
		crs = append(crs, cr)
	}
	rerr := rows.Err()
	rows.Close()
	if rerr != nil {
		return nil, false, fmt.Errorf("iterate clusters: %w", rerr)
	}

	truncated := false
	if len(crs) > maxDiagnosticsClusters {
		crs = crs[:maxDiagnosticsClusters]
		truncated = true
	}

	ids := make([]string, len(crs))
	for i, cr := range crs {
		ids[i] = cr.id
	}

	factsByCluster := map[string]*tunnel.ClusterDetectors{}
	// When the hub last RECEIVED each facts row. Reported alongside the
	// detector statuses read out of it because those statuses are absolute-
	// state snapshots that carry no evidence of their own age (PROJECT.md
	// B177): "sweep last succeeded at T" is only a statement about now if the
	// snapshot containing it is itself recent. The agent re-sends facts every
	// agent.factsRefreshInterval over an established tunnel, so a bundle
	// showing a detector "ok" against a factsUpdatedAt far in the past is
	// reporting what WAS true, and this is the field that says so.
	factsUpdatedByCluster := map[string]time.Time{}
	if len(ids) > 0 {
		if err := data.SetRequestScope(ctx, rc.Tx, rc.TenantID, ids); err != nil {
			return nil, false, fmt.Errorf("widen request scope to this tenant's clusters: %w", err)
		}
		factRows, err := rc.Tx.Query(ctx, `SELECT cluster_id, facts, updated_at FROM cluster_facts WHERE cluster_id = ANY($1)`, ids)
		if err != nil {
			return nil, false, fmt.Errorf("query cluster facts: %w", err)
		}
		for factRows.Next() {
			var clusterID string
			var raw []byte
			var updatedAt time.Time
			if err := factRows.Scan(&clusterID, &raw, &updatedAt); err != nil {
				factRows.Close()
				return nil, false, fmt.Errorf("scan cluster facts: %w", err)
			}
			factsUpdatedByCluster[clusterID] = updatedAt
			var parsed struct {
				Detectors *tunnel.ClusterDetectors `json:"detectors"`
			}
			// Best-effort: a facts row that doesn't decode (shouldn't
			// happen — the agent is the only writer) just leaves this
			// cluster's Detectors nil, which reads as "no detector data
			// available" — the same safe fallback an older agent's absent
			// field already gets.
			if err := json.Unmarshal(raw, &parsed); err == nil {
				factsByCluster[clusterID] = parsed.Detectors
			}
		}
		if err := factRows.Err(); err != nil {
			factRows.Close()
			return nil, false, fmt.Errorf("iterate cluster facts: %w", err)
		}
		factRows.Close()
	}

	out := make([]diagnosticsCluster, 0, len(crs))
	for _, cr := range crs {
		dc := diagnosticsCluster{ID: cr.id, DisplayName: cr.displayName, State: cr.state, AgentVersion: cr.agentVersion}
		if cr.lastHeartbeatAt != nil {
			f := formatRFC3339(*cr.lastHeartbeatAt)
			dc.LastHeartbeatAt = &f
		}
		if updatedAt, ok := factsUpdatedByCluster[cr.id]; ok {
			f := formatRFC3339(updatedAt)
			dc.FactsUpdatedAt = &f
		}
		if det := factsByCluster[cr.id]; det != nil {
			dc.Detectors = &diagnosticsDetectors{
				WarningEvents: diagnosticsStatusFor(det.WarningEvents),
				PodConditions: diagnosticsStatusFor(det.PodConditions),
				Sweep:         diagnosticsStatusFor(det.Sweep),
			}
		}
		out = append(out, dc)
	}
	return out, truncated, nil
}

// diagnosticsStatusFor never reads tunnel.DetectorStatus's zero value as
// healthy or as failing — see that type's own doc comment, and this
// function's "unknown" case below.
func diagnosticsStatusFor(d tunnel.DetectorStatus) diagnosticsDetectorStatus {
	out := diagnosticsDetectorStatus{DeniedReads: d.DeniedReads, TimedOutChecks: d.TimedOutChecks}
	switch {
	case d.LastSuccessAt.IsZero() && d.Error == "":
		out.Status = "unknown"
	case d.ErrorAt.After(d.LastSuccessAt):
		out.Status = "failing"
	case len(d.TimedOutChecks) > 0:
		// PROJECT.md P19's residual: "one check did not answer" and "the
		// sweep failed" are now separate facts on the wire, so they get
		// separate words here. The detector IS running — its last pass
		// advanced LastSuccessAt, which is why the failing case above does
		// not catch this — but that pass was incomplete, and calling it
		// plain "ok" would claim a coverage it did not have. Ordered after
		// "failing" deliberately: a checker that was refused outright is
		// the more actionable of the two when a pass produced both.
		out.Status = "degraded"
	default:
		out.Status = "ok"
	}
	if !d.LastSuccessAt.IsZero() {
		out.LastSuccessAt = formatRFC3339(d.LastSuccessAt)
	}
	if d.Error != "" {
		out.Error = d.Error
		out.ErrorAt = formatRFC3339(d.ErrorAt)
	}
	return out
}

// sanitizeDiagnosticsBundle is the one place every freeform string in the
// bundle is scrubbed before it is marshaled — see this file's package
// comment for the three-layer reasoning. Deliberately centralized rather
// than sanitized at each fetch call site: a single, directly-tested
// function is what makes "adversarial, not illustrative" checkable at all.
func sanitizeDiagnosticsBundle(b *diagnosticsBundle, knownSecrets []string) {
	for i := range b.Clusters {
		b.Clusters[i].DisplayName = sanitizeDiagnosticsText(b.Clusters[i].DisplayName, knownSecrets)
		if det := b.Clusters[i].Detectors; det != nil {
			for _, ds := range []*diagnosticsDetectorStatus{&det.WarningEvents, &det.PodConditions, &det.Sweep} {
				ds.Error = sanitizeDiagnosticsText(ds.Error, knownSecrets)
				for j, dr := range ds.DeniedReads {
					ds.DeniedReads[j] = sanitizeDiagnosticsText(dr, knownSecrets)
				}
				// Checker names come from a fixed in-code catalogue, like
				// DeniedReads' labels above, and carry no cluster text —
				// scrubbed anyway for the same defense-in-depth reason
				// those are, so a future field that DOES carry text cannot
				// be added here and quietly skip this loop.
				for j, tc := range ds.TimedOutChecks {
					ds.TimedOutChecks[j] = sanitizeDiagnosticsText(tc, knownSecrets)
				}
			}
		}
	}
	for i := range b.AIProviders {
		p := &b.AIProviders[i]
		p.BaseURL = sanitizeDiagnosticsText(p.BaseURL, knownSecrets)
		p.RunnerURL = sanitizeDiagnosticsText(p.RunnerURL, knownSecrets)
		p.Model = sanitizeDiagnosticsText(p.Model, knownSecrets)
		p.ConnectivitySummary = sanitizeDiagnosticsText(p.ConnectivitySummary, knownSecrets)
		p.ConnectivityDetail = sanitizeDiagnosticsText(p.ConnectivityDetail, knownSecrets)
		p.ConnectivityCaveat = sanitizeDiagnosticsText(p.ConnectivityCaveat, knownSecrets)
	}
	for i := range b.Repositories {
		r := &b.Repositories[i]
		r.Host = sanitizeDiagnosticsText(r.Host, knownSecrets)
		r.ConnectivitySummary = sanitizeDiagnosticsText(r.ConnectivitySummary, knownSecrets)
	}
	for i := range b.RecentInternalErrors {
		e := &b.RecentInternalErrors[i]
		e.Action = sanitizeDiagnosticsText(e.Action, knownSecrets)
		e.Summary = sanitizeDiagnosticsText(e.Summary, knownSecrets)
	}
}

// sanitizeDiagnosticsText is the single scrub applied to every freeform
// field this bundle carries: first an exact-match strip of every value in
// knownSecrets (real secret material this request actually resolved — see
// this file's package comment), then internal/redact's bounded pattern
// layer (catches anything of a recognisable credential SHAPE that isn't in
// knownSecrets — a URL-embedded userinfo password on a connectivity error is
// exactly the case that motivated this second layer), then a length cap.
//
// Order matters: an exact match runs before the pattern layer so a known
// secret that happens to also match a pattern (e.g. a bearer token) is
// still removed even if some future refactor narrowed the pattern layer.
func sanitizeDiagnosticsText(s string, knownSecrets []string) string {
	if s == "" {
		return s
	}
	out := s
	for _, secret := range knownSecrets {
		secret = strings.TrimSpace(secret)
		if secret == "" {
			continue
		}
		out = strings.ReplaceAll(out, secret, redact.Marker)
	}
	out = redact.Text(out)
	if runes := []rune(out); len(runes) > diagnosticsFieldMaxRunes {
		out = string(runes[:diagnosticsFieldMaxRunes]) + "…"
	}
	return out
}

// buildDiagnosticsManifest is the trust boundary of the whole bundle: what
// this download actually contains, and — just as load-bearing — what it
// deliberately does not, stated as data rather than left to be inferred
// from an absent key.
func buildDiagnosticsManifest(b diagnosticsBundle, probed bool) diagnosticsManifest {
	trunc := func(n int, capped bool) string {
		if capped {
			return fmt.Sprintf("%d (truncated)", n)
		}
		return fmt.Sprintf("%d", n)
	}

	included := []string{
		fmt.Sprintf("hub version: %s", b.Hub.Version),
		"applied migration version (schema_migrations)",
		"cluster connection state, agent version, and last heartbeat: " + trunc(len(b.Clusters), b.ClustersTruncated) + " cluster(s)",
		"per-cluster detector health (last success, last error, denied reads) where an agent has reported it",
		"AI provider configuration presence (kind, active flag, apiKeySet/runnerTokenSet booleans): " + trunc(len(b.AIProviders), b.ProvidersTruncated) + " provider(s)",
		"repository binding configuration presence (provider, host, credentialStored): " + trunc(len(b.Repositories), b.ReposTruncated) + " binding(s)",
		fmt.Sprintf("recent ARGUS-internal errors (audit_events, outcome=error, most recent %d): %s", maxDiagnosticsRecentErrors, trunc(len(b.RecentInternalErrors), b.ErrorsTruncated)),
	}
	if probed {
		included = append(included, "live connectivity results for the AI providers and repositories above (requested via ?probe=true)")
	}

	omitted := []diagnosticsOmission{
		{Field: "AI provider API keys / CLI runner tokens", Reason: "presence only (apiKeySet/runnerTokenSet). A probed provider's real key is used in-process for one connectivity check and never placed in this response — internal/llm.ProbeResult is documented to never carry a credential — and is additionally added to this bundle's own redaction scrub list."},
		{Field: "repository credentials", Reason: "presence only (credentialStored). A probed repository's decrypted token stays inside the SCM client that makes the one connectivity call; this handler never receives it."},
		{Field: "Kubernetes Secret contents", Reason: "this bundle never queries a cluster directly — it reads only what the hub already holds in Postgres and its own process, none of which is a Secret object."},
		{Field: "raw workload/pod logs", Reason: "not collected. This is a support artifact, not log aggregation."},
		{Field: "process environment variables", Reason: "never read directly by this handler (no os.Getenv/os.Environ call in it), even though some of them can influence resolved AI-provider configuration through settings.GetProbeConfig's own env fallback — which is why a resolved secret is added to the redaction scrub list rather than trusted to never appear."},
		{Field: "the full audit trail / arbitrary database rows", Reason: fmt.Sprintf("only the most recent %d outcome=error audit_events rows, read through this file's own fixed queries — never an ad hoc read of another table or an unbounded export (see /api/v1/audit-events/export for that, gated on its own audit:read capability).", maxDiagnosticsRecentErrors)},
		{Field: "cluster resource inventory (pods, deployments, nodes, etc.)", Reason: "out of scope for a support bundle — see the incidents/cluster-facts API for that."},
	}
	if !probed {
		omitted = append(omitted, diagnosticsOmission{
			Field:  "live AI-provider / repository connectivity results",
			Reason: "not requested for this download. A connectivity check spends AI-provider tokens and makes a live outbound call to a configured Git host, so — matching the existing per-provider \"Test\" action's own rule — it never runs automatically; pass ?probe=true to request it.",
		})
	}

	return diagnosticsManifest{
		Included:  included,
		Omitted:   omitted,
		Truncated: b.ClustersTruncated || b.ProvidersTruncated || b.ReposTruncated || b.ErrorsTruncated,
	}
}

func derefOrEmptyStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
