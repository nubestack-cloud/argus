package api

// GET/POST /api/v1/admin/ai-providers, PUT/DELETE .../{id},
// POST .../{id}/activate, POST .../{id}/test
//
// The management surface for migration 000034's `ai_providers` table: an
// operator can configure several providers (a metered API key, one or more CLI
// runners) and switch which one is in use without retyping configuration.
//
// All six routes are gated on org:settings:write, the same capability that
// already guards GET/PUT /admin/settings — these carry the same secrets (an
// LLM API key, a runner bearer token), so splitting them onto a narrower or
// wider capability would be inconsistent for no gain.
//
// Secrets are never returned. Each response reports apiKeySet/runnerTokenSet
// booleans only, the same contract llmSettingsView already uses.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/llm"
	"argus/internal/logging"
	"argus/internal/settings"
)

type aiProviderView struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Active bool   `json:"active"`

	BaseURL   string `json:"baseUrl"`
	Model     string `json:"model"`
	APIKeySet bool   `json:"apiKeySet"`

	RunnerURL      string `json:"runnerUrl"`
	Agent          string `json:"agent"`
	RunnerTokenSet bool   `json:"runnerTokenSet"`
}

type aiProvidersResponse struct {
	// Always a non-nil slice so a client never has to distinguish null from
	// empty — same normalization the settings response already applies to its
	// array fields.
	Providers []aiProviderView `json:"providers"`
	// ActiveProviderID is empty when nothing is active, which is a real state
	// (fresh install, or the active provider was deleted) and not an error.
	ActiveProviderID string `json:"activeProviderId"`
}

// aiProviderRequest is the create/update body. APIKey/RunnerToken follow the
// documented absent-vs-empty pointer contract: omitted means "leave unchanged"
// (on update), present-as-"" means "clear it".
type aiProviderRequest struct {
	Name string `json:"name"`
	Kind string `json:"kind"`

	BaseURL string  `json:"baseUrl"`
	Model   string  `json:"model"`
	APIKey  *string `json:"apiKey"`

	RunnerURL   string  `json:"runnerUrl"`
	Agent       string  `json:"agent"`
	RunnerToken *string `json:"runnerToken"`
}

func (r aiProviderRequest) toInput() settings.ProviderInput {
	return settings.ProviderInput{
		Name:        r.Name,
		Kind:        r.Kind,
		BaseURL:     r.BaseURL,
		Model:       r.Model,
		APIKey:      r.APIKey,
		RunnerURL:   r.RunnerURL,
		Agent:       r.Agent,
		RunnerToken: r.RunnerToken,
	}
}

func toProviderViews(ps []settings.AIProvider) ([]aiProviderView, string) {
	out := make([]aiProviderView, 0, len(ps))
	activeID := ""
	for _, p := range ps {
		if p.Active {
			activeID = p.ID
		}
		out = append(out, aiProviderView{
			ID: p.ID, Name: p.Name, Kind: p.Kind, Active: p.Active,
			BaseURL: p.BaseURL, Model: p.Model, APIKeySet: p.APIKeySet,
			RunnerURL: p.RunnerURL, Agent: p.Agent, RunnerTokenSet: p.RunnerTokenSet,
		})
	}
	return out, activeID
}

func (s *Server) handleListAIProviders(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	providers, err := settings.ListProviders(r.Context(), rc.Tx)
	if err != nil {
		logger.ErrorContext(r.Context(), "listing the AI providers failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list AI providers", "")
		return
	}
	views, activeID := toProviderViews(providers)
	writeJSON(w, http.StatusOK, aiProvidersResponse{Providers: views, ActiveProviderID: activeID})
}

func (s *Server) handleCreateAIProvider(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	var req aiProviderRequest
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}

	id, err := settings.CreateProvider(r.Context(), rc.Tx, rc.TenantID, req.toInput())
	if err != nil {
		s.writeProviderError(w, err, "Could not create the AI provider")
		return
	}

	s.auditProviderChange(r, rc, "ai_provider:create", id, map[string]any{"name": req.Name, "kind": req.Kind})
	s.respondWithProviders(w, r, rc, http.StatusCreated)
}

func (s *Server) handleUpdateAIProvider(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	id := r.PathValue("id")
	var req aiProviderRequest
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}

	if err := settings.UpdateProvider(r.Context(), rc.Tx, id, req.toInput()); err != nil {
		s.writeProviderError(w, err, "Could not update the AI provider")
		return
	}

	s.auditProviderChange(r, rc, "ai_provider:update", id, map[string]any{"name": req.Name, "kind": req.Kind})
	s.respondWithProviders(w, r, rc, http.StatusOK)
}

func (s *Server) handleDeleteAIProvider(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	id := r.PathValue("id")

	if err := settings.DeleteProvider(r.Context(), rc.Tx, id); err != nil {
		s.writeProviderError(w, err, "Could not delete the AI provider")
		return
	}

	// Worth auditing loudly: deleting the active provider silently stops all
	// analysis until another is activated.
	s.auditProviderChange(r, rc, "ai_provider:delete", id, nil)
	s.respondWithProviders(w, r, rc, http.StatusOK)
}

func (s *Server) handleActivateAIProvider(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	id := r.PathValue("id")

	if err := settings.ActivateProvider(r.Context(), rc.Tx, id); err != nil {
		s.writeProviderError(w, err, "Could not activate the AI provider")
		return
	}

	s.auditProviderChange(r, rc, "ai_provider:activate", id, nil)
	s.respondWithProviders(w, r, rc, http.StatusOK)
}

// respondWithProviders re-reads and returns the full list after a mutation, so
// a client never has to guess what changed (an activate flips two rows' Active
// flag; a delete may clear the active pointer). Same "reflect the new state
// back" convention handlePutSettings already follows.
func (s *Server) respondWithProviders(w http.ResponseWriter, r *http.Request, rc *requestContext, status int) {
	providers, err := settings.ListProviders(r.Context(), rc.Tx)
	if err != nil {
		logger.ErrorContext(r.Context(), "reading back the AI providers failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Change applied but could not be read back", "")
		return
	}
	views, activeID := toProviderViews(providers)
	writeJSON(w, status, aiProvidersResponse{Providers: views, ActiveProviderID: activeID})
}

// writeProviderError maps this package's sentinel errors onto the right status
// so a caller can distinguish "you sent something invalid" (400), "that id
// doesn't exist" (404) and "that name is taken" (409) without parsing prose.
func (s *Server) writeProviderError(w http.ResponseWriter, err error, title string) {
	switch {
	case errors.Is(err, settings.ErrProviderNotFound):
		writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "AI provider not found", "")
	case errors.Is(err, settings.ErrDuplicateProviderName):
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/conflict", "An AI provider with that name already exists", "Pick a different name.")
	default:
		// Validation errors from ProviderInput.Validate carry a precise,
		// caller-actionable message ("baseUrl is required for an api
		// provider"), so they're surfaced verbatim as a 400. Anything else is
		// logged and generalized.
		if isProviderValidationError(err) {
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", title, err.Error())
			return
		}
		logger.Error("an AI-provider request failed", slog.String("title", title), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", title, "")
	}
}

// isProviderValidationError distinguishes a Validate() failure from a database
// error. Validate returns bare errors.New/fmt.Errorf values that are not
// wrapped by any package-level sentinel, and every DB path in
// internal/settings wraps with a "settings: ..." prefix — so the absence of
// that prefix is the signal. Crude but honest, and it fails safe: an
// unrecognized error becomes a 500, never a 400 that implies the caller was at
// fault.
func isProviderValidationError(err error) bool {
	// strings.HasPrefix rather than a length guard plus a slice: the guard
	// here used to read `len(msg) < 7 || msg[:10] != "settings: "`, where the
	// bound was 7 and the slice was 10, so any error message of length 7, 8
	// or 9 sliced out of range and panicked inside a live handler. No
	// currently-reachable message is that short, which is exactly why it
	// survived. Behaviour is identical for every length that did not panic.
	return !strings.HasPrefix(err.Error(), "settings: ")
}

func (s *Server) auditProviderChange(r *http.Request, rc *requestContext, action, providerID string, details map[string]any) {
	capability := authz.CapOrgSettingsWrite
	// "action" as a Details key, matching this package's existing convention
	// (see handleGenerateDemoData) — audit.Event has no dedicated action
	// field, and internal/api/audit.go's summarizer already reads this key.
	d := map[string]any{"action": action, "providerId": providerID}
	for k, v := range details {
		if v != "" && v != nil {
			d[k] = v
		}
	}
	if err := audit.RecordEvent(r.Context(), rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		Outcome:         audit.OutcomeSuccess,
		Details:         d,
	}); err != nil {
		// Logged, not fatal: the change is already applied in this
		// transaction, and failing the request now would report an error for
		// something that succeeded.
		logger.ErrorContext(r.Context(), "recording an AI-provider change in the audit log failed",
			slog.String("action", action), slog.String("provider_id", providerID), logging.Err(err))
	}
}

// decodeJSON is a small local helper so each handler above stays one
// straight-line read. Writes the 400 itself and reports whether the caller
// should stop.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}

// aiProviderTestResult is the success body of POST
// /admin/ai-providers/{id}/test. Failures are RFC 9457 problems instead (see
// handleTestAIProvider), so this shape only ever describes a pass.
//
// Carries no configuration back at all — not the base URL, not the model as
// configured, and obviously not the credential. The one echoed value is the
// model the PROVIDER named in its own response, which is diagnostic rather
// than a reflection of stored state (see llm.ProbeResult.Model).
type aiProviderTestResult struct {
	OK   bool   `json:"ok"`
	Kind string `json:"kind"`
	// Summary and Detail are the same two-part shape the failure problem uses
	// (title/detail), so the UI renders a pass and a failure the same way.
	Summary string `json:"summary"`
	Detail  string `json:"detail"`
	// Caveat is what the test did NOT prove. Always populated on a pass, and
	// always shown: the one genuinely dangerous outcome of this feature would
	// be a green tick read as "analysis will work".
	Caveat    string `json:"caveat,omitempty"`
	Model     string `json:"model,omitempty"`
	TokensIn  int    `json:"tokensIn,omitempty"`
	TokensOut int    `json:"tokensOut,omitempty"`
	LatencyMs int    `json:"latencyMs"`
}

// handleTestAIProvider is POST /api/v1/admin/ai-providers/{id}/test. Requires
// org:settings:write, the same capability as every other route in this file.
//
// Modelled directly on handleCheckRepositoryBinding (internal/api/repositories.go):
// prove the integration works NOW, before an incident depends on it, and pass
// the specific reason it does not straight through to the operator rather than
// collapsing every failure into "check failed". The reasoning there applies
// verbatim here — the first time anyone learns an AI provider is misconfigured
// should not be a failed analysis during an outage.
//
// Three things worth stating about the gate:
//
// It is org:settings:write rather than a new capability, because the ability to
// *change* this configuration already implies the ability to break it, and
// anyone who can rewrite a provider can already cause exactly the outbound
// request this route makes. A narrower read-only capability would be a fiction:
// the route spends money.
//
// It costs money, so it is audited on **every** call including failures — see
// internal/llm's cost note for the (tiny) per-invocation figure. An outbound
// paid request triggered from the UI must be attributable to a person.
//
// It is never called except by a human clicking the button. Nothing in the hub
// invokes it on save, on activate, on a timer, or on page load.
func (s *Server) handleTestAIProvider(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	id := r.PathValue("id")

	// GetProbeConfig is the one reader in internal/settings that returns real
	// secrets. They are handed to the probe and never touched again here: the
	// cfg value is deliberately not logged, not echoed, and not carried into
	// either the audit record or the response.
	cfg, err := settings.GetProbeConfig(r.Context(), rc.Tx, id)
	if err != nil {
		s.writeProviderError(w, err, "Could not test the AI provider")
		return
	}

	result := llm.ProbeProvider(r.Context(), nil, llm.ProbeTarget{
		Kind:        cfg.Kind,
		BaseURL:     cfg.BaseURL,
		Model:       cfg.Model,
		APIKey:      cfg.APIKey,
		RunnerURL:   cfg.RunnerURL,
		RunnerToken: cfg.RunnerToken,
		Agent:       cfg.Agent,
		// The same operator allowlist internal/llm.NewProvider dials with,
		// from the same source — so "test connection" and a real analysis
		// agree about which private destinations are permitted. Without it
		// this button would report a refusal for an endpoint the real path
		// reaches, which is the mirror image of the false green
		// aiProviderOutboundPolicy's comment warns about and just as
		// misleading.
		PrivateDestinations: settings.PrivateDestinationSource(s.db.Pool),
	})

	// A cli provider can be configured perfectly, pass its probe, and still be
	// unusable on THIS hub, because the CLI backend additionally needs an MCP
	// listener that only ARGUS_MCP_ADDR turns on. That is a hub-level fact the
	// probe cannot see, and the existing UI only warns about it for the
	// *active* provider — so a passing test on an inactive cli provider would
	// otherwise be quietly incomplete. Appended to the caveat rather than
	// turned into a failure: nothing about the provider is wrong.
	if result.OK && cfg.Kind == settings.KindCLI && !s.cliBackendAvailable() {
		result.Caveat += " Separately: this hub cannot run a cli provider at all, because the CLI backend " +
			"needs an MCP listener that this hub was not started with (ARGUS_MCP_ADDR). The runner is fine; " +
			"analysis through it would still fail until the hub is restarted with that set."
	}

	// Audited on both outcomes, with the classification but never any
	// configuration value. "outcome" carries the machine-readable kind so an
	// audit reader can see *why* a test failed without the prose.
	//
	// The two paths differ, and the reason is a trap this codebase already
	// documented once: completeRequest ROLLS BACK the request transaction for
	// any response >= 400 (internal/api/middleware.go), so an audit row written
	// on rc.Tx before a 422 is silently discarded. Caught by checking the
	// audit table after a live failing test, not by reading the code.
	//
	// A failed test is exactly the outcome most worth having a record of — it
	// is the one someone will be asked about later — so the failure path
	// records in its own transaction, the same way recordCapabilityDenial does
	// and for precisely the same reason.
	auditDetails := map[string]any{
		"kind":    cfg.Kind,
		"outcome": result.Kind,
		"passed":  result.OK,
	}

	if !result.OK {
		s.auditProviderTestOutcome(r, rc, id, auditDetails)
		// 422 and a dedicated problem type, matching
		// handleCheckRepositoryBinding's "this integration could not be used"
		// shape: the request itself was well-formed and authorized, and the
		// thing it tested does not work. The kind travels as an RFC 9457
		// extension member so the UI can branch on it structurally rather
		// than matching on the message (writeProblemWithExtras' own contract).
		writeProblemWithExtras(w, http.StatusUnprocessableEntity,
			"https://argus.io/errors/ai-provider-unusable",
			result.Summary, result.Detail,
			map[string]any{"kind": result.Kind, "latencyMs": result.LatencyMs})
		return
	}

	s.auditProviderChange(r, rc, "ai_provider:test", id, auditDetails)
	writeJSON(w, http.StatusOK, aiProviderTestResult{
		OK:        true,
		Kind:      result.Kind,
		Summary:   result.Summary,
		Detail:    result.Detail,
		Caveat:    result.Caveat,
		Model:     result.Model,
		TokensIn:  result.TokensIn,
		TokensOut: result.TokensOut,
		LatencyMs: result.LatencyMs,
	})
}

// auditProviderTestOutcome records a connection test whose response will be a
// 4xx, in a transaction of its own.
//
// Necessary because completeRequest rolls back the request transaction for any
// response >= 400, which would throw the record away. Mirrors
// recordCapabilityDenial (internal/api/middleware.go) exactly, including the
// data.SetRequestScope call — a fresh transaction has no RLS scope set, and an
// insert into a FORCE ROW LEVEL SECURITY table without one is the mistake this
// codebase has already made three times.
//
// The outcome recorded is audit.OutcomeSuccess, not OutcomeError: the hub did
// exactly what it was asked and got a clean answer back. OutcomeError is
// reserved for a genuine internal failure while attempting an action (see
// internal/audit's own note on the closed set), and a provider that is
// misconfigured is not that. What the test FOUND lives in details.outcome.
//
// Failures here are logged and dropped rather than failing the request: the
// caller is already being told their provider does not work, and replacing that
// specific, actionable answer with "could not record this" would be a strictly
// worse response.
func (s *Server) auditProviderTestOutcome(r *http.Request, rc *requestContext, providerID string, details map[string]any) {
	ctx := r.Context()
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "recording an AI-provider test outcome: begin transaction failed", slog.String("provider_id", providerID), logging.Err(err))
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := data.SetRequestScope(ctx, tx, rc.TenantID, nil); err != nil {
		logger.ErrorContext(ctx, "recording an AI-provider test outcome: set request scope failed", slog.String("provider_id", providerID), logging.Err(err))
		return
	}

	capability := authz.CapOrgSettingsWrite
	d := map[string]any{"action": "ai_provider:test", "providerId": providerID}
	for k, v := range details {
		d[k] = v
	}
	if err := audit.RecordEvent(ctx, tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		Outcome:         audit.OutcomeSuccess,
		Details:         d,
	}); err != nil {
		logger.ErrorContext(ctx, "recording an AI-provider test outcome: audit write failed", slog.String("provider_id", providerID), logging.Err(err))
		return
	}
	if err := tx.Commit(ctx); err != nil {
		logger.ErrorContext(ctx, "recording an AI-provider test outcome: commit failed", slog.String("provider_id", providerID), logging.Err(err))
	}
}
