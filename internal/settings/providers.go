package settings

// AI provider management — the `ai_providers` table from migration 000034.
//
// Before that migration there was exactly one provider, stored as columns on
// org_settings. Now there are many, and one of them is active. The important
// property this file preserves: **Config's resolved provider fields keep their
// old shape and meaning.** Resolve fills LLMProviderKind/LLMBaseURL/... from
// whichever provider is active, so internal/llm's Router, Provider and
// CLIInvestigator required no changes at all when this landed — they still ask
// "what is configured right now" and get one answer.
//
// That is why this file exists separately from settings.go: the CRUD surface
// for managing the *set* of providers is a different concern from resolving the
// *active* one, and only the latter is on the investigation hot path.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"

	"argus/internal/domain"
)

// Provider kinds. Kept as the same two string values migration 000033
// introduced and 000034's CHECK constraint still enforces, so nothing that
// already persisted 'api'/'cli' needs translating.
const (
	KindAPI = ProviderKindAPI
	KindCLI = ProviderKindCLI
)

// ErrProviderNotFound is returned by Get/Update/Delete/Activate for an id that
// doesn't exist (or belongs to another tenant, which RLS makes
// indistinguishable — deliberately, since telling a caller "that exists but
// isn't yours" is itself a leak).
var ErrProviderNotFound = errors.New("settings: ai provider not found")

// ErrDuplicateProviderName is returned when a name collides with an existing
// provider's, case-insensitively (the unique index is on lower(name)).
var ErrDuplicateProviderName = errors.New("settings: an AI provider with that name already exists")

// AIProvider is one configured provider as read back for management/listing.
//
// Secrets are never carried here — only the ...Set booleans, the same contract
// Config uses for LLMAPIKeySet/CLIRunnerTokenSet and for the same reason: this
// struct is serialized to an admin UI, and a field that holds a real key will
// eventually be logged or echoed by something.
type AIProvider struct {
	ID   string
	Name string
	Kind string

	// kind == KindAPI
	BaseURL   string
	Model     string
	APIKeySet bool

	// kind == KindCLI
	RunnerURL      string
	Agent          string
	RunnerTokenSet bool

	// Active reports whether org_settings currently points at this provider.
	// Derived at read time rather than stored per row — see migration 000034's
	// comment on why the pointer lives on org_settings.
	Active bool
}

// ProviderInput is a create/update request. Pointer fields follow the same
// absent-vs-empty contract as LLMUpdate.APIKey: nil means "leave the stored
// value unchanged" (meaningless on create, where nil simply stores nothing),
// non-nil means "set it to exactly this", and a non-nil "" explicitly clears.
type ProviderInput struct {
	Name string
	Kind string

	BaseURL string
	Model   string
	APIKey  *string

	RunnerURL   string
	Agent       string
	RunnerToken *string
}

// Validate checks a provider input independently of the database, so a bad
// request fails at the edge with a precise message instead of as a CHECK
// constraint violation.
//
// Mirrors migration 000034's ai_providers_kind_fields constraint deliberately:
// the database is the backstop, this is the error message a human reads.
func (in ProviderInput) Validate() error {
	if strings.TrimSpace(in.Name) == "" {
		return errors.New("name is required")
	}
	switch in.Kind {
	case KindAPI:
		if strings.TrimSpace(in.BaseURL) == "" {
			return errors.New("baseUrl is required for an api provider")
		}
	case KindCLI:
		if strings.TrimSpace(in.RunnerURL) == "" {
			return errors.New("runnerUrl is required for a cli provider")
		}
		if a := in.Agent; a != "" && a != "claude" && a != "codex" {
			return fmt.Errorf("agent must be \"claude\" or \"codex\", got %q", a)
		}
	default:
		return fmt.Errorf("kind must be %q or %q, got %q", KindAPI, KindCLI, in.Kind)
	}
	return nil
}

// clearedForKind is BUGS.md 125's second, additive fix: it returns in with
// every field the OTHER kind would need forced to an explicit-clear value,
// for whichever kind in.Kind actually is.
//
// Validate above only checks that the fields a given kind NEEDS are
// present; it says nothing about the fields the OTHER kind would need, so a
// client that always sends the full form (both api and cli fields
// populated), or a row that started as one kind and was edited into the
// other without its old fields being blanked, could accumulate values from
// a kind the row no longer is. Migration 000034's own
// ai_providers_kind_fields CHECK permits exactly this — it only requires
// the active kind's fields to be present, never the inactive kind's fields
// to be absent. That leftover baggage is what settings.go's resolve() used
// to surface unconditionally into Config.LLMBaseURL/LLMModel/LLMAPIKey
// regardless of the row's actual kind (BUGS.md 125's root finding, now
// fixed separately by gating resolve() on LLMProviderKind == "api"). This
// is the write-time half: stop the baggage from accumulating in the first
// place, rather than only hiding it once read back.
//
// RunnerToken/APIKey are forced to a non-nil pointer to "" — the "explicitly
// clear the stored secret" value both CreateProvider and UpdateProvider
// already give a non-nil-but-empty pointer (see derefOrNil) — rather than
// left nil ("leave whatever is stored alone"), specifically so a kind
// switch clears the OTHER kind's secret even when the caller's request
// never mentioned it at all.
func (in ProviderInput) clearedForKind() ProviderInput {
	out := in
	cleared := ""
	switch in.Kind {
	case KindAPI:
		out.RunnerURL = ""
		out.Agent = ""
		out.RunnerToken = &cleared
	case KindCLI:
		out.BaseURL = ""
		out.Model = ""
		out.APIKey = &cleared
	}
	return out
}

const providerSelect = `
	SELECT p.id, p.name, p.kind,
	       COALESCE(p.base_url, ''), COALESCE(p.model, ''), (p.api_key IS NOT NULL AND p.api_key <> ''),
	       COALESCE(p.runner_url, ''), COALESCE(p.agent, ''), (p.runner_token IS NOT NULL AND p.runner_token <> ''),
	       -- IS NOT DISTINCT FROM, not "=", because active_ai_provider_id is
	       -- NULL whenever no provider is active — which is a normal state, and
	       -- one this table's own ON DELETE SET NULL deliberately produces when
	       -- the active provider is deleted. Plain "=" against NULL yields SQL
	       -- NULL rather than false, which fails to scan into a bool and made
	       -- every list read error out immediately after deleting the active
	       -- provider. Found by testing that exact path.
	       (s.active_ai_provider_id IS NOT DISTINCT FROM p.id)
	  FROM ai_providers p
	  CROSS JOIN org_settings s`

// ListProviders returns every configured provider, active one flagged,
// ordered by name so a picker's order is stable across reloads.
func ListProviders(ctx context.Context, q querier) ([]AIProvider, error) {
	rows, err := q.Query(ctx, providerSelect+` WHERE s.id = $1 ORDER BY lower(p.name)`, singletonID)
	if err != nil {
		return nil, fmt.Errorf("settings: list ai providers: %w", err)
	}
	defer rows.Close()

	var out []AIProvider
	for rows.Next() {
		var p AIProvider
		if err := rows.Scan(&p.ID, &p.Name, &p.Kind, &p.BaseURL, &p.Model, &p.APIKeySet,
			&p.RunnerURL, &p.Agent, &p.RunnerTokenSet, &p.Active); err != nil {
			return nil, fmt.Errorf("settings: scan ai provider: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("settings: list ai providers: %w", err)
	}
	return out, nil
}

// CreateProvider inserts a provider and returns its id.
//
// If no provider is active yet, the new one becomes active. That makes the
// common first-run path ("add a provider") work without a second explicit
// activate call, while never silently stealing the active slot from an
// existing provider.
func CreateProvider(ctx context.Context, tx pgx.Tx, tenantID string, in ProviderInput) (string, error) {
	if err := in.Validate(); err != nil {
		return "", err
	}
	in = in.clearedForKind()
	id := domain.NewID(domain.PrefixAIProvider)

	_, err := tx.Exec(ctx, `
		INSERT INTO ai_providers (id, tenant_id, name, kind, base_url, model, api_key, runner_url, runner_token, agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		id, tenantID, strings.TrimSpace(in.Name), in.Kind,
		nilIfEmpty(in.BaseURL), nilIfEmpty(in.Model), derefOrNil(in.APIKey),
		nilIfEmpty(in.RunnerURL), derefOrNil(in.RunnerToken), nilIfEmpty(in.Agent))
	if err != nil {
		if isUniqueViolation(err) {
			return "", ErrDuplicateProviderName
		}
		return "", fmt.Errorf("settings: create ai provider: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`UPDATE org_settings SET active_ai_provider_id = $1, updated_at = now()
		  WHERE id = $2 AND active_ai_provider_id IS NULL`, id, singletonID); err != nil {
		return "", fmt.Errorf("settings: activate first ai provider: %w", err)
	}
	return id, nil
}

// UpdateProvider applies a full update to one provider. Kind is updatable —
// converting an api provider into a cli one is a legitimate thing to want, and
// refusing it would only make the operator delete and recreate, losing the
// name and the active pointer for no benefit.
func UpdateProvider(ctx context.Context, tx pgx.Tx, id string, in ProviderInput) error {
	if err := in.Validate(); err != nil {
		return err
	}
	in = in.clearedForKind()
	// Secrets follow the pointer contract: a nil APIKey/RunnerToken leaves
	// whatever is stored alone, so an admin can rename a provider without
	// re-pasting its key.
	apiKeyProvided := in.APIKey != nil
	runnerTokenProvided := in.RunnerToken != nil

	tag, err := tx.Exec(ctx, `
		UPDATE ai_providers SET
			name         = $1,
			kind         = $2,
			base_url     = $3,
			model        = $4,
			api_key      = CASE WHEN $5 THEN $6::text ELSE api_key END,
			runner_url   = $7,
			agent        = $8,
			runner_token = CASE WHEN $9 THEN $10::text ELSE runner_token END,
			updated_at   = now()
		WHERE id = $11`,
		strings.TrimSpace(in.Name), in.Kind,
		nilIfEmpty(in.BaseURL), nilIfEmpty(in.Model),
		apiKeyProvided, derefOrNil(in.APIKey),
		nilIfEmpty(in.RunnerURL), nilIfEmpty(in.Agent),
		runnerTokenProvided, derefOrNil(in.RunnerToken),
		id)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicateProviderName
		}
		return fmt.Errorf("settings: update ai provider: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrProviderNotFound
	}
	return nil
}

// DeleteProvider removes a provider. Deleting the active one is allowed and
// leaves no provider active (the FK is ON DELETE SET NULL) — internal/llm then
// reports ErrNotConfigured, which every caller already handles.
func DeleteProvider(ctx context.Context, tx pgx.Tx, id string) error {
	tag, err := tx.Exec(ctx, `DELETE FROM ai_providers WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("settings: delete ai provider: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrProviderNotFound
	}
	return nil
}

// ActivateProvider points org_settings at one provider. Takes effect on the
// very next investigation — nothing caches the resolved provider (see
// Resolve's own contract), so no restart is needed.
func ActivateProvider(ctx context.Context, tx pgx.Tx, id string) error {
	// Checked explicitly rather than relying on the FK: a foreign-key
	// violation would surface as a 500, where "that provider doesn't exist" is
	// a 404 the caller can act on.
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ai_providers WHERE id = $1)`, id).Scan(&exists); err != nil {
		return fmt.Errorf("settings: look up ai provider: %w", err)
	}
	if !exists {
		return ErrProviderNotFound
	}
	if _, err := tx.Exec(ctx,
		`UPDATE org_settings SET active_ai_provider_id = $1, updated_at = now() WHERE id = $2`,
		id, singletonID); err != nil {
		return fmt.Errorf("settings: activate ai provider: %w", err)
	}
	return nil
}

// UpdateActiveProvider applies an LLMUpdate to whichever provider is currently
// active. This is what keeps PUT /api/v1/admin/settings' existing "llm" section
// working after 000034: its documented meaning — "change the AI configuration
// in use" — maps cleanly onto "edit the active provider", so existing callers
// (scripts/smoke-test.sh, scripts/eval-harness) needed no changes.
//
// BUGS.md 92: when nothing is active yet — a genuinely fresh install, before
// POST /admin/ai-providers or this legacy path has ever run against this
// database — this used to return ErrProviderNotFound, which the API layer had
// no special handling for and so surfaced as a bare 500 ("ai provider not
// found") on an otherwise perfectly valid request. Whether that happened
// depended entirely on which endpoint a caller happened to hit first against
// a fresh database, which is exactly the fragility the bug asked to remove.
// This now creates and activates a provider from the update instead, by
// delegating to CreateProvider — the same function POST /admin/ai-providers
// itself calls, so "the first provider this installation has ever had" is
// exactly one code path regardless of which endpoint triggered it, and
// CreateProvider's own "activate only if nothing is active yet" guard (its
// own doc comment) means a second legacy PUT against an installation that
// already has an active provider still takes the ordinary edit-in-place
// branch below, never a second create.
//
// The new provider is named "Default", matching migration 000034's own
// backfill naming for the single pre-existing provider it created out of
// org_settings' old single-provider columns — this path is the same
// "there has only ever been one provider" situation, just reached without a
// migration ever having run.
func UpdateActiveProvider(ctx context.Context, tx pgx.Tx, tenantID string, in LLMUpdate) error {
	var id, kind, name string
	err := tx.QueryRow(ctx, `
		SELECT p.id, p.kind, p.name FROM ai_providers p
		  JOIN org_settings s ON s.active_ai_provider_id = p.id
		 WHERE s.id = $1`, singletonID).Scan(&id, &kind, &name)
	if errors.Is(err, pgx.ErrNoRows) {
		// Nothing configured and nothing to configure: clearing a section that
		// was never set is a no-op, not an attempt to create an empty provider.
		if in.BaseURL == "" && in.CLIRunnerURL == "" {
			return nil
		}
		_, err := CreateProvider(ctx, tx, tenantID, ProviderInput{
			Name:        "Default",
			Kind:        NormalizeProviderKind(in.ProviderKind),
			BaseURL:     in.BaseURL,
			Model:       in.Model,
			APIKey:      in.APIKey,
			RunnerURL:   in.CLIRunnerURL,
			Agent:       in.CLIAgent,
			RunnerToken: in.CLIRunnerToken,
		})
		return err
	}
	if err != nil {
		return fmt.Errorf("settings: look up active ai provider: %w", err)
	}

	// The legacy shape carries no name and may carry no kind; preserve both
	// from the stored row so a partial update can't blank them.
	next := ProviderInput{
		Name:        name,
		Kind:        kind,
		BaseURL:     in.BaseURL,
		Model:       in.Model,
		APIKey:      in.APIKey,
		RunnerURL:   in.CLIRunnerURL,
		Agent:       in.CLIAgent,
		RunnerToken: in.CLIRunnerToken,
	}
	if in.ProviderKind != "" {
		next.Kind = in.ProviderKind
	}
	// A legacy caller sending only {baseUrl, model, apiKey} leaves the cli
	// fields empty; for a cli-kind provider that would fail Validate. Fill
	// them from the stored row so the legacy path can never accidentally
	// invalidate a provider it wasn't trying to reconfigure.
	if next.Kind == KindCLI && next.RunnerURL == "" {
		if err := tx.QueryRow(ctx, `SELECT COALESCE(runner_url, ''), COALESCE(agent, '') FROM ai_providers WHERE id = $1`, id).
			Scan(&next.RunnerURL, &next.Agent); err != nil {
			return fmt.Errorf("settings: read active provider cli fields: %w", err)
		}
	}
	if next.Kind == KindAPI && next.BaseURL == "" {
		// Same in reverse: a caller switching kind to api without supplying a
		// base URL has nothing usable, and Validate will say so clearly.
		if err := tx.QueryRow(ctx, `SELECT COALESCE(base_url, ''), COALESCE(model, '') FROM ai_providers WHERE id = $1`, id).
			Scan(&next.BaseURL, &next.Model); err != nil {
			return fmt.Errorf("settings: read active provider api fields: %w", err)
		}
		if in.Model != "" {
			next.Model = in.Model
		}
	}
	return UpdateProvider(ctx, tx, id, next)
}

func derefOrNil(s *string) *string {
	if s == nil {
		return nil
	}
	return nilIfEmpty(*s)
}

// isUniqueViolation reports whether err is Postgres' 23505 unique_violation.
// Matched on the SQLSTATE code rather than the message text, which is
// locale- and version-dependent.
func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}

// ProbeConfig is one provider's configuration INCLUDING its secrets, read for
// the single purpose of making a live connection test against that provider
// (internal/llm.ProbeProvider, behind POST /admin/ai-providers/{id}/test).
//
// Deliberately a **different type** from AIProvider rather than a flag on it.
// AIProvider is what the admin API serializes, which is exactly why it carries
// only APIKeySet/RunnerTokenSet booleans — a struct that holds a real key will
// eventually be logged or echoed by something (its own doc comment says so).
// Keeping the secret-bearing shape separate and unexported-in-spirit means the
// existing list/create/update paths cannot start leaking a key by accident, and
// a reviewer can see at a glance which of the two a function returns.
//
// **No caller may return this struct, or any field of it, to a client.** Its
// one legitimate consumer hands it to a probe and keeps only the probe's
// classified result.
type ProbeConfig struct {
	ID   string
	Name string
	Kind string

	BaseURL string
	Model   string
	APIKey  string

	RunnerURL   string
	Agent       string
	RunnerToken string
}

// GetProbeConfig reads one provider by id, applying the same env-var fallback
// Resolve applies to the active provider.
//
// The fallback is the subtle part and it is load-bearing. Resolve computes each
// provider field as firstNonEmpty(column, env-var), so a hub configured
// entirely by ARGUS_LLM_* env vars has provider rows with NULL columns that
// nonetheless work perfectly once active. A probe that read only the columns
// would report "no API key" for such a hub — a confident, wrong answer about a
// working configuration, which is the worst thing a test button can do. The
// fallback is applied per field, exactly as resolve() does it, so what gets
// probed is what an investigation would actually use.
//
// Note this is true for any provider, not only the active one: the env tier is
// per field and has nothing to do with which row is active, so a provider that
// tests clean here will still have that key once it is activated.
func GetProbeConfig(ctx context.Context, q querier, id string) (ProbeConfig, error) {
	var name, kind, baseURL, model, apiKey, runnerURL, agent, runnerToken string
	err := q.QueryRow(ctx, `
		SELECT name, kind,
		       COALESCE(base_url, ''), COALESCE(model, ''), COALESCE(api_key, ''),
		       COALESCE(runner_url, ''), COALESCE(agent, ''), COALESCE(runner_token, '')
		  FROM ai_providers WHERE id = $1`, id).
		Scan(&name, &kind, &baseURL, &model, &apiKey, &runnerURL, &agent, &runnerToken)
	if errors.Is(err, pgx.ErrNoRows) {
		// Also the answer for a provider belonging to another tenant, which
		// RLS makes indistinguishable — the same deliberate choice
		// ErrProviderNotFound's own doc comment records.
		return ProbeConfig{}, ErrProviderNotFound
	}
	if err != nil {
		return ProbeConfig{}, fmt.Errorf("settings: read ai provider for probe: %w", err)
	}

	return ProbeConfig{
		ID:   id,
		Name: name,
		// Normalized for the same reason resolve() normalizes it: "" means api
		// on a row predating migration 000033, and no consumer should have to
		// remember that.
		Kind:        NormalizeProviderKind(kind),
		BaseURL:     orEnv(baseURL, "ARGUS_LLM_BASE_URL"),
		Model:       orEnv(model, "ARGUS_LLM_MODEL"),
		APIKey:      orEnv(apiKey, "ARGUS_LLM_API_KEY"),
		RunnerURL:   orEnv(runnerURL, "ARGUS_CLI_RUNNER_URL"),
		Agent:       orEnv(agent, "ARGUS_CLI_AGENT"),
		RunnerToken: orEnv(runnerToken, "ARGUS_CLI_RUNNER_TOKEN"),
	}, nil
}

// orEnv is firstNonEmpty for a non-pointer column already COALESCEd to "".
// Kept separate rather than reusing firstNonEmpty so the query above can
// scan into plain strings, which is what makes it readable.
func orEnv(dbVal, envName string) string {
	if dbVal != "" {
		return dbVal
	}
	return os.Getenv(envName)
}
