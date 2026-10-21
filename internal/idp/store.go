package idp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/domain"
	"argus/internal/secretbox"
)

// secretPurpose is the encrypted_secrets.purpose value for an OIDC client
// secret. That table's own comment establishes purpose strings as how an
// operator inventories secrets without decrypting them, so this is a stable
// identifier, not a label.
const secretPurpose = "oidc_client_secret"

// ErrNoSuchState is returned when a callback presents a state value with no
// matching row: expired, already consumed, or never issued. All three are the
// same answer to the caller — refuse the login — and are deliberately not
// distinguished, because telling a caller which one it was tells an attacker
// whether a state value ever existed.
var ErrNoSuchState = errors.New("idp: no such login state")

// Store is the database half of identity-provider support.
//
// It mirrors internal/scm.Store: it holds the envelope-encryption keeper and
// takes a pgx.Tx per call, so it owns no connection and every query runs
// inside a transaction the caller has already scoped with
// internal/data.SetRequestScope. That is not a convention to be polite about
// — every table this file touches has FORCE ROW LEVEL SECURITY, and this
// codebase has shipped three separate RLS-scoping bugs, all of them in auth
// code (the bootstrap insert, refresh-token issuance, refresh-token
// rotation). A query here on an unscoped transaction returns zero rows rather
// than an error, which looks exactly like "no provider is configured".
type Store struct {
	keeper *secretbox.Keeper
}

func NewStore(keeper *secretbox.Keeper) *Store { return &Store{keeper: keeper} }

// GroupMapping is one IdP-group-to-ARGUS-role rule.
type GroupMapping struct {
	ID        string
	GroupName string
	RoleID    string
	Scope     []byte // raw jsonb, copied verbatim into grants.scope
}

// ProviderRow is a stored provider without its secret. This is the shape
// returned by every read path, so the secret cannot leak through one by
// accident.
type ProviderRow struct {
	ID          string
	DisplayName string
	Issuer      string
	ClientID    string
	Scopes      []string
	GroupsClaim string
	RedirectURI string
	Enabled     bool
	HasSecret   bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ListProviders returns every configured provider, secrets excluded.
func (s *Store) ListProviders(ctx context.Context, tx pgx.Tx, tenantID string) ([]ProviderRow, error) {
	rows, err := tx.Query(ctx,
		`SELECT id, display_name, issuer, client_id, scopes, groups_claim, redirect_uri, enabled,
		        client_secret_ref IS NOT NULL, created_at, updated_at
		   FROM identity_providers
		  WHERE tenant_id = $1
		  ORDER BY created_at`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("idp: list providers: %w", err)
	}
	defer rows.Close()

	var out []ProviderRow
	for rows.Next() {
		var p ProviderRow
		if err := rows.Scan(&p.ID, &p.DisplayName, &p.Issuer, &p.ClientID, &p.Scopes,
			&p.GroupsClaim, &p.RedirectURI, &p.Enabled, &p.HasSecret, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("idp: scan provider: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// EnabledProviders returns only the providers a login may use.
//
// The login screen calls this UNAUTHENTICATED, so it returns nothing that is
// not already public: a display name and an id. The issuer and client id are
// not secret either, but there is no reason to publish them, so they are not
// part of what the caller renders.
func (s *Store) EnabledProviders(ctx context.Context, tx pgx.Tx, tenantID string) ([]ProviderRow, error) {
	all, err := s.ListProviders(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	var out []ProviderRow
	for _, p := range all {
		if p.Enabled {
			out = append(out, p)
		}
	}
	return out, nil
}

// LoadConfig returns a provider with its client secret decrypted, ready to
// hand to Discover.
//
// The caller must zero the returned ClientSecret when finished; secretbox.Zero
// exists for that. Only the login path needs this — every other read uses
// ListProviders and never sees the secret.
func (s *Store) LoadConfig(ctx context.Context, tx pgx.Tx, tenantID, providerID string) (Config, error) {
	var (
		cfg       Config
		secretRef *string
		enabled   bool
	)
	err := tx.QueryRow(ctx,
		`SELECT id, display_name, issuer, client_id, scopes, groups_claim, redirect_uri, enabled, client_secret_ref
		   FROM identity_providers
		  WHERE tenant_id = $1 AND id = $2`, tenantID, providerID).
		Scan(&cfg.ID, &cfg.DisplayName, &cfg.Issuer, &cfg.ClientID, &cfg.Scopes,
			&cfg.GroupsClaim, &cfg.RedirectURI, &enabled, &secretRef)
	if errors.Is(err, pgx.ErrNoRows) {
		return Config{}, fmt.Errorf("idp: provider %s not found", providerID)
	}
	if err != nil {
		return Config{}, fmt.Errorf("idp: load provider: %w", err)
	}
	if !enabled {
		// Checked here rather than only at the call site so a disabled
		// provider cannot authenticate anyone even if a future caller forgets
		// to filter. `enabled` is the switch an operator uses to turn SSO off
		// in a hurry; it has to hold at the lowest layer that can enforce it.
		return Config{}, fmt.Errorf("idp: provider %s is disabled", providerID)
	}

	if secretRef != nil {
		plaintext, err := s.openSecret(ctx, tx, tenantID, *secretRef)
		if err != nil {
			return Config{}, err
		}
		cfg.ClientSecret = string(plaintext)
		secretbox.Zero(plaintext)
	}
	return cfg, nil
}

func (s *Store) openSecret(ctx context.Context, tx pgx.Tx, tenantID, id string) ([]byte, error) {
	var ciphertext, keyVersion string
	err := tx.QueryRow(ctx,
		`SELECT ciphertext, key_version FROM encrypted_secrets
		  WHERE tenant_id = $1 AND id = $2 AND purpose = $3`,
		tenantID, id, secretPurpose).Scan(&ciphertext, &keyVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		// The provider row points at a secret that is gone. Refusing is
		// correct: continuing would silently attempt a public-client flow
		// against an IdP configured to require a secret, and the resulting
		// error would come from the IdP with no clue as to the real cause.
		return nil, fmt.Errorf("idp: provider's client secret %s is missing from encrypted_secrets", id)
	}
	if err != nil {
		return nil, fmt.Errorf("idp: read client secret: %w", err)
	}
	plaintext, err := s.keeper.Open(ciphertext, keyVersion)
	if err != nil {
		return nil, fmt.Errorf("idp: decrypt client secret: %w", err)
	}
	return plaintext, nil
}

// SaveProviderInput is a create-or-replace of one provider's configuration.
//
// ClientSecret semantics are deliberately three-way, because a settings form
// that round-trips a secret it cannot read needs to distinguish them:
//   - nil          -- leave whatever is stored untouched (an edit that did not
//     retype the secret)
//   - pointer to "" -- delete the stored secret (become a public client)
//   - pointer to a value -- replace it
type SaveProviderInput struct {
	ID           string // empty to create
	DisplayName  string
	Issuer       string
	ClientID     string
	ClientSecret *string
	Scopes       []string
	GroupsClaim  string
	RedirectURI  string
	Enabled      bool
}

// SaveProvider writes a provider and returns its id.
func (s *Store) SaveProvider(ctx context.Context, tx pgx.Tx, tenantID string, in SaveProviderInput) (string, error) {
	id := in.ID
	if id == "" {
		id = domain.NewID(domain.PrefixIdentityProvider)
		if _, err := tx.Exec(ctx,
			`INSERT INTO identity_providers
			   (id, tenant_id, display_name, issuer, client_id, scopes, groups_claim, redirect_uri, enabled)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			id, tenantID, in.DisplayName, in.Issuer, in.ClientID, in.Scopes,
			in.GroupsClaim, in.RedirectURI, in.Enabled); err != nil {
			return "", fmt.Errorf("idp: insert provider: %w", err)
		}
	} else {
		tag, err := tx.Exec(ctx,
			`UPDATE identity_providers
			    SET display_name = $3, issuer = $4, client_id = $5, scopes = $6,
			        groups_claim = $7, redirect_uri = $8, enabled = $9, updated_at = now()
			  WHERE tenant_id = $1 AND id = $2`,
			tenantID, id, in.DisplayName, in.Issuer, in.ClientID, in.Scopes,
			in.GroupsClaim, in.RedirectURI, in.Enabled)
		if err != nil {
			return "", fmt.Errorf("idp: update provider: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return "", fmt.Errorf("idp: provider %s not found", id)
		}
	}

	if in.ClientSecret != nil {
		if err := s.replaceSecret(ctx, tx, tenantID, id, *in.ClientSecret); err != nil {
			return "", err
		}
	}
	return id, nil
}

// replaceSecret stores a new client secret and drops the previous one, or
// clears it entirely when value is empty.
func (s *Store) replaceSecret(ctx context.Context, tx pgx.Tx, tenantID, providerID, value string) error {
	var old *string
	if err := tx.QueryRow(ctx,
		`SELECT client_secret_ref FROM identity_providers WHERE tenant_id = $1 AND id = $2`,
		tenantID, providerID).Scan(&old); err != nil {
		return fmt.Errorf("idp: read existing secret ref: %w", err)
	}

	var newRef *string
	if value != "" {
		ciphertext, keyVersion, err := s.keeper.Seal([]byte(value))
		if err != nil {
			return fmt.Errorf("idp: seal client secret: %w", err)
		}
		ref := domain.NewID(domain.PrefixEncryptedSecret)
		if _, err := tx.Exec(ctx,
			`INSERT INTO encrypted_secrets (id, tenant_id, purpose, ciphertext, key_version)
			 VALUES ($1, $2, $3, $4, $5)`,
			ref, tenantID, secretPurpose, ciphertext, keyVersion); err != nil {
			return fmt.Errorf("idp: store client secret: %w", err)
		}
		newRef = &ref
	}

	if _, err := tx.Exec(ctx,
		`UPDATE identity_providers SET client_secret_ref = $3, updated_at = now()
		  WHERE tenant_id = $1 AND id = $2`, tenantID, providerID, newRef); err != nil {
		return fmt.Errorf("idp: point provider at new secret: %w", err)
	}

	// Only after the provider no longer references it — the other order
	// leaves a window where a concurrent login reads a dangling ref.
	if old != nil {
		if _, err := tx.Exec(ctx,
			`DELETE FROM encrypted_secrets WHERE tenant_id = $1 AND id = $2 AND purpose = $3`,
			tenantID, *old, secretPurpose); err != nil {
			return fmt.Errorf("idp: delete superseded client secret: %w", err)
		}
	}
	return nil
}

// DeleteProvider removes a provider, its group mappings, its in-flight login
// states, and its client secret.
//
// The mappings and states go by ON DELETE CASCADE; the secret does not,
// because there is deliberately no FK from identity_providers into
// encrypted_secrets (see migration 000103's comment on client_secret_ref), so
// it is deleted explicitly here in the same transaction.
func (s *Store) DeleteProvider(ctx context.Context, tx pgx.Tx, tenantID, providerID string) error {
	var secretRef *string
	err := tx.QueryRow(ctx,
		`SELECT client_secret_ref FROM identity_providers WHERE tenant_id = $1 AND id = $2`,
		tenantID, providerID).Scan(&secretRef)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("idp: provider %s not found", providerID)
	}
	if err != nil {
		return fmt.Errorf("idp: read provider before delete: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`DELETE FROM identity_providers WHERE tenant_id = $1 AND id = $2`, tenantID, providerID); err != nil {
		return fmt.Errorf("idp: delete provider: %w", err)
	}
	if secretRef != nil {
		if _, err := tx.Exec(ctx,
			`DELETE FROM encrypted_secrets WHERE tenant_id = $1 AND id = $2 AND purpose = $3`,
			tenantID, *secretRef, secretPurpose); err != nil {
			return fmt.Errorf("idp: delete client secret: %w", err)
		}
	}
	return nil
}

// GroupMappings returns the group-to-role rules for one provider.
func (s *Store) GroupMappings(ctx context.Context, tx pgx.Tx, tenantID, providerID string) ([]GroupMapping, error) {
	rows, err := tx.Query(ctx,
		`SELECT id, group_name, role_id, scope
		   FROM identity_provider_group_mappings
		  WHERE tenant_id = $1 AND provider_id = $2
		  ORDER BY group_name, role_id`, tenantID, providerID)
	if err != nil {
		return nil, fmt.Errorf("idp: list group mappings: %w", err)
	}
	defer rows.Close()

	var out []GroupMapping
	for rows.Next() {
		var m GroupMapping
		if err := rows.Scan(&m.ID, &m.GroupName, &m.RoleID, &m.Scope); err != nil {
			return nil, fmt.Errorf("idp: scan group mapping: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// AddGroupMapping creates one rule. Re-adding an identical rule is a no-op
// rather than an error, so a settings form that resubmits is harmless.
func (s *Store) AddGroupMapping(ctx context.Context, tx pgx.Tx, tenantID, providerID, groupName, roleID string, scope []byte) (string, error) {
	id := domain.NewID(domain.PrefixIdentityGroupMapping)
	err := tx.QueryRow(ctx,
		`INSERT INTO identity_provider_group_mappings (id, tenant_id, provider_id, group_name, role_id, scope)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (tenant_id, provider_id, group_name, role_id) DO UPDATE SET scope = EXCLUDED.scope
		 RETURNING id`,
		id, tenantID, providerID, groupName, roleID, scope).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("idp: add group mapping: %w", err)
	}
	return id, nil
}

func (s *Store) DeleteGroupMapping(ctx context.Context, tx pgx.Tx, tenantID, mappingID string) error {
	tag, err := tx.Exec(ctx,
		`DELETE FROM identity_provider_group_mappings WHERE tenant_id = $1 AND id = $2`, tenantID, mappingID)
	if err != nil {
		return fmt.Errorf("idp: delete group mapping: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("idp: group mapping %s not found", mappingID)
	}
	return nil
}

// PendingLogin is the state of one in-flight login, recovered on callback.
type PendingLogin struct {
	ProviderID string
	Nonce      string
	Verifier   string
	ReturnTo   string
}

// SaveLoginState records an in-flight login and opportunistically reaps
// expired rows.
//
// The reap is here rather than in a sweeper because this table only ever holds
// seconds of state and every write is a natural opportunity — a background job
// for it would be more moving parts than the problem deserves.
func (s *Store) SaveLoginState(ctx context.Context, tx pgx.Tx, tenantID, providerID string, ls LoginStart, returnTo string) error {
	if _, err := tx.Exec(ctx,
		`DELETE FROM oidc_login_states WHERE tenant_id = $1 AND expires_at < now()`, tenantID); err != nil {
		return fmt.Errorf("idp: reap expired login states: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO oidc_login_states (state_hash, tenant_id, provider_id, nonce, pkce_verifier, return_to, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, now() + $7::interval)`,
		HashState(ls.State), tenantID, providerID, ls.Nonce, ls.Verifier,
		SafeReturnTo(returnTo), fmt.Sprintf("%d seconds", int(StateTTL.Seconds()))); err != nil {
		return fmt.Errorf("idp: save login state: %w", err)
	}
	return nil
}

// ConsumeLoginState looks up and DELETES the state row for a callback, making
// it single-use.
//
// Single-use matters: without the delete, a captured callback URL could be
// replayed until the row expired. The DELETE ... RETURNING does both in one
// statement so two concurrent callbacks with the same state cannot both
// succeed — the second finds no row.
func (s *Store) ConsumeLoginState(ctx context.Context, tx pgx.Tx, tenantID, state string) (PendingLogin, error) {
	var pl PendingLogin
	err := tx.QueryRow(ctx,
		`DELETE FROM oidc_login_states
		  WHERE tenant_id = $1 AND state_hash = $2 AND expires_at >= now()
		  RETURNING provider_id, nonce, pkce_verifier, return_to`,
		tenantID, HashState(state)).Scan(&pl.ProviderID, &pl.Nonce, &pl.Verifier, &pl.ReturnTo)
	if errors.Is(err, pgx.ErrNoRows) {
		return PendingLogin{}, ErrNoSuchState
	}
	if err != nil {
		return PendingLogin{}, fmt.Errorf("idp: consume login state: %w", err)
	}
	return pl, nil
}
