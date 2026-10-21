package api

// Personal access tokens for the user-facing MCP endpoint (PROJECT.md AD3,
// migration 000128). A person creates one in Settings, pastes it into their
// own MCP client's config, and every tool call that client makes runs AS THAT
// PERSON — see mcp_user.go for the endpoint, and lld/01-threat-model.md's
// 2026-10-11 addendum for the credential's security boundary.
//
// What a token is NOT: a capability. It carries no scope of its own and is
// accepted nowhere except POST /api/v1/mcp — requireAuth (the REST API) only
// ever accepts the hub's own short-lived JWTs, and never sees one of these.
// Every MCP request re-resolves the owner's grants, so a revoked role, a
// narrowed cluster scope or a disabled account takes effect on the very next
// call rather than at the token's expiry.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/logging"
)

const (
	// personalTokenDefaultDays and personalTokenMaxDays bound a token's life.
	// A personal token sits in a config file on a laptop, so it must end on
	// its own: there is no "never expires" option, and a year is the most
	// anyone can ask for.
	personalTokenDefaultDays = 90
	personalTokenMaxDays     = 365
	// maxActivePersonalTokens bounds how many working tokens one person may
	// hold at once — enough for every AI tool on a couple of machines, few
	// enough that the Settings list stays a list someone actually reads.
	maxActivePersonalTokens = 20
	maxPersonalTokenNameLen = 100

	// personalTokenPrefix starts every token, so a secret scanner (and a
	// person reading a config file) can recognise one, and so the token can
	// name its own row: argus_pat_<ulid>_<64 hex chars>.
	personalTokenPrefix = "argus_pat_"
)

// personalTokenStatus is the token's state as a word, computed by the hub so
// the UI never has to compare clocks itself.
const (
	personalTokenActive  = "active"
	personalTokenExpired = "expired"
	personalTokenRevoked = "revoked"
)

type personalTokenView struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Hint       string     `json:"hint"`
	CreatedAt  time.Time  `json:"createdAt"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
	RevokedAt  *time.Time `json:"revokedAt"`
	Status     string     `json:"status"`
}

type personalTokenListResponse struct {
	Tokens []personalTokenView `json:"tokens"`
	// DefaultDays/MaxDays are the bounds the create form offers, served
	// rather than duplicated in the UI so the two cannot disagree.
	DefaultDays int `json:"defaultDays"`
	MaxDays     int `json:"maxDays"`
	// MaxActive is how many active tokens one person may hold.
	MaxActive int `json:"maxActive"`
}

type createPersonalTokenRequest struct {
	Name          string `json:"name"`
	ExpiresInDays *int   `json:"expiresInDays"`
}

type createPersonalTokenResponse struct {
	Token personalTokenView `json:"token"`
	// Secret is the full token, returned exactly once. Only its hash is
	// stored, so it cannot be shown again.
	Secret string `json:"secret"`
}

// newPersonalTokenSecret returns the presented token for row id and the hash
// to store. id is domain.NewID(PrefixPersonalToken), i.e. "pat_<ulid>".
func newPersonalTokenSecret(id string) (token, hash, hint string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", "", fmt.Errorf("generate token: %w", err)
	}
	secret := hex.EncodeToString(raw)
	token = personalTokenPrefix + strings.TrimPrefix(id, domain.PrefixPersonalToken+"_") + "_" + secret
	return token, hashPersonalTokenSecret(secret), secret[len(secret)-4:], nil
}

func hashPersonalTokenSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// parsePersonalToken splits a presented token into its row id and secret.
// ok is false for anything that is not exactly the shape this file mints, so
// a malformed token never reaches the database.
func parsePersonalToken(token string) (id, secret string, ok bool) {
	rest, found := strings.CutPrefix(token, personalTokenPrefix)
	if !found {
		return "", "", false
	}
	ulidPart, secret, found := strings.Cut(rest, "_")
	if !found || len(ulidPart) != 26 || len(secret) != 64 {
		return "", "", false
	}
	for _, c := range ulidPart {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z') {
			return "", "", false
		}
	}
	if _, err := hex.DecodeString(secret); err != nil {
		return "", "", false
	}
	return domain.PrefixPersonalToken + "_" + ulidPart, secret, true
}

func personalTokenStatusAt(now, expiresAt time.Time, revokedAt *time.Time) string {
	switch {
	case revokedAt != nil:
		return personalTokenRevoked
	case !now.Before(expiresAt):
		return personalTokenExpired
	default:
		return personalTokenActive
	}
}

// validatePersonalTokenRequest returns the cleaned name and the lifetime in
// days, or a reason the request is refused.
func validatePersonalTokenRequest(req createPersonalTokenRequest) (name string, days int, problem string) {
	name = strings.TrimSpace(req.Name)
	if name == "" {
		return "", 0, "name is required — say which tool or machine this token is for, so you can tell it apart later"
	}
	if len([]rune(name)) > maxPersonalTokenNameLen {
		return "", 0, fmt.Sprintf("name must be at most %d characters", maxPersonalTokenNameLen)
	}
	days = personalTokenDefaultDays
	if req.ExpiresInDays != nil {
		days = *req.ExpiresInDays
	}
	if days < 1 || days > personalTokenMaxDays {
		return "", 0, fmt.Sprintf("expiresInDays must be between 1 and %d; a personal token cannot be made to last longer than a year", personalTokenMaxDays)
	}
	return name, days, ""
}

// GET /api/v1/users/me/mcp-tokens — the caller's own tokens, newest first.
//
// No capability check beyond being signed in, deliberately: someone whose
// mcp:use was withdrawn must still be able to see, and revoke, the tokens
// they already hold. The query is bound to rc.UserID, never to a parameter.
func (s *Server) handleListPersonalTokens(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	rows, err := rc.Tx.Query(ctx,
		`SELECT id, name, token_hint, created_at, expires_at, last_used_at, revoked_at
		   FROM mcp_personal_tokens WHERE user_id = $1
		  ORDER BY created_at DESC, id DESC`, rc.UserID)
	if err != nil {
		logger.ErrorContext(ctx, "listing personal access tokens failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list your tokens", "")
		return
	}
	defer rows.Close()
	now := time.Now()
	out := personalTokenListResponse{Tokens: []personalTokenView{}, DefaultDays: personalTokenDefaultDays, MaxDays: personalTokenMaxDays, MaxActive: maxActivePersonalTokens}
	for rows.Next() {
		var t personalTokenView
		if err := rows.Scan(&t.ID, &t.Name, &t.Hint, &t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt); err != nil {
			logger.ErrorContext(ctx, "scanning a personal access token failed", logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list your tokens", "")
			return
		}
		t.Status = personalTokenStatusAt(now, t.ExpiresAt, t.RevokedAt)
		out.Tokens = append(out.Tokens, t)
	}
	if err := rows.Err(); err != nil {
		logger.ErrorContext(ctx, "listing personal access tokens failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list your tokens", "")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// POST /api/v1/users/me/mcp-tokens — mint a token for the caller. Gated on
// mcp:use at the route. The secret is in this response and nowhere else.
func (s *Server) handleCreatePersonalToken(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	var req createPersonalTokenRequest
	if decodeJSON(w, r, &req) != nil {
		return
	}
	name, days, problem := validatePersonalTokenRequest(req)
	if problem != "" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/validation", "Invalid token request", problem)
		return
	}

	var active int
	if err := rc.Tx.QueryRow(ctx,
		`SELECT count(*) FROM mcp_personal_tokens WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()`,
		rc.UserID).Scan(&active); err != nil {
		logger.ErrorContext(ctx, "counting personal access tokens failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not create the token", "")
		return
	}
	if active >= maxActivePersonalTokens {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/too-many-tokens", "Too many active tokens",
			fmt.Sprintf("you already hold %d active tokens, the most one person may hold; revoke one you no longer use first", active))
		return
	}

	id := domain.NewID(domain.PrefixPersonalToken)
	token, hash, hint, err := newPersonalTokenSecret(id)
	if err != nil {
		logger.ErrorContext(ctx, "generating a personal access token failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not create the token", "")
		return
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	expires := now.Add(time.Duration(days) * 24 * time.Hour)
	if _, err := rc.Tx.Exec(ctx,
		`INSERT INTO mcp_personal_tokens (id, tenant_id, user_id, name, token_hash, token_hint, created_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		id, rc.TenantID, rc.UserID, name, hash, hint, now, expires); err != nil {
		logger.ErrorContext(ctx, "storing a personal access token failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not create the token", "")
		return
	}

	capability := authz.CapMCPUse
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID: rc.TenantID, ActorID: &rc.UserID, ActorAuthMethod: "jwt",
		SourceIP: clientIP(r), Capability: &capability, Outcome: audit.OutcomeSuccess,
		Details: map[string]any{"action": "mcp_token:create", "tokenId": id, "name": name, "expiresAt": expires.Format(time.RFC3339)},
	}); err != nil {
		// The token must not exist without its audit record: failing here
		// rolls the insert back with it.
		logger.ErrorContext(ctx, "recording a personal token creation in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record this change", "")
		return
	}

	writeJSON(w, http.StatusCreated, createPersonalTokenResponse{
		Token: personalTokenView{
			ID: id, Name: name, Hint: hint, CreatedAt: now, ExpiresAt: expires, Status: personalTokenActive,
		},
		Secret: token,
	})
}

// DELETE /api/v1/users/me/mcp-tokens/{id} — revoke one of the caller's own
// tokens. Like the list, needs only a session: revoking your own credential
// must never be blocked by a missing capability. A token that is not the
// caller's is a 404, the same answer as one that does not exist.
func (s *Server) handleRevokePersonalToken(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	id := r.PathValue("id")
	var name string
	var revokedAt *time.Time
	err := rc.Tx.QueryRow(ctx,
		`SELECT name, revoked_at FROM mcp_personal_tokens WHERE id = $1 AND user_id = $2 FOR UPDATE`,
		id, rc.UserID).Scan(&name, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Token not found", "no token with that id belongs to you")
		return
	}
	if err != nil {
		logger.ErrorContext(ctx, "looking up a personal access token failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not revoke the token", "")
		return
	}
	if revokedAt != nil {
		// Idempotent: the outcome the caller asked for is already true.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if _, err := rc.Tx.Exec(ctx, `UPDATE mcp_personal_tokens SET revoked_at = now() WHERE id = $1`, id); err != nil {
		logger.ErrorContext(ctx, "revoking a personal access token failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not revoke the token", "")
		return
	}
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID: rc.TenantID, ActorID: &rc.UserID, ActorAuthMethod: "jwt",
		SourceIP: clientIP(r), Outcome: audit.OutcomeSuccess,
		Details: map[string]any{"action": "mcp_token:revoke", "tokenId": id, "name": name},
	}); err != nil {
		logger.ErrorContext(ctx, "recording a personal token revocation in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record this change", "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// errPersonalTokenInvalid is every authentication failure the client must not
// be able to tell apart: unknown, malformed, wrong secret, expired, revoked,
// or belonging to a disabled or removed account.
var errPersonalTokenInvalid = errors.New("invalid personal access token")

// personalTokenOwner is what a valid token resolves to.
type personalTokenOwner struct {
	TokenID   string
	UserID    string
	TenantID  string
	ExpiresAt time.Time
}

// lookupPersonalToken validates a presented token and stamps its
// last_used_at. Opens and scopes its own transaction: there is no session to
// inherit scope from (the same position authz.RotateRefreshToken is in).
//
// The row is found by the id embedded in the token, and the secret is then
// compared by hash with crypto/subtle (SR-19) — the lookup key is not the
// secret, so the index probe reveals nothing about it.
func (s *Server) lookupPersonalToken(ctx context.Context, presented string) (personalTokenOwner, error) {
	id, secret, ok := parsePersonalToken(presented)
	if !ok {
		return personalTokenOwner{}, errPersonalTokenInvalid
	}
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return personalTokenOwner{}, fmt.Errorf("begin token lookup: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		return personalTokenOwner{}, fmt.Errorf("resolve organisation: %w", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		return personalTokenOwner{}, fmt.Errorf("set request scope: %w", err)
	}

	var owner personalTokenOwner
	var storedHash string
	var revokedAt, userDisabledAt, userDeletedAt *time.Time
	err = tx.QueryRow(ctx,
		`SELECT t.user_id, t.token_hash, t.expires_at, t.revoked_at, u.disabled_at, u.deleted_at
		   FROM mcp_personal_tokens t JOIN users u ON u.id = t.user_id
		  WHERE t.id = $1`, id).Scan(&owner.UserID, &storedHash, &owner.ExpiresAt, &revokedAt, &userDisabledAt, &userDeletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return personalTokenOwner{}, errPersonalTokenInvalid
	}
	if err != nil {
		return personalTokenOwner{}, fmt.Errorf("look up personal token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(storedHash), []byte(hashPersonalTokenSecret(secret))) != 1 {
		return personalTokenOwner{}, errPersonalTokenInvalid
	}
	if revokedAt != nil || !time.Now().Before(owner.ExpiresAt) || userDisabledAt != nil || userDeletedAt != nil {
		return personalTokenOwner{}, errPersonalTokenInvalid
	}

	// Throttled to one write a minute per token: "last used" is for a person
	// deciding whether a token is still needed, and a write per tool call
	// would buy nothing for that.
	if _, err := tx.Exec(ctx,
		`UPDATE mcp_personal_tokens SET last_used_at = now()
		  WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')`, id); err != nil {
		return personalTokenOwner{}, fmt.Errorf("stamp personal token use: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return personalTokenOwner{}, fmt.Errorf("commit token lookup: %w", err)
	}
	owner.TokenID = id
	owner.TenantID = tenantID
	return owner, nil
}

// logPersonalTokenFailure keeps the real reason for an internal failure in
// the hub's log while the client sees only the generic refusal.
func logPersonalTokenFailure(ctx context.Context, err error) {
	if err != nil && !errors.Is(err, errPersonalTokenInvalid) {
		logger.ErrorContext(ctx, "authenticating a personal access token failed", logging.Err(err))
	} else if err != nil {
		logger.InfoContext(ctx, "refused an MCP request with an invalid personal access token", slog.String("reason", "invalid"))
	}
}
