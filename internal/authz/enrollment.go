package authz

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/logging"
)

// Onboarding path TTL classes, per lld/03-agent-protocol.md §2's table.
const (
	TTLClassKubeconfig  = "A" // admin-supplied kubeconfig, 15 min, 1 redemption
	TTLClassSelfService = "B" // self-service install command, 1 hour, 1 redemption
	TTLClassBulk        = "C" // declarative/bulk, 24 hours, explicit batch size
	TTLClassFleet       = "F" // a fleet's shared token: long-lived, multi-use, revocable (IssueFleetToken)
)

// Fleet token bounds. A fleet token is shared by every cluster a GitOps
// rollout enrolls, so it lives longer than any other class, but never past a
// year, and is capped like any other.
const (
	FleetTokenDefaultDays           = 90
	FleetTokenMaxDays               = 365
	FleetTokenDefaultMaxRedemptions = 1000
	FleetTokenMaxRedemptions        = 10000
)

var ttlClassDefaults = map[string]struct {
	ttl            time.Duration
	maxRedemptions int
}{
	TTLClassKubeconfig:  {15 * time.Minute, 1},
	TTLClassSelfService: {1 * time.Hour, 1},
	TTLClassBulk:        {24 * time.Hour, 1}, // caller may raise maxRedemptions explicitly for this class only
}

// EnrollmentSigner signs enrollment tokens. A separate key from the JWT signer
// (lld/02-authz-spec.md §9's discipline of not reusing one key for two purposes
// with different threat models — session auth vs. one-time cluster enrollment).
type EnrollmentSigner struct {
	key []byte
	// localKey is the hub chart's local enrollment key (local_enrollment.go);
	// empty when the hub was not installed with its own cluster's agent.
	localKey string
}

// NewEphemeralEnrollmentSigner generates a fresh HMAC key on every call. Same
// Phase 0 caveat as authz.NewEphemeralTokenSigner: not persisted, restart
// invalidates every outstanding enrollment token. Acceptable for now — see
// STATUS.md — but real key persistence is deployment-design's job, not this.
func NewEphemeralEnrollmentSigner() *EnrollmentSigner {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(fmt.Errorf("generate enrollment signing key: %w", err))
	}
	logger.Warn("using an ephemeral, non-persisted enrollment token signing key — outstanding tokens are invalidated on restart")
	return &EnrollmentSigner{key: key}
}

// signingKeyPurposeEnrollment is this signer's row key in the signing_keys
// table (internal/migrations/000016_signing_keys.up.sql).
const signingKeyPurposeEnrollment = "enrollment"

// NewPersistentEnrollmentSigner loads the enrollment-token HMAC key persisted
// in Postgres (signing_keys, purpose='enrollment') if one exists, or
// generates a fresh 32-byte key exactly like NewEphemeralEnrollmentSigner and
// persists it if not — same shape and same rationale as
// authz.NewPersistentTokenSigner, see that function's doc comment for the
// full explanation (loaded/generated logging distinction, the deliberate
// non-KMS tradeoff, and a pointer to the concurrency handling).
func NewPersistentEnrollmentSigner(ctx context.Context, pool *pgxpool.Pool) (signer *EnrollmentSigner, loaded bool, err error) {
	material, loaded, err := data.LoadOrCreateSigningKey(ctx, pool, signingKeyPurposeEnrollment, generateEnrollmentKeyMaterial)
	if err != nil {
		return nil, false, fmt.Errorf("load or create enrollment signing key: %w", err)
	}
	return &EnrollmentSigner{key: material}, loaded, nil
}

// generateEnrollmentKeyMaterial generates a fresh 32-byte HMAC key — the
// exact same generation NewEphemeralEnrollmentSigner performs inline, pulled
// out so data.LoadOrCreateSigningKey can call it as its "generate" callback
// when no persisted key exists yet. No serialization step is needed beyond
// the raw bytes themselves (unlike the ECDSA keys in jwt.go/devca.go), since
// an HMAC key is just an opaque byte string to begin with.
func generateEnrollmentKeyMaterial() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate enrollment signing key: %w", err)
	}
	return key, nil
}

// IssueEnrollmentToken implements lld/03-agent-protocol.md §2's format:
//
//	base64url(token_id) + "." + base64url(HMAC-SHA256(key, token_id || issuingPrincipalID || ttlClass || maxRedemptions || issuedAt || expiresAt))
//
// The token itself carries no other information — an opaque reference, not a
// self-describing JWT — because the payload fields it commits to are stored
// server-side and there is nothing here that benefits from client-side
// inspection (§2's explicit design choice).
// validateEnrollmentRequest is the pure-logic half of issuance — pulled out of
// IssueEnrollmentToken so it's unit-testable without a database (internal/authz's
// other tests are all DB-free; this keeps that property rather than making the
// enrollment-token rules only exercisable via the smoke test).
func validateEnrollmentRequest(ttlClass string, maxRedemptions int) (ttl time.Duration, resolvedMaxRedemptions int, err error) {
	defaults, ok := ttlClassDefaults[ttlClass]
	if !ok {
		return 0, 0, fmt.Errorf("unknown ttl class %q", ttlClass)
	}
	if maxRedemptions <= 0 {
		maxRedemptions = defaults.maxRedemptions
	}
	if ttlClass != TTLClassBulk && maxRedemptions != 1 {
		// §2: only the bulk path may ever exceed a single redemption, and even
		// then it must be an explicit, logged choice, never silently unbounded.
		return 0, 0, fmt.Errorf("maxRedemptions > 1 is only permitted for ttl class %q", TTLClassBulk)
	}
	return defaults.ttl, maxRedemptions, nil
}

// FleetTokenRequest is what a fleet token is issued with.
type FleetTokenRequest struct {
	Name           string
	Days           int  // 1..FleetTokenMaxDays; 0 means FleetTokenDefaultDays
	MaxRedemptions int  // 1..FleetTokenMaxRedemptions; 0 means the default
	AutoAccept     bool // the caller has checked the issuer holds cluster:accept
}

// validateFleetToken is the pure-logic half of IssueFleetToken.
func validateFleetToken(req FleetTokenRequest) (FleetTokenRequest, error) {
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 100 {
		return req, fmt.Errorf("a fleet token needs a name of 1 to 100 characters")
	}
	if req.Days == 0 {
		req.Days = FleetTokenDefaultDays
	}
	if req.Days < 1 || req.Days > FleetTokenMaxDays {
		return req, fmt.Errorf("a fleet token lasts 1 to %d days, got %d", FleetTokenMaxDays, req.Days)
	}
	if req.MaxRedemptions == 0 {
		req.MaxRedemptions = FleetTokenDefaultMaxRedemptions
	}
	if req.MaxRedemptions < 1 || req.MaxRedemptions > FleetTokenMaxRedemptions {
		return req, fmt.Errorf("a fleet token allows 1 to %d enrollments, got %d", FleetTokenMaxRedemptions, req.MaxRedemptions)
	}
	return req, nil
}

// IssueFleetToken issues a fleet token: the one token a whole rollout shares.
// Its auto-accept flag is signed with the rest, so it cannot be switched on
// in the database alone.
func (s *EnrollmentSigner) IssueFleetToken(ctx context.Context, tx pgx.Tx, tenantID, issuingPrincipalID string, req FleetTokenRequest) (token, tokenID string, expiresAt time.Time, err error) {
	req, err = validateFleetToken(req)
	if err != nil {
		return "", "", time.Time{}, err
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return "", "", time.Time{}, fmt.Errorf("generate token id: %w", err)
	}
	tokenID = base64.RawURLEncoding.EncodeToString(idBytes)
	issuedAt := time.Now()
	expiresAt = issuedAt.Add(time.Duration(req.Days) * 24 * time.Hour)
	sig := s.signToken(tokenID, issuingPrincipalID, TTLClassFleet, req.MaxRedemptions, issuedAt, expiresAt, req.AutoAccept)
	if _, err := tx.Exec(ctx,
		`INSERT INTO enrollment_tokens
		   (token_id, tenant_id, issuing_principal_id, scope_hint, ttl_class, max_redemptions, issued_at, expires_at, name, auto_accept)
		 VALUES ($1, $2, $3, '{}', $4, $5, $6, $7, $8, $9)`,
		tokenID, tenantID, issuingPrincipalID, TTLClassFleet, req.MaxRedemptions, issuedAt, expiresAt, req.Name, req.AutoAccept); err != nil {
		return "", "", time.Time{}, fmt.Errorf("insert fleet token: %w", err)
	}
	return tokenID + "." + base64.RawURLEncoding.EncodeToString(sig), tokenID, expiresAt, nil
}

func (s *EnrollmentSigner) IssueEnrollmentToken(
	ctx context.Context, tx pgx.Tx,
	tenantID, issuingPrincipalID, ttlClass string,
	maxRedemptions int, scopeHint map[string]string,
) (token string, expiresAt time.Time, err error) {
	ttl, maxRedemptions, err := validateEnrollmentRequest(ttlClass, maxRedemptions)
	if err != nil {
		return "", time.Time{}, err
	}

	tokenIDBytes := make([]byte, 16)
	if _, err := rand.Read(tokenIDBytes); err != nil {
		return "", time.Time{}, fmt.Errorf("generate token id: %w", err)
	}
	tokenID := base64.RawURLEncoding.EncodeToString(tokenIDBytes)

	issuedAt := time.Now()
	expiresAt = issuedAt.Add(ttl)

	mac := hmac.New(sha256.New, s.key)
	fmt.Fprintf(mac, "%s|%s|%s|%d|%d|%d", tokenID, issuingPrincipalID, ttlClass, maxRedemptions, issuedAt.Unix(), expiresAt.Unix())
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if scopeHint == nil {
		scopeHint = map[string]string{}
	}
	scopeHintJSON, err := json.Marshal(scopeHint)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("marshal scope hint: %w", err)
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO enrollment_tokens
		   (token_id, tenant_id, issuing_principal_id, scope_hint, ttl_class, max_redemptions, issued_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		tokenID, tenantID, issuingPrincipalID, scopeHintJSON, ttlClass, maxRedemptions, issuedAt, expiresAt)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("insert enrollment token: %w", err)
	}

	return tokenID + "." + signature, expiresAt, nil
}

// splitEnrollmentToken parses "token_id.signature" — both halves base64url,
// matching IssueEnrollmentToken's format exactly. token_id itself never
// contains "." (it's base64.RawURLEncoding of 16 random bytes), so splitting
// on the last "." is unambiguous.
func splitEnrollmentToken(token string) (tokenID, signature string, ok bool) {
	idx := strings.LastIndex(token, ".")
	if idx < 0 || idx == 0 || idx == len(token)-1 {
		return "", "", false
	}
	return token[:idx], token[idx+1:], true
}

// enrollmentTokenSignature recomputes the HMAC over the same fields
// IssueEnrollmentToken signs. Pulled out of RedeemEnrollmentToken so the
// signature check is unit-testable without a database, matching
// validateEnrollmentRequest's pattern above.
func (s *EnrollmentSigner) enrollmentTokenSignature(tokenID, issuingPrincipalID, ttlClass string, maxRedemptions int, issuedAt, expiresAt time.Time) []byte {
	return s.signToken(tokenID, issuingPrincipalID, ttlClass, maxRedemptions, issuedAt, expiresAt, false)
}

// signToken is the HMAC every token carries. Auto-accept is appended only
// when set, so every token issued before it existed still verifies.
func (s *EnrollmentSigner) signToken(tokenID, issuingPrincipalID, ttlClass string, maxRedemptions int, issuedAt, expiresAt time.Time, autoAccept bool) []byte {
	mac := hmac.New(sha256.New, s.key)
	fmt.Fprintf(mac, "%s|%s|%s|%d|%d|%d", tokenID, issuingPrincipalID, ttlClass, maxRedemptions, issuedAt.Unix(), expiresAt.Unix())
	if autoAccept {
		fmt.Fprint(mac, "|auto-accept")
	}
	return mac.Sum(nil)
}

// verifyEnrollmentTokenSignature compares a presented base64url signature
// against the recomputed one using hmac.Equal (constant-time — this
// codebase's rule 6 for any signature/token comparison, matching
// password.go/jwt.go's discipline).
func (s *EnrollmentSigner) verifyEnrollmentTokenSignature(tokenID, issuingPrincipalID, ttlClass string, maxRedemptions int, issuedAt, expiresAt time.Time, presentedSig string) bool {
	return s.verifySignature(tokenID, issuingPrincipalID, ttlClass, maxRedemptions, issuedAt, expiresAt, false, presentedSig)
}

func (s *EnrollmentSigner) verifySignature(tokenID, issuingPrincipalID, ttlClass string, maxRedemptions int, issuedAt, expiresAt time.Time, autoAccept bool, presentedSig string) bool {
	wantSig := s.signToken(tokenID, issuingPrincipalID, ttlClass, maxRedemptions, issuedAt, expiresAt, autoAccept)
	gotSig, err := base64.RawURLEncoding.DecodeString(presentedSig)
	if err != nil {
		return false
	}
	return hmac.Equal(wantSig, gotSig)
}

// checkEnrollmentTokenRedeemable is the pure-logic half of redemption — pulled
// out for the same DB-free-unit-test reason as validateEnrollmentRequest and
// enrollmentTokenSignature above. A token is redeemable iff it hasn't expired
// and hasn't already hit its redemption limit.
func checkEnrollmentTokenRedeemable(now, expiresAt time.Time, redemptionCount, maxRedemptions int) error {
	if now.After(expiresAt) {
		return fmt.Errorf("enrollment token expired")
	}
	if redemptionCount >= maxRedemptions {
		return fmt.Errorf("enrollment token redemption limit reached")
	}
	return nil
}

// RedeemEnrollmentToken implements the agent-facing half of §2's token
// lifecycle: an agent presents "token_id.signature" plus a CSR (the CSR itself
// is handled by the caller, internal/api's enroll handler — this function only
// verifies and consumes the token), and this validates it against the stored
// enrollment_tokens row and increments redemption_count.
//
// Called with no prior session or tenant context — the caller is an
// unauthenticated agent, not a logged-in user with an already-scoped
// transaction — so, exactly like authz.RotateRefreshToken's no-prior-session
// case (internal/authz/session.go), this resolves the single organisation and
// sets request scope on the given transaction itself before touching
// enrollment_tokens, which has FORCE ROW LEVEL SECURITY. The caller must still
// supply an open transaction (not the bare pool) so this and the caller's own
// subsequent writes (e.g. inserting the new `clusters` row) commit or roll
// back together.
//
// Returns the redeemed token's tenant_id — the tenant the resulting cluster
// belongs to. Every rejection reason (not found, bad signature, expired,
// exhausted) is logged server-side with detail and returned to the caller as a
// generic error — this is reachable from an unauthenticated public endpoint,
// so no internal detail (which check failed, the token's real expiry, etc.)
// should leak in the returned error text itself.
func (s *EnrollmentSigner) RedeemEnrollmentToken(ctx context.Context, tx pgx.Tx, token string) (tokenID, tenantID string, err error) {
	r, err := s.Redeem(ctx, tx, token)
	return r.TokenID, r.TenantID, err
}

// Redemption is what redeeming a token establishes.
type Redemption struct {
	TokenID  string
	TenantID string
	// AutoAccept: the token accepts the cluster on behalf of Issuer, who held
	// cluster:accept when issuing it.
	AutoAccept bool
	Issuer     string
}

// Redeem is RedeemEnrollmentToken, returning everything the token says.
func (s *EnrollmentSigner) Redeem(ctx context.Context, tx pgx.Tx, token string) (Redemption, error) {
	// The local key first: it is an opaque string that may itself contain
	// a ".", so it must not be parsed as "token_id.signature".
	local := s.localKey != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.localKey)) == 1
	tokenID, presentedSig, ok := splitEnrollmentToken(token)
	if local {
		tokenID, presentedSig, ok = localTokenID(token), "", true
	}
	if !ok {
		logger.WarnContext(ctx, "a malformed enrollment token was presented")
		return Redemption{}, fmt.Errorf("enrollment token not recognized")
	}

	resolvedTenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		return Redemption{}, fmt.Errorf("resolve organisation: %w", err)
	}
	if err := data.SetRequestScope(ctx, tx, resolvedTenantID, nil); err != nil {
		return Redemption{}, fmt.Errorf("set request scope: %w", err)
	}

	var rowTenantID, issuingPrincipalID, ttlClass string
	var maxRedemptions, redemptionCount int
	var issuedAt, expiresAt time.Time
	var autoAccept bool
	var revokedAt *time.Time
	err = tx.QueryRow(ctx,
		`SELECT tenant_id, issuing_principal_id, ttl_class, max_redemptions, redemption_count, issued_at, expires_at, auto_accept, revoked_at
		   FROM enrollment_tokens WHERE token_id = $1 FOR UPDATE`,
		tokenID).Scan(&rowTenantID, &issuingPrincipalID, &ttlClass, &maxRedemptions, &redemptionCount, &issuedAt, &expiresAt, &autoAccept, &revokedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			logger.WarnContext(ctx, "enrollment token not found", slog.String("token_id", tokenID))
			return Redemption{}, fmt.Errorf("enrollment token not recognized")
		}
		logger.ErrorContext(ctx, "looking up an enrollment token failed", slog.String("token_id", tokenID), logging.Err(err))
		return Redemption{}, fmt.Errorf("enrollment token not recognized")
	}

	if !local && !s.verifySignature(tokenID, issuingPrincipalID, ttlClass, maxRedemptions, issuedAt, expiresAt, autoAccept, presentedSig) {
		logger.WarnContext(ctx, "enrollment token signature mismatch", slog.String("token_id", tokenID))
		return Redemption{}, fmt.Errorf("enrollment token not recognized")
	}

	if revokedAt != nil {
		logger.WarnContext(ctx, "a revoked enrollment token was presented", slog.String("token_id", tokenID))
		return Redemption{}, fmt.Errorf("enrollment token not redeemable")
	}
	if err := checkEnrollmentTokenRedeemable(time.Now(), expiresAt, redemptionCount, maxRedemptions); err != nil {
		logger.WarnContext(ctx, "enrollment token is not redeemable", slog.String("token_id", tokenID), logging.Err(err))
		return Redemption{}, fmt.Errorf("enrollment token not redeemable")
	}

	if _, err := tx.Exec(ctx,
		`UPDATE enrollment_tokens SET redemption_count = redemption_count + 1 WHERE token_id = $1`,
		tokenID); err != nil {
		return Redemption{}, fmt.Errorf("update redemption count: %w", err)
	}

	return Redemption{TokenID: tokenID, TenantID: rowTenantID, AutoAccept: autoAccept, Issuer: issuingPrincipalID}, nil
}

// FleetToken is a fleet token as listed for the people managing it. The token
// itself is shown once, when issued, and never again.
type FleetToken struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	IssuedBy       string     `json:"issuedBy"`
	IssuedAt       time.Time  `json:"issuedAt"`
	ExpiresAt      time.Time  `json:"expiresAt"`
	Redemptions    int        `json:"redemptions"`
	MaxRedemptions int        `json:"maxRedemptions"`
	AutoAccept     bool       `json:"autoAccept"`
	RevokedAt      *time.Time `json:"revokedAt,omitempty"`
}

// ListFleetTokens lists the tenant's fleet tokens, newest first. tx must
// carry the request scope.
func ListFleetTokens(ctx context.Context, tx pgx.Tx) ([]FleetToken, error) {
	rows, err := tx.Query(ctx,
		`SELECT token_id, name, issuing_principal_id, issued_at, expires_at, redemption_count, max_redemptions, auto_accept, revoked_at
		   FROM enrollment_tokens WHERE ttl_class = 'F' ORDER BY issued_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FleetToken{}
	for rows.Next() {
		var t FleetToken
		if err := rows.Scan(&t.ID, &t.Name, &t.IssuedBy, &t.IssuedAt, &t.ExpiresAt, &t.Redemptions, &t.MaxRedemptions, &t.AutoAccept, &t.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeFleetToken ends a fleet token now. Clusters already enrolled with it
// are not affected. Reports whether a live token was revoked.
func RevokeFleetToken(ctx context.Context, tx pgx.Tx, tokenID string) (bool, error) {
	tag, err := tx.Exec(ctx,
		`UPDATE enrollment_tokens SET revoked_at = now() WHERE token_id = $1 AND ttl_class = 'F' AND revoked_at IS NULL`, tokenID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}
