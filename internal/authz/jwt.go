package authz

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
)

// AccessTokenTTL is the fixed access-token lifetime (lld/02-authz-spec.md §9.1).
const AccessTokenTTL = 15 * time.Minute

const issuer = "argus"
const audience = "argus-api"

// TokenSigner issues and verifies access tokens.
//
// lld/02-authz-spec.md §9.1 requires ES256 only — no algorithm negotiation, no
// "none", no falling back to a symmetric algorithm — pinned at verification time
// regardless of what the token header claims. This is SR-18 (lld/01-threat-model.md);
// jwt/v5's WithValidMethods is what actually enforces the pin, not just a comment
// saying it should be ES256.
type TokenSigner struct {
	private *ecdsa.PrivateKey
	public  *ecdsa.PublicKey
}

// NewEphemeralTokenSigner generates a fresh ES256 key pair on every call.
//
// Phase 0 simplification: this key is NOT persisted, so every hub restart
// invalidates every outstanding session. That's an accepted, explicitly logged
// gap for this stage of implementation — lld/12-deployment-design.md's chart
// values (or an equivalent secret-management step) needs to own real key
// persistence/rotation before this is anything but a local-dev convenience.
// Do not carry this function into a production code path unmodified.
func NewEphemeralTokenSigner() (*TokenSigner, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ES256 key: %w", err)
	}
	logger.Warn("using an ephemeral, non-persisted JWT signing key — every session will be invalidated on restart. Not a production configuration")
	return &TokenSigner{private: priv, public: &priv.PublicKey}, nil
}

// signingKeyPurposeJWT is this signer's row key in the signing_keys table
// (internal/migrations/000016_signing_keys.up.sql).
const signingKeyPurposeJWT = "jwt"

// NewPersistentTokenSigner loads the JWT signing key persisted in Postgres
// (signing_keys, purpose='jwt') if one exists, or generates a fresh ES256 key
// pair exactly like NewEphemeralTokenSigner and persists it if not. Either
// way, the same key survives a hub restart — closing the gap
// NewEphemeralTokenSigner's own doc comment and STATUS.md both flag: every
// outstanding session used to be invalidated on every restart.
//
// loaded reports which branch was taken (true: an existing key was read;
// false: this call generated and persisted a new one) — purely informational,
// so the caller can log the two cases distinctly rather than a single
// "configured" line that hides which one happened.
//
// This is deliberately not a replacement for real KMS/envelope-encrypted key
// management (DESIGN.md §18.6) — the key material sits in a
// plain bytea column, protected only by the same DB access controls as every
// other table. See internal/data.LoadOrCreateSigningKey's doc comment for the
// concurrency handling and internal/migrations/000016_signing_keys.up.sql for
// why this table deliberately has no RLS policy.
func NewPersistentTokenSigner(ctx context.Context, pool *pgxpool.Pool) (signer *TokenSigner, loaded bool, err error) {
	material, loaded, err := data.LoadOrCreateSigningKey(ctx, pool, signingKeyPurposeJWT, generateECDSAKeyMaterial)
	if err != nil {
		return nil, false, fmt.Errorf("load or create JWT signing key: %w", err)
	}
	priv, err := x509.ParseECPrivateKey(material)
	if err != nil {
		return nil, false, fmt.Errorf("parse persisted JWT signing key: %w", err)
	}
	return &TokenSigner{private: priv, public: &priv.PublicKey}, loaded, nil
}

// generateECDSAKeyMaterial generates a fresh ES256 (P-256) key pair and
// serializes the private key to DER (x509.MarshalECPrivateKey) — the exact
// byte shape parseECDSAKeyMaterial expects back. Shared by
// NewPersistentTokenSigner as the "generate" callback
// data.LoadOrCreateSigningKey calls when no row exists yet.
func generateECDSAKeyMaterial() ([]byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ES256 key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal ES256 key: %w", err)
	}
	return der, nil
}

// accessTokenClaims extends the standard registered claim set with a
// generation number mirroring users.token_generation (migration
// 000023_password_management). This is the mechanism that lets a password
// change/reset invalidate an already-issued, not-yet-expired access token
// immediately: requireAuth (internal/api/middleware.go) compares Generation
// against the user's CURRENT token_generation on every request, and a
// change/reset bumps the latter. Deliberately a monotonic counter, not a
// "tokens issued before time T are invalid" timestamp comparison — a counter
// sidesteps any cross-process/cross-container clock-skew concern the latter
// would otherwise carry.
type accessTokenClaims struct {
	jwt.RegisteredClaims
	Generation int64 `json:"gen"`
}

// IssueAccessToken mints a token per lld/02-authz-spec.md §9.1's claim set,
// plus the generation number (above) active for userID at issuance time —
// callers get this from the same query that authenticated the request (e.g.
// handleLogin's SELECT) or from CurrentTokenGeneration (session.go) when no
// such query already ran (handleRefresh).
func (s *TokenSigner) IssueAccessToken(userID string, generation int64) (string, error) {
	now := time.Now()
	claims := accessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    issuer,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(AccessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        newJTI(),
		},
		Generation: generation,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	return token.SignedString(s.private)
}

// VerifyAccessToken validates signature, algorithm, issuer, audience, and expiry —
// every one of SR-18's requirements, not just the signature — and returns the
// token's embedded generation number alongside the subject. It does NOT by
// itself check that generation against the user's current value; that needs a
// DB lookup, and is requireAuth's job (the one caller that has an open, scoped
// transaction to do it in), not this signature-only verification step's.
func (s *TokenSigner) VerifyAccessToken(tokenString string) (userID string, generation int64, err error) {
	token, err := jwt.ParseWithClaims(tokenString, &accessTokenClaims{}, func(t *jwt.Token) (any, error) {
		return s.public, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}), // rejects "none" and any algorithm confusion attempt
		jwt.WithIssuer(issuer),
		jwt.WithAudience(audience),
	)
	if err != nil {
		return "", 0, fmt.Errorf("verify access token: %w", err)
	}
	claims, ok := token.Claims.(*accessTokenClaims)
	if !ok || claims.Subject == "" {
		return "", 0, fmt.Errorf("verify access token: missing subject claim")
	}
	return claims.Subject, claims.Generation, nil
}

func newJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
