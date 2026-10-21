package authz

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
)

// The hub's own cluster enrolls without anyone issuing a token. The hub chart
// installs an agent beside the hub and hands both the same random key, from a
// Secret the chart generates. The hub registers the key as a fleet token that
// accepts its cluster automatically and can be redeemed exactly once, so it is
// listed under Fleet tokens, audited like any auto-accepted enrollment, and
// revocable there. A stolen key enrolls at most one cluster, and only until
// the hub's own agent has used it.
//
// The agent presents the key itself. It carries no signature: the key is the
// credential, compared in constant time, and the token row is found by a hash
// of it, so the database never holds the key.

// LocalEnrollmentTokenName labels the token in the Fleet tokens list.
const LocalEnrollmentTokenName = "This cluster (installed with the hub)"

const (
	localEnrollmentMinKeyLength = 32
	localEnrollmentDays         = 365
)

var errLocalKeyTooShort = errors.New("local enrollment key is shorter than 32 characters")

// localTokenID is the token row's id for key: derived, so the hub needs to
// store nothing but the row, and never the key.
func localTokenID(key string) string {
	sum := sha256.Sum256([]byte("argus-local-enrollment\x00" + key))
	return "local-" + base64.RawURLEncoding.EncodeToString(sum[:18])
}

// SetLocalEnrollmentKey makes Redeem accept key as the local cluster's
// enrollment token.
func (s *EnrollmentSigner) SetLocalEnrollmentKey(key string) error {
	if len(key) < localEnrollmentMinKeyLength {
		return errLocalKeyTooShort
	}
	s.localKey = key
	return nil
}

// EnsureLocalEnrollmentToken registers the local key's token row, issued by
// the bootstrap super-admin, the first time this hub sees the key. It returns
// whether it created the row; a later call (every restart) is a no-op, so the
// one redemption is never handed back.
func (s *EnrollmentSigner) EnsureLocalEnrollmentToken(ctx context.Context, pool *pgxpool.Pool) (created bool, err error) {
	if s.localKey == "" {
		return false, nil
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // a no-op after commit

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		return false, fmt.Errorf("resolve organisation: %w", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		return false, fmt.Errorf("set request scope: %w", err)
	}
	// Accepting a cluster records who accepted it. The local cluster is
	// accepted on behalf of the first super-admin, the account the hub
	// created when it was installed.
	var issuer string
	if err := tx.QueryRow(ctx,
		`SELECT g.principal_id FROM grants g JOIN users u ON u.id = g.principal_id
		  WHERE g.principal_type = 'user' AND g.role_id = 'super-admin'
		    AND g.revoked_at IS NULL AND u.deleted_at IS NULL
		  ORDER BY g.granted_at LIMIT 1`).Scan(&issuer); err != nil {
		return false, fmt.Errorf("find the super-admin to issue the local token: %w", err)
	}
	issuedAt := time.Now()
	tag, err := tx.Exec(ctx,
		`INSERT INTO enrollment_tokens
		   (token_id, tenant_id, issuing_principal_id, scope_hint, ttl_class, max_redemptions, issued_at, expires_at, name, auto_accept)
		 VALUES ($1, $2, $3, '{}', $4, 1, $5, $6, $7, true)
		 ON CONFLICT (token_id) DO NOTHING`,
		localTokenID(s.localKey), tenantID, issuer, TTLClassFleet, issuedAt,
		issuedAt.Add(localEnrollmentDays*24*time.Hour), LocalEnrollmentTokenName)
	if err != nil {
		return false, fmt.Errorf("insert local enrollment token: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
