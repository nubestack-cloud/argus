package authz

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
)

// Sentinel errors RotateRefreshToken returns, so a caller can tell apart
// three genuinely different cases with errors.Is instead of matching on
// error message text — matching the convention already established by
// internal/llm.ErrNotConfigured (checked via errors.Is at its one call site,
// internal/api/analyze.go). Before this, all three collapsed into one
// untyped error; see internal/api/auth.go's handleRefresh for why that
// mattered: ErrRefreshTokenReused is the actual compromise signal
// (lld/01-threat-model.md's asset table: "refresh-token theft is the
// higher-value target since it renews"; lld/02-authz-spec.md §14 names it
// `refresh_token.reuse_detected`, "a signal worth its own high-priority
// alert") — the other two are just an old or unrecognized token, not a
// security event.
var (
	// ErrRefreshTokenNotFound means the presented token's hash matches no
	// row in refresh_tokens at all — never issued, or long since deleted.
	ErrRefreshTokenNotFound = errors.New("refresh token not recognized")
	// ErrRefreshTokenExpired means the row exists, was never revoked, but
	// its expires_at has passed. An old-but-legitimate token, not a signal.
	ErrRefreshTokenExpired = errors.New("refresh token expired")
	// ErrRefreshTokenReused means the row exists AND has already been
	// revoked/superseded by a later rotation (revoked_at IS NOT NULL) —
	// i.e. this exact token was already exchanged for a newer one, and is
	// now being presented again. That is different from "not found" (never
	// existed) and from "expired" (never rotated, just outlived) — it is
	// the one case that means someone is replaying a token that should no
	// longer exist. The whole rotation chain has already been revoked by
	// the time this is returned (see below).
	ErrRefreshTokenReused = errors.New("refresh token reuse detected — session terminated, re-authentication required")
	// ErrRefreshTokenIdle means the row exists, is unrevoked and unexpired,
	// but org_settings.session_idle_timeout_minutes is configured and this
	// token's issued_at is older than that limit — PROJECT.md 2026-10-14's
	// server-enforced idle timeout (migration 000131's doc comment has the
	// full mechanism). Treated exactly like ErrRefreshTokenExpired, not like
	// ErrRefreshTokenReused: an old-but-legitimate token outliving its limit,
	// not a compromise signal, so nothing is explicitly revoked here (there is
	// nothing TO revoke that isn't already refused — issued_at never changes,
	// so every future presentation of this same row keeps failing this same
	// check on its own) and it is never audited as reuse.
	ErrRefreshTokenIdle = errors.New("refresh token idle timeout exceeded — session terminated, re-authentication required")
)

// RefreshTokenTTL is the refresh-token lifetime before it must be renewed by login.
// lld/02-authz-spec.md §9.2 doesn't pin an exact value; 30 days is a reasonable
// starting default for a session that rotates on every use.
const RefreshTokenTTL = 30 * 24 * time.Hour

// IssueRefreshToken creates a new refresh token, unrelated to any prior one — the
// first token in a rotation chain. Returns the opaque token to hand to the client;
// only its hash is ever stored (lld/02-authz-spec.md §9.2).
//
// Takes the CALLER's already-scoped transaction (app.tenant_id already set by
// data.SetRequestScope) rather than the bare pool — refresh_tokens has FORCE ROW
// LEVEL SECURITY (lld/05-data-model.md §6), so an INSERT issued on a fresh,
// unscoped connection is rejected by its own WITH CHECK clause. Found by actually
// running the login flow end-to-end, not by review — see STATUS.md's Phase 0 notes.
func IssueRefreshToken(ctx context.Context, tx pgx.Tx, tenantID, userID string) (string, error) {
	token, hash, err := newOpaqueTokenAndHash()
	if err != nil {
		return "", err
	}
	// family_id (migration 000086) identifies this token's whole rotation
	// chain — every token RotateRefreshToken later derives from this one
	// carries the SAME family_id forward. This is the first token in the
	// chain, so its family is just itself; there is no root to inherit from.
	_, err = tx.Exec(ctx,
		`INSERT INTO refresh_tokens (token_hash, tenant_id, user_id, expires_at, family_id)
		 VALUES ($1, $2, $3, $4, $1)`,
		hash, tenantID, userID, time.Now().Add(RefreshTokenTTL))
	if err != nil {
		return "", fmt.Errorf("insert refresh token: %w", err)
	}
	return token, nil
}

// RotateRefreshToken implements lld/02-authz-spec.md §9.2's rotation-with-reuse-
// detection: presenting a valid, unrevoked token issues a new one and revokes the
// old. Presenting an ALREADY-REVOKED token is treated as a compromise signal —
// every token in that rotation chain is revoked, not just the one presented, and
// the caller must force full re-authentication rather than silently continuing.
// The one exception is RefreshReuseGrace's: the immediate predecessor of a
// never-used head, presented within seconds of its rotation, is a lost
// response rather than a replay, and is exchanged once.
//
// On any failure, err is one of the three sentinels above (checkable via
// errors.Is), or a wrapped internal error for a genuine unexpected DB failure
// — never a bare string a caller would have to pattern-match on. userID is
// still populated on ErrRefreshTokenReused and ErrRefreshTokenExpired (the
// row was found and scanned before either check runs; only the not-found
// case has no user_id to give), specifically so a caller auditing reuse
// detection can attribute it to an actor without a second query.
//
// Unlike IssueRefreshToken, this opens and scopes its own transaction — there is
// no prior authenticated session to inherit scope from at refresh time (that's
// the whole point of a refresh call), so it resolves the organisation itself
// before touching refresh_tokens, the same way handleLogin does.
func RotateRefreshToken(ctx context.Context, pool *pgxpool.Pool, presented string, idleTimeoutMinutes *int) (newToken, userID string, err error) {
	res, err := RotateRefreshTokenDetailed(ctx, pool, presented, idleTimeoutMinutes)
	return res.Token, res.UserID, err
}

// RefreshReuseGrace is how long after a rotation the token it superseded may
// still be exchanged ONCE more, provided the successor that rotation minted has
// never itself been presented. It exists for one failure: the hub commits a
// rotation and the response carrying the new cookie never reaches the browser
// (a connection reset, an ingress timeout, a page torn down mid-request), so the
// browser's next refresh presents the token it still holds. Without this, that
// is indistinguishable from a replayed stolen token — the whole family is
// revoked, the user is signed out, and the audit log raises a compromise signal
// for what was a dropped packet. Enough of those and nobody reads the signal.
//
// Why this stays safe, and what it costs:
//   - Only the IMMEDIATE predecessor of the family's live head qualifies, and
//     only while that head has never been used. Once the legitimate client has
//     presented its new token, the old one is plain reuse again, at any age.
//   - It is one-shot: the grace exchange rotates the head itself, so the
//     presented token's successor is no longer the head and a second
//     presentation of it is reuse.
//   - A token revoked by sign-out, a password change, an admin action or a
//     detected reuse has no live head to rotate, so it never qualifies.
//   - The cost: a thief who replays a just-superseded token inside the window,
//     before the legitimate client next refreshes, gets a session — and is cut
//     off, with the reuse audited, the next time the legitimate client
//     refreshes, because that client's token was the one the grace exchange
//     retired. Detection is delayed by at most one renewal interval, not lost.
//
// Ten seconds covers what it is for (a reload during a refresh, two tabs
// racing, a retry after a reset) — those land in well under a second — and
// nothing longer, since every extra second only widens that replay window. A
// var rather than a const so tests can pin the strict, zero-grace contract.
var RefreshReuseGrace = 10 * time.Second

// RotationResult is RotateRefreshTokenDetailed's success value. Graced reports
// that the presented token was the just-superseded predecessor exchanged under
// RefreshReuseGrace rather than the live head — a caller audits it, since a
// grace exchange is the one successful refresh that is worth a record.
type RotationResult struct {
	Token  string
	UserID string
	Graced bool
}

// RotateRefreshTokenDetailed is RotateRefreshToken with the grace outcome
// reported (see RefreshReuseGrace). Same error contract: userID is populated
// in the result on ErrRefreshTokenReused, ErrRefreshTokenExpired and
// ErrRefreshTokenIdle.
//
// idleTimeoutMinutes is the caller's already-resolved
// settings.Config.SessionIdleTimeoutMinutes — this package does not import
// internal/settings itself (internal/api already imports both, and resolving
// here would mean either a second DB round trip inside this transaction or
// threading a querier through a function whose whole contract today is "takes
// a presented token and a pool"). nil means no idle limit, matching that
// field's own nil-means-off contract exactly.
func RotateRefreshTokenDetailed(ctx context.Context, pool *pgxpool.Pool, presented string, idleTimeoutMinutes *int) (res RotationResult, err error) {
	hash := hashOpaqueToken(presented)
	var userID string
	defer func() { res.UserID = userID }()

	tx, err := pool.Begin(ctx)
	if err != nil {
		return RotationResult{}, fmt.Errorf("begin rotation transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		return RotationResult{}, fmt.Errorf("resolve organisation: %w", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		return RotationResult{}, fmt.Errorf("set request scope: %w", err)
	}

	// Look up the presented token's family (BACKLOG.md G7, migration 000086)
	// — the id shared by every token in its rotation chain, root included.
	// family_id is assigned once, at INSERT time, and never updated by any
	// code path afterwards, so reading it here with a plain, unlocked SELECT
	// is safe: nothing can race a column value that never changes. What DOES
	// change — revoked_at, replaced_by, and which rows in the family even
	// exist yet — must not be read until AFTER the family lock immediately
	// below; that ordering is the entire fix.
	var familyID string
	if err := tx.QueryRow(ctx,
		`SELECT family_id FROM refresh_tokens WHERE token_hash = $1`, hash).Scan(&familyID); err != nil {
		if err == pgx.ErrNoRows {
			return RotationResult{}, ErrRefreshTokenNotFound
		}
		return RotationResult{}, fmt.Errorf("look up refresh token family: %w", err)
	}

	// Lock the WHOLE family up front, before reading the presented token's
	// own validity/superseded state. This is BACKLOG.md G7's decided fix for
	// a race the per-row lock further down (kept below, on the presented
	// row's own re-read) never covered: that lock only ever serialised two
	// concurrent presentations of the SAME row. It does nothing when one
	// caller presents a revoked ANCESTOR (say A, in a chain A -> B -> C, with
	// C current) while another legitimately rotates a DIFFERENT, later row
	// in the same chain (C) — the two FOR UPDATE locks land on different
	// rows and never conflict, so both proceed concurrently. The reuse branch
	// below revokes "the whole family" by walking from the presented token,
	// but if that walk's own read happened to be computed before the
	// legitimate rotation's INSERT of its new successor committed, the new
	// successor is invisible to it and escapes revocation — the exact
	// "leave the newest token unrevoked" failure BACKLOG.md G7 names.
	//
	// Locking every row that currently shares this family_id, in its own
	// statement before anything else touches this family, forces every
	// concurrent RotateRefreshToken call anywhere in the chain to serialize
	// behind whichever one gets here first — not just two calls on one row.
	// The loser blocks here until the winner commits or rolls back, and
	// every statement THIS call issues afterwards is a NEW statement, which
	// under READ COMMITTED takes a fresh snapshot at the moment it runs — so
	// once unblocked, this call sees the winner's fully committed writes,
	// including any new successor row the winner inserted while we waited.
	// That is what makes the reuse branch's family-wide revoke below correct
	// even in the interleaving above: by the time it runs, either the
	// legitimate rotation hasn't started yet (nothing to miss) or it has
	// already fully committed and its new token is visible and revocable.
	rows, err := tx.Query(ctx, `SELECT token_hash FROM refresh_tokens WHERE family_id = $1 FOR UPDATE`, familyID)
	if err != nil {
		return RotationResult{}, fmt.Errorf("lock token family: %w", err)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return RotationResult{}, fmt.Errorf("lock token family: %w", err)
	}

	// Re-read the presented token now that the family lock is held — a NEW
	// statement, so it is not the stale pre-lock view the unlocked family_id
	// lookup above returned. The old per-row FOR UPDATE that used to live
	// here is now subsumed by the family lock above (this row's family_id is
	// familyID by construction, so it was already among the rows just
	// locked); this SELECT is a plain read of that already-locked row's
	// current data, kept only for the same two callers the doc comment above
	// describes racing on the SAME row — that case still resolves correctly
	// here, it's just the family lock, not this SELECT, doing the work now.
	var revokedAt *time.Time
	var expiresAt, issuedAt time.Time
	var replacedBy *string
	var withinGrace bool
	// withinGrace is computed by the database against its own clock — the
	// same clock that stamped revoked_at — so hub/DB clock skew cannot widen
	// or close the window. clock_timestamp(), not now(): now() is this
	// transaction's START, which can precede a concurrent rotation's
	// revoked_at that this one waited on the family lock for.
	err = tx.QueryRow(ctx,
		`SELECT user_id, revoked_at, expires_at, replaced_by, issued_at,
		        revoked_at IS NOT NULL AND revoked_at > clock_timestamp() - make_interval(secs => $2)
		   FROM refresh_tokens WHERE token_hash = $1`,
		hash, RefreshReuseGrace.Seconds()).Scan(&userID, &revokedAt, &expiresAt, &replacedBy, &issuedAt, &withinGrace)
	if err != nil {
		if err == pgx.ErrNoRows {
			return RotationResult{}, ErrRefreshTokenNotFound
		}
		return RotationResult{}, fmt.Errorf("look up refresh token: %w", err)
	}

	if revokedAt != nil && replacedBy != nil && withinGrace {
		// The just-superseded predecessor, inside the grace window. Exchange
		// it only if its successor is still the family's live head — never
		// presented, never revoked by sign-out/password change/reuse — and
		// do it by rotating THAT head, so the family keeps exactly one live
		// token and this predecessor stops qualifying. See RefreshReuseGrace.
		var headLive bool
		if err := tx.QueryRow(ctx,
			`SELECT revoked_at IS NULL AND expires_at > now() FROM refresh_tokens WHERE token_hash = $1`,
			*replacedBy).Scan(&headLive); err != nil && err != pgx.ErrNoRows {
			return RotationResult{}, fmt.Errorf("look up successor token: %w", err)
		}
		if headLive {
			newTok, err := rotateWithinFamily(ctx, tx, tenantID, userID, familyID, *replacedBy)
			if err != nil {
				return RotationResult{}, err
			}
			if err := tx.Commit(ctx); err != nil {
				return RotationResult{}, fmt.Errorf("commit grace rotation: %w", err)
			}
			return RotationResult{Token: newTok, Graced: true}, nil
		}
	}

	if revokedAt != nil {
		// Reuse of an already-revoked token: revoke every currently-unrevoked
		// row in the family and refuse. This used to be a recursive CTE
		// walking replaced_by from the presented token in both directions —
		// replaced by a plain family_id-scoped UPDATE now that family_id
		// exists (migration 000086) and, per the lock comment above, this
		// statement's own fresh snapshot is guaranteed to already include
		// every row that will ever need revoking, not just the ones that
		// existed when an earlier, differently-timed walk would have run.
		if _, revokeErr := tx.Exec(ctx,
			`UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL`,
			familyID); revokeErr != nil {
			return RotationResult{}, fmt.Errorf("revoke compromised token family: %w", revokeErr)
		}
		_ = tx.Commit(ctx)
		return RotationResult{}, ErrRefreshTokenReused
	}
	if time.Now().After(expiresAt) {
		return RotationResult{}, ErrRefreshTokenExpired
	}
	// issued_at is when THIS row was minted, which is also exactly "when this
	// chain was last actively rotated" — a token is re-minted on every
	// rotation (rotateWithinFamily below), so no separate last-used column is
	// needed to answer "how long has it been since someone actually used
	// this session" (see migration 000131's doc comment).
	if idleTimeoutMinutes != nil && time.Since(issuedAt) > time.Duration(*idleTimeoutMinutes)*time.Minute {
		return RotationResult{}, ErrRefreshTokenIdle
	}

	newTok, err := rotateWithinFamily(ctx, tx, tenantID, userID, familyID, hash)
	if err != nil {
		return RotationResult{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return RotationResult{}, fmt.Errorf("commit rotation: %w", err)
	}
	return RotationResult{Token: newTok}, nil
}

// rotateWithinFamily mints the successor of the token whose hash is
// currentHash, in the same family, and retires currentHash pointing at it. The
// caller holds the family lock and commits.
func rotateWithinFamily(ctx context.Context, tx pgx.Tx, tenantID, userID, familyID, currentHash string) (string, error) {
	newTok, newHash, err := newOpaqueTokenAndHash()
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO refresh_tokens (token_hash, tenant_id, user_id, expires_at, family_id) VALUES ($1, $2, $3, $4, $5)`,
		newHash, tenantID, userID, time.Now().Add(RefreshTokenTTL), familyID); err != nil {
		return "", fmt.Errorf("insert rotated refresh token: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now(), replaced_by = $1 WHERE token_hash = $2`,
		newHash, currentHash); err != nil {
		return "", fmt.Errorf("revoke prior refresh token: %w", err)
	}
	return newTok, nil
}

// RevokeAllRefreshTokens revokes every currently-active (non-revoked) refresh
// token belonging to userID — the primitive a password change/reset uses to
// actually end every outstanding refresh-token session for that user, not
// just change what a future login would use. Any of those tokens later
// re-presented to RotateRefreshToken will be rejected as ErrRefreshTokenReused
// (its revoked_at IS NOT NULL branch), exactly as if that session's token had
// been individually rotated-and-replayed — no separate "already revoked, but
// not via reuse detection" case needs to exist.
//
// Takes the CALLER's already-scoped transaction, same requirement as
// IssueRefreshToken: refresh_tokens has FORCE ROW LEVEL SECURITY, so this must
// run inside a transaction that already had data.SetRequestScope called on it.
func RevokeAllRefreshTokens(ctx context.Context, tx pgx.Tx, userID string) error {
	if _, err := tx.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`,
		userID); err != nil {
		return fmt.Errorf("revoke refresh tokens for user: %w", err)
	}
	return nil
}

// RevokeRefreshTokenFamily revokes every currently-active (non-revoked)
// refresh token in the SAME rotation chain as presented — the primitive
// PROJECT.md B164's logout endpoint (internal/api/auth.go's handleLogout)
// uses to make signing out actually end that browser's whole refresh-token
// lineage, not merely stop using it client-side. Unlike RevokeAllRefreshTokens
// (which ends every session the user holds, on every device), this ends
// exactly the ONE chain presented — signing out of one browser must not
// silently end every other device's session too.
//
// presented is the raw, currently-held opaque token, never a hash the caller
// computed itself — this hashes it exactly as IssueRefreshToken/
// RotateRefreshToken do. Returns ErrRefreshTokenNotFound when the token is
// not recognized at all (already deleted, or never issued); callers should
// treat that as a no-op; logging out with an unknown or already-gone token
// is not a failure, and revoking nothing is the only correct response to it.
// userID is populated whenever a family_id is found — even one that turns
// out to already be fully revoked — mirroring RotateRefreshToken's contract,
// so a caller can audit the event against an actor without a second query.
//
// Opens and scopes its own transaction, same as RotateRefreshToken and
// CurrentTokenGeneration: the request that reaches a logout endpoint carries
// only this cookie, not a verified, already-scoped session to inherit from.
func RevokeRefreshTokenFamily(ctx context.Context, pool *pgxpool.Pool, presented string) (userID string, err error) {
	hash := hashOpaqueToken(presented)

	tx, err := pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("begin revoke-family transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		return "", fmt.Errorf("resolve organisation: %w", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		return "", fmt.Errorf("set request scope: %w", err)
	}

	var familyID string
	if err := tx.QueryRow(ctx,
		`SELECT family_id, user_id FROM refresh_tokens WHERE token_hash = $1`, hash).Scan(&familyID, &userID); err != nil {
		if err == pgx.ErrNoRows {
			return "", ErrRefreshTokenNotFound
		}
		return "", fmt.Errorf("look up refresh token family: %w", err)
	}

	// Lock the whole family before revoking it — same reasoning as
	// RotateRefreshToken's family lock above: without it, a rotation racing
	// this logout could insert its new successor row after this statement's
	// snapshot was taken, leaving that successor un-revoked. That is
	// BACKLOG.md G7's "leave the newest token unrevoked" failure, and it
	// applies here exactly as much as it does to reuse detection.
	if _, err := tx.Exec(ctx, `SELECT 1 FROM refresh_tokens WHERE family_id = $1 FOR UPDATE`, familyID); err != nil {
		return userID, fmt.Errorf("lock token family: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL`,
		familyID); err != nil {
		return userID, fmt.Errorf("revoke token family: %w", err)
	}

	return userID, tx.Commit(ctx)
}

// CurrentTokenGeneration reads a user's current users.token_generation value
// — the number handleRefresh (internal/api/auth.go) embeds in the access
// token it mints after every rotation, so a password change/reset that has
// just bumped this value is reflected in the very next access token issued
// for this user, not only in a future login's. handleLogin reads this column
// itself as part of its own user lookup and doesn't need this helper;
// handleRefresh has no such query already in flight, hence this.
//
// Opens and scopes its own transaction, like RotateRefreshToken itself —
// there is no prior authenticated session's transaction to inherit scope
// from at refresh time.
func CurrentTokenGeneration(ctx context.Context, pool *pgxpool.Pool, userID string) (int64, error) {
	generation, _, err := CurrentSessionState(ctx, pool, userID)
	return generation, err
}

// CurrentSessionState is CurrentTokenGeneration plus users.must_change_password
// — what handleRefresh reports back alongside the new access token, so a
// session restored on page load knows the same thing the sign-in response told
// it. Reporting a constant false there made the change-your-password prompt
// vanish on the first reload after a sign-in that had raised it.
func CurrentSessionState(ctx context.Context, pool *pgxpool.Pool, userID string) (generation int64, mustChangePassword bool, err error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, false, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		return 0, false, fmt.Errorf("resolve organisation: %w", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		return 0, false, fmt.Errorf("set request scope: %w", err)
	}

	if err := tx.QueryRow(ctx, `SELECT token_generation, must_change_password FROM users WHERE id = $1 AND deleted_at IS NULL`, userID).Scan(&generation, &mustChangePassword); err != nil {
		return 0, false, fmt.Errorf("look up token generation: %w", err)
	}
	return generation, mustChangePassword, tx.Commit(ctx)
}

func newOpaqueTokenAndHash() (token, hash string, err error) {
	buf := make([]byte, 32) // 256 bits, per lld/02-authz-spec.md §9.2
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generate refresh token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(buf)
	return token, hashOpaqueToken(token), nil
}

func hashOpaqueToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
