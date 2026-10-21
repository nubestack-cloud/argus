package authz

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/domain"
)

// RotateRefreshToken's three error cases (not-found, expired, reused) are
// distinguished by real queries against refresh_tokens (row absent vs.
// row's revoked_at vs. row's expires_at) — there is no pure, DB-free way to
// exercise that logic honestly, and simulating a "reuse" case by hand-
// crafting a row would only prove the SELECT's WHERE clause, not that
// RotateRefreshToken's OWN rotation actually produces a revoked row a
// second presentation then trips on. So, unlike the rest of this package
// (see enrollment_test.go's doc comment — no DB-test harness existed before
// this), these tests talk to a real Postgres, gated behind
// ARGUS_TEST_DATABASE_URL so a machine without one still gets a clean skip
// rather than a failure. Point it at the same dev-compose stack
// scripts/smoke-test.sh already exercises, e.g.:
//
//	export ARGUS_TEST_DATABASE_URL="postgres://argus_app:dev-local-password@localhost:5432/argus?sslmode=disable"
//
// (argus_app, not the postgres superuser — matching what hub-api itself
// connects as, so these tests actually exercise the same FORCE ROW LEVEL
// SECURITY path production traffic does, not a superuser's RLS-bypassing
// view of the table.)
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connString := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if connString == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping DB-backed RotateRefreshToken test (see this file's doc comment)")
	}
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// testUser inserts a throwaway user under the hub's one organisation
// (data.SingleOrganisationID's single-row assumption — see its own doc
// comment) so IssueRefreshToken/RotateRefreshToken have a real user_id to
// satisfy refresh_tokens' foreign key, and cleans it (and any refresh
// tokens it accumulates) up afterwards.
func testUser(t *testing.T, pool *pgxpool.Pool) (tenantID, userID string) {
	t.Helper()
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err = data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	userID = domain.NewID(domain.PrefixUser)
	if _, err := tx.Exec(ctx,
		`INSERT INTO users (id, tenant_id, email, display_name) VALUES ($1, $2, $3, $4)`,
		userID, tenantID, userID+"@test.invalid", "RotateRefreshToken test user"); err != nil {
		t.Fatalf("insert test user: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup transaction: %v", err)
	}

	t.Cleanup(func() {
		cleanupCtx := context.Background()
		tx, err := pool.Begin(cleanupCtx)
		if err != nil {
			t.Logf("cleanup: begin transaction: %v", err)
			return
		}
		defer tx.Rollback(cleanupCtx) //nolint:errcheck
		if err := data.SetRequestScope(cleanupCtx, tx, tenantID, nil); err != nil {
			t.Logf("cleanup: set request scope: %v", err)
			return
		}
		// refresh_tokens has no ON DELETE CASCADE from users, and
		// replaced_by is self-referencing — clear that column first so the
		// FK doesn't block deleting the chain, then delete the tokens, then
		// the user itself.
		if _, err := tx.Exec(cleanupCtx, `UPDATE refresh_tokens SET replaced_by = NULL WHERE user_id = $1`, userID); err != nil {
			t.Logf("cleanup: clear replaced_by: %v", err)
			return
		}
		if _, err := tx.Exec(cleanupCtx, `DELETE FROM refresh_tokens WHERE user_id = $1`, userID); err != nil {
			t.Logf("cleanup: delete refresh tokens: %v", err)
			return
		}
		if _, err := tx.Exec(cleanupCtx, `DELETE FROM users WHERE id = $1`, userID); err != nil {
			t.Logf("cleanup: delete test user: %v", err)
			return
		}
		if err := tx.Commit(cleanupCtx); err != nil {
			t.Logf("cleanup: commit: %v", err)
		}
	})

	return tenantID, userID
}

func TestRotateRefreshToken_NotFound(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	newToken, userID, err := RotateRefreshToken(ctx, pool, "this-token-was-never-issued", nil)
	if !errors.Is(err, ErrRefreshTokenNotFound) {
		t.Fatalf("got err %v, want ErrRefreshTokenNotFound", err)
	}
	if newToken != "" || userID != "" {
		t.Errorf("got (newToken=%q, userID=%q), want both empty on not-found", newToken, userID)
	}
}

func TestRotateRefreshToken_Expired(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tenantID, userID := testUser(t, pool)

	// Insert a refresh token row directly with an expires_at already in the
	// past — IssueRefreshToken always sets a fixed 30-day-out expiry, so
	// producing a genuinely expired-but-never-rotated row requires inserting
	// it directly rather than going through the normal issuance path.
	presented, hash, err := newOpaqueTokenAndHash()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO refresh_tokens (token_hash, tenant_id, user_id, expires_at, family_id) VALUES ($1, $2, $3, $4, $1)`,
		hash, tenantID, userID, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("insert expired token: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	newToken, gotUserID, err := RotateRefreshToken(ctx, pool, presented, nil)
	if !errors.Is(err, ErrRefreshTokenExpired) {
		t.Fatalf("got err %v, want ErrRefreshTokenExpired", err)
	}
	if newToken != "" {
		t.Errorf("got newToken %q, want empty on expired", newToken)
	}
	if gotUserID != userID {
		t.Errorf("got userID %q, want %q — the row was found and scanned, so the actor should still be attributable", gotUserID, userID)
	}
}

// TestRotateRefreshToken_ReuseDetected is the case the task brief singled
// out: a real double rotation, not a hand-simulated row. It issues a token,
// rotates it once (a normal, successful refresh — exactly what
// web/src/auth/AuthContext.tsx's silent restore/proactive-renewal calls do),
// then presents the now-already-rotated ORIGINAL token a second time — the
// actual "replaying a token that should no longer exist" scenario, not a
// row someone set revoked_at on for the test's convenience.
func TestRotateRefreshToken_ReuseDetected(t *testing.T) {
	pool := testPool(t)
	pinStrictReuse(t)
	ctx := context.Background()
	tenantID, userID := testUser(t, pool)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	original, err := IssueRefreshToken(ctx, tx, tenantID, userID)
	if err != nil {
		t.Fatalf("issue refresh token: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// First rotation: a genuine, successful refresh. This is the case that
	// must NOT be treated as reuse — it's the routine renewal internal/api's
	// handleRefresh no longer audits.
	rotated, rotatedUserID, err := RotateRefreshToken(ctx, pool, original, nil)
	if err != nil {
		t.Fatalf("first rotation: unexpected error: %v", err)
	}
	if rotated == "" || rotatedUserID != userID {
		t.Fatalf("first rotation: got (rotated=%q, userID=%q), want a non-empty token and userID %q", rotated, rotatedUserID, userID)
	}

	// Second presentation of the ORIGINAL (now-superseded) token: this is
	// the actual reuse-of-an-already-rotated-token case.
	newToken, reuseUserID, err := RotateRefreshToken(ctx, pool, original, nil)
	if !errors.Is(err, ErrRefreshTokenReused) {
		t.Fatalf("second presentation of the original token: got err %v, want ErrRefreshTokenReused", err)
	}
	if newToken != "" {
		t.Errorf("got newToken %q, want empty on reuse", newToken)
	}
	if reuseUserID != userID {
		t.Errorf("got userID %q, want %q — the actor a caller would audit this reuse event against", reuseUserID, userID)
	}

	// The whole chain — the original AND the token it was rotated into —
	// must end up revoked, not just the presented one, per §9.2's
	// "revoke the entire token family" requirement.
	//
	// This has to run inside its own scoped transaction, not a bare
	// pool.QueryRow — refresh_tokens has FORCE ROW LEVEL SECURITY, and an
	// unscoped connection sees zero rows regardless of what's actually in
	// the table (the exact bug class STATUS.md documents catching three
	// times already for other tables: an RLS-blocked SELECT looks
	// identical to "no matching row exists" from the caller's side).
	verifyTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin verification transaction: %v", err)
	}
	defer verifyTx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, verifyTx, tenantID, nil); err != nil {
		t.Fatalf("set request scope for verification: %v", err)
	}
	var originalRevoked, rotatedRevoked bool
	if err := verifyTx.QueryRow(ctx,
		`SELECT revoked_at IS NOT NULL FROM refresh_tokens WHERE token_hash = $1`,
		hashOpaqueToken(original)).Scan(&originalRevoked); err != nil {
		t.Fatalf("query original token revocation state: %v", err)
	}
	if err := verifyTx.QueryRow(ctx,
		`SELECT revoked_at IS NOT NULL FROM refresh_tokens WHERE token_hash = $1`,
		hashOpaqueToken(rotated)).Scan(&rotatedRevoked); err != nil {
		t.Fatalf("query rotated token revocation state: %v", err)
	}
	if !originalRevoked {
		t.Error("original token: want revoked_at set (it was rotated away by the first, successful rotation)")
	}
	if !rotatedRevoked {
		t.Error("rotated token: want revoked_at set — reuse detection must revoke the WHOLE chain, not just the presented token, else the descendant token stays silently usable")
	}

	// A third presentation, of the token from the (now also revoked)
	// successful first rotation, must independently also be detected as
	// reuse — confirming the chain-wide revocation actually blocks it, not
	// just that its revoked_at column got set.
	if _, _, err := RotateRefreshToken(ctx, pool, rotated, nil); !errors.Is(err, ErrRefreshTokenReused) {
		t.Fatalf("presenting the now-revoked descendant token: got err %v, want ErrRefreshTokenReused", err)
	}
}

// tokenRowsForUser counts refresh_tokens rows belonging to userID, and
// reports how many of them are revoked. Runs in its own properly-scoped
// transaction for the same reason TestRotateRefreshToken_ReuseDetected's
// verification block does: refresh_tokens has FORCE ROW LEVEL SECURITY, so
// an unscoped connection would see zero rows and cheerfully report that
// everything is fine.
func tokenRowsForUser(t *testing.T, pool *pgxpool.Pool, tenantID, userID string) (total, revoked int) {
	t.Helper()
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin count transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope for count: %v", err)
	}
	if err := tx.QueryRow(ctx,
		`SELECT count(*), count(*) FILTER (WHERE revoked_at IS NOT NULL) FROM refresh_tokens WHERE user_id = $1`,
		userID).Scan(&total, &revoked); err != nil {
		t.Fatalf("count refresh tokens: %v", err)
	}
	return total, revoked
}

// TestRotateRefreshToken_ConcurrentRotationDoesNotForkChain is the
// regression test for the missing row lock on RotateRefreshToken's lookup
// SELECT.
//
// Without FOR UPDATE, two rotations of the SAME token overlapping in time
// both read revoked_at IS NULL, both INSERT a successor, and both run the
// "revoke the prior token" UPDATE — whose WHERE clause is keyed only on
// token_hash, so the second writer simply overwrites the first's
// replaced_by. The result is two live successors but only one of them
// reachable from the chain, and the recursive CTE in the reuse branch walks
// exactly replaced_by: the orphaned successor survives the "revoke the
// entire token family" response to a later compromise signal, which is the
// one thing lld/02-authz-spec.md §9.2's reuse detection exists to make
// impossible.
//
// The interleaving is driven by hand rather than left to goroutine
// scheduling (see TestRotateRefreshToken_SimultaneousRefreshes below for the
// genuinely-concurrent companion) so this test's verdict is deterministic:
// the test itself holds the presented token's row locked exactly the way an
// in-flight RotateRefreshToken now does, and only then lets a second
// rotation loose on the same token.
func TestRotateRefreshToken_ConcurrentRotationDoesNotForkChain(t *testing.T) {
	pool := testPool(t)
	pinStrictReuse(t)
	ctx := context.Background()
	tenantID, userID := testUser(t, pool)

	issueTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin issue transaction: %v", err)
	}
	if err := data.SetRequestScope(ctx, issueTx, tenantID, nil); err != nil {
		t.Fatalf("set request scope for issue: %v", err)
	}
	original, err := IssueRefreshToken(ctx, issueTx, tenantID, userID)
	if err != nil {
		t.Fatalf("issue refresh token: %v", err)
	}
	if err := issueTx.Commit(ctx); err != nil {
		t.Fatalf("commit issue: %v", err)
	}
	originalHash := hashOpaqueToken(original)

	// The first of the two racing refreshes, opened and locked by hand.
	firstTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin first-rotation transaction: %v", err)
	}
	defer firstTx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, firstTx, tenantID, nil); err != nil {
		t.Fatalf("set request scope for first rotation: %v", err)
	}
	var lockedUserID string
	if err := firstTx.QueryRow(ctx,
		`SELECT user_id FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE`,
		originalHash).Scan(&lockedUserID); err != nil {
		t.Fatalf("lock presented token row: %v", err)
	}

	// The second refresh, arriving while the first still holds the lock.
	type rotation struct {
		token  string
		userID string
		err    error
	}
	second := make(chan rotation, 1)
	go func() {
		token, uid, err := RotateRefreshToken(ctx, pool, original, nil)
		second <- rotation{token, uid, err}
	}()

	// This sleep only SHAPES the interleaving; no assertion below rests on
	// it. If it were too short and the second rotation ran entirely after
	// firstTx commits, every assertion still holds — it would simply observe
	// the completed rotation instead of blocking on it — so this cannot
	// flake into a false failure, only into exercising a less interesting
	// ordering. (Note it deliberately does NOT assert "the goroutine is
	// still blocked": the pre-fix code blocks here too, just one statement
	// later, on the prior-token UPDATE rather than on the lookup SELECT.
	// What distinguishes the two is the state they leave behind, asserted
	// below.)
	time.Sleep(300 * time.Millisecond)

	firstSuccessor, firstSuccessorHash, err := newOpaqueTokenAndHash()
	if err != nil {
		t.Fatalf("generate first successor token: %v", err)
	}
	if _, err := firstTx.Exec(ctx,
		`INSERT INTO refresh_tokens (token_hash, tenant_id, user_id, expires_at, family_id) VALUES ($1, $2, $3, $4, $5)`,
		firstSuccessorHash, tenantID, userID, time.Now().Add(RefreshTokenTTL), originalHash); err != nil {
		t.Fatalf("insert first successor: %v", err)
	}
	if _, err := firstTx.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now(), replaced_by = $1 WHERE token_hash = $2`,
		firstSuccessorHash, originalHash); err != nil {
		t.Fatalf("revoke original token: %v", err)
	}
	if err := firstTx.Commit(ctx); err != nil {
		t.Fatalf("commit first rotation: %v", err)
	}

	result := <-second

	// Having blocked until the first rotation committed, the second must now
	// see what that rotation actually did — a token already exchanged for a
	// newer one — and refuse. Fail-closed is the correct answer here: the
	// alternative is handing out a second, divergent chain for a token that
	// has already been spent.
	if !errors.Is(result.err, ErrRefreshTokenReused) {
		t.Fatalf("second rotation: got (token=%q, err=%v), want ErrRefreshTokenReused — it read the row before the first rotation's commit and never re-read it under a lock, so it rotated a token that had already been rotated",
			result.token, result.err)
	}
	if result.token != "" {
		t.Errorf("second rotation: got token %q, want empty", result.token)
	}

	// The signature of the bug: three rows (original plus TWO successors)
	// instead of two, one of which no replaced_by edge points at.
	total, revoked := tokenRowsForUser(t, pool, tenantID, userID)
	if total != 2 {
		t.Errorf("got %d refresh_tokens rows for this user, want 2 (the original and the single successor the first rotation issued) — a third row means both rotations minted a successor and the chain forked", total)
	}
	if revoked != total {
		t.Errorf("got %d of %d rows revoked, want all of them — reuse detection must revoke the whole family, and a live row after this sequence is a token that escaped it", revoked, total)
	}

	// replaced_by must still point at the first rotation's successor. The
	// pre-fix failure overwrites it with the second rotation's successor,
	// which is what orphans the first one from the recursive CTE's walk.
	verifyTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin verification transaction: %v", err)
	}
	defer verifyTx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, verifyTx, tenantID, nil); err != nil {
		t.Fatalf("set request scope for verification: %v", err)
	}
	var replacedBy *string
	if err := verifyTx.QueryRow(ctx,
		`SELECT replaced_by FROM refresh_tokens WHERE token_hash = $1`, originalHash).Scan(&replacedBy); err != nil {
		t.Fatalf("read replaced_by: %v", err)
	}
	if replacedBy == nil || *replacedBy != firstSuccessorHash {
		t.Errorf("original token's replaced_by = %v, want the first rotation's successor — anything else means a later writer clobbered the chain edge", replacedBy)
	}

	// And the surviving successor really is unusable, not merely marked:
	// the whole point of revoking the family.
	if _, _, err := RotateRefreshToken(ctx, pool, firstSuccessor, nil); !errors.Is(err, ErrRefreshTokenReused) {
		t.Errorf("presenting the first rotation's successor afterwards: got err %v, want ErrRefreshTokenReused", err)
	}
}

// TestRotateRefreshToken_RevokedAncestorRaceWithLegitimateRotation is the
// regression test for BACKLOG.md G7's "residual race in refresh-token reuse
// detection" — the race the per-row FOR UPDATE lock (see the test above)
// never covered, because it only ever serialises two callers presenting the
// SAME row. This one presents a revoked ANCESTOR (A) concurrently with a
// legitimate, in-flight rotation of a LATER, still-current row in the same
// chain (B, A's own successor) — two different rows, so the old per-row lock
// never made them contend at all.
//
// Chain going in: A -> B, A already revoked (a real prior rotation), B
// current and valid. Concurrently:
//   - a legitimate rotation of B, driven by hand up to the point where it
//     would insert B's own successor (C) and revoke B, exactly the way
//     TestRotateRefreshToken_ConcurrentRotationDoesNotForkChain drives the
//     SAME-row case; and
//   - a real RotateRefreshToken(A) call — presenting the already-revoked
//     ancestor, i.e. a replay/compromise signal, which must revoke the
//     WHOLE family, not just A and whatever existed when its walk began.
//
// Before the family lock: RotateRefreshToken(A) locks only A's own row,
// notices A is revoked, and revokes the chain it can see FROM A — which does
// not yet include C, because the hand-driven rotation of B has not committed
// C into existence yet. It blocks only when its revoke UPDATE tries to touch
// B's row (held by the hand-driven transaction), and once that transaction
// commits, revisits B's row alone (via Postgres's EvalPlanQual) but never
// re-derives the chain, so C — the newest, now-current token — is never
// considered and comes out unrevoked: the exact "leave the newest token
// unrevoked" failure BACKLOG.md G7 names. That is confirmed below by running
// this test against the pre-fix code (see this task's own report for the
// captured failure).
//
// After the family lock: RotateRefreshToken(A) locks every row sharing A's
// family_id up front, including B, and therefore blocks THERE instead,
// before ever deciding anything. By the time it unblocks, the hand-driven
// rotation has fully committed C, and the reuse branch's family-wide UPDATE
// — a fresh statement, fresh READ COMMITTED snapshot — sees and revokes C
// too. The chain ends up fully revoked and C is confirmed unusable by
// actually presenting it afterwards, not just by reading its revoked_at
// column.
func TestRotateRefreshToken_RevokedAncestorRaceWithLegitimateRotation(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tenantID, userID := testUser(t, pool)

	issueTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin issue transaction: %v", err)
	}
	if err := data.SetRequestScope(ctx, issueTx, tenantID, nil); err != nil {
		t.Fatalf("set request scope for issue: %v", err)
	}
	tokenA, err := IssueRefreshToken(ctx, issueTx, tenantID, userID)
	if err != nil {
		t.Fatalf("issue token A: %v", err)
	}
	if err := issueTx.Commit(ctx); err != nil {
		t.Fatalf("commit issue: %v", err)
	}

	// A real, successful rotation A -> B: this is the ordinary renewal that
	// establishes B as the current, valid token and A as its (correctly)
	// revoked predecessor — not a hand-crafted row.
	tokenB, _, err := RotateRefreshToken(ctx, pool, tokenA, nil)
	if err != nil {
		t.Fatalf("rotate A -> B: %v", err)
	}
	hashA := hashOpaqueToken(tokenA)
	hashB := hashOpaqueToken(tokenB)

	// The hand-driven "legitimate rotation of B, in flight" — locks B's row
	// and holds the transaction open without committing, exactly like
	// TestRotateRefreshToken_ConcurrentRotationDoesNotForkChain does for A.
	bTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin in-flight rotation of B: %v", err)
	}
	defer bTx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, bTx, tenantID, nil); err != nil {
		t.Fatalf("set request scope for in-flight rotation of B: %v", err)
	}
	var lockedUserID string
	if err := bTx.QueryRow(ctx,
		`SELECT user_id FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE`,
		hashB).Scan(&lockedUserID); err != nil {
		t.Fatalf("lock B's row: %v", err)
	}

	// The replay of the revoked ancestor, arriving while B's rotation is
	// still in flight.
	type rotation struct {
		token  string
		userID string
		err    error
	}
	replay := make(chan rotation, 1)
	go func() {
		token, uid, err := RotateRefreshToken(ctx, pool, tokenA, nil)
		replay <- rotation{token, uid, err}
	}()

	// Shapes the interleaving only, exactly like the SAME-row test's own
	// sleep — no assertion below depends on the replay still being blocked
	// at this instant.
	time.Sleep(300 * time.Millisecond)

	tokenC, hashC, err := newOpaqueTokenAndHash()
	if err != nil {
		t.Fatalf("generate C: %v", err)
	}
	if _, err := bTx.Exec(ctx,
		`INSERT INTO refresh_tokens (token_hash, tenant_id, user_id, expires_at, family_id) VALUES ($1, $2, $3, $4, $5)`,
		hashC, tenantID, userID, time.Now().Add(RefreshTokenTTL), hashA); err != nil {
		t.Fatalf("insert C: %v", err)
	}
	if _, err := bTx.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now(), replaced_by = $1 WHERE token_hash = $2`,
		hashC, hashB); err != nil {
		t.Fatalf("revoke B: %v", err)
	}
	if err := bTx.Commit(ctx); err != nil {
		t.Fatalf("commit in-flight rotation of B: %v", err)
	}

	result := <-replay

	// A was already revoked before either of these transactions began, so
	// the replay must be told exactly that — this holds regardless of the
	// fix, and isn't the interesting assertion here.
	if !errors.Is(result.err, ErrRefreshTokenReused) {
		t.Fatalf("replaying revoked ancestor A: got (token=%q, err=%v), want ErrRefreshTokenReused", result.token, result.err)
	}
	if result.userID != userID {
		t.Errorf("replaying revoked ancestor A: got userID %q, want %q", result.userID, userID)
	}

	// The load-bearing assertion: C — the newest token, current at the
	// moment the replay's reuse detection ran — must end up revoked too.
	// Pre-fix, this is exactly where the bug shows: C survives with
	// revoked_at still NULL.
	verifyTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin verification transaction: %v", err)
	}
	defer verifyTx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, verifyTx, tenantID, nil); err != nil {
		t.Fatalf("set request scope for verification: %v", err)
	}
	var aRevoked, bRevoked, cRevoked bool
	if err := verifyTx.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM refresh_tokens WHERE token_hash = $1`, hashA).Scan(&aRevoked); err != nil {
		t.Fatalf("query A revocation state: %v", err)
	}
	if err := verifyTx.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM refresh_tokens WHERE token_hash = $1`, hashB).Scan(&bRevoked); err != nil {
		t.Fatalf("query B revocation state: %v", err)
	}
	if err := verifyTx.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM refresh_tokens WHERE token_hash = $1`, hashC).Scan(&cRevoked); err != nil {
		t.Fatalf("query C revocation state: %v", err)
	}
	if !aRevoked {
		t.Error("A: want revoked_at set (it already was, before this test's race even began)")
	}
	if !bRevoked {
		t.Error("B: want revoked_at set (the hand-driven rotation set this directly, unrelated to the fix)")
	}
	if !cRevoked {
		t.Error("C: want revoked_at set — reuse detection on the revoked ancestor A must revoke the WHOLE family, including the token that became current only after the replay's family lock started waiting. A live token surviving a detected-compromise response is the bug BACKLOG.md G7 describes.")
	}

	// Confirm it behaviourally, not just via the column: presenting C
	// afterwards must be refused as reuse, not accepted as an ordinary
	// rotation of a still-live token.
	if _, _, err := RotateRefreshToken(ctx, pool, tokenC, nil); !errors.Is(err, ErrRefreshTokenReused) {
		t.Errorf("presenting C afterwards: got err %v, want ErrRefreshTokenReused — C must actually be unusable, not merely marked", err)
	}
}

// TestRotateRefreshToken_FamilyLockDoesNotBlockOtherFamilies confirms the
// family lock added for BACKLOG.md G7 is scoped to ONE family. A lock held
// on one token's family must never block a rotation on a completely
// unrelated family — that would be a correctness/performance regression of
// its own (effectively a global refresh-token lock), not a narrower version
// of the same fix.
func TestRotateRefreshToken_FamilyLockDoesNotBlockOtherFamilies(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tenantID, userID := testUser(t, pool)

	issueTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin issue transaction: %v", err)
	}
	if err := data.SetRequestScope(ctx, issueTx, tenantID, nil); err != nil {
		t.Fatalf("set request scope for issue: %v", err)
	}
	// Two independent families — each its own IssueRefreshToken call, never
	// rotated against each other, so they share no row and no family_id.
	tokenP, err := IssueRefreshToken(ctx, issueTx, tenantID, userID)
	if err != nil {
		t.Fatalf("issue token P (family P): %v", err)
	}
	tokenQ, err := IssueRefreshToken(ctx, issueTx, tenantID, userID)
	if err != nil {
		t.Fatalf("issue token Q (family Q): %v", err)
	}
	if err := issueTx.Commit(ctx); err != nil {
		t.Fatalf("commit issue: %v", err)
	}

	// Hold family P's lock open, indefinitely as far as this test is
	// concerned — it is only ever released by the deferred Rollback at the
	// end, well after the assertion below has already run.
	pTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin family P holder: %v", err)
	}
	defer pTx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, pTx, tenantID, nil); err != nil {
		t.Fatalf("set request scope for family P holder: %v", err)
	}
	var lockedUserID string
	if err := pTx.QueryRow(ctx,
		`SELECT user_id FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE`,
		hashOpaqueToken(tokenP)).Scan(&lockedUserID); err != nil {
		t.Fatalf("lock family P: %v", err)
	}

	// Rotating Q (a different family) must complete promptly. A regression
	// here — a lock scoped wider than one family — would hang this call
	// until pTx's deferred rollback runs at test teardown, so this is
	// bounded rather than a bare blocking call: a correctness failure must
	// show up as a test failure, not a suite that never finishes.
	type rotation struct {
		token string
		err   error
	}
	done := make(chan rotation, 1)
	go func() {
		token, _, err := RotateRefreshToken(ctx, pool, tokenQ, nil)
		done <- rotation{token, err}
	}()

	select {
	case result := <-done:
		if result.err != nil {
			t.Fatalf("rotate Q while family P is locked: unexpected error: %v", result.err)
		}
		if result.token == "" {
			t.Error("rotate Q while family P is locked: got empty token on success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("rotate Q while family P is locked: timed out — the family lock is blocking an unrelated family, not just family P")
	}
}

// TestRotateRefreshToken_SimultaneousRefreshes is the genuinely-concurrent
// companion to the hand-interleaved test above: two goroutines presenting
// the same refresh token at the same instant, which is precisely what
// web/src/auth/AuthContext.tsx produces when a silent session restore races
// its own proactive renewal, or when React StrictMode double-mounts in dev.
//
// Whichever transaction wins the row lock, the outcome must be the same
// shape every round: exactly one rotation succeeds, exactly one is told the
// token was already spent, and the chain has exactly two rows — never three.
// Several rounds, because unlike the test above this one depends on the two
// goroutines actually overlapping, and a round where they happen not to
// still passes.
func TestRotateRefreshToken_SimultaneousRefreshes(t *testing.T) {
	pool := testPool(t)
	pinStrictReuse(t)
	ctx := context.Background()
	tenantID, userID := testUser(t, pool)

	const rounds = 5
	for round := 1; round <= rounds; round++ {
		issueTx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("round %d: begin issue transaction: %v", round, err)
		}
		if err := data.SetRequestScope(ctx, issueTx, tenantID, nil); err != nil {
			t.Fatalf("round %d: set request scope: %v", round, err)
		}
		original, err := IssueRefreshToken(ctx, issueTx, tenantID, userID)
		if err != nil {
			t.Fatalf("round %d: issue refresh token: %v", round, err)
		}
		if err := issueTx.Commit(ctx); err != nil {
			t.Fatalf("round %d: commit issue: %v", round, err)
		}

		// Released together so both calls are in flight at once, rather than
		// one reliably finishing before the other starts.
		var start, done sync.WaitGroup
		start.Add(1)
		errs := make([]error, 2)
		for i := range errs {
			done.Add(1)
			go func(i int) {
				defer done.Done()
				start.Wait()
				_, _, errs[i] = RotateRefreshToken(ctx, pool, original, nil)
			}(i)
		}
		start.Done()
		done.Wait()

		succeeded, reused := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, ErrRefreshTokenReused):
				reused++
			default:
				t.Fatalf("round %d: unexpected error from a concurrent rotation: %v", round, err)
			}
		}
		if succeeded != 1 || reused != 1 {
			t.Fatalf("round %d: %d rotations succeeded and %d were rejected as reuse, want exactly 1 of each — two successes mean both presentations of one token minted a successor",
				round, succeeded, reused)
		}

		// 2 rows per round (an original and its one successor); anything
		// more is a forked chain from some round.
		total, _ := tokenRowsForUser(t, pool, tenantID, userID)
		if want := 2 * round; total != want {
			t.Fatalf("round %d: got %d refresh_tokens rows for this user, want %d (two per round)", round, total, want)
		}
	}
}

// TestRevokeAllRefreshTokens is the session-revocation trigger the task
// brief asked for explicitly: a password change/reset must actually end
// every OTHER outstanding refresh-token session for the affected user, not
// merely change what a future login would use. This issues two independent
// tokens (simulating two separate logged-in sessions/devices), revokes all
// of them via RevokeAllRefreshTokens, and confirms both are now rejected —
// as ErrRefreshTokenReused, since a revoked-but-presented token is
// indistinguishable at the RotateRefreshToken layer from one that was
// individually rotated-and-replayed (see RevokeAllRefreshTokens' own doc
// comment for why that's the correct, not just convenient, behavior).
func TestRevokeAllRefreshTokens(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tenantID, userID := testUser(t, pool)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	sessionA, err := IssueRefreshToken(ctx, tx, tenantID, userID)
	if err != nil {
		t.Fatalf("issue refresh token (session A): %v", err)
	}
	sessionB, err := IssueRefreshToken(ctx, tx, tenantID, userID)
	if err != nil {
		t.Fatalf("issue refresh token (session B): %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	revokeTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin revocation transaction: %v", err)
	}
	if err := data.SetRequestScope(ctx, revokeTx, tenantID, nil); err != nil {
		t.Fatalf("set request scope for revocation: %v", err)
	}
	if err := RevokeAllRefreshTokens(ctx, revokeTx, userID); err != nil {
		t.Fatalf("RevokeAllRefreshTokens: %v", err)
	}
	if err := revokeTx.Commit(ctx); err != nil {
		t.Fatalf("commit revocation: %v", err)
	}

	if _, _, err := RotateRefreshToken(ctx, pool, sessionA, nil); !errors.Is(err, ErrRefreshTokenReused) {
		t.Errorf("session A after RevokeAllRefreshTokens: got err %v, want ErrRefreshTokenReused", err)
	}
	if _, _, err := RotateRefreshToken(ctx, pool, sessionB, nil); !errors.Is(err, ErrRefreshTokenReused) {
		t.Errorf("session B after RevokeAllRefreshTokens: got err %v, want ErrRefreshTokenReused", err)
	}
}

// TestCurrentTokenGeneration confirms the read-back half of the
// access-token-invalidation mechanism (accessTokenClaims, jwt.go): a fresh
// user starts at generation 0 (the column's default), and once something
// bumps users.token_generation directly (standing in for
// handleChangePassword/handleResetPassword's own UPDATE), the very next read
// reflects it — this is what makes handleRefresh mint an access token
// carrying the CURRENT generation rather than a stale one.
func TestCurrentTokenGeneration(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tenantID, userID := testUser(t, pool)

	generation, err := CurrentTokenGeneration(ctx, pool, userID)
	if err != nil {
		t.Fatalf("CurrentTokenGeneration: %v", err)
	}
	if generation != 0 {
		t.Errorf("got generation %d for a freshly-created user, want 0", generation)
	}

	// Bumped through a properly-scoped transaction, not the bare pool —
	// users has FORCE ROW LEVEL SECURITY, so an update issued on an
	// unscoped connection would silently match zero rows rather than error,
	// the exact bug class this codebase has already been bitten by three
	// times (see argus-context's implementation-conventions notes).
	bumpTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin bump transaction: %v", err)
	}
	if err := data.SetRequestScope(ctx, bumpTx, tenantID, nil); err != nil {
		t.Fatalf("set request scope for bump: %v", err)
	}
	if _, err := bumpTx.Exec(ctx, `UPDATE users SET token_generation = token_generation + 1 WHERE id = $1`, userID); err != nil {
		t.Fatalf("bump token_generation: %v", err)
	}
	if err := bumpTx.Commit(ctx); err != nil {
		t.Fatalf("commit bump: %v", err)
	}

	generation, err = CurrentTokenGeneration(ctx, pool, userID)
	if err != nil {
		t.Fatalf("CurrentTokenGeneration (after bump): %v", err)
	}
	if generation != 1 {
		t.Errorf("got generation %d after bumping the column by 1, want 1", generation)
	}
}
