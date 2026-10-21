package authz

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
)

// pinStrictReuse sets RefreshReuseGrace to zero for one test: the tests that
// pin the original contract — any second presentation of a superseded token is
// reuse — run under it, so the grace window is an explicit, separately tested
// exception rather than something that silently loosened them.
func pinStrictReuse(t *testing.T) {
	t.Helper()
	prev := RefreshReuseGrace
	RefreshReuseGrace = 0
	t.Cleanup(func() { RefreshReuseGrace = prev })
}

func issueForTest(t *testing.T, pool *pgxpool.Pool, tenantID, userID string) string {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("scope: %v", err)
	}
	tok, err := IssueRefreshToken(ctx, tx, tenantID, userID)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return tok
}

func graceExecScoped(t *testing.T, pool *pgxpool.Pool, tenantID, sql string, args ...any) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("scope: %v", err)
	}
	if _, err := tx.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// The failure the grace window exists for, reproduced live against the hub on
// 2026-10-11: the hub rotates T0 into T1, the response carrying T1 never
// reaches the browser (its tab closed mid-request), and the browser's next
// refresh presents T0. That is exchanged once — and only once.
func TestRotateRefreshToken_GraceExchangesALostRotationOnce(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tenantID, userID := testUser(t, pool)

	t0 := issueForTest(t, pool, tenantID, userID)
	lost, err := RotateRefreshTokenDetailed(ctx, pool, t0, nil)
	if err != nil || lost.Graced {
		t.Fatalf("first rotation: %+v, %v — want an ordinary rotation", lost, err)
	}

	again, err := RotateRefreshTokenDetailed(ctx, pool, t0, nil)
	if err != nil {
		t.Fatalf("re-presenting T0 while its successor is unused: got %v, want a grace exchange", err)
	}
	if !again.Graced || again.Token == "" || again.UserID != userID {
		t.Fatalf("grace exchange: got %+v, want Graced with a token for %s", again, userID)
	}

	// One live head, no fork: T0 → T1 → T2 with only T2 live.
	total, revoked := tokenRowsForUser(t, pool, tenantID, userID)
	if total != 3 || revoked != 2 {
		t.Fatalf("after the grace exchange: %d rows / %d revoked, want 3 / 2 (exactly one live head)", total, revoked)
	}
	// One-shot: T0 a third time is reuse — its successor is no longer the
	// live head — and it ends the family, including the head the grace
	// exchange just issued. An unrelated family is untouched.
	other := issueForTest(t, pool, tenantID, userID)
	if _, err := RotateRefreshTokenDetailed(ctx, pool, t0, nil); !errors.Is(err, ErrRefreshTokenReused) {
		t.Fatalf("third presentation of T0: got %v, want ErrRefreshTokenReused", err)
	}
	if _, _, err := RotateRefreshToken(ctx, pool, again.Token, nil); !errors.Is(err, ErrRefreshTokenReused) {
		t.Fatalf("the grace-issued head after detected reuse: got %v, want it revoked", err)
	}
	if _, _, err := RotateRefreshToken(ctx, pool, other, nil); err != nil {
		t.Fatalf("an unrelated family was affected: %v", err)
	}
}

// The case reuse detection exists for is untouched by the grace window: once
// the legitimate client has USED its new token, presenting the old one is a
// replay at any age, and the whole family is revoked.
func TestRotateRefreshToken_GraceNeverCoversAPredecessorOfAUsedToken(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tenantID, userID := testUser(t, pool)

	stolen := issueForTest(t, pool, tenantID, userID)
	t1, _, err := RotateRefreshToken(ctx, pool, stolen, nil)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	t2, _, err := RotateRefreshToken(ctx, pool, t1, nil) // the legitimate client carries on
	if err != nil {
		t.Fatalf("rotate t1: %v", err)
	}
	res, err := RotateRefreshTokenDetailed(ctx, pool, stolen, nil)
	if !errors.Is(err, ErrRefreshTokenReused) || res.UserID != userID {
		t.Fatalf("replaying a token whose successor was used: got (%+v, %v), want ErrRefreshTokenReused attributed to %s", res, err, userID)
	}
	if _, _, err := RotateRefreshToken(ctx, pool, t2, nil); !errors.Is(err, ErrRefreshTokenReused) {
		t.Fatalf("live head after detected reuse: got %v, want it revoked", err)
	}
}

// Outside the window, the lost-response shape is reuse again.
func TestRotateRefreshToken_GraceExpires(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tenantID, userID := testUser(t, pool)

	t0 := issueForTest(t, pool, tenantID, userID)
	if _, _, err := RotateRefreshToken(ctx, pool, t0, nil); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	graceExecScoped(t, pool, tenantID,
		`UPDATE refresh_tokens SET revoked_at = now() - make_interval(secs => $2) WHERE token_hash = $1`,
		hashOpaqueToken(t0), (RefreshReuseGrace + time.Second).Seconds())
	if _, err := RotateRefreshTokenDetailed(ctx, pool, t0, nil); !errors.Is(err, ErrRefreshTokenReused) {
		t.Fatalf("presenting T0 after the grace window: got %v, want ErrRefreshTokenReused", err)
	}
}

// A token ended by sign-out (or a password change, or an admin action) has no
// live head, so the grace window never revives it, however recent.
func TestRotateRefreshToken_GraceNeverRevivesASignedOutSession(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tenantID, userID := testUser(t, pool)

	t0 := issueForTest(t, pool, tenantID, userID)
	t1, _, err := RotateRefreshToken(ctx, pool, t0, nil)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := RevokeRefreshTokenFamily(ctx, pool, t1); err != nil {
		t.Fatalf("sign out: %v", err)
	}
	for name, tok := range map[string]string{"superseded predecessor": t0, "signed-out head": t1} {
		if _, err := RotateRefreshTokenDetailed(ctx, pool, tok, nil); !errors.Is(err, ErrRefreshTokenReused) {
			t.Errorf("%s after sign-out: got %v, want ErrRefreshTokenReused", name, err)
		}
	}
}

// Two refreshes of one token at the same instant — two tabs, or a retry racing
// the original — both succeed under the grace window, and the family still
// ends with exactly one live token: the family lock serialises them, and the
// second rotates the first's head rather than forking a sibling.
func TestRotateRefreshToken_GraceSimultaneousRefreshesDoNotFork(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tenantID, userID := testUser(t, pool)

	original := issueForTest(t, pool, tenantID, userID)
	var start, done sync.WaitGroup
	start.Add(1)
	results := make([]RotationResult, 2)
	errs := make([]error, 2)
	for i := range errs {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			start.Wait()
			results[i], errs[i] = RotateRefreshTokenDetailed(ctx, pool, original, nil)
		}(i)
	}
	start.Done()
	done.Wait()
	graced := 0
	for i, err := range errs {
		if err != nil {
			t.Fatalf("refresh %d: %v", i, err)
		}
		if results[i].Graced {
			graced++
		}
	}
	if graced != 1 {
		t.Fatalf("got %d grace exchanges, want exactly 1 (one ordinary rotation, one exchange)", graced)
	}
	total, revoked := tokenRowsForUser(t, pool, tenantID, userID)
	if total != 3 || total-revoked != 1 {
		t.Fatalf("got %d rows / %d live, want 3 / 1 — a second live token is a forked family", total, total-revoked)
	}
}

// CurrentSessionState reports must_change_password, so a refresh can tell a
// restored session what the sign-in response told the original one.
func TestCurrentSessionStateReportsMustChangePassword(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tenantID, userID := testUser(t, pool)
	for _, want := range []bool{true, false} {
		graceExecScoped(t, pool, tenantID, `UPDATE users SET must_change_password = $2 WHERE id = $1`, userID, want)
		_, got, err := CurrentSessionState(ctx, pool, userID)
		if err != nil {
			t.Fatalf("CurrentSessionState: %v", err)
		}
		if got != want {
			t.Errorf("mustChangePassword = %v, want %v", got, want)
		}
	}
}
