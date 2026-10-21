package data_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"argus/internal/data"
)

// These exercise the part of PROJECT.md G11 the structural tests cannot see:
// that the callback never gets a transaction which has not had scope set on
// it, and that the caller cannot end up having discarded a commit error —
// the second half of what made PROJECT.md B175 silent.
//
// No Postgres needed. Beginner is an interface for exactly this reason, and
// pgx.Tx is one already.

type fakeTx struct {
	pgx.Tx // nil: any method these tests do not stub panics loudly rather than lying

	execs      []string
	committed  bool
	rolledBack bool
	execErr    error
	commitErr  error
}

func (f *fakeTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.execs = append(f.execs, sql)
	return pgconn.CommandTag{}, f.execErr
}

func (f *fakeTx) Commit(ctx context.Context) error {
	if f.commitErr != nil {
		return f.commitErr
	}
	f.committed = true
	return nil
}

func (f *fakeTx) Rollback(ctx context.Context) error {
	f.rolledBack = true
	return nil
}

type fakePool struct {
	tx       *fakeTx
	beginErr error
	begins   int
}

func (p *fakePool) Begin(ctx context.Context) (pgx.Tx, error) {
	p.begins++
	if p.beginErr != nil {
		return nil, p.beginErr
	}
	return p.tx, nil
}

func TestInScopeSetsScopeBeforeTheCallbackRuns(t *testing.T) {
	tx := &fakeTx{}
	pool := &fakePool{tx: tx}

	var sawAtCallbackEntry int
	err := data.InScope(context.Background(), pool, "org_1", []string{"cl_a"}, func(ctx context.Context, got pgx.Tx) error {
		sawAtCallbackEntry = len(tx.execs)
		return nil
	})
	if err != nil {
		t.Fatalf("InScope: %v", err)
	}
	if sawAtCallbackEntry != 2 {
		t.Errorf("callback entered with %d scope statements already run, want 2 (app.tenant_id and app.accessible_cluster_ids) — the callback must never see a transaction that has not been scoped", sawAtCallbackEntry)
	}
	if !tx.committed {
		t.Error("InScope did not commit a successful callback")
	}
}

func TestInScopeRefusesAnEmptyTenant(t *testing.T) {
	pool := &fakePool{tx: &fakeTx{}}
	called := false
	err := data.InScope(context.Background(), pool, "", nil, func(ctx context.Context, tx pgx.Tx) error {
		called = true
		return nil
	})
	if !errors.Is(err, data.ErrNoTenantScope) {
		t.Errorf("InScope with an empty tenant returned %v, want ErrNoTenantScope — an empty app.tenant_id matches zero rows instead of failing, which is PROJECT.md B175's whole failure mode", err)
	}
	if called {
		t.Error("the callback ran despite an empty tenant")
	}
	if pool.begins != 0 {
		t.Error("a transaction was opened despite an empty tenant")
	}
}

func TestInScopeRollsBackAndReturnsTheCallbackError(t *testing.T) {
	sentinel := errors.New("callback said no")
	tx := &fakeTx{}
	pool := &fakePool{tx: tx}

	err := data.InScope(context.Background(), pool, "org_1", nil, func(ctx context.Context, got pgx.Tx) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("InScope returned %v, want the callback's own error unwrapped so callers can still errors.Is it", err)
	}
	if tx.committed {
		t.Error("InScope committed a failed callback")
	}
	if !tx.rolledBack {
		t.Error("InScope did not roll back a failed callback")
	}
}

func TestInScopeSurfacesACommitFailure(t *testing.T) {
	boom := errors.New("commit exploded")
	tx := &fakeTx{commitErr: boom}
	pool := &fakePool{tx: tx}

	err := data.InScope(context.Background(), pool, "org_1", nil, func(ctx context.Context, got pgx.Tx) error {
		return nil
	})
	if !errors.Is(err, boom) {
		t.Errorf("InScope returned %v, want the commit error — a swallowed commit is the other half of what made PROJECT.md B175 report success", err)
	}
}

func TestInScopeStopsIfScopeCannotBeSet(t *testing.T) {
	boom := errors.New("set_config refused")
	tx := &fakeTx{execErr: boom}
	pool := &fakePool{tx: tx}

	called := false
	err := data.InScope(context.Background(), pool, "org_1", nil, func(ctx context.Context, got pgx.Tx) error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("InScope returned nil after failing to set scope")
	}
	if called {
		t.Error("the callback ran on a transaction whose scope could not be set — this is precisely the state the helper exists to make unreachable")
	}
	if tx.committed {
		t.Error("InScope committed after failing to set scope")
	}
}

func TestReadInScopeNeverCommits(t *testing.T) {
	tx := &fakeTx{}
	pool := &fakePool{tx: tx}

	if err := data.ReadInScope(context.Background(), pool, "org_1", nil, func(ctx context.Context, got pgx.Tx) error {
		return nil
	}); err != nil {
		t.Fatalf("ReadInScope: %v", err)
	}
	if tx.committed {
		t.Error("ReadInScope committed — its two callers rely on it not doing that")
	}
	if !tx.rolledBack {
		t.Error("ReadInScope did not roll back")
	}
	if len(tx.execs) != 2 {
		t.Errorf("ReadInScope ran %d scope statements, want 2", len(tx.execs))
	}
}
