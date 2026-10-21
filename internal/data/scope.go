package data

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// This file exists because "remember to call SetRequestScope" is not a control.
//
// This codebase has gotten RLS scoping wrong four times: the bootstrap insert,
// refresh-token issuance, refresh-token rotation, and PROJECT.md B175 — a
// hand-written DELETE that ran on an unscoped transaction, matched nothing
// under FORCE ROW LEVEL SECURITY, deleted 0 rows, and reported no error,
// because every return value was discarded. Each fix was correct and none of
// them removed the next author's opportunity to make the same mistake.
//
// Authenticated HTTP has never been in that set, and the reason is structural
// rather than cultural: requireAuth opens the transaction and sets scope
// before a handler runs, so a handler has no way to obtain an unscoped one.
// InScope gives background work — sweepers, reconcilers, the unattended
// executor — the same property. The callback is handed an already-scoped
// pgx.Tx, so there is no window in which an unscoped transaction exists and
// no separate step for a future author to omit; commit and rollback are the
// helper's problem, so a discarded commit error cannot repeat PROJECT.md B175's
// silent success either.
//
// SetRequestScope remains exported and remains the only place the RLS session
// variables are set (see db.go's package comment) — InScope calls it. Code
// that genuinely runs before any tenant scope can exist still uses the raw
// pool, and internal/data/scope_structural_test.go is the list of those places
// plus the reason each one is on it.

// Beginner is the slice of *pgxpool.Pool that InScope needs.
//
// An interface rather than *pgxpool.Pool for the same reason
// internal/api's txBeginner is one: it makes "the database is unavailable"
// reachable from a test suite with no Postgres. Everything past Begin already
// works against pgx.Tx, which is itself an interface, so this adds no layer.
type Beginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// ErrNoTenantScope is returned when InScope is asked to scope a transaction to
// an empty tenant.
//
// Failing loudly is the whole point. An empty app.tenant_id is not "no filter",
// it is a filter that matches no row in any table with FORCE ROW LEVEL
// SECURITY — so a SELECT returns nothing and a DELETE removes nothing, both
// without an error. That is precisely PROJECT.md B175's failure mode, and a caller
// that cannot name its tenant has a bug upstream of the query.
var ErrNoTenantScope = errors.New("data: refusing to open a transaction with an empty tenant id — under FORCE ROW LEVEL SECURITY that silently matches zero rows instead of failing")

// InScope runs fn inside a transaction that already has RLS scope set to
// tenantID and accessibleClusterIDs, then commits it. If fn returns an error
// the transaction is rolled back and that error is returned unwrapped, so
// callers can still errors.Is/errors.As their own sentinels through it.
//
// accessibleClusterIDs nil means fleet-wide within the tenant, matching
// SetRequestScope: that is what a background job that legitimately works
// across every cluster passes. It is not a way to opt out of scoping —
// app.tenant_id is still set, and every RLS policy still applies.
//
// fn receives the ctx as an argument rather than closing over it so that a
// future timeout or cancellation wrapper here reaches the queries inside.
func InScope(ctx context.Context, pool Beginner, tenantID string, accessibleClusterIDs []string, fn func(ctx context.Context, tx pgx.Tx) error) error {
	if tenantID == "" {
		return ErrNoTenantScope
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin scoped transaction: %w", err)
	}
	// No-op once Commit has succeeded; the safety net for every early return
	// and every panic in fn.
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := SetRequestScope(ctx, tx, tenantID, accessibleClusterIDs); err != nil {
		return err
	}
	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit scoped transaction: %w", err)
	}
	return nil
}

// InFleetScope is InScope for a background job that works across the whole
// fleet and has no tenant in hand to start from.
//
// It resolves the single organisation inside the transaction and passes it to
// fn, which is the SingleOrganisationID + SetRequestScope(..., nil) pattern
// every sweeper in internal/orchestrator, internal/notify and
// internal/autoanalyze had hand-rolled — four copies of it carried a comment
// pointing at one of the others as the reference implementation, which is a
// good sign it wanted to be a function.
//
// The resolve happens inside the transaction on purpose: `organisations`
// deliberately has no RLS policy (see SingleOrganisationID), so it is readable
// before scope is set, and doing it in the same transaction means the tenant
// the job scopes to is the tenant it read.
//
// When a second organisation is ever hosted here, this is one of the two
// places that has to change (SingleOrganisationID is the other).
func InFleetScope(ctx context.Context, pool Beginner, fn func(ctx context.Context, tx pgx.Tx, tenantID string) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin fleet-scoped transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := SingleOrganisationID(ctx, tx)
	if err != nil {
		return err
	}
	if tenantID == "" {
		return ErrNoTenantScope
	}
	if err := SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		return err
	}
	if err := fn(ctx, tx, tenantID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit fleet-scoped transaction: %w", err)
	}
	return nil
}

// InClusterScope is InFleetScope narrowed to one cluster: the shape for a
// background write against a single cluster's scoped tables, where
// cluster-scoped RLS WITH CHECK requires the row's cluster to be in scope.
func InClusterScope(ctx context.Context, pool Beginner, clusterID string, fn func(ctx context.Context, tx pgx.Tx, tenantID string) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin cluster-scoped transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tenantID, err := SingleOrganisationID(ctx, tx)
	if err != nil {
		return err
	}
	if tenantID == "" {
		return ErrNoTenantScope
	}
	if err := SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		return err
	}
	if err := fn(ctx, tx, tenantID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit cluster-scoped transaction: %w", err)
	}
	return nil
}

// ReadInScope is InScope for work that must not commit: it begins, sets scope,
// runs fn, and always rolls back.
//
// Two call sites need this rather than InScope, and both say so in their own
// comments. internal/api's unattended executor opens a transaction purely to
// give preparePlan a reader while the actual writes happen in separate
// transactions opened by the recording functions — that split is what makes a
// crash mid-execution leave an honest record, and committing this one would
// start quietly collapsing it. internal/notify's settings read has nothing to
// commit and says so.
//
// A rollback of a transaction that wrote nothing is identical to a commit of
// it, so this is not a safety control — it is a statement of intent that the
// compiler keeps true. Use InScope unless the read-only-ness is load-bearing.
func ReadInScope(ctx context.Context, pool Beginner, tenantID string, accessibleClusterIDs []string, fn func(ctx context.Context, tx pgx.Tx) error) error {
	if tenantID == "" {
		return ErrNoTenantScope
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin read-only scoped transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := SetRequestScope(ctx, tx, tenantID, accessibleClusterIDs); err != nil {
		return err
	}
	return fn(ctx, tx)
}
