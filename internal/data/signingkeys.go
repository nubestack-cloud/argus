package data

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// LoadOrCreateSigningKey implements the load-if-present /
// generate-and-persist-if-not pattern backing internal/migrations/000016_signing_keys.
// It's the shared plumbing behind authz.NewPersistentTokenSigner,
// authz.NewPersistentEnrollmentSigner, and gateway.NewPersistentDevCA — each
// of those callers only supplies its own key-generation function and knows
// how to turn the resulting raw bytes back into its own key type; this
// function owns the one place that actually talks to the signing_keys table,
// so there is exactly one query/transaction shape to audit rather than three
// near-duplicates.
//
// Runs directly against the pool, not a caller-supplied, already-scoped
// transaction — deliberately, matching authz.EnsureBootstrap's precedent
// (internal/authz/bootstrap.go): this table has no RLS policy at all (see
// migration 000016's own comment for the full reasoning — it holds
// organisation-wide operational secrets, not tenant data, and is touched only
// by hub startup code that runs before any request/tenant scope exists), so
// there is no app.tenant_id to set and no reason to require one.
//
// Concurrency: two callers racing to initialize the same purpose is only
// plausible if the hub is somehow started twice at once against the same
// database (this codebase runs exactly one hub-api process per deployment,
// so this is a defensive correctness property, not a load-bearing scenario —
// see the callers' own doc comments). Handled without a SELECT ... FOR UPDATE
// (there is no row to lock before the first insert exists) via
// INSERT ... ON CONFLICT (purpose) DO NOTHING followed by a re-SELECT inside
// the same transaction: `purpose` is the table's primary key, so Postgres
// makes the second writer's INSERT block until the first writer's
// transaction commits or rolls back. Once that resolves, the re-SELECT in
// either transaction always observes whichever row actually won — never a
// duplicate, never a lost write, and never two different processes ending up
// with two different keys material for the same purpose.
func LoadOrCreateSigningKey(ctx context.Context, pool *pgxpool.Pool, purpose string, generate func() ([]byte, error)) (material []byte, loaded bool, err error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("begin signing key transaction (%s): %w", purpose, err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after a successful commit

	var existing []byte
	err = tx.QueryRow(ctx, "SELECT key_material FROM signing_keys WHERE purpose = $1", purpose).Scan(&existing)
	if err == nil {
		if err := tx.Commit(ctx); err != nil {
			return nil, false, fmt.Errorf("commit signing key read (%s): %w", purpose, err)
		}
		return existing, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, fmt.Errorf("look up signing key (%s): %w", purpose, err)
	}

	fresh, err := generate()
	if err != nil {
		return nil, false, fmt.Errorf("generate signing key (%s): %w", purpose, err)
	}

	if _, err := tx.Exec(ctx,
		"INSERT INTO signing_keys (purpose, key_material) VALUES ($1, $2) ON CONFLICT (purpose) DO NOTHING",
		purpose, fresh); err != nil {
		return nil, false, fmt.Errorf("insert signing key (%s): %w", purpose, err)
	}

	// Re-select rather than assume our own INSERT won the race: if a
	// concurrent caller's transaction committed first, this returns their
	// persisted value, not the one we just generated and discarded.
	if err := tx.QueryRow(ctx, "SELECT key_material FROM signing_keys WHERE purpose = $1", purpose).Scan(&existing); err != nil {
		return nil, false, fmt.Errorf("re-read signing key after insert (%s): %w", purpose, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, false, fmt.Errorf("commit signing key write (%s): %w", purpose, err)
	}

	// loaded=true here means "someone else's generation won the race, and
	// what we're returning is their persisted material, not ours" — from
	// this caller's point of view, the honest description is still that a
	// key was loaded, not generated, since nothing this call generated ever
	// took effect.
	return existing, !bytes.Equal(existing, fresh), nil
}
