package authz

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/domain"
)

// DefaultFindingRetentionDays is how long a new install keeps findings.
const DefaultFindingRetentionDays = 30

// EnsureBootstrap implements HLD §5.6 / lld/02-authz-spec.md §5.6: on first boot
// against an empty database, create the singleton organisation, a super-admin user,
// and its grant. Never ships a well-known default password — see the precedence
// order below. Idempotent: safe to call on every hub startup, a no-op once the
// organisation already exists.
func EnsureBootstrap(ctx context.Context, pool *pgxpool.Pool) error {
	var existingOrgCount int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM organisations").Scan(&existingOrgCount); err != nil {
		return fmt.Errorf("check existing organisations: %w", err)
	}
	if existingOrgCount > 0 {
		return nil // already bootstrapped
	}

	orgID := domain.NewID(domain.PrefixOrganisation)
	userID := domain.NewID(domain.PrefixUser)
	grantID := domain.NewID(domain.PrefixGrant)

	password, fromEnv := bootstrapPassword()
	hash, err := HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash bootstrap password: %w", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin bootstrap transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is a no-op after a successful commit

	if _, err := tx.Exec(ctx,
		"INSERT INTO organisations (id, name) VALUES ($1, $2)",
		orgID, "default"); err != nil {
		return fmt.Errorf("insert organisation: %w", err)
	}

	// users/grants have FORCE ROW LEVEL SECURITY (000009_row_level_security.up.sql),
	// and Postgres reuses a table's USING clause as its WITH CHECK clause by default
	// — so without this, the INSERTs below would be rejected by their own RLS
	// policy, since app.tenant_id has no value yet at true first boot. Setting it
	// to the org we just created (inside the same transaction, before the inserts
	// that need it) satisfies the policy without granting argus_app BYPASSRLS,
	// which would defeat SR-2's whole point for the sake of one bootstrap path.
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", orgID); err != nil {
		return fmt.Errorf("set bootstrap tenant scope: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO users (id, tenant_id, email, display_name, password_hash, must_change_password)
		 VALUES ($1, $2, $3, $4, $5, true)`,
		userID, orgID, "admin@localhost", "Super Admin", hash); err != nil {
		return fmt.Errorf("insert super-admin user: %w", err)
	}

	// scope: AllClusters, per lld/02-authz-spec.md §3 — {"type":"AllClusters"}
	if _, err := tx.Exec(ctx,
		`INSERT INTO grants (id, tenant_id, principal_type, principal_id, role_id, scope, granted_by)
		 VALUES ($1, $2, 'user', $3, 'super-admin', $4, $3)`,
		grantID, orgID, userID, `{"type":"AllClusters"}`); err != nil {
		return fmt.Errorf("insert super-admin grant: %w", err)
	}

	// A new install keeps findings for DefaultFindingRetentionDays, so the
	// database has a bound out of the box (most of its volume is findings).
	// Only here, on first boot: an existing install keeps whatever it chose,
	// including keeping them forever, and an admin changes it in Settings.
	if _, err := tx.Exec(ctx,
		`UPDATE org_settings SET finding_retention_days = $1 WHERE finding_retention_days IS NULL`,
		DefaultFindingRetentionDays); err != nil {
		return fmt.Errorf("set default finding retention: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit bootstrap transaction: %w", err)
	}

	if fromEnv {
		logger.InfoContext(ctx, "super-admin created from ARGUS_BOOTSTRAP_PASSWORD", slog.String("email", "admin@localhost"))
	} else {
		// Printed exactly once, per HLD §5.6 — never logged again, never stored
		// anywhere but as the hash already committed above.
		fmt.Println("=================================================================")
		fmt.Println(" ARGUS bootstrap super-admin created.")
		fmt.Println("   email:    admin@localhost")
		fmt.Printf("   password: %s\n", password)
		fmt.Println(" This password is shown ONCE and is not recoverable. A password")
		fmt.Println(" change is required on first login.")
		fmt.Println("=================================================================")
	}

	return nil
}

// bootstrapPassword implements the precedence order in HLD §5.6: an operator-supplied
// secret first, a generated high-entropy password otherwise.
func bootstrapPassword() (password string, fromEnv bool) {
	if p := os.Getenv("ARGUS_BOOTSTRAP_PASSWORD"); p != "" {
		return p, true
	}
	buf := make([]byte, 20) // 160 bits
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failing is not a recoverable condition worth a softer path.
		panic(fmt.Errorf("generate bootstrap password: %w", err))
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), false
}
