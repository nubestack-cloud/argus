package data

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// SetAppRolePassword sets the LOGIN password on the argus_app role, which the
// RLS migration (000009_row_level_security.up.sql) deliberately creates NOLOGIN
// — no password ever belongs in a migration file. Called with the
// migration-owning connection (the same one RunMigrations uses), immediately
// after migrating, so there is no separate container/step for this — see
// STATUS.md's note on why that separate step (`hub-app-role`) was removed.
//
// The password comes from a trusted deploy-time environment variable, not
// attacker-reachable input, but it's still escaped correctly (doubling single
// quotes, the standard SQL literal escape) rather than trusted to never contain
// one — a self-hosted operator's password manager can generate anything.
func SetAppRolePassword(ctx context.Context, connString, password string) error {
	conn, err := pgx.Connect(ctx, connString)
	if err != nil {
		return fmt.Errorf("connect to set app role password: %w", err)
	}
	defer conn.Close(ctx)

	escaped := strings.ReplaceAll(password, "'", "''")
	if _, err := conn.Exec(ctx, fmt.Sprintf("ALTER ROLE argus_app LOGIN PASSWORD '%s'", escaped)); err != nil {
		return fmt.Errorf("alter argus_app role: %w", err)
	}
	return nil
}
