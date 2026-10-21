package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"

	"argus/internal/argusctl"
)

// runAuditVerify implements `argusctl audit verify` — SR-15
// (lld/01-threat-model.md, lld/05-data-model.md §7): a standalone tool that
// walks the whole audit_events hash chain and flags the first row where
// recomputation diverges. Deliberately not a hub API endpoint — see
// internal/argusctl/audit.go's package comment for why "not controllable by
// a compromised hub" is the actual point of this command existing as its own
// binary rather than a route.
func runAuditVerify(args []string) {
	fs := flag.NewFlagSet("audit verify", flag.ExitOnError)
	dbURL := fs.String("database-url", "", "Postgres connection string with full, cross-tenant read access to audit_events "+
		"(a role that bypasses row-level security — e.g. a superuser). Default: $ARGUS_MIGRATE_DATABASE_URL, then $ARGUS_DATABASE_URL.")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	connString := *dbURL
	if connString == "" {
		connString = envOr("ARGUS_MIGRATE_DATABASE_URL", "")
	}
	if connString == "" {
		connString = envOr("ARGUS_DATABASE_URL", "")
	}
	if connString == "" {
		fail("no database connection string given: pass --database-url, or set $ARGUS_MIGRATE_DATABASE_URL or $ARGUS_DATABASE_URL")
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, connString)
	if err != nil {
		fail("could not connect to postgres: %v", err)
	}
	defer conn.Close(ctx)

	// This tool deliberately needs the OPPOSITE precondition
	// internal/data.DB.CheckRLSPreconditions enforces for the hub's own app
	// connection (SR-2: the app must NOT be able to bypass RLS, so its
	// tenant-scoping guarantees actually hold). audit_events has FORCE ROW
	// LEVEL SECURITY (migration 000009) with policies keyed on
	// app.tenant_id/app.accessible_cluster_ids — session variables nothing
	// sets on a bare psql-style connection like this one. A non-bypassing
	// connection would therefore see ZERO rows regardless of how many really
	// exist, and this tool would misreport a chain of hidden rows as "intact"
	// (vacuously true over an empty set) instead of failing loudly — exactly
	// the false negative a tamper-evidence tool must never produce. So: fail
	// outright rather than silently "verify" a filtered view.
	currentUser, bypasses, err := argusctl.RoleBypassesRLS(ctx, conn)
	if err != nil {
		fail("could not check whether %s can see all audit_events rows: %v", connStringRedacted(connString), err)
	}
	if !bypasses {
		fail(`connected as role %q, which does not bypass row-level security.
audit_events has FORCE ROW LEVEL SECURITY — a non-bypassing role sees only
rows matching the (unset, in a bare connection like this one) app.tenant_id /
app.accessible_cluster_ids session variables, which is likely ZERO rows, not
a genuinely empty or intact table. This tool must connect as a role that
bypasses RLS entirely (a superuser, or a role with the BYPASSRLS attribute)
so it can see every tenant's rows — use --database-url, or
$ARGUS_MIGRATE_DATABASE_URL (the migration-owning connection, already a
superuser in this project's dev/compose setup), not $ARGUS_DATABASE_URL (the
argus_app role, which is deliberately NOT allowed to bypass RLS — see
internal/data.DB.CheckRLSPreconditions).`, currentUser)
	}

	rows, err := argusctl.LoadAuditEvents(ctx, conn)
	if err != nil {
		fail("could not read audit_events: %v", err)
	}

	report := argusctl.VerifyChain(rows)
	if report.OK() {
		fmt.Printf("audit verify: checked %d row(s). Chain intact.\n", report.RowsChecked)
		return
	}

	d := report.Divergence
	fmt.Fprintf(os.Stderr, "audit verify: checked %d row(s). CHAIN NOT INTACT.\n", report.RowsChecked)
	fmt.Fprintf(os.Stderr, "  first divergent row: id=%s occurred_at=%s (position %d in the chain)\n", d.ID, d.OccurredAt.Format("2006-01-02T15:04:05.000000Z07:00"), d.RowIndex)
	switch d.Kind {
	case argusctl.FailureHashMismatch:
		fmt.Fprintf(os.Stderr, "  check failed: recomputed hash does not match this row's stored hash\n")
		fmt.Fprintf(os.Stderr, "    expected (stored hash):    %s\n", d.Expected)
		fmt.Fprintf(os.Stderr, "    actual (recomputed hash):  %s\n", d.Actual)
		fmt.Fprintf(os.Stderr, "  meaning: this row's own core fields (or its stored hash itself) were altered after it was written.\n")
	case argusctl.FailurePrevHashMismatch:
		fmt.Fprintf(os.Stderr, "  check failed: this row's stored prev_hash does not match the preceding row's stored hash\n")
		fmt.Fprintf(os.Stderr, "    expected (preceding row's hash, or genesis for row 0): %s\n", d.Expected)
		fmt.Fprintf(os.Stderr, "    actual (this row's stored prev_hash):                   %s\n", d.Actual)
		fmt.Fprintf(os.Stderr, "  meaning: the chain link into this row is broken — an earlier row's hash was altered without this row's prev_hash being updated to match, or this row was spliced in out of place.\n")
	default:
		fmt.Fprintf(os.Stderr, "  check failed: unknown failure kind %q\n", d.Kind)
	}
	os.Exit(1)
}

// connStringRedacted returns just enough of a Postgres connection string to
// be useful in an error message without echoing a password back to the
// terminal/logs.
func connStringRedacted(s string) string {
	if cfg, err := pgx.ParseConfig(s); err == nil {
		return fmt.Sprintf("%s@%s:%d/%s", cfg.User, cfg.Host, cfg.Port, cfg.Database)
	}
	return "<connection string>"
}
