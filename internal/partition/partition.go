// Package partition implements ARGUS's daily partition-maintenance job — the
// fix for a real, previously-undiscovered problem: findings, incidents, and
// audit_events (migrations 000004, 000005, 000008) are all declared
// PARTITION BY RANGE, but nothing anywhere in this codebase has ever
// actually created a dated partition. Every row of every one of those three
// tables, since this project began, has landed in that table's `_default`
// catch-all partition — confirmed live against a running deployment
// (`SELECT tablename FROM pg_tables WHERE tablename LIKE '%_default'`
// returns exactly these three and nothing else). The partitioning exists
// structurally but has never actually happened, which defeats its entire
// purpose (query performance that doesn't degrade as history grows, and
// cheap, instant retention via DROP TABLE instead of a slow DELETE+VACUUM)
// at any real scale.
//
// This package closes that gap with the same architectural shape as
// internal/gateway/health.go's HealthMonitor and internal/notify's
// WebhookNotifier — an independent background poller, wired into
// cmd/hub/main.go's runAPI as its own goroutine — doing two things on a
// daily schedule:
//
//  1. Ensures the current period's and the next period's partition exist
//     for each of the three tables (CREATE TABLE IF NOT EXISTS ... PARTITION
//     OF ... FOR VALUES FROM (...) TO (...)), far enough ahead of a period
//     boundary that a burst of inserts around midnight/month-end never has
//     to wait on a just-in-time partition create. Because this also
//     includes the CURRENT period, the very first run after this ships is
//     a genuine catch-up: it creates the first real dated partition either
//     table has ever had, not just "tomorrow's."
//  2. Reads each table's configured retention (internal/settings' new
//     AuditRetentionDays/IncidentRetentionDays/FindingRetentionDays,
//     migration 000021) and, only where a real, operator-set duration
//     exists, drops whole partitions strictly older than that cutoff —
//     DROP TABLE, not a row-by-row DELETE, which is only cheap/fast
//     *because* real partitioning now exists (task 1 above). A table whose
//     retention is left at its default (nil == "keep forever") is never
//     touched by this half of the job, and a partition still within its
//     retention window is never dropped early.
//
// Explicitly NOT in scope here (see STATUS.md and the top-level task this
// package was built for): migrating the years of historical rows already
// sitting in each table's `_default` partition into real dated partitions.
// That's a real, separate, live-data migration concern — moving rows
// between partitions on a table with FORCE ROW LEVEL SECURITY, at whatever
// size the `_default` partition has grown to, is not something to fold into
// "build the ongoing mechanism" without its own design and testing pass.
// This job creates dated partitions for new writes going forward and never
// touches `_default`'s existing rows.
//
// Monthly period, chosen deliberately over daily or weekly: it already
// matches the period the original migration files' own comments committed
// to ("findings... Monthly range-partitioned," "audit_events... Partitioned
// monthly like findings/incidents" — migrations 000004/000008) before any
// job existed to actually enforce it, and it's a reasonable default for
// this data's realistic volume. §17.5 of DESIGN.md sizes a
// 1,000-cluster deployment at ~10,000 findings/day steady state — roughly
// 300K rows/month per table at that scale, comfortably within a single
// partition's practical size, and small enough at the 5-100 cluster scale
// lld/12-deployment-design.md's new capacity-planning section covers that
// daily sub-partitioning would be pure overhead (more partitions to plan
// ahead of, more catalog entries, no real benefit) for a very long time.
// Daily sub-partitioning during a genuine ingestion storm is called out as
// a conditional, not-yet-committed option in lld/05-data-model.md §10 — this
// job doesn't attempt it.
package partition

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/data"
	"argus/internal/logging"
	"argus/internal/metrics"
	"argus/internal/settings"
)

// DefaultMaintenanceInterval is how often Run sweeps. Daily is plenty: this
// is not latency-sensitive (a partition needed a month from now doesn't
// need to exist within the hour), and both halves of sweep are idempotent
// (CREATE TABLE IF NOT EXISTS; DROP TABLE IF EXISTS on an already-computed,
// already-past-cutoff partition), so a missed tick or two from a hub
// restart is harmless — the next successful tick catches up completely.
const DefaultMaintenanceInterval = 24 * time.Hour

// tableSpec is everything sweep needs to know about one partitioned table:
// which column it's range-partitioned on (for the FOR VALUES FROM/TO bounds)
// and which settings.Config field holds its configured retention. The three
// values here are the single place this table-to-retention-column mapping
// exists in Go — migration 000021's comment points back here, keep both in
// sync if either changes.
type tableSpec struct {
	table          string
	partitionKey   string // the column PARTITION BY RANGE uses
	retentionField string // human-readable only, used in log lines
}

var tableSpecs = []tableSpec{
	{table: "findings", partitionKey: "occurred_at", retentionField: "findingRetentionDays"},
	{table: "incidents", partitionKey: "first_seen", retentionField: "incidentRetentionDays"},
	{table: "audit_events", partitionKey: "occurred_at", retentionField: "auditRetentionDays"},
}

// Maintainer owns the daily partition-ensure/retention-drop job.
type Maintainer struct {
	db *data.DB
}

// NewMaintainer constructs a Maintainer. Doesn't start sweeping — call Run
// for that.
func NewMaintainer(db *data.DB) *Maintainer {
	return &Maintainer{db: db}
}

// Run sweeps once immediately, then ticks every interval, until ctx is
// cancelled. Blocks — callers run it in its own goroutine, the same pattern
// cmd/hub/main.go's runAPI already uses for gateway.HealthMonitor.Run and
// notify.WebhookNotifier.Run.
//
// The immediate sweep before entering the ticker loop is a deliberate
// deviation from HealthMonitor/WebhookNotifier (neither of which sweeps
// before their first tick): this job's very first run on an existing
// deployment is a one-time catch-up (see the package doc comment) — every
// row so far has landed in `_default`, so waiting a full DefaultMaintenanceInterval
// before creating the first real dated partition would mean an entire extra
// day of new writes still landing in `_default` for no reason. Every
// subsequent call is a no-op repeat of idempotent work, so running it once
// extra on every hub restart is harmless.
// logger is this package's structured logger (PROJECT.md T22).
var logger = logging.For("partition")

func (m *Maintainer) Run(ctx context.Context, interval time.Duration) {
	m.runOnce(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.runOnce(ctx)
		}
	}
}

// runOnce is one sweep plus its correlation id and its metrics — factored
// out because Run calls it twice (once at startup, once per tick) and the
// two must not drift apart.
func (m *Maintainer) runOnce(ctx context.Context) {
	sweepCtx, _ := logging.NewUnitOfWork(ctx)
	start := time.Now()
	err := m.sweep(sweepCtx)
	metrics.ObserveSweeperRun("partition", time.Since(start), err)
	if err != nil {
		logger.ErrorContext(sweepCtx, "partition-maintenance sweep failed", logging.Err(err))
	}
}

// sweep runs one full pass: ensure this-period-and-next partitions for every
// table (Part A), then apply each table's configured retention, if any
// (Part B). Each table is handled independently and errors are logged, not
// fatal to the sweep — one table's DDL failure (e.g. a lock held by a
// concurrent migration) should never prevent the other two tables from
// getting their maintenance done on this tick.
//
// Deliberately does not open one RLS-scoped transaction the way
// gateway.HealthMonitor.sweep/notify.WebhookNotifier.sweep do: everything
// here is schema-level DDL (CREATE TABLE/DROP TABLE) or a system-catalog
// read (pg_tables), neither of which row-level security ever governs, and
// org_settings itself carries no RLS at all (migration 000018's comment).
// There is no per-request tenant/cluster scope to set because none of this
// work is scoped to a tenant or cluster in the first place — it operates on
// whole tables.
func (m *Maintainer) sweep(ctx context.Context) error {
	now := time.Now().UTC()

	cfg, err := settings.Resolve(ctx, m.db.Pool)
	if err != nil {
		return fmt.Errorf("resolve retention settings: %w", err)
	}
	retentionDays := map[string]*int{
		"findings":     cfg.FindingRetentionDays,
		"incidents":    cfg.IncidentRetentionDays,
		"audit_events": cfg.AuditRetentionDays,
	}

	for _, spec := range tableSpecs {
		if err := m.ensureUpcomingPartitions(ctx, spec, now); err != nil {
			logger.ErrorContext(ctx, "ensuring partitions for a table failed",
				slog.String("table", spec.table), logging.Err(err))
		}
		if err := m.applyRetention(ctx, spec, retentionDays[spec.table], now); err != nil {
			logger.ErrorContext(ctx, "applying retention for a table failed",
				slog.String("table", spec.table), logging.Err(err))
		}
	}
	return nil
}

// ensureUpcomingPartitions creates spec.table's partition for the month
// containing `now` (the catch-up case on a fresh deployment; a no-op
// IF NOT EXISTS on every later run) and for the following month (the
// ahead-of-time case — by the time a month actually rolls over, its
// partition has existed since the previous day's sweep at the very latest,
// so a burst of inserts at midnight on the 1st never waits on a
// just-in-time create).
func (m *Maintainer) ensureUpcomingPartitions(ctx context.Context, spec tableSpec, now time.Time) error {
	thisMonth := monthStart(now)
	nextMonth := nextMonthStart(thisMonth)
	for _, ms := range []time.Time{thisMonth, nextMonth} {
		created, err := m.ensurePartition(ctx, spec.table, ms)
		if err != nil {
			return err
		}
		if created {
			start, end := monthBounds(ms)
			logger.InfoContext(ctx, "created partition",
				slog.String("partition", partitionName(spec.table, ms)),
				slog.String("table", spec.table),
				slog.Time("range_from", start), slog.Time("range_to", end))
		}
	}
	return nil
}

// ensurePartition issues CREATE TABLE IF NOT EXISTS ... PARTITION OF ... for
// the single month starting at monthStart, and reports whether it actually
// created anything (so the caller only logs real creates, not every
// already-exists no-op). Table/partition identifiers are built from
// pgx.Identifier.Sanitize() rather than parameterised — both are always
// either the fixed, hardcoded table name from tableSpecs or a name this
// package itself computed from it (see partitionName), never
// caller/request-supplied input, so there is no injection surface despite
// the string-built SQL; Postgres has no other way to parameterise a bare
// identifier in DDL.
//
// The FOR VALUES FROM/TO bounds are ALSO string-built rather than passed as
// bind parameters ($1/$2), for a different, harder reason: Postgres's DDL
// grammar does not accept bind parameters inside a partition bound
// expression at all — `CREATE TABLE ... FOR VALUES FROM ($1) TO ($2)` fails
// at the protocol level with "mismatched param and argument count" no
// matter how many parameters are supplied, confirmed live against a real
// Postgres 16 while building this job. The bound values are formatted as
// quoted RFC3339 literals instead; safe here for the same reason the
// identifiers above are — start/end are always this package's own
// monthBounds() output, never request-supplied.
func (m *Maintainer) ensurePartition(ctx context.Context, table string, monthStart time.Time) (created bool, err error) {
	start, end := monthBounds(monthStart)
	name := partitionName(table, monthStart)

	// Checked BEFORE issuing CREATE, not after — immediately after a
	// successful CREATE TABLE IF NOT EXISTS, pg_tables shows the partition
	// as present unconditionally (whether it already existed or was just
	// created), so that ordering could never actually distinguish the two
	// cases. A query error here only degrades the log line below to "assume
	// not newly created" — it does not skip or fail the CREATE itself.
	existedBefore, err := m.partitionExists(ctx, name)
	if err != nil {
		logger.WarnContext(ctx, "partition existence check failed; assuming it was not newly created",
			slog.String("partition", name), logging.Err(err))
	}

	sql := fmt.Sprintf(
		"CREATE TABLE IF NOT EXISTS %s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')",
		pgx.Identifier{name}.Sanitize(), pgx.Identifier{table}.Sanitize(),
		start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339),
	)
	if _, err := m.db.Pool.Exec(ctx, sql); err != nil {
		return false, fmt.Errorf("create partition %s: %w", name, err)
	}
	return !existedBefore, nil
}

// partitionExists reports whether name currently exists as a table in the
// public schema.
func (m *Maintainer) partitionExists(ctx context.Context, name string) (bool, error) {
	var count int
	err := m.db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM pg_tables WHERE schemaname = 'public' AND tablename = $1`, name,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// applyRetention drops every dated partition of spec.table whose entire
// range is strictly older than retentionDays before now. A nil
// retentionDays (the shipped default — see internal/settings.Config's doc
// comment and migration 000021) means "keep forever": this function returns
// immediately without listing or dropping anything, and in particular never
// touches `table`_default (excluded by construction — see
// listDatedPartitions).
func (m *Maintainer) applyRetention(ctx context.Context, spec tableSpec, retentionDays *int, now time.Time) error {
	if retentionDays == nil {
		return nil
	}
	cutoff := retentionCutoff(now, *retentionDays)

	names, err := m.listDatedPartitions(ctx, spec.table)
	if err != nil {
		return fmt.Errorf("list partitions: %w", err)
	}

	for _, name := range names {
		partMonth, ok := parsePartitionMonth(spec.table, name)
		if !ok {
			// Not one of this job's own dated partitions (e.g. `_default`,
			// or something created by hand under a different naming scheme)
			// — never a candidate for this job to drop.
			continue
		}
		if pastRetention(partMonth, cutoff) {
			if err := m.dropPartition(ctx, name); err != nil {
				return fmt.Errorf("drop partition %s: %w", name, err)
			}
			logger.WarnContext(ctx, "dropped a partition past its retention window",
				slog.String("partition", name), slog.String("table", spec.table),
				slog.Int("retention_days", *retentionDays), slog.Time("cutoff", cutoff))
		}
	}
	return nil
}

// listDatedPartitions returns every child partition of table that this
// package's own naming scheme produced (see partitionName/parsePartitionMonth)
// — i.e. every candidate applyRetention might drop. table_default never
// matches (its name has no "_y" year/month suffix), so it is structurally
// excluded from this list, not just skipped by a special-cased check: this
// job can never drop the default partition or anything not shaped like one
// of its own dated partitions, no matter what retentionDays is set to.
func (m *Maintainer) listDatedPartitions(ctx context.Context, table string) ([]string, error) {
	rows, err := m.db.Pool.Query(ctx,
		`SELECT c.relname
		   FROM pg_inherits i
		   JOIN pg_class c ON c.oid = i.inhrelid
		   JOIN pg_class p ON p.oid = i.inhparent
		  WHERE p.relname = $1`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// dropPartition issues DROP TABLE IF EXISTS for a name this package itself
// already confirmed is one of its own dated partitions (listDatedPartitions
// + parsePartitionMonth, both called before this by applyRetention) — same
// "internally-generated identifier, not request input" reasoning as
// ensurePartition's Sanitize() usage applies here too.
func (m *Maintainer) dropPartition(ctx context.Context, name string) error {
	sql := fmt.Sprintf("DROP TABLE IF EXISTS %s", pgx.Identifier{name}.Sanitize())
	_, err := m.db.Pool.Exec(ctx, sql)
	return err
}
