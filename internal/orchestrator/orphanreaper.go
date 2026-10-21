package orchestrator

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/data"
	"argus/internal/logging"
	"argus/internal/metrics"
)

// PROJECT.md B157: deleting an incident silently orphans every child row
// that references it via incident_id, and until this file existed nothing
// reaped them. Measured 2026-09-08 on the dev database: 407 of 606
// timeline_events (67%) pointed at an incident that no longer existed, plus
// 19 orphaned analyses rows and 1 orphaned findings row.
//
// WHY THERE IS NO FOREIGN KEY, AND WHY THERE NEVER WILL BE ONE
//
// This is deliberately NOT "fixed" by adding a foreign key to incidents.
// migration 000053's own comment (incident_feedback) already spells this out
// at length, and it applies here for the identical structural reason:
// incidents is RANGE-partitioned on first_seen (migration 000005), so its
// primary key is (id, first_seen), not id alone — there is no unique
// constraint on id by itself for a child row's incident_id-only column to
// reference. Postgres refuses such a foreign key outright; the first attempt
// at incident_feedback tried exactly this and the migration failed on it.
// Every table carrying an incident_id column (this file's five, plus
// remediation_recommendations, remediation_executions, mcp_tool_calls,
// incident_notifications, incident_tolerations and others) is in the same
// position by necessity, not by oversight. Do not re-attempt the FK on any
// of them.
//
// WHY A REAPER RATHER THAN FIXING EVERY DELETE CALL SITE
//
// ARGUS itself has exactly one route that deletes an incident —
// DELETE /api/v1/demo-data (internal/api/demo_data.go's clearDemoData),
// gated behind ARGUS_ENABLE_DEMO_DATA and used only by the dev compose stack
// and web/e2e — so production exposure is low. The real source is DB-backed
// test cleanup (the internal/*_db_test.go files across this repo) deleting
// clusters/incidents by cluster_id without also deleting their children:
// some of those fixtures use internal/dbtest's Fixture, whose strict
// Cleanup only checks the tables its own TableDelete list names, so a
// fixture that never lists timeline_events/analyses/findings never learns
// it leaked them; others delete by hand and simply forget one table (see
// e.g. internal/gateway/correlation_db_test.go's clusterID-scoped cleanups,
// which never delete timeline_events). Auditing every existing call site
// and proving the audit exhaustive is not something a one-time pass can give
// a permanent guarantee for — the next fixture added the same way
// reintroduces exactly this bug, silently, the same way this one
// accumulated. A reaper closes the gap regardless of which code path forgot
// to cascade, including future ones, which a per-call-site fix cannot do.
// This is choice (a) of PROJECT.md B157's two options, not choice (b).
//
// SCOPE
//
// Limited to the three tables B157 actually measured orphans in
// (timeline_events, analyses, findings) plus the two tables that must be
// reaped BEFORE analyses for the analyses delete to succeed at all: both
// evidence.analysis_id and analysis_embeddings.analysis_id carry a real,
// NO-ACTION foreign key to analyses(id) (migrations 000005, 000082) with no
// ON DELETE clause, so an orphaned analyses row with a surviving evidence or
// analysis_embeddings child fails the delete with a foreign-key violation —
// exactly BUGS.md 119's shape, already hit once by clearDemoData for the
// same reason. Other incident_id-carrying tables
// (remediation_recommendations, remediation_executions, mcp_tool_calls,
// incident_notifications, incident_tolerations, unattended_batch_members,
// remediation_execution_attempts, mcp_tool_call_content, token_usage) are
// structurally in the same position but had no measured orphans backing
// this fix; extend sweep's pattern to one of them if a future measurement
// finds it needed, rather than reaping tables nothing has shown a problem
// in.

// DefaultOrphanReapInterval mirrors partition.DefaultMaintenanceInterval's
// cadence and reasoning: this is retroactive housekeeping, not a
// user-visible correctness path (nothing reads an orphaned row as if it
// still belonged to a live incident — every query here joins through
// incidents first), so ticking any faster than once a day buys nothing.
const DefaultOrphanReapInterval = 24 * time.Hour

// OrphanReaper deletes rows in incident-child tables whose incident_id no
// longer names a row in incidents. See this file's package-level comment
// for why no foreign key does this instead, and why a reaper rather than a
// per-call-site fix.
type OrphanReaper struct {
	db *data.DB
}

// NewOrphanReaper constructs an OrphanReaper. Doesn't start sweeping — call
// Run for that.
func NewOrphanReaper(db *data.DB) *OrphanReaper {
	return &OrphanReaper{db: db}
}

// Run ticks every interval, running one sweep per tick, until ctx is
// cancelled. Blocks — callers run it in its own goroutine, same pattern as
// every other sweeper in this package.
func (r *OrphanReaper) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweepCtx, _ := logging.NewUnitOfWork(ctx)
			start := time.Now()
			counts, err := r.sweep(sweepCtx)
			metrics.ObserveSweeperRun("orphan_reap", time.Since(start), err)
			if err != nil {
				logger.ErrorContext(sweepCtx, "orphan-reap sweep failed", logging.Err(err))
				continue
			}
			if total := counts.Total(); total > 0 {
				logger.InfoContext(sweepCtx, "deleted orphaned rows with no matching incident",
					slog.Int64("total", total),
					slog.Int64("timeline_events", counts.TimelineEvents),
					slog.Int64("evidence", counts.Evidence),
					slog.Int64("analysis_embeddings", counts.AnalysisEmbeddings),
					slog.Int64("analyses", counts.Analyses),
					slog.Int64("findings", counts.Findings))
			}
		}
	}
}

// OrphanCounts is how many rows one sweep pass actually deleted, by table —
// returned (rather than just logged) so tests can assert on it directly.
type OrphanCounts struct {
	TimelineEvents     int64
	Evidence           int64
	AnalysisEmbeddings int64
	Analyses           int64
	Findings           int64
}

// Total sums every table's count, for the single "was there anything to do
// this tick" check Run uses to decide whether to log at all.
func (c OrphanCounts) Total() int64 {
	return c.TimelineEvents + c.Evidence + c.AnalysisEmbeddings + c.Analyses + c.Findings
}

// sweep is the production entry point Run calls every tick: an unscoped
// pass across every cluster in the tenant.
func (r *OrphanReaper) sweep(ctx context.Context) (OrphanCounts, error) {
	return r.sweepClusters(ctx, nil)
}

// sweepClusters runs one pass inside a single RLS-scoped transaction — the
// same data.SingleOrganisationID + data.SetRequestScope(..., nil) fleet-wide
// pattern ApprovalSweeper.sweep/ValidationSweeper.sweep/MergeSweeper.sweep
// all use, since an orphan can belong to any cluster and production's own
// call (sweep, above) has to see every one of them in a single pass, not
// just one.
//
// clusterIDs, when non-empty, additionally restricts every delete to rows
// whose OWN cluster_id column (denormalized on all five tables per
// lld/05-data-model.md §6) is in the list — nil/empty (what sweep passes)
// means no restriction at all. This parameter exists for exactly one
// caller: this file's own tests. This repo has no separate ephemeral test
// database — ARGUS_TEST_DATABASE_URL ordinarily points at the same dev
// Postgres real work happens against (internal/dbtest's own doc comment
// explains why that package is as strict as it is: DB-test cleanup has
// twice destroyed real development data). B157 is exactly this kind of
// accumulation, already sitting in that database — an unscoped sweep run
// from an ordinary `go test ./...` would delete those real rows as a side
// effect of proving the mechanism correct, before anyone reviewing this
// change had a chance to see the count first. Scoping to a single,
// freshly-generated test cluster ID makes that structurally impossible —
// the ID cannot collide with any pre-existing row — while still exercising
// the identical SQL, and the identical RLS policies, production runs
// unscoped.
//
// Order matters: evidence and analysis_embeddings are deleted before
// analyses (see this file's package comment for why), and both are found
// via their OWN incident_id column rather than by joining through analyses
// — each is independently denormalized at write time
// (internal/api/evidence.go, internal/knowledge/store.go), so orphan
// detection here does not depend on the analyses row still existing either.
// timeline_events and findings have no foreign-key relationship to any of
// the other three or to each other, so their position in the list is
// arbitrary.
func (r *OrphanReaper) sweepClusters(ctx context.Context, clusterIDs []string) (OrphanCounts, error) {
	var counts OrphanCounts

	// PROJECT.md G11: these are hand-written DELETEs against RLS-forced tables,
	// which is exactly PROJECT.md B175's shape — an unscoped one matches nothing,
	// removes nothing and reports no error. InFleetScope means this function
	// never holds a transaction that could be in that state.
	if err := data.InFleetScope(ctx, r.db.Pool, func(ctx context.Context, tx pgx.Tx, tenantID string) error {
		var err error
		// reap runs one table's DELETE, appending the cluster restriction (if
		// any) to baseSQL's WHERE clause under the given alias, and returns how
		// many rows it actually removed.
		reap := func(table, alias, baseSQL string) (int64, error) {
			sql := baseSQL
			var args []any
			if len(clusterIDs) > 0 {
				sql += fmt.Sprintf(" AND %s.cluster_id = ANY($1)", alias)
				args = []any{clusterIDs}
			}
			tag, err := tx.Exec(ctx, sql, args...)
			if err != nil {
				return 0, fmt.Errorf("reap %s: %w", table, err)
			}
			return tag.RowsAffected(), nil
		}

		if counts.TimelineEvents, err = reap("timeline_events", "t",
			`DELETE FROM timeline_events t WHERE NOT EXISTS (SELECT 1 FROM incidents i WHERE i.id = t.incident_id)`,
		); err != nil {
			return err
		}
		if counts.Evidence, err = reap("evidence", "e",
			`DELETE FROM evidence e WHERE NOT EXISTS (SELECT 1 FROM incidents i WHERE i.id = e.incident_id)`,
		); err != nil {
			return err
		}
		if counts.AnalysisEmbeddings, err = reap("analysis_embeddings", "ae",
			`DELETE FROM analysis_embeddings ae WHERE NOT EXISTS (SELECT 1 FROM incidents i WHERE i.id = ae.incident_id)`,
		); err != nil {
			return err
		}
		if counts.Analyses, err = reap("analyses", "a",
			`DELETE FROM analyses a WHERE NOT EXISTS (SELECT 1 FROM incidents i WHERE i.id = a.incident_id)`,
		); err != nil {
			return err
		}
		// findings.incident_id is nullable (a Finding the correlation layer
		// never attached to an incident, or one an incident_tolerations rule
		// suppressed — migration 000041's own comment) — those NULL rows are
		// intentional, not orphans, and must survive this sweep.
		if counts.Findings, err = reap("findings", "f",
			`DELETE FROM findings f WHERE f.incident_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM incidents i WHERE i.id = f.incident_id)`,
		); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return counts, err
	}
	return counts, nil
}
