package knowledge

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"argus/internal/data"
	"argus/internal/logging"
	"argus/internal/metrics"
)

// DefaultBackfillSweepInterval is deliberately relaxed — this sweep exists to
// catch up analyses that predate this package (BACKLOG.md H2's 247+ real
// ones) and retry ones an earlier attempt couldn't reach Ollama for, not to
// serve a live request. Nothing in this codebase reads analysis_embeddings
// yet (L2's retrieval half is still deferred), so there is no freshness
// deadline to hit — nolint style "run whenever, it does not need to be fast."
const DefaultBackfillSweepInterval = 30 * time.Second

// backfillBatchSize bounds how many analyses one sweep tick embeds. Small on
// purpose: each one is a real Ollama call plus its own transaction, and
// nothing downstream is waiting on this sweep finishing quickly — a small
// batch keeps a single tick's cost predictable rather than trying to drain a
// large backlog in one go the first time a hub with an existing history of
// analyses starts up with this feature newly enabled.
const backfillBatchSize = 5

// RunBackfillSweep periodically embeds analyses this package hasn't embedded
// yet — see this package's own doc comment for the two cases that means
// (never attempted, or attempted and outcome not yet final) and
// analysis_embeddings' migration comment for why "no row" is the correct
// representation of "not embedded yet" rather than a nullable column. Same
// long-running-goroutine shape as internal/autoanalyze.Poller's sweepers
// (RunStaleObjectSweeper) — intended to be started once, in a `go` statement,
// at hub startup, and left running until the process exits (no graceful
// shutdown exists anywhere in this codebase yet — see that package's own
// precedent).
//
// Safe to call on a nil *Store (a no-op loop that just blocks on ctx.Done —
// still returns cleanly rather than leaving the caller to add its own nil
// check before the `go` statement).
// logger is this package's structured logger (PROJECT.md T22).
var logger = logging.For("knowledge")

func (s *Store) RunBackfillSweep(ctx context.Context, interval time.Duration) {
	if s == nil {
		<-ctx.Done()
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		sweepCtx, _ := logging.NewUnitOfWork(ctx)
		start := time.Now()
		err := s.backfillOnce(sweepCtx)
		metrics.ObserveSweeperRun("knowledge_backfill", time.Since(start), err)
		if err != nil {
			logger.ErrorContext(sweepCtx, "knowledge backfill sweep failed", logging.Err(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type backfillCandidate struct {
	analysisID string
	tenantID   string
	clusterID  string
}

func (s *Store) backfillOnce(ctx context.Context) error {
	candidates, err := s.selectBackfillCandidates(ctx, backfillBatchSize)
	if err != nil {
		return fmt.Errorf("select candidates: %w", err)
	}
	for _, c := range candidates {
		if err := s.EmbedAnalysis(ctx, c.tenantID, c.clusterID, c.analysisID); err != nil {
			logger.WarnContext(ctx, "embedding an analysis during backfill failed; it will retry on a later sweep",
				slog.String("analysis_id", c.analysisID), logging.Err(err))
			continue
		}
	}
	return nil
}

// selectBackfillCandidates runs tenant-wide, not scoped to one cluster — same
// shape as internal/autoanalyze.collectEligible, which calls
// data.SetRequestScope with a nil cluster list for the identical reason: this
// sweep has to see every analysis across the whole fleet to find the ones
// still missing (or stale) here, not just one cluster's. See migration
// 000082's RLS comment for why analysis_embeddings' policies are shaped to
// make that actually work (a permissive tenant_id policy admits every row
// when accessible_cluster_ids is empty, same as analyses/incidents/findings
// since migration 000035).
//
// limit is a parameter (not just the package-level backfillBatchSize
// constant) so this package's own tests can ask for a much larger batch than
// production ever would — this sweep's own ORDER BY a.created_at ASC means a
// real, populated deployment's oldest analyses fill a small batch first
// (BACKLOG.md H2's 247+ real ones predate this feature), and a test fixture
// created "now" would otherwise never appear in a small, fixed-size batch.
func (s *Store) selectBackfillCandidates(ctx context.Context, limit int) ([]backfillCandidate, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("resolve organisation: %w", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		return nil, fmt.Errorf("set request scope: %w", err)
	}

	// ORDER BY leads with "never embedded at all" (ae.analysis_id IS NULL,
	// true sorts after false, so DESC puts it first) ahead of "already
	// embedded, only re-embedding for a possibly-updated outcome" —
	// deliberately, found live against this deployment's real 337 analyses:
	// a handful of the OLDEST ones sit in a non-terminal state
	// (NeedsHumanInvestigation) that may never resolve, so a plain
	// `ORDER BY a.created_at ASC` re-selected those same few forever, once
	// they'd been embedded once, and starved the 318 genuinely
	// never-embedded analyses newer than them out of every batch —
	// structurally the same "LIMIT with an ORDER BY that favours dead rows"
	// class of bug this codebase has hit before (see fleetgroup's own
	// auto-analysis candidate query fix), just running in the opposite
	// direction: here it was the already-processed-at-least-once rows
	// crowding out the ones that had never been touched. Clearing the real
	// backlog takes priority; re-embedding for a stale outcome is best-effort
	// once there is no backlog left to starve.
	rows, err := tx.Query(ctx, `
		SELECT a.id, a.tenant_id, a.cluster_id
		  FROM analyses a
		  LEFT JOIN analysis_embeddings ae ON ae.analysis_id = a.id
		 WHERE ae.analysis_id IS NULL OR ae.outcome_final = false
		 ORDER BY (ae.analysis_id IS NULL) DESC, a.created_at ASC
		 LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("query backfill candidates: %w", err)
	}
	defer rows.Close()

	var candidates []backfillCandidate
	for rows.Next() {
		var c backfillCandidate
		if err := rows.Scan(&c.analysisID, &c.tenantID, &c.clusterID); err != nil {
			return nil, fmt.Errorf("scan backfill candidate: %w", err)
		}
		candidates = append(candidates, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate backfill candidates: %w", err)
	}

	return candidates, tx.Commit(ctx)
}
