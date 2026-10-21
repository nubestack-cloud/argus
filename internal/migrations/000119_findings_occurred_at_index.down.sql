-- Drops the fleet-wide scan index. Nothing depends on it for correctness:
-- GET /api/v1/findings returns the same rows in the same order without it,
-- by sequentially scanning every partition in the window and sorting. Dropping
-- the parent's index drops the per-partition ones with it.
DROP INDEX IF EXISTS findings_occurred_at_idx;
