-- BACKLOG.md T2 (candidate 3): "self-healed" and "remediated" read identically
-- as `Resolved` today. Measured 2026-09-04 on this dev DB: of 336 Resolved
-- incidents, only 4 carry a merged pull request and 36 carry a succeeded
-- execution — the rest (roughly 88%) closed with no ARGUS action behind them
-- at all, which is exactly the "closes by attrition, and the product cannot
-- tell the difference" gap T2's own entry names.
--
-- resolution_kind is set ONLY on the transition INTO Resolved
-- (internal/orchestrator/db.go's SetState, the one function that ever writes
-- incidents.state — see deriveResolutionKind's own doc comment there), and it
-- is NULL for every other state, including Dismissed: a human's active
-- rejection of a plan is a different fact than "this closed, and here is
-- what closed it," and forcing it into this enum would misdescribe it rather
-- than leave it honestly inapplicable.
--
-- Two values, not more: BACKLOG.md T2's own text asks for exactly this
-- split ("self-healed" vs "remediated"), and only for a fact this codebase
-- can safely derive after the fact — "did this incident have any linked
-- execution/PR at all" — never for "was the underlying fault actually gone
-- vs still lurking," which nothing here can know retroactively. See the
-- backfill UPDATE below for why applying that exact test to already-Resolved
-- rows is safe where guessing at the second question would not be.
ALTER TABLE incidents ADD COLUMN resolution_kind text
  CHECK (resolution_kind IN ('remediated', 'self_healed'));

-- Backfill, not a guess: this UPDATE runs the IDENTICAL test
-- deriveResolutionKind applies going forward (a succeeded
-- remediation_executions row, or a non-null pr_merged_at) against every row
-- already sitting in Resolved. That is the one fact BACKLOG.md T2 explicitly
-- sanctions recovering after the fact — it does not reinterpret WHY any of
-- these 336 rows closed, only records whether ARGUS's own remediation
-- machinery had anything to do with it, which is exactly as true today as it
-- was the moment each row closed.
UPDATE incidents
   SET resolution_kind = CASE
         WHEN pr_merged_at IS NOT NULL
           OR EXISTS (
             SELECT 1 FROM remediation_executions re
              WHERE re.incident_id = incidents.id AND re.outcome = 'succeeded'
           )
         THEN 'remediated'
         ELSE 'self_healed'
       END
 WHERE state = 'Resolved';

-- No index: read by incident id (the primary key) for one row, or aggregated
-- fleet-wide by internal/api's digest/insights queries, which already scan
-- incidents under whatever clusterId/state scope bounds them — same
-- reasoning as every other pr_* column's own "no index" note.
