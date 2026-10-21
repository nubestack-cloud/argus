-- True unattended execution, plus the blast-radius cap that ships WITH it.
--
-- WHY THESE TWO ARE ONE MIGRATION
--
-- DESIGN.md §10.5 requires blast-radius batching to ship in the same release as
-- unattended mode, and REMEDIATION_ROADMAP.md D-R7 sequences rollback, freeze
-- windows and blast-radius limits BEFORE auto-remediation. The owner chose
-- (2026-08-22) to enable unattended execution now with the smallest honest piece
-- of that safety net rather than all of it — so the cap is not optional and not
-- a follow-up. Splitting them across two migrations would allow a state where
-- unattended execution exists and nothing bounds it.
--
-- THE SPECIFIC RISK THE CAP ADDRESSES
--
-- Fleet correlation works (migration 000038). One bad image tag rolled to thirty
-- clusters produces thirty separate incidents, each individually low-risk and
-- each individually auto-approvable — which without a cap would execute
-- simultaneously across the fleet with nothing limiting the total. That is the
-- failure mode that turns one wrong diagnosis into thirty wrong mutations, and
-- it is invisible in any per-incident risk assessment because every incident is
-- genuinely low-risk on its own.
ALTER TABLE org_settings
  -- The switch. NOT NULL DEFAULT false: an installation that never touches this
  -- keeps today's behaviour exactly, where nothing reaches Executing without a
  -- human. Same conservative default as autonomy_require_reversible.
  ADD COLUMN autonomy_unattended_execution_enabled boolean NOT NULL DEFAULT false,

  -- Nullable, and NULL means "fall back to the code's own conservative value"
  -- rather than "no limit" — the analysis.maxIterations convention, deliberately
  -- NOT detection's null-means-off one. Getting that backwards here would make a
  -- blank field mean unlimited unattended execution, which is the single worst
  -- possible reading of an empty input on this page.
  ADD COLUMN autonomy_max_unattended_per_cluster integer
    CHECK (autonomy_max_unattended_per_cluster IS NULL OR autonomy_max_unattended_per_cluster > 0),

  -- The fleet-wide cap exists separately because the per-cluster one cannot see
  -- the correlated case at all: thirty clusters each executing once is thirty
  -- unattended mutations and one per cluster, which no per-cluster limit would
  -- ever catch.
  ADD COLUMN autonomy_max_unattended_fleet_wide integer
    CHECK (autonomy_max_unattended_fleet_wide IS NULL OR autonomy_max_unattended_fleet_wide > 0),

  ADD COLUMN autonomy_unattended_window_seconds integer
    CHECK (autonomy_unattended_window_seconds IS NULL OR autonomy_unattended_window_seconds > 0);

-- The cap is counted from remediation_executions, which is the only durable
-- record of what actually ran. It needs to answer "how many unattended
-- executions in this cluster / anywhere, since T" cheaply and on every candidate,
-- so it gets an index rather than a sequential scan over execution history that
-- grows forever.
--
-- unattended is a column rather than inferred from a NULL actor: an execution
-- with no approving user could also be a future service-principal path, and
-- conflating "nobody approved this" with "no human approved this" is exactly the
-- ambiguity a safety counter must not have.
ALTER TABLE remediation_executions
  ADD COLUMN unattended boolean NOT NULL DEFAULT false;

CREATE INDEX remediation_executions_unattended_recent_idx
  ON remediation_executions (executed_at DESC, cluster_id)
  WHERE unattended;
