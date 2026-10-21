-- Structural rollback only, matching every other down.sql in this
-- directory's own convention (checked: 000020_auto_analysis.down.sql, the
-- migration this one supersedes, does the same) -- no attempt to
-- reconstruct auto_analysis_min_severity's value from
-- auto_analysis_severities' set, because a threshold genuinely cannot
-- represent an arbitrary set (that gap is this whole task's reason for
-- existing): a non-contiguous selection like {medium} alone, or {low,high}
-- with medium deliberately excluded, has no equivalent single threshold.
-- Rolling back re-creates the column as NULL ("every severity qualifies",
-- 000020's own default) for every row, same "re-added column starts at its
-- own fresh default, not restored from whatever superseded it" treatment
-- 000020's down.sql already gives auto_analysis_enabled/
-- auto_analysis_attempted_at.
ALTER TABLE org_settings DROP COLUMN auto_analysis_severities;

ALTER TABLE org_settings
  ADD COLUMN auto_analysis_min_severity text
    CHECK (auto_analysis_min_severity IS NULL
           OR auto_analysis_min_severity IN ('low', 'medium', 'high', 'critical'));
