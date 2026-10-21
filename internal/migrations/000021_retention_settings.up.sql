-- Adds per-data-type, per-duration retention configuration for the three
-- range-partitioned tables (findings, incidents, audit_events — migrations
-- 000004, 000005, 000008) to org_settings, closing the gap flagged directly
-- by the user: retention must be configurable per data type and by
-- duration ("we might want to keep audit logs for one year"), and it must
-- NEVER silently delete anything by default.
--
-- All three columns follow a DELIBERATELY DIFFERENT null convention than
-- every other org_settings column (contrast with 000018/000019's "NULL
-- means fall back to an env var" and 000020's "NULL means every severity
-- qualifies"): here, NULL is not a fallback to some other source of truth —
-- it is the shipped, permanent-until-changed default, and it means "keep
-- forever." There is no env var, no third tier, nothing else this ever
-- resolves to. internal/partition's daily maintenance job (the mechanism
-- that actually enforces this — see that package's doc comment) treats a
-- NULL retention column as "never drop a partition of this table for
-- retention reasons," full stop, and that is the ENTIRE reason NULL is safe
-- to ship as the default: an operator who never visits
-- PUT /api/v1/admin/settings gets a platform that keeps every row it has
-- ever written, forever, exactly like the pre-existing (accidentally
-- unpartitioned-in-practice) behaviour this same task is otherwise fixing.
-- Rotation is opt-in, via an explicit positive integer, never implied-on.
--
-- Column-to-table mapping (internal/partition.tableSpecs is the single
-- place this mapping is duplicated in Go — keep both in sync):
--   audit_retention_days    -> audit_events (partitioned on occurred_at)
--   incident_retention_days -> incidents    (partitioned on first_seen)
--   finding_retention_days  -> findings     (partitioned on occurred_at)
--
-- Deliberately NOT named e.g. "auditRetentionDays: 0 means forever" — zero
-- and negative values are rejected as invalid input by
-- internal/api/settings.go's PUT handler (a zero-day retention has no sane
-- interpretation: "drop everything, including today," is never what an
-- admin setting "0" actually means to communicate), so NULL remains the
-- only "forever" sentinel, with no second one that would need reconciling
-- against it.
ALTER TABLE org_settings
  ADD COLUMN audit_retention_days    int CHECK (audit_retention_days    IS NULL OR audit_retention_days    > 0),
  ADD COLUMN incident_retention_days int CHECK (incident_retention_days IS NULL OR incident_retention_days > 0),
  ADD COLUMN finding_retention_days  int CHECK (finding_retention_days  IS NULL OR finding_retention_days  > 0);
