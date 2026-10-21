-- Circuit breakers: the last unbuilt piece of REMEDIATION_ROADMAP.md D-R7's safety
-- net, and the one docs/USER_GUIDE.md §6 named as missing.
--
-- It is a genuinely different mechanism from the two limits that already exist,
-- which is why folding it into either would not have worked:
--
--   blast radius (000046)  bounds VOLUME     -- "no more than N per hour"
--   windows      (000051)  bounds TIME       -- "not during the freeze"
--   this                   bounds on OUTCOME -- "stop, because it isn't working"
--
-- A cap and a window are both statements made in advance. Neither can notice that
-- the changes ARGUS is making are failing, and an unattended loop that keeps acting
-- while every action fails is the case with no existing brake at all.
--
-- WHY THE TRIP IS PERSISTED rather than held in memory: a hub restart would
-- otherwise silently re-arm unattended execution. That is the worst shape of bug
-- this codebase keeps running into — nothing errors, and work quietly resumes. A
-- trip has to outlive the process that observed it.
CREATE TABLE circuit_breaker_trips (
  id                text        PRIMARY KEY,
  tenant_id         text        NOT NULL REFERENCES organisations(id),

  -- NULL cluster_id means the FLEET-WIDE breaker. Two scopes for the same reason
  -- the blast-radius cap has two counters: thirty clusters each failing once trips
  -- no per-cluster breaker, and is exactly the situation worth stopping for.
  cluster_id        text        REFERENCES clusters(id),

  tripped_at        timestamptz NOT NULL DEFAULT now(),
  -- The operator-facing sentence, composed when the breaker trips. Stored rather
  -- than recomputed because the window it counted over will have moved on by the
  -- time anybody reads it, and a reason that no longer reproduces is worse than no
  -- reason at all.
  reason            text        NOT NULL,
  bad_outcomes      integer     NOT NULL,
  threshold         integer     NOT NULL,

  -- Reset is MANUAL, by design. A breaker that re-closes on a timer is a rate
  -- limiter, and the blast-radius cap is already the rate limiter. The point of
  -- this one is that somebody looks.
  reset_at          timestamptz,
  reset_by          text        REFERENCES users(id),
  reset_note        text,

  CONSTRAINT circuit_breaker_trips_reset_actor
    CHECK ((reset_at IS NULL) = (reset_by IS NULL))
);

-- One OPEN trip per scope. The partial unique index is what makes "trip it" safely
-- idempotent: a sweep that trips a breaker already tripped conflicts instead of
-- accumulating a row every thirty seconds for as long as the fault lasts.
-- COALESCE, because NULL cluster_id (fleet-wide) would otherwise never conflict
-- with itself under UNIQUE.
CREATE UNIQUE INDEX circuit_breaker_trips_one_open
  ON circuit_breaker_trips (tenant_id, COALESCE(cluster_id, ''))
  WHERE reset_at IS NULL;

CREATE INDEX circuit_breaker_trips_history
  ON circuit_breaker_trips (tenant_id, tripped_at DESC);

ALTER TABLE circuit_breaker_trips ENABLE ROW LEVEL SECURITY;
ALTER TABLE circuit_breaker_trips FORCE ROW LEVEL SECURITY;

-- Tenant-scoped, NOT cluster-scoped, and deliberately so: a fleet-wide trip has a
-- NULL cluster_id and a cluster-id predicate would hide the single most important
-- row in the table. This is also why the fleet-wide breaker could not have been
-- modelled as a row per cluster.
CREATE POLICY circuit_breaker_trips_scope ON circuit_breaker_trips
  USING (tenant_id = current_setting('app.tenant_id', true));

-- Thresholds live with the other autonomy settings. NULL means fall back to the
-- code default (the analysis.maxIterations convention), never "no limit".
ALTER TABLE org_settings
  ADD COLUMN autonomy_breaker_enabled            boolean NOT NULL DEFAULT true,
  ADD COLUMN autonomy_breaker_per_cluster        integer,
  ADD COLUMN autonomy_breaker_fleet_wide         integer,
  ADD COLUMN autonomy_breaker_window_seconds     integer;

ALTER TABLE org_settings
  ADD CONSTRAINT org_settings_autonomy_breaker_per_cluster_check
    CHECK (autonomy_breaker_per_cluster IS NULL OR autonomy_breaker_per_cluster > 0),
  ADD CONSTRAINT org_settings_autonomy_breaker_fleet_wide_check
    CHECK (autonomy_breaker_fleet_wide IS NULL OR autonomy_breaker_fleet_wide > 0),
  ADD CONSTRAINT org_settings_autonomy_breaker_window_seconds_check
    CHECK (autonomy_breaker_window_seconds IS NULL OR autonomy_breaker_window_seconds > 0);
