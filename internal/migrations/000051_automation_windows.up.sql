-- Maintenance and freeze windows: automatic remediation gated by time.
--
-- DESIGN.md §7.2 specifies both, §9.4's autonomy predicate includes
-- `now ∈ maintenanceWindows AND now ∉ freezeWindows`, and §10.5 lists them among
-- the prerequisites for automatic mode. Unattended execution shipped without them
-- (WORKLOG §139), so a change freeze or a release window has been invisible to the
-- sweeper — the Settings warning said so, which was honest but not a substitute.
--
-- A TABLE RATHER THAN JSONB ON org_settings
--
-- The blast-radius caps are columns on org_settings because each is one number.
-- These are a list of structured rows an operator adds and removes individually,
-- each independently validatable and independently worth an audit trail — so they
-- get a table, the same reasoning that gave repository_bindings one.
--
-- A DEVIATION FROM DESIGN.md §18.4, STATED RATHER THAN GLOSSED
--
-- §18.4 requires freeze windows to be LOCALLY owned — a `LocalGuardrail` CR the
-- agent may read but not write, which the hub cannot touch at all, so that a fully
-- compromised hub cannot act inside a freeze. It calls that a v1 requirement, and
-- it is right: a hub-side freeze is only as trustworthy as the hub.
--
-- These rows are hub-side, because the detection-policy CRD and cluster-side
-- controller (BACKLOG S4) are not built, and a hub-side window is strictly better
-- than no window at all. What it does NOT do is defend against a compromised hub,
-- and nothing here should be read as claiming otherwise. When S4 lands, the
-- cluster-side copy becomes authoritative and this table becomes the thing that
-- gets pushed down, not the thing that decides.
CREATE TABLE automation_windows (
  id            text PRIMARY KEY,            -- 'awin_...'
  tenant_id     text NOT NULL,

  -- 'maintenance' permits automation while open; 'freeze' forbids it. The two are
  -- deliberately not symmetric in how they combine — see
  -- orchestrator.CheckWindows — but they share a shape, so they share a table.
  kind          text NOT NULL CHECK (kind IN ('maintenance', 'freeze')),

  -- The window's START, as a 5-field cron expression. NOT a bare "when it
  -- applies": DESIGN.md §7.2 is explicit that a bare cron denotes an instant, and
  -- that the schedule+duration pair exists so this can interoperate with Argo CD's
  -- own sync windows (§11.6), which use the same pair for the same reason.
  schedule      text NOT NULL,
  duration_seconds integer NOT NULL CHECK (duration_seconds > 0 AND duration_seconds <= 604800),

  -- IANA name. Empty string means UTC, and it is stored rather than defaulted at
  -- read time so that "this window has no timezone" and "this window is UTC" are
  -- the same explicit thing rather than two readings of NULL.
  timezone      text NOT NULL DEFAULT 'UTC',

  -- Why this window exists. Required for a freeze at the API layer, not here: it
  -- is a request-validation rule ("the text an operator reads when automation was
  -- blocked must exist") rather than a data-integrity one, the same distinction
  -- migration 000027 draws for a rejection's reason.
  reason        text NOT NULL DEFAULT '',

  created_by    text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX automation_windows_tenant_kind_idx ON automation_windows (tenant_id, kind);

ALTER TABLE automation_windows ENABLE ROW LEVEL SECURITY;
ALTER TABLE automation_windows FORCE ROW LEVEL SECURITY;
CREATE POLICY automation_windows_tenant_scope ON automation_windows
  USING (tenant_id = current_setting('app.tenant_id', true));
GRANT SELECT, INSERT, UPDATE, DELETE ON automation_windows TO argus_app;
