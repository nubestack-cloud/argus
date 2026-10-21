-- BACKLOG.md B1: wire timeline_events properly (the previous state was V2's
-- "worst of both" — a real table nothing wrote or read). This migration is
-- the RLS half of making it a genuinely usable table rather than a dead one.
--
-- timeline_events has carried migration 000009's single, ORIGINAL
-- cluster-keyed PERMISSIVE policy since it was created (migration 000005) —
-- `USING (cluster_id = ANY(string_to_array(current_setting('app.accessible_
-- cluster_ids', true), ',')))` — with NO tenant fallback and NO "empty list
-- means unrestricted" branch. Migration 000035 deliberately did NOT touch
-- it, because at the time nothing wrote or read it, so its "empty list =
-- zero rows" behaviour was harmless (§105-117 of that migration's header
-- names timeline_events explicitly as one of the tables "never part of this
-- bug" for exactly that reason) — but that migration's own header also flags
-- it as one of the tables that "will need the restrictive treatment ... when
-- per-cluster grants land."
--
-- That moment is now, for a different reason than per-cluster grants: B1
-- adds the first real writers and the first real reader
-- (GET /incidents/{id}/timeline), and every one of those call sites writes
-- inside a transaction whose ambient app.accessible_cluster_ids is the
-- ordinary "" (unset) value — internal/api/middleware.go's requireAuth only
-- ever narrows it for a genuinely per-cluster-scoped grant (still unbuilt
-- per STATUS.md §2), and the background jobs
-- (internal/orchestrator.ValidationSweeper, internal/api's
-- recordExecutingTransition/recordExecutionOutcome) call
-- data.SetRequestScope(..., nil) outright because they each sweep or act
-- across many clusters in one transaction. Under timeline_events' OLD
-- policy, "" means the array ARRAY[''], which never equals a real cluster_id
-- — so every write attempted under this task would have been rejected by
-- Postgres as an RLS policy violation (WITH CHECK defaults to the USING
-- clause), and every read would have silently returned zero rows. Not a
-- narrow bug — total breakage for the default, unrestricted-grant path this
-- product ships with today.
--
-- FIX: give timeline_events the exact same two-policy shape 000035 already
-- established and proved correct for incidents/findings/analyses/clusters —
-- a PERMISSIVE tenant_scope policy (this is a single-organisation deployment,
-- so this alone already admits every row belonging to the caller's tenant)
-- ANDed with a RESTRICTIVE cluster_scope policy carrying the "empty list
-- means no narrowing" bypass. Ambient, tenant-wide callers (every call site
-- this task adds) keep working exactly as they do for incidents today;
-- narrowing only ever restricts further, never widens past the tenant.
DROP POLICY IF EXISTS timeline_events_scope ON timeline_events;

CREATE POLICY timeline_events_tenant_scope ON timeline_events
  USING (tenant_id = current_setting('app.tenant_id', true));

CREATE POLICY timeline_events_cluster_scope ON timeline_events AS RESTRICTIVE
  USING (
    COALESCE(current_setting('app.accessible_cluster_ids', true), '') = ''
    OR cluster_id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ','))
  )
  WITH CHECK (
    COALESCE(current_setting('app.accessible_cluster_ids', true), '') = ''
    OR cluster_id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ','))
  );
