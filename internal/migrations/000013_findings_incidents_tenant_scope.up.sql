-- Fixes the same structural RLS gap already found and fixed twice —
-- `clusters` in migration 000011, `audit_events` in migration 000012. Read
-- 000011's comment first; this is the exact same bug class, hitting two more
-- tables proactively this time, ahead of (not found by) their first real
-- writer (internal/gateway's handleFinding) and first real reader
-- (GET /api/v1/incidents, internal/api/incidents.go) landing in this same
-- increment.
--
-- findings' and incidents' only RLS policy, from migration 000009's generic
-- cluster_id-scoped loop, is:
--
--   USING (cluster_id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ',')))
--
-- Nothing anywhere in this codebase populates app.accessible_cluster_ids with
-- anything real for a general-purpose caller — internal/api/middleware.go's
-- requireAuth always passes nil (per-cluster grant scope resolution is still
-- deferred, same as it was for 000011/000012). That means this policy, as the
-- ONLY policy on either table, blocks every read/write for every caller,
-- including a super-admin calling GET /incidents — not a corner case, a
-- total block, identical in root cause to what 000011/000012 already found
-- and fixed. internal/gateway's own writers (handleHeartbeat's
-- handleInventoryDelta sibling, and now handleFinding) narrow
-- app.accessible_cluster_ids to the one already-known cluster_id before
-- touching these tables, same as handleInventoryDelta already does for
-- cluster_facts — so writes from the tunnel would actually work even
-- without this migration. Reads from a route with no single known cluster
-- (GET /api/v1/incidents, GET /api/v1/incidents/{id}) would not: they run
-- through requireAuth's nil-scoped transaction, so without this migration
-- an authenticated super-admin's own incident list would silently and
-- permanently come back empty.
--
-- Fix: add a second, additive, PERMISSIVE tenant_id-keyed policy on each
-- table, exactly the shape 000011/000012 already used twice. Postgres ORs
-- multiple permissive policies together for the same command, so this is
-- additive, not a weakening — the existing cluster_id-based policy still
-- applies and still narrows access further once per-cluster-scoped grants
-- and their accessible_cluster_ids resolution are ever implemented
-- (authz-spec §6, still not built anywhere). Until then, tenant_id scoping
-- is the only policy that can possibly match any row, and for this confirmed
-- single-organisation deployment (DESIGN.md §5.1/D9) it is
-- exactly as safe as every other table's tenant_id policy already in
-- production use.

CREATE POLICY findings_tenant_scope ON findings
  USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY incidents_tenant_scope ON incidents
  USING (tenant_id = current_setting('app.tenant_id', true));
