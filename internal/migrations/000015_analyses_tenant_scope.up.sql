-- Same structural RLS bug found and fixed three times already (migrations
-- 000011/000012/000013 for clusters/audit_events/findings+incidents — read
-- 000011's comment for the full explanation), fixed proactively here before
-- any code writes to `analyses` for the first time: its only policy
-- (migration 000009's generic cluster_id-scoped loop) keys on
-- app.accessible_cluster_ids, which nothing populates for a general-purpose
-- caller, so it alone would permanently block every read/write. Additive,
-- permissive, tenant_id-keyed, same shape as the three precedents.
CREATE POLICY analyses_tenant_scope ON analyses
  USING (tenant_id = current_setting('app.tenant_id', true));
