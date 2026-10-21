-- Drops the column and its shape constraint together. Rolling back means an
-- installation loses its named exceptions and returns to plain default-deny for
-- every private destination — the behaviour before this migration, and the safe
-- direction: a rollback that left private destinations reachable with nothing
-- recording which ones were approved would be the failure this whole feature
-- exists to avoid. The visible consequence for an operator running a
-- self-hosted vLLM or an internal GHES is that those calls start being refused
-- again, with internal/outbound's stated reason.
ALTER TABLE org_settings DROP CONSTRAINT IF EXISTS org_settings_outbound_private_allowlist_shape;
ALTER TABLE org_settings DROP COLUMN IF EXISTS outbound_private_allowlist;
