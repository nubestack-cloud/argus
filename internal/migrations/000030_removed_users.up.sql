-- Soft-removal for users. Removed users are hidden from active user
-- management, cannot authenticate, and cannot be re-enabled, while their
-- historical identity remains available to audit/grant rows.
ALTER TABLE users ADD COLUMN deleted_at timestamptz;

DROP INDEX users_tenant_email_idx;
CREATE UNIQUE INDEX users_tenant_email_active_idx ON users (tenant_id, lower(email)) WHERE deleted_at IS NULL;
