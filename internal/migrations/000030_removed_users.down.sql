DROP INDEX users_tenant_email_active_idx;
CREATE UNIQUE INDEX users_tenant_email_idx ON users (tenant_id, lower(email));
ALTER TABLE users DROP COLUMN deleted_at;
