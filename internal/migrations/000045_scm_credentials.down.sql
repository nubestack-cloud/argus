-- Reversible, unlike a backfill: nothing here derives data that could not be
-- recreated. Dropping encrypted_secrets DOES destroy stored credentials, which
-- is correct for a down migration — they are re-enterable, and keeping
-- ciphertext for a schema that no longer exists would be worse.
DROP INDEX IF EXISTS repository_bindings_tenant_url_idx;
ALTER TABLE repository_bindings
  DROP COLUMN IF EXISTS api_base_url,
  DROP COLUMN IF EXISTS host,
  DROP COLUMN IF EXISTS default_branch,
  DROP COLUMN IF EXISTS created_at,
  DROP COLUMN IF EXISTS updated_at;
DROP TABLE IF EXISTS encrypted_secrets;
