DROP POLICY IF EXISTS clusters_tenant_scope ON clusters;
DROP INDEX IF EXISTS clusters_poll_token_idx;
ALTER TABLE clusters DROP COLUMN IF EXISTS issued_cert_pem;
ALTER TABLE clusters DROP COLUMN IF EXISTS csr_pem;
ALTER TABLE clusters DROP COLUMN IF EXISTS poll_token_hash;
