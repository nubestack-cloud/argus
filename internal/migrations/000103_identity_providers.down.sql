-- Reverses 000103. Order matters: the FK from the mappings and login-state
-- tables to identity_providers means providers must go last, and the users
-- constraint must go before its columns.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_local_xor_federated;
DROP INDEX IF EXISTS users_idp_identity_key;
ALTER TABLE users DROP COLUMN IF EXISTS idp_subject;
ALTER TABLE users DROP COLUMN IF EXISTS idp_issuer;

DROP TABLE IF EXISTS oidc_login_states;
DROP TABLE IF EXISTS identity_provider_group_mappings;
DROP TABLE IF EXISTS identity_providers;

-- Deliberately NOT reversed: grants written with source='idp_sync'. Dropping
-- the provider tables does not un-authorise anyone who is currently signed
-- in, and silently deleting grants on a schema rollback would be a surprising
-- way to lose access. An operator rolling this back should revoke those
-- grants explicitly:
--   UPDATE grants SET revoked_at = now() WHERE source = 'idp_sync' AND revoked_at IS NULL;
