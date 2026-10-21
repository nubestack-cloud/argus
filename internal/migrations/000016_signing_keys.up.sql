-- Persisted signing/CA key material, closing the gap STATUS.md's foundation-
-- hardening notes flagged and deferred twice already ("Signing-key
-- persistence" and the Phase 0 table's "real key/cert persistence across a
-- hub restart" row): authz.NewEphemeralTokenSigner, authz.NewEphemeralEnrollmentSigner,
-- and gateway.NewEphemeralDevCA each generated a fresh key on every hub
-- restart, silently invalidating every outstanding session, enrollment
-- token, and issued cluster certificate (including the gateway's own TLS
-- server cert). This table lets internal/authz.NewPersistentTokenSigner,
-- internal/authz.NewPersistentEnrollmentSigner, and
-- gateway.NewPersistentDevCA load key material that survives a restart.
--
-- Explicitly NOT real production-grade key management: no envelope
-- encryption, no external KMS/Vault integration -- DESIGN.md
-- §18.6 is where that eventually goes. This is a real, meaningful
-- improvement over "invalidates every restart," not the final answer, and
-- STATUS.md documents it as exactly that.
--
-- Deliberately NO row-level security on this table -- decided, not defaulted.
-- Reasoning: this table holds system-level operational secrets (one row per
-- signing purpose), not tenant data, and every read/write happens from hub
-- startup code that runs before any request/tenant scope exists. That's the
-- same category `organisations` is already in (internal/data/org.go's
-- SingleOrganisationID doc comment: "deliberately has no RLS policy at all
-- ... it's the root every other table's tenant_id resolves against, so it
-- has to be queryable without already knowing the answer") and the same
-- category authz.EnsureBootstrap's inserts are in (they run against
-- db.Pool directly, not through argus_app + a scoped transaction, because
-- there is no tenant_id to scope by yet at true first boot). A tenant_id-
-- keyed policy on signing_keys would be actively wrong, not just
-- unnecessary: these keys are organisation-wide (there is exactly one
-- signer per purpose, not one per tenant), and gating their own bootstrap
-- read/write on app.tenant_id being set would risk exactly the kind of
-- startup-ordering bug this codebase has already hit three times (see
-- STATUS.md's RLS bug history) for a table that was never RLS-eligible in
-- the first place.
--
-- argus_app still needs an explicit grant -- it's an ordinary table owned by
-- the migration role, and this migration runs after 000009's
-- ALTER DEFAULT PRIVILEGES, so an explicit GRANT here matches the same
-- belt-and-suspenders precedent 000010_enrollment_tokens.up.sql already set
-- for a table created after that point.
CREATE TABLE signing_keys (
  purpose       text PRIMARY KEY,   -- e.g. 'jwt', 'enrollment', 'dev_ca_root'
  key_material  bytea NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON signing_keys TO argus_app;
