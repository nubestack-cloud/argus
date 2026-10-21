-- Encrypted secret storage, and the repository bindings that point at it.
--
-- WHY A NEW TABLE RATHER THAN ANOTHER COLUMN
--
-- org_settings.llm_api_key stores a secret in plaintext (migration 000018 says
-- so outright), which is already out of compliance with DESIGN.md §18.6's
-- envelope-encryption requirement. A Git credential is a higher-value secret —
-- it grants write access to the customer's source of truth — so it does not
-- inherit that gap. §18.6 also wants "ciphertext plus key version" in the DB,
-- which a bare text column has nowhere to put.
--
-- REMEDIATION_ROADMAP.md D-R9 made this load-bearing rather than defence in
-- depth: dropping the GitHub App means what sits at rest is a LIVE BEARER
-- TOKEN, not a signing key that is useless without an installation. A leaked
-- row is directly usable, so the encryption is the control and not a nicety.
CREATE TABLE encrypted_secrets (
  id          text PRIMARY KEY,
  tenant_id   text NOT NULL,
  -- What this secret is for, e.g. 'scm_token'. Present so a future secret type
  -- does not need another table, and so an operator can audit what is stored
  -- without decrypting anything.
  purpose     text NOT NULL,
  -- internal/secretbox's self-describing v1.<wrappedDEK>.<payload>. The DEK and
  -- the payload live in ONE column on purpose: they must move together, and
  -- splitting them invites a partial write that produces an unopenable row.
  ciphertext  text NOT NULL,
  -- §18.6: "In the DB: ciphertext plus key version. Rotation re-wraps without
  -- re-encrypting payloads." This column is what makes a later move to an
  -- external KMS a re-wrap of DEKs rather than a migration of payloads.
  key_version text NOT NULL,
  -- Advisory only, and NOT enforced here. A fine-grained PAT expires, and when
  -- it does PR creation simply starts failing — so ARGUS must warn BEFORE the
  -- date, not report failures after it (D-R9's stated requirement). Nullable
  -- because a group access token may have no expiry.
  expires_at  timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX encrypted_secrets_tenant_purpose_idx ON encrypted_secrets (tenant_id, purpose);

-- Expiry warnings are a sweep over "what expires soon", so the index is on the
-- date. Partial, because a NULL expiry can never match that query.
CREATE INDEX encrypted_secrets_expiring_idx ON encrypted_secrets (expires_at)
  WHERE expires_at IS NOT NULL;

ALTER TABLE encrypted_secrets ENABLE ROW LEVEL SECURITY;
-- FORCE, not just ENABLE. Migration 000009 explains why: ENABLE alone leaves RLS
-- inapplicable to the table OWNER, so a bug in code running as the owner
-- bypasses tenant isolation entirely. The hub's own startup check (SR-2) fails
-- loudly on an enabled-but-not-forced table — and it caught this migration
-- before the feature shipped, which is exactly what it is for.
ALTER TABLE encrypted_secrets FORCE ROW LEVEL SECURITY;
-- The setting is `app.tenant_id`, matching migration 000009 and every other
-- policy in this schema. Worth naming explicitly because an invented setting
-- name does not fail loudly at migration time: the policy is created happily and
-- then matches nothing, so every INSERT is refused and every SELECT returns
-- empty. Caught by actually exercising the endpoint.
CREATE POLICY encrypted_secrets_tenant_isolation ON encrypted_secrets
  USING (tenant_id = current_setting('app.tenant_id', true));

-- repository_bindings has existed since migration 000007 and has never had a
-- line of Go behind it. These columns are what the API needs to actually use it,
-- added rather than replaced so the existing shape (id/tenant_id/provider/url/
-- credential_ref/spec) keeps working.
ALTER TABLE repository_bindings
  -- The API host, so a binding for github.com and one for an internal GHES are
  -- distinguishable, and so ParseRepoURL's host can be checked against the
  -- binding rather than trusted (internal/scm.MatchesHost).
  ADD COLUMN IF NOT EXISTS api_base_url text,
  -- DESIGN.md §11.3: "configurable API base URL — required, not optional" for
  -- GHES and GitLab CE/EE. NULL means the provider's public API.
  ADD COLUMN IF NOT EXISTS host text,
  ADD COLUMN IF NOT EXISTS default_branch text,
  ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();

-- One binding per repository URL per tenant. Two bindings for one repo would
-- mean two credentials could open a PR against it and nothing would say which
-- ARGUS used — the kind of ambiguity that is much cheaper to forbid than to
-- resolve later.
CREATE UNIQUE INDEX IF NOT EXISTS repository_bindings_tenant_url_idx
  ON repository_bindings (tenant_id, url);

ALTER TABLE repository_bindings ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
  CREATE POLICY repository_bindings_tenant_isolation ON repository_bindings
    USING (tenant_id = current_setting('app.tenant_id', true));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
