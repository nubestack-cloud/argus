-- PROJECT.md AD3: personal access tokens for the user-facing MCP endpoint
-- (POST /api/v1/mcp). An engineer points their own MCP client (Claude Code,
-- Cursor, VS Code) at the hub with one of these and gets the read-only
-- investigation tools AS THEMSELVES — every call re-resolves this row's
-- owner's grants, so the token never carries a capability of its own.
--
-- SHAPE:
--
--   * token_hash only. The secret is shown to its owner once, at creation,
--     and never stored: a SHA-256 of a 256-bit random value, the same
--     treatment refresh_tokens.token_hash gets (internal/authz/session.go).
--     A plain hash rather than a password KDF because the input is already
--     full-entropy — there is nothing for a slow hash to protect against.
--     The presented token names its row by id (argus_pat_<id>_<secret>), so
--     the hub looks the row up by primary key and compares hashes with
--     crypto/subtle; the hash column is UNIQUE as a second guard, not as the
--     lookup path.
--   * token_hint is the last four characters of the secret, for telling two
--     tokens with the same name apart in the list. Four characters of a
--     43-character random string is not a meaningful disclosure.
--   * expires_at is NOT NULL. There is no "never expires" token: the API
--     caps it at one year and defaults to 90 days.
--   * revoked_at rather than DELETE, so the list and the audit trail can
--     still name a token after it stops working.
--   * tenant_id denormalised, RLS tenant-scoped like refresh_tokens (000009).
--     No cluster_id: a personal token is not cluster-shaped; which clusters
--     it reaches is decided per call by its owner's grants.
CREATE TABLE mcp_personal_tokens (
  id            text PRIMARY KEY,   -- 'pat_...' (domain.PrefixPersonalToken)
  tenant_id     text NOT NULL REFERENCES organisations(id),
  user_id       text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name          text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  token_hash    text NOT NULL UNIQUE,
  token_hint    text NOT NULL DEFAULT '',
  created_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  last_used_at  timestamptz,
  revoked_at    timestamptz,
  CHECK (expires_at > created_at)
);

-- Every read is "this user's tokens" (the Settings list) or a primary-key
-- lookup (authentication).
CREATE INDEX mcp_personal_tokens_user_idx ON mcp_personal_tokens (user_id, created_at DESC);

ALTER TABLE mcp_personal_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_personal_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY mcp_personal_tokens_tenant_scope ON mcp_personal_tokens
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON mcp_personal_tokens TO argus_app;
