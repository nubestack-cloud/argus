-- External identity providers (PROJECT.md S2, brought into release scope
-- 2026-09-09). ARGUS speaks exactly ONE federation protocol: OIDC as a
-- relying party.
--
-- # Why one protocol and not a provider catalogue
--
-- The obvious-looking alternative was to port Rancher's auth providers, which
-- carry fifteen implementations (Active Directory, LDAP, SAML, Google, Azure,
-- Okta, Keycloak, GitHub, Cognito, ...). Two reasons that is the wrong shape
-- here, recorded so nobody re-opens it on the assumption it was never
-- considered:
--
--   1. Rancher's providers are not portable. Its LDAP provider alone imports
--      Norman, Wrangler, two generated Rancher client packages and
--      management.cattle.io/v3 CRD types -- 8 of 15 imports are
--      Rancher-internal. Rancher keeps users, tokens and auth configs as CRDs
--      in a management cluster driven by controllers; ARGUS keeps everything
--      in Postgres under RLS and has no CRD for a user at all. Porting one
--      provider means adopting a second architecture.
--   2. A provider catalogue is an enumeration that grows one entry per
--      vendor, which is the shape this project rejects everywhere else. An
--      OIDC relying party reaches every OIDC IdP directly (Okta, Keycloak,
--      Azure AD, Google Workspace, Auth0), and reaches LDAP/Active Directory
--      and SAML through a broker -- Dex ships sixteen connectors and is what
--      lld/01-threat-model.md's asset table ALREADY assumed when it named the
--      "IdP/OIDC client secret (Dex connector config)".
--
-- So: one code path, one set of security tests, and the vendor matrix becomes
-- someone else's maintained problem.

-- One row per configured provider. Deliberately not constrained to a single
-- row: an org migrating between IdPs needs both configured briefly, and the
-- login screen can offer more than one. `enabled` is what gates use, so a
-- half-configured provider cannot authenticate anyone.
CREATE TABLE identity_providers (
  id                      text        PRIMARY KEY,
  tenant_id               text        NOT NULL REFERENCES organisations(id),
  kind                    text        NOT NULL DEFAULT 'oidc' CHECK (kind IN ('oidc')),
  -- Shown on the login button ("Sign in with Acme SSO").
  display_name            text        NOT NULL,
  -- The OIDC issuer URL. Discovery appends /.well-known/openid-configuration;
  -- go-oidc verifies the document's own `issuer` matches this exactly, which
  -- is the check that stops a discovery-document swap.
  issuer                  text        NOT NULL,
  client_id               text        NOT NULL,
  -- Points at encrypted_secrets (migration 000045), whose own comment says
  -- "the next secret does not need another table" -- so the client secret
  -- lives there under purpose 'oidc_client_secret' rather than in an inline
  -- column here. That keeps every envelope-encrypted value in one place an
  -- operator can inventory without decrypting anything, and reuses
  -- internal/secretbox's existing Seal/Open path rather than adding a second
  -- one on an authentication-critical value.
  --
  -- NULL is legal: a public client authenticating with PKCE alone.
  -- lld/01-threat-model.md rates this secret an "Authentication trust anchor
  -- -- compromise = ability to mint sessions", so it is write-only over the
  -- API and never returned by any read path.
  -- A plain id reference with no FOREIGN KEY, matching
  -- repository_bindings.credential_ref -- the only other pointer into that
  -- table, and deliberately unconstrained there too. encrypted_secrets has
  -- FORCE ROW LEVEL SECURITY, and Postgres enforces FK checks with a
  -- system-level read that ignores RLS, so an FK here would both create a
  -- cross-policy read path and diverge from the established pattern for no
  -- gain. Deleting a provider therefore has to delete its secret explicitly;
  -- internal/idp.Store.DeleteProvider does that in the same transaction.
  client_secret_ref       text,
  -- Requested at the authorization endpoint. `openid` is mandatory and is
  -- added by the code regardless of what is stored here.
  scopes                  text[]      NOT NULL DEFAULT ARRAY['openid', 'email', 'profile', 'groups'],
  -- Which ID-token claim carries group membership. Varies by IdP: Dex and
  -- Keycloak use "groups", Azure AD uses "groups" or "roles", Okta is
  -- configurable. Made a column rather than hardcoded because getting this
  -- wrong silently grants nobody anything, which is hard to debug from the
  -- outside.
  groups_claim            text        NOT NULL DEFAULT 'groups',
  -- Where the IdP redirects back to. Stored rather than derived because a
  -- hub behind a proxy cannot reliably infer its own public URL, and a wrong
  -- redirect_uri is rejected by the IdP with an opaque error.
  redirect_uri            text        NOT NULL,
  enabled                 boolean     NOT NULL DEFAULT false,
  created_at              timestamptz NOT NULL DEFAULT now(),
  updated_at              timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, issuer, client_id)
);

ALTER TABLE identity_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_providers FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_providers_scope ON identity_providers
  USING (tenant_id = current_setting('app.tenant_id', true));

-- IdP group -> ARGUS role. This is the whole authorization story for a
-- federated user: the IdP says who you are and which groups you are in, and
-- these rows say what that means here.
--
-- role_id, not capability_set: internal/api/users.go's own header records
-- that every grant sets role_id and never capability_set, and a federated
-- grant must not be the exception that makes capability_set reachable.
CREATE TABLE identity_provider_group_mappings (
  id           text        PRIMARY KEY,
  tenant_id    text        NOT NULL REFERENCES organisations(id),
  provider_id  text        NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
  -- Compared case-sensitively against the values in the groups claim. LDAP
  -- distinguished names arrive verbatim through Dex, so this may be a full
  -- DN ("cn=platform-sre,ou=groups,dc=example,dc=com") rather than a bare
  -- name -- do not normalise it, an IdP's group identity is its own business.
  group_name   text        NOT NULL,
  role_id      text        NOT NULL,
  -- Same shape as grants.scope, so the sync path can copy it straight across
  -- without a translation step that could widen it.
  scope        jsonb       NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, provider_id, group_name, role_id)
);

ALTER TABLE identity_provider_group_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_provider_group_mappings FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_provider_group_mappings_scope ON identity_provider_group_mappings
  USING (tenant_id = current_setting('app.tenant_id', true));

-- In-flight login state. Written BEFORE anyone is authenticated, which is the
-- same position enrollment_tokens is in (migration 000010) and is exactly
-- where this codebase has gotten RLS wrong before -- the bootstrap insert and
-- refresh-token issuance both did. The policy is tenant_id-based like
-- 000010's, and the writer must therefore have set app.tenant_id from the
-- resolved single organisation, NOT from anything in the request.
--
-- Rows are single-use and short-lived; the callback deletes the row it
-- consumed and the login handler opportunistically reaps expired ones, so no
-- sweeper is needed for a table that only ever holds seconds of state.
CREATE TABLE oidc_login_states (
  -- SHA-256 of the state parameter, not the parameter itself: a stolen
  -- database read must not yield a usable state value.
  state_hash     text        PRIMARY KEY,
  tenant_id      text        NOT NULL REFERENCES organisations(id),
  provider_id    text        NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
  -- Sent to the IdP in the auth request and required to match the ID token's
  -- nonce claim on the way back. Stored as a hash for the same reason as
  -- state; go-oidc compares the claim against the value we supply, so the
  -- plaintext only has to survive inside one request.
  nonce          text        NOT NULL,
  -- PKCE (RFC 7636). The verifier has to be REPLAYED to the token endpoint,
  -- so unlike state and nonce it cannot be stored hashed. It is worthless
  -- without the matching authorization code, single-use, and expires in
  -- minutes. PKCE is defence in depth here rather than the primary control,
  -- since a confidential client already authenticates with its secret.
  pkce_verifier  text        NOT NULL,
  -- Where to send the browser after a successful login. Validated as a
  -- relative path on the way in; never an absolute URL, or this is an open
  -- redirect.
  return_to      text        NOT NULL DEFAULT '/',
  created_at     timestamptz NOT NULL DEFAULT now(),
  expires_at     timestamptz NOT NULL
);

ALTER TABLE oidc_login_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE oidc_login_states FORCE ROW LEVEL SECURITY;
CREATE POLICY oidc_login_states_scope ON oidc_login_states
  USING (tenant_id = current_setting('app.tenant_id', true));

CREATE INDEX oidc_login_states_expires_at_idx ON oidc_login_states (expires_at);

-- A federated user's identity at the IdP. (issuer, subject) is the only
-- stable pair OIDC guarantees -- email is explicitly NOT stable and MUST NOT
-- be the join key, or an IdP that recycles an address hands one person
-- another person's grants.
ALTER TABLE users ADD COLUMN idp_issuer  text;
ALTER TABLE users ADD COLUMN idp_subject text;

-- Partial unique index: local users have both NULL and are unconstrained.
CREATE UNIQUE INDEX users_idp_identity_key
  ON users (tenant_id, idp_issuer, idp_subject)
  WHERE idp_issuer IS NOT NULL AND idp_subject IS NOT NULL;

-- Either a local user (password_hash set) or a federated one (idp identity
-- set), never a hybrid: a federated account with a usable password would be a
-- way around whatever the IdP enforces (MFA, conditional access), which is
-- most of the reason to federate at all.
ALTER TABLE users ADD CONSTRAINT users_local_xor_federated CHECK (
  (idp_issuer IS NULL AND idp_subject IS NULL)
  OR (password_hash IS NULL AND idp_issuer IS NOT NULL AND idp_subject IS NOT NULL)
);
