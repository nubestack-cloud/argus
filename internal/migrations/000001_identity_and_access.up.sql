-- Identity and access schema. See lld/02-authz-spec.md and lld/05-data-model.md §3.1.

CREATE TABLE organisations (
  id              text PRIMARY KEY,
  name            text NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id              text PRIMARY KEY,
  tenant_id       text NOT NULL REFERENCES organisations(id),
  email           text NOT NULL,
  display_name    text NOT NULL,
  password_hash   text,
  must_change_password boolean NOT NULL DEFAULT false,
  disabled_at     timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_tenant_email_idx ON users (tenant_id, lower(email));

CREATE TABLE identities (
  id              text PRIMARY KEY,
  tenant_id       text NOT NULL REFERENCES organisations(id),  -- denormalized for RLS (§6's convention); missing from the LLD-05 sketch
  user_id         text NOT NULL REFERENCES users(id),
  provider        text NOT NULL,
  subject         text NOT NULL,
  linked_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider, subject)
);

CREATE TABLE service_principals (
  id              text PRIMARY KEY,
  tenant_id       text NOT NULL REFERENCES organisations(id),
  name            text NOT NULL,
  token_hash      text NOT NULL,
  capability_set  jsonb NOT NULL,
  scope           jsonb NOT NULL,
  expires_at      timestamptz NOT NULL,
  revoked_at      timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE grants (
  id              text PRIMARY KEY,
  tenant_id       text NOT NULL REFERENCES organisations(id),
  principal_type  text NOT NULL CHECK (principal_type IN ('user','service_principal')),
  principal_id    text NOT NULL,
  role_id         text,
  capability_set  jsonb,
  scope           jsonb NOT NULL,
  source          text NOT NULL DEFAULT 'manual' CHECK (source IN ('manual','idp_sync')),
  granted_by      text NOT NULL,
  granted_at      timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz,
  revoked_at      timestamptz,
  justification   text,
  CHECK ((role_id IS NULL) <> (capability_set IS NULL))
);
CREATE INDEX grants_principal_active_idx ON grants (principal_type, principal_id) WHERE revoked_at IS NULL;

CREATE TABLE identity_mappings (
  id                text PRIMARY KEY,
  tenant_id         text NOT NULL REFERENCES organisations(id),
  provider          text NOT NULL,
  claim             text NOT NULL,
  value             text NOT NULL,
  grants_template   jsonb NOT NULL,
  create_if_missing boolean NOT NULL DEFAULT false
);

CREATE TABLE refresh_tokens (
  token_hash      text PRIMARY KEY,
  tenant_id       text NOT NULL REFERENCES organisations(id),  -- denormalized for RLS (§6's convention); missing from the LLD-05 sketch
  user_id         text NOT NULL REFERENCES users(id),
  issued_at       timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz NOT NULL,
  revoked_at      timestamptz,
  replaced_by     text REFERENCES refresh_tokens(token_hash),
  client_info     jsonb
);

CREATE TABLE breakglass_policies (
  scope             jsonb PRIMARY KEY,
  require_approval  boolean NOT NULL DEFAULT false,
  max_ttl_minutes   int NOT NULL DEFAULT 60
);
