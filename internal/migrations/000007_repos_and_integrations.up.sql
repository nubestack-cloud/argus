-- See lld/05-data-model.md §3.7, lld/09-repo-gitops-design.md.

CREATE TABLE repository_bindings (
  id              text PRIMARY KEY,
  tenant_id       text NOT NULL,
  provider        text NOT NULL,
  url             text NOT NULL,
  credential_ref  text NOT NULL,
  spec            jsonb NOT NULL
);

CREATE TABLE integrations (
  id              text PRIMARY KEY,
  tenant_id       text NOT NULL,
  kind            text NOT NULL,
  config          jsonb NOT NULL,
  credential_ref  text
);

CREATE TABLE notification_routes (
  id                text PRIMARY KEY,
  tenant_id         text NOT NULL,
  match             jsonb NOT NULL,
  targets           text[] NOT NULL,
  on_events         text[] NOT NULL,
  digest_interval   interval
);
