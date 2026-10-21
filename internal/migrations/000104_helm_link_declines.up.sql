-- BACKLOG.md F30 decision 4's own memory requirement: "Never ask twice for
-- the same (scope, release, namespace), and if the operator declines, do
-- not re-ask on the next incident for the same release." A CONFIRMED link
-- already has its own durable record — the ObjectMapping itself, on
-- repository_bindings.spec — so FindObjectMapping matching it is what stops
-- ARGUS asking again. A DECLINED link has no repo/path to record anywhere,
-- so it needs its own row, or every future incident on that release would
-- show the same discovery banner again.
--
-- Scoped to (cluster_id, release_name, namespace) — one cluster, not the
-- release's Scope-as-eventually-confirmed: a decline is a fact about "an
-- operator looked at THIS release on THIS cluster and said no", and F30's
-- own "prove narrowly" principle for the render proof applies just as much
-- to a refusal as to a link — declining on one cluster must not silence the
-- question on a different cluster running a same-named-but-different
-- release.
--
-- tenant_id has no FK to organisations(id), matching custom_roles (000077)
-- and cluster_group_members (000078)'s identical choice and reasoning.
CREATE TABLE helm_link_declines (
  id            text PRIMARY KEY,
  tenant_id     text NOT NULL,
  cluster_id    text NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
  release_name  text NOT NULL,
  namespace     text NOT NULL,
  declined_by   text NOT NULL,
  declined_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (cluster_id, release_name, namespace)
);
CREATE INDEX helm_link_declines_lookup_idx ON helm_link_declines (cluster_id, release_name, namespace);

ALTER TABLE helm_link_declines ENABLE ROW LEVEL SECURITY;
ALTER TABLE helm_link_declines FORCE ROW LEVEL SECURITY;
CREATE POLICY helm_link_declines_scope ON helm_link_declines
  USING (tenant_id = current_setting('app.tenant_id', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON helm_link_declines TO argus_app;
