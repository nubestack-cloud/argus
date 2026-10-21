-- Custom roles (BACKLOG.md S3): an admin-defined, named bundle of capabilities
-- ALREADY in internal/authz/permissions.go's catalogue — composing existing
-- capabilities into a new reusable role, never inventing a new permission.
-- This is the feature internal/api/users.go's own doc comment (2026-08-22)
-- flagged as deliberately out of scope ("no custom-role authoring... a grant's
-- role is always one of the 5 fixed builtin role names") and
-- internal/authz/permissions.go's IsBuiltinRole doc comment called a closed
-- set with "no custom-role-authoring feature" — both now superseded.
--
-- A grant references a custom role the exact same way it references a
-- builtin one: grants.role_id holds this table's id (see
-- internal/authz.ResolveRoleCapabilities, which tries the builtin map first
-- and falls back to this table) — no new column on grants, no parallel
-- assignment mechanism.
--
-- tenant_id deliberately has NO foreign key to organisations(id), unlike
-- users/clusters/grants/cluster_groups' stricter convention — matching
-- repository_bindings' (migration 000007) and scm_credentials' looser one
-- instead. This keeps a same-process two-tenant RLS-isolation test as simple
-- as internal/scm/objectmapping_db_test.go's (no throwaway organisations row
-- required) and costs nothing in a single-organisation deployment (D_HLD
-- §5.1's confirmed scope) where every tenant_id in play already comes from
-- data.SingleOrganisationID.
--
-- Added after migration 000009's generic RLS loop already ran, so this gets
-- its own ENABLE/FORCE/CREATE POLICY here, following 000010_enrollment_tokens'
-- precedent (a table that doesn't fit that loop's cluster_id-per-row shape)
-- rather than editing a past migration.
CREATE TABLE custom_roles (
  id              text PRIMARY KEY,
  tenant_id       text NOT NULL,
  name            text NOT NULL,
  -- Every entry must be a real, current capability string
  -- (internal/authz.ValidCapabilities) — enforced at write time by
  -- internal/api/custom_roles.go, never trusted from the column alone. A
  -- capability removed from the Go catalogue after a role was created is not
  -- retroactively stripped here; internal/authz.ResolveRoleCapabilities
  -- returns it as-is and it simply never matches anything at
  -- authorization-check time, the same "capability catalogue ahead of its
  -- handlers" shape as any other stale string, not a correctness bug.
  capability_set  jsonb NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  created_by      text NOT NULL
);
-- One name per tenant (case-insensitive) — the same uniqueness shape as
-- users_tenant_email_idx (migration 000001), and it is what lets an admin
-- create a role called "on-call-viewer" without silently shadowing an
-- earlier one of the same name.
CREATE UNIQUE INDEX custom_roles_tenant_name_idx ON custom_roles (tenant_id, lower(name));

ALTER TABLE custom_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE custom_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY custom_roles_scope ON custom_roles
  USING (tenant_id = current_setting('app.tenant_id', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON custom_roles TO argus_app;
