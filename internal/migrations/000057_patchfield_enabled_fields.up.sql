-- Tenant-selected PatchField fields: the allowlist becomes a product feature.
--
-- THE PROBLEM
--
-- PatchField's permission table (internal/remediation/patchfield.go) is a
-- hardcoded 16-entry list of (kind, field path) pairs. As a safety design that is
-- correct — deny by default, every entry individually reviewed and risk-rated. As
-- a PRODUCT it does not hold: every customer who needs a field we did not think of
-- needs an ARGUS release, and 14 of the 16 entries name kinds the shipped agent
-- chart cannot patch, so the list simultaneously over-promises and under-delivers.
--
-- The alternative that must NOT be built is a free-form list where an operator (or
-- worse, the model) can name any field. That would put policy authorship in the
-- hands of whatever proposed the change, and cluster contents are
-- attacker-influenceable — a pod annotation or a log line can reach the model's
-- context, so "the model nominates what a human is asked to authorise" is a path
-- from injected text to a standing write permission.
--
-- THE SHAPE INSTEAD: TWO TIERS
--
--   Tier 1, the CATALOGUE (Go, shipped, immutable at runtime): every (kind, field)
--   pair we have safety-reviewed, each carrying the risk floor WE assign. Nothing
--   in it is active. It can grow to hundreds of entries without granting anything.
--
--   Tier 2, ENABLED (this table): the subset a tenant admin has turned on.
--
-- A row here SELECTS a catalogue entry; it cannot invent one. field_path stores the
-- catalogue PATTERN ("spec.ports.*.targetPort"), not a concrete path, because what
-- is being enabled is the reviewed rule rather than one object's field. Enablement
-- is resolved by looking the pattern up in the catalogue on every read, which buys
-- a property worth having: if a future release REMOVES a catalogue entry because it
-- turned out to be unsafe, every tenant's enablement of it stops working
-- immediately, with no migration and no cleanup. The catalogue stays authoritative;
-- this table only ever narrows it.
--
-- WHAT THIS TABLE DOES NOT GRANT
--
-- Enabling a field means "stop refusing this kind of change outright". It does NOT
-- mean "execute it without asking" — PatchField remains in
-- remediation.neverAutoApprove regardless of what is enabled here, so every one
-- still goes to a human. Those are very different grants and a UI that blurs them
-- would be collecting consent for one while performing the other.
--
-- Nor does it grant Kubernetes permission. If the agent's ServiceAccount cannot
-- patch a Service, enabling a Service field here changes nothing except which
-- error the operator sees. That is why enablement is gated on a live
-- SelfSubjectAccessReview against the target cluster rather than on this row alone.
--
-- WHY A TABLE AND NOT A COLUMN ON org_settings
--
-- Same reasoning migration 000051 gives for automation_windows: the blast-radius
-- caps are single numbers, so they are columns; these are structured rows an admin
-- adds and removes individually, each independently worth an audit trail. Who
-- enabled a write permission, when, and off the back of which incident is exactly
-- the question an auditor asks first.
CREATE TABLE patchfield_enabled_fields (
  id          text PRIMARY KEY,            -- 'pfef_...'
  tenant_id   text NOT NULL,

  -- The catalogue entry this row selects. Both columns must match a catalogue
  -- entry EXACTLY (after path normalisation) or the row is inert — validated in
  -- Go on write and re-checked on every read, because the catalogue is the
  -- authority and it can change under this table between releases.
  gvk         text NOT NULL,
  field_path  text NOT NULL,

  -- Provenance. enabled_by is a user id, never a service principal: this is a
  -- policy decision a person makes, and the audit trail is worthless if it can
  -- read "enabled by automation".
  enabled_by  text NOT NULL,
  enabled_at  timestamptz NOT NULL DEFAULT now(),

  -- The incident whose approval prompted this, when it came from the
  -- just-in-time flow rather than the settings page. Nullable because enabling a
  -- field up front, before anything has needed it, is equally legitimate — and
  -- the difference is worth being able to see.
  source_incident_id text,

  -- Free text the admin may leave for whoever reads this list in six months.
  note        text NOT NULL DEFAULT '',

  -- One row per (tenant, catalogue entry). Re-enabling something already enabled
  -- is a no-op rather than a second row, so the list cannot accumulate duplicates
  -- that disagree about who enabled it.
  UNIQUE (tenant_id, gvk, field_path)
);

CREATE INDEX patchfield_enabled_fields_tenant_idx ON patchfield_enabled_fields (tenant_id);

ALTER TABLE patchfield_enabled_fields ENABLE ROW LEVEL SECURITY;
ALTER TABLE patchfield_enabled_fields FORCE ROW LEVEL SECURITY;
CREATE POLICY patchfield_enabled_fields_tenant_scope ON patchfield_enabled_fields
  USING (tenant_id = current_setting('app.tenant_id', true));
GRANT SELECT, INSERT, UPDATE, DELETE ON patchfield_enabled_fields TO argus_app;

COMMENT ON TABLE patchfield_enabled_fields IS
  'Catalogue entries (internal/remediation/patchfield.go) a tenant admin has enabled for PatchField. Selects within the shipped catalogue; never widens it. Enabling permits a change to be proposed and approved, never executed unattended.';
