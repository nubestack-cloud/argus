-- Hub-authored/pushed policy side only. LocalGuardrail is a spoke CRD, never mirrored
-- here (lld/04-rbac-profiles.md §3, §6). See lld/05-data-model.md §3.3.

CREATE TABLE remediation_policies (
  id                  text PRIMARY KEY,
  tenant_id           text NOT NULL REFERENCES organisations(id),
  name                text NOT NULL,
  namespace_scope     text,
  current_version_id  text,
  created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE policy_versions (
  id              text PRIMARY KEY,
  tenant_id       text NOT NULL REFERENCES organisations(id),  -- denormalized for RLS (§6's convention); missing from the LLD-05 sketch
  policy_id       text NOT NULL REFERENCES remediation_policies(id),
  -- spec holds ONLY: detectors, dedup, rateLimiting, budget, escalation, notifications,
  -- maintenanceWindows. NEVER guardrails/freezeWindows — those live in the spoke-resident
  -- LocalGuardrail CR that the hub cannot write (lld/04-rbac-profiles.md §3).
  spec            jsonb NOT NULL,
  created_by      text NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE remediation_policies
  ADD CONSTRAINT fk_current_version FOREIGN KEY (current_version_id) REFERENCES policy_versions(id);
