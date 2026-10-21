-- Enrollment tokens (lld/03-agent-protocol.md §2). Neither that document nor
-- lld/05-data-model.md's §3 DDL actually specified this table's schema — §2
-- describes the token's payload fields as "stored server-side, keyed by
-- token_id" without giving the DDL. Added here, following that section's field
-- list directly.

CREATE TABLE enrollment_tokens (
  token_id              text PRIMARY KEY,
  tenant_id             text NOT NULL REFERENCES organisations(id),
  issuing_principal_id  text NOT NULL,
  scope_hint            jsonb,           -- advisory display-name pattern / labels; checked at accept time, not a hard constraint on the CSR
  ttl_class             text NOT NULL CHECK (ttl_class IN ('A', 'B', 'C')), -- onboarding paths, §2's table
  max_redemptions       int NOT NULL DEFAULT 1,
  redemption_count      int NOT NULL DEFAULT 0,
  issued_at             timestamptz NOT NULL DEFAULT now(),
  expires_at            timestamptz NOT NULL
);

ALTER TABLE enrollment_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrollment_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY enrollment_tokens_scope ON enrollment_tokens
  USING (tenant_id = current_setting('app.tenant_id', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON enrollment_tokens TO argus_app;
