-- Multiple configurable AI providers, switchable from Settings.
--
-- Migration 000033 gave org_settings a single provider: one kind ('api'|'cli')
-- plus one set of fields for each. That works for one deployment with one
-- model, and stops working the moment an operator wants a metered API key for
-- real incidents and a CLI runner for experimenting, or two runners on
-- different credentials, and wants to switch between them without retyping
-- configuration each time.
--
-- This replaces those columns with a real table plus an active-provider
-- pointer on org_settings. Design notes:
--
--   * The pointer lives on org_settings rather than an `is_active` flag on
--     each row. A flag needs a partial unique index to stop two rows both
--     being active, and even then "exactly one active" is an invariant the
--     application has to maintain on every write. A single nullable FK makes
--     "at most one active" structurally true and "which one" a single-row
--     update.
--
--   * The pointer is ON DELETE SET NULL, not RESTRICT. Deleting the active
--     provider is a thing an operator will do, and it should degrade to "no
--     provider configured" (which internal/llm already handles as
--     ErrNotConfigured) rather than being refused with a foreign-key error.
--
--   * Kind-specific columns are nullable rather than split into two tables or
--     a JSONB blob. Two tables would need a union view for the common "list
--     everything" read; JSONB would lose the CHECK constraints that keep a
--     typo'd agent name out of the column. Nullable columns with a CHECK per
--     kind keep both, at the cost of some columns being irrelevant per row —
--     an acceptable trade at this width.
CREATE TABLE ai_providers (
  id             text PRIMARY KEY,            -- 'aip_...' (domain.PrefixAIProvider)
  tenant_id      text NOT NULL,
  -- Operator-chosen label, the thing shown in the Settings picker. Unique per
  -- tenant so the picker can never show two identically-named entries.
  name           text NOT NULL,
  kind           text NOT NULL CHECK (kind IN ('api', 'cli')),

  -- kind = 'api': an OpenAI-compatible endpoint ARGUS calls itself.
  base_url       text,
  model          text,
  api_key        text,

  -- kind = 'cli': a runner service that drives a coding-agent CLI
  -- (lld/14-adrs.md ADR-17, lld/12-deployment-design.md §12).
  runner_url     text,
  runner_token   text,
  agent          text CHECK (agent IS NULL OR agent IN ('claude', 'codex')),

  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),

  -- Enforce that a row actually carries the fields its own kind needs, so an
  -- unusable provider cannot be stored and then fail confusingly at
  -- investigation time. Deliberately does NOT require a credential: an api
  -- provider may legitimately have no key (a local Ollama endpoint), and a cli
  -- provider's model credential lives in the runner's own environment, not
  -- here.
  CONSTRAINT ai_providers_kind_fields CHECK (
    (kind = 'api' AND base_url IS NOT NULL AND base_url <> '')
    OR
    (kind = 'cli' AND runner_url IS NOT NULL AND runner_url <> '')
  )
);

CREATE UNIQUE INDEX ai_providers_tenant_name_idx ON ai_providers (tenant_id, lower(name));

-- **Deliberately no RLS on this table**, matching `org_settings` and
-- `signing_keys` — the other two org-wide-configuration tables, both of which
-- also have `relrowsecurity = false`.
--
-- This was learned the hard way in the same session this migration was written:
-- the table originally shipped with ENABLE + FORCE ROW LEVEL SECURITY and a
-- tenant_id policy, copying migration 000027's shape. That broke provider
-- resolution outright and silently — `settings.Resolve` reads on the
-- investigation hot path through a **bare pool connection** with no
-- `app.tenant_id` set (exactly as it already did for org_settings, which has no
-- RLS to care), so the policy hid every row, the LEFT JOIN produced all NULLs,
-- and the API cheerfully reported "no provider configured" no matter which one
-- was active.
--
-- RLS is the right default for per-cluster and per-incident data, and the wrong
-- one here: this is a single org-wide config set, exactly as sensitive as
-- org_settings, and access to it is already gated at the API layer by
-- `org:settings:write` (super-admin only). `tenant_id` is still stored, so a
-- policy can be added the day genuine multi-tenancy arrives — at which point
-- Resolve will need a scoped transaction, and that is the change to make then
-- rather than a policy that cannot work now.
GRANT SELECT, INSERT, UPDATE, DELETE ON ai_providers TO argus_app;

ALTER TABLE org_settings
  ADD COLUMN active_ai_provider_id text REFERENCES ai_providers(id) ON DELETE SET NULL;

-- Carry the existing single provider across, so an upgrade changes nothing an
-- operator can observe: same endpoint, same model, same credential, same
-- behaviour on the very next investigation.
--
-- Only runs when 000033's columns actually hold a usable provider. A
-- deployment that never configured one (the env-var-only path, which
-- internal/settings still supports as a fallback) gets no row and no active
-- pointer, which is correct — it had no DB-configured provider before either.
WITH migrated AS (
  INSERT INTO ai_providers (id, tenant_id, name, kind, base_url, model, api_key, runner_url, runner_token, agent)
  SELECT
    'aip_' || lower(replace(gen_random_uuid()::text, '-', '')),
    (SELECT id FROM organisations ORDER BY created_at LIMIT 1),
    'Default',
    COALESCE(NULLIF(s.llm_provider_kind, ''), 'api'),
    s.llm_base_url, s.llm_model, s.llm_api_key,
    s.cli_runner_url, s.cli_runner_token, s.cli_agent
  FROM org_settings s
  WHERE s.id = 'singleton'
    AND (SELECT count(*) FROM organisations) > 0
    AND (
      (COALESCE(NULLIF(s.llm_provider_kind, ''), 'api') = 'api' AND s.llm_base_url IS NOT NULL AND s.llm_base_url <> '')
      OR
      (s.llm_provider_kind = 'cli' AND s.cli_runner_url IS NOT NULL AND s.cli_runner_url <> '')
    )
  RETURNING id
)
UPDATE org_settings SET active_ai_provider_id = (SELECT id FROM migrated) WHERE id = 'singleton';

-- The 000033 columns are now redundant. Dropped rather than left in place:
-- two sources of truth for "which provider" is exactly the drift this table
-- exists to prevent, and internal/settings would have to pick one anyway.
ALTER TABLE org_settings DROP COLUMN llm_provider_kind;
ALTER TABLE org_settings DROP COLUMN llm_base_url;
ALTER TABLE org_settings DROP COLUMN llm_model;
ALTER TABLE org_settings DROP COLUMN llm_api_key;
ALTER TABLE org_settings DROP COLUMN cli_runner_url;
ALTER TABLE org_settings DROP COLUMN cli_runner_token;
ALTER TABLE org_settings DROP COLUMN cli_agent;
