-- Reverses 000034: restores 000033's single-provider columns and copies the
-- currently-active provider back into them.
--
-- Lossy by nature, and stated rather than hidden: a deployment that had
-- configured several providers keeps only the active one. Every other provider
-- row is discarded with the table. Down-migrations here are for rolling back a
-- bad deploy, not for round-tripping data.
ALTER TABLE org_settings ADD COLUMN llm_provider_kind text
  CHECK (llm_provider_kind IS NULL OR llm_provider_kind IN ('api', 'cli'));
ALTER TABLE org_settings ADD COLUMN llm_base_url text;
ALTER TABLE org_settings ADD COLUMN llm_model text;
ALTER TABLE org_settings ADD COLUMN llm_api_key text;
ALTER TABLE org_settings ADD COLUMN cli_runner_url text;
ALTER TABLE org_settings ADD COLUMN cli_runner_token text;
ALTER TABLE org_settings ADD COLUMN cli_agent text
  CHECK (cli_agent IS NULL OR cli_agent IN ('claude', 'codex'));

UPDATE org_settings s SET
  llm_provider_kind = p.kind,
  llm_base_url      = p.base_url,
  llm_model         = p.model,
  llm_api_key       = p.api_key,
  cli_runner_url    = p.runner_url,
  cli_runner_token  = p.runner_token,
  cli_agent         = p.agent
FROM ai_providers p
WHERE s.id = 'singleton' AND s.active_ai_provider_id = p.id;

ALTER TABLE org_settings DROP COLUMN active_ai_provider_id;
DROP TABLE ai_providers;
