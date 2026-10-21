-- Reverses 000033. Dropping these columns discards any CLI-backend
-- configuration and every row's recorded cost_basis; a re-up backfills
-- cost_basis to 'metered' for all rows again, which is truthful for rows the
-- api backend wrote and NOT truthful for any row a CLI backend wrote in
-- between. Noted rather than worked around: down-migrations in this repo are
-- for rolling back a bad deploy, not for round-tripping data.
ALTER TABLE analyses DROP COLUMN IF EXISTS cost_basis;

ALTER TABLE org_settings DROP COLUMN IF EXISTS cli_agent;
ALTER TABLE org_settings DROP COLUMN IF EXISTS cli_runner_token;
ALTER TABLE org_settings DROP COLUMN IF EXISTS cli_runner_url;
ALTER TABLE org_settings DROP COLUMN IF EXISTS llm_provider_kind;
