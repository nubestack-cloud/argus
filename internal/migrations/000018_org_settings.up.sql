-- Single-row, organisation-wide operational config for the AI provider and
-- the notification webhook (DESIGN.md §16.2/§13), replacing
-- "env var, read once at hub startup" with "DB row, read fresh on every use,
-- editable at runtime via PUT /api/v1/admin/settings" (internal/settings,
-- internal/api/settings.go). Confirmed single-organisation deployment
-- (§5.1) — a real per-tenant table is not needed yet, so this is a fixed
-- singleton row, the same shape STATUS.md's other single-org settings
-- (ARGUS_BOOTSTRAP_PASSWORD, ARGUS_APP_PASSWORD) have always implicitly had,
-- just now DB-backed and runtime-editable instead of env-only.
--
-- Every column is nullable and starts NULL: NULL means "not set in the DB,
-- fall back to the env var" (internal/settings.Resolve's precedence rule),
-- not "set to empty." A cleared value (PUT with a field present as "") is
-- also stored as NULL, for the same reason — there is no distinct "keep the
-- literal empty string" state anywhere in this design.
--
-- Deliberately NO row-level security on this table, matching migration
-- 000016_signing_keys.up.sql's decision and reasoning, not just its shape:
-- (1) this holds organisation-wide operational config, not tenant-scoped
-- data -- there is exactly one row, for the one confirmed organisation, not
-- one per tenant; (2) the two real READ call sites that matter most --
-- internal/llm.Provider.Complete (one HTTP call per incident analysis) and
-- internal/notify.WebhookNotifier's poll tick -- run with no per-request
-- tenant/RLS context at all, unlike the internal/api/settings.go handler
-- that reads/writes this table over an already-scoped request transaction.
-- A tenant_id-keyed policy here would make those two call sites either fail
-- outright (no app.tenant_id set) or need to freshly resolve+set scope on
-- every single LLM call and every 30s notify sweep tick just to read one
-- config row -- the same class of startup/call-time-ordering risk the
-- 000016 comment already flagged for signing_keys, for a table that was
-- never RLS-eligible in the first place.
--
-- Holds real secrets: llm_api_key outright, and notify_webhook_url too --
-- despite the column being named "url," a Slack incoming-webhook URL embeds
-- a bearer-equivalent token in its path (anyone holding the URL can post as
-- that integration), so it gets the same "never echo back over the API"
-- treatment as llm_api_key (internal/api/settings.go's GET handler returns
-- only booleans for both, never the stored value).
--
-- argus_app needs an explicit grant, matching 000016's and 000010's
-- precedent for a table created after 000009's ALTER DEFAULT PRIVILEGES.
CREATE TABLE org_settings (
  id                  text PRIMARY KEY DEFAULT 'singleton',
  llm_base_url        text,
  llm_model           text,
  llm_api_key         text,
  notify_webhook_url  text,
  updated_at          timestamptz NOT NULL DEFAULT now()
);

INSERT INTO org_settings (id) VALUES ('singleton');

GRANT SELECT, INSERT, UPDATE, DELETE ON org_settings TO argus_app;
