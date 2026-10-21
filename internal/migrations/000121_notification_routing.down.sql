-- Restores migration 000007's exact shape for both tables, so that a
-- `migrate down` past this point leaves the schema as 000120 left it.
--
-- This down file DOES drop data — every notification destination and routing
-- rule an operator configured — and that is correct rather than regrettable:
-- the columns holding them do not exist at 000120, so there is nowhere for the
-- values to go. What it must NOT do is break the deployment it rolls back to,
-- and it does not: at 000120 the effective webhook is org_settings.
-- notify_webhook_url (or ARGUS_NOTIFY_WEBHOOK_URL), which this migration never
-- touched, so rolling back returns every deployment to the single global
-- webhook it had before — the same destination F32's default rule preserved.
--
-- The DELETE is explicit rather than left to the column drops. `integrations`
-- rows without a url column are meaningless, and `notification_routes` rows
-- re-acquire NOT NULL `match`/`targets`/`on_events` columns they have no values
-- for, which would fail outright on a non-empty table. Deleting first states
-- what is happening instead of discovering it as a constraint violation.
--
-- Order matters: notification_routes.destination_id references integrations
-- with ON DELETE RESTRICT, so the rules go first.
DELETE FROM notification_routes;
DELETE FROM integrations;

DROP INDEX IF EXISTS notification_routes_order_idx;

ALTER TABLE notification_routes DROP COLUMN name;
ALTER TABLE notification_routes DROP COLUMN priority;
ALTER TABLE notification_routes DROP COLUMN cluster_group_id;
ALTER TABLE notification_routes DROP COLUMN min_severity;
ALTER TABLE notification_routes DROP COLUMN transition;
ALTER TABLE notification_routes DROP COLUMN destination_id;
ALTER TABLE notification_routes DROP COLUMN enabled;
ALTER TABLE notification_routes DROP COLUMN created_at;
ALTER TABLE notification_routes DROP COLUMN updated_at;

ALTER TABLE notification_routes ADD COLUMN match jsonb NOT NULL;
ALTER TABLE notification_routes ADD COLUMN targets text[] NOT NULL;
ALTER TABLE notification_routes ADD COLUMN on_events text[] NOT NULL;
ALTER TABLE notification_routes ADD COLUMN digest_interval interval;

DROP INDEX IF EXISTS integrations_tenant_name_idx;

ALTER TABLE integrations DROP CONSTRAINT integrations_kind_check;
ALTER TABLE integrations DROP COLUMN name;
ALTER TABLE integrations DROP COLUMN url;
ALTER TABLE integrations DROP COLUMN created_at;
ALTER TABLE integrations DROP COLUMN updated_at;

ALTER TABLE integrations ADD COLUMN config jsonb NOT NULL;
ALTER TABLE integrations ADD COLUMN credential_ref text;
