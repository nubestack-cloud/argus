-- PROJECT.md F32: one global webhook for the entire fleet becomes a routing
-- table — rules that match on cluster group, severity and state transition and
-- select a destination.
--
-- # Why this RETYPES two existing tables instead of creating new ones
--
-- `integrations` and `notification_routes` have existed since migration 000007
-- and have never been read or written. They are two of the entries in
-- internal/migrations/schema_coverage_test.go's notImplementedTables registry,
-- whose whole purpose is to fail when a table it lists grows real SQL usage —
-- so this migration is exactly the event that registry was built to force, and
-- both entries come out of it in the same change.
--
-- Creating `notification_destinations` and `notification_rules` beside them
-- would have left two dead tables named almost exactly like the two live ones,
-- which is the confusion the registry exists to prevent, not to document.
--
-- # What changes, and why the dropped columns are dropped rather than kept
--
-- Both tables are EMPTY on every deployment — that is not an assumption, it is
-- what "no query touches them" means, and the coverage test has been asserting
-- it continuously. So a destructive ALTER here costs no data anywhere.
--
--   integrations.config (jsonb NOT NULL), integrations.credential_ref
--     A webhook destination's entire credential IS its URL — a Slack incoming
--     webhook URL embeds a bearer-equivalent token in its path (migration
--     000018 says so about org_settings.notify_webhook_url, and it is the
--     reason that column is never echoed back over the API). A separate
--     credential reference has nothing to hold, and a `config` blob nothing
--     reads is a decoy: the next person to touch this table would have to
--     work out that a NOT NULL jsonb column is written '{}' on every insert
--     and never read back. Both are restored by the down file.
--
--   notification_routes.match (jsonb), .targets (text[]), .on_events (text[])
--     000007's untyped sketch. `match` cannot carry a foreign key to
--     cluster_groups, and neither `match` nor `targets` can be validated by
--     the database at all, so a typo in a routing rule would store cleanly and
--     then silently never match — a rule that looks configured and is dead.
--     The typed columns below are checkable: the cluster group is a real
--     reference, the severity is a real CHECK, and the destination is a real
--     foreign key.
--
--   notification_routes.digest_interval
--     Digest batching is not in F32's scope and nothing in this change moves
--     toward it. A nullable column no code path can ever set is the same decoy
--     as `config` above.
--
-- # The default rule is deliberately NOT a row in this table
--
-- F32's acceptance is that the existing single URL becomes the default rule so
-- that no deployment changes behaviour on upgrade. That default is synthetic
-- and lives in internal/notify's routing table builder, not here, for a reason
-- this migration could not work around even if it wanted to: the effective
-- webhook URL is org_settings.notify_webhook_url OR the ARGUS_NOTIFY_WEBHOOK_URL
-- environment variable, resolved fresh on every sweep tick by
-- internal/settings.Resolve. A migration cannot see an environment variable, so
-- seeding a row from the column here would silently drop every deployment that
-- configures the webhook by env var alone — precisely the deployments that
-- would "change behaviour on upgrade".
--
-- So this table holds only the rules an operator wrote, and the default rule is
-- appended last, always, by internal/notify.LoadRouting. See routing.go.

-- --- destinations ----------------------------------------------------------

ALTER TABLE integrations DROP COLUMN config;
ALTER TABLE integrations DROP COLUMN credential_ref;

-- name is the operator-facing identity of a destination AND the key routing
-- rules reference it by in the API payload (a rule cannot reference a
-- destination created in the same request by id, because the id is minted
-- server-side). Unique per tenant for that reason, not merely for tidiness.
ALTER TABLE integrations ADD COLUMN name text;
UPDATE integrations SET name = id WHERE name IS NULL;
ALTER TABLE integrations ALTER COLUMN name SET NOT NULL;
CREATE UNIQUE INDEX integrations_tenant_name_idx ON integrations (tenant_id, name);

-- Holds a real secret, exactly like org_settings.notify_webhook_url: never
-- echoed back over the API (internal/api/notification_routing.go returns a
-- boolean, the same treatment llm_api_key already gets).
ALTER TABLE integrations ADD COLUMN url text NOT NULL DEFAULT '';
ALTER TABLE integrations ALTER COLUMN url DROP DEFAULT;

-- One kind today. Email, PagerDuty and Opsgenie are named in F32 as absent and
-- stay absent: this change is about ROUTING, not about a second transport, and
-- a CHECK that lists only what is implemented is what stops a destination being
-- stored that nothing can deliver to.
ALTER TABLE integrations ADD CONSTRAINT integrations_kind_check CHECK (kind IN ('webhook'));

ALTER TABLE integrations ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE integrations ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();

-- --- rules -----------------------------------------------------------------

ALTER TABLE notification_routes DROP COLUMN match;
ALTER TABLE notification_routes DROP COLUMN targets;
ALTER TABLE notification_routes DROP COLUMN on_events;
ALTER TABLE notification_routes DROP COLUMN digest_interval;

ALTER TABLE notification_routes ADD COLUMN name text NOT NULL DEFAULT '';
ALTER TABLE notification_routes ALTER COLUMN name DROP DEFAULT;

-- Evaluation is ordered by (priority, id) and the FIRST matching rule wins —
-- see internal/notify/routing.go's RoutingTable.Match for why first-match-wins
-- rather than fan-out, and what that buys F32's actual problem statement.
ALTER TABLE notification_routes ADD COLUMN priority integer NOT NULL DEFAULT 0;
ALTER TABLE notification_routes ALTER COLUMN priority DROP DEFAULT;

-- NULL means "any cluster group", i.e. this dimension is not matched on.
-- ON DELETE CASCADE rather than RESTRICT: a rule whose group is gone can never
-- match anything again (membership went with it), so keeping the row would only
-- preserve a rule that is already dead while making the group undeletable.
ALTER TABLE notification_routes
  ADD COLUMN cluster_group_id text REFERENCES cluster_groups(id) ON DELETE CASCADE;

-- Minimum severity, not exact severity: "tell this team about high and above"
-- is the rule operators actually write, and an equality matcher forces two
-- rules for it and four for "anything". The cost is that "only medium" is not
-- expressible; that has no operational meaning here, and the ladder is closed,
-- so the trade is one-directional. NULL means "any severity".
ALTER TABLE notification_routes ADD COLUMN min_severity text
  CHECK (min_severity IS NULL OR min_severity IN ('low', 'medium', 'high', 'critical'));

-- The transition token this rule matches: 'NewIncident' for the new-incident
-- queue, or an incidents.state name for a state transition ('Reopened',
-- 'AwaitingApproval', 'Failed', 'ExecutionUnknown', 'ValidationUnknown',
-- 'AwaitingMerge'). Deliberately NOT a CHECK constraint: the authoritative list
-- is internal/orchestrator's notifiableStates plus the escalation sweepers'
-- key prefixes, and a CHECK here would be a fourth copy of it that goes stale
-- silently in the database, where nothing compiles. internal/notify.
-- KnownTransitions is the one list, the API validates against it, and a token
-- that matches nothing falls through to the default rule rather than being
-- dropped. NULL means "any transition".
ALTER TABLE notification_routes ADD COLUMN transition text;

ALTER TABLE notification_routes ADD COLUMN destination_id text NOT NULL
  REFERENCES integrations(id) ON DELETE RESTRICT;

-- Disabling a rule is not the same as deleting it: an operator silencing a
-- noisy route for an afternoon must not lose which group/severity/transition
-- it named. A disabled rule is skipped during matching, so traffic falls
-- through to the next rule and ultimately to the default — never nowhere.
ALTER TABLE notification_routes ADD COLUMN enabled boolean NOT NULL DEFAULT true;

ALTER TABLE notification_routes ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE notification_routes ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();

CREATE INDEX notification_routes_order_idx ON notification_routes (tenant_id, priority, id);

-- Both tables already carry migration 000009's generic tenant_id-keyed RLS
-- policy (integrations and notification_routes are both named in its loop), and
-- both already have argus_app's grants from the same migration's ALTER DEFAULT
-- PRIVILEGES. Nothing about retyping their columns changes either, so there is
-- deliberately no RLS statement in this file — re-CREATEing a policy that
-- already exists would fail, and neither table's scope-bearing shape changed:
-- a notification rule is org-wide configuration with no cluster_id of its own
-- (it names a cluster GROUP), the same shape cluster_group_members has for the
-- same reason.
