-- Toleration rules — the "mute switch" BACKLOG.md's A5 entry designs and
-- CapIncidentSilence (declared since the first authz pass, granted to
-- resolver/tenant-admin/super-admin, never backed by anything) has been
-- waiting for.
--
-- WHY THIS EXISTS
--
-- Motivating live case: rancher-monitoring-windows-exporter's Service has a
-- selector but no endpoints, because its DaemonSet needs Windows nodes this
-- cluster doesn't have. That is not a bug — the Helm chart ships the
-- component enabled by default so it activates automatically if a Windows
-- node ever joins — but ARGUS has no way to say "real, expected, stop
-- re-opening this" short of resolving or dismissing the incident every time
-- its detector re-fires. Neither Resolved nor Dismissed actually helps:
-- internal/gateway/finding.go's correlation query is `state NOT IN
-- ('Resolved', 'Dismissed')` — both are "closed" for matching purposes only,
-- not "stop telling me about this object." The very next Finding for the
-- same object opens a brand-new incident, because closing an incident is
-- deliberately a statement about the past (see incident_triage.go's own doc
-- comment), not a suppression mechanism. Left alone, an accepted-but-real
-- condition like this one costs a fresh incident (and, if auto-analysis is
-- ever enabled, a fresh paid investigation) every detection cycle forever.
--
-- WHAT THIS IS NOT
--
-- Not a new incident state, and not a way to suppress a fault nobody has
-- looked at yet. A toleration is created FROM an already-open incident (the
-- operator has seen the specific symptom and decided it needs no action),
-- and it takes effect only for FUTURE findings on that same object —
-- internal/gateway/finding.go checks it at the exact point where it would
-- otherwise open a new incident, the same hook storm protection already
-- uses, and a suppressed Finding is still fully recorded (findings row with
-- incident_id NULL) rather than dropped. The existing findings, the incident
-- that prompted this rule, and the note explaining why all stay exactly as
-- durable as any other resolve/dismiss decision.
--
-- SCOPE: object_key, optionally narrowed by REASON
--
-- object_key matches incidents.object_key's own definition
-- (gvk|namespace|name, see migration 000036) — a toleration is always about
-- one concrete object, never a whole namespace or cluster; broader
-- suppression is exactly the kind of thing that hides a real, unrelated
-- future problem on the same object behind an old, specific decision.
--
-- reasons narrows further, to specific detector reason strings, and is
-- nullable on purpose: NULL means "every reason on this object is
-- tolerated" (the operator explicitly chose to silence the whole object,
-- e.g. a known-broken dev workload); a non-null array means "only these
-- specific symptoms" (the default the API applies — see
-- internal/api/tolerations.go — is the exact set of reasons the triggering
-- incident's findings already carry, so approving a Windows-exporter
-- toleration does not also silently swallow a future, unrelated OOMKill on
-- the same Service object).
CREATE TABLE incident_tolerations (
  id          text PRIMARY KEY,   -- 'tol_...' (domain.PrefixToleration)
  tenant_id   text NOT NULL,
  cluster_id  text NOT NULL,
  object_key  text NOT NULL,
  reasons     text[],            -- NULL = every reason on this object
  note        text NOT NULL,      -- required, same rationale as dismiss's note
  created_by  text NOT NULL,      -- users.id of whoever created the rule
  created_at  timestamptz NOT NULL DEFAULT now(),
  -- Optional: a toleration for "we might add a Windows node later" can be
  -- open-ended, but many real cases are "ignore this until the maintenance
  -- window closes" — after expires_at, the rule stops matching and the next
  -- occurrence opens a normal incident again. Enforced in the lookup query
  -- (WHERE expires_at IS NULL OR expires_at > now()), not by a cron sweep —
  -- an expired-but-unswept row is harmless dead data, not a live risk.
  expires_at  timestamptz,
  -- Soft delete, same convention as grants.revoked_at (internal/api/users.go)
  -- — removing a toleration keeps who created it, why, and who/when it was
  -- removed, all auditable, rather than losing that history to a DELETE.
  removed_at  timestamptz,
  removed_by  text
);

-- The one query internal/gateway/finding.go's hot path runs: "is there an
-- active rule for this (cluster, object)". Partial on removed_at IS NULL
-- (an active rule) — expires_at is left out of the predicate since `now()`
-- is not IMMUTABLE and can't appear in a partial index's WHERE clause; the
-- query itself still filters on it.
CREATE INDEX incident_tolerations_active_idx ON incident_tolerations (cluster_id, object_key)
  WHERE removed_at IS NULL;

-- Same RLS shape as mcp_tool_calls (000037): PERMISSIVE tenant policy,
-- RESTRICTIVE cluster-narrowing policy spelled out in full rather than
-- relying on the default-empty-means-no-narrowing rule implicitly. This
-- table is read/written from two contexts, both already inside a
-- tenant/cluster-scoped transaction: internal/gateway/finding.go's own
-- tx (data.SetRequestScope, narrowed to the one calling cluster) and
-- internal/api's request transaction (middleware.go's requireAuth).
ALTER TABLE incident_tolerations ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_tolerations FORCE ROW LEVEL SECURITY;
CREATE POLICY incident_tolerations_tenant_scope ON incident_tolerations
  USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY incident_tolerations_cluster_scope ON incident_tolerations AS RESTRICTIVE
  USING (
    COALESCE(current_setting('app.accessible_cluster_ids', true), '') = ''
    OR cluster_id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ','))
  )
  WITH CHECK (
    COALESCE(current_setting('app.accessible_cluster_ids', true), '') = ''
    OR cluster_id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ','))
  );

-- Explicit grant, matching every migration since 000010's stated convention
-- of spelling this out rather than relying on 000009's default privileges.
GRANT SELECT, INSERT, UPDATE, DELETE ON incident_tolerations TO argus_app;
