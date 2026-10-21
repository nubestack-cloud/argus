-- BACKLOG.md N1: internal/notify's trigger set widens beyond "new incident,
-- once" (migration 000017's incidents.notified_at). This table is the
-- mechanism behind DESIGN.md §13.3's "one notification per incident,
-- updated in place, not one per event" rule -- decided up front, per N1's
-- own instruction, rather than retrofitted once the spam already happened.
--
-- One row per incident (incident_id is unique, not a log of every
-- transition): notify_key records what the row's most recent notification
-- was ABOUT, and is opaque to this table -- see internal/notify/
-- transitions.go's own doc comment for what each caller puts in it. For the
-- four state-transition triggers (internal/orchestrator.SetState) it is a
-- timestamp-suffixed state name (e.g. 'AwaitingApproval@2026-08-31T12:00:00Z'),
-- deliberately unique per call so a SECOND entry into the same state later in
-- the incident's life still notifies. For mergewatch.go's stale-unmerged-pull-
-- request escalation (DESIGN.md §12.3, previously logged with no delivery
-- route -- see mergewatch.go's own comment) it is the fixed, literal
-- 'AwaitingMerge:StalePR', deliberately UNCHANGED across repeated ticks, since
-- that condition is a repeatedly-observed time threshold, not a discrete
-- transition -- only a key that differs from what's already stored (the
-- ON CONFLICT ... WHERE guard below) queues a fresh send.
--
-- incident_id is deliberately NOT a foreign key: incidents' primary key is
-- the composite (id, first_seen) its own range partitioning needs (migration
-- 000005), so nothing else in this codebase declares REFERENCES
-- incidents(id) either -- see unattended_batch_members' identical incident_id
-- column (migration 000073) for the precedent and its own fuller comment.
--
-- tenant_id/cluster_id are denormalized (lld/05-data-model.md §6), matching
-- unattended_batch_members' identical reasoning: internal/notify's sweep
-- reads this table fleet-wide on every tick, and a join back through
-- incidents for columns this cheap to duplicate is pure overhead.
--
-- Neither carries a foreign key, deliberately — unlike
-- unattended_batch_members' own cluster_id, which does. This table is
-- written from SetState (db.go), the one function every incident state
-- transition in this codebase already goes through, so its rows outlive
-- whatever test or code path happens to delete a cluster/incident row next;
-- matching remediation_recommendations/remediation_executions' identical
-- plain `cluster_id text NOT NULL` (no REFERENCES) avoids forcing every one
-- of this codebase's many existing DB-backed tests that delete a throwaway
-- cluster in cleanup to learn about this table's existence just to order a
-- DELETE before it.
CREATE TABLE incident_notifications (
  incident_id  text        NOT NULL,
  tenant_id    text        NOT NULL,
  cluster_id   text        NOT NULL,
  notify_key   text        NOT NULL,
  summary      text        NOT NULL,
  -- pending = true means "notify_key describes something that has not been
  -- delivered yet" -- set true whenever notify_key actually changes (see the
  -- ON CONFLICT ... WHERE guard below), set false by internal/notify's sweep
  -- once the webhook POST for the CURRENT notify_key has succeeded.
  pending      boolean     NOT NULL DEFAULT true,
  notified_at  timestamptz,
  updated_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (incident_id)
);

-- Cluster-scoped, matching migration 000009's generic loop shape (this table
-- postdates that loop, so it gets its own policy here rather than being
-- added to it retroactively -- same precedent as 000010_enrollment_tokens'
-- own tenant-scoped policy).
ALTER TABLE incident_notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_notifications FORCE ROW LEVEL SECURITY;
CREATE POLICY incident_notifications_scope ON incident_notifications
  USING (cluster_id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ',')));

-- Second, additive, PERMISSIVE tenant_id-keyed policy -- the exact RLS gap
-- migration 000013 already found and fixed twice on findings/incidents (see
-- that migration's own comment for the full mechanics), hit proactively here
-- instead of by a first fleet-wide reader landing broken. internal/notify's
-- sweep (both the pre-existing "new incident" queue and this table) reads
-- fleet-wide with app.accessible_cluster_ids left unset -- it isn't scoped
-- to any single known cluster the way a tunnel connection's writes are -- so
-- the cluster_id-scoped policy above, alone, would make this table
-- permanently and silently empty from that context. Postgres ORs multiple
-- permissive policies together for the same command, so this is additive,
-- not a weakening: the cluster_id policy still narrows access further once
-- per-cluster-scoped grants are ever implemented (authz-spec §6, still not
-- built), and until then tenant_id scoping is exactly as safe as every other
-- tenant_id policy already in production use, for this confirmed
-- single-organisation deployment (DESIGN.md §5.1/D9).
CREATE POLICY incident_notifications_tenant_scope ON incident_notifications
  USING (tenant_id = current_setting('app.tenant_id', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON incident_notifications TO argus_app;
