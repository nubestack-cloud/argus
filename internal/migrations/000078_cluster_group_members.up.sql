-- Cluster group membership (BACKLOG.md S3, "cluster groups and team
-- ownership"). cluster_groups itself has existed since migration 000002
-- with no handler or UI behind it — lld/02-authz-spec.md §3 describes its
-- `label_selector` column as resolving membership dynamically ("never
-- materialized into a fixed cluster-ID list at grant time... every
-- authorization decision re-evaluates the scope against the current cluster
-- set"). That design cannot actually be implemented against this schema's
-- RLS as it stands, for a concrete reason worth recording rather than
-- silently working around:
--
--   the `clusters` table's own RLS policy (migration 000009) is
--   `id = ANY(accessible_cluster_ids)` — no tenant_id fallback, because
--   `clusters` is the one table 000009 special-cases (its identifying
--   column IS the cluster, not a cluster_id foreign key). Resolving a
--   ClusterGroup scope by evaluating `label_selector` against
--   `clusters.labels` would require reading `clusters` BEFORE
--   `accessible_cluster_ids` is known — the exact value this resolution is
--   trying to compute. There is no tenant-scoped fallback query that could
--   answer "which clusters currently match this selector" without already
--   having full cluster visibility.
--
-- So membership here is instead an explicit, audited row (this table) —
-- tenant-scoped rather than cluster-scoped, deliberately: like `grants`
-- itself, it must be readable in internal/api/middleware.go's requireAuth
-- BEFORE app.accessible_cluster_ids is narrowed (internal/authz.
-- AccessibleClusterIDs' ClusterGroup case queries it directly), which a
-- cluster_id-keyed RLS policy (migration 000009's generic loop) cannot
-- support for the same chicken-and-egg reason above. This does not weaken
-- lld/02-authz-spec.md §3's actual goal ("assign a role across a growing
-- fleet" without re-granting per cluster) — adding a cluster to a group
-- still extends every ClusterGroup grant on it immediately — it only changes
-- HOW membership is expressed: an explicit INSERT into this table (itself
-- the audited event lld/02-authz-spec.md §14's `cluster_group.
-- membership_changed` names) rather than a label match nothing here can
-- actually evaluate in time.
--
-- cluster_groups.label_selector is left in place (still NOT NULL) but is no
-- longer read for authorization — internal/api/cluster_groups.go stores an
-- empty object for it on every group this table's endpoints create.
--
-- tenant_id has no FK to organisations(id), matching custom_roles' identical
-- choice in migration 000077 and for the same reason (see that migration's
-- comment).
CREATE TABLE cluster_group_members (
  id                text PRIMARY KEY,
  tenant_id         text NOT NULL,
  cluster_group_id  text NOT NULL REFERENCES cluster_groups(id) ON DELETE CASCADE,
  cluster_id        text NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
  added_at          timestamptz NOT NULL DEFAULT now(),
  added_by          text NOT NULL,
  UNIQUE (cluster_group_id, cluster_id)
);
CREATE INDEX cluster_group_members_group_idx ON cluster_group_members (cluster_group_id);

ALTER TABLE cluster_group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE cluster_group_members FORCE ROW LEVEL SECURITY;
CREATE POLICY cluster_group_members_scope ON cluster_group_members
  USING (tenant_id = current_setting('app.tenant_id', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON cluster_group_members TO argus_app;
