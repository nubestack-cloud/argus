package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/domain"
	"argus/internal/logging"
)

// This file implements cluster groups and their membership (BACKLOG.md S3,
// "cluster groups and team ownership"). cluster_groups itself has existed
// since migration 000002 with no handler or UI behind it at all — P2's
// unreferenced-table audit named it, and authz.AccessibleClusterIDs used to
// refuse a ClusterGroup-scoped grant outright specifically because this
// table had no membership.
//
// "Team ownership" is not a new concept or a new column: it is a grant
// (internal/api/users.go's existing POST /users/{id}/grants) scoped to
// `{"type": "ClusterGroup", "clusterGroupId": "..."}` instead of one cluster
// or all of them — the SAME scope grammar lld/02-authz-spec.md §3 specified
// from the start. Once a group has real membership (this file's job) and
// authz.AccessibleClusterIDs can resolve that scope (internal/authz/
// permissions.go), granting a role to "the payments team" is just granting
// that role scoped to the payments cluster group — no separate ownership
// schema is needed on top of the grant mechanism that already exists.
//
// Membership is an explicit, audited row (migration 000078's
// cluster_group_members) rather than cluster_groups.label_selector's
// originally-specified dynamic evaluation — see that migration's own comment
// for the concrete RLS reason a live label-selector match cannot work against
// this schema's `clusters` policy.

type clusterGroupView struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	ClusterIDs []string `json:"clusterIds"`
}

// handleListClusterGroups is GET /api/v1/cluster-groups. Requires
// cluster:read — the same floor GET /api/v1/clusters already uses; a group
// is just a named subset of the same cluster inventory that route lists.
func (s *Server) handleListClusterGroups(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()

	rows, err := rc.Tx.Query(ctx, `SELECT id, name FROM cluster_groups ORDER BY lower(name)`)
	if err != nil {
		logger.ErrorContext(ctx, "querying cluster groups failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list cluster groups", "")
		return
	}
	defer rows.Close()

	groups := []clusterGroupView{}
	order := []string{}
	byID := map[string]*clusterGroupView{}
	for rows.Next() {
		var g clusterGroupView
		if err := rows.Scan(&g.ID, &g.Name); err != nil {
			logger.ErrorContext(ctx, "scanning a cluster-group row failed", logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list cluster groups", "")
			return
		}
		g.ClusterIDs = []string{}
		groups = append(groups, g)
		order = append(order, g.ID)
	}
	if err := rows.Err(); err != nil {
		logger.ErrorContext(ctx, "iterating the cluster-group rows failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list cluster groups", "")
		return
	}
	for i := range groups {
		byID[groups[i].ID] = &groups[i]
	}

	// Second query rather than combined into the first, matching
	// handleListUsers' own precedent (users.go) for the identical shape
	// reason: a slice-per-parent field is awkward from one joined result
	// set, and this list is small (a handful of groups per fleet, not
	// fleet-scale itself).
	//
	// JOINed against clusters HERE, deliberately, rather than a bare
	// `SELECT ... FROM cluster_group_members`: cluster_group_members is
	// tenant-scoped, not cluster-scoped (migration 000078's own comment
	// explains why it has to be), so on its own it would return every
	// member row in the tenant regardless of which clusters THIS caller's
	// grants actually reach — a real cross-scope leak found in review, since
	// a principal scoped to one cluster could otherwise enumerate every
	// other cluster's raw id via a group it can see. `clusters` itself IS
	// properly scoped by app.accessible_cluster_ids (migration 000009), so
	// joining against it makes the visible member list exactly the
	// intersection of "in this group" and "a cluster this caller can see" —
	// enforced by the same RLS policy already governing GET /clusters,
	// rather than reimplemented here.
	if len(order) > 0 {
		memberRows, err := rc.Tx.Query(ctx,
			`SELECT cgm.cluster_group_id, cgm.cluster_id FROM cluster_group_members cgm
			   JOIN clusters c ON c.id = cgm.cluster_id
			   WHERE cgm.cluster_group_id = ANY($1) ORDER BY cgm.added_at`, order)
		if err != nil {
			logger.ErrorContext(ctx, "querying the cluster group's members failed", logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list cluster groups", "")
			return
		}
		defer memberRows.Close()
		for memberRows.Next() {
			var groupID, clusterID string
			if err := memberRows.Scan(&groupID, &clusterID); err != nil {
				logger.ErrorContext(ctx, "scanning a cluster-group member row failed", logging.Err(err))
				writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list cluster groups", "")
				return
			}
			if g, ok := byID[groupID]; ok {
				g.ClusterIDs = append(g.ClusterIDs, clusterID)
			}
		}
		if err := memberRows.Err(); err != nil {
			logger.ErrorContext(ctx, "iterating the cluster-group member rows failed", logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list cluster groups", "")
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"clusterGroups": groups})
}

type createClusterGroupRequest struct {
	Name string `json:"name"`
}

// handleCreateClusterGroup is POST /api/v1/cluster-groups. Requires
// cluster:group:manage.
//
// label_selector is stored as an empty object — see this file's package
// comment and migration 000078's own comment for why the column exists but
// is not read for authorization here: membership is the explicit
// cluster_group_members table this file also manages, not a dynamic
// selector match, for a concrete RLS reason rather than an oversight.
func (s *Server) handleCreateClusterGroup(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	var req createClusterGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "A group name is required", "")
		return
	}

	ctx := r.Context()
	id := domain.NewID(domain.PrefixClusterGroup)
	if _, err := rc.Tx.Exec(ctx,
		`INSERT INTO cluster_groups (id, tenant_id, name, label_selector) VALUES ($1, $2, $3, '{}'::jsonb)`,
		id, rc.TenantID, name); err != nil {
		logger.ErrorContext(ctx, "inserting the cluster group failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not create cluster group", "")
		return
	}

	capability := authz.CapClusterGroupManage
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		Outcome:         audit.OutcomeSuccess,
		Details:         map[string]any{"action": "create_cluster_group", "groupId": id, "name": name},
	}); err != nil {
		logger.ErrorContext(ctx, "recording a cluster-group creation in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	writeJSON(w, http.StatusCreated, clusterGroupView{ID: id, Name: name, ClusterIDs: []string{}})
}

// handleDeleteClusterGroup is DELETE /api/v1/cluster-groups/{id}. Requires
// cluster:group:manage. Refuses while any non-revoked, non-expired grant is
// still scoped to this group (409) — the identical "don't silently orphan a
// live reference" caution handleDeleteCustomRole applies to a role still
// granted to someone. grants.scope is jsonb (authz.Scope's own JSON shape),
// so the check reads it directly rather than via a foreign key that shape
// does not have.
func (s *Server) handleDeleteClusterGroup(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	id := r.PathValue("id")
	ctx := r.Context()

	var name string
	if err := rc.Tx.QueryRow(ctx, `SELECT name FROM cluster_groups WHERE id = $1`, id).Scan(&name); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Cluster group not found", "")
			return
		}
		logger.ErrorContext(ctx, "looking up the cluster group to delete failed", slog.String("group_id", id), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up cluster group", "")
		return
	}

	var inUse bool
	if err := rc.Tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM grants
		   WHERE scope->>'type' = 'ClusterGroup' AND scope->>'clusterGroupId' = $1 AND `+activeGrantsWhere+`)`,
		id).Scan(&inUse); err != nil {
		logger.ErrorContext(ctx, "checking whether the cluster group is in use failed", slog.String("group_id", id), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not check whether the group is in use", "")
		return
	}
	if inUse {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/in-use",
			"This group still has at least one active grant scoped to it",
			"revoke every grant scoped to it first, then delete it")
		return
	}

	// ON DELETE CASCADE (migration 000078) removes this group's own
	// cluster_group_members rows along with it.
	if _, err := rc.Tx.Exec(ctx, `DELETE FROM cluster_groups WHERE id = $1`, id); err != nil {
		logger.ErrorContext(ctx, "deleting the cluster group failed", slog.String("group_id", id), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not delete cluster group", "")
		return
	}

	capability := authz.CapClusterGroupManage
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		Outcome:         audit.OutcomeSuccess,
		Details:         map[string]any{"action": "delete_cluster_group", "groupId": id, "name": name},
	}); err != nil {
		logger.ErrorContext(ctx, "recording a cluster-group deletion in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"groupId": id, "status": "deleted"})
}

type addClusterToGroupRequest struct {
	ClusterID string `json:"clusterId"`
}

// handleAddClusterToGroup is POST /api/v1/cluster-groups/{id}/clusters.
// Requires cluster:group:manage.
//
// Adding a cluster to a group is itself the audited event
// lld/02-authz-spec.md §3 names ("cluster-group membership changes are
// themselves an audited event... since adding a cluster to a group can
// silently grant access to everyone holding a ClusterGroup grant on it") —
// audit.RecordEvent below is not incidental logging, it is the specific
// control that section calls for.
func (s *Server) handleAddClusterToGroup(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	groupID := r.PathValue("id")
	ctx := r.Context()

	var groupName string
	if err := rc.Tx.QueryRow(ctx, `SELECT name FROM cluster_groups WHERE id = $1`, groupID).Scan(&groupName); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Cluster group not found", "")
			return
		}
		logger.ErrorContext(ctx, "looking up the cluster group failed", slog.String("group_id", groupID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up cluster group", "")
		return
	}

	var req addClusterToGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}
	clusterID := strings.TrimSpace(req.ClusterID)
	if clusterID == "" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "clusterId is required", "")
		return
	}

	exists, err := clusterExists(ctx, rc.Tx, clusterID)
	if err != nil {
		logger.ErrorContext(ctx, "checking that the cluster exists failed", slog.String("group_id", groupID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not validate cluster", "")
		return
	}
	if !exists {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "Unknown cluster", "")
		return
	}

	id := domain.NewID(domain.PrefixClusterGroupMember)
	if _, err := rc.Tx.Exec(ctx,
		`INSERT INTO cluster_group_members (id, tenant_id, cluster_group_id, cluster_id, added_by)
		 VALUES ($1, $2, $3, $4, $5)`,
		id, rc.TenantID, groupID, clusterID, rc.UserID); err != nil {
		if isUniqueViolation(err) {
			writeProblem(w, http.StatusConflict, "https://argus.io/errors/already-exists", "This cluster is already a member of the group", "")
			return
		}
		logger.ErrorContext(ctx, "adding a cluster to a group failed", slog.String("group_id", groupID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not add cluster to group", "")
		return
	}

	capability := authz.CapClusterGroupManage
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		Outcome:         audit.OutcomeSuccess,
		Details: map[string]any{
			"action":    "cluster_group.membership_changed",
			"groupId":   groupID,
			"groupName": groupName,
			"clusterId": clusterID,
			"change":    "added",
		},
	}); err != nil {
		logger.ErrorContext(ctx, "recording a cluster-group membership addition in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"groupId": groupID, "clusterId": clusterID})
}

// handleRemoveClusterFromGroup is
// DELETE /api/v1/cluster-groups/{id}/clusters/{clusterId}. Requires
// cluster:group:manage. Same membership-changed audit event as adding one,
// for the identical reason: removing a cluster from a group can silently
// narrow everyone holding a ClusterGroup grant on it just as adding one
// silently widens it — both directions are worth a record.
func (s *Server) handleRemoveClusterFromGroup(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	groupID := r.PathValue("id")
	clusterID := r.PathValue("clusterId")
	ctx := r.Context()

	tag, err := rc.Tx.Exec(ctx,
		`DELETE FROM cluster_group_members WHERE cluster_group_id = $1 AND cluster_id = $2`,
		groupID, clusterID)
	if err != nil {
		logger.ErrorContext(ctx, "removing a cluster from a group failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not remove cluster from group", "")
		return
	}
	if tag.RowsAffected() == 0 {
		writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "This cluster is not a member of that group", "")
		return
	}

	capability := authz.CapClusterGroupManage
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		Outcome:         audit.OutcomeSuccess,
		Details: map[string]any{
			"action":    "cluster_group.membership_changed",
			"groupId":   groupID,
			"clusterId": clusterID,
			"change":    "removed",
		},
	}); err != nil {
		logger.ErrorContext(ctx, "recording a cluster-group membership removal in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"groupId": groupID, "clusterId": clusterID, "status": "removed"})
}
