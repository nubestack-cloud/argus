package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/logging"
	"argus/internal/resourcechanges"
)

// Field-level change history (docs/CLUSTER_INSIGHT_SPECS.md CI-S2).

// GET /api/v1/clusters/{id}/resource-changes?namespace&kind&name&since&until&limit
func (s *Server) handleListResourceChanges(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	clusterID := r.PathValue("id")
	if !s.authorizeClusterScoped(w, r, rc, authz.CapClusterRead, clusterID) {
		return
	}
	q := resourcechanges.Query{ClusterID: clusterID,
		Namespace: r.URL.Query().Get("namespace"), Kind: r.URL.Query().Get("kind"), Name: r.URL.Query().Get("name")}
	var err error
	if q.Since, err = optionalTime(r.URL.Query().Get("since")); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/validation", "Invalid since", "since must be RFC 3339")
		return
	}
	if q.Until, err = optionalTime(r.URL.Query().Get("until")); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/validation", "Invalid until", "until must be RFC 3339")
		return
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		q.Limit, _ = strconv.Atoi(l)
	}
	res, err := resourcechanges.List(ctx, rc.Tx, q)
	if err != nil {
		logger.ErrorContext(ctx, "listing resource changes failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list changes", "")
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// precedingWindow is how far before an incident opened its "what changed"
// list looks.
const precedingWindow = 2 * time.Hour

// GET /api/v1/incidents/{id}/preceding-changes — changes to the incident's
// object, its workload and anything they own, from two hours before it
// opened until now, plus any gap overlapping that window.
func (s *Server) handleIncidentPrecedingChanges(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	incidentID := r.PathValue("id")
	q, found, err := precedingChangesQuery(ctx, rc.Tx, incidentID)
	if err != nil {
		logger.ErrorContext(ctx, "loading the incident for its preceding changes failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up incident", "")
		return
	}
	if !found {
		writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Incident not found", "")
		return
	}
	res, err := resourcechanges.List(ctx, rc.Tx, q)
	if err != nil {
		logger.ErrorContext(ctx, "listing preceding changes failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list changes", "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"since": q.Since, "changes": res.Changes, "gaps": res.Gaps, "truncated": res.Truncated})
}

// precedingChangesQuery builds the query for one incident from its own row,
// never from request input. RLS on the caller's transaction decides whether
// the incident is visible at all.
func precedingChangesQuery(ctx context.Context, tx pgx.Tx, incidentID string) (resourcechanges.Query, bool, error) {
	var clusterID string
	var objectKey, workloadKey, relatedKey *string
	var firstSeen time.Time
	err := tx.QueryRow(ctx, `SELECT cluster_id, object_key, workload_key, related_workload_key, first_seen FROM incidents WHERE id = $1`, incidentID).
		Scan(&clusterID, &objectKey, &workloadKey, &relatedKey, &firstSeen)
	if err == pgx.ErrNoRows {
		return resourcechanges.Query{}, false, nil
	}
	if err != nil {
		return resourcechanges.Query{}, false, err
	}
	q := resourcechanges.Query{ClusterID: clusterID, Since: firstSeen.Add(-precedingWindow), Limit: 200}
	for _, k := range []*string{objectKey, workloadKey, relatedKey} {
		if ref, ok := objectRefFromKey(k); ok {
			q.Objects = append(q.Objects, ref)
		}
	}
	return q, true, nil
}

// objectRefFromKey parses a "gvk|namespace|name" correlation key
// (internal/gateway's objectCorrelationKey) into an object reference.
func objectRefFromKey(k *string) (resourcechanges.ObjectRef, bool) {
	if k == nil || *k == "" {
		return resourcechanges.ObjectRef{}, false
	}
	parts := strings.SplitN(*k, "|", 3)
	if len(parts) != 3 || parts[2] == "" {
		return resourcechanges.ObjectRef{}, false
	}
	gvk := parts[0]
	kind := gvk[strings.LastIndex(gvk, "/")+1:]
	return resourcechanges.ObjectRef{Kind: kind, Namespace: parts[1], Name: parts[2]}, true
}

func optionalTime(v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, v)
}

// authorizeClusterScoped checks capability on the cluster named in the URL
// and narrows the request's RLS scope to it — handleGetCluster's pattern,
// shared by the cluster-insight routes. Writes the problem and returns false
// when the caller may not proceed.
func (s *Server) authorizeClusterScoped(w http.ResponseWriter, r *http.Request, rc *requestContext, capability, clusterID string) bool {
	ctx := r.Context()
	allowed, err := authz.HasCapabilityForCluster(ctx, rc.Tx, rc.Grants, capability, clusterID)
	if err != nil {
		logger.ErrorContext(ctx, "resolving cluster-scoped capability failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not resolve the scope of your permissions", "")
		return false
	}
	if !allowed {
		s.recordCapabilityDenial(ctx, rc, capability, clientIP(r))
		writeProblem(w, http.StatusForbidden, "https://argus.io/errors/scope-denied", "Missing required capability",
			fmt.Sprintf("this requires capability %q on cluster %s", capability, clusterID))
		return false
	}
	if err := data.SetRequestScope(ctx, rc.Tx, rc.TenantID, []string{clusterID}); err != nil {
		logger.ErrorContext(ctx, "narrowing the request scope to this cluster failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not scope request", "")
		return false
	}
	return true
}
