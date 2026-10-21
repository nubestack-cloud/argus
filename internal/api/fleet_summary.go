package api

import (
	"encoding/json"
	"net/http"
	"time"

	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/fleetchecks"
	"argus/internal/logging"
)

// GET /api/v1/fleet/summary — what the fleet Overview draws from, in one read
// rather than one detail request and four live agent calls per cluster.
//
// Per visible (non-archived) cluster:
//   - facts: the digest of its last facts report the Overview uses (version,
//     nodes, detector health, NetworkPolicy coverage), or null before the
//     agent's first inventory sync;
//   - checks: the stored fleet checks (internal/fleetchecks), each with when
//     it was last read and the latest failure — present only when the viewer
//     holds cluster:inspect on that cluster, which is what reading the same
//     data live through the inspect route requires. checksReadable says
//     which, so a viewer without it is told so rather than shown an empty
//     cluster.
//
// Which clusters appear is cluster:read per cluster, resolved from the
// viewer's grants (see the handler).

type fleetClusterSummary struct {
	ClusterID      string                          `json:"clusterId"`
	Facts          json.RawMessage                 `json:"facts"`
	FactsUpdatedAt *time.Time                      `json:"factsUpdatedAt"`
	ChecksReadable bool                            `json:"checksReadable"`
	Checks         map[string]fleetchecks.Snapshot `json:"checks"`
}

type fleetSummaryResponse struct {
	// IntervalSeconds is how often the hub re-reads each connected cluster,
	// so the UI can say how old "current" is allowed to be.
	IntervalSeconds int                   `json:"intervalSeconds"`
	Clusters        []fleetClusterSummary `json:"clusters"`
}

// fleetFactsDigestSQL keeps the facts fields the Overview reads. Built in SQL
// so the large parts of a facts report (the object-cache and insight
// summaries) never leave the database for a page that does not draw them.
const fleetFactsDigestSQL = `SELECT c.id,
	CASE WHEN f.facts IS NULL THEN NULL ELSE jsonb_strip_nulls(jsonb_build_object(
		'kubernetesVersion', f.facts->'kubernetesVersion',
		'nodeCount', f.facts->'nodeCount',
		'reachable', f.facts->'reachable',
		'nodes', COALESCE(f.facts->'nodes', '[]'::jsonb),
		'detectors', f.facts->'detectors',
		'summary', jsonb_build_object('networkPolicyCoverage', f.facts->'summary'->'networkPolicyCoverage')
	)) END,
	f.updated_at
	FROM clusters c LEFT JOIN cluster_facts f ON f.cluster_id = c.id
	WHERE c.id = ANY($1)
	ORDER BY c.id`

func (s *Server) fleetSummaryFailed(w http.ResponseWriter, r *http.Request, what string, err error) {
	logger.ErrorContext(r.Context(), what, logging.Err(err))
	writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not read the fleet summary", "")
}

func (s *Server) handleFleetSummary(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	out := fleetSummaryResponse{IntervalSeconds: int(fleetchecks.DefaultInterval / time.Second), Clusters: []fleetClusterSummary{}}

	// The clusters this viewer may read. cluster_facts has only a
	// cluster-keyed policy, under which the request's unnarrowed scope reads
	// as zero rows (handleGetCluster's comment), so the scope is narrowed to
	// exactly these — each authorised from the viewer's grants first, never
	// from anything the caller sent.
	rows, err := rc.Tx.Query(ctx, `SELECT id FROM clusters WHERE archived_at IS NULL ORDER BY id`)
	if err != nil {
		s.fleetSummaryFailed(w, r, "listing clusters for the fleet summary failed", err)
		return
	}
	var all []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			s.fleetSummaryFailed(w, r, "listing clusters for the fleet summary failed", err)
			return
		}
		all = append(all, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		s.fleetSummaryFailed(w, r, "listing clusters for the fleet summary failed", err)
		return
	}
	readable := make([]string, 0, len(all))
	for _, id := range all {
		ok, err := authz.HasCapabilityForCluster(ctx, rc.Tx, rc.Grants, authz.CapClusterRead, id)
		if err != nil {
			s.fleetSummaryFailed(w, r, "resolving cluster-scoped capability failed", err)
			return
		}
		if ok {
			readable = append(readable, id)
		}
	}
	// An empty list would mean "every cluster" to the restrictive policies
	// on fleet_check_snapshots, so nothing is read under it.
	if len(readable) == 0 {
		writeJSON(w, http.StatusOK, out)
		return
	}
	if err := data.SetRequestScope(ctx, rc.Tx, rc.TenantID, readable); err != nil {
		s.fleetSummaryFailed(w, r, "narrowing the request scope for the fleet summary failed", err)
		return
	}

	rows, err = rc.Tx.Query(ctx, fleetFactsDigestSQL, readable)
	if err != nil {
		s.fleetSummaryFailed(w, r, "reading the fleet facts digest failed", err)
		return
	}
	for rows.Next() {
		var c fleetClusterSummary
		if err := rows.Scan(&c.ClusterID, &c.Facts, &c.FactsUpdatedAt); err != nil {
			rows.Close()
			s.fleetSummaryFailed(w, r, "reading the fleet facts digest failed", err)
			return
		}
		out.Clusters = append(out.Clusters, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		s.fleetSummaryFailed(w, r, "reading the fleet facts digest failed", err)
		return
	}

	snaps, err := fleetchecks.ReadAll(ctx, rc.Tx)
	if err != nil {
		s.fleetSummaryFailed(w, r, "reading the fleet checks failed", err)
		return
	}
	for i := range out.Clusters {
		c := &out.Clusters[i]
		c.Checks = map[string]fleetchecks.Snapshot{}
		ok, err := authz.HasCapabilityForCluster(ctx, rc.Tx, rc.Grants, authz.CapClusterInspect, c.ClusterID)
		if err != nil {
			s.fleetSummaryFailed(w, r, "resolving cluster-scoped capability failed", err)
			return
		}
		c.ChecksReadable = ok
		if ok {
			for name, snap := range snaps[c.ClusterID] {
				c.Checks[name] = snap
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}
