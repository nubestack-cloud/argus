package api

import (
	"net/http"
	"strings"
	"time"

	"argus/internal/authz"
	"argus/internal/clustertimeline"
	"argus/internal/logging"
)

// GET /api/v1/clusters/{id}/timeline?since&until&namespace&types&onlyIncidents
// — PROJECT.md AD1: one cluster's object changes, detector findings and
// incident openings/closings on one time axis, one row per object grouped
// under its owning workload (internal/clustertimeline).
//
// cluster:read gates the route, as it gates the change history it is built
// on. Findings and incidents are additionally read only under incident:read
// on this cluster — the capability GET /findings and GET /incidents already
// require for exactly those rows. A caller without it gets the changes and a
// `restricted` entry naming each left-out source and the capability, never
// an empty list that would read as "nothing happened".
//
// Parameters (all optional):
//   - since/until — RFC 3339. until defaults to now, since to 24 hours before
//     until; the window may not exceed clustertimeline.MaxWindow.
//   - namespace — one namespace; cluster-scoped objects drop out.
//   - types — comma-separated subset of changes,findings,incidents.
//   - onlyIncidents=true — only rows carrying an incident.
//
// The filters run in SQL before any cap, so a filtered view is the true
// answer for that filter, not a slice of the unfiltered first page.
func (s *Server) handleClusterTimeline(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	clusterID := r.PathValue("id")
	if !s.authorizeClusterScoped(w, r, rc, authz.CapClusterRead, clusterID) {
		return
	}
	params := r.URL.Query()

	until := time.Now().UTC()
	if v := params.Get("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/validation", "Invalid until", "until must be an RFC 3339 timestamp")
			return
		}
		until = t
	}
	since := until.Add(-24 * time.Hour)
	if v := params.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/validation", "Invalid since", "since must be an RFC 3339 timestamp")
			return
		}
		since = t
	}
	if !since.Before(until) {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/validation", "Invalid window", "since must be earlier than until")
		return
	}
	if until.Sub(since) > clustertimeline.MaxWindow {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/validation", "Window too long", "the timeline covers at most 7 days; narrow since/until")
		return
	}

	sources := map[string]bool{
		clustertimeline.SourceChanges: true, clustertimeline.SourceFindings: true, clustertimeline.SourceIncidents: true,
	}
	if v := params.Get("types"); v != "" {
		sources = map[string]bool{}
		for _, t := range strings.Split(v, ",") {
			t = strings.TrimSpace(t)
			switch t {
			case clustertimeline.SourceChanges, clustertimeline.SourceFindings, clustertimeline.SourceIncidents:
				sources[t] = true
			default:
				writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/validation", "Invalid types",
					"types must be a comma-separated subset of: changes, findings, incidents")
				return
			}
		}
	}
	onlyIncidents := false
	switch params.Get("onlyIncidents") {
	case "", "false":
	case "true":
		onlyIncidents = true
	default:
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/validation", "Invalid onlyIncidents", "onlyIncidents must be true or false")
		return
	}

	var restricted []clustertimeline.Restriction
	canIncidents, err := authz.HasCapabilityForCluster(ctx, rc.Tx, rc.Grants, authz.CapIncidentRead, clusterID)
	if err != nil {
		logger.ErrorContext(ctx, "resolving incident:read for the timeline failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not resolve the scope of your permissions", "")
		return
	}
	if !canIncidents {
		for _, src := range []string{clustertimeline.SourceFindings, clustertimeline.SourceIncidents} {
			if sources[src] {
				restricted = append(restricted, clustertimeline.Restriction{Source: src, Capability: authz.CapIncidentRead})
				delete(sources, src)
			}
		}
	}

	resp, err := clustertimeline.Build(ctx, rc.Tx, clustertimeline.Query{
		ClusterID: clusterID, Since: since.UTC(), Until: until.UTC(), Namespace: params.Get("namespace"),
		Sources: sources, OnlyIncidents: onlyIncidents, Restricted: restricted,
	})
	if err != nil {
		logger.ErrorContext(ctx, "building the cluster timeline failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not build the timeline", "")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
