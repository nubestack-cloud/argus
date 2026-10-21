package api

import (
	"fmt"
	"net/http"
	"time"

	"argus/internal/logging"
)

// This file is BACKLOG.md T2 (candidate 2): "a digest view that rolls up by
// fingerprint instead of listing every occurrence, so an operator can see
// '230 low-severity incidents, but really only 12 distinct underlying
// problems' rather than a wall of rows." Measured 2026-09-04 on this dev DB:
// 230 incidents currently sit in Detected, 48 of them over 7 days old and 15
// over 30 — this endpoint is what lets an operator see how many DISTINCT
// problems that pile actually represents, without changing a single
// incident's state (the lower-risk half of T2's own item text, and the
// piece recommended to ship even without the other two).
//
// Deliberately a SEPARATE endpoint from GET /api/v1/incidents rather than a
// response-shape-changing query parameter on it: the two return genuinely
// different shapes (one row per incident vs. one row per fingerprint), and
// IncidentsPage's existing consumers of the list endpoint's shape must not
// have to guard against a differently-shaped response depending on a query
// string they didn't set. Same capability gate as the list endpoint
// (incident:read) — this is a read-only reshaping of the same data, not a
// new resource with its own access question.
//
// Grouping key is incidents.fingerprint, not (gvk, reason): fingerprint
// already IS "namespace, kind, name, reason" hashed together
// (internal/agent/detector.go's computeFingerprint), so grouping by it is
// both the more precise choice and the one that introduces no second
// notion of "same underlying problem" — exactly the reasoning
// queryIssueClasses (insights.go) already gives for grouping `findings` the
// same way. Unlike queryIssueClasses, this groups `incidents` (not
// `findings`) and is scoped by incidentScopeFilter/?search= exactly like
// handleListIncidents, because this answers "what does the CURRENT open
// pile look like," not "what has this fingerprint done across all
// history."

// incidentDigestGroup is one fingerprint's worth of currently-matching
// incidents, collapsed to a single row.
type incidentDigestGroup struct {
	Fingerprint string `json:"fingerprint"`
	// IncidentCount is how many incidents (in the request's scope) share
	// this fingerprint — the number that makes "230 incidents, 12 problems"
	// legible; ClusterCount is how many of those are on distinct clusters,
	// which is a different and also useful fact (the same problem hitting
	// five clusters at once reads differently than one cluster five times).
	IncidentCount int `json:"incidentCount"`
	ClusterCount  int `json:"clusterCount"`
	// MaxSeverity is the highest severity (severityOrder's total order,
	// reusing rankCaseExpr exactly like incidentSortSpecs' own "severity"
	// sort key) among this group's incidents — the group's own worst case,
	// not an average, matching lld/11-ui-design.md §8's "never blend a
	// severity down."
	MaxSeverity string `json:"maxSeverity"`
	// OldestFirstSeen/NewestLastSeen bound the group's age: the oldest
	// member's first_seen (how long has SOME incident on this fingerprint
	// existed) and the newest member's last_seen (is this still actively
	// recurring, or gone quiet).
	OldestFirstSeen string `json:"oldestFirstSeen"`
	NewestLastSeen  string `json:"newestLastSeen"`
	// SampleIncidentID is one real incident id sharing this fingerprint
	// (the most recently seen), so the UI can link straight into the
	// existing list, pre-filtered to this fingerprint, rather than the
	// digest being a dead end.
	SampleIncidentID string `json:"sampleIncidentId"`
	// ObjectGVK/ObjectNamespace/ObjectName/OpeningReason are read off any one
	// member (MAX, same "every row sharing one fingerprint shares these"
	// reasoning queryIssueClasses' own doc comment already gives) — the
	// object identity and reason, so a digest row reads as "OOMKilled ·
	// payments-api" rather than a bare fingerprint hash, matching
	// incidentIdentity's labeling on the ungrouped list.
	ObjectGVK       *string `json:"objectGvk,omitempty"`
	ObjectNamespace *string `json:"objectNamespace,omitempty"`
	ObjectName      *string `json:"objectName,omitempty"`
	OpeningReason   *string `json:"openingReason,omitempty"`
}

// incidentDigestTopN bounds the response the same way insightsTopN bounds
// Insights' ranked lists — this is a "how does the pile break down" digest,
// not an exhaustive listing (GET /api/v1/incidents already is that). Higher
// than insightsTopN's 10: the whole point is showing "12 distinct problems"
// when there are 12, not truncating to 10 and hiding two of them, but a
// fingerprint count in the thousands (an unrecognisable value for what this
// endpoint claims to summarise) still needs a cap.
const incidentDigestTopN = 200

// handleListIncidentsDigest is GET /api/v1/incidents/digest. Requires
// incident:read — see this file's own header comment for why this is the
// same gate as GET /api/v1/incidents rather than a new one. Accepts the
// identical scope parameters as that endpoint (?clusterId=/?state=/
// ?fleetGroupId=/?workloadGroupId=/?objectGroupId=/?search=) via the same
// incidentScopeFilter, so a caller already looking at (say) ?state=Detected
// can ask for its digest without learning a second filter vocabulary.
//
// Ordered by incident_count DESC (the biggest underlying problem first),
// newest_last_seen DESC as the tiebreak — unlike the list endpoint, there is
// no ?sort= here: a digest of a bounded number of GROUPS earns none of
// P10's keyset-pagination machinery, which exists specifically because the
// UNGROUPED list can be arbitrarily long.
func (s *Server) handleListIncidentsDigest(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	scopeClause, scopeArgs, invalid := incidentScopeFilter(r)
	if invalid != "" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
			"Invalid state filter", invalid)
		return
	}

	// severityRankExpr gives array_agg's ORDER BY the same total order
	// incidentSortSpecs' "severity" sort key uses, so "highest severity in
	// this group" ranks exactly the way sorting the ungrouped list by
	// severity already does.
	severityRankExpr := rankCaseExpr("incidents.severity", severityOrder)

	query := `
		SELECT
		    incidents.fingerprint,
		    count(*) AS incident_count,
		    count(DISTINCT incidents.cluster_id) AS cluster_count,
		    (array_agg(incidents.severity ORDER BY ` + severityRankExpr + ` DESC))[1] AS max_severity,
		    min(incidents.first_seen) AS oldest_first_seen,
		    max(incidents.last_seen) AS newest_last_seen,
		    (array_agg(incidents.id ORDER BY incidents.last_seen DESC))[1] AS sample_incident_id,
		    MAX(incidents.object_key) AS object_key,
		    MAX(incidents.opening_reason) AS opening_reason
		  FROM incidents
		  JOIN clusters ON clusters.id = incidents.cluster_id
		 WHERE incidents.archived_at IS NULL` + scopeClause
	args := append([]any{}, scopeArgs...)

	// ?search=: identical ILIKE fields and escaping as handleListIncidents'
	// own ?search= clause (incidents.go) — duplicated rather than shared
	// because the two queries' column/GROUP BY shape differ enough that
	// factoring out just the WHERE fragment would cost more indirection
	// than the few lines it saves. Any future drift between the two is
	// exactly the kind of thing a reviewer diffing this file against
	// incidents.go's own comment will catch.
	if search := r.URL.Query().Get("search"); search != "" {
		args = append(args, "%"+escapeLikePattern(search)+"%")
		n := len(args)
		query += fmt.Sprintf(` AND (
			incidents.fingerprint ILIKE $%d ESCAPE '\' OR
			incidents.id ILIKE $%d ESCAPE '\' OR
			clusters.display_name ILIKE $%d ESCAPE '\' OR
			incidents.cluster_id ILIKE $%d ESCAPE '\' OR
			incidents.opening_reason ILIKE $%d ESCAPE '\' OR
			incidents.object_key ILIKE $%d ESCAPE '\'
		)`, n, n, n, n, n, n)
	}

	args = append(args, incidentDigestTopN)
	query += fmt.Sprintf(" GROUP BY incidents.fingerprint ORDER BY incident_count DESC, newest_last_seen DESC LIMIT $%d", len(args))

	rows, err := rc.Tx.Query(r.Context(), query, args...)
	if err != nil {
		logger.ErrorContext(r.Context(), "querying the incident digest failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not compute incident digest", "")
		return
	}
	defer rows.Close()

	groups := []incidentDigestGroup{}
	total := 0
	for rows.Next() {
		var g incidentDigestGroup
		var oldestFirstSeen, newestLastSeen time.Time
		var objectKey *string
		if err := rows.Scan(&g.Fingerprint, &g.IncidentCount, &g.ClusterCount, &g.MaxSeverity,
			&oldestFirstSeen, &newestLastSeen, &g.SampleIncidentID, &objectKey, &g.OpeningReason); err != nil {
			logger.ErrorContext(r.Context(), "scanning an incident-digest row failed", logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not compute incident digest", "")
			return
		}
		g.OldestFirstSeen = formatRFC3339(oldestFirstSeen)
		g.NewestLastSeen = formatRFC3339(newestLastSeen)
		if objectKey != nil && *objectKey != "" {
			gvk, namespace, name := splitObjectKey(*objectKey)
			if gvk != "" {
				g.ObjectGVK = &gvk
			}
			if namespace != "" {
				g.ObjectNamespace = &namespace
			}
			if name != "" {
				g.ObjectName = &name
			}
		}
		total += g.IncidentCount
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		logger.ErrorContext(r.Context(), "iterating the incident-digest rows failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not compute incident digest", "")
		return
	}

	resp := map[string]any{
		// totalIncidents is the sum of every returned group's IncidentCount
		// — "230 incidents, 12 problems" needs both halves, and this avoids
		// a second round trip to incidentCountsFor for the first one.
		// Honest only up to incidentDigestTopN groups, which is exactly why
		// "truncated" below is reported alongside it rather than silently.
		"totalIncidents": total,
	}
	if len(groups) == incidentDigestTopN {
		// Matches handleListIncidents' own nextCursor convention: a signal
		// present only when the cap was actually hit, so a caller under it
		// never has to think about truncation at all.
		resp["truncated"] = true
	}
	resp["groups"] = groups

	writeJSON(w, http.StatusOK, resp)
}
