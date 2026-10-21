package api

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"argus/internal/logging"
)

// GET /api/v1/incidents/overview — the fleet Overview's incident figures,
// aggregated over the WHOLE matching set rather than counted from a fetched page.
//
// The Overview used to bucket the incident list client-side for its per-day
// chart and severity ring. That list is capped (defaultIncidentPageLimit) and
// ordered by last_seen, so on a busy fleet the older days undercounted and the
// page had to say so. Everything here is one GROUP BY away in Postgres, so the
// page draws exact figures instead of caveated ones.
//
// Three shapes, all scoped by incidentScopeFilter exactly like the list and
// counts queries (so ?clusterId= narrows them the same way):
//
//   - byState: open incidents per state, for the lifecycle stage bar.
//   - byCluster: open incidents per cluster by severity, plus how many of them
//     need a person and how many are fixes that did not hold.
//   - daily: per UTC day over the last ?days= (7–90, default 14) — incidents
//     opened by severity, incidents closed, and how many were open at the end
//     of the day.
//
// openAtEnd is reconstructed from first_seen and resolved_at, and resolved_at
// is stamped on every close (orchestrator.SetState via IsClosed) and is not
// cleared on reopen. Two consequences, both deliberate: an incident that
// closed and later reopened counts as open from its first_seen onwards (the
// closed gap is not recorded anywhere to subtract), and a closed row with no
// resolved_at (older than migration 000065) is treated as never open, rather
// than as open forever. The last day's value equals the counts query's
// `open` for the same scope.
type incidentOverviewDay struct {
	Date      string              `json:"date"`
	Opened    incidentSeverityMix `json:"opened"`
	Resolved  int                 `json:"resolved"`
	OpenAtEnd int                 `json:"openAtEnd"`
}

type incidentSeverityMix struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type incidentStateCount struct {
	State string `json:"state"`
	Count int    `json:"count"`
}

type incidentClusterOverview struct {
	ClusterID string `json:"clusterId"`
	incidentSeverityMix
	Open           int `json:"open"`
	RequiresAction int `json:"requiresAction"`
	FixNotHeld     int `json:"fixNotHeld"`
}

const (
	incidentOverviewDefaultDays = 14
	incidentOverviewMinDays     = 7
	incidentOverviewMaxDays     = 90
)

// openIncidentsFrom is the FROM/WHERE every open-set aggregate here shares.
var openIncidentsFrom = `
	  FROM incidents
	  JOIN clusters ON clusters.id = incidents.cluster_id
	 WHERE incidents.archived_at IS NULL
	   AND incidents.state NOT IN ` + closedStateClause

func (s *Server) handleIncidentOverview(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	scopeClause, scopeArgs, invalid := incidentScopeFilter(r)
	if invalid != "" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "Invalid filter", invalid)
		return
	}
	days := incidentOverviewDefaultDays
	if raw := r.URL.Query().Get("days"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < incidentOverviewMinDays || n > incidentOverviewMaxDays {
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "Invalid days",
				fmt.Sprintf("days must be a whole number from %d to %d", incidentOverviewMinDays, incidentOverviewMaxDays))
			return
		}
		days = n
	}
	ctx := r.Context()
	fail := func(what string, err error) {
		logger.ErrorContext(ctx, "computing the incident overview failed", "part", what, logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not compute the incident overview", "")
	}

	byState := []incidentStateCount{}
	rows, err := rc.Tx.Query(ctx, `SELECT incidents.state, count(*)`+openIncidentsFrom+scopeClause+
		` GROUP BY incidents.state ORDER BY incidents.state`, scopeArgs...)
	if err != nil {
		fail("byState", err)
		return
	}
	for rows.Next() {
		var c incidentStateCount
		if err := rows.Scan(&c.State, &c.Count); err != nil {
			rows.Close()
			fail("byState scan", err)
			return
		}
		byState = append(byState, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		fail("byState rows", err)
		return
	}

	byCluster := []incidentClusterOverview{}
	rows, err = rc.Tx.Query(ctx, `
		SELECT incidents.cluster_id,
		       count(*) FILTER (WHERE incidents.severity = 'critical'),
		       count(*) FILTER (WHERE incidents.severity = 'high'),
		       count(*) FILTER (WHERE incidents.severity = 'medium'),
		       count(*) FILTER (WHERE incidents.severity = 'low'),
		       count(*),
		       count(*) FILTER (WHERE incidents.state IN `+requiresActionStateClause+`),
		       count(*) FILTER (WHERE incidents.state IN `+fixNotHeldStateClause+`)`+
		openIncidentsFrom+scopeClause+` GROUP BY incidents.cluster_id ORDER BY incidents.cluster_id`, scopeArgs...)
	if err != nil {
		fail("byCluster", err)
		return
	}
	for rows.Next() {
		var c incidentClusterOverview
		if err := rows.Scan(&c.ClusterID, &c.Critical, &c.High, &c.Medium, &c.Low, &c.Open, &c.RequiresAction, &c.FixNotHeld); err != nil {
			rows.Close()
			fail("byCluster scan", err)
			return
		}
		byCluster = append(byCluster, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		fail("byCluster rows", err)
		return
	}

	// One row per UTC day, every day present even when nothing happened on it.
	// day_end is the next midnight as a timestamptz, the instant "open at the end
	// of the day" is measured at.
	args := append([]any{}, scopeArgs...)
	args = append(args, days)
	daysArg := fmt.Sprintf("$%d", len(args))
	rows, err = rc.Tx.Query(ctx, `
		WITH d AS (
		    SELECT day::date AS day,
		           ((day::date + 1)::timestamp AT TIME ZONE 'UTC') AS day_end
		      FROM generate_series((now() AT TIME ZONE 'UTC')::date - (`+daysArg+`::int - 1),
		                           (now() AT TIME ZONE 'UTC')::date, interval '1 day') AS day
		), i AS (
		    SELECT incidents.severity, incidents.state, incidents.first_seen, incidents.resolved_at
		      FROM incidents
		      JOIN clusters ON clusters.id = incidents.cluster_id
		     WHERE incidents.archived_at IS NULL`+scopeClause+`
		)
		SELECT d.day,
		       count(i.first_seen) FILTER (WHERE (i.first_seen AT TIME ZONE 'UTC')::date = d.day AND i.severity = 'critical'),
		       count(i.first_seen) FILTER (WHERE (i.first_seen AT TIME ZONE 'UTC')::date = d.day AND i.severity = 'high'),
		       count(i.first_seen) FILTER (WHERE (i.first_seen AT TIME ZONE 'UTC')::date = d.day AND i.severity = 'medium'),
		       count(i.first_seen) FILTER (WHERE (i.first_seen AT TIME ZONE 'UTC')::date = d.day AND i.severity = 'low'),
		       count(i.first_seen) FILTER (WHERE (i.resolved_at AT TIME ZONE 'UTC')::date = d.day AND i.state IN `+closedStateClause+`),
		       count(i.first_seen) FILTER (WHERE i.first_seen < d.day_end
		                                     AND NOT (i.state IN `+closedStateClause+` AND (i.resolved_at IS NULL OR i.resolved_at < d.day_end)))
		  FROM d LEFT JOIN i ON true
		 GROUP BY d.day
		 ORDER BY d.day`, args...)
	if err != nil {
		fail("daily", err)
		return
	}
	daily := make([]incidentOverviewDay, 0, days)
	for rows.Next() {
		var day time.Time
		var d incidentOverviewDay
		if err := rows.Scan(&day, &d.Opened.Critical, &d.Opened.High, &d.Opened.Medium, &d.Opened.Low, &d.Resolved, &d.OpenAtEnd); err != nil {
			rows.Close()
			fail("daily scan", err)
			return
		}
		d.Date = day.Format("2006-01-02")
		daily = append(daily, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		fail("daily rows", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"days":        days,
		"byState":     byState,
		"byCluster":   byCluster,
		"daily":       daily,
		"generatedAt": formatRFC3339(time.Now()),
	})
}
