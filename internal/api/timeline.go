// This file implements GET /api/v1/incidents/{id}/timeline
// (lld/11-ui-design.md §4, BACKLOG.md B1) — the chronology of what ARGUS did
// and when for one incident, backed by timeline_events (migration 000005,
// RLS-corrected by migration 000067 — see that migration's header for why
// the correction was necessary before this endpoint could return anything
// under the ordinary ambient request scope).
//
// Gated identically to GET /incidents/{id} (incident:read, server.go) —
// there is no scenario where a principal can read an incident but should not
// see its own history, matching evidence.go's own reasoning for its sibling
// route one line above this one's registration.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"argus/internal/logging"

	"github.com/jackc/pgx/v5"
)

// timelineEventView is one row of GET .../timeline's response —
// TimelineEvent per lld/11-ui-design.md §4/lld/05-data-model.md §3.5.
// Detail is rendered as a raw object rather than re-typed per event: the UI
// (a follow-up task, deliberately not built here — see this file's header)
// reads it generically, and a closed Go type per event.Type would have to be
// kept in lockstep with internal/timeline's own const set for no benefit
// this endpoint's one consumer (a chronological list) needs.
type timelineEventView struct {
	ID         string          `json:"id"`
	EventType  string          `json:"eventType"`
	Summary    string          `json:"summary"`
	Detail     json.RawMessage `json:"detail,omitempty"`
	OccurredAt string          `json:"occurredAt"`
}

// handleGetIncidentTimeline is GET /api/v1/incidents/{id}/timeline. Requires
// incident:read (server.go).
func (s *Server) handleGetIncidentTimeline(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	incidentID := r.PathValue("id")
	ctx := r.Context()

	// Existence (and RLS visibility, which is indistinguishable from
	// non-existence to the caller and equally a 404) checked explicitly
	// first, exactly like handleGetIncident/handleGetEvidence — an incident
	// with zero timeline rows (a pre-B1 incident that never had a Finding
	// re-processed, or a genuinely fresh one whose detection write is still
	// in flight) must read as "no history yet", not as "incident not
	// found", and only a separate existence check can tell those apart.
	var exists bool
	if err := rc.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM incidents WHERE id = $1)`, incidentID).Scan(&exists); err != nil {
		logger.ErrorContext(ctx, "checking that the incident exists failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up incident", "")
		return
	}
	if !exists {
		writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Incident not found", "")
		return
	}

	events, err := listTimelineEvents(ctx, rc.Tx, incidentID)
	if err != nil {
		logger.ErrorContext(ctx, "querying the incident's timeline failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up incident timeline", "")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

// listTimelineEvents reads every timeline_events row for one incident,
// oldest first — lld/11-ui-design.md §4's contract renders them in order
// with durations computed CLIENT-SIDE from adjacent timestamps, so the
// server's only ordering obligation is chronological, ascending order.
func listTimelineEvents(ctx context.Context, tx pgx.Tx, incidentID string) ([]timelineEventView, error) {
	rows, err := tx.Query(ctx,
		`SELECT id, event_type, payload, occurred_at
		   FROM timeline_events
		  WHERE incident_id = $1
		  ORDER BY occurred_at ASC, id ASC`, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := []timelineEventView{}
	for rows.Next() {
		var (
			id, eventType string
			payload       []byte
			occurredAt    time.Time
		)
		if err := rows.Scan(&id, &eventType, &payload, &occurredAt); err != nil {
			return nil, err
		}

		ev := timelineEventView{
			ID:         id,
			EventType:  eventType,
			OccurredAt: formatRFC3339(occurredAt),
		}

		// summary is pulled out of the payload object (internal/timeline's
		// own convention — see that package's Event.Summary doc comment for
		// why it is a jsonb key rather than a separate column) and the rest
		// of the object is passed through verbatim as Detail, so a client
		// gets the human-readable line as its own field without losing any
		// of the structured detail underneath it.
		var decoded map[string]any
		if err := json.Unmarshal(payload, &decoded); err == nil {
			if s, ok := decoded["summary"].(string); ok {
				ev.Summary = s
			}
		}
		ev.Detail = payload

		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}
