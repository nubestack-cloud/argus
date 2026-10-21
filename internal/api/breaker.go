package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/logging"
	"argus/internal/orchestrator"
	"argus/internal/settings"

	"github.com/jackc/pgx/v5"
)

// The circuit breaker's operator surface (BACKLOG R2's second half).
//
// Why the breaker needs a surface at all, when the blast-radius cap does not: a
// cap refuses and the next window lets the work through, so nothing accumulates
// that a person has to clear. A breaker STAYS tripped by design, which means
// unattended execution is off until somebody acts — and a stopped automatic
// process that cannot be seen or restarted from the UI is worse than no automatic
// process, because the operator's mental model says it is still running.
//
// Gated on `org:settings:write`, the same capability as the autonomy policy and
// the automation windows: whoever decides what may be auto-approved, and when, is
// who should decide that it may resume.

// breakerTrip is one trip as the UI sees it.
type breakerTrip struct {
	ID           string     `json:"id"`
	ClusterID    string     `json:"clusterId,omitempty"`
	ClusterName  string     `json:"clusterName,omitempty"`
	FleetWide    bool       `json:"fleetWide"`
	TrippedAt    time.Time  `json:"trippedAt"`
	Reason       string     `json:"reason"`
	BadOutcomes  int        `json:"badOutcomes"`
	Threshold    int        `json:"threshold"`
	ResetAt      *time.Time `json:"resetAt,omitempty"`
	ResetByEmail string     `json:"resetByEmail,omitempty"`
	ResetNote    string     `json:"resetNote,omitempty"`
}

// handleGetBreaker is GET /api/v1/admin/circuit-breaker.
//
// Returns the OPEN trips, the resolved policy, and a bounded slice of history.
// History is included because the first question an operator asks after a trip is
// whether this keeps happening, and answering it from the audit log would mean
// reading the audit log.
func (s *Server) handleGetBreaker(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	resp, err := buildBreakerResponse(r.Context(), rc)
	if err != nil {
		logger.ErrorContext(r.Context(), "reading the breaker state failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not read the breaker state", "")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// buildBreakerResponse reads the resolved policy plus the open/history trip
// lists — the shared shape both handleGetBreaker and handlePutBreaker return,
// so a PUT's response reflects the same complete picture a follow-up GET
// would, the same "build the response from what was just written" pattern
// handlePutSettings already uses for the general settings endpoint.
func buildBreakerResponse(ctx context.Context, rc *requestContext) (map[string]any, error) {
	cfg, err := settings.Resolve(ctx, rc.Tx)
	if err != nil {
		return nil, fmt.Errorf("resolve settings: %w", err)
	}
	limits := orchestrator.ResolveBreakerLimits(
		cfg.AutonomyBreakerEnabled, cfg.AutonomyBreakerPerCluster,
		cfg.AutonomyBreakerFleetWide, cfg.AutonomyBreakerWindowSeconds)

	trips, err := loadBreakerTrips(ctx, rc, breakerHistoryLimit)
	if err != nil {
		return nil, fmt.Errorf("load trips: %w", err)
	}

	open := make([]breakerTrip, 0, len(trips))
	history := make([]breakerTrip, 0, len(trips))
	for _, t := range trips {
		if t.ResetAt == nil {
			open = append(open, t)
		} else {
			history = append(history, t)
		}
	}

	return map[string]any{
		"enabled":       limits.Enabled,
		"maxPerCluster": limits.MaxPerCluster,
		"maxFleetWide":  limits.MaxFleetWide,
		"windowSeconds": int(limits.Window.Seconds()),
		"open":          open,
		"history":       history,
	}, nil
}

// putCircuitBreakerRequest is PUT /api/v1/admin/circuit-breaker's request
// body — see internal/settings.BreakerUpdate's doc comment for the full
// per-field leave-unchanged contract this mirrors exactly: every field here
// is a pointer, and nil (the key absent from the JSON body, or present as
// literal null — this handler does not distinguish the two, matching
// putLLMSettingsRequest.APIKey/putNotifySettingsRequest.WebhookURL's
// identical convention) means "leave the stored value unchanged." A non-nil
// value sets that field explicitly, validated by validateCircuitBreakerRequest
// below before it ever reaches internal/settings.
//
// This is deliberately NOT nested under a "circuitBreaker" (or similar)
// wrapper key the way putSettingsRequest nests "autonomy"/"detection"/etc:
// this is this endpoint's ENTIRE body, so there is no outer "was the section
// present at all" question to ask — only "was this one field present."
type putCircuitBreakerRequest struct {
	Enabled       *bool `json:"enabled"`
	MaxPerCluster *int  `json:"maxPerCluster"`
	MaxFleetWide  *int  `json:"maxFleetWide"`
	WindowSeconds *int  `json:"windowSeconds"`
}

// validateCircuitBreakerRequest rejects a non-positive threshold outright,
// matching validateAutonomySettingsRequest's identical rule for the sibling
// maxUnattendedPerCluster/maxUnattendedFleetWide/unattendedWindowSeconds
// fields and for the same reason: orchestrator.ResolveBreakerLimits treats
// any value <= 0 as "unconfigured, fall back to the default" (breaker.go's
// own doc comment), so silently accepting a zero or negative threshold here
// would let an operator type 0 meaning "trip on the very first bad outcome"
// and get DefaultBreakerLimits' 2/4 instead, with nothing to tell them so.
//
// The per-cluster-vs-fleet-wide unreachability check is deliberately
// narrower than validateAutonomySettingsRequest's version: that one resolves
// BOTH fields against their hardcoded defaults before comparing, which is
// correct there because AutonomyUpdate's fields are always taken exactly as
// given once the "autonomy" section is present — the resolved value IS the
// real post-update state. Here, an omitted field means "leave whatever is
// currently stored," an unknown value at validation time, so resolving it
// against the default instead would compare against a value the update will
// not actually produce. Only the case both fields being set IN THIS REQUEST
// is checked, since that is the only case decidable without reading the
// database.
func validateCircuitBreakerRequest(req putCircuitBreakerRequest) error {
	for _, limit := range []struct {
		field string
		value *int
	}{
		{"maxPerCluster", req.MaxPerCluster},
		{"maxFleetWide", req.MaxFleetWide},
		{"windowSeconds", req.WindowSeconds},
	} {
		if limit.value != nil && *limit.value <= 0 {
			return fmt.Errorf("invalid %s: %d is not a threshold. Omit this field to leave it unchanged, "+
				"or set enabled to false to turn the breaker off entirely — a zero or negative value here would be "+
				"read as \"unconfigured\" and silently fall back to the default", limit.field, *limit.value)
		}
	}
	if req.MaxPerCluster != nil && req.MaxFleetWide != nil && *req.MaxPerCluster > *req.MaxFleetWide {
		return fmt.Errorf("invalid circuit breaker thresholds: the per-cluster limit (%d) is above the fleet-wide limit (%d), "+
			"which can never take effect — a single cluster's bad outcomes all count towards the fleet total, so the "+
			"fleet threshold would always be reached first", *req.MaxPerCluster, *req.MaxFleetWide)
	}
	return nil
}

// handlePutBreaker is PUT /api/v1/admin/circuit-breaker — BACKLOG.md R5, the
// write half of the breaker's threshold configuration GET has always been
// able to read but nothing could ever set (org:settings:write could change
// the blast-radius caps sitting right next to it, but not this). Requires
// org:settings:write, the same capability the GET and reset routes above
// already use — see this file's doc comment for why.
//
// Applies settings.Update inside rc.Tx, atomic with the audit event below,
// then re-reads the resolved state (including open/history trips) from that
// same still-open transaction so the response reflects this request's own
// write, matching handlePutSettings' identical pattern.
func (s *Server) handlePutBreaker(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	var req putCircuitBreakerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}
	if err := validateCircuitBreakerRequest(req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", err.Error(), "")
		return
	}

	ctx := r.Context()
	if err := settings.Update(ctx, rc.Tx, settings.UpdateInput{
		Breaker: &settings.BreakerUpdate{
			Enabled:       req.Enabled,
			MaxPerCluster: req.MaxPerCluster,
			MaxFleetWide:  req.MaxFleetWide,
			WindowSeconds: req.WindowSeconds,
		},
	}); err != nil {
		logger.ErrorContext(ctx, "updating the circuit-breaker policy failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not update the breaker policy", "")
		return
	}

	// Details records WHICH fields changed, never secret (there is nothing
	// secret in this section, but matching handlePutSettings' own convention
	// of never even hinting at raw values keeps the audit log's shape uniform
	// across every settings-writing route).
	capability := authz.CapOrgSettingsWrite
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID: rc.TenantID, ActorID: &rc.UserID, ActorAuthMethod: "jwt",
		SourceIP: clientIP(r), Capability: &capability, Outcome: audit.OutcomeSuccess,
		Details: map[string]any{
			"action":               "update_circuit_breaker_policy",
			"enabledChanged":       req.Enabled != nil,
			"maxPerClusterChanged": req.MaxPerCluster != nil,
			"maxFleetWideChanged":  req.MaxFleetWide != nil,
			"windowSecondsChanged": req.WindowSeconds != nil,
		},
	}); err != nil {
		logger.ErrorContext(ctx, "recording the circuit-breaker policy change in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record this change", "")
		return
	}

	resp, err := buildBreakerResponse(ctx, rc)
	if err != nil {
		logger.ErrorContext(ctx, "reading back the updated breaker state failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not read back the updated breaker state", "")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// breakerHistoryLimit bounds the reset trips returned. Enough to answer "is this
// recurring" without turning this endpoint into an unbounded read as an
// installation ages.
const breakerHistoryLimit = 20

// handleResetBreaker is POST /api/v1/admin/circuit-breaker/{id}/reset.
//
// Addressed by trip id rather than by scope, deliberately: resetting "the
// breaker" when a cluster trip and a fleet-wide trip are both open would be
// ambiguous, and an operator who has read one reason has not necessarily read the
// other.
func (s *Server) handleResetBreaker(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	id := r.PathValue("id")

	var body struct {
		Note string `json:"note"`
	}
	// An empty body is fine — the note is optional. Only malformed JSON is an
	// error.
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err == nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "Could not read the request", err.Error())
			return
		}
	}

	var note *string
	if body.Note != "" {
		note = &body.Note
	}

	// The WHERE clause requires the trip to still be open, so two operators
	// clicking Reset at the same time cannot both record a reset — the second gets
	// a 404 and, correctly, is told it is already closed. This is also why the
	// reset is not an idempotent UPDATE with no guard.
	var reason string
	var clusterID *string
	if err := rc.Tx.QueryRow(ctx,
		`UPDATE circuit_breaker_trips
		    SET reset_at = now(), reset_by = $2, reset_note = $3
		  WHERE id = $1 AND reset_at IS NULL
		  RETURNING reason, cluster_id`, id, rc.UserID, note).Scan(&reason, &clusterID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found",
				"No open breaker trip with that id",
				"It may already have been reset, by you in another tab or by someone else.")
			return
		}
		logger.ErrorContext(ctx, "resetting a circuit-breaker trip failed", slog.String("trip_id", id), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not reset the breaker", "")
		return
	}

	scope := "fleet-wide"
	if clusterID != nil {
		scope = *clusterID
	}
	capability := authz.CapOrgSettingsWrite
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID: rc.TenantID, ActorID: &rc.UserID, ActorAuthMethod: "jwt",
		SourceIP: clientIP(r), Capability: &capability, Outcome: audit.OutcomeSuccess,
		Details: map[string]any{
			"action": "reset_circuit_breaker", "tripId": id, "scope": scope,
			"tripReason": reason, "note": body.Note,
		},
	}); err != nil {
		logger.ErrorContext(ctx, "recording a circuit-breaker reset in the audit log failed", slog.String("trip_id", id), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record this change", "")
		return
	}

	// Logged as well as audited: a breaker resuming automatic execution is
	// something whoever is reading hub logs during an incident wants to see
	// without going to the audit page.
	logger.InfoContext(ctx, "circuit breaker trip reset; unattended execution may resume",
		slog.String("trip_id", id), slog.String("scope", scope))

	writeJSON(w, http.StatusOK, map[string]any{"reset": true})
}

// loadBreakerTrips reads open trips first, then the most recent reset ones, and
// joins the cluster's display name so the UI never has to render a raw id.
func loadBreakerTrips(ctx context.Context, rc *requestContext, historyLimit int) ([]breakerTrip, error) {
	rows, err := rc.Tx.Query(ctx,
		`SELECT t.id, t.cluster_id, COALESCE(c.display_name, ''), t.tripped_at, t.reason,
		        t.bad_outcomes, t.threshold, t.reset_at, COALESCE(u.email, ''), COALESCE(t.reset_note, '')
		   FROM circuit_breaker_trips t
		   LEFT JOIN clusters c ON c.id = t.cluster_id
		   LEFT JOIN users u ON u.id = t.reset_by
		  -- Open trips first regardless of age: an open trip is the actionable row
		  -- and must never be pushed off the end by newer resolved history.
		  ORDER BY (t.reset_at IS NULL) DESC, t.tripped_at DESC
		  LIMIT $1`, historyLimit+maxOpenBreakerTrips)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []breakerTrip
	for rows.Next() {
		var t breakerTrip
		var clusterID *string
		if err := rows.Scan(&t.ID, &clusterID, &t.ClusterName, &t.TrippedAt, &t.Reason,
			&t.BadOutcomes, &t.Threshold, &t.ResetAt, &t.ResetByEmail, &t.ResetNote); err != nil {
			return nil, err
		}
		if clusterID != nil {
			t.ClusterID = *clusterID
		} else {
			t.FleetWide = true
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// maxOpenBreakerTrips is the most open trips that can exist at once — one
// fleet-wide plus one per cluster, bounded generously so the LIMIT above cannot
// hide an open trip behind history.
const maxOpenBreakerTrips = 200
