package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/domain"
	"argus/internal/logging"
	"argus/internal/orchestrator"

	"github.com/jackc/pgx/v5"
)

// Maintenance and freeze windows (BACKLOG.md R2, DESIGN.md §7.2/§9.4/§10.5).
//
// What each kind means, and why the two do not combine symmetrically, is in
// orchestrator.CheckWindows — the decision belongs with the evaluation, not with
// the CRUD.
//
// Gated on `org:settings:write`, the same capability as the autonomy policy these
// windows constrain: a principal who can decide what may be auto-approved is
// exactly the one who should be able to decide when. Deliberately NOT a new
// capability — DESIGN.md §18.4 wants freeze windows locally owned rather than
// hub-owned (see migration 000051's note), and inventing a hub-side capability
// for them would imply a separation this build does not actually have.

type automationWindowView struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Schedule string `json:"schedule"`
	// DurationSeconds on the wire; the UI renders hours. Seconds because every
	// other duration setting in this API is in seconds, and one unit throughout
	// beats a friendlier unit per field.
	DurationSeconds int    `json:"durationSeconds"`
	Timezone        string `json:"timezone"`
	Reason          string `json:"reason,omitempty"`
	CreatedAt       string `json:"createdAt"`
	// OpenNow is evaluated at read time so the UI can show which window is in
	// force right now without reimplementing cron matching in TypeScript. The
	// alternative — shipping the schedule and letting the browser decide — would
	// mean two implementations of the one rule that decides whether automation
	// runs, and they would disagree.
	OpenNow bool `json:"openNow"`
	// InvalidReason is set when a stored window cannot be evaluated. Surfaced
	// rather than hidden: a malformed freeze is treated as IN FORCE, so an
	// operator seeing "nothing is running" needs to be able to find out why.
	InvalidReason string `json:"invalidReason,omitempty"`
	// Upcoming is when this window is open over the next windowUpcomingHorizon,
	// earliest first, from orchestrator.Window.Openings — the same matching rule
	// as OpenNow, so the Overview's runway cannot disagree with the sweeper.
	// Empty for a window that cannot be evaluated (InvalidReason says why).
	Upcoming []windowOpeningView `json:"upcoming"`
}

type windowOpeningView struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

// The Overview draws 90 days; 40 intervals covers a weekly window with room to
// spare, and caps an every-hour schedule at a size worth sending.
const (
	windowUpcomingHorizon = 90 * 24 * time.Hour
	windowUpcomingMax     = 40
)

type putAutomationWindowRequest struct {
	Kind            string `json:"kind"`
	Schedule        string `json:"schedule"`
	DurationSeconds int    `json:"durationSeconds"`
	Timezone        string `json:"timezone"`
	Reason          string `json:"reason"`
}

// handleListAutomationWindows is GET /api/v1/admin/automation-windows.
func (s *Server) handleListAutomationWindows(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	windows, err := loadAutomationWindows(r.Context(), rc.Tx)
	if err != nil {
		logger.ErrorContext(r.Context(), "listing the automation windows failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list automation windows", "")
		return
	}
	now := time.Now()
	out := make([]automationWindowView, 0, len(windows))
	for _, win := range windows {
		v := automationWindowView{
			ID: win.ID, Kind: string(win.Kind), Schedule: win.Schedule,
			DurationSeconds: int(win.Duration.Seconds()), Timezone: win.Timezone,
			Reason: win.Reason, CreatedAt: win.createdAt,
			Upcoming: []windowOpeningView{},
		}
		if openings, err := win.Window.Openings(now, windowUpcomingHorizon, windowUpcomingMax); err == nil {
			for _, o := range openings {
				v.Upcoming = append(v.Upcoming, windowOpeningView{Start: formatRFC3339(o.Start), End: formatRFC3339(o.End)})
			}
		}
		open, err := win.Window.IsOpen(now)
		if err != nil {
			v.InvalidReason = err.Error()
			// A malformed freeze blocks, so it is effectively open. Reporting it as
			// closed would tell the operator the opposite of what the sweeper does.
			v.OpenNow = win.Kind == orchestrator.WindowFreeze
		} else {
			v.OpenNow = open
		}
		out = append(out, v)
	}

	// The effective decision, alongside the rows. This is the question an operator
	// actually has — "would automation run right now?" — and answering it here
	// means the UI shows the same verdict the sweeper will reach rather than a
	// second guess at it.
	decision := orchestrator.CheckWindows(now, windowsOf(windows))
	writeJSON(w, http.StatusOK, map[string]any{
		"windows":           out,
		"automationOpenNow": decision.Allowed,
		"decisionReason":    decision.Reason,
	})
}

// handleCreateAutomationWindow is POST /api/v1/admin/automation-windows.
func (s *Server) handleCreateAutomationWindow(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	var req putAutomationWindowRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}
	tz := req.Timezone
	if tz == "" {
		tz = "UTC"
	}
	win := orchestrator.Window{
		Kind:     orchestrator.WindowKind(req.Kind),
		Schedule: req.Schedule,
		Duration: time.Duration(req.DurationSeconds) * time.Second,
		Timezone: tz,
		Reason:   req.Reason,
	}
	// Validated here, at configuration time, so a bad schedule is refused when it
	// is typed rather than discovered when a window fails to open — or worse, when
	// a malformed freeze silently blocks everything.
	if err := orchestrator.ValidateWindow(win); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
			"That window is not valid", err.Error())
		return
	}

	id := domain.NewID(domain.PrefixAutomationWindow)
	if _, err := rc.Tx.Exec(r.Context(),
		`INSERT INTO automation_windows (id, tenant_id, kind, schedule, duration_seconds, timezone, reason, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		id, rc.TenantID, req.Kind, req.Schedule, req.DurationSeconds, tz, req.Reason, rc.UserID); err != nil {
		logger.ErrorContext(r.Context(), "creating the automation window failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not save this window", "")
		return
	}

	capability := authz.CapOrgSettingsWrite
	if err := audit.RecordEvent(r.Context(), rc.Tx, audit.Event{
		TenantID: rc.TenantID, ActorID: &rc.UserID, ActorAuthMethod: "jwt",
		SourceIP: clientIP(r), Capability: &capability, Outcome: audit.OutcomeSuccess,
		Details: map[string]any{
			"action": "create_automation_window", "windowId": id, "kind": req.Kind,
			"schedule": req.Schedule, "durationSeconds": req.DurationSeconds,
			"timezone": tz, "reason": req.Reason,
		},
	}); err != nil {
		logger.ErrorContext(r.Context(), "recording an automation-window creation in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record this change", "")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

// handleDeleteAutomationWindow is DELETE /api/v1/admin/automation-windows/{id}.
//
// Audited like any other write, and worth being audited specifically: deleting a
// freeze window is the act of permitting automation during a period somebody
// deliberately closed.
func (s *Server) handleDeleteAutomationWindow(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	id := r.PathValue("id")
	var kind, schedule, reason string
	if err := rc.Tx.QueryRow(r.Context(),
		`DELETE FROM automation_windows WHERE id = $1 RETURNING kind, schedule, reason`, id).
		Scan(&kind, &schedule, &reason); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "No such window", "")
			return
		}
		logger.ErrorContext(r.Context(), "deleting the automation window failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not remove this window", "")
		return
	}
	capability := authz.CapOrgSettingsWrite
	if err := audit.RecordEvent(r.Context(), rc.Tx, audit.Event{
		TenantID: rc.TenantID, ActorID: &rc.UserID, ActorAuthMethod: "jwt",
		SourceIP: clientIP(r), Capability: &capability, Outcome: audit.OutcomeSuccess,
		Details: map[string]any{
			"action": "delete_automation_window", "windowId": id, "kind": kind,
			"schedule": schedule, "reason": reason,
		},
	}); err != nil {
		logger.ErrorContext(r.Context(), "recording an automation-window deletion in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record this change", "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// storedWindow is a Window plus the row metadata the view needs.
type storedWindow struct {
	orchestrator.Window
	createdAt string
}

func windowsOf(stored []storedWindow) []orchestrator.Window {
	out := make([]orchestrator.Window, 0, len(stored))
	for _, s := range stored {
		out = append(out, s.Window)
	}
	return out
}

// loadAutomationWindows reads every configured window for the caller's tenant.
// Exported through the querier rather than the Server so the unattended sweeper
// can use the same loader — one definition of what a stored window is.
func loadAutomationWindows(ctx context.Context, tx pgx.Tx) ([]storedWindow, error) {
	rows, err := tx.Query(ctx,
		`SELECT id, kind, schedule, duration_seconds, timezone, reason, created_at
		   FROM automation_windows ORDER BY kind, created_at`)
	if err != nil {
		return nil, fmt.Errorf("query automation windows: %w", err)
	}
	defer rows.Close()
	var out []storedWindow
	for rows.Next() {
		var w storedWindow
		var kind string
		var seconds int
		var createdAt time.Time
		if err := rows.Scan(&w.ID, &kind, &w.Schedule, &seconds, &w.Timezone, &w.Reason, &createdAt); err != nil {
			return nil, fmt.Errorf("scan automation window: %w", err)
		}
		w.Kind = orchestrator.WindowKind(kind)
		w.Duration = time.Duration(seconds) * time.Second
		w.createdAt = formatRFC3339(createdAt)
		out = append(out, w)
	}
	return out, rows.Err()
}
