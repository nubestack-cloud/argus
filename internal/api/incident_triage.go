package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/events"
	"argus/internal/logging"
	"argus/internal/orchestrator"
	"argus/internal/timeline"
)

// Human incident close-out: POST /api/v1/incidents/{id}/resolve and
// POST /api/v1/incidents/{id}/dismiss.
//
// # Why this file exists
//
// Until it did, an incident could only leave the open set along the
// remediation path: Validating -> Resolved after a successful execution, or
// AwaitingApproval -> Dismissed via /reject. Every other route was a dead end.
// So the two most ordinary things an operator does — fixing a problem by hand,
// and deciding a problem needs no action — had no representation in the
// product at all. The incident stayed open forever, and the list only grew.
//
// That was found by using it: a six-fault validation sweep left ~30
// permanently-open incidents whose objects had already been deleted, because
// deleting a broken object is precisely what an operator does when they fix
// something (WORKLOG §88). An incident list that cannot shrink is one people
// stop reading, and a monitoring product nobody reads has no value whatever
// its detection quality.
//
// # resolve vs dismiss
//
// Kept as two distinct verdicts rather than one "close" button, because they
// mean different things to anyone reading the history later, and because
// lld/08-remediation-contracts.md §2 already defines Dismissed as terminal
// with that meaning:
//
//   - resolve  = "the underlying problem is gone." Either the operator fixed
//     it, or the object stopped existing.
//   - dismiss  = "this is real but needs no action from ARGUS." Expected
//     noise, a known-broken dev workload, an accepted risk.
//
// Both are terminal (orchestrator's allowedTransitions gives Resolved and
// Dismissed empty edge sets), so neither can be undone — which is exactly why
// the note is mandatory on dismiss: a permanently-silenced real problem must
// carry a reason someone can audit.
//
// # What this deliberately is NOT
//
// Not a way to close an incident whose problem is still present and still
// being detected. Nothing here suppresses future findings: if the fault is
// still there, its detector re-sends the fingerprint and
// internal/gateway/finding.go opens a NEW incident, because correlation only
// attaches to incidents not already Resolved/Dismissed. That is the correct
// behaviour — closing an incident is a statement about the past, not a mute
// switch. The mute switch is CapIncidentSilence — see tolerations.go's
// handleTolerateIncident and migration 000041's incident_tolerations table —
// which actually prevents a future occurrence from opening a new incident,
// rather than just closing the current one.

// incidentTriageRequest is the body for both endpoints. Note is optional for
// resolve (the state change plus actor is often the whole story) and required
// for dismiss — see this file's doc comment.
type incidentTriageRequest struct {
	Note string `json:"note"`
}

// incidentTriageResponse mirrors approveRejectResponse's shape so the two
// close-out families look the same to a client.
type incidentTriageResponse struct {
	IncidentID    string `json:"incidentId"`
	Verdict       string `json:"verdict"`
	IncidentState string `json:"incidentState"`
	Message       string `json:"message"`
}

// maxTriageNoteLen bounds the stored note. Generous for a real explanation,
// bounded so an audit detail blob cannot be used as arbitrary storage.
const maxTriageNoteLen = 2000

func (s *Server) handleResolveIncident(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	s.triageIncident(w, r, rc, orchestrator.StateResolved, "resolved", false,
		"Resolved — the incident is closed. If the problem is still present, its detector will open a new incident.")
}

func (s *Server) handleDismissIncident(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	s.triageIncident(w, r, rc, orchestrator.StateDismissed, "dismissed", true,
		"Dismissed — the incident is closed with no action. If the problem is still present, its detector will open a new incident.")
}

// triageIncident is the shared body of both handlers. One function rather than
// two near-identical ones so the state check, audit record and event publish
// cannot drift apart between resolve and dismiss.
func (s *Server) triageIncident(w http.ResponseWriter, r *http.Request, rc *requestContext,
	targetState, verdict string, noteRequired bool, successMessage string) {
	ctx := r.Context()
	incidentID := r.PathValue("id")

	var req incidentTriageRequest
	// An absent body is allowed (io.EOF) — resolve often needs no note, and
	// requiring `{}` to close an incident would be gratuitous. Malformed JSON
	// is still an error, since that means the caller tried to send something
	// and got it wrong.
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}
	req.Note = strings.TrimSpace(req.Note)
	if len(req.Note) > maxTriageNoteLen {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
			"Note is too long", fmt.Sprintf("note must be at most %d characters", maxTriageNoteLen))
		return
	}
	if noteRequired && req.Note == "" {
		// Required on dismiss specifically: Dismissed is terminal and says
		// "this real problem will be ignored", which nobody should be able to
		// do anonymously and without stating why.
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
			"A note is required to dismiss an incident",
			"dismissing records that a real problem will not be acted on — say why, so the decision can be audited later")
		return
	}

	clusterID, state, err := incidentClusterAndState(ctx, rc.Tx, incidentID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Incident not found", "")
			return
		}
		logger.ErrorContext(ctx, "looking up the incident to triage failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up incident", "")
		return
	}

	// Checked here, with a specific message, rather than relying on
	// SetState's own rejection — a 409 that names the current state is
	// actionable, an opaque internal error is not. SetState still enforces it
	// as the real authority (it is the one function that writes
	// incidents.state).
	if !orchestrator.CanTransition(state, targetState) {
		detail := fmt.Sprintf("incident is currently %q, which cannot move to %q", state, targetState)
		if state == orchestrator.StateResolved || state == orchestrator.StateDismissed {
			detail = fmt.Sprintf("incident is already closed (%s)", state)
		} else if state == orchestrator.StateInvestigating {
			detail = "an investigation is currently running on this incident — wait for it to finish, then close it"
		}
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/invalid-state",
			"Incident cannot be closed from its current state", detail)
		return
	}

	if err := orchestrator.SetState(ctx, rc.Tx, incidentID, targetState); err != nil {
		logger.ErrorContext(ctx, "setting the triaged incident's state failed",
			logging.IncidentID(incidentID), slog.String("target_state", string(targetState)), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not update incident state", "")
		return
	}

	// PROJECT.md L8: what this close-out is a judgement OF.
	//
	// A dismissal's note is mandatory precisely because it is a verdict — "this
	// real problem will not be acted on", and usually an implicit verdict on
	// what ARGUS said about it. The note lands in timeline_events.payload and
	// audit_events.details (this path has no table of its own — the reason is
	// not a column anywhere, unlike remediation_approval_decisions.reason), so
	// the anchor goes in the same two blobs rather than in a new column.
	// Recorded for resolve too, and not only because triageIncident is one
	// shared body: "the operator fixed this by hand" is feedback on an analysis
	// in exactly the same way "no action needed" is, and splitting the two
	// would mean deliberately recording provenance for the more negative half
	// only.
	//
	// WHICH ANALYSIS. The incident's newest, which is the right answer here for
	// the opposite reason it is the wrong one on the approvals screen: a
	// close-out is a judgement of the incident as the detail page presents it,
	// and that page renders exactly one analysis — getLatestAnalysis's
	// `ORDER BY created_at DESC LIMIT 1`, mirrored below so the two cannot
	// disagree about what was on screen. (An approval, by contrast, is a
	// judgement of a specific plan, whose own analysis may be older; see
	// execution.DecisionAnalysisSubquery.)
	//
	// A null value means "this incident was never analysed", which is the
	// common case for a quick dismiss and is a fact worth keeping — it is how a
	// later reader tells "the operator disagreed with ARGUS" from "ARGUS never
	// said anything". An ABSENT key means the event predates this code.
	closedAgainstAnalysis, err := latestAnalysisIDForIncident(ctx, rc.Tx, incidentID)
	if err != nil {
		// Treated as a hard failure, like every other DB error in this handler,
		// rather than skipped as best-effort bookkeeping: the only way this
		// trivial select fails is a transaction that is already broken, and the
		// timeline and audit writes below would then fail anyway. So this cannot
		// turn a close-out that would have succeeded into one that does not.
		logger.ErrorContext(ctx, "looking up the incident's latest analysis failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up the incident's analysis", "")
		return
	}

	// BACKLOG.md D9 B7: until now this handler wrote an audit.RecordEvent
	// (the compliance trail, below) but never a timeline.Record — so a human
	// resolving or dismissing an incident, one of the two most ordinary
	// things an operator does on this screen (this file's own header
	// comment), left the incident's own "what happened" history completely
	// silent about the close-out. audit_events and timeline_events answer
	// different questions (is this auditable vs. what happened to THIS
	// incident) and are not substitutes for each other. See
	// timeline.EventIncidentResolved/EventIncidentDismissed's own doc
	// comments.
	timelineEventType := timeline.EventIncidentResolved
	if targetState == orchestrator.StateDismissed {
		timelineEventType = timeline.EventIncidentDismissed
	}
	timelineSummary := successMessage
	if req.Note != "" {
		timelineSummary = fmt.Sprintf("%s Note: %s", successMessage, req.Note)
	}
	if err := timeline.Record(ctx, rc.Tx, timeline.Event{
		TenantID: rc.TenantID, ClusterID: clusterID, IncidentID: incidentID,
		Type:    timelineEventType,
		Summary: timelineSummary,
		Detail:  map[string]any{"verdict": verdict, "fromState": state, "note": req.Note, "analysisId": closedAgainstAnalysis},
	}); err != nil {
		logger.ErrorContext(ctx, "recording the triage timeline event failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record incident history", "")
		return
	}

	capability := authz.CapIncidentTriage
	details := map[string]any{
		"action":     "triage_incident",
		"verdict":    verdict,
		"incidentId": incidentID,
		"fromState":  state,
		"toState":    targetState,
		"note":       req.Note,
	}
	// Recorded only when there IS one, unlike the timeline payload above,
	// which carries an explicit null. Not a change of mind about what is worth
	// knowing — the two blobs are rendered differently. audit_events is
	// summarised for the audit list by summarizeActionDetails, which formats
	// every value generically, and a JSON null formats as the literal
	// "<nil>" (audit.go's formatDetailValue, asserted by its own test). An
	// operator-facing list reading "analysisId=<nil>" is Go debug output
	// presented as a fact, which is exactly what this codebase refuses to do
	// with an unavailable value. The three-way distinction — pinned, none,
	// pre-L8 — is preserved in full on the timeline event written in this same
	// transaction, so nothing is lost by leaving the key out here.
	if closedAgainstAnalysis != nil {
		details["analysisId"] = *closedAgainstAnalysis
	}
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		ClusterID:       &clusterID,
		Outcome:         audit.OutcomeSuccess,
		Details:         details,
	}); err != nil {
		logger.ErrorContext(ctx, "recording an incident triage in the audit log failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	// Published after commit, not inline: a client that reacts to this by
	// re-reading the incident must not be able to observe the old state (the
	// 2xx-before-commit class of bug this codebase already fixed once).
	rc.OnCommit(func() {
		if s.events != nil {
			s.events.Publish(events.IncidentUpdated(incidentID, clusterID))
		}
	})

	writeJSON(w, http.StatusOK, incidentTriageResponse{
		IncidentID:    incidentID,
		Verdict:       verdict,
		IncidentState: targetState,
		Message:       successMessage,
	})
}

// incidentClusterAndState reads the two facts both handlers need in one
// round-trip. Scoped by RLS like every other query on this transaction, so an
// incident in a cluster the caller cannot see reads as not-found rather than
// forbidden.
func incidentClusterAndState(ctx context.Context, tx pgx.Tx, incidentID string) (clusterID, state string, err error) {
	err = tx.QueryRow(ctx, `SELECT cluster_id, state FROM incidents WHERE id = $1`, incidentID).Scan(&clusterID, &state)
	return clusterID, state, err
}

// latestAnalysisIDForIncident returns the id of the analysis the operator was
// looking at when they closed this incident, or nil if the incident was never
// analysed at all — the common case for a quick dismiss, and a fact the caller
// records as such rather than dropping.
//
// The ordering is getLatestAnalysis's (analyze.go), deliberately character for
// character: that function is what puts an analysis on the incident detail
// page, so anything else here would pin a row the operator did not see. A
// returned error is a real database failure only; pgx.ErrNoRows is folded into
// the nil result, because "never analysed" is an answer, not a fault.
//
// RLS: runs on the request's transaction, so an incident whose analyses the
// caller cannot see yields nil rather than another tenant's row.
func latestAnalysisIDForIncident(ctx context.Context, tx pgx.Tx, incidentID string) (*string, error) {
	var id string
	err := tx.QueryRow(ctx,
		`SELECT id FROM analyses WHERE incident_id = $1 ORDER BY created_at DESC LIMIT 1`,
		incidentID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &id, nil
}
