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
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/domain"
	"argus/internal/events"
	"argus/internal/logging"
	"argus/internal/orchestrator"
)

// This file implements CapIncidentSilence — the "mute switch" declared in
// internal/authz/permissions.go since the first authz pass and referenced by
// name in incident_triage.go's doc comment as "a separate, still-unbuilt
// feature," until now. See BACKLOG.md's A5 entry and migration 000041's own
// doc comment for the full design and the live case that motivated it
// (rancher-monitoring-windows-exporter's Service having no endpoints on a
// Linux-only cluster — real, expected, and not actionable, but re-detected
// every cycle with no way to say "stop opening incidents for this").
//
// Four endpoints:
//
//   - POST   /api/v1/incidents/{id}/tolerate  — create a rule scoped to this
//     incident's object, and close THIS incident the same way /dismiss does
//     (a toleration is always created from an already-open incident the
//     operator has looked at, not blind).
//   - GET    /api/v1/tolerations              — list active rules, RLS-scoped
//     like every other fleet-wide read.
//   - GET    /api/v1/tolerations/{id}          — one rule in full: the rule
//     itself, the incident it was created from (with that incident's analysis
//     and proposed remediation), and what it has actually suppressed. The
//     deliberate mirror of GET /incidents/{id}, which is also "the row, plus
//     what explains it, plus its history" — see handleGetToleration.
//   - DELETE /api/v1/tolerations/{id}          — soft-delete a rule (future
//     findings on that object resume opening incidents normally).
//
// maxToleranceExpirySeconds caps how far out an expiry can be set — generous
// enough for "until the next maintenance window" or longer, bounded so a
// typo (or a client bug) can't produce a rule that outlives anyone's memory
// of why it exists. A toleration with no expiry at all is allowed and
// expected to be the common case (the Windows-exporter example has no
// natural end date), so this only bounds an explicit value, never imposes
// one.
const maxToleranceExpirySeconds = 3 * 365 * 24 * 60 * 60 // ~3 years

type tolerateIncidentRequest struct {
	Note string `json:"note"`
	// Reasons narrows the rule to specific detector reason strings. Omitted
	// or empty AND AllReasons is false: defaults to the exact set of reasons
	// already attached to this incident's findings — "tolerate what I'm
	// looking at," not "tolerate anything that ever happens to this object."
	Reasons []string `json:"reasons"`
	// AllReasons, when true, ignores Reasons and stores a wildcard rule
	// (NULL reasons column) — an explicit, opt-in choice to silence every
	// future symptom on this object, for the "this whole workload is
	// known-broken in dev" case.
	AllReasons bool `json:"allReasons"`
	// ExpiresInSeconds is optional; nil/omitted means the rule never expires.
	ExpiresInSeconds *int `json:"expiresInSeconds"`
}

type tolerationView struct {
	ID string `json:"id"`
	// ClusterID and ClusterDisplayName: the ID identifies the row, the display
	// name is what an operator can actually read. Both are sent because the ID
	// is what a link needs and the name is what a column shows — and a raw
	// `cls_01H...` in a table tells a reader nothing about which cluster a rule
	// is silencing findings on, which was half of the complaint this view
	// answers (BUGS.md item 32).
	ClusterID          string `json:"clusterId"`
	ClusterDisplayName string `json:"clusterDisplayName"`
	// ObjectKey is the raw composite `gvk|namespace|name`
	// (gateway.objectCorrelationKey). Kept for exactness and for anything
	// matching on it, but the three parts below are what a UI should render:
	// the composite is long, and the most identifying part of it — the object
	// NAME — is at the very end, so any width-limited column truncates away
	// precisely the half a reader needs. Split here rather than in the client
	// so every consumer gets the same parse, and so the delimiter stays an
	// implementation detail of the package that produces it.
	ObjectKey       string   `json:"objectKey"`
	ObjectGVK       string   `json:"objectGvk"`
	ObjectNamespace string   `json:"objectNamespace"`
	ObjectName      string   `json:"objectName"`
	Reasons         []string `json:"reasons,omitempty"`
	AllReasons      bool     `json:"allReasons"`
	// Note is why this was tolerated, and it is the one field on this row
	// whose entire job is explaining a decision — required at creation for
	// that reason. Sent on the list as well as the detail so a client never
	// has to fetch a rule to find out why it exists.
	Note string `json:"note"`
	// IncidentID is the incident this rule was created from (migration
	// 000044), or nil. Nil is a normal, honest state rather than a fault: a
	// rule created before that migration whose creation audit event is gone,
	// or one whose incident has aged out of retention — see the migration's
	// own comment. It is the join key behind GET /tolerations/{id}'s origin
	// block, and on its own it is enough for a client to link back to the
	// incident.
	IncidentID *string `json:"incidentId,omitempty"`
	// CreatedBy is the raw users.id; CreatedByEmail is the readable form, left
	// empty if the user row is gone. LEFT JOIN, never INNER: a rule created by
	// a since-removed user must still be listed and removable — losing the
	// author is not a reason to hide a rule that is still suppressing findings.
	CreatedBy      string `json:"createdBy"`
	CreatedByEmail string `json:"createdByEmail,omitempty"`
	// AutoCreated distinguishes a rule ARGUS created for itself (on a
	// Dismissed/Expired transition) from one a human created via
	// POST /incidents/{id}/tolerate. Both are removed the same way; the
	// difference matters because an empty author is otherwise indistinguishable
	// from a missing one, and migration 000112's own comment promises the UI
	// badges these differently.
	AutoCreated bool    `json:"autoCreated"`
	CreatedAt   string  `json:"createdAt"`
	ExpiresAt   *string `json:"expiresAt,omitempty"`

	// SuppressedCount / FirstSuppressed / LastSuppressed are what this rule has
	// actually DONE — the findings it stopped from opening incidents.
	//
	// This is the answer to "what error is being silenced here", and it is a
	// live one where the originating incident is a historical one: that incident
	// is closed, whereas these are the conditions the rule is suppressing *now*
	// (both are worth having, which is why IncidentID above exists too). It also
	// makes the opposite case visible — a rule with a zero count is silencing
	// nothing and is a candidate for removal, which no other field on this row
	// could tell you.
	//
	// See suppressedFindingsPredicate for why these can be attributed to a
	// specific rule at all without a foreign key.
	SuppressedCount int     `json:"suppressedCount"`
	FirstSuppressed *string `json:"firstSuppressed,omitempty"`
	LastSuppressed  *string `json:"lastSuppressed,omitempty"`
}

// suppressedFindingsPredicate matches the findings one toleration suppressed.
//
// # Why this attribution is exact, and not a heuristic
//
// findings.incident_id IS NULL means "arrived but correlated to no incident",
// and there are TWO ways that happens: this rule suppressed it, or storm
// protection did. They are not distinguishable by any column.
//
// They do not need to be, because of the order the two checks run in:
// internal/gateway/finding.go evaluates tolerations FIRST and only reaches
// storm protection `if !suppressed` — its own doc comment says so explicitly
// ("checked in the same branch as storm protection and before it"). So a
// finding that matches an active rule's object and reason can only have been
// suppressed by that rule. If that ordering ever changes, this attribution
// becomes a guess and this comment is where to start.
//
// The two time bounds are what keep it honest rather than merely plausible:
//   - `occurred_at >= created_at` — a rule cannot have suppressed something
//     that happened before it existed. Without this, a pre-existing
//     storm-suppressed finding for the same object would be claimed as this
//     rule's work.
//   - `occurred_at < removed_at` when removed — nor after it stopped applying.
//
// $1 is the toleration id. Written as a correlated subquery against the
// toleration row itself so the object/reason match cannot drift out of step
// with what the suppression actually compared.
const suppressedFindingsPredicate = `
	f.incident_id IS NULL
	AND f.cluster_id = t.cluster_id
	AND f.gvk || '|' || f.namespace || '|' || f.object_name = t.object_key
	AND (t.reasons IS NULL OR f.reason = ANY(t.reasons))
	AND f.occurred_at >= t.created_at
	AND (t.removed_at IS NULL OR f.occurred_at < t.removed_at)`

// splitObjectKey parses gateway.objectCorrelationKey's `gvk|namespace|name`.
//
// Returns the whole string as the name on any unexpected shape rather than
// guessing: a caller showing the full key is merely verbose, whereas a caller
// showing the wrong field as "name" is misleading. A cluster-scoped object
// legitimately has an empty namespace, so an empty middle part is normal and
// not a parse failure.
func splitObjectKey(key string) (gvk, namespace, name string) {
	parts := strings.Split(key, "|")
	if len(parts) != 3 {
		return "", "", key
	}
	return parts[0], parts[1], parts[2]
}

type tolerateIncidentResponse struct {
	IncidentID    string         `json:"incidentId"`
	IncidentState string         `json:"incidentState"`
	Toleration    tolerationView `json:"toleration"`
	Message       string         `json:"message"`
}

// handleTolerateIncident is POST /api/v1/incidents/{id}/tolerate. Requires
// incident:silence. Creates a toleration rule for this incident's object and
// closes the incident (Dismissed) in the same transaction — see this file's
// doc comment for why those two things always happen together.
func (s *Server) handleTolerateIncident(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	incidentID := r.PathValue("id")

	var req tolerateIncidentRequest
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
	if req.Note == "" {
		// Same rationale as dismiss's required note (incident_triage.go): a
		// toleration silences a real, ongoing condition indefinitely (or
		// until expiry) with no per-occurrence review from that point on —
		// nobody should be able to do that anonymously and without saying why.
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
			"A note is required to tolerate an incident",
			"tolerating silences future occurrences of this condition — say why, so the decision can be audited later")
		return
	}
	if req.ExpiresInSeconds != nil && (*req.ExpiresInSeconds <= 0 || *req.ExpiresInSeconds > maxToleranceExpirySeconds) {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
			"Invalid expiry", fmt.Sprintf("expiresInSeconds must be between 1 and %d", maxToleranceExpirySeconds))
		return
	}

	var clusterID, state string
	var objectKey *string
	if err := rc.Tx.QueryRow(ctx, `SELECT cluster_id, state, object_key FROM incidents WHERE id = $1`, incidentID).
		Scan(&clusterID, &state, &objectKey); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Incident not found", "")
			return
		}
		logger.ErrorContext(ctx, "looking up the incident to tolerate failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up incident", "")
		return
	}
	if objectKey == nil || strings.TrimSpace(*objectKey) == "" {
		// A fingerprint-only incident (no named object — see
		// objectCorrelationKey's own doc comment) has no stable identity to
		// scope future suppression to. Tolerating it would either match
		// nothing ever again (too narrow to be useful) or require matching
		// on fingerprint alone, which is a materially different, broader
		// rule than "this one object" — not built here; dismiss remains the
		// right tool for this incident today.
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/invalid-state",
			"This incident cannot be tolerated",
			"this incident names no specific object, so there is nothing to scope a toleration rule to — use dismiss instead")
		return
	}
	if !orchestrator.CanTransition(state, orchestrator.StateDismissed) {
		detail := fmt.Sprintf("incident is currently %q, which cannot move to %q", state, orchestrator.StateDismissed)
		if state == orchestrator.StateResolved || state == orchestrator.StateDismissed {
			detail = fmt.Sprintf("incident is already closed (%s)", state)
		} else if state == orchestrator.StateInvestigating {
			detail = "an investigation is currently running on this incident — wait for it to finish, then tolerate it"
		}
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/invalid-state",
			"Incident cannot be closed from its current state", detail)
		return
	}

	reasons, allReasons, err := resolveToleranceReasons(ctx, rc.Tx, incidentID, req.Reasons, req.AllReasons)
	if err != nil {
		logger.ErrorContext(ctx, "resolving the toleration's reasons failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not determine toleration scope", "")
		return
	}

	var expiresAt *time.Time
	if req.ExpiresInSeconds != nil {
		t := time.Now().Add(time.Duration(*req.ExpiresInSeconds) * time.Second)
		expiresAt = &t
	}

	tolerationID := domain.NewID(domain.PrefixToleration)
	var reasonsArg any
	if !allReasons {
		reasonsArg = reasons
	}
	// Capture where the real fix lives, NOW, while the object still exists.
	//
	// This is the same reasoning as the pre-execution rollback capture: the answer
	// is only knowable at this moment. A toleration routinely outlives its object
	// by weeks — that is often *why* the rule is still there — so reading the
	// ownership column when someone eventually reviews the rule finds either a
	// stale answer or, for an incident nobody analysed, nothing at all. Asking now
	// costs one tunnel call against a cluster whose object is, by definition,
	// actively firing.
	//
	// Only when nothing is stored: an analysed incident already has the answer
	// from analysis time, and that one is about the object as the investigation
	// saw it, which is the more relevant version.
	//
	// Silent on every failure, like cacheIncidentOwnership itself: a missing
	// caveat must not stop someone silencing a noisy alert.
	var alreadyStored bool
	if err := rc.Tx.QueryRow(ctx,
		`SELECT ownership IS NOT NULL FROM incidents WHERE id = $1`, incidentID).Scan(&alreadyStored); err != nil {
		logger.ErrorContext(ctx, "checking the incident's stored ownership failed", logging.IncidentID(incidentID), logging.Err(err))
	} else if !alreadyStored {
		s.cacheIncidentOwnership(ctx, rc, incidentID, clusterID)
	}

	var createdAt time.Time
	// incident_id is written here and nowhere else: this is the only path that
	// creates a toleration, and it is the only point at which the originating
	// incident is known without inference (migration 000044).
	if err := rc.Tx.QueryRow(ctx,
		`INSERT INTO incident_tolerations (id, tenant_id, cluster_id, object_key, reasons, note, incident_id, created_by, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 RETURNING created_at`,
		tolerationID, rc.TenantID, clusterID, *objectKey, reasonsArg, req.Note, incidentID, rc.UserID, expiresAt).Scan(&createdAt); err != nil {
		logger.ErrorContext(ctx, "inserting the toleration failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not create toleration", "")
		return
	}

	if err := orchestrator.SetState(ctx, rc.Tx, incidentID, orchestrator.StateDismissed); err != nil {
		logger.ErrorContext(ctx, "dismissing the tolerated incident failed",
			logging.IncidentID(incidentID), slog.String("target_state", string(orchestrator.StateDismissed)), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not update incident state", "")
		return
	}

	capability := authz.CapIncidentSilence
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		ClusterID:       &clusterID,
		Outcome:         audit.OutcomeSuccess,
		Details: map[string]any{
			"action":       "tolerate_incident",
			"incidentId":   incidentID,
			"tolerationId": tolerationID,
			"objectKey":    *objectKey,
			"reasons":      reasons,
			"allReasons":   allReasons,
			"note":         req.Note,
		},
	}); err != nil {
		logger.ErrorContext(ctx, "recording a toleration in the audit log failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	rc.OnCommit(func() {
		if s.events != nil {
			s.events.Publish(events.IncidentUpdated(incidentID, clusterID))
		}
	})

	view := tolerationView{
		ID:         tolerationID,
		ClusterID:  clusterID,
		ObjectKey:  *objectKey,
		Reasons:    reasons,
		AllReasons: allReasons,
		Note:       req.Note,
		IncidentID: &incidentID,
		CreatedBy:  rc.UserID,
		CreatedAt:  formatRFC3339(createdAt),
	}
	// Built by hand rather than read back through scanTolerationView (the row
	// is not committed yet), so the derived fields have to be filled in here
	// too — they were missing, which made this one response the only place a
	// tolerationView arrived with an unsplit object key. ClusterDisplayName and
	// the suppression aggregate are still legitimately absent: no join here,
	// and a rule created a moment ago has suppressed nothing.
	view.ObjectGVK, view.ObjectNamespace, view.ObjectName = splitObjectKey(*objectKey)
	if expiresAt != nil {
		f := formatRFC3339(*expiresAt)
		view.ExpiresAt = &f
	}

	writeJSON(w, http.StatusOK, tolerateIncidentResponse{
		IncidentID:    incidentID,
		IncidentState: orchestrator.StateDismissed,
		Toleration:    view,
		Message:       "Tolerated — future occurrences of this on the same object will no longer open new incidents. Remove the toleration rule to resume normal detection.",
	})
}

// resolveToleranceReasons decides the reasons a new toleration rule should
// store, given the request's explicit choice. Pulled out as its own function
// so the default-to-current-findings behaviour (the part that needs a query)
// is unit-testable in isolation from the handler's HTTP plumbing... except
// the query means it isn't pure; kept small and single-purpose instead so a
// future db-backed test can target it directly without going through the
// whole handler.
func resolveToleranceReasons(ctx context.Context, tx pgx.Tx, incidentID string, requested []string, allReasons bool) (reasons []string, wildcard bool, err error) {
	if allReasons {
		return nil, true, nil
	}
	requested = dedupNonEmpty(requested)
	if len(requested) > 0 {
		return requested, false, nil
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT reason FROM findings WHERE incident_id = $1`, incidentID)
	if err != nil {
		return nil, false, fmt.Errorf("query findings reasons: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var reason string
		if err := rows.Scan(&reason); err != nil {
			return nil, false, fmt.Errorf("scan finding reason: %w", err)
		}
		reasons = append(reasons, reason)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate findings reasons: %w", err)
	}
	if len(reasons) == 0 {
		// Should not happen — every incident has at least one finding — but
		// erring towards the wildcard here (rather than an unusable rule that
		// matches nothing) keeps this a safe fallback rather than a silent
		// no-op toleration.
		logger.WarnContext(ctx, "incident has no findings to derive toleration reasons from; defaulting to all reasons", logging.IncidentID(incidentID))
		return nil, true, nil
	}
	return reasons, false, nil
}

func dedupNonEmpty(in []string) []string {
	seen := make(map[string]bool, len(in))
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// tolerationListQuery is shared by handleListTolerations and
// handleGetToleration — same joins and column set, the latter only swapping
// the WHERE clause. Exactly incidentListQuery's role in incidents.go, and
// kept shared for the same reason: two copies of this join set would drift,
// and a rule must not read differently depending on which endpoint returned
// it.
//
// LEFT JOINs, following internal/api/audit.go's own precedent and for the
// same stated reason: a LEFT JOIN degrades to a null display name, while an
// INNER JOIN would silently DROP a rule whose cluster or author row is gone.
// A toleration that has outlived its author is still suppressing findings and
// still needs to be visible and removable.
//
// The suppression aggregate rides along as a LATERAL rather than a second
// round-trip per row: the list is small (active rules only) and an N+1 on a
// page that polls would be worse than one slightly wider query. Only the
// counts are aggregated here — the individual findings, and the originating
// incident's analysis, are fetched on expand (handleGetToleration), so
// neither a rule that has suppressed thousands of findings nor an incident
// with a long causal chain bloats the list payload.
// created_by is COALESCEd, and auto_created carried alongside it, because
// migration 000112 made created_by NULLABLE: a rule SetState creates
// automatically on a Dismissed/Expired transition (PROJECT.md T6) has no human
// author, and the migration's CHECK ties the two columns together. Scanning
// that NULL into tolerationView's plain string field took the ENTIRE list
// endpoint down with "cannot scan NULL into *string" the moment the first
// automatic rule existed — and on a real fleet almost every rule is automatic
// (24 of 25 on the development instance the day after T6 landed). The list is
// also the only place an operator can inspect or remove one, so this failure
// took out the override path for the whole mechanism.
const tolerationListQuery = `
	SELECT t.id, t.cluster_id, COALESCE(c.display_name, ''), t.object_key,
	       t.reasons, t.note, t.incident_id,
	       COALESCE(t.created_by, ''), COALESCE(u.email, ''), t.auto_created,
	       t.created_at, t.expires_at,
	       s.count, s.first_suppressed, s.last_suppressed
	  FROM incident_tolerations t
	  LEFT JOIN clusters c ON c.id = t.cluster_id
	  LEFT JOIN users u ON u.id = t.created_by
	  LEFT JOIN LATERAL (
	    SELECT count(*) AS count, min(f.occurred_at) AS first_suppressed, max(f.occurred_at) AS last_suppressed
	      FROM findings f
	     WHERE ` + suppressedFindingsPredicate + `
	  ) s ON true`

// scanTolerationView scans one row shaped like tolerationListQuery's SELECT,
// including the derived fields (the split object key, the wildcard flag) so
// every endpoint returns the same shape from the same code.
func scanTolerationView(row pgx.Row) (tolerationView, error) {
	var v tolerationView
	var reasons []string
	var createdAt time.Time
	var expiresAt *time.Time
	var firstSuppressed, lastSuppressed *time.Time
	if err := row.Scan(&v.ID, &v.ClusterID, &v.ClusterDisplayName, &v.ObjectKey,
		&reasons, &v.Note, &v.IncidentID, &v.CreatedBy, &v.CreatedByEmail, &v.AutoCreated, &createdAt, &expiresAt,
		&v.SuppressedCount, &firstSuppressed, &lastSuppressed); err != nil {
		return tolerationView{}, err
	}
	v.Reasons = reasons
	v.AllReasons = len(reasons) == 0
	v.ObjectGVK, v.ObjectNamespace, v.ObjectName = splitObjectKey(v.ObjectKey)
	v.CreatedAt = formatRFC3339(createdAt)
	if expiresAt != nil {
		f := formatRFC3339(*expiresAt)
		v.ExpiresAt = &f
	}
	if firstSuppressed != nil {
		f := formatRFC3339(*firstSuppressed)
		v.FirstSuppressed = &f
	}
	if lastSuppressed != nil {
		f := formatRFC3339(*lastSuppressed)
		v.LastSuppressed = &f
	}
	return v, nil
}

// handleListTolerations is GET /api/v1/tolerations. Requires incident:silence.
// Returns every active (non-removed) rule visible to the caller's RLS scope,
// newest first — the management surface BACKLOG.md's A5 entry calls for, so
// an operator can see what's being silenced and undo it.
func (s *Server) handleListTolerations(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	rows, err := rc.Tx.Query(ctx, tolerationListQuery+`
	 WHERE t.removed_at IS NULL
	 ORDER BY t.created_at DESC`)
	if err != nil {
		logger.ErrorContext(ctx, "querying tolerations failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list tolerations", "")
		return
	}
	defer rows.Close()

	views := []tolerationView{}
	for rows.Next() {
		v, err := scanTolerationView(rows)
		if err != nil {
			logger.ErrorContext(ctx, "scanning a toleration row failed", logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list tolerations", "")
			return
		}
		views = append(views, v)
	}
	if err := rows.Err(); err != nil {
		logger.ErrorContext(ctx, "iterating the toleration rows failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list tolerations", "")
		return
	}

	writeJSON(w, http.StatusOK, views)
}

// suppressedFindingGroup is one reason a rule has been suppressing, with the
// count, the time range, and one real message.
//
// Grouped by reason rather than listed flat, matching what BUGS.md item 30
// established for an incident's own findings history and for the same reason:
// a rule that has suppressed a condition 108 times has one thing to say, not
// 108. The sample message is what actually answers "what error is this
// silencing" — the reason is a short code, the message is the sentence.
type suppressedFindingGroup struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
	// FirstSeen/LastSeen span every suppressed finding in this group, not just
	// the sampled one — so the range is the truth about the whole group.
	FirstSeen string `json:"firstSeen"`
	LastSeen  string `json:"lastSeen"`
	// SampleMessage is the most recent message for this reason. One, not all:
	// they are near-identical by construction (the same detector re-firing on
	// the same object), so shipping every copy would be volume without
	// information.
	SampleMessage string `json:"sampleMessage"`
	Severity      string `json:"severity"`
}

// tolerationOriginView is the incident a rule was created FROM: what was
// detected, and — if an investigation ever ran on it — what ARGUS concluded
// and what it proposed doing about it.
//
// Both fields are the incident endpoints' OWN view structs rather than
// narrower copies of them (incidentSummary from incidents.go, analysisResponse
// from analyze.go, which carries planView from remediation.go). That is the
// point: a toleration is an incident that has been accepted, so the client
// renders this with the same components it already uses on the incident
// detail page instead of a second, parallel vocabulary for the same facts —
// and a field added to either shape shows up here without this file changing.
//
// Analysis is nil when the incident was never investigated, which is the
// common case: tolerating is what an operator does with a condition they
// already understand, so most rules have no analysis behind them. Nil is
// rendered as "never investigated", never as an empty analysis.
type tolerationOriginView struct {
	Incident incidentSummary   `json:"incident"`
	Analysis *analysisResponse `json:"analysis"`
	// Ownership is where the real fix lives — the Helm release or GitOps
	// controller that owns the object, and the repository, path and synced commit
	// behind it. Absent when nothing owned it.
	//
	// On the origin rather than inside Incident on purpose: incidentSummary is
	// the LIST row shape, shared by every screen that lists incidents, and
	// ownership is a detail-level fact that would cost every one of those queries
	// a jsonb column to carry here. The incident detail endpoint exposes it the
	// same way, at the same level, for the same reason.
	Ownership *ownershipSummary `json:"ownership,omitempty"`
}

// tolerationDetailResponse is GET /api/v1/tolerations/{id}'s body: the rule,
// where it came from, and what it has done.
//
// Origin is nil in two different situations the client tells apart using
// Toleration.IncidentID — no incident recorded at all (nil id) versus an
// incident id whose row is no longer stored (non-nil id, nil origin, i.e.
// retention dropped the partition). Both are honest states and neither is an
// error, so neither fails the request: a rule must stay readable and removable
// regardless of what happened to the incident that prompted it, which is the
// same rule the LEFT JOINs above follow for its cluster and its author.
type tolerationDetailResponse struct {
	Toleration tolerationView           `json:"toleration"`
	Origin     *tolerationOriginView    `json:"origin"`
	Suppressed []suppressedFindingGroup `json:"suppressed"`
}

// handleGetToleration is GET /api/v1/tolerations/{id}. Requires
// incident:silence, the same capability as seeing the rule in the list at all
// — if you can see a rule you can see why it exists and what it silences.
//
// This is the expandable detail behind a toleration row, and it answers the
// two halves of "why is this being silenced, and what is it silencing?" that
// no single table can:
//
//   - The originating incident (BUGS.md item 37): the analysis that explains
//     the condition and the remediation ARGUS had proposed. Historical by
//     definition — that incident is closed — but it is the only place the
//     reasoning and the proposed fix are stored.
//   - The suppressed findings (WORKLOG §130): what the rule is stopping NOW,
//     which the incident cannot tell you.
//
// One endpoint rather than two, because the panel needs both on one click and
// neither is useful without the other. Nothing here is fetched by the list, so
// a fleet's worth of rules costs no analysis payloads until someone opens one.
func (s *Server) handleGetToleration(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	tolerationID := r.PathValue("id")

	// Not filtered on removed_at, here or in either query below: a removed
	// rule's history is still worth reading (what did it hide while it was
	// live?), and the suppression predicate's own time bounds already stop it
	// claiming findings from after it stopped applying.
	view, err := scanTolerationView(rc.Tx.QueryRow(ctx, tolerationListQuery+` WHERE t.id = $1`, tolerationID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Toleration not found", "")
			return
		}
		logger.ErrorContext(ctx, "looking up the toleration failed", slog.String("toleration_id", tolerationID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up toleration", "")
		return
	}

	origin, err := tolerationOrigin(ctx, rc, view.IncidentID)
	if err != nil {
		logger.ErrorContext(ctx, "looking up a toleration's originating incident failed", slog.String("toleration_id", tolerationID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up the incident this rule came from", "")
		return
	}

	groups, err := suppressedFindingGroups(ctx, rc.Tx, tolerationID)
	if err != nil {
		logger.ErrorContext(ctx, "listing the findings a toleration suppressed failed", slog.String("toleration_id", tolerationID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list suppressed findings", "")
		return
	}

	writeJSON(w, http.StatusOK, tolerationDetailResponse{Toleration: view, Origin: origin, Suppressed: groups})
}

// tolerationOrigin loads the incident a rule was created from, or nil.
//
// Reuses incidentListQuery/scanIncidentSummary and getLatestAnalysis rather
// than querying incidents and analyses directly, so this endpoint cannot
// disagree with GET /incidents/{id} about the same incident — including the
// analysis's plan, its approval and its execution outcome, all of which
// getLatestAnalysis already assembles (analyze.go's latestPlanViewForAnalysis).
//
// A missing incident row returns nil, not an error: see
// tolerationDetailResponse. Everything runs inside the caller's RLS-scoped
// transaction, so an incident outside the caller's cluster scope is invisible
// here exactly as it is everywhere else — which reads as "not stored", the
// same as retention having dropped it.
func tolerationOrigin(ctx context.Context, rc *requestContext, incidentID *string) (*tolerationOriginView, error) {
	if incidentID == nil || *incidentID == "" {
		return nil, nil
	}
	incident, err := scanIncidentSummary(rc.Tx.QueryRow(ctx, incidentListQuery+" AND incidents.id = $1", *incidentID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("look up incident %s: %w", *incidentID, err)
	}
	analysis, err := getLatestAnalysis(ctx, rc, *incidentID)
	if err != nil {
		return nil, fmt.Errorf("look up analysis for incident %s: %w", *incidentID, err)
	}

	// Where the real fix lives, if the object was owned by Helm or a GitOps
	// controller.
	//
	// A toleration is a decision to live with something, and the failure this
	// prevents is specific: a suppression that loses the fix location is how a
	// stop-gap becomes permanent. Someone reviewing muted rules months later
	// needs to know that this one is silencing a workload whose manifest is in a
	// named repository at a named path — otherwise the rule is the only surviving
	// record and it says nothing actionable.
	//
	// Read from incidents.ownership, the same column the incident detail page
	// uses, rather than asking the cluster: the object is very likely gone by now
	// (that is often WHY a rule outlives its incident), and a stored answer about
	// the object as it was is the honest one here. nil when nothing owned it,
	// which is the ordinary case and renders nothing.
	var ownershipRaw []byte
	if err := rc.Tx.QueryRow(ctx, `SELECT ownership FROM incidents WHERE id = $1`, *incidentID).Scan(&ownershipRaw); err != nil {
		// Logged, not returned: losing the ownership caveat must not fail the
		// panel that explains why a rule exists.
		logger.ErrorContext(ctx, "reading the originating incident's ownership failed", logging.IncidentID(*incidentID), logging.Err(err))
	}

	return &tolerationOriginView{
		Incident:  incident,
		Analysis:  analysis,
		Ownership: storedOwnership(ownershipRaw, nil, analysis),
	}, nil
}

// suppressedFindingGroups is what one rule has actually silenced, grouped by
// reason — the honest answer to "what is this rule hiding from me?", live
// rather than historical.
func suppressedFindingGroups(ctx context.Context, tx pgx.Tx, tolerationID string) ([]suppressedFindingGroup, error) {
	rows, err := tx.Query(ctx,
		`SELECT f.reason, count(*), min(f.occurred_at), max(f.occurred_at),
		        (array_agg(f.message ORDER BY f.occurred_at DESC))[1],
		        (array_agg(f.severity ORDER BY f.occurred_at DESC))[1]
		   FROM incident_tolerations t
		   JOIN findings f ON `+suppressedFindingsPredicate+`
		  WHERE t.id = $1
		  GROUP BY f.reason
		  ORDER BY count(*) DESC, f.reason ASC`, tolerationID)
	if err != nil {
		return nil, fmt.Errorf("query suppressed findings: %w", err)
	}
	defer rows.Close()

	groups := []suppressedFindingGroup{}
	for rows.Next() {
		var g suppressedFindingGroup
		var reason, message, severity *string
		var first, last time.Time
		if err := rows.Scan(&reason, &g.Count, &first, &last, &message, &severity); err != nil {
			return nil, fmt.Errorf("scan suppressed finding group: %w", err)
		}
		// findings.reason and .message are both nullable columns. Rendered as
		// an explicit placeholder rather than an empty string, so a reader can
		// tell "the detector reported no reason" from a UI that failed to
		// render one.
		g.Reason = "(no reason reported)"
		if reason != nil && *reason != "" {
			g.Reason = *reason
		}
		if message != nil {
			g.SampleMessage = *message
		}
		if severity != nil {
			g.Severity = *severity
		}
		g.FirstSeen = formatRFC3339(first)
		g.LastSeen = formatRFC3339(last)
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate suppressed findings: %w", err)
	}
	return groups, nil
}

// handleRemoveToleration is DELETE /api/v1/tolerations/{id}. Requires
// incident:silence. Soft-deletes the rule (removed_at/removed_by, same
// convention as grants.revoked_at) — future findings on that object resume
// opening incidents normally the next time one arrives.
func (s *Server) handleRemoveToleration(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	tolerationID := r.PathValue("id")

	var clusterID, objectKey string
	if err := rc.Tx.QueryRow(ctx,
		`UPDATE incident_tolerations SET removed_at = now(), removed_by = $2
		   WHERE id = $1 AND removed_at IS NULL
		   RETURNING cluster_id, object_key`,
		tolerationID, rc.UserID).Scan(&clusterID, &objectKey); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Toleration not found (or already removed)", "")
			return
		}
		logger.ErrorContext(ctx, "removing the toleration failed", slog.String("toleration_id", tolerationID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not remove toleration", "")
		return
	}

	capability := authz.CapIncidentSilence
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		ClusterID:       &clusterID,
		Outcome:         audit.OutcomeSuccess,
		Details: map[string]any{
			"action":       "remove_toleration",
			"tolerationId": tolerationID,
			"objectKey":    objectKey,
		},
	}); err != nil {
		logger.ErrorContext(ctx, "recording a toleration removal in the audit log failed", slog.String("toleration_id", tolerationID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
