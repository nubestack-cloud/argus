package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/events"
	"argus/internal/gateway"
	"argus/internal/logging"
	"argus/internal/orchestrator"
	"argus/internal/timeline"
)

// Promotion reconciliation: POST /api/v1/incidents/reconcile-promotion.
//
// # The gap this closes
//
// Migration 000092 gave findings evidence dimensions (signal_class /
// confidence / impact) and internal/gateway/promotion.go turned them into a
// boundary: only an active fault, on better than explicitly unverified
// evidence, carrying observed degradation, opens an incident. Risks and
// anomalies are retained as findings and nothing more.
//
// The migration's own header says it "does not ... chang[e] historical
// incident state", and that was the right call for a migration to make (see
// "Why this is not a migration" below). The consequence is that the boundary
// is true only of the future. Every incident raised before it stayed exactly
// where it was, and on the development database that was 42 of the 54 open
// incidents that have any finding history at all — the oldest from
// 2026-06-17, nearly all of them Rancher and Fleet lifecycle conditions
// (CreatorMadeOwner, BackingNamespaceCreated, EtcdIsVoter, Approved) that
// flip once during setup and then never change again. Those never resolve on
// their own, because there is nothing wrong: the object is in the state its
// controller left it in, permanently. An operator's queue full of incidents
// the product itself would no longer raise is a queue people stop reading,
// which is the same failure internal/api/incident_triage.go's header
// describes and costs more than any single missed detection.
//
// # What this does and, precisely, does not do
//
// It closes the INCIDENT — the claim that a human should look. It never
// touches a findings row. The findings are the record that the detector
// fired and what it saw; deleting or rewriting them would destroy the
// evidence for a claim about the evidence, and the response reports how many
// findings were retained specifically so that is checkable rather than
// asserted. Nothing here writes to findings at all.
//
// # Why this is not a migration
//
// Two reasons, either of which is sufficient.
//
// Structurally, a migration cannot do it. Closing an incident correctly means
// orchestrator.SetState: the legal-edge check, resolved_at, resolution_kind,
// the notification hook, and three correlation-group recomputations. That is
// Go, and internal/migrations runs SQL. A migration could only do what
// closeIncidentsForDecommission used to do and was fixed for — a raw UPDATE
// that opts out of every invariant SetState holds.
//
// Politically, it should not. A migration runs everywhere, unattended, on
// every deployment including a customer's, the first time they take an
// upgrade. What it would do there is close incidents nobody reviewed, in a
// queue nobody was watching at the time, with no actor on the audit record.
// The decision "these were raised under a rule the product has since
// retired, and I accept closing them unread" is exactly the kind a person
// should make deliberately, once, knowing the number.
//
// # Why an API route rather than an argusctl command
//
// argusctl was the other candidate and audit verify is the precedent for it,
// but that command's whole design point is being independent of the hub,
// because the hub is the thing it audits. Nothing like that applies here, and
// the price would be real: argusctl connects as a role that BYPASSES row-level
// security (see cmd/argusctl/audit.go), and it has no authenticated user, so
// a bulk close would run outside every authorization control the product has
// and land in audit_events with a null actor. For an action whose entire
// difficulty is "you are closing incidents nobody reviewed", the named human
// on the audit row is the most important thing it produces. A route also
// scopes to the caller's visible clusters through RLS for free, previews over
// the same code path that applies, and refreshes any open incident list
// through the events bus.
//
// # Why it is durable surface rather than a one-shot script
//
// This is the first tightening of the promotion boundary, not the last —
// the per-rule `class:` declarations landing in internal/agent/rules alone
// will make another set of stored findings non-promotable the moment agents
// carrying them deploy. The question "which open incidents would today's
// boundary no longer raise?" recurs every time that boundary moves, and a
// mechanism that answers it from the live gate is worth more than a script
// that hardcodes this month's answer.
//
// # Two safeguards
//
// Dry run is the default. `{"apply": true}` is required to change anything,
// and then a note is required as well, for the same reason dismissing a
// single incident requires one: this is terminal and it must carry a reason
// somebody can audit later.
//
// Incidents another writer owns are refused, not walked around.
// closeIncidentsForDecommission walks an Investigating incident through
// Detected to reach Dismissed, and is right to, because severing the tunnel
// is what makes the in-flight analysis unable to finish. Nothing here makes
// anything unable to finish. So an inProgress incident (Investigating,
// Executing, AwaitingMerge, Validating) is reported and left alone: an
// analysis lands in a few minutes, a pull request is under review by a
// person, a validation window is being watched. Re-run afterwards and it will
// be picked up if it is still a candidate.

const (
	// promotionReconcileMaxLimit bounds one call's work, in incidents.
	//
	// The number comes from closeIncidentsForDecommission's measurement on the
	// same machinery (dev Postgres, 2026-09-05): roughly 10 ms an incident up
	// to 500, and distinctly non-linear beyond it, because
	// orchestrator.SetState's three Recompute calls each scan tables that have
	// no index leading on the column they filter by. That is a property of
	// every closing transition in this codebase, not of this loop; this is
	// simply the second caller that pays it in bulk. 500 keeps one call inside
	// a few seconds and inside a request transaction. A bigger pile takes more
	// calls, which is the honest cost — never a bulk UPDATE that buys the time
	// back by opting out of the state machine.
	promotionReconcileMaxLimit = 500

	// promotionReconcileReason is the machine-readable key on both the
	// timeline detail and the audit record. There is no incidents column
	// saying why a closure happened and this is deliberately not the change
	// that adds one — the same decision decommissionClosureRecord made, and
	// for the same reason. It matters more here than there: a future
	// calibration over operator decisions (the deferred L1/L3 work) must be
	// able to exclude a bulk close nobody actually judged one at a time, and
	// this key is how it finds them.
	promotionReconcileReason = "promotion_evidence_reconciliation"
)

type promotionReconcileRequest struct {
	// Apply must be explicitly true to change anything. The zero value is a
	// preview, so a caller who forgets the field gets the safe behaviour.
	Apply bool   `json:"apply"`
	Note  string `json:"note"`
	Limit int    `json:"limit"`
}

// promotionReconcileIncident is one open incident's evidence summary — enough
// for a reader to check the verdict themselves rather than trust the count.
type promotionReconcileIncident struct {
	IncidentID     string   `json:"incidentId"`
	ClusterID      string   `json:"clusterId"`
	State          string   `json:"state"`
	OpeningReason  string   `json:"openingReason,omitempty"`
	FirstSeen      string   `json:"firstSeen"`
	Findings       int      `json:"findings"`
	FindingReasons []string `json:"findingReasons"`

	// Closed is false in a dry run, and false in an applied run for an
	// incident that was skipped; SkipReason then says why.
	Closed     bool   `json:"closed"`
	SkipReason string `json:"skipReason,omitempty"`

	// promotable is not serialized: a candidate is by definition an incident
	// whose count is zero. It is carried so the scan and the filter are the
	// same pass.
	promotable int
}

type promotionReconcileResponse struct {
	Applied bool `json:"applied"`
	// IncidentsWithFindings is how many open incidents the scan considered.
	// An open incident with no findings at all is not in it and is never a
	// candidate — an empty history is not a non-promotable one, and on the
	// development database every such row was a leftover DB-test fixture.
	IncidentsWithFindings int `json:"incidentsWithFindings"`
	Candidates            int `json:"candidates"`
	Closed                int `json:"closed"`
	SkippedInProgress     int `json:"skippedInProgress"`
	// FindingsRetained counts the finding rows attached to the incidents
	// listed below. Every one of them still exists; this endpoint never
	// deletes or rewrites a finding.
	FindingsRetained int                          `json:"findingsRetained"`
	Truncated        bool                         `json:"truncated"`
	Incidents        []promotionReconcileIncident `json:"incidents"`
	Message          string                       `json:"message"`
}

// handleReconcilePromotion is POST /api/v1/incidents/reconcile-promotion.
// Requires incident:triage — the same capability that dismisses one incident
// by hand, because this is the same decision made once for a set rather than
// a new authority. A caller sees and can close exactly the clusters their
// grants reach, enforced by RLS on rc.Tx rather than by anything in this file.
func (s *Server) handleReconcilePromotion(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()

	var req promotionReconcileRequest
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
	if req.Apply && req.Note == "" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
			"A note is required to close incidents in bulk",
			"this closes incidents nobody reviewed, and Expired has no way back except a genuine recurrence — say why, so the decision can be audited later")
		return
	}
	limit := req.Limit
	if limit <= 0 || limit > promotionReconcileMaxLimit {
		limit = promotionReconcileMaxLimit
	}

	scanned, candidates, err := promotionReconcileScan(ctx, rc.Tx)
	if err != nil {
		logger.ErrorContext(ctx, "scanning a promotion-reconcile candidate row failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not scan open incidents", "")
		return
	}

	resp := promotionReconcileResponse{
		Applied:               req.Apply,
		IncidentsWithFindings: scanned,
		Candidates:            len(candidates),
		Incidents:             []promotionReconcileIncident{},
	}
	if len(candidates) > limit {
		candidates = candidates[:limit]
		resp.Truncated = true
	}

	for _, inc := range candidates {
		resp.FindingsRetained += inc.Findings
		switch {
		// Refused, not walked around — see this file's header. The two
		// conditions are separate questions and both have to hold. Disposition
		// asks whether anyone else owns the next move (AwaitingMerge and
		// Validating both HAVE a legal Expired edge, and closing them here
		// would still be wrong). CanTransition asks the state machine itself,
		// and is the fail-closed backstop for a state added later that this
		// function has never heard of.
		case !orchestrator.RequiresAction(inc.State):
			inc.SkipReason = fmt.Sprintf("another writer owns this incident (%s); re-run once it settles", inc.State)
			resp.SkippedInProgress++
		case !orchestrator.CanTransition(inc.State, orchestrator.StateExpired):
			inc.SkipReason = fmt.Sprintf("no legal transition from %s to %s", inc.State, orchestrator.StateExpired)
			resp.SkippedInProgress++
		case !req.Apply:
			// Nothing: a dry run reports the candidate with Closed false and
			// no skip reason, which is the difference between "would close"
			// and "would be skipped".
		default:
			if err := promotionReconcileClose(ctx, rc.Tx, rc.TenantID, inc, req.Note); err != nil {
				logger.ErrorContext(ctx, "closing an incident during promotion reconcile failed", logging.IncidentID(inc.IncidentID), logging.Err(err))
				writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not close an incident", "")
				return
			}
			inc.Closed = true
			resp.Closed++
		}
		resp.Incidents = append(resp.Incidents, inc)
	}

	if req.Apply {
		capability := authz.CapIncidentTriage
		if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
			TenantID:        rc.TenantID,
			ActorID:         &rc.UserID,
			ActorAuthMethod: "jwt",
			SourceIP:        clientIP(r),
			Capability:      &capability,
			Outcome:         audit.OutcomeSuccess,
			// The incident IDs are listed, not just counted. "Be able to say
			// exactly which rows moved and why" is the whole reversibility
			// story for a bulk close: audit_events is append-only and
			// hash-chained, so this list is the durable, tamper-evident record
			// of the set. It is bounded by promotionReconcileMaxLimit, so the
			// blob cannot grow without bound.
			Details: map[string]any{
				"action":            "reconcile_incident_promotion",
				"reason":            promotionReconcileReason,
				"note":              req.Note,
				"incidentsClosed":   resp.Closed,
				"incidentsSkipped":  resp.SkippedInProgress,
				"findingsRetained":  resp.FindingsRetained,
				"closedIncidentIds": closedIncidentIDs(resp.Incidents),
			},
		}); err != nil {
			logger.ErrorContext(ctx, "recording a promotion reconcile in the audit log failed", logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
			return
		}
	}

	if req.Apply && resp.Closed > 0 {
		// One aggregate event for the batch, for the reason
		// handleDecommissionCluster states: events.Bus gives each subscriber a
		// small buffer and drops beyond it, so a few hundred per-incident
		// events would evict every other client's pending events to say the
		// same thing several hundred times.
		rc.OnCommit(func() {
			if s.events != nil {
				s.events.Publish(events.IncidentUpdated("", ""))
			}
		})
	}

	switch {
	case resp.Candidates == 0:
		resp.Message = "No open incident's finding history is entirely non-promotable under the current evidence boundary."
	case !req.Apply:
		resp.Message = fmt.Sprintf(
			"Dry run: %d open incident(s) were raised from findings this hub would no longer promote. Re-send with {\"apply\": true, \"note\": \"...\"} to close them. No finding is deleted; %d finding(s) stay attached to them.",
			resp.Candidates, resp.FindingsRetained)
	default:
		resp.Message = fmt.Sprintf(
			"Closed %d incident(s) as Expired; %d skipped because another writer owns them. None of the %d finding(s) on this candidate set was deleted, detached or rewritten.",
			resp.Closed, resp.SkippedInProgress, resp.FindingsRetained)
	}
	writeJSON(w, http.StatusOK, resp)
}

func closedIncidentIDs(incidents []promotionReconcileIncident) []string {
	ids := []string{}
	for _, inc := range incidents {
		if inc.Closed {
			ids = append(ids, inc.IncidentID)
		}
	}
	return ids
}

// promotionReconcileScan returns how many open incidents have any finding
// history, and which of those have NO finding that today's boundary would
// promote, oldest first.
//
// # Why the verdict is computed in Go
//
// The obvious implementation is a HAVING clause expressing "promotable" in
// SQL. It is the wrong one: there would then be two definitions of the
// boundary, one in internal/gateway and one here, and the first time the gate
// changed this would go on closing incidents by the old rule with nothing
// failing. So the query returns the DISTINCT evidence tuples per incident —
// a group-by, not a row per finding, so it stays small however many
// occurrences an incident has accumulated — and gateway.WouldPromoteStoredFinding
// gives every verdict.
//
// # Why the join, not a subquery on incidents
//
// An open incident with no findings at all cannot appear in this result, and
// that is the wanted behaviour: it is not evidence of a non-promotable
// history, it is the absence of any history, and closing it would be a
// different (unjustified) claim.
func promotionReconcileScan(ctx context.Context, tx pgx.Tx) (scanned int, candidates []promotionReconcileIncident, err error) {
	rows, err := tx.Query(ctx, `
		SELECT f.incident_id, i.cluster_id, i.state, i.opening_reason, i.first_seen,
		       f.reason, f.signal_class, f.confidence, f.impact, count(*)
		  FROM findings f
		  JOIN incidents i ON i.id = f.incident_id
		 WHERE i.state NOT IN ('Resolved', 'Dismissed', 'Expired')
		 GROUP BY f.incident_id, i.cluster_id, i.state, i.opening_reason, i.first_seen,
		          f.reason, f.signal_class, f.confidence, f.impact
		 ORDER BY i.first_seen, f.incident_id`)
	if err != nil {
		return 0, nil, fmt.Errorf("query open incidents' finding evidence: %w", err)
	}
	defer rows.Close()

	byIncident := map[string]*promotionReconcileIncident{}
	var order []*promotionReconcileIncident
	reasonsSeen := map[string]map[string]bool{}

	for rows.Next() {
		var incidentID, clusterID, state, class, confidence, impact string
		var openingReason, reason *string
		var firstSeen time.Time
		var count int
		if err := rows.Scan(&incidentID, &clusterID, &state, &openingReason, &firstSeen,
			&reason, &class, &confidence, &impact, &count); err != nil {
			return 0, nil, fmt.Errorf("scan finding evidence row: %w", err)
		}

		inc, ok := byIncident[incidentID]
		if !ok {
			inc = &promotionReconcileIncident{
				IncidentID: incidentID,
				ClusterID:  clusterID,
				State:      state,
				FirstSeen:  firstSeen.UTC().Format(time.RFC3339),
			}
			if openingReason != nil {
				inc.OpeningReason = *openingReason
			}
			byIncident[incidentID] = inc
			order = append(order, inc)
			reasonsSeen[incidentID] = map[string]bool{}
		}
		inc.Findings += count
		if reason != nil && *reason != "" && !reasonsSeen[incidentID][*reason] {
			reasonsSeen[incidentID][*reason] = true
			inc.FindingReasons = append(inc.FindingReasons, *reason)
		}
		if gateway.WouldPromoteStoredFinding(deref(reason), class, confidence, impact) {
			inc.promotable += count
		}
	}
	if err := rows.Err(); err != nil {
		return 0, nil, fmt.Errorf("read finding evidence rows: %w", err)
	}

	for _, inc := range order {
		if inc.promotable > 0 {
			continue
		}
		sort.Strings(inc.FindingReasons)
		candidates = append(candidates, *inc)
	}
	return len(order), candidates, nil
}

// promotionReconcileClose closes one incident, through the state machine.
//
// # Expired, decided 2026-09-07 (T2) — this function used to close as
// # Dismissed, and the comment that argued for that is superseded, not
// # deleted, below
//
// Resolved asserts the problem is gone, which nobody established — and since
// migration 000091 it is worse than merely unsupported: SetState derives
// resolution_kind on every transition into Resolved, and these incidents
// carry no succeeded execution and no merged pull request, so every one of
// them would be stamped 'self_healed'. Expired leaves it NULL, same as
// Dismissed did — honestly inapplicable.
//
// PlanRejected is a refusal of a proposed plan. There is no plan here, and it
// is not a closed state anyway.
//
// # What changed, and why the old reasoning below no longer holds
//
// This function used to close as Dismissed, on the argument that "the
// difference has no consumer a timeline detail cannot serve" — while
// explicitly deferring the real question to T2 as an open decision rather
// than answering it silently (see PROJECT.md's Decided log). T2 is now
// decided: a bulk, mechanical closure over a whole candidate SET — nobody
// looked at any one of these incidents and judged it individually — is
// exactly what StateExpired exists to name, distinctly, at the row level,
// rather than three clicks deep in a timeline detail. What makes a REAL
// Dismissed still mean "a human decided it does not matter" is that this
// function no longer produces one: only internal/api/incident_triage.go's
// individual, per-incident dismiss route does now.
//
// The route-not-state argument survives in a narrower form: what makes THIS
// closure legitimate at all is still a named person with incident:triage,
// applying deliberately, having seen the preview, with a mandatory note and
// the closed IDs on the audit chain — Expired is the honest LABEL for what
// that deliberate bulk action produces, not a claim that nobody was
// accountable for running it.
func promotionReconcileClose(ctx context.Context, tx pgx.Tx, tenantID string, inc promotionReconcileIncident, note string) error {
	if err := orchestrator.SetState(ctx, tx, inc.IncidentID, orchestrator.StateExpired); err != nil {
		return fmt.Errorf("set incident %s (%s -> %s): %w", inc.IncidentID, inc.State, orchestrator.StateExpired, err)
	}

	summary := fmt.Sprintf(
		"Expired by promotion reconciliation: all %d finding(s) on this incident are ones ARGUS would no longer raise an incident for — they are retained as findings and none was deleted. Nobody established that anything was wrong or that anything was fixed. Note: %s",
		inc.Findings, note)
	return timeline.Record(ctx, tx, timeline.Event{
		TenantID: tenantID, ClusterID: inc.ClusterID, IncidentID: inc.IncidentID,
		Type:    timeline.EventIncidentExpired,
		Summary: summary,
		Detail: map[string]any{
			"reason":           promotionReconcileReason,
			"fromState":        inc.State,
			"findingsRetained": inc.Findings,
			"findingReasons":   inc.FindingReasons,
			"note":             note,
		},
	})
}
