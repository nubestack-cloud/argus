package orchestrator

// PROJECT.md T6 and T7 — feeding operator outcomes back into promotion, and
// making what was learned survive the incident that learned it. Both live
// here, in one file, because they share a mechanism: everything below reads
// or writes incident_tolerations/remediation_approval_decisions keyed on
// incidents.object_key, and both are triggered from the ONE place an
// incident's lifecycle ever changes (SetState, db.go) or ONE place a new
// plan is ever persisted (ApplyAnalysisResult, db.go).
//
// # T6 — suppression, by extending tolerations, not building a second path
//
// Measured 2026-09-17: 302,966 findings produced 111 incidents, 74% of which
// closed Dismissed or Expired — closed, but with nothing about that closure
// changing whether the identical finding shape opens another incident
// tomorrow. Tolerations (migration 000041) already exist for exactly this
// problem when a human notices it and asks for it explicitly
// (POST /incidents/{id}/tolerate); this makes the SAME mechanism fire
// automatically on the two closures that already say "this needs no action"
// or "nobody reviewed this occurrence" — see suppressRecurrenceOnClose.
// Deliberately not a new table, a new column on findings, or a learned
// score: the owner's constraint on T6 is "inspectable and overridable,
// never an opaque learned score," and a toleration row already is exactly
// that — an operator reads incident_tolerations.note in plain English on
// TolerationsPage and removes the row to undo it, the same DELETE
// /tolerations/{id} a human-created rule already uses.
//
// # T7 — a recurrence links, and a rejection reason reaches something that
// acts on it
//
// The owner's decision: a recurrence opens a NEW incident carrying a link to
// the prior ones (internal/api/incidents.go's priorIncidentLinksFor computes
// that link at read time via a join on object_key), and Resolved stays
// terminal — no edge is added out of it. demoteIfPreviouslyRejected below is
// the other half: the specific gap PROJECT.md T7 names ("0 rejection reasons
// have ever been read back") closed by making a rejection reason change a
// real decision on the NEXT incident for the same object, not just something
// a human can scroll back and find.
import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/domain"
	"argus/internal/logging"
	"argus/internal/remediation"
)

// autoTolerationWindowByState bounds T6's suppression — the answer to "a
// dismissal that silences a finding shape forever will eventually hide a
// real fault," stated as a concrete, visible number rather than left
// implicit. Keyed by which closed state triggered it, because the two
// closures are not the same kind of evidence:
//
//   - StateDismissed is a considered human verdict on THIS incident
//     (incident_triage.go's own doc comment: "a named person looked at this
//     specific incident and decided it did not need action") — it earns the
//     longer window.
//   - StateExpired is explicitly the opposite (StateExpired's own doc
//     comment: "a mechanical judgement about a whole candidate SET... never
//     a considered verdict on THIS one") — it earns a much shorter window,
//     just enough to stop an immediate re-open storm right after a bulk
//     reconciliation sweep, without pretending anyone actually reviewed this
//     specific case.
//
// Either way the bound is real: FindingTolerated (internal/gateway/
// toleration.go) already refuses to match a row whose expires_at has passed,
// unchanged by this task, so a genuine regression that outlives this window
// re-opens an incident normally, and an operator can always remove the rule
// sooner via the same DELETE /tolerations/{id} a human-created rule uses.
var autoTolerationWindowByState = map[string]time.Duration{
	StateDismissed: 14 * 24 * time.Hour,
	StateExpired:   3 * 24 * time.Hour,
}

// suppressRecurrenceOnClose is T6's writer, called from SetState's
// Dismissed/Expired branch (db.go) with the row it just locked and closed
// already in hand. It creates one incident_tolerations row (migration
// 000041, extended by 000112's auto_created flag) scoped to this incident's
// own object and the exact reasons its findings carried — never broader —
// so internal/gateway/toleration.go's FindingTolerated (completely
// unchanged) suppresses the identical finding shape on the identical object
// the next time it fires, exactly as it already does for a human-created
// rule.
//
// Never creates a SECOND active rule for the same (cluster, object): a human
// who tolerated this object explicitly in the SAME request
// (handleTolerateIncident inserts its row before calling SetState ->
// Dismissed, in one transaction, so that INSERT is already visible to the
// EXISTS check below) must not be shadowed by an auto-created row saying the
// same thing with a shorter, expiring bound — and a still-active earlier
// auto-suppression on this object needs no second row either.
//
// Failure anywhere here is logged and swallowed, never returned: this is an
// enhancement layered on top of closing an incident, and an incident must
// stay closeable even if this extra write fails.
func suppressRecurrenceOnClose(ctx context.Context, tx pgx.Tx, incidentID, tenantID, clusterID, newState string, objectKey *string) {
	window, ok := autoTolerationWindowByState[newState]
	if !ok {
		return
	}
	if objectKey == nil || strings.TrimSpace(*objectKey) == "" {
		// Same rule handleTolerateIncident enforces for a human-created
		// rule: a fingerprint-only incident names no object, so there is
		// nothing stable to scope a suppression rule to.
		return
	}

	var alreadyCovered bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(
		   SELECT 1 FROM incident_tolerations
		    WHERE cluster_id = $1 AND object_key = $2 AND removed_at IS NULL
		      AND (expires_at IS NULL OR expires_at > now())
		 )`,
		clusterID, *objectKey).Scan(&alreadyCovered); err != nil {
		logger.ErrorContext(ctx, "checking for an existing toleration failed; not auto-suppressing",
			logging.IncidentID(incidentID), logging.ClusterID(clusterID),
			slog.String("object_key", *objectKey), logging.Err(err))
		return
	}
	if alreadyCovered {
		return
	}

	reasons, err := findingReasonsFor(ctx, tx, incidentID)
	if err != nil {
		logger.ErrorContext(ctx, "collecting this incident's finding reasons failed; not auto-suppressing",
			logging.IncidentID(incidentID), logging.ClusterID(clusterID), logging.Err(err))
		return
	}
	if len(reasons) == 0 {
		// Every incident is expected to have at least one finding; failing
		// safe (no rule at all) is the right response to an unexpected empty
		// set, not guessing a wildcard "tolerate everything on this object"
		// rule from nothing.
		return
	}

	expiresAt := time.Now().Add(window)
	verdict, basis := "Dismissed", "a person reviewed this incident and decided it needs no action"
	if newState == StateExpired {
		verdict, basis = "Expired", "this incident aged out in a bulk reconciliation sweep — nobody reviewed this specific occurrence individually"
	}
	note := fmt.Sprintf(
		"Automatically suppressed: incident %s closed %s on %s — %s. "+
			"Future occurrences of %s on this object will not open a new incident until %s, unless this rule is removed first.",
		incidentID, verdict, time.Now().UTC().Format(time.RFC3339), basis,
		strings.Join(reasons, ", "), expiresAt.UTC().Format(time.RFC3339))

	tolerationID := domain.NewID(domain.PrefixToleration)
	if _, err := tx.Exec(ctx,
		`INSERT INTO incident_tolerations
		   (id, tenant_id, cluster_id, object_key, reasons, note, incident_id, created_by, auto_created, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, true, $8)`,
		tolerationID, tenantID, clusterID, *objectKey, reasons, note, incidentID, expiresAt); err != nil {
		logger.ErrorContext(ctx, "creating the automatic toleration failed",
			logging.IncidentID(incidentID), logging.ClusterID(clusterID), logging.Err(err))
		return
	}
	logger.InfoContext(ctx, "auto-suppressed future occurrences on this object",
		logging.IncidentID(incidentID), logging.ClusterID(clusterID),
		slog.String("closed_as", newState), slog.String("object_key", *objectKey),
		slog.Time("expires_at", expiresAt), slog.String("reasons", strings.Join(reasons, ", ")))
}

// findingReasonsFor is the sorted, deduplicated set of reasons this
// incident's own findings carry — the same default a human-created
// toleration falls back to (internal/api/tolerations.go's
// resolveToleranceReasons) when no explicit reason list is given, computed
// independently here since internal/orchestrator cannot import internal/api
// (that would be the reverse of this codebase's whole package layering).
// Sorted so the stored array — and therefore the note text, and any test
// comparing it — is deterministic rather than depending on scan order.
func findingReasonsFor(ctx context.Context, tx pgx.Tx, incidentID string) ([]string, error) {
	rows, err := tx.Query(ctx,
		`SELECT DISTINCT reason FROM findings WHERE incident_id = $1 AND reason IS NOT NULL AND reason <> ''`,
		incidentID)
	if err != nil {
		return nil, fmt.Errorf("query finding reasons: %w", err)
	}
	defer rows.Close()

	var reasons []string
	for rows.Next() {
		var reason string
		if err := rows.Scan(&reason); err != nil {
			return nil, fmt.Errorf("scan finding reason: %w", err)
		}
		reasons = append(reasons, reason)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate finding reasons: %w", err)
	}
	sort.Strings(reasons)
	return reasons, nil
}

// demoteIfPreviouslyRejected is T7's other half: "a rejection reason reaches
// something that acts on it." It only ever matters for decision.Outcome ==
// AutoApprove, because that is the one outcome
// internal/api/unattended.go's sweeper can execute with no human looking at
// it — every other outcome already reaches a human via AwaitingApproval.
//
// If a human already rejected the identical action type
// (remediation_approval_decisions.verdict = 'rejected') on a DIFFERENT
// incident for this SAME object, this downgrades the outcome to
// NeedsApproval — the plan still reaches a human, exactly as it would if
// this incident had never gated to AutoApprove at all; it just cannot skip
// that human a second time on the strength of an incident's own gate
// evaluation alone. It never blocks the plan outright and never touches a
// Blocked/NeedsApproval decision, both of which already reach a human by a
// different route.
//
// Deterministic and inspectable, per T6's own "never an opaque learned
// score" constraint applied here too: the downgraded Decision.Reason names
// the prior incident and quotes its stored rejection reason verbatim. There
// is no count, no decay, no threshold — one matching prior rejection is
// enough, forever, until a human approves the SAME action type on this
// object at least once (at which point a later query here finds an
// approval, not just a rejection, and — see the query's own WHERE clause —
// only 'rejected' verdicts are matched, so an approval does not re-arm
// anything; it simply means the next AutoApprove candidate has nothing to
// downgrade against).
//
// Returns demoted=false, note="" when nothing changed, so a caller can
// decide whether to touch Advancement.Reason (which is a separate field,
// already computed by the time this runs — see ApplyAnalysisResult's call
// site) only when something actually did.
func demoteIfPreviouslyRejected(ctx context.Context, tx pgx.Tx, incidentID string, plan *remediation.RemediationPlan, decision *remediation.Decision) (demoted bool, note string) {
	if plan == nil || decision == nil || decision.Outcome != remediation.AutoApprove {
		return false, ""
	}

	// The workload key too: a Deployment's pods are renamed by every rollout,
	// so a rejection recorded against one pod must still demote the same
	// action proposed for its replacement. Matching more here only ever sends
	// a plan to a human — the safe direction for this check.
	var objectKey, workloadKey *string
	if err := tx.QueryRow(ctx, `SELECT object_key, workload_key FROM incidents WHERE id = $1`, incidentID).Scan(&objectKey, &workloadKey); err != nil {
		logger.ErrorContext(ctx, "reading object_key failed; leaving auto-approve as decided",
			logging.IncidentID(incidentID), logging.Err(err))
		return false, ""
	}
	if objectKey == nil || strings.TrimSpace(*objectKey) == "" {
		return false, ""
	}
	workloadKeyOrEmpty := ""
	if workloadKey != nil {
		workloadKeyOrEmpty = *workloadKey
	}

	var priorIncidentID, reason string
	err := tx.QueryRow(ctx,
		`SELECT d.incident_id, COALESCE(d.reason, '')
		   FROM remediation_approval_decisions d
		   JOIN remediation_recommendations r ON r.id = d.recommendation_id
		   JOIN incidents i ON i.id = d.incident_id
		  WHERE d.verdict = 'rejected' AND r.action_type = $1
		    AND (i.object_key = $2 OR ($4 <> '' AND i.workload_key = $4)) AND d.incident_id <> $3
		  ORDER BY d.created_at DESC
		  LIMIT 1`,
		string(plan.ActionType), *objectKey, incidentID, workloadKeyOrEmpty,
	).Scan(&priorIncidentID, &reason)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return false, ""
	case err != nil:
		logger.ErrorContext(ctx, "checking for a prior rejection failed; leaving auto-approve as decided",
			logging.IncidentID(incidentID), logging.Err(err))
		return false, ""
	}

	original := decision.Reason
	decision.Outcome = remediation.NeedsApproval
	decision.Reason = fmt.Sprintf(
		"downgraded from auto-approve: a %s plan for this same object was REJECTED on incident %s (%q) — a human must approve this again rather than an unattended repeat of a refused fix. The gate's own verdict was: %s",
		plan.ActionType, priorIncidentID, reason, original)
	logger.WarnContext(ctx, "downgraded a plan from AutoApprove to NeedsApproval: the same action was rejected before on this object",
		logging.IncidentID(incidentID), slog.String("action_type", string(plan.ActionType)),
		slog.String("prior_incident_id", priorIncidentID), slog.String("prior_rejection_reason", reason))
	return true, decision.Reason
}
