package api

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/authz"
	"argus/internal/execution"
	"argus/internal/logging"
	"argus/internal/objdiff"
	"argus/internal/orchestrator"
	"argus/internal/remediation"
)

// preflightResponse is what an approver gets before deciding.
type preflightResponse struct {
	IncidentID string `json:"incidentId"`
	PlanID     string `json:"planId"`
	// AttestedAt is when the cluster accepted the rehearsal. An attestation is
	// a statement about a moment, so the moment is part of it.
	AttestedAt time.Time `json:"attestedAt"`
	// Target is the object the change will actually be applied to, which for a
	// pod-template action is NOT the object the finding named — a CrashLooping
	// Pod's fix lands on its Deployment. Reported because an approver looking
	// at a diff needs to know whose fields these are.
	Target preflightTarget `json:"target"`
	// Diff is the classified field-level diff. Present unless DiffUnavailable
	// explains why not.
	Diff *objdiff.Result `json:"diff,omitempty"`
	// DiffUnavailable says, in plain language, why there is no diff — the
	// rehearsal still succeeded. Never both this and Diff.
	DiffUnavailable string `json:"diffUnavailable,omitempty"`
	// NoChange is true when the rehearsal was accepted but nothing would
	// actually change. Surfaced explicitly rather than left as an empty diff,
	// because it usually means the plan is stale — someone already applied the
	// fix — and "nothing to do" is a different decision from "here is what
	// happens".
	NoChange bool `json:"noChange"`
	// BlockedBy lists guardrail refusals that approving will additionally
	// require the operator to confirm. Advisory here by design: the preflight
	// deliberately shows the diff for a plan a bare approval would refuse,
	// because a GitOps-managed object is exactly the case where seeing the
	// change matters most.
	BlockedBy []string `json:"blockedBy,omitempty"`
	// Notes carries non-blocking context the approver should see, e.g. a
	// RevertContainerImage resolving to a mutable tag rather than a digest.
	Notes []string `json:"notes,omitempty"`
}

type preflightTarget struct {
	GVK       string `json:"gvk"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// handlePreflightIncident rehearses a pending plan and returns the diff the
// cluster itself says would result.
//
// # Why this is a POST, and why it is not automatic
//
// It is a POST because it is not free: a server-side dry run traverses the full
// authorisation and admission chain, which means a mutating webhook without
// `sideEffects: NoneOnDryRun` can act on it (DESIGN.md §18.3). Nothing is
// persisted and nothing of ARGUS's is committed, but a GET that quietly sends
// requests into a customer's cluster would be dishonest about that.
//
// It is explicitly operator-invoked rather than folded into the approvals list
// for a blunter reason: that list refetches on its own. Rehearsing on render
// would fire a patch request per pending plan on every refresh, for as long as
// anyone left the page open — a self-inflicted load pattern on the customer's
// API server, and a stream of webhook invocations nobody asked for. The rate
// changed with PROJECT.md P16 (the list is now refreshed by the live event
// stream, with a 60s fallback poll rather than a 5s one) and the argument did
// not: it is per REFRESH, and an event arrives precisely when something about
// that queue changed.
// So the diff is something a reviewer asks for when they are reviewing.
//
// # Capability
//
// Gated identically to approving: the route requires `remediation:approve` and
// this handler re-applies the same per-action-type gate from planApprovalGates.
// Anyone who cannot approve a plan cannot make ARGUS send a dry-run patch on its
// behalf. A read-only "let me see the diff without being able to act on it"
// role is imaginable, but it would be a *wider* audience for a call with a
// cluster-side effect, so it is not the default.
func (s *Server) handlePreflightIncident(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	incidentID := r.PathValue("id")
	ctx := r.Context()

	state, err := incidentState(ctx, rc.Tx, incidentID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Incident not found", "")
			return
		}
		logger.ErrorContext(ctx, "looking up the incident to preflight failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up incident", "")
		return
	}
	if state != orchestrator.StateAwaitingApproval {
		// Shares approvals.go's explanation, so an AwaitingMerge incident gets the
		// same true sentence here as it does from approve and reject — three
		// different generic "wrong state" lines for one situation is how an
		// operator ends up believing the product is broken.
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/invalid-state",
			"Incident is not awaiting approval", wrongStateForApprovalDetail(state, "previewed"))
		return
	}

	planID, clusterID, err := latestRecommendationForIncident(ctx, rc.Tx, incidentID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "No plan found for this incident", "")
			return
		}
		logger.ErrorContext(ctx, "looking up the incident's plan failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up plan", "")
		return
	}

	plan, err := execution.LoadRecommendationPlan(ctx, rc.Tx, planID)
	if err != nil {
		logger.ErrorContext(ctx, "loading the plan to preflight failed", slog.String("plan_id", planID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not load the plan for this incident", "")
		return
	}

	// The same second gate approving applies. Deliberately the identical table
	// rather than a parallel check, so the two cannot drift into a state where
	// someone can preview what they could not approve.
	gate, ok := planApprovalGates[plan.ActionType]
	if !ok {
		logger.ErrorContext(ctx, "plan has an action type with no approval gate defined; refusing to preflight it",
			slog.String("plan_id", planID), slog.String("action_type", string(plan.ActionType)))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal",
			"Could not determine which capability previewing this plan requires", "")
		return
	}
	// Scope-aware, not just capability-aware (BACKLOG S1). Holding
	// remediation:execute:inplace on one cluster is not holding it on another, and
	// until this check existed a grant the UI displayed as "Cluster: rke2"
	// authorised the whole fleet. The route-level requireCapability above cannot do
	// this — it does not know which cluster the request touches — so the per-plan
	// gate is where it belongs.
	allowed, err := authz.HasCapabilityForCluster(ctx, rc.Tx, rc.Grants, gate.capability, clusterID)
	if err != nil {
		logger.ErrorContext(ctx, "resolving cluster-scoped capability failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not resolve the scope of your permissions", "")
		return
	}
	if !allowed {
		s.recordCapabilityDenial(ctx, rc, gate.capability, clientIP(r))
		writeProblem(w, http.StatusForbidden, "https://argus.io/errors/scope-denied",
			"Missing required capability",
			fmt.Sprintf("previewing this %s plan requires capability %q in addition to %q, because the preview asks the cluster to evaluate the change",
				plan.ActionType, gate.capability, authz.CapRemediationApprove))
		return
	}

	// OpenPR has no cluster patch to rehearse — there is nothing to dry-run,
	// and saying so is better than rehearsing something unrelated.
	if plan.ActionType == remediation.ActionOpenPR {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/not-implemented",
			"This plan cannot be previewed",
			"A GitOps pull-request plan makes no change to the cluster, so there is nothing for the cluster to evaluate. Preview applies to plans that patch a live object.")
		return
	}

	clusterName := clusterDisplayName(ctx, rc.Tx, clusterID)
	if !s.gw.IsConnected(clusterID) {
		writeProblem(w, http.StatusServiceUnavailable, "https://argus.io/errors/cluster-unreachable",
			"Preview could not run",
			fmt.Sprintf("Preview could not run: %s has no live agent connection right now, so the change cannot be evaluated. Nothing has been recorded or changed — try again once the cluster reconnects.", nameOrID(clusterName, clusterID)))
		return
	}
	// The rehearsal is a dry-run WRITE, so it goes to the remediation agent
	// (tunnel.RoleForTool). Without one, the gateway's own error names the
	// cluster by id and the dry-run wrapper describes an execution that was
	// never asked for — so it is answered here, in preview terms.
	if reason := s.remediationAgentBlockedReason(plan.ActionType, clusterID, clusterName); reason != "" {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/no-remediation-agent",
			"Preview could not run", "Preview could not run: "+reason)
		return
	}

	// execution.Overrides{} — the zero value, deliberately and load-bearingly.
	// Guardrail confirmation tokens are single-use and are burned by Redeem
	// before it validates anything, so forwarding the operator's token here
	// would leave their real approval refused by the guardrail they had just
	// confirmed. execution.PrepForPreflight makes that structural rather than a matter of
	// remembering to pass an empty struct, but both are stated because this is
	// the one destructive thing in the whole preparation path.
	prep, err := s.exec().PreparePlan(ctx, scopeOf(rc), incidentID, planID, clusterID, plan, execution.Overrides{}, execution.PrepForPreflight)
	if err != nil {
		// Includes the dry-run gate's own refusal, which is the most useful
		// outcome this endpoint has: the operator learns the cluster will
		// reject the change, in the cluster's words, without having approved
		// anything. Reported as 422 rather than 502 — the plan is the problem,
		// not the transport.
		writeProblem(w, http.StatusUnprocessableEntity, "https://argus.io/errors/preflight-failed",
			"Preview could not run", "Preview could not run: "+err.Error())
		return
	}

	resp := preflightResponse{
		IncidentID: incidentID,
		PlanID:     planID,
		AttestedAt: prep.Attestation.At,
		Target:     preflightTarget{GVK: prep.TargetGVK, Namespace: prep.TargetNamespace, Name: prep.TargetName},
		BlockedBy:  prep.BlockedBy,
	}
	if prep.DigestWarning != "" {
		resp.Notes = append(resp.Notes, prep.DigestWarning)
	}

	switch {
	case len(prep.Attestation.Object) == 0:
		// The gate succeeded; only the diff payload is missing (the object
		// exceeded the agent's size cap, or could not be marshaled). Said
		// plainly, because "no diff" must never be read as "no change".
		resp.DiffUnavailable = "The cluster accepted this change, but the resulting object was too large to return for a comparison. The change is still valid — there is just nothing to display."
	case len(prep.LiveObject) == 0:
		resp.DiffUnavailable = "The cluster accepted this change, but its current state could not be read for comparison."
	default:
		diff, diffErr := objdiff.Compute(prep.LiveObject, prep.Attestation.Object, prep.Attestation.Patch)
		if diffErr != nil {
			logger.WarnContext(ctx, "computing the preflight diff failed", logging.IncidentID(incidentID), logging.Err(diffErr))
			resp.DiffUnavailable = "The cluster accepted this change, but the comparison could not be computed."
		} else {
			resp.Diff = &diff
			resp.NoChange = diff.Empty()
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// nameOrID is a cluster's display name for a sentence shown to a person,
// falling back to its id only when it has no name.
func nameOrID(name, id string) string {
	if name != "" {
		return name
	}
	return id
}
