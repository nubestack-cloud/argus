package api

import (
	"encoding/json"
	"io"
	"net/http"

	"argus/internal/gitops"
)

// POST /api/v1/incidents/{id}/repository-change/preview
//
// What a pull request WOULD contain: for every file in the request, the diff
// ARGUS computed against the pinned synced commit, what it checked, and what it
// could not check — with nothing branched, committed or opened.
//
// # Why this exists
//
// An operator authorising a change to the repository that runs their cluster
// should see the change first; and every refusal this path can make — a
// forbidden path, a file outside the synced directory, unparseable YAML, drift
// since the synced commit — was otherwise reachable only by attempting the
// write. A refusal that costs a branch is a worse refusal than one that costs a
// request.
//
// It is also where a multi-file change is assembled: a client calls this after
// each edit, with every file it has so far, and shows the operator the whole
// set of diffs before anything is proposed.
//
// # It runs the same code as the commit, deliberately
//
// gitops.PreviewChanges and gitops.ProposeChanges share prepareChanges
// verbatim; the preview simply stops where the other cuts a branch. A preview
// computed by a parallel path would be a claim about what a commit would do.
// This is the computation the commit performs.
//
// # Capabilities
//
// Gated on the same three the open route requires (repo:write,
// remediation:approve, remediation:execute:pr) rather than a narrower read-only
// set. That looks over-strict for something that writes nothing, and is
// deliberate: a preview reads repository content at a specific commit and
// renders it back, so anyone who can call it can read any file the binding can
// reach under the synced directory. Granting that to a strictly wider audience
// than the people who may open the pull request would be a new exposure in
// exchange for nothing.
type repositoryPreviewResponse struct {
	IncidentID     string `json:"incidentId"`
	Repository     string `json:"repository"`
	SyncedRevision string `json:"syncedRevision"`
	BaseBranch     string `json:"baseBranch"`
	// Branch is the branch the change WOULD be opened on, so a client can warn
	// about an existing one before the operator commits to anything.
	Branch       string                     `json:"branch"`
	Verification repositoryChangeVerifiedAs `json:"verification"`
	// RenderEvidence is BACKLOG.md F28 finding 2's fix: BACKLOG.md F26 built
	// the render-and-diff check, but it only ever ran on the two paths that
	// OPEN a pull request — after a human had already approved, or on the
	// direct-edit path — never on the diff a human actually reviews BEFORE
	// approving. This is the exact same map shape
	// renderEvidenceAuditFields already produces for the audit/timeline
	// record (reused rather than re-typed, so the two surfaces can never
	// silently disagree about what a given evidence result means):
	// {"attempted": false} when rendering was never attempted;
	// {"attempted": true, "degraded": "..."} when it was tried and could
	// not produce a usable answer — including, per finding 2's own honesty
	// requirement, whenever the source is a Helm chart and no values-file
	// list is available, since a defaults-only render cannot confirm the
	// real deployed configuration; or {"attempted": true, "rendererKind":
	// ..., "effective": ..., "objectsCompared": ..., "objectsChanged": ...,
	// "summary": ...} for a real, checked answer.
	RenderEvidence map[string]any `json:"renderEvidence"`
}

func (s *Server) handlePreviewRepositoryChange(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	incidentID := r.PathValue("id")

	var req repositoryChangeRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxRepositoryChangeBytes)).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}
	if title, detail, ok := req.validate(); !ok {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", title, detail)
		return
	}

	// Deliberately NOT refused for a closed incident, unlike the open route: a
	// preview writes nothing, and being able to look at what ARGUS would have
	// proposed for an incident somebody has since resolved is useful rather
	// than dangerous.
	resolved, ok := s.resolveRepoChangeTarget(w, r, rc, incidentID)
	if !ok {
		return
	}

	// BACKLOG.md F28 finding 2: the same evaluateRenderEffect call
	// handleOpenRepositoryChange makes (repository_change.go), computed here
	// too so the diff an operator reviews BEFORE approving carries the
	// identical "is this an effective change" evidence F26 already computes
	// for the post-approval paths, rather than that evidence appearing for
	// the first time only after they have already clicked approve. Never a
	// reason to refuse the preview — see evaluateRenderEffect's own doc
	// comment for why its signature has no error return at all.
	renderEvidence := s.evaluateRenderEffect(ctx,
		scopeForTarget(ctx, rc.Tx, s.scmStore, incidentID, resolved.target),
		req.fileEdits(), nil)

	preview, err := gitops.PreviewChanges(ctx, resolved.provider, resolved.repo, gitops.ProposalInput{
		Object:         resolved.object,
		Files:          req.fileEdits(),
		SyncedRevision: resolved.target.Revision,
		SourceDir:      resolved.target.Path,
		BaseBranch:     baseBranchFor(resolved.binding, resolved.target),
		ForbiddenPaths: resolved.binding.WriteScope.ForbiddenPaths,
		RenderEvidence: renderEvidence,
	})
	if err != nil {
		writeRepositoryChangeFailure(w, err)
		return
	}

	writeJSON(w, http.StatusOK, repositoryPreviewResponse{
		IncidentID:     incidentID,
		Repository:     resolved.target.RepoURL,
		SyncedRevision: preview.SyncedRevision,
		BaseBranch:     baseBranchFor(resolved.binding, resolved.target),
		Branch:         gitops.BranchName(resolved.binding.FixBranchPattern, incidentID),
		Verification:   toRepositoryChangeVerification(preview.Verification),
		RenderEvidence: renderEvidenceAuditFields(preview.RenderEvidence),
	})
}
