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
	"argus/internal/gitops"
	"argus/internal/logging"
	"argus/internal/orchestrator"
	"argus/internal/remediation"
	"argus/internal/scm"
)

// POST /api/v1/incidents/{id}/repository-change — the pull-request remediation
// channel.
//
// # The shape of the request
//
// A repository change is a set of WHOLE FILES: `{"files": [{"path": "...",
// "content": "..."}], "reason": "..."}`. Not a field and a value — that grammar
// was removed on 2026-08-28 because it could express a small fraction of the
// fixes that actually need this channel (see internal/gitops/files.go). One
// file or several, each carrying the content the file should end up holding.
// ARGUS computes the diff.
//
// # Why it is a separate route rather than part of approve
//
// POST .../approve decides the fate of a stored plan, whose params the MODEL
// wrote. This endpoint instead takes the files and their content in the
// REQUEST: the human states exactly what they are authorising, and the audit
// record is of specific files going to specific content. DESIGN.md §18.3's
// rule — the model proposes, non-LLM code decides — is easier to hold this way
// round, and both routes converge on the same gitops.ProposeChanges, which is
// where every security refusal lives.
//
// The hub still refuses to take the caller's word for the things it can check
// itself: the repository, the directory and the synced commit come from the
// incident's stored ownership, never from the request; every path is confined
// to the directory the controller reports syncing and checked against the
// forbidden-path denylist; every file is read at the pinned commit and
// committed as a compare-and-swap against the blob that was read.
//
// # Capability gate
//
// Three capabilities, and the reasoning for each:
//
//   - `repo:write` (route) — this writes to a registered repository, the same
//     capability that registers one.
//   - `remediation:approve` (route) — this authorises a remediation, and every
//     other route that does requires it.
//   - `remediation:execute:pr` (route) — the PR channel's own execution
//     capability. approvals.go's planApprovalGates already maps ActionOpenPR to
//     exactly this, and lld/02-authz-spec.md §6's headline example is a
//     principal who "may approve PRs but never touch a cluster in place".
//
// All three are checked at the route (server.go) by nesting requireCapability,
// and again per-cluster inside resolveRepoChangeTarget, which is the only place
// that knows which cluster the incident belongs to.

// repositoryChangeFile is one file's whole proposed content, on the wire.
type repositoryChangeFile struct {
	// Path is relative to the repository root. It is a request, never an
	// authorisation: it is confined to the synced directory and checked against
	// the denylist before anything is read or written.
	Path string `json:"path"`
	// Content is the whole file exactly as it should read after the change —
	// not a diff, not a patch. Must be empty when Delete is true.
	Content string `json:"content"`
	// Delete asks for Path to be removed from the repository entirely,
	// instead of written with Content — BACKLOG.md "still open" #2, the same
	// distinct field remediation.ProposedFile.Delete uses for the model-
	// proposed path, offered here too so an operator driving this endpoint
	// by hand has the identical capability. See that type's doc comment for
	// why this is not expressed as empty Content.
	Delete bool `json:"delete,omitempty"`
}

// repositoryChangeRequest is the proposed change. The repository, the directory
// and the commit are deliberately NOT in it — see this file's header.
type repositoryChangeRequest struct {
	// Files is the change. At least one entry; a file that does not exist at
	// the synced commit is created.
	Files []repositoryChangeFile `json:"files"`
	// Reason is why this change is being made, quoted into the pull request
	// body. Optional; when absent the incident's own analysis is used if it has
	// a root cause statement.
	Reason string `json:"reason"`
}

func (req repositoryChangeRequest) validate() (title, detail string, ok bool) {
	if len(req.Files) == 0 {
		return "At least one file is required",
			`A repository change is one or more whole files, e.g. {"files": [{"path": "envs/prod/deployment.yaml", "content": "apiVersion: apps/v1\n..."}]}. Fetch a file's current content first (GET .../repository-change/file), then submit your edited version of it.`,
			false
	}
	for _, f := range req.Files {
		if strings.TrimSpace(f.Path) == "" {
			return "Every file must name a path",
				"One of the files in this request has no path, so ARGUS cannot say what it is proposing to change.", false
		}
		if f.Delete {
			if strings.TrimSpace(f.Content) != "" {
				return "A file cannot be both deleted and given new content",
					"`" + f.Path + "` was sent with \"delete\": true and non-empty content. Send one or the other.", false
			}
			continue
		}
		if strings.TrimSpace(f.Content) == "" {
			return "Every file must carry its whole new content",
				"`" + f.Path + "` was sent with no content. Send the file as you want it to read, or set \"delete\": true to remove it entirely.", false
		}
	}
	return "", "", true
}

func (req repositoryChangeRequest) fileEdits() []gitops.FileEdit {
	out := make([]gitops.FileEdit, 0, len(req.Files))
	for _, f := range req.Files {
		out = append(out, gitops.FileEdit{Path: strings.TrimSpace(f.Path), Content: []byte(f.Content), Delete: f.Delete})
	}
	return out
}

// repositoryChangeResponse is what the caller gets back. Verbose on purpose:
// the per-file diff and the advisories are the product here, and a client that
// only showed "PR opened" would throw away the part that makes the PR
// reviewable.
type repositoryChangeResponse struct {
	IncidentID    string `json:"incidentId"`
	Repository    string `json:"repository"`
	PullRequestNo int    `json:"pullRequestNumber"`
	URL           string `json:"url"`
	Branch        string `json:"branch"`
	BaseBranch    string `json:"baseBranch"`
	// CommitSHA is the branch head; Commits is one SHA per file committed.
	CommitSHA string   `json:"commitSha"`
	Commits   []string `json:"commits"`
	// SyncedRevision is the commit the files were READ at — the one the GitOps
	// controller reports as applied, not the branch head.
	SyncedRevision string                     `json:"syncedRevision"`
	Verification   repositoryChangeVerifiedAs `json:"verification"`
	// Warning is set when the PR exists but something non-fatal did not (today,
	// only a labelling failure). Non-empty means "read this", not "it failed".
	Warning string `json:"warning,omitempty"`
	Message string `json:"message"`
}

// repositoryChangeFileResult is one file's outcome, on the wire.
type repositoryChangeFileResult struct {
	Path string `json:"path"`
	// Created is true when the file did not exist at the synced commit.
	Created bool `json:"created"`
	// Deleted is true when this change REMOVES the file entirely rather
	// than writing it — BACKLOG.md "still open" #2.
	Deleted bool `json:"deleted"`
	// Unchanged is true when the submitted content already matched the file.
	// Such a file is reported and NOT committed — an operator who opened three
	// files and edited one is a normal thing to submit.
	Unchanged     bool     `json:"unchanged"`
	Diff          string   `json:"diff"`
	LinesAdded    int      `json:"linesAdded"`
	LinesRemoved  int      `json:"linesRemoved"`
	LineCount     int      `json:"lineCount"`
	DocumentCount int      `json:"documentCount"`
	Parsed        bool     `json:"parsed"`
	Checks        []string `json:"checks"`
	// Advisories are the things a reviewer must check because ARGUS could not:
	// a templated file it did not render, a changed document count, an object
	// identity that moved. A client MUST render these next to the diff.
	Advisories []string `json:"advisories"`
}

// repositoryChangeVerifiedAs is what ARGUS checked, per file and in aggregate.
type repositoryChangeVerifiedAs struct {
	Files        []repositoryChangeFileResult `json:"files"`
	FilesChanged int                          `json:"filesChanged"`
	LinesAdded   int                          `json:"linesAdded"`
	LinesRemoved int                          `json:"linesRemoved"`
	Checks       []string                     `json:"checks"`
	Advisories   []string                     `json:"advisories"`
	// Label is §11.4's verification label, and Caveat states in words what that
	// label withholds. Both are in the response as well as on the PR so a UI
	// shows the same caveat the reviewer will see.
	Label  string `json:"label"`
	Caveat string `json:"caveat"`
}

// changeCaveat is the sentence stating what ARGUS did NOT establish. It is
// deliberately blunt, and deliberately the same words the pull-request body
// carries: a whole-file change makes no "only this moved" claim at all, and an
// operator authorising one must read the diff.
const changeCaveat = "ARGUS computed these diffs from the files at the pinned synced commit and the content proposed for them. It makes NO claim that only the intended thing changed — review each diff as carefully as you would review a hand-written patch. It also did NOT render any chart or overlay, and did NOT cross-check the result against what Argo CD itself would render, because no Argo CD API connection is registered for this repository."

func toRepositoryChangeVerification(v gitops.ChangeVerification) repositoryChangeVerifiedAs {
	out := repositoryChangeVerifiedAs{
		Files:        make([]repositoryChangeFileResult, 0, len(v.Files)),
		FilesChanged: v.FilesChanged,
		LinesAdded:   v.LinesAdded,
		LinesRemoved: v.LinesRemoved,
		Checks:       v.Checks,
		Advisories:   v.Advisories,
		Label:        gitops.LabelVerifiedLocally,
		Caveat:       changeCaveat,
	}
	for _, f := range v.Files {
		out.Files = append(out.Files, repositoryChangeFileResult{
			Path:          f.Path,
			Created:       f.Created,
			Deleted:       f.Deleted,
			Unchanged:     f.Unchanged,
			Diff:          f.Diff,
			LinesAdded:    f.LinesAdded,
			LinesRemoved:  f.LinesRemoved,
			LineCount:     f.LineCount,
			DocumentCount: f.DocumentCount,
			Parsed:        f.Parsed,
			Checks:        nonNilStrings(f.Checks),
			Advisories:    nonNilStrings(f.Advisories),
		})
	}
	return out
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// maxRepositoryChangeBytes bounds one request. A change carries WHOLE files,
// not one path and one value, and internal/gitops' own 2MiB-per-file manifest
// bound is the real ceiling — this just has to be large enough for several of
// those plus the JSON envelope.
const maxRepositoryChangeBytes = 12 << 20

// loadRepoTargetWithFallback reads the stored ownership and, if it carries no
// repository, asks the cluster live — exactly as checkGitOpsPrecedence's
// resolveOwnership already does for the in-place path.
//
// # The asymmetry this removes, found by a live campaign rather than by reading
//
// incidents.ownership is written once, by cacheIncidentOwnership, at the end of
// an analysis, and every failure path there is deliberately silent — a caveat
// must not fail an investigation somebody has already paid for. The in-place
// path tolerates that silence because resolveOwnership falls back to a live
// lookup. This path did not, so a single transient tool-call failure left the
// PR channel permanently unavailable for that incident, with the 422 blaming
// the object ("not managed by Argo CD or Flux…") for what was actually a lost
// cache write. Re-analysing was the only recovery, and re-analysing costs money.
//
// That happened on the first real end-to-end run: the model's own root cause
// named the Argo CD Application, the repository, the path and the revision in
// prose, `incidents.ownership` was NULL because the hub's own follow-up call
// timed out, and a preflight seconds later resolved the same ownership live in
// under three seconds. Every fact needed was available; only the one place this
// path looked was empty.
//
// The live answer is written back, so the next call is cheap and the incident
// page's ownership panel starts working too — the same repair, in one place,
// for every reader of that column.
func (s *Server) loadRepoTargetWithFallback(ctx context.Context, rc *requestContext, incidentID, clusterID string) (*incidentRepoTarget, error) {
	target, err := loadRepoTarget(ctx, rc.Tx, incidentID)
	if err != nil {
		return nil, err
	}
	if target != nil || clusterID == "" {
		return target, err
	}

	// Nothing stored. Ask again, live — one tool call against a connected agent.
	gvk, namespace, name, sourceKey, err := ownershipQueryTarget(ctx, rc.Tx, incidentID)
	if err != nil {
		return nil, fmt.Errorf("read object_key: %w", err)
	}
	if sourceKey == "" {
		return nil, nil
	}
	args, err := json.Marshal(map[string]string{"gvk": gvk, "namespace": namespace, "name": name})
	if err != nil {
		return nil, nil
	}
	raw, err := s.gw.CallTool(ctx, clusterID, "get_gitops_ownership", args)
	if err != nil {
		// Logged, not returned: an unreachable agent means ownership is unknown,
		// which is the same answer as "nothing stored" and produces the same
		// honest 422. Failing the request instead would turn "we could not ask"
		// into a 500 the operator can do nothing about.
		logger.WarnContext(ctx, "live get_gitops_ownership failed; falling back to what is already stored",
			logging.IncidentID(incidentID), slog.String("source_key", sourceKey), logging.Err(err))
		return nil, nil
	}
	if _, err := rc.Tx.Exec(ctx, `UPDATE incidents SET ownership = $2 WHERE id = $1`, incidentID, raw); err != nil {
		// Same reasoning as cacheIncidentOwnership: a failed cache write must not
		// fail the operation the answer was fetched for.
		logger.ErrorContext(ctx, "persisting the incident's freshly fetched ownership failed", logging.IncidentID(incidentID), logging.Err(err))
	}
	return parseRepoTarget(ctx, raw, incidentID), nil
}

// ownershipQueryTarget picks which gvk|namespace|name tuple to ask
// get_gitops_ownership about for an incident: incidents.workload_key when
// present and well-formed, else incidents.object_key. Returns sourceKey == ""
// when neither is usable (nothing to ask).
//
// Mirrors loadIncidentObject's own workload_key-over-object_key preference a
// few functions below, and for the same reason: object_key is almost always a
// Pod (whatever the detector fired on), and a Pod can be gone by the time
// this runs — evicted, rescheduled, or simply replaced by its ReplicaSet —
// while workload_key names the stable owning Deployment/StatefulSet/etc. that
// a GitOps controller actually tracks. Querying get_gitops_ownership with a
// Pod name that no longer exists 404s before that tool ever gets to walk the
// owner chain up to the Deployment, even though it is built to do exactly
// that walk (internal/agent/tools.go's getGitOpsOwnership) — so preferring
// the stable name here avoids a spurious "no repository known" on any
// incident whose original Pod churned before approval.
func ownershipQueryTarget(ctx context.Context, tx pgx.Tx, incidentID string) (gvk, namespace, name, sourceKey string, err error) {
	var objectKey, workloadKey *string
	if err := tx.QueryRow(ctx, `SELECT object_key, workload_key FROM incidents WHERE id = $1`, incidentID).Scan(&objectKey, &workloadKey); err != nil {
		return "", "", "", "", err
	}
	gvk, namespace, name, sourceKey = pickOwnershipQueryTuple(objectKey, workloadKey)
	return gvk, namespace, name, sourceKey, nil
}

// pickOwnershipQueryTuple is ownershipQueryTarget's parsing, pulled out so it
// can be tested without a database: given the two raw column values, prefer
// workloadKey and fall back to objectKey, each split on the wire convention
// used throughout this package ("<gvk>|<namespace>|<name>"). Returns
// sourceKey == "" when neither key is usable.
func pickOwnershipQueryTuple(objectKey, workloadKey *string) (gvk, namespace, name, sourceKey string) {
	if workloadKey != nil && *workloadKey != "" {
		if parts := strings.SplitN(*workloadKey, "|", 3); len(parts) == 3 && parts[2] != "" {
			return parts[0], parts[1], parts[2], *workloadKey
		}
	}
	if objectKey != nil && *objectKey != "" {
		if parts := strings.SplitN(*objectKey, "|", 3); len(parts) == 3 && parts[2] != "" {
			return parts[0], parts[1], parts[2], *objectKey
		}
	}
	return "", "", "", ""
}

// incidentRepoTarget is the part of incidents.ownership this path needs: where
// the fix belongs. Decoded from the same jsonb column storedOwnership reads
// (migration 000038), with the same wire field names the agent writes
// (internal/agent/tools.go's gitOpsRepoTarget).
//
// A narrower read rather than a call to storedOwnership, deliberately: that
// function's job is to build the incident-detail RESPONSE, so it takes the
// incident's findings and its latest analysis in order to name the object in the
// same words the rest of the page uses. This path needs four strings out of one
// column, and making it assemble a findings list first would couple the write
// path to the shape of a view.
type incidentRepoTarget struct {
	ManagedBy      string
	RepoURL        string
	Path           string
	Branch         string
	Revision       string
	RevisionPinned bool
	ResolvedFrom   string
}

// loadRepoTarget reads the incident's stored GitOps ownership.
//
// Returns a nil target with no error when nothing is stored or nothing useful is
// in it: "this incident has no known repository" is an ordinary answer that the
// handler turns into a 422 explaining what would fix it (§11.2 step 6's honest
// degradation), not a database error.
func loadRepoTarget(ctx context.Context, tx pgx.Tx, incidentID string) (*incidentRepoTarget, error) {
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT ownership FROM incidents WHERE id = $1`, incidentID).Scan(&raw); err != nil {
		return nil, err
	}
	return parseRepoTarget(ctx, raw, incidentID), nil
}

// parseRepoTarget decodes one ownership blob, from the stored column or straight
// from a live tool result — the same bytes either way, which is why the decoding
// is shared rather than written twice. The agent's wire shape is the contract
// (internal/agent/tools.go's gitOpsRepoTarget); a second copy of these field
// tags is a second place for it to drift.
func parseRepoTarget(ctx context.Context, raw []byte, incidentID string) *incidentRepoTarget {
	if len(raw) == 0 {
		return nil
	}
	var stored struct {
		ManagedBy string `json:"managed_by"`
		Repo      *struct {
			RepoURL        string `json:"repo_url"`
			Path           string `json:"path"`
			Branch         string `json:"branch"`
			Revision       string `json:"revision"`
			RevisionPinned bool   `json:"revision_pinned"`
			ResolvedFrom   string `json:"resolved_from"`
		} `json:"repo"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		// Same treatment storedOwnership gives unparseable JSON: silence rather
		// than a 500. A malformed ownership blob is not a reason to fail a
		// request; it is a reason to say the repository is unknown.
		logger.WarnContext(ctx, "the incident's stored ownership does not parse; treating the repository as unknown",
			logging.IncidentID(incidentID), logging.Err(err))
		return nil
	}
	if stored.Repo == nil || stored.Repo.RepoURL == "" {
		return nil
	}
	return &incidentRepoTarget{
		ManagedBy: stored.ManagedBy, RepoURL: stored.Repo.RepoURL, Path: stored.Repo.Path,
		Branch: stored.Repo.Branch, Revision: stored.Repo.Revision,
		RevisionPinned: stored.Repo.RevisionPinned, ResolvedFrom: stored.Repo.ResolvedFrom,
	}
}

// loadIncidentObject resolves WHICH Kubernetes object this incident is about, so
// the right document in a multi-document manifest can be identified.
//
// Three sources, in descending order of how well each answers "which object does
// the manifest declare?":
//
//  1. The latest plan's target — already resolved to the owning workload by the
//     approval path, and what an operator is about to change.
//  2. incidents.workload_key — the same resolution, computed by replica
//     correlation from the owner chain, available with no analysis at all.
//  3. The newest finding — whatever the detector fired on, which for most
//     incidents is a Pod that no manifest declares.
//
// The gap between 2 and 3 is the whole reason 2 exists: see the comment inside.
func loadIncidentObject(ctx context.Context, tx pgx.Tx, incidentID string) (gitops.ObjectRef, string, error) {
	var gvk, name string
	var namespace *string
	err := tx.QueryRow(ctx,
		`SELECT target_gvk, target_namespace, target_name FROM remediation_recommendations
		  WHERE incident_id = $1 ORDER BY created_at DESC LIMIT 1`, incidentID).Scan(&gvk, &namespace, &name)
	if errors.Is(err, pgx.ErrNoRows) {
		// No plan. Prefer incidents.workload_key over the raw finding, because for
		// the most common incidents they are DIFFERENT OBJECTS and only one of them
		// is in the manifest.
		//
		// A pod-level incident — OOMKilled, CrashLoopBackOff, ImagePullBackOff, the
		// majority — names a Pod. A manifest defines the Deployment. Falling
		// straight to the finding therefore refused with "this file does not define
		// Pod web-fcb79c966-9xrq6", which is true, unhelpful, and looks like the
		// file is wrong rather than the question. workload_key is exactly the
		// resolved owning workload (migration 000042's replica correlation computes
		// it from the owner chain), which is the object a manifest actually
		// declares.
		//
		// Found by GITOPS_TEST_PLAN Phase 10: every un-analysed pod incident was
		// unable to use the pull-request path at all, and an analysis is not a
		// reasonable prerequisite for "change this field in this file" — it costs
		// money and the operator has already told us the file.
		var workloadKey *string
		if wkErr := tx.QueryRow(ctx, `SELECT workload_key FROM incidents WHERE id = $1`, incidentID).Scan(&workloadKey); wkErr == nil &&
			workloadKey != nil && *workloadKey != "" {
			if parts := strings.SplitN(*workloadKey, "|", 3); len(parts) == 3 && parts[2] != "" {
				apiVersion, kind := splitGVKWire(parts[0])
				return gitops.ObjectRef{APIVersion: apiVersion, Kind: kind, Namespace: parts[1], Name: parts[2]}, parts[0], nil
			}
		}
		err = tx.QueryRow(ctx,
			`SELECT gvk, namespace, object_name FROM findings
			  WHERE incident_id = $1 AND object_name IS NOT NULL
			  ORDER BY occurred_at DESC LIMIT 1`, incidentID).Scan(&gvk, &namespace, &name)
	}
	if err != nil {
		return gitops.ObjectRef{}, "", err
	}
	apiVersion, kind := splitGVKWire(gvk)
	return gitops.ObjectRef{APIVersion: apiVersion, Kind: kind, Namespace: deref(namespace), Name: name}, gvk, nil
}

// splitGVKWire splits this codebase's "<apiVersion>/<Kind>" wire convention
// (internal/agent/tools.go's parseGVKString) into the two halves
// gitops.ObjectRef wants: "apps/v1/Deployment" -> ("apps/v1", "Deployment"),
// "v1/Pod" -> ("v1", "Pod"). gvkKind (internal/execution) already takes the Kind
// half the same way; this needs both, and the apiVersion half is what lets
// documentMatches compare API GROUPS rather than exact versions.
func splitGVKWire(gvk string) (apiVersion, kind string) {
	idx := strings.LastIndex(gvk, "/")
	if idx < 0 {
		return "", gvk
	}
	return gvk[:idx], gvk[idx+1:]
}

// handleOpenRepositoryChange is POST /api/v1/incidents/{id}/repository-change.
// Requires repo:write + remediation:approve + remediation:execute:pr (all three
// at the route — see this file's header).
func (s *Server) handleOpenRepositoryChange(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	incidentID := r.PathValue("id")
	ctx := r.Context()

	var req repositoryChangeRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxRepositoryChangeBytes)).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}
	if title, detail, ok := req.validate(); !ok {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", title, detail)
		return
	}
	if !s.refuseIfIncidentClosed(w, r, rc, incidentID) {
		return
	}
	resolved, ok := s.resolveRepoChangeTarget(w, r, rc, incidentID)
	if !ok {
		return
	}
	clusterID := resolved.clusterID

	approver := s.approverIdentity(ctx, rc)
	rootCause := strings.TrimSpace(req.Reason)
	if rootCause == "" {
		rootCause = latestRootCause(ctx, rc.Tx, incidentID)
	}

	// BACKLOG.md F26: best-effort, bounded, and computed BEFORE
	// ProposeChanges so a usable result lands in the pull request body
	// itself rather than needing a second write after the fact. Never a
	// reason to refuse — see evaluateRenderEffect's own doc comment for
	// why its signature has no error return at all.
	renderEvidence := s.evaluateRenderEffect(ctx,
		scopeForTarget(ctx, rc.Tx, s.scmStore, incidentID, resolved.target),
		req.fileEdits(), nil)

	// Everything above is a read. From here the calls leave the hub, and the
	// first irreversible one is CreateBranch inside ProposeChanges — which is
	// why every refusal this endpoint can make has already been made, and why
	// every refusal ProposeChanges can make precedes its own first write.
	proposal, err := gitops.ProposeChanges(ctx, resolved.provider, resolved.repo, gitops.ProposalInput{
		Object:         resolved.object,
		Files:          req.fileEdits(),
		SyncedRevision: resolved.target.Revision,
		SourceDir:      resolved.target.Path,
		BaseBranch:     baseBranchFor(resolved.binding, resolved.target),
		Branch:         gitops.BranchName(resolved.binding.FixBranchPattern, incidentID),
		ForbiddenPaths: resolved.binding.WriteScope.ForbiddenPaths,
		RenderEvidence: renderEvidence,
		Provenance: gitops.Provenance{
			IncidentID:   incidentID,
			ApprovedBy:   approver,
			ClusterID:    clusterID,
			ClusterName:  clusterDisplayName(ctx, rc.Tx, clusterID),
			RootCause:    rootCause,
			ResolvedFrom: resolved.target.ResolvedFrom,
			Author:       commitAuthor(),
		},
	})
	if err != nil {
		writeRepositoryChangeFailure(w, err)
		return
	}

	s.recordOpenedPullRequest(ctx, rc, incidentID, proposal)

	capability := authz.CapRepoWrite
	var clusterRef *string
	if clusterID != "" {
		clusterRef = &clusterID
	}
	if auditErr := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID: rc.TenantID, ActorID: &rc.UserID, ActorAuthMethod: "jwt",
		SourceIP: clientIP(r), Capability: &capability, ClusterID: clusterRef,
		Outcome: audit.OutcomeSuccess,
		Details: map[string]any{
			"action":     "open_repository_change",
			"incidentId": incidentID,
			"repository": resolved.target.RepoURL,
			// The security-relevant facts, recorded so the audit chain answers
			// "what exactly did ARGUS change, where, and against which commit"
			// without anyone having to go and read the pull request. Every
			// changed path is named, and the advisory count is recorded ALWAYS
			// — including the ordinary zero — for the same reason
			// confirmScaleFromZero is: a key that only appears on the
			// interesting case cannot be searched for.
			"filePaths":      proposal.Verification.Paths(),
			"filesChanged":   proposal.Verification.FilesChanged,
			"linesAdded":     proposal.Verification.LinesAdded,
			"linesRemoved":   proposal.Verification.LinesRemoved,
			"advisories":     proposal.Verification.Advisories,
			"objectGvk":      resolved.gvk,
			"syncedRevision": resolved.target.Revision,
			"branch":         proposal.PullRequest.Head,
			"baseBranch":     proposal.PullRequest.Base,
			"commitSha":      proposal.CommitSHA,
			"commits":        proposal.Commits,
			"pullRequestUrl": proposal.PullRequest.URL,
			"verification":   gitops.LabelVerifiedLocally,
			"approvedBy":     approver,
			"filePathSource": "named_by_caller",
			// BACKLOG.md F26 — recorded ALWAYS, including when rendering was
			// never attempted (nil), for the same reason "advisories" above
			// is recorded even at zero: a key that only appears on the
			// interesting case cannot be searched for.
			"renderEvidence": renderEvidenceAuditFields(proposal.RenderEvidence),
		},
	}); auditErr != nil {
		// The pull request is already open, so this cannot be turned into a
		// failure of the request — but it must not be silent either. The 500 is
		// honest: the write happened and the record of it did not, and the
		// middleware rolls the transaction back, so the response says so rather
		// than reporting a success ARGUS cannot account for.
		logger.ErrorContext(ctx, "recording a repository change in the audit log failed — the pull request IS open",
			logging.IncidentID(incidentID), slog.String("pull_request_url", proposal.PullRequest.URL), logging.Err(auditErr))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal",
			"The pull request was opened but could not be recorded",
			fmt.Sprintf("pull request %s exists. ARGUS could not write its audit record, so this request is being reported as failed rather than as an unrecorded change — review the pull request by hand.", proposal.PullRequest.URL))
		return
	}

	writeJSON(w, http.StatusCreated, repositoryChangeResponse{
		IncidentID:     incidentID,
		Repository:     resolved.repo.String(),
		PullRequestNo:  proposal.PullRequest.Number,
		URL:            proposal.PullRequest.URL,
		Branch:         proposal.PullRequest.Head,
		BaseBranch:     proposal.PullRequest.Base,
		CommitSHA:      proposal.CommitSHA,
		Commits:        proposal.Commits,
		SyncedRevision: resolved.target.Revision,
		Verification:   toRepositoryChangeVerification(proposal.Verification),
		Warning:        proposal.LabelWarning,
		Message:        "Pull request opened. Nothing in the cluster has changed: the fix takes effect when this is merged and the GitOps controller syncs it.",
	})
}

// prProposedFile is one changed file's path and whole proposed content,
// persisted at PR-open time (incidents.pr_proposed_files, migration 000075)
// so BACKLOG.md F23's post-merge assertion has something to compare the
// synced content against. Captured from gitops.ChangeVerification.Changed(),
// which is exactly what ProposeChanges committed via scm.Provider.PutFile —
// so a byte-for-byte comparison against this later is a comparison against
// what actually landed, not a re-derivation of it.
//
// # Why persist content rather than a hash
//
// A hash would let the post-merge check say "it changed" but never "to what",
// and the whole point of F23's assertion failing is that an operator needs to
// see what the file now holds versus what ARGUS proposed. Content is bounded
// by the same maxManifestBytes/maxProposedFiles limits ProposeChanges already
// enforces, so this is not an unbounded write.
type prProposedFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	// Deleted is true when this file was REMOVED by the pull request rather
	// than written — BACKLOG.md "still open" #2. VerifyMergedPullRequest's
	// re-check inverts its usual comparison for such an entry: the file
	// existing again at the currently synced revision is the FAILURE, not
	// its absence. Content is always empty when Deleted is true.
	Deleted bool `json:"deleted,omitempty"`
}

// encodeProposedFiles captures the whole-file content a proposal actually
// committed — verification.Changed() only, since an Unchanged file was never
// written and there is nothing to assert about it post-merge. Returns nil
// (stored as SQL NULL) for a proposal with nothing changed, which
// prepareChanges already refuses (ErrNothingToChange), so in practice this is
// only ever nil if the marshal itself fails.
func encodeProposedFiles(changed []gitops.FileChange) []byte {
	if len(changed) == 0 {
		return nil
	}
	out := make([]prProposedFile, 0, len(changed))
	for _, f := range changed {
		out = append(out, prProposedFile{Path: f.Path, Content: string(f.Content), Deleted: f.Deleted})
	}
	b, err := json.Marshal(out)
	if err != nil {
		// Unreachable in practice (a []prProposedFile of strings always
		// marshals), but this must not panic or block the pull request that
		// already exists — same "log, don't fail" discipline as the rest of
		// this function.
		logger.Error("marshalling the proposed files failed", slog.Int("files", len(out)), logging.Err(err))
		return nil
	}
	return b
}

// recordOpenedPullRequest is the bookkeeping every path that opens a pull
// request performs, in the caller's transaction, after the pull request exists.
//
// Every failure here is LOGGED, not returned, and the reason is the same one in
// each case: the pull request is already open by this point, so reporting a
// failure over bookkeeping would send someone looking for a PR that exists. The
// consequences are stated rather than hidden.
func (s *Server) recordOpenedPullRequest(ctx context.Context, rc *requestContext, incidentID string, proposal gitops.Proposal) {
	// Mark this incident's in-place recommendations superseded, in the SAME
	// transaction as the audit record, before the response says a pull request
	// is open.
	//
	// This is the fix for the sharpest thing the first live GitOps run found
	// (migration 000049's comment has the detail): the in-place plan stayed
	// approvable after the source fix merged, and for RevertContainerImage its
	// meaning had inverted — approving it would have restored the broken image,
	// because "the previous revision" is resolved from live rollout history at
	// approval time and the previous revision was now the bad one.
	if _, err := rc.Tx.Exec(ctx,
		`UPDATE remediation_recommendations
		    SET superseded_at = now(), superseded_by_url = $2
		  WHERE incident_id = $1 AND superseded_at IS NULL`,
		incidentID, proposal.PullRequest.URL); err != nil {
		logger.ErrorContext(ctx, "marking the superseded recommendations failed — the pull request IS open",
			logging.IncidentID(incidentID), slog.String("pull_request_url", proposal.PullRequest.URL), logging.Err(err))
	}

	// pr_number (migration 000058) is what orchestrator.MergeSweeper polls the
	// provider with later, so a pull request opened through THIS self-service
	// route gets watched for merge exactly the same as one from an approved
	// recommendation.
	//
	// pr_field_path/pr_expected_value (migration 000059) are explicitly
	// NULLed. A whole-file change has no single field to assert after the
	// merge syncs, so claiming one — or leaving a STALE one from an earlier
	// recommendation on this incident — would be worse than the honest
	// degradation those columns already support: VerifyMergedPullRequest
	// treats a NULL field path as "this pull request opened through a path
	// that did not record one" and falls back to the per-file check below
	// (migration 000075), or to ValidationSweeper's quiet-grace-period
	// behaviour if that has nothing recorded either.
	//
	// pr_proposed_files (migration 000075, BACKLOG.md F23) IS what the
	// whole-file grammar can still assert post-merge: not a single field's
	// value, but every changed file's whole content, so VerifyMergedPullRequest
	// can re-read each one at the revision the GitOps controller reports
	// synced and confirm nothing reverted or conflicted with it after this
	// merged.
	// pr_url (migration 000089, BACKLOG.md D9 U6): the provider's own link to
	// this pull request, mirroring approveByOpeningPullRequest's identical
	// write, so a self-service change gets the same clickable record.
	//
	// pr_merged_at/pr_closed_unmerged_at/pr_rejection_reason are explicitly
	// NULLed here too, mirroring approveByOpeningPullRequest's identical fix
	// — see that call site's own comment for the bug this closes (a second
	// pull request on the same incident otherwise inherits the first one's
	// stale "closed unmerged" timestamp).
	//
	// pr_opened_at (migration 000114) mirrors approveByOpeningPullRequest's
	// identical write, and THIS is the call site that made the column necessary
	// rather than merely useful: this route records no `PullRequestOpened`
	// timeline event, so before this column a pull request opened here carried
	// no opened-at timestamp anywhere in the product at all — changes.go's
	// header said exactly that about the two real pull requests in the
	// development database. Set unconditionally, in the same statement, for the
	// same current-pull-request reason given at the other call site.
	if _, err := rc.Tx.Exec(ctx,
		`UPDATE incidents SET pr_number = $2, pr_url = $3, pr_field_path = NULL, pr_expected_value = NULL, pr_proposed_files = $4,
		        pr_opened_at = now(),
		        pr_merged_at = NULL, pr_closed_unmerged_at = NULL, pr_rejection_reason = NULL
		  WHERE id = $1`,
		incidentID, proposal.PullRequest.Number, nullIfEmpty(proposal.PullRequest.URL), encodeProposedFiles(proposal.Verification.Changed())); err != nil {
		logger.ErrorContext(ctx, "recording the pull-request number on the incident failed — the pull request IS open",
			logging.IncidentID(incidentID), slog.String("pull_request_url", proposal.PullRequest.URL), logging.Err(err))
	}

	// AwaitingApproval -> AwaitingMerge. The incident's fix is now a pull
	// request, and this state says so — see orchestrator.StateAwaitingMerge for
	// why this is a state rather than the column above on its own. The short
	// version: the column has to be remembered by every query that asks "what
	// may be executed?", and the one query with no human behind it forgot.
	if err := orchestrator.SetState(ctx, rc.Tx, incidentID, orchestrator.StateAwaitingMerge); err != nil {
		logger.ErrorContext(ctx, "moving the incident to AwaitingMerge failed — the pull request IS open",
			logging.IncidentID(incidentID), slog.String("pull_request_url", proposal.PullRequest.URL), logging.Err(err))
	}
}

// writeRepositoryChangeFailure maps the proposal path's errors onto statuses.
//
// The mapping matters more than it looks, and the reason is the same one
// github.go's status mapping gives: these outcomes have DIFFERENT fixes, and a
// caller (or a UI) that cannot tell them apart sends the operator to the wrong
// place. A refusal because the file is a Helm values file is permanent and needs
// a different approach; a conflict is transient and needs a re-analysis; an
// expired token needs renewing, not widening.
//
// Every one of these means NOTHING was merged and, in all but the conflict case,
// nothing was written at all.
func writeRepositoryChangeFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, gitops.ErrVerificationFailed):
		// A file ARGUS could not accept as reviewable content: empty, over the
		// byte bound, or plain YAML that does not parse. Its own problem type
		// because a UI must be able to say "ARGUS refused this content" rather
		// than "something went wrong".
		writeProblem(w, http.StatusUnprocessableEntity, "https://argus.io/errors/change-not-verified",
			"Refusing to open a pull request for this content", err.Error())
	case errors.Is(err, gitops.ErrRedactedValueEchoed):
		// BUGS.md 112. Its own problem type because the fix is specific and
		// nothing else here shares it: the value was withheld from the model at
		// capture time, so a human has to supply the real one.
		writeProblem(w, http.StatusUnprocessableEntity, "https://argus.io/errors/redacted-value-echoed",
			"This change would write a redaction marker into a file", err.Error())
	case errors.Is(err, gitops.ErrNothingToChange):
		writeProblem(w, http.StatusUnprocessableEntity, "https://argus.io/errors/no-change",
			"Nothing in this change differs from the repository", err.Error())
	case errors.Is(err, gitops.ErrAmbiguousDocument):
		// File DISCOVERY could not name a single file for this object — the
		// object is declared in none of the synced directory's files, or in
		// several. The fix is to name the file, so it gets its own type.
		writeProblem(w, http.StatusUnprocessableEntity, "https://argus.io/errors/file-not-located",
			"ARGUS could not determine which file this object is declared in", err.Error())
	case errors.Is(err, scm.ErrConflict):
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/repository-changed",
			"A file has changed since this proposal was built", err.Error())
	case errors.Is(err, scm.ErrCredentialExpired), errors.Is(err, scm.ErrForbidden):
		writeProblem(w, http.StatusForbidden, "https://argus.io/errors/repository-unusable",
			"This repository's credential could not be used", err.Error())
	case errors.Is(err, scm.ErrAlreadyExists):
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/invalid-state",
			"A fix branch for this incident already exists", err.Error())
	case errors.Is(err, scm.ErrNotFound):
		writeProblem(w, http.StatusUnprocessableEntity, "https://argus.io/errors/not-found",
			"That file does not exist at the synced commit", err.Error())
	default:
		// Not logged-and-generalised: the errors reaching here are written for an
		// operator to act on (a forbidden path, a file outside the synced
		// directory, an unpinned revision), and replacing them with "could not
		// open a pull request" would discard the only useful part.
		logger.Error("opening a repository change failed", logging.Err(err))
		writeProblem(w, http.StatusUnprocessableEntity, "https://argus.io/errors/repository-change-refused",
			"Could not open a pull request for this change", err.Error())
	}
}

// baseBranchFor picks what the pull request merges into.
//
// The binding's configured default branch wins over the branch the GitOps
// controller reports tracking, because the binding is the operator's stated
// policy for this repository while the controller's `targetRevision` is a fact
// about deployment that may name a tag or a commit. Both empty asks the provider,
// which is the only source that knows the repository's real default — and
// branching from the wrong base produces a pull request full of unrelated
// changes.
func baseBranchFor(binding scm.Binding, target *incidentRepoTarget) string {
	if binding.DefaultBranch != "" {
		return binding.DefaultBranch
	}
	// Only a plausible branch name, never a SHA: a pull request whose base is a
	// commit is not a pull request the provider will accept.
	if b := strings.TrimSpace(target.Branch); b != "" && !looksLikeSHA(b) {
		return b
	}
	return ""
}

func looksLikeSHA(s string) bool {
	if len(s) < 7 || len(s) > 40 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// commitAuthor is the identity the commit is attributed to.
//
// D-R9: a dedicated MACHINE USER, not the approving human — it survives
// offboarding, keeps `git blame` honest by not attributing hundreds of changes to
// someone who never saw them, and avoids the self-approval rules that would
// otherwise stop the token's human owner approving ARGUS's own pull requests. The
// human is named in the commit trailer and the PR body instead.
//
// A constant rather than a setting because there is nothing to configure yet: the
// provider attributes the commit to whichever account the token belongs to
// regardless, and this only supplies the name and address that appear beside it.
func commitAuthor() scm.Identity {
	return scm.Identity{Name: "ARGUS", Email: "argus@localhost"}
}

// approverIdentity is how the approving human is named in the trailer and the PR
// body. Their email where one is readable, otherwise their user id — never
// nothing, because "approved by" with no name is worse than the id.
func (s *Server) approverIdentity(ctx context.Context, rc *requestContext) string {
	var email string
	if err := rc.Tx.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, rc.UserID).Scan(&email); err != nil || email == "" {
		return rc.UserID
	}
	return email
}

// latestRootCause quotes the incident's most recent analysis into the pull
// request, so a reviewer who has never heard of ARGUS can see why the change is
// being proposed.
//
// Best-effort throughout: a missing, partial or unparseable analysis costs the
// pull request a paragraph, not the request. Reads the same
// analyses.root_cause jsonb shape analyze.go's rootCauseStored defines — and only
// a COMPLETE analysis' statement, because a partial analysis' partialReason says
// why the investigation stopped, which is not a reason to make a change.
func latestRootCause(ctx context.Context, tx pgx.Tx, incidentID string) string {
	var raw []byte
	if err := tx.QueryRow(ctx,
		`SELECT root_cause FROM analyses WHERE incident_id = $1 ORDER BY created_at DESC LIMIT 1`,
		incidentID).Scan(&raw); err != nil || len(raw) == 0 {
		return ""
	}
	var stored rootCauseStored
	if err := json.Unmarshal(raw, &stored); err != nil || stored.Status == "partial" {
		return ""
	}
	return stored.Statement
}

func clusterIDForIncident(ctx context.Context, tx pgx.Tx, incidentID string) string {
	var clusterID string
	if err := tx.QueryRow(ctx, `SELECT cluster_id FROM incidents WHERE id = $1`, incidentID).Scan(&clusterID); err != nil {
		return ""
	}
	return clusterID
}

// filePathSource records whether the changed file was named by the caller or
// discovered by ARGUS — a fact worth keeping in the audit chain, because the two
// carry different responsibility.
func filePathSource(located *discoveredFile) string {
	if located == nil {
		return "named_by_caller"
	}
	if located.IdentitySource != "" {
		// BACKLOG.md "still open" #4: this file was found by searching for a
		// kind/name parsed out of the incident's own sync-failure message, not
		// by reading an identity off anything that ever existed as a live
		// object — a real distinction worth a UI being able to render
		// differently, not folded into the ordinary "located_by_argus" answer.
		return "located_by_argus_via_" + located.IdentitySource
	}
	return "located_by_argus"
}

// filesScanned is how many YAML files were read to find the file, or 0 when it
// was named.
func filesScanned(located *discoveredFile) int {
	if located == nil {
		return 0
	}
	return located.FilesScanned
}

// proposeFromApprovedPlan opens a pull request for an OpenPR plan that a human
// has just approved.
//
// # Why a second caller of ProposeChanges rather than a refactor
//
// handleOpenRepositoryChange is the endpoint a human drives, and it carries
// HTTP-coupled refusals. A second focused caller is safe here for a specific
// reason rather than a hopeful one: **every security refusal lives inside
// gitops.ProposeChanges** — the forbidden-path denylist, the confinement of
// every path to the directory the controller reports syncing, the pinned read
// and the per-file compare-and-swap are all made in there, so a second caller
// inherits them automatically and cannot skip one by forgetting to copy it.
// What the handler owns and this does not need is request parsing and its own
// capability checks — the approve path has already made its own.
//
// # What the model supplied, and what it did not
//
// params.Files is the model's proposal: paths and whole contents. The
// repository, the directory, the synced commit, the base branch and the fix
// branch are ARGUS's, resolved here from the incident's own stored ownership —
// a plan cannot choose any of them, and params.Repository is deliberately not
// consulted.
//
// Returns the proposal for the caller to record. It performs no audit and no
// state transition: those belong to the approving caller, in its transaction,
// alongside its own approval record.
func (s *Server) proposeFromApprovedPlan(ctx context.Context, rc *requestContext, incidentID, clusterID, approver string, params remediation.OpenPRParams) (gitops.Proposal, string, error) {
	if err := params.Validate(); err != nil {
		return gitops.Proposal{}, "", fmt.Errorf("this plan cannot be turned into a pull request: %w", err)
	}

	target, err := s.loadRepoTargetWithFallback(ctx, rc, incidentID, clusterID)
	if err != nil {
		return gitops.Proposal{}, "", fmt.Errorf("read this incident's GitOps ownership: %w", err)
	}
	if target == nil {
		return gitops.Proposal{}, "", fmt.Errorf("no repository is known for this incident, so there is nowhere to propose a change — that happens when the object is not managed by Argo CD or Flux, when it is a Helm release, or when its controller has never synced")
	}
	if !target.RevisionPinned || target.Revision == "" {
		// The same rule the human path enforces: a change computed against a
		// moving branch is computed against content that is not what is running.
		return gitops.Proposal{}, "", fmt.Errorf("the commit this object is running is not known, so a change cannot be computed against the source that produced it")
	}

	object, _, err := loadIncidentObject(ctx, rc.Tx, incidentID)
	if err != nil {
		return gitops.Proposal{}, "", fmt.Errorf("determine which object this incident is about: %w", err)
	}

	provider, repo, binding, err := s.scmStore.ProviderFor(ctx, rc.Tx, target.RepoURL)
	if err != nil {
		return gitops.Proposal{}, "", err
	}
	if !binding.PullRequestEnabled {
		return gitops.Proposal{}, "", fmt.Errorf("pull requests are disabled for %s, so ARGUS may read it but must not propose changes to it", target.RepoURL)
	}

	files := make([]gitops.FileEdit, 0, len(params.Files))
	for _, f := range params.Files {
		files = append(files, gitops.FileEdit{Path: strings.TrimSpace(f.Path), Content: []byte(f.Content), Delete: f.Delete})
	}

	// BACKLOG.md F26: same best-effort, bounded, non-gating computation as
	// handleOpenRepositoryChange's — see evaluateRenderEffect's doc comment.
	// This is the model's OWN proposed plan being turned into a pull
	// request, which is exactly the case F26 names: a human approved this
	// already trusting today's "unproven" label, and this is what promotes
	// it to checked where a renderer is available at all.
	renderEvidence := s.evaluateRenderEffect(ctx, scopeForTarget(ctx, rc.Tx, s.scmStore, incidentID, target), files, nil)

	input := gitops.ProposalInput{
		Object:         object,
		Files:          files,
		SyncedRevision: target.Revision,
		SourceDir:      target.Path,
		BaseBranch:     baseBranchFor(binding, target),
		Branch:         gitops.BranchName(binding.FixBranchPattern, incidentID),
		ForbiddenPaths: binding.WriteScope.ForbiddenPaths,
		RenderEvidence: renderEvidence,
		Provenance: gitops.Provenance{
			IncidentID:   incidentID,
			ApprovedBy:   approver,
			ClusterID:    clusterID,
			ClusterName:  clusterDisplayName(ctx, rc.Tx, clusterID),
			RootCause:    latestRootCause(ctx, rc.Tx, incidentID),
			ResolvedFrom: target.ResolvedFrom,
			Author:       commitAuthor(),
		},
	}

	// BUGS.md 114: a preview-only pass (no branch, no commit, no pull
	// request — see PreviewChanges' own doc comment) so
	// checkReadinessThresholdNotInert can see the SAME before/after content
	// ProposeChanges is about to commit, before anything is opened. This is
	// the OpenPR path the bug was actually found on: a model's plan, already
	// approved by a human trusting the gate's own safety evaluation, about
	// to become a real pull request. See internal/api/inert_readiness_guard.go
	// for the full reasoning and for why this is the only OpenPR entry point
	// that carries this guard.
	preview, err := gitops.PreviewChanges(ctx, provider, repo, input)
	if err != nil {
		return gitops.Proposal{}, "", err
	}
	if err := s.checkReadinessThresholdNotInert(ctx, clusterID, object, preview.Verification.Changed()); err != nil {
		return gitops.Proposal{}, "", err
	}

	proposal, err := gitops.ProposeChanges(ctx, provider, repo, input)
	if err != nil {
		return gitops.Proposal{}, "", err
	}
	return proposal, repo.String(), nil
}

// clusterDisplayName is the cluster's human name for the pull request body
// (gitops.Provenance.ClusterName). Best-effort by design: it returns "" on any
// failure and the body falls back to the bare id, because a pull request must
// not fail to open over a cosmetic lookup.
//
// Read inside the caller's RLS-scoped transaction like every other read here, so
// it cannot name a cluster the actor could not otherwise see.
func clusterDisplayName(ctx context.Context, tx pgx.Tx, clusterID string) string {
	if clusterID == "" {
		return ""
	}
	var name string
	if err := tx.QueryRow(ctx, `SELECT COALESCE(display_name, '') FROM clusters WHERE id = $1`, clusterID).Scan(&name); err != nil {
		logger.WarnContext(ctx, "reading the cluster's display name failed; the pull request body will name the id only",
			logging.ClusterID(clusterID), logging.Err(err))
		return ""
	}
	return name
}
