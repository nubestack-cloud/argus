package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"argus/internal/authz"
	"argus/internal/gitops"
	"argus/internal/logging"
	"argus/internal/orchestrator"
	"argus/internal/scm"
)

// The read side of the repository-change channel, and the resolution phase
// every route in it shares.
//
// GET /api/v1/incidents/{id}/repository-change/file?filePath=... returns one
// file's current content at the pinned synced commit — what an editor is
// seeded with before a human proposes new content for it, and what a client
// re-reads when the operator wants a second file in the same change.
//
// filePath is optional: with none, ARGUS finds the single file under the
// synced directory that declares this incident's object, and refuses if there
// are none or several. That discovery is the ONLY thing the object-to-document
// machinery is still used for — a change itself is whole files, and a
// values.yaml declares no Kubernetes object to find.

// repositoryFileResponse is the current, unedited content of one file.
type repositoryFileResponse struct {
	IncidentID     string `json:"incidentId"`
	Repository     string `json:"repository"`
	FilePath       string `json:"filePath"`
	FilePathSource string `json:"filePathSource"`
	FilesScanned   int    `json:"filesScanned"`
	SyncedRevision string `json:"syncedRevision"`
	Content        string `json:"content"`
}

// handleGetRepositoryChangeFile is GET
// /api/v1/incidents/{id}/repository-change/file?filePath=...
//
// Read-only: a plain scm.Provider.ReadFile, not the blob-SHA-carrying
// UpdatableFileReader.ReadFileForUpdate the write path uses, because nothing
// here will ever be compared-and-swapped against.
//
// It carries the SAME three capabilities the write routes do even though it
// writes nothing: it returns real repository content, so whoever can call it
// can read any file the binding reaches under the synced directory, and
// handing that to a wider audience than the people who may open the pull
// request would be a new exposure for no gain.
func (s *Server) handleGetRepositoryChangeFile(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	incidentID := r.PathValue("id")
	filePath := strings.TrimSpace(r.URL.Query().Get("filePath"))

	resolved, ok := s.resolveRepoChangeTarget(w, r, rc, incidentID)
	if !ok {
		return
	}

	var located *discoveredFile
	if filePath == "" {
		found, lerr := locateObjectFileWithFallback(ctx, rc.Tx, incidentID, resolved.gvk, resolved.provider, resolved.binding, resolved.target.RepoURL, resolved.target.Revision, resolved.target.Path, resolved.object)
		if lerr != nil {
			writeProblem(w, http.StatusUnprocessableEntity, "https://argus.io/errors/file-not-located",
				"ARGUS could not determine which file to open", lerr.Error())
			return
		}
		filePath = found.Path
		located = &found
	} else if resolved.target.Path != "" && !scm.WithinRepoDir(resolved.target.Path, filePath) {
		// The same confinement gitops.prepareChanges enforces for a write,
		// applied here too so a caller cannot use the read route to fetch a
		// file outside the directory this object's controller reports syncing.
		writeProblem(w, http.StatusUnprocessableEntity, "https://argus.io/errors/file-not-located",
			"That file is outside the synced directory",
			resolved.target.Path+" is the directory this object's GitOps controller reports syncing; "+filePath+" is outside it.")
		return
	}

	// The forbidden-path check gitops.prepareChanges runs before any WRITE also
	// applies here, before any READ — this route has no prepareChanges call
	// downstream to catch it otherwise. builtinForbiddenPaths exists partly FOR
	// exactly this reason (scm/writescope.go's own comment: "*.age, *.sops.*
	// and sealed secrets are here... ARGUS must not touch content it cannot
	// read"), and CI definitions/scripts are forbidden for the same reason a
	// write is: this route would otherwise let an operator use an "open this
	// file" feature to pull the content of a file ARGUS is supposed never to
	// touch, whether or not they go on to edit it.
	if pattern := scm.ForbiddenPath(filePath, resolved.binding.WriteScope.ForbiddenPaths); pattern != "" {
		writeProblem(w, http.StatusUnprocessableEntity, "https://argus.io/errors/repository-change-refused",
			"ARGUS may not read this file",
			filePath+" matches the forbidden path "+pattern+" — ARGUS must never read or modify anything CI executes, or content it cannot read")
		return
	}

	content, err := resolved.provider.ReadFile(ctx, resolved.repo, resolved.target.Revision, filePath)
	if err != nil {
		writeRepositoryChangeFailure(w, err)
		return
	}

	writeJSON(w, http.StatusOK, repositoryFileResponse{
		IncidentID:     incidentID,
		Repository:     resolved.target.RepoURL,
		FilePath:       filePath,
		FilePathSource: filePathSource(located),
		FilesScanned:   filesScanned(located),
		SyncedRevision: resolved.target.Revision,
		Content:        string(content),
	})
}

// resolvedRepoChangeTarget is everything the read, preview and open routes need
// before they can call into gitops — the shared resolution phase, extracted so
// the three handlers cannot drift on which refusals they check.
type resolvedRepoChangeTarget struct {
	target    *incidentRepoTarget
	object    gitops.ObjectRef
	gvk       string
	provider  scm.Provider
	repo      scm.Repo
	binding   scm.Binding
	clusterID string
}

// resolveRepoChangeTarget runs the read-only resolution phase: the scope-aware
// capability check, ownership, the revision pin, object identity and the
// provider/binding lookup — everything up to where gitops takes over. It
// writes an HTTP response and returns ok=false on any refusal.
//
// The repository, the directory and the synced commit come from the incident's
// stored ownership, NEVER from the request. That is the boundary that makes it
// safe for a request (or a model) to name a file: it names a file within a
// repository and directory it did not choose.
func (s *Server) resolveRepoChangeTarget(w http.ResponseWriter, r *http.Request, rc *requestContext, incidentID string) (resolvedRepoChangeTarget, bool) {
	ctx := r.Context()
	clusterID := clusterIDForIncident(ctx, rc.Tx, incidentID)

	// Scope-aware capability check (BACKLOG S1). The three route capabilities
	// are checked scope-blind at the route, so a grant scoped to one cluster
	// could otherwise read or propose a change for another cluster's incident.
	// Only the handler knows the cluster.
	if clusterID != "" {
		for _, capability := range []string{authz.CapRepoWrite, authz.CapRemediationApprove, authz.CapRemediationExecPR} {
			allowed, err := authz.HasCapabilityForCluster(ctx, rc.Tx, rc.Grants, capability, clusterID)
			if err != nil {
				logger.ErrorContext(ctx, "resolving cluster-scoped capability failed", logging.IncidentID(incidentID), logging.Err(err))
				writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not resolve the scope of your permissions", "")
				return resolvedRepoChangeTarget{}, false
			}
			if !allowed {
				s.recordCapabilityDenial(ctx, rc, capability, clientIP(r))
				writeProblem(w, http.StatusForbidden, "https://argus.io/errors/scope-denied",
					"Missing required capability for this cluster",
					"this incident belongs to a cluster you hold this capability on a narrower scope than")
				return resolvedRepoChangeTarget{}, false
			}
		}
	}

	target, err := s.loadRepoTargetWithFallback(ctx, rc, incidentID, clusterID)
	if err != nil {
		logger.ErrorContext(ctx, "resolving the incident's repository target failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not determine this incident's repository", "")
		return resolvedRepoChangeTarget{}, false
	}
	if target == nil {
		writeProblem(w, http.StatusUnprocessableEntity, "https://argus.io/errors/no-repository-target",
			"No repository is known for this incident",
			"ARGUS has not resolved a Git source for the object this incident is about, so it has nowhere to propose a change. That happens when the object is not managed by Argo CD or Flux, when it is a Helm release (whose metadata names a release, not a repository), or when its controller has never synced.")
		return resolvedRepoChangeTarget{}, false
	}
	if !target.RevisionPinned || target.Revision == "" {
		// §11.4's first non-obvious point, enforced rather than noted: "Pin the
		// SHA. Use status.sync.revision, not HEAD."
		writeProblem(w, http.StatusUnprocessableEntity, "https://argus.io/errors/revision-not-pinned",
			"The commit this object is running is not known",
			"The GitOps controller reports a branch or tag rather than a resolved commit, so nobody can say which commit is actually running. A change computed against the branch head would be computed against content the cluster has never applied. Re-analyse this incident once the controller reports a synced commit.")
		return resolvedRepoChangeTarget{}, false
	}

	object, gvk, err := loadIncidentObject(ctx, rc.Tx, incidentID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeProblem(w, http.StatusUnprocessableEntity, "https://argus.io/errors/invalid-state",
				"This incident does not name an object",
				"Neither a proposed plan nor any finding on this incident names a Kubernetes object, so ARGUS cannot say which file this change is about or find one to open.")
			return resolvedRepoChangeTarget{}, false
		}
		logger.ErrorContext(ctx, "resolving the incident's object for a repository change failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not determine which object this incident is about", "")
		return resolvedRepoChangeTarget{}, false
	}

	provider, repo, binding, err := s.scmStore.ProviderFor(ctx, rc.Tx, target.RepoURL)
	if err != nil {
		title := "This repository cannot be written to"
		if errors.Is(err, scm.ErrNoBinding) {
			title = "This repository is not registered with ARGUS"
		}
		writeProblem(w, http.StatusUnprocessableEntity, "https://argus.io/errors/repository-unusable", title, err.Error())
		return resolvedRepoChangeTarget{}, false
	}
	if !binding.PullRequestEnabled {
		writeProblem(w, http.StatusUnprocessableEntity, "https://argus.io/errors/repository-unusable",
			"Pull requests are disabled for this repository",
			"the binding for this repository has pullRequest.enabled set to false, so ARGUS may read it but must not propose changes to it")
		return resolvedRepoChangeTarget{}, false
	}

	return resolvedRepoChangeTarget{
		target: target, object: object, gvk: gvk,
		provider: provider, repo: repo, binding: binding, clusterID: clusterID,
	}, true
}

// refuseIfIncidentClosed refuses a proposal for an incident nobody is asking
// about any more. Terminal states only, and nothing else — deliberately NOT
// the approve route's stricter "must be AwaitingApproval", because that state
// exists for a stored plan waiting on a verdict and this route does not act on
// a stored plan.
func (s *Server) refuseIfIncidentClosed(w http.ResponseWriter, r *http.Request, rc *requestContext, incidentID string) bool {
	ctx := r.Context()
	state, err := incidentState(ctx, rc.Tx, incidentID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Incident not found", "")
			return false
		}
		logger.ErrorContext(ctx, "looking up the incident to check whether it is closed failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up incident", "")
		return false
	}
	if state == orchestrator.StateDismissed || state == orchestrator.StateResolved {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/invalid-state",
			"This incident is closed",
			"incident is "+string(state)+"; reopen it before proposing a change for it")
		return false
	}
	return true
}
