package api

// BACKLOG.md F30 piece 3: "ask once, where the problem is met" — the three
// routes a blocked incident's own page calls, wrapping
// objectmapping_discovery.go's discover-then-prove step in the one place an
// operator actually meets this problem, instead of a disconnected Settings
// screen.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/logging"
	"argus/internal/scm"
)

// linkTargetMode is which of F30's two identity shapes a blocked incident's
// target resolves to. Both reach the same three routes and the same
// render-then-confirm flow; only WHAT gets rendered against (a chart vs. a
// bare manifest file, objectmapping_discovery.go vs.
// objectmapping_discovery_manifest.go) and WHAT the confirmed ObjectMapping
// is keyed on (ReleaseName+Namespace vs. LabelSelector) differ.
type linkTargetMode string

const (
	linkModeHelm     linkTargetMode = "helm"
	linkModeManifest linkTargetMode = "manifest"
)

// helmReleaseTarget is what every one of these three routes needs to start
// from: the incident's own cluster, its mode-specific identity (a Helm
// release's name+namespace, or — F30 owner decision 2026-09-09 — a
// plain-manifest object's own labels, read verbatim from get_gitops_
// ownership's report and never operator-typed), and the live object's own
// kind+namespace+name — ownershipQueryTarget's own tuple, the SAME one
// gatherOwnershipFacts asks the cluster about.
type helmReleaseTarget struct {
	mode             linkTargetMode
	clusterID        string
	releaseName      string
	releaseNamespace string
	// labels is manifest-mode only — the exact labels wire.Labels already
	// carried, i.e. the SAME set matchObjectMapping (routing.go) reads back
	// out to match a confirmed mapping on the next incident. Never a subset
	// or a guess: what confirmRepositoryLink stores as LabelSelector is
	// exactly this map, so "no label selectors" (never operator-typed) is
	// true without also being "no labels at all".
	labels          map[string]string
	objectGVK       string
	objectNamespace string
	objectName      string
}

// resolveHelmReleaseTarget reads the incident's stored ownership and object
// identity, and refuses (ok=false) anything that is not exactly one of the
// two states this feature exists for: a Helm-managed object, or a
// plain-manifest object (no Helm release, no GitOps controller) — either
// way with NO repository already known. An Argo/Flux-managed object (a real
// controller already owns it — nothing to discover), or a target that
// already resolves to a repo (an ObjectMapping already matched, or the
// operator registered one another way), has nothing for these routes to do
// — see this file's callers for the 409 each maps to.
func resolveHelmReleaseTarget(ctx context.Context, rc *requestContext, incidentID string) (helmReleaseTarget, string, error) {
	var clusterID string
	var rawOwnership []byte
	if err := rc.Tx.QueryRow(ctx, `SELECT cluster_id, ownership FROM incidents WHERE id = $1`, incidentID).
		Scan(&clusterID, &rawOwnership); err != nil {
		return helmReleaseTarget{}, "", err
	}

	var wire ownershipWire
	if len(rawOwnership) > 0 {
		if err := json.Unmarshal(rawOwnership, &wire); err != nil {
			return helmReleaseTarget{}, "not-applicable", nil
		}
	}

	var mode linkTargetMode
	var releaseName, releaseNamespace string
	var labels map[string]string
	switch wire.ManagedBy {
	case "helm":
		if wire.AppRef == nil || wire.AppRef.Name == "" || wire.AppRef.Namespace == "" {
			return helmReleaseTarget{}, "not-applicable", nil
		}
		mode, releaseName, releaseNamespace = linkModeHelm, wire.AppRef.Name, wire.AppRef.Namespace
	case "", "none":
		// F30 owner decision 2026-09-09: a plain-manifest object is matched
		// the same way, by rendering — but it needs SOME identity to store a
		// confirmed link against, and with no release to key on, its own
		// labels are what get_gitops_ownership already reports (populated for
		// every managed_by value, per routing.go's ownershipWire doc
		// comment). No labels at all means no identity this feature can
		// safely register a mapping against — no object-level "no labels"
		// form is offered, exactly F30's "no label selectors" typed by a
		// human, and no fallback to matching by namespace+name alone, which
		// would risk one mapping quietly covering every future object sharing
		// just those two fields.
		if len(wire.Labels) == 0 {
			return helmReleaseTarget{}, "not-applicable", nil
		}
		mode, labels = linkModeManifest, wire.Labels
	default: // "argocd", "flux" — a real controller already owns this
		return helmReleaseTarget{}, "not-applicable", nil
	}
	if wire.Repo != nil && wire.Repo.RepoURL != "" {
		return helmReleaseTarget{}, "already-linked", nil
	}

	gvk, namespace, name, sourceKey, err := ownershipQueryTarget(ctx, rc.Tx, incidentID)
	if err != nil {
		return helmReleaseTarget{}, "", err
	}
	if sourceKey == "" {
		return helmReleaseTarget{}, "no-object", nil
	}

	return helmReleaseTarget{
		mode: mode, clusterID: clusterID, releaseName: releaseName, releaseNamespace: releaseNamespace,
		labels: labels, objectGVK: gvk, objectNamespace: namespace, objectName: name,
	}, "", nil
}

// writeHelmReleaseTargetProblem maps resolveHelmReleaseTarget's own
// "not applicable" reasons onto RFC 9457 responses — 409 (a real, current
// state conflict) rather than 400, since the request itself is well-formed;
// it is the incident's OWN state that makes this action inapplicable right
// now.
func writeHelmReleaseTargetProblem(w http.ResponseWriter, reason string) bool {
	switch reason {
	case "not-applicable":
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/conflict",
			"This incident is not a Helm release or plain-manifest object with no repository link", "")
		return true
	case "already-linked":
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/conflict",
			"This incident already resolves to a repository — nothing to link", "")
		return true
	case "no-object":
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/conflict",
			"This incident names no object to check ownership for", "")
		return true
	default:
		return false
	}
}

// otherClusterRunningRelease is one fact discoverRepositoryLinkResponse's
// "widen" option needs: another cluster ARGUS has independently observed
// this exact release/namespace on. See handleDiscoverRepositoryLink's own
// query comment for the honest limit on what "other clusters running this
// release" actually means here.
type otherClusterRunningRelease struct {
	ClusterID          string `json:"clusterId"`
	ClusterDisplayName string `json:"clusterDisplayName"`
}

type discoverRepositoryLinkResponse struct {
	Status     string          `json:"status"`
	Candidates []LinkCandidate `json:"candidates"`
	Degraded   string          `json:"degraded,omitempty"`
	// Mode says which of F30's two identity shapes this discovery ran
	// against — "helm" or "manifest" — so the frontend can render the right
	// copy without needing its own (deliberately null-for-unmanaged, see
	// ObjectOwnership's doc comment) ownership summary.
	Mode string `json:"mode"`
	// ReleaseName/Namespace are set for mode "helm" only, empty for
	// "manifest" — a plain-manifest object has no release identity at all.
	ReleaseName string `json:"releaseName"`
	Namespace   string `json:"namespace"`
	// ObjectGVK/ObjectNamespace/ObjectName are always set, in both modes —
	// the live object this discovery is actually about, which is what
	// LinkRepositoryForm names when there is no release to name instead.
	ObjectGVK       string                       `json:"objectGvk"`
	ObjectNamespace string                       `json:"objectNamespace"`
	ObjectName      string                       `json:"objectName"`
	OtherClusters   []otherClusterRunningRelease `json:"otherClusters"`
}

// handleDiscoverRepositoryLink is POST /api/v1/incidents/{id}/discover-repository-link.
// Requires repo:read — this never writes anything, only renders (mode
// "helm") or parses (mode "manifest") candidates.
func (s *Server) handleDiscoverRepositoryLink(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	incidentID := r.PathValue("id")

	target, reason, err := resolveHelmReleaseTarget(r.Context(), rc, incidentID)
	if err != nil {
		logger.ErrorContext(r.Context(), "resolving the incident's repository-link target failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not read this incident's ownership", "")
		return
	}
	if writeHelmReleaseTargetProblem(w, reason) {
		return
	}

	// F30 decision 4: a prior decline for this exact identity means "do not
	// re-ask" — checked BEFORE ever running a render/parse, so declining is
	// also what keeps a repeatedly-reopened incident from spending that cost
	// every time. Which identity a decline is keyed on follows target.mode
	// exactly the way a confirmed mapping already does.
	declined, err := declineAlreadyRecorded(r.Context(), rc.Tx, target)
	if err != nil {
		logger.ErrorContext(r.Context(), "checking the incident's repository-link declines failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not check prior declines", "")
		return
	}
	if declined {
		writeJSON(w, http.StatusOK, discoverRepositoryLinkResponse{
			Status: "declined", Mode: string(target.mode), ReleaseName: target.releaseName, Namespace: target.releaseNamespace,
			ObjectGVK: target.objectGVK, ObjectNamespace: target.objectNamespace, ObjectName: target.objectName,
		})
		return
	}

	var result LinkDiscoveryResult
	var otherClusters []otherClusterRunningRelease
	switch target.mode {
	case linkModeManifest:
		result = s.discoverManifestLink(r.Context(), rc.Tx, target.objectGVK, target.objectNamespace, target.objectName)
		// No "widen to every cluster running this" offer in manifest mode —
		// there is no release identity to widen BY (see this file's own
		// otherClustersRunningRelease doc comment); a plain-manifest object
		// present on more than one cluster still gets one confirmation per
		// cluster, which is a real cost but never a wrong link.
	default:
		result = s.discoverRepositoryLink(r.Context(), rc.Tx, target.releaseName, target.releaseNamespace, target.objectGVK, target.objectNamespace, target.objectName)
		otherClusters, err = otherClustersRunningRelease(r.Context(), rc.Tx, target.clusterID, target.releaseName, target.releaseNamespace)
		if err != nil {
			// Not fatal to the whole response — the candidate/proof result is
			// the important half, and a caller can still confirm a Cluster-only
			// scope with no widen option offered.
			logger.ErrorContext(r.Context(), "resolving the other clusters this repository link would cover failed", logging.IncidentID(incidentID), logging.Err(err))
		}
	}

	writeJSON(w, http.StatusOK, discoverRepositoryLinkResponse{
		Status: result.Status, Candidates: result.Candidates, Degraded: result.Degraded, Mode: string(target.mode),
		ReleaseName: target.releaseName, Namespace: target.releaseNamespace,
		ObjectGVK: target.objectGVK, ObjectNamespace: target.objectNamespace, ObjectName: target.objectName,
		OtherClusters: otherClusters,
	})
}

// otherClustersRunningRelease is the honest version of "which other
// clusters run this release": every cluster (other than this one) that
// ARGUS's OWN incidents already record the identical Helm release/namespace
// against, via incidents.ownership — not a live, fleet-wide inventory scan,
// which does not exist. A cluster running the release with zero incidents
// ever recorded on it is genuinely unknown to this query, and the "widen"
// UI must never claim otherwise (see the frontend's own copy).
func otherClustersRunningRelease(ctx context.Context, tx pgx.Tx, excludeClusterID, releaseName, releaseNamespace string) ([]otherClusterRunningRelease, error) {
	rows, err := tx.Query(ctx,
		`SELECT DISTINCT i.cluster_id, c.display_name
		   FROM incidents i
		   JOIN clusters c ON c.id = i.cluster_id
		  WHERE i.cluster_id <> $1
		    AND i.ownership ->> 'managed_by' = 'helm'
		    AND i.ownership -> 'app_ref' ->> 'name' = $2
		    AND i.ownership -> 'app_ref' ->> 'namespace' = $3
		  ORDER BY c.display_name`,
		excludeClusterID, releaseName, releaseNamespace)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []otherClusterRunningRelease{}
	for rows.Next() {
		var c otherClusterRunningRelease
		if err := rows.Scan(&c.ClusterID, &c.ClusterDisplayName); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

type confirmRepositoryLinkRequest struct {
	BindingID string      `json:"bindingId"`
	Path      string      `json:"path"`
	Scope     authz.Scope `json:"scope"`
}

// handleConfirmRepositoryLink is POST /api/v1/incidents/{id}/confirm-repository-link.
// Requires repo:write — this is the one-click confirmation F30 decision 1
// requires: ARGUS never links silently, even on an exact render match, and
// this route is the only write path that actually adds an ObjectMapping
// FOR this feature (as opposed to RepositoriesCard's own hand-authored
// editor, still there for the direct-API/manual case).
//
// releaseName/namespace are NEVER taken from the request body — they are
// re-read from the incident's own stored ownership, the same way path/scope
// are the only things this form actually asks a human to confirm. A client
// that could name its own release/namespace could register a mapping this
// incident's own evidence never proved.
func (s *Server) handleConfirmRepositoryLink(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	incidentID := r.PathValue("id")

	var req confirmRepositoryLinkRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}
	if req.BindingID == "" || req.Path == "" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "bindingId and path are both required", "")
		return
	}

	target, reason, err := resolveHelmReleaseTarget(r.Context(), rc, incidentID)
	if err != nil {
		logger.ErrorContext(r.Context(), "resolving the incident's repository-link target failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not read this incident's ownership", "")
		return
	}
	if writeHelmReleaseTargetProblem(w, reason) {
		return
	}

	// Default scope, per F30 decision 4: "propose Scope: Cluster by
	// default... narrow is the safe default". A caller that omits scope
	// entirely gets exactly that, rather than an error demanding it spell
	// out what the UI's own default button already means.
	scope := req.Scope
	if scope.Type == "" {
		scope = authz.Scope{Type: "Cluster", ClusterID: target.clusterID}
	}

	// The two identity shapes F30 confirms — see helmReleaseTarget's own doc
	// comment. Manifest mode stores target.labels VERBATIM as the
	// LabelSelector: those are exactly the labels get_gitops_ownership
	// reported for the live object, never a human's typed-in guess, which is
	// what "matched the same way, by rendering, with no label selectors"
	// (owner decision 2026-09-09) actually means in code — the SELECTOR
	// exists, only its VALUES are never typed.
	newMapping := scm.ObjectMapping{Path: req.Path, Scope: scope}
	switch target.mode {
	case linkModeManifest:
		newMapping.LabelSelector = target.labels
	default:
		newMapping.ReleaseName, newMapping.Namespace = target.releaseName, target.releaseNamespace
	}
	if err := newMapping.Validate(); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "Could not register this link", err.Error())
		return
	}

	bindings, err := s.scmStore.ListBindings(r.Context(), rc.Tx)
	if err != nil {
		logger.ErrorContext(r.Context(), "listing the repository bindings failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up the repository", "")
		return
	}
	var repoBinding *scm.Binding
	for i := range bindings {
		if bindings[i].ID == req.BindingID {
			repoBinding = &bindings[i]
			break
		}
	}
	if repoBinding == nil {
		writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "No such repository binding", "")
		return
	}

	mappings := append(append([]scm.ObjectMapping{}, repoBinding.ObjectMappings...), newMapping)
	saved, err := s.scmStore.UpdateBinding(r.Context(), rc.Tx, rc.TenantID, req.BindingID, scm.BindingPatch{ObjectMappings: &mappings}, nil)
	if err != nil {
		if errors.Is(err, scm.ErrNoBinding) {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "No such repository binding", "")
			return
		}
		logger.ErrorContext(r.Context(), "updating the repository binding failed", slog.String("binding_id", req.BindingID), logging.Err(err))
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "Could not register this link", err.Error())
		return
	}

	// Re-resolve THIS incident's ownership immediately, now that a mapping
	// exists to match — the same live lookup gatherOwnershipFacts always
	// runs, so this incident's own ownership.repo (and therefore the PR
	// channel on its detail page) reflects the confirmed link on this same
	// request, not only on the next re-analyze. incidents.route/
	// route_reason are a separate fact this does not recompute — the next
	// real analysis picks those up, same as any other ownership change that
	// happens between analyses.
	gatherOwnershipFacts(r.Context(), rc.Tx, s.gw, s.scmStore, incidentID, target.clusterID)

	capability := authz.CapRepoWrite
	if err := recordRepoLinkAudit(r.Context(), rc, r, "confirm_repository_link", map[string]any{
		"incidentId": incidentID, "repositoryBindingId": saved.ID, "path": req.Path, "mode": string(target.mode),
		"releaseName": target.releaseName, "namespace": target.releaseNamespace, "labels": target.labels, "scopeType": scope.Type,
	}, capability); err != nil {
		logger.ErrorContext(r.Context(), "recording a repository-link confirmation in the audit log failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record this change", "")
		return
	}
	writeJSON(w, http.StatusOK, bindingView(saved))
}

// handleDeclineRepositoryLink is POST /api/v1/incidents/{id}/decline-repository-link.
// Requires repo:write — a decline is stored, durable state (migration
// 000104), the same reason confirming one is.
func (s *Server) handleDeclineRepositoryLink(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	incidentID := r.PathValue("id")

	target, reason, err := resolveHelmReleaseTarget(r.Context(), rc, incidentID)
	if err != nil {
		logger.ErrorContext(r.Context(), "resolving the incident's repository-link target failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not read this incident's ownership", "")
		return
	}
	if writeHelmReleaseTargetProblem(w, reason) {
		return
	}

	if err := recordDecline(r.Context(), rc.Tx, rc.TenantID, rc.UserID, target); err != nil {
		logger.ErrorContext(r.Context(), "recording a repository-link decline failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record this decision", "")
		return
	}

	capability := authz.CapRepoWrite
	if err := recordRepoLinkAudit(r.Context(), rc, r, "decline_repository_link", map[string]any{
		"incidentId": incidentID, "clusterId": target.clusterID, "mode": string(target.mode),
		"releaseName": target.releaseName, "namespace": target.releaseNamespace,
		"objectGvk": target.objectGVK, "objectNamespace": target.objectNamespace, "objectName": target.objectName,
	}, capability); err != nil {
		logger.ErrorContext(r.Context(), "recording a repository-link decline in the audit log failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record this change", "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// helmLinkAlreadyDeclined is F30 decision 4's read side.
func helmLinkAlreadyDeclined(ctx context.Context, tx pgx.Tx, clusterID, releaseName, releaseNamespace string) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM helm_link_declines WHERE cluster_id = $1 AND release_name = $2 AND namespace = $3)`,
		clusterID, releaseName, releaseNamespace).Scan(&exists)
	return exists, err
}

// recordRepoLinkAudit is the audit.RecordEvent call shape every repository
// write in this package already uses (repositories.go), pulled out once
// since all three of this file's routes want the identical shape with only
// the action name and details changing.
func recordRepoLinkAudit(ctx context.Context, rc *requestContext, r *http.Request, action string, details map[string]any, capability string) error {
	details["action"] = action
	return audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID: rc.TenantID, ActorID: &rc.UserID, ActorAuthMethod: "jwt",
		SourceIP: clientIP(r), Capability: &capability, Outcome: audit.OutcomeSuccess,
		Details: details,
	})
}
