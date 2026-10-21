package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/logging"
	"argus/internal/scm"
)

// Repository bindings: which Git repositories ARGUS may open a pull request
// against, and the credential it uses.
//
// The credential model is settled in REMEDIATION_ROADMAP.md D-R9: one
// fine-grained token per provider, org-level rather than per-user,
// envelope-encrypted at rest, scoped to named repositories — never "everything
// this account can reach". A classic PAT is refused not out of purity but
// because that exposure cannot be sized, and a risk that cannot be sized cannot
// be accepted, only ignored.
//
// Gated on `repo:write` for mutation and `repo:read` for the list. Those two
// capabilities have existed in the catalogue since the beginning with nothing
// behind them; this is what they now gate.

type repositoryBindingView struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	URL      string `json:"url"`
	Host     string `json:"host"`
	// Empty means the provider's public API. Non-empty is a self-hosted GHES or
	// GitLab CE/EE — DESIGN.md §11.3's "configurable API base URL, required not
	// optional".
	APIBaseURL    string `json:"apiBaseUrl,omitempty"`
	DefaultBranch string `json:"defaultBranch,omitempty"`
	// The token is NEVER returned, in any form. Only whether one is stored and
	// when it expires — the same write-only contract as the LLM API key.
	CredentialStored bool   `json:"credentialStored"`
	ExpiresAt        string `json:"expiresAt,omitempty"`
	// ExpiresInDays is computed rather than left to the client, so every
	// consumer agrees on when to warn. Negative means already expired, which is
	// a state the UI must be able to show differently from "expires soon".
	ExpiresInDays *int   `json:"expiresInDays,omitempty"`
	CreatedAt     string `json:"createdAt"`
	// ObjectMappings is now returned (previously write-only from the
	// frontend's perspective: scm.Store.ListBindings didn't decode it, so
	// this view had nothing to put here even though the API always accepted
	// it). An editing UI needs this to pre-fill from — otherwise "edit the
	// mappings" can only ever mean "blindly replace them," the exact hazard
	// this field's own "supplying it replaces the list" contract exists to
	// warn about, not to invite. Never omitted, even when empty: an absent
	// key and an empty list are different facts for a form deciding whether
	// to render "no mappings configured yet" or a client bug.
	ObjectMappings []scm.ObjectMapping `json:"objectMappings"`
}

func bindingView(b scm.Binding) repositoryBindingView {
	objectMappings := b.ObjectMappings
	if objectMappings == nil {
		objectMappings = []scm.ObjectMapping{}
	}
	v := repositoryBindingView{
		ID: b.ID, Provider: b.Provider, URL: b.URL, Host: b.Host,
		APIBaseURL: b.APIBaseURL, DefaultBranch: b.DefaultBranch,
		CredentialStored: b.CredentialRef != "",
		CreatedAt:        formatRFC3339(b.CreatedAt),
		ObjectMappings:   objectMappings,
	}
	if b.CredentialExpiresAt != nil {
		v.ExpiresAt = formatRFC3339(*b.CredentialExpiresAt)
		days := int(time.Until(*b.CredentialExpiresAt).Hours() / 24)
		v.ExpiresInDays = &days
	}
	return v
}

type createRepositoryBindingRequest struct {
	Provider string `json:"provider"`
	URL      string `json:"url"`
	// Token is write-only. A fine-grained PAT (GitHub) or group access token
	// (GitLab), scoped to this repository with contents:write and
	// pull_requests:write and nothing else.
	Token         string `json:"token"`
	APIBaseURL    string `json:"apiBaseUrl"`
	DefaultBranch string `json:"defaultBranch"`
	// ExpiresAt is what the operator read off the token when they created it.
	// Optional, and its absence is not an error — but supplying it is what lets
	// ARGUS warn BEFORE the token dies rather than reporting the resulting PR
	// failures after, which D-R9 calls out as a requirement rather than a nicety.
	ExpiresAt string `json:"expiresAt"`
	// ObjectMappings is BACKLOG.md F19 mechanism 1: an operator's explicit
	// statement of where a plain-Helm or kubectl-applied object's config
	// lives inside THIS repository — see scm.ObjectMapping's own doc comment
	// for the two forms an entry may take. Optional; omitting it (or sending
	// an empty list) registers the repository with no mappings, same as
	// before this field existed.
	//
	// Re-registering the same URL — the existing rotate-a-token path —
	// REPLACES whatever objectMappings were stored, the same "supplying it
	// updates it" semantics the credential itself already has. There is no
	// per-mapping add/remove: an operator managing more than a couple of
	// mappings sends the whole list each time (matching how, in this
	// codebase's stated defaults, the other spec fields — writeScope,
	// fixBranch — are not independently editable either).
	//
	// PUT /api/v1/repositories/{id} (updateRepositoryBindingRequest, below)
	// is now the preferred way to change this on an EXISTING binding without
	// resending every other field or a fresh token — this create path's own
	// rotate-by-repeating-the-URL behaviour still works exactly as described
	// above, it's just no longer the only way to reach this field.
	ObjectMappings []scm.ObjectMapping `json:"objectMappings"`
}

// handleListRepositoryBindings is GET /api/v1/repositories. Requires repo:read.
func (s *Server) handleListRepositoryBindings(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	bindings, err := s.scmStore.ListBindings(r.Context(), rc.Tx)
	if err != nil {
		logger.ErrorContext(r.Context(), "listing the repository bindings failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list repositories", "")
		return
	}
	out := make([]repositoryBindingView, 0, len(bindings))
	for _, b := range bindings {
		out = append(out, bindingView(b))
	}
	writeJSON(w, http.StatusOK, map[string]any{"repositories": out})
}

// handleCreateRepositoryBinding is POST /api/v1/repositories. Requires
// repo:write.
//
// Re-registering the same URL replaces its credential rather than failing —
// that is how a token is rotated, and making rotation an error would push
// operators towards deleting and recreating the binding, which loses its
// history for no reason.
func (s *Server) handleCreateRepositoryBinding(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	var req createRepositoryBindingRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}
	if req.Token == "" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
			"A token is required",
			"Register the repository with a fine-grained token scoped to it, granting contents:write and pull_requests:write. Without one ARGUS can read the repository's identity but cannot propose a change to it.")
		return
	}
	// docs/USER_GUIDE.md §3 has always said ARGUS refuses a classic broad-scope
	// token. Until now nothing did — see internal/scm/tokenshape.go for why that
	// mattered more than an ordinary doc drift: the guide's promise meant an
	// operator could infer they would be warned about an over-scoped credential,
	// and they never were.
	if reason := scm.ClassicTokenRefusal(req.Token); reason != "" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
			"That token is broader than ARGUS will accept", reason)
		return
	}

	var expiresAt *time.Time
	if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
				"Invalid expiresAt", "expiresAt must be an RFC 3339 timestamp, e.g. 2027-01-31T00:00:00Z")
			return
		}
		expiresAt = &t
	}

	// The token is converted to bytes here and never held as a string beyond
	// this call: SaveBinding zeroes the slice. The request struct's own copy is
	// unavoidable (Go strings are immutable and cannot be zeroed), which is why
	// the request body is size-limited and never logged.
	expiresAtForAudit := req.ExpiresAt
	token := []byte(req.Token)
	req.Token = ""

	saved, err := s.scmStore.SaveBinding(r.Context(), rc.Tx, rc.TenantID, scm.Binding{
		Provider:            req.Provider,
		URL:                 req.URL,
		APIBaseURL:          req.APIBaseURL,
		DefaultBranch:       req.DefaultBranch,
		CredentialExpiresAt: expiresAt,
		ObjectMappings:      req.ObjectMappings,
	}, token)
	if err != nil {
		// scm's validation errors are written for an operator to act on (bad
		// scheme, embedded credentials, unknown provider), so they are passed
		// through as the detail rather than replaced with something generic.
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
			"Could not register this repository", err.Error())
		return
	}

	capability := authz.CapRepoWrite
	if err := audit.RecordEvent(r.Context(), rc.Tx, audit.Event{
		TenantID: rc.TenantID, ActorID: &rc.UserID, ActorAuthMethod: "jwt",
		SourceIP: clientIP(r), Capability: &capability, Outcome: audit.OutcomeSuccess,
		Details: map[string]any{
			"action":              "register_repository",
			"repositoryBindingId": saved.ID,
			"provider":            saved.Provider,
			"url":                 saved.URL,
			// Recorded because it is the security-relevant half of the decision
			// and is not otherwise visible later: whether this binding talks to
			// a public provider or a self-hosted one.
			"apiBaseUrl":        saved.APIBaseURL,
			"credentialExpires": expiresAtForAudit,
			// BACKLOG.md F19 — a count, not the mappings themselves: a mapping
			// names a release/namespace or labels, not a secret, but the audit
			// record does not need the full list to show that this write
			// changed them, and keeping this entry the same shape as the rest
			// (small, scalar facts) is worth more than completeness here.
			"objectMappingsCount": len(saved.ObjectMappings),
		},
	}); err != nil {
		logger.ErrorContext(r.Context(), "recording a repository-binding creation in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record this change", "")
		return
	}
	writeJSON(w, http.StatusCreated, bindingView(saved))
}

// updateRepositoryBindingRequest is PUT /api/v1/repositories/{id}'s body — a
// genuine partial update, unlike create's implicit full overwrite. Every
// field is a pointer for the same reason settings.UpdateProvider's are: nil
// (omitted, or explicit JSON `null`) means "leave this alone." A non-nil
// value, including an empty string, is applied — matching create's own
// contract for what an empty apiBaseUrl/defaultBranch/expiresAt means, just
// now something an operator can set INDEPENDENTLY of every other field.
type updateRepositoryBindingRequest struct {
	URL           *string `json:"url"`
	APIBaseURL    *string `json:"apiBaseUrl"`
	DefaultBranch *string `json:"defaultBranch"`
	// Token is optional here, unlike create's required field: nil or ""
	// leaves the stored credential untouched. A non-empty value rotates it,
	// through the same classic-token refusal check create's own path uses.
	Token *string `json:"token"`
	// ExpiresAt distinguishes three states through one nullable string,
	// mirroring scm.BindingPatch.ExpiresAtProvided: omitted/null leaves the
	// stored expiry alone; "" clears it; anything else must parse as RFC
	// 3339.
	ExpiresAt      *string              `json:"expiresAt"`
	ObjectMappings *[]scm.ObjectMapping `json:"objectMappings"`
}

// handleUpdateRepositoryBinding is PUT /api/v1/repositories/{id}. Requires
// repo:write.
//
// See scm.BindingPatch's own doc comment for why this exists: create's
// re-register-the-same-URL rotation path is a full overwrite (a
// default-branch fix that didn't happen to resend apiBaseUrl/objectMappings
// would silently wipe them back to their create-time defaults) and cannot
// change the URL at all (a different URL is a different repo_key, so it
// would register a second, orphaned binding rather than editing this one).
func (s *Server) handleUpdateRepositoryBinding(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	id := r.PathValue("id")

	var req updateRepositoryBindingRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}

	var token []byte
	rotating := req.Token != nil && *req.Token != ""
	if rotating {
		if reason := scm.ClassicTokenRefusal(*req.Token); reason != "" {
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
				"That token is broader than ARGUS will accept", reason)
			return
		}
		token = []byte(*req.Token)
	}

	patch := scm.BindingPatch{
		URL:            req.URL,
		APIBaseURL:     req.APIBaseURL,
		DefaultBranch:  req.DefaultBranch,
		ObjectMappings: req.ObjectMappings,
	}
	if req.ExpiresAt != nil {
		patch.ExpiresAtProvided = true
		if *req.ExpiresAt != "" {
			t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
			if err != nil {
				writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
					"Invalid expiresAt", "expiresAt must be an RFC 3339 timestamp, e.g. 2027-01-31T00:00:00Z")
				return
			}
			patch.CredentialExpiresAt = &t
		}
	}

	saved, err := s.scmStore.UpdateBinding(r.Context(), rc.Tx, rc.TenantID, id, patch, token)
	if err != nil {
		switch {
		case errors.Is(err, scm.ErrNoBinding):
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "No such repository binding", "")
		case errors.Is(err, scm.ErrRepoKeyConflict):
			writeProblem(w, http.StatusConflict, "https://argus.io/errors/conflict",
				"Another repository is already registered for that URL", "")
		default:
			// scm's own validation errors (bad URL scheme, embedded
			// credentials, a malformed object mapping) are written for an
			// operator to act on, same as create's — passed through as the
			// detail rather than replaced with something generic.
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
				"Could not update this repository", err.Error())
		}
		return
	}

	capability := authz.CapRepoWrite
	if err := audit.RecordEvent(r.Context(), rc.Tx, audit.Event{
		TenantID: rc.TenantID, ActorID: &rc.UserID, ActorAuthMethod: "jwt",
		SourceIP: clientIP(r), Capability: &capability, Outcome: audit.OutcomeSuccess,
		Details: map[string]any{
			"action":              "update_repository",
			"repositoryBindingId": saved.ID,
			"url":                 saved.URL,
			"apiBaseUrl":          saved.APIBaseURL,
			// Whether the credential itself changed is the security-relevant
			// fact worth a boolean here — the token's own value never is.
			"credentialRotated": rotating,
		},
	}); err != nil {
		logger.ErrorContext(r.Context(), "recording a repository-binding update in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record this change", "")
		return
	}
	writeJSON(w, http.StatusOK, bindingView(saved))
}

// handleDeleteRepositoryBinding is DELETE /api/v1/repositories/{id}. Requires
// repo:write. Removes the binding and its credential together — an orphaned
// credential nobody can see is worse than either half alone.
func (s *Server) handleDeleteRepositoryBinding(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	id := r.PathValue("id")
	if err := s.scmStore.DeleteBinding(r.Context(), rc.Tx, id); err != nil {
		if errors.Is(err, scm.ErrNoBinding) {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "No such repository binding", "")
			return
		}
		logger.ErrorContext(r.Context(), "deleting the repository binding failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not remove this repository", "")
		return
	}
	capability := authz.CapRepoWrite
	if err := audit.RecordEvent(r.Context(), rc.Tx, audit.Event{
		TenantID: rc.TenantID, ActorID: &rc.UserID, ActorAuthMethod: "jwt",
		SourceIP: clientIP(r), Capability: &capability, Outcome: audit.OutcomeSuccess,
		Details: map[string]any{"action": "unregister_repository", "repositoryBindingId": id},
	}); err != nil {
		logger.ErrorContext(r.Context(), "recording a repository-binding deletion in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record this change", "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleCheckRepositoryBinding is POST /api/v1/repositories/{id}/check.
// Requires repo:write.
//
// Proves the credential works NOW, before an incident depends on it. Without
// this the first time anyone learns a token is wrong is when a remediation PR
// fails, which is both the worst moment to find out and the hardest place to
// debug it. Reads the repository's default branch: the cheapest call that
// exercises authentication, authorization and the API base URL together.
func (s *Server) handleCheckRepositoryBinding(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	id := r.PathValue("id")

	bindings, err := s.scmStore.ListBindings(r.Context(), rc.Tx)
	if err != nil {
		logger.ErrorContext(r.Context(), "listing the repository bindings for a connectivity check failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up this repository", "")
		return
	}
	var target *scm.Binding
	for i := range bindings {
		if bindings[i].ID == id {
			target = &bindings[i]
			break
		}
	}
	if target == nil {
		writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "No such repository binding", "")
		return
	}

	provider, repo, _, err := s.scmStore.ProviderFor(r.Context(), rc.Tx, target.URL)
	if err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "https://argus.io/errors/repository-unusable",
			"This repository's credential could not be used", err.Error())
		return
	}

	// An operator-configured DefaultBranch is authoritative, matching
	// baseBranchFor (internal/api/repository_change.go) and
	// matchObjectMapping (internal/api/routing.go) — the two places that
	// actually resolve a base branch to open a pull request already treat a
	// stored branch as settled and never re-derive it. This handler used to
	// be the one place that skipped that check and always called the
	// provider's own auto-detection instead, which reads a repository's
	// `default_branch` field — and on at least one real self-hosted GitLab
	// project with genuine commit history, that field comes back empty (its
	// default-branch pointer left unset, an admin-side GitLab state, not
	// anything wrong with the credential). That surfaced as "Check
	// credential" failing on a repository the credential could read fine, on
	// a binding whose own stored branch this handler had never even looked
	// at.
	//
	// A stored branch still has to be PROVEN, not just echoed back — this
	// endpoint's whole point is exercising the credential now, not trusting
	// what the operator typed. ResolveRef does that: it is a real
	// authenticated read (proving the credential still works) that also
	// confirms the configured branch actually exists, which DefaultBranch's
	// own auto-detection never checked in the first place.
	branch := target.DefaultBranch
	if branch != "" {
		if _, err = provider.ResolveRef(r.Context(), repo, branch); err != nil {
			status := http.StatusUnprocessableEntity
			if errors.Is(err, scm.ErrCredentialExpired) || errors.Is(err, scm.ErrForbidden) {
				status = http.StatusForbidden
			}
			writeProblem(w, status, "https://argus.io/errors/repository-unusable",
				"This repository's credential could not be used", err.Error())
			return
		}
	} else {
		branch, err = provider.DefaultBranch(r.Context(), repo)
		if err != nil {
			// The provider's own message is passed through: it distinguishes an
			// expired token from an under-scoped one from a rate limit, and each has
			// a different fix. Collapsing them into "check failed" would throw away
			// the only part that tells the operator what to do.
			status := http.StatusUnprocessableEntity
			if errors.Is(err, scm.ErrCredentialExpired) || errors.Is(err, scm.ErrForbidden) {
				status = http.StatusForbidden
			}
			writeProblem(w, status, "https://argus.io/errors/repository-unusable",
				"This repository's credential could not be used", err.Error())
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"provider":      provider.Name(),
		"repository":    repo.String(),
		"defaultBranch": branch,
		"message":       "The credential can read this repository. Note this proves READ access; opening a pull request additionally needs contents:write and pull_requests:write.",
	})
}

// A limit worth stating rather than leaving a reader to assume otherwise: Go
// strings cannot be zeroed, so the token's copy inside the decoded request
// struct lives until GC. The mitigations that DO work are the ones applied
// above — the body is size-limited, never logged, and the plaintext byte slice
// handed to the store is zeroed by SaveBinding.
