package scm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"argus/internal/outbound"
)

// GitLab is a Provider over GitLab's REST API v4, authenticated with a scoped
// access token (REMEDIATION_ROADMAP.md D-R9, BACKLOG.md F15: "one scoped token
// per provider, no App").
//
// # The credential
//
// A **group access token** — not a personal one (F15 is explicit about this: a
// personal token dies at offboarding and self-approval policies at many orgs
// forbid a human reviewer's own token acting here) — on a dedicated machine
// identity, scoped to the group/subgroup with the `api` scope. GitLab has no
// finer-grained split of "read repo contents" vs "open merge requests" the way
// a GitHub fine-grained PAT does; `api` is the narrowest scope that can do
// both, and that coarseness is GitLab's, not a choice made here.
//
// # Configurable base URL
//
// Same reasoning as GitHub's (see github.go): DESIGN.md §11.3 requires this be
// configurable from the first commit so a customer's self-hosted GitLab CE/EE
// is reachable. BaseURL, like GitHub's, is the full API root an operator
// types — empty means the public "https://gitlab.com/api/v4"; self-hosted is
// typically "https://gitlab.example.com/api/v4".
type GitLab struct {
	// BaseURL is the API root. Empty means "https://gitlab.com/api/v4".
	BaseURL string
	// Token is the group access token. Held in memory only for the lifetime of
	// this value; see internal/secretbox.Open's contract.
	Token string
	// HTTPClient is injectable so tests can run against a local server. A nil
	// client gets a bounded default — see GitHub's identical field for why an
	// unbounded one is refused.
	HTTPClient *http.Client
	// UserAgent is sent on every request. GitLab does not require one the way
	// GitHub does, but sending one is free and consistent with the sibling
	// provider.
	UserAgent string
	// PrivateDestinations is GitHub's identical field — the operator allowlist
	// of private destinations this client may reach, for a self-hosted GitLab
	// CE/EE on an internal address. See that field's doc comment.
	PrivateDestinations outbound.AllowlistSource
}

func (g *GitLab) Name() string { return "gitlab" }

func (g *GitLab) client() *http.Client {
	if g.HTTPClient != nil {
		return g.HTTPClient
	}
	// See GitHub.client's identical comment: BaseURL is admin-configured
	// (a self-hosted GitLab CE/EE root) and gets the same default refusal
	// of metadata/loopback/link-local/private destinations, and the same
	// narrow operator allowlist as the only way past it (owner decision,
	// 2026-09-19; migration 000115). No AllowPrivate here either.
	return outbound.NewClient(outbound.Policy{PrivateDestinations: g.PrivateDestinations}, 30*time.Second)
}

func (g *GitLab) base() string {
	if g.BaseURL == "" {
		return "https://gitlab.com/api/v4"
	}
	return strings.TrimSuffix(g.BaseURL, "/")
}

func (g *GitLab) userAgent() string {
	if g.UserAgent == "" {
		return "argus"
	}
	return g.UserAgent
}

// errGitLabBadRequest marks a 400 whose message did not identify a more
// specific cause (i.e., not "already exists" — see the 400 case in do). It is
// unexported and exists only so PutFile can apply the judgment call documented
// on its own body, without that heuristic accidentally firing on a 401, 403,
// 404, 409 or 5xx — none of which may ever be reported as a compare-and-swap
// conflict.
var errGitLabBadRequest = errors.New("gitlab: request rejected (400)")

// do performs one API call and maps the status code onto this package's
// sentinels. Structurally identical to GitHub's do (see github.go for the
// general rationale); the differences below are GitLab-specific, not
// stylistic.
func (g *GitLab) do(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("gitlab: marshal request: %w", err)
		}
		reader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, g.base()+path, reader)
	if err != nil {
		return fmt.Errorf("gitlab: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", g.userAgent())
	// PRIVATE-TOKEN, deliberately NOT "Authorization: Bearer" — GitLab's REST API
	// takes the token in its own header, unlike GitHub's bearer scheme (and
	// unlike GitLab's own GraphQL API, which DOES take a bearer token — the
	// REST/GraphQL split is real and this provider only speaks REST). Getting
	// this wrong does not 400 with a helpful message; it 401s exactly the way an
	// invalid token would, which is the easy-to-get-wrong asymmetry BACKLOG.md
	// F15 calls out by name.
	if g.Token != "" {
		req.Header.Set("PRIVATE-TOKEN", g.Token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := g.client().Do(req)
	if err != nil {
		// Deliberately does not wrap the URL — see github.go's identical
		// comment on why that is the one path a future change could start
		// echoing a token-bearing value through.
		return fmt.Errorf("gitlab: %s request failed: %w", method, err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return ErrNotFound
	case resp.StatusCode == http.StatusUnauthorized:
		return fmt.Errorf("%w: GitLab rejected the credential (401). A group access token expires; renew it rather than widening its scope", ErrCredentialExpired)
	case resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("%w: GitLab refused this operation (403). Check that the group access token's role and scope (api) cover this project. GitLab said: %s", ErrForbidden, gitlabMessage(payload))
	case resp.StatusCode == http.StatusTooManyRequests:
		// GitLab gives rate limiting its OWN status code rather than overloading
		// 403 the way GitHub does — simpler than GitHub's header-sniffing, except
		// that GitLab's own RateLimit-* headers are documented as unreliable on
		// the 429 response itself, so the status code alone is what this checks,
		// not a header value.
		return fmt.Errorf("%w: GitLab rate limit exceeded (429) — not a permissions problem", ErrForbidden)
	case resp.StatusCode == http.StatusConflict:
		// Observed (via community reports, not the primary "create merge
		// request" docs page, which does not itself spell out this status code)
		// for "this merge request already exists" — a second MR proposed for the
		// same source/target branch pair. Could not be independently verified
		// against a live GitLab instance.
		return fmt.Errorf("%w: %s", ErrAlreadyExists, gitlabMessage(payload))
	case resp.StatusCode == http.StatusBadRequest:
		// GitLab's own docs for the repository-files write endpoints say a failed
		// commit comes back as "400 Bad Request" with "a non-specific error
		// message" — its own word, not this codebase's guess — so unlike GitHub's
		// 422 (where the message is what distinguishes "already exists" from a
		// genuine validation failure), a 400 here is not reliably self-describing
		// beyond the "already exists" case (confirmed via GitLab's own branch-
		// creation error text). Anything else 400s into errGitLabBadRequest,
		// which PutFile — and only PutFile — turns into ErrConflict, with that
		// judgment call documented on PutFile itself rather than here.
		msg := gitlabMessage(payload)
		if strings.Contains(strings.ToLower(msg), "already exist") {
			return fmt.Errorf("%w: %s", ErrAlreadyExists, msg)
		}
		return fmt.Errorf("%w: %s", errGitLabBadRequest, msg)
	case resp.StatusCode >= 300:
		return fmt.Errorf("gitlab: unexpected status %d: %s", resp.StatusCode, gitlabMessage(payload))
	}

	if out != nil && len(payload) > 0 {
		if err := json.Unmarshal(payload, out); err != nil {
			return fmt.Errorf("gitlab: decode response: %w", err)
		}
	}
	return nil
}

// gitlabMessage pulls a human-readable message out of an error body. GitLab's
// error shapes are less uniform than GitHub's single {"message": "..."}: a
// plain string, an array of strings (validation errors), and an OAuth-flavored
// {"error": "...", "error_description": "..."} (seen on some auth failures)
// are all real, so each is tried in turn before falling back to the raw body —
// never silently empty.
func gitlabMessage(payload []byte) string {
	var asString struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(payload, &asString) == nil && asString.Message != "" {
		return truncateMessage(asString.Message)
	}
	var asArray struct {
		Message []string `json:"message"`
	}
	if json.Unmarshal(payload, &asArray) == nil && len(asArray.Message) > 0 {
		return truncateMessage(strings.Join(asArray.Message, "; "))
	}
	var asOAuth struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if json.Unmarshal(payload, &asOAuth) == nil && (asOAuth.Error != "" || asOAuth.ErrorDescription != "") {
		s := asOAuth.Error
		if asOAuth.ErrorDescription != "" {
			if s != "" {
				s += ": "
			}
			s += asOAuth.ErrorDescription
		}
		return truncateMessage(s)
	}
	return truncateMessage(string(payload))
}

// truncateMessage bounds a provider message the same way githubMessage does —
// this text ends up in an API response an operator reads, and its length is
// not ARGUS's to control.
func truncateMessage(msg string) string {
	msg = strings.Join(strings.Fields(msg), " ")
	if len(msg) > 400 {
		msg = msg[:400] + "… (truncated)"
	}
	return msg
}

// projectPath builds GitLab's `:id` path segment. Unlike GitHub's two clean
// URL segments (owner, name), GitLab's project API takes ONE path segment that
// is the URL-encoded "namespace/project" string — including subgroups, so
// "group/subgroup/project" becomes one segment with its internal slashes
// percent-encoded too. This is exactly what url.PathEscape does to a string
// containing "/" (unlike GitHub's contentsPath, which escapes each segment
// individually and rejoins with a literal "/" so the API sees real path
// segments) — the one place this file's escaping deliberately looks different
// from github.go's, for a reason, not by accident.
func projectPath(r Repo) string {
	return "/projects/" + url.PathEscape(r.Owner+"/"+r.Name)
}

func (g *GitLab) DefaultBranch(ctx context.Context, repo Repo) (string, error) {
	var out struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := g.do(ctx, http.MethodGet, projectPath(repo), nil, &out); err != nil {
		return "", err
	}
	if out.DefaultBranch == "" {
		// Observed live against a real self-hosted GitLab project with real
		// commit history and branches: `default_branch` still came back
		// empty — its pointer was unset on GitLab's side, not anything wrong
		// with the token. Named as a workaround, not just a failure: the
		// operator can set this binding's own Default branch field instead
		// of waiting on GitLab, and every real caller that opens a pull
		// request (baseBranchFor, matchObjectMapping) already prefers a
		// stored branch over calling this method at all.
		return "", fmt.Errorf("gitlab: %s has no default branch configured on GitLab's side (this can happen even with real commit history) — set this repository's Default branch field in ARGUS instead of relying on auto-detection", repo)
	}
	return out.DefaultBranch, nil
}

func (g *GitLab) ResolveRef(ctx context.Context, repo Repo, ref string) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	// :sha accepts a branch, tag or commit SHA per GitLab's own docs, same as
	// GitHub's commits endpoint. A branch name containing "/" needs the same
	// percent-encoded-slash treatment as projectPath, hence PathEscape rather
	// than a bare string concatenation.
	path := projectPath(repo) + "/repository/commits/" + url.PathEscape(ref)
	if err := g.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", fmt.Errorf("gitlab: %s@%s resolved to no commit", repo, ref)
	}
	return out.ID, nil
}

// gitlabFileMeta is the Repository Files API's per-file shape.
//
// last_commit_id — NOT blob_id — is what this file uses as the compare-and-swap
// token, because it is what the write endpoints' own `last_commit_id`
// parameter compares against (see PutFile). blob_id is the git blob SHA of the
// content, which GitHub's Contents API also returns and which GitHub's write
// endpoint compares against directly — GitLab's write endpoint does not take a
// blob SHA at all, so blob_id is read here but deliberately never used as a
// precondition token.
type gitlabFileMeta struct {
	Content      string `json:"content"`
	Encoding     string `json:"encoding"`
	BlobID       string `json:"blob_id"`
	LastCommitID string `json:"last_commit_id"`
}

// readFilePath builds the GET path. ref is a REQUIRED parameter on this
// endpoint (unlike GitHub's, where an absent ref means "the default branch"),
// so an empty ref is defaulted to the literal "HEAD", which GitLab documents as
// meaning exactly that.
func (g *GitLab) readFilePath(repo Repo, path, ref string) string {
	if ref == "" {
		ref = "HEAD"
	}
	// The whole path is percent-encoded as ONE segment (internal "/" becomes
	// "%2F") — this is GitLab's own documented convention for :file_path, the
	// opposite of GitHub's per-segment escaping in contentsPath. There is also
	// no directory-vs-file ambiguity to handle here the way GitHub's unified
	// Contents API has: GitLab exposes directory listing as a wholly separate
	// endpoint (`/repository/tree`), so a path that names a directory simply
	// 404s against this one rather than coming back with `"type": "dir"`.
	return projectPath(repo) + "/repository/files/" + url.PathEscape(strings.TrimPrefix(path, "/")) + "?ref=" + url.QueryEscape(ref)
}

func (g *GitLab) readFileWithMeta(ctx context.Context, repo Repo, ref, path string) ([]byte, string, error) {
	var meta gitlabFileMeta
	if err := g.do(ctx, http.MethodGet, g.readFilePath(repo, path, ref), nil, &meta); err != nil {
		return nil, "", err
	}
	if meta.Encoding != "base64" {
		// Not documented as ever happening (unlike GitHub's ">1MB -> encoding
		// none"), but refused loudly rather than assumed, matching this
		// package's "never silently pretend a guarantee holds" rule — decoding
		// an unexpected encoding as base64 could silently produce garbage
		// content and a PR that corrupts the file it meant to fix.
		return nil, "", fmt.Errorf("gitlab: %s came back with encoding %q rather than base64 — this build only decodes base64", path, meta.Encoding)
	}
	raw, err := base64.StdEncoding.DecodeString(meta.Content)
	if err != nil {
		return nil, "", fmt.Errorf("gitlab: decode %s: %w", path, err)
	}
	return raw, meta.LastCommitID, nil
}

func (g *GitLab) ReadFile(ctx context.Context, repo Repo, ref, path string) ([]byte, error) {
	content, _, err := g.readFileWithMeta(ctx, repo, ref, path)
	return content, err
}

// ReadFileForUpdate returns a file plus its last_commit_id to pass back as
// PutFileInput.BaseSHA. See PutFile for exactly what guarantee this does and
// does not buy on GitLab.
func (g *GitLab) ReadFileForUpdate(ctx context.Context, repo Repo, ref, path string) (content []byte, blobSHA string, err error) {
	return g.readFileWithMeta(ctx, repo, ref, path)
}

func (g *GitLab) CreateBranch(ctx context.Context, repo Repo, branch, fromSHA string) error {
	if fromSHA == "" {
		return errors.New("gitlab: CreateBranch needs a commit SHA to branch from — resolve the ref first, so the branch point is recorded rather than implied")
	}
	body := map[string]string{"branch": branch, "ref": fromSHA}
	return g.do(ctx, http.MethodPost, projectPath(repo)+"/repository/branches", body, nil)
}

// PutFile commits new content for one path on a branch.
//
// # The compare-and-swap this can and cannot promise
//
// GitHub's write endpoint takes the file's exact blob SHA and 409s if it does
// not match what is currently on the branch — a precise, per-file
// compare-and-swap. GitLab's file-write endpoints have no equivalent
// parameter. The closest thing is `last_commit_id`, an OPTIONAL parameter that
// — per GitLab's own issue tracker (gitlab-org/gitlab#3138,
// gitlab-org/gitlab-foss#50381: "last_commit_id parameter should refer to the
// file commit_id in API") — is checked against the BRANCH's last commit, not
// specifically against this file's own last-modifying commit. That means:
//
//   - It DOES prevent a silent overwrite: if the branch moved at all since the
//     caller read last_commit_id, the commit is rejected rather than applied.
//     The core guarantee Provider.PutFile's doc comment requires — never
//     overwrite a change that landed between the read and the write — holds.
//   - It is COARSER than a true per-file CAS: a commit to a completely
//     unrelated file on the same branch also rejects this one, which GitHub's
//     blob-SHA check would not do. A caller may see spurious conflicts that
//     GitHub-backed code would not.
//   - GitLab's own docs describe a failed commit's 400 response as carrying "a
//     non-specific error message" — its wording, not a guess made here — so
//     this cannot even reliably distinguish a last_commit_id mismatch from
//     some other 400 (an empty/no-op diff, a malformed branch name). See the
//     errGitLabBadRequest handling below for the resulting judgment call.
//
// This is reported here rather than silently treated as GitHub-equivalent,
// per this package's "never silently pretend a guarantee holds" convention —
// none of it was verifiable against a live GitLab instance, only against
// GitLab's own documentation and public issue tracker.
//
// # The missing commit SHA
//
// Separately, GitLab's write response carries only {file_path, branch} — NO
// commit SHA at all (this is itself a tracked GitLab gap:
// gitlab-org/gitlab#26371, "Return new SHA on file update"). Provider.PutFile
// must return one, so after a successful write this resolves the branch's new
// head via ResolveRef. That is a second call, not part of the same atomic
// operation as the commit, so it carries its own small race if something else
// commits to the branch in the instant between: the caller would be told
// about a commit that is not its own. There is no better answer available
// through this API — flagged rather than hidden.
func (g *GitLab) PutFile(ctx context.Context, repo Repo, in PutFileInput) (string, error) {
	if in.Branch == "" || in.Path == "" {
		return "", errors.New("gitlab: PutFile needs a branch and a path")
	}
	if len(in.Content) == 0 {
		return "", errors.New("gitlab: refusing to commit empty content — an empty manifest is almost never the intended change, and this is the shape a decode failure upstream would take")
	}

	message := messageWithTrailers(in.Message, in.Trailers)

	body := map[string]any{
		"branch":         in.Branch,
		"content":        base64.StdEncoding.EncodeToString(in.Content),
		"encoding":       "base64",
		"commit_message": message,
	}
	if in.Author.Name != "" {
		body["author_name"] = in.Author.Name
	}
	if in.Author.Email != "" {
		body["author_email"] = in.Author.Email
	}

	// Absent BaseSHA means "create" -> POST, per GitLab's split endpoints
	// (unlike GitHub, which uses PUT for both and distinguishes by whether "sha"
	// is present). Present means "update this exact version" -> PUT with
	// last_commit_id — see the doc comment above for exactly what that does and
	// does not guarantee.
	method := http.MethodPost
	if in.BaseSHA != "" {
		method = http.MethodPut
		body["last_commit_id"] = in.BaseSHA
	}

	path := projectPath(repo) + "/repository/files/" + url.PathEscape(strings.TrimPrefix(in.Path, "/"))
	if err := g.do(ctx, method, path, body, nil); err != nil {
		if errors.Is(err, errGitLabBadRequest) {
			// The judgment call documented above: once the request is otherwise
			// well-formed, the overwhelmingly likely cause of an unspecific 400 is
			// exactly what optimistic concurrency exists to catch — the file
			// already existing when BaseSHA=="" said "create", or the branch (and
			// so, most of the time, this file) having moved when BaseSHA!="" said
			// "update this exact version". Reported as ErrConflict rather than a
			// bare error so a caller (internal/gitops/propose.go) gets its
			// "re-read and retry" handling instead of an opaque failure. The
			// direction of the possible mistake here is the safe one: at worst an
			// unrelated 400 (a malformed branch name, an empty diff) is
			// mis-labelled as a conflict and a caller retries needlessly — this
			// can never hide a real conflict behind a false success.
			return "", fmt.Errorf("%w: %s", ErrConflict, err)
		}
		return "", err
	}

	commitSHA, err := g.ResolveRef(ctx, repo, in.Branch)
	if err != nil {
		return "", fmt.Errorf("gitlab: %s was committed to branch %q but its new commit SHA could not be resolved afterward: %w", in.Path, in.Branch, err)
	}
	return commitSHA, nil
}

// DeleteFile removes one path via GitLab's Repository Files API — the same
// endpoint family PutFile writes through, DELETE instead of POST/PUT.
//
// GitLab's delete-file endpoint accepts an OPTIONAL last_commit_id, exactly
// like its update endpoint (see PutFile's own doc comment for the full
// discussion of what that guarantee is and is not — it is checked against
// the BRANCH's last commit, not specifically this file's, so it is coarser
// than GitHub's per-blob compare-and-swap but still prevents a silent
// overwrite of a change that landed since the caller read this file).
// BaseSHA is REQUIRED here regardless of the parameter being optional on the
// wire: DeleteFileInput's own contract is that an unconditional delete is
// never allowed, the same rule github.go's DeleteFile enforces.
func (g *GitLab) DeleteFile(ctx context.Context, repo Repo, in DeleteFileInput) (string, error) {
	if in.Branch == "" || in.Path == "" {
		return "", errors.New("gitlab: DeleteFile needs a branch and a path")
	}
	if in.BaseSHA == "" {
		return "", errors.New("gitlab: DeleteFile needs the file's last known commit id — an unconditional delete could remove a file a concurrent commit just changed, the same risk an unconditional PutFile would carry")
	}

	message := messageWithTrailers(in.Message, in.Trailers)

	body := map[string]any{
		"branch":         in.Branch,
		"commit_message": message,
		"last_commit_id": in.BaseSHA,
	}
	if in.Author.Name != "" {
		body["author_name"] = in.Author.Name
	}
	if in.Author.Email != "" {
		body["author_email"] = in.Author.Email
	}

	path := projectPath(repo) + "/repository/files/" + url.PathEscape(strings.TrimPrefix(in.Path, "/"))
	if err := g.do(ctx, http.MethodDelete, path, body, nil); err != nil {
		if errors.Is(err, errGitLabBadRequest) {
			// Same judgment call PutFile documents for its own 400 handling:
			// once the request is otherwise well-formed, the overwhelmingly
			// likely cause is last_commit_id no longer matching the branch.
			return "", fmt.Errorf("%w: %s", ErrConflict, err)
		}
		return "", err
	}

	// Same missing-commit-SHA gap PutFile documents (gitlab-org/gitlab#26371):
	// the delete response carries no new commit SHA, so resolve the branch's
	// new head afterward — a second call, with the identical small race
	// PutFile's own doc comment already flags.
	commitSHA, err := g.ResolveRef(ctx, repo, in.Branch)
	if err != nil {
		return "", fmt.Errorf("gitlab: %s was deleted from branch %q but its new commit SHA could not be resolved afterward: %w", in.Path, in.Branch, err)
	}
	return commitSHA, nil
}

func (g *GitLab) OpenPullRequest(ctx context.Context, repo Repo, in PullRequestInput) (PullRequest, error) {
	if in.Head == "" || in.Base == "" {
		return PullRequest{}, errors.New("gitlab: OpenPullRequest needs both head and base branches")
	}
	body := map[string]any{
		"source_branch": in.Head,
		"target_branch": in.Base,
		"title":         in.Title,
		"description":   in.Body,
	}
	if len(in.Labels) > 0 {
		// Unlike GitHub, GitLab's create-merge-request call accepts labels
		// directly (confirmed via GitLab community documentation of accepted
		// parameter shapes, not the primary REST docs page, which is silent on
		// this parameter) — so there is no separate labelling call here, and so
		// no GitLab analogue of GitHub's "PR opened but its labels could not be
		// set" partial-failure path.
		body["labels"] = in.Labels
	}
	var out struct {
		IID    int    `json:"iid"`
		WebURL string `json:"web_url"`
	}
	if err := g.do(ctx, http.MethodPost, projectPath(repo)+"/merge_requests", body, &out); err != nil {
		return PullRequest{}, err
	}
	return PullRequest{Number: out.IID, URL: out.WebURL, Head: in.Head, Base: in.Base}, nil
}

// PullRequestStatus reads one merge request's current state.
//
// GitLab's state vocabulary (opened/closed/merged/locked) differs from
// GitHub's (open/closed plus a separate merged boolean) — Merged is derived
// here rather than carried as its own field, because GitLab's "merged" IS a
// value of state, not an orthogonal flag.
func (g *GitLab) PullRequestStatus(ctx context.Context, repo Repo, number int) (PullRequestStatus, error) {
	var out struct {
		State           string     `json:"state"`
		MergedAt        *time.Time `json:"merged_at"`
		CreatedAt       time.Time  `json:"created_at"`
		MergeCommitSHA  string     `json:"merge_commit_sha"`
		SquashCommitSHA string     `json:"squash_commit_sha"`
	}
	path := fmt.Sprintf("%s/merge_requests/%d", projectPath(repo), number)
	if err := g.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return PullRequestStatus{}, err
	}

	commitSHA := out.MergeCommitSHA
	if commitSHA == "" {
		// A squash-merged MR leaves merge_commit_sha empty and reports the
		// landed commit under squash_commit_sha instead — the two are documented
		// as mutually exclusive depending on the project's merge method. Missing
		// this would make a squash-merged PR look merged with no commit SHA at
		// all to internal/api.CheckPullRequestMerged, which needs exactly this
		// value to compare against the GitOps controller's synced revision.
		commitSHA = out.SquashCommitSHA
	}

	status := PullRequestStatus{
		Merged:         out.State == "merged",
		MergeCommitSHA: commitSHA,
		State:          out.State,
		CreatedAt:      out.CreatedAt,
	}
	if out.MergedAt != nil {
		status.MergedAt = *out.MergedAt
	}
	return status, nil
}

// IsAncestor implements Provider.IsAncestor via GitLab's compare endpoint,
// which — unlike GitHub's compare API — has no ahead/behind/diverged status
// field and no exposed merge-base SHA (confirmed against GitLab's own compare
// docs, which show the full response shape and explicitly do not include
// either). So this does not read a status; it computes the answer from commit
// reachability instead, using the endpoint's `straight` parameter:
//
// `straight=true` requests a plain two-dot comparison, i.e. GitLab documents
// it as `from..to`: the returned `commits` are exactly the commits reachable
// from `to` that are NOT reachable from `from` (docs say this array is always
// complete, even when the comparison as a whole times out on the diff side).
//
// Calling compare(from=ref, to=ancestor, straight=true) therefore returns the
// commits reachable from ancestor that ref's history does NOT already contain
// — which is empty if and only if every commit reachable from ancestor
// (ancestor included) is also reachable from ref. That is precisely the
// definition of "ancestor's commit is contained in ref's history", including
// the ref==ancestor case (compare_same_ref, and trivially an empty commit
// list either way).
//
// This is a derivation from GitLab's documented semantics of `straight`, not
// something observed against a live GitLab instance — flagged rather than
// presented as verified, per this package's convention. A different provider
// build could behave otherwise if GitLab's own documentation of `straight` is
// itself imprecise.
func (g *GitLab) IsAncestor(ctx context.Context, repo Repo, ancestor, ref string) (bool, error) {
	var out struct {
		Commits []struct {
			ID string `json:"id"`
		} `json:"commits"`
	}
	path := fmt.Sprintf("%s/repository/compare?from=%s&to=%s&straight=true",
		projectPath(repo), url.QueryEscape(ref), url.QueryEscape(ancestor))
	if err := g.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		// An unresolvable SHA 404s, which g.do turns into ErrNotFound and which
		// is propagated rather than swallowed into false — BUGS.md 81's own
		// constraint, restated in github.go's IsAncestor: "cannot tell" and
		// "checked and it's not there" must stay distinguishable.
		return false, err
	}
	return len(out.Commits) == 0, nil
}

// Verify at compile time that GitLab satisfies Provider — see github.go's
// identical assertion for why a missing method must be a build failure here,
// not a runtime surprise at the one call site that needed it.
var (
	_ Provider            = (*GitLab)(nil)
	_ UpdatableFileReader = (*GitLab)(nil)
	_ CloneCredentialer   = (*GitLab)(nil)
)

// CloneToken implements CloneCredentialer. A GitLab access token authenticates
// an HTTPS clone the same way a GitHub fine-grained PAT does — as the password
// half of basic auth, with any non-empty username accepted (GitLab's own docs
// use "oauth2" as the conventional placeholder) — so CloneCredentialer's
// stated reasoning for GitHub (file discovery may fall back to a real clone
// using this exact credential, and the credential never needs to be obtained
// any other way) applies to GitLab unchanged, not by assumption but because
// the underlying mechanism — HTTPS basic auth carrying a bearer-style token as
// the password — is the same one git itself uses regardless of host.
func (g *GitLab) CloneToken() string { return g.Token }
