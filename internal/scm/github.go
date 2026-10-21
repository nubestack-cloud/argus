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

// GitHub is a Provider over GitHub's REST API, authenticated with a
// fine-grained personal access token (REMEDIATION_ROADMAP.md D-R9).
//
// # Configurable base URL is required, not optional
//
// DESIGN.md §11.3 says exactly that, and it is the reason the self-hosted
// reachability question is answered rather than open: ARGUS runs inside the
// customer's own infrastructure, so their internal GitHub Enterprise Server is
// normally reachable — provided this is configurable from the first commit
// rather than added later as enterprise polish. BaseURL empty means github.com.
//
// # The credential
//
// A fine-grained PAT on a dedicated machine user, scoped to the named
// repositories with `contents: write` + `pull_requests: write`. Never a classic
// PAT: "everything this account can reach, forever" is an exposure that cannot
// be sized, and a risk that cannot be sized cannot be accepted, only ignored.
type GitHub struct {
	// BaseURL is the API root. Empty means "https://api.github.com". For GHES it
	// is typically "https://ghe.example.com/api/v3".
	BaseURL string
	// Token is the fine-grained PAT. Held in memory only for the lifetime of
	// this value; the caller is responsible for not retaining it longer than
	// needed (see internal/secretbox.Open's contract).
	Token string
	// HTTPClient is injectable so tests can run against a local server. A nil
	// client gets a bounded default — an unbounded one would let a hung provider
	// hold an incident's execution path open indefinitely.
	HTTPClient *http.Client
	// UserAgent is sent on every request. GitHub requires one and rejects
	// requests without it.
	UserAgent string
	// PrivateDestinations is the operator's allowlist of private destinations
	// this client may reach, resolved at dial time — the narrow opt-in that
	// makes an internal GitHub Enterprise Server on a private address usable
	// without turning off the guard for everything else. Set by
	// Store.ProviderFor, the only place a real provider is constructed. nil
	// means plain default-deny, which is what a test or a hand-built value
	// gets and is the behaviour that existed before the allowlist.
	PrivateDestinations outbound.AllowlistSource
}

func (g *GitHub) Name() string { return "github" }

func (g *GitHub) client() *http.Client {
	if g.HTTPClient != nil {
		return g.HTTPClient
	}
	// BaseURL is admin-configured (a self-hosted GHES root, for the same
	// reason described on the BaseURL field above) and is exactly the class
	// of admin-supplied URL lld/01-threat-model.md T15/SR-9 is about: refuse
	// metadata/loopback/link-local/private destinations by default, and
	// re-validate the resolved address at connect time and on every
	// redirect rather than trusting a hostname match alone.
	//
	// Default-deny stays, and the open question this comment used to record
	// — a self-hosted GHES root on a private address is a real, plausible
	// deployment, which lld/01-threat-model.md's B7 row already treats as
	// intended reachability — was decided by the owner on 2026-09-19: keep
	// default-deny, and let an operator NAME the specific private
	// destinations they trust. So there is still no AllowPrivate carve-out
	// here, and there must never be one: what is passed instead is
	// PrivateDestinations, which can only permit the addresses an operator
	// listed with a written reason, can never reach a cloud metadata
	// address, and is matched against the RESOLVED address at dial time, so
	// the rebinding defence above is unaffected. See internal/outbound/
	// allowlist.go and migration 000115.
	return outbound.NewClient(outbound.Policy{PrivateDestinations: g.PrivateDestinations}, 30*time.Second)
}

func (g *GitHub) base() string {
	if g.BaseURL == "" {
		return "https://api.github.com"
	}
	return strings.TrimSuffix(g.BaseURL, "/")
}

func (g *GitHub) userAgent() string {
	if g.UserAgent == "" {
		return "argus"
	}
	return g.UserAgent
}

// do performs one API call and maps the status code onto this package's
// sentinels.
//
// The mapping is where most of the value is: a caller deciding whether to search
// another path, ask a human to renew a token, or abort needs those to be
// distinguishable, and an HTTP status alone does not distinguish them. In
// particular 401 vs 403 is split into "expired/revoked" vs "forbidden", because
// a fine-grained PAT expiring is the failure this integration will actually hit
// over time and it has a different fix (renew, not widen).
func (g *GitHub) do(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("github: marshal request: %w", err)
		}
		reader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, g.base()+path, reader)
	if err != nil {
		return fmt.Errorf("github: build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", g.userAgent())
	if g.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.Token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := g.client().Do(req)
	if err != nil {
		// Deliberately does not wrap the URL: it is safe here, but this is the
		// one path where a future change could start echoing a token-bearing
		// value, and §18.6 requires credentials be redacted in every error path.
		return fmt.Errorf("github: %s request failed: %w", method, err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return ErrNotFound
	case resp.StatusCode == http.StatusUnauthorized:
		return fmt.Errorf("%w: GitHub rejected the credential (401). A fine-grained token expires; renew it rather than widening its scope", ErrCredentialExpired)
	case resp.StatusCode == http.StatusForbidden:
		// 403 with a rate-limit marker is not an authorization problem, and
		// telling an operator to check their token scopes when they are actually
		// rate-limited sends them to the wrong place entirely.
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return fmt.Errorf("%w: GitHub rate limit exhausted (resets at %s) — not a permissions problem", ErrForbidden, resp.Header.Get("X-RateLimit-Reset"))
		}
		return fmt.Errorf("%w: GitHub refused this operation (403). Check that the token's repository selection includes this repo and that it grants contents:write and pull_requests:write. GitHub said: %s", ErrForbidden, githubMessage(payload))
	case resp.StatusCode == http.StatusConflict:
		return fmt.Errorf("%w: %s", ErrConflict, githubMessage(payload))
	case resp.StatusCode == http.StatusUnprocessableEntity:
		// 422 covers "branch already exists", a non-fast-forward ref update,
		// and genuine validation failures — only the message distinguishes
		// them.
		msg := githubMessage(payload)
		lower := strings.ToLower(msg)
		switch {
		case strings.Contains(lower, "already exists"):
			return fmt.Errorf("%w: %s", ErrAlreadyExists, msg)
		case strings.Contains(lower, "not a fast forward") || strings.Contains(lower, "not a fast-forward") || strings.Contains(lower, "update is not a simple fast-forward"):
			// PutFiles' ref update (git/refs/heads/{branch}, force:false) is
			// GitHub's real fast-forward-only compare-and-swap: this is what a
			// concurrent push to the branch looks like, and it must map to the
			// same sentinel PutFile's blob-SHA 409 does, so callers do not need
			// to know which write path produced it.
			return fmt.Errorf("%w: %s", ErrConflict, msg)
		}
		return fmt.Errorf("github: rejected (422): %s", msg)
	case resp.StatusCode >= 300:
		return fmt.Errorf("github: unexpected status %d: %s", resp.StatusCode, githubMessage(payload))
	}

	if out != nil && len(payload) > 0 {
		if err := json.Unmarshal(payload, out); err != nil {
			return fmt.Errorf("github: decode response: %w", err)
		}
	}
	return nil
}

// githubMessage pulls the human-readable message out of an error body, falling
// back to the raw body. Bounded, because a provider's message length is not
// ARGUS's to control and this text ends up in an API response an operator reads.
func githubMessage(payload []byte) string {
	var e struct {
		Message string `json:"message"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	msg := ""
	if json.Unmarshal(payload, &e) == nil && e.Message != "" {
		msg = e.Message
		if len(e.Errors) > 0 && e.Errors[0].Message != "" {
			msg += ": " + e.Errors[0].Message
		}
	} else {
		msg = string(payload)
	}
	return truncateMessage(msg)
}

func repoPath(r Repo) string {
	return fmt.Sprintf("/repos/%s/%s", url.PathEscape(r.Owner), url.PathEscape(r.Name))
}

func (g *GitHub) DefaultBranch(ctx context.Context, repo Repo) (string, error) {
	var out struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := g.do(ctx, http.MethodGet, repoPath(repo), nil, &out); err != nil {
		return "", err
	}
	if out.DefaultBranch == "" {
		// Rarer here than on gitlab.go's sibling method (GitHub sets this on
		// every non-empty repo), but the same escape hatch applies when it
		// does happen: every real caller that opens a pull request
		// (baseBranchFor, matchObjectMapping) already prefers a stored
		// branch over calling this method at all.
		return "", fmt.Errorf("github: %s reported no default branch — set this repository's Default branch field in ARGUS instead of relying on auto-detection", repo)
	}
	return out.DefaultBranch, nil
}

func (g *GitHub) ResolveRef(ctx context.Context, repo Repo, ref string) (string, error) {
	// The commits endpoint accepts a branch, tag or SHA and returns the commit,
	// which saves guessing which kind of ref the caller was given.
	var out struct {
		SHA string `json:"sha"`
	}
	path := repoPath(repo) + "/commits/" + url.PathEscape(ref)
	if err := g.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return "", err
	}
	if out.SHA == "" {
		return "", fmt.Errorf("github: %s@%s resolved to no commit", repo, ref)
	}
	return out.SHA, nil
}

// fileMeta is the Contents API's per-file shape. `SHA` here is the BLOB sha,
// which is what PutFile's compare-and-swap needs — not the commit sha. Mixing
// the two produces a 409 that reads like a race when it is actually a bug.
type fileMeta struct {
	SHA      string `json:"sha"`
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
	Type     string `json:"type"`
}

func (g *GitHub) contentsPath(repo Repo, path, ref string) string {
	// Path segments are escaped individually: url.PathEscape would turn the
	// separating slashes into %2F and the API would 404 on a path that exists.
	segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	p := repoPath(repo) + "/contents/" + strings.Join(segs, "/")
	if ref != "" {
		p += "?ref=" + url.QueryEscape(ref)
	}
	return p
}

func (g *GitHub) ReadFile(ctx context.Context, repo Repo, ref, path string) ([]byte, error) {
	content, _, err := g.readFileWithSHA(ctx, repo, ref, path)
	return content, err
}

// readFileWithSHA also returns the blob SHA, which PutFile needs. Unexported
// because the Provider interface deliberately keeps the SHA opaque — a caller
// that wants compare-and-swap goes through ReadFileForUpdate.
func (g *GitHub) readFileWithSHA(ctx context.Context, repo Repo, ref, path string) ([]byte, string, error) {
	var meta fileMeta
	if err := g.do(ctx, http.MethodGet, g.contentsPath(repo, path, ref), nil, &meta); err != nil {
		return nil, "", err
	}
	if meta.Type == "dir" {
		return nil, "", fmt.Errorf("%w: %s is a directory, not a file", ErrNotFound, path)
	}
	if meta.Encoding != "base64" {
		// A file over ~1MB comes back with empty content and encoding "none",
		// which would otherwise decode to an empty manifest and produce a PR
		// that deletes everything in it. Refused loudly instead.
		return nil, "", fmt.Errorf("github: %s came back with encoding %q rather than base64 — files over about 1MB need the blob API, which this build does not use", path, meta.Encoding)
	}
	// GitHub wraps base64 at 60 columns, which strict decoders reject.
	raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(meta.Content, "\n", ""))
	if err != nil {
		return nil, "", fmt.Errorf("github: decode %s: %w", path, err)
	}
	return raw, meta.SHA, nil
}

// ReadFileForUpdate returns a file plus the blob SHA to pass back as
// PutFileInput.BaseSHA — the read half of the compare-and-swap.
func (g *GitHub) ReadFileForUpdate(ctx context.Context, repo Repo, ref, path string) (content []byte, blobSHA string, err error) {
	return g.readFileWithSHA(ctx, repo, ref, path)
}

func (g *GitHub) CreateBranch(ctx context.Context, repo Repo, branch, fromSHA string) error {
	if fromSHA == "" {
		return errors.New("github: CreateBranch needs a commit SHA to branch from — resolve the ref first, so the branch point is recorded rather than implied")
	}
	body := map[string]string{"ref": "refs/heads/" + branch, "sha": fromSHA}
	return g.do(ctx, http.MethodPost, repoPath(repo)+"/git/refs", body, nil)
}

func (g *GitHub) PutFile(ctx context.Context, repo Repo, in PutFileInput) (string, error) {
	if in.Branch == "" || in.Path == "" {
		return "", errors.New("github: PutFile needs a branch and a path")
	}
	if len(in.Content) == 0 {
		return "", errors.New("github: refusing to commit empty content — an empty manifest is almost never the intended change, and this is the shape a decode failure upstream would take")
	}

	message := messageWithTrailers(in.Message, in.Trailers)

	body := map[string]any{
		"message": message,
		"content": base64.StdEncoding.EncodeToString(in.Content),
		"branch":  in.Branch,
	}
	if in.BaseSHA != "" {
		// Absent means "create". Present means "replace exactly this blob" —
		// GitHub 409s if the file moved, which is the compare-and-swap.
		body["sha"] = in.BaseSHA
	}
	if in.Author.Name != "" && in.Author.Email != "" {
		body["committer"] = map[string]string{"name": in.Author.Name, "email": in.Author.Email}
	}

	var out struct {
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	if err := g.do(ctx, http.MethodPut, g.contentsPath(repo, in.Path, ""), body, &out); err != nil {
		return "", err
	}
	return out.Commit.SHA, nil
}

// DeleteFile removes one path via GitHub's Contents API — the same endpoint
// PutFile writes through, DELETE instead of PUT. BaseSHA is REQUIRED (see
// DeleteFileInput's doc comment) and is GitHub's own compare-and-swap
// precondition for a delete exactly as it is for a write: the API 409s if
// the blob at this path no longer matches, which do() already maps to
// ErrConflict.
func (g *GitHub) DeleteFile(ctx context.Context, repo Repo, in DeleteFileInput) (string, error) {
	if in.Branch == "" || in.Path == "" {
		return "", errors.New("github: DeleteFile needs a branch and a path")
	}
	if in.BaseSHA == "" {
		return "", errors.New("github: DeleteFile needs the file's current blob SHA — an unconditional delete could remove a file a concurrent commit just changed, the same risk an unconditional PutFile would carry")
	}

	message := messageWithTrailers(in.Message, in.Trailers)

	body := map[string]any{
		"message": message,
		"sha":     in.BaseSHA,
		"branch":  in.Branch,
	}
	if in.Author.Name != "" && in.Author.Email != "" {
		body["committer"] = map[string]string{"name": in.Author.Name, "email": in.Author.Email}
	}

	var out struct {
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	// The Contents API's DELETE takes its body the same way GitHub's docs
	// specify for every other JSON-bodied verb here — g.do already marshals
	// whatever is passed regardless of method.
	if err := g.do(ctx, http.MethodDelete, g.contentsPath(repo, in.Path, ""), body, &out); err != nil {
		return "", err
	}
	return out.Commit.SHA, nil
}

// gitTreeEntry is one entry in a git tree, per GitHub's git/trees API. Only
// the fields PutFiles needs to send are here — GitHub's own response shape
// carries more, decoded separately where read back.
//
// SHA is a pointer, not a bare string, specifically so a DELETE entry can
// marshal as a literal JSON `null` rather than an omitted key — GitHub's own
// documented meaning of "sha: null" on a tree entry is "delete this path",
// which is different from the key being absent at all (absent, under
// base_tree, means "inherit unchanged"). omitempty is deliberately NOT on
// this field: an omitted key and an explicit null must stay distinguishable
// in the JSON this sends.
type gitTreeEntry struct {
	Path string  `json:"path"`
	Mode string  `json:"mode"`
	Type string  `json:"type"`
	SHA  *string `json:"sha"`
}

// refPath builds the git-refs path for a branch, escaping each slash-
// separated segment individually — same reasoning as contentsPath: a branch
// name commonly has segments (e.g. "argus/fix-inc123"), and url.PathEscape
// on the whole string would turn the separating slash into %2F and 404.
func (g *GitHub) refPath(repo Repo, branch string) string {
	segs := strings.Split(branch, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return repoPath(repo) + "/git/refs/heads/" + strings.Join(segs, "/")
}

// PutFiles implements scm.AtomicCommitter via GitHub's git-data API: create a
// blob per WRITTEN file (a DELETED one, FileCommit.Delete, gets a tree entry
// with a null sha instead — no blob to create, see gitTreeEntry's doc
// comment), one tree that inherits everything else from the branch's
// CURRENT tree (base_tree) and overrides only the changed paths, one commit
// pointing at that tree with the branch's current commit as its sole parent,
// then one ref update. A batch mixing a delete and a write to DIFFERENT
// paths lands in this same one atomic commit — the tree API does not care
// which entries are which, and step 3's compare-and-swap runs identically
// for both. That update is the ONLY step that touches the branch,
// and it is a fast-forward-only compare-and-swap against in.BaseCommitSHA —
// see do()'s 422 handling — so a concurrent push is caught atomically with
// nothing partially landed: every blob/tree/commit object created before a
// failing ref update is a git object nothing else references, exactly like
// the local commits behind a rejected `git push`.
//
// Before any of that, every file's CURRENT blob at its path (read fresh from
// the branch's own tree, not assumed from the caller's bookkeeping) is
// checked against FileCommit.BaseSHA — the compare-and-swap PutFile gets for
// free from the Contents API's own SHA parameter, reimplemented by hand here
// because the trees API has no per-entry precondition of its own. A mismatch
// aborts before a single object is created, so a stale read is refused as a
// conflict rather than silently overwritten by the tree's base_tree
// inheritance.
func (g *GitHub) PutFiles(ctx context.Context, repo Repo, in PutFilesInput) (string, error) {
	if in.Branch == "" {
		return "", errors.New("github: PutFiles needs a branch")
	}
	if in.BaseCommitSHA == "" {
		return "", errors.New("github: PutFiles needs the branch's current commit SHA — without it the ref update could not be a compare-and-swap")
	}
	if len(in.Files) == 0 {
		return "", errors.New("github: PutFiles needs at least one file")
	}
	seen := make(map[string]bool, len(in.Files))
	for _, f := range in.Files {
		if f.Path == "" {
			return "", errors.New("github: every file in PutFiles needs a path")
		}
		if seen[f.Path] {
			return "", fmt.Errorf("github: %s appears twice in one PutFiles call", f.Path)
		}
		seen[f.Path] = true
		if f.Delete {
			if f.BaseSHA == "" {
				return "", fmt.Errorf("github: %s is marked for deletion but carries no blob SHA — a delete needs to know what it is removing, the same compare-and-swap precondition every write here already requires", f.Path)
			}
			continue
		}
		if len(f.Content) == 0 {
			return "", fmt.Errorf("github: refusing to commit empty content for %s — an empty manifest is almost never the intended change, and this is the shape a decode failure upstream would take", f.Path)
		}
	}

	// Step 1: the branch's current tree.
	var commitOut struct {
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	if err := g.do(ctx, http.MethodGet, repoPath(repo)+"/git/commits/"+url.PathEscape(in.BaseCommitSHA), nil, &commitOut); err != nil {
		return "", fmt.Errorf("github: could not read base commit %s: %w", in.BaseCommitSHA, err)
	}
	baseTreeSHA := commitOut.Tree.SHA
	if baseTreeSHA == "" {
		return "", fmt.Errorf("github: commit %s reported no tree", in.BaseCommitSHA)
	}

	// Step 2: every path's CURRENT blob SHA on that tree — read fresh, right
	// now, which is what the compare-and-swap below checks against.
	var treeOut struct {
		Tree []struct {
			Path string `json:"path"`
			SHA  string `json:"sha"`
			Type string `json:"type"`
		} `json:"tree"`
		Truncated bool `json:"truncated"`
	}
	treePath := repoPath(repo) + "/git/trees/" + url.PathEscape(baseTreeSHA) + "?recursive=1"
	if err := g.do(ctx, http.MethodGet, treePath, nil, &treeOut); err != nil {
		return "", fmt.Errorf("github: could not read the branch's current tree: %w", err)
	}
	if treeOut.Truncated {
		// GitHub truncates a recursive listing over its own size cap. A
		// truncated listing cannot be trusted to include every path this
		// commit touches, and proceeding anyway could mistake "not in the
		// truncated page" for "unchanged" — refused rather than risk missing
		// a real conflict.
		return "", errors.New("github: this repository's tree is too large to list in one call, so the atomic multi-file path cannot verify every path's current blob — refusing rather than risk missing a conflict")
	}
	current := make(map[string]string, len(treeOut.Tree))
	for _, e := range treeOut.Tree {
		if e.Type == "blob" {
			current[e.Path] = e.SHA
		}
	}

	// Step 3: the compare-and-swap, per file, before anything is written.
	for _, f := range in.Files {
		got := current[f.Path]
		switch {
		case got == f.BaseSHA:
			// matches — proceed
		case f.BaseSHA == "":
			return "", fmt.Errorf("%w: %s: this file was expected to be created, but it already exists on the branch (blob %s)", ErrConflict, f.Path, got)
		case got == "":
			return "", fmt.Errorf("%w: %s: expected blob %s, but the file no longer exists on the branch", ErrConflict, f.Path, f.BaseSHA)
		default:
			return "", fmt.Errorf("%w: %s: expected blob %s, the branch currently has %s", ErrConflict, f.Path, f.BaseSHA, got)
		}
	}

	// Step 4: one blob per file being WRITTEN — a file being DELETED needs no
	// blob at all, only a tree entry naming it with a null sha (see
	// gitTreeEntry's own doc comment for why that field is a pointer).
	// Explicit blob creation for the rest (rather than the tree API's own
	// inline "content" shortcut) keeps this binary-safe the same way PutFile
	// already is — base64 in, no assumption that the content is valid UTF-8
	// text.
	entries := make([]gitTreeEntry, 0, len(in.Files))
	for _, f := range in.Files {
		if f.Delete {
			entries = append(entries, gitTreeEntry{Path: f.Path, Mode: "100644", Type: "blob", SHA: nil})
			continue
		}
		var blobOut struct {
			SHA string `json:"sha"`
		}
		blobBody := map[string]string{
			"content":  base64.StdEncoding.EncodeToString(f.Content),
			"encoding": "base64",
		}
		if err := g.do(ctx, http.MethodPost, repoPath(repo)+"/git/blobs", blobBody, &blobOut); err != nil {
			return "", fmt.Errorf("github: could not create a blob for %s: %w", f.Path, err)
		}
		if blobOut.SHA == "" {
			return "", fmt.Errorf("github: blob creation for %s reported no SHA", f.Path)
		}
		entries = append(entries, gitTreeEntry{Path: f.Path, Mode: "100644", Type: "blob", SHA: &blobOut.SHA})
	}

	// Step 5: one tree. base_tree means every path NOT listed here is
	// inherited unchanged from the branch's current tree — this is what
	// makes N files one call instead of ARGUS walking and re-listing the
	// whole tree by hand.
	var treeResult struct {
		SHA string `json:"sha"`
	}
	treeBody := map[string]any{"base_tree": baseTreeSHA, "tree": entries}
	if err := g.do(ctx, http.MethodPost, repoPath(repo)+"/git/trees", treeBody, &treeResult); err != nil {
		return "", fmt.Errorf("github: could not create the tree: %w", err)
	}

	// Step 6: one commit, parented on the branch's current head.
	message := messageWithTrailers(in.Message, in.Trailers)
	commitBody := map[string]any{
		"message": message,
		"tree":    treeResult.SHA,
		"parents": []string{in.BaseCommitSHA},
	}
	if in.Author.Name != "" && in.Author.Email != "" {
		commitBody["committer"] = map[string]string{"name": in.Author.Name, "email": in.Author.Email}
		commitBody["author"] = map[string]string{"name": in.Author.Name, "email": in.Author.Email}
	}
	var newCommit struct {
		SHA string `json:"sha"`
	}
	if err := g.do(ctx, http.MethodPost, repoPath(repo)+"/git/commits", commitBody, &newCommit); err != nil {
		return "", fmt.Errorf("github: could not create the commit: %w", err)
	}
	if newCommit.SHA == "" {
		return "", errors.New("github: commit creation reported no SHA")
	}

	// Step 7: the one write that touches the branch. force:false makes this
	// fast-forward-only: it succeeds only if newCommit is a descendant of the
	// branch's CURRENT head, which holds trivially when the branch is still
	// at in.BaseCommitSHA (our commit's sole parent) and fails otherwise —
	// the atomic compare-and-swap. Everything above this line created
	// objects nothing else can see yet, so a failure here leaves nothing
	// landed on the branch: not some of the files, not a half-applied tree.
	refBody := map[string]any{"sha": newCommit.SHA, "force": false}
	if err := g.do(ctx, http.MethodPatch, g.refPath(repo, in.Branch), refBody, nil); err != nil {
		if errors.Is(err, ErrConflict) {
			return "", fmt.Errorf("github: branch %q moved since it was read — the atomic commit was built but could not be applied, and nothing landed on the branch: %w", in.Branch, err)
		}
		return "", fmt.Errorf("github: could not update branch %q to the new commit: %w", in.Branch, err)
	}
	return newCommit.SHA, nil
}

func (g *GitHub) OpenPullRequest(ctx context.Context, repo Repo, in PullRequestInput) (PullRequest, error) {
	if in.Head == "" || in.Base == "" {
		return PullRequest{}, errors.New("github: OpenPullRequest needs both head and base branches")
	}
	body := map[string]any{"title": in.Title, "body": in.Body, "head": in.Head, "base": in.Base}
	var out struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
	}
	if err := g.do(ctx, http.MethodPost, repoPath(repo)+"/pulls", body, &out); err != nil {
		return PullRequest{}, err
	}
	pr := PullRequest{Number: out.Number, URL: out.HTMLURL, Head: in.Head, Base: in.Base}

	// Labels are a separate call, and a failure here must NOT fail the PR: the
	// change is already proposed and open, and losing a label is cosmetic where
	// reporting failure would send someone looking for a PR that exists.
	if len(in.Labels) > 0 && pr.Number != 0 {
		path := fmt.Sprintf("%s/issues/%d/labels", repoPath(repo), pr.Number)
		if err := g.do(ctx, http.MethodPost, path, map[string]any{"labels": in.Labels}, nil); err != nil {
			return pr, fmt.Errorf("github: pull request #%d was opened at %s but its labels could not be set: %w", pr.Number, pr.URL, err)
		}
	}
	return pr, nil
}

// PullRequestStatus reads one PR's current state. GitHub's single GET
// response already carries everything needed — merged, merged_at,
// merge_commit_sha, state, created_at — so this is one call, not the two
// (list + events) some other hosts would need.
func (g *GitHub) PullRequestStatus(ctx context.Context, repo Repo, number int) (PullRequestStatus, error) {
	var out struct {
		State          string     `json:"state"`
		Merged         bool       `json:"merged"`
		MergedAt       *time.Time `json:"merged_at"`
		CreatedAt      time.Time  `json:"created_at"`
		MergeCommitSHA string     `json:"merge_commit_sha"`
	}
	path := fmt.Sprintf("%s/pulls/%d", repoPath(repo), number)
	if err := g.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return PullRequestStatus{}, err
	}
	status := PullRequestStatus{Merged: out.Merged, MergeCommitSHA: out.MergeCommitSHA, State: out.State, CreatedAt: out.CreatedAt}
	if out.MergedAt != nil {
		status.MergedAt = *out.MergedAt
	}
	return status, nil
}

// IsAncestor implements Provider.IsAncestor via GitHub's compare API, which
// already answers exactly this question: comparing base...head, "ahead"
// means head has every commit base has plus more (base is an ancestor of
// head), "identical" means they are the same commit, and "behind"/"diverged"
// both mean base is NOT contained in head's history.
//
// A comparison against an unknown SHA (a force-push that dropped it, a
// shallow/expired ref) 404s, which g.do turns into ErrNotFound — propagated
// as an error, not swallowed into false, because "cannot tell" and "checked
// and it's not there" are different facts to the caller (BUGS.md 81's own
// constraint: an unreachable/confused provider must never be read as a
// verdict).
func (g *GitHub) IsAncestor(ctx context.Context, repo Repo, ancestor, ref string) (bool, error) {
	var out struct {
		Status string `json:"status"`
	}
	path := repoPath(repo) + "/compare/" + url.PathEscape(ancestor) + "..." + url.PathEscape(ref)
	if err := g.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return false, err
	}
	switch out.Status {
	case "identical", "ahead":
		return true, nil
	case "behind", "diverged":
		return false, nil
	default:
		return false, fmt.Errorf("github: compare %s...%s returned unrecognized status %q", ancestor, ref, out.Status)
	}
}

// Verify at compile time that GitHub satisfies Provider — a missing method
// should be a build failure here, not at the one call site that uses it. The
// second assertion matters more than it looks: the PR path type-asserts for
// UpdatableFileReader and refuses to commit without it, so losing that method
// would degrade to a runtime refusal rather than a build failure. The third
// is the same reasoning for F24's atomic path: gitops.ProposeChanges
// type-asserts for AtomicCommitter, so losing this method would silently
// fall back to the sequential path rather than fail to build.
var (
	_ Provider            = (*GitHub)(nil)
	_ UpdatableFileReader = (*GitHub)(nil)
	_ AtomicCommitter     = (*GitHub)(nil)
)

// CloneToken implements CloneCredentialer. See that interface for why this is the
// one place a credential is handed out rather than used in place.
func (g *GitHub) CloneToken() string { return g.Token }
