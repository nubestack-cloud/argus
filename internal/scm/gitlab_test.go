package scm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeGitLab is a scripted API — deliberately not a full GitLab, the same
// posture fakeGitHub takes in github_test.go: it asserts the requests ARGUS
// makes and returns the shapes GitLab documents.
type fakeGitLab struct {
	t        *testing.T
	requests []string // "METHOD /path", in order
	handler  func(w http.ResponseWriter, r *http.Request)
}

func (f *fakeGitLab) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.requests = append(f.requests, r.Method+" "+r.URL.EscapedPath()+"?"+r.URL.RawQuery)
	// PRIVATE-TOKEN, not Authorization — this is the one asymmetry with GitHub
	// that is easy to get wrong silently (a bad header still compiles, still
	// sends a request, and just always 401s), so it is asserted on every call
	// rather than in one dedicated test.
	if got := r.Header.Get("PRIVATE-TOKEN"); got != "test-token" {
		f.t.Errorf("%s %s: PRIVATE-TOKEN = %q", r.Method, r.URL.EscapedPath(), got)
	}
	if got := r.Header.Get("Authorization"); got != "" {
		f.t.Errorf("%s %s: Authorization header was set to %q — GitLab must never see a bearer token, only PRIVATE-TOKEN", r.Method, r.URL.EscapedPath(), got)
	}
	f.handler(w, r)
}

func newFakeGitLab(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) (*GitLab, *fakeGitLab) {
	t.Helper()
	f := &fakeGitLab{t: t, handler: h}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return &GitLab{BaseURL: srv.URL, Token: "test-token", HTTPClient: srv.Client()}, f
}

// The whole chain a remediation PR needs: resolve, read, branch, commit, open.
// Mirrors github_test.go's TestFullPullRequestChain so the two providers are
// held to the same bar.
func TestGitLabFullPullRequestChain(t *testing.T) {
	repo := Repo{Owner: "acme-group/platform", Name: "config"}
	const lastCommitID = "commit111"
	var committed map[string]any

	// The project path segment is "acme-group/platform/config" with its OWN
	// internal slashes percent-encoded, i.e. "acme-group%2Fplatform%2Fconfig" —
	// this is the one thing this test pins down that github_test.go has no
	// equivalent for, because GitHub never encodes a slash into a path segment.
	const encodedProject = "acme-group%2Fplatform%2Fconfig"

	gl, fake := newFakeGitLab(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.EscapedPath() == "/projects/"+encodedProject:
			jsonResp(w, 200, map[string]any{"default_branch": "trunk"})
		// Matched on the exact ref, not a prefix: ResolveRef is called TWICE in
		// this chain (once for the base branch, once for the fix branch after
		// PutFile), and a prefix match would let the first response shadow the
		// second, silently hiding a real bug where PutFile's returned commit SHA
		// never advances past the base branch's.
		case r.Method == "GET" && r.URL.EscapedPath() == "/projects/"+encodedProject+"/repository/commits/trunk":
			jsonResp(w, 200, map[string]any{"id": "commitAAA"})
		case r.Method == "GET" && r.URL.EscapedPath() == "/projects/"+encodedProject+"/repository/files/envs%2Fprod%2Fvalues.yaml":
			if got := r.URL.Query().Get("ref"); got != "commitAAA" {
				t.Errorf("read was not pinned to the resolved commit: ref=%q", got)
			}
			jsonResp(w, 200, map[string]any{
				"encoding": "base64", "last_commit_id": lastCommitID, "blob_id": "blob999",
				"content": base64.StdEncoding.EncodeToString([]byte("replicas: 2\nmemory: 256Mi\n")),
			})
		case r.Method == "POST" && r.URL.EscapedPath() == "/projects/"+encodedProject+"/repository/branches":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["branch"] != "argus/fix-inc123" {
				t.Errorf("branch = %q", body["branch"])
			}
			if body["ref"] != "commitAAA" {
				t.Errorf("branch point = %q, want the resolved commit", body["ref"])
			}
			jsonResp(w, 201, map[string]any{"name": "argus/fix-inc123"})
		case r.Method == "PUT" && r.URL.EscapedPath() == "/projects/"+encodedProject+"/repository/files/envs%2Fprod%2Fvalues.yaml":
			_ = json.NewDecoder(r.Body).Decode(&committed)
			jsonResp(w, 200, map[string]any{"file_path": "envs/prod/values.yaml", "branch": "argus/fix-inc123"})
		case r.Method == "GET" && r.URL.EscapedPath() == "/projects/"+encodedProject+"/repository/commits/argus%2Ffix-inc123":
			// PutFile's post-commit ResolveRef, to recover the commit SHA GitLab's
			// write endpoint itself never returns.
			jsonResp(w, 200, map[string]any{"id": "commitBBB"})
		case r.Method == "POST" && r.URL.EscapedPath() == "/projects/"+encodedProject+"/merge_requests":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["source_branch"] != "argus/fix-inc123" {
				t.Errorf("source_branch = %v", body["source_branch"])
			}
			jsonResp(w, 201, map[string]any{"iid": 42, "web_url": "https://gitlab.example/mr/42"})
		default:
			t.Errorf("unexpected call: %s %s", r.Method, r.URL.EscapedPath())
			w.WriteHeader(500)
		}
	})
	ctx := context.Background()

	base, err := gl.DefaultBranch(ctx, repo)
	if err != nil || base != "trunk" {
		t.Fatalf("DefaultBranch = %q, %v", base, err)
	}
	sha, err := gl.ResolveRef(ctx, repo, base)
	if err != nil || sha != "commitAAA" {
		t.Fatalf("ResolveRef = %q, %v", sha, err)
	}
	content, lastCommit, err := gl.ReadFileForUpdate(ctx, repo, sha, "envs/prod/values.yaml")
	if err != nil {
		t.Fatalf("ReadFileForUpdate: %v", err)
	}
	if !strings.Contains(string(content), "replicas: 2") {
		t.Errorf("decoded content = %q", content)
	}
	if lastCommit != lastCommitID {
		t.Errorf("compare-and-swap token = %q, want the last_commit_id %q (NOT blob_id — GitLab's write endpoint has no blob-SHA precondition)", lastCommit, lastCommitID)
	}
	if err := gl.CreateBranch(ctx, repo, "argus/fix-inc123", sha); err != nil {
		t.Fatalf("CreateBranch: %v", err)
	}
	commit, err := gl.PutFile(ctx, repo, PutFileInput{
		Branch: "argus/fix-inc123", Path: "envs/prod/values.yaml",
		Content: []byte("replicas: 2\nmemory: 512Mi\n"),
		Message: "Raise checkout-worker memory limit to 512Mi",
		BaseSHA: lastCommit,
		Author:  Identity{Name: "argus", Email: "argus@acme.example"},
		Trailers: []string{
			"Requested-by: alice@acme.example",
			"Argus-Incident: inc123",
		},
	})
	if err != nil || commit != "commitBBB" {
		t.Fatalf("PutFile = %q, %v — the commit SHA must come from the post-write ResolveRef, since GitLab's write response carries none", commit, err)
	}

	if committed["last_commit_id"] != lastCommitID {
		t.Errorf("commit did not send last_commit_id as the compare-and-swap token: %v", committed["last_commit_id"])
	}
	if committed["encoding"] != "base64" {
		t.Errorf("commit did not declare encoding=base64 — GitLab treats \"content\" as plain text by default, so omitting this would store the base64 STRING as the file's literal content: %v", committed["encoding"])
	}
	msg, _ := committed["commit_message"].(string)
	if !strings.Contains(msg, "Requested-by: alice@acme.example") {
		t.Errorf("commit message lost its trailers:\n%s", msg)
	}
	raw, err := base64.StdEncoding.DecodeString(committed["content"].(string))
	if err != nil || !strings.Contains(string(raw), "512Mi") {
		t.Errorf("committed content = %q (%v)", raw, err)
	}

	pr, err := gl.OpenPullRequest(ctx, repo, PullRequestInput{
		Title: "Raise memory limit", Body: "b", Head: "argus/fix-inc123", Base: base,
		Labels: []string{"argus/verified-locally"},
	})
	if err != nil {
		t.Fatalf("OpenPullRequest: %v", err)
	}
	if pr.Number != 42 || pr.URL == "" {
		t.Errorf("PR = %+v", pr)
	}
	if len(fake.requests) != 7 {
		t.Errorf("expected 7 calls in the chain, got %d: %v", len(fake.requests), fake.requests)
	}
}

// A 401 and a 403 have different fixes, same as GitHub — mirrors
// TestCredentialFailuresAreDistinguishable.
func TestGitLabCredentialFailuresAreDistinguishable(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		want    error
		wantMsg string
	}{
		{"expired token", 401, ErrCredentialExpired, "renew"},
		{"insufficient scope", 403, ErrForbidden, "scope"},
		{"rate limited", 429, ErrForbidden, "rate limit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gl, _ := newFakeGitLab(t, func(w http.ResponseWriter, r *http.Request) {
				jsonResp(w, tc.status, map[string]any{"message": "403 Forbidden"})
			})
			_, err := gl.DefaultBranch(context.Background(), Repo{Owner: "a", Name: "b"})
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.wantMsg) {
				t.Errorf("message does not tell the operator what to do (%q): %v", tc.wantMsg, err)
			}
		})
	}
}

// GitLab's own docs for the repository-files write endpoints call a failed
// commit's 400 body "a non-specific error message" — so, unlike GitHub's 422,
// only the ONE case (already exists) is meant to be distinguishable by text;
// everything else 400s into a conflict via PutFile's documented judgment call.
func TestGitLabNotFoundAlreadyExistsAndAmbiguousBadRequest(t *testing.T) {
	t.Run("branch already exists reads as ErrAlreadyExists", func(t *testing.T) {
		gl, _ := newFakeGitLab(t, func(w http.ResponseWriter, r *http.Request) {
			jsonResp(w, 400, map[string]any{"message": "Branch already exists"})
		})
		err := gl.CreateBranch(context.Background(), Repo{Owner: "a", Name: "b"}, "br", "sha")
		if !errors.Is(err, ErrAlreadyExists) {
			t.Errorf("CreateBranch on a duplicate branch = %v, want ErrAlreadyExists", err)
		}
	})

	t.Run("not found reads as ErrNotFound", func(t *testing.T) {
		gl, _ := newFakeGitLab(t, func(w http.ResponseWriter, r *http.Request) {
			jsonResp(w, 404, map[string]any{"message": "404 Project Not Found"})
		})
		_, err := gl.DefaultBranch(context.Background(), Repo{Owner: "a", Name: "b"})
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("DefaultBranch on an unknown project = %v, want ErrNotFound", err)
		}
	})

	t.Run("a non-specific 400 commit failure reads as ErrConflict via PutFile", func(t *testing.T) {
		gl, _ := newFakeGitLab(t, func(w http.ResponseWriter, r *http.Request) {
			// No "already exists" text — this is the case GitLab's own docs
			// describe as carrying no specific reason.
			jsonResp(w, 400, map[string]any{"message": "400 Bad request - You are not allowed to push into this branch"})
		})
		_, err := gl.PutFile(context.Background(), Repo{Owner: "a", Name: "b"}, PutFileInput{
			Branch: "br", Path: "p.yaml", Content: []byte("x: 1\n"), BaseSHA: "commit123",
		})
		if !errors.Is(err, ErrConflict) {
			t.Errorf("PutFile on a non-specific 400 = %v, want ErrConflict (PutFile's own documented judgment call)", err)
		}
	})

	t.Run("a merge-request duplicate reads as ErrAlreadyExists", func(t *testing.T) {
		gl, _ := newFakeGitLab(t, func(w http.ResponseWriter, r *http.Request) {
			jsonResp(w, 409, map[string]any{"message": "409 Conflict: This merge request already exists"})
		})
		_, err := gl.OpenPullRequest(context.Background(), Repo{Owner: "a", Name: "b"},
			PullRequestInput{Head: "h", Base: "trunk"})
		if !errors.Is(err, ErrAlreadyExists) {
			t.Errorf("OpenPullRequest on a duplicate MR = %v, want ErrAlreadyExists", err)
		}
	})
}

func TestGitLabPutFileRefusesEmptyContent(t *testing.T) {
	gl, _ := newFakeGitLab(t, func(w http.ResponseWriter, r *http.Request) { jsonResp(w, 200, map[string]any{}) })
	_, err := gl.PutFile(context.Background(), Repo{Owner: "a", Name: "b"},
		PutFileInput{Branch: "br", Path: "p.yaml", Content: nil})
	if err == nil {
		t.Fatal("committing empty content was allowed — this is the shape an upstream decode failure takes")
	}
}

// GitLab's write endpoints do not return the new commit SHA at all (a
// documented GitLab API gap — gitlab-org/gitlab#26371) — PutFile must resolve
// it with a follow-up call, and this pins down that it does so against the
// BRANCH it just wrote to, not some other ref.
func TestGitLabPutFileResolvesCommitSHAAfterwards(t *testing.T) {
	var sawResolveFor string
	gl, _ := newFakeGitLab(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "PUT" && strings.Contains(r.URL.EscapedPath(), "/repository/files/"):
			jsonResp(w, 200, map[string]any{"file_path": "p.yaml", "branch": "argus/fix"})
		case r.Method == "GET" && strings.Contains(r.URL.EscapedPath(), "/repository/commits/"):
			sawResolveFor = r.URL.EscapedPath()
			jsonResp(w, 200, map[string]any{"id": "newcommitsha"})
		default:
			t.Errorf("unexpected call: %s %s", r.Method, r.URL.EscapedPath())
		}
	})
	commit, err := gl.PutFile(context.Background(), Repo{Owner: "a", Name: "b"}, PutFileInput{
		Branch: "argus/fix", Path: "p.yaml", Content: []byte("x: 1\n"), BaseSHA: "oldcommit",
	})
	if err != nil || commit != "newcommitsha" {
		t.Fatalf("PutFile = %q, %v", commit, err)
	}
	if !strings.HasSuffix(sawResolveFor, "/repository/commits/argus%2Ffix") {
		t.Errorf("ResolveRef was not called against the branch just written to: %q", sawResolveFor)
	}
}

// TestGitLabDeleteFileSendsLastCommitID is BACKLOG.md "still open" #2: GitLab
// does implement a delete-file endpoint, and it takes the same OPTIONAL
// last_commit_id precondition PutFile's write endpoint does — this pins that
// DeleteFile sends it, and resolves the branch's new head afterward exactly
// like PutFile must (GitLab's delete response carries no commit SHA either).
func TestGitLabDeleteFileSendsLastCommitID(t *testing.T) {
	var deletedBody map[string]any
	var sawResolveFor string
	gl, _ := newFakeGitLab(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "DELETE" && strings.Contains(r.URL.EscapedPath(), "/repository/files/"):
			_ = json.NewDecoder(r.Body).Decode(&deletedBody)
			w.WriteHeader(204)
		case r.Method == "GET" && strings.Contains(r.URL.EscapedPath(), "/repository/commits/"):
			sawResolveFor = r.URL.EscapedPath()
			jsonResp(w, 200, map[string]any{"id": "commit-after-delete"})
		default:
			t.Errorf("unexpected call: %s %s", r.Method, r.URL.EscapedPath())
			w.WriteHeader(500)
		}
	})
	commit, err := gl.DeleteFile(context.Background(), Repo{Owner: "a", Name: "b"}, DeleteFileInput{
		Branch:  "argus/fix-inc123",
		Path:    "envs/prod/hpa-a.yaml",
		Message: "delete envs/prod/hpa-a.yaml",
		BaseSHA: "commit111",
	})
	if err != nil || commit != "commit-after-delete" {
		t.Fatalf("DeleteFile = %q, %v", commit, err)
	}
	if deletedBody["last_commit_id"] != "commit111" {
		t.Errorf("delete did not send last_commit_id as its compare-and-swap token: %v", deletedBody)
	}
	if deletedBody["branch"] != "argus/fix-inc123" {
		t.Errorf("delete did not target the fix branch: %v", deletedBody)
	}
	if !strings.HasSuffix(sawResolveFor, "/repository/commits/argus%2Ffix-inc123") {
		t.Errorf("ResolveRef was not called against the branch just deleted from: %q", sawResolveFor)
	}
}

// TestGitLabDeleteFileRequiresBaseSHA mirrors GitHub's identical rule:
// DeleteFileInput.BaseSHA is ALWAYS required, unlike PutFileInput's (which is
// only empty for a file being created) — a delete has no "does not exist
// yet" case to allow.
func TestGitLabDeleteFileRequiresBaseSHA(t *testing.T) {
	gl, _ := newFakeGitLab(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no network call should be made for an unconditional delete: %s %s", r.Method, r.URL.EscapedPath())
		w.WriteHeader(500)
	})
	_, err := gl.DeleteFile(context.Background(), Repo{Owner: "a", Name: "b"}, DeleteFileInput{Branch: "br", Path: "p.yaml"})
	if err == nil {
		t.Fatal("an unconditional delete (no BaseSHA) was allowed")
	}
}

// TestGitLabDeleteFileConflict mirrors PutFile's own judgment call (see its
// doc comment): a 400 with no more specific cause is read as ErrConflict,
// because the overwhelmingly likely cause once the request is otherwise
// well-formed is last_commit_id no longer matching the branch.
func TestGitLabDeleteFileConflict(t *testing.T) {
	gl, _ := newFakeGitLab(t, func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, 400, map[string]any{"message": "A file with this name doesn't exist"})
	})
	_, err := gl.DeleteFile(context.Background(), Repo{Owner: "a", Name: "b"}, DeleteFileInput{
		Branch: "br", Path: "p.yaml", BaseSHA: "commit111",
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

// A directory has no equivalent "type": "dir" response on GitLab's file
// endpoint (unlike GitHub's unified Contents API) — it is simply a different
// endpoint (`/repository/tree`) that this provider never calls, so requesting
// one here 404s like any other missing path.
func TestGitLabDirectoryPathReadsAsNotFound(t *testing.T) {
	gl, _ := newFakeGitLab(t, func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, 404, map[string]any{"message": "404 File Not Found"})
	})
	_, err := gl.ReadFile(context.Background(), Repo{Owner: "a", Name: "b"}, "", "envs")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("a directory path gave %v, want ErrNotFound", err)
	}
}

// An unspecified ref defaults to the literal "HEAD" — GitLab's ref parameter
// is required, unlike GitHub's, where an absent ref means the default branch
// implicitly.
func TestGitLabReadFileDefaultsRefToHEAD(t *testing.T) {
	var sawRef string
	gl, _ := newFakeGitLab(t, func(w http.ResponseWriter, r *http.Request) {
		sawRef = r.URL.Query().Get("ref")
		jsonResp(w, 200, map[string]any{"encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte("x")), "last_commit_id": "c"})
	})
	if _, err := gl.ReadFile(context.Background(), Repo{Owner: "a", Name: "b"}, "", "p.yaml"); err != nil {
		t.Fatal(err)
	}
	if sawRef != "HEAD" {
		t.Errorf("ref = %q, want the literal \"HEAD\" GitLab documents as meaning the default branch", sawRef)
	}
}

// Nested paths must have their slashes percent-encoded into ONE segment
// (GitLab's convention), the opposite of GitHub's per-segment escaping that
// preserves literal "/" characters — this is the test that would fail if
// gitlab.go's escaping were copy-pasted from github.go without adjustment.
func TestGitLabNestedPathsAreEncodedAsOneSegment(t *testing.T) {
	var seenPath, seenRawQuery string
	gl, _ := newFakeGitLab(t, func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.EscapedPath()
		seenRawQuery = r.URL.RawQuery
		jsonResp(w, 200, map[string]any{"encoding": "base64", "content": "eA==", "last_commit_id": "c"})
	})
	if _, err := gl.ReadFile(context.Background(), Repo{Owner: "a", Name: "b"}, "main", "envs/prod/eu/values.yaml"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(seenPath, "/repository/files/envs%2Fprod%2Feu%2Fvalues.yaml") {
		t.Errorf("path = %q — internal slashes must be percent-encoded into one segment for GitLab's :file_path", seenPath)
	}
	if !strings.Contains(seenRawQuery, "ref=main") {
		t.Errorf("query = %q, want ref=main", seenRawQuery)
	}
}

// TestGitLabIsAncestor exercises IsAncestor's documented derivation from
// GitLab's compare endpoint (no status field, no exposed merge-base — see the
// method's own doc comment): empty commits means ancestor's whole history is
// already contained in ref's.
func TestGitLabIsAncestor(t *testing.T) {
	for _, tc := range []struct {
		name    string
		commits []string
		want    bool
	}{
		{"nothing unique to ancestor -> contained", nil, true},
		{"ancestor has commits ref lacks -> not contained", []string{"x", "y"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gl, fake := newFakeGitLab(t, func(w http.ResponseWriter, r *http.Request) {
				commits := make([]map[string]any, len(tc.commits))
				for i, id := range tc.commits {
					commits[i] = map[string]any{"id": id}
				}
				jsonResp(w, 200, map[string]any{"commits": commits, "compare_same_ref": len(tc.commits) == 0})
			})
			got, err := gl.IsAncestor(context.Background(), Repo{Owner: "a", Name: "b"}, "deadbeef", "c0ffee")
			if err != nil {
				t.Fatalf("IsAncestor: %v", err)
			}
			if got != tc.want {
				t.Errorf("IsAncestor = %v, want %v", got, tc.want)
			}
			if len(fake.requests) != 1 || !strings.Contains(fake.requests[0], "from=c0ffee") || !strings.Contains(fake.requests[0], "to=deadbeef") || !strings.Contains(fake.requests[0], "straight=true") {
				t.Errorf("requests = %v, want a single compare call with from=ref, to=ancestor, straight=true", fake.requests)
			}
		})
	}

	// An unreachable provider (or an unknown SHA, which 404s) must surface as a
	// real error, never a silent false — the same BUGS.md 81 constraint
	// github_test.go's TestIsAncestor pins down for GitHub.
	t.Run("provider error propagates, is not swallowed into false", func(t *testing.T) {
		gl, _ := newFakeGitLab(t, func(w http.ResponseWriter, r *http.Request) {
			jsonResp(w, 404, map[string]any{"message": "404 Not Found"})
		})
		if _, err := gl.IsAncestor(context.Background(), Repo{Owner: "a", Name: "b"}, "deadbeef", "unknown-sha"); !errors.Is(err, ErrNotFound) {
			t.Errorf("IsAncestor on an unknown SHA = %v, want ErrNotFound", err)
		}
	})
}

// PullRequestStatus must tell "still open" from "closed without merging" apart
// (BUGS.md 82's own point, restated for GitLab's own state vocabulary), and
// must recover a squash-merged MR's landed commit from squash_commit_sha since
// merge_commit_sha is left empty in that case.
func TestGitLabPullRequestStatus(t *testing.T) {
	t.Run("merged (regular merge commit)", func(t *testing.T) {
		gl, _ := newFakeGitLab(t, func(w http.ResponseWriter, r *http.Request) {
			jsonResp(w, 200, map[string]any{
				"state": "merged", "created_at": "2026-08-20T09:00:00Z",
				"merged_at": "2026-08-24T15:45:00Z", "merge_commit_sha": "deadbeef",
			})
		})
		status, err := gl.PullRequestStatus(context.Background(), Repo{Owner: "a", Name: "b"}, 24)
		if err != nil {
			t.Fatalf("PullRequestStatus: %v", err)
		}
		if !status.Merged || status.MergeCommitSHA != "deadbeef" || status.MergedAt.IsZero() {
			t.Errorf("status = %+v", status)
		}
	})

	t.Run("merged via squash — merge_commit_sha empty, squash_commit_sha carries it", func(t *testing.T) {
		gl, _ := newFakeGitLab(t, func(w http.ResponseWriter, r *http.Request) {
			jsonResp(w, 200, map[string]any{
				"state": "merged", "merged_at": "2026-08-24T15:45:00Z",
				"merge_commit_sha": "", "squash_commit_sha": "c0ffee",
			})
		})
		status, err := gl.PullRequestStatus(context.Background(), Repo{Owner: "a", Name: "b"}, 24)
		if err != nil {
			t.Fatalf("PullRequestStatus: %v", err)
		}
		if !status.Merged || status.MergeCommitSHA != "c0ffee" {
			t.Errorf("status = %+v, want the squash commit to be reported as the landed SHA", status)
		}
	})

	t.Run("still open", func(t *testing.T) {
		gl, _ := newFakeGitLab(t, func(w http.ResponseWriter, r *http.Request) {
			jsonResp(w, 200, map[string]any{"state": "opened", "created_at": "2026-08-20T09:00:00Z"})
		})
		status, err := gl.PullRequestStatus(context.Background(), Repo{Owner: "a", Name: "b"}, 24)
		if err != nil {
			t.Fatalf("PullRequestStatus: %v", err)
		}
		if status.Merged || !status.MergedAt.IsZero() {
			t.Errorf("status = %+v, want Merged=false for a still-open MR", status)
		}
		if status.State != "opened" {
			t.Errorf("status.State = %q, want %q", status.State, "opened")
		}
	})

	t.Run("closed without merging", func(t *testing.T) {
		gl, _ := newFakeGitLab(t, func(w http.ResponseWriter, r *http.Request) {
			jsonResp(w, 200, map[string]any{"state": "closed"})
		})
		status, err := gl.PullRequestStatus(context.Background(), Repo{Owner: "a", Name: "b"}, 24)
		if err != nil {
			t.Fatalf("PullRequestStatus: %v", err)
		}
		if status.Merged {
			t.Errorf("status = %+v, want Merged=false for closed-without-merging", status)
		}
		if status.State != "closed" {
			t.Errorf("status.State = %q, want %q — this is what distinguishes this from \"still open\"", status.State, "closed")
		}
	})

	t.Run("not found", func(t *testing.T) {
		gl, _ := newFakeGitLab(t, func(w http.ResponseWriter, r *http.Request) {
			jsonResp(w, 404, map[string]any{"message": "404 Not found"})
		})
		if _, err := gl.PullRequestStatus(context.Background(), Repo{Owner: "a", Name: "b"}, 999); !errors.Is(err, ErrNotFound) {
			t.Errorf("PullRequestStatus on a missing MR = %v, want ErrNotFound", err)
		}
	})
}

// CloneToken hands out the same token used for API calls — see the method's
// own doc comment for why that is the correct, symmetric-with-GitHub answer
// rather than an oversight.
func TestGitLabCloneToken(t *testing.T) {
	gl := &GitLab{Token: "test-token"}
	if gl.CloneToken() != "test-token" {
		t.Errorf("CloneToken() = %q, want the configured token", gl.CloneToken())
	}
}

// TestGitLabIsNotAnAtomicCommitter is BACKLOG.md F24's regression guard on
// the OTHER provider: GitLab's file-write API is one call per file with no
// multi-file tree equivalent (see PutFile's own doc comment for the GitLab
// issue-tracker citations backing that), so *GitLab must NOT satisfy
// scm.AtomicCommitter. gitops.ProposeChanges type-asserts for that interface
// to decide whether to commit atomically or fall back to N sequential
// PutFile calls — if GitLab ever accidentally started satisfying it (e.g. by
// gaining an unrelated PutFiles-shaped method), that caller would silently
// switch behaviour for GitLab without anyone deciding it should.
func TestGitLabIsNotAnAtomicCommitter(t *testing.T) {
	var p Provider = &GitLab{}
	if _, ok := p.(AtomicCommitter); ok {
		t.Fatal("*GitLab satisfies AtomicCommitter — it must not, since its REST API has no atomic multi-file commit equivalent; gitops.ProposeChanges relies on this assertion failing to keep using the sequential PutFile path for GitLab")
	}
}
