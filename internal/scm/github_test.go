package scm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeGitHub is a scripted API. Deliberately not a full GitHub: it asserts the
// requests ARGUS makes and returns the shapes GitHub documents, which is what
// these tests are about.
type fakeGitHub struct {
	t        *testing.T
	requests []string // "METHOD /path", in order — so a test can assert the chain
	handler  func(w http.ResponseWriter, r *http.Request)
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	// Contract checks that apply to every call, asserted once here rather than
	// forgotten in individual tests.
	if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
		f.t.Errorf("%s %s: Authorization = %q", r.Method, r.URL.Path, got)
	}
	if r.Header.Get("User-Agent") == "" {
		f.t.Errorf("%s %s: no User-Agent — GitHub rejects requests without one", r.Method, r.URL.Path)
	}
	if r.Header.Get("X-GitHub-Api-Version") == "" {
		f.t.Errorf("%s %s: no API version pin", r.Method, r.URL.Path)
	}
	f.handler(w, r)
}

func newFake(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) (*GitHub, *fakeGitHub) {
	t.Helper()
	f := &fakeGitHub{t: t, handler: h}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	// BaseURL pointing at a local server is the same mechanism GHES uses —
	// DESIGN.md §11.3's "configurable API base URL, required not optional".
	return &GitHub{BaseURL: srv.URL, Token: "test-token", HTTPClient: srv.Client()}, f
}

func jsonResp(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// The whole chain a remediation PR needs: resolve, read, branch, commit, open.
func TestFullPullRequestChain(t *testing.T) {
	repo := Repo{Owner: "acme", Name: "platform-config"}
	const blobSHA = "blob111"
	var committed map[string]any

	gh, fake := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/acme/platform-config":
			jsonResp(w, 200, map[string]any{"default_branch": "trunk"})
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/repos/acme/platform-config/commits/"):
			jsonResp(w, 200, map[string]any{"sha": "commitAAA"})
		case r.Method == "GET" && r.URL.Path == "/repos/acme/platform-config/contents/envs/prod/values.yaml":
			if got := r.URL.Query().Get("ref"); got != "commitAAA" {
				t.Errorf("read was not pinned to the resolved commit: ref=%q", got)
			}
			jsonResp(w, 200, map[string]any{
				"type": "file", "encoding": "base64", "sha": blobSHA,
				// Wrapped at 60 cols, as GitHub actually returns it.
				"content": "cmVwbGljYXM6IDIKbWVtb3J5OiAyNTZNaQo=\n",
			})
		case r.Method == "POST" && r.URL.Path == "/repos/acme/platform-config/git/refs":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["ref"] != "refs/heads/argus/fix-inc123" {
				t.Errorf("branch ref = %q", body["ref"])
			}
			if body["sha"] != "commitAAA" {
				t.Errorf("branch point = %q, want the resolved commit", body["sha"])
			}
			jsonResp(w, 201, map[string]any{})
		case r.Method == "PUT" && r.URL.Path == "/repos/acme/platform-config/contents/envs/prod/values.yaml":
			_ = json.NewDecoder(r.Body).Decode(&committed)
			jsonResp(w, 200, map[string]any{"commit": map[string]any{"sha": "commitBBB"}})
		case r.Method == "POST" && r.URL.Path == "/repos/acme/platform-config/pulls":
			jsonResp(w, 201, map[string]any{"number": 42, "html_url": "https://github.example/pr/42"})
		case r.Method == "POST" && r.URL.Path == "/repos/acme/platform-config/issues/42/labels":
			jsonResp(w, 200, []any{})
		default:
			t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	})
	ctx := context.Background()

	base, err := gh.DefaultBranch(ctx, repo)
	if err != nil || base != "trunk" {
		t.Fatalf("DefaultBranch = %q, %v", base, err)
	}
	sha, err := gh.ResolveRef(ctx, repo, base)
	if err != nil {
		t.Fatalf("ResolveRef: %v", err)
	}
	content, blob, err := gh.ReadFileForUpdate(ctx, repo, sha, "envs/prod/values.yaml")
	if err != nil {
		t.Fatalf("ReadFileForUpdate: %v", err)
	}
	if !strings.Contains(string(content), "replicas: 2") {
		t.Errorf("decoded content = %q", content)
	}
	if blob != blobSHA {
		t.Errorf("blob SHA = %q, want %q — PutFile's compare-and-swap depends on this being the BLOB sha, not the commit", blob, blobSHA)
	}
	if err := gh.CreateBranch(ctx, repo, "argus/fix-inc123", sha); err != nil {
		t.Fatalf("CreateBranch: %v", err)
	}
	commit, err := gh.PutFile(ctx, repo, PutFileInput{
		Branch: "argus/fix-inc123", Path: "envs/prod/values.yaml",
		Content: []byte("replicas: 2\nmemory: 512Mi\n"),
		Message: "Raise checkout-worker memory limit to 512Mi",
		BaseSHA: blob,
		Author:  Identity{Name: "argus", Email: "argus@acme.example"},
		Trailers: []string{
			"Requested-by: alice@acme.example",
			"Argus-Incident: inc123",
		},
	})
	if err != nil || commit != "commitBBB" {
		t.Fatalf("PutFile = %q, %v", commit, err)
	}

	// The commit must carry the compare-and-swap token and the attribution.
	if committed["sha"] != blobSHA {
		t.Errorf("commit did not send the base blob SHA: %v", committed["sha"])
	}
	msg, _ := committed["message"].(string)
	if !strings.Contains(msg, "Requested-by: alice@acme.example") {
		t.Errorf("commit message lost its trailers — D-R9 puts attribution here, on the commit, not on the credential:\n%s", msg)
	}
	if !strings.HasPrefix(msg, "Raise checkout-worker memory limit") {
		t.Errorf("trailers displaced the subject line:\n%s", msg)
	}
	raw, err := base64.StdEncoding.DecodeString(committed["content"].(string))
	if err != nil || !strings.Contains(string(raw), "512Mi") {
		t.Errorf("committed content = %q (%v)", raw, err)
	}

	pr, err := gh.OpenPullRequest(ctx, repo, PullRequestInput{
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

// A 401 and a 403 have DIFFERENT fixes — renew the token vs widen its scope —
// so they must not collapse into one error.
func TestCredentialFailuresAreDistinguishable(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		headers map[string]string
		want    error
		wantMsg string
	}{
		{"expired token", 401, nil, ErrCredentialExpired, "renew"},
		{"insufficient scope", 403, nil, ErrForbidden, "contents:write"},
		{"rate limited", 403, map[string]string{"X-RateLimit-Remaining": "0"}, ErrForbidden, "rate limit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gh, _ := newFake(t, func(w http.ResponseWriter, r *http.Request) {
				for k, v := range tc.headers {
					w.Header().Set(k, v)
				}
				jsonResp(w, tc.status, map[string]any{"message": "Resource not accessible"})
			})
			_, err := gh.DefaultBranch(context.Background(), Repo{Owner: "a", Name: "b"})
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.wantMsg) {
				t.Errorf("message does not tell the operator what to do (%q): %v", tc.wantMsg, err)
			}
		})
	}
}

func TestNotFoundAndConflictAndAlreadyExists(t *testing.T) {
	cases := []struct {
		status int
		body   any
		want   error
	}{
		{404, map[string]any{"message": "Not Found"}, ErrNotFound},
		{409, map[string]any{"message": "is at abc but expected def"}, ErrConflict},
		{422, map[string]any{"message": "Reference already exists"}, ErrAlreadyExists},
	}
	for _, tc := range cases {
		gh, _ := newFake(t, func(w http.ResponseWriter, r *http.Request) { jsonResp(w, tc.status, tc.body) })
		err := gh.CreateBranch(context.Background(), Repo{Owner: "a", Name: "b"}, "br", "sha")
		if !errors.Is(err, tc.want) {
			t.Errorf("status %d -> %v, want %v", tc.status, err, tc.want)
		}
	}
}

// A 422 that is NOT "already exists" is a real validation failure and must not
// be mistaken for one.
func TestUnprocessableIsNotAlwaysAlreadyExists(t *testing.T) {
	gh, _ := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, 422, map[string]any{"message": "Invalid request", "errors": []any{map[string]any{"message": "base is invalid"}}})
	})
	err := gh.CreateBranch(context.Background(), Repo{Owner: "a", Name: "b"}, "br", "sha")
	if errors.Is(err, ErrAlreadyExists) {
		t.Fatal("a genuine validation failure was reported as ErrAlreadyExists")
	}
	if !strings.Contains(err.Error(), "base is invalid") {
		t.Errorf("the provider's own reason was lost: %v", err)
	}
}

// A file too large for the Contents API comes back with empty content. Decoding
// that would produce an empty manifest and a PR that deletes its contents.
func TestOversizeFileIsRefusedRatherThanDecodedToEmpty(t *testing.T) {
	gh, _ := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, 200, map[string]any{"type": "file", "encoding": "none", "content": "", "sha": "s"})
	})
	_, err := gh.ReadFile(context.Background(), Repo{Owner: "a", Name: "b"}, "main", "big.yaml")
	if err == nil {
		t.Fatal("a file with encoding \"none\" decoded to empty instead of failing")
	}
	if !strings.Contains(err.Error(), "1MB") {
		t.Errorf("error does not explain the size limit: %v", err)
	}
}

func TestPutFileRefusesEmptyContent(t *testing.T) {
	gh, _ := newFake(t, func(w http.ResponseWriter, r *http.Request) { jsonResp(w, 200, map[string]any{}) })
	_, err := gh.PutFile(context.Background(), Repo{Owner: "a", Name: "b"},
		PutFileInput{Branch: "br", Path: "p.yaml", Content: nil})
	if err == nil {
		t.Fatal("committing empty content was allowed — this is the shape an upstream decode failure takes")
	}
}

// TestDeleteFileCommitsWithBlobSHA is BACKLOG.md "still open" #2: GitHub's
// Contents API can delete a file with the same DELETE-verb, same-endpoint,
// same blob-SHA-as-compare-and-swap shape PutFile already uses for writes.
func TestDeleteFileCommitsWithBlobSHA(t *testing.T) {
	repo := Repo{Owner: "acme", Name: "platform-config"}
	var deleted map[string]any
	gh, _ := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "DELETE" && r.URL.Path == "/repos/acme/platform-config/contents/envs/prod/hpa-a.yaml":
			_ = json.NewDecoder(r.Body).Decode(&deleted)
			jsonResp(w, 200, map[string]any{"commit": map[string]any{"sha": "commit-delete-1"}})
		default:
			t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	})
	commit, err := gh.DeleteFile(context.Background(), repo, DeleteFileInput{
		Branch:  "argus/fix-inc123",
		Path:    "envs/prod/hpa-a.yaml",
		Message: "delete envs/prod/hpa-a.yaml",
		BaseSHA: "blob-hpa-a",
		Author:  Identity{Name: "argus", Email: "argus@acme.example"},
	})
	if err != nil || commit != "commit-delete-1" {
		t.Fatalf("DeleteFile = %q, %v", commit, err)
	}
	if deleted["sha"] != "blob-hpa-a" {
		t.Errorf("delete did not send the blob SHA compare-and-swap token: %v", deleted)
	}
	if deleted["branch"] != "argus/fix-inc123" {
		t.Errorf("delete did not target the fix branch: %v", deleted)
	}
}

// TestDeleteFileRequiresBaseSHA: unlike PutFile (empty BaseSHA means
// "create"), DeleteFile has no analogous meaning for an empty BaseSHA — a
// file must already exist, at a known blob, to be deleted at all.
func TestDeleteFileRequiresBaseSHA(t *testing.T) {
	gh, _ := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no network call should be made for an unconditional delete: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(500)
	})
	_, err := gh.DeleteFile(context.Background(), Repo{Owner: "a", Name: "b"},
		DeleteFileInput{Branch: "br", Path: "p.yaml"})
	if err == nil {
		t.Fatal("an unconditional delete (no BaseSHA) was allowed — this could remove a file a concurrent commit just changed")
	}
}

// TestDeleteFileConflict: the file moved (or was already deleted) since it
// was read — the same 409 PutFile's compare-and-swap produces.
func TestDeleteFileConflict(t *testing.T) {
	gh, _ := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, 409, map[string]any{"message": "hpa-a.yaml sha does not match blob-hpa-a"})
	})
	_, err := gh.DeleteFile(context.Background(), Repo{Owner: "a", Name: "b"},
		DeleteFileInput{Branch: "br", Path: "p.yaml", BaseSHA: "blob-hpa-a"})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

// TestPutFilesMixedDeleteAndWrite is BACKLOG.md "still open" #2 item 6(d):
// deleting one path and writing a DIFFERENT one lands in ONE atomic commit.
// The tree API represents the delete as a null-sha entry — no blob is
// created for it — alongside the write's real new blob.
func TestPutFilesMixedDeleteAndWrite(t *testing.T) {
	repo := Repo{Owner: "acme", Name: "platform-config"}
	const baseCommit = "basecommitAAA"
	const baseTree = "basetreeBBB"
	var blobsCreated []map[string]any
	var treeBody map[string]any

	gh, _ := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/acme/platform-config/git/commits/"+baseCommit:
			jsonResp(w, 200, map[string]any{"sha": baseCommit, "tree": map[string]any{"sha": baseTree}})
		case r.Method == "GET" && r.URL.Path == "/repos/acme/platform-config/git/trees/"+baseTree:
			jsonResp(w, 200, map[string]any{
				"tree": []map[string]any{
					{"path": "envs/prod/hpa-a.yaml", "sha": "blob-hpa-a-OLD", "type": "blob"},
					{"path": "envs/prod/values.yaml", "sha": "blob-values-OLD", "type": "blob"},
				},
			})
		case r.Method == "POST" && r.URL.Path == "/repos/acme/platform-config/git/blobs":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			blobsCreated = append(blobsCreated, body)
			jsonResp(w, 201, map[string]any{"sha": "blob-new-1"})
		case r.Method == "POST" && r.URL.Path == "/repos/acme/platform-config/git/trees":
			_ = json.NewDecoder(r.Body).Decode(&treeBody)
			jsonResp(w, 201, map[string]any{"sha": "newtree-CCC"})
		case r.Method == "POST" && r.URL.Path == "/repos/acme/platform-config/git/commits":
			jsonResp(w, 201, map[string]any{"sha": "newcommit-DDD"})
		case r.Method == "PATCH" && r.URL.Path == "/repos/acme/platform-config/git/refs/heads/argus/fix-inc123":
			jsonResp(w, 200, map[string]any{})
		default:
			t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	})

	sha, err := gh.PutFiles(context.Background(), repo, PutFilesInput{
		Branch:        "argus/fix-inc123",
		BaseCommitSHA: baseCommit,
		Files: []FileCommit{
			{Path: "envs/prod/hpa-a.yaml", BaseSHA: "blob-hpa-a-OLD", Delete: true},
			{Path: "envs/prod/values.yaml", Content: []byte("replicas: 3\n"), BaseSHA: "blob-values-OLD"},
		},
		Message: "fix(shop/checkout): update 2 file(s)",
	})
	if err != nil {
		t.Fatalf("PutFiles: %v", err)
	}
	if sha != "newcommit-DDD" {
		t.Errorf("PutFiles = %q, want the new commit SHA", sha)
	}
	// Exactly one blob — for the WRITE. The delete needs none.
	if len(blobsCreated) != 1 {
		t.Fatalf("created %d blobs, want exactly 1", len(blobsCreated))
	}
	entries, _ := treeBody["tree"].([]any)
	if len(entries) != 2 {
		t.Fatalf("tree has %d entries, want 2", len(entries))
	}
	var sawDeleteNullSHA, sawWriteRealSHA bool
	for _, raw := range entries {
		e, _ := raw.(map[string]any)
		switch e["path"] {
		case "envs/prod/hpa-a.yaml":
			if _, hasKey := e["sha"]; !hasKey {
				t.Errorf("deleted entry has no \"sha\" key at all — GitHub's own documented meaning of delete is an explicit null, not an absent key: %v", e)
			}
			sawDeleteNullSHA = e["sha"] == nil
		case "envs/prod/values.yaml":
			sawWriteRealSHA = e["sha"] == "blob-new-1"
		}
	}
	if !sawDeleteNullSHA {
		t.Errorf("delete entry's sha was not a literal null: %v", entries)
	}
	if !sawWriteRealSHA {
		t.Errorf("write entry's sha was not the new blob: %v", entries)
	}
}

// Nested paths must not be escaped into a single segment, or the API 404s on a
// path that exists.
func TestNestedPathsKeepTheirSlashes(t *testing.T) {
	var seen string
	gh, _ := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.Path
		jsonResp(w, 200, map[string]any{"type": "file", "encoding": "base64", "content": "eA==", "sha": "s"})
	})
	if _, err := gh.ReadFile(context.Background(), Repo{Owner: "a", Name: "b"}, "", "envs/prod/eu/values.yaml"); err != nil {
		t.Fatal(err)
	}
	if seen != "/repos/a/b/contents/envs/prod/eu/values.yaml" {
		t.Errorf("path = %q — slashes must survive escaping", seen)
	}
}

// A directory returned where a file was expected must be ErrNotFound, so a
// caller searching for a manifest keeps searching instead of aborting.
func TestDirectoryReadsAsNotFound(t *testing.T) {
	gh, _ := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, 200, map[string]any{"type": "dir"})
	})
	_, err := gh.ReadFile(context.Background(), Repo{Owner: "a", Name: "b"}, "", "envs")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("a directory gave %v, want ErrNotFound", err)
	}
}

// Labels are cosmetic; the PR is the deliverable. A label failure must report
// the PR that DOES exist rather than reading as "no PR was opened".
func TestLabelFailureStillReturnsTheOpenPR(t *testing.T) {
	gh, _ := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/labels") {
			jsonResp(w, 403, map[string]any{"message": "no"})
			return
		}
		jsonResp(w, 201, map[string]any{"number": 7, "html_url": "https://example/pr/7"})
	})
	pr, err := gh.OpenPullRequest(context.Background(), Repo{Owner: "a", Name: "b"},
		PullRequestInput{Head: "h", Base: "b", Labels: []string{"x"}})
	if pr.Number != 7 || pr.URL == "" {
		t.Errorf("the opened PR was lost when labelling failed: %+v", pr)
	}
	if err == nil || !strings.Contains(err.Error(), "#7") {
		t.Errorf("error should name the PR that exists: %v", err)
	}
}

// PullRequestStatus is MergeSweeper's only window into a PR it opened
// earlier — merged, still open, and gone (deleted/inaccessible) are the
// three answers it has to tell apart correctly.
func TestPullRequestStatus(t *testing.T) {
	t.Run("merged", func(t *testing.T) {
		gh, _ := newFake(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" || r.URL.Path != "/repos/acme/platform-config/pulls/24" {
				t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			}
			jsonResp(w, 200, map[string]any{
				"state": "closed", "merged": true, "created_at": "2026-08-20T09:00:00Z",
				"merged_at": "2026-08-24T15:45:00Z", "merge_commit_sha": "deadbeef",
			})
		})
		status, err := gh.PullRequestStatus(context.Background(), Repo{Owner: "acme", Name: "platform-config"}, 24)
		if err != nil {
			t.Fatalf("PullRequestStatus: %v", err)
		}
		if !status.Merged || status.MergeCommitSHA != "deadbeef" || status.MergedAt.IsZero() {
			t.Errorf("status = %+v, want Merged=true with a commit SHA and a non-zero MergedAt", status)
		}
		if status.CreatedAt.IsZero() {
			t.Errorf("status = %+v, want a non-zero CreatedAt", status)
		}
	})

	t.Run("still open", func(t *testing.T) {
		gh, _ := newFake(t, func(w http.ResponseWriter, r *http.Request) {
			jsonResp(w, 200, map[string]any{"state": "open", "merged": false, "created_at": "2026-08-20T09:00:00Z"})
		})
		status, err := gh.PullRequestStatus(context.Background(), Repo{Owner: "acme", Name: "platform-config"}, 24)
		if err != nil {
			t.Fatalf("PullRequestStatus: %v", err)
		}
		if status.Merged || !status.MergedAt.IsZero() {
			t.Errorf("status = %+v, want Merged=false and a zero MergedAt for a PR nobody has merged yet", status)
		}
		if status.State != "open" {
			t.Errorf("status.State = %q, want %q — MergeSweeper's staleness check runs for exactly this case", status.State, "open")
		}
	})

	// BUGS.md 82: Merged alone cannot tell "still open" from "closed without
	// merging" apart — both are false — which is exactly why the bug existed.
	// State is what the caller (internal/api.CheckPullRequestMerged) now reads
	// to make that distinction, so this test asserts State survives the
	// decode, not just Merged.
	t.Run("closed without merging", func(t *testing.T) {
		gh, _ := newFake(t, func(w http.ResponseWriter, r *http.Request) {
			jsonResp(w, 200, map[string]any{"state": "closed", "merged": false})
		})
		status, err := gh.PullRequestStatus(context.Background(), Repo{Owner: "acme", Name: "platform-config"}, 24)
		if err != nil {
			t.Fatalf("PullRequestStatus: %v", err)
		}
		if status.Merged {
			t.Errorf("status = %+v, want Merged=false for a closed-without-merging PR", status)
		}
		if status.State != "closed" {
			t.Errorf("status.State = %q, want %q — this is the one field that now distinguishes this case from \"still open\"", status.State, "closed")
		}
	})

	t.Run("not found", func(t *testing.T) {
		gh, _ := newFake(t, func(w http.ResponseWriter, r *http.Request) {
			jsonResp(w, 404, map[string]any{"message": "Not Found"})
		})
		if _, err := gh.PullRequestStatus(context.Background(), Repo{Owner: "acme", Name: "platform-config"}, 999); !errors.Is(err, ErrNotFound) {
			t.Errorf("PullRequestStatus on a missing PR = %v, want ErrNotFound", err)
		}
	})
}

// --- PutFiles: the atomic multi-file path (BACKLOG.md F24) -----------------

// TestPutFilesCommitsOneAtomicCommit is the headline contract: three files go
// out through blobs -> tree -> commit -> ref update, as ONE commit, not three
// PUTs.
func TestPutFilesCommitsOneAtomicCommit(t *testing.T) {
	repo := Repo{Owner: "acme", Name: "platform-config"}
	const baseCommit = "basecommitAAA"
	const baseTree = "basetreeBBB"

	var blobsCreated []map[string]any
	var treeBody map[string]any
	var commitBody map[string]any
	var refBody map[string]any

	gh, fake := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/acme/platform-config/git/commits/"+baseCommit:
			jsonResp(w, 200, map[string]any{"sha": baseCommit, "tree": map[string]any{"sha": baseTree}})
		case r.Method == "GET" && r.URL.Path == "/repos/acme/platform-config/git/trees/"+baseTree:
			if r.URL.Query().Get("recursive") != "1" {
				t.Errorf("tree read was not recursive: %s", r.URL.RawQuery)
			}
			jsonResp(w, 200, map[string]any{
				"tree": []map[string]any{
					{"path": "envs/prod/values.yaml", "sha": "blob-values-OLD", "type": "blob"},
					{"path": "envs/prod/deploy.yaml", "sha": "blob-deploy-OLD", "type": "blob"},
					{"path": "README.md", "sha": "blob-readme-unrelated", "type": "blob"},
				},
			})
		case r.Method == "POST" && r.URL.Path == "/repos/acme/platform-config/git/blobs":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			blobsCreated = append(blobsCreated, body)
			jsonResp(w, 201, map[string]any{"sha": "blob-new-" + strings.TrimSpace(fmt.Sprint(len(blobsCreated)))})
		case r.Method == "POST" && r.URL.Path == "/repos/acme/platform-config/git/trees":
			_ = json.NewDecoder(r.Body).Decode(&treeBody)
			jsonResp(w, 201, map[string]any{"sha": "newtree-CCC"})
		case r.Method == "POST" && r.URL.Path == "/repos/acme/platform-config/git/commits":
			_ = json.NewDecoder(r.Body).Decode(&commitBody)
			jsonResp(w, 201, map[string]any{"sha": "newcommit-DDD"})
		case r.Method == "PATCH" && r.URL.Path == "/repos/acme/platform-config/git/refs/heads/argus/fix-inc123":
			_ = json.NewDecoder(r.Body).Decode(&refBody)
			jsonResp(w, 200, map[string]any{})
		default:
			t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	})

	sha, err := gh.PutFiles(context.Background(), repo, PutFilesInput{
		Branch:        "argus/fix-inc123",
		BaseCommitSHA: baseCommit,
		Files: []FileCommit{
			{Path: "envs/prod/values.yaml", Content: []byte("replicas: 3\n"), BaseSHA: "blob-values-OLD"},
			{Path: "envs/prod/deploy.yaml", Content: []byte("image: v2\n"), BaseSHA: "blob-deploy-OLD"},
			{Path: "envs/prod/new.yaml", Content: []byte("kind: NEW\n"), BaseSHA: ""},
		},
		Message:  "fix(shop/checkout): update 3 files",
		Author:   Identity{Name: "argus", Email: "argus@acme.example"},
		Trailers: []string{"Argus-Incident: inc123"},
	})
	if err != nil {
		t.Fatalf("PutFiles: %v", err)
	}
	if sha != "newcommit-DDD" {
		t.Errorf("PutFiles returned %q, want the new commit SHA", sha)
	}
	if len(blobsCreated) != 3 {
		t.Fatalf("created %d blobs, want one per file", len(blobsCreated))
	}

	// The tree is based on the branch's CURRENT tree and lists only the
	// changed paths — everything else (README.md) is inherited via base_tree,
	// never re-listed.
	if treeBody["base_tree"] != baseTree {
		t.Errorf("tree base_tree = %v, want %q", treeBody["base_tree"], baseTree)
	}
	entries, _ := treeBody["tree"].([]any)
	if len(entries) != 3 {
		t.Fatalf("tree has %d entries, want exactly the 3 changed files (README.md must NOT be re-listed): %v", len(entries), entries)
	}

	// The commit is parented on the branch's current head and carries the
	// shared message and trailers — there is no per-file commit to put them
	// on.
	if commitBody["tree"] != "newtree-CCC" {
		t.Errorf("commit tree = %v, want %q", commitBody["tree"], "newtree-CCC")
	}
	parents, _ := commitBody["parents"].([]any)
	if len(parents) != 1 || parents[0] != baseCommit {
		t.Errorf("commit parents = %v, want [%q]", parents, baseCommit)
	}
	msg, _ := commitBody["message"].(string)
	if !strings.Contains(msg, "Argus-Incident: inc123") {
		t.Errorf("commit message lost its trailers:\n%s", msg)
	}

	// The ref update is the ONLY step that touches the branch, and it must be
	// fast-forward-only (force:false) — that is the atomic compare-and-swap.
	if refBody["sha"] != "newcommit-DDD" {
		t.Errorf("ref update sha = %v, want the new commit", refBody["sha"])
	}
	if force, _ := refBody["force"].(bool); force {
		t.Error("ref update set force:true — that would silently overwrite a concurrent push instead of rejecting it")
	}

	// Exactly one write to git/refs/heads: no PUT to the contents API at all.
	for _, r := range fake.requests {
		if strings.Contains(r, "/contents/") {
			t.Errorf("PutFiles used the per-file contents API (%s) instead of the trees API", r)
		}
	}
}

// TestPutFilesPrecheckCatchesDriftBeforeWritingAnything is the property that
// actually fixes BACKLOG.md F24, not just a nice-to-have: if a file moved on
// the branch since it was read (drift between the synced-commit read and the
// branch's current tree), PutFiles must catch it as ErrConflict BEFORE
// creating a single blob, tree or commit — not after, and not by silently
// overwriting it via base_tree inheritance.
func TestPutFilesPrecheckCatchesDriftBeforeWritingAnything(t *testing.T) {
	repo := Repo{Owner: "acme", Name: "platform-config"}
	const baseCommit = "basecommitAAA"
	const baseTree = "basetreeBBB"
	var writesAfterPrecheck []string

	gh, _ := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/acme/platform-config/git/commits/"+baseCommit:
			jsonResp(w, 200, map[string]any{"sha": baseCommit, "tree": map[string]any{"sha": baseTree}})
		case r.Method == "GET" && r.URL.Path == "/repos/acme/platform-config/git/trees/"+baseTree:
			// The branch's current blob for values.yaml is NOT what the caller
			// read (blob-values-OLD) — someone else committed to this path
			// between the synced-commit read and now.
			jsonResp(w, 200, map[string]any{
				"tree": []map[string]any{
					{"path": "envs/prod/values.yaml", "sha": "blob-values-MOVED", "type": "blob"},
				},
			})
		default:
			writesAfterPrecheck = append(writesAfterPrecheck, r.Method+" "+r.URL.Path)
			w.WriteHeader(500)
		}
	})

	_, err := gh.PutFiles(context.Background(), repo, PutFilesInput{
		Branch:        "argus/fix-inc123",
		BaseCommitSHA: baseCommit,
		Files: []FileCommit{
			{Path: "envs/prod/values.yaml", Content: []byte("replicas: 3\n"), BaseSHA: "blob-values-OLD"},
		},
		Message: "fix",
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
	if len(writesAfterPrecheck) != 0 {
		t.Errorf("a write happened after the precheck should have aborted: %v", writesAfterPrecheck)
	}
}

// TestPutFilesRefUpdateConflictLeavesNothingLanded is the OTHER conflict
// window: the branch moves between the precheck (reading the branch's
// current tree) and the final ref update (a concurrent push landing in that
// narrow gap). GitHub's fast-forward-only ref update is what catches this —
// this test proves it maps to ErrConflict and that the commit git objects
// created before it (harmless, unreferenced) never become visible on the
// branch: no pull request would ever be opened on the strength of them.
func TestPutFilesRefUpdateConflictLeavesNothingLanded(t *testing.T) {
	repo := Repo{Owner: "acme", Name: "platform-config"}
	const baseCommit = "basecommitAAA"
	const baseTree = "basetreeBBB"
	var refUpdateCalls int

	gh, _ := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/acme/platform-config/git/commits/"+baseCommit:
			jsonResp(w, 200, map[string]any{"sha": baseCommit, "tree": map[string]any{"sha": baseTree}})
		case r.Method == "GET" && r.URL.Path == "/repos/acme/platform-config/git/trees/"+baseTree:
			jsonResp(w, 200, map[string]any{"tree": []map[string]any{
				{"path": "envs/prod/values.yaml", "sha": "blob-values-OLD", "type": "blob"},
			}})
		case r.Method == "POST" && r.URL.Path == "/repos/acme/platform-config/git/blobs":
			jsonResp(w, 201, map[string]any{"sha": "blob-new-1"})
		case r.Method == "POST" && r.URL.Path == "/repos/acme/platform-config/git/trees":
			jsonResp(w, 201, map[string]any{"sha": "newtree-CCC"})
		case r.Method == "POST" && r.URL.Path == "/repos/acme/platform-config/git/commits":
			jsonResp(w, 201, map[string]any{"sha": "newcommit-DDD"})
		case r.Method == "PATCH" && r.URL.Path == "/repos/acme/platform-config/git/refs/heads/argus/fix-inc123":
			refUpdateCalls++
			// GitHub's real wording for a non-fast-forward update.
			jsonResp(w, 422, map[string]any{"message": "Update is not a fast forward"})
		default:
			t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	})

	_, err := gh.PutFiles(context.Background(), repo, PutFilesInput{
		Branch:        "argus/fix-inc123",
		BaseCommitSHA: baseCommit,
		Files: []FileCommit{
			{Path: "envs/prod/values.yaml", Content: []byte("replicas: 3\n"), BaseSHA: "blob-values-OLD"},
		},
		Message: "fix",
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict — the non-fast-forward ref update is a concurrent push, and PutFile's own blob-SHA conflict maps to the same sentinel", err)
	}
	if refUpdateCalls != 1 {
		t.Errorf("ref update called %d times, want exactly 1 (no retry-by-force)", refUpdateCalls)
	}
}

func TestPutFilesValidatesInput(t *testing.T) {
	repo := Repo{Owner: "a", Name: "b"}
	gh, _ := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no network call should be made for invalid input: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(500)
	})
	cases := []struct {
		name string
		in   PutFilesInput
	}{
		{"no branch", PutFilesInput{BaseCommitSHA: "x", Files: []FileCommit{{Path: "a", Content: []byte("x")}}}},
		{"no base commit", PutFilesInput{Branch: "b", Files: []FileCommit{{Path: "a", Content: []byte("x")}}}},
		{"no files", PutFilesInput{Branch: "b", BaseCommitSHA: "x"}},
		{"a file with no path", PutFilesInput{Branch: "b", BaseCommitSHA: "x", Files: []FileCommit{{Content: []byte("x")}}}},
		{"a file with empty content", PutFilesInput{Branch: "b", BaseCommitSHA: "x", Files: []FileCommit{{Path: "a"}}}},
		{"the same path twice", PutFilesInput{Branch: "b", BaseCommitSHA: "x", Files: []FileCommit{{Path: "a", Content: []byte("x")}, {Path: "a", Content: []byte("y")}}}},
		{"a delete with no blob SHA", PutFilesInput{Branch: "b", BaseCommitSHA: "x", Files: []FileCommit{{Path: "a", Delete: true}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := gh.PutFiles(context.Background(), repo, tc.in); err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
}

// TestIsAncestor covers BUGS.md 81's fix: whether a GitOps controller's
// reported revision has the merge commit somewhere in its history, not just
// whether it equals it exactly.
func TestIsAncestor(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  string
		want    bool
		wantErr bool
	}{
		// The controller synced to something strictly newer than the merge
		// commit — another PR merged before the next sync (BUGS.md 81's own
		// scenario) — and "ahead" is GitHub's word for "head has everything
		// base has, plus more".
		{name: "ahead — a later commit contains the merge commit", status: "ahead", want: true},
		{name: "identical — synced to the merge commit exactly", status: "identical", want: true},
		{name: "behind — genuinely not synced yet", status: "behind", want: false},
		{name: "diverged — unrelated history, not a descendant", status: "diverged", want: false},
		{name: "unrecognized status — fail loud, not silently false", status: "sideways", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gh, fake := newFake(t, func(w http.ResponseWriter, r *http.Request) {
				jsonResp(w, 200, map[string]any{"status": tc.status})
			})
			got, err := gh.IsAncestor(context.Background(), Repo{Owner: "acme", Name: "platform-config"}, "deadbeef", "c0ffee")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("IsAncestor with provider status %q: want an error, got got=%v", tc.status, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("IsAncestor: %v", err)
			}
			if got != tc.want {
				t.Errorf("IsAncestor with provider status %q = %v, want %v", tc.status, got, tc.want)
			}
			wantReq := "GET /repos/acme/platform-config/compare/deadbeef...c0ffee"
			if len(fake.requests) != 1 || fake.requests[0] != wantReq {
				t.Errorf("requests = %v, want exactly [%q]", fake.requests, wantReq)
			}
		})
	}

	// An unreachable provider (or an unknown SHA, which 404s) must surface as
	// a real error, never as a silent false — BUGS.md 81's fail-open-to-retry
	// constraint: "I could not check" and "checked and it's not there" must
	// stay distinguishable all the way up to MergeSweeper.
	t.Run("provider error propagates, is not swallowed into false", func(t *testing.T) {
		gh, _ := newFake(t, func(w http.ResponseWriter, r *http.Request) {
			jsonResp(w, 404, map[string]any{"message": "Not Found"})
		})
		if _, err := gh.IsAncestor(context.Background(), Repo{Owner: "acme", Name: "platform-config"}, "deadbeef", "unknown-sha"); !errors.Is(err, ErrNotFound) {
			t.Errorf("IsAncestor on an unknown SHA = %v, want ErrNotFound", err)
		}
	})
}
