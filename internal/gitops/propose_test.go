package gitops

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

	"argus/internal/redact"
	"argus/internal/scm"
)

// The repository these tests propose against, deliberately holding all three
// shapes the old single-field grammar could not express:
//
//   - a plain-YAML manifest (the only thing that used to work),
//   - a Helm chart TEMPLATE, full of {{ }} — refused outright before 2026-08-28,
//   - a values file feeding it.
//
// Every test below is about the multi-file, whole-content contract or about one
// of the boundaries that survived the removal of the field grammar.
const (
	manifestPath = "envs/prod/checkout-worker.yaml"
	valuesPath   = "envs/prod/values.yaml"
	templatePath = "envs/prod/templates/deployment.yaml"
	newFilePath  = "envs/prod/pdb.yaml"

	syncedSHA     = "1111111111111111111111111111111111111111"
	baseHeadSHA   = "2222222222222222222222222222222222222222"
	incidentID    = "inc_01J000000000000000000000"
	approverEmail = "alice@example.com"
)

const proposeManifest = `# Managed by the platform team.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: checkout-worker
  namespace: shop
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: checkout-worker
          image: registry.example.com/shop/checkout:1.20.3
          readinessProbe:
            httpGet:
              port: 9999      # wrong: the container listens on 80
`

const proposeValues = `replicaCount: 2
resources:
  limits:
    memory: 128Mi
`

// A real chart template: not valid YAML on its own, and the exact shape
// PlainYAMLRefusal used to refuse by name.
const proposeTemplate = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "chart.fullname" . }}
spec:
  replicas: {{ .Values.replicaCount }}
  template:
    spec:
      containers:
        - name: app
          resources:
            limits:
              memory: {{ .Values.resources.limits.memory }}
`

type fakeGit struct {
	t     *testing.T
	files map[string]string

	requests []string
	readRefs map[string]string
	puts     []map[string]any
	prBody   map[string]any

	putStatusFor map[string]int
	prStatus     int
	labelStatus  int

	// deletes is every DELETE the Contents API single-file path received —
	// BACKLOG.md "still open" #2.
	deletes []map[string]any

	// --- the atomic (trees-API) path, BACKLOG.md F24 ---

	// currentBranchBlob overrides the blob SHA the git/trees listing reports
	// for a path, independent of what f.files/blobSHAFor would say — this is
	// what lets a test simulate "this file moved on the branch since it was
	// read at the synced commit" without also changing what the Contents API
	// read returns (those are two different reads in the real API: one
	// pinned to the synced commit, one against the branch's current head).
	currentBranchBlob map[string]string
	// treeTruncated forces the git/trees listing to report truncated:true.
	treeTruncated bool
	// refStatusFor forces the ref-update PATCH for a branch to fail with the
	// given status and a GitHub-shaped "not a fast forward" message —
	// simulating a concurrent push landing between the atomic path's
	// precheck and its ref update.
	refStatusFor map[string]int

	blobs         []map[string]any
	postedTrees   []map[string]any
	postedCommits []map[string]any
	refUpdates    []map[string]any
}

func newFakeGit(t *testing.T) *fakeGit {
	return &fakeGit{
		t: t,
		files: map[string]string{
			manifestPath: proposeManifest,
			valuesPath:   proposeValues,
			templatePath: proposeTemplate,
		},
		readRefs:          map[string]string{},
		putStatusFor:      map[string]int{},
		currentBranchBlob: map[string]string{},
		refStatusFor:      map[string]int{},
	}
}

func blobSHAFor(path string) string { return "blob-" + strings.ReplaceAll(path, "/", "-") }

func (f *fakeGit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	p := r.URL.Path
	const contents = "/repos/acme/config/contents/"

	switch {
	case r.Method == "GET" && p == "/repos/acme/config":
		writeJSONResp(w, 200, map[string]any{"default_branch": "main"})

	case r.Method == "GET" && p == "/repos/acme/config/commits/main":
		writeJSONResp(w, 200, map[string]any{"sha": baseHeadSHA})

	case r.Method == "GET" && strings.HasPrefix(p, contents):
		path := strings.TrimPrefix(p, contents)
		content, ok := f.files[path]
		if !ok {
			writeJSONResp(w, 404, map[string]any{"message": "Not Found"})
			return
		}
		f.readRefs[path] = r.URL.Query().Get("ref")
		writeJSONResp(w, 200, map[string]any{
			"type": "file", "encoding": "base64", "sha": blobSHAFor(path),
			"content": base64.StdEncoding.EncodeToString([]byte(content)),
		})

	case r.Method == "POST" && p == "/repos/acme/config/git/refs":
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		writeJSONResp(w, 201, map[string]any{})

	case r.Method == "PUT" && strings.HasPrefix(p, contents):
		path := strings.TrimPrefix(p, contents)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		body["_path"] = path
		f.puts = append(f.puts, body)
		if status := f.putStatusFor[path]; status != 0 {
			writeJSONResp(w, status, map[string]any{"message": "is at aaaa but expected bbbb"})
			return
		}
		writeJSONResp(w, 200, map[string]any{"commit": map[string]any{"sha": "commit-" + fmt.Sprint(len(f.puts))}})

	case r.Method == "DELETE" && strings.HasPrefix(p, contents):
		path := strings.TrimPrefix(p, contents)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		body["_path"] = path
		f.deletes = append(f.deletes, body)
		delete(f.files, path)
		if status := f.putStatusFor[path]; status != 0 {
			writeJSONResp(w, status, map[string]any{"message": "is at aaaa but expected bbbb"})
			return
		}
		writeJSONResp(w, 200, map[string]any{"commit": map[string]any{"sha": "commit-delete-" + fmt.Sprint(len(f.deletes))}})

	case r.Method == "POST" && p == "/repos/acme/config/pulls":
		_ = json.NewDecoder(r.Body).Decode(&f.prBody)
		if f.prStatus != 0 {
			writeJSONResp(w, f.prStatus, map[string]any{"message": "no"})
			return
		}
		writeJSONResp(w, 201, map[string]any{"number": 7, "html_url": "https://github.example/acme/config/pull/7"})

	case r.Method == "POST" && p == "/repos/acme/config/issues/7/labels":
		if f.labelStatus != 0 {
			writeJSONResp(w, f.labelStatus, map[string]any{"message": "no label for you"})
			return
		}
		writeJSONResp(w, 200, []any{})

	// --- the atomic (trees-API) path, BACKLOG.md F24 ---

	case r.Method == "GET" && strings.HasPrefix(p, "/repos/acme/config/git/commits/"):
		sha := strings.TrimPrefix(p, "/repos/acme/config/git/commits/")
		writeJSONResp(w, 200, map[string]any{"sha": sha, "tree": map[string]any{"sha": "tree-" + sha}})

	case r.Method == "GET" && strings.HasPrefix(p, "/repos/acme/config/git/trees/"):
		entries := make([]map[string]any, 0, len(f.files))
		for path := range f.files {
			sha := blobSHAFor(path)
			if override, ok := f.currentBranchBlob[path]; ok {
				sha = override
			}
			entries = append(entries, map[string]any{"path": path, "sha": sha, "type": "blob"})
		}
		writeJSONResp(w, 200, map[string]any{"tree": entries, "truncated": f.treeTruncated})

	case r.Method == "POST" && p == "/repos/acme/config/git/blobs":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.blobs = append(f.blobs, body)
		writeJSONResp(w, 201, map[string]any{"sha": fmt.Sprintf("newblob-%d", len(f.blobs))})

	case r.Method == "POST" && p == "/repos/acme/config/git/trees":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.postedTrees = append(f.postedTrees, body)
		writeJSONResp(w, 201, map[string]any{"sha": fmt.Sprintf("newtree-%d", len(f.postedTrees))})

	case r.Method == "POST" && p == "/repos/acme/config/git/commits":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.postedCommits = append(f.postedCommits, body)
		writeJSONResp(w, 201, map[string]any{"sha": fmt.Sprintf("atomic-commit-%d", len(f.postedCommits))})

	case r.Method == "PATCH" && strings.HasPrefix(p, "/repos/acme/config/git/refs/heads/"):
		branch := strings.TrimPrefix(p, "/repos/acme/config/git/refs/heads/")
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.refUpdates = append(f.refUpdates, body)
		if status := f.refStatusFor[branch]; status != 0 {
			writeJSONResp(w, status, map[string]any{"message": "Update is not a fast forward"})
			return
		}
		writeJSONResp(w, 200, map[string]any{})

	default:
		f.t.Errorf("unexpected call: %s %s", r.Method, p)
		w.WriteHeader(500)
	}
}

func writeJSONResp(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func newProvider(t *testing.T) (*scm.GitHub, *fakeGit) {
	t.Helper()
	f := newFakeGit(t)
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return &scm.GitHub{BaseURL: srv.URL, Token: "test-token", HTTPClient: srv.Client(), UserAgent: "argus"}, f
}

func previewRepo() scm.Repo { return scm.Repo{Owner: "acme", Name: "config"} }

func baseInput(files ...FileEdit) ProposalInput {
	return ProposalInput{
		Object: ObjectRef{
			APIVersion: "apps/v1", Kind: "Deployment",
			Namespace: "shop", Name: "checkout-worker",
		},
		Files:          files,
		SyncedRevision: syncedSHA,
		SourceDir:      "envs/prod",
		Branch:         "argus/fix-" + incidentID,
		ForbiddenPaths: []string{"envs/prod/frozen-*.yaml"},
		Provenance: Provenance{
			IncidentID:   incidentID,
			ApprovedBy:   approverEmail,
			ClusterID:    "cl_abc",
			RootCause:    "The readiness probe targets port 9999; the container listens on 80.",
			ResolvedFrom: "argoproj.io/Application argocd/shop .status.sync.revision",
			Author:       scm.Identity{Name: "ARGUS", Email: "argus@localhost"},
		},
	}
}

func fixedManifest() []byte {
	return []byte(strings.Replace(proposeManifest, "port: 9999", "port: 80", 1))
}

func fixedValues() []byte {
	return []byte(strings.Replace(proposeValues, "memory: 128Mi", "memory: 512Mi", 1))
}

func fixedTemplate() []byte {
	return []byte(strings.Replace(proposeTemplate, "replicas: {{ .Values.replicaCount }}", "replicas: {{ .Values.replicaCount | default 2 }}", 1))
}

// --- the multi-file contract ------------------------------------------------

// TestProposeChanges_MultipleFilesInOnePullRequest is the headline contract:
// three files — a plain manifest, a TEMPLATED chart file, and a brand new file
// — go out as one pull request, all read at the pinned synced commit.
//
// Since 2026-08-28's F24 fix, more than one changed file against a real
// GitHub provider takes the atomic trees-API path (scm.AtomicCommitter): one
// commit, not three sequential PUTs. See
// TestProposeChanges_FallsBackToSequentialPutFileWithoutAtomicCommitter for
// the regression guard proving the OLD per-file path is unchanged for a
// provider that cannot do this (GitLab, in production).
//
// The templated file is the whole point of the 2026-08-28 rewrite. Before
// that, ErrNeedsRendering refused it outright and no pull request could touch
// a Helm chart at all.
func TestProposeChanges_MultipleFilesInOnePullRequest(t *testing.T) {
	provider, fake := newProvider(t)

	in := baseInput(
		FileEdit{Path: manifestPath, Content: fixedManifest()},
		FileEdit{Path: templatePath, Content: fixedTemplate()},
		FileEdit{Path: newFilePath, Content: []byte("apiVersion: policy/v1\nkind: PodDisruptionBudget\nmetadata:\n  name: checkout\n")},
	)
	proposal, err := ProposeChanges(t.Context(), provider, previewRepo(), in)
	if err != nil {
		t.Fatalf("ProposeChanges: %v", err)
	}

	if proposal.PullRequest.Number != 7 {
		t.Fatalf("PullRequest.Number = %d, want 7", proposal.PullRequest.Number)
	}
	if got := proposal.Verification.FilesChanged; got != 3 {
		t.Errorf("FilesChanged = %d, want 3", got)
	}
	// The atomic path is ONE commit for all three files, not one per file.
	if len(proposal.Commits) != 1 {
		t.Fatalf("Commits = %v, want exactly one atomic commit for all 3 files", proposal.Commits)
	}
	if proposal.CommitSHA != proposal.Commits[0] {
		t.Errorf("CommitSHA = %q, want the atomic commit %q", proposal.CommitSHA, proposal.Commits[0])
	}
	// No per-file PUT to the contents API happened at all.
	if len(fake.puts) != 0 {
		t.Errorf("used the per-file PUT path (%d calls), want the atomic trees-API path for 3 changed files: %v", len(fake.puts), fake.puts)
	}

	// Every read was pinned to the SYNCED commit, never to the branch head.
	for _, p := range []string{manifestPath, templatePath} {
		if fake.readRefs[p] != syncedSHA {
			t.Errorf("%s was read at ref %q, want the synced commit %q", p, fake.readRefs[p], syncedSHA)
		}
	}

	// One blob per changed file, one tree, one commit, one ref update.
	if len(fake.blobs) != 3 {
		t.Fatalf("created %d blobs, want one per changed file", len(fake.blobs))
	}
	if len(fake.postedTrees) != 1 || len(fake.postedCommits) != 1 || len(fake.refUpdates) != 1 {
		t.Fatalf("trees=%d commits=%d refUpdates=%d, want exactly one of each", len(fake.postedTrees), len(fake.postedCommits), len(fake.refUpdates))
	}
	entries, _ := fake.postedTrees[0]["tree"].([]any)
	if len(entries) != 3 {
		t.Errorf("tree has %d entries, want exactly the 3 changed files", len(entries))
	}
	if force, _ := fake.refUpdates[0]["force"].(bool); force {
		t.Error("ref update set force:true — that would silently overwrite a concurrent push")
	}
	msg, _ := fake.postedCommits[0]["message"].(string)
	if !strings.Contains(msg, "3 file(s)") {
		t.Errorf("atomic commit message does not summarize the file count: %q", msg)
	}

	// The templated file produced an ADVISORY rather than a refusal, and it is
	// in the pull-request body where a reviewer sees it.
	body, _ := fake.prBody["body"].(string)
	if !strings.Contains(body, templatePath) {
		t.Errorf("pull request body does not mention the templated file:\n%s", body)
	}
	if !strings.Contains(body, "templated") {
		t.Errorf("pull request body does not carry the templated-file advisory:\n%s", body)
	}
	if !strings.Contains(body, "What was NOT checked") {
		t.Errorf("pull request body omits the honest-degradation section:\n%s", body)
	}
	// Three per-file diffs, computed by ARGUS.
	if n := strings.Count(body, "```diff"); n != 3 {
		t.Errorf("pull request body has %d diff blocks, want 3", n)
	}

	// HOW MANY FILES MOVED, asserted on the body rather than the title.
	//
	// This used to assert "3 files" in the TITLE, and that assertion moved
	// rather than being deleted because the fact it guards is still worth
	// guarding — a reviewer must be able to tell a three-file change from a
	// one-file one. What changed is where a reviewer reads it. The title now
	// leads with the root cause (pullRequestTitle has the reasoning: a path
	// told a reviewer scanning a list of pull requests nothing about whether
	// this one was worth opening), and the file count lives in the body's Edit
	// row, which is the first thing under the heading.
	if !strings.Contains(body, "3 file(s)") {
		t.Errorf("pull request body does not say how many files moved:\n%s", body)
	}
	title, _ := fake.prBody["title"].(string)
	if !strings.Contains(title, "readiness probe") {
		t.Errorf("title = %q, want it to lead with WHY — the root cause is the only statement of the point anything recorded", title)
	}
}

func TestProposeChanges_SingleFileChangeNamesTheFileForTheReviewer(t *testing.T) {
	provider, fake := newProvider(t)
	if _, err := ProposeChanges(t.Context(), provider, previewRepo(),
		baseInput(FileEdit{Path: valuesPath, Content: fixedValues()})); err != nil {
		t.Fatalf("ProposeChanges: %v", err)
	}
	// Same move as above: the path is in the body's Files row, and the title is
	// now spent on the point of the change. pullRequestTitle still names the
	// file when there is no root cause to lead with — covered separately by
	// TestPullRequestTitleFallsBackToTheFileWhenNoRootCauseWasRecorded, so the
	// fallback is not left untested by this test changing.
	body, _ := fake.prBody["body"].(string)
	if !strings.Contains(body, valuesPath) {
		t.Errorf("pull request body does not name the one file changed:\n%s", body)
	}
}

// TestPreviewChanges_IsTheComputationTheCommitPerforms guards the property the
// preview exists for: it runs prepareChanges, the identical function
// ProposeChanges runs, and writes nothing.
func TestPreviewChanges_IsTheComputationTheCommitPerforms(t *testing.T) {
	provider, fake := newProvider(t)
	in := baseInput(
		FileEdit{Path: manifestPath, Content: fixedManifest()},
		FileEdit{Path: valuesPath, Content: fixedValues()},
	)
	preview, err := PreviewChanges(t.Context(), provider, previewRepo(), in)
	if err != nil {
		t.Fatalf("PreviewChanges: %v", err)
	}
	if preview.SyncedRevision != syncedSHA {
		t.Errorf("SyncedRevision = %q, want %q", preview.SyncedRevision, syncedSHA)
	}
	if preview.Verification.FilesChanged != 2 {
		t.Errorf("FilesChanged = %d, want 2", preview.Verification.FilesChanged)
	}
	assertNoWrites(t, fake)

	proposal, err := ProposeChanges(t.Context(), provider, previewRepo(), in)
	if err != nil {
		t.Fatalf("ProposeChanges: %v", err)
	}
	for i, f := range proposal.Verification.Files {
		if f.Diff != preview.Verification.Files[i].Diff {
			t.Errorf("%s: the committed diff is not the previewed diff", f.Path)
		}
	}
}

// TestProposeChanges_UnchangedFilesAreReportedNotCommitted is the multi-file
// editor's real flow: an operator opens three files and edits one. The two they
// left alone are reported as unchanged rather than committed as no-op commits
// or used to refuse the whole proposal.
func TestProposeChanges_UnchangedFilesAreReportedNotCommitted(t *testing.T) {
	provider, fake := newProvider(t)
	proposal, err := ProposeChanges(t.Context(), provider, previewRepo(), baseInput(
		FileEdit{Path: manifestPath, Content: fixedManifest()},
		FileEdit{Path: valuesPath, Content: []byte(proposeValues)},
	))
	if err != nil {
		t.Fatalf("ProposeChanges: %v", err)
	}
	if proposal.Verification.FilesChanged != 1 {
		t.Errorf("FilesChanged = %d, want 1", proposal.Verification.FilesChanged)
	}
	if len(fake.puts) != 1 || fake.puts[0]["_path"] != manifestPath {
		t.Errorf("committed %v, want only the file that actually changed", fake.puts)
	}
	var sawUnchanged bool
	for _, c := range proposal.Verification.Checks {
		if strings.Contains(c, valuesPath) && strings.Contains(c, "unchanged") {
			sawUnchanged = true
		}
	}
	if !sawUnchanged {
		t.Errorf("the unchanged file is not reported in the verification: %v", proposal.Verification.Checks)
	}
}

func TestProposeChanges_AllFilesUnchangedIsRefused(t *testing.T) {
	provider, fake := newProvider(t)
	_, err := ProposeChanges(t.Context(), provider, previewRepo(), baseInput(
		FileEdit{Path: manifestPath, Content: []byte(proposeManifest)},
	))
	if !errors.Is(err, ErrNothingToChange) {
		t.Fatalf("err = %v, want ErrNothingToChange", err)
	}
	assertNoWrites(t, fake)
}

// --- the boundaries that must survive ---------------------------------------

// TestProposeChanges_RefusesBeforeTouchingTheNetwork covers the boundaries the
// brief requires to hold unchanged. Each of them is checked BEFORE any read, so
// a forbidden path is refused whether or not it exists.
func TestProposeChanges_RefusesBeforeTouchingTheNetwork(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*ProposalInput)
		wantMsg string
	}{
		{
			name: "a forbidden path — the privilege-escalation denylist",
			mutate: func(in *ProposalInput) {
				in.SourceDir = ""
				in.Files = []FileEdit{{Path: ".github/workflows/deploy.yaml", Content: []byte("on: push\n")}}
			},
			wantMsg: "forbidden path",
		},
		{
			name: "a forbidden path reached inside a multi-file proposal",
			mutate: func(in *ProposalInput) {
				in.SourceDir = ""
				in.Files = []FileEdit{
					{Path: manifestPath, Content: fixedManifest()},
					{Path: "scripts/deploy.sh", Content: []byte("#!/bin/sh\n")},
				}
			},
			wantMsg: "forbidden path",
		},
		{
			name: "Chart.yaml is forbidden even under the synced directory",
			mutate: func(in *ProposalInput) {
				in.Files = []FileEdit{{Path: "envs/prod/Chart.yaml", Content: []byte("name: x\n")}}
			},
			wantMsg: "forbidden path",
		},
		{
			name: "a binding's own extra denylist entry",
			mutate: func(in *ProposalInput) {
				in.Files = []FileEdit{{Path: "envs/prod/frozen-db.yaml", Content: []byte("a: b\n")}}
			},
			wantMsg: "forbidden path",
		},
		{
			name: "a file outside the directory the controller syncs",
			mutate: func(in *ProposalInput) {
				in.Files = []FileEdit{{Path: "envs/staging/checkout-worker.yaml", Content: fixedManifest()}}
			},
			wantMsg: "outside envs/prod",
		},
		{
			name: "path traversal out of the repository",
			mutate: func(in *ProposalInput) {
				in.SourceDir = ""
				in.Files = []FileEdit{{Path: "envs/prod/../../../etc/passwd", Content: []byte("a: b\n")}}
			},
			wantMsg: "must name a path",
		},
		{
			name: "no pinned synced commit",
			mutate: func(in *ProposalInput) {
				in.SyncedRevision = ""
				in.Files = []FileEdit{{Path: manifestPath, Content: fixedManifest()}}
			},
			wantMsg: "moving branch",
		},
		{
			name:    "no files at all",
			mutate:  func(in *ProposalInput) { in.Files = nil },
			wantMsg: "none were given",
		},
		{
			name: "the same file twice",
			mutate: func(in *ProposalInput) {
				in.Files = []FileEdit{
					{Path: manifestPath, Content: fixedManifest()},
					{Path: manifestPath, Content: []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n")},
				}
			},
			wantMsg: "appears twice",
		},
		{
			name: "more files than one pull request may carry",
			mutate: func(in *ProposalInput) {
				in.Files = nil
				for i := 0; i < maxProposedFiles+1; i++ {
					in.Files = append(in.Files, FileEdit{Path: fmt.Sprintf("envs/prod/f%d.yaml", i), Content: []byte("a: b\n")})
				}
			},
			wantMsg: "over the",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			provider, fake := newProvider(t)
			in := baseInput()
			tc.mutate(&in)
			_, err := ProposeChanges(t.Context(), provider, previewRepo(), in)
			if err == nil {
				t.Fatalf("expected a refusal")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("err = %v, want it to mention %q", err, tc.wantMsg)
			}
			assertNoWrites(t, fake)
			// A refusal made before the network means no read either.
			for _, r := range fake.requests {
				if strings.HasPrefix(r, "GET /repos/acme/config/contents/") {
					t.Errorf("read %s despite a pre-network refusal", r)
				}
			}
		})
	}
}

// TestProposeChanges_RefusesContentThatCannotBeReviewed covers the content
// refusals that survived: they are the ones where the proposal could not
// produce a reviewable, appliable file at all.
func TestProposeChanges_RefusesContentThatCannotBeReviewed(t *testing.T) {
	cases := []struct {
		name    string
		file    FileEdit
		wantErr error
		wantMsg string
	}{
		{
			name:    "empty content",
			file:    FileEdit{Path: manifestPath, Content: []byte("   \n")},
			wantErr: ErrVerificationFailed,
			wantMsg: "no content",
		},
		{
			name:    "plain YAML that does not parse",
			file:    FileEdit{Path: manifestPath, Content: []byte("apiVersion: apps/v1\nkind: Deployment\n  bad: [indent\n")},
			wantErr: ErrVerificationFailed,
			wantMsg: "does not parse",
		},
		{
			name:    "content echoing the redaction marker (BUGS.md 112)",
			file:    FileEdit{Path: valuesPath, Content: []byte("replicaCount: 2\nretryLimit: \"" + redact.Marker + "\"\n")},
			wantErr: ErrRedactedValueEchoed,
			wantMsg: "withheld from the model",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			provider, fake := newProvider(t)
			_, err := ProposeChanges(t.Context(), provider, previewRepo(), baseInput(tc.file))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("err = %v, want it to mention %q", err, tc.wantMsg)
			}
			assertNoWrites(t, fake)
		})
	}
}

// TestProposeChanges_TemplatedFileIsAdvisedNotRefused is the single behaviour
// change this rewrite exists for, asserted directly: a chart template — not
// valid YAML, full of {{ }} — is editable, and the fact that ARGUS did not
// parse or render it travels with the change instead of being a refusal.
func TestProposeChanges_TemplatedFileIsAdvisedNotRefused(t *testing.T) {
	provider, _ := newProvider(t)
	preview, err := PreviewChanges(t.Context(), provider, previewRepo(),
		baseInput(FileEdit{Path: templatePath, Content: fixedTemplate()}))
	if err != nil {
		t.Fatalf("PreviewChanges on a chart template: %v", err)
	}
	if len(preview.Verification.Advisories) == 0 {
		t.Fatalf("a templated file produced no advisory: %+v", preview.Verification)
	}
	if !strings.Contains(strings.Join(preview.Verification.Advisories, " "), "templated") {
		t.Errorf("advisories = %v, want one naming the file as templated", preview.Verification.Advisories)
	}
	if preview.Verification.Files[0].Parsed {
		t.Errorf("a chart template must not be reported as parsed")
	}
}

// TestProposeChanges_ObjectIdentityIsAdvisoryNotARefusal is the demotion the
// brief asks for. A whole-file edit that stops declaring the incident's object
// is a thing a reviewer must check, not a thing ARGUS refuses — and it is
// meaningless for a values file, which never declared one.
func TestProposeChanges_ObjectIdentityIsAdvisoryNotARefusal(t *testing.T) {
	provider, _ := newProvider(t)
	swapped := strings.Replace(proposeManifest, "name: checkout-worker\n  namespace: shop", "name: something-else\n  namespace: shop", 1)
	preview, err := PreviewChanges(t.Context(), provider, previewRepo(),
		baseInput(FileEdit{Path: manifestPath, Content: []byte(swapped)}))
	if err != nil {
		t.Fatalf("PreviewChanges: %v", err)
	}
	joined := strings.Join(preview.Verification.Advisories, " ")
	if !strings.Contains(joined, "no longer") {
		t.Errorf("advisories = %v, want one saying the file no longer declares the object", preview.Verification.Advisories)
	}

	// And the values file, which never declared the object, gets no such note.
	valuesPreview, err := PreviewChanges(t.Context(), provider, previewRepo(),
		baseInput(FileEdit{Path: valuesPath, Content: fixedValues()}))
	if err != nil {
		t.Fatalf("PreviewChanges(values): %v", err)
	}
	if strings.Contains(strings.Join(valuesPreview.Verification.Advisories, " "), "no longer declares") {
		t.Errorf("a values file must not be judged on declaring a Kubernetes object: %v", valuesPreview.Verification.Advisories)
	}
}

// TestProposeChanges_AtomicConflictOpensNoPullRequestAndCommitsNothing is
// BACKLOG.md F24's headline property, checked at the gitops caller rather
// than just inside scm/github_test.go: with two files changed, a real GitHub
// provider takes the atomic path, and a file that moved on the branch since
// it was read at the synced commit must be caught as a conflict with NO
// commits at all — not "1 of 2", zero — and no pull request opened.
func TestProposeChanges_AtomicConflictOpensNoPullRequestAndCommitsNothing(t *testing.T) {
	provider, fake := newProvider(t)
	// The values file's blob on the branch is not what was read at the synced
	// commit — someone else pushed to this path in between.
	fake.currentBranchBlob[valuesPath] = "blob-values-moved-since-read"

	_, err := ProposeChanges(t.Context(), provider, previewRepo(), baseInput(
		FileEdit{Path: manifestPath, Content: fixedManifest()},
		FileEdit{Path: valuesPath, Content: fixedValues()},
	))
	if !errors.Is(err, scm.ErrConflict) {
		t.Fatalf("err = %v, want scm.ErrConflict", err)
	}
	if !strings.Contains(err.Error(), "moved") {
		t.Errorf("err = %v, want it to say the branch moved", err)
	}
	// The property this fix exists for: NOTHING landed, not "the first file
	// did". No blob, no tree, no commit and no ref update were ever created —
	// the precheck aborts before any of them.
	if len(fake.blobs) != 0 || len(fake.postedTrees) != 0 || len(fake.postedCommits) != 0 || len(fake.refUpdates) != 0 {
		t.Errorf("a write happened despite the precheck detecting a conflict: blobs=%d trees=%d commits=%d refUpdates=%d",
			len(fake.blobs), len(fake.postedTrees), len(fake.postedCommits), len(fake.refUpdates))
	}
	for _, r := range fake.requests {
		if strings.HasSuffix(r, "/pulls") {
			t.Errorf("a pull request was opened despite a conflict")
		}
	}
}

// TestProposeChanges_AtomicRefUpdateConflict covers the OTHER conflict
// window in the atomic path: the branch moves in the narrow gap between the
// precheck and the final ref update (a push landing mid-flight). GitHub's
// fast-forward-only ref update catches this — see scm's own
// TestPutFilesRefUpdateConflictLeavesNothingLanded for the provider-level
// proof; this asserts the gitops caller surfaces it the same way and opens no
// pull request.
func TestProposeChanges_AtomicRefUpdateConflict(t *testing.T) {
	provider, fake := newProvider(t)
	fake.refStatusFor["argus/fix-"+incidentID] = http.StatusUnprocessableEntity

	_, err := ProposeChanges(t.Context(), provider, previewRepo(), baseInput(
		FileEdit{Path: manifestPath, Content: fixedManifest()},
		FileEdit{Path: valuesPath, Content: fixedValues()},
	))
	if !errors.Is(err, scm.ErrConflict) {
		t.Fatalf("err = %v, want scm.ErrConflict", err)
	}
	for _, r := range fake.requests {
		if strings.HasSuffix(r, "/pulls") {
			t.Errorf("a pull request was opened despite the ref update failing")
		}
	}
}

// --- the fallback for a provider that cannot commit atomically -------------

// sequentialOnlyProvider wraps a real *scm.GitHub through scm.Provider and
// scm.UpdatableFileReader ONLY — deliberately not embedding it directly,
// which would promote PutFiles and make the wrapper satisfy
// scm.AtomicCommitter too. This reproduces, in this package's own test
// fixture, the exact shape a GitLab-backed binding has in production (see
// scm.TestGitLabIsNotAnAtomicCommitter), without standing up GitLab's
// different HTTP surface — so ProposeChanges's fallback branch gets exercised
// against the same fakeGit server the atomic-path tests use.
type sequentialOnlyProvider struct{ inner *scm.GitHub }

func (s sequentialOnlyProvider) Name() string { return s.inner.Name() }
func (s sequentialOnlyProvider) ReadFile(ctx context.Context, repo scm.Repo, ref, path string) ([]byte, error) {
	return s.inner.ReadFile(ctx, repo, ref, path)
}
func (s sequentialOnlyProvider) DefaultBranch(ctx context.Context, repo scm.Repo) (string, error) {
	return s.inner.DefaultBranch(ctx, repo)
}
func (s sequentialOnlyProvider) CreateBranch(ctx context.Context, repo scm.Repo, branch, fromSHA string) error {
	return s.inner.CreateBranch(ctx, repo, branch, fromSHA)
}
func (s sequentialOnlyProvider) ResolveRef(ctx context.Context, repo scm.Repo, ref string) (string, error) {
	return s.inner.ResolveRef(ctx, repo, ref)
}
func (s sequentialOnlyProvider) PutFile(ctx context.Context, repo scm.Repo, in scm.PutFileInput) (string, error) {
	return s.inner.PutFile(ctx, repo, in)
}
func (s sequentialOnlyProvider) DeleteFile(ctx context.Context, repo scm.Repo, in scm.DeleteFileInput) (string, error) {
	return s.inner.DeleteFile(ctx, repo, in)
}
func (s sequentialOnlyProvider) OpenPullRequest(ctx context.Context, repo scm.Repo, in scm.PullRequestInput) (scm.PullRequest, error) {
	return s.inner.OpenPullRequest(ctx, repo, in)
}
func (s sequentialOnlyProvider) PullRequestStatus(ctx context.Context, repo scm.Repo, number int) (scm.PullRequestStatus, error) {
	return s.inner.PullRequestStatus(ctx, repo, number)
}
func (s sequentialOnlyProvider) IsAncestor(ctx context.Context, repo scm.Repo, ancestor, ref string) (bool, error) {
	return s.inner.IsAncestor(ctx, repo, ancestor, ref)
}
func (s sequentialOnlyProvider) ReadFileForUpdate(ctx context.Context, repo scm.Repo, ref, path string) ([]byte, string, error) {
	return s.inner.ReadFileForUpdate(ctx, repo, ref, path)
}

var (
	_ scm.Provider            = sequentialOnlyProvider{}
	_ scm.UpdatableFileReader = sequentialOnlyProvider{}
)

func TestSequentialOnlyProviderDoesNotSatisfyAtomicCommitter(t *testing.T) {
	var p scm.Provider = sequentialOnlyProvider{}
	if _, ok := p.(scm.AtomicCommitter); ok {
		t.Fatal("this test fixture must not satisfy scm.AtomicCommitter — the whole point is to exercise ProposeChanges's fallback branch")
	}
}

// TestProposeChanges_FallsBackToSequentialPutFileWithoutAtomicCommitter is
// BACKLOG.md F24's regression guard (c): a provider that does not implement
// scm.AtomicCommitter — GitLab, in production — must still commit N files as
// N sequential PutFile calls, unchanged from before this fix.
func TestProposeChanges_FallsBackToSequentialPutFileWithoutAtomicCommitter(t *testing.T) {
	inner, fake := newProvider(t)
	provider := sequentialOnlyProvider{inner: inner}

	in := baseInput(
		FileEdit{Path: manifestPath, Content: fixedManifest()},
		FileEdit{Path: valuesPath, Content: fixedValues()},
	)
	proposal, err := ProposeChanges(t.Context(), provider, previewRepo(), in)
	if err != nil {
		t.Fatalf("ProposeChanges: %v", err)
	}
	if len(proposal.Commits) != 2 {
		t.Fatalf("Commits = %v, want one PutFile commit per file (no AtomicCommitter available)", proposal.Commits)
	}
	if len(fake.puts) != 2 {
		t.Fatalf("got %d PUTs, want 2 — the atomic trees-API path must not be used", len(fake.puts))
	}
	// None of the atomic-path endpoints were ever touched.
	if len(fake.blobs) != 0 || len(fake.postedTrees) != 0 || len(fake.postedCommits) != 0 || len(fake.refUpdates) != 0 {
		t.Errorf("the atomic path was used despite the provider not implementing AtomicCommitter: blobs=%d trees=%d commits=%d refUpdates=%d",
			len(fake.blobs), len(fake.postedTrees), len(fake.postedCommits), len(fake.refUpdates))
	}
}

// TestProposeChanges_SequentialProviderDeletesAndWritesBothViaContentsAPI is
// BACKLOG.md "still open" #2 for a provider with NO atomic trees API —
// GitLab, in production, reproduced here via sequentialOnlyProvider exactly
// like TestProposeChanges_FallsBackToSequentialPutFileWithoutAtomicCommitter.
// A delete and a write to different files each take their own sequential
// Contents-API call (DELETE, PUT) rather than one atomic commit — still two
// real compare-and-swaps, still safe, just not atomic, unchanged from what
// F24 already documented for this provider shape.
func TestProposeChanges_SequentialProviderDeletesAndWritesBothViaContentsAPI(t *testing.T) {
	inner, fake := newProvider(t)
	provider := sequentialOnlyProvider{inner: inner}

	proposal, err := ProposeChanges(t.Context(), provider, previewRepo(), baseInput(
		FileEdit{Path: manifestPath, Content: fixedManifest()},
		FileEdit{Path: valuesPath, Delete: true},
	))
	if err != nil {
		t.Fatalf("ProposeChanges: %v", err)
	}
	if len(proposal.Commits) != 2 {
		t.Fatalf("Commits = %v, want one commit per file (no AtomicCommitter available)", proposal.Commits)
	}
	if len(fake.puts) != 1 {
		t.Errorf("got %d PUTs, want exactly 1 (the write)", len(fake.puts))
	}
	if len(fake.deletes) != 1 {
		t.Errorf("got %d DELETEs, want exactly 1 (the delete)", len(fake.deletes))
	}
	if len(fake.blobs) != 0 || len(fake.postedTrees) != 0 {
		t.Errorf("the atomic trees-API path was used despite the provider not implementing AtomicCommitter: blobs=%d trees=%d", len(fake.blobs), len(fake.postedTrees))
	}
}

// TestProposeChanges_FallbackConflictStillFailsSafe is the sequential path's
// OWN conflict behaviour, unchanged: a file that moved between the synced
// commit and the branch leaves the files before it committed, opens no pull
// request, and says so — exactly what BACKLOG.md F24 describes as "fails
// safe... but leaves litter". This guards that the fix for GitHub did not
// accidentally change GitLab's (and any non-atomic provider's) behaviour.
func TestProposeChanges_FallbackConflictStillFailsSafe(t *testing.T) {
	inner, fake := newProvider(t)
	provider := sequentialOnlyProvider{inner: inner}
	fake.putStatusFor[valuesPath] = http.StatusConflict

	_, err := ProposeChanges(t.Context(), provider, previewRepo(), baseInput(
		FileEdit{Path: manifestPath, Content: fixedManifest()},
		FileEdit{Path: valuesPath, Content: fixedValues()},
	))
	if err == nil {
		t.Fatal("expected a conflict")
	}
	if !strings.Contains(err.Error(), "1 of 2 file(s) were already committed") {
		t.Errorf("err = %v, want it to name the partially-committed branch", err)
	}
	for _, r := range fake.requests {
		if strings.HasSuffix(r, "/pulls") {
			t.Errorf("a pull request was opened despite a conflict")
		}
	}
}

// TestProposeChanges_LabelFailureIsReportedNotFatal: the PR exists, so the
// caller must be told it exists — with the missing label surfaced, because the
// label is how §11.4's table says which verification was performed.
func TestProposeChanges_LabelFailureIsReportedNotFatal(t *testing.T) {
	provider, fake := newProvider(t)
	fake.labelStatus = http.StatusForbidden

	proposal, err := ProposeChanges(t.Context(), provider, previewRepo(),
		baseInput(FileEdit{Path: manifestPath, Content: fixedManifest()}))
	if err != nil {
		t.Fatalf("a labelling failure must not fail the proposal: %v", err)
	}
	if proposal.PullRequest.Number != 7 {
		t.Fatalf("PullRequest.Number = %d, want the opened PR", proposal.PullRequest.Number)
	}
	if proposal.LabelWarning == "" {
		t.Error("LabelWarning is empty; a PR that could not be labelled makes a weaker claim than the reviewer will assume")
	}
}

// TestProposeChanges_CommitTrailersNameTheHumanAndTheIncident guards the
// provenance chain: the machine account authors, the approving human is named
// in a trailer, and the verification label is greppable in git history.
func TestProposeChanges_CommitTrailersNameTheHumanAndTheIncident(t *testing.T) {
	provider, fake := newProvider(t)
	if _, err := ProposeChanges(t.Context(), provider, previewRepo(),
		baseInput(FileEdit{Path: manifestPath, Content: fixedManifest()})); err != nil {
		t.Fatalf("ProposeChanges: %v", err)
	}
	message, _ := fake.puts[0]["message"].(string)
	for _, want := range []string{
		"Approved-by: " + approverEmail,
		"Argus-Incident: " + incidentID,
		"Argus-Verified: " + LabelVerifiedLocally,
		"Argus-Edit: 1 file(s)",
	} {
		if !strings.Contains(message, want) {
			t.Errorf("commit message is missing %q:\n%s", want, message)
		}
	}
	committer, _ := fake.puts[0]["committer"].(map[string]any)
	if committer["email"] != "argus@localhost" {
		t.Errorf("committer = %v, want ARGUS's own machine identity rather than the approver's", committer)
	}
}

// --- BACKLOG.md F26: render evidence in the pull request --------------------

// TestProposeChanges_NoRenderEvidence_SaysNotAttempted is the regression
// guard for "never gate, never claim a check that didn't run": a proposal
// with no RenderEvidence (today's status quo, and every existing test above
// this one) must still open cleanly and say plainly that rendering was not
// attempted, never silently omit the section or imply a check happened.
func TestProposeChanges_NoRenderEvidence_SaysNotAttempted(t *testing.T) {
	provider, fake := newProvider(t)
	in := baseInput(FileEdit{Path: manifestPath, Content: fixedManifest()})
	in.RenderEvidence = nil
	if _, err := ProposeChanges(t.Context(), provider, previewRepo(), in); err != nil {
		t.Fatalf("ProposeChanges: %v", err)
	}
	body, _ := fake.prBody["body"].(string)
	if !strings.Contains(body, "## Rendered delta") {
		t.Fatalf("pull request body is missing the Rendered delta section:\n%s", body)
	}
	if !strings.Contains(body, "Not attempted") {
		t.Fatalf("with no RenderEvidence, the body must say rendering was not attempted:\n%s", body)
	}
	if strings.Contains(body, "Effective change confirmed") || strings.Contains(body, "No effective change") {
		t.Fatalf("body must not claim a render result that never happened:\n%s", body)
	}
}

// TestProposeChanges_RenderEvidence_NoEffectiveChange is the
// values-file-precedence case this item exists for: a real edit, correctly
// reported as changing nothing a cluster would run, must be labelled loudly
// enough that a reviewer does not merge it expecting an effect.
func TestProposeChanges_RenderEvidence_NoEffectiveChange(t *testing.T) {
	provider, fake := newProvider(t)
	in := baseInput(FileEdit{Path: manifestPath, Content: fixedManifest()})
	in.RenderEvidence = &RenderEvidence{
		Attempted:       true,
		RendererKind:    "helm",
		Effective:       false,
		ObjectsCompared: 3,
		Summary:         "rendered 3 object(s) from both the original and proposed content and found them identical — this edit does not change what the cluster would run",
	}
	if _, err := ProposeChanges(t.Context(), provider, previewRepo(), in); err != nil {
		t.Fatalf("ProposeChanges: %v", err)
	}
	body, _ := fake.prBody["body"].(string)
	if !strings.Contains(body, "No effective change") {
		t.Fatalf("body must say plainly that the render found no effective change:\n%s", body)
	}
	if !strings.Contains(body, "Verify this is intentional before merging") {
		t.Fatalf("a no-effective-change render must warn the reviewer explicitly:\n%s", body)
	}
	message, _ := fake.puts[0]["message"].(string)
	if !strings.Contains(message, "Argus-Render: no-effective-change") {
		t.Errorf("commit trailer is missing the render outcome:\n%s", message)
	}
}

// TestProposeChanges_RenderEvidence_EffectiveChange is the contrast case:
// a genuine change must name the objects it affects.
func TestProposeChanges_RenderEvidence_EffectiveChange(t *testing.T) {
	provider, fake := newProvider(t)
	in := baseInput(FileEdit{Path: manifestPath, Content: fixedManifest()})
	in.RenderEvidence = &RenderEvidence{
		Attempted:       true,
		RendererKind:    "helm",
		Effective:       true,
		ObjectsCompared: 3,
		ObjectsChanged:  []string{"apps/v1/Deployment shop/checkout-worker"},
		Summary:         "rendered 3 object(s) and found 1 differ between the original and proposed content — this edit changes what the cluster would run",
	}
	if _, err := ProposeChanges(t.Context(), provider, previewRepo(), in); err != nil {
		t.Fatalf("ProposeChanges: %v", err)
	}
	body, _ := fake.prBody["body"].(string)
	if !strings.Contains(body, "Effective change confirmed") {
		t.Fatalf("body must confirm the effective change:\n%s", body)
	}
	if !strings.Contains(body, "apps/v1/Deployment shop/checkout-worker") {
		t.Fatalf("body must name the changed object:\n%s", body)
	}
	message, _ := fake.puts[0]["message"].(string)
	if !strings.Contains(message, "Argus-Render: effective") {
		t.Errorf("commit trailer is missing the effective render outcome:\n%s", message)
	}
}

// TestProposeChanges_RenderEvidence_Degraded proves a render that was
// attempted but inconclusive (sandbox unreachable, timeout, renderer error)
// degrades to the SAME honest posture as never having attempted it — never
// blocks the pull request, and never claims a definite answer it doesn't
// have.
func TestProposeChanges_RenderEvidence_Degraded(t *testing.T) {
	provider, fake := newProvider(t)
	in := baseInput(FileEdit{Path: manifestPath, Content: fixedManifest()})
	in.RenderEvidence = &RenderEvidence{Attempted: true, Degraded: "render sandbox timed out after 2m0s"}
	if _, err := ProposeChanges(t.Context(), provider, previewRepo(), in); err != nil {
		t.Fatalf("ProposeChanges must still open even when rendering degraded: %v", err)
	}
	body, _ := fake.prBody["body"].(string)
	if !strings.Contains(body, "inconclusive") {
		t.Fatalf("body must say the render was inconclusive:\n%s", body)
	}
	if !strings.Contains(body, "render sandbox timed out") {
		t.Fatalf("body must carry the actual degradation reason:\n%s", body)
	}
	message, _ := fake.puts[0]["message"].(string)
	if !strings.Contains(message, "Argus-Render: degraded") {
		t.Errorf("commit trailer is missing the degraded render outcome:\n%s", message)
	}
}

// --- deleting a file, BACKLOG.md "still open" #2 ----------------------------

// TestProposeChanges_DeleteSingleFile is the headline case AB1/CRD-001 name:
// removing one whole manifest from the repository. A single deleted file
// takes the sequential path (ProposeChanges never uses the atomic trees API
// for exactly one changed file), which means this exercises scm.Provider's
// new DeleteFile method via GitHub's Contents API DELETE — the same endpoint
// PutFile writes through.
func TestProposeChanges_DeleteSingleFile(t *testing.T) {
	provider, fake := newProvider(t)

	proposal, err := ProposeChanges(t.Context(), provider, previewRepo(),
		baseInput(FileEdit{Path: valuesPath, Delete: true}))
	if err != nil {
		t.Fatalf("ProposeChanges: %v", err)
	}
	if got := proposal.Verification.FilesChanged; got != 1 {
		t.Errorf("FilesChanged = %d, want 1", got)
	}
	if len(fake.deletes) != 1 {
		t.Fatalf("got %d DELETE calls, want 1: %v", len(fake.deletes), fake.deletes)
	}
	if len(fake.puts) != 0 {
		t.Errorf("a delete used the PUT (write) path: %v", fake.puts)
	}
	if fake.deletes[0]["sha"] != blobSHAFor(valuesPath) {
		t.Errorf("delete did not send the blob it read as its compare-and-swap token: %v", fake.deletes[0])
	}

	body, _ := fake.prBody["body"].(string)
	if !strings.Contains(body, valuesPath+" (DELETED)") {
		t.Errorf("pull request body does not mark the file as deleted:\n%s", body)
	}
	msg, _ := fake.deletes[0]["message"].(string)
	if !strings.Contains(msg, "delete "+valuesPath) {
		t.Errorf("commit message does not say this is a deletion: %q", msg)
	}
}

// TestProposeChanges_DeleteNonexistentFileIsRefused: a delete needs the file
// to actually exist at the synced commit — there is no "create" case to
// mirror for a delete, so an absent path is a refusal, not a no-op.
func TestProposeChanges_DeleteNonexistentFileIsRefused(t *testing.T) {
	provider, fake := newProvider(t)
	_, err := ProposeChanges(t.Context(), provider, previewRepo(),
		baseInput(FileEdit{Path: "envs/prod/never-existed.yaml", Delete: true}))
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if !errors.Is(err, scm.ErrNotFound) {
		t.Errorf("err = %v, want it to wrap scm.ErrNotFound (so it is excluded from content-correction eligibility, unlike gitops.ErrVerificationFailed)", err)
	}
	if !strings.Contains(err.Error(), "nothing to remove") {
		t.Errorf("err = %v, want an explanation naming the file", err)
	}
	assertNoWrites(t, fake)
}

// TestProposeChanges_MixedDeleteAndWriteAtomic: deleting one file and writing
// a DIFFERENT file in the same proposal lands in ONE atomic commit — the
// trees API represents the delete as a null-sha entry alongside the write's
// real blob, so there is nothing about mixing the two that needs a second
// commit or a special case.
func TestProposeChanges_MixedDeleteAndWriteAtomic(t *testing.T) {
	provider, fake := newProvider(t)

	proposal, err := ProposeChanges(t.Context(), provider, previewRepo(), baseInput(
		FileEdit{Path: manifestPath, Content: fixedManifest()},
		FileEdit{Path: valuesPath, Delete: true},
	))
	if err != nil {
		t.Fatalf("ProposeChanges: %v", err)
	}
	if len(proposal.Commits) != 1 {
		t.Fatalf("Commits = %v, want exactly one atomic commit for the mixed batch", proposal.Commits)
	}
	if len(fake.puts) != 0 || len(fake.deletes) != 0 {
		t.Errorf("the mixed batch used the per-file Contents API instead of the atomic trees API: puts=%v deletes=%v", fake.puts, fake.deletes)
	}
	// Exactly one blob created — for the WRITE. The delete needs no blob.
	if len(fake.blobs) != 1 {
		t.Fatalf("created %d blobs, want exactly 1 (only the written file needs one)", len(fake.blobs))
	}
	if len(fake.postedTrees) != 1 {
		t.Fatalf("posted %d trees, want 1", len(fake.postedTrees))
	}
	entries, _ := fake.postedTrees[0]["tree"].([]any)
	if len(entries) != 2 {
		t.Fatalf("tree has %d entries, want exactly the 2 changed files", len(entries))
	}
	var sawDelete, sawWrite bool
	for _, raw := range entries {
		e, _ := raw.(map[string]any)
		switch e["path"] {
		case valuesPath:
			sawDelete = true
			if e["sha"] != nil {
				t.Errorf("the deleted file's tree entry has sha=%v, want a literal null", e["sha"])
			}
		case manifestPath:
			sawWrite = true
			if e["sha"] == nil {
				t.Errorf("the written file's tree entry has a null sha, want the new blob's")
			}
		}
	}
	if !sawDelete || !sawWrite {
		t.Fatalf("tree entries = %v, want both the delete and the write represented", entries)
	}
}

// TestProposeChanges_DeleteOfObjectsOwnManifestIsAdvised: deleting the file
// that declares the incident's own Kubernetes object is exactly AB1's shape
// (two overlapping HPAs, delete one) — legitimate, and flagged as something
// the reviewer must confirm is intended, not refused.
func TestProposeChanges_DeleteOfObjectsOwnManifestIsAdvised(t *testing.T) {
	provider, _ := newProvider(t)
	preview, err := PreviewChanges(t.Context(), provider, previewRepo(),
		baseInput(FileEdit{Path: manifestPath, Delete: true}))
	if err != nil {
		t.Fatalf("PreviewChanges: %v", err)
	}
	joined := strings.Join(preview.Verification.Advisories, " ")
	if !strings.Contains(joined, "REMOVED ENTIRELY") {
		t.Errorf("advisories = %v, want one flagging that the object's own manifest would be removed", preview.Verification.Advisories)
	}
	if preview.Verification.Files[0].Deleted != true {
		t.Errorf("Files[0].Deleted = false, want true")
	}
}

// TestProposeChanges_DeleteConflict: the same compare-and-swap every other
// write already gets — a file deleted (or changed) by someone else between
// the synced-commit read and this commit is caught as ErrConflict, not
// silently applied against whatever is there now.
func TestProposeChanges_DeleteConflict(t *testing.T) {
	provider, fake := newProvider(t)
	fake.putStatusFor[valuesPath] = http.StatusConflict

	_, err := ProposeChanges(t.Context(), provider, previewRepo(),
		baseInput(FileEdit{Path: valuesPath, Delete: true}))
	if !errors.Is(err, scm.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

func TestBranchName(t *testing.T) {
	if got := BranchName("argus/fix-{incidentId}", incidentID); got != "argus/fix-"+incidentID {
		t.Errorf("BranchName = %q", got)
	}
	// A pattern with no placeholder would collide on the second incident.
	if got := BranchName("argus/fix", incidentID); got != "argus/fix-"+incidentID {
		t.Errorf("BranchName(no placeholder) = %q, want the documented default", got)
	}
}

func assertNoWrites(t *testing.T, f *fakeGit) {
	t.Helper()
	for _, r := range f.requests {
		if strings.HasPrefix(r, "PUT ") || strings.HasPrefix(r, "POST ") {
			t.Errorf("a refusal performed a write: %s", r)
		}
	}
}

// The pull request title is read by a human scanning a list of pull requests in
// GitHub, who has no ARGUS session. These assert the two things that made the
// old title useless there — it named a file path and nothing else — without
// pinning the exact wording.
func TestPullRequestTitleLeadsWithWhyWhenAnAnalysisSuppliedOne(t *testing.T) {
	in := ProposalInput{
		Object: ObjectRef{Kind: "Deployment", Namespace: "argus-gitops-rke2", Name: "api"},
		Provenance: Provenance{
			RootCause: "The api Deployment's container memory limit of 128Mi is below its steady-state working set. The kubelet OOMKills it within a minute of every start.",
		},
	}
	got := pullRequestTitle(in, ChangeVerification{})
	if !strings.HasPrefix(got, "fix(argus-gitops-rke2/api): ") {
		t.Errorf("title = %q, want the §11.1 fix(scope) shape with the OBJECT as the scope", got)
	}
	if !strings.Contains(got, "memory limit") {
		t.Errorf("title = %q — it must say what the point is; the root cause is the only statement of that anything recorded", got)
	}
	if strings.Contains(got, "OOMKills") {
		t.Errorf("title = %q — only the FIRST sentence belongs in a git subject line", got)
	}
	if len(got) > maxTitleLen {
		t.Errorf("title = %q is %d chars, over the %d-char subject budget GitHub truncates at", got, len(got), maxTitleLen)
	}
}

func TestPullRequestTitleFallsBackToTheFileWhenNoRootCauseWasRecorded(t *testing.T) {
	// The self-service repository-change route can have no analysis behind it,
	// and Provenance.RootCause is documented Optional. Naming the file is a
	// weak title; asserting a cause nobody determined would be a false one.
	in := ProposalInput{Object: ObjectRef{Namespace: "ns", Name: "api"}}
	got := pullRequestTitle(in, ChangeVerification{Files: []FileChange{{Path: "apps/api/deployment.yaml"}}})
	if got != "fix(ns/api): update apps/api/deployment.yaml" {
		t.Errorf("title = %q, want the unchanged file-based fallback", got)
	}
}

func TestTitleSummaryRefusesToEmitAStubWhenTheBudgetIsTooSmall(t *testing.T) {
	if got := titleSummary("The memory limit is too low for the workload's steady state", 10); got != "" {
		t.Errorf("titleSummary = %q, want \"\" so the caller falls back to naming the file", got)
	}
	if got := titleSummary("   ", 60); got != "" {
		t.Errorf("titleSummary(whitespace) = %q, want \"\"", got)
	}
}
