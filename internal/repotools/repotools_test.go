package repotools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"argus/internal/gitops"
)

// fakeCheckouts builds a Checkouts whose "clone" just materialises files on
// disk, so every test below exercises the real Reader, the real confinement and
// the real bounds without a git server. Returns the cache and a counter of how
// many times a fetch actually happened — the thing the cache exists to reduce.
func fakeCheckouts(t *testing.T, files map[string]string) (*Checkouts, *int) {
	t.Helper()
	var mu sync.Mutex
	fetches := 0
	c := &Checkouts{
		entries: map[string]*checkoutEntry{},
		parent:  t.TempDir(),
		clone: func(_ context.Context, opts gitops.CloneOptions) error {
			mu.Lock()
			fetches++
			mu.Unlock()
			for p, content := range files {
				full := filepath.Join(opts.Dir, filepath.FromSlash(p))
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					return err
				}
				if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
					return err
				}
			}
			return nil
		},
	}
	t.Cleanup(func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		for key, e := range c.entries {
			c.removeLocked(key, e)
		}
	})
	return c, &fetches
}

func testScope() Scope {
	return Scope{
		RepoURL:   "https://github.com/example/apps",
		Revision:  "0123456789abcdef0123456789abcdef01234567",
		SourceDir: "charts/web",
		Host:      "github.com",
	}
}

func testFiles() map[string]string {
	return map[string]string{
		"charts/web/values.yaml":               "resources:\n  limits:\n    memory: 64Mi\n",
		"charts/web/Chart.yaml":                "name: web\n",
		"charts/web/templates/deployment.yaml": "memory: {{ .Values.resources.limits.memory }}\n",
		"charts/web/scripts/deploy.sh":         "#!/bin/sh\necho deploying\n",
		"envs/prod/secret.yaml":                "not in the synced directory\n",
	}
}

func call(t *testing.T, r *Reader, tool string, args any) (map[string]any, error) {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	out, err := r.Call(context.Background(), tool, raw)
	if err != nil {
		return nil, err
	}
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("tool result is not JSON: %v", err)
	}
	return decoded, nil
}

// TestReadRepoFile_ServesTheSyncedDirectoryAndNothingElse is the scope
// property the whole feature rests on: a Reader is built for one incident's
// binding and there is no argument that could widen it.
func TestReadRepoFile_ServesTheSyncedDirectoryAndNothingElse(t *testing.T) {
	cache, fetches := fakeCheckouts(t, testFiles())
	r := NewReader(testScope(), cache)

	got, err := call(t, r, ToolReadRepoFile, map[string]any{"path": "values.yaml"})
	if err != nil {
		t.Fatalf("read_repo_file: %v", err)
	}
	if !strings.Contains(got["content"].(string), "memory: 64Mi") {
		t.Errorf("content = %q, want the values file's own text", got["content"])
	}
	if got["path"] != "charts/web/values.yaml" {
		t.Errorf("path = %q, want the repository-relative form so it can be handed straight back", got["path"])
	}
	if got["revision"] != testScope().Revision {
		t.Error("the result must name the pinned revision it was read at")
	}

	// Outside the synced directory: refused, not read. This is the "an incident
	// about envs/dev must not become a read of envs/prod" confinement.
	if _, err := call(t, r, ToolReadRepoFile, map[string]any{"path": "envs/prod/secret.yaml"}); err == nil {
		t.Error("a path outside the synced directory must be refused")
	}
	if _, err := call(t, r, ToolReadRepoFile, map[string]any{"path": "../../etc/passwd"}); err == nil {
		t.Error("a traversal must be refused")
	}

	// Several calls, one fetch: the cache is what keeps F22's cost caveat from
	// meaning a git fetch per tool call.
	if *fetches != 1 {
		t.Errorf("made %d fetches for several reads of the same commit, want 1", *fetches)
	}
}

// TestRepoTools_RefuseForbiddenPaths: the binding's write denylist is applied
// to READS too. `scripts/**` is the case that matters — it is what CI invokes,
// and DESIGN.md §18.4's rule is that this class of content does not flow into
// prompts.
func TestRepoTools_RefuseForbiddenPaths(t *testing.T) {
	cache, _ := fakeCheckouts(t, testFiles())
	r := NewReader(testScope(), cache)

	if _, err := call(t, r, ToolReadRepoFile, map[string]any{"path": "scripts/deploy.sh"}); err == nil {
		t.Error("a forbidden path must not be readable into an investigation")
	}

	listing, err := call(t, r, ToolListRepoFiles, map[string]any{})
	if err != nil {
		t.Fatalf("list_repo_files: %v", err)
	}
	for _, f := range listing["files"].([]any) {
		p := f.(map[string]any)["path"].(string)
		if strings.Contains(p, "scripts/") {
			t.Errorf("the listing offered %q, which the reader will refuse — a listing must not advertise what cannot be read", p)
		}
		if !strings.HasPrefix(p, "charts/web/") {
			t.Errorf("the listing escaped the synced directory: %q", p)
		}
	}
}

// TestReadRepoFile_IsBounded: every other tool in this system reports
// totalMatched/truncated so a model can tell "not there" from "not shown", and
// this one must too — a model that believes a windowed file was the whole file
// reasons from absence about a key that is simply further down.
//
// Since whole-file proposals (2026-08-28) it carries a second, sharper duty: a
// model that proposes new content for a file it read only part of silently
// discards the rest, and the diff looks plausible. So a truncated read also
// carries a sentence saying exactly that.
func TestReadRepoFile_IsBounded(t *testing.T) {
	var big strings.Builder
	for i := 0; i < defaultReadLines*2; i++ {
		big.WriteString("line\n")
	}
	files := testFiles()
	files["charts/web/big.yaml"] = big.String()
	cache, _ := fakeCheckouts(t, files)
	r := NewReader(testScope(), cache)

	got, err := call(t, r, ToolReadRepoFile, map[string]any{"path": "big.yaml"})
	if err != nil {
		t.Fatalf("read_repo_file: %v", err)
	}
	if got["truncated"] != true {
		t.Error("a file longer than the default window must report truncated")
	}
	if int(got["totalLines"].(float64)) != defaultReadLines*2+1 {
		t.Errorf("totalLines = %v, want the file's real length so the model knows what it did not see", got["totalLines"])
	}
	if int(got["endLine"].(float64)) != defaultReadLines {
		t.Errorf("endLine = %v, want the default window %d", got["endLine"], defaultReadLines)
	}
	// A truncated read must SAY what a partial read now means: a repository
	// change is a set of whole files, so content the model did not see would be
	// discarded if it proposed this file's new content from this window. A
	// boolean it may or may not weigh is weaker than the sentence.
	warning, _ := got["warning"].(string)
	if !strings.Contains(warning, "NOT the whole file") {
		t.Errorf("warning = %q, want it to say plainly that this is not the whole file", warning)
	}
	if !strings.Contains(warning, "would be discarded") {
		t.Errorf("warning = %q, want it to name the consequence of proposing content from a partial read", warning)
	}

	// A caller asking for more than the cap gets the cap, not the ask.
	got, err = call(t, r, ToolReadRepoFile, map[string]any{"path": "big.yaml", "maxLines": 100000})
	if err != nil {
		t.Fatalf("read_repo_file: %v", err)
	}
	if int(got["endLine"].(float64)) > maxReadLines {
		t.Errorf("endLine = %v, want no more than the hard cap %d", got["endLine"], maxReadLines)
	}
}

// TestReader_WithNoRepositoryRefusesRatherThanGuessing — a Reader with an
// unpinned revision, or no repository at all, must answer "there is none"
// rather than fetching a branch head.
func TestReader_WithNoRepositoryRefusesRatherThanGuessing(t *testing.T) {
	cache, fetches := fakeCheckouts(t, testFiles())
	for name, scope := range map[string]Scope{
		"no repository": {},
		"no revision":   {RepoURL: "https://github.com/example/apps", Host: "github.com"},
		"no host":       {RepoURL: "https://github.com/example/apps", Revision: "abc"},
	} {
		t.Run(name, func(t *testing.T) {
			if scope.Valid() {
				t.Fatal("this scope should not be considered usable")
			}
			_, err := NewReader(scope, cache).Call(context.Background(), ToolReadRepoFile, json.RawMessage(`{"path":"values.yaml"}`))
			if !errors.Is(err, ErrNoRepository) {
				t.Errorf("err = %v, want ErrNoRepository", err)
			}
		})
	}
	if *fetches != 0 {
		t.Error("an unusable scope must never reach a fetch")
	}
}

// TestIsRepoTool pins the dispatch predicate: only these two names are served
// hub-side, and nothing else may be diverted away from the cluster agent.
func TestIsRepoTool(t *testing.T) {
	for _, name := range ToolNames() {
		if !IsRepoTool(name) {
			t.Errorf("IsRepoTool(%q) = false for a name this package serves", name)
		}
	}
	for _, name := range []string{"get_events", "describe_resource", "dry_run_patch", "scale_deployment", ""} {
		if IsRepoTool(name) {
			t.Errorf("IsRepoTool(%q) = true — a cluster tool must never be diverted from the tunnel", name)
		}
	}
}

// --- ReadLog: BACKLOG.md F25's truncation-provenance guard ------------------

// TestReadLog_RecordsTruncationAcrossCalls is (a)/(b)/(d) of F25's test list,
// exercised directly against the real Reader.readFile path (via SetReadLog)
// rather than against a hand-built ReadLog, so what is proven is what a real
// investigation's tool calls actually produce.
func TestReadLog_RecordsTruncationAcrossCalls(t *testing.T) {
	files := testFiles()
	// A file long enough that a default-window read is truncated, so a
	// second, explicit full read is required to see the rest.
	var big strings.Builder
	for i := 0; i < defaultReadLines+50; i++ {
		big.WriteString("line\n")
	}
	files["charts/web/big.yaml"] = big.String()
	cache, _ := fakeCheckouts(t, files)

	t.Run("a file read whole is not flagged", func(t *testing.T) {
		log := NewReadLog()
		r := NewReader(testScope(), cache).SetReadLog(log)
		if _, err := call(t, r, ToolReadRepoFile, map[string]any{"path": "values.yaml"}); err != nil {
			t.Fatalf("read_repo_file: %v", err)
		}
		if bad := log.CheckPaths(testScope().SourceDir, []string{"values.yaml"}); len(bad) != 0 {
			t.Errorf("CheckPaths flagged a file that was read in full: %+v", bad)
		}
	})

	t.Run("a file read only partially is flagged, with the line range", func(t *testing.T) {
		log := NewReadLog()
		r := NewReader(testScope(), cache).SetReadLog(log)
		if _, err := call(t, r, ToolReadRepoFile, map[string]any{"path": "big.yaml"}); err != nil {
			t.Fatalf("read_repo_file: %v", err)
		}
		bad := log.CheckPaths(testScope().SourceDir, []string{"big.yaml"})
		if len(bad) != 1 {
			t.Fatalf("CheckPaths did not flag a file whose only read was truncated: %+v", bad)
		}
		if bad[0].StartLine != 1 || bad[0].EndLine != defaultReadLines || bad[0].TotalLines != defaultReadLines+51 {
			t.Errorf("got %+v, want the actual window and total line count so the refusal message can name them", bad[0])
		}
	})

	t.Run("a truncated read followed by a full re-read is judged by the LATEST read", func(t *testing.T) {
		log := NewReadLog()
		r := NewReader(testScope(), cache).SetReadLog(log)
		if _, err := call(t, r, ToolReadRepoFile, map[string]any{"path": "big.yaml"}); err != nil {
			t.Fatalf("first (truncated) read_repo_file: %v", err)
		}
		if bad := log.CheckPaths(testScope().SourceDir, []string{"big.yaml"}); len(bad) != 1 {
			t.Fatalf("expected the first, truncated read to be flagged before the correction: %+v", bad)
		}
		// The legitimate two-step correction: page through with maxLines/
		// startLine until truncated is false.
		if _, err := call(t, r, ToolReadRepoFile, map[string]any{"path": "big.yaml", "maxLines": maxReadLines}); err != nil {
			t.Fatalf("second (whole-file) read_repo_file: %v", err)
		}
		if bad := log.CheckPaths(testScope().SourceDir, []string{"big.yaml"}); len(bad) != 0 {
			t.Errorf("CheckPaths still flags %+v after a corrective full re-read of the same path — it must track the most recent read, not the first", bad)
		}
	})

	t.Run("a path never read at all is not flagged — a different, out-of-scope question", func(t *testing.T) {
		log := NewReadLog()
		if bad := log.CheckPaths(testScope().SourceDir, []string{"never-read.yaml"}); len(bad) != 0 {
			t.Errorf("CheckPaths flagged a path with no read record at all: %+v", bad)
		}
	})

	t.Run("a nil ReadLog is a no-op, matching Reader's own nil-tolerance", func(t *testing.T) {
		var log *ReadLog
		r := NewReader(testScope(), cache).SetReadLog(log)
		if _, err := call(t, r, ToolReadRepoFile, map[string]any{"path": "big.yaml"}); err != nil {
			t.Fatalf("read_repo_file with a nil log attached: %v", err)
		}
		if bad := log.CheckPaths(testScope().SourceDir, []string{"big.yaml"}); bad != nil {
			t.Errorf("CheckPaths on a nil *ReadLog should return nil, got %+v", bad)
		}
	})

	t.Run("a Reader with no log attached at all still serves reads normally", func(t *testing.T) {
		r := NewReader(testScope(), cache)
		if _, err := call(t, r, ToolReadRepoFile, map[string]any{"path": "values.yaml"}); err != nil {
			t.Fatalf("read_repo_file with no ReadLog attached: %v", err)
		}
	})
}

// TestReadRepoFile_RedactsCredentialShapedContent is DESIGN.md §18.4 /
// non-negotiable 9 applied at the only capture point repository content has.
// The path denylist is the stronger control and refuses `**/secrets/**` and
// friends outright; this covers what a denylist structurally cannot — a
// plaintext credential in an ordinary values file.
func TestReadRepoFile_RedactsCredentialShapedContent(t *testing.T) {
	files := testFiles()
	files["charts/web/values.yaml"] = "image:\n  repository: registry.example/web\n" +
		"registryUrl: https://svc:hunter2supersecret@registry.example/web\n" +
		"apiKey: AKIAIOSFODNN7EXAMPLE\n" +
		"resources:\n  limits:\n    memory: 64Mi\n"
	cache, _ := fakeCheckouts(t, files)
	r := NewReader(testScope(), cache)

	got, err := call(t, r, ToolReadRepoFile, map[string]any{"path": "values.yaml"})
	if err != nil {
		t.Fatalf("read_repo_file: %v", err)
	}
	content := got["content"].(string)
	for _, secret := range []string{"hunter2supersecret", "AKIAIOSFODNN7EXAMPLE"} {
		if strings.Contains(content, secret) {
			t.Errorf("a credential-shaped value reached the model verbatim: %q", secret)
		}
	}
	// Diagnostic context survives — the point is to drop the value, not the
	// line, so the model can still reason about which setting is involved.
	if !strings.Contains(content, "memory: 64Mi") || !strings.Contains(content, "registry.example/web") {
		t.Errorf("redaction removed more than the credentials:\n%s", content)
	}
}

// TestReadLog_Unread is BACKLOG.md F28 finding 1's own widening of F25's
// ReadLog: a path with NO record at all is exactly what Unread must report,
// distinct from CheckPaths' "was a read that happened truncated" question —
// see Unread's own doc comment for why the two are deliberately separate.
func TestReadLog_Unread(t *testing.T) {
	files := testFiles()
	cache, _ := fakeCheckouts(t, files)

	t.Run("a file never read at all is reported", func(t *testing.T) {
		log := NewReadLog()
		if bad := log.Unread(testScope().SourceDir, []string{"values.yaml"}); len(bad) != 1 || bad[0] != "values.yaml" {
			t.Errorf("Unread(values.yaml) = %v, want [\"values.yaml\"] — nothing was ever read this investigation", bad)
		}
	})

	t.Run("a file read in full is not reported", func(t *testing.T) {
		log := NewReadLog()
		r := NewReader(testScope(), cache).SetReadLog(log)
		if _, err := call(t, r, ToolReadRepoFile, map[string]any{"path": "values.yaml"}); err != nil {
			t.Fatalf("read_repo_file: %v", err)
		}
		if bad := log.Unread(testScope().SourceDir, []string{"values.yaml"}); len(bad) != 0 {
			t.Errorf("Unread flagged a path that was actually read: %v", bad)
		}
	})

	t.Run("a file read but truncated is STILL reported as read by Unread — that is CheckPaths' job, not this one's", func(t *testing.T) {
		var big strings.Builder
		for i := 0; i < defaultReadLines+50; i++ {
			big.WriteString("line\n")
		}
		f := testFiles()
		f["charts/web/big.yaml"] = big.String()
		c2, _ := fakeCheckouts(t, f)
		log := NewReadLog()
		r := NewReader(testScope(), c2).SetReadLog(log)
		if _, err := call(t, r, ToolReadRepoFile, map[string]any{"path": "big.yaml"}); err != nil {
			t.Fatalf("read_repo_file: %v", err)
		}
		if bad := log.Unread(testScope().SourceDir, []string{"big.yaml"}); len(bad) != 0 {
			t.Errorf("Unread must not flag a path that was read at all, even truncated: %v", bad)
		}
		// The same path IS flagged by CheckPaths — proving the two checks
		// are answering genuinely different questions about the same read.
		if bad := log.CheckPaths(testScope().SourceDir, []string{"big.yaml"}); len(bad) != 1 {
			t.Errorf("expected CheckPaths to flag the truncated read that Unread correctly ignored: %v", bad)
		}
	})

	t.Run("mixed paths report only the unread ones", func(t *testing.T) {
		log := NewReadLog()
		r := NewReader(testScope(), cache).SetReadLog(log)
		if _, err := call(t, r, ToolReadRepoFile, map[string]any{"path": "values.yaml"}); err != nil {
			t.Fatalf("read_repo_file: %v", err)
		}
		bad := log.Unread(testScope().SourceDir, []string{"values.yaml", "Chart.yaml"})
		if len(bad) != 1 || bad[0] != "Chart.yaml" {
			t.Errorf("Unread(values.yaml [read], Chart.yaml [not read]) = %v, want just [\"Chart.yaml\"]", bad)
		}
	})

	t.Run("nil log and empty paths are no-ops", func(t *testing.T) {
		var log *ReadLog
		if bad := log.Unread("charts/web", []string{"values.yaml"}); bad != nil {
			t.Errorf("Unread on a nil *ReadLog should return nil, got %v", bad)
		}
		real := NewReadLog()
		if bad := real.Unread("charts/web", nil); bad != nil {
			t.Errorf("Unread with no paths should return nil, got %v", bad)
		}
	})
}

// TestReadLog_UnreadExemptsAPathEstablishedAbsentByListing is B141's
// regression test: before this exemption, ARGUS could not propose adding a
// file to a repository under any circumstances — read_repo_file can never
// succeed against a path that does not exist, so it could never be
// "read," and a plan naming it was refused exactly like one inventing
// content for a path it never opened. A non-truncated list_repo_files call
// that does not contain the path is the same kind of established fact the
// delete exemption already accepts for a path confirmed to EXIST, applied
// the other direction.
func TestReadLog_UnreadExemptsAPathEstablishedAbsentByListing(t *testing.T) {
	files := testFiles()
	cache, _ := fakeCheckouts(t, files)

	t.Run("a path confirmed absent from a non-truncated listing is not reported", func(t *testing.T) {
		log := NewReadLog()
		r := NewReader(testScope(), cache).SetReadLog(log)
		if _, err := call(t, r, ToolListRepoFiles, map[string]any{}); err != nil {
			t.Fatalf("list_repo_files: %v", err)
		}
		bad := log.Unread(testScope().SourceDir, []string{"configmap.yaml"})
		if len(bad) != 0 {
			t.Errorf("Unread(configmap.yaml) = %v, want none — a full listing of the synced directory already proved this path does not exist there", bad)
		}
	})

	t.Run("a path that DOES appear in the listing is still reported unread", func(t *testing.T) {
		log := NewReadLog()
		r := NewReader(testScope(), cache).SetReadLog(log)
		if _, err := call(t, r, ToolListRepoFiles, map[string]any{}); err != nil {
			t.Fatalf("list_repo_files: %v", err)
		}
		bad := log.Unread(testScope().SourceDir, []string{"values.yaml"})
		if len(bad) != 1 || bad[0] != "values.yaml" {
			t.Errorf("Unread(values.yaml) = %v, want [\"values.yaml\"] — listing a directory does not establish the CONTENT of a file that does exist in it, only read_repo_file does", bad)
		}
	})

	t.Run("a path outside any listed directory is still reported unread", func(t *testing.T) {
		log := NewReadLog()
		r := NewReader(testScope(), cache).SetReadLog(log)
		if _, err := call(t, r, ToolListRepoFiles, map[string]any{"subdir": "templates"}); err != nil {
			t.Fatalf("list_repo_files: %v", err)
		}
		// "configmap.yaml" is a sibling of templates/, not underneath it — the
		// templates/ listing says nothing about whether it exists.
		bad := log.Unread(testScope().SourceDir, []string{"configmap.yaml"})
		if len(bad) != 1 || bad[0] != "configmap.yaml" {
			t.Errorf("Unread(configmap.yaml) = %v, want it reported — only templates/ was listed, not the directory this path is actually in", bad)
		}
	})

	t.Run("a truncated listing establishes nothing", func(t *testing.T) {
		f := testFiles()
		for i := 0; i < defaultListLimit+50; i++ {
			f[fmt.Sprintf("charts/web/generated/file-%03d.yaml", i)] = "x\n"
		}
		c2, _ := fakeCheckouts(t, f)
		log := NewReadLog()
		r := NewReader(testScope(), c2).SetReadLog(log)
		result, err := call(t, r, ToolListRepoFiles, map[string]any{})
		if err != nil {
			t.Fatalf("list_repo_files: %v", err)
		}
		if truncated, _ := result["truncated"].(bool); !truncated {
			t.Fatalf("test setup bug: expected this listing to be truncated, result: %+v", result)
		}
		bad := log.Unread(testScope().SourceDir, []string{"configmap.yaml"})
		if len(bad) != 1 || bad[0] != "configmap.yaml" {
			t.Errorf("Unread(configmap.yaml) = %v, want it reported — a truncated listing cannot prove any path's absence, only that it wasn't among the first results", bad)
		}
	})

	t.Run("a forbidden path is never established absent by a listing that omits it", func(t *testing.T) {
		// scripts/deploy.sh exists in testFiles but is forbidden
		// (testScope/ForbiddenPaths — see the read/delete tests above for the
		// same fixture) and so never appears in list_repo_files' own Files —
		// its absence from the RETURNED list must never be misread as
		// "confirmed absent," since it may exist and simply be withheld.
		scope := testScope()
		scope.ForbiddenPaths = []string{"**/*.sh"}
		log := NewReadLog()
		r := NewReader(scope, cache).SetReadLog(log)
		if _, err := call(t, r, ToolListRepoFiles, map[string]any{}); err != nil {
			t.Fatalf("list_repo_files: %v", err)
		}
		bad := log.Unread(scope.SourceDir, []string{"scripts/deploy.sh"})
		if len(bad) != 1 || bad[0] != "scripts/deploy.sh" {
			t.Errorf("Unread(scripts/deploy.sh) = %v, want it reported — a forbidden path missing from the listing is withheld, not confirmed absent", bad)
		}
	})
}

// TestReadLogRegistry is BACKLOG.md F28 finding 1's other half: closing the
// cli-backend gap F25 documented and declined to close ("the cli backend's
// tool calls reach internal/api.CallRepoTool through a fresh
// *repotools.Reader per MCP call with no ReadLog attached"). The registry
// is what lets a call arriving through a completely different code path
// still write into the SAME log the investigation's own caller built.
func TestReadLogRegistry(t *testing.T) {
	t.Run("Begin then Get returns the same log, recording across both", func(t *testing.T) {
		reg := NewReadLogRegistry()
		log := reg.Begin("inc_1")
		if got := reg.Get("inc_1"); got != log {
			t.Fatalf("Get after Begin returned a different log")
		}
		// Simulate the api backend's in-process Reader recording a read...
		log.record("charts/web/values.yaml", false, 1, 10, 10)
		// ...and CallRepoTool's OWN, separately-constructed Reader, looking
		// the log up by incident id and recording into the identical
		// instance, exactly as repo_tools.go's CallRepoTool now does.
		bridged := reg.Get("inc_1")
		bridged.record("charts/web/Chart.yaml", false, 1, 1, 1)
		if bad := log.Unread("charts/web", []string{"values.yaml", "Chart.yaml"}); len(bad) != 0 {
			t.Errorf("both reads should be visible through the ORIGINAL log reference: unread = %v", bad)
		}
	})

	t.Run("two different incidents never collide", func(t *testing.T) {
		reg := NewReadLogRegistry()
		logA := reg.Begin("inc_a")
		logB := reg.Begin("inc_b")
		logA.record("a.yaml", false, 1, 1, 1)
		if bad := logB.Unread("", []string{"a.yaml"}); len(bad) != 1 {
			t.Errorf("incident B's log must not see incident A's read: %v", bad)
		}
	})

	t.Run("End removes the entry", func(t *testing.T) {
		reg := NewReadLogRegistry()
		reg.Begin("inc_1")
		reg.End("inc_1")
		if got := reg.Get("inc_1"); got != nil {
			t.Errorf("Get after End should return nil, got a log")
		}
	})

	t.Run("Get on an unknown incident returns nil", func(t *testing.T) {
		reg := NewReadLogRegistry()
		if got := reg.Get("inc_never_began"); got != nil {
			t.Errorf("Get for an incident with no Begin should return nil")
		}
	})

	t.Run("a nil registry is a safe, unshared fallback — the pre-F28 behaviour", func(t *testing.T) {
		var reg *ReadLogRegistry
		log := reg.Begin("inc_1") // must not panic
		if log == nil {
			t.Fatal("Begin on a nil registry must still return a usable ReadLog")
		}
		log.record("a.yaml", false, 1, 1, 1)
		if bad := log.Unread("", []string{"a.yaml"}); len(bad) != 0 {
			t.Errorf("the returned log must still work normally: %v", bad)
		}
		if got := reg.Get("inc_1"); got != nil {
			t.Errorf("Get on a nil registry must return nil, not the log Begin handed back (it was never stored anywhere)")
		}
		reg.End("inc_1") // must not panic
	})
}
