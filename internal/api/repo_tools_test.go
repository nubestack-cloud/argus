package api

// Tests for BACKLOG.md F25's enforcement point: RefuseTruncatedRepositoryProposals.
//
// These build a REAL repotools.Reader/ReadLog pair (via
// repotools.NewCheckoutsForTest, the exported fake-clone seam added
// alongside this feature) and drive it through actual read_repo_file calls,
// exactly the way internal/repotools' own tests do — so what is proven here
// is the glue between a real, populated ReadLog and a proposed
// remediation.RemediationPlan, not a hand-built stand-in for either.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"argus/internal/gitops"
	"argus/internal/llm"
	"argus/internal/remediation"
	"argus/internal/repotools"
)

func testRepoScope() repotools.Scope {
	return repotools.Scope{
		RepoURL:   "https://github.com/example/apps",
		Revision:  "0123456789abcdef0123456789abcdef01234567",
		SourceDir: "charts/web",
		Host:      "github.com",
	}
}

// newTestReader builds a Reader over a fake checkout holding files, with a
// fresh ReadLog attached — the same "one Reader, one ReadLog, one
// investigation" pairing analyze.go/autoanalyze.go wire up for real.
func newTestReader(t *testing.T, files map[string]string) (*repotools.Reader, *repotools.ReadLog) {
	t.Helper()
	cache := repotools.NewCheckoutsForTest(t.TempDir(), func(_ context.Context, opts gitops.CloneOptions) error {
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
	})
	log := repotools.NewReadLog()
	r := repotools.NewReader(testRepoScope(), cache).SetReadLog(log)
	return r, log
}

func readRepoFile(t *testing.T, r *repotools.Reader, path string, extra map[string]any) {
	t.Helper()
	args := map[string]any{"path": path}
	for k, v := range extra {
		args[k] = v
	}
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Call(context.Background(), repotools.ToolReadRepoFile, raw); err != nil {
		t.Fatalf("read_repo_file(%q): %v", path, err)
	}
}

// listRepoFiles calls list_repo_files on r (recording into whichever ReadLog
// it was built with, per newTestReader) — the B141 establishment-of-fact
// call a test can make before proposing a path that does not exist.
func listRepoFiles(t *testing.T, r *repotools.Reader, subdir string) {
	t.Helper()
	args := map[string]any{}
	if subdir != "" {
		args["subdir"] = subdir
	}
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Call(context.Background(), repotools.ToolListRepoFiles, raw); err != nil {
		t.Fatalf("list_repo_files(subdir=%q): %v", subdir, err)
	}
}

func openPRPlan(files ...remediation.ProposedFile) *remediation.RemediationPlan {
	return &remediation.RemediationPlan{
		ActionType: remediation.ActionOpenPR,
		TargetGVK:  "apps/v1/Deployment",
		Params:     remediation.OpenPRParams{Repository: "example-org/apps", Files: files},
	}
}

func manyLines(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("line\n")
	}
	return b.String()
}

// TestRefuseTruncatedRepositoryProposals_FullReadSucceeds is F25's regression
// guard (a): a file read in full, then proposed, must sail through unchanged.
func TestRefuseTruncatedRepositoryProposals_FullReadSucceeds(t *testing.T) {
	r, log := newTestReader(t, map[string]string{"charts/web/values.yaml": "memory: 64Mi\n"})
	readRepoFile(t, r, "values.yaml", nil)

	result := llm.Investigation{
		Status:       "complete",
		ProposedPlan: openPRPlan(remediation.ProposedFile{Path: "charts/web/values.yaml", Content: "memory: 128Mi\n"}),
	}
	got := RefuseTruncatedRepositoryProposals(result, testRepoScope().SourceDir, log)
	if got.ProposedPlan == nil {
		t.Fatal("a plan built from a full read must not be refused")
	}
}

// TestRefuseTruncatedRepositoryProposals_TruncatedReadRefused is (b): a file
// read only partially, then proposed for that same path, must be refused
// outright — the plan comes back nil, not merely flagged.
func TestRefuseTruncatedRepositoryProposals_TruncatedReadRefused(t *testing.T) {
	r, log := newTestReader(t, map[string]string{"charts/web/values.yaml": manyLines(700)})
	readRepoFile(t, r, "values.yaml", nil) // default window (600) truncates a 700-line file

	result := llm.Investigation{
		Status:       "complete",
		ProposedPlan: openPRPlan(remediation.ProposedFile{Path: "charts/web/values.yaml", Content: "replaced\n"}),
	}
	got := RefuseTruncatedRepositoryProposals(result, testRepoScope().SourceDir, log)
	if got.ProposedPlan != nil {
		t.Fatal("a plan proposing new content for a file this investigation only partially read must be refused")
	}
}

// TestRefuseTruncatedRepositoryProposals_DeleteIgnoresTruncation is
// BACKLOG.md "still open" #2's F25 interaction: a delete proposes no
// content, so a truncated read of the SAME path earlier in the investigation
// is irrelevant to it — truncation only matters to a content-replace, which
// a delete is not. This must sail through even though the read this guard
// would otherwise flag was, in fact, truncated.
func TestRefuseTruncatedRepositoryProposals_DeleteIgnoresTruncation(t *testing.T) {
	r, log := newTestReader(t, map[string]string{"charts/web/hpa-a.yaml": manyLines(700)})
	readRepoFile(t, r, "hpa-a.yaml", nil) // truncated at the default 600-line window

	result := llm.Investigation{
		Status:       "complete",
		ProposedPlan: openPRPlan(remediation.ProposedFile{Path: "charts/web/hpa-a.yaml", Delete: true}),
	}
	got := RefuseTruncatedRepositoryProposals(result, testRepoScope().SourceDir, log)
	if got.ProposedPlan == nil {
		t.Fatal("a delete proposal must not be refused for a truncated read of the same path — truncation is a content-replace risk, not a delete risk")
	}
}

// TestRefuseTruncatedRepositoryProposals_NeverReadPathUnaffected is (c): a
// path this guard's log has no record of at all — a genuinely different
// question (see repotools.ReadLog.CheckPaths' own doc comment) — must NOT be
// refused by this guard; existing behaviour for that case is unchanged.
func TestRefuseTruncatedRepositoryProposals_NeverReadPathUnaffected(t *testing.T) {
	_, log := newTestReader(t, map[string]string{"charts/web/values.yaml": "memory: 64Mi\n"})
	// Deliberately no read_repo_file call at all.

	result := llm.Investigation{
		Status:       "complete",
		ProposedPlan: openPRPlan(remediation.ProposedFile{Path: "charts/web/values.yaml", Content: "memory: 128Mi\n"}),
	}
	got := RefuseTruncatedRepositoryProposals(result, testRepoScope().SourceDir, log)
	if got.ProposedPlan == nil {
		t.Fatal("a path this guard never saw a read for must not be refused by it")
	}
}

// TestRefuseTruncatedRepositoryProposals_CorrectiveFullRereadSucceeds is (d):
// a truncated read followed by a full re-read of the SAME path (the
// legitimate two-step correction the read_repo_file tool's own description
// asks for) must let the eventual proposal through — the guard tracks the
// MOST RECENT read, not the first.
func TestRefuseTruncatedRepositoryProposals_CorrectiveFullRereadSucceeds(t *testing.T) {
	r, log := newTestReader(t, map[string]string{"charts/web/values.yaml": manyLines(700)})
	readRepoFile(t, r, "values.yaml", nil)                              // truncated: default window is 600
	readRepoFile(t, r, "values.yaml", map[string]any{"maxLines": 4000}) // corrective full re-read

	result := llm.Investigation{
		Status:       "complete",
		ProposedPlan: openPRPlan(remediation.ProposedFile{Path: "charts/web/values.yaml", Content: "replaced\n"}),
	}
	got := RefuseTruncatedRepositoryProposals(result, testRepoScope().SourceDir, log)
	if got.ProposedPlan == nil {
		t.Fatal("a path re-read in full after an initial truncated read must not be refused — the guard must judge the latest read, not the first")
	}
}

// TestRefuseTruncatedRepositoryProposals_AppliesIndependentlyToBothPlanFields
// confirms ProposedPlan and ProposedPairedPlan (lld/08 §12.5's paired route)
// are each checked and refused on their own — one bad file in one field must
// not take down the other's otherwise-clean proposal.
func TestRefuseTruncatedRepositoryProposals_AppliesIndependentlyToBothPlanFields(t *testing.T) {
	r, log := newTestReader(t, map[string]string{
		"charts/web/values.yaml": "memory: 64Mi\n",
		"charts/web/big.yaml":    manyLines(700),
	})
	readRepoFile(t, r, "values.yaml", nil) // full read
	readRepoFile(t, r, "big.yaml", nil)    // truncated read

	result := llm.Investigation{
		Status:             "complete",
		ProposedPlan:       openPRPlan(remediation.ProposedFile{Path: "charts/web/values.yaml", Content: "memory: 128Mi\n"}),
		ProposedPairedPlan: openPRPlan(remediation.ProposedFile{Path: "charts/web/big.yaml", Content: "replaced\n"}),
	}
	got := RefuseTruncatedRepositoryProposals(result, testRepoScope().SourceDir, log)
	if got.ProposedPlan == nil {
		t.Error("proposedPlan was built from a full read and must survive")
	}
	if got.ProposedPairedPlan != nil {
		t.Error("proposedPairedPlan was built from a truncated read and must be refused")
	}
}

// TestRefuseTruncatedRepositoryProposals_IgnoresNonOpenPRAndNilCases pins the
// guard's actual scope: it only ever looks at OpenPR plans, and tolerates a
// nil plan / nil log / a plan whose Params didn't even parse as OpenPRParams
// without panicking or refusing something it has no business judging.
func TestRefuseTruncatedRepositoryProposals_IgnoresNonOpenPRAndNilCases(t *testing.T) {
	scaleDeploy := &remediation.RemediationPlan{
		ActionType: remediation.ActionScaleDeployment,
		Params:     remediation.ScaleDeploymentParams{Replicas: 2},
	}
	malformedOpenPR := &remediation.RemediationPlan{ActionType: remediation.ActionOpenPR, Params: nil}

	t.Run("nil plans and nil log", func(t *testing.T) {
		got := RefuseTruncatedRepositoryProposals(llm.Investigation{}, "charts/web", nil)
		if got.ProposedPlan != nil || got.ProposedPairedPlan != nil {
			t.Error("nil plans must stay nil")
		}
	})
	t.Run("non-OpenPR plan is untouched", func(t *testing.T) {
		got := RefuseTruncatedRepositoryProposals(llm.Investigation{ProposedPlan: scaleDeploy}, "charts/web", nil)
		if got.ProposedPlan != scaleDeploy {
			t.Error("a ScaleDeployment plan must never be examined or refused by this guard")
		}
	})
	t.Run("OpenPR plan with unparsed params is left for Validate() to Block, not refused here", func(t *testing.T) {
		got := RefuseTruncatedRepositoryProposals(llm.Investigation{ProposedPlan: malformedOpenPR}, "charts/web", nil)
		if got.ProposedPlan != malformedOpenPR {
			t.Error("a plan whose Params didn't parse into OpenPRParams must pass through unchanged — remediation.RemediationPlan.Validate() handles that failure, not this guard")
		}
	})
}
