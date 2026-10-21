package api

// Tests for BACKLOG.md F28 finding 1's enforcement point:
// RefuseUnreadRepositoryProposals.
//
// Same harness as repo_tools_test.go (F25's own test file) — a REAL
// repotools.Reader/ReadLog pair, driven through actual read_repo_file calls
// — for the identical reason: what is proven here is the glue between a
// real, populated ReadLog and a proposed remediation.RemediationPlan, not a
// hand-built stand-in for either. Deliberately a SEPARATE test file/function
// from F25's, mirroring RefuseUnreadRepositoryProposals being a separate
// function: the two guards answer different questions (repotools.ReadLog's
// own CheckPaths vs. Unread doc comments), and a plan can trip one, the
// other, both, or neither.

import (
	"testing"

	"argus/internal/llm"
	"argus/internal/remediation"
)

// TestRefuseUnreadRepositoryProposals_NeverReadPathRefused is this guard's
// whole reason to exist: a path this investigation never called
// read_repo_file for AT ALL — not even a truncated read — must be refused
// outright when an OpenPR plan proposes new content for it. This is the
// measured finding (253 real OpenPR proposals, only 13 with any recorded
// read_repo_file call at all) and the exact gap F25's own doc comment named
// and declined to close.
func TestRefuseUnreadRepositoryProposals_NeverReadPathRefused(t *testing.T) {
	_, log := newTestReader(t, map[string]string{"charts/web/values.yaml": "memory: 64Mi\n"})
	// Deliberately no read_repo_file call at all — this is finding 1's exact
	// shape: a whole-file replacement proposed for a path never opened.

	result := llm.Investigation{
		Status:       "complete",
		ProposedPlan: openPRPlan(remediation.ProposedFile{Path: "charts/web/values.yaml", Content: "memory: 128Mi\n"}),
	}
	got := RefuseUnreadRepositoryProposals(result, testRepoScope().SourceDir, log)
	if got.ProposedPlan != nil {
		t.Fatal("a plan proposing new content for a path never read this investigation must be refused")
	}
}

// TestRefuseUnreadRepositoryProposals_NewFileEstablishedAbsentByListingSucceeds
// is B141's regression test at this guard's own integration level: a genuinely
// new file — one that does not exist at the pinned revision, so
// read_repo_file could never succeed against it no matter how many times it
// were called — must be proposable once list_repo_files has already
// established it is not there. Before this exemption existed, this exact
// case had no route through OpenPR at all: every "the referenced object is
// missing" fault whose real fix is a new file was permanently refused.
func TestRefuseUnreadRepositoryProposals_NewFileEstablishedAbsentByListingSucceeds(t *testing.T) {
	r, log := newTestReader(t, map[string]string{"charts/web/values.yaml": "memory: 64Mi\n"})
	listRepoFiles(t, r, "")

	result := llm.Investigation{
		Status:       "complete",
		ProposedPlan: openPRPlan(remediation.ProposedFile{Path: "charts/web/configmap.yaml", Content: "data:\n  MODE: ready\n"}),
	}
	got := RefuseUnreadRepositoryProposals(result, testRepoScope().SourceDir, log)
	if got.ProposedPlan == nil {
		t.Fatal("a genuinely new file, confirmed absent by a full list_repo_files listing, must not be refused by this guard")
	}
}

// TestRefuseUnreadRepositoryProposals_NewFileWithoutAListingStillRefused is
// the negative complement: proposing a new file with NO list_repo_files call
// at all must still be refused exactly as before — B141's fix widens what
// counts as established, it does not weaken the guard for a path that
// merely went unread and unlisted.
func TestRefuseUnreadRepositoryProposals_NewFileWithoutAListingStillRefused(t *testing.T) {
	_, log := newTestReader(t, map[string]string{"charts/web/values.yaml": "memory: 64Mi\n"})
	// Deliberately no list_repo_files and no read_repo_file call at all.

	result := llm.Investigation{
		Status:       "complete",
		ProposedPlan: openPRPlan(remediation.ProposedFile{Path: "charts/web/configmap.yaml", Content: "data:\n  MODE: ready\n"}),
	}
	got := RefuseUnreadRepositoryProposals(result, testRepoScope().SourceDir, log)
	if got.ProposedPlan != nil {
		t.Fatal("a new file never established absent by any listing must still be refused")
	}
}

// TestRefuseUnreadRepositoryProposals_FullyReadPathSucceeds is the negative
// case: a file actually read (in full) before being proposed must sail
// through unchanged — this guard must not become a blanket refusal of every
// OpenPR proposal, only the provably-blind ones.
func TestRefuseUnreadRepositoryProposals_FullyReadPathSucceeds(t *testing.T) {
	r, log := newTestReader(t, map[string]string{"charts/web/values.yaml": "memory: 64Mi\n"})
	readRepoFile(t, r, "values.yaml", nil)

	result := llm.Investigation{
		Status:       "complete",
		ProposedPlan: openPRPlan(remediation.ProposedFile{Path: "charts/web/values.yaml", Content: "memory: 128Mi\n"}),
	}
	got := RefuseUnreadRepositoryProposals(result, testRepoScope().SourceDir, log)
	if got.ProposedPlan == nil {
		t.Fatal("a plan built from a real read must not be refused by this guard")
	}
}

// TestRefuseUnreadRepositoryProposals_TruncatedReadStillCountsAsRead proves
// this guard answers a DIFFERENT question from F25's: a read that happened
// but was truncated is still a read — Unread's own doc comment is explicit
// that CheckPaths (F25) and Unread (this guard) are separate checks. A
// truncated-but-read path must be left for RefuseTruncatedRepositoryProposals
// to judge, not refused a second time by this one.
func TestRefuseUnreadRepositoryProposals_TruncatedReadStillCountsAsRead(t *testing.T) {
	r, log := newTestReader(t, map[string]string{"charts/web/big.yaml": manyLines(700)})
	readRepoFile(t, r, "big.yaml", nil) // truncated at the default 600-line window, but a read did happen

	result := llm.Investigation{
		Status:       "complete",
		ProposedPlan: openPRPlan(remediation.ProposedFile{Path: "charts/web/big.yaml", Content: "replaced\n"}),
	}
	got := RefuseUnreadRepositoryProposals(result, testRepoScope().SourceDir, log)
	if got.ProposedPlan == nil {
		t.Fatal("a truncated-but-read path must not be refused by RefuseUnreadRepositoryProposals — that is RefuseTruncatedRepositoryProposals' own job")
	}
}

// TestRefuseUnreadRepositoryProposals_DeleteIgnoresUnread mirrors F25's own
// delete exemption for the identical reason: a delete proposes no content at
// all, so whether the path was ever read for its CONTENT is irrelevant to
// it.
func TestRefuseUnreadRepositoryProposals_DeleteIgnoresUnread(t *testing.T) {
	_, log := newTestReader(t, map[string]string{"charts/web/hpa-a.yaml": "spec: {}\n"})
	// No read at all.

	result := llm.Investigation{
		Status:       "complete",
		ProposedPlan: openPRPlan(remediation.ProposedFile{Path: "charts/web/hpa-a.yaml", Delete: true}),
	}
	got := RefuseUnreadRepositoryProposals(result, testRepoScope().SourceDir, log)
	if got.ProposedPlan == nil {
		t.Fatal("a delete proposal must not be refused for an unread path — a delete needs no content read")
	}
}

// TestRefuseUnreadRepositoryProposals_AppliesIndependentlyToBothPlanFields
// confirms ProposedPlan and ProposedPairedPlan are each checked and refused
// on their own, same as F25's guard.
func TestRefuseUnreadRepositoryProposals_AppliesIndependentlyToBothPlanFields(t *testing.T) {
	r, log := newTestReader(t, map[string]string{
		"charts/web/values.yaml": "memory: 64Mi\n",
		"charts/web/unread.yaml": "memory: 64Mi\n",
	})
	readRepoFile(t, r, "values.yaml", nil) // read
	// unread.yaml deliberately never read

	result := llm.Investigation{
		Status:             "complete",
		ProposedPlan:       openPRPlan(remediation.ProposedFile{Path: "charts/web/values.yaml", Content: "memory: 128Mi\n"}),
		ProposedPairedPlan: openPRPlan(remediation.ProposedFile{Path: "charts/web/unread.yaml", Content: "memory: 128Mi\n"}),
	}
	got := RefuseUnreadRepositoryProposals(result, testRepoScope().SourceDir, log)
	if got.ProposedPlan == nil {
		t.Error("proposedPlan was built from a real read and must survive")
	}
	if got.ProposedPairedPlan != nil {
		t.Error("proposedPairedPlan names a path never read this investigation and must be refused")
	}
}

// TestRefuseUnreadRepositoryProposals_IgnoresNonOpenPRAndNilCases pins the
// guard's scope, mirroring F25's own equivalent test.
func TestRefuseUnreadRepositoryProposals_IgnoresNonOpenPRAndNilCases(t *testing.T) {
	scaleDeploy := &remediation.RemediationPlan{
		ActionType: remediation.ActionScaleDeployment,
		Params:     remediation.ScaleDeploymentParams{Replicas: 2},
	}
	malformedOpenPR := &remediation.RemediationPlan{ActionType: remediation.ActionOpenPR, Params: nil}

	t.Run("nil plans and nil log", func(t *testing.T) {
		got := RefuseUnreadRepositoryProposals(llm.Investigation{}, "charts/web", nil)
		if got.ProposedPlan != nil || got.ProposedPairedPlan != nil {
			t.Error("nil plans must stay nil")
		}
	})
	t.Run("non-OpenPR plan is untouched", func(t *testing.T) {
		got := RefuseUnreadRepositoryProposals(llm.Investigation{ProposedPlan: scaleDeploy}, "charts/web", nil)
		if got.ProposedPlan != scaleDeploy {
			t.Error("a ScaleDeployment plan must never be examined or refused by this guard")
		}
	})
	t.Run("OpenPR plan with unparsed params is left for Validate() to Block, not refused here", func(t *testing.T) {
		got := RefuseUnreadRepositoryProposals(llm.Investigation{ProposedPlan: malformedOpenPR}, "charts/web", nil)
		if got.ProposedPlan != malformedOpenPR {
			t.Error("a plan whose Params didn't parse into OpenPRParams must pass through unchanged")
		}
	})
	t.Run("nil log refuses nothing, even for an otherwise-unread path", func(t *testing.T) {
		// A nil log means "no repository scope for this incident at all" —
		// the same degenerate case F25's guard tolerates. This guard must not
		// misread "no log" as "definitely unread" and refuse everything.
		got := RefuseUnreadRepositoryProposals(llm.Investigation{
			ProposedPlan: openPRPlan(remediation.ProposedFile{Path: "charts/web/values.yaml", Content: "x\n"}),
		}, "charts/web", nil)
		if got.ProposedPlan == nil {
			t.Error("a nil ReadLog must not cause a refusal")
		}
	})
}
