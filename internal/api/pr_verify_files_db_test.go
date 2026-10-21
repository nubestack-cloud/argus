package api

import (
	"context"
	"encoding/json"
	"testing"

	"argus/internal/data"
	"argus/internal/gitops"
	"argus/internal/orchestrator"
	"argus/internal/scm"
)

// TestRecordOpenedPullRequestPersistsProposedFiles is BACKLOG.md F23's
// persistence half: recordOpenedPullRequest must write
// incidents.pr_proposed_files (migration 000075) from the proposal's own
// gitops.ChangeVerification — the same one the pull request body and audit
// record already quote — so a later VerifyMergedPullRequest has something to
// re-check the merged files against. Only the CHANGED files are captured; an
// Unchanged one was never committed and there is nothing to assert about it
// post-merge.
func TestRecordOpenedPullRequestPersistsProposedFiles(t *testing.T) {
	pool := authTestPool(t)
	tenantID, clusterID, incidentID, _ := timelineExecFixture(t, pool)

	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin request tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	s := &Server{db: &data.DB{Pool: pool}}
	rc := &requestContext{Tx: tx, TenantID: tenantID, UserID: "usr_test"}

	proposal := gitops.Proposal{
		PullRequest: scm.PullRequest{Number: 42, URL: "https://github.com/acme/platform-config/pull/42", Head: "argus/fix-" + incidentID, Base: "main"},
		Commits:     []string{"deadbeef"},
		CommitSHA:   "deadbeef",
		Verification: gitops.ChangeVerification{
			Files: []gitops.FileChange{
				{Path: "envs/prod/deployment.yaml", Content: []byte("replicas: 3\n")},
				{Path: "envs/prod/values.yaml", Content: []byte("image: nginx:1.27\n"), Unchanged: true},
				// BACKLOG.md "still open" #2: a deleted file must round-trip
				// through pr_proposed_files with Deleted=true, so a later
				// VerifyMergedPullRequest can apply the inverted comparison a
				// delete needs.
				{Path: "envs/prod/hpa-a.yaml", Deleted: true},
			},
			FilesChanged: 2,
		},
	}

	s.recordOpenedPullRequest(ctx, rc, incidentID, proposal)

	var prNumber *int
	var fieldPath, expectedValue *string
	var proposedFilesRaw []byte
	if err := tx.QueryRow(ctx,
		`SELECT pr_number, pr_field_path, pr_expected_value, pr_proposed_files FROM incidents WHERE id = $1`, incidentID,
	).Scan(&prNumber, &fieldPath, &expectedValue, &proposedFilesRaw); err != nil {
		t.Fatalf("read incident: %v", err)
	}
	if prNumber == nil || *prNumber != 42 {
		t.Errorf("pr_number = %v, want 42", prNumber)
	}
	if fieldPath != nil || expectedValue != nil {
		t.Errorf("pr_field_path/pr_expected_value = %v/%v, want both NULL — a whole-file change records no single field", fieldPath, expectedValue)
	}
	if len(proposedFilesRaw) == 0 {
		t.Fatal("pr_proposed_files is NULL/empty, want the changed file recorded")
	}
	var proposed []prProposedFile
	if err := json.Unmarshal(proposedFilesRaw, &proposed); err != nil {
		t.Fatalf("unmarshal pr_proposed_files: %v", err)
	}
	if len(proposed) != 2 {
		t.Fatalf("pr_proposed_files has %d entries, want exactly 2 (the Unchanged file must not be recorded): %+v", len(proposed), proposed)
	}
	if proposed[0].Path != "envs/prod/deployment.yaml" || proposed[0].Content != "replicas: 3\n" || proposed[0].Deleted {
		t.Errorf("pr_proposed_files[0] = %+v, want {envs/prod/deployment.yaml, \"replicas: 3\\n\", Deleted: false}", proposed[0])
	}
	if proposed[1].Path != "envs/prod/hpa-a.yaml" || !proposed[1].Deleted || proposed[1].Content != "" {
		t.Errorf("pr_proposed_files[1] = %+v, want {envs/prod/hpa-a.yaml, \"\", Deleted: true}", proposed[1])
	}

	var state string
	if err := tx.QueryRow(ctx, `SELECT state FROM incidents WHERE id = $1`, incidentID).Scan(&state); err != nil {
		t.Fatalf("read state: %v", err)
	}
	if state != orchestrator.StateAwaitingMerge {
		t.Errorf("state = %q, want %q", state, orchestrator.StateAwaitingMerge)
	}
}

// TestVerifyMergedPullRequestFallsBackWhenNeitherIsRecorded is the regression
// guard BACKLOG.md F23 asks for: an incident whose pull request predates
// BOTH migration 000059 (pr_field_path/pr_expected_value) and migration
// 000075 (pr_proposed_files) — or whose bookkeeping write for either simply
// failed — must still get exactly the same honest "cannot tell" answer it
// got before this feature existed, so ValidationSweeper falls back to its
// quiet-grace-period behaviour rather than the sweep failing outright or
// (worse) silently treating this as held.
func TestVerifyMergedPullRequestFallsBackWhenNeitherIsRecorded(t *testing.T) {
	pool := authTestPool(t)
	_, _, incidentID, _ := timelineExecFixture(t, pool)

	s := &Server{db: &data.DB{Pool: pool}}
	held, detail, err := s.VerifyMergedPullRequest(context.Background(), incidentID)
	if err == nil {
		t.Fatalf("err = nil, want an error — held=%v detail=%q, and neither column is recorded on this fixture", held, detail)
	}
	if held {
		t.Error("held = true, want false alongside the error — an inconclusive check must never read as a positive assertion")
	}
}
