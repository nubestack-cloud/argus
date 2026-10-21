package api

import (
	"strings"
	"testing"

	"argus/internal/execution"
	"argus/internal/orchestrator"
)

// The pure half of internal/api/changes.go: the undo-availability decision and
// the merged-pull-request summary. The DB-backed round trip (the two queries,
// the window, the RLS cluster scope) is in changes_db_test.go.

// TestUndoForDelegatesEveryRefusalToCheckUndoable is the guard that matters on
// this file. The changes list must never carry its own paraphrase of an undo
// refusal: the whole point of the front door is that the answer it shows is the
// answer POST /executions/{id}/rollback would give. These cases assert the
// DELEGATION (the strings come back from checkUndoable), not the wording — a
// reworded refusal in rollback.go should change this screen with no edit here,
// which is exactly why the expectations below compare against checkUndoable's
// own output rather than against literals copied out of it.
func TestUndoForDelegatesEveryRefusalToCheckUndoable(t *testing.T) {
	cases := []struct {
		name string
		exec execution.UndoableExecution
	}{
		{
			name: "a failed execution",
			exec: execution.UndoableExecution{ID: "exec_1", IncidentID: "inc_1", Outcome: "failed", ActionType: "ScaleDeployment"},
		},
		{
			name: "an execution whose outcome could not be confirmed",
			exec: execution.UndoableExecution{ID: "exec_2", IncidentID: "inc_1", Outcome: "unknown", ActionType: "ScaleDeployment"},
		},
		{
			name: "an action type with no representable undo (a restart)",
			exec: execution.UndoableExecution{ID: "exec_3", IncidentID: "inc_1", Outcome: "succeeded", ActionType: ""},
		},
		{
			name: "an execution already undone",
			exec: execution.UndoableExecution{ID: "exec_4", IncidentID: "inc_1", Outcome: "succeeded", ActionType: "ScaleDeployment", AlreadyUndone: strPtr("exec_9")},
		},
		{
			name: "an incident with a signed plan in flight right now",
			exec: execution.UndoableExecution{ID: "exec_5", IncidentID: "inc_1", Outcome: "succeeded", ActionType: "ScaleDeployment", IncidentState: orchestrator.StateExecuting},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := execution.CheckUndoable(tc.exec)
			if want == nil {
				t.Fatalf("test setup bug: checkUndoable accepted %+v, so this case proves nothing", tc.exec)
			}
			got := undoFor(tc.exec, "scale back to 2 replica(s)")
			if got.Available {
				t.Fatalf("undo.available = true for %s — the rollback endpoint would refuse this with %q, and offering the control anyway sends an operator at a production cluster on a promise the hub will not keep", tc.name, want.Title)
			}
			if got.Reason != want.Title {
				t.Errorf("undo.reason = %q, want checkUndoable's own title %q", got.Reason, want.Title)
			}
			if got.Detail != want.Detail {
				t.Errorf("undo.detail = %q, want checkUndoable's own detail %q", got.Detail, want.Detail)
			}
			if got.ExecutionID != "" {
				t.Errorf("undo.executionId = %q on an unavailable undo, want empty — the list must not read as a menu of execution ids to try", got.ExecutionID)
			}
		})
	}
}

func TestUndoForOffersAnUndoCheckUndoableAccepts(t *testing.T) {
	exec := execution.UndoableExecution{
		ID: "exec_ok", IncidentID: "inc_1", Outcome: "succeeded",
		ActionType: "ScaleDeployment", IncidentState: orchestrator.StateValidating,
	}
	if problem := execution.CheckUndoable(exec); problem != nil {
		t.Fatalf("test setup bug: checkUndoable refused %+v (%s)", exec, problem.Title)
	}
	got := undoFor(exec, "scale back to 2 replica(s)")
	if !got.Available {
		t.Fatalf("undo.available = false (%s), want true", got.Reason)
	}
	if got.ExecutionID != "exec_ok" {
		t.Errorf("undo.executionId = %q, want the execution's own id — this is what POST /executions/{id}/rollback takes", got.ExecutionID)
	}
	if got.Description != "scale back to 2 replica(s)" {
		t.Errorf("undo.description = %q, want the captured compensating description", got.Description)
	}
	if got.Reason != "" || got.Detail != "" {
		t.Errorf("undo carries a refusal (%q / %q) while reporting available", got.Reason, got.Detail)
	}
}

// A compensating action with no description is not offerable: the confirmation
// an operator reads before mutating a production cluster IS the description.
func TestUndoForRefusesAnUndoItCannotDescribe(t *testing.T) {
	exec := execution.UndoableExecution{ID: "exec_nodesc", IncidentID: "inc_1", Outcome: "succeeded", ActionType: "ScaleDeployment"}
	got := undoFor(exec, "")
	if got.Available {
		t.Fatal("undo.available = true with no recorded description — the confirmation would name no consequence")
	}
	if got.Reason == "" || got.Detail == "" {
		t.Errorf("a refusal must say why: reason=%q detail=%q", got.Reason, got.Detail)
	}
}

func TestMergedPullRequestSummaryNeverFabricatesAFileCount(t *testing.T) {
	// A pull request opened before migration 000075 recorded its files. Saying
	// "0 files" about a change that definitely touched something is the
	// fabricated-zero failure this codebase keeps writing down.
	got := mergedPullRequestSummary(103, nil)
	if strings.Contains(got, "0 ") || strings.Contains(got, "file") {
		t.Errorf("summary with no recorded files = %q, want no claim about files at all", got)
	}
	if !strings.Contains(got, "#103") {
		t.Errorf("summary = %q, want the pull request number", got)
	}

	one := mergedPullRequestSummary(103, []string{"apps/web/deployment.yaml"})
	if !strings.Contains(one, "apps/web/deployment.yaml") {
		t.Errorf("single-file summary = %q, want the path named", one)
	}
	if strings.Contains(one, "more file") {
		t.Errorf("single-file summary = %q, want no \"and N more\"", one)
	}

	many := mergedPullRequestSummary(103, []string{"a.yaml", "b.yaml", "c.yaml"})
	if !strings.Contains(many, "a.yaml") || !strings.Contains(many, "2 more") {
		t.Errorf("multi-file summary = %q, want the first path plus a count of the rest", many)
	}

	// A pull request whose number was never recorded still gets an honest
	// summary rather than "#0".
	noNumber := mergedPullRequestSummary(0, []string{"a.yaml"})
	if strings.Contains(noNumber, "#0") {
		t.Errorf("summary = %q, want no fabricated pull request number", noNumber)
	}
}

func strPtr(s string) *string { return &s }
