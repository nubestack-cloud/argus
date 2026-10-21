package execution

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"argus/internal/orchestrator"
	"argus/internal/remediation"
)

// Every refusal, exhaustively, because this endpoint writes to a production
// cluster in the situation where something has already gone wrong — which is the
// worst moment to discover a check was missing.
func TestCheckUndoableRefusals(t *testing.T) {
	base := UndoableExecution{
		ID: "exec_1", IncidentID: "inc_1", PlanID: "plan_1", ClusterID: "cl_1",
		Outcome: "succeeded", ActionType: string(remediation.ActionScaleDeployment),
		Params: []byte(`{"replicas":2}`), Description: "scale back to 2 replica(s)",
	}

	t.Run("a succeeded execution with an undo is allowed", func(t *testing.T) {
		if p := CheckUndoable(base); p != nil {
			t.Fatalf("refused a valid undo: %s — %s", p.Title, p.Detail)
		}
	})

	t.Run("a failed execution is refused", func(t *testing.T) {
		e := base
		e.Outcome = "failed"
		p := CheckUndoable(e)
		if p == nil {
			t.Fatal("a failed execution was accepted. Its outcome is unknown by definition — the patch may have applied, partly applied, or not at all — so 'put it back' is not a truthful statement")
		}
		if p.Status != http.StatusConflict {
			t.Errorf("status = %d, want 409", p.Status)
		}
		if !strings.Contains(p.Detail, "Re-analyse") {
			t.Error("the refusal does not say what to do instead")
		}
	})

	t.Run("an action with no recorded undo is refused, and says why that is normal", func(t *testing.T) {
		e := base
		e.ActionType = ""
		p := CheckUndoable(e)
		if p == nil {
			t.Fatal("an execution with no compensating action was accepted")
		}
		// The message matters here: a RestartPod legitimately has no undo, and an
		// operator must not read that as a defect.
		if !strings.Contains(p.Detail, "restart") {
			t.Error("the refusal does not explain that a workload restart has no undo by nature")
		}
	})

	t.Run("an already-undone execution is refused, naming the undo", func(t *testing.T) {
		e := base
		undo := "exec_2"
		e.AlreadyUndone = &undo
		p := CheckUndoable(e)
		if p == nil {
			t.Fatal("an already-rolled-back execution was accepted. Applying the same compensating action twice restores a value it was not derived from")
		}
		if !strings.Contains(p.Detail, "exec_2") {
			t.Error("the refusal does not name the execution that already undid this one")
		}
	})

	t.Run("an empty rolled_back_by is not treated as undone", func(t *testing.T) {
		e := base
		empty := ""
		e.AlreadyUndone = &empty
		if p := CheckUndoable(e); p != nil {
			t.Errorf("a non-nil but empty rolled_back_by_execution_id read as already-undone: %s", p.Title)
		}
	})
}

// The undo must target the object the forward change targeted, and it must carry
// the recorded params rather than anything re-derived. Getting the target from
// the compensating action instead of the recommendation would be a second source
// of truth for the same fact.
func TestUndoPlanTargetsTheOriginalObject(t *testing.T) {
	e := UndoableExecution{
		ActionType: string(remediation.ActionScaleDeployment),
		Params:     []byte(`{"replicas":5}`),
		TargetGVK:  "apps/v1/Deployment", TargetNamespace: "prod", TargetName: "web",
	}
	plan, err := UndoPlan(e)
	if err != nil {
		t.Fatalf("UndoPlan: %v", err)
	}
	if plan.TargetGVK != "apps/v1/Deployment" || plan.TargetNamespace != "prod" || plan.TargetName != "web" {
		t.Errorf("undo targets %s %s/%s, want the original object", plan.TargetGVK, plan.TargetNamespace, plan.TargetName)
	}
	params, ok := plan.Params.(remediation.ScaleDeploymentParams)
	if !ok {
		t.Fatalf("params are %T, not ScaleDeploymentParams", plan.Params)
	}
	if params.Replicas != 5 {
		t.Errorf("undo would scale to %d, want the recorded 5", params.Replicas)
	}
	if !plan.Reversible {
		t.Error("an undo is reversible by construction — its own inverse is the value the forward change applied")
	}
}

// TestUndoPlanMarksRestoreVerified (PROJECT.md B171): UndoPlan must build its
// plan through remediation.NewVerifiedRestorePlan, not a literal
// RemediationPlan{...}, so that a live-state check downstream (this
// codebase's checkResourceLimitsBound) can tell "restoring an already-live
// value" apart from "a fresh proposal" — provably, not by trusting a flag
// this handler could set on any plan it liked. If UndoPlan ever regresses to
// the literal construction, this is the test that catches it.
func TestUndoPlanMarksRestoreVerified(t *testing.T) {
	e := UndoableExecution{
		ActionType: string(remediation.ActionPatchResourceLimits),
		Params:     []byte(`{"container":"web","memoryLimit":"4Mi","memoryRequest":"4Mi"}`),
		TargetGVK:  "apps/v1/Deployment", TargetNamespace: "prod", TargetName: "web",
	}
	plan, err := UndoPlan(e)
	if err != nil {
		t.Fatalf("UndoPlan: %v", err)
	}
	if !plan.RestoreVerified() {
		t.Error("UndoPlan's plan must report RestoreVerified() == true — it was built from a stored compensating action, never a fresh proposal")
	}
	params, ok := plan.Params.(remediation.PatchResourceLimitsParams)
	if !ok {
		t.Fatalf("params are %T, not PatchResourceLimitsParams", plan.Params)
	}
	if params.MemoryLimit != "4Mi" {
		t.Errorf("undo would restore memoryLimit %q, want 4Mi", params.MemoryLimit)
	}
	// A memory limit below internal/remediation's absolute minimum
	// (minMemoryQuantity, 16Mi) is exactly the shape that made this bug
	// visible live (T5): the compensating action for a container that was
	// OOMKilling under a 4Mi limit necessarily says "4Mi." UndoPlan itself
	// must not refuse to build that plan — it is PreparePlan's job (in
	// internal/execution, outside this package's reach) to
	// decide, using RestoreVerified(), whether the live-state bound still
	// permits applying it.
}

// TestCheckResourceLimitsBoundRefusesForwardLoweringButAllowsAVerifiedRestore
// is PROJECT.md B171's required negative control, and the assertion that the
// item is actually closed rather than merely wired.
//
// Rule 2 ("a memory limit may only be RAISED") exists because lowering the
// ceiling a running container already lives under is how a working workload
// becomes an OOMKilled one. It must keep refusing a fresh proposal
// unconditionally — that is the guard this item forbids weakening. What it
// must NOT refuse is the undo of a raise, which is a decrease by definition:
// its value was read off the live container moments before the forward change,
// so the workload demonstrably ran under it.
//
// The two halves are asserted together deliberately. Either one alone can
// pass for the wrong reason — the refusal half passes if the relaxation was
// never wired, and the restore half passes if rule 2 was simply deleted.
func TestCheckResourceLimitsBoundRefusesForwardLoweringButAllowsAVerifiedRestore(t *testing.T) {
	live := containerResources{MemoryLimit: "256Mi", MemoryRequest: "128Mi"}
	lowered := remediation.PatchResourceLimitsParams{Container: "web", MemoryLimit: "4Mi"}
	// A real captured undo restores the request alongside the limit — the
	// shape the compensating action actually carries ("restore container
	// \"web\" to memory limit 4Mi, memory request 4Mi"). Lowering the limit
	// ALONE would strand the live 128Mi request above a 4Mi ceiling, which
	// rule 4 refuses for a restore exactly as it does for a forward plan;
	// that case is asserted separately below.
	undo := remediation.PatchResourceLimitsParams{Container: "web", MemoryLimit: "4Mi", MemoryRequest: "4Mi"}

	// A fresh (model-authored or hand-authored) plan proposing to lower a
	// memory limit. Refused, and the relaxation below must not change that.
	if err := checkResourceLimitsBound(live, lowered, false); err == nil {
		t.Fatal("checkResourceLimitsBound accepted a memory-limit decrease from an ordinary plan — rule 2 must refuse this unconditionally")
	} else if !errors.Is(err, ErrResourceLimitsBoundRefused) {
		t.Errorf("error is %v, want it wrapped in ErrResourceLimitsBoundRefused", err)
	}

	// The SAME params, sourced from a verified restore plan exactly like
	// UndoPlan builds one. This is the undo an operator asked for, and it is
	// now executable.
	restorePlan, err := remediation.NewVerifiedRestorePlan(remediation.ActionPatchResourceLimits, undo, "apps/v1/Deployment", "prod", "web")
	if err != nil {
		t.Fatalf("NewVerifiedRestorePlan: %v", err)
	}
	if !restorePlan.RestoreVerified() {
		t.Fatal("sanity: restorePlan should report RestoreVerified() == true")
	}
	restoreParams, ok := restorePlan.Params.(remediation.PatchResourceLimitsParams)
	if !ok {
		t.Fatalf("params are %T, not PatchResourceLimitsParams", restorePlan.Params)
	}
	if err := checkResourceLimitsBound(live, restoreParams, restorePlan.RestoreVerified()); err != nil {
		t.Fatalf("checkResourceLimitsBound refused a verified restore of a memory limit: %v — this is the whole of B171; the captured undo must be executable", err)
	}

	// Provenance is the ONLY thing that relaxes rule 2. The same params with
	// the flag false are still refused, so an ordinary plan cannot reach the
	// relaxed path by carrying restore-shaped values.
	if err := checkResourceLimitsBound(live, restoreParams, false); err == nil {
		t.Fatal("restore-shaped params were accepted without the provenance flag — the relaxation must key on RestoreVerified(), not on what the values look like")
	}

	// Every OTHER rule still applies to a verified restore. Rule 4: the
	// post-patch request must not exceed the post-patch limit, so a restore
	// that would strand the live 128Mi request above a 4Mi limit is refused
	// even though it is a genuine undo.
	strands := remediation.PatchResourceLimitsParams{Container: "web", MemoryLimit: "4Mi"}
	if err := checkResourceLimitsBound(containerResources{MemoryLimit: "256Mi", MemoryRequest: "128Mi"}, strands, true); err == nil {
		t.Error("a verified restore that leaves the live memory request above the restored limit was accepted — rule 4 must still apply to an undo")
	}

	// And the "will not introduce a limit where none exists" refusal, which
	// is about QoS class rather than magnitude, is equally unaffected.
	if err := checkResourceLimitsBound(containerResources{MemoryRequest: "128Mi"}, lowered, true); err == nil {
		t.Error("a verified restore was allowed to introduce a memory limit the container does not have — that rule is about QoS class, not direction, and must still apply")
	}
}

// pick is what keeps the live-value comparison honest: it compares only the field
// the forward change actually set, not whatever else the container has configured.
func TestPickComparesOnlyTheChangedField(t *testing.T) {
	if got := pick("", "128Mi"); got != "" {
		t.Errorf("pick(\"\", live) = %q, want empty — the undo does not name this field, so it was not the one changed", got)
	}
	if got := pick("64Mi", "128Mi"); got != "128Mi" {
		t.Errorf("pick(named, live) = %q, want the live value", got)
	}
}

// singleAppliedValue must return empty for a multi-field change rather than
// picking one, because there is then no single scalar an undo can be compared
// against and pretending otherwise would assert a check that was not made.
func TestSingleAppliedValueRefusesToGuess(t *testing.T) {
	one := remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: "256Mi"}
	if got := singleAppliedValue(one); got != "256Mi" {
		t.Errorf("one field set -> %q, want 256Mi", got)
	}
	two := remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: "256Mi", CPULimit: "500m"}
	if got := singleAppliedValue(two); got != "" {
		t.Errorf("two fields set -> %q, want empty so the undo relies on the resourceVersion precondition and says so", got)
	}
	if got := singleAppliedValue(remediation.PatchResourceLimitsParams{Container: "app"}); got != "" {
		t.Errorf("no fields set -> %q, want empty", got)
	}
}

// The incident-state half of the refusal. Before this, handleRollback looked
// only at the execution's own outcome, so an undo could be applied to an
// incident mid-execution — and, worse, to one whose state had no legal
// destination, which meant the cluster was changed and then the record of
// having changed it was rolled back.
func TestCheckUndoableIncidentState(t *testing.T) {
	base := UndoableExecution{
		ID: "exec_1", IncidentID: "inc_1", PlanID: "plan_1", ClusterID: "cl_1",
		Outcome: "succeeded", ActionType: string(remediation.ActionScaleDeployment),
		Params: []byte(`{"replicas":2}`), Description: "scale back to 2 replica(s)",
	}

	t.Run("refused while another change is in flight", func(t *testing.T) {
		e := base
		e.IncidentState = orchestrator.StateExecuting
		p := CheckUndoable(e)
		if p == nil {
			t.Fatal("an undo was accepted on an incident with a signed plan in flight — two writers would race to describe the same object, and the value being restored predates a change that has not finished")
		}
		if p.Status != http.StatusConflict {
			t.Errorf("status = %d, want 409", p.Status)
		}
		if !strings.Contains(p.Detail, "Nothing was changed") {
			t.Error("the refusal does not tell the operator that nothing was changed")
		}
	})

	// Every other state is allowed through deliberately — the refusal that
	// matters is the one made BEFORE the cluster is touched, and where an undo
	// has a sensible answer the answer is given rather than withheld.
	for _, state := range []string{
		orchestrator.StateValidating, orchestrator.StateReopened, orchestrator.StateResolved,
		orchestrator.StateDismissed, orchestrator.StateFailed, orchestrator.StateExecutionUnknown,
		orchestrator.StateInvestigating, orchestrator.StateAwaitingApproval, orchestrator.StateAwaitingMerge,
		orchestrator.StateDetected, orchestrator.StateNeedsHumanInvestigation, orchestrator.StateDiagnosed,
	} {
		t.Run("allowed from "+state, func(t *testing.T) {
			e := base
			e.IncidentState = state
			if p := CheckUndoable(e); p != nil {
				t.Errorf("refused an undo from %s: %s — %s", state, p.Title, p.Detail)
			}
		})
	}
}

// What an undo does to the incident, from each state it can legally start
// from. The table is the decision, so the test is the table: an undo is a
// statement about the cluster, and Validating is the single state where
// leaving the incident alone would be a lie (the validation sweeper would
// resolve it on a grace period that started while the fix was still applied).
func TestUndoOutcomeStates(t *testing.T) {
	t.Run("from Validating a successful undo reopens", func(t *testing.T) {
		got := undoOutcomeStates(orchestrator.StateValidating)
		if got.Succeeded != orchestrator.StateReopened {
			t.Errorf("Succeeded = %q, want %q", got.Succeeded, orchestrator.StateReopened)
		}
		if got.Failed != "" || got.Unknown != "" {
			t.Errorf("Failed = %q, Unknown = %q, want both empty — the remediation did not fail, the attempt to take it back did", got.Failed, got.Unknown)
		}
	})

	for _, state := range []string{
		orchestrator.StateResolved, orchestrator.StateDismissed, orchestrator.StateReopened,
		orchestrator.StateFailed, orchestrator.StateExecutionUnknown, orchestrator.StateInvestigating,
		orchestrator.StateAwaitingApproval, orchestrator.StateAwaitingMerge, orchestrator.StateDetected,
		orchestrator.StateNeedsHumanInvestigation, orchestrator.StateDiagnosed,
	} {
		t.Run("from "+state+" an undo changes no state at all", func(t *testing.T) {
			got := undoOutcomeStates(state)
			if got != (incidentOutcomeStates{}) {
				t.Errorf("undoOutcomeStates(%q) = %+v, want every destination empty", state, got)
			}
		})
	}
}

// Every destination this product can ask for must be one the state machine
// will actually accept from the state it is asked from — otherwise the
// transition is refused at the moment a cluster has already been changed. This
// is the property the two lost-record faults violated, asserted directly
// against orchestrator's own edge set rather than against a copy of it.
func TestExecutionDestinationsAreReachableFromWhereTheyAreUsed(t *testing.T) {
	forward := forwardOutcomeStates()
	for _, want := range []string{forward.Succeeded, forward.Failed, forward.Unknown} {
		if !orchestrator.CanTransition(orchestrator.StateExecuting, want) {
			t.Errorf("a forward execution can land on %q, which is not reachable from %q", want, orchestrator.StateExecuting)
		}
	}
	if got := undoOutcomeStates(orchestrator.StateValidating).Succeeded; !orchestrator.CanTransition(orchestrator.StateValidating, got) {
		t.Errorf("a successful undo from %q lands on %q, which is not reachable from it", orchestrator.StateValidating, got)
	}
}

// TestInterpretDeletionVerificationResult is PROJECT.md B140's regression
// test: a genuinely successful DeleteResource execution used to be
// unconditionally unassertable (VerifyAppliedValue returned an error for
// every action type with no recorded ForwardApplied), which meant the
// incident could never reach Resolved/remediated and always landed in
// ValidationUnknown after the deadline elapsed — even though the object was
// confirmed gone. Mirrors TestInterpretAbsenceCheckResult's three cases,
// same describe_resource result, opposite meaning for each (see this
// function's own doc comment for why).
func TestInterpretDeletionVerificationResult(t *testing.T) {
	t.Run("describe_resource failed with not-found text: deletion held", func(t *testing.T) {
		// The exact wrapped shape callers see over the tunnel: sanitizeK8sErr's
		// fixed string, wrapped by the gateway/tool-call machinery.
		wrapped := fmt.Errorf("describe v1/PersistentVolumeClaim payments/bad-storage-class: %w", errors.New(remediation.ErrResourceNotFoundMessage))
		held, detail, err := interpretDeletionVerificationResult("v1/PersistentVolumeClaim", "payments", "bad-storage-class", wrapped)
		if err != nil {
			t.Fatalf("interpretDeletionVerificationResult(not-found error) = err %v, want nil (confirmed still deleted)", err)
		}
		if !held {
			t.Error("held = false, want true — the object is confirmed gone, so the deletion holds")
		}
		if !strings.Contains(detail, "still gone") {
			t.Errorf("detail %q does not say the object is still gone", detail)
		}
	})

	t.Run("describe_resource succeeded: object exists again, deletion did not hold", func(t *testing.T) {
		held, detail, err := interpretDeletionVerificationResult("v1/PersistentVolumeClaim", "payments", "bad-storage-class", nil)
		if err != nil {
			t.Fatalf("interpretDeletionVerificationResult(nil error) = err %v, want nil (a real recurrence, not an assertion failure)", err)
		}
		if held {
			t.Error("held = true, want false — the object exists again, so the deletion did not hold")
		}
		if !strings.Contains(detail, "exists again") {
			t.Errorf("detail %q does not say the object exists again", detail)
		}
	})

	t.Run("describe_resource failed for an unrelated reason: ambiguous, no assertion", func(t *testing.T) {
		held, _, err := interpretDeletionVerificationResult("v1/PersistentVolumeClaim", "payments", "bad-storage-class", errors.New("permission denied"))
		if err == nil {
			t.Fatal("interpretDeletionVerificationResult(ambiguous error) = nil error, want a refusal — deletion could not be confirmed held")
		}
		if held {
			t.Error("held = true alongside a non-nil error — an ambiguous result must never be reported as held")
		}
		if !strings.Contains(err.Error(), "could not confirm") {
			t.Errorf("error %q does not say the assertion could not be made", err.Error())
		}
	})
}

// TestCompareResourceLimitsHeld is the multi-field PatchResourceLimits
// verification added for T5, found live 2026-09-17: a successful in-place
// remediation that set BOTH a memory request and a memory limit had no single
// scalar in remediation_executions.forward_applied_value, so
// VerifyAppliedValue could not assert anything and the sweeper logged "the
// change itself could not be re-checked" once a minute on its way to
// ValidationUnknown — for a fix whose pod was back to 1/1 Running.
//
// The sweeper REOPENS an incident on held=false, so the false cases matter as
// much as the true one: every "we cannot tell" must be an error, never false.
func TestCompareResourceLimitsHeld(t *testing.T) {
	const gvk, ns, name = "apps/v1/Deployment", "default", "t5-checkout-api"
	planned := remediation.PatchResourceLimitsParams{Container: "web", MemoryLimit: "128Mi", MemoryRequest: "64Mi"}

	t.Run("every field the plan set still holds", func(t *testing.T) {
		held, detail, err := compareResourceLimitsHeld(planned,
			containerResources{MemoryLimit: "128Mi", MemoryRequest: "64Mi", CPULimit: "200m", CPURequest: "25m"}, gvk, ns, name)
		if err != nil || !held {
			t.Fatalf("held=%v err=%v, want held with no error (detail: %q)", held, err, detail)
		}
		// The assertion has to say what was actually checked — "it resolved"
		// with no statement of what held is the thing V1 exists to stop.
		for _, want := range []string{"memory limit 128Mi", "memory request 64Mi", "web"} {
			if !strings.Contains(detail, want) {
				t.Errorf("detail %q does not name %q", detail, want)
			}
		}
		// A field the plan never set must not be asserted about.
		if strings.Contains(detail, "cpu") {
			t.Errorf("detail %q asserts about a field this plan never set", detail)
		}
	})

	t.Run("equal values in different notation are not a reverted change", func(t *testing.T) {
		// The API server serializes what it stores, so this is what a live
		// read legitimately looks like. A string comparison would call this a
		// revert and reopen a correctly fixed incident.
		held, detail, err := compareResourceLimitsHeld(planned,
			containerResources{MemoryLimit: "134217728", MemoryRequest: "65536Ki"}, gvk, ns, name)
		if err != nil || !held {
			t.Fatalf("held=%v err=%v, want held: 134217728 == 128Mi and 65536Ki == 64Mi (detail: %q)", held, err, detail)
		}
	})

	t.Run("one field moved is a reverted change, and names which", func(t *testing.T) {
		held, detail, err := compareResourceLimitsHeld(planned,
			containerResources{MemoryLimit: "128Mi", MemoryRequest: "4Mi"}, gvk, ns, name)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if held {
			t.Fatal("held=true although the memory request was moved back to 4Mi")
		}
		if !strings.Contains(detail, "memory request") || !strings.Contains(detail, "4Mi") {
			t.Errorf("detail %q does not say which field moved and to what", detail)
		}
	})

	t.Run("a field the plan set that is now absent is a reverted change", func(t *testing.T) {
		held, detail, err := compareResourceLimitsHeld(planned,
			containerResources{MemoryLimit: "128Mi"}, gvk, ns, name)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if held {
			t.Fatal("held=true although the memory request is gone entirely")
		}
		if !strings.Contains(detail, "memory request") {
			t.Errorf("detail %q does not name the missing field", detail)
		}
	})

	t.Run("an unreadable value is an error, never held=false", func(t *testing.T) {
		if _, _, err := compareResourceLimitsHeld(planned,
			containerResources{MemoryLimit: "128Mi", MemoryRequest: "sixty-four megs"}, gvk, ns, name); err == nil {
			t.Error("an unreadable live value returned no error — the sweeper would reopen a healthy incident on ignorance")
		}
		if _, _, err := compareResourceLimitsHeld(
			remediation.PatchResourceLimitsParams{Container: "web", MemoryLimit: "a lot"},
			containerResources{MemoryLimit: "128Mi"}, gvk, ns, name); err == nil {
			t.Error("an unreadable planned value returned no error")
		}
	})

	t.Run("a plan naming nothing is an error, not a vacuous pass", func(t *testing.T) {
		if held, _, err := compareResourceLimitsHeld(
			remediation.PatchResourceLimitsParams{Container: "web"},
			containerResources{MemoryLimit: "128Mi"}, gvk, ns, name); err == nil || held {
			t.Error("a plan with no fields verified nothing and reported success")
		}
	})
}
