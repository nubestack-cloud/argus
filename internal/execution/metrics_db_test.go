package execution

// PROJECT.md T11's execution-outcomes metric, proven against the real
// chokepoint (recordExecutionOutcome) rather than merely against Counter's
// own already-unit-tested arithmetic — reuses timelineExecFixture, the same
// fixture execution_recovery_db_test.go's own reproductions build on.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"argus/internal/data"
	"argus/internal/metrics"
	"argus/internal/orchestrator"
)

func executionCounterValue(t *testing.T, actionType, kind, outcome string) float64 {
	t.Helper()
	var buf strings.Builder
	metrics.DefaultRegistry.WriteExposition(&buf)
	want := fmt.Sprintf(`argus_remediation_execution_total{action_type="%s",kind="%s",outcome="%s"} `, actionType, kind, outcome)
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(line, want) {
			var v float64
			if _, err := fmt.Sscanf(strings.TrimPrefix(line, want), "%g", &v); err != nil {
				t.Fatalf("parse counter line %q: %v", line, err)
			}
			return v
		}
	}
	return 0
}

func TestRemediationExecutionMetric_MovesOnForwardSuccess(t *testing.T) {
	pool := authTestPool(t)
	tenantID, clusterID, incidentID, planID := timelineExecFixture(t, pool)

	s := &Executor{db: &data.DB{Pool: pool}}
	rc := Scope{TenantID: tenantID}
	actor := Actor{UserID: "usr_test", AuthMethod: "jwt"}

	before := executionCounterValue(t, "PatchResourceLimits", "forward", "succeeded")

	if _, err := s.recordExecutionOutcome(context.Background(), rc, incidentID, planID, clusterID, actor,
		"succeeded", "", "rv-metrics-1", nil, "", forwardOutcomeStates(), "", "PatchResourceLimits", "forward"); err != nil {
		t.Fatalf("recordExecutionOutcome: %v", err)
	}

	after := executionCounterValue(t, "PatchResourceLimits", "forward", "succeeded")
	if after != before+1 {
		t.Fatalf(`argus_remediation_execution_total{action_type="PatchResourceLimits",kind="forward",outcome="succeeded"} went from %v to %v, want exactly +1`, before, after)
	}
}

func TestRemediationExecutionMetric_MovesOnUndoFailure(t *testing.T) {
	pool := authTestPool(t)
	tenantID, clusterID, incidentID, planID := timelineExecFixture(t, pool)

	s := &Executor{db: &data.DB{Pool: pool}}
	rc := Scope{TenantID: tenantID}
	actor := Actor{UserID: "usr_test", AuthMethod: "jwt"}

	setIncidentState(t, pool, tenantID, clusterID, incidentID, orchestrator.StateExecuting, orchestrator.StateValidating)

	before := executionCounterValue(t, "RevertContainerImage", "undo", "failed")

	if _, err := s.recordExecutionOutcome(context.Background(), rc, incidentID, planID, clusterID, actor,
		"failed", "the agent rejected the undo", "rv-metrics-2", nil, "", undoOutcomeStates(orchestrator.StateValidating), "", "RevertContainerImage", "undo"); err != nil {
		t.Fatalf("recordExecutionOutcome: %v", err)
	}

	after := executionCounterValue(t, "RevertContainerImage", "undo", "failed")
	if after != before+1 {
		t.Fatalf(`argus_remediation_execution_total{action_type="RevertContainerImage",kind="undo",outcome="failed"} went from %v to %v, want exactly +1`, before, after)
	}
}
