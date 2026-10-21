package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/execution"
	"argus/internal/remediation"
)

// TestRecordPolicyRefusal is BACKLOG.md L5's regression/proof test against a
// real Postgres: writePreparePlanExecutionError's eight execution.PreparePlan
// pre-flight sentinels must each leave a real, queryable audit_events row —
// before this fix, a real refusal (reproduced live on rke2 —
// CAPABILITIES.md §6z, an argus.io/protected-namespace block and a
// tier=data risk-floor block) left ZERO rows in audit_events, so the hub
// actively refusing a remediation on policy grounds was invisible to
// Insights, the audit trail, and everything else.
//
// This exercises the two cases CAPABILITIES.md §6z confirmed live
// (execution.ErrNamespaceProtectedRefused, execution.ErrRiskFloorRecheckRefused) plus one more
// (execution.ErrScaleFromZeroRefused, the guardrail path that goes through
// writeGuardrailRefusal rather than plain writeProblem) to prove the audit
// call fires on both shapes of branch, not just the plain-writeProblem
// majority.
//
// Unlike this package's other _db_test.go fixtures, this test does NOT
// clean up the rows it creates. audit_events is one single, global,
// hash-chained sequence (internal/audit's package doc, RecordEvent's own
// comment): deleting a row this test genuinely appended through the real
// chain (not a hand-crafted fake-hash row the way audit_export_db_test.go's
// fixture is, which DOES clean up for exactly this reason) would leave any
// row inserted after it — by this test run or by anything else touching
// this shared dev database in the meantime — pointing at a prev_hash whose
// row no longer exists, breaking `argusctl audit verify` for the real log.
// This matches the precedent already established by auth_test.go's login-
// failure denials, which go through the same real RecordEvent path and are
// also never deleted afterward.
func TestRecordPolicyRefusal(t *testing.T) {
	pool := analyzeDetachTestPool(t)
	ctx := context.Background()

	tenantID := func() string {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		id, err := data.SingleOrganisationID(ctx, tx)
		if err != nil {
			t.Fatalf("resolve organisation: %v", err)
		}
		return id
	}()

	s := &Server{db: &data.DB{Pool: pool}, guardrailTokens: authz.NewGuardrailConfirmationIssuer()}

	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantRule   string
	}{
		{
			name:       "namespace-protected refusal (CAPABILITIES.md §6z, live-reproduced)",
			err:        fmt.Errorf("%w: namespace %q is marked argus.io/protected", execution.ErrNamespaceProtectedRefused, "argus-e9-test-r4"),
			wantStatus: http.StatusConflict,
			wantRule:   "namespace-protected-refused",
		},
		{
			name:       "tier=data risk floor recheck refusal (CAPABILITIES.md §6z, live-reproduced)",
			err:        fmt.Errorf("%w: the real target is labelled tier=data", execution.ErrRiskFloorRecheckRefused),
			wantStatus: http.StatusConflict,
			wantRule:   "risk-floor-recheck-refused",
		},
		{
			name:       "scale-from-zero guardrail refusal (writeGuardrailRefusal path, not plain writeProblem)",
			err:        fmt.Errorf("%w: refusing to scale up from zero", execution.ErrScaleFromZeroRefused),
			wantStatus: http.StatusConflict,
			wantRule:   "scale-from-zero-refused",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			userID := domain.NewID(domain.PrefixUser)
			incidentID := domain.NewID(domain.PrefixIncident)
			planID := domain.NewID(domain.PrefixApproval)
			clusterID := domain.NewID(domain.PrefixCluster)

			rc := &requestContext{TenantID: tenantID, UserID: userID}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/"+incidentID+"/approve", nil)
			rec := httptest.NewRecorder()

			s.writePreparePlanExecutionError(ctx, rc, req, rec, incidentID, planID, clusterID, remediation.ActionScaleDeployment, c.err)

			if rec.Code != c.wantStatus {
				t.Fatalf("response status = %d, want %d (body: %s)", rec.Code, c.wantStatus, rec.Body.String())
			}

			// Read back through a request-scoped, RLS-respecting transaction
			// — audit_events has FORCE ROW LEVEL SECURITY, so an unscoped
			// read would silently see nothing rather than erroring
			// (internal/data's own documented RLS pitfall).
			readTx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin read tx: %v", err)
			}
			defer readTx.Rollback(ctx) //nolint:errcheck
			if err := data.SetRequestScope(ctx, readTx, tenantID, nil); err != nil {
				t.Fatalf("set request scope: %v", err)
			}

			var outcome, action, rule, gotPlanID, gotIncidentID, gotActionType string
			err = readTx.QueryRow(ctx,
				`SELECT outcome, details->>'action', details->>'rule', details->>'planId', details->>'incidentId', details->>'actionType'
				   FROM audit_events
				  WHERE tenant_id = $1 AND actor_id = $2 AND details->>'incidentId' = $3
				  ORDER BY occurred_at DESC LIMIT 1`,
				tenantID, userID, incidentID).Scan(&outcome, &action, &rule, &gotPlanID, &gotIncidentID, &gotActionType)
			if err != nil {
				t.Fatalf("expected a real audit_events row for this refusal, found none: %v", err)
			}

			if outcome != "denied" {
				t.Errorf("outcome = %q, want %q", outcome, "denied")
			}
			if action != "remediation_policy_refused" {
				t.Errorf("details.action = %q, want %q (must be distinguishable from a human's reject_remediation)", action, "remediation_policy_refused")
			}
			if rule != c.wantRule {
				t.Errorf("details.rule = %q, want %q", rule, c.wantRule)
			}
			if gotPlanID != planID {
				t.Errorf("details.planId = %q, want %q", gotPlanID, planID)
			}
			if gotIncidentID != incidentID {
				t.Errorf("details.incidentId = %q, want %q", gotIncidentID, incidentID)
			}
			if gotActionType != string(remediation.ActionScaleDeployment) {
				t.Errorf("details.actionType = %q, want %q", gotActionType, remediation.ActionScaleDeployment)
			}
		})
	}
}
