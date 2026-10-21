package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"argus/internal/authz"
	"argus/internal/execution"
	"argus/internal/gateway"
	"argus/internal/orchestrator"
	"argus/internal/remediation"
)

// TestHandleRejectIncidentRequiresNonEmptyReason is the DB-free slice of
// handleRejectIncident: a missing or blank reason must be rejected with 400
// before any query ever reaches rc.Tx (a nil Tx here would panic if the
// handler tried) — mirroring
// TestHandleListIncidentsRejectsInvalidState's own "reject before the query"
// pattern in incidents_test.go. Everything past this check needs a live
// Postgres connection (the incident-state lookup, the plan lookup, the
// decision insert, the state transition) and is covered by
// scripts/smoke-test.sh instead.
func TestHandleRejectIncidentRequiresNonEmptyReason(t *testing.T) {
	s := &Server{}
	cases := []struct {
		name string
		body string
	}{
		{"missing reason field", `{}`},
		{"empty string reason", `{"reason":""}`},
		{"whitespace-only reason", `{"reason":"   "}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/inc_x/reject", strings.NewReader(c.body))
			rec := httptest.NewRecorder()

			s.handleRejectIncident(rec, req, &requestContext{})

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
		})
	}
}

// TestHandleRejectIncidentRejectsMalformedBody confirms a body that isn't
// even valid JSON fails the same way every other POST handler in this
// codebase does (400 malformed-request), before the reason-required check
// ever runs.
func TestHandleRejectIncidentRejectsMalformedBody(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/inc_x/reject", strings.NewReader(`not json`))
	rec := httptest.NewRecorder()

	s.handleRejectIncident(rec, req, &requestContext{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestDecodeApproveRequestDefaultsToUnconfirmed is the contract the
// scale-from-zero guardrail rests on at the wire level: nothing short of the
// flag being explicitly true may come out true. An absent body (this
// endpoint's long-standing calling convention — scripts/smoke-test.sh
// approves with no body at all, and so did every UI build before this
// guardrail existed) and an empty object must both decode to "no
// confirmation given", so that approving from a queue can never turn a
// deliberately switched-off workload back on by omission.
func TestDecodeApproveRequestDefaultsToUnconfirmed(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"no body at all", ``, false},
		{"empty object", `{}`, false},
		{"explicitly false", `{"confirmScaleFromZero":false}`, false},
		{"JSON null body", `null`, false},
		{"an unrelated field only", `{"somethingElse":true}`, false},
		{"explicitly true — the only way through", `{"confirmScaleFromZero":true}`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, err := decodeApproveRequest(strings.NewReader(c.body))
			if err != nil {
				t.Fatalf("decodeApproveRequest(%q) error = %v, want nil", c.body, err)
			}
			if req.ConfirmScaleFromZero != c.want {
				t.Errorf("decodeApproveRequest(%q).ConfirmScaleFromZero = %v, want %v", c.body, req.ConfirmScaleFromZero, c.want)
			}
		})
	}
}

// TestHandleApproveIncidentRejectsMalformedBody mirrors reject's own
// malformed-body test: a body that tried to say something and failed is
// rejected with 400 before any query reaches rc.Tx (a nil Tx here would
// panic if the handler got that far), rather than being silently read as the
// absent-body default.
func TestHandleApproveIncidentRejectsMalformedBody(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/inc_x/approve", strings.NewReader(`{"confirmScaleFromZero":`))
	rec := httptest.NewRecorder()

	s.handleApproveIncident(rec, req, &requestContext{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestPlanApprovalGatesCoverEveryActionType guards the closed table Bug 1's fix
// depends on: every action type remediation.validActionTypes knows about must
// have an approval gate, or approving it would 500 instead of executing (fail
// closed, but still a bug), and the in-place/PR split must be exactly what
// lld/02-authz-spec.md §6's "PR-only, never in-place" pattern needs.
func TestPlanApprovalGatesCoverEveryActionType(t *testing.T) {
	// Asserted against remediation.AllActionTypes() rather than a restated
	// literal list — BUGS.md 78 was exactly this test's blind spot: PatchField
	// was added to remediation.validActionTypes without a matching
	// planApprovalGates entry, and a hand-copied list here would have kept
	// missing it right along with the production code.
	for _, actionType := range remediation.AllActionTypes() {
		gate, ok := planApprovalGates[actionType]
		if !ok {
			t.Fatalf("planApprovalGates has no entry for %q — approving it would 500 instead of executing (BUGS.md 78)", actionType)
		}
		if gate.effect == nil {
			t.Fatalf("planApprovalGates[%q].effect is nil — the 403 would panic building itself", actionType)
		}
		if got := gate.effect(remediation.RemediationPlan{ActionType: actionType}); got == "" {
			t.Errorf("planApprovalGates[%q].effect(...) is empty — the 403 would not explain itself", actionType)
		}
	}

	if got := planApprovalGates[remediation.ActionPatchField].capability; got != authz.CapRemediationExecInplace {
		t.Errorf("PatchField gate = %q, want %q — it patches the live cluster in place (BUGS.md 78)", got, authz.CapRemediationExecInplace)
	}
	// The effect string is the whole point of making this a function of the
	// plan: PatchField's name alone says nothing about which field it
	// touches, so a real plan's params must show up in the message a denied
	// approver reads.
	patchFieldPlan := remediation.RemediationPlan{
		ActionType: remediation.ActionPatchField,
		Params:     remediation.PatchFieldParams{FieldPath: "spec.ports[0].targetPort", NewValue: "9090"},
	}
	if got := planApprovalGates[remediation.ActionPatchField].effect(patchFieldPlan); !strings.Contains(got, "spec.ports[0].targetPort") || !strings.Contains(got, "9090") {
		t.Errorf("PatchField effect(plan) = %q, want it to name the plan's own field path and value", got)
	}

	if got := planApprovalGates[remediation.ActionScaleDeployment].capability; got != authz.CapRemediationExecInplace {
		t.Errorf("ScaleDeployment gate = %q, want %q — it patches the live cluster", got, authz.CapRemediationExecInplace)
	}
	if got := planApprovalGates[remediation.ActionRestartPod].capability; got != authz.CapRemediationExecInplace {
		t.Errorf("RestartPod gate = %q, want %q — it patches the live cluster", got, authz.CapRemediationExecInplace)
	}
	if got := planApprovalGates[remediation.ActionPatchResourceLimits].capability; got != authz.CapRemediationExecInplace {
		t.Errorf("PatchResourceLimits gate = %q, want %q — it patches the live cluster", got, authz.CapRemediationExecInplace)
	}
	if got := planApprovalGates[remediation.ActionRevertContainerImage].capability; got != authz.CapRemediationExecInplace {
		t.Errorf("RevertContainerImage gate = %q, want %q — it patches the live cluster", got, authz.CapRemediationExecInplace)
	}
	if got := planApprovalGates[remediation.ActionOpenPR].capability; got != authz.CapRemediationExecPR {
		t.Errorf("OpenPR gate = %q, want %q — it never touches a cluster", got, authz.CapRemediationExecPR)
	}

	// The §6 grant pattern itself: "may approve PRs but never touch a cluster
	// in place" must be expressible as a capability set, and must actually
	// separate the two channels.
	prOnly := grantsFor(authz.CapRemediationApprove, authz.CapRemediationExecPR)
	if !authz.HasCapability(prOnly, planApprovalGates[remediation.ActionOpenPR].capability) {
		t.Error("a PR-only grant cannot approve an OpenPR plan — §6's pattern is still not expressible")
	}
	if authz.HasCapability(prOnly, planApprovalGates[remediation.ActionScaleDeployment].capability) {
		t.Error("a PR-only grant satisfies the in-place gate — this is exactly Bug 1")
	}
}

// stubRow is a canned pgx.Row: it assigns pre-set values into whatever the
// caller's Scan destinations are.
type stubRow struct {
	values []any
}

func (r stubRow) Scan(dest ...any) error {
	if len(dest) != len(r.values) {
		return fmt.Errorf("stubRow: handler scanned %d columns, stub supplies %d", len(dest), len(r.values))
	}
	for i := range dest {
		target := reflect.ValueOf(dest[i])
		if target.Kind() != reflect.Pointer {
			return fmt.Errorf("stubRow: destination %d is not a pointer", i)
		}
		value := reflect.ValueOf(r.values[i])
		if !value.IsValid() {
			return fmt.Errorf("stubRow: value %d is untyped nil; use a typed nil", i)
		}
		if !value.Type().AssignableTo(target.Elem().Type()) {
			return fmt.Errorf("stubRow: value %d of type %s is not assignable to %s", i, value.Type(), target.Elem().Type())
		}
		target.Elem().Set(value)
	}
	return nil
}

// stubTx is a read-only pgx.Tx stand-in that answers handleApproveIncident's
// lookups from canned rows, matched by a distinctive fragment of each query.
// pgx.Tx is embedded as a nil interface on purpose: any method these tests'
// code path does NOT expect to be reached panics loudly instead of quietly
// returning a zero value — which is what makes "the handler stopped at the
// capability check and executed nothing" a real assertion rather than an
// assumption.
type stubTx struct {
	pgx.Tx
	rows map[string][]any
	t    *testing.T
}

func (tx *stubTx) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	for fragment, values := range tx.rows {
		if strings.Contains(sql, fragment) {
			return stubRow{values: values}
		}
	}
	tx.t.Fatalf("stubTx: unexpected query: %s", sql)
	return nil
}

func (tx *stubTx) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	tx.t.Fatalf("stubTx: unexpected write, the request should not have got this far: %s", sql)
	return pgconn.CommandTag{}, nil
}

// approvableIncidentTx builds the stub transaction handleApproveIncident sees
// for an incident that is genuinely AwaitingApproval with one not-yet-approved
// plan of the given action type — i.e. everything up to the capability check
// passes, so what the handler does next is decided purely by the caller's
// grants.
func approvableIncidentTx(t *testing.T, actionType remediation.ActionType, params map[string]any) *stubTx {
	t.Helper()
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	namespace := "default"
	return &stubTx{
		t: t,
		rows: map[string][]any{
			// incidentState
			"SELECT state FROM incidents": {orchestrator.StateAwaitingApproval},
			// latestRecommendationForIncident
			"SELECT id, cluster_id FROM remediation_recommendations": {"rec_1", "cl_1"},
			// the already-approved check
			"SELECT EXISTS": {false},
			// the superseded-by-a-pull-request check (migration 000049). A nil
			// URL is the ordinary case: no source fix has been proposed, so the
			// in-place plan is still the current recommendation.
			"SELECT superseded_by_url": {(*string)(nil)},
			// loadRecommendationPlan
			"SELECT incident_id, analysis_id": {
				"inc_1", "an_1", string(actionType), "apps/v1/Deployment", &namespace, "api",
				paramsJSON, true, string(remediation.RiskLow),
			},
		},
	}
}

// TestHandleApproveIncidentRequiresExecutionCapability is Bug 1's regression
// test: POST /api/v1/incidents/{id}/approve now really does mutate a customer
// cluster for a ScaleDeployment/RestartPod plan (internal/execution), so
// remediation:approve alone must no longer be enough for it — while the same
// route must still let a PR-only approver through for an OpenPR plan.
//
// The allowed in-place case asserts 503, not 200: s.gw is a real but empty
// Gateway, so the handler gets past the capability gate and stops at its
// "cluster not connected" check — which proves the gate passed without any
// stub write ever being reached (stubTx.Exec fails the test if it is).
func TestHandleApproveIncidentRequiresExecutionCapability(t *testing.T) {
	cases := []struct {
		name         string
		actionType   remediation.ActionType
		params       map[string]any
		grants       []authz.EffectiveGrant
		wantStatus   int
		wantMentions string
	}{
		{
			name:         "approve alone cannot execute in place",
			actionType:   remediation.ActionScaleDeployment,
			params:       map[string]any{"replicas": 3},
			grants:       grantsFor(authz.CapRemediationApprove),
			wantStatus:   http.StatusForbidden,
			wantMentions: authz.CapRemediationExecInplace,
		},
		{
			name:       "PR-only approver cannot scale in place",
			actionType: remediation.ActionScaleDeployment,
			params:     map[string]any{"replicas": 3},
			// lld/02-authz-spec.md §6's headline pattern: "may approve PRs but
			// never touch a cluster in place".
			grants:       grantsFor(authz.CapRemediationApprove, authz.CapRemediationExecPR),
			wantStatus:   http.StatusForbidden,
			wantMentions: authz.CapRemediationExecInplace,
		},
		{
			name:         "PR-only approver cannot restart in place",
			actionType:   remediation.ActionRestartPod,
			params:       map[string]any{},
			grants:       grantsFor(authz.CapRemediationApprove, authz.CapRemediationExecPR),
			wantStatus:   http.StatusForbidden,
			wantMentions: authz.CapRemediationExecInplace,
		},
		{
			name:         "in-place executor without the PR capability cannot approve an OpenPR plan",
			actionType:   remediation.ActionOpenPR,
			params:       map[string]any{"repository": "org/repo", "files": []any{map[string]any{"path": "envs/prod/d.yaml", "content": "spec:\n  replicas: 3\n"}}},
			grants:       grantsFor(authz.CapRemediationApprove, authz.CapRemediationExecInplace),
			wantStatus:   http.StatusForbidden,
			wantMentions: authz.CapRemediationExecPR,
		},
		{
			name:       "approve plus in-place executor gets past the gate",
			actionType: remediation.ActionScaleDeployment,
			params:     map[string]any{"replicas": 3},
			grants:     grantsFor(authz.CapRemediationApprove, authz.CapRemediationExecInplace),
			// Past the gate, stopped by the disconnected cluster — nothing
			// executed, nothing recorded.
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name:         "PR-only approver cannot patch a field in place",
			actionType:   remediation.ActionPatchField,
			params:       map[string]any{"fieldPath": "spec.progressDeadlineSeconds", "newValue": "900"},
			grants:       grantsFor(authz.CapRemediationApprove, authz.CapRemediationExecPR),
			wantStatus:   http.StatusForbidden,
			wantMentions: authz.CapRemediationExecInplace,
		},
		{
			// BUGS.md 78's regression case: before the fix, planApprovalGates had
			// no entry for PatchField at all, so approving one 500'd here with
			// "Could not determine which capability approving this plan
			// requires" regardless of grants. It must now behave exactly like
			// every other in-place action type — reach the same disconnected-
			// cluster stop, never a 500.
			name:       "approve plus in-place executor gets past the gate for PatchField",
			actionType: remediation.ActionPatchField,
			params:     map[string]any{"fieldPath": "spec.progressDeadlineSeconds", "newValue": "900"},
			grants:     grantsFor(authz.CapRemediationApprove, authz.CapRemediationExecInplace),
			wantStatus: http.StatusServiceUnavailable,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := serverWithUnreachableAuditDB(t)
			s.gw = gateway.NewGateway(nil, nil, nil) // no cluster is ever connected

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/inc_1/approve", nil)
			req.SetPathValue("id", "inc_1")

			s.handleApproveIncident(rec, req, &requestContext{
				Tx:       approvableIncidentTx(t, c.actionType, c.params),
				UserID:   "usr_1",
				TenantID: "org_1",
				Grants:   c.grants,
			})

			if rec.Code != c.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, c.wantStatus, rec.Body.String())
			}
			if c.wantMentions != "" && !strings.Contains(rec.Body.String(), c.wantMentions) {
				t.Errorf("403 body does not name the missing capability %q: %s", c.wantMentions, rec.Body.String())
			}
			if c.wantStatus == http.StatusForbidden && !strings.Contains(rec.Body.String(), authz.CapRemediationApprove) {
				t.Errorf("403 body should also name the capability the caller DOES hold, for a usable message: %s", rec.Body.String())
			}
		})
	}
}

// TestWritePreparePlanExecutionError is BUGS.md 95's regression test:
// handleApproveIncident's classification of an execution.ExecuteApprovedPlan failure
// (approvals.go's writePreparePlanExecutionError, split out of the handler
// specifically so this is testable without a live DB/gateway/transaction —
// everything downstream of an execution.PreparePlan failure is already decided by the
// time this function runs) must tell a pre-flight refusal ("we understood
// perfectly and are declining, nothing was signed/sent/recorded") apart from
// a genuine execution failure ("we tried and something broke").
//
// Before this fix, only execution.ErrScaleFromZeroRefused/execution.ErrGitOpsManagedRefused had
// this treatment; checkResourceLimitsBound's refusal (the case actually
// reproduced live on rke2 — CAPABILITIES.md §6l) fell through to the same
// 502 remediation-execution-failed a disconnected cluster or a signing
// failure would produce, indistinguishable from an actual attempted-and-failed
// execution. This table covers all six execution.PreparePlan pre-flight sentinels plus
// the two response shapes that must NOT change: execution.ErrPlanAlreadyDecided's own
// 409, and a genuinely unclassified error's 502 fallback (proving this
// change narrowed the 502 bucket, not removed it).
//
// The "incident stays untouched at AwaitingApproval" half of BUGS.md 95 is
// not re-verified here: it is a structural property of the calling code, not
// of this classification step — execution.PreparePlan (and preparePlanWithCorrection)
// return their error BEFORE execution.ExecuteApprovedPlan's recordExecutingTransition
// ever runs (internal/execution's ExecuteApprovedPlan, the
// preparePlanWithCorrection call precedes the Executing-transition commit by
// construction), so no sentinel this function sees was ever produced after a
// signed plan reached the cluster. That ordering is identical for all six
// sentinels below — it is what already made execution.ErrScaleFromZeroRefused/
// execution.ErrGitOpsManagedRefused's 409 honest, and this change adds no new call
// site that could violate it.
//
// BACKLOG.md L5 (2026-08-30) added ctx/rc/r/clusterID/actionType parameters
// so each sentinel branch can also call recordPolicyRefusal — this table
// passes nil for rc, which recordPolicyRefusal treats as "no live
// request/DB, nothing to record" and returns immediately, so the response
// assertions below are unaffected. TestRecordPolicyRefusal
// (approvals_db_test.go) is the DB-backed proof that a real refusal leaves
// a real audit_events row; this table only proves the HTTP classification.
func TestWritePreparePlanExecutionError(t *testing.T) {
	cases := []struct {
		name        string
		err         error
		wantStatus  int
		wantType    string
		notWantType string
	}{
		{
			name:       "scale-from-zero guardrail (pre-existing)",
			err:        fmt.Errorf("%w: refusing", execution.ErrScaleFromZeroRefused),
			wantStatus: http.StatusConflict,
			wantType:   "https://argus.io/errors/scale-from-zero-refused",
		},
		{
			name:       "gitops-managed guardrail (pre-existing)",
			err:        fmt.Errorf("%w: refusing", execution.ErrGitOpsManagedRefused),
			wantStatus: http.StatusConflict,
			wantType:   "https://argus.io/errors/gitops-managed-refused",
		},
		{
			name:       "scale bound refusal (BUGS.md 95)",
			err:        fmt.Errorf("%w: implausible jump", execution.ErrScaleBoundRefused),
			wantStatus: http.StatusConflict,
			wantType:   "https://argus.io/errors/scale-bound-refused",
		},
		{
			name:       "resource limits bound refusal (BUGS.md 95, the live-reproduced case)",
			err:        fmt.Errorf("%w: memoryRequest 150Mi is more than 4x the container's current memoryRequest (20Mi)", execution.ErrResourceLimitsBoundRefused),
			wantStatus: http.StatusConflict,
			wantType:   "https://argus.io/errors/resource-limits-bound-refused",
		},
		{
			name:       "container not found on the pod template (BUGS.md 95)",
			err:        fmt.Errorf("%w: no container named %q", execution.ErrContainerNotInPodTemplate, "sidecar"),
			wantStatus: http.StatusConflict,
			wantType:   "https://argus.io/errors/container-not-found",
		},
		{
			name:       "no well-defined previous image to revert to (BUGS.md 95)",
			err:        fmt.Errorf("%w: nothing to revert", execution.ErrImageRevertRefused),
			wantStatus: http.StatusConflict,
			wantType:   "https://argus.io/errors/image-revert-refused",
		},
		{
			name:       "live risk floor recheck refusal (BUGS.md 101)",
			err:        fmt.Errorf("%w: the real target is labelled tier=data", execution.ErrRiskFloorRecheckRefused),
			wantStatus: http.StatusConflict,
			wantType:   "https://argus.io/errors/risk-floor-recheck-refused",
		},
		{
			name:       "namespace-protected guardrail refusal (BUGS.md 101, the rke2-live-reproduced case)",
			err:        fmt.Errorf("%w: namespace %q is marked argus.io/protected", execution.ErrNamespaceProtectedRefused, "argus-e9-test-r4"),
			wantStatus: http.StatusConflict,
			wantType:   "https://argus.io/errors/namespace-protected-refused",
		},
		{
			// Found live 2026-09-17 (T5): before this branch existed, a
			// rollback-capture refusal was the one remaining hub-side
			// declination still answering 502 "Could not execute this
			// remediation" — blaming a cluster that was never contacted.
			name:       "rollback capture refusal (T5, the live-reproduced case)",
			err:        fmt.Errorf("%w: the compensating action built from the live container's values is not itself a valid plan", execution.ErrRollbackCaptureRefused),
			wantStatus: http.StatusConflict,
			wantType:   "https://argus.io/errors/rollback-capture-refused",
		},
		{
			name:       "plan already decided (BACKLOG.md G6, must be unaffected)",
			err:        &execution.ErrPlanAlreadyDecided{IncidentID: "inc_1", PlanID: "plan_1", Detail: "already approved"},
			wantStatus: http.StatusConflict,
			wantType:   "https://argus.io/errors/plan-already-decided",
		},
		{
			name:        "a genuinely unclassified error still falls back to 502 (the bucket narrowed, not removed)",
			err:         errors.New("dial tcp: connection refused"),
			wantStatus:  http.StatusBadGateway,
			wantType:    "https://argus.io/errors/remediation-execution-failed",
			notWantType: "https://argus.io/errors/scale-bound-refused",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &Server{guardrailTokens: authz.NewGuardrailConfirmationIssuer()}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/inc_1/approve", nil)

			// rc is deliberately nil: this test's whole point (see the doc
			// comment above) is exercising the classification with no live
			// DB/request behind it. recordPolicyRefusal (BACKLOG.md L5)
			// treats a nil rc as "nothing to record" and returns
			// immediately, so passing nil here proves that path doesn't
			// panic and doesn't change any response below — it is NOT
			// itself proof that a real refusal gets audited; that is
			// TestRecordPolicyRefusal's job (approvals_db_test.go).
			s.writePreparePlanExecutionError(context.Background(), nil, req, rec, "inc_1", "plan_1", "cl_1", remediation.ActionScaleDeployment, c.err)

			if rec.Code != c.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, c.wantStatus, rec.Body.String())
			}
			if rec.Code == http.StatusBadGateway && c.wantStatus != http.StatusBadGateway {
				t.Fatalf("a pre-flight refusal must never report 502 remediation-execution-failed — that status is reserved for a genuine execution failure")
			}
			var body struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("response is not valid JSON: %v (body: %s)", err, rec.Body.String())
			}
			if body.Type != c.wantType {
				t.Errorf("problem type = %q, want %q", body.Type, c.wantType)
			}
			if c.notWantType != "" && body.Type == c.notWantType {
				t.Errorf("problem type = %q, must not be %q", body.Type, c.notWantType)
			}
		})
	}
}
