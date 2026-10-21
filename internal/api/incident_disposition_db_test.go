package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
	"argus/internal/orchestrator"
	"argus/internal/timeline"
)

// The review's findings 6 and 9 against a real Postgres. Both are about the
// same question — what does "open" mean, and who decides an incident is
// finished — so they share a file and, where it helps, a fixture.
//
// Run with ARGUS_TEST_DATABASE_URL pointed at a database whose role is NOT a
// superuser: `postgres` carries BYPASSRLS, so every RLS-scoping assertion in
// this package passes vacuously under it. `argus_app` is the role these are
// written for.

// TestRejectingAPlanLeavesTheIncidentOpenAndOnAHuman is finding 6.
//
// The API encoded a rejection as AwaitingApproval -> Dismissed. Dismissed is
// terminal and means "this is real but needs no action from ARGUS", so one
// click on "this proposed fix is unsafe" produced "this fault no longer
// matters", and the incident left the queue with the fault still live in the
// cluster and nobody assigned to it.
//
// This asserts the four things that have to be simultaneously true afterwards,
// because getting any one of them alone would be a different bug: the plan is
// refused, the incident is NOT closed, the incident is still on a human's
// plate, and the reason the human gave is readable back out.
func TestRejectingAPlanLeavesTheIncidentOpenAndOnAHuman(t *testing.T) {
	pool := authTestPool(t)
	tenantID, clusterID, incidentID, planID := timelineExecFixture(t, pool)
	ctx := context.Background()

	const reason = "scaling hides the leak; the pod OOMs at any replica count"

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin request tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	s := &Server{}
	rc := &requestContext{Tx: tx, TenantID: tenantID, UserID: "usr_test"}
	body, _ := json.Marshal(rejectIncidentRequest{Reason: reason})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/"+incidentID+"/reject", strings.NewReader(string(body)))
	req.SetPathValue("id", incidentID)
	rec := httptest.NewRecorder()
	s.handleRejectIncident(rec, req, rc)
	if rec.Code != http.StatusOK {
		t.Fatalf("reject status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	var resp approveRejectResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal reject response: %v", err)
	}
	if resp.IncidentState != orchestrator.StatePlanRejected {
		t.Errorf("response incidentState = %q, want %q — the plan is rejected, the incident is not",
			resp.IncidentState, orchestrator.StatePlanRejected)
	}

	// The state as the DATABASE has it, not just as the response claims.
	var state string
	if err := tx.QueryRow(ctx, `SELECT state FROM incidents WHERE id = $1`, incidentID).Scan(&state); err != nil {
		t.Fatalf("read incidents.state: %v", err)
	}
	if state == orchestrator.StateDismissed {
		t.Fatalf("incidents.state = %q — this is the bug: refusing a fix must not close the incident that fix was for", state)
	}
	if state != orchestrator.StatePlanRejected {
		t.Fatalf("incidents.state = %q, want %q", state, orchestrator.StatePlanRejected)
	}
	if orchestrator.IsClosed(state) {
		t.Errorf("state %q is classified closed — the fault is unchanged in the cluster", state)
	}
	if !orchestrator.RequiresAction(state) {
		t.Errorf("state %q does not require action — a refused plan leaves the next move with a person, and an incident nobody is told to look at is one nobody looks at", state)
	}

	// The reason survives AND is read back out. remediation_approval_decisions
	// has always stored it; latestApprovalDecisionView is what puts it on the
	// plan the incident detail page renders, and this codebase has form for
	// capturing a rejection reason that nothing ever reads (grants
	// .justification, incidents.pr_rejection_reason).
	decision, err := latestApprovalDecisionView(ctx, tx, planID)
	if err != nil {
		t.Fatalf("latestApprovalDecisionView: %v", err)
	}
	if decision == nil {
		t.Fatal("no approval decision is readable for the rejected plan — the refusal is invisible to the next person")
	}
	if decision.Verdict != "rejected" {
		t.Errorf("decision verdict = %q, want %q", decision.Verdict, "rejected")
	}
	if decision.Reason != reason {
		t.Errorf("decision reason = %q, want %q — the whole point of requiring a reason is that someone later reads it", decision.Reason, reason)
	}

	// PROJECT.md L8: the rejection now records what it was a judgement OF.
	// Not cosmetic — `reason` above is prose aimed at ONE analysis: one root
	// cause, produced by one prompt_version and one model (analyses carries
	// both, migration 000005), offering one action type out of whatever
	// internal/resolution permitted that day. Every one of those moves, so a
	// reader who finds this rejection in six months cannot tell whether it
	// still applies unless the row says which of them it was aimed at.
	//
	// Asserted against the RECOMMENDATION's analysis rather than a literal id,
	// because that is the claim being made: the operator judged the plan they
	// were shown, and approvalQueueQuery renders that plan's analysis beside
	// it — not the incident's newest, which a re-analysis can change underneath
	// a pending approval.
	var pinned, fromRecommendation *string
	if err := tx.QueryRow(ctx,
		`SELECT d.analysis_id, r.analysis_id
		   FROM remediation_approval_decisions d
		   JOIN remediation_recommendations r ON r.id = d.recommendation_id
		  WHERE d.recommendation_id = $1`, planID).Scan(&pinned, &fromRecommendation); err != nil {
		t.Fatalf("read the decision's analysis pin: %v", err)
	}
	if pinned == nil {
		t.Fatal("remediation_approval_decisions.analysis_id is NULL — the verdict records no analysis, which is the whole gap PROJECT.md L8 exists to close")
	}
	if fromRecommendation == nil || *pinned != *fromRecommendation {
		t.Errorf("decision pinned analysis %v; want the plan's own analysis %v", *pinned, fromRecommendation)
	}

	// The gate is unchanged: the refused plan is not approvable, and the
	// refusal says so in words rather than "wrong state".
	approveReq := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/"+incidentID+"/approve", strings.NewReader(`{}`))
	approveReq.SetPathValue("id", incidentID)
	approveRec := httptest.NewRecorder()
	s.handleApproveIncident(approveRec, approveReq, rc)
	if approveRec.Code != http.StatusConflict {
		t.Fatalf("approving a rejected plan: status = %d, want 409 (body: %s)", approveRec.Code, approveRec.Body.String())
	}
	if !strings.Contains(approveRec.Body.String(), "already rejected") {
		t.Errorf("409 detail does not say the plan was rejected: %s", approveRec.Body.String())
	}
}

// dispositionFixture is one throwaway cluster carrying one incident in each
// state the two definitions of "open" disagree about, plus the two they agree
// about. Severities are all "low" so the severity buckets in `counts` stay out
// of the way of what this is measuring.
type dispositionFixture struct {
	tenantID  string
	clusterID string
	byState   map[string]string
}

func setupDispositionFixture(t *testing.T, pool *pgxpool.Pool) dispositionFixture {
	t.Helper()
	ctx := context.Background()

	f := dispositionFixture{clusterID: domain.NewID(domain.PrefixCluster), byState: map[string]string{}}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	f.tenantID, err = data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		f.clusterID, f.tenantID, "disposition-test-"+f.clusterID, "fp-"+f.clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	fixture := dbtest.New(t)
	fixture.Created("clusters", 1)

	now := time.Now()
	for _, state := range []string{
		// Requires action, and the two the old definition got wrong by
		// accident rather than by disagreement: Diagnosed is the six-incident
		// case from the review, PlanRejected did not exist.
		orchestrator.StateDetected,
		orchestrator.StateDiagnosed,
		orchestrator.StatePlanRejected,
		// In progress: open, unresolved, and nobody's queue item.
		orchestrator.StateInvestigating,
		orchestrator.StateExecuting,
		orchestrator.StateValidating,
		orchestrator.StateAwaitingMerge,
		// Closed.
		orchestrator.StateResolved,
		orchestrator.StateDismissed,
	} {
		id := domain.NewID(domain.PrefixIncident)
		f.byState[state] = id
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
			 VALUES ($1, $2, $3, $4, 'low', $5, $6, $6, 1)`,
			id, f.tenantID, f.clusterID, "disposition-"+id, state, now); err != nil {
			t.Fatalf("insert incident in state %s: %v", state, err)
		}
		fixture.Created("incidents", 1)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}

	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterID})
	}, []dbtest.TableDelete{
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{f.clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{f.clusterID}},
	})
	return f
}

func (f dispositionFixture) list(t *testing.T, pool *pgxpool.Pool, rawQuery string) map[string]any {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin request tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents?clusterId="+f.clusterID+"&"+rawQuery, nil)
	rec := httptest.NewRecorder()
	s := &Server{}
	s.handleListIncidents(rec, req, &requestContext{Tx: tx, TenantID: f.tenantID})
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal list response: %v", err)
	}
	return body
}

// TestIncidentCountsAskWhoOwesWorkNotWhoIsOpen is finding 9 at the endpoint.
//
// The counts query defined its queue bucket as "state NOT IN ('Resolved',
// 'Dismissed')" — a question about the state machine, standing in for a
// question about the product. Nine incidents, one per state: the old
// definition counts seven of them, this one counts three, and the four it
// stops counting are the four where another writer owns the next move.
func TestIncidentCountsAskWhoOwesWorkNotWhoIsOpen(t *testing.T) {
	pool := authTestPool(t)
	f := setupDispositionFixture(t, pool)

	body := f.list(t, pool, "limit=100")
	counts, _ := body["counts"].(map[string]any)
	if counts == nil {
		t.Fatal("response has no \"counts\" field")
	}
	// `open` stays, and carrying both numbers IS finding 9's answer rather
	// than a failure to apply it. The bug was one figure standing for two
	// questions; the fix was to ask them separately. `requiresAction` is "a
	// human owes the next move", `open` is "the lifecycle is not over", and
	// an incident mid-investigation or waiting on a reviewer to merge is the
	// second without being the first. This assertion used to demand that
	// `open` be ABSENT — written while the rename was in flight, and left
	// behind when the field came back with a narrower meaning. It is
	// `required` in docs/openapi.yaml's IncidentQuickViewCounts and present
	// in web/src/api/generated.ts, so deleting it would break the contract
	// test and the generated client; the two numbers differing is the thing
	// worth pinning.
	openCount, hasOpen := counts["open"].(float64)
	if !hasOpen {
		t.Error("counts has no \"open\" — it is required by docs/openapi.yaml's IncidentQuickViewCounts")
	}
	if openCount != 7 {
		t.Errorf("counts[open] = %v, want 7 — every state but Resolved and Dismissed", counts["open"])
	}
	if requiresAction, _ := counts["requiresAction"].(float64); hasOpen && openCount == requiresAction {
		t.Errorf("counts[open] and counts[requiresAction] are both %v — finding 9 is that these are different questions, and a fixture spanning all nine states must show them differing", openCount)
	}
	if got, _ := counts["all"].(float64); got != 9 {
		t.Fatalf("counts[all] = %v, want 9 — the fixture is not what this test thinks it is", counts["all"])
	}
	if got, _ := counts["requiresAction"].(float64); got != 3 {
		t.Errorf("counts[requiresAction] = %v, want 3 (Detected, Diagnosed, PlanRejected). Investigating/Executing/Validating/AwaitingMerge are open and are nobody's queue item; Resolved/Dismissed are closed", counts["requiresAction"])
	}

	// And the rows a click on that number would show must be the same set. The
	// count and the rows are built by two different queries and this is the
	// only thing that keeps them honest.
	t.Run("the rows match the number", func(t *testing.T) {
		body := f.list(t, pool, "limit=100&requiresAction=true")
		got := map[string]bool{}
		for _, id := range incidentIDsFrom(body) {
			got[id] = true
		}
		if len(got) != 3 {
			t.Fatalf("?requiresAction=true returned %d rows, want 3", len(got))
		}
		for _, state := range []string{orchestrator.StateDetected, orchestrator.StateDiagnosed, orchestrator.StatePlanRejected} {
			if !got[f.byState[state]] {
				t.Errorf("the %s incident is missing from ?requiresAction=true — it is on a human's plate and nothing else will move it", state)
			}
		}
	})

	// ?requiresAction=false is deliberately NOT "closed": it is everything
	// nobody owes work on, which includes the four in-flight states. Asserting
	// it here stops anyone "fixing" the filter back into a closed-set filter.
	t.Run("false means nobody owes work, not closed", func(t *testing.T) {
		body := f.list(t, pool, "limit=100&requiresAction=false")
		ids := incidentIDsFrom(body)
		if len(ids) != 6 {
			t.Fatalf("?requiresAction=false returned %d rows, want 6 (4 in-flight + 2 closed)", len(ids))
		}
		got := map[string]bool{}
		for _, id := range ids {
			got[id] = true
		}
		for _, state := range []string{orchestrator.StateInvestigating, orchestrator.StateExecuting, orchestrator.StateValidating, orchestrator.StateAwaitingMerge} {
			if !got[f.byState[state]] {
				t.Errorf("the %s incident is missing from ?requiresAction=false — it is not closed, it just is not anybody's queue item", state)
			}
		}
	})

	t.Run("an unrecognized value is a 400, never a filter that matches nothing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents?requiresAction=yes", nil)
		rec := httptest.NewRecorder()
		s := &Server{}
		s.handleListIncidents(rec, req, &requestContext{})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})
}

// TestDiagnosedIncidentsStillListAsNeedingAction is the six-incident
// observation from the review, kept as its own named case because it is the
// one an operator would notice: a finished investigation with nothing to
// execute stays in the queue, because the fault is still in the cluster and
// the guidance is somebody's to act on. It is NOT quietly dropped by the
// narrower definition — that would have been the easy wrong fix.
func TestDiagnosedIncidentsStillListAsNeedingAction(t *testing.T) {
	pool := authTestPool(t)
	f := setupDispositionFixture(t, pool)

	body := f.list(t, pool, "limit=100&requiresAction=true&state=Diagnosed")
	ids := incidentIDsFrom(body)
	if len(ids) != 1 || ids[0] != f.byState[orchestrator.StateDiagnosed] {
		t.Fatalf("?requiresAction=true&state=Diagnosed returned %v, want exactly the Diagnosed incident", ids)
	}
}

// TestDismissingAnIncidentRecordsWhatItWasAJudgementOf is PROJECT.md L8's other
// half. Dismissal is a separate path from approve/reject and has no decision
// table of its own: the mandatory note lands in timeline_events.payload and
// audit_events.details, so the anchor goes in the same two blobs rather than in
// a column. A dismissal is the most load-bearing verdict in the product — it
// says a real problem will not be acted on, permanently — and "the operator
// disagreed with what ARGUS said" and "ARGUS never said anything" are opposite
// facts that were previously indistinguishable afterwards.
//
// Unlike the approvals path, the right analysis here IS the incident's newest:
// a close-out is a judgement of the incident as its detail page presents it,
// and that page renders exactly one analysis (getLatestAnalysis).
func TestDismissingAnIncidentRecordsWhatItWasAJudgementOf(t *testing.T) {
	pool := authTestPool(t)
	tenantID, clusterID, incidentID, _ := timelineExecFixture(t, pool)
	ctx := context.Background()

	const note = "known-broken staging workload; the team is decommissioning it this week"

	// Never committed — the assertions read the handler's own writes inside its
	// transaction, the same way the rejection test above does, so this test
	// leaves nothing behind beyond the fixture's own rows.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin request tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	s := &Server{}
	rc := &requestContext{Tx: tx, TenantID: tenantID, UserID: "usr_test"}
	body, _ := json.Marshal(incidentTriageRequest{Note: note})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/"+incidentID+"/dismiss", strings.NewReader(string(body)))
	req.SetPathValue("id", incidentID)
	rec := httptest.NewRecorder()
	s.handleDismissIncident(rec, req, rc)
	if rec.Code != http.StatusOK {
		t.Fatalf("dismiss status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	var payload []byte
	if err := tx.QueryRow(ctx,
		`SELECT payload FROM timeline_events WHERE incident_id = $1 AND event_type = $2`,
		incidentID, timeline.EventIncidentDismissed).Scan(&payload); err != nil {
		t.Fatalf("read the dismissal timeline event: %v", err)
	}
	var detail struct {
		Note       string  `json:"note"`
		AnalysisID *string `json:"analysisId"`
	}
	if err := json.Unmarshal(payload, &detail); err != nil {
		t.Fatalf("unmarshal timeline payload %s: %v", payload, err)
	}
	if detail.Note != note {
		t.Errorf("timeline note = %q, want %q", detail.Note, note)
	}

	var latest string
	if err := tx.QueryRow(ctx,
		`SELECT id FROM analyses WHERE incident_id = $1 ORDER BY created_at DESC LIMIT 1`,
		incidentID).Scan(&latest); err != nil {
		t.Fatalf("read the incident's latest analysis: %v", err)
	}
	if detail.AnalysisID == nil {
		t.Fatalf("dismissal payload carries no analysisId, but this incident HAS an analysis (%s) — a null here would be the claim that ARGUS never said anything about it", latest)
	}
	if *detail.AnalysisID != latest {
		t.Errorf("dismissal pinned analysis %q, want the incident's latest %q — the operator judged what the detail page showed them", *detail.AnalysisID, latest)
	}

	// The audit trail carries the same anchor, because audit_events and
	// timeline_events answer different questions (is this auditable vs. what
	// happened to THIS incident) and triageIncident's own doc comment says
	// neither substitutes for the other.
	var auditDetails []byte
	if err := tx.QueryRow(ctx,
		`SELECT details FROM audit_events
		  WHERE details->>'incidentId' = $1 AND details->>'action' = 'triage_incident'
		  ORDER BY occurred_at DESC LIMIT 1`, incidentID).Scan(&auditDetails); err != nil {
		t.Fatalf("read the dismissal audit event: %v", err)
	}
	var auditDetail struct {
		AnalysisID *string `json:"analysisId"`
	}
	if err := json.Unmarshal(auditDetails, &auditDetail); err != nil {
		t.Fatalf("unmarshal audit details %s: %v", auditDetails, err)
	}
	if auditDetail.AnalysisID == nil || *auditDetail.AnalysisID != latest {
		t.Errorf("audit details pinned analysis %v, want %q", auditDetail.AnalysisID, latest)
	}
}
