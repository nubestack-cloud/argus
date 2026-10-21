package orchestrator

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
)

// validationResolveFixture builds a Validating incident whose in-place fix
// "landed" well outside validationGracePeriod, with a real
// remediation_recommendations + remediation_executions(succeeded) pair
// behind it — the minimum sweep() actually reads (see its own query) to pick
// this incident up as resolvable on the next tick.
//
// openingRuleID sets incidents.opening_rule_id (migration 000071,
// BACKLOG.md V3) when non-empty, else leaves it NULL — the "opened by a
// hand-written detector" case every incident had until this feature existed,
// and still the common case for any detector this feature does not cover.
func validationResolveFixture(t *testing.T, pool *pgxpool.Pool, openingRuleID string) (fixture *dbtest.Fixture, tenantID, clusterID, incidentID string) {
	t.Helper()
	ctx := context.Background()

	clusterID = domain.NewID(domain.PrefixCluster)
	incidentID = domain.NewID(domain.PrefixIncident)
	analysisID := domain.NewID(domain.PrefixAnalysis)
	planID := domain.NewID(domain.PrefixPlan)
	executionID := domain.NewID(domain.PrefixExecution)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err = data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "validation-timeline-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	fixture = dbtest.New(t)
	fixture.OwnsCluster(tenantID, clusterID)
	fixture.Created("clusters", 1)

	now := time.Now()
	// last_seen well before the fix landed, so the sweep's own
	// "i.last_seen <= exec.executed_at" double-check passes.
	fixLandedAt := now.Add(-validationGracePeriod - time.Hour)
	lastSeen := fixLandedAt.Add(-time.Minute)
	var openingRuleIDArg any
	if openingRuleID != "" {
		openingRuleIDArg = openingRuleID
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, object_key, opening_rule_id, severity, state, first_seen, last_seen, occurrence_count)
		 VALUES ($1, $2, $3, $4, $5, $6, 'high', 'Validating', $7, $7, 1)`,
		incidentID, tenantID, clusterID, "test-validation-timeline-"+incidentID,
		"policy/v1/PodDisruptionBudget|ns|test-pdb", openingRuleIDArg, lastSeen); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	fixture.Created("incidents", 1)
	if _, err := tx.Exec(ctx,
		`INSERT INTO analyses (id, tenant_id, incident_id, cluster_id, prompt_version, model,
		    causal_chain, iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd)
		 VALUES ($1,$2,$3,$4,'test','test-model','[]'::jsonb,1,1,0,0,0,0)`,
		analysisID, tenantID, incidentID, clusterID); err != nil {
		t.Fatalf("insert analysis: %v", err)
	}
	fixture.Created("analyses", 1)
	if _, err := tx.Exec(ctx,
		`INSERT INTO remediation_recommendations (
		   id, incident_id, tenant_id, cluster_id, analysis_id, action_type,
		   target_gvk, target_namespace, target_name, params, reversible, risk_level,
		   gate_outcome, gate_reason
		 ) VALUES ($1,$2,$3,$4,$5,'ScaleDeployment','apps/v1/Deployment','ns','web','{"replicas":3}'::jsonb,true,'low','AutoApprove','test')`,
		planID, incidentID, tenantID, clusterID, analysisID); err != nil {
		t.Fatalf("insert recommendation: %v", err)
	}
	fixture.Created("remediation_recommendations", 1)
	if _, err := tx.Exec(ctx,
		`INSERT INTO remediation_executions (id, recommendation_id, incident_id, tenant_id, cluster_id, outcome, executed_at)
		 VALUES ($1,$2,$3,$4,$5,'succeeded',$6)`,
		executionID, planID, incidentID, tenantID, clusterID, fixLandedAt); err != nil {
		t.Fatalf("insert execution: %v", err)
	}
	fixture.Created("remediation_executions", 1)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}

	return fixture, tenantID, clusterID, incidentID
}

// cleanupValidationResolveFixture runs fixture.Cleanup with the full delete
// list every test built on validationResolveFixture needs — the caller must
// have already tracked the test-specific timeline_events/
// incident_notifications counts (both written by the real v.sweep() call,
// not this fixture) via fixture.Created before calling this.
func cleanupValidationResolveFixture(fixture *dbtest.Fixture, pool *pgxpool.Pool, tenantID, clusterID string) {
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "timeline_events", SQL: `DELETE FROM timeline_events WHERE cluster_id = $1`, Args: []any{clusterID}},
		// BACKLOG.md N1: SetState now writes incident_notifications for
		// every AwaitingApproval/Failed/ExecutionUnknown/Reopened
		// transition, and this fixture's ValidationSweeper tests drive
		// Reopened — see migration 000083's own comment for why this
		// table carries no foreign key back to clusters, but is still
		// cleaned up here like every other table in this list.
		{Table: "incident_notifications", SQL: `DELETE FROM incident_notifications WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "remediation_executions", SQL: `DELETE FROM remediation_executions WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "remediation_recommendations", SQL: `DELETE FROM remediation_recommendations WHERE cluster_id = $1`, Args: []any{clusterID}},
		// BUGS.md 119: same delete-order footgun as clearDemoData — this
		// fixture doesn't insert evidence/analysis_embeddings today, but
		// clearing them before analyses matches every other fixture in
		// this package. Tracked at 0 below (see each test's own
		// fixture.Created calls).
		{Table: "evidence", SQL: `DELETE FROM evidence WHERE analysis_id IN (SELECT id FROM analyses WHERE cluster_id = $1)`, Args: []any{clusterID}},
		{Table: "analysis_embeddings", SQL: `DELETE FROM analysis_embeddings WHERE analysis_id IN (SELECT id FROM analyses WHERE cluster_id = $1)`, Args: []any{clusterID}},
		{Table: "analyses", SQL: `DELETE FROM analyses WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})
}

// TestValidationSweeperWritesValidationOutcomeEvent is BACKLOG.md B1's
// acceptance test for the validation transition: the automated
// Validating -> Resolved re-check must write a ValidationOutcome
// timeline_events row alongside the state transition it makes.
func TestValidationSweeperWritesValidationOutcomeEvent(t *testing.T) {
	pool := testPool(t)
	fixture, tenantID, clusterID, incidentID := validationResolveFixture(t, pool, "")

	v := NewValidationSweeper(&data.DB{Pool: pool}, nil, nil)
	if err := v.sweep(context.Background()); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin verify tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	var state string
	if err := tx.QueryRow(ctx, `SELECT state FROM incidents WHERE id = $1`, incidentID).Scan(&state); err != nil {
		t.Fatalf("read incident state: %v", err)
	}
	if state != StateResolved {
		t.Fatalf("incident state = %q, want %q (sweep should have auto-resolved it)", state, StateResolved)
	}

	rows, err := tx.Query(ctx, `SELECT event_type, payload FROM timeline_events WHERE incident_id = $1`, incidentID)
	if err != nil {
		t.Fatalf("query timeline_events: %v", err)
	}
	defer rows.Close()
	var count int
	for rows.Next() {
		var eventType string
		var payload []byte
		if err := rows.Scan(&eventType, &payload); err != nil {
			t.Fatalf("scan: %v", err)
		}
		count++
		if eventType != "ValidationOutcome" {
			t.Errorf("event_type = %q, want %q", eventType, "ValidationOutcome")
		}
		var decoded map[string]any
		if err := json.Unmarshal(payload, &decoded); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		if got, _ := decoded["outcome"].(string); got != StateResolved {
			t.Errorf("payload[\"outcome\"] = %q, want %q", got, StateResolved)
		}
		if summary, _ := decoded["summary"].(string); summary == "" {
			t.Error("payload[\"summary\"] is empty, want the sweep's own evidence sentence")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}
	if count != 1 {
		t.Fatalf("timeline_events rows for incident %s = %d, want exactly 1", incidentID, count)
	}

	// One ValidationOutcome timeline event, just confirmed above. Resolved is
	// not one of the AwaitingApproval/Failed/ExecutionUnknown/Reopened
	// transitions BACKLOG.md N1 notifies on, so no incident_notifications row.
	fixture.Created("timeline_events", 1)
	fixture.Created("incident_notifications", 0)
	fixture.Created("evidence", 0)
	fixture.Created("analysis_embeddings", 0)
	cleanupValidationResolveFixture(fixture, pool, tenantID, clusterID)
}

// readIncidentStateAndEvidence is the three tests below's shared assertion
// helper: read the incident's current state plus its ValidationOutcome
// timeline event's summary, so each test can check both the transition AND
// the evidence sentence sweep() actually wrote (the whole point of V3 is
// that the SENTENCE, not just the state, must change for the case it
// covers).
func readIncidentStateAndEvidence(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID string) (state, summary string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin verify tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	if err := tx.QueryRow(ctx, `SELECT state FROM incidents WHERE id = $1`, incidentID).Scan(&state); err != nil {
		t.Fatalf("read incident state: %v", err)
	}
	if err := tx.QueryRow(ctx,
		`SELECT payload->>'summary' FROM timeline_events WHERE incident_id = $1 AND event_type = 'ValidationOutcome'
		 ORDER BY occurred_at DESC LIMIT 1`, incidentID).Scan(&summary); err != nil {
		t.Fatalf("read ValidationOutcome summary: %v", err)
	}
	return state, summary
}

// BACKLOG.md V3's three acceptance scenarios, all exercised through the REAL
// sweep() loop against a real Postgres — only the verifier is faked, the
// same shape TestValidationVerifierOutcomesMapToTheRightStates already
// established for V1, now extended to RuleStillFires. A DB is genuinely
// needed here (unlike that unit test): what's being proven is that sweep()
// wires RuleStillFires's three outcomes into the right STATE TRANSITION and
// the right EVIDENCE SENTENCE end to end, not just that the interface method
// returns the right tuple in isolation.

// TestValidationSweeperRuleStillFires_Reopens is point 3's decision, proven:
// when the rule that opened this incident is re-evaluated and STILL fires,
// the incident is flipped to Reopened even though the quiet-grace-period and
// field-assertion checks both would have resolved it — this is the stronger,
// independent signal V3 exists to add, described in
// AppliedValueVerifier.RuleStillFires' own doc comment.
func TestValidationSweeperRuleStillFires_Reopens(t *testing.T) {
	pool := testPool(t)
	fixture, tenantID, clusterID, incidentID := validationResolveFixture(t, pool, "pdb-blocks-all-disruptions")

	v := NewValidationSweeper(&data.DB{Pool: pool}, nil, fakeVerifier{
		held: true, detail: "still 3", // the weaker checks both say "fine"
		evaluated: true, fires: true, // but the rule itself says otherwise
	})
	if err := v.sweep(context.Background()); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	state, summary := readIncidentStateAndEvidence(t, pool, tenantID, clusterID, incidentID)
	if state != StateReopened {
		t.Fatalf("incident state = %q, want %q — a rule that still fires must reopen the incident even though the field assertion held", state, StateReopened)
	}
	if !strings.Contains(summary, "STILL TRUE") {
		t.Errorf("evidence sentence = %q, want it to say the original condition is still true", summary)
	}

	// One ValidationOutcome timeline event, plus one incident_notifications
	// row — this is the one test in this file whose sweep transitions to
	// Reopened, which BACKLOG.md N1 notifies on.
	fixture.Created("timeline_events", 1)
	fixture.Created("incident_notifications", 1)
	fixture.Created("evidence", 0)
	fixture.Created("analysis_embeddings", 0)
	cleanupValidationResolveFixture(fixture, pool, tenantID, clusterID)
}

// TestValidationSweeperRuleCleared_ResolvesWithStrongerClaim is the case V3
// actually delivers: an incident opened by a KNOWN rule, re-checked against
// live state, and confirmed cleared — the "we confirmed this is fixed" claim
// docs/USER_GUIDE.md §6 could not honestly make before this feature existed.
func TestValidationSweeperRuleCleared_ResolvesWithStrongerClaim(t *testing.T) {
	pool := testPool(t)
	fixture, tenantID, clusterID, incidentID := validationResolveFixture(t, pool, "pdb-blocks-all-disruptions")

	v := NewValidationSweeper(&data.DB{Pool: pool}, nil, fakeVerifier{
		held: true, detail: "condition no longer holds",
		evaluated: true, fires: false,
	})
	if err := v.sweep(context.Background()); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	state, summary := readIncidentStateAndEvidence(t, pool, tenantID, clusterID, incidentID)
	if state != StateResolved {
		t.Fatalf("incident state = %q, want %q", state, StateResolved)
	}
	if !strings.Contains(summary, "re-checked the original condition against live state") {
		t.Errorf("evidence sentence = %q, want the stronger V3 claim, not just the old quiet-period wording", summary)
	}

	// One ValidationOutcome timeline event; Resolved is not one of N1's
	// notified transitions.
	fixture.Created("timeline_events", 1)
	fixture.Created("incident_notifications", 0)
	fixture.Created("evidence", 0)
	fixture.Created("analysis_embeddings", 0)
	cleanupValidationResolveFixture(fixture, pool, tenantID, clusterID)
}

// TestValidationSweeperHandWrittenDetector_FallsBackUnchanged is the explicit
// regression proof for V3's scope boundary: an incident with NO
// opening_rule_id (every hand-written Go checker's Finding, and every
// watch-based detector's) must resolve exactly as it did before this feature
// existed — the plain quiet-grace-period/field-assertion evidence sentence,
// with no "re-checked the original condition" language grafted on for a
// check that was never actually re-run.
func TestValidationSweeperHandWrittenDetector_FallsBackUnchanged(t *testing.T) {
	pool := testPool(t)
	fixture, tenantID, clusterID, incidentID := validationResolveFixture(t, pool, "") // no rule — a hand-written detector's incident

	v := NewValidationSweeper(&data.DB{Pool: pool}, nil, fakeVerifier{
		held: true, detail: "still 3",
		// evaluated left at its zero value (false): RuleStillFires must
		// report "nothing to re-run" for this incident, exactly the scope
		// boundary documented on the interface method.
	})
	if err := v.sweep(context.Background()); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	state, summary := readIncidentStateAndEvidence(t, pool, tenantID, clusterID, incidentID)
	if state != StateResolved {
		t.Fatalf("incident state = %q, want %q", state, StateResolved)
	}
	if strings.Contains(summary, "re-checked the original condition") {
		t.Errorf("evidence sentence = %q — a hand-written-detector incident must not carry V3's rule-recheck language; it was never re-run", summary)
	}
	if !strings.Contains(summary, "the change still holds") {
		t.Errorf("evidence sentence = %q, want V1's unchanged field-assertion wording", summary)
	}

	// One ValidationOutcome timeline event; Resolved is not one of N1's
	// notified transitions.
	fixture.Created("timeline_events", 1)
	fixture.Created("incident_notifications", 0)
	fixture.Created("evidence", 0)
	fixture.Created("analysis_embeddings", 0)
	cleanupValidationResolveFixture(fixture, pool, tenantID, clusterID)
}
