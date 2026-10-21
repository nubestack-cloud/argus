package api

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
)

// PROJECT.md T7: "a recurrence reuses what was learned rather than starting
// from zero." priorIncidentLinksFor is the read side of the owner's decided
// mechanism (LINK, computed at read time via a join on object_key, never a
// stored edge) — these prove the join itself against a real Postgres,
// exactly like incidents_recent_changes_db_test.go proves getRecentChanges'
// reads the same way, and for the same reason: a JOIN LATERAL is a property
// of the database, not of Go control flow.
func TestPriorIncidentLinksFor(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()

	clusterID := domain.NewID(domain.PrefixCluster)
	objectKey := "apps/v1/Deployment|default|payments-api"
	otherObjectKey := "apps/v1/Deployment|default|unrelated"
	currentID := domain.NewID(domain.PrefixIncident)
	closedWithAnalysisID := domain.NewID(domain.PrefixIncident)
	closedNoAnalysisID := domain.NewID(domain.PrefixIncident)
	openSameObjectID := domain.NewID(domain.PrefixIncident)
	closedDifferentObjectID := domain.NewID(domain.PrefixIncident)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	fixture := dbtest.New(t)
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "t7-links-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	fixture.Created("clusters", 1)

	now := time.Now()
	isClosed := map[string]bool{"Resolved": true, "Dismissed": true, "Expired": true}
	insertIncident := func(id, state, objKey string, ageAgo time.Duration, resolutionKind *string) {
		firstSeen := now.Add(-ageAgo)
		var resolvedAt *time.Time
		if isClosed[state] {
			resolvedAt = &firstSeen
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, object_key, resolved_at, resolution_kind)
			 VALUES ($1, $2, $3, $4, 'high', $5, $6, $6, 1, $7, $8, $9)`,
			id, tenantID, clusterID, "t7links-"+id, state, firstSeen, objKey, resolvedAt, resolutionKind); err != nil {
			t.Fatalf("insert incident %s: %v", id, err)
		}
	}
	remediated := "remediated"
	insertIncident(currentID, "Investigating", objectKey, 0, nil)
	insertIncident(closedWithAnalysisID, "Resolved", objectKey, 48*time.Hour, &remediated)
	insertIncident(closedNoAnalysisID, "Dismissed", objectKey, 24*time.Hour, nil)
	insertIncident(openSameObjectID, "Investigating", objectKey, 12*time.Hour, nil)
	insertIncident(closedDifferentObjectID, "Resolved", otherObjectKey, 1*time.Hour, &remediated)
	fixture.Created("incidents", 5)

	analysisID := domain.NewID(domain.PrefixAnalysis)
	if _, err := tx.Exec(ctx,
		`INSERT INTO analyses (id, tenant_id, incident_id, cluster_id, prompt_version, model,
		    causal_chain, root_cause, confidence, iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd)
		 VALUES ($1,$2,$3,$4,'test','test-model','[]'::jsonb, $5, 0.75, 1,1,0,0,0,0)`,
		analysisID, tenantID, closedWithAnalysisID, clusterID, `{"statement": "OOMKilled — memory limit too low"}`); err != nil {
		t.Fatalf("insert analysis: %v", err)
	}
	fixture.Created("analyses", 1)

	recID := domain.NewID(domain.PrefixPlan)
	if _, err := tx.Exec(ctx,
		`INSERT INTO remediation_recommendations
		   (id, incident_id, tenant_id, cluster_id, analysis_id, action_type, target_gvk,
		    target_namespace, target_name, params, reversible, risk_level, gate_outcome, gate_reason)
		 VALUES ($1, $2, $3, $4, $5, 'ScaleDeployment', 'apps/v1/Deployment', 'default', 'payments-api',
		         '{}'::jsonb, true, 'low', 'AutoApprove', 'test')`,
		recID, closedWithAnalysisID, tenantID, clusterID, analysisID); err != nil {
		t.Fatalf("insert recommendation: %v", err)
	}
	fixture.Created("remediation_recommendations", 1)

	approvalID := domain.NewID(domain.PrefixApproval)
	userID := domain.NewID(domain.PrefixUser)
	if _, err := tx.Exec(ctx,
		`INSERT INTO remediation_approval_decisions
		   (id, recommendation_id, incident_id, tenant_id, cluster_id, actor_id, verdict, reason)
		 VALUES ($1, $2, $3, $4, $5, $6, 'rejected', $7)`,
		approvalID, recID, closedWithAnalysisID, tenantID, clusterID, userID,
		"scaling replicas does not fix a per-pod OOM"); err != nil {
		t.Fatalf("insert rejection: %v", err)
	}
	fixture.Created("remediation_approval_decisions", 1)
	fixture.Created("evidence", 0)
	fixture.Created("analysis_embeddings", 0)

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}
	defer func() {
		fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
			return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
		}, []dbtest.TableDelete{
			{Table: "remediation_approval_decisions", SQL: `DELETE FROM remediation_approval_decisions WHERE cluster_id = $1`, Args: []any{clusterID}},
			{Table: "remediation_recommendations", SQL: `DELETE FROM remediation_recommendations WHERE cluster_id = $1`, Args: []any{clusterID}},
			{Table: "evidence", SQL: `DELETE FROM evidence WHERE analysis_id IN (SELECT id FROM analyses WHERE cluster_id = $1)`, Args: []any{clusterID}},
			{Table: "analysis_embeddings", SQL: `DELETE FROM analysis_embeddings WHERE analysis_id IN (SELECT id FROM analyses WHERE cluster_id = $1)`, Args: []any{clusterID}},
			{Table: "analyses", SQL: `DELETE FROM analyses WHERE cluster_id = $1`, Args: []any{clusterID}},
			{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
			{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
		})
	}()

	readTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin read: %v", err)
	}
	defer readTx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, readTx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope read: %v", err)
	}

	links, err := priorIncidentLinksFor(ctx, readTx, objectKey, "", currentID)
	if err != nil {
		t.Fatalf("priorIncidentLinksFor: %v", err)
	}

	// Exactly the two CLOSED incidents on the SAME object — not the open
	// one on this object, not the closed one on a DIFFERENT object, and not
	// the current incident itself.
	if len(links) != 2 {
		t.Fatalf("len(links) = %d, want 2 (got %+v)", len(links), links)
	}
	// Newest first.
	if links[0].IncidentID != closedNoAnalysisID {
		t.Fatalf("links[0].IncidentID = %s, want %s (newest first)", links[0].IncidentID, closedNoAnalysisID)
	}
	if links[1].IncidentID != closedWithAnalysisID {
		t.Fatalf("links[1].IncidentID = %s, want %s", links[1].IncidentID, closedWithAnalysisID)
	}

	// The un-analysed prior incident is honest about having no analysis —
	// no fabricated root cause.
	noAnalysis := links[0]
	if noAnalysis.State != "Dismissed" {
		t.Fatalf("links[0].State = %s, want Dismissed", noAnalysis.State)
	}
	if noAnalysis.RootCause != nil {
		t.Fatalf("links[0].RootCause = %v, want nil (no analysis was ever run)", *noAnalysis.RootCause)
	}
	if noAnalysis.RejectedPlan != nil {
		t.Fatalf("links[0].RejectedPlan = %+v, want nil", noAnalysis.RejectedPlan)
	}

	// "What was learned" AND the rejection reason — the two specific gaps
	// PROJECT.md T7 names — both surfaced for the analysed, rejected prior
	// incident.
	analysed := links[1]
	if analysed.State != "Resolved" {
		t.Fatalf("links[1].State = %s, want Resolved", analysed.State)
	}
	if analysed.ResolutionKind == nil || *analysed.ResolutionKind != "remediated" {
		t.Fatalf("links[1].ResolutionKind = %v, want remediated", analysed.ResolutionKind)
	}
	if analysed.RootCause == nil || *analysed.RootCause != "OOMKilled — memory limit too low" {
		t.Fatalf("links[1].RootCause = %v, want the stored root cause statement", analysed.RootCause)
	}
	if analysed.RejectedPlan == nil {
		t.Fatalf("links[1].RejectedPlan = nil, want the recorded rejection")
	}
	if analysed.RejectedPlan.ActionType != "ScaleDeployment" {
		t.Fatalf("RejectedPlan.ActionType = %s, want ScaleDeployment", analysed.RejectedPlan.ActionType)
	}
	if analysed.RejectedPlan.Reason != "scaling replicas does not fix a per-pod OOM" {
		t.Fatalf("RejectedPlan.Reason = %q, want the stored rejection reason verbatim", analysed.RejectedPlan.Reason)
	}
}

func TestPriorIncidentLinksFor_NoPriorIncidentsIsAnEmptySliceNotNil(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()

	clusterID := domain.NewID(domain.PrefixCluster)
	objectKey := "apps/v1/Deployment|default|first-occurrence"
	currentID := domain.NewID(domain.PrefixIncident)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	fixture := dbtest.New(t)
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "t7-links-empty-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	fixture.Created("clusters", 1)
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, object_key)
		 VALUES ($1, $2, $3, $4, 'high', 'Investigating', now(), now(), 1, $5)`,
		currentID, tenantID, clusterID, "t7linksempty-"+currentID, objectKey); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	fixture.Created("incidents", 1)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	defer func() {
		fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
			return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
		}, []dbtest.TableDelete{
			{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
			{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
		})
	}()

	readTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin read: %v", err)
	}
	defer readTx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, readTx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope read: %v", err)
	}

	links, err := priorIncidentLinksFor(ctx, readTx, objectKey, "", currentID)
	if err != nil {
		t.Fatalf("priorIncidentLinksFor: %v", err)
	}
	if links == nil {
		t.Fatalf("links = nil, want a non-nil empty slice — this codebase renders an empty array, never null, for a bounded list field")
	}
	if len(links) != 0 {
		t.Fatalf("len(links) = %d, want 0", len(links))
	}
}

// A Deployment's pods are renamed by every rollout, so a recurrence of the same
// workload fault arrives on a new object_key. The workload_key match is what
// links it back to the last time (found live on rke2, 2026-10-12). A closed
// incident on a different workload must still not match.
func TestPriorIncidentLinksFor_MatchesTheSameWorkloadAcrossPodNames(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()

	clusterID := domain.NewID(domain.PrefixCluster)
	workloadKey := "apps/v1/Deployment|default|web"
	currentID := domain.NewID(domain.PrefixIncident)
	siblingID := domain.NewID(domain.PrefixIncident)
	otherWorkloadID := domain.NewID(domain.PrefixIncident)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	fixture := dbtest.New(t)
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "t7-links-workload-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	fixture.Created("clusters", 1)
	insert := func(id, state, objKey, wlKey string, ago time.Duration) {
		at := time.Now().Add(-ago)
		var resolvedAt *time.Time
		if state != "Investigating" {
			resolvedAt = &at
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, object_key, workload_key, resolved_at)
			 VALUES ($1, $2, $3, $4, 'medium', $5, $6, $6, 1, $7, $8, $9)`,
			id, tenantID, clusterID, "t7wl-"+id, state, at, objKey, wlKey, resolvedAt); err != nil {
			t.Fatalf("insert incident %s: %v", id, err)
		}
	}
	insert(currentID, "Investigating", "v1/Pod|default|web-99d6c96bf-8lxxm", workloadKey, 0)
	insert(siblingID, "Resolved", "v1/Pod|default|web-f6f45b5bc-ddshr", workloadKey, time.Hour)
	insert(otherWorkloadID, "Resolved", "v1/Pod|default|api-688b444f78-kpbbx", "apps/v1/Deployment|default|api", time.Hour)
	fixture.Created("incidents", 3)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	defer func() {
		fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
			return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
		}, []dbtest.TableDelete{
			{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
			{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
		})
	}()

	readTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin read: %v", err)
	}
	defer readTx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, readTx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope read: %v", err)
	}

	links, err := priorIncidentLinksFor(ctx, readTx, "v1/Pod|default|web-99d6c96bf-8lxxm", workloadKey, currentID)
	if err != nil {
		t.Fatalf("priorIncidentLinksFor: %v", err)
	}
	if len(links) != 1 || links[0].IncidentID != siblingID {
		t.Fatalf("links = %+v, want exactly the closed incident on a sibling pod of the same workload (%s)", links, siblingID)
	}

	// With no workload key, the match is the exact object only — as before.
	links, err = priorIncidentLinksFor(ctx, readTx, "v1/Pod|default|web-99d6c96bf-8lxxm", "", currentID)
	if err != nil {
		t.Fatalf("priorIncidentLinksFor (no workload key): %v", err)
	}
	if len(links) != 0 {
		t.Fatalf("links = %+v, want none without a workload key", links)
	}
}
