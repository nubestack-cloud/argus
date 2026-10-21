package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
	"argus/internal/tunnel"
)

// BUGS.md 94's regression test.
//
// The correlation tier has two producers of Findings about the same object —
// E9's declarative rules and the hand-written Go checkers — and which of them
// reaches the hub first is a race with no meaning. Live on rke2, metrics-
// server's ordinary "no sample yet" warning events opened an incident about a
// HorizontalPodAutoscaler two minutes before the 90s-sustained
// hpa-pegged-at-max-replicas rule fired on the SAME object. The rule's
// finding correlated into that incident correctly (same object_key), but
// incidents.opening_rule_id — written once, at INSERT — stayed empty, so
// V3's post-fix re-check (api.RuleStillFires, gated on that column being
// non-empty) could silently never re-run a rule that had genuinely fired.
//
// Not provable in pure Go: what was broken is which SQL statement writes the
// column, under RLS, through the real ingestion entry point. Uses
// finding_db_test.go's testPool harness (argus_app, not the superuser), and
// calls the real (g *Gateway).handleFinding twice in the order the live case
// produced.
func openingRuleTestCluster(t *testing.T, pool *pgxpool.Pool) (tenantID, clusterID string, fixture *dbtest.Fixture) {
	t.Helper()
	ctx := context.Background()
	clusterID = domain.NewID(domain.PrefixCluster)

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
		t.Fatalf("set request scope: %v", err)
	}
	fixture = dbtest.New(t)
	fixture.OwnsCluster(tenantID, clusterID)
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "openingrule-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	fixture.Created("clusters", 1)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}
	return tenantID, clusterID, fixture
}

// openingRuleCleanup registers this fixture's cleanup once the caller knows
// exactly how many findings/incidents/timeline_events rows its own
// handleFinding calls produced.
func openingRuleCleanup(fixture *dbtest.Fixture, pool *pgxpool.Pool, tenantID, clusterID string) {
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "timeline_events", SQL: `DELETE FROM timeline_events WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "findings", SQL: `DELETE FROM findings WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})
}

// openingRuleFor reads back the one incident this test's object produced,
// with the two columns the bug is about.
func openingRuleFor(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, objectKey string) (incidentID string, openingReason, openingRuleID *string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin lookup: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	rows, err := tx.Query(ctx,
		`SELECT id, opening_reason, opening_rule_id FROM incidents WHERE cluster_id = $1 AND object_key = $2`,
		clusterID, objectKey)
	if err != nil {
		t.Fatalf("query incidents: %v", err)
	}
	defer rows.Close()
	found := 0
	for rows.Next() {
		found++
		if err := rows.Scan(&incidentID, &openingReason, &openingRuleID); err != nil {
			t.Fatalf("scan incident: %v", err)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate incidents: %v", err)
	}
	if found != 1 {
		t.Fatalf("found %d incidents for object %s, want exactly 1 — both findings are about the same object and must correlate into one incident", found, objectKey)
	}
	return incidentID, openingReason, openingRuleID
}

func TestBug94_LaterRuleFindingSuppliesOpeningRuleID(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, fixture := openingRuleTestCluster(t, pool)
	// One incident (the rule finding correlates into the warning event's
	// incident, object tier), one findings row per handleFinding call below,
	// and exactly one IncidentOpened event — the second call never changes
	// incident state.
	fixture.Created("incidents", 1)
	fixture.Created("findings", 2)
	fixture.Created("timeline_events", 1)
	openingRuleCleanup(fixture, pool, tenantID, clusterID)
	g := &Gateway{db: &data.DB{Pool: pool}}
	ctx := context.Background()

	const (
		gvk       = "autoscaling/v2/HorizontalPodAutoscaler"
		namespace = "argus-bug94-test"
		name      = "web-hpa"
		ruleID    = "hpa-pegged-at-max-replicas"
	)
	objectKey := gvk + "|" + namespace + "|" + name

	// 1. The non-rule finding that wins the race live: a warning event
	//    forwarded by the event-based detector, carrying no RuleID at all.
	warningEvent := &tunnel.Finding{
		DetectorID:      "k8s-warning-events",
		DetectorVersion: "v1",
		Fingerprint:     "test-fp-bug94-warning",
		GVK:             gvk,
		Namespace:       namespace,
		ObjectName:      name,
		ObjectUID:       "uid-bug94",
		ResourceVersion: "1",
		Reason:          "FailedGetResourceMetric",
		Message:         "no metrics returned from resource metrics API",
		OccurrenceCount: 1,
		Severity:        "medium",
		OccurredAt:      time.Now(),
	}
	if err := g.handleFinding(ctx, clusterID, warningEvent); err != nil {
		t.Fatalf("handleFinding(warning event): %v", err)
	}

	incidentID, openingReason, openingRuleID := openingRuleFor(t, pool, tenantID, clusterID, objectKey)
	if openingRuleID != nil && *openingRuleID != "" {
		t.Fatalf("incident %s carries opening_rule_id = %q after only a non-rule finding — nothing should have named a rule yet", incidentID, *openingRuleID)
	}

	// 2. The rule fires two minutes later on the SAME object. It correlates
	//    into the same incident (object tier — unchanged by this fix), and
	//    that is exactly the path that used to lose its rule identity.
	ruleFinding := &tunnel.Finding{
		DetectorID:      "k8s-sweep",
		DetectorVersion: "v1",
		Fingerprint:     "test-fp-bug94-rule",
		GVK:             gvk,
		Namespace:       namespace,
		ObjectName:      name,
		ObjectUID:       "uid-bug94",
		ResourceVersion: "2",
		Reason:          "HPAPeggedAtMaxReplicas",
		Message:         "HorizontalPodAutoscaler has been at maxReplicas for 90s",
		OccurrenceCount: 1,
		Severity:        "high",
		OccurredAt:      time.Now(),
		RuleID:          ruleID,
	}
	if err := g.handleFinding(ctx, clusterID, ruleFinding); err != nil {
		t.Fatalf("handleFinding(rule finding): %v", err)
	}

	sameIncidentID, openingReason, openingRuleID := openingRuleFor(t, pool, tenantID, clusterID, objectKey)
	if sameIncidentID != incidentID {
		t.Fatalf("the rule finding opened a SECOND incident (%s, was %s) — object-level correlation must still fold both findings into one incident; this fix must not change which tier a rule-format finding lands in", sameIncidentID, incidentID)
	}
	// THE BUG-94 DELIVERABLE. Before the fix this was NULL, so
	// api.RuleStillFires' scope-boundary check returned "not evaluated" for
	// an incident whose rule had demonstrably fired.
	if openingRuleID == nil || *openingRuleID != ruleID {
		got := "NULL"
		if openingRuleID != nil {
			got = *openingRuleID
		}
		t.Fatalf("incident %s has opening_rule_id = %s, want %q — a rule-format finding that correlates into an incident an earlier non-rule finding opened must supply the rule identity V3's re-check needs (BUGS.md 94)", incidentID, got, ruleID)
	}
	// opening_reason is deliberately NOT adopted: it still names the symptom
	// that OPENED the incident, exactly as migration 000042/000043 specify.
	// Only the rule identity — which has no other writer and whose NULL
	// silently disables a safety re-check — is filled in.
	if openingReason == nil || *openingReason != warningEvent.Reason {
		got := "NULL"
		if openingReason != nil {
			got = *openingReason
		}
		t.Fatalf("opening_reason = %s, want %q — the later finding must not rewrite which symptom opened the incident", got, warningEvent.Reason)
	}
}

// The other half of the decision: an incident that ALREADY names a rule keeps
// naming it. Migration 000071's invariant — a later finding never retroactively
// changes which rule a post-fix re-check re-runs — is preserved for every case
// it was actually reasoning about; only an empty slot is ever filled.
func TestBug94_ExistingOpeningRuleIDIsNeverOverwritten(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, fixture := openingRuleTestCluster(t, pool)
	// Both rule findings correlate into the same incident (same object), so
	// one incident, one IncidentOpened event, and one findings row per
	// handleFinding call below.
	fixture.Created("incidents", 1)
	fixture.Created("findings", 2)
	fixture.Created("timeline_events", 1)
	openingRuleCleanup(fixture, pool, tenantID, clusterID)
	g := &Gateway{db: &data.DB{Pool: pool}}
	ctx := context.Background()

	const (
		gvk       = "policy/v1/PodDisruptionBudget"
		namespace = "argus-bug94-test"
		name      = "web-pdb"
	)
	objectKey := gvk + "|" + namespace + "|" + name

	finding := func(ruleID, reason, fingerprint string) *tunnel.Finding {
		return &tunnel.Finding{
			DetectorID:      "k8s-sweep",
			DetectorVersion: "v1",
			Fingerprint:     fingerprint,
			GVK:             gvk,
			Namespace:       namespace,
			ObjectName:      name,
			ObjectUID:       "uid-bug94-pdb",
			ResourceVersion: "1",
			Reason:          reason,
			Message:         "test",
			OccurrenceCount: 1,
			Severity:        "high",
			OccurredAt:      time.Now(),
			RuleID:          ruleID,
		}
	}

	if err := g.handleFinding(ctx, clusterID, finding("pdb-blocks-all-disruptions", "PDBBlocksAllDisruptions", "test-fp-bug94-pdb-1")); err != nil {
		t.Fatalf("handleFinding(first rule): %v", err)
	}
	if err := g.handleFinding(ctx, clusterID, finding("pdb-min-available-exceeds-replicas", "PDBMinAvailableExceedsReplicas", "test-fp-bug94-pdb-2")); err != nil {
		t.Fatalf("handleFinding(second rule): %v", err)
	}

	_, _, openingRuleID := openingRuleFor(t, pool, tenantID, clusterID, objectKey)
	if openingRuleID == nil || *openingRuleID != "pdb-blocks-all-disruptions" {
		got := "NULL"
		if openingRuleID != nil {
			got = *openingRuleID
		}
		t.Fatalf("opening_rule_id = %s, want %q — a second rule's finding must not take over an incident that already names the rule that opened it", got, "pdb-blocks-all-disruptions")
	}
}
