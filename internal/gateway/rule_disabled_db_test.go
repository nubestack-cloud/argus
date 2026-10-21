package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/tunnel"
)

// setDisabledRuleIDsForTest points org_settings.disabled_rule_ids at exactly
// ids for the duration of the calling test, restoring whatever value was
// there before on cleanup. org_settings carries no row-level security at all
// (migration 000018's comment; see also settings.Resolve's querier, which
// reads it via the bare pool with no scoped transaction), so this reads/
// writes the singleton row directly, the same way settings.Resolve itself
// does.
//
// This package's tests never use t.Parallel() (see tools_retry_test.go's own
// note), so mutating this single shared row for the duration of one test is
// safe — there is no concurrent test in this package that could observe the
// temporary value.
func setDisabledRuleIDsForTest(t *testing.T, pool *pgxpool.Pool, ids []string) {
	t.Helper()
	ctx := context.Background()

	var previous []string
	if err := pool.QueryRow(ctx, `SELECT disabled_rule_ids FROM org_settings WHERE id = 'singleton'`).Scan(&previous); err != nil {
		t.Fatalf("read current disabled_rule_ids: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE org_settings SET disabled_rule_ids = $1 WHERE id = 'singleton'`, ids); err != nil {
		t.Fatalf("set disabled_rule_ids: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := pool.Exec(ctx, `UPDATE org_settings SET disabled_rule_ids = $1 WHERE id = 'singleton'`, previous); err != nil {
			t.Errorf("restore disabled_rule_ids: %v", err)
		}
	})
}

// TestHandleFindingDropsDisabledRuleButNotItsSiblingDetector is BUGS.md 111's
// acceptance test at the handleFinding level (the pure-function-level case is
// TestIsRuleDisabled above): a Finding whose RuleID is in
// org_settings.disabled_rule_ids must be dropped in full — no findings row,
// no incident — while a DIFFERENT rule's Finding, sharing the exact SAME
// DetectorID ("k8s-sweep", the shared ID every rule-format finding carries
// per sweep_detector.go), still creates an incident normally. That second
// half is the actual bug: before this fix, the only way to silence one rule
// was DisabledDetectorIDs, which would have dropped BOTH of these findings,
// not just the disabled one.
func TestHandleFindingDropsDisabledRuleButNotItsSiblingDetector(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, fixture := timelineTestCluster(t, pool)
	// The disabled rule's finding is dropped before its transaction ever
	// opens — no findings row, no incident. The still-enabled rule's finding
	// is a normal promoted finding that opens its own incident: one incident,
	// one IncidentOpened event, one findings row.
	fixture.Created("incidents", 1)
	fixture.Created("findings", 1)
	fixture.Created("timeline_events", 1)
	timelineCleanup(fixture, pool, tenantID, clusterID)
	setDisabledRuleIDsForTest(t, pool, []string{"pdb-blocks-all-disruptions"})
	g := &Gateway{db: &data.DB{Pool: pool}}

	disabledFinding := &tunnel.Finding{
		DetectorID:      "k8s-sweep",
		DetectorVersion: "1",
		RuleID:          "pdb-blocks-all-disruptions",
		Fingerprint:     "test-fp-disabled-rule-" + clusterID,
		GVK:             "policy/v1/PodDisruptionBudget",
		Namespace:       "default",
		ObjectName:      "rule-disabled-test-pdb",
		ObjectUID:       "uid-disabled-" + clusterID,
		ResourceVersion: "1",
		Reason:          "PodDisruptionBudgetBlocksAllDisruptions",
		Message:         "this PDB blocks all voluntary disruptions",
		OccurrenceCount: 1,
		Severity:        "medium",
		OccurredAt:      time.Now(),
	}
	// A different rule, deliberately sharing disabledFinding's DetectorID —
	// this is the exact scenario BUGS.md 111 describes: two different rules'
	// findings, same shared sweep-detector ID, only one of them disabled.
	stillEnabledFinding := &tunnel.Finding{
		DetectorID:      "k8s-sweep",
		DetectorVersion: "1",
		RuleID:          "hpa-pegged-at-max-replicas",
		Fingerprint:     "test-fp-still-enabled-rule-" + clusterID,
		GVK:             "autoscaling/v2/HorizontalPodAutoscaler",
		Namespace:       "default",
		ObjectName:      "rule-disabled-test-hpa",
		ObjectUID:       "uid-enabled-" + clusterID,
		ResourceVersion: "1",
		Reason:          "HorizontalPodAutoscalerPeggedAtMaxReplicas",
		Message:         "this HPA has been pegged at its max replica count",
		OccurrenceCount: 1,
		Severity:        "medium",
		OccurredAt:      time.Now(),
	}

	if err := g.handleFinding(context.Background(), clusterID, disabledFinding); err != nil {
		t.Fatalf("handleFinding(disabled rule finding): %v", err)
	}
	if err := g.handleFinding(context.Background(), clusterID, stillEnabledFinding); err != nil {
		t.Fatalf("handleFinding(still-enabled rule finding): %v", err)
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

	// The disabled rule's finding must have been dropped before ever
	// reaching the transaction that would have recorded a findings row or
	// opened an incident — matching handleFinding's documented
	// "no findings row, no incident touched" contract for the
	// detector-level filter, mirrored here for the rule-level one.
	var disabledFindingCount, disabledIncidentCount int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM findings WHERE cluster_id = $1 AND fingerprint = $2`,
		clusterID, disabledFinding.Fingerprint).Scan(&disabledFindingCount); err != nil {
		t.Fatalf("count findings for disabled rule: %v", err)
	}
	if disabledFindingCount != 0 {
		t.Errorf("findings rows for disabled rule %q = %d, want 0 (dropped in full)", disabledFinding.RuleID, disabledFindingCount)
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM incidents WHERE cluster_id = $1 AND fingerprint = $2`,
		clusterID, disabledFinding.Fingerprint).Scan(&disabledIncidentCount); err != nil {
		t.Fatalf("count incidents for disabled rule: %v", err)
	}
	if disabledIncidentCount != 0 {
		t.Errorf("incident rows for disabled rule %q = %d, want 0 (dropped in full)", disabledFinding.RuleID, disabledIncidentCount)
	}

	// The still-enabled rule's finding, sharing the SAME DetectorID as the
	// disabled one, must still open a real incident — this is the property
	// that was impossible before BUGS.md 111's fix (disabling the shared
	// detector ID would have dropped this one too).
	var enabledIncidentID string
	if err := tx.QueryRow(ctx, `SELECT id FROM incidents WHERE cluster_id = $1 AND fingerprint = $2`,
		clusterID, stillEnabledFinding.Fingerprint).Scan(&enabledIncidentID); err != nil {
		t.Fatalf("look up the incident the still-enabled rule's finding should have opened: %v", err)
	}
	if enabledIncidentID == "" {
		t.Errorf("expected a real incident id for the still-enabled rule's finding, got empty")
	}
}
