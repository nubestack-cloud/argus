package api

import (
	"context"
	"testing"
	"time"

	"argus/internal/data"
	"argus/internal/domain"
)

// BUGS.md 121 part (b): queryIssueClasses/queryNoisyNamespaces rank
// fleet-wide, ALL-HISTORY top-N by raw count, which structurally cannot
// surface a small, brand-new signal once an old, high-volume one already
// dominates the ranking. The owner's decision was to keep that ranking
// completely unchanged and ADD queryNewIssueClasses/queryNewNoisyNamespaces
// as a separate "new in this window" pair alongside it — this file is the
// regression coverage for both halves of that decision: the new queries
// surface the new signal and exclude the old dominant one, and the EXISTING
// queries keep ranking exactly as they did before this task touched
// anything.
//
// Single transaction, no commit, matching
// TestQueryDetectionDryRunFindings_DanglingIncidentIDDoesNotCrash's pattern
// (detection_dryrun_db_test.go): findings.incident_id carries no FK to
// incidents, so a synthetic incident_id string needs no real incidents row,
// and rolling the transaction back on defer is all the cleanup a
// never-committed insert needs.

func TestQueryNewIssueClassesAndNewNoisyNamespaces(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	clusterID := domain.NewID(domain.PrefixCluster)
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "new-signals-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert throwaway cluster: %v", err)
	}

	oldFP := "old-dominant-fp-" + clusterID
	oldNS := "old-dominant-ns-" + clusterID
	newFP := "new-signal-fp-" + clusterID
	newNS := "new-signal-ns-" + clusterID
	now := time.Now()

	insertFinding := func(fingerprint, namespace string, occurrenceCount int, occurredAt time.Time) {
		id := domain.NewID(domain.PrefixFinding)
		incidentID := domain.NewID(domain.PrefixIncident) // no FK — a synthetic id is enough
		if _, err := tx.Exec(ctx,
			`INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint,
			                       gvk, namespace, object_name, reason, occurrence_count, occurred_at,
			                       ingested_at, severity, incident_id)
			 VALUES ($1, $2, $3, 'k8s-warning-events', 'v1', $4, 'v1/Pod', $5, 'obj', 'TestReason', $6, $7, $7, 'medium', $8)`,
			id, tenantID, clusterID, fingerprint, namespace, occurrenceCount, occurredAt, incidentID); err != nil {
			t.Fatalf("insert finding (fp=%s ns=%s): %v", fingerprint, namespace, err)
		}
	}

	// Old, high-volume signal: 4 findings, occurrence_count=5 each
	// (totalOccurrences=20, incidentCount=4), every one well OUTSIDE
	// insightsNewSignalWindowDays (7 days) — from 60 days ago down to 10
	// days ago. This must dominate the existing top-N ranking AND be
	// entirely absent from the "new" lists.
	for _, daysAgo := range []int{60, 45, 30, 10} {
		insertFinding(oldFP, oldNS, 5, now.AddDate(0, 0, -daysAgo))
	}

	// New signal: 2 findings, occurrence_count=1 each (totalOccurrences=2,
	// incidentCount=2), every one INSIDE the window — 2 days and 1 day ago.
	// Small enough that it would never survive an all-time count-based
	// ranking against the old signal above, which is exactly BUGS.md 121's
	// point.
	for _, daysAgo := range []int{2, 1} {
		insertFinding(newFP, newNS, 1, now.AddDate(0, 0, -daysAgo))
	}

	// --- Regression: the EXISTING queries are untouched by this task ---
	// Both groups are visible, ranked purely by count, oldest-and-biggest
	// first — exactly as queryIssueClasses/queryNoisyNamespaces behaved
	// before this task added anything.
	issueClasses, err := queryIssueClasses(ctx, tx, clusterID, 0)
	if err != nil {
		t.Fatalf("queryIssueClasses: %v", err)
	}
	if len(issueClasses) != 2 {
		t.Fatalf("queryIssueClasses returned %d rows, want 2 (old dominant + new): %+v", len(issueClasses), issueClasses)
	}
	if issueClasses[0].Fingerprint != oldFP {
		t.Errorf("queryIssueClasses[0].Fingerprint = %s, want the old dominant fingerprint %s ranked first by count — existing ranking must be unchanged", issueClasses[0].Fingerprint, oldFP)
	}
	if issueClasses[0].IncidentCount != 4 || issueClasses[0].TotalOccurrences != 20 {
		t.Errorf("old dominant issue class = %+v, want incidentCount=4 totalOccurrences=20", issueClasses[0])
	}
	if issueClasses[1].Fingerprint != newFP {
		t.Errorf("queryIssueClasses[1].Fingerprint = %s, want the new fingerprint %s", issueClasses[1].Fingerprint, newFP)
	}

	noisyNamespaces, err := queryNoisyNamespaces(ctx, tx, clusterID, 0)
	if err != nil {
		t.Fatalf("queryNoisyNamespaces: %v", err)
	}
	if len(noisyNamespaces) != 2 {
		t.Fatalf("queryNoisyNamespaces returned %d rows, want 2: %+v", len(noisyNamespaces), noisyNamespaces)
	}
	if noisyNamespaces[0].Namespace != oldNS {
		t.Errorf("queryNoisyNamespaces[0].Namespace = %s, want the old dominant namespace %s ranked first — existing ranking must be unchanged", noisyNamespaces[0].Namespace, oldNS)
	}
	if noisyNamespaces[0].FindingCount != 4 {
		t.Errorf("old dominant namespace FindingCount = %d, want 4", noisyNamespaces[0].FindingCount)
	}

	// --- The new "new in this window" lists ---
	newIssueClasses, err := queryNewIssueClasses(ctx, tx, clusterID)
	if err != nil {
		t.Fatalf("queryNewIssueClasses: %v", err)
	}
	if len(newIssueClasses) != 1 {
		t.Fatalf("queryNewIssueClasses returned %d rows, want exactly 1 (the new signal only): %+v", len(newIssueClasses), newIssueClasses)
	}
	if newIssueClasses[0].Fingerprint != newFP {
		t.Errorf("queryNewIssueClasses[0].Fingerprint = %s, want %s", newIssueClasses[0].Fingerprint, newFP)
	}
	if newIssueClasses[0].IncidentCount != 2 || newIssueClasses[0].TotalOccurrences != 2 {
		t.Errorf("new issue class = %+v, want incidentCount=2 totalOccurrences=2", newIssueClasses[0])
	}
	for _, ic := range newIssueClasses {
		if ic.Fingerprint == oldFP {
			t.Errorf("queryNewIssueClasses must NOT include the old dominant fingerprint %s, even though it dominates queryIssueClasses: %+v", oldFP, newIssueClasses)
		}
	}

	newNoisyNamespaces, err := queryNewNoisyNamespaces(ctx, tx, clusterID)
	if err != nil {
		t.Fatalf("queryNewNoisyNamespaces: %v", err)
	}
	if len(newNoisyNamespaces) != 1 {
		t.Fatalf("queryNewNoisyNamespaces returned %d rows, want exactly 1: %+v", len(newNoisyNamespaces), newNoisyNamespaces)
	}
	if newNoisyNamespaces[0].Namespace != newNS {
		t.Errorf("queryNewNoisyNamespaces[0].Namespace = %s, want %s", newNoisyNamespaces[0].Namespace, newNS)
	}
	if newNoisyNamespaces[0].FindingCount != 2 {
		t.Errorf("new namespace FindingCount = %d, want 2", newNoisyNamespaces[0].FindingCount)
	}
	if newNoisyNamespaces[0].FirstSeen == "" {
		t.Error("new namespace FirstSeen is empty, want a real timestamp")
	}
	for _, ns := range newNoisyNamespaces {
		if ns.Namespace == oldNS {
			t.Errorf("queryNewNoisyNamespaces must NOT include the old dominant namespace %s, even though it dominates queryNoisyNamespaces: %+v", oldNS, newNoisyNamespaces)
		}
	}

	// --- clusterId scoping: an unrelated cluster id sees neither group ---
	otherCluster := domain.NewID(domain.PrefixCluster)
	if empty, err := queryNewIssueClasses(ctx, tx, otherCluster); err != nil {
		t.Fatalf("queryNewIssueClasses (other cluster): %v", err)
	} else if len(empty) != 0 {
		t.Errorf("queryNewIssueClasses(otherCluster) = %+v, want empty", empty)
	}
}
