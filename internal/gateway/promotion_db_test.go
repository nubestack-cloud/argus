package gateway

import (
	"context"
	"testing"
	"time"

	"argus/internal/data"
	"argus/internal/tunnel"
)

func TestHandleFindingPersistsRiskWithoutOpeningIncident(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, fixture := timelineTestCluster(t, pool)
	// A Risk-classed finding is never promoted (shouldPromoteFinding requires
	// Class == fault), so it gets a findings row but no incident and no
	// timeline event — that is exactly the property this test asserts.
	fixture.Created("findings", 1)
	fixture.Created("incidents", 0)
	fixture.Created("timeline_events", 0)
	timelineCleanup(fixture, pool, tenantID, clusterID)
	g := &Gateway{db: &data.DB{Pool: pool}}
	f := &tunnel.Finding{
		DetectorID: "k8s-sweep", DetectorVersion: "v1", Fingerprint: "risk-" + clusterID,
		GVK: "batch/v1/Job", Namespace: "default", ObjectName: "completed-job",
		Reason: "JobMissingActiveDeadlineSeconds", Message: "no deadline", Severity: "low",
		OccurrenceCount: 1, OccurredAt: time.Now(), Class: tunnel.FindingClassRisk,
		Confidence: tunnel.FindingConfidenceVerified, Impact: tunnel.FindingImpactPotential,
	}
	if err := g.handleFinding(context.Background(), clusterID, f); err != nil {
		t.Fatalf("handleFinding: %v", err)
	}

	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatal(err)
	}
	var findings, incidents int
	var class, confidence, impact string
	if err := tx.QueryRow(ctx, `SELECT count(*), max(signal_class), max(confidence), max(impact) FROM findings WHERE cluster_id=$1 AND fingerprint=$2`, clusterID, f.Fingerprint).Scan(&findings, &class, &confidence, &impact); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM incidents WHERE cluster_id=$1 AND fingerprint=$2`, clusterID, f.Fingerprint).Scan(&incidents); err != nil {
		t.Fatal(err)
	}
	if findings != 1 || incidents != 0 || class != "risk" || confidence != "verified" || impact != "potential" {
		t.Fatalf("findings=%d incidents=%d evidence=%s/%s/%s", findings, incidents, class, confidence, impact)
	}
}
