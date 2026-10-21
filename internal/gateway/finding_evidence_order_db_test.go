package gateway

import (
	"context"
	"testing"
	"time"

	"argus/internal/data"
	"argus/internal/tunnel"
)

// PROJECT.md B173.
//
// applyConditionPolarityGate (polarity_gate.go) and normalizeFindingEvidence
// (promotion.go) both run inside handleFinding (finding.go) for every
// GenericConditionAnomaly:* Finding. Before this fix, the gate ran FIRST,
// followed by normalizeFindingEvidence — so a legacy agent's Finding, which
// arrives with Class/Confidence/Impact all empty, got its Confidence raised
// to Verified by the gate while Class/Impact stayed empty; the leftover
// empty Class then made normalizeFindingEvidence's invalid-tuple branch fire
// and reset the WHOLE tuple back to (anomaly, unverified, none), discarding
// the gate's confirmation entirely.
//
// The fix reorders the two calls (normalizeFindingEvidence now runs before
// the gate) rather than changing either function's own logic: neither
// function reads a field the other one owns (normalizeFindingEvidence never
// reads Confidence; the gate never reads Class/Confidence/Impact — see both
// files' doc comments), so this changes nothing about non-generic-anomaly
// Findings or about the gate's own drop/proceed decision, only which of the
// two writes to Class/Confidence/Impact lands last.
//
// This file's two tests are B173's own acceptance pair: the gate's
// confirmation must survive (TestHandleFinding_PolarityGateConfirmation...),
// and a genuinely invalid tuple the gate never touches must still be reset
// (TestHandleFinding_GenuinelyInvalidEvidenceTuple...) — without the second
// test, the fix would be indistinguishable from deleting the invalid-tuple
// branch outright.

// TestHandleFinding_PolarityGateConfirmation_SurvivesNormalization is B173's
// positive case: a legacy-agent GenericConditionAnomaly:* Finding — empty
// Class/Confidence/Impact, but ConditionType/ConditionObservedValue
// populated — whose polarity gate confidently confirms a genuine anomaly
// (not a healthy reading) must keep that confirmation (Confidence=Verified)
// through normalizeFindingEvidence, landing on (anomaly, verified, none):
// still Class=Anomaly (the gate deliberately never raises Class — see
// polarity_gate.go and promotion.go's WouldPromoteStoredFinding comment) and
// still Impact=None (so this alone still cannot open an incident — this
// fix closes a signal-fidelity gap, not a promotion-boundary one), but no
// longer silently discarded back to Unverified.
//
// This tuple is also the exact one migration 000107's trigger
// (findings_reconcile_legacy_generic_evidence) is documented to leave alone
// — it only rewrites the byte-identical (fault, verified, degraded)
// pre-evidence default — so this test's assertion also confirms the trigger
// does not fight this fix. legacy_generic_evidence_trigger_db_test.go's
// TestLegacyGenericEvidenceTriggerLeavesEverythingElseAlone already pins
// that at the trigger level directly; this test pins it end to end through
// handleFinding.
func TestHandleFinding_PolarityGateConfirmation_SurvivesNormalization(t *testing.T) {
	const kind, condType = "B173PolarityWidget", "MemoryPressure"
	cleanupPolarityGateRow(t, kind, condType)
	t.Cleanup(func() { cleanupPolarityGateRow(t, kind, condType) })

	pool := testPool(t)
	tenantID, clusterID, fixture := timelineTestCluster(t, pool)
	fixture.Created("findings", 1)
	fixture.Created("incidents", 0)
	fixture.Created("timeline_events", 0)
	timelineCleanup(fixture, pool, tenantID, clusterID)

	g := &Gateway{db: &data.DB{Pool: pool}} // no LLM: forced onto the statistical mechanism

	fingerprint := "test-fp-b173-confirmed-" + clusterID
	f := &tunnel.Finding{
		DetectorID:      "k8s-sweep",
		DetectorVersion: "1",
		Fingerprint:     fingerprint,
		GVK:             "example.com/v1/" + kind,
		Namespace:       "default",
		ObjectName:      "b173-widget",
		ObjectUID:       "uid-" + clusterID,
		ResourceVersion: "1",
		Reason:          "GenericConditionAnomaly:" + condType,
		Message:         condType + " reads True, differing from this object's peers",
		OccurrenceCount: 1,
		Severity:        "high",
		OccurredAt:      time.Now(),
		// Legacy agent: no evidence dimensions sent at all.
		Class:      "",
		Confidence: "",
		Impact:     "",
		// But the generic-predicate condition fields ARE populated — the
		// exact shape B173 describes.
		ConditionType:             condType,
		ConditionObservedValue:    "True",  // the minority/anomalous reading
		ConditionSampleCount:      10,      // >= minStatisticalSampleCount(5): confident statistical read, no model needed
		ConditionMajorityValue:    "False", // False is the confident majority => True is the anomaly
		ConditionMajorityFraction: 0.9,
	}

	if err := g.handleFinding(context.Background(), clusterID, f); err != nil {
		t.Fatalf("handleFinding: %v", err)
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

	var class, confidence, impact string
	if err := tx.QueryRow(ctx,
		`SELECT signal_class, confidence, impact FROM findings WHERE cluster_id = $1 AND fingerprint = $2`,
		clusterID, fingerprint,
	).Scan(&class, &confidence, &impact); err != nil {
		t.Fatalf("look up the finding row handleFinding should have inserted: %v", err)
	}

	if class != "anomaly" || confidence != "verified" || impact != "none" {
		t.Fatalf("B173: got (signal_class=%s, confidence=%s, impact=%s), want (anomaly, verified, none) — "+
			"the polarity gate's confirmation must survive normalizeFindingEvidence, not be reset to unverified",
			class, confidence, impact)
	}

	var incidentCount int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM incidents WHERE cluster_id = $1`, clusterID).Scan(&incidentCount); err != nil {
		t.Fatalf("count incidents: %v", err)
	}
	if incidentCount != 0 {
		t.Fatalf("expected this confirmation NOT to open an incident (Impact stays none), got %d incidents", incidentCount)
	}
}

// TestHandleFinding_GenuinelyInvalidEvidenceTuple_StillReset is B173's
// negative case, required so the fix above cannot be mistaken for having
// weakened or deleted normalizeFindingEvidence's invalid-tuple branch: a
// Finding with a partially-populated, genuinely invalid evidence tuple and a
// Reason the polarity gate never touches (no GenericConditionAnomaly/
// GenericDanglingReference/GenericPeerConditionShapeOutlier prefix, so
// applyConditionPolarityGate returns true immediately without writing
// anything) must still land on the safe (anomaly, unverified, none) default
// — trusting half of an invalid tuple would be a broad trust hole traded for
// closing this narrow one.
func TestHandleFinding_GenuinelyInvalidEvidenceTuple_StillReset(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, fixture := timelineTestCluster(t, pool)
	fixture.Created("findings", 1)
	fixture.Created("incidents", 0)
	fixture.Created("timeline_events", 0)
	timelineCleanup(fixture, pool, tenantID, clusterID)

	g := &Gateway{db: &data.DB{Pool: pool}}

	fingerprint := "test-fp-b173-invalid-" + clusterID
	f := &tunnel.Finding{
		DetectorID:      "k8s-sweep",
		DetectorVersion: "1",
		Fingerprint:     fingerprint,
		GVK:             "v1/Pod",
		Namespace:       "default",
		ObjectName:      "invalid-tuple-pod",
		ObjectUID:       "uid-" + clusterID,
		ResourceVersion: "1",
		// Deliberately NOT a generic-anomaly reason: the polarity gate must
		// never touch this Finding at all.
		Reason:          "SomeOrdinaryDetectorReason",
		Message:         "an ordinary detector finding with a broken evidence tuple",
		OccurrenceCount: 1,
		Severity:        "high",
		OccurredAt:      time.Now(),
		// Partially populated and invalid on its face: Class is a real
		// value, Confidence is nonsense, Impact is empty — not the
		// "all three empty" legacy shape, and not a tuple any mechanism in
		// this codebase (the polarity gate included) would ever produce.
		Class:      tunnel.FindingClassFault,
		Confidence: "extremely-sure",
		Impact:     "",
	}

	if err := g.handleFinding(context.Background(), clusterID, f); err != nil {
		t.Fatalf("handleFinding: %v", err)
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

	var class, confidence, impact string
	if err := tx.QueryRow(ctx,
		`SELECT signal_class, confidence, impact FROM findings WHERE cluster_id = $1 AND fingerprint = $2`,
		clusterID, fingerprint,
	).Scan(&class, &confidence, &impact); err != nil {
		t.Fatalf("look up the finding row handleFinding should have inserted: %v", err)
	}

	if class != "anomaly" || confidence != "unverified" || impact != "none" {
		t.Fatalf("B173 regression: a genuinely invalid evidence tuple with no polarity-gate involvement landed as "+
			"(signal_class=%s, confidence=%s, impact=%s), want (anomaly, unverified, none) — "+
			"the invalid-tuple branch must still fire for a tuple the gate never confirmed",
			class, confidence, impact)
	}

	var incidentCount int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM incidents WHERE cluster_id = $1`, clusterID).Scan(&incidentCount); err != nil {
		t.Fatalf("count incidents: %v", err)
	}
	if incidentCount != 0 {
		t.Fatalf("expected the reset tuple NOT to open an incident, got %d incidents", incidentCount)
	}
}
