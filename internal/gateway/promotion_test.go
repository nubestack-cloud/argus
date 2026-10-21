package gateway

import (
	"testing"

	"argus/internal/tunnel"
)

func TestShouldPromoteFindingUsesEvidenceNotKindOrReason(t *testing.T) {
	tests := []struct {
		name string
		f    tunnel.Finding
		want bool
	}{
		{"verified degraded fault", tunnel.Finding{Class: "fault", Confidence: "verified", Impact: "degraded"}, true},
		{"inferred unavailable fault", tunnel.Finding{Class: "fault", Confidence: "inferred", Impact: "unavailable"}, true},
		{"unverified fault", tunnel.Finding{Class: "fault", Confidence: "unverified", Impact: "degraded"}, false},
		{"verified risk", tunnel.Finding{Class: "risk", Confidence: "verified", Impact: "potential"}, false},
		{"verified anomaly", tunnel.Finding{Class: "anomaly", Confidence: "verified", Impact: "degraded"}, false},
		{"fault with potential impact", tunnel.Finding{Class: "fault", Confidence: "verified", Impact: "potential"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldPromoteFinding(&tt.f); got != tt.want {
				t.Fatalf("shouldPromoteFinding(%+v) = %v, want %v", tt.f, got, tt.want)
			}
		})
	}
}

func TestNormalizeFindingEvidenceKeepsLegacyCompatibilityWithoutPromotingGenericUncertainty(t *testing.T) {
	legacyFault := &tunnel.Finding{Reason: "CrashLoopBackOff"}
	normalizeFindingEvidence(legacyFault)
	if !shouldPromoteFinding(legacyFault) {
		t.Fatalf("legacy fault normalized to %+v, want incident-compatible evidence", legacyFault)
	}

	for _, reason := range []string{
		"GenericConditionAnomaly:Ready",
		"GenericDanglingReference:Secret",
		"GenericPeerConditionShapeOutlier",
	} {
		f := &tunnel.Finding{Reason: reason}
		normalizeFindingEvidence(f)
		if shouldPromoteFinding(f) {
			t.Errorf("legacy generic anomaly %q normalized to promotable evidence: %+v", reason, f)
		}
		if f.Class != tunnel.FindingClassAnomaly || f.Confidence != tunnel.FindingConfidenceUnverified || f.Impact != tunnel.FindingImpactNone {
			t.Errorf("legacy generic anomaly %q normalized to %+v", reason, f)
		}
	}
}

func TestNormalizeMalformedEvidenceFailsTowardObservation(t *testing.T) {
	f := &tunnel.Finding{Class: "fault", Confidence: "certain-ish", Impact: "huge"}
	normalizeFindingEvidence(f)
	if shouldPromoteFinding(f) {
		t.Fatalf("malformed evidence became promotable: %+v", f)
	}
}

// TestWouldPromoteStoredFinding pins the read-time verdict the promotion
// reconciliation (internal/api/incident_promotion_reconcile.go) closes
// incidents on. The interesting rows are the last group: a generic mechanism
// carrying migration 000092's exact column defaults is a row written by a hub
// that predates these columns, not an assertion that anything is wrong, and
// reading it as a verified fault is what leaves 42 permanently-unclosable
// incidents in an operator's queue.
func TestWouldPromoteStoredFinding(t *testing.T) {
	tests := []struct {
		name                        string
		reason, class, conf, impact string
		want                        bool
	}{
		// An ordinary detector row is judged purely on its stored evidence.
		{"real fault", "CrashLoopBackOff", "fault", "verified", "degraded", true},
		{"real fault, inferred and unavailable", "PendingTimeout", "fault", "inferred", "unavailable", true},
		{"declared risk", "JobMissingActiveDeadlineSeconds", "risk", "verified", "potential", false},
		{"unverified fault", "ServiceNoEndpoints", "fault", "unverified", "degraded", false},

		// Backfilled generic rows: 000092 already wrote the honest tuple.
		{"backfilled generic anomaly", "GenericConditionAnomaly:Ready", "anomaly", "unverified", "none", false},
		{"polarity-confirmed generic anomaly", "GenericConditionAnomaly:Ready", "anomaly", "verified", "none", false},

		// The residue: written after 000092 ran, by a build that did not know
		// the columns existed, so the tuple is the schema default.
		{"generic condition anomaly at schema default", "GenericConditionAnomaly:CreatorMadeOwner", "fault", "verified", "degraded", false},
		{"generic dangling reference at schema default", "GenericDanglingReference:Secret", "fault", "verified", "degraded", false},
		{"generic shape outlier at schema default", "GenericPeerConditionShapeOutlier", "fault", "verified", "degraded", false},

		// The correction is narrow: it reads the default triple, and nothing
		// else. A generic reason carrying any other fault tuple would have to
		// have been asserted by something, so it is left alone and promotes —
		// which is what makes a future decision to fault-class a generic
		// mechanism visible rather than silently swallowed here.
		{"generic reason with a non-default fault tuple", "GenericConditionAnomaly:Ready", "fault", "inferred", "unavailable", true},

		// A non-generic reason at the same default triple IS the pre-evidence
		// behaviour migration 000092 deliberately preserved, and must keep it.
		{"legacy non-generic row at schema default", "ImagePullBackOff", "fault", "verified", "degraded", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := WouldPromoteStoredFinding(tt.reason, tt.class, tt.conf, tt.impact); got != tt.want {
				t.Fatalf("WouldPromoteStoredFinding(%q, %q, %q, %q) = %v, want %v",
					tt.reason, tt.class, tt.conf, tt.impact, got, tt.want)
			}
		})
	}
}
