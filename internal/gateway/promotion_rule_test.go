package gateway

import (
	"slices"
	"strings"
	"testing"

	"argus/internal/tunnel"
)

// PROJECT.md F31. promotion.go's rule statement, per-row explanation and SQL
// predicate are all DERIVED by enumerating shouldPromoteFinding's input
// domain rather than restating the rule. This file pins the assumptions that
// derivation rests on. If one of them stops holding, the derivation would go
// on producing a confident, wrong answer — so each gets a test that fails
// loudly rather than a comment asking the next person to remember.

// allEvidenceTuples is the gate's entire input domain: every legal
// (class, confidence, impact) the CHECK constraints admit. 3 x 3 x 4 = 36.
func allEvidenceTuples() [][3]string {
	var out [][3]string
	for _, class := range findingClasses {
		for _, confidence := range findingConfidences {
			for _, impact := range findingImpacts {
				out = append(out, [3]string{class, confidence, impact})
			}
		}
	}
	return out
}

// TestPromotionRuleIsSeparablePerDimension is the load-bearing one.
//
// buildPromotionRule collects, per dimension, every value that appears in ANY
// promotable tuple, and PromotionVerdict.Unmet then reports a dimension as
// failing whenever its value is outside that set. Both steps are only
// faithful if the gate is a conjunction of independent per-dimension
// predicates — which shouldPromoteFinding is today, and which nothing
// structurally prevents a future edit from breaking (an impact acceptable
// only for one class, say).
//
// So: for all 36 tuples, "the gate promotes it" must equal "all three values
// are in their accepted sets". The day that stops being true, the rule
// statement in every findings response would be claiming a rule the gate does
// not enforce, and this fails instead.
func TestPromotionRuleIsSeparablePerDimension(t *testing.T) {
	rule := PromotionRule()
	accepted := map[string][]string{}
	for _, c := range rule.Criteria {
		accepted[c.Dimension] = c.Accepted
	}
	if len(accepted) != 3 {
		t.Fatalf("rule has %d criteria, want one each for class/confidence/impact: %+v", len(accepted), rule.Criteria)
	}

	for _, tuple := range allEvidenceTuples() {
		class, confidence, impact := tuple[0], tuple[1], tuple[2]
		gate := shouldPromoteFinding(&tunnel.Finding{Class: class, Confidence: confidence, Impact: impact})
		perDimension := slices.Contains(accepted["class"], class) &&
			slices.Contains(accepted["confidence"], confidence) &&
			slices.Contains(accepted["impact"], impact)
		if gate != perDimension {
			t.Errorf("(%s, %s, %s): gate says promotable=%v, the derived per-dimension rule says %v — the boundary is no longer a conjunction of independent per-dimension predicates, so PromotionRule() and PromotionVerdict.Unmet now describe a rule that is not the one being enforced",
				class, confidence, impact, gate, perDimension)
		}
	}
}

// TestPromotionRuleStatementsMatchTheirAcceptedValues guards the other half of
// the same honesty: a criterion's prose is generated from its Accepted list,
// so it can never be edited into contradicting it. This asserts that
// generation actually happened rather than someone hand-writing the strings
// back in later.
func TestPromotionRuleStatementsMatchTheirAcceptedValues(t *testing.T) {
	for _, c := range PromotionRule().Criteria {
		if len(c.Accepted) == 0 {
			t.Errorf("criterion %q accepts nothing at all — no finding could ever be promoted", c.Dimension)
			continue
		}
		want := c.Dimension + " must be " + strings.Join(c.Accepted, " or ")
		if c.Statement != want {
			t.Errorf("criterion %q statement = %q, want %q — prose and accepted values must not be able to disagree", c.Dimension, c.Statement, want)
		}
	}
}

// TestPromotionRuleIsACopy: PromotionRule's return value ends up marshalled
// into an HTTP response on every findings list. If it handed out the package
// slices, one caller sorting or appending to them would silently rewrite the
// rule every later request reports — and, worse, the accepted sets
// ExplainStoredFinding reads to compute Unmet.
func TestPromotionRuleIsACopy(t *testing.T) {
	first := PromotionRule()
	first.Criteria[0].Accepted = append(first.Criteria[0].Accepted[:0], "anomaly")
	second := PromotionRule()
	if got := second.Criteria[0].Accepted; len(got) != 1 || got[0] != tunnel.FindingClassFault {
		t.Errorf("after a caller overwrote its copy, PromotionRule() returns class accepted=%v, want [%s]", got, tunnel.FindingClassFault)
	}
}

// TestExplainStoredFindingNamesWhatFailed is the operator-facing claim: a row
// that stayed a finding says which criteria it missed, not just that it
// missed. The legacy case is the one worth spelling out — its stored tuple is
// (fault, verified, degraded), which reads as promotable, and the verdict must
// report the CORRECTED tuple plus the flag saying so, or the response looks
// like it is contradicting the row it describes.
func TestExplainStoredFindingNamesWhatFailed(t *testing.T) {
	tests := []struct {
		name                            string
		reason, class, conf, impact     string
		wantPromotable, wantCorrected   bool
		wantUnmet                       []string
		wantClass, wantConf, wantImpact string
	}{
		{
			name:   "a real fault is promotable and explains nothing",
			reason: "CrashLoopBackOff", class: tunnel.FindingClassFault,
			conf: tunnel.FindingConfidenceVerified, impact: tunnel.FindingImpactDegraded,
			wantPromotable: true, wantUnmet: nil,
			wantClass: tunnel.FindingClassFault, wantConf: tunnel.FindingConfidenceVerified, wantImpact: tunnel.FindingImpactDegraded,
		},
		{
			name:   "a risk fails on class and impact, not on confidence",
			reason: "JobMissingActiveDeadlineSeconds", class: tunnel.FindingClassRisk,
			conf: tunnel.FindingConfidenceVerified, impact: tunnel.FindingImpactPotential,
			wantUnmet: []string{"class", "impact"},
			wantClass: tunnel.FindingClassRisk, wantConf: tunnel.FindingConfidenceVerified, wantImpact: tunnel.FindingImpactPotential,
		},
		{
			name:   "an unverified fault fails on confidence alone",
			reason: "SomethingLooksOff", class: tunnel.FindingClassFault,
			conf: tunnel.FindingConfidenceUnverified, impact: tunnel.FindingImpactDegraded,
			wantUnmet: []string{"confidence"},
			wantClass: tunnel.FindingClassFault, wantConf: tunnel.FindingConfidenceUnverified, wantImpact: tunnel.FindingImpactDegraded,
		},
		{
			name:   "a legacy generic row stored as the 000092 defaults is judged on the corrected tuple and says so",
			reason: "GenericConditionAnomaly:CreatorMadeOwner", class: tunnel.FindingClassFault,
			conf: tunnel.FindingConfidenceVerified, impact: tunnel.FindingImpactDegraded,
			wantCorrected: true, wantUnmet: []string{"class", "confidence", "impact"},
			wantClass: tunnel.FindingClassAnomaly, wantConf: tunnel.FindingConfidenceUnverified, wantImpact: tunnel.FindingImpactNone,
		},
		{
			name:   "a generic mechanism whose polarity gate confirmed it is NOT corrected — only the exact default triple is",
			reason: "GenericConditionAnomaly:Ready", class: tunnel.FindingClassAnomaly,
			conf: tunnel.FindingConfidenceVerified, impact: tunnel.FindingImpactNone,
			wantUnmet: []string{"class", "impact"},
			wantClass: tunnel.FindingClassAnomaly, wantConf: tunnel.FindingConfidenceVerified, wantImpact: tunnel.FindingImpactNone,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ExplainStoredFinding(tc.reason, tc.class, tc.conf, tc.impact)
			if got.Promotable != tc.wantPromotable {
				t.Errorf("promotable = %v, want %v", got.Promotable, tc.wantPromotable)
			}
			if got.Corrected != tc.wantCorrected {
				t.Errorf("evidenceCorrected = %v, want %v", got.Corrected, tc.wantCorrected)
			}
			if !slices.Equal(got.Unmet, tc.wantUnmet) {
				t.Errorf("unmet = %v, want %v", got.Unmet, tc.wantUnmet)
			}
			if got.Class != tc.wantClass || got.Confidence != tc.wantConf || got.Impact != tc.wantImpact {
				t.Errorf("effective tuple = (%s, %s, %s), want (%s, %s, %s)",
					got.Class, got.Confidence, got.Impact, tc.wantClass, tc.wantConf, tc.wantImpact)
			}
		})
	}
}

// TestExplainStoredFindingAgreesWithWouldPromote: WouldPromoteStoredFinding is
// now a one-line caller of ExplainStoredFinding, and internal/api's promotion
// reconciliation closes real incidents through it. Pinned over the whole
// domain on both sides of the legacy correction so a future refactor that
// re-splits them cannot quietly change what gets closed.
func TestExplainStoredFindingAgreesWithWouldPromote(t *testing.T) {
	for _, reason := range []string{"CrashLoopBackOff", "GenericConditionAnomaly:Ready", legacyGenericAnomalyExact, ""} {
		for _, tuple := range allEvidenceTuples() {
			want := ExplainStoredFinding(reason, tuple[0], tuple[1], tuple[2]).Promotable
			if got := WouldPromoteStoredFinding(reason, tuple[0], tuple[1], tuple[2]); got != want {
				t.Errorf("reason=%q %v: WouldPromoteStoredFinding=%v, ExplainStoredFinding=%v", reason, tuple, got, want)
			}
		}
	}
}

// TestLegacyReasonsAreInterchangeable is the assumption buildPromotableFindingSQL
// relies on when it renders ONE legacy branch from ONE representative reason:
// legacyGenericAnomaly is a boolean, so every reason it accepts must take the
// identical correction. If a future mechanism needed its own treatment, the
// SQL's single CASE branch would quietly apply the wrong one.
func TestLegacyReasonsAreInterchangeable(t *testing.T) {
	reasons := []string{legacyGenericAnomalyExact}
	for _, prefix := range legacyGenericAnomalyPrefixes {
		reasons = append(reasons, prefix+"Ready", prefix+"SomethingElse")
	}
	for _, tuple := range allEvidenceTuples() {
		want := ExplainStoredFinding(reasons[0], tuple[0], tuple[1], tuple[2])
		for _, reason := range reasons[1:] {
			got := ExplainStoredFinding(reason, tuple[0], tuple[1], tuple[2])
			if got.Promotable != want.Promotable || got.Corrected != want.Corrected ||
				got.Class != want.Class || got.Confidence != want.Confidence || got.Impact != want.Impact {
				t.Fatalf("legacy reasons disagree on %v: %q -> %+v, %q -> %+v", tuple, reasons[0], want, reason, got)
			}
		}
		// And a reason the predicate does NOT accept must not be corrected.
		if plain := ExplainStoredFinding("CrashLoopBackOff", tuple[0], tuple[1], tuple[2]); plain.Corrected {
			t.Fatalf("a non-legacy reason was corrected on %v", tuple)
		}
	}
}

// TestPromotableFindingSQLIsRenderable is the cheap, database-free half of
// the SQL check (promotion_sql_db_test.go runs it inside Postgres): the
// predicate must name only the three evidence columns and the reason column,
// carry no placeholder a caller would have to supply, and quote every literal.
func TestPromotableFindingSQLIsRenderable(t *testing.T) {
	sql := PromotableFindingSQL()
	if strings.Contains(sql, "$") {
		t.Errorf("predicate contains a placeholder, so it cannot be spliced into an arbitrary query: %s", sql)
	}
	for _, col := range []string{"findings.signal_class", "findings.confidence", "findings.impact", "findings.reason"} {
		if !strings.Contains(sql, col) {
			t.Errorf("predicate never mentions %s: %s", col, sql)
		}
	}
	if strings.Count(sql, "'")%2 != 0 {
		t.Errorf("odd number of quote characters — something is unquoted: %s", sql)
	}
}
