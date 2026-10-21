package gateway

import (
	"slices"
	"strings"

	"argus/internal/tunnel"
)

// normalizeFindingEvidence canonicalizes the evidence dimensions before they
// are persisted or used for promotion. A completely empty evidence tuple is a
// legacy agent finding and retains the old incident-opening behavior. Generic
// anomaly mechanisms are the exception: older agents already identify those
// mechanisms in Reason, so treating their uncertainty as an active fault would
// preserve the exact noise this promotion boundary exists to stop.
func normalizeFindingEvidence(f *tunnel.Finding) {
	if f.Class == "" && f.Confidence == "" && f.Impact == "" {
		if legacyGenericAnomaly(f.Reason) {
			f.Class = tunnel.FindingClassAnomaly
			f.Confidence = tunnel.FindingConfidenceUnverified
			f.Impact = tunnel.FindingImpactNone
			return
		}
		f.Class = tunnel.FindingClassFault
		f.Confidence = tunnel.FindingConfidenceVerified
		f.Impact = tunnel.FindingImpactDegraded
		return
	}

	if !validFindingClass(f.Class) || !validFindingConfidence(f.Confidence) || !validFindingImpact(f.Impact) {
		f.Class = tunnel.FindingClassAnomaly
		f.Confidence = tunnel.FindingConfidenceUnverified
		f.Impact = tunnel.FindingImpactNone
	}
}

// shouldPromoteFinding is intentionally independent of Kind and Reason. Only
// an active fault, supported by more than explicitly unverified evidence and
// carrying observed degradation or unavailability, enters incident
// correlation. Risks and anomalies remain queryable findings.
func shouldPromoteFinding(f *tunnel.Finding) bool {
	return f.Class == tunnel.FindingClassFault &&
		f.Confidence != tunnel.FindingConfidenceUnverified &&
		(f.Impact == tunnel.FindingImpactDegraded || f.Impact == tunnel.FindingImpactUnavailable)
}

// legacyGenericAnomalyPrefixes/legacyGenericAnomalyExact are the three
// mechanism names migrations 000092 and 000107 name in SQL. Lifted out of
// legacyGenericAnomaly's body so legacyGenericReasonSQL (below) can render the
// same match from the same literals rather than retyping them a fourth time.
var legacyGenericAnomalyPrefixes = []string{
	"GenericConditionAnomaly:",
	"GenericDanglingReference:",
}

const legacyGenericAnomalyExact = "GenericPeerConditionShapeOutlier"

func legacyGenericAnomaly(reason string) bool {
	for _, prefix := range legacyGenericAnomalyPrefixes {
		if strings.HasPrefix(reason, prefix) {
			return true
		}
	}
	return reason == legacyGenericAnomalyExact
}

// The three validity predicates read findingClasses/findingConfidences/
// findingImpacts (declared with the F31 block below) so this package holds
// exactly one list of legal values per dimension — the same list the rule
// derivation and the SQL rendering enumerate.
func validFindingClass(v string) bool {
	return slices.Contains(findingClasses, v)
}

func validFindingConfidence(v string) bool {
	return slices.Contains(findingConfidences, v)
}

func validFindingImpact(v string) bool {
	return slices.Contains(findingImpacts, v)
}

// WouldPromoteStoredFinding answers, for a findings row already in Postgres,
// the question shouldPromoteFinding answers for a Finding still on the wire:
// would this hub open an incident for it today?
//
// It exists for internal/api's promotion reconciliation, which has to judge
// incidents raised before this boundary existed. It lives HERE, beside the
// gate itself, so the two cannot drift: a reconciliation that re-implemented
// "promotable" in SQL would keep closing (or refusing to close) incidents by
// last quarter's rule the first time this file changed.
//
// # The one correction it makes, and why it is not a new judgement
//
// Migration 000092 added the evidence columns with defaults
// ('fault','verified','degraded') — the pre-evidence behaviour, so that a
// legacy agent's findings kept opening incidents — and then backfilled the
// three generic mechanism names to ('anomaly','unverified','none'), for the
// reason its own header states: those names were already stable on the wire
// before evidence dimensions existed, so their stored tuple says nothing
// about what the detector actually proved.
//
// That backfill WAS a one-shot UPDATE against a moving target: any hub build
// older than this file that writes a finding AFTER the migration runs — a
// rolled-back image, or the old replica of a rolling update still serving the
// tunnel while the new one migrates — inserts the column defaults again and
// re-creates exactly the rows 000092 corrected. That was not hypothetical: on
// the development database 490 such rows existed on 2026-09-05, ingested in a
// 35-minute window between the migration running and the gate deploying,
// growing to 494 by 2026-09-08.
//
// PROJECT.md B138 / migration 000107 closes the moving-target half: a
// BEFORE INSERT OR UPDATE trigger on findings (findings_reconcile_legacy_generic_evidence)
// applies the identical correction below to every write, present and future,
// regardless of which hub build performs it — including one older than this
// file, since the trigger runs in Postgres, not in application code. 000107
// also re-ran the backfill for rows already stored. Read-time defense in
// depth here is UNCHANGED and deliberately kept: it is what let every
// incident opened before 000107 existed keep resolving correctly in the
// meantime, and it still governs any row a future migration number predates.
//
// So a stored generic-mechanism row carrying EXACTLY the schema default triple
// is read as what 000092 already declared it to be. The correction is narrow on
// purpose — it fires only on the default triple, not on any fault-classed
// generic row — and it is safe because nothing in this codebase emits that
// combination: every generic predicate in internal/agent sends
// Class=anomaly (generic_predicates.go), and the one thing that later
// strengthens such a finding, the condition-polarity gate, raises Confidence to
// verified and deliberately leaves Class alone (polarity_gate.go). A
// ('fault','verified','degraded') tuple on a Generic* reason therefore has
// exactly one possible author: a writer that did not know these columns
// existed. internal/migrations/000107_reconcile_legacy_generic_evidence.up.sql's
// trigger predicate is deliberately identical to isPreEvidenceDefault/
// legacyGenericAnomaly below — internal/gateway/legacy_generic_evidence_trigger_db_test.go
// pins the two against each other so a future change to either cannot drift
// silently out of sync with the other.
//
// If a generic mechanism is ever promoted to a real fault class, this function
// is the thing that has to change with it — and TestWouldPromoteStoredFinding
// pins the current answer in both directions so the change cannot be silent.
//
// The verdict itself (and the correction described above) now lives in
// ExplainStoredFinding, which returns the same answer plus the reasoning
// behind it for PROJECT.md F31's findings surface. This stays as the
// boolean-only spelling its existing callers want, and delegates rather than
// re-deciding, so "would this be promoted" and "why not" can never diverge.
func WouldPromoteStoredFinding(reason, class, confidence, impact string) bool {
	return ExplainStoredFinding(reason, class, confidence, impact).Promotable
}

// isPreEvidenceDefault reports whether an evidence tuple is byte-identical to
// migration 000092's column defaults — the tuple a writer that has never heard
// of these columns leaves behind. Written out as its own predicate rather than
// inlined so the three literals stay next to the migration that chose them.
func isPreEvidenceDefault(class, confidence, impact string) bool {
	return class == tunnel.FindingClassFault &&
		confidence == tunnel.FindingConfidenceVerified &&
		impact == tunnel.FindingImpactDegraded
}

// --- PROJECT.md F31: the boundary, stated rather than only enforced ---
//
// Everything below exists so that an operator-facing surface
// (GET /api/v1/findings, internal/api/findings.go) can say WHY a finding
// stayed a finding, and so that a SQL query can filter and count by that
// answer — without a second copy of the rule existing anywhere.
//
// The technique throughout is the same one, and it is the reason none of this
// can drift: nothing here restates shouldPromoteFinding. Each piece derives
// its answer by ENUMERATING the rule's entire input domain — three classes,
// three confidences, four impacts, on each side of the legacy-generic
// correction, 72 tuples in total — and asking the gate itself for every
// verdict. Change the gate and the accepted-value lists, the per-finding
// "unmet criteria" explanation, and the SQL predicate all change with it, in
// the same compile. promotion_test.go pins the one assumption that makes the
// derivation faithful (see TestPromotionRuleIsSeparablePerDimension).

// findingClasses/findingConfidences/findingImpacts are the closed value
// vocabularies of findings.signal_class/confidence/impact — the same three
// CHECK constraints migration 000092 wrote, expressed once here in the
// tunnel.* constants both the wire and the column share. validFindingClass
// and its two siblings above read them, so there is exactly one list of
// legal values per dimension in this package.
var (
	findingClasses     = []string{tunnel.FindingClassFault, tunnel.FindingClassRisk, tunnel.FindingClassAnomaly}
	findingConfidences = []string{tunnel.FindingConfidenceVerified, tunnel.FindingConfidenceInferred, tunnel.FindingConfidenceUnverified}
	findingImpacts     = []string{tunnel.FindingImpactUnavailable, tunnel.FindingImpactDegraded, tunnel.FindingImpactPotential, tunnel.FindingImpactNone}
)

// FindingClasses/FindingConfidences/FindingImpacts hand a caller its own copy
// of one dimension's legal values — for validating a query parameter and for
// telling the caller what the legal values were when it rejects one. Copies,
// not the package slices themselves, so a caller cannot reorder or append to
// the vocabulary the gate reads.
func FindingClasses() []string     { return slices.Clone(findingClasses) }
func FindingConfidences() []string { return slices.Clone(findingConfidences) }
func FindingImpacts() []string     { return slices.Clone(findingImpacts) }

// PromotionCriterion is one dimension of the evidence boundary and the values
// it accepts. Accepted is DERIVED (see buildPromotionRule), never written out
// by hand, and Statement is generated from Accepted — so a criterion's prose
// cannot claim something its own list contradicts.
type PromotionCriterion struct {
	Dimension string   `json:"dimension"`
	Accepted  []string `json:"accepted"`
	Statement string   `json:"statement"`
}

// PromotionRuleStatement is the whole boundary, in a shape a response can
// carry. Summary is the only hand-written prose in it, because "why this rule"
// is a judgement no enumeration can produce; everything else is derived.
type PromotionRuleStatement struct {
	Summary  string               `json:"summary"`
	Criteria []PromotionCriterion `json:"criteria"`
	// NotRecorded is the honesty clause. Three of FindingsProcessedTotal's
	// outcomes (dropped_detector_disabled, dropped_rule_disabled,
	// dropped_polarity_healthy) return from handleFinding BEFORE any row is
	// inserted, so those findings exist in no table and can never appear in a
	// findings list. A surface that exists to answer "what did ARGUS notice
	// and not raise" must say that out loud, or it quietly overstates itself.
	NotRecorded string `json:"notRecorded"`
	Source      string `json:"source"`
}

// PromotionVerdict is ExplainStoredFinding's answer for one stored row.
type PromotionVerdict struct {
	Promotable bool `json:"promotable"`
	// Class/Confidence/Impact are the EFFECTIVE tuple the gate judged, which
	// is not always the stored one — see Corrected.
	Class      string `json:"class"`
	Confidence string `json:"confidence"`
	Impact     string `json:"impact"`
	// Corrected reports that the stored tuple was migration 000092's column
	// defaults on a legacy generic mechanism, and so was read as
	// (anomaly, unverified, none) — WouldPromoteStoredFinding's long-standing
	// correction, surfaced rather than applied silently. Without this flag a
	// reader sees a row stored as (fault, verified, degraded) reported as not
	// promotable and reasonably concludes the product is lying to them.
	Corrected bool `json:"evidenceCorrected,omitempty"`
	// Unmet names the dimensions that fail, in class/confidence/impact order.
	// Empty for a promotable finding. This is the "why did this stay a
	// finding" answer at row level.
	Unmet []string `json:"unmet,omitempty"`
}

// promotionRule is derived once, at package initialisation, from the gate.
var promotionRule = buildPromotionRule()

// PromotionRule returns the evidence boundary as data. The returned slices are
// copies; a caller serialising this into a response cannot mutate the package
// copy the row-level explanation reads.
func PromotionRule() PromotionRuleStatement {
	out := promotionRule
	out.Criteria = make([]PromotionCriterion, len(promotionRule.Criteria))
	for i, c := range promotionRule.Criteria {
		out.Criteria[i] = PromotionCriterion{Dimension: c.Dimension, Accepted: slices.Clone(c.Accepted), Statement: c.Statement}
	}
	return out
}

// buildPromotionRule asks shouldPromoteFinding about every tuple in the domain
// and collects, per dimension, the values that appear in any promotable one.
//
// For a rule that is a conjunction of independent per-dimension predicates —
// which shouldPromoteFinding is, and which TestPromotionRuleIsSeparablePerDimension
// pins — that set IS the dimension's accepted set, and "promotable" is exactly
// "every dimension's value is in its accepted set". If the gate ever stops
// being separable that way (an impact that is only acceptable for one class,
// say), the test fails rather than this quietly reporting a rule the gate no
// longer enforces.
func buildPromotionRule() PromotionRuleStatement {
	accepted := map[string]map[string]bool{"class": {}, "confidence": {}, "impact": {}}
	for _, class := range findingClasses {
		for _, confidence := range findingConfidences {
			for _, impact := range findingImpacts {
				if !shouldPromoteFinding(&tunnel.Finding{Class: class, Confidence: confidence, Impact: impact}) {
					continue
				}
				accepted["class"][class] = true
				accepted["confidence"][confidence] = true
				accepted["impact"][impact] = true
			}
		}
	}
	criteria := make([]PromotionCriterion, 0, 3)
	for _, dim := range []struct {
		name       string
		vocabulary []string
	}{
		{"class", findingClasses},
		{"confidence", findingConfidences},
		{"impact", findingImpacts},
	} {
		// Ordered by the vocabulary, not by map iteration: this ends up in an
		// HTTP response and in a generated SQL predicate, and both must be
		// byte-stable across processes.
		var values []string
		for _, v := range dim.vocabulary {
			if accepted[dim.name][v] {
				values = append(values, v)
			}
		}
		criteria = append(criteria, PromotionCriterion{
			Dimension: dim.name,
			Accepted:  values,
			Statement: dim.name + " must be " + strings.Join(values, " or "),
		})
	}
	return PromotionRuleStatement{
		Summary: "Only an active fault, on better than explicitly unverified evidence, carrying observed degradation or unavailability, opens an incident. " +
			"Everything else is recorded and stays queryable — this is a promotion boundary, not suppression.",
		Criteria: criteria,
		NotRecorded: "Findings dropped before storage — a disabled detector, a disabled rule, or a condition the polarity gate confidently resolved as healthy — " +
			"are never written to the findings table and cannot appear in any findings list. Those three outcomes are visible only as argus_findings_processed_total labels.",
		Source: "internal/gateway/promotion.go",
	}
}

// ExplainStoredFinding is WouldPromoteStoredFinding with its reasoning shown:
// the same verdict, plus the effective evidence tuple it was reached on and
// which criteria the finding fails.
//
// One function, so the answer and the explanation can never disagree —
// WouldPromoteStoredFinding is now a thin caller of this rather than a second
// evaluation of the same question.
func ExplainStoredFinding(reason, class, confidence, impact string) PromotionVerdict {
	v := PromotionVerdict{Class: class, Confidence: confidence, Impact: impact}
	if legacyGenericAnomaly(reason) && isPreEvidenceDefault(class, confidence, impact) {
		v.Class, v.Confidence, v.Impact = tunnel.FindingClassAnomaly, tunnel.FindingConfidenceUnverified, tunnel.FindingImpactNone
		v.Corrected = true
	}
	v.Promotable = shouldPromoteFinding(&tunnel.Finding{
		Reason: reason, Class: v.Class, Confidence: v.Confidence, Impact: v.Impact,
	})
	if v.Promotable {
		return v
	}
	for _, c := range promotionRule.Criteria {
		var got string
		switch c.Dimension {
		case "class":
			got = v.Class
		case "confidence":
			got = v.Confidence
		case "impact":
			got = v.Impact
		}
		if !slices.Contains(c.Accepted, got) {
			v.Unmet = append(v.Unmet, c.Dimension)
		}
	}
	return v
}

// PromotableFindingSQL is the same boundary as a SQL predicate over a
// `findings`-shaped row, for a query that has to FILTER or COUNT by it rather
// than fetch every row and decide in Go.
//
// # Why this is not the mistake internal/api/incident_promotion_reconcile.go
// warns about
//
// That file's promotionReconcileScan explains at length why its verdict is
// computed in Go: "there would then be two definitions of the boundary, one in
// internal/gateway and one here, and the first time the gate changed this would
// go on closing incidents by the old rule with nothing failing." That reasoning
// is intact and this does not violate it, because this predicate is not a
// second definition — it is a rendering of THIS file's gate, produced by
// evaluating shouldPromoteFinding over its entire (finite, 36-tuple) input
// domain on each side of the legacy correction and emitting the tuples that
// came back true. There is no rule expressed in SQL here to fall behind; move
// the boundary and the emitted tuple list moves in the same build.
//
// The one thing genuinely restated in SQL is legacyGenericAnomaly's reason
// match, which is rendered from the same prefix constants the Go predicate
// reads (see legacyGenericReasonSQL) — the same duplication migrations 000092
// and 000107 already carry, and which
// legacy_generic_evidence_trigger_db_test.go already pins.
//
// Contains no parameters and no caller-supplied text: every literal comes from
// this package's own constants, so it is safe to splice into a query string.
// promotion_sql_db_test.go evaluates it inside Postgres against
// ExplainStoredFinding over all 72 combinations, so a rendering bug (quoting,
// a NULL reason, an emitted tuple that does not parse) fails a test rather
// than silently mis-filtering an operator's list.
func PromotableFindingSQL() string { return promotableFindingSQL }

var promotableFindingSQL = buildPromotableFindingSQL()

func buildPromotableFindingSQL() string {
	// A representative legacy reason — any one of them, because
	// legacyGenericAnomaly is a boolean and every reason it accepts takes the
	// identical correction. TestLegacyReasonsAreInterchangeable pins that.
	legacyReason := legacyGenericAnomalyPrefixes[0] + "Ready"
	var legacyTuples, plainTuples []string
	for _, class := range findingClasses {
		for _, confidence := range findingConfidences {
			for _, impact := range findingImpacts {
				tuple := "(" + sqlStringLiteral(class) + ", " + sqlStringLiteral(confidence) + ", " + sqlStringLiteral(impact) + ")"
				if ExplainStoredFinding(legacyReason, class, confidence, impact).Promotable {
					legacyTuples = append(legacyTuples, tuple)
				}
				if ExplainStoredFinding("", class, confidence, impact).Promotable {
					plainTuples = append(plainTuples, tuple)
				}
			}
		}
	}
	return "(CASE WHEN " + legacyGenericReasonSQL() +
		" THEN " + tupleInSQL(legacyTuples) +
		" ELSE " + tupleInSQL(plainTuples) + " END)"
}

// tupleInSQL renders one side of the CASE. FALSE, not an empty IN-list, when
// the gate promotes nothing on that side — an empty `IN ()` is a syntax error,
// and this must keep rendering valid SQL however the boundary is tightened.
func tupleInSQL(tuples []string) string {
	if len(tuples) == 0 {
		return "FALSE"
	}
	return "(findings.signal_class, findings.confidence, findings.impact) IN (" + strings.Join(tuples, ", ") + ")"
}

// legacyGenericReasonSQL renders legacyGenericAnomaly, from the same constants
// it reads. coalesce because findings.reason is nullable: a NULL reason is not
// a legacy generic mechanism, and Go's own predicate says the same of "".
func legacyGenericReasonSQL() string {
	clauses := make([]string, 0, len(legacyGenericAnomalyPrefixes)+1)
	for _, prefix := range legacyGenericAnomalyPrefixes {
		// The prefixes are compile-time constants from this file and contain
		// no LIKE metacharacter; rendered without an ESCAPE clause for that
		// reason, exactly as migrations 000092 and 000107 render them.
		clauses = append(clauses, "coalesce(findings.reason, '') LIKE "+sqlStringLiteral(prefix+"%"))
	}
	clauses = append(clauses, "coalesce(findings.reason, '') = "+sqlStringLiteral(legacyGenericAnomalyExact))
	return "(" + strings.Join(clauses, " OR ") + ")"
}

// sqlStringLiteral quotes a Go string as a SQL literal. Doubling a single
// quote is the whole of it — every value passed here is one of this package's
// own constants, and this exists so that stays true by construction rather
// than by the reader checking each call site.
func sqlStringLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
