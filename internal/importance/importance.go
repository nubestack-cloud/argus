// Package importance is PROJECT.md T1's mechanism: replace the remaining
// static triage assumption (severity alone, or a fixed sort by recency) with
// a real, explainable ranking over blast radius, workload criticality,
// duration/trend, and evidence learned during analysis — built from data the
// hub already has (plus one new, honestly-collected agent-side signal for
// criticality — see below), no per-kind/per-reason table.
//
// # Why one Go package, not SQL-only or Go-only
//
// internal/api/incidents.go's list endpoint uses KEYSET pagination
// (lld/10-api-spec.md rules out OFFSET), which means every sort key must be
// a SQL expression the database can both ORDER BY and compare a cursor
// against — Score below cannot live only in Go. But "explainable" means an
// operator gets the SAME breakdown the ranking actually used, not a
// plausible-sounding guess reconstructed after the fact — so the WEIGHTS
// live in exactly one place (this file's exported constants), and
// incidents.go's SQL expression is built by formatting these same Go
// constants into a string, never a second, independently hand-typed copy of
// the numbers. Score/Explain are what a human-facing "why" answer calls;
// the SQL expression is what pagination needs; both compute the identical
// formula from the identical constants.
//
// # Workload criticality — now built, from a Pod's own resolved spec.priority
//
// T1's own brief names four inputs: blast radius, workload criticality,
// duration/trend, and evidence learned during analysis. The first, third,
// and fourth were built first, from data already durably recorded
// (fleetgroup/workloadgroup/objectgroup counts, incidents.first_seen/
// occurrence_count, analyses.confidence). Workload criticality had no
// equivalent already-collected signal anywhere in this codebase — confirmed
// by reading generic_predicates.go's own doc comment, which explicitly
// declined to resolve spec.priorityClassName generically for a DIFFERENT
// predicate (dangling-reference resolution needs to know a bare string's
// target KIND, which that field's shape doesn't carry). Reading a Pod's own
// resolved spec.priority instead (the INTEGER the API server's priority
// admission plugin already stamps onto the Pod from that PriorityClass,
// needing no such resolution) is exactly the legitimate, kind-agnostic
// signal that doc comment implies exists — it is now collected agent-side
// (internal/agent/pod_conditions_detector.go, sweep_detector.go's
// checkPodPendingTimeout, and detector.go's handleWatchedEvent — the three
// call sites that already hold a full *corev1.Pod object), carried on
// tunnel.Finding.PodPriority (a purely additive wire field, nil-means-
// unknown), and persisted once at incident-open time onto incidents.
// pod_priority (migration 000111, internal/gateway/finding.go) — the exact
// same "set once from the opening Finding, never updated" convention
// workload_key/opening_reason already use, since correlation groups Findings
// about the same fault onto one incident and the identity of "which Pod
// opened this" doesn't change afterward.
//
// WorkloadCriticality below is that persisted integer, unchanged — never a
// namespace-name or label-based proxy (exactly the per-kind/per-reason table
// this item's own "done when" rules out). It degrades to nil (unknown, never
// a fabricated low-criticality zero) for every incident whose object isn't a
// Pod (a Service, a PVC, a CRD, ...), for an older agent that never sent the
// field, and for a real Pod the priority admission plugin never stamped a
// value onto — three different causes, one honest "no signal" reading, same
// convention as ClusterRemediation/ClusterDetectors in
// internal/tunnel/protocol.go.
//
// The RAW integer is what's stored and what Explain's sentence names, but
// it is NOT what Score/SQLExprWithCriticality feed into their weighted sum
// directly — see workloadCriticalityContribution and
// WeightWorkloadCriticality's own doc comment for why a bounded log1p form
// replaced a first attempt at plain linear scaling, and what real-cluster
// measurement showed was wrong with that first attempt.
//
// SQLExpr (the 4-factor form) is UNCHANGED and still compiles: it is a thin
// wrapper over SQLExprWithCriticality passing SQL literal NULL for the fifth
// argument, which COALESCEs to 0 — i.e. "no criticality data available to
// this caller yet." internal/api/incidents.go, which owns the ORDER BY
// expression and the SELECT list Explain's own rebuild reads from, still
// calls the 4-arg SQLExpr as of this writing; wiring it to
// SQLExprWithCriticality (selecting incidents.pod_priority and passing it
// through, plus rebuilding Factors.WorkloadCriticality for Explain) is a
// deliberate follow-up left to that file's owner — see this repo's
// concurrent-edit boundary for why this package does not make that edit
// itself. Weight validation against a clean dataset (calibrating
// WeightWorkloadCriticality, like the other three weights) remains open
// separately; this only adds the factor honestly.
package importance

import (
	"fmt"
	"math"
	"sort"
)

// Weight* are the ONLY numbers this package's score is built from — named
// and adjustable in one place, not buried inline in a SQL string.
// Each is a judgment call, same convention as every other heuristic constant
// in this codebase (e.g. internal/agent/generic_predicates.go's
// minGenericPolaritySamples): stated as one, not dressed up as derived.
// Chosen so that none of the four factors can dominate by construction for
// a typical incident (a lone, hours-old, low-recurrence, low-confidence
// incident scores near zero; a widely-shared, days-old, frequently-recurring,
// high-confidence one scores highest) — revisit these once real operator
// behavior (Resolved/Dismissed vs Expired — see this package's own
// calibration query, PROJECT.md T1) gives a basis to tune them instead of
// guessing again.
const (
	// WeightBlastRadius applies per OTHER open incident sharing this one's
	// fleet-wide, same-workload, or same-object correlation group (whichever
	// grouping is widest) — see Factors.BlastRadius's own doc comment.
	WeightBlastRadius = 10.0
	// WeightAgeHours applies per hour this incident has been open
	// (now - first_seen). A small per-hour weight so age alone cannot
	// dominate a fresh, severe incident, while still separating "just
	// opened" from "been sitting for a week."
	WeightAgeHours = 0.5
	// WeightOccurrenceRate applies per (occurrence_count / age-in-hours) —
	// how often the SAME incident keeps re-firing per hour it has been open,
	// which is a trend (worsening/steady), not just a raw count that only
	// ever grows with age.
	WeightOccurrenceRate = 5.0
	// WeightConfidence applies per point of the latest analysis's own
	// confidence (0..1) — "evidence learned during analysis." An incident
	// never yet analysed contributes zero here, honestly: an unconfirmed
	// guess is not evidence, and this must not reward "nobody has looked at
	// this yet" as if that were itself a reason to rank it higher.
	WeightConfidence = 20.0
	// WeightWorkloadCriticality applies to log1p (natural log of 1+x) of the
	// opening Pod's own resolved spec.priority (see
	// Factors.WorkloadCriticality's own doc comment for exactly what this
	// is and is not, and workloadCriticalityContribution below for the one
	// place that formula lives).
	//
	// This was raw-linear (weight * priority) in an earlier version of this
	// factor, and that was wrong, demonstrated on a real cluster rather than
	// argued in the abstract: `kubectl get priorityclass` on a live kind
	// cluster returned ONLY Kubernetes' two built-ins
	// (system-node-critical=2000001000, system-cluster-critical=2000000000)
	// — no operator had defined a custom PriorityClass at all. Under
	// raw-linear scaling, EVERY kube-system Pod's incident scored
	// +20,000,000-ish against every application incident's +0, which is not
	// a criticality signal an operator set — it is Kubernetes' own plumbing
	// permanently burying every real incident by six orders of magnitude,
	// and it directly contradicted this const block's own "none of the four
	// factors can dominate by construction" rule above. log1p fixes both
	// problems at once: it is still strictly monotonic (a higher priority
	// always scores higher, so a genuinely operator-flagged high-priority
	// workload still ranks above an identical incident on an unflagged one —
	// TestScore_HighWorkloadPriorityOutranksLowPriority), but it compresses
	// Kubernetes' 2-billion-range system values down to the same rough
	// magnitude as the other three factors (log1p(2e9)≈21.4,
	// log1p(1000)≈6.9, log1p(0)=0 exactly) instead of erasing them. 2.0 is
	// the judgment call (same "stated as one, not dressed up as derived"
	// convention as every other weight here): it lands a system-critical
	// Pod's contribution (≈42.8) in the same range as this package's other
	// three factors' own typical maximums, dominating only a genuinely
	// unremarkable incident on every other axis — not automatically
	// outranking every real application fault the way raw-linear did.
	// Negative priorities (a real, if rare, PriorityClass use — a
	// deliberately below-default, best-effort class) are clamped to 0
	// before the log rather than passed through: log1p is undefined below
	// -1, and this factor does not attempt to model "less critical than
	// default", only "at or above it."
	WeightWorkloadCriticality = 2.0
)

// Factors is the raw, per-incident input to Score/Explain — every field
// traceable to an existing column or already-computed correlation, never a
// new detector or a fabricated number.
type Factors struct {
	// BlastRadius is how many currently-open incidents (this one included)
	// share the WIDEST of this incident's three existing correlation groups
	// — fleet-wide (internal/fleetgroup, same fault across clusters),
	// same-workload (internal/replicagroup, same fault across a workload's
	// replicas), or cross-object (internal/objectgroup). 1 when none apply
	// (an isolated incident is its own group of one), never 0 — an incident
	// always shares its own group with at least itself.
	BlastRadius int
	// AgeHours is now() - incidents.first_seen, in hours. Always >= 0.
	AgeHours float64
	// OccurrenceRate is how many times this incident has recurred BEYOND
	// its first sighting (occurrence_count - 1, never the raw count) per
	// hour open (AgeHours floored at 1 so a few-minutes-old incident's rate
	// isn't inflated by a near-zero denominator). A first-ever sighting is
	// not yet a trend and must be zero here, not "recurring once an hour" —
	// see internal/api/incidents.go's importanceOccurrenceRateExpr, which
	// this mirrors, for the concrete bug this exact wording prevents.
	OccurrenceRate float64
	// Confidence is the incident's latest analysis's own stated confidence,
	// or nil when no analysis exists yet (never a fabricated 0 standing in
	// for "not yet known" — see this codebase's own "never render an
	// unavailable cost as $0.00" precedent, same principle applied here).
	Confidence *float64
	// WorkloadCriticality is the resolved spec.priority integer of the Pod
	// whose Finding opened this incident — persisted once, at incident-open
	// time, onto incidents.pod_priority (migration 000111), sourced from
	// tunnel.Finding.PodPriority (see that field's own doc comment for
	// exactly how and where it is collected agent-side).
	//
	// nil, never a fabricated 0, for every one of three genuinely different
	// causes this package deliberately does not distinguish (the consumer's
	// job is the same either way — treat it as "no criticality signal"):
	// the incident's opening object isn't a Pod at all (a Service, a PVC, a
	// CRD — the fault this factor degrades to "unknown" for, honestly,
	// rather than inventing a priority for a kind that has none); the
	// opening Finding came from an agent older than
	// tunnel.Finding.PodPriority; or the opening Pod's own spec.priority was
	// itself never resolved by the API server (the priority admission
	// plugin disabled, or a very old Kubernetes version) — the same
	// "absent means unknown" reading pod.Spec.Priority *int32 already
	// carries before this package ever sees it.
	WorkloadCriticality *int32
}

// workloadCriticalityContribution is the ONE place Score and Explain both
// read the workload-criticality term from, so they cannot independently
// drift on its shape the same way they cannot drift on the Weight*
// constants themselves. nil (no signal — see Factors.WorkloadCriticality's
// own doc comment) contributes exactly 0, never a fabricated value. A
// negative priority is clamped to 0 before the log (see
// WeightWorkloadCriticality's own doc comment for why) — this still leaves
// priority-0 (a REAL resolved value, e.g. the globally-default
// PriorityClass) distinct from nil at the Factors level; it only happens to
// also contribute 0 here, the same way Confidence=0 and Confidence=nil both
// contribute 0 without being the same fact.
func workloadCriticalityContribution(priority *int32) float64 {
	if priority == nil {
		return 0
	}
	p := float64(*priority)
	if p < 0 {
		p = 0
	}
	return WeightWorkloadCriticality * math.Log1p(p)
}

// Score combines Factors into one comparable number — higher means more
// important. Deliberately a plain weighted sum, not a fitted model: every
// term is individually nameable (see Explain), which a black-box score
// could not offer, and "explainable... without adding another per-kind/
// per-reason table" is this item's own done-when bar.
func Score(f Factors) float64 {
	score := WeightBlastRadius*float64(f.BlastRadius) + WeightAgeHours*f.AgeHours + WeightOccurrenceRate*f.OccurrenceRate
	if f.Confidence != nil {
		score += WeightConfidence * (*f.Confidence)
	}
	score += workloadCriticalityContribution(f.WorkloadCriticality)
	return score
}

// SQLExpr is the SAME formula as Score, expressed as a Postgres scalar
// expression built from the identical Weight* constants — the one place
// internal/api/incidents.go's ORDER BY/keyset-cursor expression comes from,
// so the SQL and the Go-side Explain() below can never independently drift
// on what the numbers actually are. blastRadiusExpr/ageHoursExpr/
// occurrenceRateExpr/confidenceExpr are the caller's own SQL fragments for
// each raw factor (each already exists as a correlated subquery or plain
// column reference in incidents.go — this function only ever combines them,
// never invents its own reference to a table or column, since knowing the
// schema is that caller's job, not this package's).
//
// This is the 4-factor form, kept so today's caller (internal/api/
// incidents.go) keeps compiling and behaving exactly as before without
// this package forcing an edit onto a file it does not own — it is a thin
// wrapper over SQLExprWithCriticality passing SQL literal "NULL" for the
// workload-criticality argument, which COALESCEs to 0 there exactly like
// confidenceExpr already does: "no criticality data available to this
// caller yet," the honest reading until incidents.go is wired to select
// incidents.pod_priority and call SQLExprWithCriticality directly. See this
// package's own doc comment for that follow-up.
//
// Returns a BIGINT-cast, rounded expression: keyset pagination compares by
// exact equality on the cursor's stored value, and an integer is what
// sortKindInt already round-trips through the cursor cleanly.
func SQLExpr(blastRadiusExpr, ageHoursExpr, occurrenceRateExpr, confidenceExpr string) string {
	return SQLExprWithCriticality(blastRadiusExpr, ageHoursExpr, occurrenceRateExpr, confidenceExpr, "NULL")
}

// SQLExprWithCriticality is SQLExpr's full, 4-factor-plus-criticality form —
// the SAME formula as Score once Factors.WorkloadCriticality is populated,
// built from the identical Weight* constants so the SQL and Go-side
// Explain() below can never independently drift on the numbers.
// workloadCriticalityExpr is the caller's own SQL fragment for
// incidents.pod_priority (or the literal "NULL" — see SQLExpr above). The
// workload-criticality term mirrors workloadCriticalityContribution's Go
// logic exactly: COALESCE to 0 (no signal contributes nothing), GREATEST
// against 0 (a negative priority is clamped, matching the Go-side clamp —
// LN is undefined below -1), then LN(1 + that) — Postgres's natural-log
// equivalent of Go's math.Log1p, scaled by WeightWorkloadCriticality.
//
// The sum is explicitly CAST to NUMERIC before ROUND, not left as whatever
// type Postgres would otherwise infer. LN(double precision) returns double
// precision, and once ANY term in the sum is double precision the whole
// expression is — which silently switches ROUND's own tie-breaking rule
// from "half away from zero" (numeric, the SQL-standard behavior, and the
// same rule Go's math.Round uses) to "half to even" (double precision).
// Caught by this package's own DB-backed invariant test
// (TestSQLExprWithCriticality_AgreesWithScoreAndExplain): an incident whose
// raw score landed on an exact .5 — the isolated/nil-criticality case,
// 10*1 + 0.5*1 + 5*0 = 10.5 — rounded to 10 in Postgres (nearest even) but
// 11 in Go (away from zero) before this cast was added.
func SQLExprWithCriticality(blastRadiusExpr, ageHoursExpr, occurrenceRateExpr, confidenceExpr, workloadCriticalityExpr string) string {
	return fmt.Sprintf(
		"CAST(ROUND(CAST(%g * (%s) + %g * (%s) + %g * (%s) + %g * COALESCE((%s), 0) + %g * LN(1 + GREATEST(COALESCE((%s), 0), 0)) AS NUMERIC)) AS BIGINT)",
		WeightBlastRadius, blastRadiusExpr,
		WeightAgeHours, ageHoursExpr,
		WeightOccurrenceRate, occurrenceRateExpr,
		WeightConfidence, confidenceExpr,
		WeightWorkloadCriticality, workloadCriticalityExpr,
	)
}

// Explain returns human-readable reasons Score(f) came out the way it did,
// ranked by how much each factor actually contributed — the direct answer
// to "why did this incident outrank that one," not a guess reconstructed
// after the fact. A factor that contributed nothing (BlastRadius of 1, zero
// occurrence rate, no analysis yet) is omitted rather than stated as a
// zero-value non-reason; an incident every factor is silent on returns nil,
// meaning "ranked low because nothing about it stood out on any of these
// axes" — itself a real, honest answer.
func Explain(f Factors) []string {
	type contribution struct {
		amount float64
		text   string
	}
	var contributions []contribution
	if f.BlastRadius > 1 {
		contributions = append(contributions, contribution{
			WeightBlastRadius * float64(f.BlastRadius),
			fmt.Sprintf("shares its fault with %d other open incident(s) right now", f.BlastRadius-1),
		})
	}
	if f.AgeHours >= 1 {
		contributions = append(contributions, contribution{
			WeightAgeHours * f.AgeHours,
			fmt.Sprintf("has been open for %s", humanizeHours(f.AgeHours)),
		})
	}
	if f.OccurrenceRate > 0 {
		contributions = append(contributions, contribution{
			WeightOccurrenceRate * f.OccurrenceRate,
			fmt.Sprintf("recurring about %.1f time(s) per hour since it opened", f.OccurrenceRate),
		})
	}
	if f.Confidence != nil && *f.Confidence > 0 {
		contributions = append(contributions, contribution{
			WeightConfidence * (*f.Confidence),
			fmt.Sprintf("the latest analysis is %.0f%% confident this is a real fault", *f.Confidence*100),
		})
	}
	// Uses workloadCriticalityContribution, the SAME helper Score calls, so
	// this can never rank the factor by a different amount than Score
	// actually added. > 0 excludes both nil (no signal) and priority <= 0
	// (log1p(0) = 0 exactly, and a clamped negative also lands at 0) — a
	// Pod at or below default priority is not itself a reason, the same
	// convention every other factor here already follows.
	if crit := workloadCriticalityContribution(f.WorkloadCriticality); crit > 0 {
		contributions = append(contributions, contribution{
			crit,
			fmt.Sprintf("the pod that opened it has a resolved priority of %d", *f.WorkloadCriticality),
		})
	}
	sort.SliceStable(contributions, func(i, j int) bool { return contributions[i].amount > contributions[j].amount })
	if len(contributions) == 0 {
		return nil
	}
	reasons := make([]string, len(contributions))
	for i, c := range contributions {
		reasons[i] = c.text
	}
	return reasons
}

func humanizeHours(hours float64) string {
	switch {
	case hours < 24:
		return fmt.Sprintf("%.0f hour(s)", hours)
	default:
		return fmt.Sprintf("%.1f day(s)", hours/24)
	}
}
