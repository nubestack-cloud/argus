package gateway

// PROJECT.md B153: promotion.go's own header is explicit that
// Class=Anomaly on checkGenericConditions/checkGenericDanglingReference/
// checkGenericPeerOutlier is DELIBERATE — flipping any of them to emit
// Class=Fault directly "would preserve the exact noise this promotion
// boundary exists to stop," the flood where nearly half of all incidents
// were one-shot lifecycle markers re-detected hundreds of times
// (promotion.go's own comment, and the historical reason shouldPromoteFinding
// exists at all).
//
// This file is deliberately NOT that. It is the mechanism that makes a
// DIFFERENT, later decision implementable: whether a SPECIFIC anomaly
// instance — this object, this reason — has, over time, produced enough
// real evidence to stop being treated as noise. Three criteria, all
// evidence-based, all read from findings the hub already has durably
// recorded (not re-derived from a fresh cluster call, and not a new
// detector):
//
//   - Corroborated across observations: this exact (object, reason) pair
//     has been independently reported at least MinObservations times, not
//     one sweep tick's fluke re-sent by cooldown.
//   - Sustained over time: the span between the first and last of those
//     observations is at least MinSustainedWindow — a burst of retries in
//     one minute does not qualify, no matter how many. Measured on the
//     HUB's own ingest clock (findings.ingested_at), never on occurred_at
//     — see MinSustainedWindow's own doc comment and PROJECT.md B155 for
//     why that distinction is the whole difference between this criterion
//     working and it being permanently unsatisfiable.
//   - Real impact: EITHER the same object, OR some other object that
//     REFERENCES it, has, within ImpactLookback, ALSO produced at least one
//     Fault-classed finding of its own — independent corroboration that
//     something is actually wrong, not just this one generic mechanism's
//     own uncertain signal about ITS object. See hasFaultImpact's own doc
//     comment for why same-object alone was not enough: a broken Gateway
//     API Gateway/GatewayClass (Accepted=False, Programmed=False) never
//     carries a second fault on itself — the consequence lands on the
//     HTTPRoutes and workloads that route through it.
//
// # Enabled by owner decision, 2026-09-18
//
// earnedPromotionConfig.Enabled was false from this file's creation until
// 2026-09-18, when the owner decided to turn it on. It stays a compile-time
// constant rather than a settings row, deliberately: a live, remotely
// flippable row would let this decision be re-made by whoever next touches
// PUT /api/v1/admin/settings rather than by someone reading this file.
//
// The decision was taken against a measurement, not a guess. PROJECT.md
// B155 had to land first: the sustained-window criterion was computed from
// the condition's own lastTransitionTime, which for a persistent
// misconfiguration never advances, so the window was permanently zero and
// this mechanism could not have fired for the cases it exists to serve. On
// the fixed ingest clock, 195 anomaly groups now pass corroboration AND the
// sustained window — but only 2 of those also satisfy hasFaultImpact. The
// impact criterion, not the sustained window, is what actually bounds this:
// an anomaly is promoted only where a real fault was observed on the same
// object, or on an object that names it. Enabling therefore admits a
// handful of well-corroborated incidents rather than a flood, and that
// ratio (195 -> 2) is the number to re-measure if the noise ever changes
// character.
//
// # Why "real impact" is cross-reason co-occurrence, not a fourth invented signal
//
// Every other plausible "impact" signal specific to one predicate (a
// dangling reference actually causing a scheduling failure; a peer-outlier
// condition actually causing pod churn) would be its own new, bespoke check
// per predicate — exactly the enumeration problem B148 already found and
// fixed once in checkGenericDanglingReference's OWN scan. Cross-reason
// co-occurrence generalizes across every current and future Anomaly-classed
// predicate for free: it asks only "is ANYTHING else independently
// confirming this object is unwell," which is answerable from the SAME
// findings table with no per-predicate knowledge at all — and the
// REFERENCE-direction half of it (hasFaultImpact) reuses the exact same
// reasoning one hop further out: "is anything that points AT this object
// independently unwell," answered from tunnel.Finding.References, which
// checkGenericObjectHealth's own dispatcher already populates for every
// Finding by reusing checkGenericDanglingReference's own extraction
// (findObjectReferences) — not a second, hand-maintained table of what
// depends on what.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/tunnel"
)

// earnedPromotionConfig is this mechanism's whole tunable surface. A
// package-level var (not a function default) so a test can override it
// without threading a parameter through every call site — matching this
// package's own sustainedThreshold-style precedent elsewhere in this
// codebase for a value that is a considered constant, not per-request
// input.
type earnedPromotionConfig struct {
	// Enabled gates the ENTIRE mechanism, checked FIRST and cheaply (no
	// query at all) in earnedFaultPromotionEligible below, so that turning
	// it off restores the exact previous behaviour with no query cost. True
	// since 2026-09-18 by owner decision — see this file's own package doc
	// comment for the measurement that decision was taken against.
	Enabled bool
	// MinObservations is how many independent findings rows (same cluster,
	// object, reason) must exist before "corroborated across observations"
	// is satisfied. 3, not 2: two data points cannot distinguish "sustained
	// pattern" from "detected, then detected once more before anyone acted"
	// — the exact shape a real fix landing between two sweep ticks produces,
	// which must NOT earn promotion.
	MinObservations int
	// MinSustainedWindow is the minimum span between the earliest and
	// latest of those observations, measured on findings.ingested_at — the
	// HUB-clock time each observation arrived — and deliberately NOT on
	// findings.occurred_at. 30 minutes: long enough that a single
	// short-lived transient (a rolling update's old pod, a brief config
	// reload) cannot satisfy it by retrying quickly, short enough that a
	// genuinely persistent condition clears it within one ordinary
	// investigation/remediation cycle rather than sitting unactionable for
	// hours.
	//
	// PROJECT.md B155: occurred_at is the wrong clock for this ONE
	// question, and computing the span from it made this criterion
	// unsatisfiable for exactly the cases it exists to serve. occurred_at
	// is the time the PROBLEM began — checkGenericConditions sets it from
	// the Kubernetes condition's own lastTransitionTime (B154's fix), and
	// checkGenericStuckFinalizer from the object's deletionTimestamp. Both
	// are correct and must stay: the object's own transition time is better
	// evidence about the fault than the agent's observation time, and it is
	// what an operator reading "since when" needs. But both are also
	// CONSTANTS for as long as the fault persists unchanged — a condition
	// that has not flapped since it appeared reports the identical
	// occurred_at on its 1st and its 556th observation, so
	// max(occurred_at) - min(occurred_at) is exactly zero forever, and the
	// more persistent the misconfiguration the more certainly it scored
	// zero. Measured live 2026-09-07: 93 of 158 multi-occurrence
	// GenericConditionAnomaly groups had a zero occurred_at spread,
	// including one observed 556 times across 2 days 20 hours.
	//
	// "Sustained" here is a fact about how long ARGUS has OBSERVED the
	// anomaly, not about how long ago the object changed, and ingested_at
	// (migration 000004, DEFAULT now(), never written by insertFindingRow)
	// is exactly that clock: hub-set, monotonically advancing with every
	// new observation, and not agent-supplied — the same reasoning, and the
	// same class of bug, as storm protection's own fix (see
	// finding_db_test.go's TestCountIncidentsCreatedSinceIgnoresAgentSuppliedTimestamps:
	// a hub-computed window compared against an agent-stamped column). It
	// is also clock-level rather than per-predicate, so it covers every
	// present and future predicate that reports an object-derived
	// occurred_at without this file having to enumerate them.
	MinSustainedWindow time.Duration
	// ObservationLookback bounds how far back the corroboration/sustained
	// query looks at all — independent of MinSustainedWindow, which is the
	// minimum span REQUIRED within whatever this window returns. 24 hours:
	// generous enough to span a quiet weekend, bounded enough that an
	// anomaly from a month ago cannot retroactively promote a finding today
	// just because the object happened to still exist.
	//
	// Bounded on ingested_at too, for the same reason (PROJECT.md B155) and
	// not merely for symmetry: a stable condition whose lastTransitionTime
	// is three days old carries that occurred_at on EVERY row, so an
	// occurred_at-bounded 24h window returned zero rows for it and the
	// count criterion failed first — the sustained-window fix alone would
	// have been inert for precisely the groups it was written for.
	// "How long have we been seeing this" and "have we seen it recently"
	// are both observation-clock questions.
	ObservationLookback time.Duration
	// ImpactLookback bounds the "real impact" co-occurrence check — how
	// recently a Fault-classed finding on the SAME object counts as
	// corroborating evidence. 2 hours: a fault from days ago says nothing
	// about whether the object is unwell RIGHT NOW, which is what "real
	// impact" has to mean for a decision made today.
	//
	// Still bounded on occurred_at, deliberately, and this is the one place
	// PROJECT.md B155's clock argument was NOT applied — see
	// hasFaultImpact's own doc comment for the measurement that decided it.
	ImpactLookback time.Duration
}

// defaultEarnedPromotionConfig is what handleFinding actually uses.
// Enabled: true since 2026-09-18 by owner decision — see this file's own
// package doc comment for the 195-groups-pass / 2-actually-promote
// measurement that decision was taken against, and for why this is a
// compile-time constant rather than a settings row.
var defaultEarnedPromotionConfig = earnedPromotionConfig{
	Enabled:             true,
	MinObservations:     3,
	MinSustainedWindow:  30 * time.Minute,
	ObservationLookback: 24 * time.Hour,
	ImpactLookback:      2 * time.Hour,
}

// earnedPromotionObservationQuery is the corroboration + sustained-window
// half of earnedFaultPromotionEligible, hoisted to a package-level const so
// that the load-bearing part of PROJECT.md B155's fix — WHICH COLUMN the
// window is computed from — is asserted by a test that runs on every
// machine (earned_promotion_test.go), not only on one with
// ARGUS_TEST_DATABASE_URL set. The DB-backed tests in
// earned_promotion_db_test.go prove the behaviour end to end; this const is
// what lets the cheap test check the same string the live path executes,
// rather than a second hand-copied query that could silently disagree with
// it.
//
// Both the aggregate and the lookback bound read ingested_at (the hub's own
// arrival clock), never occurred_at (the agent-supplied time the problem
// began) — see MinSustainedWindow's and ObservationLookback's doc comments.
//
// Cost note for whoever enables this: findings is RANGE-partitioned on
// occurred_at (migration 000004), so an ingested_at-only bound cannot prune
// partitions the way the old occurred_at bound did. That is unavoidable
// here — occurred_at can legitimately be arbitrarily old for exactly the
// stable conditions this criterion is about, so no occurred_at bound is
// safe to add back — and it costs nothing while Enabled is false, since
// this query never runs. If it is ever enabled at fleet scale, a
// (cluster_id, reason, object_name, ingested_at DESC) index is the obvious
// next step; deliberately not added now, because a new index on a
// high-write partitioned table is a real write-path cost for a query that
// currently never executes.
const earnedPromotionObservationQuery = `SELECT count(*), min(ingested_at), max(ingested_at)
	   FROM findings
	  WHERE cluster_id = $1 AND gvk = $2 AND namespace = $3 AND object_name = $4
	    AND reason = $5 AND ingested_at >= $6`

// earnedFaultPromotionEligible reports whether f — an Anomaly-classed
// Finding already recorded via normalizeFindingEvidence — has, per cfg,
// earned Fault class from its own observed history. Returns
// (false, "", nil) immediately, before any query, when cfg.Enabled is
// false: the cost of this mechanism being wired in at all must be zero when
// it is off.
//
// Reads only; never writes, and never itself decides what a caller does
// with a true result — matching applyConditionPolarityGate's own division
// of labor (that function mutates f in place for its own reasons; this one
// deliberately does not, so a caller can log an eligibility result even
// while cfg.Enabled stays false, for measurement, without ever touching a
// live Finding's Class).
func earnedFaultPromotionEligible(ctx context.Context, tx pgx.Tx, clusterID string, f *tunnel.Finding, now time.Time, cfg earnedPromotionConfig) (eligible bool, why string, err error) {
	if !cfg.Enabled {
		return false, "", nil
	}
	if f.Class != tunnel.FindingClassAnomaly {
		return false, "", nil
	}

	var count int
	// min/max come back NULL, not a zero time.Time, when count is 0 —
	// *time.Time so that zero-row case scans cleanly instead of erroring.
	var firstObserved, lastObserved *time.Time
	err = tx.QueryRow(ctx, earnedPromotionObservationQuery,
		clusterID, f.GVK, f.Namespace, f.ObjectName, f.Reason, now.Add(-cfg.ObservationLookback),
	).Scan(&count, &firstObserved, &lastObserved)
	if err != nil {
		return false, "", fmt.Errorf("count prior observations: %w", err)
	}
	if count < cfg.MinObservations {
		return false, fmt.Sprintf("only %d observation(s) in the last %s, need >= %d", count, cfg.ObservationLookback, cfg.MinObservations), nil
	}
	sustained := lastObserved.Sub(*firstObserved)
	if sustained < cfg.MinSustainedWindow {
		return false, fmt.Sprintf("%d observations span only %s of observation time, need >= %s", count, sustained.Round(time.Second), cfg.MinSustainedWindow), nil
	}

	hasImpact, via, err := hasFaultImpact(ctx, tx, clusterID, f, now, cfg.ImpactLookback)
	if err != nil {
		return false, "", err
	}
	if !hasImpact {
		return false, fmt.Sprintf("%d observations over %s of observation time, but no co-occurring Fault-classed finding on the same object or anything referencing it, in the last %s", count, sustained.Round(time.Second), cfg.ImpactLookback), nil
	}

	return true, fmt.Sprintf("%d observations over %s of observation time, plus a co-occurring Fault-classed finding (%s) within %s", count, sustained.Round(time.Second), via, cfg.ImpactLookback), nil
}

// hasFaultImpact is the impact criterion, in two independent halves —
// PROJECT.md B153's own addendum: the original same-object check alone
// structurally cannot fire for a whole class of anomaly (a broken Gateway
// API Gateway/GatewayClass never carries a SECOND fault on itself; the
// consequence lands on the HTTPRoutes and workloads that route through it),
// which is exactly the "findings nobody sees" trap this mechanism exists to
// fix, one level up.
//
//   - Same-object: the anomalous object itself also produced a real fault.
//   - Reference-direction: some OTHER object, whose own Finding names this
//     anomalous object among its outbound references (tunnel.Finding.
//     References, populated agent-side by reusing checkGenericDanglingReference's
//     own extraction — NOT a second, hand-maintained table of what depends
//     on what), ALSO produced a real fault. A jsonb containment query
//     (@>) against findings.references_out (migration 000100), never a
//     per-kind join.
//
// Returns which half fired (for the why string) — "same-object" or
// "reference-direction" — so a caller/report can tell the two apart, since
// that distinction is the whole point of measuring both.
//
// # Why both halves still bound on occurred_at, after PROJECT.md B155
//
// B155 moved the corroboration/sustained window off occurred_at because a
// static lastTransitionTime made that criterion unsatisfiable. The same
// staleness argument could be made here — a currently-active fault whose
// own condition transitioned days ago carries a days-old occurred_at and so
// falls outside a 2h occurred_at bound — so this was measured rather than
// assumed. Against the live dev database (role postgres, 2026-09-17), of
// the 147 groups that satisfy count+sustained under the fixed observation
// clock, the set with a qualifying impact signal is the SAME 2 groups
// whether this lookback reads occurred_at or ingested_at. With no measured
// difference, the criterion keeps the clock whose meaning matches the
// question it asks ("did something actually go wrong on this object
// recently"), and the clock change stays confined to the one criterion
// B155 is about. Named here so the next person measures again rather than
// assuming this half was overlooked.
func hasFaultImpact(ctx context.Context, tx pgx.Tx, clusterID string, f *tunnel.Finding, now time.Time, lookback time.Duration) (bool, string, error) {
	var sameObject bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(
		   SELECT 1 FROM findings
		    WHERE cluster_id = $1 AND gvk = $2 AND namespace = $3 AND object_name = $4
		      AND signal_class = $5 AND occurred_at >= $6
		 )`,
		clusterID, f.GVK, f.Namespace, f.ObjectName, tunnel.FindingClassFault, now.Add(-lookback),
	).Scan(&sameObject); err != nil {
		return false, "", fmt.Errorf("check same-object impact: %w", err)
	}
	if sameObject {
		return true, "same-object", nil
	}

	needle, err := json.Marshal([]tunnel.ObjectReference{{Kind: gvkKind(f.GVK), Namespace: f.Namespace, Name: f.ObjectName}})
	if err != nil {
		return false, "", fmt.Errorf("encode reference-direction needle: %w", err)
	}
	var viaReference bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(
		   SELECT 1 FROM findings
		    WHERE cluster_id = $1 AND signal_class = $2 AND occurred_at >= $3
		      AND references_out @> $4::jsonb
		 )`,
		clusterID, tunnel.FindingClassFault, now.Add(-lookback), string(needle),
	).Scan(&viaReference); err != nil {
		return false, "", fmt.Errorf("check reference-direction impact: %w", err)
	}
	if viaReference {
		return true, "reference-direction", nil
	}
	return false, "", nil
}
