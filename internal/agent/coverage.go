package agent

// coverage.go answers the one question about a scoped agent that nothing in
// this codebase could answer before — PROJECT.md E11.
//
// # The defect
//
// An agent bound to argus-investigate resolves a fraction of the kinds a
// cluster-admin-bound one does (measured 2026-09-26 against a stock kind
// v1.34 cluster: 44 readable of 216 served). Every consequence of that is an
// absence: fewer findings, a quieter fleet page, incidents that never open.
// An operator reading a cluster with no incidents cannot tell a healthy
// cluster from one where four fifths of it stopped being watched, and
// narrowing the grant — which is what E11's security half does — makes that
// gap wider on purpose.
//
// # Why this is not DetectorStatus.DeniedReads
//
// DeniedReads is sourced from detector_status.go's requiredDetectorReads, a
// deliberately fixed 14-entry catalogue of reads the built-in detectors are
// hardcoded to need. It can never name the other 172, and stretching it to
// try would be worse than leaving it alone: a non-empty DeniedReads renders
// the whole detector as BLOCKED (web/src/pages/ClusterDetailPage.tsx's
// classifyDetectorStatus), and a sweep running correctly over a narrower
// grant is not blocked. Coverage is a separate field because it is a
// separate fact: DeniedReads is "a read this detector needs is refused",
// coverage is "here is how much of the cluster this detector ran over".
//
// # Two measurements, and why both
//
// The grant-shaped half (discovery.go's WatchSetCoverage) is what RBAC
// PERMITS, free — it falls out of the ServerPreferredResources ∩
// SelfSubjectRulesReview intersection the watch set is already built from,
// costing no extra API call, and it is available before any sweep has run.
//
// The sweep-shaped half (B185's kindReadOK/kindForbidden/kindNotServed/
// kindNotAffordable record) is what the agent ACTUALLY READ last pass. It
// catches what a grant cannot: the memory guard declining a read (P18 /
// P17(c)'s pagination escalation), a list that failed mid-pass, a deadline
// that expired part-way through the build. A grant can happily say
// "readable" about a kind no pass has managed to read for an hour.
//
// Reporting only the first would overstate coverage. Reporting only the
// second would lose the denominator — you cannot say "44 of 216" from a read
// record alone, because a kind RBAC excluded is never attempted and so never
// recorded. Hence both, side by side, never merged into one number.

import (
	"context"

	"argus/internal/tunnel"
)

// snapshotClusterCoverage builds the wire-shape tunnel.ClusterCoverage for
// one fact-gathering pass. Called from factsWithDetection (client.go)
// alongside snapshotClusterDetectors, and bounded by the same factsTimeout
// every other capability check GatherFacts triggers already is.
//
// Never returns nil: an agent that cannot compute coverage still reports
// Checked:false with the reason, which is a materially different and more
// useful statement than omitting the field (which a consumer must read as
// "this agent is too old to know", per ClusterCoverage's own doc comment).
// The LastSweep half is attached regardless of whether the grant-shaped half
// succeeded — they fail independently, and half an answer beats none.
func snapshotClusterCoverage(ctx context.Context) *tunnel.ClusterCoverage {
	ctx, cancel := context.WithTimeout(ctx, factsTimeout)
	defer cancel()

	cov := &tunnel.ClusterCoverage{LastSweep: snapshotSweepCoverage()}

	// Nil until runSweepDetector has called enableDiscoveredWatchSet — an
	// agent with no reachable cluster, or one whose sweep goroutine has not
	// started yet. Reported as unchecked with the reason rather than as zero
	// coverage, which would read as "this agent sees nothing".
	cache := discoveredWatchSetCache.Load()
	if cache == nil {
		cov.Error = "capability discovery has not started on this agent yet, so its coverage is not known"
		return cov
	}

	wsc, ok, err := cache.GetWithCoverage(ctx)
	if err != nil {
		// Deliberately the error's own text: this is a discovery/RBAC call
		// against the agent's OWN cluster, not client-facing hub output, and
		// the whole value of the field is naming what went wrong. It carries
		// no credential — see redact_egress_test.go's coverage of the facts
		// path.
		cov.Error = "capability discovery failed, so this agent's coverage could not be computed: " + err.Error()
		return cov
	}
	if !ok {
		cov.Error = "capability discovery returned no result, so this agent's coverage is not known"
		return cov
	}

	cov.Checked = true
	cov.KindsServed = wsc.Served
	cov.KindsReadable = wsc.Readable
	cov.DeniedSample = wsc.Denied
	cov.DeniedSampleTruncated = wsc.DeniedTruncated
	return cov
}
