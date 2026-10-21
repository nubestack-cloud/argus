package autoanalyze

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMeetsSelectedSeverities pins set-membership semantics — replacing the
// old ordinal "severity >= threshold" comparison (meetsSeverityThreshold,
// migration 000020) with plain "is severity one of the configured set"
// (migration 000024_auto_analysis_severities): a nil/empty set means nothing
// qualifies (the deliberate, safe reading — see
// internal/settings.Config's AutoAnalysisSeverities doc comment — NOT "every
// severity qualifies" the way the old nil threshold used to mean), and a
// non-contiguous set (e.g. {low, high} with medium deliberately excluded) is
// exercised explicitly since that is exactly the shape a single ordered
// threshold could never express — the whole reason this task exists.
func TestMeetsSelectedSeverities(t *testing.T) {
	cases := []struct {
		name       string
		severity   string
		severities []string
		want       bool
	}{
		{"nil set means nothing qualifies (low)", "low", nil, false},
		{"nil set means nothing qualifies (critical)", "critical", nil, false},
		{"empty (non-nil) set means nothing qualifies", "high", []string{}, false},

		{"member of the set qualifies", "high", []string{"high", "critical"}, true},
		{"non-member of the set does not qualify", "medium", []string{"high", "critical"}, false},

		{"single-element set matches only that severity", "critical", []string{"critical"}, true},
		{"single-element set excludes every other severity", "high", []string{"critical"}, false},

		// The case a single ordered threshold structurally cannot express:
		// low and high selected, medium deliberately excluded.
		{"non-contiguous set includes a selected low severity", "low", []string{"low", "high"}, true},
		{"non-contiguous set excludes the deliberately-unselected middle severity", "medium", []string{"low", "high"}, false},
		{"non-contiguous set includes a selected high severity", "high", []string{"low", "high"}, true},

		{"unrecognized severity never qualifies, even against a full set", "unknown", []string{"low", "medium", "high", "critical"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := meetsSelectedSeverities(c.severity, c.severities); got != c.want {
				t.Errorf("meetsSelectedSeverities(%q, %v) = %v, want %v", c.severity, c.severities, got, c.want)
			}
		})
	}
}

// fakeConnected is a trivial isConnected stand-in for selectEligible's
// tests — no gateway, no tunnel, just a set of cluster ids treated as
// connected.
func fakeConnected(connected ...string) func(string) bool {
	set := make(map[string]bool, len(connected))
	for _, id := range connected {
		set[id] = true
	}
	return func(clusterID string) bool { return set[clusterID] }
}

// TestSelectEligibleExcludesAlreadyAnalyzed pins the first of the three
// selection behaviors this task's brief asked to be independently
// unit-testable: an incident that already has an analysis is never
// re-selected for automatic investigation, regardless of severity or
// connectivity. Uses a permissive severities set (containing every
// candidate's severity) so this test isolates the HasAnalysis exclusion
// alone, not the severity-set filter exercised separately below.
func TestSelectEligibleExcludesAlreadyAnalyzed(t *testing.T) {
	candidates := []incidentCandidate{
		{ID: "inc_analyzed", ClusterID: "cl_a", Severity: "critical", HasAnalysis: true},
		{ID: "inc_fresh", ClusterID: "cl_a", Severity: "critical", HasAnalysis: false},
	}
	got, _ := selectEligible(candidates, []string{"critical"}, fakeConnected("cl_a"), nil)
	assertSelectedIDs(t, got, "inc_fresh")
}

// TestSelectEligibleAppliesSeveritySet pins the second, and the whole reason
// this task exists: selection is plain set membership, not an ordered
// threshold — covering an empty set (nothing eligible, even though
// auto-analysis is otherwise enabled), a set containing exactly one
// candidate's severity (that candidate alone is eligible), a set NOT
// containing a candidate's severity (that candidate is excluded), and a
// non-contiguous set (low + critical selected, medium and high deliberately
// excluded) — a selection no single ordered "at or above" threshold could
// ever express, which is the concrete case the user asked for directly.
func TestSelectEligibleAppliesSeveritySet(t *testing.T) {
	candidates := []incidentCandidate{
		{ID: "inc_low", ClusterID: "cl_a", Severity: "low"},
		{ID: "inc_medium", ClusterID: "cl_a", Severity: "medium"},
		{ID: "inc_high", ClusterID: "cl_a", Severity: "high"},
		{ID: "inc_critical", ClusterID: "cl_a", Severity: "critical"},
	}
	isConnected := fakeConnected("cl_a")

	t.Run("empty set selects nothing, even though enabled", func(t *testing.T) {
		got, _ := selectEligible(candidates, []string{}, isConnected, nil)
		assertSelectedIDs(t, got)
	})

	t.Run("nil set selects nothing, same as empty", func(t *testing.T) {
		got, _ := selectEligible(candidates, nil, isConnected, nil)
		assertSelectedIDs(t, got)
	})

	t.Run("set containing exactly one candidate's severity selects only that one", func(t *testing.T) {
		got, _ := selectEligible(candidates, []string{"high"}, isConnected, nil)
		assertSelectedIDs(t, got, "inc_high")
	})

	t.Run("set not containing a candidate's severity excludes it", func(t *testing.T) {
		got, _ := selectEligible(candidates, []string{"high", "critical"}, isConnected, nil)
		assertSelectedIDs(t, got, "inc_high", "inc_critical")
		// inc_medium's severity is not in {high, critical}, so it must not
		// appear — asserted implicitly by assertSelectedIDs' exact-set check
		// above, and restated here for clarity since it's the crux of this
		// test.
	})

	t.Run("full set selects every severity", func(t *testing.T) {
		got, _ := selectEligible(candidates, []string{"low", "medium", "high", "critical"}, isConnected, nil)
		assertSelectedIDs(t, got, "inc_low", "inc_medium", "inc_high", "inc_critical")
	})

	t.Run("non-contiguous set (no threshold could express this) selects low and critical, excludes medium and high", func(t *testing.T) {
		got, _ := selectEligible(candidates, []string{"low", "critical"}, isConnected, nil)
		assertSelectedIDs(t, got, "inc_low", "inc_critical")
	})
}

// TestSelectEligibleLogsSeveritySkip pins BACKLOG.md C12's second named
// defect (the skip used to be a bare `continue`, no log at all): every
// candidate excluded for NOT matching the configured severity set must call
// the injected logSeveritySkip callback with that candidate's own ID and
// severity, exactly once per candidate per call to selectEligible. Excluded
// by the OTHER two filters (already analyzed, disconnected) must NOT call
// it — those are different, unrelated reasons to skip, and conflating their
// logging would misreport why an eligible-looking incident never got
// investigated.
func TestSelectEligibleLogsSeveritySkip(t *testing.T) {
	candidates := []incidentCandidate{
		{ID: "inc_high", ClusterID: "cl_a", Severity: "high"},                          // matches severity set: not skipped, not logged
		{ID: "inc_medium", ClusterID: "cl_a", Severity: "medium"},                      // severity skip: must be logged
		{ID: "inc_low", ClusterID: "cl_a", Severity: "low"},                            // severity skip: must be logged
		{ID: "inc_analyzed", ClusterID: "cl_a", Severity: "medium", HasAnalysis: true}, // already-analyzed skip, NOT a severity skip: must NOT be logged as one
	}
	var logged []string
	logSkip := func(incidentID, severity string) {
		logged = append(logged, incidentID+":"+severity)
	}
	got, _ := selectEligible(candidates, []string{"high", "critical"}, fakeConnected("cl_a"), logSkip)
	assertSelectedIDs(t, got, "inc_high")

	wantLogged := map[string]bool{"inc_medium:medium": true, "inc_low:low": true}
	if len(logged) != len(wantLogged) {
		t.Fatalf("logSeveritySkip calls = %v, want exactly %v", logged, wantLogged)
	}
	for _, l := range logged {
		if !wantLogged[l] {
			t.Errorf("unexpected logSeveritySkip call %q — inc_analyzed should not be logged as a severity skip (it was excluded for already having an analysis)", l)
		}
	}
}

// TestSelectEligibleNilLogSeveritySkipIsSafe confirms selectEligible stays
// callable with no logging at all (nil callback) — every existing call site
// above already relies on this; stated as its own test so it stays a
// deliberate, guarded contract rather than an accident of "every other test
// happens to pass nil."
func TestSelectEligibleNilLogSeveritySkipIsSafe(t *testing.T) {
	candidates := []incidentCandidate{{ID: "inc_medium", ClusterID: "cl_a", Severity: "medium"}}
	got, _ := selectEligible(candidates, []string{"critical"}, fakeConnected("cl_a"), nil)
	assertSelectedIDs(t, got)
}

// TestPollerLogSeveritySkipOnceDedups pins logSeveritySkipOnce's own
// contract (the real callback wired into production, unlike the plain
// recording spy above): the same incident ID logs at most once per Poller
// lifetime, because candidateQuery's priority ordering (see its own doc
// comment) means a severity-ineligible incident can resurface on every
// later tick forever — an unconditional log here would eventually mean
// relogging the identical line for the identical incident every poll
// interval, once the genuinely eligible backlog drains below one tick's
// batch size.
func TestPollerLogSeveritySkipOnceDedups(t *testing.T) {
	p := &Poller{}
	// Three calls: two for the same incident (must log once), one for a
	// different incident (must log its own first line).
	p.logSeveritySkipOnce("inc_a", "medium")
	p.logSeveritySkipOnce("inc_a", "medium")
	p.logSeveritySkipOnce("inc_b", "low")

	if !p.loggedSeveritySkips["inc_a"] {
		t.Errorf("loggedSeveritySkips[inc_a] = false, want true after logging")
	}
	if !p.loggedSeveritySkips["inc_b"] {
		t.Errorf("loggedSeveritySkips[inc_b] = false, want true after logging")
	}
	if len(p.loggedSeveritySkips) != 2 {
		t.Errorf("loggedSeveritySkips = %v, want exactly 2 entries (inc_a logged once despite two calls, inc_b logged once)", p.loggedSeveritySkips)
	}
}

// TestSelectEligibleExcludesDisconnectedCluster pins the third: an incident
// on a cluster with no live tunnel connection right now is skipped rather
// than attempted, regardless of severity or analysis status — reusing
// Gateway.IsConnected (here, a fake standing in for it) to avoid burning a
// doomed attempt. Uses a permissive severities set for the same isolation
// reason TestSelectEligibleExcludesAlreadyAnalyzed does.
func TestSelectEligibleExcludesDisconnectedCluster(t *testing.T) {
	candidates := []incidentCandidate{
		{ID: "inc_connected", ClusterID: "cl_connected", Severity: "critical"},
		{ID: "inc_disconnected", ClusterID: "cl_disconnected", Severity: "critical"},
	}
	got, _ := selectEligible(candidates, []string{"critical"}, fakeConnected("cl_connected"), nil)
	assertSelectedIDs(t, got, "inc_connected")
}

// TestSelectEligibleCombinesAllThreeFilters exercises all three exclusions
// together against one candidate list, the shape closest to a real sweep —
// pinning that the disconnected-cluster and already-attempted/already-
// analyzed exclusions keep working unchanged now that severity selection is
// set membership instead of a threshold.
func TestSelectEligibleCombinesAllThreeFilters(t *testing.T) {
	candidates := []incidentCandidate{
		{ID: "inc_eligible", ClusterID: "cl_up", Severity: "high"},
		{ID: "inc_already_analyzed", ClusterID: "cl_up", Severity: "critical", HasAnalysis: true},
		{ID: "inc_not_selected_severity", ClusterID: "cl_up", Severity: "low"},
		{ID: "inc_disconnected", ClusterID: "cl_down", Severity: "critical"},
	}
	got, _ := selectEligible(candidates, []string{"high", "critical"}, fakeConnected("cl_up"), nil)
	assertSelectedIDs(t, got, "inc_eligible")
}

// TestSelectEligibleEmptyInputReturnsEmpty guards the trivial base case —
// no candidates means nothing selected, not a nil-slice panic somewhere
// downstream.
func TestSelectEligibleEmptyInputReturnsEmpty(t *testing.T) {
	got, _ := selectEligible(nil, nil, fakeConnected(), nil)
	if len(got) != 0 {
		t.Errorf("selectEligible(nil, ...) = %v, want empty", got)
	}
}

func assertSelectedIDs(t *testing.T, got []incidentCandidate, wantIDs ...string) {
	t.Helper()
	gotIDs := make(map[string]bool, len(got))
	for _, c := range got {
		gotIDs[c.ID] = true
	}
	wantSet := make(map[string]bool, len(wantIDs))
	for _, id := range wantIDs {
		wantSet[id] = true
	}
	if len(gotIDs) != len(wantSet) {
		t.Fatalf("selectEligible returned %d incidents %v, want %d %v", len(got), idsOf(got), len(wantIDs), wantIDs)
	}
	for id := range wantSet {
		if !gotIDs[id] {
			t.Errorf("selectEligible did not select expected incident %q; got %v", id, idsOf(got))
		}
	}
}

func idsOf(candidates []incidentCandidate) []string {
	ids := make([]string, len(candidates))
	for i, c := range candidates {
		ids[i] = c.ID
	}
	return ids
}

// TestCandidateQueryExcludesUnactionableStates pins the state filter in the
// candidate SQL. It is asserted against the query text rather than a live
// database because this package's other tests are deliberately DB-free, and the
// property worth protecting is structural: the filter must not be quietly
// dropped or narrowed in a refactor.
//
// Why it matters more than log noise: the query is ORDER BY first_seen ASC
// LIMIT n, so the oldest rows win the candidate slots — and closed incidents
// are by definition the oldest. Without this filter a fleet with a few dozen
// resolved incidents fills every slot with rows that can never be actioned,
// and a genuinely new high-severity incident is never analysed at all. That was
// observed live: automatic analysis logged busily every poll while starving the
// one real incident it existed to catch.
func TestCandidateQueryExcludesUnactionableStates(t *testing.T) {
	for _, state := range []string{
		// Terminal — internal/orchestrator gives these no outgoing edges, so a
		// Detected -> Investigating transition can only ever fail.
		"Resolved", "Dismissed",
		// Work already in flight — a second investigation is wasted spend at
		// best and a racing writer at worst.
		"Investigating", "Executing",
	} {
		if !strings.Contains(candidateQuery, "'"+state+"'") {
			t.Errorf("candidateQuery must exclude %q — it can never be actioned, and because the query is LIMITed and ordered oldest-first it would starve incidents that can", state)
		}
	}
	if !strings.Contains(candidateQuery, "state NOT IN") {
		t.Error("candidateQuery lost its state filter entirely")
	}
	// The states an incident legitimately sits in while waiting for a first
	// automatic look must NOT be excluded.
	for _, state := range []string{"Detected", "Reopened"} {
		if strings.Contains(candidateQuery, "'"+state+"'") {
			t.Errorf("candidateQuery excludes %q, which is exactly the case automatic analysis exists to pick up", state)
		}
	}
}

// TestCandidateQueryExcludesUnreachableClusters pins BUGS.md 120's fix: an
// incident whose CLUSTER can never dispatch again must not occupy a candidate
// slot forever, the same starvation shape TestCandidateQueryExcludesUnactionableStates
// already guards for incident state — just one level up, on the cluster the
// incident belongs to. Asserted against the query text for the same
// structural reason: this package's other tests are deliberately DB-free, and
// what matters is that the join and predicate survive a refactor, not their
// exact formatting. TestCandidateQuerySelectsFreshIncidentOverStarvedOnes
// (autoanalyze_db_test.go) proves the same fix end to end against a real
// database.
func TestCandidateQueryExcludesUnreachableClusters(t *testing.T) {
	if !strings.Contains(candidateQuery, "JOIN clusters") {
		t.Fatal("candidateQuery no longer joins clusters — it can't tell a permanently-unreachable cluster's incidents from a live one's, which is exactly the starvation BUGS.md 120 found")
	}
	for _, terminal := range []string{"Archived", "Rejected"} {
		if !strings.Contains(candidateQuery, "'"+terminal+"'") {
			t.Errorf("candidateQuery must exclude cluster state %q unconditionally — it is terminal (no automatic transition out of it), so its incidents can never be dispatched no matter how young the row", terminal)
		}
	}
	if !strings.Contains(candidateQuery, "clusters.state NOT IN") {
		t.Error("candidateQuery lost its cluster-state exclusion entirely")
	}
	// Active/Degraded must never be named in an exclusion — they are exactly
	// the states a dispatchable cluster is in.
	for _, live := range []string{"'Active'", "'Degraded'"} {
		if strings.Contains(candidateQuery, live) {
			t.Errorf("candidateQuery excludes cluster state %s, which is a live/recoverable state incidents must remain eligible in", live)
		}
	}
	// Disconnected must be excluded CONDITIONALLY (age-gated), not outright —
	// unlike Archived/Rejected, any heartbeat flips it straight back to
	// Active (internal/gateway/server.go's handleHeartbeat), so an outright
	// exclusion would defeat that recovery path for a cluster that blipped
	// moments ago.
	if !strings.Contains(candidateQuery, "'Disconnected'") {
		t.Error("candidateQuery no longer names Disconnected at all — a cluster down for months would stay eligible forever, the exact bug this fix closes")
	}
	if strings.Contains(candidateQuery, "clusters.state NOT IN ('Archived', 'Rejected', 'Disconnected')") {
		t.Error("candidateQuery excludes Disconnected unconditionally alongside the terminal states — this would stop a cluster that reconnects from ever being reconsidered, trading one starvation bug for a worse one")
	}
	if !strings.Contains(candidateQuery, "last_heartbeat_at") {
		t.Error("candidateQuery's Disconnected exclusion must be age-gated against last_heartbeat_at, not unconditional")
	}
}

// TestCandidateQueryPrioritizesConfiguredSeverities pins BACKLOG.md C12's
// starvation fix, found while turning automatic investigation on: a
// severity-ineligible incident is never marked auto_analysis_attempted_at,
// so — unlike the two starvation shapes above — it never leaves this
// query's WHERE clause on its own. Structural, DB-free, same reasoning as
// TestCandidateQueryExcludesUnreachableClusters above: what matters is that
// the ORDER BY priority term survives a refactor, not its exact formatting.
// TestCandidateQueryPrioritizesEligibleSeverityOverBacklog
// (autoanalyze_db_test.go) proves the same fix end to end against a real
// database, together with the skip-logging fix.
func TestCandidateQueryPrioritizesConfiguredSeverities(t *testing.T) {
	if !strings.Contains(candidateQuery, "ORDER BY") {
		t.Fatal("candidateQuery lost its ORDER BY entirely")
	}
	if !strings.Contains(candidateQuery, "incidents.severity = ANY($3::text[])") {
		t.Error("candidateQuery no longer prioritizes rows matching the configured severity set ($3) — without this, a large enough backlog of severity-ineligible incidents (which never leave the WHERE clause, since they're never marked attempted) can starve a genuinely eligible incident out of every candidate slot, indefinitely")
	}
	if !strings.Contains(candidateQuery, "incidents.first_seen ASC") {
		t.Error("candidateQuery must still fall back to first_seen ASC as the tie-breaker within each priority group, or ordering becomes nondeterministic")
	}
	// This must be an ORDER BY priority key, not an added WHERE exclusion —
	// see candidateQuery's own doc comment for why an outright SQL exclusion
	// was rejected (it would stop a severity-ineligible incident from ever
	// reaching selectEligible again to be logged).
	if strings.Contains(candidateQuery, "AND incidents.severity") {
		t.Error("candidateQuery appears to filter on severity in WHERE, not just prioritize it in ORDER BY — this would stop severity-skip logging from ever firing in real operation (see candidateQuery's own doc comment)")
	}
}

// TestStaleDisconnectedClusterAgeIsWellPastHealthMonitorThresholds guards the
// relationship this fix depends on: staleUnreachableClusterAge must be much
// larger than internal/gateway/health.go's own demotion thresholds (75s/150s),
// or this predicate would start excluding a cluster that merely blipped,
// before it had any real chance to send a recovering heartbeat.
func TestStaleDisconnectedClusterAgeIsWellPastHealthMonitorThresholds(t *testing.T) {
	const disconnectedThreshold = 150 * time.Second // mirrors internal/gateway/health.go
	if staleUnreachableClusterAge < 10*disconnectedThreshold {
		t.Errorf("staleUnreachableClusterAge (%v) is too close to the health monitor's own disconnectedThreshold (%v) — a routine restart or network blip could be excluded before it has a chance to reconnect", staleUnreachableClusterAge, disconnectedThreshold)
	}
}

// TestObjectIsGoneIsConservative pins the asymmetry that makes this check safe
// to run before spending an investigation: it may only ever say "gone" on a
// clear not-found. Every other outcome must let the investigation proceed.
//
// The asymmetry is deliberate and worth stating: wrongly skipping hides a real
// problem from an operator, while wrongly investigating costs a few cents. A
// flaky existence check must never be able to silently close real incidents.
func TestObjectIsGoneIsConservative(t *testing.T) {
	// A candidate with no usable object identity is never "gone" — the finding
	// that opened it simply named no object.
	for name, key := range map[string]string{
		"empty key":         "",
		"malformed key":     "not-a-key",
		"two segments only": "v1/Pod|apps",
		"empty object name": "v1/Pod|apps|",
	} {
		t.Run("not gone for "+name, func(t *testing.T) {
			p := &Poller{} // gw is never reached for these
			gone, reason := p.objectIsGone(context.Background(), incidentCandidate{ObjectKey: key})
			if gone {
				t.Errorf("objectIsGone(%q) = true, want false — a missing identity is not evidence of absence", key)
			}
			if reason != "" {
				t.Errorf("expected no reason, got %q", reason)
			}
		})
	}
}

// TestCandidateQuerySelectsObjectKey guards the wiring: without object_key in
// the SELECT the existence check silently never fires, and the cost leak it
// closes reopens with no error anywhere.
func TestCandidateQuerySelectsObjectKey(t *testing.T) {
	if !strings.Contains(candidateQuery, "object_key") {
		t.Error("candidateQuery no longer selects object_key — objectIsGone would see an empty key for every incident and never skip anything")
	}
	// COALESCE matters: object_key is nullable, and scanning NULL into a string
	// errors out, which would fail candidate collection entirely.
	if !strings.Contains(candidateQuery, "COALESCE(incidents.object_key") {
		t.Error("object_key is nullable — it must be COALESCEd, or scanning a NULL breaks the whole sweep")
	}
}

// The stale-object sweep is the only thing in the product that closes an incident
// without a human, so what it refuses to consider matters as much as what it
// closes. Asserted as query text because the alternative is a live cluster, and a
// missing clause here is not a subtle degradation.
func TestStaleCandidateQueryExcludesWhatItMust(t *testing.T) {
	for _, want := range []struct{ fragment, why string }{
		{"'Resolved', 'Dismissed'", "already closed; re-closing them would churn state and publish pointless updates"},
		{"'Executing'", "a mutation is in flight and another writer owns the state"},
		{"'Validating'", "the object disappearing is the EXPECTED result of a successful fix rolling its pods — closing on that basis would bypass the validation sweeper's grace period and its recurrence check"},
		{"object_key IS NOT NULL", "an incident that names no object cannot be asked about at all"},
		{"i.last_seen < now()", "without the grace period this races an ordinary rollout, where the old pod is briefly gone while the incident about it is still current"},
		{"LIMIT $2", "the candidate list is bounded (maxStaleCandidates); staleCheckLog.pick then bounds the tunnel calls per pass"},
		{"ORDER BY i.last_seen ASC", "oldest first, so the most-stale incidents are cleared before recently-quiet ones"},
	} {
		if !strings.Contains(staleCandidateQuery, want.fragment) {
			t.Errorf("stale candidate query is missing %q: %s", want.fragment, want.why)
		}
	}
}

// TestCandidateQuerySelectsFleetGroupID is the same wiring guard
// TestCandidateQuerySelectsObjectKey above applies to object_key, for
// BUGS.md 99's column: without fleet_group_id in the SELECT every candidate
// looks unrelated to every other, fleetWaves can never put two siblings in
// one wave, and the sequential behaviour that made fleet batching
// unreachable comes back silently.
func TestCandidateQuerySelectsFleetGroupID(t *testing.T) {
	if !strings.Contains(candidateQuery, "COALESCE(incidents.fleet_group_id") {
		t.Error("candidateQuery no longer COALESCEs fleet_group_id — fleet-correlated incidents would look unrelated (BUGS.md 99) and a NULL would break the scan for every incident that is not fleet-grouped")
	}
}

// TestFleetWavesSchedulesCorrelatedSiblingsTogether is the scheduling half
// of BUGS.md 99's regression guard.
//
// The live failure: two incidents on two clusters sharing one
// fleet_group_id were investigated one after the other (30-90s each), so
// each became the only eligible candidate on its own 30s unattended tick and
// executed ungated — no batch, no wave-1 canary, the exact BACKLOG.md R3
// scenario. The precondition ResolveBatchGating needs is that both are
// eligible AT THE SAME MOMENT, which can only happen if their
// investigations overlap.
func TestFleetWavesSchedulesCorrelatedSiblingsTogether(t *testing.T) {
	// Deliberately NOT adjacent in the list: the candidate query orders by
	// first_seen, and an unrelated incident detected between two clusters'
	// reports of one fleet-wide fault sits between them.
	candidates := []incidentCandidate{
		{ID: "inc_a", FleetGroupID: "fgrp_1"},
		{ID: "inc_unrelated", FleetGroupID: ""},
		{ID: "inc_b", FleetGroupID: "fgrp_1"},
	}
	waves := fleetWaves(candidates, 2)
	if len(waves) != 2 {
		t.Fatalf("got %d waves, want 2 (the correlated pair, then the unrelated incident): %v", len(waves), waves)
	}
	if len(waves[0]) != 2 || waves[0][0].ID != "inc_a" || waves[0][1].ID != "inc_b" {
		t.Fatalf("first wave = %v, want both fgrp_1 members (inc_a, inc_b) — a sibling that is not adjacent in first_seen order must still be pulled into the same wave", waves[0])
	}
	if len(waves[1]) != 1 || waves[1][0].ID != "inc_unrelated" {
		t.Fatalf("second wave = %v, want just the ungrouped incident", waves[1])
	}
}

// An ungrouped fleet — the normal case — must keep the exact serial
// behaviour it had before BUGS.md 99's fix: one candidate per wave, in
// first_seen order. Concurrency here would be a cost change nobody asked
// for.
func TestFleetWavesLeavesUngroupedCandidatesSerial(t *testing.T) {
	candidates := []incidentCandidate{{ID: "inc_a"}, {ID: "inc_b"}, {ID: "inc_c"}}
	waves := fleetWaves(candidates, 2)
	if len(waves) != 3 {
		t.Fatalf("got %d waves for 3 ungrouped candidates, want 3", len(waves))
	}
	for i, w := range waves {
		if len(w) != 1 || w[0].ID != candidates[i].ID {
			t.Fatalf("wave %d = %v, want exactly %s — ungrouped candidates must stay one per wave, in order", i, w, candidates[i].ID)
		}
	}
}

// A group larger than the concurrency cap splits across consecutive waves
// rather than growing the number of simultaneous LLM calls without bound:
// the first wave forms the batch, later members attach as wave-2
// stragglers (orchestrator.addStragglers).
func TestFleetWavesRespectsConcurrencyCap(t *testing.T) {
	candidates := []incidentCandidate{
		{ID: "inc_a", FleetGroupID: "fgrp_1"},
		{ID: "inc_b", FleetGroupID: "fgrp_1"},
		{ID: "inc_c", FleetGroupID: "fgrp_1"},
		{ID: "inc_d", FleetGroupID: "fgrp_1"},
		{ID: "inc_e", FleetGroupID: "fgrp_1"},
	}
	waves := fleetWaves(candidates, 2)
	if len(waves) != 3 {
		t.Fatalf("got %d waves for a 5-member group capped at 2, want 3", len(waves))
	}
	for i, w := range waves {
		if len(w) > 2 {
			t.Fatalf("wave %d holds %d candidates, want at most 2 — the cap bounds how many pooled connections and LLM calls are in flight at once", i, len(w))
		}
	}
	// Every candidate is scheduled exactly once: a scheduler that drops or
	// duplicates one would silently drop or double-pay for an investigation.
	seen := map[string]int{}
	for _, w := range waves {
		for _, c := range w {
			seen[c.ID]++
		}
	}
	if len(seen) != len(candidates) {
		t.Fatalf("scheduled %d distinct candidates, want %d: %v", len(seen), len(candidates), seen)
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("candidate %s scheduled %d times, want exactly once", id, n)
		}
	}
	// A nonsense cap must not produce an empty schedule — every candidate
	// still runs, just one at a time.
	if got := len(fleetWaves(candidates, 0)); got != len(candidates) {
		t.Fatalf("cap 0 produced %d waves, want %d (one per candidate) — a bad constant must degrade to the old serial behaviour, never to investigating nothing", got, len(candidates))
	}
}

// TestRunWavesOverlapsOneWaveAndSerializesBetweenWaves is the executing half
// of BUGS.md 99's guard: fleetWaves putting two siblings in one wave only
// helps if that wave actually runs them at the same time. This fails if the
// sweep loop is ever re-serialized.
func TestRunWavesOverlapsOneWaveAndSerializesBetweenWaves(t *testing.T) {
	var mu sync.Mutex
	inFlight, maxInFlight := 0, 0
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	// Released exactly once, and on every exit path: a failing assertion
	// below must not leave this test's own goroutines blocked forever.
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseAll()

	run := func(ctx context.Context, c incidentCandidate) {
		mu.Lock()
		inFlight++
		if inFlight > maxInFlight {
			maxInFlight = inFlight
		}
		mu.Unlock()
		started <- struct{}{}
		// Blocks until BOTH members of the wave have started. A serial
		// implementation deadlocks here rather than passing, which is the
		// point: the assertion cannot be satisfied by accident.
		<-release
		mu.Lock()
		inFlight--
		mu.Unlock()
	}

	waves := [][]incidentCandidate{
		{{ID: "inc_a", FleetGroupID: "fgrp_1"}, {ID: "inc_b", FleetGroupID: "fgrp_1"}},
		{{ID: "inc_c"}},
	}
	done := make(chan struct{})
	go func() {
		runWaves(context.Background(), waves, run)
		close(done)
	}()

	// Both members of wave 1 must be in flight before either is allowed to
	// finish — the "simultaneously eligible" property ResolveBatchGating
	// needs. Guarded by the test's own timeout rather than a sleep.
	timeout := time.After(10 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-timeout:
			t.Fatal("only one investigation of a two-member fleet-correlated wave started — the sweep is running siblings serially (BUGS.md 99), so they can never be eligible for batch gating at the same moment")
		}
	}
	releaseAll()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("runWaves did not finish")
	}

	mu.Lock()
	defer mu.Unlock()
	if maxInFlight != 2 {
		t.Fatalf("peak concurrency = %d, want exactly 2 — one wave runs together, and no more than one wave runs at a time", maxInFlight)
	}
	if inFlight != 0 {
		t.Fatalf("%d investigations still in flight after runWaves returned — it must wait for every wave", inFlight)
	}
}

// A cancelled sweep must stop starting new waves rather than paying for
// every remaining candidate's LLM call on the way down (hub shutdown is the
// real case).
func TestRunWavesStopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ran := 0
	runWaves(ctx, [][]incidentCandidate{{{ID: "inc_a"}}, {{ID: "inc_b"}}}, func(context.Context, incidentCandidate) { ran++ })
	if ran != 0 {
		t.Fatalf("ran %d investigations under an already-cancelled context, want 0", ran)
	}
}
