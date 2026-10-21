package api

import (
	"testing"
	"time"
)

// TestParseDetectionDryRunDays covers the "days" query parameter's parsing
// and bounds — no HTTP request needed (see parseDetectionDryRunDays' own
// doc comment for why it's pulled out).
func TestParseDetectionDryRunDays(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    int
		wantErr bool
	}{
		{name: "absent defaults to 7", raw: "", want: detectionDryRunDefaultDays},
		{name: "valid value", raw: "30", want: 30},
		{name: "minimum boundary", raw: "1", want: 1},
		{name: "maximum boundary", raw: "90", want: detectionDryRunMaxDays},
		{name: "zero rejected", raw: "0", wantErr: true},
		{name: "negative rejected", raw: "-5", wantErr: true},
		{name: "over max rejected", raw: "91", wantErr: true},
		{name: "non-numeric rejected", raw: "abc", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDetectionDryRunDays(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseDetectionDryRunDays(%q) = %d, nil; want an error", tt.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseDetectionDryRunDays(%q) unexpected error: %v", tt.raw, err)
			}
			if got != tt.want {
				t.Errorf("parseDetectionDryRunDays(%q) = %d, want %d", tt.raw, got, tt.want)
			}
		})
	}
}

// TestSimulateDetectionDryRun_DisabledDetectorFilterCounts is this
// function's most direct test: a finding from a detector the candidate
// disables must be counted as filtered; one from a detector the candidate
// leaves enabled must not be, and out-of-scope (lookback-only) findings
// must never be counted here at all regardless of detector.
func TestSimulateDetectionDryRun_DisabledDetectorFilterCounts(t *testing.T) {
	base := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	rows := []detectionDryRunFindingRow{
		{ClusterID: "cl_a", ClusterName: "prod-a", DetectorID: "k8s-warning-events", OccurredAt: base, HadIncident: true, CreatedNewIncident: true, InScope: true},
		{ClusterID: "cl_a", ClusterName: "prod-a", DetectorID: "k8s-warning-events", OccurredAt: base.Add(time.Minute), HadIncident: true, CreatedNewIncident: false, InScope: true},
		{ClusterID: "cl_a", ClusterName: "prod-a", DetectorID: "k8s-pod-conditions", OccurredAt: base.Add(2 * time.Minute), HadIncident: true, CreatedNewIncident: true, InScope: true},
		// Out of scope (context-only) — must never contribute to FilteredCount even though its detector is disabled.
		{ClusterID: "cl_a", ClusterName: "prod-a", DetectorID: "k8s-warning-events", OccurredAt: base.Add(-time.Hour), HadIncident: true, CreatedNewIncident: true, InScope: false},
	}

	got := simulateDetectionDryRun(rows, candidateDetectionSettings{
		DisabledDetectorIDs: []string{"k8s-warning-events"},
	})

	if got.totalFindingsInScope != 3 {
		t.Errorf("totalFindingsInScope = %d, want 3 (the out-of-scope row must not count)", got.totalFindingsInScope)
	}
	if got.filterResult.FilteredCount != 2 {
		t.Errorf("FilteredCount = %d, want 2 (both in-scope k8s-warning-events findings)", got.filterResult.FilteredCount)
	}
	if len(got.filterResult.ByClusterDetector) != 2 {
		t.Fatalf("len(ByClusterDetector) = %d, want 2 buckets (one per detector)", len(got.filterResult.ByClusterDetector))
	}
	byDetector := map[string]detectionDryRunFilterBucket{}
	for _, b := range got.filterResult.ByClusterDetector {
		byDetector[b.DetectorID] = b
	}
	if b := byDetector["k8s-warning-events"]; b.FindingCount != 2 || !b.FilteredUnderCandidate {
		t.Errorf("k8s-warning-events bucket = %+v, want FindingCount=2, FilteredUnderCandidate=true", b)
	}
	if b := byDetector["k8s-pod-conditions"]; b.FindingCount != 1 || b.FilteredUnderCandidate {
		t.Errorf("k8s-pod-conditions bucket = %+v, want FindingCount=1, FilteredUnderCandidate=false", b)
	}
}

// TestSimulateDetectionDryRun_BumpsExcludedFromStormStats confirms a
// finding that bumped an already-open incident in reality (HadIncident
// true, CreatedNewIncident false) is never treated as a storm-protection
// "opportunity" — it's unaffected by storm protection regardless of any
// candidate setting, exactly like handleFinding's live behavior.
func TestSimulateDetectionDryRun_BumpsExcludedFromStormStats(t *testing.T) {
	base := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	max, window := 1, 60
	rows := []detectionDryRunFindingRow{
		{ClusterID: "cl_a", ClusterName: "prod-a", DetectorID: "k8s-warning-events", OccurredAt: base, HadIncident: true, CreatedNewIncident: false, InScope: true},
	}

	got := simulateDetectionDryRun(rows, candidateDetectionSettings{MaxNewIncidents: &max, WindowSeconds: &window})

	if got.stormResult.EligibleOpportunities != 0 {
		t.Errorf("EligibleOpportunities = %d, want 0 (a bump is not an opportunity)", got.stormResult.EligibleOpportunities)
	}
	if len(got.stormResult.ByClusterDetector) != 0 {
		t.Errorf("ByClusterDetector = %+v, want empty", got.stormResult.ByClusterDetector)
	}
}

// TestSimulateDetectionDryRun_StormProtectionAppliesCandidateCeiling is the
// core storm-protection scenario: three brand-new-incident opportunities
// for the same (cluster, detector) fingerprint history, all of which
// actually became real incidents (no storm protection was live at the
// time), replayed against a candidate ceiling of 2 within a 60s window. The
// third must be simulated as suppressed, and that's exactly the case this
// task's brief calls out: "incidents that were created would have been
// suppressed instead."
func TestSimulateDetectionDryRun_StormProtectionAppliesCandidateCeiling(t *testing.T) {
	base := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	max, window := 2, 60
	rows := []detectionDryRunFindingRow{
		{ClusterID: "cl_a", ClusterName: "prod-a", DetectorID: "k8s-warning-events", OccurredAt: base, HadIncident: true, CreatedNewIncident: true, InScope: true},
		{ClusterID: "cl_a", ClusterName: "prod-a", DetectorID: "k8s-warning-events", OccurredAt: base.Add(10 * time.Second), HadIncident: true, CreatedNewIncident: true, InScope: true},
		{ClusterID: "cl_a", ClusterName: "prod-a", DetectorID: "k8s-warning-events", OccurredAt: base.Add(20 * time.Second), HadIncident: true, CreatedNewIncident: true, InScope: true},
	}

	got := simulateDetectionDryRun(rows, candidateDetectionSettings{MaxNewIncidents: &max, WindowSeconds: &window})

	if !got.stormResult.CandidateConfigured {
		t.Fatal("CandidateConfigured = false, want true")
	}
	if got.stormResult.EligibleOpportunities != 3 {
		t.Errorf("EligibleOpportunities = %d, want 3", got.stormResult.EligibleOpportunities)
	}
	if got.stormResult.Actual.CreatedCount != 3 || got.stormResult.Actual.SuppressedCount != 0 {
		t.Errorf("Actual = %+v, want {CreatedCount:3 SuppressedCount:0}", got.stormResult.Actual)
	}
	if got.stormResult.Candidate.CreatedCount != 2 || got.stormResult.Candidate.SuppressedCount != 1 {
		t.Errorf("Candidate = %+v, want {CreatedCount:2 SuppressedCount:1}", got.stormResult.Candidate)
	}
	if got.stormResult.NewlySuppressedCount != 1 {
		t.Errorf("NewlySuppressedCount = %d, want 1", got.stormResult.NewlySuppressedCount)
	}
	if got.stormResult.NewlyAllowedCount != 0 {
		t.Errorf("NewlyAllowedCount = %d, want 0", got.stormResult.NewlyAllowedCount)
	}
	if len(got.stormResult.ByClusterDetector) != 1 {
		t.Fatalf("len(ByClusterDetector) = %d, want 1", len(got.stormResult.ByClusterDetector))
	}
	b := got.stormResult.ByClusterDetector[0]
	if b.Opportunities != 3 || b.NewlySuppressedCount != 1 {
		t.Errorf("bucket = %+v, want Opportunities=3, NewlySuppressedCount=1", b)
	}
}

// TestSimulateDetectionDryRun_NewlyAllowed is the mirror case: a finding
// that WAS actually suppressed by storm protection at the time (recorded
// as incident_id NULL, per finding.go), replayed against a candidate with
// a looser ceiling that would have let it through.
func TestSimulateDetectionDryRun_NewlyAllowed(t *testing.T) {
	base := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	max, window := 10, 60 // deliberately loose — nothing should be suppressed under this candidate
	rows := []detectionDryRunFindingRow{
		{ClusterID: "cl_a", ClusterName: "prod-a", DetectorID: "k8s-warning-events", OccurredAt: base, HadIncident: false, CreatedNewIncident: false, InScope: true},
	}

	got := simulateDetectionDryRun(rows, candidateDetectionSettings{MaxNewIncidents: &max, WindowSeconds: &window})

	if got.stormResult.Actual.SuppressedCount != 1 || got.stormResult.Actual.CreatedCount != 0 {
		t.Errorf("Actual = %+v, want {CreatedCount:0 SuppressedCount:1}", got.stormResult.Actual)
	}
	if got.stormResult.Candidate.CreatedCount != 1 || got.stormResult.Candidate.SuppressedCount != 0 {
		t.Errorf("Candidate = %+v, want {CreatedCount:1 SuppressedCount:0}", got.stormResult.Candidate)
	}
	if got.stormResult.NewlyAllowedCount != 1 {
		t.Errorf("NewlyAllowedCount = %d, want 1", got.stormResult.NewlyAllowedCount)
	}
}

// TestSimulateDetectionDryRun_LookbackRowsWarmUpButAreNotReported confirms
// a finding fetched only to seed the rolling storm-protection window (it
// precedes the caller's requested window, per handleDetectionDryRun's own
// lookbackStart) still occupies a real slot in the candidate's ceiling, but
// is itself never counted in TotalFindingsInWindow, FilteredCount, or
// EligibleOpportunities.
func TestSimulateDetectionDryRun_LookbackRowsWarmUpButAreNotReported(t *testing.T) {
	base := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	max, window := 1, 3600 // a tight ceiling of 1-per-hour
	rows := []detectionDryRunFindingRow{
		// Context-only: 30 minutes before the requested window, but still
		// within the candidate's 1-hour rolling window.
		{ClusterID: "cl_a", ClusterName: "prod-a", DetectorID: "k8s-warning-events", OccurredAt: base.Add(-30 * time.Minute), HadIncident: true, CreatedNewIncident: true, InScope: false},
		// In-scope: actually created for real (no ceiling live at the time),
		// but the candidate's ceiling of 1/hour was already spent by the
		// context-only row above, so this must simulate as suppressed.
		{ClusterID: "cl_a", ClusterName: "prod-a", DetectorID: "k8s-warning-events", OccurredAt: base, HadIncident: true, CreatedNewIncident: true, InScope: true},
	}

	got := simulateDetectionDryRun(rows, candidateDetectionSettings{MaxNewIncidents: &max, WindowSeconds: &window})

	if got.totalFindingsInScope != 1 {
		t.Errorf("totalFindingsInScope = %d, want 1 (the lookback row must not count)", got.totalFindingsInScope)
	}
	if got.stormResult.EligibleOpportunities != 1 {
		t.Errorf("EligibleOpportunities = %d, want 1", got.stormResult.EligibleOpportunities)
	}
	if got.stormResult.Candidate.SuppressedCount != 1 {
		t.Errorf("Candidate.SuppressedCount = %d, want 1 — the lookback row should have consumed the only ceiling slot", got.stormResult.Candidate.SuppressedCount)
	}
	if got.stormResult.NewlySuppressedCount != 1 {
		t.Errorf("NewlySuppressedCount = %d, want 1", got.stormResult.NewlySuppressedCount)
	}
}

// TestSimulateDetectionDryRun_DisabledDetectorExcludedFromStormSimulation
// confirms a disabled-under-candidate detector's opportunity never
// occupies a slot in another detector's storm-protection ceiling — under
// the candidate, that finding never arrives at all, so it must not affect
// anyone else's rolling count either.
func TestSimulateDetectionDryRun_DisabledDetectorExcludedFromStormSimulation(t *testing.T) {
	base := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	max, window := 1, 60
	rows := []detectionDryRunFindingRow{
		// k8s-warning-events is disabled under the candidate below — this
		// opportunity must not consume the shared cluster's ceiling slot.
		{ClusterID: "cl_a", ClusterName: "prod-a", DetectorID: "k8s-warning-events", OccurredAt: base, HadIncident: true, CreatedNewIncident: true, InScope: true},
		{ClusterID: "cl_a", ClusterName: "prod-a", DetectorID: "k8s-pod-conditions", OccurredAt: base.Add(5 * time.Second), HadIncident: true, CreatedNewIncident: true, InScope: true},
	}

	got := simulateDetectionDryRun(rows, candidateDetectionSettings{
		DisabledDetectorIDs: []string{"k8s-warning-events"},
		MaxNewIncidents:     &max,
		WindowSeconds:       &window,
	})

	// Only the k8s-pod-conditions opportunity should even reach the storm
	// simulation — the disabled detector's opportunity is excluded entirely.
	if got.stormResult.EligibleOpportunities != 1 {
		t.Errorf("EligibleOpportunities = %d, want 1 (the disabled detector's opportunity must be excluded)", got.stormResult.EligibleOpportunities)
	}
	if got.stormResult.Candidate.SuppressedCount != 0 {
		t.Errorf("Candidate.SuppressedCount = %d, want 0 — the disabled detector's finding must not have consumed the ceiling slot", got.stormResult.Candidate.SuppressedCount)
	}
	if len(got.stormResult.ByClusterDetector) != 1 || got.stormResult.ByClusterDetector[0].DetectorID != "k8s-pod-conditions" {
		t.Errorf("ByClusterDetector = %+v, want exactly one k8s-pod-conditions bucket", got.stormResult.ByClusterDetector)
	}
}

// TestSimulateDetectionDryRun_NoCandidateStormConfiguredNeverSuppresses
// covers the baseline "candidate leaves storm protection off" case —
// every opportunity must simulate as created, regardless of volume.
func TestSimulateDetectionDryRun_NoCandidateStormConfiguredNeverSuppresses(t *testing.T) {
	base := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	rows := make([]detectionDryRunFindingRow, 0, 5)
	for i := 0; i < 5; i++ {
		rows = append(rows, detectionDryRunFindingRow{
			ClusterID: "cl_a", ClusterName: "prod-a", DetectorID: "k8s-warning-events",
			OccurredAt: base.Add(time.Duration(i) * time.Second), HadIncident: true, CreatedNewIncident: true, InScope: true,
		})
	}

	got := simulateDetectionDryRun(rows, candidateDetectionSettings{})

	if got.stormResult.CandidateConfigured {
		t.Error("CandidateConfigured = true, want false")
	}
	if got.stormResult.Candidate.SuppressedCount != 0 || got.stormResult.Candidate.CreatedCount != 5 {
		t.Errorf("Candidate = %+v, want {CreatedCount:5 SuppressedCount:0}", got.stormResult.Candidate)
	}
}

// TestSimulateDetectionDryRun_ByClusterDetectorIsSortedDeterministically
// guards the output ordering — the response must not depend on Go's
// unordered map iteration.
func TestSimulateDetectionDryRun_ByClusterDetectorIsSortedDeterministically(t *testing.T) {
	base := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	rows := []detectionDryRunFindingRow{
		{ClusterID: "cl_b", ClusterName: "prod-b", DetectorID: "k8s-pod-conditions", OccurredAt: base, HadIncident: true, CreatedNewIncident: true, InScope: true},
		{ClusterID: "cl_a", ClusterName: "prod-a", DetectorID: "k8s-warning-events", OccurredAt: base, HadIncident: true, CreatedNewIncident: true, InScope: true},
		{ClusterID: "cl_a", ClusterName: "prod-a", DetectorID: "k8s-pod-conditions", OccurredAt: base, HadIncident: true, CreatedNewIncident: true, InScope: true},
	}

	got := simulateDetectionDryRun(rows, candidateDetectionSettings{})

	if len(got.filterResult.ByClusterDetector) != 3 {
		t.Fatalf("len(ByClusterDetector) = %d, want 3", len(got.filterResult.ByClusterDetector))
	}
	for i := 1; i < len(got.filterResult.ByClusterDetector); i++ {
		prev, cur := got.filterResult.ByClusterDetector[i-1], got.filterResult.ByClusterDetector[i]
		if prev.ClusterID > cur.ClusterID || (prev.ClusterID == cur.ClusterID && prev.DetectorID > cur.DetectorID) {
			t.Errorf("ByClusterDetector not sorted: %+v then %+v", prev, cur)
		}
	}
}
