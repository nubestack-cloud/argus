package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/gateway"
	"argus/internal/logging"
)

// This file implements POST /api/v1/detection/dry-run — a scoped, real slice
// of lld/11-ui-design.md §3's named-but-never-built PolicyEditor feature
// ("RemediationPolicy authoring, including the dry-run-against-history
// feature ... the feature that makes policy authoring tractable"). NOT the
// RemediationPolicy CRD or a cluster-side controller
// (lld/06-detection-framework.md §6-7's fuller design; see
// internal/gateway/finding.go's own doc comment for what's real and what
// isn't) — this is the dry-run idea applied to the two detection controls
// that ARE real and live-editable today (WORKLOG.md §48): per-detector
// enable/disable and storm protection.
//
// Read-only, pure simulation. It NEVER writes anything (no org_settings
// row is touched, no incident/finding is inserted or updated) and NEVER
// calls out to a live cluster — it is pure Postgres querying over
// already-recorded `findings`/`incidents` history, plus an in-memory,
// DB-free replay.
//
// The property this file exists to guarantee, restated because it's the
// entire point of the task this file closes: the replay below calls
// gateway.IsDetectorDisabled / gateway.StormProtectionConfigured /
// gateway.StormProtectionWindowStart / gateway.StormProtectionShouldSuppress
// — the EXACT SAME pure functions internal/gateway/finding.go's handleFinding
// calls on the live tunnel path for every real Finding it processes (those
// four functions were exported from that file specifically for this reuse;
// see that file's own doc comments on each). There is no second,
// hand-written copy of "is this detector disabled" or "does this breach the
// storm-protection ceiling" anywhere in this file — if handleFinding's
// behavior ever changes, this dry-run automatically replays the new
// behavior too, because it is calling the new behavior, not a snapshot of
// it.
//
// The request body reuses putDetectionSettingsRequest and
// validateDetectionSettingsRequest verbatim from settings.go (same JSON
// shape as PUT /api/v1/admin/settings' "detection" section, same
// validation rule) — a candidate PUT would reject gets exactly the same 400
// here, before a single query runs.
//
// Capability: org:settings:write — the same capability that gates writing
// detection settings (server.go's route registration), per this task's own
// instruction: read-only, but it reveals the same operational-policy-shaped
// information (which detectors are candidates for disabling, how
// aggressive a storm-protection ceiling would be against real history) that
// writing detection settings does, so it gets that capability's existing
// scope rather than a broader read capability with no catalogue precedent.
//
// What correlation matching is NOT resimulated: this endpoint does not
// rebuild an alternate incident-correlation state machine from scratch.
// Whether a given historical finding matched an already-open incident
// ("bumped") vs. faced a genuine "open a new incident, or not" decision
// ("opportunity") is read directly off what actually happened
// (findings.incident_id and whether that finding's occurred_at equals its
// incident's first_seen) — that fact is unaffected by either detection
// control being simulated here (correlation depends on fingerprint/state,
// not on which detectors are disabled or where the storm ceiling sits).
// What IS resimulated, faithfully, per opportunity: (a) whether the
// opportunity's own detector would have been filtered out entirely under
// the candidate's disabledDetectorIds — in which case, like the live path,
// it never reaches storm-protection at all; and (b) whether the candidate's
// storm-protection ceiling would have suppressed it, replayed as a genuine
// rolling window over the surviving (non-filtered) opportunities in
// chronological order, exactly mirroring handleFinding's own
// count-in-window-then-compare-to-ceiling logic.
type detectionDryRunRequest = putDetectionSettingsRequest

// detectionDryRunDefaultDays/MaxDays bound the "days" query parameter — a
// reporting-shaped window, not a paginated exhaustive query, matching
// insights.go's own "top N / fixed window" precedent rather than
// IncidentList's virtualization discipline. 90 is a generous but bounded
// ceiling so a mistyped huge value can't turn this into an unbounded
// full-table scan.
const (
	detectionDryRunDefaultDays = 7
	detectionDryRunMaxDays     = 90
)

// detectionDryRunResponse is POST /api/v1/detection/dry-run's full response
// shape.
type detectionDryRunResponse struct {
	WindowDays             int                         `json:"windowDays"`
	WindowStart            string                      `json:"windowStart"`
	GeneratedAt            string                      `json:"generatedAt"`
	TotalFindingsInWindow  int                         `json:"totalFindingsInWindow"`
	DisabledDetectorFilter detectionDryRunFilterResult `json:"disabledDetectorFilter"`
	StormProtection        detectionDryRunStormResult  `json:"stormProtection"`
}

// detectionDryRunFilterResult is the disabled-detector-filter half of the
// response — how many of the window's real findings would never have
// reached correlation at all under the candidate's disabledDetectorIds,
// exactly like handleFinding's own hub-side filter (finding.go's doc
// comment: "no findings row, no incident touched").
type detectionDryRunFilterResult struct {
	FilteredCount     int                           `json:"filteredCount"`
	ByClusterDetector []detectionDryRunFilterBucket `json:"byClusterDetector"`
}

type detectionDryRunFilterBucket struct {
	ClusterID              string `json:"clusterId"`
	ClusterName            string `json:"clusterName"`
	DetectorID             string `json:"detectorId"`
	FindingCount           int    `json:"findingCount"`
	FilteredUnderCandidate bool   `json:"filteredUnderCandidate"`
}

// detectionDryRunStormOutcome is a plain created/suppressed tally — used
// for both "what actually happened" (under whatever settings were live at
// the time each finding arrived) and "what the candidate would have done."
type detectionDryRunStormOutcome struct {
	CreatedCount    int `json:"createdCount"`
	SuppressedCount int `json:"suppressedCount"`
}

// detectionDryRunStormResult is the storm-protection half of the response.
// EligibleOpportunities is the count of "would this finding open a brand
// new incident, or not" decisions whose detector is NOT among the
// candidate's disabledDetectorIds (an opportunity whose detector IS
// disabled under the candidate is counted once, in
// DisabledDetectorFilter, and excluded here entirely — under the
// candidate it never arrives, so it never faces a storm-protection decision
// either).
type detectionDryRunStormResult struct {
	CandidateConfigured   bool                        `json:"candidateConfigured"`
	EligibleOpportunities int                         `json:"eligibleOpportunities"`
	Actual                detectionDryRunStormOutcome `json:"actual"`
	Candidate             detectionDryRunStormOutcome `json:"candidate"`
	// NewlySuppressedCount/NewlyAllowedCount are the numbers a UI narrative
	// ("N incidents that were created would have been suppressed instead")
	// reads most directly from — the subset of opportunities where the
	// candidate's outcome actually differs from what happened in reality,
	// not just the raw totals above.
	NewlySuppressedCount int                          `json:"newlySuppressedCount"`
	NewlyAllowedCount    int                          `json:"newlyAllowedCount"`
	ByClusterDetector    []detectionDryRunStormBucket `json:"byClusterDetector"`
}

type detectionDryRunStormBucket struct {
	ClusterID            string                      `json:"clusterId"`
	ClusterName          string                      `json:"clusterName"`
	DetectorID           string                      `json:"detectorId"`
	Opportunities        int                         `json:"opportunities"`
	Actual               detectionDryRunStormOutcome `json:"actual"`
	Candidate            detectionDryRunStormOutcome `json:"candidate"`
	NewlySuppressedCount int                         `json:"newlySuppressedCount"`
	NewlyAllowedCount    int                         `json:"newlyAllowedCount"`
}

// handleDetectionDryRun is POST /api/v1/detection/dry-run. Requires
// org:settings:write (server.go). See this file's header comment for the
// full design; in short: decode + validate the candidate exactly like PUT
// /api/v1/admin/settings does, run one bounded aggregation query over real
// history, then hand the rows to the pure, DB-free simulateDetectionDryRun
// (unit tested independently in detection_dryrun_test.go).
func (s *Server) handleDetectionDryRun(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	var req detectionDryRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}
	// Reuses settings.go's own validation function verbatim — a candidate
	// this endpoint would simulate against but PUT /api/v1/admin/settings
	// would reject (e.g. a storm-protection ceiling with no window) is
	// rejected here identically, before any query runs.
	if err := validateDetectionSettingsRequest(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", err.Error(), "")
		return
	}

	days, err := parseDetectionDryRunDays(r.URL.Query().Get("days"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Invalid days query parameter", err.Error())
		return
	}

	now := time.Now().UTC()
	windowStart := now.AddDate(0, 0, -days)

	// lookbackStart extends further back than the requested window only
	// when the candidate's own storm-protection window needs it — findings
	// just before windowStart still occupy a real slot in the candidate's
	// rolling ceiling for opportunities right at the start of the requested
	// window, and skipping them would make this endpoint UNDER-count how
	// aggressive the candidate ceiling would really have been. They're
	// fetched purely to warm up that rolling state (see the InScope flag
	// below) — never counted in any returned statistic themselves.
	lookbackStart := windowStart
	if gateway.StormProtectionConfigured(req.StormProtectionMaxNewIncidents, req.StormProtectionWindowSeconds) {
		lookbackStart = windowStart.Add(-time.Duration(*req.StormProtectionWindowSeconds) * time.Second)
	}

	rows, err := queryDetectionDryRunFindings(r.Context(), rc.Tx, lookbackStart, windowStart)
	if err != nil {
		logger.ErrorContext(r.Context(), "querying the historical findings for a detection dry run failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not compute dry-run simulation", "")
		return
	}

	result := simulateDetectionDryRun(rows, candidateDetectionSettings{
		DisabledDetectorIDs: req.DisabledDetectorIDs,
		MaxNewIncidents:     req.StormProtectionMaxNewIncidents,
		WindowSeconds:       req.StormProtectionWindowSeconds,
	})

	writeJSON(w, http.StatusOK, detectionDryRunResponse{
		WindowDays:             days,
		WindowStart:            formatRFC3339(windowStart),
		GeneratedAt:            nowRFC3339(),
		TotalFindingsInWindow:  result.totalFindingsInScope,
		DisabledDetectorFilter: result.filterResult,
		StormProtection:        result.stormResult,
	})
}

// parseDetectionDryRunDays parses the "days" query parameter, defaulting to
// detectionDryRunDefaultDays when absent and rejecting anything outside
// [1, detectionDryRunMaxDays] with a clear error rather than silently
// clamping — pulled out as its own pure function so it's unit-testable with
// no HTTP request involved (see detection_dryrun_test.go).
func parseDetectionDryRunDays(raw string) (int, error) {
	if raw == "" {
		return detectionDryRunDefaultDays, nil
	}
	days, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("must be a whole number of days")
	}
	if days < 1 || days > detectionDryRunMaxDays {
		return 0, fmt.Errorf("must be between 1 and %d", detectionDryRunMaxDays)
	}
	return days, nil
}

// detectionDryRunFindingRow is one row of queryDetectionDryRunFindings'
// result — exactly the facts simulateDetectionDryRun needs, already
// decoded from Postgres, so that function itself stays pure and DB-free.
type detectionDryRunFindingRow struct {
	ClusterID   string
	ClusterName string
	DetectorID  string
	OccurredAt  time.Time
	// IngestedAt is the HUB-clock time this finding arrived (findings.ingested_at,
	// DEFAULT now()), as distinct from OccurredAt, which is the AGENT-supplied
	// time the problem was observed. The storm-protection replay below must use
	// this one: live storm protection counts incidents by hub clock, so
	// replaying against agent time would simulate different behaviour from the
	// one it claims to mirror — badly wrong for a skewed or backfilling agent,
	// which is exactly the case storm protection exists to handle.
	IngestedAt         time.Time
	HadIncident        bool // findings.incident_id IS NOT NULL
	CreatedNewIncident bool // this finding is the one whose incident it was — occurred_at == that incident's first_seen
	InScope            bool // within the caller's requested window, not just the storm-protection lookback
}

// queryDetectionDryRunFindings is this endpoint's one and only query — a
// single pass over `findings` (LEFT JOINed to `incidents` to determine
// whether a given finding actually opened its incident, and JOINed to
// `clusters` for a human-readable name), no N+1, matching insights.go's
// established "real Postgres aggregation, never a per-row follow-up query"
// discipline. Ordered by (cluster_id, occurred_at) so the caller can
// replay each cluster's history in true chronological order with a single
// linear pass.
//
// created_new_incident's equality check (f.occurred_at = i.first_seen)
// is safe because both values originate from the exact same
// time.Time — handleFinding's INSERT INTO incidents and INSERT INTO
// findings within one transaction both use the literal Finding.OccurredAt
// value for first_seen/occurred_at respectively when a new incident is
// created (finding.go) — so the finding that created an incident always
// carries the identical timestamp its incident's first_seen does, and no
// other finding sharing that incident_id (a later "bump") can ever
// coincidentally match unless it happened at the exact same instant, which
// would itself already be a `bump`, not a second creation.
//
// created_new_incident is gated on `i.first_seen IS NOT NULL`,
// not just `f.incident_id IS NOT NULL` — a finding whose incident_id names a
// row the LEFT JOIN can't resolve (the incident was deleted, or is outside
// this request's RLS scope) leaves i.first_seen NULL, and
// `TRUE AND (f.occurred_at = NULL)` evaluates to SQL NULL under three-valued
// logic, which pgx cannot scan into this struct's plain (non-pointer) bool
// field — found live via a real, if orphaned, findings row
// (fnd_01m0gj9gbfar8tjh9vm8y7mr4r, incident_id inc_sweep_reopen1, no matching
// incidents row) that 500'd this whole endpoint. A finding whose incident
// record is not resolvable could not have visibly created it, so `false` is
// the correct answer here, not just the safe one.
func queryDetectionDryRunFindings(ctx context.Context, tx pgx.Tx, lookbackStart, windowStart time.Time) ([]detectionDryRunFindingRow, error) {
	rows, err := tx.Query(ctx, `
		SELECT f.cluster_id, c.display_name, f.detector_id, f.occurred_at, f.ingested_at,
		       f.incident_id IS NOT NULL AS had_incident,
		       (i.first_seen IS NOT NULL AND f.occurred_at = i.first_seen) AS created_new_incident,
		       f.occurred_at >= $2 AS in_scope
		  FROM findings f
		  JOIN clusters c ON c.id = f.cluster_id
		  LEFT JOIN incidents i ON i.id = f.incident_id
		 WHERE f.occurred_at >= $1
		 ORDER BY f.cluster_id, f.occurred_at ASC, f.id ASC`,
		lookbackStart, windowStart)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []detectionDryRunFindingRow{}
	for rows.Next() {
		var row detectionDryRunFindingRow
		if err := rows.Scan(&row.ClusterID, &row.ClusterName, &row.DetectorID, &row.OccurredAt, &row.IngestedAt,
			&row.HadIncident, &row.CreatedNewIncident, &row.InScope); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// candidateDetectionSettings is simulateDetectionDryRun's input — the exact
// three fields putDetectionSettingsRequest/detectionSettingsView carry,
// renamed slightly (MaxNewIncidents/WindowSeconds instead of the
// Storm-Protection-prefixed wire names) purely for brevity inside this
// file's own simulation code.
type candidateDetectionSettings struct {
	DisabledDetectorIDs []string
	MaxNewIncidents     *int
	WindowSeconds       *int
}

// detectionDryRunSimResult is simulateDetectionDryRun's return value —
// unexported, since handleDetectionDryRun immediately reshapes it into the
// public detectionDryRunResponse above.
type detectionDryRunSimResult struct {
	totalFindingsInScope int
	filterResult         detectionDryRunFilterResult
	stormResult          detectionDryRunStormResult
}

// clusterDetectorKey groups both halves of this endpoint's output by
// (cluster, detector) — the breakdown this task's brief explicitly asks
// for.
type clusterDetectorKey struct {
	clusterID  string
	detectorID string
}

// simulateDetectionDryRun is the pure, DB-free replay at the center of this
// feature — unit tested independently of any live Postgres connection (see
// detection_dryrun_test.go), matching insights.go's fillDailyTrend
// precedent for "pull the one genuinely pure step out where it can be
// tested directly."
//
// It makes exactly one real decision per input row beyond what's already
// recorded in history: whether the candidate's disabledDetectorIds would
// have filtered this finding's detector (gateway.IsDetectorDisabled — the
// live path's own function), and, for findings that faced a genuine
// "open a new incident, or not" decision in reality (opportunities — see
// detectionDryRunFindingRow's doc comment), whether the candidate's
// storm-protection settings would have suppressed it, replayed
// chronologically per cluster with gateway.StormProtectionConfigured/
// WindowStart/ShouldSuppress — again, the live path's own functions, never
// a second copy.
//
// rows must already be ordered by (cluster_id, occurred_at) ascending —
// queryDetectionDryRunFindings guarantees this; the rolling
// storm-protection window this function maintains per cluster depends on
// that ordering.
func simulateDetectionDryRun(rows []detectionDryRunFindingRow, candidate candidateDetectionSettings) detectionDryRunSimResult {
	type filterAgg struct {
		clusterName  string
		findingCount int
		filtered     bool
	}
	filterBuckets := map[clusterDetectorKey]*filterAgg{}

	type stormAgg struct {
		clusterName                                                      string
		opportunities                                                    int
		actualCreated, actualSuppressed, candidateCreated, candidateSupp int
		newlySuppressed, newlyAllowed                                    int
	}
	stormBuckets := map[clusterDetectorKey]*stormAgg{}

	// simCreations tracks, per cluster, the occurred_at of every
	// opportunity the CANDIDATE settings would actually have let through as
	// a new incident so far — the in-memory equivalent of handleFinding's
	// live `SELECT count(*) FROM incidents WHERE cluster_id = $1 AND
	// first_seen >= $2` query, replayed instead of queried, since this
	// candidate's alternate history was never actually written to
	// `incidents`.
	simCreations := map[string][]time.Time{}

	stormConfigured := gateway.StormProtectionConfigured(candidate.MaxNewIncidents, candidate.WindowSeconds)

	var result detectionDryRunSimResult
	result.stormResult.CandidateConfigured = stormConfigured

	for _, row := range rows {
		disabled := gateway.IsDetectorDisabled(row.DetectorID, candidate.DisabledDetectorIDs)
		key := clusterDetectorKey{clusterID: row.ClusterID, detectorID: row.DetectorID}

		if row.InScope {
			result.totalFindingsInScope++
			b, ok := filterBuckets[key]
			if !ok {
				b = &filterAgg{clusterName: row.ClusterName, filtered: disabled}
				filterBuckets[key] = b
			}
			b.findingCount++
			if disabled {
				result.filterResult.FilteredCount++
			}
		}

		// Only "opportunities" — findings that, in reality, faced a genuine
		// new-incident-or-not decision — are relevant to storm protection at
		// all. A finding that bumped an already-open incident is unaffected
		// by storm protection regardless of any setting (finding.go's own
		// comment: "An already-open incident sharing this Finding's
		// fingerprint still updates completely normally regardless of storm
		// protection").
		isOpportunity := row.CreatedNewIncident || !row.HadIncident
		if !isOpportunity {
			continue
		}

		// Under the candidate, a disabled detector's finding never reaches
		// correlation at all (handleFinding's own hub-side filter, applied
		// before the transaction even opens) — so it never faces a
		// storm-protection decision either, and it must not occupy a slot
		// in another detector's rolling ceiling. It's already been counted
		// above, in the disabled-detector-filter tally; it plays no further
		// part here.
		if disabled {
			continue
		}

		var candidateCreated bool
		if !stormConfigured {
			candidateCreated = true
		} else {
			// Hub clock, not row.OccurredAt — see IngestedAt's doc comment.
			windowStart := gateway.StormProtectionWindowStart(row.IngestedAt, *candidate.WindowSeconds)
			countInWindow := 0
			for _, t := range simCreations[row.ClusterID] {
				if !t.Before(windowStart) {
					countInWindow++
				}
			}
			if gateway.StormProtectionShouldSuppress(countInWindow, *candidate.MaxNewIncidents) {
				candidateCreated = false
			} else {
				candidateCreated = true
				simCreations[row.ClusterID] = append(simCreations[row.ClusterID], row.IngestedAt)
			}
		}

		// Rows fetched only to warm up simCreations' rolling window (they
		// precede the caller's actual requested window) still had to run
		// through the candidate ceiling above so later, in-scope rows see
		// an accurate count — but they are never themselves reported.
		if !row.InScope {
			continue
		}

		actualCreated := row.CreatedNewIncident // isOpportunity guarantees this is the exact opposite of "was suppressed at the time"

		result.stormResult.EligibleOpportunities++
		sb, ok := stormBuckets[key]
		if !ok {
			sb = &stormAgg{clusterName: row.ClusterName}
			stormBuckets[key] = sb
		}
		sb.opportunities++
		if actualCreated {
			sb.actualCreated++
			result.stormResult.Actual.CreatedCount++
		} else {
			sb.actualSuppressed++
			result.stormResult.Actual.SuppressedCount++
		}
		if candidateCreated {
			sb.candidateCreated++
			result.stormResult.Candidate.CreatedCount++
		} else {
			sb.candidateSupp++
			result.stormResult.Candidate.SuppressedCount++
		}
		if actualCreated && !candidateCreated {
			sb.newlySuppressed++
			result.stormResult.NewlySuppressedCount++
		}
		if !actualCreated && candidateCreated {
			sb.newlyAllowed++
			result.stormResult.NewlyAllowedCount++
		}
	}

	for key, b := range filterBuckets {
		result.filterResult.ByClusterDetector = append(result.filterResult.ByClusterDetector, detectionDryRunFilterBucket{
			ClusterID:              key.clusterID,
			ClusterName:            b.clusterName,
			DetectorID:             key.detectorID,
			FindingCount:           b.findingCount,
			FilteredUnderCandidate: b.filtered,
		})
	}
	sort.Slice(result.filterResult.ByClusterDetector, func(i, j int) bool {
		a, c := result.filterResult.ByClusterDetector[i], result.filterResult.ByClusterDetector[j]
		if a.ClusterID != c.ClusterID {
			return a.ClusterID < c.ClusterID
		}
		return a.DetectorID < c.DetectorID
	})

	for key, sb := range stormBuckets {
		result.stormResult.ByClusterDetector = append(result.stormResult.ByClusterDetector, detectionDryRunStormBucket{
			ClusterID:     key.clusterID,
			ClusterName:   sb.clusterName,
			DetectorID:    key.detectorID,
			Opportunities: sb.opportunities,
			Actual: detectionDryRunStormOutcome{
				CreatedCount:    sb.actualCreated,
				SuppressedCount: sb.actualSuppressed,
			},
			Candidate: detectionDryRunStormOutcome{
				CreatedCount:    sb.candidateCreated,
				SuppressedCount: sb.candidateSupp,
			},
			NewlySuppressedCount: sb.newlySuppressed,
			NewlyAllowedCount:    sb.newlyAllowed,
		})
	}
	sort.Slice(result.stormResult.ByClusterDetector, func(i, j int) bool {
		a, c := result.stormResult.ByClusterDetector[i], result.stormResult.ByClusterDetector[j]
		if a.ClusterID != c.ClusterID {
			return a.ClusterID < c.ClusterID
		}
		return a.DetectorID < c.DetectorID
	})

	// Non-nil-on-the-wire, matching this codebase's established convention
	// (automationSettingsView/detectionSettingsView's own doc comments) —
	// an empty simulation should render as an empty array, not a JSON null
	// the frontend has to special-case.
	if result.filterResult.ByClusterDetector == nil {
		result.filterResult.ByClusterDetector = []detectionDryRunFilterBucket{}
	}
	if result.stormResult.ByClusterDetector == nil {
		result.stormResult.ByClusterDetector = []detectionDryRunStormBucket{}
	}

	return result
}
