package api

import (
	"testing"
	"time"
)

// TestFillDailyTrendZeroFillsMissingDays covers queryDailyTrend's date-
// arithmetic step in isolation (no DB needed — see fillDailyTrend's own doc
// comment for why this one function is split out): a day with a real
// aggregated row keeps it, a day with no analyses at all gets an explicit
// zero point rather than being silently absent, and the window is exactly
// `days` long, oldest first.
func TestFillDailyTrendZeroFillsMissingDays(t *testing.T) {
	now := time.Date(2026, 8, 20, 15, 4, 5, 0, time.UTC)
	byDay := map[string]dailyTrendPoint{
		"2026-08-20": {Day: "2026-08-20", Investigations: 3, TotalTokens: 900},
		"2026-08-18": {Day: "2026-08-18", Investigations: 1, TotalTokens: 100},
	}

	got := fillDailyTrend(byDay, 5, now)

	if len(got) != 5 {
		t.Fatalf("len(got) = %d, want 5", len(got))
	}

	want := []dailyTrendPoint{
		{Day: "2026-08-16", Investigations: 0, TotalTokens: 0},
		{Day: "2026-08-17", Investigations: 0, TotalTokens: 0},
		{Day: "2026-08-18", Investigations: 1, TotalTokens: 100},
		{Day: "2026-08-19", Investigations: 0, TotalTokens: 0},
		{Day: "2026-08-20", Investigations: 3, TotalTokens: 900},
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("got[%d] = %+v, want %+v", i, got[i], w)
		}
	}
}

// TestFillDailyTrendEmptyInput covers the "no analyses at all in the
// window" case — every day must still come back as an explicit zero point,
// never an empty slice, so the frontend's trend panel renders a real
// zero-height chart rather than nothing at all (lld/11-ui-design.md §7's
// "no results" vs. "no data exists at all" distinction, applied to a chart
// rather than a list).
func TestFillDailyTrendEmptyInput(t *testing.T) {
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	got := fillDailyTrend(map[string]dailyTrendPoint{}, 3, now)

	want := []dailyTrendPoint{
		{Day: "2026-08-18", Investigations: 0, TotalTokens: 0},
		{Day: "2026-08-19", Investigations: 0, TotalTokens: 0},
		{Day: "2026-08-20", Investigations: 0, TotalTokens: 0},
	}
	if len(got) != len(want) {
		t.Fatalf("len(got) = %d, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("got[%d] = %+v, want %+v", i, got[i], w)
		}
	}
}

// TestTrendWindowStartIsUTCMidnightOfOldestKey is the regression guard for
// the day-bucketing bug: queryDailyTrend's SQL window start and
// fillDailyTrend's zero-fill keys must describe the same range of UTC
// calendar days, or a real aggregated row falls outside the key set and is
// silently dropped (which is what happened to *today's* row whenever the
// Postgres session's TimeZone was east of UTC). Asserted structurally —
// trendWindowStart must be exactly midnight UTC on the oldest day
// fillDailyTrend emits — rather than by restating the arithmetic.
func TestTrendWindowStartIsUTCMidnightOfOldestKey(t *testing.T) {
	// 23:30 UTC: the exact case the old SQL got wrong. Under a session
	// TimeZone of, say, Asia/Tokyo, date_trunc('day', created_at) bucketed
	// a row created at this instant as *tomorrow*, a key never generated.
	nows := []time.Time{
		time.Date(2026, 8, 21, 23, 30, 0, 0, time.UTC),
		time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
		// Same instant as 2026-08-21T23:30Z, but expressed in a +09:00
		// location, i.e. already "tomorrow" locally. The window start and
		// the keys must both stay on the UTC day.
		time.Date(2026, 8, 22, 8, 30, 0, 0, time.FixedZone("JST", 9*3600)),
	}
	for _, now := range nows {
		for _, days := range []int{1, 14, 30, 90} {
			got := trendWindowStart(now, days)

			if got.Location() != time.UTC {
				t.Errorf("trendWindowStart(%s, %d) location = %v, want UTC", now, days, got.Location())
			}
			if h, m, s := got.Clock(); h != 0 || m != 0 || s != 0 || got.Nanosecond() != 0 {
				t.Errorf("trendWindowStart(%s, %d) = %s, want midnight", now, days, got)
			}

			keys := fillDailyTrend(map[string]dailyTrendPoint{}, days, now)
			if len(keys) != days {
				t.Fatalf("fillDailyTrend(%s, %d) returned %d points", now, days, len(keys))
			}
			if want := keys[0].Day; got.Format("2006-01-02") != want {
				t.Errorf("trendWindowStart(%s, %d) = %s, but oldest zero-filled key is %s",
					now, days, got.Format("2006-01-02"), want)
			}
			// The newest key must be the UTC day of `now` — never the
			// local-time day, which for the JST case above is a day later.
			if want, got := now.UTC().Format("2006-01-02"), keys[len(keys)-1].Day; got != want {
				t.Errorf("newest key for now=%s is %s, want the UTC day %s", now, got, want)
			}
		}
	}
}

// TestFillDailyTrendKeysAreUTCDays pins the Go half of the SQL/Go agreement:
// whatever location the clock arrives in, the keys are UTC calendar days, so
// they can be looked up with the `(created_at AT TIME ZONE 'UTC')::date`
// buckets the query now returns.
func TestFillDailyTrendKeysAreUTCDays(t *testing.T) {
	// 2026-08-22T08:30+09:00 == 2026-08-21T23:30Z.
	now := time.Date(2026, 8, 22, 8, 30, 0, 0, time.FixedZone("JST", 9*3600))
	byDay := map[string]dailyTrendPoint{
		"2026-08-21": {Day: "2026-08-21", Investigations: 2, TotalTokens: 500},
	}

	got := fillDailyTrend(byDay, 2, now)

	want := []dailyTrendPoint{
		{Day: "2026-08-20", Investigations: 0, TotalTokens: 0},
		{Day: "2026-08-21", Investigations: 2, TotalTokens: 500},
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("got[%d] = %+v, want %+v", i, got[i], w)
		}
	}
}

// TestNotBuiltInsightsHasBothGaps guards against the "explicitly NOT built"
// markers this task's own spec required silently disappearing in a future
// edit — calibration curves and autonomy readiness must both keep showing
// up as honest gaps until they're actually built, not quietly dropped
// because someone refactoring this file didn't realize they were load-
// bearing rather than decorative.
func TestNotBuiltInsightsHasBothGaps(t *testing.T) {
	ids := map[string]bool{}
	for _, n := range notBuiltInsights {
		if n.Label == "" || n.Reason == "" {
			t.Errorf("notBuilt entry %q has an empty Label or Reason", n.ID)
		}
		ids[n.ID] = true
	}
	for _, want := range []string{"calibrationCurve", "autonomyReadiness"} {
		if !ids[want] {
			t.Errorf("notBuiltInsights is missing %q", want)
		}
	}
}
