package partition

import (
	"testing"
	"time"
)

func date(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// TestMonthStart pins the truncation rule: any timestamp within a calendar
// month (UTC) truncates to that month's first instant, regardless of
// day/time-of-day, and regardless of the input's own location.
func TestMonthStart(t *testing.T) {
	cases := []struct {
		name string
		in   time.Time
		want time.Time
	}{
		{"first of month, midnight", date(2026, time.August, 1), date(2026, time.August, 1)},
		{"mid-month with a time-of-day", time.Date(2026, time.August, 19, 14, 32, 7, 0, time.UTC), date(2026, time.August, 1)},
		{"last day of month", date(2026, time.August, 31), date(2026, time.August, 1)},
		{"non-UTC input is normalised to UTC first", func() time.Time {
			loc := time.FixedZone("UTC-5", -5*3600)
			// 2026-08-01 02:00 UTC-5 == 2026-08-01 07:00 UTC, still August.
			return time.Date(2026, time.August, 1, 2, 0, 0, 0, loc)
		}(), date(2026, time.August, 1)},
		{"non-UTC input that rolls back a calendar day in UTC still resolves correctly", func() time.Time {
			loc := time.FixedZone("UTC+10", 10*3600)
			// 2026-08-01 05:00 UTC+10 == 2026-07-31 19:00 UTC -> July, not August.
			return time.Date(2026, time.August, 1, 5, 0, 0, 0, loc)
		}(), date(2026, time.July, 1)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := monthStart(c.in); !got.Equal(c.want) {
				t.Errorf("monthStart(%v) = %v, want %v", c.in, got, c.want)
			}
			if got := monthStart(c.in); got.Location() != time.UTC {
				t.Errorf("monthStart(%v) location = %v, want UTC", c.in, got.Location())
			}
		})
	}
}

// TestNextMonthStartAndMonthBounds pins the rollover arithmetic, including
// the two edge cases most likely to be gotten wrong by hand: December ->
// January (year rollover) and February in a leap vs. non-leap year (which
// must not matter at all, since bounds are computed from AddDate, never by
// hardcoding a day count).
func TestNextMonthStartAndMonthBounds(t *testing.T) {
	cases := []struct {
		name          string
		start         time.Time
		wantNextStart time.Time
	}{
		{"ordinary month", date(2026, time.August, 1), date(2026, time.September, 1)},
		{"december rolls into january of the next year", date(2026, time.December, 1), date(2027, time.January, 1)},
		{"january rolls back from december correctly", date(2026, time.January, 1), date(2026, time.February, 1)},
		{"february in a leap year", date(2024, time.February, 1), date(2024, time.March, 1)},
		{"february in a non-leap year", date(2025, time.February, 1), date(2025, time.March, 1)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := nextMonthStart(c.start); !got.Equal(c.wantNextStart) {
				t.Errorf("nextMonthStart(%v) = %v, want %v", c.start, got, c.wantNextStart)
			}
			start, end := monthBounds(c.start)
			if !start.Equal(c.start) {
				t.Errorf("monthBounds(%v) start = %v, want %v", c.start, start, c.start)
			}
			if !end.Equal(c.wantNextStart) {
				t.Errorf("monthBounds(%v) end = %v, want %v (exclusive upper bound)", c.start, end, c.wantNextStart)
			}
		})
	}
}

// TestPartitionNameAndParseRoundTrip pins the naming scheme itself and its
// exact inverse — every (table, month) pair this package could ever compute
// a name for must parse back to the identical month, for every table this
// job actually manages.
func TestPartitionNameAndParseRoundTrip(t *testing.T) {
	tables := []string{"findings", "incidents", "audit_events"}
	months := []time.Time{
		date(2026, time.January, 1),
		date(2026, time.August, 1),
		date(2026, time.December, 1),
		date(2027, time.January, 1),
		date(2099, time.November, 1),
	}
	for _, table := range tables {
		for _, m := range months {
			name := partitionName(table, m)
			got, ok := parsePartitionMonth(table, name)
			if !ok {
				t.Errorf("parsePartitionMonth(%q, %q) ok = false, want true", table, name)
				continue
			}
			if !got.Equal(m) {
				t.Errorf("parsePartitionMonth(%q, %q) = %v, want %v", table, name, got, m)
			}
		}
	}

	t.Run("exact expected format", func(t *testing.T) {
		if got, want := partitionName("findings", date(2026, time.August, 1)), "findings_y2026m08"; got != want {
			t.Errorf("partitionName = %q, want %q", got, want)
		}
		if got, want := partitionName("audit_events", date(2026, time.January, 1)), "audit_events_y2026m01"; got != want {
			t.Errorf("partitionName = %q, want %q", got, want)
		}
	})
}

// TestParsePartitionMonthRejectsNonMatches pins the property applyRetention
// depends on for safety: anything that isn't exactly this package's own
// "<table>_yYYYYmMM" naming scheme fails to parse, most importantly
// "<table>_default" (migrations 000004/000005/000008's catch-all partition,
// which this job must NEVER drop) and another table's own dated partition
// name.
func TestParsePartitionMonthRejectsNonMatches(t *testing.T) {
	cases := []struct {
		name  string
		table string
		part  string
	}{
		{"the default partition itself", "findings", "findings_default"},
		{"a different table's default partition", "incidents", "findings_default"},
		{"a different table's own dated partition", "incidents", "findings_y2026m08"},
		{"the parent table name with no suffix at all", "findings", "findings"},
		{"garbage suffix that still starts with _y", "findings", "findings_yNOTANUMBER"},
		{"month out of range (13)", "findings", "findings_y2026m13"},
		{"month out of range (00)", "findings", "findings_y2026m00"},
		{"trailing garbage after a valid-looking suffix", "findings", "findings_y2026m08extra"},
		{"completely unrelated name", "findings", "some_other_table"},
		{"empty string", "findings", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, ok := parsePartitionMonth(c.table, c.part); ok {
				t.Errorf("parsePartitionMonth(%q, %q) ok = true, want false", c.table, c.part)
			}
		})
	}
}

// TestPartitionBoundsIntegration ties monthStart/nextMonthStart/monthBounds/
// partitionName together the way ensureUpcomingPartitions actually uses
// them: given "now," what are the current and next period's partition name
// and FOR VALUES FROM/TO bounds. This is the exact computation the task
// asked to be unit-testable without a live database.
func TestPartitionBoundsIntegration(t *testing.T) {
	now := time.Date(2026, time.August, 19, 10, 0, 0, 0, time.UTC)

	thisMonth := monthStart(now)
	nextMonth := nextMonthStart(thisMonth)

	thisStart, thisEnd := monthBounds(thisMonth)
	if !thisStart.Equal(date(2026, time.August, 1)) || !thisEnd.Equal(date(2026, time.September, 1)) {
		t.Errorf("this month's bounds = [%v, %v), want [2026-08-01, 2026-09-01)", thisStart, thisEnd)
	}
	if got := partitionName("findings", thisMonth); got != "findings_y2026m08" {
		t.Errorf("this month's partition name = %q, want findings_y2026m08", got)
	}

	nextStart, nextEnd := monthBounds(nextMonth)
	if !nextStart.Equal(date(2026, time.September, 1)) || !nextEnd.Equal(date(2026, time.October, 1)) {
		t.Errorf("next month's bounds = [%v, %v), want [2026-09-01, 2026-10-01)", nextStart, nextEnd)
	}
	if got := partitionName("findings", nextMonth); got != "findings_y2026m09" {
		t.Errorf("next month's partition name = %q, want findings_y2026m09", got)
	}
}

// TestRetentionCutoffAndPastRetention pins the drop decision itself: given
// "now" and a configured retention window, which partitions are wholly past
// it. This is Part B's core boundary calculation — a partition is only ever
// dropped once its ENTIRE month has aged out, never while any part of its
// range could still hold a row within the retention window.
func TestRetentionCutoffAndPastRetention(t *testing.T) {
	now := date(2026, time.August, 19)

	t.Run("retentionCutoff subtracts days from now", func(t *testing.T) {
		got := retentionCutoff(now, 30)
		want := date(2026, time.July, 20)
		if !got.Equal(want) {
			t.Errorf("retentionCutoff(%v, 30) = %v, want %v", now, got, want)
		}
	})

	cutoff := retentionCutoff(now, 30) // 2026-07-20

	cases := []struct {
		name    string
		partMon time.Time // partition's month-start
		want    bool
	}{
		{"a partition ending well before cutoff is past retention", date(2026, time.May, 1), true},
		// May 2026 covers [2026-05-01, 2026-06-01), which ends before the
		// 2026-07-20 cutoff.
		{"june 2026 (ends 2026-07-01, before cutoff) is past retention", date(2026, time.June, 1), true},
		{"july 2026 (ends 2026-08-01, AFTER cutoff) straddles the cutoff and is NOT past retention", date(2026, time.July, 1), false},
		{"august 2026 (the current, still-open month) is nowhere near past retention", date(2026, time.August, 1), false},
		{"a future month is never past retention", date(2026, time.December, 1), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := pastRetention(c.partMon, cutoff); got != c.want {
				t.Errorf("pastRetention(%v, %v) = %v, want %v", c.partMon, cutoff, got, c.want)
			}
		})
	}

	t.Run("a partition whose end lands exactly on the cutoff counts as past retention", func(t *testing.T) {
		// Constructed so monthBounds' end exactly equals cutoff (not just
		// close to it) — pastRetention uses !end.After(cutoff), so an exact
		// match must count as past retention, not straddling.
		exactCutoff := date(2026, time.July, 1)
		partMonth := date(2026, time.June, 1) // ends exactly at 2026-07-01
		if !pastRetention(partMonth, exactCutoff) {
			t.Errorf("pastRetention(%v, %v) = false, want true (end exactly equals cutoff)", partMonth, exactCutoff)
		}
	})
}
