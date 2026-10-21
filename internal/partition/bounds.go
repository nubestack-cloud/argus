package partition

import (
	"fmt"
	"time"
)

// This file holds every piece of pure, DB-free partition-boundary logic —
// given a date, what this period's or the next period's partition bounds
// and name are, and the inverse (given a partition's name, what period does
// it cover). Deliberately separated from partition.go's DB-touching
// Maintainer methods so it's obvious at a glance which logic bounds_test.go
// can exercise with no database at all.

// monthStart truncates t to the first instant of its UTC calendar month —
// the partition period boundary this package uses throughout. Always
// returns a UTC time, regardless of t's own location, since every
// partitioned column here (occurred_at, first_seen) is timestamptz and this
// package's bounds must be unambiguous regardless of the caller's local
// clock.
func monthStart(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// nextMonthStart returns the first instant of the calendar month after ms.
// ms is assumed to already be a month start (i.e. the result of monthStart
// or of this function itself) — callers never pass an arbitrary mid-month
// time here.
func nextMonthStart(ms time.Time) time.Time {
	return ms.AddDate(0, 1, 0)
}

// monthBounds returns the [start, end) range a single monthly partition
// covers, given its start (a month-start time, per monthStart's contract).
// end is exclusive, matching Postgres range-partition FOR VALUES FROM (...)
// TO (...) semantics exactly — end itself belongs to the next partition, not
// this one.
func monthBounds(ms time.Time) (start, end time.Time) {
	return ms, nextMonthStart(ms)
}

// partitionName computes the deterministic name this package gives the
// partition of table covering the calendar month starting at ms — e.g.
// partitionName("findings", time.Date(2026, 8, 1, ...)) ==
// "findings_y2026m08". Sortable (lexical order matches chronological order
// for any fixed table, since the year/month digits are always zero-padded
// to a fixed width) and self-describing in `\d+` / pg_tables output, unlike
// a bare sequence number would be.
func partitionName(table string, ms time.Time) string {
	return fmt.Sprintf("%s_%s", table, partitionSuffix(ms))
}

// partitionSuffix is partitionName's suffix half, factored out so
// parsePartitionMonth's prefix-stripping logic and this function agree on
// the exact same format string by construction rather than by convention.
func partitionSuffix(ms time.Time) string {
	return fmt.Sprintf("y%04dm%02d", ms.Year(), int(ms.Month()))
}

// parsePartitionMonth is partitionName's inverse: given a table name and a
// candidate partition name (as returned by a live `pg_inherits` query
// against that table — see listDatedPartitions), reports the month-start
// time that partition covers, and whether name actually matched this
// package's own "<table>_yYYYYmMM" naming scheme at all. Returns ok == false
// for anything that doesn't match — most importantly `<table>_default`
// (migrations 000004/000005/000008's catch-all partition), which has no
// "_y" year/month suffix and therefore can never be mistaken for one of
// this job's own dated partitions. This is what makes "never touch
// `_default`" a structural property of applyRetention rather than a
// special-cased check: a name that doesn't parse is simply never considered
// a drop candidate.
func parsePartitionMonth(table, name string) (time.Time, bool) {
	prefix := table + "_"
	if len(name) <= len(prefix) || name[:len(prefix)] != prefix {
		return time.Time{}, false
	}
	suffix := name[len(prefix):]

	var year, month int
	n, err := fmt.Sscanf(suffix, "y%04dm%02d", &year, &month)
	if err != nil || n != 2 {
		return time.Time{}, false
	}
	if month < 1 || month > 12 {
		return time.Time{}, false
	}
	// Round-trip check: guards against fmt.Sscanf accepting a superficially
	// similar but not-actually-matching suffix (e.g. trailing garbage after
	// the two numbers, which Sscanf silently ignores rather than erroring
	// on) — if reconstructing the suffix from the parsed year/month doesn't
	// give back the exact same string, this wasn't really one of this
	// package's own names.
	parsed := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC)
	if partitionSuffix(parsed) != suffix {
		return time.Time{}, false
	}
	return parsed, true
}

// pastRetention reports whether the monthly partition starting at ms is
// wholly older than a retention window ending at cutoff — i.e. every row it
// could possibly contain (its whole [start, end) range) is at or before
// cutoff. A partition straddling cutoff (its end is after cutoff) is NOT
// past retention: this job only ever drops a partition once its entire
// range has aged out, never rows within a still-partially-current one,
// since dropping is all-or-nothing (DROP TABLE), unlike a row-level DELETE.
func pastRetention(ms, cutoff time.Time) bool {
	_, end := monthBounds(ms)
	return !end.After(cutoff)
}

// retentionCutoff computes the cutoff instant for a retention window of
// retentionDays ending at now: any partition whose range ends at or before
// this instant is past retention (see pastRetention). Pure arithmetic,
// factored out from applyRetention so the "given a retention window and
// now, what's the cutoff" computation is independently testable.
func retentionCutoff(now time.Time, retentionDays int) time.Time {
	return now.AddDate(0, 0, -retentionDays)
}
