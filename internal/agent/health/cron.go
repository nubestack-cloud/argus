package health

// A rough cadence for a cron schedule, so a CronJob's staleness is judged
// against its own interval rather than a flat day: a quarterly job that last
// ran, on time, 29 days ago is healthy, not stale.

import (
	"slices"
	"strconv"
	"strings"
	"time"
)

const cronDay = 24 * time.Hour

// cronMacros are the @-schedules with fixed cadences.
var cronMacros = map[string]time.Duration{
	"@yearly": 365 * cronDay, "@annually": 365 * cronDay,
	"@monthly": 28 * cronDay, "@weekly": 7 * cronDay,
	"@daily": cronDay, "@midnight": cronDay, "@hourly": time.Hour,
}

// cronMinInterval estimates the interval between runs of a five-field cron
// schedule (minute hour day-of-month month day-of-week) or an @-macro. It is
// approximate on purpose: its only job is to stop a staleness check calling a
// weekly, monthly, quarterly or yearly job stale by a daily yardstick, so
// wherever it must guess, it guesses long — for months and days of the
// month, the widest gap between firings. ok is false for a schedule it
// cannot read, and callers fall back to the flat threshold.
func cronMinInterval(schedule string) (time.Duration, bool) {
	// '?' is Quartz's "no particular value" for the day fields; read as '*',
	// so a daily "0 0 ? * *" is not taken for monthly.
	s := strings.ReplaceAll(strings.TrimSpace(schedule), "?", "*")
	if d, ok := cronMacros[s]; ok {
		return d, true
	}
	f := strings.Fields(s)
	if len(f) != 5 {
		return 0, false
	}
	hour, dom, month, dow := f[1], f[2], f[3], f[4]
	widest := func(gap time.Duration, ok bool) time.Duration {
		if ok {
			return gap
		}
		return 28 * cronDay
	}
	switch {
	case month != "*":
		// Some months only: the widest gap between them (a year for one).
		return widest(cronMaxMonthGapDays(month)), true
	case dom != "*":
		// Some days of the month: the widest gap between them, not a flat
		// month — "1,15" runs fortnightly, and taking it for monthly let it
		// miss two runs in a row and still read healthy for six weeks.
		return widest(cronMaxDomGapDays(dom)), true
	case dow != "*":
		// Some days of the week: at most a week apart.
		return 7 * cronDay, true
	case hour != "*" && !strings.HasPrefix(hour, "*/"):
		return cronDay, true
	}
	// Several times a day.
	return time.Hour, true
}

// cronMaxDomGapDays is the longest a day-of-month field can go between runs.
// Days of the month are not even steps: the wrap into the next month depends
// on its length, and the 29th to 31st do not exist in every month. Both are
// taken the long way, so the answer is an upper bound and a healthy job never
// trips a staleness check: the wrap is measured over a 31-day month, and
// only days that every month has are counted on to fire.
func cronMaxDomGapDays(field string) (time.Duration, bool) {
	days, ok := cronFieldValues(field, 1, 31)
	if !ok {
		return 0, false
	}
	sure := slices.DeleteFunc(days, func(d int) bool { return d > 28 })
	if len(sure) == 0 {
		// Only the 29th–31st: a short month can go by without a run (the
		// 31st of January to the 31st of March).
		return 62 * cronDay, true
	}
	// One day a month is a 31-day cycle at worst (1 January to 1 February).
	gap := 31 - sure[len(sure)-1] + sure[0]
	for i := 1; i < len(sure); i++ {
		gap = max(gap, sure[i]-sure[i-1])
	}
	return time.Duration(gap) * cronDay, true
}

// cronMaxMonthGapDays is the longest a month field can go between runs, each
// month counted as 31 days so the answer is an upper bound: a year for one
// month, otherwise the widest gap between consecutive months, December
// wrapping round to the next year.
func cronMaxMonthGapDays(field string) (time.Duration, bool) {
	months, ok := cronFieldValues(field, 1, 12)
	if !ok {
		return 0, false
	}
	if len(months) == 1 {
		return 365 * cronDay, true
	}
	gap := months[0] + 12 - months[len(months)-1]
	for i := 1; i < len(months); i++ {
		gap = max(gap, months[i]-months[i-1])
	}
	return time.Duration(gap) * 31 * cronDay, true
}

// cronFieldValues expands one cron field — a list of *, single values and
// ranges, each optionally with a /step — into its sorted values within
// [lo, hi]. A single value with a step runs from it to hi, as cron reads
// "5/15". Any part it cannot read makes ok false, so a caller never trusts a
// partial set.
func cronFieldValues(field string, lo, hi int) ([]int, bool) {
	var out []int
	for _, part := range strings.Split(field, ",") {
		rng, stepText, stepped := strings.Cut(part, "/")
		step := 1
		if stepped {
			n, err := strconv.Atoi(stepText)
			if err != nil || n <= 0 {
				return nil, false
			}
			step = n
		}
		from, to := lo, hi
		if rng != "*" {
			a, b, isRange := strings.Cut(rng, "-")
			first, err := strconv.Atoi(a)
			if err != nil {
				return nil, false
			}
			from, to = first, first
			switch {
			case isRange:
				if to, err = strconv.Atoi(b); err != nil {
					return nil, false
				}
			case stepped:
				to = hi
			}
		}
		if from < lo || to > hi || from > to {
			return nil, false
		}
		for v := from; v <= to; v += step {
			out = append(out, v)
		}
	}
	slices.Sort(out)
	out = slices.Compact(out)
	return out, len(out) > 0
}

// cronStaleThreshold is how long a CronJob may go without a run before it is
// stale: its interval and half again, but never less than a day, so frequent
// jobs keep a day's sensitivity.
func cronStaleThreshold(schedule string) time.Duration {
	interval, ok := cronMinInterval(schedule)
	if !ok {
		return cronDay
	}
	return max(interval+interval/2, cronDay)
}
