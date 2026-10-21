package health

import (
	"testing"
	"time"
)

const day = 24 * time.Hour

// The estimate may be generous — it exists to stop rare jobs reading stale —
// so most cases bound it from below; the day-of-month cases bound it from
// above too, since too generous an estimate lets a job miss runs unnoticed.
func TestCronMinInterval(t *testing.T) {
	cases := []struct {
		schedule    string
		least, most time.Duration
	}{
		{"*/10 * * * *", time.Hour, time.Hour},
		{"15 * * * *", time.Hour, time.Hour},
		{"0 3 * * *", day, day},
		{"30 2 * * 0", 7 * day, 7 * day},
		{"0 4 1 * *", 28 * day, 31 * day},
		{"0 0 1 */3 *", 90 * day, 93 * day},    // quarterly, three 31-day months
		{"0 6 1 3 *", 365 * day, 365 * day},    // once a year
		{"0 0 1 4,10 *", 180 * day, 186 * day}, // twice a year
		{"0 0 1 2/6 *", 180 * day, 186 * day},  // February and August
		{"0 1 ? * *", day, day},                // Quartz '?' is '*'
		{"0 1 * * ?", day, day},
		{"0 0 1,15 * *", 14 * day, 17 * day}, // fortnightly, not monthly
		{"0 0 */7 * *", 7 * day, 10 * day},   // 1, 8, 15, 22, 29→ only to 22 is sure
		{"0 0 1-5 * *", day, 27 * day},       // the wrap off the 5th is widest
		{"0 0 30 * *", 60 * day, 62 * day},   // a short month passes without a run
		{"@weekly", 7 * day, 7 * day},
		{"@annually", 365 * day, 365 * day},
		{"@hourly", time.Hour, time.Hour},
	}
	for _, c := range cases {
		got, ok := cronMinInterval(c.schedule)
		if !ok || got < c.least || got > c.most {
			t.Errorf("%q: %s (%v), want %s–%s", c.schedule, got, ok, c.least, c.most)
		}
	}
	// Not five fields and not a macro: refused, so the caller falls back.
	for _, bad := range []string{"", "every day", "0 0 * *", "0 0 1 1 1 1"} {
		if got, ok := cronMinInterval(bad); ok {
			t.Errorf("%q parsed as %s", bad, got)
		}
	}
	// A month field that cannot be read is taken as monthly, not refused.
	if got, ok := cronMinInterval("0 0 1 13 *"); !ok || got != 28*day {
		t.Errorf("bad month field = %s %v", got, ok)
	}
}

func TestCronFieldValues(t *testing.T) {
	for _, c := range []struct {
		field string
		want  []int
		ok    bool
	}{
		{"*", []int{1, 2, 3, 4, 5, 6}, true},
		{"*/2", []int{1, 3, 5}, true},
		{"2/3", []int{2, 5}, true},
		{"1-3,5", []int{1, 2, 3, 5}, true},
		{"4,1,4", []int{1, 4}, true},
		{"0", nil, false},
		{"7", nil, false},
		{"3-1", nil, false},
		{"x", nil, false},
		{"*/0", nil, false},
	} {
		got, ok := cronFieldValues(c.field, 1, 6)
		if ok != c.ok || ok && !equalInts(got, c.want) {
			t.Errorf("%q: %v %v, want %v %v", c.field, got, ok, c.want, c.ok)
		}
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Half again the cadence, never under a day.
func TestCronStaleThreshold(t *testing.T) {
	for schedule, want := range map[string]time.Duration{
		"*/10 * * * *": day,
		"0 3 * * *":    36 * time.Hour,
		"30 2 * * 0":   10*day + 12*time.Hour,
		"@yearly":      547*day + 12*time.Hour,
		"garbage":      day,
	} {
		if got := cronStaleThreshold(schedule); got != want {
			t.Errorf("%q: %s, want %s", schedule, got, want)
		}
	}
}
