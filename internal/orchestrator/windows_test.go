package orchestrator

import (
	"testing"
	"time"
)

func at(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("bad test timestamp %q: %v", s, err)
	}
	return ts
}

// The core question: schedule names the START, duration says how long it stays
// open. A bare cron is an instant, so without duration nothing would ever be
// "inside" a window at all.
func TestWindowIsOpenForItsWholeDuration(t *testing.T) {
	w := Window{ID: "w1", Kind: WindowMaintenance, Schedule: "0 9 * * 1-5", Duration: 8 * time.Hour, Timezone: "UTC"}
	for _, tc := range []struct {
		when string
		open bool
		why  string
	}{
		{"2026-08-24T08:59:00Z", false, "one minute before it opens"},
		{"2026-08-24T09:00:00Z", true, "the firing minute itself"},
		{"2026-08-24T13:00:00Z", true, "the middle"},
		{"2026-08-24T16:59:59Z", true, "the last second"},
		{"2026-08-24T17:00:00Z", false, "exactly duration later — the window is half-open, [start, start+duration)"},
		{"2026-08-24T20:00:00Z", false, "long after"},
		{"2026-08-23T13:00:00Z", false, "a Sunday, which the day-of-week field excludes"},
		{"2026-08-22T13:00:00Z", false, "a Saturday"},
	} {
		open, err := w.IsOpen(at(t, tc.when))
		if err != nil {
			t.Fatalf("%s: %v", tc.when, err)
		}
		if open != tc.open {
			t.Errorf("IsOpen(%s) = %v, want %v — %s", tc.when, open, tc.open, tc.why)
		}
	}
}

// Timezone is not decoration: a window written as 9am London must be 9am London
// on both sides of a DST boundary, which is the whole reason the walk is over UTC
// instants converted into the location rather than over local wall-clock times.
func TestWindowRespectsTimezoneAcrossDST(t *testing.T) {
	w := Window{ID: "w", Kind: WindowMaintenance, Schedule: "0 9 * * *", Duration: time.Hour, Timezone: "Europe/London"}
	// London is UTC+1 in August: 9am local is 08:00Z.
	summerOpen, err := w.IsOpen(at(t, "2026-08-24T08:30:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if !summerOpen {
		t.Error("9am Europe/London window was closed at 08:30Z in August, when London is UTC+1")
	}
	if open, _ := w.IsOpen(at(t, "2026-08-24T09:30:00Z")); open {
		t.Error("the window was open at 09:30Z in August — that is 10:30 local, an hour after it closed")
	}
	// London is UTC+0 in January: 9am local is 09:00Z. Same expression, different
	// instant — which is the point.
	winterOpen, err := w.IsOpen(at(t, "2026-01-15T09:30:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if !winterOpen {
		t.Error("the same 9am Europe/London window was closed at 09:30Z in January, when London is UTC+0")
	}
	if open, _ := w.IsOpen(at(t, "2026-01-15T08:30:00Z")); open {
		t.Error("the window was open at 08:30Z in January — that is 08:30 local, before it opens")
	}
}

// A freeze beats everything, including an open maintenance window. DESIGN.md
// §7.2: "nothing automatic, ever".
func TestFreezeBeatsMaintenance(t *testing.T) {
	now := at(t, "2026-12-25T12:00:00Z")
	windows := []Window{
		{ID: "always", Kind: WindowMaintenance, Schedule: "* * * * *", Duration: time.Hour, Timezone: "UTC"},
		{ID: "xmas", Kind: WindowFreeze, Schedule: "0 0 24 12 *", Duration: 72 * time.Hour, Timezone: "UTC", Reason: "December change freeze"},
	}
	d := CheckWindows(now, windows)
	if d.Allowed {
		t.Fatal("automation was allowed inside a change freeze, with a maintenance window also open. A freeze must win outright")
	}
	if d.BlockedBy != "xmas" {
		t.Errorf("BlockedBy = %q, want the freeze window's id", d.BlockedBy)
	}
	if !containsAll(d.Reason, "change freeze", "December change freeze") {
		t.Errorf("the refusal does not carry the operator's own reason: %q", d.Reason)
	}
}

// The null-semantics decision, asserted because getting it the other way would
// silently stop automation on every existing installation the day this shipped.
func TestNoMaintenanceWindowsMeansNoTimeRestriction(t *testing.T) {
	d := CheckWindows(at(t, "2026-08-24T03:00:00Z"), nil)
	if !d.Allowed {
		t.Fatal("an empty window list blocked automation. An empty MAINTENANCE list must mean 'no time restriction' — the literal reading of 'automatic mode only inside these' would take every installation that runs unattended execution today and silently stop it")
	}
	// A freeze alone must still be able to block, without any maintenance window
	// existing — the two lists are independent.
	freezeOnly := []Window{{ID: "f", Kind: WindowFreeze, Schedule: "* * * * *", Duration: time.Hour, Timezone: "UTC", Reason: "incident in progress"}}
	if CheckWindows(at(t, "2026-08-24T03:00:00Z"), freezeOnly).Allowed {
		t.Error("a freeze window with no maintenance window configured failed to block")
	}
}

// Outside a maintenance window, automation waits. The reason must say so rather
// than reading as an error.
func TestOutsideMaintenanceWindowWaits(t *testing.T) {
	windows := []Window{{ID: "weekdays", Kind: WindowMaintenance, Schedule: "0 9 * * 1-5", Duration: 8 * time.Hour, Timezone: "UTC"}}
	d := CheckWindows(at(t, "2026-08-24T22:00:00Z"), windows)
	if d.Allowed {
		t.Fatal("allowed outside every maintenance window")
	}
	if !containsAll(d.Reason, "outside", "maintenance window") {
		t.Errorf("reason = %q, want it to say the request waits for the next window", d.Reason)
	}
}

// An unreadable rule must never widen what is permitted. A broken freeze blocks;
// a broken maintenance window does not grant.
func TestUnreadableWindowsFailSafe(t *testing.T) {
	badFreeze := []Window{{ID: "bad", Kind: WindowFreeze, Schedule: "not a cron", Duration: time.Hour, Reason: "x"}}
	if d := CheckWindows(time.Now(), badFreeze); d.Allowed {
		t.Error("a malformed FREEZE window allowed automation. An unreadable prohibition must be treated as in force")
	}
	badMaint := []Window{{ID: "bad", Kind: WindowMaintenance, Schedule: "not a cron", Duration: time.Hour}}
	if d := CheckWindows(time.Now(), badMaint); d.Allowed {
		t.Error("a malformed MAINTENANCE window granted permission. An unreadable rule must not widen what is allowed")
	}
}

// Vixie cron's day-field rule, which is the one genuinely surprising part of the
// format: when BOTH day-of-month and day-of-week are restricted, a match on
// EITHER is a match. A naive AND turns "0 0 13 * 5" into Friday the 13th, so the
// window would fire roughly twice a year instead of ~60 times.
func TestBothDayFieldsRestrictedMeansOr(t *testing.T) {
	f, err := parseCron("0 0 13 * 5")
	if err != nil {
		t.Fatal(err)
	}
	// 2026-08-13 is a Thursday: day-of-month matches, day-of-week does not.
	if !f.matches(at(t, "2026-08-13T00:00:00Z")) {
		t.Error("the 13th did not match, though day-of-month names it — both day fields are restricted, so either matching is a match")
	}
	// 2026-08-14 is a Friday: day-of-week matches, day-of-month does not.
	if !f.matches(at(t, "2026-08-14T00:00:00Z")) {
		t.Error("a Friday did not match, though day-of-week names it")
	}
	// A Tuesday that is not the 13th matches neither.
	if f.matches(at(t, "2026-08-11T00:00:00Z")) {
		t.Error("a day matching neither day field matched")
	}
	// And with only ONE day field restricted, the fields AND as usual.
	g, err := parseCron("0 0 * * 5")
	if err != nil {
		t.Fatal(err)
	}
	if g.matches(at(t, "2026-08-13T00:00:00Z")) {
		t.Error("day-of-week-only expression matched a Thursday")
	}
	if !g.matches(at(t, "2026-08-14T00:00:00Z")) {
		t.Error("day-of-week-only expression did not match a Friday")
	}
}

func TestParseCronFieldForms(t *testing.T) {
	for _, expr := range []string{
		"* * * * *", "0 9 * * 1-5", "*/15 * * * *", "0 0,12 * * *",
		"30 2 1 1 *", "0 9-17 * * *", "0 0-23/6 * * *", "0 0 * * 0", "0 0 * * 7",
	} {
		if _, err := parseCron(expr); err != nil {
			t.Errorf("parseCron(%q) = %v, want it accepted", expr, err)
		}
	}
	// Sunday is both 0 and 7 in cron, and the parser normalises 7 so matches()
	// can compare against time.Weekday directly.
	f, err := parseCron("0 0 * * 7")
	if err != nil {
		t.Fatal(err)
	}
	if !f.matches(at(t, "2026-08-23T00:00:00Z")) { // a Sunday
		t.Error("day-of-week 7 did not match a Sunday; cron allows both 0 and 7")
	}
}

// Every refusal names what was wrong, because a schedule is compared by hand
// against Argo CD's own sync windows and silently accepting a syntax one side
// does not support is worse than refusing it.
func TestParseCronRefusals(t *testing.T) {
	for _, tc := range []struct{ expr, wantIn string }{
		{"* * * *", "exactly 5 fields"},
		{"* * * * * *", "exactly 5 fields"},
		{"60 * * * *", "outside"},
		{"* 24 * * *", "outside"},
		{"0 0 0 * *", "outside"},
		{"0 0 * 13 *", "outside"},
		{"@daily", "5 fields"},
		{"0 9 * * MON", "names like MON"},
		{"9-5 * * * *", "backwards"},
		{"*/0 * * * *", "invalid step"},
		{"0 , * * *", "empty term"},
	} {
		_, err := parseCron(tc.expr)
		if err == nil {
			t.Errorf("parseCron(%q) was accepted", tc.expr)
			continue
		}
		if !containsAll(err.Error(), tc.wantIn) {
			t.Errorf("parseCron(%q) = %v, want a message containing %q", tc.expr, err, tc.wantIn)
		}
	}
}

func TestValidateWindow(t *testing.T) {
	ok := Window{Kind: WindowMaintenance, Schedule: "0 9 * * 1-5", Duration: 8 * time.Hour, Timezone: "Europe/London"}
	if err := ValidateWindow(ok); err != nil {
		t.Fatalf("a valid window was refused: %v", err)
	}
	for _, tc := range []struct {
		name   string
		w      Window
		wantIn string
	}{
		{"unknown kind", Window{Kind: "sometimes", Schedule: "* * * * *", Duration: time.Hour}, "window kind"},
		{"zero duration", Window{Kind: WindowMaintenance, Schedule: "* * * * *"}, "positive"},
		{"absurd duration", Window{Kind: WindowMaintenance, Schedule: "* * * * *", Duration: 8 * 24 * time.Hour}, "longer than a week"},
		{"unknown timezone", Window{Kind: WindowMaintenance, Schedule: "* * * * *", Duration: time.Hour, Timezone: "Mars/Olympus"}, "IANA"},
		{"freeze with no reason", Window{Kind: WindowFreeze, Schedule: "* * * * *", Duration: time.Hour}, "needs a reason"},
	} {
		if err := ValidateWindow(tc.w); err == nil {
			t.Errorf("%s: accepted", tc.name)
		} else if !containsAll(err.Error(), tc.wantIn) {
			t.Errorf("%s: %v, want a message containing %q", tc.name, err, tc.wantIn)
		}
	}
	// A maintenance window needs no reason — only a freeze does, because only a
	// freeze produces a refusal somebody has to understand.
	if err := ValidateWindow(Window{Kind: WindowMaintenance, Schedule: "* * * * *", Duration: time.Hour}); err != nil {
		t.Errorf("a maintenance window without a reason was refused: %v", err)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Openings is IsOpen's walk run forward, for display: each firing opens
// [F, F+duration), an interval already open at `from` keeps its real start, and
// overlapping firings merge into one interval.
func TestWindowOpenings(t *testing.T) {
	weekly := Window{ID: "w", Kind: WindowFreeze, Schedule: "0 18 * * 5", Duration: 48 * time.Hour, Timezone: "UTC"}
	// Monday 2026-10-12: the next Friday 18:00 is the 16th.
	got, err := weekly.Openings(at(t, "2026-10-12T10:00:00Z"), 21*24*time.Hour, 10)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"2026-10-16T18:00:00Z", "2026-10-23T18:00:00Z", "2026-10-30T18:00:00Z"}
	if len(got) != len(want) {
		t.Fatalf("got %d openings, want %d: %v", len(got), len(want), got)
	}
	for i, w := range want {
		if !got[i].Start.Equal(at(t, w)) || got[i].End.Sub(got[i].Start) != 48*time.Hour {
			t.Errorf("opening %d = %v–%v, want %s for 48h", i, got[i].Start, got[i].End, w)
		}
	}

	// Saturday noon is inside the window that opened on Friday at 18:00.
	inside, _ := weekly.Openings(at(t, "2026-10-17T12:00:00Z"), 24*time.Hour, 10)
	if len(inside) != 1 || !inside[0].Start.Equal(at(t, "2026-10-16T18:00:00Z")) {
		t.Errorf("an open window should be reported from its real start, got %v", inside)
	}

	// Every minute of 09:00 fires; with 30 minutes each they merge to 09:00–10:29.
	busy := Window{ID: "b", Kind: WindowMaintenance, Schedule: "* 9 * * *", Duration: 30 * time.Minute}
	merged, _ := busy.Openings(at(t, "2026-10-12T00:00:00Z"), 24*time.Hour, 10)
	if len(merged) != 1 || !merged[0].Start.Equal(at(t, "2026-10-12T09:00:00Z")) || !merged[0].End.Equal(at(t, "2026-10-12T10:29:00Z")) {
		t.Errorf("overlapping firings should merge into one interval, got %v", merged)
	}

	capped, _ := weekly.Openings(at(t, "2026-10-12T10:00:00Z"), 90*24*time.Hour, 2)
	if len(capped) != 2 {
		t.Errorf("max should cap the list, got %d", len(capped))
	}
	if _, err := (Window{Schedule: "bad"}).Openings(at(t, "2026-10-12T10:00:00Z"), time.Hour, 1); err == nil {
		t.Error("a malformed schedule should be an error, not an empty list")
	}
}
