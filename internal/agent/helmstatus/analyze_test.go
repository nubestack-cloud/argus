package helmstatus

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)

// history reads "N:status@-age" entries, e.g. "1:superseded@-3h 2:failed@-9m";
// an entry without "@" has no timestamp, and "_" in a status is a space.
func history(spec string) []Revision {
	var out []Revision
	for _, f := range strings.Fields(spec) {
		n, rest, _ := strings.Cut(f, ":")
		st, ago, timed := strings.Cut(rest, "@")
		r := Revision{Status: strings.ReplaceAll(st, "_", " ")}
		r.Revision, _ = strconv.Atoi(n)
		if timed {
			d, err := time.ParseDuration(strings.TrimPrefix(ago, "-"))
			if err != nil {
				panic(err)
			}
			r.Updated = testNow.Add(-d)
		}
		out = append(out, r)
	}
	return out
}

// brief renders an operation as kind:revision, or kind:failed>recovered.
func brief(op *Operation) string {
	if op == nil {
		return "-"
	}
	if op.Kind == KindFailureSuperseded {
		return fmt.Sprintf("%s:%d>%d", op.Kind, op.FailedRevision, op.RecoveredRevision)
	}
	return fmt.Sprintf("%s:%d", op.Kind, op.Revision)
}

func summary(a Analysis) string {
	ops := make([]string, len(a.Operations))
	for i := range a.Operations {
		ops[i] = brief(&a.Operations[i])
	}
	return "last=" + brief(a.LastOperation) + " ops=[" + strings.Join(ops, " ") + "]"
}

func TestAnalyze(t *testing.T) {
	cases := []struct {
		name    string
		current int
		revs    string
		opts    Options
		want    string
	}{
		{"nothing to read", 0, "", Options{}, "last=- ops=[]"},
		// The live failure is reported once, as live, not again from history.
		{"current upgrade failed", 2, "1:superseded@-2h 2:failed@-5m", Options{}, "last=upgrade_failed:2 ops=[]"},
		{"first install failed", 1, "1:failed@-5m", Options{}, "last=release_failed:1 ops=[]"},
		{"next revision deployed over a failure", 3, "1:superseded@-3h 2:failed@-10m 3:deployed@-9m", Options{},
			"last=failure_superseded:2>3 ops=[failure_superseded:2>3]"},
		{"statuses are trimmed and case-folded", 3, "1:_Superseded_ 2:FAILED 3:_Deployed", Options{},
			"last=failure_superseded:2>3 ops=[failure_superseded:2>3]"},
		// With revision 3 missing, 4 cannot be said to follow the failure.
		{"a gap breaks the recovery", 4, "2:failed@-3h 4:deployed@-1h", Options{}, "last=- ops=[upgrade_failed:2]"},
		// Once a later healthy upgrade lands, the recovery is history only.
		{"old recovery", 4, "1:superseded@-4h 2:failed@-3h 3:superseded@-2h 4:deployed@-1h", Options{},
			"last=- ops=[failure_superseded:2>3]"},
		{"current revision not in the history", 9, "1:failed@-1h", Options{}, "last=- ops=[release_failed:1]"},
		{"zero means the newest", 0, "1:deployed@-2h 2:failed@-1h", Options{}, "last=upgrade_failed:2 ops=[]"},
		{"newest first, capped", 7, "1:superseded@-7h 2:failed@-6h 3:superseded@-5h 4:failed@-4h 5:superseded@-3h 6:failed@-2h 7:deployed@-1h",
			Options{MaxOperations: 2}, "last=failure_superseded:6>7 ops=[failure_superseded:6>7 failure_superseded:4>5]"},
		{"pending past the threshold", 4, "4:pending-upgrade@-18m", Options{PendingStuckAfter: 10 * time.Minute}, "last=pending:4 ops=[]"},
		{"pending under the threshold", 4, "4:pending-upgrade@-2m", Options{PendingStuckAfter: 10 * time.Minute}, "last=- ops=[]"},
		// The default is three times Helm's own five-minute timeout.
		{"default threshold, under", 4, "4:pending-install@-14m", Options{}, "last=- ops=[]"},
		{"default threshold, over", 4, "4:pending-install@-16m", Options{}, "last=pending:4 ops=[]"},
		{"pending with no timestamp has no age", 4, "4:pending-upgrade", Options{}, "last=- ops=[]"},
	}
	for _, c := range cases {
		c.opts.Now = testNow
		if got := summary(Analyze("cart", c.current, history(c.revs), c.opts)); got != c.want {
			t.Errorf("%s:\n got  %s\n want %s", c.name, got, c.want)
		}
	}
}

func TestAnalyzeWording(t *testing.T) {
	op := Analyze("ingress-nginx", 0, history("1:failed@-5m"), Options{Now: testNow}).LastOperation
	if op.Source != SourceStatus || op.Confidence != ConfidenceHigh || !strings.HasPrefix(op.Message, `Helm release "ingress-nginx": The install at revision 1 failed`) {
		t.Errorf("failed install = %+v", op)
	}
	// Rollback or fixed upgrade is written only in the payload, so neither
	// is claimed.
	op = Analyze("cart", 0, history("2:failed@-10m 3:deployed@-9m"), Options{Now: testNow}).LastOperation
	if op.Confidence != ConfidenceLow || !strings.Contains(op.Message, "which is unknown") || !op.Updated.Equal(testNow.Add(-9*time.Minute)) {
		t.Errorf("recovery = %+v", op)
	}
	op = Analyze("cart", 0, history("4:pending-rollback@-3h"), Options{Now: testNow}).LastOperation
	if op.Message != "Stuck in pending-rollback for 3h." || op.PendingStatus != "pending-rollback" || op.Status != StatusStuck {
		t.Errorf("stuck = %+v", op)
	}
}

func TestRoughly(t *testing.T) {
	for d, want := range map[time.Duration]string{
		10 * time.Second: "1m", 18 * time.Minute: "18m", 59 * time.Minute: "59m",
		time.Hour: "1h", 90 * time.Minute: "2h", 26 * time.Hour: "26h",
	} {
		if got := roughly(d); got != want {
			t.Errorf("roughly(%s) = %s, want %s", d, got, want)
		}
	}
}

func TestIsPending(t *testing.T) {
	for st, want := range map[string]bool{
		"pending-install": true, "Pending-Upgrade": true, " pending-rollback ": true,
		"deployed": false, "failed": false, "uninstalling": false, "": false,
	} {
		if got := IsPending(st); got != want {
			t.Errorf("IsPending(%q) = %v, want %v", st, got, want)
		}
	}
}
