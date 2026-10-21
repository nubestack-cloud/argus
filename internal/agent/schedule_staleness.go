package agent

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// Schedules that stopped running (PROJECT.md IN8). A CronJob, a Velero
// Schedule or a CloudNativePG ScheduledBackup declares how often it should run
// and records when it last did; nothing fires when the gap between the two
// grows. The declarative rules compare a field against a literal and cannot
// derive "how late is late" from a cron expression, so this is Go.
//
// The rule, for every kind: from the last successful run (or the object's
// creation, if it never succeeded), at least scheduleMissedRuns scheduled
// runs must have come and gone, the latest of them more than
// scheduleRunSlack ago. Two missed runs, not one, so a single slow or
// skipped run is not a fault. Suspended or paused objects are skipped:
// stopping on purpose is not stopping.
const (
	scheduleMissedRuns = 2
	scheduleRunSlack   = 15 * time.Minute
)

// scheduleSource is one kind with a cron schedule and a last-run time, read
// from fixed field paths. lastRun is the most trustworthy "it worked" time
// the kind records.
type scheduleSource struct {
	gvr      schema.GroupVersionResource
	gvk      string
	schedule []string
	suspend  []string
	lastRun  [][]string // first non-empty wins
	seconds  bool       // six-field cron with a leading seconds field
	what     string     // "completed successfully" / "created a backup"
	// shared is true for a kind the pass' unstructured snapshot already
	// lists: it is read from there (staleSchedulesInSnapshot), never listed a
	// second time (PROJECT.md P28).
	shared bool
}

var scheduleSources = []scheduleSource{
	{
		gvr: schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "cronjobs"}, gvk: "batch/v1/CronJob", shared: true,
		schedule: []string{"spec", "schedule"}, suspend: []string{"spec", "suspend"},
		lastRun: [][]string{{"status", "lastSuccessfulTime"}}, what: "completed a run successfully",
	},
	{
		gvr: schema.GroupVersionResource{Group: "velero.io", Version: "v1", Resource: "schedules"}, gvk: "velero.io/v1/Schedule",
		schedule: []string{"spec", "schedule"}, suspend: []string{"spec", "paused"},
		lastRun: [][]string{{"status", "lastBackup"}}, what: "created a backup",
	},
	{
		gvr: schema.GroupVersionResource{Group: "postgresql.cnpg.io", Version: "v1", Resource: "scheduledbackups"}, gvk: "postgresql.cnpg.io/v1/ScheduledBackup",
		schedule: []string{"spec", "schedule"}, suspend: []string{"spec", "suspend"},
		lastRun: [][]string{{"status", "lastScheduleTime"}}, seconds: true, what: "scheduled a backup",
	},
}

func checkStaleSchedules(ctx context.Context, dyn dynamic.Interface, now time.Time, _ time.Duration) ([]sweepCandidate, error) {
	var out []sweepCandidate
	for _, src := range scheduleSources {
		if src.shared {
			continue
		}
		list, err := dyn.Resource(src.gvr).Namespace(metav1.NamespaceAll).List(ctx, sweepListOptions)
		if err != nil {
			if meta.IsNoMatchError(err) || apierrors.IsNotFound(err) || apierrors.IsForbidden(err) {
				continue // kind not installed, or not granted: nothing to judge
			}
			return out, err
		}
		for i := range list.Items {
			if c, ok := staleSchedule(&list.Items[i], src, now); ok {
				out = append(out, c)
			}
		}
	}
	return out, nil
}

// staleSchedulesInSnapshot judges the shared kinds from the pass' one list.
func staleSchedulesInSnapshot(snap *unstructuredSnapshot, now time.Time) []sweepCandidate {
	var out []sweepCandidate
	for _, src := range scheduleSources {
		if !src.shared {
			continue
		}
		for _, obj := range snap.objectsOf(src.gvk[strings.LastIndex(src.gvk, "/")+1:]) {
			if c, ok := staleSchedule(obj, src, now); ok {
				out = append(out, c)
			}
		}
	}
	return out
}

func staleSchedule(obj *unstructured.Unstructured, src scheduleSource, now time.Time) (sweepCandidate, bool) {
	if suspended, _, _ := unstructured.NestedBool(obj.Object, src.suspend...); suspended {
		return sweepCandidate{}, false
	}
	expr, _, _ := unstructured.NestedString(obj.Object, src.schedule...)
	sched, err := parseCron(expr, src.seconds)
	if err != nil {
		return sweepCandidate{}, false
	}
	since, ranBefore := obj.GetCreationTimestamp().Time, false
	for _, path := range src.lastRun {
		if s, _, _ := unstructured.NestedString(obj.Object, path...); s != "" {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				since, ranBefore = t, true
				break
			}
		}
	}
	if since.IsZero() {
		return sweepCandidate{}, false
	}
	missed, latest := 0, time.Time{}
	for t := sched.next(since); !t.IsZero() && t.Before(now.Add(-scheduleRunSlack)); t = sched.next(t) {
		missed++
		latest = t
		if missed >= scheduleMissedRuns {
			break
		}
	}
	if missed < scheduleMissedRuns {
		return sweepCandidate{}, false
	}
	last := "has never " + src.what
	if ranBefore {
		last = "last " + src.what + " at " + since.UTC().Format(time.RFC3339)
	}
	kind := src.gvk[strings.LastIndex(src.gvk, "/")+1:]
	return sweepCandidate{
		GVK: src.gvk, Namespace: obj.GetNamespace(), Name: obj.GetName(), UID: string(obj.GetUID()), ResourceVersion: obj.GetResourceVersion(),
		Reason: "ScheduleNotRunning",
		Message: fmt.Sprintf("%s %s/%s %s; at least %d runs of its schedule %q have been due since (latest %s), so it has stopped running",
			kind, obj.GetNamespace(), obj.GetName(), last, scheduleMissedRuns, expr, latest.UTC().Format(time.RFC3339)),
		Severity: "medium", Class: "fault", Confidence: "verified", Impact: "degraded",
		SustainedFrom: latest, OccurredAt: now,
	}, true
}

// cronSchedule is a parsed cron expression: the allowed values per field.
type cronSchedule struct {
	sec, min, hour, dom, month, dow map[int]bool
	domStar, dowStar                bool
}

// parseCron reads a standard five-field expression (or six with leading
// seconds), and the @yearly/@monthly/@weekly/@daily/@hourly macros. Names
// (JAN, MON) and the L/W/# extensions are not supported; an expression using
// them is skipped rather than guessed at.
func parseCron(expr string, withSeconds bool) (*cronSchedule, error) {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "CRON_TZ=") || strings.HasPrefix(expr, "TZ=") {
		if i := strings.IndexByte(expr, ' '); i > 0 {
			expr = strings.TrimSpace(expr[i:])
		}
	}
	switch expr {
	case "@yearly", "@annually":
		expr = "0 0 1 1 *"
	case "@monthly":
		expr = "0 0 1 * *"
	case "@weekly":
		expr = "0 0 * * 0"
	case "@daily", "@midnight":
		expr = "0 0 * * *"
	case "@hourly":
		expr = "0 * * * *"
	default:
		if strings.HasPrefix(expr, "@") {
			return nil, fmt.Errorf("unsupported macro %q", expr)
		}
		if withSeconds {
			fields := strings.Fields(expr)
			if len(fields) != 6 {
				return nil, fmt.Errorf("want six fields, got %d", len(fields))
			}
			s, err := cronField(fields[0], 0, 59)
			if err != nil {
				return nil, err
			}
			c, err := parseCron(strings.Join(fields[1:], " "), false)
			if err != nil {
				return nil, err
			}
			c.sec = s
			return c, nil
		}
	}
	f := strings.Fields(expr)
	if len(f) != 5 {
		return nil, fmt.Errorf("want five fields, got %d", len(f))
	}
	var c cronSchedule
	var err error
	bounds := [5][2]int{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7}}
	dst := []*map[int]bool{&c.min, &c.hour, &c.dom, &c.month, &c.dow}
	for i := range f {
		if *dst[i], err = cronField(f[i], bounds[i][0], bounds[i][1]); err != nil {
			return nil, err
		}
	}
	if c.dow[7] {
		c.dow[0] = true
	}
	c.domStar, c.dowStar = f[2] == "*" || f[2] == "?", f[4] == "*" || f[4] == "?"
	c.sec = map[int]bool{0: true}
	return &c, nil
}

func cronField(s string, lo, hi int) (map[int]bool, error) {
	out := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		step := 1
		if i := strings.IndexByte(part, '/'); i >= 0 {
			n, err := strconv.Atoi(part[i+1:])
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("bad step in %q", part)
			}
			step, part = n, part[:i]
		}
		from, to := lo, hi
		switch {
		case part == "*" || part == "?":
		case strings.Contains(part, "-"):
			a, b, _ := strings.Cut(part, "-")
			x, err1 := strconv.Atoi(a)
			y, err2 := strconv.Atoi(b)
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("bad range %q", part)
			}
			from, to = x, y
		default:
			x, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("bad value %q", part)
			}
			from, to = x, x
			if step > 1 {
				to = hi
			}
		}
		if from < lo || to > hi || from > to {
			return nil, fmt.Errorf("%q out of range %d-%d", part, lo, hi)
		}
		for v := from; v <= to; v += step {
			out[v] = true
		}
	}
	return out, nil
}

// next is the first scheduled time strictly after t, in UTC (the controllers'
// default), or zero if none falls within the next 400 days.
func (c *cronSchedule) next(t time.Time) time.Time {
	t = t.UTC().Truncate(time.Second).Add(time.Second)
	end := t.AddDate(0, 0, 400)
	for day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC); day.Before(end); day = day.AddDate(0, 0, 1) {
		if !c.month[int(day.Month())] || !c.dayMatches(day) {
			continue
		}
		for h := 0; h < 24; h++ {
			if !c.hour[h] {
				continue
			}
			for m := 0; m < 60; m++ {
				if !c.min[m] {
					continue
				}
				for s := 0; s < 60; s++ {
					if !c.sec[s] {
						continue
					}
					if at := day.Add(time.Duration(h)*time.Hour + time.Duration(m)*time.Minute + time.Duration(s)*time.Second); !at.Before(t) {
						return at
					}
				}
			}
		}
	}
	return time.Time{}
}

// dayMatches applies cron's rule: when both day-of-month and day-of-week are
// restricted, either matching is enough.
func (c *cronSchedule) dayMatches(d time.Time) bool {
	dom, dow := c.dom[d.Day()], c.dow[int(d.Weekday())]
	switch {
	case c.domStar && c.dowStar:
		return true
	case c.domStar:
		return dow
	case c.dowStar:
		return dom
	default:
		return dom || dow
	}
}
