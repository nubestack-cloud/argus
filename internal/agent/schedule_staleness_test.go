package agent

import (
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestCronNext(t *testing.T) {
	base := time.Date(2026, 10, 14, 10, 7, 0, 0, time.UTC) // a Wednesday
	for _, tc := range []struct {
		expr    string
		seconds bool
		want    string
	}{
		{"*/15 * * * *", false, "2026-10-14T10:15:00Z"},
		{"30 2 * * *", false, "2026-10-15T02:30:00Z"},
		{"0 0 * * 0", false, "2026-10-18T00:00:00Z"}, // Sunday
		{"@hourly", false, "2026-10-14T11:00:00Z"},
		{"0 0 1 * *", false, "2026-11-01T00:00:00Z"},
		{"0 0 0 * * *", true, "2026-10-15T00:00:00Z"}, // CloudNativePG's six fields
	} {
		c, err := parseCron(tc.expr, tc.seconds)
		if err != nil {
			t.Fatalf("%q: %v", tc.expr, err)
		}
		if got := c.next(base).Format(time.RFC3339); got != tc.want {
			t.Errorf("next(%q) = %s, want %s", tc.expr, got, tc.want)
		}
	}
	for _, bad := range []string{"", "* * *", "61 * * * *", "0 0 * JAN *", "@reboot"} {
		if _, err := parseCron(bad, false); err == nil {
			t.Errorf("parseCron(%q) accepted", bad)
		}
	}
}

// PROJECT.md IN8: two missed runs since the last success is a fault; one is
// not; a suspended schedule never is.
func TestStaleSchedule(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	cron := func(lastSuccess string, suspend bool) *unstructured.Unstructured {
		o := &unstructured.Unstructured{Object: map[string]any{
			"metadata": map[string]any{"name": "nightly", "namespace": "ops", "creationTimestamp": "2026-09-01T00:00:00Z"},
			"spec":     map[string]any{"schedule": "0 1 * * *", "suspend": suspend},
			"status":   map[string]any{},
		}}
		if lastSuccess != "" {
			o.Object["status"] = map[string]any{"lastSuccessfulTime": lastSuccess}
		}
		return o
	}
	src := scheduleSources[0]
	if _, ok := staleSchedule(cron("2026-10-13T01:05:00Z", false), src, now); ok {
		t.Error("a daily job that succeeded yesterday was reported")
	}
	c, ok := staleSchedule(cron("2026-10-11T01:05:00Z", false), src, now)
	if !ok || c.Reason != "ScheduleNotRunning" || c.GVK != "batch/v1/CronJob" {
		t.Fatalf("a daily job last successful three days ago was not reported: %+v", c)
	}
	if _, ok := staleSchedule(cron("2026-10-11T01:05:00Z", true), src, now); ok {
		t.Error("a suspended job was reported")
	}
	if _, ok := staleSchedule(cron("", false), src, now); !ok {
		t.Error("a daily job that never succeeded in six weeks was not reported")
	}
}

// addScheduleListKinds registers the schedule sources with a fake dynamic
// client's list kinds: the fake panics on a List it has no kind for, where a
// real API server answers NotFound, so every fake that reaches runOneSweep
// needs them.
func addScheduleListKinds(m map[schema.GroupVersionResource]string) map[schema.GroupVersionResource]string {
	for _, s := range scheduleSources {
		m[s.gvr] = s.gvk[strings.LastIndex(s.gvk, "/")+1:] + "List"
	}
	for _, s := range batchAISources {
		m[s.gvr] = s.gvk[strings.LastIndex(s.gvk, "/")+1:] + "List"
	}
	return m
}
