package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// PROJECT.md T15's pure-Go coverage: classification, per-tool extraction, and
// the two stated bounds (time window, row cap) — none of this needs
// Postgres, matching this package's own preference (buildEvidenceSummary's
// doc comment in evidence.go) for keeping rules that need testing out of SQL.
// The DB-backed round trip through getRecentChanges itself, and the two
// empty states, are in incidents_recent_changes_db_test.go.

func TestClassifyRecentChangeEvent(t *testing.T) {
	cases := []struct {
		evType, reason, want string
	}{
		{"Warning", "BackOff", "warning_event"},
		{"Warning", "FailedScheduling", "warning_event"},
		{"Normal", "ScalingReplicaSet", "replica_change"},
		{"Normal", "SuccessfulCreate", "rollout_created"},
		{"Normal", "Pulling", "image_pull"},
		{"Normal", "Pulled", "image_pull"},
		{"Normal", "Scheduled", ""},
		{"Normal", "Started", ""},
		{"Normal", "Killing", ""},
	}
	for _, c := range cases {
		got := classifyRecentChangeEvent(c.evType, c.reason)
		if got != c.want {
			t.Errorf("classifyRecentChangeEvent(%q, %q) = %q, want %q", c.evType, c.reason, got, c.want)
		}
	}
}

func TestExtractRecentChangesGetEvents(t *testing.T) {
	result := json.RawMessage(`[
		{"namespace":"prod","involvedObjectKind":"Pod","involvedObjectName":"web-1","reason":"BackOff","message":"Back-off restarting failed container","type":"Warning","count":3,"lastTimestamp":"2026-09-17T10:00:00Z"},
		{"namespace":"prod","involvedObjectKind":"ReplicaSet","involvedObjectName":"web-abc123","reason":"SuccessfulCreate","message":"Created pod: web-abc123-xyz","type":"Normal","count":1,"lastTimestamp":"2026-09-17T09:55:00Z"},
		{"namespace":"prod","involvedObjectKind":"Deployment","involvedObjectName":"web","reason":"ScalingReplicaSet","message":"Scaled up replica set web-abc123 to 3 from 1","type":"Normal","count":1,"lastTimestamp":"2026-09-17T09:54:00Z"},
		{"namespace":"prod","involvedObjectKind":"Pod","involvedObjectName":"web-1","reason":"Pulling","message":"Pulling image \"nginx:1.25\"","type":"Normal","count":1,"lastTimestamp":"2026-09-17T09:56:00Z"},
		{"namespace":"prod","involvedObjectKind":"Pod","involvedObjectName":"web-1","reason":"Scheduled","message":"Successfully assigned prod/web-1 to node-3","type":"Normal","count":1,"lastTimestamp":"2026-09-17T09:53:00Z"}
	]`)

	got := extractRecentChanges("get_events", result)
	if len(got) != 4 {
		t.Fatalf("got %d changes, want 4 (the Scheduled event must be dropped): %+v", len(got), got)
	}
	byCategory := map[string]recentChange{}
	for _, c := range got {
		if c.Source != "get_events" {
			t.Errorf("change %+v has Source %q, want %q", c, c.Source, "get_events")
		}
		byCategory[c.Category] = c
	}
	for _, want := range []string{"warning_event", "rollout_created", "replica_change", "image_pull"} {
		if _, ok := byCategory[want]; !ok {
			t.Errorf("missing category %q in %+v", want, got)
		}
	}
	if rc := byCategory["replica_change"]; !strings.Contains(rc.Message, "Scaled up replica set") {
		t.Errorf("replica_change message = %q, want the verbatim ScalingReplicaSet message", rc.Message)
	}
	if byCategory["warning_event"].ObjectName != "web-1" {
		t.Errorf("warning_event ObjectName = %q, want %q", byCategory["warning_event"].ObjectName, "web-1")
	}
}

func TestExtractRecentChangesListResources(t *testing.T) {
	result := json.RawMessage(`{
		"gvk": "apps/v1/ReplicaSet",
		"namespace": "prod",
		"items": [
			{"name": "web-abc123", "creationTimestamp": "2026-09-17T09:50:00Z"},
			{"name": "web-def456", "creationTimestamp": "2026-09-10T09:50:00Z"}
		],
		"returned": 2,
		"totalMatched": 2
	}`)

	got := extractRecentChanges("list_resources", result)
	if len(got) != 2 {
		t.Fatalf("got %d changes, want 2: %+v", len(got), got)
	}
	for _, c := range got {
		if c.Category != "created" {
			t.Errorf("category = %q, want %q", c.Category, "created")
		}
		if c.Source != "list_resources" {
			t.Errorf("source = %q, want %q", c.Source, "list_resources")
		}
		if c.ObjectKind != "ReplicaSet" {
			t.Errorf("objectKind = %q, want %q (parsed from the gvk, not carried over verbatim)", c.ObjectKind, "ReplicaSet")
		}
		if c.ObjectNamespace != "prod" {
			t.Errorf("objectNamespace = %q, want %q", c.ObjectNamespace, "prod")
		}
	}
}

func TestExtractRecentChangesDescribeResource(t *testing.T) {
	result := json.RawMessage(`{
		"object": {
			"kind": "Deployment",
			"metadata": {"name": "web", "namespace": "prod", "creationTimestamp": "2026-09-01T00:00:00Z"},
			"spec": {"replicas": 3, "template": {"spec": {"containers": [{"image": "nginx:1.25"}]}}}
		},
		"events": [
			{"namespace":"prod","involvedObjectKind":"Deployment","involvedObjectName":"web","reason":"ScalingReplicaSet","message":"Scaled up replica set web-abc123 to 3 from 1","type":"Normal","lastTimestamp":"2026-09-17T09:54:00Z"}
		]
	}`)

	got := extractRecentChanges("describe_resource", result)
	if len(got) != 2 {
		t.Fatalf("got %d changes, want 2 (one creation fact, one embedded event): %+v", len(got), got)
	}

	var creation, event *recentChange
	for i := range got {
		switch got[i].Category {
		case "created":
			creation = &got[i]
		case "replica_change":
			event = &got[i]
		}
	}
	if creation == nil {
		t.Fatal("no 'created' fact extracted from the object's own metadata.creationTimestamp")
	}
	if creation.Time != "2026-09-01T00:00:00Z" || creation.ObjectKind != "Deployment" || creation.ObjectName != "web" {
		t.Errorf("creation fact = %+v, want time/kind/name from metadata", creation)
	}
	if creation.Source != "describe_resource" {
		t.Errorf("creation.Source = %q, want %q", creation.Source, "describe_resource")
	}
	if event == nil {
		t.Fatal("no replica_change fact extracted from the object's embedded events")
	}

	// The object's CURRENT declared image/replica count must never be
	// reported as a change fact — that would be presenting a snapshot as
	// evidence of change with nothing to diff it against (this function's
	// own doc comment, "What was deliberately NOT used").
	for _, c := range got {
		if strings.Contains(c.Message, "nginx:1.25") || c.Category == "image_change" || c.Category == "replica_change_snapshot" {
			t.Errorf("a spec snapshot leaked into the change list: %+v", c)
		}
	}
}

func TestExtractRecentChangesUnparsableResultIsSkippedNotFatal(t *testing.T) {
	for _, tool := range []string{"get_events", "list_resources", "describe_resource", "some_unknown_tool"} {
		got := extractRecentChanges(tool, json.RawMessage(`not valid json`))
		if got != nil {
			t.Errorf("tool %q: got %v for unparsable input, want nil", tool, got)
		}
	}
	if got := extractRecentChanges("get_events", nil); got != nil {
		t.Errorf("empty result: got %v, want nil", got)
	}
}

func TestExtractRecentChangesMessageIsTruncated(t *testing.T) {
	longMsg := strings.Repeat("x", 5000)
	result := json.RawMessage(`[{"involvedObjectKind":"Pod","involvedObjectName":"p","reason":"BackOff","message":"` + longMsg + `","type":"Warning","lastTimestamp":"2026-09-17T10:00:00Z"}]`)
	got := extractRecentChanges("get_events", result)
	if len(got) != 1 {
		t.Fatalf("got %d changes, want 1", len(got))
	}
	if len(got[0].Message) > 500 {
		t.Errorf("message length = %d, want <= 500 (maxToolCallErrorLen-style bound)", len(got[0].Message))
	}
}

// TestFilterAndCapRecentChangesWindow proves the stated time-window bound:
// only facts inside [firstSeen-recentChangeWindow, firstSeen] survive, and
// the survivors come back sorted chronologically.
func TestFilterAndCapRecentChangesWindow(t *testing.T) {
	firstSeen := mustParseRFC3339(t, "2026-09-17T10:00:00Z")
	changeAt := func(offset time.Duration, category string) recentChange {
		return recentChange{Time: firstSeen.Add(offset).UTC().Format(time.RFC3339), Category: category}
	}

	candidates := []recentChange{
		changeAt(-30*time.Hour, "too_old"),        // outside the 24h window — must be dropped
		changeAt(-23*time.Hour, "inside_early"),   // just inside
		changeAt(-1*time.Hour, "inside_late"),     // just inside, closer to the fault
		changeAt(0, "at_first_seen"),              // exactly at first_seen — inclusive
		changeAt(1*time.Hour, "after_first_seen"), // AFTER first_seen — must be dropped ("preceding")
	}

	got, truncated := filterAndCapRecentChanges(candidates, firstSeen)

	var categories []string
	for _, c := range got {
		categories = append(categories, c.Category)
	}
	want := []string{"inside_early", "inside_late", "at_first_seen"}
	if len(categories) != len(want) {
		t.Fatalf("categories = %v, want %v", categories, want)
	}
	for i, c := range categories {
		if c != want[i] {
			t.Errorf("categories[%d] = %q, want %q (order matters — must be chronological)", i, c, want[i])
		}
	}
	if truncated {
		t.Error("truncated = true, want false — nothing here exceeds the row cap")
	}
}

// TestFilterAndCapRecentChangesCap proves the stated row-cap bound: more
// than maxRecentChangeItems candidates inside the window are capped, keeping
// the ones CLOSEST to firstSeen.
func TestFilterAndCapRecentChangesCap(t *testing.T) {
	firstSeen := mustParseRFC3339(t, "2026-09-17T10:00:00Z")

	n := maxRecentChangeItems + 15
	var candidates []recentChange
	for i := 0; i < n; i++ {
		// Spread evenly across the last 23 hours, oldest first.
		offset := -time.Duration(n-i) * time.Minute
		candidates = append(candidates, recentChange{
			Time:       firstSeen.Add(offset).UTC().Format(time.RFC3339),
			Category:   "created",
			ObjectName: "item-" + time.Duration(i).String(),
		})
	}

	got, truncated := filterAndCapRecentChanges(candidates, firstSeen)
	if len(got) != maxRecentChangeItems {
		t.Fatalf("got %d items, want exactly the cap (%d)", len(got), maxRecentChangeItems)
	}
	if !truncated {
		t.Error("truncated = false, want true — more candidates fell inside the window than the cap keeps")
	}
	// The kept items must be the ones closest to firstSeen, i.e. the LAST
	// maxRecentChangeItems of the input (already oldest-first).
	wantFirstKept := candidates[n-maxRecentChangeItems].Time
	if got[0].Time != wantFirstKept {
		t.Errorf("first kept item time = %q, want %q (the cap must drop the OLDEST entries, not arbitrary ones)", got[0].Time, wantFirstKept)
	}
	if got[len(got)-1].Time != candidates[n-1].Time {
		t.Errorf("last kept item time = %q, want the entry closest to firstSeen (%q)", got[len(got)-1].Time, candidates[n-1].Time)
	}
	// Still chronological.
	for i := 1; i < len(got); i++ {
		if got[i].Time < got[i-1].Time {
			t.Fatalf("result not chronological at index %d: %v", i, got)
		}
	}
}

func mustParseRFC3339(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return tm
}
