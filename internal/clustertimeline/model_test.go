package clustertimeline

import (
	"fmt"
	"testing"
	"time"
)

var (
	t0    = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	since = t0.Add(-24 * time.Hour)
	until = t0
)

func at(minAgo int) time.Time { return t0.Add(-time.Duration(minAgo) * time.Minute) }

func findRow(rows []Row, kind, name string) *Row {
	for i := range rows {
		if rows[i].Kind == kind && rows[i].Name == name {
			return &rows[i]
		}
	}
	return nil
}

// A Pod's change, a finding on that Pod, and its ReplicaSet's change all
// land on the Deployment's row, each mark still naming its own object.
func TestAssembleRollsUpToOwningWorkload(t *testing.T) {
	ow := owners{
		"shop/Pod/web-7d9-abc":    {Kind: "ReplicaSet", Name: "web-7d9"},
		"shop/ReplicaSet/web-7d9": {Kind: "Deployment", Name: "web"},
	}
	changes := []changeRec{
		{ID: "chg1", ObservedAt: at(30), Object: ObjectRef{Kind: "Pod", Namespace: "shop", Name: "web-7d9-abc"}, OwnerKind: "ReplicaSet", OwnerName: "web-7d9", Op: "update", Summary: "restartCount 0→3"},
		{ID: "chg2", ObservedAt: at(40), Object: ObjectRef{Kind: "Deployment", APIGroup: "apps", Namespace: "shop", Name: "web"}, Op: "update", Summary: "image web:1 → web:2"},
	}
	runs := []findingRun{{Fingerprint: "fp1", First: at(29), Last: at(5), Reports: 6, GVK: "v1/Pod", Namespace: "shop", ObjectName: "web-7d9-abc", Reason: "CrashLoopBackOff", Severity: "high", DetectorID: "k8s-warning-events"}}
	rows, total := assemble(since, until, ow, changes, runs, nil, false)
	if total != 1 || len(rows) != 1 {
		t.Fatalf("rows = %d (total %d), want the one Deployment row: %+v", len(rows), total, rows)
	}
	r := rows[0]
	if r.Kind != "Deployment" || r.Name != "web" || r.Namespace != "shop" || r.APIGroup != "apps" {
		t.Fatalf("row = %+v, want apps Deployment shop/web", r.ObjectRef)
	}
	if r.Counts.Changes != 2 || r.Counts.FindingRuns != 1 || r.Counts.FindingReports != 6 {
		t.Errorf("counts = %+v", r.Counts)
	}
	if len(r.Marks) != 3 || r.Marks[0].ID != "chg2" || r.Marks[2].Type != MarkFinding {
		t.Fatalf("marks not in time order: %+v", r.Marks)
	}
	if r.Marks[1].Object == nil || r.Marks[1].Object.Kind != "Pod" {
		t.Errorf("the Pod's change lost its own object: %+v", r.Marks[1])
	}
	if f := r.Marks[2]; f.Until == nil || !f.Until.Equal(at(5)) || f.Reports != 6 {
		t.Errorf("finding run = %+v", f)
	}
	if r.LastActivityAt == nil || !r.LastActivityAt.Equal(at(5)) {
		t.Errorf("last activity = %v, want the finding's last report", r.LastActivityAt)
	}
}

// Owners outside the workload set (a cluster-scoped catalogue object) do not
// swallow the object.
func TestAssembleDoesNotRollUpIntoNonWorkloadOwners(t *testing.T) {
	ow := owners{"cattle-system/ConfigMap/charts": {Kind: "ClusterRepo", Name: "rancher-charts"}}
	changes := []changeRec{{ID: "c", ObservedAt: at(1), Object: ObjectRef{Kind: "ConfigMap", Namespace: "cattle-system", Name: "charts"}, OwnerKind: "ClusterRepo", OwnerName: "rancher-charts", Op: "update"}}
	rows, _ := assemble(since, until, ow, changes, nil, nil, false)
	if findRow(rows, "ConfigMap", "charts") == nil {
		t.Fatalf("ConfigMap was rolled into a non-workload owner: %+v", rows)
	}
}

// An incident's workload_key groups its object's findings even when no
// change row recorded the Pod's owner, and the span/marks are right.
func TestAssembleIncidentSpansAndWorkloadKey(t *testing.T) {
	resolved := at(10)
	incidents := []incidentRec{
		{ID: "inc_open", Severity: "critical", State: "Detected", FirstSeen: at(120), LastSeen: at(2),
			ObjectKey: "v1/Pod|pay|api-5f-x", WorkloadKey: "apps/v1/Deployment|pay|api", OpeningReason: "OOMKilled"},
		{ID: "inc_done", Severity: "medium", State: "Resolved", Closed: true, FirstSeen: since.Add(-48 * time.Hour), LastSeen: at(11), ResolvedAt: &resolved,
			ObjectKey: "v1/Pod|pay|api-5f-y", WorkloadKey: "apps/v1/Deployment|pay|api", OpeningReason: "CrashLoopBackOff"},
		{ID: "inc_legacy", Severity: "low", State: "Dismissed", Closed: true, FirstSeen: at(300), LastSeen: at(200),
			ObjectKey: "v1/Node||node-1", OpeningReason: "NodeNotReady"},
	}
	runs := []findingRun{{Fingerprint: "fp", First: at(121), Last: at(2), Reports: 40, GVK: "v1/Pod", Namespace: "pay", ObjectName: "api-5f-x", Reason: "OOMKilled", Severity: "critical", IncidentID: "inc_open"}}
	rows, _ := assemble(since, until, owners{}, nil, runs, incidents, false)
	api := findRow(rows, "Deployment", "api")
	if api == nil {
		t.Fatalf("no Deployment row: %+v", rows)
	}
	if api.Counts.FindingRuns != 1 {
		t.Errorf("the Pod's finding did not land on its workload's row: %+v", rows)
	}
	if len(api.Spans) != 2 || api.Counts.Incidents != 2 {
		t.Fatalf("spans = %+v", api.Spans)
	}
	for _, s := range api.Spans {
		switch s.IncidentID {
		case "inc_open":
			if s.To != nil {
				t.Errorf("an open incident's span has an end: %+v", s)
			}
		case "inc_done":
			if s.To == nil || !s.To.Equal(resolved) || s.EndEstimated {
				t.Errorf("resolved span = %+v", s)
			}
		}
	}
	if api.Counts.IncidentsOpened != 1 || api.Counts.IncidentsClosed != 1 {
		t.Errorf("opened/closed = %+v (the resolved one opened before the window)", api.Counts)
	}
	node := findRow(rows, "Node", "node-1")
	if node == nil || len(node.Spans) != 1 || !node.Spans[0].EndEstimated || !node.Spans[0].To.Equal(at(200)) {
		t.Fatalf("a closed incident with no resolved_at must end at last_seen, flagged: %+v", node)
	}
	if node.Counts.IncidentsClosed != 0 {
		t.Error("an estimated end was drawn as a closing mark")
	}
	// Ranking: the Deployment (incident + activity at 2 min) before the Node.
	if rows[0].Name != "api" {
		t.Errorf("first row = %s", rows[0].Name)
	}
}

func TestAssembleRanksIncidentRowsFirstThenActivityThenQuiet(t *testing.T) {
	changes := []changeRec{{ID: "c", ObservedAt: at(1), Object: ObjectRef{Kind: "ConfigMap", Namespace: "a", Name: "busy"}, Op: "update"}}
	incidents := []incidentRec{
		{ID: "loud", Severity: "high", State: "Detected", FirstSeen: at(60), LastSeen: at(60), ObjectKey: "apps/v1/Deployment|a|loud"},
		{ID: "quiet", Severity: "high", State: "Detected", FirstSeen: since.Add(-time.Hour), LastSeen: since.Add(-time.Hour), ObjectKey: "apps/v1/Deployment|a|quiet"},
	}
	rows, _ := assemble(since, until, owners{}, changes, nil, incidents, false)
	got := []string{rows[0].Name, rows[1].Name, rows[2].Name}
	want := []string{"loud", "busy", "quiet"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("order = %v, want %v", got, want)
	}
	only, total := assemble(since, until, owners{}, changes, nil, incidents, true)
	if total != 2 || len(only) != 2 {
		t.Errorf("onlyIncidents kept %d rows (total %d), want the 2 with spans", len(only), total)
	}
}

func TestAssembleCapsRowsAndMarksHonestly(t *testing.T) {
	var changes []changeRec
	for i := 0; i < MaxRows+5; i++ {
		changes = append(changes, changeRec{ID: fmt.Sprint("r", i), ObservedAt: at(i + 1), Object: ObjectRef{Kind: "ConfigMap", Namespace: "n", Name: fmt.Sprint("cm-", i)}, Op: "update"})
	}
	rows, total := assemble(since, until, owners{}, changes, nil, nil, false)
	if total != MaxRows+5 || len(rows) != MaxRows {
		t.Fatalf("rows %d of %d", len(rows), total)
	}
}

// A row busier than MaxMarksPerRow is thinned across the WHOLE window, not
// cut to its newest events: every stretch that had a change keeps one, and
// the rest are counted on it.
func TestBusyRowIsThinnedAcrossTheWindow(t *testing.T) {
	var changes []changeRec
	n := 500
	for i := 0; i < n; i++ {
		// One change every ~2.9 minutes across the 24h window.
		changes = append(changes, changeRec{ID: fmt.Sprint("m", i), ObservedAt: until.Add(-time.Duration(i) * 24 * time.Hour / time.Duration(n)),
			Object: ObjectRef{Kind: "ConfigMap", Namespace: "n", Name: "busy"}, Op: "update"})
	}
	rows, _ := assemble(since, until, owners{}, changes, nil, nil, false)
	r := rows[0]
	if len(r.Marks) > MaxMarksPerRow || r.MarkBucketSeconds == 0 {
		t.Fatalf("marks %d bucket %ds", len(r.Marks), r.MarkBucketSeconds)
	}
	drawn := 0
	for _, m := range r.Marks {
		drawn += 1 + m.More
	}
	if drawn != n || r.MarksOmitted != n-len(r.Marks) || r.Counts.Changes != n {
		t.Errorf("drawn+more = %d, omitted = %d, count = %d; want %d / %d / %d", drawn, r.MarksOmitted, r.Counts.Changes, n, n-len(r.Marks), n)
	}
	if first := r.Marks[0].At; first.Sub(since) > time.Duration(r.MarkBucketSeconds)*time.Second {
		t.Errorf("earliest kept mark %v is not in the window's first stretch — the row was cut, not thinned", first)
	}
}

func TestObjectlessFindingsGetTheirOwnRow(t *testing.T) {
	runs := []findingRun{{Fingerprint: "fp", First: at(5), Last: at(5), Reports: 1, GVK: "v1/Node", Reason: "ClusterDNSDown", Severity: "high"}}
	rows, _ := assemble(since, until, owners{}, nil, runs, nil, false)
	if len(rows) != 1 || !rows[0].Objectless || rows[0].Name != "ClusterDNSDown" || rows[0].Marks[0].Object != nil {
		t.Fatalf("rows = %+v", rows)
	}
}

// One Node, one row, even when a source recorded a namespace for it.
func TestClusterScopedObjectsLoseAStrayNamespace(t *testing.T) {
	incidents := []incidentRec{
		{ID: "a", Severity: "medium", State: "Detected", FirstSeen: at(30), LastSeen: at(30), ObjectKey: "v1/Node|kube-system|cp-0"},
		{ID: "b", Severity: "medium", State: "Detected", FirstSeen: at(20), LastSeen: at(20), ObjectKey: "v1/Node||cp-0"},
	}
	rows, _ := assemble(since, until, owners{}, nil, nil, incidents, false)
	if len(rows) != 1 || rows[0].Namespace != "" || len(rows[0].Spans) != 2 {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestFindingRunGap(t *testing.T) {
	if FindingRunGap(time.Hour) != 45*time.Minute || FindingRunGap(7*24*time.Hour) != 3*time.Hour+30*time.Minute {
		t.Errorf("gap 1h=%v 7d=%v", FindingRunGap(time.Hour), FindingRunGap(7*24*time.Hour))
	}
}

func TestParseKey(t *testing.T) {
	o, ok := parseKey("apps/v1/Deployment|ns|web")
	if !ok || o != (ObjectRef{Kind: "Deployment", APIGroup: "apps", Namespace: "ns", Name: "web"}) {
		t.Errorf("got %+v", o)
	}
	if _, ok := parseKey("fingerprint-only"); ok {
		t.Error("parsed a non-key")
	}
}
