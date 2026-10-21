// Package clustertimeline builds the cluster timeline (PROJECT.md AD1): one
// cluster's recorded object changes, detector findings and incident
// openings/closings over one window, merged onto a single time axis, one row
// per object, rows grouped under the workload that owns them.
//
// It reads only what the hub already stores — resource_changes and
// resource_change_gaps (internal/resourcechanges), findings, incidents — and
// asks the agent nothing. Every query takes a transaction whose RLS scope the
// caller has already narrowed to this cluster (internal/api's
// authorizeClusterScoped); this package never widens scope.
//
// The file is split in two: this one is the wire shape plus the pure
// assembly (owner roll-up, row ranking, caps), testable without a database;
// query.go is the SQL.
package clustertimeline

import (
	"sort"
	"strings"
	"time"
)

// Mark types, the closed vocabulary of Mark.Type.
const (
	MarkChange         = "change"
	MarkFinding        = "finding"
	MarkIncidentOpened = "incident-opened"
	MarkIncidentClosed = "incident-closed"
)

// Source names, the closed vocabulary of ?types= and Restriction.Source.
const (
	SourceChanges   = "changes"
	SourceFindings  = "findings"
	SourceIncidents = "incidents"
)

// Caps. Each is stated in the response (Limits) and every cap that bites is
// reported as a count in Truncated or on the row, never silently.
const (
	MaxRows        = 60
	MaxMarksPerRow = 60
	MaxSpansPerRow = 8
	// Source caps: the newest rows of each source in the window. Far above
	// what one cluster records in a day today (measured 2026-10-11: ~700
	// changes and ~60 finding fingerprints a day on the busier test cluster),
	// so they bite only on a cluster that is genuinely churning, and then
	// the response says how many were left out.
	MaxChanges     = 5000
	MaxFindingRuns = 3000
	MaxIncidents   = 1000
	// MaxWindow bounds until-since. The UI offers 1h/6h/24h/7d; an hour of
	// slack lets a client compute "7 days ago" without tripping the bound.
	MaxWindow = 7*24*time.Hour + time.Hour
)

// FindingRunGap is how far apart two reports of one finding may be and
// still be drawn as one continuous run. Detectors re-send a persisting
// finding every few minutes (the agent's resend cooldown is 5 minutes and
// the sweep runs every ~13 minutes on the test clusters), so a finding with
// no gap longer than this was being reported the whole time; a longer
// silence starts a new run. Wider windows get a proportionally coarser gap
// so a 7-day view is not split by one missed sweep.
func FindingRunGap(window time.Duration) time.Duration {
	g := window / 48
	if g < 45*time.Minute {
		g = 45 * time.Minute
	}
	return g
}

// ObjectRef names one Kubernetes object.
type ObjectRef struct {
	Kind      string `json:"kind"`
	APIGroup  string `json:"apiGroup,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

func (o ObjectRef) key() string { return o.Namespace + "/" + o.Kind + "/" + o.Name }

// Mark is one point on a row.
type Mark struct {
	At   time.Time `json:"at"`
	Type string    `json:"type"`
	// Summary is one line saying what happened, taken from the stored row
	// (a change's summary, a finding's reason and message, an incident's
	// opening reason) — never composed by a model.
	Summary  string `json:"summary"`
	Severity string `json:"severity,omitempty"`
	// ID is the change id, the finding fingerprint, or the incident id.
	ID string `json:"id"`
	// Object is the object this mark is about — a Pod's change on a
	// Deployment's row names the Pod. Absent for a finding or incident that
	// named no object.
	Object     *ObjectRef `json:"object,omitempty"`
	IncidentID string     `json:"incidentId,omitempty"`
	// change only
	Op string `json:"op,omitempty"`
	// finding only: At is the first report of this run inside the window,
	// Until the last; Reports is how many times it was reported in between.
	// ContinuesFromBefore says it was also reported within FindingRunGap
	// before the window opened, so At is not when it started.
	Reason              string     `json:"reason,omitempty"`
	DetectorID          string     `json:"detectorId,omitempty"`
	Until               *time.Time `json:"until,omitempty"`
	Reports             int        `json:"reports,omitempty"`
	ContinuesFromBefore bool       `json:"continuesFromBefore,omitempty"`
	// incident marks only
	State string `json:"state,omitempty"`
	// More counts earlier events of the same type on this row, in the same
	// stretch of Row.MarkBucketSeconds, that are not drawn individually —
	// set only when the row had more events than MaxMarksPerRow.
	More int `json:"more,omitempty"`
}

// Span is one incident's open interval, clipped by nobody: From may precede
// the window and To is null while the incident is still open.
type Span struct {
	IncidentID string     `json:"incidentId"`
	From       time.Time  `json:"from"`
	To         *time.Time `json:"to"`
	// EndEstimated: a closed incident that carries no resolved_at (rows
	// closed before that column was stamped on every close) ends at its
	// last_seen, and says so.
	EndEstimated bool       `json:"endEstimated,omitempty"`
	Severity     string     `json:"severity"`
	State        string     `json:"state"`
	Summary      string     `json:"summary"`
	Object       *ObjectRef `json:"object,omitempty"`
}

// RowCounts are exact counts of everything on the row in the window,
// before MaxMarksPerRow/MaxSpansPerRow.
type RowCounts struct {
	Changes         int `json:"changes"`
	FindingRuns     int `json:"findingRuns"`
	FindingReports  int `json:"findingReports"`
	Incidents       int `json:"incidents"`
	IncidentsOpened int `json:"incidentsOpened"`
	IncidentsClosed int `json:"incidentsClosed"`
}

// Row is one object — the owning workload when one was resolved.
type Row struct {
	Key string `json:"key"`
	ObjectRef
	// Objectless rows hold findings/incidents that named no object; Name is
	// then the reason, and there is nothing to open.
	Objectless   bool      `json:"objectless,omitempty"`
	Marks        []Mark    `json:"marks"`
	Spans        []Span    `json:"spans"`
	Counts       RowCounts `json:"counts"`
	MarksOmitted int       `json:"marksOmitted"`
	// MarkBucketSeconds is the stretch a busy row's marks were thinned over
	// (see Mark.More); zero when every event is drawn.
	MarkBucketSeconds int        `json:"markBucketSeconds"`
	SpansOmitted      int        `json:"spansOmitted"`
	LastActivityAt    *time.Time `json:"lastActivityAt"`

	tier int
	open bool
}

// Gap is a window in which the agent lost change records.
type Gap struct {
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	Reason string    `json:"reason"`
}

// Restriction names a source left out because the caller lacks the
// capability that reads it.
type Restriction struct {
	Source     string `json:"source"`
	Capability string `json:"capability"`
}

// Totals are exact, over the whole window and filter, never the page.
type Totals struct {
	Rows           int `json:"rows"`
	Changes        int `json:"changes"`
	FindingRuns    int `json:"findingRuns"`
	FindingReports int `json:"findingReports"`
	Incidents      int `json:"incidents"`
	// IncidentsOpened is how many of Incidents opened inside the window; the
	// rest were already open when it began. Both exact, so the two add up to
	// Incidents whatever the row cap drew.
	IncidentsOpened int `json:"incidentsOpened"`
}

// Truncated counts what a source cap or the row cap left out. Zero means
// nothing was.
type Truncated struct {
	Rows        int `json:"rows"`
	Changes     int `json:"changes"`
	FindingRuns int `json:"findingRuns"`
	Incidents   int `json:"incidents"`
}

// Limits echoes the caps so a client never hardcodes them.
type Limits struct {
	MaxRows        int `json:"maxRows"`
	MaxMarksPerRow int `json:"maxMarksPerRow"`
	MaxSpansPerRow int `json:"maxSpansPerRow"`
}

// Response is GET /api/v1/clusters/{id}/timeline.
type Response struct {
	ClusterID            string        `json:"clusterId"`
	Since                time.Time     `json:"since"`
	Until                time.Time     `json:"until"`
	Namespace            string        `json:"namespace,omitempty"`
	Types                []string      `json:"types"`
	OnlyIncidents        bool          `json:"onlyIncidents"`
	Rows                 []Row         `json:"rows"`
	Gaps                 []Gap         `json:"gaps"`
	Namespaces           []string      `json:"namespaces"`
	Totals               Totals        `json:"totals"`
	Truncated            Truncated     `json:"truncated"`
	Limits               Limits        `json:"limits"`
	FindingRunGapSeconds int           `json:"findingRunGapSeconds"`
	Restricted           []Restriction `json:"restricted"`
}

// ---------------------------------------------------------------- inputs

// changeRec, findingRun and incidentRec are what query.go reads.
type changeRec struct {
	ID         string
	ObservedAt time.Time
	Object     ObjectRef
	OwnerKind  string
	OwnerName  string
	Op         string
	Summary    string
}

type findingRun struct {
	Fingerprint         string
	First, Last         time.Time
	Reports             int
	GVK                 string
	Namespace           string
	ObjectName          string
	Reason              string
	Message             string
	Severity            string
	DetectorID          string
	IncidentID          string
	ContinuesFromBefore bool
}

type incidentRec struct {
	ID            string
	Severity      string
	State         string
	Closed        bool
	FirstSeen     time.Time
	LastSeen      time.Time
	ResolvedAt    *time.Time
	ObjectKey     string
	WorkloadKey   string
	OpeningReason string
	Fingerprint   string
}

// owners maps an object to its controlling owner, as recorded on its
// change rows (ownerReferences, the controller one first).
type owners map[string]ObjectRef

// workloadKinds are the owners a row rolls up into: namespaced controllers
// whose children are created from them. Anything else an ownerReference
// names (an Argo Application, a Rancher ClusterRepo, a cluster-scoped
// owner) keeps the object as its own row — grouping a ConfigMap under a
// cluster-scoped catalogue object would be a row nobody could open.
var workloadKinds = map[string]string{
	"Deployment":            "apps",
	"ReplicaSet":            "apps",
	"StatefulSet":           "apps",
	"DaemonSet":             "apps",
	"Job":                   "batch",
	"CronJob":               "batch",
	"ReplicationController": "",
}

// knownGroups fills an API group where a source named only the kind (an
// ownerReference carries apiVersion, but the agent records the kind alone).
var knownGroups = map[string]string{
	"Pod": "", "Service": "", "ConfigMap": "", "PersistentVolumeClaim": "", "Node": "",
	"Ingress": "networking.k8s.io", "HorizontalPodAutoscaler": "autoscaling",
}

// clusterScoped kinds have no namespace. A source occasionally records one
// anyway (a Node incident keyed under the namespace of the event that
// reported it), which would split one Node into two rows and break the link
// to it; the namespace is dropped for these kinds wherever an object is named.
var clusterScoped = map[string]bool{
	"Node": true, "Namespace": true, "PersistentVolume": true, "ClusterRole": true, "ClusterRoleBinding": true,
	"StorageClass": true, "CustomResourceDefinition": true, "MutatingWebhookConfiguration": true,
	"ValidatingWebhookConfiguration": true, "PriorityClass": true, "IngressClass": true, "GatewayClass": true,
	"APIService": true, "CSIDriver": true, "RuntimeClass": true, "VolumeAttachment": true, "ClusterIssuer": true,
}

func normalize(o ObjectRef) ObjectRef {
	if clusterScoped[o.Kind] {
		o.Namespace = ""
	}
	return o
}

func groupFor(kind string) string {
	if g, ok := workloadKinds[kind]; ok {
		return g
	}
	return knownGroups[kind]
}

// parseGVK splits "apps/v1/Deployment" or "v1/Pod" into group and kind.
func parseGVK(gvk string) (group, kind string) {
	parts := strings.Split(gvk, "/")
	kind = parts[len(parts)-1]
	if len(parts) == 3 {
		group = parts[0]
	}
	return group, kind
}

// parseKey reads a "gvk|namespace|name" correlation key
// (internal/gateway's objectCorrelationKey / workloadCorrelationKey).
func parseKey(k string) (ObjectRef, bool) {
	parts := strings.SplitN(k, "|", 3)
	if len(parts) != 3 || parts[2] == "" {
		return ObjectRef{}, false
	}
	g, kind := parseGVK(parts[0])
	if kind == "" {
		return ObjectRef{}, false
	}
	return normalize(ObjectRef{Kind: kind, APIGroup: g, Namespace: parts[1], Name: parts[2]}), true
}

// root walks o's owner chain through workload kinds only, at most six hops
// (Pod → ReplicaSet → Deployment is two; a cycle cannot loop forever).
func (ow owners) root(o ObjectRef) ObjectRef {
	cur := o
	for i := 0; i < 6; i++ {
		next, ok := ow[cur.key()]
		if !ok || next.Name == "" {
			break
		}
		if _, isWorkload := workloadKinds[next.Kind]; !isWorkload {
			break
		}
		next.Namespace = cur.Namespace
		if next.APIGroup == "" {
			next.APIGroup = groupFor(next.Kind)
		}
		cur = next
	}
	return cur
}

// ---------------------------------------------------------------- assembly

type assembler struct {
	since, until time.Time
	ow           owners
	rows         map[string]*Row
}

func (a *assembler) row(o ObjectRef) *Row {
	r := a.root(normalize(o))
	k := r.key()
	if row, ok := a.rows[k]; ok {
		return row
	}
	row := &Row{Key: k, ObjectRef: r, Marks: []Mark{}, Spans: []Span{}}
	a.rows[k] = row
	return row
}

func (a *assembler) root(o ObjectRef) ObjectRef {
	r := a.ow.root(o)
	if r.APIGroup == "" {
		r.APIGroup = groupFor(r.Kind)
	}
	return r
}

func (a *assembler) objectlessRow(label string) *Row {
	k := "objectless/" + label
	if row, ok := a.rows[k]; ok {
		return row
	}
	row := &Row{Key: k, ObjectRef: ObjectRef{Name: label}, Objectless: true, Marks: []Mark{}, Spans: []Span{}}
	a.rows[k] = row
	return row
}

func (a *assembler) inWindow(t time.Time) bool { return !t.Before(a.since) && !t.After(a.until) }

func touch(r *Row, t time.Time) {
	if r.LastActivityAt == nil || t.After(*r.LastActivityAt) {
		tt := t
		r.LastActivityAt = &tt
	}
}

func ptr(o ObjectRef) *ObjectRef { return &o }

func (a *assembler) addChange(c changeRec) {
	r := a.row(c.Object)
	r.Counts.Changes++
	touch(r, c.ObservedAt)
	r.Marks = append(r.Marks, Mark{
		At: c.ObservedAt, Type: MarkChange, ID: c.ID, Op: c.Op,
		Summary: changeSummary(c), Object: ptr(c.Object),
	})
}

func changeSummary(c changeRec) string {
	s := strings.TrimSpace(c.Summary)
	switch c.Op {
	case "add":
		if s == "" || s == "created" {
			return "created"
		}
		return "created — " + s
	case "delete":
		return "deleted"
	}
	if s == "" {
		return "changed"
	}
	return s
}

func (a *assembler) addFinding(f findingRun, incidentObject map[string]ObjectRef) {
	var r *Row
	var obj *ObjectRef
	if f.ObjectName != "" {
		g, kind := parseGVK(f.GVK)
		o := normalize(ObjectRef{Kind: kind, APIGroup: g, Namespace: f.Namespace, Name: f.ObjectName})
		obj = &o
		// A correlated finding goes where its incident's workload is, when
		// the incident resolved one and the change history could not.
		if w, ok := incidentObject[f.IncidentID]; ok && a.ow.root(o) == o && w.key() != o.key() {
			r = a.row(w)
		} else {
			r = a.row(o)
		}
	} else {
		r = a.objectlessRow(f.Reason)
	}
	r.Counts.FindingRuns++
	r.Counts.FindingReports += f.Reports
	touch(r, f.Last)
	summary := f.Reason
	if m := strings.TrimSpace(f.Message); m != "" {
		summary += ": " + m
	}
	last := f.Last
	r.Marks = append(r.Marks, Mark{
		At: f.First, Type: MarkFinding, ID: f.Fingerprint, Summary: summary, Severity: f.Severity,
		Object: obj, IncidentID: f.IncidentID, Reason: f.Reason, DetectorID: f.DetectorID,
		Until: &last, Reports: f.Reports, ContinuesFromBefore: f.ContinuesFromBefore,
	})
}

func (a *assembler) addIncident(i incidentRec) {
	obj, hasObj := parseKey(i.ObjectKey)
	work, hasWork := parseKey(i.WorkloadKey)
	var r *Row
	var subject *ObjectRef
	switch {
	case hasWork:
		r = a.row(work)
		if hasObj {
			subject = ptr(obj)
		} else {
			subject = ptr(work)
		}
	case hasObj:
		r = a.row(obj)
		subject = ptr(obj)
	default:
		label := i.OpeningReason
		if label == "" {
			label = i.Fingerprint
		}
		r = a.objectlessRow(label)
	}
	summary := i.OpeningReason
	if summary == "" {
		summary = "incident"
	}
	r.open = r.open || !i.Closed
	r.Counts.Incidents++
	span := Span{IncidentID: i.ID, From: i.FirstSeen, Severity: i.Severity, State: i.State, Summary: summary, Object: subject}
	if i.Closed {
		end := i.LastSeen
		if i.ResolvedAt != nil {
			end = *i.ResolvedAt
		} else {
			span.EndEstimated = true
		}
		span.To = &end
	}
	r.Spans = append(r.Spans, span)

	activity := false
	if a.inWindow(i.FirstSeen) {
		r.Counts.IncidentsOpened++
		touch(r, i.FirstSeen)
		activity = true
		r.Marks = append(r.Marks, Mark{At: i.FirstSeen, Type: MarkIncidentOpened, ID: i.ID, IncidentID: i.ID,
			Severity: i.Severity, State: i.State, Summary: "opened: " + summary, Object: subject})
	}
	if span.To != nil && !span.EndEstimated && a.inWindow(*span.To) {
		r.Counts.IncidentsClosed++
		touch(r, *span.To)
		activity = true
		r.Marks = append(r.Marks, Mark{At: *span.To, Type: MarkIncidentClosed, ID: i.ID, IncidentID: i.ID,
			Severity: i.Severity, State: i.State, Summary: strings.ToLower(i.State) + ": " + summary, Object: subject})
	}
	if !activity && a.inWindow(i.LastSeen) {
		// Still recurring inside the window: activity, though not a mark
		// of its own (the recurring finding is the mark).
		touch(r, i.LastSeen)
	}
}

// finish ranks, caps and orders. Tiers: a row carrying an incident span with
// activity in the window first, then any other row with activity, then rows
// that only carry an incident that was quiet the whole window. Inside a
// tier, the most recent activity first.
func (a *assembler) finish(onlyIncidents bool) ([]Row, int) {
	all := make([]*Row, 0, len(a.rows))
	for _, r := range a.rows {
		if onlyIncidents && len(r.Spans) == 0 {
			continue
		}
		switch {
		case len(r.Spans) > 0 && r.LastActivityAt != nil:
			r.tier = 0
		case r.LastActivityAt != nil:
			r.tier = 1
		default:
			r.tier = 2
		}
		all = append(all, r)
	}
	sort.SliceStable(all, func(i, j int) bool {
		x, y := all[i], all[j]
		if x.tier != y.tier {
			return x.tier < y.tier
		}
		xt, yt := activityOrZero(x), activityOrZero(y)
		if !xt.Equal(yt) {
			return xt.After(yt)
		}
		return x.Key < y.Key
	})
	total := len(all)
	if len(all) > MaxRows {
		all = all[:MaxRows]
	}
	out := make([]Row, 0, len(all))
	for _, r := range all {
		capRow(r, a.since, a.until)
		out = append(out, *r)
	}
	return out, total
}

func activityOrZero(r *Row) time.Time {
	if r.LastActivityAt != nil {
		return *r.LastActivityAt
	}
	// Quiet incident rows rank among themselves by their latest span start.
	var t time.Time
	for _, s := range r.Spans {
		if s.From.After(t) {
			t = s.From
		}
	}
	return t
}

// capRow keeps every incident mark that belongs to a kept span. When the
// rest do not fit MaxMarksPerRow it thins them across the whole window —
// the newest change and the newest finding in each equal stretch, the others
// counted on it as More — so a busy row still shows WHEN it was busy rather
// than only its last hour. Kept marks are ordered by time.
func capRow(r *Row, since, until time.Time) {
	// Spans: open ones first, then the most recently started.
	sort.SliceStable(r.Spans, func(i, j int) bool {
		oi, oj := r.Spans[i].To == nil, r.Spans[j].To == nil
		if oi != oj {
			return oi
		}
		return r.Spans[i].From.After(r.Spans[j].From)
	})
	keptSpan := map[string]bool{}
	if len(r.Spans) > MaxSpansPerRow {
		r.SpansOmitted = len(r.Spans) - MaxSpansPerRow
		r.Spans = r.Spans[:MaxSpansPerRow]
	}
	for _, s := range r.Spans {
		keptSpan[s.IncidentID] = true
	}
	sort.SliceStable(r.Spans, func(i, j int) bool { return r.Spans[i].From.Before(r.Spans[j].From) })

	sort.SliceStable(r.Marks, func(i, j int) bool {
		pi, pj := markPriority(r.Marks[i], keptSpan), markPriority(r.Marks[j], keptSpan)
		if pi != pj {
			return pi < pj
		}
		return markEnd(r.Marks[i]).After(markEnd(r.Marks[j]))
	})
	if len(r.Marks) > MaxMarksPerRow {
		r.Marks = thin(r.Marks, keptSpan, since, until, r)
	}
	if len(r.Marks) > MaxMarksPerRow {
		// Only reachable with more kept incident marks than the cap allows.
		r.MarksOmitted += len(r.Marks) - MaxMarksPerRow
		r.Marks = r.Marks[:MaxMarksPerRow]
	}
	sort.SliceStable(r.Marks, func(i, j int) bool { return r.Marks[i].At.Before(r.Marks[j].At) })
}

// thin keeps the priority marks and, for the rest, the newest mark per
// (stretch, type), counting the others onto it. marks arrive priority-first,
// then newest-first.
func thin(marks []Mark, keptSpan map[string]bool, since, until time.Time, r *Row) []Mark {
	var keep, rest []Mark
	for _, m := range marks {
		if markPriority(m, keptSpan) == 0 {
			keep = append(keep, m)
		} else {
			rest = append(rest, m)
		}
	}
	buckets := (MaxMarksPerRow - len(keep)) / 2
	if buckets < 4 {
		buckets = 4
	}
	width := until.Sub(since) / time.Duration(buckets)
	if width <= 0 {
		return marks
	}
	r.MarkBucketSeconds = int(width.Seconds())
	type slot struct {
		b   int
		typ string
	}
	idx := map[slot]int{}
	for _, m := range rest {
		b := int(m.At.Sub(since) / width)
		if b < 0 {
			b = 0
		}
		k := slot{b, m.Type}
		if i, ok := idx[k]; ok {
			keep[i].More++
			r.MarksOmitted++
			continue
		}
		idx[k] = len(keep)
		keep = append(keep, m)
	}
	return keep
}

func markPriority(m Mark, keptSpan map[string]bool) int {
	if (m.Type == MarkIncidentOpened || m.Type == MarkIncidentClosed) && keptSpan[m.IncidentID] {
		return 0
	}
	return 1
}

func markEnd(m Mark) time.Time {
	if m.Until != nil {
		return *m.Until
	}
	return m.At
}

// assemble is the pure half: everything query.go read, merged into rows.
func assemble(since, until time.Time, ow owners, changes []changeRec, runs []findingRun, incidents []incidentRec, onlyIncidents bool) ([]Row, int) {
	rows, total, _ := assembleWithTotals(since, until, ow, changes, runs, incidents, onlyIncidents)
	return rows, total
}

// assembleWithTotals also sums the exact counts of every row the filter
// kept, before the row cap.
func assembleWithTotals(since, until time.Time, ow owners, changes []changeRec, runs []findingRun, incidents []incidentRec, onlyIncidents bool) ([]Row, int, RowCounts) {
	a := &assembler{since: since, until: until, ow: ow, rows: map[string]*Row{}}
	incidentObject := map[string]ObjectRef{}
	for _, i := range incidents {
		if w, ok := parseKey(i.WorkloadKey); ok {
			incidentObject[i.ID] = w
		}
	}
	// The incident's own workload_key is what the agent resolved for that
	// object; teach the owner map, so the same Pod's changes and findings
	// land on the same row even when no change row recorded its owner.
	for _, i := range incidents {
		obj, okO := parseKey(i.ObjectKey)
		w, okW := parseKey(i.WorkloadKey)
		if okO && okW && obj.key() != w.key() {
			if _, known := ow[obj.key()]; !known {
				ow[obj.key()] = ObjectRef{Kind: w.Kind, APIGroup: w.APIGroup, Name: w.Name}
			}
		}
	}
	for _, c := range changes {
		a.addChange(c)
	}
	for _, f := range runs {
		a.addFinding(f, incidentObject)
	}
	for _, i := range incidents {
		a.addIncident(i)
	}
	var sum RowCounts
	for _, r := range a.rows {
		if onlyIncidents && len(r.Spans) == 0 {
			continue
		}
		sum.Changes += r.Counts.Changes
		sum.FindingRuns += r.Counts.FindingRuns
		sum.FindingReports += r.Counts.FindingReports
	}
	rows, total := a.finish(onlyIncidents)
	return rows, total, sum
}
