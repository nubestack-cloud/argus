package clustertimeline

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
)

// PROJECT.md AD1 against a real Postgres. Run with ARGUS_TEST_DATABASE_URL
// pointed at the argus_app role (not a superuser: postgres bypasses RLS and
// the cross-cluster assertion below would pass vacuously).

type timelineFixture struct {
	tenantID, cluster, other string
	now                      time.Time
}

func timelineTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	conn := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if conn == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping the cluster timeline DB test")
	}
	pool, err := pgxpool.New(context.Background(), conn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// The fixture, on one throwaway cluster ("shop" namespace unless noted):
//
//	Deployment web ← ReplicaSet web-7d9 ← Pod web-7d9-abc
//	  - an image change on the Deployment 50 min ago
//	  - the ReplicaSet created 50 min ago (its owner row says Deployment web)
//	  - the Pod's restart change 20 min ago; its owner ReplicaSet is known
//	    only from the ReplicaSet's own change row 3 days ago — the owner
//	    lookup has to reach outside the window for it
//	  - a CrashLoopBackOff finding on the Pod every 5 min from 30 min ago,
//	    and the same fingerprint 2h ago then silent (a separate, earlier
//	    run) — inside a 6h window that is two runs
//	  - an open critical incident on the Pod opened 25 min ago, with no
//	    workload_key (so grouping must come from the change history)
//	ConfigMap settings in namespace "ops": one change 10 min ago
//	A Resolved incident on Node node-1 (cluster-scoped) opened 3h ago,
//	closed 2h ago
//	A change gap 40–35 min ago
//	A second cluster with its own change and finding, which must not appear.
func newTimelineFixture(t *testing.T, pool *pgxpool.Pool) timelineFixture {
	t.Helper()
	ctx := context.Background()
	f := timelineFixture{cluster: domain.NewID(domain.PrefixCluster), other: domain.NewID(domain.PrefixCluster), now: time.Now().UTC().Truncate(time.Second)}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if f.tenantID, err = data.SingleOrganisationID(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.cluster, f.other}); err != nil {
		t.Fatal(err)
	}
	fx, fxOther := dbtest.New(t), dbtest.New(t)
	for c, x := range map[string]*dbtest.Fixture{f.cluster: fx, f.other: fxOther} {
		if _, err := tx.Exec(ctx, `INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
			VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`, c, f.tenantID, "timeline-test-"+c, "fp-"+c); err != nil {
			t.Fatal(err)
		}
		x.Created("clusters", 1)
		x.OwnsCluster(f.tenantID, c)
	}
	ago := func(d time.Duration) time.Time { return f.now.Add(-d) }

	change := func(x *dbtest.Fixture, cluster string, when time.Time, kind, group, ns, name, ownerKind, ownerName, op, summary string) {
		if _, err := tx.Exec(ctx, `INSERT INTO resource_changes (id, tenant_id, cluster_id, observed_at, kind, api_group, namespace, name, owner_kind, owner_name, op, summary)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, domain.NewID(domain.PrefixResourceChange), f.tenantID, cluster, when,
			kind, group, ns, name, ownerKind, ownerName, op, summary); err != nil {
			t.Fatal(err)
		}
		x.Created("resource_changes", 1)
	}
	change(fx, f.cluster, ago(3*24*time.Hour), "ReplicaSet", "apps", "shop", "web-7d9", "Deployment", "web", "add", "created")
	change(fx, f.cluster, ago(50*time.Minute), "Deployment", "apps", "shop", "web", "", "", "update", "image web:1 → web:2")
	change(fx, f.cluster, ago(50*time.Minute), "ReplicaSet", "apps", "shop", "web-8aa", "Deployment", "web", "add", "created")
	change(fx, f.cluster, ago(20*time.Minute), "Pod", "", "shop", "web-7d9-abc", "ReplicaSet", "web-7d9", "update", "restartCount 2 → 3")
	change(fx, f.cluster, ago(10*time.Minute), "ConfigMap", "", "ops", "settings", "", "", "update", "data.mode changed")
	change(fxOther, f.other, ago(5*time.Minute), "ConfigMap", "", "shop", "leak", "", "", "update", "must not appear")

	finding := func(x *dbtest.Fixture, cluster string, when time.Time, fp, gvk, ns, name, reason, sev string) {
		if _, err := tx.Exec(ctx, `INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint,
			gvk, namespace, object_name, reason, message, severity, occurred_at, signal_class, confidence, impact)
			VALUES ($1,$2,$3,'k8s-warning-events','v1',$4,$5,$6,$7,$8,'Back-off restarting failed container',$9,$10,'fault','verified','degraded')`,
			domain.NewID(domain.PrefixFinding), f.tenantID, cluster, fp, gvk, ns, name, reason, sev, when); err != nil {
			t.Fatal(err)
		}
		x.Created("findings", 1)
	}
	fp := "fp-crash-" + f.cluster
	for m := 30; m >= 0; m -= 5 {
		finding(fx, f.cluster, ago(time.Duration(m)*time.Minute), fp, "v1/Pod", "shop", "web-7d9-abc", "CrashLoopBackOff", "high")
	}
	finding(fx, f.cluster, ago(2*time.Hour), fp, "v1/Pod", "shop", "web-7d9-abc", "CrashLoopBackOff", "high")
	finding(fxOther, f.other, ago(5*time.Minute), "fp-other", "v1/Pod", "shop", "leak", "OOMKilled", "high")

	incident := func(when time.Time, state, sev string, resolved *time.Time, objectKey, reason string) {
		if _, err := tx.Exec(ctx, `INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen,
			occurrence_count, opening_reason, object_key, resolved_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$7,1,$8,$9,$10)`,
			domain.NewID(domain.PrefixIncident), f.tenantID, f.cluster, "fp-inc-"+reason, sev, state, when, reason, objectKey, resolved); err != nil {
			t.Fatal(err)
		}
		fx.Created("incidents", 1)
	}
	incident(ago(25*time.Minute), "Detected", "critical", nil, "v1/Pod|shop|web-7d9-abc", "CrashLoopBackOff")
	closedAt := ago(2 * time.Hour)
	incident(ago(3*time.Hour), "Resolved", "medium", &closedAt, "v1/Node||node-1", "NodeNotReady")

	if _, err := tx.Exec(ctx, `INSERT INTO resource_change_gaps (id, tenant_id, cluster_id, gap_from, gap_to, reason) VALUES ($1,$2,$3,$4,$5,'agent buffer overflow')`,
		domain.NewID(domain.PrefixResourceChangeGap), f.tenantID, f.cluster, ago(40*time.Minute), ago(35*time.Minute)); err != nil {
		t.Fatal(err)
	}
	fx.Created("resource_change_gaps", 1)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	scope := func(c string) func(context.Context, pgx.Tx) error {
		return func(ctx context.Context, tx pgx.Tx) error {
			return data.SetRequestScope(ctx, tx, f.tenantID, []string{c})
		}
	}
	fx.Cleanup(pool, scope(f.cluster), []dbtest.TableDelete{
		{Table: "resource_changes", SQL: `DELETE FROM resource_changes WHERE cluster_id = $1`, Args: []any{f.cluster}},
		{Table: "resource_change_gaps", SQL: `DELETE FROM resource_change_gaps WHERE cluster_id = $1`, Args: []any{f.cluster}},
		{Table: "findings", SQL: `DELETE FROM findings WHERE cluster_id = $1`, Args: []any{f.cluster}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{f.cluster}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{f.cluster}},
	})
	fxOther.Cleanup(pool, scope(f.other), []dbtest.TableDelete{
		{Table: "resource_changes", SQL: `DELETE FROM resource_changes WHERE cluster_id = $1`, Args: []any{f.other}},
		{Table: "findings", SQL: `DELETE FROM findings WHERE cluster_id = $1`, Args: []any{f.other}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{f.other}},
	})
	return f
}

func allSources() map[string]bool {
	return map[string]bool{SourceChanges: true, SourceFindings: true, SourceIncidents: true}
}

// build runs Build as the request path does: a transaction scoped to the
// accessible clusters, here possibly BOTH, so the cluster_id predicates —
// not RLS alone — must keep the other cluster out.
func build(t *testing.T, pool *pgxpool.Pool, f timelineFixture, accessible []string, q Query) Response {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, f.tenantID, accessible); err != nil {
		t.Fatal(err)
	}
	resp, err := Build(ctx, tx, q)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return resp
}

func TestBuildMergesTheThreeSourcesByOwningWorkload(t *testing.T) {
	pool := timelineTestPool(t)
	f := newTimelineFixture(t, pool)
	resp := build(t, pool, f, []string{f.cluster, f.other}, Query{
		ClusterID: f.cluster, Since: f.now.Add(-6 * time.Hour), Until: f.now.Add(time.Second), Sources: allSources(),
	})

	if resp.Totals.Changes != 4 || resp.Truncated.Changes != 0 {
		t.Errorf("changes total = %d (truncated %d), want the 4 in-window changes on this cluster", resp.Totals.Changes, resp.Truncated.Changes)
	}
	if resp.Totals.FindingRuns != 2 || resp.Totals.FindingReports != 8 {
		t.Errorf("finding runs = %d reports = %d, want 2 runs from 8 reports", resp.Totals.FindingRuns, resp.Totals.FindingReports)
	}
	if resp.Totals.Incidents != 2 || resp.Totals.IncidentsOpened != 2 {
		t.Errorf("incidents = %d (opened in window %d), want 2 (2)", resp.Totals.Incidents, resp.Totals.IncidentsOpened)
	}
	// A narrower window: the Node incident opened before it began (and closed
	// inside it), so it counts as open in the window but not opened in it.
	narrow := build(t, pool, f, []string{f.cluster, f.other}, Query{
		ClusterID: f.cluster, Since: f.now.Add(-150 * time.Minute), Until: f.now.Add(time.Second), Sources: allSources(),
	})
	if narrow.Totals.Incidents != 2 || narrow.Totals.IncidentsOpened != 1 {
		t.Errorf("narrow window: incidents = %d, opened in it = %d; want 2 and 1", narrow.Totals.Incidents, narrow.Totals.IncidentsOpened)
	}
	if len(resp.Gaps) != 1 || resp.Gaps[0].Reason != "agent buffer overflow" {
		t.Errorf("gaps = %+v", resp.Gaps)
	}
	if strings.Join(resp.Namespaces, ",") != "ops,shop" {
		t.Errorf("namespaces = %v, want [ops shop]", resp.Namespaces)
	}
	for _, r := range resp.Rows {
		if r.Name == "leak" {
			t.Fatal("another cluster's row is on this cluster's timeline")
		}
	}

	web := findRow(resp.Rows, "Deployment", "web")
	if web == nil {
		t.Fatalf("no Deployment web row: %+v", resp.Rows)
	}
	if web.Counts.Changes != 3 || web.Counts.FindingRuns != 2 || web.Counts.Incidents != 1 || web.Counts.IncidentsOpened != 1 {
		t.Errorf("web counts = %+v — the Pod's change, findings and incident should all roll up to the Deployment", web.Counts)
	}
	if len(web.Spans) != 1 || web.Spans[0].To != nil || web.Spans[0].Severity != "critical" {
		t.Errorf("web spans = %+v", web.Spans)
	}
	if resp.Rows[0].Name != "web" {
		t.Errorf("first row = %s, want the row with an open incident and recent activity", resp.Rows[0].Name)
	}
	var runs []Mark
	for _, m := range web.Marks {
		if m.Type == MarkFinding {
			runs = append(runs, m)
		}
	}
	if len(runs) != 2 || runs[0].Reports != 1 || runs[1].Reports != 7 || runs[1].Severity != "high" {
		t.Errorf("finding runs = %+v", runs)
	}
	if runs[1].Object == nil || runs[1].Object.Kind != "Pod" {
		t.Errorf("finding mark lost its Pod: %+v", runs[1].Object)
	}

	node := findRow(resp.Rows, "Node", "node-1")
	if node == nil || len(node.Spans) != 1 || node.Spans[0].To == nil || node.Counts.IncidentsClosed != 1 || node.Counts.IncidentsOpened != 1 {
		t.Errorf("node row = %+v", node)
	}
}

func TestBuildFiltersInSQL(t *testing.T) {
	pool := timelineTestPool(t)
	f := newTimelineFixture(t, pool)
	window := Query{ClusterID: f.cluster, Since: f.now.Add(-time.Hour), Until: f.now.Add(time.Second)}

	q := window
	q.Sources, q.Namespace = allSources(), "ops"
	resp := build(t, pool, f, []string{f.cluster}, q)
	if len(resp.Rows) != 1 || resp.Rows[0].Name != "settings" || resp.Totals.Changes != 1 {
		t.Errorf("namespace=ops rows = %+v", resp.Rows)
	}
	if strings.Join(resp.Namespaces, ",") != "ops,shop" {
		t.Errorf("the namespace list must ignore the namespace filter: %v", resp.Namespaces)
	}

	q = window
	q.Sources = map[string]bool{SourceFindings: true}
	resp = build(t, pool, f, []string{f.cluster}, q)
	if resp.Totals.Changes != 0 || len(resp.Gaps) != 0 || len(resp.Rows) != 1 || resp.Rows[0].Counts.Changes != 0 {
		t.Errorf("types=findings still carried changes: %+v", resp)
	}
	// In a 1h window the run that started before it continues from before.
	if m := resp.Rows[0].Marks; len(m) != 1 || m[0].ContinuesFromBefore {
		// The 2h-ago report is outside the 45-minute run gap of a 1h
		// window, so this run did start inside it.
		t.Errorf("finding marks = %+v", m)
	}

	q = window
	q.Sources, q.OnlyIncidents = allSources(), true
	resp = build(t, pool, f, []string{f.cluster}, q)
	if len(resp.Rows) != 1 || resp.Rows[0].Name != "web" || resp.Truncated.Rows != 0 {
		t.Errorf("onlyIncidents rows = %+v", resp.Rows)
	}
	// The totals count only what the filter kept: web's three in-window
	// changes and its one finding run, not the ops ConfigMap's change.
	if resp.Totals.Changes != 3 || resp.Totals.FindingRuns != 1 || resp.Totals.FindingReports != 7 {
		t.Errorf("onlyIncidents totals = %+v", resp.Totals)
	}
}

func TestFindingRunContinuesFromBeforeTheWindow(t *testing.T) {
	pool := timelineTestPool(t)
	f := newTimelineFixture(t, pool)
	// A window opening 12 minutes ago: the run was being reported at 15 and
	// 20 minutes ago, within the run gap before the window.
	resp := build(t, pool, f, []string{f.cluster}, Query{ClusterID: f.cluster, Since: f.now.Add(-12 * time.Minute), Until: f.now.Add(time.Second),
		Sources: map[string]bool{SourceFindings: true}})
	if len(resp.Rows) != 1 || len(resp.Rows[0].Marks) != 1 || !resp.Rows[0].Marks[0].ContinuesFromBefore {
		t.Fatalf("rows = %+v", resp.Rows)
	}
}

// The finding query must seek on findings_cluster_occurred_idx (migration
// 000129), not scan every cluster's findings in the window.
func TestFindingRunQueryUsesTheClusterTimeIndex(t *testing.T) {
	pool := timelineTestPool(t)
	f := newTimelineFixture(t, pool)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.cluster}); err != nil {
		t.Fatal(err)
	}
	// A tiny fixture table would always seq-scan; disable that to ask the
	// planner which index it would pick when scanning is not free.
	if _, err := tx.Exec(ctx, `SET LOCAL enable_seqscan = off`); err != nil {
		t.Fatal(err)
	}
	rows, err := tx.Query(ctx, `EXPLAIN SELECT fingerprint, occurred_at FROM findings WHERE cluster_id = $1 AND occurred_at >= $2 AND occurred_at <= $3`,
		f.cluster, f.now.Add(-7*24*time.Hour), f.now)
	if err != nil {
		t.Fatal(err)
	}
	var plan []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, line)
	}
	rows.Close()
	joined := strings.Join(plan, "\n")
	if !strings.Contains(joined, "cluster_id_occurred_at_idx") && !strings.Contains(joined, "cluster_occurred_idx") {
		t.Errorf("finding window query does not use the cluster/time index:\n%s", joined)
	}
	fmt.Fprintln(os.Stderr, joined)
}
