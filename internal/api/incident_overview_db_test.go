package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
)

// GET /api/v1/incidents/overview against a real Postgres. The fixture is one
// throwaway cluster with five incidents placed on known UTC days, and every
// request is narrowed to it with ?clusterId=, so the shared development data
// cannot move the figures. The per-day openAtEnd values are the part worth
// pinning: they are reconstructed from first_seen and resolved_at, and an
// off-by-one at a day boundary would draw a plausible but wrong trend line.
func TestIncidentOverviewAggregates(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	tenantID, err := singleOrgIDForTest(ctx, pool)
	if err != nil {
		t.Fatalf("resolve tenant: %v", err)
	}
	fixture := dbtest.New(t)
	clusterID := domain.NewID(domain.PrefixCluster)
	fixture.OwnsCluster(tenantID, clusterID)

	today := time.Now().UTC().Truncate(24 * time.Hour)
	day := func(n int) time.Time { return today.AddDate(0, 0, -n).Add(time.Hour) }
	type inc struct {
		severity, state string
		firstSeen       time.Time
		resolvedAt      *time.Time
	}
	resolvedYesterday, resolvedLongAgo := day(1), today.AddDate(0, 0, -18)
	incs := []inc{
		{"critical", "Detected", today, nil},                                // opened today
		{"high", "AwaitingApproval", day(3), nil},                           // open since 3 days ago
		{"medium", "Resolved", day(5), &resolvedYesterday},                  // open days -5..-2, closed yesterday
		{"low", "Failed", day(2), nil},                                      // a fix that did not hold
		{"medium", "Dismissed", today.AddDate(0, 0, -20), &resolvedLongAgo}, // entirely before the window
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "overview-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	fixture.Created("clusters", 1)
	for i, x := range incs {
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, opening_reason, object_key, resolved_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$7,1,'BackOff','v1/Pod|ns|p',$8)`,
			domain.NewID(domain.PrefixIncident), tenantID, clusterID, "fp-overview-"+clusterID+"-"+string(rune('a'+i)),
			x.severity, x.state, x.firstSeen, x.resolvedAt); err != nil {
			t.Fatalf("insert incident %d: %v", i, err)
		}
		fixture.Created("incidents", 1)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	fixture.Cleanup(pool,
		func(ctx context.Context, tx pgx.Tx) error {
			return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
		},
		[]dbtest.TableDelete{
			{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
			{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
		})

	var body struct {
		Days    int `json:"days"`
		ByState []struct {
			State string `json:"state"`
			Count int    `json:"count"`
		} `json:"byState"`
		ByCluster []struct {
			ClusterID                                         string `json:"clusterId"`
			Critical, High, Medium, Low, Open, RequiresAction int
			FixNotHeld                                        int `json:"fixNotHeld"`
		} `json:"byCluster"`
		Daily []struct {
			Date   string `json:"date"`
			Opened struct {
				Critical, High, Medium, Low int
			} `json:"opened"`
			Resolved  int `json:"resolved"`
			OpenAtEnd int `json:"openAtEnd"`
		} `json:"daily"`
	}
	get := func(query string) *httptest.ResponseRecorder {
		t.Helper()
		rtx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin request tx: %v", err)
		}
		defer rtx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, rtx, tenantID, nil); err != nil {
			t.Fatalf("set scope: %v", err)
		}
		rc := &requestContext{Tx: rtx, TenantID: tenantID, Grants: grantsFor(authz.CapIncidentRead)}
		rec := httptest.NewRecorder()
		(&Server{}).handleIncidentOverview(rec, httptest.NewRequest(http.MethodGet, "/api/v1/incidents/overview?"+query, nil), rc)
		return rec
	}

	rec := get("clusterId=" + clusterID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	states := map[string]int{}
	for _, s := range body.ByState {
		states[s.State] = s.Count
	}
	if len(states) != 3 || states["Detected"] != 1 || states["AwaitingApproval"] != 1 || states["Failed"] != 1 {
		t.Errorf("byState = %v, want only the three open states, one each", states)
	}

	if len(body.ByCluster) != 1 {
		t.Fatalf("byCluster has %d rows, want 1", len(body.ByCluster))
	}
	c := body.ByCluster[0]
	if c.ClusterID != clusterID || c.Critical != 1 || c.High != 1 || c.Medium != 0 || c.Low != 1 || c.Open != 3 || c.RequiresAction != 3 || c.FixNotHeld != 1 {
		t.Errorf("byCluster = %+v, want 1 critical, 1 high, 0 medium, 1 low; 3 open, 3 requiring action, 1 fix not held", c)
	}

	if body.Days != 14 || len(body.Daily) != 14 {
		t.Fatalf("days = %d with %d rows, want the default 14", body.Days, len(body.Daily))
	}
	last := len(body.Daily) - 1
	if body.Daily[last].Date != today.Format("2006-01-02") {
		t.Fatalf("the last row is %s, want today %s", body.Daily[last].Date, today.Format("2006-01-02"))
	}
	for _, tc := range []struct {
		ago                                   int
		critical, high, medium, low, resolved int
		openAtEnd                             int
	}{
		{0, 1, 0, 0, 0, 0, 3},  // #1 opens; #2 and #4 still open
		{1, 0, 0, 0, 0, 1, 2},  // #3 closes during the day, so it is not open at its end
		{2, 0, 0, 0, 1, 0, 3},  // #4 opens beside #2 and #3
		{3, 0, 1, 0, 0, 0, 2},  // #2 opens beside #3
		{5, 0, 0, 1, 0, 0, 1},  // #3 opens
		{13, 0, 0, 0, 0, 0, 0}, // #5 closed 18 days ago, before the window
	} {
		d := body.Daily[last-tc.ago]
		if d.Opened.Critical != tc.critical || d.Opened.High != tc.high || d.Opened.Medium != tc.medium || d.Opened.Low != tc.low ||
			d.Resolved != tc.resolved || d.OpenAtEnd != tc.openAtEnd {
			t.Errorf("%d days ago (%s) = %+v, want opened %d/%d/%d/%d, resolved %d, open at end %d",
				tc.ago, d.Date, d, tc.critical, tc.high, tc.medium, tc.low, tc.resolved, tc.openAtEnd)
		}
	}

	if rec := get("clusterId=" + clusterID + "&days=6"); rec.Code != http.StatusBadRequest {
		t.Errorf("days=6 returned %d, want 400", rec.Code)
	}
	if rec := get("clusterId=" + clusterID + "&days=30"); rec.Code != http.StatusOK {
		t.Errorf("days=30 returned %d, want 200", rec.Code)
	}
}
