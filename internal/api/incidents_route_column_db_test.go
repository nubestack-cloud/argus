package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
	"argus/internal/resolution"
)

// The incidents LIST carries incidents.route.
//
// The route is the decision ADR-18 made authoritative: internal/resolution
// .RouteFor picks pull request / in-place / both / guidance from ownership
// facts BEFORE the model is asked anything, and it is persisted on the
// incident (migration 000062). It reached the browser on the detail page only
// — a triage list could therefore not answer "how would this one actually get
// fixed" without opening every row, and the one workaround available to a
// list (read it off a plan's actionType) is the exact derivation
// incidentRouteRecord's own doc comment records as broken: it shows NOTHING
// for the `guidance` route, which is the case with no plan at all.
//
// Three incidents, because the interesting behaviour is at the edges:
//
//   - inPlace    — a plain executable route, present as a readable wire value.
//   - guidance   — the route with no plan, the one a plan-derived list drops.
//   - (no route) — NULL, which must be OMITTED rather than rendered as a
//     string. "" or null would both be a route a client could accidentally
//     label; absent is the only shape that forces "not routed yet".
//
// Run with ARGUS_TEST_DATABASE_URL pointed at `argus_app`, never `postgres` —
// that role carries BYPASSRLS and makes this package's scoping assertions
// vacuous.
func TestHandleListIncidents_CarriesResolutionRoute(t *testing.T) {
	pool := authTestPool(t)
	f := setupIncidentRouteFixture(t, pool)

	code, body := callListIncidents(t, pool, incidentSearchFixture{tenantID: f.tenantID, visibleCluster: f.clusterID}, "")
	if code != http.StatusOK {
		t.Fatalf("status = %d, body: %+v", code, body)
	}

	rows, _ := body["incidents"].([]any)
	byID := map[string]map[string]any{}
	for _, item := range rows {
		row, _ := item.(map[string]any)
		id, _ := row["id"].(string)
		byID[id] = row
	}
	for role, id := range map[string]string{"inPlace": f.inPlace, "guidance": f.guidance, "unrouted": f.unrouted} {
		if byID[id] == nil {
			t.Fatalf("the %s incident (%s) is missing from the list response entirely", role, id)
		}
	}

	if got := byID[f.inPlace]["route"]; got != string(resolution.RouteInPlace) {
		t.Errorf("inPlace incident's route = %#v, want %q — the list cannot say how this incident gets fixed",
			got, resolution.RouteInPlace)
	}
	if got := byID[f.guidance]["route"]; got != string(resolution.RouteGuidance) {
		t.Errorf("guidance incident's route = %#v, want %q — this is the route no plan.actionType can stand in for",
			got, resolution.RouteGuidance)
	}
	if raw, present := byID[f.unrouted]["route"]; present {
		t.Errorf("unrouted incident carries route = %#v — a NULL route must be OMITTED, so a client renders "+
			"\"not routed yet\" rather than treating an empty value as a channel", raw)
	}
}

type incidentRouteFixture struct {
	tenantID  string
	clusterID string
	inPlace   string
	guidance  string
	unrouted  string
}

// setupIncidentRouteFixture builds one throwaway cluster carrying three
// incidents that differ ONLY in incidents.route, so nothing but the column
// under test can explain a difference in the response.
//
// Cleanup goes through internal/dbtest rather than a hand-written
// `DELETE ... WHERE tenant_id = $1`: that shape has twice destroyed real
// development data in this repo (see dbtest's package doc), and the row-count
// assertion is what makes an over- or under-matching predicate refuse to
// commit rather than report the damage afterwards.
func setupIncidentRouteFixture(t *testing.T, pool *pgxpool.Pool) incidentRouteFixture {
	t.Helper()
	ctx := context.Background()

	f := incidentRouteFixture{clusterID: domain.NewID(domain.PrefixCluster)}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	f.tenantID, err = data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		f.clusterID, f.tenantID, "route-column-test-"+f.clusterID, "fp-"+f.clusterID); err != nil {
		t.Fatalf("insert throwaway cluster: %v", err)
	}
	fixture := dbtest.New(t)
	fixture.Created("clusters", 1)

	now := time.Now()
	add := func(route *string) string {
		id := domain.NewID(domain.PrefixIncident)
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state,
			   first_seen, last_seen, occurrence_count, route)
			 VALUES ($1, $2, $3, $4, 'medium', 'Detected', $5, $5, 1, $6)`,
			id, f.tenantID, f.clusterID, "fp-route-"+id, now, route); err != nil {
			t.Fatalf("insert incident (route=%v): %v", route, err)
		}
		fixture.Created("incidents", 1)
		return id
	}
	inPlace, guidance := string(resolution.RouteInPlace), string(resolution.RouteGuidance)
	f.inPlace = add(&inPlace)
	f.guidance = add(&guidance)
	f.unrouted = add(nil)

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup transaction: %v", err)
	}

	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterID})
	}, []dbtest.TableDelete{
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{f.clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{f.clusterID}},
	})

	return f
}
