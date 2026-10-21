package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/timeline"
)

// TestHandleGetIncidentTimelineRequiresAuth proves the route is wrapped with
// requireAuth (server.go's registration): a request with no bearer token at
// all must be refused before anything else runs, and requireAuth's own
// missing-token branch returns before ever touching the database — so this
// needs no DB and no real Server fields.
func TestHandleGetIncidentTimelineRequiresAuth(t *testing.T) {
	s := &Server{}
	handler := s.requireAuth(s.requireCapability(authz.CapIncidentRead, s.handleGetIncidentTimeline))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/inc_x/timeline", nil)
	req.SetPathValue("id", "inc_x")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d (body: %s) — a request with no Authorization header must be refused before reaching the handler",
			rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// TestHandleGetIncidentTimelineRequiresCapability proves the route's
// requireCapability(authz.CapIncidentRead, ...) wrapper actually gates it —
// mirrors clusters_test.go's TestHandleGetClusterRefusesOutOfScopeCluster in
// structure: a case that clears the gate goes on to call
// rc.Tx.QueryRow on a nil Tx and panics, which is caught and treated as
// "passed the gate" rather than a test failure, since proving the gate lets
// a correctly-capable caller through is part of the same assertion as
// proving it blocks everyone else.
func TestHandleGetIncidentTimelineRequiresCapability(t *testing.T) {
	cases := []struct {
		name       string
		grants     []authz.EffectiveGrant
		wantDenied bool
	}{
		{"no grants at all", nil, true},
		{"a grant for a different capability", grantsFor(authz.CapRemediationApprove), true},
		{"incident:read grant", grantsFor(authz.CapIncidentRead), false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := serverWithUnreachableAuditDB(t)
			handler := s.requireCapability(authz.CapIncidentRead, s.handleGetIncidentTimeline)

			req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/inc_x/timeline", nil)
			req.SetPathValue("id", "inc_x")
			rec := httptest.NewRecorder()

			passedGate := false
			func() {
				defer func() {
					if recover() != nil {
						passedGate = true
					}
				}()
				handler(rec, req, &requestContext{Grants: c.grants})
			}()

			denied := !passedGate && rec.Code == http.StatusForbidden
			if denied != c.wantDenied {
				t.Fatalf("status = %d (denied=%v, passedGate=%v), want denied=%v — body: %s",
					rec.Code, denied, passedGate, c.wantDenied, rec.Body.String())
			}
		})
	}
}

// timelineReadFixture builds two clusters (visible/hidden), each with one
// incident and one timeline_events row — the RLS shape
// setupIncidentSearchFixture (incidents_test.go) already established for
// this exact purpose, trimmed to what this endpoint needs.
type timelineReadFixture struct {
	tenantID                        string
	visibleCluster, hiddenCluster   string
	visibleIncident, hiddenIncident string
}

func setupTimelineReadFixture(t *testing.T, pool *pgxpool.Pool) timelineReadFixture {
	t.Helper()
	ctx := context.Background()
	f := timelineReadFixture{
		visibleCluster:  domain.NewID(domain.PrefixCluster),
		hiddenCluster:   domain.NewID(domain.PrefixCluster),
		visibleIncident: domain.NewID(domain.PrefixIncident),
		hiddenIncident:  domain.NewID(domain.PrefixIncident),
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	f.tenantID, err = data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.visibleCluster, f.hiddenCluster}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	now := time.Now()
	for _, c := range []struct{ id, incidentID, name string }{
		{f.visibleCluster, f.visibleIncident, "timeline-read-visible-" + f.visibleCluster},
		{f.hiddenCluster, f.hiddenIncident, "timeline-read-hidden-" + f.hiddenCluster},
	} {
		if _, err := tx.Exec(ctx,
			`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
			 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
			c.id, f.tenantID, c.name, "fp-"+c.id); err != nil {
			t.Fatalf("insert cluster %s: %v", c.id, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
			 VALUES ($1, $2, $3, $4, 'high', 'Detected', $5, $5, 1)`,
			c.incidentID, f.tenantID, c.id, "fp-"+c.incidentID, now); err != nil {
			t.Fatalf("insert incident %s: %v", c.incidentID, err)
		}
		if err := timeline.Record(ctx, tx, timeline.Event{
			TenantID: f.tenantID, ClusterID: c.id, IncidentID: c.incidentID,
			Type: timeline.EventIncidentOpened, Summary: "test detection event",
		}); err != nil {
			t.Fatalf("record timeline event for %s: %v", c.incidentID, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Errorf("cleanup: begin: %v", err)
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		clusterIDs := []string{f.visibleCluster, f.hiddenCluster}
		if err := data.SetRequestScope(ctx, tx, f.tenantID, clusterIDs); err != nil {
			t.Errorf("cleanup: scope: %v", err)
			return
		}
		for _, stmt := range []string{
			`DELETE FROM timeline_events WHERE cluster_id = ANY($1)`,
			`DELETE FROM incidents WHERE cluster_id = ANY($1)`,
			`DELETE FROM clusters WHERE id = ANY($1)`,
		} {
			if _, err := tx.Exec(ctx, stmt, clusterIDs); err != nil {
				t.Errorf("cleanup %q: %v", stmt, err)
			}
		}
		if err := tx.Commit(ctx); err != nil {
			t.Errorf("cleanup: commit: %v", err)
		}
	})
	return f
}

// callGetIncidentTimeline opens its own transaction scoped only to
// visibleClusterIDs (mirroring incidents_test.go's callListIncidents), and
// calls the real handler directly.
func callGetIncidentTimeline(t *testing.T, pool *pgxpool.Pool, tenantID string, visibleClusterIDs []string, incidentID string) (int, map[string]any) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin request tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, visibleClusterIDs); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/"+incidentID+"/timeline", nil)
	req.SetPathValue("id", incidentID)
	rec := httptest.NewRecorder()
	s := &Server{}
	s.handleGetIncidentTimeline(rec, req, &requestContext{Tx: tx, TenantID: tenantID})

	var body map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal response (status %d, body %s): %v", rec.Code, rec.Body.String(), err)
		}
	}
	return rec.Code, body
}

// TestHandleGetIncidentTimelineReturnsEventsInOrder is the endpoint's shape
// test: a 200 with an "events" array, each element carrying id/eventType/
// summary/detail/occurredAt, oldest first (lld/11-ui-design.md §4's
// "rendered in order, durations computed client-side from adjacent
// timestamps" contract).
func TestHandleGetIncidentTimelineReturnsEventsInOrder(t *testing.T) {
	pool := authTestPool(t)
	f := setupTimelineReadFixture(t, pool)

	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.visibleCluster}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	// A second, later event on the visible incident, so ordering is a real
	// assertion rather than trivially true of a single row.
	if err := timeline.Record(ctx, tx, timeline.Event{
		TenantID: f.tenantID, ClusterID: f.visibleCluster, IncidentID: f.visibleIncident,
		Type: timeline.EventInvestigationStarted, Summary: "second event",
	}); err != nil {
		t.Fatalf("record second event: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	code, body := callGetIncidentTimeline(t, pool, f.tenantID, []string{f.visibleCluster}, f.visibleIncident)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %+v)", code, body)
	}
	events, _ := body["events"].([]any)
	if len(events) != 2 {
		t.Fatalf("events = %+v, want exactly 2", events)
	}
	first, _ := events[0].(map[string]any)
	second, _ := events[1].(map[string]any)
	if first["eventType"] != "IncidentOpened" || second["eventType"] != "InvestigationStarted" {
		t.Fatalf("event order = [%v, %v], want [IncidentOpened, InvestigationStarted]", first["eventType"], second["eventType"])
	}
	for _, key := range []string{"id", "eventType", "summary", "occurredAt"} {
		if _, ok := first[key]; !ok {
			t.Errorf("first event is missing %q: %+v", key, first)
		}
	}
	if first["summary"] != "test detection event" {
		t.Errorf("first event summary = %v, want %q", first["summary"], "test detection event")
	}
}

// TestHandleGetIncidentTimelineReturns404ForUnknownOrInvisibleIncident
// covers both the genuinely-nonexistent case and the RLS-invisible case in
// one test, matching this codebase's own "absent and RLS-invisible are
// indistinguishable, and equally a 404" convention
// (orchestrator.ErrIncidentNotFound's doc comment).
func TestHandleGetIncidentTimelineReturns404ForUnknownOrInvisibleIncident(t *testing.T) {
	pool := authTestPool(t)
	f := setupTimelineReadFixture(t, pool)

	t.Run("genuinely nonexistent incident", func(t *testing.T) {
		code, body := callGetIncidentTimeline(t, pool, f.tenantID, []string{f.visibleCluster}, domain.NewID(domain.PrefixIncident))
		if code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (body: %+v)", code, body)
		}
	})

	t.Run("the hidden cluster's incident is invisible under a narrower scope, not just filtered", func(t *testing.T) {
		code, body := callGetIncidentTimeline(t, pool, f.tenantID, []string{f.visibleCluster}, f.hiddenIncident)
		if code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (body: %+v) — a request scoped to the visible cluster must not be able to tell the hidden incident exists, let alone read its timeline", code, body)
		}
	})

	t.Run("the hidden cluster's incident IS visible once its own cluster is in scope", func(t *testing.T) {
		code, body := callGetIncidentTimeline(t, pool, f.tenantID, []string{f.hiddenCluster}, f.hiddenIncident)
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200 once the hidden cluster is actually in scope (body: %+v) — proves the 404 above is real RLS isolation, not a bug that 404s everything", code, body)
		}
		events, _ := body["events"].([]any)
		if len(events) != 1 {
			t.Fatalf("events = %+v, want exactly 1 (the hidden incident's own IncidentOpened row)", events)
		}
	})
}
