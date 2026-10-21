package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
)

// probes_test.go pins PROJECT.md B162's probe semantics, which are a split of
// responsibility rather than a behaviour tweak: liveness answers "is this
// process alive", readiness answers "should this process be sent traffic".
// Both halves are provable without a live cluster and without a real database,
// which is the point — the defect this fixes (both probes on /healthz, and
// /healthz pinging Postgres, so a database blip killed the hub and every
// agent tunnel with it) would have been caught by the first test here.

// unreachableDB builds a *data.DB whose pool points at a port nothing listens
// on. pgxpool.New is lazy — it does not dial until a query or a Ping — so this
// is a genuinely unreachable database with no live Postgres involved, which is
// exactly the condition B162 is about. (data.Connect cannot be used here: it
// Pings eagerly and would fail at construction.)
func unreachableDB(t *testing.T) *data.DB {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://argus_app:nope@127.0.0.1:1/argus?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return &data.DB{Pool: pool}
}

// TestHealthzIsProcessOnlyAndSurvivesAnUnreachableDatabase is B162's core
// claim. A Server whose database is unreachable must still answer 200 on
// /healthz, because that path is the LIVENESS target: a 503 there makes
// kubelet kill the hub, and every enrolled cluster's mTLS tunnel dies with it.
func TestHealthzIsProcessOnlyAndSurvivesAnUnreachableDatabase(t *testing.T) {
	s := &Server{db: unreachableDB(t)}

	rec := httptest.NewRecorder()
	s.handleHealthz(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz with an unreachable database = %d, want %d — liveness must not depend on the database (PROJECT.md B162)", rec.Code, http.StatusOK)
	}
}

// TestHealthzTouchesNoDatabaseAtAll is the stronger, structural version of the
// test above: this Server has NO database field set at all, so any attempt to
// reach one from the liveness path is a nil-pointer panic rather than a
// tolerated slow answer. It is deliberately a separate test — a future change
// that reintroduced a dependency behind a fallback or a timeout would still
// pass the first test and fail this one.
func TestHealthzTouchesNoDatabaseAtAll(t *testing.T) {
	s := &Server{} // no db, no pool, nothing

	rec := httptest.NewRecorder()
	s.handleHealthz(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz on a Server with no database = %d, want %d", rec.Code, http.StatusOK)
	}
}

// TestHealthzStaysGreenWhileDraining pins the other half of the liveness
// contract: /healthz must keep answering 200 for the whole SIGTERM drain. If
// it reported the shutdown state, kubelet would fail liveness and kill the
// process in the middle of the drain — the exact thing the drain exists to
// avoid.
func TestHealthzStaysGreenWhileDraining(t *testing.T) {
	s := &Server{}
	s.BeginShutdown()

	rec := httptest.NewRecorder()
	s.handleHealthz(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz while draining = %d, want %d — liveness must stay green for the whole drain", rec.Code, http.StatusOK)
	}
}

// TestReadyzReportsNotReadyWhenTheDatabaseIsUnreachable is the counterpart
// claim: the database check did not disappear in B162's fix, it moved to the
// probe where a failure means "take me out of the Service's endpoints" rather
// than "restart me".
func TestReadyzReportsNotReadyWhenTheDatabaseIsUnreachable(t *testing.T) {
	s := &Server{db: unreachableDB(t)}

	rec := httptest.NewRecorder()
	s.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz with an unreachable database = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	var problem struct {
		Type   string `json:"type"`
		Status int    `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatalf("readyz body is not RFC 9457 problem+json: %v (%s)", err, rec.Body.String())
	}
	if problem.Type != "https://argus.io/errors/db-unreachable" {
		t.Errorf("problem type = %q, want the db-unreachable type so an operator can tell this apart from an RLS-precondition failure", problem.Type)
	}
}

// TestReadyzReportsNotReadyWhileDraining proves the readiness half of the
// drain: BeginShutdown must take this hub out of its Service's endpoints
// BEFORE the listener stops accepting, and it must do so without touching the
// database (this Server has none — a check ordered after the ping would panic
// here).
func TestReadyzReportsNotReadyWhileDraining(t *testing.T) {
	s := &Server{}
	s.BeginShutdown()

	rec := httptest.NewRecorder()
	s.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz while draining = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	var problem struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatalf("readyz body is not RFC 9457 problem+json: %v (%s)", err, rec.Body.String())
	}
	if problem.Type != "https://argus.io/errors/shutting-down" {
		t.Errorf("problem type = %q, want the shutting-down type — a draining hub is a different condition from a broken one", problem.Type)
	}
}

// TestProbeRoutesAreDistinctPaths guards the shape of the fix rather than its
// behaviour: the two probes must remain two different registered paths. The
// chart pointing both probes at one path is what turned a database blip into a
// fleet-wide outage, and that mistake is only possible when the two probes
// have a single path to point at.
func TestProbeRoutesAreDistinctPaths(t *testing.T) {
	s := &Server{mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /readyz", s.handleReadyz)
	s.BeginShutdown() // so /readyz answers without needing a database

	liveness := httptest.NewRecorder()
	s.mux.ServeHTTP(liveness, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	readiness := httptest.NewRecorder()
	s.mux.ServeHTTP(readiness, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if liveness.Code == readiness.Code {
		t.Fatalf("/healthz and /readyz both answered %d for a draining hub — they must be able to disagree, or pointing both probes at one of them is indistinguishable from pointing them at the right ones", liveness.Code)
	}
}

// TestDrainWebSocketsIsSafeWithNothingToDrain covers the two degenerate cases
// the drain has to tolerate: a bare &Server{} (this package's test
// convention), which has no drain channel at all, and a real Server with no
// connected clients.
func TestDrainWebSocketsIsSafeWithNothingToDrain(t *testing.T) {
	bare := &Server{}
	if open, drained := bare.DrainWebSockets(context.Background()); open != 0 || !drained {
		t.Errorf("DrainWebSockets on a bare &Server{} = (%d, %t), want (0, true)", open, drained)
	}

	real := &Server{wsDrain: make(chan struct{})}
	if open, drained := real.DrainWebSockets(context.Background()); open != 0 || !drained {
		t.Errorf("DrainWebSockets with no clients = (%d, %t), want (0, true)", open, drained)
	}
	// Idempotent: a second call must not panic on a closed channel.
	if open, drained := real.DrainWebSockets(context.Background()); open != 0 || !drained {
		t.Errorf("second DrainWebSockets = (%d, %t), want (0, true)", open, drained)
	}
	if !real.wsDrainClosed() {
		t.Error("wsDrainClosed() = false after DrainWebSockets, want true")
	}
}
