package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"argus/internal/authz"
	"argus/internal/events"
)

// TestWSEventScopeFiltersByCapability is the unit half of Bug 3's regression
// test: which event kinds a subscriber is entitled to must follow from their
// capabilities, and an unrecognized event kind must fail CLOSED — the previous
// behaviour (forward everything on the process-wide bus to every socket) is
// exactly what let a zero-grant user watch the whole fleet's incident and
// cluster ids stream by.
func TestWSEventScopeFiltersByCapability(t *testing.T) {
	incidentEv := events.IncidentUpdated("inc_1", "cl_1")
	clusterEv := events.ClusterUpdated("cl_1")
	findingEv := events.FindingRecorded("cl_1")
	unknownEv := events.Event{Type: "SomeFutureEventKind", ClusterID: "cl_1"}

	cases := []struct {
		name         string
		grants       []authz.EffectiveGrant
		wantAny      bool
		wantIncident bool
		wantCluster  bool
	}{
		{"no grants at all", nil, false, false, false},
		{"unrelated capability only", grantsFor(authz.CapRemediationApprove), false, false, false},
		{"incident:read only", grantsFor(authz.CapIncidentRead), true, true, false},
		{"cluster:read only", grantsFor(authz.CapClusterRead), true, false, true},
		{"both reads", grantsFor(authz.CapIncidentRead, authz.CapClusterRead), true, true, true},
		{"viewer's full set", grantsFor(authz.CapIncidentRead, authz.CapAnalysisRead, authz.CapClusterRead, authz.CapPolicyRead), true, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			scope := wsEventScopeFor(c.grants)
			if got := scope.allowsAnything(); got != c.wantAny {
				t.Errorf("allowsAnything() = %v, want %v", got, c.wantAny)
			}
			if got := scope.allows(incidentEv); got != c.wantIncident {
				t.Errorf("allows(IncidentUpdated) = %v, want %v", got, c.wantIncident)
			}
			if got := scope.allows(clusterEv); got != c.wantCluster {
				t.Errorf("allows(ClusterUpdated) = %v, want %v", got, c.wantCluster)
			}
			// FindingRecorded rides incident:read, the capability GET
			// /api/v1/findings itself requires.
			if got := scope.allows(findingEv); got != c.wantIncident {
				t.Errorf("allows(FindingRecorded) = %v, want %v", got, c.wantIncident)
			}
			if scope.allows(unknownEv) {
				t.Error("allows(unknown event type) = true, want false — an unclassified event kind must fail closed")
			}
		})
	}
}

// TestHandleCreateWSTicketIssuesTicket covers the happy path of the (now
// capability-gated — see routes()) ticket endpoint: an authorized caller still
// gets a usable, redeemable ticket. The gate itself is covered by
// TestRequireAnyCapability in middleware_test.go, since that's where it lives.
func TestHandleCreateWSTicketIssuesTicket(t *testing.T) {
	s := &Server{wsTickets: authz.NewWSTicketIssuer()}

	rec := httptest.NewRecorder()
	s.handleCreateWSTicket(rec, httptest.NewRequest(http.MethodPost, "/api/v1/ws/ticket", nil),
		&requestContext{UserID: "usr_1", TenantID: "org_1", Grants: grantsFor(authz.CapIncidentRead)})

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusCreated, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"ticket"`) {
		t.Errorf("response has no ticket field: %s", rec.Body.String())
	}
}

// TestHandleWSEventsRejectsMissingOrBadTicket confirms the ticket check still
// runs before anything else — including before the new capability resolution,
// which is what keeps this handler DB-free for an unauthenticated caller.
func TestHandleWSEventsRejectsMissingOrBadTicket(t *testing.T) {
	s := &Server{wsTickets: authz.NewWSTicketIssuer()}
	for _, target := range []string{"/ws/events", "/ws/events?ticket=", "/ws/events?ticket=not-a-real-ticket"} {
		rec := httptest.NewRecorder()
		s.handleWSEvents(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s: status = %d, want %d (body: %s)", target, rec.Code, http.StatusUnauthorized, rec.Body.String())
		}
	}
}

// TestServeWSClientFiltersEventsByScope is Bug 3's end-to-end regression test
// over a real WebSocket connection: a subscriber holding incident:read but not
// cluster:read must never be sent a ClusterUpdated event, even though the bus
// broadcasts it to every subscriber.
//
// The ClusterUpdated event is published FIRST on purpose: the bus delivers into
// each subscriber's channel in order and serveWSClient forwards in order, so
// receiving the IncidentUpdated event as the first frame is proof the cluster
// event was dropped rather than merely delayed.
func TestServeWSClientFiltersEventsByScope(t *testing.T) {
	bus := events.NewBus()
	s := &Server{events: bus}
	scope := wsEventScopeFor(grantsFor(authz.CapIncidentRead)) // no cluster:read

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		s.serveWSClient(conn, "usr_1", scope)
	}))
	defer srv.Close()

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/ws/events", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Publishing before the subscription exists would simply drop the events
	// (the bus has no replay), so wait for serveWSClient to have subscribed.
	deadline := time.Now().Add(5 * time.Second)
	for bus.SubscriberCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("serveWSClient never subscribed to the bus")
		}
		time.Sleep(time.Millisecond)
	}

	bus.Publish(events.ClusterUpdated("cl_secret")) // must be filtered out
	bus.Publish(events.IncidentUpdated("inc_1", "cl_1"))

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	var got events.Event
	if err := conn.ReadJSON(&got); err != nil {
		t.Fatalf("read event: %v", err)
	}
	if got.Type != events.TypeIncidentUpdated {
		t.Fatalf("first delivered event = %+v, want the IncidentUpdated one — a ClusterUpdated frame means the filter is not applied", got)
	}
	if got.IncidentID != "inc_1" {
		t.Errorf("delivered incident id = %q, want %q", got.IncidentID, "inc_1")
	}
}
