package notify

// PROJECT.md T11's notification-delivery-failures metric, proven against a
// real sweep rather than a unit-tested pure function: metrics.NotifyDeliveryTotal
// must actually move when sweepIncidents delivers successfully and when it
// fails, using the exact same fixture/webhook shape delivery_db_test.go's
// own tests already establish.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"argus/internal/data"
	"argus/internal/metrics"
)

// deliveryCounterValue scrapes DefaultRegistry for one
// argus_notify_delivery_total{outcome="..."} series, returning 0 if it is
// entirely absent (a real possibility the very first time this process ever
// runs a successful/failed delivery) rather than failing — callers compare
// a BEFORE/AFTER delta, which is well-defined either way.
func deliveryCounterValue(t *testing.T, outcome string) float64 {
	t.Helper()
	var buf strings.Builder
	metrics.DefaultRegistry.WriteExposition(&buf)
	want := `argus_notify_delivery_total{outcome="` + outcome + `"} `
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(line, want) {
			var v float64
			if _, err := fmt.Sscanf(strings.TrimPrefix(line, want), "%g", &v); err != nil {
				t.Fatalf("parse counter line %q: %v", line, err)
			}
			return v
		}
	}
	return 0
}

func TestSweepIncidents_RecordsSuccessfulDeliveryInMetrics(t *testing.T) {
	pool := testPool(t)
	tenantID, _, ids := seedUnnotifiedIncidents(t, pool, 1)
	ctx := context.Background()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	before := deliveryCounterValue(t, "success")

	n := NewWebhookNotifier(&data.DB{Pool: pool})
	if err := n.sweepIncidents(ctx, tenantID, defaultRouting(srv.URL)); err != nil {
		t.Fatalf("sweepIncidents: %v", err)
	}

	// At least +1, not exactly: sweepIncidents is fleet-wide and this is a
	// shared dev database — a real backlog of OTHER un-notified incidents
	// (visible in the "sweep hit the batch cap" log line on a dirty
	// database) can ride along in the same batch and add more successes of
	// its own. What matters is that OUR delivery is not missing from the
	// count, not that nothing else happened to be delivered too.
	after := deliveryCounterValue(t, "success")
	if after < before+1 {
		t.Fatalf("argus_notify_delivery_total{outcome=\"success\"} went from %v to %v, want at least +1 for incident %s's successful delivery", before, after, ids[0])
	}
}

func TestSweepIncidents_RecordsFailedDeliveryInMetrics(t *testing.T) {
	pool := testPool(t)
	tenantID, _, ids := seedUnnotifiedIncidents(t, pool, 1)
	ctx := context.Background()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	before := deliveryCounterValue(t, "failure")

	n := NewWebhookNotifier(&data.DB{Pool: pool})
	if err := n.sweepIncidents(ctx, tenantID, defaultRouting(srv.URL)); err != nil {
		t.Fatalf("sweepIncidents: %v", err)
	}

	// At least +1 — see the success test's own comment on why this is not
	// an exact-delta assertion on a shared, fleet-wide-queried dev database.
	after := deliveryCounterValue(t, "failure")
	if after < before+1 {
		t.Fatalf("argus_notify_delivery_total{outcome=\"failure\"} went from %v to %v, want at least +1 for incident %s's failed (500) delivery", before, after, ids[0])
	}
}
