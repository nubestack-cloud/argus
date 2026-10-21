package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestPayloadIncludesEveryField is the DB-free unit test the task brief asked
// for explicitly: given a fake incidentRow (no database, no HTTP), confirm
// the JSON body actually describes the incident — cluster id, fingerprint,
// severity, and when first seen — and is shaped as Slack's incoming-webhook
// format ({"text": "..."}) expects.
func TestPayloadIncludesEveryField(t *testing.T) {
	firstSeen := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	row := incidentRow{
		ID:          "inc_01example",
		ClusterID:   "cl_01example",
		Fingerprint: "abc123fingerprint",
		Severity:    "high",
		FirstSeen:   firstSeen,
	}

	body, err := row.payload()
	if err != nil {
		t.Fatalf("payload: %v", err)
	}

	var decoded map[string]string
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("payload did not produce valid JSON: %v", err)
	}
	text, ok := decoded["text"]
	if !ok {
		t.Fatalf("payload JSON has no \"text\" key (Slack incoming-webhook shape) — got %v", decoded)
	}

	for _, want := range []string{row.ID, row.ClusterID, row.Fingerprint, row.Severity, "2026-08-19T12:00:00Z"} {
		if !strings.Contains(text, want) {
			t.Errorf("payload text %q does not contain %q", text, want)
		}
	}
}

// TestPayloadIsDeterministic guards against a future change accidentally
// making payload() depend on wall-clock time or map-iteration order (a
// single string key means json.Marshal has nothing to reorder today, but
// this pins the behavior so a later refactor toward multiple fields doesn't
// silently introduce nondeterminism).
func TestPayloadIsDeterministic(t *testing.T) {
	row := incidentRow{
		ID:          "inc_x",
		ClusterID:   "cl_x",
		Fingerprint: "fp_x",
		Severity:    "medium",
		FirstSeen:   time.Unix(0, 0).UTC(),
	}
	a, err := row.payload()
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	b, err := row.payload()
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	if string(a) != string(b) {
		t.Errorf("payload() is not deterministic: %q vs %q", a, b)
	}
}

// TestPostSuccess and TestPostFailure exercise WebhookNotifier.post against a
// local httptest.Server rather than a real database or live webhook — the
// live-stack round trip (real incident, real notified_at flip, real retry
// after a failure) is verified separately against the containerized stack
// per this task's brief, since that needs Postgres and a real HTTP receiver
// reachable from inside the hub-api container; this test only pins post's
// own 2xx-vs-not contract.
func TestPostSuccess(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := &WebhookNotifier{client: srv.Client()}
	body := []byte(`{"text":"hello"}`)
	if err := n.post(t.Context(), srv.URL, body); err != nil {
		t.Fatalf("post: %v", err)
	}
	if string(gotBody) != string(body) {
		t.Errorf("server received body %q, want %q", gotBody, body)
	}
}

func TestPostFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	n := &WebhookNotifier{client: srv.Client()}
	if err := n.post(t.Context(), srv.URL, []byte(`{"text":"hello"}`)); err == nil {
		t.Fatal("post: expected an error for a 500 response, got nil")
	}
}

func TestPostUnreachable(t *testing.T) {
	// A closed-port URL, never a live server — exercises the transport-level
	// failure path (connection refused) distinctly from an HTTP-level 5xx.
	n := &WebhookNotifier{client: &http.Client{Timeout: 2 * time.Second}}
	if err := n.post(t.Context(), "http://127.0.0.1:1", []byte(`{"text":"hello"}`)); err == nil {
		t.Fatal("post: expected an error for an unreachable webhook, got nil")
	}
}

// TestNewWebhookNotifierAlwaysNonNil pins NewWebhookNotifier's new contract
// (see its doc comment): unlike the old NewWebhookNotifierFromEnv, there is
// no "not configured at construction time" nil case anymore — whether a
// webhook URL is set is resolved fresh per sweep tick (settings.Resolve),
// not baked in at construction.
func TestNewWebhookNotifierAlwaysNonNil(t *testing.T) {
	n := NewWebhookNotifier(nil)
	if n == nil {
		t.Fatal("NewWebhookNotifier returned nil")
	}
}
