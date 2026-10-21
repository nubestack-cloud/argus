package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestArgoManagedResourceDrift(t *testing.T) {
	desired := `{"apiVersion":"apps/v1","kind":"Deployment","spec":{"replicas":3,"template":{"spec":{"containers":[{"name":"web","image":"web:2"}]}}}}`
	live := `{"apiVersion":"apps/v1","kind":"Deployment","spec":{"replicas":5,"template":{"spec":{"containers":[{"name":"web","image":"web:2"}]}}},"status":{"readyReplicas":5}}`
	var gotAuth, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotQuery = r.Header.Get("Authorization"), r.URL.RawQuery
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{map[string]any{"predictedLiveState": desired, "normalizedLiveState": live}}})
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	api := &argoAPI{base: u, token: "t0ken", http: srv.Client()}
	d, err := api.managedResourceDrift(context.Background(), "argocd", "web", "apps", "Deployment", "shop", "web")
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer t0ken" || gotQuery == "" {
		t.Fatalf("request: auth=%q query=%q", gotAuth, gotQuery)
	}
	// Only the replica count differs; status is never drift.
	if len(d.Entries) != 1 || d.Entries[0].Path != "spec.replicas" || string(d.Source) != "argoDiff" {
		t.Fatalf("drift = %+v", d)
	}
}
