package llm

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCompleteSendsResolvedConfig exercises complete() — the pure-plumbing
// half of Provider.Complete that takes an already-resolved base URL/API
// key/model rather than calling internal/settings.Resolve itself — against
// a local httptest.Server, with no database involved. This is what actually
// proves a resolved settings.Config (whether it came from the DB or an env
// var — complete() doesn't know or care) drives the real HTTP request.
func TestCompleteSendsResolvedConfig(t *testing.T) {
	var gotAuth, gotModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		var req chatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		gotModel = req.Model
		_ = json.NewEncoder(w).Encode(chatResponse{
			Model: "actual-model",
			Choices: []struct {
				Message chatMessage `json:"message"`
			}{{Message: chatMessage{Role: "assistant", Content: "hello"}}},
		})
	}))
	defer srv.Close()

	result, err := complete(t.Context(), srv.Client(), srv.URL, "s3cr3t-key", "requested-model", "sys", "user")
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if gotAuth != "Bearer s3cr3t-key" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer s3cr3t-key")
	}
	if gotModel != "requested-model" {
		t.Errorf("request model = %q, want %q", gotModel, "requested-model")
	}
	if result.Text != "hello" {
		t.Errorf("result.Text = %q, want %q", result.Text, "hello")
	}
	if result.Model != "actual-model" {
		t.Errorf("result.Model = %q, want the response's own model field", result.Model)
	}
}

// TestCompleteNoAPIKeyOmitsAuthHeader confirms an empty API key (the
// resolved settings.Config for a self-hosted server that needs none) never
// sends an Authorization header at all, matching the original
// NewProviderFromEnv-era behavior.
func TestCompleteNoAPIKeyOmitsAuthHeader(t *testing.T) {
	var sawAuthHeader bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			sawAuthHeader = true
		}
		_ = json.NewEncoder(w).Encode(chatResponse{
			Choices: []struct {
				Message chatMessage `json:"message"`
			}{{Message: chatMessage{Content: "ok"}}},
		})
	}))
	defer srv.Close()

	if _, err := complete(t.Context(), srv.Client(), srv.URL, "", "m", "sys", "user"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if sawAuthHeader {
		t.Error("expected no Authorization header when apiKey is empty")
	}
}

// TestCompleteNonOKStatusIsAnError confirms a non-2xx response from the
// provider surfaces as an error rather than being silently treated as a
// valid (empty) completion.
func TestCompleteNonOKStatusIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	if _, err := complete(t.Context(), srv.Client(), srv.URL, "", "m", "sys", "user"); err == nil {
		t.Fatal("complete: expected an error for a 500 response, got nil")
	}
}

// TestCompleteFallsBackToRequestModelWhenResponseOmitsIt exercises the
// "response didn't echo a model field" branch.
func TestCompleteFallsBackToRequestModelWhenResponseOmitsIt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(chatResponse{
			Choices: []struct {
				Message chatMessage `json:"message"`
			}{{Message: chatMessage{Content: "ok"}}},
		})
	}))
	defer srv.Close()

	result, err := complete(t.Context(), srv.Client(), srv.URL, "", "requested-model", "sys", "user")
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if result.Model != "requested-model" {
		t.Errorf("result.Model = %q, want fallback to the requested model", result.Model)
	}
}
