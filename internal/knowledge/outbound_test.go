package knowledge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"argus/internal/outbound"
)

// TestOllamaProvider_ReachesLoopbackButRefusesMetadata proves the Ollama
// caller (lld/01-threat-model.md T15) adopted internal/outbound, and that
// its documented, deliberate exception for a self-hosted model server —
// this file's own DefaultOllamaURL is a compose-internal address, and the
// FIX-AND-IMPLEMENT-PROMPT's critical trap note calls out
// localhost:11434 by name — does not also open the one unconditional
// exception: cloud metadata.
func TestOllamaProvider_ReachesLoopbackButRefusesMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vec := make([]float32, 4)
		_ = json.NewEncoder(w).Encode(ollamaEmbeddingsResponse{Embedding: vec})
	}))
	defer srv.Close()

	// A real Ollama on loopback (e.g. http://localhost:11434) must still be
	// reachable.
	loopback := NewOllamaProvider(srv.URL, "bge-m3", 4)
	if _, err := loopback.Embed(context.Background(), "text"); err != nil {
		t.Fatalf("expected a loopback Ollama instance to be reachable, got: %v", err)
	}

	// Cloud metadata must be refused unconditionally, even though this
	// caller's policy allows private/loopback destinations.
	metadata := NewOllamaProvider("http://169.254.169.254", "bge-m3", 4)
	_, err := metadata.Embed(context.Background(), "text")
	if err == nil {
		t.Fatal("expected embedding against a cloud-metadata base URL to fail")
	}
	if !outbound.IsRefusal(err) {
		t.Fatalf("expected a stated outbound refusal reason, got: %v", err)
	}
}
