package knowledge

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestOllamaProvider_LiveCall is the one thing about this package that
// cannot be faked (see this package's own doc comment on never fabricating a
// vector): a real HTTP round-trip to a real, running Ollama instance with
// bge-m3 actually pulled, exercising OllamaProvider's real request/response
// handling — not a mock of it.
//
// Skipped by default, same ARGUS_TEST_*_URL-gated convention as
// testPool/ARGUS_TEST_DATABASE_URL above: set ARGUS_TEST_OLLAMA_URL to a
// reachable Ollama (e.g. "http://localhost:11434" if its port is published,
// or reachable from wherever `go test` runs — on the dev compose network
// itself, http://ollama:11434 as internal/knowledge's production code
// resolves it by default) with bge-m3 already pulled
// (`docker compose exec ollama ollama pull bge-m3`, see RUNBOOK.md) to run
// it for real.
func TestOllamaProvider_LiveCall(t *testing.T) {
	url, model, dims := liveOllamaTestConfig(t)
	provider := NewOllamaProvider(url, model, dims)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	vec, err := provider.Embed(ctx, "ImagePullBackOff on payments/api-1: expired registry token, fixed by rotating the credential")
	if err != nil {
		t.Fatalf("live Ollama embed call to %s failed: %v", url, err)
	}
	if len(vec) != dims {
		t.Fatalf("got a %d-dim vector, want %d", len(vec), dims)
	}
	allZero := true
	for _, f := range vec {
		if f != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatalf("vector is all zeros — indistinguishable from a fabricated placeholder, which this package must never write")
	}
	t.Logf("live Ollama call OK: model=%s dims=%d first5=%v", provider.Model(), len(vec), vec[:5])
}

func liveOllamaTestConfig(t *testing.T) (url, model string, dims int) {
	t.Helper()
	url = os.Getenv("ARGUS_TEST_OLLAMA_URL")
	if url == "" {
		t.Skip("ARGUS_TEST_OLLAMA_URL not set; skipping the live Ollama round-trip test (see this test's own doc comment)")
	}
	return url, DefaultEmbeddingModel, DefaultEmbeddingDims
}
