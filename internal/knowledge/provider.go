package knowledge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"argus/internal/outbound"
)

// EmbeddingProvider is the swappable seam decision D6 (lld/14-adrs.md) calls
// for: "analysis-contracts §5's retrieval interface is written to swap
// providers behind it without a wider redesign." Today's only implementation
// is OllamaProvider, self-hosted, matching DESIGN.md §16.2's default
// (`embedding: {provider: local, model: bge-m3}`) — a future provider (a
// different self-hosted model, a hosted embeddings API, or a swap to Qdrant's
// own embedding path per D6's consequences note) implements the same three
// methods and nothing else in this package needs to change.
type EmbeddingProvider interface {
	// Embed returns a real embedding vector for text. An error means "could
	// not be computed right now" — the caller (Store.EmbedAnalysis) must
	// treat that as "not embedded yet, retry later," never as license to
	// substitute a zero-vector or any other placeholder.
	Embed(ctx context.Context, text string) ([]float32, error)
	// Model identifies which model produced Embed's vectors — persisted
	// into analysis_embeddings.model alongside every vector, since
	// DESIGN.md §16.2 notes changing embedding model requires a full
	// reindex, so a per-row record of which model wrote it is what makes
	// that reindex possible to scope later.
	Model() string
	// Dimensions is the vector length this provider's Model produces —
	// bge-m3 is 1024 (DESIGN.md §16.2). Used to sanity-check every response
	// Embed receives before it's trusted.
	Dimensions() int
}

// Defaults matching DESIGN.md §16.2's embedding tier exactly: a self-hosted
// local model regardless of hosting choice elsewhere, bge-m3, 1024
// dimensions. ARGUS_OLLAMA_URL / ARGUS_EMBEDDING_MODEL override the first two
// for an operator running a different self-hosted setup; the dimension count
// is a property of the model, not independently configurable — change it by
// changing the model, and expect to reindex (see analysis_embeddings' own
// migration comment).
//
// SECURITY WARNING for ARGUS_OLLAMA_URL specifically: the text this provider
// embeds (BuildEmbeddedText's symptom/root-cause/fix/outcome) is built from
// real cluster data — object names, namespaces, error messages — the exact
// category of information non-negotiable 9 otherwise keeps inside the hub's
// own boundary. The default (this file's own DefaultOllamaURL, the
// self-hosted Ollama on the compose network) keeps that data local. Pointing
// this variable at a third-party or otherwise external endpoint sends that
// same cluster data to it on every embedding call — an egress this product
// otherwise promises against. Only override it to point at another
// self-hosted instance you control, never a third-party embedding API.
const (
	DefaultOllamaURL      = "http://ollama:11434"
	DefaultEmbeddingModel = "bge-m3"
	DefaultEmbeddingDims  = 1024
)

// OllamaProvider calls a real, running Ollama instance's documented
// /api/embeddings endpoint (POST {"model": "...", "prompt": "..."} ->
// {"embedding": [...]}). No fallback, no synthetic vector on failure — see
// this package's own doc comment for why that matters here specifically.
type OllamaProvider struct {
	baseURL string
	model   string
	dims    int
	client  *http.Client
}

// NewOllamaProvider builds a provider against baseURL (e.g.
// "http://ollama:11434" on the compose network) for model (e.g. "bge-m3"),
// expecting dims-dimensional vectors back. Empty/zero arguments fall back to
// this package's DESIGN.md §16.2 defaults.
func NewOllamaProvider(baseURL, model string, dims int) *OllamaProvider {
	if baseURL == "" {
		baseURL = DefaultOllamaURL
	}
	if model == "" {
		model = DefaultEmbeddingModel
	}
	if dims <= 0 {
		dims = DefaultEmbeddingDims
	}
	return &OllamaProvider{
		baseURL: strings.TrimRight(baseURL, "/"),
		model:   model,
		dims:    dims,
		// A real embedding call over a compose-internal network is fast, but
		// generous enough to survive the model still loading into memory on
		// its first call after a fresh `ollama pull`/container start —
		// EmbedAnalysis itself runs under its own outer timeout
		// (embedTimeout, store.go) that this must stay comfortably under.
		//
		// AllowPrivate: this file's own SECURITY WARNING above already
		// documents that ARGUS_OLLAMA_URL is expected to be a self-hosted
		// instance ARGUS's operator controls, routinely on localhost or a
		// private LAN address (lld/01-threat-model.md T15's admin-supplied-
		// URL gap, carved out here deliberately rather than left as a gap).
		// Cloud metadata is still refused unconditionally regardless
		// (internal/outbound's one absolute).
		client: outbound.NewClient(outbound.Policy{
			AllowPrivate: true,
			Reason:       "Ollama is a self-hosted model server, routinely on localhost or a private LAN address",
		}, 30*time.Second),
	}
}

func (o *OllamaProvider) Model() string   { return o.model }
func (o *OllamaProvider) Dimensions() int { return o.dims }

type ollamaEmbeddingsRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
}

type ollamaEmbeddingsResponse struct {
	Embedding []float32 `json:"embedding"`
}

func (o *OllamaProvider) Embed(ctx context.Context, text string) ([]float32, error) {
	reqBody, err := json.Marshal(ollamaEmbeddingsRequest{Model: o.model, Prompt: text})
	if err != nil {
		return nil, fmt.Errorf("marshal ollama embeddings request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+"/api/embeddings", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("build ollama embeddings request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call ollama embeddings endpoint %s: %w", o.baseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("ollama embeddings endpoint %s returned %d: %s", o.baseURL, resp.StatusCode, string(body))
	}

	var wire ollamaEmbeddingsResponse
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return nil, fmt.Errorf("decode ollama embeddings response: %w", err)
	}
	if len(wire.Embedding) == 0 {
		return nil, fmt.Errorf("ollama embeddings endpoint returned an empty vector for model %q", o.model)
	}
	if o.dims > 0 && len(wire.Embedding) != o.dims {
		return nil, fmt.Errorf("ollama embeddings endpoint returned a %d-dim vector for model %q, expected %d — is ARGUS_EMBEDDING_MODEL configured to match ARGUS_EMBEDDING_DIMS?", len(wire.Embedding), o.model, o.dims)
	}
	return wire.Embedding, nil
}
