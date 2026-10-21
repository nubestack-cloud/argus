// Package knowledge is the storage half of BACKLOG.md's L2 item ("Past-incident
// retrieval / knowledge base"), per the owner's 2026-08-30 decision to split
// that item: build storage now — embed and store every completed analysis so
// history accumulates in a retrievable shape — and do NOT wire retrieval into
// the investigation prompt yet. That means:
//
//   - This package has NO search/query-by-similarity entry point. Nothing here
//     is a "search_knowledge" tool, and nothing here is called from
//     internal/llm/toolloop.go's system prompt or tool surface. Adding either
//     is explicitly out of scope until the retrieval half of L2 is decided.
//   - What it DOES do: build the (symptom, root cause, fix, outcome) text
//     DESIGN.md §910 specifies for a resolved incident's embedding, call an
//     EmbeddingProvider (Ollama-backed by default, per DESIGN.md §16.2's
//     `embedding: {provider: local, model: bge-m3}` default), and persist the
//     result into `analysis_embeddings` (migration 000082), which uses
//     `pgvector` per decision D6 (lld/14-adrs.md).
//
// Two entry points a caller needs:
//
//   - Store.TriggerAsync — call once, right after the caller's own transaction
//     that persisted a fresh analyses row has committed (internal/api/analyze.go's
//     handleAnalyzeIncident and internal/autoanalyze's investigateOne both do
//     this). Runs in its own goroutine and its own DB transaction, so it never
//     adds latency to the analyze request/sweep tick it's called from.
//   - Store.RunBackfillSweep — a long-running background loop (same shape as
//     internal/autoanalyze.Poller.RunStaleObjectSweeper), started once at hub
//     startup, that finds analyses with no analysis_embeddings row yet (never
//     embedded — including the 247+ that predate this package, BACKLOG.md H2 —
//     or a previous attempt failed, e.g. Ollama unreachable) and embeds them at
//     an idle pace. It also re-embeds rows whose outcome_final is still false,
//     in case their incident has since reached a terminal state (see
//     analysis_embeddings' own migration comment for why one sweep serves both
//     jobs).
//
// Never fabricated: if the embedding provider can't be reached, EmbedAnalysis
// returns an error and NO row is written — never a zero-vector or synthetic
// placeholder. A missing row is exactly the backfill sweep's retry queue (see
// migration 000082's doc comment) — this is the "nullable / a retriable queue"
// behaviour BACKLOG.md L2's decision calls for.
package knowledge
