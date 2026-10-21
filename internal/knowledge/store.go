package knowledge

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/logging"
	"argus/internal/orchestrator"
)

// embedTimeout bounds one TriggerAsync goroutine end to end (DB reads, the
// Ollama call, the DB write) — generous against OllamaProvider's own 30s HTTP
// client timeout so a slow-but-real response is never cut off by this
// package's own outer bound instead of the provider's.
const embedTimeout = 45 * time.Second

// Store is this package's one exported entry point: a thin wrapper around a
// connection pool and an EmbeddingProvider. Every method is safe to call on a
// nil *Store — a hub started with embedding not configured (no Store built at
// all) then has TriggerAsync/RunBackfillSweep as no-ops, so call sites never
// need their own "is embedding enabled" branch.
type Store struct {
	pool     *pgxpool.Pool
	provider EmbeddingProvider
}

// NewStore builds a Store. provider must not be nil when the returned Store
// is used directly (EmbedAnalysis returns an error otherwise); pass a nil
// *Store itself (not `NewStore(pool, nil)`) from a call site that wants
// embedding fully disabled, so TriggerAsync/RunBackfillSweep's nil-receiver
// no-op applies.
func NewStore(pool *pgxpool.Pool, provider EmbeddingProvider) *Store {
	return &Store{pool: pool, provider: provider}
}

// TriggerAsync embeds one freshly-persisted analysis in the background —
// never blocking the caller on an embedding call. Call ONLY after the
// caller's own transaction that persisted this analyses row (PersistAnalysis)
// has actually committed: this opens its own, independent transaction to read
// and write, so calling it before commit would race the embed against a row
// that might still roll back, and could embed an analysis that never
// existed.
//
// Safe to call on a nil *Store.
func (s *Store) TriggerAsync(tenantID, clusterID, analysisID string) {
	if s == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), embedTimeout)
		defer cancel()
		if err := s.EmbedAnalysis(ctx, tenantID, clusterID, analysisID); err != nil {
			logger.WarnContext(ctx, "embedding an analysis failed; left un-embedded for the backfill sweep to retry",
				slog.String("analysis_id", analysisID), logging.Err(err))
		}
	}()
}

// EmbedAnalysis builds the (symptom, root cause, fix, outcome) text for one
// analysis, calls the configured EmbeddingProvider, and upserts the result
// into analysis_embeddings — all inside one transaction scoped to
// (tenantID, clusterID), the same request-scope discipline every other
// cluster-scoped background writer in this codebase follows (see
// internal/autoanalyze.investigateOne).
//
// Returns an error — and writes NOTHING — if the provider can't be reached or
// returns something unusable. This is the one hard rule this package has: no
// row is ever written with a fabricated or placeholder vector (see this
// package's own doc comment, and analysis_embeddings' migration comment, for
// why a missing row is the correct "not embedded yet" representation rather
// than a nullable/zero column).
func (s *Store) EmbedAnalysis(ctx context.Context, tenantID, clusterID, analysisID string) error {
	if s == nil {
		return fmt.Errorf("knowledge: nil store")
	}
	if s.provider == nil {
		return fmt.Errorf("knowledge: no embedding provider configured")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		return fmt.Errorf("set request scope: %w", err)
	}

	inputs, err := queryEmbeddingInputs(ctx, tx, analysisID)
	if err != nil {
		return fmt.Errorf("query embedding inputs: %w", err)
	}

	text := BuildEmbeddedText(inputs.symptom, inputs.rootCause, inputs.fix, inputs.outcome)

	vector, err := s.provider.Embed(ctx, text)
	if err != nil {
		return fmt.Errorf("embed: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO analysis_embeddings (analysis_id, incident_id, tenant_id, cluster_id, model, embedded_text, embedding, outcome_final, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7::vector, $8, now())
		ON CONFLICT (analysis_id) DO UPDATE SET
			embedded_text = EXCLUDED.embedded_text,
			embedding     = EXCLUDED.embedding,
			model         = EXCLUDED.model,
			outcome_final = EXCLUDED.outcome_final,
			updated_at    = now()
	`, analysisID, inputs.incidentID, tenantID, clusterID, s.provider.Model(), text, vectorLiteral(vector), inputs.outcomeFinal)
	if err != nil {
		return fmt.Errorf("store embedding: %w", err)
	}

	return tx.Commit(ctx)
}

// embeddingInputs is queryEmbeddingInputs' result — everything EmbedAnalysis
// needs to build the embedded text and decide outcomeFinal, resolved fresh
// from the current state of the DB rather than passed in by the caller: a
// backfill re-embed (RunBackfillSweep) has no in-memory Investigation result
// to pass, only an analysisID, so this must be able to reconstruct
// everything from what's already persisted.
type embeddingInputs struct {
	incidentID   string
	symptom      string
	rootCause    string
	fix          string
	outcome      string
	outcomeFinal bool
}

// analysisRootCause mirrors internal/api/analyze.go's unexported
// rootCauseStored shape — the JSON that package writes into
// analyses.root_cause. Duplicated rather than imported: internal/api imports
// this package (to call TriggerAsync after PersistAnalysis), so the reverse
// import would cycle. This is a private wire format for the contents of one
// jsonb column, not a type either package hands to a caller across an API
// boundary, so a small mirrored struct here is the honest fix rather than
// standing up a shared package for one two-field shape.
type analysisRootCause struct {
	Status        string `json:"status"`
	Statement     string `json:"statement,omitempty"`
	PartialReason string `json:"partialReason,omitempty"`
}

// queryEmbeddingInputs reads everything BuildEmbeddedText needs for one
// analysis, from tables this package's caller has already scoped tx to.
//
//   - symptom: the incident's opening finding (incidents.opening_reason +
//     object_key), per DESIGN.md §910 — what a human would have seen first.
//   - rootCause: analyses.root_cause's stored statement (complete) or a
//     partial reason (incomplete) — never fabricated when absent.
//   - fix: the newest remediation_recommendations row proposed FROM this
//     analysis (there is at most one per lld/05-data-model.md's "one
//     incident carries at most one proposed plan" note), with its newest
//     approval decision folded in if one has been made — or empty (rendered
//     by BuildEmbeddedText as "no plan") if this analysis never proposed one
//     (a guidance-only route, lld/07-analysis-contracts.md §12).
//   - outcome / outcomeFinal: the incident's CURRENT state. outcomeFinal is
//     true only once orchestrator.IsTerminalState says so (Resolved or
//     Dismissed, in this codebase's state machine) — an incident still open
//     is embedded with an honest "not yet known" outcome, and outcomeFinal
//     stays false so RunBackfillSweep re-embeds this row once the incident
//     actually closes.
func queryEmbeddingInputs(ctx context.Context, tx pgx.Tx, analysisID string) (embeddingInputs, error) {
	var (
		incidentID    string
		rootCauseJSON []byte
		state         string
		openingReason string
		objectKey     string
	)
	err := tx.QueryRow(ctx, `
		SELECT a.incident_id, a.root_cause,
		       i.state, COALESCE(i.opening_reason, ''), COALESCE(i.object_key, '')
		  FROM analyses a
		  JOIN incidents i ON i.id = a.incident_id
		 WHERE a.id = $1
	`, analysisID).Scan(&incidentID, &rootCauseJSON, &state, &openingReason, &objectKey)
	if err != nil {
		return embeddingInputs{}, fmt.Errorf("query analysis %s and its incident: %w", analysisID, err)
	}

	var stored analysisRootCause
	rootCause := ""
	if len(rootCauseJSON) > 0 {
		if err := json.Unmarshal(rootCauseJSON, &stored); err != nil {
			return embeddingInputs{}, fmt.Errorf("unmarshal root_cause for analysis %s: %w", analysisID, err)
		}
		switch stored.Status {
		case "complete":
			rootCause = stored.Statement
		default:
			if stored.PartialReason != "" {
				rootCause = fmt.Sprintf("not determined (%s)", stored.PartialReason)
			}
		}
	}

	var (
		actionType, targetGVK, targetNamespace, targetName, paramsJSON string
		recommendationID                                               string
	)
	fixErr := tx.QueryRow(ctx, `
		SELECT id, action_type, target_gvk, COALESCE(target_namespace, ''), target_name, params::text
		  FROM remediation_recommendations
		 WHERE analysis_id = $1
		 ORDER BY created_at DESC
		 LIMIT 1
	`, analysisID).Scan(&recommendationID, &actionType, &targetGVK, &targetNamespace, &targetName, &paramsJSON)

	verdict := ""
	if fixErr == nil {
		// A plan exists for this analysis — see if it's already been decided.
		// pgx.ErrNoRows here just means "not decided yet" (or never will be,
		// e.g. it was superseded), not an error worth failing this whole
		// function over.
		_ = tx.QueryRow(ctx, `
			SELECT verdict FROM remediation_approval_decisions
			 WHERE recommendation_id = $1
			 ORDER BY created_at DESC
			 LIMIT 1
		`, recommendationID).Scan(&verdict)
	} else if fixErr != pgx.ErrNoRows {
		return embeddingInputs{}, fmt.Errorf("query remediation recommendation for analysis %s: %w", analysisID, fixErr)
	}

	fix := ""
	if fixErr == nil {
		fix = buildFix(actionType, targetGVK, targetNamespace, targetName, paramsJSON, verdict)
	}

	outcome := ""
	outcomeFinal := orchestrator.IsTerminalState(state)
	if outcomeFinal {
		outcome = state
	} else {
		outcome = fmt.Sprintf("not yet known (incident currently %s)", state)
	}

	return embeddingInputs{
		incidentID:   incidentID,
		symptom:      buildSymptom(openingReason, objectKey),
		rootCause:    rootCause,
		fix:          fix,
		outcome:      outcome,
		outcomeFinal: outcomeFinal,
	}, nil
}
