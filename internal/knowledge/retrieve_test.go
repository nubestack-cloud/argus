package knowledge

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/domain"
	"argus/internal/orchestrator"
)

func TestFormatRetrievedForPrompt_Empty(t *testing.T) {
	if got := FormatRetrievedForPrompt(nil); got != "" {
		t.Errorf("FormatRetrievedForPrompt(nil) = %q, want empty string — no header claiming similar cases exist when none were found", got)
	}
	if got := FormatRetrievedForPrompt([]RetrievedAnalysis{}); got != "" {
		t.Errorf("FormatRetrievedForPrompt([]) = %q, want empty string", got)
	}
}

// PROJECT.md's "Learn" step brief, verbatim: a retrieved analysis must be
// "clearly labelled as prior belief, never as established fact, and never as
// evidence." This test pins the actual wording rather than trusting intent.
func TestFormatRetrievedForPrompt_NeverReadsAsEvidence(t *testing.T) {
	got := FormatRetrievedForPrompt([]RetrievedAnalysis{
		{AnalysisID: "an_1", IncidentID: "inc_1", EmbeddedText: "Symptom: OOMKilled\nRoot cause: memory limit too low", OutcomeFinal: true},
	})
	for _, want := range []string{"NOT evidence", "hypothesis", "Symptom: OOMKilled"} {
		if !strings.Contains(got, want) {
			t.Errorf("FormatRetrievedForPrompt output missing %q; got:\n%s", want, got)
		}
	}
}

func TestFormatRetrievedForPrompt_StatesWhetherOutcomeWasConfirmed(t *testing.T) {
	final := FormatRetrievedForPrompt([]RetrievedAnalysis{{EmbeddedText: "x", OutcomeFinal: true}})
	if !strings.Contains(final, "confirmed outcome") {
		t.Errorf("a terminal prior case should say its outcome was confirmed; got:\n%s", final)
	}
	open := FormatRetrievedForPrompt([]RetrievedAnalysis{{EmbeddedText: "x", OutcomeFinal: false}})
	if !strings.Contains(open, "still open") || !strings.Contains(open, "unconfirmed") {
		t.Errorf("a still-open prior case should say its own outcome is unconfirmed too; got:\n%s", open)
	}
}

func TestRetrieveSimilar_NilStoreIsANoOp(t *testing.T) {
	var s *Store
	results, err := s.RetrieveSimilar(context.Background(), nil, "inc_does_not_matter")
	if err != nil {
		t.Fatalf("RetrieveSimilar on a nil *Store returned an error: %v", err)
	}
	if results != nil {
		t.Fatalf("RetrieveSimilar on a nil *Store returned %v, want nil", results)
	}
}

// directionalProvider gives each test full control over which fixture is
// "closer" to the query, which the package's own fakeProvider cannot: that
// fixture's vectors are all positive scalar multiples of the all-ones
// direction (same text length -> identical vector; different lengths still
// share a direction), so cosine distance between any two of its outputs is
// always ~0 — useless for proving an ORDER BY embedding <=> query actually
// orders by real similarity. This one maps a chosen keyword inside the
// embedded text to an explicit direction instead.
type directionalProvider struct {
	dims     int
	keywords []struct {
		keyword string
		vector  []float32
	}
}

func (p *directionalProvider) Model() string   { return "directional-test-model" }
func (p *directionalProvider) Dimensions() int { return p.dims }
func (p *directionalProvider) Embed(_ context.Context, text string) ([]float32, error) {
	for _, kv := range p.keywords {
		if strings.Contains(text, kv.keyword) {
			return kv.vector, nil
		}
	}
	// An unrelated text gets an orthogonal fallback direction, so a fixture
	// that matches no keyword can never accidentally land nearest.
	v := make([]float32, p.dims)
	v[p.dims-1] = 1
	return v, nil
}

func directionVector(dims, axis int) []float32 {
	v := make([]float32, dims)
	v[axis] = 1
	return v
}

// TestRetrieveSimilar_OrdersByRealSimilarityAndExcludesOwnIncident is the
// core regression: given one incident under investigation and two OTHER
// incidents' embedded analyses — one whose fixture keyword maps to the SAME
// direction as the query, one to an ORTHOGONAL one — RetrieveSimilar must
// return the same-direction one first, and must never return the current
// incident's OWN embedded analysis (a re-analysis retrieving its own past
// self is not "a prior similar incident").
func TestRetrieveSimilar_OrdersByRealSimilarityAndExcludesOwnIncident(t *testing.T) {
	pool := testPool(t)
	const dims = DefaultEmbeddingDims

	// The incident currently being investigated — its OWN symptom is the
	// retrieval query text (buildSymptom(openingReason, objectKey)). Its
	// cluster is reused below for every other fixture: RetrieveSimilar runs
	// inside the caller's own already-scoped transaction (its own doc
	// comment explains why), so a fixture under a DIFFERENT cluster would be
	// invisible to it through RLS regardless of similarity — this test's
	// near/far fixtures must share one cluster to test similarity at all.
	_, currentClusterID, currentIncidentID, _ := testFixture(t, pool,
		orchestrator.StateInvestigating, "CurrentSymptomKeyword", "v1,Kind=Pod|ns/current-pod", "{}")
	tenantID := resolveTenantID(t, pool)

	// A SECOND analysis of the SAME (current) incident — e.g. a re-analysis's
	// own prior investigation. Must be excluded from the current retrieval
	// even though it is genuinely closest by construction (same keyword).
	ownPriorAnalysisID := domain.NewID(domain.PrefixAnalysis)
	insertBareAnalysis(t, pool, tenantID, currentClusterID, currentIncidentID, ownPriorAnalysisID)

	// A different incident, same cluster, same fault shape (near direction)
	// — the one retrieval SHOULD surface, and first.
	nearIncidentID, nearAnalysisID := insertBareIncidentAndAnalysis(t, pool, tenantID, currentClusterID,
		"CurrentSymptomKeyword", "v1,Kind=Pod|ns/other-pod-a")

	// A different incident, same cluster, unrelated fault shape (far
	// direction).
	farIncidentID, farAnalysisID := insertBareIncidentAndAnalysis(t, pool, tenantID, currentClusterID,
		"UnrelatedSymptomKeyword", "v1,Kind=Pod|ns/other-pod-b")

	near := directionVector(dims, 0)
	far := directionVector(dims, 1)
	provider := &directionalProvider{dims: dims, keywords: []struct {
		keyword string
		vector  []float32
	}{
		{"CurrentSymptomKeyword", near},
		{"UnrelatedSymptomKeyword", far},
	}}
	store := NewStore(pool, provider)

	// Embed all three OTHER analyses (own-prior, near, far) so they exist in
	// analysis_embeddings for RetrieveSimilar to find. The current incident's
	// OWN analysis is deliberately never embedded here — RetrieveSimilar
	// reads the current incident's live opening_reason/object_key directly,
	// not a stored embedding of itself.
	for _, id := range []string{ownPriorAnalysisID, nearAnalysisID, farAnalysisID} {
		if err := store.EmbedAnalysis(context.Background(), tenantID, currentClusterID, id); err != nil {
			t.Fatalf("embed analysis %s: %v", id, err)
		}
	}
	t.Cleanup(func() {
		withScopedTx(t, pool, tenantID, currentClusterID, func(ctx context.Context, tx pgx.Tx) {
			for _, id := range []string{ownPriorAnalysisID, nearAnalysisID, farAnalysisID} {
				_, _ = tx.Exec(ctx, `DELETE FROM analysis_embeddings WHERE analysis_id = $1`, id)
			}
		})
	})

	var results []RetrievedAnalysis
	withScopedTx(t, pool, tenantID, currentClusterID, func(ctx context.Context, tx pgx.Tx) {
		var err error
		results, err = store.RetrieveSimilar(ctx, tx, currentIncidentID)
		if err != nil {
			t.Fatalf("RetrieveSimilar: %v", err)
		}
	})

	for _, r := range results {
		if r.IncidentID == currentIncidentID {
			t.Fatalf("RetrieveSimilar returned the current incident's own analysis (%s) — a re-analysis must not retrieve itself; got %+v", r.AnalysisID, results)
		}
	}
	if len(results) != 2 {
		t.Fatalf("RetrieveSimilar returned %d results, want 2 (near and far, own-incident excluded): %+v", len(results), results)
	}
	if results[0].IncidentID != nearIncidentID {
		t.Fatalf("results[0].IncidentID = %q, want the near-direction incident %q (nearest-first ordering) — got order %+v",
			results[0].IncidentID, nearIncidentID, results)
	}
	if results[1].IncidentID != farIncidentID {
		t.Fatalf("results[1].IncidentID = %q, want the far-direction incident %q", results[1].IncidentID, farIncidentID)
	}
	if results[0].Distance >= results[1].Distance {
		t.Errorf("results[0].Distance = %v, results[1].Distance = %v — want the near case to have a strictly smaller distance", results[0].Distance, results[1].Distance)
	}
}

// TestRetrieveSimilar_NoSymptomText_ReturnsEmptyNotError covers an incident
// with neither an opening reason nor an object key (buildSymptom's own
// documented edge case, e.g. a fleet-group synthetic incident) — there is no
// honest query text to embed, so this must return an empty result rather
// than fabricating one or erroring the caller's whole investigation.
func TestRetrieveSimilar_NoSymptomText_ReturnsEmptyNotError(t *testing.T) {
	pool := testPool(t)
	_, clusterID, incidentID, _ := testFixture(t, pool, orchestrator.StateInvestigating, "", "", "{}")
	tenantID := resolveTenantID(t, pool)
	store := NewStore(pool, newFakeProvider(DefaultEmbeddingDims))

	var results []RetrievedAnalysis
	var err error
	withScopedTx(t, pool, tenantID, clusterID, func(ctx context.Context, tx pgx.Tx) {
		results, err = store.RetrieveSimilar(ctx, tx, incidentID)
	})
	if err != nil {
		t.Fatalf("RetrieveSimilar: %v", err)
	}
	if results != nil {
		t.Fatalf("results = %+v, want nil for an incident with no symptom text to query on", results)
	}
}

// insertBareAnalysis inserts a minimal, otherwise-unused analyses row
// against an EXISTING incident (unlike testFixture, which creates its own
// incident too) — for the "a second analysis of the SAME incident" case
// this file's own main test needs, which testFixture's one-incident-per-call
// shape cannot express directly.
func insertBareAnalysis(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID, analysisID string) {
	t.Helper()
	withScopedTx(t, pool, tenantID, clusterID, func(ctx context.Context, tx pgx.Tx) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO analyses (
			    id, incident_id, tenant_id, cluster_id, prompt_version, model, causal_chain, ruled_out,
			    root_cause, confidence, iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out,
			    cost_usd, cost_basis, triggered_by
			 ) VALUES ($1,$2,$3,$4,'v2-tool-loop','test-model','[]','[]','{}',0.9,1,100,0,0,0,0,'metered','manual')`,
			analysisID, incidentID, tenantID, clusterID); err != nil {
			t.Fatalf("insert bare analysis %s: %v", analysisID, err)
		}
	})
	t.Cleanup(func() {
		withScopedTx(t, pool, tenantID, clusterID, func(ctx context.Context, tx pgx.Tx) {
			_, _ = tx.Exec(ctx, `DELETE FROM analyses WHERE id = $1`, analysisID)
		})
	})
}

// insertBareIncidentAndAnalysis inserts a fresh incident AND its one
// analysis under an EXISTING cluster (unlike testFixture, which always
// creates its own fresh cluster) — for a test that needs several incidents
// to genuinely share one cluster's RLS scope, as RetrieveSimilar's own
// same-cluster-only design requires (see its doc comment).
func insertBareIncidentAndAnalysis(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, openingReason, objectKey string) (incidentID, analysisID string) {
	t.Helper()
	incidentID = domain.NewID(domain.PrefixIncident)
	analysisID = domain.NewID(domain.PrefixAnalysis)
	fingerprint := "test-knowledge-retrieval-" + incidentID

	withScopedTx(t, pool, tenantID, clusterID, func(ctx context.Context, tx pgx.Tx) {
		now := time.Now()
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, opening_reason, object_key)
			 VALUES ($1, $2, $3, $4, 'high', 'Resolved', $5, $5, 1, $6, $7)`,
			incidentID, tenantID, clusterID, fingerprint, now, openingReason, objectKey); err != nil {
			t.Fatalf("insert bare incident %s: %v", incidentID, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO analyses (
			    id, incident_id, tenant_id, cluster_id, prompt_version, model, causal_chain, ruled_out,
			    root_cause, confidence, iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out,
			    cost_usd, cost_basis, triggered_by
			 ) VALUES ($1,$2,$3,$4,'v2-tool-loop','test-model','[]','[]','{}',0.9,1,100,0,0,0,0,'metered','manual')`,
			analysisID, incidentID, tenantID, clusterID); err != nil {
			t.Fatalf("insert analysis %s for bare incident %s: %v", analysisID, incidentID, err)
		}
	})
	t.Cleanup(func() {
		withScopedTx(t, pool, tenantID, clusterID, func(ctx context.Context, tx pgx.Tx) {
			_, _ = tx.Exec(ctx, `DELETE FROM analysis_embeddings WHERE analysis_id = $1`, analysisID)
			_, _ = tx.Exec(ctx, `DELETE FROM analyses WHERE id = $1`, analysisID)
			_, _ = tx.Exec(ctx, `DELETE FROM incidents WHERE id = $1`, incidentID)
		})
	})
	return incidentID, analysisID
}
