package knowledge

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// This file is the read half of L2 (BACKLOG.md), deliberately deferred when
// store.go/migration 000082 landed: "do NOT wire retrieval into the
// investigation prompt until it would actually return something useful."
// This session's own governing brief re-opens that question explicitly —
// "build retrieval... measure it... if it does not measurably help, that is
// a real finding" — so this is that measurement's mechanism, not a decision
// that it already helps.
//
// # What this is NOT
//
// A retrieved analysis is a HYPOTHESIS to check, never a conclusion to reuse
// and never evidence — see PROJECT.md B151 for exactly why that distinction
// matters: crossCheckCausalChain only ever grades a citation against a REAL
// tool call this hub actually dispatched for THIS investigation. Retrieved
// text is prompt content, never a tool result and never a Finding — it has
// no EvidenceID, is never persisted into a causal chain step, and
// structurally CANNOT be marked "corroborated" by that mechanism, because it
// never enters it. FormatRetrievedForPrompt's own wording is the other half
// of that guarantee: the model is told, in the prompt itself, to treat each
// retrieved case as something to verify against this incident's own real
// findings, not as an answer already reached.

// RetrievedAnalysis is one prior analysis found similar to the incident
// currently being investigated, per RetrieveSimilar.
type RetrievedAnalysis struct {
	AnalysisID   string
	IncidentID   string
	EmbeddedText string
	OutcomeFinal bool
	// Distance is pgvector's own cosine distance (<=>) — 0 is identical,
	// larger is less similar. Carried for logging/measurement, not shown to
	// the model: a raw distance number means nothing to it, and stating one
	// risks reading as a confidence score this mechanism never computed.
	Distance float64
}

// retrieveDerefString mirrors internal/llm/prompt_findings.go's identical
// helper — duplicated rather than imported for the same reason
// splitObjectKey (text.go) already is: a three-line nil-safe deref is not
// worth a shared package, and this package cannot import internal/llm
// anyway (internal/orchestrator, which this package already imports,
// imports internal/llm itself — the reverse edge would cycle).
func retrieveDerefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// maxRetrievedAnalyses bounds how many prior cases ever reach the prompt —
// small on purpose. This is context to consider, not a second findings feed:
// BuildFindingsPrompt's own header explains at length what happens when an
// unbounded section is handed to a model or a `claude -p` argv, and this
// section adds to the same budget.
const maxRetrievedAnalyses = 3

// RetrieveSimilar finds prior analyses whose own (symptom, root cause, fix,
// outcome) embedding is closest to the CURRENT incident's symptom — read
// fresh from incidents.opening_reason/object_key, the same fields
// queryEmbeddingInputs uses to build the "symptom" component when THIS
// incident is eventually embedded itself.
//
// Runs inside the caller's own already-scoped transaction (tx) rather than
// opening a new one, unlike EmbedAnalysis — BuildFindingsPrompt's own
// callers (internal/api/analyze.go, internal/autoanalyze) already hold one
// scoped to the incident's tenant/cluster, and reusing it means this
// necessarily inherits the EXACT same RLS boundary that scope enforces:
// today that is one cluster, so retrieval is scoped to the SAME cluster's
// own history, not the whole fleet. Widening that to genuine cross-cluster
// retrieval is a real, separate decision (it would mean deliberately
// broadening the request scope beyond what an ordinary per-incident
// investigation transaction carries) — named here as a follow-on, not
// silently done.
//
// Excludes analysis_embeddings rows belonging to THIS incident's own past
// analyses (a re-analysis retrieving its own prior investigation is not
// "prior similar incidents," it is the same incident talking to itself).
//
// Safe to call on a nil *Store (returns nil, nil) — matches TriggerAsync's
// own nil-receiver convention, so a hub with embedding not configured needs
// no special-case branch AT THIS FUNCTION for that. This function itself has
// no product on/off switch of its own — that lives one level up, at both
// call sites, as settings.Config.RetrievalEnabled (migration 000102,
// default false): a live measurement found 31% higher cost with no
// measurable confidence benefit on one real repeated fault, an inconclusive
// result that must not ship as an unconditional cost increase just because
// embedding happens to be configured. Any other error this function itself
// returns (provider unreachable, current incident has no symptom text worth
// embedding, query failure) is non-fatal to the CALLER's own investigation —
// both call sites log it and continue with no retrieved context, the same
// posture TriggerAsync already established for embedding failures: this is
// an enhancement to the prompt, never a new hard dependency an investigation
// cannot proceed without.
func (s *Store) RetrieveSimilar(ctx context.Context, tx pgx.Tx, incidentID string) ([]RetrievedAnalysis, error) {
	if s == nil {
		return nil, nil
	}
	if s.provider == nil {
		return nil, fmt.Errorf("knowledge: no embedding provider configured")
	}

	var openingReason, objectKey *string
	if err := tx.QueryRow(ctx,
		`SELECT opening_reason, object_key FROM incidents WHERE id = $1`, incidentID,
	).Scan(&openingReason, &objectKey); err != nil {
		return nil, fmt.Errorf("read incident %s for retrieval query text: %w", incidentID, err)
	}
	querySymptom := buildSymptom(retrieveDerefString(openingReason), retrieveDerefString(objectKey))
	if strings.TrimSpace(querySymptom) == "" {
		// Nothing to embed a query against — an incident with neither an
		// opening reason nor an object identity (a fleet-group synthetic
		// incident, per buildSymptom's own doc comment) has no honest basis
		// for a similarity search. Not an error; there is simply nothing
		// retrievable to ask for.
		return nil, nil
	}

	queryVector, err := s.provider.Embed(ctx, querySymptom)
	if err != nil {
		return nil, fmt.Errorf("embed retrieval query for incident %s: %w", incidentID, err)
	}

	rows, err := tx.Query(ctx, `
		SELECT analysis_id, incident_id, embedded_text, outcome_final, embedding <=> $1::vector AS distance
		  FROM analysis_embeddings
		 WHERE incident_id != $2
		 ORDER BY embedding <=> $1::vector
		 LIMIT $3
	`, vectorLiteral(queryVector), incidentID, maxRetrievedAnalyses)
	if err != nil {
		return nil, fmt.Errorf("query analysis_embeddings for incident %s: %w", incidentID, err)
	}
	defer rows.Close()

	var results []RetrievedAnalysis
	for rows.Next() {
		var r RetrievedAnalysis
		if err := rows.Scan(&r.AnalysisID, &r.IncidentID, &r.EmbeddedText, &r.OutcomeFinal, &r.Distance); err != nil {
			return nil, fmt.Errorf("scan retrieved analysis for incident %s: %w", incidentID, err)
		}
		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate retrieved analyses for incident %s: %w", incidentID, err)
	}
	return results, nil
}

// FormatRetrievedForPrompt renders RetrieveSimilar's result as a prompt
// section, or "" for no results (never an empty header claiming similar
// cases exist when none were found). A pure function on purpose, same
// reasoning as BuildEmbeddedText: the wording that makes this safe to hand a
// model is worth unit-testing on its own, without a database.
//
// outcomeFinal is surfaced in prose ("this one was still open when
// recorded" vs the incident's own terminal state) because a prior case that
// never actually got confirmed fixed is weaker context than one that did,
// and the model should be able to tell the two apart rather than treating
// every retrieved case as equally settled.
func FormatRetrievedForPrompt(results []RetrievedAnalysis) string {
	if len(results) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("Prior similar investigations, found by semantic similarity to this incident's own symptom. " +
		"These are NOT this cluster's current state, NOT verified against it, and NOT evidence — each is a " +
		"PRIOR BELIEF about a different incident that may or may not share this one's actual cause. Treat each " +
		"as a hypothesis worth checking against the real findings below, never as a conclusion to cite or reuse " +
		"without checking:\n\n")
	for i, r := range results {
		status := "confirmed outcome"
		if !r.OutcomeFinal {
			status = "still open when this was recorded — treat its own outcome as unconfirmed too"
		}
		fmt.Fprintf(&b, "%d. (%s)\n%s\n\n", i+1, status, r.EmbeddedText)
	}
	b.WriteString("The findings below are this incident's own real evidence. Investigate them directly; " +
		"do not assume any prior case above still applies until you have checked it against what is actually " +
		"true here.\n\n")
	return b.String()
}
