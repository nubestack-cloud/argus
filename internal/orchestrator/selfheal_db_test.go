package orchestrator

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
)

// PROJECT.md T4: "a fault that clears itself has no closure path" — proven
// live on two incidents that reached the identical dead end by different
// routes (gwas-frontend, isFault:false -> Diagnosed; gwas-db, a complete
// investigation with nothing to execute -> NeedsHumanInvestigation), and a
// third that must NEVER auto-close (a bound-hit, inconclusive investigation
// sitting in NeedsHumanInvestigation with no persisted root cause at all —
// closing that one would silently drop a fault nobody has actually looked
// at). This file drives sweepSelfHealing against real Postgres for all
// three, plus the recurrence guard.

// selfHealFixture inserts a throwaway cluster and returns a helper that adds
// one incident, with one analysis row behind it, in a single call — every
// test below needs exactly that shape, varying only the incident's state,
// the analysis's root_cause JSON, and the two clocks (last_seen, the
// analysis's created_at).
func selfHealFixture(t *testing.T, pool *pgxpool.Pool) (fixture *dbtest.Fixture, tenantID, clusterID string, addIncident func(state string, rootCause map[string]any, analysisCreatedAt, lastSeen time.Time) string) {
	t.Helper()
	ctx := context.Background()
	clusterID = domain.NewID(domain.PrefixCluster)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tenantID, err = data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "selfheal-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}
	fixture = dbtest.New(t)
	fixture.OwnsCluster(tenantID, clusterID)
	fixture.Created("clusters", 1)

	addIncident = func(state string, rootCause map[string]any, analysisCreatedAt, lastSeen time.Time) string {
		t.Helper()
		incidentID := domain.NewID(domain.PrefixIncident)
		analysisID := domain.NewID(domain.PrefixAnalysis)

		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin insert: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Fatalf("scope: %v", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
			 VALUES ($1, $2, $3, $4, 'high', $5, $6, $6, 1)`,
			incidentID, tenantID, clusterID, "selfheal-"+incidentID, state, lastSeen); err != nil {
			t.Fatalf("insert incident: %v", err)
		}
		rootCauseJSON, err := json.Marshal(rootCause)
		if err != nil {
			t.Fatalf("marshal root_cause: %v", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO analyses (id, tenant_id, incident_id, cluster_id, prompt_version, model,
			    causal_chain, iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd,
			    root_cause, created_at)
			 VALUES ($1,$2,$3,$4,'test','test-model','[]'::jsonb,1,1,0,0,0,0,$5,$6)`,
			analysisID, tenantID, incidentID, clusterID, rootCauseJSON, analysisCreatedAt); err != nil {
			t.Fatalf("insert analysis: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit insert: %v", err)
		}
		fixture.Created("incidents", 1)
		fixture.Created("analyses", 1)
		return incidentID
	}

	return fixture, tenantID, clusterID, addIncident
}

// cleanupSelfHealFixture runs fixture.Cleanup with the full delete list every
// test built on selfHealFixture needs. NOT called from inside selfHealFixture
// itself — every test here calls sweepSelfHealing, which may write a
// timeline_events row the fixture builder above could not have counted yet,
// so Created must be called for that count (0 or 1) before this runs,
// exactly the split validationResolveFixture/cleanupValidationResolveFixture
// already establish for the same reason in validation_timeline_db_test.go.
func cleanupSelfHealFixture(fixture *dbtest.Fixture, pool *pgxpool.Pool, tenantID, clusterID string) {
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "timeline_events", SQL: `DELETE FROM timeline_events WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "analyses", SQL: `DELETE FROM analyses WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})
}

// readSelfHealResult re-reads what sweepSelfHealing is supposed to have
// decided: the incident's current state, its resolution_kind (only set once
// Resolved), and the summary of its IncidentSelfHealed timeline event, if
// any was written.
func readSelfHealResult(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID string) (state string, resolutionKind *string, timelineCount int, summary string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin verify tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	if err := tx.QueryRow(ctx, `SELECT state, resolution_kind FROM incidents WHERE id = $1`, incidentID).Scan(&state, &resolutionKind); err != nil {
		t.Fatalf("read incident: %v", err)
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM timeline_events WHERE incident_id = $1 AND event_type = $2`,
		incidentID, "IncidentSelfHealed").Scan(&timelineCount); err != nil {
		t.Fatalf("count timeline events: %v", err)
	}
	if timelineCount > 0 {
		if err := tx.QueryRow(ctx,
			`SELECT payload->>'summary' FROM timeline_events WHERE incident_id = $1 AND event_type = $2 ORDER BY occurred_at DESC LIMIT 1`,
			incidentID, "IncidentSelfHealed").Scan(&summary); err != nil {
			t.Fatalf("read timeline summary: %v", err)
		}
	}
	return state, resolutionKind, timelineCount, summary
}

// TestSelfHealSweeper_DiagnosedClosesAfterQuietPeriod is PROJECT.md T4's
// first live case: gwas-frontend, isFault:false, Diagnosed — Advance's
// isFault:false branch never carries a plan, so this incident's only
// analysis is exactly what that branch produces: a complete root cause with
// no plan attached. Quiet well past validationGracePeriod, with nothing
// having recurred, must close it self_healed with no human action.
func TestSelfHealSweeper_DiagnosedClosesAfterQuietPeriod(t *testing.T) {
	pool := testPool(t)
	fixture, tenantID, clusterID, addIncident := selfHealFixture(t, pool)

	concludedAt := time.Now().Add(-validationGracePeriod - time.Hour)
	lastSeen := concludedAt.Add(-time.Minute) // quiet since before the conclusion, and ever since
	incidentID := addIncident(StateDiagnosed,
		map[string]any{"status": "complete", "statement": "PVC bound; the pod that failed to schedule is gone", "isFault": false},
		concludedAt, lastSeen)

	v := NewValidationSweeper(&data.DB{Pool: pool}, nil, nil)
	if err := v.sweepSelfHealing(context.Background()); err != nil {
		t.Fatalf("sweepSelfHealing: %v", err)
	}

	state, resolutionKind, timelineCount, summary := readSelfHealResult(t, pool, tenantID, clusterID, incidentID)
	if state != StateResolved {
		t.Fatalf("incident state = %q, want %q — a Diagnosed incident quiet well past the grace period must close on its own", state, StateResolved)
	}
	if resolutionKind == nil || *resolutionKind != "self_healed" {
		t.Fatalf("resolution_kind = %v, want %q", resolutionKind, "self_healed")
	}
	if timelineCount != 1 {
		t.Fatalf("IncidentSelfHealed timeline events = %d, want exactly 1", timelineCount)
	}
	if summary == "" {
		t.Error("timeline summary is empty, want the sweep's own evidence sentence")
	}

	fixture.Created("timeline_events", 1)
	cleanupSelfHealFixture(fixture, pool, tenantID, clusterID)
}

// TestSelfHealSweeper_NeedsHumanInvestigationWithPersistedRootCauseCloses is
// PROJECT.md T4's SECOND, independently-discovered live case: gwas-db — the
// model did not say "not a fault", it said the fault was real and had
// cleared, so Advance fell through to NeedsHumanInvestigation's no-plan
// branch instead of Diagnosed. isFault is never involved here at all (left
// nil, exactly as the live case had it) — proving the fix does not key on
// isFault, only on whether a root cause was actually persisted
// (root_cause->>'status' = 'complete').
func TestSelfHealSweeper_NeedsHumanInvestigationWithPersistedRootCauseCloses(t *testing.T) {
	pool := testPool(t)
	fixture, tenantID, clusterID, addIncident := selfHealFixture(t, pool)

	concludedAt := time.Now().Add(-validationGracePeriod - time.Hour)
	lastSeen := concludedAt.Add(-time.Minute)
	incidentID := addIncident(StateNeedsHumanInvestigation,
		map[string]any{"status": "complete", "statement": "Multi-Attach cleared once the old pod finished terminating"},
		concludedAt, lastSeen)

	v := NewValidationSweeper(&data.DB{Pool: pool}, nil, nil)
	if err := v.sweepSelfHealing(context.Background()); err != nil {
		t.Fatalf("sweepSelfHealing: %v", err)
	}

	state, resolutionKind, timelineCount, _ := readSelfHealResult(t, pool, tenantID, clusterID, incidentID)
	if state != StateResolved {
		t.Fatalf("incident state = %q, want %q — a NeedsHumanInvestigation incident with a persisted, complete root cause and no recurrence must close on its own, the same as Diagnosed", state, StateResolved)
	}
	if resolutionKind == nil || *resolutionKind != "self_healed" {
		t.Fatalf("resolution_kind = %v, want %q", resolutionKind, "self_healed")
	}
	if timelineCount != 1 {
		t.Fatalf("IncidentSelfHealed timeline events = %d, want exactly 1", timelineCount)
	}

	fixture.Created("timeline_events", 1)
	cleanupSelfHealFixture(fixture, pool, tenantID, clusterID)
}

// TestSelfHealSweeper_RecurrenceDuringGracePeriodPreventsClose is the
// companion the task's own test-first rule asks for: a Finding recurring
// during the grace window (last_seen bumped past the analysis's
// created_at, exactly what internal/gateway/finding.go's handleFinding
// already does unconditionally on any non-closed incident) must NOT be
// auto-closed — it stays exactly where it was, open, for a human or a fresh
// analysis to actually deal with. No StateReopened transition is expected
// here (see sweepSelfHealing's own "Recurrence" doc comment for why): the
// incident was never closed in the first place.
func TestSelfHealSweeper_RecurrenceDuringGracePeriodPreventsClose(t *testing.T) {
	pool := testPool(t)
	fixture, tenantID, clusterID, addIncident := selfHealFixture(t, pool)

	concludedAt := time.Now().Add(-validationGracePeriod - time.Hour)
	// last_seen AFTER the investigation concluded — a Finding correlated
	// back onto this incident (handleFinding's unconditional bump) after
	// ARGUS had already decided there was nothing to execute.
	recurredAt := concludedAt.Add(5 * time.Minute)
	incidentID := addIncident(StateDiagnosed,
		map[string]any{"status": "complete", "statement": "looked fixed, but recurred", "isFault": false},
		concludedAt, recurredAt)

	v := NewValidationSweeper(&data.DB{Pool: pool}, nil, nil)
	if err := v.sweepSelfHealing(context.Background()); err != nil {
		t.Fatalf("sweepSelfHealing: %v", err)
	}

	state, _, timelineCount, _ := readSelfHealResult(t, pool, tenantID, clusterID, incidentID)
	if state != StateDiagnosed {
		t.Fatalf("incident state = %q, want %q — a recurrence after the investigation concluded must NOT be auto-closed", state, StateDiagnosed)
	}
	if timelineCount != 0 {
		t.Fatalf("IncidentSelfHealed timeline events = %d, want 0 — nothing should have closed", timelineCount)
	}

	fixture.Created("timeline_events", 0)
	cleanupSelfHealFixture(fixture, pool, tenantID, clusterID)
}

// TestSelfHealSweeper_BoundHitInvestigationNeverAutoCloses is the guard
// against the wrong generalisation: NeedsHumanInvestigation is ALSO where a
// bound-hit, inconclusive investigation lands (Investigation.Status ==
// "partial" — no root cause was ever reached, let alone persisted). Closing
// that one on quiet alone would silently drop a fault nobody has actually
// looked at, which is a materially different and much worse mistake than
// leaving it open. root_cause->>'status' = 'partial' must exclude it from
// this sweep entirely, however long it has sat quiet.
func TestSelfHealSweeper_BoundHitInvestigationNeverAutoCloses(t *testing.T) {
	pool := testPool(t)
	fixture, tenantID, clusterID, addIncident := selfHealFixture(t, pool)

	concludedAt := time.Now().Add(-validationGracePeriod - 24*time.Hour) // very old — not a "not yet due" false negative
	lastSeen := concludedAt.Add(-time.Minute)
	incidentID := addIncident(StateNeedsHumanInvestigation,
		map[string]any{"status": "partial", "partialReason": "iteration_limit"},
		concludedAt, lastSeen)

	v := NewValidationSweeper(&data.DB{Pool: pool}, nil, nil)
	if err := v.sweepSelfHealing(context.Background()); err != nil {
		t.Fatalf("sweepSelfHealing: %v", err)
	}

	state, _, timelineCount, _ := readSelfHealResult(t, pool, tenantID, clusterID, incidentID)
	if state != StateNeedsHumanInvestigation {
		t.Fatalf("incident state = %q, want %q — a bound-hit investigation with no persisted root cause must never auto-close, no matter how long it has been quiet", state, StateNeedsHumanInvestigation)
	}
	if timelineCount != 0 {
		t.Fatalf("IncidentSelfHealed timeline events = %d, want 0", timelineCount)
	}

	fixture.Created("timeline_events", 0)
	cleanupSelfHealFixture(fixture, pool, tenantID, clusterID)
}

// TestSelfHealSweeper_NotYetDueLeavesItAlone confirms the floor itself is
// honoured: a Diagnosed incident whose investigation concluded only a
// minute ago must not close, even with nothing having recurred — this is
// the same "no news is good news, but only after actually waiting" contract
// sweep() enforces for the in-place/pull-request routes.
func TestSelfHealSweeper_NotYetDueLeavesItAlone(t *testing.T) {
	pool := testPool(t)
	fixture, tenantID, clusterID, addIncident := selfHealFixture(t, pool)

	concludedAt := time.Now().Add(-time.Minute)
	incidentID := addIncident(StateDiagnosed,
		map[string]any{"status": "complete", "statement": "just concluded", "isFault": false},
		concludedAt, concludedAt.Add(-time.Second))

	v := NewValidationSweeper(&data.DB{Pool: pool}, nil, nil)
	if err := v.sweepSelfHealing(context.Background()); err != nil {
		t.Fatalf("sweepSelfHealing: %v", err)
	}

	state, _, timelineCount, _ := readSelfHealResult(t, pool, tenantID, clusterID, incidentID)
	if state != StateDiagnosed {
		t.Fatalf("incident state = %q, want %q — the grace period has not elapsed yet", state, StateDiagnosed)
	}
	if timelineCount != 0 {
		t.Fatalf("IncidentSelfHealed timeline events = %d, want 0", timelineCount)
	}

	fixture.Created("timeline_events", 0)
	cleanupSelfHealFixture(fixture, pool, tenantID, clusterID)
}
