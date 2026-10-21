package gateway

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/domain"
)

// PROJECT.md B138. Migration 000092's evidence backfill
// (internal/migrations/000092_finding_promotion_evidence.up.sql) was a
// one-shot UPDATE: any hub build that does not know findings.signal_class/
// confidence/impact exist — a rolled-back image, or the old replica of a
// rolling deploy still serving the tunnel — issues an INSERT that never
// mentions those three columns, so Postgres fills in the schema default
// ('fault','verified','degraded') right back in, re-creating exactly the
// rows 000092 corrected.
//
// internal/gateway/promotion.go's normalizeFindingEvidence, reached from
// handleFinding (finding.go), closes this for any Finding a CURRENT hub
// build processes. It cannot close it for a writer running OLDER code —
// there is no hub-code fix for a binary that predates the fix. Migration
// 000107 closes that half at the one layer every writer, however old, must
// still go through: a BEFORE INSERT OR UPDATE trigger on the findings table
// itself.
//
// This file proves that trigger, directly, by doing the thing no Go code
// path can: inserting a row with the three evidence columns OMITTED from
// the column list entirely — exactly what an INSERT statement written
// before these columns existed looks like — and confirming Postgres's own
// trigger machinery corrects it before the row is ever visible to a reader,
// regardless of which hub binary (if any) issued the INSERT.
//
// insertLaggingWriterFinding below bypasses internal/gateway/finding.go's
// insertFindingRow completely — it is a raw SQL INSERT naming NONE of
// signal_class/confidence/impact, which is the one thing insertFindingRow
// (a CURRENT build) never does. That is deliberate: this test is exercising
// the database's own defense, not this package's Go code, which the other
// tests in this package already cover.

// insertLaggingWriterFinding inserts one findings row the way a hub build
// that predates findings.signal_class/confidence/impact would — omitting
// all three from the column list so Postgres's schema defaults
// ('fault','verified','degraded') apply — and returns the row's id.
func insertLaggingWriterFinding(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, reason, fingerprint string) string {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	id := domain.NewID(domain.PrefixFinding)
	// Deliberately no signal_class/confidence/impact/references_out in this
	// column list — a pre-000092 INSERT could not have named them, and the
	// only thing standing in for that build's absent app-level gate is the
	// trigger migration 000107 installs on this table.
	if _, err := tx.Exec(ctx,
		`INSERT INTO findings (
		   id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk,
		   namespace, object_name, reason, message, severity, occurred_at
		 ) VALUES ($1, $2, $3, 'k8s-sweep', 'v1', $4, 'v1/ConfigMap', 'default', 'cm-test', $5, 'lagging writer simulation', 'low', now())`,
		id, tenantID, clusterID, fingerprint, reason); err != nil {
		t.Fatalf("insert lagging-writer finding: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return id
}

func readFindingEvidence(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, id string) (class, confidence, impact string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if err := tx.QueryRow(ctx,
		`SELECT signal_class, confidence, impact FROM findings WHERE id = $1`, id,
	).Scan(&class, &confidence, &impact); err != nil {
		t.Fatalf("read finding %s: %v", id, err)
	}
	return class, confidence, impact
}

// TestLegacyGenericEvidenceTriggerCorrectsLaggingWriter is the core
// re-runnability proof B138 asks for: a "lagging writer" INSERT (one that
// never names the evidence columns) lands already corrected, and a SECOND,
// independent lagging-writer event right after it is corrected too — the
// mechanism is not a one-shot fix that gets used up on the first bad row,
// and correcting the second row neither undoes nor duplicates the first
// row's correction.
func TestLegacyGenericEvidenceTriggerCorrectsLaggingWriter(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, fixture := timelineTestCluster(t, pool)
	// 2 reasons in the loop below, plus first/second for the re-runnability
	// check further down — 4 findings rows total, tracked upfront so
	// Cleanup's exact-count check (dbtest's whole point) still holds no
	// matter where in the test body each insert happens.
	fixture.Created("findings", 4)
	fixture.Created("incidents", 0)
	fixture.Created("timeline_events", 0)
	timelineCleanup(fixture, pool, tenantID, clusterID)

	for _, reason := range []string{
		"GenericConditionAnomaly:Ready",
		"GenericDanglingReference:Secret",
	} {
		t.Run(reason, func(t *testing.T) {
			id := insertLaggingWriterFinding(t, pool, tenantID, clusterID, reason, "test-fp-lagging-"+reason)
			class, confidence, impact := readFindingEvidence(t, pool, tenantID, clusterID, id)
			if class != "anomaly" || confidence != "unverified" || impact != "none" {
				t.Fatalf("lagging-writer row for reason %q landed as (%s,%s,%s), want (anomaly,unverified,none) — the schema default the trigger must intercept before this row is ever readable", reason, class, confidence, impact)
			}
		})
	}

	// Two independent lagging-writer events for the SAME reason, proving
	// the trigger fires per-row rather than being a one-time correction:
	// neither insert's correction depends on, undoes, or duplicates the
	// other's.
	first := insertLaggingWriterFinding(t, pool, tenantID, clusterID, "GenericPeerConditionShapeOutlier", "test-fp-lagging-first")
	second := insertLaggingWriterFinding(t, pool, tenantID, clusterID, "GenericPeerConditionShapeOutlier", "test-fp-lagging-second")

	fc, fconf, fimp := readFindingEvidence(t, pool, tenantID, clusterID, first)
	sc, sconf, simp := readFindingEvidence(t, pool, tenantID, clusterID, second)
	if fc != "anomaly" || fconf != "unverified" || fimp != "none" {
		t.Fatalf("first lagging-writer row = (%s,%s,%s), want (anomaly,unverified,none)", fc, fconf, fimp)
	}
	if sc != "anomaly" || sconf != "unverified" || simp != "none" {
		t.Fatalf("second lagging-writer row = (%s,%s,%s), want (anomaly,unverified,none) — the trigger must correct this write too, not just the first one", sc, sconf, simp)
	}
	// Re-reading the first row again, after the second insert, proves the
	// second correction did not disturb the first's.
	fc2, fconf2, fimp2 := readFindingEvidence(t, pool, tenantID, clusterID, first)
	if fc2 != fc || fconf2 != fconf || fimp2 != fimp {
		t.Fatalf("first lagging-writer row changed after a later, unrelated correction: was (%s,%s,%s), now (%s,%s,%s)", fc, fconf, fimp, fc2, fconf2, fimp2)
	}
}

// TestLegacyGenericEvidenceTriggerLeavesEverythingElseAlone pins the
// narrowness promotion.go's own comment relies on: the trigger must fire
// ONLY on the exact pre-evidence default triple on one of the three legacy
// generic reasons — never on an ordinary fault (whatever its reason), and
// never on a generic-reason row a real mechanism (the condition-polarity
// gate, earned fault promotion) has already, deliberately, classed
// differently. If this ever fails, the trigger's predicate has drifted from
// isPreEvidenceDefault/legacyGenericAnomaly in promotion.go and the two must
// be brought back in sync, not this test loosened.
func TestLegacyGenericEvidenceTriggerLeavesEverythingElseAlone(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, fixture := timelineTestCluster(t, pool)
	fixture.Created("findings", 3)
	fixture.Created("incidents", 0)
	fixture.Created("timeline_events", 0)
	timelineCleanup(fixture, pool, tenantID, clusterID)

	ctx := context.Background()
	insertWithExplicitEvidence := func(reason, class, confidence, impact, fingerprint string) string {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Fatalf("set request scope: %v", err)
		}
		id := domain.NewID(domain.PrefixFinding)
		if _, err := tx.Exec(ctx,
			`INSERT INTO findings (
			   id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk,
			   namespace, object_name, reason, message, severity, occurred_at,
			   signal_class, confidence, impact
			 ) VALUES ($1, $2, $3, 'k8s-sweep', 'v1', $4, 'v1/ConfigMap', 'default', 'cm-test', $5, 'test', 'low', now(), $6, $7, $8)`,
			id, tenantID, clusterID, fingerprint, reason, class, confidence, impact); err != nil {
			t.Fatalf("insert: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
		return id
	}

	// A real fault, unrelated reason, carrying the SAME triple the trigger
	// watches for on a Generic* reason — must be left alone, since the
	// trigger's reason check must exclude it.
	realFault := insertWithExplicitEvidence("PodCrashLoopBackOff", "fault", "verified", "degraded", "test-fp-real-fault")
	// A generic reason the condition-polarity gate already confirmed
	// (Confidence raised to verified, Class deliberately left at anomaly,
	// Impact still none per polarity_gate.go) — must be left alone too.
	polarityConfirmed := insertWithExplicitEvidence("GenericConditionAnomaly:Ready", "anomaly", "verified", "none", "test-fp-polarity-confirmed")
	// A generic reason earned fault promotion already upgraded (Class
	// flipped to fault, Confidence/Impact NOT raised to verified/degraded —
	// finding.go's B153 path only ever touches Class) — must be left alone:
	// this is exactly the case promotion.go's comment says the trigger must
	// never touch.
	earnedPromoted := insertWithExplicitEvidence("GenericDanglingReference:Secret", "fault", "unverified", "none", "test-fp-earned-promoted")

	if class, confidence, impact := readFindingEvidence(t, pool, tenantID, clusterID, realFault); class != "fault" || confidence != "verified" || impact != "degraded" {
		t.Fatalf("real fault with an unrelated reason was mutated to (%s,%s,%s) — the trigger must only match Generic* reasons", class, confidence, impact)
	}
	if class, confidence, impact := readFindingEvidence(t, pool, tenantID, clusterID, polarityConfirmed); class != "anomaly" || confidence != "verified" || impact != "none" {
		t.Fatalf("polarity-gate-confirmed row was mutated to (%s,%s,%s) — the trigger must only match the exact (fault,verified,degraded) triple", class, confidence, impact)
	}
	if class, confidence, impact := readFindingEvidence(t, pool, tenantID, clusterID, earnedPromoted); class != "fault" || confidence != "unverified" || impact != "none" {
		t.Fatalf("earned-promotion row was mutated to (%s,%s,%s) — the trigger must only match the exact (fault,verified,degraded) triple", class, confidence, impact)
	}
}
