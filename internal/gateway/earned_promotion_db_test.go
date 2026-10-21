package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
	"argus/internal/tunnel"
)

// TestEarnedFaultPromotionEligible_DisabledIsANoOpWithNoQuery proves
// PROJECT.md B153's central safety property directly: with Enabled: false,
// earnedFaultPromotionEligible must return before ever touching tx. Passing
// a nil pgx.Tx is the proof — any code path that dereferenced it would
// panic, not silently return a wrong answer, so a passing test is a real
// guarantee, not a coincidence of what a fake happened to return.
func TestEarnedFaultPromotionEligible_DisabledIsANoOpWithNoQuery(t *testing.T) {
	f := &tunnel.Finding{Class: tunnel.FindingClassAnomaly, GVK: "v1/Pod", Namespace: "default", ObjectName: "x", Reason: "GenericDanglingReference:ServiceAccount"}
	eligible, why, err := earnedFaultPromotionEligible(context.Background(), nil, "clu_1", f, time.Now(), earnedPromotionConfig{Enabled: false})
	if err != nil {
		t.Fatalf("earnedFaultPromotionEligible: %v", err)
	}
	if eligible {
		t.Error("eligible = true with Enabled: false")
	}
	if why != "" {
		t.Errorf("why = %q, want empty", why)
	}
}

// TestEarnedFaultPromotionEligible_NonAnomalyIsANoOpWithNoQuery is the same
// proof for the other cheap short-circuit: a Fault- or Risk-classed Finding
// was never the noise this mechanism exists to earn a promotion out of, so
// it must never be queried against either, even with Enabled: true.
func TestEarnedFaultPromotionEligible_NonAnomalyIsANoOpWithNoQuery(t *testing.T) {
	f := &tunnel.Finding{Class: tunnel.FindingClassFault, GVK: "v1/Pod", Namespace: "default", ObjectName: "x", Reason: "CrashLoopBackOff"}
	eligible, _, err := earnedFaultPromotionEligible(context.Background(), nil, "clu_1", f, time.Now(), earnedPromotionConfig{Enabled: true})
	if err != nil {
		t.Fatalf("earnedFaultPromotionEligible: %v", err)
	}
	if eligible {
		t.Error("eligible = true for a non-Anomaly-classed Finding")
	}
}

// earnedPromotionTestCluster mirrors correlation_db_test.go's own
// correlationCluster/timelineTestCluster helpers — a throwaway cluster this
// file's tests insert findings rows against directly, tracked by a
// dbtest.Fixture so cleanup is exact.
func earnedPromotionTestCluster(t *testing.T, pool *pgxpool.Pool) (tenantID, clusterID string, fixture *dbtest.Fixture) {
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
	fixture = dbtest.New(t)
	fixture.OwnsCluster(tenantID, clusterID)
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "earned-promo-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	fixture.Created("clusters", 1)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}
	return tenantID, clusterID, fixture
}

// insertRawFinding writes one findings row directly (bypassing
// insertFindingRow/handleFinding entirely) — this file's tests are about
// earnedFaultPromotionEligible's own query, not about correlation, so
// building the exact history it reads is more direct than round-tripping
// through handleFinding.
//
// occurredAt and ingestedAt are BOTH explicit, and that is the point
// (PROJECT.md B155): occurred_at is the agent-supplied time the problem
// began (for a condition, its own lastTransitionTime — potentially days old
// and identical on every observation), while ingested_at is the hub-clock
// time each observation arrived. The live path leaves ingested_at to its
// DEFAULT now(); a test that did the same could only ever build rows whose
// ingest times are all "now", which is exactly the history that cannot
// exercise a sustained window at all.
func insertRawFinding(t *testing.T, pool *pgxpool.Pool, fixture *dbtest.Fixture, tenantID, clusterID, gvk, namespace, objectName, reason, signalClass string, occurredAt, ingestedAt time.Time) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint,
		    gvk, namespace, object_name, reason, message, occurrence_count, severity, occurred_at,
		    ingested_at, signal_class, confidence, impact)
		 VALUES ($1, $2, $3, 'k8s-test', 'v1', $4, $5, $6, $7, $8, 'test', 1, 'high', $9, $10, $11, 'unverified', 'none')`,
		domain.NewID(domain.PrefixFinding), tenantID, clusterID, "fp_"+domain.NewID(domain.PrefixFinding),
		gvk, namespace, objectName, reason, occurredAt, ingestedAt, signalClass); err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	fixture.Created("findings", 1)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// TestEarnedFaultPromotionEligible_RealHistory exercises all three
// criteria against a real database, one at a time, on the SAME
// (cluster, object, reason) — proving each is independently necessary, not
// just the conjunction happening to work in the success case.
//
// Every row here carries occurred_at == ingested_at deliberately: this is a
// GenericDanglingReference group, and that predicate computes its own
// observation clock rather than reading an object condition's
// lastTransitionTime, so the two clocks genuinely do agree sweep to sweep
// (confirmed live in PROJECT.md B155's own measurement). The case where
// they DISAGREE — a static lastTransitionTime — is
// TestEarnedFaultPromotionEligible_StaticConditionTransitionTimeStillEarnsSustainedWindow
// below.
func TestEarnedFaultPromotionEligible_RealHistory(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, fixture := earnedPromotionTestCluster(t, pool)
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "findings", SQL: `DELETE FROM findings WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})

	now := time.Now()
	gvk, ns, name, reason := "v1/RoleBinding", "b153-test", "rb-1", "GenericDanglingReference:ServiceAccount"
	cfg := earnedPromotionConfig{Enabled: true, MinObservations: 3, MinSustainedWindow: 30 * time.Minute, ObservationLookback: 24 * time.Hour, ImpactLookback: 2 * time.Hour}

	runTx := func(t *testing.T) (bool, string) {
		t.Helper()
		ctx := context.Background()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Fatalf("scope: %v", err)
		}
		f := &tunnel.Finding{Class: tunnel.FindingClassAnomaly, GVK: gvk, Namespace: ns, ObjectName: name, Reason: reason}
		eligible, why, err := earnedFaultPromotionEligible(ctx, tx, clusterID, f, now, cfg)
		if err != nil {
			t.Fatalf("earnedFaultPromotionEligible: %v", err)
		}
		return eligible, why
	}

	if eligible, why := runTx(t); eligible {
		t.Fatalf("eligible with zero observations: %s", why)
	}

	// Two observations 45 minutes apart: enough SPAN, not enough COUNT.
	insertRawFinding(t, pool, fixture, tenantID, clusterID, gvk, ns, name, reason, tunnel.FindingClassAnomaly, now.Add(-45*time.Minute), now.Add(-45*time.Minute))
	insertRawFinding(t, pool, fixture, tenantID, clusterID, gvk, ns, name, reason, tunnel.FindingClassAnomaly, now.Add(-1*time.Minute), now.Add(-1*time.Minute))
	if eligible, why := runTx(t); eligible {
		t.Fatalf("eligible with only 2 observations: %s", why)
	}

	// A third observation, but all three bunched within 2 minutes: enough
	// COUNT, not enough SPAN.
	insertRawFinding(t, pool, fixture, tenantID, clusterID, gvk, ns, name, reason, tunnel.FindingClassAnomaly, now.Add(-2*time.Minute), now.Add(-2*time.Minute))
	if eligible, why := runTx(t); eligible {
		t.Fatalf("eligible with 3 observations spanning only ~2 minutes: %s", why)
	}

	// Widen the span past MinSustainedWindow by adding an older observation:
	// now 4 observations spanning 45 minutes — count and span both satisfied,
	// but still no co-occurring Fault-classed finding on this object.
	insertRawFinding(t, pool, fixture, tenantID, clusterID, gvk, ns, name, reason, tunnel.FindingClassAnomaly, now.Add(-46*time.Minute), now.Add(-46*time.Minute))
	if eligible, why := runTx(t); eligible {
		t.Fatalf("eligible with no co-occurring Fault finding: %s", why)
	}

	// A Fault-classed finding on the SAME object (any reason) within
	// ImpactLookback — the last criterion — makes it eligible.
	insertRawFinding(t, pool, fixture, tenantID, clusterID, gvk, ns, name, "SomeOtherRealFault", tunnel.FindingClassFault, now.Add(-10*time.Minute), now.Add(-10*time.Minute))
	eligible, why := runTx(t)
	if !eligible {
		t.Fatalf("still not eligible once every criterion is met: %s", why)
	}
	if why == "" {
		t.Error("eligible with no reason given — an operator reading the log line needs to know why")
	}
}

// insertRawFindingWithReferences is insertRawFinding plus references_out —
// the shape a Finding whose object names other objects in its own
// spec/status carries (tunnel.Finding.References, PROJECT.md B153's
// addendum).
func insertRawFindingWithReferences(t *testing.T, pool *pgxpool.Pool, fixture *dbtest.Fixture, tenantID, clusterID, gvk, namespace, objectName, reason, signalClass string, occurredAt, ingestedAt time.Time, refs []tunnel.ObjectReference) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	encoded, err := json.Marshal(refs)
	if err != nil {
		t.Fatalf("encode references: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint,
		    gvk, namespace, object_name, reason, message, occurrence_count, severity, occurred_at,
		    ingested_at, signal_class, confidence, impact, references_out)
		 VALUES ($1, $2, $3, 'k8s-test', 'v1', $4, $5, $6, $7, $8, 'test', 1, 'high', $9, $10, $11, 'unverified', 'none', $12)`,
		domain.NewID(domain.PrefixFinding), tenantID, clusterID, "fp_"+domain.NewID(domain.PrefixFinding),
		gvk, namespace, objectName, reason, occurredAt, ingestedAt, signalClass, encoded); err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	fixture.Created("findings", 1)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// TestEarnedFaultPromotionEligible_ReferenceDirectionImpact is PROJECT.md
// B153's addendum regression test: the exact Gateway API shape the original
// same-object-only impact criterion cannot reach at all. A Gateway (Anomaly,
// Accepted=False) never carries a SECOND fault on itself — the consequence
// lands on an HTTPRoute that routes through it. The HTTPRoute's own Fault-
// classed finding must satisfy impact via its References pointing back at
// the Gateway, with no same-object fault anywhere.
func TestEarnedFaultPromotionEligible_ReferenceDirectionImpact(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, fixture := earnedPromotionTestCluster(t, pool)
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "findings", SQL: `DELETE FROM findings WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})

	now := time.Now()
	gwGVK, gwNS, gwName, reason := "gateway.networking.k8s.io/v1/Gateway", "b153-gw-test", "my-gateway", "GenericConditionAnomaly:Accepted"
	cfg := earnedPromotionConfig{Enabled: true, MinObservations: 3, MinSustainedWindow: 30 * time.Minute, ObservationLookback: 24 * time.Hour, ImpactLookback: 2 * time.Hour}

	// Sustained, corroborated: 3 observations spanning 45 minutes.
	insertRawFinding(t, pool, fixture, tenantID, clusterID, gwGVK, gwNS, gwName, reason, tunnel.FindingClassAnomaly, now.Add(-46*time.Minute), now.Add(-46*time.Minute))
	insertRawFinding(t, pool, fixture, tenantID, clusterID, gwGVK, gwNS, gwName, reason, tunnel.FindingClassAnomaly, now.Add(-20*time.Minute), now.Add(-20*time.Minute))
	insertRawFinding(t, pool, fixture, tenantID, clusterID, gwGVK, gwNS, gwName, reason, tunnel.FindingClassAnomaly, now.Add(-1*time.Minute), now.Add(-1*time.Minute))

	runTx := func(t *testing.T) (bool, string) {
		t.Helper()
		ctx := context.Background()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Fatalf("scope: %v", err)
		}
		f := &tunnel.Finding{Class: tunnel.FindingClassAnomaly, GVK: gwGVK, Namespace: gwNS, ObjectName: gwName, Reason: reason}
		eligible, why, err := earnedFaultPromotionEligible(ctx, tx, clusterID, f, now, cfg)
		if err != nil {
			t.Fatalf("earnedFaultPromotionEligible: %v", err)
		}
		return eligible, why
	}

	// No same-object fault, and no reference-direction fault yet either —
	// must not be eligible.
	if eligible, why := runTx(t); eligible {
		t.Fatalf("eligible with no impact signal of either kind: %s", why)
	}

	// An HTTPRoute's own Fault-classed finding, referencing an UNRELATED
	// Gateway — must not satisfy impact for THIS Gateway.
	insertRawFindingWithReferences(t, pool, fixture, tenantID, clusterID,
		"gateway.networking.k8s.io/v1/HTTPRoute", gwNS, "unrelated-route", "SomeRouteFault", tunnel.FindingClassFault, now.Add(-5*time.Minute), now.Add(-5*time.Minute),
		[]tunnel.ObjectReference{{Kind: "Gateway", Namespace: gwNS, Name: "some-other-gateway"}})
	if eligible, why := runTx(t); eligible {
		t.Fatalf("eligible via a reference to an unrelated Gateway: %s", why)
	}

	// An HTTPRoute's own Fault-classed finding, referencing THIS Gateway —
	// the reference-direction impact signal — makes it eligible, with no
	// same-object fault anywhere.
	insertRawFindingWithReferences(t, pool, fixture, tenantID, clusterID,
		"gateway.networking.k8s.io/v1/HTTPRoute", gwNS, "real-route", "BackendNotFound", tunnel.FindingClassFault, now.Add(-5*time.Minute), now.Add(-5*time.Minute),
		[]tunnel.ObjectReference{{Kind: "Gateway", Namespace: gwNS, Name: gwName}})
	eligible, why := runTx(t)
	if !eligible {
		t.Fatalf("still not eligible with a real reference-direction fault: %s", why)
	}
	if !strings.Contains(why, "reference-direction") {
		t.Errorf("why = %q, want it to name reference-direction specifically, not just \"a\" fault", why)
	}
}

// TestEarnedFaultPromotionEligible_StaticConditionTransitionTimeStillEarnsSustainedWindow
// is PROJECT.md B155's regression test, and the case that motivates the
// whole item: a condition that has NOT flapped since it appeared.
//
// Every observation below carries the identical, three-day-old occurred_at,
// because that is what checkGenericConditions reports for such a condition
// — the object's own lastTransitionTime (B154's fix, which must stay). Two
// separate things follow from that, and both are asserted directly against
// the pre-fix SQL on these same rows rather than merely described:
//
//   - max(occurred_at) - min(occurred_at) is exactly zero, so the old
//     sustained-window computation could never reach MinSustainedWindow no
//     matter how many observations accumulated or how long they spanned.
//   - the old ObservationLookback bound (occurred_at >= now - 24h) did not
//     even MATCH these rows, so the old code failed at the COUNT criterion
//     first, with "only 0 observation(s)" — which is why fixing the window
//     alone would have been inert.
//
// The fixed criterion reads ingested_at, the hub's own arrival clock, and
// must therefore let this group accumulate a real, nonzero window and
// ultimately earn promotion — while still refusing a burst of observations
// that arrived too close together, which the first assertion below pins
// down so the fix cannot degrade into "always sustained".
func TestEarnedFaultPromotionEligible_StaticConditionTransitionTimeStillEarnsSustainedWindow(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, fixture := earnedPromotionTestCluster(t, pool)
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "findings", SQL: `DELETE FROM findings WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})

	now := time.Now()
	// The object's own lastTransitionTime: three days old, and identical on
	// every observation — a persistent misconfiguration nobody has touched.
	transitioned := now.Add(-72 * time.Hour)
	gvk, ns, name, reason := "cert-manager.io/v1/Certificate", "b155-test", "cert-1", "GenericConditionAnomaly:Ready"
	cfg := earnedPromotionConfig{Enabled: true, MinObservations: 3, MinSustainedWindow: 30 * time.Minute, ObservationLookback: 24 * time.Hour, ImpactLookback: 2 * time.Hour}

	runTx := func(t *testing.T) (bool, string) {
		t.Helper()
		ctx := context.Background()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Fatalf("scope: %v", err)
		}
		f := &tunnel.Finding{Class: tunnel.FindingClassAnomaly, GVK: gvk, Namespace: ns, ObjectName: name, Reason: reason}
		eligible, why, err := earnedFaultPromotionEligible(ctx, tx, clusterID, f, now, cfg)
		if err != nil {
			t.Fatalf("earnedFaultPromotionEligible: %v", err)
		}
		return eligible, why
	}

	// Three observations that ARRIVED within three minutes of each other:
	// enough COUNT, not enough observed span. A static occurred_at must not
	// make this pass — the retry-burst shape the criterion exists to exclude
	// is still excluded.
	insertRawFinding(t, pool, fixture, tenantID, clusterID, gvk, ns, name, reason, tunnel.FindingClassAnomaly, transitioned, now.Add(-46*time.Minute))
	insertRawFinding(t, pool, fixture, tenantID, clusterID, gvk, ns, name, reason, tunnel.FindingClassAnomaly, transitioned, now.Add(-44*time.Minute))
	insertRawFinding(t, pool, fixture, tenantID, clusterID, gvk, ns, name, reason, tunnel.FindingClassAnomaly, transitioned, now.Add(-43*time.Minute))
	if eligible, why := runTx(t); eligible {
		t.Fatalf("eligible with 3 observations that all arrived within 3 minutes: %s", why)
	}

	// The agent keeps re-detecting the same unchanged condition 45 minutes
	// later. occurred_at is STILL the same three-day-old timestamp; only the
	// arrival clock has moved. Count and window are now both satisfied, and
	// the only thing left to fail on is impact.
	insertRawFinding(t, pool, fixture, tenantID, clusterID, gvk, ns, name, reason, tunnel.FindingClassAnomaly, transitioned, now.Add(-1*time.Minute))
	eligible, why := runTx(t)
	if eligible {
		t.Fatalf("eligible with no co-occurring Fault finding: %s", why)
	}
	if !strings.Contains(why, "45m0s") {
		t.Fatalf("why = %q, want a 45m0s observed window — a zero (or absent) window here means the sustained criterion is still being computed from the condition's own static occurred_at (PROJECT.md B155)", why)
	}

	// A Fault-classed finding on the same object: the impact criterion, which
	// deliberately still reads occurred_at (see hasFaultImpact's doc comment),
	// so this row's own occurred_at is what has to be recent.
	insertRawFinding(t, pool, fixture, tenantID, clusterID, gvk, ns, name, "CertificateRequestFailed", tunnel.FindingClassFault, now.Add(-10*time.Minute), now.Add(-10*time.Minute))
	eligible, why = runTx(t)
	if !eligible {
		t.Fatalf("a condition observed 4 times over 45 minutes, with same-object impact, still did not earn promotion: %s", why)
	}
	if !strings.Contains(why, "same-object") {
		t.Errorf("why = %q, want it to name which impact half fired", why)
	}

	// The pre-fix computation, run against these exact rows, to pin down what
	// was actually broken. Both numbers are asserted, so reverting either half
	// of the fix fails loudly here rather than silently agreeing.
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	var oldCount int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM findings
		  WHERE cluster_id = $1 AND gvk = $2 AND namespace = $3 AND object_name = $4
		    AND reason = $5 AND occurred_at >= $6`,
		clusterID, gvk, ns, name, reason, now.Add(-cfg.ObservationLookback)).Scan(&oldCount); err != nil {
		t.Fatalf("pre-fix lookback query: %v", err)
	}
	if oldCount != 0 {
		t.Errorf("pre-fix occurred_at lookback matched %d row(s), want 0 — this test's fixture no longer reproduces the bug it guards", oldCount)
	}
	var occurredSpread time.Duration
	if err := tx.QueryRow(ctx,
		`SELECT coalesce(max(occurred_at) - min(occurred_at), interval '0') FROM findings
		  WHERE cluster_id = $1 AND gvk = $2 AND namespace = $3 AND object_name = $4 AND reason = $5`,
		clusterID, gvk, ns, name, reason).Scan(&occurredSpread); err != nil {
		t.Fatalf("pre-fix spread query: %v", err)
	}
	if occurredSpread != 0 {
		t.Errorf("occurred_at spread = %s, want exactly 0 — this test's fixture no longer reproduces the bug it guards", occurredSpread)
	}
}
