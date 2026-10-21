package orchestrator

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
)

// siblingStillFailing is a SQL predicate running under FORCE ROW LEVEL SECURITY,
// so its real behaviour is a property of live Postgres and not of Go. Reviewing
// it is not enough: the B2 bug earlier this session was a query that compiled,
// ran, and silently matched nothing because the transaction's RLS scope was
// empty, and this query runs in exactly that kind of transaction — the sweep's
// fleet-wide one. A test with no database could not tell the difference between
// "no sibling" and "RLS hid the sibling", which is the one distinction that
// matters here.
//
// Uses db_test.go's testPool harness (argus_app, not the superuser).

// siblingFixture inserts a throwaway cluster and returns a helper that adds
// incidents to it, plus the tenant to scope transactions to.
func siblingFixture(t *testing.T, pool *pgxpool.Pool) (tenantID, clusterID string, addIncident func(state, workloadKey, reason string, lastSeen time.Time) string) {
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
		clusterID, tenantID, "sibling-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}
	fixture := dbtest.New(t)
	fixture.OwnsCluster(tenantID, clusterID)
	fixture.Created("clusters", 1)

	addIncident = func(state, workloadKey, reason string, lastSeen time.Time) string {
		t.Helper()
		id := domain.NewID(domain.PrefixIncident)
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin insert: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Fatalf("scope: %v", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents
			   (id, tenant_id, cluster_id, fingerprint, severity, state,
			    first_seen, last_seen, occurrence_count, workload_key, opening_reason)
			 VALUES ($1, $2, $3, $4, 'high', $5, $6, $6, 1, $7, $8)`,
			id, tenantID, clusterID, "sib-"+id, state, lastSeen,
			nullIfEmpty(workloadKey), nullIfEmpty(reason)); err != nil {
			t.Fatalf("insert incident: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit insert: %v", err)
		}
		fixture.Created("incidents", 1)
		return id
	}

	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})
	return tenantID, clusterID, addIncident
}

func TestSiblingStillFailing(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tenantID, clusterID, addIncident := siblingFixture(t, pool)

	const workload = "apps/v1/Deployment|argus-test|sib-target"
	executedAt := time.Now().Add(-30 * time.Minute)

	// The subject: the remediated incident, watching a pod the fix rolled away.
	subject := addIncident(StateValidating, workload, "OOMKilled", executedAt.Add(-5*time.Minute))
	base := resolvableIncident{
		IncidentID:  subject,
		ClusterID:   clusterID,
		ExecutionID: "exec_test",
		FixLandedAt: executedAt,
		WorkloadKey: workload,
	}

	// A workload with no other incidents on it: the fix looks good, and this
	// must stay the common case or every successful remediation reopens.
	if detail, failing := runSibling(t, ctx, pool, tenantID, clusterID, base); failing {
		t.Fatalf("a workload with no other incidents reported a sibling: %s", detail)
	}

	// The live case (WORKLOG §178): a new pod, same workload, failing since the
	// fix. This is the whole point — the subject's own fingerprint can never
	// recur because the object it names no longer exists.
	newPod := addIncident(StateDetected, workload, "OOMKilled", executedAt.Add(10*time.Minute))
	detail, failing := runSibling(t, ctx, pool, tenantID, clusterID, base)
	if !failing {
		t.Fatal("a sibling incident failing AFTER the fix was not detected — the incident would resolve while its workload is still broken, which is the bug this exists to stop")
	}
	if !strings.Contains(detail, newPod) {
		t.Errorf("reason %q does not name the sibling incident %s — an operator cannot check the claim", detail, newPod)
	}

	// A symptom that CHANGED rather than stopped is still not fixed. Asserted
	// because requiring opening_reason equality (which replicagroup.Recompute
	// does group on) would silently resolve this.
	if _, failing := runSibling(t, ctx, pool, tenantID, clusterID, base); !failing {
		t.Fatal("precondition for the reason-mismatch case failed")
	}
	mustExec(t, ctx, pool, tenantID, clusterID,
		`UPDATE incidents SET opening_reason = 'CrashLoopBackOff' WHERE id = $1`, newPod)
	if _, failing := runSibling(t, ctx, pool, tenantID, clusterID, base); !failing {
		t.Error("a sibling with a DIFFERENT opening_reason was ignored — a partial fix that turns OOMKilled into CrashLoopBackOff would be reported as a success")
	}

	// Terminal siblings are history, not evidence. Both terminal states, because
	// a Dismissed sibling reopening the subject would be an operator's explicit
	// judgement being overridden.
	for _, state := range []string{StateResolved, StateDismissed} {
		mustExec(t, ctx, pool, tenantID, clusterID,
			`UPDATE incidents SET state = $2 WHERE id = $1`, newPod, state)
		if detail, failing := runSibling(t, ctx, pool, tenantID, clusterID, base); failing {
			t.Errorf("a %s sibling was treated as an active failure (%s)", state, detail)
		}
	}

	// An OLD sibling — active, same workload, but last seen BEFORE the fix — is
	// evidence the fix worked. Reopening on it would make every remediation on a
	// workload with any prior incident unresolvable.
	mustExec(t, ctx, pool, tenantID, clusterID,
		`UPDATE incidents SET state = 'Detected', last_seen = $2 WHERE id = $1`,
		newPod, executedAt.Add(-time.Minute))
	if detail, failing := runSibling(t, ctx, pool, tenantID, clusterID, base); failing {
		t.Errorf("a sibling last seen BEFORE the fix was read as a recurrence (%s)", detail)
	}

	// Another cluster's copy of the same workload_key is a different workload.
	// workload_key is only unique within a cluster, and cross-cluster bleed here
	// would reopen incidents on clusters nobody remediated.
	_, otherCluster, addOther := siblingFixture(t, pool)
	addOther(StateDetected, workload, "OOMKilled", executedAt.Add(10*time.Minute))
	if detail, failing := runSibling(t, ctx, pool, tenantID, clusterID, base); failing {
		t.Errorf("another cluster's copy of the same workload_key reopened this incident (%s) — cluster %s is unrelated", detail, otherCluster)
	}

	// No workload_key (a bare Pod, a Service — nothing owns it): nothing to ask
	// about, and the fingerprint-recurrence path already covers an object that
	// survives its own fix.
	noKey := base
	noKey.WorkloadKey = ""
	if detail, failing := runSibling(t, ctx, pool, tenantID, clusterID, noKey); failing {
		t.Errorf("an incident with no workload_key found a sibling (%s)", detail)
	}
}

// runSibling calls siblingStillFailing in a transaction scoped the way the sweep
// scopes its own: fleet-wide, no cluster narrowing. That is the scope the B2 bug
// lived in, so testing under any narrower one would test the wrong thing.
func runSibling(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, clusterID string, c resolvableIncident) (string, bool) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("scope: %v", err)
	}
	detail, failing, err := siblingStillFailing(ctx, tx, c)
	if err != nil {
		t.Fatalf("siblingStillFailing: %v", err)
	}
	return detail, failing
}

func mustExec(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, clusterID, sql string, args ...any) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	if _, err := tx.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}
