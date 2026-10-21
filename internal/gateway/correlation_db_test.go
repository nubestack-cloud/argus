package gateway

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
	"argus/internal/tunnel"
)

// correlationSetScope builds the setScope callback dbtest.Fixture.Cleanup
// needs — every cluster this file creates resolves to the same single
// organisation (data.SingleOrganisationID), so callers that discarded a
// per-call tenantID with `_` can safely reuse the outer one here.
func correlationSetScope(tenantID, clusterID string) func(context.Context, pgx.Tx) error {
	return func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}
}

// correlationIdentity.find is three SQL predicates running under FORCE ROW
// LEVEL SECURITY, so its real behaviour is a property of Postgres and not of Go.
// The interesting cases are all about what must NOT match — a terminal
// incident, another cluster's identical workload — and none of those can be
// shown without rows in a real table.
//
// Uses finding_db_test.go's testPool harness (argus_app, not the superuser, so
// these see the same RLS the hub does).

// correlationCluster inserts a throwaway cluster and returns a helper that
// adds incidents to it, plus the dbtest.Fixture tracking both — the caller
// must register its own Cleanup once it knows exactly what else (findings,
// remediation_executions/recommendations, analyses, ...) its own test body
// goes on to write, in the same dependency order the old hand-written
// cleanup used: findings and executions reference the cluster, and
// executions reference the recommendation; BUGS.md 119's evidence/
// analysis_embeddings-before-analyses ordering (no ON DELETE CASCADE) is
// preserved by whichever caller actually populates those tables.
func correlationCluster(t *testing.T, pool *pgxpool.Pool) (tenantID, clusterID string, add func(state, objectKey, workloadKey, fingerprint string, lastSeen time.Time) string, fixture *dbtest.Fixture) {
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
		clusterID, tenantID, "corr-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	fixture.Created("clusters", 1)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}

	add = func(state, objectKey, workloadKey, fingerprint string, lastSeen time.Time) string {
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
			   (id, tenant_id, cluster_id, fingerprint, object_key, workload_key, severity, state,
			    first_seen, last_seen, occurrence_count)
			 VALUES ($1, $2, $3, $4, $5, $6, 'high', $7, $8, $8, 1)`,
			id, tenantID, clusterID, fingerprint,
			nullIfBlank(objectKey), nullIfBlank(workloadKey), state, lastSeen); err != nil {
			t.Fatalf("insert incident: %v", err)
		}
		fixture.Created("incidents", 1)
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit insert: %v", err)
		}
		return id
	}
	return tenantID, clusterID, add, fixture
}

func nullIfBlank(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// runFind calls correlationIdentity.find in a transaction scoped the way
// handleFinding scopes its own — to the one cluster the finding arrived from.
func runFind(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID string, c correlationIdentity) (string, bool) {
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
	var id, state, severity string
	var lastSeen time.Time
	err = c.find(ctx, tx, &id, &lastSeen, &state, &severity)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false
	}
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	return id, true
}

func TestCorrelationIdentityFind(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, add, fixture := correlationCluster(t, pool)
	// Every incident below is inserted directly via `add` (deterministic —
	// no handleFinding involved), so only clusters+incidents are ever
	// touched by this fixture; one incident (pod A's — this cluster's own).
	fixture.Cleanup(pool, correlationSetScope(tenantID, clusterID), []dbtest.TableDelete{
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})
	now := time.Now()

	const workload = "apps/v1/Deployment|argus-test|web"

	// The incident pod A opened.
	podA := add("Detected", "v1/Pod|argus-test|web-aaa", workload, "fp_a", now.Add(-10*time.Minute))

	// A SECOND pod of the same workload must find pod A's incident rather than
	// opening its own. This is the whole change: without it, a rolling workload
	// opens a new incident per pod generation, without bound.
	podB := correlationIdentity{clusterID: clusterID, workloadKey: workload,
		objectKey: "v1/Pod|argus-test|web-bbb", fingerprint: "fp_b"}
	if got, found := runFind(t, pool, tenantID, clusterID, podB); !found || got != podA {
		t.Fatalf("a second pod of the same workload found %q (found=%v), want pod A's incident %s — one fault would open one incident per pod", got, found, podA)
	}

	// A DIFFERENT workload in the same namespace must not match.
	other := correlationIdentity{clusterID: clusterID, workloadKey: "apps/v1/Deployment|argus-test|api",
		objectKey: "v1/Pod|argus-test|api-xxx", fingerprint: "fp_x"}
	if got, found := runFind(t, pool, tenantID, clusterID, other); found {
		t.Errorf("an unrelated workload matched incident %s", got)
	}

	// A workload whose only incident is terminal must open a new one. Attaching
	// a live failure to a Resolved incident would resurrect closed history, and
	// attaching to a Dismissed one would override an operator's explicit
	// judgement.
	for _, terminal := range []string{"Resolved", "Dismissed"} {
		_, cl2, add2, fixture2 := correlationCluster(t, pool)
		add2(terminal, "v1/Pod|argus-test|done-aaa", workload, "fp_done", now)
		fixture2.Cleanup(pool, correlationSetScope(tenantID, cl2), []dbtest.TableDelete{
			{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{cl2}},
			{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{cl2}},
		})
		probe := correlationIdentity{clusterID: cl2, workloadKey: workload,
			objectKey: "v1/Pod|argus-test|done-bbb", fingerprint: "fp_done2"}
		if got, found := runFind(t, pool, tenantID, cl2, probe); found {
			t.Errorf("a %s incident was matched (%s) — a new failure must open a new incident", terminal, got)
		}
	}

	// Another cluster running the identical workload is a different workload.
	// workload_key is only unique within a cluster.
	_, otherCluster, addOther, fixtureOther := correlationCluster(t, pool)
	fixtureOther.Cleanup(pool, correlationSetScope(tenantID, otherCluster), []dbtest.TableDelete{
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{otherCluster}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{otherCluster}},
	})
	foreign := addOther("Detected", "v1/Pod|argus-test|web-zzz", workload, "fp_z", now)
	if got, found := runFind(t, pool, tenantID, clusterID, podB); !found || got == foreign {
		t.Errorf("cross-cluster bleed: found %q, want cluster %s's own incident %s (foreign incident was %s)", got, clusterID, podA, foreign)
	}
	_ = otherCluster

	// The object tier still works for a finding with no workload — a
	// Deployment-, Node-, PVC-, Service- or Ingress-level finding. This is the
	// regression guard for the tier that already existed.
	_, cl3, add3, fixture3 := correlationCluster(t, pool)
	fixture3.Cleanup(pool, correlationSetScope(tenantID, cl3), []dbtest.TableDelete{
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{cl3}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{cl3}},
	})
	svcIncident := add3("Detected", "v1/Service|argus-test|web", "", "fp_svc", now)
	svcProbe := correlationIdentity{clusterID: cl3, objectKey: "v1/Service|argus-test|web", fingerprint: "fp_svc_other"}
	if got, found := runFind(t, pool, tenantID, cl3, svcProbe); !found || got != svcIncident {
		t.Errorf("object-tier correlation broke: found %q (found=%v), want %s", got, found, svcIncident)
	}

	// And the fingerprint tier, which only matches incidents that named no
	// object at all.
	_, cl4, add4, fixture4 := correlationCluster(t, pool)
	fixture4.Cleanup(pool, correlationSetScope(tenantID, cl4), []dbtest.TableDelete{
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{cl4}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{cl4}},
	})
	bare := add4("Detected", "", "", "fp_bare", now)
	bareProbe := correlationIdentity{clusterID: cl4, fingerprint: "fp_bare"}
	if got, found := runFind(t, pool, tenantID, cl4, bareProbe); !found || got != bare {
		t.Errorf("fingerprint-tier correlation broke: found %q (found=%v), want %s", got, found, bare)
	}
	// A fingerprint probe must NOT match an incident that DID name an object.
	fpVsObject := correlationIdentity{clusterID: cl3, fingerprint: "fp_svc"}
	if got, found := runFind(t, pool, tenantID, cl3, fpVsObject); found {
		t.Errorf("a fingerprint-only probe matched object-keyed incident %s — the object_key IS NULL guard is not holding", got)
	}
}

// TestStaleEvidenceForReopen covers the guard that stopped a working fix being
// declared broken (WORKLOG §181).
//
// The measured case is the first subtest, and it is the reason this guard has
// two windows instead of one comparison: the fix executed at 19:52:16, the old
// pod's final BackOff event was stamped 19:52:17 — ONE SECOND LATER, because a
// rolling update takes seconds to remove the old pod — and a watch reconnect
// replayed it at 20:03:35. The new pod had been Running and healthy the whole
// time. A bare "did it occur after the execution?" test, which is what the first
// version of this guard did, calls that a recurrence and reopens.
func TestStaleEvidenceForReopen(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tenantID, clusterID, add, fixture := correlationCluster(t, pool)
	executedAt := time.Now().Add(-20 * time.Minute).Truncate(time.Second)
	incidentID := add("Validating", "v1/Pod|argus-test|web-aaa", "apps/v1/Deployment|argus-test|web", "fp_p", executedAt)

	// No execution yet: no fix to be stale relative to, so nothing may be
	// suppressed.
	if stale, _, err := runStale(t, pool, tenantID, clusterID, incidentID, executedAt.Add(-time.Hour), executedAt); err != nil {
		t.Fatalf("no-execution case: %v", err)
	} else if stale {
		t.Error("an incident with no execution suppressed a reopen — there is no fix for the finding to be stale against")
	}

	addExecutionRow(t, pool, fixture, tenantID, clusterID, incidentID, "succeeded", executedAt)
	// The pod this incident was opened on, reported BEFORE the fix — this is
	// what makes it "an object the fix could have replaced".
	addFindingRow(t, pool, fixture, tenantID, clusterID, incidentID, "v1/Pod", "argus-test", "web-aaa", executedAt.Add(-time.Minute))
	// One incident (add), one findings row (addFindingRow), and one each of
	// analyses/remediation_recommendations/remediation_executions
	// (addExecutionRow) — this fixture never writes evidence/
	// analysis_embeddings, so those two deletes are omitted rather than
	// tracked at 0.
	fixture.Cleanup(pool, correlationSetScope(tenantID, clusterID), []dbtest.TableDelete{
		{Table: "findings", SQL: `DELETE FROM findings WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "remediation_executions", SQL: `DELETE FROM remediation_executions WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "remediation_recommendations", SQL: `DELETE FROM remediation_recommendations WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "analyses", SQL: `DELETE FROM analyses WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})

	for _, tc := range []struct {
		name       string
		occurredAt time.Time
		now        time.Time
		wantStale  bool
	}{
		{
			// THE MEASURED CASE. Both windows are violated at once: inside the
			// roll settle window, and delivered eleven minutes late.
			name:       "the measured false reopen: one second after the fix, delivered 11 minutes later",
			occurredAt: executedAt.Add(time.Second),
			now:        executedAt.Add(11*time.Minute + 18*time.Second),
			wantStale:  true,
		},
		{
			// The roll window alone, with prompt delivery: the old pod's dying
			// gasp, arriving immediately. Still not a recurrence.
			name:       "inside the roll settle window even when delivered promptly",
			occurredAt: executedAt.Add(30 * time.Second),
			now:        executedAt.Add(31 * time.Second),
			wantStale:  true,
		},
		{
			// The delivery window alone: occurred well after the roll settled,
			// so it is about a post-fix pod, but arrived far too late to say
			// anything about the cluster's current state.
			name:       "occurred after the roll but delivered far too late",
			occurredAt: executedAt.Add(5 * time.Minute),
			now:        executedAt.Add(25 * time.Minute),
			wantStale:  true,
		},
		{
			name:       "clearly before the fix",
			occurredAt: executedAt.Add(-2 * time.Minute),
			now:        executedAt.Add(time.Minute),
			wantStale:  true,
		},
		{
			// A GENUINE recurrence must still reopen. This is the whole risk of
			// the guard, so it is asserted directly rather than assumed.
			name:       "after the roll settled and delivered promptly is a real recurrence",
			occurredAt: executedAt.Add(5 * time.Minute),
			now:        executedAt.Add(5*time.Minute + 10*time.Second),
			wantStale:  false,
		},
		{
			// Just past both windows: the boundary a real recurrence lands on
			// when the new pod fails as soon as it starts, and the resend
			// cooldown delivers the second report.
			name:       "just past the roll window, delivered promptly",
			occurredAt: executedAt.Add(rollSettleWindow + time.Second),
			now:        executedAt.Add(rollSettleWindow + 2*time.Second),
			wantStale:  false,
		},
		{
			// Fails open: an agent that sent no timestamp cannot be placed
			// either side of anything.
			name:       "zero timestamp fails open",
			occurredAt: time.Time{},
			now:        executedAt.Add(time.Minute),
			wantStale:  false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stale, why, err := runStale(t, pool, tenantID, clusterID, incidentID, tc.occurredAt, tc.now)
			if err != nil {
				t.Fatalf("staleEvidenceForReopen: %v", err)
			}
			if stale != tc.wantStale {
				t.Errorf("stale = %v, want %v (reason: %q)", stale, tc.wantStale, why)
			}
			if stale && why == "" {
				t.Error("suppressed a reopen without saying why — the log line is the only record an operator gets")
			}
		})
	}

	// THE REFINEMENT (measured on rke2): the REPLACEMENT pod failing nine
	// seconds after the fix is real evidence the fix did not work. It sits well
	// inside the roll settle window, and must still reopen — the window only
	// protects objects that existed before the fix.
	if stale, why, err := runStaleForObject(t, pool, tenantID, clusterID, incidentID,
		"v1/Pod", "argus-test", "web-NEW-after-fix", executedAt.Add(9*time.Second), executedAt.Add(11*time.Second)); err != nil {
		t.Fatalf("replacement-pod case: %v", err)
	} else if stale {
		t.Errorf("a pod first seen AFTER the fix was suppressed as pre-fix evidence (%s) — this is exactly the failure the fix was supposed to catch", why)
	}

	// And the same object, same instant, but known from before the fix: that one
	// IS the terminating pod, and must be suppressed.
	if stale, _, err := runStaleForObject(t, pool, tenantID, clusterID, incidentID,
		"v1/Pod", "argus-test", "web-aaa", executedAt.Add(9*time.Second), executedAt.Add(11*time.Second)); err != nil {
		t.Fatalf("terminating-pod case: %v", err)
	} else if !stale {
		t.Error("the pod the fix replaced was treated as a recurrence while it was still terminating")
	}

	// A FAILED execution is not a fix. A finding after it must reopen normally,
	// or a failed remediation would suppress the evidence that it failed.
	_, cl2, add2, fixture2 := correlationCluster(t, pool)
	failedIncident := add2("Validating", "v1/Pod|argus-test|f-aaa", "apps/v1/Deployment|argus-test|f", "fp_f", executedAt)
	addExecutionRow(t, pool, fixture2, tenantID, cl2, failedIncident, "failed", executedAt)
	// One incident (add2) plus one each of analyses/
	// remediation_recommendations/remediation_executions (addExecutionRow) —
	// no findings row in this section.
	fixture2.Cleanup(pool, correlationSetScope(tenantID, cl2), []dbtest.TableDelete{
		{Table: "remediation_executions", SQL: `DELETE FROM remediation_executions WHERE cluster_id = $1`, Args: []any{cl2}},
		{Table: "remediation_recommendations", SQL: `DELETE FROM remediation_recommendations WHERE cluster_id = $1`, Args: []any{cl2}},
		{Table: "analyses", SQL: `DELETE FROM analyses WHERE cluster_id = $1`, Args: []any{cl2}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{cl2}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{cl2}},
	})
	if stale, _, err := runStale(t, pool, tenantID, cl2, failedIncident, executedAt.Add(-time.Minute), executedAt); err != nil {
		t.Fatalf("failed-execution case: %v", err)
	} else if stale {
		t.Error("a FAILED execution suppressed a reopen — only a succeeded change can make an earlier finding stale, and suppressing here would hide the evidence that the remediation failed")
	}
	_ = ctx
}

// TestStaleEvidenceForReopen_PRMergedPath pins BUGS.md 138: an OpenPR fix
// never writes a remediation_executions row, so before this fix the ENTIRE
// staleness guard was a silent no-op for a PR-merged incident — this test
// reproduces the exact live shape (a replayed Event naming a pod Argo had
// already replaced, arriving minutes after the merge) and confirms it is now
// correctly suppressed, using pr_merged_at instead of an execution row.
func TestStaleEvidenceForReopen_PRMergedPath(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, add, fixture := correlationCluster(t, pool)
	mergedAt := time.Now().Add(-20 * time.Minute).Truncate(time.Second)
	incidentID := add("Validating", "v1/Pod|argus-test|nolimits-old", "apps/v1/Deployment|argus-test|nolimits", "fp_pr", mergedAt)
	setPRMergedAt(t, pool, tenantID, clusterID, incidentID, mergedAt)
	// The pod the PR-driven rollout replaced, reported before the merge.
	addFindingRow(t, pool, fixture, tenantID, clusterID, incidentID, "v1/Pod", "argus-test", "nolimits-old", mergedAt.Add(-time.Minute))
	// One incident (add) plus one findings row (addFindingRow, above) —
	// setPRMergedAt only UPDATEs the incident already tracked, no new row.
	fixture.Cleanup(pool, correlationSetScope(tenantID, clusterID), []dbtest.TableDelete{
		{Table: "findings", SQL: `DELETE FROM findings WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})

	// THE LIVE CASE: the old pod's Event last updated ~2 seconds after the
	// merge (right as Argo replaced it), replayed 12.5 minutes later by an
	// agent watch restart.
	if stale, _, err := runStaleForObject(t, pool, tenantID, clusterID, incidentID,
		"v1/Pod", "argus-test", "nolimits-old", mergedAt.Add(2*time.Second), mergedAt.Add(12*time.Minute+30*time.Second)); err != nil {
		t.Fatalf("PR-merged replay case: %v", err)
	} else if !stale {
		t.Error("a replayed Event for a pod the merge had already replaced was NOT suppressed — this is BUGS.md 138's exact live failure")
	}

	// A genuine recurrence on the SAME PR-merged incident must still reopen.
	if stale, _, err := runStaleForObject(t, pool, tenantID, clusterID, incidentID,
		"v1/Pod", "argus-test", "nolimits-new", mergedAt.Add(5*time.Minute), mergedAt.Add(5*time.Minute+10*time.Second)); err != nil {
		t.Fatalf("PR-merged genuine recurrence case: %v", err)
	} else if stale {
		t.Error("a genuine post-merge recurrence was suppressed on a PR-merged incident")
	}

	// No execution AND no validating_at: fails open exactly like the no-fix
	// case above.
	_, cl2, add2, fixture2 := correlationCluster(t, pool)
	noFixIncident := add2("Validating", "v1/Pod|argus-test|g-aaa", "apps/v1/Deployment|argus-test|g", "fp_g", mergedAt)
	fixture2.Cleanup(pool, correlationSetScope(tenantID, cl2), []dbtest.TableDelete{
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{cl2}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{cl2}},
	})
	if stale, _, err := runStale(t, pool, tenantID, cl2, noFixIncident, mergedAt.Add(-time.Hour), mergedAt); err != nil {
		t.Fatalf("no-fix-at-all case: %v", err)
	} else if stale {
		t.Error("an incident with neither an execution nor a merged PR suppressed a reopen")
	}
}

// setPRMergedAt sets incidents.pr_merged_at AND validating_at directly — the
// PR-path equivalent of addExecutionRow's in-place fix marker. Both, not
// just pr_merged_at: PROJECT.md B139 moved staleEvidenceForReopen's actual
// clock to validating_at (the real "fix landed" instant, stamped once
// MergeSweeper has already confirmed the sync — pr_merged_at alone is only
// the earlier GitHub-merge instant). This test fixture sets both to the
// SAME instant deliberately, since it is testing staleEvidenceForReopen's
// windows relative to a landing time, not B139's merge-vs-sync gap itself —
// that gap has its own dedicated live reproduction in docs/VERIFICATION.md.
func setPRMergedAt(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID string, mergedAt time.Time) {
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
	if _, err := tx.Exec(ctx, `UPDATE incidents SET pr_merged_at = $1, validating_at = $1 WHERE id = $2`, mergedAt, incidentID); err != nil {
		t.Fatalf("set pr_merged_at/validating_at: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// TestHandleFindingDoesNotAdvanceLastSeenForStaleValidatingEvidence pins
// PROJECT.md B150, the third validation-promotion defect of its class after
// B139 (wrong clock) and B143 (unreachable check). Unlike those two,
// staleEvidenceForReopen itself was already correct here — it judges a
// terminating pre-fix pod's dying event as NOT a recurrence, and handleFinding
// correctly left the incident in Validating rather than reopening it. The bug
// was one line downstream of that correct verdict: last_seen was still
// advanced past validating_at UNCONDITIONALLY, before the stale check ever
// ran. orchestrator.ValidationSweeper's candidate query
// (internal/orchestrator/validation.go) requires last_seen <= validating_at
// with zero tolerance, on the — until this bug — undisproven assumption that
// state='Validating' alone already guarantees that. Once last_seen crept a
// few hundred milliseconds past validating_at, the sweeper would never
// consider the incident again: not a delayed resolution, a PERMANENT one,
// silently sitting past its grace floor with zero further sweep activity
// until a human noticed. Reproduced live 2026-09-07 (breadth-campaign-round-4
// APP-005 fixture: a trailing finding from the terminating old pod arrived
// 12 seconds after validating_at, correctly judged stale, and the incident
// sat 22+ minutes past its grace floor while sibling incidents from the same
// batch cleared normally). Root-caused independently by two agents dispatched
// this session, converging on the same finding.go lines — this test pins the
// fix so last_seen and the reopen decision can never again disagree.
func TestHandleFindingDoesNotAdvanceLastSeenForStaleValidatingEvidence(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, add, fixture := correlationCluster(t, pool)
	g := &Gateway{db: &data.DB{Pool: pool}}
	ctx := context.Background()

	executedAt := time.Now().Add(-30 * time.Second).Truncate(time.Millisecond)
	incidentID := add("Validating", "v1/Pod|argus-test|b150-old", "apps/v1/Deployment|argus-test|b150", "fp_b150", executedAt)

	addExecutionRow(t, pool, fixture, tenantID, clusterID, incidentID, "succeeded", executedAt)
	// The pod this incident was opened on, reported BEFORE the fix — this is
	// what objectSeenBeforeFix needs to judge the recurring Finding below as
	// pre-fix evidence rather than a real recurrence.
	addFindingRow(t, pool, fixture, tenantID, clusterID, incidentID, "v1/Pod", "argus-test", "b150-old", executedAt.Add(-time.Minute))
	// One incident (add) plus one findings row (addFindingRow) plus one each
	// of analyses/remediation_recommendations/remediation_executions
	// (addExecutionRow), plus the ONE additional findings row handleFinding
	// itself inserts for the incoming Finding below. No timeline_events row:
	// the stale branch logs but does not write one (only reopenAfterRecurrence
	// does).
	fixture.Created("findings", 1)
	fixture.Cleanup(pool, correlationSetScope(tenantID, clusterID), []dbtest.TableDelete{
		{Table: "findings", SQL: `DELETE FROM findings WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "remediation_executions", SQL: `DELETE FROM remediation_executions WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "remediation_recommendations", SQL: `DELETE FROM remediation_recommendations WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "analyses", SQL: `DELETE FROM analyses WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})

	// THE LIVE CASE: the old pod's terminating event, 12 seconds after the
	// fix — well inside the 60s roll settle window.
	f := &tunnel.Finding{
		DetectorID:      "k8s-pod-conditions",
		DetectorVersion: "1",
		Fingerprint:     "test-fp-b150-recurrence-" + clusterID,
		GVK:             "v1/Pod",
		Namespace:       "argus-test",
		ObjectName:      "b150-old",
		ObjectUID:       "uid-b150-" + clusterID,
		ResourceVersion: "1",
		Reason:          "OOMKilled",
		Message:         "terminating pod's last event",
		OccurrenceCount: 1,
		Severity:        "high",
		OccurredAt:      executedAt.Add(12 * time.Second),
	}
	if err := g.handleFinding(ctx, clusterID, f); err != nil {
		t.Fatalf("handleFinding: %v", err)
	}

	verifyTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin verify tx: %v", err)
	}
	defer verifyTx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, verifyTx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	var state string
	var lastSeen time.Time
	var occurrenceCount int
	if err := verifyTx.QueryRow(ctx,
		`SELECT state, last_seen, occurrence_count FROM incidents WHERE id = $1`, incidentID,
	).Scan(&state, &lastSeen, &occurrenceCount); err != nil {
		t.Fatalf("look up incident: %v", err)
	}

	if state != "Validating" {
		t.Errorf("state = %q, want %q — this Finding is stale pre-fix evidence and must not reopen the incident", state, "Validating")
	}
	// occurrence_count still increments unconditionally — only last_seen's
	// advancement is gated on the stale verdict.
	if occurrenceCount != 2 {
		t.Errorf("occurrence_count = %d, want 2", occurrenceCount)
	}
	if !lastSeen.Equal(executedAt) {
		t.Errorf("last_seen = %s, want unchanged at %s (executedAt) — THE BUG: a stale Finding must never advance last_seen past validating_at, or orchestrator.ValidationSweeper's last_seen <= validating_at candidate query permanently excludes this incident",
			lastSeen.Format(time.RFC3339Nano), executedAt.Format(time.RFC3339Nano))
	}
}

func runStale(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID string, occurredAt, now time.Time) (bool, string, error) {
	// Defaults to the object the fixture's incident was opened on, so the
	// timestamp-only cases exercise the pre-existing-object path.
	return runStaleForObject(t, pool, tenantID, clusterID, incidentID, "v1/Pod", "argus-test", "web-aaa", occurredAt, now)
}

func runStaleForObject(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID, gvk, ns, name string, occurredAt, now time.Time) (bool, string, error) {
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
	f := &tunnel.Finding{GVK: gvk, Namespace: ns, ObjectName: name, OccurredAt: occurredAt}
	stale, why, _, err := staleEvidenceForReopen(ctx, tx, incidentID, f, now)
	return stale, why, err
}

// addFindingRow records a finding against an incident, which is what
// objectSeenBeforeFix reads to decide whether an object predates a fix.
// Tracks its own insert against fixture — the same *dbtest.Fixture
// correlationCluster returned for this cluster — since this is a
// fixture-owned insert (called directly, not through handleFinding) with a
// fully deterministic count.
func addFindingRow(t *testing.T, pool *pgxpool.Pool, fixture *dbtest.Fixture, tenantID, clusterID, incidentID, gvk, ns, name string, occurredAt time.Time) {
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
		    gvk, namespace, object_name, reason, message, occurrence_count, severity, occurred_at, incident_id)
		 VALUES ($1, $2, $3, 'k8s-test', 'v1', $4, $5, $6, $7, 'OOMKilled', 'test', 1, 'high', $8, $9)`,
		domain.NewID(domain.PrefixFinding), tenantID, clusterID, "fp_"+name+occurredAt.Format("150405"),
		gvk, ns, name, occurredAt, incidentID); err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	fixture.Created("findings", 1)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// addExecutionRow records a full analysis/recommendation/execution chain
// against an incident — three fixture-owned inserts, tracked against fixture
// the same way addFindingRow does.
func addExecutionRow(t *testing.T, pool *pgxpool.Pool, fixture *dbtest.Fixture, tenantID, clusterID, incidentID, outcome string, executedAt time.Time) {
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
	analysisID := domain.NewID(domain.PrefixAnalysis)
	recID := domain.NewID(domain.PrefixPlan)
	if _, err := tx.Exec(ctx,
		`INSERT INTO analyses (id, tenant_id, incident_id, cluster_id, prompt_version, model, causal_chain,
		    iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd)
		 VALUES ($1, $2, $3, $4, 'test', 'test-model', '[]'::jsonb, 1, 1, 0, 0, 0, 0)`,
		analysisID, tenantID, incidentID, clusterID); err != nil {
		t.Fatalf("insert analysis: %v", err)
	}
	fixture.Created("analyses", 1)
	if _, err := tx.Exec(ctx,
		`INSERT INTO remediation_recommendations
		   (id, incident_id, tenant_id, cluster_id, analysis_id, action_type, target_gvk,
		    target_namespace, target_name, params, reversible, risk_level, gate_outcome, gate_reason)
		 VALUES ($1, $2, $3, $4, $5, 'PatchResourceLimits', 'apps/v1/Deployment',
		         'argus-test', 'web', '{}'::jsonb, true, 'medium', 'NeedsApproval', 'test')`,
		recID, incidentID, tenantID, clusterID, analysisID); err != nil {
		t.Fatalf("insert recommendation: %v", err)
	}
	fixture.Created("remediation_recommendations", 1)
	if _, err := tx.Exec(ctx,
		`INSERT INTO remediation_executions
		   (id, recommendation_id, incident_id, tenant_id, cluster_id, outcome, executed_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		domain.NewID(domain.PrefixExecution), recID, incidentID, tenantID, clusterID, outcome, executedAt); err != nil {
		t.Fatalf("insert execution: %v", err)
	}
	fixture.Created("remediation_executions", 1)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}
