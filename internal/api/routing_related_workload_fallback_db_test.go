package api

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/orchestrator"
)

// TestApplyRelatedWorkloadFallback is BUGS.md 124's reproduction and fix
// proof. Before this fix, gatherOwnershipFacts (used for incidents.route)
// and repoScopeForMCP (used to decide whether list_repo_files/read_repo_file
// are even offered) each carried their OWN copy of BUGS.md 118's "fall back
// to the related workload when the object's own answer is unmanaged" logic
// — and only gatherOwnershipFacts's copy actually existed; repoScopeForMCP's
// live fallback (repo_tools.go, before this fix) called only
// ownershipQueryTarget + a raw CallTool, with no reference anywhere to
// relatedWorkloadQueryTarget at all (confirmed by reading the pre-fix
// function: grep -c relatedWorkloadQueryTarget repo_tools.go was 0). So a
// cold first analysis on an incident whose own object resolves unmanaged
// but whose related workload has a real GitOps source would get
// `route: "pullRequest"` from gatherOwnershipFacts while list_repo_files
// failed outright from repoScopeForMCP on the exact same incident.
//
// Both call sites now go through the single applyRelatedWorkloadFallback
// function (via resolveLiveOwnership) exercised directly here, with a fake
// `ask` in place of a live tunnel call — this codebase's existing db_test
// precedent for this exact fallback (routing_related_workload_db_test.go)
// likewise never stands up a live tunnel/agent for it, verifying the
// decision logic itself and leaving the wire round trip to live-cluster
// evidence (see BUGS.md 118's own "Live evidence" sections).
func TestApplyRelatedWorkloadFallback(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	clusterID := domain.NewID(domain.PrefixCluster)
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, 'b124-cluster', 'Active', 'shard-test', $3)`,
		clusterID, tenantID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}

	now := time.Now()
	withResolvableRelated := domain.NewID(domain.PrefixIncident)
	noRelatedAtAll := domain.NewID(domain.PrefixIncident)
	withStillUnmanagedRelated := domain.NewID(domain.PrefixIncident)

	insert := func(id string, relatedKey *string) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, opening_reason, object_key, related_workload_key)
			 VALUES ($1, $2, $3, $4, 'high', 'Detected', $5, $5, 1, 'PersistentVolumeClaimOrphaned', 'v1/PersistentVolumeClaim|argus-b124|data-victim-2', $6)`,
			id, tenantID, clusterID, "b124fp-"+id, now, relatedKey); err != nil {
			t.Fatalf("insert incident %s: %v", id, err)
		}
	}
	resolvable := "apps/v1/StatefulSet|argus-b124|sts-victim"
	stillUnmanaged := "apps/v1/StatefulSet|argus-b124|sts-orphan-too"
	insert(withResolvableRelated, &resolvable)
	insert(noRelatedAtAll, nil)
	insert(withStillUnmanagedRelated, &stillUnmanaged)

	unmanagedRaw := json.RawMessage(`{"managed_by":"none"}`)
	unmanagedFacts := orchestrator.OwnershipFacts{Determined: true, ManagedBy: "none"}
	managedRaw := json.RawMessage(`{"managed_by":"argocd","repo":{"repo_url":"https://example.invalid/repo.git","applier":"argocd"}}`)
	managedFacts := orchestrator.OwnershipFacts{Determined: true, ManagedBy: "argocd", RepoKnown: true}

	t.Run("object unmanaged, related workload resolves to a real repo — adopts the related answer (the fix)", func(t *testing.T) {
		calls := 0
		ask := func(gvk, namespace, name string) (json.RawMessage, orchestrator.OwnershipFacts, error) {
			calls++
			if gvk != "apps/v1/StatefulSet" || namespace != "argus-b124" || name != "sts-victim" {
				t.Fatalf("ask called with unexpected tuple: %s|%s|%s", gvk, namespace, name)
			}
			return managedRaw, managedFacts, nil
		}
		raw, facts := applyRelatedWorkloadFallback(ctx, tx, withResolvableRelated, unmanagedRaw, unmanagedFacts, ask)
		if calls != 1 {
			t.Fatalf("ask called %d times, want 1", calls)
		}
		if facts.ManagedBy != "argocd" || !facts.RepoKnown {
			t.Fatalf("facts = %+v, want the related workload's managed/repo-known answer", facts)
		}
		if string(raw) != string(managedRaw) {
			t.Fatalf("raw = %s, want the related workload's raw answer", raw)
		}
	})

	t.Run("object unmanaged, no related_workload_key at all — stays unmanaged, ask never called (regression)", func(t *testing.T) {
		calls := 0
		ask := func(gvk, namespace, name string) (json.RawMessage, orchestrator.OwnershipFacts, error) {
			calls++
			return managedRaw, managedFacts, nil
		}
		raw, facts := applyRelatedWorkloadFallback(ctx, tx, noRelatedAtAll, unmanagedRaw, unmanagedFacts, ask)
		if calls != 0 {
			t.Fatalf("ask called %d times, want 0 — there is no related workload to ask about", calls)
		}
		if facts.ManagedBy != "none" || facts.RepoKnown {
			t.Fatalf("facts = %+v, want the object's own unchanged unmanaged answer", facts)
		}
		if string(raw) != string(unmanagedRaw) {
			t.Fatalf("raw = %s, want the object's own unchanged raw answer", raw)
		}
	})

	t.Run("object unmanaged, related workload is ALSO unmanaged — no regression, keeps the object's own answer", func(t *testing.T) {
		calls := 0
		ask := func(gvk, namespace, name string) (json.RawMessage, orchestrator.OwnershipFacts, error) {
			calls++
			return unmanagedRaw, unmanagedFacts, nil
		}
		raw, facts := applyRelatedWorkloadFallback(ctx, tx, withStillUnmanagedRelated, unmanagedRaw, unmanagedFacts, ask)
		if calls != 1 {
			t.Fatalf("ask called %d times, want 1", calls)
		}
		if facts.ManagedBy != "none" || facts.RepoKnown {
			t.Fatalf("facts = %+v, want the object's own unchanged unmanaged answer since the related workload was no improvement", facts)
		}
		if string(raw) != string(unmanagedRaw) {
			t.Fatalf("raw = %s, want the object's own unchanged raw answer", raw)
		}
	})

	t.Run("object already managed — never even reads related_workload_key", func(t *testing.T) {
		calls := 0
		ask := func(gvk, namespace, name string) (json.RawMessage, orchestrator.OwnershipFacts, error) {
			calls++
			return managedRaw, managedFacts, nil
		}
		raw, facts := applyRelatedWorkloadFallback(ctx, tx, withResolvableRelated, managedRaw, managedFacts, ask)
		if calls != 0 {
			t.Fatalf("ask called %d times, want 0 — the object's own answer is already resolved", calls)
		}
		if facts.ManagedBy != "argocd" || !facts.RepoKnown {
			t.Fatalf("facts = %+v, want the object's own unchanged managed answer", facts)
		}
		if string(raw) != string(managedRaw) {
			t.Fatalf("raw = %s, want the object's own unchanged raw answer", raw)
		}
	})
}
