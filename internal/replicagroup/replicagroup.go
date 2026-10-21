// Package replicagroup implements the write-time counterpart of
// BACKLOG.md's A3 entry, replica-level correlation half: persisting
// incidents.workload_group_id (migration 000042) whenever the SAME
// (workload_key, opening_reason) pair is currently open on more than one
// incident within a single cluster — e.g. two Pods of one Deployment both
// hitting OOMKilled, or (the measured case, CAPABILITIES.md §5) a missing
// ConfigMap producing FailedMount on two replicas at once.
//
// This is internal/fleetgroup's exact mechanism, re-scoped: fleetgroup
// groups incidents sharing a FINGERPRINT across DISTINCT CLUSTERS (a
// fleet-wide issue); this package groups incidents sharing a WORKLOAD +
// REASON within ONE cluster (sibling replicas of the same underlying
// fault). Both are deliberately display-only — neither ever merges
// incident state, findings, or lifecycle. A pod that gets fixed while its
// sibling doesn't must still be independently trackable; grouping only
// says "these are the same underlying fault," not "these are the same
// incident."
//
// NOT a new detection mechanism, and not built from a full ownership/
// reference graph — workload_key/opening_reason are supplied by the finding
// itself (internal/agent/workload.go resolves the owning workload agent-side,
// cheaply, from a Pod's own OwnerReferences at detection time; the hub joins
// them into a display key in internal/gateway/finding.go's
// workloadCorrelationKey). The harder cross-object case BACKLOG.md's A3 also
// names — a PVC that never binds and the Service whose workload never
// starts — needs an actual ownership/reference graph and remains open.
package replicagroup

import (
	"context"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"

	"argus/internal/domain"
)

// Recompute assigns, reuses, merges, or clears workload_group_id for every
// currently-open (state NOT IN ('Resolved', 'Dismissed')) incident on
// clusterID sharing (workload_key, opening_reason), based on how many such
// incidents currently exist. It is the single place in this codebase that
// ever writes incidents.workload_group_id.
//
// Call it exactly when an incident's open/closed status for a given
// (workload_key, opening_reason) pair might have just changed — the same two
// events fleetgroup.Recompute's own doc comment names, re-scoped to one
// cluster:
//
//   - internal/gateway.handleFinding, right after a Finding creates or bumps
//     an open incident whose workloadCorrelationKey is non-empty.
//   - internal/orchestrator.SetState, right after an incident carrying a
//     non-empty workload_key transitions TO a closed state.
//
// Grouping decision, given N = the number of currently-open incidents on
// clusterID sharing (workload_key, reason) (including the incident that
// triggered this call):
//
//   - N < 2: every one of them is ungrouped (workload_group_id set to NULL).
//     A workload+reason confined to one incident is not a replica-level
//     duplication, whether it never spread to a sibling or a sibling's
//     incident just closed.
//   - N >= 2 and none of them already carries a workload_group_id: a new one
//     is generated (domain.NewID(domain.PrefixWorkloadGroup)) and applied to
//     all of them.
//   - N >= 2 and exactly one distinct workload_group_id already exists among
//     them: that id is reused and applied to every one of them (including a
//     newcomer that had none).
//   - N >= 2 and more than one distinct workload_group_id already exists:
//     a merge, canonicalized to the lexicographically smallest (oldest,
//     since ids are ULIDs) of the colliding ids — identical reasoning to
//     fleetgroup.decideGroupID's own merge case, and equally expected to be
//     unreachable in practice given the advisory lock below, but handled
//     explicitly rather than left unconsidered.
//
// Concurrency: acquires pg_advisory_xact_lock(hashtext("replicagroup:" +
// clusterID + ":" + workloadKey + ":" + reason)) itself, transaction-scoped,
// mirroring fleetgroup.Recompute's own per-fingerprint lock for the identical
// reason. Callers must NOT acquire this lock themselves.
func Recompute(ctx context.Context, tx pgx.Tx, clusterID, workloadKey, reason string) error {
	lockKey := "replicagroup:" + clusterID + ":" + workloadKey + ":" + reason
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, lockKey); err != nil {
		return fmt.Errorf("replicagroup: acquire recompute lock for cluster %s workload %s reason %s: %w", clusterID, workloadKey, reason, err)
	}

	rows, err := tx.Query(ctx,
		`SELECT id, workload_group_id FROM incidents
		   WHERE cluster_id = $1 AND workload_key = $2 AND opening_reason = $3 AND state NOT IN ('Resolved', 'Dismissed')`,
		clusterID, workloadKey, reason)
	if err != nil {
		return fmt.Errorf("replicagroup: query open incidents for cluster %s workload %s reason %s: %w", clusterID, workloadKey, reason, err)
	}

	incidentCount := 0
	existingGroupIDs := map[string]bool{}
	for rows.Next() {
		var incidentID string
		var groupID *string
		if err := rows.Scan(&incidentID, &groupID); err != nil {
			rows.Close()
			return fmt.Errorf("replicagroup: scan open incident for cluster %s workload %s reason %s: %w", clusterID, workloadKey, reason, err)
		}
		incidentCount++
		if groupID != nil {
			existingGroupIDs[*groupID] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("replicagroup: read open incidents for cluster %s workload %s reason %s: %w", clusterID, workloadKey, reason, err)
	}

	target := decideGroupID(incidentCount, existingGroupIDs)

	if _, err := tx.Exec(ctx,
		`UPDATE incidents SET workload_group_id = $4
		   WHERE cluster_id = $1 AND workload_key = $2 AND opening_reason = $3 AND state NOT IN ('Resolved', 'Dismissed')`,
		clusterID, workloadKey, reason, target); err != nil {
		return fmt.Errorf("replicagroup: update workload_group_id for cluster %s workload %s reason %s: %w", clusterID, workloadKey, reason, err)
	}
	return nil
}

// decideGroupID is Recompute's pure decision logic, pulled out so it's
// unit-testable without a database — same discipline as
// fleetgroup.decideGroupID, which this deliberately does not import: the two
// count genuinely different things (distinct clusters vs. sibling incidents
// within one cluster), and duplicating ~15 lines of already-tested logic
// costs less than the coupling a shared export would add for two callers
// whose domain meaning differs. Returns nil to mean "clear
// workload_group_id" (a nil *string binds as SQL NULL via pgx).
func decideGroupID(incidentCount int, existingGroupIDs map[string]bool) *string {
	if incidentCount < 2 {
		return nil
	}

	switch len(existingGroupIDs) {
	case 0:
		id := domain.NewID(domain.PrefixWorkloadGroup)
		return &id
	case 1:
		for id := range existingGroupIDs {
			return &id
		}
	}

	ids := make([]string, 0, len(existingGroupIDs))
	for id := range existingGroupIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return &ids[0]
}
