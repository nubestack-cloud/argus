// Package objectgroup implements BACKLOG.md's A3b, the cross-object half of
// the "Noise and correlation" theme — the harder remainder left after A1
// (object-level correlation, internal/gateway's objectCorrelationKey,
// migration 000036) and A3a (replica-level correlation,
// internal/replicagroup, migration 000042) both landed.
//
// # What this groups, and why it is a THIRD mechanism rather than a reuse
//
// A1 folds every symptom of ONE object onto one incident. A3a folds several
// PODS of the SAME workload onto a shared display group. Neither touches the
// measured A3b case (CAPABILITIES.md §5): a PersistentVolumeClaim stuck
// Pending and the Service whose backing workload never started because of
// it are two DIFFERENT kinds of object, neither owning nor owned by the
// other — a PVC is referenced BY a Pod's volume, a Service's selector
// matches Pods it doesn't own. Kubernetes maintains no queryable graph for
// either relationship the way it does for OwnerReferences, so this codebase
// has to build and maintain that graph itself: internal/agent/objectref.go
// resolves, agent-side, which Pod(s) a broken PVC/Service relates to and
// what WORKLOAD those Pod(s) belong to (reusing the exact
// resolveWorkloadFromOwnerRefs walk A3a already relies on) — see that
// file's doc comment for the full mechanism and cost argument.
//
// This package is the hub-side counterpart, and it is deliberately a THIRD
// mechanism, not a rescoped call into internal/replicagroup, because the
// keys it joins are asymmetric in a way replicagroup's are not:
// replicagroup groups incidents that all carry the SAME (workload_key,
// opening_reason) — every member is a peer. objectgroup groups an
// "anchor" incident (a Pod-shaped Finding's own workload_key — the thing
// A3a already stamps) together with any incident whose object merely
// REFERENCES that anchor (a PVC's or Service's related_workload_key) — the
// members are not peers, they are "the workload" and "things that point at
// the workload". Modeling that as one replicagroup call with an extra
// column would blur a real distinction migration 000070's header explains
// at length: related_workload_key must NEVER be compared against itself the
// way workload_key is (two Services that happen to select the same
// nonexistent workload are not thereby related to EACH OTHER), only against
// workload_key. See Recompute's query below.
//
// # Read-only, exactly like fleetgroup/replicagroup before it
//
// object_group_id (migration 000070) is set/cleared/merged for DISPLAY only
// — it never merges incident state, findings, or lifecycle, and never
// changes which incident a Finding attaches to (that's
// internal/gateway/finding.go's correlationIdentity, which this package's
// anchor key — related_workload_key — is deliberately kept out of; see that
// field's own doc comment in migration 000070 for why a PVC/Service Finding
// must NOT be foldable into the Pod's own incident). A PVC that gets fixed
// while its Service's incident doesn't (or vice versa) must stay
// independently trackable — the same non-negotiable A3a's own package doc
// states for pod siblings, extended to cross-object siblings.
package objectgroup

import (
	"context"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"

	"argus/internal/domain"
)

// Recompute assigns, reuses, merges, or clears object_group_id for every
// currently-open (state NOT IN ('Resolved', 'Dismissed')) incident on
// clusterID that is either:
//
//   - the anchor: workload_key = anchorWorkloadKey (a Pod-shaped Finding's
//     own workload, A3a's existing column), or
//   - a reference to the anchor: related_workload_key = anchorWorkloadKey
//     (a PVC's or Service's Finding that resolved to this same workload,
//     migration 000070's new column).
//
// anchorWorkloadKey is always a WORKLOAD identity — "<gvk>|<ns>|<name>" —
// never an object_key or a PVC/Service's own identity; the caller passes
// whichever of an incident's workload_key/related_workload_key is
// non-empty (see internal/gateway/finding.go's call site and
// internal/orchestrator/db.go's close-time one). A no-op, not an error,
// when anchorWorkloadKey is "" — every call site already guards this, but
// Recompute guards it again rather than trust every future caller to.
//
// Call it exactly when an incident's open/closed status for this anchor
// might have just changed — the same two events fleetgroup.Recompute's and
// replicagroup.Recompute's own doc comments name, re-scoped to this
// package's asymmetric key:
//
//   - internal/gateway.handleFinding, right after a Finding creates or
//     bumps an open incident whose workload_key OR related_workload_key is
//     non-empty (called with whichever one is set).
//   - internal/orchestrator.SetState, right after an incident carrying
//     either column transitions TO a closed state.
//
// Grouping decision, given N = the number of currently-open incidents on
// clusterID matching the OR above (including the incident that triggered
// this call) — identical structure to replicagroup.decideGroupID, since the
// decision itself (not what it's applied to) is the same shape:
//
//   - N < 2: every one of them is ungrouped (object_group_id set to NULL).
//     An anchor with only ONE currently-open incident touching it — whether
//     that's just the workload's own incident with nothing yet pointing at
//     it, or just a PVC/Service incident with the workload's own incident
//     not (yet, or no longer) open — is not a cross-object correlation to
//     show.
//   - N >= 2 and none of them already carries an object_group_id: a new one
//     is generated (domain.NewID(domain.PrefixObjectGroup)) and applied to
//     all of them.
//   - N >= 2 and exactly one distinct object_group_id already exists among
//     them: that id is reused and applied to every one of them (including a
//     newcomer that had none).
//   - N >= 2 and more than one distinct object_group_id already exists: a
//     merge, canonicalized to the lexicographically smallest (oldest, since
//     ids are ULIDs) of the colliding ids — same reasoning as fleetgroup's
//     and replicagroup's own merge case, and equally expected to be
//     unreachable in practice given the advisory lock below.
//
// Concurrency: acquires pg_advisory_xact_lock(hashtext("objectgroup:" +
// clusterID + ":" + anchorWorkloadKey)), transaction-scoped, mirroring
// fleetgroup/replicagroup's own per-key lock for the identical reason.
// Callers must NOT acquire this lock themselves.
func Recompute(ctx context.Context, tx pgx.Tx, clusterID, anchorWorkloadKey string) error {
	if anchorWorkloadKey == "" {
		return nil
	}

	lockKey := "objectgroup:" + clusterID + ":" + anchorWorkloadKey
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, lockKey); err != nil {
		return fmt.Errorf("objectgroup: acquire recompute lock for cluster %s workload %s: %w", clusterID, anchorWorkloadKey, err)
	}

	rows, err := tx.Query(ctx,
		`SELECT id, object_group_id FROM incidents
		   WHERE cluster_id = $1 AND (workload_key = $2 OR related_workload_key = $2) AND state NOT IN ('Resolved', 'Dismissed')`,
		clusterID, anchorWorkloadKey)
	if err != nil {
		return fmt.Errorf("objectgroup: query open incidents for cluster %s workload %s: %w", clusterID, anchorWorkloadKey, err)
	}

	incidentCount := 0
	existingGroupIDs := map[string]bool{}
	for rows.Next() {
		var incidentID string
		var groupID *string
		if err := rows.Scan(&incidentID, &groupID); err != nil {
			rows.Close()
			return fmt.Errorf("objectgroup: scan open incident for cluster %s workload %s: %w", clusterID, anchorWorkloadKey, err)
		}
		incidentCount++
		if groupID != nil {
			existingGroupIDs[*groupID] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("objectgroup: read open incidents for cluster %s workload %s: %w", clusterID, anchorWorkloadKey, err)
	}

	target := decideGroupID(incidentCount, existingGroupIDs)

	if _, err := tx.Exec(ctx,
		`UPDATE incidents SET object_group_id = $3
		   WHERE cluster_id = $1 AND (workload_key = $2 OR related_workload_key = $2) AND state NOT IN ('Resolved', 'Dismissed')`,
		clusterID, anchorWorkloadKey, target); err != nil {
		return fmt.Errorf("objectgroup: update object_group_id for cluster %s workload %s: %w", clusterID, anchorWorkloadKey, err)
	}
	return nil
}

// decideGroupID is Recompute's pure decision logic, pulled out so it's
// unit-testable without a database — same discipline as
// fleetgroup.decideGroupID/replicagroup.decideGroupID, which this
// deliberately does not import or share: all three count genuinely
// different things, and duplicating ~15 lines of already-tested logic costs
// less than the coupling a shared export would add across three callers
// whose domain meaning differs (see replicagroup.decideGroupID's own doc
// comment for the same argument made first). Returns nil to mean "clear
// object_group_id" (a nil *string binds as SQL NULL via pgx).
func decideGroupID(incidentCount int, existingGroupIDs map[string]bool) *string {
	if incidentCount < 2 {
		return nil
	}

	switch len(existingGroupIDs) {
	case 0:
		id := domain.NewID(domain.PrefixObjectGroup)
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
