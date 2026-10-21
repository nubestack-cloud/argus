// Package fleetgroup implements the write-time counterpart of
// DESIGN.md §15.1's "fleet-wide issue groups surfaced
// first" fleet-overview requirement: persisting incidents.fleet_group_id
// (migration 000005_incidents_and_analysis.up.sql — the column and its
// incidents_fleet_group_idx index have existed since that migration, with
// nothing anywhere in this codebase ever setting or reading either, until
// this package) whenever the SAME fingerprint (internal/agent/detector.go's
// computeFingerprint — sha256(namespace, kind, name, reason), which
// deliberately excludes cluster identity, per that function's own doc
// comment) is currently open on more than one cluster at once.
//
// This is NOT a new detection mechanism. internal/gateway.handleFinding
// already correlates a Finding into a per-(cluster_id, fingerprint)
// incident; internal/api/insights.go's queryIssueClasses already computes
// an ad hoc, read-time, all-history "how many clusters has this fingerprint
// ever touched" number for the Insights screen. This package is the third,
// narrower thing: a persisted, currently-open-only grouping of incidents
// that already exist, so a fleet-wide problem can be surfaced as ONE row
// instead of requiring an operator to notice, unaided, that three
// cluster-local incidents happen to share a fingerprint.
//
// # Why there is still exactly one key here, and not a coarser second tier
//
// PROJECT.md's E16 proposed adding a coarser "issue class" key beside the
// exact fingerprint — (kind, reason, owning-workload name) — on the theory
// that the fingerprint's inclusion of the object NAME stops Pod-level faults
// from ever grouping across clusters, leaving this package dormant. That was
// measured against the real incident table before being built, and the
// measurement did not support it. Recorded here because the theory is
// plausible enough that it will be proposed again.
//
//   - Of 58 currently-open incidents, 8 are Pod-level with a resolved
//     workload. The rest are Certificates, Nodes, Jobs, Services, PVCs,
//     ClusterRepos and similar — cluster-scoped or namespace-singleton
//     objects whose names are ALREADY identical across clusters, so the exact
//     fingerprint groups them with nothing to relax. Pod-level faults are not
//     the dominant shape of this table, which is the premise E16 rests on.
//   - Keying on (kind, reason, workload name) grouped the same 3 groups / 4
//     incidents as the exact fingerprint: no gain. Over all history (139
//     incidents from real agent findings, 9 clusters) it moved 20 grouped
//     incidents to 21.
//   - The only coarsening that did move the number — dropping the object name
//     to (kind, namespace, reason), 4 groups / 8 incidents — bought it by
//     merging unrelated workloads: 3 of its 4 groups mixed 2-3 distinct
//     workloads, e.g. coredns and kube-apiserver both under
//     "v1/Pod|kube-system|Unhealthy". A display row claiming a fleet-wide
//     issue that is really two problems is worse than no row.
//   - The dev fleet's apparent cross-cluster groups are an artefact: the two
//     "clusters" carrying them are two enrollments of one physical rke2
//     cluster (which is why a Pod name matched across them down to its
//     ReplicaSet hash). Counting those as one, NO key — exact or coarse —
//     produces a single genuine cross-cluster group. This package is dormant
//     because this fleet has no genuinely shared faults on distinct clusters,
//     not because its key is too tight.
//
// One trap worth keeping if a coarser tier is ever revisited: it must be a
// function of the FINGERPRINT, not of the individual incident. incidents
// .workload_key is best-effort (the agent may or may not resolve an owner),
// so keying on it per-incident SPLITS groups the fingerprint already holds —
// measured, on the pair of argus-agent-sideload incidents, which the exact
// key groups and a naive workload key does not.
//
// Neither this package's key nor any coarser one may be fed into
// internal/gateway/finding.go's correlationIdentity. That is the object_key
// lesson recorded there: a grouping key decides what is DISPLAYED together,
// never which incident a Finding attaches to or which findings are collapsed
// into one.
package fleetgroup

import (
	"context"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"

	"argus/internal/domain"
)

// ClosedStates mirrors internal/migrations/000005_incidents_and_analysis
// .up.sql's incidents.state CHECK constraint's two terminal-for-correlation
// values — the exact same set internal/gateway/finding.go's own
// closedIncidentStates already hardcoded before this package existed; that
// file now delegates to ClosedStates/IsClosedState (see its own comment)
// rather than keeping a second, independently-maintained copy, now that a
// second consumer (this package, and internal/orchestrator.SetState) needs
// the identical definition.
var ClosedStates = map[string]bool{
	"Resolved":  true,
	"Dismissed": true,
}

// IsClosedState reports whether state counts as "closed" for fleet-group
// (and handleFinding's per-cluster) correlation-matching purposes.
func IsClosedState(state string) bool {
	return ClosedStates[state]
}

// Recompute assigns, reuses, merges, or clears fleet_group_id for every
// currently-open (state NOT IN ('Resolved', 'Dismissed'), matching
// IsClosedState) incident sharing fingerprint, based on how many distinct
// clusters currently have one open. It is the single place in this codebase
// that ever writes incidents.fleet_group_id.
//
// Call it exactly when an incident's open/closed status for a given
// fingerprint might have just changed — the only two events that can:
//
//   - internal/gateway.handleFinding, right after a Finding creates or
//     bumps an open incident (that incident just entered, or stayed inside,
//     this fingerprint's open set).
//   - internal/orchestrator.SetState, right after an incident's state
//     changes TO a closed state (that incident just left the open set —
//     the group may need to shrink or disband).
//
// Grouping decision, given N = the number of distinct cluster_ids with a
// currently-open incident on this fingerprint (including the incident that
// triggered this call):
//
//   - N < 2: every currently-open incident on this fingerprint is ungrouped
//     (fleet_group_id set to NULL). A fingerprint confined to one cluster is
//     not a fleet-wide issue, whether it never spread or it just stopped
//     being one (the other cluster's incident closed) — see this package's
//     test file for the explicit "does a group un-group when it drops to
//     one cluster" judgment call this resolves in favor of "yes."
//   - N >= 2 and none of these incidents already carries a fleet_group_id:
//     a brand new one is generated (domain.NewID(domain.PrefixFleetGroup))
//     and applied to all of them — this is "two previously-unrelated
//     single-cluster incidents both now need to join the same group."
//   - N >= 2 and exactly one distinct fleet_group_id already exists among
//     them: that id is reused and applied to every open incident on this
//     fingerprint (including a newcomer that had none) — "a third cluster
//     joins an existing group."
//   - N >= 2 and MORE than one distinct fleet_group_id already exists among
//     them: a merge. Deterministically canonicalized to the
//     lexicographically smallest of the colliding ids — since ids are
//     ULIDs (domain.NewID), that's the OLDEST of the colliding groups, so a
//     merge keeps the longest-lived group's identity rather than picking
//     arbitrarily. This branch IS reachable, and routinely so: fleet_group_id
//     is one column, but an incident collects several symptoms (migration
//     000036), so one incident can be a member of two different fingerprints'
//     groups at once. Whichever of the two Recompute calls runs second sees
//     both ids on that shared incident and collapses them onto the older one,
//     which is why the merge must be deterministic rather than arbitrary —
//     an arbitrary winner would let the pair flap between two ids on every
//     recurrence. The advisory lock below serialises same-fingerprint racers;
//     it does not and cannot serialise two DIFFERENT fingerprints that happen
//     to share an incident, which is the case this branch settles.
//
// Concurrency: acquires pg_advisory_xact_lock(hashtext("fleetgroup:" +
// fingerprint)) itself, transaction-scoped (released automatically at
// commit/rollback) — mirroring internal/gateway/finding.go's own
// per-(cluster_id, fingerprint) advisory lock, for the identical reason
// stated there: two concurrent callers racing to recompute the SAME
// fingerprint's group membership (e.g. a Finding arriving for cluster A at
// the same instant an operator resolves the open incident on cluster B)
// must never interleave their read-then-decide-then-write sequences.
// Callers must NOT acquire this lock themselves — Recompute always does,
// unconditionally, as its first statement.
func Recompute(ctx context.Context, tx pgx.Tx, fingerprint string) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "fleetgroup:"+fingerprint); err != nil {
		return fmt.Errorf("fleetgroup: acquire recompute lock for fingerprint %s: %w", fingerprint, err)
	}

	// Which open incidents involve this fingerprint — resolved through
	// FINDINGS, not through incidents.fingerprint.
	//
	// That indirection became necessary with migration 000036's object-level
	// correlation. incidents.fingerprint used to identify an incident; it now
	// records only the symptom that OPENED it, because several symptoms on one
	// object are deliberately collected into a single incident. Reading the
	// incident column directly would therefore silently stop grouping any
	// fingerprint that only ever arrived as a second or later symptom — a
	// cluster running the same fault as three others would drop out of the
	// fleet group, and the failure mode is invisible: fewer clusters listed,
	// no error anywhere.
	//
	// Going through findings.fingerprint is also simply more correct than the
	// old query, independent of 000036: it asks "which open incidents has this
	// symptom actually been seen on", which is the question fleet grouping
	// means to ask. DISTINCT because one incident can hold many findings
	// sharing a fingerprint (every recurrence past the resend cooldown).
	rows, err := tx.Query(ctx,
		`SELECT DISTINCT i.id, i.cluster_id, i.fleet_group_id
		   FROM incidents i
		   JOIN findings f ON f.incident_id = i.id
		  WHERE f.fingerprint = $1 AND i.state NOT IN ('Resolved', 'Dismissed')`,
		fingerprint)
	if err != nil {
		return fmt.Errorf("fleetgroup: query open incidents for fingerprint %s: %w", fingerprint, err)
	}

	memberIDs := []string{}
	clusters := map[string]bool{}
	existingGroupIDs := map[string]bool{}
	for rows.Next() {
		var incidentID, clusterID string
		var groupID *string
		if err := rows.Scan(&incidentID, &clusterID, &groupID); err != nil {
			rows.Close()
			return fmt.Errorf("fleetgroup: scan open incident for fingerprint %s: %w", fingerprint, err)
		}
		memberIDs = append(memberIDs, incidentID)
		clusters[clusterID] = true
		if groupID != nil {
			existingGroupIDs[*groupID] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("fleetgroup: read open incidents for fingerprint %s: %w", fingerprint, err)
	}

	target := decideGroupID(len(clusters), existingGroupIDs)

	// Write to the SAME set the decision above was made from, plus the rows
	// the old predicate alone reached.
	//
	// The read half was moved onto findings.fingerprint (see the comment on
	// the query above) precisely because incidents.fingerprint records only
	// the symptom that OPENED an incident. The write half was left on
	// `WHERE fingerprint = $1`, so it reproduced, in the UPDATE, exactly the
	// failure that comment describes: an incident that carries this
	// fingerprint as a SECOND or later symptom counted toward
	// distinctClusterCount but was never stamped with the group id that count
	// produced, and a stale id on such an incident was never cleared either.
	// Measured on the dev incident table (2026-09-23): 2 of the 4 currently-
	// open incidents that a findings-resolved recompute places in a fleet
	// group hold their group's fingerprint as a non-opening symptom, and one
	// live fleet group had exactly one member left in it as a result.
	//
	// `id = ANY($2)` is that member set, carried over from the read rather
	// than recomputed, so the two halves cannot drift apart again. The
	// `fingerprint = $1` arm is retained rather than replaced because
	// `findings` is partitioned on occurred_at and its partitions are dropped
	// by finding_retention_days (migration 000021), independently of
	// incident_retention_days: an old open incident whose findings have aged
	// out resolves through no finding at all, and dropping the arm would
	// leave any stale fleet_group_id on it permanently unclearable. Such a
	// row is written but not counted — which is what the read half already
	// did before this change, so the counting side is unchanged.
	if _, err := tx.Exec(ctx,
		`UPDATE incidents SET fleet_group_id = $3
		   WHERE state NOT IN ('Resolved', 'Dismissed')
		     AND (fingerprint = $1 OR id = ANY($2))`,
		fingerprint, memberIDs, target); err != nil {
		return fmt.Errorf("fleetgroup: update fleet_group_id for fingerprint %s: %w", fingerprint, err)
	}
	return nil
}

// decideGroupID is Recompute's pure decision logic, pulled out so it's
// unit-testable without a database (see fleetgroup_test.go) — the same
// "SQL stays a thin shell around a tested Go function" discipline
// internal/gateway/finding.go's nextLastSeen/isClosedIncidentState already
// established. Returns nil to mean "clear fleet_group_id" (a nil *string
// binds as SQL NULL via pgx), matching internal/api's own nil-pointer =
// SQL-NULL convention elsewhere (e.g. incidents.go's findingSummary
// scanning).
func decideGroupID(distinctClusterCount int, existingGroupIDs map[string]bool) *string {
	if distinctClusterCount < 2 {
		return nil
	}

	switch len(existingGroupIDs) {
	case 0:
		id := domain.NewID(domain.PrefixFleetGroup)
		return &id
	case 1:
		for id := range existingGroupIDs {
			return &id
		}
	}

	// Merge: more than one distinct group id already exists among this
	// fingerprint's currently-open incidents — see Recompute's doc comment
	// for why this should be unreachable in practice, and why the
	// lexicographically-smallest (oldest) id is the deterministic winner.
	ids := make([]string, 0, len(existingGroupIDs))
	for id := range existingGroupIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return &ids[0]
}
