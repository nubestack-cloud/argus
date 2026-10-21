package gateway

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// FindingTolerated reports whether an active incident_tolerations rule
// (migration 000041) covers this exact (cluster, object, reason) —
// handleFinding's third hub-side filter, checked at the same point storm
// protection is: right before a Finding would otherwise open a brand-new
// incident. Matches only when correlateByObject is true (objectKey != ""),
// same as the object-correlation query above it — a toleration is always
// scoped to one concrete object, so a fingerprint-only Finding (no object)
// has nothing to match against.
//
// A NULL reasons column means the operator tolerated every reason on this
// object, not just the one that prompted the rule — see migration 000041's
// own doc comment for why that's opt-in rather than the default.
//
// Returns the matching rule's id (for logging/audit) when tolerated, "" when
// not. Runs on the same transaction handleFinding already holds, under the
// per-object advisory lock it already acquired — no separate locking needed,
// since this only ever READS.
func FindingTolerated(ctx context.Context, tx pgx.Tx, clusterID, objectKey, reason string) (tolerationID string, err error) {
	err = tx.QueryRow(ctx,
		`SELECT id FROM incident_tolerations
		   WHERE cluster_id = $1 AND object_key = $2 AND removed_at IS NULL
		     AND (expires_at IS NULL OR expires_at > now())
		     AND (reasons IS NULL OR $3 = ANY(reasons))
		   ORDER BY created_at DESC
		   LIMIT 1`,
		clusterID, objectKey, reason).Scan(&tolerationID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return tolerationID, nil
}
