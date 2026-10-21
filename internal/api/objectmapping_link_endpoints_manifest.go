package api

// BACKLOG.md F30's manifest-mode decline/re-ask plumbing — the sibling of
// objectmapping_link_endpoints.go's helm-mode helmLinkAlreadyDeclined, kept
// in its own file rather than folded into that function so the existing
// helm-mode DB test (objectmapping_link_endpoints_db_test.go) keeps calling
// helmLinkAlreadyDeclined with its original, unchanged signature.
//
// migration 000113 is what makes this possible: helm_link_declines now
// carries object_gvk/object_namespace/object_name alongside the original
// release_name/namespace, with a CHECK constraint enforcing "exactly one
// form" the same way scm.ObjectMapping.Validate does for a CONFIRMED link —
// see that migration's own comment for why a decline's identity discipline
// should not be looser than a confirmation's.
import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"argus/internal/domain"
)

// declineAlreadyRecorded is handleDiscoverRepositoryLink's single entry
// point for F30 decision 4's "do not re-ask" check, dispatching on
// target.mode to whichever identity a prior decline could have been
// recorded against — release_name+namespace for a Helm release,
// object_gvk+object_namespace+object_name for a plain-manifest object.
func declineAlreadyRecorded(ctx context.Context, tx pgx.Tx, target helmReleaseTarget) (bool, error) {
	if target.mode == linkModeManifest {
		return manifestLinkAlreadyDeclined(ctx, tx, target.clusterID, target.objectGVK, target.objectNamespace, target.objectName)
	}
	return helmLinkAlreadyDeclined(ctx, tx, target.clusterID, target.releaseName, target.releaseNamespace)
}

// manifestLinkAlreadyDeclined is helmLinkAlreadyDeclined's manifest-mode
// counterpart — same "has anyone already said no for this exact identity,
// on this exact cluster" question, keyed on the live object's own
// kind+namespace+name (migration 000113's object_gvk/object_namespace/
// object_name columns) rather than a release.
func manifestLinkAlreadyDeclined(ctx context.Context, tx pgx.Tx, clusterID, objectGVK, objectNamespace, objectName string) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM helm_link_declines WHERE cluster_id = $1 AND object_gvk = $2 AND object_namespace = $3 AND object_name = $4)`,
		clusterID, objectGVK, objectNamespace, objectName).Scan(&exists)
	return exists, err
}

// recordDecline is handleDeclineRepositoryLink's single write, dispatching
// on target.mode to the matching arbiter — the table constraint
// `UNIQUE (cluster_id, release_name, namespace)` migration 000104 already
// created for Helm mode, or migration 000113's partial
// `helm_link_declines_manifest_lookup_idx` for manifest mode. Postgres
// requires the ON CONFLICT target to name the exact index a row would
// violate, which is why this is two statements rather than one that tries
// to cover both.
func recordDecline(ctx context.Context, tx pgx.Tx, tenantID, userID string, target helmReleaseTarget) error {
	id := domain.NewID(domain.PrefixHelmLinkDecline)
	if target.mode == linkModeManifest {
		_, err := tx.Exec(ctx,
			`INSERT INTO helm_link_declines (id, tenant_id, cluster_id, object_gvk, object_namespace, object_name, declined_by)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)
			 ON CONFLICT (cluster_id, object_gvk, object_namespace, object_name) WHERE object_gvk IS NOT NULL
			 DO UPDATE SET declined_at = now(), declined_by = EXCLUDED.declined_by`,
			id, tenantID, target.clusterID, target.objectGVK, target.objectNamespace, target.objectName, userID)
		if err != nil {
			return fmt.Errorf("api: record manifest-mode decline: %w", err)
		}
		return nil
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO helm_link_declines (id, tenant_id, cluster_id, release_name, namespace, declined_by)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (cluster_id, release_name, namespace)
		 DO UPDATE SET declined_at = now(), declined_by = EXCLUDED.declined_by`,
		id, tenantID, target.clusterID, target.releaseName, target.releaseNamespace, userID)
	if err != nil {
		return fmt.Errorf("api: record helm-mode decline: %w", err)
	}
	return nil
}
