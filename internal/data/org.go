package data

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// SingleOrganisationID returns the one organisation row's ID. Safe to call before
// any RLS scope is set, because `organisations` deliberately has no RLS policy at
// all (lld/05-data-model.md §6) — it's the root every other table's tenant_id
// resolves against, so it has to be queryable without already knowing the answer.
//
// If a second organisation is ever hosted on this hub (lld/02-authz-spec.md §3's
// dormant multi-tenancy note), this function's single-row assumption is exactly
// what needs to change — the tenant would instead come from the session/JWT
// directly, not from "the one row in this table."
func SingleOrganisationID(ctx context.Context, tx pgx.Tx) (string, error) {
	var id string
	if err := tx.QueryRow(ctx, "SELECT id FROM organisations LIMIT 1").Scan(&id); err != nil {
		return "", fmt.Errorf("resolve organisation: %w", err)
	}
	return id, nil
}
