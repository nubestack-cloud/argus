package api

import (
	"context"
	"testing"
	"time"

	"argus/internal/data"
	"argus/internal/domain"
)

// TestScanTolerationView_AutoCreatedRuleWithNoHumanAuthorIsListable is the
// regression test for a live P0 that an external review found the day after
// PROJECT.md T6 landed: GET /api/v1/tolerations returned 500 for EVERY caller,
// with "scan: can't scan into dest[7] (col: created_by): cannot scan NULL into
// *string".
//
// The cause was a seam, not a typo. T6 made incident_tolerations.created_by
// nullable (migration 000112) so that a rule ARGUS creates for itself on a
// Dismissed/Expired transition has no human author — correct, and the
// migration paired it with auto_created and a CHECK. But tolerationListQuery
// selected created_by bare into tolerationView's plain string field, while
// both of its neighbours in the same SELECT were already COALESCEd. Nothing
// caught it because T6's own tests exercised the WRITE path and the
// suppression predicate; no test read a NULL-authored row back out.
//
// The damage was larger than a broken page: the list is the only surface on
// which an operator can see or remove a suppression, so the failure removed
// the override half of "inspectable and overridable" — the property T6's
// acceptance criterion is actually about — for every rule the mechanism
// created. On this development instance 24 of 25 rules were automatic within
// a day.
func TestScanTolerationView_AutoCreatedRuleWithNoHumanAuthorIsListable(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	tenantID, err := singleOrgIDForTest(ctx, pool)
	if err != nil {
		t.Fatalf("resolve tenant: %v", err)
	}
	clusterID := clusterGroupTestCluster(t, pool, tenantID)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set scope: %v", err)
	}

	tolerationID := domain.NewID(domain.PrefixToleration)
	// Exactly the shape suppressRecurrenceOnClose writes: NULL author,
	// auto_created true, which is the only combination the 000112 CHECK
	// permits for an automatic rule.
	if _, err := tx.Exec(ctx, `
		INSERT INTO incident_tolerations
		  (id, tenant_id, cluster_id, object_key, reasons, note, incident_id,
		   created_by, auto_created, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, NULL, NULL, true, $7)`,
		tolerationID, tenantID, clusterID, "v1/Pod|default|autocreated-probe",
		[]string{"CrashLoopBackOff"}, "suppressed automatically on dismissal",
		time.Now().Add(14*24*time.Hour),
	); err != nil {
		t.Fatalf("insert auto-created toleration: %v", err)
	}

	row := tx.QueryRow(ctx, tolerationListQuery+" WHERE t.id = $1", tolerationID)
	v, err := scanTolerationView(row)
	if err != nil {
		t.Fatalf("scanTolerationView refused a rule ARGUS created for itself: %v\n"+
			"this is the whole defect: an automatic rule has no human author, and the list "+
			"endpoint is the only place an operator can inspect or remove one", err)
	}
	if !v.AutoCreated {
		t.Error("autoCreated is false for a rule inserted with auto_created=true — " +
			"the UI cannot tell an ARGUS-created rule from a human one, and migration " +
			"000112's own comment promises it badges them differently")
	}
	if v.CreatedBy != "" {
		t.Errorf("createdBy = %q, want empty for an automatic rule — a fabricated author is worse than none", v.CreatedBy)
	}
	if v.CreatedByEmail != "" {
		t.Errorf("createdByEmail = %q, want empty for an automatic rule", v.CreatedByEmail)
	}
}

// TestScanTolerationView_HumanAuthoredRuleStillCarriesItsAuthor is the other
// half: the COALESCE must not erase a real author, and auto_created must stay
// false for anything a person created through POST /incidents/{id}/tolerate.
// Without this, "fix the NULL scan" could be satisfied by blanking the column.
func TestScanTolerationView_HumanAuthoredRuleStillCarriesItsAuthor(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	tenantID, err := singleOrgIDForTest(ctx, pool)
	if err != nil {
		t.Fatalf("resolve tenant: %v", err)
	}
	clusterID := clusterGroupTestCluster(t, pool, tenantID)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set scope: %v", err)
	}

	var userID string
	if err := tx.QueryRow(ctx,
		`SELECT id FROM users WHERE deleted_at IS NULL ORDER BY created_at LIMIT 1`).Scan(&userID); err != nil {
		t.Skipf("no user to attribute a toleration to: %v", err)
	}

	tolerationID := domain.NewID(domain.PrefixToleration)
	if _, err := tx.Exec(ctx, `
		INSERT INTO incident_tolerations
		  (id, tenant_id, cluster_id, object_key, reasons, note, incident_id,
		   created_by, auto_created, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, NULL, $7, false, $8)`,
		tolerationID, tenantID, clusterID, "v1/Pod|default|human-probe",
		[]string{"CrashLoopBackOff"}, "silenced by hand",
		userID, time.Now().Add(24*time.Hour),
	); err != nil {
		t.Fatalf("insert human toleration: %v", err)
	}

	v, err := scanTolerationView(tx.QueryRow(ctx, tolerationListQuery+" WHERE t.id = $1", tolerationID))
	if err != nil {
		t.Fatalf("scanTolerationView: %v", err)
	}
	if v.AutoCreated {
		t.Error("autoCreated is true for a human-created rule")
	}
	if v.CreatedBy != userID {
		t.Errorf("createdBy = %q, want the real author %q — the COALESCE must not erase a real id", v.CreatedBy, userID)
	}
}
