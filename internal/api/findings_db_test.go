package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
	"argus/internal/orchestrator"
	"argus/internal/tunnel"
)

// PROJECT.md F31 — GET /api/v1/findings against a real Postgres.
//
// The four things this file exists to prove, because each of them is a way
// the endpoint could look right and be wrong:
//
//  1. Every stored finding's DISPOSITION is what the promotion boundary
//     actually implies for it, and the SQL that filters by a disposition
//     agrees with the Go that labels each row with one. Two definitions that
//     drift apart would give an operator a tab whose number and whose rows
//     describe different sets — the exact bug incidentCountsFor was written
//     to stop, in a new place.
//  2. The counts are the TRUE total, not the page length. This repo has a
//     recorded bug of precisely that shape (the overview's open count, and
//     the incident quick-view tabs before they moved server-side): a figure
//     derived from the fetched array that silently understated itself the
//     moment the list truncated, while still reading as a fact.
//  3. RLS scoping holds. A findings list is the one surface that shows raw
//     detection output across the whole fleet, so "which clusters can this
//     caller see" is load-bearing here in a way it is not for a route that
//     already took a cluster id in its path.
//  4. The promotion rule is IN the response. The whole product argument for
//     this endpoint is that an operator can see why something stayed a
//     finding; a list of unraised findings with no statement of the rule is
//     a list of unexplained decisions.
//
// Run with ARGUS_TEST_DATABASE_URL pointed at a database whose role is NOT a
// superuser: `postgres` carries BYPASSRLS, so assertion (3) would pass
// vacuously under it. `argus_app` is the role these are written for.

type findingsFixture struct {
	tenantID   string
	clusterA   string
	clusterB   string
	incidentID string
	// ids by role — see findingsTestFixture for what each one is.
	ids map[string]string
}

// The evidence tuples the fixture uses, named for what they are rather than
// repeated as three-string literals at five call sites.
var (
	tupleRealFault      = [3]string{tunnel.FindingClassFault, tunnel.FindingConfidenceVerified, tunnel.FindingImpactDegraded}
	tupleRisk           = [3]string{tunnel.FindingClassRisk, tunnel.FindingConfidenceVerified, tunnel.FindingImpactPotential}
	tupleUnverifiedFlt  = [3]string{tunnel.FindingClassFault, tunnel.FindingConfidenceUnverified, tunnel.FindingImpactDegraded}
	tupleGenericAnomaly = [3]string{tunnel.FindingClassAnomaly, tunnel.FindingConfidenceUnverified, tunnel.FindingImpactNone}
)

// findingsTestFixture builds two throwaway clusters whose findings cover
// every disposition, plus one finding deliberately outside the default time
// window.
//
// Cluster A (5 findings in window, 1 outside):
//
//	correlated   — a real fault, attached to an incident
//	retainedRisk — a risk: the boundary records it and raises nothing
//	retainedWeak — a fault on explicitly unverified evidence
//	retainedGeneric — a generic mechanism, stored as anomaly/unverified/none
//	suppressed   — a real fault with NO incident, which is what a toleration
//	               or storm protection leaves behind
//	stale        — a risk 30 days back, outside the default 7-day window
//
// Cluster B (1 finding): the same shape as retainedRisk, and the reason the
// cluster filter and the RLS assertions below can tell "scoped correctly"
// apart from "returned nothing at all".
//
// Two dbtest fixtures rather than one, because Fixture.OwnsCluster (the
// post-cleanup residue check, PROJECT.md B175) tracks a single cluster and
// both of these deserve one.
func findingsTestFixture(t *testing.T, pool *pgxpool.Pool) findingsFixture {
	t.Helper()
	ctx := context.Background()

	f := findingsFixture{
		clusterA: domain.NewID(domain.PrefixCluster),
		clusterB: domain.NewID(domain.PrefixCluster),
		ids:      map[string]string{},
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	f.tenantID, err = data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterA, f.clusterB}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	fixtureA, fixtureB := dbtest.New(t), dbtest.New(t)
	for cluster, fx := range map[string]*dbtest.Fixture{f.clusterA: fixtureA, f.clusterB: fixtureB} {
		if _, err := tx.Exec(ctx,
			`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
			 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
			cluster, f.tenantID, "findings-test-"+cluster, "fp-"+cluster); err != nil {
			t.Fatalf("insert throwaway cluster %s: %v", cluster, err)
		}
		fx.Created("clusters", 1)
		fx.OwnsCluster(f.tenantID, cluster)
	}

	now := time.Now()

	f.incidentID = domain.NewID(domain.PrefixIncident)
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen,
		   occurrence_count, opening_reason, object_key)
		 VALUES ($1, $2, $3, $4, 'high', $5, $6, $6, 1, 'CrashLoopBackOff', $7)`,
		f.incidentID, f.tenantID, f.clusterA, "fp-f31-"+f.incidentID, orchestrator.StateDetected, now,
		f.clusterA+"/v1/Pod/default/payments-api"); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	fixtureA.Created("incidents", 1)

	addFinding := func(fx *dbtest.Fixture, cluster, role, reason string, tuple [3]string, incidentID any, occurredAt time.Time) {
		id := domain.NewID(domain.PrefixFinding)
		f.ids[role] = id
		if _, err := tx.Exec(ctx,
			`INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint,
			   gvk, namespace, object_name, reason, message, severity, occurred_at, incident_id,
			   signal_class, confidence, impact)
			 VALUES ($1, $2, $3, 'k8s-sweep', 'v1', $4, 'v1/Pod', 'default', $5, $6, 'fixture message',
			   'medium', $7, $8, $9, $10, $11)`,
			id, f.tenantID, cluster, "fp-f31-"+id, "obj-"+role, reason, occurredAt, incidentID,
			tuple[0], tuple[1], tuple[2]); err != nil {
			t.Fatalf("insert %s finding: %v", role, err)
		}
		fx.Created("findings", 1)
	}

	addFinding(fixtureA, f.clusterA, "correlated", "CrashLoopBackOff", tupleRealFault, f.incidentID, now.Add(-time.Hour))
	addFinding(fixtureA, f.clusterA, "retainedRisk", "JobMissingActiveDeadlineSeconds", tupleRisk, nil, now.Add(-2*time.Hour))
	addFinding(fixtureA, f.clusterA, "retainedWeak", "PodConditionUnknown", tupleUnverifiedFlt, nil, now.Add(-3*time.Hour))
	// Stored already-corrected: migration 000107's BEFORE INSERT trigger
	// rewrites a generic mechanism carrying 000092's column defaults at write
	// time, so a current database cannot hold the uncorrected shape for a
	// test to insert. ExplainStoredFinding's read-time correction is pinned
	// directly in internal/gateway/promotion_rule_test.go; what matters here
	// is that this list agrees with the boundary on the row as it is actually
	// stored.
	addFinding(fixtureA, f.clusterA, "retainedGeneric", "GenericConditionAnomaly:CreatorMadeOwner", tupleGenericAnomaly, nil, now.Add(-4*time.Hour))
	// A finding that CLEARS the boundary and still has no incident: what a
	// toleration or storm protection leaves in the table.
	addFinding(fixtureA, f.clusterA, "suppressed", "ImagePullBackOff", tupleRealFault, nil, now.Add(-5*time.Hour))
	// Outside the default window.
	addFinding(fixtureA, f.clusterA, "stale", "JobMissingActiveDeadlineSeconds", tupleRisk, nil, now.Add(-30*24*time.Hour))

	addFinding(fixtureB, f.clusterB, "otherCluster", "JobMissingActiveDeadlineSeconds", tupleRisk, nil, now.Add(-time.Hour))

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup transaction: %v", err)
	}

	scopeFor := func(cluster string) func(context.Context, pgx.Tx) error {
		return func(ctx context.Context, tx pgx.Tx) error {
			return data.SetRequestScope(ctx, tx, f.tenantID, []string{cluster})
		}
	}
	fixtureA.Cleanup(pool, scopeFor(f.clusterA), []dbtest.TableDelete{
		{Table: "findings", SQL: `DELETE FROM findings WHERE cluster_id = $1`, Args: []any{f.clusterA}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{f.clusterA}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{f.clusterA}},
	})
	fixtureB.Cleanup(pool, scopeFor(f.clusterB), []dbtest.TableDelete{
		{Table: "findings", SQL: `DELETE FROM findings WHERE cluster_id = $1`, Args: []any{f.clusterB}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{f.clusterB}},
	})

	return f
}

// callListFindings drives the handler directly, the way every other
// *_db_test.go in this package does, inside a transaction scoped to
// accessibleClusters — which is what makes the RLS assertion below mean
// something rather than being a WHERE clause checking itself.
func callListFindings(t *testing.T, pool *pgxpool.Pool, tenantID string, accessibleClusters []string, query string) (int, findingsResponse, []byte) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin request transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, accessibleClusters); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings?"+query, nil)
	rec := httptest.NewRecorder()
	s := &Server{}
	s.handleListFindings(rec, req, &requestContext{Tx: tx, TenantID: tenantID, UserID: "usr_f31_test"})

	body := rec.Body.Bytes()
	var resp findingsResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("unmarshal response %s: %v", body, err)
		}
	}
	return rec.Code, resp, body
}

func findingByID(resp findingsResponse, id string) (findingListItem, bool) {
	for _, f := range resp.Findings {
		if f.ID == id {
			return f, true
		}
	}
	return findingListItem{}, false
}

// TestFindingsListReportsDispositionAndPromotionRule is the product claim in
// one test: an operator can see what ARGUS noticed, what it did with each
// observation, and the rule that decided.
func TestFindingsListReportsDispositionAndPromotionRule(t *testing.T) {
	pool := authTestPool(t)
	f := findingsTestFixture(t, pool)

	code, resp, body := callListFindings(t, pool, f.tenantID, []string{f.clusterA, f.clusterB}, "clusterId="+f.clusterA)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", code, body)
	}

	if len(resp.Findings) != 5 {
		t.Fatalf("returned %d findings, want the 5 in-window ones on this cluster: %+v", len(resp.Findings), resp.Findings)
	}
	// Newest first, and the stale one is not here at all.
	if resp.Findings[0].ID != f.ids["correlated"] {
		t.Errorf("first row is %s, want the most recent finding %s — the list is not ordered occurred_at DESC",
			resp.Findings[0].ID, f.ids["correlated"])
	}
	if _, found := findingByID(resp, f.ids["stale"]); found {
		t.Error("a finding from 30 days ago is in the default 7-day window's result")
	}

	wantDisposition := map[string]string{
		"correlated":      findingDispositionCorrelated,
		"retainedRisk":    findingDispositionRetained,
		"retainedWeak":    findingDispositionRetained,
		"retainedGeneric": findingDispositionRetained,
		"suppressed":      findingDispositionSuppressed,
	}
	for role, want := range wantDisposition {
		item, found := findingByID(resp, f.ids[role])
		if !found {
			t.Errorf("%s finding is missing from the list", role)
			continue
		}
		if item.Disposition != want {
			t.Errorf("%s disposition = %q, want %q (promotion: %+v)", role, item.Disposition, want, item.Promotion)
		}
		if (item.IncidentID != nil) != (want == findingDispositionCorrelated) {
			t.Errorf("%s incidentId = %v but disposition is %q — the two must be the same fact", role, item.IncidentID, item.Disposition)
		}
	}
	if item, _ := findingByID(resp, f.ids["correlated"]); item.IncidentID == nil || *item.IncidentID != f.incidentID {
		t.Errorf("correlated finding names incident %v, want %s", item.IncidentID, f.incidentID)
	}

	// The row-level "why did this stay a finding" answer. A risk fails the
	// class and impact criteria and passes confidence; reporting all three,
	// or only one, would both be wrong.
	risk, _ := findingByID(resp, f.ids["retainedRisk"])
	if risk.Promotion.Promotable {
		t.Error("a risk-classed finding is reported as promotable")
	}
	if got := risk.Promotion.Unmet; len(got) != 2 || got[0] != "class" || got[1] != "impact" {
		t.Errorf("risk unmet criteria = %v, want [class impact]", got)
	}
	weak, _ := findingByID(resp, f.ids["retainedWeak"])
	if got := weak.Promotion.Unmet; len(got) != 1 || got[0] != "confidence" {
		t.Errorf("unverified fault unmet criteria = %v, want [confidence] — its class and impact are both fine, and saying otherwise sends an operator to fix the wrong thing", got)
	}
	suppressed, _ := findingByID(resp, f.ids["suppressed"])
	if !suppressed.Promotion.Promotable || len(suppressed.Promotion.Unmet) != 0 {
		t.Errorf("suppressed finding promotion = %+v, want promotable with nothing unmet — it cleared the boundary; something downstream stopped the incident", suppressed.Promotion)
	}

	// The rule itself, in the response rather than only in a comment.
	rule := resp.PromotionRule
	if rule.Summary == "" || rule.Source == "" {
		t.Errorf("promotionRule is not stated: %+v", rule)
	}
	if len(rule.Criteria) != 3 {
		t.Fatalf("promotionRule has %d criteria, want one each for class/confidence/impact: %+v", len(rule.Criteria), rule.Criteria)
	}
	for _, c := range rule.Criteria {
		if len(c.Accepted) == 0 || c.Statement == "" {
			t.Errorf("criterion %q is empty: %+v", c.Dimension, c)
		}
	}
	if rule.NotRecorded == "" {
		t.Error("promotionRule.notRecorded is empty — a surface that cannot show dropped findings must say so, or it overstates what it covers")
	}

	// And the window the counts were taken over.
	if resp.Window.Since == "" {
		t.Error("window.since is empty — a count is only honest alongside the window it counted")
	}
}

// TestFindingsCountsAreTheTrueTotalNotThePageLength is assertion (2).
//
// Asserted by truncating the page to a single row and requiring every count
// to be unchanged from the untruncated request. A count derived from the
// returned array — the recorded bug this guards against — would collapse to
// 1/1/0/0 here and look entirely plausible.
func TestFindingsCountsAreTheTrueTotalNotThePageLength(t *testing.T) {
	pool := authTestPool(t)
	f := findingsTestFixture(t, pool)

	_, full, _ := callListFindings(t, pool, f.tenantID, []string{f.clusterA}, "clusterId="+f.clusterA)
	if full.Counts.All != 5 || full.Counts.Correlated != 1 || full.Counts.RetainedUnpromoted != 3 || full.Counts.Suppressed != 1 {
		t.Fatalf("untruncated counts = %+v, want all=5 correlated=1 retained=3 suppressed=1", full.Counts)
	}
	if full.NextCursor != "" {
		t.Errorf("nextCursor = %q on a partial page, want empty", full.NextCursor)
	}

	code, page, body := callListFindings(t, pool, f.tenantID, []string{f.clusterA}, "clusterId="+f.clusterA+"&limit=1")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", code, body)
	}
	if len(page.Findings) != 1 {
		t.Fatalf("limit=1 returned %d findings", len(page.Findings))
	}
	if page.NextCursor == "" {
		t.Error("a full page came back with no nextCursor — the rest of the list is unreachable")
	}
	if page.Counts != full.Counts {
		t.Errorf("counts on a truncated page = %+v, want the untruncated %+v — a total derived from the page it happened to fetch is the bug this endpoint was required not to reproduce",
			page.Counts, full.Counts)
	}

	// And the cursor actually walks the whole set exactly once.
	seen := map[string]bool{page.Findings[0].ID: true}
	cursor := page.NextCursor
	for range 10 {
		if cursor == "" {
			break
		}
		_, next, _ := callListFindings(t, pool, f.tenantID, []string{f.clusterA}, "clusterId="+f.clusterA+"&limit=1&cursor="+cursor)
		for _, item := range next.Findings {
			if seen[item.ID] {
				t.Fatalf("finding %s came back on two different pages", item.ID)
			}
			seen[item.ID] = true
		}
		cursor = next.NextCursor
	}
	if len(seen) != 5 {
		t.Errorf("paging through with limit=1 saw %d distinct findings, want 5", len(seen))
	}
}

// TestFindingsDispositionFilterAgreesWithRowLabels closes the gap between the
// two places a disposition is decided: findingDispositionClauses (SQL, which
// decides which rows a filter returns and what each count counts) and
// findingDispositionOf (Go, which decides what a returned row says it is).
// Both are derived from the same gate, and this proves they land in the same
// place on real rows.
func TestFindingsDispositionFilterAgreesWithRowLabels(t *testing.T) {
	pool := authTestPool(t)
	f := findingsTestFixture(t, pool)

	counts := map[string]int{
		findingDispositionCorrelated: 1,
		findingDispositionRetained:   3,
		findingDispositionSuppressed: 1,
	}
	for disposition, want := range counts {
		t.Run(disposition, func(t *testing.T) {
			code, resp, body := callListFindings(t, pool, f.tenantID, []string{f.clusterA},
				"clusterId="+f.clusterA+"&disposition="+disposition)
			if code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body: %s", code, body)
			}
			if len(resp.Findings) != want {
				t.Errorf("?disposition=%s returned %d rows, want %d", disposition, len(resp.Findings), want)
			}
			for _, item := range resp.Findings {
				if item.Disposition != disposition {
					t.Errorf("a row returned by ?disposition=%s labels itself %q — the SQL filter and the Go label disagree, so a tab's number and its rows describe different sets",
						disposition, item.Disposition)
				}
			}
			// The counts are NOT narrowed by ?disposition= — they stay the
			// whole-scope breakdown, so the tab an operator is on and the
			// ones they are not both keep reading correctly.
			if resp.Counts.All != 5 {
				t.Errorf("counts.all = %d under ?disposition=%s, want the unnarrowed 5", resp.Counts.All, disposition)
			}
		})
	}
}

// TestFindingsListIsRLSScoped is assertion (3). The request transaction is
// scoped to cluster B only; cluster A's findings must be invisible in the
// rows AND in the counts. A count computed outside the scoped transaction is
// a realistic way to leak, so both are checked.
func TestFindingsListIsRLSScoped(t *testing.T) {
	pool := authTestPool(t)
	f := findingsTestFixture(t, pool)

	code, resp, body := callListFindings(t, pool, f.tenantID, []string{f.clusterB}, "")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", code, body)
	}
	for _, item := range resp.Findings {
		if item.ClusterID == f.clusterA {
			t.Fatalf("a caller scoped to %s was served finding %s from %s", f.clusterB, item.ID, f.clusterA)
		}
	}
	if _, found := findingByID(resp, f.ids["otherCluster"]); !found {
		t.Fatal("cluster B's own finding is missing — the scoping returned nothing at all, so the assertion above proved nothing")
	}
	// The whole-set counts must respect the same scope.
	if resp.Counts.All < 1 {
		t.Errorf("counts.all = %d with one visible finding", resp.Counts.All)
	}
	// Cluster A holds 4 retained + 1 correlated + 1 suppressed; if any of
	// them were counted, the retained/correlated/suppressed numbers would
	// exceed what cluster B can possibly contribute.
	if resp.Counts.Correlated != 0 || resp.Counts.Suppressed != 0 {
		t.Errorf("counts = %+v for a caller who can see only cluster B, which has neither a correlated nor a suppressed finding — the counts query is not running under the request's scope", resp.Counts)
	}

	// Explicitly asking for the invisible cluster must also return nothing,
	// rather than an error that would confirm it exists.
	_, scoped, _ := callListFindings(t, pool, f.tenantID, []string{f.clusterB}, "clusterId="+f.clusterA)
	if len(scoped.Findings) != 0 || scoped.Counts.All != 0 {
		t.Errorf("?clusterId= for a cluster outside the caller's scope returned %d rows and counts %+v", len(scoped.Findings), scoped.Counts)
	}
}

// TestFindingsFiltersNarrowAndValidate covers the two filters the acceptance
// names explicitly (cluster and reason), the evidence-dimension filters that
// are how an operator drills into "why was nothing raised", and the rejection
// of a value outside a closed vocabulary — which must be a 400 rather than a
// filter that silently matches nothing and reads as "there is none of that".
func TestFindingsFiltersNarrowAndValidate(t *testing.T) {
	pool := authTestPool(t)
	f := findingsTestFixture(t, pool)
	scope := []string{f.clusterA, f.clusterB}

	t.Run("by reason, across the fleet", func(t *testing.T) {
		_, resp, _ := callListFindings(t, pool, f.tenantID, scope, "reason=JobMissingActiveDeadlineSeconds")
		// Cluster A's in-window risk and cluster B's, not the 30-day-old one.
		if len(resp.Findings) != 2 || resp.Counts.All != 2 {
			t.Fatalf("?reason= returned %d rows / counts %+v, want 2 of each", len(resp.Findings), resp.Counts)
		}
		for _, item := range resp.Findings {
			if item.Reason != "JobMissingActiveDeadlineSeconds" {
				t.Errorf("row %s has reason %q", item.ID, item.Reason)
			}
		}
	})

	t.Run("by class", func(t *testing.T) {
		_, resp, _ := callListFindings(t, pool, f.tenantID, scope, "clusterId="+f.clusterA+"&class=risk")
		if len(resp.Findings) != 1 || resp.Findings[0].ID != f.ids["retainedRisk"] {
			t.Fatalf("?class=risk returned %+v", resp.Findings)
		}
	})

	t.Run("an out-of-window finding is reachable by widening ?since=", func(t *testing.T) {
		since := time.Now().Add(-60 * 24 * time.Hour).UTC().Format(time.RFC3339)
		_, resp, _ := callListFindings(t, pool, f.tenantID, scope, "clusterId="+f.clusterA+"&since="+since)
		if _, found := findingByID(resp, f.ids["stale"]); !found {
			t.Error("the 30-day-old finding is unreachable even with ?since= 60 days back")
		}
		if resp.Counts.All != 6 {
			t.Errorf("counts.all = %d over the widened window, want 6", resp.Counts.All)
		}
		if resp.Window.Since != since {
			t.Errorf("window.since = %q, want the requested %q", resp.Window.Since, since)
		}
	})

	for _, bad := range []struct{ name, query string }{
		{"class", "class=nonsense"},
		{"confidence", "confidence=probably"},
		{"impact", "impact=catastrophic"},
		{"disposition", "disposition=ignored"},
		{"since", "since=yesterday"},
		{"until", "until=tomorrow"},
		{"limit", "limit=0"},
		{"limit over the cap", "limit=99999"},
		{"cursor", "cursor=not-a-cursor"},
	} {
		t.Run("rejects an invalid ?"+bad.name, func(t *testing.T) {
			code, _, body := callListFindings(t, pool, f.tenantID, scope, bad.query)
			if code != http.StatusBadRequest {
				t.Fatalf("?%s: status = %d, want 400; body: %s", bad.query, code, body)
			}
			assertMatchesProblemSchema(t, body)
		})
	}
}

// TestFindingsResponseMatchesOpenAPISchema holds docs/openapi.yaml to the
// handler, through the same kin-openapi validator openapi_contract_db_test.go
// uses for the other list endpoints — so the documented shape of a brand-new
// route cannot be wrong from the day it lands.
func TestFindingsResponseMatchesOpenAPISchema(t *testing.T) {
	pool := authTestPool(t)
	f := findingsTestFixture(t, pool)

	code, _, body := callListFindings(t, pool, f.tenantID, []string{f.clusterA}, "clusterId="+f.clusterA)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", code, body)
	}
	assertMatchesSchema(t, "FindingsResponse", body)
}
