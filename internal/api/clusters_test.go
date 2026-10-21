package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"argus/internal/agentversion"
	"argus/internal/authz"
)

// TestHandleGetClusterRefusesOutOfScopeCluster is a security regression test.
//
// handleGetCluster narrows the RLS scope to the cluster id in its URL, because
// cluster_facts' policy has no "empty means unrestricted" branch and would
// otherwise read as zero rows. That narrowing takes a CALLER-CONTROLLED value and
// widens what the transaction can see, and under S1 nothing else bounds a read —
// so without a per-cluster capability check, a user granted cluster:read on one
// cluster could read any cluster in the fleet by editing the URL. The route-level
// requireCapability cannot catch it: it checks the capability with no scope.
//
// The assertion is deliberately "403 or not 403" rather than a full response:
// reaching the DB is out of scope for a unit test, and whether the gate refuses is
// exactly the property at issue. A non-403 here means the request got PAST the
// gate, which for the wrong-cluster cases is the vulnerability.
func TestHandleGetClusterRefusesOutOfScopeCluster(t *testing.T) {
	const (
		granted   = "cl_granted"
		otherwise = "cl_someone_elses"
	)
	clusterScoped := func(clusterID string) []authz.EffectiveGrant {
		return []authz.EffectiveGrant{{
			Capability: authz.CapClusterRead,
			Scope:      authz.Scope{Type: "Cluster", ClusterID: clusterID},
		}}
	}

	cases := []struct {
		name       string
		grants     []authz.EffectiveGrant
		requestID  string
		wantDenied bool
	}{
		{
			name:       "cluster-scoped grant reading ANOTHER cluster is refused",
			grants:     clusterScoped(granted),
			requestID:  otherwise,
			wantDenied: true,
		},
		{
			name:       "cluster-scoped grant reading its OWN cluster is allowed through the gate",
			grants:     clusterScoped(granted),
			requestID:  granted,
			wantDenied: false,
		},
		{
			name:       "AllClusters grant is allowed through the gate",
			grants:     grantsFor(authz.CapClusterRead),
			requestID:  otherwise,
			wantDenied: false,
		},
		{
			name:       "no grant at all is refused",
			grants:     nil,
			requestID:  granted,
			wantDenied: true,
		},
		{
			name:       "a grant for a DIFFERENT capability on the right cluster is refused",
			grants:     []authz.EffectiveGrant{{Capability: authz.CapIncidentRead, Scope: authz.Scope{Type: "Cluster", ClusterID: granted}}},
			requestID:  granted,
			wantDenied: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := serverWithUnreachableAuditDB(t)
			req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/"+c.requestID, nil)
			req.SetPathValue("id", c.requestID)
			rec := httptest.NewRecorder()

			// A case that PASSES the gate goes on to narrow the RLS scope on
			// requestContext.Tx, which is nil here, and panics. That panic is the
			// evidence the gate allowed the request, so it is caught and recorded
			// as "not denied" rather than failing the test — the alternative is a
			// live Postgres in a unit test to assert something this already shows.
			passedGate := false
			func() {
				defer func() {
					if recover() != nil {
						passedGate = true
					}
				}()
				s.handleGetCluster(rec, req, &requestContext{Grants: c.grants})
			}()

			denied := !passedGate && rec.Code == http.StatusForbidden
			if denied != c.wantDenied {
				t.Fatalf("status = %d (denied=%v), want denied=%v — body: %s",
					rec.Code, denied, c.wantDenied, rec.Body.String())
			}
		})
	}
}

// clusterSummaryStubRow builds the exact 7-column row shape
// scanClusterSummary reads (id, display_name, state, agent_version,
// last_heartbeat_at, created_at, archived_at) with a given agent_version.
// archived_at is nil here because these two tests are about the
// compatibility verdict on a live cluster; the retired shape is covered
// end-to-end against real rows in clusters_archived_db_test.go.
func clusterSummaryStubRow(agentVersion *string) stubRow {
	return stubRow{values: []any{
		"cl_x", "test cluster", "Active", agentVersion, (*time.Time)(nil), time.Unix(0, 0).UTC(), (*time.Time)(nil),
	}}
}

// TestScanClusterSummaryDerivesCompatibilityFromServerPolicy is T16's core
// assertion at the API layer, not just inside internal/agentversion:
// scanClusterSummary — the one function both handleListClusters and
// handleGetCluster go through — must get its Compatibility verdict from
// agentversion.Policy, the single server-owned policy, and not from any
// comparison of its own. Proven the same way the acceptance criterion asks
// for: change the policy (in Go, here, not a React fixture) and watch the
// SAME stubbed row's verdict change with it.
func TestScanClusterSummaryDerivesCompatibilityFromServerPolicy(t *testing.T) {
	original := agentversion.Policy
	t.Cleanup(func() { agentversion.Policy = original })

	agentVersion := "1.4.0"

	agentversion.Policy = agentversion.VersionPolicy{MinSupportedVersion: "1.0.0", RecommendedVersion: "1.4.0"}
	c, err := scanClusterSummary(clusterSummaryStubRow(&agentVersion))
	if err != nil {
		t.Fatalf("scanClusterSummary: %v", err)
	}
	if c.Compatibility.Verdict != agentversion.VerdictCurrent {
		t.Fatalf("under the lenient policy, verdict = %q, want %q", c.Compatibility.Verdict, agentversion.VerdictCurrent)
	}

	agentversion.Policy = agentversion.VersionPolicy{MinSupportedVersion: "2.0.0", RecommendedVersion: "3.0.0"}
	c, err = scanClusterSummary(clusterSummaryStubRow(&agentVersion))
	if err != nil {
		t.Fatalf("scanClusterSummary: %v", err)
	}
	if c.Compatibility.Verdict != agentversion.VerdictUpgradeRequired {
		t.Fatalf("under the strict policy, verdict = %q, want %q — same row, same code path, only the policy changed", c.Compatibility.Verdict, agentversion.VerdictUpgradeRequired)
	}
}

// TestScanClusterSummaryUnknownVersionNeverReadsAsConfident guards the other
// half: a cluster with no reported agent version (nil — never heartbeated)
// must come back Unknown, regardless of how strict or lenient the policy is,
// and must not carry upgrade guidance or a claimed feature gap.
func TestScanClusterSummaryUnknownVersionNeverReadsAsConfident(t *testing.T) {
	original := agentversion.Policy
	t.Cleanup(func() { agentversion.Policy = original })
	agentversion.Policy = agentversion.VersionPolicy{MinSupportedVersion: "1.0.0", RecommendedVersion: "9.0.0"}

	c, err := scanClusterSummary(clusterSummaryStubRow(nil))
	if err != nil {
		t.Fatalf("scanClusterSummary: %v", err)
	}
	if c.Compatibility.Verdict != agentversion.VerdictUnknown {
		t.Fatalf("verdict = %q, want %q for a cluster with no reported agent version", c.Compatibility.Verdict, agentversion.VerdictUnknown)
	}
	if c.Compatibility.Upgrade != nil {
		t.Fatalf("Upgrade = %+v, want nil for an unknown version", c.Compatibility.Upgrade)
	}
	if len(c.Compatibility.MissingFeatures) != 0 {
		t.Fatalf("MissingFeatures = %v, want none for an unknown version", c.Compatibility.MissingFeatures)
	}
	if c.Compatibility.Label == "" {
		t.Fatalf("Label is empty — a verdict must always carry a text label, never colour alone")
	}
}
