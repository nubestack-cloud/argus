package gateway

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
	"argus/internal/tunnel"
)

// linkedFinding inserts a fault finding attached to incidentID carrying refs.
func linkedFinding(t *testing.T, pool *pgxpool.Pool, fixture *dbtest.Fixture, tenantID, clusterID, incidentID, gvk, ns, name string, refs []tunnel.ObjectReference) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	encoded, _ := json.Marshal(refs)
	if _, err := tx.Exec(ctx,
		`INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint,
		    gvk, namespace, object_name, reason, message, occurrence_count, severity, occurred_at,
		    ingested_at, signal_class, confidence, impact, references_out, incident_id)
		 VALUES ($1, $2, $3, 'k8s-test', 'v1', $4, $5, $6, $7, 'FailedScheduling', 'test', 1, 'high', now(), now(),
		         'fault', 'inferred', 'degraded', $8, $9)`,
		domain.NewID(domain.PrefixFinding), tenantID, clusterID, "fp_"+domain.NewID(domain.PrefixFinding),
		gvk, ns, name, encoded, incidentID); err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	fixture.Created("findings", 1)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func runBridge(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID string, f *tunnel.Finding) (string, bool) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	var id, state, severity string
	var lastSeen time.Time
	ok, err := referenceBridge(ctx, tx, clusterID, f, &id, &lastSeen, &state, &severity)
	if err != nil {
		t.Fatalf("referenceBridge: %v", err)
	}
	return id, ok
}

// PROJECT.md IN1/IN3: one cause seen from both ends of a declared dependency
// is one incident (loop campaign 2026-10-13, S06; the 2026-10-13 node blip).
func TestReferenceBridge(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, add, fixture := correlationCluster(t, pool)
	fixture.Cleanup(pool, correlationSetScope(tenantID, clusterID), []dbtest.TableDelete{
		{Table: "findings", SQL: `DELETE FROM findings WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})
	now := time.Now()
	const ns = "shop"
	pvcIncident := add("Detected", "v1/PersistentVolumeClaim|shop|data", "", "fp_pvc", now.Add(-time.Minute))
	nodeIncident := add("Detected", "Node||worker-1", "", "fp_node", now.Add(-time.Minute))
	add("Resolved", "v1/ConfigMap|shop|settings", "", "fp_cm", now.Add(-time.Hour))

	// Forward: the pod waits on a PVC whose own incident is open.
	pod := &tunnel.Finding{GVK: "v1/Pod", Namespace: ns, ObjectName: "web-1", Reason: "FailedScheduling",
		References: []tunnel.ObjectReference{{Kind: "PersistentVolumeClaim", Namespace: ns, Name: "data"}}}
	if got, ok := runBridge(t, pool, tenantID, clusterID, pod); !ok || got != pvcIncident {
		t.Errorf("a pod waiting on the PVC joined %q (%v), want the PVC's incident %s", got, ok, pvcIncident)
	}
	// Forward, bare-kind key: node incidents may be keyed "Node||name".
	onNode := &tunnel.Finding{GVK: "v1/Pod", Namespace: ns, ObjectName: "api-1", Reason: "NodeNotReady",
		References: []tunnel.ObjectReference{{Kind: "Node", Name: "worker-1"}}}
	if got, ok := runBridge(t, pool, tenantID, clusterID, onNode); !ok || got != nodeIncident {
		t.Errorf("a pod on the NotReady node joined %q (%v), want the node's incident %s", got, ok, nodeIncident)
	}
	// A closed incident on the referenced object is history, not a match.
	cm := &tunnel.Finding{GVK: "v1/Pod", Namespace: ns, ObjectName: "web-2", Reason: "Failed",
		References: []tunnel.ObjectReference{{Kind: "ConfigMap", Namespace: ns, Name: "settings"}}}
	if got, ok := runBridge(t, pool, tenantID, clusterID, cm); ok {
		t.Errorf("joined a Resolved incident %s", got)
	}

	// Reverse: the pod's incident opened first; the PVC's finding joins it.
	podFirst := add("Detected", "v1/Pod|shop|db-1", "apps/v1/Deployment|shop|db", "fp_db", now)
	linkedFinding(t, pool, fixture, tenantID, clusterID, podFirst, "v1/Pod", ns, "db-1",
		[]tunnel.ObjectReference{{Kind: "PersistentVolumeClaim", Namespace: ns, Name: "db-data"}})
	pvc := &tunnel.Finding{GVK: "v1/PersistentVolumeClaim", Namespace: ns, ObjectName: "db-data", Reason: "ProvisioningFailed"}
	if got, ok := runBridge(t, pool, tenantID, clusterID, pvc); !ok || got != podFirst {
		t.Errorf("the PVC's finding joined %q (%v), want the waiting pod's incident %s", got, ok, podFirst)
	}

	// Siblings on an unready node: a second workload's pod joins the first's.
	firstOnNode := add("Detected", "v1/Pod|shop|cache-1", "apps/v1/Deployment|shop|cache", "fp_cache", now)
	linkedFinding(t, pool, fixture, tenantID, clusterID, firstOnNode, "v1/Pod", ns, "cache-1",
		[]tunnel.ObjectReference{{Kind: "Node", Name: "worker-2"}})
	second := &tunnel.Finding{GVK: "v1/Pod", Namespace: ns, ObjectName: "queue-1", Reason: "NodeNotReady",
		References: []tunnel.ObjectReference{{Kind: "Node", Name: "worker-2"}}}
	if got, ok := runBridge(t, pool, tenantID, clusterID, second); !ok || got != firstOnNode {
		t.Errorf("a second workload on the same unready node joined %q (%v), want %s", got, ok, firstOnNode)
	}
	// Producers (IN5): a pod waiting on Secret tls joins the incident on the
	// Certificate whose findings say it produces tls.
	certIncident := add("Detected", "cert-manager.io/v1/Certificate|shop|web-cert", "", "fp_cert", now)
	linkedFinding(t, pool, fixture, tenantID, clusterID, certIncident, "cert-manager.io/v1/Certificate", ns, "web-cert",
		[]tunnel.ObjectReference{{Kind: "Secret", Namespace: ns, Name: "web-tls", Role: tunnel.ReferenceRoleProduces}})
	waiting := &tunnel.Finding{GVK: "v1/Pod", Namespace: ns, ObjectName: "web-9", Reason: "FailedMount",
		References: []tunnel.ObjectReference{{Kind: "Secret", Namespace: ns, Name: "web-tls"}}}
	if got, ok := runBridge(t, pool, tenantID, clusterID, waiting); !ok || got != certIncident {
		t.Errorf("a pod waiting on the Certificate's Secret joined %q (%v), want %s", got, ok, certIncident)
	}
	// And the other way: the producer's finding joins the waiting pod's incident.
	podWaits := add("Detected", "v1/Pod|shop|api-9", "apps/v1/Deployment|shop|api", "fp_api9", now)
	linkedFinding(t, pool, fixture, tenantID, clusterID, podWaits, "v1/Pod", ns, "api-9",
		[]tunnel.ObjectReference{{Kind: "Secret", Namespace: ns, Name: "api-tls"}})
	producerFinding := &tunnel.Finding{GVK: "cert-manager.io/v1/Certificate", Namespace: ns, ObjectName: "api-cert", Reason: "NotReady",
		References: []tunnel.ObjectReference{{Kind: "Secret", Namespace: ns, Name: "api-tls", Role: tunnel.ReferenceRoleProduces}}}
	if got, ok := runBridge(t, pool, tenantID, clusterID, producerFinding); !ok || got != podWaits {
		t.Errorf("the Certificate's finding joined %q (%v), want the waiting pod's incident %s", got, ok, podWaits)
	}

	// Fan-in (IN5): autoscalers that cannot reach the same unavailable
	// metrics API join one incident.
	hpaFirst := add("Detected", "autoscaling/v2/HorizontalPodAutoscaler|shop|web", "", "fp_hpa1", now)
	metricsAPI := tunnel.ObjectReference{Kind: "APIService", Name: "v1beta1.metrics.k8s.io"}
	linkedFinding(t, pool, fixture, tenantID, clusterID, hpaFirst, "autoscaling/v2/HorizontalPodAutoscaler", ns, "web",
		[]tunnel.ObjectReference{metricsAPI})
	hpaSecond := &tunnel.Finding{GVK: "autoscaling/v2/HorizontalPodAutoscaler", Namespace: ns, ObjectName: "api", Reason: "FailedGetResourceMetric",
		References: []tunnel.ObjectReference{metricsAPI}}
	if got, ok := runBridge(t, pool, tenantID, clusterID, hpaSecond); !ok || got != hpaFirst {
		t.Errorf("a second autoscaler failing on the same metrics API joined %q (%v), want %s", got, ok, hpaFirst)
	}

	// But sharing a ConfigMap is no evidence of a shared cause.
	cmUser := add("Detected", "v1/Pod|shop|report-1", "apps/v1/Deployment|shop|report", "fp_rep", now)
	linkedFinding(t, pool, fixture, tenantID, clusterID, cmUser, "v1/Pod", ns, "report-1",
		[]tunnel.ObjectReference{{Kind: "ConfigMap", Namespace: ns, Name: "app-config"}})
	unrelated := &tunnel.Finding{GVK: "v1/Pod", Namespace: ns, ObjectName: "mailer-1", Reason: "FailedScheduling",
		References: []tunnel.ObjectReference{{Kind: "ConfigMap", Namespace: ns, Name: "app-config"}}}
	if got, ok := runBridge(t, pool, tenantID, clusterID, unrelated); ok {
		t.Errorf("two pods sharing a ConfigMap were merged into %s", got)
	}
}
