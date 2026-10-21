package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
)

var crdNeighborhoodGVRs = map[string]schema.GroupVersionResource{
	"argoproj.io/Application":     {Group: "argoproj.io", Version: "v1alpha1", Resource: "applications"},
	"cert-manager.io/Certificate": {Group: "cert-manager.io", Version: "v1", Resource: "certificates"},
}

// crdNeighborhoodExecutor is shaped like the live objects that made the hub
// show a 502: results/results-example-org-tls on lab-dev (a cert-manager
// Certificate created by ingress-shim, so owned by the Ingress
// results-frontend) and argocd/argus-gitops-api on rke2 (an Argo CD
// Application whose status.resources lists the Deployment it manages in
// another namespace, with no ownerReference back).
func crdNeighborhoodExecutor(t *testing.T) *ToolExecutor {
	t.Helper()
	cert := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cert-manager.io/v1", "kind": "Certificate",
		"metadata": map[string]any{
			"name": "results-example-org-tls", "namespace": "results", "uid": "cert-uid",
			"labels": map[string]any{"app.kubernetes.io/managed-by": "Helm"},
			"ownerReferences": []any{map[string]any{
				"apiVersion": "networking.k8s.io/v1", "kind": "Ingress", "name": "results-frontend",
				"uid": "8e6b0de4-366a-4c6f-b89e-b29c681e1f6e", "controller": true, "blockOwnerDeletion": true,
			}},
		},
		"spec": map[string]any{"secretName": "results-example-org-tls",
			"issuerRef": map[string]any{"group": "cert-manager.io", "kind": "ClusterIssuer", "name": "example-internal-acme"}},
		"status": map[string]any{"conditions": []any{map[string]any{
			"type": "Ready", "status": "True", "reason": "Ready", "message": "Certificate is up to date and has not expired",
		}}},
	}}
	app := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1", "kind": "Application",
		"metadata": map[string]any{"name": "argus-gitops-api", "namespace": "argocd", "uid": "app-uid"},
		"spec": map[string]any{"destination": map[string]any{"namespace": "argus-gitops-rke2"},
			"source": map[string]any{"repoURL": "https://example.invalid/repo.git", "path": "api"}},
		"status": map[string]any{
			"health": map[string]any{"status": "Healthy"},
			"sync":   map[string]any{"status": "Unknown"},
			"resources": []any{map[string]any{
				"group": "apps", "kind": "Deployment", "name": "api", "namespace": "argus-gitops-rke2",
				"requiresPruning": true, "status": "Unknown", "version": "v1",
			}},
		},
	}}
	kinds := gitOpsTestListKinds()
	kinds[crdNeighborhoodGVRs["cert-manager.io/Certificate"]] = "CertificateList"
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(k8sscheme.Scheme, kinds, cert, app)
	typed := k8sfake.NewSimpleClientset()
	exec := &ToolExecutor{typed: typed, dynamic: dyn}

	ingress := &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{
		Name: "results-frontend", Namespace: "results", UID: types.UID("8e6b0de4-366a-4c6f-b89e-b29c681e1f6e")}}
	deploy := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "argus-gitops-rke2", UID: "dep-uid"}}
	attachObjectCache(t, exec, typed, crdNeighborhoodGVRs, []runtime.Object{ingress, deploy}...)
	return exec
}

func neighborhood(t *testing.T, exec *ToolExecutor, args string) (map[string]any, error) {
	t.Helper()
	raw, _, err := exec.Execute(context.Background(), "get_neighborhood", json.RawMessage(args))
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out, nil
}

func nodeIDs(out map[string]any) []string {
	var ids []string
	for _, n := range out["nodes"].([]any) {
		ids = append(ids, n.(map[string]any)["id"].(string))
	}
	return ids
}

func TestNeighborhoodCertificateIsUnmappedNotAnError(t *testing.T) {
	exec := crdNeighborhoodExecutor(t)
	out, err := neighborhood(t, exec, `{"kind":"Certificate","apiGroup":"cert-manager.io","namespace":"results","name":"results-example-org-tls","hops":1}`)
	if err != nil {
		t.Fatalf("a CRD root must not be an error: %v", err)
	}
	if out["unmapped"] != true || out["note"] != "Relationships for Certificate are not mapped yet." {
		t.Errorf("unmapped/note = %v / %v", out["unmapped"], out["note"])
	}
	ids := nodeIDs(out)
	if len(ids) != 2 || ids[0] != "certificate.cert-manager.io/results/results-example-org-tls" || ids[1] != "ingress/results/results-frontend" {
		t.Fatalf("nodes = %v, want the Certificate root then its owning Ingress", ids)
	}
	root := out["nodes"].([]any)[0].(map[string]any)
	if root["status"] != "healthy" || root["kind"] != "Certificate" || root["apiGroup"] != "cert-manager.io" {
		t.Errorf("root node = %v", root)
	}
	edges := out["edges"].([]any)
	if len(edges) != 1 || edges[0].(map[string]any)["source"] != "ingress/results/results-frontend" || edges[0].(map[string]any)["type"] != "owns" {
		t.Errorf("edges = %v, want Ingress owns Certificate", edges)
	}
	if out["root"].(map[string]any)["name"] != "results-example-org-tls" {
		t.Errorf("root = %v", out["root"])
	}

	// The group may be left out; the cache's registry supplies it.
	if out, err := neighborhood(t, exec, `{"kind":"Certificate","namespace":"results","name":"results-example-org-tls"}`); err != nil || out["unmapped"] != true {
		t.Errorf("without apiGroup: %v %v", out, err)
	}
}

func TestNeighborhoodArgoApplicationShowsManagedObjects(t *testing.T) {
	exec := crdNeighborhoodExecutor(t)
	out, err := neighborhood(t, exec, `{"kind":"Application","apiGroup":"argoproj.io","namespace":"argocd","name":"argus-gitops-api"}`)
	if err != nil {
		t.Fatalf("Application root: %v", err)
	}
	if out["unmapped"] != true || out["note"] != "Relationships for Application are not mapped yet." {
		t.Errorf("unmapped/note = %v / %v", out["unmapped"], out["note"])
	}
	ids := nodeIDs(out)
	if len(ids) != 2 || ids[1] != "deployment/argus-gitops-rke2/api" {
		t.Fatalf("nodes = %v, want the managed Deployment", ids)
	}
	if out["nodes"].([]any)[0].(map[string]any)["status"] != "healthy" {
		t.Errorf("Argo health.status Healthy should grade healthy: %v", out["nodes"])
	}
}

func TestNeighborhoodMissingObjectIsSpecificError(t *testing.T) {
	exec := crdNeighborhoodExecutor(t)
	_, err := neighborhood(t, exec, `{"kind":"Certificate","apiGroup":"cert-manager.io","namespace":"results","name":"gone"}`)
	if err == nil || !strings.Contains(err.Error(), "Certificate results/gone not found") {
		t.Errorf("missing CRD object: err = %v", err)
	}
	_, err = neighborhood(t, exec, `{"kind":"Pod","namespace":"results","name":"gone"}`)
	if err == nil || !strings.Contains(err.Error(), "Pod results/gone not found") {
		t.Errorf("missing built-in object: err = %v", err)
	}
	_, err = neighborhood(t, exec, `{"kind":"Node","name":"gone"}`)
	if err == nil || !strings.Contains(err.Error(), "Node gone not found") {
		t.Errorf("missing cluster-scoped object: err = %v", err)
	}
}

// A kind the cache does not hold at all cannot be looked up; it is still a
// normal, explicitly unmapped answer rather than a failure.
func TestNeighborhoodUncachedKindIsUnmapped(t *testing.T) {
	exec := crdNeighborhoodExecutor(t)
	out, err := neighborhood(t, exec, `{"kind":"CertificateRequest","apiGroup":"cert-manager.io","namespace":"results","name":"results-example-org-tls-1"}`)
	if err != nil {
		t.Fatalf("uncached kind: %v", err)
	}
	if out["unmapped"] != true || out["note"] != "Relationships for CertificateRequest are not mapped yet." || len(out["nodes"].([]any)) != 0 {
		t.Errorf("uncached kind = %v", out)
	}
}
