package argusagentchart

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeKubeconfig points helm at a minimal, empty Kubernetes API. `helm install
// --dry-run=client` renders NOTES.txt, which `helm template` skips, but Helm 3
// still checks the cluster is reachable and asks it for its API versions
// before rendering. This answers those reads as an empty cluster, refuses any
// write, and so lets the NOTES tests run the same on Helm 3 and Helm 4, with
// no cluster behind them.
func fakeKubeconfig(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","code":403}`)
			return
		}
		p := r.URL.Path
		switch {
		case p == "/version":
			fmt.Fprint(w, `{"major":"1","minor":"30","gitVersion":"v1.30.0"}`)
			return
		case p == "/api":
			fmt.Fprint(w, `{"kind":"APIVersions","versions":["v1"]}`)
			return
		case p == "/apis":
			groups := []string{}
			for gv := range fakeAPIResources {
				if gv == "v1" {
					continue
				}
				g, v, _ := strings.Cut(gv, "/")
				groups = append(groups, fmt.Sprintf(`{"name":%q,"versions":[{"groupVersion":%q,"version":%q}],"preferredVersion":{"groupVersion":%q,"version":%q}}`, g, gv, v, gv, v))
			}
			fmt.Fprintf(w, `{"kind":"APIGroupList","apiVersion":"v1","groups":[%s]}`, strings.Join(groups, ","))
			return
		case strings.HasSuffix(p, "/secrets"):
			fmt.Fprint(w, `{"kind":"SecretList","apiVersion":"v1","items":[]}`)
			return
		}
		gv := strings.TrimPrefix(strings.TrimPrefix(p, "/apis/"), "/api/")
		if kinds, ok := fakeAPIResources[gv]; ok {
			res := []string{}
			for _, k := range kinds {
				res = append(res, fmt.Sprintf(`{"name":%q,"namespaced":%t,"kind":%q,"verbs":["get","list"]}`, k.plural, k.namespaced, k.kind))
			}
			fmt.Fprintf(w, `{"kind":"APIResourceList","groupVersion":%q,"resources":[%s]}`, gv, strings.Join(res, ","))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`)
	}))
	t.Cleanup(srv.Close)
	path := filepath.Join(t.TempDir(), "kubeconfig")
	cfg := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters: [{name: fake, cluster: {server: %q}}]
users: [{name: fake, user: {}}]
contexts: [{name: fake, context: {cluster: fake, user: fake, namespace: default}}]
current-context: fake
`, srv.URL)
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type fakeKind struct {
	kind, plural string
	namespaced   bool
}

// fakeAPIResources is every kind the charts render, by group/version.
var fakeAPIResources = map[string][]fakeKind{
	"v1": {{"Namespace", "namespaces", false}, {"ServiceAccount", "serviceaccounts", true}, {"Secret", "secrets", true},
		{"ConfigMap", "configmaps", true}, {"Service", "services", true}, {"PersistentVolumeClaim", "persistentvolumeclaims", true},
		{"Pod", "pods", true}},
	"apps/v1":                      {{"Deployment", "deployments", true}, {"StatefulSet", "statefulsets", true}},
	"batch/v1":                     {{"Job", "jobs", true}, {"CronJob", "cronjobs", true}},
	"rbac.authorization.k8s.io/v1": {{"Role", "roles", true}, {"RoleBinding", "rolebindings", true}, {"ClusterRole", "clusterroles", false}, {"ClusterRoleBinding", "clusterrolebindings", false}},
	"networking.k8s.io/v1":         {{"Ingress", "ingresses", true}, {"NetworkPolicy", "networkpolicies", true}},
	"admissionregistration.k8s.io/v1": {{"ValidatingAdmissionPolicy", "validatingadmissionpolicies", false},
		{"ValidatingAdmissionPolicyBinding", "validatingadmissionpolicybindings", false}},
	"apiextensions.k8s.io/v1":      {{"CustomResourceDefinition", "customresourcedefinitions", false}},
	"gateway.networking.k8s.io/v1": {{"HTTPRoute", "httproutes", true}},
	"policy/v1":                    {{"PodDisruptionBudget", "poddisruptionbudgets", true}},
}
