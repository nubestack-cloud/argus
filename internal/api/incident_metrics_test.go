package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"
)

func TestParseMatrixReadsQueryMetricsResult(t *testing.T) {
	raw := json.RawMessage(`{"resultType":"matrix","result":[{"metric":{"pod":"a-1"},"values":[[1700000000,"0.5"],[1700000030,"x"],[1700000060,"1.25"]]}],"totalSeries":1,"returned":1,"truncated":false}`)
	got := parseMatrix(raw)
	if len(got) != 1 || got[0].Labels["pod"] != "a-1" || len(got[0].Points) != 2 || got[0].Points[1][1] != 1.25 {
		t.Fatalf("parseMatrix = %+v", got)
	}
}

func TestObjectRefFromKey(t *testing.T) {
	k := "apps/v1/Deployment|prod|payments"
	ref, ok := objectRefFromKey(&k)
	if !ok || ref.Kind != "Deployment" || ref.Namespace != "prod" || ref.Name != "payments" {
		t.Fatalf("got %+v %v", ref, ok)
	}
	bad := "v1/Pod|prod|"
	if _, ok := objectRefFromKey(&bad); ok {
		t.Fatal("empty name accepted")
	}
}

// PROJECT.md AD7: the pod pattern is spliced into PromQL, so only DNS-1123
// names of a pod-owning kind produce one.
func TestPodPatternFor(t *testing.T) {
	for _, tc := range []struct{ kind, ns, name, want string }{
		{"StatefulSet", "shop", "db", `db-[0-9]+`},
		{"Pod", "shop", "web-1", `web-1`},
		{"Service", "shop", "web", ""},
		{"Deployment", "shop", `web"}) or vector(1`, ""},
		{"Deployment", "Shop", "web", ""},
		{"Deployment", "", "web", ""},
	} {
		if got := podPatternFor(tc.kind, tc.ns, tc.name); got != tc.want {
			t.Errorf("podPatternFor(%q, %q, %q) = %q, want %q", tc.kind, tc.ns, tc.name, got, tc.want)
		}
	}
}

// Input is refused before anything is read: a missing field, or an object the
// tab cannot chart, is a 400 with nothing sent to the agent.
func TestWorkloadMetricsRejectsBadInput(t *testing.T) {
	s := &Server{}
	for _, q := range []string{
		"kind=Deployment&namespace=shop",
		"kind=Service&namespace=shop&name=web",
		"kind=Deployment&namespace=shop&name=" + url.QueryEscape(`web"}`),
	} {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/cl_x/workload-metrics?"+q, nil)
		r.SetPathValue("id", "cl_x")
		w := httptest.NewRecorder()
		s.handleWorkloadMetrics(w, r, &requestContext{})
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", q, w.Code)
		}
	}
}

// The pattern must match the controllers' real pod names and nothing a
// sibling workload with a longer name runs (the postgres-0 that appeared on
// the hub Deployment's chart, 2026-10-14).
func TestPodPatternMatchesOnlyItsOwnPods(t *testing.T) {
	for _, tc := range []struct {
		kind, name, pod string
		want            bool
	}{
		{"Deployment", "argus-hub", "argus-hub-644c9d85bc-ndfsm", true},
		{"Deployment", "argus-hub", "argus-hub-7c6b8d9f5-x2b4z", true},
		{"Deployment", "argus-hub", "argus-hub-postgres-0", false},
		{"Deployment", "argus-hub", "argus-hub-cli-runner-55c57bf875-zhhkl", false},
		{"Deployment", "web", "web-api-6d4b9c7f8-qwxyz", false},
		{"StatefulSet", "db", "db-0", true},
		{"StatefulSet", "db", "db-backup-29865720-9k8mb", false},
		{"DaemonSet", "agent", "agent-x7z9k", true},
		{"DaemonSet", "agent", "agent-exporter-x7z9k", false},
		{"Job", "migrate", "migrate-4b2cd", true},
	} {
		re := regexp.MustCompile("^(?:" + podPatternFor(tc.kind, "ns", tc.name) + ")$")
		if got := re.MatchString(tc.pod); got != tc.want {
			t.Errorf("%s %q vs pod %q: matched %v, want %v", tc.kind, tc.name, tc.pod, got, tc.want)
		}
	}
}
