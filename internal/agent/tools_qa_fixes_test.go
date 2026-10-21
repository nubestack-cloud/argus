package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func execJSON(t *testing.T, exec *ToolExecutor, tool, args string) map[string]any {
	t.Helper()
	raw, _, err := exec.Execute(context.Background(), tool, json.RawMessage(args))
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	return out
}

// shop-apps lives in default on lab-dev and annotates workloads in apps. Its
// release Secrets all carry modifiedAt=1773839038 (2026-03-18), while v18's
// Secret was created on 2026-10-05.
func TestHelmRevisionsCarryCreatedAtFromCreationTimestamp(t *testing.T) {
	staleModified := "1773839038"
	v17 := time.Date(2026, 8, 28, 13, 2, 45, 0, time.UTC)
	v18 := time.Date(2026, 10, 5, 12, 36, 18, 0, time.UTC)
	secret := func(rev int, status string, created time.Time) *corev1.Secret {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("sh.helm.release.v1.shop-apps.v%d", rev), Namespace: "default",
				CreationTimestamp: metav1.NewTime(created),
				Labels: map[string]string{"owner": "helm", "name": "shop-apps", "status": status,
					"version": fmt.Sprint(rev), "modifiedAt": staleModified},
			},
			Type: "helm.sh/release.v1",
			Data: map[string][]byte{"release": []byte("H4sI-PAYLOAD-MUST-NOT-LEAK")},
		}
	}
	replicas := int32(1)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "gwas-frontend", Namespace: "apps",
			Annotations: map[string]string{"meta.helm.sh/release-name": "shop-apps", "meta.helm.sh/release-namespace": "default"}},
		Spec: appsv1.DeploymentSpec{Replicas: &replicas},
	}
	exec, typed := newTestExecutor()
	attachObjectCache(t, exec, typed, nil, []runtime.Object{dep, secret(17, "superseded", v17), secret(18, "deployed", v18)}...)

	list := execJSON(t, exec, "list_helm_releases", `{}`)
	rels := list["releases"].([]any)
	if len(rels) != 1 {
		t.Fatalf("releases = %v", rels)
	}
	row := rels[0].(map[string]any)
	if row["revision"].(float64) != 18 || row["createdAt"] != "2026-10-05T12:36:18Z" || row["updated"] != "2026-10-05T12:36:18Z" {
		t.Errorf("release row revision/createdAt/updated = %v/%v/%v, want 18 and v18's creation", row["revision"], row["createdAt"], row["updated"])
	}
	if !strings.HasPrefix(fmt.Sprint(row["modifiedAt"]), "2026-03-18T") {
		t.Errorf("modifiedAt = %v, want Helm's label kept verbatim", row["modifiedAt"])
	}

	st := execJSON(t, exec, "get_helm_release_status", `{"namespace":"default","name":"shop-apps"}`)
	hist := st["history"].([]any)
	if len(hist) != 2 {
		t.Fatalf("history = %v", hist)
	}
	for i, want := range []string{"2026-08-28T13:02:45Z", "2026-10-05T12:36:18Z"} {
		h := hist[i].(map[string]any)
		if h["createdAt"] != want || h["updated"] != want {
			t.Errorf("history[%d] createdAt/updated = %v/%v, want %s", i, h["createdAt"], h["updated"], want)
		}
	}
	b, _ := json.Marshal(st)
	if strings.Contains(string(b), "PAYLOAD-MUST-NOT-LEAK") || strings.Contains(string(b), "H4sI") {
		t.Fatalf("release Secret payload reached the output: %s", b)
	}
}

// apps/gwas-frontend on lab-dev through the tool: one replica, Progressing=False
// ProgressDeadlineExceeded, the new ReplicaSet's pod stuck ContainerCreating.
func TestDiagnoseRolloutToolReportsStuckSingleReplicaRollout(t *testing.T) {
	replicas := int32(1)
	pct := intstr.FromString("25%")
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "gwas-frontend", Namespace: "apps", UID: "dep-uid", Generation: 26,
			Annotations: map[string]string{"deployment.kubernetes.io/revision": "7"}},
		Spec: appsv1.DeploymentSpec{Replicas: &replicas, Strategy: appsv1.DeploymentStrategy{Type: appsv1.RollingUpdateDeploymentStrategyType,
			RollingUpdate: &appsv1.RollingUpdateDeployment{MaxSurge: &pct, MaxUnavailable: &pct}}},
		Status: appsv1.DeploymentStatus{ObservedGeneration: 26, Replicas: 2, UpdatedReplicas: 1, ReadyReplicas: 1, AvailableReplicas: 1, UnavailableReplicas: 1,
			Conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentAvailable, Status: corev1.ConditionTrue, Reason: "MinimumReplicasAvailable", Message: "Deployment has minimum availability."},
				{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse, Reason: "ProgressDeadlineExceeded", Message: `ReplicaSet "gwas-frontend-5dc7fb87d4" has timed out progressing.`},
			}},
	}
	owner := []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "gwas-frontend", UID: "dep-uid"}}
	newRS := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "gwas-frontend-5dc7fb87d4", Namespace: "apps", UID: "new-rs",
		OwnerReferences: owner, Annotations: map[string]string{"deployment.kubernetes.io/revision": "7"}},
		Spec: appsv1.ReplicaSetSpec{Replicas: &replicas}, Status: appsv1.ReplicaSetStatus{Replicas: 1}}
	oldRS := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "gwas-frontend-86c9b566b8", Namespace: "apps", UID: "old-rs",
		OwnerReferences: owner, Annotations: map[string]string{"deployment.kubernetes.io/revision": "6"}},
		Spec: appsv1.ReplicaSetSpec{Replicas: &replicas}, Status: appsv1.ReplicaSetStatus{Replicas: 1, ReadyReplicas: 1, AvailableReplicas: 1}}
	stuckPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "gwas-frontend-5dc7fb87d4-b65jw", Namespace: "apps",
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "gwas-frontend-5dc7fb87d4", UID: "new-rs"}}},
		Spec: corev1.PodSpec{NodeName: "lab-worker-pool-1", Containers: []corev1.Container{{Name: "gwas-frontend", Image: "img"}}},
		Status: corev1.PodStatus{Phase: corev1.PodPending,
			Conditions: []corev1.PodCondition{{Type: corev1.PodScheduled, Status: corev1.ConditionTrue}, {Type: corev1.PodReady, Status: corev1.ConditionFalse}},
			ContainerStatuses: []corev1.ContainerStatus{{Name: "gwas-frontend",
				State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}}}}},
	}
	exec, typed := newTestExecutor()
	attachObjectCache(t, exec, typed, nil, []runtime.Object{dep, newRS, oldRS, stuckPod}...)

	out := execJSON(t, exec, "diagnose_rollout", `{"namespace":"apps","name":"gwas-frontend"}`)
	if out["verdict"] != "stuck" {
		t.Fatalf("verdict = %v, want stuck: %v", out["verdict"], out)
	}
	if r := fmt.Sprint(out["reason"]); !strings.Contains(r, "ProgressDeadlineExceeded") || !strings.Contains(r, "ContainerCreating") {
		t.Errorf("reason = %q", r)
	}
	p := out["progress"].(map[string]any)
	if p["state"] != "stuck" || p["newReplicaSet"] != "gwas-frontend-5dc7fb87d4" || len(p["notReadyPods"].([]any)) != 1 {
		t.Errorf("progress = %v", p)
	}
	if out["policyVerdict"] != "notApplicable" || len(out["notes"].([]any)) != 1 {
		t.Errorf("policyVerdict/notes = %v / %v", out["policyVerdict"], out["notes"])
	}

	// The same stuck pod through explain_scheduling: already bound, so not a
	// scheduling problem.
	sched := execJSON(t, exec, "explain_scheduling", `{"namespace":"apps","pod":"gwas-frontend-5dc7fb87d4-b65jw"}`)
	if sched["alreadyScheduled"] != true || sched["nodeName"] != "lab-worker-pool-1" ||
		sched["verdict"] != "Already scheduled to lab-worker-pool-1; this is not a scheduling problem." {
		t.Errorf("explain_scheduling = %v", sched)
	}
	if n := sched["nodes"].([]any); len(n) != 0 {
		t.Errorf("no node may be evaluated for a bound pod: %v", n)
	}
}

// promProxyFunc stands in for the agent's metrics proxy.
type promProxyFunc func(endpoint string, params map[string]string) ([]byte, error)

func (f promProxyFunc) Get(_ context.Context, endpoint string, params map[string]string) ([]byte, error) {
	return f(endpoint, params)
}

// rancherMonitoringServices is cattle-monitoring-system on rke2: the
// operator's headless prometheus-operated, the ClusterIP
// rancher-monitoring-prometheus, and two prometheus-named components that are
// not a Prometheus server (adapter on 443, node exporter on 9796).
func rancherMonitoringServices() []runtime.Object {
	svc := func(name, clusterIP string, labels map[string]string, ports ...corev1.ServicePort) *corev1.Service {
		return &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "cattle-monitoring-system", Labels: labels},
			Spec: corev1.ServiceSpec{ClusterIP: clusterIP, Ports: ports}}
	}
	return []runtime.Object{
		svc("prometheus-operated", corev1.ClusterIPNone, map[string]string{"operated-prometheus": "true"}, corev1.ServicePort{Name: "http-web", Port: 9090}),
		svc("rancher-monitoring-prometheus", "10.43.11.4", map[string]string{"app": "rancher-monitoring-prometheus"},
			corev1.ServicePort{Name: "http-web", Port: 9090}, corev1.ServicePort{Name: "reloader-web", Port: 8080}),
		svc("rancher-monitoring-prometheus-adapter", "10.43.104.253", map[string]string{"app.kubernetes.io/name": "prometheus-adapter"}, corev1.ServicePort{Name: "https", Port: 443}),
		svc("rancher-monitoring-prometheus-node-exporter", "10.43.150.7", map[string]string{"app.kubernetes.io/name": "prometheus-node-exporter"}, corev1.ServicePort{Name: "http-metrics", Port: 9796}),
	}
}

func assertNoConfigKey(t *testing.T, what string, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), "prometheusService") || strings.Contains(string(b), "metrics.") {
		t.Errorf("%s leaks a config key: %s", what, b)
	}
}

func TestCostAndTrafficNotConfiguredDetectsPrometheus(t *testing.T) {
	exec, typed := newTestExecutor()
	attachObjectCache(t, exec, typed, nil, rancherMonitoringServices()...)

	c := execJSON(t, exec, "get_cost_summary", `{}`)
	s := c["summary"].(map[string]any)
	if s["available"] != false || s["reason"] != "not_configured" || !strings.Contains(fmt.Sprint(s["detail"]), "No Prometheus is connected") {
		t.Errorf("cost summary = %v", s)
	}
	want := map[string]any{"namespace": "cattle-monitoring-system", "name": "rancher-monitoring-prometheus", "port": float64(9090), "flavour": "prometheus"}
	if fmt.Sprint(c["detectedPrometheus"]) != fmt.Sprint(want) {
		t.Errorf("cost detectedPrometheus = %v, want %v", c["detectedPrometheus"], want)
	}
	assertNoConfigKey(t, "cost", c)

	tr := execJSON(t, exec, "get_traffic", `{}`)
	if tr["available"] != false || tr["reasonCode"] != "not_configured" || !strings.HasSuffix(fmt.Sprint(tr["reason"]), ".") {
		t.Errorf("traffic = %v", tr)
	}
	if fmt.Sprint(tr["detectedPrometheus"]) != fmt.Sprint(want) {
		t.Errorf("traffic detectedPrometheus = %v, want %v", tr["detectedPrometheus"], want)
	}
	assertNoConfigKey(t, "traffic", tr)
}

func TestDetectPrometheusFallsBackToOperatedAndToNone(t *testing.T) {
	exec, typed := newTestExecutor()
	attachObjectCache(t, exec, typed, nil, rancherMonitoringServices()[0], rancherMonitoringServices()[2])
	if d := exec.detectPrometheus(); d == nil || d.Name != "prometheus-operated" || d.Port != 9090 {
		t.Errorf("detectPrometheus = %+v, want prometheus-operated:9090", d)
	}
	exec2, typed2 := newTestExecutor()
	attachObjectCache(t, exec2, typed2, nil, rancherMonitoringServices()[2], rancherMonitoringServices()[3])
	if d := exec2.detectPrometheus(); d != nil {
		t.Errorf("an adapter and an exporter are not Prometheus: %+v", d)
	}
	out := execJSON(t, exec2, "get_cost_summary", `{}`)
	if _, ok := out["detectedPrometheus"]; ok {
		t.Errorf("no detection must leave the field out: %v", out)
	}
}

func TestCostAndTrafficUnreachableVsNoMetrics(t *testing.T) {
	exec, typed := newTestExecutor()
	attachObjectCache(t, exec, typed, nil)

	// The service proxy fails: a 503 from the API server.
	exec.metricsProxy = promProxyFunc(func(string, map[string]string) ([]byte, error) {
		return nil, apierrors.NewServiceUnavailable("no endpoints available for service \"rancher-monitoring-prometheus:9090\"")
	})
	s := execJSON(t, exec, "get_cost_summary", `{}`)["summary"].(map[string]any)
	if s["reason"] != "unreachable" || strings.Contains(fmt.Sprint(s["detail"]), "endpoints") {
		t.Errorf("unreachable cost = %v", s)
	}
	tr := execJSON(t, exec, "get_traffic", `{}`)
	if tr["reasonCode"] != "unreachable" || tr["detectedPrometheus"] != nil {
		t.Errorf("unreachable traffic = %v", tr)
	}

	// Prometheus answers every query with an empty vector.
	exec.metricsProxy = promProxyFunc(func(string, map[string]string) ([]byte, error) {
		return []byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`), nil
	})
	s = execJSON(t, exec, "get_cost_summary", `{}`)["summary"].(map[string]any)
	if s["reason"] != "no_metrics" {
		t.Errorf("no-metrics cost = %v", s)
	}
	if tr := execJSON(t, exec, "get_traffic", `{}`); tr["reasonCode"] != "no_source" {
		t.Errorf("no-source traffic = %v", tr)
	}

	// Prometheus rejects the query (HTTP 400): it answered, so not unreachable.
	exec.metricsProxy = promProxyFunc(func(string, map[string]string) ([]byte, error) {
		return nil, apierrors.NewBadRequest("bad_data: parse error")
	})
	if s := execJSON(t, exec, "get_cost_summary", `{}`)["summary"].(map[string]any); s["reason"] != "query_error" {
		t.Errorf("rejected-query cost = %v", s)
	}
}

// Release members: every annotated object, worst health first, capped.
func TestHelmReleaseRowListsMembers(t *testing.T) {
	ann := map[string]string{"meta.helm.sh/release-name": "shop-apps", "meta.helm.sh/release-namespace": "default"}
	one, zero := int32(1), int32(0)
	dep := func(name string, ready int32) *appsv1.Deployment {
		return &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "apps", Annotations: ann, Generation: 1},
			Spec:   appsv1.DeploymentSpec{Replicas: &one},
			Status: appsv1.DeploymentStatus{ObservedGeneration: 1, Replicas: 1, ReadyReplicas: ready, AvailableReplicas: ready, UpdatedReplicas: 1}}
	}
	objs := []runtime.Object{dep("lab-mainpage", 1), dep("gwas-frontend", zero),
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "gwas-frontend", Namespace: "apps", Annotations: ann}}}
	for i := 0; i < 60; i++ {
		objs = append(objs, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("cm-%02d", i), Namespace: "apps", Annotations: ann}})
	}
	exec, typed := newTestExecutor()
	attachObjectCache(t, exec, typed, nil, objs...)

	row := execJSON(t, exec, "list_helm_releases", `{}`)["releases"].([]any)[0].(map[string]any)
	if row["objects"].(float64) != 63 || row["membersTruncated"] != true {
		t.Fatalf("objects/membersTruncated = %v/%v", row["objects"], row["membersTruncated"])
	}
	ms := row["members"].([]any)
	if len(ms) != 50 {
		t.Fatalf("members = %d, want the cap of 50", len(ms))
	}
	first, second := ms[0].(map[string]any), ms[1].(map[string]any)
	if first["name"] != "gwas-frontend" || first["kind"] != "Deployment" || first["apiGroup"] != "apps" || first["namespace"] != "apps" || first["health"] != "unhealthy" {
		t.Errorf("members[0] = %v, want the unhealthy Deployment first", first)
	}
	if second["name"] != "lab-mainpage" || second["health"] != "healthy" {
		t.Errorf("members[1] = %v, want the healthy Deployment next", second)
	}
	if third := ms[2].(map[string]any); third["kind"] != "ConfigMap" || third["name"] != "cm-00" || third["health"] != nil {
		t.Errorf("members[2] = %v, want ungraded ConfigMaps after graded objects, by name", third)
	}
}

// Error text crosses the tunnel too: Execute runs it through the pattern
// layer, and the original stays reachable for errors.Is/As.
func TestExecuteRedactsErrorText(t *testing.T) {
	exec, typed := newTestExecutor()
	attachObjectCache(t, exec, typed, nil)
	const secret = "s3cr3t-value-must-not-egress"
	_, _, err := exec.Execute(context.Background(), "get_neighborhood",
		json.RawMessage(`{"kind":"Pod","namespace":"prod","name":"api password=`+secret+`"}`))
	if err == nil {
		t.Fatal("want a not-found error")
	}
	if strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "not found") {
		t.Errorf("error text = %q, want the credential redacted and the message kept", err)
	}

	sentinel := errors.New("Authorization: Bearer " + secret)
	wrapped := redactError(fmt.Errorf("upstream: %w", sentinel))
	if strings.Contains(wrapped.Error(), secret) {
		t.Errorf("redactError kept the bearer token: %q", wrapped)
	}
	if !errors.Is(wrapped, sentinel) {
		t.Error("errors.Is must still see the original through the redacted wrapper")
	}
	var nf *apierrors.StatusError
	if !errors.As(redactError(apierrors.NewNotFound(corev1.Resource("pods"), "x")), &nf) {
		t.Error("errors.As must still reach a wrapped StatusError")
	}
}

func TestDescribeMissingObjectNamesIt(t *testing.T) {
	exec, _ := newTestExecutor()
	_, _, err := exec.Execute(context.Background(), "describe_resource", json.RawMessage(`{"gvk":"apps/v1/Deployment","namespace":"apps","name":"gone"}`))
	if err == nil || err.Error() != "Deployment apps/gone not found" {
		t.Errorf("err = %v, want \"Deployment apps/gone not found\"", err)
	}
}

func TestNetpolMissingSourcePodNamesIt(t *testing.T) {
	exec, typed := newTestExecutor()
	attachObjectCache(t, exec, typed, nil, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod"}})
	_, _, err := exec.Execute(context.Background(), "evaluate_network_policy",
		json.RawMessage(`{"source":{"namespace":"prod","pod":"ghost"},"destination":{"kind":"Service","namespace":"prod","name":"api"},"port":80}`))
	if err == nil || err.Error() != "source pod prod/ghost not found" {
		t.Errorf("err = %v", err)
	}
}

// The log stream's own error (the API server's 400) is not what the caller
// sees; the pod's status explains it. The typed fake cannot fail a log
// stream, so explainLogsError is exercised directly with the 400 it gets.
func TestExplainLogsErrorFromPodStatus(t *testing.T) {
	waiting := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "gwas-frontend-5dc7fb87d4-b65jw", Namespace: "apps"},
		Spec:       corev1.PodSpec{NodeName: "n1", Containers: []corev1.Container{{Name: "gwas-frontend", Image: "img"}}},
		Status: corev1.PodStatus{Phase: corev1.PodPending, ContainerStatuses: []corev1.ContainerStatus{{Name: "gwas-frontend",
			State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}}}}},
	}
	running := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "apps"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "web", Image: "img"}, {Name: "sidecar", Image: "img"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{
			{Name: "web", RestartCount: 0, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}},
			{Name: "sidecar", RestartCount: 0, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}},
	}
	exec, typed := newTestExecutor()
	attachObjectCache(t, exec, typed, nil, waiting, running)
	streamErr := apierrors.NewBadRequest(`container "gwas-frontend" in pod "gwas-frontend-5dc7fb87d4-b65jw" is waiting to start: ContainerCreating`)

	for _, tc := range []struct {
		args getLogsArgs
		want string
	}{
		{getLogsArgs{Namespace: "apps", Pod: "gwas-frontend-5dc7fb87d4-b65jw"},
			"container gwas-frontend in pod apps/gwas-frontend-5dc7fb87d4-b65jw has not started yet (ContainerCreating), so it has no logs"},
		{getLogsArgs{Namespace: "apps", Pod: "web-1", Container: "web", Previous: true},
			"container web has not restarted, so there is no previous container's log"},
		{getLogsArgs{Namespace: "apps", Pod: "web-1"},
			"pod apps/web-1 has 2 containers (web, sidecar); name the container to read"},
		{getLogsArgs{Namespace: "apps", Pod: "web-1", Container: "nope"},
			"container nope not found in pod apps/web-1"},
		{getLogsArgs{Namespace: "apps", Pod: "gone"}, "Pod apps/gone not found"},
	} {
		if got := exec.explainLogsError(context.Background(), tc.args, streamErr); got == nil || got.Error() != tc.want {
			t.Errorf("%+v: err = %v, want %q", tc.args, got, tc.want)
		}
	}
}
