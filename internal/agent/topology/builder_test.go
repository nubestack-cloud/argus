package topology

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestBuild_NilProviderErrors(t *testing.T) {
	if _, err := NewBuilder(nil).Build(BuildOptions{}); err == nil {
		t.Fatal("expected an error without a provider")
	}
}

// A Service's selector matches a Job's pod template whether or not the Job
// is still running; only a running one is a backend, and a CronJob's
// template never is.
func TestBuild_ServiceOnlyExposesActiveJobs(t *testing.T) {
	tmpl := corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"role": "reindex"}}}
	job := func(name string, st batchv1.JobStatus) *batchv1.Job {
		return &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "search", Name: name}, Spec: batchv1.JobSpec{Template: tmpl}, Status: st}
	}
	provider := &mockProvider{
		services: []*corev1.Service{{ObjectMeta: metav1.ObjectMeta{Namespace: "search", Name: "reindex-status"},
			Spec: corev1.ServiceSpec{Selector: tmpl.Labels}}},
		jobs: []*batchv1.Job{job("reindex-0915", batchv1.JobStatus{Active: 2}), job("reindex-0914", batchv1.JobStatus{Succeeded: 1})},
		cronJobs: []*batchv1.CronJob{{ObjectMeta: metav1.ObjectMeta{Namespace: "search", Name: "reindex"},
			Spec: batchv1.CronJobSpec{JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{Template: tmpl}}}}},
	}
	var exposed []string
	for e := range edgeSet(build(t, provider, BuildOptions{}).Edges) {
		if strings.HasPrefix(e, "service/search/reindex-status -exposes-> ") {
			exposed = append(exposed, strings.TrimPrefix(e, "service/search/reindex-status -exposes-> "))
		}
	}
	if !slices.Equal(exposed, []string{"job/search/reindex-0915"}) {
		t.Errorf("exposed = %v, want only the running Job", exposed)
	}
}

func TestBuild_ServiceExposesAllPorts(t *testing.T) {
	provider := &mockProvider{services: []*corev1.Service{{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "prod"},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 80, TargetPort: intstr.FromInt32(8080), Protocol: corev1.ProtocolTCP},
				{Name: "https", Port: 443, TargetPort: intstr.FromString("https"), Protocol: corev1.ProtocolTCP},
			},
		},
	}}}
	n := nodeByID(build(t, provider, BuildOptions{}).Nodes, "service/prod/web")
	if n == nil {
		t.Fatal("expected Service node")
	}
	got, err := json.Marshal(n.Summary["ports"])
	if err != nil {
		t.Fatal(err)
	}
	if want := `[{"name":"http","port":80,"targetPort":"8080","protocol":"TCP"},{"name":"https","port":443,"targetPort":"https","protocol":"TCP"}]`; string(got) != want {
		t.Fatalf("ports = %s, want %s", got, want)
	}
}

func TestServiceTopologyPorts(t *testing.T) {
	h2c := "kubernetes.io/h2c"
	got, err := json.Marshal(serviceTopologyPorts([]corev1.ServicePort{
		{Name: "http", Port: 80, TargetPort: intstr.FromInt32(8080), Protocol: corev1.ProtocolTCP, AppProtocol: &h2c},
		// Unnamed: valid and common when a Service declares only one port.
		{Port: 9090, TargetPort: intstr.FromInt32(9090), Protocol: corev1.ProtocolTCP},
	}))
	if err != nil {
		t.Fatal(err)
	}
	// The JSON the map's Service node reads: no name or appProtocol key
	// where the port has none.
	want := `[{"name":"http","port":80,"targetPort":"8080","protocol":"TCP","appProtocol":"kubernetes.io/h2c"},{"port":9090,"targetPort":"9090","protocol":"TCP"}]`
	if string(got) != want {
		t.Fatalf("ports = %s\nwant    %s", got, want)
	}
	if n := len(serviceTopologyPorts(make([]corev1.ServicePort, 25))); n != maxSummaryListItems {
		t.Errorf("ports not capped: %d", n)
	}
}

func TestBuild_NetworkPolicyNodes(t *testing.T) {
	provider := &mockProvider{
		deployments: []*appsv1.Deployment{
			deployment("demo", "frontend", map[string]string{"app": "frontend"}),
			deployment("demo", "backend", map[string]string{"app": "backend"}),
		},
		networkPolicies: []*networkingv1.NetworkPolicy{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "allow-frontend", Namespace: "demo"},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "frontend"}},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				},
			},
			{
				// Empty selector: no edges, flagged instead.
				ObjectMeta: metav1.ObjectMeta{Name: "default-deny", Namespace: "demo"},
				Spec:       networkingv1.NetworkPolicySpec{PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}},
			},
			{
				// Different namespace: must not match demo workloads.
				ObjectMeta: metav1.ObjectMeta{Name: "other-ns-policy", Namespace: "other"},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "frontend"}},
				},
			},
		},
	}
	topo := build(t, provider, BuildOptions{})
	count := 0
	for _, n := range topo.Nodes {
		if n.Kind == KindNetworkPolicy {
			count++
			if n.Status != StatusHealthy || n.APIGroup != "networking.k8s.io" {
				t.Errorf("%s: status %s group %q", n.ID, n.Status, n.APIGroup)
			}
		}
	}
	if count != 3 {
		t.Errorf("expected 3 NetworkPolicy nodes, got %d", count)
	}
	if n := nodeByID(topo.Nodes, "networkpolicy/demo/default-deny"); n == nil || n.Summary["matchesAllPods"] != true {
		t.Error("default-deny should carry matchesAllPods=true")
	}
	var protects []string
	for _, e := range topo.Edges {
		if e.Type == EdgeProtects {
			protects = append(protects, e.Source+" -> "+e.Target)
		}
	}
	if !slices.Equal(protects, []string{"networkpolicy/demo/allow-frontend -> deployment/demo/frontend"}) {
		t.Errorf("protects edges = %v", protects)
	}
}

func TestBuild_PDBProtectsSelectedWorkloads(t *testing.T) {
	provider := &mockProvider{
		deployments: []*appsv1.Deployment{deployment("prod", "api", map[string]string{"app": "api"})},
		statefulSets: []*appsv1.StatefulSet{{
			ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "prod"},
			Spec:       appsv1.StatefulSetSpec{Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "db"}}}},
		}},
		pdbs: []*policyv1.PodDisruptionBudget{{
			ObjectMeta: metav1.ObjectMeta{Name: "api-pdb", Namespace: "prod"},
			Spec:       policyv1.PodDisruptionBudgetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}}},
			Status:     policyv1.PodDisruptionBudgetStatus{DisruptionsAllowed: 0, CurrentHealthy: 1, DesiredHealthy: 2},
		}},
	}
	topo := build(t, provider, BuildOptions{})
	edges := edgeSet(topo.Edges)
	if !edges["poddisruptionbudget/prod/api-pdb -protects-> deployment/prod/api"] {
		t.Errorf("missing PDB edge: %v", edges)
	}
	if edges["poddisruptionbudget/prod/api-pdb -protects-> statefulset/prod/db"] {
		t.Error("PDB protected an unselected workload")
	}
	if n := nodeByID(topo.Nodes, "poddisruptionbudget/prod/api-pdb"); n.Status != StatusDegraded {
		t.Errorf("PDB blocking all disruptions below desired = %s, want degraded", n.Status)
	}
}

func TestBuild_NetworkPolicyNamespaceIsolation(t *testing.T) {
	provider := &mockProvider{
		deployments: []*appsv1.Deployment{deployment("ns-b", "web", map[string]string{"app": "web"})},
		networkPolicies: []*networkingv1.NetworkPolicy{{
			ObjectMeta: metav1.ObjectMeta{Name: "web-policy", Namespace: "ns-a"},
			Spec:       networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}},
		}},
	}
	for _, e := range build(t, provider, BuildOptions{}).Edges {
		if e.Source == "networkpolicy/ns-a/web-policy" {
			t.Errorf("cross-namespace edge %s", e.ID)
		}
	}
}

// An owner reference names a CronJob only when its API group is batch; a
// same-named kind from another group is a different object.
func TestBuild_JobOwnerRequiresCronJobGroup(t *testing.T) {
	owned := func(name, apiVersion string) *batchv1.Job {
		j := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "ops", Name: name}, Status: batchv1.JobStatus{Active: 1}}
		j.OwnerReferences = append(j.OwnerReferences, metav1.OwnerReference{APIVersion: apiVersion, Kind: "CronJob", Name: "rotate-logs"})
		return j
	}
	topo := build(t, &mockProvider{
		cronJobs: []*batchv1.CronJob{{ObjectMeta: metav1.ObjectMeta{Namespace: "ops", Name: "rotate-logs"}}},
		jobs:     []*batchv1.Job{owned("rotate-logs-28911", "batch/v1"), owned("rotate-logs-x", "scheduler.example.com/v1alpha1")},
	}, BuildOptions{})
	var owns []string
	for _, e := range topo.Edges {
		if e.Type == EdgeOwns && e.Source == "cronjob/ops/rotate-logs" {
			owns = append(owns, e.Target)
		}
	}
	if !slices.Equal(owns, []string{"job/ops/rotate-logs-28911"}) {
		t.Errorf("CronJob owns %v", owns)
	}
}

func TestOwnerGroupMatches(t *testing.T) {
	for _, tc := range []struct {
		kind, apiVersion string
		want             bool
	}{
		{"ReplicaSet", "apps/v1", true},
		{"ReplicaSet", "", true},
		{"Job", "batch/v1", true},
		{"Job", "batch.volcano.sh/v1alpha1", false},
		{"Deployment", "extensions.example/v1", false},
		{"Widget", "widgets.example/v1", true},
	} {
		if got := ownerGroupMatches(tc.kind, tc.apiVersion); got != tc.want {
			t.Errorf("ownerGroupMatches(%s, %s) = %v, want %v", tc.kind, tc.apiVersion, got, tc.want)
		}
	}
}

// Workload-template references are inverted into consumer edges: referenced
// ConfigMaps / PVCs / ServiceAccounts get a node and an edge to every
// referencing workload, unreferenced ones are omitted, and matching is
// strictly namespace-scoped.
func TestBuild_ConfigPVCAndIdentityEdges(t *testing.T) {
	withRefs := func(ns, name, cmName, pvcName, sa string) *appsv1.Deployment {
		d := deployment(ns, name, nil)
		spec := &d.Spec.Template.Spec
		spec.ServiceAccountName = sa
		if cmName != "" {
			spec.Volumes = append(spec.Volumes, corev1.Volume{Name: "cm", VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: cmName}}}})
		}
		if pvcName != "" {
			spec.Volumes = append(spec.Volumes, corev1.Volume{Name: "data", VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: pvcName}}})
		}
		return d
	}
	cm := func(ns, name string) *corev1.ConfigMap {
		return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
	}
	provider := &mockProvider{
		deployments: []*appsv1.Deployment{
			withRefs("app", "web", "shared-cm", "data", "web-identity"),
			withRefs("app", "worker", "shared-cm", "", ""),
			withRefs("other", "web", "shared-cm", "", ""),
		},
		configMaps: []*corev1.ConfigMap{cm("app", "shared-cm"), cm("app", "unused-cm"), cm("other", "shared-cm")},
		pvcs: []*corev1.PersistentVolumeClaim{
			{ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "app"}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "pv-1"},
				Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}},
			{ObjectMeta: metav1.ObjectMeta{Name: "unused-pvc", Namespace: "app"}},
		},
		pvs: []*corev1.PersistentVolume{
			{ObjectMeta: metav1.ObjectMeta{Name: "pv-1"}, Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound}},
			{ObjectMeta: metav1.ObjectMeta{Name: "pv-unbound"}},
		},
		serviceAccounts: []*corev1.ServiceAccount{
			{ObjectMeta: metav1.ObjectMeta{Name: "web-identity", Namespace: "app"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "unused", Namespace: "app"}},
		},
	}
	topo := build(t, provider, BuildOptions{})
	edges := edgeSet(topo.Edges)
	for _, want := range []string{
		"configmap/app/shared-cm -configures-> deployment/app/web",
		"configmap/app/shared-cm -configures-> deployment/app/worker",
		"configmap/other/shared-cm -configures-> deployment/other/web",
		"persistentvolumeclaim/app/data -uses-> deployment/app/web",
		"persistentvolume//pv-1 -uses-> persistentvolumeclaim/app/data",
		"serviceaccount/app/web-identity -configures-> deployment/app/web",
	} {
		if !edges[want] {
			t.Errorf("missing edge %s", want)
		}
	}
	for _, unwanted := range []string{
		"configmap/other/shared-cm -configures-> deployment/app/web",
		"configmap/app/shared-cm -configures-> deployment/other/web",
	} {
		if edges[unwanted] {
			t.Errorf("cross-namespace edge %s", unwanted)
		}
	}
	for _, absent := range []string{"configmap/app/unused-cm", "persistentvolumeclaim/app/unused-pvc", "serviceaccount/app/unused", "persistentvolume//pv-unbound"} {
		if nodeByID(topo.Nodes, absent) != nil {
			t.Errorf("unreferenced %s should be absent", absent)
		}
	}
	if pv := nodeByID(topo.Nodes, "persistentvolume//pv-1"); pv == nil || pv.Namespace != "" || pv.Status != StatusHealthy {
		t.Errorf("bound PV node = %+v", pv)
	}
	if calls := provider.calls[KindPV]; len(calls) != 1 || calls[0] != "" {
		t.Errorf("PVs must be listed cluster-wide once, got %v", calls)
	}
}

// Secret references are never collected: there is no Secret node kind, and a
// workload that mounts a Secret gains no edge or node for it.
func TestBuild_SecretsNeverAppear(t *testing.T) {
	d := deployment("app", "web", nil)
	d.Spec.Template.Spec.Volumes = []corev1.Volume{{Name: "tls", VolumeSource: corev1.VolumeSource{
		Secret: &corev1.SecretVolumeSource{SecretName: "web-tls"}}}}
	d.Spec.Template.Spec.Containers = []corev1.Container{{Name: "app", Env: []corev1.EnvVar{{
		Name: "PASSWORD", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: "db-creds"}, Key: "password"}},
	}}}}
	topo := build(t, &mockProvider{deployments: []*appsv1.Deployment{d}}, BuildOptions{})
	for _, n := range topo.Nodes {
		if strings.Contains(n.ID, "secret") || strings.Contains(n.Name, "web-tls") || strings.Contains(n.Name, "db-creds") {
			t.Errorf("secret surfaced as node %s", n.ID)
		}
	}
	if len(topo.Edges) != 0 {
		t.Errorf("secret references produced edges: %v", topo.Edges)
	}
	if _, ok := normalizeKind("Secret"); ok {
		t.Error("Secret must not be a drawable kind")
	}
}

// Summaries are a curated set of status counters: spec fields, env, pod
// annotations and ConfigMap values never enter a node.
func TestBuild_SummariesAreCurated(t *testing.T) {
	d := deployment("app", "web", map[string]string{"app": "web"})
	d.Annotations = map[string]string{"kubectl.kubernetes.io/last-applied-configuration": "{...}"}
	pod := runningPod("app", "web-1", "", map[string]string{"app": "web"})
	pod.Annotations = map[string]string{"note": "private"}
	pod.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "API_KEY", Value: "sha256:" + strings.Repeat("c", 64)}}
	provider := &mockProvider{
		deployments: []*appsv1.Deployment{d},
		pods:        []*corev1.Pod{pod},
		configMaps: []*corev1.ConfigMap{{
			ObjectMeta: metav1.ObjectMeta{Name: "cfg", Namespace: "app"},
			Data:       map[string]string{"password": "sha256:" + strings.Repeat("d", 64)},
		}},
	}
	topo := build(t, provider, BuildOptions{Focus: Ref{Kind: "ConfigMap", Namespace: "app", Name: "cfg"}})
	allowed := map[NodeKind]map[string]bool{
		KindDeployment: {"replicas": true, "readyReplicas": true, "availableReplicas": true, "updatedReplicas": true, "strategy": true},
		KindPod:        {"phase": true, "ready": true, "restarts": true, "containers": true, "nodeName": true, "terminating": true},
		KindConfigMap:  {"keys": true},
	}
	for _, n := range topo.Nodes {
		for k := range n.Summary {
			if !allowed[n.Kind][k] {
				t.Errorf("%s summary has unexpected key %q", n.ID, k)
			}
		}
		dump := fmt.Sprint(n)
		for _, leak := range []string{strings.Repeat("c", 64), "API_KEY", strings.Repeat("d", 64), "private", "last-applied"} {
			if strings.Contains(dump, leak) {
				t.Errorf("%s leaked %q: %+v", n.ID, leak, n)
			}
		}
	}
	if cmNode := nodeByID(topo.Nodes, "configmap/app/cfg"); cmNode == nil || cmNode.Summary["keys"] != 1 {
		t.Errorf("focus ConfigMap node = %+v, want keys=1", cmNode)
	}
}

// ReplicaSets owned by a Deployment in the graph are hidden and their pods
// hang off the Deployment; a ReplicaSet without one is drawn so the chain is
// never cut.
func TestBuild_ReplicaSetVisibility(t *testing.T) {
	labels := map[string]string{"app": "web"}
	bare := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{Name: "bare", Namespace: "prod"},
		Spec:       appsv1.ReplicaSetSpec{Replicas: int32Ptr(1), Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "bare"}}}},
	}
	scaledDown := replicaSet("prod", "web-old", "web", labels)
	scaledDown.Spec.Replicas = int32Ptr(0)
	provider := &mockProvider{
		deployments: []*appsv1.Deployment{deployment("prod", "web", labels)},
		replicaSets: []*appsv1.ReplicaSet{replicaSet("prod", "web-rs", "web", labels), scaledDown, bare},
		pods: []*corev1.Pod{
			runningPod("prod", "web-1", "web-rs", labels),
			runningPod("prod", "bare-1", "bare", map[string]string{"app": "bare"}),
		},
		services: []*corev1.Service{{ObjectMeta: metav1.ObjectMeta{Name: "bare", Namespace: "prod"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "bare"}}}},
	}

	topo := build(t, provider, BuildOptions{})
	edges := edgeSet(topo.Edges)
	if nodeByID(topo.Nodes, "replicaset/prod/web-rs") != nil || nodeByID(topo.Nodes, "replicaset/prod/web-old") != nil {
		t.Error("Deployment-owned ReplicaSets should be hidden by default")
	}
	if !edges["deployment/prod/web -owns-> pod/prod/web-1"] {
		t.Errorf("pod should hang off the Deployment: %v", edges)
	}
	if !edges["replicaset/prod/bare -owns-> pod/prod/bare-1"] {
		t.Errorf("a bare ReplicaSet must be drawn as its pod's owner: %v", edges)
	}
	if !edges["service/prod/bare -exposes-> replicaset/prod/bare"] {
		t.Errorf("a Service should expose a bare ReplicaSet by its template: %v", edges)
	}

	topo = build(t, provider, BuildOptions{IncludeReplicaSets: true})
	edges = edgeSet(topo.Edges)
	if !edges["deployment/prod/web -owns-> replicaset/prod/web-rs"] || !edges["replicaset/prod/web-rs -owns-> pod/prod/web-1"] {
		t.Errorf("IncludeReplicaSets should draw the full chain: %v", edges)
	}
	if nodeByID(topo.Nodes, "replicaset/prod/web-old") != nil {
		t.Error("a scaled-to-zero ReplicaSet is history, not topology")
	}

	topo = build(t, provider, BuildOptions{Focus: Ref{Kind: "ReplicaSet", Namespace: "prod", Name: "web-rs"}})
	if nodeByID(topo.Nodes, "replicaset/prod/web-rs") == nil {
		t.Error("a focus ReplicaSet must be drawn")
	}
}

// A Service with no workload owner in the graph links to standalone pods by
// their own labels; an empty selector links to nothing.
func TestBuild_ServiceExposesStandalonePods(t *testing.T) {
	provider := &mockProvider{
		pods: []*corev1.Pod{runningPod("prod", "debug", "", map[string]string{"run": "debug"})},
		services: []*corev1.Service{
			{ObjectMeta: metav1.ObjectMeta{Name: "debug", Namespace: "prod"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"run": "debug"}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "headless", Namespace: "prod"}},
		},
	}
	edges := edgeSet(build(t, provider, BuildOptions{}).Edges)
	if !edges["service/prod/debug -exposes-> pod/prod/debug"] {
		t.Errorf("missing standalone pod edge: %v", edges)
	}
	if len(edges) != 1 {
		t.Errorf("a selector-less Service must expose nothing: %v", edges)
	}
}

func TestBuild_IngressRoutesToServices(t *testing.T) {
	provider := &mockProvider{
		services: []*corev1.Service{
			{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "prod"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "fallback", Namespace: "prod"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "other"}},
		},
		ingresses: []*networkingv1.Ingress{{
			ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: "prod"},
			Spec: networkingv1.IngressSpec{
				DefaultBackend: &networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "fallback"}},
				TLS:            []networkingv1.IngressTLS{{Hosts: []string{"shop.example.com"}, SecretName: "shop-tls"}},
				Rules: []networkingv1.IngressRule{{
					Host: "shop.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{
						{Path: "/", Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "web"}}},
						{Path: "/v2", Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "web"}}},
					}}},
				}},
			},
		}},
	}
	topo := build(t, provider, BuildOptions{})
	edges := edgeSet(topo.Edges)
	if !edges["ingress/prod/edge -routes-to-> service/prod/web"] || !edges["ingress/prod/edge -routes-to-> service/prod/fallback"] {
		t.Errorf("ingress edges = %v", edges)
	}
	if edges["ingress/prod/edge -routes-to-> service/other/web"] || len(topo.Edges) != 2 {
		t.Errorf("unexpected or duplicate ingress edges: %v", topo.Edges)
	}
	ing := nodeByID(topo.Nodes, "ingress/prod/edge")
	if ing.Summary["tls"] != true || fmt.Sprint(ing.Summary["hosts"]) != "[shop.example.com]" {
		t.Errorf("ingress summary = %v", ing.Summary)
	}
	if strings.Contains(fmt.Sprint(ing), "shop-tls") {
		t.Error("the TLS Secret name must not reach the node")
	}
}

func TestBuild_HPAUsesScaleTarget(t *testing.T) {
	provider := &mockProvider{
		deployments: []*appsv1.Deployment{deployment("prod", "api", nil)},
		hpas: []*autoscalingv2.HorizontalPodAutoscaler{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod"},
				Spec: autoscalingv2.HorizontalPodAutoscalerSpec{MaxReplicas: 5, ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{
					APIVersion: "apps/v1", Kind: "Deployment", Name: "api",
				}},
			},
			{
				// A custom resource that shadows the kind is not the Deployment.
				ObjectMeta: metav1.ObjectMeta{Name: "shadow", Namespace: "prod"},
				Spec: autoscalingv2.HorizontalPodAutoscalerSpec{MaxReplicas: 5, ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{
					APIVersion: "custom.example/v1", Kind: "Deployment", Name: "api",
				}},
			},
		},
	}
	edges := edgeSet(build(t, provider, BuildOptions{}).Edges)
	if !edges["horizontalpodautoscaler/prod/api -uses-> deployment/prod/api"] || edges["horizontalpodautoscaler/prod/shadow -uses-> deployment/prod/api"] {
		t.Errorf("hpa edges = %v", edges)
	}
}

// Large pod sets collapse into a PodGroup with one owner edge per distinct
// owner; small ones stay individual.
func TestBuild_PodGrouping(t *testing.T) {
	labels := map[string]string{"app": "web"}
	provider := &mockProvider{
		deployments: []*appsv1.Deployment{deployment("prod", "web", labels)},
		replicaSets: []*appsv1.ReplicaSet{replicaSet("prod", "web-a", "web", labels), replicaSet("prod", "web-b", "web", labels)},
	}
	for i := 0; i < 7; i++ {
		rs := "web-a"
		if i%2 == 1 {
			rs = "web-b"
		}
		provider.pods = append(provider.pods, runningPod("prod", fmt.Sprintf("web-%d", i), rs, labels))
	}
	topo := build(t, provider, BuildOptions{IncludeReplicaSets: true})
	group := nodeByID(topo.Nodes, "podgroup-prod-app-web")
	if group == nil {
		t.Fatalf("expected a PodGroup, nodes=%v", topo.Nodes)
	}
	if group.Summary["podCount"] != 7 || group.Status != StatusHealthy {
		t.Errorf("group = %+v", group)
	}
	edges := edgeSet(topo.Edges)
	if !edges["replicaset/prod/web-a -owns-> podgroup-prod-app-web"] || !edges["replicaset/prod/web-b -owns-> podgroup-prod-app-web"] {
		t.Errorf("a mixed-owner group needs an edge per owner: %v", edges)
	}

	topo = build(t, provider, BuildOptions{MaxIndividualPods: 10})
	if nodeByID(topo.Nodes, "podgroup-prod-app-web") != nil || nodeByID(topo.Nodes, "pod/prod/web-0") == nil {
		t.Error("below MaxIndividualPods pods stay individual")
	}
}

func TestBuild_PodsLinkToTheirNodes(t *testing.T) {
	pod := runningPod("prod", "web-1", "", nil)
	pod.Spec.NodeName = "worker-1"
	unscheduled := runningPod("prod", "web-2", "", nil)
	provider := &mockProvider{
		pods: []*corev1.Pod{pod, unscheduled},
		nodes: []*corev1.Node{
			{ObjectMeta: metav1.ObjectMeta{Name: "worker-1"}, Spec: corev1.NodeSpec{Unschedulable: true},
				Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "idle"}},
		},
	}
	topo := build(t, provider, BuildOptions{Namespaces: []string{"prod"}})
	if !edgeSet(topo.Edges)["node//worker-1 -uses-> pod/prod/web-1"] {
		t.Errorf("missing node edge: %v", topo.Edges)
	}
	n := nodeByID(topo.Nodes, "node//worker-1")
	if n == nil || n.Status != StatusDegraded || n.StatusReason != "Cordoned" {
		t.Errorf("cordoned node = %+v", n)
	}
	if nodeByID(topo.Nodes, "node//idle") != nil {
		t.Error("a node hosting no drawn pod should be absent")
	}
	if calls := provider.calls[KindNode]; len(calls) != 1 || calls[0] != "" {
		t.Errorf("nodes must be listed cluster-wide, got %v", calls)
	}
	if calls := provider.calls[KindPod]; len(calls) != 1 || calls[0] != "prod" {
		t.Errorf("a single-namespace build lists only that namespace, got %v", calls)
	}
}

// A failed list marks its kind unavailable; the rest of the graph still
// builds, and owner edges into the missing kind are dropped, not dangling.
func TestBuild_UnavailableKindsAndDanglingEdges(t *testing.T) {
	labels := map[string]string{"app": "db"}
	pod := runningPod("prod", "db-0", "", labels)
	pod.OwnerReferences = []metav1.OwnerReference{controllerRef("apps/v1", "StatefulSet", "db")}
	provider := &mockProvider{
		pods: []*corev1.Pod{pod},
		statefulSets: []*appsv1.StatefulSet{{
			ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "prod"},
			Spec:       appsv1.StatefulSetSpec{Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}}},
		}},
		fail: map[NodeKind]bool{KindStatefulSet: true, KindConfigMap: true},
	}
	topo := build(t, provider, BuildOptions{})
	if !slices.Equal(topo.Unavailable, []string{"ConfigMap", "StatefulSet"}) {
		t.Errorf("Unavailable = %v", topo.Unavailable)
	}
	if nodeByID(topo.Nodes, "pod/prod/db-0") == nil {
		t.Error("pods should still be drawn")
	}
	for _, e := range topo.Edges {
		if nodeByID(topo.Nodes, e.Source) == nil || nodeByID(topo.Nodes, e.Target) == nil {
			t.Errorf("dangling edge %s", e.ID)
		}
	}
}

func TestBuild_PVCSummaryAndStatus(t *testing.T) {
	sc := "fast"
	p := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "prod"},
		Spec: corev1.PersistentVolumeClaimSpec{
			StorageClassName: &sc,
			AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources:        corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("10Gi")}},
		},
		Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending},
	}
	topo := build(t, &mockProvider{pvcs: []*corev1.PersistentVolumeClaim{p}}, BuildOptions{Focus: Ref{Kind: "PersistentVolumeClaim", Namespace: "prod", Name: "data"}})
	n := nodeByID(topo.Nodes, "persistentvolumeclaim/prod/data")
	if n == nil || n.Status != StatusNeutral || n.StatusReason != "Pending" {
		t.Fatalf("pending PVC = %+v, want neutral/Pending", n)
	}
	if n.Summary["storage"] != "10Gi" || n.Summary["storageClass"] != "fast" {
		t.Errorf("summary = %v", n.Summary)
	}
}
