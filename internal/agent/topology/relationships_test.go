package topology

import (
	"fmt"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// syntheticProvider is n Deployments, each with a ReplicaSet, two pods, a
// Service, a ConfigMap and a PDB, spread over a few namespaces.
func syntheticProvider(n int) *mockProvider {
	p := &mockProvider{}
	for i := 0; i < n; i++ {
		ns := fmt.Sprintf("ns-%d", i%5)
		app := fmt.Sprintf("app-%d", i)
		labels := map[string]string{"app": app}
		d := deployment(ns, app, labels)
		d.Spec.Template.Spec.Volumes = []corev1.Volume{{Name: "cfg", VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: app + "-config"}},
		}}}
		p.deployments = append(p.deployments, d)
		p.replicaSets = append(p.replicaSets, replicaSet(ns, app+"-rs", app, labels))
		for j := 0; j < 2; j++ {
			p.pods = append(p.pods, runningPod(ns, fmt.Sprintf("%s-pod-%d", app, j), app+"-rs", labels))
		}
		p.services = append(p.services, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: app + "-svc", Namespace: ns}, Spec: corev1.ServiceSpec{Selector: labels}})
		p.configMaps = append(p.configMaps, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: app + "-config", Namespace: ns}})
	}
	return p
}

// For every node, the index hands back the same edges, in the same order, as
// filtering the whole edge list by source and by target.
func TestIndexByResource_EquivalentToLinearScan(t *testing.T) {
	topo := build(t, syntheticProvider(100), BuildOptions{IncludeReplicaSets: true})
	if len(topo.Edges) == 0 {
		t.Fatal("synthetic topology has no edges")
	}
	where := func(keep func(Edge) bool) []Edge {
		var out []Edge
		for _, e := range topo.Edges {
			if keep(e) {
				out = append(out, e)
			}
		}
		return out
	}
	idx := IndexByResource(topo)
	for _, n := range topo.Nodes {
		in, out := idx.EdgesFor(n.ID)
		wantIn := where(func(e Edge) bool { return e.Target == n.ID })
		wantOut := where(func(e Edge) bool { return e.Source == n.ID })
		if !slices.Equal(in, wantIn) || !slices.Equal(out, wantOut) {
			t.Errorf("%s: index in=%d out=%d, scan in=%d out=%d", n.ID, len(in), len(out), len(wantIn), len(wantOut))
		}
	}
}

func TestIndexByResource_NilTopologySafe(t *testing.T) {
	idx := IndexByResource(nil)
	if idx == nil {
		t.Fatal("IndexByResource(nil) returned nil; want non-nil empty index")
	}
	if inc, out := idx.EdgesFor("anything"); inc != nil || out != nil {
		t.Errorf("EdgesFor on empty index should return nil/nil, got inc=%v out=%v", inc, out)
	}
}

func TestRelationshipsIndex_NilReceiver(t *testing.T) {
	var idx *RelationshipsIndex
	if inc, out := idx.EdgesFor("any"); inc != nil || out != nil {
		t.Errorf("nil receiver EdgesFor should return nil/nil, got inc=%v out=%v", inc, out)
	}
}

func TestNodeIDsAndGroups(t *testing.T) {
	for _, tc := range []struct {
		kind      NodeKind
		ns, name  string
		wantID    string
		wantGroup string
	}{
		{KindDeployment, "prod", "web", "deployment/prod/web", "apps"},
		{KindPVC, "prod", "data", "persistentvolumeclaim/prod/data", ""},
		{KindNode, "", "worker-1", "node//worker-1", ""},
		{KindHTTPRoute, "team", "web", "httproute/team/web", GatewayAPIGroup},
	} {
		if id := buildNodeID(tc.kind, tc.ns, tc.name); id != tc.wantID {
			t.Errorf("buildNodeID(%s) = %q, want %q", tc.kind, id, tc.wantID)
		}
		if builtinGroups[tc.kind] != tc.wantGroup {
			t.Errorf("group of %s = %q, want %q", tc.kind, builtinGroups[tc.kind], tc.wantGroup)
		}
	}
}

func TestNormalizeKindAcceptsCommonSpellings(t *testing.T) {
	for in, want := range map[string]NodeKind{
		"Pod": KindPod, "pods": KindPod, "deploy": KindDeployment, "StatefulSets": KindStatefulSet,
		"pvc": KindPVC, "PersistentVolume": KindPV, "hpa": KindHPA, "netpol": KindNetworkPolicy,
		"HTTPRoute": KindHTTPRoute, " Service ": KindService, "sa": KindServiceAccount,
	} {
		if got, ok := normalizeKind(in); !ok || got != want {
			t.Errorf("normalizeKind(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"Secret", "secrets", "Widget", ""} {
		if _, ok := normalizeKind(in); ok {
			t.Errorf("normalizeKind(%q) should not resolve", in)
		}
	}
}

func TestExtractWorkloadReferences(t *testing.T) {
	spec := corev1.PodSpec{
		ServiceAccountName: "runner",
		InitContainers: []corev1.Container{{Name: "init", EnvFrom: []corev1.EnvFromSource{
			{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "init-env"}}},
			{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "init-secret"}}},
		}}},
		Containers: []corev1.Container{{Name: "app", Env: []corev1.EnvVar{
			{Name: "A", ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "app-env"}, Key: "a"}}},
			{Name: "B", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "app-secret"}, Key: "b"}}},
		}}},
		Volumes: []corev1.Volume{
			{Name: "v1", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "mounted"}}}},
			{Name: "v2", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{
				{ConfigMap: &corev1.ConfigMapProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "projected"}}},
			}}}},
			{Name: "v3", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data"}}},
			{Name: "v4", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "tls"}}},
		},
	}
	refs := extractWorkloadReferences(spec)
	for _, cm := range []string{"init-env", "app-env", "mounted", "projected"} {
		if !refs.configMaps[cm] {
			t.Errorf("missing ConfigMap ref %q", cm)
		}
	}
	if len(refs.configMaps) != 4 || !refs.pvcs["data"] || len(refs.pvcs) != 1 || refs.serviceAccount != "runner" {
		t.Errorf("refs = %+v", refs)
	}
}

func TestMatchesSelector(t *testing.T) {
	labels := map[string]string{"app": "web", "tier": "front"}
	if !matchesSelector(labels, map[string]string{"app": "web"}) {
		t.Error("subset selector should match")
	}
	if matchesSelector(labels, map[string]string{"app": "api"}) {
		t.Error("mismatched value should not match")
	}
	if matchesSelector(labels, nil) || matchesSelector(labels, map[string]string{}) {
		t.Error("an empty selector matches nothing")
	}
}

// Consumer lists come back sorted, so edge order does not depend on map
// iteration.
func TestBuildConsumerIndexIsDeterministic(t *testing.T) {
	refs := map[string]map[string]bool{
		"deployment/a/z": {"cfg": true},
		"deployment/a/m": {"cfg": true},
		"deployment/a/b": {"cfg": true},
	}
	ns := map[string]string{"deployment/a/z": "a", "deployment/a/m": "a", "deployment/a/b": "a"}
	got := buildConsumerIndex(refs, ns)[refKey{"a", "cfg"}]
	if !slices.Equal(got, []string{"deployment/a/b", "deployment/a/m", "deployment/a/z"}) {
		t.Errorf("consumers = %v", got)
	}
}
