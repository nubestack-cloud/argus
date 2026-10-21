package agent

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDrainImpact(t *testing.T) {
	ctrl := func(kind, name string) []metav1.OwnerReference {
		yes := true
		return []metav1.OwnerReference{{Kind: kind, Name: name, Controller: &yes}}
	}
	ready := corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}
	pod := func(name, node string, owners []metav1.OwnerReference, mut func(*corev1.Pod)) *corev1.Pod {
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: name, OwnerReferences: owners, Labels: map[string]string{"app": name[:3]}},
			Spec: corev1.PodSpec{NodeName: node}, Status: ready}
		if mut != nil {
			mut(p)
		}
		return p
	}
	pods := []*corev1.Pod{
		pod("web-1", "n1", ctrl("ReplicaSet", "web-abc"), nil),
		pod("web-2", "n2", ctrl("ReplicaSet", "web-abc"), nil), // a ready replica elsewhere
		pod("dbs-0", "n1", ctrl("StatefulSet", "dbs"), func(p *corev1.Pod) {
			p.Spec.Volumes = []corev1.Volume{{Name: "scratch", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
		}),
		pod("bare", "n1", nil, nil),
		pod("log-x", "n1", ctrl("DaemonSet", "logs"), nil),
		pod("old-1", "n1", ctrl("ReplicaSet", "web-abc"), func(p *corev1.Pod) { p.Status.Phase = corev1.PodSucceeded }),
	}
	rsOwner := map[string]metav1.OwnerReference{"app/web-abc": {Kind: "Deployment", Name: "web"}}
	pdbs := []*policyv1.PodDisruptionBudget{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "dbs"},
		Spec:       policyv1.PodDisruptionBudgetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "dbs"}}},
		Status:     policyv1.PodDisruptionBudgetStatus{DisruptionsAllowed: 0},
	}}

	r := drainImpact("n1", pods, rsOwner, pdbs)
	if r.Evicted != 3 {
		t.Fatalf("evicted = %d, want 3 (web-1, dbs-0, bare; not the DaemonSet pod or the finished one)", r.Evicted)
	}
	if len(r.Unavailable) != 1 || r.Unavailable[0] != "StatefulSet app/dbs" {
		t.Fatalf("unavailable = %v, want only the StatefulSet with no replica elsewhere", r.Unavailable)
	}
	if len(r.Workloads) != 2 || r.Workloads[1].Kind != "Deployment" || r.Workloads[1].ReadyElsewhere != 1 {
		t.Fatalf("workloads = %+v, want the Deployment resolved through its ReplicaSet with 1 ready elsewhere", r.Workloads)
	}
	if len(r.PDBs) != 1 || !r.PDBs[0].Blocks {
		t.Fatalf("pdbs = %+v, want the zero-budget PDB to hold the drain", r.PDBs)
	}
	if len(r.LosesData) != 1 || len(r.NotRecreated) != 1 || len(r.Stays) != 1 {
		t.Fatalf("emptyDir=%v noController=%v stays=%v", r.LosesData, r.NotRecreated, r.Stays)
	}
}
