package rightsizing

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestJoin(t *testing.T) {
	pod := func(name string, req corev1.ResourceList, podLevel bool) *corev1.Pod {
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}}
		if podLevel {
			p.Spec.Resources = &corev1.ResourceRequirements{Requests: req}
		} else {
			p.Spec.Containers[0].Resources.Requests = req
		}
		return p
	}
	q := resource.MustParse
	pods := []*corev1.Pod{
		pod("big-1", corev1.ResourceList{"cpu": q("2"), "memory": q("4Gi")}, false),
		pod("big-2", corev1.ResourceList{"cpu": q("2"), "memory": q("4Gi")}, false),
		pod("hot-1", corev1.ResourceList{"cpu": q("100m"), "memory": q("256Mi")}, false),
		pod("pl-1", corev1.ResourceList{"cpu": q("1")}, true),
	}
	owner := func(p *corev1.Pod) (string, string) { return "Deployment", p.Name[:len(p.Name)-2] }
	cpu := usage{{"big-1", "app"}: 0.05, {"big-2", "app"}: 0.2, {"hot-1", "app"}: 0.3, {"pl-1", "app"}: 0.1}
	mem := usage{{"big-1", "app"}: 200 << 20, {"hot-1", "app"}: 100 << 20}
	peak := usage{{"big-1", "app"}: 900 << 20, {"hot-1", "app"}: 120 << 20}

	rows := Join(pods, owner, cpu, mem, peak)
	by := map[string]Row{}
	for _, r := range rows {
		by[r.Workload] = r
	}
	big := by["big"]
	// The busiest replica sets the figure: 200m p95 -> 240m recommended.
	if big.Pods != 2 || *big.RecCPUMilli != 240 || big.CPUVerdict != VerdictOver {
		t.Fatalf("big cpu = %+v", big)
	}
	// Peak memory (900Mi) beats p95*1.2 (240Mi): never recommend below the peak.
	if *big.RecMemBytes != 900<<20 || big.MemVerdict != VerdictOver {
		t.Fatalf("big mem rec = %d verdict %s", *big.RecMemBytes, big.MemVerdict)
	}
	if hot := by["hot"]; hot.CPUVerdict != VerdictUnder || rows[0].Workload != "hot" {
		t.Fatalf("an under-provisioned container must sort first: %+v", rows)
	}
	if pl := by["pl"]; !pl.PodLevel || pl.RecCPUMilli != nil || *pl.CPURequestMilli != 1000 {
		t.Fatalf("pod-level row = %+v, want the pod's request and no per-container recommendation", pl)
	}
}
