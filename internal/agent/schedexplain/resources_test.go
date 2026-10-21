package schedexplain

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// resourceList reads "cpu=250m,memory=64Mi".
func resourceList(spec string) corev1.ResourceList {
	out := corev1.ResourceList{}
	for _, kv := range strings.Split(spec, ",") {
		if name, q, ok := strings.Cut(kv, "="); ok {
			out[corev1.ResourceName(name)] = resource.MustParse(q)
		}
	}
	return out
}

func asking(spec string) corev1.Container {
	return corev1.Container{Resources: corev1.ResourceRequirements{Requests: resourceList(spec)}}
}

func sidecar(spec string) corev1.Container {
	always := corev1.ContainerRestartPolicyAlways
	c := asking(spec)
	c.RestartPolicy = &always
	return c
}

// sameQuantities compares as quantities, so 1000m equals 1.
func sameQuantities(got, want corev1.ResourceList) bool {
	if len(got) != len(want) {
		return false
	}
	for name, q := range want {
		if g, ok := got[name]; !ok || g.Cmp(q) != 0 {
			return false
		}
	}
	return true
}

func TestPodRequests(t *testing.T) {
	cases := []struct {
		why  string
		spec corev1.PodSpec
		want string
	}{
		{"app containers add up, plus one pod slot",
			corev1.PodSpec{Containers: []corev1.Container{asking("cpu=150m,memory=100Mi"), asking("cpu=50m")}},
			"cpu=200m,memory=100Mi,pods=1"},
		// Each init container runs alone, so only the largest one counts, and
		// only when it exceeds the app total.
		{"the largest init container, when larger",
			corev1.PodSpec{Containers: []corev1.Container{asking("cpu=300m")}, InitContainers: []corev1.Container{asking("cpu=700m"), asking("cpu=500m,memory=1Gi")}},
			"cpu=700m,memory=1Gi,pods=1"},
		// A sidecar runs beside the app containers and beside every init
		// container that starts after it.
		{"sidecars",
			corev1.PodSpec{Containers: []corev1.Container{asking("cpu=300m")}, InitContainers: []corev1.Container{asking("cpu=900m"), sidecar("cpu=100m"), asking("cpu=800m")}},
			"cpu=900m,pods=1"},
		{"sidecar plus a later init container",
			corev1.PodSpec{Containers: []corev1.Container{asking("cpu=100m")}, InitContainers: []corev1.Container{sidecar("cpu=200m"), asking("cpu=600m")}},
			"cpu=800m,pods=1"},
		// Pod-level resources replace the containers' cpu and memory only;
		// overhead goes on top; vendor resources pass through.
		{"pod-level, overhead and other resources",
			corev1.PodSpec{
				Containers: []corev1.Container{asking("cpu=200m,memory=256Mi,ephemeral-storage=2Gi,nvidia.com/gpu=1,hugepages-1Gi=2Gi")},
				Resources:  &corev1.ResourceRequirements{Requests: resourceList("cpu=2,memory=4Gi")},
				Overhead:   resourceList("cpu=100m,memory=64Mi"),
			},
			"cpu=2100m,memory=4160Mi,ephemeral-storage=2Gi,nvidia.com/gpu=1,hugepages-1Gi=2Gi,pods=1"},
		{"nothing asked", corev1.PodSpec{Containers: []corev1.Container{{}}}, "pods=1"},
	}
	for _, c := range cases {
		if got := PodRequests(&corev1.Pod{Spec: c.spec}); !sameQuantities(got, resourceList(c.want)) {
			t.Errorf("%s: %v, want %s", c.why, got, c.want)
		}
	}
	if PodRequests(nil) != nil {
		t.Error("nil pod has requests")
	}
}
