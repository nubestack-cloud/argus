package agent

import (
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDetectMetricsService(t *testing.T) {
	svc := func(ns, name string, port int32) *corev1.Service {
		return &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Spec: corev1.ServiceSpec{ClusterIP: "10.0.0.1", Ports: []corev1.ServicePort{{Port: port}}}}
	}
	cases := []struct {
		name string
		svcs []*corev1.Service
		want string
	}{
		{"thanos query", []*corev1.Service{svc("mon", "thanos-query", 10902)}, "mon/thanos-query:10902 thanos"},
		{"vm single", []*corev1.Service{svc("vm", "vmsingle-main", 8428)}, "vm/vmsingle-main:8428 victoriametrics"},
		// vmselect serves the API under /select/<tenant>/prometheus, which the
		// proxy path cannot reach, and a sidecar is not a query endpoint.
		{"vmselect and sidecar are not candidates", []*corev1.Service{svc("vm", "vmselect", 8481), svc("mon", "thanos-sidecar", 10902)}, ""},
		{"prometheus beats thanos", []*corev1.Service{svc("mon", "thanos-query", 9090), svc("mon", "kps-prometheus", 9090)}, "mon/kps-prometheus:9090 prometheus"},
	}
	for _, c := range cases {
		got := ""
		if d := detectMetricsService(c.svcs); d != nil {
			got = fmt.Sprintf("%s/%s:%d %s", d.Namespace, d.Name, d.Port, d.Flavour)
		}
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
