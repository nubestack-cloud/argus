package pathprobe

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestProbe(t *testing.T) {
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "api"},
		Spec: corev1.ServiceSpec{ClusterIP: "10.0.0.9", Ports: []corev1.ServicePort{{Name: "grpc", Port: 9000}}}}
	port, ready, notReady := int32(9000), true, false
	slices := []*discoveryv1.EndpointSlice{{
		Ports: []discoveryv1.EndpointPort{{Port: &port}},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.1.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
			{Addresses: []string{"10.1.0.2"}, Conditions: discoveryv1.EndpointConditions{Ready: &notReady}},
		},
	}}
	open := map[string]bool{"10.0.0.9:9000": true}
	pr := Prober{
		Resolve: func(context.Context, string) ([]string, error) { return []string{"10.0.0.9"}, nil },
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			if open[addr] {
				c, s := net.Pipe()
				_ = s.Close()
				return c, nil
			}
			return nil, errors.New("dial tcp " + addr + ": connect: connection refused")
		},
		HTTP: http.DefaultClient,
	}
	r := pr.Probe(context.Background(), svc, slices)
	// The Service IP answers but its one ready endpoint refuses: partial, and
	// the not-ready endpoint is never contacted.
	if r.Verdict != "partial" || len(r.Steps) != 3 {
		t.Fatalf("result = %+v", r)
	}
	if last := r.Steps[2]; last.Target != "10.1.0.1:9000" || last.OK {
		t.Fatalf("endpoint step = %+v, want the ready endpoint, refused", last)
	}
	// The live shape on rke2: the name resolves, nothing answers. Unreachable,
	// because a resolved name carries no traffic.
	delete(open, "10.0.0.9:9000")
	if r := pr.Probe(context.Background(), svc, slices); r.Verdict != "unreachable" {
		t.Fatalf("resolved but nothing answering should be unreachable, got %+v", r)
	}
	open["10.0.0.9:9000"] = true
	open["10.1.0.1:9000"] = true
	if r := pr.Probe(context.Background(), svc, slices); r.Verdict != "reachable" {
		t.Fatalf("all answering should be reachable, got %+v", r)
	}
}
