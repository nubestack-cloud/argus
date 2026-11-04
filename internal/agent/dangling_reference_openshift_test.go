package agent

import (
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// OpenShift's operators write references to a Node that carry a namespace
// (the referring object's own). A Node is cluster-scoped, so that namespace
// must be ignored: the Node below exists, and reporting it as missing is a
// false finding about a healthy cluster.
func TestDanglingReference_ClusterScopedTargetIgnoresReferenceNamespace(t *testing.T) {
	ref := newGenericObj("controlplane.operator.openshift.io/v1alpha1", "PodNetworkConnectivityCheck", "openshift-network-diagnostics", "check", "u")
	setSpecRef(ref, []string{"spec", "target"}, "Node", "worker-0", "openshift-network-diagnostics")

	exists := map[string][]*unstructured.Unstructured{
		"PodNetworkConnectivityCheck": {ref},
		"Node":                        {newGenericObj("v1", "Node", "", "worker-0", "n")},
	}
	if out := checkGenericDanglingReference(readSnapshotOf(exists), time.Now()); len(out) != 0 {
		t.Fatalf("a Node that exists was reported missing: %+v", out)
	}

	missing := map[string][]*unstructured.Unstructured{
		"PodNetworkConnectivityCheck": {ref},
		"Node":                        {newGenericObj("v1", "Node", "", "worker-1", "n")},
	}
	if out := checkGenericDanglingReference(readSnapshotOf(missing), time.Now()); len(out) != 1 {
		t.Fatalf("a Node that is really missing must still be reported, got %d: %+v", len(out), out)
	}
}

// An Event about a deleted Pod is history, not a broken dependency, and both
// v1 and events.k8s.io/v1 serve it under the same bare Kind.
func TestDanglingReference_EventsAreNeverReferrers(t *testing.T) {
	coreEvent := newGenericObj("v1", "Event", "ns", "example.18e4", "e1")
	setSpecRef(coreEvent, []string{"involvedObject"}, "Pod", "example", "ns")
	newEvent := newGenericObj("events.k8s.io/v1", "Event", "ns", "example.18e5", "e2")
	setSpecRef(newEvent, []string{"regarding"}, "Pod", "example", "ns")

	objs := map[string][]*unstructured.Unstructured{
		"Event": {coreEvent, newEvent},
		"Pod":   {newGenericObj("v1", "Pod", "ns", "some-other-pod", "p")},
	}
	if out := checkGenericDanglingReference(readSnapshotOf(objs), time.Now()); len(out) != 0 {
		t.Fatalf("an Event naming a deleted Pod was reported as a dangling reference: %+v", out)
	}
}

// An OpenShift Template's objects are blueprints, and "${NAME}" is a
// parameter, not a name anything can have.
func TestDanglingReference_TemplatesAndParametersAreNotReferences(t *testing.T) {
	tmpl := newGenericObj("template.openshift.io/v1", "Template", "openshift", "rails-postgresql-example", "t")
	_ = unstructured.SetNestedSlice(tmpl.Object, []any{
		map[string]any{"kind": "Route", "spec": map[string]any{"to": map[string]any{"kind": "Service", "name": "fixed-name"}}},
	}, "objects")

	parameterised := newGenericObj("autoscaling/v2", "HorizontalPodAutoscaler", "ns", "hpa", "h")
	setSpecRef(parameterised, []string{"spec", "scaleTargetRef"}, "Deployment", "${NAME}", "")

	objs := map[string][]*unstructured.Unstructured{
		"Template":                {tmpl},
		"HorizontalPodAutoscaler": {parameterised},
		"Service":                 {},
		"Deployment":              {},
	}
	if out := checkGenericDanglingReference(readSnapshotOf(objs), time.Now()); len(out) != 0 {
		t.Fatalf("a template blueprint or an unsubstituted parameter was reported: %+v", out)
	}
}

func TestResolveReferenceNamespace(t *testing.T) {
	cases := []struct {
		ref, referrer string
		namespaced    bool
		want          string
	}{
		{"openshift-network-diagnostics", "openshift-network-diagnostics", false, ""},
		{"", "ns", true, "ns"},
		{"other", "ns", true, "other"},
		{"", "ns", false, ""},
	}
	for _, c := range cases {
		if got := resolveReferenceNamespace(c.ref, c.namespaced, c.referrer); got != c.want {
			t.Errorf("resolveReferenceNamespace(%q, %v, %q) = %q, want %q", c.ref, c.namespaced, c.referrer, got, c.want)
		}
	}
}
