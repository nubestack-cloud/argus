package agent

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// certificateWithRenewalObj builds a cert-manager Certificate directly as an
// unstructured object (there is no typed Go type for it registered in this
// package's fake scheme, same reason rules_test.go's own certificateObj
// helper does the same) carrying both status.renewalTime and status.notAfter
// — the two fields BUGS.md 105's live incident was actually about.
func certificateWithRenewalObj(namespace, name, renewalTime, notAfter string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cert-manager.io/v1",
		"kind":       "Certificate",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name},
		"status": map[string]any{
			"renewalTime": renewalTime,
			"notAfter":    notAfter,
		},
	}}
}

// TestDescribeResource_AnnotatesCertificateRenewalTimeWithSecondsUntil
// reproduces BUGS.md 105 / BACKLOG.md C9's exact fixture shape end to end
// through describe_resource: a real, freshly-issued Certificate whose
// renewalTime is ~41 minutes in the future must come back carrying a
// positive renewalTimeSecondsUntil, computed server-side — not left for the
// investigation to derive (incorrectly, as it did live) from the raw
// timestamp alone.
func TestDescribeResource_AnnotatesCertificateRenewalTimeWithSecondsUntil(t *testing.T) {
	// BUGS.md 105's real fixture: renewalTime ~41 minutes ahead of "now",
	// notAfter a further 5 minutes beyond that (this rule's renewBefore).
	// Computed relative to time.Now() rather than a fixed historical
	// timestamp, since describeResource stamps its own now() at call time.
	renewalTime := time.Now().Add(41 * time.Minute).UTC().Format(time.RFC3339)
	notAfter := time.Now().Add(46 * time.Minute).UTC().Format(time.RFC3339)
	cert := certificateWithRenewalObj("argus-r26-e9rules", "r26-short-lived-cert", renewalTime, notAfter)
	executor, _ := newTestExecutor(cert)

	data, _, err := executor.describeResource(context.Background(), mustMarshal(describeResourceArgs{
		GVK:       "cert-manager.io/v1/Certificate",
		Namespace: "argus-r26-e9rules",
		Name:      "r26-short-lived-cert",
	}))
	if err != nil {
		t.Fatalf("describeResource: %v", err)
	}

	var result describeResourceResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(result.Object, &obj); err != nil {
		t.Fatalf("decode object: %v", err)
	}
	status, _ := obj["status"].(map[string]any)
	if status["renewalTime"] != renewalTime {
		t.Fatalf("status.renewalTime altered or missing: %+v", status)
	}
	secondsUntil, ok := status["renewalTimeSecondsUntil"].(float64) // JSON numbers decode as float64
	if !ok {
		t.Fatalf("status.renewalTimeSecondsUntil missing from describe_resource output: %+v", status)
	}
	if secondsUntil <= 0 {
		t.Errorf("status.renewalTimeSecondsUntil = %v, want a positive value — the Certificate's own renewalTime is in the future relative to now, exactly the fact BUGS.md 105's investigation got backwards", secondsUntil)
	}
	if _, ok := status["notAfterSecondsUntil"]; !ok {
		t.Errorf("status.notAfterSecondsUntil missing — notAfter is also a future-facing field this mechanism should cover: %+v", status)
	}
}

// TestGetEvents_AnnotatesLastTimestampWithSecondsSince checks get_events'
// typed eventResult carries the same precomputed relative value as
// describe_resource's generic path, for the one timestamp field Events
// actually carry.
func TestGetEvents_AnnotatesLastTimestampWithSecondsSince(t *testing.T) {
	past := time.Now().Add(-10 * time.Minute)
	executor, typed := newTestExecutor()
	installEventsReactor(typed, []corev1.Event{
		{
			ObjectMeta:     metav1.ObjectMeta{Name: "ev1", Namespace: "default"},
			InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "web-1"},
			Reason:         "BackOff",
			LastTimestamp:  metav1.NewTime(past),
		},
	})

	data, _, err := executor.getEvents(context.Background(), mustMarshal(getEventsArgs{Namespace: "default"}))
	if err != nil {
		t.Fatalf("getEvents: %v", err)
	}
	var results []eventResult
	if err := json.Unmarshal(data, &results); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d events, want 1: %+v", len(results), results)
	}
	if results[0].LastTimestampSecondsSince <= 0 {
		t.Errorf("LastTimestampSecondsSince = %d, want a positive value for an event roughly 10 minutes in the past", results[0].LastTimestampSecondsSince)
	}
}

// TestListResources_AnnotatesCreationTimestampWithSecondsSince is
// list_resources' equivalent of the describe_resource/get_events tests above:
// the compact per-item projection also carries the precomputed value.
func TestListResources_AnnotatesCreationTimestampWithSecondsSince(t *testing.T) {
	created := time.Now().Add(-48 * time.Hour)
	web := testPod("apps", "web-1", "Running", 1, 1)
	web.CreationTimestamp = metav1.NewTime(created)
	executor, _ := newTestExecutor(web)

	data, _, err := executor.listResources(context.Background(), mustMarshal(listResourcesArgs{
		Kind: "Pod", Namespace: "apps",
	}))
	if err != nil {
		t.Fatalf("listResources: %v", err)
	}
	var result listResourcesResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("got %d items, want 1: %+v", len(result.Items), result.Items)
	}
	if result.Items[0].CreationTimestampSecondsSince <= 0 {
		t.Errorf("CreationTimestampSecondsSince = %d, want a positive value for an object created 48 hours ago", result.Items[0].CreationTimestampSecondsSince)
	}
}
