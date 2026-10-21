package agent

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestBatchAIJudges(t *testing.T) {
	obj := func(status map[string]any) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{"metadata": map[string]any{"namespace": "ml", "name": "x"}, "status": status}}
	}
	cond := func(t, s, r, m string) map[string]any {
		return map[string]any{"type": t, "status": s, "reason": r, "message": m}
	}
	judge := func(gvk string, o *unstructured.Unstructured) (string, string, bool) {
		for _, s := range batchAISources {
			if s.gvk == gvk {
				return s.judge(o)
			}
		}
		t.Fatalf("no source for %s", gvk)
		return "", "", false
	}
	// KServe names the component holding the service back.
	reason, msg, ok := judge("serving.kserve.io/v1beta1/InferenceService", obj(map[string]any{"conditions": []any{
		cond("Ready", "False", "", ""), cond("PredictorReady", "False", "RevisionMissing", "model download failed")}}))
	if !ok || reason != "InferenceServiceNotReady" || !strings.Contains(msg, "PredictorReady is False (RevisionMissing): model download failed") {
		t.Fatalf("kserve: %v %q %q", ok, reason, msg)
	}
	// Kueue: eviction for not becoming ready is a fault; preemption is not.
	if _, _, ok := judge("kueue.x-k8s.io/v1beta1/Workload", obj(map[string]any{"conditions": []any{cond("Evicted", "True", "Preempted", "")}})); ok {
		t.Fatal("a preempted Kueue workload is capacity sharing, not a fault")
	}
	if r, _, ok := judge("kueue.x-k8s.io/v1beta1/Workload", obj(map[string]any{"conditions": []any{cond("Evicted", "True", "PodsReadyTimeout", "")}})); !ok || r != "KueueWorkloadEvicted" {
		t.Fatalf("kueue readiness timeout: %v %q", ok, r)
	}
	// A healthy JobSet is quiet.
	if _, _, ok := judge("jobset.x-k8s.io/v1alpha2/JobSet", obj(map[string]any{"conditions": []any{cond("Completed", "True", "", "")}})); ok {
		t.Fatal("a completed JobSet must not fire")
	}
}
