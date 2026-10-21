package health

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

// A vector is one fixture object and the level a one-status-per-object
// surface should show for it: PodDisplayLevel for a pod, Workload for the
// rest. The fixtures are in testdata/vectors.json.
type goldenVector struct {
	Name   string          `json:"name"`
	Kind   string          `json:"kind"`
	Level  string          `json:"level"`
	Object json.RawMessage `json:"object"`
}

// decoders turn a vector's JSON into the typed object its kind needs.
var decoders = map[string]func([]byte) (any, error){
	"Pod":                   decodeAs[corev1.Pod],
	"Deployment":            decodeAs[appsv1.Deployment],
	"StatefulSet":           decodeAs[appsv1.StatefulSet],
	"DaemonSet":             decodeAs[appsv1.DaemonSet],
	"Job":                   decodeAs[batchv1.Job],
	"CronJob":               decodeAs[batchv1.CronJob],
	"PersistentVolumeClaim": decodeAs[corev1.PersistentVolumeClaim],
}

func decodeAs[T any](raw []byte) (any, error) {
	v := new(T)
	return v, json.Unmarshal(raw, v)
}

func TestGoldenVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct{ Vectors []goldenVector }
	if err := json.Unmarshal(raw, &file); err != nil || len(file.Vectors) == 0 {
		t.Fatalf("vectors: %d, %v", len(file.Vectors), err)
	}
	// No vector depends on time; the clock is pinned anyway.
	now := time.Date(2026, 9, 14, 9, 30, 0, 0, time.UTC)
	for _, v := range file.Vectors {
		decode, ok := decoders[v.Kind]
		if !ok {
			t.Errorf("%s: no decoder for kind %s", v.Name, v.Kind)
			continue
		}
		obj, err := decode(v.Object)
		if err != nil {
			t.Errorf("%s: %v", v.Name, err)
			continue
		}
		var got Level
		if p, isPod := obj.(*corev1.Pod); isPod {
			got = PodDisplayLevel(p, now)
		} else {
			got = Workload(obj, now).Level
		}
		if string(got) != v.Level {
			t.Errorf("%s [%s]: %s, want %s", v.Name, v.Kind, got, v.Level)
		}
	}
}
