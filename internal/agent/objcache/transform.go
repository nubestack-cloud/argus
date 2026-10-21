package objcache

import (
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// hashSensitive replaces sensitive values in place. Typed workloads have
// their pod spec's env values hashed, ConfigMaps their data values; for
// unstructured (CRD) objects the same field classes are applied by name at
// any depth — an "env" list's "value" entries and "data"/"stringData" maps —
// so a CRD that embeds a pod template or inline data is covered without a
// per-kind rule.
func hashSensitive(obj any) {
	switch o := obj.(type) {
	case *corev1.Pod:
		hashPodSpec(&o.Spec)
	case *appsv1.Deployment:
		hashPodSpec(&o.Spec.Template.Spec)
	case *appsv1.ReplicaSet:
		hashPodSpec(&o.Spec.Template.Spec)
	case *appsv1.StatefulSet:
		hashPodSpec(&o.Spec.Template.Spec)
	case *appsv1.DaemonSet:
		hashPodSpec(&o.Spec.Template.Spec)
	case *batchv1.Job:
		hashPodSpec(&o.Spec.Template.Spec)
	case *batchv1.CronJob:
		hashPodSpec(&o.Spec.JobTemplate.Spec.Template.Spec)
	case *corev1.ConfigMap:
		for k, v := range o.Data {
			if !isHash(v) {
				o.Data[k] = HashValue([]byte(v))
			}
		}
		for k, v := range o.BinaryData {
			if !isHash(string(v)) {
				o.BinaryData[k] = []byte(HashValue(v))
			}
		}
	case *unstructured.Unstructured:
		o.Object = hashUnstructured(o.Object, 0).(map[string]any)
	}
}

func hashPodSpec(spec *corev1.PodSpec) {
	hashEnv := func(cs []corev1.Container) {
		for i := range cs {
			for j := range cs[i].Env {
				if v := cs[i].Env[j].Value; v != "" && !isHash(v) {
					cs[i].Env[j].Value = HashValue([]byte(v))
				}
			}
		}
	}
	hashEnv(spec.InitContainers)
	hashEnv(spec.Containers)
	for i := range spec.EphemeralContainers {
		for j := range spec.EphemeralContainers[i].Env {
			if v := spec.EphemeralContainers[i].Env[j].Value; v != "" && !isHash(v) {
				spec.EphemeralContainers[i].Env[j].Value = HashValue([]byte(v))
			}
		}
	}
}

const maxDepth = 64

func hashUnstructured(node any, depth int) any {
	if depth > maxDepth {
		return node
	}
	switch n := node.(type) {
	case map[string]any:
		for k, v := range n {
			switch k {
			case "env":
				n[k] = hashEnvList(v, depth+1)
			case "data", "stringData", "binaryData":
				if m, ok := v.(map[string]any); ok {
					for dk, dv := range m {
						if s, ok := dv.(string); ok && !isHash(s) {
							m[dk] = HashValue([]byte(s))
						} else if !ok {
							m[dk] = hashUnstructured(dv, depth+1)
						}
					}
					continue
				}
				n[k] = hashUnstructured(v, depth+1)
			default:
				n[k] = hashUnstructured(v, depth+1)
			}
		}
		return n
	case []any:
		for i := range n {
			n[i] = hashUnstructured(n[i], depth+1)
		}
		return n
	default:
		return node
	}
}

func hashEnvList(v any, depth int) any {
	list, ok := v.([]any)
	if !ok {
		return hashUnstructured(v, depth)
	}
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if s, ok := m["value"].(string); ok && s != "" && !isHash(s) {
			m["value"] = HashValue([]byte(s))
		}
		if vf, ok := m["valueFrom"]; ok {
			m["valueFrom"] = hashUnstructured(vf, depth+1)
		}
	}
	return list
}

func isHash(s string) bool {
	return len(s) == len("sha256:")+64 && strings.HasPrefix(s, "sha256:")
}

func toUnstructured(obj any) (*unstructured.Unstructured, error) {
	ro, ok := obj.(runtime.Object)
	if !ok {
		return nil, errNotObject
	}
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(ro)
	if err != nil {
		return nil, err
	}
	return &unstructured.Unstructured{Object: m}, nil
}

type objErr string

func (e objErr) Error() string { return string(e) }

const errNotObject = objErr("not a runtime.Object")

func isForbidden(err error) bool {
	return apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) ||
		strings.Contains(err.Error(), "forbidden")
}
