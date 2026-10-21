package schedexplain

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// PodRequests returns the requests the scheduler charges a pod against a
// node, following its accounting rules:
//   - app containers are summed;
//   - restartable init containers (sidecars) run alongside them and are added;
//   - each ordinary init container runs alone with the sidecars started before
//     it, and the pod needs the maximum of those and the app total;
//   - pod-level requests (spec.resources) replace the container figure for
//     cpu and memory, the only resources pod-level resources cover;
//   - spec.overhead is added;
//   - one "pods" slot is charged.
//
// In-place resize is not modelled: the scheduler charges max(spec, allocated)
// while a resize is pending, and this reads spec only.
func PodRequests(pod *corev1.Pod) corev1.ResourceList {
	if pod == nil {
		return nil
	}
	reqs := corev1.ResourceList{}
	for _, c := range pod.Spec.Containers {
		addResources(reqs, c.Resources.Requests)
	}
	sidecars := corev1.ResourceList{}
	initMax := corev1.ResourceList{}
	for _, c := range pod.Spec.InitContainers {
		var step corev1.ResourceList
		if c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways {
			addResources(reqs, c.Resources.Requests)
			addResources(sidecars, c.Resources.Requests)
			step = sidecars
		} else {
			step = corev1.ResourceList{}
			addResources(step, c.Resources.Requests)
			addResources(step, sidecars)
		}
		maxResources(initMax, step)
	}
	maxResources(reqs, initMax)

	if pod.Spec.Resources != nil {
		for _, name := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory} {
			if q, ok := pod.Spec.Resources.Requests[name]; ok {
				reqs[name] = q.DeepCopy()
			}
		}
	}
	addResources(reqs, pod.Spec.Overhead)

	pods := reqs[corev1.ResourcePods]
	pods.Add(*resource.NewQuantity(1, resource.DecimalSI))
	reqs[corev1.ResourcePods] = pods
	return reqs
}

func addResources(total, add corev1.ResourceList) {
	for name, q := range add {
		cur := total[name]
		cur.Add(q)
		total[name] = cur
	}
}

func maxResources(total, other corev1.ResourceList) {
	for name, q := range other {
		if cur, ok := total[name]; !ok || q.Cmp(cur) > 0 {
			total[name] = q.DeepCopy()
		}
	}
}

func isTerminal(pod *corev1.Pod) bool {
	return pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed
}
