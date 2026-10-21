package clustersummary

import (
	"sort"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

// Kind keys used in CountsInput.Unavailable and ResourceCounts.Unavailable.
const (
	KindPods         = "pods"
	KindDeployments  = "deployments"
	KindStatefulSets = "statefulsets"
	KindDaemonSets   = "daemonsets"
	KindServices     = "services"
	KindIngresses    = "ingresses"
	KindNodes        = "nodes"
	KindNamespaces   = "namespaces"
	KindJobs         = "jobs"
	KindCronJobs     = "cronjobs"
	KindConfigMaps   = "configmaps"
	KindPVCs         = "persistentvolumeclaims"
)

// CountsInput is the set of listed objects to count. A nil slice and an
// empty slice both mean "listed, none found"; a kind the caller could not
// list (forbidden, absent, cache still syncing) must be named in Unavailable
// so its count is omitted instead of reported as a fabricated zero.
//
// Secrets are deliberately not a field: the agent never lists them.
type CountsInput struct {
	Pods         []*corev1.Pod
	Deployments  []*appsv1.Deployment
	StatefulSets []*appsv1.StatefulSet
	DaemonSets   []*appsv1.DaemonSet
	Services     []*corev1.Service
	Ingresses    []*networkingv1.Ingress
	Nodes        []*corev1.Node
	Namespaces   []*corev1.Namespace
	Jobs         []*batchv1.Job
	CronJobs     []*batchv1.CronJob
	ConfigMaps   []*corev1.ConfigMap
	PVCs         []*corev1.PersistentVolumeClaim

	Unavailable []string
}

// ResourceCounts holds per-kind counts. A nil field means the kind was not
// counted (see Unavailable), never zero objects.
type ResourceCounts struct {
	Pods         *PodCount     `json:"pods,omitempty"`
	Deployments  *ReplicaCount `json:"deployments,omitempty"`
	StatefulSets *ReplicaCount `json:"statefulSets,omitempty"`
	DaemonSets   *ReplicaCount `json:"daemonSets,omitempty"`
	Services     *int          `json:"services,omitempty"`
	Ingresses    *int          `json:"ingresses,omitempty"`
	Nodes        *NodeCount    `json:"nodes,omitempty"`
	Namespaces   *int          `json:"namespaces,omitempty"`
	Jobs         *JobCount     `json:"jobs,omitempty"`
	CronJobs     *CronJobCount `json:"cronJobs,omitempty"`
	ConfigMaps   *int          `json:"configMaps,omitempty"`
	PVCs         *PVCCount     `json:"pvcs,omitempty"`
	Unavailable  []string      `json:"unavailable,omitempty"`
}

// PodCount splits pods by phase. Pods in an unrecognised phase count only
// toward Total.
type PodCount struct {
	Total     int `json:"total"`
	Running   int `json:"running"`
	Pending   int `json:"pending"`
	Failed    int `json:"failed"`
	Succeeded int `json:"succeeded"`
}

// ReplicaCount splits workloads into ready and not ready. Workloads scaled
// to zero are counted in ScaledToZero and in neither of the other two: they
// are neither healthy nor broken.
type ReplicaCount struct {
	Total        int `json:"total"`
	Ready        int `json:"ready"`
	NotReady     int `json:"notReady"`
	ScaledToZero int `json:"scaledToZero"`
}

// NodeCount splits nodes three ways. A NotReady node is NotReady whether or
// not it is also cordoned; Cordoned counts only Ready nodes that are
// unschedulable, so Ready+NotReady+Cordoned == Total.
type NodeCount struct {
	Total    int `json:"total"`
	Ready    int `json:"ready"`
	NotReady int `json:"notReady"`
	Cordoned int `json:"cordoned"`
}

// JobCount counts Jobs (not pods) by state.
type JobCount struct {
	Total     int `json:"total"`
	Active    int `json:"active"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
}

// CronJobCount counts CronJobs. Suspended takes precedence over Active.
type CronJobCount struct {
	Total     int `json:"total"`
	Active    int `json:"active"`
	Suspended int `json:"suspended"`
}

// PVCCount counts claims by phase; Lost and unknown phases are Unbound.
type PVCCount struct {
	Total   int `json:"total"`
	Bound   int `json:"bound"`
	Pending int `json:"pending"`
	Unbound int `json:"unbound"`
}

// Counts counts every kind in the input that is not marked unavailable.
func Counts(in CountsInput) ResourceCounts {
	skip := make(map[string]bool, len(in.Unavailable))
	for _, k := range in.Unavailable {
		skip[k] = true
	}
	var out ResourceCounts
	if len(skip) > 0 {
		out.Unavailable = make([]string, 0, len(skip))
		for k := range skip {
			out.Unavailable = append(out.Unavailable, k)
		}
		sort.Strings(out.Unavailable)
	}

	if !skip[KindPods] {
		c := &PodCount{Total: len(in.Pods)}
		for _, p := range in.Pods {
			switch p.Status.Phase {
			case corev1.PodRunning:
				c.Running++
			case corev1.PodPending:
				c.Pending++
			case corev1.PodFailed:
				c.Failed++
			case corev1.PodSucceeded:
				c.Succeeded++
			}
		}
		out.Pods = c
	}

	if !skip[KindDeployments] {
		c := &ReplicaCount{Total: len(in.Deployments)}
		for _, d := range in.Deployments {
			countReplicas(c, d.Status.Replicas, d.Status.AvailableReplicas)
		}
		out.Deployments = c
	}

	if !skip[KindStatefulSets] {
		c := &ReplicaCount{Total: len(in.StatefulSets)}
		for _, s := range in.StatefulSets {
			countReplicas(c, s.Status.Replicas, s.Status.ReadyReplicas)
		}
		out.StatefulSets = c
	}

	if !skip[KindDaemonSets] {
		c := &ReplicaCount{Total: len(in.DaemonSets)}
		for _, d := range in.DaemonSets {
			switch {
			case d.Status.DesiredNumberScheduled == 0:
				c.ScaledToZero++
			case d.Status.NumberUnavailable == 0:
				c.Ready++
			default:
				c.NotReady++
			}
		}
		out.DaemonSets = c
	}

	if !skip[KindServices] {
		out.Services = intPtr(len(in.Services))
	}
	if !skip[KindIngresses] {
		out.Ingresses = intPtr(len(in.Ingresses))
	}
	if !skip[KindNamespaces] {
		out.Namespaces = intPtr(len(in.Namespaces))
	}
	if !skip[KindConfigMaps] {
		out.ConfigMaps = intPtr(len(in.ConfigMaps))
	}

	if !skip[KindNodes] {
		c := &NodeCount{Total: len(in.Nodes)}
		for _, n := range in.Nodes {
			switch {
			case !nodeReady(n):
				c.NotReady++
			case n.Spec.Unschedulable:
				c.Cordoned++
			default:
				c.Ready++
			}
		}
		out.Nodes = c
	}

	if !skip[KindJobs] {
		c := &JobCount{Total: len(in.Jobs)}
		for _, j := range in.Jobs {
			switch {
			case jobCondition(j, batchv1.JobFailed):
				c.Failed++
			case jobCondition(j, batchv1.JobComplete):
				c.Succeeded++
			case j.Status.Active > 0:
				c.Active++
			}
		}
		out.Jobs = c
	}

	if !skip[KindCronJobs] {
		c := &CronJobCount{Total: len(in.CronJobs)}
		for _, cj := range in.CronJobs {
			if cj.Spec.Suspend != nil && *cj.Spec.Suspend {
				c.Suspended++
			} else if len(cj.Status.Active) > 0 {
				c.Active++
			}
		}
		out.CronJobs = c
	}

	if !skip[KindPVCs] {
		c := &PVCCount{Total: len(in.PVCs)}
		for _, pvc := range in.PVCs {
			switch pvc.Status.Phase {
			case corev1.ClaimBound:
				c.Bound++
			case corev1.ClaimPending:
				c.Pending++
			default:
				c.Unbound++
			}
		}
		out.PVCs = c
	}

	return out
}

func countReplicas(c *ReplicaCount, replicas, ready int32) {
	switch {
	case replicas == 0:
		c.ScaledToZero++
	case ready >= replicas:
		c.Ready++
	default:
		c.NotReady++
	}
}

// nodeReady is true only for an explicit Ready=True condition; a node with
// no Ready condition yet (just registered, or the condition was lost) is not
// ready.
func nodeReady(n *corev1.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

func jobCondition(j *batchv1.Job, t batchv1.JobConditionType) bool {
	for _, c := range j.Status.Conditions {
		if c.Type == t && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func intPtr(n int) *int { return &n }
