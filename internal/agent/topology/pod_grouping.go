package topology

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// podGroupListLimit bounds how many members a PodGroup node names in its
// summary. The tally always covers every pod; only the list is cut.
const podGroupListLimit = 10

// PodGroup is the pods that share one group identity — a run, an app, or a
// controller — and are drawn as a single node once there are more of them
// than BuildOptions.MaxIndividualPods.
type PodGroup struct {
	Key       string // "<namespace>/<GroupKind>/<GroupName>"
	GroupKind string // Workflow, Job, app, a controller kind, or standalone
	GroupName string
	Namespace string
	Pods      []*corev1.Pod
	Counts    podTally
}

// podTally counts pods by the bucket podSummaryStatus puts them in.
type podTally struct {
	Healthy, Degraded, Unhealthy int
}

func tallyPods(pods []*corev1.Pod, now time.Time) podTally {
	var t podTally
	for _, p := range pods {
		switch podSummaryStatus(p, now) {
		case StatusHealthy:
			t.Healthy++
		case StatusDegraded:
			t.Degraded++
		default:
			t.Unhealthy++
		}
	}
	return t
}

// status is the group's status: its worst bucket that has anyone in it.
func (t podTally) status() HealthStatus {
	switch {
	case t.Unhealthy > 0:
		return StatusUnhealthy
	case t.Degraded > 0:
		return StatusDegraded
	}
	return StatusHealthy
}

// groupLabels are the labels that name a pod's group, strongest first. A run
// label (Argo Workflow, Job) keeps each run apart even when every run carries
// the same app label; the app labels then gather an app's pods across its
// controllers. byApp marks the two app labels, which owner grouping ignores.
var groupLabels = []struct {
	label, kind string
	byApp       bool
}{
	{"workflows.argoproj.io/workflow", "Workflow", false},
	{"batch.kubernetes.io/job-name", "Job", false},
	{"job-name", "Job", false},
	{"app.kubernetes.io/name", "app", true},
	{"app", "app", true},
}

// podGroupOf names the group a pod belongs to. With byOwner set the app
// labels are skipped: a Helm chart stamps one app.kubernetes.io/name on every
// workload in a release, and grouping on it would pour all of them into one
// node. Without a group label the pod falls to its controller, and without a
// controller it is a group of one.
func podGroupOf(pod *corev1.Pod, byOwner bool) (kind, name string) {
	for _, g := range groupLabels {
		if g.byApp && byOwner {
			continue
		}
		if v := pod.Labels[g.label]; v != "" {
			return g.kind, v
		}
	}
	for _, ref := range pod.OwnerReferences {
		if ref.Controller != nil && *ref.Controller {
			return ref.Kind, ref.Name
		}
	}
	return "standalone", pod.Name
}

// GroupPods sorts the pods in namespaces opts admits into their groups, keyed
// by PodGroup.Key.
func GroupPods(pods []*corev1.Pod, opts BuildOptions, now time.Time) map[string]*PodGroup {
	out := map[string]*PodGroup{}
	for _, pod := range pods {
		if !opts.matchesNamespace(pod.Namespace) {
			continue
		}
		kind, name := podGroupOf(pod, opts.GroupPodsByOwner)
		key := strings.Join([]string{pod.Namespace, kind, name}, "/")
		g := out[key]
		if g == nil {
			g = &PodGroup{Key: key, GroupKind: kind, GroupName: name, Namespace: pod.Namespace}
			out[key] = g
		}
		g.Pods = append(g.Pods, pod)
	}
	for _, g := range out {
		g.Counts = tallyPods(g.Pods, now)
	}
	return out
}

// newPodNode is the node for one pod drawn on its own.
func newPodNode(pod *corev1.Pod, now time.Time) Node {
	var ready int
	var restarts int32
	for _, cs := range pod.Status.ContainerStatuses {
		restarts += cs.RestartCount
		if cs.Ready {
			ready++
		}
	}
	summary := map[string]any{
		"phase":      string(pod.Status.Phase),
		"ready":      strconv.Itoa(ready) + "/" + strconv.Itoa(len(pod.Spec.Containers)),
		"restarts":   restarts,
		"containers": len(pod.Spec.Containers),
	}
	if pod.Spec.NodeName != "" {
		summary["nodeName"] = pod.Spec.NodeName
	}
	if pod.DeletionTimestamp != nil {
		summary["terminating"] = true
	}
	status, reason := podStatus(pod, now)
	return Node{
		ID:           buildNodeID(KindPod, pod.Namespace, pod.Name),
		Kind:         KindPod,
		Namespace:    pod.Namespace,
		Name:         pod.Name,
		Status:       status,
		StatusReason: reason,
		Labels:       pod.Labels,
		Summary:      summary,
	}
}

// severityOrder sorts statuses worst first for a group's member list.
var severityOrder = map[HealthStatus]int{
	StatusUnhealthy: 0, StatusDegraded: 1, StatusUnknown: 2, StatusNeutral: 3, StatusHealthy: 4,
}

// newPodGroupNode is the node for a collapsed group. The summary carries the
// tally for every pod and names up to podGroupListLimit of them, worst first,
// each with its own computed status: a crash-looping pod still reports phase
// Running, so a member list that re-derived health from the phase would hide
// exactly the pod worth seeing. The node's reason is its worst member's.
func newPodGroupNode(g *PodGroup, now time.Time) Node {
	type member struct {
		name, reason string
		status       HealthStatus
	}
	members := make([]member, len(g.Pods))
	var restarts int32
	for i, pod := range g.Pods {
		s, r := podStatus(pod, now)
		members[i] = member{name: pod.Name, reason: r, status: s}
		for _, cs := range pod.Status.ContainerStatuses {
			restarts += cs.RestartCount
		}
	}
	slices.SortStableFunc(members, func(a, b member) int {
		return cmp.Or(cmp.Compare(severityOrder[a.status], severityOrder[b.status]), strings.Compare(a.name, b.name))
	})

	reason := ""
	for _, m := range members {
		if m.reason != "" && (m.status == StatusUnhealthy || m.status == StatusDegraded) {
			reason = m.reason
			break
		}
	}
	listed := make([]map[string]any, 0, min(len(members), podGroupListLimit))
	for _, m := range members[:min(len(members), podGroupListLimit)] {
		entry := map[string]any{"name": m.name, "status": string(m.status)}
		if m.reason != "" {
			entry["statusReason"] = m.reason
		}
		listed = append(listed, entry)
	}

	name := g.GroupName
	if name == "" {
		name = "pods"
	}
	return Node{
		ID:           "podgroup-" + strings.ReplaceAll(g.Key, "/", "-"),
		Kind:         KindPodGroup,
		Namespace:    g.Namespace,
		Name:         name,
		Status:       g.Counts.status(),
		StatusReason: reason,
		Summary: map[string]any{
			"groupKind":     g.GroupKind,
			"podCount":      len(g.Pods),
			"healthy":       g.Counts.Healthy,
			"degraded":      g.Counts.Degraded,
			"unhealthy":     g.Counts.Unhealthy,
			"totalRestarts": restarts,
			"pods":          listed,
		},
	}
}
