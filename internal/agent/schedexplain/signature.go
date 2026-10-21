package schedexplain

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// A scheduling signature identifies pods the scheduler will place in exactly
// the same way: the same nodeSelector, required node affinity and
// tolerations, plus the constraints that cannot be judged from labels and
// taints (pod affinity and anti-affinity, topology spread, volumes, host
// ports, runtime class, scheduler name, extended resources, gates and claims).
// Each is written as one canonical line and the lines are sorted, so two
// specs that differ only in order hash the same.
//
// The group fingerprint adds the namespace, the owner and the pod's requests,
// so the stuck replicas of one workload fold into one answer, and a workload
// whose requests changed between rollouts does not.

// OwnerRef identifies the workload a pending pod belongs to.
type OwnerRef struct {
	Group string `json:"group,omitempty"`
	Kind  string `json:"kind"`
	Name  string `json:"name"`
}

// Signature is the pod's scheduling signature, "sha256:<hex>".
func Signature(pod *corev1.Pod) string {
	return "sha256:" + digestLines(placementLines(pod, PodRequests(pod)))
}

// PodOwner returns the pod's controller owner, or the pod itself when it has
// none. A ReplicaSet owner is returned as it is; a caller that wants the
// replicas of a Deployment's successive ReplicaSets to fold together resolves
// the owner further and uses GroupFingerprintFor.
func PodOwner(pod *corev1.Pod) OwnerRef {
	if owner := metav1.GetControllerOf(pod); owner != nil {
		return OwnerRef{Group: schema.FromAPIVersionAndKind(owner.APIVersion, owner.Kind).Group, Kind: owner.Kind, Name: owner.Name}
	}
	return OwnerRef{Kind: "Pod", Name: pod.Name}
}

// GroupFingerprint is "sha256:<hex>" over the namespace, the controller
// owner, the pod's requests and its signature.
func GroupFingerprint(pod *corev1.Pod) string {
	return GroupFingerprintFor(pod, PodOwner(pod))
}

// GroupFingerprintFor is GroupFingerprint with an owner the caller resolved.
func GroupFingerprintFor(pod *corev1.Pod, owner OwnerRef) string {
	requests := PodRequests(pod)
	lines := []string{
		"namespace " + strconv.Quote(pod.Namespace),
		fmt.Sprintf("owner %q %q %q", owner.Group, owner.Kind, owner.Name),
		"signature " + digestLines(placementLines(pod, requests)),
	}
	for name, q := range requests {
		lines = append(lines, fmt.Sprintf("request %q %s", name, q.String()))
	}
	return "sha256:" + digestLines(lines)
}

// IsPending reports a pod the scheduler has yet to place: unbound, not
// finished, not being deleted.
func IsPending(pod *corev1.Pod) bool {
	return pod != nil && pod.Spec.NodeName == "" && !isTerminal(pod) && pod.DeletionTimestamp == nil
}

// SimilarPending counts the pending pods in pod's namespace — pod itself
// among them when it is pending — with pod's group fingerprint.
func SimilarPending(pod *corev1.Pod, candidates []*corev1.Pod) int {
	want := GroupFingerprint(pod)
	n := 0
	for _, c := range candidates {
		if IsPending(c) && c.Namespace == pod.Namespace && GroupFingerprint(c) == want {
			n++
		}
	}
	return n
}

// placementLines writes everything that decides where pod can go as one
// canonical line each.
func placementLines(pod *corev1.Pod, requests corev1.ResourceList) []string {
	var lines []string
	for k, v := range pod.Spec.NodeSelector {
		lines = append(lines, "selector "+requirementText(k, corev1.NodeSelectorOpIn, []string{v}))
	}
	if a := pod.Spec.Affinity; a != nil && a.NodeAffinity != nil && a.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution != nil {
		// Present with no terms matches no node, which is not the same as
		// having no required affinity, so its presence is a line of its own.
		lines = append(lines, "affinity required")
		for _, t := range a.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms {
			lines = append(lines, "affinity term "+termText(t))
		}
	}
	for _, t := range pod.Spec.Tolerations {
		// An omitted operator is Equal, as the scheduler reads it.
		op := cmp.Or(t.Operator, corev1.TolerationOpEqual)
		seconds := "-"
		if t.TolerationSeconds != nil {
			seconds = strconv.FormatInt(*t.TolerationSeconds, 10)
		}
		lines = append(lines, fmt.Sprintf("toleration %q %s %q %s %s", t.Key, op, t.Value, t.Effect, seconds))
	}
	for _, c := range opaqueConstraints(pod, requests) {
		lines = append(lines, "constraint "+c)
	}
	return lines
}

// termText is one affinity term with its requirements, and each one's values,
// in a fixed order: the scheduler reads all of them as sets.
func termText(t corev1.NodeSelectorTerm) string {
	part := func(label string, reqs []corev1.NodeSelectorRequirement) string {
		texts := make([]string, len(reqs))
		for i, r := range reqs {
			texts[i] = requirementText(r.Key, r.Operator, r.Values)
		}
		slices.Sort(texts)
		return label + "(" + strings.Join(texts, "; ") + ")"
	}
	return part("labels", t.MatchExpressions) + " " + part("fields", t.MatchFields)
}

func requirementText(key string, op corev1.NodeSelectorOperator, values []string) string {
	return fmt.Sprintf("%q %s %q", key, op, distinctSorted(values))
}

// opaqueConstraints names the placement inputs that labels and taints do not
// settle. Their content is hashed rather than read: two pods that differ in
// any of them must not share a signature.
func opaqueConstraints(pod *corev1.Pod, requests corev1.ResourceList) []string {
	var out []string
	add := func(s string) { out = append(out, s) }
	if a := pod.Spec.Affinity; a != nil {
		if a.PodAffinity != nil && len(a.PodAffinity.RequiredDuringSchedulingIgnoredDuringExecution) > 0 {
			add(digestOf("podAffinity", a.PodAffinity.RequiredDuringSchedulingIgnoredDuringExecution))
		}
		if a.PodAntiAffinity != nil && len(a.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution) > 0 {
			add(digestOf("podAntiAffinity", a.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution))
		}
	}
	for _, c := range pod.Spec.TopologySpreadConstraints {
		if c.WhenUnsatisfiable == corev1.DoNotSchedule {
			add(digestOf("topologySpread", c))
		}
	}
	for _, v := range pod.Spec.Volumes {
		switch {
		case v.PersistentVolumeClaim != nil:
			add("persistentVolumeClaim:" + v.PersistentVolumeClaim.ClaimName)
		case v.Ephemeral != nil:
			add(digestOf("ephemeralVolume", v.Ephemeral))
		}
	}
	for _, c := range slices.Concat(pod.Spec.InitContainers, pod.Spec.Containers) {
		for _, p := range c.Ports {
			if p.HostPort > 0 {
				add(fmt.Sprintf("hostPort:%s:%s:%d", p.HostIP, p.Protocol, p.HostPort))
			}
		}
	}
	for name := range requests {
		// A vendor resource (nvidia.com/gpu) depends on device plugins.
		if strings.Contains(string(name), "/") {
			add("providerResource:" + string(name))
		}
	}
	if rc := pod.Spec.RuntimeClassName; rc != nil {
		add("runtimeClass:" + *rc)
	}
	if s := pod.Spec.SchedulerName; s != "" && s != corev1.DefaultSchedulerName {
		add("schedulerName:" + s)
	}
	if len(pod.Spec.SchedulingGates) > 0 {
		add(digestOf("schedulingGates", pod.Spec.SchedulingGates))
	}
	if len(pod.Spec.ResourceClaims) > 0 {
		add(digestOf("resourceClaims", pod.Spec.ResourceClaims))
	}
	return distinctSorted(out)
}

// digestOf is "name:sha256:<hex>" over value's JSON encoding.
func digestOf(name string, value any) string {
	b, _ := json.Marshal(value)
	sum := sha256.Sum256(b)
	return name + ":sha256:" + hex.EncodeToString(sum[:])
}

// digestLines is hex SHA-256 over the lines sorted, so their order is never
// part of the answer.
func digestLines(lines []string) string {
	sorted := slices.Sorted(slices.Values(lines))
	sum := sha256.Sum256([]byte(strings.Join(sorted, "\n")))
	return hex.EncodeToString(sum[:])
}

func distinctSorted(values []string) []string {
	return slices.Compact(slices.Sorted(slices.Values(values)))
}
