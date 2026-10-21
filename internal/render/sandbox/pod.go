package sandbox

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// runLabel is set on every render pod and is exactly what BuildNetworkPolicy
// scopes its deny-all rule to — one pod, one NetworkPolicy, one label value,
// so there is never a window where a render pod exists without its policy
// already selecting it (the policy is created first; see runner.go).
const runLabelKey = "argus.io/render-run"

// PodName and NetworkPolicyName are deterministic from a run ID, so a caller
// (or a test) never has to guess what BuildPod/BuildNetworkPolicy will name
// their own objects.
func PodName(runID string) string           { return "argus-render-" + runID }
func NetworkPolicyName(runID string) string { return "argus-render-deny-" + runID }

// BuildPod constructs the single-use render pod. Every property below is one
// lld/09-repo-gitops-design.md §2 line item made concrete — see this
// package's doc comment for which of them this implementation actually
// achieves versus discloses as unachieved (gVisor), and pod_test.go for the
// mechanical check that every OTHER one is really set, not just claimed in a
// comment.
//
// The pod's single container just sleeps for the pod's own timeout — nothing
// is rendered until runner.go execs into it. That is deliberate: exec traffic
// (kubectl exec / client-go remotecommand) reaches the container over the
// API server -> kubelet -> container-runtime path, which is NOT the pod's
// own network namespace and is therefore NOT blocked by the deny-all
// NetworkPolicy below — the pod can be fed content and have its output read
// back over the one channel that must stay open, while every path the POD
// ITSELF could use to dial out stays closed.
func BuildPod(cfg Config, runID string) (*corev1.Pod, error) {
	cfg = cfg.withDefaults()

	memLimit, err := resource.ParseQuantity(cfg.MemoryLimit)
	if err != nil {
		return nil, fmt.Errorf("sandbox: invalid MemoryLimit %q: %w", cfg.MemoryLimit, err)
	}
	scratchLimit, err := resource.ParseQuantity(cfg.ScratchSizeLimit)
	if err != nil {
		return nil, fmt.Errorf("sandbox: invalid ScratchSizeLimit %q: %w", cfg.ScratchSizeLimit, err)
	}
	if scratchLimit.Cmp(memLimit) > 0 {
		return nil, fmt.Errorf("sandbox: ScratchSizeLimit (%s) must not exceed MemoryLimit (%s) — the scratch volume is tmpfs and counts against the pod's own memory limit", cfg.ScratchSizeLimit, cfg.MemoryLimit)
	}
	cpuLimit, err := resource.ParseQuantity(cfg.CPULimit)
	if err != nil {
		return nil, fmt.Errorf("sandbox: invalid CPULimit %q: %w", cfg.CPULimit, err)
	}

	falseVal := false
	trueVal := true
	nonRootUID := int64(65532)
	deadline := int64(cfg.PodTimeout.Seconds())
	if deadline <= 0 {
		deadline = 1
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      PodName(runID),
			Namespace: cfg.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "argus-render-sandbox",
				"app.kubernetes.io/managed-by": "argus",
				runLabelKey:                    runID,
			},
			Annotations: map[string]string{
				// Human-readable breadcrumb only — nothing reads this back
				// programmatically, and it names no secret or content.
				"argus.io/purpose": "single-use render-and-diff sandbox — never reused across renders",
			},
		},
		Spec: corev1.PodSpec{
			RestartPolicy:                corev1.RestartPolicyNever,
			ActiveDeadlineSeconds:        &deadline,
			AutomountServiceAccountToken: &falseVal,
			EnableServiceLinks:           &falseVal,
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: &trueVal,
				RunAsUser:    &nonRootUID,
				RunAsGroup:   &nonRootUID,
				FSGroup:      &nonRootUID,
				SeccompProfile: &corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				},
			},
			// No image pull secrets, no node selector, no toleration beyond
			// the default — this pod asks for nothing beyond a place to run
			// and the resources declared below.
			Containers: []corev1.Container{
				{
					Name:    "render",
					Image:   cfg.Image,
					Command: []string{"sleep", fmt.Sprintf("%d", deadline)},
					SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: &falseVal,
						ReadOnlyRootFilesystem:   &trueVal,
						RunAsNonRoot:             &trueVal,
						RunAsUser:                &nonRootUID,
						Privileged:               &falseVal,
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"ALL"},
						},
					},
					Resources: corev1.ResourceRequirements{
						// Requests EQUAL limits on every dimension — lld/09
						// §2: "no burst headroom for a workload this
						// untrusted".
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:              cpuLimit,
							corev1.ResourceMemory:           memLimit,
							corev1.ResourceEphemeralStorage: resource.MustParse("32Mi"),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:              cpuLimit,
							corev1.ResourceMemory:           memLimit,
							corev1.ResourceEphemeralStorage: resource.MustParse("32Mi"),
						},
					},
					Env: []corev1.EnvVar{
						// helm/kubectl both want a writable HOME for cache
						// and config lookup — pointed at the tmpfs scratch
						// mount, never at the read-only root filesystem.
						{Name: "HOME", Value: "/scratch"},
						{Name: "XDG_CACHE_HOME", Value: "/scratch/.cache"},
						{Name: "XDG_CONFIG_HOME", Value: "/scratch/.config"},
					},
					VolumeMounts: []corev1.VolumeMount{
						{Name: "scratch", MountPath: "/scratch"},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "scratch",
					// tmpfs-only scratch — lld/09 §2. Never a HostPath, never
					// a PVC: an EmptyDir with Medium Memory is backed by RAM
					// and is gone the moment the pod is deleted.
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{
							Medium:    corev1.StorageMediumMemory,
							SizeLimit: &scratchLimit,
						},
					},
				},
			},
		},
	}
	if cfg.RuntimeClassName != "" {
		pod.Spec.RuntimeClassName = &cfg.RuntimeClassName
	}
	return pod, nil
}

// BuildNetworkPolicy is lld/09 §2's "network disabled by default" — a
// deny-all policy (no ingress rules, no egress rules, both PolicyTypes
// present) scoped to exactly this run's render pod, nothing broader.
//
// Kubernetes' own semantics make the empty rule lists do the denying:
// selecting a pod under a NetworkPolicy at all switches that pod from
// "unrestricted" to "whatever the union of matching policies allows", and a
// policy with a PolicyType listed but no rules for it allows nothing in that
// direction. No "except..." rule is added anywhere in this package — a
// chart with `dependencies` needing a remote fetch is explicitly named in
// lld/09 §2 as a case that would need a narrow, per-binding opt-in, and this
// package does not implement one, so that class of chart cannot be rendered
// here today. That is a real, disclosed limitation (see evaluate.go/render's
// caller-facing docs), not a silent gap.
func BuildNetworkPolicy(cfg Config, runID string) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      NetworkPolicyName(runID),
			Namespace: cfg.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "argus-render-sandbox",
				"app.kubernetes.io/managed-by": "argus",
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{runLabelKey: runID},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			// Deliberately no Ingress/Egress rule entries — see doc comment.
		},
	}
}
