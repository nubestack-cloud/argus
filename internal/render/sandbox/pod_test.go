package sandbox

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

// These are "the sandbox's isolation properties... to whatever extent
// mechanically checkable" (BACKLOG.md F26) that DON'T need a real cluster:
// everything here is a static assertion against the PodSpec/NetworkPolicy
// objects this package actually builds, so a future edit that quietly drops
// one of lld/09 §2's requirements fails a test rather than shipping.
// runner_live_test.go covers the properties that can only be proven by
// actually running something on a real cluster (network denial in fact).

func testConfig() Config {
	return Config{Namespace: "argus-render-sandbox-test"}
}

func TestBuildPod_NoHostMounts(t *testing.T) {
	pod, err := BuildPod(testConfig(), "run1")
	if err != nil {
		t.Fatalf("BuildPod: %v", err)
	}
	for _, v := range pod.Spec.Volumes {
		if v.HostPath != nil {
			t.Fatalf("volume %q is a HostPath mount — lld/09 §2 requires no host mounts", v.Name)
		}
		if v.PersistentVolumeClaim != nil {
			t.Fatalf("volume %q is a PVC — scratch must be tmpfs-only, not persistent", v.Name)
		}
	}
	if len(pod.Spec.Volumes) != 1 || pod.Spec.Volumes[0].EmptyDir == nil {
		t.Fatalf("expected exactly one EmptyDir scratch volume, got %+v", pod.Spec.Volumes)
	}
	if pod.Spec.Volumes[0].EmptyDir.Medium != corev1.StorageMediumMemory {
		t.Fatalf("scratch volume must be tmpfs (Medium: Memory), got %q", pod.Spec.Volumes[0].EmptyDir.Medium)
	}
}

func TestBuildPod_NoDockerSocket(t *testing.T) {
	pod, err := BuildPod(testConfig(), "run1")
	if err != nil {
		t.Fatalf("BuildPod: %v", err)
	}
	for _, v := range pod.Spec.Volumes {
		if v.HostPath != nil && (v.HostPath.Path == "/var/run/docker.sock" || v.HostPath.Path == "/run/containerd/containerd.sock") {
			t.Fatalf("pod mounts a container runtime socket: %s", v.HostPath.Path)
		}
	}
	for _, c := range pod.Spec.Containers {
		for _, vm := range c.VolumeMounts {
			if vm.MountPath == "/var/run/docker.sock" {
				t.Fatalf("container %q mounts the docker socket", c.Name)
			}
		}
	}
}

func TestBuildPod_ReadOnlyRootAndNonRoot(t *testing.T) {
	pod, err := BuildPod(testConfig(), "run1")
	if err != nil {
		t.Fatalf("BuildPod: %v", err)
	}
	if pod.Spec.SecurityContext == nil || pod.Spec.SecurityContext.RunAsNonRoot == nil || !*pod.Spec.SecurityContext.RunAsNonRoot {
		t.Fatalf("pod SecurityContext must set RunAsNonRoot: true")
	}
	for _, c := range pod.Spec.Containers {
		sc := c.SecurityContext
		if sc == nil {
			t.Fatalf("container %q has no SecurityContext", c.Name)
		}
		if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
			t.Fatalf("container %q must set ReadOnlyRootFilesystem: true", c.Name)
		}
		if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
			t.Fatalf("container %q must set AllowPrivilegeEscalation: false", c.Name)
		}
		if sc.Privileged != nil && *sc.Privileged {
			t.Fatalf("container %q must not be privileged", c.Name)
		}
		if sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
			t.Fatalf("container %q must set RunAsNonRoot: true", c.Name)
		}
		if sc.Capabilities == nil || len(sc.Capabilities.Drop) != 1 || sc.Capabilities.Drop[0] != "ALL" {
			t.Fatalf("container %q must drop ALL capabilities, got %+v", c.Name, sc.Capabilities)
		}
	}
}

func TestBuildPod_NoServiceAccountToken(t *testing.T) {
	pod, err := BuildPod(testConfig(), "run1")
	if err != nil {
		t.Fatalf("BuildPod: %v", err)
	}
	if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		t.Fatalf("render pod must not automount a service account token — it has no business calling the API server about anything")
	}
}

func TestBuildPod_ResourceLimitsEqualRequests(t *testing.T) {
	pod, err := BuildPod(testConfig(), "run1")
	if err != nil {
		t.Fatalf("BuildPod: %v", err)
	}
	for _, c := range pod.Spec.Containers {
		for _, res := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory, corev1.ResourceEphemeralStorage} {
			req, hasReq := c.Resources.Requests[res]
			lim, hasLim := c.Resources.Limits[res]
			if !hasReq || !hasLim {
				t.Fatalf("container %q missing request or limit for %s", c.Name, res)
			}
			if req.Cmp(lim) != 0 {
				t.Fatalf("container %q resource %s: request (%s) != limit (%s) — lld/09 §2 requires no burst headroom", c.Name, res, req.String(), lim.String())
			}
		}
	}
}

func TestBuildPod_HasWallClockTimeout(t *testing.T) {
	pod, err := BuildPod(testConfig(), "run1")
	if err != nil {
		t.Fatalf("BuildPod: %v", err)
	}
	if pod.Spec.ActiveDeadlineSeconds == nil || *pod.Spec.ActiveDeadlineSeconds <= 0 {
		t.Fatalf("pod must set a positive ActiveDeadlineSeconds")
	}
	if pod.Spec.RestartPolicy != corev1.RestartPolicyNever {
		t.Fatalf("a single-use render pod must never restart, got %q", pod.Spec.RestartPolicy)
	}
}

func TestBuildPod_ScratchLimitCannotExceedMemoryLimit(t *testing.T) {
	cfg := testConfig()
	cfg.MemoryLimit = "128Mi"
	cfg.ScratchSizeLimit = "256Mi"
	if _, err := BuildPod(cfg, "run1"); err == nil {
		t.Fatalf("expected an error when scratch size exceeds the memory limit")
	}
}

func TestBuildPod_RuntimeClassOptedInOnlyWhenConfigured(t *testing.T) {
	pod, err := BuildPod(testConfig(), "run1")
	if err != nil {
		t.Fatalf("BuildPod: %v", err)
	}
	if pod.Spec.RuntimeClassName != nil {
		t.Fatalf("expected no RuntimeClassName when Config.RuntimeClassName is empty, got %q", *pod.Spec.RuntimeClassName)
	}

	cfg := testConfig()
	cfg.RuntimeClassName = "gvisor"
	pod2, err := BuildPod(cfg, "run1")
	if err != nil {
		t.Fatalf("BuildPod: %v", err)
	}
	if pod2.Spec.RuntimeClassName == nil || *pod2.Spec.RuntimeClassName != "gvisor" {
		t.Fatalf("expected RuntimeClassName 'gvisor' to be requested when configured")
	}
}

func TestBuildNetworkPolicy_DeniesAllIngressAndEgress(t *testing.T) {
	np := BuildNetworkPolicy(testConfig(), "run1")
	hasIngress, hasEgress := false, false
	for _, pt := range np.Spec.PolicyTypes {
		if pt == networkingv1.PolicyTypeIngress {
			hasIngress = true
		}
		if pt == networkingv1.PolicyTypeEgress {
			hasEgress = true
		}
	}
	if !hasIngress || !hasEgress {
		t.Fatalf("NetworkPolicy must govern both Ingress and Egress, got %+v", np.Spec.PolicyTypes)
	}
	if len(np.Spec.Ingress) != 0 {
		t.Fatalf("expected zero ingress rules (deny-all), got %+v", np.Spec.Ingress)
	}
	if len(np.Spec.Egress) != 0 {
		t.Fatalf("expected zero egress rules (deny-all), got %+v", np.Spec.Egress)
	}
	if np.Spec.PodSelector.MatchLabels[runLabelKey] != "run1" {
		t.Fatalf("NetworkPolicy must be scoped to this run's own pod label, got %+v", np.Spec.PodSelector)
	}
}

// --- argument/flag-injection hardening (security review finding) ----------

func TestValidateArgvElement_RefusesFlagLikeValues(t *testing.T) {
	for _, bad := range []string{"-f", "--set-string=foo=bar", "-", "--kube-context=evil"} {
		if err := validateArgvElement("Field", bad); err == nil {
			t.Errorf("expected %q to be refused as flag-like", bad)
		}
	}
	for _, ok := range []string{"", "my-release", "argus-render", "release_1"} {
		if err := validateArgvElement("Field", ok); err != nil {
			t.Errorf("expected %q to be accepted, got %v", ok, err)
		}
	}
}

func TestValidateValueFilePath_RefusesTraversalAndAbsolute(t *testing.T) {
	for _, bad := range []string{"../../etc/passwd", "../secrets.yaml", "/etc/passwd", "-f", "", "a/../../b"} {
		if err := validateValueFilePath(bad); err == nil {
			t.Errorf("expected %q to be refused", bad)
		}
	}
	for _, ok := range []string{"values-prod.yaml", "env/prod/values.yaml"} {
		if err := validateValueFilePath(ok); err != nil {
			t.Errorf("expected %q to be accepted, got %v", ok, err)
		}
	}
}

func TestPodAndNetworkPolicyNames_MatchTheirLabelSelector(t *testing.T) {
	pod, err := BuildPod(testConfig(), "run42")
	if err != nil {
		t.Fatalf("BuildPod: %v", err)
	}
	np := BuildNetworkPolicy(testConfig(), "run42")
	if pod.Labels[runLabelKey] != np.Spec.PodSelector.MatchLabels[runLabelKey] {
		t.Fatalf("pod's own run label (%q) must match the NetworkPolicy's selector (%q) — otherwise the policy silently selects nothing", pod.Labels[runLabelKey], np.Spec.PodSelector.MatchLabels[runLabelKey])
	}
}
