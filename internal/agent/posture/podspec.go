package posture

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// template is a pod spec and the object it is reported against: a workload's
// template is judged once for the workload, not once per pod it makes.
type template struct {
	at   subject
	spec *corev1.PodSpec
}

// templates lists the pod specs the container checks judge: every
// Deployment, StatefulSet and DaemonSet template, and each pod that has no
// owner. Pods with an owner are their workload's business.
func (in *CheckInput) templates() []template {
	var out []template
	for _, o := range in.Deployments {
		out = append(out, template{object("Deployment", o.Namespace, o.Name), &o.Spec.Template.Spec})
	}
	for _, o := range in.StatefulSets {
		out = append(out, template{object("StatefulSet", o.Namespace, o.Name), &o.Spec.Template.Spec})
	}
	for _, o := range in.DaemonSets {
		out = append(out, template{object("DaemonSet", o.Namespace, o.Name), &o.Spec.Template.Spec})
	}
	for _, o := range in.Pods {
		if len(o.OwnerReferences) == 0 {
			out = append(out, template{object("Pod", o.Namespace, o.Name), &o.Spec})
		}
	}
	return out
}

// The checks each group below judges on every template. A group counts its
// whole list once per template, whether or not the template has containers.
var (
	hostChecks      = []string{"hostNetwork", "hostPID", "hostIPC"}
	containerChecks = []string{"runAsRoot", "privileged", "privilegeEscalation", "readOnlyRootFs", "dangerousCapabilities", "insecureCapabilities"}
	runtimeChecks   = []string{"readinessProbeMissing", "livenessProbeMissing", "imageTagLatest", "pullPolicyNotAlways"}
	resourceChecks  = []string{"cpuRequestMissing", "memoryRequestMissing", "cpuLimitMissing", "memoryLimitMissing"}
	volumeChecks    = []string{"dockerSocketMount", "sensitiveHostPath"}
)

func (s *scan) podTemplates() {
	accounts := map[string]*corev1.ServiceAccount{}
	for _, sa := range s.in.ServiceAccounts {
		accounts[sa.Namespace+"/"+sa.Name] = sa
	}
	defaults := map[string]resourceDefaults{}
	for _, lr := range s.in.LimitRanges {
		defaults[lr.Namespace] = defaults[lr.Namespace].with(lr)
	}
	for _, t := range s.in.templates() {
		s.hostAccess(t, accounts)
		for i := range t.spec.InitContainers {
			s.containerSecurity(t, &t.spec.InitContainers[i])
		}
		for i := range t.spec.Containers {
			s.containerSecurity(t, &t.spec.Containers[i])
		}
		s.runtimeHygiene(t)
		// Without the LimitRange list a missing request may be one the
		// namespace fills in at admission; skip rather than guess.
		if s.in.LimitRanges != nil {
			s.resourceSizing(t, defaults[t.at.namespace])
		}
		s.hostVolumes(t)
	}
}

// hostAccess judges the pod-level settings: host namespaces and the service
// account token.
func (s *scan) hostAccess(t template, accounts map[string]*corev1.ServiceAccount) {
	ns := t.at.namespace
	s.evaluated(ns, hostChecks...)
	s.evaluated(ns, containerChecks...)
	if t.spec.HostNetwork {
		s.flag(t.at, "hostNetwork", SeverityWarning, "Shares the node's network namespace")
	}
	if t.spec.HostPID {
		s.flag(t.at, "hostPID", SeverityDanger, "Shares the node's process namespace")
	}
	if t.spec.HostIPC {
		s.flag(t.at, "hostIPC", SeverityDanger, "Shares the node's IPC namespace")
	}

	// A pod-level setting decides on its own. Left unset, the service
	// account's setting decides, so the account list must cover this
	// namespace for the answer to mean anything.
	explicit := t.spec.AutomountServiceAccountToken
	inventory := s.in.ServiceAccounts != nil &&
		(s.in.ServiceAccountsNamespace == "" || s.in.ServiceAccountsNamespace == ns)
	if explicit == nil && !inventory {
		return
	}
	s.evaluated(ns, "automountServiceAccountToken")
	mounted := true
	switch {
	case explicit != nil:
		mounted = *explicit
	default:
		name := t.spec.ServiceAccountName
		if name == "" {
			name = "default"
		}
		if sa := accounts[ns+"/"+name]; sa != nil && sa.AutomountServiceAccountToken != nil {
			mounted = *sa.AutomountServiceAccountToken
		}
	}
	if mounted {
		s.flag(t.at, "automountServiceAccountToken", SeverityWarning, "A service account token is mounted into the pod")
	}
}

// capabilityRisk sorts added capabilities into the two capability checks.
var capabilityRisk = map[string]string{
	"SYS_ADMIN": "dangerousCapabilities", "NET_ADMIN": "dangerousCapabilities", "ALL": "dangerousCapabilities",
	"NET_RAW": "insecureCapabilities", "SYS_PTRACE": "insecureCapabilities",
	"MKNOD": "insecureCapabilities", "DAC_OVERRIDE": "insecureCapabilities",
}

// containerSecurity judges one container's securityContext, with the pod's
// securityContext supplying the user settings the container leaves unset.
func (s *scan) containerSecurity(t template, c *corev1.Container) {
	sc := c.SecurityContext
	if sc == nil {
		sc = &corev1.SecurityContext{}
	}
	isTrue := func(b *bool) bool { return b != nil && *b }

	nonRoot, uid := sc.RunAsNonRoot, sc.RunAsUser
	if pod := t.spec.SecurityContext; pod != nil {
		if nonRoot == nil {
			nonRoot = pod.RunAsNonRoot
		}
		if uid == nil {
			uid = pod.RunAsUser
		}
	}
	if !isTrue(nonRoot) && (uid == nil || *uid == 0) {
		s.flag(t.at, "runAsRoot", SeverityWarning, fmt.Sprintf("container %q is not required to run as a non-root user", c.Name))
	}
	if isTrue(sc.Privileged) {
		s.flag(t.at, "privileged", SeverityDanger, fmt.Sprintf("container %q is privileged", c.Name))
	}
	if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
		s.flag(t.at, "privilegeEscalation", SeverityDanger, fmt.Sprintf("container %q does not set allowPrivilegeEscalation: false", c.Name))
	}
	if !isTrue(sc.ReadOnlyRootFilesystem) {
		s.flag(t.at, "readOnlyRootFs", SeverityWarning, fmt.Sprintf("container %q can write to its root filesystem", c.Name))
	}
	if sc.Capabilities == nil {
		return
	}
	for _, added := range sc.Capabilities.Add {
		switch capabilityRisk[strings.ToUpper(string(added))] {
		case "dangerousCapabilities":
			s.flag(t.at, "dangerousCapabilities", SeverityDanger, fmt.Sprintf("container %q adds %s", c.Name, added))
		case "insecureCapabilities":
			s.flag(t.at, "insecureCapabilities", SeverityWarning, fmt.Sprintf("container %q adds %s", c.Name, added))
		}
	}
}

// runtimeHygiene judges probes and image pinning on the app containers; init
// containers run to completion and take no probes.
func (s *scan) runtimeHygiene(t template) {
	s.evaluated(t.at.namespace, runtimeChecks...)
	for _, c := range t.spec.Containers {
		if c.ReadinessProbe == nil {
			s.flag(t.at, "readinessProbeMissing", SeverityWarning, fmt.Sprintf("container %q has no readiness probe", c.Name))
		}
		if c.LivenessProbe == nil {
			s.flag(t.at, "livenessProbeMissing", SeverityWarning, fmt.Sprintf("container %q has no liveness probe", c.Name))
		}
		tag, pinned := imagePin(c.Image)
		if pinned {
			continue
		}
		shown := tag
		if shown == "" {
			shown = "no tag"
		}
		s.flag(t.at, "imageTagLatest", SeverityDanger, fmt.Sprintf("container %q runs %s (%s)", c.Name, c.Image, shown))
		if policy := c.ImagePullPolicy; policy != corev1.PullAlways {
			s.flag(t.at, "pullPolicyNotAlways", SeverityWarning, fmt.Sprintf("container %q has a mutable tag but imagePullPolicy %s", c.Name, cmp.Or(string(policy), "unset")))
		}
	}
}

// imagePin returns an image reference's tag (or digest) and whether it pins
// a version: a digest does, so does any tag but "latest". A colon before the
// last "/" is a registry port, not a tag.
func imagePin(image string) (tag string, pinned bool) {
	if _, digest, ok := strings.Cut(image, "@"); ok {
		return digest, true
	}
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		tag = image[i+1:]
	}
	return tag, tag != "" && tag != "latest"
}

// resourceDefaults records which container requests and limits a
// namespace's LimitRanges fill in at admission, or the pod sets as a whole.
type resourceDefaults struct{ cpuRequest, memRequest, cpuLimit, memLimit bool }

func (d resourceDefaults) with(lr *corev1.LimitRange) resourceDefaults {
	for _, item := range lr.Spec.Limits {
		if item.Type != corev1.LimitTypeContainer {
			continue
		}
		d.cpuRequest = d.cpuRequest || has(item.DefaultRequest, corev1.ResourceCPU)
		d.memRequest = d.memRequest || has(item.DefaultRequest, corev1.ResourceMemory)
		d.cpuLimit = d.cpuLimit || has(item.Default, corev1.ResourceCPU)
		d.memLimit = d.memLimit || has(item.Default, corev1.ResourceMemory)
	}
	return d
}

func has(l corev1.ResourceList, name corev1.ResourceName) bool {
	_, ok := l[name]
	return ok
}

func set(l corev1.ResourceList, name corev1.ResourceName) bool {
	q, ok := l[name]
	return ok && !q.IsZero()
}

// resourceSizing judges requests and limits on the app containers. A value
// a LimitRange defaults, or that pod-level resources set, is not missing.
func (s *scan) resourceSizing(t template, d resourceDefaults) {
	s.evaluated(t.at.namespace, resourceChecks...)
	if pod := t.spec.Resources; pod != nil {
		d.cpuRequest = d.cpuRequest || set(pod.Requests, corev1.ResourceCPU)
		d.memRequest = d.memRequest || set(pod.Requests, corev1.ResourceMemory)
		d.cpuLimit = d.cpuLimit || set(pod.Limits, corev1.ResourceCPU)
		d.memLimit = d.memLimit || set(pod.Limits, corev1.ResourceMemory)
	}
	sizes := []struct {
		checkID  string
		covered  bool
		list     func(corev1.ResourceRequirements) corev1.ResourceList
		resource corev1.ResourceName
		what     string
	}{
		{"cpuRequestMissing", d.cpuRequest, requests, corev1.ResourceCPU, "CPU request"},
		{"memoryRequestMissing", d.memRequest, requests, corev1.ResourceMemory, "memory request"},
		{"cpuLimitMissing", d.cpuLimit, limits, corev1.ResourceCPU, "CPU limit"},
		{"memoryLimitMissing", d.memLimit, limits, corev1.ResourceMemory, "memory limit"},
	}
	for _, c := range t.spec.Containers {
		for _, z := range sizes {
			if !z.covered && !set(z.list(c.Resources), z.resource) {
				s.flag(t.at, z.checkID, SeverityWarning, fmt.Sprintf("container %q sets no %s", c.Name, z.what))
			}
		}
	}
}

func requests(r corev1.ResourceRequirements) corev1.ResourceList { return r.Requests }
func limits(r corev1.ResourceRequirements) corev1.ResourceList   { return r.Limits }

// runtimeSockets are the container runtime sockets a hostPath can expose;
// sensitiveRoots are host directories that should never be mounted.
var (
	runtimeSockets = []string{"docker.sock", "containerd.sock", "crio.sock"}
	sensitiveRoots = []string{"/etc", "/proc", "/sys", "/var/run", "/var/log", "/root"}
)

func (s *scan) hostVolumes(t template) {
	s.evaluated(t.at.namespace, volumeChecks...)
	for _, v := range t.spec.Volumes {
		if v.HostPath == nil {
			continue
		}
		p := v.HostPath.Path
		under := func(root string) bool { return p == root || strings.HasPrefix(p, root+"/") }
		switch {
		case slices.ContainsFunc(runtimeSockets, func(sock string) bool { return strings.Contains(p, sock) }):
			s.flag(t.at, "dockerSocketMount", SeverityDanger, fmt.Sprintf("volume %q mounts the container runtime socket %s", v.Name, p))
		case p == "/":
			s.flag(t.at, "sensitiveHostPath", SeverityDanger, fmt.Sprintf("volume %q mounts the node's whole filesystem", v.Name))
		case slices.ContainsFunc(sensitiveRoots, under):
			s.flag(t.at, "sensitiveHostPath", SeverityWarning, fmt.Sprintf("volume %q mounts host path %s", v.Name, p))
		}
	}
}
