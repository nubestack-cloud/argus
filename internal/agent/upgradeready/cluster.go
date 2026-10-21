package upgradeready

import (
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// versionSequence: a control plane moves one minor at a time.
func (s *scan) versionSequence() Check {
	r := newReport("control-plane-upgrade-path", "Upgrade path", "Control plane version sequence",
		"Kubernetes control plane version policy", "The target is the next minor version.").citing(docSkew)
	from, to := s.from, s.to
	if to.Major() == from.Major() && to.Minor() <= from.Minor()+1 {
		return r.Check
	}
	var path []string
	for m := from.Minor(); m <= to.Minor() && to.Major() == from.Major(); m++ {
		path = append(path, fmt.Sprintf("%d.%d", from.Major(), m))
	}
	if len(path) > 10 {
		path = append(path[:8], "…", label(to))
	}
	impact := "Control planes are upgraded one minor version at a time; skipping a minor is unsupported."
	fix := "Upgrade in steps, " + strings.Join(path, " → ") + ", and scan again before each one."
	if to.Major() != from.Major() {
		path = []string{label(from), label(to)}
		impact = "A control plane cannot jump straight to another major version."
		fix = fmt.Sprintf("Target %d.%d first, then scan again for each step after it.", from.Major(), from.Minor()+1)
	}
	r.flag(LevelBlocker, "Control plane cannot skip versions", nil,
		Evidence{Source: "version policy", Path: "controlPlane", Detail: strings.Join(path, " → ")}, impact, fix)
	r.Summary = "The target skips versions the control plane has to pass through."
	return r.Check
}

// The agent cannot read the API server's metrics, rendered Helm manifests
// (they are in release Secrets) or the original manifests kubectl applied,
// so the checks built on them always stop at unknown and say what to look
// at instead.
const noSourceManifests = "Rendered Helm manifests are not collected (they live in release Secret payloads), and no kubectl last-applied configuration was available."

func (s *scan) deprecatedAPIRequests() Check {
	r := newReport("deprecated-api-requests", "API compatibility", "Removed API usage",
		"Kubernetes API server usage metrics", "").citing(docAPIMigration)
	r.caveat("The ARGUS agent does not read the API server's /metrics endpoint. Look for apiserver_requested_deprecated_apis in your own monitoring before upgrading.")
	return r.unknown("API usage metrics are not collected, so requests to removed APIs could not be looked for.")
}

func (s *scan) manifestAPIVersions() Check {
	r := newReport("manifest-api-compatibility", "API compatibility", "Source manifest API versions",
		"Helm release manifests and kubectl last-applied configuration", "").citing(docAPIMigration)
	r.caveat(noSourceManifests)
	return r.unknown("No source manifests were available, so their API versions could not be checked: Helm release manifests are not collected.")
}

func (s *scan) strictNetworkValidation() Check {
	r := newReport("strict-ip-cidr-validation", "API compatibility", "Strict source IP and CIDR validation",
		"Helm and kubectl last-applied source manifests", "").since("1.36").citing(docStrictIP)
	r.caveat(noSourceManifests)
	return r.unknown("No source manifests were available, so IP and CIDR values in them could not be validated.")
}

func ready(n *corev1.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

func (s *scan) nodeReadiness() Check {
	r := newReport("node-health", "Cluster health", "Node readiness", "Live Node Ready conditions", "Every node is Ready.")
	nodes := s.in.Nodes
	if len(nodes) == 0 {
		return r.unknown("Nodes could not be read, so cluster health before the upgrade is unverified.")
	}
	r.Inspected = len(nodes)
	for _, n := range nodes {
		if n != nil && !ready(n) {
			r.flag(LevelWarning, "Node not Ready", nodeRef(n.Name), live("status.conditions[Ready]", ""),
				"Upgrading with a node already down leaves less capacity, and makes upgrade disruption hard to tell from the existing failure.",
				"Bring the node back to Ready, or remove it from the cluster, before starting.")
		}
	}
	return r.finish(func(n int) string { return count(n, "node is", "nodes are") + " not Ready." }, "")
}

// skewed reports whether a kubelet or kube-proxy at v is outside what a
// control plane at the target supports.
func (s *scan) skewed(v minor) bool { return v.LessThan(oldestSupported(s.to)) || v.GreaterThan(s.to) }

func (s *scan) supportedRange() string {
	return fmt.Sprintf("Kubernetes %s supports %s through %s.", label(s.to), label(oldestSupported(s.to)), label(s.to))
}

func (s *scan) kubeletSkew() Check {
	r := newReport("kubelet-version-skew", "Component compatibility", "Kubelet version skew",
		"Node status kubelet versions", "Every kubelet is within what the target control plane supports.").citing(docSkew)
	nodes := s.in.Nodes
	if len(nodes) == 0 {
		return r.unknown("Nodes could not be read, so kubelet versions are unverified.")
	}
	r.Inspected = len(nodes)
	unreadable := 0
	for _, n := range nodes {
		if n == nil {
			continue
		}
		raw := n.Status.NodeInfo.KubeletVersion
		v, err := readMinor(raw)
		if err != nil {
			unreadable++
			continue
		}
		if !s.skewed(v) {
			continue
		}
		fix := fmt.Sprintf("Upgrade this node's kubelet to %s or later before the control plane.", label(oldestSupported(s.to)))
		if v.GreaterThan(s.to) {
			fix = fmt.Sprintf("This kubelet is newer than the %s target: pick a target that supports kubelet %s, or replace the node.", label(s.to), label(v))
		}
		f := r.flag(LevelBlocker, "Kubelet "+label(v)+" unsupported", nodeRef(n.Name), live("status.nodeInfo.kubeletVersion", raw), "Kubelet versions: "+s.supportedRange(), fix)
		f.AppliesFrom = label(s.to)
	}
	if unreadable > 0 {
		r.caveat(fmt.Sprintf("The kubelet version on %s could not be read.", count(unreadable, "node", "nodes")))
	}
	return r.finish(func(n int) string {
		return fmt.Sprintf("%s outside the skew Kubernetes %s supports.", count(n, "kubelet is", "kubelets are"), label(s.to))
	}, fmt.Sprintf("The kubelet version could not be read on %s.", count(unreadable, "node", "nodes")))
}

func isKubeProxy(ds *appsv1.DaemonSet) bool {
	return ds.Name == "kube-proxy" || ds.Labels["k8s-app"] == "kube-proxy" || ds.Labels["component"] == "kube-proxy"
}

// imageMinor reads the Kubernetes minor from an image's tag, "v1.36.2",
// "1.36.2-eks-1" or "v1.36.2+rke2r1" alike.
func imageMinor(image string) (minor, bool) {
	image, _, _ = strings.Cut(image, "@")
	i := strings.LastIndex(image, ":")
	if i < strings.LastIndex(image, "/") || i < 0 {
		return nil, false
	}
	tag := strings.TrimPrefix(image[i+1:], "v")
	end := strings.IndexAny(tag, "-+")
	if end < 0 {
		end = len(tag)
	}
	parts := strings.Split(tag[:end], ".")
	if len(parts) < 2 || len(parts) > 3 {
		return nil, false
	}
	for _, p := range parts {
		if p == "" || strings.Trim(p, "0123456789") != "" {
			return nil, false
		}
	}
	v, err := readMinor(parts[0] + "." + parts[1])
	return v, err == nil
}

// proxyImage is the kube-proxy container's image: the one container, or
// the one named kube-proxy among several.
func proxyImage(ds *appsv1.DaemonSet) (string, bool) {
	cs := ds.Spec.Template.Spec.Containers
	for _, c := range cs {
		if len(cs) == 1 || c.Name == "kube-proxy" {
			return c.Image, true
		}
	}
	return "", false
}

func (s *scan) kubeProxySkew() Check {
	r := newReport("kube-proxy-version-skew", "Component compatibility", "kube-proxy version skew",
		"kube-proxy DaemonSet images", "kube-proxy's version is within what the target control plane supports.").citing(docSkew)
	if s.in.DaemonSets == nil {
		return r.unknown("DaemonSets could not be read, so kube-proxy is unverified.")
	}
	unreadable := 0
	for _, ds := range s.in.DaemonSets {
		if ds == nil || !isKubeProxy(ds) {
			continue
		}
		r.Inspected++
		image, _ := proxyImage(ds)
		v, ok := imageMinor(image)
		if !ok {
			unreadable++
			continue
		}
		if s.skewed(v) {
			f := r.flag(LevelBlocker, "kube-proxy "+label(v)+" unsupported", &ResourceRef{Group: "apps", Kind: "DaemonSet", Namespace: ds.Namespace, Name: ds.Name},
				live("spec.template.spec.containers[].image", image), "kube-proxy versions: "+s.supportedRange(),
				"Upgrade kube-proxy to a supported version as one of the upgrade's steps.")
			f.AppliesFrom = label(s.to)
		}
	}
	if r.Inspected == 0 {
		return r.notApplicable("No kube-proxy DaemonSet: the provider manages it, something else replaces it, or it runs another way.")
	}
	if unreadable > 0 {
		r.caveat("The version of " + count(unreadable, "kube-proxy installation", "kube-proxy installations") + " could not be read from its image.")
	}
	return r.finish(func(n int) string {
		return count(n, "kube-proxy installation is", "kube-proxy installations are") + " outside the supported skew."
	}, "kube-proxy was found, but its version could not be read from its image.")
}

// kubeletUnseen explains why a check built on kubelet evidence cannot see
// it; the agent deliberately holds no nodes/proxy access.
func (s *scan) kubeletUnseen(r *report, what string) {
	r.caveat(what)
	if s.in.Nodes != nil {
		r.caveat("Kubelet metrics and effective configuration are reachable only through nodes/proxy, which the ARGUS agent deliberately does not hold; check this on the nodes themselves.")
	}
}

func linuxNodes(nodes []*corev1.Node) (seen, linux int) {
	for _, n := range nodes {
		if n == nil {
			continue
		}
		seen++
		if !strings.EqualFold(n.Status.NodeInfo.OperatingSystem, "windows") {
			linux++
		}
	}
	return seen, linux
}

func (s *scan) cgroupV1() Check {
	r := newReport("node-cgroup-v1", "Node compatibility", "Node cgroup compatibility", "Kubelet cgroup version metric", "").since("1.35").citing(docCgroup)
	if seen, linux := linuxNodes(s.in.Nodes); seen == 0 {
		return r.unknown("Nodes could not be read, so cgroup versions are unverified.")
	} else if linux == 0 {
		return r.notApplicable("Every node runs Windows, which has no cgroups.")
	}
	s.kubeletUnseen(r, "The kubelet's cgroup version metric could not be read.")
	return r.unknown("The kubelet cgroup version metric is not collected, so cgroup v1 nodes could not be ruled out.")
}

func (s *scan) runtimeSupport() Check {
	r := newReport("container-runtime-support", "Node compatibility", "Container runtime support", "Kubelet CRI support metric and Node status", "").since("1.36").citing(docRuntime)
	if seen, linux := linuxNodes(s.in.Nodes); seen == 0 {
		return r.unknown("Nodes could not be read, so container runtimes are unverified.")
	} else if linux == 0 {
		return r.notApplicable("Every node runs Windows, where this runtime change does not apply.")
	}
	s.kubeletUnseen(r, "The kubelet's CRI support metric could not be read.")
	return r.unknown("The kubelet CRI support metric is not collected, so an unsupported runtime could not be ruled out.")
}

func (s *scan) eventQPS() Check {
	r := newReport("kubelet-event-qps-change", "Node configuration", "Kubelet event throttling behavior", "Effective kubelet configuration", "").since("1.37").citing(docEventQPS)
	if s.in.Nodes != nil {
		s.kubeletUnseen(r, "The kubelet's eventRecordQPS setting could not be read.")
	}
	return r.unknown("Effective kubelet configuration is not collected, so an eventRecordQPS of zero, which 1.37 turns into unlimited, could not be ruled out.")
}
