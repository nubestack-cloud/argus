package upgradeready

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// Platforms DetectPlatform reports. PlatformKubernetes means the nodes were
// read and carry no managed-platform or distribution signal: known not to be
// GKE/EKS/AKS, which is what the platform-specific checks need to say "not
// applicable" rather than "unknown".
const (
	PlatformGKE        = "gke"
	PlatformEKS        = "eks"
	PlatformAKS        = "aks"
	PlatformRKE2       = "rke2"
	PlatformK3s        = "k3s"
	PlatformKubernetes = "kubernetes"
)

// DetectPlatform infers the cluster platform from its Nodes alone — the
// provider ID scheme, the managed-platform node labels and the kubelet's
// version suffix — so it needs nothing beyond the Node objects the agent
// already caches. readable=false (the Node list could not be read) yields "",
// which the checks treat as unknown. A managed cloud platform wins over a
// distribution signal, since GKE/EKS/AKS behaviour is what the
// platform-specific checks key on.
func DetectPlatform(nodes []*corev1.Node, readable bool) string {
	if !readable {
		return ""
	}
	var eks, aks, rke2, k3s bool
	for _, n := range nodes {
		if n == nil {
			continue
		}
		provider := strings.ToLower(n.Spec.ProviderID)
		labels := n.Labels
		has := func(prefix string) bool {
			for k := range labels {
				if strings.HasPrefix(k, prefix) {
					return true
				}
			}
			return false
		}
		kubelet := strings.ToLower(n.Status.NodeInfo.KubeletVersion)
		switch {
		case strings.HasPrefix(provider, "gce://") || has("cloud.google.com/gke-"):
			return PlatformGKE
		case has("eks.amazonaws.com/"):
			eks = true
		case strings.HasPrefix(provider, "azure://") && has("kubernetes.azure.com/"):
			aks = true
		case strings.Contains(kubelet, "+rke2") || strings.HasPrefix(provider, "rke2://") || labels["node.kubernetes.io/instance-type"] == "rke2":
			rke2 = true
		case strings.Contains(kubelet, "+k3s") || strings.HasPrefix(provider, "k3s://") || labels["node.kubernetes.io/instance-type"] == "k3s":
			k3s = true
		}
	}
	switch {
	case eks:
		return PlatformEKS
	case aks:
		return PlatformAKS
	case rke2:
		return PlatformRKE2
	case k3s:
		return PlatformK3s
	}
	return PlatformKubernetes
}
