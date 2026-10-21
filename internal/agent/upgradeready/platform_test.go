package upgradeready

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func platformNode(provider, kubelet string, labels map[string]string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "n", Labels: labels},
		Spec:       corev1.NodeSpec{ProviderID: provider},
		Status:     corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{KubeletVersion: kubelet}},
	}
}

func TestDetectPlatform(t *testing.T) {
	// The rke2 and lab-dev nodes as observed live.
	rke2 := platformNode("rke2://my-rke2-cluster-control-1", "v1.35.5+rke2r2",
		map[string]string{"node.kubernetes.io/instance-type": "rke2", "beta.kubernetes.io/instance-type": "rke2"})
	for _, tc := range []struct {
		name     string
		nodes    []*corev1.Node
		readable bool
		want     string
	}{
		{"rke2 from provider, kubelet suffix and instance-type", []*corev1.Node{rke2}, true, PlatformRKE2},
		{"rke2 from kubelet suffix alone", []*corev1.Node{platformNode("", "v1.34.10+rke2r1", nil)}, true, PlatformRKE2},
		{"gke from provider ID", []*corev1.Node{platformNode("gce://proj/europe-west2-a/gke-pool-1", "v1.35.1-gke.100", nil)}, true, PlatformGKE},
		{"gke from node-pool label", []*corev1.Node{platformNode("", "v1.35.1", map[string]string{"cloud.google.com/gke-nodepool": "default-pool"})}, true, PlatformGKE},
		{"eks", []*corev1.Node{platformNode("aws:///eu-west-2a/i-0abc", "v1.35.0-eks-1", map[string]string{"eks.amazonaws.com/nodegroup": "ng"})}, true, PlatformEKS},
		{"aks", []*corev1.Node{platformNode("azure:///subscriptions/x/vm-0", "v1.35.0", map[string]string{"kubernetes.azure.com/cluster": "rg"})}, true, PlatformAKS},
		{"k3s", []*corev1.Node{platformNode("k3s://n", "v1.35.0+k3s1", nil)}, true, PlatformK3s},
		{"plain kubeadm is known not managed", []*corev1.Node{platformNode("", "v1.35.0", nil)}, true, PlatformKubernetes},
		{"unreadable nodes are unknown", nil, false, ""},
	} {
		if got := DetectPlatform(tc.nodes, tc.readable); got != tc.want {
			t.Errorf("%s: DetectPlatform = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The GKE exec-probe check is Not applicable on an RKE2 cluster once the
// platform is detected, and Unknown only when the nodes could not be read.
func TestGKEExecProbeCheckUsesDetectedPlatform(t *testing.T) {
	rke2 := platformNode("rke2://n", "v1.35.5+rke2r2", map[string]string{"node.kubernetes.io/instance-type": "rke2"})
	in := &Input{Nodes: []*corev1.Node{rke2}, Platform: DetectPlatform([]*corev1.Node{rke2}, true)}
	gke := func(in *Input) Check { return (&scan{in: in, owners: ownersOf(in)}).gkeExecProbes() }
	if got := gke(in).Status; got != CheckNotApplicable {
		t.Errorf("rke2: status = %v, want not applicable", got)
	}
	in = &Input{Platform: DetectPlatform(nil, false)}
	if got := gke(in).Status; got != CheckUnknown {
		t.Errorf("unreadable nodes: status = %v, want unknown", got)
	}
}
