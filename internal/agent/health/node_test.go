package health

import (
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// node builds a node from "Type=Status" conditions, cordoned if asked.
func node(cordoned bool, conds ...string) *corev1.Node {
	n := &corev1.Node{Spec: corev1.NodeSpec{Unschedulable: cordoned}}
	n.Status.NodeInfo.KubeletVersion = "v1.31.4+rke2r1"
	for _, c := range conds {
		typ, status, _ := strings.Cut(c, "=")
		n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
			Type: corev1.NodeConditionType(typ), Status: corev1.ConditionStatus(status), Message: "kubelet: " + status,
		})
	}
	return n
}

func TestNodeHealth(t *testing.T) {
	h := Node(node(true, "DiskPressure=True", "Ready=True", "MemoryPressure=True", "PIDPressure=False"))
	if !h.Ready || !h.ReadyKnown || !h.Unschedulable || h.Version != "v1.31.4+rke2r1" || !slices.Equal(h.Pressures, []string{"MemoryPressure", "DiskPressure"}) {
		t.Errorf("health = %+v", h)
	}
	if h := Node(node(false, "Ready=False")); h.Ready || !h.ReadyKnown || h.Reason != "kubelet: False" {
		t.Errorf("not ready = %+v", h)
	}
	// No Ready condition: the kubelet never reported.
	if h := Node(node(false)); h.ReadyKnown {
		t.Errorf("unreported = %+v", h)
	}
}

func TestNodeVerdict(t *testing.T) {
	for _, c := range []struct {
		why    string
		node   *corev1.Node
		level  Level
		reason string
	}{
		{"never reported", node(false), LevelUnknown, ""},
		{"ready", node(false, "Ready=True"), LevelHealthy, ""},
		{"ready unknown", node(false, "Ready=Unknown"), LevelUnhealthy, "NotReady"},
		{"cordoned", node(true, "Ready=True"), LevelDegraded, "Cordoned"},
		{"under pressure", node(false, "Ready=True", "PIDPressure=True"), LevelDegraded, "PIDPressure"},
		// Down outranks cordoned; cordoned outranks pressure.
		{"down and cordoned", node(true, "Ready=False"), LevelUnhealthy, "NotReady"},
		{"cordoned under pressure", node(true, "Ready=True", "DiskPressure=True"), LevelDegraded, "Cordoned"},
	} {
		if v := NodeVerdict(c.node); v.Level != c.level || v.Reason != c.reason {
			t.Errorf("%s: %+v", c.why, v)
		}
	}
}
