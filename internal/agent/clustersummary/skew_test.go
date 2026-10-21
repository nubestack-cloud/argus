package clustersummary

import (
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// fleet makes one node per kubelet version, named n0, n1, ...; "nil" stands
// for a missing node object.
func fleet(versions ...string) []*corev1.Node {
	out := make([]*corev1.Node, len(versions))
	for i, v := range versions {
		if v == "nil" {
			continue
		}
		out[i] = &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("n%d", i)},
			Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{KubeletVersion: v}}}
	}
	return out
}

// Each case reads "min..max", with "skewed" when they differ and "+N" for N
// nodes whose version could not be read; "-" means no answer at all.
func TestDetectVersionSkew(t *testing.T) {
	for want, versions := range map[string][]string{
		"-":                 nil,
		"--":                {"", "not-a-version"},
		"1.30..1.30":        {"v1.30.1", "v1.30.9"}, // patch level is not skew
		"1.29..1.30 skewed": {"v1.30.0", "v1.29.6"},
		"1.8..1.31 skewed":  {"v1.31.2", "v1.8.15"},                     // minors compare as numbers
		"1.29..1.31 skewed": {"v1.31.4+rke2r1", "1.29.3", "v1.30+k3s2"}, // suffixes, no "v"
		"1.31..1.31 +1":     {"v1.31.0", "", "nil"},                     // a nil node is skipped, not counted
	} {
		got := DetectVersionSkew(fleet(versions...))
		var s string
		switch {
		case got == nil && strings.HasPrefix(want, "-"):
			continue
		case got == nil:
			s = "nil"
		default:
			s = got.Min + ".." + got.Max
			if got.Skewed {
				s += " skewed"
			}
			if got.Unparsed > 0 {
				s += fmt.Sprintf(" +%d", got.Unparsed)
			}
		}
		if s != want {
			t.Errorf("%v: %s, want %s", versions, s, want)
		}
	}
}

func TestDetectVersionSkewCountsNodesPerMinor(t *testing.T) {
	got := DetectVersionSkew(fleet("v1.30.2", "v1.31.0", "v1.31.1", "v1.31.5"))
	if fmt.Sprint(got.NodesByMinor) != "map[1.30:1 1.31:3]" {
		t.Fatalf("NodesByMinor = %v", got.NodesByMinor)
	}
}
