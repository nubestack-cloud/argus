// Package clustersummary computes the cluster health summary the agent
// reports with its facts: object counts, kubelet version skew across nodes,
// and how many workloads at least one core NetworkPolicy selects. Every
// function is pure over typed objects the caller has already listed, so the
// same code serves the facts refresh and any tool that wants the same figures.
package clustersummary

import (
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// VersionSkew describes the spread of kubelet minor versions across nodes.
// Patch differences are normal during a rolling node upgrade and are not
// skew; only a minor-version difference sets Skewed.
type VersionSkew struct {
	Min    string `json:"min"`
	Max    string `json:"max"`
	Skewed bool   `json:"skewed"`
	// NodesByMinor counts nodes per kubelet minor version. Counts rather than
	// node names keep the summary a fixed size on a large cluster.
	NodesByMinor map[string]int `json:"nodesByMinor"`
	// Unparsed counts nodes whose kubelet version did not carry a
	// major.minor, so a reader can tell the figures above are partial.
	Unparsed int `json:"unparsed,omitempty"`
}

// DetectVersionSkew reports the min and max kubelet minor versions across
// nodes. It returns nil when no node reports a parseable version — the skew
// is then unknown, which is different from "no skew".
//
// Minors are compared numerically: as strings "1.9" sorts after "1.28".
func DetectVersionSkew(nodes []*corev1.Node) *VersionSkew {
	byMinor := make(map[string]int)
	parsed := make(map[string][2]int)
	unparsed := 0
	for _, node := range nodes {
		if node == nil {
			continue
		}
		minor, nums, ok := minorVersion(node.Status.NodeInfo.KubeletVersion)
		if !ok {
			unparsed++
			continue
		}
		byMinor[minor]++
		parsed[minor] = nums
	}
	if len(byMinor) == 0 {
		return nil
	}

	minors := make([]string, 0, len(byMinor))
	for m := range byMinor {
		minors = append(minors, m)
	}
	sort.Slice(minors, func(i, j int) bool {
		a, b := parsed[minors[i]], parsed[minors[j]]
		if a[0] != b[0] {
			return a[0] < b[0]
		}
		return a[1] < b[1]
	})

	return &VersionSkew{
		Min:          minors[0],
		Max:          minors[len(minors)-1],
		Skewed:       len(minors) > 1,
		NodesByMinor: byMinor,
		Unparsed:     unparsed,
	}
}

// minorVersion extracts "1.28" from "v1.28.3", "1.28.3" or
// "v1.28.3+rke2r1", returning the numeric major and minor for ordering.
func minorVersion(version string) (string, [2]int, bool) {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return "", [2]int{}, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return "", [2]int{}, false
	}
	// A minor may carry a suffix when there is no patch ("1.28+k3s1").
	minorDigits := parts[1]
	if i := strings.IndexFunc(minorDigits, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		minorDigits = minorDigits[:i]
	}
	minor, err := strconv.Atoi(minorDigits)
	if err != nil {
		return "", [2]int{}, false
	}
	return strconv.Itoa(major) + "." + strconv.Itoa(minor), [2]int{major, minor}, true
}
