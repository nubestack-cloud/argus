package clustersummary

// Summary is the cluster health summary carried in the agent's facts.
// NodeVersionSkew is nil when no node reported a parseable kubelet version;
// NetworkPolicyCoverage is nil when the caller could not list NetworkPolicies
// or workloads — in both cases the figure is unknown, not zero.
type Summary struct {
	ResourceCounts        ResourceCounts         `json:"resourceCounts"`
	NodeVersionSkew       *VersionSkew           `json:"nodeVersionSkew,omitempty"`
	NetworkPolicyCoverage *NetworkPolicyCoverage `json:"networkPolicyCoverage,omitempty"`
}

// SummaryInput is everything Build needs. Coverage inputs reuse the same
// workload slices as the counts.
type SummaryInput struct {
	Counts CountsInput
	// Coverage is evaluated only when set; leave it nil when NetworkPolicies
	// or any of the workload kinds could not be listed.
	Coverage *CoverageInput
}

// Build assembles a Summary from listed objects.
func Build(in SummaryInput) Summary {
	s := Summary{ResourceCounts: Counts(in.Counts)}
	if !unavailable(in.Counts.Unavailable, KindNodes) {
		s.NodeVersionSkew = DetectVersionSkew(in.Counts.Nodes)
	}
	if in.Coverage != nil {
		s.NetworkPolicyCoverage = ComputeNetworkPolicyCoverage(*in.Coverage)
	}
	return s
}

func unavailable(kinds []string, kind string) bool {
	for _, k := range kinds {
		if k == kind {
			return true
		}
	}
	return false
}
