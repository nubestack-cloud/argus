package api

import (
	"strings"
	"testing"
)

// The live defect: a one-off scan for 1.99 was accepted and stored, and its
// verdict replaced the cluster's "next upgrade" everywhere. The target is now
// validated against the cluster's own version and the catalogue's reviewed
// range before anything is sent to the agent.
func TestValidateScanTarget(t *testing.T) {
	cases := []struct {
		name, target, current, reviewed string
		wantErr                         string // substring; "" means accepted
	}{
		{"next minor", "1.34", "v1.33.5+rke2r1", "1.37", ""},
		{"multi-minor jump inside the reviewed range is allowed", "1.36", "v1.33.5+rke2r1", "1.37", ""},
		{"top of the reviewed range", "1.37", "v1.33.5", "1.37", ""},
		{"beyond the reviewed range", "1.99", "v1.33.5+rke2r1", "1.37", "reviewed through Kubernetes 1.37"},
		{"beyond names the usable range", "1.99", "v1.33.5+rke2r1", "1.37", "choose 1.34 to 1.37"},
		{"same minor", "1.33", "v1.33.5", "1.37", "is not newer than this cluster's Kubernetes 1.33"},
		{"older minor", "1.30", "v1.33.5", "1.37", "starting at 1.34"},
		{"next minor past the catalogue is still allowed", "1.38", "v1.37.1", "1.37", ""},
		{"two past the catalogue from its edge", "1.39", "v1.37.1", "1.37", "choose only 1.38, the next minor"},
		{"unknown current: reviewed range still applies", "1.99", "", "1.37", "reviewed through Kubernetes 1.37"},
		{"unknown current: in range accepted", "1.35", "", "1.37", ""},
		{"garbage", "latest", "v1.33.5", "1.37", "must look like"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validateScanTarget(tc.target, tc.current, tc.reviewed)
			if tc.wantErr == "" {
				if got != "" {
					t.Fatalf("want accepted, got %q", got)
				}
				return
			}
			if !strings.Contains(got, tc.wantErr) {
				t.Fatalf("want an error containing %q, got %q", tc.wantErr, got)
			}
		})
	}
}
