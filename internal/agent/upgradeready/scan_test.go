package upgradeready

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func ids(r *ScanResults) []string {
	var out []string
	for _, c := range r.Checks {
		out = append(out, c.ID)
	}
	return out
}

func checkIn(t *testing.T, r *ScanResults, id string) Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no %s check in %v", id, ids(r))
	return Check{}
}

func mustScan(t *testing.T, in *Input, from, to string) *ScanResults {
	t.Helper()
	r, err := Scan(in, from, to)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestVersions(t *testing.T) {
	for _, tc := range []struct {
		current, target string
		from, to        string
		err             error
	}{
		{"1.36", "1.37", "1.36", "1.37", nil},
		{"v1.36.4", "", "1.36", "1.37", nil},
		{"1.36.4-gke.1200", "v1.38", "1.36", "1.38", nil},
		{"v1.31.4+rke2r1", " 1.32 ", "1.31", "1.32", nil},
		{"rolling", "1.37", "", "", ErrInvalidCurrentVersion},
		{"0.9", "1.37", "", "", ErrInvalidCurrentVersion},
		{"1.36", "1.37.1", "", "", ErrInvalidTargetVersion},
		{"1.36", "latest", "", "", ErrInvalidTargetVersion},
		{"1.36", "1.99999", "", "", ErrInvalidTargetVersion},
		{"1.36", "1.36", "", "", ErrNonForwardTarget},
		{"1.36", "1.35", "", "", ErrNonForwardTarget},
	} {
		r, err := Scan(nil, tc.current, tc.target)
		switch {
		case tc.err != nil:
			if !errors.Is(err, tc.err) {
				t.Errorf("%q→%q: err %v, want %v", tc.current, tc.target, err, tc.err)
			}
		case err != nil:
			t.Errorf("%q→%q: %v", tc.current, tc.target, err)
		case r.CurrentVersion != tc.from || r.TargetVersion != tc.to || r.ReviewedThrough != ReviewedThrough:
			t.Errorf("%q→%q: %s→%s", tc.current, tc.target, r.CurrentVersion, r.TargetVersion)
		}
	}
}

func TestChecksFollowTheUpgrade(t *testing.T) {
	everyUpgrade := []string{"control-plane-upgrade-path", "deprecated-api-requests", "manifest-api-compatibility", "node-health", "kubelet-version-skew", "kube-proxy-version-skew"}
	closing := []string{"node-drain-feasibility", "admission-webhook-readiness", "crd-conversion-webhook-readiness", "aggregated-apiservice-readiness"}
	at135 := []string{"node-cgroup-v1", "gke-exec-probe-timeout"}
	at136 := []string{"container-runtime-support", "gitrepo-volume-removed", "flexvolume-kubeadm-support", "service-externalips-deprecated", "renamed-control-plane-metrics", "strict-ip-cidr-validation"}
	at137 := []string{"removed-feature-gates", "removed-component-flags", "removed-kubelet-cadvisor-options", "kubelet-event-qps-change", "removed-scheduling-apis", "kubeadm-config-v1beta3", "removed-control-plane-metrics", "selinux-mount-transition"}
	mode := []string{"kube-proxy-mode-transition"}
	for _, tc := range []struct {
		from, to string
		want     [][]string
	}{
		{"1.33", "1.34", [][]string{everyUpgrade, closing}},
		{"1.34", "1.35", [][]string{everyUpgrade, at135, closing}},
		{"1.35", "1.36", [][]string{everyUpgrade, at136, closing}},
		{"1.36", "1.37", [][]string{everyUpgrade, at137, mode, closing}},
		{"1.34", "1.37", [][]string{everyUpgrade, at135, at136, at137, mode, closing}},
		{"1.38", "1.39", [][]string{everyUpgrade, mode, closing}},
		{"1.40", "1.41", [][]string{everyUpgrade, closing}},
	} {
		if got, want := ids(mustScan(t, calm(), tc.from, tc.to)), slices.Concat(tc.want...); !slices.Equal(got, want) {
			t.Errorf("%s→%s:\n got %v\nwant %v", tc.from, tc.to, got, want)
		}
	}
}

func TestVersionSequence(t *testing.T) {
	for _, tc := range []struct {
		from, to string
		detail   string
	}{
		{"1.36", "1.37", ""},
		{"1.34", "1.37", "1.34 → 1.35 → 1.36 → 1.37"},
		{"1.20", "1.37", "1.20 → 1.21 → 1.22 → 1.23 → 1.24 → 1.25 → 1.26 → 1.27 → … → 1.37"},
		{"1.36", "2.0", "1.36 → 2.0"},
	} {
		c := checkIn(t, mustScan(t, calm(), tc.from, tc.to), "control-plane-upgrade-path")
		switch {
		case tc.detail == "" && c.Status != CheckPassed:
			t.Errorf("%s→%s: %s", tc.from, tc.to, c.Status)
		case tc.detail != "" && (c.Status != CheckBlocked || c.Findings[0].Evidence.Detail != tc.detail):
			t.Errorf("%s→%s: %s %+v", tc.from, tc.to, c.Status, c.Findings)
		}
	}
}

func TestVerdict(t *testing.T) {
	for _, tc := range []struct {
		summary  Summary
		coverage string
		target   string
		want     Verdict
	}{
		{Summary{Blocked: 1, Warnings: 3, Unknown: 2}, "partial", "1.37", VerdictBlocked},
		{Summary{Warnings: 1, Reviews: 4}, "partial", "1.37", VerdictWarning},
		{Summary{Reviews: 1, Unknown: 1}, "partial", "1.37", VerdictReview},
		{Summary{Passed: 9, Unknown: 1}, "complete", "1.37", VerdictUnknown},
		{Summary{Passed: 9}, "partial", "1.37", VerdictUnknown},
		// Beyond what the checks were written for, a clean scan proves nothing.
		{Summary{Passed: 9}, "complete", "1.38", VerdictUnknown},
		{Summary{Passed: 9, NotApplicable: 2}, "complete", "1.37", VerdictNoKnownBlockers},
	} {
		r := &ScanResults{Summary: tc.summary, Coverage: Coverage{State: tc.coverage}}
		if got := verdict(r, release(tc.target)); got != tc.want {
			t.Errorf("%+v %s %s: %s, want %s", tc.summary, tc.coverage, tc.target, got, tc.want)
		}
	}
	// What the agent cannot collect keeps every real scan away from "no
	// known blockers".
	if r := mustScan(t, calm(), "1.36", "1.37"); r.Verdict == VerdictNoKnownBlockers || r.Coverage.State != "partial" {
		t.Errorf("calm cluster: %s, coverage %s", r.Verdict, r.Coverage.State)
	}
}

func TestSummaryAndCoverage(t *testing.T) {
	r := mustScan(t, troubled(), "1.36", "1.37")
	counted := Summary{}
	for _, c := range r.Checks {
		counted.Findings += c.FindingsTotal
		*statusCounter(&counted, c.Status)++
	}
	if counted != r.Summary {
		t.Errorf("summary %+v, recount %+v", r.Summary, counted)
	}
	if r.Verdict != VerdictBlocked {
		t.Errorf("verdict %s", r.Verdict)
	}

	blindScan := mustScan(t, blind(), "1.36", "1.37")
	want := []string{"apiservices", "cronjobs", "customresourcedefinitions", "daemonsets", "deployments", "events", "jobs", "nodes",
		"persistentvolumeclaims", "persistentvolumes", "poddisruptionbudgets", "pods", "replicasets", "services", "statefulsets", "configmaps"}
	slices.Sort(want)
	if !slices.Equal(blindScan.Coverage.UnavailableKinds, want) || blindScan.Coverage.State != "partial" {
		t.Errorf("unavailable %v", blindScan.Coverage.UnavailableKinds)
	}
	if got := mustScan(t, blind(), "1.33", "1.34").Coverage.UnavailableKinds; slices.Contains(got, "events") || slices.Contains(got, "configmaps") {
		t.Errorf("an upgrade that needs neither events nor ConfigMaps lists them: %v", got)
	}
	if got := mustScan(t, partialWebhooks(), "1.36", "1.37").Coverage.UnavailableKinds; !slices.Equal(got, []string{"MutatingWebhookConfiguration"}) {
		t.Errorf("unreadable webhook kinds: %v", got)
	}
}

func TestFindingsCappedButCounted(t *testing.T) {
	in := calm()
	for i := range 64 {
		in.Nodes = append(in.Nodes, node(fmt.Sprintf("edge-%02d", i), "v1.36.2", notReady))
	}
	in.Nodes = append(in.Nodes, node("edge-old", "v1.30.1"))
	c := checkIn(t, mustScan(t, in, "1.36", "1.37"), "node-health")
	if c.FindingsTotal != 64 || len(c.Findings) != MaxFindingsPerCheck || !c.Truncated || len(c.Groups) != 1 || c.Groups[0].Count != 64 {
		t.Fatalf("total %d kept %d truncated %v groups %+v", c.FindingsTotal, len(c.Findings), c.Truncated, c.Groups)
	}
	if c.Findings[0].Resource.Name != "edge-00" || c.Findings[49].Resource.Name != "edge-49" {
		t.Errorf("kept findings are not the first in order: %s … %s", c.Findings[0].Resource.Name, c.Findings[49].Resource.Name)
	}
	if strings.Contains(c.Summary, "50") {
		t.Errorf("summary counts the cut list: %q", c.Summary)
	}
}

func TestFindingsWorstFirst(t *testing.T) {
	c := checkIn(t, mustScan(t, troubled(), "1.36", "1.37"), "node-drain-feasibility")
	var levels []Level
	for _, f := range c.Findings {
		levels = append(levels, f.Level)
	}
	if !slices.IsSortedFunc(levels, func(a, b Level) int { return rankOf(a) - rankOf(b) }) || c.Status != CheckBlocked {
		t.Errorf("levels %v, status %s", levels, c.Status)
	}
}

// The checks built on evidence the agent never holds always say so.
func TestUncollectableEvidence(t *testing.T) {
	r := mustScan(t, calm(), "1.34", "1.37")
	for id, why := range map[string]string{
		"deprecated-api-requests":    "/metrics",
		"manifest-api-compatibility": "Helm release manifests are not collected",
		"strict-ip-cidr-validation":  "release Secret payloads",
		"node-cgroup-v1":             "nodes/proxy",
		"container-runtime-support":  "nodes/proxy",
		"kubelet-event-qps-change":   "nodes/proxy",
		"removed-feature-gates":      "nodes/proxy",
		"removed-scheduling-apis":    "kubectl get",
		"kubeadm-config-v1beta3":     "",
	} {
		c := checkIn(t, r, id)
		if id == "kubeadm-config-v1beta3" {
			continue // not applicable without a kubeadm-config ConfigMap
		}
		if c.Status != CheckUnknown || !strings.Contains(c.Summary+" "+c.Caveat, why) {
			t.Errorf("%s: %s, %q / %q", id, c.Status, c.Summary, c.Caveat)
		}
	}
}
