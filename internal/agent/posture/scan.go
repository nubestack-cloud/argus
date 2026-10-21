package posture

import (
	"slices"
	"strings"
	"time"
)

// subject is the object a finding is about.
type subject struct{ group, kind, namespace, name string }

// builtinGroups gives the API group of the built-in kinds checks report on;
// a kind not listed is in the core group.
var builtinGroups = map[string]string{
	"Deployment": "apps", "StatefulSet": "apps", "DaemonSet": "apps", "ReplicaSet": "apps",
	"Job": "batch", "CronJob": "batch",
	"HorizontalPodAutoscaler": "autoscaling",
	"Ingress":                 "networking.k8s.io", "NetworkPolicy": "networking.k8s.io",
	"PodDisruptionBudget": "policy",
}

func object(kind, namespace, name string) subject {
	return subject{builtinGroups[kind], kind, namespace, name}
}

// scan carries one RunChecks call: what it has found, which subjects each
// check looked at, and what it could not see.
type scan struct {
	in    *CheckInput
	now   time.Time
	found []Finding
	// looked counts subjects per check per namespace. Every check visits
	// each subject once and counts it once, at the grain findings merge on
	// (a workload, not its containers), so passed = looked - failed.
	looked map[string]map[string]int
	gaps   []string
}

func (s *scan) evaluated(namespace string, checkIDs ...string) {
	for _, id := range checkIDs {
		if s.looked[id] == nil {
			s.looked[id] = map[string]int{}
		}
		s.looked[id][namespace]++
	}
}

func (s *scan) missing(input string) {
	if !slices.Contains(s.gaps, input) {
		s.gaps = append(s.gaps, input)
	}
}

// flag records a failure. The category comes from the catalogue, so a
// finding is always filed where the catalogue lists its check.
func (s *scan) flag(at subject, checkID, severity, message string) {
	s.found = append(s.found, Finding{
		Group: at.group, Kind: at.kind, Namespace: at.namespace, Name: at.name,
		CheckID: checkID, Category: CheckRegistry[checkID].Category,
		Severity: severity, Message: message,
	})
}

// inventories are the kinds whose absence a scan reports. The order is the
// order MissingInputs lists them in.
var inventories = []struct {
	name   string
	listed func(*CheckInput) bool
}{
	{"serviceaccounts", func(in *CheckInput) bool { return in.ServiceAccounts != nil }},
	{"deployments", func(in *CheckInput) bool { return in.Deployments != nil }},
	{"statefulsets", func(in *CheckInput) bool { return in.StatefulSets != nil }},
	{"daemonsets", func(in *CheckInput) bool { return in.DaemonSets != nil }},
	// Jobs and CronJobs carry no checks of their own, but their pod
	// templates reference ConfigMaps, so not having them hides references.
	{"jobs", func(in *CheckInput) bool { return in.Jobs != nil }},
	{"cronjobs", func(in *CheckInput) bool { return in.CronJobs != nil }},
	{"limitranges", func(in *CheckInput) bool { return in.LimitRanges != nil }},
	{"horizontalpodautoscalers", func(in *CheckInput) bool { return in.HorizontalPodAutoscalers != nil }},
	{"poddisruptionbudgets", func(in *CheckInput) bool { return in.PodDisruptionBudgets != nil }},
	{"pods", func(in *CheckInput) bool { return in.Pods != nil }},
	{"replicasets", func(in *CheckInput) bool { return in.ReplicaSets != nil }},
	{"configmaps", func(in *CheckInput) bool { return in.ConfigMaps != nil }},
	{"services", func(in *CheckInput) bool { return in.Services != nil }},
	{"ingresses", func(in *CheckInput) bool { return in.Ingresses != nil }},
	{"persistentvolumeclaims", func(in *CheckInput) bool { return in.PersistentVolumeClaims != nil }},
	{"persistentvolumes", func(in *CheckInput) bool { return in.PersistentVolumes != nil }},
	{"certificates", func(in *CheckInput) bool { return in.Certificates != nil }},
}

func listed(in *CheckInput, name string) bool {
	for _, inv := range inventories {
		if inv.name == name {
			return inv.listed(in)
		}
	}
	return false
}

// phases run in order; a phase runs only when every inventory it needs was
// listed, because a check missing one side of a relationship would call
// everything on the other side dangling. A phase with its own applicability
// test (GitOps, Traefik, Crossplane) makes it inside run.
var phases = []struct {
	needs []string
	run   func(*scan)
}{
	{nil, (*scan).podTemplates},
	// The HorizontalPodAutoscaler list decides which Deployments are out of
	// scope; without it an autoscaled Deployment at one replica would fail.
	{[]string{"horizontalpodautoscalers"}, (*scan).singleReplica},
	{[]string{"deployments"}, (*scan).rolloutRisk},
	{[]string{"poddisruptionbudgets"}, (*scan).disruptionBudgets},
	{nil, (*scan).topologySpread},
	{[]string{"pods", "replicasets"}, (*scan).colocatedReplicas},
	{[]string{"configmaps"}, (*scan).unusedConfigMaps},
	{[]string{"configmaps"}, (*scan).credentialKeys},
	{[]string{"services", "pods"}, (*scan).emptyServices},
	{[]string{"ingresses", "services"}, (*scan).ingressBackends},
	{nil, (*scan).deprecatedAPIs},
	{nil, (*scan).stuckTerminating},
	{nil, (*scan).gitopsCoverage},
	{[]string{"persistentvolumeclaims"}, (*scan).pendingClaims},
	{[]string{"persistentvolumeclaims", "pods"}, (*scan).unusedClaims},
	{[]string{"persistentvolumes"}, (*scan).volumePhases},
	{[]string{"certificates"}, (*scan).certificates},
	{nil, (*scan).traefik},
	{nil, (*scan).crossplane},
}

// RunChecks runs every check over in. It does no I/O; the clock is read once,
// for ages.
func RunChecks(in *CheckInput) *ScanResults {
	if in == nil {
		return &ScanResults{Summary: ScanSummary{Categories: map[string]CategorySummary{}}}
	}
	s := &scan{in: in, now: time.Now(), looked: map[string]map[string]int{}}
	var gaps []string
	for _, inv := range inventories {
		if !inv.listed(in) {
			gaps = append(gaps, inv.name)
		}
	}
	for _, p := range phases {
		if !slices.ContainsFunc(p.needs, func(n string) bool { return !listed(in, n) }) {
			p.run(s)
		}
	}
	findings := mergeFindings(s.found)
	checks := make(map[string]CheckMeta, len(CheckRegistry))
	for id, m := range CheckRegistry {
		checks[id] = m
	}
	out := tally(findings, s.looked)
	out.Findings = findings
	out.Checks = checks
	out.MissingInputs = append(gaps, s.gaps...)
	return out
}

// mergeFindings folds findings for the same check on the same object into
// one, joining their messages, so a workload with three containers missing a
// probe is one failure that names all three.
func mergeFindings(in []Finding) []Finding {
	type key struct {
		at      subject
		checkID string
	}
	var out []Finding
	at := map[key]int{}
	for _, f := range in {
		k := key{subject{f.Group, f.Kind, f.Namespace, f.Name}, f.CheckID}
		if i, ok := at[k]; ok {
			out[i].Message += "; " + f.Message
			continue
		}
		at[k] = len(out)
		out = append(out, f)
	}
	return out
}

// tally builds the summary and per-check counts from findings that count and
// the subjects each check looked at.
func tally(findings []Finding, looked map[string]map[string]int) *ScanResults {
	sum := ScanSummary{Categories: map[string]CategorySummary{}}
	for _, c := range categories {
		sum.Categories[c] = CategorySummary{}
	}
	failed := map[string]int{}
	for _, f := range findings {
		failed[f.CheckID]++
		c := sum.Categories[f.Category]
		switch f.Severity {
		case SeverityDanger:
			c.Danger++
			sum.Danger++
		case SeverityWarning:
			c.Warning++
			sum.Warning++
		}
		sum.Categories[f.Category] = c
	}
	counts := map[string]CheckCount{}
	for id, byNS := range looked {
		n := 0
		for _, v := range byNS {
			n += v
		}
		if n == 0 {
			continue
		}
		// One subject can fail more than once only where a served API
		// version has several deprecated kinds; never let passed go negative.
		passed := max(n-failed[id], 0)
		counts[id] = CheckCount{Evaluated: n, Passed: passed}
		sum.Passing += passed
		if cat := CheckRegistry[id].Category; cat != "" {
			c := sum.Categories[cat]
			c.Passing += passed
			sum.Categories[cat] = c
		}
	}
	return &ScanResults{Summary: sum, CheckCounts: counts, EvaluatedByNamespace: looked}
}

// recount rebuilds a result from a new finding list and evaluation detail,
// keeping its catalogue and missing inputs. Excepted findings stay in the
// list and count nowhere; their subjects are already out of looked.
func recount(r *ScanResults, all []Finding, looked map[string]map[string]int) *ScanResults {
	var counted []Finding
	excepted := 0
	for _, f := range all {
		if f.Excepted {
			excepted++
		} else {
			counted = append(counted, f)
		}
	}
	out := tally(counted, looked)
	out.Summary.Excepted = excepted
	out.Findings = all
	out.Checks = r.Checks
	out.MissingInputs = r.MissingInputs
	return out
}

// DefaultIgnoredNamespaces are skipped unless an operator says otherwise:
// Kubernetes' own namespaces, the agent's, and Rancher's cattle-* ones.
var DefaultIgnoredNamespaces = []string{"kube-system", "kube-public", "kube-node-lease", "argus-system", "cattle-*"}

// namespaceMatcher matches exact names and patterns with one leading or
// trailing "*" ("cattle-*", "*-system").
func namespaceMatcher(patterns []string) func(string) bool {
	return func(ns string) bool {
		for _, p := range patterns {
			switch {
			case strings.HasSuffix(p, "*") && strings.HasPrefix(ns, strings.TrimSuffix(p, "*")):
				return true
			case strings.HasPrefix(p, "*") && strings.HasSuffix(ns, strings.TrimPrefix(p, "*")):
				return true
			case p == ns:
				return true
			}
		}
		return false
	}
}

// ApplySettings drops findings in ignored namespaces and for disabled checks,
// takes the same subjects out of the evaluation counts, and recounts. It
// returns a new result; r may be a cached scan other readers share.
func ApplySettings(r *ScanResults, ignoredNamespaces, disabledChecks []string) *ScanResults {
	if r == nil || len(ignoredNamespaces)+len(disabledChecks) == 0 {
		return r
	}
	ignored := namespaceMatcher(ignoredNamespaces)
	off := func(id string) bool { return slices.Contains(disabledChecks, id) }

	var kept []Finding
	for _, f := range r.Findings {
		if !ignored(f.Namespace) && !off(f.CheckID) {
			kept = append(kept, f)
		}
	}
	var looked map[string]map[string]int
	if r.EvaluatedByNamespace != nil {
		looked = map[string]map[string]int{}
		for id, byNS := range r.EvaluatedByNamespace {
			if off(id) {
				continue
			}
			for ns, n := range byNS {
				if ignored(ns) {
					continue
				}
				if looked[id] == nil {
					looked[id] = map[string]int{}
				}
				looked[id][ns] = n
			}
		}
	}
	return recount(r, kept, looked)
}
