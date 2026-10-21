package upgradeready

import (
	"cmp"
	"slices"
)

// MaxFindingsPerCheck bounds how many findings one check returns, so a scan
// fits a tool response; the most serious are kept.
const MaxFindingsPerCheck = 50

// scan is one Scan call: the evidence and the two minors.
type scan struct {
	in       *Input
	from, to minor
	owners   *ownership
}

func always(minor, minor) bool { return true }

func after(release string) func(minor, minor) bool {
	return func(from, to minor) bool { return crosses(from, to, release) }
}

// checklist is every check, in the order a result lists them, with the
// upgrades it applies to.
var checklist = []struct {
	applies func(from, to minor) bool
	run     func(*scan) Check
}{
	{always, (*scan).versionSequence},
	{always, (*scan).deprecatedAPIRequests},
	{always, (*scan).manifestAPIVersions},
	{always, (*scan).nodeReadiness},
	{always, (*scan).kubeletSkew},
	{always, (*scan).kubeProxySkew},

	{after("1.35"), (*scan).cgroupV1},
	{after("1.35"), (*scan).gkeExecProbes},

	{after("1.36"), (*scan).runtimeSupport},
	{after("1.36"), (*scan).gitRepoVolumes},
	{after("1.36"), (*scan).flexVolumes},
	{after("1.36"), (*scan).externalIPs},
	{after("1.36"), (*scan).metricRenames136},
	{after("1.36"), (*scan).strictNetworkValidation},

	{after("1.37"), (*scan).featureGates},
	{after("1.37"), (*scan).componentFlags},
	{after("1.37"), (*scan).cadvisorOptions},
	{after("1.37"), (*scan).eventQPS},
	{after("1.37"), (*scan).schedulingAPIs},
	{after("1.37"), (*scan).kubeadmConfig},
	{after("1.37"), (*scan).metricChanges137},
	{after("1.37"), (*scan).selinuxMounts},

	{kubeProxyModeWindow, (*scan).kubeProxyMode},

	{always, (*scan).drainFeasibility},
	{always, (*scan).admissionWebhooks},
	{always, (*scan).conversionWebhooks},
	{always, (*scan).aggregatedAPIs},
}

// Scan checks what the upgrade from currentVersion to targetVersion (the
// next minor when empty) would meet in this evidence.
func Scan(in *Input, currentVersion, targetVersion string) (*ScanResults, error) {
	from, to, err := plan(currentVersion, targetVersion)
	if err != nil {
		return nil, err
	}
	if in == nil {
		in = &Input{}
	}
	s := &scan{in: in, from: from, to: to, owners: ownersOf(in)}
	out := &ScanResults{
		CurrentVersion: label(from), TargetVersion: label(to), ReviewedThrough: ReviewedThrough,
		Checks:   []Check{},
		Coverage: Coverage{Source: "live", State: "complete", UnavailableKinds: s.unreadable()},
	}
	if len(out.Coverage.UnavailableKinds) > 0 {
		out.Coverage.State = "partial"
	}
	for _, c := range checklist {
		if !c.applies(from, to) {
			continue
		}
		check := settle(c.run(s))
		if check.Caveat != "" || check.Status == CheckUnknown {
			out.Coverage.State = "partial"
		}
		out.Summary.Findings += check.FindingsTotal
		*statusCounter(&out.Summary, check.Status)++
		out.Checks = append(out.Checks, check)
	}
	out.Verdict = verdict(out, to)
	return out, nil
}

func statusCounter(s *Summary, status CheckStatus) *int {
	switch status {
	case CheckBlocked:
		return &s.Blocked
	case CheckWarning:
		return &s.Warnings
	case CheckReview:
		return &s.Reviews
	case CheckPassed:
		return &s.Passed
	case CheckNotApplicable:
		return &s.NotApplicable
	}
	return &s.Unknown
}

// verdict is the worst thing found. With nothing found it is "no known
// blockers" only when every check could judge, coverage was complete, and
// the target is one these checks were written for.
func verdict(r *ScanResults, to minor) Verdict {
	s := r.Summary
	switch {
	case s.Blocked > 0:
		return VerdictBlocked
	case s.Warnings > 0:
		return VerdictWarning
	case s.Reviews > 0:
		return VerdictReview
	case s.Unknown > 0 || r.Coverage.State != "complete" || to.GreaterThan(release(ReviewedThrough)):
		return VerdictUnknown
	}
	return VerdictNoKnownBlockers
}

var levelRank = map[Level]int{LevelBlocker: 0, LevelWarning: 1}

func rankOf(l Level) int {
	if r, ok := levelRank[l]; ok {
		return r
	}
	return 2
}

func compareRefs(a, b *ResourceRef) int {
	switch {
	case a == nil || b == nil:
		return cmp.Compare(boolInt(a != nil), boolInt(b != nil))
	}
	return cmp.Or(cmp.Compare(a.Group, b.Group), cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// settle orders a check's findings (most serious, then by object and
// evidence), takes its status from the worst of them, counts and groups
// them all, and cuts the list to MaxFindingsPerCheck.
func settle(c Check) Check {
	if c.Findings == nil {
		c.Findings = []Finding{}
	}
	slices.SortStableFunc(c.Findings, func(a, b Finding) int {
		return cmp.Or(
			cmp.Compare(rankOf(a.Level), rankOf(b.Level)),
			compareRefs(a.Resource, b.Resource),
			cmp.Compare(a.Evidence.Source, b.Evidence.Source), cmp.Compare(a.Evidence.Path, b.Evidence.Path), cmp.Compare(a.Evidence.Detail, b.Evidence.Detail),
			cmp.Compare(a.Title, b.Title), cmp.Compare(a.AppliesFrom, b.AppliesFrom),
			compareRefs(a.ManagedBy, b.ManagedBy),
			cmp.Compare(a.Impact, b.Impact), cmp.Compare(a.Remediation, b.Remediation),
		)
	})
	if len(c.Findings) > 0 {
		switch rankOf(c.Findings[0].Level) {
		case 0:
			c.Status = CheckBlocked
		case 1:
			c.Status = CheckWarning
		default:
			c.Status = CheckReview
		}
	}
	c.FindingsTotal = len(c.Findings)
	c.Groups = nil
	at := map[string]int{}
	for _, f := range c.Findings {
		title := cmp.Or(f.Title, f.RuleID)
		i, seen := at[title]
		if !seen {
			i = len(c.Groups)
			at[title] = i
			c.Groups = append(c.Groups, FindingGroup{Title: title, Impact: f.Impact, Remediation: f.Remediation})
		}
		c.Groups[i].Count++
	}
	if len(c.Findings) > MaxFindingsPerCheck {
		c.Findings, c.Truncated = c.Findings[:MaxFindingsPerCheck], true
	}
	return c
}

type readable struct {
	name string
	read bool
}

// unreadable names the inventories that could not be read, of those this
// upgrade's checks depend on.
func (s *scan) unreadable() []string {
	in := s.in
	need := []readable{
		{"pods", in.Pods != nil}, {"deployments", in.Deployments != nil}, {"replicasets", in.ReplicaSets != nil},
		{"statefulsets", in.StatefulSets != nil}, {"daemonsets", in.DaemonSets != nil}, {"jobs", in.Jobs != nil},
		{"cronjobs", in.CronJobs != nil}, {"services", in.Services != nil}, {"poddisruptionbudgets", in.PodDisruptionBudgets != nil},
		{"persistentvolumes", in.PersistentVolumes != nil}, {"nodes", in.Nodes != nil},
		{"customresourcedefinitions", in.CustomResourceDefinitions != nil}, {"apiservices", in.APIServices != nil},
	}
	if kubeProxyModeWindow(s.from, s.to) {
		need = append(need, readable{"configmaps", in.ConfigMaps != nil})
	}
	if crosses(s.from, s.to, "1.37") {
		need = append(need, readable{"persistentvolumeclaims", in.PersistentVolumeClaims != nil})
	}
	if crosses(s.from, s.to, "1.35") || crosses(s.from, s.to, "1.37") {
		need = append(need, readable{"events", in.Events != nil})
	}
	out := slices.Clone(in.AdmissionWebhookUnavailableKinds)
	for _, n := range need {
		if !n.read {
			out = append(out, n.name)
		}
	}
	slices.Sort(out)
	return out
}
