package upgradeready

import (
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// metricChange is a metric a release renames or removes. A prefix entry
// covers every metric starting with name.
type metricChange struct {
	name    string
	renamed string // empty: removed outright
	prefix  bool
	cite    []Reference
}

var (
	metricChanges136 = []metricChange{
		{name: "volume_operation_total_errors", renamed: "volume_operation_errors_total", cite: docNotes136},
		{name: "etcd_bookmark_counts", renamed: "etcd_bookmark_total", cite: docNotes136},
	}
	metricChanges137list = []metricChange{
		{name: "resourceclaim_controller_creates_total", renamed: "dynamic_resource_allocation_resourceclaim_creates_total", cite: docDRAMetrics},
		{name: "scheduler_resourceclaim_creates_total", renamed: "dynamic_resource_allocation_resourceclaim_creates_total", cite: docDRAMetrics},
		{name: "resourceclaim_controller_resource_claims", renamed: "dynamic_resource_allocation_resource_claims", cite: docDRAMetrics},
		{name: "container_cpu_load_average_10s", cite: docCAdvisor137},
		{name: "container_cpu_load_d_average_10s", cite: docCAdvisor137},
		{name: "container_tasks_state", cite: docCAdvisor137},
		{name: "container_application_", prefix: true, cite: docCAdvisor137},
	}
)

// metricNames lists the metric-like identifiers in PromQL expressions: the
// maximal runs of letters, digits, '_' and ':'.
func metricNames(exprs []string) []string {
	var out []string
	for _, e := range exprs {
		out = append(out, strings.FieldsFunc(e, func(r rune) bool {
			return !(r == '_' || r == ':' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z')
		})...)
	}
	return out
}

func ruleExpressions(rule *unstructured.Unstructured) []string {
	groups, _, _ := unstructured.NestedSlice(rule.Object, "spec", "groups")
	var out []string
	for _, g := range groups {
		gm, _ := g.(map[string]any)
		rules, _ := gm["rules"].([]any)
		for _, r := range rules {
			if rm, ok := r.(map[string]any); ok {
				if e, ok := rm["expr"].(string); ok {
					out = append(out, e)
				}
			}
		}
	}
	return out
}

// matches lists the metrics a change applies to among names, each once.
func (c metricChange) matches(names []string) []string {
	var out []string
	for _, n := range names {
		hit := n == c.name
		if c.prefix {
			hit = len(n) > len(c.name) && strings.HasPrefix(n, c.name) && !isDigit(n[len(c.name)])
		}
		if hit && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// ruleMetrics runs one release's metric changes over every PrometheusRule.
func (s *scan) ruleMetrics(r *report, version string, changes []metricChange) Check {
	in := s.in
	switch {
	case !in.PrometheusRulesDiscoveryAvailable:
		return r.unknown("API discovery was unavailable, so whether PrometheusRule is installed is unknown.")
	case !in.PrometheusRulesInstalled:
		return r.notApplicable("PrometheusRule is not installed in this cluster.")
	case in.PrometheusRules == nil:
		return r.unknown("PrometheusRule is installed, but its objects could not be read.")
	}
	r.Inspected = len(in.PrometheusRules)
	for _, rule := range in.PrometheusRules {
		if rule == nil {
			continue
		}
		names := metricNames(ruleExpressions(rule))
		at := &ResourceRef{Group: "monitoring.coreos.com", Kind: "PrometheusRule", Namespace: rule.GetNamespace(), Name: rule.GetName()}
		for _, c := range changes {
			for _, m := range c.matches(names) {
				title, impact, fix := m+" removed in "+version,
					"This alert or recording rule stops receiving data: Kubernetes "+version+" no longer exports the metric.",
					"Rework or remove the expression before upgrading; nothing replaces this metric."
				if c.renamed != "" {
					title, impact, fix = m+" renamed in "+version,
						"This alert or recording rule stops receiving data when Kubernetes "+version+" renames the metric.",
						"Use "+c.renamed+" in place of "+m+" in the expression before upgrading."
				}
				f := r.flag(LevelWarning, title, at, live("spec.groups[].rules[].expr", m), impact, fix)
				f.References = refs(c.cite)
			}
		}
	}
	return r.finish(func(n int) string {
		return count(n, "PrometheusRule reference needs", "PrometheusRule references need") + " updating for Kubernetes " + version + "."
	}, "")
}

func (s *scan) metricRenames136() Check {
	r := newReport("renamed-control-plane-metrics", "Observability", "Renamed Kubernetes metrics",
		"Prometheus Operator rule expressions", "No PrometheusRule uses a metric Kubernetes 1.36 renames.").since("1.36").citing(docNotes136)
	return s.ruleMetrics(r, "1.36", metricChanges136)
}

func (s *scan) metricChanges137() Check {
	r := newReport("removed-control-plane-metrics", "Observability", "Kubernetes metric changes in Kubernetes 1.37",
		"Prometheus Operator rule expressions", "No PrometheusRule uses a metric Kubernetes 1.37 renames or removes.").since("1.37").citing(docNotes137)
	return s.ruleMetrics(r, "1.37", metricChanges137list)
}
