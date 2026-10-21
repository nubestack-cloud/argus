package posture

import (
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IgnoreChecksAnnotation lets a team record, on the object itself or on its
// namespace, that a check does not apply to it: a comma-separated list of
// check IDs, or "*" for every check. The finding stays in the result marked
// Excepted, so the exception is visible and reviewable on the Posture tab,
// but it no longer counts as a failure or reaches Signals. It never touches a
// fault: incidents come from the detectors, not from this package.
const IgnoreChecksAnnotation = "argus.io/ignore-checks"

// ObjectKey names one object a finding can be about.
type ObjectKey struct{ Kind, Namespace, Name string }

// IgnoresCheck reports whether an ignore-checks annotation value covers checkID.
func IgnoresCheck(value, checkID string) bool {
	for _, id := range strings.Split(value, ",") {
		id = strings.TrimSpace(id)
		if id == "*" || (id != "" && strings.EqualFold(id, checkID)) {
			return true
		}
	}
	return false
}

// ObjectExceptions collects the ignore-checks annotation from every object
// in the input that carries one.
func ObjectExceptions(in *CheckInput) map[ObjectKey]string {
	out := map[ObjectKey]string{}
	add := func(kind string, m metav1.ObjectMeta) {
		if v := m.Annotations[IgnoreChecksAnnotation]; v != "" {
			out[ObjectKey{kind, m.Namespace, m.Name}] = v
		}
	}
	for _, o := range in.Pods {
		add("Pod", o.ObjectMeta)
	}
	for _, o := range in.Deployments {
		add("Deployment", o.ObjectMeta)
	}
	for _, o := range in.StatefulSets {
		add("StatefulSet", o.ObjectMeta)
	}
	for _, o := range in.DaemonSets {
		add("DaemonSet", o.ObjectMeta)
	}
	for _, o := range in.Jobs {
		add("Job", o.ObjectMeta)
	}
	for _, o := range in.CronJobs {
		add("CronJob", o.ObjectMeta)
	}
	for _, o := range in.Services {
		add("Service", o.ObjectMeta)
	}
	for _, o := range in.Ingresses {
		add("Ingress", o.ObjectMeta)
	}
	for _, o := range in.HorizontalPodAutoscalers {
		add("HorizontalPodAutoscaler", o.ObjectMeta)
	}
	for _, o := range in.PodDisruptionBudgets {
		add("PodDisruptionBudget", o.ObjectMeta)
	}
	for _, o := range in.ConfigMaps {
		add("ConfigMap", o.ObjectMeta)
	}
	for _, o := range in.ServiceAccounts {
		add("ServiceAccount", o.ObjectMeta)
	}
	for _, o := range in.PersistentVolumeClaims {
		add("PersistentVolumeClaim", o.ObjectMeta)
	}
	for _, o := range in.PersistentVolumes {
		add("PersistentVolume", o.ObjectMeta)
	}
	return out
}

// ApplyExceptions marks every finding whose object or namespace carries an
// ignore-checks annotation covering its check as Excepted, and recounts so an
// excepted subject is neither a failure nor a pass: it leaves the evaluated
// denominator too. The input is not modified.
func ApplyExceptions(results *ScanResults, objects map[ObjectKey]string, namespaces map[string]string) *ScanResults {
	if results == nil || (len(objects) == 0 && len(namespaces) == 0) {
		return results
	}
	excepted := func(f Finding) bool {
		return IgnoresCheck(objects[ObjectKey{f.Kind, f.Namespace, f.Name}], f.CheckID) ||
			(f.Namespace != "" && IgnoresCheck(namespaces[f.Namespace], f.CheckID))
	}
	var all []Finding
	nExcepted := 0
	evalByNS := copyEvaluated(results.EvaluatedByNamespace)
	for _, f := range results.Findings {
		if excepted(f) {
			f.Excepted = true
			nExcepted++
			if byNS := evalByNS[f.CheckID]; byNS != nil && byNS[f.Namespace] > 0 {
				byNS[f.Namespace]--
			}
		}
		all = append(all, f)
	}
	if nExcepted == 0 {
		return results
	}
	return recount(results, all, evalByNS)
}

func copyEvaluated(in map[string]map[string]int) map[string]map[string]int {
	if in == nil {
		return nil
	}
	out := make(map[string]map[string]int, len(in))
	for id, byNS := range in {
		c := make(map[string]int, len(byNS))
		for ns, n := range byNS {
			c[ns] = n
		}
		out[id] = c
	}
	return out
}
