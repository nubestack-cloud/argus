package topology

import (
	"strings"
	"time"

	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"argus/internal/agent/health"
)

// levelToStatus maps a health level to a node status: the same word, with
// anything the health package might add later read as unknown rather than
// passed through unvetted.
func levelToStatus(l health.Level) HealthStatus {
	switch s := HealthStatus(l); s {
	case StatusHealthy, StatusDegraded, StatusUnhealthy, StatusNeutral:
		return s
	}
	return StatusUnknown
}

// verdictStatus is levelToStatus plus the verdict's reason token.
func verdictStatus(v health.Verdict) (HealthStatus, string) {
	return levelToStatus(v.Level), v.Reason
}

// workloadStatus grades a typed workload/batch/PVC object.
func workloadStatus(obj any, now time.Time) (HealthStatus, string) {
	return verdictStatus(health.Workload(obj, now))
}

// podStatus is the one-status-per-pod display grade: health.PodDisplayLevel,
// which folds unschedulable and stuck-terminating in as a floor. The reason is
// the classifier's own when it has one, else the folded signal that raised it.
func podStatus(pod *corev1.Pod, now time.Time) (HealthStatus, string) {
	v := health.Pod(pod, now)
	level := health.PodDisplayLevel(pod, now)
	reason := v.Reason
	if level != v.Level || reason == "" {
		switch {
		case health.IsStuckTerminating(pod, now):
			reason = "StuckTerminating"
		case health.IsPodUnschedulable(pod):
			reason = corev1.PodReasonUnschedulable
		}
	}
	return levelToStatus(level), reason
}

// podSummaryStatus buckets a pod into the PodGroup counters. A neutral
// (completed) pod counts as healthy — it is emphatically not unhealthy — while
// an unknown pod joins the unhealthy bucket, since a pod that cannot be
// classified is worth surfacing in a rollup.
func podSummaryStatus(pod *corev1.Pod, now time.Time) HealthStatus {
	switch health.PodDisplayLevel(pod, now) {
	case health.LevelDegraded:
		return StatusDegraded
	case health.LevelUnhealthy, health.LevelUnknown:
		return StatusUnhealthy
	default:
		return StatusHealthy
	}
}

// nodeStatus grades a cluster Node.
func nodeStatus(node *corev1.Node) (HealthStatus, string) {
	return verdictStatus(health.NodeVerdict(node))
}

// hpaStatus grades an HPA from its conditions, downgrading only on negative
// evidence: routine scaling is not a problem. Precedence, worst first:
//
//	no conditions              → unknown   (controller has never reconciled it)
//	AbleToScale=False          → unhealthy (UnableToScale)
//	ScalingActive=False        → unhealthy (MetricsUnavailable), or neutral
//	                             (ScalingDisabled) when the target is at zero
//	ScalingLimited at maximum  → degraded  (LimitedMax)
//	scaled to zero / pinned /
//	stabilized / at minimum    → neutral   (intentional)
//	stale status               → unknown
//	otherwise                  → healthy
func hpaStatus(hpa *autoscalingv2.HorizontalPodAutoscaler) (HealthStatus, string) {
	if hpa == nil || len(hpa.Status.Conditions) == 0 {
		return StatusUnknown, ""
	}
	minReplicas := int32(1)
	if hpa.Spec.MinReplicas != nil {
		minReplicas = *hpa.Spec.MinReplicas
	}
	observed := int64(0)
	if hpa.Status.ObservedGeneration != nil {
		observed = *hpa.Status.ObservedGeneration
	}
	stale := hpa.Generation > 0 && observed > 0 && observed < hpa.Generation
	pinned := hpa.Spec.MaxReplicas > 0 && minReplicas == hpa.Spec.MaxReplicas

	conds := make(map[autoscalingv2.HorizontalPodAutoscalerConditionType]autoscalingv2.HorizontalPodAutoscalerCondition, len(hpa.Status.Conditions))
	for _, c := range hpa.Status.Conditions {
		conds[c.Type] = c
	}

	if c, ok := conds[autoscalingv2.AbleToScale]; ok && c.Status == corev1.ConditionFalse {
		return StatusUnhealthy, "UnableToScale"
	}
	scalingDisabled := false
	if c, ok := conds[autoscalingv2.ScalingActive]; ok && c.Status == corev1.ConditionFalse {
		if strings.EqualFold(c.Reason, "ScalingDisabled") || strings.Contains(strings.ToLower(c.Message), "scaling is disabled") {
			scalingDisabled = true
		} else {
			return StatusUnhealthy, "MetricsUnavailable"
		}
	}
	limited := ""
	if c, ok := conds[autoscalingv2.ScalingLimited]; ok && c.Status == corev1.ConditionTrue && !stale {
		reason, message := strings.ToLower(c.Reason), strings.ToLower(c.Message)
		switch {
		case pinned && (strings.Contains(reason, "toomany") || strings.Contains(reason, "toofew") ||
			strings.Contains(message, "maximum") || strings.Contains(message, "minimum")):
			limited = "Pinned"
		case strings.Contains(reason, "toomany") || strings.Contains(message, "maximum"):
			return StatusDegraded, "LimitedMax"
		case strings.Contains(reason, "toofew") || strings.Contains(message, "minimum"):
			limited = "LimitedMin"
		case strings.Contains(reason, "stabiliz") || strings.Contains(message, "stabiliz"):
			limited = "Stabilized"
		}
	}
	if c, ok := conds[autoscalingv2.ScaledToZero]; ok && c.Status == corev1.ConditionTrue && minReplicas == 0 && hpa.Status.DesiredReplicas == 0 {
		return StatusNeutral, "ScaledToZero"
	}
	if scalingDisabled {
		return StatusNeutral, "ScalingDisabled"
	}
	if limited != "" {
		return StatusNeutral, limited
	}
	if pinned && hpa.Status.CurrentReplicas == hpa.Status.DesiredReplicas && hpa.Status.DesiredReplicas == hpa.Spec.MaxReplicas {
		return StatusNeutral, "Pinned"
	}
	if stale {
		return StatusUnknown, "StaleStatus"
	}
	return StatusHealthy, ""
}

// pdbStatus is degraded when the budget currently allows no disruption
// because the selected pods are below their desired healthy count.
func pdbStatus(disruptionsAllowed, currentHealthy, desiredHealthy int32) (HealthStatus, string) {
	if disruptionsAllowed == 0 && currentHealthy < desiredHealthy {
		return StatusDegraded, "InsufficientHealthy"
	}
	return StatusHealthy, ""
}

// gatewayStatus grades a Gateway from its Programmed / Accepted conditions.
func gatewayStatus(gw *unstructured.Unstructured) (HealthStatus, string) {
	conditions, _, _ := unstructured.NestedSlice(gw.Object, "status", "conditions")
	programmed, accepted := false, false
	for _, c := range conditions {
		m, ok := c.(map[string]any)
		if !ok {
			continue
		}
		t, _ := m["type"].(string)
		s, _ := m["status"].(string)
		if t == "Programmed" && s == "True" {
			programmed = true
		}
		if t == "Accepted" && s == "True" {
			accepted = true
		}
	}
	switch {
	case programmed:
		return StatusHealthy, ""
	case accepted:
		return StatusDegraded, "NotProgrammed"
	case len(conditions) > 0:
		return StatusUnhealthy, "NotAccepted"
	}
	return StatusUnknown, ""
}

// routeStatus grades a Gateway API route from status.parents[].conditions.
// Conditions observed against an older generation are ignored, and a parent
// with no current Accepted/ResolvedRefs condition counts as unassessed rather
// than letting the parents that did report speak for it. Accepted alone does
// not make a route healthy: an unresolved backendRef is the failure an operator
// opens the graph to find.
func routeStatus(route *unstructured.Unstructured) (HealthStatus, string) {
	parents, _, _ := unstructured.NestedSlice(route.Object, "status", "parents")
	if len(parents) == 0 {
		return StatusUnknown, ""
	}
	generation := route.GetGeneration()

	reporting, accepted, notAccepted, resolved, unresolved, unassessed := 0, 0, 0, 0, 0, 0
	for _, p := range parents {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		var acceptedStatus, resolvedStatus string
		conditions, _, _ := unstructured.NestedSlice(pm, "conditions")
		for _, c := range conditions {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			if og, found, err := unstructured.NestedInt64(cm, "observedGeneration"); found && err == nil && generation != 0 && og != generation {
				continue
			}
			switch cm["type"] {
			case "Accepted":
				acceptedStatus, _ = cm["status"].(string)
			case "ResolvedRefs":
				resolvedStatus, _ = cm["status"].(string)
			}
		}
		if acceptedStatus == "" && resolvedStatus == "" {
			unassessed++
			continue
		}
		reporting++
		switch acceptedStatus {
		case "True":
			accepted++
		case "False":
			notAccepted++
		}
		switch resolvedStatus {
		case "True":
			resolved++
		case "False":
			unresolved++
		}
	}

	if reporting == 0 {
		return StatusUnknown, ""
	}
	if notAccepted == reporting && unassessed == 0 {
		return StatusUnhealthy, "NotAccepted"
	}
	if notAccepted > 0 {
		return StatusDegraded, "NotAccepted"
	}
	if unresolved > 0 {
		return StatusDegraded, "UnresolvedRefs"
	}
	if accepted == reporting && resolved == reporting && unassessed == 0 {
		return StatusHealthy, ""
	}
	return StatusDegraded, "PendingParents"
}
