package hpaexplain

import (
	"fmt"

	autoscalingv2 "k8s.io/api/autoscaling/v2"
	"k8s.io/apimachinery/pkg/api/resource"
)

const (
	statusAbove       = "above target"
	statusAt          = "at target"
	statusBelow       = "below target"
	statusNotReported = "not reported"
)

// source is what identifies a metric across spec and status: its kind plus
// the name (and container, or described object) that makes it unique.
type source struct {
	kind autoscalingv2.MetricSourceType
	key  string
}

// readMetrics pairs each configured metric with the controller's latest
// reading of the same metric. A status entry with nothing configured for it
// is ignored: it belongs to an older spec.
func readMetrics(hpa *autoscalingv2.HorizontalPodAutoscaler) []Metric {
	readings := map[source]autoscalingv2.MetricValueStatus{}
	for _, st := range hpa.Status.CurrentMetrics {
		if src, cur, ok := statusReading(st); ok {
			readings[src] = cur
		}
	}
	var out []Metric
	for _, spec := range hpa.Spec.Metrics {
		src, name, target, ok := specTarget(spec)
		if !ok {
			continue
		}
		m := Metric{Type: string(spec.Type), Name: name, Target: describeTarget(target, name), Status: statusNotReported}
		if cur, ok := readings[src]; ok && hasValue(cur) {
			m.Current = describeCurrent(cur, target, name)
			m.Status = judge(cur, target)
		}
		out = append(out, m)
	}
	return out
}

func specTarget(m autoscalingv2.MetricSpec) (source, string, autoscalingv2.MetricTarget, bool) {
	switch m.Type {
	case autoscalingv2.ResourceMetricSourceType:
		if m.Resource == nil {
			break
		}
		n := string(m.Resource.Name)
		return source{m.Type, n}, n, m.Resource.Target, true
	case autoscalingv2.ContainerResourceMetricSourceType:
		if m.ContainerResource == nil {
			break
		}
		n := fmt.Sprintf("%s (container %s)", m.ContainerResource.Name, m.ContainerResource.Container)
		return source{m.Type, string(m.ContainerResource.Name) + "/" + m.ContainerResource.Container}, n, m.ContainerResource.Target, true
	case autoscalingv2.PodsMetricSourceType:
		if m.Pods == nil {
			break
		}
		return source{m.Type, m.Pods.Metric.Name}, m.Pods.Metric.Name, m.Pods.Target, true
	case autoscalingv2.ObjectMetricSourceType:
		if m.Object == nil {
			break
		}
		obj := m.Object.DescribedObject
		return source{m.Type, m.Object.Metric.Name + "@" + obj.Kind + "/" + obj.Name},
			fmt.Sprintf("%s on %s %s", m.Object.Metric.Name, obj.Kind, obj.Name), m.Object.Target, true
	case autoscalingv2.ExternalMetricSourceType:
		if m.External == nil {
			break
		}
		return source{m.Type, m.External.Metric.Name}, m.External.Metric.Name, m.External.Target, true
	}
	return source{}, "", autoscalingv2.MetricTarget{}, false
}

func statusReading(s autoscalingv2.MetricStatus) (source, autoscalingv2.MetricValueStatus, bool) {
	switch s.Type {
	case autoscalingv2.ResourceMetricSourceType:
		if s.Resource != nil {
			return source{s.Type, string(s.Resource.Name)}, s.Resource.Current, true
		}
	case autoscalingv2.ContainerResourceMetricSourceType:
		if s.ContainerResource != nil {
			return source{s.Type, string(s.ContainerResource.Name) + "/" + s.ContainerResource.Container}, s.ContainerResource.Current, true
		}
	case autoscalingv2.PodsMetricSourceType:
		if s.Pods != nil {
			return source{s.Type, s.Pods.Metric.Name}, s.Pods.Current, true
		}
	case autoscalingv2.ObjectMetricSourceType:
		if s.Object != nil {
			obj := s.Object.DescribedObject
			return source{s.Type, s.Object.Metric.Name + "@" + obj.Kind + "/" + obj.Name}, s.Object.Current, true
		}
	case autoscalingv2.ExternalMetricSourceType:
		if s.External != nil {
			return source{s.Type, s.External.Metric.Name}, s.External.Current, true
		}
	}
	return source{}, autoscalingv2.MetricValueStatus{}, false
}

func hasValue(v autoscalingv2.MetricValueStatus) bool {
	return v.AverageUtilization != nil || v.AverageValue != nil || v.Value != nil
}

// describeTarget: "80% of requested cpu", "500m average per pod", "100 total".
func describeTarget(t autoscalingv2.MetricTarget, name string) string {
	switch t.Type {
	case autoscalingv2.UtilizationMetricType:
		if t.AverageUtilization != nil {
			return fmt.Sprintf("%d%% of requested %s", *t.AverageUtilization, name)
		}
	case autoscalingv2.AverageValueMetricType:
		if t.AverageValue != nil {
			return t.AverageValue.String() + " average per pod"
		}
	case autoscalingv2.ValueMetricType:
		if t.Value != nil {
			return t.Value.String() + " total"
		}
	}
	return ""
}

// describeCurrent reads the current value in the same terms as the target,
// so the two columns compare; utilisation also gets the raw average when the
// controller reported one.
func describeCurrent(v autoscalingv2.MetricValueStatus, t autoscalingv2.MetricTarget, name string) string {
	switch t.Type {
	case autoscalingv2.UtilizationMetricType:
		if v.AverageUtilization != nil {
			s := fmt.Sprintf("%d%% of requested %s", *v.AverageUtilization, name)
			if v.AverageValue != nil {
				s += fmt.Sprintf(" (%s average)", v.AverageValue.String())
			}
			return s
		}
	case autoscalingv2.AverageValueMetricType:
		if v.AverageValue != nil {
			return v.AverageValue.String() + " average per pod"
		}
	case autoscalingv2.ValueMetricType:
		if v.Value != nil {
			return v.Value.String() + " total"
		}
	}
	for _, q := range []*resource.Quantity{v.AverageValue, v.Value} {
		if q != nil {
			return q.String()
		}
	}
	if v.AverageUtilization != nil {
		return fmt.Sprintf("%d%%", *v.AverageUtilization)
	}
	return ""
}

// judge compares like with like; a reading in a different form from the
// target cannot be compared, and says so.
func judge(v autoscalingv2.MetricValueStatus, t autoscalingv2.MetricTarget) string {
	var c int
	switch {
	case t.Type == autoscalingv2.UtilizationMetricType && t.AverageUtilization != nil && v.AverageUtilization != nil:
		c = cmpInt(*v.AverageUtilization, *t.AverageUtilization)
	case t.Type == autoscalingv2.AverageValueMetricType && t.AverageValue != nil && v.AverageValue != nil:
		c = v.AverageValue.Cmp(*t.AverageValue)
	case t.Type == autoscalingv2.ValueMetricType && t.Value != nil && v.Value != nil:
		c = v.Value.Cmp(*t.Value)
	default:
		return statusNotReported
	}
	switch {
	case c > 0:
		return statusAbove
	case c < 0:
		return statusBelow
	}
	return statusAt
}

func cmpInt(a, b int32) int {
	switch {
	case a > b:
		return 1
	case a < b:
		return -1
	}
	return 0
}
