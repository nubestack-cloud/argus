package hpaexplain

import (
	"strings"
	"testing"

	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func i32(v int32) *int32 { return &v }
func i64(v int64) *int64 { return &v }

// hpa builds an autoscaler for web (min 2, max 10, cpu at 70%) and lets each
// case change only what it is about.
func hpa(edit ...func(*autoscalingv2.HorizontalPodAutoscaler)) *autoscalingv2.HorizontalPodAutoscaler {
	h := &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "shop", Generation: 4},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{Kind: "Deployment", Name: "web"},
			MinReplicas:    i32(2), MaxReplicas: 10,
			Metrics: []autoscalingv2.MetricSpec{cpuSpec(70)},
		},
		Status: autoscalingv2.HorizontalPodAutoscalerStatus{
			ObservedGeneration: i64(4), CurrentReplicas: 3, DesiredReplicas: 3,
			CurrentMetrics: []autoscalingv2.MetricStatus{cpuStatus(65)},
			Conditions: []autoscalingv2.HorizontalPodAutoscalerCondition{
				cond(autoscalingv2.AbleToScale, corev1.ConditionTrue, "ReadyForNewScale"),
				cond(autoscalingv2.ScalingActive, corev1.ConditionTrue, "ValidMetricFound"),
				cond(autoscalingv2.ScalingLimited, corev1.ConditionFalse, "DesiredWithinRange"),
			},
		},
	}
	for _, e := range edit {
		e(h)
	}
	return h
}

func cpuSpec(pct int32) autoscalingv2.MetricSpec {
	return autoscalingv2.MetricSpec{Type: autoscalingv2.ResourceMetricSourceType, Resource: &autoscalingv2.ResourceMetricSource{
		Name: corev1.ResourceCPU, Target: autoscalingv2.MetricTarget{Type: autoscalingv2.UtilizationMetricType, AverageUtilization: i32(pct)}}}
}

func cpuStatus(pct int32) autoscalingv2.MetricStatus {
	return autoscalingv2.MetricStatus{Type: autoscalingv2.ResourceMetricSourceType, Resource: &autoscalingv2.ResourceMetricStatus{
		Name: corev1.ResourceCPU, Current: autoscalingv2.MetricValueStatus{AverageUtilization: i32(pct)}}}
}

func cond(t autoscalingv2.HorizontalPodAutoscalerConditionType, s corev1.ConditionStatus, reason string) autoscalingv2.HorizontalPodAutoscalerCondition {
	return autoscalingv2.HorizontalPodAutoscalerCondition{Type: t, Status: s, Reason: reason, Message: "controller says " + reason}
}

func setCond(t autoscalingv2.HorizontalPodAutoscalerConditionType, s corev1.ConditionStatus, reason string) func(*autoscalingv2.HorizontalPodAutoscaler) {
	return func(h *autoscalingv2.HorizontalPodAutoscaler) {
		for i := range h.Status.Conditions {
			if h.Status.Conditions[i].Type == t {
				h.Status.Conditions[i] = cond(t, s, reason)
				return
			}
		}
		h.Status.Conditions = append(h.Status.Conditions, cond(t, s, reason))
	}
}

func replicas(cur, des int32) func(*autoscalingv2.HorizontalPodAutoscaler) {
	return func(h *autoscalingv2.HorizontalPodAutoscaler) {
		h.Status.CurrentReplicas, h.Status.DesiredReplicas = cur, des
	}
}

func TestStates(t *testing.T) {
	cases := []struct {
		name string
		h    *autoscalingv2.HorizontalPodAutoscaler
		want string
	}{
		{"within range and on target", hpa(), StateOK},
		{"metrics ask for more", hpa(replicas(3, 6)), StateScalingUp},
		{"metrics ask for fewer", hpa(replicas(6, 3)), StateScalingDown},
		{"a spec the controller has not seen yet", hpa(func(h *autoscalingv2.HorizontalPodAutoscaler) { h.Generation = 5 }), StateStale},
		{"target set to zero by hand", hpa(replicas(0, 0), setCond(autoscalingv2.ScalingActive, corev1.ConditionFalse, "ScalingDisabled")), StateDisabled},
		{"scale-to-zero allowed and agreed", hpa(replicas(0, 0), func(h *autoscalingv2.HorizontalPodAutoscaler) { h.Spec.MinReplicas = i32(0) }), StateScaledToZero},
		// A zero current with a non-zero desired is waking up, not at zero.
		{"zero current but scaling up", hpa(replicas(0, 2), func(h *autoscalingv2.HorizontalPodAutoscaler) { h.Spec.MinReplicas = i32(0) }), StateScalingUp},
		{"cannot read the scale subresource", hpa(setCond(autoscalingv2.AbleToScale, corev1.ConditionFalse, "FailedGetScale")), StateUnableToScale},
		{"metrics-server down", hpa(setCond(autoscalingv2.ScalingActive, corev1.ConditionFalse, "FailedGetResourceMetric")), StateMetricsUnavailable},
		{"no reading for any metric", hpa(func(h *autoscalingv2.HorizontalPodAutoscaler) { h.Status.CurrentMetrics = nil }), StateMetricsUnavailable},
		{"min equals max", hpa(func(h *autoscalingv2.HorizontalPodAutoscaler) { h.Spec.MinReplicas = i32(10) }, replicas(10, 10)), StatePinned},
		{"held at the maximum", hpa(replicas(10, 10), setCond(autoscalingv2.ScalingLimited, corev1.ConditionTrue, "TooManyReplicas")), StateLimitedMax},
		{"held at the minimum", hpa(replicas(2, 2), setCond(autoscalingv2.ScalingLimited, corev1.ConditionTrue, "TooFewReplicas")), StateLimitedMin},
		// The condition outlived a bounds change: 6 is no longer the maximum.
		{"limit condition from old bounds", hpa(replicas(6, 6), setCond(autoscalingv2.ScalingLimited, corev1.ConditionTrue, "TooManyReplicas")), StateOK},
		{"stabilisation window holding", hpa(setCond(autoscalingv2.AbleToScale, corev1.ConditionTrue, "ScaleDownStabilized")), StateStabilized},
		{"never reconciled", hpa(func(h *autoscalingv2.HorizontalPodAutoscaler) {
			h.Status = autoscalingv2.HorizontalPodAutoscalerStatus{}
		}), StateUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Explain(c.h)
			if got.State != c.want {
				t.Fatalf("state = %s (%s), want %s", got.State, got.Summary, c.want)
			}
			if got.Summary == "" {
				t.Fatal("every state needs a sentence")
			}
		})
	}
}

func TestStaleStatusIsNotShownAgainstNewBounds(t *testing.T) {
	// The max was raised to 20 and not reconciled; the old 10/10 figures
	// would read as "at the maximum" against the old limit.
	h := hpa(replicas(10, 10), func(h *autoscalingv2.HorizontalPodAutoscaler) { h.Generation, h.Spec.MaxReplicas = 5, 20 })
	got := Explain(h)
	if got.State != StateStale || got.Bounds.Current != nil || got.Bounds.Desired != nil || got.Bounds.Max != 20 {
		t.Fatalf("got %+v", got)
	}
}

func TestMetricsPairSpecWithReading(t *testing.T) {
	q := resource.MustParse("150")
	h := hpa(func(h *autoscalingv2.HorizontalPodAutoscaler) {
		h.Spec.Metrics = append(h.Spec.Metrics, autoscalingv2.MetricSpec{Type: autoscalingv2.PodsMetricSourceType, Pods: &autoscalingv2.PodsMetricSource{
			Metric: autoscalingv2.MetricIdentifier{Name: "requests_per_second"},
			Target: autoscalingv2.MetricTarget{Type: autoscalingv2.AverageValueMetricType, AverageValue: &q}}})
		// A reading for a metric no longer configured belongs to an older spec.
		h.Status.CurrentMetrics = append(h.Status.CurrentMetrics, autoscalingv2.MetricStatus{Type: autoscalingv2.ExternalMetricSourceType,
			External: &autoscalingv2.ExternalMetricStatus{Metric: autoscalingv2.MetricIdentifier{Name: "queue_depth"}, Current: autoscalingv2.MetricValueStatus{Value: &q}}})
	})
	got := Explain(h)
	if got.State != StateMetricsIncomplete || len(got.Metrics) != 2 {
		t.Fatalf("got %s with %d metrics", got.State, len(got.Metrics))
	}
	cpu, rps := got.Metrics[0], got.Metrics[1]
	if cpu.Target != "70% of requested cpu" || cpu.Current != "65% of requested cpu" || cpu.Status != statusBelow {
		t.Errorf("cpu = %+v", cpu)
	}
	if rps.Name != "requests_per_second" || rps.Target != "150 average per pod" || rps.Status != statusNotReported || rps.Current != "" {
		t.Errorf("pods metric = %+v", rps)
	}
	if !strings.Contains(got.Summary, "1 of 2") {
		t.Errorf("summary = %q", got.Summary)
	}
}

func TestReasonsArePlainWordsThenTheControllersOwn(t *testing.T) {
	got := Explain(hpa(setCond(autoscalingv2.ScalingActive, corev1.ConditionFalse, "FailedGetResourceMetric")))
	if len(got.Reasons) != 1 {
		t.Fatalf("reasons = %+v", got.Reasons)
	}
	r := got.Reasons[0]
	if r.ID != "FailedGetResourceMetric" || !strings.Contains(r.Message, "metrics-server") || r.Detail != "controller says FailedGetResourceMetric" {
		t.Errorf("reason = %+v", r)
	}
	// A reason the table does not know still appears, named.
	odd := Explain(hpa(setCond(autoscalingv2.AbleToScale, corev1.ConditionFalse, "SomethingNew")))
	if len(odd.Reasons) != 1 || !strings.Contains(odd.Reasons[0].Message, "SomethingNew") {
		t.Errorf("unknown reason = %+v", odd.Reasons)
	}
	// A healthy autoscaler has nothing to explain.
	if r := Explain(hpa()).Reasons; len(r) != 0 {
		t.Errorf("healthy reasons = %+v", r)
	}
}

func TestNil(t *testing.T) {
	if Explain(nil) != nil {
		t.Fatal("nil in, nil out")
	}
}
