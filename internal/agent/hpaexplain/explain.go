// Package hpaexplain says, in a sentence, what a HorizontalPodAutoscaler is
// doing and why: whether it can scale, whether its metrics are readable, and
// whether a bound is holding it. It reads only the HPA object — spec, status
// and the three conditions the controller maintains — so it needs no extra
// API calls and works from the agent's cache.
package hpaexplain

import (
	"fmt"
	"strings"

	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
)

// Explanation is the answer for one autoscaler. The JSON shape is what the
// object panel's Autoscaler tab and the investigation tool read.
type Explanation struct {
	// State is one of the State* values.
	State   string    `json:"state"`
	Summary string    `json:"summary"`
	Target  TargetRef `json:"target"`
	Bounds  Replicas  `json:"bounds"`
	Metrics []Metric  `json:"metrics,omitempty"`
	// Reasons are the controller's conditions that explain the state, in
	// plain words first and the controller's own message as Detail.
	Reasons []Reason `json:"reasons,omitempty"`
}

type TargetRef struct {
	Kind string `json:"kind,omitempty"`
	Name string `json:"name,omitempty"`
}

// Replicas are the autoscaler's bounds and where it stands between them.
// Current and Desired are absent until the controller has reported them.
type Replicas struct {
	Min     int32  `json:"min"`
	Max     int32  `json:"max"`
	Current *int32 `json:"current,omitempty"`
	Desired *int32 `json:"desired,omitempty"`
}

// Metric is one configured metric with what the controller last measured.
type Metric struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Current string `json:"current,omitempty"`
	Target  string `json:"target,omitempty"`
	// Status compares current with target: "above target", "at target",
	// "below target", or "not reported" when the controller has no value.
	Status string `json:"status"`
}

type Reason struct {
	ID      string `json:"id"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

// The states the UI names (web/src/insight/tabs/AnalysisTabs.tsx).
const (
	StateOK                 = "ok"
	StateScalingUp          = "scaling_up"
	StateScalingDown        = "scaling_down"
	StateLimitedMax         = "limited_max"
	StateLimitedMin         = "limited_min"
	StateMetricsUnavailable = "metrics_unavailable"
	StateMetricsIncomplete  = "metrics_incomplete"
	StateUnableToScale      = "unable_to_scale"
	StateScaledToZero       = "scaled_to_zero"
	StateDisabled           = "disabled"
	StatePinned             = "pinned"
	StateStale              = "stale"
	StateStabilized         = "stabilized"
	StateUnknown            = "unknown"
)

// view is the HPA read once into the facts the rules below ask about.
type view struct {
	hpa        *autoscalingv2.HorizontalPodAutoscaler
	bounds     Replicas
	metrics    []Metric
	conditions map[autoscalingv2.HorizontalPodAutoscalerConditionType]autoscalingv2.HorizontalPodAutoscalerCondition
	// reconciled is false when the controller has not yet acted on the
	// current spec, so its status describes an older one.
	reconciled bool
	// seen is false until the controller has written any status at all; an
	// unread metric then means nothing has been measured yet, not a failure.
	seen bool
}

func (v *view) cond(t autoscalingv2.HorizontalPodAutoscalerConditionType) (autoscalingv2.HorizontalPodAutoscalerCondition, bool) {
	c, ok := v.conditions[t]
	return c, ok
}

func (v *view) condIs(t autoscalingv2.HorizontalPodAutoscalerConditionType, status corev1.ConditionStatus) bool {
	c, ok := v.cond(t)
	return ok && c.Status == status
}

func (v *view) reasonIs(t autoscalingv2.HorizontalPodAutoscalerConditionType, reasons ...string) bool {
	c, ok := v.cond(t)
	if !ok {
		return false
	}
	for _, r := range reasons {
		if c.Reason == r {
			return true
		}
	}
	return false
}

func (v *view) reported() (missing, total int) {
	for _, m := range v.metrics {
		total++
		if m.Status == statusNotReported {
			missing++
		}
	}
	return missing, total
}

// rule decides one state when its test holds; rules are tried in order and
// the first that holds wins, so the most fundamental problem is the one named.
type rule struct {
	state   string
	holds   func(*view) bool
	summary func(*view) string
}

var rules = []rule{
	{StateStale, func(v *view) bool { return !v.reconciled },
		func(v *view) string {
			return "The autoscaler's spec changed and the controller has not acted on it yet, so its status describes the previous settings."
		}},
	{StateDisabled, func(v *view) bool {
		return v.condIs(autoscalingv2.ScalingActive, corev1.ConditionFalse) && v.reasonIs(autoscalingv2.ScalingActive, "ScalingDisabled")
	}, func(v *view) string {
		return fmt.Sprintf("Scaling is off: %s was set to zero replicas, and the autoscaler leaves a target at zero alone.", v.targetWords())
	}},
	{StateScaledToZero, func(v *view) bool {
		// Scale-to-zero is only that when every signal agrees; a zero from
		// a stale or half-written status is not.
		return v.bounds.Min == 0 && isZero(v.bounds.Current) && isZero(v.bounds.Desired)
	}, func(v *view) string {
		return fmt.Sprintf("%s is scaled to zero, which this autoscaler's minimum allows.", capitalise(v.targetWords()))
	}},
	{StateUnableToScale, func(v *view) bool { return v.condIs(autoscalingv2.AbleToScale, corev1.ConditionFalse) },
		func(v *view) string {
			return fmt.Sprintf("The autoscaler cannot read or change the replica count of %s.", v.targetWords())
		}},
	{StateMetricsUnavailable, func(v *view) bool {
		missing, total := v.reported()
		return v.condIs(autoscalingv2.ScalingActive, corev1.ConditionFalse) || (v.seen && total > 0 && missing == total)
	}, func(v *view) string {
		return "The autoscaler cannot read its metrics, so it is not changing the replica count."
	}},
	{StateMetricsIncomplete, func(v *view) bool {
		missing, _ := v.reported()
		return v.seen && missing > 0
	}, func(v *view) string {
		missing, total := v.reported()
		return fmt.Sprintf("%d of %d metrics have no current value; the autoscaler decides on the rest.", missing, total)
	}},
	{StatePinned, func(v *view) bool { return v.bounds.Min == v.bounds.Max },
		func(v *view) string {
			return fmt.Sprintf("Minimum and maximum are both %d, so the autoscaler can never change the replica count.", v.bounds.Max)
		}},
	{StateScalingUp, func(v *view) bool { return compare(v.bounds.Desired, v.bounds.Current) > 0 },
		func(v *view) string {
			return fmt.Sprintf("Scaling up from %d to %d replicas.", *v.bounds.Current, *v.bounds.Desired)
		}},
	{StateScalingDown, func(v *view) bool { return compare(v.bounds.Desired, v.bounds.Current) < 0 },
		func(v *view) string {
			return fmt.Sprintf("Scaling down from %d to %d replicas.", *v.bounds.Current, *v.bounds.Desired)
		}},
	{StateLimitedMax, func(v *view) bool { return v.limitedAt("TooManyReplicas", v.bounds.Max) },
		func(v *view) string {
			return fmt.Sprintf("Held at the maximum of %d replicas; the metrics ask for more.", v.bounds.Max)
		}},
	{StateLimitedMin, func(v *view) bool { return v.limitedAt("TooFewReplicas", v.bounds.Min) },
		func(v *view) string {
			return fmt.Sprintf("Held at the minimum of %d replicas; the metrics would allow fewer.", v.bounds.Min)
		}},
	{StateStabilized, func(v *view) bool {
		return v.reasonIs(autoscalingv2.AbleToScale, "ScaleDownStabilized", "ScaleUpStabilized", "BackoffDownscale", "BackoffBoth")
	}, func(v *view) string {
		return "A change was recommended, but the stabilisation window is holding the current replica count for now."
	}},
	{StateOK, func(v *view) bool { return v.bounds.Current != nil && v.bounds.Desired != nil },
		func(v *view) string {
			return fmt.Sprintf("Running %d replicas, within %d–%d; the metrics are where the targets want them.", *v.bounds.Current, v.bounds.Min, v.bounds.Max)
		}},
}

// limitedAt: the controller says it is holding at a bound, and the replica
// count is at that bound now — a condition left over from a previous range
// does not count once the bounds have moved.
func (v *view) limitedAt(reason string, bound int32) bool {
	return v.condIs(autoscalingv2.ScalingLimited, corev1.ConditionTrue) && v.reasonIs(autoscalingv2.ScalingLimited, reason) &&
		v.bounds.Current != nil && *v.bounds.Current == bound
}

func (v *view) targetWords() string {
	r := v.hpa.Spec.ScaleTargetRef
	if r.Name == "" {
		return "the target"
	}
	return fmt.Sprintf("%s %s", r.Kind, r.Name)
}

// Explain reads one autoscaler. A nil HPA gives nil.
func Explain(hpa *autoscalingv2.HorizontalPodAutoscaler) *Explanation {
	if hpa == nil {
		return nil
	}
	v := &view{
		hpa:        hpa,
		conditions: map[autoscalingv2.HorizontalPodAutoscalerConditionType]autoscalingv2.HorizontalPodAutoscalerCondition{},
		reconciled: hpa.Status.ObservedGeneration == nil || *hpa.Status.ObservedGeneration >= hpa.Generation,
	}
	for _, c := range hpa.Status.Conditions {
		v.conditions[c.Type] = c
	}
	v.seen = len(hpa.Status.Conditions) > 0 || hpa.Status.ObservedGeneration != nil || len(hpa.Status.CurrentMetrics) > 0
	v.bounds = Replicas{Min: 1, Max: hpa.Spec.MaxReplicas}
	if hpa.Spec.MinReplicas != nil {
		v.bounds.Min = *hpa.Spec.MinReplicas
	}
	// Until the controller has reconciled the spec, its replica figures
	// belong to the old bounds; showing them against the new ones would
	// read as a breach that is not there.
	if v.reconciled {
		if hpa.Status.CurrentReplicas != 0 || hpa.Status.DesiredReplicas != 0 || len(hpa.Status.Conditions) > 0 {
			cur, des := hpa.Status.CurrentReplicas, hpa.Status.DesiredReplicas
			v.bounds.Current, v.bounds.Desired = &cur, &des
		}
	}
	v.metrics = readMetrics(hpa)

	out := &Explanation{
		Target:  TargetRef{Kind: hpa.Spec.ScaleTargetRef.Kind, Name: hpa.Spec.ScaleTargetRef.Name},
		Bounds:  v.bounds,
		Metrics: v.metrics,
		Reasons: explainConditions(v),
		State:   StateUnknown,
		Summary: "The controller has not reported this autoscaler's state yet.",
	}
	for _, r := range rules {
		if r.holds(v) {
			out.State, out.Summary = r.state, r.summary(v)
			break
		}
	}
	return out
}

// conditionWords puts the controller's reasons into plain words. A reason
// not listed here is still shown, with its own name and message.
var conditionWords = map[string]string{
	"FailedGetScale":                   "The autoscaler cannot read the target's scale subresource.",
	"FailedUpdateScale":                "The autoscaler could not change the target's replica count.",
	"FailedGetResourceMetric":          "CPU or memory usage could not be read; check that metrics-server is running.",
	"FailedGetContainerResourceMetric": "A container's CPU or memory usage could not be read; check metrics-server and the container name.",
	"FailedGetPodsMetric":              "A per-pod custom metric could not be read; check the custom metrics adapter.",
	"FailedGetObjectMetric":            "An object metric could not be read; check the custom metrics adapter.",
	"FailedGetExternalMetric":          "An external metric could not be read; check the external metrics adapter.",
	"InvalidSelector":                  "The target's label selector is invalid or matches pods of more than one autoscaler.",
	"InvalidMetricSourceType":          "A metric has a type the autoscaler does not understand.",
	"ScalingDisabled":                  "The target has zero replicas, so the autoscaler is not scaling it.",
	"TooManyReplicas":                  "The metrics ask for more replicas than the maximum.",
	"TooFewReplicas":                   "The metrics would allow fewer replicas than the minimum.",
	"ScaleUpLimit":                     "A scale-up policy limits how fast replicas are added.",
	"ScaleDownLimit":                   "A scale-down policy limits how fast replicas are removed.",
	"ScaleDownStabilized":              "Scale-down is waiting out its stabilisation window.",
	"ScaleUpStabilized":                "Scale-up is waiting out its stabilisation window.",
	"BackoffDownscale":                 "A recent scale-up is holding off scale-down.",
	"BackoffBoth":                      "A recent change is holding off any further change.",
}

// explainConditions lists the conditions that say something is wrong or
// holding: False where True is healthy, and ScalingLimited when True.
func explainConditions(v *view) []Reason {
	var out []Reason
	for _, t := range []autoscalingv2.HorizontalPodAutoscalerConditionType{autoscalingv2.AbleToScale, autoscalingv2.ScalingActive, autoscalingv2.ScalingLimited} {
		c, ok := v.cond(t)
		if !ok {
			continue
		}
		notable := c.Status == corev1.ConditionFalse
		if t == autoscalingv2.ScalingLimited {
			notable = c.Status == corev1.ConditionTrue
		}
		if t == autoscalingv2.AbleToScale && c.Status == corev1.ConditionTrue && conditionWords[c.Reason] != "" {
			notable = true // stabilisation and back-off are True but holding
		}
		if !notable {
			continue
		}
		msg := conditionWords[c.Reason]
		if msg == "" {
			msg = fmt.Sprintf("%s is %s (%s).", t, strings.ToLower(string(c.Status)), c.Reason)
		}
		out = append(out, Reason{ID: c.Reason, Message: msg, Detail: c.Message})
	}
	return out
}

func compare(a, b *int32) int {
	if a == nil || b == nil {
		return 0
	}
	switch {
	case *a > *b:
		return 1
	case *a < *b:
		return -1
	}
	return 0
}

func isZero(p *int32) bool { return p != nil && *p == 0 }

func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
