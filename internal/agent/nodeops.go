package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"argus/internal/remediation"
)

// cordon_node and drain_node execute remediation.ActionCordonNode and
// ActionDrainNode (PROJECT.md PG15) under the remediate identity, with the
// RBAC the chart grants only when remediate.nodeOps.enabled is set.

func (e *ToolExecutor) cordonNode(ctx context.Context, rawArgs json.RawMessage) (json.RawMessage, bool, error) {
	plan, gvr, err := e.verifySignedPlan(rawArgs, remediation.ActionCordonNode)
	if err != nil {
		return nil, false, err
	}
	if err := remediation.NodeActionPermitted(remediation.ActionCordonNode, plan.TargetGVK); err != nil {
		return nil, false, err
	}
	var params remediation.CordonNodeParams
	if err := json.Unmarshal(plan.Params, &params); err != nil {
		return nil, false, fmt.Errorf("invalid cordon params: %w", err)
	}
	patch, err := cordonPatch(plan.ResourceVersion, params.Unschedulable)
	if err != nil {
		return nil, false, err
	}
	opts := metav1.PatchOptions{}
	if plan.DryRun {
		opts.DryRun = []string{metav1.DryRunAll}
	}
	patched, err := e.dynamic.Resource(gvr).Patch(ctx, plan.TargetName, types.StrategicMergePatchType, patch, opts)
	if err != nil {
		return nil, false, sanitizeK8sErr(err)
	}
	return planPatchResult(plan, patched, patch), false, nil
}

// cordonPatch sets spec.unschedulable with the resourceVersion precondition
// inside the same request (SR-20). unschedulable=false is sent as an explicit
// false, which the API server stores by dropping the field.
func cordonPatch(rv string, unschedulable bool) ([]byte, error) {
	return json.Marshal(map[string]any{
		"metadata": map[string]any{"resourceVersion": rv},
		"spec":     map[string]any{"unschedulable": unschedulable},
	})
}

type drainOutcome struct {
	ResourceVersion string         `json:"resourceVersion"`
	DryRun          bool           `json:"dryRun,omitempty"`
	Evicted         []string       `json:"evicted"`
	Blocked         []drainRefusal `json:"blocked,omitempty"`
	Skipped         []string       `json:"skipped,omitempty"`
}

type drainRefusal struct {
	Pod    string `json:"pod"`
	Reason string `json:"reason"`
}

// drainBlockers returns why a drain must not start: a pod with no controller
// (it would not come back) or, without permission, emptyDir data. Pure, so
// the refusal can be tested without a cluster.
func drainBlockers(pods []corev1.Pod, deleteEmptyDir bool) []string {
	var out []string
	for i := range pods {
		p := &pods[i]
		if skipOnDrain(p) {
			continue
		}
		id := p.Namespace + "/" + p.Name
		if metav1.GetControllerOf(p) == nil {
			out = append(out, id+" has no controller and would not be recreated")
			continue
		}
		if !deleteEmptyDir && len(emptyDirs(p)) > 0 {
			out = append(out, id+" has emptyDir data ("+strings.Join(emptyDirs(p), ", ")+") that the drain would lose")
		}
	}
	sort.Strings(out)
	return out
}

// skipOnDrain: DaemonSet pods (their controller ignores cordons and would
// put them straight back), static pods (owned by the kubelet, not the API),
// and pods that have already finished.
func skipOnDrain(p *corev1.Pod) bool {
	if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
		return true
	}
	if _, mirror := p.Annotations[corev1.MirrorPodAnnotationKey]; mirror {
		return true
	}
	ref := metav1.GetControllerOf(p)
	return ref != nil && ref.Kind == "DaemonSet"
}

func (e *ToolExecutor) drainNode(ctx context.Context, rawArgs json.RawMessage) (json.RawMessage, bool, error) {
	plan, gvr, err := e.verifySignedPlan(rawArgs, remediation.ActionDrainNode)
	if err != nil {
		return nil, false, err
	}
	if err := remediation.NodeActionPermitted(remediation.ActionDrainNode, plan.TargetGVK); err != nil {
		return nil, false, err
	}
	var params remediation.DrainNodeParams
	if err := json.Unmarshal(plan.Params, &params); err != nil {
		return nil, false, fmt.Errorf("invalid drain params: %w", err)
	}
	pods, err := e.typed.CoreV1().Pods("").List(ctx, metav1.ListOptions{FieldSelector: "spec.nodeName=" + plan.TargetName})
	if err != nil {
		return nil, false, sanitizeK8sErr(err)
	}
	// Refuse before anything changes: nothing is cordoned, nothing evicted.
	if blockers := drainBlockers(pods.Items, params.DeleteEmptyDirData); len(blockers) > 0 {
		return nil, false, errors.New("drain refused before starting: " + strings.Join(blockers, "; "))
	}

	patch, err := cordonPatch(plan.ResourceVersion, true)
	if err != nil {
		return nil, false, err
	}
	opts := metav1.PatchOptions{}
	var dryRun []string
	if plan.DryRun {
		dryRun = []string{metav1.DryRunAll}
		opts.DryRun = dryRun
	}
	patched, err := e.dynamic.Resource(gvr).Patch(ctx, plan.TargetName, types.StrategicMergePatchType, patch, opts)
	if err != nil {
		return nil, false, sanitizeK8sErr(err)
	}

	out := drainOutcome{ResourceVersion: patched.GetResourceVersion(), DryRun: plan.DryRun, Evicted: []string{}}
	for i := range pods.Items {
		p := &pods.Items[i]
		id := p.Namespace + "/" + p.Name
		if skipOnDrain(p) {
			out.Skipped = append(out.Skipped, id)
			continue
		}
		ev := &policyv1.Eviction{
			ObjectMeta:    metav1.ObjectMeta{Name: p.Name, Namespace: p.Namespace},
			DeleteOptions: &metav1.DeleteOptions{DryRun: dryRun, Preconditions: &metav1.Preconditions{UID: &p.UID}},
		}
		err := e.typed.PolicyV1().Evictions(p.Namespace).Evict(ctx, ev)
		switch {
		case err == nil, apierrors.IsNotFound(err):
			out.Evicted = append(out.Evicted, id)
		case apierrors.IsTooManyRequests(err):
			// The eviction API's own answer when a disruption budget would be
			// broken: kept, and reported, never forced.
			out.Blocked = append(out.Blocked, drainRefusal{Pod: id, Reason: sanitizeK8sErr(err).Error()})
		default:
			out.Blocked = append(out.Blocked, drainRefusal{Pod: id, Reason: sanitizeK8sErr(err).Error()})
		}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, false, err
	}
	return b, false, nil
}
