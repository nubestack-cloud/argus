package changes

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	apiequality "k8s.io/apimachinery/pkg/api/equality"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// kindDiffFunc compares two snapshots of one object and returns the tracked
// field changes plus summary fragments. Both inputs share one concrete type.
type kindDiffFunc func(oldObj, newObj any) ([]FieldChange, []string)

type kindDiffRegistration struct {
	group string
	diff  kindDiffFunc
}

// diffFunctions is the one list of kinds with an audited differ, each in its
// home API group. ComputeDiff dispatches through it, and Classify and
// KindHasDiffer read it, so what is tracked can never drift from what is
// diffed.
//
// Registering a kind is a promise: an update whose diff comes back empty is
// dropped as status churn, so its differ must surface every field an
// operator would care about. All versions within a group share a differ; a
// kind of the same name from another group (a Volcano Job, an Istio Gateway)
// gets the generic unstructured differ instead.
var diffFunctions = func() map[string]kindDiffRegistration {
	m := map[string]kindDiffRegistration{}
	in := func(group string, kinds map[string]kindDiffFunc) {
		for kind, fn := range kinds {
			m[kind] = kindDiffRegistration{group: group, diff: fn}
		}
	}
	in("", map[string]kindDiffFunc{
		"Pod": diffPod, "Service": diffService, "ConfigMap": diffConfigMap, "Node": diffNode,
		"PersistentVolumeClaim": diffPVC, "ResourceQuota": diffResourceQuota, "LimitRange": diffLimitRange,
	})
	in("apps", map[string]kindDiffFunc{
		"Deployment": diffDeployment, "ReplicaSet": diffReplicaSet, "DaemonSet": diffDaemonSet, "StatefulSet": diffStatefulSet,
	})
	in("batch", map[string]kindDiffFunc{"Job": diffJob})
	in("autoscaling", map[string]kindDiffFunc{"HorizontalPodAutoscaler": diffHPA})
	in("networking.k8s.io", map[string]kindDiffFunc{"Ingress": diffIngress})
	in("admissionregistration.k8s.io", map[string]kindDiffFunc{
		"MutatingWebhookConfiguration":   diffAdmissionWebhookConfiguration,
		"ValidatingWebhookConfiguration": diffAdmissionWebhookConfiguration,
	})
	in("gateway.networking.k8s.io", map[string]kindDiffFunc{
		"Gateway": diffGateway, "GatewayClass": diffGatewayClass, "ReferenceGrant": diffReferenceGrant,
		"HTTPRoute": diffGatewayRoute, "GRPCRoute": diffGatewayRoute, "TCPRoute": diffGatewayRoute, "TLSRoute": diffGatewayRoute,
	})
	in("argoproj.io", map[string]kindDiffFunc{"Application": diffApplication})
	in("kustomize.toolkit.fluxcd.io", map[string]kindDiffFunc{"Kustomization": diffKustomization})
	in("helm.toolkit.fluxcd.io", map[string]kindDiffFunc{"HelmRelease": diffFluxHelmRelease})
	sources := map[string]kindDiffFunc{}
	for _, k := range []string{"GitRepository", "OCIRepository", "HelmRepository"} {
		sources[k] = fluxSourceDiffer(k)
	}
	in("source.toolkit.fluxcd.io", sources)
	return m
}()

// KindHasDiffer reports whether kind has an audited differ (in its home API
// group). For these kinds an update with an empty diff is status churn.
func KindHasDiffer(kind string) bool {
	_, ok := diffFunctions[kind]
	return ok
}

// ComputeDiff returns the tracked field changes between two snapshots of one
// object, or nil when there is nothing tracked to report or the inputs cannot
// be compared. Inputs are typed objects (*appsv1.Deployment, …) or
// *unstructured.Unstructured; an unstructured pair for a typed kind is
// converted first. Unstructured inputs with an apiVersion are dispatched by
// group, so a CRD that reuses a built-in kind name gets the generic differ,
// and two snapshots from different groups are never diffed as one object.
// Secret kinds always return nil.
func ComputeDiff(kind string, oldObj, newObj any) *DiffInfo {
	if isSecretKind(kind) {
		return nil
	}
	oldGroup, oldKnown := unstructuredGroup(oldObj)
	newGroup, newKnown := unstructuredGroup(newObj)
	if oldKnown && newKnown && oldGroup != newGroup {
		return nil
	}
	group, known := newGroup, newKnown
	if !known {
		group, known = oldGroup, oldKnown
	}

	registration, ok := diffFunctions[kind]
	if ok && known && group != registration.group {
		ok = false
	}
	if !ok {
		oldU, newU, pair := unstructuredPair(oldObj, newObj)
		if !pair {
			return nil
		}
		return buildDiff(diffGenericUnstructured(oldU, newU))
	}
	if oldU, newU, pair := unstructuredPair(oldObj, newObj); pair {
		oldObj = diffInputForUnstructured(kind, oldU)
		newObj = diffInputForUnstructured(kind, newU)
	}
	return buildDiff(registration.diff(oldObj, newObj))
}

// ComputeDiffFromUnstructured is ComputeDiff for a dynamic-cache pair.
func ComputeDiffFromUnstructured(kind string, oldU, newU *unstructured.Unstructured) *DiffInfo {
	if oldU == nil || newU == nil {
		return nil
	}
	return ComputeDiff(kind, oldU, newU)
}

// unstructuredGroup returns the API group of an unstructured object that
// carries an apiVersion. Typed informer objects have no TypeMeta; their Go
// type already pins the group, so they report unknown.
func unstructuredGroup(obj any) (string, bool) {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok || u == nil || u.GetAPIVersion() == "" {
		return "", false
	}
	gv, err := schema.ParseGroupVersion(u.GetAPIVersion())
	if err != nil {
		return "", false
	}
	return gv.Group, true
}

// typedKinds converts an unstructured snapshot of a kind with a typed differ
// into the typed object that differ expects.
var typedKinds = map[string]func(*unstructured.Unstructured) any{
	"Deployment":              asTyped[appsv1.Deployment],
	"ReplicaSet":              asTyped[appsv1.ReplicaSet],
	"DaemonSet":               asTyped[appsv1.DaemonSet],
	"StatefulSet":             asTyped[appsv1.StatefulSet],
	"Job":                     asTyped[batchv1.Job],
	"HorizontalPodAutoscaler": asTyped[autoscalingv2.HorizontalPodAutoscaler],
	"Ingress":                 asTyped[networkingv1.Ingress],
	"Pod":                     asTyped[corev1.Pod],
	"Service":                 asTyped[corev1.Service],
	"ConfigMap":               asTyped[corev1.ConfigMap],
	"Node":                    asTyped[corev1.Node],
	"PersistentVolumeClaim":   asTyped[corev1.PersistentVolumeClaim],
	"ResourceQuota":           asTyped[corev1.ResourceQuota],
	"LimitRange":              asTyped[corev1.LimitRange],
}

// diffInputForUnstructured is what a kind's differ takes: the typed object
// for a typed kind, a copy of the unstructured one otherwise.
func diffInputForUnstructured(kind string, u *unstructured.Unstructured) any {
	if conv, ok := typedKinds[kind]; ok {
		return conv(u)
	}
	return u.DeepCopy()
}

func unstructuredPair(oldObj, newObj any) (*unstructured.Unstructured, *unstructured.Unstructured, bool) {
	oldU, ok1 := oldObj.(*unstructured.Unstructured)
	newU, ok2 := newObj.(*unstructured.Unstructured)
	return oldU, newU, ok1 && ok2 && oldU != nil && newU != nil
}

// buildDiff joins the summary and caps every value string; nil when nothing
// changed.
func buildDiff(changes []FieldChange, summaryParts []string) *DiffInfo {
	if len(changes) == 0 {
		return nil
	}
	for i := range changes {
		changes[i].OldValue = capValue(changes[i].OldValue)
		changes[i].NewValue = capValue(changes[i].NewValue)
	}
	parts := make([]string, len(summaryParts))
	for i, p := range summaryParts {
		parts[i] = truncateValue(p)
	}
	return &DiffInfo{Fields: changes, Summary: strings.Join(parts, ", ")}
}

// truncateValue cuts s to MaxValueLen runes, the last being TruncationMarker.
func truncateValue(s string) string {
	if utf8.RuneCountInString(s) <= MaxValueLen {
		return s
	}
	runes := []rune(s)
	return string(runes[:MaxValueLen-1]) + TruncationMarker
}

// capValue applies truncateValue to every string inside a change value.
func capValue(v any) any {
	switch x := v.(type) {
	case string:
		return truncateValue(x)
	case []string:
		out := make([]string, len(x))
		for i, s := range x {
			out[i] = truncateValue(s)
		}
		return out
	case map[string]string:
		out := make(map[string]string, len(x))
		for k, s := range x {
			out[k] = truncateValue(s)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = capValue(item)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, item := range x {
			out[k] = capValue(item)
		}
		return out
	default:
		return v
	}
}

// diffGenericUnstructured covers kinds without an audited differ: a spec
// generation bump, condition (status, reason) flips, and otherwise a bare
// "resource changed" marker when anything beyond reconcile bookkeeping moved.
// It never emits field values from the object body.
func diffGenericUnstructured(oldU, newU *unstructured.Unstructured) ([]FieldChange, []string) {
	var changes []FieldChange
	var summary []string

	// A generation bump counts only when spec itself moved: a controller that
	// writes another top-level field (Argo CD's `operation`) bumps generation
	// every reconcile, which would otherwise read as a stream of spec edits.
	if oldGen, newGen := oldU.GetGeneration(), newU.GetGeneration(); oldGen != newGen && oldGen > 0 && newGen > 0 &&
		!apiequality.Semantic.DeepEqual(oldU.Object["spec"], newU.Object["spec"]) {
		changes = append(changes, FieldChange{Path: "metadata.generation", OldValue: oldGen, NewValue: newGen})
		summary = append(summary, fmt.Sprintf("spec changed (gen %d→%d, fields not specifically tracked)", oldGen, newGen))
	}

	for _, change := range genericConditionChanges(oldU, newU, "status", "conditions") {
		changes = append(changes, change)
		summary = append(summary, fmt.Sprintf("%s changed", change.Path))
	}

	if len(changes) > 0 {
		return changes, summary
	}

	if reflect.DeepEqual(normalizedForDiff(oldU), normalizedForDiff(newU)) {
		return nil, nil
	}
	return []FieldChange{{Path: "resource", OldValue: "changed", NewValue: "changed"}}, []string{"resource changed"}
}

// asTyped converts u to a *T, or falls back to a copy of u when it does not
// fit the type.
func asTyped[T any](u *unstructured.Unstructured) any {
	out := new(T)
	if runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, out) != nil {
		return u.DeepCopy()
	}
	return out
}

// genericConditionChanges reports each condition, at the given path, whose
// status or reason differs between the snapshots (appearing and vanishing
// included), in type order.
func genericConditionChanges(oldU, newU *unstructured.Unstructured, fields ...string) []FieldChange {
	before := genericConditionSignalMap(oldU.Object, fields...)
	after := genericConditionSignalMap(newU.Object, fields...)
	all := maps.Clone(before)
	if all == nil {
		all = map[string]string{}
	}
	maps.Copy(all, after)
	prefix := strings.Join(fields, ".")
	var out []FieldChange
	for _, typ := range slices.Sorted(maps.Keys(all)) {
		was, hadIt := before[typ]
		is, hasIt := after[typ]
		if hadIt == hasIt && was == is {
			continue
		}
		out = append(out, FieldChange{Path: prefix + "[" + typ + "]", OldValue: was, NewValue: is})
	}
	return out
}

// genericConditionSignalMap maps each condition type to its status and
// reason, each quoted, so different pairs never collide whatever they
// contain, and a NUL (which jsonb cannot hold) comes out escaped.
func genericConditionSignalMap(obj map[string]any, fields ...string) map[string]string {
	list, found, _ := unstructured.NestedSlice(obj, fields...)
	if !found {
		return nil
	}
	out := make(map[string]string, len(list))
	for _, c := range conditionMaps(list) {
		if c.typ != "" {
			out[c.typ] = strconv.Quote(c.status) + ":" + strconv.Quote(c.reason)
		}
	}
	return out
}

func normalizedForDiff(u *unstructured.Unstructured) map[string]any {
	cp := u.DeepCopy().Object
	dropNoiseKeys(cp)
	return cp
}

func dropNoiseKeys(v any) {
	switch typed := v.(type) {
	case map[string]any:
		for k, child := range typed {
			if isNoiseKey(k) {
				delete(typed, k)
				continue
			}
			dropNoiseKeys(child)
		}
	case []any:
		for _, child := range typed {
			dropNoiseKeys(child)
		}
	}
}

// isNoiseKey names reconcile bookkeeping fields that change without anything
// an operator would call a change.
func isNoiseKey(key string) bool {
	switch key {
	case "resourceVersion", "managedFields", "observedGeneration",
		"lastTransitionTime", "lastUpdateTime", "lastHeartbeatTime", "lastProbeTime",
		"lastReconcileTime", "lastReconciledTime", "lastSyncTime",
		"lastHandledReconcileAt", "lastHandledRefresh":
		return true
	default:
		return false
	}
}

type rawCondition struct{ typ, status, reason string }

func conditionMaps(list []any) []rawCondition {
	var out []rawCondition
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		var c rawCondition
		c.typ, _ = m["type"].(string)
		c.status, _ = m["status"].(string)
		c.reason, _ = m["reason"].(string)
		out = append(out, c)
	}
	return out
}

// getConditionMap is condition type to status for a nested conditions list.
func getConditionMap(obj map[string]any, path ...string) map[string]string {
	list, _, _ := unstructured.NestedSlice(obj, path...)
	out := map[string]string{}
	for _, c := range conditionMaps(list) {
		if c.typ != "" {
			out[c.typ] = c.status
		}
	}
	return out
}

func valueOrNil(v string, ok bool) any {
	if !ok {
		return nil
	}
	return v
}

func emptyAsNone(s string) string {
	if s == "" {
		return "(default)"
	}
	return s
}

func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// diffStringSlices is the elements of a that b lacks, sorted.
func diffStringSlices(a, b []string) []string {
	out := slices.DeleteFunc(slices.Clone(a), func(s string) bool { return slices.Contains(b, s) })
	slices.Sort(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func equalStringSlices(a, b []string) bool { return slices.Equal(a, b) }

func equalStringMaps(a, b map[string]string) bool { return maps.Equal(a, b) }

// truncateImage shortens a long image reference to its tag or digest for
// summaries; FieldChange values keep the full reference.
func truncateImage(image string) string {
	if len(image) > 40 {
		if i := strings.LastIndexAny(image, ":@"); i >= 0 {
			return "..." + image[i:]
		}
		return image[:37] + "..."
	}
	return image
}

// truncateRevision is a revision's first seven characters, as git shows it.
func truncateRevision(rev string) string { return rev[:min(len(rev), 7)] }

// truncateMessage shortens a controller message for a summary.
func truncateMessage(msg string) string {
	if len(msg) <= 50 {
		return msg
	}
	return msg[:47] + "..."
}
