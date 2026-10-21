package changes

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// configMapSummaryKeys is how many changed ConfigMap keys a summary names
// before counting the rest.
const configMapSummaryKeys = 5

// diffConfigMap reports which data and binaryData keys were added, removed
// or modified. The object cache has replaced every value with a
// "sha256:<hex>" digest, so a modified key is a digest that changed, and the
// change carries only that word.
func diffConfigMap(oldObj, newObj any) ([]FieldChange, []string) {
	was, is, ok := both[corev1.ConfigMap](oldObj, newObj)
	if !ok {
		return nil, nil
	}
	var d delta
	d.fields = slices.Concat(
		keyLevelChanges("data", was.Data, is.Data, func(a, b string) bool { return a == b }),
		keyLevelChanges("binaryData", was.BinaryData, is.BinaryData, func(a, b []byte) bool { return string(a) == string(b) }),
	)
	for i, c := range d.fields {
		if i == configMapSummaryKeys {
			d.note(fmt.Sprintf("%d more keys changed", len(d.fields)-configMapSummaryKeys))
			break
		}
		d.note(fmt.Sprintf("%s %s", c.Path, c.NewValue))
	}
	// Turning immutable on locks the ConfigMap until it is recreated.
	if a, b := flag(was.Immutable), flag(is.Immutable); a != b {
		d.add("immutable", a, b, map[bool]string{true: "marked immutable", false: "immutable cleared"}[b])
	}
	return d.result()
}

func flag(p *bool) bool { return p != nil && *p }

// keyLevelChanges is one "<field>.<key>" change per key that differs, its
// only value the word added, removed or modified.
func keyLevelChanges[T any](field string, before, after map[string]T, equal func(a, b T) bool) []FieldChange {
	all := map[string]bool{}
	for k := range before {
		all[k] = true
	}
	for k := range after {
		all[k] = true
	}
	var out []FieldChange
	for _, key := range slices.Sorted(maps.Keys(all)) {
		a, inOld := before[key]
		b, inNew := after[key]
		word := ""
		switch {
		case !inOld:
			word = ValueAdded
		case !inNew:
			word = ValueRemoved
		case !equal(a, b):
			word = ValueModified
		}
		if word != "" {
			out = append(out, FieldChange{Path: field + "." + key, NewValue: word})
		}
	}
	return out
}

func diffService(oldObj, newObj any) ([]FieldChange, []string) {
	was, is, ok := both[corev1.Service](oldObj, newObj)
	if !ok {
		return nil, nil
	}
	var d delta
	if a, b := was.Spec.Type, is.Spec.Type; a != b {
		d.add("spec.type", string(a), string(b), fmt.Sprintf("type: %s→%s", a, b))
	}
	if a, b := servicePorts(was.Spec.Ports), servicePorts(is.Spec.Ports); !slices.Equal(a, b) {
		d.add("spec.ports", a, b, "ports changed")
	}
	if a, b := was.Spec.Selector, is.Spec.Selector; !maps.Equal(a, b) {
		d.add("spec.selector", a, b, "selector changed")
	}
	d.merge(lbAddressChange(lbAddresses(was.Status.LoadBalancer.Ingress), lbAddresses(is.Status.LoadBalancer.Ingress)))
	if a, b := was.Spec.ExternalIPs, is.Spec.ExternalIPs; !slices.Equal(a, b) {
		d.add("spec.externalIPs", a, b, "externalIPs changed")
	}
	return d.result()
}

// lbAddressChange is the change, if any, in a load balancer's published
// addresses: appearing, disappearing, or moving.
func lbAddressChange(before, after []string) ([]FieldChange, []string) {
	if slices.Equal(before, after) {
		return nil, nil
	}
	var d delta
	const path = "status.loadBalancer.ingress"
	switch {
	case len(before) == 0:
		d.add(path, nil, after, "LB ready: "+strings.Join(after, ", "))
	case len(after) == 0:
		d.add(path, before, nil, "LB removed")
	default:
		d.add(path, before, after, "LB addresses changed")
	}
	return d.result()
}

// lbAddresses is each entry's IP, or its hostname when it has no IP.
func lbAddresses(ingress []corev1.LoadBalancerIngress) []string {
	var out []string
	for _, e := range ingress {
		if a := cmp.Or(e.IP, e.Hostname); a != "" {
			out = append(out, a)
		}
	}
	return out
}

// servicePorts writes each port as protocol/port→targetPort.
func servicePorts(ports []corev1.ServicePort) []string {
	out := make([]string, len(ports))
	for i, p := range ports {
		out[i] = string(p.Protocol) + "/" + strconv.Itoa(int(p.Port)) + "→" + p.TargetPort.String()
	}
	return out
}

func diffIngress(oldObj, newObj any) ([]FieldChange, []string) {
	was, is, ok := both[networkingv1.Ingress](oldObj, newObj)
	if !ok {
		return nil, nil
	}
	var d delta
	if a, b := len(was.Spec.Rules), len(is.Spec.Rules); a != b {
		d.add("spec.rules", a, b, fmt.Sprintf("rules: %d→%d", a, b))
	}
	if a, b := len(was.Spec.TLS), len(is.Spec.TLS); a != b {
		d.add("spec.tls", a, b, fmt.Sprintf("tls: %d→%d", a, b))
	}
	d.merge(lbAddressChange(ingressLBAddresses(was.Status.LoadBalancer.Ingress), ingressLBAddresses(is.Status.LoadBalancer.Ingress)))
	if a, b := ingressHosts(was.Spec.Rules), ingressHosts(is.Spec.Rules); !slices.Equal(a, b) {
		d.add("spec.rules[*].host", a, b, "hosts changed")
	}
	return d.result()
}

func ingressLBAddresses(ingress []networkingv1.IngressLoadBalancerIngress) []string {
	var out []string
	for _, e := range ingress {
		if a := cmp.Or(e.IP, e.Hostname); a != "" {
			out = append(out, a)
		}
	}
	return out
}

func ingressHosts(rules []networkingv1.IngressRule) []string {
	var out []string
	for _, r := range rules {
		if r.Host != "" {
			out = append(out, r.Host)
		}
	}
	return out
}

// nodeConditionsTracked are the Node conditions whose flips are recorded:
// Ready, and the pressures that come before evictions and scheduling
// failures.
var nodeConditionsTracked = []corev1.NodeConditionType{
	corev1.NodeReady, corev1.NodeMemoryPressure, corev1.NodeDiskPressure, corev1.NodePIDPressure, corev1.NodeNetworkUnavailable,
}

func diffNode(oldObj, newObj any) ([]FieldChange, []string) {
	was, is, ok := both[corev1.Node](oldObj, newObj)
	if !ok {
		return nil, nil
	}
	var d delta
	if a, b := was.Spec.Unschedulable, is.Spec.Unschedulable; a != b {
		d.add("spec.unschedulable", a, b, map[bool]string{true: "cordoned", false: "uncordoned"}[b])
	}
	if a, b := taintKeys(was.Spec.Taints), taintKeys(is.Spec.Taints); !slices.Equal(a, b) {
		d.add("spec.taints", a, b)
		if added := diffStringSlices(b, a); len(added) > 0 {
			d.note(fmt.Sprintf("taints added: %v", added))
		}
		if removed := diffStringSlices(a, b); len(removed) > 0 {
			d.note(fmt.Sprintf("taints removed: %v", removed))
		}
	}
	for _, c := range nodeConditionsTracked {
		if a, b := nodeCondition(was, c), nodeCondition(is, c); a != b {
			d.add("status.conditions["+string(c)+"]", a, b, fmt.Sprintf("%s: %s→%s", c, a, b))
		}
	}
	if a, b := was.Status.NodeInfo.KubeletVersion, is.Status.NodeInfo.KubeletVersion; a != b {
		d.add("status.nodeInfo.kubeletVersion", a, b, fmt.Sprintf("kubelet: %s→%s", a, b))
	}
	if a, b := was.Status.NodeInfo.KernelVersion, is.Status.NodeInfo.KernelVersion; a != b {
		d.add("status.nodeInfo.kernelVersion", a, b, "kernel upgraded")
	}
	// Allocatable, what the scheduler works from, rather than capacity: it
	// also moves when the kubelet's reservations change.
	for _, r := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory, corev1.ResourcePods} {
		a, b := was.Status.Allocatable[r], is.Status.Allocatable[r]
		if a.Cmp(b) != 0 {
			d.add("status.allocatable."+string(r), a.String(), b.String(), fmt.Sprintf("allocatable %s: %s→%s", r, a.String(), b.String()))
		}
	}
	return d.result()
}

func taintKeys(taints []corev1.Taint) []string {
	out := make([]string, len(taints))
	for i, t := range taints {
		out[i] = t.Key
	}
	return out
}

// nodeCondition is a condition's status, or Unknown when the node does not
// report it.
func nodeCondition(node *corev1.Node, t corev1.NodeConditionType) string {
	if i := slices.IndexFunc(node.Status.Conditions, func(c corev1.NodeCondition) bool { return c.Type == t }); i >= 0 {
		return string(node.Status.Conditions[i].Status)
	}
	return "Unknown"
}

func diffPVC(oldObj, newObj any) ([]FieldChange, []string) {
	was, is, ok := both[corev1.PersistentVolumeClaim](oldObj, newObj)
	if !ok {
		return nil, nil
	}
	var d delta
	if a, b := was.Status.Phase, is.Status.Phase; a != b {
		d.add("status.phase", string(a), string(b), fmt.Sprintf("phase: %s→%s", a, b))
	}
	if was.Spec.VolumeName == "" && is.Spec.VolumeName != "" {
		d.add("spec.volumeName", "", is.Spec.VolumeName, "bound to "+is.Spec.VolumeName)
	}
	a, b := was.Status.Capacity[corev1.ResourceStorage], is.Status.Capacity[corev1.ResourceStorage]
	if !a.IsZero() && !b.IsZero() && a.Cmp(b) != 0 {
		d.add("status.capacity.storage", a.String(), b.String(), fmt.Sprintf("capacity: %s→%s", a.String(), b.String()))
	}
	// Resizing=True is an expansion in progress; FileSystemResizePending=True
	// means the volume grows only once a pod restarts on it.
	for _, t := range []corev1.PersistentVolumeClaimConditionType{corev1.PersistentVolumeClaimResizing, corev1.PersistentVolumeClaimFileSystemResizePending} {
		if a, b := pvcCondition(was, t), pvcCondition(is, t); a != b {
			d.add("status.conditions["+string(t)+"]", a, b, fmt.Sprintf("%s: %s→%s", t, a, b))
		}
	}
	return d.result()
}

func pvcCondition(pvc *corev1.PersistentVolumeClaim, t corev1.PersistentVolumeClaimConditionType) string {
	if i := slices.IndexFunc(pvc.Status.Conditions, func(c corev1.PersistentVolumeClaimCondition) bool { return c.Type == t }); i >= 0 {
		return string(pvc.Status.Conditions[i].Status)
	}
	return ""
}

// diffResourceQuota reports spec.hard, the limits admission enforces.
// status.used moves with every pod coming and going and is left out.
func diffResourceQuota(oldObj, newObj any) ([]FieldChange, []string) {
	was, is, ok := both[corev1.ResourceQuota](oldObj, newObj)
	if !ok {
		return nil, nil
	}
	names := map[string]bool{}
	for n := range was.Spec.Hard {
		names[string(n)] = true
	}
	for n := range is.Spec.Hard {
		names[string(n)] = true
	}
	quantity := func(l corev1.ResourceList, name string) (string, bool) {
		q, set := l[corev1.ResourceName(name)]
		if !set {
			return "", false
		}
		return q.String(), true
	}
	var d delta
	for _, name := range slices.Sorted(maps.Keys(names)) {
		a, inOld := quantity(was.Spec.Hard, name)
		b, inNew := quantity(is.Spec.Hard, name)
		if a != b {
			d.add("spec.hard."+name, valueOrNil(a, inOld), valueOrNil(b, inNew), fmt.Sprintf("quota %s: %s→%s", name, emptyAsNone(a), emptyAsNone(b)))
		}
	}
	return d.result()
}

// diffLimitRange reports spec.limits, one compact string per item.
func diffLimitRange(oldObj, newObj any) ([]FieldChange, []string) {
	was, is, ok := both[corev1.LimitRange](oldObj, newObj)
	if !ok {
		return nil, nil
	}
	a, b := limitRangeItemRefs(was.Spec.Limits), limitRangeItemRefs(is.Spec.Limits)
	if slices.Equal(a, b) {
		return nil, nil
	}
	return []FieldChange{{Path: "spec.limits", OldValue: a, NewValue: b}}, []string{"limit ranges changed"}
}

// limitRangeItemRefs writes each item as its type and then every bound,
// "max.cpu=2 min.memory=64Mi …", the items sorted.
func limitRangeItemRefs(items []corev1.LimitRangeItem) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		words := []string{string(it.Type)}
		for _, bound := range []struct {
			label string
			list  corev1.ResourceList
		}{{"max", it.Max}, {"min", it.Min}, {"default", it.Default}, {"defaultRequest", it.DefaultRequest}} {
			for _, name := range slices.Sorted(maps.Keys(bound.list)) {
				q := bound.list[name]
				words = append(words, bound.label+"."+string(name)+"="+q.String())
			}
		}
		out = append(out, strings.Join(words, " "))
	}
	slices.Sort(out)
	return out
}

// diffAdmissionWebhookConfiguration follows each webhook of a Mutating- or
// ValidatingWebhookConfiguration by name: failure policy, backend, CA
// bundle, rules, selectors and timing. A webhook gates or rewrites every
// object it matches, so being re-scoped or having its CA rotated must show.
// The CA bundle itself is never emitted, only a short digest of it.
func diffAdmissionWebhookConfiguration(oldObj, newObj any) ([]FieldChange, []string) {
	oldU, newU, ok := unstructuredPair(oldObj, newObj)
	if !ok {
		return nil, nil
	}
	before, after := indexWebhooksByName(oldU), indexWebhooksByName(newU)
	all := maps.Clone(before)
	maps.Copy(all, after)
	var d delta
	for _, name := range slices.Sorted(maps.Keys(all)) {
		a, inOld := before[name]
		b, inNew := after[name]
		if inOld && inNew && a == b {
			continue
		}
		what := "changed"
		switch {
		case !inOld:
			what = "added"
		case !inNew:
			what = "removed"
		}
		d.add("webhooks["+name+"]", valueOrNil(a, inOld), valueOrNil(b, inNew), "webhook "+name+" "+what)
	}
	return d.result()
}

// indexWebhooksByName is each named webhook's one-line summary.
func indexWebhooksByName(u *unstructured.Unstructured) map[string]string {
	out := map[string]string{}
	hooks, _, _ := unstructured.NestedSlice(u.Object, "webhooks")
	for _, h := range hooks {
		if hm, ok := h.(map[string]any); ok {
			if name, _, _ := unstructured.NestedString(hm, "name"); name != "" {
				out[name] = webhookSummary(hm)
			}
		}
	}
	return out
}

// webhookSummary writes everything about a webhook that decides what it
// does to admission, as space-separated key=value words in a fixed order.
func webhookSummary(hm map[string]any) string {
	str := func(path ...string) (string, bool) {
		s, ok, _ := unstructured.NestedString(hm, path...)
		return s, ok
	}
	num := func(path ...string) (int64, bool) {
		n, ok, _ := unstructured.NestedInt64(hm, path...)
		return n, ok
	}
	var w []string
	if v, ok := str("failurePolicy"); ok {
		w = append(w, "failurePolicy="+v)
	}
	if name, ok := str("clientConfig", "service", "name"); ok {
		ns, _ := str("clientConfig", "service", "namespace")
		backend := "service=" + ns + "/" + name
		if port, ok := num("clientConfig", "service", "port"); ok && port != 0 {
			backend += ":" + strconv.FormatInt(port, 10)
		}
		if path, _ := str("clientConfig", "service", "path"); path != "" {
			backend += path
		}
		w = append(w, backend)
	} else if url, ok := str("clientConfig", "url"); ok {
		w = append(w, "url="+url)
	}
	// A digest, not a length, so a CA rotated for one of the same size shows.
	if ca, _ := str("clientConfig", "caBundle"); ca != "" {
		sum := sha256.Sum256([]byte(ca))
		w = append(w, "caBundle=sha256:"+hex.EncodeToString(sum[:6]))
	} else {
		w = append(w, "caBundle=none")
	}
	for _, key := range []string{"sideEffects", "matchPolicy"} {
		if v, ok := str(key); ok {
			w = append(w, key+"="+v)
		}
	}
	if v, ok := num("timeoutSeconds"); ok {
		w = append(w, "timeoutSeconds="+strconv.FormatInt(v, 10))
	}
	if v, ok := str("reinvocationPolicy"); ok {
		w = append(w, "reinvocationPolicy="+v)
	}
	// The selectors are how far the webhook reaches.
	for _, sel := range []string{"namespaceSelector", "objectSelector"} {
		if s := webhookSelectorSummary(hm, sel); s != "" {
			w = append(w, sel+"={"+s+"}")
		}
	}
	return strings.Join(append(w, "rules="+webhookRulesSummary(hm)), " ")
}

// webhookSelectorSummary writes a selector as its matchLabels and then its
// matchExpressions, each sorted; "" for the selector that matches
// everything.
func webhookSelectorSummary(hm map[string]any, field string) string {
	labels, _, _ := unstructured.NestedStringMap(hm, field, "matchLabels")
	exprs, _, _ := unstructured.NestedSlice(hm, field, "matchExpressions")
	var terms, written []string
	for _, k := range slices.Sorted(maps.Keys(labels)) {
		terms = append(terms, k+"="+labels[k])
	}
	for _, e := range exprs {
		if em, ok := e.(map[string]any); ok {
			key, _, _ := unstructured.NestedString(em, "key")
			op, _, _ := unstructured.NestedString(em, "operator")
			vals, _, _ := unstructured.NestedStringSlice(em, "values")
			written = append(written, key+" "+op+" ["+strings.Join(vals, ",")+"]")
		}
	}
	slices.Sort(written)
	return strings.Join(append(terms, written...), ",")
}

// webhookRulesSummary writes each rule as its whole match tuple — two rules
// that differ only in API group match different resources — sorted and
// joined with ";".
func webhookRulesSummary(hm map[string]any) string {
	rules, _, _ := unstructured.NestedSlice(hm, "rules")
	var out []string
	for _, rm := range objectsIn(rules) {
		list := func(key string) string {
			v, _, _ := unstructured.NestedStringSlice(rm, key)
			return strings.Join(v, ",")
		}
		ops, _, _ := unstructured.NestedStringSlice(rm, "operations")
		entry := strings.Join(ops, "/") + ":" + list("apiGroups") + "/" + list("apiVersions") + "/" + list("resources")
		if scope, _, _ := unstructured.NestedString(rm, "scope"); scope != "" {
			entry += "[" + scope + "]"
		}
		out = append(out, entry)
	}
	slices.Sort(out)
	return strings.Join(out, ";")
}

// objectsIn is the map entries of a decoded JSON list.
func objectsIn(list []any) []map[string]any {
	var out []map[string]any
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
