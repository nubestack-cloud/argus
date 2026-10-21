package changes

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// listLen is the length of the list at path, 0 when absent.
func listLen(u *unstructured.Unstructured, path ...string) int {
	l, _, _ := unstructured.NestedSlice(u.Object, path...)
	return len(l)
}

// countChange records a list whose length moved, as "N <noun>".
func (d *delta) countChange(path, noun, label string, a, b int) {
	if a != b {
		d.add(path, fmt.Sprintf("%d %s", a, noun), fmt.Sprintf("%d %s", b, noun), fmt.Sprintf("%s: %d→%d", label, a, b))
	}
}

func diffGateway(oldObj, newObj any) ([]FieldChange, []string) {
	was, is, ok := unstructuredPair(oldObj, newObj)
	if !ok {
		return nil, nil
	}
	var d delta
	d.countChange("spec.listeners", "listeners", "listeners", listLen(was, "spec", "listeners"), listLen(is, "spec", "listeners"))
	d.countChange("status.addresses", "addresses", "addresses", listLen(was, "status", "addresses"), listLen(is, "status", "addresses"))
	// A condition appearing or vanishing is not a flip; only a status that
	// is reported on both sides and moved.
	before, after := getConditionMap(was.Object, "status", "conditions"), getConditionMap(is.Object, "status", "conditions")
	for _, t := range []string{"Accepted", "Programmed"} {
		if a, b := before[t], after[t]; a != b && a != "" && b != "" {
			d.add("status.conditions."+t, a, b, fmt.Sprintf("%s: %s→%s", t, a, b))
		}
	}
	return d.result()
}

// diffGatewayRoute covers HTTPRoute, GRPCRoute, TCPRoute and TLSRoute. Each
// parent's conditions are compared one by one: a route reports bad config
// or a missing backend through Programmed or ResolvedRefs while Accepted
// stays True.
func diffGatewayRoute(oldObj, newObj any) ([]FieldChange, []string) {
	was, is, ok := unstructuredPair(oldObj, newObj)
	if !ok {
		return nil, nil
	}
	var d delta
	a, _, _ := unstructured.NestedStringSlice(was.Object, "spec", "hostnames")
	b, _, _ := unstructured.NestedStringSlice(is.Object, "spec", "hostnames")
	if !slices.Equal(a, b) {
		d.add("spec.hostnames", strings.Join(a, ", "), strings.Join(b, ", "), "hostnames: "+strings.Join(a, ",")+"→"+strings.Join(b, ","))
	}
	d.countChange("spec.rules", "rules", "rules", listLen(was, "spec", "rules"), listLen(is, "spec", "rules"))
	d.countChange("status.parents", "parents", "parents", listLen(was, "status", "parents"), listLen(is, "status", "parents"))

	// Every parent on either side, so one that went away shows even when
	// another took its place and the count held.
	oldParents, _, _ := unstructured.NestedSlice(was.Object, "status", "parents")
	newParents, _, _ := unstructured.NestedSlice(is.Object, "status", "parents")
	before, after := indexParentConditions(oldParents), indexParentConditions(newParents)
	all := maps.Clone(before)
	maps.Copy(all, after)
	for _, parent := range slices.Sorted(maps.Keys(all)) {
		for _, t := range []string{"Accepted", "ResolvedRefs", "Programmed"} {
			x, inOld := before[parent][t]
			y, inNew := after[parent][t]
			if (inOld || inNew) && x != y {
				d.add("status.parents["+parent+"].conditions["+t+"]", x, y, fmt.Sprintf("%s/%s: %s→%s", parent, t, x, y))
			}
		}
	}
	return d.result()
}

// diffGatewayClass follows which controller the class binds to and its
// Accepted and SupportedVersion conditions; the rest of its status is
// reconcile noise.
func diffGatewayClass(oldObj, newObj any) ([]FieldChange, []string) {
	was, is, ok := unstructuredPair(oldObj, newObj)
	if !ok {
		return nil, nil
	}
	var d delta
	a, _, _ := unstructured.NestedString(was.Object, "spec", "controllerName")
	b, _, _ := unstructured.NestedString(is.Object, "spec", "controllerName")
	if a != b {
		d.add("spec.controllerName", a, b, fmt.Sprintf("controller: %s→%s", a, b))
	}
	before, after := getConditionMap(was.Object, "status", "conditions"), getConditionMap(is.Object, "status", "conditions")
	for _, t := range []string{"Accepted", "SupportedVersion"} {
		if x, y := before[t], after[t]; x != y {
			d.add("status.conditions."+t, x, y, fmt.Sprintf("%s: %s→%s", t, x, y))
		}
	}
	return d.result()
}

// diffReferenceGrant follows spec.from and spec.to, the cross-namespace
// permission a grant exists to give.
func diffReferenceGrant(oldObj, newObj any) ([]FieldChange, []string) {
	was, is, ok := unstructuredPair(oldObj, newObj)
	if !ok {
		return nil, nil
	}
	var d delta
	for _, side := range []string{"from", "to"} {
		if a, b := listLen(was, "spec", side), listLen(is, "spec", side); a != b {
			d.add("spec."+side, a, b, fmt.Sprintf("%s: %d→%d", side, a, b))
		}
	}
	return d.result()
}

// indexParentConditions is each route parent's condition statuses, keyed by
// group/kind/namespace/name/sectionName/port: one route can attach to a
// Gateway through several listeners.
func indexParentConditions(parents []any) map[string]map[string]string {
	out := make(map[string]map[string]string, len(parents))
	for _, p := range parents {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		ref := func(field string) string {
			s, _, _ := unstructured.NestedString(pm, "parentRef", field)
			return s
		}
		port, _, _ := unstructured.NestedInt64(pm, "parentRef", "port")
		key := strings.Join([]string{ref("group"), ref("kind"), ref("namespace"), ref("name"), ref("sectionName"), strconv.FormatInt(port, 10)}, "/")
		out[key] = getConditionMap(pm, "conditions")
	}
	return out
}
