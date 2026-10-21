package policyreports

import (
	"fmt"
	"slices"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// report is a PolicyReport in ns (a ClusterPolicyReport when ns is ""),
// with an optional scope and the given results.
func report(ns string, scope map[string]any, results ...map[string]any) *unstructured.Unstructured {
	r := &unstructured.Unstructured{Object: map[string]any{}}
	r.SetAPIVersion("wgpolicyk8s.io/v1alpha2")
	r.SetKind("PolicyReport")
	if ns == "" {
		r.SetKind("ClusterPolicyReport")
	}
	r.SetNamespace(ns)
	r.SetName("polr-" + fmt.Sprint(len(results)))
	if scope != nil {
		r.Object["scope"] = scope
	}
	list := make([]any, len(results))
	for i, res := range results {
		list[i] = res
	}
	r.Object["results"] = list
	return r
}

// result is one result for policy/rule with outcome, about refs.
func result(policy, rule, outcome string, refs ...map[string]any) map[string]any {
	res := map[string]any{"policy": policy, "rule": rule, "result": outcome, "severity": "medium", "category": "Pod Security", "message": policy + "/" + rule + " " + outcome, "source": "kyverno"}
	if refs != nil {
		list := make([]any, len(refs))
		for i, ref := range refs {
			list[i] = ref
		}
		res["resources"] = list
	}
	return res
}

func ref(apiVersion, kind, ns, name string) map[string]any {
	m := map[string]any{"apiVersion": apiVersion, "kind": kind, "name": name}
	if ns != "" {
		m["namespace"] = ns
	}
	return m
}

// rules lists "policy/rule:result" for an object's findings.
func rules(idx *Index, group, kind, ns, name string) []string {
	var out []string
	for _, f := range idx.FindingsFor(group, kind, ns, name) {
		out = append(out, f.Policy+"/"+f.Rule+":"+f.Result)
	}
	return out
}

func TestBuildIndex(t *testing.T) {
	idx := BuildIndex([]*unstructured.Unstructured{
		// Two objects named in one result, one of them without a namespace.
		report("shop", nil,
			result("require-requests", "cpu", "fail", ref("apps/v1", "Deployment", "shop", "cart"), ref("v1", "Pod", "", "cart-7f")),
			result("disallow-latest", "tag", "pass", ref("apps/v1", "Deployment", "shop", "cart")),
		),
		// The whole report is about one object; its namespace is the report's.
		report("shop", ref("apps/v1", "Deployment", "", "checkout"), result("require-probes", "liveness", "warn")),
		// Malformed references fall back to the scope; so does an empty list.
		report("shop", ref("v1", "Service", "shop", "checkout"),
			result("svc-labels", "team", "fail", map[string]any{}, map[string]any{"kind": "Service"}),
			result("svc-type", "no-nodeport", "pass", []map[string]any{}...),
		),
		// Nothing to file under: dropped.
		report("shop", nil, result("orphan", "r", "fail")),
		// A cluster report about a cluster-scoped object.
		report("", nil, result("node-labels", "zone", "fail", ref("v1", "Node", "", "worker-3"))),
		// The same Kind in two groups is two objects.
		report("argocd", nil,
			result("app-owner", "label", "fail", ref("argoproj.io/v1alpha1", "Application", "argocd", "storefront")),
			result("other-app", "label", "pass", ref("example.com/v1", "Application", "argocd", "storefront")),
		),
		nil,
	})
	cases := []struct {
		group, kind, ns, name string
		want                  []string
	}{
		{"apps", "Deployment", "shop", "cart", []string{"disallow-latest/tag:pass", "require-requests/cpu:fail"}},
		{"", "Pod", "shop", "cart-7f", []string{"require-requests/cpu:fail"}},
		{"apps", "Deployment", "shop", "checkout", []string{"require-probes/liveness:warn"}},
		{"", "Service", "shop", "checkout", []string{"svc-labels/team:fail", "svc-type/no-nodeport:pass"}},
		{"", "Node", "", "worker-3", []string{"node-labels/zone:fail"}},
		{"argoproj.io", "Application", "argocd", "storefront", []string{"app-owner/label:fail"}},
		{"example.com", "Application", "argocd", "storefront", []string{"other-app/label:pass"}},
		// The group is part of the identity.
		{"", "Deployment", "shop", "cart", nil},
		{"apps", "Deployment", "staging", "cart", nil},
	}
	for _, c := range cases {
		if got := rules(idx, c.group, c.kind, c.ns, c.name); !slices.Equal(got, c.want) {
			t.Errorf("%s/%s %s/%s: %v, want %v", c.group, c.kind, c.ns, c.name, got, c.want)
		}
	}
	if f := idx.FindingsFor("", "Pod", "shop", "cart-7f")[0]; f != (Finding{"require-requests", "cpu", "fail", "medium", "Pod Security", "require-requests/cpu fail", "kyverno"}) {
		t.Errorf("finding = %+v", f)
	}
}

// The same finding from two reports — or from both report API families while
// a cluster migrates — counts once; a finding that differs in any field is
// its own. The order is the same however the reports were listed.
func TestBuildIndexDeduplicatesAndSorts(t *testing.T) {
	cart := ref("apps/v1", "Deployment", "shop", "cart")
	a := report("shop", nil, result("p", "r", "fail", cart), result("b-policy", "r", "pass", cart))
	b := report("shop", nil, result("p", "r", "fail", cart))
	openreports := report("shop", nil, result("p", "r", "fail", cart))
	openreports.SetAPIVersion("openreports.io/v1alpha1")
	other := result("p", "r", "fail", cart)
	other["message"] = "a different message"
	c := report("shop", nil, other)

	one := BuildIndex([]*unstructured.Unstructured{a, b, openreports, c}).FindingsFor("apps", "Deployment", "shop", "cart")
	two := BuildIndex([]*unstructured.Unstructured{c, openreports, b, a}).FindingsFor("apps", "Deployment", "shop", "cart")
	if len(one) != 3 || !slices.Equal(one, two) {
		t.Fatalf("got %d findings:\n%+v\n%+v", len(one), one, two)
	}
	if one[0].Policy != "b-policy" || one[1].Message != "a different message" {
		t.Errorf("order = %+v", one)
	}
}

// Callers may change what they get without touching the index.
func TestFindingsForReturnsACopy(t *testing.T) {
	idx := BuildIndex([]*unstructured.Unstructured{report("shop", nil, result("p", "r", "fail", ref("v1", "Pod", "shop", "x")))})
	got := idx.FindingsFor("", "Pod", "shop", "x")
	got[0].Message = "changed"
	if idx.FindingsFor("", "Pod", "shop", "x")[0].Message == "changed" {
		t.Fatal("the index shares its slice")
	}
	var none *Index
	if none.FindingsFor("", "Pod", "shop", "x") != nil || BuildIndex(nil).FindingsFor("", "Pod", "shop", "x") != nil {
		t.Fatal("an empty index returned findings")
	}
}
