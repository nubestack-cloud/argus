package policyreports

import (
	"cmp"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// subject is an object findings are filed under. The API group is part of
// it, so two kinds of the same name from different groups (argoproj.io's
// Application and some other Application) are never confused.
type subject struct{ group, kind, namespace, name string }

// Index is the findings of a set of reports, filed by the object each is
// about. It is built once and only read.
type Index struct {
	findings map[subject][]Finding
}

// BuildIndex files every result of every report under each object it names.
// An object's namespace, when its reference leaves it out, is the report's
// own (a ClusterPolicyReport has none). A result that names no usable object
// — no resources[], an empty list, or entries without kind and name — falls
// back to the report's scope; with no scope either, there is nothing to file
// it under and it is dropped.
//
// The same finding reaching an object twice — from two reports, or from both
// report API families while a cluster moves between them — is kept once;
// counted twice it would inflate every total. Each object's findings are
// sorted, so the answer does not depend on the order reports were listed in.
func BuildIndex(reports []*unstructured.Unstructured) *Index {
	idx := &Index{findings: map[subject][]Finding{}}
	for _, r := range reports {
		if r != nil {
			idx.add(r)
		}
	}
	for s, fs := range idx.findings {
		slices.SortFunc(fs, func(a, b Finding) int {
			return cmp.Or(
				strings.Compare(a.Policy, b.Policy), strings.Compare(a.Rule, b.Rule),
				strings.Compare(a.Result, b.Result), strings.Compare(a.Severity, b.Severity),
				strings.Compare(a.Category, b.Category), strings.Compare(a.Message, b.Message),
				strings.Compare(a.Source, b.Source),
			)
		})
		idx.findings[s] = slices.Compact(fs)
	}
	return idx
}

// FindingsFor is a copy of the findings filed for one object, nil when there
// are none. group is the object's API group, "" for the core group.
func (i *Index) FindingsFor(group, kind, namespace, name string) []Finding {
	if i == nil {
		return nil
	}
	return slices.Clone(i.findings[subject{group, kind, namespace, name}])
}

func (i *Index) add(report *unstructured.Unstructured) {
	results, _, _ := unstructured.NestedFieldNoCopy(report.Object, "results")
	list, _ := results.([]any)
	if len(list) == 0 {
		return
	}
	scopeVal, _, _ := unstructured.NestedFieldNoCopy(report.Object, "scope")
	scope, _ := scopeVal.(map[string]any)
	home := report.GetNamespace()

	for _, item := range list {
		res, ok := item.(map[string]any)
		if !ok {
			continue
		}
		f := Finding{
			Policy: text(res, "policy"), Rule: text(res, "rule"), Result: text(res, "result"),
			Severity: text(res, "severity"), Category: text(res, "category"),
			Message: text(res, "message"), Source: text(res, "source"),
		}
		refs, _ := res["resources"].([]any)
		var about []subject
		for _, ref := range refs {
			if m, ok := ref.(map[string]any); ok {
				if s, ok := subjectOf(m, home); ok {
					about = append(about, s)
				}
			}
		}
		if len(about) == 0 && scope != nil {
			if s, ok := subjectOf(scope, home); ok {
				about = append(about, s)
			}
		}
		for _, s := range about {
			i.findings[s] = append(i.findings[s], f)
		}
	}
}

// subjectOf reads an object reference (apiVersion, kind, namespace, name),
// defaulting the namespace to the report's. Without kind and name it names
// nothing.
func subjectOf(ref map[string]any, home string) (subject, bool) {
	group, _, hasGroup := strings.Cut(text(ref, "apiVersion"), "/")
	if !hasGroup {
		group = ""
	}
	s := subject{group: group, kind: text(ref, "kind"), namespace: cmp.Or(text(ref, "namespace"), home), name: text(ref, "name")}
	return s, s.kind != "" && s.name != ""
}

func text(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}
