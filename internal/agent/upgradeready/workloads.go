package upgradeready

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// owner is a controller as an owner reference names it.
type owner struct{ group, kind, namespace, name string }

func controllerOf(o metav1.Object) *metav1.OwnerReference { return metav1.GetControllerOf(o) }

func ownerOf(o metav1.Object) (owner, bool) {
	ref := controllerOf(o)
	if ref == nil {
		return owner{}, false
	}
	gv, err := schema.ParseGroupVersion(ref.APIVersion)
	if err != nil {
		return owner{}, false
	}
	return owner{gv.Group, ref.Kind, o.GetNamespace(), ref.Name}, true
}

// ownership knows which workload objects the input holds, so a pod spec is
// judged once, on the object an operator would edit.
type ownership struct {
	present   map[owner]bool
	templates map[owner]*corev1.PodSpec // Deployments' and CronJobs' templates
}

func ownersOf(in *Input) *ownership {
	o := &ownership{present: map[owner]bool{}, templates: map[owner]*corev1.PodSpec{}}
	mark := func(group, kind string, m metav1.Object, template *corev1.PodSpec) {
		k := owner{group, kind, m.GetNamespace(), m.GetName()}
		o.present[k] = true
		if template != nil {
			o.templates[k] = template
		}
	}
	for _, d := range in.Deployments {
		if d != nil {
			mark("apps", "Deployment", d, &d.Spec.Template.Spec)
		}
	}
	for _, cj := range in.CronJobs {
		if cj != nil {
			mark("batch", "CronJob", cj, &cj.Spec.JobTemplate.Spec.Template.Spec)
		}
	}
	for _, rs := range in.ReplicaSets {
		if rs != nil {
			mark("apps", "ReplicaSet", rs, nil)
		}
	}
	for _, st := range in.StatefulSets {
		if st != nil {
			mark("apps", "StatefulSet", st, nil)
		}
	}
	for _, ds := range in.DaemonSets {
		if ds != nil {
			mark("apps", "DaemonSet", ds, nil)
		}
	}
	for _, j := range in.Jobs {
		if j != nil {
			mark("batch", "Job", j, nil)
		}
	}
	return o
}

// ownedByPresent reports whether o's controller is in the input.
func (w *ownership) ownedByPresent(o metav1.Object) bool {
	k, ok := ownerOf(o)
	return ok && w.present[k]
}

// sameAsTemplate reports whether o was stamped out of its controller's
// current template: a ReplicaSet of its Deployment's current revision, a Job
// of its CronJob's current template. An older revision may differ, so it is
// judged on its own.
func (w *ownership) sameAsTemplate(o metav1.Object, spec *corev1.PodSpec) bool {
	k, ok := ownerOf(o)
	if !ok {
		return false
	}
	t, ok := w.templates[k]
	return ok && equality.Semantic.DeepEqual(*spec, *t)
}

// podSpec is a pod spec to judge, with the object it belongs to and the path
// to it within that object.
type podSpec struct {
	obj    metav1.Object
	at     ResourceRef
	spec   *corev1.PodSpec
	prefix string
}

// podSpecs lists every pod spec the input holds once: each workload's
// template, and each pod or ReplicaSet or Job only when nothing above it in
// the input already carries the same spec.
func (s *scan) podSpecs() []podSpec {
	in, w := s.in, s.owners
	const template = "spec.template.spec"
	var out []podSpec
	for _, p := range in.Pods {
		if p != nil && !w.ownedByPresent(p) {
			out = append(out, podSpec{p, ResourceRef{Kind: "Pod", Namespace: p.Namespace, Name: p.Name}, &p.Spec, "spec"})
		}
	}
	for _, d := range in.Deployments {
		if d != nil {
			out = append(out, podSpec{d, ResourceRef{Group: "apps", Kind: "Deployment", Namespace: d.Namespace, Name: d.Name}, &d.Spec.Template.Spec, template})
		}
	}
	for _, rs := range in.ReplicaSets {
		if rs != nil && !w.sameAsTemplate(rs, &rs.Spec.Template.Spec) {
			out = append(out, podSpec{rs, ResourceRef{Group: "apps", Kind: "ReplicaSet", Namespace: rs.Namespace, Name: rs.Name}, &rs.Spec.Template.Spec, template})
		}
	}
	for _, st := range in.StatefulSets {
		if st != nil {
			out = append(out, podSpec{st, ResourceRef{Group: "apps", Kind: "StatefulSet", Namespace: st.Namespace, Name: st.Name}, &st.Spec.Template.Spec, template})
		}
	}
	for _, ds := range in.DaemonSets {
		if ds != nil {
			out = append(out, podSpec{ds, ResourceRef{Group: "apps", Kind: "DaemonSet", Namespace: ds.Namespace, Name: ds.Name}, &ds.Spec.Template.Spec, template})
		}
	}
	for _, j := range in.Jobs {
		if j != nil && !w.sameAsTemplate(j, &j.Spec.Template.Spec) {
			out = append(out, podSpec{j, ResourceRef{Group: "batch", Kind: "Job", Namespace: j.Namespace, Name: j.Name}, &j.Spec.Template.Spec, template})
		}
	}
	for _, cj := range in.CronJobs {
		if cj != nil {
			out = append(out, podSpec{cj, ResourceRef{Group: "batch", Kind: "CronJob", Namespace: cj.Namespace, Name: cj.Name}, &cj.Spec.JobTemplate.Spec.Template.Spec, "spec.jobTemplate.spec.template.spec"})
		}
	}
	return out
}

// workloadsIncomplete is true when any workload kind could not be read.
func (in *Input) workloadsIncomplete() bool {
	return in.Pods == nil || in.Deployments == nil || in.ReplicaSets == nil || in.StatefulSets == nil ||
		in.DaemonSets == nil || in.Jobs == nil || in.CronJobs == nil
}

// flagSpec records a finding on a pod spec, naming whatever manages it.
func (r *report) flagSpec(p podSpec, level Level, title, path, impact, fix string) *Finding {
	at := p.at
	f := r.flag(level, title, &at, live(path, ""), impact, fix)
	f.ManagedBy = managerOf(p.obj)
	return f
}

// managerOf names what manages an object, from its own marks: a Flux
// HelmRelease or Kustomization, an Argo CD Application (by tracking ID, then
// instance label), or a Helm release. Nil when there is no mark.
func managerOf(o metav1.Object) *ResourceRef {
	if o == nil {
		return nil
	}
	l, a := o.GetLabels(), o.GetAnnotations()
	for _, flux := range []struct{ prefix, kind string }{{"helm.toolkit.fluxcd.io", "HelmRelease"}, {"kustomize.toolkit.fluxcd.io", "Kustomization"}} {
		if name, ns := l[flux.prefix+"/name"], l[flux.prefix+"/namespace"]; name != "" && ns != "" {
			return &ResourceRef{Group: flux.prefix, Kind: flux.kind, Namespace: ns, Name: name}
		}
	}
	if ns, name, ok := argoApplication(a["argocd.argoproj.io/tracking-id"]); ok {
		return &ResourceRef{Group: "argoproj.io", Kind: "Application", Namespace: ns, Name: name}
	}
	if name := l["argocd.argoproj.io/instance"]; name != "" {
		return &ResourceRef{Group: "argoproj.io", Kind: "Application", Name: name}
	}
	if name := a["meta.helm.sh/release-name"]; name != "" {
		// A release installed by the helm CLI, not Flux's HelmRelease kind:
		// the empty group keeps them apart.
		return &ResourceRef{Kind: "HelmRelease", Namespace: a["meta.helm.sh/release-namespace"], Name: name}
	}
	return nil
}

// argoApplication reads the Application out of an Argo CD tracking ID,
// "<app>:<group>/<kind>:<namespace>/<name>", where an Application outside
// Argo's namespace is written "<app-namespace>_<app>".
func argoApplication(id string) (namespace, name string, ok bool) {
	app, _, found := strings.Cut(id, ":")
	if !found {
		return "", "", false
	}
	if ns, n, namespaced := strings.Cut(app, "_"); namespaced {
		return ns, n, n != ""
	}
	return "", app, app != ""
}
