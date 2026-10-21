package posture

import (
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The GitOps coverage checks. They are two so that an operator can switch
// off the softer "Helm, but not through GitOps" finding and keep the
// "nothing manages this" one.
const (
	checkGitOpsUnmanaged = "gitops-unmanaged-workload"
	checkGitOpsHelmOnly  = "gitops-helm-only-workload"
)

// management is who an object's own metadata says manages its desired state.
type management int

const (
	byNobody management = iota
	byHelm
	byGitOps
)

// managedBy reads Flux and Argo CD marks first: an Argo CD Application that
// renders a chart leaves Helm's annotation too, and Argo is what drives it.
// Under Argo's label tracking the only mark is app.kubernetes.io/instance,
// which plain Helm and kustomize installs carry as well, so that label means
// GitOps only when it names a real Application.
func managedBy(obj metav1.Object, argoApps map[string]struct{}) management {
	l, a := obj.GetLabels(), obj.GetAnnotations()
	pair := func(prefix string) bool { return l[prefix+"/name"] != "" && l[prefix+"/namespace"] != "" }
	_, argoInstance := argoApps[l["app.kubernetes.io/instance"]]
	switch {
	case pair("helm.toolkit.fluxcd.io"), pair("kustomize.toolkit.fluxcd.io"):
		return byGitOps
	case argoTrackingID(a["argocd.argoproj.io/tracking-id"]), l["argocd.argoproj.io/instance"] != "":
		return byGitOps
	case l["app.kubernetes.io/instance"] != "" && argoInstance:
		return byGitOps
	case a["meta.helm.sh/release-name"] != "":
		return byHelm
	}
	return byNobody
}

// argoTrackingID reports whether an Argo CD tracking-id annotation names an
// Application: "<app>:<group>/<kind>:<namespace>/<name>", with "<app>"
// written "<app-namespace>_<app>" for an Application outside Argo's own
// namespace.
func argoTrackingID(v string) bool {
	app, _, ok := strings.Cut(v, ":")
	if !ok {
		return false
	}
	if _, name, namespaced := strings.Cut(app, "_"); namespaced {
		app = name
	}
	return app != ""
}

// gitopsCoverage flags top-level workloads nothing in Git manages. It runs
// only on clusters that use GitOps. A workload with an owner is skipped: the
// owner's tracking marks are not copied to what it creates, so the question
// is the owner's.
func (s *scan) gitopsCoverage() {
	in := s.in
	if !in.GitOpsToolsPresent {
		return
	}
	judge := func(kind string, o metav1.Object) {
		if len(o.GetOwnerReferences()) > 0 {
			return
		}
		s.evaluated(o.GetNamespace(), checkGitOpsUnmanaged, checkGitOpsHelmOnly)
		at := object(kind, o.GetNamespace(), o.GetName())
		switch managedBy(o, in.ArgoAppNames) {
		case byHelm:
			s.flag(at, checkGitOpsHelmOnly, SeverityWarning,
				"installed by the helm CLI; upgrades skip Git review and the declarative rollback path")
		case byNobody:
			s.flag(at, checkGitOpsUnmanaged, SeverityWarning,
				"no GitOps or Helm marks; most likely applied by hand, so Git holds no record of its desired state")
		}
	}
	each(in.Deployments, "Deployment", judge)
	each(in.StatefulSets, "StatefulSet", judge)
	each(in.DaemonSets, "DaemonSet", judge)
	each(in.CronJobs, "CronJob", judge)
}
