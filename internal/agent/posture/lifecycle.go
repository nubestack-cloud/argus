package posture

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilversion "k8s.io/apimachinery/pkg/util/version"

	"argus/internal/agent/certexpiry"
)

// shortAge renders a duration in its largest whole unit: 40s, 12m, 5h, 3d.
func shortAge(d time.Duration) string {
	d = max(d, 0)
	for _, u := range []struct {
		size time.Duration
		unit string
	}{{24 * time.Hour, "d"}, {time.Hour, "h"}, {time.Minute, "m"}} {
		if d >= u.size {
			return strconv.Itoa(int(d/u.size)) + u.unit
		}
	}
	return strconv.Itoa(int(d/time.Second)) + "s"
}

// Deletion normally finishes within a minute or two. Past terminatingSlow it
// looks like a stuck finalizer; past terminatingStuck, a broken one.
const (
	terminatingSlow  = 5 * time.Minute
	terminatingStuck = 30 * time.Minute
)

// stuckTerminating flags objects deleted but still present, naming the
// finalizers holding them, which is what an operator needs to find the
// controller at fault.
func (s *scan) stuckTerminating() {
	judge := func(kind string, o metav1.Object) {
		s.evaluated(o.GetNamespace(), "stuckTerminating")
		at := o.GetDeletionTimestamp()
		if at == nil || at.IsZero() {
			return
		}
		age := s.now.Sub(at.Time)
		if age < terminatingSlow {
			return
		}
		sev := SeverityWarning
		if age >= terminatingStuck {
			sev = SeverityDanger
		}
		msg := "deleted " + shortAge(age) + " ago and still present"
		if f := o.GetFinalizers(); len(f) > 0 {
			msg += "; waiting on finalizers " + strings.Join(f, ", ")
		}
		s.flag(object(kind, o.GetNamespace(), o.GetName()), "stuckTerminating", sev, msg)
	}
	in := s.in
	each(in.Pods, "Pod", judge)
	each(in.Deployments, "Deployment", judge)
	each(in.StatefulSets, "StatefulSet", judge)
	each(in.DaemonSets, "DaemonSet", judge)
	each(in.Services, "Service", judge)
	each(in.Ingresses, "Ingress", judge)
	each(in.HorizontalPodAutoscalers, "HorizontalPodAutoscaler", judge)
	each(in.PodDisruptionBudgets, "PodDisruptionBudget", judge)
	each(in.ConfigMaps, "ConfigMap", judge)
	each(in.ServiceAccounts, "ServiceAccount", judge)
}

func each[T metav1.Object](objs []T, kind string, fn func(string, metav1.Object)) {
	for _, o := range objs {
		fn(kind, o)
	}
}

// deprecation is one API that Kubernetes deprecated and then removes.
type deprecation struct {
	groupVersion string
	kind         string // empty: every kind in the group/version
	since, gone  string
	use          string
}

// deprecations follows the Kubernetes deprecated API migration guide,
// reviewed through 1.37. Grouped by the release that removes them.
var deprecations = removedIn("1.22",
	deprecation{"extensions/v1beta1", "Ingress", "1.14", "", "networking.k8s.io/v1"},
	deprecation{"extensions/v1beta1", "DaemonSet", "1.14", "", "apps/v1"},
	deprecation{"extensions/v1beta1", "Deployment", "1.14", "", "apps/v1"},
	deprecation{"extensions/v1beta1", "ReplicaSet", "1.14", "", "apps/v1"},
	deprecation{"networking.k8s.io/v1beta1", "Ingress", "1.19", "", "networking.k8s.io/v1"},
	deprecation{"networking.k8s.io/v1beta1", "IngressClass", "1.19", "", "networking.k8s.io/v1"},
	deprecation{"rbac.authorization.k8s.io/v1beta1", "", "1.17", "", "rbac.authorization.k8s.io/v1"},
	deprecation{"coordination.k8s.io/v1beta1", "Lease", "1.19", "", "coordination.k8s.io/v1"},
).and("1.25",
	deprecation{"batch/v1beta1", "CronJob", "1.21", "", "batch/v1"},
	deprecation{"discovery.k8s.io/v1beta1", "EndpointSlice", "1.21", "", "discovery.k8s.io/v1"},
	deprecation{"events.k8s.io/v1beta1", "Event", "1.21", "", "events.k8s.io/v1"},
	deprecation{"policy/v1beta1", "PodDisruptionBudget", "1.21", "", "policy/v1"},
	deprecation{"policy/v1beta1", "PodSecurityPolicy", "1.21", "", "Pod Security Admission (no API replaces it)"},
	deprecation{"node.k8s.io/v1beta1", "RuntimeClass", "1.22", "", "node.k8s.io/v1"},
).and("1.26",
	deprecation{"autoscaling/v2beta2", "HorizontalPodAutoscaler", "1.23", "", "autoscaling/v2"},
	deprecation{"flowcontrol.apiserver.k8s.io/v1beta1", "", "1.23", "", "flowcontrol.apiserver.k8s.io/v1beta3"},
).and("1.27",
	deprecation{"storage.k8s.io/v1beta1", "CSIStorageCapacity", "1.24", "", "storage.k8s.io/v1"},
).and("1.29",
	deprecation{"flowcontrol.apiserver.k8s.io/v1beta2", "", "1.26", "", "flowcontrol.apiserver.k8s.io/v1"},
).and("1.32",
	deprecation{"flowcontrol.apiserver.k8s.io/v1beta3", "", "1.29", "", "flowcontrol.apiserver.k8s.io/v1"},
).and("1.37",
	deprecation{"scheduling.k8s.io/v1alpha2", "Workload", "1.36", "", "scheduling.k8s.io/v1beta1"},
	deprecation{"scheduling.k8s.io/v1alpha2", "PodGroup", "1.36", "", "scheduling.k8s.io/v1beta1"},
)

type deprecationTable []deprecation

func removedIn(release string, ds ...deprecation) deprecationTable {
	return deprecationTable(nil).and(release, ds...)
}

func (t deprecationTable) and(release string, ds ...deprecation) deprecationTable {
	for _, d := range ds {
		d.gone = release
		t = append(t, d)
	}
	return t
}

// deprecatedAPIs flags each served group/version that is deprecated as of
// the cluster's version. A served group/version is one subject, however many
// of its kinds are deprecated. An unparseable cluster version cannot rule a
// deprecation out, so every entry for a served version counts.
func (s *scan) deprecatedAPIs() {
	if len(s.in.ServedAPIs) == 0 || s.in.ClusterVersion == "" {
		return
	}
	current, err := utilversion.ParseGeneric(strings.TrimPrefix(strings.TrimSpace(s.in.ClusterVersion), "v"))
	for _, gv := range s.in.ServedAPIs {
		s.evaluated("", "deprecatedAPIVersion")
		for _, d := range deprecations {
			if d.groupVersion != gv || (err == nil && current.LessThan(utilversion.MustParseGeneric(d.since))) {
				continue
			}
			what := gv
			if d.kind != "" {
				what += " " + d.kind
			}
			s.flag(subject{kind: "APIVersion", name: gv}, "deprecatedAPIVersion", SeverityDanger,
				fmt.Sprintf("%s: deprecated in %s, removed in %s; use %s", what, d.since, d.gone, d.use))
		}
	}
}

// claimBindWindow is how long a claim may sit Pending before it counts as
// stuck; it matches the sweep detector's sustained-fault threshold.
const claimBindWindow = 10 * time.Minute

func (s *scan) pendingClaims() {
	for _, pvc := range s.in.PersistentVolumeClaims {
		s.evaluated(pvc.Namespace, "pvcPending")
		created := pvc.CreationTimestamp
		if pvc.Status.Phase != corev1.ClaimPending || created.IsZero() {
			continue
		}
		if age := s.now.Sub(created.Time); age >= claimBindWindow {
			s.flag(object("PersistentVolumeClaim", pvc.Namespace, pvc.Name), "pvcPending", SeverityDanger,
				"Pending for "+shortAge(age))
		}
	}
}

// unusedClaims flags Bound claims no pod mounts. Any pod counts, finished
// or not: a mount is a reference.
func (s *scan) unusedClaims() {
	mounted := map[NamespacedRef]bool{}
	for _, p := range s.in.Pods {
		for _, v := range p.Spec.Volumes {
			if v.PersistentVolumeClaim != nil {
				mounted[NamespacedRef{p.Namespace, v.PersistentVolumeClaim.ClaimName}] = true
			}
		}
	}
	for _, pvc := range s.in.PersistentVolumeClaims {
		if pvc.Status.Phase != corev1.ClaimBound {
			continue
		}
		s.evaluated(pvc.Namespace, "orphanPVC")
		if !mounted[NamespacedRef{pvc.Namespace, pvc.Name}] {
			s.flag(object("PersistentVolumeClaim", pvc.Namespace, pvc.Name), "orphanPVC", SeverityWarning,
				"Bound, but no pod mounts it")
		}
	}
}

// volumePhases flags Released volumes (housekeeping: the claim is gone and
// a Retain policy kept the data) and Failed ones (a real fault).
func (s *scan) volumePhases() {
	for _, pv := range s.in.PersistentVolumes {
		s.evaluated("", "pvReleasedOrFailed")
		at := object("PersistentVolume", "", pv.Name)
		switch pv.Status.Phase {
		case corev1.VolumeReleased:
			s.flag(at, "pvReleasedOrFailed", SeverityWarning, "Released: its claim was deleted, and the volume (with its data, under Retain) is still here")
		case corev1.VolumeFailed:
			msg := "Failed"
			if pv.Status.Message != "" {
				msg += ": " + pv.Status.Message
			}
			s.flag(at, "pvReleasedOrFailed", SeverityDanger, msg)
		}
	}
}

// certificates reports cert-manager Certificates on certexpiry's own grade:
// degraded within 30 days is a warning, unhealthy within 7 is danger.
// Probed serving certificates are another source with their own tab.
func (s *scan) certificates() {
	for _, c := range s.in.Certificates {
		if c.Source != certexpiry.SourceCertManager {
			continue
		}
		s.evaluated(c.Namespace, "certificateExpiry")
		var sev string
		switch c.Health {
		case certexpiry.HealthDegraded:
			sev = SeverityWarning
		case certexpiry.HealthUnhealthy:
			sev = SeverityDanger
		default:
			continue
		}
		when := "with an unknown number of days left"
		switch d := c.DaysLeft; {
		case d == nil:
		case *d < 0:
			when = "and has already expired"
		default:
			when = fmt.Sprintf("with %d days left", *d)
		}
		s.flag(subject{"cert-manager.io", "Certificate", c.Namespace, c.Name}, "certificateExpiry", sev,
			fmt.Sprintf("certificate for %s expires %s %s", c.Domains, c.Expiry, when))
	}
}

// crossplane flags claims and composites reporting Ready=False. One with no
// Ready condition yet is unknown, not failing.
func (s *scan) crossplane() {
	if !s.in.CrossplaneCRDsPresent {
		return
	}
	for _, o := range s.in.CrossplaneObjects {
		s.evaluated(o.Namespace, "crossplaneNotReady")
		if o.Ready == nil || *o.Ready {
			continue
		}
		kind := o.Kind
		if kind == "" {
			kind = "CompositeResource"
		}
		msg := "Ready is False"
		if o.Message != "" {
			msg += ": " + o.Message
		}
		s.flag(subject{o.Group, kind, o.Namespace, o.Name}, "crossplaneNotReady", SeverityDanger, msg)
	}
}
