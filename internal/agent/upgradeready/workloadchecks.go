package upgradeready

import (
	"fmt"
	"strings"
	"unicode"

	corev1 "k8s.io/api/core/v1"
)

const someWorkloadsUnread = "Some workload kinds could not be read, so more uses may exist."

func (s *scan) gitRepoVolumes() Check {
	r := newReport("gitrepo-volume-removed", "Workload configuration", "gitRepo volume driver disabled",
		"Pod specs across seven workload kinds", "No workload uses a gitRepo volume.").since("1.36").citing(docGitRepo)
	specs := s.podSpecs()
	r.Inspected = len(specs)
	for _, p := range specs {
		for i, v := range p.spec.Volumes {
			if v.GitRepo != nil {
				r.flagSpec(p, LevelBlocker, r.Title, fmt.Sprintf("%s.volumes[%d].gitRepo", p.prefix, i),
					"Kubernetes 1.36 turns the gitRepo volume driver off with no way back on, so Pods using it cannot start.",
					"Clone the repository into an emptyDir from an init container, and mount that emptyDir instead.")
			}
		}
	}
	if s.in.workloadsIncomplete() {
		r.caveat(someWorkloadsUnread)
	}
	return r.finish(func(n int) string {
		return count(n, "workload uses", "workloads use") + " the disabled gitRepo driver."
	},
		"Not every workload kind could be read, so gitRepo volumes could not be ruled out.")
}

const flexImpact = "Kubernetes 1.36 drops kubeadm's built-in FlexVolume setup; a kubeadm control plane needs controller-manager configuration for it by hand."

func (s *scan) flexVolumes() Check {
	r := newReport("flexvolume-kubeadm-support", "Storage", "FlexVolume upgrade exposure",
		"Pod specs and PersistentVolume sources", "No workload or PersistentVolume uses FlexVolume.").since("1.36").citing(docNotes136)
	in := s.in
	if in.managedControlPlane() {
		return r.notApplicable("The 1.36 FlexVolume change concerns kubeadm control planes only.")
	}
	nodes := 0
	for _, n := range in.Nodes {
		if n != nil {
			nodes++
		}
	}
	if nodes == 0 {
		return r.unknown("Nodes could not be read, so whether this kubeadm-only change applies is unknown.")
	}
	specs := s.podSpecs()
	r.Inspected = len(specs)
	for _, p := range specs {
		for i, v := range p.spec.Volumes {
			if v.FlexVolume != nil {
				r.flagSpec(p, LevelWarning, "Workload uses FlexVolume", fmt.Sprintf("%s.volumes[%d].flexVolume", p.prefix, i), flexImpact,
					"Move the volume to a CSI driver, or confirm the kube-controller-manager image, flag and mount FlexVolume needs before upgrading.")
			}
		}
	}
	for _, pv := range in.PersistentVolumes {
		if pv == nil {
			continue
		}
		r.Inspected++
		if pv.Spec.FlexVolume != nil {
			r.flag(LevelWarning, "PersistentVolume uses FlexVolume", &ResourceRef{Kind: "PersistentVolume", Name: pv.Name}, live("spec.flexVolume", ""), flexImpact,
				"Move this volume to CSI, or work through kubeadm's FlexVolume steps before upgrading.")
		}
	}
	if in.workloadsIncomplete() || in.PersistentVolumes == nil {
		r.caveat("Some workloads or PersistentVolumes could not be read, so more FlexVolume use may exist.")
	}
	return r.finish(func(n int) string {
		return count(n, "FlexVolume use needs", "FlexVolume uses need") + " attention for Kubernetes 1.36."
	},
		"Not every workload or PersistentVolume could be read, so FlexVolume use could not be ruled out.")
}

func (s *scan) externalIPs() Check {
	r := newReport("service-externalips-deprecated", "Networking", "Service externalIPs deprecation",
		"Live Services", "No Service sets spec.externalIPs.").since("1.36").citing(docExternalIPs)
	if s.in.Services == nil {
		return r.unknown("Services could not be read, so spec.externalIPs was not looked at.")
	}
	for _, svc := range s.in.Services {
		if svc == nil {
			continue
		}
		r.Inspected++
		if len(svc.Spec.ExternalIPs) == 0 {
			continue
		}
		f := r.flag(LevelReview, r.Title, &ResourceRef{Kind: "Service", Namespace: svc.Namespace, Name: svc.Name},
			live("spec.externalIPs", strings.Join(svc.Spec.ExternalIPs, ", ")),
			"Kubernetes 1.36 deprecates this field as insecure, and a later release will stop honouring it.",
			"Expose the Service another way: a LoadBalancer Service, Gateway API, or anything else under explicit administrative control.")
		f.ManagedBy = managerOf(svc)
	}
	return r.finish(func(n int) string {
		return count(n, "Service uses", "Services use") + " the deprecated spec.externalIPs."
	}, "")
}

// timedOut reports whether a probe event says its command timed out.
func timedOut(message string) bool {
	m := strings.ToLower(message)
	for _, kind := range []string{"liveness", "readiness", "startup"} {
		for _, verb := range []string{"failed", "errored"} {
			if rest, ok := strings.CutPrefix(m, kind+" probe "+verb); ok && strings.Contains(rest, ": command timed out") {
				return true
			}
		}
	}
	rest, ok := strings.CutPrefix(strings.TrimLeftFunc(m, unicode.IsSpace), "probe errored and resulted in ")
	return ok && strings.Contains(rest, " state: command timed out")
}

// workloadKey names an object by kind, namespace and name.
type workloadKey struct{ kind, namespace, name string }

// timingOut lists the pods recent events show with an exec probe timing
// out, and every controller above them, so a finding on a Deployment can
// say its probe is already failing.
func (s *scan) timingOut() map[workloadKey]bool {
	out := map[workloadKey]bool{}
	in := s.in
	ownerIn := func(kind, ns, name string) (owner, bool) {
		switch kind {
		case "ReplicaSet":
			for _, rs := range in.ReplicaSets {
				if rs != nil && rs.Namespace == ns && rs.Name == name {
					return ownerOf(rs)
				}
			}
		case "Job":
			for _, j := range in.Jobs {
				if j != nil && j.Namespace == ns && j.Name == name {
					return ownerOf(j)
				}
			}
		}
		return owner{}, false
	}
	for _, e := range in.Events {
		if e == nil {
			continue
		}
		o := e.InvolvedObject
		if (o.Kind != "" && o.Kind != "Pod") || !timedOut(e.Message) {
			continue
		}
		out[workloadKey{"Pod", o.Namespace, o.Name}] = true
		for _, p := range in.Pods {
			if p == nil || p.Namespace != o.Namespace || p.Name != o.Name {
				continue
			}
			if up, ok := ownerOf(p); ok {
				out[workloadKey{up.kind, o.Namespace, up.name}] = true
				if top, ok := ownerIn(up.kind, o.Namespace, up.name); ok {
					out[workloadKey{top.kind, o.Namespace, top.name}] = true
				}
			}
			break
		}
	}
	return out
}

// gkeExecProbes: GKE 1.35 starts enforcing exec probe timeouts, so a probe
// leaning on the one-second default can start failing.
func (s *scan) gkeExecProbes() Check {
	r := newReport("gke-exec-probe-timeout", "Managed Kubernetes", "GKE exec probe timeout exposure",
		"Workload probes and recent Kubernetes Events", "No GKE exec probe relies on the one-second default timeout.").since("1.35").citing(docGKEExecProbes)
	in := s.in
	switch platform := strings.ToLower(strings.TrimSpace(in.Platform)); {
	case platform == "" || platform == "unknown":
		return r.unknown("The cluster's platform could not be detected, so whether this GKE-only change applies is unknown.")
	case !strings.Contains(platform, "gke") && !strings.Contains(platform, "google"):
		return r.notApplicable("This cluster does not run on GKE.")
	}
	incomplete := in.workloadsIncomplete()
	if incomplete {
		r.caveat("Some workload kinds could not be read, so more exec probes may exist.")
	}
	failing := s.timingOut()
	exec := 0
	for _, p := range s.podSpecs() {
		for _, group := range []struct {
			field string
			list  []corev1.Container
		}{{"initContainers", p.spec.InitContainers}, {"containers", p.spec.Containers}} {
			for _, c := range group.list {
				for _, probe := range []struct {
					field string
					p     *corev1.Probe
				}{{"livenessProbe", c.LivenessProbe}, {"readinessProbe", c.ReadinessProbe}, {"startupProbe", c.StartupProbe}} {
					if probe.p == nil || probe.p.Exec == nil {
						continue
					}
					exec++
					r.Inspected++
					if probe.p.TimeoutSeconds > 1 {
						continue
					}
					path := fmt.Sprintf("%s.%s[%s].%s.timeoutSeconds", p.prefix, group.field, c.Name, probe.field)
					fix := "Measure how long the command normally takes, set timeoutSeconds above 1 with room to spare, and check the probe still behaves."
					if failing[workloadKey{p.at.Kind, p.at.Namespace, p.at.Name}] {
						r.flagSpec(p, LevelBlocker, "Exec probe already timing out", path,
							"Recent events show this exec probe timing out: the GKE change is already visible here.", fix)
					} else {
						r.flagSpec(p, LevelReview, "Exec probe relies on the one-second default timeout", path,
							"This exec probe uses the one-second default and may start failing once GKE 1.35 enforces it.", fix)
					}
				}
			}
		}
	}
	if r.found() > 0 {
		if in.Events == nil {
			r.caveat("Events could not be read, so probes already timing out could not be told apart from ones that only might.")
		}
		r.Summary = count(r.found(), "GKE exec probe relies", "GKE exec probes rely") + " on a one-second timeout."
		return r.Check
	}
	switch {
	case incomplete:
		return r.unknown("No exposed GKE exec probe was found in the workloads read, but not every workload kind could be read.")
	case exec > 0:
		r.caveat("Check how long the probes really take, in staging or in longer-lived logs, before upgrading.")
		return r.unknown("Every exec probe sets a timeout, but configuration and short-lived events cannot prove the commands finish within it.")
	}
	return r.Check
}
