package upgradeready

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Kubernetes 1.37 mounts eligible volumes with an SELinux context option by
// default instead of relabeling their files. Pods that share one volume must
// then agree on its label and on how relabeling is done, or the kubelet will
// mount it for only one of them.

// volumeUse is how one pod uses one persistent volume.
type volumeUse struct {
	pod      string // namespace/name
	policy   corev1.PodSELinuxChangePolicy
	label    string // the merged SELinux label, under MountOption
	fallback string // why the pod relabels recursively without asking to
}

func (s *scan) selinuxMounts() Check {
	r := newReport("selinux-mount-transition", "Storage", "SELinux volume labeling transition",
		"Linux Pods, persistent volumes, CSI drivers, kubelet metrics, and Events",
		"No workload conflict with Kubernetes 1.37's SELinux mount behaviour was found.").since("1.37").citing(docSELinux)
	in := s.in
	// The SELinuxMount opt-out exists for a 1.37 target only.
	optOut := s.to.Major() == 1 && s.to.Minor() == 37

	uses, eligible, incomplete := s.persistentVolumeUses(r, optOut)
	r.Inspected = eligible
	for _, pv := range slices.Sorted(maps.Keys(uses)) {
		sharedVolume(r, pv, uses[pv], optOut)
	}
	if r.found() > 0 {
		r.caveat("Whether the affected nodes enforce SELinux could not be confirmed; these findings do not apply where SELinux is disabled.")
	}
	if in.Events == nil {
		r.caveat("Events could not be read, so SELinux conflicts already reported were not looked for.")
	} else {
		selinuxEvents(r, in.Events, optOut)
	}
	if in.Nodes == nil {
		r.caveat("Nodes could not be read, so the kubelets' SELinux conflict metrics were not looked at.")
	} else if _, linux := linuxNodes(in.Nodes); linux > 0 {
		s.kubeletUnseen(r, fmt.Sprintf("Kubelet SELinux conflict metrics could not be read on %s.", count(linux, "Linux node", "Linux nodes")))
	}

	switch {
	case r.found() > 0:
		r.Summary = count(r.found(), "SELinux labeling signal needs", "SELinux labeling signals need") + " attention before the upgrade."
	case in.Pods == nil:
		r.caveat("Pods could not be read, so their volume use was not looked at.")
		return r.unknown("No SELinux volume conflict was found, but Pods could not be read.")
	case incomplete:
		r.caveat("Storage evidence (claims, volumes or CSI drivers) was missing for at least one Linux Pod volume.")
		return r.unknown("No SELinux volume conflict was found, but storage evidence is incomplete.")
	case eligible == 0:
		return r.notApplicable("No Linux Pod uses a persistent volume that Kubernetes 1.37's SELinux mount behaviour newly affects.")
	}
	if in.Pods == nil {
		r.caveat("Pods could not be read, so their volume use was not looked at.")
	} else if incomplete {
		r.caveat("Storage evidence (claims, volumes or CSI drivers) was missing for at least one Linux Pod volume.")
	}
	return r.Check
}

func selinuxFix(action string, optOut bool) string {
	if optOut {
		return action + " For a 1.37 target only, turning the SELinuxMount feature gate off on every kubelet postpones this change; the gate is expected to lock on in 1.38."
	}
	return action + " The SELinuxMount opt-out exists only for a 1.37 target, so this has to be resolved before upgrading to 1.38 or later."
}

func onWindows(nodes []*corev1.Node, p *corev1.Pod) bool {
	if p.Spec.OS != nil && p.Spec.OS.Name == corev1.Windows {
		return true
	}
	if p.Spec.NodeName == "" {
		return false
	}
	i := slices.IndexFunc(nodes, func(n *corev1.Node) bool { return n != nil && n.Name == p.Spec.NodeName })
	return i >= 0 && strings.EqualFold(nodes[i].Status.NodeInfo.OperatingSystem, "windows")
}

// persistentVolumeUses walks every running Linux pod's claim-backed volumes
// to the persistent volumes behind them, keeping uses the 1.37 change
// reaches. A pod mixing labels on one volume is flagged right away.
func (s *scan) persistentVolumeUses(r *report, optOut bool) (byPV map[string][]volumeUse, eligible int, incomplete bool) {
	in := s.in
	byPV = map[string][]volumeUse{}
	if in.Pods == nil {
		return byPV, 0, true
	}
	claims := map[string]*corev1.PersistentVolumeClaim{}
	for _, c := range in.PersistentVolumeClaims {
		if c != nil {
			claims[c.Namespace+"/"+c.Name] = c
		}
	}
	volumes := map[string]*corev1.PersistentVolume{}
	for _, v := range in.PersistentVolumes {
		if v != nil {
			volumes[v.Name] = v
		}
	}
	drivers := map[string]*storagev1.CSIDriver{}
	for _, d := range in.CSIDrivers {
		if d != nil {
			drivers[d.Name] = d
		}
	}
	for _, p := range in.Pods {
		if p == nil || p.DeletionTimestamp != nil || p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed || onWindows(in.Nodes, p) {
			continue
		}
		for i, v := range p.Spec.Volumes {
			var claimName string
			switch {
			case v.PersistentVolumeClaim != nil:
				claimName = v.PersistentVolumeClaim.ClaimName
			case v.Ephemeral != nil:
				claimName = p.Name + "-" + v.Name // the claim Kubernetes generates
			default:
				continue
			}
			if in.PersistentVolumeClaims == nil || in.PersistentVolumes == nil {
				incomplete = true
				continue
			}
			claim := claims[p.Namespace+"/"+claimName]
			// A generated claim belongs to the pod only if the pod controls it.
			if claim == nil || claim.Spec.VolumeName == "" || (v.Ephemeral != nil && !metav1.IsControlledBy(claim, p)) {
				incomplete = true
				continue
			}
			pv := volumes[claim.Spec.VolumeName]
			if pv == nil {
				incomplete = true
				continue
			}
			affected, known := mountOptionApplies(pv, claim, drivers, in.CSIDrivers != nil)
			if !known {
				incomplete = true
				continue
			}
			if !affected {
				continue
			}
			use, mounted, consistent := selinuxUse(p, v.Name)
			if !mounted {
				continue
			}
			eligible++
			if !consistent {
				r.flag(LevelReview, "Pod uses several SELinux labels on one volume", podRef(p.Namespace, p.Name),
					live(fmt.Sprintf("spec.volumes[%d]", i), "persistentVolume="+pv.Name),
					"On a node enforcing SELinux one volume cannot be mounted with several contexts, so the Pod can stay in ContainerCreating.",
					selinuxFix("Give every container mounting this volume the same SELinux label, or set seLinuxChangePolicy: Recursive.", optOut))
				continue
			}
			use.pod = p.Namespace + "/" + p.Name
			byPV[pv.Name] = append(byPV[pv.Name], use)
		}
	}
	return byPV, eligible, incomplete
}

// inTreeDrivers are the CSI drivers that serve in-tree volume types under
// CSI migration.
func inTreeDriver(pv *corev1.PersistentVolume) (string, bool) {
	src := pv.Spec.PersistentVolumeSource
	for _, d := range []struct {
		set    bool
		driver string
	}{
		{src.AWSElasticBlockStore != nil, "ebs.csi.aws.com"},
		{src.GCEPersistentDisk != nil, "pd.csi.storage.gke.io"},
		{src.AzureDisk != nil, "disk.csi.azure.com"},
		{src.AzureFile != nil, "file.csi.azure.com"},
		{src.Cinder != nil, "cinder.csi.openstack.org"},
		{src.VsphereVolume != nil, "csi.vsphere.vmware.com"},
		{src.PortworxVolume != nil, "pxd.portworx.com"},
	} {
		if d.set {
			return d.driver, true
		}
	}
	return "", false
}

// mountOptionApplies reports whether 1.37 newly mounts this volume with an
// SELinux context option, and whether that could be decided. Volumes only
// mounted ReadWriteOncePod already were; FC and iSCSI always support it;
// anything served by CSI does when its driver says so.
func mountOptionApplies(pv *corev1.PersistentVolume, pvc *corev1.PersistentVolumeClaim, drivers map[string]*storagev1.CSIDriver, driversRead bool) (affected, known bool) {
	modes := pvc.Spec.AccessModes
	if len(modes) == 0 {
		modes = pv.Spec.AccessModes
	}
	if !slices.ContainsFunc(modes, func(m corev1.PersistentVolumeAccessMode) bool { return m != corev1.ReadWriteOncePod }) {
		return false, true
	}
	if pv.Spec.FC != nil || pv.Spec.ISCSI != nil {
		return true, true
	}
	name, ok := inTreeDriver(pv)
	if !ok {
		if pv.Spec.CSI == nil {
			return false, true
		}
		name = pv.Spec.CSI.Driver
	}
	if !driversRead {
		return false, false
	}
	d := drivers[name]
	return d != nil && d.Spec.SELinuxMount != nil && *d.Spec.SELinuxMount, true
}

// selinuxUse works out how a pod mounts one volume: whether any container
// mounts it, the effective policy and label, and whether its containers
// agree on the label.
func selinuxUse(p *corev1.Pod, volume string) (use volumeUse, mounted, consistent bool) {
	podSC := p.Spec.SecurityContext
	use.policy = corev1.SELinuxChangePolicyMountOption
	if podSC != nil && podSC.SELinuxChangePolicy != nil {
		use.policy = *podSC.SELinuxChangePolicy
	}
	type mounter struct {
		sc      *corev1.SecurityContext
		mounts  []corev1.VolumeMount
		devices []corev1.VolumeDevice
	}
	var all []mounter
	for _, c := range slices.Concat(p.Spec.InitContainers, p.Spec.Containers) {
		all = append(all, mounter{c.SecurityContext, c.VolumeMounts, c.VolumeDevices})
	}
	for _, c := range p.Spec.EphemeralContainers {
		all = append(all, mounter{c.SecurityContext, c.VolumeMounts, c.VolumeDevices})
	}
	labels := map[string]bool{}
	users, privileged, unlabelled := 0, false, false
	for _, m := range all {
		if !slices.ContainsFunc(m.mounts, func(v corev1.VolumeMount) bool { return v.Name == volume }) &&
			!slices.ContainsFunc(m.devices, func(v corev1.VolumeDevice) bool { return v.Name == volume }) {
			continue
		}
		users++
		if m.sc != nil && m.sc.Privileged != nil && *m.sc.Privileged {
			privileged = true
			continue
		}
		opts := (*corev1.SELinuxOptions)(nil)
		if podSC != nil {
			opts = podSC.SELinuxOptions
		}
		if m.sc != nil && m.sc.SELinuxOptions != nil {
			opts = m.sc.SELinuxOptions
		}
		if opts == nil || opts.Level == "" {
			unlabelled = true
			continue
		}
		labels[strings.Join([]string{opts.User, opts.Role, opts.Type, opts.Level}, ":")] = true
	}
	switch {
	case users == 0:
		return volumeUse{}, false, true
	case privileged:
		return volumeUse{policy: corev1.SELinuxChangePolicyRecursive, fallback: "a privileged container mounts the volume"}, true, true
	case unlabelled || len(labels) == 0:
		return volumeUse{policy: corev1.SELinuxChangePolicyRecursive, fallback: "a mounting container has no explicit SELinux level"}, true, true
	}
	label, ok := mergeLabels(slices.Collect(maps.Keys(labels)))
	if !ok {
		return volumeUse{}, true, false
	}
	use.label = label
	return use, true, true
}

// mergeLabels combines SELinux labels (user:role:type:level) field by
// field; an empty field defers to another label's. They are compatible
// when no field disagrees and the result has a level.
func mergeLabels(labels []string) (string, bool) {
	var merged [4]string
	for _, l := range labels {
		parts := strings.SplitN(l, ":", 4)
		if len(parts) != 4 {
			return "", false
		}
		for i, p := range parts {
			switch {
			case merged[i] == "":
				merged[i] = p
			case p != "" && p != merged[i]:
				return "", false
			}
		}
	}
	return strings.Join(merged[:], ":"), merged[3] != ""
}

// sharedVolume flags a volume several pods mount when they disagree on how
// it is relabeled or on its label.
func sharedVolume(r *report, pv string, uses []volumeUse, optOut bool) {
	if len(uses) < 2 {
		return
	}
	policies := map[corev1.PodSELinuxChangePolicy]bool{}
	var labels, pods, fallbacks []string
	for _, u := range uses {
		policies[u.policy] = true
		if u.policy == corev1.SELinuxChangePolicyMountOption && !slices.Contains(labels, u.label) {
			labels = append(labels, u.label)
		}
		pods = append(pods, u.pod)
		if u.fallback != "" {
			fallbacks = append(fallbacks, u.pod+" ("+u.fallback+")")
		}
	}
	podList := shortList(pods, ", ")
	flag := func(title, detail, impact, fix string) {
		r.flag(LevelReview, title, &ResourceRef{Kind: "PersistentVolume", Name: pv}, live("spec.claimRef", detail), impact, selinuxFix(fix, optOut))
	}
	_, compatible := mergeLabels(labels)
	switch {
	case len(policies) > 1 && len(fallbacks) > 0:
		flag("Shared volume falls back to recursive relabeling",
			"effectivePolicies=MountOption,Recursive recursiveFallbacks="+shortList(fallbacks, ", ")+" pods="+podList,
			"If these Pods share an SELinux-enforcing node, one cannot use mount-time labeling while another asks for it, and the kubelet can refuse one of the mounts.",
			"Give every unprivileged container mounting the volume an explicit SELinux level, or set seLinuxChangePolicy: Recursive on every Pod sharing it; a privileged sharer needs Recursive.")
	case len(policies) > 1:
		flag("Shared volume mixes SELinux change policies", "policies=MountOption,Recursive pods="+podList,
			"If these Pods share an SELinux-enforcing node, their relabeling modes clash and the kubelet can refuse one of the mounts.",
			"Use one seLinuxChangePolicy on every Pod sharing this volume; Recursive when privileged and unprivileged Pods share it.")
	case policies[corev1.SELinuxChangePolicyMountOption] && !compatible:
		flag("Shared volume mixes SELinux labels", fmt.Sprintf("labels=%d pods=%s", len(labels), podList),
			"If these Pods share an SELinux-enforcing node, the volume takes one context and Pods asking for another stay in ContainerCreating.",
			"Use one SELinux label on every Pod sharing this volume, or set seLinuxChangePolicy: Recursive.")
	}
}

var selinuxReasons = []string{"SELinuxLabelConflict", "SELinuxChangePolicyConflict", "MultipleSELinuxLabels"}

// selinuxEvents flags the conflicts the selinux-warning-controller has
// already reported, once per reason and object.
func selinuxEvents(r *report, events []*corev1.Event, optOut bool) {
	seen := map[string]bool{}
	for _, e := range events {
		if e == nil || !slices.Contains(selinuxReasons, e.Reason) {
			continue
		}
		o := e.InvolvedObject
		key := strings.Join([]string{e.Reason, o.APIVersion, o.Kind, o.Namespace, o.Name}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		group, _, _ := strings.Cut(o.APIVersion, "/")
		if !strings.Contains(o.APIVersion, "/") {
			group = ""
		}
		impact := "The selinux-warning-controller reported a volume labeling conflict that can keep the workload from starting if the Pods involved land on one node."
		fix := "Use selinux_warning_controller_selinux_volume_conflict to find both Pods, then give every Pod sharing the volume the same SELinux label and seLinuxChangePolicy."
		if e.Reason == "MultipleSELinuxLabels" {
			impact = "The selinux-warning-controller reported this Pod mounting one volume more than once with different SELinux labels, which can keep it from starting."
			fix = "Compare the Pod's pod-level and container-level seLinuxOptions and give every mount of the volume the same label."
		}
		r.flag(LevelWarning, e.Reason, &ResourceRef{Group: group, Kind: o.Kind, Namespace: o.Namespace, Name: o.Name},
			Evidence{Source: "event", Path: "reason", Detail: e.Message}, impact, selinuxFix(fix, optOut))
	}
}
