package upgradeready

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
)

// argv is a container's command line, each word remembering whether it came
// from command or args, since a finding's evidence path names which.
type argv []struct{ word, field string }

func commandLine(c corev1.Container) argv {
	var out argv
	for _, w := range c.Command {
		out = append(out, struct{ word, field string }{w, "command"})
	}
	for _, w := range c.Args {
		out = append(out, struct{ word, field string }{w, "args"})
	}
	return out
}

// setting is one occurrence of a flag: its value and where it was written.
type setting struct{ value, field string }

// flag returns every occurrence of a flag written "--name=value" or
// "--name value". A bare "--name" with nothing after it, or followed by
// another flag, is returned with an empty value when bare is set and
// skipped otherwise.
func (a argv) flag(name string, bare bool) []setting {
	var out []setting
	for i := 0; i < len(a); i++ {
		w := a[i]
		if v, ok := strings.CutPrefix(w.word, name+"="); ok {
			out = append(out, setting{v, w.field})
			continue
		}
		if w.word != name {
			continue
		}
		if i+1 < len(a) && !strings.HasPrefix(a[i+1].word, "--") {
			out = append(out, setting{a[i+1].word, w.field})
			i++
		} else if bare {
			out = append(out, setting{"", w.field})
		}
	}
	return out
}

func (a argv) first(name string) (setting, bool) {
	if s := a.flag(name, false); len(s) > 0 {
		return s[0], true
	}
	return setting{}, false
}

// featureGates reads every --feature-gates occurrence into gate → setting;
// a later mention of a gate wins.
func (a argv) featureGates() map[string]setting {
	out := map[string]setting{}
	for _, s := range a.flag("--feature-gates", false) {
		for _, entry := range strings.Split(s.value, ",") {
			if name, value, ok := strings.Cut(strings.TrimSpace(entry), "="); ok && name != "" {
				out[name] = setting{value, s.field}
			}
		}
	}
	return out
}

// gate137 is what Kubernetes 1.37 does to a feature gate: removes it, or
// locks it to a value any other setting of which is rejected.
type gate137 struct {
	locked   bool
	lockedTo bool
	cite     []Reference
}

var (
	lockedGAGates = []Reference{pr(138907, "Locked GA feature gates removed")}
	genericWork   = []Reference{pr(139520, "Scheduling feature gates folded into GenericWorkload")}

	gates137 = map[string]gate137{
		"AnonymousAuthConfigurableEndpoints":    {cite: docGateLifecycle},
		"APIServerTracing":                      {cite: lockedGAGates},
		"AnyVolumeDataSource":                   {cite: []Reference{pr(135336, "AnyVolumeDataSource feature gate removed")}},
		"AuthorizeNodeWithSelectors":            {cite: docGateLifecycle},
		"AuthorizeWithSelectors":                {cite: docGateLifecycle},
		"BtreeWatchCache":                       {cite: lockedGAGates},
		"ConsistentListFromCache":               {cite: lockedGAGates},
		"GangScheduling":                        {cite: genericWork},
		"JobBackoffLimitPerIndex":               {cite: docGateLifecycle},
		"JobPodReplacementPolicy":               {cite: docGateLifecycle},
		"JobSuccessPolicy":                      {cite: docGateLifecycle},
		"LogarithmicScaleDown":                  {cite: docGateLifecycle},
		"OrderedNamespaceDeletion":              {cite: lockedGAGates},
		"PodLifecycleSleepAction":               {cite: docGateLifecycle},
		"PodLifecycleSleepActionAllowZero":      {cite: docGateLifecycle},
		"PreventStaticPodAPIReferences":         {cite: []Reference{pr(140226, "PreventStaticPodAPIReferences removed")}},
		"RelaxedDNSSearchValidation":            {cite: []Reference{pr(139217, "RelaxedDNSSearchValidation removed")}},
		"ResilientWatchCacheInitialization":     {cite: lockedGAGates},
		"RetryGenerateName":                     {cite: lockedGAGates},
		"SchedulerQueueingHints":                {cite: docGateLifecycle},
		"SidecarContainers":                     {cite: []Reference{pr(137755, "SidecarContainers removed")}},
		"StreamingCollectionEncodingToJSON":     {cite: lockedGAGates},
		"StreamingCollectionEncodingToProtobuf": {cite: lockedGAGates},
		"StructuredAuthenticationConfiguration": {cite: docGateLifecycle},
		"WorkloadAwarePreemption":               {cite: genericWork},

		"DeclarativeValidationTakeover":           {locked: true, lockedTo: false, cite: []Reference{pr(139212, "DeclarativeValidationTakeover locked to its default")}},
		"DisableCPUQuotaWithExclusiveCPUs":        {locked: true, lockedTo: true, cite: docGateLifecycle},
		"DRAExtendedResource":                     {locked: true, lockedTo: true, cite: docGateLifecycle},
		"DRAPrioritizedList":                      {locked: true, lockedTo: true, cite: []Reference{pr(139110, "DRAPrioritizedList locked to its default")}},
		"DRAResourceClaimDeviceStatus":            {locked: true, lockedTo: true, cite: docGateLifecycle},
		"HostnameOverride":                        {locked: true, lockedTo: true, cite: []Reference{pr(139116, "HostnameOverride locked to its default")}},
		"HPAConfigurableTolerance":                {locked: true, lockedTo: true, cite: docGateLifecycle},
		"InPlacePodVerticalScalingInitContainers": {locked: true, lockedTo: true, cite: docGateLifecycle},
		"NodeDeclaredFeatures":                    {locked: true, lockedTo: true, cite: docGateLifecycle},
		"PLEGOnDemandRelist":                      {locked: true, lockedTo: true, cite: docGateLifecycle},
		"PodReadyToStartContainersCondition":      {locked: true, lockedTo: true, cite: docGateLifecycle},
		"RelaxedServiceNameValidation":            {locked: true, lockedTo: true, cite: docGateLifecycle},
		"WatchCacheInitializationPostStartHook":   {locked: true, lockedTo: true, cite: docGateLifecycle},
	}
)

var controlPlane = []string{"kube-apiserver", "kube-controller-manager", "kube-scheduler"}

// mirrorPods are the static pods the kubelet reports, which is where a
// self-managed control plane's command lines can be read.
func (in *Input) mirrorPods() []*corev1.Pod {
	var out []*corev1.Pod
	for _, p := range in.Pods {
		if p != nil && p.Annotations[corev1.MirrorPodAnnotationKey] != "" {
			out = append(out, p)
		}
	}
	return out
}

// managedControlPlane is true on platforms whose provider runs the control
// plane (GKE, EKS, AKS), where its command lines are not visible at all.
func (in *Input) managedControlPlane() bool {
	if strings.EqualFold(in.Platform, "gke-autopilot") {
		return true
	}
	for _, n := range in.Nodes {
		if n == nil {
			continue
		}
		for k := range n.Labels {
			switch {
			case k == "cloud.google.com/gke-nodepool", k == "cloud.google.com/gke-os-distribution",
				k == "eks.amazonaws.com/nodegroup", k == "eks.amazonaws.com/capacityType",
				strings.HasPrefix(k, "kubernetes.azure.com/"):
				return true
			}
		}
	}
	return false
}

const providerOwnsControlPlane = "The provider runs the control plane, so its components' settings are not visible to ARGUS."

func (s *scan) featureGates() Check {
	r := newReport("removed-feature-gates", "Component configuration", "Feature gates removed or locked in Kubernetes 1.37",
		"Effective kubelet configuration and readable control-plane mirror Pods",
		"No readable component sets a feature gate 1.37 removes or locks.").since("1.37").citing(docNotes137)
	in := s.in
	managed := in.managedControlPlane()
	nodes := 0
	for _, n := range in.Nodes {
		if n != nil {
			nodes++
		}
	}
	r.Inspected = nodes

	// Kubelets: their effective configuration needs nodes/proxy.
	if in.Nodes == nil {
		r.caveat("Nodes could not be read, so kubelet feature gates were not looked at.")
	} else if nodes > 0 {
		s.kubeletUnseen(r, fmt.Sprintf("Effective kubelet configuration could not be read on %s.", count(nodes, "node", "nodes")))
	}

	// Control-plane components: their command lines, from mirror pods.
	controlPlaneUnseen := false
	unseen := func(why string) {
		if managed {
			r.note(providerOwnsControlPlane)
		} else {
			controlPlaneUnseen = true
			r.caveat(why)
		}
	}
	seen := map[string]bool{}
	if in.Pods == nil {
		unseen("Pods could not be read, so control-plane feature gates were not looked at.")
	} else {
		for _, p := range in.mirrorPods() {
			for i, c := range p.Spec.Containers {
				if !slices.Contains(controlPlane, c.Name) {
					continue
				}
				r.Inspected++
				seen[c.Name] = true
				gates := commandLine(c).featureGates()
				for _, name := range slices.Sorted(maps.Keys(gates)) {
					judgeGate(r, p, i, c.Name, name, gates[name])
				}
			}
		}
		var missing []string
		for _, c := range controlPlane {
			if !seen[c] {
				missing = append(missing, c)
			}
		}
		switch {
		case len(seen) == 0:
			unseen("No control-plane mirror Pod could be read, so a self-managed control plane's feature gates were not looked at.")
		case len(missing) > 0:
			r.caveat("Control-plane feature gates could not be read for " + strings.Join(missing, ", ") + ".")
		}
	}

	if r.found() > 0 {
		r.Summary = count(r.found(), "feature-gate setting has", "feature-gate settings have") + " to change before the upgrade."
		return r.Check
	}
	// With nothing found, any kubelet in the picture is unverified.
	switch {
	case in.Nodes == nil:
		return r.unknown("Nodes could not be read, so kubelet feature gates are unverified.")
	case nodes > 0:
		if controlPlaneUnseen {
			return r.unknown("No incompatible feature gate was found, but neither kubelet nor control-plane settings could be read.")
		}
		return r.unknown("No incompatible feature gate was found in control-plane settings, but kubelet settings could not be read.")
	case r.Inspected == 0:
		return r.unknown("No kubelet or control-plane feature-gate settings could be read.")
	}
	return r.Check
}

func judgeGate(r *report, p *corev1.Pod, container int, component, name string, set setting) {
	g, known := gates137[name]
	if !known {
		return
	}
	ev := live(fmt.Sprintf("spec.containers[%d].%s[--feature-gates].%s", container, set.field, name), set.value)
	if !g.locked {
		f := r.flag(LevelBlocker, name+" removed", podRef(p.Namespace, p.Name), ev,
			component+" 1.37 does not know this feature gate and can refuse to start.",
			"Take "+name+" out of the component's --feature-gates before upgrading the control plane.")
		f.References = refs(g.cite)
		return
	}
	if v, err := strconv.ParseBool(set.value); err == nil && v == g.lockedTo {
		return
	}
	f := r.flag(LevelBlocker, name+" must keep its locked value", podRef(p.Namespace, p.Name), ev,
		fmt.Sprintf("Kubernetes 1.37 locks this gate to %t and %s refuses to start with anything else.", g.lockedTo, component),
		fmt.Sprintf("Set %s=%t, or drop the setting, before upgrading the control plane.", name, g.lockedTo))
	f.References = refs(g.cite)
}

func (s *scan) componentFlags() Check {
	r := newReport("removed-component-flags", "Component configuration", "Component options removed in Kubernetes 1.37",
		"Readable control-plane mirror Pods", "No readable control-plane component uses a removed flag or admission plugin.").
		since("1.37").citing(docFlags137, docPodGroupAdmit)
	in := s.in
	managed := in.managedControlPlane()
	if in.Pods == nil {
		if managed {
			return r.notApplicable(providerOwnsControlPlane)
		}
		return r.unknown("Pods could not be read, so control-plane options were not looked at.")
	}
	seen := map[string]bool{}
	for _, p := range in.mirrorPods() {
		for i, c := range p.Spec.Containers {
			args := commandLine(c)
			switch c.Name {
			case "kube-controller-manager":
				seen[c.Name] = true
				r.Inspected++
				if sets := args.flag("--concurrent-service-syncs", true); len(sets) > 0 {
					set := sets[0]
					f := r.flag(LevelBlocker, "--concurrent-service-syncs removed", podRef(p.Namespace, p.Name),
						live(fmt.Sprintf("spec.containers[%d].%s[--concurrent-service-syncs]", i, set.field), cmpOr(set.value, "set")),
						"kube-controller-manager 1.37 does not know this flag and can refuse to start.",
						"Remove --concurrent-service-syncs from kube-controller-manager's arguments before upgrading.")
					f.References = refs(docFlags137)
				}
			case "kube-apiserver":
				seen[c.Name] = true
				r.Inspected++
				for _, name := range []string{"--enable-admission-plugins", "--disable-admission-plugins"} {
					for _, set := range args.flag(name, false) {
						for _, plugin := range strings.Split(set.value, ",") {
							if strings.TrimSpace(plugin) != "PodGroupWorkloadExists" {
								continue
							}
							f := r.flag(LevelBlocker, "PodGroupWorkloadExists admission plugin removed", podRef(p.Namespace, p.Name),
								live(fmt.Sprintf("spec.containers[%d].%s[%s]", i, set.field, name), "PodGroupWorkloadExists"),
								"kube-apiserver 1.37 refuses to start when given a removed admission plugin's name.",
								"Remove PodGroupWorkloadExists from "+name+" before upgrading.")
							f.References = refs(docPodGroupAdmit)
						}
					}
				}
			}
		}
	}
	if len(seen) == 0 && managed {
		return r.notApplicable(providerOwnsControlPlane)
	}
	var missing []string
	for _, c := range []string{"kube-apiserver", "kube-controller-manager"} {
		if !seen[c] {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		r.caveat("Startup options could not be read for " + strings.Join(missing, ", ") + ".")
	}
	return r.finish(func(n int) string {
		return count(n, "removed option has", "removed options have") + " to go before the upgrade."
	}, "No removed option was found, but not every self-managed control-plane component could be read.")
}

func cmpOr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// removedCAdvisorFlags137 are the kubelet flags 1.37 no longer accepts.
var removedCAdvisorFlags137 = []string{
	"--application-metrics-count-limit", "--boot-id-file", "--container-hints", "--containerd",
	"--containerd-namespace", "--enable-load-reader", "--event-storage-age-limit", "--event-storage-event-limit",
	"--global-housekeeping-interval", "--log-cadvisor-usage", "--machine-id-file",
	"--storage-driver-user", "--storage-driver-password", "--storage-driver-host", "--storage-driver-db",
	"--storage-driver-table", "--storage-driver-secure", "--storage-driver-buffer-duration",
}

// cadvisorOptions always asks for a human: kubelet flags and direct
// cAdvisor consumers are invisible through the Kubernetes API.
func (s *scan) cadvisorOptions() Check {
	r := newReport("removed-kubelet-cadvisor-options", "Node configuration", "Kubelet cAdvisor options removed in Kubernetes 1.37",
		"Kubelet process arguments and direct cAdvisor API consumers", "Kubelet arguments and direct cAdvisor metric consumers need checking by hand.").
		since("1.37").citing(docCAdvisor137)
	r.flag(LevelReview, "Kubelet cAdvisor settings cannot be seen through the Kubernetes API", nil,
		Evidence{Source: "Kubernetes 1.37 release notes", Path: "kubelet process arguments and cAdvisor metric consumers", Detail: "manual verification required"},
		fmt.Sprintf("A 1.37 kubelet will not start with any of %d removed cAdvisor flags set. Direct consumers also lose userDefinedMetrics, the container_application_* metrics and three /metrics/cadvisor series.", len(removedCAdvisorFlags137)),
		"On every node, check the kubelet's service and bootstrap arguments and remove these flags first: "+strings.Join(removedCAdvisorFlags137, ", ")+
			". --housekeeping-interval is still supported. Check /stats/summary consumers for userDefinedMetrics, and /metrics/cadvisor consumers for container_application_*, container_cpu_load_average_10s, container_cpu_load_d_average_10s and container_tasks_state.")
	return r.Check
}

func (s *scan) schedulingAPIs() Check {
	r := newReport("removed-scheduling-apis", "API compatibility", "Scheduling APIs removed in Kubernetes 1.37",
		"Stored Workload and PodGroup objects", "").since("1.37").citing(docScheduling137)
	r.caveat("Where the API is served, run `kubectl get workloads.v1alpha2.scheduling.k8s.io,podgroups.v1alpha2.scheduling.k8s.io -A`; delete what it lists before upgrading and recreate it with scheduling.k8s.io/v1beta1 afterwards.")
	return r.unknown("scheduling.k8s.io/v1alpha2 Workload and PodGroup objects are not collected, so objects stored under the removed API could not be ruled out.")
}

// hashedAtCapture reports whether a ConfigMap value is the hash the agent's
// cache stored in place of the content.
func hashedAtCapture(v string) bool {
	h, ok := strings.CutPrefix(v, "sha256:")
	return ok && len(h) == 64
}

var removedKubeadmGates137 = map[string][]Reference{
	"NodeLocalCRISocket": {pr(138645, "NodeLocalCRISocket feature gate removed")},
	"PublicKeysECDSA":    docKubeadm137,
}

func (s *scan) kubeadmConfig() Check {
	r := newReport("kubeadm-config-v1beta3", "Cluster lifecycle", "kubeadm configuration API",
		"kube-system/kubeadm-config ConfigMap", "No kubeadm cluster configuration was found.").since("1.37").citing(docNotes137)
	r.Status = CheckNotApplicable
	if s.in.ConfigMaps == nil {
		return r.unknown("ConfigMaps could not be read, so kubeadm's configuration was not looked at.")
	}
	i := slices.IndexFunc(s.in.ConfigMaps, func(cm *corev1.ConfigMap) bool {
		return cm != nil && cm.Namespace == "kube-system" && cm.Name == "kubeadm-config"
	})
	if i < 0 {
		return r.Check
	}
	cm := s.in.ConfigMaps[i]
	r.Inspected, r.Status = 1, CheckPassed
	r.Summary = "kubeadm's stored cluster configuration does not use kubeadm.k8s.io/v1beta3."
	r.note("Only the stored kubeadm-config ConfigMap is read; configuration files passed to kubeadm with --config on control-plane hosts are not visible to ARGUS.")
	raw, present := cm.Data["ClusterConfiguration"]
	if present && hashedAtCapture(raw) {
		r.caveat("The agent hashes ConfigMap values when it captures them, so the ClusterConfiguration cannot be read here. Check its apiVersion and featureGates with `kubectl -n kube-system get configmap kubeadm-config -o yaml`.")
		return r.unknown("A kubeadm-config ConfigMap exists, but its content is not collected.")
	}
	parsed, broken := 0, false
	at := &ResourceRef{Kind: "ConfigMap", Namespace: cm.Namespace, Name: cm.Name}
	dec := k8syaml.NewYAMLOrJSONDecoder(strings.NewReader(raw), 4096)
	for doc := 0; present; doc++ {
		var o map[string]any
		if err := dec.Decode(&o); err == io.EOF {
			break
		} else if err != nil {
			broken = true
			break
		}
		if len(o) == 0 {
			continue
		}
		parsed++
		path := fmt.Sprintf("data.ClusterConfiguration.document[%d]", doc)
		if v, _, _ := unstructured.NestedString(o, "apiVersion"); v == "kubeadm.k8s.io/v1beta3" {
			f := r.flag(LevelBlocker, "kubeadm v1beta3 configuration removed", at, live(path+".apiVersion", v),
				"kubeadm 1.37 no longer reads the v1beta3 configuration API, which can stop upgrade operations that use it.",
				"With a pre-1.37 kubeadm, run kubeadm config migrate on the source file, then upload the result with kubeadm init phase upload-config kubeadm --config <file> before upgrading.")
			f.References = refs(docKubeadm137)
		}
		gates, _, _ := unstructured.NestedMap(o, "featureGates")
		for _, name := range slices.Sorted(maps.Keys(gates)) {
			if cite, removed := removedKubeadmGates137[name]; removed {
				f := r.flag(LevelBlocker, "kubeadm feature gate "+name+" removed", at, live(path+".featureGates."+name, fmt.Sprint(gates[name])),
					"kubeadm 1.37 does not know this feature gate and can reject the configuration.",
					"Remove "+name+" from kubeadm's featureGates before upgrading.")
				f.References = refs(cite)
			}
		}
	}
	incomplete := ""
	if broken || parsed == 0 {
		r.caveat("Part of the kubeadm configuration could not be parsed.")
		incomplete = "The kubeadm ConfigMap exists, but its configuration API could not be read."
	}
	return r.finish(func(n int) string {
		return count(n, "kubeadm setting has", "kubeadm settings have") + " to change before the upgrade."
	}, incomplete)
}
