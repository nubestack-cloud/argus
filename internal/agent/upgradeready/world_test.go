package upgradeready

import (
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	policyv1 "k8s.io/api/policy/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// The fixtures below describe clusters the way the agent sees them: every
// inventory it collects, with ConfigMap values hashed at capture.

const hashed = "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"

func ptr[T any](v T) *T { return &v }

func om(ns, name string) metav1.ObjectMeta { return metav1.ObjectMeta{Namespace: ns, Name: name} }

func controlledBy(m *metav1.ObjectMeta, apiVersion, kind, name string) {
	m.OwnerReferences = append(m.OwnerReferences, metav1.OwnerReference{APIVersion: apiVersion, Kind: kind, Name: name, UID: types.UID("uid-" + name), Controller: ptr(true)})
}

func node(name, kubelet string, mods ...func(*corev1.Node)) *corev1.Node {
	n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"kubernetes.io/os": "linux"}}}
	n.Status.NodeInfo = corev1.NodeSystemInfo{KubeletVersion: kubelet, OperatingSystem: "linux"}
	n.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}
	for _, m := range mods {
		m(n)
	}
	return n
}

func notReady(n *corev1.Node) { n.Status.Conditions[0].Status = corev1.ConditionFalse }
func windows(n *corev1.Node) {
	n.Status.NodeInfo.OperatingSystem = "windows"
	n.Labels["kubernetes.io/os"] = "windows"
}
func gkePool(n *corev1.Node) {
	n.Labels["cloud.google.com/gke-nodepool"] = "default-pool"
	n.Spec.ProviderID = "gce://shop-prod/europe-west2-a/" + n.Name
}

func app(name string, mods ...func(*corev1.PodSpec)) corev1.PodSpec {
	spec := corev1.PodSpec{Containers: []corev1.Container{{Name: name, Image: "registry.example.org/" + name + ":2.4.1"}}}
	for _, m := range mods {
		m(&spec)
	}
	return spec
}

func volume(v corev1.Volume) func(*corev1.PodSpec) {
	return func(s *corev1.PodSpec) {
		s.Volumes = append(s.Volumes, v)
		s.Containers[0].VolumeMounts = append(s.Containers[0].VolumeMounts, corev1.VolumeMount{Name: v.Name, MountPath: "/mnt/" + v.Name})
	}
}

func execProbe(timeout int32) func(*corev1.PodSpec) {
	return func(s *corev1.PodSpec) {
		s.Containers[0].LivenessProbe = &corev1.Probe{ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"/bin/check"}}}, TimeoutSeconds: timeout}
	}
}

func deployment(ns, name string, spec corev1.PodSpec) *appsv1.Deployment {
	labels := map[string]string{"app": name}
	return &appsv1.Deployment{ObjectMeta: om(ns, name), Spec: appsv1.DeploymentSpec{
		Replicas: ptr(int32(2)), Selector: &metav1.LabelSelector{MatchLabels: labels},
		Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: spec},
	}}
}

// rollout gives a Deployment its ReplicaSet and running pods, as the
// controllers would.
func rollout(in *Input, d *appsv1.Deployment, pods int) {
	rs := &appsv1.ReplicaSet{ObjectMeta: om(d.Namespace, d.Name+"-6c9f8")}
	controlledBy(&rs.ObjectMeta, "apps/v1", "Deployment", d.Name)
	rs.Spec.Template = d.Spec.Template
	in.Deployments = append(in.Deployments, d)
	in.ReplicaSets = append(in.ReplicaSets, rs)
	for i := 0; i < pods; i++ {
		p := runningPod(d.Namespace, rs.Name+"-"+string(rune('a'+i)), d.Spec.Template.Labels, d.Spec.Template.Spec)
		controlledBy(&p.ObjectMeta, "apps/v1", "ReplicaSet", rs.Name)
		in.Pods = append(in.Pods, p)
	}
}

func runningPod(ns, name string, labels map[string]string, spec corev1.PodSpec) *corev1.Pod {
	p := &corev1.Pod{ObjectMeta: om(ns, name), Spec: spec}
	p.Labels = labels
	p.Spec.NodeName = "worker-1"
	p.Status.Phase = corev1.PodRunning
	p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	return p
}

func mirrorPod(name, container string, args ...string) *corev1.Pod {
	p := runningPod("kube-system", name, map[string]string{"component": container}, corev1.PodSpec{Containers: []corev1.Container{{Name: container, Image: "registry.k8s.io/" + container + ":v1.36.2", Command: append([]string{container}, args...)}}})
	p.Annotations = map[string]string{corev1.MirrorPodAnnotationKey: "f1d2d2f924e986ac86fdf7b36c94bcdf32beec15"}
	return p
}

func kubeProxy(image string, args ...string) *appsv1.DaemonSet {
	ds := &appsv1.DaemonSet{ObjectMeta: om("kube-system", "kube-proxy")}
	ds.Labels = map[string]string{"k8s-app": "kube-proxy"}
	ds.Spec.Template.Spec.Containers = []corev1.Container{{Name: "kube-proxy", Image: image, Command: append([]string{"/usr/local/bin/kube-proxy"}, args...)}}
	return ds
}

func service(ns, name string, mods ...func(*corev1.Service)) *corev1.Service {
	s := &corev1.Service{ObjectMeta: om(ns, name), Spec: corev1.ServiceSpec{Selector: map[string]string{"app": name}, Ports: []corev1.ServicePort{{Port: 443, TargetPort: intstr.FromInt32(8443)}}}}
	for _, m := range mods {
		m(s)
	}
	return s
}

func endpoints(ns, svc string, ready bool) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: svc + "-x7k2p", Labels: map[string]string{discoveryv1.LabelServiceName: svc}},
		Endpoints:  []discoveryv1.Endpoint{{Addresses: []string{"10.42.1.17"}, Conditions: discoveryv1.EndpointConditions{Ready: ptr(ready)}}},
	}
}

func budget(ns, name string, app string, allowed, healthy, expected int32) *policyv1.PodDisruptionBudget {
	pdb := &policyv1.PodDisruptionBudget{ObjectMeta: om(ns, name), Spec: policyv1.PodDisruptionBudgetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": app}}}}
	pdb.Generation, pdb.Status.ObservedGeneration = 3, 3
	pdb.Status.DisruptionsAllowed, pdb.Status.CurrentHealthy, pdb.Status.DesiredHealthy, pdb.Status.ExpectedPods = allowed, healthy, healthy, expected
	return pdb
}

func obj(apiVersion, kind, ns, name string, fields map[string]any) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{"apiVersion": apiVersion, "kind": kind}}
	for k, v := range fields {
		u.Object[k] = v
	}
	u.SetNamespace(ns)
	u.SetName(name)
	return u
}

func webhookConfig(kind, name string, hooks ...map[string]any) *unstructured.Unstructured {
	list := make([]any, len(hooks))
	for i, h := range hooks {
		list[i] = h
	}
	return obj("admissionregistration.k8s.io/v1", kind, "", name, map[string]any{"webhooks": list})
}

func hook(name string, fields map[string]any) map[string]any {
	h := map[string]any{"name": name, "matchPolicy": "Equivalent", "failurePolicy": "Fail"}
	for k, v := range fields {
		h[k] = v
	}
	return h
}

func backend(ns, svc string) map[string]any {
	return map[string]any{"service": map[string]any{"namespace": ns, "name": svc}}
}

func conversionCRD(name string, client map[string]any, served ...string) *unstructured.Unstructured {
	var versions []any
	for i, v := range served {
		versions = append(versions, map[string]any{"name": v, "served": true, "storage": i == len(served)-1})
	}
	spec := map[string]any{"versions": versions, "conversion": map[string]any{"strategy": "Webhook", "webhook": map[string]any{"clientConfig": client}}}
	return obj("apiextensions.k8s.io/v1", "CustomResourceDefinition", "", name, map[string]any{"spec": spec})
}

func apiService(name string, delegated bool, status string) *unstructured.Unstructured {
	spec := map[string]any{"group": "metrics.k8s.io"}
	if delegated {
		spec["service"] = map[string]any{"namespace": "kube-system", "name": "metrics-server"}
	}
	fields := map[string]any{"spec": spec}
	if status != "" {
		fields["status"] = map[string]any{"conditions": []any{map[string]any{"type": "Available", "status": status, "reason": "FailedDiscoveryCheck", "message": "failing or missing response from https://10.43.0.9:443"}}}
	}
	return obj("apiregistration.k8s.io/v1", "APIService", "", name, fields)
}

func promRule(ns, name string, exprs ...string) *unstructured.Unstructured {
	var rules []any
	for _, e := range exprs {
		rules = append(rules, map[string]any{"alert": "A", "expr": e})
	}
	return obj("monitoring.coreos.com/v1", "PrometheusRule", ns, name, map[string]any{"spec": map[string]any{"groups": []any{map[string]any{"name": "g", "rules": rules}}}})
}

// calm is a self-managed cluster at 1.36 with nothing wrong in anything the
// agent can see.
func calm() *Input {
	in := &Input{
		Nodes:                             []*corev1.Node{node("cp-1", "v1.36.2"), node("worker-1", "v1.36.2"), node("worker-2", "v1.36.1")},
		DaemonSets:                        []*appsv1.DaemonSet{kubeProxy("registry.k8s.io/kube-proxy:v1.36.2", "--proxy-mode=nftables")},
		StatefulSets:                      []*appsv1.StatefulSet{},
		Jobs:                              []*batchv1.Job{},
		CronJobs:                          []*batchv1.CronJob{},
		Services:                          []*corev1.Service{service("shop", "web"), service("policy", "gatekeeper"), service("kube-system", "metrics-server")},
		ConfigMaps:                        []*corev1.ConfigMap{{ObjectMeta: om("shop", "web-flags"), Data: map[string]string{"flags": hashed}}},
		PersistentVolumeClaims:            []*corev1.PersistentVolumeClaim{},
		PersistentVolumes:                 []*corev1.PersistentVolume{},
		PodDisruptionBudgets:              []*policyv1.PodDisruptionBudget{budget("shop", "web", "web", 1, 2, 2)},
		EndpointSlices:                    []*discoveryv1.EndpointSlice{endpoints("shop", "web", true), endpoints("policy", "gatekeeper", true), endpoints("kube-system", "metrics-server", true)},
		CSIDrivers:                        []*storagev1.CSIDriver{},
		Events:                            []*corev1.Event{},
		AdmissionWebhookConfigurations:    []*unstructured.Unstructured{webhookConfig("ValidatingWebhookConfiguration", "gatekeeper", hook("check.gatekeeper.sh", map[string]any{"clientConfig": backend("policy", "gatekeeper")}))},
		CustomResourceDefinitions:         []*unstructured.Unstructured{},
		APIServices:                       []*unstructured.Unstructured{apiService("v1beta1.metrics.k8s.io", true, "True"), apiService("v1.apps", false, "True")},
		PrometheusRules:                   []*unstructured.Unstructured{promRule("monitoring", "nodes", `up{job="node"} == 0`)},
		PrometheusRulesInstalled:          true,
		PrometheusRulesDiscoveryAvailable: true,
		Platform:                          PlatformKubernetes,
	}
	in.WebhookServices = in.Services
	rollout(in, deployment("shop", "web", app("web")), 2)
	in.Pods = append(in.Pods,
		mirrorPod("kube-apiserver-cp-1", "kube-apiserver", "--enable-admission-plugins=NodeRestriction"),
		mirrorPod("kube-controller-manager-cp-1", "kube-controller-manager"),
		mirrorPod("kube-scheduler-cp-1", "kube-scheduler"),
	)
	return in
}

// troubled is calm with one of nearly everything wrong.
func troubled() *Input {
	in := calm()
	in.Nodes = append(in.Nodes, node("worker-3", "v1.31.9", notReady))
	in.DaemonSets[0] = kubeProxy("registry.k8s.io/kube-proxy:v1.31.9", "--proxy-mode=ipvs")

	rollout(in, deployment("shop", "docs", app("docs", volume(corev1.Volume{Name: "site", VolumeSource: corev1.VolumeSource{GitRepo: &corev1.GitRepoVolumeSource{Repository: "https://git.example.org/docs.git"}}}))), 1)
	legacy := deployment("ops", "nfs-reader", app("reader", volume(corev1.Volume{Name: "share", VolumeSource: corev1.VolumeSource{FlexVolume: &corev1.FlexVolumeSource{Driver: "example.io/nfs"}}})))
	legacy.Labels = map[string]string{"helm.toolkit.fluxcd.io/name": "readers", "helm.toolkit.fluxcd.io/namespace": "flux-system"}
	rollout(in, legacy, 1)
	in.PersistentVolumes = append(in.PersistentVolumes, &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "pv-flex"}, Spec: corev1.PersistentVolumeSpec{PersistentVolumeSource: corev1.PersistentVolumeSource{FlexVolume: &corev1.FlexPersistentVolumeSource{Driver: "example.io/nfs"}}}})
	in.Services = append(in.Services, service("shop", "legacy-lb", func(s *corev1.Service) { s.Spec.ExternalIPs = []string{"203.0.113.10", "203.0.113.11"} }))

	// Drain: a bare pod with scratch space, a budget at zero, two budgets
	// over the same pods, one budget the controller has not caught up with.
	bare := runningPod("shop", "debug-shell", map[string]string{"app": "debug"}, app("shell", volume(corev1.Volume{Name: "scratch", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}})))
	in.Pods = append(in.Pods, bare)
	rollout(in, deployment("shop", "cart", app("cart")), 2)
	in.PodDisruptionBudgets = append(in.PodDisruptionBudgets,
		budget("shop", "cart-strict", "cart", 0, 2, 2),
		budget("shop", "cart-loose", "cart", 1, 2, 2),
		func() *policyv1.PodDisruptionBudget {
			b := budget("shop", "docs", "docs", 1, 1, 1)
			b.Generation = 4
			return b
		}(),
	)

	in.AdmissionWebhookConfigurations = append(in.AdmissionWebhookConfigurations,
		webhookConfig("MutatingWebhookConfiguration", "injector",
			hook("inject.mesh.io", map[string]any{"matchPolicy": "Exact", "clientConfig": backend("mesh", "injector")}),
			hook("soft.mesh.io", map[string]any{"failurePolicy": "Ignore", "clientConfig": backend("shop", "web-gone")}),
			hook("remote.example.org", map[string]any{"clientConfig": map[string]any{"url": "https://hooks.example.org/validate"}}),
			hook("authn.example.org", map[string]any{"clientConfig": backend("shop", "web"), "rules": []any{map[string]any{"apiGroups": []any{"authentication.k8s.io"}, "resources": []any{"tokenreviews"}, "operations": []any{"CREATE"}}}}),
		))
	in.CustomResourceDefinitions = append(in.CustomResourceDefinitions,
		conversionCRD("widgets.example.org", backend("shop", "widget-converter"), "v1alpha1", "v1"),
		conversionCRD("gadgets.example.org", backend("shop", "gadget-converter"), "v1"),
		conversionCRD("remote.example.org", map[string]any{"url": "https://convert.example.org"}, "v1"),
		conversionCRD("broken.example.org", map[string]any{"service": map[string]any{"name": "nameless"}}, "v1beta1", "v1"),
	)
	in.APIServices = append(in.APIServices, apiService("v1beta1.custom.metrics.k8s.io", true, "False"), apiService("v1.external.example.org", true, ""))
	in.PrometheusRules = append(in.PrometheusRules,
		promRule("monitoring", "storage", `rate(volume_operation_total_errors[5m]) > 0`, `etcd_bookmark_counts > 5`),
		promRule("monitoring", "dra", `increase(resourceclaim_controller_creates_total[1h]) > 10`, `container_tasks_state{state="iowaiting"} > 0`, `sum(container_application_requests_total) by (pod)`),
	)
	in.Pods = append(in.Pods[:0:0], in.Pods...)
	for i, p := range in.Pods {
		switch p.Name {
		case "kube-apiserver-cp-1":
			in.Pods[i] = mirrorPod(p.Name, "kube-apiserver", "--feature-gates=SidecarContainers=true,HostnameOverride=false,RelaxedServiceNameValidation=true", "--enable-admission-plugins=NodeRestriction,PodGroupWorkloadExists")
		case "kube-controller-manager-cp-1":
			in.Pods[i] = mirrorPod(p.Name, "kube-controller-manager", "--concurrent-service-syncs", "5", "--feature-gates", "DRAPrioritizedList=false")
		}
	}
	in.ConfigMaps = append(in.ConfigMaps, &corev1.ConfigMap{ObjectMeta: om("kube-system", "kubeadm-config"), Data: map[string]string{"ClusterConfiguration": hashed}})
	return in
}

// googleCluster is calm on GKE: a managed control plane and exec probes, one
// of them already timing out.
func googleCluster() *Input {
	in := calm()
	for _, n := range in.Nodes {
		gkePool(n)
	}
	in.Platform = PlatformGKE
	in.Pods = in.Pods[:2] // no control-plane mirror pods on GKE
	rollout(in, deployment("shop", "worker", app("worker", execProbe(0))), 1)
	rollout(in, deployment("shop", "indexer", app("indexer", execProbe(1))), 1)
	rollout(in, deployment("shop", "patient", app("patient", execProbe(5))), 1)
	in.Events = append(in.Events, &corev1.Event{
		ObjectMeta:     om("shop", "worker-6c9f8-a.17e3"),
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Namespace: "shop", Name: "worker-6c9f8-a"},
		Reason:         "Unhealthy", Message: "Liveness probe failed: command timed out: \"/bin/check\" timed out after 1s",
		LastTimestamp: metav1.NewTime(time.Date(2026, 10, 19, 22, 0, 0, 0, time.UTC)),
	})
	return in
}

// proxyVariants carries the kube-proxy shapes the mode check must tell apart.
func proxyVariants() *Input {
	in := calm()
	viaConfig := kubeProxy("registry.k8s.io/kube-proxy:v1.36.2", "--config=/var/lib/kube-proxy/config.conf")
	viaConfig.Name = "kube-proxy-config"
	viaConfig.Spec.Template.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "cfg", MountPath: "/var/lib/kube-proxy"}}
	viaConfig.Spec.Template.Spec.Volumes = []corev1.Volume{{Name: "cfg", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "kube-proxy"}}}}}
	in.ConfigMaps = append(in.ConfigMaps, &corev1.ConfigMap{ObjectMeta: om("kube-system", "kube-proxy"), Data: map[string]string{"config.conf": hashed}})
	implicit := kubeProxy("registry.k8s.io/kube-proxy:v1.36.2")
	implicit.Name = "kube-proxy-implicit"
	win := kubeProxy("sigwindowstools/kube-proxy:v1.36.2-calico-hostprocess")
	win.Name = "kube-proxy-windows"
	win.Spec.Template.Spec.NodeSelector = map[string]string{"kubernetes.io/os": "windows"}
	odd := kubeProxy("registry.k8s.io/kube-proxy:v1.36.2", "--proxy-mode", "userspace")
	odd.Name = "kube-proxy-odd"
	unmounted := kubeProxy("registry.k8s.io/kube-proxy:v1.36.2", "--config=/etc/kube-proxy.yaml")
	unmounted.Name = "kube-proxy-unmounted"
	sidecar := kubeProxy("registry.k8s.io/kube-proxy:v1.36.2")
	sidecar.Name = "kube-proxy-sidecar"
	sidecar.Spec.Template.Spec.Containers = []corev1.Container{{Name: "proxy", Image: "x:1"}, {Name: "agent", Image: "y:1"}}
	in.DaemonSets = []*appsv1.DaemonSet{viaConfig, implicit, win, odd, unmounted, sidecar}
	return in
}

// staticProxy runs kube-proxy as a mirror pod instead of a DaemonSet.
func staticProxy() *Input {
	in := calm()
	in.DaemonSets = []*appsv1.DaemonSet{}
	in.Pods = append(in.Pods, mirrorPod("kube-proxy-worker-1", "kube-proxy", "--proxy-mode=iptables"), mirrorPod("kube-proxy-worker-2", "kube-proxy"))
	return in
}

// sharedVolumes has Linux pods sharing persistent volumes in ways the 1.37
// SELinux mount change cares about.
func sharedVolumes() *Input {
	in := calm()
	in.CSIDrivers = []*storagev1.CSIDriver{
		{ObjectMeta: metav1.ObjectMeta{Name: "rbd.csi.ceph.com"}, Spec: storagev1.CSIDriverSpec{SELinuxMount: ptr(true)}},
		{ObjectMeta: metav1.ObjectMeta{Name: "nfs.csi.k8s.io"}, Spec: storagev1.CSIDriverSpec{SELinuxMount: ptr(false)}},
	}
	pv := func(name, driver string, mode corev1.PersistentVolumeAccessMode) *corev1.PersistentVolume {
		return &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: corev1.PersistentVolumeSpec{
			AccessModes:            []corev1.PersistentVolumeAccessMode{mode},
			PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: driver, VolumeHandle: name}},
		}}
	}
	claim := func(ns, name, pvName string) *corev1.PersistentVolumeClaim {
		return &corev1.PersistentVolumeClaim{ObjectMeta: om(ns, name), Spec: corev1.PersistentVolumeClaimSpec{VolumeName: pvName}}
	}
	in.PersistentVolumes = []*corev1.PersistentVolume{
		pv("pv-shared", "rbd.csi.ceph.com", corev1.ReadWriteMany),
		pv("pv-labels", "rbd.csi.ceph.com", corev1.ReadWriteMany),
		pv("pv-solo", "rbd.csi.ceph.com", corev1.ReadWriteOncePod),
		pv("pv-nfs", "nfs.csi.k8s.io", corev1.ReadWriteMany),
		pv("pv-unknown-driver", "lustre.example.org", corev1.ReadWriteMany),
	}
	in.PersistentVolumeClaims = []*corev1.PersistentVolumeClaim{
		claim("data", "shared", "pv-shared"), claim("data", "labels", "pv-labels"), claim("data", "solo", "pv-solo"),
		claim("data", "nfs", "pv-nfs"), claim("data", "lustre", "pv-unknown-driver"), claim("data", "unbound", ""),
	}
	mounting := func(name, claimName string, sc *corev1.PodSecurityContext, privileged bool) *corev1.Pod {
		spec := app(name, volume(corev1.Volume{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claimName}}}))
		spec.SecurityContext = sc
		if privileged {
			spec.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: ptr(true)}
		}
		return runningPod("data", name, nil, spec)
	}
	level := func(l string) *corev1.PodSecurityContext {
		return &corev1.PodSecurityContext{SELinuxOptions: &corev1.SELinuxOptions{Level: l}}
	}
	recursive := corev1.SELinuxChangePolicyRecursive
	in.Pods = append(in.Pods,
		mounting("writer", "shared", level("s0:c1,c2"), false),
		mounting("backup", "shared", &corev1.PodSecurityContext{SELinuxOptions: &corev1.SELinuxOptions{Level: "s0:c1,c2"}, SELinuxChangePolicy: &recursive}, false),
		mounting("label-a", "labels", level("s0:c3,c4"), false),
		mounting("label-b", "labels", level("s0:c5,c6"), false),
		mounting("loner", "solo", level("s0:c7"), false),
		mounting("nfs-a", "nfs", level("s0:c1"), false),
		mounting("lustre-a", "lustre", level("s0:c1"), false),
		mounting("waiting", "unbound", nil, false),
	)
	in.Events = append(in.Events, &corev1.Event{
		ObjectMeta: om("data", "label-a.1"), InvolvedObject: corev1.ObjectReference{APIVersion: "v1", Kind: "Pod", Namespace: "data", Name: "label-a"},
		Reason: "SELinuxLabelConflict", Message: "SELinux label s0:c3,c4 conflicts with pod data/label-b",
	})
	return in
}

// blind is what a scan sees when nothing could be listed.
func blind() *Input { return &Input{} }

// windowsOnly is calm with only Windows nodes.
func windowsOnly() *Input {
	in := calm()
	in.Nodes = []*corev1.Node{node("win-1", "v1.36.2", windows), node("win-2", "v1.36.2", windows)}
	return in
}

// partialWebhooks could read only one webhook configuration kind, and has no
// EndpointSlices to judge backends with.
func partialWebhooks() *Input {
	in := calm()
	in.AdmissionWebhookUnavailableKinds = []string{"MutatingWebhookConfiguration"}
	in.EndpointSlices = nil
	in.PrometheusRules, in.PrometheusRulesInstalled = []*unstructured.Unstructured{}, false
	return in
}

var worlds = []struct {
	name  string
	input func() *Input
}{
	{"blind", blind}, {"calm", calm}, {"troubled", troubled}, {"google", googleCluster},
	{"proxy-variants", proxyVariants}, {"static-proxy", staticProxy}, {"shared-volumes", sharedVolumes},
	{"windows-only", windowsOnly}, {"partial-webhooks", partialWebhooks},
}

var upgrades = [][2]string{
	{"1.34", "1.35"}, {"1.35", "1.36"}, {"v1.36.2", ""}, {"1.36", "1.37"}, {"1.33.4", "1.37"},
	{"1.37", "1.38"}, {"1.39", "1.40"}, {"1.36", "2.0"},
}
