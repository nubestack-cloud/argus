package posture

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// configRef identifies a ConfigMap or Secret.
type configRef struct{ Kind, Namespace, Name string }

// refSet accumulates the ConfigMaps and Secrets something refers to.
type refSet map[configRef]bool

func (r refSet) add(kind, namespace, name string) {
	if namespace != "" && name != "" {
		r[configRef{kind, namespace, name}] = true
	}
}

// liveSpecs are the pod specs whose references keep a ConfigMap or Secret in
// use: workload templates, CronJob templates, and pods and Jobs that have not
// finished.
func (in *CheckInput) liveSpecs() []template {
	var out []template
	for _, p := range in.Pods {
		if p.Status.Phase != corev1.PodSucceeded && p.Status.Phase != corev1.PodFailed {
			out = append(out, template{subject{namespace: p.Namespace}, &p.Spec})
		}
	}
	for _, t := range in.templates() {
		if t.at.kind != "Pod" {
			out = append(out, t)
		}
	}
	for _, j := range in.Jobs {
		if !finished(j) {
			out = append(out, template{subject{namespace: j.Namespace}, &j.Spec.Template.Spec})
		}
	}
	for _, cj := range in.CronJobs {
		out = append(out, template{subject{namespace: cj.Namespace}, &cj.Spec.JobTemplate.Spec.Template.Spec})
	}
	return out
}

func finished(j *batchv1.Job) bool {
	return slices.ContainsFunc(j.Status.Conditions, func(c batchv1.JobCondition) bool {
		return c.Status == corev1.ConditionTrue && (c.Type == batchv1.JobComplete || c.Type == batchv1.JobFailed)
	})
}

// volumeSecrets reads the Secret name each volume type that takes a
// credential can carry.
var volumeSecrets = []func(corev1.VolumeSource) string{
	func(v corev1.VolumeSource) string {
		if v.Secret != nil {
			return v.Secret.SecretName
		}
		return ""
	},
	func(v corev1.VolumeSource) string {
		if v.AzureFile != nil {
			return v.AzureFile.SecretName
		}
		return ""
	},
	func(v corev1.VolumeSource) string {
		if v.CSI != nil {
			return localName(v.CSI.NodePublishSecretRef)
		}
		return ""
	},
	func(v corev1.VolumeSource) string {
		if v.FlexVolume != nil {
			return localName(v.FlexVolume.SecretRef)
		}
		return ""
	},
	func(v corev1.VolumeSource) string {
		if v.CephFS != nil {
			return localName(v.CephFS.SecretRef)
		}
		return ""
	},
	func(v corev1.VolumeSource) string {
		if v.RBD != nil {
			return localName(v.RBD.SecretRef)
		}
		return ""
	},
	func(v corev1.VolumeSource) string {
		if v.Cinder != nil {
			return localName(v.Cinder.SecretRef)
		}
		return ""
	},
	func(v corev1.VolumeSource) string {
		if v.ISCSI != nil {
			return localName(v.ISCSI.SecretRef)
		}
		return ""
	},
	func(v corev1.VolumeSource) string {
		if v.ScaleIO != nil {
			return localName(v.ScaleIO.SecretRef)
		}
		return ""
	},
	func(v corev1.VolumeSource) string {
		if v.StorageOS != nil {
			return localName(v.StorageOS.SecretRef)
		}
		return ""
	},
}

func localName(ref *corev1.LocalObjectReference) string {
	if ref == nil {
		return ""
	}
	return ref.Name
}

// specRefs adds what one pod spec refers to: environment, volumes and image
// pull secrets. A spec with no pull secrets of its own gets its service
// account's at admission, so those count too.
func specRefs(ns string, spec *corev1.PodSpec, accounts map[string]*corev1.ServiceAccount, into refSet) {
	env := func(vars []corev1.EnvVar, from []corev1.EnvFromSource) {
		for _, e := range vars {
			if src := e.ValueFrom; src != nil {
				if src.ConfigMapKeyRef != nil {
					into.add("ConfigMap", ns, src.ConfigMapKeyRef.Name)
				}
				if src.SecretKeyRef != nil {
					into.add("Secret", ns, src.SecretKeyRef.Name)
				}
			}
		}
		for _, f := range from {
			if f.ConfigMapRef != nil {
				into.add("ConfigMap", ns, f.ConfigMapRef.Name)
			}
			if f.SecretRef != nil {
				into.add("Secret", ns, f.SecretRef.Name)
			}
		}
	}
	for _, c := range slices.Concat(spec.InitContainers, spec.Containers) {
		env(c.Env, c.EnvFrom)
	}
	for _, c := range spec.EphemeralContainers {
		env(c.Env, c.EnvFrom)
	}
	for _, v := range spec.Volumes {
		if v.ConfigMap != nil {
			into.add("ConfigMap", ns, v.ConfigMap.Name)
		}
		if v.Projected != nil {
			for _, p := range v.Projected.Sources {
				if p.ConfigMap != nil {
					into.add("ConfigMap", ns, p.ConfigMap.Name)
				}
				if p.Secret != nil {
					into.add("Secret", ns, p.Secret.Name)
				}
			}
		}
		for _, read := range volumeSecrets {
			into.add("Secret", ns, read(v.VolumeSource))
		}
	}
	pull := spec.ImagePullSecrets
	if len(pull) == 0 {
		name := cmp.Or(spec.ServiceAccountName, "default")
		if sa := accounts[ns+"/"+name]; sa != nil {
			pull = sa.ImagePullSecrets
		}
	}
	for _, p := range pull {
		into.add("Secret", ns, p.Name)
	}
}

// CollectConfigObjectRefs lists every ConfigMap and Secret the input refers
// to by name: from live pod specs, Ingress TLS, and in.ConfigObjectRefs.
// Nothing is dereferenced. The result is sorted.
func CollectConfigObjectRefs(in *CheckInput) []ConfigObjectRef {
	refs := refSet{}
	accounts := map[string]*corev1.ServiceAccount{}
	for _, sa := range in.ServiceAccounts {
		accounts[sa.Namespace+"/"+sa.Name] = sa
	}
	for _, t := range in.liveSpecs() {
		specRefs(t.at.namespace, t.spec, accounts, refs)
	}
	for _, r := range in.ConfigObjectRefs {
		if r.Kind == "ConfigMap" || r.Kind == "Secret" {
			refs.add(r.Kind, r.Namespace, r.Name)
		}
	}
	for _, ing := range in.Ingresses {
		for _, tls := range ing.Spec.TLS {
			refs.add("Secret", ing.Namespace, tls.SecretName)
		}
	}
	out := make([]ConfigObjectRef, 0, len(refs))
	for _, r := range slices.SortedFunc(maps.Keys(refs), compareConfigRefs) {
		out = append(out, ConfigObjectRef(r))
	}
	return out
}

func compareConfigRefs(a, b configRef) int {
	return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
}

// ConfigReferenceEvidence is what lets the unused-ConfigMap check conclude
// anything. A ConfigMap is called unused only in a namespace listed in
// CompleteNamespaces for its kind: everywhere else, not seeing a reference
// proves nothing. Refs and Objects add to what the typed input shows.
// ReflectionsComplete says whether consumers of mirrored copies (see
// mirrors) were inventoried too.
type ConfigReferenceEvidence struct {
	Refs                []ConfigObjectRef
	Objects             []ConfigObject
	CompleteNamespaces  map[string][]string
	ReflectionsComplete map[string]bool
}

// ConfigObject is a ConfigMap or Secret's identity and annotations, all the
// mirror model reads.
type ConfigObject struct {
	Kind        string
	Namespace   string
	Name        string
	Annotations map[string]string
}

// ConfigObjectMetadata takes the identity and annotations of obj.
func ConfigObjectMetadata(kind string, obj metav1.Object) ConfigObject {
	return ConfigObject{Kind: kind, Namespace: obj.GetNamespace(), Name: obj.GetName(), Annotations: obj.GetAnnotations()}
}

// reflector is the annotation prefix of the kubernetes-reflector controller,
// which copies a ConfigMap or Secret into other namespaces.
const reflector = "reflector.v1.k8s.emberstack.com/"

// mirrors is the copy graph between observed objects, as the annotations
// declare it; whether the controller has caught up is not checked.
type mirrors struct {
	sourcesOf  map[configRef][]configRef // mirror → the object it copies
	isSource   map[configRef]bool        // allows copies, or has one
	automatic  map[configRef]bool        // created by the controller itself
	unresolved map[configRef]bool        // copies something not observed
}

func readMirrors(objects []ConfigObject) mirrors {
	m := mirrors{sourcesOf: map[configRef][]configRef{}, isSource: map[configRef]bool{}, automatic: map[configRef]bool{}, unresolved: map[configRef]bool{}}
	seen := map[configRef]bool{}
	for _, o := range objects {
		if o.Kind == "ConfigMap" || o.Kind == "Secret" {
			seen[configRef{o.Kind, o.Namespace, o.Name}] = true
		}
	}
	yes := func(o ConfigObject, key string) bool { return strings.EqualFold(o.Annotations[reflector+key], "true") }
	for _, o := range objects {
		self := configRef{o.Kind, o.Namespace, o.Name}
		if !seen[self] {
			continue
		}
		if yes(o, "reflection-allowed") {
			m.isSource[self] = true
		}
		ns, name, ok := strings.Cut(o.Annotations[reflector+"reflects"], "/")
		if !ok || validation.IsDNS1123Label(ns) != nil || validation.IsDNS1123Subdomain(name) != nil {
			continue
		}
		from := configRef{o.Kind, ns, name}
		switch {
		case from == self:
			continue
		case !seen[from]:
			m.unresolved[self] = true
			continue
		}
		m.isSource[from] = true
		if !slices.Contains(m.sourcesOf[self], from) {
			m.sourcesOf[self] = append(m.sourcesOf[self], from)
		}
		if yes(o, "auto-reflects") {
			m.automatic[self] = true
		}
	}
	return m
}

// spread marks the source of every used copy as used, transitively.
func (m mirrors) spread(used refSet) {
	var queue []configRef
	for r, ok := range used {
		if ok {
			queue = append(queue, r)
		}
	}
	for len(queue) > 0 {
		r := queue[0]
		queue = queue[1:]
		for _, src := range m.sourcesOf[r] {
			if !used[src] {
				used[src] = true
				queue = append(queue, src)
			}
		}
	}
}

// unusedConfigMaps flags ConfigMaps nothing refers to. Platform-managed and
// controller-owned ConfigMaps are skipped outright. Elsewhere the check needs
// proof of absence (ConfigReferenceEvidence) to say "unused"; without it the
// ConfigMap is left unjudged and "configmap-references" reported missing.
func (s *scan) unusedConfigMaps() {
	in := s.in
	if len(in.ConfigMaps) == 0 {
		return
	}
	used := refSet{}
	for _, r := range CollectConfigObjectRefs(in) {
		used[configRef(r)] = true
	}
	objects := make([]ConfigObject, 0, len(in.ConfigMaps))
	for _, cm := range in.ConfigMaps {
		objects = append(objects, ConfigObjectMetadata("ConfigMap", cm))
	}
	ev := in.ConfigReferenceEvidence
	if ev != nil {
		for _, r := range ev.Refs {
			used[configRef(r)] = true
		}
		objects = append(objects, ev.Objects...)
	}
	m := readMirrors(objects)
	m.spread(used)

	for _, cm := range in.ConfigMaps {
		if platformConfigMap(cm) || metav1.GetControllerOf(cm) != nil {
			continue
		}
		self := configRef{"ConfigMap", cm.Namespace, cm.Name}
		if used[self] {
			s.evaluated(cm.Namespace, "orphanConfigMapSecret")
			continue
		}
		if m.automatic[self] {
			continue
		}
		proven := ev != nil && slices.Contains(ev.CompleteNamespaces["ConfigMap"], cm.Namespace)
		if proven && (m.isSource[self] || m.unresolved[self]) {
			proven = ev.ReflectionsComplete["ConfigMap"]
		}
		if !proven {
			s.missing("configmap-references")
			continue
		}
		s.evaluated(cm.Namespace, "orphanConfigMapSecret")
		s.flag(object("ConfigMap", cm.Namespace, cm.Name), "orphanConfigMapSecret", SeverityWarning,
			"nothing this check understands refers to this ConfigMap")
	}
}

// platformRule recognises ConfigMaps a platform or controller keeps for
// itself, which nothing references by design. Names empty means any name.
type platformRule struct {
	match func(*corev1.ConfigMap) bool
	names []string
}

func inNamespace(nss ...string) func(*corev1.ConfigMap) bool {
	return func(cm *corev1.ConfigMap) bool { return slices.Contains(nss, cm.Namespace) }
}

func labelled(key, value string) func(*corev1.ConfigMap) bool {
	return func(cm *corev1.ConfigMap) bool { return cm.Labels[key] == value }
}

func either(a, b func(*corev1.ConfigMap) bool) func(*corev1.ConfigMap) bool {
	return func(cm *corev1.ConfigMap) bool { return a(cm) || b(cm) }
}

func anywhere(*corev1.ConfigMap) bool { return true }

var platformRules = []platformRule{
	{anywhere, []string{"kube-root-ca.crt"}},
	{inNamespace("kube-system"), []string{
		// Kubernetes itself and managed control planes (EKS, GKE).
		"extension-apiserver-authentication", "kube-apiserver-legacy-service-account-token-tracking",
		"aws-auth", "amazon-vpc-cni", "cluster-kubestore", "clustermetrics",
		"gke-common-webhook-heartbeat", "gke-common-webhook-lock", "ingress-uid",
		"kube-dns-autoscaler", "konnectivity-agent-autoscaler-config", "kubedns-config-images",
		"pdcsi-metrics-collector-config-map",
	}},
	{inNamespace("kube-system", "cluster-autoscaler"), []string{"cluster-autoscaler-status"}},
	{inNamespace("gmp-system"), []string{"config-images", "scheduled-jobs"}},
	{either(inNamespace("argocd"), labelled("app.kubernetes.io/part-of", "argocd")), []string{
		"argocd-cm", "argocd-cmd-params-cm", "argocd-dex-cm", "argocd-gpg-keys-cm",
		"argocd-notifications-cm", "argocd-rbac-cm", "argocd-ssh-known-hosts-cm", "argocd-tls-certs-cm",
	}},
	{inNamespace("argo-rollouts"), []string{"argo-rollouts-config", "argo-rollouts-notification-configmap"}},
	{labelled("app.kubernetes.io/name", "ingress-nginx"), nil},
	{labelled("app.kubernetes.io/part-of", "kyverno"), []string{"kyverno", "kyverno-metrics"}},
	{labelled("app.kubernetes.io/part-of", "argo-workflows"), []string{"argo-workflows-workflow-controller-configmap"}},
	{labelled("app.kubernetes.io/name", "cloudnative-pg"), []string{"cnpg-controller-manager-config"}},
}

// loaderLabels are watched by sidecars (Grafana's, Prometheus rule loaders,
// fluentd) that pick ConfigMaps up by label rather than by name. Any value
// but an explicit "off" opts a ConfigMap in.
var loaderLabels = []string{"grafana_dashboard", "grafana_datasource", "prometheus_rule", "fluentd_config"}

func platformConfigMap(cm *corev1.ConfigMap) bool {
	for _, key := range loaderLabels {
		switch v := strings.ToLower(strings.TrimSpace(cm.Labels[key])); v {
		case "", "false", "0", "no", "off":
		default:
			return true
		}
	}
	switch strings.ToLower(strings.TrimSpace(cm.Labels["k8sgpt.ai/dynamically-loaded"])) {
	case "true", "1", "yes", "on":
		return true
	}
	// A leader-election lock is controller state, often with no owner.
	if strings.TrimSpace(cm.Annotations["control-plane.alpha.kubernetes.io/leader"]) != "" {
		return true
	}
	for _, r := range platformRules {
		if r.match(cm) && (r.names == nil || slices.Contains(r.names, cm.Name)) {
			return true
		}
	}
	return false
}

// credentialWords are fragments of key names that mean a credential whatever
// the value, compared with separators removed ("api-key" is "apikey").
// Vaguer words (token, auth, credential) are left out: without the value,
// "auth_enabled" cannot be told from a real credential.
var credentialWords = []string{"password", "passwd", "apikey", "privatekey", "accesskey", "secretkey"}

// credentialKey reports whether a ConfigMap key name looks like it holds a
// credential. A key that names a Secret ("db-secret-name", "tls_secret_ref")
// holds a reference, not a credential.
func credentialKey(key string) bool {
	k := strings.ToLower(key)
	snake := strings.NewReplacer("-", "_", ".", "_").Replace(k)
	snake = strings.TrimSuffix(snake, "s")
	for _, ref := range []string{"secret_name", "secret_ref", "secret_reference"} {
		if strings.HasSuffix(snake, ref) {
			return false
		}
	}
	bare := strings.NewReplacer("_", "", "-", "", ".", "").Replace(k)
	if bare == "secret" || strings.HasSuffix(bare, "clientsecret") {
		return true
	}
	return slices.ContainsFunc(credentialWords, func(w string) bool { return strings.Contains(bare, w) })
}

// credentialKeys flags ConfigMap keys named like credentials. Only names are
// read; the values reaching this package are hashes.
func (s *scan) credentialKeys() {
	for _, cm := range s.in.ConfigMaps {
		s.evaluated(cm.Namespace, "secretInConfigMap")
		for _, key := range slices.Sorted(maps.Keys(cm.Data)) {
			if credentialKey(key) {
				s.flag(object("ConfigMap", cm.Namespace, cm.Name), "secretInConfigMap", SeverityWarning,
					fmt.Sprintf("key %q looks like a credential; keep it in a Secret", key))
			}
		}
	}
}
