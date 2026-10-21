package posture

import (
	"slices"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCredentialKey(t *testing.T) {
	for key, want := range map[string]bool{
		"db_password": true, "SMTP_PASSWD": true, "stripe-api-key": true, "apiKey": true,
		"tls.private_key": true, "aws_access_key_id": true, "minio-secret-key": true,
		"client_secret": true, "oidc.clientSecret": true, "secret": true,
		// Names of Secrets, not their contents.
		"db_secret_name": false, "tls-secret-ref": false, "vault.secret.references": false,
		// Too vague without the value.
		"api_token": false, "auth_enabled": false, "credentials_path": false,
		"log_level": false, "secretary_email": false,
	} {
		if got := credentialKey(key); got != want {
			t.Errorf("credentialKey(%q) = %v, want %v", key, got, want)
		}
	}
}

func TestCollectConfigObjectRefs(t *testing.T) {
	spec := corev1.PodSpec{
		InitContainers: []corev1.Container{{Name: "init", EnvFrom: []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "init-env"}}}}}},
		Containers: []corev1.Container{{Name: "api", Env: []corev1.EnvVar{
			{Name: "MODE", ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "modes"}, Key: "mode"}}},
			{Name: "DB", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "db"}, Key: "url"}}},
		}}},
		EphemeralContainers: []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug",
			EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "debug-token"}}}}}}},
		Volumes: []corev1.Volume{
			{Name: "conf", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "nginx-conf"}}}},
			{Name: "bundle", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{
				{ConfigMap: &corev1.ConfigMapProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "ca-bundle"}}},
				{Secret: &corev1.SecretProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "client-cert"}}},
			}}}},
			{Name: "csi", VolumeSource: corev1.VolumeSource{CSI: &corev1.CSIVolumeSource{Driver: "secrets-store", NodePublishSecretRef: &corev1.LocalObjectReference{Name: "csi-creds"}}}},
			{Name: "share", VolumeSource: corev1.VolumeSource{AzureFile: &corev1.AzureFileVolumeSource{SecretName: "azure-share"}}},
		},
		ServiceAccountName: "puller",
	}
	ing := &networkingv1.Ingress{ObjectMeta: meta("shop", "web"), Spec: networkingv1.IngressSpec{TLS: []networkingv1.IngressTLS{{SecretName: "web-tls"}}}}
	done := &batchv1.Job{ObjectMeta: meta("shop", "backfill"), Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
		Volumes: []corev1.Volume{{Name: "c", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "backfill-plan"}}}}},
	}}}}
	done.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}

	in := &CheckInput{
		Deployments:      []*appsv1.Deployment{deployment("shop", "api", 2, spec)},
		Jobs:             []*batchv1.Job{done},
		Ingresses:        []*networkingv1.Ingress{ing},
		ServiceAccounts:  []*corev1.ServiceAccount{{ObjectMeta: meta("shop", "puller"), ImagePullSecrets: []corev1.LocalObjectReference{{Name: "registry"}}}},
		ConfigObjectRefs: []ConfigObjectRef{{Kind: "ConfigMap", Namespace: "shop", Name: "route-filter"}, {Kind: "Deployment", Namespace: "shop", Name: "ignored"}},
	}
	var got []string
	for _, r := range CollectConfigObjectRefs(in) {
		got = append(got, r.Kind+":"+r.Name)
	}
	want := []string{
		"ConfigMap:ca-bundle", "ConfigMap:init-env", "ConfigMap:modes", "ConfigMap:nginx-conf", "ConfigMap:route-filter",
		"Secret:azure-share", "Secret:client-cert", "Secret:csi-creds", "Secret:db", "Secret:debug-token", "Secret:registry", "Secret:web-tls",
	}
	if !slices.Equal(got, want) {
		t.Errorf("refs\n got %v\nwant %v", got, want)
	}

	// The account's pull secrets apply only when the pod names none.
	spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: "own-registry"}}
	in.Deployments = []*appsv1.Deployment{deployment("shop", "api", 2, spec)}
	refs := CollectConfigObjectRefs(in)
	if !slices.Contains(refs, ConfigObjectRef{"Secret", "shop", "own-registry"}) || slices.Contains(refs, ConfigObjectRef{"Secret", "shop", "registry"}) {
		t.Errorf("pull secrets: %v", refs)
	}
}

// proven gives the unused-ConfigMap check what it needs to conclude:
// every reference the input shows, with every ConfigMap's namespace (and its
// mirrors) inventoried completely.
func proven(in *CheckInput) *CheckInput {
	ev := &ConfigReferenceEvidence{CompleteNamespaces: map[string][]string{}, ReflectionsComplete: map[string]bool{"ConfigMap": true}}
	for _, cm := range in.ConfigMaps {
		ev.CompleteNamespaces["ConfigMap"] = append(ev.CompleteNamespaces["ConfigMap"], cm.Namespace)
	}
	in.ConfigReferenceEvidence = ev
	return in
}

func configMap(ns, name string, mods ...func(*corev1.ConfigMap)) *corev1.ConfigMap {
	cm := &corev1.ConfigMap{ObjectMeta: meta(ns, name)}
	for _, m := range mods {
		m(cm)
	}
	return cm
}

func label(k, v string) func(*corev1.ConfigMap) {
	return func(cm *corev1.ConfigMap) {
		if cm.Labels == nil {
			cm.Labels = map[string]string{}
		}
		cm.Labels[k] = v
	}
}

func annotate(k, v string) func(*corev1.ConfigMap) {
	return func(cm *corev1.ConfigMap) {
		if cm.Annotations == nil {
			cm.Annotations = map[string]string{}
		}
		cm.Annotations[k] = v
	}
}

func mounting(names ...string) corev1.PodSpec {
	spec := tidySpec("api")
	for _, n := range names {
		spec.Volumes = append(spec.Volumes, corev1.Volume{Name: n, VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: n}}}})
	}
	return spec
}

func TestUnusedConfigMaps(t *testing.T) {
	in := proven(&CheckInput{
		Deployments: []*appsv1.Deployment{deployment("shop", "api", 2, mounting("api-conf"))},
		ConfigMaps: []*corev1.ConfigMap{
			configMap("shop", "api-conf"),
			configMap("shop", "leftover"),
			configMap("shop", "kube-root-ca.crt"),
			configMap("kube-system", "aws-auth"),
			configMap("argocd", "argocd-rbac-cm"),
			configMap("tools", "argocd-cm", label("app.kubernetes.io/part-of", "argocd")),
			configMap("ingress", "nginx-tcp", label("app.kubernetes.io/name", "ingress-nginx")),
			configMap("monitoring", "slo-dashboard", label("grafana_dashboard", "1")),
			configMap("monitoring", "retired-dashboard", label("grafana_dashboard", "false")),
			configMap("monitoring", "loaded", label("k8sgpt.ai/dynamically-loaded", "yes")),
			configMap("ops", "controller-lock", annotate("control-plane.alpha.kubernetes.io/leader", `{"holderIdentity":"a"}`)),
			// The platform names only count in the platform's namespace.
			configMap("shop", "aws-auth"),
			configMap("shop", "argocd-cm"),
			func() *corev1.ConfigMap {
				cm := configMap("shop", "generated")
				cm.OwnerReferences = []metav1.OwnerReference{{Kind: "Widget", Name: "w", Controller: ptr(true)}}
				return cm
			}(),
		},
	})
	r := RunChecks(in)
	got := findingNames(r.Findings, "orphanConfigMapSecret")
	want := map[string]bool{"leftover": true, "retired-dashboard": true, "aws-auth": true, "argocd-cm": true}
	if len(got) != len(want) {
		t.Fatalf("flagged %v, want %v", got, want)
	}
	for _, f := range r.Findings {
		if f.CheckID == "orphanConfigMapSecret" && f.Namespace != "shop" && f.Name != "retired-dashboard" {
			t.Errorf("platform ConfigMap flagged: %s/%s", f.Namespace, f.Name)
		}
	}
	// Five judged: api-conf (used), leftover, retired-dashboard, and the two
	// look-alikes in shop.
	if c := r.CheckCounts["orphanConfigMapSecret"]; c != (CheckCount{Evaluated: 5, Passed: 1}) {
		t.Errorf("counts %+v", c)
	}
}

func TestUnusedConfigMapsNeedProof(t *testing.T) {
	cms := func() []*corev1.ConfigMap {
		return []*corev1.ConfigMap{configMap("shop", "api-conf"), configMap("shop", "leftover")}
	}
	deps := []*appsv1.Deployment{deployment("shop", "api", 2, mounting("api-conf"))}

	r := RunChecks(&CheckInput{Deployments: deps, ConfigMaps: cms()})
	if len(findingNames(r.Findings, "orphanConfigMapSecret")) != 0 || !slices.Contains(r.MissingInputs, "configmap-references") {
		t.Errorf("concluded without evidence: %v", r.MissingInputs)
	}
	// A used ConfigMap needs no proof of anything.
	if c := r.CheckCounts["orphanConfigMapSecret"]; c != (CheckCount{Evaluated: 1, Passed: 1}) {
		t.Errorf("counts %+v", c)
	}

	in := &CheckInput{Deployments: deps, ConfigMaps: cms(), ConfigReferenceEvidence: &ConfigReferenceEvidence{
		CompleteNamespaces: map[string][]string{"ConfigMap": {"staging"}, "Secret": {"shop"}},
	}}
	if r := RunChecks(in); len(findingNames(r.Findings, "orphanConfigMapSecret")) != 0 {
		t.Error("proof for another namespace, or for Secrets, was taken as proof here")
	}

	in.ConfigReferenceEvidence = &ConfigReferenceEvidence{
		CompleteNamespaces: map[string][]string{"ConfigMap": {"shop"}},
		Refs:               []ConfigObjectRef{{Kind: "ConfigMap", Namespace: "shop", Name: "leftover"}},
	}
	if r := RunChecks(in); len(findingNames(r.Findings, "orphanConfigMapSecret")) != 0 || r.CheckCounts["orphanConfigMapSecret"].Evaluated != 2 {
		t.Error("a reference supplied as evidence must count as use, alongside the input's own")
	}

	// Jobs that have finished keep nothing alive.
	done := &batchv1.Job{ObjectMeta: meta("shop", "migrate"), Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: mounting("leftover")}}}
	done.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue}}
	in = proven(&CheckInput{Deployments: deps, ConfigMaps: cms(), Jobs: []*batchv1.Job{done}})
	if !findingNames(RunChecks(in).Findings, "orphanConfigMapSecret")["leftover"] {
		t.Error("a finished Job's reference kept a ConfigMap in use")
	}
}

func TestMirroredConfigMaps(t *testing.T) {
	const r = reflector
	source := configMap("platform", "ca", annotate(r+"reflection-allowed", "true"))
	copyOf := configMap("shop", "ca", annotate(r+"reflects", "platform/ca"))
	auto := configMap("staging", "ca", annotate(r+"reflects", "platform/ca"), annotate(r+"auto-reflects", "true"))
	dangling := configMap("shop", "orphan-copy", annotate(r+"reflects", "platform/gone"))
	bad := configMap("shop", "bad-copy", annotate(r+"reflects", "Not_A_Namespace/ca"))

	scan := func(reflections bool, deps ...*appsv1.Deployment) map[string]bool {
		in := proven(&CheckInput{Deployments: deps, ConfigMaps: []*corev1.ConfigMap{source, copyOf, auto, dangling, bad}})
		in.ConfigReferenceEvidence.ReflectionsComplete["ConfigMap"] = reflections
		out := map[string]bool{}
		for _, f := range RunChecks(in).Findings {
			if f.CheckID == "orphanConfigMapSecret" {
				out[f.Namespace+"/"+f.Name] = true
			}
		}
		return out
	}

	// Using the copy uses its source; an automatic copy is the
	// controller's, never flagged; an invalid reference is just a ConfigMap.
	got := scan(true, deployment("shop", "api", 2, mounting("ca")))
	if got["platform/ca"] || got["shop/ca"] || got["staging/ca"] || !got["shop/orphan-copy"] || !got["shop/bad-copy"] {
		t.Errorf("with the copy in use: %v", got)
	}
	got = scan(true)
	if !got["platform/ca"] || !got["shop/ca"] || got["staging/ca"] {
		t.Errorf("nothing in use: %v", got)
	}
	// Without the copies' consumers inventoried, a source and a dangling
	// copy cannot be called unused; a plain ConfigMap still can.
	got = scan(false)
	if got["platform/ca"] || got["shop/orphan-copy"] || !got["shop/ca"] || !got["shop/bad-copy"] {
		t.Errorf("mirrors not inventoried: %v", got)
	}

	m := readMirrors([]ConfigObject{
		{Kind: "ConfigMap", Namespace: "a", Name: "x", Annotations: map[string]string{r + "reflects": "a/x"}},
		{Kind: "Secret", Namespace: "a", Name: "y", Annotations: map[string]string{r + "reflects": "b/y"}},
		{Kind: "Secret", Namespace: "b", Name: "y"},
		{Kind: "Secret", Namespace: "c", Name: "y", Annotations: map[string]string{r + "reflects": "a/y"}},
	})
	used := refSet{{"Secret", "c", "y"}: true}
	m.spread(used)
	if len(m.sourcesOf[configRef{"ConfigMap", "a", "x"}]) != 0 || !used[configRef{"Secret", "a", "y"}] || !used[configRef{"Secret", "b", "y"}] {
		t.Errorf("a copy of a copy must keep the original in use, and a self-reference is no copy: %v", used)
	}
}

func TestCredentialKeys(t *testing.T) {
	cm := configMap("shop", "settings")
	cm.Data = map[string]string{"smtp_password": "sha256:00", "log_level": "sha256:01", "apiKey": "sha256:02"}
	r := RunChecks(&CheckInput{ConfigMaps: []*corev1.ConfigMap{cm, configMap("shop", "empty")}})
	f := findingFor(r, "secretInConfigMap", "settings")
	if f == nil || f.Message != `key "apiKey" looks like a credential; keep it in a Secret; key "smtp_password" looks like a credential; keep it in a Secret` {
		t.Errorf("finding %+v (keys are reported in order)", f)
	}
	if c := r.CheckCounts["secretInConfigMap"]; c != (CheckCount{Evaluated: 2, Passed: 1}) {
		t.Errorf("counts %+v", c)
	}
}
