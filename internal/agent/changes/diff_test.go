package changes

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// changeAt is the change at path, if there is one.
func changeAt(changes []FieldChange, path string) (FieldChange, bool) {
	i := slices.IndexFunc(changes, func(c FieldChange) bool { return c.Path == path })
	if i < 0 {
		return FieldChange{}, false
	}
	return changes[i], true
}

func pathsOf(changes []FieldChange) []string {
	var out []string
	for _, c := range changes {
		out = append(out, c.Path)
	}
	return out
}

// shopTemplate is a pod template with an init container and an app
// container, configured enough that each test edits one thing.
func shopTemplate() corev1.PodSpec {
	ndots := "3"
	return corev1.PodSpec{
		ServiceAccountName: "shop",
		NodeSelector:       map[string]string{"pool": "general"},
		DNSConfig:          &corev1.PodDNSConfig{Nameservers: []string{"10.43.0.10"}, Searches: []string{"shop.svc.cluster.local"}, Options: []corev1.PodDNSConfigOption{{Name: "ndots", Value: &ndots}}},
		Volumes: []corev1.Volume{{Name: "settings", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{Name: "shop-settings"}}}}},
		InitContainers: []corev1.Container{{
			Name: "schema", Image: "ghcr.io/acme/schema:1.4", ImagePullPolicy: corev1.PullIfNotPresent,
			Env:     []corev1.EnvVar{{Name: "DB_URL", Value: "sha256:1111"}},
			EnvFrom: []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "schema-env"}}}},
			Command: []string{"migrate"}, Args: []string{"--to=latest"},
			ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/ok", Port: intstr.FromInt32(9000)}}},
			VolumeMounts:   []corev1.VolumeMount{{Name: "settings", MountPath: "/etc/schema"}},
			Ports:          []corev1.ContainerPort{{Name: "admin", ContainerPort: 9000}},
		}},
		Containers: []corev1.Container{{
			Name: "web", Image: "ghcr.io/acme/web:2.0",
			Resources:    corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("200m")}},
			VolumeMounts: []corev1.VolumeMount{{Name: "settings", MountPath: "/etc/web", ReadOnly: true}},
			Ports:        []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}},
		}},
	}
}

func TestDiffPodTemplate(t *testing.T) {
	const init, web = "spec.template.spec.initContainers[schema]", "spec.template.spec.containers[web]"
	cases := []struct {
		why     string
		edit    func(*corev1.PodSpec)
		paths   []string // exactly these, in order
		summary []string // each must appear
	}{
		{"nothing", func(*corev1.PodSpec) {}, nil, nil},
		{"an init container's image", func(s *corev1.PodSpec) { s.InitContainers[0].Image = "ghcr.io/acme/schema:1.5" },
			[]string{init + ".image"}, []string{"image(schema): ghcr.io/acme/schema:1.4→ghcr.io/acme/schema:1.5"}},
		{"resources", func(s *corev1.PodSpec) {
			s.Containers[0].Resources.Requests[corev1.ResourceCPU] = resource.MustParse("1")
		},
			[]string{"spec.template.spec.containers[*].resources"}, []string{"resources changed"}},
		// Everything about an init container is reported under its own list.
		{"init container configuration", func(s *corev1.PodSpec) {
			c := &s.InitContainers[0]
			c.Env[0].Value = "sha256:2222"
			c.EnvFrom[0].ConfigMapRef.Name = "schema-env-v2"
			c.ImagePullPolicy = corev1.PullAlways
			c.ReadinessProbe.HTTPGet.Path = "/ready"
			c.Command, c.Args = []string{"migrate", "--dry-run"}, []string{"--to=12"}
			c.VolumeMounts[0].MountPath = "/schema"
			c.Ports[0].ContainerPort = 9001
		}, []string{init + ".env.DB_URL", init + ".envFrom", init + ".imagePullPolicy", init + ".readinessProbe", init + ".command", init + ".args", init + ".volumeMounts", init + ".ports"},
			[]string{"env(schema/DB_URL) changed", "envFrom(schema) changed", "imagePullPolicy(schema): IfNotPresent→Always", "readinessProbe(schema) changed", "command(schema) changed", "args(schema) changed", "volumeMounts(schema) changed", "ports(schema) changed"}},
		{"env added and removed", func(s *corev1.PodSpec) {
			s.InitContainers[0].Env = []corev1.EnvVar{{Name: "LOG_LEVEL", Value: "sha256:3333"}}
		},
			[]string{init + ".env.DB_URL", init + ".env.LOG_LEVEL"}, []string{"env(schema/DB_URL) removed", "env(schema/LOG_LEVEL) added"}},
		{"env to valueFrom", func(s *corev1.PodSpec) {
			s.InitContainers[0].Env[0] = corev1.EnvVar{Name: "DB_URL", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "db"}, Key: "url"}}}
		}, []string{init + ".env.DB_URL"}, []string{"env(schema/DB_URL) changed"}},
		// A container gained or lost is one entry naming it (and the
		// per-container resources map moves with it).
		{"a sidecar swapped", func(s *corev1.PodSpec) {
			s.Containers = append(s.Containers, corev1.Container{Name: "otel", Image: "otel/collector:0.98"})
			s.InitContainers = nil
		}, []string{"spec.template.spec.containers[*].resources", "spec.template.spec.containers[otel]", init}, []string{"container otel added (otel/collector:0.98)", "init container schema removed"}},
		// Moving lists is a removal from one and an addition to the other.
		{"moved to the init list", func(s *corev1.PodSpec) {
			s.InitContainers, s.Containers = append(s.InitContainers, s.Containers[0]), nil
		},
			[]string{web, "spec.template.spec.initContainers[web]"}, []string{"container web removed", "init container web added"}},
		{"pod placement and identity", func(s *corev1.PodSpec) {
			s.ServiceAccountName = ""
			s.NodeSelector["zone"] = "eu-west-2a"
			s.Tolerations = []corev1.Toleration{{Key: "spot", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}}
			s.Volumes = append(s.Volumes, corev1.Volume{Name: "scratch", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}})
		}, []string{"spec.template.spec.volumes", "spec.template.spec.serviceAccountName", "spec.template.spec.nodeSelector", "spec.template.spec.tolerations"},
			[]string{"volumes changed", "serviceAccountName: shop→(default)", "nodeSelector changed", "tolerations changed"}},
		// Security context and affinity only say that they changed.
		{"security and affinity", func(s *corev1.PodSpec) {
			yes := true
			s.Containers[0].SecurityContext = &corev1.SecurityContext{ReadOnlyRootFilesystem: &yes}
			s.SecurityContext = &corev1.PodSecurityContext{RunAsNonRoot: &yes}
			s.Affinity = &corev1.Affinity{PodAntiAffinity: &corev1.PodAntiAffinity{}}
		}, []string{web + ".securityContext", "spec.template.spec.affinity", "spec.template.spec.securityContext"},
			[]string{"securityContext(web) changed", "affinity changed", "pod securityContext changed"}},
		{"DNS", func(s *corev1.PodSpec) {
			s.DNSPolicy = corev1.DNSNone
			s.DNSConfig = &corev1.PodDNSConfig{Nameservers: []string{"1.1.1.1"}, Searches: []string{"shop.svc.cluster.local", "svc.cluster.local"}, Options: []corev1.PodDNSConfigOption{{Name: "edns0"}}}
		}, []string{"spec.template.spec.dnsPolicy", "spec.template.spec.dnsConfig.nameservers", "spec.template.spec.dnsConfig.searches", "spec.template.spec.dnsConfig.options"},
			[]string{"dnsPolicy: ClusterFirst→None", "dnsConfig.nameservers changed", "dnsConfig.searches changed", "dnsConfig.options changed"}},
		// The resolver tries nameservers and search domains in order.
		{"DNS order alone", func(s *corev1.PodSpec) {
			s.DNSConfig.Nameservers = []string{"10.43.0.10", "10.43.0.11"}
			s.DNSConfig.Searches = []string{"svc.cluster.local", "shop.svc.cluster.local"}
		}, []string{"spec.template.spec.dnsConfig.nameservers", "spec.template.spec.dnsConfig.searches"}, nil},
	}
	for _, c := range cases {
		was, is := shopTemplate(), shopTemplate()
		c.edit(&is)
		changes, summary := diffPodTemplate(was, is)
		if got := pathsOf(changes); !slices.Equal(got, c.paths) {
			t.Errorf("%s: paths\n got  %v\n want %v", c.why, got, c.paths)
		}
		joined := strings.Join(summary, "; ")
		for _, s := range c.summary {
			if !strings.Contains(joined, s) {
				t.Errorf("%s: summary %q lacks %q", c.why, joined, s)
			}
		}
	}
}

func TestDiffPodTemplateValues(t *testing.T) {
	was, is := shopTemplate(), shopTemplate()
	is.InitContainers[0].Command = []string{"migrate", "--password=hunter2"}
	is.Containers[0].Resources.Requests[corev1.ResourceMemory] = resource.MustParse("256Mi")
	is.Volumes[0].ConfigMap.Name = "shop-settings-v2"
	ndots := "5"
	is.DNSConfig.Options = []corev1.PodDNSConfigOption{{Name: "ndots", Value: &ndots}, {Name: "rotate"}}
	changes, summary := diffPodTemplate(was, is)

	// What may carry a credential is a bare marker.
	if c, _ := changeAt(changes, "spec.template.spec.initContainers[schema].command"); c.OldValue != "changed" || c.NewValue != "changed" {
		t.Errorf("command = %+v", c)
	}
	if rendered := fmt.Sprint(changes, summary); strings.Contains(rendered, "hunter2") {
		t.Errorf("a command value leaked: %s", rendered)
	}
	res, _ := changeAt(changes, "spec.template.spec.containers[*].resources")
	if want := map[string]any{"schema": map[string]any{}, "web": map[string]any{"requests.cpu": "200m", "requests.memory": "256Mi"}}; !reflect.DeepEqual(res.NewValue, want) {
		t.Errorf("resources = %#v", res.NewValue)
	}
	vols, _ := changeAt(changes, "spec.template.spec.volumes")
	if !reflect.DeepEqual(vols.NewValue, []string{"settings:configMap/shop-settings-v2"}) {
		t.Errorf("volumes = %#v", vols.NewValue)
	}
	opts, _ := changeAt(changes, "spec.template.spec.dnsConfig.options")
	if !reflect.DeepEqual(opts.OldValue, []string{"ndots=3"}) || !reflect.DeepEqual(opts.NewValue, []string{"ndots=5", "rotate"}) {
		t.Errorf("options = %#v → %#v", opts.OldValue, opts.NewValue)
	}
}

// The API server's defaults and empty lists are the same as leaving fields
// out.
func TestDiffPodTemplateIgnoresDefaults(t *testing.T) {
	filled := corev1.PodSpec{DNSPolicy: corev1.DNSClusterFirst, DNSConfig: &corev1.PodDNSConfig{Nameservers: []string{}, Searches: []string{}, Options: []corev1.PodDNSConfigOption{}}}
	if c, s := diffPodTemplateConfig(corev1.PodSpec{}, filled); len(c)+len(s) != 0 {
		t.Errorf("defaults produced %v %v", c, s)
	}
}

func TestNormalizedProbe(t *testing.T) {
	http := func(port intstr.IntOrString) *corev1.Probe {
		return &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/live", Port: port}}}
	}
	exec := func(cmd ...string) *corev1.Probe {
		return &corev1.Probe{ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: cmd}}}
	}
	// Named ports stay apart from each other and from numbers.
	named, other, number := normalizedProbe(http(intstr.FromString("health"))), normalizedProbe(http(intstr.FromString("admin"))), normalizedProbe(http(intstr.FromInt32(8081)))
	if reflect.DeepEqual(named, other) || reflect.DeepEqual(named, number) {
		t.Errorf("probes collapsed: %v %v %v", named, other, number)
	}
	// An exec command is digested: a change shows, the text does not.
	a, b := normalizedProbe(exec("check", "--key=s3cret")), normalizedProbe(exec("check", "--key=s3cret2"))
	if reflect.DeepEqual(a, b) || strings.Contains(fmt.Sprint(a, b), "s3cret") {
		t.Errorf("exec probes = %v / %v", a, b)
	}
	if normalizedProbe(nil) != nil {
		t.Error("no probe should normalise to nil")
	}
}

func TestDiffWorkloadsShareTheTemplate(t *testing.T) {
	was, is := shopTemplate(), shopTemplate()
	is.InitContainers[0].Image = "ghcr.io/acme/schema:2.0"
	tmpl := func(s corev1.PodSpec) corev1.PodTemplateSpec { return corev1.PodTemplateSpec{Spec: s} }
	for kind, pair := range map[string][2]any{
		"Deployment":  {&appsv1.Deployment{Spec: appsv1.DeploymentSpec{Template: tmpl(was)}}, &appsv1.Deployment{Spec: appsv1.DeploymentSpec{Template: tmpl(is)}}},
		"StatefulSet": {&appsv1.StatefulSet{Spec: appsv1.StatefulSetSpec{Template: tmpl(was)}}, &appsv1.StatefulSet{Spec: appsv1.StatefulSetSpec{Template: tmpl(is)}}},
		"DaemonSet":   {&appsv1.DaemonSet{Spec: appsv1.DaemonSetSpec{Template: tmpl(was)}}, &appsv1.DaemonSet{Spec: appsv1.DaemonSetSpec{Template: tmpl(is)}}},
	} {
		d := ComputeDiff(kind, pair[0], pair[1])
		if d == nil || !slices.Equal(pathsOf(d.Fields), []string{"spec.template.spec.initContainers[schema].image"}) {
			t.Errorf("%s: %+v", kind, d)
		}
	}
}

func TestDiffDeployment(t *testing.T) {
	two, five := int32(2), int32(5)
	was := &appsv1.Deployment{Spec: appsv1.DeploymentSpec{Replicas: &two, Template: corev1.PodTemplateSpec{Spec: shopTemplate()}}}
	is := was.DeepCopy()
	is.Spec.Replicas, is.Spec.Paused = &five, true
	d := ComputeDiff("Deployment", was, is)
	if d == nil || !slices.Equal(pathsOf(d.Fields), []string{"spec.replicas", "spec.paused"}) || d.Summary != "replicas: 2→5, rollout paused" {
		t.Fatalf("diff = %+v", d)
	}
}

func TestDiffApplication(t *testing.T) {
	app := func(phase, message string, automated bool) *unstructured.Unstructured {
		u := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{}, "status": map[string]any{}}}
		if phase != "" {
			_ = unstructured.SetNestedMap(u.Object, map[string]any{"phase": phase, "message": message}, "status", "operationState")
		}
		if automated {
			_ = unstructured.SetNestedMap(u.Object, map[string]any{"prune": true, "selfHeal": true}, "spec", "syncPolicy", "automated")
		}
		return u
	}
	const wrapped = "rpc error: code = Unknown desc = path 'overlays/prod' does not exist"
	// A failure's message is shown without its gRPC wrapper, whether the
	// operation appeared already failed or failed while running.
	for _, before := range []*unstructured.Unstructured{app("", "", false), app("Running", "", false)} {
		d := ComputeDiff("Application", before, app("Failed", wrapped, false))
		if d == nil || strings.Contains(d.Summary, "rpc error") || !strings.Contains(d.Summary, "error: path 'overlays/prod' does not exist") {
			t.Errorf("failure summary = %+v", d)
		}
	}
	// Turning auto-sync on is a boolean; the policy body is not carried.
	d := ComputeDiff("Application", app("", "", false), app("", "", true))
	if c, ok := changeAt(d.Fields, "spec.syncPolicy.automated"); !ok || c.OldValue != false || c.NewValue != true || !strings.Contains(d.Summary, "auto-sync enabled") {
		t.Errorf("auto-sync = %+v", d)
	}
}

func TestDiffFlux(t *testing.T) {
	repo := func(rev, branch string) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{
			"spec":   map[string]any{"url": "https://git.example.org/platform/apps", "ref": map[string]any{"branch": branch}},
			"status": map[string]any{"artifact": map[string]any{"revision": rev}},
		}}
	}
	d := ComputeDiff("GitRepository", repo("main@sha1:a1b2c3d4e5f6", "main"), repo("release@sha1:0f9e8d7c6b5a", "release"))
	if d == nil || !slices.Equal(pathsOf(d.Fields), []string{"status.artifact.revision", "spec.ref.branch"}) ||
		!strings.Contains(d.Summary, "artifact: main@a1b2c3d→release@0f9e8d7") || !strings.Contains(d.Summary, "branch: main→release") {
		t.Errorf("GitRepository = %+v", d)
	}
	release := func(released string, failures int64) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{"status": map[string]any{
			"conditions": []any{map[string]any{"type": "Released", "status": released}}, "upgradeFailures": failures,
		}}}
	}
	d = ComputeDiff("HelmRelease", release("True", 0), release("False", 3))
	if d == nil || !slices.Equal(pathsOf(d.Fields), []string{"status.conditions[Released]", "status.upgradeFailures"}) || !strings.Contains(d.Summary, "upgrade failures: 3") {
		t.Errorf("HelmRelease = %+v", d)
	}
}

func TestDiffServiceAndIngress(t *testing.T) {
	was := &corev1.Service{Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, Selector: map[string]string{"app": "web"},
		Ports: []corev1.ServicePort{{Protocol: corev1.ProtocolTCP, Port: 443, TargetPort: intstr.FromString("https")}}}}
	is := was.DeepCopy()
	is.Spec.Type = corev1.ServiceTypeLoadBalancer
	is.Spec.Ports[0].TargetPort = intstr.FromInt32(8443)
	is.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{Hostname: "shop-lb.example.net"}}
	d := ComputeDiff("Service", was, is)
	if d == nil || !slices.Equal(pathsOf(d.Fields), []string{"spec.type", "spec.ports", "status.loadBalancer.ingress"}) || !strings.Contains(d.Summary, "LB ready: shop-lb.example.net") {
		t.Errorf("Service = %+v", d)
	}
	if c, _ := changeAt(d.Fields, "spec.ports"); !reflect.DeepEqual(c.NewValue, []string{"TCP/443→8443"}) {
		t.Errorf("ports = %#v", c.NewValue)
	}
}

func TestDiffQuotaAndLimits(t *testing.T) {
	quota := func(cpu string) *corev1.ResourceQuota {
		q := &corev1.ResourceQuota{Spec: corev1.ResourceQuotaSpec{Hard: corev1.ResourceList{"requests.cpu": resource.MustParse(cpu), "pods": resource.MustParse("40")}}}
		return q
	}
	c, s := diffResourceQuota(quota("8"), quota("16"))
	if !slices.Equal(pathsOf(c), []string{"spec.hard.requests.cpu"}) || !strings.Contains(strings.Join(s, ","), "quota requests.cpu: 8→16") {
		t.Errorf("quota = %v %v", c, s)
	}
	// Usage moving is not a quota change.
	busy := quota("8")
	busy.Status.Used = corev1.ResourceList{"requests.cpu": resource.MustParse("7")}
	if c, _ := diffResourceQuota(quota("8"), busy); len(c) != 0 {
		t.Errorf("used-only = %v", c)
	}
	limits := func(def string) *corev1.LimitRange {
		return &corev1.LimitRange{Spec: corev1.LimitRangeSpec{Limits: []corev1.LimitRangeItem{{Type: corev1.LimitTypeContainer, Default: corev1.ResourceList{"cpu": resource.MustParse(def)}}}}}
	}
	if c, _ := diffLimitRange(limits("500m"), limits("1")); !slices.Equal(pathsOf(c), []string{"spec.limits"}) || !reflect.DeepEqual(c[0].NewValue, []string{"Container default.cpu=1"}) {
		t.Errorf("limits = %v", c)
	}
	if c, _ := diffLimitRange(limits("1"), limits("1")); len(c) != 0 {
		t.Errorf("same limits = %v", c)
	}
}

func TestDiffAdmissionWebhooks(t *testing.T) {
	config := func(failurePolicy, ca string, selector map[string]any) *unstructured.Unstructured {
		hook := map[string]any{
			"name": "verify-images.policy.example.org", "failurePolicy": failurePolicy, "sideEffects": "None",
			"clientConfig": map[string]any{"caBundle": ca, "service": map[string]any{"namespace": "policy", "name": "image-verifier", "path": "/verify"}},
			"rules":        []any{map[string]any{"operations": []any{"CREATE"}, "apiGroups": []any{""}, "apiVersions": []any{"v1"}, "resources": []any{"pods"}}},
		}
		if selector != nil {
			hook["namespaceSelector"] = selector
		}
		return &unstructured.Unstructured{Object: map[string]any{"webhooks": []any{hook}}}
	}
	caA, caB := strings.Repeat("Q", 48), strings.Repeat("R", 48)
	// A rotated CA shows — even at the same length — as a digest only.
	c, s := diffAdmissionWebhookConfiguration(config("Fail", caA, nil), config("Fail", caB, nil))
	rendered := fmt.Sprint(c)
	if !slices.Equal(pathsOf(c), []string{"webhooks[verify-images.policy.example.org]"}) || strings.Contains(rendered, caA) || strings.Contains(rendered, caB) ||
		!strings.Contains(rendered, "caBundle=sha256:") || !strings.Contains(strings.Join(s, ","), "webhook verify-images.policy.example.org changed") {
		t.Errorf("CA rotation = %v %v", c, s)
	}
	if c, _ := diffAdmissionWebhookConfiguration(config("Ignore", caA, nil), config("Fail", caA, nil)); len(c) != 1 {
		t.Errorf("failure policy = %v", c)
	}
	// Being re-scoped to some namespaces shows, with the selector.
	rescoped := config("Fail", caA, map[string]any{"matchLabels": map[string]any{"tier": "prod"}})
	if c, _ := diffAdmissionWebhookConfiguration(config("Fail", caA, nil), rescoped); len(c) != 1 || !strings.Contains(fmt.Sprint(c), "namespaceSelector={tier=prod}") {
		t.Errorf("rescope = %v", c)
	}
	if c, _ := diffAdmissionWebhookConfiguration(config("Fail", caA, nil), config("Fail", caA, nil)); len(c) != 0 {
		t.Errorf("unchanged = %v", c)
	}
	none := &unstructured.Unstructured{Object: map[string]any{"webhooks": []any{}}}
	if c, s := diffAdmissionWebhookConfiguration(none, config("Fail", caA, nil)); len(c) != 1 || c[0].OldValue != nil || !strings.Contains(strings.Join(s, ","), "added") {
		t.Errorf("added = %v %v", c, s)
	}
}
