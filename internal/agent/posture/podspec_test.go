package posture

import (
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// TestTemplateChecks starts each case from a template nothing objects to,
// changes one thing, and expects exactly the checks that change should fail.
func TestTemplateChecks(t *testing.T) {
	first := func(f func(*corev1.Container)) func(*corev1.PodSpec) {
		return func(s *corev1.PodSpec) { f(&s.Containers[0]) }
	}
	hostPath := func(path string) func(*corev1.PodSpec) {
		return func(s *corev1.PodSpec) {
			s.Volumes = append(s.Volumes, corev1.Volume{Name: "host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: path}}})
		}
	}
	image := func(ref string, policy corev1.PullPolicy) func(*corev1.PodSpec) {
		return first(func(c *corev1.Container) { c.Image, c.ImagePullPolicy = ref, policy })
	}
	capabilities := func(caps ...corev1.Capability) func(*corev1.PodSpec) {
		return first(func(c *corev1.Container) { c.SecurityContext.Capabilities = &corev1.Capabilities{Add: caps} })
	}
	unset := func(res string) func(*corev1.PodSpec) {
		return first(func(c *corev1.Container) {
			list, name, _ := strings.Cut(res, ".")
			l := c.Resources.Requests
			if list == "limits" {
				l = c.Resources.Limits
			}
			delete(l, corev1.ResourceName(name))
		})
	}

	for _, tc := range []struct {
		why    string
		change func(*corev1.PodSpec)
		fails  []string
	}{
		{"nothing changed", func(*corev1.PodSpec) {}, nil},

		{"host network", func(s *corev1.PodSpec) { s.HostNetwork = true }, []string{"hostNetwork"}},
		{"host PID", func(s *corev1.PodSpec) { s.HostPID = true }, []string{"hostPID"}},
		{"host IPC", func(s *corev1.PodSpec) { s.HostIPC = true }, []string{"hostIPC"}},
		{"token mounted on purpose", func(s *corev1.PodSpec) { s.AutomountServiceAccountToken = ptr(true) }, []string{"automountServiceAccountToken"}},
		// With the pod silent, the "default" account decides, and the
		// listed inventory has no such account: Kubernetes mounts.
		{"token left to an unknown account", func(s *corev1.PodSpec) { s.AutomountServiceAccountToken = nil }, []string{"automountServiceAccountToken"}},

		{"root not ruled out", first(func(c *corev1.Container) { c.SecurityContext.RunAsNonRoot = nil }), []string{"runAsRoot"}},
		{"non-root from the pod", func(s *corev1.PodSpec) {
			s.Containers[0].SecurityContext.RunAsNonRoot = nil
			s.SecurityContext = &corev1.PodSecurityContext{RunAsNonRoot: ptr(true)}
		}, nil},
		{"a non-zero uid from the pod", func(s *corev1.PodSpec) {
			s.Containers[0].SecurityContext.RunAsNonRoot = nil
			s.SecurityContext = &corev1.PodSecurityContext{RunAsUser: ptr(int64(10001))}
		}, nil},
		{"uid 0 is root", func(s *corev1.PodSpec) {
			s.Containers[0].SecurityContext.RunAsNonRoot = nil
			s.Containers[0].SecurityContext.RunAsUser = ptr(int64(0))
		}, []string{"runAsRoot"}},
		{"container overrides the pod's promise", func(s *corev1.PodSpec) {
			s.Containers[0].SecurityContext.RunAsNonRoot = ptr(false)
			s.SecurityContext = &corev1.PodSecurityContext{RunAsNonRoot: ptr(true)}
		}, []string{"runAsRoot"}},
		{"privileged", first(func(c *corev1.Container) { c.SecurityContext.Privileged = ptr(true) }), []string{"privileged"}},
		{"escalation left open", first(func(c *corev1.Container) { c.SecurityContext.AllowPrivilegeEscalation = nil }), []string{"privilegeEscalation"}},
		{"writable root", first(func(c *corev1.Container) { c.SecurityContext.ReadOnlyRootFilesystem = ptr(false) }), []string{"readOnlyRootFs"}},
		{"no security context at all", first(func(c *corev1.Container) { c.SecurityContext = nil }),
			[]string{"privilegeEscalation", "readOnlyRootFs", "runAsRoot"}},
		{"SYS_ADMIN", capabilities("SYS_ADMIN"), []string{"dangerousCapabilities"}},
		{"lower-case net_raw", capabilities("net_raw"), []string{"insecureCapabilities"}},
		{"both kinds", capabilities("NET_ADMIN", "SYS_PTRACE"), []string{"dangerousCapabilities", "insecureCapabilities"}},
		{"a harmless capability", capabilities("NET_BIND_SERVICE"), nil},
		{"privileged init container", func(s *corev1.PodSpec) {
			c := tidy("migrate")
			c.SecurityContext.Privileged = ptr(true)
			s.InitContainers = []corev1.Container{c}
		}, []string{"privileged"}},
		{"init container without probes or sizing", func(s *corev1.PodSpec) {
			c := tidy("migrate")
			c.ReadinessProbe, c.LivenessProbe, c.Resources = nil, nil, corev1.ResourceRequirements{}
			s.InitContainers = []corev1.Container{c}
		}, nil},

		{"no readiness probe", first(func(c *corev1.Container) { c.ReadinessProbe = nil }), []string{"readinessProbeMissing"}},
		{"no liveness probe", first(func(c *corev1.Container) { c.LivenessProbe = nil }), []string{"livenessProbeMissing"}},
		{"latest, cached", image("redis:latest", corev1.PullIfNotPresent), []string{"imageTagLatest", "pullPolicyNotAlways"}},
		{"latest, always pulled", image("redis:latest", corev1.PullAlways), []string{"imageTagLatest"}},
		{"untagged", image("redis", corev1.PullIfNotPresent), []string{"imageTagLatest", "pullPolicyNotAlways"}},
		{"registry port and no tag", image("registry.local:5000/redis", corev1.PullAlways), []string{"imageTagLatest"}},
		{"registry port and a tag", image("registry.local:5000/redis:7.4.1", corev1.PullIfNotPresent), nil},
		{"digest", image("redis@sha256:4c5b2fa3f17a5f1c0a76c4a2a43c7e3c7f7c0a8b2f60d1f5ad92b41c3a5e7d01", corev1.PullIfNotPresent), nil},

		{"no CPU request", unset("requests.cpu"), []string{"cpuRequestMissing"}},
		{"no memory request", unset("requests.memory"), []string{"memoryRequestMissing"}},
		{"no CPU limit", unset("limits.cpu"), []string{"cpuLimitMissing"}},
		{"no memory limit", unset("limits.memory"), []string{"memoryLimitMissing"}},
		{"a zero request is no request", first(func(c *corev1.Container) { c.Resources.Requests[corev1.ResourceCPU] = resource.MustParse("0") }), []string{"cpuRequestMissing"}},
		{"sized at pod level", func(s *corev1.PodSpec) {
			s.Containers[0].Resources = corev1.ResourceRequirements{}
			s.Resources = &corev1.ResourceRequirements{Requests: sized().Requests, Limits: sized().Limits}
		}, nil},

		{"docker socket", hostPath("/var/run/docker.sock"), []string{"dockerSocketMount"}},
		{"containerd socket elsewhere", hostPath("/run/containerd/containerd.sock"), []string{"dockerSocketMount"}},
		{"whole host", hostPath("/"), []string{"sensitiveHostPath"}},
		{"under /etc", hostPath("/etc/ssl/certs"), []string{"sensitiveHostPath"}},
		{"/proc itself", hostPath("/proc"), []string{"sensitiveHostPath"}},
		{"a look-alike of /etc", hostPath("/etcd-data"), nil},
		{"an ordinary host directory", hostPath("/srv/cache"), nil},
	} {
		spec := tidySpec("api")
		tc.change(&spec)
		in := listedEverything()
		in.Deployments = []*appsv1.Deployment{deployment("billing", "invoices", 1, spec)}
		got := RunChecks(in)
		// One replica and no autoscaler list: only template checks can fail.
		if fails := checksFailing(got); !slices.Equal(fails, tc.fails) {
			t.Errorf("%s: failing %v, want %v", tc.why, fails, tc.fails)
		}
	}
}

func TestTemplateSeverities(t *testing.T) {
	spec := tidySpec("api")
	spec.HostNetwork, spec.HostPID = true, true
	spec.Containers[0].SecurityContext.Privileged = ptr(true)
	spec.Containers[0].Image = "redis"
	spec.Volumes = []corev1.Volume{
		{Name: "root", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/"}}},
		{Name: "logs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/pods"}}},
	}
	in := listedEverything()
	in.Deployments = []*appsv1.Deployment{deployment("billing", "invoices", 2, spec)}
	r := RunChecks(in)
	want := map[string]string{
		"hostNetwork": SeverityWarning, "hostPID": SeverityDanger, "privileged": SeverityDanger,
		"imageTagLatest": SeverityDanger, "pullPolicyNotAlways": SeverityWarning,
	}
	for id, sev := range want {
		if f := findingFor(r, id, "invoices"); f == nil || f.Severity != sev {
			t.Errorf("%s: %+v, want severity %s", id, f, sev)
		}
	}
	// Two host paths on one workload merge into one finding; it keeps the
	// first one's severity and names both volumes.
	f := findingFor(r, "sensitiveHostPath", "invoices")
	if f == nil || f.Severity != SeverityDanger || !strings.Contains(f.Message, `"root"`) || !strings.Contains(f.Message, `"logs"`) {
		t.Errorf("host paths: %+v", f)
	}
}

func TestTemplatesJudged(t *testing.T) {
	bad := tidySpec("api")
	bad.HostPID = true
	ownedPod := pod("billing", "invoices-7d9f-x2k4", nil, bad)
	owned(&ownedPod.ObjectMeta, "ReplicaSet", "invoices-7d9f", "rs-1")
	in := listedEverything()
	in.Deployments = []*appsv1.Deployment{deployment("billing", "invoices", 2, bad)}
	in.StatefulSets = []*appsv1.StatefulSet{statefulSet("billing", "ledger", 3, bad)}
	in.DaemonSets = []*appsv1.DaemonSet{{ObjectMeta: meta("billing", "shipper"), Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: bad}}}}
	in.Pods = []*corev1.Pod{ownedPod, pod("billing", "debug-shell", nil, bad)}
	r := RunChecks(in)
	var got []string
	for _, f := range failing(r) {
		if strings.HasPrefix(f, "hostPID@") {
			got = append(got, f)
		}
	}
	want := []string{"hostPID@DaemonSet/billing/shipper", "hostPID@Deployment/billing/invoices", "hostPID@Pod/billing/debug-shell", "hostPID@StatefulSet/billing/ledger"}
	if !slices.Equal(got, want) {
		t.Errorf("judged %v, want %v (an owned pod is its workload's business)", got, want)
	}
	if f := findingFor(r, "hostPID", "invoices"); f.Group != "apps" || f.Category != CategorySecurity {
		t.Errorf("group and category come from the kind and the catalogue: %+v", f)
	}
}

func TestServiceAccountToken(t *testing.T) {
	silent := tidySpec("api")
	silent.AutomountServiceAccountToken = nil
	named := silent
	named.ServiceAccountName = "invoicer"
	optOut := func(ns, name string) *corev1.ServiceAccount {
		return &corev1.ServiceAccount{ObjectMeta: meta(ns, name), AutomountServiceAccountToken: ptr(false)}
	}

	for _, tc := range []struct {
		why       string
		spec      corev1.PodSpec
		accounts  []*corev1.ServiceAccount
		scope     string
		evaluated int
		fails     bool
	}{
		{"default account opts out", silent, []*corev1.ServiceAccount{optOut("billing", "default")}, "", 1, false},
		{"named account opts out", named, []*corev1.ServiceAccount{optOut("billing", "invoicer")}, "", 1, false},
		{"another namespace's account says nothing", silent, []*corev1.ServiceAccount{optOut("payroll", "default")}, "", 1, true},
		{"the pod's own setting wins", func() corev1.PodSpec { s := named; s.AutomountServiceAccountToken = ptr(true); return s }(),
			[]*corev1.ServiceAccount{optOut("billing", "invoicer")}, "", 1, true},
		{"accounts never listed", silent, nil, "", 0, false},
		{"accounts listed for another namespace only", silent, []*corev1.ServiceAccount{}, "payroll", 0, false},
		{"accounts listed for this namespace", silent, []*corev1.ServiceAccount{}, "billing", 1, true},
		{"explicit pod setting needs no inventory", func() corev1.PodSpec { s := silent; s.AutomountServiceAccountToken = ptr(false); return s }(), nil, "", 1, false},
	} {
		in := listedEverything()
		in.ServiceAccounts, in.ServiceAccountsNamespace = tc.accounts, tc.scope
		in.Deployments = []*appsv1.Deployment{deployment("billing", "invoices", 2, tc.spec)}
		r := RunChecks(in)
		count := r.CheckCounts["automountServiceAccountToken"]
		failed := findingFor(r, "automountServiceAccountToken", "invoices") != nil
		if count.Evaluated != tc.evaluated || failed != tc.fails {
			t.Errorf("%s: evaluated %d failed %v, want %d %v", tc.why, count.Evaluated, failed, tc.evaluated, tc.fails)
		}
	}
}

func TestLimitRangeDefaults(t *testing.T) {
	bare := tidySpec("api")
	bare.Containers[0].Resources = corev1.ResourceRequirements{}
	all := []string{"cpuLimitMissing", "cpuRequestMissing", "memoryLimitMissing", "memoryRequestMissing"}
	cpu := corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m")}
	both := corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("64Mi")}
	rng := func(ns string, item corev1.LimitRangeItem) *corev1.LimitRange {
		return &corev1.LimitRange{ObjectMeta: meta(ns, "defaults"), Spec: corev1.LimitRangeSpec{Limits: []corev1.LimitRangeItem{item}}}
	}

	for _, tc := range []struct {
		why    string
		ranges []*corev1.LimitRange
		fails  []string
	}{
		{"no ranges", []*corev1.LimitRange{}, all},
		{"container defaults for everything", []*corev1.LimitRange{rng("billing", corev1.LimitRangeItem{Type: corev1.LimitTypeContainer, Default: both, DefaultRequest: both})}, nil},
		{"CPU defaults only", []*corev1.LimitRange{rng("billing", corev1.LimitRangeItem{Type: corev1.LimitTypeContainer, Default: cpu, DefaultRequest: cpu})},
			[]string{"memoryLimitMissing", "memoryRequestMissing"}},
		{"request defaults only", []*corev1.LimitRange{rng("billing", corev1.LimitRangeItem{Type: corev1.LimitTypeContainer, DefaultRequest: both})},
			[]string{"cpuLimitMissing", "memoryLimitMissing"}},
		{"a pod-type range fills nothing in", []*corev1.LimitRange{rng("billing", corev1.LimitRangeItem{Type: corev1.LimitTypePod, Default: both, DefaultRequest: both})}, all},
		{"a maximum is not a default", []*corev1.LimitRange{rng("billing", corev1.LimitRangeItem{Type: corev1.LimitTypeContainer, Max: both})}, all},
		{"another namespace's defaults", []*corev1.LimitRange{rng("payroll", corev1.LimitRangeItem{Type: corev1.LimitTypeContainer, Default: both, DefaultRequest: both})}, all},
	} {
		in := listedEverything()
		in.LimitRanges = tc.ranges
		in.Deployments = []*appsv1.Deployment{deployment("billing", "invoices", 2, bare)}
		r := RunChecks(in)
		var fails []string
		for _, id := range checksFailing(r) {
			if CheckRegistry[id].Category == CategoryEfficiency {
				fails = append(fails, id)
			}
		}
		if !slices.Equal(fails, tc.fails) {
			t.Errorf("%s: failing %v, want %v", tc.why, fails, tc.fails)
		}
	}

	// Without the LimitRange list the sizing checks cannot know what
	// admission fills in, so they do not run at all.
	in := listedEverything()
	in.LimitRanges = nil
	in.Deployments = []*appsv1.Deployment{deployment("billing", "invoices", 2, bare)}
	r := RunChecks(in)
	if _, ran := r.CheckCounts["cpuRequestMissing"]; ran || !slices.Contains(r.MissingInputs, "limitranges") {
		t.Errorf("sizing judged without LimitRanges: %+v, missing %v", r.CheckCounts["cpuRequestMissing"], r.MissingInputs)
	}
}

func TestContainersMergeIntoTheirWorkload(t *testing.T) {
	spec := tidySpec("api", "metrics-sidecar", "log-shipper")
	for i := range spec.Containers[:2] {
		spec.Containers[i].ReadinessProbe = nil
	}
	in := listedEverything()
	in.Deployments = []*appsv1.Deployment{deployment("billing", "invoices", 2, spec)}
	r := RunChecks(in)
	f := findingFor(r, "readinessProbeMissing", "invoices")
	if f == nil || !strings.Contains(f.Message, `"api"`) || !strings.Contains(f.Message, `"metrics-sidecar"`) || strings.Contains(f.Message, "log-shipper") {
		t.Fatalf("merged finding: %+v", f)
	}
	if c := r.CheckCounts["readinessProbeMissing"]; c != (CheckCount{Evaluated: 1, Passed: 0}) {
		t.Errorf("one workload is one subject: %+v", c)
	}
}
