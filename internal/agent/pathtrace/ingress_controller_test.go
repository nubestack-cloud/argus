package pathtrace

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func ingFixture(mod func(*networkingv1.Ingress)) *networkingv1.Ingress {
	ing := &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "ing", Namespace: "ns"}}
	if mod != nil {
		mod(ing)
	}
	return ing
}

func ingressClass(name, controller string) *networkingv1.IngressClass {
	ic := &networkingv1.IngressClass{Spec: networkingv1.IngressClassSpec{Controller: controller}}
	ic.Name = name
	return ic
}

// classedIngress is the shared Ingress fixture with class className, then mod.
func classedIngress(className string, mod func(*networkingv1.Ingress)) *networkingv1.Ingress {
	return ingFixture(func(i *networkingv1.Ingress) {
		i.Spec.IngressClassName = &className
		if mod != nil {
			mod(i)
		}
	})
}

func withLBAddress(i *networkingv1.Ingress) {
	i.Status.LoadBalancer.Ingress = append(i.Status.LoadBalancer.Ingress, networkingv1.IngressLoadBalancerIngress{Hostname: "k8s-shop-web-1a2b3c.elb.eu-west-2.amazonaws.com"})
}

func controllerPod(name, ns string, lbls map[string]string, ready bool) *corev1.Pod {
	return mkPod(name, ns, lbls, ready)
}

func walkerWith(classes ...*networkingv1.IngressClass) (*walker, *fakeProvider) {
	f := newFake()
	f.ingressClasses = classes
	return &walker{p: f}, f
}

// Pods that have finished or are being deleted cannot serve and are not
// counted.
func TestLivePods_ExcludesTerminalAndDeleting(t *testing.T) {
	gone := metav1.Now()
	phase := func(name string, ph corev1.PodPhase) *corev1.Pod {
		p := &corev1.Pod{Status: corev1.PodStatus{Phase: ph}}
		p.Name = name
		return p
	}
	deleting := phase("draining", corev1.PodRunning)
	deleting.DeletionTimestamp = &gone
	var names []string
	for _, p := range livePods([]*corev1.Pod{
		phase("serving", corev1.PodRunning), phase("starting", corev1.PodPending), nil,
		phase("job-done", corev1.PodSucceeded), phase("crashed", corev1.PodFailed), deleting,
	}) {
		names = append(names, p.Name)
	}
	if strings.Join(names, ",") != "serving,starting" {
		t.Fatalf("live = %v", names)
	}
}

func TestIngressEntryAddress(t *testing.T) {
	for _, c := range []struct {
		lb   []networkingv1.IngressLoadBalancerIngress
		want string
	}{
		{nil, ""},
		{[]networkingv1.IngressLoadBalancerIngress{{Hostname: "edge.example.org"}}, "edge.example.org"},
		{[]networkingv1.IngressLoadBalancerIngress{{IP: "198.51.100.9"}}, "198.51.100.9"},
		// A hostname is preferred to an IP on the same entry; an entry with
		// neither is skipped.
		{[]networkingv1.IngressLoadBalancerIngress{{Hostname: "edge.example.org", IP: "198.51.100.9"}, {}, {IP: "198.51.100.10"}}, "edge.example.org,198.51.100.10"},
	} {
		ing := ingFixture(func(i *networkingv1.Ingress) { i.Status.LoadBalancer.Ingress = c.lb })
		if got := strings.Join(ingressEntryAddress(ing), ","); got != c.want {
			t.Errorf("%v: %q, want %q", c.lb, got, c.want)
		}
	}
}

func TestHasCloudLBAnnotations(t *testing.T) {
	for anno, want := range map[string]bool{
		"": false,
		"alb.ingress.kubernetes.io/target-type=ip":       true,
		"ingress.gcp.kubernetes.io/pre-shared-cert=edge": true,
		"networking.gke.io/v1beta1.FrontendConfig=edge":  true,
		"kubernetes.io/ingress.class=gce-internal":       true,
		"kubernetes.io/ingress.class=nginx":              false,
		"nginx.ingress.kubernetes.io/ssl-redirect=true":  false,
	} {
		ing := ingFixture(func(i *networkingv1.Ingress) {
			if k, v, ok := strings.Cut(anno, "="); ok {
				i.Annotations = map[string]string{k: v}
			}
		})
		if got := hasCloudLBAnnotations(ing); got != want {
			t.Errorf("%q: %v, want %v", anno, got, want)
		}
	}
}

func TestIngressControllerFinding_Honesty(t *testing.T) {
	t.Run("unreadable IngressClasses → soft label, never a finding", func(t *testing.T) {
		w, f := walkerWith()
		f.unreadable["IngressClass"] = true
		st := w.ingressControllerStatus(ingFixture(nil))
		if st.hasFinding {
			t.Fatalf("must not condemn; got %+v", st.finding)
		}
		if st.servedBy == "" || !strings.Contains(st.servedByTitle, "IngressClasses") {
			t.Errorf("want the couldn't-identify label; got %q / %q", st.servedBy, st.servedByTitle)
		}
	})
	t.Run("cloud-LB annotations → served label, no finding", func(t *testing.T) {
		w, _ := walkerWith()
		ing := ingFixture(func(i *networkingv1.Ingress) {
			i.Annotations = map[string]string{"alb.ingress.kubernetes.io/scheme": "internet-facing"}
			withLBAddress(i)
		})
		st := w.ingressControllerStatus(ing)
		if st.hasFinding || !strings.Contains(st.servedByTitle, "cloud load balancer") {
			t.Errorf("got finding=%v title=%q", st.hasFinding, st.servedByTitle)
		}
	})
	t.Run("published address → served label, never no-controller", func(t *testing.T) {
		w, _ := walkerWith()
		st := w.ingressControllerStatus(ingFixture(withLBAddress))
		if st.hasFinding || st.servedBy == "" {
			t.Errorf("got finding=%+v servedBy=%q", st.finding, st.servedBy)
		}
	})
	t.Run("legacy class annotation → never no-controller", func(t *testing.T) {
		w, _ := walkerWith()
		ing := ingFixture(func(i *networkingv1.Ingress) {
			i.Annotations = map[string]string{"kubernetes.io/ingress.class": "nginx"}
		})
		if st := w.ingressControllerStatus(ing); st.hasFinding {
			t.Errorf("legacy class must not be condemned; got %+v", st.finding)
		}
	})
}

func TestKnownControllers_CloudClassified(t *testing.T) {
	alb := knownControllers["ingress.k8s.aws/alb"]
	if !alb.cloud || alb.labels["app.kubernetes.io/name"] != "aws-load-balancer-controller" || alb.podOwnerName() != "aws-load-balancer-controller" {
		t.Errorf("ALB must be cloud with the controller pod identity; got %+v", alb)
	}
	if gce := knownControllers["k8s.io/ingress-gce"]; !gce.cloud || len(gce.labels) != 0 {
		t.Errorf("ingress-gce must be cloud with no pod labels; got %+v", gce)
	}
	if info := knownControllers["k8s.io/ingress-nginx"]; info.cloud || len(info.labels) == 0 {
		t.Errorf("ingress-nginx must be in-cluster with pod labels; got %+v", info)
	}
}

func TestIngressControllerStatus_CloudClassNoAddress_Warns(t *testing.T) {
	w, _ := walkerWith(ingressClass("alb", "ingress.k8s.aws/alb"))
	st := w.ingressControllerStatus(classedIngress("alb", nil))
	if !st.hasFinding || st.finding.Code != "ingress:no-address" || st.finding.Severity != SeverityWarning {
		t.Fatalf("want ingress:no-address warning; got %v %+v", st.hasFinding, st.finding)
	}
	if !strings.Contains(st.finding.Message, "no load balancer address has been assigned") {
		t.Errorf("message = %q", st.finding.Message)
	}
	if strings.Contains(st.finding.Message, "Served by") || strings.Contains(st.servedByTitle, "Served by") {
		t.Errorf("configured-only tier must never read as served")
	}
}

func TestIngressControllerStatus_CloudClassWithAddress_Served(t *testing.T) {
	w, _ := walkerWith(ingressClass("alb", "ingress.k8s.aws/alb"))
	st := w.ingressControllerStatus(classedIngress("alb", withLBAddress))
	if st.hasFinding {
		t.Fatalf("must not warn; got %+v", st.finding)
	}
	if !strings.Contains(st.servedByTitle, "Served by AWS Application Load Balancer") || strings.Contains(st.servedByTitle, "pod") {
		t.Errorf("want programmed-tier wording without pod claims; got %q", st.servedByTitle)
	}
}

func TestIngressControllerStatus_ClassBeatsStaleCloudAnnotations(t *testing.T) {
	w, f := walkerWith(ingressClass("nginx", "k8s.io/ingress-nginx"))
	f.pods = append(f.pods, controllerPod("nginx-0", "ingress-nginx", map[string]string{"app.kubernetes.io/name": "ingress-nginx", "app.kubernetes.io/component": "controller"}, false))
	ing := classedIngress("nginx", func(i *networkingv1.Ingress) {
		i.Annotations = map[string]string{"alb.ingress.kubernetes.io/scheme": "internet-facing"}
	})
	st := w.ingressControllerStatus(ing)
	if !st.hasFinding || st.finding.Code != "ingress:controller-unready" || !strings.Contains(st.finding.Message, "ingress-nginx") {
		t.Fatalf("nginx class must get the nginx pod check; got %+v", st.finding)
	}
	if !strings.Contains(st.finding.Command, "app.kubernetes.io/name=ingress-nginx") {
		t.Errorf("command = %q", st.finding.Command)
	}
}

func TestIngressControllerStatus_InClusterHealthy(t *testing.T) {
	w, f := walkerWith(ingressClass("nginx", "k8s.io/ingress-nginx"))
	f.pods = append(f.pods, controllerPod("nginx-0", "ingress-nginx", map[string]string{"app.kubernetes.io/name": "ingress-nginx", "app.kubernetes.io/component": "controller"}, true))
	st := w.ingressControllerStatus(classedIngress("nginx", nil))
	if st.hasFinding || st.servedBy != "ingress-nginx" || !strings.Contains(st.servedByTitle, "1/1 pods ready") {
		t.Errorf("got %+v", st)
	}
}

func TestIngressControllerStatus_ALBControllerCrashlooping(t *testing.T) {
	w, f := walkerWith(ingressClass("alb", "ingress.k8s.aws/alb"))
	f.pods = append(f.pods, controllerPod("lbc-0", "kube-system", map[string]string{"app.kubernetes.io/name": "aws-load-balancer-controller"}, false))
	st := w.ingressControllerStatus(classedIngress("alb", nil))
	if !st.hasFinding || st.finding.Code != "ingress:controller-unready" {
		t.Fatalf("got %+v", st.finding)
	}
	if !strings.Contains(st.finding.Message, "aws-load-balancer-controller") || !strings.Contains(st.finding.Message, "isn't being served") {
		t.Errorf("message = %q", st.finding.Message)
	}
	// With an address the pods are not judged.
	st = w.ingressControllerStatus(classedIngress("alb", withLBAddress))
	if st.hasFinding || strings.Contains(st.servedByTitle, "pods ready") {
		t.Errorf("address-assigned readout must not judge pods; got %+v", st)
	}
}

func TestIngressControllerStatus_EmptyClassesFiresNoController(t *testing.T) {
	w, _ := walkerWith()
	if _, _, couldRead := w.resolveIngressClass(ingFixture(nil)); !couldRead {
		t.Fatal("a readable empty class list is a real observation")
	}
	st := w.ingressControllerStatus(ingFixture(nil))
	if !st.hasFinding || st.finding.Code != "ingress:no-controller" {
		t.Fatalf("want no-controller; got %+v", st.finding)
	}
}

func TestIngressControllerStatus_NamedClassMissing(t *testing.T) {
	w, _ := walkerWith(ingressClass("nginx", "k8s.io/ingress-nginx"))
	st := w.ingressControllerStatus(classedIngress("ngnix", nil))
	if !st.hasFinding || st.finding.Code != "ingress:no-controller" || !strings.Contains(st.finding.Cause, `"ngnix"`) {
		t.Fatalf("want no-controller naming the missing class; got %+v", st.finding)
	}
}

func TestIngressControllerStatus_DefaultClassResolves(t *testing.T) {
	def := ingressClass("traefik", "traefik.io/ingress-controller")
	def.Annotations = map[string]string{defaultClassAnnotation: "true"}
	w, _ := walkerWith(def)
	st := w.ingressControllerStatus(ingFixture(nil))
	if st.hasFinding || st.servedBy != "Traefik" {
		t.Errorf("the default class must resolve; got %+v", st)
	}
}

func TestBuild_IngressNoControllerDegradesEntry(t *testing.T) {
	f := newFake()
	f.services = append(f.services, mkService("api", "prod", apiLabels))
	f.pods = append(f.pods, mkPod("api-1", "prod", apiLabels, true))
	f.ingresses = append(f.ingresses, ingressTo("web", "prod", "api"))
	tr := build(t, f, "Ingress", "prod", "web")
	nc := findingByCode(tr.Findings, "ingress:no-controller")
	if nc == nil || nc.Hop != "downstream[0]" || nc.Command != "kubectl get ingressclass" {
		t.Fatalf("no-controller = %+v", nc)
	}
	if tr.Verdict != VerdictDegraded {
		t.Errorf("verdict = %q, want degraded", tr.Verdict)
	}
}
