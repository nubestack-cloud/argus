package pathtrace

import (
	"cmp"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// An Ingress is only routing rules; an ingress controller serves the
// traffic. This file surfaces that tier on the Ingress hop - who serves it,
// and whether that is evidenced - without a separate node.
//
// Honesty rules:
//   - Report the tier of evidence: configured (a class or annotation exists)
//     < controller observed (its pods found and ready) < programmed (a load
//     balancer address is published). "Served by" needs at least an observed
//     controller or a published address.
//   - Uncertainty is never a problem. "Couldn't read IngressClasses" or
//     "couldn't find the controller pods" never reads as "no controller".
//   - Only three states are findings: no class resolves (with the classes
//     readable, no address, no cloud annotations, no legacy class), the
//     controller's pods exist but none is ready, or a cloud-class Ingress has
//     no published address.

// ingressEntryAddress is the addresses a controller published in
// status.loadBalancer, a hostname preferred over an IP. None is normal for
// NodePort and hostNetwork set-ups.
func ingressEntryAddress(ing *networkingv1.Ingress) []string {
	if ing == nil {
		return nil
	}
	var out []string
	for _, lb := range ing.Status.LoadBalancer.Ingress {
		if a := cmp.Or(lb.Hostname, lb.IP); a != "" {
			out = append(out, a)
		}
	}
	return out
}

type controllerInfo struct {
	name string // what serves the traffic
	// controllerName is the in-cluster component that manages it when that
	// is something else (the AWS Load Balancer Controller manages ALBs).
	controllerName string
	labels         map[string]string // how to find its pods; none means nothing in-cluster to check
	cloud          bool              // the data plane is a cloud load balancer, and its published address is the evidence
}

// podOwnerName is what runs the pods checkControllerPods looks at.
func (i controllerInfo) podOwnerName() string { return cmp.Or(i.controllerName, i.name) }

// knownControllers is how to recognise and describe the controller behind
// an IngressClass's spec.controller, with the label selector its own charts
// put on its pods. A controller not listed is named and never condemned.
var knownControllers = func() map[string]controllerInfo {
	m := map[string]controllerInfo{}
	add := func(controller, name, selector string, opts ...func(*controllerInfo)) {
		info := controllerInfo{name: name}
		if selector != "" {
			info.labels, _ = labels.ConvertSelectorToLabelsMap(selector)
		}
		for _, o := range opts {
			o(&info)
		}
		m[controller] = info
	}
	cloud := func(i *controllerInfo) { i.cloud = true }
	add("haproxy.org/ingress-controller", "HAProxy Ingress", "app.kubernetes.io/instance=haproxy-ingress")
	add("k8s.io/ingress-nginx", "ingress-nginx", "app.kubernetes.io/component=controller,app.kubernetes.io/name=ingress-nginx")
	add("nginx.org/ingress-controller", "NGINX Ingress (F5)", "app.kubernetes.io/name=nginx-ingress")
	add("projectcontour.io/contour", "Contour", "app.kubernetes.io/name=contour")
	add("traefik.io/ingress-controller", "Traefik", "app.kubernetes.io/name=traefik")
	add("ingress.k8s.aws/alb", "AWS Application Load Balancer", "app.kubernetes.io/name=aws-load-balancer-controller", cloud,
		func(i *controllerInfo) { i.controllerName = "aws-load-balancer-controller" })
	add("k8s.io/ingress-gce", "Google Cloud load balancer", "", cloud)
	return m
}()

const defaultClassAnnotation = "ingressclass.kubernetes.io/is-default-class"

// resolveIngressClass returns the controller string of the IngressClass
// governing the Ingress: the named class, else the cluster default.
// couldRead=false means the classes could not be read at all, which must
// never be reported as "no controller".
func (w *walker) resolveIngressClass(ing *networkingv1.Ingress) (controller string, found, couldRead bool) {
	classes, err := w.p.IngressClasses()
	if err != nil {
		return "", false, false
	}
	want := ""
	if ing.Spec.IngressClassName != nil {
		want = strings.TrimSpace(*ing.Spec.IngressClassName)
	}
	var def *networkingv1.IngressClass
	for _, ic := range classes {
		if ic == nil {
			continue
		}
		if want != "" {
			if ic.Name == want {
				return ic.Spec.Controller, true, true
			}
			continue
		}
		if ic.Annotations[defaultClassAnnotation] == "true" {
			def = ic
		}
	}
	if want == "" && def != nil {
		return def.Spec.Controller, true, true
	}
	return "", false, true
}

// legacyIngressClass returns the legacy kubernetes.io/ingress.class
// annotation, still honoured by ingress-nginx: an Ingress classed only this
// way must not be called controller-less.
func legacyIngressClass(ing *networkingv1.Ingress) string {
	if ing == nil {
		return ""
	}
	return strings.TrimSpace(ing.Annotations["kubernetes.io/ingress.class"])
}

// hasCloudLBAnnotations reports cloud load-balancer annotations -
// configured-tier evidence, consulted only when no IngressClass resolves.
func hasCloudLBAnnotations(ing *networkingv1.Ingress) bool {
	if ing == nil {
		return false
	}
	for key, value := range ing.Annotations {
		if strings.HasPrefix(key, "alb.ingress.kubernetes.io/") ||
			strings.HasPrefix(key, "ingress.gcp.kubernetes.io/") ||
			strings.HasPrefix(key, "networking.gke.io/") {
			return true
		}
		if key == "kubernetes.io/ingress.class" && (strings.Contains(value, "alb") || strings.Contains(value, "gce")) {
			return true
		}
	}
	return false
}

// checkControllerPods finds a controller's pods cluster-wide by its labels.
// found=false (no match, or pods unreadable) means "couldn't see", never
// "broken". Terminal and deleting pods are excluded from the counts.
func (w *walker) checkControllerPods(info controllerInfo) (found bool, ready, total int) {
	if len(info.labels) == 0 {
		return false, 0, 0
	}
	all, err := w.podsIn("")
	if err != nil {
		return false, 0, 0
	}
	sel := labels.SelectorFromSet(labels.Set(info.labels))
	var matched []*corev1.Pod
	for _, p := range all {
		if p != nil && sel.Matches(labels.Set(p.Labels)) {
			matched = append(matched, p)
		}
	}
	if len(matched) == 0 {
		return false, 0, 0
	}
	live := livePods(matched)
	return true, readyCount(live), len(live)
}

// controllerStatus is the controller-tier readout for an Ingress hop: the
// quiet case is a ServedBy label; only a real problem is a finding.
type controllerStatus struct {
	servedBy      string
	servedByTitle string
	finding       Finding
	hasFinding    bool
}

const sharedControllerNote = "It's shared cluster infrastructure that serves this and other Ingresses."

// applyIngressController attaches the controller readout to an Ingress hop.
func (w *walker) applyIngressController(hop *Hop, ing *networkingv1.Ingress) {
	st := w.ingressControllerStatus(ing)
	if st.hasFinding {
		hop.Findings = append(hop.Findings, st.finding)
		sortFindingsBySeverity(hop.Findings)
	}
	if st.servedBy != "" && hop.Config != nil {
		hop.Config.ServedBy = st.servedBy
		hop.Config.ServedByTitle = st.servedByTitle
	}
}

func (w *walker) ingressControllerStatus(ing *networkingv1.Ingress) controllerStatus {
	if ing == nil {
		return controllerStatus{}
	}
	addr := ingressEntryAddress(ing)
	controller, resolved, readable := w.resolveIngressClass(ing)

	// A class that resolves settles who serves the Ingress.
	if resolved {
		info, known := knownControllers[controller]
		switch {
		case !known:
			return unknownControllerStatus(controller, addr)
		case info.cloud:
			return w.cloudClassStatus(ing, info, addr)
		}
		return w.inClusterClassStatus(info, addr)
	}

	// Without a class, every signal is weaker, and so is every claim.
	served := func(label, title string) controllerStatus {
		return controllerStatus{servedBy: label, servedByTitle: title}
	}
	switch legacy := legacyIngressClass(ing); {
	case hasCloudLBAnnotations(ing) && len(addr) > 0:
		return served("via a cloud LB", "A cloud load balancer serves this Ingress - it has been given a load balancer address.")
	case hasCloudLBAnnotations(ing):
		return served("cloud LB (no address)", "This Ingress carries cloud load balancer annotations, but has not been given a load balancer address, so nothing is confirmed to serve it yet.")
	case len(addr) > 0:
		return served("via a controller", fmt.Sprintf("Reachable at %s - some ingress controller serves this, but which one could not be told.", strings.Join(addr, ", ")))
	case legacy != "":
		return served("via a controller", fmt.Sprintf("Class %q is given by the legacy kubernetes.io/ingress.class annotation. %s", legacy, sharedControllerNote))
	case !readable:
		return served("via a controller", "Which ingress controller serves this could not be told, because the IngressClasses could not be read. That does not mean nothing serves it.")
	}

	// Positive evidence of no controller: the classes were read and none
	// resolves; no address, no cloud annotations, no legacy class.
	cause := "An ingress controller is what actually serves Ingress traffic, and none is set up for this one: no IngressClass applies (none is named and there is no default) and no controller has given it an address."
	if name := ing.Spec.IngressClassName; name != nil && strings.TrimSpace(*name) != "" {
		cause = fmt.Sprintf("An ingress controller is what actually serves Ingress traffic. This Ingress names class %q, but there is no IngressClass of that name (misspelt, or not installed) and no controller has given it an address.", *name)
	}
	return controllerStatus{hasFinding: true, finding: Finding{
		Code:     "ingress:no-controller",
		Severity: SeverityWarning,
		Message:  "No ingress controller handles this Ingress - its rules exist, but nothing serves them.",
		Cause:    cause,
		Action:   "Install an ingress controller, or set the Ingress's class to one that is installed",
		Command:  "kubectl get ingressclass",
	}}
}

// cloudClassStatus: the class is a cloud load balancer, so a published
// address is the evidence it is served. Only without one are the managing
// controller's pods checked, since a dead controller is then the likely
// reason.
func (w *walker) cloudClassStatus(ing *networkingv1.Ingress, info controllerInfo, addr []string) controllerStatus {
	what := info.name + " (a cloud load balancer)"
	if len(addr) > 0 {
		return controllerStatus{servedBy: "via " + info.name, servedByTitle: "Served by " + what + " - it has been given a load balancer address."}
	}
	found, ready, total := w.checkControllerPods(info)
	if found && ready == 0 {
		return controllerStatus{hasFinding: true, finding: Finding{
			Code:     "ingress:controller-unready",
			Severity: SeverityWarning,
			Message:  fmt.Sprintf("The %s has no ready pods and no load balancer address has been assigned - this Ingress isn't being served.", info.podOwnerName()),
			Cause:    fmt.Sprintf("This controller creates the cloud load balancer for the Ingress; none of its %d pods is Ready, and no address appears in the Ingress status.", total),
			Action:   "Check the controller's pods",
			Command:  "kubectl get pods -A -l " + labels.Set(info.labels).String(),
		}}
	}
	cause := fmt.Sprintf("This Ingress's class is served by %s, which must create the load balancer and write its address into the Ingress status before any traffic arrives; no address is there. A new Ingress can take a few minutes; an address that never appears usually means creating the load balancer failed, or the controller is not running.", what)
	if found {
		cause += fmt.Sprintf(" The %s is running (%d/%d pods ready), so its logs and the Ingress's events should say what failed.", info.podOwnerName(), ready, total)
	}
	return controllerStatus{hasFinding: true, finding: Finding{
		Code:     "ingress:no-address",
		Severity: SeverityWarning,
		Message:  fmt.Sprintf("Set up for %s, but no load balancer address has been assigned yet - most likely nothing serves this Ingress.", what),
		Cause:    cause,
		Action:   "Check the Ingress events for provisioning errors",
		Command:  fmt.Sprintf("kubectl describe ingress %s -n %s", ing.Name, ing.Namespace),
	}}
}

// inClusterClassStatus: the class resolves to a known in-cluster controller;
// pod readiness is the primary evidence. A missing address is normal here.
func (w *walker) inClusterClassStatus(info controllerInfo, addr []string) controllerStatus {
	var st controllerStatus
	found, ready, total := w.checkControllerPods(info)
	if found {
		if ready == 0 {
			st.finding = Finding{
				Code:     "ingress:controller-unready",
				Severity: SeverityWarning,
				Message:  fmt.Sprintf("The ingress controller (%s) has no ready pods - traffic to this Ingress can't be served right now.", info.name),
				Cause:    fmt.Sprintf("An ingress controller is the component that actually serves Ingress traffic; 0 of %d %s pods are Ready.", total, info.name),
				Action:   "Check the ingress controller's pods",
				Command:  fmt.Sprintf("kubectl get pods -A -l %s", labels.SelectorFromSet(labels.Set(info.labels)).String()),
			}
			st.hasFinding = true
			return st
		}
		st.servedBy = info.name
		if len(addr) > 0 {
			st.servedByTitle = fmt.Sprintf("Handled by the cluster's %s ingress controller (%d/%d pods ready) - a load balancer address is assigned. %s", info.name, ready, total, sharedControllerNote)
		} else {
			st.servedByTitle = fmt.Sprintf("Handled by the cluster's %s ingress controller (%d/%d pods ready). %s", info.name, ready, total, sharedControllerNote)
		}
		return st
	}
	// Pods not found - usually a namespace the agent can't read. Never
	// condemn; only an address upgrades "configured" to "served".
	st.servedBy = info.name
	if len(addr) > 0 {
		st.servedByTitle = fmt.Sprintf("Served by the %s ingress controller - a load balancer address is assigned. Its pods couldn't be seen, so controller health wasn't checked. %s", info.name, sharedControllerNote)
	} else {
		st.servedByTitle = fmt.Sprintf("This Ingress's class is configured for the %s ingress controller - its pods couldn't be seen, so it couldn't be confirmed running. %s", info.name, sharedControllerNote)
	}
	return st
}

// unknownControllerStatus: a class whose controller has no known pod
// labels. Never condemned - many controllers never publish an address.
func unknownControllerStatus(ctrlStr string, addr []string) controllerStatus {
	var st controllerStatus
	st.servedBy = "via a controller"
	if len(addr) > 0 {
		st.servedByTitle = fmt.Sprintf("Served by ingress controller %q - a load balancer address is assigned. %s", ctrlStr, sharedControllerNote)
	} else {
		st.servedByTitle = fmt.Sprintf("This Ingress's class is handled by controller %q - its pods can't be checked, and no load balancer address is published (many controllers never publish one). %s", ctrlStr, sharedControllerNote)
	}
	return st
}
