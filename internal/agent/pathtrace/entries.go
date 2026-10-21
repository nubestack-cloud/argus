package pathtrace

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"iter"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// walker carries the provider and options through one Build, memoizing the
// per-namespace pod lists the fan-out reads repeatedly.
type walker struct {
	p    Provider
	opts Options
	pods map[string]podList
}

type podList struct {
	pods []*corev1.Pod
	err  error
}

func (w *walker) podsIn(ns string) ([]*corev1.Pod, error) {
	if w.pods == nil {
		w.pods = map[string]podList{}
	}
	if pl, ok := w.pods[ns]; ok {
		return pl.pods, pl.err
	}
	pods, err := w.p.Pods(ns)
	w.pods[ns] = podList{pods, err}
	return pods, err
}

func (w *walker) getService(ns, name string) (*corev1.Service, error) {
	svcs, err := w.p.Services(ns)
	if err != nil {
		return nil, err
	}
	for _, s := range svcs {
		if s != nil && s.Name == name {
			return s, nil
		}
	}
	return nil, errNotFound
}

func (w *walker) getIngress(ns, name string) (*networkingv1.Ingress, error) {
	ings, err := w.p.Ingresses(ns)
	if err != nil {
		return nil, err
	}
	for _, i := range ings {
		if i != nil && i.Name == name {
			return i, nil
		}
	}
	return nil, errNotFound
}

// listGateway lists a Gateway API kind. served=false means the cluster does
// not serve the kind, so the (empty) answer is authoritative.
func (w *walker) listGateway(kind, ns string) (items []*unstructured.Unstructured, served bool, err error) {
	if w.p.State(gatewayGroup, kind) == StateAbsent {
		return nil, false, nil
	}
	items, err = w.p.Dynamic(gatewayGroup, kind, ns)
	return items, true, err
}

func (w *walker) getGateway(kind, ns, name string) (obj *unstructured.Unstructured, served bool, err error) {
	items, served, err := w.listGateway(kind, ns)
	if !served || err != nil {
		return nil, served, err
	}
	for _, it := range items {
		if it != nil && it.GetName() == name {
			return it, true, nil
		}
	}
	return nil, true, errNotFound
}

func lookupReason(err error, subject ResourceRef) string {
	if errors.Is(err, errNotFound) {
		return fmt.Sprintf("%s %s/%s was not found", subject.Kind, subject.Namespace, subject.Name)
	}
	return strings.TrimSpace(fmt.Sprintf("%s could not be read: %v", subject.Kind, err))
}

// serviceEntry: downstream is the Service and the pods it selects; upstream
// is every Ingress and route that points at it, each judged on its own,
// since side-by-side entries fail independently.
func (w *walker) serviceEntry(ctx context.Context, t *Trace) {
	svc, err := w.getService(t.Subject.Namespace, t.Subject.Name)
	if err != nil {
		t.Verdict, t.Reason, t.UnknownClass = VerdictUnknown, lookupReason(err, t.Subject), UnknownClassInvestigate
		return
	}
	t.Subject = refForService(svc)
	defer w.setServiceUpstreams(ctx, svc, t)
	hop := Hop{Resource: t.Subject, Edge: "entry:Service", Config: serviceConfig(svc)}

	if svc.Spec.Type == corev1.ServiceTypeExternalName {
		t.Downstream = []Hop{hop, {
			Resource: ResourceRef{Kind: "ExternalName", Name: svc.Spec.ExternalName},
			Edge:     "Service->ExternalName",
			Findings: []Finding{externalNameFinding(svc)},
		}}
		return
	}
	if len(svc.Spec.Selector) == 0 {
		w.annotateSelectorless(&hop, svc)
		t.Downstream = []Hop{hop}
		return
	}
	hop.Meta = map[string]any{}
	if svc.Spec.ClusterIP == corev1.ClusterIPNone {
		hop.Meta["headless"] = true
	}
	// Without an external address a LoadBalancer cannot be reached from
	// outside; inside the cluster its ClusterIP still works.
	if svc.Spec.Type == corev1.ServiceTypeLoadBalancer && len(svc.Status.LoadBalancer.Ingress) == 0 {
		hop.Findings = append(hop.Findings, Finding{
			Code:     "svc:loadbalancer-pending",
			Severity: SeverityWarning,
			Message:  "The LoadBalancer has no external address yet, so nothing outside the cluster can reach it (inside, its ClusterIP works as usual)",
			Command:  fmt.Sprintf("kubectl get service %s -n %s", svc.Name, svc.Namespace),
		})
	}
	pods := w.backendHops(&hop, svc)
	t.Downstream = []Hop{hop, pods}
}

// backendHops fills the Service hop's backend findings and builds the Pods
// hop behind it. backendPorts scopes the NetworkPolicy check to the Service
// ports the upstream route actually uses (empty = every port).
func (w *walker) backendHops(svcHop *Hop, svc *corev1.Service, backendPorts ...string) Hop {
	pods, unreadable := w.selectedPods(svc)
	svcHop.Findings = append(svcHop.Findings, serviceBackendFindings(svc, pods, unreadable)...)
	if adv, ok := targetPortAdvisory(svc, pods); ok {
		svcHop.Findings = append(svcHop.Findings, adv)
	}
	podsHop := w.buildPodsHop(svc, pods, unreadable, backendPorts...)
	linkNoReadyToCulprit(svcHop, &podsHop)
	sortFindingsBySeverity(svcHop.Findings)
	return podsHop
}

func externalNameFinding(svc *corev1.Service) Finding {
	return Finding{
		Code:     "svc:external-name",
		Severity: SeverityInfo,
		Message:  fmt.Sprintf("Service resolves to %q outside the cluster; the path beyond it is not traced", svc.Spec.ExternalName),
	}
}

// annotateSelectorless marks a selectorless Service hop: its endpoints are
// managed by hand, so pod health can't be derived and the verdict reads
// unknown (by design). The EndpointSlice count is stated when readable.
func (w *walker) annotateSelectorless(hop *Hop, svc *corev1.Service) {
	if hop.Meta == nil {
		hop.Meta = map[string]any{}
	}
	hop.Meta["selectorless"] = true
	msg := "Service has no selector; endpoints are managed manually and pod health is not derivable"
	if total, ready, ok := w.manualEndpoints(svc); ok {
		hop.Meta["manualEndpoints"] = total
		hop.Meta["manualReadyEndpoints"] = ready
		if total == 0 {
			msg += "; it currently has no endpoints at all, so connections to it fail"
		} else {
			msg += fmt.Sprintf("; it lists %d endpoint(s), %d ready", total, ready)
		}
	}
	hop.Findings = append(hop.Findings, Finding{
		Code:     "svc:selectorless",
		Severity: SeverityInfo,
		Message:  msg,
		Command:  fmt.Sprintf("kubectl get endpointslices -n %s -l kubernetes.io/service-name=%s", svc.Namespace, svc.Name),
	})
}

// manualEndpoints counts the endpoints in the Service's EndpointSlices. A
// nil Ready condition counts as ready, as the EndpointSlice API defines.
func (w *walker) manualEndpoints(svc *corev1.Service) (total, ready int, ok bool) {
	slices, err := w.p.EndpointSlices(svc.Namespace)
	if err != nil {
		return 0, 0, false
	}
	for _, s := range slices {
		if s == nil || s.Labels[discoveryv1.LabelServiceName] != svc.Name {
			continue
		}
		for _, e := range s.Endpoints {
			total++
			if e.Conditions.Ready == nil || *e.Conditions.Ready {
				ready++
			}
		}
	}
	return total, ready, true
}

// annotateServiceTerminal applies the Service-entry terminal handling to a
// backend Service reached from an Ingress or route, so an entry backed by a
// selectorless Service reads unknown exactly as a direct trace of it does.
// Returns true when terminal (no Pods hop follows).
func (w *walker) annotateServiceTerminal(hop *Hop, svc *corev1.Service) bool {
	if svc == nil {
		return false
	}
	if svc.Spec.Type == corev1.ServiceTypeExternalName {
		hop.Findings = append(hop.Findings, externalNameFinding(svc))
		return true
	}
	if len(svc.Spec.Selector) == 0 {
		w.annotateSelectorless(hop, svc)
		return true
	}
	return false
}

func (w *walker) setServiceUpstreams(ctx context.Context, svc *corev1.Service, t *Trace) {
	upstreams, complete := w.serviceUpstreams(ctx, svc)
	var notes []Finding
	if n := len(upstreams); n > maxUpstreams {
		t.Truncated = true
		upstreams = upstreams[:maxUpstreams]
		notes = append(notes, Finding{
			Code:     "trace:upstreams-truncated",
			Severity: SeverityInfo,
			Message:  fmt.Sprintf("%d Ingresses and routes reference this Service; the first %d are shown", n, maxUpstreams),
		})
	}
	if !complete {
		notes = append(notes, Finding{
			Code:     "trace:upstreams-incomplete",
			Severity: SeverityInfo,
			Message:  "Not every Ingress or Gateway API route could be read, so the entries listed may not be all of them - an empty list does not show that nothing points here.",
		})
	}
	t.Upstreams = upstreams
	if len(t.Downstream) > 0 {
		t.Downstream[0].Findings = append(t.Downstream[0].Findings, notes...)
	}
}

// serviceConfig is the wiring a Service declares.
func serviceConfig(svc *corev1.Service) *HopConfig {
	if svc == nil {
		return nil
	}
	c := &HopConfig{ServiceType: string(svc.Spec.Type), ClusterIP: svc.Spec.ClusterIP, Ports: servicePortMaps(svc)}
	if len(svc.Spec.Selector) > 0 {
		c.Selector = maps.Clone(svc.Spec.Selector)
	}
	return c
}

// servicePortMaps lists each Service port with the port its pods receive on:
// the targetPort as written (a number or a name), or the Service port when
// targetPort is left out.
func servicePortMaps(svc *corev1.Service) []PortMap {
	out := make([]PortMap, len(svc.Spec.Ports))
	for i, p := range svc.Spec.Ports {
		target := p.TargetPort.String()
		if p.TargetPort.Type == intstr.Int && p.TargetPort.IntVal <= 0 || target == "" {
			target = strconv.Itoa(int(p.Port))
		}
		out[i] = PortMap{Name: p.Name, Port: p.Port, TargetPort: target, Protocol: string(p.Protocol)}
		if p.AppProtocol != nil {
			out[i].AppProtocol = *p.AppProtocol
		}
	}
	return out
}

// buildPodsHop is the hop for the pods a Service selects. Its "ready" meta is
// the number of endpoints the dataplane routes to: for a Service that
// publishes not-ready addresses that is every selected pod, so its by-design
// zero-ready state is not drawn as an outage (each pod's own readiness is
// still in Config.Pods).
func (w *walker) buildPodsHop(svc *corev1.Service, pods []*corev1.Pod, unreadable bool, backendPorts ...string) Hop {
	ref := ResourceRef{Kind: "Pods", Namespace: svc.Namespace}
	publishAll := svc.Spec.PublishNotReadyAddresses
	meta := map[string]any{"selected": len(pods), "ready": readyCount(pods), "endpointSource": "pod-readiness"}
	if publishAll {
		meta["ready"] = publishedEndpointCount(pods)
		meta["publishNotReadyAddresses"] = true
	}
	hop := Hop{Resource: ref, Edge: "Service->Pods", Meta: meta, Config: podsConfig(pods, svc)}
	if hop.Config != nil {
		hop.Config.Workload = w.podsWorkload(pods)
	}
	if unreadable {
		// An empty selection that could not be read is not "no backends".
		meta["endpointSource"] = "unknown"
		hop.Findings = append(hop.Findings, Finding{
			Code:     "pods:lister-error",
			Severity: SeverityInfo,
			Message:  "The pods behind the Service's selector could not be listed - the agent may not be allowed to read pods, or its cache has not synced. Until that clears, nothing past this hop is verified.",
		})
	}
	if f, extra, ok := policyFinding(w.p, w.opts.PolicyEvaluator, svc, pods, backendPorts...); ok {
		hop.Findings = append(hop.Findings, f)
		maps.Copy(meta, extra)
	}
	hop.Findings = append(hop.Findings, notReadyPodFindings(pods, publishAll)...)
	if cmd := selectorReproducer(ref, svc.Spec.Selector); cmd != "" {
		for i := range hop.Findings {
			hop.Findings[i].Command = cmp.Or(hop.Findings[i].Command, cmd)
		}
	}
	sortFindingsBySeverity(hop.Findings)
	return hop
}

// notReadyPodFindings reports the first not-ready pod (by name) whose state
// says why. With none ready it is pods:no-ready-endpoints, a warning — the
// Service hop carries the critical symptom — or only info when the Service
// publishes not-ready addresses anyway. With some ready it is
// pods:some-not-ready: degraded, still serving.
func notReadyPodFindings(pods []*corev1.Pod, publishAll bool) []Finding {
	live := livePods(pods)
	ready := readyCount(live)
	if ready == len(live) {
		return nil
	}
	var culprit *corev1.Pod
	var cause, command string
	for _, p := range sortedPods(live) {
		if podIsReady(p) {
			continue
		}
		if c, cmd := podDiagnosis(p); c != "" {
			culprit, cause, command = p, c, cmd
			break
		}
	}
	if culprit == nil {
		return nil
	}
	f := Finding{Command: command, Resource: &ResourceRef{Kind: "Pod", Namespace: culprit.Namespace, Name: culprit.Name}}
	switch {
	case ready > 0:
		f.Code, f.Severity, f.Cause = "pods:some-not-ready", SeverityWarning, cause
		f.Message = fmt.Sprintf("%d of %d selected pods are not ready; only the %d ready ones receive traffic", len(live)-ready, len(live), ready)
	case publishAll:
		f.Code, f.Severity = "pods:no-ready-endpoints", SeverityInfo
		f.Message = cause + " - but this Service publishes endpoints whether or not pods are ready (publishNotReadyAddresses), so traffic still goes to it"
	default:
		f.Code, f.Severity, f.Message = "pods:no-ready-endpoints", SeverityWarning, cause
	}
	return []Finding{f}
}

// sortedPods is pods without nils, by name.
func sortedPods(pods []*corev1.Pod) []*corev1.Pod {
	out := slices.DeleteFunc(slices.Clone(pods), func(p *corev1.Pod) bool { return p == nil })
	slices.SortFunc(out, func(a, b *corev1.Pod) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// podsConfig summarises the selected pods: the container ports the Service
// actually sends to (a sidecar's or admin port is not on the path), their
// probes, and a roster of at most maxPodsInConfig pods with the not-ready
// ones first, so a culprit is never the one cut. PodTotal is the real count,
// so a cut roster never reads as all of them.
func podsConfig(pods []*corev1.Pod, svc *corev1.Service) *HopConfig {
	sorted := sortedPods(pods)
	if len(sorted) == 0 {
		return nil
	}
	onPath := targetedBy(svc)
	c := &HopConfig{PodTotal: len(sorted)}
	ports := map[ContainerPortRef]bool{}
	checks := map[[2]string]HealthCheckRef{}
	var roster []PodStatus
	for _, pod := range sorted {
		st := PodStatus{Name: pod.Name, IP: pod.Status.PodIP, Ready: podIsReady(pod)}
		if !st.Ready {
			cause, _ := podDiagnosis(pod)
			st.Reason = cmp.Or(cause, "not ready")
		}
		roster = append(roster, st)
		for _, ctr := range pod.Spec.Containers {
			for _, p := range ctr.Ports {
				if onPath(p.Name, p.ContainerPort) {
					ports[ContainerPortRef{Container: ctr.Name, Name: p.Name, Port: p.ContainerPort, Protocol: string(p.Protocol)}] = true
				}
			}
			for kind, probe := range map[string]*corev1.Probe{"readiness": ctr.ReadinessProbe, "liveness": ctr.LivenessProbe} {
				if ref, ok := describeHealthCheck(ctr.Name, kind, probe, ctr.Ports); ok {
					checks[[2]string{ctr.Name, kind}] = ref
				}
			}
		}
	}
	// Not ready first, each group still by name.
	slices.SortStableFunc(roster, func(a, b PodStatus) int {
		switch {
		case a.Ready == b.Ready:
			return 0
		case !a.Ready:
			return -1
		}
		return 1
	})
	c.Pods = roster[:min(len(roster), maxPodsInConfig)]
	// One entry per container, port name and number; a protocol differing
	// on another pod does not make a second entry.
	seen := map[string]bool{}
	for _, p := range slices.SortedFunc(maps.Keys(ports), func(a, b ContainerPortRef) int {
		return cmp.Or(strings.Compare(a.Container, b.Container), cmp.Compare(a.Port, b.Port), strings.Compare(a.Name, b.Name), strings.Compare(a.Protocol, b.Protocol))
	}) {
		if id := p.Container + "/" + p.Name + "/" + strconv.Itoa(int(p.Port)); !seen[id] {
			seen[id] = true
			c.ContainerPorts = append(c.ContainerPorts, p)
		}
	}
	for _, k := range slices.SortedFunc(maps.Keys(checks), func(a, b [2]string) int {
		return cmp.Or(strings.Compare(a[0], b[0]), strings.Compare(a[1], b[1]))
	}) {
		c.HealthChecks = append(c.HealthChecks, checks[k])
	}
	return c
}

// targetedBy says whether a container port, by name and number, is one the
// Service sends to. A targetPort left out means the Service port. Without a
// Service, or one with no ports, every port counts.
func targetedBy(svc *corev1.Service) func(name string, port int32) bool {
	if svc == nil || len(svc.Spec.Ports) == 0 {
		return func(string, int32) bool { return true }
	}
	numbers, names := map[int32]bool{}, map[string]bool{}
	for _, sp := range svc.Spec.Ports {
		switch tp := sp.TargetPort; {
		case tp.Type == intstr.String && tp.StrVal != "":
			names[tp.StrVal] = true
		case tp.Type == intstr.Int && tp.IntVal > 0:
			numbers[tp.IntVal] = true
		default:
			numbers[sp.Port] = true
		}
	}
	return func(name string, port int32) bool { return numbers[port] || name != "" && names[name] }
}

// describeHealthCheck summarises one probe. A named probe port is shown with
// the number the container declares for it ("http→8080"), or marked
// unresolved when it declares none.
func describeHealthCheck(container, kind string, probe *corev1.Probe, ports []corev1.ContainerPort) (HealthCheckRef, bool) {
	if probe == nil {
		return HealthCheckRef{}, false
	}
	portText := func(p intstr.IntOrString) string {
		if p.Type == intstr.Int {
			if p.IntVal > 0 {
				return strconv.Itoa(int(p.IntVal))
			}
			return ""
		}
		if i := slices.IndexFunc(ports, func(cp corev1.ContainerPort) bool { return cp.Name == p.StrVal && cp.ContainerPort > 0 }); i >= 0 {
			return fmt.Sprintf("%s→%d", p.StrVal, ports[i].ContainerPort)
		}
		if p.StrVal == "" {
			return ""
		}
		return p.StrVal + "(unresolved)"
	}
	ref := HealthCheckRef{Container: container, Type: kind}
	h := probe.ProbeHandler
	switch {
	case h.HTTPGet != nil:
		ref.Port, ref.Path, ref.Scheme = portText(h.HTTPGet.Port), h.HTTPGet.Path, string(h.HTTPGet.Scheme)
	case h.TCPSocket != nil:
		ref.Port, ref.Scheme = portText(h.TCPSocket.Port), "TCP"
	case h.GRPC != nil:
		ref.Scheme = "gRPC"
		if h.GRPC.Port > 0 {
			ref.Port = strconv.Itoa(int(h.GRPC.Port))
		}
	case h.Exec != nil:
		ref.Scheme = "exec"
	default:
		return HealthCheckRef{}, false
	}
	return ref, true
}

// selectedPods returns the pods matching the Service selector. unreadable is
// true when the pod list could not be read: callers must then mark the Pods
// hop unknown instead of treating the empty slice as "no backends".
func (w *walker) selectedPods(svc *corev1.Service) (pods []*corev1.Pod, unreadable bool) {
	if svc == nil || len(svc.Spec.Selector) == 0 {
		return nil, false
	}
	all, err := w.podsIn(svc.Namespace)
	if err != nil {
		return nil, true
	}
	sel := labels.SelectorFromSet(labels.Set(svc.Spec.Selector))
	for _, p := range all {
		if p != nil && sel.Matches(labels.Set(p.Labels)) {
			pods = append(pods, p)
		}
	}
	return pods, false
}

// serviceUpstreams reverse-walks Ingresses and Gateway API routes pointing at
// the Service. complete=false means some kind could not be read, so the list
// (or its emptiness) must not be presented as the full set.
func (w *walker) serviceUpstreams(ctx context.Context, svc *corev1.Service) ([]Hop, bool) {
	out, complete := w.ingressUpstreamsForService(ctx, svc)
	for _, kind := range []string{"HTTPRoute", "GRPCRoute"} {
		hops, ok := w.routeUpstreamsForService(svc, kind)
		out = append(out, hops...)
		complete = complete && ok
	}
	sortHopsByResource(out)
	return out, complete
}

func (w *walker) ingressUpstreamsForService(ctx context.Context, svc *corev1.Service) ([]Hop, bool) {
	ingresses, err := w.p.Ingresses(svc.Namespace)
	if err != nil {
		return nil, false
	}
	var out []Hop
	for _, ing := range ingresses {
		if !ingressReferencesService(ing, svc.Name) {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		ref := ResourceRef{Group: "networking.k8s.io", Kind: "Ingress", Namespace: ing.Namespace, Name: ing.Name}
		hop := Hop{
			Resource: ref,
			Edge:     "Ingress->Service",
			Config:   ingressConfig(ing),
			Findings: w.ingressMissingRefFindings(ing),
		}
		w.applyIngressController(&hop, ing)
		out = append(out, hop)
	}
	return out, true
}

// ingressBackends yields every Service backend an Ingress names, in the
// order it names them: the default backend, then each rule's paths. host is
// the rule's host ("" for the default backend and host-less rules) and path
// the rule path, "(default backend)" for the default.
func ingressBackends(ing *networkingv1.Ingress) iter.Seq2[ingressPath, *networkingv1.IngressServiceBackend] {
	return func(yield func(ingressPath, *networkingv1.IngressServiceBackend) bool) {
		if ing == nil {
			return
		}
		if d := ing.Spec.DefaultBackend; d != nil && d.Service != nil {
			if !yield(ingressPath{path: "(default backend)", isDefault: true}, d.Service) {
				return
			}
		}
		for _, r := range ing.Spec.Rules {
			if r.HTTP == nil {
				continue
			}
			for _, p := range r.HTTP.Paths {
				if !yield(ingressPath{host: r.Host, path: cmp.Or(p.Path, "/")}, p.Backend.Service) {
					return
				}
			}
		}
	}
}

// ingressPath is where in an Ingress a backend is named.
type ingressPath struct {
	host, path string
	isDefault  bool
}

func ingressReferencesService(ing *networkingv1.Ingress, svcName string) bool {
	for _, b := range ingressBackends(ing) {
		if b != nil && b.Name == svcName {
			return true
		}
	}
	return false
}

// routeUpstreamsForService lists routes of kind referencing the Service from
// any namespace (backendRefs may cross namespaces). The bool reports whether
// the enumeration is authoritative.
func (w *walker) routeUpstreamsForService(svc *corev1.Service, kind string) ([]Hop, bool) {
	routes, served, err := w.listGateway(kind, "")
	if !served {
		return nil, true
	}
	if err != nil {
		return nil, false
	}
	var out []Hop
	for _, route := range routes {
		if route == nil || !routeReferencesService(route, svc.Namespace, svc.Name) {
			continue
		}
		ref := ResourceRef{Group: gatewayGroup, Kind: kind, Namespace: route.GetNamespace(), Name: route.GetName()}
		findings := w.routeMissingRefFindings(route, kind)
		findings = append(findings, routeStatusFindings(route, kind, nil)...)
		out = append(out, Hop{
			Resource: ref,
			Edge:     kind + "->Service",
			Findings: findings,
		})
	}
	return out, true
}

// routeRule is one rule of an HTTPRoute or GRPCRoute: its match maps and its
// backendRefs, read once.
type routeRule struct {
	matches []map[string]any
	refs    []routeRef
}

// routeRef is one backendRef. namespace is resolved (the route's when the ref
// leaves it out) and port is the ref's port as text; weighted reports
// whether a weight was written at all.
type routeRef struct {
	raw             map[string]any
	group, kind     string
	name, namespace string
	port            string
	weight          int64
	weighted        bool
}

func (r routeRef) isService() bool { return gatewayBackendIsService(r.raw) }

// rulesOf reads a route's rules; entries of the wrong shape are skipped.
func rulesOf(route *unstructured.Unstructured) []routeRule {
	list, _, _ := unstructured.NestedSlice(route.Object, "spec", "rules")
	var out []routeRule
	for _, item := range list {
		rm, ok := item.(map[string]any)
		if !ok {
			continue
		}
		var rule routeRule
		for _, m := range asMaps(rm["matches"]) {
			rule.matches = append(rule.matches, m)
		}
		for _, ref := range asMaps(rm["backendRefs"]) {
			r := routeRef{raw: ref, namespace: gatewayRefNamespace(ref, route.GetNamespace()), port: backendPortString(ref["port"])}
			r.group, _ = ref["group"].(string)
			r.kind, _ = ref["kind"].(string)
			r.name, _ = ref["name"].(string)
			r.weight, r.weighted = backendRefWeight(ref)
			rule.refs = append(rule.refs, r)
		}
		out = append(out, rule)
	}
	return out
}

func asMaps(v any) []map[string]any {
	list, _ := v.([]any)
	var out []map[string]any
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// serviceRefs is every backendRef of the route that names a core Service.
func serviceRefs(route *unstructured.Unstructured) []routeRef {
	var out []routeRef
	for _, rule := range rulesOf(route) {
		for _, r := range rule.refs {
			if r.isService() {
				out = append(out, r)
			}
		}
	}
	return out
}

func routeReferencesService(route *unstructured.Unstructured, svcNS, svcName string) bool {
	return slices.ContainsFunc(serviceRefs(route), func(r routeRef) bool { return r.name == svcName && r.namespace == svcNS })
}

// routeBackendRefMaps is every rule's backendRefs, flattened, as written.
func routeBackendRefMaps(route *unstructured.Unstructured) []map[string]any {
	var out []map[string]any
	for _, rule := range rulesOf(route) {
		for _, r := range rule.refs {
			out = append(out, r.raw)
		}
	}
	return out
}

func (w *walker) ingressEntry(ctx context.Context, t *Trace) {
	ing, err := w.getIngress(t.Subject.Namespace, t.Subject.Name)
	if err != nil {
		t.Verdict, t.Reason, t.UnknownClass = VerdictUnknown, lookupReason(err, t.Subject), UnknownClassInvestigate
		return
	}
	t.Subject = ResourceRef{Group: "networking.k8s.io", Kind: "Ingress", Namespace: ing.Namespace, Name: ing.Name}
	entry := Hop{Resource: t.Subject, Edge: "entry:Ingress", Config: ingressConfig(ing), Findings: w.ingressMissingRefFindings(ing)}
	w.applyIngressController(&entry, ing)

	names := ingressBackendNames(ing)
	if len(names) > maxBackendsTraced {
		// The verdict covers only the backends walked; the entry says so.
		t.Truncated = true
		entry.Findings = append(entry.Findings, Finding{
			Code:     "ingress:backends-truncated",
			Severity: SeverityInfo,
			Message:  fmt.Sprintf("%d backends; the first %d are traced, to keep the result bounded", len(names), maxBackendsTraced),
		})
		names = names[:maxBackendsTraced]
	}
	t.Downstream = []Hop{entry}
	for _, name := range names {
		if ctx.Err() != nil {
			break
		}
		ref := ResourceRef{Kind: "Service", Namespace: ing.Namespace, Name: name}
		t.Downstream = append(t.Downstream, w.backendBranch(ref, "Ingress->Service", ingressBackendPorts(ing, name), nil)...)
	}
}

// backendBranch builds the Service hop (and Pods hop when the Service selects
// pods) for one route backend. A Service that couldn't be read is marked
// unknown; a confirmed missing one is left bare because the entry hop's
// missing_ref finding already states the break.
func (w *walker) backendBranch(svcRef ResourceRef, edge string, backendPorts []string, extra func(*Hop) bool) []Hop {
	svcHop := Hop{Resource: svcRef, Edge: edge}
	svc, err := w.getService(svcRef.Namespace, svcRef.Name)
	if err == nil {
		svcHop.Config = serviceConfig(svc)
	} else if !errors.Is(err, errNotFound) {
		svcHop.Meta = map[string]any{"endpointSource": "unknown"}
	}
	if extra != nil && extra(&svcHop) {
		return []Hop{svcHop}
	}
	if err != nil || w.annotateServiceTerminal(&svcHop, svc) {
		return []Hop{svcHop}
	}
	podsHop := w.backendHops(&svcHop, svc, backendPorts...)
	return []Hop{svcHop, podsHop}
}

// ingressBackendPorts is the distinct Service ports the Ingress sends to for
// one backend, so the NetworkPolicy check looks only at the ports on the
// path.
func ingressBackendPorts(ing *networkingv1.Ingress, name string) []string {
	var out []string
	for _, b := range ingressBackends(ing) {
		if b == nil || b.Name != name {
			continue
		}
		if p := ingressBackendPortString(b.Port); p != "" && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// ingressConfig is what an Ingress declares: its hosts, a rule per path
// (host and path to backend), its class and the address it is published at.
func ingressConfig(ing *networkingv1.Ingress) *HopConfig {
	if ing == nil {
		return nil
	}
	c := &HopConfig{}
	for _, r := range ing.Spec.Rules {
		if r.Host != "" && !slices.Contains(c.Hostnames, r.Host) {
			c.Hostnames = append(c.Hostnames, r.Host)
		}
	}
	for at, b := range ingressBackends(ing) {
		rule := RouteRule{Paths: []string{at.path}}
		if at.host != "" {
			rule.Hosts = []string{at.host}
		}
		if b != nil {
			rule.Backends = []BackendRef{{Kind: "Service", Name: b.Name, Port: ingressBackendPortString(b.Port)}}
		}
		c.Rules = append(c.Rules, rule)
	}
	if cls := ing.Spec.IngressClassName; cls != nil && *cls != "" {
		c.Selector = map[string]string{"ingressClass": *cls}
	}
	c.Addresses = ingressEntryAddress(ing)
	return c
}

// ingressBackendPortString is a backend port by name, else by number.
func ingressBackendPortString(p networkingv1.ServiceBackendPort) string {
	switch {
	case p.Name != "":
		return p.Name
	case p.Number > 0:
		return strconv.Itoa(int(p.Number))
	}
	return ""
}

// ingressBackendNames is the distinct backend Service names, in the order
// the Ingress names them.
func ingressBackendNames(ing *networkingv1.Ingress) []string {
	var out []string
	for _, b := range ingressBackends(ing) {
		if b != nil && b.Name != "" && !slices.Contains(out, b.Name) {
			out = append(out, b.Name)
		}
	}
	return out
}

// ingressMissingRefFindings checks each backend Service exists and exposes
// the referenced port. A Service that couldn't be read is not flagged: only
// a confirmed absence is a missing reference.
func (w *walker) ingressMissingRefFindings(ing *networkingv1.Ingress) []Finding {
	var out []Finding
	seen := map[string]bool{}
	check := func(b *networkingv1.IngressServiceBackend, source string) {
		if b == nil || b.Name == "" {
			return
		}
		key := b.Name + "|" + b.Port.Name + "|" + strconv.Itoa(int(b.Port.Number))
		if seen[key] {
			return
		}
		seen[key] = true
		svc, err := w.getService(ing.Namespace, b.Name)
		if err != nil {
			if errors.Is(err, errNotFound) {
				out = append(out, missingServiceFinding(source, b.Name, ing.Namespace))
			}
			return
		}
		port := ingressBackendPortString(b.Port)
		if port != "" && !serviceHasPort(svc, port) {
			out = append(out, missingPortFinding(source, b.Name, ing.Namespace, port))
		}
	}
	if ing.Spec.DefaultBackend != nil {
		check(ing.Spec.DefaultBackend.Service, "defaultBackend")
	}
	for _, rule := range ing.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, p := range rule.HTTP.Paths {
			check(p.Backend.Service, fmt.Sprintf("rule[host=%q].path[%q]", rule.Host, p.Path))
		}
	}
	return out
}

// routeMissingRefFindings is the Gateway API equivalent: every Service
// backendRef must exist and name a port the Service exposes.
func (w *walker) routeMissingRefFindings(route *unstructured.Unstructured, kind string) []Finding {
	var out []Finding
	seen := map[string]bool{}
	for i, refm := range routeBackendRefMaps(route) {
		name, _ := refm["name"].(string)
		if name == "" || !gatewayBackendIsService(refm) {
			continue
		}
		ns := gatewayRefNamespace(refm, route.GetNamespace())
		port := backendPortString(refm["port"])
		key := ns + "/" + name + "/" + port
		if seen[key] {
			continue
		}
		seen[key] = true
		source := fmt.Sprintf("%s backendRef %d", kind, i)
		svc, err := w.getService(ns, name)
		if err != nil {
			if errors.Is(err, errNotFound) {
				out = append(out, missingServiceFinding(source, name, ns))
			}
			continue
		}
		if port == "" {
			out = append(out, Finding{
				Code:     "missing_ref:backend-port",
				Severity: SeverityCritical,
				Message:  fmt.Sprintf("%s references Service %s/%s without a port, so the backend can't receive traffic", source, ns, name),
				Command:  fmt.Sprintf("kubectl get service %s -n %s -o jsonpath='{.spec.ports}'", name, ns),
			})
			continue
		}
		if !serviceHasPort(svc, port) {
			out = append(out, missingPortFinding(source, name, ns, port))
		}
	}
	return out
}

func missingServiceFinding(source, name, ns string) Finding {
	return Finding{
		Code:     "missing_ref:backend-service",
		Severity: SeverityCritical,
		Message:  fmt.Sprintf("%s references Service %s/%s, which does not exist - that route serves nothing", source, ns, name),
		Action:   "Point the backend at an existing Service, remove the stale backend, or create the Service",
		Command:  fmt.Sprintf("kubectl get service %s -n %s", name, ns),
	}
}

func missingPortFinding(source, name, ns, port string) Finding {
	return Finding{
		Code:     "missing_ref:backend-port",
		Severity: SeverityCritical,
		Message:  fmt.Sprintf("%s targets port %q of Service %s/%s, which the Service does not expose - traffic to that route is dropped", source, port, ns, name),
		Action:   "Point the backend at a port the Service exposes, or add the port to the Service",
		Command:  fmt.Sprintf("kubectl get service %s -n %s -o jsonpath='{.spec.ports}'", name, ns),
	}
}

func serviceHasPort(svc *corev1.Service, port string) bool {
	n, numErr := strconv.Atoi(port)
	for _, sp := range svc.Spec.Ports {
		if sp.Name == port || (numErr == nil && int(sp.Port) == n) {
			return true
		}
	}
	return false
}

func (w *walker) routeEntry(ctx context.Context, t *Trace, kind string) {
	route, served, err := w.getGateway(kind, t.Subject.Namespace, t.Subject.Name)
	if !served || err != nil {
		t.Verdict, t.UnknownClass = VerdictUnknown, UnknownClassInvestigate
		t.Reason = kind + " is not served in this cluster"
		if served {
			t.Reason = lookupReason(err, t.Subject)
		}
		return
	}
	t.Subject = ResourceRef{Group: gatewayGroup, Kind: kind, Namespace: route.GetNamespace(), Name: route.GetName()}
	entry := Hop{Resource: t.Subject, Edge: "entry:" + kind, Config: routeConfig(route), Findings: w.routeMissingRefFindings(route, kind)}
	entry.Findings = append(entry.Findings, routeStatusFindings(route, kind, nil)...)

	backends := routeBackends(route)
	if len(backends) > maxBackendsTraced {
		t.Truncated = true
		entry.Findings = append(entry.Findings, Finding{
			Code:     "route:backends-truncated",
			Severity: SeverityInfo,
			Message:  fmt.Sprintf("%d backends; the first %d are traced, to keep the result bounded", len(backends), maxBackendsTraced),
		})
		backends = backends[:maxBackendsTraced]
	}
	t.Downstream = []Hop{entry}
	for _, b := range backends {
		if ctx.Err() != nil {
			break
		}
		// Weighted to 0 while a sibling takes the traffic, a backend is
		// drained on purpose: it serves nothing, so it is listed without its
		// pods and left out of the verdict.
		drained := func(h *Hop) bool {
			if !routeBackendDrained(route, b.Namespace, b.Name) {
				return false
			}
			if h.Meta == nil {
				h.Meta = map[string]any{}
			}
			h.Meta["drained"] = true
			h.Findings = append(h.Findings, Finding{
				Code:     "route:drained-weight-zero",
				Severity: SeverityInfo,
				Message:  fmt.Sprintf("Backend Service %q has weight 0 while another backend takes the traffic - drained on purpose, it serves no requests", b.Name),
			})
			return true
		}
		t.Downstream = append(t.Downstream, w.backendBranch(b, kind+"->Service", routeBackendPorts(route, b.Namespace, b.Name), drained)...)
	}
	t.Upstreams = w.routeParentGateways(route)
}

// routeConfig is what a route declares: hostnames, and per rule its path
// matches and backends. A path match of any type but PathPrefix is written
// with its type in front ("Exact:/healthz").
func routeConfig(route *unstructured.Unstructured) *HopConfig {
	c := &HopConfig{}
	c.Hostnames, _, _ = unstructured.NestedStringSlice(route.Object, "spec", "hostnames")
	for _, rule := range rulesOf(route) {
		var out RouteRule
		for _, m := range rule.matches {
			path, ok := m["path"].(map[string]any)
			if !ok {
				continue
			}
			typ, _ := path["type"].(string)
			value, _ := path["value"].(string)
			value = cmp.Or(value, "/")
			if typ != "" && typ != "PathPrefix" {
				value = typ + ":" + value
			}
			out.Paths = append(out.Paths, value)
		}
		for _, r := range rule.refs {
			kind := cmp.Or(r.kind, "Service")
			if r.group != "" {
				kind = r.group + "/" + kind
			}
			ns, _ := r.raw["namespace"].(string)
			out.Backends = append(out.Backends, BackendRef{Kind: kind, Name: r.name, Namespace: ns, Port: r.port})
		}
		c.Rules = append(c.Rules, out)
	}
	return c
}

// backendPortString is a port from decoded JSON as text; a fractional number
// is not a port.
func backendPortString(v any) string {
	switch n := v.(type) {
	case string:
		return n
	case int:
		return strconv.Itoa(n)
	case int32:
		return strconv.Itoa(int(n))
	case int64:
		return strconv.FormatInt(n, 10)
	case float64:
		if n == math.Trunc(n) {
			return strconv.FormatInt(int64(n), 10)
		}
	}
	return ""
}

// routeBackendPorts is the distinct ports the route's refs to one Service
// use.
func routeBackendPorts(route *unstructured.Unstructured, namespace, name string) []string {
	var out []string
	for _, r := range serviceRefs(route) {
		if r.name == name && r.namespace == namespace && r.port != "" && !slices.Contains(out, r.port) {
			out = append(out, r.port)
		}
	}
	return out
}

// routeBackendDrained reports a backend drained on purpose: in every rule
// that names it, every ref to it has weight 0 written out, and in at least
// one of those rules another backend carries traffic. A ref to it with no
// weight anywhere means it carries traffic.
func routeBackendDrained(route *unstructured.Unstructured, namespace, name string) bool {
	drained := false
	for _, rule := range rulesOf(route) {
		mine, others := false, false
		for _, r := range rule.refs {
			if !r.isService() {
				continue
			}
			if r.name != name || r.namespace != namespace {
				others = others || !r.weighted || r.weight > 0
				continue
			}
			if !r.weighted || r.weight != 0 {
				return false
			}
			mine = true
		}
		drained = drained || mine && others
	}
	return drained
}

// backendRefWeight is a ref's weight, and whether one was written.
func backendRefWeight(ref map[string]any) (int64, bool) {
	switch v := ref["weight"]; v.(type) {
	case int, int64, float64:
		return wholeNumber(v), true
	}
	return 0, false
}

// routeBackends is the distinct Services a route sends to, in order.
func routeBackends(route *unstructured.Unstructured) []ResourceRef {
	var out []ResourceRef
	for _, r := range serviceRefs(route) {
		ref := ResourceRef{Kind: "Service", Namespace: r.namespace, Name: r.name}
		if r.name != "" && !slices.Contains(out, ref) {
			out = append(out, ref)
		}
	}
	return out
}

// routeParentGateways builds one upstream hop per parent Gateway. Only a
// confirmed absence is gateway:missing-parent; an unreadable Gateway marks
// the hop unknown instead.
func (w *walker) routeParentGateways(route *unstructured.Unstructured) []Hop {
	parents, found, _ := unstructured.NestedSlice(route.Object, "spec", "parentRefs")
	if !found {
		return nil
	}
	seen := map[string]bool{}
	var out []Hop
	for _, p := range parents {
		pm, ok := p.(map[string]any)
		if !ok || !gatewayParentIsGateway(pm) {
			continue
		}
		name, _ := pm["name"].(string)
		ns := gatewayRefNamespace(pm, route.GetNamespace())
		key := ns + "/" + name
		if name == "" || seen[key] {
			continue
		}
		seen[key] = true
		hop := Hop{
			Resource: ResourceRef{Group: gatewayGroup, Kind: "Gateway", Namespace: ns, Name: name},
			Edge:     "Gateway->Route",
		}
		gw, served, err := w.getGateway("Gateway", ns, name)
		switch {
		case !served || errors.Is(err, errNotFound):
			hop.Findings = append(hop.Findings, Finding{
				Code:     "gateway:missing-parent",
				Severity: SeverityCritical,
				Message:  fmt.Sprintf("parentRef points at Gateway %q in namespace %q, which does not exist", name, ns),
				Command:  fmt.Sprintf("kubectl get gateway.gateway.networking.k8s.io -n %s", ns),
			})
		case err != nil:
			hop.Meta = map[string]any{"endpointSource": "unknown"}
		default:
			hop.Config = gatewayConfig(gw)
			hop.Findings = append(hop.Findings, gatewayStatusFindings(gw)...)
		}
		out = append(out, hop)
	}
	return out
}

// gatewayEntry: a Gateway's downstream is its attached routes, side by side
// and capped. Each route's own backends belong to that route's trace.
func (w *walker) gatewayEntry(ctx context.Context, t *Trace) {
	gw, served, err := w.getGateway("Gateway", t.Subject.Namespace, t.Subject.Name)
	if !served || err != nil {
		t.Verdict, t.UnknownClass = VerdictUnknown, UnknownClassInvestigate
		t.Reason = "the Gateway API is not served in this cluster"
		if served {
			t.Reason = lookupReason(err, t.Subject)
		}
		return
	}
	gwRef := ResourceRef{Group: gatewayGroup, Kind: "Gateway", Namespace: gw.GetNamespace(), Name: gw.GetName()}
	t.Subject = gwRef
	entry := Hop{Resource: gwRef, Edge: "entry:Gateway", Config: gatewayConfig(gw), Findings: gatewayStatusFindings(gw)}

	attached, total, complete := w.attachedRoutes(gw)
	if !complete {
		entry.Findings = append(entry.Findings, Finding{
			Code:     "trace:attached-routes-incomplete",
			Severity: SeverityInfo,
			Message:  "Not every Gateway API route kind could be read, so routes attached to this Gateway may be missing from the list.",
		})
	}
	t.Downstream = []Hop{entry}
	for _, ar := range attached {
		if ctx.Err() != nil {
			break
		}
		hop := Hop{Resource: ar.ref, Edge: "Gateway->" + ar.ref.Kind}
		switch ar.ref.Kind {
		case "TCPRoute", "TLSRoute":
			// Listed, so the inventory never looks HTTP-only, but an L4
			// route's backends are not walked.
			hop.Findings = []Finding{{
				Code:     "gateway:l4-route-not-traced",
				Severity: SeverityInfo,
				Message:  fmt.Sprintf("This %s is attached to the Gateway; the backends of L4 routes are not traced.", ar.ref.Kind),
			}}
		default:
			hop.Findings = routeStatusFindings(ar.obj, ar.ref.Kind, &gwRef)
		}
		t.Downstream = append(t.Downstream, hop)
	}
	if total > len(attached) {
		t.Truncated = true
		t.Downstream = append(t.Downstream, Hop{
			Resource: ResourceRef{Kind: "Routes"},
			Edge:     "Gateway->Routes",
			Findings: []Finding{{
				Code:     "gateway:routes-truncated",
				Severity: SeverityInfo,
				Message:  fmt.Sprintf("%d routes are attached; %d are shown", total, len(attached)),
			}},
		})
	}
}

// gatewayConfig is a Gateway's listeners and the addresses in its status.
func gatewayConfig(gw *unstructured.Unstructured) *HopConfig {
	if gw == nil {
		return nil
	}
	c := &HopConfig{}
	listeners, _, _ := unstructured.NestedSlice(gw.Object, "spec", "listeners")
	for _, l := range asMaps(listeners) {
		gl := GatewayListener{Port: int32(wholeNumber(l["port"]))}
		gl.Name, _ = l["name"].(string)
		gl.Protocol, _ = l["protocol"].(string)
		gl.Hostname, _ = l["hostname"].(string)
		c.Listeners = append(c.Listeners, gl)
	}
	addresses, _, _ := unstructured.NestedSlice(gw.Object, "status", "addresses")
	for _, a := range asMaps(addresses) {
		if v, _ := a["value"].(string); v != "" {
			c.Addresses = append(c.Addresses, v)
		}
	}
	return c
}

// gatewayRouteKinds is every route kind inventoried on a Gateway trace.
var gatewayRouteKinds = []string{"HTTPRoute", "GRPCRoute", "TCPRoute", "TLSRoute"}

type attachedRoute struct {
	ref ResourceRef
	obj *unstructured.Unstructured
}

// wholeNumber reads a JSON number whatever Go type decoding gave it.
func wholeNumber(v any) int64 {
	switch n := v.(type) {
	case int:
		return int64(n)
	case int32:
		return int64(n)
	case int64:
		return n
	case float64:
		return int64(n)
	}
	return 0
}

// attachedRoutes is the routes, from any namespace, attached to the Gateway:
// sorted, at most gatewayRouteCap of them, the total before the cap, and
// whether every route kind served could be read.
func (w *walker) attachedRoutes(gw *unstructured.Unstructured) ([]attachedRoute, int, bool) {
	var all []attachedRoute
	complete := true
	for _, kind := range gatewayRouteKinds {
		routes, served, err := w.listGateway(kind, "")
		switch {
		case !served:
			continue
		case err != nil:
			complete = false
			continue
		}
		for _, r := range routes {
			if r != nil && routeAttachedToGateway(r, gw.GetNamespace(), gw.GetName()) {
				all = append(all, attachedRoute{ResourceRef{Group: gatewayGroup, Kind: kind, Namespace: r.GetNamespace(), Name: r.GetName()}, r})
			}
		}
	}
	slices.SortFunc(all, func(a, b attachedRoute) int { return compareRefs(a.ref, b.ref) })
	return all[:min(len(all), gatewayRouteCap)], len(all), complete
}

// routeAttachedToGateway reports a parentRef naming the Gateway.
func routeAttachedToGateway(route *unstructured.Unstructured, gwNS, gwName string) bool {
	parents, _, _ := unstructured.NestedSlice(route.Object, "spec", "parentRefs")
	return slices.ContainsFunc(asMaps(parents), func(p map[string]any) bool {
		name, _ := p["name"].(string)
		return gatewayParentIsGateway(p) && name == gwName && gatewayRefNamespace(p, route.GetNamespace()) == gwNS
	})
}

func refForService(svc *corev1.Service) ResourceRef {
	return ResourceRef{Kind: "Service", Namespace: svc.Namespace, Name: svc.Name}
}

// sortHopsByResource puts upstream hops in a fixed order: the outermost
// entry kinds first (Ingress, then the routes, then Gateways), then by
// namespace and name.
func sortHopsByResource(hops []Hop) {
	slices.SortStableFunc(hops, func(a, b Hop) int {
		return cmp.Or(cmp.Compare(hopKindPrecedence(a.Resource.Kind), hopKindPrecedence(b.Resource.Kind)),
			strings.Compare(a.Resource.Namespace, b.Resource.Namespace), strings.Compare(a.Resource.Name, b.Resource.Name))
	})
}

var entryKindOrder = map[string]int{"Ingress": 0, "HTTPRoute": 1, "GRPCRoute": 2, "Gateway": 3}

func hopKindPrecedence(kind string) int {
	if n, ok := entryKindOrder[kind]; ok {
		return n
	}
	return 100
}

// compareRefs orders refs by kind, namespace, then name.
func compareRefs(a, b ResourceRef) int {
	return cmp.Or(strings.Compare(a.Kind, b.Kind), strings.Compare(a.Namespace, b.Namespace), strings.Compare(a.Name, b.Name))
}

// podsWorkload names what runs the selected pods, through the owner chain
// (Pod -> ReplicaSet -> Deployment; other controllers own pods directly).
// nil unless every pod agrees on one owner.
func (w *walker) podsWorkload(pods []*corev1.Pod) *ResourceRef {
	var found *ResourceRef
	for _, p := range pods {
		if p == nil {
			continue
		}
		ref := w.ownerWorkload(p)
		if ref == nil {
			return nil
		}
		if found == nil {
			found = ref
			continue
		}
		if *found != *ref {
			return nil
		}
	}
	return found
}

// ownerWorkload walks one pod's owner chain to the workload a human would
// name. The ReplicaSet itself is returned when its parent can't be read.
func (w *walker) ownerWorkload(pod *corev1.Pod) *ResourceRef {
	owner := controllerRef(pod.OwnerReferences)
	if owner == nil {
		return nil
	}
	if owner.Kind != "ReplicaSet" {
		return &ResourceRef{Kind: owner.Kind, Namespace: pod.Namespace, Name: owner.Name}
	}
	rsRef := &ResourceRef{Kind: "ReplicaSet", Namespace: pod.Namespace, Name: owner.Name}
	rss, err := w.p.ReplicaSets(pod.Namespace)
	if err != nil {
		return rsRef
	}
	for _, rs := range rss {
		if rs == nil || rs.Name != owner.Name {
			continue
		}
		if dep := controllerRef(rs.OwnerReferences); dep != nil {
			return &ResourceRef{Kind: dep.Kind, Namespace: pod.Namespace, Name: dep.Name}
		}
	}
	return rsRef
}

func controllerRef(refs []metav1.OwnerReference) *metav1.OwnerReference {
	for i := range refs {
		if refs[i].Controller != nil && *refs[i].Controller {
			return &refs[i]
		}
	}
	return nil
}
