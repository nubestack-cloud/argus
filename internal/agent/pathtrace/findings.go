package pathtrace

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// reproducerForRef is a read-only kubectl command that shows the state
// behind a finding on ref. The trace explains; the operator decides.
func reproducerForRef(ref ResourceRef) string {
	inNS := ""
	if ref.Namespace != "" {
		inNS = " -n " + ref.Namespace
	}
	switch ref.Kind {
	case "Pods":
		return "kubectl get pods" + inNS
	case "Service", "Pod", "Ingress":
		// For a Pod this is the fallback; podDiagnosis gives the command its
		// state calls for (logs --previous after a crash) when it knows it.
		return "kubectl describe " + strings.ToLower(ref.Kind) + " " + ref.Name + inNS
	case "HTTPRoute", "GRPCRoute":
		return "kubectl get " + strings.ToLower(ref.Kind) + " " + ref.Name + inNS + " -o jsonpath='{.status.parents}'"
	case "Gateway":
		return "kubectl get gateway.gateway.networking.k8s.io " + ref.Name + inNS + " -o yaml"
	}
	return ""
}

// selectorReproducer lists the pods a selector picks, its terms in a fixed
// order so the command is stable.
func selectorReproducer(ref ResourceRef, selector map[string]string) string {
	if len(selector) == 0 || ref.Namespace == "" {
		return ""
	}
	return "kubectl get pods -n " + ref.Namespace + " -l " + labels.Set(selector).String()
}

// serviceBackendFindings is the Service-level backend check: does the
// selector reach ready pods, and do named targetPorts resolve. Nothing is
// said when the pods couldn't be read - the Pods hop carries that as
// unknown instead.
func serviceBackendFindings(svc *corev1.Service, pods []*corev1.Pod, unreadable bool) []Finding {
	if svc == nil || unreadable || svc.Spec.Type == corev1.ServiceTypeExternalName || len(svc.Spec.Selector) == 0 {
		return nil
	}
	ref := ResourceRef{Kind: "Pods", Namespace: svc.Namespace}
	var out []Finding
	ready := readyCount(pods)
	switch {
	case len(pods) == 0:
		out = append(out, Finding{
			Code:     "svc:no-ready-endpoints",
			Severity: SeverityCritical,
			Message:  "No ready endpoints: the Service selector matches no pods",
			Cause:    "nothing receives this Service's traffic; if the workload is intentionally scaled to 0 this is expected, otherwise the selector or the pod labels are wrong",
			Command:  selectorReproducer(ref, svc.Spec.Selector),
		})
	case ready == 0 && svc.Spec.PublishNotReadyAddresses:
		out = append(out, Finding{
			Code:     "svc:no-ready-endpoints",
			Severity: SeverityInfo,
			Message:  fmt.Sprintf("0 of %d selected pods ready; this Service publishes endpoints regardless of readiness (publishNotReadyAddresses), so readiness alone doesn't stop routing", len(pods)),
		})
	case ready == 0:
		out = append(out, Finding{
			Code:     "svc:no-ready-endpoints",
			Severity: SeverityCritical,
			Message:  fmt.Sprintf("No ready endpoints: 0 of %d selected pods are ready", len(pods)),
			Command:  fmt.Sprintf("kubectl describe service %s -n %s", svc.Name, svc.Namespace),
		})
	}
	if missing := unresolvedNamedTargetPorts(svc, pods); len(missing) > 0 {
		out = append(out, Finding{
			Code:     "svc:unresolved-targetport",
			Severity: SeverityWarning,
			Message:  fmt.Sprintf("Named targetPort %s matches no container port declared by the selected pods - traffic on that port has nowhere to go", strings.Join(missing, ", ")),
			Command:  fmt.Sprintf("kubectl get svc %s -n %s -o yaml", svc.Name, svc.Namespace),
		})
	}
	return out
}

// unresolvedNamedTargetPorts lists named targetPorts that no selected pod
// declares. Silent when there are no pods (that is a different finding).
func unresolvedNamedTargetPorts(svc *corev1.Service, pods []*corev1.Pod) []string {
	if len(pods) == 0 {
		return nil
	}
	declared := map[string]bool{}
	for _, p := range pods {
		if p == nil {
			continue
		}
		for _, c := range p.Spec.Containers {
			for _, cp := range c.Ports {
				if cp.Name != "" {
					declared[cp.Name] = true
				}
			}
		}
	}
	var missing []string
	seen := map[string]bool{}
	for _, sp := range svc.Spec.Ports {
		if sp.TargetPort.Type != intstr.String || sp.TargetPort.StrVal == "" {
			continue
		}
		n := sp.TargetPort.StrVal
		if !declared[n] && !seen[n] {
			seen[n] = true
			missing = append(missing, fmt.Sprintf("%q", n))
		}
	}
	return missing
}

// targetPortAdvisory flags a numeric targetPort that is probably wrong: no
// ready pod declares that port, though they do declare others. Declaring a
// containerPort is informational — traffic is forwarded either way — so
// this is a warning to check, never proof of a break, and pods declaring no
// ports at all are left alone.
func targetPortAdvisory(svc *corev1.Service, pods []*corev1.Pod) (Finding, bool) {
	if svc == nil {
		return Finding{}, false
	}
	declared := map[int32]bool{}
	for _, p := range pods {
		if p != nil && podIsReady(p) {
			for _, c := range p.Spec.Containers {
				for _, cp := range c.Ports {
					declared[cp.ContainerPort] = true
				}
			}
		}
	}
	if len(declared) == 0 {
		return Finding{}, false
	}
	var wrong []string
	for _, sp := range svc.Spec.Ports {
		// A named targetPort resolves by name (unresolvedNamedTargetPorts).
		if sp.TargetPort.Type != intstr.Int {
			continue
		}
		target := cmp.Or(sp.TargetPort.IntVal, sp.Port)
		if !declared[target] {
			wrong = append(wrong, fmt.Sprintf("%d→:%d", sp.Port, target))
		}
	}
	if len(wrong) == 0 {
		return Finding{}, false
	}
	var have []string
	for _, p := range slices.Sorted(maps.Keys(declared)) {
		have = append(have, fmt.Sprintf(":%d", p))
	}
	return Finding{
		Code:     "svc:targetport-no-listener",
		Severity: SeverityWarning,
		Message:  fmt.Sprintf("Service targetPort %s is not a port the ready pods declare (they declare %s). If nothing listens there, traffic is dropped without an error.", strings.Join(wrong, ", "), strings.Join(have, ", ")),
		Cause:    "Service targetPort likely wrong",
		Action:   "Check that the Service's targetPort is the port the container listens on",
		Command:  fmt.Sprintf("kubectl get svc %s -n %s -o yaml", svc.Name, svc.Namespace),
	}, true
}

// linkNoReadyToCulprit points the Service's "no ready endpoints" symptom at
// the failing pod the Pods hop names: that pod's logs are the next step, not
// describing the Service.
func linkNoReadyToCulprit(svcHop, podsHop *Hop) {
	i := slices.IndexFunc(podsHop.Findings, func(f Finding) bool {
		return f.Resource != nil && f.Resource.Kind == "Pod" && f.Command != ""
	})
	if i < 0 {
		return
	}
	pod := podsHop.Findings[i]
	for j := range svcHop.Findings {
		f := &svcHop.Findings[j]
		if f.Code != "svc:no-ready-endpoints" || f.Severity != SeverityCritical {
			continue
		}
		f.Command = pod.Command
		f.Resource = cmp.Or(f.Resource, pod.Resource)
		f.Cause = cmp.Or(f.Cause, pod.Cause, pod.Message)
		f.Action = cmp.Or(f.Action, pod.Action)
	}
}

// podDiagnosis turns a pod's reported state into a plain cause and the one
// read-only command most worth running, or ("", "") when nothing in its
// state is clearly blocking. Every cause is the kubelet's own report, never
// a guess. logs --previous is offered only after a crash: a container that
// never started has no previous run.
func podDiagnosis(pod *corev1.Pod) (cause, command string) {
	if pod == nil {
		return "", ""
	}
	inNS := ""
	if pod.Namespace != "" {
		inNS = " -n " + pod.Namespace
	}
	describe := "kubectl describe pod " + pod.Name + inNS
	previousLogs := "kubectl logs " + pod.Name + inNS + " --previous"
	all := slices.Concat(pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses)
	for _, cs := range all {
		w := cs.State.Waiting
		switch {
		case w == nil:
		case w.Reason == "CrashLoopBackOff" && lastOOM(cs):
			return fmt.Sprintf("Container %q ran out of memory (OOMKilled) and is crash-looping", cs.Name), previousLogs
		case w.Reason == "CrashLoopBackOff":
			return fmt.Sprintf("Container %q is crash-looping (CrashLoopBackOff)", cs.Name), previousLogs
		case isImagePullReason(w.Reason):
			return fmt.Sprintf("Container %q cannot pull its image (%s)", cs.Name, w.Reason), describe
		case w.Reason == "CreateContainerConfigError", w.Reason == "CreateContainerError":
			return fmt.Sprintf("Container %q could not be started (%s)", cs.Name, w.Reason), describe
		}
	}
	if i := slices.IndexFunc(all, func(cs corev1.ContainerStatus) bool {
		return cs.State.Terminated != nil && cs.State.Terminated.Reason == "OOMKilled"
	}); i >= 0 {
		return fmt.Sprintf("Container %q ran out of memory (OOMKilled)", all[i].Name), previousLogs
	}
	// Until every init container has finished, the main ones do not start.
	for _, cs := range pod.Status.InitContainerStatuses {
		done := cs.State.Terminated != nil && cs.State.Terminated.ExitCode == 0
		if !done && cs.State.Waiting == nil {
			return fmt.Sprintf("Init container %q has not finished, and the main containers wait for it", cs.Name), describe
		}
	}
	switch {
	case pod.Status.Phase == corev1.PodPending:
		return "Pod is Pending (not yet scheduled, or its containers have not started)", describe
	case pod.Status.Phase == corev1.PodRunning && !podIsReady(pod):
		return "Pod is Running but not Ready (its readiness probe is failing)", describe
	}
	return "", ""
}

func isImagePullReason(r string) bool {
	switch r {
	case "ImagePullBackOff", "ErrImagePull", "InvalidImageName", "ErrImageNeverPull", "RegistryUnavailable":
		return true
	}
	return false
}

func lastOOM(cs corev1.ContainerStatus) bool {
	return cs.LastTerminationState.Terminated != nil && cs.LastTerminationState.Terminated.Reason == "OOMKilled"
}

func podIsReady(pod *corev1.Pod) bool {
	if pod == nil {
		return false
	}
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

func readyCount(pods []*corev1.Pod) int {
	n := 0
	for _, pod := range pods {
		if podIsReady(pod) {
			n++
		}
	}
	return n
}

// livePods drops pods that have finished or are being deleted, so counts are
// of pods that can serve.
func livePods(pods []*corev1.Pod) []*corev1.Pod {
	return slices.DeleteFunc(slices.Clone(pods), func(p *corev1.Pod) bool {
		return p == nil || p.DeletionTimestamp != nil || finished(p)
	})
}

// publishedEndpointCount is how many pods a publishNotReadyAddresses Service
// publishes: every one that has an IP and has not finished. A terminating
// pod stays published until it is gone.
func publishedEndpointCount(pods []*corev1.Pod) int {
	n := 0
	for _, p := range pods {
		if p != nil && p.Status.PodIP != "" && !finished(p) {
			n++
		}
	}
	return n
}

func finished(p *corev1.Pod) bool {
	return p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed
}

// --- Gateway API status and reference checks ---

// gatewayBackendIsService reports whether a backendRef names a core Service
// (omitted group/kind default to it).
func gatewayBackendIsService(ref map[string]any) bool {
	group, _ := ref["group"].(string)
	kind, _ := ref["kind"].(string)
	return group == "" && (kind == "" || kind == "Service")
}

// gatewayParentIsGateway reports whether a parentRef names a Gateway.
func gatewayParentIsGateway(ref map[string]any) bool {
	group, hasGroup := ref["group"].(string)
	kind, _ := ref["kind"].(string)
	return (!hasGroup || group == gatewayGroup) && (kind == "" || kind == "Gateway")
}

// gatewayRefNamespace returns a ref's namespace, defaulting to the route's.
func gatewayRefNamespace(ref map[string]any, routeNamespace string) string {
	if ns, _ := ref["namespace"].(string); ns != "" {
		return ns
	}
	return routeNamespace
}

// condition is one status condition read from an unstructured object.
type condition struct {
	Type, Status, Reason, Message string
}

func conditionsOf(v any) []condition {
	list, _ := v.([]any)
	out := make([]condition, 0, len(list))
	for _, c := range list {
		m, ok := c.(map[string]any)
		if !ok {
			continue
		}
		var cd condition
		cd.Type, _ = m["type"].(string)
		cd.Status, _ = m["status"].(string)
		cd.Reason, _ = m["reason"].(string)
		cd.Message, _ = m["message"].(string)
		out = append(out, cd)
	}
	return out
}

func findCondition(cs []condition, typ string) (condition, bool) {
	for _, c := range cs {
		if c.Type == typ {
			return c, true
		}
	}
	return condition{}, false
}

func conditionDetail(c condition) string {
	switch {
	case c.Reason != "" && c.Message != "":
		return c.Reason + ": " + c.Message
	case c.Message != "":
		return c.Message
	}
	return c.Reason
}

// routeStatusFindings reads a route's status.parents for parents that refused
// it (Accepted=False) or could not resolve its backends (ResolvedRefs=False).
// When onlyParent is set, only that Gateway's status entry counts. A route no
// parent accepts receives no traffic (critical); one refused by some parents
// still serves through the others (warning).
func routeStatusFindings(route *unstructured.Unstructured, kind string, onlyParent *ResourceRef) []Finding {
	parents, _, _ := unstructured.NestedSlice(route.Object, "status", "parents")
	type refused struct{ gw, detail string }
	var rejected []refused
	var unresolved []refused
	considered := 0
	for _, p := range parents {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		ref, _ := pm["parentRef"].(map[string]any)
		if ref == nil || !gatewayParentIsGateway(ref) {
			continue
		}
		name, _ := ref["name"].(string)
		ns := gatewayRefNamespace(ref, route.GetNamespace())
		if onlyParent != nil && (name != onlyParent.Name || ns != onlyParent.Namespace) {
			continue
		}
		considered++
		conds := conditionsOf(pm["conditions"])
		if c, ok := findCondition(conds, "Accepted"); ok && c.Status == "False" {
			rejected = append(rejected, refused{ns + "/" + name, conditionDetail(c)})
		}
		if c, ok := findCondition(conds, "ResolvedRefs"); ok && c.Status == "False" {
			unresolved = append(unresolved, refused{ns + "/" + name, conditionDetail(c)})
		}
	}
	var out []Finding
	cmd := reproducerForRef(ResourceRef{Kind: kind, Namespace: route.GetNamespace(), Name: route.GetName()})
	if len(rejected) > 0 {
		sev := SeverityWarning
		if len(rejected) == considered {
			sev = SeverityCritical
		}
		names := make([]string, 0, len(rejected))
		for _, r := range rejected {
			names = append(names, r.gw)
		}
		msg := fmt.Sprintf("Gateway %s has not accepted this %s, so it receives no traffic from it", strings.Join(names, ", "), kind)
		f := Finding{Code: "gwroute:not-accepted", Severity: sev, Message: msg, Command: cmd}
		if d := rejected[0].detail; d != "" {
			f.Cause = d
		}
		out = append(out, f)
	}
	if len(unresolved) > 0 {
		f := Finding{
			Code:     "gwroute:refs-unresolved",
			Severity: SeverityWarning,
			Message:  fmt.Sprintf("The Gateway controller could not resolve some of this %s's backend references; requests routed to them fail", kind),
			Command:  cmd,
		}
		if d := unresolved[0].detail; d != "" {
			f.Cause = d
		}
		out = append(out, f)
	}
	return out
}

// gatewayStatusFindings reports a Gateway its controller has not accepted or
// programmed: such a Gateway serves no traffic for any route.
func gatewayStatusFindings(gw *unstructured.Unstructured) []Finding {
	conds := conditionsOf(nestedValue(gw.Object, "status", "conditions"))
	for _, typ := range []string{"Accepted", "Programmed"} {
		c, ok := findCondition(conds, typ)
		if !ok || c.Status != "False" {
			continue
		}
		f := Finding{
			Code:     "gateway:not-programmed",
			Severity: SeverityCritical,
			Message:  fmt.Sprintf("The Gateway controller reports this Gateway %s=False, so it is not serving traffic", typ),
			Command:  reproducerForRef(ResourceRef{Kind: "Gateway", Namespace: gw.GetNamespace(), Name: gw.GetName()}),
		}
		if d := conditionDetail(c); d != "" {
			f.Cause = d
		}
		return []Finding{f}
	}
	return nil
}

func nestedValue(obj map[string]any, fields ...string) any {
	v, found, err := unstructured.NestedFieldNoCopy(obj, fields...)
	if err != nil || !found {
		return nil
	}
	return v
}
