package pathtrace

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

// Finding codes the NetworkPolicy layer emits.
const (
	codePolicyWouldDeny = "netpol:would-deny"
	codePolicyAdvisory  = "netpol:advisory"
)

// Evaluator verdicts the trace understands; anything else is "depends on
// the caller".
const (
	evalAllowed = "allowed"
	evalDenied  = "denied"
)

// policyVerdict is the caller-independent conclusion for one backend. It is
// a prediction: the CNI is the only authority on enforcement, so a would-deny
// is a warning, never a broken verdict.
type policyVerdict int

const (
	policyNotRestricted policyVerdict = iota
	policyAdvisory
	policyWouldDeny
)

// advisoryReason says why a verdict is advisory rather than decided, so the
// finding names the right cause.
type advisoryReason int

const (
	advisoryCallerDependent advisoryReason = iota
	advisoryHostNetwork
	advisoryUnresolvedPort
	advisoryMixed
)

type policyResult struct {
	verdict  policyVerdict
	advisory advisoryReason
	port     string // ":80" - the Service port the verdict is about
	names    []string
}

// policyFinding evaluates the NetworkPolicies in the Service's namespace for
// its ready endpoint pods (every published pod for a
// publishNotReadyAddresses Service) on the Service ports the path uses, and
// turns a would-deny or advisory result into a finding. Silent when there is
// no evaluator, no policy, no eligible pod, or traffic is admitted.
// backendPorts narrows the check to the ports an upstream route references;
// empty means every Service port.
func policyFinding(p Provider, eval PolicyEvaluator, svc *corev1.Service, pods []*corev1.Pod, backendPorts ...string) (Finding, map[string]any, bool) {
	if eval == nil || svc == nil || len(pods) == 0 {
		return Finding{}, nil, false
	}
	policies, err := p.NetworkPolicies(svc.Namespace)
	if err != nil || len(policies) == 0 {
		return Finding{}, nil, false
	}
	eligible := make([]*corev1.Pod, 0, len(pods))
	for _, pod := range pods {
		if pod != nil && (svc.Spec.PublishNotReadyAddresses || podIsReady(pod)) {
			eligible = append(eligible, pod)
		}
	}
	if len(eligible) == 0 {
		return Finding{}, nil, false
	}
	res := evaluatePolicies(eval, eligible, filterPortMapsByRef(servicePortMaps(svc), backendPorts), policies)
	if res.verdict == policyNotRestricted {
		return Finding{}, nil, false
	}

	cmd := fmt.Sprintf("kubectl get networkpolicy -n %s", svc.Namespace)
	if len(res.names) == 1 {
		cmd = fmt.Sprintf("kubectl describe networkpolicy %s -n %s", res.names[0], svc.Namespace)
	}
	meta := map[string]any{"policyPort": res.port}
	if len(res.names) > 0 {
		meta["policyNames"] = res.names
	}
	names := strings.Join(res.names, ", ")
	if names == "" {
		names = "a policy in this namespace"
	}

	if res.verdict == policyWouldDeny {
		meta["policyVerdict"] = "would-deny"
		return Finding{
			Code:     codePolicyWouldDeny,
			Severity: SeverityWarning,
			Message:  fmt.Sprintf("NetworkPolicy would block traffic to these pods on %s - no rule allows it from any source.", res.port),
			Cause:    fmt.Sprintf("NetworkPolicy (%s) selects these pods and no ingress rule admits %s. This is a static prediction: whether it is enforced depends on the cluster's network plugin.", names, res.port),
			Action:   "Add an ingress rule that allows this port, or confirm the policy is intended",
			Command:  cmd,
		}, meta, true
	}

	meta["policyVerdict"] = "advisory"
	msg := "NetworkPolicy limits who can reach these pods on " + res.port + "; whether a given caller is admitted depends on its labels and namespace."
	cause := fmt.Sprintf("NetworkPolicy (%s) admits this port only from specific sources.", names)
	action := "If your client should be allowed, check that its labels and namespace match the policy's allowed sources"
	switch res.advisory {
	case advisoryHostNetwork:
		msg = "NetworkPolicy selects these pods, but they run on the host network, where policy enforcement is CNI-specific - the outcome can't be predicted."
		cause = fmt.Sprintf("NetworkPolicy (%s) selects host-network pods; whether it governs host-network traffic depends on the network plugin.", names)
		action = "Confirm whether your network plugin enforces NetworkPolicy for host-network pods"
	case advisoryUnresolvedPort:
		msg = "NetworkPolicy selects these pods, but the Service's named targetPort doesn't resolve to a declared container port, so the outcome can't be predicted."
		cause = fmt.Sprintf("NetworkPolicy (%s) is evaluated per pod port, and the named targetPort doesn't resolve on the endpoint pods.", names)
		action = "Check that the Service's named targetPort matches a declared container port"
	case advisoryMixed:
		msg = "NetworkPolicy would block some of these pods but not others on " + res.port + "; the outcome depends on which pod serves the request."
		cause = fmt.Sprintf("NetworkPolicy (%s) denies this port on some endpoint pods while others are open.", names)
		action = "Make the policy consistent across the pods behind this Service"
	}
	return Finding{
		Code:     codePolicyAdvisory,
		Severity: SeverityInfo,
		Message:  msg,
		Cause:    cause,
		Action:   action,
		Command:  cmd,
	}, meta, true
}

// evaluatePolicies returns the worst result across the route's ports
// (would-deny > advisory > not restricted).
func evaluatePolicies(eval PolicyEvaluator, pods []*corev1.Pod, ports []PortMap, policies []*networkingv1.NetworkPolicy) policyResult {
	worst := policyResult{verdict: policyNotRestricted}
	nameSet := map[string]bool{}
	for _, pm := range ports {
		r := evaluatePort(eval, pods, pm, policies, nameSet)
		if r.verdict > worst.verdict {
			worst = r
		}
	}
	worst.names = make([]string, 0, len(nameSet))
	for n := range nameSet {
		worst.names = append(worst.names, n)
	}
	sort.Strings(worst.names)
	return worst
}

// evaluatePort resolves the Service port to each pod's container port, asks
// the evaluator once per distinct pod port, and aggregates: a route would
// deny only when every eligible pod is denied; host-network pods, named
// ports that don't resolve, and caller-dependent answers make it advisory.
func evaluatePort(eval PolicyEvaluator, pods []*corev1.Pod, pm PortMap, policies []*networkingv1.NetworkPolicy, names map[string]bool) policyResult {
	label := fmt.Sprintf(":%d", pm.Port)
	proto := corev1.Protocol(pm.Protocol)
	if proto == "" {
		proto = corev1.ProtocolTCP
	}
	byPort := map[int32][]*corev1.Pod{}
	var order []int32
	hostNetwork, unresolved := false, false
	for _, pod := range pods {
		if pod.Spec.HostNetwork {
			hostNetwork = true
			continue
		}
		port, ok := resolveTargetPort(pm, pod, proto)
		if !ok {
			unresolved = true
			continue
		}
		if _, seen := byPort[port]; !seen {
			order = append(order, port)
		}
		byPort[port] = append(byPort[port], pod)
	}
	allowed, denied, dependent := false, false, false
	for _, port := range order {
		verdict, decided := eval(false, byPort[port], port, proto, policies)
		for _, n := range decided {
			names[n] = true
		}
		switch verdict {
		case evalAllowed:
			allowed = true
		case evalDenied:
			denied = true
		default:
			dependent = true
		}
	}
	switch {
	case hostNetwork:
		return policyResult{verdict: policyAdvisory, advisory: advisoryHostNetwork, port: label}
	case unresolved:
		return policyResult{verdict: policyAdvisory, advisory: advisoryUnresolvedPort, port: label}
	case dependent:
		return policyResult{verdict: policyAdvisory, advisory: advisoryCallerDependent, port: label}
	case denied && allowed:
		return policyResult{verdict: policyAdvisory, advisory: advisoryMixed, port: label}
	case denied:
		return policyResult{verdict: policyWouldDeny, port: label}
	}
	return policyResult{verdict: policyNotRestricted, port: label}
}

// resolveTargetPort applies the targetPort rule: numeric as-is, empty is the
// Service port, named is looked up among the pod's container ports.
func resolveTargetPort(pm PortMap, pod *corev1.Pod, proto corev1.Protocol) (int32, bool) {
	tp := strings.TrimSpace(pm.TargetPort)
	if tp == "" {
		return pm.Port, true
	}
	if n, err := strconv.ParseInt(tp, 10, 32); err == nil {
		return int32(n), true
	}
	for _, c := range pod.Spec.Containers {
		for _, cp := range c.Ports {
			cpProto := cp.Protocol
			if cpProto == "" {
				cpProto = corev1.ProtocolTCP
			}
			if cp.Name == tp && cpProto == proto {
				return cp.ContainerPort, true
			}
		}
	}
	return 0, false
}

// filterPortMapsByRef keeps the Service ports an upstream backendRef names,
// by number or by name, so a denial on a port the path does not use never
// condemns it. Without refs every port stays; refs naming no port leave none.
func filterPortMapsByRef(all []PortMap, refs []string) []PortMap {
	var named []string
	for _, r := range refs {
		if r = strings.TrimSpace(r); r != "" {
			named = append(named, r)
		}
	}
	if len(named) == 0 {
		return all
	}
	return slices.DeleteFunc(slices.Clone(all), func(pm PortMap) bool {
		return !slices.Contains(named, pm.Name) && !slices.Contains(named, strconv.Itoa(int(pm.Port)))
	})
}
