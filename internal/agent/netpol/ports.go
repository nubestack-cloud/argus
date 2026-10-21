// Package netpol reads core networking.k8s.io/v1 NetworkPolicy objects
// without a cluster: the caller passes the pods, namespaces and policies it
// has already listed.
//
// A policy states intent. Whether packets flow is up to the CNI, which may
// not enforce NetworkPolicy at all (kindnet) or may add rules of its own
// (Cilium and Calico CRDs). An answer from here is what the policies say,
// and must never be presented as what happens on the wire.
package netpol

import (
	"cmp"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// PolicyTypes is which directions a policy isolates for the pods it selects.
type PolicyTypes struct {
	Ingress bool
	Egress  bool
}

// EffectivePolicyTypes applies Kubernetes' defaulting of spec.policyTypes.
// When it is set, it is the answer. When it is not, a policy always isolates
// ingress, and isolates egress only if it has egress rules — so an
// egress-only policy written without policyTypes is not an inbound
// restriction, and reading it as one would invent a block.
func EffectivePolicyTypes(np *networkingv1.NetworkPolicy) PolicyTypes {
	types := np.Spec.PolicyTypes
	if len(types) == 0 {
		return PolicyTypes{Ingress: true, Egress: len(np.Spec.Egress) > 0}
	}
	return PolicyTypes{
		Ingress: slices.Contains(types, networkingv1.PolicyTypeIngress),
		Egress:  slices.Contains(types, networkingv1.PolicyTypeEgress),
	}
}

// RuleMatchesPort reports whether a rule's ports cover a port and protocol on
// pod. No ports means every port. A named port is looked up among pod's
// declared container ports, and a name pod does not declare simply does not
// match — Kubernetes ignores the entry for that pod. That is a definite no,
// not an open question: calling it uncertain would let a policy whose only
// allow rule names an undeclared port look harmless while it blocks the
// traffic.
func RuleMatchesPort(rulePorts []networkingv1.NetworkPolicyPort, podPort int32, proto corev1.Protocol, pod *corev1.Pod) bool {
	if len(rulePorts) == 0 {
		return true
	}
	proto = ProtocolOrTCP(string(proto))
	return slices.ContainsFunc(rulePorts, func(e networkingv1.NetworkPolicyPort) bool {
		return entryCovers(e, podPort, proto, pod)
	})
}

// entryCovers is RuleMatchesPort for one entry; proto is already normalised.
func entryCovers(e networkingv1.NetworkPolicyPort, port int32, proto corev1.Protocol, pod *corev1.Pod) bool {
	switch {
	case entryProtocol(e) != proto:
		return false
	case e.Port == nil:
		// A protocol with no port: every port of it.
		return true
	case e.Port.Type == intstr.Int:
		last := e.Port.IntVal
		if e.EndPort != nil && *e.EndPort > last {
			last = *e.EndPort
		}
		return e.Port.IntVal <= port && port <= last
	}
	n, ok := ContainerPortByName(pod, e.Port.StrVal, proto)
	return ok && n == port
}

func entryProtocol(e networkingv1.NetworkPolicyPort) corev1.Protocol {
	if e.Protocol == nil {
		return corev1.ProtocolTCP
	}
	return ProtocolOrTCP(string(*e.Protocol))
}

// ContainerPortByName finds the number of the container port pod declares
// under name for proto.
func ContainerPortByName(pod *corev1.Pod, name string, proto corev1.Protocol) (int32, bool) {
	if pod == nil {
		return 0, false
	}
	for _, c := range pod.Spec.Containers {
		i := slices.IndexFunc(c.Ports, func(p corev1.ContainerPort) bool {
			return p.Name == name && ProtocolOrTCP(string(p.Protocol)) == proto
		})
		if i >= 0 {
			return c.Ports[i].ContainerPort, true
		}
	}
	return 0, false
}

// ProtocolOrTCP upper-cases a protocol and supplies TCP where it is left
// out, as Kubernetes does everywhere a protocol is optional.
func ProtocolOrTCP(p string) corev1.Protocol {
	return corev1.Protocol(strings.ToUpper(cmp.Or(p, string(corev1.ProtocolTCP))))
}
