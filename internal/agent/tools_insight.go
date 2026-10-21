package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"

	"argus/internal/agent/hpaexplain"
	"argus/internal/agent/netpol"
	"argus/internal/agent/objcache"
	"argus/internal/agent/pathprobe"
	"argus/internal/agent/pathtrace"
	"argus/internal/agent/rbacgrants"
	"argus/internal/agent/rolloutcheck"
	"argus/internal/agent/topology"
)

// The cluster-insight tools (docs/CLUSTER_INSIGHT_SPECS.md, CI-F2's recipe)
// answer from the object cache rather than the API server. Every response
// carries observedAt and coverage so whoever reads it — the model or a
// person — can tell a complete answer from one computed over kinds this
// agent cannot see.

// insightMeta is embedded in every cluster-insight tool response.
type insightMeta struct {
	// ObservedAt is when the answer was computed from the live cache.
	ObservedAt time.Time `json:"observedAt"`
	// Coverage lists the kinds this answer needed that were not synced,
	// with why. Empty means the inputs were complete.
	Coverage  []objcache.KindStatus `json:"coverage,omitempty"`
	Truncated bool                  `json:"truncated,omitempty"`
}

// insightStamp is insightMeta without its own truncated flag, for responses
// whose embedded result already carries one.
type insightStamp struct {
	ObservedAt time.Time             `json:"observedAt"`
	Coverage   []objcache.KindStatus `json:"coverage,omitempty"`
}

func stampOf(m insightMeta) insightStamp {
	return insightStamp{ObservedAt: m.ObservedAt, Coverage: m.Coverage}
}

// maxInsightOutputBytes keeps every response under half the tunnel's 1 MiB
// frame (internal/gateway/server.go maxTunnelMessageBytes).
const maxInsightOutputBytes = 512 << 10

var errNoObjectCache = errors.New("the object cache is not running on this agent (disabled, still starting, or a remediation-role agent); cluster-insight tools are unavailable")

func (e *ToolExecutor) cache() (*objcache.Cache, error) {
	if e == nil || e.objects == nil {
		return nil, errNoObjectCache
	}
	return e.objects, nil
}

func (e *ToolExecutor) meta(kinds ...[2]string) insightMeta {
	m := insightMeta{ObservedAt: time.Now().UTC()}
	if e.objects != nil {
		m.Coverage = e.objects.Coverage(kinds...)
	}
	return m
}

// marshalInsight serialises a response and enforces the output budget.
func marshalInsight(v any) (json.RawMessage, bool, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, false, err
	}
	if len(b) > maxInsightOutputBytes {
		return nil, false, fmt.Errorf("result is %d bytes, over the %d-byte budget; narrow the request", len(b), maxInsightOutputBytes)
	}
	return b, false, nil
}

func decodeInsightArgs(raw json.RawMessage, into any) error {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("invalid arguments: %w", err)
	}
	return nil
}

func requireName(ns, name string, namespaced bool) error {
	if name == "" {
		return errors.New("name is required")
	}
	if namespaced && ns == "" {
		return errors.New("namespace is required")
	}
	return nil
}

var (
	kindPod           = [2]string{"", "Pod"}
	kindService       = [2]string{"", "Service"}
	kindNamespace     = [2]string{"", "Namespace"}
	kindNetworkPolicy = [2]string{"networking.k8s.io", "NetworkPolicy"}
	kindDeployment    = [2]string{"apps", "Deployment"}
	kindReplicaSet    = [2]string{"apps", "ReplicaSet"}
	kindHPA           = [2]string{"autoscaling", "HorizontalPodAutoscaler"}
)

// ---------------------------------------------------------------- evaluate_network_policy

type netpolArgs struct {
	Source struct {
		Namespace string `json:"namespace"`
		Pod       string `json:"pod"`
		External  bool   `json:"external"`
	} `json:"source"`
	Destination struct {
		Kind      string `json:"kind"` // Service | Pod
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	} `json:"destination"`
	Port     int32  `json:"port"`
	Protocol string `json:"protocol"`
}

type netpolResult struct {
	insightMeta
	Verdict      netpol.Verdict      `json:"verdict"`
	Backends     int                 `json:"backends"`
	Explanations []netpolExplanation `json:"explanations,omitempty"`
	Note         string              `json:"note"`
}

type netpolExplanation struct {
	Policy      string             `json:"policy"`
	Direction   netpol.Direction   `json:"direction"`
	Explanation netpol.Explanation `json:"explanation"`
}

func (e *ToolExecutor) evaluateNetworkPolicy(_ context.Context, raw json.RawMessage) (json.RawMessage, bool, error) {
	c, err := e.cache()
	if err != nil {
		return nil, false, err
	}
	var a netpolArgs
	if err := decodeInsightArgs(raw, &a); err != nil {
		return nil, false, err
	}
	if err := requireName(a.Destination.Namespace, a.Destination.Name, true); err != nil {
		return nil, false, fmt.Errorf("destination: %w", err)
	}
	proto := netpol.ProtocolOrTCP(a.Protocol)
	nsObj := func(name string) *corev1.Namespace {
		nss, _ := c.Namespaces()
		for _, n := range nss {
			if n.Name == name {
				return n
			}
		}
		return nil
	}

	var src netpol.Peer
	switch {
	case a.Source.External:
		src = netpol.Peer{External: true}
	case a.Source.Pod != "":
		p, ok, err := c.Pod(a.Source.Namespace, a.Source.Pod)
		if err != nil {
			return nil, false, err
		}
		if !ok {
			return nil, false, fmt.Errorf("source pod %s/%s not found", a.Source.Namespace, a.Source.Pod)
		}
		src = netpol.Peer{Pod: p, Namespace: nsObj(p.Namespace)}
	default:
		src = netpol.Peer{External: true}
	}

	var backends []netpol.Backend
	dstNS := a.Destination.Namespace
	switch strings.ToLower(a.Destination.Kind) {
	case "pod":
		p, ok, err := c.Pod(dstNS, a.Destination.Name)
		if err != nil {
			return nil, false, err
		}
		if !ok {
			return nil, false, fmt.Errorf("destination pod %s/%s not found", dstNS, a.Destination.Name)
		}
		if a.Port == 0 {
			return nil, false, errors.New("port is required for a Pod destination")
		}
		backends = append(backends, netpol.Backend{Peer: netpol.Peer{Pod: p, Namespace: nsObj(dstNS)}, Port: a.Port, Protocol: proto})
	default: // Service
		svcs, err := c.Services(dstNS)
		if err != nil {
			return nil, false, err
		}
		var svc *corev1.Service
		for _, s := range svcs {
			if s.Name == a.Destination.Name {
				svc = s
			}
		}
		if svc == nil {
			return nil, false, fmt.Errorf("service %s/%s not found", dstNS, a.Destination.Name)
		}
		var sp *corev1.ServicePort
		for i := range svc.Spec.Ports {
			p := &svc.Spec.Ports[i]
			if a.Port == 0 || p.Port == a.Port {
				sp = p
				break
			}
		}
		if sp == nil {
			return nil, false, fmt.Errorf("service %s/%s has no port %d", dstNS, a.Destination.Name, a.Port)
		}
		proto = sp.Protocol
		if proto == "" {
			proto = corev1.ProtocolTCP
		}
		if len(svc.Spec.Selector) > 0 {
			pods, err := c.Pods(dstNS)
			if err != nil {
				return nil, false, err
			}
			sel := labels.SelectorFromSet(svc.Spec.Selector)
			for _, p := range pods {
				if !sel.Matches(labels.Set(p.Labels)) {
					continue
				}
				port := targetPortFor(sp, p, proto)
				if port == 0 {
					continue
				}
				backends = append(backends, netpol.Backend{Peer: netpol.Peer{Pod: p, Namespace: nsObj(dstNS)}, Port: port, Protocol: proto})
			}
		}
	}

	policies, err := c.NetworkPolicies(dstNS)
	if err != nil {
		return nil, false, err
	}
	if src.Pod != nil && src.Pod.Namespace != dstNS {
		srcPolicies, err := c.NetworkPolicies(src.Pod.Namespace)
		if err != nil {
			return nil, false, err
		}
		policies = append(append([]*networkingv1.NetworkPolicy{}, policies...), srcPolicies...)
	}

	verdict := netpol.Evaluate(src, backends, policies)
	if src.Pod == nil {
		verdict = evaluateFromOutside(src, backends, policies)
	}
	out := netpolResult{
		insightMeta: e.meta(kindPod, kindService, kindNamespace, kindNetworkPolicy),
		Verdict:     verdict,
		Backends:    len(backends),
		Note:        "Static prediction from core NetworkPolicy objects only; the network plugin is the enforcement authority, and plugin-specific policy kinds are not evaluated.",
	}
	if len(backends) > 0 {
		b := backends[0]
		for _, np := range policies {
			if np.Namespace == dstNS {
				ex := netpol.Explain(np, netpol.DirectionIngress, b.Pod, src, b.Port, b.Protocol)
				out.Explanations = append(out.Explanations, netpolExplanation{Policy: np.Namespace + "/" + np.Name, Direction: netpol.DirectionIngress, Explanation: ex})
			}
			if src.Pod != nil && np.Namespace == src.Pod.Namespace {
				ex := netpol.Explain(np, netpol.DirectionEgress, src.Pod, b.Peer, b.Port, b.Protocol)
				out.Explanations = append(out.Explanations, netpolExplanation{Policy: np.Namespace + "/" + np.Name, Direction: netpol.DirectionEgress, Explanation: ex})
			}
			if len(out.Explanations) >= 50 {
				out.Truncated = true
				break
			}
		}
	}
	return marshalInsight(out)
}

// evaluateFromOutside decides traffic from outside any pod (the source has no
// egress policies to consult), using only the destination's ingress side:
// Denied when every backend is selected by at least one ingress policy and
// none of them admits the source; Allowed when any policy admits it for every
// backend; otherwise Unknown — including any backend no policy selects,
// which is open by default but is reported as allowed only when that is all
// there is.
func evaluateFromOutside(src netpol.Peer, backends []netpol.Backend, policies []*networkingv1.NetworkPolicy) netpol.Verdict {
	if len(backends) == 0 {
		return netpol.Verdict{Kind: netpol.Unknown}
	}
	denied, allowed := 0, 0
	var deciding []string
	for _, b := range backends {
		selected, admits, undecidable := false, false, false
		for _, np := range policies {
			if np.Namespace != b.Pod.Namespace || !netpol.EffectivePolicyTypes(np).Ingress {
				continue
			}
			sel, err := netpol.Selects(np, b.Pod)
			if err != nil {
				undecidable = true
				continue
			}
			if !sel {
				continue
			}
			selected = true
			switch netpol.Explain(np, netpol.DirectionIngress, b.Pod, src, b.Port, b.Protocol).Effect {
			case netpol.Admits:
				admits = true
			case netpol.Undecidable:
				undecidable = true
			}
			deciding = append(deciding, np.Namespace+"/"+np.Name)
		}
		switch {
		case undecidable:
			return netpol.Verdict{Kind: netpol.Unknown}
		case !selected || admits:
			allowed++
		default:
			denied++
		}
	}
	if denied == len(backends) {
		return netpol.Verdict{Kind: netpol.Denied, Direction: netpol.DirectionIngress, Policies: dedupe(deciding)}
	}
	if allowed == len(backends) {
		return netpol.Verdict{Kind: netpol.Allowed}
	}
	return netpol.Verdict{Kind: netpol.Unknown}
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func targetPortFor(sp *corev1.ServicePort, p *corev1.Pod, proto corev1.Protocol) int32 {
	tp := sp.TargetPort
	switch {
	case tp.Type == intstr.Int && tp.IntVal != 0:
		return tp.IntVal
	case tp.Type == intstr.String && tp.StrVal != "":
		if port, ok := netpol.ContainerPortByName(p, tp.StrVal, proto); ok {
			return port
		}
		return 0
	default:
		return sp.Port
	}
}

// ---------------------------------------------------------------- get_subject_permissions

type subjectArgs struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type subjectResult struct {
	insightStamp
	rbacgrants.Report
}

func (e *ToolExecutor) getSubjectPermissions(_ context.Context, raw json.RawMessage) (json.RawMessage, bool, error) {
	c, err := e.cache()
	if err != nil {
		return nil, false, err
	}
	var a subjectArgs
	if err := decodeInsightArgs(raw, &a); err != nil {
		return nil, false, err
	}
	switch a.Kind {
	case "ServiceAccount":
		if err := requireName(a.Namespace, a.Name, true); err != nil {
			return nil, false, err
		}
	case "User", "Group":
		if a.Name == "" {
			return nil, false, errors.New("name is required")
		}
		a.Namespace = ""
	default:
		return nil, false, errors.New(`kind must be "ServiceAccount", "User" or "Group"`)
	}
	roles, err1 := c.Roles("")
	croles, err2 := c.ClusterRoles()
	rbs, err3 := c.RoleBindings("")
	crbs, err4 := c.ClusterRoleBindings()
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		return nil, false, err
	}
	rep := rbacgrants.Describe(rbacgrants.Cluster{Roles: roles, ClusterRoles: croles, RoleBindings: rbs, ClusterRoleBindings: crbs},
		rbacgrants.Identity{Kind: a.Kind, Namespace: a.Namespace, Name: a.Name})
	m := e.meta([2]string{"rbac.authorization.k8s.io", "Role"}, [2]string{"rbac.authorization.k8s.io", "ClusterRole"},
		[2]string{"rbac.authorization.k8s.io", "RoleBinding"}, [2]string{"rbac.authorization.k8s.io", "ClusterRoleBinding"})
	return marshalInsight(subjectResult{insightStamp: stampOf(m), Report: rep})
}

// ---------------------------------------------------------------- diagnose_autoscaler / diagnose_rollout

type nsNameArgs struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type autoscalerResult struct {
	insightMeta
	Diagnosis *hpaexplain.Explanation `json:"diagnosis"`
}

func (e *ToolExecutor) diagnoseAutoscaler(_ context.Context, raw json.RawMessage) (json.RawMessage, bool, error) {
	c, err := e.cache()
	if err != nil {
		return nil, false, err
	}
	var a nsNameArgs
	if err := decodeInsightArgs(raw, &a); err != nil {
		return nil, false, err
	}
	if err := requireName(a.Namespace, a.Name, true); err != nil {
		return nil, false, err
	}
	hpas, err := c.HorizontalPodAutoscalers(a.Namespace)
	if err != nil {
		return nil, false, err
	}
	for _, h := range hpas {
		if h.Name == a.Name {
			return marshalInsight(autoscalerResult{insightMeta: e.meta(kindHPA), Diagnosis: hpaexplain.Explain(h)})
		}
	}
	return nil, false, fmt.Errorf("HorizontalPodAutoscaler %s/%s not found", a.Namespace, a.Name)
}

type rolloutResult struct {
	insightMeta
	rolloutcheck.Report
}

func (e *ToolExecutor) diagnoseRollout(_ context.Context, raw json.RawMessage) (json.RawMessage, bool, error) {
	c, err := e.cache()
	if err != nil {
		return nil, false, err
	}
	var a nsNameArgs
	if err := decodeInsightArgs(raw, &a); err != nil {
		return nil, false, err
	}
	if err := requireName(a.Namespace, a.Name, true); err != nil {
		return nil, false, err
	}
	deps, err := c.Deployments(a.Namespace)
	if err != nil {
		return nil, false, err
	}
	for _, d := range deps {
		if d.Name == a.Name {
			// ReplicaSets and pods only refine the answer (which ReplicaSet
			// is new, what its pods wait on); the verdict comes from the
			// Deployment's own status, so a kind that is not synced shows
			// in coverage rather than failing the call.
			rss, _ := c.ReplicaSets(a.Namespace)
			pods, _ := c.Pods(a.Namespace)
			return marshalInsight(rolloutResult{insightMeta: e.meta(kindDeployment, kindReplicaSet, kindPod), Report: rolloutcheck.Check(d, rss, pods)})
		}
	}
	return nil, false, fmt.Errorf("Deployment %s/%s not found", a.Namespace, a.Name)
}

// ---------------------------------------------------------------- trace_service_path

// pathTraceProvider adapts the cache to pathtrace.Provider; a kind the cache
// does not register (TCPRoute, TLSRoute) reports absent rather than "".
type pathTraceProvider struct{ *objcache.Cache }

func (p pathTraceProvider) State(group, kind string) string {
	if s := p.Cache.State(group, kind); s != "" {
		return s
	}
	return objcache.StateAbsent
}

// ingressPolicyEvaluator answers the trace's question "would NetworkPolicy
// admit an unspecified in-cluster caller to these pods on this port":
// allowed when no ingress policy selects the pods or one admits every
// source on the port; denied when policies select every pod and none has a
// rule matching the port at all; "depends" otherwise (the answer turns on
// who the caller is).
func ingressPolicyEvaluator(_ bool, dstPods []*corev1.Pod, port int32, proto corev1.Protocol, policies []*networkingv1.NetworkPolicy) (string, []string) {
	var deciding []string
	allowed, denied := 0, 0
	for _, pod := range dstPods {
		selected, openToAll, anyPortRule := false, false, false
		for _, np := range policies {
			if np.Namespace != pod.Namespace || !netpol.EffectivePolicyTypes(np).Ingress {
				continue
			}
			if ok, err := netpol.Selects(np, pod); err != nil || !ok {
				continue
			}
			selected = true
			deciding = append(deciding, np.Namespace+"/"+np.Name)
			for _, rule := range np.Spec.Ingress {
				if !netpol.RuleMatchesPort(rule.Ports, port, proto, pod) {
					continue
				}
				anyPortRule = true
				if len(rule.From) == 0 {
					openToAll = true
				}
			}
		}
		switch {
		case !selected || openToAll:
			allowed++
		case !anyPortRule:
			denied++
		}
	}
	switch {
	case len(dstPods) > 0 && allowed == len(dstPods):
		return "allowed", nil
	case len(dstPods) > 0 && denied == len(dstPods):
		return "denied", dedupe(deciding)
	default:
		return "depends", dedupe(deciding)
	}
}

type traceResult struct {
	insightStamp
	*pathtrace.Trace
	// Probe is the optional one-shot live check (PROJECT.md PG16), present
	// only when asked for and only for a Service.
	Probe *pathprobe.Result `json:"probe,omitempty"`
}

func (e *ToolExecutor) traceServicePath(ctx context.Context, raw json.RawMessage) (json.RawMessage, bool, error) {
	c, err := e.cache()
	if err != nil {
		return nil, false, err
	}
	var a struct {
		Kind      string `json:"kind"`
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
		Probe     bool   `json:"probe"`
	}
	if err := decodeInsightArgs(raw, &a); err != nil {
		return nil, false, err
	}
	if !pathtrace.IsEntryKind(a.Kind) {
		return nil, false, errors.New("kind must be Service, Ingress, HTTPRoute, GRPCRoute or Gateway")
	}
	if a.Name == "" {
		return nil, false, errors.New("name is required")
	}
	tr := pathtrace.Build(ctx, pathTraceProvider{c}, a.Kind, a.Namespace, a.Name, pathtrace.Options{PolicyEvaluator: ingressPolicyEvaluator})
	m := e.meta(kindService, kindPod, [2]string{"discovery.k8s.io", "EndpointSlice"}, [2]string{"networking.k8s.io", "Ingress"}, kindNetworkPolicy)
	out := traceResult{insightStamp: stampOf(m), Trace: tr}
	if a.Probe && a.Kind == "Service" {
		if svcs, err := c.Services(a.Namespace); err == nil {
			for _, svc := range svcs {
				if svc.Name != a.Name {
					continue
				}
				var mine []*discoveryv1.EndpointSlice
				if all, err := c.EndpointSlices(a.Namespace); err == nil {
					for _, sl := range all {
						if sl.Labels[discoveryv1.LabelServiceName] == a.Name {
							mine = append(mine, sl)
						}
					}
				}
				p := pathprobe.Default().Probe(ctx, svc, mine)
				out.Probe = &p
			}
		}
	}
	return marshalInsight(out)
}

// ---------------------------------------------------------------- get_neighborhood

// topologyProvider adapts the cache to topology.ResourceProvider and
// DynamicProvider.
type topologyProvider struct{ *objcache.Cache }

func (p topologyProvider) PersistentVolumes(string) ([]*corev1.PersistentVolume, error) {
	return p.Cache.PersistentVolumes()
}

func (p topologyProvider) Nodes(string) ([]*corev1.Node, error) { return p.Cache.Nodes() }

func (p topologyProvider) List(gk schema.GroupKind, ns string) ([]*unstructured.Unstructured, error) {
	switch p.Cache.State(gk.Group, gk.Kind) {
	case "", objcache.StateAbsent:
		return nil, topology.ErrNotServed
	}
	return p.Cache.Dynamic(gk.Group, gk.Kind, ns)
}

type neighborhoodResult struct {
	insightStamp
	*topology.Subgraph
}

func (e *ToolExecutor) getNeighborhood(_ context.Context, raw json.RawMessage) (json.RawMessage, bool, error) {
	c, err := e.cache()
	if err != nil {
		return nil, false, err
	}
	var a struct {
		Kind      string `json:"kind"`
		APIGroup  string `json:"apiGroup"`
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
		Hops      int    `json:"hops"`
		MaxNodes  int    `json:"maxNodes"`
		Profile   string `json:"profile"`
	}
	if err := decodeInsightArgs(raw, &a); err != nil {
		return nil, false, err
	}
	if a.Kind == "" || a.Name == "" {
		return nil, false, errors.New("kind and name are required")
	}
	kind, group, mapped := topology.IsMapped(a.Kind, a.APIGroup)
	if !mapped {
		return e.unmappedNeighborhood(c, a.Kind, a.APIGroup, a.Namespace, a.Name)
	}
	ns := a.Namespace
	if topology.IsClusterScoped(kind) {
		ns = ""
	}
	// A root the cache can read and does not hold is missing, which is the
	// one case that is an error. A root whose kind is not synced falls
	// through: the graph reports the kind as unavailable instead.
	if _, ok, err := c.Get(group, string(kind), ns, a.Name); err == nil && !ok {
		return nil, false, notFoundError(string(kind), ns, a.Name)
	}
	p := topologyProvider{c}
	sg, err := topology.Neighborhood(p, topology.Ref{Kind: a.Kind, APIGroup: a.APIGroup, Namespace: a.Namespace, Name: a.Name},
		topology.Options{Profile: topology.ResolveProfile(a.Profile), Hops: a.Hops, MaxNodes: a.MaxNodes, Dynamic: p})
	if err != nil {
		return nil, false, err
	}
	return marshalInsight(neighborhoodResult{insightStamp: stampOf(e.meta()), Subgraph: sg})
}

// notFoundError is the plain "<Kind> <ns>/<name> not found" every insight
// tool uses for a missing object.
func notFoundError(kind, ns, name string) error {
	if ns == "" {
		return fmt.Errorf("%s %s not found", kind, name)
	}
	return fmt.Errorf("%s %s/%s not found", kind, ns, name)
}

// maxUnmappedOwnedScan bounds how many managed-resource entries an
// application's status is resolved for.
const maxUnmappedOwnedScan = 200

// unmappedNeighborhood answers get_neighborhood for a kind the relationship
// graph does not map (a CRD such as an Argo CD Application or a cert-manager
// Certificate): a normal result with the object as root and generic
// ownership links, marked unmapped with a note — never an error unless the
// object is missing from a kind the cache can read.
func (e *ToolExecutor) unmappedNeighborhood(c *objcache.Cache, kindArg, groupArg, ns, name string) (json.RawMessage, bool, error) {
	kind, group, registered := resolveCachedKind(c, kindArg, groupArg)
	if !registered || c.State(group, kind) != objcache.StateSynced {
		// The cache does not hold this kind (or cannot read it right now):
		// nothing to draw, which the coverage on the response explains.
		sg := &topology.Subgraph{
			Root:  topology.Ref{Kind: kind, APIGroup: group, Namespace: ns, Name: name},
			Nodes: []topology.Node{}, Edges: []topology.Edge{},
			Unmapped: true, Note: topology.UnmappedNote(kind),
		}
		return marshalInsight(neighborhoodResult{insightStamp: stampOf(e.meta([2]string{group, kind})), Subgraph: sg})
	}
	obj, ok, err := c.Get(group, kind, ns, name)
	if err == nil && !ok && ns != "" {
		// A cluster-scoped kind asked for with a namespace.
		if o, ok2, err2 := c.Get(group, kind, "", name); err2 == nil && ok2 {
			obj, ok = o, true
		}
	}
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, notFoundError(kind, ns, name)
	}
	rootMeta, err := meta.Accessor(obj)
	if err != nil {
		return nil, false, fmt.Errorf("%s %s/%s has no object metadata", kind, ns, name)
	}
	root := topology.ObjectNode{Kind: kind, APIGroup: group, Obj: rootMeta}

	var owners []topology.ObjectNode
	for _, ref := range rootMeta.GetOwnerReferences() {
		gv, err := schema.ParseGroupVersion(ref.APIVersion)
		if err != nil {
			continue
		}
		for _, ons := range []string{rootMeta.GetNamespace(), ""} {
			if o, ok, err := c.Get(gv.Group, ref.Kind, ons, ref.Name); err == nil && ok {
				if om, err := meta.Accessor(o); err == nil && (ref.UID == "" || om.GetUID() == ref.UID) {
					owners = append(owners, topology.ObjectNode{Kind: ref.Kind, APIGroup: gv.Group, Obj: om})
				}
				break
			}
		}
	}

	var owned []topology.ObjectNode
	if rootNS := rootMeta.GetNamespace(); rootNS != "" {
		for _, ks := range c.Status() {
			if ks.State != objcache.StateSynced {
				continue
			}
			items, err := c.List(ks.Group, ks.Kind, rootNS)
			if err != nil {
				continue
			}
			for _, it := range items {
				m, err := meta.Accessor(it)
				if err != nil {
					continue
				}
				for _, ref := range m.GetOwnerReferences() {
					if ref.UID == rootMeta.GetUID() && ref.UID != "" {
						owned = append(owned, topology.ObjectNode{Kind: ks.Kind, APIGroup: ks.Group, Obj: m})
						break
					}
				}
			}
		}
	}
	// A GitOps application lists what it manages in status.resources; those
	// objects carry no ownerReference back to it.
	if u, ok := obj.(*unstructured.Unstructured); ok {
		managed, _, _ := unstructured.NestedSlice(u.Object, "status", "resources")
		for i, r := range managed {
			if i >= maxUnmappedOwnedScan {
				break
			}
			m, ok := r.(map[string]any)
			if !ok {
				continue
			}
			rg, _ := m["group"].(string)
			rk, _ := m["kind"].(string)
			rns, _ := m["namespace"].(string)
			rn, _ := m["name"].(string)
			if rk == "" || rn == "" {
				continue
			}
			if o, ok, err := c.Get(rg, rk, rns, rn); err == nil && ok {
				if om, err := meta.Accessor(o); err == nil {
					owned = append(owned, topology.ObjectNode{Kind: rk, APIGroup: rg, Obj: om})
				}
			}
		}
	}
	sg := topology.UnmappedNeighborhood(root, owners, owned, time.Now())
	return marshalInsight(neighborhoodResult{insightStamp: stampOf(e.meta([2]string{group, kind})), Subgraph: sg})
}

// resolveCachedKind finds the cache's own spelling of a kind (and its group,
// when the caller did not give one). registered is false when the cache does
// not know the kind at all; kind/group then echo the request.
func resolveCachedKind(c *objcache.Cache, kind, group string) (string, string, bool) {
	for _, ks := range c.Status() {
		if strings.EqualFold(ks.Kind, kind) && (group == "" || strings.EqualFold(ks.Group, group)) {
			return ks.Kind, ks.Group, true
		}
	}
	return kind, group, false
}
