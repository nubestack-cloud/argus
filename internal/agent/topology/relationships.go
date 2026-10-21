package topology

import (
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// RelationshipsIndex maps node ID to the edges touching that node, built in
// one pass over Topology.Edges so per-node neighbour lookups cost O(degree)
// instead of O(E). Lookups are read-only and goroutine-safe.
type RelationshipsIndex struct {
	byNodeID map[string]*nodeEdgeSlots
}

type nodeEdgeSlots struct {
	incoming []Edge
	outgoing []Edge
}

// IndexByResource builds a RelationshipsIndex over topo. A nil topology
// yields an empty index whose lookups all miss.
func IndexByResource(topo *Topology) *RelationshipsIndex {
	idx := &RelationshipsIndex{byNodeID: map[string]*nodeEdgeSlots{}}
	if topo == nil {
		return idx
	}
	slot := func(id string) *nodeEdgeSlots {
		s := idx.byNodeID[id]
		if s == nil {
			s = &nodeEdgeSlots{}
			idx.byNodeID[id] = s
		}
		return s
	}
	for _, e := range topo.Edges {
		if e.Source != "" {
			s := slot(e.Source)
			s.outgoing = append(s.outgoing, e)
		}
		if e.Target != "" {
			s := slot(e.Target)
			s.incoming = append(s.incoming, e)
		}
	}
	return idx
}

// EdgesFor returns the incoming and outgoing edges touching nodeID. Both
// slices alias the index's storage — callers must not mutate them. A nil
// index, or a node with no edges, returns (nil, nil).
func (r *RelationshipsIndex) EdgesFor(nodeID string) (incoming, outgoing []Edge) {
	if r == nil {
		return nil, nil
	}
	s := r.byNodeID[nodeID]
	if s == nil {
		return nil, nil
	}
	return s.incoming, s.outgoing
}

// kindAliases maps every accepted spelling of a kind (lowercase singular,
// plural, and common short names) to its NodeKind.
var kindAliases = func() map[string]NodeKind {
	m := map[string]NodeKind{}
	add := func(k NodeKind, aliases ...string) {
		m[strings.ToLower(string(k))] = k
		for _, a := range aliases {
			m[a] = k
		}
	}
	add(KindPod, "pods", "po")
	add(KindPodGroup, "podgroups")
	add(KindDeployment, "deployments", "deploy")
	add(KindReplicaSet, "replicasets", "rs")
	add(KindStatefulSet, "statefulsets", "sts")
	add(KindDaemonSet, "daemonsets", "ds")
	add(KindJob, "jobs")
	add(KindCronJob, "cronjobs", "cj")
	add(KindService, "services", "svc")
	add(KindIngress, "ingresses", "ing")
	add(KindGateway, "gateways", "gtw")
	add(KindHTTPRoute, "httproutes")
	add(KindGRPCRoute, "grpcroutes")
	add(KindTCPRoute, "tcproutes")
	add(KindTLSRoute, "tlsroutes")
	add(KindConfigMap, "configmaps", "cm")
	add(KindServiceAccount, "serviceaccounts", "sa")
	add(KindPVC, "persistentvolumeclaims", "pvc", "pvcs")
	add(KindPV, "persistentvolumes", "pv", "pvs")
	add(KindHPA, "horizontalpodautoscalers", "hpa", "hpas")
	add(KindPDB, "poddisruptionbudgets", "pdb", "pdbs")
	add(KindNetworkPolicy, "networkpolicies", "netpol", "netpols")
	add(KindNode, "nodes", "no")
	return m
}()

// normalizeKind resolves any accepted spelling of a kind to its NodeKind.
// ok is false for kinds the graph does not draw.
func normalizeKind(kind string) (NodeKind, bool) {
	k, ok := kindAliases[strings.ToLower(strings.TrimSpace(kind))]
	return k, ok
}

// buildNodeID constructs a node ID: lowercase kind / namespace / name. "/" is
// not allowed in Kubernetes names, so the ID is unambiguous; cluster-scoped
// objects have an empty namespace segment.
func buildNodeID(kind NodeKind, namespace, name string) string {
	return strings.ToLower(string(kind)) + "/" + namespace + "/" + name
}

// workloadRefs are the objects a pod template references by name. Secrets are
// deliberately not collected.
type workloadRefs struct {
	configMaps     map[string]bool
	pvcs           map[string]bool
	serviceAccount string
}

// extractWorkloadReferences collects the ConfigMaps (env valueFrom, envFrom,
// volumes, projected volumes), PVCs and ServiceAccount a pod spec uses.
func extractWorkloadReferences(spec corev1.PodSpec) workloadRefs {
	refs := workloadRefs{
		configMaps:     make(map[string]bool),
		pvcs:           make(map[string]bool),
		serviceAccount: spec.ServiceAccountName,
	}
	containers := make([]corev1.Container, 0, len(spec.Containers)+len(spec.InitContainers))
	containers = append(containers, spec.Containers...)
	containers = append(containers, spec.InitContainers...)
	for _, c := range containers {
		for _, env := range c.Env {
			if env.ValueFrom != nil && env.ValueFrom.ConfigMapKeyRef != nil {
				refs.configMaps[env.ValueFrom.ConfigMapKeyRef.Name] = true
			}
		}
		for _, envFrom := range c.EnvFrom {
			if envFrom.ConfigMapRef != nil {
				refs.configMaps[envFrom.ConfigMapRef.Name] = true
			}
		}
	}
	for _, v := range spec.Volumes {
		if v.ConfigMap != nil {
			refs.configMaps[v.ConfigMap.Name] = true
		}
		if v.Projected != nil {
			for _, src := range v.Projected.Sources {
				if src.ConfigMap != nil {
					refs.configMaps[src.ConfigMap.Name] = true
				}
			}
		}
		if v.PersistentVolumeClaim != nil {
			refs.pvcs[v.PersistentVolumeClaim.ClaimName] = true
		}
	}
	return refs
}

// matchesSelector reports whether labels satisfy an equality selector. An
// empty selector matches nothing: a Service without a selector routes to
// manually managed endpoints, not to every pod.
func matchesSelector(labels, selector map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// refKey is a (namespace, name) pair.
type refKey struct {
	namespace string
	name      string
}

// buildConsumerIndex inverts workloadID → referenced names into
// (namespace, name) → sorted workload IDs, so each ConfigMap/PVC looks up its
// consumers directly instead of scanning every workload.
func buildConsumerIndex(refs map[string]map[string]bool, workloadNamespaces map[string]string) map[refKey][]string {
	idx := make(map[refKey][]string)
	for workloadID, names := range refs {
		ns := workloadNamespaces[workloadID]
		for name := range names {
			key := refKey{namespace: ns, name: name}
			idx[key] = append(idx[key], workloadID)
		}
	}
	for _, ids := range idx {
		sort.Strings(ids)
	}
	return idx
}
