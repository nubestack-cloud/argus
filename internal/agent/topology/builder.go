package topology

import (
	"errors"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Per-node list caps inside a summary, so one object with many hosts / ports
// cannot dominate a tool result.
const maxSummaryListItems = 10

// Builder constructs topology graphs from a ResourceProvider.
type Builder struct {
	provider ResourceProvider
	dynamic  DynamicProvider
	now      func() time.Time
}

// NewBuilder creates a builder over provider.
func NewBuilder(provider ResourceProvider) *Builder {
	return &Builder{provider: provider, now: time.Now}
}

// WithDynamic adds Gateway API support. A nil provider leaves it off.
func (b *Builder) WithDynamic(dp DynamicProvider) *Builder {
	b.dynamic = dp
	return b
}

// WithClock injects the clock health grading uses (age-gated verdicts such as
// pending-too-long and CronJob staleness).
func (b *Builder) WithClock(now func() time.Time) *Builder {
	if now != nil {
		b.now = now
	}
	return b
}

// buildState carries one Build call's accumulators.
type buildState struct {
	b     *Builder
	opts  BuildOptions
	now   time.Time
	listN string // namespace passed to provider lists

	nodes       []Node
	nodeIndex   map[string]int
	edges       []Edge
	edgeSeen    map[string]bool
	unavailable []string

	// Workload template references, keyed by consumer node ID.
	configMapRefs      map[string]map[string]bool
	pvcRefs            map[string]map[string]bool
	serviceAccountRefs map[string]map[string]bool
	consumerNamespace  map[string]string
	// nodeConsumers: cluster Node name → pod / pod-group node IDs it hosts.
	nodeConsumers map[string]map[string]bool
}

// Build constructs the graph for opts.Namespaces. Kinds whose list fails are
// named in Topology.Unavailable and the graph is built from the rest; Build
// itself only fails when there is no provider.
func (b *Builder) Build(opts BuildOptions) (*Topology, error) {
	if b == nil || b.provider == nil {
		return nil, errors.New("topology: resource provider not initialized")
	}
	s := &buildState{
		b:                  b,
		opts:               opts,
		now:                b.now(),
		nodeIndex:          map[string]int{},
		edgeSeen:           map[string]bool{},
		configMapRefs:      map[string]map[string]bool{},
		pvcRefs:            map[string]map[string]bool{},
		serviceAccountRefs: map[string]map[string]bool{},
		consumerNamespace:  map[string]string{},
		nodeConsumers:      map[string]map[string]bool{},
	}
	if len(opts.Namespaces) == 1 {
		s.listN = opts.Namespaces[0]
	}
	s.build()
	return s.finish(), nil
}

// list calls fn and records kind as unavailable when it fails.
func list[T any](s *buildState, kind NodeKind, ns string, fn func(string) ([]T, error)) []T {
	items, err := fn(ns)
	if err != nil {
		s.unavailable = append(s.unavailable, string(kind))
		return nil
	}
	return items
}

func (s *buildState) addNode(n Node) {
	if _, dup := s.nodeIndex[n.ID]; dup {
		return
	}
	if n.APIGroup == "" {
		n.APIGroup = builtinGroups[n.Kind]
	}
	s.nodeIndex[n.ID] = len(s.nodes)
	s.nodes = append(s.nodes, n)
}

func (s *buildState) hasNode(id string) bool {
	_, ok := s.nodeIndex[id]
	return ok
}

func (s *buildState) addEdge(source, target string, typ EdgeType) {
	if source == "" || target == "" || source == target {
		return
	}
	id := source + "-" + string(typ) + "-" + target
	if s.edgeSeen[id] {
		return
	}
	s.edgeSeen[id] = true
	s.edges = append(s.edges, Edge{ID: id, Source: source, Target: target, Type: typ})
}

// trackRefs records which ConfigMaps / PVCs / ServiceAccount consumerID's pod
// template references.
func (s *buildState) trackRefs(consumerID, namespace string, refs workloadRefs) {
	s.consumerNamespace[consumerID] = namespace
	if len(refs.configMaps) > 0 {
		s.configMapRefs[consumerID] = refs.configMaps
	}
	if len(refs.pvcs) > 0 {
		s.pvcRefs[consumerID] = refs.pvcs
	}
	if refs.serviceAccount != "" {
		s.serviceAccountRefs[consumerID] = map[string]bool{refs.serviceAccount: true}
	}
}

func (s *buildState) trackNodeName(nodeName, consumerID string) {
	if nodeName == "" {
		return
	}
	if s.nodeConsumers[nodeName] == nil {
		s.nodeConsumers[nodeName] = map[string]bool{}
	}
	s.nodeConsumers[nodeName][consumerID] = true
}

// finish drops edges that dangle off a node never created (an owner whose list
// was forbidden, say) and returns the topology.
func (s *buildState) finish() *Topology {
	edges := s.edges[:0]
	for _, e := range s.edges {
		if s.hasNode(e.Source) && s.hasNode(e.Target) {
			edges = append(edges, e)
		}
	}
	sort.Strings(s.unavailable)
	return &Topology{Nodes: s.nodes, Edges: edges, Unavailable: s.unavailable}
}

// ownerGroupMatches reports whether an owner reference's apiVersion is
// consistent with kind's built-in group, so a custom resource that shadows a
// built-in kind (a batch-scheduler "Job", say) is never joined to a same-named
// typed workload. An owner ref with no apiVersion is treated permissively.
func ownerGroupMatches(kind, apiVersion string) bool {
	if apiVersion == "" {
		return true
	}
	expected, known := builtinGroups[NodeKind(kind)]
	if !known {
		return true
	}
	return groupFromAPIVersion(apiVersion) == expected
}

// groupFromAPIVersion returns the group of "group/version" ("" for "v1").
func groupFromAPIVersion(apiVersion string) string {
	if i := strings.Index(apiVersion, "/"); i >= 0 {
		return apiVersion[:i]
	}
	return ""
}

func specReplicas(r *int32) int32 {
	if r != nil {
		return *r
	}
	return 1
}

func capStrings(in []string) []string {
	if len(in) > maxSummaryListItems {
		return in[:maxSummaryListItems]
	}
	return in
}

func (s *buildState) build() {
	p := s.b.provider
	opts := s.opts
	now := s.now

	// Workloads -------------------------------------------------------------

	deployments := list(s, KindDeployment, s.listN, p.Deployments)
	deploymentIDs := map[string]string{}
	for _, d := range deployments {
		if !opts.matchesNamespace(d.Namespace) {
			continue
		}
		id := buildNodeID(KindDeployment, d.Namespace, d.Name)
		deploymentIDs[d.Namespace+"/"+d.Name] = id
		status, reason := workloadStatus(d, now)
		s.addNode(Node{
			ID: id, Kind: KindDeployment, Namespace: d.Namespace, Name: d.Name,
			Status: status, StatusReason: reason, Labels: d.Labels,
			Summary: map[string]any{
				"replicas":          specReplicas(d.Spec.Replicas),
				"readyReplicas":     d.Status.ReadyReplicas,
				"availableReplicas": d.Status.AvailableReplicas,
				"updatedReplicas":   d.Status.UpdatedReplicas,
				"strategy":          string(d.Spec.Strategy.Type),
			},
		})
		s.trackRefs(id, d.Namespace, extractWorkloadReferences(d.Spec.Template.Spec))
	}

	daemonSets := list(s, KindDaemonSet, s.listN, p.DaemonSets)
	for _, ds := range daemonSets {
		if !opts.matchesNamespace(ds.Namespace) {
			continue
		}
		id := buildNodeID(KindDaemonSet, ds.Namespace, ds.Name)
		status, reason := workloadStatus(ds, now)
		s.addNode(Node{
			ID: id, Kind: KindDaemonSet, Namespace: ds.Namespace, Name: ds.Name,
			Status: status, StatusReason: reason, Labels: ds.Labels,
			Summary: map[string]any{
				"desired":   ds.Status.DesiredNumberScheduled,
				"ready":     ds.Status.NumberReady,
				"available": ds.Status.NumberAvailable,
				"updated":   ds.Status.UpdatedNumberScheduled,
			},
		})
		s.trackRefs(id, ds.Namespace, extractWorkloadReferences(ds.Spec.Template.Spec))
	}

	statefulSets := list(s, KindStatefulSet, s.listN, p.StatefulSets)
	for _, sts := range statefulSets {
		if !opts.matchesNamespace(sts.Namespace) {
			continue
		}
		id := buildNodeID(KindStatefulSet, sts.Namespace, sts.Name)
		status, reason := workloadStatus(sts, now)
		s.addNode(Node{
			ID: id, Kind: KindStatefulSet, Namespace: sts.Namespace, Name: sts.Name,
			Status: status, StatusReason: reason, Labels: sts.Labels,
			Summary: map[string]any{
				"replicas":        specReplicas(sts.Spec.Replicas),
				"readyReplicas":   sts.Status.ReadyReplicas,
				"updatedReplicas": sts.Status.UpdatedReplicas,
			},
		})
		s.trackRefs(id, sts.Namespace, extractWorkloadReferences(sts.Spec.Template.Spec))
	}

	cronJobs := list(s, KindCronJob, s.listN, p.CronJobs)
	cronJobIDs := map[string]string{}
	for _, cj := range cronJobs {
		if !opts.matchesNamespace(cj.Namespace) {
			continue
		}
		id := buildNodeID(KindCronJob, cj.Namespace, cj.Name)
		cronJobIDs[cj.Namespace+"/"+cj.Name] = id
		status, reason := workloadStatus(cj, now)
		summary := map[string]any{
			"schedule":   cj.Spec.Schedule,
			"suspend":    cj.Spec.Suspend != nil && *cj.Spec.Suspend,
			"activeJobs": len(cj.Status.Active),
		}
		if cj.Status.LastScheduleTime != nil {
			summary["lastScheduleTime"] = cj.Status.LastScheduleTime.UTC().Format(time.RFC3339)
		}
		s.addNode(Node{
			ID: id, Kind: KindCronJob, Namespace: cj.Namespace, Name: cj.Name,
			Status: status, StatusReason: reason, Labels: cj.Labels, Summary: summary,
		})
		s.trackRefs(id, cj.Namespace, extractWorkloadReferences(cj.Spec.JobTemplate.Spec.Template.Spec))
	}

	jobs := list(s, KindJob, s.listN, p.Jobs)
	jobIDs := map[string]string{}
	for _, job := range jobs {
		if !opts.matchesNamespace(job.Namespace) {
			continue
		}
		id := buildNodeID(KindJob, job.Namespace, job.Name)
		jobIDs[job.Namespace+"/"+job.Name] = id
		status, reason := workloadStatus(job, now)
		summary := map[string]any{
			"succeeded": job.Status.Succeeded,
			"failed":    job.Status.Failed,
			"active":    job.Status.Active,
		}
		if job.Spec.Completions != nil {
			summary["completions"] = *job.Spec.Completions
		}
		if job.Status.StartTime != nil {
			summary["startTime"] = job.Status.StartTime.UTC().Format(time.RFC3339)
		}
		if job.Status.CompletionTime != nil {
			summary["completionTime"] = job.Status.CompletionTime.UTC().Format(time.RFC3339)
		}
		s.addNode(Node{
			ID: id, Kind: KindJob, Namespace: job.Namespace, Name: job.Name,
			Status: status, StatusReason: reason, Labels: job.Labels, Summary: summary,
		})
		s.trackRefs(id, job.Namespace, extractWorkloadReferences(job.Spec.Template.Spec))
		for _, ref := range job.OwnerReferences {
			if ref.Kind == "CronJob" && ownerGroupMatches(ref.Kind, ref.APIVersion) {
				s.addEdge(cronJobIDs[job.Namespace+"/"+ref.Name], id, EdgeOwns)
			}
		}
	}

	// ReplicaSets: hidden behind their Deployment unless asked for, but a
	// ReplicaSet with no Deployment in the graph is always drawn so its pods
	// keep an owner.
	replicaSets := list(s, KindReplicaSet, s.listN, p.ReplicaSets)
	rsIDs := map[string]string{}          // visible ReplicaSets
	rsToDeployment := map[string]string{} // rs key → owning Deployment node
	for _, rs := range replicaSets {
		if !opts.matchesNamespace(rs.Namespace) || (rs.Spec.Replicas != nil && *rs.Spec.Replicas == 0) {
			continue
		}
		key := rs.Namespace + "/" + rs.Name
		for _, ref := range rs.OwnerReferences {
			if ref.Kind == "Deployment" && ownerGroupMatches(ref.Kind, ref.APIVersion) {
				if depID, ok := deploymentIDs[rs.Namespace+"/"+ref.Name]; ok {
					rsToDeployment[key] = depID
				}
			}
		}
		if _, owned := rsToDeployment[key]; owned && !opts.IncludeReplicaSets && !opts.isFocus(KindReplicaSet, rs.Namespace, rs.Name) {
			continue
		}
		id := buildNodeID(KindReplicaSet, rs.Namespace, rs.Name)
		rsIDs[key] = id
		status, reason := workloadStatus(rs, now)
		s.addNode(Node{
			ID: id, Kind: KindReplicaSet, Namespace: rs.Namespace, Name: rs.Name,
			Status: status, StatusReason: reason, Labels: rs.Labels,
			Summary: map[string]any{
				"replicas":      specReplicas(rs.Spec.Replicas),
				"readyReplicas": rs.Status.ReadyReplicas,
			},
		})
		s.addEdge(rsToDeployment[key], id, EdgeOwns)
	}

	// Pods ------------------------------------------------------------------

	pods := list(s, KindPod, s.listN, p.Pods)
	// unownedPods are pod / pod-group nodes with no owner in the graph; a
	// Service can only be linked to them by their own labels.
	type podTarget struct {
		id     string
		ns     string
		labels map[string]string
	}
	var unownedPods []podTarget
	podOwnerEdges := func(pod *corev1.Pod, targetID string) bool {
		owned := false
		for _, ref := range pod.OwnerReferences {
			if !ownerGroupMatches(ref.Kind, ref.APIVersion) {
				continue
			}
			key := pod.Namespace + "/" + ref.Name
			var ownerID string
			switch ref.Kind {
			case "ReplicaSet":
				if id, ok := rsIDs[key]; ok {
					ownerID = id
				} else {
					ownerID = rsToDeployment[key]
				}
			case "DaemonSet":
				ownerID = buildNodeID(KindDaemonSet, pod.Namespace, ref.Name)
			case "StatefulSet":
				ownerID = buildNodeID(KindStatefulSet, pod.Namespace, ref.Name)
			case "Job":
				ownerID = jobIDs[key]
			}
			if ownerID != "" && s.hasNode(ownerID) {
				s.addEdge(ownerID, targetID, EdgeOwns)
				owned = true
			}
		}
		return owned
	}
	addPod := func(pod *corev1.Pod) {
		n := newPodNode(pod, now)
		s.addNode(n)
		s.trackRefs(n.ID, pod.Namespace, extractWorkloadReferences(pod.Spec))
		s.trackNodeName(pod.Spec.NodeName, n.ID)
		if !podOwnerEdges(pod, n.ID) {
			unownedPods = append(unownedPods, podTarget{id: n.ID, ns: pod.Namespace, labels: pod.Labels})
		}
	}
	maxIndividual := opts.MaxIndividualPods
	if maxIndividual <= 0 {
		maxIndividual = 5
	}
	groups := GroupPods(pods, opts, now)
	groupKeys := make([]string, 0, len(groups))
	for k := range groups {
		groupKeys = append(groupKeys, k)
	}
	sort.Strings(groupKeys)
	for _, k := range groupKeys {
		group := groups[k]
		sort.Slice(group.Pods, func(i, j int) bool { return group.Pods[i].Name < group.Pods[j].Name })
		// The focus pod always stands alone; the rest group as usual.
		rest := group.Pods[:0:0]
		for _, pod := range group.Pods {
			if opts.isFocus(KindPod, pod.Namespace, pod.Name) {
				addPod(pod)
				continue
			}
			rest = append(rest, pod)
		}
		if len(rest) <= maxIndividual {
			for _, pod := range rest {
				addPod(pod)
			}
			continue
		}
		restGroup := *group
		restGroup.Pods = rest
		restGroup.Counts = tallyPods(rest, now)
		n := newPodGroupNode(&restGroup, now)
		s.addNode(n)
		// One owner edge per distinct owner among the group's pods — a group
		// can span several ReplicaSets mid-rollout.
		owned := false
		seenOwner := map[string]bool{}
		for _, pod := range rest {
			s.trackNodeName(pod.Spec.NodeName, n.ID)
			for _, ref := range pod.OwnerReferences {
				ok := ref.Kind + "/" + ref.Name
				if seenOwner[ok] {
					continue
				}
				seenOwner[ok] = true
				if podOwnerEdges(pod, n.ID) {
					owned = true
				}
			}
		}
		if !owned {
			unownedPods = append(unownedPods, podTarget{id: n.ID, ns: group.Namespace, labels: rest[0].Labels})
		}
	}

	// Services --------------------------------------------------------------

	type templated struct {
		id     string
		labels map[string]string
	}
	byNS := map[string][]templated{}
	for _, d := range deployments {
		if id, ok := deploymentIDs[d.Namespace+"/"+d.Name]; ok {
			byNS[d.Namespace] = append(byNS[d.Namespace], templated{id, d.Spec.Template.Labels})
		}
	}
	for _, sts := range statefulSets {
		if id := buildNodeID(KindStatefulSet, sts.Namespace, sts.Name); s.hasNode(id) {
			byNS[sts.Namespace] = append(byNS[sts.Namespace], templated{id, sts.Spec.Template.Labels})
		}
	}
	for _, ds := range daemonSets {
		if id := buildNodeID(KindDaemonSet, ds.Namespace, ds.Name); s.hasNode(id) {
			byNS[ds.Namespace] = append(byNS[ds.Namespace], templated{id, ds.Spec.Template.Labels})
		}
	}
	// Completed Jobs have no pods left to back a Service.
	activeJobsByNS := map[string][]templated{}
	for _, job := range jobs {
		if id, ok := jobIDs[job.Namespace+"/"+job.Name]; ok && job.Status.Active > 0 {
			activeJobsByNS[job.Namespace] = append(activeJobsByNS[job.Namespace], templated{id, job.Spec.Template.Labels})
		}
	}
	for _, rs := range replicaSets {
		key := rs.Namespace + "/" + rs.Name
		if id, ok := rsIDs[key]; ok && rsToDeployment[key] == "" {
			byNS[rs.Namespace] = append(byNS[rs.Namespace], templated{id, rs.Spec.Template.Labels})
		}
	}

	services := list(s, KindService, s.listN, p.Services)
	serviceIDs := map[string]string{}
	for _, svc := range services {
		if !opts.matchesNamespace(svc.Namespace) {
			continue
		}
		id := buildNodeID(KindService, svc.Namespace, svc.Name)
		serviceIDs[svc.Namespace+"/"+svc.Name] = id
		s.addNode(Node{
			ID: id, Kind: KindService, Namespace: svc.Namespace, Name: svc.Name,
			Status: StatusHealthy, Labels: svc.Labels,
			Summary: map[string]any{
				"type":      string(svc.Spec.Type),
				"clusterIP": svc.Spec.ClusterIP,
				"ports":     serviceTopologyPorts(svc.Spec.Ports),
			},
		})
		for _, w := range byNS[svc.Namespace] {
			if matchesSelector(w.labels, svc.Spec.Selector) {
				s.addEdge(id, w.id, EdgeExposes)
			}
		}
		for _, w := range activeJobsByNS[svc.Namespace] {
			if matchesSelector(w.labels, svc.Spec.Selector) {
				s.addEdge(id, w.id, EdgeExposes)
			}
		}
		for _, pt := range unownedPods {
			if pt.ns == svc.Namespace && matchesSelector(pt.labels, svc.Spec.Selector) {
				s.addEdge(id, pt.id, EdgeExposes)
			}
		}
	}

	// Ingresses -------------------------------------------------------------

	for _, ing := range list(s, KindIngress, s.listN, p.Ingresses) {
		if !opts.matchesNamespace(ing.Namespace) {
			continue
		}
		id := buildNodeID(KindIngress, ing.Namespace, ing.Name)
		var hosts []string
		for _, rule := range ing.Spec.Rules {
			if rule.Host != "" {
				hosts = append(hosts, rule.Host)
			}
		}
		summary := map[string]any{"tls": len(ing.Spec.TLS) > 0}
		if len(hosts) > 0 {
			summary["hosts"] = capStrings(hosts)
		}
		if ing.Spec.IngressClassName != nil {
			summary["ingressClassName"] = *ing.Spec.IngressClassName
		}
		s.addNode(Node{
			ID: id, Kind: KindIngress, Namespace: ing.Namespace, Name: ing.Name,
			Status: StatusHealthy, Labels: ing.Labels, Summary: summary,
		})
		if db := ing.Spec.DefaultBackend; db != nil && db.Service != nil {
			s.addEdge(id, serviceIDs[ing.Namespace+"/"+db.Service.Name], EdgeRoutesTo)
		}
		for _, rule := range ing.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}
			for _, path := range rule.HTTP.Paths {
				if path.Backend.Service != nil {
					s.addEdge(id, serviceIDs[ing.Namespace+"/"+path.Backend.Service.Name], EdgeRoutesTo)
				}
			}
		}
	}

	// Gateway API -----------------------------------------------------------

	s.buildGatewayAPI(serviceIDs)

	// ConfigMaps / ServiceAccounts / PVCs / PVs -----------------------------

	cmConsumers := buildConsumerIndex(s.configMapRefs, s.consumerNamespace)
	for _, cm := range list(s, KindConfigMap, s.listN, p.ConfigMaps) {
		if !opts.matchesNamespace(cm.Namespace) {
			continue
		}
		consumers := cmConsumers[refKey{cm.Namespace, cm.Name}]
		if len(consumers) == 0 && !opts.isFocus(KindConfigMap, cm.Namespace, cm.Name) {
			continue
		}
		id := buildNodeID(KindConfigMap, cm.Namespace, cm.Name)
		// Only the key count: values are never read, and in the agent cache
		// they are hashes anyway.
		s.addNode(Node{
			ID: id, Kind: KindConfigMap, Namespace: cm.Namespace, Name: cm.Name,
			Status: StatusHealthy, Labels: cm.Labels,
			Summary: map[string]any{"keys": len(cm.Data) + len(cm.BinaryData)},
		})
		for _, c := range consumers {
			s.addEdge(id, c, EdgeConfigures)
		}
	}

	saConsumers := buildConsumerIndex(s.serviceAccountRefs, s.consumerNamespace)
	for _, sa := range list(s, KindServiceAccount, s.listN, p.ServiceAccounts) {
		if !opts.matchesNamespace(sa.Namespace) {
			continue
		}
		consumers := saConsumers[refKey{sa.Namespace, sa.Name}]
		if len(consumers) == 0 && !opts.isFocus(KindServiceAccount, sa.Namespace, sa.Name) {
			continue
		}
		id := buildNodeID(KindServiceAccount, sa.Namespace, sa.Name)
		s.addNode(Node{
			ID: id, Kind: KindServiceAccount, Namespace: sa.Namespace, Name: sa.Name,
			Status: StatusHealthy, Labels: sa.Labels,
		})
		for _, c := range consumers {
			s.addEdge(id, c, EdgeConfigures)
		}
	}

	pvcConsumers := buildConsumerIndex(s.pvcRefs, s.consumerNamespace)
	pvToPVC := map[string]string{} // PV name → PVC node ID
	for _, pvc := range list(s, KindPVC, s.listN, p.PersistentVolumeClaims) {
		if !opts.matchesNamespace(pvc.Namespace) {
			continue
		}
		consumers := pvcConsumers[refKey{pvc.Namespace, pvc.Name}]
		if len(consumers) == 0 && !opts.isFocus(KindPVC, pvc.Namespace, pvc.Name) {
			continue
		}
		id := buildNodeID(KindPVC, pvc.Namespace, pvc.Name)
		status, reason := workloadStatus(pvc, now)
		summary := map[string]any{"phase": string(pvc.Status.Phase)}
		if q, ok := pvc.Spec.Resources.Requests[corev1.ResourceStorage]; ok {
			summary["storage"] = q.String()
		}
		if pvc.Spec.StorageClassName != nil {
			summary["storageClass"] = *pvc.Spec.StorageClassName
		}
		if len(pvc.Spec.AccessModes) > 0 {
			modes := make([]string, 0, len(pvc.Spec.AccessModes))
			for _, m := range pvc.Spec.AccessModes {
				modes = append(modes, string(m))
			}
			summary["accessModes"] = modes
		}
		if pvc.Spec.VolumeName != "" {
			summary["volumeName"] = pvc.Spec.VolumeName
			pvToPVC[pvc.Spec.VolumeName] = id
		}
		s.addNode(Node{
			ID: id, Kind: KindPVC, Namespace: pvc.Namespace, Name: pvc.Name,
			Status: status, StatusReason: reason, Labels: pvc.Labels, Summary: summary,
		})
		for _, c := range consumers {
			s.addEdge(id, c, EdgeUses)
		}
	}
	focusPV := opts.Focus.Name != "" && opts.isFocus(KindPV, "", opts.Focus.Name)
	if len(pvToPVC) > 0 || focusPV {
		for _, pv := range list(s, KindPV, "", p.PersistentVolumes) {
			pvcID, bound := pvToPVC[pv.Name]
			if !bound && !opts.isFocus(KindPV, "", pv.Name) {
				continue
			}
			id := buildNodeID(KindPV, "", pv.Name)
			status, reason := pvStatus(pv)
			summary := map[string]any{
				"phase":         string(pv.Status.Phase),
				"reclaimPolicy": string(pv.Spec.PersistentVolumeReclaimPolicy),
			}
			if q, ok := pv.Spec.Capacity[corev1.ResourceStorage]; ok {
				summary["capacity"] = q.String()
			}
			if pv.Spec.StorageClassName != "" {
				summary["storageClass"] = pv.Spec.StorageClassName
			}
			s.addNode(Node{
				ID: id, Kind: KindPV, Name: pv.Name,
				Status: status, StatusReason: reason, Labels: pv.Labels, Summary: summary,
			})
			s.addEdge(id, pvcID, EdgeUses)
		}
	}

	// Scaling and protection ------------------------------------------------

	statefulSetID := func(ns, name string) string { return buildNodeID(KindStatefulSet, ns, name) }
	for _, hpa := range list(s, KindHPA, s.listN, p.HorizontalPodAutoscalers) {
		if !opts.matchesNamespace(hpa.Namespace) {
			continue
		}
		id := buildNodeID(KindHPA, hpa.Namespace, hpa.Name)
		status, reason := hpaStatus(hpa)
		summary := map[string]any{
			"maxReplicas":     hpa.Spec.MaxReplicas,
			"currentReplicas": hpa.Status.CurrentReplicas,
			"desiredReplicas": hpa.Status.DesiredReplicas,
		}
		if hpa.Spec.MinReplicas != nil {
			summary["minReplicas"] = *hpa.Spec.MinReplicas
		}
		s.addNode(Node{
			ID: id, Kind: KindHPA, Namespace: hpa.Namespace, Name: hpa.Name,
			Status: status, StatusReason: reason, Labels: hpa.Labels, Summary: summary,
		})
		target := hpa.Spec.ScaleTargetRef
		if !ownerGroupMatches(target.Kind, target.APIVersion) {
			continue
		}
		key := hpa.Namespace + "/" + target.Name
		switch target.Kind {
		case "Deployment":
			s.addEdge(id, deploymentIDs[key], EdgeUses)
		case "StatefulSet":
			s.addEdge(id, statefulSetID(hpa.Namespace, target.Name), EdgeUses)
		case "ReplicaSet":
			s.addEdge(id, rsIDs[key], EdgeUses)
		}
	}

	protect := func(sourceID, ns string, sel labels.Selector) {
		for _, w := range byNS[ns] {
			if sel.Matches(labels.Set(w.labels)) {
				s.addEdge(sourceID, w.id, EdgeProtects)
			}
		}
		for _, pt := range unownedPods {
			if pt.ns == ns && sel.Matches(labels.Set(pt.labels)) {
				s.addEdge(sourceID, pt.id, EdgeProtects)
			}
		}
	}

	for _, pdb := range list(s, KindPDB, s.listN, p.PodDisruptionBudgets) {
		if !opts.matchesNamespace(pdb.Namespace) {
			continue
		}
		id := buildNodeID(KindPDB, pdb.Namespace, pdb.Name)
		status, reason := pdbStatus(pdb.Status.DisruptionsAllowed, pdb.Status.CurrentHealthy, pdb.Status.DesiredHealthy)
		s.addNode(Node{
			ID: id, Kind: KindPDB, Namespace: pdb.Namespace, Name: pdb.Name,
			Status: status, StatusReason: reason, Labels: pdb.Labels,
			Summary: map[string]any{
				"disruptionsAllowed": pdb.Status.DisruptionsAllowed,
				"currentHealthy":     pdb.Status.CurrentHealthy,
				"desiredHealthy":     pdb.Status.DesiredHealthy,
			},
		})
		if pdb.Spec.Selector == nil {
			continue
		}
		if sel, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector); err == nil && !sel.Empty() {
			protect(id, pdb.Namespace, sel)
		}
	}

	for _, np := range list(s, KindNetworkPolicy, s.listN, p.NetworkPolicies) {
		if !opts.matchesNamespace(np.Namespace) {
			continue
		}
		id := buildNodeID(KindNetworkPolicy, np.Namespace, np.Name)
		policyTypes := make([]string, 0, len(np.Spec.PolicyTypes))
		for _, pt := range np.Spec.PolicyTypes {
			policyTypes = append(policyTypes, string(pt))
		}
		summary := map[string]any{"policyTypes": policyTypes}
		s.addNode(Node{
			ID: id, Kind: KindNetworkPolicy, Namespace: np.Namespace, Name: np.Name,
			Status: StatusHealthy, Labels: np.Labels, Summary: summary,
		})
		// An empty podSelector selects every pod in the namespace (typically
		// a default-deny). Drawing an edge to every workload would bury the
		// graph, so it is flagged on the node instead.
		if np.Spec.PodSelector.Size() == 0 {
			summary["matchesAllPods"] = true
			continue
		}
		if sel, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector); err == nil {
			protect(id, np.Namespace, sel)
		}
	}

	// Cluster nodes hosting the drawn pods -----------------------------------

	focusNode := opts.Focus.Name != "" && opts.isFocus(KindNode, "", opts.Focus.Name)
	if len(s.nodeConsumers) > 0 || focusNode {
		for _, node := range list(s, KindNode, "", p.Nodes) {
			consumers := s.nodeConsumers[node.Name]
			if len(consumers) == 0 && !opts.isFocus(KindNode, "", node.Name) {
				continue
			}
			id := buildNodeID(KindNode, "", node.Name)
			status, reason := nodeStatus(node)
			summary := map[string]any{
				"unschedulable":  node.Spec.Unschedulable,
				"kubeletVersion": node.Status.NodeInfo.KubeletVersion,
			}
			s.addNode(Node{
				ID: id, Kind: KindNode, Name: node.Name,
				Status: status, StatusReason: reason, Labels: node.Labels, Summary: summary,
			})
			ids := make([]string, 0, len(consumers))
			for c := range consumers {
				ids = append(ids, c)
			}
			sort.Strings(ids)
			for _, c := range ids {
				s.addEdge(id, c, EdgeUses)
			}
		}
	}
}

// pvStatus grades a PersistentVolume by phase.
func pvStatus(pv *corev1.PersistentVolume) (HealthStatus, string) {
	switch pv.Status.Phase {
	case corev1.VolumeBound:
		return StatusHealthy, ""
	case corev1.VolumeAvailable, corev1.VolumePending:
		return StatusNeutral, string(pv.Status.Phase)
	case corev1.VolumeReleased:
		return StatusDegraded, string(pv.Status.Phase)
	case corev1.VolumeFailed:
		return StatusUnhealthy, string(pv.Status.Phase)
	}
	return StatusUnknown, ""
}

// topologyPort is one Service port as the map's Service node shows it.
type topologyPort struct {
	Name        string `json:"name,omitempty"`
	Port        int32  `json:"port"`
	TargetPort  string `json:"targetPort"`
	Protocol    string `json:"protocol"`
	AppProtocol string `json:"appProtocol,omitempty"`
}

// serviceTopologyPorts lists a Service's ports — all of them, since the first
// alone misdescribes a multi-port Service — up to maxSummaryListItems.
func serviceTopologyPorts(svcPorts []corev1.ServicePort) []topologyPort {
	n := min(len(svcPorts), maxSummaryListItems)
	out := make([]topologyPort, n)
	for i := range out {
		sp := svcPorts[i]
		out[i] = topologyPort{Name: sp.Name, Port: sp.Port, TargetPort: sp.TargetPort.String(), Protocol: string(sp.Protocol)}
		if sp.AppProtocol != nil {
			out[i].AppProtocol = *sp.AppProtocol
		}
	}
	return out
}

// buildGatewayAPI adds Gateways and routes, then Gateway → route and route →
// Service edges.
func (s *buildState) buildGatewayAPI(serviceIDs map[string]string) {
	dp := s.b.dynamic
	if dp == nil {
		return
	}
	listGK := func(kind NodeKind) []*unstructured.Unstructured {
		items, err := dp.List(schema.GroupKind{Group: GatewayAPIGroup, Kind: string(kind)}, s.listN)
		if err != nil {
			if !errors.Is(err, ErrNotServed) {
				s.unavailable = append(s.unavailable, string(kind))
			}
			return nil
		}
		return items
	}

	gatewayIDs := map[string]string{}
	for _, gw := range listGK(KindGateway) {
		ns := gw.GetNamespace()
		if !s.opts.matchesNamespace(ns) {
			continue
		}
		id := buildNodeID(KindGateway, ns, gw.GetName())
		gatewayIDs[ns+"/"+gw.GetName()] = id
		listeners, _, _ := unstructured.NestedSlice(gw.Object, "spec", "listeners")
		className, _, _ := unstructured.NestedString(gw.Object, "spec", "gatewayClassName")
		status, reason := gatewayStatus(gw)
		summary := map[string]any{"listenerCount": len(listeners)}
		if className != "" {
			summary["gatewayClassName"] = className
		}
		s.addNode(Node{
			ID: id, Kind: KindGateway, APIGroup: GatewayAPIGroup, Namespace: ns, Name: gw.GetName(),
			Status: status, StatusReason: reason, Labels: gw.GetLabels(), Summary: summary,
		})
	}

	for _, kind := range gatewayRouteKinds {
		for _, route := range listGK(kind) {
			ns := route.GetNamespace()
			if !s.opts.matchesNamespace(ns) {
				continue
			}
			id := buildNodeID(kind, ns, route.GetName())
			hostnames, _, _ := unstructured.NestedStringSlice(route.Object, "spec", "hostnames")
			rules, _, _ := unstructured.NestedSlice(route.Object, "spec", "rules")
			status, reason := routeStatus(route)
			summary := map[string]any{"rulesCount": len(rules)}
			if len(hostnames) > 0 {
				summary["hostnames"] = capStrings(hostnames)
			}
			s.addNode(Node{
				ID: id, Kind: kind, APIGroup: GatewayAPIGroup, Namespace: ns, Name: route.GetName(),
				Status: status, StatusReason: reason, Labels: route.GetLabels(), Summary: summary,
			})

			parentRefs, _, _ := unstructured.NestedSlice(route.Object, "spec", "parentRefs")
			for _, raw := range parentRefs {
				ref, ok := raw.(map[string]any)
				if !ok || !gatewayParentIsGateway(ref) {
					continue
				}
				name, _ := ref["name"].(string)
				s.addEdge(gatewayIDs[gatewayRefNamespace(ref, ns)+"/"+name], id, EdgeRoutesTo)
			}
			for _, rawRule := range rules {
				rule, ok := rawRule.(map[string]any)
				if !ok {
					continue
				}
				backendRefs, _, _ := unstructured.NestedSlice(rule, "backendRefs")
				for _, raw := range backendRefs {
					ref, ok := raw.(map[string]any)
					if !ok || !gatewayBackendIsService(ref) {
						continue
					}
					name, _ := ref["name"].(string)
					s.addEdge(id, serviceIDs[gatewayRefNamespace(ref, ns)+"/"+name], EdgeRoutesTo)
				}
			}
		}
	}
}

// gatewayBackendIsService reports whether a route backendRef names a core
// Service (group "" and kind "" or "Service").
func gatewayBackendIsService(ref map[string]any) bool {
	group, _ := ref["group"].(string)
	kind, _ := ref["kind"].(string)
	return group == "" && (kind == "" || kind == "Service")
}

// gatewayParentIsGateway reports whether a route parentRef names a Gateway.
// An absent group defaults to the Gateway API group; an explicit "" is core.
func gatewayParentIsGateway(ref map[string]any) bool {
	group, hasGroup := ref["group"].(string)
	kind, _ := ref["kind"].(string)
	return (!hasGroup || group == GatewayAPIGroup) && (kind == "" || kind == "Gateway")
}

// gatewayRefNamespace returns the reference's namespace, defaulting to the
// route's own.
func gatewayRefNamespace(ref map[string]any, routeNamespace string) string {
	if ns, _ := ref["namespace"].(string); ns != "" {
		return ns
	}
	return routeNamespace
}
