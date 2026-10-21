package agent

// sweep_snapshot.go is the sweep detector's per-pass, list-once view of the
// cluster (PROJECT.md P17(a)/(b)).
//
// # The problem this exists to fix
//
// Every checker in sweepCheckers used to issue its own cluster-wide List for
// every kind it touched, independently of every other checker in the same
// pass. Measured on 2026-09-23, one sweep made 25 List calls, and nine kinds
// were listed two or three times in the same pass: Services 3x, and
// Deployments, StatefulSets, PVCs, Pods, Nodes, HPAs, EndpointSlices and
// Ingresses 2x each. On a large cluster a cluster-wide Pod list is the single
// most expensive read an API server serves, and the sweep asked for it twice
// every five minutes, forever, for no benefit: the two callers wanted the
// same objects at the same instant.
//
// One snapshot per pass collapses that to one List per kind. This is a pure
// cost change, not a behaviour change: two checkers that previously listed
// the same kind a few milliseconds apart now read one list, which if anything
// makes the pass MORE internally consistent (a Service and its EndpointSlices
// can no longer be read across a write).
//
// # Laziness, and why it is not an optimisation detail
//
// Lists are issued on first demand, not eagerly up front, because two
// checkers deliberately short-circuit: checkOrphanedPVC returns early when
// the cluster has no StatefulSets at all (so it never pays for the PVC and
// Pod lists), and checkIngressBackendMissing returns early when it has no
// Ingresses (so it never pays for the Service list). Building the snapshot
// eagerly would quietly spend exactly the reads those two checkers were
// written to avoid.
//
// # Errors are cached too, deliberately
//
// If a List fails, the failure is cached and handed to every later checker
// that asks for the same kind. That preserves the pre-snapshot error
// behaviour exactly — when the Service list was failing, all three of its
// callers reported an error and all three appeared in runOneSweep's aggregate
// — while not re-paying for a read that has already failed once this pass.
// It matters more since P19: each checker runs under its own deadline, so a
// retry would let one slow kind burn every remaining checker's budget in
// turn, which is the precise failure P19 exists to bound.
//
// # Not a cache across passes
//
// A snapshot lives for exactly one runOneSweep call and is discarded. It is
// not a store, not an informer, and holds no state between passes. The
// SharedInformerFactory end state named at detector.go:120 is a different,
// larger change and is explicitly not what this is.

import (
	"context"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// sweepListOptions is the ListOptions every read in this file uses.
//
// ResourceVersion: "0" (PROJECT.md P17(b)) asks the API server to serve the
// list from its own watch cache instead of doing a quorum read through to
// etcd. The cost of that is that the returned objects may be very slightly
// stale — typically milliseconds, bounded by how far the API server's cache
// lags the write.
//
// That is safe HERE, and this is the whole justification: every check fed by
// this snapshot already requires a sustained observation window before it
// reports anything. A Deployment must have been Available=False for
// sustainedThreshold (10 minutes by default); a PVC must have been Pending
// that long; a condition with no authoritative transition time must have been
// seen by this detector on an earlier pass entirely (sustainedLongEnough's
// firstObserved path). No checker in this file fires on a single observation,
// so no checker in this file can be made wrong by reading state that is a few
// milliseconds behind — the threshold already absorbs orders of magnitude
// more lag than the watch cache can introduce.
//
// The converse is what makes it worth doing: a quorum read of every Pod on a
// large cluster is one of the most expensive things an API server does, and
// the sweep was asking for several of them every five minutes to answer
// questions that tolerate staleness by construction.
//
// Deliberately no Limit/Continue, and that is now a decision rather than an
// absence: the API server IGNORES Limit for a ResourceVersion: "0" read and
// hands back the whole collection, so the two cannot be stacked and every
// read has to choose. PROJECT.md P17(c) is that choice, and it lives in
// sweep_pagination.go — this value is the side of it a correctly-sized agent
// takes for every read, every pass. A read the memory guard cannot afford
// whole is issued under a different ListOptions entirely
// (sweepReadPlan.listOptions), which drops the ResourceVersion precisely
// because keeping it would make the Limit silently ineffective.
var sweepListOptions = metav1.ListOptions{ResourceVersion: "0"}

// sweepListOptionsFor is sweepListOptions with a label selector added, for
// the handful of sweep reads that filter server-side. Same
// ResourceVersion: "0" reasoning — see above; a selector changes which
// objects come back, not how consistent they need to be.
func sweepListOptionsFor(labelSelector string) metav1.ListOptions {
	opts := sweepListOptions
	opts.LabelSelector = labelSelector
	return opts
}

// cachedList is one kind's list-once slot: the result of the first successful
// or failed List for that kind this pass, handed back unchanged to every
// later caller.
//
// Not mutex-protected, and deliberately so: a snapshot belongs to exactly one
// runOneSweep call, whose checkers run sequentially on that one goroutine.
// Anything that starts running the checkers concurrently must give this a
// lock (or a singleflight) at the same time.
type cachedList[T any] struct {
	loaded bool
	list   T
	err    error
}

func (c *cachedList[T]) get(ctx context.Context, kind string, load func(context.Context, metav1.ListOptions) (T, error)) (T, error) {
	if !c.loaded {
		// PROJECT.md P18/P17(c): the last chance to decide this read before
		// it is paid for. Every cluster-wide typed list in a pass goes
		// through here, which is what makes both the budget check and the
		// watch-cache-or-pagination choice structural rather than something
		// each of the 14 accessors below has to remember.
		//
		// A refusal is deliberately NOT cached, unlike a List error: the
		// caching above exists so a pass never pays for a failed API call
		// twice, and a refusal costs no API call at all. Leaving it uncached
		// means a later checker whose kind is cheap can still get its list if
		// a GC freed room in the meantime, instead of being denied by a
		// decision taken about a different kind earlier in the pass.
		plan, err := sweepMemoryGuardInstance.planTypedList(kind)
		if err != nil {
			var zero T
			return zero, err
		}
		c.list, c.err = listPaged(ctx, plan, load)
		c.loaded = true
		// PROJECT.md P17(c): what this kind actually returned, fed back so
		// the NEXT pass can price it before issuing it. Without this the
		// guard can only ever price Pods, and thirteen of these fourteen
		// kinds are admitted blind however large they grow.
		if c.err == nil {
			if items, err := itemsField(c.list); err == nil {
				sweepMemoryGuardInstance.recordKindCount(kind, items.Len())
			}
		}
	}
	return c.list, c.err
}

// sweepSnapshot is one sweep pass's shared view. Checkers receive this in
// place of the raw clientset, which is what makes the list-once property
// structural: a checker cannot accidentally re-list a kind the pass has
// already read, because it has no client to do it with.
//
// clientset stays reachable for the handful of reads that genuinely are NOT
// per-pass cluster-wide lists — resolveRelatedWorkloadForPVC/
// resolveRelatedWorkloadForSelector's per-candidate, namespace-scoped
// lookups and their owner-chain Gets, which happen only for objects already
// flagged and so cost nothing on a healthy cluster.
type sweepSnapshot struct {
	clientset kubernetes.Interface

	deploymentList        cachedList[*appsv1.DeploymentList]
	replicaSetList        cachedList[*appsv1.ReplicaSetList]
	statefulSetList       cachedList[*appsv1.StatefulSetList]
	daemonSetList         cachedList[*appsv1.DaemonSetList]
	podList               cachedList[*corev1.PodList]
	pvcList               cachedList[*corev1.PersistentVolumeClaimList]
	serviceList           cachedList[*corev1.ServiceList]
	nodeList              cachedList[*corev1.NodeList]
	jobList               cachedList[*batchv1.JobList]
	hpaList               cachedList[*autoscalingv2.HorizontalPodAutoscalerList]
	endpointSliceList     cachedList[*discoveryv1.EndpointSliceList]
	ingressList           cachedList[*networkingv1.IngressList]
	validatingWebhookList cachedList[*admissionregistrationv1.ValidatingWebhookConfigurationList]
	mutatingWebhookList   cachedList[*admissionregistrationv1.MutatingWebhookConfigurationList]
}

// newSweepSnapshot returns an empty snapshot bound to clientset. Nothing is
// read until a checker asks for it.
func newSweepSnapshot(clientset kubernetes.Interface) *sweepSnapshot {
	return &sweepSnapshot{clientset: clientset}
}

// The accessors below are all the same shape: list this kind cluster-wide
// once per pass, hand the same result to everyone who asks. Callers must
// treat what comes back as read-only — it is shared with every other checker
// in the pass, so mutating an item (or sorting Items in place) would corrupt
// a later checker's view rather than just its own.

func (s *sweepSnapshot) deployments(ctx context.Context) (*appsv1.DeploymentList, error) {
	return s.deploymentList.get(ctx, "Deployment", func(ctx context.Context, opts metav1.ListOptions) (*appsv1.DeploymentList, error) {
		return s.clientset.AppsV1().Deployments(metav1.NamespaceAll).List(ctx, opts)
	})
}

func (s *sweepSnapshot) replicaSets(ctx context.Context) (*appsv1.ReplicaSetList, error) {
	return s.replicaSetList.get(ctx, "ReplicaSet", func(ctx context.Context, opts metav1.ListOptions) (*appsv1.ReplicaSetList, error) {
		return s.clientset.AppsV1().ReplicaSets(metav1.NamespaceAll).List(ctx, opts)
	})
}

func (s *sweepSnapshot) statefulSets(ctx context.Context) (*appsv1.StatefulSetList, error) {
	return s.statefulSetList.get(ctx, "StatefulSet", func(ctx context.Context, opts metav1.ListOptions) (*appsv1.StatefulSetList, error) {
		return s.clientset.AppsV1().StatefulSets(metav1.NamespaceAll).List(ctx, opts)
	})
}

func (s *sweepSnapshot) daemonSets(ctx context.Context) (*appsv1.DaemonSetList, error) {
	return s.daemonSetList.get(ctx, "DaemonSet", func(ctx context.Context, opts metav1.ListOptions) (*appsv1.DaemonSetList, error) {
		return s.clientset.AppsV1().DaemonSets(metav1.NamespaceAll).List(ctx, opts)
	})
}

func (s *sweepSnapshot) pods(ctx context.Context) (*corev1.PodList, error) {
	return s.podList.get(ctx, "Pod", func(ctx context.Context, opts metav1.ListOptions) (*corev1.PodList, error) {
		return s.clientset.CoreV1().Pods(metav1.NamespaceAll).List(ctx, opts)
	})
}

func (s *sweepSnapshot) persistentVolumeClaims(ctx context.Context) (*corev1.PersistentVolumeClaimList, error) {
	return s.pvcList.get(ctx, "PersistentVolumeClaim", func(ctx context.Context, opts metav1.ListOptions) (*corev1.PersistentVolumeClaimList, error) {
		return s.clientset.CoreV1().PersistentVolumeClaims(metav1.NamespaceAll).List(ctx, opts)
	})
}

func (s *sweepSnapshot) services(ctx context.Context) (*corev1.ServiceList, error) {
	return s.serviceList.get(ctx, "Service", func(ctx context.Context, opts metav1.ListOptions) (*corev1.ServiceList, error) {
		return s.clientset.CoreV1().Services(metav1.NamespaceAll).List(ctx, opts)
	})
}

func (s *sweepSnapshot) nodes(ctx context.Context) (*corev1.NodeList, error) {
	return s.nodeList.get(ctx, "Node", func(ctx context.Context, opts metav1.ListOptions) (*corev1.NodeList, error) {
		return s.clientset.CoreV1().Nodes().List(ctx, opts)
	})
}

func (s *sweepSnapshot) jobs(ctx context.Context) (*batchv1.JobList, error) {
	return s.jobList.get(ctx, "Job", func(ctx context.Context, opts metav1.ListOptions) (*batchv1.JobList, error) {
		return s.clientset.BatchV1().Jobs(metav1.NamespaceAll).List(ctx, opts)
	})
}

func (s *sweepSnapshot) horizontalPodAutoscalers(ctx context.Context) (*autoscalingv2.HorizontalPodAutoscalerList, error) {
	return s.hpaList.get(ctx, "HorizontalPodAutoscaler", func(ctx context.Context, opts metav1.ListOptions) (*autoscalingv2.HorizontalPodAutoscalerList, error) {
		return s.clientset.AutoscalingV2().HorizontalPodAutoscalers(metav1.NamespaceAll).List(ctx, opts)
	})
}

func (s *sweepSnapshot) endpointSlices(ctx context.Context) (*discoveryv1.EndpointSliceList, error) {
	return s.endpointSliceList.get(ctx, "EndpointSlice", func(ctx context.Context, opts metav1.ListOptions) (*discoveryv1.EndpointSliceList, error) {
		return s.clientset.DiscoveryV1().EndpointSlices(metav1.NamespaceAll).List(ctx, opts)
	})
}

func (s *sweepSnapshot) ingresses(ctx context.Context) (*networkingv1.IngressList, error) {
	return s.ingressList.get(ctx, "Ingress", func(ctx context.Context, opts metav1.ListOptions) (*networkingv1.IngressList, error) {
		return s.clientset.NetworkingV1().Ingresses(metav1.NamespaceAll).List(ctx, opts)
	})
}

func (s *sweepSnapshot) validatingWebhookConfigurations(ctx context.Context) (*admissionregistrationv1.ValidatingWebhookConfigurationList, error) {
	return s.validatingWebhookList.get(ctx, "ValidatingWebhookConfiguration", func(ctx context.Context, opts metav1.ListOptions) (*admissionregistrationv1.ValidatingWebhookConfigurationList, error) {
		return s.clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, opts)
	})
}

func (s *sweepSnapshot) mutatingWebhookConfigurations(ctx context.Context) (*admissionregistrationv1.MutatingWebhookConfigurationList, error) {
	return s.mutatingWebhookList.get(ctx, "MutatingWebhookConfiguration", func(ctx context.Context, opts metav1.ListOptions) (*admissionregistrationv1.MutatingWebhookConfigurationList, error) {
		return s.clientset.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, opts)
	})
}
