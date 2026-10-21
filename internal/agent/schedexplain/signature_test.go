package schedexplain

import (
	"regexp"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// testPod is a pending pod in shop with one container requesting cpu.
func testPod(name, cpu string) *corev1.Pod {
	app := corev1.Container{Name: "app"}
	app.Resources.Requests = corev1.ResourceList{corev1.ResourceCPU: resource.MustParse(cpu)}
	p := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{app}}}
	p.Namespace, p.Name, p.UID = "shop", name, types.UID(name)
	p.Status.Phase = corev1.PodPending
	return p
}

// requiredNodeAffinity is required node affinity of the given terms, each a
// list of requirements; with no terms it is a required affinity that has none.
func requiredNodeAffinity(terms ...[]corev1.NodeSelectorRequirement) *corev1.Affinity {
	sel := &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{}}
	for _, reqs := range terms {
		sel.NodeSelectorTerms = append(sel.NodeSelectorTerms, corev1.NodeSelectorTerm{MatchExpressions: reqs})
	}
	return &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{RequiredDuringSchedulingIgnoredDuringExecution: sel}}
}

func withOwner(p *corev1.Pod, kind, name string) *corev1.Pod {
	yes := true
	p.OwnerReferences = append(p.OwnerReferences[:0], metav1.OwnerReference{APIVersion: "apps/v1", Kind: kind, Name: name, Controller: &yes})
	return p
}

// Order carries no meaning in a nodeSelector, a toleration list, the ORed
// affinity terms or a requirement's values, and must not change the answer.
func TestSignatureIgnoresOrder(t *testing.T) {
	gpu := corev1.NodeSelectorRequirement{Key: "accelerator", Operator: corev1.NodeSelectorOpIn, Values: []string{"a100", "h100"}}
	notSpot := corev1.NodeSelectorRequirement{Key: "capacity-type", Operator: corev1.NodeSelectorOpNotIn, Values: []string{"spot"}}
	one := withOwner(testPod("trainer-0", "4"), "StatefulSet", "trainer")
	one.Spec.NodeSelector = map[string]string{"pool": "ml", "kubernetes.io/os": "linux"}
	one.Spec.Tolerations = []corev1.Toleration{
		{Key: "nvidia.com/gpu", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
		{Key: "team", Operator: corev1.TolerationOpEqual, Value: "research", Effect: corev1.TaintEffectNoExecute},
	}
	one.Spec.Affinity = requiredNodeAffinity([]corev1.NodeSelectorRequirement{gpu, notSpot}, []corev1.NodeSelectorRequirement{notSpot})

	two := one.DeepCopy()
	two.Name, two.UID = "trainer-1", "trainer-1"
	two.Spec.Tolerations[0], two.Spec.Tolerations[1] = two.Spec.Tolerations[1], two.Spec.Tolerations[0]
	reordered := gpu
	reordered.Values = []string{"h100", "a100", "h100"}
	two.Spec.Affinity = requiredNodeAffinity([]corev1.NodeSelectorRequirement{notSpot}, []corev1.NodeSelectorRequirement{notSpot, reordered})

	if Signature(one) != Signature(two) || GroupFingerprint(one) != GroupFingerprint(two) {
		t.Fatal("the same constraints in another order hashed differently")
	}
	if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(Signature(one)) {
		t.Fatalf("signature = %q", Signature(one))
	}
}

func TestSignatureTolerationOperatorDefaultCoalesces(t *testing.T) {
	implicit := testPod("implicit-equal", "500m")
	implicit.Spec.Tolerations = []corev1.Toleration{{Key: "dedicated", Value: "batch", Effect: corev1.TaintEffectNoSchedule}}
	explicit := testPod("explicit-equal", "500m")
	explicit.Spec.Tolerations = []corev1.Toleration{{Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "batch", Effect: corev1.TaintEffectNoSchedule}}
	if Signature(implicit) != Signature(explicit) {
		t.Fatal("an omitted toleration operator is Equal; signatures must match")
	}
}

func TestSignatureDistinguishesConstraints(t *testing.T) {
	base := testPod("a", "500m")
	cases := map[string]func(p *corev1.Pod){
		"node selector":       func(p *corev1.Pod) { p.Spec.NodeSelector = map[string]string{"pool": "gpu"} },
		"empty required term": func(p *corev1.Pod) { p.Spec.Affinity = requiredNodeAffinity() },
		"toleration": func(p *corev1.Pod) {
			p.Spec.Tolerations = []corev1.Toleration{{Key: "gpu", Operator: corev1.TolerationOpExists}}
		},
		"pvc": func(p *corev1.Pod) {
			p.Spec.Volumes = []corev1.Volume{{Name: "d", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data-0"}}}}
		},
		"host port": func(p *corev1.Pod) {
			p.Spec.Containers[0].Ports = []corev1.ContainerPort{{HostPort: 8080, Protocol: corev1.ProtocolTCP}}
		},
		"scheduler name": func(p *corev1.Pod) { p.Spec.SchedulerName = "volcano" },
		"topology spread": func(p *corev1.Pod) {
			p.Spec.TopologySpreadConstraints = []corev1.TopologySpreadConstraint{{MaxSkew: 1, TopologyKey: "zone", WhenUnsatisfiable: corev1.DoNotSchedule}}
		},
		"extended resource": func(p *corev1.Pod) {
			p.Spec.Containers[0].Resources.Requests["nvidia.com/gpu"] = resource.MustParse("1")
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := base.DeepCopy()
			mutate(p)
			if Signature(p) == Signature(base) {
				t.Fatalf("%s did not change the signature", name)
			}
		})
	}
	// ScheduleAnyway spread is a preference, not a placement constraint.
	soft := base.DeepCopy()
	soft.Spec.TopologySpreadConstraints = []corev1.TopologySpreadConstraint{{MaxSkew: 1, TopologyKey: "zone", WhenUnsatisfiable: corev1.ScheduleAnyway}}
	if Signature(soft) != Signature(base) {
		t.Fatal("ScheduleAnyway spread should not change the signature")
	}
}

// The group fingerprint separates what the signature alone does not:
// namespace, owner and per-pod requests.
func TestGroupFingerprintSeparatesOwnerNamespaceAndRequests(t *testing.T) {
	a := withOwner(testPod("a", "500m"), "ReplicaSet", "web-1")
	sameOwner := withOwner(testPod("b", "500m"), "ReplicaSet", "web-1")
	otherOwner := withOwner(testPod("c", "500m"), "ReplicaSet", "api-1")
	otherRequests := withOwner(testPod("d", "1"), "ReplicaSet", "web-1")
	otherNS := withOwner(testPod("e", "500m"), "ReplicaSet", "web-1")
	otherNS.Namespace = "other"

	if GroupFingerprint(a) != GroupFingerprint(sameOwner) {
		t.Fatal("replicas of one owner should share a fingerprint")
	}
	for name, p := range map[string]*corev1.Pod{"owner": otherOwner, "requests": otherRequests, "namespace": otherNS} {
		if GroupFingerprint(a) == GroupFingerprint(p) {
			t.Errorf("different %s should not share a fingerprint", name)
		}
	}
	// A caller-resolved owner folds successive ReplicaSets together.
	rs2 := withOwner(testPod("f", "500m"), "ReplicaSet", "web-2")
	deploy := OwnerRef{Group: "apps", Kind: "Deployment", Name: "web"}
	if GroupFingerprintFor(a, deploy) != GroupFingerprintFor(rs2, deploy) {
		t.Fatal("resolved owner should fold ReplicaSets of one Deployment")
	}
	// An equal quantity written differently is the same request.
	milli := withOwner(testPod("g", "1000m"), "ReplicaSet", "web-1")
	if GroupFingerprint(milli) != GroupFingerprint(otherRequests) {
		t.Fatal("1000m and 1 cpu should fingerprint the same")
	}
}

func TestPodOwner(t *testing.T) {
	if got := PodOwner(withOwner(testPod("a", "1"), "ReplicaSet", "web-1")); got != (OwnerRef{Group: "apps", Kind: "ReplicaSet", Name: "web-1"}) {
		t.Fatalf("owner = %+v", got)
	}
	if got := PodOwner(testPod("bare", "1")); got != (OwnerRef{Kind: "Pod", Name: "bare"}) {
		t.Fatalf("bare pod owner = %+v", got)
	}
}

func TestSimilarPending(t *testing.T) {
	a := withOwner(testPod("a", "500m"), "ReplicaSet", "web-1")
	b := withOwner(testPod("b", "500m"), "ReplicaSet", "web-1")
	bound := withOwner(testPod("c", "500m"), "ReplicaSet", "web-1")
	bound.Spec.NodeName = "n1"
	failed := withOwner(testPod("d", "500m"), "ReplicaSet", "web-1")
	failed.Status.Phase = corev1.PodFailed
	deleting := withOwner(testPod("e", "500m"), "ReplicaSet", "web-1")
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	other := withOwner(testPod("f", "500m"), "ReplicaSet", "api-1")

	if got := SimilarPending(a, []*corev1.Pod{a, b, bound, failed, deleting, other, nil}); got != 2 {
		t.Fatalf("SimilarPending = %d, want 2", got)
	}
}
