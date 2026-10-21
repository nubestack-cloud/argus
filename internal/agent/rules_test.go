package agent

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	k8sruntime "k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"argus/internal/tunnel"
)

// newRulesFake builds a dynamic fake client that knows the List Kind for
// every GVR this file's rules exercise — the same
// NewSimpleDynamicClientWithCustomListKinds pattern syncfailure_test.go's
// newArgoFake already uses, generalized to the four kinds BACKLOG.md E9's
// representative rules read.
func newRulesFake(objs ...runtime.Object) *dynfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	gvrToKind := map[k8sruntime.GroupVersionResource]string{
		{Group: "policy", Version: "v1", Resource: "poddisruptionbudgets"}:                "PodDisruptionBudgetList",
		{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}:          "NetworkPolicyList",
		{Group: "", Version: "v1", Resource: "resourcequotas"}:                            "ResourceQuotaList",
		{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}:               "CertificateList",
		{Group: "", Version: "v1", Resource: "persistentvolumes"}:                         "PersistentVolumeList",
		{Group: "", Version: "v1", Resource: "persistentvolumeclaims"}:                    "PersistentVolumeClaimList",
		{Group: "", Version: "v1", Resource: "pods"}:                                      "PodList",
		{Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers"}:       "HorizontalPodAutoscalerList",
		{Group: "kustomize.toolkit.fluxcd.io", Version: "v1", Resource: "kustomizations"}: "KustomizationList",
		{Group: "helm.toolkit.fluxcd.io", Version: "v2", Resource: "helmreleases"}:        "HelmReleaseList",
		// dynamicSweepCheckers (syncfailure.go's checkArgoSyncFailed) also runs
		// on every dyn != nil sweep, alongside rules — this fake stands in for
		// runOneSweep's real dyn client in the integration tests below, so it
		// must know this GVR too, or that pre-existing checker panics the fake
		// (rather than the real API server's clean "no such resource").
		argoApplicationsGVR: "ApplicationList",
		// Third batch (BACKLOG.md E9, third pass) — the five additional GVRs
		// its rules exercise.
		{Group: "", Version: "v1", Resource: "namespaces"}:                              "NamespaceList",
		{Group: "velero.io", Version: "v1", Resource: "backups"}:                        "BackupList",
		{Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "gitrepositories"}: "GitRepositoryList",
		{Group: "apps", Version: "v1", Resource: "deployments"}:                         "DeploymentList",
		{Group: "apps", Version: "v1", Resource: "daemonsets"}:                          "DaemonSetList",
		{Group: "apps", Version: "v1", Resource: "statefulsets"}:                        "StatefulSetList",
		// Fourth batch (BACKLOG.md E9, fourth pass) — the two additional GVRs
		// its rules exercise that no prior pass needed (Node was already
		// listable via supportedGVKs, but no rule ever evaluated one until
		// node-cordoned-sustained; Restore is a wholly new GVK this pass).
		{Group: "", Version: "v1", Resource: "nodes"}:             "NodeList",
		{Group: "velero.io", Version: "v1", Resource: "restores"}: "RestoreList",
		// BACKLOG.md E10 — job-missing-active-deadline-seconds's GVR. Job was
		// already in supportedGVKs (checkFailedJobs, sweep_detector.go) but
		// no rule had evaluated one via the dynamic client before this one.
		{Group: "batch", Version: "v1", Resource: "jobs"}: "JobList",
	}
	return dynfake.NewSimpleDynamicClientWithCustomListKinds(scheme, addScheduleListKinds(gvrToKind), objs...)
}

func pdbObj(namespace, name string, disruptionsAllowed int64) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "policy/v1",
		"kind":       "PodDisruptionBudget",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name},
		"status":     map[string]any{"disruptionsAllowed": disruptionsAllowed},
	}}
}

func networkPolicyObj(namespace, name string, matchLabels map[string]any) *unstructured.Unstructured {
	spec := map[string]any{}
	if matchLabels != nil {
		spec["podSelector"] = map[string]any{"matchLabels": matchLabels}
	} else {
		spec["podSelector"] = map[string]any{}
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name},
		"spec":       spec,
	}}
}

func resourceQuotaObj(namespace, name string, hard, used map[string]any) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "ResourceQuota",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name},
		"status":     map[string]any{"hard": hard, "used": used},
	}}
}

// resourceQuotaObjNoUsedYet is a freshly-created ResourceQuota: status.hard
// is set (the quota itself exists) but status.used has not been populated
// by the resource-quota controller yet — a genuinely different real-world
// state from "used is present and every key is 0", which is exactly why
// resourcequota-at-hard-limit's condition does NOT (and, per validateRule,
// cannot) set AbsentFieldMeansZero: a missing key in a quantity map is not
// safely the same claim as a zero value for that key (BUGS.md 129's own
// warning against widening this indiscriminately). See
// evaluateCondition's PerMapKey branch, which is untouched by the
// AbsentFieldMeansZero fix.
func resourceQuotaObjNoUsedYet(namespace, name string, hard map[string]any) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "ResourceQuota",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name},
		"status":     map[string]any{"hard": hard},
	}}
}

func certificateObj(namespace, name, notAfter string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cert-manager.io/v1",
		"kind":       "Certificate",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name},
		"status":     map[string]any{"notAfter": notAfter},
	}}
}

func pdbSelectorObj(namespace, name string, matchLabels map[string]any) *unstructured.Unstructured {
	spec := map[string]any{}
	if matchLabels != nil {
		spec["selector"] = map[string]any{"matchLabels": matchLabels}
	} else {
		spec["selector"] = map[string]any{}
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "policy/v1",
		"kind":       "PodDisruptionBudget",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name},
		"spec":       spec,
	}}
}

func persistentVolumeObj(name, phase string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "PersistentVolume",
		"metadata":   map[string]any{"name": name, "uid": "uid-" + name},
		"status":     map[string]any{"phase": phase},
	}}
}

// persistentVolumeTerminatingObj and the pod/PVC equivalents below build an
// object with metadata.creationTimestamp always set, and
// metadata.deletionTimestamp set only when deletionTimestamp is non-empty —
// the exact two fields persistentvolume-stuck-terminating (and its Pod/PVC
// siblings) compares.
func persistentVolumeTerminatingObj(name, creationTimestamp, deletionTimestamp string) *unstructured.Unstructured {
	meta := map[string]any{"name": name, "uid": "uid-" + name, "creationTimestamp": creationTimestamp}
	if deletionTimestamp != "" {
		meta["deletionTimestamp"] = deletionTimestamp
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "PersistentVolume",
		"metadata":   meta,
	}}
}

func persistentVolumeClaimTerminatingObj(namespace, name, creationTimestamp, deletionTimestamp string) *unstructured.Unstructured {
	meta := map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name, "creationTimestamp": creationTimestamp}
	if deletionTimestamp != "" {
		meta["deletionTimestamp"] = deletionTimestamp
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "PersistentVolumeClaim",
		"metadata":   meta,
	}}
}

func podTerminatingObj(namespace, name, creationTimestamp, deletionTimestamp string) *unstructured.Unstructured {
	meta := map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name, "creationTimestamp": creationTimestamp}
	if deletionTimestamp != "" {
		meta["deletionTimestamp"] = deletionTimestamp
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   meta,
	}}
}

func hpaObj(namespace, name string, currentReplicas, maxReplicas int64) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "autoscaling/v2",
		"kind":       "HorizontalPodAutoscaler",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name},
		"spec":       map[string]any{"maxReplicas": maxReplicas},
		"status":     map[string]any{"currentReplicas": currentReplicas},
	}}
}

func kustomizationObj(namespace, name string, generation, observedGeneration int64) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "kustomize.toolkit.fluxcd.io/v1",
		"kind":       "Kustomization",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name, "generation": generation},
		"status":     map[string]any{"observedGeneration": observedGeneration},
	}}
}

func helmReleaseObj(namespace, name string, generation, observedGeneration int64) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "helm.toolkit.fluxcd.io/v2",
		"kind":       "HelmRelease",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name, "generation": generation},
		"status":     map[string]any{"observedGeneration": observedGeneration},
	}}
}

// --- third batch (BACKLOG.md E9, third pass) object constructors ---

// namespaceTerminatingObj mirrors persistentVolumeTerminatingObj's shape —
// creationTimestamp always set, deletionTimestamp only when non-empty — for
// the same deletionTimestamp-vs-creationTimestamp comparison, on a
// cluster-scoped Namespace instead.
func namespaceTerminatingObj(name, creationTimestamp, deletionTimestamp string) *unstructured.Unstructured {
	meta := map[string]any{"name": name, "uid": "uid-" + name, "creationTimestamp": creationTimestamp}
	if deletionTimestamp != "" {
		meta["deletionTimestamp"] = deletionTimestamp
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata":   meta,
	}}
}

func veleroBackupObj(namespace, name, phase string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "velero.io/v1",
		"kind":       "Backup",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name},
		"status":     map[string]any{"phase": phase},
	}}
}

func argoApplicationHealthObj(namespace, name, healthStatus string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Application",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name},
		"status":     map[string]any{"health": map[string]any{"status": healthStatus}},
	}}
}

func gitRepositoryObj(namespace, name string, generation, observedGeneration int64) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "source.toolkit.fluxcd.io/v1",
		"kind":       "GitRepository",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name, "generation": generation},
		"status":     map[string]any{"observedGeneration": observedGeneration},
	}}
}

func deploymentPausedObj(namespace, name string, paused bool) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name},
		"spec":       map[string]any{"paused": paused},
	}}
}

// deploymentGenerationObjNoStatusYet is a Deployment the controller has
// never reconciled at all: status.observedGeneration is not merely 0, it
// has never been WRITTEN — a genuinely different real-world claim from
// "observed and confirmed at generation 0", and the regression case for
// BUGS.md 129: deployment-observedgeneration-behind uses the same lt
// comparator as the three rollout-stalled rules this bug fixed, but does
// NOT set AbsentFieldMeansZero (status.observedGeneration is not the
// omitempty-numeric-status shape those three rules are about), so an
// absent field here must still mean "does not match", exactly as before
// this fix.
func deploymentGenerationObjNoStatusYet(namespace, name string, generation int64) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name, "generation": generation},
	}}
}

func deploymentGenerationObj(namespace, name string, generation, observedGeneration int64) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name, "generation": generation},
		"status":     map[string]any{"observedGeneration": observedGeneration},
	}}
}

func daemonSetRolloutObj(namespace, name string, updatedNumberScheduled, desiredNumberScheduled int64) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "DaemonSet",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name},
		"status": map[string]any{
			"updatedNumberScheduled": updatedNumberScheduled,
			"desiredNumberScheduled": desiredNumberScheduled,
		},
	}}
}

// daemonSetRolloutObjFieldOmitted is BUGS.md 129's exact zero-vs-absent
// case: status.updatedNumberScheduled genuinely IS 0 (every pod still on
// the old revision), which is precisely when apps/v1 DaemonSetStatus's own
// `json:",omitempty"` tag makes the real API server omit the key entirely
// — so, unlike daemonSetRolloutObj(ns, name, 0, desired) above (which sets
// the key to a literal 0 and would mask this exact bug), this constructor
// leaves the key out of status altogether, the same shape
// unstructured.NestedFieldNoCopy sees from a real cluster.
func daemonSetRolloutObjFieldOmitted(namespace, name string, desiredNumberScheduled int64) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "DaemonSet",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name},
		"status": map[string]any{
			"desiredNumberScheduled": desiredNumberScheduled,
		},
	}}
}

func statefulSetRolloutObj(namespace, name string, updatedReplicas, specReplicas int64) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "StatefulSet",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name},
		"spec":       map[string]any{"replicas": specReplicas},
		"status":     map[string]any{"updatedReplicas": updatedReplicas},
	}}
}

// statefulSetRolloutObjFieldOmitted is the same BUGS.md 129 shape as
// daemonSetRolloutObjFieldOmitted above, for apps/v1 StatefulSetStatus.
// UpdatedReplicas (also `json:",omitempty"`): status.updatedReplicas is
// genuinely 0, so it is left out of status entirely rather than set to a
// literal 0.
func statefulSetRolloutObjFieldOmitted(namespace, name string, specReplicas int64) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "StatefulSet",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name},
		"spec":       map[string]any{"replicas": specReplicas},
		"status":     map[string]any{},
	}}
}

// statefulSetPartitionObj is statefulset-partition-blocks-rollout's fixture
// (BACKLOG.md item #6, AR1/STS-011) — a partition value with no
// updatedReplicas/status at all, deliberately: this rule's condition never
// reads either, so a fixture that included them (and made it look like the
// same object as statefulSetRolloutObj) would be misleading about what's
// actually under test.
func statefulSetPartitionObj(namespace, name string, partition int64) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "StatefulSet",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name},
		"spec": map[string]any{
			"updateStrategy": map[string]any{
				"rollingUpdate": map[string]any{"partition": partition},
			},
		},
	}}
}

// --- fourth batch (BACKLOG.md E9, fourth pass) object constructors ---

func deploymentReplicasObj(namespace, name string, specReplicas *int64, updatedReplicas int64) *unstructured.Unstructured {
	spec := map[string]any{}
	if specReplicas != nil {
		spec["replicas"] = *specReplicas
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name},
		"spec":       spec,
		"status":     map[string]any{"updatedReplicas": updatedReplicas},
	}}
}

// deploymentReplicasObjFieldOmitted is the same BUGS.md 129 shape as
// daemonSetRolloutObjFieldOmitted/statefulSetRolloutObjFieldOmitted above,
// for apps/v1 DeploymentStatus.UpdatedReplicas (also `json:",omitempty"`):
// status.updatedReplicas is genuinely 0, so status has no key for it at
// all, rather than deploymentReplicasObj's literal-0 shape.
func deploymentReplicasObjFieldOmitted(namespace, name string, specReplicas int64) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name},
		"spec":       map[string]any{"replicas": specReplicas},
		"status":     map[string]any{},
	}}
}

func deploymentScaledObj(namespace, name string, replicas int64) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name},
		"spec":       map[string]any{"replicas": replicas},
	}}
}

func deploymentRevisionHistoryObj(namespace, name string, limit int64) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name},
		"spec":       map[string]any{"revisionHistoryLimit": limit},
	}}
}

func podReasonObj(namespace, name, reason string) *unstructured.Unstructured {
	status := map[string]any{}
	if reason != "" {
		status["reason"] = reason
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name},
		"status":     status,
	}}
}

func nodeUnschedulableObj(name string, unschedulable bool) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Node",
		"metadata":   map[string]any{"name": name, "uid": "uid-" + name},
		"spec":       map[string]any{"unschedulable": unschedulable},
	}}
}

func argoApplicationSyncObj(namespace, name, syncStatus string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Application",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name},
		"status":     map[string]any{"sync": map[string]any{"status": syncStatus}},
	}}
}

func fluxSuspendObj(kind, apiVersion, namespace, name string, suspend bool) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name},
		"spec":       map[string]any{"suspend": suspend},
	}}
}

func veleroRestoreObj(namespace, name, phase string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "velero.io/v1",
		"kind":       "Restore",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name},
		"status":     map[string]any{"phase": phase},
	}}
}

// --- BACKLOG.md E10 object constructors ---

// jobActiveDeadlineObj builds a Job with spec.activeDeadlineSeconds set only
// when hasDeadline is true — job-missing-active-deadline-seconds' fixture
// (notPresent must fire on absence, never on a zero or other explicit
// value).
func jobActiveDeadlineObj(namespace, name string, hasDeadline bool, deadlineSeconds int64) *unstructured.Unstructured {
	spec := map[string]any{}
	if hasDeadline {
		spec["activeDeadlineSeconds"] = deadlineSeconds
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "batch/v1",
		"kind":       "Job",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name},
		"spec":       spec,
	}}
}

// deploymentSelectorObj builds a Deployment with spec.selector set to
// matchLabels — deployment-all-replicas-single-node's primary object; the
// matching Pods are supplied separately to the typed fake clientset, mirroring
// how pdbSelectorObj/networkPolicyObj's own tests already split "the object
// with the selector" from "the Pods it selects".
func deploymentSelectorObj(namespace, name string, matchLabels map[string]any) *unstructured.Unstructured {
	spec := map[string]any{}
	if matchLabels != nil {
		spec["selector"] = map[string]any{"matchLabels": matchLabels}
	} else {
		spec["selector"] = map[string]any{}
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": "uid-" + name},
		"spec":       spec,
	}}
}

// podOnNode builds a typed Pod carrying labels and a bound spec.nodeName —
// deployment-all-replicas-single-node's evaluateAllPodsSameValue reads
// exactly this field off each matched Pod.
func podOnNode(namespace, name string, labels map[string]string, nodeName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: labels},
		Spec:       corev1.PodSpec{NodeName: nodeName},
	}
}

func mustRule(t *testing.T, r Rule) Rule {
	t.Helper()
	if err := validateRule(r); err != nil {
		t.Fatalf("test rule %s is invalid: %v", r.ID, err)
	}
	return r
}

var pdbBlocksAllDisruptionsRule = Rule{
	ID: "pdb-blocks-all-disruptions", GVK: "policy/v1/PodDisruptionBudget",
	Reason: "PodDisruptionBudgetBlocksAllDisruptions", Severity: "medium",
	Message:   "{{.Namespace}}/{{.Name}} disruptionsAllowed={{.Value}}",
	Condition: RuleCondition{Field: "status.disruptionsAllowed", Comparator: "eq", Value: "0"},
}

var networkPolicySelectsNoPodsRule = Rule{
	ID: "networkpolicy-selects-no-pods", GVK: "networking.k8s.io/v1/NetworkPolicy",
	Reason: "NetworkPolicySelectsNoPods", Severity: "medium",
	Message:   "{{.Namespace}}/{{.Name}} selects no pods",
	Condition: RuleCondition{SelectorField: "spec.podSelector", Comparator: comparatorSelectorMatchesNoPods},
}

var resourceQuotaAtHardLimitRule = Rule{
	ID: "resourcequota-at-hard-limit", GVK: "v1/ResourceQuota",
	Reason: "ResourceQuotaAtHardLimit", Severity: "medium",
	Message:   "{{.Namespace}}/{{.Name}} {{.MatchedKey}} used={{.Value}} hard={{.CompareValue}}",
	Condition: RuleCondition{Field: "status.used", CompareField: "status.hard", Comparator: "gte", PerMapKey: true},
}

var certificateExpiryImminentRule = Rule{
	ID: "certificate-expiry-imminent", GVK: "cert-manager.io/v1/Certificate",
	Reason: "CertificateExpiryImminent", Severity: "high",
	Message:   "{{.Namespace}}/{{.Name}} notAfter={{.Value}}",
	Condition: RuleCondition{Field: "status.notAfter", Comparator: comparatorExpiresWithin, Value: "168h"},
}

// --- second batch (BACKLOG.md E9, second pass) ---

var pdbSelectorMatchesNoPodsRule = Rule{
	ID: "pdb-selector-matches-no-pods", GVK: "policy/v1/PodDisruptionBudget",
	Reason: "PodDisruptionBudgetSelectorMatchesNoPods", Severity: "medium",
	Message:   "{{.Namespace}}/{{.Name}} selects no pods",
	Condition: RuleCondition{SelectorField: "spec.selector", Comparator: comparatorSelectorMatchesNoPods},
}

var persistentVolumeReleasedStuckRule = Rule{
	ID: "persistentvolume-released-stuck", GVK: "v1/PersistentVolume",
	Reason: "PersistentVolumeReleasedStuck", Severity: "medium",
	Message:   "{{.Name}} phase={{.Value}}",
	Condition: RuleCondition{Field: "status.phase", Comparator: "eq", Value: "Released"},
}

var persistentVolumeStuckTerminatingRule = Rule{
	ID: "persistentvolume-stuck-terminating", GVK: "v1/PersistentVolume",
	Reason: "PersistentVolumeStuckTerminating", Severity: "medium",
	Message:   "{{.Name}} deletionTimestamp={{.Value}}",
	Condition: RuleCondition{Field: "metadata.deletionTimestamp", CompareField: "metadata.creationTimestamp", Comparator: "ne"},
}

var persistentVolumeClaimStuckTerminatingRule = Rule{
	ID: "persistentvolumeclaim-stuck-terminating", GVK: "v1/PersistentVolumeClaim",
	Reason: "PersistentVolumeClaimStuckTerminating", Severity: "medium",
	Message:   "{{.Namespace}}/{{.Name}} deletionTimestamp={{.Value}}",
	Condition: RuleCondition{Field: "metadata.deletionTimestamp", CompareField: "metadata.creationTimestamp", Comparator: "ne"},
}

var podStuckTerminatingRule = Rule{
	ID: "pod-stuck-terminating", GVK: "v1/Pod",
	Reason: "PodStuckTerminating", Severity: "medium",
	Message:   "{{.Namespace}}/{{.Name}} deletionTimestamp={{.Value}}",
	Condition: RuleCondition{Field: "metadata.deletionTimestamp", CompareField: "metadata.creationTimestamp", Comparator: "ne"},
}

var hpaPeggedAtMaxReplicasRule = Rule{
	ID: "hpa-pegged-at-max-replicas", GVK: "autoscaling/v2/HorizontalPodAutoscaler",
	Reason: "HPAPeggedAtMaxReplicas", Severity: "medium",
	Message:   "{{.Namespace}}/{{.Name}} current={{.Value}} max={{.CompareValue}}",
	Condition: RuleCondition{Field: "status.currentReplicas", CompareField: "spec.maxReplicas", Comparator: "gte"},
}

var fluxKustomizationReconciliationStalledRule = Rule{
	ID: "flux-kustomization-reconciliation-stalled", GVK: "kustomize.toolkit.fluxcd.io/v1/Kustomization",
	Reason: "FluxKustomizationReconciliationStalled", Severity: "medium",
	Message:   "{{.Namespace}}/{{.Name}} observedGeneration={{.Value}} generation={{.CompareValue}}",
	Condition: RuleCondition{Field: "status.observedGeneration", CompareField: "metadata.generation", Comparator: "lt"},
}

var fluxHelmReleaseReconciliationStalledRule = Rule{
	ID: "flux-helmrelease-reconciliation-stalled", GVK: "helm.toolkit.fluxcd.io/v2/HelmRelease",
	Reason: "FluxHelmReleaseReconciliationStalled", Severity: "medium",
	Message:   "{{.Namespace}}/{{.Name}} observedGeneration={{.Value}} generation={{.CompareValue}}",
	Condition: RuleCondition{Field: "status.observedGeneration", CompareField: "metadata.generation", Comparator: "lt"},
}

// --- third batch (BACKLOG.md E9, third pass) ---

var namespaceStuckTerminatingRule = Rule{
	ID: "namespace-stuck-terminating", GVK: "v1/Namespace",
	Reason: "NamespaceStuckTerminating", Severity: "medium",
	Message:   "{{.Name}} deletionTimestamp={{.Value}}",
	Condition: RuleCondition{Field: "metadata.deletionTimestamp", CompareField: "metadata.creationTimestamp", Comparator: "ne"},
}

var veleroBackupPartiallyFailedRule = Rule{
	ID: "velero-backup-partially-failed", GVK: "velero.io/v1/Backup",
	Reason: "VeleroBackupPartiallyFailed", Severity: "high",
	Message:   "{{.Namespace}}/{{.Name}} phase={{.Value}}",
	Condition: RuleCondition{Field: "status.phase", Comparator: "eq", Value: "PartiallyFailed"},
}

var argoApplicationHealthDegradedRule = Rule{
	ID: "argo-application-health-degraded", GVK: "argoproj.io/v1alpha1/Application",
	Reason: "ArgoApplicationHealthDegraded", Severity: "high",
	Message:   "{{.Namespace}}/{{.Name}} health={{.Value}}",
	Condition: RuleCondition{Field: "status.health.status", Comparator: "eq", Value: "Degraded"},
}

var fluxGitRepositoryReconciliationStalledRule = Rule{
	ID: "flux-gitrepository-reconciliation-stalled", GVK: "source.toolkit.fluxcd.io/v1/GitRepository",
	Reason: "FluxGitRepositoryReconciliationStalled", Severity: "medium",
	Message:   "{{.Namespace}}/{{.Name}} observedGeneration={{.Value}} generation={{.CompareValue}}",
	Condition: RuleCondition{Field: "status.observedGeneration", CompareField: "metadata.generation", Comparator: "lt"},
}

var deploymentPausedRule = Rule{
	ID: "deployment-paused", GVK: "apps/v1/Deployment",
	Reason: "DeploymentPaused", Severity: "medium",
	Message:   "{{.Namespace}}/{{.Name}} paused={{.Value}}",
	Condition: RuleCondition{Field: "spec.paused", Comparator: "eq", Value: "true"},
}

var deploymentObservedGenerationBehindRule = Rule{
	ID: "deployment-observedgeneration-behind", GVK: "apps/v1/Deployment",
	Reason: "DeploymentObservedGenerationBehind", Severity: "medium",
	Message:   "{{.Namespace}}/{{.Name}} observedGeneration={{.Value}} generation={{.CompareValue}}",
	Condition: RuleCondition{Field: "status.observedGeneration", CompareField: "metadata.generation", Comparator: "lt"},
}

// AbsentFieldMeansZero: true mirrors default-rules.yaml's own fix for
// BUGS.md 129 — apps/v1 DaemonSetStatus.UpdatedNumberScheduled is a plain
// int32 tagged `json:",omitempty"`, so the API server's own JSON
// serialization omits it entirely once its real value is 0, which is
// otherwise indistinguishable from the field never existing on this object
// at all. See RuleCondition's own doc comment on AbsentFieldMeansZero.
var daemonSetRolloutStalledRule = Rule{
	ID: "daemonset-rollout-stalled", GVK: "apps/v1/DaemonSet",
	Reason: "DaemonSetRolloutStalled", Severity: "medium",
	Message:   "{{.Namespace}}/{{.Name}} updated={{.Value}} desired={{.CompareValue}}",
	Condition: RuleCondition{Field: "status.updatedNumberScheduled", CompareField: "status.desiredNumberScheduled", Comparator: "lt", AbsentFieldMeansZero: true},
}

// AbsentFieldMeansZero: true — same BUGS.md 129 fix as
// daemonSetRolloutStalledRule above: apps/v1 StatefulSetStatus.
// UpdatedReplicas is the identical omitempty-tagged int32 shape.
var statefulSetRolloutStalledRule = Rule{
	ID: "statefulset-rollout-stalled", GVK: "apps/v1/StatefulSet",
	Reason: "StatefulSetRolloutStalled", Severity: "medium",
	Message:   "{{.Namespace}}/{{.Name}} updated={{.Value}} replicas={{.CompareValue}}",
	Condition: RuleCondition{Field: "status.updatedReplicas", CompareField: "spec.replicas", Comparator: "lt", AbsentFieldMeansZero: true},
}

// statefulSetPartitionBlocksRolloutRule mirrors default-rules.yaml's
// statefulset-partition-blocks-rollout (BACKLOG.md item #6, AR1/STS-011).
var statefulSetPartitionBlocksRolloutRule = Rule{
	ID: "statefulset-partition-blocks-rollout", GVK: "apps/v1/StatefulSet",
	Reason: "StatefulSetPartitionBlocksRollout", Severity: "medium",
	Message:   "{{.Namespace}}/{{.Name}} partition={{.Value}}",
	Condition: RuleCondition{Field: "spec.updateStrategy.rollingUpdate.partition", Comparator: "gt", Value: "0"},
}

var persistentVolumeFailedRule = Rule{
	ID: "persistentvolume-failed", GVK: "v1/PersistentVolume",
	Reason: "PersistentVolumeFailed", Severity: "high",
	Message:   "{{.Name}} phase={{.Value}}",
	Condition: RuleCondition{Field: "status.phase", Comparator: "eq", Value: "Failed"},
}

// --- fourth batch (BACKLOG.md E9, fourth pass) ---

// AbsentFieldMeansZero: true — same BUGS.md 129 fix as
// daemonSetRolloutStalledRule/statefulSetRolloutStalledRule above: apps/v1
// DeploymentStatus.UpdatedReplicas is the identical omitempty-tagged int32
// shape.
var deploymentRolloutStalledRule = Rule{
	ID: "deployment-rollout-stalled", GVK: "apps/v1/Deployment",
	Reason: "DeploymentRolloutStalled", Severity: "medium",
	Message:   "{{.Namespace}}/{{.Name}} updated={{.Value}} replicas={{.CompareValue}}",
	Condition: RuleCondition{Field: "status.updatedReplicas", CompareField: "spec.replicas", Comparator: "lt", AbsentFieldMeansZero: true},
}

var deploymentScaledToZeroRule = Rule{
	ID: "deployment-scaled-to-zero", GVK: "apps/v1/Deployment",
	Reason: "DeploymentScaledToZero", Severity: "low",
	Message:   "{{.Namespace}}/{{.Name}} replicas={{.Value}}",
	Condition: RuleCondition{Field: "spec.replicas", Comparator: "eq", Value: "0"},
}

var deploymentRevisionHistoryLimitZeroRule = Rule{
	ID: "deployment-revision-history-limit-zero", GVK: "apps/v1/Deployment",
	Reason: "DeploymentRevisionHistoryLimitZero", Severity: "low",
	Message:   "{{.Namespace}}/{{.Name}} revisionHistoryLimit={{.Value}}",
	Condition: RuleCondition{Field: "spec.revisionHistoryLimit", Comparator: "eq", Value: "0"},
}

var podEvictedNotCleanedUpRule = Rule{
	ID: "pod-evicted-not-cleaned-up", GVK: "v1/Pod",
	Reason: "PodEvictedNotCleanedUp", Severity: "low",
	Message:   "{{.Namespace}}/{{.Name}} reason={{.Value}}",
	Condition: RuleCondition{Field: "status.reason", Comparator: "eq", Value: "Evicted"},
}

var nodeCordonedSustainedRule = Rule{
	ID: "node-cordoned-sustained", GVK: "v1/Node",
	Reason: "NodeCordonedSustained", Severity: "medium",
	Message:   "{{.Name}} unschedulable={{.Value}}",
	Condition: RuleCondition{Field: "spec.unschedulable", Comparator: "eq", Value: "true"},
}

var argoApplicationOutOfSyncRule = Rule{
	ID: "argo-application-out-of-sync", GVK: "argoproj.io/v1alpha1/Application",
	Reason: "ArgoApplicationOutOfSync", Severity: "medium",
	Message:   "{{.Namespace}}/{{.Name}} sync={{.Value}}",
	Condition: RuleCondition{Field: "status.sync.status", Comparator: "eq", Value: "OutOfSync"},
}

var fluxKustomizationSuspendedRule = Rule{
	ID: "flux-kustomization-suspended", GVK: "kustomize.toolkit.fluxcd.io/v1/Kustomization",
	Reason: "FluxKustomizationSuspended", Severity: "medium",
	Message:   "{{.Namespace}}/{{.Name}} suspend={{.Value}}",
	Condition: RuleCondition{Field: "spec.suspend", Comparator: "eq", Value: "true"},
}

var fluxHelmReleaseSuspendedRule = Rule{
	ID: "flux-helmrelease-suspended", GVK: "helm.toolkit.fluxcd.io/v2/HelmRelease",
	Reason: "FluxHelmReleaseSuspended", Severity: "medium",
	Message:   "{{.Namespace}}/{{.Name}} suspend={{.Value}}",
	Condition: RuleCondition{Field: "spec.suspend", Comparator: "eq", Value: "true"},
}

var fluxGitRepositorySuspendedRule = Rule{
	ID: "flux-gitrepository-suspended", GVK: "source.toolkit.fluxcd.io/v1/GitRepository",
	Reason: "FluxGitRepositorySuspended", Severity: "medium",
	Message:   "{{.Namespace}}/{{.Name}} suspend={{.Value}}",
	Condition: RuleCondition{Field: "spec.suspend", Comparator: "eq", Value: "true"},
}

var veleroBackupFailedRule = Rule{
	ID: "velero-backup-failed", GVK: "velero.io/v1/Backup",
	Reason: "VeleroBackupFailed", Severity: "high",
	Message:   "{{.Namespace}}/{{.Name}} phase={{.Value}}",
	Condition: RuleCondition{Field: "status.phase", Comparator: "eq", Value: "Failed"},
}

var veleroRestorePartiallyFailedRule = Rule{
	ID: "velero-restore-partially-failed", GVK: "velero.io/v1/Restore",
	Reason: "VeleroRestorePartiallyFailed", Severity: "high",
	Message:   "{{.Namespace}}/{{.Name}} phase={{.Value}}",
	Condition: RuleCondition{Field: "status.phase", Comparator: "eq", Value: "PartiallyFailed"},
}

var veleroRestoreFailedRule = Rule{
	ID: "velero-restore-failed", GVK: "velero.io/v1/Restore",
	Reason: "VeleroRestoreFailed", Severity: "high",
	Message:   "{{.Namespace}}/{{.Name}} phase={{.Value}}",
	Condition: RuleCondition{Field: "status.phase", Comparator: "eq", Value: "Failed"},
}

// --- BACKLOG.md E10 ---

var jobMissingActiveDeadlineSecondsRule = Rule{
	ID: "job-missing-active-deadline-seconds", GVK: "batch/v1/Job",
	Reason: "JobMissingActiveDeadlineSeconds", Severity: "low",
	Message:   "{{.Namespace}}/{{.Name}} has no activeDeadlineSeconds",
	Condition: RuleCondition{Field: "spec.activeDeadlineSeconds", Comparator: comparatorNotPresent},
}

var deploymentAllReplicasSingleNodeRule = Rule{
	ID: "deployment-all-replicas-single-node", GVK: "apps/v1/Deployment",
	Reason: "DeploymentAllReplicasOnSingleNode", Severity: "medium",
	Message:   "{{.Namespace}}/{{.Name}} {{.Count}} replicas on node {{.Value}}",
	Condition: RuleCondition{SelectorField: "spec.selector", AggregateField: "spec.nodeName", Comparator: comparatorAllPodsSameValue},
}

// --- pdb-blocks-all-disruptions ---

func TestEvaluateRule_PDBBlocksAllDisruptions_Fires(t *testing.T) {
	rule := mustRule(t, pdbBlocksAllDisruptionsRule)
	dyn := newRulesFake(pdbObj("checkout", "checkout-pdb", 0))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
	if out[0].Reason != "PodDisruptionBudgetBlocksAllDisruptions" || out[0].Namespace != "checkout" || out[0].Name != "checkout-pdb" {
		t.Errorf("unexpected candidate: %+v", out[0])
	}
}

func TestEvaluateRule_PDBAllowsDisruptions_DoesNotFire(t *testing.T) {
	rule := mustRule(t, pdbBlocksAllDisruptionsRule)
	dyn := newRulesFake(pdbObj("checkout", "checkout-pdb", 2))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a PDB with disruptionsAllowed=2 must not fire, got %+v", out)
	}
}

// --- networkpolicy-selects-no-pods ---

func TestEvaluateRule_NetworkPolicySelectsNoPods_Fires(t *testing.T) {
	rule := mustRule(t, networkPolicySelectsNoPodsRule)
	dyn := newRulesFake(networkPolicyObj("web", "np-typo", map[string]any{"app": "does-not-exist"}))
	clientset := k8sfake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "other-app", Labels: map[string]string{"app": "something-else"}},
	})
	out, err := evaluateRule(context.Background(), dyn, clientset, rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_NetworkPolicySelectsSomePods_DoesNotFire(t *testing.T) {
	rule := mustRule(t, networkPolicySelectsNoPodsRule)
	dyn := newRulesFake(networkPolicyObj("web", "np-ok", map[string]any{"app": "checkout"}))
	clientset := k8sfake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "checkout-1", Labels: map[string]string{"app": "checkout"}},
	})
	out, err := evaluateRule(context.Background(), dyn, clientset, rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a NetworkPolicy matching a live pod must not fire, got %+v", out)
	}
}

func TestEvaluateRule_NetworkPolicyEmptySelector_SkippedNotFlagged(t *testing.T) {
	rule := mustRule(t, networkPolicySelectsNoPodsRule)
	// No matchLabels at all — selects every pod in the namespace, a common
	// deliberate "apply to everything" policy, not a misconfiguration.
	dyn := newRulesFake(networkPolicyObj("web", "np-all", nil))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("an empty (select-everything) podSelector must never fire, got %+v", out)
	}
}

// --- resourcequota-at-hard-limit ---

func TestEvaluateRule_ResourceQuotaAtHardLimit_Fires(t *testing.T) {
	rule := mustRule(t, resourceQuotaAtHardLimitRule)
	dyn := newRulesFake(resourceQuotaObj("team-a", "compute-quota",
		map[string]any{"cpu": "4", "memory": "2Gi"},
		map[string]any{"cpu": "4", "memory": "1Gi"}, // cpu used == hard
	))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
	if out[0].Message == "" {
		t.Error("message must not be empty")
	}
}

func TestEvaluateRule_ResourceQuotaUnderLimit_DoesNotFire(t *testing.T) {
	rule := mustRule(t, resourceQuotaAtHardLimitRule)
	dyn := newRulesFake(resourceQuotaObj("team-a", "compute-quota",
		map[string]any{"cpu": "4", "memory": "2Gi"},
		map[string]any{"cpu": "500m", "memory": "1Gi"},
	))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a quota nowhere near its hard limit must not fire, got %+v", out)
	}
}

func TestEvaluateRule_ResourceQuotaQuantityAware(t *testing.T) {
	// "1000m" (used) vs "1" (hard) are the SAME quantity — a string
	// comparison would wrongly call them unequal (and, depending on
	// comparator, wrongly decide "not yet at the limit").
	rule := mustRule(t, resourceQuotaAtHardLimitRule)
	dyn := newRulesFake(resourceQuotaObj("team-a", "compute-quota",
		map[string]any{"cpu": "1"},
		map[string]any{"cpu": "1000m"},
	))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("1000m used against a 1 hard limit is AT the limit (quantity-equal), got %d candidates", len(out))
	}
}

// TestEvaluateRule_ResourceQuotaNoUsedFieldYet_DoesNotFire is BUGS.md 129's
// own regression guard: this codebase's own comment on
// resourcequota-at-hard-limit already claimed "a ResourceQuota with no
// status.used yet (freshly created) is exactly this case" for "not found →
// never a match", and this proves that claim is still true after the
// AbsentFieldMeansZero fix — this rule does not (and, per validateRule,
// cannot) opt in, so a genuinely-absent status.used must still mean "does
// not match", not "every key is 0".
func TestEvaluateRule_ResourceQuotaNoUsedFieldYet_DoesNotFire(t *testing.T) {
	rule := mustRule(t, resourceQuotaAtHardLimitRule)
	dyn := newRulesFake(resourceQuotaObjNoUsedYet("team-a", "compute-quota", map[string]any{"cpu": "4"}))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a freshly-created ResourceQuota with no status.used yet must not fire, got %+v", out)
	}
}

// --- certificate-expiry-imminent ---

func TestEvaluateRule_CertificateExpiryImminent_Fires(t *testing.T) {
	rule := mustRule(t, certificateExpiryImminentRule)
	now := time.Now()
	dyn := newRulesFake(certificateObj("tls", "api-cert", now.Add(2*time.Hour).Format(time.RFC3339)))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, now, sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
	if out[0].Severity != "high" {
		t.Errorf("Severity = %q, want %q", out[0].Severity, "high")
	}
}

func TestEvaluateRule_CertificateAlreadyExpired_StillFires(t *testing.T) {
	rule := mustRule(t, certificateExpiryImminentRule)
	now := time.Now()
	dyn := newRulesFake(certificateObj("tls", "api-cert", now.Add(-time.Hour).Format(time.RFC3339)))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, now, sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("an already-expired certificate is certainly within any warning window, got %+v", out)
	}
}

func TestEvaluateRule_CertificateFarFromExpiry_DoesNotFire(t *testing.T) {
	rule := mustRule(t, certificateExpiryImminentRule)
	now := time.Now()
	dyn := newRulesFake(certificateObj("tls", "api-cert", now.Add(90*24*time.Hour).Format(time.RFC3339)))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, now, sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a certificate 90 days from expiry must not fire against a 7-day window, got %+v", out)
	}
}

// --- pdb-selector-matches-no-pods ---

func TestEvaluateRule_PDBSelectorMatchesNoPods_Fires(t *testing.T) {
	rule := mustRule(t, pdbSelectorMatchesNoPodsRule)
	dyn := newRulesFake(pdbSelectorObj("checkout", "checkout-pdb", map[string]any{"app": "does-not-exist"}))
	clientset := k8sfake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "checkout", Name: "other-app", Labels: map[string]string{"app": "something-else"}},
	})
	out, err := evaluateRule(context.Background(), dyn, clientset, rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
	if out[0].Reason != "PodDisruptionBudgetSelectorMatchesNoPods" {
		t.Errorf("unexpected candidate: %+v", out[0])
	}
}

func TestEvaluateRule_PDBSelectorMatchesSomePods_DoesNotFire(t *testing.T) {
	rule := mustRule(t, pdbSelectorMatchesNoPodsRule)
	dyn := newRulesFake(pdbSelectorObj("checkout", "checkout-pdb", map[string]any{"app": "checkout"}))
	clientset := k8sfake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "checkout", Name: "checkout-1", Labels: map[string]string{"app": "checkout"}},
	})
	out, err := evaluateRule(context.Background(), dyn, clientset, rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a PDB whose selector matches a live pod must not fire, got %+v", out)
	}
}

// --- persistentvolume-released-stuck ---

func TestEvaluateRule_PersistentVolumeReleasedStuck_Fires(t *testing.T) {
	rule := mustRule(t, persistentVolumeReleasedStuckRule)
	dyn := newRulesFake(persistentVolumeObj("pv-checkout-data", "Released"))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_PersistentVolumeBound_DoesNotFire(t *testing.T) {
	rule := mustRule(t, persistentVolumeReleasedStuckRule)
	dyn := newRulesFake(persistentVolumeObj("pv-checkout-data", "Bound"))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a Bound PersistentVolume must not fire, got %+v", out)
	}
}

// --- persistentvolume-stuck-terminating / persistentvolumeclaim-stuck-terminating / pod-stuck-terminating ---

func TestEvaluateRule_PersistentVolumeStuckTerminating_Fires(t *testing.T) {
	rule := mustRule(t, persistentVolumeStuckTerminatingRule)
	dyn := newRulesFake(persistentVolumeTerminatingObj("pv-checkout-data", "2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z"))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_PersistentVolumeNotDeleted_DoesNotFire(t *testing.T) {
	rule := mustRule(t, persistentVolumeStuckTerminatingRule)
	dyn := newRulesFake(persistentVolumeTerminatingObj("pv-checkout-data", "2026-01-01T00:00:00Z", ""))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a PersistentVolume with no deletionTimestamp must not fire, got %+v", out)
	}
}

func TestEvaluateRule_PersistentVolumeClaimStuckTerminating_Fires(t *testing.T) {
	rule := mustRule(t, persistentVolumeClaimStuckTerminatingRule)
	dyn := newRulesFake(persistentVolumeClaimTerminatingObj("checkout", "data", "2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z"))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_PersistentVolumeClaimNotDeleted_DoesNotFire(t *testing.T) {
	rule := mustRule(t, persistentVolumeClaimStuckTerminatingRule)
	dyn := newRulesFake(persistentVolumeClaimTerminatingObj("checkout", "data", "2026-01-01T00:00:00Z", ""))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a PersistentVolumeClaim with no deletionTimestamp must not fire, got %+v", out)
	}
}

func TestEvaluateRule_PodStuckTerminating_Fires(t *testing.T) {
	rule := mustRule(t, podStuckTerminatingRule)
	dyn := newRulesFake(podTerminatingObj("checkout", "checkout-7f8", "2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z"))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_PodNotDeleted_DoesNotFire(t *testing.T) {
	rule := mustRule(t, podStuckTerminatingRule)
	dyn := newRulesFake(podTerminatingObj("checkout", "checkout-7f8", "2026-01-01T00:00:00Z", ""))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a Pod with no deletionTimestamp must not fire, got %+v", out)
	}
}

// --- hpa-pegged-at-max-replicas ---

func TestEvaluateRule_HPAPeggedAtMaxReplicas_Fires(t *testing.T) {
	rule := mustRule(t, hpaPeggedAtMaxReplicasRule)
	dyn := newRulesFake(hpaObj("checkout", "checkout-hpa", 10, 10))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_HPABelowMaxReplicas_DoesNotFire(t *testing.T) {
	rule := mustRule(t, hpaPeggedAtMaxReplicasRule)
	dyn := newRulesFake(hpaObj("checkout", "checkout-hpa", 4, 10))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("an HPA well below its maxReplicas ceiling must not fire, got %+v", out)
	}
}

// --- flux-kustomization-reconciliation-stalled / flux-helmrelease-reconciliation-stalled ---

func TestEvaluateRule_FluxKustomizationReconciliationStalled_Fires(t *testing.T) {
	rule := mustRule(t, fluxKustomizationReconciliationStalledRule)
	dyn := newRulesFake(kustomizationObj("platform", "core-infra", 5, 4))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_FluxKustomizationReconciled_DoesNotFire(t *testing.T) {
	rule := mustRule(t, fluxKustomizationReconciliationStalledRule)
	dyn := newRulesFake(kustomizationObj("platform", "core-infra", 5, 5))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a Kustomization whose observedGeneration matches its generation must not fire, got %+v", out)
	}
}

func TestEvaluateRule_FluxHelmReleaseReconciliationStalled_Fires(t *testing.T) {
	rule := mustRule(t, fluxHelmReleaseReconciliationStalledRule)
	dyn := newRulesFake(helmReleaseObj("platform", "core-infra", 3, 2))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_FluxHelmReleaseReconciled_DoesNotFire(t *testing.T) {
	rule := mustRule(t, fluxHelmReleaseReconciliationStalledRule)
	dyn := newRulesFake(helmReleaseObj("platform", "core-infra", 3, 3))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a HelmRelease whose observedGeneration matches its generation must not fire, got %+v", out)
	}
}

// --- third batch (BACKLOG.md E9, third pass) fire/no-fire pairs ---

// --- namespace-stuck-terminating ---

func TestEvaluateRule_NamespaceStuckTerminating_Fires(t *testing.T) {
	rule := mustRule(t, namespaceStuckTerminatingRule)
	dyn := newRulesFake(namespaceTerminatingObj("checkout", "2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z"))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_NamespaceNotDeleted_DoesNotFire(t *testing.T) {
	rule := mustRule(t, namespaceStuckTerminatingRule)
	dyn := newRulesFake(namespaceTerminatingObj("checkout", "2026-01-01T00:00:00Z", ""))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a Namespace with no deletionTimestamp must not fire, got %+v", out)
	}
}

// --- velero-backup-partially-failed ---

func TestEvaluateRule_VeleroBackupPartiallyFailed_Fires(t *testing.T) {
	rule := mustRule(t, veleroBackupPartiallyFailedRule)
	dyn := newRulesFake(veleroBackupObj("velero", "nightly-20260826", "PartiallyFailed"))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_VeleroBackupCompleted_DoesNotFire(t *testing.T) {
	rule := mustRule(t, veleroBackupPartiallyFailedRule)
	dyn := newRulesFake(veleroBackupObj("velero", "nightly-20260826", "Completed"))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a Completed backup must not fire, got %+v", out)
	}
}

// --- argo-application-health-degraded ---

func TestEvaluateRule_ArgoApplicationHealthDegraded_Fires(t *testing.T) {
	rule := mustRule(t, argoApplicationHealthDegradedRule)
	dyn := newRulesFake(argoApplicationHealthObj("platform", "checkout", "Degraded"))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_ArgoApplicationHealthy_DoesNotFire(t *testing.T) {
	rule := mustRule(t, argoApplicationHealthDegradedRule)
	dyn := newRulesFake(argoApplicationHealthObj("platform", "checkout", "Healthy"))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a Healthy Application must not fire, got %+v", out)
	}
}

// --- flux-gitrepository-reconciliation-stalled ---

func TestEvaluateRule_FluxGitRepositoryReconciliationStalled_Fires(t *testing.T) {
	rule := mustRule(t, fluxGitRepositoryReconciliationStalledRule)
	dyn := newRulesFake(gitRepositoryObj("platform", "core-infra", 5, 4))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_FluxGitRepositoryReconciled_DoesNotFire(t *testing.T) {
	rule := mustRule(t, fluxGitRepositoryReconciliationStalledRule)
	dyn := newRulesFake(gitRepositoryObj("platform", "core-infra", 5, 5))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a GitRepository whose observedGeneration matches its generation must not fire, got %+v", out)
	}
}

// --- deployment-paused ---

func TestEvaluateRule_DeploymentPaused_Fires(t *testing.T) {
	rule := mustRule(t, deploymentPausedRule)
	dyn := newRulesFake(deploymentPausedObj("checkout", "checkout", true))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_DeploymentNotPaused_DoesNotFire(t *testing.T) {
	rule := mustRule(t, deploymentPausedRule)
	dyn := newRulesFake(deploymentPausedObj("checkout", "checkout", false))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a Deployment with spec.paused=false must not fire, got %+v", out)
	}
}

// --- deployment-observedgeneration-behind ---

func TestEvaluateRule_DeploymentObservedGenerationBehind_Fires(t *testing.T) {
	rule := mustRule(t, deploymentObservedGenerationBehindRule)
	dyn := newRulesFake(deploymentGenerationObj("checkout", "checkout", 5, 4))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_DeploymentObservedGenerationCurrent_DoesNotFire(t *testing.T) {
	rule := mustRule(t, deploymentObservedGenerationBehindRule)
	dyn := newRulesFake(deploymentGenerationObj("checkout", "checkout", 5, 5))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a Deployment whose observedGeneration matches its generation must not fire, got %+v", out)
	}
}

// TestEvaluateRule_DeploymentObservedGenerationFieldNeverWritten_DoesNotFire
// is BUGS.md 129's regression guard, using a DIFFERENT lt-comparator rule
// that never opted into AbsentFieldMeansZero: see
// deploymentGenerationObjNoStatusYet's own doc comment for why this is a
// genuinely-absent, non-numeric-zero-ambiguous case, unlike the three
// rollout-stalled rules this bug actually fixed.
func TestEvaluateRule_DeploymentObservedGenerationFieldNeverWritten_DoesNotFire(t *testing.T) {
	rule := mustRule(t, deploymentObservedGenerationBehindRule)
	dyn := newRulesFake(deploymentGenerationObjNoStatusYet("checkout", "checkout", 5))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a Deployment whose status.observedGeneration was never written must not fire (this rule did not opt into AbsentFieldMeansZero), got %+v", out)
	}
}

// --- daemonset-rollout-stalled ---

func TestEvaluateRule_DaemonSetRolloutStalled_Fires(t *testing.T) {
	rule := mustRule(t, daemonSetRolloutStalledRule)
	dyn := newRulesFake(daemonSetRolloutObj("kube-system", "node-agent", 3, 5))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_DaemonSetRolloutComplete_DoesNotFire(t *testing.T) {
	rule := mustRule(t, daemonSetRolloutStalledRule)
	dyn := newRulesFake(daemonSetRolloutObj("kube-system", "node-agent", 5, 5))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a DaemonSet with updatedNumberScheduled==desiredNumberScheduled must not fire, got %+v", out)
	}
}

// TestEvaluateRule_DaemonSetRolloutStalled_FiresWhenUpdatedFieldOmitted is
// BUGS.md 129's own live-confirmed case: an OnDelete DaemonSet whose pods
// are all still on the OLD revision has status.updatedNumberScheduled
// genuinely 0, which apps/v1's own `json:",omitempty"` tag makes the real
// API server omit from the object entirely — see
// daemonSetRolloutObjFieldOmitted's own doc comment. Before
// AbsentFieldMeansZero existed, evaluateCondition's "field not found →
// never a match" tolerance ate this comparison before lt ever ran, so this
// rule silently never fired on the single most literal "rollout never
// started" case. This is the exact zero-vs-absent ambiguity the fix
// resolves.
func TestEvaluateRule_DaemonSetRolloutStalled_FiresWhenUpdatedFieldOmitted(t *testing.T) {
	rule := mustRule(t, daemonSetRolloutStalledRule)
	dyn := newRulesFake(daemonSetRolloutObjFieldOmitted("kube-system", "node-agent", 5))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("a DaemonSet with status.updatedNumberScheduled omitted (genuinely 0) below desiredNumberScheduled=5 must fire, got %d candidates: %+v", len(out), out)
	}
}

// --- statefulset-rollout-stalled ---

func TestEvaluateRule_StatefulSetRolloutStalled_Fires(t *testing.T) {
	rule := mustRule(t, statefulSetRolloutStalledRule)
	dyn := newRulesFake(statefulSetRolloutObj("data", "cache", 2, 5))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_StatefulSetRolloutComplete_DoesNotFire(t *testing.T) {
	rule := mustRule(t, statefulSetRolloutStalledRule)
	dyn := newRulesFake(statefulSetRolloutObj("data", "cache", 5, 5))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a StatefulSet with updatedReplicas==spec.replicas must not fire, got %+v", out)
	}
}

// TestEvaluateRule_StatefulSetRolloutStalled_FiresWhenUpdatedFieldOmitted is
// BUGS.md 129's StatefulSet case, structurally identical to the DaemonSet
// one above: apps/v1 StatefulSetStatus.UpdatedReplicas is also
// `json:",omitempty"`, so a genuinely-0 updatedReplicas (an ordered rollout
// stuck before its first ordinal updates) is indistinguishable from the
// field never existing on this object at all.
func TestEvaluateRule_StatefulSetRolloutStalled_FiresWhenUpdatedFieldOmitted(t *testing.T) {
	rule := mustRule(t, statefulSetRolloutStalledRule)
	dyn := newRulesFake(statefulSetRolloutObjFieldOmitted("data", "cache", 5))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("a StatefulSet with status.updatedReplicas omitted (genuinely 0) below spec.replicas=5 must fire, got %d candidates: %+v", len(out), out)
	}
}

// --- statefulset-partition-blocks-rollout (BACKLOG.md item #6, AR1) ---

func TestEvaluateRule_StatefulSetPartitionBlocksRollout_Fires(t *testing.T) {
	rule := mustRule(t, statefulSetPartitionBlocksRolloutRule)
	dyn := newRulesFake(statefulSetPartitionObj("data", "cache", 2))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
	if out[0].Reason != "StatefulSetPartitionBlocksRollout" {
		t.Errorf("unexpected reason: %+v", out[0])
	}
}

func TestEvaluateRule_StatefulSetPartitionZero_DoesNotFire(t *testing.T) {
	rule := mustRule(t, statefulSetPartitionBlocksRolloutRule)
	// partition: 0 is the default/healthy steady state — every ordinal is
	// eligible to update, nothing is frozen.
	dyn := newRulesFake(statefulSetPartitionObj("data", "cache", 0))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a StatefulSet with partition=0 must not fire, got %+v", out)
	}
}

// --- persistentvolume-failed ---

func TestEvaluateRule_PersistentVolumeFailed_Fires(t *testing.T) {
	rule := mustRule(t, persistentVolumeFailedRule)
	dyn := newRulesFake(persistentVolumeObj("pv-checkout-data", "Failed"))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_PersistentVolumeBoundNotFailed_DoesNotFire(t *testing.T) {
	rule := mustRule(t, persistentVolumeFailedRule)
	dyn := newRulesFake(persistentVolumeObj("pv-checkout-data", "Bound"))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a Bound PersistentVolume must not fire against the Failed literal, got %+v", out)
	}
}

// --- fourth batch (BACKLOG.md E9, fourth pass) ---

func TestEvaluateRule_DeploymentRolloutStalled_Fires(t *testing.T) {
	rule := mustRule(t, deploymentRolloutStalledRule)
	three := int64(3)
	dyn := newRulesFake(deploymentReplicasObj("checkout", "web", &three, 1))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_DeploymentRolloutComplete_DoesNotFire(t *testing.T) {
	rule := mustRule(t, deploymentRolloutStalledRule)
	three := int64(3)
	dyn := newRulesFake(deploymentReplicasObj("checkout", "web", &three, 3))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a Deployment fully updated must not fire, got %+v", out)
	}
}

// TestEvaluateRule_DeploymentRolloutStalled_FiresWhenUpdatedFieldOmitted is
// BUGS.md 129's Deployment case, structurally identical to the DaemonSet
// and StatefulSet ones above: apps/v1 DeploymentStatus.UpdatedReplicas is
// also `json:",omitempty"`, so a genuinely-0 updatedReplicas (a rollout
// stuck before its first new pod comes up) is indistinguishable from the
// field never existing on this object at all.
func TestEvaluateRule_DeploymentRolloutStalled_FiresWhenUpdatedFieldOmitted(t *testing.T) {
	rule := mustRule(t, deploymentRolloutStalledRule)
	dyn := newRulesFake(deploymentReplicasObjFieldOmitted("checkout", "web", 3))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("a Deployment with status.updatedReplicas omitted (genuinely 0) below spec.replicas=3 must fire, got %d candidates: %+v", len(out), out)
	}
}

func TestEvaluateRule_DeploymentScaledToZero_Fires(t *testing.T) {
	rule := mustRule(t, deploymentScaledToZeroRule)
	dyn := newRulesFake(deploymentScaledObj("checkout", "web", 0))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_DeploymentNotScaledToZero_DoesNotFire(t *testing.T) {
	rule := mustRule(t, deploymentScaledToZeroRule)
	dyn := newRulesFake(deploymentScaledObj("checkout", "web", 3))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a Deployment with replicas=3 must not fire against the ==0 literal, got %+v", out)
	}
}

func TestEvaluateRule_DeploymentRevisionHistoryLimitZero_Fires(t *testing.T) {
	rule := mustRule(t, deploymentRevisionHistoryLimitZeroRule)
	dyn := newRulesFake(deploymentRevisionHistoryObj("checkout", "web", 0))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_DeploymentRevisionHistoryLimitDefault_DoesNotFire(t *testing.T) {
	rule := mustRule(t, deploymentRevisionHistoryLimitZeroRule)
	dyn := newRulesFake(deploymentRevisionHistoryObj("checkout", "web", 10))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a Deployment with revisionHistoryLimit=10 must not fire against the ==0 literal, got %+v", out)
	}
}

func TestEvaluateRule_PodEvictedNotCleanedUp_Fires(t *testing.T) {
	rule := mustRule(t, podEvictedNotCleanedUpRule)
	dyn := newRulesFake(podReasonObj("checkout", "web-abc123", "Evicted"))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_PodNotEvicted_DoesNotFire(t *testing.T) {
	rule := mustRule(t, podEvictedNotCleanedUpRule)
	dyn := newRulesFake(podReasonObj("checkout", "web-abc123", ""))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a Pod with no status.reason must not fire, got %+v", out)
	}
}

func TestEvaluateRule_NodeCordonedSustained_Fires(t *testing.T) {
	rule := mustRule(t, nodeCordonedSustainedRule)
	dyn := newRulesFake(nodeUnschedulableObj("node-1", true))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_NodeSchedulable_DoesNotFire(t *testing.T) {
	rule := mustRule(t, nodeCordonedSustainedRule)
	dyn := newRulesFake(nodeUnschedulableObj("node-1", false))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a schedulable Node must not fire, got %+v", out)
	}
}

func TestEvaluateRule_ArgoApplicationOutOfSync_Fires(t *testing.T) {
	rule := mustRule(t, argoApplicationOutOfSyncRule)
	dyn := newRulesFake(argoApplicationSyncObj("checkout", "web", "OutOfSync"))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_ArgoApplicationSynced_DoesNotFire(t *testing.T) {
	rule := mustRule(t, argoApplicationOutOfSyncRule)
	dyn := newRulesFake(argoApplicationSyncObj("checkout", "web", "Synced"))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a Synced Application must not fire, got %+v", out)
	}
}

func TestEvaluateRule_FluxKustomizationSuspended_Fires(t *testing.T) {
	rule := mustRule(t, fluxKustomizationSuspendedRule)
	dyn := newRulesFake(fluxSuspendObj("Kustomization", "kustomize.toolkit.fluxcd.io/v1", "checkout", "web", true))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_FluxKustomizationNotSuspended_DoesNotFire(t *testing.T) {
	rule := mustRule(t, fluxKustomizationSuspendedRule)
	dyn := newRulesFake(fluxSuspendObj("Kustomization", "kustomize.toolkit.fluxcd.io/v1", "checkout", "web", false))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a non-suspended Kustomization must not fire, got %+v", out)
	}
}

func TestEvaluateRule_FluxHelmReleaseSuspended_Fires(t *testing.T) {
	rule := mustRule(t, fluxHelmReleaseSuspendedRule)
	dyn := newRulesFake(fluxSuspendObj("HelmRelease", "helm.toolkit.fluxcd.io/v2", "checkout", "web", true))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_FluxHelmReleaseNotSuspended_DoesNotFire(t *testing.T) {
	rule := mustRule(t, fluxHelmReleaseSuspendedRule)
	dyn := newRulesFake(fluxSuspendObj("HelmRelease", "helm.toolkit.fluxcd.io/v2", "checkout", "web", false))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a non-suspended HelmRelease must not fire, got %+v", out)
	}
}

func TestEvaluateRule_FluxGitRepositorySuspended_Fires(t *testing.T) {
	rule := mustRule(t, fluxGitRepositorySuspendedRule)
	dyn := newRulesFake(fluxSuspendObj("GitRepository", "source.toolkit.fluxcd.io/v1", "checkout", "web", true))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_FluxGitRepositoryNotSuspended_DoesNotFire(t *testing.T) {
	rule := mustRule(t, fluxGitRepositorySuspendedRule)
	dyn := newRulesFake(fluxSuspendObj("GitRepository", "source.toolkit.fluxcd.io/v1", "checkout", "web", false))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a non-suspended GitRepository must not fire, got %+v", out)
	}
}

func TestEvaluateRule_VeleroBackupFailed_Fires(t *testing.T) {
	rule := mustRule(t, veleroBackupFailedRule)
	dyn := newRulesFake(veleroBackupObj("velero", "nightly-20260826", "Failed"))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_VeleroBackupCompleted_DoesNotFireFailed(t *testing.T) {
	rule := mustRule(t, veleroBackupFailedRule)
	dyn := newRulesFake(veleroBackupObj("velero", "nightly-20260826", "Completed"))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a Completed Backup must not fire against the Failed literal, got %+v", out)
	}
}

func TestEvaluateRule_VeleroRestorePartiallyFailed_Fires(t *testing.T) {
	rule := mustRule(t, veleroRestorePartiallyFailedRule)
	dyn := newRulesFake(veleroRestoreObj("velero", "restore-20260826", "PartiallyFailed"))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_VeleroRestoreCompleted_DoesNotFirePartiallyFailed(t *testing.T) {
	rule := mustRule(t, veleroRestorePartiallyFailedRule)
	dyn := newRulesFake(veleroRestoreObj("velero", "restore-20260826", "Completed"))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a Completed Restore must not fire against the PartiallyFailed literal, got %+v", out)
	}
}

func TestEvaluateRule_VeleroRestoreFailed_Fires(t *testing.T) {
	rule := mustRule(t, veleroRestoreFailedRule)
	dyn := newRulesFake(veleroRestoreObj("velero", "restore-20260826", "Failed"))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
}

func TestEvaluateRule_VeleroRestoreCompleted_DoesNotFireFailed(t *testing.T) {
	rule := mustRule(t, veleroRestoreFailedRule)
	dyn := newRulesFake(veleroRestoreObj("velero", "restore-20260826", "Completed"))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a Completed Restore must not fire against the Failed literal, got %+v", out)
	}
}

// TestEvaluateRule_NoMatchingCRD_ReturnsNoErrorNoCandidates pins the same
// tolerance checkArgoSyncFailed already has for "the CRD isn't installed on
// this cluster" (a common case for a CRD-backed rule, e.g. no cert-manager):
// a List against a GVR the API server has no mapping for surfaces to client
// code as a meta.NoResourceMatchError, which evaluateRule must swallow as
// "nothing to do" rather than an error. Simulated with a reactor rather than
// an unregistered fake client, since the fake dynamic client panics (a
// test-setup coding error, not a runtime condition) on a List for a GVR it
// was never told about at all.
func TestEvaluateRule_NoMatchingCRD_ReturnsNoErrorNoCandidates(t *testing.T) {
	rule := mustRule(t, certificateExpiryImminentRule)
	dyn := newRulesFake()
	dyn.PrependReactor("list", "certificates", func(action k8stesting.Action) (bool, runtime.Object, error) {
		gvr := action.GetResource()
		return true, nil, &meta.NoResourceMatchError{PartialResource: gvr}
	})
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("a cluster with no cert-manager CRD installed must not be reported as an error: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("got %d candidates from a cluster with no matching CRD, want 0", len(out))
	}
}

// --- runOneSweep integration: sustained-duration + cooldown discipline ---

// TestRunOneSweep_RuleRespectsSustainedThreshold drives a rule through the
// REAL sweep loop (runOneSweep, the same function runSweepDetector's ticker
// calls) rather than evaluateRule directly, to prove a rule-based candidate
// gets the exact same firstObserved/sustainedLongEnough gate every
// hand-written checker gets: not sustained long enough yet -> nothing sent;
// sustained past the threshold -> sent exactly once.
func TestRunOneSweep_RuleRespectsSustainedThreshold(t *testing.T) {
	rule := mustRule(t, pdbBlocksAllDisruptionsRule)
	dyn := newRulesFake(pdbObj("checkout", "checkout-pdb", 0))
	clientset := k8sfake.NewSimpleClientset()

	findingCh := make(chan tunnel.Finding, 4)
	lastSent := map[string]time.Time{}
	firstObserved := map[string]time.Time{}

	// First sweep: newly observed, must not report yet.
	runOneSweep(context.Background(), clientset, dyn, findingCh, lastSent, firstObserved, defaultFindingResendCooldown, defaultSweepSustainedThreshold, defaultTestCheckerTimeout, []Rule{rule})
	if len(findingCh) != 0 {
		t.Fatalf("a condition observed for the first time must not report yet; got %d findings", len(findingCh))
	}
	if len(firstObserved) != 1 {
		t.Fatalf("first sweep should record exactly one observation, got %d", len(firstObserved))
	}

	// Still not sustained long enough (a few seconds later, real time).
	runOneSweep(context.Background(), clientset, dyn, findingCh, lastSent, firstObserved, defaultFindingResendCooldown, defaultSweepSustainedThreshold, defaultTestCheckerTimeout, []Rule{rule})
	if len(findingCh) != 0 {
		t.Fatalf("a condition sustained only a few seconds must not report yet; got %d findings", len(findingCh))
	}

	// Backdate the observation past the threshold — simulating the condition
	// persisting across real sweeps — and sweep again.
	for fp := range firstObserved {
		firstObserved[fp] = time.Now().Add(-defaultSweepSustainedThreshold - time.Minute)
	}
	runOneSweep(context.Background(), clientset, dyn, findingCh, lastSent, firstObserved, defaultFindingResendCooldown, defaultSweepSustainedThreshold, defaultTestCheckerTimeout, []Rule{rule})
	if len(findingCh) != 1 {
		t.Fatalf("a rule condition sustained past the threshold must report exactly once; got %d findings", len(findingCh))
	}
	f := <-findingCh
	if f.Reason != "PodDisruptionBudgetBlocksAllDisruptions" || f.GVK != "policy/v1/PodDisruptionBudget" {
		t.Errorf("unexpected finding: %+v", f)
	}

	// Immediately sweeping again must NOT resend within the cooldown window.
	runOneSweep(context.Background(), clientset, dyn, findingCh, lastSent, firstObserved, defaultFindingResendCooldown, defaultSweepSustainedThreshold, defaultTestCheckerTimeout, []Rule{rule})
	if len(findingCh) != 0 {
		t.Fatalf("a rule finding must respect the resend cooldown; got %d findings on the very next sweep", len(findingCh))
	}
}

// TestRunOneSweep_RuleClearingConditionNeverFires proves the inverse of the
// sustained-threshold test above: a condition that clears BEFORE the
// threshold is crossed must never be reported at all, not reported late.
func TestRunOneSweep_RuleClearingConditionNeverFires(t *testing.T) {
	rule := mustRule(t, pdbBlocksAllDisruptionsRule)
	clientset := k8sfake.NewSimpleClientset()
	findingCh := make(chan tunnel.Finding, 4)
	lastSent := map[string]time.Time{}
	firstObserved := map[string]time.Time{}

	// First sweep: the PDB is blocked, observed for the first time.
	dyn := newRulesFake(pdbObj("checkout", "checkout-pdb", 0))
	runOneSweep(context.Background(), clientset, dyn, findingCh, lastSent, firstObserved, defaultFindingResendCooldown, defaultSweepSustainedThreshold, defaultTestCheckerTimeout, []Rule{rule})
	if len(firstObserved) != 1 {
		t.Fatalf("expected one observation recorded, got %d", len(firstObserved))
	}

	// Condition clears (disruptionsAllowed goes back above zero) before the
	// sustained threshold is ever reached.
	dyn2 := newRulesFake(pdbObj("checkout", "checkout-pdb", 3))
	runOneSweep(context.Background(), clientset, dyn2, findingCh, lastSent, firstObserved, defaultFindingResendCooldown, defaultSweepSustainedThreshold, defaultTestCheckerTimeout, []Rule{rule})
	if len(findingCh) != 0 {
		t.Fatalf("a condition that cleared before the threshold must never report; got %d findings", len(findingCh))
	}
	if len(firstObserved) != 0 {
		t.Fatalf("a cleared condition's observation must be pruned, so a later recurrence starts its clock over; firstObserved still has %d entries", len(firstObserved))
	}
}

// --- LoadRules / validateRule ---

func TestLoadRules_EmbeddedDefaultSetLoadsAndIsRepresentative(t *testing.T) {
	rules, err := LoadRules("")
	if err != nil {
		t.Fatalf("LoadRules(\"\"): %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("expected a non-empty default rule set")
	}
	seenIDs := map[string]bool{}
	for _, r := range rules {
		if seenIDs[r.ID] {
			t.Errorf("duplicate rule id in the shipped default set: %s", r.ID)
		}
		seenIDs[r.ID] = true
	}
	// BUGS.md 129: the three rules the fix actually applies to must carry
	// absentFieldMeansZero in the SHIPPED yaml, not just in this test
	// file's separately-maintained Go mirror of it (daemonSetRolloutStalledRule
	// et al.) — a mismatch there would mean the fix compiles and is
	// unit-tested but was never actually wired into what the agent ships.
	for _, id := range []string{"daemonset-rollout-stalled", "statefulset-rollout-stalled", "deployment-rollout-stalled"} {
		r, ok := findRule(rules, id)
		if !ok {
			t.Errorf("expected the default rule set to include %q", id)
			continue
		}
		if !r.Condition.AbsentFieldMeansZero {
			t.Errorf("rule %q: expected absentFieldMeansZero: true (BUGS.md 129) in the shipped default-rules.yaml", id)
		}
	}

	for _, want := range []string{
		"pdb-blocks-all-disruptions",
		"networkpolicy-selects-no-pods",
		"resourcequota-at-hard-limit",
		"certificate-expiry-imminent",
		"pdb-selector-matches-no-pods",
		"persistentvolume-released-stuck",
		"persistentvolume-stuck-terminating",
		"persistentvolumeclaim-stuck-terminating",
		"pod-stuck-terminating",
		"hpa-pegged-at-max-replicas",
		"flux-kustomization-reconciliation-stalled",
		"flux-helmrelease-reconciliation-stalled",
		"namespace-stuck-terminating",
		"velero-backup-partially-failed",
		"argo-application-health-degraded",
		"flux-gitrepository-reconciliation-stalled",
		"deployment-paused",
		"deployment-observedgeneration-behind",
		"daemonset-rollout-stalled",
		"statefulset-rollout-stalled",
		"persistentvolume-failed",
		"deployment-rollout-stalled",
		"deployment-scaled-to-zero",
		"deployment-revision-history-limit-zero",
		"pod-evicted-not-cleaned-up",
		"node-cordoned-sustained",
		"argo-application-out-of-sync",
		"flux-kustomization-suspended",
		"flux-helmrelease-suspended",
		"flux-gitrepository-suspended",
		"velero-backup-failed",
		"velero-restore-partially-failed",
		"velero-restore-failed",
		"statefulset-partition-blocks-rollout",
		"job-missing-active-deadline-seconds",
		"deployment-all-replicas-single-node",
	} {
		if !seenIDs[want] {
			t.Errorf("expected the default rule set to include %q", want)
		}
	}
}

func TestValidateRule_RejectsUnknownComparator(t *testing.T) {
	r := Rule{ID: "x", GVK: "v1/ResourceQuota", Reason: "X", Severity: "medium", Message: "m",
		Condition: RuleCondition{Field: "status.used", Comparator: "regex", Value: "y"}}
	if err := validateRule(r); err == nil {
		t.Fatal("expected an error for an unknown comparator")
	}
}

func TestValidateRule_RejectsUnsupportedGVK(t *testing.T) {
	r := Rule{ID: "x", GVK: "made.up/v1/NotAThing", Reason: "X", Severity: "medium", Message: "m",
		Condition: RuleCondition{Field: "status.x", Comparator: "eq", Value: "1"}}
	if err := validateRule(r); err == nil {
		t.Fatal("expected an error for a gvk absent from supportedGVKs — an incident it raised could never be investigated")
	}
}

func TestValidateRule_RejectsBadSeverity(t *testing.T) {
	r := Rule{ID: "x", GVK: "v1/ResourceQuota", Reason: "X", Severity: "urgent", Message: "m",
		Condition: RuleCondition{Field: "status.used", Comparator: "eq", Value: "1"}}
	if err := validateRule(r); err == nil {
		t.Fatal("expected an error for an invalid severity")
	}
}

func TestValidateRule_RejectsMissingMessage(t *testing.T) {
	r := Rule{ID: "x", GVK: "v1/ResourceQuota", Reason: "X", Severity: "medium",
		Condition: RuleCondition{Field: "status.used", Comparator: "eq", Value: "1"}}
	if err := validateRule(r); err == nil {
		t.Fatal("expected an error for a missing message")
	}
}

func TestValidateRule_SelectorModeRejectsExtraFields(t *testing.T) {
	r := Rule{ID: "x", GVK: "networking.k8s.io/v1/NetworkPolicy", Reason: "X", Severity: "medium", Message: "m",
		Condition: RuleCondition{SelectorField: "spec.podSelector", Comparator: comparatorSelectorMatchesNoPods, Value: "1"}}
	if err := validateRule(r); err == nil {
		t.Fatal("expected an error: selectorMatchesNoPods takes only selectorField")
	}
}

func TestValidateRule_ExpiresWithinRejectsNonDuration(t *testing.T) {
	r := Rule{ID: "x", GVK: "cert-manager.io/v1/Certificate", Reason: "X", Severity: "high", Message: "m",
		Condition: RuleCondition{Field: "status.notAfter", Comparator: comparatorExpiresWithin, Value: "soon"}}
	if err := validateRule(r); err == nil {
		t.Fatal("expected an error for a non-duration expiresWithin value")
	}
}

// TestValidateRule_AbsentFieldMeansZeroRejectsPerMapKey is part of BUGS.md
// 129's own scope guard: a ResourceQuota-shaped map's missing key is a
// different claim than a zero value for that key (see
// resourceQuotaObjNoUsedYet's own doc comment), so this flag must never be
// combinable with perMapKey.
func TestValidateRule_AbsentFieldMeansZeroRejectsPerMapKey(t *testing.T) {
	r := Rule{ID: "x", GVK: "v1/ResourceQuota", Reason: "X", Severity: "medium", Message: "m",
		Condition: RuleCondition{Field: "status.used", CompareField: "status.hard", Comparator: "gte", PerMapKey: true, AbsentFieldMeansZero: true}}
	if err := validateRule(r); err == nil {
		t.Fatal("expected an error: absentFieldMeansZero must not be combinable with perMapKey")
	}
}

// TestValidateRule_AbsentFieldMeansZeroRejectsNotPresent is part of the same
// guard: notPresent's entire job is "absence IS the signal" — combining it
// with AbsentFieldMeansZero would silently invert that comparator's own
// healthy case.
func TestValidateRule_AbsentFieldMeansZeroRejectsNotPresent(t *testing.T) {
	r := Rule{ID: "x", GVK: "batch/v1/Job", Reason: "X", Severity: "low", Message: "m",
		Condition: RuleCondition{Field: "spec.activeDeadlineSeconds", Comparator: comparatorNotPresent, AbsentFieldMeansZero: true}}
	if err := validateRule(r); err == nil {
		t.Fatal("expected an error: absentFieldMeansZero must not be combinable with notPresent")
	}
}

// TestValidateRule_AbsentFieldMeansZeroRejectsSelectorMode is the same
// guard for a mode-mismatched comparator entirely (no scalar Field to be
// absent at all in selector mode).
func TestValidateRule_AbsentFieldMeansZeroRejectsSelectorMode(t *testing.T) {
	r := Rule{ID: "x", GVK: "networking.k8s.io/v1/NetworkPolicy", Reason: "X", Severity: "medium", Message: "m",
		Condition: RuleCondition{SelectorField: "spec.podSelector", Comparator: comparatorSelectorMatchesNoPods, AbsentFieldMeansZero: true}}
	if err := validateRule(r); err == nil {
		t.Fatal("expected an error: absentFieldMeansZero must not be combinable with selectorMatchesNoPods")
	}
}

// TestValidateRule_AbsentFieldMeansZeroAcceptedOnPlainFieldCompare is the
// positive case: eq/ne/lt/lte/gt/gte with no perMapKey is exactly the shape
// daemonset-rollout-stalled/statefulset-rollout-stalled/
// deployment-rollout-stalled use.
func TestValidateRule_AbsentFieldMeansZeroAcceptedOnPlainFieldCompare(t *testing.T) {
	r := Rule{ID: "x", GVK: "apps/v1/DaemonSet", Reason: "X", Severity: "medium", Message: "m",
		Condition: RuleCondition{Field: "status.updatedNumberScheduled", CompareField: "status.desiredNumberScheduled", Comparator: "lt", AbsentFieldMeansZero: true}}
	if err := validateRule(r); err != nil {
		t.Fatalf("expected absentFieldMeansZero to be accepted on a plain field-vs-compareField lt condition, got: %v", err)
	}
}

func TestLoadRules_RejectsDuplicateIDs(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/dup.yaml"
	writeFile(t, path, `
rules:
  - id: same-id
    gvk: v1/ResourceQuota
    reason: A
    severity: medium
    message: "m"
    condition: {field: status.used, comparator: eq, value: "1"}
  - id: same-id
    gvk: v1/ResourceQuota
    reason: B
    severity: medium
    message: "m"
    condition: {field: status.used, comparator: eq, value: "1"}
`)
	if _, err := LoadRules(path); err == nil {
		t.Fatal("expected an error for duplicate rule ids")
	}
}

func TestLoadRules_MissingFileReturnsError(t *testing.T) {
	if _, err := LoadRules("/nonexistent/path/rules.yaml"); err == nil {
		t.Fatal("expected an error for a missing rules file")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing test fixture %s: %v", path, err)
	}
}

// --- BACKLOG.md E10: job-missing-active-deadline-seconds (comparatorNotPresent) ---

func TestEvaluateRule_JobMissingActiveDeadlineSeconds_Fires(t *testing.T) {
	rule := mustRule(t, jobMissingActiveDeadlineSecondsRule)
	dyn := newRulesFake(jobActiveDeadlineObj("batch", "nightly-sync", false, 0))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("a Job with no activeDeadlineSeconds must fire, got %d candidates: %+v", len(out), out)
	}
	if out[0].Reason != "JobMissingActiveDeadlineSeconds" || out[0].Namespace != "batch" || out[0].Name != "nightly-sync" {
		t.Errorf("unexpected candidate: %+v", out[0])
	}
}

func TestEvaluateRule_JobHasActiveDeadlineSeconds_DoesNotFire(t *testing.T) {
	rule := mustRule(t, jobMissingActiveDeadlineSecondsRule)
	dyn := newRulesFake(jobActiveDeadlineObj("batch", "nightly-sync", true, 3600))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a Job with activeDeadlineSeconds set must not fire, got %+v", out)
	}
}

// TestEvaluateRule_JobActiveDeadlineSecondsZero_DoesNotFire is the edge case
// notPresent exists specifically to get right: an explicit 0 is PRESENT
// (Kubernetes would reject spec.activeDeadlineSeconds: 0 as invalid in
// practice, but this rule's own job is only to distinguish "set" from
// "absent" — it must not treat a present-but-falsy value as absent the way
// a naive "if not fieldVal" check in a dynamically typed language might).
func TestEvaluateRule_JobActiveDeadlineSecondsZero_DoesNotFire(t *testing.T) {
	rule := mustRule(t, jobMissingActiveDeadlineSecondsRule)
	dyn := newRulesFake(jobActiveDeadlineObj("batch", "nightly-sync", true, 0))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("an explicit activeDeadlineSeconds=0 is PRESENT, not absent — must not fire, got %+v", out)
	}
}

// --- BACKLOG.md E10: deployment-all-replicas-single-node (comparatorAllPodsSameValue) ---

func TestEvaluateRule_DeploymentAllReplicasSingleNode_Fires(t *testing.T) {
	rule := mustRule(t, deploymentAllReplicasSingleNodeRule)
	dyn := newRulesFake(deploymentSelectorObj("checkout", "checkout", map[string]any{"app": "checkout"}))
	clientset := k8sfake.NewSimpleClientset(
		podOnNode("checkout", "checkout-1", map[string]string{"app": "checkout"}, "worker-1"),
		podOnNode("checkout", "checkout-2", map[string]string{"app": "checkout"}, "worker-1"),
		podOnNode("checkout", "checkout-3", map[string]string{"app": "checkout"}, "worker-1"),
	)
	out, err := evaluateRule(context.Background(), dyn, clientset, rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("3 replicas all on worker-1 must fire, got %d candidates: %+v", len(out), out)
	}
	if out[0].Reason != "DeploymentAllReplicasOnSingleNode" {
		t.Errorf("unexpected candidate: %+v", out[0])
	}
	if !strings.Contains(out[0].Message, "worker-1") || !strings.Contains(out[0].Message, "3") {
		t.Errorf("message should name the shared node and the count, got %q", out[0].Message)
	}
}

func TestEvaluateRule_DeploymentReplicasSpreadAcrossNodes_DoesNotFire(t *testing.T) {
	rule := mustRule(t, deploymentAllReplicasSingleNodeRule)
	dyn := newRulesFake(deploymentSelectorObj("checkout", "checkout", map[string]any{"app": "checkout"}))
	clientset := k8sfake.NewSimpleClientset(
		podOnNode("checkout", "checkout-1", map[string]string{"app": "checkout"}, "worker-1"),
		podOnNode("checkout", "checkout-2", map[string]string{"app": "checkout"}, "worker-2"),
		podOnNode("checkout", "checkout-3", map[string]string{"app": "checkout"}, "worker-1"),
	)
	out, err := evaluateRule(context.Background(), dyn, clientset, rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("replicas spread across worker-1 and worker-2 must not fire, got %+v", out)
	}
}

// TestEvaluateRule_DeploymentSingleReplica_DoesNotFire is the cardinality
// guard: one Pod trivially "agrees with itself", which would be worthless
// noise (every single-replica Deployment would fire) and, more importantly,
// meaningless — there is nothing to compare it against.
func TestEvaluateRule_DeploymentSingleReplica_DoesNotFire(t *testing.T) {
	rule := mustRule(t, deploymentAllReplicasSingleNodeRule)
	dyn := newRulesFake(deploymentSelectorObj("checkout", "checkout", map[string]any{"app": "checkout"}))
	clientset := k8sfake.NewSimpleClientset(
		podOnNode("checkout", "checkout-1", map[string]string{"app": "checkout"}, "worker-1"),
	)
	out, err := evaluateRule(context.Background(), dyn, clientset, rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a single replica must not fire — nothing to compare it against, got %+v", out)
	}
}

// TestEvaluateRule_DeploymentUnboundPod_DoesNotFire is the fail-closed edge
// case: a Pod not yet scheduled has no spec.nodeName at all, and this must
// not be silently treated as "matches everyone" or as its own distinct
// group of one.
func TestEvaluateRule_DeploymentUnboundPod_DoesNotFire(t *testing.T) {
	rule := mustRule(t, deploymentAllReplicasSingleNodeRule)
	dyn := newRulesFake(deploymentSelectorObj("checkout", "checkout", map[string]any{"app": "checkout"}))
	clientset := k8sfake.NewSimpleClientset(
		podOnNode("checkout", "checkout-1", map[string]string{"app": "checkout"}, "worker-1"),
		podOnNode("checkout", "checkout-2", map[string]string{"app": "checkout"}, ""), // not yet scheduled
	)
	out, err := evaluateRule(context.Background(), dyn, clientset, rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("an unscheduled pod (empty nodeName) must not fire, got %+v", out)
	}
}

func TestEvaluateRule_DeploymentEmptySelector_SkippedNotFlagged(t *testing.T) {
	rule := mustRule(t, deploymentAllReplicasSingleNodeRule)
	// No matchLabels at all — mirrors networkpolicy-selects-no-pods'
	// TestEvaluateRule_NetworkPolicyEmptySelector_SkippedNotFlagged: an empty
	// selector is a common, deliberate shape (or, for a Deployment
	// specifically, would never validly occur), not something this rule can
	// safely evaluate.
	dyn := newRulesFake(deploymentSelectorObj("checkout", "checkout", nil))
	out, err := evaluateRule(context.Background(), dyn, k8sfake.NewSimpleClientset(), rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("an empty selector must never fire, got %+v", out)
	}
}

// --- BACKLOG.md E10: validateRule coverage for both new comparators ---

func TestValidateRule_NotPresentRequiresField(t *testing.T) {
	r := Rule{ID: "x", GVK: "batch/v1/Job", Reason: "X", Severity: "low", Message: "m",
		Condition: RuleCondition{Comparator: comparatorNotPresent}}
	if err := validateRule(r); err == nil {
		t.Fatal("expected an error: notPresent requires field")
	}
}

func TestValidateRule_NotPresentRejectsExtraFields(t *testing.T) {
	r := Rule{ID: "x", GVK: "batch/v1/Job", Reason: "X", Severity: "low", Message: "m",
		Condition: RuleCondition{Field: "spec.activeDeadlineSeconds", Comparator: comparatorNotPresent, Value: "1"}}
	if err := validateRule(r); err == nil {
		t.Fatal("expected an error: notPresent takes only field")
	}
}

func TestValidateRule_AllPodsSameValueRequiresSelectorAndAggregateField(t *testing.T) {
	for _, c := range []RuleCondition{
		{Comparator: comparatorAllPodsSameValue},
		{SelectorField: "spec.selector", Comparator: comparatorAllPodsSameValue},
		{AggregateField: "spec.nodeName", Comparator: comparatorAllPodsSameValue},
	} {
		r := Rule{ID: "x", GVK: "apps/v1/Deployment", Reason: "X", Severity: "medium", Message: "m", Condition: c}
		if err := validateRule(r); err == nil {
			t.Fatalf("expected an error for incomplete allPodsSameValue condition %+v", c)
		}
	}
}

func TestValidateRule_AllPodsSameValueRejectsExtraFields(t *testing.T) {
	r := Rule{ID: "x", GVK: "apps/v1/Deployment", Reason: "X", Severity: "medium", Message: "m",
		Condition: RuleCondition{SelectorField: "spec.selector", AggregateField: "spec.nodeName", Comparator: comparatorAllPodsSameValue, PerMapKey: true}}
	if err := validateRule(r); err == nil {
		t.Fatal("expected an error: allPodsSameValue takes only selectorField and aggregateField")
	}
}

func TestDefaultRulesDeclarePromotionClass(t *testing.T) {
	rules, err := LoadRules("")
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	for _, rule := range rules {
		if rule.Class == "" {
			t.Errorf("default rule %q has no class; omitted classes are retained as anomaly findings", rule.ID)
		}
	}
}

func TestValidateRuleRejectsUnknownPromotionClass(t *testing.T) {
	r := Rule{ID: "x", GVK: "batch/v1/Job", Reason: "X", Severity: "low", Class: "urgent", Message: "m",
		Condition: RuleCondition{Field: "spec.activeDeadlineSeconds", Comparator: comparatorNotPresent}}
	if err := validateRule(r); err == nil {
		t.Fatal("expected an error for an unknown promotion class")
	}
}
