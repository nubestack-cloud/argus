package agent

// Live, cluster-touching proof of BACKLOG.md E10's two new predicate
// primitives (comparatorNotPresent, comparatorAllPodsSameValue) — skipped
// unless ARGUS_AGENT_RULES_LIVE=1, following the same convention
// internal/render/sandbox/runner_live_test.go and internal/gitops/live_test.go
// already use (ARGUS_RENDER_SANDBOX_LIVE, ARGUS_GITOPS_LIVE).
//
// Matches E10's own precedent for what "live-verified" means at this layer
// (checkFieldOwnershipConflict, BACKLOG.md E10 2026-08-31 entry): a direct
// call to evaluateRule against a real kubernetes.Interface/dynamic.Interface
// built from a live cluster's kubeconfig, proving the predicate's LOGIC
// fires against real API-server data — not a full agent-tunnel-hub-incident
// path, which is a separate, larger claim this file does not make either.
//
// Run against the disposable kind cluster (RUNBOOK.md "The disposable kind
// cluster" — 3 real nodes, safe to create/delete real Jobs/Deployments on):
//
//	ARGUS_AGENT_RULES_LIVE=1 KUBECONFIG=<kubeconfig> \
//	  go test ./internal/agent/ -run TestLiveRule -v
//
// Each test gets its own dedicated namespace (deleted at the end of that
// test) so it cannot collide with argus-system (where the disposable
// cluster's own argus-agent Helm release lives), with the other live test in
// this file, or with any other concurrent work on a shared cluster.

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// liveRulesClients builds the same two client shapes evaluateRule itself
// takes (dynamic.Interface, kubernetes.Interface) from KUBECONFIG, skipping
// the test entirely unless ARGUS_AGENT_RULES_LIVE=1 is set — the same gate
// runner_live_test.go's liveRunner uses.
func liveRulesClients(t *testing.T) (dynamic.Interface, kubernetes.Interface) {
	t.Helper()
	if os.Getenv("ARGUS_AGENT_RULES_LIVE") != "1" {
		t.Skip("set ARGUS_AGENT_RULES_LIVE=1 (and KUBECONFIG) to run the live E10 predicate tests")
	}
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		home, _ := os.UserHomeDir()
		kubeconfig = filepath.Join(home, ".kube", "config")
	}
	restCfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatalf("building rest.Config from KUBECONFIG=%s: %v", kubeconfig, err)
	}
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		t.Fatalf("kubernetes.NewForConfig: %v", err)
	}
	dyn, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		t.Fatalf("dynamic.NewForConfig: %v", err)
	}
	return dyn, clientset
}

// liveRulesSetup ensures namespace exists (creating it if not) and registers
// cleanup to delete it (and everything in it) when the test ends — so a run
// left interrupted mid-way is still cleaned up by `go test`'s own
// defer/cleanup machinery, not a manual step. Each caller passes its OWN
// namespace name (see the package doc above for why these are never
// shared).
func liveRulesSetup(t *testing.T, clientset kubernetes.Interface, namespace string) {
	t.Helper()
	ctx := context.Background()
	_, err := clientset.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = clientset.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: namespace},
		}, metav1.CreateOptions{})
	}
	if err != nil {
		t.Fatalf("ensuring namespace %s: %v", namespace, err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().Namespaces().Delete(context.Background(), namespace, metav1.DeleteOptions{})
	})
}

// TestLiveRule_JobMissingActiveDeadlineSeconds is BACKLOG.md E10's live
// verification of comparatorNotPresent (issue-catalog AP1/JOB-003) — a real
// Job created with no spec.activeDeadlineSeconds must fire, and an
// otherwise-identical real Job with the field set (the "healthy control"
// this campaign always runs alongside the fault) must not.
func TestLiveRule_JobMissingActiveDeadlineSeconds(t *testing.T) {
	const namespace = "argus-e10-rules-live-job"
	dyn, clientset := liveRulesClients(t)
	liveRulesSetup(t, clientset, namespace)
	ctx := context.Background()

	rules, err := LoadRules("")
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	rule, ok := findRule(rules, "job-missing-active-deadline-seconds")
	if !ok {
		t.Fatal("job-missing-active-deadline-seconds not in the embedded default rule set")
	}

	backoffLimit := int32(0)
	victim := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "e10-job-no-deadline", Namespace: namespace},
		Spec: batchv1.JobSpec{
			BackoffLimit: &backoffLimit,
			// No ActiveDeadlineSeconds — this is the fault.
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					Containers: []corev1.Container{{
						Name: "sleep", Image: "busybox:1.36", Command: []string{"sleep", "600"},
					}},
				},
			},
		},
	}
	deadline := int64(600)
	healthy := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "e10-job-with-deadline", Namespace: namespace},
		Spec: batchv1.JobSpec{
			BackoffLimit:          &backoffLimit,
			ActiveDeadlineSeconds: &deadline,
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					Containers: []corev1.Container{{
						Name: "sleep", Image: "busybox:1.36", Command: []string{"sleep", "600"},
					}},
				},
			},
		},
	}

	if _, err := clientset.BatchV1().Jobs(namespace).Create(ctx, victim, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating victim Job: %v", err)
	}
	t.Cleanup(func() {
		_ = clientset.BatchV1().Jobs(namespace).Delete(context.Background(), victim.Name, metav1.DeleteOptions{})
	})
	if _, err := clientset.BatchV1().Jobs(namespace).Create(ctx, healthy, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating healthy Job: %v", err)
	}
	t.Cleanup(func() {
		_ = clientset.BatchV1().Jobs(namespace).Delete(context.Background(), healthy.Name, metav1.DeleteOptions{})
	})

	out, err := evaluateRule(ctx, dyn, clientset, rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}

	fired := map[string]bool{}
	for _, c := range out {
		fired[c.Name] = true
		t.Logf("fired: %s/%s — %s", c.Namespace, c.Name, c.Message)
	}
	if !fired[victim.Name] {
		t.Errorf("expected %q (no activeDeadlineSeconds) to fire against the real cluster, it did not — candidates: %+v", victim.Name, out)
	}
	if fired[healthy.Name] {
		t.Errorf("expected %q (activeDeadlineSeconds=600) to NOT fire against the real cluster — false positive on the healthy control", healthy.Name)
	}
}

// TestLiveRule_DeploymentAllReplicasSingleNode is BACKLOG.md E10's live
// verification of comparatorAllPodsSameValue (issue-catalog AV1/DEPL-019) —
// a real Deployment whose replicas are all scheduled onto the same real Node
// (forced via nodeSelector, the disposable cluster's control-plane carries
// the standard NoSchedule taint so only the two workers are eligible) must
// fire, and an otherwise-identical real Deployment whose replicas are forced
// apart onto different real Nodes (via a hard podAntiAffinity rule) must
// not.
func TestLiveRule_DeploymentAllReplicasSingleNode(t *testing.T) {
	const namespace = "argus-e10-rules-live-depl"
	dyn, clientset := liveRulesClients(t)
	liveRulesSetup(t, clientset, namespace)
	ctx := context.Background()

	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("listing nodes: %v", err)
	}
	var workers []string
	for _, n := range nodes.Items {
		if _, isControlPlane := n.Labels["node-role.kubernetes.io/control-plane"]; !isControlPlane {
			workers = append(workers, n.Name)
		}
	}
	if len(workers) < 2 {
		t.Skipf("this live test needs at least 2 schedulable worker nodes, found %d: %v", len(workers), workers)
	}

	rules, err := LoadRules("")
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	rule, ok := findRule(rules, "deployment-all-replicas-single-node")
	if !ok {
		t.Fatal("deployment-all-replicas-single-node not in the embedded default rule set")
	}

	replicas := int32(2)

	packed := newLiveTestDeployment("e10-depl-packed", namespace, replicas,
		map[string]string{"kubernetes.io/hostname": workers[0]}, nil)
	if _, err := clientset.AppsV1().Deployments(namespace).Create(ctx, packed, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating packed Deployment: %v", err)
	}
	t.Cleanup(func() {
		_ = clientset.AppsV1().Deployments(namespace).Delete(context.Background(), packed.Name, metav1.DeleteOptions{})
	})

	spread := newLiveTestDeployment("e10-depl-spread", namespace, replicas, nil,
		&corev1.PodAntiAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{{
				TopologyKey: "kubernetes.io/hostname",
				LabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "e10-depl-spread"},
				},
			}},
		})
	if _, err := clientset.AppsV1().Deployments(namespace).Create(ctx, spread, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating spread Deployment: %v", err)
	}
	t.Cleanup(func() {
		_ = clientset.AppsV1().Deployments(namespace).Delete(context.Background(), spread.Name, metav1.DeleteOptions{})
	})

	waitForPodsScheduled(t, clientset, namespace, "app", packed.Name, int(replicas))
	waitForPodsScheduled(t, clientset, namespace, "app", spread.Name, int(replicas))

	out, err := evaluateRule(ctx, dyn, clientset, rule, time.Now(), sweepReadPlan{})
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}

	fired := map[string]bool{}
	for _, c := range out {
		fired[c.Name] = true
		t.Logf("fired: %s/%s — %s", c.Namespace, c.Name, c.Message)
	}
	if !fired[packed.Name] {
		t.Errorf("expected %q (both replicas pinned to node %s) to fire against the real cluster, it did not — candidates: %+v", packed.Name, workers[0], out)
	}
	if fired[spread.Name] {
		t.Errorf("expected %q (replicas forced onto different nodes) to NOT fire against the real cluster — false positive on the healthy control", spread.Name)
	}
}

// newLiveTestDeployment builds a real Deployment for
// TestLiveRule_DeploymentAllReplicasSingleNode — nodeSelector forces the
// "packed" case onto one named node; antiAffinity forces the "spread" case
// apart. Exactly one of the two is set by each caller.
func newLiveTestDeployment(name, namespace string, replicas int32, nodeSelector map[string]string, antiAffinity *corev1.PodAntiAffinity) *appsv1.Deployment {
	labels := map[string]string{"app": name}
	var affinity *corev1.Affinity
	if antiAffinity != nil {
		affinity = &corev1.Affinity{PodAntiAffinity: antiAffinity}
	}
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					NodeSelector: nodeSelector,
					Affinity:     affinity,
					Containers: []corev1.Container{{
						Name: "pause", Image: "busybox:1.36", Command: []string{"sleep", "600"},
					}},
				},
			},
		},
	}
}

// waitForPodsScheduled polls until `count` Pods matching label app=appName
// in namespace all have spec.nodeName set (i.e. the scheduler has bound
// them) — evaluateAllPodsSameValue's aggregateField (spec.nodeName) is only
// meaningful once binding has happened, and scheduling is asynchronous.
func waitForPodsScheduled(t *testing.T, clientset kubernetes.Interface, namespace, labelKey, appName string, count int) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		pods, err := clientset.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{
			LabelSelector: labelKey + "=" + appName,
		})
		if err == nil {
			scheduled := 0
			for _, p := range pods.Items {
				if p.Spec.NodeName != "" {
					scheduled++
				}
			}
			if scheduled >= count {
				return
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("timed out waiting for %d pods labeled app=%s in %s to be scheduled", count, appName, namespace)
}
