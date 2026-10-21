package agent

// Live demonstration of PROJECT.md B185 against a real API server and a real
// narrow ClusterRole — not a fake client, and not cluster-admin.
//
// B185 is that a kind the agent may not read is indistinguishable, to
// checkGenericDanglingReference, from a kind with nothing in it, so every
// reference into the denied kind is reported as a broken reference. The
// failure gets worse exactly as an operator narrows the grant, which is the
// direction BACKLOG.md E11 is moving, so a fixture cannot be the whole
// answer: the thing to show is a real identity, with a real ClusterRole that
// omits one kind, reading a real cluster.
//
// Read-mostly, but it DOES write: a namespace, a Deployment, two
// HorizontalPodAutoscalers, a ClusterRole and a ClusterRoleBinding, all
// prefixed argus-b185 and all deleted at the end. Run it against a
// disposable cluster ONLY:
//
//	ARGUS_AGENT_B185_LIVE=1 ARGUS_AGENT_B185_CONTEXT=kind-argus-disposable \
//	  go test ./internal/agent/ -run TestLiveDanglingReferenceUnderNarrowRBAC -v
//
// The narrow identity is reached by impersonation rather than by minting a
// ServiceAccount token: the RBAC decision the API server makes is identical,
// and it keeps the fixture to objects that are trivially deletable.

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	b185Namespace   = "argus-b185"
	b185Identity    = "argus-b185-narrow-reader"
	b185ClusterRole = "argus-b185-narrow"
)

func TestLiveDanglingReferenceUnderNarrowRBAC(t *testing.T) {
	if os.Getenv("ARGUS_AGENT_B185_LIVE") != "1" {
		t.Skip("set ARGUS_AGENT_B185_LIVE=1 (and a disposable-cluster KUBECONFIG/context) to demonstrate B185 against a real narrow ClusterRole")
	}
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		home, _ := os.UserHomeDir()
		kubeconfig = filepath.Join(home, ".kube", "config")
	}
	loading := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: os.Getenv("ARGUS_AGENT_B185_CONTEXT")}
	adminCfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loading, overrides).ClientConfig()
	if err != nil {
		t.Fatalf("building rest.Config: %v", err)
	}
	admin, err := kubernetes.NewForConfig(adminCfg)
	if err != nil {
		t.Fatalf("building clientset: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	b185Setup(ctx, t, admin)
	t.Cleanup(func() { b185Teardown(context.Background(), t, admin) })

	dynFor := func(cfg *rest.Config) dynamic.Interface {
		dyn, err := dynamic.NewForConfig(cfg)
		if err != nil {
			t.Fatalf("building dynamic client: %v", err)
		}
		return dyn
	}
	narrowCfg := rest.CopyConfig(adminCfg)
	narrowCfg.Impersonate = rest.ImpersonationConfig{UserName: b185Identity}

	report := func(label string, dyn dynamic.Interface) {
		snap, err := listWatchedKindObjects(ctx, dyn, sweepReadPlan{})
		if err != nil {
			t.Fatalf("%s: building the snapshot: %v", label, err)
		}
		t.Logf("%s: Deployment readable=%v state=%v reason=%q",
			label, snap.readable("Deployment"), snap.readState("Deployment"), snap.unreadableReason("Deployment"))
		found := map[string]string{}
		for _, c := range checkGenericDanglingReference(snap, time.Now()) {
			if c.Namespace == b185Namespace {
				found[c.Name] = c.Message
			}
		}
		// What the SAME predicate said before the read record existed: an
		// unread kind was simply missing from the object map, with nothing
		// to distinguish it from an empty one. Reproduced exactly, by
		// marking every kind readable regardless of whether it was read.
		before := newUnstructuredSnapshot()
		for kind, objs := range snap.objects {
			before.record(kind, kindReadResult{state: kindReadOK})
			before.add(kind, objs)
		}
		for kind := range snap.reads {
			before.record(kind, kindReadResult{state: kindReadOK})
		}
		beforeFound := 0
		for _, c := range checkGenericDanglingReference(before, time.Now()) {
			if c.Namespace == b185Namespace {
				beforeFound++
			}
		}
		t.Logf("%s: dangling-reference findings in %s — before the read record: %d, now: %d",
			label, b185Namespace, beforeFound, len(found))
		for _, name := range []string{"hpa-target-exists", "hpa-target-missing"} {
			if msg, ok := found[name]; ok {
				t.Logf("  %-18s -> FINDING: %s", name, msg)
			} else {
				t.Logf("  %-18s -> no finding", name)
			}
		}
		if label == "narrow identity (no Deployment read)" {
			if snap.readable("Deployment") {
				t.Fatal("the narrow ClusterRole must deny Deployments, or this test proves nothing")
			}
			if snap.readState("Deployment") != kindForbidden {
				t.Fatalf("Deployment readState = %v, want kindForbidden", snap.readState("Deployment"))
			}
			if len(found) != 0 {
				t.Fatalf("a reference into a kind this identity may not read must produce NO dangling-reference finding; got %v", found)
			}
		}
		if label == "full grant (Deployment read)" {
			if _, ok := found["hpa-target-exists"]; ok {
				t.Fatal("an HPA whose target exists must never be reported as dangling")
			}
			if _, ok := found["hpa-target-missing"]; !ok {
				t.Fatal("an HPA whose target genuinely does not exist must still be reported — otherwise the predicate has simply stopped working")
			}
		}
	}

	report("full grant (Deployment read)", dynFor(adminCfg))
	report("narrow identity (no Deployment read)", dynFor(narrowCfg))
	t.Log("the honest cost, stated: under the narrow grant the agent also stops reporting hpa-target-missing, which IS broken. It cannot tell the two apart without reading Deployments, and inventing the confident answer is what B185 is about.")
}

func b185Setup(ctx context.Context, t *testing.T, admin kubernetes.Interface) {
	t.Helper()
	_, err := admin.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: b185Namespace},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("creating namespace: %v", err)
	}

	replicas := int32(1)
	_, err = admin.AppsV1().Deployments(b185Namespace).Create(ctx, &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "real-target", Namespace: b185Namespace},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "b185"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "b185"}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.k8s.io/pause:3.9"}}},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("creating deployment: %v", err)
	}

	hpa := func(name, target string) *autoscalingv2.HorizontalPodAutoscaler {
		max := int32(3)
		return &autoscalingv2.HorizontalPodAutoscaler{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: b185Namespace},
			Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
				ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{APIVersion: "apps/v1", Kind: "Deployment", Name: target},
				MaxReplicas:    max,
			},
		}
	}
	for _, h := range []*autoscalingv2.HorizontalPodAutoscaler{
		hpa("hpa-target-exists", "real-target"),
		hpa("hpa-target-missing", "no-such-deployment"),
	} {
		if _, err := admin.AutoscalingV2().HorizontalPodAutoscalers(b185Namespace).Create(ctx, h, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatalf("creating hpa %s: %v", h.Name, err)
		}
	}

	// The narrow grant: everything this predicate needs to see the HPA and
	// resolve its reference, EXCEPT apps/deployments. Deliberately not
	// cluster-admin and deliberately not the chart's own ClusterRole — the
	// point is an identity one kind short of what it wants to verify.
	_, err = admin.RbacV1().ClusterRoles().Create(ctx, &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: b185ClusterRole},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"pods", "services", "nodes", "namespaces", "configmaps", "persistentvolumeclaims", "persistentvolumes", "serviceaccounts", "endpoints", "resourcequotas"}, Verbs: []string{"get", "list", "watch"}},
			{APIGroups: []string{"apps"}, Resources: []string{"statefulsets", "daemonsets", "replicasets"}, Verbs: []string{"get", "list", "watch"}},
			{APIGroups: []string{"autoscaling"}, Resources: []string{"horizontalpodautoscalers"}, Verbs: []string{"get", "list", "watch"}},
			{APIGroups: []string{"batch"}, Resources: []string{"jobs", "cronjobs"}, Verbs: []string{"get", "list", "watch"}},
		},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("creating clusterrole: %v", err)
	}
	_, err = admin.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: b185ClusterRole},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: b185ClusterRole},
		Subjects:   []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: "User", Name: b185Identity}},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("creating clusterrolebinding: %v", err)
	}
}

func b185Teardown(ctx context.Context, t *testing.T, admin kubernetes.Interface) {
	t.Helper()
	_ = admin.RbacV1().ClusterRoleBindings().Delete(ctx, b185ClusterRole, metav1.DeleteOptions{})
	_ = admin.RbacV1().ClusterRoles().Delete(ctx, b185ClusterRole, metav1.DeleteOptions{})
	if err := admin.CoreV1().Namespaces().Delete(ctx, b185Namespace, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		t.Logf("deleting namespace %s: %v", b185Namespace, err)
	}
}
