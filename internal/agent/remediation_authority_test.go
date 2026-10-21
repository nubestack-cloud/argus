package agent

import (
	"context"
	"errors"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// ssarClientset builds a clientset whose SelfSubjectAccessReview answers from
// allow, keyed by "<verb> <resource>" for a cluster-scoped review or
// "<namespace> <verb> <resource>" for a namespace-scoped one. A verb/resource
// (or namespace/verb/resource) absent from the map answers false, which is what
// a real API server does for an unmatched rule.
func ssarClientset(allow map[string]bool) *k8sfake.Clientset {
	cs := k8sfake.NewSimpleClientset()
	cs.PrependReactor("create", "selfsubjectaccessreviews",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			review := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
			attrs := review.Spec.ResourceAttributes
			key := attrs.Verb + " " + attrs.Resource
			if attrs.Namespace != "" {
				key = attrs.Namespace + " " + key
			}
			review.Status.Allowed = allow[key]
			return true, review, nil
		})
	return cs
}

// remediateRoleClientset is ssarClientset's namespace-scoped counterpart set up
// with a namespace-scoped "argus-remediate" Role object in each of namespaces —
// exactly the shape deploy/helm/argus-agent/templates/remediate-role.yaml renders
// once per entry in remediate.namespaces, and the signal
// candidateRemediationNamespaces uses to find which namespaces are worth a real
// per-namespace SelfSubjectAccessReview.
func remediateRoleClientset(allow map[string]bool, namespaces ...string) *k8sfake.Clientset {
	objs := make([]runtime.Object, 0, len(namespaces))
	for _, ns := range namespaces {
		objs = append(objs, &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Name: remediateRoleName, Namespace: ns},
		})
	}
	cs := k8sfake.NewSimpleClientset(objs...)
	cs.PrependReactor("create", "selfsubjectaccessreviews",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			review := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
			attrs := review.Spec.ResourceAttributes
			key := attrs.Verb + " " + attrs.Resource
			if attrs.Namespace != "" {
				key = attrs.Namespace + " " + key
			}
			review.Status.Allowed = allow[key]
			return true, review, nil
		})
	return cs
}

// TestGatherRemediationAuthority covers BACKLOG B4's three states. The live
// clusters both answer all-true (their agents hold a cluster-admin kubeconfig), so
// the two states that actually change what an operator is told — a real denial and
// an unanswerable question — are only reachable here.
func TestGatherRemediationAuthority(t *testing.T) {
	t.Run("all granted", func(t *testing.T) {
		got := gatherRemediationAuthority(context.Background(), ssarClientset(map[string]bool{
			"patch deployments": true, "patch statefulsets": true, "delete pods": true,
		}))
		if !got.Checked || !got.CanPatchDeployments || !got.CanPatchStatefulSets || !got.CanDeletePods {
			t.Fatalf("got %+v, want everything granted and Checked", got)
		}
	})

	t.Run("nothing granted is a real answer, not an unknown", func(t *testing.T) {
		got := gatherRemediationAuthority(context.Background(), ssarClientset(nil))
		if !got.Checked {
			t.Errorf("Checked = false, want true — the question WAS asked and the answer was no; reporting that as unknown loses the distinction B4 exists to draw")
		}
		if got.CanPatchDeployments || got.CanPatchStatefulSets || got.CanDeletePods {
			t.Errorf("got %+v, want nothing granted", got)
		}
	})

	t.Run("partial grants are reported per action", func(t *testing.T) {
		// A real posture: the workload-recovery RBAC pack grants patch on the two
		// workload kinds but not delete on pods.
		got := gatherRemediationAuthority(context.Background(), ssarClientset(map[string]bool{
			"patch deployments": true, "patch statefulsets": true,
		}))
		if !got.CanPatchDeployments || !got.CanPatchStatefulSets {
			t.Errorf("got %+v, want both workload patches granted", got)
		}
		if got.CanDeletePods {
			t.Errorf("CanDeletePods = true, want false — a per-action report that rounds up to 'can remediate' would tell an approver a RestartPod plan will work when it will not")
		}
	})

	t.Run("an unanswerable question is unknown, never a denial", func(t *testing.T) {
		cs := k8sfake.NewSimpleClientset()
		cs.PrependReactor("create", "selfsubjectaccessreviews",
			func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("authorization endpoint unreachable")
			})

		got := gatherRemediationAuthority(context.Background(), cs)
		if got.Checked {
			t.Fatalf("Checked = true, want false — an unreachable authorizer is not a denial, and reporting it as one tells an operator remediation is unavailable when nobody actually asked")
		}
		if got.Error == "" {
			t.Error("Error is empty, want the reason so the UI can say why it is unknown")
		}
		if got.CanPatchDeployments || got.CanPatchStatefulSets || got.CanDeletePods {
			t.Errorf("got %+v, want no grant claimed alongside Checked=false", got)
		}
	})

	t.Run("a later failure discards earlier answers", func(t *testing.T) {
		// Deployments answer true, then statefulsets errors. Returning a partial
		// result would present "can patch deployments" as established fact from a
		// check that did not complete.
		cs := k8sfake.NewSimpleClientset()
		calls := 0
		cs.PrependReactor("create", "selfsubjectaccessreviews",
			func(action k8stesting.Action) (bool, runtime.Object, error) {
				calls++
				if calls == 1 {
					review := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
					review.Status.Allowed = true
					return true, review, nil
				}
				return true, nil, errors.New("connection reset")
			})

		got := gatherRemediationAuthority(context.Background(), cs)
		if got.Checked || got.CanPatchDeployments {
			t.Fatalf("got %+v, want Checked=false and no grant carried over from the one check that did complete", got)
		}
	})
}

// TestGatherRemediationAuthority_Namespaced covers B170: the recommended,
// least-privilege remediate.namespaces install answers false fleet-wide (RBAC
// really is namespace-scoped, so the cluster-scoped review is correctly false),
// but a per-namespace review of exactly the namespace the chart's Role covers
// must answer true — that is the live discrepancy the board item proved
// (all three false at the cluster scope, PatchResourceLimits executing
// successfully against default/t5-checkout-api moments later).
func TestGatherRemediationAuthority_Namespaced(t *testing.T) {
	t.Run("namespace-scoped grant is invisible fleet-wide but visible per-namespace", func(t *testing.T) {
		cs := remediateRoleClientset(map[string]bool{
			"default patch deployments":  true,
			"default patch statefulsets": true,
			"default delete pods":        true,
		}, "default")

		got := gatherRemediationAuthority(context.Background(), cs)

		if got.CanPatchDeployments || got.CanPatchStatefulSets || got.CanDeletePods {
			t.Errorf("fleet-wide got %+v, want all three false — the cluster-scoped review is correctly negative for a namespace-scoped grant", got)
		}
		if len(got.Namespaces) != 1 {
			t.Fatalf("got %d namespace entries, want exactly 1 (default): %+v", len(got.Namespaces), got.Namespaces)
		}
		ns := got.Namespaces[0]
		if ns.Namespace != "default" {
			t.Errorf("got namespace %q, want %q", ns.Namespace, "default")
		}
		if !ns.CanPatchDeployments || !ns.CanPatchStatefulSets || !ns.CanDeletePods {
			t.Errorf("got %+v, want everything granted in default — this is the exact case the fleet-wide answer understates", ns)
		}
		if got.NamespacesTruncated {
			t.Errorf("NamespacesTruncated = true, want false — only one candidate namespace existed")
		}
	})

	t.Run("a namespace with no matching Role is not probed and does not appear", func(t *testing.T) {
		cs := remediateRoleClientset(map[string]bool{
			"team-payments patch deployments": true,
		}, "team-payments")

		got := gatherRemediationAuthority(context.Background(), cs)

		if len(got.Namespaces) != 1 || got.Namespaces[0].Namespace != "team-payments" {
			t.Fatalf("got %+v, want exactly one entry for team-payments", got.Namespaces)
		}
	})

	t.Run("no namespace-scoped Role anywhere means an empty, not fabricated-denied, breakdown", func(t *testing.T) {
		// remediate.allNamespaces shape: cluster-wide grant, no per-namespace
		// Role objects at all.
		got := gatherRemediationAuthority(context.Background(), ssarClientset(map[string]bool{
			"patch deployments": true, "patch statefulsets": true, "delete pods": true,
		}))
		if !got.CanPatchDeployments {
			t.Fatalf("got %+v, want the fleet-wide grant intact", got)
		}
		if len(got.Namespaces) != 0 {
			t.Errorf("got %+v, want no per-namespace entries — there is no namespace-scoped Role to find in the allNamespaces shape", got.Namespaces)
		}
	})

	t.Run("more candidate namespaces than the bound truncates deterministically and says so", func(t *testing.T) {
		namespaces := make([]string, 0, maxNamespaceRemediationChecks+5)
		allow := map[string]bool{}
		for i := 0; i < maxNamespaceRemediationChecks+5; i++ {
			ns := string(rune('a'+i%26)) + "-team"
			namespaces = append(namespaces, ns)
		}
		// Grant everything everywhere, so a truncated result is unambiguous:
		// any namespace present in got.Namespaces reports fully granted.
		for _, ns := range namespaces {
			allow[ns+" patch deployments"] = true
			allow[ns+" patch statefulsets"] = true
			allow[ns+" delete pods"] = true
		}
		cs := remediateRoleClientset(allow, namespaces...)

		got := gatherRemediationAuthority(context.Background(), cs)

		if !got.NamespacesTruncated {
			t.Errorf("NamespacesTruncated = false, want true — %d candidates exceeds the %d bound", len(namespaces), maxNamespaceRemediationChecks)
		}
		if len(got.Namespaces) != maxNamespaceRemediationChecks {
			t.Errorf("got %d namespace entries, want exactly the bound (%d)", len(got.Namespaces), maxNamespaceRemediationChecks)
		}
	})

	t.Run("a failure to list candidate namespaces omits the breakdown, not the fleet-wide answer", func(t *testing.T) {
		cs := ssarClientset(map[string]bool{"patch deployments": true})
		cs.PrependReactor("list", "roles",
			func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("rbac.authorization.k8s.io unreachable")
			})

		got := gatherRemediationAuthority(context.Background(), cs)

		if !got.Checked || !got.CanPatchDeployments {
			t.Fatalf("got %+v, want the fleet-wide answer unaffected by a namespace-discovery failure", got)
		}
		if got.Namespaces != nil {
			t.Errorf("got %+v, want a nil breakdown (unknown), not an empty one that could be read as 'checked, found none'", got.Namespaces)
		}
	})
}
