package rbacgrants

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func rule(verbs, groups, resources []string) rbacv1.PolicyRule {
	return rbacv1.PolicyRule{Verbs: verbs, APIGroups: groups, Resources: resources}
}

func sa(ns, name string) rbacv1.Subject {
	return rbacv1.Subject{Kind: "ServiceAccount", Namespace: ns, Name: name}
}

// A small cluster: an app's own reader Role, a shared ClusterRole bound into
// its namespace, a wildcard ClusterRoleBinding to a CI group, cluster-admin
// for one user, and a binding to a role that was deleted.
func cluster() Cluster {
	return Cluster{
		Roles: []*rbacv1.Role{{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "reader"},
			Rules: []rbacv1.PolicyRule{rule([]string{"get", "list"}, []string{""}, []string{"configmaps"})}}},
		ClusterRoles: []*rbacv1.ClusterRole{
			{ObjectMeta: metav1.ObjectMeta{Name: "deployer"}, Rules: []rbacv1.PolicyRule{
				rule([]string{"create", "patch"}, []string{"apps"}, []string{"deployments"}),
				rule([]string{"get", "list"}, []string{""}, []string{"configmaps"}),
			}},
			{ObjectMeta: metav1.ObjectMeta{Name: "everything"}, Rules: []rbacv1.PolicyRule{rule([]string{"*"}, []string{"*"}, []string{"*"})}},
			{ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"}, Rules: []rbacv1.PolicyRule{rule([]string{"*"}, []string{"*"}, []string{"*"})}},
			{ObjectMeta: metav1.ObjectMeta{Name: "rbac-manager"}, Rules: []rbacv1.PolicyRule{rule([]string{"bind", "escalate"}, []string{"rbac.authorization.k8s.io"}, []string{"roles"})}},
		},
		RoleBindings: []*rbacv1.RoleBinding{
			{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "api-reads"}, Subjects: []rbacv1.Subject{sa("shop", "api")},
				RoleRef: rbacv1.RoleRef{Kind: "Role", Name: "reader"}},
			// Namespace omitted on the subject: defaults to the binding's.
			{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "api-deploys"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: "api"}},
				RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "deployer"}},
			{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "gone"}, Subjects: []rbacv1.Subject{sa("shop", "api")},
				RoleRef: rbacv1.RoleRef{Kind: "Role", Name: "deleted-role"}},
			{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "rbac-in-shop"}, Subjects: []rbacv1.Subject{sa("shop", "api")},
				RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "rbac-manager"}},
			// Another namespace's account of the same name is someone else.
			{ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "not-ours"}, Subjects: []rbacv1.Subject{sa("other", "api")},
				RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "everything"}},
		},
		ClusterRoleBindings: []*rbacv1.ClusterRoleBinding{
			{ObjectMeta: metav1.ObjectMeta{Name: "all-sa-in-shop"}, Subjects: []rbacv1.Subject{{Kind: "Group", Name: "system:serviceaccounts:shop"}},
				RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "everything"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "alice-admin"}, Subjects: []rbacv1.Subject{{Kind: "User", Name: "alice"}},
				RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"}},
		},
	}
}

func TestServiceAccountGrants(t *testing.T) {
	rep := Describe(cluster(), Identity{Kind: "ServiceAccount", Namespace: "shop", Name: "api"})
	by := map[string]Grant{}
	for _, g := range rep.ViaBindings {
		by[g.Binding.Name] = g
	}
	if len(by) != 5 {
		t.Fatalf("grants = %v", rep.ViaBindings)
	}
	if g := by["api-deploys"]; g.ScopeNamespace != "shop" || g.Role.Kind != "ClusterRole" || g.RuleCount != 2 {
		t.Errorf("a ClusterRole bound by a RoleBinding is confined to that namespace: %+v", g)
	}
	if g := by["gone"]; !g.RoleMissing || g.RuleCount != 0 {
		t.Errorf("missing role = %+v", g)
	}
	if g := by["all-sa-in-shop"]; g.InheritedFromGroup != "system:serviceaccounts:shop" || g.ScopeNamespace != "" {
		t.Errorf("group grant = %+v", g)
	}
	if _, wrong := by["not-ours"]; wrong {
		t.Error("an account of the same name in another namespace matched")
	}
	// The configmaps read appears once though two roles grant it.
	n := 0
	for _, r := range rep.Flat {
		if len(r.Resources) == 1 && r.Resources[0] == "configmaps" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("configmaps rule listed %d times", n)
	}
	// Broadest first: the inherited wildcard leads, and is the score.
	if rep.ViaBindings[0].Binding.Name != "all-sa-in-shop" || rep.Flat[0].Score != 100 || rep.BlastRadius.Score != 100 {
		t.Errorf("order: first grant %s, first rule %+v, score %d", rep.ViaBindings[0].Binding.Name, rep.Flat[0], rep.BlastRadius.Score)
	}
}

func TestFlags(t *testing.T) {
	triggers := func(id Identity) map[string]Flag {
		out := map[string]Flag{}
		for _, f := range Describe(cluster(), id).BlastRadius.Flags {
			out[f.Trigger+"@"+f.Binding.Name] = f
		}
		return out
	}
	api := triggers(Identity{Kind: "ServiceAccount", Namespace: "shop", Name: "api"})
	for _, k := range []string{TriggerVerbWildcard + "@all-sa-in-shop", TriggerClusterCreatePods + "@all-sa-in-shop", TriggerEscalationVerb + "@rbac-in-shop"} {
		if _, ok := api[k]; !ok {
			t.Errorf("api is missing %s (got %v)", k, api)
		}
	}
	if f := api[TriggerVerbWildcard+"@all-sa-in-shop"]; f.InheritedFromGroup != "system:serviceaccounts:shop" || f.Reason == "" {
		t.Errorf("flag = %+v", f)
	}
	// Deploying within one namespace is not cluster-level.
	for k := range api {
		if k == TriggerClusterCreatePods+"@api-deploys" {
			t.Error("a namespaced deployer was flagged as cluster-wide pod creation")
		}
	}
	alice := triggers(Identity{Kind: "User", Name: "alice"})
	if _, ok := alice[TriggerClusterAdmin+"@alice-admin"]; !ok {
		t.Errorf("alice = %v", alice)
	}
	if bob := Describe(cluster(), Identity{Kind: "User", Name: "bob"}); len(bob.ViaBindings) != 0 || len(bob.BlastRadius.Flags) != 0 {
		t.Errorf("an unbound user = %+v", bob)
	}
}

func TestScoreOrdersBreadth(t *testing.T) {
	read := score(rule([]string{"get"}, []string{""}, []string{"configmaps"}), true)
	write := score(rule([]string{"patch"}, []string{"apps"}, []string{"deployments"}), true)
	secrets := score(rule([]string{"get"}, []string{""}, []string{"secrets"}), true)
	nsSecrets := score(rule([]string{"get"}, []string{""}, []string{"secrets"}), false)
	named := score(rbacv1.PolicyRule{Verbs: []string{"get"}, Resources: []string{"secrets"}, ResourceNames: []string{"tls"}}, true)
	if !(read < write && read < secrets && nsSecrets < secrets && named < secrets) {
		t.Fatalf("read %d write %d secrets %d ns-secrets %d named %d", read, write, secrets, nsSecrets, named)
	}
}
