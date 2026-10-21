// Package rbacgrants answers "what can this identity do, and through which
// bindings" for a ServiceAccount, User or Group, from the cluster's Roles,
// ClusterRoles and their bindings as the agent's cache holds them. It also
// names the grants that would make a compromise of the identity a
// cluster-wide problem, and ranks rules by how much they allow so the
// broadest reads first.
package rbacgrants

import (
	"fmt"
	"sort"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
)

// Identity is who is asked about. Namespace is set for a ServiceAccount only.
type Identity struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

// ObjectRef names a binding or a role.
type ObjectRef struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

// Grant is one binding that applies to the identity.
type Grant struct {
	Binding ObjectRef `json:"binding"`
	Role    ObjectRef `json:"role"`
	// ScopeNamespace is the namespace a RoleBinding confines the role to;
	// empty for a ClusterRoleBinding, which grants cluster-wide.
	ScopeNamespace string `json:"scopeNamespace,omitempty"`
	// InheritedFromGroup is the group through which the binding reaches the
	// identity, when it does not name the identity itself.
	InheritedFromGroup string `json:"inheritedFromGroup,omitempty"`
	RoleMissing        bool   `json:"roleMissing,omitempty"`
	RuleCount          int    `json:"ruleCount"`
	MaxRuleScore       int    `json:"maxRuleScore"`
}

// Rule is one effective rule, deduplicated across grants.
type Rule struct {
	Verbs           []string `json:"verbs,omitempty"`
	APIGroups       []string `json:"apiGroups,omitempty"`
	Resources       []string `json:"resources,omitempty"`
	ResourceNames   []string `json:"resourceNames,omitempty"`
	NonResourceURLs []string `json:"nonResourceURLs,omitempty"`
	// Score ranks how much the rule allows, 1–100: a comparison between
	// rules and identities, not a probability.
	Score int `json:"score"`
}

// Flag is a grant that reaches cluster-takeover territory.
type Flag struct {
	Trigger            string    `json:"trigger"`
	Binding            ObjectRef `json:"binding"`
	InheritedFromGroup string    `json:"inheritedFromGroup,omitempty"`
	Reason             string    `json:"reason"`
}

// Triggers the UI names (web/src/insight/views/PermissionsView.tsx).
const (
	TriggerClusterAdmin      = "clusterAdmin"
	TriggerVerbWildcard      = "verbWildcard"
	TriggerEscalationVerb    = "escalationVerb"
	TriggerClusterCreatePods = "clusterCreatePods"
)

type Exposure struct {
	Flags []Flag `json:"flags"`
	// Score is the highest rule score the identity holds.
	Score int `json:"score"`
}

// Report is the whole answer; its JSON is what get_subject_permissions
// returns beside the insight stamp.
type Report struct {
	Subject     Identity `json:"subject"`
	ViaBindings []Grant  `json:"viaBindings"`
	Flat        []Rule   `json:"flat"`
	BlastRadius Exposure `json:"blastRadius"`
	// Truncated says the lists were cut at their caps; the flags and score
	// were still computed over everything.
	Truncated bool `json:"truncated,omitempty"`
}

const (
	maxGrants = 200
	maxRules  = 300
)

// Cluster is the RBAC objects to search, as the agent's cache returns them.
type Cluster struct {
	Roles               []*rbacv1.Role
	ClusterRoles        []*rbacv1.ClusterRole
	RoleBindings        []*rbacv1.RoleBinding
	ClusterRoleBindings []*rbacv1.ClusterRoleBinding
}

// Describe reports what id may do in c.
func Describe(c Cluster, id Identity) Report {
	roles := map[string][]rbacv1.PolicyRule{}
	for _, r := range c.Roles {
		if r != nil {
			roles["Role/"+r.Namespace+"/"+r.Name] = r.Rules
		}
	}
	for _, r := range c.ClusterRoles {
		if r != nil {
			roles["ClusterRole//"+r.Name] = r.Rules
		}
	}
	groups := memberOf(id)

	type found struct {
		grant Grant
		rules []rbacv1.PolicyRule
	}
	var all []found
	consider := func(binding ObjectRef, subjects []rbacv1.Subject, ref rbacv1.RoleRef, scope string) {
		via, ok := appliesTo(subjects, id, groups, binding.Namespace)
		if !ok {
			return
		}
		roleNS := ""
		if ref.Kind == "Role" {
			roleNS = binding.Namespace
		}
		rules, exists := roles[ref.Kind+"/"+roleNS+"/"+ref.Name]
		g := Grant{
			Binding:            binding,
			Role:               ObjectRef{Kind: ref.Kind, Namespace: roleNS, Name: ref.Name},
			ScopeNamespace:     scope,
			InheritedFromGroup: via,
			RoleMissing:        !exists,
			RuleCount:          len(rules),
		}
		for _, r := range rules {
			if s := score(r, scope == ""); s > g.MaxRuleScore {
				g.MaxRuleScore = s
			}
		}
		all = append(all, found{g, rules})
	}
	for _, b := range c.RoleBindings {
		if b != nil {
			consider(ObjectRef{Kind: "RoleBinding", Namespace: b.Namespace, Name: b.Name}, b.Subjects, b.RoleRef, b.Namespace)
		}
	}
	for _, b := range c.ClusterRoleBindings {
		if b != nil {
			consider(ObjectRef{Kind: "ClusterRoleBinding", Name: b.Name}, b.Subjects, b.RoleRef, "")
		}
	}

	rep := Report{Subject: id, ViaBindings: []Grant{}, Flat: []Rule{}, BlastRadius: Exposure{Flags: []Flag{}}}
	seen := map[string]int{}
	for _, f := range all {
		rep.ViaBindings = append(rep.ViaBindings, f.grant)
		clusterWide := f.grant.ScopeNamespace == ""
		for _, pr := range f.rules {
			r := Rule{Verbs: pr.Verbs, APIGroups: pr.APIGroups, Resources: pr.Resources, ResourceNames: pr.ResourceNames, NonResourceURLs: pr.NonResourceURLs, Score: score(pr, clusterWide)}
			k := ruleKey(r)
			if i, dup := seen[k]; dup {
				// The same rule granted twice keeps its broadest scope's score.
				if r.Score > rep.Flat[i].Score {
					rep.Flat[i].Score = r.Score
				}
				continue
			}
			seen[k] = len(rep.Flat)
			rep.Flat = append(rep.Flat, r)
		}
		rep.BlastRadius.Flags = append(rep.BlastRadius.Flags, flagsFor(f.grant, f.rules)...)
		if f.grant.MaxRuleScore > rep.BlastRadius.Score {
			rep.BlastRadius.Score = f.grant.MaxRuleScore
		}
	}
	sort.SliceStable(rep.ViaBindings, func(i, j int) bool { return rep.ViaBindings[i].MaxRuleScore > rep.ViaBindings[j].MaxRuleScore })
	sort.SliceStable(rep.Flat, func(i, j int) bool { return rep.Flat[i].Score > rep.Flat[j].Score })
	if len(rep.ViaBindings) > maxGrants {
		rep.ViaBindings, rep.Truncated = rep.ViaBindings[:maxGrants], true
	}
	if len(rep.Flat) > maxRules {
		rep.Flat, rep.Truncated = rep.Flat[:maxRules], true
	}
	return rep
}

// memberOf is the groups Kubernetes puts an identity in without any binding
// naming them: every authenticated identity is in system:authenticated, and
// a ServiceAccount also in the service-account groups for its namespace.
func memberOf(id Identity) map[string]bool {
	switch id.Kind {
	case "ServiceAccount":
		return map[string]bool{"system:authenticated": true, "system:serviceaccounts": true, "system:serviceaccounts:" + id.Namespace: true}
	case "User":
		return map[string]bool{"system:authenticated": true}
	}
	return nil
}

// appliesTo reports whether one of a binding's subjects is the identity, or
// a group it belongs to — returning the group in that case.
func appliesTo(subjects []rbacv1.Subject, id Identity, groups map[string]bool, bindingNS string) (string, bool) {
	viaGroup := ""
	for _, s := range subjects {
		switch s.Kind {
		case "ServiceAccount":
			ns := s.Namespace
			if ns == "" {
				ns = bindingNS // a RoleBinding's ServiceAccount subject defaults to its own namespace
			}
			if id.Kind == "ServiceAccount" && s.Name == id.Name && ns == id.Namespace {
				return "", true
			}
		case "User":
			if id.Kind == "User" && s.Name == id.Name {
				return "", true
			}
		case "Group":
			if id.Kind == "Group" && s.Name == id.Name {
				return "", true
			}
			if groups[s.Name] && viaGroup == "" {
				viaGroup = s.Name
			}
		}
	}
	return viaGroup, viaGroup != ""
}

// Verb and resource weights for score. Writes beat reads; the verbs that
// grant more permissions beat both; secrets, pod exec and RBAC itself are
// the resources a takeover goes through.
var verbWeight = map[string]int{
	"*": 10, "escalate": 10, "bind": 10, "impersonate": 10,
	"create": 6, "delete": 6, "deletecollection": 7, "patch": 6, "update": 6,
	"get": 2, "list": 3, "watch": 3,
}

func resourceWeight(r string) int {
	switch {
	case r == "*":
		return 10
	case r == "secrets", r == "pods/exec", r == "pods/attach", r == "nodes/proxy", r == "serviceaccounts/token":
		return 9
	case strings.HasPrefix(r, "clusterroles"), strings.HasPrefix(r, "roles"), strings.HasPrefix(r, "clusterrolebindings"), strings.HasPrefix(r, "rolebindings"):
		return 9
	case r == "pods", r == "deployments", r == "daemonsets", r == "statefulsets", r == "jobs", r == "cronjobs":
		return 6
	case strings.Contains(r, "/"):
		return 4
	}
	return 3
}

// score rates a rule 1–100: its strongest verb times its most sensitive
// resource, halved when confined to a namespace and cut further when only
// named objects are covered.
func score(r rbacv1.PolicyRule, clusterWide bool) int {
	v := 0
	for _, verb := range r.Verbs {
		w, ok := verbWeight[verb]
		if !ok {
			w = 4
		}
		if w > v {
			v = w
		}
	}
	res := 0
	for _, x := range r.Resources {
		if w := resourceWeight(x); w > res {
			res = w
		}
	}
	if len(r.NonResourceURLs) > 0 && res == 0 {
		res = 2
		for _, u := range r.NonResourceURLs {
			if u == "*" {
				res = 6
			}
		}
	}
	s := v * res
	if !clusterWide {
		s /= 2
	}
	if len(r.ResourceNames) > 0 {
		s /= 3
	}
	switch {
	case s < 1:
		return 1
	case s > 100:
		return 100
	}
	return s
}

func ruleKey(r Rule) string {
	j := func(v []string) string {
		c := append([]string(nil), v...)
		sort.Strings(c)
		return strings.Join(c, ",")
	}
	return strings.Join([]string{j(r.Verbs), j(r.APIGroups), j(r.Resources), j(r.ResourceNames), j(r.NonResourceURLs)}, "|")
}

func has(v []string, want ...string) bool {
	for _, x := range v {
		for _, w := range want {
			if x == w {
				return true
			}
		}
	}
	return false
}

// flagsFor names what makes this grant a cluster-level risk. Escalation
// verbs count anywhere — a namespaced bind or escalate is still a way to
// grant more than one holds; the rest only count cluster-wide.
func flagsFor(g Grant, rules []rbacv1.PolicyRule) []Flag {
	var out []Flag
	add := func(trigger, reason string) {
		for _, f := range out {
			if f.Trigger == trigger {
				return
			}
		}
		out = append(out, Flag{Trigger: trigger, Binding: g.Binding, InheritedFromGroup: g.InheritedFromGroup, Reason: reason})
	}
	clusterWide := g.ScopeNamespace == ""
	if clusterWide && g.Role.Kind == "ClusterRole" && g.Role.Name == "cluster-admin" {
		add(TriggerClusterAdmin, "cluster-admin allows every action on every resource in every namespace")
	}
	for _, r := range rules {
		if clusterWide && has(r.Verbs, "*") && (has(r.Resources, "*") || len(r.NonResourceURLs) > 0 || len(r.Resources) > 0) {
			add(TriggerVerbWildcard, fmt.Sprintf("every verb on %s across the cluster", strings.Join(nonEmpty(r.Resources, r.NonResourceURLs), ", ")))
		}
		if v := pick(r.Verbs, "escalate", "bind", "impersonate"); v != "" {
			where := "across the cluster"
			if !clusterWide {
				where = "in namespace " + g.ScopeNamespace
			}
			add(TriggerEscalationVerb, fmt.Sprintf("%s lets it grant or assume permissions it does not hold, %s", v, where))
		}
		if clusterWide && has(r.Verbs, "create", "*") && has(r.Resources, "pods", "*") && has(r.APIGroups, "", "*") {
			add(TriggerClusterCreatePods, "creating pods in any namespace means running as any service account there, and reading any secret it can mount")
		}
	}
	return out
}

func pick(v []string, want ...string) string {
	for _, w := range want {
		if has(v, w) {
			return w
		}
	}
	return ""
}

func nonEmpty(a, b []string) []string {
	if len(a) > 0 {
		return a
	}
	return b
}
