package argusagentchart

// chart_identity_test.go is PROJECT.md B163's chart half: durable agent
// identity has to be what an operator gets WITHOUT opting into anything, and
// the grant that makes it possible has to stay as narrow as it was written.
//
// Reuses helmTemplateRaw/decodeYAMLDocs from chart_metrics_test.go, and the
// same "no live cluster needed, `helm template` renders locally" verification
// chart_test.go's header comment establishes for this chart.

import (
	"strings"
	"testing"
)

// identityRoleObject mirrors a rendered Role including resourceNames, which
// chart_test.go's rbacObject deliberately omits.
type identityRoleObject struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Rules []struct {
		APIGroups     []string `yaml:"apiGroups"`
		Resources     []string `yaml:"resources"`
		Verbs         []string `yaml:"verbs"`
		ResourceNames []string `yaml:"resourceNames"`
	} `yaml:"rules"`
}

type identitySecretObject struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Type       string            `yaml:"type"`
	Data       map[string]string `yaml:"data"`
	StringData map[string]string `yaml:"stringData"`
}

type identityBindingObject struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Subjects []struct {
		Kind      string `yaml:"kind"`
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"subjects"`
	RoleRef struct {
		Kind string `yaml:"kind"`
		Name string `yaml:"name"`
	} `yaml:"roleRef"`
}

type identityDeploymentObject struct {
	Kind string `yaml:"kind"`
	// Metadata.Name distinguishes the investigation Deployment
	// (argus-agent) from the remediation one (argus-agent-remediate) —
	// PROJECT.md E11 made this chart render two.
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		Template struct {
			Spec struct {
				ServiceAccountName string `yaml:"serviceAccountName"`
				Containers         []struct {
					Name string `yaml:"name"`
					Env  []struct {
						Name      string `yaml:"name"`
						Value     string `yaml:"value"`
						ValueFrom *struct {
							FieldRef *struct {
								FieldPath string `yaml:"fieldPath"`
							} `yaml:"fieldRef"`
						} `yaml:"valueFrom"`
					} `yaml:"env"`
				} `yaml:"containers"`
			} `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

// TestDurableIdentityIsTheDefault is B163's acceptance criterion at the chart
// layer: a plain `helm install` with no extra values must produce an agent
// whose identity survives pod replacement. Before this, the documented happy
// path was the fragile one and every reader of the deployment guide had to be
// told to override it.
func TestDurableIdentityIsTheDefault(t *testing.T) {
	out, err := helmTemplateRaw(t)
	if err != nil {
		t.Fatalf("helm template (defaults) failed: %v\n%s", err, out)
	}

	secrets := decodeYAMLDocs[identitySecretObject](t, out, func(k string) bool { return k == "Secret" })
	var identity *identitySecretObject
	for i := range secrets {
		if secrets[i].Metadata.Name == "argus-agent-identity" {
			identity = &secrets[i]
		}
	}
	if identity == nil {
		t.Fatal("no argus-agent-identity Secret rendered with default values — durable identity must not be something the operator has to opt into (PROJECT.md B163)")
	}
	if identity.Metadata.Namespace != "argus-system" {
		t.Errorf("identity Secret namespace = %q, want argus-system (values.yaml's default namespace.name)", identity.Metadata.Namespace)
	}
	// The Helm-merge trap: if this chart ever renders the identity's contents,
	// a later revision that renders them empty deletes the live keys.
	if len(identity.Data) != 0 || len(identity.StringData) != 0 {
		t.Errorf("the identity Secret renders data (%v/%v) — it must render the object only, or Helm's three-way merge can delete the agent's keys on a later upgrade", identity.Data, identity.StringData)
	}

	// The env vars that make the agent actually use it.
	deployments := decodeYAMLDocs[identityDeploymentObject](t, out, func(k string) bool { return k == "Deployment" })
	if len(deployments) != 1 {
		t.Fatalf("rendered %d Deployment objects, want 1", len(deployments))
	}
	var secretName, namespaceFieldPath string
	for _, c := range deployments[0].Spec.Template.Spec.Containers {
		for _, e := range c.Env {
			switch e.Name {
			case "ARGUS_AGENT_IDENTITY_SECRET":
				secretName = e.Value
			case "ARGUS_AGENT_NAMESPACE":
				if e.ValueFrom != nil && e.ValueFrom.FieldRef != nil {
					namespaceFieldPath = e.ValueFrom.FieldRef.FieldPath
				}
			}
		}
	}
	if secretName != "argus-agent-identity" {
		t.Errorf("ARGUS_AGENT_IDENTITY_SECRET = %q, want argus-agent-identity — without it the agent silently uses the ephemeral directory", secretName)
	}
	if namespaceFieldPath != "metadata.namespace" {
		t.Errorf("ARGUS_AGENT_NAMESPACE fieldPath = %q, want metadata.namespace", namespaceFieldPath)
	}
}

// TestIdentityGrantIsNarrow guards the security shape of the fix. The agent's
// ClusterRole permanently excludes Secret access beyond a single named `get`
// (templates/clusterrole.yaml's header), and this Role must not become a way
// around that: one named Secret, in the agent's own namespace, get+update,
// nothing else. `create` in particular cannot be restricted by resourceNames,
// so granting it would mean "create any Secret in this namespace".
func TestIdentityGrantIsNarrow(t *testing.T) {
	out, err := helmTemplateRaw(t)
	if err != nil {
		t.Fatalf("helm template (defaults) failed: %v\n%s", err, out)
	}
	roles := decodeYAMLDocs[identityRoleObject](t, out, func(k string) bool { return k == "Role" })
	var role *identityRoleObject
	for i := range roles {
		if roles[i].Metadata.Name == "argus-agent-identity" {
			role = &roles[i]
		}
	}
	if role == nil {
		t.Fatal("no argus-agent-identity Role rendered — the agent could not read or write its own identity Secret")
	}
	if role.Metadata.Namespace != "argus-system" {
		t.Errorf("identity Role namespace = %q, want argus-system — a ClusterRole's resourceNames would match a same-named Secret in EVERY namespace", role.Metadata.Namespace)
	}
	if len(role.Rules) != 1 {
		t.Fatalf("identity Role has %d rules, want exactly 1", len(role.Rules))
	}
	rule := role.Rules[0]
	if len(rule.ResourceNames) != 1 || rule.ResourceNames[0] != "argus-agent-identity" {
		t.Errorf("identity Role resourceNames = %v, want exactly [argus-agent-identity] — an unrestricted secrets grant is a different and much larger permission", rule.ResourceNames)
	}
	wantVerbs := map[string]bool{"get": true, "update": true}
	for _, v := range rule.Verbs {
		if !wantVerbs[v] {
			t.Errorf("identity Role grants verb %q — only get and update are needed; list/watch would expose every other Secret in the namespace, and create cannot be restricted by name at all", v)
		}
	}
	for want := range wantVerbs {
		if !contains(rule.Verbs, want) {
			t.Errorf("identity Role does not grant %q, which the agent's read-modify-write of its own identity needs", want)
		}
	}
}

// TestIdentityBindingCoversEveryAgentServiceAccount is PROJECT.md E11's
// version of a guard this chart has needed since it grew a second
// ServiceAccount.
//
// It used to assert "the binding names the one ServiceAccount the one
// Deployment runs as", because there was one Deployment and its identity
// flipped to argus-remediate whenever remediate.enabled. E11 retired that
// flip: the investigation agent is always argus-investigate, and remediation
// is a SECOND Deployment under argus-remediate that mounts the SAME identity
// Secret (it never enrolls — it joins the cluster record its investigation
// counterpart established).
//
// So the property worth pinning is now stronger and survives another
// Deployment being added: EVERY ServiceAccount any agent Deployment runs as
// must be a subject of the identity RoleBinding. A Deployment whose identity
// is not bound cannot read the certificate it needs to connect at all, and
// would fail in a way that looks like a hub problem.
func TestIdentityBindingCoversEveryAgentServiceAccount(t *testing.T) {
	for _, tc := range []struct {
		name         string
		set          []string
		wantDeploys  int
		wantSubjects []string
	}{
		{"read-only", nil, 1, []string{"argus-investigate"}},
		{
			"remediation enabled",
			[]string{"--set", "remediate.enabled=true", "--set", "remediate.allNamespaces=true"},
			2,
			[]string{"argus-investigate", "argus-remediate"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplateRaw(t, tc.set...)
			if err != nil {
				t.Fatalf("helm template failed: %v\n%s", err, out)
			}
			deployments := decodeYAMLDocs[identityDeploymentObject](t, out, func(k string) bool { return k == "Deployment" })
			if len(deployments) != tc.wantDeploys {
				t.Fatalf("rendered %d Deployment objects, want %d — remediation is its own Deployment since PROJECT.md E11, not a change of identity on the existing one", len(deployments), tc.wantDeploys)
			}

			bindings := decodeYAMLDocs[identityBindingObject](t, out, func(k string) bool { return k == "RoleBinding" })
			var binding *identityBindingObject
			for i := range bindings {
				if bindings[i].Metadata.Name == "argus-agent-identity" {
					binding = &bindings[i]
				}
			}
			if binding == nil {
				t.Fatal("no argus-agent-identity RoleBinding rendered")
			}
			bound := map[string]bool{}
			for _, sub := range binding.Subjects {
				bound[sub.Name] = true
			}
			for _, d := range deployments {
				sa := d.Spec.Template.Spec.ServiceAccountName
				if !bound[sa] {
					t.Errorf("a Deployment runs as %q but the identity RoleBinding does not bind it (binds %v) — that agent would be forbidden from reading its own identity and could never connect", sa, binding.Subjects)
				}
			}
			for _, want := range tc.wantSubjects {
				if !bound[want] {
					t.Errorf("identity RoleBinding does not bind %q", want)
				}
			}
			// No stray subjects: the grant is get+update on this cluster's
			// own hub-issued identity, and it must reach exactly the agent
			// processes that need it.
			if len(binding.Subjects) != len(tc.wantSubjects) {
				t.Errorf("identity RoleBinding has %d subjects, want %d (%v)", len(binding.Subjects), len(tc.wantSubjects), tc.wantSubjects)
			}
		})
	}
}

// TestInvestigationAgentNeverRunsAsTheWriteIdentity is PROJECT.md E11's
// central RBAC claim, asserted against the rendered chart rather than
// described in a comment.
//
// The defect: with remediate.enabled, this chart bound ONE ServiceAccount to
// the UNION of argus-investigate and argus-remediate (a ClusterRoleBinding
// named argus-remediate-investigate) and ran the single agent as it. The
// model's read-only tool loop therefore ran under an identity that could
// patch Deployments and delete Pods — it was merely never offered a write
// tool. Non-negotiable 1 asks for structurally incapable, not un-asked.
//
// Two things have to stay true for that to be fixed, and both are checked
// here because either one alone is insufficient: the investigation
// Deployment must run as argus-investigate in EVERY configuration, and
// nothing may bind argus-investigate's read role onto the write identity (or
// vice versa).
func TestInvestigationAgentNeverRunsAsTheWriteIdentity(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  []string
	}{
		{"read-only", nil},
		{"remediation, namespaced", []string{"--set", "remediate.enabled=true", "--set", "remediate.namespaces={apps}"}},
		{"remediation, cluster-wide", []string{"--set", "remediate.enabled=true", "--set", "remediate.allNamespaces=true"}},
		{"remediation plus dry-run plus policy controller", []string{
			"--set", "remediate.enabled=true", "--set", "remediate.allNamespaces=true",
			"--set", "dryRun.enabled=true", "--set", "policyController.enabled=true",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplateRaw(t, tc.set...)
			if err != nil {
				t.Fatalf("helm template failed: %v\n%s", err, out)
			}

			deployments := decodeYAMLDocs[identityDeploymentObject](t, out, func(k string) bool { return k == "Deployment" })
			var investigation *identityDeploymentObject
			for i := range deployments {
				if deployments[i].Metadata.Name == "argus-agent" {
					investigation = &deployments[i]
				}
			}
			if investigation == nil {
				t.Fatal("no argus-agent Deployment rendered")
			}
			if got := investigation.Spec.Template.Spec.ServiceAccountName; got != "argus-investigate" {
				t.Errorf("the investigation agent runs as %q, want argus-investigate — an investigation path that runs under a write-capable identity is PROJECT.md E11's whole defect", got)
			}

			// Checked against the rendered OBJECTS, not the rendered text:
			// templates/clusterrolebinding.yaml carries a comment naming the
			// deleted binding so nobody re-adds it, and a substring search
			// would match that comment forever.
			for _, crb := range decodeYAMLDocs[identityBindingObject](t, out, func(k string) bool { return k == "ClusterRoleBinding" }) {
				if crb.Metadata.Name == "argus-remediate-investigate" {
					t.Error("the argus-remediate-investigate ClusterRoleBinding is back: it binds argus-investigate's read role onto the write ServiceAccount, which is exactly the union PROJECT.md E11 deleted")
				}
				for _, sub := range crb.Subjects {
					// Neither identity may be handed the other's role, in
					// either direction.
					if crb.RoleRef.Name == "argus-investigate" && sub.Name == "argus-remediate" {
						t.Errorf("ClusterRoleBinding %q gives the write identity argus-investigate's read role — that union is PROJECT.md E11's defect", crb.Metadata.Name)
					}
					if crb.RoleRef.Name == "argus-remediate" && sub.Name == "argus-investigate" {
						t.Errorf("ClusterRoleBinding %q gives the read-only identity argus-remediate's write role", crb.Metadata.Name)
					}
				}
			}
		})
	}
}

// TestEphemeralIdentityModeRendersNothingAndSaysSo proves the opt-out is a
// real opt-out: no Secret, no Role, no binding, and — critically — no env
// vars, since an agent that saw ARGUS_AGENT_IDENTITY_SECRET without the Role
// would refuse to start rather than fall back.
func TestEphemeralIdentityModeRendersNothingAndSaysSo(t *testing.T) {
	out, err := helmTemplateRaw(t, "--set", "identity.mode=ephemeral")
	if err != nil {
		t.Fatalf("helm template --set identity.mode=ephemeral failed: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "argus-agent-identity") {
		t.Error("identity.mode=ephemeral still renders identity objects")
	}
	if strings.Contains(string(out), "ARGUS_AGENT_IDENTITY_SECRET") {
		t.Error("identity.mode=ephemeral still sets ARGUS_AGENT_IDENTITY_SECRET — the agent would then refuse to start against a Secret this mode never created")
	}
}

// TestInvalidIdentityModeFailsTheRender is the "refuses to install in a
// configuration where it cannot" half of B163's acceptance criterion, at the
// one layer that can enforce it before anything reaches a cluster.
func TestInvalidIdentityModeFailsTheRender(t *testing.T) {
	out, err := helmTemplateRaw(t, "--set", "identity.mode=persistent")
	if err == nil {
		t.Fatalf("helm template accepted identity.mode=persistent:\n%s", out)
	}
	// The values schema refuses it first, naming the allowed values; the
	// template's own check is the backstop when a schema is bypassed.
	if !strings.Contains(string(out), "identity.mode must be") && !strings.Contains(string(out), "value must be one of 'secret', 'ephemeral'") {
		t.Errorf("the render failed without explaining which values are valid:\n%s", out)
	}
}

// TestPersistenceStillWorksAlongsideSecretIdentity is a regression guard on
// what B163 deliberately did NOT change: persistence.enabled is still
// available and still renders its PVC. The Secret replaced the DEFAULT, not
// the option.
func TestPersistenceStillWorksAlongsideSecretIdentity(t *testing.T) {
	out, err := helmTemplateRaw(t, "--set", "persistence.enabled=true")
	if err != nil {
		t.Fatalf("helm template --set persistence.enabled=true failed: %v\n%s", err, out)
	}
	pvcs := decodeYAMLDocs[pvcObject](t, out, func(k string) bool { return k == "PersistentVolumeClaim" })
	if len(pvcs) != 1 {
		t.Errorf("rendered %d PersistentVolumeClaim object(s) with persistence.enabled=true, want 1", len(pvcs))
	}
}

// TestAgentDeploymentSelectorsDoNotOverlap is a live-found defect, pinned.
//
// PROJECT.md E11 added a second agent Deployment. Given the same
// app.kubernetes.io/name and instance, the INVESTIGATION Deployment's
// selector — which is exactly those two labels, and is immutable after
// creation — also matches the REMEDIATION agent's pods. ReplicaSets survive
// it (their generated selector carries pod-template-hash), but anything that
// resolves a Deployment to pods by selector does not: `kubectl logs
// deploy/argus-agent` returned the remediation agent's log, observed on a
// real cluster.
func TestAgentDeploymentSelectorsDoNotOverlap(t *testing.T) {
	out, err := helmTemplateRaw(t, "--set", "remediate.enabled=true", "--set", "remediate.allNamespaces=true")
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, out)
	}
	deployments := decodeYAMLDocs[selectorDeploymentObject](t, out, func(k string) bool { return k == "Deployment" })
	if len(deployments) != 2 {
		t.Fatalf("rendered %d Deployments, want 2", len(deployments))
	}

	for i, a := range deployments {
		for j, b := range deployments {
			if i == j {
				continue
			}
			// a's selector must NOT match b's pod labels.
			matches := true
			for k, v := range a.Spec.Selector.MatchLabels {
				if b.Spec.Template.Metadata.Labels[k] != v {
					matches = false
					break
				}
			}
			if matches {
				t.Errorf("Deployment %q's selector %v matches Deployment %q's pod labels %v — overlapping selectors make `kubectl logs deploy/<name>` resolve to the wrong agent",
					a.Metadata.Name, a.Spec.Selector.MatchLabels, b.Metadata.Name, b.Spec.Template.Metadata.Labels)
			}
		}
	}
}

type selectorDeploymentObject struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		Selector struct {
			MatchLabels map[string]string `yaml:"matchLabels"`
		} `yaml:"selector"`
		Template struct {
			Metadata struct {
				Labels map[string]string `yaml:"labels"`
			} `yaml:"metadata"`
		} `yaml:"template"`
	} `yaml:"spec"`
}
