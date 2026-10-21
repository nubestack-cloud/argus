package argusagentchart

// TestRemediateChartGrantsCreateOnCreateResourceKinds mirrors
// TestRemediateChartGrantsDeleteOnDeleteResourceKinds exactly, for
// BACKLOG.md F9's createResource action type: confirms the `create` RBAC
// verb on ConfigMap actually appears in the rendered chart, in both shapes
// (cluster-wide ClusterRole, namespace-scoped Role), that the two rule sets
// stay identical (templates/remediate-role.yaml's own header rule), and that
// remediate.enabled=false grants none of it.
//
// No live cluster involved — same `helm template` local-render approach
// chart_test.go/chart_deleteresource_test.go and the VAP file's own header
// comment already use for checks that don't need a real API server.
import "testing"

func TestRemediateChartGrantsCreateOnCreateResourceKinds(t *testing.T) {
	wants := []struct {
		name     string
		apiGroup string
		resource string
	}{
		{"ConfigMap", "", "configmaps"},
	}

	t.Run("cluster-wide (remediate.allNamespaces)", func(t *testing.T) {
		objs := helmTemplate(t,
			"--set", "remediate.enabled=true",
			"--set", "remediate.allNamespaces=true",
		)
		role := findRole(t, objs, "ClusterRole", "argus-remediate")
		for _, w := range wants {
			t.Run(w.name, func(t *testing.T) {
				if !hasRule(role.Rules, w.apiGroup, w.resource, "create") {
					t.Errorf("templates/clusterrole.yaml's argus-remediate ClusterRole does not grant create on %s/%s", w.apiGroup, w.resource)
				}
			})
		}
	})

	t.Run("namespace-scoped (remediate.namespaces)", func(t *testing.T) {
		objs := helmTemplate(t,
			"--set", "remediate.enabled=true",
			"--set", "remediate.namespaces={apps}",
		)
		role := findRole(t, objs, "Role", "argus-remediate")
		for _, w := range wants {
			t.Run(w.name, func(t *testing.T) {
				if !hasRule(role.Rules, w.apiGroup, w.resource, "create") {
					t.Errorf("templates/remediate-role.yaml's argus-remediate Role does not grant create on %s/%s — it must mirror templates/clusterrole.yaml exactly", w.apiGroup, w.resource)
				}
			})
		}
	})

	t.Run("remediate disabled grants none of it", func(t *testing.T) {
		objs := helmTemplate(t) // remediate.enabled defaults to false
		for _, o := range objs {
			if o.Metadata.Name == "argus-remediate" {
				t.Fatalf("an argus-remediate %s rendered with remediate.enabled left at its default (false)", o.Kind)
			}
		}
	})

	t.Run("never grants create on anything but ConfigMap", func(t *testing.T) {
		// The narrowness this task's own brief insists on: `create` must not
		// have been granted broadly as a side effect of adding this one row.
		objs := helmTemplate(t,
			"--set", "remediate.enabled=true",
			"--set", "remediate.allNamespaces=true",
		)
		role := findRole(t, objs, "ClusterRole", "argus-remediate")
		for _, r := range role.Rules {
			for _, verb := range r.Verbs {
				if verb != "create" {
					continue
				}
				if len(r.Resources) != 1 || r.Resources[0] != "configmaps" {
					t.Errorf("a rule grants create on %v, want create scoped to exactly [configmaps]", r.Resources)
				}
			}
		}
	})
}
