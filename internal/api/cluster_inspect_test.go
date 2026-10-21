package api

import (
	"testing"

	"argus/internal/tunnel"
)

// Every inspectable tool must be one the hub routes to the read-only
// investigation identity: the allowlist is the only gate between a person's
// request and the agent, so a write tool here would be a write path.
func TestInspectableToolsAreReadOnly(t *testing.T) {
	for tool := range inspectableTools {
		if role := tunnel.RoleForTool(tool); role != tunnel.RoleInvestigate {
			t.Errorf("inspectable tool %q routes to %q, want the investigation identity", tool, role)
		}
	}
	for _, tool := range []string{"list_helm_releases", "list_gitops_apps", "get_namespace_topology"} {
		if _, ok := inspectableTools[tool]; !ok {
			t.Errorf("%q is missing from the inspect allowlist (cluster page Helm/GitOps/Map tabs)", tool)
		}
	}
}
