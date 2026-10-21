package llm

import (
	"encoding/json"
	"strings"
)

// insightToolDefs are the cluster-insight diagnosis tools
// (docs/CLUSTER_INSIGHT_SPECS.md CI-S3 and siblings). Each answers one
// question precisely from the agent's object cache, so the model does not
// have to infer it from raw YAML. They are appended to toolDefinitions at
// init, which makes them part of both backends' surface (the api loop's
// offeredToolDefinitions/isOfferedTool and the cli backend's MCP schemas are
// both projected from toolDefinitions) without a second list to keep in step.
//
// Every one is read-only and served by the investigation identity. An agent
// older than the tool answers "unknown tool"; an agent without the object
// cache says so — both reach the model as an ordinary tool error.
var insightToolDefs = []toolDef{
	{
		Type: "function",
		Function: toolFunctionDef{
			Name: "evaluate_network_policy",
			Description: "Statically evaluate whether Kubernetes NetworkPolicy objects would admit traffic " +
				"from a source (a pod, or outside any pod) to a destination Service or Pod on a port, and " +
				"which policies decide it. Verdict is allowed, denied or unknown — unknown is NOT 'not " +
				"blocked'. A static prediction over core NetworkPolicy only: the network plugin enforces, " +
				"and plugin-specific policy kinds are not evaluated. Use it when a connection timeout or " +
				"refusal might be a policy.",
			Parameters: json.RawMessage(`{
				"type": "object",
				"properties": {
					"source": {"type": "object", "properties": {
						"namespace": {"type": "string"},
						"pod": {"type": "string", "description": "Source pod name; omit (or set external) for traffic from outside any pod"},
						"external": {"type": "boolean"}
					}},
					"destination": {"type": "object", "properties": {
						"kind": {"type": "string", "enum": ["Service", "Pod"]},
						"namespace": {"type": "string"},
						"name": {"type": "string"}
					}, "required": ["namespace", "name"]},
					"port": {"type": "integer", "description": "Service port (for a Service) or container port (for a Pod)"},
					"protocol": {"type": "string", "description": "TCP (default), UDP or SCTP"}
				},
				"required": ["destination"]
			}`),
		},
	},
	{
		Type: "function",
		Function: toolFunctionDef{
			Name: "get_subject_permissions",
			Description: "What a ServiceAccount, User or Group can actually do: every RoleBinding/" +
				"ClusterRoleBinding that applies (including implicit groups such as " +
				"system:serviceaccounts), the effective rules ranked most-permissive first, and " +
				"blast-radius flags (cluster-admin, wildcard verbs, escalate/bind/impersonate, " +
				"cluster-wide create pods). Use it for 'forbidden' errors and to judge whether an " +
				"identity is over-privileged.",
			Parameters: json.RawMessage(`{
				"type": "object",
				"properties": {
					"kind": {"type": "string", "enum": ["ServiceAccount", "User", "Group"]},
					"namespace": {"type": "string", "description": "Required for a ServiceAccount"},
					"name": {"type": "string"}
				},
				"required": ["kind", "name"]
			}`),
		},
	},
	{
		Type: "function",
		Function: toolFunctionDef{
			Name: "diagnose_autoscaler",
			Description: "Explain a HorizontalPodAutoscaler's state: whether it is scaling, pinned at " +
				"its min or max, missing metrics, stale, or unable to scale — with the bounds, each " +
				"metric's current vs target, and the condition reasons behind the verdict.",
			Parameters: json.RawMessage(`{
				"type": "object",
				"properties": {"namespace": {"type": "string"}, "name": {"type": "string"}},
				"required": ["namespace", "name"]
			}`),
		},
	},
	{
		Type: "function",
		Function: toolFunctionDef{
			Name: "diagnose_rollout",
			Description: "Judge whether a Deployment's rolling-update settings (maxSurge, " +
				"maxUnavailable, replicas) can take every replica down at once or stall a rollout. " +
				"Returns atRisk, safe, notApplicable (with why) or unknown.",
			Parameters: json.RawMessage(`{
				"type": "object",
				"properties": {"namespace": {"type": "string"}, "name": {"type": "string"}},
				"required": ["namespace", "name"]
			}`),
		},
	},
	{
		Type: "function",
		Function: toolFunctionDef{
			Name: "trace_service_path",
			Description: "Trace the declared traffic path for a Service, Ingress, HTTPRoute, GRPCRoute or " +
				"Gateway — every entry pointing at it, then the chain down to ready pods — and name the " +
				"FIRST hop that breaks (brokenAt, headline) with findings such as no ready endpoints, " +
				"targetPort with no listener, missing backend Service/port, route not accepted, ingress " +
				"controller missing, or a NetworkPolicy that would deny. Each finding carries a kubectl " +
				"command reproducing it. Declared state only, unless probe is true: then, for a Service, the agent " +
				"also resolves its name, connects to its cluster IP and a few ready endpoints, and sends one HTTP " +
				"GET where the port looks like HTTP — status only, from the agent's own pod, which a NetworkPolicy " +
				"may treat differently from the real caller.",
			Parameters: json.RawMessage(`{
				"type": "object",
				"properties": {
					"kind": {"type": "string", "enum": ["Service", "Ingress", "HTTPRoute", "GRPCRoute", "Gateway"]},
					"namespace": {"type": "string"},
					"name": {"type": "string"},
					"probe": {"type": "boolean", "description": "Service only: also send one round of real traffic along the path"}
				},
				"required": ["kind", "name"]
			}`),
		},
	},
	{
		Type: "function",
		Function: toolFunctionDef{
			Name: "explain_scheduling",
			Description: "For a Pending pod: evaluate every node and group them by the first requirement " +
				"each fails (cordoned, untolerated taint, nodeSelector/affinity, insufficient cpu/memory/" +
				"pods — with how much is needed vs the most free), parse the scheduler's FailedScheduling " +
				"message, and count identical pending pods. Use it instead of reading node lists by hand.",
			Parameters: json.RawMessage(`{
				"type": "object",
				"properties": {"namespace": {"type": "string"}, "pod": {"type": "string"}},
				"required": ["namespace", "pod"]
			}`),
		},
	},
	{
		Type: "function",
		Function: toolFunctionDef{
			Name: "get_drain_impact",
			Description: "For a Node (NotReady, cordoned, or about to be replaced): what draining it would do. " +
				"Pods evicted per workload with how many Ready replicas each has on other nodes (zero means " +
				"the workload goes unavailable), PodDisruptionBudgets that would hold the drain, emptyDir data " +
				"lost, pods with no controller that will not come back, and DaemonSet/static pods that stay. " +
				"Read-only: nothing is cordoned or evicted.",
			Parameters: json.RawMessage(`{
				"type": "object",
				"properties": {"node": {"type": "string"}},
				"required": ["node"]
			}`),
		},
	},
	{
		Type: "function",
		Function: toolFunctionDef{
			Name: "get_karpenter_capacity",
			Description: "On a cluster running Karpenter: every NodePool's limits against what it has provisioned, its " +
				"NodeClaims by phase (Pending, Launched, Registered, Initialized, Ready, Terminating), and the pending " +
				"pods grouped by scheduling signature with each pool's verdict — which pool could launch a node for " +
				"them, or why none can (selector, affinity, taint, or a reached limit). explain_scheduling gives the " +
				"same per-pool verdict for one pod.",
			Parameters: json.RawMessage(`{"type": "object", "properties": {}}`),
		},
	},
	{
		Type: "function",
		Function: toolFunctionDef{
			Name: "get_rightsizing",
			Description: "Each container's CPU and memory requests and limits against its measured p95 usage " +
				"(and peak memory) over a window, from the cluster's Prometheus, with a recommended request " +
				"(p95 plus 20% headroom, never below peak memory) and a verdict: over, under, fits or " +
				"noRequest. Use it before proposing PatchResourceLimits so the values are measured, not " +
				"guessed. Pod-level resources are reported as such with no per-container recommendation.",
			Parameters: json.RawMessage(`{
				"type": "object",
				"properties": {
					"namespace": {"type": "string"},
					"workload": {"type": "string", "description": "Optional workload name to narrow to"},
					"windowDays": {"type": "integer", "description": "1-14, default 7"}
				},
				"required": ["namespace"]
			}`),
		},
	},
	{
		Type: "function",
		Function: toolFunctionDef{
			Name: "get_gitops_insight",
			Description: "For an Argo CD Application or a Flux Kustomization/HelmRelease/source: sync and " +
				"health, the operation's failure parsed into a plain cause (namespace missing, CRD not " +
				"installed, admission denied, field immutable, hook failed, RBAC forbidden, ...), whether " +
				"it is stuck retrying, conditions with suggested actions, and its managed resources. For " +
				"a GitOps-managed object (e.g. a Deployment): which fields drift from the configuration " +
				"the controller last applied, when that is known.",
			Parameters: json.RawMessage(`{
				"type": "object",
				"properties": {
					"group": {"type": "string", "description": "API group; optional for the GitOps kinds"},
					"kind": {"type": "string"},
					"namespace": {"type": "string"},
					"name": {"type": "string"}
				},
				"required": ["kind", "name"]
			}`),
		},
	},
	{
		Type: "function",
		Function: toolFunctionDef{
			Name: "get_policy_findings",
			Description: "Policy-engine results (Kyverno and other PolicyReport producers) for one object: " +
				"which policies and rules pass, warn or fail for it. Often the hidden reason a deploy was " +
				"blocked or flagged. Empty when no engine reports on the object.",
			Parameters: json.RawMessage(`{
				"type": "object",
				"properties": {
					"group": {"type": "string"}, "kind": {"type": "string"},
					"namespace": {"type": "string"}, "name": {"type": "string"}
				},
				"required": ["kind", "name"]
			}`),
		},
	},
	{
		Type: "function",
		Function: toolFunctionDef{
			Name: "get_traffic",
			Description: "Service-to-service traffic from this cluster's Prometheus when it carries Istio " +
				"or Beyla metrics: per edge, request rate, 5xx error rate and bytes rate over a window. " +
				"Reports available=false with a reason when no traffic source exists. Use it to find which " +
				"callers of a failing service are seeing errors. With compareMinutes, each edge also carries " +
				"`before` (the same window that long ago), and edges that carried traffic then and none now " +
				"are marked stopped: use it to see whether traffic to or from a workload dropped or stopped.",
			Parameters: json.RawMessage(`{
				"type": "object",
				"properties": {
					"namespace": {"type": "string", "description": "Limit to edges touching this namespace"},
					"windowMinutes": {"type": "integer", "description": "Rate window, 1-60; default 5"},
					"compareMinutes": {"type": "integer", "description": "Also read the same window this many minutes earlier, e.g. 60 or 1440; 0 or absent for none"}
				}
			}`),
		},
	},
	{
		Type: "function",
		Function: toolFunctionDef{
			Name: "get_neighborhood",
			Description: "The objects around one object and how they connect: what owns it (ReplicaSet → " +
				"Deployment), what routes traffic to it (Ingress/HTTPRoute → Service), what it uses " +
				"(ConfigMaps, PVCs, ServiceAccount, the Node), and what protects or scales it (PDB, " +
				"NetworkPolicy, HPA) — each node with its health. One or two hops; capped. Use it to see " +
				"blast radius and the wiring around a failing object in one call.",
			Parameters: json.RawMessage(`{
				"type": "object",
				"properties": {
					"kind": {"type": "string"}, "apiGroup": {"type": "string"},
					"namespace": {"type": "string"}, "name": {"type": "string"},
					"hops": {"type": "integer", "description": "1 (default) or 2"}
				},
				"required": ["kind", "name"]
			}`),
		},
	},
	{
		Type: "function",
		Function: toolFunctionDef{
			Name: "get_helm_release_status",
			Description: "A Helm release's latest revision and recent history (revision, status, when), " +
				"with failed installs/upgrades, failures later superseded, and operations stuck in " +
				"pending-install/upgrade/rollback (which block every later helm upgrade with 'another " +
				"operation is in progress'). Read from release metadata only — chart version, values " +
				"and manifests are not available.",
			Parameters: json.RawMessage(`{
				"type": "object",
				"properties": {"namespace": {"type": "string"}, "name": {"type": "string", "description": "Release name (the meta.helm.sh/release-name annotation)"}},
				"required": ["namespace", "name"]
			}`),
		},
	},
}

// RecentChangesToolName is served by the hub from its own change history
// (internal/api.CallRecentChanges), not over the tunnel.
const RecentChangesToolName = "get_recent_changes"

var recentChangesToolDef = toolDef{
	Type: "function",
	Function: toolFunctionDef{
		Name: RecentChangesToolName,
		Description: "What changed in this cluster recently, from ARGUS's recorded change history: " +
			"field-level diffs such as an image going from v1.4 to v1.5, replicas scaled, a ConfigMap key " +
			"modified, a Service selector edited — with when each happened. Narrow to one object " +
			"(kind+namespace+name; changes to objects it owns are included) or a namespace. Most " +
			"incidents follow a change: call this early. Values of env vars and ConfigMap keys are " +
			"never shown, only that they changed.",
		Parameters: json.RawMessage(`{
			"type": "object",
			"properties": {
				"namespace": {"type": "string"},
				"kind": {"type": "string"},
				"name": {"type": "string"},
				"sinceMinutes": {"type": "integer", "description": "How far back; default 180, max 1440"}
			}
		}`),
	},
}

func init() {
	toolDefinitions = append(toolDefinitions, insightToolDefs...)
	toolDefinitions = append(toolDefinitions, recentChangesToolDef)
}

// insightToolsPreamble names the diagnosis tools in the system prompt, read
// off insightToolDefs so the sentence cannot list a tool that is not offered.
func insightToolsPreamble() string {
	if len(insightToolDefs) == 0 {
		return ""
	}
	names := make([]string, 0, len(insightToolDefs)+1)
	for _, t := range insightToolDefs {
		names = append(names, t.Function.Name)
	}
	names = append(names, RecentChangesToolName)
	return " You also have precise read-only diagnosis tools that answer specific questions from the agent's live object cache: " +
		strings.Join(names, ", ") +
		". Prefer them over inferring the same answer from raw YAML; each response carries a coverage list naming any kind the agent could not see, and an answer computed over incomplete coverage is not proof of absence."
}
