package api

// The user-facing MCP endpoint (PROJECT.md AD3): POST /api/v1/mcp, for a
// person's OWN AI tool — Claude Code, Cursor, VS Code — authenticated by a
// personal access token (personal_tokens.go).
//
// It is the same server code as the CLI runner's listener (internal/mcp's
// Server: JSON-RPC handling, the per-grant tool allowlist, observe), mounted a
// second time with a different Authenticator and a different ToolFunc. What
// differs is who the caller is:
//
//   - The CLI runner's token is scoped to ONE cluster and ONE investigation,
//     and the cluster comes from the token.
//   - A personal token is scoped to a PERSON. The cluster is an argument, and
//     every call re-resolves that person's grants and checks the tool's own
//     capability on that cluster — the same check the equivalent REST route
//     makes (lld/01-threat-model.md non-negotiable 3: MCP is an integration
//     protocol, never an authorization boundary; scope is bound server-side
//     to the actor).
//
// READ-ONLY BY CONSTRUCTION, three ways:
//
//  1. The surface (userMCPCatalogue) contains only list/get/search tools and
//     POST /clusters/{id}/inspect's own allowlist (inspectableTools). No
//     remediation action, approval, dry-run, triage or settings tool is in
//     it, so none is reachable however the client asks — internal/mcp
//     refuses a name outside the grant before this file sees it.
//  2. Every hub-side tool runs its REST handler inside a transaction that is
//     ALWAYS rolled back, so even a handler that grew a write would persist
//     nothing through this path.
//  3. Cluster tools go to the agent's read-only investigation identity
//     (argus-investigate), whose output ToolExecutor.Execute has already
//     redacted at capture (argus-context non-negotiable 9).
//
// AUDIT. Every call — allowed, refused for a missing capability, refused as
// off-surface, failed — writes one audit_events row (actor, token id, tool,
// cluster, outcome) to the hash chain. mcp_tool_calls is NOT written: that
// table is keyed to an incident (incident_id NOT NULL) and feeds an
// investigation's evidence summary and the blast-radius budget, and a
// person's ad-hoc question belongs to neither.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/gateway"
	"argus/internal/llm"
	"argus/internal/logging"
	"argus/internal/mcp"
)

// maxUserMCPResultBytes bounds one tool result. An MCP client puts the whole
// result into a model's context; past this size the useful move is a narrower
// question, and saying so is better than a silently clipped JSON document.
const maxUserMCPResultBytes = 1 << 20

// Per-token rate limit: a burst of userMCPBurst calls, refilled at
// userMCPPerMinute a minute. Sized for a person's AI tool working through a
// problem (a few calls a second for a while), not for a script walking the
// fleet — every cluster tool is a round trip to a live agent.
const (
	userMCPBurst     = 30
	userMCPPerMinute = 60
)

// mcpAuthMethod is audit_events.actor_auth_method for a call made with a
// personal access token.
const mcpAuthMethod = "mcp_token"

// userMCPTool is one tool on the user-facing surface.
type userMCPTool struct {
	name        string
	description string
	// capability is what the caller must hold. For a clusterScoped tool it is
	// checked on the named cluster; otherwise org-wide, with RLS narrowing
	// the rows to the caller's clusters exactly as on the REST route.
	capability    string
	clusterScoped bool
	// properties/required are the tool's own arguments, excluding clusterId
	// (added for clusterScoped tools).
	properties map[string]any
	required   []string
	// run executes the call. args has already been checked against
	// properties; clusterID is the resolved cluster for a clusterScoped tool.
	run func(ctx context.Context, s *Server, rc *requestContext, cluster resolvedCluster, args map[string]any, raw json.RawMessage) (json.RawMessage, error)
}

type resolvedCluster struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func strProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}
func enumProp(desc string, values []string) map[string]any {
	return map[string]any{"type": "string", "description": desc, "enum": values}
}

// clusterIDProp is the argument every cluster tool takes.
var clusterIDProp = strProp("The cluster to ask: its id (cl_…) or its display name, as list_clusters returns them.")

// userMCPCatalogue is the whole user-facing surface, in the order tools/list
// shows it. Built per call rather than once at init so it always reflects
// inspectableTools as it is now.
func userMCPCatalogue() []userMCPTool {
	limitProp := func(def, max int) map[string]any {
		return map[string]any{"type": "integer", "minimum": 1, "maximum": max,
			"description": fmt.Sprintf("Page size; default %d, at most %d. Pass nextCursor from a previous response as cursor to read further.", def, max)}
	}
	tools := []userMCPTool{
		{
			name: "list_clusters",
			description: "List the Kubernetes clusters enrolled in ARGUS that you can see, with each one's id, " +
				"display name, connection state and agent version. Start here: every cluster tool takes a clusterId " +
				"(or the display name) from this list. Needs cluster:read.",
			capability: authz.CapClusterRead,
			properties: map[string]any{
				"archived": enumProp("Which clusters: exclude (default) leaves decommissioned clusters out, only lists just those, include lists both.", []string{"exclude", "include", "only"}),
			},
			run: handlerTool(func(s *Server) handlerFunc { return s.handleListClusters }, nil, []string{"archived"}, nil),
		},
		{
			name:          "get_cluster",
			description:   "One cluster's detail: state, last check-in, agent and Kubernetes versions, and the facts its agent last reported. Needs cluster:read on that cluster.",
			capability:    authz.CapClusterRead,
			clusterScoped: true,
			run: func(ctx context.Context, s *Server, rc *requestContext, c resolvedCluster, _ map[string]any, _ json.RawMessage) (json.RawMessage, error) {
				return s.runReadHandler(ctx, rc, s.handleGetCluster, map[string]string{"id": c.ID}, nil)
			},
		},
		{
			name: "list_incidents",
			description: "List or search ARGUS incidents (what ARGUS raised from its detectors), newest activity first. " +
				"Each row has id, cluster, object, severity, state and opening reason; filter by cluster, state, severity, " +
				"or free text. Use get_incident for one incident's analysis. Needs incident:read.",
			capability: authz.CapIncidentRead,
			properties: map[string]any{
				"clusterId":      strProp("Only incidents on this cluster (id from list_clusters)."),
				"state":          enumProp("Only incidents in this lifecycle state.", validIncidentStates),
				"severity":       enumProp("Only incidents of this severity.", validIncidentSeverities),
				"requiresAction": map[string]any{"type": "boolean", "description": "true: only incidents waiting on a person; false: only those that are not."},
				"search":         strProp("Free-text match against the object, cluster name, opening reason and incident id."),
				"limit":          limitProp(25, 200),
				"cursor":         strProp("nextCursor from a previous page."),
			},
			run: handlerTool(func(s *Server) handlerFunc { return s.handleListIncidents },
				nil, []string{"clusterId", "state", "severity", "requiresAction", "search", "limit", "cursor"}, map[string]string{"limit": "25"}),
		},
		{
			name: "get_incident",
			description: "One incident in full: the affected object, its findings, and the latest AI analysis (root cause, " +
				"causal chain with evidence references, what was ruled out, confidence) plus any proposed remediation and its " +
				"state. The analysis is model-written and says so; treat it as a claim to check, not a fact. Needs incident:read.",
			capability: authz.CapIncidentRead,
			properties: map[string]any{"incidentId": strProp("The incident id (inc_…), from list_incidents.")},
			required:   []string{"incidentId"},
			run:        handlerTool(func(s *Server) handlerFunc { return s.handleGetIncident }, map[string]string{"id": "incidentId"}, nil, nil),
		},
		{
			name:        "get_incident_timeline",
			description: "The chronology of one incident: detection, each analysis run, approvals, executions and validation, with timestamps. Needs incident:read.",
			capability:  authz.CapIncidentRead,
			properties:  map[string]any{"incidentId": strProp("The incident id (inc_…).")},
			required:    []string{"incidentId"},
			run:         handlerTool(func(s *Server) handlerFunc { return s.handleGetIncidentTimeline }, map[string]string{"id": "incidentId"}, nil, nil),
		},
		{
			name: "list_findings",
			description: "List signals (findings): everything ARGUS's detectors observed, including what it deliberately did NOT " +
				"raise as an incident, with each finding's class, confidence, impact and disposition, newest first. Defaults to " +
				"the last 24 hours. Needs incident:read.",
			capability: authz.CapIncidentRead,
			properties: map[string]any{
				"clusterId":   strProp("Only findings on this cluster (id from list_clusters)."),
				"reason":      strProp("Only findings with exactly this reason, e.g. CrashLoopBackOff."),
				"class":       enumProp("Only findings of this signal class.", gateway.FindingClasses()),
				"confidence":  enumProp("Only findings of this confidence.", gateway.FindingConfidences()),
				"impact":      enumProp("Only findings of this impact.", gateway.FindingImpacts()),
				"disposition": enumProp("What ARGUS did with the finding.", validFindingDispositions),
				"since":       strProp("RFC 3339 start of the window; default 24 hours ago."),
				"until":       strProp("RFC 3339 end of the window; default now."),
				"limit":       limitProp(50, 200),
				"cursor":      strProp("nextCursor from a previous page."),
			},
			run: handlerTool(func(s *Server) handlerFunc { return s.handleListFindings },
				nil, []string{"clusterId", "reason", "class", "confidence", "impact", "disposition", "since", "until", "limit", "cursor"}, map[string]string{"limit": "50"}),
		},
		{
			name: "search_fleet_objects",
			description: "Find Kubernetes objects by name, label or image across every connected cluster you may inspect. " +
				"Each hit names its cluster, kind, namespace and name; the response also lists clusters that did not answer, " +
				"so a partial result never reads as complete. Needs cluster:inspect (each cluster is checked separately).",
			capability: authz.CapClusterInspect,
			properties: map[string]any{"query": strProp("Up to 200 characters: an object name, label (key=value) or image.")},
			required:   []string{"query"},
			run: handlerTool(func(s *Server) handlerFunc { return s.handleSearch }, nil, nil, nil,
				withQueryRename("query", "q")),
		},
	}

	names := make([]string, 0, len(inspectableTools))
	for name := range inspectableTools {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		tools = append(tools, inspectTool(name))
	}
	return tools
}

// handlerFunc is an internal/api route handler.
type handlerFunc = func(http.ResponseWriter, *http.Request, *requestContext)

type handlerToolOption func(*handlerToolConfig)

type handlerToolConfig struct{ rename map[string]string }

// withQueryRename maps a tool argument onto a differently named query
// parameter (search's "q" reads badly as a tool argument).
func withQueryRename(arg, param string) handlerToolOption {
	return func(c *handlerToolConfig) {
		if c.rename == nil {
			c.rename = map[string]string{}
		}
		c.rename[arg] = param
	}
}

// handlerTool runs a REST handler as the tool: pathArgs maps a path value to
// the argument that fills it, queryArgs are passed as query parameters
// (plus any argument named in a withQueryRename), and defaults fill an absent
// query parameter.
func handlerTool(handler func(*Server) handlerFunc, pathArgs map[string]string, queryArgs []string, defaults map[string]string, opts ...handlerToolOption) func(context.Context, *Server, *requestContext, resolvedCluster, map[string]any, json.RawMessage) (json.RawMessage, error) {
	var cfg handlerToolConfig
	for _, o := range opts {
		o(&cfg)
	}
	return func(ctx context.Context, s *Server, rc *requestContext, _ resolvedCluster, args map[string]any, _ json.RawMessage) (json.RawMessage, error) {
		path := map[string]string{}
		for pv, arg := range pathArgs {
			v, _ := args[arg].(string)
			path[pv] = v
		}
		q := url.Values{}
		for _, arg := range queryArgs {
			if v, ok := args[arg]; ok {
				q.Set(arg, queryValue(v))
			}
		}
		for arg, param := range cfg.rename {
			if v, ok := args[arg]; ok {
				q.Set(param, queryValue(v))
			}
		}
		for k, v := range defaults {
			if q.Get(k) == "" {
				q.Set(k, v)
			}
		}
		return s.runReadHandler(ctx, rc, handler(s), path, q)
	}
}

func queryValue(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		if t == math.Trunc(t) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

// inspectSchemas are the argument shapes of the inspect tools that are not
// also investigation tools (whose schemas come from internal/llm, below).
// Each mirrors the agent-side argument struct the tool decodes.
var inspectSchemas = map[string]struct {
	description string
	properties  map[string]any
	required    []string
}{
	"get_neighborhood": {
		"The objects related to one object (owners, children, selecting Services, attached policies, mounted volumes, nodes), as a graph of nodes and typed edges.",
		map[string]any{
			"kind": strProp("e.g. Deployment, Pod, Service"), "apiGroup": strProp("API group; empty for core kinds"),
			"namespace": strProp("Namespace (omit for cluster-scoped kinds)"), "name": strProp("Object name"),
			"hops":     map[string]any{"type": "integer", "minimum": 1, "maximum": 2, "description": "Relationship depth; default 1, at most 2"},
			"maxNodes": map[string]any{"type": "integer", "minimum": 1, "description": "Cap on nodes returned; default 25"},
			"profile":  enumProp("auto (default) follows the relationships that matter for this kind; all follows every edge", []string{"auto", "all"}),
		},
		[]string{"kind", "name"},
	},
	"trace_service_path": {
		"Trace a request path from an entry point (Service, Ingress, HTTPRoute, GRPCRoute or Gateway) to its backend pods, naming the first broken hop and each hop's state.",
		map[string]any{
			"kind":      enumProp("Entry point kind", []string{"Service", "Ingress", "HTTPRoute", "GRPCRoute", "Gateway"}),
			"namespace": strProp("Namespace"), "name": strProp("Name"),
			"probe": map[string]any{"type": "boolean", "description": "Service only: also send one round of real traffic (DNS, TCP, one HTTP GET) from the agent's pod"},
		},
		[]string{"kind", "name"},
	},
	"evaluate_network_policy": {
		"Would NetworkPolicy allow traffic from a source pod (or outside the cluster) to a destination Service or Pod on a port? Returns allowed/denied/depends and the policies that decide it.",
		map[string]any{
			"source": map[string]any{"type": "object", "properties": map[string]any{
				"namespace": strProp("Source namespace"), "pod": strProp("Source pod name"),
				"external": map[string]any{"type": "boolean", "description": "true for traffic from outside the cluster"},
			}},
			"destination": map[string]any{"type": "object", "properties": map[string]any{
				"kind": enumProp("Destination kind", []string{"Service", "Pod"}), "namespace": strProp("Destination namespace"), "name": strProp("Destination name"),
			}},
			"port":     map[string]any{"type": "integer", "description": "Destination port"},
			"protocol": enumProp("Protocol; default TCP", []string{"TCP", "UDP", "SCTP"}),
		},
		[]string{"source", "destination"},
	},
	"get_subject_permissions": {
		"What a ServiceAccount, User or Group may do in the cluster, from its RoleBindings and ClusterRoleBindings.",
		map[string]any{
			"kind":      enumProp("Subject kind", []string{"ServiceAccount", "User", "Group"}),
			"namespace": strProp("Namespace (ServiceAccount only)"), "name": strProp("Subject name"),
		},
		[]string{"kind", "name"},
	},
	"diagnose_autoscaler": {
		"Why a HorizontalPodAutoscaler is (or is not) scaling: its metrics, targets, limits and conditions, explained.",
		map[string]any{"namespace": strProp("Namespace"), "name": strProp("HorizontalPodAutoscaler name")},
		[]string{"namespace", "name"},
	},
	"diagnose_rollout": {
		"Why a Deployment's rollout is stuck or progressing: its ReplicaSets, conditions and the pods holding it back.",
		map[string]any{"namespace": strProp("Namespace"), "name": strProp("Deployment name")},
		[]string{"namespace", "name"},
	},
	"explain_scheduling": {
		"Why a Pod is not scheduled (or where it went): node fit, taints, affinity, resources and the scheduler's own message.",
		map[string]any{"namespace": strProp("Namespace"), "pod": strProp("Pod name")},
		[]string{"namespace", "pod"},
	},
	"get_drain_impact": {
		"What draining a node would do: pods evicted per workload, workloads left with no ready replica, PodDisruptionBudgets that would hold the drain, emptyDir data lost, pods with no controller, and what stays.",
		map[string]any{"node": strProp("Node name")},
		[]string{"node"},
	},
	"get_karpenter_capacity": {
		"Karpenter NodePools: each pool's limit against what it has provisioned, its NodeClaims by phase, and the pending pods it could or could not take.",
		map[string]any{},
		nil,
	},
	"get_rightsizing": {
		"Each container's CPU and memory requests against its p95 usage over a window, with a recommended request and whether it is over- or under-provisioned.",
		map[string]any{"namespace": strProp("Namespace"), "workload": strProp("Workload name, to narrow to one")},
		[]string{"namespace"},
	},
	"get_policy_findings": {
		"Policy-engine reports (e.g. Kyverno PolicyReports) that concern one object.",
		map[string]any{"group": strProp("API group; empty for core kinds"), "kind": strProp("Object kind"), "namespace": strProp("Namespace"), "name": strProp("Object name")},
		[]string{"kind", "name"},
	},
	"get_gitops_insight": {
		"The Argo CD / Flux / Fleet object that owns a resource, with its sync and health state and source revision.",
		map[string]any{"group": strProp("API group; empty for core kinds"), "kind": strProp("Object kind"), "namespace": strProp("Namespace"), "name": strProp("Object name")},
		[]string{"kind", "name"},
	},
	"get_helm_release_status": {
		"A Helm release's status, chart, app version and revision history (values are not returned).",
		map[string]any{"namespace": strProp("Release namespace"), "name": strProp("Release name")},
		[]string{"namespace", "name"},
	},
	"get_upgrade_readiness": {
		"Upgrade-readiness check of the cluster for a target Kubernetes version: deprecated APIs in use, add-on compatibility, and a verdict.",
		map[string]any{"targetVersion": strProp("Target Kubernetes version, e.g. v1.32; default the next minor")},
		nil,
	},
	"get_traffic": {
		"Observed service-to-service traffic in a namespace over a recent window, where the cluster reports it.",
		map[string]any{"namespace": strProp("Namespace"), "windowMinutes": map[string]any{"type": "integer", "minimum": 1, "description": "Window in minutes"}},
		nil,
	},
	"get_cost_summary": {
		"Estimated resource cost by owner over a recent window, where the cluster reports usage.",
		map[string]any{"namespace": strProp("Namespace; omit for the whole cluster"), "windowHours": map[string]any{"type": "integer", "minimum": 1, "description": "Window in hours"}},
		nil,
	},
	"search_objects": {
		"Find objects in this one cluster by name, label or image (use search_fleet_objects to search every cluster).",
		map[string]any{"query": strProp("Name, label (key=value) or image"), "namespace": strProp("Only this namespace"), "limit": map[string]any{"type": "integer", "minimum": 1, "description": "Max hits"}},
		[]string{"query"},
	},
	"get_posture_findings": {
		"Security-posture findings (privileged pods, host mounts, missing limits and similar) in the cluster or one namespace.",
		map[string]any{"namespace": strProp("Namespace; omit for the whole cluster"), "checkId": strProp("Only this check"), "category": strProp("Only this category"), "limit": map[string]any{"type": "integer", "minimum": 1, "description": "Max findings"}},
		nil,
	},
	"list_certificates": {
		"TLS certificates the cluster serves or stores references to, with issuer and expiry (no key material).",
		map[string]any{"namespace": strProp("Namespace; omit for the whole cluster")},
		nil,
	},
}

// inspectTool builds the user-surface entry for one POST
// /clusters/{id}/inspect tool. Its schema comes from internal/llm when it is
// also an investigation tool (one definition, not two), from inspectSchemas
// otherwise, and falls back to an open object for a tool added to
// inspectableTools without a schema here — the agent validates its own
// arguments either way, so the fallback is a weaker hint, never a wider
// permission.
func inspectTool(name string) userMCPTool {
	t := userMCPTool{
		name:          name,
		capability:    authz.CapClusterInspect,
		clusterScoped: true,
		run:           runInspectTool(name),
	}
	if spec, ok := inspectSchemas[name]; ok {
		t.description, t.properties, t.required = spec.description, spec.properties, spec.required
	} else if schema, ok := investigationSchema(name); ok {
		t.description = schema.Description
		var parsed struct {
			Properties map[string]any `json:"properties"`
			Required   []string       `json:"required"`
		}
		_ = json.Unmarshal(schema.InputSchema, &parsed)
		t.properties, t.required = parsed.Properties, parsed.Required
	} else {
		t.description = "Read-only cluster inspection: " + strings.ReplaceAll(name, "_", " ") + "."
	}
	if inspectableTools[name].audited {
		t.description += " Every read is recorded in the ARGUS audit log."
	}
	t.description += " Needs cluster:inspect on that cluster."
	return t
}

func investigationSchema(name string) (llm.ToolSchema, bool) {
	for _, s := range llm.InvestigationToolSchemas() {
		if s.Name == name {
			return s, true
		}
	}
	return llm.ToolSchema{}, false
}

func runInspectTool(name string) func(context.Context, *Server, *requestContext, resolvedCluster, map[string]any, json.RawMessage) (json.RawMessage, error) {
	return func(ctx context.Context, s *Server, _ *requestContext, c resolvedCluster, args map[string]any, _ json.RawMessage) (json.RawMessage, error) {
		if !s.gw.IsConnected(c.ID) {
			return nil, fmt.Errorf("cluster %s (%s) is not connected to ARGUS right now, so live detail cannot be read; list_clusters shows each cluster's state", c.Name, c.ID)
		}
		forward := make(map[string]any, len(args))
		for k, v := range args {
			if k != "clusterId" {
				forward[k] = v
			}
		}
		body, err := json.Marshal(forward)
		if err != nil {
			return nil, fmt.Errorf("could not encode the arguments")
		}
		callCtx, cancel := context.WithTimeout(ctx, inspectCallTimeout)
		defer cancel()
		raw, err := s.gw.CallTool(callCtx, c.ID, name, body)
		if err != nil {
			// The agent's own message ("Deployment x/y not found", a missing
			// argument) is what the caller needs to correct the question; it
			// is agent text the CLI runner's surface already passes through,
			// never a hub-internal error.
			return nil, fmt.Errorf("the cluster's agent could not answer: %v", err)
		}
		return json.Marshal(map[string]any{
			"cluster":    c,
			"tool":       name,
			"receivedAt": time.Now().UTC(),
			"result":     raw,
		})
	}
}

// runReadHandler runs one REST handler as rc's user and returns its JSON body.
// The handler sees exactly what the REST route would hand it after
// requireAuth: the same requestContext shape, scoped transaction and path
// values. A problem response becomes an error carrying its title and detail.
func (s *Server) runReadHandler(ctx context.Context, rc *requestContext, h handlerFunc, pathValues map[string]string, query url.Values) (json.RawMessage, error) {
	target := "/api/v1/mcp-internal"
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(withRequestContext(ctx, rc), http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("could not build the request")
	}
	for k, v := range pathValues {
		req.SetPathValue(k, v)
	}
	buf := newBufferedResponseWriter()
	buf.Header().Set(RequestIDHeader, rc.RequestID)
	h(buf, req, rc)
	body := buf.body.Bytes()
	if buf.status >= 400 {
		var problem struct {
			Title  string `json:"title"`
			Detail string `json:"detail"`
		}
		_ = json.Unmarshal(body, &problem)
		if buf.status >= 500 {
			return nil, fmt.Errorf("the hub could not answer this (internal error, request id %s)", rc.RequestID)
		}
		msg := problem.Title
		if problem.Detail != "" {
			msg += ": " + problem.Detail
		}
		if msg == "" {
			msg = http.StatusText(buf.status)
		}
		return nil, errors.New(msg)
	}
	return json.RawMessage(body), nil
}

// mcpCapabilityError is a tool call refused because the caller lacks the
// tool's capability (on the named cluster, for a cluster tool). Its message
// is what the client sees, so it names the capability.
type mcpCapabilityError struct {
	tool, capability, clusterID string
}

func (e *mcpCapabilityError) Error() string {
	if e.clusterID != "" {
		return fmt.Sprintf("permission denied: %s needs the %s capability on cluster %s, and your ARGUS account does not hold it there. An ARGUS administrator can grant a role that includes it.", e.tool, e.capability, e.clusterID)
	}
	return fmt.Sprintf("permission denied: %s needs the %s capability, and your ARGUS account does not hold it. An ARGUS administrator can grant a role that includes it.", e.tool, e.capability)
}

// errToolNotOffered is a call for a name outside the user surface — a
// remediation action, say. Audited as a denial.
var errToolNotOffered = errors.New("this tool is not offered on the personal MCP endpoint, which serves read-only tools only")

// mcpArgumentError is a tool call refused for its arguments.
// lookup marks a well-formed argument that names nothing the caller can see
// (a cluster), which reads better without the "invalid arguments" prefix.
type mcpArgumentError struct {
	msg    string
	lookup bool
}

func (e *mcpArgumentError) Error() string {
	if e.lookup {
		return e.msg
	}
	return "invalid arguments: " + e.msg
}

// checkUserMCPArgs validates raw arguments against a tool's declared
// properties: it must be an object, every required argument present, and
// no argument the tool does not declare. Strict on purpose — a misspelt
// filter ("status" for "state") silently ignored would answer a different
// question than the one asked.
func checkUserMCPArgs(t userMCPTool, raw json.RawMessage) (map[string]any, error) {
	args := map[string]any{}
	if len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, &mcpArgumentError{msg: "arguments must be a JSON object"}
		}
	}
	allowed := map[string]bool{}
	for k := range t.properties {
		allowed[k] = true
	}
	if t.clusterScoped {
		allowed["clusterId"] = true
		if _, ok := args["clusterId"]; !ok {
			return nil, &mcpArgumentError{msg: "clusterId is required (an id or display name from list_clusters)"}
		}
	}
	for k := range args {
		if !allowed[k] {
			names := make([]string, 0, len(allowed))
			for n := range allowed {
				names = append(names, n)
			}
			sort.Strings(names)
			return nil, &mcpArgumentError{msg: fmt.Sprintf("%s does not take %q; it accepts: %s", t.name, k, strings.Join(names, ", "))}
		}
	}
	for _, k := range t.required {
		v, ok := args[k]
		if !ok || v == nil || v == "" {
			return nil, &mcpArgumentError{msg: fmt.Sprintf("%s is required", k)}
		}
	}
	for k, v := range args {
		prop, _ := t.properties[k].(map[string]any)
		if prop == nil {
			continue
		}
		if enum, ok := prop["enum"].([]string); ok {
			s, _ := v.(string)
			if !slices.Contains(enum, s) {
				return nil, &mcpArgumentError{msg: fmt.Sprintf("%s must be one of: %s", k, strings.Join(enum, ", "))}
			}
		}
		if max, ok := prop["maximum"].(int); ok {
			if n, isNum := v.(float64); isNum && n > float64(max) {
				return nil, &mcpArgumentError{msg: fmt.Sprintf("%s must be at most %d", k, max)}
			}
		}
	}
	return args, nil
}

// toolSchema renders a tool's MCP inputSchema.
func (t userMCPTool) toolSchema() json.RawMessage {
	props := map[string]any{}
	for k, v := range t.properties {
		props[k] = v
	}
	required := append([]string{}, t.required...)
	if t.clusterScoped {
		props["clusterId"] = clusterIDProp
		required = append([]string{"clusterId"}, required...)
	}
	schema := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		schema["required"] = required
	}
	b, _ := json.Marshal(schema)
	return b
}

// actAsUser scopes tx to userID exactly as requireAuth scopes a session's
// transaction: tenant first (so grants are readable), then the user's grants,
// then narrowed to the clusters those grants reach. Kept step-for-step
// parallel to requireAuth rather than shared with it so the REST middleware's
// hot path is untouched; a change to one must be made to the other.
func actAsUser(ctx context.Context, tx pgx.Tx, tenantID, userID, requestID string) (*requestContext, error) {
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		return nil, fmt.Errorf("set request scope: %w", err)
	}
	grants, err := authz.ResolveEffectivePermissions(ctx, tx, userID)
	if err != nil {
		return nil, fmt.Errorf("resolve effective permissions: %w", err)
	}
	accessible, unrestricted, err := authz.AccessibleClusterIDs(ctx, tx, grants)
	if err != nil {
		return nil, fmt.Errorf("resolve accessible clusters: %w", err)
	}
	if !unrestricted {
		if err := data.SetRequestScope(ctx, tx, tenantID, accessible); err != nil {
			return nil, fmt.Errorf("narrow request scope: %w", err)
		}
	}
	return &requestContext{Tx: tx, UserID: userID, TenantID: tenantID, Grants: grants, RequestID: requestID}, nil
}

// resolveClusterRef finds the cluster a clusterId argument names — an id, or
// a display name — among the clusters visible to rc (RLS-narrowed).
func resolveClusterRef(ctx context.Context, rc *requestContext, ref string) (resolvedCluster, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return resolvedCluster{}, &mcpArgumentError{msg: "clusterId is required (an id or display name from list_clusters)"}
	}
	rows, err := rc.Tx.Query(ctx,
		`SELECT id, display_name FROM clusters WHERE (id = $1 OR display_name = $1) AND archived_at IS NULL ORDER BY (id = $1) DESC LIMIT 2`, ref)
	if err != nil {
		return resolvedCluster{}, fmt.Errorf("look up cluster: %w", err)
	}
	defer rows.Close()
	var found []resolvedCluster
	for rows.Next() {
		var c resolvedCluster
		if err := rows.Scan(&c.ID, &c.Name); err != nil {
			return resolvedCluster{}, fmt.Errorf("scan cluster: %w", err)
		}
		found = append(found, c)
	}
	if err := rows.Err(); err != nil {
		return resolvedCluster{}, fmt.Errorf("look up cluster: %w", err)
	}
	switch {
	case len(found) == 0:
		return resolvedCluster{}, &mcpArgumentError{msg: fmt.Sprintf("no active cluster with id or name %q is visible to you; list_clusters shows the ones you can use", ref), lookup: true}
	case len(found) == 2 && found[0].ID != ref:
		return resolvedCluster{}, &mcpArgumentError{msg: fmt.Sprintf("more than one cluster is named %q; pass its id instead", ref), lookup: true}
	}
	return found[0], nil
}

// userMCPCall is one tool call's outcome, as the audit record needs it.
type userMCPCall struct {
	clusterID  string
	capability string
}

// callUserMCPTool is the user mount's ToolFunc.
func (s *Server) callUserMCPTool(ctx context.Context, grant mcp.Grant, toolName string, raw json.RawMessage) (json.RawMessage, error) {
	p := grant.Principal
	if p == nil {
		// Unreachable through the user mount's Authenticator, which always
		// sets one; refusing beats acting with no actor.
		return nil, errors.New("this endpoint only serves personal access tokens")
	}
	call := userMCPCall{}
	result, err := s.dispatchUserMCPTool(ctx, p, toolName, raw, &call)
	s.auditUserMCPCall(ctx, p, toolName, raw, call, err)
	return result, err
}

func (s *Server) dispatchUserMCPTool(ctx context.Context, p *mcp.Principal, toolName string, raw json.RawMessage, call *userMCPCall) (json.RawMessage, error) {
	var tool *userMCPTool
	for _, t := range userMCPCatalogue() {
		if t.name == toolName {
			tool = &t
			break
		}
	}
	if tool == nil {
		return nil, fmt.Errorf("%w: %q", errToolNotOffered, toolName)
	}
	call.capability = tool.capability

	args, err := checkUserMCPArgs(*tool, raw)
	if err != nil {
		return nil, err
	}

	requestID := logging.RequestIDFrom(ctx)
	if requestID == "" {
		requestID = logging.NewRequestID()
	}
	ctx = logging.ContextWith(ctx, logging.ActorID(p.UserID))

	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "MCP tool call: begin transaction failed", logging.Err(err))
		return nil, fmt.Errorf("the hub could not answer this (internal error, request id %s)", requestID)
	}
	// ALWAYS rolled back: every tool here is a read, and rolling back makes
	// that structural rather than a property each handler has to keep.
	defer tx.Rollback(ctx) //nolint:errcheck

	// Tenant scope first, in this function, so the transaction is never
	// unscoped for even one statement; actAsUser then narrows it to the
	// caller's clusters.
	if err := data.SetRequestScope(ctx, tx, p.TenantID, nil); err != nil {
		logger.ErrorContext(ctx, "MCP tool call: set request scope failed", logging.Err(err))
		return nil, fmt.Errorf("the hub could not answer this (internal error, request id %s)", requestID)
	}
	rc, err := actAsUser(ctx, tx, p.TenantID, p.UserID, requestID)
	if err != nil {
		logger.ErrorContext(ctx, "MCP tool call: resolving the caller's permissions failed", logging.Err(err))
		return nil, fmt.Errorf("the hub could not answer this (internal error, request id %s)", requestID)
	}

	var cluster resolvedCluster
	if tool.clusterScoped {
		ref, _ := args["clusterId"].(string)
		cluster, err = resolveClusterRef(ctx, rc, ref)
		if err != nil {
			var argErr *mcpArgumentError
			if !errors.As(err, &argErr) {
				logger.ErrorContext(ctx, "MCP tool call: resolving the cluster failed", logging.Err(err))
				return nil, fmt.Errorf("the hub could not answer this (internal error, request id %s)", requestID)
			}
			return nil, err
		}
		call.clusterID = cluster.ID
		allowed, err := authz.HasCapabilityForCluster(ctx, tx, rc.Grants, tool.capability, cluster.ID)
		if err != nil {
			logger.ErrorContext(ctx, "MCP tool call: resolving cluster-scoped capability failed", logging.ClusterID(cluster.ID), logging.Err(err))
			return nil, fmt.Errorf("the hub could not answer this (internal error, request id %s)", requestID)
		}
		if !allowed {
			return nil, &mcpCapabilityError{tool: tool.name, capability: tool.capability, clusterID: cluster.ID}
		}
	} else if !authz.HasCapability(rc.Grants, tool.capability) {
		return nil, &mcpCapabilityError{tool: tool.name, capability: tool.capability}
	}
	if id, ok := args["clusterId"].(string); ok && call.clusterID == "" && strings.HasPrefix(id, "cl_") && len(id) <= 64 {
		call.clusterID = id
	}

	result, err := tool.run(ctx, s, rc, cluster, args, raw)
	if err != nil {
		return nil, err
	}
	if len(result) > maxUserMCPResultBytes {
		return nil, fmt.Errorf("the answer is larger than %d KiB, more than is useful in one reply; narrow the question (a namespace, a smaller limit or tailLines, a more specific filter)", maxUserMCPResultBytes>>10)
	}
	return result, nil
}

// auditUserMCPCall writes the call's audit_events row in its own transaction,
// committed whatever happened to the call itself — the tool transaction is
// always rolled back, and a refused call is exactly the event the trail must
// keep. Failure to audit is logged; it does not change the tool's answer
// (the same posture as internal/mcp's ObserveFunc).
func (s *Server) auditUserMCPCall(ctx context.Context, p *mcp.Principal, tool string, raw json.RawMessage, call userMCPCall, callErr error) {
	outcome := audit.OutcomeSuccess
	details := map[string]any{"action": "mcp:tool_call", "tool": tool, "tokenId": p.TokenID}
	var capErr *mcpCapabilityError
	switch {
	case errors.As(callErr, &capErr), errors.Is(callErr, errToolNotOffered):
		outcome = audit.OutcomeDenied
	case callErr != nil:
		outcome = audit.OutcomeError
	}
	if callErr != nil {
		msg := callErr.Error()
		if len(msg) > 300 {
			msg = msg[:300]
		}
		details["error"] = msg
	}
	if len(raw) > 0 && len(raw) <= 4096 {
		var args map[string]any
		if json.Unmarshal(raw, &args) == nil {
			details["args"] = args
		}
	} else if len(raw) > 4096 {
		details["argsOmitted"] = "larger than 4 KiB"
	}
	ev := audit.Event{
		TenantID: p.TenantID, ActorID: &p.UserID, ActorAuthMethod: mcpAuthMethod,
		SourceIP: p.SourceIP, Outcome: outcome, Details: details,
	}
	if call.capability != "" {
		c := call.capability
		ev.Capability = &c
	}
	if call.clusterID != "" {
		c := call.clusterID
		ev.ClusterID = &c
	}
	s.writeAuditEvent(ctx, ev)
}

// writeAuditEvent records one event in its own committed transaction.
func (s *Server) writeAuditEvent(ctx context.Context, ev audit.Event) {
	// Detached from the caller's cancellation: a client that hangs up as the
	// answer arrives must not leave its call unaudited.
	ctx = context.WithoutCancel(ctx)
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "recording an MCP call in the audit log: begin failed", logging.Err(err))
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, ev.TenantID, nil); err != nil {
		logger.ErrorContext(ctx, "recording an MCP call in the audit log: set scope failed", logging.Err(err))
		return
	}
	if err := audit.RecordEvent(ctx, tx, ev); err != nil {
		logger.ErrorContext(ctx, "recording an MCP call in the audit log failed", logging.Err(err))
		return
	}
	if err := tx.Commit(ctx); err != nil {
		logger.ErrorContext(ctx, "recording an MCP call in the audit log: commit failed", logging.Err(err))
	}
}

// tokenRateLimiter is a per-token token bucket. In-process, like
// authz.LoginRateLimiter and for the same reason: a hub restart resetting the
// buckets costs one burst, not a security property.
type tokenRateLimiter struct {
	mu      sync.Mutex
	burst   float64
	perSec  float64
	now     func() time.Time
	buckets map[string]*rateBucket
}

type rateBucket struct {
	tokens float64
	last   time.Time
}

func newTokenRateLimiter(burst, perMinute int, now func() time.Time) *tokenRateLimiter {
	if now == nil {
		now = time.Now
	}
	return &tokenRateLimiter{burst: float64(burst), perSec: float64(perMinute) / 60, now: now, buckets: map[string]*rateBucket{}}
}

// allow takes one call from key's bucket. When refused, wait is how long
// until one is available.
func (l *tokenRateLimiter) allow(key string) (ok bool, wait time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, found := l.buckets[key]
	if !found {
		// Opportunistic sweep on a new key: a bucket idle long enough to have
		// refilled completely carries no state worth keeping.
		full := time.Duration(l.burst / l.perSec * float64(time.Second))
		for k, old := range l.buckets {
			if now.Sub(old.last) > full {
				delete(l.buckets, k)
			}
		}
		b = &rateBucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.perSec)
	b.last = now
	if b.tokens < 1 {
		return false, time.Duration((1 - b.tokens) / l.perSec * float64(time.Second))
	}
	b.tokens--
	return true, 0
}

// newUserMCPServer builds the user-facing MCP server: internal/mcp's Server
// with the personal-token Authenticator and callUserMCPTool.
func (s *Server) newUserMCPServer() *mcp.Server {
	catalogue := userMCPCatalogue()
	tools := make([]mcp.Tool, 0, len(catalogue))
	allowed := make(map[string]struct{}, len(catalogue))
	for _, t := range catalogue {
		tools = append(tools, mcp.Tool{
			Name: t.name, Description: t.description, InputSchema: t.toolSchema(),
			Annotations: map[string]any{"readOnlyHint": true, "destructiveHint": false, "openWorldHint": false},
		})
		allowed[t.name] = struct{}{}
	}
	limiter := newTokenRateLimiter(userMCPBurst, userMCPPerMinute, nil)

	auth := func(r *http.Request) (mcp.Grant, error) {
		owner, err := s.lookupPersonalToken(r.Context(), mcp.BearerToken(r))
		if err != nil {
			logPersonalTokenFailure(r.Context(), err)
			return mcp.Grant{}, err
		}
		if ok, wait := limiter.allow(owner.TokenID); !ok {
			retry := int(math.Ceil(wait.Seconds()))
			return mcp.Grant{}, &mcp.RefusalError{Status: http.StatusTooManyRequests, RetryAfterSeconds: retry, Message: fmt.Sprintf(
				"rate limit: this token may make %d requests a minute (bursts of %d); try again in %ds",
				userMCPPerMinute, userMCPBurst, retry)}
		}
		// mcp:use is checked on every request, not only at token creation,
		// so withdrawing it stops existing tokens at once.
		if held, err := s.userHoldsCapability(r.Context(), owner, authz.CapMCPUse); err != nil {
			logger.ErrorContext(r.Context(), "MCP request: resolving the token owner's permissions failed", logging.Err(err))
			return mcp.Grant{}, &mcp.RefusalError{Status: http.StatusServiceUnavailable, Message: "the hub could not check your permissions just now (internal error); try again"}
		} else if !held {
			s.writeAuditEvent(r.Context(), audit.Event{
				TenantID: owner.TenantID, ActorID: &owner.UserID, ActorAuthMethod: mcpAuthMethod,
				SourceIP: clientIP(r), Capability: ptrTo(authz.CapMCPUse), Outcome: audit.OutcomeDenied,
				Details: map[string]any{"action": "mcp:request", "tokenId": owner.TokenID},
			})
			return mcp.Grant{}, &mcp.RefusalError{Message: "permission denied: your ARGUS account no longer holds the mcp:use capability, which using an access token needs. An ARGUS administrator can grant a role that includes it."}
		}
		return mcp.Grant{
			AllowedTools: allowed,
			ExpiresAt:    owner.ExpiresAt,
			Principal:    &mcp.Principal{TenantID: owner.TenantID, UserID: owner.UserID, TokenID: owner.TokenID, SourceIP: clientIP(r)},
		}, nil
	}

	observe := func(ctx context.Context, grant mcp.Grant, tool string, args json.RawMessage, err error) {
		// callUserMCPTool audits every call it receives. The one kind it
		// never receives is a name outside the surface — internal/mcp refuses
		// that first — and that refusal is an authorization event too.
		if grant.Principal == nil || grant.Allows(tool) {
			return
		}
		logger.WarnContext(ctx, "refused an MCP call for a tool outside the personal surface",
			slog.String("tool", tool), logging.ActorID(grant.Principal.UserID))
		s.auditUserMCPCall(ctx, grant.Principal, tool, args, userMCPCall{}, errToolNotOffered)
	}
	return mcp.NewServerWithAuth(auth, tools, s.callUserMCPTool, observe, nil, nil)
}

// userHoldsCapability resolves owner's grants in a short read-only
// transaction and reports whether they include capability anywhere.
func (s *Server) userHoldsCapability(ctx context.Context, owner personalTokenOwner, capability string) (bool, error) {
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, owner.TenantID, nil); err != nil {
		return false, err
	}
	grants, err := authz.ResolveEffectivePermissions(ctx, tx, owner.UserID)
	if err != nil {
		return false, err
	}
	return authz.HasCapability(grants, capability), nil
}

func ptrTo[T any](v T) *T { return &v }
