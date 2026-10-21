// A TEST FIXTURE, not a product feature — read this before adding a caller.
//
// This file implements sample/demo data generation. It was BACKLOG.md item
// 16's "safe demo incident/sample data mode", on the reasoning that a fresh
// install has nothing to show. PROJECT.md D14 retired that reasoning in
// 2026-09: ARGUS is self-hosted against a cluster the operator already has,
// enrolment is one `argusctl cluster add`, and an empty ARGUS on a healthy
// cluster is the correct first impression rather than a bad one — if a demo
// needs incidents, connect a test cluster. Both UI entry points (Settings'
// "Demo data" panel, the onboarding wizard's "Load sample data instead")
// were removed, and internal/api/server.go registers the two routes below
// ONLY when cmd/hub was started with ARGUS_ENABLE_DEMO_DATA=true, which the
// dev compose stack sets so web/e2e can seed its Playwright fixture through
// real endpoints instead of mocks. That suite is now the only consumer.
//
// Why it is gated rather than merely unlinked: what it writes is fabricated
// rows in the tables whose credibility is the product — analyses with
// invented causal chains, root causes and confidence; approval decisions
// attributed to the CALLING USER by name for decisions they never made;
// execution records claiming a cluster was changed; and cost_usd marked
// 'metered' so it lands in the real spend aggregation. Nothing anywhere
// excludes demoClusterFingerprint from any count, by design, so on a real
// install this silently corrupts the incident list, the overview tiles,
// Insights, MTTR and spend. Do not re-expose it in the UI.
//
// POST /api/v1/demo-data seeds one clearly-labeled fake cluster and a spread
// of incidents covering the full state machine (Detected through
// Resolved/Reopened/Failed/Dismissed) using real rows through the real
// schema, and DELETE /api/v1/demo-data removes exactly what was generated.
//
// Deliberately NOT a fake "Active" cluster: internal/gateway.HealthMonitor's
// real sweep would demote a cluster with no real heartbeats to Degraded
// within 75s regardless of what this seeds it as, and pretending otherwise
// would be exactly the kind of dishonesty PRODUCT_DIRECTION.md's "trust is a
// feature" principle exists to rule out. The demo cluster is honestly
// Disconnected (never had a real agent); the story is told entirely through
// its incidents.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/domain"
	"argus/internal/events"
	"argus/internal/llm"
	"argus/internal/logging"
)

// demoClusterFingerprint is a fixed sentinel (never a real hash) that marks
// the one demo cluster a tenant may have — clusters_fingerprint_active_idx
// (migration 000002) already enforces uniqueness among non-archived
// clusters, so this doubles as the "already generated" check without a
// schema migration just to flag "this row is fake."
const demoClusterFingerprint = "argus-demo-cluster-fingerprint-v1"

const demoClusterDisplayName = "Demo Cluster (sample data)"

// handleGenerateDemoData is POST /api/v1/demo-data. Requires
// org:settings:write — same "administrative, org-wide, infrequent" gate as
// PUT /api/v1/admin/settings, not a capability of its own: generating or
// clearing sample data is exactly that class of action, not a day-to-day
// operational one.
func (s *Server) handleGenerateDemoData(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()

	var existingID string
	err := rc.Tx.QueryRow(ctx, `SELECT id FROM clusters WHERE cluster_fingerprint = $1 AND archived_at IS NULL`, demoClusterFingerprint).Scan(&existingID)
	if err == nil {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/already-exists",
			"Demo data already exists", "Clear the existing demo data first (DELETE /api/v1/demo-data) if you want to regenerate it.")
		return
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		logger.ErrorContext(ctx, "checking for an existing demo cluster failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not check for existing demo data", "")
		return
	}

	clusterID, incidentCount, err := generateDemoData(ctx, rc.Tx, rc.TenantID, rc.UserID)
	if err != nil {
		logger.ErrorContext(ctx, "generating the demo data failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not generate demo data", "")
		return
	}

	capability := authz.CapOrgSettingsWrite
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID: rc.TenantID, ActorID: &rc.UserID, ActorAuthMethod: "jwt", SourceIP: clientIP(r),
		Capability: &capability, ClusterID: &clusterID, Outcome: audit.OutcomeSuccess,
		Details: map[string]any{"action": "generate_demo_data", "clusterId": clusterID, "incidentCount": incidentCount},
	}); err != nil {
		logger.ErrorContext(ctx, "recording a demo-data generation in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	if s.events != nil {
		s.events.Publish(events.ClusterUpdated(clusterID))
	}
	writeJSON(w, http.StatusCreated, map[string]any{"clusterId": clusterID, "incidentCount": incidentCount})
}

// handleClearDemoData is DELETE /api/v1/demo-data. Same capability gate as
// generation. A no-op (200, clusterId null) if no demo data exists —
// clicking "Clear" twice is not an error.
func (s *Server) handleClearDemoData(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()

	var clusterID string
	err := rc.Tx.QueryRow(ctx, `SELECT id FROM clusters WHERE cluster_fingerprint = $1 AND archived_at IS NULL`, demoClusterFingerprint).Scan(&clusterID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusOK, map[string]any{"clusterId": nil, "cleared": false})
		return
	}
	if err != nil {
		logger.ErrorContext(ctx, "looking up the demo cluster failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up demo data", "")
		return
	}

	if err := clearDemoData(ctx, rc.Tx, clusterID); err != nil {
		logger.ErrorContext(ctx, "clearing the demo data failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not clear demo data", "")
		return
	}

	capability := authz.CapOrgSettingsWrite
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID: rc.TenantID, ActorID: &rc.UserID, ActorAuthMethod: "jwt", SourceIP: clientIP(r),
		Capability: &capability, Outcome: audit.OutcomeSuccess,
		Details: map[string]any{"action": "clear_demo_data", "clusterId": clusterID},
	}); err != nil {
		logger.ErrorContext(ctx, "recording a demo-data clear in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	if s.events != nil {
		s.events.Publish(events.ClusterUpdated(clusterID))
	}
	writeJSON(w, http.StatusOK, map[string]any{"clusterId": clusterID, "cleared": true})
}

// clearDemoData deletes the demo cluster and everything that references it,
// in FK/logical dependency order — the exact reverse of generateDemoData's
// insert order.
func clearDemoData(ctx context.Context, tx pgx.Tx, clusterID string) error {
	statements := []string{
		`DELETE FROM remediation_executions WHERE cluster_id = $1`,
		`DELETE FROM remediation_approval_decisions WHERE cluster_id = $1`,
		`DELETE FROM remediation_recommendations WHERE cluster_id = $1`,
		// BACKLOG.md N1: seeded demo incidents skip orchestrator.SetState
		// entirely (they're inserted directly, in whatever state the seed
		// wants), but a real approve/reject against one during an e2e run
		// goes through the real API path, which does call SetState — so a
		// demo incident CAN pick up a row here before this cluster is
		// cleared. No foreign key ties incident_notifications to clusters
		// (migration 000083's own comment explains why), so a missed
		// DELETE here would silently orphan rather than fail loudly.
		`DELETE FROM incident_notifications WHERE cluster_id = $1`,
		// BUGS.md 119: neither evidence.analysis_id nor
		// analysis_embeddings.analysis_id is ON DELETE CASCADE (migrations
		// 000037, 000082), so a demo analysis that has ever been embedded by
		// internal/knowledge's backfill sweep, or that picked up a real
		// evidence row from a manual /analyze run, makes the DELETE FROM
		// analyses below fail with a foreign-key violation unless these two
		// child tables are cleared first.
		`DELETE FROM evidence WHERE analysis_id IN (SELECT id FROM analyses WHERE cluster_id = $1)`,
		`DELETE FROM analysis_embeddings WHERE analysis_id IN (SELECT id FROM analyses WHERE cluster_id = $1)`,
		`DELETE FROM analyses WHERE cluster_id = $1`,
		`DELETE FROM findings WHERE cluster_id = $1`,
		`DELETE FROM incidents WHERE cluster_id = $1`,
		`DELETE FROM clusters WHERE id = $1`,
	}
	for _, sql := range statements {
		if _, err := tx.Exec(ctx, sql, clusterID); err != nil {
			return fmt.Errorf("exec %q: %w", sql, err)
		}
	}
	return nil
}

// --- generation ---

// demoFinding describes one Finding row to insert alongside a demo
// incident — mirrors tunnel.Finding's own fields closely enough to read as
// realistic, without needing an actual agent connection.
type demoFinding struct {
	DetectorID string
	GVK        string
	Namespace  string
	ObjectName string
	// WorkloadGVK/WorkloadName mirror tunnel.Finding's own pair: the workload
	// that OWNS this Finding's object, as internal/agent/workload.go's
	// resolveWorkloadFromOwnerRefs walk would have resolved it — the
	// Deployment behind a Pod's ReplicaSet, the Job behind a CronJob's Pod,
	// the Node behind a static Pod. Empty for exactly the cases that walk
	// returns ok=false for, and for every Finding whose object is not a Pod
	// at all (a Finding about a Deployment IS about the workload; there is
	// nothing above it to resolve). Fed through demoWorkloadKey below into
	// incidents.workload_key, the same way the hub does it for a real agent.
	WorkloadGVK     string
	WorkloadName    string
	Reason          string
	Message         string
	Severity        string
	OccurrenceCount int
	Ago             time.Duration // how long before "now" this finding occurred
}

// --- the three correlation columns, derived the way the hub derives them ---
//
// PROJECT.md B180. generateDemoData used to insert incidents with
// object_key, workload_key and opening_reason all left NULL, although the
// findings it inserted alongside them carried the gvk/namespace/object_name/
// reason those three columns are built from. The consequence was not cosmetic:
// every seeded incident rendered `incidentIdentity`'s LAST-RESORT fallback
// (web/src/utils/incidents.ts — "Incident demo-ima", a single 22px line with
// no kind line and no fault line), so the fixture had no identity block at
// all. web/e2e/list-density.spec.ts, whose whole job is to catch the incident
// row getting taller, was measuring a row shape the product never produces:
// neutralising the truncation rule that keeps the row short (B178, index.css)
// left the measured row at 82px and the spec passed identically. The guard
// could not see the thing it guards.
//
// These three helpers reproduce internal/gateway/finding.go's own derivation
// — objectCorrelationKey, workloadCorrelationKey, and the `if f.Reason != ""`
// beside them in handleFinding's INSERT — rather than inventing a shape that
// merely looks plausible. A fixture that disagrees with production trains the
// UI, and the tests that read it, on data that cannot occur. They are copied
// rather than imported because those functions are unexported package
// internals of internal/gateway; the same copy-with-a-citation is already the
// established pattern for this key on the read side
// (internal/api/tolerations.go's splitObjectKey, internal/knowledge/text.go).
// Migration 000036 defines the object key's `gvk|namespace|name`, 000042 the
// workload key's, and 000043 is why opening_reason is set independently of
// whether a workload resolved.
//
// Each returns `any` and leaves it as an untyped nil when the source field is
// empty, so pgx sends SQL NULL — never an empty string. NULL is what the
// correlation path stores in exactly these cases and what the fingerprint-only
// fallback in finding.go's lookup depends on to find its own incidents.

// demoObjectKey is gateway.objectCorrelationKey: the identity of the THING
// the Finding is about. NULL when the Finding names no object.
func demoObjectKey(f demoFinding) any {
	if strings.TrimSpace(f.ObjectName) == "" {
		return nil
	}
	return f.GVK + "|" + f.Namespace + "|" + f.ObjectName
}

// demoWorkloadKey is gateway.workloadCorrelationKey: the identity of the
// workload that owns the Finding's object. NULL when the agent resolved no
// owner.
//
// Note it joins the WORKLOAD's gvk/name with the FINDING's namespace, which
// is what the hub does — including for a cluster-scoped owner such as the
// Node that owns a static Pod, where the resulting key carries the Pod's
// namespace. Reproduced deliberately: a fixture that "corrected" that would
// be describing a key the hub never writes.
func demoWorkloadKey(f demoFinding) any {
	if strings.TrimSpace(f.WorkloadName) == "" {
		return nil
	}
	return f.WorkloadGVK + "|" + f.Namespace + "|" + f.WorkloadName
}

// demoOpeningReason is the `if f.Reason != ""` guard in finding.go's incident
// INSERT — the symptom that OPENED the incident, set independently of whether
// a workload resolved (migration 000043).
func demoOpeningReason(f demoFinding) any {
	if f.Reason == "" {
		return nil
	}
	return f.Reason
}

// demoToolCall/demoCausalStep/demoAnalysis describe one demo analysis —
// same shapes persistAnalysis (analyze.go) writes for a real investigation,
// just authored by hand instead of an LLM.
type demoToolCall struct {
	Tool   string
	Args   map[string]any
	Result map[string]any
}

type demoCausalStep struct {
	Step       int
	Hypothesis string
	Finding    string
	ToolCalls  []demoToolCall
}

type demoAnalysis struct {
	Statement          string // non-empty => "complete"; empty => "partial"
	Confidence         float64
	PartialReason      string
	SuggestedNextSteps []string
	CausalChain        []demoCausalStep
	Ago                time.Duration
}

// demoPlan/demoApproval/demoExecution describe the remediation half of an
// incident's story — approval and execution are both optional, matching
// how far along a real incident might be.
type demoApproval struct {
	Verdict string // "approved" | "rejected"
	Reason  string
	Ago     time.Duration
}

type demoExecution struct {
	Outcome         string // "succeeded" | "failed"
	Error           string
	ResourceVersion string
	Ago             time.Duration
}

type demoPlan struct {
	ActionType      string
	TargetGVK       string
	TargetNamespace string
	TargetName      string
	Params          map[string]any
	Reversible      bool
	RiskLevel       string
	GateOutcome     string
	GateReason      string
	Ago             time.Duration
	Approval        *demoApproval
	Execution       *demoExecution
}

// demoIncident is one row in the fixed story generateDemoData tells —
// spanning every state a real incident can reach, so every page in the app
// (Incidents' state filter, Approvals, the resolution-path panel) has
// something real to show for every state it renders.
type demoIncident struct {
	FingerprintSuffix string
	Severity          string
	State             string
	FirstSeenAgo      time.Duration
	OccurrenceCount   int
	Finding           demoFinding
	SecondFinding     *demoFinding // a later, recurring Finding — used for the Reopened story
	Analysis          *demoAnalysis
	Plan              *demoPlan
}

// demoStory is the fixed set generateDemoData seeds, in the order shown on
// a first visit. Deliberately hand-authored content, not templated from a
// count — BACKLOG.md item 16's whole point is a first-time
// visitor immediately understanding what ARGUS does, which needs each row
// to read as a specific, plausible incident, not "incident #4."
var demoStory = []demoIncident{
	{
		// Deliberately NOT payments/checkout-worker, which the "oomkill"
		// story below is about. Now that object_key is actually populated,
		// two SIMULTANEOUSLY OPEN incidents on one object_key would be a
		// state the hub cannot produce: handleFinding's object-tier lookup
		// (internal/gateway/finding.go) attaches a second symptom on the same
		// object to the EXISTING open incident rather than opening a second
		// one, which is the whole point of migration 000036. The two rows
		// were indistinguishable while both rendered a fingerprint hash;
		// giving them real identities made the contradiction visible.
		FingerprintSuffix: "imagepull", Severity: "high", State: "Detected",
		FirstSeenAgo: 6 * time.Minute, OccurrenceCount: 3,
		Finding: demoFinding{
			DetectorID: "k8s-warning-events", GVK: "apps/v1/Deployment", Namespace: "payments", ObjectName: "invoice-renderer",
			Reason: "ErrImagePull", Message: `Back-off pulling image "registry.internal/payments/invoice-renderer:v2.4.1": manifest not found`,
			Severity: "high", OccurrenceCount: 3, Ago: 6 * time.Minute,
		},
	},
	{
		FingerprintSuffix: "readiness", Severity: "medium", State: "NeedsHumanInvestigation",
		FirstSeenAgo: 40 * time.Minute, OccurrenceCount: 6,
		Finding: demoFinding{
			DetectorID: "k8s-pod-conditions", GVK: "v1/Pod", Namespace: "gateway", ObjectName: "api-gateway-7f9c",
			WorkloadGVK: "apps/v1/Deployment", WorkloadName: "api-gateway",
			Reason: "Unhealthy", Message: "Readiness probe failed: connection refused",
			Severity: "medium", OccurrenceCount: 6, Ago: 12 * time.Minute,
		},
		Analysis: &demoAnalysis{
			PartialReason: "iteration_limit",
			SuggestedNextSteps: []string{
				"Check NetworkPolicy rules for the gateway namespace",
				"Verify the service mesh sidecar is injected and healthy",
			},
			CausalChain: []demoCausalStep{
				{Step: 1, Hypothesis: "api-gateway is failing to bind its readiness port", Finding: "Port 8080 is listening; probe reaches the container",
					ToolCalls: []demoToolCall{{Tool: "get_logs", Args: map[string]any{"namespace": "gateway", "pod": "api-gateway-7f9c"}, Result: map[string]any{"lines": []string{"listening on :8080"}}}}},
				{Step: 2, Hypothesis: "Downstream dependency (auth-service) is unreachable", Finding: "get_events shows no NetworkPolicy denial recorded yet",
					ToolCalls: []demoToolCall{{Tool: "get_events", Args: map[string]any{"namespace": "gateway"}, Result: map[string]any{"events": []string{}}}}},
			},
			Ago: 10 * time.Minute,
		},
	},
	{
		FingerprintSuffix: "oomkill", Severity: "high", State: "AwaitingApproval",
		FirstSeenAgo: 25 * time.Minute, OccurrenceCount: 4,
		Finding: demoFinding{
			DetectorID: "k8s-warning-events", GVK: "apps/v1/Deployment", Namespace: "payments", ObjectName: "checkout-worker",
			Reason: "OOMKilled", Message: "Container checkout-worker was OOMKilled",
			Severity: "high", OccurrenceCount: 4, Ago: 4 * time.Minute,
		},
		Analysis: &demoAnalysis{
			Statement:  "checkout-worker is being OOMKilled repeatedly because its memory limit is too low for current traffic",
			Confidence: 0.82,
			CausalChain: []demoCausalStep{
				{Step: 1, Hypothesis: "Container is exceeding its memory limit under load", Finding: "Container was OOMKilled 4 times in the last 25 minutes, always within 2 minutes of a traffic spike",
					ToolCalls: []demoToolCall{{Tool: "get_events", Args: map[string]any{"namespace": "payments", "involvedObjectName": "checkout-worker"}, Result: map[string]any{"reason": "OOMKilling"}}}},
			},
			Ago: 3 * time.Minute,
		},
		Plan: &demoPlan{
			ActionType: "ScaleDeployment", TargetGVK: "apps/v1/Deployment", TargetNamespace: "payments", TargetName: "checkout-worker",
			Params: map[string]any{"replicas": 4}, Reversible: true, RiskLevel: "low",
			GateOutcome: "NeedsApproval", GateReason: "Scaling out is reversible and low-risk; requires human approval per autonomy policy.",
			Ago: 3 * time.Minute,
		},
	},
	{
		FingerprintSuffix: "authrestart", Severity: "medium", State: "Validating",
		FirstSeenAgo: 30 * time.Minute, OccurrenceCount: 2,
		Finding: demoFinding{
			DetectorID: "k8s-pod-conditions", GVK: "v1/Pod", Namespace: "platform", ObjectName: "auth-service-6b7d4",
			WorkloadGVK: "apps/v1/Deployment", WorkloadName: "auth-service",
			Reason: "CrashLoopBackOff", Message: "Back-off restarting failed container",
			Severity: "medium", OccurrenceCount: 2, Ago: 22 * time.Minute,
		},
		Analysis: &demoAnalysis{
			Statement:  "auth-service crashed on a stale database connection pool after a brief network blip; a restart clears it",
			Confidence: 0.68,
			CausalChain: []demoCausalStep{
				{Step: 1, Hypothesis: "Stale connection pool after a transient network interruption", Finding: "Logs show repeated 'connection reset by peer' just before each crash",
					ToolCalls: []demoToolCall{{Tool: "get_logs", Args: map[string]any{"namespace": "platform", "pod": "auth-service-6b7d4"}, Result: map[string]any{"lines": []string{"connection reset by peer"}}}}},
			},
			Ago: 20 * time.Minute,
		},
		Plan: &demoPlan{
			ActionType: "RestartPod", TargetGVK: "apps/v1/Deployment", TargetNamespace: "platform", TargetName: "auth-service",
			Params: map[string]any{}, Reversible: true, RiskLevel: "low",
			GateOutcome: "NeedsApproval", GateReason: "A rollout restart is reversible and low-risk; requires human approval per autonomy policy.",
			Ago:       19 * time.Minute,
			Approval:  &demoApproval{Verdict: "approved", Ago: 12 * time.Minute},
			Execution: &demoExecution{Outcome: "succeeded", ResourceVersion: "48213", Ago: 11 * time.Minute},
		},
	},
	{
		FingerprintSuffix: "diskpressure-resolved", Severity: "medium", State: "Resolved",
		FirstSeenAgo: 2 * 24 * time.Hour, OccurrenceCount: 2,
		Finding: demoFinding{
			DetectorID: "k8s-pod-conditions", GVK: "v1/Pod", Namespace: "platform", ObjectName: "log-shipper-2f8a1",
			WorkloadGVK: "apps/v1/Deployment", WorkloadName: "log-shipper",
			Reason: "Evicted", Message: "The node was low on resource: ephemeral-storage",
			Severity: "medium", OccurrenceCount: 2, Ago: 2 * 24 * time.Hour,
		},
		Analysis: &demoAnalysis{
			Statement:  "log-shipper filled its node's ephemeral storage with unrotated logs; scaling it out spread the load",
			Confidence: 0.74,
			CausalChain: []demoCausalStep{
				{Step: 1, Hypothesis: "A single replica is writing unbounded local logs", Finding: "describe_resource shows no log rotation configured",
					ToolCalls: []demoToolCall{{Tool: "describe_resource", Args: map[string]any{"gvk": "apps/v1/Deployment", "namespace": "platform", "name": "log-shipper"}, Result: map[string]any{"replicas": 1}}}},
			},
			Ago: 2*24*time.Hour - 10*time.Minute,
		},
		Plan: &demoPlan{
			ActionType: "ScaleDeployment", TargetGVK: "apps/v1/Deployment", TargetNamespace: "platform", TargetName: "log-shipper",
			Params: map[string]any{"replicas": 3}, Reversible: true, RiskLevel: "low",
			GateOutcome: "NeedsApproval", GateReason: "Scaling out is reversible and low-risk; requires human approval per autonomy policy.",
			Ago:       2*24*time.Hour - 12*time.Minute,
			Approval:  &demoApproval{Verdict: "approved", Ago: 2*24*time.Hour - 20*time.Minute},
			Execution: &demoExecution{Outcome: "succeeded", ResourceVersion: "31029", Ago: 2*24*time.Hour - 22*time.Minute},
		},
	},
	{
		FingerprintSuffix: "reopened", Severity: "high", State: "Reopened",
		FirstSeenAgo: 3 * time.Hour, OccurrenceCount: 2,
		Finding: demoFinding{
			DetectorID: "k8s-warning-events", GVK: "apps/v1/Deployment", Namespace: "batch", ObjectName: "report-generator",
			Reason: "BackOff", Message: "Back-off restarting failed container",
			Severity: "high", OccurrenceCount: 1, Ago: 3 * time.Hour,
		},
		SecondFinding: &demoFinding{
			DetectorID: "k8s-warning-events", GVK: "apps/v1/Deployment", Namespace: "batch", ObjectName: "report-generator",
			Reason: "BackOff", Message: "Back-off restarting failed container — recurred after remediation",
			Severity: "high", OccurrenceCount: 1, Ago: 4 * time.Minute,
		},
		Analysis: &demoAnalysis{
			Statement:  "report-generator is crashing on startup due to a missing config value",
			Confidence: 0.55,
			CausalChain: []demoCausalStep{
				{Step: 1, Hypothesis: "Missing required environment variable", Finding: "Logs show 'REPORT_OUTPUT_BUCKET not set' at startup",
					ToolCalls: []demoToolCall{{Tool: "get_logs", Args: map[string]any{"namespace": "batch", "pod": "report-generator-0"}, Result: map[string]any{"lines": []string{"REPORT_OUTPUT_BUCKET not set"}}}}},
			},
			Ago: 2*time.Hour + 50*time.Minute,
		},
		Plan: &demoPlan{
			ActionType: "RestartPod", TargetGVK: "apps/v1/Deployment", TargetNamespace: "batch", TargetName: "report-generator",
			Params: map[string]any{}, Reversible: true, RiskLevel: "low",
			GateOutcome: "NeedsApproval", GateReason: "A rollout restart is reversible and low-risk; requires human approval per autonomy policy.",
			Ago:       2*time.Hour + 45*time.Minute,
			Approval:  &demoApproval{Verdict: "approved", Ago: 2*time.Hour + 40*time.Minute},
			Execution: &demoExecution{Outcome: "succeeded", ResourceVersion: "19004", Ago: 2*time.Hour + 39*time.Minute},
		},
	},
	{
		FingerprintSuffix: "execfailed", Severity: "critical", State: "Failed",
		FirstSeenAgo: 50 * time.Minute, OccurrenceCount: 5,
		Finding: demoFinding{
			DetectorID: "k8s-warning-events", GVK: "apps/v1/Deployment", Namespace: "payments", ObjectName: "fraud-scoring",
			Reason: "CrashLoopBackOff", Message: "Back-off restarting failed container",
			Severity: "critical", OccurrenceCount: 5, Ago: 8 * time.Minute,
		},
		Analysis: &demoAnalysis{
			Statement:  "fraud-scoring needs more replicas to keep up with request volume",
			Confidence: 0.71,
			CausalChain: []demoCausalStep{
				{Step: 1, Hypothesis: "Insufficient replicas for current load", Finding: "5 restarts in 50 minutes, all under sustained high CPU",
					ToolCalls: []demoToolCall{{Tool: "get_events", Args: map[string]any{"namespace": "payments", "involvedObjectName": "fraud-scoring"}, Result: map[string]any{"reason": "BackOff"}}}},
			},
			Ago: 7 * time.Minute,
		},
		Plan: &demoPlan{
			ActionType: "ScaleDeployment", TargetGVK: "apps/v1/Deployment", TargetNamespace: "payments", TargetName: "fraud-scoring",
			Params: map[string]any{"replicas": 6}, Reversible: true, RiskLevel: "medium",
			GateOutcome: "NeedsApproval", GateReason: "Scale-out under sustained load; medium risk because of the larger replica jump.",
			Ago:       6 * time.Minute,
			Approval:  &demoApproval{Verdict: "approved", Ago: 5 * time.Minute},
			Execution: &demoExecution{Outcome: "failed", Error: "gateway: cluster is not connected", ResourceVersion: "77341", Ago: 4 * time.Minute},
		},
	},
	{
		FingerprintSuffix: "dismissed", Severity: "low", State: "Dismissed",
		FirstSeenAgo: 90 * time.Minute, OccurrenceCount: 1,
		Finding: demoFinding{
			// No workload: a deliberately bare Pod with no controller, which is
			// resolveWorkloadFromOwnerRefs' ok=false case and the branch of
			// incidentIdentity where the object itself is the subject. Kept
			// unowned on purpose so the fixture exercises both branches.
			DetectorID: "k8s-warning-events", GVK: "v1/Pod", Namespace: "sandbox", ObjectName: "load-test-runner",
			Reason: "BackOff", Message: "Back-off restarting failed container",
			Severity: "low", OccurrenceCount: 1, Ago: 90 * time.Minute,
		},
		Analysis: &demoAnalysis{
			Statement:  "load-test-runner is a deliberately unstable workload used for chaos testing",
			Confidence: 0.6,
			CausalChain: []demoCausalStep{
				{Step: 1, Hypothesis: "Workload is intentionally unstable", Finding: "get_gitops_ownership shows this object is managed by a chaos-testing Argo Application",
					ToolCalls: []demoToolCall{{Tool: "get_gitops_ownership", Args: map[string]any{"gvk": "v1/Pod", "namespace": "sandbox", "name": "load-test-runner"}, Result: map[string]any{"managed_by": "argocd"}}}},
			},
			Ago: 85 * time.Minute,
		},
		Plan: &demoPlan{
			ActionType: "RestartPod", TargetGVK: "v1/Pod", TargetNamespace: "sandbox", TargetName: "load-test-runner",
			Params: map[string]any{}, Reversible: true, RiskLevel: "low",
			GateOutcome: "NeedsApproval", GateReason: "A rollout restart is reversible and low-risk; requires human approval per autonomy policy.",
			Ago:      84 * time.Minute,
			Approval: &demoApproval{Verdict: "rejected", Reason: "Expected behavior for this workload; no action needed", Ago: 80 * time.Minute},
		},
	},
	{
		FingerprintSuffix: "crashloop-redis", Severity: "critical", State: "Detected",
		FirstSeenAgo: 90 * time.Second, OccurrenceCount: 1,
		Finding: demoFinding{
			DetectorID: "k8s-warning-events", GVK: "apps/v1/StatefulSet", Namespace: "platform", ObjectName: "redis-cache",
			Reason: "CrashLoopBackOff", Message: "Back-off restarting failed container",
			Severity: "critical", OccurrenceCount: 1, Ago: 90 * time.Second,
		},
	},
	{
		// THE PUNISHING ROW (PROJECT.md B180). Everything else in this story
		// is a short, friendly name; a fixture made only of those measures the
		// incident list at its easiest and tells web/e2e/list-density.spec.ts
		// nothing about the case that produced the complaint.
		//
		// This is the exact shape B178's truncation rule was written for, as
		// its own comment in web/src/index.css records: a `kube-apiserver-
		// <node>` static Pod on a Node-OWNED incident, where the node name is
		// long and unbroken. It is punishing for a structural reason, not
		// because the strings were padded — the node name appears TWICE in the
		// identity block (once as the owner that leads the row, once inside the
		// Pod name on the fault line), and `overflow-wrap: anywhere` will break
		// both at any character.
		//
		// It also exercises the one branch of the derivation nothing else here
		// does: a cluster-scoped owner. demoWorkloadKey joins the Node's gvk
		// and name with the POD's namespace, `v1/Node|kube-system|<node>`,
		// because that is literally what gateway.workloadCorrelationKey does.
		//
		// WHY ITS TIMESTAMP IS WHAT IT IS. The incident list sorts last_seen
		// DESC by default, and list-density.spec.ts measures rows.nth(1) — the
		// second row, deliberately, since the first can carry a sticky/border
		// artefact. 2 minutes puts this row there: newer than every other
		// seeded incident except "crashloop-redis" (90s). If you retime either
		// of them, the guard goes back to measuring a row that cannot fail and
		// stops being a guard — that is the failure B180 was opened for. (The
		// spec sampling only nth(1) is tracked separately as PROJECT.md B181;
		// asserting on the TALLEST row instead currently fails for an
		// unrelated reason, a state-cell wrap on "Needs human investigation".)
		//
		// State is Detected rather than something quieter so the row also
		// carries the "Needs you" badge — the two-badge state cell is what
		// sets the row's floor when the identity block is short, and the guard
		// should measure a row with a realistic state cell under it.
		FingerprintSuffix: "apiserver-probe", Severity: "critical", State: "Detected",
		FirstSeenAgo: 4 * time.Minute, OccurrenceCount: 7,
		Finding: demoFinding{
			DetectorID: "k8s-warning-events", GVK: "v1/Pod", Namespace: "kube-system",
			ObjectName:  "kube-apiserver-ip-10-42-137-204.eu-west-1.compute.internal",
			WorkloadGVK: "v1/Node", WorkloadName: "ip-10-42-137-204.eu-west-1.compute.internal",
			Reason:   "Unhealthy",
			Message:  "Liveness probe failed: HTTP probe failed with statuscode: 500",
			Severity: "critical", OccurrenceCount: 7, Ago: 2 * time.Minute,
		},
	},
	{
		FingerprintSuffix: "failedscheduling", Severity: "medium", State: "Detected",
		FirstSeenAgo: 3 * time.Minute, OccurrenceCount: 2,
		Finding: demoFinding{
			DetectorID: "k8s-warning-events", GVK: "v1/Pod", Namespace: "batch", ObjectName: "nightly-etl-job-28471-9xkq4",
			// A CronJob's Job owns its Pods directly — resolveWorkloadFromOwnerRefs
			// takes that reference as-is, with no ReplicaSet hop. The Pod is
			// named after the Job, which is why it could not keep the Job's own
			// name once the owner became visible in the identity block.
			WorkloadGVK: "batch/v1/Job", WorkloadName: "nightly-etl-job-28471",
			Reason: "FailedScheduling", Message: "0/3 nodes are available: 3 Insufficient cpu",
			Severity: "medium", OccurrenceCount: 2, Ago: 3 * time.Minute,
		},
	},
}

// generateDemoData creates the demo cluster and every incident in
// demoStory, all in the caller's already-open, RLS-scoped transaction —
// returns the new cluster's id and how many incidents were created.
func generateDemoData(ctx context.Context, tx pgx.Tx, tenantID, actorUserID string) (clusterID string, incidentCount int, err error) {
	clusterID = domain.NewID(domain.PrefixCluster)
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Disconnected', 'default', $4)`,
		clusterID, tenantID, demoClusterDisplayName, demoClusterFingerprint); err != nil {
		return "", 0, fmt.Errorf("insert demo cluster: %w", err)
	}

	now := time.Now()
	for _, di := range demoStory {
		incidentID := domain.NewID(domain.PrefixIncident)
		fingerprint := "demo-" + di.FingerprintSuffix
		firstSeen := now.Add(-di.FirstSeenAgo)
		lastSeen := now.Add(-di.Finding.Ago)
		if di.SecondFinding != nil && di.SecondFinding.Ago < di.Finding.Ago {
			lastSeen = now.Add(-di.SecondFinding.Ago)
		}

		// object_key/workload_key/opening_reason come from the finding that
		// OPENED the incident — di.Finding, never di.SecondFinding — because
		// that is what they mean in internal/gateway/finding.go: all three are
		// written once, at INSERT, and a later correlated finding never
		// rewrites them (migrations 000042/000043 and the INSERT's own comment
		// there). The "reopened" story's second finding is exactly that later
		// case, so it correctly contributes only last_seen above.
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, object_key, workload_key, opening_reason, severity, state, first_seen, last_seen, occurrence_count)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			incidentID, tenantID, clusterID, fingerprint,
			demoObjectKey(di.Finding), demoWorkloadKey(di.Finding), demoOpeningReason(di.Finding),
			di.Severity, di.State, firstSeen, lastSeen, di.OccurrenceCount); err != nil {
			return "", 0, fmt.Errorf("insert demo incident %s: %w", di.FingerprintSuffix, err)
		}

		if err := insertDemoFinding(ctx, tx, tenantID, clusterID, incidentID, fingerprint, di.Finding, now); err != nil {
			return "", 0, fmt.Errorf("incident %s: %w", di.FingerprintSuffix, err)
		}
		if di.SecondFinding != nil {
			if err := insertDemoFinding(ctx, tx, tenantID, clusterID, incidentID, fingerprint, *di.SecondFinding, now); err != nil {
				return "", 0, fmt.Errorf("incident %s: second finding: %w", di.FingerprintSuffix, err)
			}
		}

		var analysisID string
		if di.Analysis != nil {
			analysisID, err = insertDemoAnalysis(ctx, tx, tenantID, clusterID, incidentID, *di.Analysis, now)
			if err != nil {
				return "", 0, fmt.Errorf("incident %s: analysis: %w", di.FingerprintSuffix, err)
			}
		}

		if di.Plan != nil {
			planID, err := insertDemoPlan(ctx, tx, tenantID, clusterID, incidentID, analysisID, *di.Plan, now)
			if err != nil {
				return "", 0, fmt.Errorf("incident %s: plan: %w", di.FingerprintSuffix, err)
			}
			if di.Plan.Approval != nil {
				if err := insertDemoApproval(ctx, tx, tenantID, clusterID, incidentID, planID, actorUserID, *di.Plan.Approval, now); err != nil {
					return "", 0, fmt.Errorf("incident %s: approval: %w", di.FingerprintSuffix, err)
				}
			}
			if di.Plan.Execution != nil {
				if err := insertDemoExecution(ctx, tx, tenantID, clusterID, incidentID, planID, *di.Plan.Execution, now); err != nil {
					return "", 0, fmt.Errorf("incident %s: execution: %w", di.FingerprintSuffix, err)
				}
			}
		}

		incidentCount++
	}

	return clusterID, incidentCount, nil
}

func insertDemoFinding(ctx context.Context, tx pgx.Tx, tenantID, clusterID, incidentID, fingerprint string, f demoFinding, now time.Time) error {
	findingID := domain.NewID(domain.PrefixFinding)
	_, err := tx.Exec(ctx,
		`INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk, namespace, object_name, reason, message, occurrence_count, severity, occurred_at, incident_id)
		 VALUES ($1, $2, $3, $4, 'v1', $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		findingID, tenantID, clusterID, f.DetectorID, fingerprint, f.GVK, f.Namespace, f.ObjectName,
		f.Reason, f.Message, f.OccurrenceCount, f.Severity, now.Add(-f.Ago), incidentID)
	return err
}

func insertDemoAnalysis(ctx context.Context, tx pgx.Tx, tenantID, clusterID, incidentID string, a demoAnalysis, now time.Time) (string, error) {
	analysisID := domain.NewID(domain.PrefixAnalysis)

	causalChain := make([]map[string]any, 0, len(a.CausalChain))
	for _, step := range a.CausalChain {
		toolCalls := make([]map[string]any, 0, len(step.ToolCalls))
		for _, tc := range step.ToolCalls {
			toolCalls = append(toolCalls, map[string]any{"tool": tc.Tool, "args": tc.Args, "result": tc.Result, "error": nil})
		}
		causalChain = append(causalChain, map[string]any{"step": step.Step, "hypothesis": step.Hypothesis, "finding": step.Finding, "toolCalls": toolCalls})
	}
	causalChainJSON, err := json.Marshal(causalChain)
	if err != nil {
		return "", fmt.Errorf("marshal causal chain: %w", err)
	}

	var rootCause map[string]any
	var confidence *float64
	if a.Statement != "" {
		rootCause = map[string]any{"status": "complete", "statement": a.Statement}
		c := a.Confidence
		confidence = &c
	} else {
		rootCause = map[string]any{"status": "partial", "partialReason": a.PartialReason, "suggestedNextSteps": a.SuggestedNextSteps}
	}
	// BACKLOG.md C10: every demo causal chain represents tool calls the demo
	// story narrates as having actually happened (see demoToolCall's own
	// fabricated-but-labeled-real Args/Result) — the same kind of artifact the
	// api backend's own loop produces, never the cli backend's self-reported
	// kind. Labeled explicitly rather than left blank so demo mode exercises
	// the same provenance rendering a real hub-observed analysis does.
	rootCause["causalChainProvenance"] = llm.CausalChainProvenanceHubObserved
	rootCauseJSON, err := json.Marshal(rootCause)
	if err != nil {
		return "", fmt.Errorf("marshal root cause: %w", err)
	}

	iterations := len(a.CausalChain)
	if iterations == 0 {
		iterations = 1
	}
	_, err = tx.Exec(ctx,
		// cost_basis 'metered' explicitly (migration 000033): the sample data
		// carries real-looking cost_usd figures, so it is simulating a
		// metered deployment. Leaving the column NULL would make every demo
		// analysis read as "cost unavailable" in Insights and the spend
		// aggregation (internal/api.TodaySpend counts a non-'metered' basis
		// as unmeasured), which would misrepresent the demo rather than
		// showing what a real metered install looks like.
		`INSERT INTO analyses (id, incident_id, tenant_id, cluster_id, prompt_version, model, causal_chain, ruled_out, root_cause, confidence, iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd, cost_basis, created_at)
		 VALUES ($1, $2, $3, $4, 'v2-tool-calling', 'demo', $5, '[]'::jsonb, $6, $7, $8, $9, $10, $11, $12, $13, 'metered', $14)`,
		analysisID, incidentID, tenantID, clusterID, causalChainJSON, rootCauseJSON, confidence,
		iterations, 3200, int64(iterations*900), int64(iterations*200), int64(iterations*120), 0.008*float64(iterations), now.Add(-a.Ago))
	if err != nil {
		return "", fmt.Errorf("insert demo analysis: %w", err)
	}
	return analysisID, nil
}

func insertDemoPlan(ctx context.Context, tx pgx.Tx, tenantID, clusterID, incidentID, analysisID string, p demoPlan, now time.Time) (string, error) {
	planID := domain.NewID(domain.PrefixPlan)
	paramsJSON, err := json.Marshal(p.Params)
	if err != nil {
		return "", fmt.Errorf("marshal plan params: %w", err)
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO remediation_recommendations (id, incident_id, tenant_id, cluster_id, analysis_id, action_type, target_gvk, target_namespace, target_name, params, reversible, risk_level, gate_outcome, gate_reason, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
		planID, incidentID, tenantID, clusterID, analysisID, p.ActionType, p.TargetGVK, p.TargetNamespace, p.TargetName,
		paramsJSON, p.Reversible, p.RiskLevel, p.GateOutcome, p.GateReason, now.Add(-p.Ago))
	if err != nil {
		return "", fmt.Errorf("insert demo plan: %w", err)
	}
	return planID, nil
}

func insertDemoApproval(ctx context.Context, tx pgx.Tx, tenantID, clusterID, incidentID, planID, actorUserID string, ap demoApproval, now time.Time) error {
	decisionID := domain.NewID(domain.PrefixApproval)
	var reason *string
	if ap.Reason != "" {
		reason = &ap.Reason
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO remediation_approval_decisions (id, recommendation_id, incident_id, tenant_id, cluster_id, actor_id, verdict, reason, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		decisionID, planID, incidentID, tenantID, clusterID, actorUserID, ap.Verdict, reason, now.Add(-ap.Ago))
	return err
}

func insertDemoExecution(ctx context.Context, tx pgx.Tx, tenantID, clusterID, incidentID, planID string, ex demoExecution, now time.Time) error {
	executionID := domain.NewID(domain.PrefixExecution)
	var execErr *string
	if ex.Error != "" {
		execErr = &ex.Error
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO remediation_executions (id, recommendation_id, incident_id, tenant_id, cluster_id, outcome, error, resource_version_precondition, executed_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		executionID, planID, incidentID, tenantID, clusterID, ex.Outcome, execErr, ex.ResourceVersion, now.Add(-ex.Ago))
	return err
}
