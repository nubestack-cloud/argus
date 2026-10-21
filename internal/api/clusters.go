package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/agentversion"
	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/events"
	"argus/internal/logging"
	"argus/internal/orchestrator"
	"argus/internal/timeline"
)

// maxClusterDisplayNameLength bounds handleRenameCluster's input — the
// display_name column itself is a plain, unconstrained `text` (migration
// 000002), but an admin fat-fingering a huge paste into a rename field
// shouldn't get to store an unbounded string just because the schema would
// technically allow it. 200 matches this codebase's other free-text-label
// bounds (e.g. audit `details` values) rather than inventing a new number.
const maxClusterDisplayNameLength = 200

type createEnrollmentTokenRequest struct {
	TTLClass       string            `json:"ttlClass"`       // "A" | "B" | "C" | "F" — lld/03-agent-protocol.md §2, plus F for a fleet token
	MaxRedemptions int               `json:"maxRedemptions"` // only meaningful (>1) for ttlClass "C" and "F"
	ScopeHint      map[string]string `json:"scopeHint"`      // advisory display-name pattern / labels
	// Fleet tokens (ttlClass "F") only.
	Name          string `json:"name"`
	ExpiresInDays int    `json:"expiresInDays"`
	AutoAccept    bool   `json:"autoAccept"`
}

type createEnrollmentTokenResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt"`
	// TokenID names a fleet token for listing and revoking it.
	TokenID string `json:"tokenId,omitempty"`
	// AgentInstall is what the UI needs to print a `helm install` for the
	// agent that works as written, with nothing guessed.
	AgentInstall agentInstallInfo `json:"agentInstall"`
}

// agentInstallInfo comes from the hub's own deployment (the hub chart sets
// these from its values). A field the hub was not told is null, so the UI
// prints a placeholder and says what to fill in rather than inventing an
// address or installing whatever chart version happens to be newest.
type agentInstallInfo struct {
	// ChartRef is where the agent chart is pulled from.
	ChartRef string `json:"chartRef"`
	// ChartVersion is the agent chart released with this hub.
	ChartVersion *string `json:"chartVersion"`
	// HubAPIURL is the address agents use to reach this hub's API.
	HubAPIURL *string `json:"hubApiUrl"`
}

// defaultAgentChartRef is the published agent chart. It is not called
// argus-agent: Docker Hub keeps a chart and an image of the same name in one
// repository, where a chart tag would overwrite the image tag of the same
// release.
const defaultAgentChartRef = "oci://registry-1.docker.io/nubestack/argus-agent-chart"

func optionalEnv(name string) *string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return &v
	}
	return nil
}

func currentAgentInstallInfo() agentInstallInfo {
	ref := strings.TrimSpace(os.Getenv("ARGUS_AGENT_CHART_REF"))
	if ref == "" {
		ref = defaultAgentChartRef
	}
	url := optionalEnv("ARGUS_PUBLIC_API_URL")
	if url != nil {
		trimmed := strings.TrimRight(*url, "/")
		url = &trimmed
	}
	return agentInstallInfo{ChartRef: ref, ChartVersion: optionalEnv("ARGUS_AGENT_CHART_VERSION"), HubAPIURL: url}
}

// handleCreateEnrollmentToken is POST /api/v1/clusters/enrollment-tokens
// (lld/03-agent-protocol.md §2, HLD Appendix A). Requires cluster:onboard
// (lld/02-authz-spec.md §4) — wired via requireCapability in routes().
func (s *Server) handleCreateEnrollmentToken(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	var req createEnrollmentTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}

	if req.TTLClass == authz.TTLClassFleet {
		s.createFleetToken(w, r, rc, req)
		return
	}
	token, expiresAt, err := s.enrollmentSigner.IssueEnrollmentToken(
		r.Context(), rc.Tx, rc.TenantID, rc.UserID, req.TTLClass, req.MaxRedemptions, req.ScopeHint)
	if err != nil {
		logger.ErrorContext(r.Context(), "issuing an enrollment token failed", logging.Err(err))
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-enrollment-request", "Could not issue enrollment token", err.Error())
		return
	}

	// Recorded on rc.Tx — the same request-scoped transaction requireAuth
	// opened and will commit after this handler returns (see
	// requireAuth/bufferedResponseWriter in middleware.go) — so the audit row
	// and the enrollment token it describes commit atomically together.
	// Details carries the AS-REQUESTED ttlClass/maxRedemptions, not
	// IssueEnrollmentToken's internally resolved default (that function
	// doesn't return the resolved value) — acceptable here since `details`
	// is explicitly free-form/non-authoritative and excluded from the hash.
	capability := authz.CapClusterOnboard
	if err := audit.RecordEvent(r.Context(), rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		Outcome:         audit.OutcomeSuccess,
		Details: map[string]any{
			"action":         "create_enrollment_token",
			"ttlClass":       req.TTLClass,
			"maxRedemptions": req.MaxRedemptions,
		},
	}); err != nil {
		logger.ErrorContext(r.Context(), "recording an enrollment-token issue in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	writeJSON(w, http.StatusCreated, createEnrollmentTokenResponse{
		Token:        token,
		ExpiresAt:    formatRFC3339(expiresAt),
		AgentInstall: currentAgentInstallInfo(),
	})
}

// handleAcceptCluster is POST /api/v1/clusters/{id}/accept
// (lld/03-agent-protocol.md §5's `Accept` step, §4's PendingApproval ->
// Provisioning transition). Requires cluster:accept — wired via
// requireCapability in routes(). No request body; records accepted_by.
func (s *Server) handleAcceptCluster(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	clusterID := r.PathValue("id")
	ctx := r.Context()

	var state string
	err := rc.Tx.QueryRow(ctx, `SELECT state FROM clusters WHERE id = $1`, clusterID).Scan(&state)
	if err != nil {
		if err == pgx.ErrNoRows {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Cluster not found", "")
			return
		}
		logger.ErrorContext(ctx, "looking up the cluster to accept failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up cluster", "")
		return
	}
	if state != "PendingApproval" {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/invalid-state",
			"Cluster is not pending approval", fmt.Sprintf("cluster is in state %q", state))
		return
	}

	if _, err := rc.Tx.Exec(ctx,
		`UPDATE clusters SET state = 'Provisioning', accepted_by = $2 WHERE id = $1`,
		clusterID, rc.UserID); err != nil {
		logger.ErrorContext(ctx, "accepting the cluster failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not accept cluster", "")
		return
	}

	// Recorded on rc.Tx, before requireAuth's later Commit — same atomicity
	// rationale as handleCreateEnrollmentToken above.
	capability := authz.CapClusterAccept
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		ClusterID:       &clusterID,
		Outcome:         audit.OutcomeSuccess,
	}); err != nil {
		logger.ErrorContext(ctx, "recording a cluster acceptance in the audit log failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	// Published here, not after a commit this handler never directly
	// observes (rc.Tx commits inside requireAuth's wrapper, after this
	// function returns — see handleDecommissionCluster's s.gw.Disconnect
	// call just below for the identical, already-established reasoning:
	// this is the closest available proxy for "after commit" without a
	// bigger refactor, used consistently rather than reinvented per call site).
	if s.events != nil {
		s.events.Publish(events.ClusterUpdated(clusterID))
	}
	writeJSON(w, http.StatusOK, map[string]string{"clusterId": clusterID, "status": "Provisioning"})
}

type renameClusterRequest struct {
	DisplayName string `json:"displayName"`
}

// handleRenameCluster is POST /api/v1/clusters/{id}/rename. Requires
// cluster:onboard — the same capability that already governs naming a
// cluster at enrollment time (handleEnroll/handleCreateEnrollmentToken's
// scopeHint), since renaming is that same "manage a cluster's identity
// metadata" authority applied after the fact rather than a distinct
// concern. lld/02-authz-spec.md §4 was never asked this exact question (its
// four-capability cluster row predates this endpoint) — reusing the closest
// existing capability rather than minting a new one nothing else needs
// matches this codebase's own established practice (e.g. the approval
// queue reusing remediation:approve/reject rather than a new capability).
//
// Valid from any state, including terminal ones (Archived/Rejected) — an
// operator correcting a typo in a decommissioned cluster's historical name
// (it still shows up in past incidents/audit rows) is a legitimate, harmless
// edit, unlike accept/decommission which are real state transitions with
// real preconditions.
//
// Added directly in response to a real, user-reported gap: a cluster
// enrolled without ARGUS_CLUSTER_DISPLAY_NAME/values.displayName set falls
// back to "cluster-" + a short fingerprint hash (handleEnroll) — meaningful
// to no one looking at the fleet list. The right long-term fix is setting
// that value at install time; this is the necessary complement for every
// cluster already enrolled before an operator thinks to do that, or for
// simply renaming a cluster later without a real re-enrollment.
func (s *Server) handleRenameCluster(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	clusterID := r.PathValue("id")
	ctx := r.Context()

	var req renameClusterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "displayName must not be empty", "")
		return
	}
	if len(displayName) > maxClusterDisplayNameLength {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
			fmt.Sprintf("displayName must be %d characters or fewer", maxClusterDisplayNameLength), "")
		return
	}

	tag, err := rc.Tx.Exec(ctx, `UPDATE clusters SET display_name = $2 WHERE id = $1`, clusterID, displayName)
	if err != nil {
		logger.ErrorContext(ctx, "renaming the cluster failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not rename cluster", "")
		return
	}
	if tag.RowsAffected() == 0 {
		writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Cluster not found", "")
		return
	}

	capability := authz.CapClusterOnboard
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		ClusterID:       &clusterID,
		Outcome:         audit.OutcomeSuccess,
		Details:         map[string]any{"action": "rename_cluster", "displayName": displayName},
	}); err != nil {
		logger.ErrorContext(ctx, "recording a cluster rename in the audit log failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	if s.events != nil {
		s.events.Publish(events.ClusterUpdated(clusterID))
	}
	writeJSON(w, http.StatusOK, map[string]string{"clusterId": clusterID, "displayName": displayName})
}

// handleDecommissionCluster is POST /api/v1/clusters/{id}/decommission
// (lld/03-agent-protocol.md §4's "explicit offboarding action" — the only way
// into the terminal Archived state; there is no automatic transition into it).
// Requires cluster:delete. Valid from any non-terminal state (Archived and
// Rejected are both already terminal — decommissioning either again is a
// no-op the caller should not be misled about, hence 409, not 200).
func (s *Server) handleDecommissionCluster(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	clusterID := r.PathValue("id")
	ctx := r.Context()

	// display_name is read alongside state because every incident this call
	// closes gets a timeline line naming the cluster that went away — an
	// operator reading a closed incident six months later needs to know WHICH
	// cluster's decommission closed it, and the id alone doesn't say.
	var state, displayName string
	err := rc.Tx.QueryRow(ctx, `SELECT state, display_name FROM clusters WHERE id = $1`, clusterID).Scan(&state, &displayName)
	if err != nil {
		if err == pgx.ErrNoRows {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Cluster not found", "")
			return
		}
		logger.ErrorContext(ctx, "looking up the cluster to decommission failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up cluster", "")
		return
	}
	if state == "Archived" || state == "Rejected" {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/invalid-state",
			"Cluster is already in a terminal state", fmt.Sprintf("cluster is in state %q", state))
		return
	}

	if _, err := rc.Tx.Exec(ctx,
		`UPDATE clusters SET state = 'Archived', archived_at = now() WHERE id = $1`,
		clusterID); err != nil {
		logger.ErrorContext(ctx, "marking the cluster decommissioned failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not decommission cluster", "")
		return
	}

	// Close this cluster's still-open incidents, in the same transaction as
	// the archival itself. See closeIncidentsForDecommission for why they must
	// be closed at all, why they go through the state machine one at a time,
	// and what happens to work that is in flight when this runs.
	closure, err := closeIncidentsForDecommission(ctx, rc.Tx, rc.TenantID, clusterID, displayName)
	if err != nil {
		logger.ErrorContext(ctx, "closing the cluster's open incidents during decommission failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not close the cluster's open incidents", "")
		return
	}
	if closure.Closed > 0 || closure.LeftOpen > 0 {
		logger.InfoContext(ctx, "cluster decommissioned: open incidents dismissed",
			logging.ClusterID(clusterID), slog.Int("closed", closure.Closed),
			slog.Int("investigations_cancelled", closure.InvestigationsCancelled),
			slog.Int("executions_unconfirmed", closure.ExecutionsUnconfirmed),
			slog.Int("left_open", closure.LeftOpen))
	}

	capability := authz.CapClusterDelete
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		ClusterID:       &clusterID,
		Outcome:         audit.OutcomeSuccess,
		// incidentsDismissed is recorded because this one call can close an
		// arbitrary number of incidents as a side effect, and an audit trail
		// that shows only "cluster archived" would leave that invisible.
		//
		// The three counters beside it are the side effects a reader would
		// otherwise have to reconstruct from timeline rows one incident at a
		// time: how much work this call cancelled or abandoned, and whether it
		// managed to close everything. investigationsCancelled and
		// executionsLeftUnconfirmed are not decorations — an unconfirmed
		// execution means a mutation may have landed on a cluster ARGUS can no
		// longer see, which is a fact an auditor asking "what changed in that
		// cluster?" has to be able to find. incidentsLeftOpen is normally 0;
		// anything else means closeIncidentsForDecommission fail-closed on a
		// state it did not recognise, and the residue this whole path exists
		// to prevent is back.
		Details: map[string]any{
			"action":                    "decommission_cluster",
			"previousState":             state,
			"incidentsDismissed":        closure.Closed,
			"investigationsCancelled":   closure.InvestigationsCancelled,
			"executionsLeftUnconfirmed": closure.ExecutionsUnconfirmed,
			"incidentsLeftOpen":         closure.LeftOpen,
		},
	}); err != nil {
		logger.ErrorContext(ctx, "recording a cluster decommission in the audit log failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	// Sever any live tunnel connection this cluster has right now, rather
	// than leaving it running until it happens to drop on its own.
	// lookupClusterBySerial's clusterState check (internal/gateway/server.go)
	// already refuses a *new* connection attempt from a decommissioned
	// cluster's (still cryptographically valid) cert — but that check only
	// ever runs at the top of handleConn, so on its own it does nothing for
	// a tunnel that was already open at the moment this handler ran. This
	// call is what actually closes that gap. It's a best-effort in-memory
	// action (not persisted, not part of rc.Tx) issued once the state
	// change and its audit record have both been written successfully to
	// rc.Tx — the same *gateway.Gateway instance the tunnel listener itself
	// runs on (s.gw, threaded in via NewServer — see server.go), not a
	// second one. A false return (no connection was live) is the ordinary,
	// unremarkable case and not logged as an error.
	//
	// Deferred to after the commit (requestContext.OnCommit) rather than run
	// inline. The comment above says "issued once the state change and its
	// audit record have both been written successfully to rc.Tx" — but written
	// to a transaction is not the same as committed, and rc.Tx commits only
	// after this handler returns. A commit failure therefore used to leave the
	// tunnel severed while the cluster stayed Active in the database: a cluster
	// that looks healthy and connected but isn't, recoverable only by
	// restarting the agent. Severing a live tunnel is exactly the kind of
	// irreversible, outside-the-database side effect that must not happen
	// unless the decommission actually persisted.
	rc.OnCommit(func() {
		s.gw.Disconnect(clusterID)
		if s.events != nil {
			s.events.Publish(events.ClusterUpdated(clusterID))
			// One aggregate IncidentUpdated for the whole batch, not one per
			// closed incident. ClusterUpdated alone invalidates only the
			// ['clusters'] query key (web/src/realtime/useLiveEvents.ts), so
			// without this an operator watching the incident list keeps seeing
			// incidents this call just closed until the next poll. Per-incident
			// events would be the obvious alternative and are the wrong one:
			// events.Bus gives each subscriber a 16-event buffer and drops
			// beyond it, so a decommission closing a few hundred incidents
			// would evict every other client's pending events to say the same
			// thing several hundred times. IncidentID is omitempty on the wire
			// and the frontend branches only on Type, so a cluster-scoped
			// IncidentUpdated is a valid, already-understood message.
			if closure.Closed > 0 {
				s.events.Publish(events.IncidentUpdated("", clusterID))
			}
		}
	})

	writeJSON(w, http.StatusOK, map[string]string{"clusterId": clusterID, "status": "Archived"})
}

// decommissionClosure is what closeIncidentsForDecommission actually did,
// reported back so the handler's audit record and log line can state it
// rather than a bare row count.
type decommissionClosure struct {
	// Closed is how many incidents reached Dismissed.
	Closed int
	// InvestigationsCancelled counts the subset of Closed that were
	// Investigating — an analysis was running and this call ended it.
	InvestigationsCancelled int
	// ExecutionsUnconfirmed counts the subset of Closed that were Executing —
	// a signed plan was in flight over the tunnel this call is about to sever,
	// and whether it landed is now permanently unknown.
	ExecutionsUnconfirmed int
	// LeftOpen counts incidents this helper refused to touch because their
	// state has no path to Dismissed it recognises. Expected to be 0; a
	// non-zero value is a bug report, not a routine outcome.
	LeftOpen int
}

// closeIncidentsForDecommission closes every still-open incident belonging to
// a cluster being archived, inside the caller's transaction — the same one
// that flips clusters.state to Archived, so the archival and its consequences
// commit or roll back together.
//
// # Why the incidents have to close at all
//
// Left open they are the worst kind of open: nothing can ever progress them.
// The agent is gone, so no recurrence can resolve them and no detector can
// update them; the tunnel is refused on connect (the gateway rejects an
// Archived cluster), so no investigation can gather evidence and no
// remediation can execute. They sit in the operator's list as permanent,
// un-actionable residue — observed live, an archived cluster still showing
// open node-pressure incidents it had no way to shed.
//
// # Why one at a time through SetState, and not one UPDATE
//
// This was a single `UPDATE incidents SET state = 'Dismissed' WHERE ...`. It
// was fast and it was wrong, in a way that got worse every time somebody
// added an invariant somewhere else:
//
//   - It never stamped resolved_at, so incidents closed by a decommission had
//     no close time at all while every other closing path had one.
//   - It never recomputed the fleet/replica/object correlation groups, so a
//     fleet-wide group could keep counting a cluster that no longer exists.
//   - It never wrote a timeline event, so the incident's own history simply
//     stopped, with no line saying why.
//   - It took edges the state machine forbids. Executing -> Dismissed is not
//     in allowedTransitions, and the raw UPDATE took it anyway, closing
//     incidents with a signed plan in flight as though nothing were happening.
//   - It excluded Investigating to avoid exactly that problem, which produced
//     the reverse one: an analysis still running when the cluster was archived
//     landed afterwards and moved its incident to AwaitingApproval — an
//     actionable plan, awaiting a human, for a cluster that can never
//     reconnect. Nothing could act on it and nothing would ever close it.
//
// None of those are individually hard to fix in place. The point is that each
// one had to be REMEMBERED here, separately, forever, and the fifth invariant
// nobody remembers is the one that bites. orchestrator.SetState is the single
// function in this codebase that writes incidents.state, and everything the
// list above is missing already lives inside it. Going through it means the
// next invariant added there applies here for free.
//
// The cost is real and is accepted, and the numbers are measured rather than
// assumed. Each incident costs roughly a dozen statements — the locking read,
// the state write, three correlation-group recomputations, a timeline row —
// instead of one statement for the whole set. Against the dev Postgres
// (2026-09-05), closing a synthetic cluster's incidents took 0.5 s for 50,
// 2.2 s for 200 and 3.5 s for 500: around 10 ms an incident, which is what a
// human dismissing one incident already pays today.
//
// It is not linear at the top end — 2,000 incidents took a little over a
// minute — and the reason is worth writing down so nobody re-derives it. The
// dominant cost is orchestrator.SetState's three Recompute calls, and each one
// scans: neither incidents.fingerprint nor findings.fingerprint has an index
// leading on the column these queries filter by, so the per-incident cost
// grows with the size of the tables. That is a pre-existing property of every
// closing transition in this codebase, not something this loop introduces; it
// is simply the first caller that pays it a few thousand times in a row. If a
// real fleet ever decommissions a cluster carrying that many open incidents,
// the fix is an index, or moving this loop to a background job that still
// calls SetState — never reintroducing a bulk UPDATE that opts out of the
// state machine to buy the time back.
//
// A decommission is a deliberate, once-per-cluster administrative action, and
// a cluster with hundreds of simultaneously-open incidents is already an
// unusual one (detection dedups by object and has storm protection). Paying a
// couple of seconds once, to close a cluster's incidents the same way every
// other path closes an incident, is the right trade.
//
// # Two decisions worth stating explicitly
//
// 1. In-flight work is CANCELLED, not waited for, and does not block the
// decommission. The alternatives were to let an analysis land and close the
// incident afterwards, or to refuse the decommission while anything is in
// flight. Letting it land needs a durable "close me when you are done" marker
// and a sweeper to honour it, all so an investigation can finish against a
// cluster whose tunnel is severed at commit — every remaining tool call would
// fail, so the analysis it produces is worthless even if it completes.
// Refusing is worse: an operator offboarding a cluster would be blocked by a
// background auto-analysis they cannot see or stop, and an incident wedged in
// Executing by a hub crash would block the decommission permanently. Cancelling
// is the only option that leaves nothing pending, and it is honest about it —
// both cases get a timeline line saying what was abandoned.
//
// A cancelled investigation or execution that lands after this commits is not
// silently dropped: orchestrator.SetState refuses the illegal transition out
// of the now-terminal incident, and recordExecutionOutcome (internal/execution)
// already handles that by persisting the execution row with its real outcome
// and recording a stateNote explaining why the incident did not move. The work
// that finished is recorded; only its claim on the incident's state is denied.
//
// 2. These closures are Dismissed, never Resolved. Resolved asserts the
// problem is gone; nobody established that. What changed is that ARGUS stopped
// watching. The stakes went up when incidents.resolution_kind landed
// (migration 000091): SetState derives that column on every transition into
// Resolved, and since a decommissioned cluster's incidents carry no succeeded
// execution and no merged pull request, closing them as Resolved would stamp
// every one of them 'self_healed'. That column exists precisely to measure how
// often incidents close with no ARGUS action behind them, so filling it with
// clusters that were switched off would corrupt the one distinction it was
// added to make. Dismissed leaves resolution_kind NULL — honestly inapplicable
// — which is the same treatment SetState already gives a human's rejection,
// and for the same reason. No third enum value is invented here: the column's
// contract is "set only on the transition into Resolved", and the reason for
// this closure belongs in the timeline event and the audit record, which is
// where it is written.
func closeIncidentsForDecommission(ctx context.Context, tx pgx.Tx, tenantID, clusterID, clusterDisplayName string) (decommissionClosure, error) {
	var closure decommissionClosure

	type openIncident struct{ id, state string }

	// FOR UPDATE here, rather than relying on the lock SetState takes per
	// incident further down. Without it the state read here could be stale by
	// the time the matching SetState runs, and the walk chosen for it would be
	// the wrong one. Taking every lock in the one statement that reads the set
	// makes each row's state fixed for the rest of this transaction, so the
	// path decided below is the path that is still legal when it is applied.
	// Re-locking the same row inside SetState is then a no-op.
	//
	// This blocks on any row another transaction currently holds, which is
	// bounded: the remediation path commits its Executing transition and
	// releases the lock BEFORE the tunnel call, so this never waits on a
	// network round trip to a cluster.
	rows, err := tx.Query(ctx,
		`SELECT id, state FROM incidents
		   WHERE cluster_id = $1 AND state NOT IN ('Resolved', 'Dismissed')
		   ORDER BY first_seen, id
		   FOR UPDATE`, clusterID)
	if err != nil {
		return closure, fmt.Errorf("list open incidents for cluster %s: %w", clusterID, err)
	}
	var open []openIncident
	for rows.Next() {
		var inc openIncident
		if err := rows.Scan(&inc.id, &inc.state); err != nil {
			rows.Close()
			return closure, fmt.Errorf("scan an open incident for cluster %s: %w", clusterID, err)
		}
		open = append(open, inc)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return closure, fmt.Errorf("read open incidents for cluster %s: %w", clusterID, err)
	}

	for _, inc := range open {
		path := decommissionClosurePath(inc.state)
		if path == nil {
			// Fail closed on a state this function does not recognise rather
			// than forcing it through an edge that might not exist. Loud,
			// counted, and surfaced in the audit record — an incident left
			// open here is the exact residue this path exists to prevent, so
			// it must not be silent.
			closure.LeftOpen++
			logger.WarnContext(ctx, "leaving an incident open during decommission: its state has no path to Dismissed",
				logging.IncidentID(inc.id), logging.ClusterID(clusterID),
				slog.String("state", string(inc.state)), slog.String("target_state", string(orchestrator.StateDismissed)))
			continue
		}
		for _, next := range path {
			if err := orchestrator.SetState(ctx, tx, inc.id, next); err != nil {
				return closure, fmt.Errorf("close incident %s (%s -> %s) for decommissioned cluster %s: %w",
					inc.id, inc.state, next, clusterID, err)
			}
		}

		summary, detail := decommissionClosureRecord(inc.state, clusterID, clusterDisplayName)
		if err := timeline.Record(ctx, tx, timeline.Event{
			TenantID: tenantID, ClusterID: clusterID, IncidentID: inc.id,
			Type:    timeline.EventIncidentDismissed,
			Summary: summary,
			Detail:  detail,
		}); err != nil {
			return closure, fmt.Errorf("record the closing timeline event for incident %s: %w", inc.id, err)
		}

		closure.Closed++
		switch inc.state {
		case orchestrator.StateInvestigating:
			closure.InvestigationsCancelled++
		case orchestrator.StateExecuting:
			closure.ExecutionsUnconfirmed++
		}
	}
	return closure, nil
}

// decommissionClosurePath returns the states an incident currently in `state`
// must be walked through, in order, to reach Dismissed — or nil if this
// function knows no legal way to get it there.
//
// Every step is an edge orchestrator.allowedTransitions already permits. That
// is deliberate: the alternative was to add Investigating -> Dismissed and
// Executing -> Dismissed to the state machine, and both are edges the state
// machine refuses ON PURPOSE. Their absence is what stops a human closing an
// incident out from under a writer that owns it, and adding them for this
// caller's convenience would remove that protection from every other caller
// too. Most open states already have a direct Dismissed edge; three do not,
// each for its own reason, and each has an existing intermediate state that
// already means what a decommission does to it — two have work in flight;
// the third, Expired (PROJECT.md T2), has no direct Dismissed edge at all
// because its only real edge is back to Detected (a genuine recurrence):
//
//   - Investigating -> Detected is the analyzer's own failure edge, and it
//     means precisely "no analysis exists, nothing is running, and the incident
//     is exactly as un-investigated as before the attempt" — which is the true
//     state of an investigation whose cluster just went away. (state.go's
//     comment on that edge notes it had a single caller; this is the second,
//     and it qualifies for the same reason the first does: it is taken by a
//     writer that has just made the in-flight work impossible, in the
//     transaction that made it impossible.)
//   - Executing -> ExecutionUnknown means "a mutation was in flight and we
//     cannot confirm whether it applied", which is exactly what severing the
//     tunnel mid-plan produces. Reaching it also notifies (it is in
//     orchestrator's notifiableStates), which is correct and wanted here: a
//     change may have landed on a cluster nobody is watching any more, and
//     that is worth telling a human even though the incident then closes.
//   - Expired -> Detected -> Dismissed is the third two-hop case, added when
//     PROJECT.md T2 gave Expired its own state: Expired's only real edge is
//     back to Detected (a genuine recurrence), so it has no direct Dismissed
//     edge to fall back on the same way Investigating does not. This is not
//     a step backward for a bulk/mechanical closure that was already
//     disposition=closed — nobody reads the momentary Detected hop, and the
//     final Dismissed is what the decommission's own timeline event records.
//
// The intermediate state is never externally visible — both hops happen in the
// decommission's own transaction — so this is a way of reusing the state
// machine's existing vocabulary, not a way of smuggling an extra state into
// the incident's history. The history is written explicitly, once, by the
// timeline event the caller records.
func decommissionClosurePath(state string) []string {
	switch state {
	case orchestrator.StateInvestigating:
		return []string{orchestrator.StateDetected, orchestrator.StateDismissed}
	case orchestrator.StateExecuting:
		return []string{orchestrator.StateExecutionUnknown, orchestrator.StateDismissed}
	case orchestrator.StateExpired:
		return []string{orchestrator.StateDetected, orchestrator.StateDismissed}
	}
	if orchestrator.CanTransition(state, orchestrator.StateDismissed) {
		return []string{orchestrator.StateDismissed}
	}
	return nil
}

// decommissionClosureRecord builds the timeline line for one closed incident.
//
// The summary says what happened and refuses to imply more than that: the
// cluster was decommissioned, so ARGUS stopped watching — not that the problem
// was fixed. The two in-flight cases get an extra sentence each, because
// "your analysis was cancelled" and "a change may have been applied and we
// cannot tell" are things an operator reading this incident later has to be
// told outright, not left to infer from a state name.
//
// Detail carries the same facts structurally (reason, fromState, clusterId,
// and for the in-flight cases inFlightWork) so a query can find these closures
// without parsing prose — there is no incidents column recording why a closure
// happened, and this is deliberately not the change that adds one.
func decommissionClosureRecord(fromState, clusterID, clusterDisplayName string) (string, map[string]any) {
	summary := fmt.Sprintf(
		"Closed because cluster %q was decommissioned. ARGUS is no longer watching this cluster; nobody established that the underlying problem went away.",
		clusterDisplayName)
	detail := map[string]any{
		"reason":    "cluster_decommissioned",
		"fromState": fromState,
		"clusterId": clusterID,
	}
	switch fromState {
	case orchestrator.StateInvestigating:
		summary += " An investigation was running and was cancelled — the cluster's tunnel is being severed, so it could not have completed."
		detail["inFlightWork"] = "investigation"
	case orchestrator.StateExecuting:
		summary += " A remediation plan was in flight when the tunnel was severed. Whether it applied to the cluster is unknown and can no longer be checked through ARGUS — check the cluster directly if it still exists."
		detail["inFlightWork"] = "execution"
	}
	return summary, detail
}

// clusterSummary is the shape returned by both handleListClusters (as an
// element of "clusters") and as the base fields of handleGetCluster's
// response.
type clusterSummary struct {
	ID              string  `json:"id"`
	DisplayName     string  `json:"displayName"`
	State           string  `json:"state"`
	AgentVersion    *string `json:"agentVersion"`
	LastHeartbeatAt *string `json:"lastHeartbeatAt"`
	CreatedAt       string  `json:"createdAt"`
	// ArchivedAt is non-null exactly when this cluster has been
	// decommissioned (handleDecommissionCluster sets state='Archived' and
	// archived_at=now() in one UPDATE, so the two can't disagree). It is on
	// the wire so a retirement is a SERVER-STATED fact with a date, rather
	// than something the UI infers from the state string — the fleet list
	// has to be able to say WHEN a cluster was retired, and a client that
	// re-derived "archived" from `state` would be a second copy of a rule
	// only the hub should own.
	ArchivedAt *string `json:"archivedAt"`
	// Compatibility is T16's fleet- and detail-page verdict, derived from
	// the ONE server-owned policy (agentversion.Policy) every time this
	// struct is built — never computed twice, and never computed in the
	// frontend. See agentversion's package comment for why this rides
	// alongside `state` rather than through it.
	Compatibility agentversion.Compatibility `json:"compatibility"`
}

// clusterArchivalPredicate maps the ?archived= query parameter to the SQL
// predicate handleListClusters appends. The values are a closed set and the
// predicates are compile-time constants — nothing the caller sends is ever
// interpolated into the statement.
//
// The default (parameter absent) stays `exclude`, and that default is
// load-bearing rather than incidental: every cluster picker, cluster count
// and cluster-scope control in the web UI calls GET /clusters with no
// parameters, so a retired cluster is excluded from all of them by
// construction — not by each call site remembering to filter. Only a caller
// that deliberately asks for the retired fleet gets it.
var clusterArchivalPredicate = map[string]string{
	"exclude": "WHERE archived_at IS NULL",
	"only":    "WHERE archived_at IS NOT NULL",
	"include": "",
}

// handleListClusters is GET /api/v1/clusters. Requires cluster:read.
//
// ?archived=exclude (the default) | only | include — see
// clusterArchivalPredicate. An unknown value is a 400 rather than a silent
// fallback to the default: a caller that asked for the retired fleet and
// misspelled it would otherwise get the live fleet back and have no way to
// tell, which is the "looks like data, is actually a different question"
// failure this codebase has already paid for elsewhere.
func (s *Server) handleListClusters(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	archived := r.URL.Query().Get("archived")
	if archived == "" {
		archived = "exclude"
	}
	predicate, ok := clusterArchivalPredicate[archived]
	if !ok {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
			"Unknown archived filter",
			fmt.Sprintf("archived must be one of \"exclude\", \"include\" or \"only\"; got %q", archived))
		return
	}

	rows, err := rc.Tx.Query(r.Context(),
		`SELECT id, display_name, state, agent_version, last_heartbeat_at, created_at, archived_at
		   FROM clusters `+predicate+` ORDER BY id`)
	if err != nil {
		logger.ErrorContext(r.Context(), "querying clusters failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list clusters", "")
		return
	}
	defer rows.Close()

	clusters := []clusterSummary{}
	for rows.Next() {
		c, err := scanClusterSummary(rows)
		if err != nil {
			logger.ErrorContext(r.Context(), "scanning a cluster row failed", logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list clusters", "")
			return
		}
		clusters = append(clusters, c)
	}
	if err := rows.Err(); err != nil {
		logger.ErrorContext(r.Context(), "iterating the cluster rows failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list clusters", "")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"clusters": clusters})
}

// scanClusterSummary scans one row shaped like handleListClusters'/
// handleGetCluster's shared SELECT (id, display_name, state, agent_version,
// last_heartbeat_at, created_at, archived_at) into a clusterSummary.
func scanClusterSummary(row pgx.Row) (clusterSummary, error) {
	var c clusterSummary
	var agentVersion *string
	var lastHeartbeatAt *time.Time
	var createdAt time.Time
	var archivedAt *time.Time
	if err := row.Scan(&c.ID, &c.DisplayName, &c.State, &agentVersion, &lastHeartbeatAt, &createdAt, &archivedAt); err != nil {
		return clusterSummary{}, err
	}
	c.AgentVersion = agentVersion
	if lastHeartbeatAt != nil {
		f := formatRFC3339(*lastHeartbeatAt)
		c.LastHeartbeatAt = &f
	}
	c.CreatedAt = formatRFC3339(createdAt)
	if archivedAt != nil {
		f := formatRFC3339(*archivedAt)
		c.ArchivedAt = &f
	}
	// The single evaluation point: every cluster this codebase ever renders
	// (fleet list or detail page) gets its Compatibility from this one call,
	// against the one package-level agentversion.Policy — see that
	// package's comment for what "server-owned" means in practice.
	c.Compatibility = agentversion.Policy.Evaluate(c.AgentVersion)
	return c, nil
}

// handleGetCluster is GET /api/v1/clusters/{id}. Requires cluster:read. Same
// fields as handleListClusters' elements, plus the joined cluster_facts row
// (null if the agent hasn't completed its first inventory sync yet).
func (s *Server) handleGetCluster(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	clusterID := r.PathValue("id")
	ctx := r.Context()

	// requireAuth already scoped rc.Tx to this tenant with an EMPTY
	// accessible-cluster-id list (no per-route cluster-scope resolution exists
	// yet — see internal/api/middleware.go's comment). clusters itself reads
	// fine regardless (migration 000011 added a tenant_id-keyed policy
	// alongside its id-keyed one), but cluster_facts is one of migration
	// 000009's generic cluster_id-scoped tables with ONLY that predicate — no
	// tenant_id fallback. We already know exactly which cluster this request
	// is about (the URL's {id}), so narrow the scope to it for the rest of
	// this handler; found by actually exercising this route against the live
	// stack, not by review (an empty-cluster_facts response was silently
	// returned instead of an RLS error, because "no matching row" and
	// "row exists but RLS hides it" look identical to a SELECT).
	//
	// SECURITY: the narrowing below sets the RLS scope from a value the CALLER
	// controls (the URL path), so it must be authorised first. Under S1 read
	// access is bounded by RLS alone — there is no per-row read check after this
	// point — which means widening the scope to an unchecked cluster id would let
	// a user granted cluster:read on ONE cluster read any cluster in the fleet by
	// changing the URL. The route-level requireCapability cannot catch it: it
	// checks the capability without a scope, exactly as
	// internal/api/approvals.go's per-plan gate explains. So the per-cluster check
	// belongs here, before the scope is touched.
	//
	// 403 rather than 404, matching the four existing cluster-scoped gates and
	// recording the denial in the audit trail. That does confirm to a caller that
	// a cluster id they cannot read exists; consistency with every other authz
	// gate and having the attempt audited are worth more than hiding that, and a
	// cluster id is not a secret.
	allowed, err := authz.HasCapabilityForCluster(ctx, rc.Tx, rc.Grants, authz.CapClusterRead, clusterID)
	if err != nil {
		logger.ErrorContext(ctx, "resolving cluster-scoped capability failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not resolve the scope of your permissions", "")
		return
	}
	if !allowed {
		s.recordCapabilityDenial(ctx, rc, authz.CapClusterRead, clientIP(r))
		writeProblem(w, http.StatusForbidden, "https://argus.io/errors/scope-denied",
			"Missing required capability",
			fmt.Sprintf("reading cluster %s requires capability %q on that cluster; your grant for it is scoped to other clusters", clusterID, authz.CapClusterRead))
		return
	}

	if err := data.SetRequestScope(ctx, rc.Tx, rc.TenantID, []string{clusterID}); err != nil {
		logger.ErrorContext(ctx, "narrowing the request scope to this cluster failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not scope request", "")
		return
	}

	row := rc.Tx.QueryRow(ctx,
		`SELECT id, display_name, state, agent_version, last_heartbeat_at, created_at, archived_at
		   FROM clusters WHERE id = $1`, clusterID)
	c, err := scanClusterSummary(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Cluster not found", "")
			return
		}
		logger.ErrorContext(ctx, "looking up the cluster failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up cluster", "")
		return
	}

	// factsUpdatedAt is when the HUB last received this payload, not when the
	// agent claims it looked (PROJECT.md B177). Everything inside `facts` is
	// an absolute-state snapshot — detector last-success times, denied reads,
	// node counts, remediation authority — and a snapshot carries no evidence
	// of its own age, so without this a reader cannot tell "the sweep detector
	// succeeded two minutes ago" from the same sentence recorded an hour ago
	// and never revisited. The agent re-sends facts every
	// agent.factsRefreshInterval over an established tunnel, so on a healthy
	// cluster this timestamp is minutes old; if it is not, the facts beside it
	// are exactly that stale and must not be read as current.
	//
	// Hub clock, deliberately: this answers "how long since we heard", which
	// is the hub's own question and must not depend on an agent's clock being
	// right. (Comparisons WITHIN facts — LastSuccessAt against ErrorAt — are
	// all agent-clock and stay internally consistent regardless.)
	var facts json.RawMessage
	var factsUpdatedAt time.Time
	err = rc.Tx.QueryRow(ctx, `SELECT facts, updated_at FROM cluster_facts WHERE cluster_id = $1`, clusterID).Scan(&facts, &factsUpdatedAt)
	if err != nil && err != pgx.ErrNoRows {
		logger.ErrorContext(ctx, "looking up the cluster's facts failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up cluster facts", "")
		return
	}
	// Omitted rather than zero-valued when there is no row at all: a cluster
	// whose agent has never completed an inventory sync has no freshness to
	// report, and "0001-01-01" would be a fabricated one. Same discipline as
	// never rendering a missing count as 0.
	var factsUpdatedAtJSON *string
	if err == nil {
		f := formatRFC3339(factsUpdatedAt)
		factsUpdatedAtJSON = &f
	}

	// PROJECT.md B176's residual: what this cluster's agent last reported
	// about its own finding queue, from the clusters row the heartbeat
	// handler keeps current (migration 000118). A separate read rather than
	// a wider first SELECT so scanClusterSummary — shared with the fleet
	// list, which does not carry this — stays one shape.
	//
	// Null-preserving all the way out: nil here means the agent never
	// reported it (a build older than tunnel.Heartbeat.FindingQueue), which
	// is NOT the same claim as "nothing dropped", and the response omits the
	// object entirely rather than rendering a fabricated zero.
	var qPending, qDropped, qCapacity *int
	if err := rc.Tx.QueryRow(ctx,
		`SELECT finding_queue_pending, finding_queue_dropped, finding_queue_capacity FROM clusters WHERE id = $1`,
		clusterID).Scan(&qPending, &qDropped, &qCapacity); err != nil {
		logger.ErrorContext(ctx, "looking up the cluster's finding-queue status failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up cluster", "")
		return
	}
	var findingQueue map[string]any
	if qDropped != nil {
		findingQueue = map[string]any{"pending": qPending, "dropped": qDropped, "capacity": qCapacity}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":              c.ID,
		"displayName":     c.DisplayName,
		"state":           c.State,
		"agentVersion":    c.AgentVersion,
		"lastHeartbeatAt": c.LastHeartbeatAt,
		"createdAt":       c.CreatedAt,
		// What this cluster's agent last said about its own finding queue,
		// as of lastHeartbeatAt above. Absent when the agent does not report
		// it — never a zero standing in for "we don't know".
		"findingQueue": findingQueue,
		// Same field handleListClusters' rows carry (ClusterDetail allOf's
		// Cluster in the spec, so omitting it here would be a contract
		// break, not just a missing convenience).
		"archivedAt": c.ArchivedAt,
		"facts":      facts, // nil (json.RawMessage) marshals as null when no row yet
		// When the hub last received `facts` — see the query above. Null
		// whenever facts itself is null.
		"factsUpdatedAt": factsUpdatedAtJSON,
		// Same value handleListClusters puts on this cluster's list row —
		// scanClusterSummary is the one place either endpoint computes it.
		"compatibility": c.Compatibility,
		// PROJECT.md AD10: the agent image this hub was released with, or
		// null when the hub was not told (no upgrade is offered then).
		"hubAgentImage": optionalString(hubAgentImage()),
	})
}

func optionalString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// createFleetToken issues a fleet token (ttlClass "F"): one token a whole
// GitOps rollout of the agent chart shares. Auto-accept accepts every cluster
// enrolled with it on the issuer's behalf, so issuing one needs cluster:accept
// as well as cluster:onboard.
func (s *Server) createFleetToken(w http.ResponseWriter, r *http.Request, rc *requestContext, req createEnrollmentTokenRequest) {
	if req.AutoAccept && !authz.HasCapability(rc.Grants, authz.CapClusterAccept) {
		writeProblem(w, http.StatusForbidden, "https://argus.io/errors/forbidden",
			"Auto-accept needs the cluster:accept capability", "A fleet token that accepts clusters by itself accepts them on your behalf.")
		return
	}
	token, tokenID, expiresAt, err := s.enrollmentSigner.IssueFleetToken(r.Context(), rc.Tx, rc.TenantID, rc.UserID, authz.FleetTokenRequest{
		Name: req.Name, Days: req.ExpiresInDays, MaxRedemptions: req.MaxRedemptions, AutoAccept: req.AutoAccept,
	})
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-enrollment-request", "Could not issue fleet token", err.Error())
		return
	}
	capability := authz.CapClusterOnboard
	if err := audit.RecordEvent(r.Context(), rc.Tx, audit.Event{
		TenantID: rc.TenantID, ActorID: &rc.UserID, ActorAuthMethod: "jwt", SourceIP: clientIP(r),
		Capability: &capability, Outcome: audit.OutcomeSuccess,
		Details: map[string]any{
			"action": "create_fleet_token", "tokenId": tokenID, "name": req.Name,
			"expiresAt": formatRFC3339(expiresAt), "maxRedemptions": req.MaxRedemptions, "autoAccept": req.AutoAccept,
		},
	}); err != nil {
		logger.ErrorContext(r.Context(), "recording a fleet token issue in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}
	writeJSON(w, http.StatusCreated, createEnrollmentTokenResponse{
		Token: token, TokenID: tokenID, ExpiresAt: formatRFC3339(expiresAt), AgentInstall: currentAgentInstallInfo(),
	})
}

// handleListFleetTokens is GET /api/v1/clusters/fleet-tokens. Requires
// cluster:onboard. Never returns a token itself, which is shown once.
func (s *Server) handleListFleetTokens(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	tokens, err := authz.ListFleetTokens(r.Context(), rc.Tx)
	if err != nil {
		logger.ErrorContext(r.Context(), "listing fleet tokens failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list fleet tokens", "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": tokens})
}

// handleRevokeFleetToken is DELETE /api/v1/clusters/fleet-tokens/{id}.
// Requires cluster:onboard. Clusters already enrolled are unaffected.
func (s *Server) handleRevokeFleetToken(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	id := r.PathValue("id")
	revoked, err := authz.RevokeFleetToken(r.Context(), rc.Tx, id)
	if err != nil {
		logger.ErrorContext(r.Context(), "revoking a fleet token failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not revoke fleet token", "")
		return
	}
	if !revoked {
		writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "No live fleet token with that id", "")
		return
	}
	capability := authz.CapClusterOnboard
	if err := audit.RecordEvent(r.Context(), rc.Tx, audit.Event{
		TenantID: rc.TenantID, ActorID: &rc.UserID, ActorAuthMethod: "jwt", SourceIP: clientIP(r),
		Capability: &capability, Outcome: audit.OutcomeSuccess,
		Details: map[string]any{"action": "revoke_fleet_token", "tokenId": id},
	}); err != nil {
		logger.ErrorContext(r.Context(), "recording a fleet token revocation in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
