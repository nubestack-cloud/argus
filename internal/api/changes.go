package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"time"

	"argus/internal/execution"
	"argus/internal/logging"

	"github.com/jackc/pgx/v5"
)

// GET /api/v1/changes — every change ARGUS has made to a cluster recently,
// across every incident.
//
// # Why this endpoint exists at all
//
// Undo already worked: POST /api/v1/executions/{id}/rollback (rollback.go) has
// been real since BACKLOG.md R1, and the UI has offered it on an incident's own
// remediation card since. But the ONLY way to reach it was to already know
// which incident made the change. An operator whose starting point is
// "something changed production on Tuesday" — which is the normal starting
// point — had no way in at all: incidents are listed by what BROKE, not by what
// ARGUS DID about it, and the audit log is an append-only record of every
// request including reads, not a list of mutations with an action attached.
//
// This is that front door. It is deliberately a READ that also carries, per
// row, the exact undoability answer the POST would give — see undoFor below.
//
// # What counts as "a change"
//
// Two things, on one list, because from an operator's point of view they are
// the same fact ("ARGUS changed my cluster") reached by two routes (ADR-18):
//
//  1. An in-place execution (`remediation_executions`) — ARGUS patched the live
//     object. Its "when" is `executed_at`.
//  2. A MERGED repository change — ARGUS opened a pull request against the
//     GitOps source and it merged, so the controller applied it. Its "when" is
//     `incidents.pr_merged_at`.
//
// # Open pull requests, and why they are here now
//
// This list was merged-pull-requests-only, on two stated grounds. One of them
// has been removed and the other has been answered rather than overruled, so
// both are recorded here instead of being quietly deleted.
//
// The removed ground was mechanical: "there is no column recording when a pull
// request was OPENED". There is now — `incidents.pr_opened_at`, migration
// 000114, written by BOTH routes (approveByOpeningPullRequest and
// recordOpenedPullRequest) in the same statement that records pr_number, so it
// always describes the CURRENT pull request. Before it, an open pull request
// could not even be ordered into this list.
//
// The standing ground was honesty, and it is the important one: AN OPEN PULL
// REQUEST HAS NOT CHANGED ANYTHING. A feed called "recent changes" that lists
// one as a change is making a false claim, and every column here would carry it
// — "Merged" in the outcome, an applier in "applied by", an undo refusal that
// talks about reverting a merge commit that does not exist.
//
// That is answered by `Status`, not by exclusion. Each row now says which of the
// two it is — `landed` (the cluster changed) or `proposed` (ARGUS opened a pull
// request and the cluster has NOT changed) — and the two carry different
// timestamps in different fields: `changedAt` for landed, `proposedAt` for
// proposed, never one standing in for the other. A proposed row has no
// `changedAt` at all, because `changeItem`'s own rule is that an absent field is
// honest and a zero value in it is not, and putting an opened-at into a field
// documented as "the moment the cluster actually changed" is exactly the
// fabrication that rule exists to stop.
//
// The reason to include them rather than keep the clean boundary: the boundary
// was leaving a real hole. An open pull request was reachable from the one
// incident that owns it and nowhere else, so an operator watching a fleet had no
// way to ask "is anything waiting on me?" — and AwaitingMerge is the single
// state in this product that is explicitly waiting on a human. A proposal the
// product never surfaces is a proposal nobody merges.
//
// A pull request CLOSED UNMERGED is still excluded, and that boundary is
// unchanged: it never changed anything and it is not waiting on anyone either,
// so it is neither a change nor an outstanding proposal. It belongs to its
// incident's own history.
//
// # Capability
//
// incident:read AND analysis:read, nested at the route — the same pair Insights
// uses, and deliberately NOT remediation:approve.
//
// The reasoning is exposure parity, not convenience. Every field on an in-place
// row here is already served to an incident:read holder by GET
// /api/v1/incidents/{id}: latestExecutionView supplies the outcome, the
// executed-at, the execution id and the rollback description, and
// latestApprovalDecisionView supplies the approver's email (remediation.go).
// Gating this list behind remediation:approve would therefore not protect
// anything — it would only stop a viewer from finding, in one place, facts they
// can already read one incident at a time. analysis:read is required alongside
// because a change is only ever proposed by an analysis, and the summary
// rendered here is that plan's own plain-language summary.
//
// Cluster scope is enforced by RLS, not by this handler, and the JOIN is what
// carries it: `remediation_executions` has only a tenant-scope policy, while
// `incidents` and `clusters` carry the RESTRICTIVE cluster-scope policy
// (migration 000035). Joining every execution to its incident means a
// cluster-scoped grant cannot see an execution on a cluster it has no access
// to. Do not "optimise" that join away.

// changesDefaultWindowHours is a week. Long enough that "something changed on
// Tuesday" is answerable on a Friday, short enough that the default page is
// about recent work rather than history.
const changesDefaultWindowHours = 168

// changesMaxWindowHours is 90 days. Past that the answer belongs to the audit
// log, which is the append-only record built for retention.
const changesMaxWindowHours = 24 * 90

const (
	changesDefaultLimit = 50
	changesMaxLimit     = 200
)

// changeKind* are the wire values for changeItem.Kind. Two, matching the two
// resolution channels that can actually alter a cluster (internal/resolution).
const (
	changeKindInPlace     = "inPlace"
	changeKindPullRequest = "pullRequest"
)

// changeStatus* say whether this row has actually altered a cluster. The
// distinction the "kind" pair above cannot carry: `pullRequest` covers both a
// merged change and an open proposal, and they are opposite answers to the only
// question this screen exists to ask.
//
// An in-place execution is ALWAYS landed, including a failed one — it reached
// the cluster and the attempt is the fact being reported; its `outcome` says how
// it went. `proposed` is reachable only by an open pull request.
const (
	changeStatusLanded   = "landed"
	changeStatusProposed = "proposed"
)

// changeUndoView is the per-row answer to "can I undo this, and if not, why
// not" — computed server-side so the UI never re-derives a safety rule.
//
// Reason/Detail are the SAME strings POST /executions/{id}/rollback would
// return, because they come from the same function (checkUndoable). That is the
// point: a list that renders its own paraphrase of an undo refusal is a second
// hand-maintained copy of a safety rule, and this codebase has already been
// burned by exactly that shape ("a hand-maintained list in a test cannot guard
// a hand-maintained list in code").
//
// Available == true is NOT a promise the undo will succeed. Three of the
// rollback path's refusals can only be evaluated against the live cluster at
// the moment of the request — the field has moved since, the change is already
// gone, the agent is disconnected — and pre-computing them here would mean
// reading every listed object's live state on every page load. The UI offers
// the control and renders the refusal in full if one comes back.
type changeUndoView struct {
	Available bool `json:"available"`
	// ExecutionID is what POST /api/v1/executions/{id}/rollback takes. Present
	// only when Available, so a caller cannot read this list as a menu of
	// execution ids to try.
	ExecutionID string `json:"executionId,omitempty"`
	// Description is what undoing would do, in the words captured off the live
	// object BEFORE the forward change ("scale back to 2 replica(s)").
	Description string `json:"description,omitempty"`
	// Reason/Detail are checkUndoable's title and detail, or the pull-request
	// explanation. Present only when Available is false.
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// changeItem is one change. The kind-specific fields are omitempty because a
// pull request has no outcome and an in-place patch has no file list — an
// absent field is honest, a zero value in it would not be.
type changeItem struct {
	// ID is a stable React key, not an addressable resource id: an execution's
	// own id for an in-place change, and "pr:<incidentId>" for a repository
	// change, which has no row of its own to be identified by.
	ID   string `json:"id"`
	Kind string `json:"kind"`
	// Status is landed | proposed — see changeStatus* above. Always present:
	// a reader must never have to infer "has this happened?" from which other
	// fields came back.
	Status string `json:"status"`
	// ChangedAt is the moment the cluster changed, and is ABSENT on a proposed
	// row because no such moment exists yet. Callers that sort must use
	// changeSortKey, which knows about both timestamps.
	ChangedAt string `json:"changedAt,omitempty"`
	// ProposedAt is when the pull request was opened
	// (`incidents.pr_opened_at`, migration 000114). Present on proposed rows.
	// Absent on landed ones — a merged pull request's own opened-at is on the
	// incident, and repeating it here would invite a reader to treat this
	// column as "when it happened" for two different meanings of happened.
	ProposedAt  string `json:"proposedAt,omitempty"`
	ClusterID   string `json:"clusterId"`
	ClusterName string `json:"clusterName"`
	IncidentID  string `json:"incidentId"`
	// Summary is plain language, from planSummary — the same rendering the
	// approval queue and the incident page show, never a raw action type.
	Summary string `json:"summary"`

	// The workload, on BOTH kinds. This used to be in-place only, and the
	// asymmetry was a real gap: an operator asking "what changed on
	// production" got `apps/api/deployment.yaml` for a repository change and
	// had to already know which workload that file declares.
	//
	// Read from the incident's own OpenPR recommendation
	// (`remediation_recommendations.target_*`) — the SAME three columns the
	// in-place rows above read, from the same table, which is what makes the
	// two symmetric rather than merely similar. RemediationPlan's doc comment
	// is explicit that for ActionOpenPR these name "the logical target the PR
	// would change".
	//
	// Deliberately NOT `incidents.object_key`, though that is always present
	// and was the obvious source. object_key is what the FINDING was on, which
	// for the live PR-route incident this was checked against is
	// `v1/Pod|argus-gitops-rke2|api-5c7f4f4b45-xq8jl` — an ephemeral Pod that
	// no longer exists, not the Deployment the merged file declares. Rendering
	// it as "what changed" would be the same mistake internal/api has already
	// shipped once (asking an incident's own Pod whether a Deployment is
	// GitOps-managed), and mergedPullRequestSummary's own comment refuses it
	// on exactly these grounds. Absent when no OpenPR recommendation is
	// recorded, which is the self-service route's normal case.
	TargetGVK       string `json:"targetGvk,omitempty"`
	TargetNamespace string `json:"targetNamespace,omitempty"`
	TargetName      string `json:"targetName,omitempty"`
	// In-place only.
	Outcome string `json:"outcome,omitempty"` // succeeded | failed | unknown
	Error   string `json:"error,omitempty"`

	// Pull request only.
	PullRequestNumber int      `json:"pullRequestNumber,omitempty"`
	PullRequestURL    string   `json:"pullRequestUrl,omitempty"`
	FilePaths         []string `json:"filePaths,omitempty"`

	// Unattended is true for a change the unattended executor applied with no
	// human decision behind it (internal/api/unattended.go). Always false for a
	// merged pull request: a merge is a human act in the provider.
	Unattended bool `json:"unattended"`
	// ActorEmail is the approver, empty when nobody is recorded. For a pull
	// request opened through the self-service repository-change route that is
	// the normal case, not a data loss — that path records its actor in the
	// audit chain rather than as an approval decision.
	ActorEmail string `json:"actorEmail,omitempty"`

	Undo changeUndoView `json:"undo"`
}

type changesResponse struct {
	Changes     []changeItem `json:"changes"`
	WindowHours int          `json:"windowHours"`
	Limit       int          `json:"limit"`
	// Truncated is true when the window holds more changes than Limit. The UI
	// has to say so beside the count: an unlabelled partial reads as a total.
	Truncated bool `json:"truncated"`
	// HasAnyChanges answers "has ARGUS ever changed anything at all", ignoring
	// BOTH the window and the cluster filter, so the UI can tell three
	// genuinely different empties apart: nothing has ever happened, nothing
	// happened in this window, and nothing happened on this cluster. Collapsing
	// them into one "no changes" message is the half-built case this codebase
	// keeps producing.
	HasAnyChanges bool `json:"hasAnyChanges"`
}

// changeSortKey is the one place that knows a row may be timestamped by either
// field. Both are RFC 3339 in UTC, which sorts correctly as a string, and
// exactly one of the two is ever set — so this is the SQL `COALESCE(pr_merged_at,
// pr_opened_at)` the two queries already order by, applied again across the
// merged list rather than re-derived differently. A row with neither (which no
// query can produce) sorts last rather than panicking.
func changeSortKey(c changeItem) string {
	if c.ChangedAt != "" {
		return c.ChangedAt
	}
	return c.ProposedAt
}

func (s *Server) handleListChanges(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	q := r.URL.Query()

	windowHours := changesDefaultWindowHours
	if raw := q.Get("windowHours"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 || n > changesMaxWindowHours {
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request",
				"Invalid windowHours", fmt.Sprintf("windowHours must be an integer between 1 and %d", changesMaxWindowHours))
			return
		}
		windowHours = n
	}

	limit := changesDefaultLimit
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 || n > changesMaxLimit {
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request",
				"Invalid limit", fmt.Sprintf("limit must be an integer between 1 and %d", changesMaxLimit))
			return
		}
		limit = n
	}

	clusterID := q.Get("clusterId")
	since := time.Now().Add(-time.Duration(windowHours) * time.Hour)

	// limit+1 from each source so the merged list can report truncation
	// honestly rather than guessing from "we got exactly limit back".
	executions, err := queryExecutionChanges(ctx, rc.Tx, since, clusterID, limit+1)
	if err != nil {
		logger.ErrorContext(ctx, "querying the execution changes failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not load recent changes", "")
		return
	}
	pullRequests, err := queryPullRequestChanges(ctx, rc.Tx, since, clusterID, limit+1)
	if err != nil {
		logger.ErrorContext(ctx, "querying the pull-request changes failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not load recent changes", "")
		return
	}

	items := append(executions, pullRequests...)
	// Newest first, with the id as a deterministic tiebreak so two changes that
	// landed in the same millisecond do not reorder between two fetches of the
	// same data.
	sort.SliceStable(items, func(i, j int) bool {
		a, b := changeSortKey(items[i]), changeSortKey(items[j])
		if a != b {
			return a > b
		}
		return items[i].ID < items[j].ID
	})
	truncated := len(items) > limit
	if truncated {
		items = items[:limit]
	}

	hasAny, err := anyChangeExists(ctx, rc.Tx)
	if err != nil {
		logger.ErrorContext(ctx, "probing for the existence of any change failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not load recent changes", "")
		return
	}

	writeJSON(w, http.StatusOK, changesResponse{
		Changes:       items,
		WindowHours:   windowHours,
		Limit:         limit,
		Truncated:     truncated,
		HasAnyChanges: hasAny,
	})
}

// queryExecutionChanges reads in-place executions in the window.
//
// The JOIN to `incidents` is the cluster-scope enforcement point (see this
// file's header) as well as the source of the incident state checkUndoable
// needs. The LATERAL is the most recent APPROVED decision on the plan, which is
// who authorised the change — matching latestApprovalDecisionView's own
// ordering (remediation.go) rather than inventing a second answer to the same
// question.
func queryExecutionChanges(ctx context.Context, tx pgx.Tx, since time.Time, clusterID string, limit int) ([]changeItem, error) {
	rows, err := tx.Query(ctx,
		`SELECT x.id, x.incident_id, x.cluster_id, c.display_name, x.executed_at,
		        x.outcome, x.error, x.unattended,
		        x.rollback_action_type, x.rollback_description, x.rolled_back_by_execution_id,
		        r.action_type, r.target_gvk, COALESCE(r.target_namespace, ''), r.target_name, r.params,
		        i.state, u.email
		   FROM remediation_executions x
		   JOIN remediation_recommendations r ON r.id = x.recommendation_id
		   JOIN incidents i ON i.id = x.incident_id
		   JOIN clusters c ON c.id = x.cluster_id
		   LEFT JOIN LATERAL (
		        SELECT d.actor_id
		          FROM remediation_approval_decisions d
		         WHERE d.recommendation_id = x.recommendation_id AND d.verdict = 'approved'
		         ORDER BY d.created_at DESC
		         LIMIT 1
		   ) d ON true
		   LEFT JOIN users u ON u.id = d.actor_id
		  WHERE x.executed_at >= $1
		    AND ($2 = '' OR x.cluster_id = $2)
		  ORDER BY x.executed_at DESC
		  LIMIT $3`, since, clusterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []changeItem
	for rows.Next() {
		var e execution.UndoableExecution
		var item changeItem
		var executedAt time.Time
		var execErr, rollbackActionType, rollbackDescription, actorEmail *string
		var params json.RawMessage
		if err := rows.Scan(
			&item.ID, &item.IncidentID, &item.ClusterID, &item.ClusterName, &executedAt,
			&item.Outcome, &execErr, &item.Unattended,
			&rollbackActionType, &rollbackDescription, &e.AlreadyUndone,
			&e.RecommendationActionType, &item.TargetGVK, &item.TargetNamespace, &item.TargetName, &params,
			&e.IncidentState, &actorEmail,
		); err != nil {
			return nil, err
		}
		item.Kind = changeKindInPlace
		item.Status = changeStatusLanded
		item.ChangedAt = formatRFC3339(executedAt)
		item.Error = deref(execErr)
		item.ActorEmail = deref(actorEmail)
		item.Summary = planSummary(e.RecommendationActionType, item.TargetNamespace, item.TargetName, params)

		// Only the fields checkUndoable actually reads are filled here — the
		// params, the target and the signed plan are the POST's business, not
		// this list's.
		e.ID = item.ID
		e.IncidentID = item.IncidentID
		e.Outcome = item.Outcome
		e.ActionType = deref(rollbackActionType)
		item.Undo = undoFor(e, deref(rollbackDescription))

		out = append(out, item)
	}
	return out, rows.Err()
}

// queryPullRequestChanges reads repository changes in the window — merged ones
// (landed) and still-open ones (proposed), in one pass, distinguished by
// `Status`. See this file's header for why open ones are here at all.
//
// The window and the ordering both use COALESCE(pr_merged_at, pr_opened_at) —
// "when this row got its current standing": when it merged, or, while it has
// not, when it was opened. Using pr_merged_at alone would put every open pull
// request outside every window, and using pr_opened_at alone would re-sort a
// merged pull request by a moment days before it changed anything.
//
// The WHERE admits exactly two shapes and no third. Merged: pr_merged_at set.
// Open: pr_number set, pr_opened_at set, and NEITHER pr_merged_at NOR
// pr_closed_unmerged_at set. Closed-unmerged is excluded on purpose (header),
// and so is an open pull request with no pr_opened_at — one opened before
// migration 000114 whose URL the backfill could not match. That is the honest
// exclusion rather than the alternative: it has no timestamp of any kind, so it
// could only be placed in a time-ordered window by inventing one.
//
// `pr_proposed_files` (migration 000075) is read for its PATHS only. The column
// also holds each file's whole content, which VerifyMergedPullRequest needs and
// a list screen does not — sending it would put megabytes of YAML on a page
// that renders a filename.
//
// The second LATERAL is the workload (changeItem.TargetGVK's doc comment has
// why it is the recommendation's target and not the incident's object_key). It
// is separate from the approval-decision LATERAL beside it rather than folded
// into it, because that one requires an approved decision to exist: a pull
// request opened through the self-service route has none, and joining the two
// would drop the workload on exactly those rows.
func queryPullRequestChanges(ctx context.Context, tx pgx.Tx, since time.Time, clusterID string, limit int) ([]changeItem, error) {
	rows, err := tx.Query(ctx,
		`SELECT i.id, i.cluster_id, c.display_name, i.pr_merged_at, i.pr_opened_at, i.pr_number, i.pr_url,
		        COALESCE((SELECT array_agg(f->>'path' ORDER BY f->>'path')
		                    FROM jsonb_array_elements(i.pr_proposed_files) f), '{}'::text[]),
		        u.email,
		        t.target_gvk, COALESCE(t.target_namespace, ''), t.target_name
		   FROM incidents i
		   JOIN clusters c ON c.id = i.cluster_id
		   LEFT JOIN LATERAL (
		        SELECT d.actor_id
		          FROM remediation_approval_decisions d
		          JOIN remediation_recommendations r ON r.id = d.recommendation_id
		         WHERE d.incident_id = i.id AND d.verdict = 'approved' AND r.action_type = 'OpenPR'
		         ORDER BY d.created_at DESC
		         LIMIT 1
		   ) d ON true
		   LEFT JOIN users u ON u.id = d.actor_id
		   LEFT JOIN LATERAL (
		        SELECT r.target_gvk, r.target_namespace, r.target_name
		          FROM remediation_recommendations r
		         WHERE r.incident_id = i.id AND r.action_type = 'OpenPR'
		         ORDER BY r.created_at DESC
		         LIMIT 1
		   ) t ON true
		  WHERE ($2 = '' OR i.cluster_id = $2)
		    AND COALESCE(i.pr_merged_at, i.pr_opened_at) >= $1
		    AND (
		          i.pr_merged_at IS NOT NULL
		       OR (i.pr_number IS NOT NULL
		           AND i.pr_opened_at IS NOT NULL
		           AND i.pr_closed_unmerged_at IS NULL)
		        )
		  ORDER BY COALESCE(i.pr_merged_at, i.pr_opened_at) DESC
		  LIMIT $3`, since, clusterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []changeItem
	for rows.Next() {
		var item changeItem
		var mergedAt, openedAt *time.Time
		var prNumber *int
		var prURL, actorEmail, targetGVK, targetNamespace, targetName *string
		var paths []string
		if err := rows.Scan(&item.IncidentID, &item.ClusterID, &item.ClusterName, &mergedAt, &openedAt,
			&prNumber, &prURL, &paths, &actorEmail,
			&targetGVK, &targetNamespace, &targetName); err != nil {
			return nil, err
		}
		item.ID = "pr:" + item.IncidentID
		item.Kind = changeKindPullRequest
		item.PullRequestURL = deref(prURL)
		item.FilePaths = paths
		item.ActorEmail = deref(actorEmail)
		item.TargetGVK = deref(targetGVK)
		item.TargetNamespace = deref(targetNamespace)
		item.TargetName = deref(targetName)
		if prNumber != nil {
			item.PullRequestNumber = *prNumber
		}

		if mergedAt != nil {
			item.Status = changeStatusLanded
			item.ChangedAt = formatRFC3339(*mergedAt)
			item.Summary = mergedPullRequestSummary(item.PullRequestNumber, paths)
			item.Undo = changeUndoView{
				Available: false,
				Reason:    "ARGUS cannot undo a merged pull request",
				Detail: "This change was applied by the GitOps controller from the repository, so the repository is what would have to change back. " +
					"Reverting the merge commit — and letting the controller sync that — is the reversal, and ARGUS does not open revert pull requests. " +
					"Undoing it in the cluster instead would be overwritten on the controller's next sync.",
			}
		} else {
			// The WHERE guarantees openedAt is non-NULL on this branch.
			item.Status = changeStatusProposed
			item.ProposedAt = formatRFC3339(*openedAt)
			item.Summary = openPullRequestSummary(item.PullRequestNumber, paths)
			// Not "undo unavailable because it is risky" — unavailable because
			// there is nothing to undo, and the detail says what the actual
			// next action is. An operator reading a refusal on this screen is
			// entitled to know whether they are blocked or simply looking at
			// something that has not happened.
			item.Undo = changeUndoView{
				Available: false,
				Reason:    "Nothing to undo — this has not changed anything",
				Detail: "This pull request is still open, so the cluster is unchanged and there is nothing to reverse. " +
					"Merging it is what applies the change; closing it without merging leaves the cluster exactly as it is now.",
			}
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// openPullRequestSummary is mergedPullRequestSummary's open-state sibling, and
// it leads with the word that matters: this is a PROPOSAL. It states the same
// stored facts — which pull request, and which files it would change — in the
// conditional, because none of them has happened yet.
func openPullRequestSummary(number int, paths []string) string {
	where := changedFilesClause(paths)
	if number > 0 {
		return fmt.Sprintf("Pull request #%d open, not yet merged%s", number, where)
	}
	return fmt.Sprintf("Pull request open, not yet merged%s", where)
}

// changedFilesClause is the file-naming half both summaries share, so the two
// cannot drift into describing the same stored column differently. Its empty
// case is load-bearing: see mergedPullRequestSummary.
func changedFilesClause(paths []string) string {
	switch len(paths) {
	case 0:
		return ""
	case 1:
		return fmt.Sprintf(" — %s", paths[0])
	default:
		return fmt.Sprintf(" — %s and %d more file(s)", paths[0], len(paths)-1)
	}
}

// mergedPullRequestSummary states only what the stored columns support: which
// pull request, and how many files it changed. It deliberately does not name
// the object the incident was about — the incident's `object_key` is what the
// FINDING was on, not a statement about what the merged files declare, and
// presenting one as the other would be a claim nothing verified.
func mergedPullRequestSummary(number int, paths []string) string {
	// The empty case says nothing about files rather than "0 files changed":
	// pr_proposed_files is NULL for a pull request opened before migration
	// 000075, and a fabricated zero about a change that definitely touched
	// something is worse than saying less. changedFilesClause carries that.
	where := changedFilesClause(paths)
	if number > 0 {
		return fmt.Sprintf("Merged pull request #%d%s", number, where)
	}
	return fmt.Sprintf("Merged pull request%s", where)
}

// undoFor is the single place this list decides whether a row can be undone,
// and it decides it by ASKING THE ROLLBACK PATH — checkUndoable is rollback.go's
// own pure refusal function, so a rule added there (or a message reworded there)
// reaches this screen with no second edit and cannot drift out of step with what
// the POST actually does.
func undoFor(e execution.UndoableExecution, description string) changeUndoView {
	if problem := execution.CheckUndoable(e); problem != nil {
		return changeUndoView{Available: false, Reason: problem.Title, Detail: problem.Detail}
	}
	if description == "" {
		// checkUndoable passed, so a compensating action IS recorded, but
		// nothing describes it. Offering "Undo" with no statement of what it
		// would do would be a confirmation the operator cannot actually read,
		// on a control that mutates a production cluster.
		return changeUndoView{
			Available: false,
			Reason:    "This execution's undo has no recorded description",
			Detail: "A compensating action was captured for this execution but no plain-language description of it was stored, so ARGUS cannot state what undoing would do. " +
				"Open the incident and re-analyse it so a fresh plan is derived from the cluster's current state.",
		}
	}
	return changeUndoView{Available: true, ExecutionID: e.ID, Description: description}
}

// anyChangeExists answers "has this list ever had anything on it", ignoring the
// window and the cluster filter, so the screen can tell "nothing yet" from
// "nothing recently". Three bounded EXISTS probes — one per row shape the two
// queries above can produce, INCLUDING an open pull request, because the
// alternative is a screen that says "ARGUS has never changed anything" while
// rendering a proposal underneath it. Never a count: the number is not shown
// anywhere, and a COUNT(*) over every execution ever would be paid on every page
// load to answer a yes/no question.
func anyChangeExists(ctx context.Context, tx pgx.Tx) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM remediation_executions x JOIN incidents i ON i.id = x.incident_id)
		     OR EXISTS (SELECT 1 FROM incidents WHERE pr_merged_at IS NOT NULL)
		     OR EXISTS (SELECT 1 FROM incidents
		                 WHERE pr_number IS NOT NULL AND pr_opened_at IS NOT NULL
		                   AND pr_merged_at IS NULL AND pr_closed_unmerged_at IS NULL)`).Scan(&exists)
	return exists, err
}
