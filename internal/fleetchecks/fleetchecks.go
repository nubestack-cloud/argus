// Package fleetchecks keeps the Overview's fleet-wide checks: the last answer
// each connected cluster's agent gave to four read-only inventory tools
// (certificates, posture, Helm releases, GitOps apps), reduced to counts by
// the hub and stored one row per cluster and check (migration 000130). A
// worker refreshes them on an interval so the fleet page reads one aggregate
// instead of calling every agent four times each time it is opened — at 200
// clusters that was 800 tunnel calls per page load.
//
// Only counts and the handful of rows a fleet view draws are kept (the
// certificates due inside the runway), never the agent's full answer: the
// cluster's own pages still read that live, through the inspect route.
package fleetchecks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/data"
	"argus/internal/logging"
	"argus/internal/settings"
)

var logger = logging.For("fleetchecks")

// ToolCaller is the gateway's CallTool.
type ToolCaller interface {
	CallTool(ctx context.Context, clusterID, tool string, args json.RawMessage) (json.RawMessage, error)
	IsConnected(clusterID string) bool
}

// The four checks, by the name stored in check_name and served to the UI,
// and the agent tool each one asks.
const (
	CheckCertificates = "certificates"
	CheckPosture      = "posture"
	CheckHelm         = "helm"
	CheckGitOps       = "gitops"
)

var checkTools = []struct{ check, tool string }{
	{CheckCertificates, "list_certificates"},
	{CheckPosture, "get_posture_findings"},
	{CheckHelm, "list_helm_releases"},
	{CheckGitOps, "list_gitops_apps"},
}

// DefaultInterval is how often every connected cluster is re-read. Expiry and
// posture move over days; a failing release is the fastest of the four, and
// ten minutes is still well inside the time a person takes to notice one.
const DefaultInterval = 10 * time.Minute

// RunwayDays is the horizon a certificate must expire inside to be listed
// individually (the Overview's "Next 90 days").
const RunwayDays = 90

// maxDuePins bounds the per-cluster certificate rows kept. DueTotal still
// counts every certificate inside the runway, so the cap is stated, not hidden.
const maxDuePins = 25

// clusterConcurrency bounds how many clusters are read at once; each cluster's
// four calls run one after another.
const clusterConcurrency = 8

// callTimeout bounds one tool call, matching the inspect route's.
const callTimeout = 20 * time.Second

// ---------------------------------------------------------------- summaries

// CertPin is one certificate expiring inside the runway (or expired).
type CertPin struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	DaysLeft  int    `json:"daysLeft"`
}

// CertificatesSummary counts a cluster's certificates by when they expire.
type CertificatesSummary struct {
	// Listed is how many certificates the agent returned.
	Listed int `json:"listed"`
	// Unknown have no readable expiry — never counted as due or as safe.
	Unknown int `json:"unknown"`
	// Later expire after the runway.
	Later int `json:"later"`
	// Due is the soonest maxDuePins inside the runway, soonest first;
	// DueTotal counts all of them.
	Due      []CertPin `json:"due"`
	DueTotal int       `json:"dueTotal"`
	// Truncated is the agent's own cap on its list.
	Truncated bool `json:"truncated"`
}

// CategoryCounts mirrors the agent's posture.CategorySummary.
type CategoryCounts struct {
	Passing int `json:"passing"`
	Warning int `json:"warning"`
	Danger  int `json:"danger"`
}

// PostureSummary is the agent's own posture totals, per category.
type PostureSummary struct {
	Danger     int                       `json:"danger"`
	Warning    int                       `json:"warning"`
	Categories map[string]CategoryCounts `json:"categories"`
}

// HelmSummary counts releases and the failing ones among those listed.
type HelmSummary struct {
	Total     int  `json:"total"`
	Listed    int  `json:"listed"`
	Failing   int  `json:"failing"`
	Truncated bool `json:"truncated"`
	// Releases is the listed releases, capped at maxStoredApps, for the
	// Applications view (PROJECT.md PG19).
	Releases []HelmApp `json:"releases,omitempty"`
}

// HelmApp is one Helm release as the Applications view needs it.
type HelmApp struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Revision  int    `json:"revision,omitempty"`
	Status    string `json:"status,omitempty"`
	Health    string `json:"health,omitempty"`
	App       string `json:"app,omitempty"`
}

// GitOpsApp is one Argo CD or Flux application, with its declared source.
type GitOpsApp struct {
	Tool           string `json:"tool"`
	Kind           string `json:"kind"`
	Name           string `json:"name"`
	Namespace      string `json:"namespace"`
	RepoURL        string `json:"repoURL,omitempty"`
	Path           string `json:"path,omitempty"`
	Chart          string `json:"chart,omitempty"`
	SourceRef      string `json:"sourceRef,omitempty"`
	TargetRevision string `json:"targetRevision,omitempty"`
	Revision       string `json:"revision,omitempty"`
	Sync           string `json:"sync,omitempty"`
	Health         string `json:"health,omitempty"`
	Problem        bool   `json:"problem,omitempty"`
	App            string `json:"app,omitempty"`
}

// maxStoredApps bounds the application rows kept per cluster and check.
const maxStoredApps = 300

// GitOpsSummary counts applications and those with a problem among those listed.
type GitOpsSummary struct {
	Total     int         `json:"total"`
	Listed    int         `json:"listed"`
	Problems  int         `json:"problems"`
	Truncated bool        `json:"truncated"`
	Apps      []GitOpsApp `json:"apps,omitempty"`
}

func summarizeCertificates(raw json.RawMessage) (CertificatesSummary, error) {
	var in struct {
		Truncated    bool `json:"truncated"`
		Certificates []struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
			DaysLeft  *int   `json:"daysLeft"`
		} `json:"certificates"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return CertificatesSummary{}, err
	}
	out := CertificatesSummary{Listed: len(in.Certificates), Truncated: in.Truncated, Due: []CertPin{}}
	for _, c := range in.Certificates {
		switch {
		case c.DaysLeft == nil:
			out.Unknown++
		case *c.DaysLeft > RunwayDays:
			out.Later++
		default:
			out.DueTotal++
			out.Due = append(out.Due, CertPin{Name: c.Name, Namespace: c.Namespace, DaysLeft: *c.DaysLeft})
		}
	}
	sort.SliceStable(out.Due, func(i, j int) bool { return out.Due[i].DaysLeft < out.Due[j].DaysLeft })
	if len(out.Due) > maxDuePins {
		out.Due = out.Due[:maxDuePins]
	}
	return out, nil
}

func summarizePosture(raw json.RawMessage) (PostureSummary, error) {
	var in struct {
		Summary *struct {
			Warning    int                       `json:"warning"`
			Danger     int                       `json:"danger"`
			Categories map[string]CategoryCounts `json:"categories"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return PostureSummary{}, err
	}
	// An agent that sends no per-category summary has not answered the
	// question this check asks; storing zeros would read as a clean cluster.
	if in.Summary == nil || in.Summary.Categories == nil {
		return PostureSummary{}, errors.New("this agent does not report posture by category")
	}
	return PostureSummary{Danger: in.Summary.Danger, Warning: in.Summary.Warning, Categories: in.Summary.Categories}, nil
}

// helmReleaseFailing is the same rule as the web UI's isHelmProblem
// (web/src/fleet/helmModel.ts): a failed or stuck status, an operation in
// progress or failed, or a release whose objects are degraded.
func helmReleaseFailing(status string, lastOperation json.RawMessage, health string) bool {
	return status == "failed" || strings.HasPrefix(status, "pending-") || status == "uninstalling" ||
		(len(lastOperation) > 0 && string(lastOperation) != "null") ||
		health == "degraded" || health == "unhealthy"
}

func summarizeHelm(raw json.RawMessage) (HelmSummary, error) {
	var in struct {
		Truncated bool `json:"truncated"`
		Total     int  `json:"total"`
		Releases  []struct {
			Name          string          `json:"name"`
			Namespace     string          `json:"namespace"`
			Revision      int             `json:"revision"`
			Status        string          `json:"status"`
			LastOperation json.RawMessage `json:"lastOperation"`
			Health        string          `json:"health"`
			App           string          `json:"app"`
		} `json:"releases"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return HelmSummary{}, err
	}
	out := HelmSummary{Total: in.Total, Listed: len(in.Releases), Truncated: in.Truncated || in.Total > len(in.Releases)}
	for _, r := range in.Releases {
		if helmReleaseFailing(r.Status, r.LastOperation, r.Health) {
			out.Failing++
		}
		if len(out.Releases) < maxStoredApps {
			out.Releases = append(out.Releases, HelmApp{Name: r.Name, Namespace: r.Namespace, Revision: r.Revision, Status: r.Status, Health: r.Health, App: r.App})
		}
	}
	return out, nil
}

func summarizeGitOps(raw json.RawMessage) (GitOpsSummary, error) {
	var in struct {
		Apps   []GitOpsApp `json:"apps"`
		Counts struct {
			Total int `json:"total"`
		} `json:"counts"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return GitOpsSummary{}, err
	}
	out := GitOpsSummary{Total: in.Counts.Total, Listed: len(in.Apps), Truncated: len(in.Apps) < in.Counts.Total}
	for _, a := range in.Apps {
		if a.Problem {
			out.Problems++
		}
		if len(out.Apps) < maxStoredApps {
			out.Apps = append(out.Apps, a)
		}
	}
	return out, nil
}

// Summarize reduces one tool answer to the check's stored summary.
func Summarize(check string, raw json.RawMessage) (any, error) {
	switch check {
	case CheckCertificates:
		return summarizeCertificates(raw)
	case CheckPosture:
		return summarizePosture(raw)
	case CheckHelm:
		return summarizeHelm(raw)
	case CheckGitOps:
		return summarizeGitOps(raw)
	}
	return nil, fmt.Errorf("unknown check %q", check)
}

// ---------------------------------------------------------------- storage

// Snapshot is one stored check for one cluster.
type Snapshot struct {
	// Summary is the last successful answer, or nil when there has been none.
	Summary   json.RawMessage `json:"summary"`
	SummaryAt *time.Time      `json:"summaryAt"`
	// Error is the latest attempt's failure, when it failed after (or
	// without) the summary above.
	Error   *string    `json:"error"`
	ErrorAt *time.Time `json:"errorAt"`
}

// errorText is the stored failure: short, and the agent's own wording only
// up to a bound, since it is shown to anyone who can read the fleet.
func errorText(err error) string {
	s := err.Error()
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

func record(ctx context.Context, db *data.DB, clusterID, check string, summary any, callErr error) error {
	return data.InClusterScope(ctx, db.Pool, clusterID, func(ctx context.Context, tx pgx.Tx, tenantID string) error {
		return upsert(ctx, tx, tenantID, clusterID, check, summary, callErr)
	})
}

// upsert stores one check's outcome in an already-scoped transaction. A
// failure leaves the last good summary in place beside it; a success clears
// the failure.
func upsert(ctx context.Context, tx pgx.Tx, tenantID, clusterID, check string, summary any, callErr error) error {
	if callErr != nil {
		_, err := tx.Exec(ctx, `INSERT INTO fleet_check_snapshots (tenant_id, cluster_id, check_name, error, error_at)
			VALUES ($1, $2, $3, $4, now())
			ON CONFLICT (cluster_id, check_name) DO UPDATE SET error = EXCLUDED.error, error_at = EXCLUDED.error_at`,
			tenantID, clusterID, check, errorText(callErr))
		return err
	}
	b, err := json.Marshal(summary)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO fleet_check_snapshots (tenant_id, cluster_id, check_name, summary, summary_at)
		VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (cluster_id, check_name) DO UPDATE SET summary = EXCLUDED.summary, summary_at = EXCLUDED.summary_at, error = NULL, error_at = NULL`,
		tenantID, clusterID, check, b)
	return err
}

// ReadAll returns every visible cluster's snapshots, keyed by cluster and
// check, in the caller's already-scoped transaction.
func ReadAll(ctx context.Context, tx pgx.Tx) (map[string]map[string]Snapshot, error) {
	rows, err := tx.Query(ctx, `SELECT cluster_id, check_name, summary, summary_at, error, error_at FROM fleet_check_snapshots`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]Snapshot{}
	for rows.Next() {
		var clusterID, check string
		var s Snapshot
		if err := rows.Scan(&clusterID, &check, &s.Summary, &s.SummaryAt, &s.Error, &s.ErrorAt); err != nil {
			return nil, err
		}
		if out[clusterID] == nil {
			out[clusterID] = map[string]Snapshot{}
		}
		out[clusterID][check] = s
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- worker

// RefreshCluster asks one cluster's agent all four checks, one after another,
// and stores each answer or failure.
func RefreshCluster(ctx context.Context, db *data.DB, gw ToolCaller, clusterID string) {
	cfg, _ := settings.Resolve(ctx, db.Pool)
	for _, ct := range checkTools {
		args := json.RawMessage(`{}`)
		if ct.tool == "get_posture_findings" {
			args = cfg.WithPostureArgs(args)
		}
		cctx, cancel := context.WithTimeout(ctx, callTimeout)
		raw, err := gw.CallTool(cctx, clusterID, ct.tool, args)
		cancel()
		var summary any
		if err == nil {
			summary, err = Summarize(ct.check, raw)
		}
		if err != nil && ctx.Err() != nil {
			return // shutting down: not the agent's failure
		}
		if rerr := record(ctx, db, clusterID, ct.check, summary, err); rerr != nil {
			logger.ErrorContext(ctx, "storing a fleet check failed", logging.ClusterID(clusterID), logging.Err(rerr))
		}
	}
}

// dueClusters lists the Active and Degraded clusters this process holds a
// tunnel to whose four checks are not all fresher than maxAge — never read,
// read too long ago, or last attempted too long ago. Another replica's
// tunnels are not callable from here, the same limit internal/upgradescans'
// scheduler has.
func dueClusters(ctx context.Context, db *data.DB, gw ToolCaller, maxAge time.Duration) ([]string, error) {
	var ids []string
	err := data.InFleetScope(ctx, db.Pool, func(ctx context.Context, tx pgx.Tx, _ string) error {
		due, err := dueIDs(ctx, tx, maxAge)
		for _, id := range due {
			if gw.IsConnected(id) {
				ids = append(ids, id)
			}
		}
		return err
	})
	return ids, err
}

// dueIDs is dueClusters' query, in the caller's transaction.
func dueIDs(ctx context.Context, tx pgx.Tx, maxAge time.Duration) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT c.id FROM clusters c
		WHERE c.state IN ('Active', 'Degraded') AND c.archived_at IS NULL
		AND (SELECT count(*) FROM fleet_check_snapshots s WHERE s.cluster_id = c.id
			AND GREATEST(COALESCE(s.summary_at, '-infinity'), COALESCE(s.error_at, '-infinity')) > now() - make_interval(secs => $1)) < $2
		ORDER BY c.id`, maxAge.Seconds(), len(checkTools))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// RefreshDue reads every connected cluster whose checks are older than
// maxAge, clusterConcurrency at a time.
func RefreshDue(ctx context.Context, db *data.DB, gw ToolCaller, maxAge time.Duration) {
	ids, err := dueClusters(ctx, db, gw, maxAge)
	if err != nil {
		logger.ErrorContext(ctx, "listing clusters for the fleet checks failed", logging.Err(err))
		return
	}
	sem := make(chan struct{}, clusterConcurrency)
	var wg sync.WaitGroup
	for _, id := range ids {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()
			RefreshCluster(ctx, db, gw, id)
		}(id)
	}
	wg.Wait()
}

// schedulerTick is how often the scheduler looks for clusters that are due.
// Short, so a cluster that connects — a new one, or every agent reconnecting
// after a hub restart — is read within a minute rather than waiting out a
// whole interval; each cluster is still read only once per interval.
const schedulerTick = time.Minute

// RunScheduler keeps every connected cluster's checks no older than interval.
// Run it under the hub's runExclusive.
func RunScheduler(ctx context.Context, db *data.DB, gw ToolCaller, interval time.Duration) {
	t := time.NewTimer(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		// A little under the interval, so a cluster read at the start of one
		// pass is due again on the pass an interval later, not one tick after.
		RefreshDue(ctx, db, gw, interval-schedulerTick/2)
		t.Reset(schedulerTick)
	}
}
