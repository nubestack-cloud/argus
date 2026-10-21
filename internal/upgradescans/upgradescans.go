// Package upgradescans records and serves upgrade-readiness scans
// (docs/CLUSTER_INSIGHT_SPECS.md CI-S5): the agent's get_upgrade_readiness
// result for a target Kubernetes minor, kept per cluster so the fleet view
// can show every cluster's verdict without asking every agent on page load.
package upgradescans

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/logging"
)

var logger = logging.For("upgradescans")

// ToolCaller is the gateway's CallTool.
type ToolCaller interface {
	CallTool(ctx context.Context, clusterID, tool string, args json.RawMessage) (json.RawMessage, error)
	IsConnected(clusterID string) bool
}

// Scan is one stored scan.
type Scan struct {
	ID              string          `json:"id"`
	ClusterID       string          `json:"clusterId"`
	CurrentVersion  string          `json:"currentVersion"`
	TargetVersion   string          `json:"targetVersion"`
	Verdict         string          `json:"verdict"`
	ReviewedThrough string          `json:"reviewedThrough"`
	ScannedAt       time.Time       `json:"scannedAt"`
	Result          json.RawMessage `json:"result,omitempty"`
}

type header struct {
	CurrentVersion  string `json:"currentVersion"`
	TargetVersion   string `json:"targetVersion"`
	ReviewedThrough string `json:"reviewedThrough"`
	Verdict         string `json:"verdict"`
}

// Run asks one cluster's agent for a scan and stores it. requestedBy is the
// user for an on-demand scan, empty for a scheduled one.
func Run(ctx context.Context, db *data.DB, gw ToolCaller, clusterID, target, requestedBy string) (Scan, error) {
	args, _ := json.Marshal(map[string]string{"targetVersion": target})
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	raw, err := gw.CallTool(cctx, clusterID, "get_upgrade_readiness", args)
	if err != nil {
		return Scan{}, err
	}
	var h header
	if err := json.Unmarshal(raw, &h); err != nil {
		return Scan{}, errors.New("the agent's scan result could not be read")
	}
	s := Scan{ID: domain.NewID(domain.PrefixUpgradeScan), ClusterID: clusterID, CurrentVersion: h.CurrentVersion,
		TargetVersion: h.TargetVersion, Verdict: h.Verdict, ReviewedThrough: h.ReviewedThrough, ScannedAt: time.Now().UTC(), Result: raw}
	err = data.InClusterScope(ctx, db.Pool, clusterID, func(ctx context.Context, tx pgx.Tx, tenantID string) error {
		var by *string
		if requestedBy != "" {
			by = &requestedBy
		}
		_, err := tx.Exec(ctx, `INSERT INTO upgrade_scans (id, tenant_id, cluster_id, current_version, target_version, verdict, reviewed_through, result, scanned_at, requested_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			s.ID, tenantID, clusterID, s.CurrentVersion, s.TargetVersion, s.Verdict, s.ReviewedThrough, raw, s.ScannedAt, by)
		return err
	})
	return s, err
}

// Latest returns the newest scan for a cluster (with its full result), in
// the caller's already-scoped transaction.
func Latest(ctx context.Context, tx pgx.Tx, clusterID string) (*Scan, error) {
	var s Scan
	err := tx.QueryRow(ctx, `SELECT id, cluster_id, current_version, target_version, verdict, reviewed_through, scanned_at, result
		FROM upgrade_scans WHERE cluster_id = $1 ORDER BY scanned_at DESC LIMIT 1`, clusterID).
		Scan(&s.ID, &s.ClusterID, &s.CurrentVersion, &s.TargetVersion, &s.Verdict, &s.ReviewedThrough, &s.ScannedAt, &s.Result)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &s, err
}

// nextMinorPredicate is true for a scan whose target is the minor directly
// after the version it was scanned from (1.33 → 1.34). That scan, and only
// that one, is a cluster's "next upgrade" verdict: a person can run a one-off
// scan for any later target from the Upgrade tab, and that answer must not
// replace the fleet's view of the next step. The CASE guards the casts —
// both columns are agent-reported strings — so a malformed row is simply not
// a next-minor scan rather than an error for the whole fleet.
const nextMinorPredicate = `CASE WHEN current_version ~ '^[0-9]{1,4}\.[0-9]{1,4}$' AND target_version ~ '^[0-9]{1,4}\.[0-9]{1,4}$'
	THEN split_part(target_version, '.', 1) = split_part(current_version, '.', 1)
		AND split_part(target_version, '.', 2)::int = split_part(current_version, '.', 2)::int + 1
	ELSE false END`

// LatestPerCluster returns each visible cluster's newest NEXT-MINOR scan
// (see nextMinorPredicate), without the full result — the fleet column and
// the cluster overview's upgrade check. A cluster whose only scans are
// one-off scans for other targets is absent, which the fleet reads as "not
// scanned for the next minor yet" rather than borrowing another target's
// verdict.
func LatestPerCluster(ctx context.Context, tx pgx.Tx) ([]Scan, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (cluster_id) id, cluster_id, current_version, target_version, verdict, reviewed_through, scanned_at
		FROM upgrade_scans WHERE `+nextMinorPredicate+` ORDER BY cluster_id, scanned_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Scan{}
	for rows.Next() {
		var s Scan
		if err := rows.Scan(&s.ID, &s.ClusterID, &s.CurrentVersion, &s.TargetVersion, &s.Verdict, &s.ReviewedThrough, &s.ScannedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ScanAge is how old the newest scan for a cluster is; ok=false when none.
func ScanAge(ctx context.Context, tx pgx.Tx, clusterID string) (time.Duration, bool, error) {
	var at time.Time
	err := tx.QueryRow(ctx, `SELECT max(scanned_at) FROM upgrade_scans WHERE cluster_id = $1`, clusterID).Scan(&at)
	if err != nil || at.IsZero() {
		return 0, false, nil
	}
	return time.Since(at), true, nil
}

// RunScheduler scans every connected Active cluster for the next minor once
// a day. Run it under the hub's runExclusive.
func RunScheduler(ctx context.Context, db *data.DB, gw ToolCaller, interval time.Duration) {
	t := time.NewTimer(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		t.Reset(interval)
		var ids []string
		_ = data.InFleetScope(ctx, db.Pool, func(ctx context.Context, tx pgx.Tx, _ string) error {
			rows, err := tx.Query(ctx, `SELECT c.id FROM clusters c WHERE c.state = 'Active' AND c.archived_at IS NULL
				AND NOT EXISTS (SELECT 1 FROM upgrade_scans u WHERE u.cluster_id = c.id AND u.requested_by IS NULL AND u.scanned_at > now() - interval '23 hours')`)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var id string
				if rows.Scan(&id) == nil {
					ids = append(ids, id)
				}
			}
			return rows.Err()
		})
		for _, id := range ids {
			if !gw.IsConnected(id) {
				continue
			}
			if _, err := Run(ctx, db, gw, id, "", ""); err != nil {
				logger.WarnContext(ctx, "scheduled upgrade-readiness scan failed", logging.ClusterID(id), logging.Err(err))
			} else {
				logger.InfoContext(ctx, "upgrade-readiness scan recorded", logging.ClusterID(id), slog.String("trigger", "schedule"))
			}
		}
	}
}
