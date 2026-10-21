// Package resourcechanges stores and queries the field-level object changes
// agents report (docs/CLUSTER_INSIGHT_SPECS.md CI-S2): the resource_changes
// and resource_change_gaps tables, their retention, and the read shapes the
// API and the investigation's get_recent_changes tool serve.
//
// Every function takes a transaction whose RLS scope the caller has already
// set (internal/data.SetRequestScope) — this package never widens scope.
package resourcechanges

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/logging"
	"argus/internal/tunnel"
)

// MaxBatchChanges bounds how many changes one agent batch may insert.
const MaxBatchChanges = 1000

// Insert records one agent batch for clusterID.
func Insert(ctx context.Context, tx pgx.Tx, tenantID, clusterID string, b *tunnel.ChangeBatch) (int, error) {
	if b == nil {
		return 0, nil
	}
	changes := b.Changes
	if len(changes) > MaxBatchChanges {
		changes = changes[:MaxBatchChanges]
	}
	batch := &pgx.Batch{}
	for _, c := range changes {
		if c.Name == "" || c.Kind == "" {
			continue
		}
		switch c.Op {
		case "add", "update", "delete":
		default:
			continue
		}
		fields, err := json.Marshal(c.Fields)
		if err != nil || len(fields) > 64<<10 {
			fields = []byte(`[]`)
		}
		if c.Fields == nil {
			fields = []byte(`[]`)
		}
		observed := c.ObservedAt
		if observed.IsZero() {
			observed = time.Now()
		}
		batch.Queue(`INSERT INTO resource_changes
			(id, tenant_id, cluster_id, observed_at, kind, api_group, namespace, name, uid, owner_kind, owner_name, op, fields, summary)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
			domain.NewID(domain.PrefixResourceChange), tenantID, clusterID, observed, trunc(c.Kind, 128), trunc(c.APIGroup, 253),
			trunc(c.Namespace, 253), trunc(c.Name, 253), trunc(c.UID, 64), trunc(c.OwnerKind, 128), trunc(c.OwnerName, 253),
			c.Op, fields, trunc(c.Summary, 1024))
	}
	for _, g := range b.Gaps {
		if g.From.IsZero() || g.To.IsZero() {
			continue
		}
		batch.Queue(`INSERT INTO resource_change_gaps (id, tenant_id, cluster_id, gap_from, gap_to, reason) VALUES ($1,$2,$3,$4,$5,$6)`,
			domain.NewID(domain.PrefixResourceChangeGap), tenantID, clusterID, g.From, g.To, trunc(g.Reason, 512))
	}
	n := batch.Len()
	if n == 0 {
		return 0, nil
	}
	br := tx.SendBatch(ctx, batch)
	for i := 0; i < n; i++ {
		if _, err := br.Exec(); err != nil {
			br.Close()
			return 0, fmt.Errorf("insert resource change: %w", err)
		}
	}
	return n, br.Close()
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// Change is one stored change, as served.
type Change struct {
	ID         string          `json:"id"`
	ClusterID  string          `json:"clusterId"`
	ObservedAt time.Time       `json:"observedAt"`
	Kind       string          `json:"kind"`
	APIGroup   string          `json:"apiGroup,omitempty"`
	Namespace  string          `json:"namespace,omitempty"`
	Name       string          `json:"name"`
	OwnerKind  string          `json:"ownerKind,omitempty"`
	OwnerName  string          `json:"ownerName,omitempty"`
	Op         string          `json:"op"`
	Fields     json.RawMessage `json:"fields"`
	Summary    string          `json:"summary,omitempty"`
}

// Gap is a window in which changes were lost.
type Gap struct {
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	Reason string    `json:"reason"`
}

// Query filters changes. Objects, when set, restricts to changes on any of
// those objects or on objects they own (owner match).
type Query struct {
	ClusterID string
	Namespace string
	Kind      string
	Name      string
	Since     time.Time
	Until     time.Time
	Objects   []ObjectRef
	Limit     int
}

// ObjectRef names an object by kind/namespace/name.
type ObjectRef struct {
	Kind, Namespace, Name string
}

// Result is a page of changes plus any gaps overlapping the window.
type Result struct {
	Changes   []Change `json:"changes"`
	Gaps      []Gap    `json:"gaps"`
	Truncated bool     `json:"truncated,omitempty"`
}

// List returns changes newest first.
func List(ctx context.Context, tx pgx.Tx, q Query) (Result, error) {
	if q.Limit <= 0 || q.Limit > 500 {
		q.Limit = 200
	}
	if q.Until.IsZero() {
		q.Until = time.Now().Add(time.Minute)
	}
	if q.Since.IsZero() {
		q.Since = q.Until.Add(-24 * time.Hour)
	}
	args := []any{q.ClusterID, q.Since, q.Until}
	where := `cluster_id = $1 AND observed_at >= $2 AND observed_at <= $3`
	add := func(cond string, v any) {
		args = append(args, v)
		where += fmt.Sprintf(" AND "+cond, len(args))
	}
	if q.Namespace != "" {
		add("namespace = $%d", q.Namespace)
	}
	if q.Kind != "" {
		add("kind = $%d", q.Kind)
	}
	if q.Name != "" {
		add("name = $%d", q.Name)
	}
	if len(q.Objects) > 0 {
		var kinds, nss, names []string
		for _, o := range q.Objects {
			kinds = append(kinds, o.Kind)
			nss = append(nss, o.Namespace)
			names = append(names, o.Name)
		}
		args = append(args, kinds, nss, names)
		k, n, nm := len(args)-2, len(args)-1, len(args)
		where += fmt.Sprintf(` AND EXISTS (SELECT 1 FROM unnest($%d::text[], $%d::text[], $%d::text[]) AS o(kind, ns, name)
			WHERE (resource_changes.kind = o.kind AND resource_changes.namespace = o.ns AND resource_changes.name = o.name)
			   OR (resource_changes.owner_kind = o.kind AND resource_changes.namespace = o.ns AND resource_changes.owner_name = o.name))`, k, n, nm)
	}
	args = append(args, q.Limit+1)
	rows, err := tx.Query(ctx, `SELECT id, cluster_id, observed_at, kind, api_group, namespace, name, owner_kind, owner_name, op, fields, summary
		FROM resource_changes WHERE `+where+fmt.Sprintf(` ORDER BY observed_at DESC, seq DESC LIMIT $%d`, len(args)), args...)
	if err != nil {
		return Result{}, err
	}
	defer rows.Close()
	res := Result{Changes: []Change{}, Gaps: []Gap{}}
	for rows.Next() {
		var c Change
		if err := rows.Scan(&c.ID, &c.ClusterID, &c.ObservedAt, &c.Kind, &c.APIGroup, &c.Namespace, &c.Name, &c.OwnerKind, &c.OwnerName, &c.Op, &c.Fields, &c.Summary); err != nil {
			return Result{}, err
		}
		res.Changes = append(res.Changes, c)
	}
	if err := rows.Err(); err != nil {
		return Result{}, err
	}
	if len(res.Changes) > q.Limit {
		res.Changes = res.Changes[:q.Limit]
		res.Truncated = true
	}
	gaps, err := tx.Query(ctx, `SELECT gap_from, gap_to, reason FROM resource_change_gaps
		WHERE cluster_id = $1 AND gap_to >= $2 AND gap_from <= $3 ORDER BY gap_from DESC LIMIT 50`, q.ClusterID, q.Since, q.Until)
	if err != nil {
		return Result{}, err
	}
	defer gaps.Close()
	for gaps.Next() {
		var g Gap
		if err := gaps.Scan(&g.From, &g.To, &g.Reason); err != nil {
			return Result{}, err
		}
		res.Gaps = append(res.Gaps, g)
	}
	return res, gaps.Err()
}

// DefaultRetention is how long changes are kept when the organisation has
// not configured resourceChanges.retentionDays.
const DefaultRetention = 14 * 24 * time.Hour

// Prune deletes changes and gaps older than retention, in bounded batches so
// a long backlog never holds one huge transaction. Idempotent, so safe to run
// from several hub replicas.
func Prune(ctx context.Context, tx pgx.Tx, retention time.Duration, batch int) (int64, error) {
	if batch <= 0 {
		batch = 5000
	}
	cutoff := time.Now().Add(-retention)
	tag, err := tx.Exec(ctx, `WITH doomed AS (
			SELECT id FROM resource_changes WHERE observed_at < $1 ORDER BY observed_at LIMIT $2
		) DELETE FROM resource_changes WHERE id IN (SELECT id FROM doomed)`, cutoff, batch)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM resource_change_gaps WHERE gap_to < $1`, cutoff); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// RunRetention prunes on a timer until ctx ends. The hub runs it under
// runExclusive, but Prune is idempotent either way.
func RunRetention(ctx context.Context, db *data.DB, retention, interval time.Duration) {
	if retention <= 0 {
		retention = DefaultRetention
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		pruneOnce(ctx, db, retention)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func pruneOnce(ctx context.Context, db *data.DB, retention time.Duration) {
	for i := 0; i < 20; i++ { // up to 100k rows per tick
		tx, err := db.Pool.Begin(ctx)
		if err != nil {
			return
		}
		tenantID, err := data.SingleOrganisationID(ctx, tx)
		if err == nil {
			err = data.SetRequestScope(ctx, tx, tenantID, nil)
		}
		var n int64
		if err == nil {
			n, err = Prune(ctx, tx, retention, 5000)
		}
		if err != nil {
			_ = tx.Rollback(ctx)
			logger.Warn("resource change retention failed", logging.Err(err))
			return
		}
		if err := tx.Commit(ctx); err != nil {
			return
		}
		if n < 5000 {
			return
		}
	}
}

var logger = logging.For("resourcechanges")
