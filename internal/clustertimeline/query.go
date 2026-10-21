package clustertimeline

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/orchestrator"
)

// Query is one timeline request, already validated by the caller.
type Query struct {
	ClusterID string
	Since     time.Time
	Until     time.Time
	// Namespace, when set, keeps only objects in it — cluster-scoped objects
	// (Nodes, ClusterRoleBindings) and objectless findings drop out.
	Namespace string
	// Sources to read: SourceChanges, SourceFindings, SourceIncidents.
	Sources map[string]bool
	// OnlyIncidents keeps only rows carrying an incident span.
	OnlyIncidents bool
	// Restricted sources are not read at all; they are echoed back so the
	// client can say why they are missing.
	Restricted []Restriction
}

// Build reads the three sources for q and assembles the timeline. tx must
// already be RLS-scoped to q.ClusterID.
func Build(ctx context.Context, tx pgx.Tx, q Query) (Response, error) {
	resp := Response{
		ClusterID: q.ClusterID, Since: q.Since, Until: q.Until, Namespace: q.Namespace,
		Types: []string{}, OnlyIncidents: q.OnlyIncidents,
		Gaps: []Gap{}, Namespaces: []string{}, Restricted: q.Restricted,
		Limits:               Limits{MaxRows: MaxRows, MaxMarksPerRow: MaxMarksPerRow, MaxSpansPerRow: MaxSpansPerRow},
		FindingRunGapSeconds: int(FindingRunGap(q.Until.Sub(q.Since)).Seconds()),
	}
	if resp.Restricted == nil {
		resp.Restricted = []Restriction{}
	}
	for _, s := range []string{SourceChanges, SourceFindings, SourceIncidents} {
		if q.Sources[s] {
			resp.Types = append(resp.Types, s)
		}
	}

	ow := owners{}
	var changes []changeRec
	var runs []findingRun
	var incidents []incidentRec
	var err error

	if q.Sources[SourceChanges] {
		if changes, resp.Totals.Changes, err = readChanges(ctx, tx, q); err != nil {
			return Response{}, err
		}
		resp.Truncated.Changes = resp.Totals.Changes - len(changes)
		for _, c := range changes {
			if c.OwnerName != "" {
				ow[c.Object.key()] = ObjectRef{Kind: c.OwnerKind, Name: c.OwnerName}
			}
		}
	}
	if q.Sources[SourceFindings] {
		var totalRuns int
		if runs, totalRuns, resp.Totals.FindingReports, err = readFindingRuns(ctx, tx, q); err != nil {
			return Response{}, err
		}
		resp.Totals.FindingRuns = totalRuns
		resp.Truncated.FindingRuns = totalRuns - len(runs)
	}
	if q.Sources[SourceIncidents] {
		if incidents, resp.Totals.Incidents, resp.Totals.IncidentsOpened, err = readIncidents(ctx, tx, q); err != nil {
			return Response{}, err
		}
		resp.Truncated.Incidents = resp.Totals.Incidents - len(incidents)
	}

	if err := resolveOwners(ctx, tx, q.ClusterID, ow, changes, runs, incidents); err != nil {
		return Response{}, err
	}

	var kept RowCounts
	resp.Rows, resp.Totals.Rows, kept = assembleWithTotals(q.Since, q.Until, ow, changes, runs, incidents, q.OnlyIncidents)
	resp.Truncated.Rows = resp.Totals.Rows - len(resp.Rows)
	if q.OnlyIncidents {
		// The source totals above count every object; with this filter the
		// sentence must count only the objects it kept.
		resp.Totals.Changes, resp.Totals.FindingRuns, resp.Totals.FindingReports = kept.Changes, kept.FindingRuns, kept.FindingReports
	}

	// Gaps are about the change record; they are shown whenever changes are,
	// whatever the namespace filter, because a lost batch could have held
	// any namespace's changes.
	if q.Sources[SourceChanges] {
		if resp.Gaps, err = readGaps(ctx, tx, q); err != nil {
			return Response{}, err
		}
	}
	if resp.Namespaces, err = readNamespaces(ctx, tx, q); err != nil {
		return Response{}, err
	}
	return resp, nil
}

func nsClause(q Query, column string, args *[]any) string {
	if q.Namespace == "" {
		return ""
	}
	*args = append(*args, q.Namespace)
	return fmt.Sprintf(" AND %s = $%d", column, len(*args))
}

// readChanges returns the newest MaxChanges changes in the window and the
// exact total. Served by resource_changes_cluster_time (cluster_id,
// observed_at DESC) — or resource_changes_object when a namespace is set.
func readChanges(ctx context.Context, tx pgx.Tx, q Query) ([]changeRec, int, error) {
	args := []any{q.ClusterID, q.Since, q.Until}
	where := `cluster_id = $1 AND observed_at >= $2 AND observed_at <= $3` + nsClause(q, "namespace", &args)
	var total int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM resource_changes WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count changes: %w", err)
	}
	args = append(args, MaxChanges)
	rows, err := tx.Query(ctx, `SELECT id, observed_at, kind, api_group, namespace, name, owner_kind, owner_name, op, summary
		FROM resource_changes WHERE `+where+fmt.Sprintf(` ORDER BY observed_at DESC, seq DESC LIMIT $%d`, len(args)), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list changes: %w", err)
	}
	defer rows.Close()
	out := []changeRec{}
	for rows.Next() {
		var c changeRec
		if err := rows.Scan(&c.ID, &c.ObservedAt, &c.Object.Kind, &c.Object.APIGroup, &c.Object.Namespace, &c.Object.Name,
			&c.OwnerKind, &c.OwnerName, &c.Op, &c.Summary); err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

// readFindingRuns collapses the window's finding reports into runs: one per
// fingerprint per stretch with no silence longer than FindingRunGap. A
// detector re-sends a persisting finding every few minutes, so the table
// holds thousands of rows a day for a few dozen distinct findings; drawing
// each report would bury the one finding that is new. Served by
// findings_cluster_occurred_idx (migration 000129).
//
// The returned totals are exact: total runs, and total reports (rows).
func readFindingRuns(ctx context.Context, tx pgx.Tx, q Query) ([]findingRun, int, int, error) {
	gap := FindingRunGap(q.Until.Sub(q.Since))
	args := []any{q.ClusterID, q.Since, q.Until, fmt.Sprintf("%d seconds", int(gap.Seconds()))}
	ns := nsClause(q, "coalesce(namespace, '')", &args)
	args = append(args, MaxFindingRuns)
	limit := len(args)
	sql := `
WITH w AS (
  SELECT fingerprint, occurred_at, gvk, coalesce(namespace, '') AS namespace, coalesce(object_name, '') AS object_name,
         coalesce(reason, '') AS reason, coalesce(message, '') AS message, severity, detector_id, incident_id,
         lag(occurred_at) OVER (PARTITION BY fingerprint ORDER BY occurred_at) AS prev
    FROM findings
   WHERE cluster_id = $1 AND occurred_at >= $2 AND occurred_at <= $3` + ns + `
), r AS (
  SELECT *, sum(CASE WHEN prev IS NULL OR occurred_at - prev > $4::interval THEN 1 ELSE 0 END)
              OVER (PARTITION BY fingerprint ORDER BY occurred_at) AS run_no
    FROM w
), g AS (
  SELECT fingerprint, run_no, min(occurred_at) AS first_at, max(occurred_at) AS last_at, count(*) AS reports,
         (array_agg(gvk ORDER BY occurred_at DESC))[1] AS gvk,
         (array_agg(namespace ORDER BY occurred_at DESC))[1] AS namespace,
         (array_agg(object_name ORDER BY occurred_at DESC))[1] AS object_name,
         (array_agg(reason ORDER BY occurred_at DESC))[1] AS reason,
         (array_agg(message ORDER BY occurred_at DESC))[1] AS message,
         (array_agg(severity ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END))[1] AS severity,
         (array_agg(detector_id ORDER BY occurred_at DESC))[1] AS detector_id,
         (array_agg(incident_id ORDER BY occurred_at DESC) FILTER (WHERE incident_id IS NOT NULL))[1] AS incident_id
    FROM r GROUP BY fingerprint, run_no
), ranked AS (
  SELECT g.*, count(*) OVER () AS total_runs, sum(reports) OVER () AS total_reports
    FROM g ORDER BY last_at DESC, fingerprint, run_no LIMIT $` + fmt.Sprint(limit) + `
)
SELECT fingerprint, first_at, last_at, reports, gvk, namespace, object_name, reason, message, severity, detector_id,
       coalesce(incident_id, ''), total_runs, total_reports,
       run_no = 1 AND EXISTS (
         SELECT 1 FROM findings p
          WHERE p.cluster_id = $1 AND p.fingerprint = ranked.fingerprint
            AND p.occurred_at < $2 AND p.occurred_at >= $2 - $4::interval)
  FROM ranked`
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("list finding runs: %w", err)
	}
	defer rows.Close()
	out := []findingRun{}
	var totalRuns, totalReports int64
	for rows.Next() {
		var f findingRun
		var reports int64
		if err := rows.Scan(&f.Fingerprint, &f.First, &f.Last, &reports, &f.GVK, &f.Namespace, &f.ObjectName, &f.Reason,
			&f.Message, &f.Severity, &f.DetectorID, &f.IncidentID, &totalRuns, &totalReports, &f.ContinuesFromBefore); err != nil {
			return nil, 0, 0, err
		}
		f.Reports = int(reports)
		out = append(out, f)
	}
	return out, int(totalRuns), int(totalReports), rows.Err()
}

// readIncidents returns every incident whose open interval overlaps the
// window: opened before it ends, and either still open or closed after it
// starts. Served by incidents_cluster_state_idx (cluster_id leading).
func readIncidents(ctx context.Context, tx pgx.Tx, q Query) ([]incidentRec, int, int, error) {
	closed := orchestrator.ClosedStateSQL()
	args := []any{q.ClusterID, q.Since, q.Until}
	where := `cluster_id = $1 AND archived_at IS NULL AND first_seen <= $3
	  AND (state NOT IN ` + closed + ` OR coalesce(resolved_at, last_seen) >= $2)` +
		nsClause(q, "split_part(coalesce(nullif(workload_key, ''), object_key, ''), '|', 2)", &args)
	var total, opened int
	if err := tx.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE first_seen >= $2) FROM incidents WHERE `+where, args...).Scan(&total, &opened); err != nil {
		return nil, 0, 0, fmt.Errorf("count incidents: %w", err)
	}
	args = append(args, MaxIncidents)
	rows, err := tx.Query(ctx, `SELECT id, severity, state, state IN `+closed+`, first_seen, last_seen, resolved_at,
	       coalesce(object_key, ''), coalesce(workload_key, ''), coalesce(opening_reason, ''), fingerprint
	  FROM incidents WHERE `+where+fmt.Sprintf(` ORDER BY greatest(last_seen, coalesce(resolved_at, last_seen)) DESC, id LIMIT $%d`, len(args)), args...)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("list incidents: %w", err)
	}
	defer rows.Close()
	out := []incidentRec{}
	for rows.Next() {
		var i incidentRec
		if err := rows.Scan(&i.ID, &i.Severity, &i.State, &i.Closed, &i.FirstSeen, &i.LastSeen, &i.ResolvedAt,
			&i.ObjectKey, &i.WorkloadKey, &i.OpeningReason, &i.Fingerprint); err != nil {
			return nil, 0, 0, err
		}
		out = append(out, i)
	}
	return out, total, opened, rows.Err()
}

// resolveOwners fills the owner map for every object the timeline names
// whose controller is not yet known, from that object's most recent change
// row at any time inside retention — a ReplicaSet created last week still
// records which Deployment owns it. Up to three rounds (Pod → ReplicaSet →
// Deployment needs two). Served by resource_changes_object.
func resolveOwners(ctx context.Context, tx pgx.Tx, clusterID string, ow owners, changes []changeRec, runs []findingRun, incidents []incidentRec) error {
	looked := map[string]bool{}
	pending := map[string]ObjectRef{}
	want := func(o ObjectRef) {
		if o.Name == "" || o.Kind == "" {
			return
		}
		k := o.key()
		if _, known := ow[k]; known || looked[k] {
			return
		}
		pending[k] = o
	}
	for _, c := range changes {
		if c.OwnerName == "" {
			// Its own change row says it has no owner.
			looked[c.Object.key()] = true
		}
	}
	for _, c := range changes {
		if c.OwnerName != "" {
			want(ObjectRef{Kind: c.OwnerKind, Namespace: c.Object.Namespace, Name: c.OwnerName})
		}
	}
	for _, f := range runs {
		if f.ObjectName != "" {
			_, kind := parseGVK(f.GVK)
			want(ObjectRef{Kind: kind, Namespace: f.Namespace, Name: f.ObjectName})
		}
	}
	for _, i := range incidents {
		if i.WorkloadKey != "" {
			continue
		}
		if o, ok := parseKey(i.ObjectKey); ok {
			want(o)
		}
	}
	for round := 0; round < 3 && len(pending) > 0; round++ {
		var nss, kinds, names []string
		for k, o := range pending {
			looked[k] = true
			if len(names) >= 2000 {
				continue
			}
			nss, kinds, names = append(nss, o.Namespace), append(kinds, o.Kind), append(names, o.Name)
		}
		pending = map[string]ObjectRef{}
		rows, err := tx.Query(ctx, `SELECT DISTINCT ON (rc.namespace, rc.kind, rc.name) rc.namespace, rc.kind, rc.name, rc.owner_kind, rc.owner_name
			  FROM resource_changes rc
			  JOIN unnest($2::text[], $3::text[], $4::text[]) AS o(ns, kind, name)
			    ON rc.namespace = o.ns AND rc.kind = o.kind AND rc.name = o.name
			 WHERE rc.cluster_id = $1
			 ORDER BY rc.namespace, rc.kind, rc.name, rc.observed_at DESC`, clusterID, nss, kinds, names)
		if err != nil {
			return fmt.Errorf("resolve owners: %w", err)
		}
		var found []ObjectRef
		for rows.Next() {
			var o, owner ObjectRef
			if err := rows.Scan(&o.Namespace, &o.Kind, &o.Name, &owner.Kind, &owner.Name); err != nil {
				rows.Close()
				return err
			}
			if owner.Name != "" {
				ow[o.key()] = owner
				found = append(found, ObjectRef{Kind: owner.Kind, Namespace: o.Namespace, Name: owner.Name})
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, o := range found {
			if _, isWorkload := workloadKinds[o.Kind]; isWorkload {
				want(o)
			}
		}
	}
	return nil
}

func readGaps(ctx context.Context, tx pgx.Tx, q Query) ([]Gap, error) {
	rows, err := tx.Query(ctx, `SELECT gap_from, gap_to, reason FROM resource_change_gaps
		WHERE cluster_id = $1 AND gap_to >= $2 AND gap_from <= $3 ORDER BY gap_from LIMIT 100`, q.ClusterID, q.Since, q.Until)
	if err != nil {
		return nil, fmt.Errorf("list change gaps: %w", err)
	}
	defer rows.Close()
	out := []Gap{}
	for rows.Next() {
		var g Gap
		if err := rows.Scan(&g.From, &g.To, &g.Reason); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// readNamespaces lists every namespace with activity in the window from the
// sources the caller may read, ignoring the namespace filter — it is what
// the client's namespace picker offers.
func readNamespaces(ctx context.Context, tx pgx.Tx, q Query) ([]string, error) {
	parts := []string{}
	if q.Sources[SourceChanges] {
		parts = append(parts, `SELECT namespace AS ns FROM resource_changes WHERE cluster_id = $1 AND observed_at >= $2 AND observed_at <= $3`)
	}
	if q.Sources[SourceFindings] {
		parts = append(parts, `SELECT coalesce(namespace, '') AS ns FROM findings WHERE cluster_id = $1 AND occurred_at >= $2 AND occurred_at <= $3`)
	}
	if q.Sources[SourceIncidents] {
		parts = append(parts, `SELECT split_part(coalesce(nullif(workload_key, ''), object_key, ''), '|', 2) AS ns FROM incidents
			WHERE cluster_id = $1 AND archived_at IS NULL AND first_seen <= $3
			  AND (state NOT IN `+orchestrator.ClosedStateSQL()+` OR coalesce(resolved_at, last_seen) >= $2)`)
	}
	if len(parts) == 0 {
		return []string{}, nil
	}
	sql := `SELECT DISTINCT ns FROM (` + parts[0]
	for _, p := range parts[1:] {
		sql += ` UNION ` + p
	}
	sql += `) n WHERE ns <> '' ORDER BY ns LIMIT 500`
	rows, err := tx.Query(ctx, sql, q.ClusterID, q.Since, q.Until)
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var ns string
		if err := rows.Scan(&ns); err != nil {
			return nil, err
		}
		out = append(out, ns)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}
