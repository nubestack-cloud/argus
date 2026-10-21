package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"argus/internal/data"
	"argus/internal/llm"
	"argus/internal/resourcechanges"
)

// get_recent_changes is served by the hub from resource_changes, not over the
// tunnel (docs/CLUSTER_INSIGHT_SPECS.md CI-S2). Like the repository tools it
// is bound to the investigation's own cluster — taken from the incident or
// the MCP grant, never from the tool arguments.

type recentChangesArgs struct {
	Namespace    string `json:"namespace"`
	Kind         string `json:"kind"`
	Name         string `json:"name"`
	SinceMinutes int    `json:"sinceMinutes"`
}

// CallRecentChanges serves one get_recent_changes call in its own short
// RLS-scoped transaction.
func CallRecentChanges(ctx context.Context, db *data.DB, clusterID string, args json.RawMessage) (json.RawMessage, error) {
	if clusterID == "" {
		return nil, errors.New("refusing get_recent_changes with no cluster in scope")
	}
	var a recentChangesArgs
	if len(args) > 0 {
		if err := json.Unmarshal(args, &a); err != nil {
			return nil, fmt.Errorf("invalid arguments: %w", err)
		}
	}
	if a.SinceMinutes <= 0 {
		a.SinceMinutes = 180
	}
	if a.SinceMinutes > 24*60 {
		a.SinceMinutes = 24 * 60
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		return nil, err
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		return nil, err
	}
	q := resourcechanges.Query{ClusterID: clusterID, Namespace: a.Namespace, Since: time.Now().Add(-time.Duration(a.SinceMinutes) * time.Minute), Limit: 100}
	if a.Name != "" {
		q.Objects = []resourcechanges.ObjectRef{{Kind: a.Kind, Namespace: a.Namespace, Name: a.Name}}
	} else {
		q.Kind = a.Kind
	}
	res, err := resourcechanges.List(ctx, tx, q)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"changes": res.Changes, "gaps": res.Gaps, "truncated": res.Truncated,
		"window": fmt.Sprintf("last %d minutes", a.SinceMinutes),
		"note":   "Field-level changes the agent observed; env and ConfigMap values appear only as added/removed/modified. A gap means changes in that window were not recorded — absence there is not evidence."}
	return json.Marshal(out)
}

// ChangesToolCallback routes get_recent_changes to the hub and everything
// else to next.
func ChangesToolCallback(db *data.DB, clusterID string, next func(context.Context, string, json.RawMessage) (json.RawMessage, error)) func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
	return func(ctx context.Context, tool string, args json.RawMessage) (json.RawMessage, error) {
		if tool == llm.RecentChangesToolName {
			return CallRecentChanges(ctx, db, clusterID, args)
		}
		return next(ctx, tool, args)
	}
}
