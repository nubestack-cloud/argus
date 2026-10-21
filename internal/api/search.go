package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"argus/internal/authz"
	"argus/internal/logging"
)

// GET /api/v1/search?q= (docs/CLUSTER_INSIGHT_SPECS.md CI-S12): find objects
// by name, label or image across every connected cluster the caller may
// inspect. Each agent searches its own object cache; the hub merges by score
// and says exactly which clusters did not answer, so a partial result never
// reads as a complete one.

const (
	searchPerClusterTimeout = 3 * time.Second
	searchConcurrency       = 16
	searchMaxHits           = 100
)

type searchHit struct {
	ClusterID   string   `json:"clusterId"`
	ClusterName string   `json:"clusterName"`
	Score       int      `json:"score"`
	Kind        string   `json:"kind"`
	APIGroup    string   `json:"apiGroup,omitempty"`
	Namespace   string   `json:"namespace,omitempty"`
	Name        string   `json:"name"`
	Matched     []string `json:"matched,omitempty"`
	Status      string   `json:"status,omitempty"`
}

type searchClusterRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type searchResponse struct {
	Query                string             `json:"query"`
	Hits                 []searchHit        `json:"hits"`
	Truncated            bool               `json:"truncated,omitempty"`
	ClustersQueried      int                `json:"clustersQueried"`
	ClustersAnswered     int                `json:"clustersAnswered"`
	ClustersFailed       []searchClusterRef `json:"clustersFailed"`
	ClustersDisconnected []searchClusterRef `json:"clustersDisconnected"`
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" || len(q) > 200 {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/validation", "Invalid query", "q is required (at most 200 characters)")
		return
	}
	rows, err := rc.Tx.Query(ctx, `SELECT id, display_name FROM clusters WHERE archived_at IS NULL AND state IN ('Active','Degraded','Disconnected') ORDER BY display_name`)
	if err != nil {
		logger.ErrorContext(ctx, "listing clusters for search failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Search failed", "")
		return
	}
	var candidates []searchClusterRef
	for rows.Next() {
		var c searchClusterRef
		if rows.Scan(&c.ID, &c.Name) == nil {
			candidates = append(candidates, c)
		}
	}
	rows.Close()

	resp := searchResponse{Query: q, Hits: []searchHit{}, ClustersFailed: []searchClusterRef{}, ClustersDisconnected: []searchClusterRef{}}
	var targets []searchClusterRef
	for _, c := range candidates {
		ok, err := authz.HasCapabilityForCluster(ctx, rc.Tx, rc.Grants, authz.CapClusterInspect, c.ID)
		if err != nil || !ok {
			continue
		}
		if !s.gw.IsConnected(c.ID) {
			resp.ClustersDisconnected = append(resp.ClustersDisconnected, c)
			continue
		}
		targets = append(targets, c)
	}
	resp.ClustersQueried = len(targets)

	args, _ := json.Marshal(map[string]any{"query": q, "limit": 50})
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, searchConcurrency)
	for _, c := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(c searchClusterRef) {
			defer wg.Done()
			defer func() { <-sem }()
			cctx, cancel := context.WithTimeout(ctx, searchPerClusterTimeout)
			defer cancel()
			raw, err := s.gw.CallTool(cctx, c.ID, "search_objects", args)
			var res struct {
				Hits []searchHit `json:"hits"`
			}
			if err == nil {
				err = json.Unmarshal(raw, &res)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				resp.ClustersFailed = append(resp.ClustersFailed, c)
				return
			}
			resp.ClustersAnswered++
			for _, h := range res.Hits {
				h.ClusterID, h.ClusterName = c.ID, c.Name
				resp.Hits = append(resp.Hits, h)
			}
		}(c)
	}
	wg.Wait()
	sort.SliceStable(resp.Hits, func(i, j int) bool {
		if resp.Hits[i].Score != resp.Hits[j].Score {
			return resp.Hits[i].Score > resp.Hits[j].Score
		}
		return resp.Hits[i].ClusterName+resp.Hits[i].Namespace+resp.Hits[i].Name < resp.Hits[j].ClusterName+resp.Hits[j].Namespace+resp.Hits[j].Name
	})
	if len(resp.Hits) > searchMaxHits {
		resp.Hits = resp.Hits[:searchMaxHits]
		resp.Truncated = true
	}
	writeJSON(w, http.StatusOK, resp)
}
