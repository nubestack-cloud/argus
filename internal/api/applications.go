package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/fleetchecks"
	"argus/internal/logging"
)

// GET /api/v1/applications (PROJECT.md PG19): the units that ship together —
// an Argo CD Application, a Flux Kustomization or HelmRelease, a Helm
// release — folded across clusters into one application each, with the
// version every cluster runs. Read from the fleet-check snapshots the hub
// already refreshes every 10 minutes, so the page costs no agent calls.
//
// How instances fold, strongest first:
//  1. a declared name: the argus.io/app annotation on the object;
//  2. a declared source: an Argo or Flux object's repository plus path or
//     chart — the same source deployed to two clusters is one application;
//  3. a Helm release no controller owns has no source ARGUS can read, so it
//     folds by release name, and the row says it matched by name.
// Version is what was applied (the synced revision, or the Helm revision
// number, which is per cluster and so never compared as skew).

type appInstance struct {
	ClusterID   string `json:"clusterId"`
	ClusterName string `json:"clusterName"`
	Kind        string `json:"kind"`
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Sync        string `json:"sync,omitempty"`
	Health      string `json:"health,omitempty"`
	Problem     bool   `json:"problem,omitempty"`
}

type application struct {
	Key       string        `json:"key"`
	Name      string        `json:"name"`
	MatchedBy string        `json:"matchedBy"` // annotation, source, name
	Source    string        `json:"source,omitempty"`
	Instances []appInstance `json:"instances"`
	// Skew is true when instances run different applied revisions.
	Skew     bool `json:"skew"`
	Problems int  `json:"problems"`
}

type applicationsResponse struct {
	Applications []application `json:"applications"`
	// Truncated names clusters whose snapshot held more applications than
	// were stored, so their list here is incomplete.
	Truncated []string   `json:"truncated,omitempty"`
	AsOf      *time.Time `json:"asOf,omitempty"`
}

func normaliseRepo(u string) string {
	u = strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(u)), "/"), ".git")
	for _, p := range []string{"https://", "http://", "ssh://", "git@"} {
		u = strings.TrimPrefix(u, p)
	}
	return strings.Replace(u, ":", "/", 1)
}

func shortRev(r string) string {
	if len(r) == 40 {
		return r[:7]
	}
	return r
}

// buildApplications is the pure fold.
func buildApplications(names map[string]string, snaps map[string]map[string]fleetchecks.Snapshot) applicationsResponse {
	byKey := map[string]*application{}
	var truncated []string
	var asOf *time.Time
	add := func(key, name, matched, source string, inst appInstance) {
		a := byKey[key]
		if a == nil {
			a = &application{Key: key, Name: name, MatchedBy: matched, Source: source}
			byKey[key] = a
		}
		a.Instances = append(a.Instances, inst)
		if inst.Problem {
			a.Problems++
		}
	}
	gitopsOwned := map[string]bool{} // cluster|namespace|name of Flux HelmReleases, so their Helm release is not listed twice
	for clusterID, checks := range snaps {
		cname := names[clusterID]
		if s, ok := checks[fleetchecks.CheckGitOps]; ok && s.Summary != nil {
			var g fleetchecks.GitOpsSummary
			if json.Unmarshal(s.Summary, &g) == nil {
				if g.Truncated {
					truncated = append(truncated, cname)
				}
				for _, app := range g.Apps {
					inst := appInstance{ClusterID: clusterID, ClusterName: cname, Kind: app.Kind, Namespace: app.Namespace, Name: app.Name,
						Version: shortRev(app.Revision), Sync: app.Sync, Health: app.Health, Problem: app.Problem}
					if app.Kind == "HelmRelease" {
						gitopsOwned[clusterID+"|"+app.Namespace+"|"+app.Name] = true
					}
					switch {
					case app.App != "":
						add("app:"+app.App, app.App, "annotation", "", inst)
					case app.RepoURL != "" || app.SourceRef != "":
						src := normaliseRepo(app.RepoURL)
						if src == "" {
							src = app.SourceRef
						}
						if app.Path != "" {
							src += "//" + strings.Trim(app.Path, "/")
						} else if app.Chart != "" {
							src += "#" + app.Chart
						}
						add("src:"+src, app.Name, "source", src, inst)
					default:
						add("name:"+app.Name, app.Name, "name", "", inst)
					}
				}
			}
			if s.SummaryAt != nil && (asOf == nil || s.SummaryAt.Before(*asOf)) {
				asOf = s.SummaryAt
			}
		}
	}
	for clusterID, checks := range snaps {
		cname := names[clusterID]
		s, ok := checks[fleetchecks.CheckHelm]
		if !ok || s.Summary == nil {
			continue
		}
		var h fleetchecks.HelmSummary
		if json.Unmarshal(s.Summary, &h) != nil {
			continue
		}
		if h.Truncated {
			truncated = append(truncated, cname)
		}
		for _, r := range h.Releases {
			if gitopsOwned[clusterID+"|"+r.Namespace+"|"+r.Name] {
				continue
			}
			failing := r.Status == "failed" || r.Health == "degraded" || r.Health == "unhealthy"
			inst := appInstance{ClusterID: clusterID, ClusterName: cname, Kind: "Helm release", Namespace: r.Namespace, Name: r.Name, Health: r.Health, Problem: failing}
			if r.Revision > 0 {
				inst.Version = "rev " + strconv.Itoa(r.Revision)
			}
			if r.App != "" {
				add("app:"+r.App, r.App, "annotation", "", inst)
			} else {
				add("helm:"+r.Name, r.Name, "name", "", inst)
			}
		}
		if s.SummaryAt != nil && (asOf == nil || s.SummaryAt.Before(*asOf)) {
			asOf = s.SummaryAt
		}
	}
	out := applicationsResponse{Applications: []application{}, AsOf: asOf}
	for _, a := range byKey {
		versions := map[string]bool{}
		for _, i := range a.Instances {
			// Helm revision numbers count per cluster; only applied source
			// revisions are comparable.
			if i.Version != "" && !strings.HasPrefix(i.Version, "rev ") {
				versions[i.Version] = true
			}
		}
		a.Skew = len(versions) > 1
		sort.Slice(a.Instances, func(x, y int) bool { return a.Instances[x].ClusterName < a.Instances[y].ClusterName })
		out.Applications = append(out.Applications, *a)
	}
	sort.Slice(out.Applications, func(i, j int) bool {
		a, b := out.Applications[i], out.Applications[j]
		if (a.Problems > 0) != (b.Problems > 0) {
			return a.Problems > 0
		}
		if a.Skew != b.Skew {
			return a.Skew
		}
		if len(a.Instances) != len(b.Instances) {
			return len(a.Instances) > len(b.Instances)
		}
		return a.Name < b.Name
	})
	sort.Strings(truncated)
	out.Truncated = truncated
	return out
}

func (s *Server) handleListApplications(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	fail := func(what string, err error) {
		logger.ErrorContext(ctx, what, logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not read applications", "")
	}
	rows, err := rc.Tx.Query(ctx, `SELECT id, display_name FROM clusters WHERE archived_at IS NULL`)
	if err != nil {
		fail("listing clusters for applications failed", err)
		return
	}
	names := map[string]string{}
	var ids []string
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			rows.Close()
			fail("listing clusters for applications failed", err)
			return
		}
		names[id] = name
		ids = append(ids, id)
	}
	rows.Close()
	var readable []string
	for _, id := range ids {
		ok, err := authz.HasCapabilityForCluster(ctx, rc.Tx, rc.Grants, authz.CapClusterRead, id)
		if err != nil {
			fail("resolving cluster-scoped capability failed", err)
			return
		}
		if ok {
			readable = append(readable, id)
		}
	}
	if len(readable) == 0 {
		writeJSON(w, http.StatusOK, applicationsResponse{Applications: []application{}})
		return
	}
	// Narrowed before reading: an empty scope would mean every cluster to the
	// restrictive policy on fleet_check_snapshots.
	if err := data.SetRequestScope(ctx, rc.Tx, rc.TenantID, readable); err != nil {
		fail("narrowing the request scope for applications failed", err)
		return
	}
	snaps, err := fleetchecks.ReadAll(ctx, rc.Tx)
	if err != nil {
		fail("reading fleet snapshots for applications failed", err)
		return
	}
	writeJSON(w, http.StatusOK, buildApplications(names, snaps))
}
