package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/logging"
)

// GET /api/v1/incidents/{id}/metrics?range=1h|6h|24h
// (docs/CLUSTER_INSIGHT_SPECS.md CI-S8): CPU, memory, restarts and CPU
// throttling for the incident's workload around the incident, through the
// agent's query_metrics tool. The workload is read from the incident row,
// never from the request. Pods are matched by the workload's own naming
// pattern, so replicas replaced during the window are included; the response
// says so (scope) rather than implying an owner join it did not do.

var metricRanges = map[string]struct {
	window time.Duration
	step   string
}{
	"1h":  {time.Hour, "30s"},
	"6h":  {6 * time.Hour, "2m"},
	"24h": {24 * time.Hour, "10m"},
}

type metricSeries struct {
	Labels map[string]string `json:"labels"`
	Points [][2]float64      `json:"points"` // [unix seconds, value]
}

type metricPanel struct {
	ID     string         `json:"id"`
	Title  string         `json:"title"`
	Unit   string         `json:"unit"`
	Series []metricSeries `json:"series"`
	Error  string         `json:"error,omitempty"`
	// Note explains an empty answer whose cause is known, so it is not read
	// as "no problem".
	Note string `json:"note,omitempty"`
}

type incidentMetricsResponse struct {
	Available  bool          `json:"available"`
	Reason     string        `json:"reason,omitempty"`
	Workload   string        `json:"workload,omitempty"`
	Scope      string        `json:"scope,omitempty"`
	Start      time.Time     `json:"start"`
	End        time.Time     `json:"end"`
	Step       string        `json:"step"`
	OpenedAt   time.Time     `json:"openedAt"`
	Panels     []metricPanel `json:"panels"`
	ReceivedAt time.Time     `json:"receivedAt"`
}

var dns1123 = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)

func (s *Server) handleIncidentMetrics(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	incidentID := r.PathValue("id")
	rng, ok := metricRanges[r.URL.Query().Get("range")]
	if !ok {
		rng = metricRanges["6h"]
	}
	var clusterID string
	var objectKey, workloadKey *string
	var firstSeen time.Time
	err := rc.Tx.QueryRow(ctx, `SELECT cluster_id, object_key, workload_key, first_seen FROM incidents WHERE id = $1`, incidentID).
		Scan(&clusterID, &objectKey, &workloadKey, &firstSeen)
	if err != nil {
		writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Incident not found", "")
		return
	}
	// The metrics gate reads cluster_facts, whose policy admits only the
	// clusters named in the request scope. Narrow to the incident's own
	// cluster: the caller could already see this incident, so this never
	// widens what they can read.
	if err := data.SetRequestScope(ctx, rc.Tx, rc.TenantID, []string{clusterID}); err != nil {
		logger.ErrorContext(ctx, "narrowing the request scope to the incident's cluster failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not scope request", "")
		return
	}
	end := time.Now().UTC()
	if t := firstSeen.Add(rng.window / 2); t.Before(end) {
		end = t
	}
	start := end.Add(-rng.window)
	resp := incidentMetricsResponse{Start: start, End: end, Step: rng.step, OpenedAt: firstSeen, Panels: []metricPanel{}, ReceivedAt: time.Now().UTC()}

	ref, ok := objectRefFromKey(workloadKey)
	if !ok {
		ref, ok = objectRefFromKey(objectKey)
	}
	var kind, namespace, name string
	if ok {
		kind, namespace, name = ref.Kind, ref.Namespace, ref.Name
	}
	m := s.workloadMetrics(ctx, rc, clusterID, kind, namespace, name, start, end, rng.step)
	if m.Reason == reasonNotAWorkload {
		m.Reason = "this incident is not about a workload or pod, so there is nothing to chart"
	}
	resp.Available, resp.Reason, resp.Workload, resp.Scope, resp.Panels = m.Available, m.Reason, m.Workload, m.Scope, m.Panels
	resp.ReceivedAt = m.ReceivedAt
	writeJSON(w, http.StatusOK, resp)
}

// workloadMetricsResponse is one workload's resource usage over a window,
// shared by the incident view and the object panel (PROJECT.md AD7). The
// incident response adds the moment it opened; this one is the rest.
type workloadMetricsResponse struct {
	Available  bool          `json:"available"`
	Reason     string        `json:"reason,omitempty"`
	Workload   string        `json:"workload,omitempty"`
	Scope      string        `json:"scope,omitempty"`
	Start      time.Time     `json:"start"`
	End        time.Time     `json:"end"`
	Step       string        `json:"step"`
	Panels     []metricPanel `json:"panels"`
	ReceivedAt time.Time     `json:"receivedAt"`
}

const reasonNotAWorkload = "this object is not a workload or pod, so there is nothing to chart"

// podPatternFor is the regular expression matching the pods a workload runs,
// by the controllers' own naming. Empty when the kind owns no pods or a name
// is not a DNS-1123 name (it is spliced into PromQL, where =~ is anchored).
//
// Generated suffixes are written in Kubernetes' safe-encoding alphabet
// (k8s.io/apimachinery/pkg/util/rand: no vowels, no 0, 1 or 3), the random
// one always five characters and a pod-template hash at most ten. Matching
// that alphabet rather than [a-z0-9] keeps a sibling with a longer name out:
// Deployment "argus-hub" must not chart StatefulSet "argus-hub-postgres"'s
// pod "argus-hub-postgres-0", which a looser pattern did.
func podPatternFor(kind, namespace, name string) string {
	if !dns1123.MatchString(name) || !dns1123.MatchString(namespace) {
		return ""
	}
	const safe = "[bcdfghjklmnpqrstvwxz2456789]"
	q := regexp.QuoteMeta(name)
	switch kind {
	case "Deployment":
		return q + "-" + safe + "{1,10}-" + safe + "{5}"
	case "StatefulSet":
		return q + "-[0-9]+"
	case "DaemonSet", "ReplicaSet", "Job":
		return q + "-" + safe + "{5}"
	case "Pod":
		return q
	}
	return ""
}

// workloadMetrics reads CPU, memory, restarts and CPU throttling for one
// workload's pods through the agent's query_metrics tool. It never returns an
// empty chart that reads as zero: no Prometheus, a disconnected agent or a
// kind with no pods each come back as Available false with the reason.
func (s *Server) workloadMetrics(ctx context.Context, rc *requestContext, clusterID, kind, namespace, name string, start, end time.Time, step string) workloadMetricsResponse {
	resp := workloadMetricsResponse{Start: start, End: end, Step: step, Panels: []metricPanel{}, ReceivedAt: time.Now().UTC()}
	podPattern := podPatternFor(kind, namespace, name)
	if podPattern == "" {
		resp.Reason = reasonNotAWorkload
		return resp
	}
	resp.Workload = kind + " " + namespace + "/" + name
	resp.Scope = "pods matched by the workload's naming pattern, including replicas replaced during the window"
	if kind == "Pod" {
		resp.Scope = "this pod's containers"
	}
	if !ClusterMetricsAvailable(ctx, rc.Tx, clusterID) {
		resp.Reason = "no Prometheus is configured for this cluster's agent (metrics.prometheusService on the agent chart)"
		return resp
	}
	if !s.gw.IsConnected(clusterID) {
		resp.Reason = "the cluster's agent is not connected"
		return resp
	}
	sel := fmt.Sprintf(`namespace="%s",pod=~"%s"`, namespace, podPattern)
	queries := []struct{ id, title, unit, q string }{
		{"cpu", "CPU usage", "cores", `sum by (pod) (rate(container_cpu_usage_seconds_total{container!="",container!="POD",` + sel + `}[5m]))`},
		{"memory", "Memory working set", "bytes", `sum by (pod) (max by (pod, container) (container_memory_working_set_bytes{container!="",container!="POD",` + sel + `}))`},
		{"restarts", "Container restarts", "count", `sum by (pod) (kube_pod_container_status_restarts_total{` + sel + `})`},
		{"throttling", "CPU throttling", "percent", `100 * sum by (pod) (rate(container_cpu_cfs_throttled_periods_total{container!="",` + sel + `}[5m])) / clamp_min(sum by (pod) (rate(container_cpu_cfs_periods_total{container!="",` + sel + `}[5m])), 1)`},
	}
	panels := make([]metricPanel, len(queries))
	var wg sync.WaitGroup
	for i, q := range queries {
		wg.Add(1)
		go func(i int, id, title, unit, promql string) {
			defer wg.Done()
			p := metricPanel{ID: id, Title: title, Unit: unit, Series: []metricSeries{}}
			args, _ := json.Marshal(map[string]string{"promql": promql, "start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339), "step": step})
			cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			raw, err := s.gw.CallTool(cctx, clusterID, "query_metrics", args)
			if err != nil {
				logger.WarnContext(ctx, "workload metrics query failed", logging.ClusterID(clusterID), logging.Err(err))
				p.Error = "the query failed or the metric is not exported by this cluster's Prometheus"
			} else {
				p.Series = parseMatrix(raw)
				if len(p.Series) == 0 && id == "throttling" {
					p.Note = "CPU throttling is recorded only for containers with a CPU limit; none of these pods' containers reported one in this window"
				}
			}
			panels[i] = p
		}(i, q.id, q.title, q.unit, q.q)
	}
	wg.Wait()
	resp.Panels = append(panels, s.redPanels(ctx, clusterID, kind, namespace, name, start, end, step)...)
	resp.Available = true
	resp.ReceivedAt = time.Now().UTC()
	return resp
}

// GET /api/v1/clusters/{id}/workload-metrics?kind=&namespace=&name=&range=
// (PROJECT.md AD7): the object panel's Metrics tab. The window ends now.
// cluster:inspect is checked on THIS cluster before the request scope is
// narrowed to it (authorizeClusterScoped), the same as every inspect route.
func (s *Server) handleWorkloadMetrics(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	clusterID := r.PathValue("id")
	q := r.URL.Query()
	kind, namespace, name := q.Get("kind"), q.Get("namespace"), q.Get("name")
	if kind == "" || namespace == "" || name == "" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/validation", "kind, namespace and name are required", "")
		return
	}
	if podPatternFor(kind, namespace, name) == "" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/validation", "Not a chartable object",
			"kind must be Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet or Job, and namespace and name must be DNS-1123 names")
		return
	}
	rng, ok := metricRanges[q.Get("range")]
	if !ok {
		rng = metricRanges["6h"]
	}
	if !s.authorizeClusterScoped(w, r, rc, authz.CapClusterInspect, clusterID) {
		return
	}
	var one int
	if err := rc.Tx.QueryRow(ctx, `SELECT 1 FROM clusters WHERE id = $1`, clusterID).Scan(&one); err != nil {
		writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Cluster not found", "")
		return
	}
	end := time.Now().UTC()
	writeJSON(w, http.StatusOK, s.workloadMetrics(ctx, rc, clusterID, kind, namespace, name, end.Add(-rng.window), end, rng.step))
}

// parseMatrix reads query_metrics' result: {"resultType":"matrix",
// "result":[{"metric":{...},"values":[[ts,"v"],...]}]}.
func parseMatrix(raw json.RawMessage) []metricSeries {
	var env struct {
		Result []struct {
			Metric map[string]string `json:"metric"`
			Values [][2]any          `json:"values"`
		} `json:"result"`
	}
	out := []metricSeries{}
	if err := json.Unmarshal(raw, &env); err != nil {
		return out
	}
	for _, r := range env.Result {
		ser := metricSeries{Labels: r.Metric, Points: [][2]float64{}}
		for _, v := range r.Values {
			ts, _ := v[0].(float64)
			s, _ := v[1].(string)
			f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
			if err != nil {
				continue
			}
			ser.Points = append(ser.Points, [2]float64{ts, f})
		}
		out = append(out, ser)
		if len(out) >= 50 {
			break
		}
	}
	return out
}

// errorRatio is the percentage of requests that failed with a 5xx. A workload
// that served requests and no 5xx has no 5xx series at all, so the failed
// rate falls back to the total times zero: 0% where there was traffic, and
// still no value where there was none.
func errorRatio(failed, total string) string {
	return `100 * (sum(rate(` + failed + `[5m])) or sum(rate(` + total + `[5m])) * 0) / clamp_min(sum(rate(` + total + `[5m])), 1e-9)`
}

// redPanels are request rate, error ratio and p95 latency for a workload
// (PROJECT.md PG21), from whichever request telemetry the cluster's
// Prometheus holds: Istio's sidecar metrics first, then Beyla's HTTP server
// metrics. With neither, one panel says so — an absent series is never drawn
// as zero traffic.
func (s *Server) redPanels(ctx context.Context, clusterID, kind, namespace, name string, start, end time.Time, step string) []metricPanel {
	type source struct {
		name                   string
		total, errors, latency string
	}
	var sources []source
	if kind != "Pod" {
		ist := fmt.Sprintf(`reporter="destination",destination_workload_namespace="%s",destination_workload="%s"`, namespace, name)
		sources = append(sources, source{"Istio",
			`sum(rate(istio_requests_total{` + ist + `}[5m]))`,
			errorRatio(`istio_requests_total{`+ist+`,response_code=~"5.."}`, `istio_requests_total{`+ist+`}`),
			`histogram_quantile(0.95, sum by (le) (rate(istio_request_duration_milliseconds_bucket{` + ist + `}[5m]))) / 1000`})
	}
	label := map[string]string{"Deployment": "k8s_deployment_name", "StatefulSet": "k8s_statefulset_name", "DaemonSet": "k8s_daemonset_name", "Pod": "k8s_pod_name"}[kind]
	if label != "" {
		bey := fmt.Sprintf(`k8s_namespace_name="%s",%s="%s"`, namespace, label, name)
		sources = append(sources, source{"Beyla",
			`sum(rate(http_server_request_duration_seconds_count{` + bey + `}[5m]))`,
			errorRatio(`http_server_request_duration_seconds_count{`+bey+`,http_response_status_code=~"5.."}`, `http_server_request_duration_seconds_count{`+bey+`}`),
			`histogram_quantile(0.95, sum by (le) (rate(http_server_request_duration_seconds_bucket{` + bey + `}[5m])))`})
	}
	query := func(promql string) ([]metricSeries, error) {
		args, _ := json.Marshal(map[string]string{"promql": promql, "start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339), "step": step})
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		raw, err := s.gw.CallTool(cctx, clusterID, "query_metrics", args)
		if err != nil {
			return nil, err
		}
		return parseMatrix(raw), nil
	}
	for _, src := range sources {
		total, err := query(src.total)
		if err != nil || len(total) == 0 {
			continue
		}
		note := "From " + src.name + " request metrics."
		out := []metricPanel{{ID: "requests", Title: "Request rate", Unit: "req/s", Series: total, Note: note}}
		for _, p := range []struct{ id, title, unit, q string }{
			{"errors", "5xx error ratio", "percent", src.errors},
			{"latency", "p95 latency", "seconds", src.latency},
		} {
			panel := metricPanel{ID: p.id, Title: p.title, Unit: p.unit, Series: []metricSeries{}, Note: note}
			if series, err := query(p.q); err != nil {
				panel.Error = "the query failed or the metric is not exported by this cluster's Prometheus"
			} else {
				panel.Series = series
			}
			out = append(out, panel)
		}
		return out
	}
	return []metricPanel{{ID: "requests", Title: "Requests, errors and latency", Unit: "req/s", Series: []metricSeries{},
		Note: "No Istio or Beyla request metrics for this workload in this window, so request rate, errors and latency cannot be drawn."}}
}
