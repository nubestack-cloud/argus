package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// httpMetricsProxyClient is a test-only metricsProxyClient that issues a
// REAL HTTP GET against an httptest.Server standing in for the Kubernetes API
// server's services/proxy subresource — the fake HTTP server this task's own
// verification bar asks for. It builds the request the same endpoint+params
// way restMetricsProxyClient (metrics_client.go) does against a real cluster,
// so these tests exercise that wire shape rather than only the JSON-parsing
// half. See metrics_client.go's package doc comment for why this cannot
// instead be driven through k8sfake: its RESTClient() is a nil client and
// cannot serve a proxy subresource at all.
type httpMetricsProxyClient struct {
	baseURL string
}

func (c httpMetricsProxyClient) Get(ctx context.Context, endpoint string, params map[string]string) ([]byte, error) {
	u, err := url.Parse(strings.TrimSuffix(c.baseURL, "/") + "/" + endpoint)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		// A generic, non-apierrors error — the same shape a real network or
		// non-Kubernetes-typed failure from rest.Request.DoRaw would take,
		// so sanitizeK8sErr's default branch is what actually runs in
		// production for this class of failure too.
		return nil, fmt.Errorf("prometheus proxy returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func newMetricsTestExecutor(t *testing.T, handler http.HandlerFunc) *ToolExecutor {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewToolExecutorForTestWithMetrics(nil, nil, httpMetricsProxyClient{baseURL: srv.URL})
}

func queryMetricsArgsJSON(t *testing.T, args queryMetricsArgs) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}
	return b
}

// TestQueryMetrics_RefusesWhenNotConfigured is the cluster-side default: no
// metrics.prometheusService configured, no client, and the tool says so
// cleanly — mirroring TestDryRunPatch_RefusesWhenNotConfigured's own
// discipline for its sibling tool.
func TestQueryMetrics_RefusesWhenNotConfigured(t *testing.T) {
	e := &ToolExecutor{} // metricsProxy is nil — the default, unconfigured state
	_, _, err := e.queryMetrics(context.Background(), queryMetricsArgsJSON(t, queryMetricsArgs{PromQL: "up"}))
	if err == nil {
		t.Fatal("queryMetrics succeeded with no metrics client configured")
	}
	if err != errMetricsNotConfigured {
		t.Errorf("queryMetrics error = %v, want errMetricsNotConfigured", err)
	}
}

// TestQueryMetrics_RequiresPromQL pins the empty-query rejection — refused
// before ever reaching the (configured) proxy client.
func TestQueryMetrics_RequiresPromQL(t *testing.T) {
	e := newMetricsTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("the proxy client must not be called for an empty promql")
	})
	for _, promql := range []string{"", "   "} {
		_, _, err := e.queryMetrics(context.Background(), queryMetricsArgsJSON(t, queryMetricsArgs{PromQL: promql}))
		if err == nil {
			t.Errorf("queryMetrics(%q) succeeded, want an error", promql)
		}
	}
}

// TestQueryMetrics_RefusesOverlongPromQL pins maxMetricsQueryLen.
func TestQueryMetrics_RefusesOverlongPromQL(t *testing.T) {
	e := newMetricsTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("the proxy client must not be called for an overlong promql")
	})
	_, _, err := e.queryMetrics(context.Background(), queryMetricsArgsJSON(t, queryMetricsArgs{PromQL: strings.Repeat("x", maxMetricsQueryLen+1)}))
	if err == nil {
		t.Fatal("queryMetrics succeeded with a promql past the length cap")
	}
}

// TestQueryMetrics_InstantQuery_Success drives a realistic instant-query
// round trip: the request lands on api/v1/query with the promql as the
// "query" parameter, and a two-series vector response comes back intact.
func TestQueryMetrics_InstantQuery_Success(t *testing.T) {
	var gotPath, gotQuery string
	e := newMetricsTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
			{"metric":{"__name__":"up","pod":"a"},"value":[1700000000,"1"]},
			{"metric":{"__name__":"up","pod":"b"},"value":[1700000000,"0"]}
		]}}`))
	})

	data, truncated, err := e.queryMetrics(context.Background(), queryMetricsArgsJSON(t, queryMetricsArgs{PromQL: `up{job="api"}`}))
	if err != nil {
		t.Fatalf("queryMetrics: %v", err)
	}
	if truncated {
		t.Error("truncated = true, want false")
	}
	if gotPath != "/api/v1/query" {
		t.Errorf("request path = %q, want /api/v1/query", gotPath)
	}
	if gotQuery != `up{job="api"}` {
		t.Errorf("request query param = %q, want the promql verbatim", gotQuery)
	}

	var result queryMetricsResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result.ResultType != "vector" {
		t.Errorf("ResultType = %q, want vector", result.ResultType)
	}
	if result.TotalSeries != 2 || result.Returned != 2 {
		t.Errorf("TotalSeries=%d Returned=%d, want 2 and 2", result.TotalSeries, result.Returned)
	}
	if result.Truncated {
		t.Error("Truncated = true, want false")
	}
	var series []map[string]any
	if err := json.Unmarshal(result.Result, &series); err != nil {
		t.Fatalf("Result does not parse as an array: %v", err)
	}
	if len(series) != 2 {
		t.Errorf("got %d series in Result, want 2", len(series))
	}
}

// TestQueryMetrics_RangeQuery_Success pins the range-query path: start+end+step
// all supplied together routes to api/v1/query_range with all three passed
// through, and a matrix result comes back intact.
func TestQueryMetrics_RangeQuery_Success(t *testing.T) {
	var gotPath string
	var gotParams url.Values
	e := newMetricsTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotParams = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[
			{"metric":{"__name__":"up"},"values":[[1700000000,"1"],[1700000030,"1"]]}
		]}}`))
	})

	data, truncated, err := e.queryMetrics(context.Background(), queryMetricsArgsJSON(t, queryMetricsArgs{
		PromQL: "up", Start: "2026-08-30T00:00:00Z", End: "2026-08-30T01:00:00Z", Step: "30s",
	}))
	if err != nil {
		t.Fatalf("queryMetrics: %v", err)
	}
	if truncated {
		t.Error("truncated = true, want false")
	}
	if gotPath != "/api/v1/query_range" {
		t.Errorf("request path = %q, want /api/v1/query_range", gotPath)
	}
	if gotParams.Get("start") != "2026-08-30T00:00:00Z" || gotParams.Get("end") != "2026-08-30T01:00:00Z" || gotParams.Get("step") != "30s" {
		t.Errorf("range params = %+v, want start/end/step passed through verbatim", gotParams)
	}

	var result queryMetricsResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result.ResultType != "matrix" {
		t.Errorf("ResultType = %q, want matrix", result.ResultType)
	}
	if result.TotalSeries != 1 || result.Returned != 1 {
		t.Errorf("TotalSeries=%d Returned=%d, want 1 and 1", result.TotalSeries, result.Returned)
	}
}

// TestQueryMetrics_RefusesPartialRangeArgs pins that start/end/step must
// arrive together — a partial trio is refused rather than silently treated
// as an instant query the caller did not ask for.
func TestQueryMetrics_RefusesPartialRangeArgs(t *testing.T) {
	e := newMetricsTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("the proxy client must not be called for a partial start/end/step trio")
	})
	cases := []queryMetricsArgs{
		{PromQL: "up", Start: "2026-08-30T00:00:00Z"},
		{PromQL: "up", Start: "2026-08-30T00:00:00Z", End: "2026-08-30T01:00:00Z"},
		{PromQL: "up", Step: "30s"},
	}
	for _, args := range cases {
		if _, _, err := e.queryMetrics(context.Background(), queryMetricsArgsJSON(t, args)); err == nil {
			t.Errorf("queryMetrics(%+v) succeeded, want an error requiring all three of start/end/step together", args)
		}
	}
}

// TestQueryMetrics_EmptyResult pins the empty-but-successful case: zero series
// is a real, valid answer ("nothing matched"), not an error.
func TestQueryMetrics_EmptyResult(t *testing.T) {
	e := newMetricsTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	})
	data, truncated, err := e.queryMetrics(context.Background(), queryMetricsArgsJSON(t, queryMetricsArgs{PromQL: "up{pod=\"ghost\"}"}))
	if err != nil {
		t.Fatalf("queryMetrics: %v", err)
	}
	if truncated {
		t.Error("truncated = true, want false")
	}
	var result queryMetricsResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result.TotalSeries != 0 || result.Returned != 0 {
		t.Errorf("TotalSeries=%d Returned=%d, want 0 and 0 for an empty match", result.TotalSeries, result.Returned)
	}
}

// TestQueryMetrics_ScalarResultNotMiscountedAsTwoSeries pins the fix for the
// shape ambiguity Prometheus's own API has: a scalar result's Data.Result is
// itself a bare [timestamp, value] JSON array, which would parse as "2
// series" if this tool naively tried the vector/matrix array shape first.
// Branching on resultType (query_metrics.go) is what keeps this from
// misreporting a single scalar as two.
func TestQueryMetrics_ScalarResultNotMiscountedAsTwoSeries(t *testing.T) {
	e := newMetricsTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"scalar","result":[1700000000,"42"]}}`))
	})
	data, _, err := e.queryMetrics(context.Background(), queryMetricsArgsJSON(t, queryMetricsArgs{PromQL: "1+1"}))
	if err != nil {
		t.Fatalf("queryMetrics: %v", err)
	}
	var result queryMetricsResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result.ResultType != "scalar" {
		t.Errorf("ResultType = %q, want scalar", result.ResultType)
	}
	if result.TotalSeries != 1 || result.Returned != 1 {
		t.Errorf("TotalSeries=%d Returned=%d, want 1 and 1 for a scalar result — it must never be miscounted as 2 series", result.TotalSeries, result.Returned)
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(result.Result, &raw); err != nil || len(raw) != 2 {
		t.Errorf("Result = %s, want the original [timestamp, value] pair preserved verbatim", result.Result)
	}
}

// TestQueryMetrics_Truncation pins the list_resources-style
// totalMatched/returned/truncated contract this tool's own doc comment
// claims: a result past maxMetricsSeriesResults is capped, never silently
// dropped without saying so.
func TestQueryMetrics_Truncation(t *testing.T) {
	n := maxMetricsSeriesResults + 37
	e := newMetricsTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		var b strings.Builder
		b.WriteString(`{"status":"success","data":{"resultType":"vector","result":[`)
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `{"metric":{"__name__":"up","i":"%d"},"value":[1700000000,"1"]}`, i)
		}
		b.WriteString(`]}}`)
		_, _ = w.Write([]byte(b.String()))
	})

	data, truncated, err := e.queryMetrics(context.Background(), queryMetricsArgsJSON(t, queryMetricsArgs{PromQL: "up"}))
	if err != nil {
		t.Fatalf("queryMetrics: %v", err)
	}
	if !truncated {
		t.Error("truncated = false, want true — the result had more series than the cap")
	}
	var result queryMetricsResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result.TotalSeries != n {
		t.Errorf("TotalSeries = %d, want %d (the true count, even though only some were returned)", result.TotalSeries, n)
	}
	if result.Returned != maxMetricsSeriesResults {
		t.Errorf("Returned = %d, want %d (the cap)", result.Returned, maxMetricsSeriesResults)
	}
	if !result.Truncated {
		t.Error("queryMetricsResult.Truncated = false, want true")
	}
	var series []json.RawMessage
	if err := json.Unmarshal(result.Result, &series); err != nil {
		t.Fatalf("Result does not parse as an array: %v", err)
	}
	if len(series) != maxMetricsSeriesResults {
		t.Errorf("Result carries %d series, want exactly %d", len(series), maxMetricsSeriesResults)
	}
}

// TestQueryMetrics_PrometheusErrorStatus pins the status=="error" path:
// Prometheus itself understood and rejected the query (a syntax error, an
// unknown function), and that reason should reach the caller rather than a
// generic failure.
func TestQueryMetrics_PrometheusErrorStatus(t *testing.T) {
	e := newMetricsTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		// Prometheus itself often answers a bad query with HTTP 400 and a
		// JSON error body — exercised here as the more common real shape,
		// distinct from the malformed-JSON case below.
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"status":"error","errorType":"bad_data","error":"parse error: unexpected character"}`))
	})
	_, _, err := e.queryMetrics(context.Background(), queryMetricsArgsJSON(t, queryMetricsArgs{PromQL: "up("}))
	if err == nil {
		t.Fatal("queryMetrics succeeded against a Prometheus error response")
	}
}

// TestQueryMetrics_PrometheusErrorStatusOn200 pins the same error path when
// Prometheus answers with HTTP 200 but status:"error" in the body — some
// Prometheus-compatible backends do this, and this tool must not treat a 200
// as automatically successful.
func TestQueryMetrics_PrometheusErrorStatusOn200(t *testing.T) {
	e := newMetricsTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"error","errorType":"execution","error":"query timed out"}`))
	})
	_, _, err := e.queryMetrics(context.Background(), queryMetricsArgsJSON(t, queryMetricsArgs{PromQL: "up"}))
	if err == nil {
		t.Fatal("queryMetrics succeeded against a status:\"error\" response")
	}
	if !strings.Contains(err.Error(), "query timed out") {
		t.Errorf("error = %v, want it to surface prometheus's own error message", err)
	}
}

// TestQueryMetrics_MalformedResponse pins the not-even-JSON case — this tool
// must fail cleanly rather than panic or forward garbage.
func TestQueryMetrics_MalformedResponse(t *testing.T) {
	e := newMetricsTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json at all`))
	})
	_, _, err := e.queryMetrics(context.Background(), queryMetricsArgsJSON(t, queryMetricsArgs{PromQL: "up"}))
	if err == nil {
		t.Fatal("queryMetrics succeeded against a non-JSON response")
	}
}

// TestQueryMetrics_ProxyHTTPFailureIsSanitized pins that a raw proxy-layer
// failure (a non-2xx from the API server's own proxy — Service unreachable,
// RBAC denied changing mid-flight, etc.) is passed through sanitizeK8sErr the
// same way every other tool's Kubernetes API error is, rather than leaking
// whatever text the underlying transport produced.
func TestQueryMetrics_ProxyHTTPFailureIsSanitized(t *testing.T) {
	e := newMetricsTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("dial tcp 10.0.0.55:9090: connection refused, tls certificate for CN=super-secret-internal-host"))
	})
	_, _, err := e.queryMetrics(context.Background(), queryMetricsArgsJSON(t, queryMetricsArgs{PromQL: "up"}))
	if err == nil {
		t.Fatal("queryMetrics succeeded against a proxy-layer HTTP failure")
	}
	if strings.Contains(err.Error(), "super-secret-internal-host") || strings.Contains(err.Error(), "10.0.0.55") {
		t.Errorf("error = %v, leaked raw transport detail — sanitizeK8sErr should have reduced this to a generic message", err)
	}
}
