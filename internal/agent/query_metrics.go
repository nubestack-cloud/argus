package agent

// query_metrics is BACKLOG.md C4's query_metrics half: an INVESTIGATION-time
// tool that runs a PromQL query against a Prometheus this cluster's operator
// has pointed ARGUS at, and returns the (bounded) result. Unblocked
// 2026-08-30 — this tool used to be listed as blocked on "needs a registered
// Prometheus integration"; deploy/helm/argus-agent/values.yaml's
// metrics.prometheusService is that integration, and metrics_client.go is the
// plumbing.
//
// This is deliberately read-only, and simpler than dry_run_patch in every way
// that matters: it never writes anything, so it needs no second identity, no
// ValidatingAdmissionPolicy, and no agent-side signature check — the ordinary
// "one more read-only tool" shape every other function in tools.go already
// follows. What makes it different from those is only WHERE the read goes:
// through the Kubernetes API server's services/proxy subresource to whatever
// Prometheus values.yaml's metrics.prometheusService names, rather than to
// the API server's own object store. See metrics_client.go's package doc
// comment for the full reasoning on why that call is abstracted behind
// metricsProxyClient instead of using e.typed directly.
//
// Not assumed to be Prometheus specifically by anything downstream of the
// HTTP call itself — this tool speaks Prometheus's HTTP query API
// (/api/v1/query, /api/v1/query_range) because that is what
// metrics.prometheusService points at today, but nothing here hardcodes a
// namespace or service name: those are supplied entirely by the chart value
// an operator sets for THEIR cluster (deploy/helm/argus-agent/values.yaml's
// header comment on metrics.prometheusService explains why a fixed default
// would be wrong — Rancher's rancher-monitoring-prometheus is one
// installation's convention, not a rule).
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	// maxMetricsQueryLen bounds the promql argument itself — a string this
	// long is almost certainly a mistake (or an attempt to smuggle something
	// unrelated through a text field), not a legitimate query; PromQL queries
	// naming several metrics with label matchers still comfortably fit in a
	// small fraction of this.
	maxMetricsQueryLen = 4096

	// maxMetricsRawResponseBytes is a sanity cap on the raw proxied response,
	// checked BEFORE this tool ever unmarshals it — the same "bound before you
	// parse" discipline getLogs' scanner buffer and list_resources' server-side
	// limit already apply, here guarding against a misbehaving or
	// unexpectedly large Prometheus instance rather than a well-formed but
	// long list_resources-style result (that case is handled by
	// maxMetricsSeriesResults below, after parsing).
	maxMetricsRawResponseBytes = 4 * 1024 * 1024

	// maxMetricsSeriesResults bounds how many series/samples this tool ever
	// returns to the model in one call — the same list_resources
	// totalMatched/returned/truncated contract (tools.go's own comment on
	// defaultListLimit/maxListLimit), applied here to a PromQL result set
	// instead of a Kubernetes List: a tool result is one message on the wire,
	// spent out of the investigation's shared context budget, so "fetch
	// everything, bound nothing" is exactly as wrong here as it is there.
	maxMetricsSeriesResults = 100
)

// queryMetricsArgs is this tool's argument shape. A range query (query_range)
// is issued when Start/End/Step are ALL supplied; otherwise this is an
// instant query (query) — lld/07-analysis-contracts.md §2's `{promql, range}`
// row, expressed as three named fields instead of one nested "range" object
// so a caller building this from scratch has an unambiguous, self-describing
// shape rather than needing to know a sentinel for "no range".
type queryMetricsArgs struct {
	PromQL string `json:"promql"`
	// Start/End are RFC3339 timestamps; Step is a Prometheus duration string
	// (e.g. "30s", "1m", "1h"). All three or none — a partial trio is refused
	// rather than silently falling back to an instant query the caller did
	// not ask for.
	Start string `json:"start,omitempty"`
	End   string `json:"end,omitempty"`
	Step  string `json:"step,omitempty"`
}

// prometheusQueryResponse is Prometheus's own HTTP API response envelope
// (https://prometheus.io/docs/prometheus/latest/querying/api/#format-overview),
// transcribed only as far as this tool needs: status, the resultType/result
// pair, and the two error fields Prometheus sets on status=="error".
type prometheusQueryResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string          `json:"resultType"`
		Result     json.RawMessage `json:"result"`
	} `json:"data"`
	ErrorType string `json:"errorType,omitempty"`
	Error     string `json:"error,omitempty"`
}

// queryMetricsResult is this tool's successful result. TotalSeries/Returned/
// Truncated mirror listResourcesResult's own contract (tools.go) so a model
// that has already learned that shape from list_resources reads this one the
// same way — deliberate, not incidental, per BACKLOG.md C1's own reasoning
// for why truncation must never be silent.
type queryMetricsResult struct {
	// ResultType is Prometheus's own "vector" | "matrix" | "scalar" | "string"
	// — passed through verbatim so the model can tell a range query's matrix
	// result from an instant query's vector result without guessing.
	ResultType string `json:"resultType"`
	// Result is Prometheus's own result array (or scalar/string value),
	// bounded per maxMetricsSeriesResults when it is an array.
	Result      json.RawMessage `json:"result"`
	TotalSeries int             `json:"totalSeries"`
	Returned    int             `json:"returned"`
	Truncated   bool            `json:"truncated"`
}

// errMetricsNotConfigured is returned by ToolExecutor.queryMetrics when this
// cluster never configured a Prometheus location — the ordinary state for
// any cluster that has not opted into BACKLOG.md C4's query_metrics half. The
// same message shape gatherClusterMetricsAuthority's Checked=false conveys to
// the hub, surfaced directly to whichever caller reached the tool anyway —
// defence in depth, per argus-context's non-negotiable 3: internal/llm is not
// supposed to ever offer this tool here, but a compromised or buggy caller
// must still be refused server-side.
var errMetricsNotConfigured = errors.New("this cluster has not configured a Prometheus location (deploy/helm/argus-agent values.yaml's metrics.prometheusService) — query_metrics is unavailable here")

// queryMetrics is the tool entry point.
func (e *ToolExecutor) queryMetrics(ctx context.Context, rawArgs json.RawMessage) (json.RawMessage, bool, error) {
	if e.metricsProxy == nil {
		return nil, false, errMetricsNotConfigured
	}

	var args queryMetricsArgs
	if err := json.Unmarshal(rawArgs, &args); err != nil {
		return nil, false, fmt.Errorf("invalid args: %w", err)
	}
	args.PromQL = strings.TrimSpace(args.PromQL)
	if args.PromQL == "" {
		return nil, false, errors.New("promql is required")
	}
	if len(args.PromQL) > maxMetricsQueryLen {
		return nil, false, fmt.Errorf("promql is %d characters, past the %d cap", len(args.PromQL), maxMetricsQueryLen)
	}

	endpoint := "api/v1/query"
	params := map[string]string{"query": args.PromQL}
	switch {
	case args.Start == "" && args.End == "" && args.Step == "":
		// Instant query — nothing else to add.
	case args.Start != "" && args.End != "" && args.Step != "":
		endpoint = "api/v1/query_range"
		params["start"] = args.Start
		params["end"] = args.End
		params["step"] = args.Step
	default:
		return nil, false, errors.New("a range query requires start, end, and step together — omit all three for an instant query instead")
	}

	raw, err := e.metricsProxy.Get(ctx, endpoint, params)
	if err != nil {
		return nil, false, sanitizeK8sErr(err)
	}
	if len(raw) > maxMetricsRawResponseBytes {
		return nil, false, fmt.Errorf("prometheus's response is %d bytes, past the %d cap", len(raw), maxMetricsRawResponseBytes)
	}

	var resp prometheusQueryResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, false, errors.New("prometheus returned a response this tool could not parse")
	}
	if resp.Status != "success" {
		msg := resp.Error
		if msg == "" {
			msg = "prometheus reported an error with no message"
		}
		return nil, false, fmt.Errorf("prometheus query failed: %s", msg)
	}

	// Data.Result is an array for vector/matrix results (one entry per
	// series) and a bare [timestamp, value] pair for scalar, or a bare
	// [timestamp, string] pair for string — Prometheus's own format-overview
	// doc names all four resultTypes. Branched on ResultType rather than on
	// whether Result happens to unmarshal as an array: a scalar's own
	// [timestamp, value] pair IS a JSON array, so trying the array shape
	// first and falling back on a parse error would silently miscount it as
	// "2 series" instead of one scalar. Only the vector/matrix shape is ever
	// bounded; a scalar/string result is exactly one value by definition, so
	// there is nothing to truncate.
	if resp.Data.ResultType != "vector" && resp.Data.ResultType != "matrix" {
		return mustMarshal(queryMetricsResult{
			ResultType:  resp.Data.ResultType,
			Result:      resp.Data.Result,
			TotalSeries: 1,
			Returned:    1,
			Truncated:   false,
		}), false, nil
	}

	var series []json.RawMessage
	if err := json.Unmarshal(resp.Data.Result, &series); err != nil {
		return nil, false, fmt.Errorf("prometheus result did not parse as the expected %q shape", resp.Data.ResultType)
	}

	total := len(series)
	truncated := false
	if total > maxMetricsSeriesResults {
		series = series[:maxMetricsSeriesResults]
		truncated = true
	}
	bounded, err := json.Marshal(series)
	if err != nil {
		return nil, false, fmt.Errorf("marshal bounded result: %w", err)
	}

	return mustMarshal(queryMetricsResult{
		ResultType:  resp.Data.ResultType,
		Result:      bounded,
		TotalSeries: total,
		Returned:    len(series),
		Truncated:   truncated,
	}), truncated, nil
}
