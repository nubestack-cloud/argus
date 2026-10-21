package traffic

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
)

// DefaultWindow is used when the caller asks for less than a minute.
// Prometheus needs two samples inside a rate window, and with a common 15s
// scrape interval a sub-minute window is a coin toss.
const DefaultWindow = 5 * time.Minute

// MaxWindow bounds the rate window. Longer windows make Prometheus read more
// samples per series and the tool budget is 12 s end to end.
const MaxWindow = time.Hour

// Detection is the outcome of probing Prometheus for a traffic source.
type Detection struct {
	Source string
	// ReasonCode is ReasonUnreachable or ReasonNoSource when no source was
	// found; empty when one was.
	ReasonCode string
	// Reason explains why no source was found, in a plain sentence. Empty
	// when one was.
	Reason string
}

// Detect probes Prometheus for metric presence and returns the first source
// that has data, in order: Istio (L7 per caller), then Beyla, then OBI.
func Detect(ctx context.Context, q PromQuerier) (source string, ok bool) {
	d := Probe(ctx, q)
	return d.Source, d.Source != ""
}

// Probe is Detect with the reason no source was found, so a caller can tell
// "Prometheus could not be queried" from "no supported source is exporting".
func Probe(ctx context.Context, q PromQuerier) Detection {
	probes := []struct {
		source string
		query  string
	}{
		{SourceIstio, `count(istio_requests_total{reporter="destination"})`},
		{SourceIstio, `count(istio_tcp_connections_opened_total{reporter="destination"})`},
		// Probed one prefix at a time, never as a regex union: a cluster part-way
		// through moving from Beyla to OBI runs both, and summing them would double
		// every edge.
		{SourceBeyla, fmt.Sprintf(`count(%s{%s})`, beylaFlowMetric, BeylaJobSelector)},
		{SourceOBI, fmt.Sprintf(`count(%s{%s})`, obiFlowMetric, BeylaJobSelector)},
	}
	var failures int
	for _, p := range probes {
		samples, err := q.Query(ctx, p.query)
		if err != nil {
			failures++
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if len(samples) > 0 && usableSample(samples[0].Value) {
			return Detection{Source: p.source}
		}
	}
	// Every probe failing means Prometheus was not usefully answering at
	// all, whether the transport failed or it rejected every query; the
	// error text itself stays out of the reason, which is read by people.
	// Hubble last: it needs its workload labels to draw anything at all.
	found, labelled, hubErr := probeHubble(ctx, q)
	if hubErr == nil && found && labelled {
		return Detection{Source: SourceHubble}
	}
	if hubErr == nil && found {
		return Detection{ReasonCode: ReasonNoSource, Reason: HubbleContextHint}
	}
	if failures == len(probes) || ctx.Err() != nil {
		return Detection{ReasonCode: ReasonUnreachable, Reason: ReasonTextUnreachable}
	}
	if failures > 0 {
		return Detection{ReasonCode: ReasonNoSource, Reason: "No Istio or Beyla traffic metrics were found in Prometheus, but some probes failed, so a source may have been missed."}
	}
	return Detection{ReasonCode: ReasonNoSource, Reason: "No Istio (istio_requests_total, istio_tcp_connections_opened_total), Beyla (beyla_/obi_network_flow_bytes_total) or Hubble (hubble_flows_processed_total) traffic metrics were found in Prometheus."}
}

// ErrUnknownSource is returned by Flows for a source name it does not know.
var ErrUnknownSource = errors.New("unknown traffic source")

// Flows reads the traffic map from the named source. namespace, when set,
// keeps edges with either end in that namespace. window is clamped to
// [1m, MaxWindow]; anything under a minute becomes DefaultWindow.
//
// An error means the primary query failed and there is no map to show; the
// caller reports it as Unavailable. Failed enrichment queries do not error —
// they are named in Result.Missing and their figures stay nil.
func Flows(ctx context.Context, q PromQuerier, source, namespace string, window time.Duration, opts ...Option) (*Result, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	if namespace != "" {
		if errs := validation.IsDNS1123Label(namespace); len(errs) > 0 {
			return nil, fmt.Errorf("invalid namespace %q: %s", namespace, strings.Join(errs, "; "))
		}
	}
	w := rateWindowFor(window)
	res := &Result{Available: true, Source: source, WindowSeconds: int(w.seconds)}
	edges, err := collect(ctx, q, source, namespace, w, res, o.resolve)
	if err != nil {
		return nil, err
	}
	if o.compareTo > 0 {
		before := w
		before.offset = fmt.Sprintf(" offset %ds", int(o.compareTo/time.Second))
		res.ComparisonSeconds = int(o.compareTo / time.Second)
		prev, perr := collect(ctx, q, source, namespace, before, &Result{}, o.resolve)
		switch {
		case perr != nil:
			res.ComparisonReason = "The earlier window could not be read from Prometheus."
		case len(prev) == 0:
			res.ComparisonReason = "No traffic was recorded then; the traffic source may be newer than that, or Prometheus keeps less history."
		default:
			res.ComparisonAvailable = true
			edges = joinBefore(edges, prev)
		}
	}
	res.TotalEdges = len(edges)
	res.Edges, res.Truncated = capEdges(edges, MaxEdges)
	return res, nil
}

// collect reads one window's flows from a source, folded and merged.
func collect(ctx context.Context, q PromQuerier, source, namespace string, w rateWindow, res *Result, resolve EndpointResolver) ([]Edge, error) {
	var (
		flows []Edge
		err   error
	)
	switch source {
	case SourceIstio:
		flows, err = istioFlows(ctx, q, namespace, w, res)
	case SourceBeyla:
		flows, err = beylaFlows(ctx, q, beylaFlowMetric, namespace, w, res)
	case SourceOBI:
		flows, err = beylaFlows(ctx, q, obiFlowMetric, namespace, w, res)
	case SourceHubble:
		flows, err = hubbleFlows(ctx, q, namespace, w)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownSource, source)
	}
	if err != nil {
		return nil, err
	}
	return AggregateFlows(foldEndpoints(flows, resolve)), nil
}

// joinBefore attaches each earlier edge's figures to the matching current
// edge, and adds an edge seen only earlier as Stopped, with no current
// figures — absent, not zero, because nothing was measured for it now.
func joinBefore(now, before []Edge) []Edge {
	prev := make(map[string]Edge, len(before))
	for _, e := range before {
		prev[edgeKey(e)] = e
	}
	seen := make(map[string]bool, len(now))
	for i := range now {
		k := edgeKey(now[i])
		seen[k] = true
		if b, ok := prev[k]; ok {
			now[i].Before = &Rates{RequestRate: b.RequestRate, ErrorRate: b.ErrorRate, ConnectionRate: b.ConnectionRate, BytesRate: b.BytesRate}
		}
	}
	for _, b := range before {
		k := edgeKey(b)
		if seen[k] {
			continue
		}
		seen[k] = true
		now = append(now, Edge{
			Src: b.Src, Dst: b.Dst, Port: b.Port, Protocol: b.Protocol, DirectionUnknown: b.DirectionUnknown, Stopped: true,
			Before: &Rates{RequestRate: b.RequestRate, ErrorRate: b.ErrorRate, ConnectionRate: b.ConnectionRate, BytesRate: b.BytesRate},
		})
	}
	return now
}

// rateWindow is the span every query rates over. Expressed in whole seconds
// so any duration is valid PromQL: time.Duration's own format renders an hour
// as "1h0m0s", which PromQL rejects.
type rateWindow struct {
	promQL  string
	seconds float64
	// offset shifts every query back in time (" offset 3600s"), for the
	// comparison window; empty for now.
	offset string
}

func rateWindowFor(d time.Duration) rateWindow {
	switch {
	case d < time.Minute:
		d = DefaultWindow
	case d > MaxWindow:
		d = MaxWindow
	}
	secs := int(d / time.Second)
	return rateWindow{promQL: fmt.Sprintf("%ds", secs), seconds: float64(secs)}
}

// externalIfNoNamespace marks a named endpoint with no namespace as outside
// the cluster.
func externalIfNoNamespace(e *Endpoint) {
	if e.Namespace == "" && e.Name != "" {
		e.Kind = KindExternal
	}
}
