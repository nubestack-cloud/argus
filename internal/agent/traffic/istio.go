package traffic

import (
	"context"
	"fmt"
	"strings"
)

// istioHTTPGroupBy is shared by every HTTP query so their series join one to
// one. A workload pair can carry several series — one per destination Service
// and protocol — so every figure joined onto a series must be keyed this
// finely, or the pair's total is attached to each series and counted once per
// series.
const istioHTTPGroupBy = "source_workload, source_workload_namespace, destination_workload, destination_workload_namespace, destination_service_name, request_protocol"

const istioTCPGroupBy = "source_workload, source_workload_namespace, destination_workload, destination_workload_namespace, destination_service_name"

// istioRateQuery builds `sum by (groupBy) (rate(metric{reporter="destination"extra}[w]))`.
// reporter="destination" counts each request once, as the server-side proxy
// saw it. A namespace filter becomes two OR'd selectors: PromQL cannot
// express "source OR destination namespace matches" inside one selector, and
// `or` drops right-hand series already present on the left, so an
// intra-namespace edge is not counted twice.
func istioRateQuery(groupBy, metric, extra, namespace string, w rateWindow) string {
	sum := func(more string) string {
		return fmt.Sprintf(`sum by (%s) (rate(%s{reporter="destination"%s%s}[%s]%s))`, groupBy, metric, extra, more, w.promQL, w.offset)
	}
	if namespace == "" {
		return sum("")
	}
	return sum(fmt.Sprintf(`, source_workload_namespace=%q`, namespace)) + " or " +
		sum(fmt.Sprintf(`, destination_workload_namespace=%q`, namespace))
}

type istioSeriesKey struct {
	srcName, srcNs, dstName, dstNs string
	dstService, protocol           string
}

func istioSeriesKeyFrom(labels map[string]string) istioSeriesKey {
	return istioSeriesKey{
		srcName:    labels["source_workload"],
		srcNs:      labels["source_workload_namespace"],
		dstName:    labels["destination_workload"],
		dstNs:      labels["destination_workload_namespace"],
		dstService: labels["destination_service_name"],
		protocol:   labels["request_protocol"],
	}
}

// istioSeriesRates reads an enrichment query's values by series. A zero or
// unusable rate is no measurement and is left out rather than joined as one.
func istioSeriesRates(ctx context.Context, q PromQuerier, query string) (map[istioSeriesKey]float64, error) {
	samples, err := q.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	rates := make(map[istioSeriesKey]float64)
	for _, s := range samples {
		if !usableSample(s.Value) {
			continue
		}
		rates[istioSeriesKeyFrom(s.Labels)] += s.Value
	}
	return rates, nil
}

func istioEndpoints(key istioSeriesKey) (Endpoint, Endpoint) {
	src := Endpoint{Namespace: key.srcNs, Name: key.srcName, Kind: KindWorkload}
	dst := Endpoint{Namespace: key.dstNs, Name: key.dstName, Kind: KindWorkload}
	// Traffic to a Service with no ready workload behind it (or outside the
	// mesh) has destination_workload "unknown"; the Service is what was
	// addressed, so it names the edge.
	if (dst.Name == "" || dst.Name == "unknown") && key.dstService != "" {
		dst.Name = key.dstService
		dst.Kind = KindService
	}
	externalIfNoNamespace(&src)
	externalIfNoNamespace(&dst)
	return src, dst
}

// istioFlows reads HTTP/gRPC request rates with their 5xx rates and request
// bytes, plus TCP connection rates. Only the request-rate query is required;
// the rest are recorded in res.Missing when they fail.
func istioFlows(ctx context.Context, q PromQuerier, namespace string, w rateWindow, res *Result) ([]Edge, error) {
	requests, err := q.Query(ctx, istioRateQuery(istioHTTPGroupBy, "istio_requests_total", "", namespace, w))
	if err != nil {
		return nil, fmt.Errorf("query istio_requests_total: %w", err)
	}

	errorRates, errErr := istioSeriesRates(ctx, q, istioRateQuery(istioHTTPGroupBy, "istio_requests_total", `, response_code=~"5.."`, namespace, w))
	if errErr != nil {
		res.Missing = append(res.Missing, "5xx error rates")
	}
	bytesSent, bytesErr := istioSeriesRates(ctx, q, istioRateQuery(istioHTTPGroupBy, "istio_request_bytes_sum", "", namespace, w))
	if bytesErr != nil {
		res.Missing = append(res.Missing, "request bytes")
	}

	flows := make([]Edge, 0, len(requests))
	for _, s := range requests {
		if !usableSample(s.Value) {
			continue
		}
		key := istioSeriesKeyFrom(s.Labels)
		protocol := strings.ToLower(key.protocol)
		if protocol == "" {
			protocol = "http"
		}
		src, dst := istioEndpoints(key)
		f := Edge{Src: src, Dst: dst, Protocol: protocol, RequestRate: ratePtr(s.Value)}
		if errErr == nil {
			// The 5xx query succeeded, so a series absent from it measured no 5xx.
			f.ErrorRate = ratePtr(errorRates[key])
		}
		if bytesErr == nil {
			if b, ok := bytesSent[key]; ok {
				f.BytesRate = ratePtr(b)
			}
		}
		flows = append(flows, f)
	}

	tcp, tcpErr := q.Query(ctx, istioRateQuery(istioTCPGroupBy, "istio_tcp_connections_opened_total", "", namespace, w))
	if tcpErr != nil {
		// Unlike the enrichments above, this can be why there are no edges at
		// all: a TCP-only mesh whose query failed must not read as idle.
		res.Missing = append(res.Missing, "TCP connections")
		return flows, nil
	}
	for _, s := range tcp {
		if !usableSample(s.Value) {
			continue
		}
		src, dst := istioEndpoints(istioSeriesKeyFrom(s.Labels))
		flows = append(flows, Edge{Src: src, Dst: dst, Protocol: "tcp", ConnectionRate: ratePtr(s.Value)})
	}
	return flows, nil
}
