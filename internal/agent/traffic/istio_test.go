package traffic

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// istioSeries is one Istio metric series from checkout to payments, seen by
// the destination's proxy, through the named Service.
func istioSeries(metric, viaService, protocol, code string, v float64) rawSeries {
	l := map[string]string{
		"reporter":                       "destination",
		"source_workload":                "checkout",
		"source_workload_namespace":      "shop",
		"destination_workload":           "payments",
		"destination_workload_namespace": "shop",
		"destination_service_name":       viaService,
		"request_protocol":               protocol,
		"response_code":                  code,
	}
	return rawSeries{metric, l, v}
}

// One workload pair reached through two Services, HTTP on one and gRPC on the
// other: the shape in which a pair-level figure is easy to attach to every
// series instead of once.
func twoServiceIstioSeries() []rawSeries {
	const req, bytes = "istio_requests_total", "istio_request_bytes_sum"
	return []rawSeries{
		istioSeries(req, "payments", "http", "200", 9),
		istioSeries(req, "payments", "http", "503", 1),
		istioSeries(req, "payments-rpc", "grpc", "200", 4.5),
		istioSeries(req, "payments-rpc", "grpc", "500", 0.5),
		istioSeries(bytes, "payments", "http", "200", 2000),
		istioSeries(bytes, "payments-rpc", "grpc", "200", 1000),
	}
}

func TestIstioFlowsPairFiguresAreNotCopiedOntoEachSeries(t *testing.T) {
	res := &Result{}
	flows, err := istioFlows(context.Background(), fakeSumBy(twoServiceIstioSeries(), nil), "", rateWindowFor(0), res)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 2 {
		t.Fatalf("want one flow per Service, got %d: %+v", len(flows), flows)
	}
	var reqs, errs, bytes float64
	for _, f := range flows {
		reqs += mustRate(t, "requestRate", f.RequestRate)
		errs += mustRate(t, "errorRate", f.ErrorRate)
		bytes += mustRate(t, "bytesRate", f.BytesRate)
	}
	if !approx(reqs, 15) || !approx(errs, 1.5) || !approx(bytes, 3000) {
		t.Fatalf("totals req=%v err=%v bytes=%v, want 15 / 1.5 / 3000 — a pair figure was attributed more than once", reqs, errs, bytes)
	}

	// Aggregated, the pair is one edge carrying the pair's totals, labelled by
	// the protocol that carries most of it.
	edges := AggregateFlows(flows)
	if len(edges) != 1 {
		t.Fatalf("want 1 edge for the pair, got %d", len(edges))
	}
	e := edges[0]
	if !approx(*e.RequestRate, 15) || !approx(*e.ErrorRate, 1.5) || e.Protocol != "http" {
		t.Fatalf("edge = req %v err %v proto %q", *e.RequestRate, *e.ErrorRate, e.Protocol)
	}
	if e.Src.Kind != KindWorkload || e.Dst.Name != "payments" {
		t.Fatalf("endpoints = %+v -> %+v", e.Src, e.Dst)
	}
}

func TestIstioFlowsNoErrorsIsAMeasuredZero(t *testing.T) {
	raw := []rawSeries{istioSeries("istio_requests_total", "payments", "http", "200", 4)}
	flows, err := istioFlows(context.Background(), fakeSumBy(raw, nil), "", rateWindowFor(0), &Result{})
	if err != nil {
		t.Fatal(err)
	}
	if got := mustRate(t, "errorRate", flows[0].ErrorRate); got != 0 {
		t.Fatalf("errorRate = %v, want 0", got)
	}
}

func TestIstioFlowsFailedSubqueriesAreReportedNotZeroed(t *testing.T) {
	boom := errors.New("query timed out")
	for _, tc := range []struct {
		name, needle, missing string
	}{
		{"error rates", `response_code=~"5.."`, "5xx error rates"},
		{"tcp", "istio_tcp_connections_opened_total", "TCP connections"},
		{"request bytes", "istio_request_bytes_sum", "request bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := &Result{}
			flows, err := istioFlows(context.Background(), fakeSumBy(twoServiceIstioSeries(), map[string]error{tc.needle: boom}), "", rateWindowFor(0), res)
			if err != nil {
				t.Fatal(err)
			}
			if len(flows) == 0 {
				t.Fatal("the request-rate query succeeded, so its flows must still be returned")
			}
			if strings.Join(res.Missing, ",") != tc.missing {
				t.Fatalf("missing = %v, want [%s]", res.Missing, tc.missing)
			}
			for _, f := range flows {
				if tc.name == "error rates" && f.ErrorRate != nil {
					t.Fatalf("errorRate = %v after the 5xx query failed, want nil", *f.ErrorRate)
				}
				if tc.name == "request bytes" && f.BytesRate != nil {
					t.Fatalf("bytesRate = %v after the bytes query failed, want nil", *f.BytesRate)
				}
			}
		})
	}
}

func TestIstioFlowsPrimaryQueryFailureIsAnError(t *testing.T) {
	_, err := istioFlows(context.Background(), fakeSumBy(nil, map[string]error{"istio_requests_total": errors.New("down")}), "", rateWindowFor(0), &Result{})
	if err == nil {
		t.Fatal("want an error when the request-rate query fails")
	}
}

func TestIstioFlowsTCPAndUnknownDestination(t *testing.T) {
	raw := []rawSeries{
		{"istio_tcp_connections_opened_total", map[string]string{
			"source_workload": "frontend", "source_workload_namespace": "shop",
			"destination_workload": "db", "destination_workload_namespace": "shop",
			"destination_service_name": "db", "reporter": "destination",
		}, 2.7},
		{"istio_requests_total", map[string]string{
			"source_workload": "frontend", "source_workload_namespace": "shop",
			"destination_workload": "unknown", "destination_workload_namespace": "shop",
			"destination_service_name": "orphan-svc", "request_protocol": "http", "reporter": "destination",
		}, 1},
		{"istio_requests_total", map[string]string{
			"source_workload": "istio-ingressgateway", "source_workload_namespace": "",
			"destination_workload": "frontend", "destination_workload_namespace": "shop",
			"request_protocol": "http", "reporter": "destination",
		}, 1},
	}
	flows, err := istioFlows(context.Background(), fakeSumBy(raw, nil), "", rateWindowFor(0), &Result{})
	if err != nil {
		t.Fatal(err)
	}
	var sawTCP, sawService, sawExternal bool
	for _, f := range flows {
		switch {
		case f.Protocol == "tcp":
			sawTCP = approx(mustRate(t, "connectionRate", f.ConnectionRate), 2.7) && f.RequestRate == nil
		case f.Dst.Kind == KindService:
			sawService = f.Dst.Name == "orphan-svc"
		case f.Src.Kind == KindExternal:
			sawExternal = f.Src.Name == "istio-ingressgateway"
		}
	}
	if !sawTCP || !sawService || !sawExternal {
		t.Fatalf("tcp=%v service=%v external=%v in %+v", sawTCP, sawService, sawExternal, flows)
	}
}

func TestIstioRateQueryShape(t *testing.T) {
	q := istioRateQuery(istioHTTPGroupBy, "istio_requests_total", "", "shop", rateWindowFor(time.Hour))
	for _, want := range []string{
		`reporter="destination"`,
		`source_workload_namespace="shop"`,
		` or `,
		`destination_workload_namespace="shop"`,
		`[3600s]`,
	} {
		if !strings.Contains(q, want) {
			t.Errorf("query %s missing %s", q, want)
		}
	}
}

func TestIstioNamespaceFilterKeepsEitherEndOnce(t *testing.T) {
	raw := []rawSeries{
		istioSeries("istio_requests_total", "payments", "http", "200", 2), // shop -> shop
		{"istio_requests_total", map[string]string{
			"source_workload": "a", "source_workload_namespace": "other",
			"destination_workload": "b", "destination_workload_namespace": "other",
			"request_protocol": "http",
		}, 7},
	}
	flows, err := istioFlows(context.Background(), fakeSumBy(raw, nil), "shop", rateWindowFor(0), &Result{})
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 1 || !approx(*flows[0].RequestRate, 2) {
		t.Fatalf("flows = %+v, want the one shop edge counted once", flows)
	}
}
