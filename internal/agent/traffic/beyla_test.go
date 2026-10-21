package traffic

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// beylaStub answers each Beyla query shape from its own fixture.
type beylaStub struct {
	l4, l7, errors5xx, unknown []Sample
	// fail makes any query containing the key return an error.
	fail    map[string]bool
	queries []string
}

func (s *beylaStub) Query(_ context.Context, q string) ([]Sample, error) {
	s.queries = append(s.queries, q)
	for needle := range s.fail {
		if strings.Contains(q, needle) {
			return nil, errors.New("query timed out")
		}
	}
	switch {
	case strings.Contains(q, `direction="unknown"`):
		return s.unknown, nil
	case strings.Contains(q, "network_flow_bytes_total"):
		return s.l4, nil
	case strings.Contains(q, `=~"5.."`):
		return s.errors5xx, nil
	case strings.Contains(q, beylaL7Metric):
		return s.l7, nil
	}
	return nil, nil
}

func runBeyla(t *testing.T, s *beylaStub) *Result {
	t.Helper()
	res, err := Flows(context.Background(), s, SourceBeyla, "", 0)
	if err != nil {
		t.Fatalf("Flows: %v", err)
	}
	return res
}

func l4(src, srcNs, dst, dstNs, port, transport string, v float64) Sample {
	l := map[string]string{
		"k8s_src_owner_name": src, "k8s_src_namespace": srcNs,
		"k8s_dst_owner_name": dst, "k8s_dst_namespace": dstNs,
	}
	if port != "" {
		l["dst_port"] = port
	}
	if transport != "" {
		l["transport"] = transport
	}
	return sample(l, v)
}

func l7(ns, owner, port string, v float64) Sample {
	return sample(map[string]string{"k8s_namespace_name": ns, "k8s_owner_name": owner, "server_port": port}, v)
}

func edgeByPort(edges []Edge) map[int]Edge {
	m := map[int]Edge{}
	for _, e := range edges {
		m[e.Port] = e
	}
	return m
}

func TestBeylaOwnerLevelEdge(t *testing.T) {
	s := sample(map[string]string{
		"k8s_src_owner_name": "frontend", "k8s_src_namespace": "web", "k8s_src_owner_type": "Deployment",
		"k8s_dst_owner_name": "backend", "k8s_dst_namespace": "api", "k8s_dst_owner_type": "Deployment",
		"dst_port": "8080", "transport": "TCP",
	}, 15.5)
	res := runBeyla(t, &beylaStub{l4: []Sample{s}})
	if len(res.Edges) != 1 {
		t.Fatalf("want 1 edge, got %d", len(res.Edges))
	}
	e := res.Edges[0]
	if e.Src != (Endpoint{Namespace: "web", Name: "frontend", Kind: KindWorkload}) || e.Dst.Name != "backend" || e.Port != 8080 || e.Protocol != "tcp" {
		t.Fatalf("edge = %+v", e)
	}
	if !approx(mustRate(t, "bytesRate", e.BytesRate), 15.5) {
		t.Fatalf("bytesRate = %v", *e.BytesRate)
	}
	// No HTTP data on this edge, so there is no request rate to report.
	if e.RequestRate != nil || e.ErrorRate != nil {
		t.Fatalf("L4-only edge reports requestRate=%v errorRate=%v, want nil", e.RequestRate, e.ErrorRate)
	}
	if len(res.Notes) != 0 {
		t.Fatalf("notes = %v, want none when port and transport are exported", res.Notes)
	}
}

func TestBeylaL7WithoutL4IsDropped(t *testing.T) {
	// The HTTP metric has no source labels, so a destination with no L4 edge
	// cannot be drawn and must not become a sourceless edge.
	res := runBeyla(t, &beylaStub{l7: []Sample{l7("api", "backend", "8080", 8)}})
	if len(res.Edges) != 0 {
		t.Fatalf("want 0 edges, got %+v", res.Edges)
	}
}

func TestBeylaL7LandsOnTheServedPortOnly(t *testing.T) {
	res := runBeyla(t, &beylaStub{
		l4: []Sample{
			l4("frontend", "web", "backend", "api", "8080", "TCP", 10),
			l4("frontend", "web", "backend", "api", "5432", "TCP", 3),
		},
		l7: []Sample{l7("api", "backend", "8080", 5)},
	})
	byPort := edgeByPort(res.Edges)
	if len(byPort) != 2 {
		t.Fatalf("want 2 edges, got %d", len(res.Edges))
	}
	if got := mustRate(t, ":8080 requestRate", byPort[8080].RequestRate); got != 5 || byPort[8080].Protocol != "http" {
		t.Errorf(":8080 = %v req/s proto %q, want 5 http (sole caller takes the whole rate)", got, byPort[8080].Protocol)
	}
	if byPort[5432].RequestRate != nil || byPort[5432].Protocol != "tcp" {
		t.Errorf(":5432 must carry no HTTP data, got %+v", byPort[5432])
	}
}

func TestBeylaL7NotAttachedWhenItsPortHasNoNamedCaller(t *testing.T) {
	res := runBeyla(t, &beylaStub{
		l4: []Sample{
			// no source owner: an external caller Beyla cannot name
			sample(map[string]string{"k8s_dst_owner_name": "backend", "k8s_dst_namespace": "api", "dst_port": "8080", "transport": "TCP"}, 10),
			l4("worker", "jobs", "backend", "api", "5432", "TCP", 3),
		},
		l7: []Sample{l7("api", "backend", "8080", 5)},
	})
	if len(res.Edges) != 1 || res.Edges[0].Port != 5432 || res.Edges[0].RequestRate != nil {
		t.Fatalf("edges = %+v, want only :5432 with no HTTP data", res.Edges)
	}
}

func TestBeylaEdgeQueryKeepsOnlyTheRequestDirection(t *testing.T) {
	s := &beylaStub{}
	runBeyla(t, s)
	var edgeQuery string
	for _, q := range s.queries {
		if strings.Contains(q, "network_flow_bytes_total") && strings.Contains(q, "dst_port") {
			edgeQuery = q
		}
	}
	if !strings.Contains(edgeQuery, `direction="request"`) {
		t.Fatalf("edge query must keep only the request direction: %q", edgeQuery)
	}
	if strings.Contains(beylaL4GroupBy, "direction") {
		t.Fatal("direction must stay out of the group-by")
	}
	if !strings.Contains(edgeQuery, BeylaJobSelector) {
		t.Fatalf("edge query is not scoped to Beyla's jobs: %q", edgeQuery)
	}
}

func TestBeylaServiceAndWorkloadDuplicateCollapsesToWorkload(t *testing.T) {
	mk := func(dstType string) Sample {
		return sample(map[string]string{
			"k8s_src_owner_name": "client", "k8s_src_namespace": "demo", "k8s_src_owner_type": "Deployment",
			"k8s_dst_owner_name": "db", "k8s_dst_namespace": "demo", "k8s_dst_owner_type": dstType,
			"dst_port": "6379", "transport": "TCP",
		}, 7)
	}
	res := runBeyla(t, &beylaStub{l4: []Sample{mk("Service"), mk("Deployment")}})
	if len(res.Edges) != 1 {
		t.Fatalf("the duplicate pair must collapse to 1 edge, got %d", len(res.Edges))
	}
	if res.Edges[0].Dst.Kind != KindWorkload || !approx(*res.Edges[0].BytesRate, 7) {
		t.Fatalf("edge = %+v, want the workload attribution at 7 B/s (not doubled)", res.Edges[0])
	}
}

func TestBeylaTransportSeparatesOtherwiseIdenticalSeries(t *testing.T) {
	flows, _ := parseL4Flows([]Sample{
		l4("client", "demo", "coredns", "kube-system", "53", "TCP", 1),
		l4("client", "demo", "coredns", "kube-system", "53", "UDP", 2),
	})
	if len(flows) != 2 {
		t.Fatalf("TCP and UDP to one port must not collide, got %d", len(flows))
	}
}

func TestBeylaNotesWhenPortAndTransportAreNotExported(t *testing.T) {
	res := runBeyla(t, &beylaStub{l4: []Sample{l4("client", "demo", "web", "demo", "", "", 5)}})
	if len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "dst.port") || !strings.Contains(res.Notes[0], "transport") {
		t.Fatalf("notes = %v", res.Notes)
	}
	if !strings.Contains(res.Notes[0], "beyla_network_flow_bytes") {
		t.Fatalf("note must name this cluster's metric: %v", res.Notes)
	}

	// On OBI the attribute key is obi_network_flow_bytes.
	obi, err := Flows(context.Background(), &beylaStub{l4: []Sample{l4("client", "demo", "web", "demo", "", "", 5)}}, SourceOBI, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(obi.Notes) != 1 || !strings.Contains(obi.Notes[0], "obi_network_flow_bytes") || strings.Contains(obi.Notes[0], "beyla_") {
		t.Fatalf("OBI notes = %v", obi.Notes)
	}
}

func TestBeylaMultiPortHTTPSumsWhenEdgesHaveNoPort(t *testing.T) {
	res := runBeyla(t, &beylaStub{
		l4:        []Sample{l4("client", "demo", "api", "demo", "", "", 40)},
		l7:        []Sample{l7("demo", "api", "80", 3), l7("demo", "api", "8080", 7)},
		errors5xx: []Sample{l7("demo", "api", "80", 0.2), l7("demo", "api", "8080", 0.5)},
	})
	if len(res.Edges) != 1 {
		t.Fatalf("want 1 edge, got %d", len(res.Edges))
	}
	e := res.Edges[0]
	if !approx(mustRate(t, "requestRate", e.RequestRate), 10) || !approx(mustRate(t, "errorRate", e.ErrorRate), 0.7) {
		t.Fatalf("edge req %v err %v, want 10 / 0.7 summed across both ports", *e.RequestRate, *e.ErrorRate)
	}
}

func TestBeylaPortedEdgesWinOverThePortZeroLeftover(t *testing.T) {
	res := runBeyla(t, &beylaStub{
		l4: []Sample{
			l4("client", "demo", "web", "demo", "80", "TCP", 20),
			l4("client", "demo", "web", "demo", "", "", 18), // from before dst.port was selected
		},
		l7: []Sample{l7("demo", "web", "80", 6)},
	})
	var total float64
	for _, e := range res.Edges {
		total += derefRate(e.RequestRate)
	}
	byPort := edgeByPort(res.Edges)
	if total != 6 || derefRate(byPort[80].RequestRate) != 6 || byPort[0].RequestRate != nil {
		t.Fatalf("rates :80=%v :0=%v total=%v, want 6 on :80 only", byPort[80].RequestRate, byPort[0].RequestRate, total)
	}
}

func TestBeylaPortedDestinationCountsEvenWhenItsCallerIsNameless(t *testing.T) {
	res := runBeyla(t, &beylaStub{
		l4: []Sample{
			sample(map[string]string{"k8s_dst_owner_name": "api", "k8s_dst_namespace": "demo", "dst_port": "8080", "transport": "TCP"}, 30),
			l4("worker", "demo", "api", "demo", "", "", 5),
		},
		l7: []Sample{l7("demo", "api", "8080", 9)},
	})
	if len(res.Edges) != 1 || res.Edges[0].Src.Name != "worker" || res.Edges[0].RequestRate != nil {
		t.Fatalf("edges = %+v; the :8080 HTTP traffic belongs to the dropped caller, not worker", res.Edges)
	}
}

func TestBeylaDestinationFiguresSplitBetweenCallers(t *testing.T) {
	res := runBeyla(t, &beylaStub{
		l4: []Sample{
			l4("busy", "demo", "api", "demo", "", "", 30),
			l4("quiet", "demo", "api", "demo", "", "", 10),
		},
		l7:        []Sample{l7("demo", "api", "80", 8)},
		errors5xx: []Sample{l7("demo", "api", "80", 4)},
	})
	var rate, errRate float64
	for _, e := range res.Edges {
		r, er := mustRate(t, "requestRate", e.RequestRate), mustRate(t, "errorRate", e.ErrorRate)
		if er > r {
			t.Errorf("%s: errorRate %v exceeds requestRate %v", e.Src.Name, er, r)
		}
		if e.Src.Name == "busy" && !approx(r, 6) {
			t.Errorf("busy carries three quarters of the bytes, so 6 of 8 req/s; got %v", r)
		}
		rate += r
		errRate += er
	}
	if !approx(rate, 8) || !approx(errRate, 4) {
		t.Fatalf("rates sum to %v / %v, want 8 / 4 — divided, not duplicated", rate, errRate)
	}
}

func TestBeylaErrorRateIsAMeasuredZeroOnlyWhenTheQuerySucceeded(t *testing.T) {
	ok := runBeyla(t, &beylaStub{
		l4: []Sample{l4("client", "demo", "web", "demo", "80", "TCP", 10)},
		l7: []Sample{l7("demo", "web", "80", 5)},
	})
	if got := mustRate(t, "errorRate", ok.Edges[0].ErrorRate); got != 0 {
		t.Fatalf("errorRate = %v, want a measured 0", got)
	}

	failed := runBeyla(t, &beylaStub{
		l4:   []Sample{l4("client", "demo", "web", "demo", "80", "TCP", 10)},
		l7:   []Sample{l7("demo", "web", "80", 5)},
		fail: map[string]bool{`=~"5.."`: true},
	})
	if failed.Edges[0].ErrorRate != nil {
		t.Fatalf("errorRate = %v after the 5xx query failed, want nil", *failed.Edges[0].ErrorRate)
	}
}

func TestBeylaUnorientableConversationBecomesOneUndirectedEdge(t *testing.T) {
	half := func(src, srcNs, dst, dstNs string, v float64) Sample {
		return sample(map[string]string{
			"k8s_src_owner_name": src, "k8s_src_namespace": srcNs, "k8s_src_owner_type": "Deployment",
			"k8s_dst_owner_name": dst, "k8s_dst_namespace": dstNs, "k8s_dst_owner_type": "Deployment",
			"transport": "UDP",
		}, v)
	}
	res := runBeyla(t, &beylaStub{unknown: []Sample{
		half("client", "demo", "coredns", "kube-system", 10),
		half("coredns", "kube-system", "client", "demo", 25),
	}})
	if len(res.Edges) != 1 {
		t.Fatalf("want the pair collapsed to 1 edge, got %d", len(res.Edges))
	}
	e := res.Edges[0]
	if !e.DirectionUnknown || e.Protocol != "udp" {
		t.Fatalf("edge = %+v, want an undirected udp edge", e)
	}
	// demo/client sorts before kube-system/coredns.
	if e.Src.Name != "client" || e.Dst.Name != "coredns" {
		t.Fatalf("endpoints %s -> %s, want stable alphabetical order", e.Src.Name, e.Dst.Name)
	}
	if !approx(mustRate(t, "bytesRate", e.BytesRate), 35) {
		t.Fatalf("bytesRate = %v, want both halves (35)", *e.BytesRate)
	}
	if e.RequestRate != nil {
		t.Fatalf("requestRate = %v, want nil: nothing here counts requests", *e.RequestRate)
	}
}

func TestBeylaUnorientablePairsCollapseAcrossEphemeralPorts(t *testing.T) {
	// The query groups without dst_port, so Prometheus has already summed the
	// ephemeral-port series; the fake evaluates the same grouping.
	raw := []rawSeries{{beylaFlowMetric, map[string]string{
		"k8s_src_owner_name": "client", "k8s_src_namespace": "demo",
		"k8s_dst_owner_name": "coredns", "k8s_dst_namespace": "kube-system",
		"transport": "UDP", "dst_port": "53", "direction": "unknown",
	}, 5}}
	for _, port := range []string{"41866", "41864", "37221", "52001"} {
		raw = append(raw, rawSeries{beylaFlowMetric, map[string]string{
			"k8s_src_owner_name": "coredns", "k8s_src_namespace": "kube-system",
			"k8s_dst_owner_name": "client", "k8s_dst_namespace": "demo",
			"transport": "UDP", "dst_port": port, "direction": "unknown",
		}, 2})
	}
	res, err := Flows(context.Background(), fakeSumBy(raw, nil), SourceBeyla, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Edges) != 1 || !approx(*res.Edges[0].BytesRate, 13) {
		t.Fatalf("edges = %+v, want one undirected edge at 13 B/s", res.Edges)
	}
}

func TestBeylaFailedEnrichmentIsReportedNotZeroed(t *testing.T) {
	for _, tc := range []struct{ needle, want string }{
		{`direction="unknown"`, "undirected (UDP) conversations"},
		{`=~"5.."`, "HTTP 5xx error rates"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			res := runBeyla(t, &beylaStub{
				l4:   []Sample{l4("frontend", "web", "backend", "api", "8080", "TCP", 10)},
				fail: map[string]bool{tc.needle: true},
			})
			if len(res.Edges) != 1 {
				t.Fatalf("the L4 edge must still be returned, got %d", len(res.Edges))
			}
			if strings.Join(res.Missing, ",") != tc.want {
				t.Fatalf("missing = %v, want [%s]", res.Missing, tc.want)
			}
		})
	}

	// The L7 rate query fails on its own (the 5xx query shares the metric name
	// and must still answer).
	s := &beylaStub{l4: []Sample{l4("frontend", "web", "backend", "api", "8080", "TCP", 10)}}
	q := queryFunc(func(ctx context.Context, promql string) ([]Sample, error) {
		if strings.Contains(promql, beylaL7Metric) && !strings.Contains(promql, `=~"5.."`) {
			return nil, errors.New("timeout")
		}
		return s.Query(ctx, promql)
	})
	res, err := Flows(context.Background(), q, SourceBeyla, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Missing, ",") != "HTTP request rates" || res.Edges[0].RequestRate != nil {
		t.Fatalf("missing = %v edge = %+v", res.Missing, res.Edges[0])
	}
}

func TestBeylaL4FailureIsAnError(t *testing.T) {
	_, err := Flows(context.Background(), &beylaStub{fail: map[string]bool{`direction="request"`: true}}, SourceBeyla, "", 0)
	if err == nil {
		t.Fatal("want an error when the edge query fails")
	}
}

func TestBeylaRatesOverTheRequestedWindow(t *testing.T) {
	s := &beylaStub{}
	res, err := Flows(context.Background(), s, SourceBeyla, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if res.WindowSeconds != 3600 {
		t.Fatalf("windowSeconds = %d", res.WindowSeconds)
	}
	for _, q := range s.queries {
		if !strings.Contains(q, "[3600s]") {
			t.Errorf("query not rated over the requested hour: %s", q)
		}
	}
}

func TestBeylaNamespaceFilterScopesEitherEnd(t *testing.T) {
	s := &beylaStub{}
	if _, err := Flows(context.Background(), s, SourceBeyla, "demo", 0); err != nil {
		t.Fatal(err)
	}
	var sawL4, sawL7 bool
	for _, q := range s.queries {
		if strings.Contains(q, "network_flow_bytes_total") {
			sawL4 = true
			if !strings.Contains(q, `k8s_src_namespace="demo"`) || !strings.Contains(q, `k8s_dst_namespace="demo"`) {
				t.Errorf("flow query does not filter either end: %s", q)
			}
		} else if strings.Contains(q, beylaL7Metric) {
			sawL7 = true
			if !strings.Contains(q, `k8s_namespace_name="demo"`) {
				t.Errorf("HTTP query does not filter the server namespace: %s", q)
			}
		}
	}
	if !sawL4 || !sawL7 {
		t.Fatalf("queries = %v", s.queries)
	}
}

func TestMapBeylaKindAndTransport(t *testing.T) {
	for in, want := range map[string]string{"Deployment": KindWorkload, "StatefulSet": KindWorkload, "Service": KindService, "Pod": KindPod, "": KindPod} {
		if got := mapBeylaKind(in); got != want {
			t.Errorf("mapBeylaKind(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"TCP": "tcp", "UDP": "udp", "udp": "udp", "": "tcp"} {
		if got := mapBeylaTransport(in); got != want {
			t.Errorf("mapBeylaTransport(%q) = %q, want %q", in, got, want)
		}
	}
}
