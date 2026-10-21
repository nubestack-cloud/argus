package traffic

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// BeylaJobSelector scopes every Beyla/OBI query to the Prometheus jobs Beyla
// is normally scraped under — standalone, or embedded in Grafana Alloy.
const BeylaJobSelector = `job=~".*beyla.*|.*alloy.*"`

const (
	// Grafana's Beyla exports the network-flow metric as beyla_*; OBI exports
	// it as obi_*. Detect decides which one a cluster has.
	beylaFlowMetric = "beyla_network_flow_bytes_total"
	obiFlowMetric   = "obi_network_flow_bytes_total"

	// beylaL4GroupBy keeps the owner types even though the edge key ignores
	// them: Beyla reports a Service-routed conversation twice with identical
	// values, once attributed to the workload and once to the Service, and
	// summing across owner types would double it.
	beylaL4GroupBy = `k8s_src_owner_name, k8s_src_namespace, k8s_src_owner_type, k8s_dst_owner_name, k8s_dst_namespace, k8s_dst_owner_type, dst_port, transport`

	// beylaL4DirectionFilter keeps only the request half of each conversation.
	// Beyla emits both halves with source and destination swapped, so without
	// it every edge gains a mirror twin pointing the wrong way. It requires
	// "request" rather than excluding "response" because UDP lands in a third
	// value, "unknown", on both halves; those are read separately by
	// beylaUnorientableFlows.
	beylaL4DirectionFilter = `, direction="request"`
	beylaUnknownDirection  = `, direction="unknown"`

	// beylaL7Metric is Beyla's OTel-aligned HTTP server histogram. It is
	// recorded server-side only and carries no caller labels at all.
	beylaL7Metric = "http_server_request_duration_seconds_count"
	// beylaL7GroupBy names a destination the way the L4 metric does: owner
	// first, pod name when a workload has no owner. Grouping by owner alone
	// collapses every owner-less series in a namespace into one nameless row.
	// server_port is what joins an HTTP rate to one specific L4 edge.
	beylaL7GroupBy = `k8s_namespace_name, k8s_owner_name, k8s_pod_name, server_port`
)

// beylaRateQuery builds `sum by (groupBy) (rate(metric{job=~...extra}[w]))`.
// A namespace filter becomes two OR'd selectors, as for Istio.
func beylaRateQuery(groupBy, metric, namespace, extra string, w rateWindow) string {
	sum := func(more string) string {
		return fmt.Sprintf(`sum by (%s) (rate(%s{%s%s%s}[%s]%s))`, groupBy, metric, BeylaJobSelector, extra, more, w.promQL, w.offset)
	}
	if namespace == "" {
		return sum("")
	}
	return sum(fmt.Sprintf(`, k8s_src_namespace=%q`, namespace)) + " or " +
		sum(fmt.Sprintf(`, k8s_dst_namespace=%q`, namespace))
}

// beylaL7Query reads the HTTP metric. It has one namespace label to filter on
// (the server's), since it has no source side.
func beylaL7Query(namespace, extra string, w rateWindow) string {
	if namespace != "" {
		extra += fmt.Sprintf(`, k8s_namespace_name=%q`, namespace)
	}
	return fmt.Sprintf(`sum by (%s) (rate(%s{%s%s}[%s]%s))`, beylaL7GroupBy, beylaL7Metric, BeylaJobSelector, extra, w.promQL, w.offset)
}

// place is a named object in a namespace: an edge end, or a destination
// without its port.
type place struct{ ns, name string }

// served is a destination and the port it served on. dst_port is opt-in in
// Beyla, so without it every edge carries port 0 and a destination's HTTP
// traffic has to be summed across ports.
type served struct {
	at   place
	port int
}

// l4Key identifies one oriented L4 edge. Owner types are left out on
// purpose: two series that differ only in owner type are two attributions of
// one conversation (see preferL4).
type l4Key struct {
	from, to  place
	port      int
	transport string
}

// l4LabelPresence records which optional attributes the scrape carried.
// dst.port and transport are off by default in Beyla, so a stock install
// exports neither and every edge arrives with port 0 and protocol tcp.
type l4LabelPresence struct {
	// portedDsts are destinations reported with a real port, recorded before
	// nameless series are dropped: a destination's only port-bearing traffic
	// can come from a caller Beyla cannot name, and judging from the surviving
	// edges alone would hand that caller's HTTP data to a port-0 leftover.
	portedDsts map[place]bool
	port       bool
	transport  bool
}

func (p l4LabelPresence) notes(metric string, edges int) []string {
	if edges == 0 {
		return nil
	}
	attr := strings.TrimSuffix(metric, "_total")
	switch {
	case !p.port && !p.transport:
		return []string{fmt.Sprintf("Beyla is not exporting dst.port or transport, so these edges have no port (shown as 0) and UDP is shown as TCP. Both are opt-in under attributes.select for %s.", attr)}
	case !p.port:
		return []string{fmt.Sprintf("Beyla is not exporting dst.port, so every edge shows port 0. It is opt-in under attributes.select for %s.", attr)}
	case !p.transport:
		return []string{fmt.Sprintf("Beyla is not exporting transport, so UDP traffic is shown as TCP. It is opt-in under attributes.select for %s.", attr)}
	}
	return nil
}

// l7Rates holds an HTTP figure per destination and port, and per destination
// across all ports for edges that carry no port.
type l7Rates struct {
	perPort map[served]float64
	perDst  map[place]float64
}

func (r l7Rates) forEdge(key served, portless bool) (float64, bool) {
	if portless {
		v, ok := r.perDst[key.at]
		return v, ok
	}
	v, ok := r.perPort[key]
	return v, ok
}

// readL7 sums an HTTP query's series per destination+port and per
// destination. Series are grouped by pod, so a destination with several
// replicas reports once per pod; those add up, as do a destination's ports.
func readL7(ctx context.Context, q PromQuerier, query string) (l7Rates, error) {
	out := l7Rates{perPort: map[served]float64{}, perDst: map[place]float64{}}
	samples, err := q.Query(ctx, query)
	if err != nil {
		return out, err
	}
	for _, s := range samples {
		if !usableSample(s.Value) {
			continue
		}
		name := pickBeylaOwner(s.Labels)
		if name == "" {
			continue
		}
		at := place{s.Labels["k8s_namespace_name"], name}
		out.perPort[served{at, parseIntLabel(s.Labels["server_port"])}] += s.Value
		out.perDst[at] += s.Value
	}
	return out, nil
}

// beylaFlows reads oriented L4 edges, attaches HTTP request and 5xx rates to
// the edges they were served on, and adds the conversations Beyla could not
// orient as undirected edges. Only the L4 query is required.
func beylaFlows(ctx context.Context, q PromQuerier, metric, namespace string, w rateWindow, res *Result) ([]Edge, error) {
	samples, err := q.Query(ctx, beylaRateQuery(beylaL4GroupBy, metric, namespace, beylaL4DirectionFilter, w))
	if err != nil {
		return nil, fmt.Errorf("query %s: %w", metric, err)
	}
	l4, presence := parseL4Flows(samples)

	requests, reqErr := readL7(ctx, q, beylaL7Query(namespace, "", w))
	if reqErr != nil {
		res.Missing = append(res.Missing, "HTTP request rates")
	}
	errorRates, errErr := readL7(ctx, q, beylaL7Query(namespace, `, http_response_status_code=~"5.."`, w))
	if errErr != nil {
		res.Missing = append(res.Missing, "HTTP 5xx error rates")
	}

	byDstPort := make(map[served][]*Edge, len(l4))
	for _, f := range l4 {
		key := served{place{f.Dst.Namespace, f.Dst.Name}, f.Port}
		byDstPort[key] = append(byDstPort[key], f)
	}

	if reqErr == nil {
		for key, edges := range byDstPort {
			// Where a destination has real ports they are authoritative; its port-0
			// bucket is then a leftover from before dst.port was selected (the rate
			// window still holds those series) and must not also receive the
			// destination-wide rate, or the same requests land on two edges.
			portless := key.port == 0 && !presence.portedDsts[key.at]
			rate, ok := requests.forEdge(key, portless)
			if !ok {
				continue
			}
			// The HTTP metric has no caller labels, so a destination's rate is
			// divided across the callers that reached it by their share of bytes,
			// the best available proxy. Errors are divided the same way: splitting
			// one and copying the other lets an edge report more errors than
			// requests.
			var total float64
			for _, f := range edges {
				total += derefRate(f.BytesRate)
			}
			errRate, errOK := errorRates.forEdge(key, portless)
			for _, f := range edges {
				share := 1 / float64(len(edges))
				if total > 0 {
					share = derefRate(f.BytesRate) / total
				}
				f.Protocol = "http"
				f.RequestRate = ratePtr(rate * share)
				if errErr == nil {
					v := 0.0
					if errOK {
						v = errRate * share
					}
					f.ErrorRate = ratePtr(v)
				}
			}
		}
	}

	flows := make([]Edge, 0, len(l4))
	for _, f := range l4 {
		flows = append(flows, *f)
	}
	unoriented, uErr := beylaUnorientableFlows(ctx, q, metric, namespace, w)
	if uErr != nil {
		res.Missing = append(res.Missing, "undirected (UDP) conversations")
	}
	flows = append(flows, unoriented...)
	res.Notes = append(res.Notes, presence.notes(metric, len(l4))...)
	return flows, nil
}

// parseL4Flows turns network-flow series into deduplicated edges, keyed while
// the raw transport and owner types are still in hand.
func parseL4Flows(samples []Sample) (map[l4Key]*Edge, l4LabelPresence) {
	flows := make(map[l4Key]*Edge)
	presence := l4LabelPresence{portedDsts: map[place]bool{}}
	for _, s := range samples {
		if !usableSample(s.Value) {
			continue
		}
		l := s.Labels
		presence.port = presence.port || l["dst_port"] != ""
		presence.transport = presence.transport || l["transport"] != ""

		// Each end is named by its owner when Beyla resolved one, else by
		// the object itself.
		end := func(side string) (place, string) {
			return place{l["k8s_"+side+"_namespace"], pickLabel(l, "k8s_"+side+"_owner_name", "k8s_"+side+"_name")},
				pickLabel(l, "k8s_"+side+"_owner_type", "k8s_"+side+"_type")
		}
		from, fromType := end("src")
		to, toType := end("dst")
		key := l4Key{from: from, to: to, port: parseIntLabel(l["dst_port"]), transport: l["transport"]}

		// Record a ported destination before dropping nameless series; see
		// l4LabelPresence.portedDsts.
		if to.name != "" && key.port != 0 {
			presence.portedDsts[to] = true
		}
		// A nameless end cannot be resolved or navigated to, so the series
		// is dropped rather than drawn as an anonymous node.
		if from.name == "" || to.name == "" {
			continue
		}

		f := &Edge{
			Src:       Endpoint{Namespace: from.ns, Name: from.name, Kind: mapBeylaKind(fromType)},
			Dst:       Endpoint{Namespace: to.ns, Name: to.name, Kind: mapBeylaKind(toType)},
			Port:      key.port,
			Protocol:  mapBeylaTransport(key.transport),
			BytesRate: ratePtr(s.Value),
		}
		externalIfNoNamespace(&f.Src)
		externalIfNoNamespace(&f.Dst)
		if existing, ok := flows[key]; ok {
			f = preferL4(existing, f)
		}
		flows[key] = f
	}
	return flows, presence
}

// preferL4 chooses between two series that describe the same conversation.
// The workload attribution wins over the Service copy of the same bytes, so
// edges point at workloads. Two attributions with the same number of Service
// ends are reported with identical values, so the larger is kept rather than
// their sum; that is also independent of the order Prometheus returned them.
func preferL4(incumbent, candidate *Edge) *Edge {
	switch {
	case serviceEnds(candidate.Src.Kind, candidate.Dst.Kind) < serviceEnds(incumbent.Src.Kind, incumbent.Dst.Kind):
		return candidate
	case serviceEnds(candidate.Src.Kind, candidate.Dst.Kind) > serviceEnds(incumbent.Src.Kind, incumbent.Dst.Kind):
		return incumbent
	default:
		if derefRate(candidate.BytesRate) > derefRate(incumbent.BytesRate) {
			incumbent.BytesRate = candidate.BytesRate
		}
		return incumbent
	}
}

func serviceEnds(srcKind, dstKind string) int {
	n := 0
	if strings.EqualFold(srcKind, KindService) {
		n++
	}
	if strings.EqualFold(dstKind, KindService) {
		n++
	}
	return n
}

// conversation identifies an unorientable exchange between two endpoints over
// one transport without saying which end began it.
type conversation struct {
	aNs, aName, bNs, bName string
	transport              string
}

// beylaUnorientableFlows reads the conversations Beyla labels
// direction="unknown" — where UDP lands, DNS above all — and returns one
// undirected edge per pair. Dropping them would take the far end (coredns)
// off the map; drawing both halves would claim two directions.
//
// Ports are not carried: where they exist one half holds the client's
// ephemeral port, so no single port describes the conversation, and grouping
// without them is what collapses hundreds of ephemeral-port series into one
// edge.
func beylaUnorientableFlows(ctx context.Context, q PromQuerier, metric, namespace string, w rateWindow) ([]Edge, error) {
	groupBy := `k8s_src_owner_name, k8s_src_namespace, k8s_src_owner_type, k8s_dst_owner_name, k8s_dst_namespace, k8s_dst_owner_type, transport`
	samples, err := q.Query(ctx, beylaRateQuery(groupBy, metric, namespace, beylaUnknownDirection, w))
	if err != nil {
		return nil, err
	}

	type halves struct{ forward, reverse float64 }
	type attrKey struct {
		conv         conversation
		aType, bType string
	}
	byAttribution := make(map[attrKey]*halves)
	for _, s := range samples {
		if !usableSample(s.Value) {
			continue
		}
		l := s.Labels
		xName := pickLabel(l, "k8s_src_owner_name", "k8s_src_name")
		yName := pickLabel(l, "k8s_dst_owner_name", "k8s_dst_name")
		if xName == "" || yName == "" {
			continue
		}
		xNs, yNs := l["k8s_src_namespace"], l["k8s_dst_namespace"]
		xType, yType := l["k8s_src_owner_type"], l["k8s_dst_owner_type"]
		// Order the ends so both halves land on one key, stably across polls.
		forward := xNs+"/"+xName <= yNs+"/"+yName
		k := attrKey{conv: conversation{aNs: xNs, aName: xName, bNs: yNs, bName: yName, transport: l["transport"]}, aType: xType, bType: yType}
		if !forward {
			k = attrKey{conv: conversation{aNs: yNs, aName: yName, bNs: xNs, bName: xName, transport: l["transport"]}, aType: yType, bType: xType}
		}
		h, ok := byAttribution[k]
		if !ok {
			h = &halves{}
			byAttribution[k] = h
		}
		if forward {
			h.forward += s.Value
		} else {
			h.reverse += s.Value
		}
	}

	// Collapse attributions of one conversation: fewest Service ends names the
	// edge; identical traffic under two attributions is kept once (max).
	chosen := make(map[conversation]attrKey)
	totals := make(map[conversation]*halves)
	for k, h := range byAttribution {
		if prev, ok := chosen[k.conv]; !ok || attrLess(k.aType, k.bType, prev.aType, prev.bType) {
			chosen[k.conv] = k
		}
		if t, ok := totals[k.conv]; ok {
			t.forward = max(t.forward, h.forward)
			t.reverse = max(t.reverse, h.reverse)
		} else {
			totals[k.conv] = &halves{forward: h.forward, reverse: h.reverse}
		}
	}

	flows := make([]Edge, 0, len(totals))
	for conv, h := range totals {
		k := chosen[conv]
		f := Edge{
			Src:              Endpoint{Namespace: conv.aNs, Name: conv.aName, Kind: mapBeylaKind(k.aType)},
			Dst:              Endpoint{Namespace: conv.bNs, Name: conv.bName, Kind: mapBeylaKind(k.bType)},
			Protocol:         mapBeylaTransport(conv.transport),
			BytesRate:        ratePtr(h.forward + h.reverse),
			DirectionUnknown: true,
		}
		externalIfNoNamespace(&f.Src)
		externalIfNoNamespace(&f.Dst)
		flows = append(flows, f)
	}
	return flows, nil
}

// attrLess orders two attributions of one conversation: fewer Service ends
// first, then by owner type so the choice never depends on map order.
func attrLess(aType, bType, prevA, prevB string) bool {
	n, m := serviceEnds(mapBeylaKind(aType), mapBeylaKind(bType)), serviceEnds(mapBeylaKind(prevA), mapBeylaKind(prevB))
	if n != m {
		return n < m
	}
	return aType+"/"+bType < prevA+"/"+prevB
}

// pickBeylaOwner resolves the destination name on an HTTP series:
// k8s_owner_name is the same value the flow metric exposes as
// k8s_dst_owner_name, so the two line up; a bare pod falls back to its name.
func pickBeylaOwner(labels map[string]string) string {
	if v := labels["k8s_owner_name"]; v != "" {
		return v
	}
	return labels["k8s_pod_name"]
}

func pickLabel(labels map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := labels[k]; v != "" {
			return v
		}
	}
	return ""
}

func parseIntLabel(s string) int {
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return v
}

func mapBeylaKind(ownerType string) string {
	switch strings.ToLower(ownerType) {
	case "deployment", "replicaset", "statefulset", "daemonset", "job", "cronjob":
		return KindWorkload
	case "service":
		return KindService
	case "", "pod":
		return KindPod
	default:
		// Any other owner — an operator's own controller, such as a
		// CloudNativePG Cluster — is the workload the pod belongs to.
		return KindWorkload
	}
}

func mapBeylaTransport(transport string) string {
	if strings.EqualFold(transport, "UDP") {
		return "udp"
	}
	return "tcp"
}

func derefRate(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}
