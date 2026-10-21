package traffic

import (
	"context"
	"fmt"
	"strings"
)

// Hubble (Cilium) as a traffic source (PROJECT.md PG6), read from the flow
// metrics Cilium exports to Prometheus. hubble_flows_processed_total carries
// source and destination workload labels only when Hubble's metrics context
// options ask for them; without them every flow is anonymous, so the source is
// refused with the setting to change rather than drawn as partial edges. The
// relay's gRPC stream stays out (docs/CLUSTER_INSIGHT_SPECS.md §5).

const (
	hubbleFlowMetric = "hubble_flows_processed_total"
	hubbleGroupBy    = "source_workload, source_namespace, destination_workload, destination_namespace, protocol"
	// HubbleContextHint is what to set when the labels are missing.
	HubbleContextHint = "Hubble flow metrics are exported without workload labels. Enable them with the flow metric's " +
		"context options, e.g. hubble.metrics.enabled: [\"flow:sourceContext=workload-name|reserved-identity;destinationContext=workload-name|reserved-identity\"] in Cilium's Helm values."
)

func hubbleRateQuery(namespace string, w rateWindow) string {
	sum := func(more string) string {
		return fmt.Sprintf(`sum by (%s) (rate(%s{verdict="FORWARDED", source_workload!="", destination_workload!=""%s}[%s]%s))`, hubbleGroupBy, hubbleFlowMetric, more, w.promQL, w.offset)
	}
	if namespace == "" {
		return sum("")
	}
	return sum(fmt.Sprintf(`, source_namespace=%q`, namespace)) + " or " + sum(fmt.Sprintf(`, destination_namespace=%q`, namespace))
}

func hubbleFlows(ctx context.Context, q PromQuerier, namespace string, w rateWindow) ([]Edge, error) {
	samples, err := q.Query(ctx, hubbleRateQuery(namespace, w))
	if err != nil {
		return nil, fmt.Errorf("query %s: %w", hubbleFlowMetric, err)
	}
	flows := make([]Edge, 0, len(samples))
	for _, s := range samples {
		if !usableSample(s.Value) {
			continue
		}
		l := s.Labels
		src := Endpoint{Namespace: l["source_namespace"], Name: l["source_workload"], Kind: "workload"}
		dst := Endpoint{Namespace: l["destination_namespace"], Name: l["destination_workload"], Kind: "workload"}
		externalIfNoNamespace(&src)
		externalIfNoNamespace(&dst)
		// A Hubble flow is a connection-level event, so the rate is shown as
		// connections, the closest field the map already draws.
		flows = append(flows, Edge{Src: src, Dst: dst, Protocol: strings.ToLower(l["protocol"]), ConnectionRate: ratePtr(s.Value)})
	}
	return flows, nil
}

// probeHubble is Probe's Hubble step: present with workload labels, present
// without them (refused, with the hint), or absent.
func probeHubble(ctx context.Context, q PromQuerier) (found bool, labelled bool, err error) {
	all, err := q.Query(ctx, `count(`+hubbleFlowMetric+`)`)
	if err != nil {
		return false, false, err
	}
	if len(all) == 0 || !usableSample(all[0].Value) {
		return false, false, nil
	}
	lab, err := q.Query(ctx, `count(`+hubbleFlowMetric+`{source_workload!="", destination_workload!=""})`)
	if err != nil {
		return true, false, err
	}
	return true, len(lab) > 0 && usableSample(lab[0].Value), nil
}
