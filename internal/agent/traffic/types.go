// Package traffic derives a service-to-service traffic map from metrics a
// service mesh or eBPF agent already exports to Prometheus: Istio's
// istio_requests_total / istio_tcp_connections_opened_total, and Beyla's (or
// OpenTelemetry eBPF Instrumentation's) network-flow and HTTP server metrics.
//
// The package never talks to Prometheus itself. Callers hand it a PromQuerier
// backed by the agent's metrics proxy, so the only egress is the one the
// agent already has, and the package is testable with a fake.
//
// Every figure is a per-second rate over the requested window. A figure the
// source does not measure, or whose query failed, is nil — never zero — so a
// reader can tell "no errors" from "errors not known".
package traffic

import "context"

// Sample is one instant-vector element: its label set and value.
type Sample struct {
	Labels map[string]string
	Value  float64
}

// PromQuerier runs an instant PromQL query and returns the vector it
// produced. A scalar result is returned as one Sample with no labels.
type PromQuerier interface {
	Query(ctx context.Context, promql string) ([]Sample, error)
}

// Source names returned by Detect and accepted by Flows.
const (
	SourceIstio = "istio"
	// SourceBeyla is Grafana Beyla, whose flow metric is beyla_network_flow_bytes_total.
	SourceBeyla = "beyla"
	// SourceOBI is OpenTelemetry eBPF Instrumentation, which exports the same
	// metrics under the obi_ prefix.
	SourceOBI = "obi"
	// SourceHubble is Cilium's Hubble flow metrics (hubble.go).
	SourceHubble = "hubble"
)

// Endpoint kinds.
const (
	KindWorkload = "Workload"
	KindPod      = "Pod"
	KindService  = "Service"
	// KindExternal marks an endpoint the source reported with no namespace:
	// outside the cluster, or outside the mesh.
	KindExternal = "External"
)

// Endpoint is one end of an edge.
type Endpoint struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
}

// Edge is aggregated traffic between two endpoints on one port.
type Edge struct {
	Src Endpoint `json:"src"`
	Dst Endpoint `json:"dst"`
	// Port is 0 when the source does not export the destination port (Istio
	// never does; Beyla only when dst.port is selected).
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	// RequestRate is requests per second. Nil on edges the source measured only
	// at L4.
	RequestRate *float64 `json:"requestRate,omitempty"`
	// ErrorRate is 5xx responses per second. Nil when request rates are not
	// known for the edge or the error query failed; zero only when it was
	// measured as zero.
	ErrorRate *float64 `json:"errorRate,omitempty"`
	// ConnectionRate is new TCP connections per second (Istio TCP traffic).
	ConnectionRate *float64 `json:"connectionRate,omitempty"`
	// BytesRate is bytes per second sent from Src to Dst. On a
	// DirectionUnknown edge it is both directions combined.
	BytesRate *float64 `json:"bytesRate,omitempty"`
	// DirectionUnknown marks a conversation whose initiator the source could
	// not establish (Beyla reports UDP, including DNS, this way). Src and Dst
	// are then ordered alphabetically, not by who called whom.
	DirectionUnknown bool `json:"directionUnknown,omitempty"`
	// Before is this edge over the same span, ComparisonSeconds earlier: nil
	// when no comparison ran or the edge had no traffic then (new).
	Before *Rates `json:"before,omitempty"`
	// Stopped marks an edge that carried traffic in the earlier window and
	// none now; its current figures are absent.
	Stopped bool `json:"stopped,omitempty"`
}

// Reason codes for an unavailable Result.
const (
	// ReasonNotConfigured: the agent has no Prometheus to query (set by the
	// caller, which owns that configuration).
	ReasonNotConfigured = "not_configured"
	// ReasonUnreachable: a Prometheus is configured but could not be queried.
	ReasonUnreachable = "unreachable"
	// ReasonNoSource: Prometheus answered, but no supported traffic source
	// exports metrics to it.
	ReasonNoSource = "no_source"
)

// Plain-sentence reasons for the codes the caller sets.
const (
	ReasonTextNotConfigured = "No Prometheus is connected to this cluster's agent, so traffic between workloads cannot be read."
	ReasonTextUnreachable   = "A Prometheus is connected to this cluster's agent, but it could not be queried."
)

// Result is the traffic map for one cluster.
type Result struct {
	Available bool `json:"available"`
	// ReasonCode is one of the Reason* codes when Available is false.
	ReasonCode string `json:"reasonCode,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Source     string `json:"source,omitempty"`
	// WindowSeconds is the span every rate was computed over.
	WindowSeconds int    `json:"windowSeconds,omitempty"`
	Edges         []Edge `json:"flows"`
	// TotalEdges is the edge count before the cap was applied.
	TotalEdges int  `json:"totalFlows"`
	Truncated  bool `json:"truncated,omitempty"`
	// Missing names figures whose queries failed. They are absent from the
	// edges above rather than zero.
	Missing []string `json:"missing,omitempty"`
	// Notes explain systematic gaps in what the source exports (for example,
	// no destination port), so the edges are read correctly.
	Notes []string `json:"notes,omitempty"`

	// ComparisonSeconds is how far back each edge's Before was read (the same
	// window, that much earlier); zero when no comparison was asked for.
	ComparisonSeconds int `json:"comparisonSeconds,omitempty"`
	// ComparisonAvailable is false when the earlier window could not be read
	// or held no traffic at all (a source installed since), with the reason:
	// every edge would otherwise read as new.
	ComparisonAvailable bool   `json:"comparisonAvailable,omitempty"`
	ComparisonReason    string `json:"comparisonReason,omitempty"`
}

// Rates are an edge's figures over one window; nil where not measured.
type Rates struct {
	RequestRate    *float64 `json:"requestRate,omitempty"`
	ErrorRate      *float64 `json:"errorRate,omitempty"`
	ConnectionRate *float64 `json:"connectionRate,omitempty"`
	BytesRate      *float64 `json:"bytesRate,omitempty"`
}

// MaxEdges caps the edges in a Result; the busiest edges are kept.
const MaxEdges = 500

// Unavailable is the Result for a cluster with no usable traffic source:
// code is one of the Reason* codes, reason its plain sentence.
func Unavailable(code, reason string) *Result {
	return &Result{Available: false, ReasonCode: code, Reason: reason, Edges: []Edge{}}
}
