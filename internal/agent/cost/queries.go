package cost

import (
	"fmt"
	"strings"
)

// perNode reduces an OpenCost price series to one value per node. The same
// node can be scraped from more than one target, and joining on a series
// with duplicates would count the price once per copy.
func perNode(metric string) string { return "max by (node) (" + metric + ")" }

// perVolume does the same per PersistentVolume.
func perVolume(expr string, labels ...string) string {
	return "max by (" + strings.Join(append([]string{"persistentvolume"}, labels...), ", ") + ") (" + expr + ")"
}

var (
	nodeTotalHourlyCostExpr = perNode("node_total_hourly_cost")
	nodeCPUHourlyCostExpr   = perNode("node_cpu_hourly_cost")
	nodeRAMHourlyCostExpr   = perNode("node_ram_hourly_cost")
	// The GPU price is exported for every node, with or without a GPU, so
	// the spend is the node's GPU count times its GPU price.
	nodeGPUHourlyCostExpr = "sum(" + perNode("node_gpu_count") + " * on (node) " + perNode("node_gpu_hourly_cost") + ")"
	// kube-state-metrics labels a volume claim's namespace claim_namespace;
	// copying it to namespace lets the join below produce a namespace.
	persistentVolumeHourlyCostExpr = perVolume("pv_hourly_cost")
	persistentVolumeClaimRef       = perVolume(`label_replace(kube_persistentvolume_claim_ref, "namespace", "$1", "claim_namespace", "(.+)")`, "namespace")
)

const bytesPerGiB = "1073741824"

// OpenCost's own series carry the workload's namespace in exported_namespace
// when Prometheus is scraping with honor_labels off (the namespace label is
// then OpenCost's own). label_replace prefers exported_namespace when present.

func cpuAllocationQuery(w string) string {
	return fmt.Sprintf(`sum by (namespace) (label_replace(avg_over_time(container_cpu_allocation{namespace!=""}[%s]), "namespace", "$1", "exported_namespace", "(.+)") * on(node) group_left() %s)`, w, nodeCPUHourlyCostExpr)
}

func cpuCostFallbackQuery(w string) string {
	return fmt.Sprintf(`sum by (namespace) (label_replace(rate(opencost_container_cpu_cost_total[%s]), "namespace", "$1", "exported_namespace", "(.+)"))`, w)
}

func memAllocationQuery(w string) string {
	return fmt.Sprintf(`sum by (namespace) (label_replace(avg_over_time(container_memory_allocation_bytes{namespace!=""}[%s]), "namespace", "$1", "exported_namespace", "(.+)") / %s * on(node) group_left() %s)`, w, bytesPerGiB, nodeRAMHourlyCostExpr)
}

func memCostFallbackQuery(w string) string {
	return fmt.Sprintf(`sum by (namespace) (label_replace(rate(opencost_container_memory_cost_total[%s]), "namespace", "$1", "exported_namespace", "(.+)"))`, w)
}

// Usage is priced at the same node rates as allocation so the two compare
// directly. cAdvisor series carry the node in instance (host:port).
func cpuUsageQuery(w string) string {
	return fmt.Sprintf(`sum by (namespace) (label_replace(rate(container_cpu_usage_seconds_total{container!="", namespace!=""}[%s]), "node", "$1", "instance", "(.+?)(?::\\d+)?$") * on(node) group_left() %s)`, w, nodeCPUHourlyCostExpr)
}

func memUsageQuery() string {
	return fmt.Sprintf(`sum by (namespace) (label_replace(container_memory_working_set_bytes{container!="", namespace!=""}, "node", "$1", "instance", "(.+?)(?::\\d+)?$") / %s * on(node) group_left() %s)`, bytesPerGiB, nodeRAMHourlyCostExpr)
}

func storageQuery() string {
	return `sum by (namespace) (` + persistentVolumeHourlyCostExpr + ` * on(persistentvolume) group_left(namespace) ` + persistentVolumeClaimRef + `)`
}

func nodeTotalQuery() string { return `sum(` + nodeTotalHourlyCostExpr + `)` }

// Per-pod variants for one namespace. Either label may hold the workload's
// namespace (see above), so both selectors are OR'd; the namespace is
// validated as a DNS label before it reaches here.

func podCPUAllocationQuery(ns, w string) string {
	return fmt.Sprintf(`sum by (pod) ((avg_over_time(container_cpu_allocation{exported_namespace=%q}[%s]) or avg_over_time(container_cpu_allocation{namespace=%q, exported_namespace=""}[%s])) * on(node) group_left() %s)`, ns, w, ns, w, nodeCPUHourlyCostExpr)
}

func podCPUCostFallbackQuery(ns, w string) string {
	return fmt.Sprintf(`sum by (pod) (rate(opencost_container_cpu_cost_total{exported_namespace=%q}[%s]) or rate(opencost_container_cpu_cost_total{namespace=%q, exported_namespace=""}[%s]))`, ns, w, ns, w)
}

func podMemAllocationQuery(ns, w string) string {
	return fmt.Sprintf(`sum by (pod) ((avg_over_time(container_memory_allocation_bytes{exported_namespace=%q}[%s]) or avg_over_time(container_memory_allocation_bytes{namespace=%q, exported_namespace=""}[%s])) / %s * on(node) group_left() %s)`, ns, w, ns, w, bytesPerGiB, nodeRAMHourlyCostExpr)
}

func podMemCostFallbackQuery(ns, w string) string {
	return fmt.Sprintf(`sum by (pod) (rate(opencost_container_memory_cost_total{exported_namespace=%q}[%s]) or rate(opencost_container_memory_cost_total{namespace=%q, exported_namespace=""}[%s]))`, ns, w, ns, w)
}

func podCPUUsageQuery(ns, w string) string {
	return fmt.Sprintf(`sum by (pod) (label_replace(rate(container_cpu_usage_seconds_total{container!="", namespace=%q}[%s]), "node", "$1", "instance", "(.+?)(?::\\d+)?$") * on(node) group_left() %s)`, ns, w, nodeCPUHourlyCostExpr)
}

func podMemUsageQuery(ns string) string {
	return fmt.Sprintf(`sum by (pod) (label_replace(container_memory_working_set_bytes{container!="", namespace=%q}, "node", "$1", "instance", "(.+?)(?::\\d+)?$") / %s * on(node) group_left() %s)`, ns, bytesPerGiB, nodeRAMHourlyCostExpr)
}
